"""Offline export and opt-in upload of closed RaspyJack capture sessions.

This module does not transmit on import or during export. Transport destinations
are fixed, credentials never enter receipts, and interrupted POSTs are not retried
automatically because the server may already have accepted them.
"""

import base64
import csv
import hashlib
import hmac
import http.client
import io
import json
import math
import os
from pathlib import Path
import re
import secrets
import ssl
import time
from collections import Counter
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit


CSV_FIELDS = ["MAC", "SSID", "AuthMode", "FirstSeen", "Channel", "Frequency",
              "RSSI", "CurrentLatitude", "CurrentLongitude", "AltitudeMeters",
              "AccuracyMeters", "RCOIs", "MfgrId", "Type"]
CSV_METADATA = "WigleWifi-1.6,appRelease=Evil-LORA-Tunnel,device=RaspyJack"
URLS = {
    "wigle": "https://api.wigle.net/api/v2/file/upload",
    "wardrift": "https://wardrift.net/v1/ingest/signals",
    "wdgwars": "https://wdgwars.pl/api/v2/upload-csv",
    "wdgwars_mesh": "https://wdgwars.pl/endpoint/upload/",
}
MAX_ARTIFACT = 512 * 1024
MAX_RESPONSE = 128 * 1024
MAX_LINE = 64 * 1024
MAX_MESH_NODES = 4096
MAX_ARTIFACTS = 256
MAX_ATTEMPTS = 3
MAX_REQUESTS = 4
RETRY_DELAYS = (30, 120, 600)
MAC = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\Z")
JOB_ID = re.compile(r"[A-Za-z0-9_-]{1,80}\Z")


class ExportError(ValueError):
    """A fixed, nonsecret error suitable for the device UI."""


class TransportFailure(Exception):
    def __init__(self, may_have_sent=True):
        super().__init__("Upload connection failed")
        self.may_have_sent = may_have_sent


def _json_read(path, limit=MAX_RESPONSE):
    with open(path, "rb") as source:
        raw = source.read(limit + 1)
    if len(raw) > limit:
        raise ExportError("Metadata exceeds its size limit")
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise ExportError("Invalid metadata") from exc
    if not isinstance(data, dict):
        raise ExportError("Invalid metadata")
    return data


def _atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".new")
    # These files never contain credentials, but capture metadata stays private.
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as target:
        json.dump(value, target, separators=(",", ":"), allow_nan=False)
        target.flush()
        os.fsync(target.fileno())
    os.replace(temporary, path)
    if os.name != "nt":
        directory = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def _sha(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _closed_session(session_dir):
    session_dir = Path(session_dir).resolve()
    metadata = _json_read(session_dir / "session.json")
    if metadata.get("status") != "closed":
        raise ExportError("Stop and save the session before exporting")
    if metadata.get("synthetic") is True:
        raise ExportError("Synthetic sessions cannot be uploaded")
    return session_dir


def _number(value, low, high):
    if isinstance(value, bool):
        raise ValueError("boolean is not a measurement")
    value = float(value)
    if not math.isfinite(value) or not low <= value <= high:
        raise ValueError("measurement out of range")
    return value


def _utc(value, *, raspyjack_local=False):
    if isinstance(value, bool):
        raise ValueError("invalid observation time")
    if isinstance(value, (float, int)):
        value = datetime.fromtimestamp(value, timezone.utc)
    elif isinstance(value, str):
        # WiGLE timestamps are UTC by contract; native JSON timestamps may be ISO.
        if raspyjack_local and re.fullmatch(r"[0-9]{9,10}(?:\.[0-9]{1,9})?", value):
            value = datetime.fromtimestamp(float(value), timezone.utc)
        else:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if value.tzinfo is None:
            # Wardriving's _ts_iso() serializes datetime.fromtimestamp() in
            # the receiver's local timezone. Other WiGLE sources use UTC.
            value = value.astimezone() if raspyjack_local else value.replace(tzinfo=timezone.utc)
    else:
        raise ValueError("invalid observation time")
    if value.year < 2020 or value.timestamp() > time.time() + 86400:
        raise ValueError("invalid observation time")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _csv_row(row, *, raspyjack_local=False):
    if row.get("Type") != "WIFI" or not MAC.fullmatch(row.get("MAC", "")):
        raise ValueError("unsupported_identity")
    first = int(row["MAC"][:2], 16)
    if first & 1 or row["MAC"].lower() == "00:00:00:00:00:00":
        raise ValueError("unsupported_identity")
    result = {field: row.get(field, "") for field in CSV_FIELDS}
    lat = _number(row["CurrentLatitude"], -90, 90)
    lon = _number(row["CurrentLongitude"], -180, 180)
    # Native CSV has no fix-valid flag, and some writers use 0,0 for no fix.
    if lat == 0 and lon == 0:
        raise ValueError("missing_gps")
    _number(row["RSSI"], -200, 0)
    result["FirstSeen"] = _utc(row["FirstSeen"], raspyjack_local=raspyjack_local)
    channel = int(row["Channel"])
    if result["Frequency"]:
        measured_frequency = _number(result["Frequency"], 2000, 7200)
        if not measured_frequency.is_integer():
            raise ValueError("invalid_frequency")
        frequency = int(measured_frequency)
        if frequency == 2484:
            expected = 14
        elif 2412 <= frequency <= 2472 and (frequency - 2407) % 5 == 0:
            expected = (frequency - 2407) // 5
        elif frequency == 5935:
            expected = 2
        elif 5955 <= frequency <= 7115 and (frequency - 5950) % 5 == 0:
            expected = (frequency - 5950) // 5
        elif 5005 <= frequency <= 5895 and frequency % 5 == 0:
            expected = (frequency - 5000) // 5
        else:
            raise ValueError("invalid_frequency")
        if expected != channel:
            raise ValueError("channel_frequency_mismatch")
        result["Frequency"] = str(frequency)
    elif not 1 <= channel <= 233:
        raise ValueError("invalid_channel")
    # Older native WiGLE CSV may omit frequency. Keep it unknown: channel 1,
    # for example, can be either 2.4 or 6 GHz and cannot establish the band.
    for field in ("SSID", "AuthMode", "RCOIs"):
        result[field] = result[field].replace("\r", "\\r").replace("\n", "\\n")
        if len(result[field].encode("utf-8")) > 4096:
            raise ValueError("oversized_field")
    for field in ("AltitudeMeters", "AccuracyMeters"):
        if result[field]:
            _number(result[field], -1000 if field == "AltitudeMeters" else 0, 100000)
    return result


def _csv_bytes(rows):
    stream = io.StringIO(newline="")
    stream.write(CSV_METADATA + "\r\n")
    writer = csv.DictWriter(stream, CSV_FIELDS, lineterminator="\r\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def _write_artifact(directory, kind, number, data, rows):
    if len(data) > MAX_ARTIFACT or number >= MAX_ARTIFACTS:
        raise ExportError("Export exceeds its size limit; split the session offline")
    extension = "csv" if kind == "wifi" else "json"
    digest = hashlib.sha256(data).hexdigest()
    name = f"{kind}-{number:04d}-{digest[:16]}.{extension}"
    path = directory / name
    if not path.exists():
        with open(path, "xb") as target:
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
    elif _sha(path) != digest:
        raise ExportError("An export artifact changed unexpectedly")
    return {"kind": kind, "path": str(path), "sha256": digest, "rows": rows}


def _wifi_export(source, output, skipped):
    if not source.exists():
        return []
    artifacts, rows, size = [], [], 0
    with open(source, encoding="utf-8-sig", newline="") as handle:
        metadata = handle.readline(MAX_LINE)
        if not metadata.startswith(("WigleWifi-1.4,", "WigleWifi-1.6,")):
            raise ExportError("Unsupported WiGLE CSV metadata")
        raspyjack_local = "appRelease=RaspyJack-v2" in metadata.rstrip().split(",")
        csv.field_size_limit(MAX_LINE)
        reader = csv.DictReader(handle)
        required = set(CSV_FIELDS) - {"Frequency", "RCOIs", "MfgrId"}
        if not required.issubset(reader.fieldnames or []):
            raise ExportError("Native WiGLE CSV is missing required columns")
        try:
            for row in reader:
                try:
                    if None in row or any(value is None for value in row.values()):
                        raise ValueError("malformed_csv")
                    normalized = _csv_row(row, raspyjack_local=raspyjack_local)
                except (ValueError, TypeError, KeyError, OverflowError):
                    skipped["wifi_invalid_or_missing_fix"] += 1
                    continue
                row_size = sum(len(v.encode("utf-8")) for v in normalized.values()) + 64
                if rows and size + row_size > MAX_ARTIFACT // 2:
                    artifacts.append(_write_artifact(output, "wifi", len(artifacts), _csv_bytes(rows), len(rows)))
                    rows, size = [], 0
                rows.append(normalized)
                size += row_size
        except (csv.Error, UnicodeError) as exc:
            raise ExportError("Malformed native WiGLE CSV") from exc
    if rows:
        artifacts.append(_write_artifact(output, "wifi", len(artifacts), _csv_bytes(rows), len(rows)))
    return artifacts


def _observations(path, skipped):
    if not path.exists():
        return
    with open(path, "rb") as source:
        while True:
            line = source.readline(MAX_LINE + 1)
            if not line:
                break
            if len(line) > MAX_LINE:
                while line and not line.endswith(b"\n"):
                    line = source.readline(MAX_LINE + 1)
                skipped["mesh_oversized_record"] += 1
                continue
            try:
                item = json.loads(line)
                if not isinstance(item, dict):
                    raise ValueError()
            except (ValueError, UnicodeError):
                skipped["mesh_malformed_record"] += 1
                continue
            yield item


def _mesh_id(decoded):
    protocol = decoded.get("protocol")
    identifier = str(decoded.get("source_id", "")).lower()
    if protocol == "meshtastic":
        identifier = identifier.removeprefix("!")
        if not re.fullmatch(r"[a-f0-9]{8}", identifier) or identifier in ("00000000", "ffffffff"):
            raise ValueError()
    elif protocol == "meshcore":
        key = decoded.get("public_key", "")
        if not isinstance(key, str) or not re.fullmatch(r"[a-f0-9]{64}", key):
            raise ValueError()
        if decoded.get("signature_valid") is not True or identifier not in (key, key[:16]):
            raise ValueError()
        identifier = key[:16]
    else:
        raise ValueError()
    return protocol, identifier


def _mesh_export(source, output, skipped):
    # A node-information packet and a position packet can arrive separately.
    # Only roles actually observed within this session can fill that gap.
    roles, best = {}, {}
    for observation in _observations(source, skipped):
        decoded = observation.get("decoded") or {}
        if not isinstance(decoded, dict) or observation.get("synthetic") is True:
            continue
        if decoded.get("decode_status") != "decoded" or observation.get("crc_ok") is False:
            continue
        try:
            identity = _mesh_id(decoded)
            role = decoded.get("node_type")
            if (isinstance(role, str) and role.lower() not in {"unknown", "unset", "none"}
                    and re.fullmatch(r"[A-Za-z_ -]{1,40}", role)):
                if identity in roles or len(roles) < MAX_MESH_NODES:
                    roles[identity] = role
        except (ValueError, TypeError):
            pass
    for observation in _observations(source, Counter()):
        decoded = observation.get("decoded") or {}
        try:
            if not isinstance(decoded, dict) or observation.get("synthetic") is True:
                raise ValueError()
            if decoded.get("decode_status") != "decoded" or observation.get("crc_ok") is False:
                raise ValueError()
            identity = _mesh_id(decoded)
            position = decoded.get("node_position") or {}
            if position.get("source") != "advertised":
                raise ValueError()
            latitude = _number(position["latitude"], -90, 90)
            longitude = _number(position["longitude"], -180, 180)
            if latitude == 0 and longitude == 0:
                raise ValueError()
            role = roles.get(identity)
            if not role:
                raise ValueError()
            hops = decoded.get("hop_count")
            if hops is None and identity[0] == "meshtastic":
                start, limit = decoded.get("hop_start"), decoded.get("hop_limit")
                if (type(start) is int and type(limit) is int and 0 <= limit <= start <= 7
                        and (start > 0 or decoded.get("sender_bitfield_present") is True)):
                    hops = start - limit
            if type(hops) is not int or not 0 <= hops <= 64:
                raise ValueError()
            record = {"node_id": identity[1], "network": identity[0],
                      "type": "MESHCORE", "node_type": role,
                      "name": str(decoded.get("name") or identity[1])[:128],
                      "lat": latitude, "lon": longitude,
                      "rssi": _number(observation["rssi_dbm"], -200, 0),
                      "first_seen": _utc(observation["timestamp"]), "path_hops": hops}
            if identity[0] == "meshcore":
                record["public_key"] = decoded["public_key"]
            # Keep the most direct sighting, then strongest signal. Original
            # packets remain in the log, including every later position change.
            rank = (hops, -record["rssi"])
            if identity in best:
                if rank < best[identity][0]:
                    best[identity] = (rank, record)
            elif len(best) < MAX_MESH_NODES:
                best[identity] = (rank, record)
            else:
                skipped["mesh_node_limit"] += 1
        except (ValueError, KeyError, TypeError, OverflowError, AttributeError):
            skipped["mesh_not_eligible"] += 1
    records = [best[key][1] for key in sorted(best)]
    artifacts = []
    for offset in range(0, len(records), 250):
        chunk = records[offset:offset + 250]
        data = json.dumps({"networks": [], "aircraft": [], "meshcore_nodes": chunk},
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
        artifacts.append(_write_artifact(output, "mesh", len(artifacts), data, len(chunk)))
    return artifacts


def prepare_session(session_dir, output_dir=None):
    """Create bounded derived files without credentials or network requests."""
    directory = _closed_session(session_dir)
    output = Path(output_dir) if output_dir else directory / ".uploads" / "exports"
    output.mkdir(parents=True, exist_ok=True)
    skipped = Counter()
    artifacts = _wifi_export(directory / "wifi.csv", output, skipped)
    artifacts += _mesh_export(directory / "observations.jsonl", output, skipped)
    return {"schema": 1, "uploaded": False, "artifacts": artifacts,
            "wifi_rows": sum(a["rows"] for a in artifacts if a["kind"] == "wifi"),
            "mesh_nodes": sum(a["rows"] for a in artifacts if a["kind"] == "mesh"),
            "skipped": dict(skipped)}


def _request(url, headers, body=None, timeout=45):
    """HTTPS only; http.client never follows redirects or logs auth headers."""
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in {"api.wigle.net", "wardrift.net", "wdgwars.pl"}:
        raise ExportError("Upload destination is not permitted")
    deadline = time.monotonic() + min(45, max(0.001, timeout))
    connection = http.client.HTTPSConnection(parsed.hostname, timeout=min(15, max(0.001, timeout)),
                                            context=ssl.create_default_context())
    sent = False
    try:
        connection.connect()
        socket_ref = connection.sock
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        socket_ref.settimeout(min(15, remaining))
        sent = True
        connection.request("POST" if body is not None else "GET", parsed.path, body=body, headers=headers)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        socket_ref.settimeout(min(15, remaining))
        response = connection.getresponse()
        pieces, received = [], 0
        while received <= MAX_RESPONSE:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            socket_ref.settimeout(min(15, remaining))
            piece = response.read1(min(8192, MAX_RESPONSE + 1 - received))
            if not piece:
                break
            pieces.append(piece)
            received += len(piece)
        raw = b"".join(pieces)
        if len(raw) > MAX_RESPONSE:
            return response.status, {}, None
        try:
            value = json.loads(raw)
            if not isinstance(value, dict):
                value = None
        except (ValueError, UnicodeError):
            value = None
        return response.status, {k.lower(): v for k, v in response.getheaders()}, value
    except Exception:
        raise TransportFailure(sent) from None
    finally:
        connection.close()


def _credential(settings, name):
    value = settings.get(name)
    if not isinstance(value, str) or not 1 <= len(value) <= 512 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ExportError("A required API credential is missing or invalid")
    return value


def _multipart(data, filename, donate=False):
    boundary = "lpp-" + secrets.token_hex(16)
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            'Content-Type: text/csv\r\n\r\n').encode() + data + b"\r\n"
    if donate:
        body += (f'--{boundary}\r\nContent-Disposition: form-data; name="donate"\r\n\r\non\r\n').encode()
    return body + f"--{boundary}--\r\n".encode(), "multipart/form-data; boundary=" + boundary


def _wire(service, settings, artifact):
    path = Path(artifact["path"])
    with open(path, "rb") as source:
        data = source.read(MAX_ARTIFACT + 1)
    if len(data) > MAX_ARTIFACT or hashlib.sha256(data).hexdigest() != artifact["sha256"]:
        raise ExportError("Export artifact failed validation")
    headers = {"Accept": "application/json", "User-Agent": "Evil-LORA-Tunnel/0.1"}
    if service == "wigle":
        name = _credential(settings, "api_name")
        if ":" in name:
            raise ExportError("Invalid WiGLE API name")
        credentials = name + ":" + _credential(settings, "api_token")
        headers["Authorization"] = "Basic " + base64.b64encode(credentials.encode()).decode()
    else:
        headers["X-API-Key"] = _credential(settings, "api_key")
    if service == "wardrift":
        body, content_type = data, "text/csv"
        headers["X-File-Name"] = path.name
    elif artifact["kind"] == "mesh":
        encoded = base64.b64encode(data).decode()
        nonce = secrets.token_hex(8)
        signature = hmac.new(headers["X-API-Key"].encode(), (nonce + encoded).encode(), hashlib.sha256).hexdigest()
        body = json.dumps({"data": encoded, "nonce": nonce, "sig": signature}, separators=(",", ":")).encode()
        content_type = "application/json"
    else:
        body, content_type = _multipart(data, path.name, service == "wigle" and settings.get("donate") is True)
    headers["Content-Type"] = content_type
    destination = "wdgwars_mesh" if service == "wdgwars" and artifact["kind"] == "mesh" else service
    return URLS[destination], headers, body


def _delay(headers, attempt, now):
    value = headers.get("retry-after", "")
    try:
        seconds = int(value) if value.isdigit() else parsedate_to_datetime(value).timestamp() - now
        return max(RETRY_DELAYS[min(attempt - 1, 2)], min(86400, seconds))
    except (ValueError, TypeError, AttributeError, OverflowError):
        return RETRY_DELAYS[min(attempt - 1, 2)]


def _counts(response, mesh=False):
    fields = ("meshcore_imported", "meshcore_already_seen", "meshcore_merged", "meshcore_rejected") if mesh else (
        "imported", "captured", "updated", "duplicates", "no_gps", "bad_rows", "merged_samples")
    return {key: value for key in fields if type(value := response.get(key)) is int and value >= 0}


def _receipt(service, kind, status, response):
    if not isinstance(response, dict):
        return {"state": "uncertain", "reason": "invalid_receipt"}
    if service == "wigle" and status == 200 and response.get("success") is True:
        detail = response.get("results")
        identifiers = detail.get("transids", []) if isinstance(detail, dict) else []
        if not isinstance(identifiers, list):
            identifiers = []
        return {"state": "accepted", "reason": "queued_for_processing",
                "transaction_ids": [x.get("transid") for x in identifiers if isinstance(x, dict) and
                                    isinstance(x.get("transid"), str) and JOB_ID.fullmatch(x["transid"])]}
    if service == "wardrift" and status == 200 and (response.get("accepted") is True or response.get("duplicate") is True):
        return {"state": "accepted", "reason": "duplicate" if response.get("duplicate") is True else "accepted"}
    if service == "wdgwars" and kind == "wifi":
        job = response.get("job_id")
        if status == 202 and response.get("ok") is True and type(job) in (str, int) and JOB_ID.fullmatch(str(job)):
            return {"state": "pending", "job_id": str(job)}
    if service == "wdgwars" and kind == "mesh" and status == 200 and response.get("ok") is True:
        return {"state": "accepted", "reason": "check_import_counts", "counts": _counts(response, mesh=True)}
    return {"state": "uncertain", "reason": "unrecognized_receipt"}


def upload_session(session_dir, private_config, service, automatic=False, transport=None,
                   *, request_limit=MAX_REQUESTS, time_fn=None, _prepared=None):
    """Advance at most four uploads/polls. Return only nonsecret state/counts.

    Calling again polls saved jobs or processes remaining chunks. Unknown POST
    outcomes require explicit operator reconciliation, never an automatic resend.
    """
    if service not in ("wigle", "wardrift", "wdgwars"):
        raise ExportError("Unknown upload service")
    if type(request_limit) is not int or not 0 <= request_limit <= MAX_REQUESTS:
        raise ExportError("Invalid upload request limit")
    settings = private_config.get("uploads", {}).get(service, {})
    if settings.get("enabled") is not True or automatic and settings.get("auto") is not True:
        return {"service": service, "state": "disabled", "requests": 0}
    directory = _closed_session(session_dir)
    # Namespace receipts by API account so changing destination credentials
    # cannot silently reuse another account's accepted checkpoints.
    if service == "wigle":
        identity = _credential(settings, "api_name") + ":" + _credential(settings, "api_token")
    else:
        identity = _credential(settings, "api_key")
    account = hashlib.sha256(identity.encode()).hexdigest()
    state_dir = directory / ".uploads" / service / account
    blocked = state_dir / "auth-blocked.json"
    if blocked.exists():
        return {"service": service, "state": "auth_failed", "requests": 0}
    report = prepare_session(directory) if _prepared is None else _prepared
    artifacts = [a for a in report["artifacts"] if service == "wdgwars" or a["kind"] == "wifi"]
    if not artifacts:
        return {"service": service, "state": "no_eligible_data", "requests": 0}
    request = transport or _request
    clock = time_fn or time.time
    now, calls, results = clock(), 0, []
    for artifact in artifacts:
        now = clock()
        checkpoint = state_dir / (artifact["sha256"] + ".json")
        state = _json_read(checkpoint) if checkpoint.exists() else {"state": "prepared", "attempts": 0}
        if state["state"] == "sending":
            state.update(state="uncertain", reason="interrupted_post")
            _atomic_json(checkpoint, state)
        if state["state"] in ("accepted", "uncertain", "rejected", "auth_failed", "failed"):
            results.append(state)
            continue
        if calls >= request_limit or state.get("next_attempt", 0) > now:
            results.append(state)
            continue
        if state["state"] == "pending":
            job = state.get("job_id", "")
            if service != "wdgwars" or artifact["kind"] != "wifi" or not isinstance(job, str) or not JOB_ID.fullmatch(job):
                raise ExportError("Invalid saved upload job")
            url = "https://wdgwars.pl/api/v2/upload-job/" + job
            headers = {"X-API-Key": _credential(settings, "api_key"), "Accept": "application/json"}
            body = None
        else:
            if state.get("attempts", 0) >= MAX_ATTEMPTS:
                state.update(state="failed", reason="retry_limit")
                _atomic_json(checkpoint, state)
                results.append(state)
                continue
            url, headers, body = _wire(service, settings, artifact)
            state.update(state="sending", attempts=state.get("attempts", 0) + 1)
            _atomic_json(checkpoint, state)
        calls += 1
        try:
            status, response_headers, response = request(url, headers, body)
            now = clock()
            if body is None:
                if status in (401, 403):
                    state.update(state="auth_failed", reason="authentication_required")
                elif status == 200 and isinstance(response, dict) and response.get("status") == "done":
                    detail = response.get("result") or {}
                    state.update(state="accepted", counts=_counts(detail) if isinstance(detail, dict) else {})
                elif status == 200 and isinstance(response, dict) and response.get("status") == "failed":
                    state.update(state="failed", reason="server_job_failed")
                else:
                    state["next_attempt"] = now + max(30, _delay(response_headers, 1, now))
            elif status in (401, 403):
                state.update(state="auth_failed", reason="authentication_required")
            elif status == 429:
                state.update(state="retry", reason="rate_limited", next_attempt=now + _delay(response_headers, state["attempts"], now))
            elif 300 <= status < 500:
                state.update(state="rejected", reason="redirect_refused" if status < 400 else "request_rejected")
            elif 200 <= status < 300:
                state.update(_receipt(service, artifact["kind"], status, response))
                if state["state"] == "pending":
                    state["next_attempt"] = now + 30
            else:
                state.update(state="uncertain", reason="server_error_after_post")
        except TransportFailure as error:
            now = clock()
            if body is None:
                state["next_attempt"] = now + 30
            elif error.may_have_sent:
                state.update(state="uncertain", reason="connection_lost_after_post")
            else:
                state.update(state="retry", reason="connection_unavailable",
                             next_attempt=now + RETRY_DELAYS[min(state["attempts"] - 1, 2)])
        except Exception:
            # Never expose exception strings from a transport: they can contain
            # headers, request bodies, keys, or returned capture identifiers.
            now = clock()
            state.update(state="uncertain", reason="transport_failed")
        state["updated_at"] = int(now)
        _atomic_json(checkpoint, state)
        results.append(state)
        if state["state"] == "auth_failed":
            _atomic_json(blocked, {"state": "auth_failed"})
            break
    counts = Counter(item["state"] for item in results)
    return {"service": service, "state": "accepted" if counts.get("accepted") == len(artifacts) else "incomplete",
            "requests": calls, "chunks": len(artifacts), "states": dict(counts), "receipts": results}


def advance_uploads(session_dir, private_config, services, automatic=False, timeout=240,
                    transport=None, *, time_fn=None, monotonic_fn=None, sleep_fn=None):
    """Advance enabled destinations fairly within 32 requests and a time budget.

    Existing receipts remain authoritative. Each round permits one request per
    destination, so a pending job cannot prevent another service from progressing.
    A rate-limit delay beyond this invocation's deadline returns immediately;
    it never truncates that delay to squeeze in another attempt. Inject all three
    clock functions together for deterministic tests without real waiting.
    """
    if (type(timeout) not in (int, float) or not math.isfinite(timeout)
            or not 0 <= timeout <= 240):
        raise ExportError("Upload timeout must be between zero and 240 seconds")
    if not isinstance(services, (list, tuple)):
        raise ExportError("Upload services must be a list")
    if any(not isinstance(service, str) or service not in ("wigle", "wardrift", "wdgwars")
           for service in services):
        raise ExportError("Unknown upload service")
    selected = list(dict.fromkeys(services))
    now = time_fn or time.time
    monotonic = monotonic_fn or time.monotonic
    sleep = sleep_fn or time.sleep
    deadline = monotonic() + timeout
    results = {}
    calls = 0
    prepared = None

    for service in selected:
        settings = private_config.get("uploads", {}).get(service, {})
        if settings.get("enabled") is not True or automatic and settings.get("auto") is not True:
            results[service] = {"service": service, "state": "disabled", "requests": 0}

    def due(result, wall_time):
        if result is None:
            return wall_time
        if result.get("state") in {"accepted", "disabled", "no_eligible_data", "auth_failed"}:
            return None
        times = []
        for receipt in result.get("receipts", []):
            state = receipt.get("state")
            if state not in {"prepared", "pending", "retry"}:
                continue
            when = receipt.get("next_attempt", wall_time)
            if type(when) not in (int, float) or not math.isfinite(when):
                continue
            times.append(max(wall_time, when))
        return min(times) if times else None

    def request(url, headers, body):
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TransportFailure(False)
        if transport is not None:
            return transport(url, headers, body)
        return _request(url, headers, body, timeout=min(45, remaining))

    reason = "complete"
    while True:
        wall_time = now()
        eligible = [(service, due(results.get(service), wall_time)) for service in selected]
        eligible = [(service, when) for service, when in eligible if when is not None]
        if not eligible:
            if any(result.get("state") not in {"accepted", "disabled", "no_eligible_data"}
                   for result in results.values()):
                reason = "blocked"
            break
        if calls >= 32:
            reason = "request_limit"
            break
        remaining = deadline - monotonic()
        if remaining <= 0:
            reason = "deadline"
            break
        ready = [service for service, when in eligible if when <= wall_time]
        if not ready:
            wait = min(when for _, when in eligible) - wall_time
            if wait >= remaining:
                reason = "deadline"
                break
            sleep(min(30, wait, remaining))
            continue
        for service in ready:
            if calls >= 32 or monotonic() >= deadline:
                break
            if prepared is None:
                # The caller holds the collector lock for this closed session.
                # Reuse hashes and artifacts across chunks, services and polls.
                prepared = prepare_session(session_dir)
                if monotonic() >= deadline:
                    break
            result = upload_session(session_dir, private_config, service, automatic=automatic,
                                    transport=request, request_limit=1, time_fn=now,
                                    _prepared=prepared)
            calls += result["requests"]
            results[service] = result

    for service in selected:
        if service not in results:
            results[service] = {"service": service, "state": "incomplete", "requests": 0}
    states = {result["state"] for result in results.values()}
    if not states or states <= {"disabled"}:
        state = "disabled"
    elif states <= {"disabled", "no_eligible_data"}:
        state = "no_eligible_data"
    elif states <= {"accepted", "disabled", "no_eligible_data"}:
        state = "accepted"
    else:
        state = "incomplete"
    return {"state": state, "requests": calls, "stop_reason": reason, "services": results}
