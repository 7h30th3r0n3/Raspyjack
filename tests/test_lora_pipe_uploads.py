# Adapted from LORA-Pager-Pipe, copyright 2026 Valleytech Solutions.
# MIT license: see evil_lora_tunnel/LICENSE.
import base64
import csv
from datetime import datetime, timezone
import hashlib
import hmac
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from evil_lora_tunnel import uploads


class FakeClock:
    def __init__(self):
        self.elapsed = 0
        self.waits = []

    def wall(self):
        return 1800000000 + self.elapsed

    def monotonic(self):
        return self.elapsed

    def sleep(self, seconds):
        if not 0 < seconds <= 30:
            raise AssertionError("wait must be positive and bounded")
        self.waits.append(seconds)
        self.elapsed += seconds


class UploadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.session = Path(self.temporary.name)
        (self.session / "session.json").write_text('{"status":"closed"}')
        self.config = {"uploads": {
            "wigle": {"enabled": True, "auto": False, "api_name": "TEST_ONLY", "api_token": "TEST_TOKEN"},
            "wardrift": {"enabled": True, "auto": False, "api_key": "TEST_TOKEN"},
            "wdgwars": {"enabled": True, "auto": False, "api_key": "TEST_TOKEN"}}}

    def wifi(self, rows=None, frequency=True, producer="fixture"):
        fields = uploads.CSV_FIELDS if frequency else [x for x in uploads.CSV_FIELDS if x != "Frequency"]
        base = {field: "" for field in fields}
        base.update(MAC="02:11:22:33:44:55", SSID='name,"quoted"', AuthMode="[WPA2-PSK-CCMP][ESS]",
                    FirstSeen="2026-01-01 12:00:00", Channel="1", RSSI="-60", CurrentLatitude="40.1",
                    CurrentLongitude="-74.1", Type="WIFI")
        if frequency:
            base["Frequency"] = "5955"
        with open(self.session / "wifi.csv", "w", encoding="utf-8", newline="") as target:
            target.write(f"WigleWifi-1.6,appRelease={producer}\n")
            writer = csv.DictWriter(target, fields)
            writer.writeheader()
            writer.writerows([base] if rows is None else [dict(base, **changes) for changes in rows])

    def mesh(self, rows):
        with open(self.session / "observations.jsonl", "w") as target:
            for row in rows:
                target.write(json.dumps(row) + "\n")

    def node(self, **changes):
        decoded = {"protocol": "meshtastic", "decode_status": "decoded", "source_id": "!12345678",
                   "node_type": "CLIENT", "hop_start": 3, "hop_limit": 2,
                   "node_position": {"latitude": 40.1, "longitude": -74.1, "source": "advertised"}}
        decoded.update(changes)
        return {"timestamp": 1767268800, "rssi_dbm": -70, "crc_ok": True, "decoded": decoded}

    def test_closed_and_nonsynthetic_required(self):
        for metadata in ({"status": "recording"}, {"status": "closed", "synthetic": True}):
            (self.session / "session.json").write_text(json.dumps(metadata))
            with self.assertRaises(uploads.ExportError):
                uploads.prepare_session(self.session)

    def test_native_wardriving_epoch_and_local_clock(self):
        stamp = 1700000000
        local_time = datetime.fromtimestamp(stamp).isoformat()
        expected = datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        self.wifi([{"FirstSeen": str(stamp)}, {"FirstSeen": local_time}],
                  frequency=False, producer="RaspyJack-v2")
        item = uploads.prepare_session(self.session)["artifacts"][0]
        with open(item["path"], newline="") as source:
            self.assertIn("device=RaspyJack", source.readline())
            rows = list(csv.DictReader(source))
        self.assertEqual([row["FirstSeen"] for row in rows], [expected, expected])
        self.assertEqual([row["Frequency"] for row in rows], ["", ""])

    def test_csv_preserves_6ghz_frequency_and_escaping(self):
        self.wifi()
        report = uploads.prepare_session(self.session)
        with open(report["artifacts"][0]["path"], newline="") as source:
            source.readline()
            row = next(csv.DictReader(source))
        self.assertEqual(row["Frequency"], "5955")
        self.assertEqual(row["SSID"], 'name,"quoted"')
        self.assertFalse(report["uploaded"])

    def test_legacy_csv_does_not_guess_band(self):
        self.wifi(frequency=False)
        report = uploads.prepare_session(self.session)
        with open(report["artifacts"][0]["path"], newline="") as source:
            source.readline()
            self.assertEqual(next(csv.DictReader(source))["Frequency"], "")

    def test_csv_rejects_missing_position_and_inconsistent_frequency(self):
        self.wifi([{"CurrentLatitude": "0", "CurrentLongitude": "0"}, {"Channel": "6"}, {"RSSI": "nan"}])
        report = uploads.prepare_session(self.session)
        self.assertEqual(report["wifi_rows"], 0)
        self.assertEqual(report["skipped"]["wifi_invalid_or_missing_fix"], 3)

    def test_mesh_does_not_use_receiver_location_or_unknown_hops(self):
        missing = self.node(node_position=None)
        missing["receiver_gps"] = {"valid": True, "latitude": 40.1, "longitude": -74.1}
        self.mesh([missing, self.node(hop_start=None, hop_limit=3), self.node(decode_status="encrypted"),
                   self.node(hop_start=0, hop_limit=0), self.node(node_type="unknown", source_id="!87654321")])
        self.assertEqual(uploads.prepare_session(self.session)["mesh_nodes"], 0)

    def test_zero_hop_start_needs_sender_bitfield(self):
        self.mesh([self.node(hop_start=0, hop_limit=0, sender_bitfield_present=True)])
        self.assertEqual(uploads.prepare_session(self.session)["mesh_nodes"], 1)

    def test_mesh_uses_observed_role_and_verified_key(self):
        role = self.node(node_position=None)
        position = self.node(node_type=None)
        key = "ab" * 32
        good = self.node(protocol="meshcore", source_id=key, public_key=key, signature_valid=True,
                         node_type="Repeater", hop_count=2)
        bad = self.node(protocol="meshcore", source_id="cd" * 32, public_key="cd" * 32,
                        signature_valid=False, node_type="Repeater", hop_count=1)
        self.mesh([role, position, good, bad])
        report = uploads.prepare_session(self.session)
        data = json.loads(Path(report["artifacts"][0]["path"]).read_text())
        self.assertEqual(report["mesh_nodes"], 2)
        ids = {node["node_id"] for node in data["meshcore_nodes"]}
        self.assertEqual(ids, {"12345678", key[:16]})

    def test_mesh_request_signature_uses_text_key(self):
        self.mesh([self.node()])
        artifact = uploads.prepare_session(self.session)["artifacts"][0]
        url, headers, body = uploads._wire("wdgwars", self.config["uploads"]["wdgwars"], artifact)
        wire = json.loads(body)
        expected = hmac.new(b"TEST_TOKEN", (wire["nonce"] + wire["data"]).encode(), hashlib.sha256).hexdigest()
        self.assertEqual(wire["sig"], expected)
        self.assertEqual(url, "https://wdgwars.pl/endpoint/upload/")
        self.assertEqual(json.loads(base64.b64decode(wire["data"]))["meshcore_nodes"][0]["network"], "meshtastic")

    def test_auto_requires_distinct_optin(self):
        self.wifi()
        def fail(*args):
            self.fail("network was called without opt-in")
        result = uploads.upload_session(self.session, self.config, "wigle", automatic=True, transport=fail)
        self.assertEqual(result["state"], "disabled")

    def test_wardrift_raw_csv_and_durable_receipt(self):
        self.wifi()
        calls = []
        def transport(url, headers, body):
            calls.append(url)
            self.assertEqual(headers["Content-Type"], "text/csv")
            self.assertTrue(body.startswith(b"WigleWifi-1.6"))
            return 200, {}, {"accepted": True}
        first = uploads.upload_session(self.session, self.config, "wardrift", transport=transport)
        second = uploads.upload_session(self.session, self.config, "wardrift", transport=transport)
        self.assertEqual(first["state"], "accepted")
        self.assertEqual(second["requests"], 0)
        self.assertEqual(calls, ["https://wardrift.net/v1/ingest/signals"])

    def test_wigle_acceptance_does_not_claim_processing_complete(self):
        self.wifi()
        def transport(url, headers, body):
            self.assertTrue(headers["Authorization"].startswith("Basic "))
            self.assertNotIn(b'name="donate"', body)
            return 200, {}, {"success": True, "results": {"transids": [{"transid": "tx_123"}]}}
        result = uploads.upload_session(self.session, self.config, "wigle", transport=transport)
        self.assertEqual(result["receipts"][0]["reason"], "queued_for_processing")

    def test_async_job_is_polled_without_repost(self):
        self.wifi()
        calls = []
        def transport(url, headers, body):
            calls.append((url, body is None))
            if body is not None:
                return 202, {}, {"ok": True, "job_id": 12, "poll_url": "https://evil.invalid/steal"}
            return 200, {}, {"status": "done", "result": {"imported": 1}}
        with patch.object(uploads.time, "time", return_value=1800000000):
            first = uploads.upload_session(self.session, self.config, "wdgwars", transport=transport)
        with patch.object(uploads.time, "time", return_value=1800000031):
            second = uploads.upload_session(self.session, self.config, "wdgwars", transport=transport)
        self.assertEqual(first["states"], {"pending": 1})
        self.assertEqual(second["state"], "accepted")
        self.assertEqual(calls[1], ("https://wdgwars.pl/api/v2/upload-job/12", True))

    def test_uncertain_transport_not_retried_and_no_secret_in_receipt(self):
        self.wifi()
        calls = []
        def transport(*args):
            calls.append(1)
            raise RuntimeError("TEST_TOKEN is deliberately secret")
        first = uploads.upload_session(self.session, self.config, "wardrift", transport=transport)
        uploads.upload_session(self.session, self.config, "wardrift", transport=transport)
        self.assertEqual(calls, [1])
        self.assertNotIn("TEST_TOKEN", json.dumps(first))
        self.assertEqual(first["states"], {"uncertain": 1})

    def test_429_retry_after_is_persistent(self):
        self.wifi()
        def transport(*args):
            return 429, {"retry-after": "3600"}, {"error": "quota"}
        with patch.object(uploads.time, "time", return_value=1800000000):
            first = uploads.upload_session(self.session, self.config, "wardrift", transport=transport)
        with patch.object(uploads.time, "time", return_value=1800000050):
            second = uploads.upload_session(self.session, self.config, "wardrift", transport=transport)
        self.assertEqual(first["receipts"][0]["next_attempt"], 1800003600)
        self.assertEqual(second["requests"], 0)

    def test_auth_failure_blocks_account_until_key_changes(self):
        self.wifi()
        def fail(*args):
            return 401, {}, {"error": "invalid"}
        uploads.upload_session(self.session, self.config, "wardrift", transport=fail)
        result = uploads.upload_session(self.session, self.config, "wardrift", transport=fail)
        self.assertEqual(result["requests"], 0)
        self.config["uploads"]["wardrift"]["api_key"] = "DIFFERENT_TEST_TOKEN"
        result = uploads.upload_session(self.session, self.config, "wardrift", transport=lambda *args: (200, {}, {"accepted": True}))
        self.assertEqual(result["state"], "accepted")

    def test_redirect_is_rejected(self):
        self.wifi()
        result = uploads.upload_session(self.session, self.config, "wardrift",
                                        transport=lambda *args: (302, {"location": "https://evil.invalid"}, {}))
        self.assertEqual(result["receipts"][0]["reason"], "redirect_refused")

    def test_checkpoint_must_be_saved_before_post(self):
        self.wifi()
        def fail(*args):
            self.fail("POST sent before durable checkpoint")
        with patch.object(uploads, "_atomic_json", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                uploads.upload_session(self.session, self.config, "wardrift", transport=fail)

    def test_interrupted_post_becomes_uncertain(self):
        self.wifi()
        def disconnect(*args):
            raise uploads.TransportFailure(True)
        first = uploads.upload_session(self.session, self.config, "wardrift", transport=disconnect)
        receipt = next((self.session / ".uploads" / "wardrift").rglob("*.json"))
        saved = json.loads(receipt.read_text())
        saved["state"] = "sending"
        receipt.write_text(json.dumps(saved))
        def should_not_send(*args):
            self.fail("interrupted upload must not be resent")
        result = uploads.upload_session(self.session, self.config, "wardrift", transport=should_not_send)
        self.assertEqual(first["states"], {"uncertain": 1})
        self.assertEqual(result["receipts"][0]["reason"], "interrupted_post")

    def test_connect_retries_stop_after_three_attempts(self):
        self.wifi()
        calls = []
        def unavailable(*args):
            calls.append(1)
            raise uploads.TransportFailure(False)
        for index in range(5):
            with patch.object(uploads.time, "time", return_value=1800000000 + index * 1000):
                result = uploads.upload_session(self.session, self.config, "wardrift", transport=unavailable)
        self.assertEqual(len(calls), 3)
        self.assertEqual(result["states"], {"failed": 1})

    def test_wdgwars_acceptance_preserves_zero_import_and_rejects(self):
        self.mesh([self.node()])
        result = uploads.upload_session(self.session, self.config, "wdgwars", transport=lambda *args:
                                        (200, {}, {"ok": True, "meshcore_imported": 0, "meshcore_rejected": 1}))
        self.assertEqual(result["receipts"][0]["counts"], {"meshcore_imported": 0, "meshcore_rejected": 1})
        self.assertEqual(result["receipts"][0]["reason"], "check_import_counts")

    def advance(self, services, transport, clock=None, **options):
        clock = clock or FakeClock()
        return uploads.advance_uploads(self.session, self.config, services, transport=transport,
                                       time_fn=clock.wall, monotonic_fn=clock.monotonic,
                                       sleep_fn=clock.sleep, **options)

    def test_advance_polls_pending_job_to_completion(self):
        self.wifi()
        clock, calls = FakeClock(), []
        def transport(url, headers, body):
            calls.append((clock.elapsed, body is None))
            if body is not None:
                return 202, {}, {"ok": True, "job_id": "job_12"}
            return 200, {}, {"status": "done", "result": {"imported": 1}}
        result = self.advance(["wdgwars"], transport, clock)
        self.assertEqual(result["state"], "accepted")
        self.assertEqual(result["stop_reason"], "complete")
        self.assertEqual(calls, [(0, False), (30, True)])
        self.assertEqual(result["requests"], 2)

    def test_advance_services_round_robin_while_job_waits(self):
        self.wifi()
        clock, calls = FakeClock(), []
        def transport(url, headers, body):
            calls.append(url)
            if "wdgwars" in url:
                return (202, {}, {"ok": True, "job_id": 13}) if body is not None else (200, {}, {"status": "done"})
            return 200, {}, {"accepted": True}
        result = self.advance(["wdgwars", "wardrift"], transport, clock)
        self.assertEqual(result["state"], "accepted")
        self.assertIn("wardrift.net", calls[1])
        self.assertIn("upload-job", calls[2])

    def artifacts(self, count):
        directory = self.session / "staged"
        directory.mkdir()
        artifacts = []
        for index in range(count):
            self.wifi([{"SSID": "fixture-%d" % index}])
            data = (self.session / "wifi.csv").read_bytes()
            artifacts.append(uploads._write_artifact(directory, "wifi", index, data, 1))
        return {"artifacts": artifacts}

    def test_advance_finishes_more_than_four_chunks(self):
        prepared = self.artifacts(6)
        calls = []
        def transport(*args):
            calls.append(1)
            return 200, {}, {"accepted": True}
        with patch.object(uploads, "prepare_session", return_value=prepared) as prepare:
            result = self.advance(["wardrift"], transport)
        prepare.assert_called_once()
        self.assertEqual(result["state"], "accepted")
        self.assertEqual(result["requests"], 6)
        self.assertEqual(len(calls), 6)

    def test_advance_enforces_32_requests_and_resumes_remaining(self):
        prepared = self.artifacts(34)
        transport = lambda *args: (200, {}, {"accepted": True})
        with patch.object(uploads, "prepare_session", return_value=prepared):
            first = self.advance(["wardrift"], transport)
            second = self.advance(["wardrift"], transport)
        self.assertEqual(first["state"], "incomplete")
        self.assertEqual(first["stop_reason"], "request_limit")
        self.assertEqual(first["requests"], 32)
        self.assertEqual(second["state"], "accepted")
        self.assertEqual(second["requests"], 2)

    def test_advance_deadline_preserves_pending_job_without_resubmit(self):
        self.wifi()
        clock, calls = FakeClock(), []
        def transport(url, headers, body):
            calls.append(body is None)
            if body is not None:
                return 202, {}, {"ok": True, "job_id": 14}
            return 200, {}, {"status": "processing"}
        first = self.advance(["wdgwars"], transport, clock, timeout=65)
        self.assertEqual(first["stop_reason"], "deadline")
        self.assertEqual(first["state"], "incomplete")
        self.assertEqual(first["services"]["wdgwars"]["states"], {"pending": 1})
        self.assertEqual(calls, [False, True, True])
        clock.elapsed = 91
        second = self.advance(["wdgwars"], lambda url, headers, body:
                              (200, {}, {"status": "done", "result": {"imported": 1}}), clock)
        self.assertEqual(second["state"], "accepted")
        self.assertEqual(second["requests"], 1)

    def test_advance_429_waits_until_retry_after(self):
        self.wifi()
        clock, calls = FakeClock(), []
        def transport(*args):
            calls.append(clock.elapsed)
            return (429, {"retry-after": "40"}, {}) if len(calls) == 1 else (200, {}, {"accepted": True})
        result = self.advance(["wardrift"], transport, clock)
        self.assertEqual(calls, [0, 40])
        self.assertEqual(clock.waits, [30, 10])
        self.assertEqual(result["state"], "accepted")

    def test_advance_long_429_delay_is_not_shortened(self):
        self.wifi()
        clock, calls = FakeClock(), []
        def transport(*args):
            calls.append(clock.elapsed)
            return 429, {"retry-after": "3600"}, {}
        result = self.advance(["wardrift"], transport, clock)
        self.assertEqual(calls, [0])
        self.assertEqual(clock.waits, [])
        self.assertEqual(result["stop_reason"], "deadline")
        receipt = result["services"]["wardrift"]["receipts"][0]
        self.assertEqual(receipt["next_attempt"], clock.wall() + 3600)

    def test_advance_retry_after_starts_when_response_arrives(self):
        self.wifi()
        clock, calls = FakeClock(), []
        def transport(*args):
            calls.append(clock.elapsed)
            if len(calls) == 1:
                clock.elapsed += 20
                return 429, {"retry-after": "40"}, {}
            return 200, {}, {"accepted": True}
        result = self.advance(["wardrift"], transport, clock)
        self.assertEqual(calls, [0, 60])
        self.assertEqual(result["state"], "accepted")

    def test_advance_passes_remaining_deadline_to_real_transport(self):
        prepared = self.artifacts(2)
        clock, budgets = FakeClock(), []
        def request(url, headers, body, timeout):
            budgets.append(timeout)
            clock.elapsed += 27 if len(budgets) == 1 else 2
            return 200, {}, {"accepted": True}
        with patch.object(uploads, "prepare_session", return_value=prepared), \
                patch.object(uploads, "_request", side_effect=request):
            result = self.advance(["wardrift"], None, clock, timeout=30)
        self.assertEqual(budgets, [30, 3])
        self.assertEqual(result["state"], "accepted")

    def test_advance_does_not_retry_uncertain_and_does_not_block_other_service(self):
        self.wifi()
        calls = []
        def transport(url, headers, body):
            calls.append(url)
            if "wigle.net" in url:
                raise uploads.TransportFailure(True)
            return 200, {}, {"accepted": True}
        result = self.advance(["wigle", "wardrift"], transport)
        self.assertEqual(len(calls), 2)
        self.assertEqual(result["stop_reason"], "blocked")
        self.assertEqual(result["services"]["wardrift"]["state"], "accepted")
        self.assertEqual(result["services"]["wigle"]["states"], {"uncertain": 1})

    def test_advance_zero_budget_and_disabled_services_do_not_send(self):
        self.wifi()
        def transport(*args):
            self.fail("transport must not run")
        result = self.advance(["wardrift"], transport, timeout=0)
        self.assertEqual(result["stop_reason"], "deadline")
        self.assertEqual(result["requests"], 0)
        result = self.advance(["wardrift"], transport, automatic=True)
        self.assertEqual(result["state"], "disabled")


if __name__ == "__main__":
    unittest.main()
