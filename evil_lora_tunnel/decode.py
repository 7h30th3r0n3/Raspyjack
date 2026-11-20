"""Bounded on-air decoders; radio capture and key availability are independent.

Wire formats: Meshtastic protobufs/mesh.proto and MeshCore docs/packet_format.md,
docs/payloads.md. This is independent Python code, not a translation of Kismet.
The cryptography package supplies AES and Ed25519. PyCryptodome and PyNaCl
are alternative providers. Recording preserves raw bytes without a provider.
"""

import base64
import hashlib
import hmac
import math
import struct


class DecodeError(ValueError):
    pass


DEFAULT_MESHTASTIC_KEY = bytes.fromhex("d4f1bb3a20290759f0bcffabcf4e6901")
PUBLIC_MESHCORE_KEY = base64.b64decode("izOH6cXN6mrJ5e26oRXNcg==")
MT_CHANNELS = ("LongFast", "LongSlow", "LongTurbo", "LongModerate", "MediumFast",
               "MediumSlow", "ShortFast", "ShortSlow", "ShortTurbo")


def _varint(data, pos):
    value = 0
    for shift in range(0, 70, 7):
        if pos >= len(data):
            raise DecodeError("Truncated varint")
        byte = data[pos]
        pos += 1
        if shift == 63 and byte > 1:
            raise DecodeError("Varint overflow")
        value |= (byte & 127) << shift
        if byte < 128:
            return value, pos
    raise DecodeError("Varint overflow")


def protobuf_fields(data):
    """Parse one bounded protobuf message, retaining wire types for validation."""
    if len(data) > 255:
        raise DecodeError("Oversize protobuf message")
    fields, pos, count = {}, 0, 0
    while pos < len(data):
        count += 1
        if count > 96:
            raise DecodeError("Too many protobuf fields")
        tag, pos = _varint(data, pos)
        number, wire = tag >> 3, tag & 7
        if not 1 <= number <= 0x1FFFFFFF:
            raise DecodeError("Invalid protobuf tag")
        if wire == 0:
            value, pos = _varint(data, pos)
        elif wire in {1, 5}:
            size = 8 if wire == 1 else 4
            if pos + size > len(data):
                raise DecodeError("Truncated fixed field")
            value = data[pos:pos + size]
            pos += size
        elif wire == 2:
            size, pos = _varint(data, pos)
            if size > len(data) - pos:
                raise DecodeError("Truncated length-delimited field")
            value = data[pos:pos + size]
            pos += size
        else:
            raise DecodeError("Unsupported protobuf wire type")
        # These protobufs have scalar fields; last scalar occurrence wins.
        fields[number] = (wire, value)
    return fields


def _field(fields, number, wire, default=None):
    if number not in fields:
        return default
    actual_wire, value = fields[number]
    if actual_wire != wire:
        raise DecodeError("Incorrect protobuf wire type")
    return value


def _text(raw, limit=240):
    if len(raw) > limit:
        raise DecodeError("Oversize text")
    value = raw.decode("utf-8", "strict").rstrip("\x00")
    return "".join(c if c.isprintable() or c in "\n\t" else "\ufffd" for c in value)


def _position(lat, lon):
    if not (math.isfinite(lat) and math.isfinite(lon) and -90 <= lat <= 90 and -180 <= lon <= 180):
        raise DecodeError("Invalid advertised position")
    return {"latitude": lat, "longitude": lon, "source": "advertised"}


def _aes(key, payload, nonce=None):
    try:
        from Crypto.Cipher import AES
        if nonce is None:
            return AES.new(key, AES.MODE_ECB).decrypt(payload)
        return AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(nonce, "big")).decrypt(payload)
    except Exception:
        # An installed package can still lack a usable native crypto provider.
        # Try the other supported provider without surfacing key-bearing errors.
        pass
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        mode = modes.ECB() if nonce is None else modes.CTR(nonce)
        decryptor = Cipher(algorithms.AES(key), mode).decryptor()
        return decryptor.update(payload) + decryptor.finalize()
    except Exception:
        return None


def _crypto_call(operation, *args):
    """Keep optional provider failures separate from malformed radio frames."""
    try:
        return operation(*args)
    except Exception:
        return None


def _verify_ed25519(key, message, signature):
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    except Exception:
        try:
            from nacl.signing import VerifyKey
            from nacl.exceptions import BadSignatureError
        except ImportError:
            return None
        try:
            VerifyKey(key).verify(message, signature)
            return True
        except (ValueError, BadSignatureError):
            return False
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
        return True
    except UnsupportedAlgorithm:
        return None
    except (ValueError, InvalidSignature):
        return False


def _key_bytes(value, protocol):
    key = value if isinstance(value, bytes) else base64.b64decode(value, validate=True)
    if protocol == "meshtastic" and len(key) == 1 and key[0] != 0:
        return DEFAULT_MESHTASTIC_KEY[:-1] + bytes([(DEFAULT_MESHTASTIC_KEY[-1] + key[0] - 1) & 255])
    if protocol == "meshtastic" and key in {b"", b"\x00"}:
        return b""
    if len(key) not in {16, 32}:
        raise ValueError("Channel keys must be 16 or 32 bytes")
    return key


def _keys(user_keys, protocol):
    # Keys are input only. Neither return records nor errors contain them.
    defaults = [(name, DEFAULT_MESHTASTIC_KEY) for name in MT_CHANNELS] if protocol == "meshtastic" else [("Public", PUBLIC_MESHCORE_KEY)]
    configured = {}
    for item in (user_keys or [])[:32]:
        try:
            name = item["name"]
            if not isinstance(name, str) or not 1 <= len(name) <= 32:
                continue
            configured[name] = _key_bytes(item["key"], protocol)
        except (ValueError, TypeError, KeyError):
            continue
    result = dict(defaults)
    result.update(configured)
    return result.items()


def _mt_hash(name, key):
    result = 0
    for byte in name.encode("utf-8") + key:
        result ^= byte
    return result


def _decode_mt_data(plaintext):
    fields = protobuf_fields(plaintext)
    port = _field(fields, 1, 0)
    body = _field(fields, 2, 2, b"")
    if port is None or not 1 <= port <= 511:
        raise DecodeError("Missing or invalid application port")
    result = {"portnum": port, "payload_hex": body.hex()}
    bitfield = _field(fields, 9, 0)
    result["sender_bitfield_present"] = bitfield is not None
    if bitfield is not None:
        result["sender_bitfield"] = bitfield
    if port == 1:
        result["text"] = _text(body)
    elif port == 4:
        info = protobuf_fields(body)
        for field, name, limit in ((2, "name", 80), (3, "short_name", 16)):
            raw = _field(info, field, 2)
            if raw is not None:
                result[name] = _text(raw, limit)
        # Proto3 User.role defaults to CLIENT=0 when omitted. This applies only
        # to decoded NodeInfo; other packet types do not imply a node role.
        role = _field(info, 7, 0, 0)
        result["role"] = role
        roles = ("client", "client_mute", "router", "router_client", "repeater",
                 "tracker", "sensor", "tak", "client_hidden", "lost_and_found",
                 "tak_tracker", "router_late", "client_base")
        if role < len(roles):
            result["node_type"] = roles[role]
        model = _field(info, 5, 0)
        if model is not None:
            result["hardware_model"] = model
    elif port == 3:
        info = protobuf_fields(body)
        lat, lon = _field(info, 1, 5), _field(info, 2, 5)
        if lat is not None and lon is not None:
            result["node_position"] = _position(struct.unpack("<i", lat)[0] / 1e7,
                                                  struct.unpack("<i", lon)[0] / 1e7)
        timestamp = _field(info, 4, 5)
        if timestamp is not None:
            result["advertised_timestamp"] = int.from_bytes(timestamp, "little")
    elif port == 67:
        telemetry = protobuf_fields(body)
        device = _field(telemetry, 2, 2)
        if device is not None:
            values, metrics = protobuf_fields(device), {}
            for field, name in ((1, "battery_percent"), (5, "uptime_seconds")):
                value = _field(values, field, 0)
                if value is not None:
                    metrics[name] = value
            for field, name in ((2, "voltage"), (3, "channel_utilization"), (4, "air_util_tx")):
                value = _field(values, field, 5)
                if value is not None:
                    scalar = struct.unpack("<f", value)[0]
                    if math.isfinite(scalar):
                        metrics[name] = scalar
            result["telemetry"] = metrics
    return result


def _meshtastic(raw, keys):
    if len(raw) <= 16:
        raise DecodeError("Truncated Meshtastic frame")
    destination, source, packet_id, flags, channel, next_hop, relay = struct.unpack("<IIIBBBB", raw[:16])
    if source in {0, 0xFFFFFFFF}:
        raise DecodeError("Invalid Meshtastic source")
    result = {"protocol": "meshtastic", "decode_status": "encrypted",
              "source_id": "!%08x" % source, "destination_id": "!%08x" % destination,
              "packet_id": "%08x" % packet_id, "hop_limit": flags & 7,
              "hop_start": flags >> 5, "want_ack": bool(flags & 8),
              "via_mqtt": bool(flags & 16), "channel_hash": channel,
              "next_hop": next_hop, "relay_node": relay}
    # Do not infer the physical transmitter from the original source address.
    nonce = struct.pack("<QII", packet_id, source, 0)
    unavailable = False
    for name, key in _keys(keys, "meshtastic"):
        if _mt_hash(name, key) != channel:
            continue
        plain = _crypto_call(_aes, key, raw[16:], nonce) if key else raw[16:]
        if plain is None:
            unavailable = True
            continue
        try:
            payload = _decode_mt_data(plain)
        except (DecodeError, UnicodeDecodeError):
            continue
        result.update(payload)
        result.update(decode_status="decoded", channel_name=name,
                      payload_authenticated=False,
                      encryption="aes-ctr" if key else "none")
        return result
    if unavailable:
        result["decode_status"] = "crypto_unavailable"
    return result


def _meshcore(raw, keys):
    if len(raw) < 3 or raw[0] >> 6:
        raise DecodeError("Unsupported MeshCore frame")
    route, kind = raw[0] & 3, (raw[0] >> 2) & 15
    if kind not in {*range(12), 15}:
        raise DecodeError("Unknown MeshCore payload type")
    index = 5 if route in {0, 3} else 1
    if index >= len(raw):
        raise DecodeError("Truncated transport header")
    path_info = raw[index]
    count, hash_size = path_info & 63, 1 + (path_info >> 6)
    path_size = count * hash_size
    if hash_size > 3 or path_size > 64 or index + 1 + path_size >= len(raw):
        raise DecodeError("Invalid MeshCore path")
    path = raw[index + 1:index + 1 + path_size]
    payload = raw[index + 1 + path_size:]
    if len(payload) > 184:
        raise DecodeError("Oversize MeshCore payload")
    result = {"protocol": "meshcore", "decode_status": "header_only", "route_type": route,
              "payload_type": kind, "path_hash_size": hash_size, "path_count": count,
              "path_hex": path.hex()}
    if route in {0, 1}:
        result["hop_count"] = count
    if kind == 4:
        if not 100 <= len(payload) <= 132:
            raise DecodeError("Invalid MeshCore advertisement length")
        key, stamp, signature, app = payload[:32], payload[32:36], payload[36:100], payload[100:]
        valid = _crypto_call(_verify_ed25519, key, key + stamp + app, signature)
        result.update(public_key=key.hex(), signature_valid=valid,
                      advertised_timestamp=int.from_bytes(stamp, "little"))
        if valid is not True:
            result["decode_status"] = "crypto_unavailable" if valid is None else "signature_invalid"
            return result
        result.update(source_id=key.hex(), decode_status="decoded")
        if not app:
            return result
        flags, cursor = app[0], 1
        result["node_type"] = {1: "companion", 2: "repeater", 3: "room_server", 4: "sensor"}.get(flags & 15, "unknown")
        if flags & 0x10:
            if cursor + 8 > len(app):
                raise DecodeError("Truncated advert location")
            lat, lon = struct.unpack("<ii", app[cursor:cursor + 8])
            cursor += 8
            # MeshCore uses both zero as no-location sentinel.
            if lat != 0 or lon != 0:
                result["node_position"] = _position(lat / 1e6, lon / 1e6)
        cursor += (2 if flags & 0x20 else 0) + (2 if flags & 0x40 else 0)
        if cursor > len(app):
            raise DecodeError("Truncated advert feature fields")
        if flags & 0x80:
            result["name"] = _text(app[cursor:], 32)
        return result
    if kind in {0, 1, 2, 8, 7, 5, 6}:
        prefix = 33 if kind == 7 else (1 if kind in {5, 6} else 2)
        if len(payload) < prefix + 18 or (len(payload) - prefix - 2) % 16:
            raise DecodeError("Invalid MeshCore encrypted length")
        result["decode_status"] = "encrypted"
        if kind not in {5, 6}:
            result["destination_hash"] = payload[:1].hex()
            if prefix == 2:
                result["source_hash"] = payload[1:2].hex()
            return result
        result["channel_hash"] = payload[0]
        cipher, mac = payload[3:], payload[1:3]
        for name, key in _keys(keys, "meshcore"):
            if hashlib.sha256(key).digest()[0] != payload[0]:
                continue
            if not hmac.compare_digest(hmac.new(key, cipher, hashlib.sha256).digest()[:2], mac):
                continue
            plain = _crypto_call(_aes, key[:16], cipher)
            if plain is None:
                result["decode_status"] = "crypto_unavailable"
                return result
            result.update(channel_name=name, decode_status="decoded", payload_authenticated=True,
                          authentication="truncated_hmac_sha256", payload_hex=plain.hex())
            if kind == 5:
                if len(plain) < 5 or plain[4] >> 2:
                    raise DecodeError("Unsupported MeshCore group text")
                result["message_timestamp"] = int.from_bytes(plain[:4], "little")
                result["text"] = _text(plain[5:].split(b"\x00", 1)[0])
            return result
        return result
    if kind == 3 and len(payload) < 4:
        raise DecodeError("Truncated MeshCore ACK")
    if kind == 9 and len(payload) < 9:
        raise DecodeError("Truncated MeshCore trace")
    return result


def decode_packet(raw, profile, *, meshtastic_keys=None, meshcore_keys=None):
    """Decode one packet without allowing malformed input to escape capture."""
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 255:
        return {"protocol": "unknown", "decode_status": "malformed"}
    try:
        protocol = profile.protocol if hasattr(profile, "protocol") else profile.get("protocol")
        if protocol == "meshtastic":
            return _meshtastic(raw, meshtastic_keys)
        if protocol == "meshcore":
            return _meshcore(raw, meshcore_keys)
        return {"protocol": "unknown", "decode_status": "raw"}
    except (DecodeError, UnicodeDecodeError, ValueError, struct.error, IndexError):
        return {"protocol": "unknown", "decode_status": "malformed"}
