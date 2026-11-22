# Adapted from LORA-Pager-Pipe, copyright 2026 Valleytech Solutions.
# MIT license: see evil_lora_tunnel/LICENSE.
import hashlib
import hmac
import random
import struct
import unittest
from unittest.mock import Mock, patch


from evil_lora_tunnel.decode import (DecodeError, DEFAULT_MESHTASTIC_KEY, PUBLIC_MESHCORE_KEY,
                        decode_packet, protobuf_fields)
from evil_lora_tunnel import RadioError
from evil_lora_tunnel.lorapipe import LoRaPipeSerial, parse_rxlog
from evil_lora_tunnel.profiles import PROFILES, select_profiles

MT = PROFILES["meshtastic-US-LONG_FAST"]
MC = PROFILES["meshcore-US-NARROW"]


def varint(number):
    result = bytearray()
    while number > 127:
        result.append((number & 127) | 128)
        number >>= 7
    result.append(number)
    return bytes(result)


def blob(field, data):
    return varint(field << 3 | 2) + varint(len(data)) + data


def mt_frame(port, payload, *, encrypted=False):
    data = b"\x08" + varint(port) + blob(2, payload)
    if encrypted:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        encryptor = Cipher(algorithms.AES(DEFAULT_MESHTASTIC_KEY),
                           modes.CTR(bytes.fromhex("7856341200000000efcdab8900000000"))).encryptor()
        data = encryptor.update(data) + encryptor.finalize()
        channel_hash = 8  # LongFast XOR default PSK
    else:
        channel_hash = 10  # LongFast XOR empty PSK
    return struct.pack("<IIIBBBB", 0xffffffff, 0x89abcdef, 0x12345678, 0x63,
                       channel_hash, 0, 0) + data


PLAIN_KEY = [{"name": "LongFast", "key": ""}]


class DecoderTests(unittest.TestCase):
    def test_serial_command_requires_response_after_echo(self):
        radio = LoRaPipeSerial(MT, "/dev/ttyUSB0")
        radio._serial = Mock()
        with patch.object(radio, "_line", side_effect=[b"rxlog off\r\n", b"  -> Error\r\n"]):
            with self.assertRaises(RadioError):
                radio._command("rxlog off", b"rxlog off")
        with patch.object(radio, "_line", return_value=b"rxlog off\r  ->    rxlog off\r\n"):
            radio._command("rxlog off", b"rxlog off")

    def test_serial_renews_temporary_profile_before_expiry(self):
        radio = LoRaPipeSerial(MT, "/dev/ttyUSB0")
        radio._serial = Mock()
        with patch.object(radio, "_command") as command, patch("evil_lora_tunnel.lorapipe.time.sleep"):
            radio.tune(MT)
            self.assertEqual([step.args[0] for step in command.call_args_list],
                             ["rxlog off", "tempradio 906.875000,250,11,5,2b,5", "rxlog on"])
        with patch.object(radio, "tune") as retune, patch.object(radio, "_line", return_value=None):
            radio.receive()
            retune.assert_not_called()
            radio._renew_at = 0
            radio.receive()
            retune.assert_called_once_with(MT)

    def test_region_is_required(self):
        for region in (None, "", "UNSET", "US; command"):
            with self.assertRaises(ValueError):
                select_profiles(region)
        self.assertEqual([p.protocol for p in select_profiles("US", "both")],
                         ["meshtastic", "meshcore"])

    def test_plaintext_nodeinfo(self):
        body = blob(2, b"Test Radio") + blob(3, b"TEST") + b"\x38\x02"
        result = decode_packet(mt_frame(4, body), MT, meshtastic_keys=PLAIN_KEY)
        self.assertEqual(result["name"], "Test Radio")
        self.assertEqual(result["source_id"], "!89abcdef")
        self.assertEqual(result["role"], 2)
        self.assertEqual(result["node_type"], "router")
        self.assertNotIn("node_position", result)
        self.assertNotIn("hop_count", result)

    def test_proto3_default_role_and_explicit_sender_bitfield(self):
        frame = mt_frame(4, blob(2, b"Client")) + b"\x48\x00"
        result = decode_packet(frame, MT, meshtastic_keys=PLAIN_KEY)
        self.assertEqual(result["node_type"], "client")
        self.assertEqual(result["role"], 0)
        self.assertTrue(result["sender_bitfield_present"])
        self.assertEqual(result["sender_bitfield"], 0)
        without = decode_packet(mt_frame(4, blob(2, b"Old Client")), MT, meshtastic_keys=PLAIN_KEY)
        self.assertFalse(without["sender_bitfield_present"])

    def test_zero_longitude_is_valid_when_fields_present(self):
        body = b"\x0d" + struct.pack("<i", 515000000) + b"\x15" + struct.pack("<i", 0)
        result = decode_packet(mt_frame(3, body), MT, meshtastic_keys=PLAIN_KEY)
        self.assertEqual(result["node_position"], {"latitude": 51.5, "longitude": 0.0,
                                                  "source": "advertised"})

    def test_missing_coordinate_is_not_fabricated(self):
        body = b"\x0d" + struct.pack("<i", 515000000)
        result = decode_packet(mt_frame(3, body), MT, meshtastic_keys=PLAIN_KEY)
        self.assertNotIn("node_position", result)

    def test_meshtastic_known_key(self):
        try:
            frame = mt_frame(1, b"Radio test", encrypted=True)
        except ImportError:
            self.skipTest("cryptography is not installed")
        result = decode_packet(frame, MT)
        self.assertEqual(result["text"], "Radio test")
        self.assertFalse(result["payload_authenticated"])

    def test_unavailable_crypto_preserves_header(self):
        with patch("evil_lora_tunnel.decode._aes", return_value=None):
            frame = struct.pack("<IIIBBBB", 0xffffffff, 123, 42, 3, 8, 0, 0) + b"cipher"
            result = decode_packet(frame, MT)
        self.assertEqual(result["decode_status"], "crypto_unavailable")
        self.assertEqual(result["source_id"], "!0000007b")
        self.assertNotIn("text", result)

    def test_crypto_runtime_failure_preserves_meshtastic_header(self):
        frame = struct.pack("<IIIBBBB", 0xffffffff, 123, 42, 3, 8, 0, 0) + b"cipher"
        with patch("evil_lora_tunnel.decode._aes", side_effect=RuntimeError("native provider unavailable")):
            result = decode_packet(frame, MT)
        self.assertEqual(result["decode_status"], "crypto_unavailable")
        self.assertEqual(result["source_id"], "!0000007b")
        self.assertEqual(result["packet_id"], "0000002a")
        self.assertNotIn("text", result)

    def test_crypto_runtime_failure_preserves_meshcore_header(self):
        with patch("evil_lora_tunnel.decode._verify_ed25519", side_effect=RuntimeError("native provider unavailable")):
            result = decode_packet(b"\x11\x00" + bytes(100), MC)
        self.assertEqual(result["protocol"], "meshcore")
        self.assertEqual(result["decode_status"], "crypto_unavailable")
        self.assertEqual(result["public_key"], "00" * 32)
        self.assertIsNone(result["signature_valid"])
        self.assertNotIn("source_id", result)

    def test_bounded_protobuf(self):
        for data in (b"\x80" * 12, b"\x00", b"\x0a\xff\xff", b"\x0d\x01", b"\x0b"):
            with self.assertRaises(DecodeError):
                protobuf_fields(data)

    def _advert(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        key = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        timestamp = struct.pack("<I", 1700000000)
        app = b"\x92" + struct.pack("<ii", 35000000, -80000000) + b"TEST REPEATER"
        signature = private.sign(key + timestamp + app)
        return b"\x11\x02\xaa\xbb" + key + timestamp + signature + app

    def test_signed_meshcore_advert(self):
        try:
            packet = self._advert()
        except ImportError:
            self.skipTest("cryptography is not installed")
        result = decode_packet(packet, MC)
        self.assertTrue(result["signature_valid"])
        self.assertEqual(result["name"], "TEST REPEATER")
        self.assertEqual(result["hop_count"], 2)
        self.assertEqual(result["node_type"], "repeater")
        self.assertEqual(result["node_position"]["longitude"], -80.0)
        self.assertEqual(len(result["source_id"]), 64)

    def test_invalid_meshcore_signature_never_creates_identity(self):
        try:
            packet = bytearray(self._advert())
        except ImportError:
            self.skipTest("cryptography is not installed")
        packet[40] ^= 1
        result = decode_packet(bytes(packet), MC)
        self.assertEqual(result["decode_status"], "signature_invalid")
        for field in ("source_id", "name", "node_position"):
            self.assertNotIn(field, result)

    def test_meshcore_missing_crypto_is_explicit(self):
        with patch("evil_lora_tunnel.decode._verify_ed25519", return_value=None):
            result = decode_packet(b"\x11\x00" + bytes(100), MC)
        self.assertIsNone(result["signature_valid"])
        self.assertNotIn("source_id", result)

    def test_public_meshcore_message_and_bad_mac(self):
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except ImportError:
            self.skipTest("cryptography is not installed")
        plain = struct.pack("<I", 1700000000) + b"\x00Alice: test\x00"
        plain += bytes((-len(plain)) % 16)
        enc = Cipher(algorithms.AES(PUBLIC_MESHCORE_KEY), modes.ECB()).encryptor()
        cipher = enc.update(plain) + enc.finalize()
        mac = hmac.new(PUBLIC_MESHCORE_KEY, cipher, hashlib.sha256).digest()[:2]
        packet = b"\x15\x00" + hashlib.sha256(PUBLIC_MESHCORE_KEY).digest()[:1] + mac + cipher
        result = decode_packet(packet, MC)
        self.assertEqual(result["text"], "Alice: test")
        self.assertEqual(result["channel_name"], "Public")
        self.assertNotIn("source_id", result)  # A displayed name is not an authenticated node key.
        bad = bytearray(packet)
        bad[3] ^= 1
        self.assertEqual(decode_packet(bytes(bad), MC)["decode_status"], "encrypted")

    def test_direct_route_count_is_not_advert_hop_count(self):
        packet = b"\x0e\x01\xaa\x01\x02\x03\x04"
        result = decode_packet(packet, MC)
        self.assertEqual(result["path_count"], 1)
        self.assertNotIn("hop_count", result)

    def test_rxlog_timestamp_and_validation(self):
        line = "1700000000,RXLOG,-102.50,-7.25,11223344\r\n"
        result = parse_rxlog(line, MT, timestamp=1710000000.25)
        self.assertEqual(result["timestamp"], 1710000000.25)
        self.assertEqual(result["receiver_timestamp"], 1700000000)
        self.assertIsNone(result["crc_ok"])
        self.assertIsNone(result["profile"]["preamble_symbols"])
        self.assertNotIn("decoded", result)
        for invalid in (line.replace("11223344", "123"), line.replace("-7.25", "nan"),
                        line.replace("-102.50", "-999"), "x" * 2048, b"\xff"):
            self.assertIsNone(parse_rxlog(invalid, MT))

    def test_malformed_packet_fuzz(self):
        rng = random.Random(42)
        for _ in range(4000):
            payload = rng.randbytes(rng.randrange(0, 270))
            for profile in (MT, MC):
                result = decode_packet(payload, profile)
                self.assertIn("protocol", result)
                self.assertIn("decode_status", result)
