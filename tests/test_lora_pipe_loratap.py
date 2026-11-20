# Adapted from LORA-Pager-Pipe, copyright 2026 Valleytech Solutions.
# MIT license: see evil_lora_tunnel/LICENSE.
import struct
import tempfile
import unittest
from pathlib import Path


from evil_lora_tunnel.loratap import PCAPWriter, encode_loratap
from evil_lora_tunnel.profiles import PROFILES


def record(profile="meshtastic-US-LONG_FAST", crc=True):
    return {"profile": PROFILES[profile].to_dict(), "timestamp": 1700000000.25,
            "raw_hex": "0102ff", "rssi_dbm": -100.5, "snr_db": -7.25, "crc_ok": crc}


class LoRaTAPTests(unittest.TestCase):
    def test_v1_header_layout(self):
        frame = encode_loratap(record())
        self.assertEqual(len(frame), 38)
        self.assertEqual(frame[:4], b"\x01\x00\x00\x23")
        self.assertEqual(struct.unpack(">I", frame[4:8])[0], 906875000)
        self.assertEqual(frame[8:15], bytes([2, 11, 39, 255, 255, 227, 0x2B]))
        self.assertEqual(frame[15:27], bytes(12))
        self.assertEqual(frame[27], 0x08)
        self.assertEqual(frame[28], 5)
        self.assertEqual(frame[35:], b"\x01\x02\xff")

    def test_narrow_bandwidth_and_unknown_crc_are_not_fabricated(self):
        frame = encode_loratap(record("meshcore-US-NARROW", None))
        self.assertEqual(frame[8], 0)
        self.assertEqual(frame[27], 0)
        self.assertEqual(frame[14], 0x12)
        self.assertEqual(encode_loratap(record(crc=False))[27], 0x10)

    def test_pcap_header_and_timestamps(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lora.pcap"
            with PCAPWriter(path) as writer:
                writer.append(record())
                writer.flush()
                self.assertEqual(writer.count, 1)
            data = path.read_bytes()
            self.assertEqual(data[:4], b"\xd4\xc3\xb2\xa1")
            self.assertEqual(struct.unpack("<I", data[20:24])[0], 270)
            self.assertEqual(struct.unpack("<IIII", data[24:40]), (1700000000, 250000, 38, 38))
            self.assertEqual(data[40:], encode_loratap(record()))
            with self.assertRaises(FileExistsError):
                PCAPWriter(path)
            self.assertEqual(path.read_bytes(), data)

    def test_invalid_record_does_not_append_partial_frame(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lora.pcap"
            with PCAPWriter(path) as writer:
                for invalid in (dict(record(), raw_hex="0"), dict(record(), timestamp=float("nan")),
                                dict(record(), snr_db=float("inf"))):
                    with self.assertRaises(ValueError):
                        writer.append(invalid)
                self.assertEqual(writer.count, 0)
            self.assertEqual(len(path.read_bytes()), 24)


if __name__ == "__main__":
    unittest.main()
