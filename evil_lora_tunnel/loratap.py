"""Independent LoRaTAP v1 / classic PCAP serializer.

Format reference: Wireshark epan/dissectors/packet-loratap.c, LoRaTAP v1
(35 bytes), and tcpdump's LINKTYPE_LORATAP registration (270). No upstream
implementation is copied. LoRaTAP cannot represent 62.5 kHz bandwidth, GPS,
or decoded mesh fields; retain the companion JSONL/SQLite observations.
"""

import math
import os
import struct

LINKTYPE_LORATAP = 270
HEADER_SIZE = 35
SNAPLEN = HEADER_SIZE + 255


def _number(value, name):
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
        raise ValueError("Invalid " + name)
    return value


def _integer(value, lower, upper, name):
    value = _number(value, name)
    if value != int(value) or not lower <= value <= upper:
        raise ValueError("Invalid " + name)
    return int(value)


def _rssi(value):
    if value is None:
        return 255  # LoRaTAP's explicit N/A value
    value = _number(value, "RSSI")
    return min(254, max(0, int(math.floor(value + 139 + 0.5))))


def encode_loratap(record):
    """Return one LoRaTAP frame; exact modem metadata remains in the record."""
    encoded = record["raw_hex"]
    if not isinstance(encoded, str) or not 2 <= len(encoded) <= 510 or len(encoded) % 2:
        raise ValueError("Invalid raw packet")
    raw = bytes.fromhex(encoded)
    if not 1 <= len(raw) <= 255:
        raise ValueError("Invalid raw packet")
    profile = record["profile"]
    frequency = _integer(profile["frequency_hz"], 1, 0xFFFFFFFF, "frequency")
    bandwidth = _integer(profile["bandwidth_hz"], 1, 1000000, "bandwidth")
    sf = _integer(profile["spreading_factor"], 5, 12, "spreading factor")
    cr = _integer(profile["coding_rate"], 5, 8, "coding rate")
    sync = _integer(profile["sync_word"], 0, 255, "sync word")
    bw = {125000: 1, 250000: 2, 500000: 4}.get(bandwidth, 0)
    snr = _number(record["snr_db"], "SNR") * 4
    snr = min(127, max(-128, int(math.floor(snr + 0.5) if snr >= 0 else math.ceil(snr - 0.5)))) & 255
    # Unknown CRC state is zero, distinct from explicitly having no air CRC.
    crc = record.get("crc_ok")
    flags = 0x08 if crc is True else (0x10 if crc is False else 0)
    prefix = struct.pack(">BBHI7B", 1, 0, HEADER_SIZE, frequency, bw, sf,
                         _rssi(record.get("rssi_dbm")), 255, 255, snr, sync)
    # No gateway EUI or concentrator tick counter is available. Do not substitute
    # receiver GPS, node identity or Unix seconds into those hardware fields.
    extension = struct.pack(">QIBBHBBH", 0, 0, flags, cr, 0, 0, 0, 0)
    return prefix + extension + raw


class PCAPWriter:
    """Create a new buffered PCAP; append never truncates an existing session."""

    def __init__(self, path):
        self._stream = open(path, "xb", buffering=65536)
        try:
            os.chmod(path, 0o600)
            # Little-endian PCAP 2.4, microsecond timestamps, full LoRa frames.
            self._stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, SNAPLEN,
                                           LINKTYPE_LORATAP))
        except Exception:
            self._stream.close()
            raise
        self.count = 0

    def append(self, record):
        if self._stream.closed:
            raise ValueError("PCAP is closed")
        timestamp = _number(record["timestamp"], "capture timestamp")
        if not 0 <= timestamp < 0x100000000:
            raise ValueError("Capture timestamp is outside PCAP range")
        seconds = int(timestamp)
        micros = min(999999, int((timestamp - seconds) * 1000000))
        frame = encode_loratap(record)
        self._stream.write(struct.pack("<IIII", seconds, micros, len(frame), len(frame)) + frame)
        self.count += 1

    def flush(self):
        if not self._stream.closed:
            self._stream.flush()
            os.fsync(self._stream.fileno())

    def close(self):
        if not self._stream.closed:
            try:
                self.flush()
            finally:
                self._stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
