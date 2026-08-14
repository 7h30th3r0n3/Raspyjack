"""
Shared NFC driver for RaspyJack NFC suite.
Supports PN532 (UART/I2C), nfcpy USB readers, Proxmark3, and Chameleon Ultra.
"""

import os
import re
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Optional, List, Tuple

try:
    import smbus2 as smbus
    SMBUS_OK = True
except ImportError:
    try:
        import smbus
        SMBUS_OK = True
    except ImportError:
        smbus = None
        SMBUS_OK = False

try:
    import serial
    SERIAL_OK = True
except ImportError:
    serial = None
    SERIAL_OK = False

try:
    import nfc as nfcpy
    NFCPY_OK = True
except ImportError:
    nfcpy = None
    NFCPY_OK = False

# PN532 protocol constants
PREAMBLE = 0x00
STARTCODE1 = 0x00
STARTCODE2 = 0xFF
HOST_TO_PN532 = 0xD4
PN532_TO_HOST = 0xD5

# Commands
CMD_GET_FIRMWARE = 0x02
CMD_GET_STATUS = 0x04
CMD_SAM_CONFIG = 0x14
CMD_RF_CONFIGURATION = 0x32
CMD_IN_LIST_PASSIVE = 0x4A
CMD_IN_DATA_EXCHANGE = 0x40
CMD_IN_COMMUNICATE_THRU = 0x42
CMD_IN_AUTO_POLL = 0x60
CMD_TG_INIT_AS_TARGET = 0x8C
CMD_TG_GET_DATA = 0x86
CMD_TG_SET_DATA = 0x8E

# MIFARE commands (via InDataExchange)
MIFARE_AUTH_A = 0x60
MIFARE_AUTH_B = 0x61
MIFARE_READ = 0x30
MIFARE_WRITE = 0xA0
MIFARE_UL_WRITE = 0xA2
MIFARE_INCREMENT = 0xC1
MIFARE_DECREMENT = 0xC0
MIFARE_TRANSFER = 0xB0

I2C_ADDR = 0x24
UART_PORTS = ["/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyAMA0"]
UART_BAUDS = [115200, 9600]


@dataclass
class CardInfo:
    uid: bytes = b""
    atqa: int = 0
    sak: int = 0
    card_type: str = "Unknown"
    tech: str = "ISO14443A"
    uid_hex: str = ""

    def __post_init__(self):
        self.uid_hex = self.uid.hex().upper() if self.uid else ""
        if not self.card_type or self.card_type == "Unknown":
            self.card_type = identify_card(self.atqa, self.sak, len(self.uid))


def identify_card(atqa: int, sak: int, uid_len: int) -> str:
    """Identify card type from ATQA, SAK, and UID length."""
    if sak == 0x08 and uid_len == 4:
        return "MIFARE Classic 1K"
    if sak == 0x18:
        return "MIFARE Classic 4K"
    if sak == 0x09:
        return "MIFARE Mini"
    if sak == 0x00 and uid_len == 7:
        return "MIFARE Ultralight"
    if sak == 0x00 and uid_len == 4:
        return "MIFARE Ultralight C"
    if sak == 0x20 and atqa in (0x0344, 0x0304):
        return "NTAG/DESFire"
    if sak == 0x20 and atqa == 0x0048:
        return "ISO 14443-4 (EMV)"
    if sak == 0x20:
        return "MIFARE Plus/DESFire"
    if sak == 0x01:
        return "TNP3XXX"
    if uid_len == 4:
        return "MIFARE Classic"
    if uid_len == 7:
        return "MIFARE UL/NTAG"
    if uid_len == 10:
        return "MIFARE DESFire"
    return "Unknown"


def is_classic(card: CardInfo) -> bool:
    return "Classic" in card.card_type or "Mini" in card.card_type

def is_ultralight(card: CardInfo) -> bool:
    return "Ultralight" in card.card_type or "NTAG" in card.card_type

def is_desfire(card: CardInfo) -> bool:
    return "DESFire" in card.card_type

def is_emv(card: CardInfo) -> bool:
    return "EMV" in card.card_type or (card.sak == 0x20 and card.atqa == 0x0048)


class _PN532Base:
    """Base class with shared PN532 protocol logic."""
    can_write = True
    can_emulate = True

    def _parse_response(self, resp, cmd_reply):
        if resp is None:
            return None
        for i in range(len(resp) - 2):
            if resp[i] == PN532_TO_HOST and resp[i + 1] == cmd_reply:
                return resp[i:]
        return None

    def _write_frame(self, data):
        raise NotImplementedError

    def _read_response(self, expected_len=32, timeout=1.0):
        raise NotImplementedError

    def close(self):
        pass

    def get_firmware(self) -> Optional[Tuple[int, int, int, int]]:
        self._write_frame([CMD_GET_FIRMWARE])
        resp = self._read_response(12)
        p = self._parse_response(resp, 0x03)
        if p and len(p) >= 6:
            return (p[2], p[3], p[4], p[5])
        return None

    def sam_config(self):
        self._write_frame([CMD_SAM_CONFIG, 0x01, 0x14, 0x01])
        self._read_response(12)

    def read_passive_target(self, card_type=0x00, timeout=2.0) -> Optional[CardInfo]:
        """Detect a card. Returns CardInfo with UID, ATQA, SAK."""
        self._write_frame([CMD_IN_LIST_PASSIVE, 0x01, card_type])
        resp = self._read_response(32, timeout=timeout)
        p = self._parse_response(resp, 0x4B)
        if p is None or len(p) < 8 or p[2] < 1:
            return None
        atqa = (p[4] << 8) | p[5]
        sak = p[6]
        uid_len = p[7]
        if len(p) < 8 + uid_len:
            return None
        uid = bytes(p[8:8 + uid_len])
        return CardInfo(uid=uid, atqa=atqa, sak=sak)

    def mifare_auth(self, block: int, key: bytes, uid: bytes, key_type: int = MIFARE_AUTH_A) -> bool:
        cmd = [CMD_IN_DATA_EXCHANGE, 0x01, key_type, block] + list(key) + list(uid[:4])
        self._write_frame(cmd)
        resp = self._read_response(12)
        p = self._parse_response(resp, 0x41)
        return p is not None and len(p) >= 3 and p[2] == 0x00

    def mifare_read(self, block: int) -> Optional[bytes]:
        self._write_frame([CMD_IN_DATA_EXCHANGE, 0x01, MIFARE_READ, block])
        resp = self._read_response(32)
        p = self._parse_response(resp, 0x41)
        if p and len(p) >= 19 and p[2] == 0x00:
            return bytes(p[3:19])
        return None

    def mifare_write(self, block: int, data: bytes) -> bool:
        cmd = [CMD_IN_DATA_EXCHANGE, 0x01, MIFARE_WRITE, block] + list(data[:16])
        self._write_frame(cmd)
        resp = self._read_response(12, timeout=2.0)
        p = self._parse_response(resp, 0x41)
        return p is not None and len(p) >= 3 and p[2] == 0x00

    def mifare_ul_read(self, page: int) -> Optional[bytes]:
        """Read 4 pages (16 bytes) from Ultralight/NTAG starting at page."""
        self._write_frame([CMD_IN_DATA_EXCHANGE, 0x01, MIFARE_READ, page])
        resp = self._read_response(32)
        p = self._parse_response(resp, 0x41)
        if p and len(p) >= 19 and p[2] == 0x00:
            return bytes(p[3:19])
        return None

    def mifare_ul_write(self, page: int, data: bytes) -> bool:
        """Write 1 page (4 bytes) to Ultralight/NTAG."""
        cmd = [CMD_IN_DATA_EXCHANGE, 0x01, MIFARE_UL_WRITE, page] + list(data[:4])
        self._write_frame(cmd)
        resp = self._read_response(12, timeout=2.0)
        p = self._parse_response(resp, 0x41)
        return p is not None and len(p) >= 3 and p[2] == 0x00

    def communicate_thru(self, data: bytes, timeout=1.0) -> Optional[bytes]:
        """Send raw data through the RF field (for APDU/EMV)."""
        cmd = [CMD_IN_COMMUNICATE_THRU] + list(data)
        self._write_frame(cmd)
        resp = self._read_response(64, timeout=timeout)
        p = self._parse_response(resp, 0x43)
        if p and len(p) >= 3 and p[2] == 0x00:
            return bytes(p[3:])
        return None

    def data_exchange(self, data: bytes, timeout=1.0) -> Optional[bytes]:
        """InDataExchange with raw payload."""
        cmd = [CMD_IN_DATA_EXCHANGE, 0x01] + list(data)
        self._write_frame(cmd)
        resp = self._read_response(64, timeout=timeout)
        p = self._parse_response(resp, 0x41)
        if p and len(p) >= 3 and p[2] == 0x00:
            return bytes(p[3:])
        return None

    def in_communicate_thru_raw(self, data: bytes, timeout=0.5) -> Optional[bytes]:
        """Send raw bytes via InCommunicateThru (no target number). For magic card backdoor."""
        cmd = [0x42] + list(data)
        self._write_frame(cmd)
        resp = self._read_response(32, timeout=timeout)
        p = self._parse_response(resp, 0x43)
        if p and len(p) >= 2:
            return bytes(p[2:])
        return None

    def init_as_target(self, uid: bytes, atqa: bytes = b"\x04\x00", sak: int = 0x08, timeout: float = 1.0) -> Optional[bytes]:
        """Initialize PN532 as a passive MIFARE target (card emulation).
        Reader sees UID as [SEL_RES, NFCID1t[0], NFCID1t[1], NFCID1t[2]].
        To emit exact 4-byte UID: uid[0] -> SEL_RES, uid[1:4] -> NFCID1t.
        """
        mode = 0x04
        sens_res = [atqa[1], atqa[0]] if len(atqa) >= 2 else [0x04, 0x00]
        # Reader sees: [NFCID1t[0], NFCID1t[1], NFCID1t[2], SEL_RES]
        # So put uid[0:3] as NFCID1t and uid[3] as SEL_RES
        if len(uid) >= 4:
            nfcid1t = list(uid[:3])
            sel_res = uid[3]
        else:
            nfcid1t = list(uid[:3]) if len(uid) >= 3 else [0x01, 0x02, 0x03]
            sel_res = sak
        mifare_params = sens_res + nfcid1t + [sel_res]
        felica_params = [0x01, 0xFE] + [0x00] * 16
        nfcid3 = list(uid[:3]) + [0x00] * 7
        cmd = [CMD_TG_INIT_AS_TARGET, mode] + mifare_params + felica_params + nfcid3 + [0x00, 0x00]
        self._write_frame(cmd)
        resp = self._read_response(32, timeout=timeout)
        p = self._parse_response(resp, 0x8D)
        if p and len(p) >= 2:
            return bytes(p[2:])
        return None

    def tg_get_data(self) -> Optional[bytes]:
        self._write_frame([CMD_TG_GET_DATA])
        resp = self._read_response(64, timeout=5.0)
        p = self._parse_response(resp, 0x87)
        if p and len(p) >= 3 and p[2] == 0x00:
            return bytes(p[3:])
        return None

    def tg_set_data(self, data: bytes) -> bool:
        self._write_frame([CMD_TG_SET_DATA] + list(data))
        resp = self._read_response(12, timeout=2.0)
        p = self._parse_response(resp, 0x8F)
        return p is not None and len(p) >= 3 and p[2] == 0x00


class PN532I2C(_PN532Base):
    def __init__(self, bus_num=1, addr=I2C_ADDR):
        self.bus = smbus.SMBus(bus_num)
        self.addr = addr

    def close(self):
        try:
            self.bus.close()
        except Exception:
            pass

    def _write_frame(self, data):
        length = len(data) + 1
        lcs = (~length + 1) & 0xFF
        body = [HOST_TO_PN532] + list(data)
        dcs = (~sum(body) + 1) & 0xFF
        frame = [PREAMBLE, STARTCODE1, STARTCODE2, length, lcs] + body + [dcs, 0x00]
        self.bus.write_i2c_block_data(self.addr, frame[0], frame[1:])

    def _read_response(self, expected_len=32, timeout=1.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                status = self.bus.read_byte(self.addr)
                if status & 0x01:
                    return self.bus.read_i2c_block_data(self.addr, 0x00, expected_len + 8)
            except OSError:
                pass
            time.sleep(0.02)
        return None


class PN532UART(_PN532Base):
    def __init__(self, port="/dev/ttyUSB0", baudrate=115200):
        self.ser = serial.Serial(port, baudrate, timeout=0.05)
        self._wakeup()

    def close(self):
        try:
            self.ser.close()
        except Exception:
            pass

    def _wakeup(self):
        self.ser.write(b"\x55\x55\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x03\xfd\xd4\x14\x01\x17\x00")
        time.sleep(0.1)
        self.ser.reset_input_buffer()

    def _write_frame(self, data):
        length = len(data) + 1
        lcs = (~length + 1) & 0xFF
        body = [HOST_TO_PN532] + list(data)
        dcs = (~sum(body) + 1) & 0xFF
        self.ser.write(bytes([PREAMBLE, STARTCODE1, STARTCODE2,
                              length, lcs] + body + [dcs, 0x00]))

    def _read_response(self, expected_len=32, timeout=1.0):
        deadline = time.time() + timeout
        buf = b""
        ack_stripped = False
        while time.time() < deadline:
            avail = self.ser.in_waiting
            if avail > 0:
                buf += self.ser.read(avail)
            elif len(buf) == 0:
                time.sleep(0.005)
                continue

            if not ack_stripped:
                ack = buf.find(b"\x00\x00\xff\x00\xff\x00")
                if ack >= 0:
                    buf = buf[ack + 6:]
                    ack_stripped = True
                elif len(buf) > 10:
                    ack_stripped = True

            resp_idx = buf.find(b"\x00\x00\xff")
            if resp_idx >= 0 and len(buf) > resp_idx + 3:
                frame_len = buf[resp_idx + 3]
                total = resp_idx + 6 + frame_len + 1
                if len(buf) >= total:
                    return list(buf[resp_idx + 5:resp_idx + 5 + frame_len + 1])

            if avail == 0:
                time.sleep(0.003)
        return None


class NfcpyDriver:
    """Wrapper for nfcpy-compatible USB readers (ACR122U, SCL3711, etc.)."""
    can_write = False
    can_emulate = False

    def __init__(self, clf):
        self.clf = clf

    def close(self):
        try:
            self.clf.close()
        except Exception:
            pass

    def get_firmware(self):
        return (0, 1, 0, 0)

    def sam_config(self):
        pass

    def read_passive_target(self, card_type=0x00, timeout=2.0) -> Optional[CardInfo]:
        try:
            tag = self.clf.connect(rdwr={"on-connect": lambda t: False},
                                   terminate=lambda: False)
            if tag and hasattr(tag, "identifier"):
                uid = bytes(tag.identifier)
                sak = getattr(tag, "sak", 0) or 0
                return CardInfo(uid=uid, sak=sak)
        except Exception:
            pass
        return None

    def mifare_auth(self, block, key, uid, key_type=MIFARE_AUTH_A):
        return False
    def mifare_read(self, block):
        return None
    def mifare_write(self, block, data):
        return False
    def mifare_ul_read(self, page):
        return None
    def mifare_ul_write(self, page, data):
        return False
    def communicate_thru(self, data, timeout=1.0):
        return None
    def data_exchange(self, data, timeout=1.0):
        return None
    def init_as_target(self, uid, atqa=b"\x04\x00", sak=0x08, timeout=1.0):
        return None
    def tg_get_data(self):
        return None
    def tg_set_data(self, data):
        return False


# ---------------------------------------------------------------------------
# Chameleon Ultra driver
# ---------------------------------------------------------------------------

_CU_SOF = 0x11
_CU_VID_PID = "6868:8686"

# Command IDs
_CU_GET_APP_VERSION = 1000
_CU_CHANGE_DEVICE_MODE = 1001
_CU_GET_DEVICE_MODEL = 1033
_CU_GET_GIT_VERSION = 1017
_CU_GET_BATTERY_INFO = 1025
_CU_HF14A_SCAN = 2000
_CU_MF1_AUTH_ONE_KEY_BLOCK = 2007
_CU_MF1_READ_ONE_BLOCK = 2008
_CU_MF1_WRITE_ONE_BLOCK = 2009
_CU_HF14A_RAW = 2010
_CU_EM410X_SCAN = 3000

# Status codes
_CU_SUCCESS_CODES = {0x0000, 0x0068, 0x0040}
_CU_HF_TAG_NO = 0x0001
_CU_MF_ERR_AUTH = 0x0006


class ChameleonUltraDriver:
    """Chameleon Ultra driver via serial binary protocol."""
    can_write = True
    can_emulate = True

    def __init__(self, port: str):
        self._port = port
        self._ser = None
        self._lock = threading.Lock()
        self._last_auth_key = None
        self._last_auth_key_type = MIFARE_AUTH_A
        self._open()

    def _open(self):
        if self._ser:
            try:
                self._ser.close()
            except Exception:
                pass
        try:
            self._ser = serial.Serial(self._port, 115200, timeout=0.05)
            time.sleep(0.3)
            self._ser.reset_input_buffer()
        except Exception:
            self._ser = None

    @staticmethod
    def _lrc(data: bytes) -> int:
        return (0x100 - (sum(data) & 0xFF)) & 0xFF

    def _build_frame(self, cmd: int, data: bytes = b"", status: int = 0) -> bytes:
        header = struct.pack(">HHH", cmd, status, len(data))
        sof = bytes([_CU_SOF])
        lrc1 = bytes([self._lrc(sof)])
        lrc2 = bytes([self._lrc(sof + lrc1 + header)])
        lrc3 = bytes([self._lrc(sof + lrc1 + header + lrc2 + data)])
        return sof + lrc1 + header + lrc2 + data + lrc3

    def _parse_frame(self, raw: bytes) -> Optional[Tuple[int, int, bytes]]:
        if len(raw) < 9 or raw[0] != _CU_SOF:
            return None
        if raw[1] != self._lrc(raw[0:1]):
            return None
        cmd, status, dlen = struct.unpack(">HHH", raw[2:8])
        if raw[8] != self._lrc(raw[0:8]):
            return None
        if len(raw) < 9 + dlen + 1:
            return None
        data = raw[9:9 + dlen]
        if raw[9 + dlen] != self._lrc(raw[0:9 + dlen]):
            return None
        return cmd, status, data

    def _send_cmd(self, cmd: int, data: bytes = b"", timeout: float = 3.0) -> Optional[Tuple[int, bytes]]:
        if not self._ser or not self._ser.is_open:
            self._open()
        if not self._ser:
            return None
        frame = self._build_frame(cmd, data)
        with self._lock:
            try:
                try:
                    self._ser.reset_input_buffer()
                except (OSError, serial.SerialException):
                    self._open()
                    if not self._ser:
                        return None
                self._ser.write(frame)
                buf = b""
                deadline = time.time() + timeout
                while time.time() < deadline:
                    chunk = self._ser.read(256)
                    if chunk:
                        buf += chunk
                        parsed = self._parse_frame(buf)
                        if parsed is not None:
                            return parsed[1], parsed[2]
                    else:
                        time.sleep(0.01)
            except (OSError, serial.SerialException):
                pass
        return None

    def close(self):
        if self._ser:
            try:
                self._ser.close()
            except Exception:
                pass
            self._ser = None

    def get_device_model(self) -> str:
        result = self._send_cmd(1033)
        if result and result[0] in _CU_SUCCESS_CODES:
            model_id = result[1][0] if result[1] else 0xFF
            return {0: "Ultra", 1: "Lite"}.get(model_id, "Unknown")
        return "Ultra"

    def get_firmware(self) -> Optional[Tuple[int, int, int, int]]:
        result = self._send_cmd(_CU_GET_APP_VERSION)
        if result is None:
            return None
        status, data = result
        if status in _CU_SUCCESS_CODES and len(data) >= 2:
            return (data[0], data[1], 0, 0)
        return None

    def sam_config(self):
        self._send_cmd(_CU_CHANGE_DEVICE_MODE, bytes([0x01]))

    def read_passive_target(self, card_type=0x00, timeout=2.0) -> Optional[CardInfo]:
        self._send_cmd(_CU_CHANGE_DEVICE_MODE, bytes([0x01]))
        time.sleep(0.3)
        deadline = time.time() + timeout
        while time.time() < deadline:
            result = self._send_cmd(_CU_HF14A_SCAN, timeout=2.0)
            if result is not None:
                status, data = result
                if status in _CU_SUCCESS_CODES and len(data) >= 4:
                    uid_len = data[0]
                    if len(data) >= 1 + uid_len + 3:
                        uid = data[1:1 + uid_len]
                        atqa_off = 1 + uid_len
                        sak_off = atqa_off + 2
                        atqa = data[atqa_off] | (data[atqa_off + 1] << 8)
                        sak = data[sak_off]
                        return CardInfo(uid=bytes(uid), atqa=atqa, sak=sak)
            time.sleep(0.2)
        return None

    def mifare_auth(self, block: int, key: bytes, uid: bytes, key_type: int = MIFARE_AUTH_A) -> bool:
        kt = 0x60 if key_type == MIFARE_AUTH_A else 0x61
        data = bytes([kt, block]) + key[:6]
        result = self._send_cmd(_CU_MF1_AUTH_ONE_KEY_BLOCK, data)
        if result is None:
            return False
        ok = result[0] in _CU_SUCCESS_CODES
        if ok:
            self._last_auth_key = key[:6]
            self._last_auth_key_type = key_type
        return ok

    def mifare_read(self, block: int) -> Optional[bytes]:
        key = self._last_auth_key or bytes.fromhex("FFFFFFFFFFFF")
        kt = 0x60 if self._last_auth_key_type == MIFARE_AUTH_A else 0x61
        data = bytes([kt, block]) + key[:6]
        result = self._send_cmd(_CU_MF1_READ_ONE_BLOCK, data)
        if result is None:
            return None
        status, resp = result
        if status in _CU_SUCCESS_CODES and len(resp) >= 16:
            return bytes(resp[:16])
        return None

    def mifare_write(self, block: int, data: bytes) -> bool:
        key = self._last_auth_key or bytes.fromhex("FFFFFFFFFFFF")
        kt = 0x60 if self._last_auth_key_type == MIFARE_AUTH_A else 0x61
        payload = bytes([kt, block]) + key[:6] + data[:16]
        result = self._send_cmd(_CU_MF1_WRITE_ONE_BLOCK, payload)
        if result is None:
            return False
        return result[0] in _CU_SUCCESS_CODES

    def mifare_ul_read(self, page: int) -> Optional[bytes]:
        pages_data = b""
        for p in range(page, min(page + 4, 256)):
            apdu = bytes([MIFARE_READ, p])
            result = self._send_cmd(_CU_HF14A_RAW, apdu, timeout=2.0)
            if result is None:
                return None
            status, resp = result
            if status != _CU_SUCCESS or len(resp) < 4:
                return None
            pages_data += resp[:4]
        return pages_data if len(pages_data) == 16 else None

    def mifare_ul_write(self, page: int, data: bytes) -> bool:
        apdu = bytes([MIFARE_UL_WRITE, page]) + data[:4]
        result = self._send_cmd(_CU_HF14A_RAW, apdu, timeout=2.0)
        if result is None:
            return False
        return result[0] in _CU_SUCCESS_CODES

    def data_exchange(self, data: bytes, timeout=1.0) -> Optional[bytes]:
        # First select card and keep RF field alive
        scan_result = self._send_cmd(2016, timeout=3.0)  # HF14A_SCAN_KEEP
        if scan_result is None or scan_result[0] not in _CU_SUCCESS_CODES:
            return None
        # HF14A_RAW format: options(1) + resp_timeout_ms(2 BE) + bitlen(2 BE) + data(N)
        # Options: activate_rf=0, wait_response=1, append_crc=1, auto_select=0, keep_rf=1, check_crc=1
        options = 0b01101100  # wait_resp + append_crc + keep_rf + check_crc
        timeout_ms = int(max(timeout, 1.0) * 1000)
        bitlen = len(data) * 8
        raw_data = struct.pack(">BHH", options, timeout_ms, bitlen) + data
        result = self._send_cmd(_CU_HF14A_RAW, raw_data, timeout=max(3.0, timeout + 1))
        if result is None:
            return None
        status, resp = result
        if resp and len(resp) >= 2:
            return bytes(resp)
        return None

    def communicate_thru(self, data: bytes, timeout=1.0) -> Optional[bytes]:
        return self.data_exchange(data, timeout=timeout)

    def in_communicate_thru_raw(self, data: bytes, timeout=0.5) -> Optional[bytes]:
        return self.data_exchange(data, timeout=timeout)

    def init_as_target(self, uid: bytes, atqa: bytes = b"\x04\x00", sak: int = 0x08, timeout: float = 1.0) -> Optional[bytes]:
        self._send_cmd(_CU_CHANGE_DEVICE_MODE, bytes([0x00]))
        return uid[:4]

    def tg_get_data(self) -> Optional[bytes]:
        return None

    def tg_set_data(self, data: bytes) -> bool:
        return False

    def command(self, cmd_id: int, data: bytes = b"", timeout: float = 3.0) -> Optional[Tuple[int, bytes]]:
        return self._send_cmd(cmd_id, data, timeout=timeout)

    def get_git_version(self) -> str:
        result = self._send_cmd(1017)
        if result and result[0] in _CU_SUCCESS_CODES and result[1]:
            return result[1].decode("utf-8", errors="replace").strip("\x00")
        return ""

    def get_battery(self) -> Optional[Tuple[int, int]]:
        result = self._send_cmd(1025)
        if result and result[0] in _CU_SUCCESS_CODES and len(result[1]) >= 3:
            voltage = (result[1][0] << 8) | result[1][1]
            pct = result[1][2]
            return voltage, pct
        return None

    def get_active_slot(self) -> int:
        result = self._send_cmd(1018)
        if result and result[0] in _CU_SUCCESS_CODES and result[1]:
            return result[1][0]
        return 0

    def set_active_slot(self, slot: int):
        self._send_cmd(1003, bytes([slot & 0x07]))

    def get_slot_info(self) -> list:
        result = self._send_cmd(1019)
        slots = []
        hf_types = {0: "None", 1: "MF1K", 2: "MF2K", 3: "MF4K", 4: "NTAG213",
                     5: "NTAG215", 6: "NTAG216", 7: "MF0ICU1", 8: "MF0ICU2",
                     9: "MF0UL11", 10: "MF0UL21", 11: "EM4100", 12: "HID"}
        lf_types = {0: "None", 1: "EM4100", 2: "HID"}
        if result and result[0] in _CU_SUCCESS_CODES and len(result[1]) >= 16:
            for i in range(8):
                hf = result[1][i * 2] if i * 2 < len(result[1]) else 0
                lf = result[1][i * 2 + 1] if i * 2 + 1 < len(result[1]) else 0
                slots.append({
                    "slot": i,
                    "hf_type": hf_types.get(hf, f"Type{hf}"),
                    "lf_type": lf_types.get(lf, f"Type{lf}"),
                })
        else:
            for i in range(8):
                slots.append({"slot": i, "hf_type": "Unknown", "lf_type": "Unknown"})
        return slots

    def get_enabled_slots(self) -> list:
        result = self._send_cmd(1023)
        if result and result[0] in _CU_SUCCESS_CODES and result[1]:
            enabled = []
            for i in range(8):
                if i < len(result[1]):
                    enabled.append(bool(result[1][i]))
                else:
                    enabled.append(True)
            return enabled
        return [True] * 8

    def set_slot_enable(self, slot: int, enable: bool):
        self._send_cmd(1006, bytes([slot & 0x07, 0x01 if enable else 0x00]))

    def em410x_scan(self) -> Optional[bytes]:
        self._send_cmd(_CU_CHANGE_DEVICE_MODE, bytes([0x01]))
        result = self._send_cmd(3000, timeout=5.0)
        if result and result[0] in _CU_SUCCESS_CODES and len(result[1]) >= 5:
            return bytes(result[1][:5])
        return None

    def hid_scan(self) -> Optional[bytes]:
        self._send_cmd(_CU_CHANGE_DEVICE_MODE, bytes([0x01]))
        result = self._send_cmd(3002, timeout=5.0)
        if result and result[0] in _CU_SUCCESS_CODES and result[1]:
            return bytes(result[1])
        return None

    @staticmethod
    def detect_chameleon() -> Optional[Tuple[str, str]]:
        """Detect a connected Chameleon Ultra by USB VID:PID. Returns (port, description) or None."""
        try:
            result = subprocess.run(["lsusb"], capture_output=True, text=True, timeout=3)
            if _CU_VID_PID not in result.stdout:
                return None
        except Exception:
            return None
        for port in ["/dev/ttyACM0", "/dev/ttyACM1"]:
            if os.path.exists(port):
                return port, f"Chameleon Ultra {port}"
        return None


PM3_PORTS = ["/dev/ttyACM0", "/dev/ttyACM1"]
_PM3_PROMPT_RE = re.compile(r"pm3\s*-->")


class PM3Driver:
    """Proxmark3 driver with persistent interactive process via PTY."""
    can_write = True
    can_emulate = True

    def __init__(self, port: str, pm3_bin: str = None):
        self._port = port
        self._bin = pm3_bin or self._find_client()
        self._last_auth_key = None
        self._last_auth_key_type = MIFARE_AUTH_A
        self._proc = None
        self._master_fd = None
        self._start()

    @staticmethod
    def _find_client() -> str:
        for path in [
            "/opt/proxmark3/client/proxmark3",
            "/usr/local/bin/proxmark3",
            "/usr/bin/proxmark3",
        ]:
            if os.path.isfile(path):
                return path
        return "proxmark3"

    def _start(self):
        self._kill_stale()
        try:
            import pty, fcntl, select
            master_fd, slave_fd = pty.openpty()
            self._proc = subprocess.Popen(
                [self._bin, self._port],
                stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
            )
            os.close(slave_fd)
            self._master_fd = master_fd
            flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
            fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            self._read_until_prompt(timeout=5.0)
        except Exception:
            self._proc = None
            self._master_fd = None

    def _read_until_prompt(self, timeout: float = 3.0) -> str:
        import select
        buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = max(0.01, deadline - time.time())
            r, _, _ = select.select([self._master_fd], [], [], min(remaining, 0.1))
            if r:
                try:
                    chunk = os.read(self._master_fd, 4096)
                    if chunk:
                        buf += chunk
                        if _PM3_PROMPT_RE.search(buf.decode("utf-8", errors="replace")):
                            break
                except OSError:
                    break
            if self._proc and self._proc.poll() is not None:
                break
        return buf.decode("utf-8", errors="replace")

    def _send(self, cmd: str, timeout: float = 5.0) -> Optional[str]:
        if not self._proc or self._proc.poll() is not None or self._master_fd is None:
            self._start()
        if not self._proc or self._master_fd is None:
            return None
        try:
            os.write(self._master_fd, (cmd + "\r").encode())
        except OSError:
            self._start()
            if not self._proc or self._master_fd is None:
                return None
            os.write(self._master_fd, (cmd + "\r").encode())
        return self._read_until_prompt(timeout=timeout)

    def close(self):
        if self._master_fd is not None:
            try:
                os.write(self._master_fd, b"quit\r")
            except OSError:
                pass
            try:
                os.close(self._master_fd)
            except OSError:
                pass
            self._master_fd = None
        if self._proc:
            try:
                self._proc.wait(timeout=3)
            except Exception:
                try:
                    self._proc.kill()
                    self._proc.wait(timeout=2)
                except Exception:
                    pass
        self._proc = None

    @staticmethod
    def _kill_stale():
        try:
            subprocess.run(
                ["pkill", "-f", "proxmark3.*ttyACM"],
                capture_output=True, timeout=3,
            )
            time.sleep(0.5)
        except Exception:
            pass

    def command(self, cmd: str, timeout: float = 10.0) -> Optional[str]:
        """Send an arbitrary PM3 command and return raw output."""
        return self._send(cmd, timeout=timeout)

    def get_firmware(self) -> Optional[Tuple[int, int, int, int]]:
        out = self._send("hw version", timeout=5.0)
        if out and ("Proxmark3" in out or "proxmark3" in out or "RRG" in out or "iceman" in out):
            return (3, 0, 0, 0)
        return None

    def sam_config(self):
        pass

    def read_passive_target(self, card_type=0x00, timeout=2.0) -> Optional[CardInfo]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            out = self._send("hf 14a reader", timeout=3.0)
            if out:
                uid = self._parse_field(out, r"UID\s*[:=]\s*([0-9A-Fa-f ]+)")
                if uid:
                    atqa = self._parse_field(out, r"ATQA\s*[:=]\s*([0-9A-Fa-f ]+)")
                    sak = self._parse_field(out, r"SAK\s*[:=]\s*([0-9A-Fa-f]+)")
                    uid_bytes = bytes.fromhex(uid.replace(" ", ""))
                    atqa_int = int(atqa.replace(" ", ""), 16) if atqa else 0
                    sak_int = int(sak.replace(" ", ""), 16) if sak else 0
                    return CardInfo(uid=uid_bytes, atqa=atqa_int, sak=sak_int)
            time.sleep(0.1)
        return None

    @staticmethod
    def _extract_block_hex(text: str) -> Optional[str]:
        """Extract 16-byte block data from PM3 table output like '| 52 AC DA B9 ... |'."""
        m = re.search(r"\|\s*((?:[0-9A-Fa-f]{2}\s+){15}[0-9A-Fa-f]{2})\s*\|", text)
        if m:
            return m.group(1).replace(" ", "")
        m = re.search(r"(?:data\s*[:=]\s*)?([0-9A-Fa-f]{32})", text)
        return m.group(1) if m else None

    def mifare_auth(self, block: int, key: bytes, uid: bytes, key_type: int = MIFARE_AUTH_A) -> bool:
        kt = "-a" if key_type == MIFARE_AUTH_A else "-b"
        key_hex = key.hex().upper()
        out = self._send(f"hf mf rdbl --blk {block} {kt} -k {key_hex}")
        if not out or "error" in out.lower():
            return False
        ok = self._extract_block_hex(out) is not None
        if ok:
            self._last_auth_key = key
            self._last_auth_key_type = key_type
        return ok

    def mifare_read(self, block: int) -> Optional[bytes]:
        key = self._last_auth_key or bytes.fromhex("FFFFFFFFFFFF")
        kt = "-a" if self._last_auth_key_type == MIFARE_AUTH_A else "-b"
        key_hex = key.hex().upper()
        out = self._send(f"hf mf rdbl --blk {block} {kt} -k {key_hex}")
        if not out:
            return None
        hex_str = self._extract_block_hex(out)
        return bytes.fromhex(hex_str) if hex_str else None

    def mifare_write(self, block: int, data: bytes) -> bool:
        key = self._last_auth_key or bytes.fromhex("FFFFFFFFFFFF")
        kt = "-a" if self._last_auth_key_type == MIFARE_AUTH_A else "-b"
        key_hex = key.hex().upper()
        data_hex = data[:16].hex().upper()
        out = self._send(f"hf mf wrbl --blk {block} {kt} -k {key_hex} -d {data_hex}")
        if not out:
            return False
        lower = out.lower()
        return "isok" in lower or "ok" in lower or "success" in lower

    def mifare_ul_read(self, page: int) -> Optional[bytes]:
        pages_data = b""
        for p in range(page, min(page + 4, 256)):
            out = self._send(f"hf mfu rdbl --blk {p}")
            if not out:
                return None
            m = re.search(r"([0-9A-Fa-f]{8})", out)
            if not m:
                return None
            pages_data += bytes.fromhex(m.group(1))
        return pages_data if len(pages_data) == 16 else None

    def mifare_ul_write(self, page: int, data: bytes) -> bool:
        data_hex = data[:4].hex().upper()
        out = self._send(f"hf mfu wrbl --blk {page} -d {data_hex}")
        if not out:
            return False
        lower = out.lower()
        return "ok" in lower or "success" in lower or "isok" in lower

    def data_exchange(self, data: bytes, timeout=1.0) -> Optional[bytes]:
        apdu_hex = data.hex().upper()
        out = self._send(f"hf 14a apdu -d {apdu_hex}", timeout=max(3.0, timeout + 2))
        if not out:
            return None
        m = re.search(r"(?:response|data|<<|RX)\s*[:=]?\s*([0-9A-Fa-f ]+)", out, re.IGNORECASE)
        if m:
            hex_str = m.group(1).replace(" ", "")
            if len(hex_str) >= 4:
                return bytes.fromhex(hex_str)
        m = re.search(r"([0-9A-Fa-f]{4,})", out)
        if m:
            return bytes.fromhex(m.group(1))
        return None

    def communicate_thru(self, data: bytes, timeout=1.0) -> Optional[bytes]:
        return self.data_exchange(data, timeout=timeout)

    def in_communicate_thru_raw(self, data: bytes, timeout=0.5) -> Optional[bytes]:
        raw_hex = data.hex().upper()
        out = self._send(f"hf 14a raw -sc {raw_hex}", timeout=max(3.0, timeout + 2))
        if not out:
            return None
        m = re.search(r"(?:received|<<|RX)\s*[:=]?\s*([0-9A-Fa-f ]+)", out, re.IGNORECASE)
        if m:
            hex_str = m.group(1).replace(" ", "")
            if hex_str:
                return bytes.fromhex(hex_str)
        return None

    def init_as_target(self, uid: bytes, atqa: bytes = b"\x04\x00", sak: int = 0x08, timeout: float = 1.0) -> Optional[bytes]:
        uid_hex = uid[:4].hex().upper()
        out = self._send(f"hf 14a sim -t 1 -u {uid_hex}", timeout=max(3.0, timeout + 2))
        if out and ("simulating" in out.lower() or "uid" in out.lower()):
            return uid[:4]
        return None

    def tg_get_data(self) -> Optional[bytes]:
        return None

    def tg_set_data(self, data: bytes) -> bool:
        return False

    @staticmethod
    def _parse_field(text: str, pattern: str) -> Optional[str]:
        m = re.search(pattern, text, re.IGNORECASE)
        return m.group(1).strip() if m else None

    @staticmethod
    def detect_pm3() -> Optional[Tuple[str, str]]:
        """Detect a connected Proxmark3. Returns (port, description) or None."""
        client = PM3Driver._find_client()
        for port in PM3_PORTS:
            if not os.path.exists(port):
                continue
            try:
                result = subprocess.run(
                    [client, port, "-c", "hw version"],
                    capture_output=True, text=True, timeout=8,
                )
                out = result.stdout + result.stderr
                if "Proxmark3" in out or "proxmark3" in out or "RRG" in out or "iceman" in out:
                    model = "PM3"
                    if "RDV4" in out or "rdv4" in out:
                        model = "PM3 RDV4"
                    elif "Easy" in out or "easy" in out:
                        model = "PM3 Easy"
                    elif "RDV2" in out:
                        model = "PM3 RDV2"
                    return port, model
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                continue
        return None


CU_USB_VID_PID = "6868:8686"
CU_SOF = 0x11

# Chameleon Ultra command IDs
CU_GET_APP_VERSION = 1000
CU_CHANGE_DEVICE_MODE = 1001
CU_GET_DEVICE_MODE = 1002
CU_SET_ACTIVE_SLOT = 1003
CU_SET_SLOT_TAG_TYPE = 1004
CU_SET_SLOT_ENABLE = 1006
CU_SET_SLOT_TAG_NICK = 1007
CU_GET_SLOT_TAG_NICK = 1008
CU_GET_DEVICE_CHIP_ID = 1011
CU_GET_GIT_VERSION = 1017
CU_GET_ACTIVE_SLOT = 1018
CU_GET_SLOT_INFO = 1019
CU_GET_ENABLED_SLOTS = 1023
CU_GET_BATTERY_INFO = 1025
CU_GET_DEVICE_MODEL = 1033
CU_HF14A_SCAN = 2000
CU_MF1_AUTH_ONE_KEY_BLOCK = 2007
CU_MF1_READ_ONE_BLOCK = 2008
CU_MF1_WRITE_ONE_BLOCK = 2009
CU_HF14A_RAW = 2010
CU_MF1_CHECK_KEYS_OF_SECTORS = 2012
CU_EM410X_SCAN = 3000
CU_HIDPROX_SCAN = 3002

CU_STATUS_OK = 0
CU_HF_TAG_OK = 0
CU_HF_TAG_NO = 1
CU_LF_TAG_OK = 0x40

CU_TAG_TYPES = {
    0: "Unknown", 1: "EM410X", 2: "MIFARE Mini", 3: "MIFARE 1K",
    4: "MIFARE 2K", 5: "MIFARE 4K", 6: "NTAG213", 7: "NTAG215",
    8: "NTAG216", 9: "MF0ICU1", 10: "MF0ICU2", 11: "MF0UL11",
    12: "MF0UL21", 13: "NTAG210", 14: "NTAG212",
}


def _usb_reset_ch340():
    """Reset CH340 USB device to recover stuck PN532."""
    import glob
    for product_path in glob.glob("/sys/bus/usb/devices/*/product"):
        try:
            with open(product_path) as f:
                if "Serial" in f.read():
                    bind = os.path.basename(os.path.dirname(product_path))
                    subprocess.run(["sh", "-c", f"echo {bind} > /sys/bus/usb/drivers/usb/unbind"],
                                   capture_output=True, timeout=3)
                    time.sleep(1)
                    subprocess.run(["sh", "-c", f"echo {bind} > /sys/bus/usb/drivers/usb/bind"],
                                   capture_output=True, timeout=3)
                    time.sleep(1)
                    return True
        except Exception:
            pass
    return False


def auto_detect() -> Tuple[Optional[_PN532Base], str]:
    """Auto-detect NFC reader. Returns (driver, description).
    Priority: Chameleon Ultra > Proxmark3 > nfcpy USB > PN532 UART > PN532 I2C.
    """
    # Chameleon Ultra (highest priority — unique VID:PID, no conflict)
    if SERIAL_OK:
        cu_result = ChameleonUltraDriver.detect_chameleon()
        if cu_result:
            port, desc = cu_result
            drv = ChameleonUltraDriver(port)
            return drv, desc

    # Proxmark3
    PM3Driver._kill_stale()
    pm3 = PM3Driver.detect_pm3()
    if pm3:
        port, model = pm3
        return PM3Driver(port), f"{model} {port}"

    if NFCPY_OK:
        for path in ["usb", "usb:072f:2200", "usb:04e6:5591"]:
            try:
                clf = nfcpy.ContactlessFrontend(path)
                desc = str(getattr(clf, "device", path))[:18]
                return NfcpyDriver(clf), f"nfcpy: {desc}"
            except Exception:
                pass

    for attempt in range(2):
        if SERIAL_OK:
            for port in UART_PORTS:
                if not os.path.exists(port):
                    continue
                for baud in UART_BAUDS:
                    try:
                        drv = PN532UART(port, baud)
                        fw = drv.get_firmware()
                        if fw:
                            drv.sam_config()
                            return drv, f"PN532 UART {port}"
                        drv.close()
                    except Exception:
                        pass
        if attempt == 0:
            _usb_reset_ch340()

    if SMBUS_OK:
        for addr in [I2C_ADDR, 0x48]:
            try:
                drv = PN532I2C(addr=addr)
                fw = drv.get_firmware()
                if fw:
                    drv.sam_config()
                    return drv, f"PN532 I2C 0x{addr:02X}"
                drv.close()
            except Exception:
                pass

    return None, "No NFC reader found"
