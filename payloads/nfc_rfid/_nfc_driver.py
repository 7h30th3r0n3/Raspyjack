"""
Shared PN532 NFC driver for RaspyJack NFC suite.
Supports UART (CH340/CP2102), I2C, and nfcpy USB readers.
"""

import os
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
        MIFARE params: SENS_RES(2B) + NFCID1t(3B) + SEL_RES(1B)
        PN532 uses NFCID1t[0..2] as UID bytes 1-3, and auto-generates byte 0 (BCC).
        To emit a full 4-byte UID, we pass uid[1:4] so the reader sees uid[1] uid[2] uid[3] + BCC.
        But most readers report the 4 bytes from anti-collision: the 3 NFCID1t bytes + generated BCC.
        We pass all 4 uid bytes packed: uid[0:3] as NFCID1t. The reader gets uid[0] uid[1] uid[2] + auto-BCC.
        """
        mode = 0x04
        sens_res = [atqa[1], atqa[0]] if len(atqa) >= 2 else [0x04, 0x00]
        # PN532 NFCID1t = 3 bytes. Reader sees these 3 bytes as UID[0..2].
        # The 4th byte the reader sees is the XOR checksum (BCC) computed by PN532.
        # To get the desired 4-byte UID, we encode it so that:
        #   NFCID1t = [uid[1], uid[2], uid[3]]
        #   The PN532 puts CT=0x88 as first byte of anticollision frame
        #   Reader sees: 0x88, uid[1], uid[2], uid[3], BCC
        #   But after SELECT, reader reports UID = uid[1], uid[2], uid[3], BCC... wrong.
        # Actually for single-size UID (4 bytes), PN532 sends:
        #   Anticollision: NFCID1t[0], NFCID1t[1], NFCID1t[2], BCC
        #   Where BCC = NFCID1t[0] ^ NFCID1t[1] ^ NFCID1t[2] ^ 0x88 (for CT-based)
        # Most readers report UID = first 4 bytes = NFCID1t[0..2] + BCC
        # So to get UID = uid[0..3], set NFCID1t = uid[0..2]
        # The 4th byte will be BCC = uid[0]^uid[1]^uid[2]^0x88 (NOT uid[3])
        # This is a PN532 limitation - we can only control 3 bytes.
        nfcid1t = list(uid[:3]) if len(uid) >= 3 else [0x01, 0x02, 0x03]
        sel_res = sak if isinstance(sak, int) else sak[0]
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


def _usb_reset_ch340():
    """Reset CH340 USB device to recover stuck PN532."""
    import subprocess, glob
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
    """Auto-detect NFC reader. Returns (driver, description)."""
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
