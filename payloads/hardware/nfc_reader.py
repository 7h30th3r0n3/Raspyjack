#!/usr/bin/env python3
"""
RaspyJack Payload -- NFC/RFID Reader & Cloner
===============================================
Read, save and clone NFC/RFID cards.
Supports PN532 (UART/I2C), ACR122U, SCL3711 via nfcpy.

Modes:
  READ       Detect card, read UID + MIFARE sectors
  CLONE      Write saved dump to a new card (magic cards supported)
  SAVED      Browse and manage saved card dumps

Controls:
  OK         Action (read/clone/select)
  UP/DOWN    Navigate / scroll
  KEY1       Cycle mode
  KEY2       Save / delete
  KEY3       Exit / back
"""

import os
import sys
import json
import time
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

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

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT

PN532_I2C_ADDR = 0x24
PN532_PREAMBLE = 0x00
PN532_STARTCODE1 = 0x00
PN532_STARTCODE2 = 0xFF
PN532_HOSTTOPN532 = 0xD4
PN532_PN532TOHOST = 0xD5
CMD_SAMCONFIGURATION = 0x14
CMD_INLISTPASSIVETARGET = 0x4A
CMD_INDATAEXCHANGE = 0x40
CMD_GETFIRMWAREVERSION = 0x02

LOOT_DIR = "/root/Raspyjack/loot/NFC"
DEBOUNCE = 0.18
_last_btn = 0

DEFAULT_KEYS = [
    bytes.fromhex("FFFFFFFFFFFF"),
    bytes.fromhex("A0A1A2A3A4A5"),
    bytes.fromhex("D3F7D3F7D3F7"),
    bytes.fromhex("000000000000"),
    bytes.fromhex("B0B1B2B3B4B5"),
    bytes.fromhex("AABBCCDDEEFF"),
    bytes.fromhex("1A2B3C4D5E6F"),
    bytes.fromhex("010203040506"),
    bytes.fromhex("123456789ABC"),
]

MODES = ["read", "clone", "saved"]


def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE:
        return None
    if b:
        _last_btn = now
    return b


# ---------------------------------------------------------------------------
# PN532 I2C driver
# ---------------------------------------------------------------------------

class PN532I2C:
    def __init__(self, bus_num=1, addr=PN532_I2C_ADDR):
        self.bus = smbus.SMBus(bus_num)
        self.addr = addr
        self.can_write = True

    def close(self):
        try:
            self.bus.close()
        except Exception:
            pass

    def _write_frame(self, data):
        length = len(data) + 1
        lcs = (~length + 1) & 0xFF
        frame = [PN532_PREAMBLE, PN532_STARTCODE1, PN532_STARTCODE2,
                 length, lcs, PN532_HOSTTOPN532] + list(data)
        dcs = (~(sum([PN532_HOSTTOPN532] + list(data))) + 1) & 0xFF
        frame += [dcs, 0x00]
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

    def _parse_response(self, resp, cmd_reply):
        if resp is None:
            return None
        for i in range(len(resp) - 2):
            if resp[i] == PN532_PN532TOHOST and resp[i + 1] == cmd_reply:
                return resp[i:]
        return None

    def get_firmware_version(self):
        self._write_frame([CMD_GETFIRMWAREVERSION])
        resp = self._read_response(12)
        p = self._parse_response(resp, 0x03)
        if p and len(p) >= 6:
            return (p[2], p[3], p[4], p[5])
        return None

    def sam_config(self):
        self._write_frame([CMD_SAMCONFIGURATION, 0x01, 0x14, 0x01])
        self._read_response(12)

    def read_passive_target(self, timeout=2.0):
        self._write_frame([CMD_INLISTPASSIVETARGET, 0x01, 0x00])
        resp = self._read_response(32, timeout=timeout)
        p = self._parse_response(resp, 0x4B)
        if p is None or len(p) < 8 or p[2] < 1:
            return None
        uid_len = p[7]
        if len(p) >= 8 + uid_len:
            return bytes(p[8:8 + uid_len])
        return None

    def mifare_auth(self, block, key, uid, key_type=0x60):
        cmd = [CMD_INDATAEXCHANGE, 0x01, key_type, block] + list(key) + list(uid[:4])
        self._write_frame(cmd)
        resp = self._read_response(12)
        p = self._parse_response(resp, 0x41)
        return p is not None and len(p) >= 3 and p[2] == 0x00

    def mifare_read(self, block):
        self._write_frame([CMD_INDATAEXCHANGE, 0x01, 0x30, block])
        resp = self._read_response(32)
        p = self._parse_response(resp, 0x41)
        if p and len(p) >= 19 and p[2] == 0x00:
            return bytes(p[3:19])
        return None

    def mifare_write(self, block, data):
        cmd = [CMD_INDATAEXCHANGE, 0x01, 0xA0, block] + list(data[:16])
        self._write_frame(cmd)
        resp = self._read_response(12)
        p = self._parse_response(resp, 0x41)
        return p is not None and len(p) >= 3 and p[2] == 0x00


# ---------------------------------------------------------------------------
# PN532 UART driver
# ---------------------------------------------------------------------------

class PN532UART:
    def __init__(self, port="/dev/ttyUSB0", baudrate=115200):
        self.ser = serial.Serial(port, baudrate, timeout=0.5)
        self.can_write = True
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
        body = [PN532_HOSTTOPN532] + list(data)
        dcs = (~sum(body) + 1) & 0xFF
        self.ser.write(bytes([PN532_PREAMBLE, PN532_STARTCODE1, PN532_STARTCODE2,
                              length, lcs] + body + [dcs, 0x00]))

    def _read_response(self, expected_len=32, timeout=1.0):
        deadline = time.time() + timeout
        buf = b""
        while time.time() < deadline:
            chunk = self.ser.read(expected_len + 16)
            if chunk:
                buf += chunk
            ack_idx = buf.find(b"\x00\x00\xff\x00\xff\x00")
            if ack_idx >= 0:
                buf = buf[ack_idx + 6:]
            resp_idx = buf.find(b"\x00\x00\xff")
            if resp_idx >= 0 and len(buf) > resp_idx + 5:
                frame_len = buf[resp_idx + 3]
                total = resp_idx + 6 + frame_len + 1
                if len(buf) >= total:
                    return list(buf[resp_idx + 5:resp_idx + 5 + frame_len + 1])
            if not chunk:
                time.sleep(0.02)
        return None

    def _parse_response(self, resp, cmd_reply):
        if resp is None:
            return None
        for i in range(len(resp) - 2):
            if resp[i] == PN532_PN532TOHOST and resp[i + 1] == cmd_reply:
                return resp[i:]
        return None

    def get_firmware_version(self):
        self._write_frame([CMD_GETFIRMWAREVERSION])
        resp = self._read_response(12)
        p = self._parse_response(resp, 0x03)
        if p and len(p) >= 6:
            return (p[2], p[3], p[4], p[5])
        return None

    def sam_config(self):
        self._write_frame([CMD_SAMCONFIGURATION, 0x01, 0x14, 0x01])
        self._read_response(12)

    def read_passive_target(self, timeout=2.0):
        self._write_frame([CMD_INLISTPASSIVETARGET, 0x01, 0x00])
        resp = self._read_response(32, timeout=timeout)
        p = self._parse_response(resp, 0x4B)
        if p is None or len(p) < 8 or p[2] < 1:
            return None
        uid_len = p[7]
        if len(p) >= 8 + uid_len:
            return bytes(p[8:8 + uid_len])
        return None

    def mifare_auth(self, block, key, uid, key_type=0x60):
        cmd = [CMD_INDATAEXCHANGE, 0x01, key_type, block] + list(key) + list(uid[:4])
        self._write_frame(cmd)
        resp = self._read_response(12)
        p = self._parse_response(resp, 0x41)
        return p is not None and len(p) >= 3 and p[2] == 0x00

    def mifare_read(self, block):
        self._write_frame([CMD_INDATAEXCHANGE, 0x01, 0x30, block])
        resp = self._read_response(32)
        p = self._parse_response(resp, 0x41)
        if p and len(p) >= 19 and p[2] == 0x00:
            return bytes(p[3:19])
        return None

    def mifare_write(self, block, data):
        cmd = [CMD_INDATAEXCHANGE, 0x01, 0xA0, block] + list(data[:16])
        self._write_frame(cmd)
        resp = self._read_response(12)
        p = self._parse_response(resp, 0x41)
        return p is not None and len(p) >= 3 and p[2] == 0x00


# ---------------------------------------------------------------------------
# nfcpy wrapper (ACR122U, SCL3711, etc.)
# ---------------------------------------------------------------------------

class NfcpyDriver:
    def __init__(self, clf):
        self.clf = clf
        self.can_write = False

    def close(self):
        try:
            self.clf.close()
        except Exception:
            pass

    def get_firmware_version(self):
        return (0, 1, 0, 0)

    def sam_config(self):
        pass

    def read_passive_target(self, timeout=2.0):
        try:
            tag = self.clf.connect(rdwr={"on-connect": lambda t: False},
                                   terminate=lambda: False)
            if tag and hasattr(tag, "identifier"):
                return bytes(tag.identifier)
        except Exception:
            pass
        return None

    def mifare_auth(self, block, key, uid, key_type=0x60):
        return False

    def mifare_read(self, block):
        return None

    def mifare_write(self, block, data):
        return False


# ---------------------------------------------------------------------------
# Auto-detect reader
# ---------------------------------------------------------------------------

UART_PORTS = ["/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyAMA0"]


def _detect_reader():
    """Auto-detect NFC reader. Returns (driver, description) or (None, error)."""
    if NFCPY_OK:
        for path in ["usb", "usb:072f:2200", "usb:04e6:5591"]:
            try:
                clf = nfcpy.ContactlessFrontend(path)
                desc = str(clf.device) if hasattr(clf, "device") else path
                return NfcpyDriver(clf), f"nfcpy: {desc[:18]}"
            except Exception:
                pass

    if SERIAL_OK:
        for port in UART_PORTS:
            if not os.path.exists(port):
                continue
            for baud in [115200, 9600]:
                try:
                    drv = PN532UART(port, baud)
                    fw = drv.get_firmware_version()
                    if fw:
                        drv.sam_config()
                        return drv, f"PN532 UART {port}"
                    drv.close()
                except Exception:
                    pass

    if SMBUS_OK:
        for addr in [PN532_I2C_ADDR, 0x48]:
            try:
                drv = PN532I2C(addr=addr)
                fw = drv.get_firmware_version()
                if fw:
                    drv.sam_config()
                    return drv, f"PN532 I2C 0x{addr:02X}"
                drv.close()
            except Exception:
                pass

    return None, "No NFC reader found"


# ---------------------------------------------------------------------------
# Card operations
# ---------------------------------------------------------------------------

def _detect_card_type(uid):
    n = len(uid)
    if n == 4:
        return "MIFARE Classic"
    if n == 7:
        return "MIFARE UL/NTAG"
    if n == 10:
        return "MIFARE DESFire"
    return f"Unknown ({n}B)"


def _full_read(drv, uid, progress_cb=None):
    """Read all sectors of a MIFARE Classic card. Returns list of sector dicts."""
    sectors = []
    n_sectors = 16 if len(uid) == 4 else 0
    for sec in range(n_sectors):
        if progress_cb:
            progress_cb(sec, n_sectors, sectors)
        first_block = sec * 4
        authed = False
        used_key = ""
        key_type_used = 0x60
        for key in DEFAULT_KEYS:
            for kt in [0x60, 0x61]:
                if drv.mifare_auth(first_block, key, uid, kt):
                    authed = True
                    used_key = key.hex().upper()
                    key_type_used = kt
                    break
            if authed:
                break
        blocks = []
        if authed:
            for b in range(4):
                data = drv.mifare_read(first_block + b)
                blocks.append(data.hex() if data else "?" * 32)
        sectors.append({
            "sector": sec,
            "blocks": blocks,
            "key": used_key,
            "key_type": "A" if key_type_used == 0x60 else "B",
            "authed": authed,
        })
    return sectors


def _write_clone(drv, uid, dump, progress_cb=None):
    """Write a dump to a MIFARE Classic card. Returns (written, skipped, errors)."""
    written = 0
    skipped = 0
    errors = 0
    all_sectors = dump.get("sectors", [])
    total = len(all_sectors)
    for idx, sec_data in enumerate(all_sectors):
        if progress_cb:
            progress_cb(idx, total, written, skipped, errors)
        sec = sec_data["sector"]
        blocks = sec_data.get("blocks", [])
        key_hex = sec_data.get("key", "")
        if not blocks or not key_hex or key_hex in ("", "NONE"):
            skipped += 1
            continue
        key = bytes.fromhex(key_hex)
        first_block = sec * 4
        if not drv.mifare_auth(first_block, key, uid):
            for dk in DEFAULT_KEYS:
                if drv.mifare_auth(first_block, dk, uid):
                    break
            else:
                errors += 1
                continue

        for i, blk_hex in enumerate(blocks):
            block_num = first_block + i
            if block_num == 0 or i == 3 or blk_hex == "?" * 32:
                continue
            try:
                data = bytes.fromhex(blk_hex)
                if drv.mifare_write(block_num, data):
                    written += 1
                else:
                    errors += 1
            except Exception:
                errors += 1
    return written, skipped, errors


def _save_dump(uid, card_type, sectors):
    """Save card dump to JSON."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    uid_hex = uid.hex().upper()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"nfc_{uid_hex}_{ts}.json"
    dump = {
        "uid": uid_hex,
        "uid_bytes": list(uid),
        "type": card_type,
        "timestamp": ts,
        "sectors": sectors,
    }
    with open(os.path.join(LOOT_DIR, fname), "w") as f:
        json.dump(dump, f, indent=2)
    return fname


def _list_dumps():
    """List saved card dumps."""
    if not os.path.isdir(LOOT_DIR):
        return []
    result = []
    for f in sorted(os.listdir(LOOT_DIR), reverse=True):
        if f.startswith("nfc_") and f.endswith(".json"):
            path = os.path.join(LOOT_DIR, f)
            try:
                with open(path) as fh:
                    d = json.load(fh)
                result.append({
                    "file": f,
                    "path": path,
                    "uid": d.get("uid", "?"),
                    "type": d.get("type", "?"),
                    "sectors": len(d.get("sectors", [])),
                    "ts": d.get("timestamp", ""),
                })
            except Exception:
                pass
    return result


def _load_dump(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    font = scaled_font(10)
    font_sm = scaled_font(8)
    font_xs = scaled_font(7)

    if not SMBUS_OK and not SERIAL_OK and not NFCPY_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 45), "No NFC library!", font=font, fill="#ff0000")
        d.text((4, 60), "pip install nfcpy", font=font_sm, fill="#888")
        d.text((4, 73), "or smbus2 / pyserial", font=font_sm, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    # Detect reader
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), "Detecting reader...", font=font_sm, fill="#FFAA00")
    lcd.LCD_ShowImage(img, 0, 0)

    drv, drv_desc = _detect_reader()

    mode_idx = 0
    scroll = 0
    last_card = None       # {uid, type, sectors}
    status = drv_desc if drv else "No reader found"
    selected_dump = None   # for clone mode

    try:
        while True:
            btn = _btn()

            if btn == "KEY3":
                break

            if btn == "KEY1":
                mode_idx = (mode_idx + 1) % len(MODES)
                scroll = 0

            mode = MODES[mode_idx]

            # ===== READ MODE =====
            if mode == "read":
                if btn == "OK":
                    if drv is None:
                        drv, drv_desc = _detect_reader()
                        status = drv_desc
                    if drv:
                        status = "Polling..."
                        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                        d = ScaledDraw(img)
                        d.rectangle((0, 0, 127, 12), fill="#111")
                        d.text((2, 1), "READ", font=font_sm, fill="#00CCFF")
                        d.text((4, 50), "Place card on reader", font=font_sm, fill="#FFAA00")
                        lcd.LCD_ShowImage(img, 0, 0)

                        uid = drv.read_passive_target(timeout=3.0)
                        if uid:
                            ctype = _detect_card_type(uid)
                            uid_hex = uid.hex().upper()

                            def _read_progress(sec, total, done):
                                authed = sum(1 for s in done if s["authed"])
                                pct = sec * 100 // max(1, total)
                                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                                d = ScaledDraw(img)
                                d.rectangle((0, 0, 127, 12), fill="#111")
                                d.text((2, 1), "READ", font=font_sm, fill="#00CCFF")
                                d.text((80, 1), f"{pct}%", font=font_sm, fill="#00FF00")
                                d.text((4, 18), f"UID: {uid_hex[:16]}", font=font_sm, fill="#00FF00")
                                d.text((4, 30), f"Type: {ctype}", font=font_sm, fill="#ccc")
                                # Progress bar
                                bar_y = 46
                                d.rectangle((4, bar_y, 123, bar_y + 8), outline="#333")
                                bw = max(1, int(119 * sec / max(1, total)))
                                d.rectangle((4, bar_y, 4 + bw, bar_y + 8), fill="#00CCFF")
                                d.text((4, bar_y + 12), f"Sector {sec}/{total}", font=font_sm, fill="#FFAA00")
                                d.text((4, bar_y + 24), f"Cracked: {authed}  Locked: {sec - authed}", font=font_xs, fill="#888")
                                # Show last cracked sector
                                if done:
                                    last = done[-1]
                                    col = "#00FF00" if last["authed"] else "#FF4444"
                                    txt = f"S{last['sector']:02d} [{last['key'][:6]}]" if last["authed"] else f"S{last['sector']:02d} LOCKED"
                                    d.text((4, bar_y + 38), txt, font=font_sm, fill=col)
                                lcd.LCD_ShowImage(img, 0, 0)

                            sectors = _full_read(drv, uid, progress_cb=_read_progress)
                            authed = sum(1 for s in sectors if s["authed"])
                            last_card = {"uid": uid, "type": ctype, "sectors": sectors}
                            status = f"UID:{uid.hex().upper()[:8]} {authed}/{len(sectors)}sec"
                            scroll = 0
                        else:
                            status = "No card detected"
                            last_card = None

                elif btn == "KEY2" and last_card:
                    fname = _save_dump(last_card["uid"], last_card["type"], last_card["sectors"])
                    status = f"Saved: {fname[:18]}"

                elif btn == "UP":
                    scroll = max(0, scroll - 1)
                elif btn == "DOWN":
                    if last_card:
                        scroll = min(scroll + 1, max(0, len(last_card["sectors"]) - 4))

                # Draw read mode
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.rectangle((0, 0, 127, 12), fill="#111")
                d.text((2, 1), "READ", font=font_sm, fill="#00CCFF")
                d.text((50, 1), drv_desc[:12] if drv else "NO READER", font=font_xs,
                       fill="#00FF00" if drv else "#FF4444")

                y = 16
                d.text((2, y), status[:24], font=font_sm, fill="#FFAA00")
                y += 13

                if last_card:
                    uid_hex = last_card["uid"].hex().upper()
                    d.text((2, y), f"UID: {uid_hex}", font=font_sm, fill="#00FF00")
                    y += 11
                    d.text((2, y), f"Type: {last_card['type']}", font=font_sm, fill="#ccc")
                    y += 13

                    secs = last_card["sectors"]
                    for i in range(scroll, min(len(secs), scroll + 4)):
                        s = secs[i]
                        col = "#00FF00" if s["authed"] else "#FF4444"
                        key_txt = s["key"][:6] if s["authed"] else "LOCKED"
                        d.text((2, y), f"S{s['sector']:02d}", font=font_sm, fill=col)
                        d.text((22, y), f"[{key_txt}]", font=font_sm, fill="#888")
                        if s["blocks"]:
                            d.text((72, y), s["blocks"][0][:12], font=font_xs, fill="#555")
                        y += 11
                else:
                    d.text((4, 55), "Press OK to read card", font=font_sm, fill="#666")

                d.rectangle((0, 116, 127, 127), fill="#111")
                d.text((2, 117), "OK:Read K2:Save K1:Mode", font=font_xs, fill="#666")
                lcd.LCD_ShowImage(img, 0, 0)

            # ===== CLONE MODE =====
            elif mode == "clone":
                dumps = _list_dumps()

                if btn == "UP":
                    scroll = max(0, scroll - 1)
                elif btn == "DOWN":
                    scroll = min(scroll + 1, max(0, len(dumps) - 1))
                elif btn == "OK" and dumps:
                    selected_dump = _load_dump(dumps[min(scroll, len(dumps) - 1)]["path"])
                    if selected_dump and drv and drv.can_write:
                        # Wait for target card
                        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                        d = ScaledDraw(img)
                        d.rectangle((0, 0, 127, 12), fill="#111")
                        d.text((2, 1), "CLONE", font=font_sm, fill="#FF00FF")
                        d.text((4, 30), f"Source: {selected_dump['uid'][:12]}", font=font_sm, fill="#ccc")
                        d.text((4, 50), "Place TARGET card", font=font_sm, fill="#FFAA00")
                        d.text((4, 65), "on reader now...", font=font_sm, fill="#FFAA00")
                        lcd.LCD_ShowImage(img, 0, 0)

                        uid = drv.read_passive_target(timeout=5.0)
                        if uid:
                            target_hex = uid.hex().upper()

                            def _clone_progress(sec, total, w, s, e):
                                pct = sec * 100 // max(1, total)
                                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                                d = ScaledDraw(img)
                                d.rectangle((0, 0, 127, 12), fill="#111")
                                d.text((2, 1), "CLONE", font=font_sm, fill="#FF00FF")
                                d.text((80, 1), f"{pct}%", font=font_sm, fill="#FF00FF")
                                d.text((4, 18), f"Target: {target_hex[:12]}", font=font_sm, fill="#ccc")
                                bar_y = 34
                                d.rectangle((4, bar_y, 123, bar_y + 8), outline="#333")
                                bw = max(1, int(119 * sec / max(1, total)))
                                d.rectangle((4, bar_y, 4 + bw, bar_y + 8), fill="#FF00FF")
                                d.text((4, bar_y + 12), f"Sector {sec}/{total}", font=font_sm, fill="#FFAA00")
                                d.text((4, bar_y + 26), f"Written:{w} Skip:{s} Err:{e}", font=font_xs, fill="#888")
                                lcd.LCD_ShowImage(img, 0, 0)

                            written, skipped, errors = _write_clone(drv, uid, selected_dump, progress_cb=_clone_progress)
                            if errors == 0 and written > 0:
                                status = f"Cloned! {written} blocks"
                            else:
                                status = f"W:{written} S:{skipped} E:{errors}"
                        else:
                            status = "No target card"
                    elif not drv:
                        status = "No reader connected"
                    elif not drv.can_write:
                        status = "Reader can't write"

                # Draw clone mode
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.rectangle((0, 0, 127, 12), fill="#111")
                d.text((2, 1), "CLONE", font=font_sm, fill="#FF00FF")
                d.text((80, 1), f"{len(dumps)}cards", font=font_xs, fill="#888")

                y = 16
                d.text((2, y), status[:24], font=font_sm, fill="#FFAA00")
                y += 13

                if not dumps:
                    d.text((4, 50), "No saved cards", font=font_sm, fill="#666")
                    d.text((4, 65), "Read a card first", font=font_sm, fill="#888")
                else:
                    d.text((2, y), "Select card to clone:", font=font_xs, fill="#888")
                    y += 10
                    for i in range(max(0, scroll - 2), min(len(dumps), scroll + 4)):
                        dm = dumps[i]
                        col = "#FF00FF" if i == scroll else "#888"
                        prefix = "> " if i == scroll else "  "
                        d.text((2, y), f"{prefix}{dm['uid'][:10]}", font=font_sm, fill=col)
                        d.text((85, y), dm["type"][:8], font=font_xs, fill="#555")
                        y += 11
                        if y > 108:
                            break

                d.rectangle((0, 116, 127, 127), fill="#111")
                can_w = drv.can_write if drv else False
                d.text((2, 117), "OK:Clone" if can_w else "Reader: read-only", font=font_xs,
                       fill="#666" if can_w else "#FF4444")
                lcd.LCD_ShowImage(img, 0, 0)

            # ===== SAVED MODE =====
            elif mode == "saved":
                dumps = _list_dumps()

                if btn == "UP":
                    scroll = max(0, scroll - 1)
                elif btn == "DOWN":
                    scroll = min(scroll + 1, max(0, len(dumps) - 1))
                elif btn == "KEY2" and dumps:
                    # Delete selected dump
                    idx = min(scroll, len(dumps) - 1)
                    try:
                        os.remove(dumps[idx]["path"])
                        status = f"Deleted {dumps[idx]['uid'][:8]}"
                        dumps = _list_dumps()
                        scroll = min(scroll, max(0, len(dumps) - 1))
                    except Exception:
                        status = "Delete failed"
                elif btn == "OK" and dumps:
                    # Show dump detail
                    idx = min(scroll, len(dumps) - 1)
                    dump = _load_dump(dumps[idx]["path"])
                    if dump:
                        detail_scroll = 0
                        while True:
                            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                            d = ScaledDraw(img)
                            d.rectangle((0, 0, 127, 12), fill="#111")
                            d.text((2, 1), "CARD DETAIL", font=font_sm, fill="#00CCFF")

                            y = 16
                            d.text((2, y), f"UID: {dump['uid']}", font=font_sm, fill="#00FF00")
                            y += 11
                            d.text((2, y), f"Type: {dump.get('type', '?')}", font=font_sm, fill="#ccc")
                            y += 11
                            d.text((2, y), f"Date: {dump.get('timestamp', '?')[:10]}", font=font_sm, fill="#888")
                            y += 13

                            secs = dump.get("sectors", [])
                            for i in range(detail_scroll, min(len(secs), detail_scroll + 4)):
                                s = secs[i]
                                col = "#00FF00" if s.get("key", "") not in ("", "NONE") else "#FF4444"
                                d.text((2, y), f"S{s['sector']:02d} [{s.get('key', '?')[:6]}]", font=font_sm, fill=col)
                                if s.get("blocks"):
                                    d.text((72, y), s["blocks"][0][:12], font=font_xs, fill="#555")
                                y += 11

                            d.rectangle((0, 116, 127, 127), fill="#111")
                            d.text((2, 117), "^v:Scroll KEY3:Back", font=font_xs, fill="#666")
                            lcd.LCD_ShowImage(img, 0, 0)

                            b2 = _btn()
                            if b2 == "KEY3":
                                break
                            elif b2 == "UP":
                                detail_scroll = max(0, detail_scroll - 1)
                            elif b2 == "DOWN":
                                detail_scroll = min(detail_scroll + 1, max(0, len(secs) - 4))

                # Draw saved mode
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.rectangle((0, 0, 127, 12), fill="#111")
                d.text((2, 1), "SAVED", font=font_sm, fill="#00FF00")
                d.text((80, 1), f"{len(dumps)}cards", font=font_xs, fill="#888")

                y = 16
                d.text((2, y), status[:24], font=font_sm, fill="#FFAA00")
                y += 13

                if not dumps:
                    d.text((4, 50), "No saved cards", font=font_sm, fill="#666")
                else:
                    for i in range(max(0, scroll - 2), min(len(dumps), scroll + 5)):
                        dm = dumps[i]
                        col = "#00CCFF" if i == scroll else "#888"
                        prefix = "> " if i == scroll else "  "
                        d.text((2, y), f"{prefix}{dm['uid'][:10]}", font=font_sm, fill=col)
                        d.text((78, y), dm["type"][:7], font=font_xs, fill="#555")
                        d.text((110, y), f"{dm['sectors']}s", font=font_xs, fill="#444")
                        y += 11
                        if y > 108:
                            break

                d.rectangle((0, 116, 127, 127), fill="#111")
                d.text((2, 117), "OK:View K2:Del K1:Mode", font=font_xs, fill="#666")
                lcd.LCD_ShowImage(img, 0, 0)

            time.sleep(0.03)

    finally:
        if drv:
            drv.close()
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
