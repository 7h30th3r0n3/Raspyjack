#!/usr/bin/env python3
"""
RaspyJack Payload -- NFC/RFID Reader
======================================
Author: 7h30th3r0n3

NFC/RFID reader via PN532 module over I2C.  Detects cards, reads UIDs,
identifies card type, and attempts MIFARE Classic sector dumps using
common default keys.

Setup / Prerequisites
---------------------
- PN532 module connected via I2C (address 0x24).
- I2C enabled (dtparam=i2c_arm=on in config.txt).
- python3-smbus or smbus2 installed.

Controls
--------
  OK         -- Read card (poll for card and read)
  UP / DOWN  -- Scroll sectors / data
  KEY1       -- Scan I2C bus for PN532
  KEY2       -- Export card dump to loot
  KEY3       -- Exit
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
from PIL import Image, ImageDraw, ImageFont
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

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
font = scaled_font()

PN532_I2C_ADDR = 0x24
I2C_BUS = 1
LOOT_DIR = "/root/Raspyjack/loot/NFC"
DEBOUNCE = 0.22

DEFAULT_KEYS = [
    bytes.fromhex("FFFFFFFFFFFF"), bytes.fromhex("A0A1A2A3A4A5"),
    bytes.fromhex("D3F7D3F7D3F7"), bytes.fromhex("000000000000"),
]

# PN532 command constants
PN532_PREAMBLE = 0x00
PN532_STARTCODE1 = 0x00
PN532_STARTCODE2 = 0xFF
PN532_HOSTTOPN532 = 0xD4
PN532_PN532TOHOST = 0xD5
CMD_SAMCONFIGURATION = 0x14
CMD_INLISTPASSIVETARGET = 0x4A
CMD_INDATAEXCHANGE = 0x40
CMD_GETFIRMWAREVERSION = 0x02

lock = threading.Lock()
_running = True


# PN532 I2C low-level

class PN532I2C:
    """Minimal PN532 I2C driver."""

    def __init__(self, bus_num=I2C_BUS, addr=PN532_I2C_ADDR):
        self.bus = smbus.SMBus(bus_num)
        self.addr = addr

    def close(self):
        try:
            self.bus.close()
        except Exception:
            pass

    def _write_frame(self, data):
        """Send a PN532 command frame."""
        length = len(data) + 1
        lcs = (~length + 1) & 0xFF
        frame = [PN532_PREAMBLE, PN532_STARTCODE1, PN532_STARTCODE2,
                 length, lcs, PN532_HOSTTOPN532] + list(data)
        dcs = (~(sum([PN532_HOSTTOPN532] + list(data))) + 1) & 0xFF
        frame.append(dcs)
        frame.append(0x00)  # postamble
        self.bus.write_i2c_block_data(self.addr, frame[0], frame[1:])

    def _read_response(self, expected_len=32, timeout=1.0):
        """Read a response frame, waiting for the ready bit."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                status = self.bus.read_byte(self.addr)
                if status & 0x01:
                    raw = self.bus.read_i2c_block_data(self.addr, 0x00, expected_len + 8)
                    # Skip ready byte and find data
                    if len(raw) > 7:
                        return raw
                    return raw
            except OSError:
                pass
            time.sleep(0.02)
        return None

    def get_firmware_version(self):
        """Return (IC, ver, rev, support) or None."""
        self._write_frame([CMD_GETFIRMWAREVERSION])
        resp = self._read_response(12)
        if resp is None:
            return None
        # Find response code 0xD5 0x03
        for i in range(len(resp) - 5):
            if resp[i] == PN532_PN532TOHOST and resp[i + 1] == 0x03:
                return (resp[i + 2], resp[i + 3], resp[i + 4], resp[i + 5])
        return None

    def sam_config(self):
        """Configure SAM for normal mode."""
        self._write_frame([CMD_SAMCONFIGURATION, 0x01, 0x14, 0x01])
        self._read_response(12)

    def read_passive_target(self, timeout=2.0):
        """Poll for a passive target. Return UID bytes or None."""
        self._write_frame([CMD_INLISTPASSIVETARGET, 0x01, 0x00])
        resp = self._read_response(32, timeout=timeout)
        if resp is None:
            return None
        # Parse InListPassiveTarget response
        for i in range(len(resp) - 3):
            if resp[i] == PN532_PN532TOHOST and resp[i + 1] == 0x4B:
                num_targets = resp[i + 2]
                if num_targets < 1:
                    return None
                # resp[i+3] = target number, resp[i+4] = SENS_RES, etc.
                uid_len_idx = i + 7
                if uid_len_idx >= len(resp):
                    return None
                uid_len = resp[uid_len_idx]
                uid_start = uid_len_idx + 1
                uid_end = uid_start + uid_len
                if uid_end <= len(resp):
                    return bytes(resp[uid_start:uid_end])
        return None

    def mifare_auth_block(self, block, key, uid):
        """Authenticate a MIFARE Classic block with Key A."""
        cmd = [CMD_INDATAEXCHANGE, 0x01, 0x60, block] + list(key) + list(uid[:4])
        self._write_frame(cmd)
        resp = self._read_response(12, timeout=1.0)
        if resp is None:
            return False
        for i in range(len(resp) - 2):
            if resp[i] == PN532_PN532TOHOST and resp[i + 1] == 0x41:
                return resp[i + 2] == 0x00
        return False

    def mifare_read_block(self, block):
        """Read 16 bytes from a MIFARE Classic block."""
        cmd = [CMD_INDATAEXCHANGE, 0x01, 0x30, block]
        self._write_frame(cmd)
        resp = self._read_response(32, timeout=1.0)
        if resp is None:
            return None
        for i in range(len(resp) - 18):
            if resp[i] == PN532_PN532TOHOST and resp[i + 1] == 0x41:
                if resp[i + 2] == 0x00:
                    return bytes(resp[i + 3:i + 19])
        return None


# I2C scan

def _scan_i2c_for_pn532():
    """Scan I2C bus for PN532 address."""
    if not SMBUS_OK:
        return False, "smbus not installed"
    for addr in [PN532_I2C_ADDR] + list(range(0x20, 0x30)):
        try:
            bus = smbus.SMBus(I2C_BUS)
            bus.read_byte(addr)
            bus.close()
            return True, f"Found at 0x{addr:02X}"
        except OSError:
            continue
    return False, "PN532 not found"


# Card type detection

def _detect_card_type(uid):
    """Guess card type from UID length."""
    uid_len = len(uid)
    if uid_len == 4:
        return "MIFARE Classic 1K/4K"
    if uid_len == 7:
        return "MIFARE Ultralight/NTAG"
    if uid_len == 10:
        return "MIFARE DESFire"
    return f"Unknown ({uid_len}B UID)"


# State

card_uid = None
card_type = ""
sector_data = []   # list of {"sector": N, "blocks": [...], "key_used": hex}
status_msg = "Ready"
scroll = 0
pn532 = None


# Export

def _export_dump():
    """Write card data to loot JSON."""
    if card_uid is None:
        return "No card data"
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    uid_hex = card_uid.hex().upper()
    fname = f"nfc_{uid_hex}_{ts}.json"
    fpath = os.path.join(LOOT_DIR, fname)

    dump = {
        "timestamp": ts,
        "uid": uid_hex,
        "uid_bytes": len(card_uid),
        "card_type": card_type,
        "sectors": [],
    }
    for s in sector_data:
        dump["sectors"].append({
            "sector": s["sector"],
            "key_used": s["key_used"],
            "blocks": [b.hex() if isinstance(b, bytes) else b for b in s["blocks"]],
        })

    try:
        with open(fpath, "w") as fh:
            json.dump(dump, fh, indent=2)
        return f"Saved: {fname[:16]}"
    except OSError as exc:
        return f"Err: {str(exc)[:16]}"


# Card reading

def _read_card():
    """Attempt to read a card: UID, type, MIFARE sector dump."""
    global card_uid, card_type, sector_data, status_msg, pn532

    if not SMBUS_OK:
        status_msg = "smbus not found"
        return

    try:
        if pn532 is None:
            pn532 = PN532I2C()
            pn532.sam_config()
    except Exception as exc:
        status_msg = f"Init err: {str(exc)[:14]}"
        pn532 = None
        return

    status_msg = "Polling..."
    uid = pn532.read_passive_target(timeout=3.0)
    if uid is None:
        status_msg = "No card detected"
        return

    with lock:
        card_uid = uid
        card_type = _detect_card_type(uid)
        sector_data = []
        status_msg = f"UID: {uid.hex().upper()}"

    # Attempt MIFARE Classic dump if 4-byte UID
    if len(uid) == 4:
        sectors = []
        for sector in range(16):
            first_block = sector * 4
            authenticated = False
            used_key = ""
            for key in DEFAULT_KEYS:
                if pn532.mifare_auth_block(first_block, key, uid):
                    authenticated = True
                    used_key = key.hex().upper()
                    break
            blocks = []
            if authenticated:
                for b in range(4):
                    data = pn532.mifare_read_block(first_block + b)
                    blocks.append(data if data else b"?" * 16)
            sectors.append({
                "sector": sector,
                "blocks": blocks,
                "key_used": used_key if authenticated else "NONE",
            })
        with lock:
            sector_data = sectors
            status_msg = f"Read {sum(1 for s in sectors if s['key_used'] != 'NONE')}/16 sectors"


# Drawing

def _draw_main(lcd, status, uid, ctype, sectors, scr):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "NFC READER", font=font, fill="#00ccff")
    d.text((108, 1), "K3", font=font, fill="#888")

    y = 16
    d.text((2, y), status[:22], font=font, fill="#ffaa00"); y += 13

    if uid is not None:
        uid_hex = uid.hex().upper()
        d.text((2, y), f"UID: {uid_hex[:16]}", font=font, fill="#00ff00"); y += 12
        d.text((2, y), f"Type: {ctype[:18]}", font=font, fill="#ccc"); y += 14

        if sectors:
            visible = 4
            end = min(len(sectors), scr + visible)
            for i in range(scr, end):
                s = sectors[i]
                key_info = s["key_used"][:6] if s["key_used"] != "NONE" else "locked"
                color = "#00ff00" if s["key_used"] != "NONE" else "#ff4444"
                d.text((2, y), f"S{s['sector']:02d} [{key_info}]", font=font, fill=color)
                # Show first block preview
                if s["blocks"]:
                    blk = s["blocks"][0]
                    if isinstance(blk, bytes):
                        preview = blk[:6].hex().upper()
                    else:
                        preview = str(blk)[:12]
                    d.text((70, y), preview[:10], font=font, fill="#888")
                y += 12
    else:
        d.text((4, 50), "Press OK to read", font=font, fill="#666")
        d.text((4, 64), "K1 to scan I2C", font=font, fill="#888")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:read K1:scan K2:exp", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)


# Main

def main():
    global _running, scroll, status_msg, pn532

    if not SMBUS_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "smbus not found!", font=font, fill="#ff0000")
        d.text((4, 65), "pip install smbus2", font=font, fill="#888")
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        LCD.LCD_Clear()
        GPIO.cleanup()
        return 1

    last_press = 0.0

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if btn == "KEY3":
                break
            elif btn == "OK":
                _read_card()
                scroll = 0
            elif btn == "KEY1":
                found, msg = _scan_i2c_for_pn532()
                status_msg = msg
            elif btn == "KEY2":
                status_msg = _export_dump()
            elif btn == "UP":
                scroll = max(0, scroll - 1)
            elif btn == "DOWN":
                with lock:
                    max_s = max(0, len(sector_data) - 4)
                scroll = min(scroll + 1, max_s)

            with lock:
                _draw_main(LCD, status_msg, card_uid, card_type, list(sector_data), scroll)

            time.sleep(0.08)

    finally:
        _running = False
        if pn532 is not None:
            pn532.close()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
