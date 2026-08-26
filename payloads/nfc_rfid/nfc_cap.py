#!/usr/bin/env python3
"""
RaspyJack Payload -- NFC Cap HAT (ST25R3916)
===============================================
MIFARE Classic read/write/clone/emulate via CardputerZero Cap HAT.

Controls:
  UP/DOWN    Navigate menus / scroll data
  OK         Select / confirm
  KEY1       Action (save / emulate)
  KEY2       Action (write / details)
  KEY3       Back / exit
"""

import os
import sys
import json
import time

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
W, H = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
DEBOUNCE = 0.18
LOOT_DIR = "/root/Raspyjack/loot/NFC"

COMMON_KEYS = [
    bytes.fromhex(k) for k in [
        "FFFFFFFFFFFF", "A0A1A2A3A4A5", "D3F7D3F7D3F7",
        "000000000000", "B0B1B2B3B4B5", "AABBCCDDEEFF",
        "1A2B3C4D5E6F", "010203040506", "123456789ABC",
        "4D3A99C351DD", "714C5C886E97", "587EE5F9350F",
    ]
]

MENU_ITEMS = ["Read", "Saved", "Emulate", "EMV", "Write"]

_lcd = None
_font = None
_font_sm = None
_font_xs = None
_last_btn = 0
_running = True


def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE:
        return None
    if b:
        _last_btn = now
    return b


def _show(img):
    _lcd.LCD_ShowImage(img, 0, 0)


def _draw_header(d, title, right=""):
    d.rectangle((0, 0, W - 1, 13), fill="#111")
    d.text((2, 1), title, font=_font_sm, fill="#00CCFF")
    if right:
        d.text((W - len(right) * 6 - 2, 1), right, font=_font_xs, fill="#888")


def _draw_footer(d, text):
    d.rectangle((0, H - 14, W - 1, H - 1), fill="#111")
    d.text((2, H - 13), text, font=_font_xs, fill="#666")


def _draw_msg(title, msg, color="#FFAA00"):
    img = Image.new("RGB", (W, H), "black")
    d = ScaledDraw(img)
    _draw_header(d, "NFC Cap")
    d.text((W // 2, H // 2 - 10), title, font=_font, fill=color, anchor="mm")
    d.text((W // 2, H // 2 + 8), msg, font=_font_sm, fill="#888", anchor="mm")
    _show(img)


def _open_driver():
    from payloads._st25r_driver import ST25R3916Driver
    drv = ST25R3916Driver()
    if drv.open():
        return drv
    return None


def _safe_close(drv):
    if drv:
        try:
            drv._cmd(0xC2)
        except Exception:
            pass
        drv.close()
    import gc
    gc.collect()


def _card_type_str(sak):
    if sak == 0x08:
        return "MIFARE Classic 1K"
    elif sak == 0x18:
        return "MIFARE Classic 4K"
    elif sak == 0x09:
        return "MIFARE Mini"
    elif sak == 0x00:
        return "MIFARE Ultralight"
    elif sak == 0x20:
        return "ISO14443-4 (EMV?)"
    return f"Unknown (SAK=0x{sak:02X})"


def _is_classic(sak):
    return sak in (0x08, 0x09, 0x18, 0x88, 0x28, 0x01)


# ── Read Mode ─────────────────────────────────────────────────────────

def _mode_read():
    _draw_msg("Read", "Opening NFC...")
    drv = _open_driver()
    if not drv:
        _draw_msg("Error", "ST25R3916 not found", "#FF4444")
        time.sleep(2)
        return

    try:
        card = None
        card_data = None
        scroll = 0

        while _running:
            btn = _btn()
            if btn == "KEY3":
                return

            if btn == "OK" or card is None:
                _draw_msg("Read", "Place card...")
                card = drv.read_passive_target(timeout=2.0)
                if not card:
                    _draw_msg("Read", "No card found", "#FF4444")
                    time.sleep(1)
                    continue
                card_type = _card_type_str(card.sak)
                if _is_classic(card.sak):
                    card_data = _read_classic(drv, card)
                else:
                    card_data = {"blocks": {}}
                scroll = 0

            if btn == "KEY1" and card and card_data:
                fname = _save_dump(card, card_data)
                _draw_msg("Saved", fname[:20], "#00FF00")
                time.sleep(1.5)

            if btn == "UP":
                scroll = max(0, scroll - 1)
            elif btn == "DOWN":
                scroll += 1

            if card:
                _draw_card_info(card, card_data, scroll)
            time.sleep(0.05)
    finally:
        _safe_close(drv)


def _read_classic(drv, card):
    from payloads.nfc_rfid._nfc_driver import MIFARE_AUTH_A, MIFARE_AUTH_B
    uid = card.uid
    sak = card.sak
    n_sectors = 16
    if sak == 0x18:
        n_sectors = 40
    elif sak == 0x09:
        n_sectors = 5

    result = {"blocks": {}, "keys_a": {}, "keys_b": {}, "sectors_ok": 0}
    last_key = None

    for sec in range(n_sectors):
        first_block = sec * 4 if sec < 32 else 128 + (sec - 32) * 16
        n_blocks = 4 if sec < 32 else 16

        pct = (sec + 1) * 100 // n_sectors
        img = Image.new("RGB", (W, H), "black")
        d = ScaledDraw(img)
        _draw_header(d, "Reading", f"{pct}%")
        d.text((4, 20), f"UID: {uid.hex().upper()}", font=_font_sm, fill="#00FF00")
        d.text((4, 34), f"Sector {sec}/{n_sectors}", font=_font_sm, fill="#FFAA00")
        bw = max(1, int((W - 8) * sec // max(1, n_sectors)))
        d.rectangle((4, 50, W - 4, 58), outline="#333")
        d.rectangle((4, 50, 4 + bw, 58), fill="#00CCFF")
        d.text((4, 64), f"OK: {result['sectors_ok']}  Locked: {sec - result['sectors_ok']}", font=_font_xs, fill="#888")
        _show(img)

        if sec > 0:
            drv._cmd(0xC2)
            time.sleep(0.003)
            drv._configure_nfc_a()
            c2 = drv._activate_nfca()
            if not c2:
                continue

        key_found = None
        kt_found = MIFARE_AUTH_A

        if last_key:
            if drv.mifare_auth(first_block, last_key[0], uid, last_key[1]):
                key_found, kt_found = last_key

        if not key_found:
            for key in COMMON_KEYS:
                if drv.mifare_auth(first_block, key, uid, MIFARE_AUTH_A):
                    key_found = key
                    kt_found = MIFARE_AUTH_A
                    break
                drv._cmd(0xC2)
                time.sleep(0.002)
                drv._configure_nfc_a()
                drv._activate_nfca()

        if not key_found:
            for key in COMMON_KEYS[:5]:
                if drv.mifare_auth(first_block, key, uid, MIFARE_AUTH_B):
                    key_found = key
                    kt_found = MIFARE_AUTH_B
                    break
                drv._cmd(0xC2)
                time.sleep(0.002)
                drv._configure_nfc_a()
                drv._activate_nfca()

        if key_found:
            last_key = (key_found, kt_found)
            result["sectors_ok"] += 1
            if kt_found == MIFARE_AUTH_A:
                result["keys_a"][str(sec)] = key_found.hex().upper()
            else:
                result["keys_b"][str(sec)] = key_found.hex().upper()

            for blk_off in range(n_blocks):
                blk = first_block + blk_off
                data = drv.mifare_read(blk)
                if data:
                    result["blocks"][str(blk)] = data.hex().upper()

    drv._cmd(0xC2)
    return result


def _draw_card_info(card, card_data, scroll):
    img = Image.new("RGB", (W, H), "black")
    d = ScaledDraw(img)
    _draw_header(d, "NFC Read")
    y = 16
    d.text((2, y), f"UID: {card.uid.hex().upper()}", font=_font_sm, fill="#00FF00")
    y += 12
    d.text((2, y), _card_type_str(card.sak), font=_font_sm, fill="#ccc")
    y += 12
    d.text((2, y), f"ATQA:{card.atqa:04X} SAK:{card.sak:02X}", font=_font_xs, fill="#888")
    y += 12

    blocks = card_data.get("blocks", {})
    ok = card_data.get("sectors_ok", 0)
    total = len(set(int(k) // 4 for k in blocks.keys())) if blocks else 0
    d.text((2, y), f"Blocks: {len(blocks)}  Sectors: {ok}", font=_font_sm, fill="#FFAA00")
    y += 14

    sorted_blocks = sorted(blocks.keys(), key=int)
    vis = (H - y - 14) // 10
    for i in range(scroll, min(len(sorted_blocks), scroll + vis)):
        blk_num = sorted_blocks[i]
        hex_data = blocks[blk_num]
        d.text((2, y), f"B{int(blk_num):02d}", font=_font_xs, fill="#00CCFF")
        d.text((22, y), hex_data[:24], font=_font_xs, fill="#aaa")
        y += 10

    _draw_footer(d, "OK:Rescan K1:Save K3:Back")
    _show(img)


# ── Save / Load ───────────────────────────────────────────────────────

def _save_dump(card, card_data):
    """Save dump in Flipper Zero .nfc format + JSON backup."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    uid_hex = card.uid.hex().upper()
    uid_spaced = ' '.join(f'{b:02X}' for b in card.uid)
    atqa_spaced = f'{card.atqa & 0xFF:02X} {(card.atqa >> 8) & 0xFF:02X}'
    sak_hex = f'{card.sak:02X}'
    card_type = _card_type_str(card.sak)
    blocks = card_data.get("blocks", {})

    # Flipper .nfc format
    fname_nfc = f"{uid_hex}_{int(time.time())}.nfc"
    lines = [
        "Filetype: Flipper NFC device",
        "Version: 4",
        f"# Device type can be ISO14443-3A, MIFARE Classic, MIFARE Ultralight",
        f"Device type: {card_type}",
        f"# UID is common for all formats",
        f"UID: {uid_spaced}",
        f"ATQA: {atqa_spaced}",
        f"SAK: {sak_hex}",
    ]
    if "Classic" in card_type:
        mf_type = "4K" if card.sak == 0x18 else "1K"
        lines.append("# Mifare Classic specific data")
        lines.append(f"Mifare Classic type: {mf_type}")
        lines.append("Data format version: 2")
        lines.append("# Mifare Classic blocks, '??' means unknown data")
        total = 256 if mf_type == "4K" else 64
        for i in range(total):
            bdata = blocks.get(str(i), blocks.get(i))
            if bdata:
                spaced = ' '.join(bdata[j:j+2] for j in range(0, len(bdata), 2))
            else:
                spaced = ' '.join(['??'] * 16)
            lines.append(f"Block {i}: {spaced}")
    with open(os.path.join(LOOT_DIR, fname_nfc), "w") as f:
        f.write('\n'.join(lines) + '\n')
    return fname_nfc


def _list_dumps():
    if not os.path.isdir(LOOT_DIR):
        return []
    files = [f for f in os.listdir(LOOT_DIR)
             if f.endswith(".nfc") or f.endswith(".json")]
    files.sort(reverse=True)
    return files


def _load_dump(fname):
    path = os.path.join(LOOT_DIR, fname)
    if fname.endswith(".nfc"):
        return _load_flipper_nfc(path)
    with open(path) as f:
        return json.load(f)


def _load_flipper_nfc(path):
    """Parse Flipper .nfc file into our dict format."""
    dump = {"blocks": {}, "keys_a": {}, "keys_b": {}}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("UID:"):
                dump["uid"] = line.split(":", 1)[1].strip().replace(" ", "")
            elif line.startswith("ATQA:"):
                parts = line.split(":", 1)[1].strip().split()
                dump["atqa"] = parts[1] + parts[0] if len(parts) >= 2 else parts[0]
            elif line.startswith("SAK:"):
                dump["sak"] = line.split(":", 1)[1].strip()
            elif line.startswith("Device type:"):
                dump["type"] = line.split(":", 1)[1].strip()
            elif line.startswith("Block "):
                parts = line.split(":", 1)
                blk_num = parts[0].replace("Block ", "").strip()
                blk_data = parts[1].strip().replace(" ", "").replace("??", "00")
                dump["blocks"][blk_num] = blk_data
    return dump


# ── Saved Mode ────────────────────────────────────────────────────────

def _mode_saved():
    files = _list_dumps()
    if not files:
        _draw_msg("Saved", "No saved cards", "#888")
        time.sleep(2)
        return

    cursor = 0
    selected = None

    while _running:
        btn = _btn()
        if btn == "KEY3":
            if selected:
                selected = None
            else:
                return
        if btn == "UP":
            cursor = max(0, cursor - 1)
        if btn == "DOWN":
            cursor = min(len(files) - 1, cursor + 1)
        if btn == "OK":
            if selected is None:
                try:
                    selected = _load_dump(files[cursor])
                except Exception:
                    _draw_msg("Error", "Bad file", "#FF4444")
                    time.sleep(1)
                    selected = None
        if btn == "KEY1" and selected:
            _emulate_dump(selected)
            selected = None

        img = Image.new("RGB", (W, H), "black")
        d = ScaledDraw(img)
        _draw_header(d, "Saved Cards", f"{len(files)}")

        if selected:
            y = 16
            d.text((2, y), f"UID: {selected.get('uid', '?')}", font=_font_sm, fill="#00FF00")
            y += 12
            d.text((2, y), selected.get("type", "?"), font=_font_sm, fill="#ccc")
            y += 12
            n_blk = len(selected.get("blocks", {}))
            d.text((2, y), f"Blocks: {n_blk}", font=_font_sm, fill="#FFAA00")
            y += 16
            d.text((2, y), "K1: Emulate", font=_font_sm, fill="#00CCFF")
            y += 12
            d.text((2, y), "K3: Back", font=_font_sm, fill="#888")
        else:
            y = 16
            vis = (H - y - 14) // 12
            start = max(0, cursor - vis // 2)
            for i in range(start, min(len(files), start + vis)):
                is_sel = i == cursor
                if is_sel:
                    d.rectangle((0, y, W - 1, y + 11), fill="#222")
                label = files[i][:20]
                d.text((4, y), label, font=_font_sm, fill="#FFAA00" if is_sel else "#888")
                y += 12

        _draw_footer(d, "OK:Open K1:Emu K3:Back")
        _show(img)
        time.sleep(0.05)


# ── Emulate Mode ──────────────────────────────────────────────────────

def _mode_emulate():
    files = _list_dumps()
    if not files:
        _draw_msg("Emulate", "No saved cards", "#888")
        time.sleep(2)
        return

    cursor = 0
    while _running:
        btn = _btn()
        if btn == "KEY3":
            return
        if btn == "UP":
            cursor = max(0, cursor - 1)
        if btn == "DOWN":
            cursor = min(len(files) - 1, cursor + 1)
        if btn == "OK":
            try:
                dump = _load_dump(files[cursor])
                _emulate_dump(dump)
            except Exception:
                _draw_msg("Error", "Emulation failed", "#FF4444")
                time.sleep(1)

        img = Image.new("RGB", (W, H), "black")
        d = ScaledDraw(img)
        _draw_header(d, "Emulate")
        y = 16
        vis = (H - y - 14) // 12
        start = max(0, cursor - vis // 2)
        for i in range(start, min(len(files), start + vis)):
            is_sel = i == cursor
            if is_sel:
                d.rectangle((0, y, W - 1, y + 11), fill="#222")
            d.text((4, y), files[i][:20], font=_font_sm, fill="#FFAA00" if is_sel else "#888")
            y += 12
        _draw_footer(d, "OK:Emulate K3:Back")
        _show(img)
        time.sleep(0.05)


def _emulate_dump(dump):
    uid = bytes.fromhex(dump.get("uid", "00000000"))
    atqa = int(dump.get("atqa", "0004"), 16)
    sak = int(dump.get("sak", "08"), 16)

    _draw_msg("Emulating", f"UID: {uid.hex().upper()}", "#00FF00")

    drv = _open_driver()
    if not drv:
        _draw_msg("Error", "ST25R3916 not found", "#FF4444")
        time.sleep(2)
        return

    try:
        from payloads._nfc_emulator import NFCEmulator
        emu = NFCEmulator(drv)

        blocks_dict = dump.get("blocks", {})
        if blocks_dict and _is_classic(sak):
            data_blocks = {}
            for k, v in blocks_dict.items():
                data_blocks[int(k)] = bytes.fromhex(v)

            keys_a = {}
            for k, v in dump.get("keys_a", {}).items():
                keys_a[int(k)] = bytes.fromhex(v)
            keys_b = {}
            for k, v in dump.get("keys_b", {}).items():
                keys_b[int(k)] = bytes.fromhex(v)

            stop = [False]

            def check_stop():
                b = _btn()
                if b == "KEY3":
                    stop[0] = True
                return stop[0]

            img = Image.new("RGB", (W, H), "black")
            d = ScaledDraw(img)
            _draw_header(d, "Emulating")
            d.text((W // 2, 30), uid.hex().upper(), font=_font, fill="#00FF00", anchor="mm")
            d.text((W // 2, 50), _card_type_str(sak), font=_font_sm, fill="#ccc", anchor="mm")
            d.text((W // 2, 70), "Present reader to CZ", font=_font_xs, fill="#FFAA00", anchor="mm")
            _draw_footer(d, "K3: Stop")
            _show(img)

            emu.emulate_mifare_classic(
                uid=uid, atqa=atqa, sak=sak,
                data_blocks=data_blocks,
                keys_a=keys_a, keys_b=keys_b,
                timeout=60.0,
            )
        else:
            emu.emulate_uid_only(uid=uid, atqa=atqa, sak=sak, timeout=30.0)

    except Exception as e:
        _draw_msg("Emulation", str(e)[:20], "#FF4444")
        time.sleep(1)
    finally:
        _safe_close(drv)


# ── EMV Mode ──────────────────────────────────────────────────────────

def _mode_emv():
    _draw_msg("EMV", "Opening NFC...")
    drv = _open_driver()
    if not drv:
        _draw_msg("Error", "ST25R3916 not found", "#FF4444")
        time.sleep(2)
        return

    try:
        _draw_msg("EMV", "Place payment card...")
        card = drv.read_passive_target(timeout=3.0)
        if not card:
            _draw_msg("EMV", "No card found", "#FF4444")
            time.sleep(2)
            return

        _draw_msg("EMV", "Reading...")
        try:
            from payloads._iso14443_4 import ISO14443_4
            from payloads._emv_reader import EMVReader
            iso = ISO14443_4(drv)
            ats = iso.activate()
            if not ats:
                _draw_msg("EMV", "No ATS (not EMV?)", "#FF4444")
                time.sleep(2)
                return
            reader = EMVReader(iso)
            emv_data = reader.read_card()
        except Exception as e:
            _draw_msg("EMV Error", str(e)[:20], "#FF4444")
            time.sleep(2)
            return

        scroll = 0
        while _running:
            btn = _btn()
            if btn == "KEY3":
                return
            if btn == "UP":
                scroll = max(0, scroll - 1)
            if btn == "DOWN":
                scroll += 1

            img = Image.new("RGB", (W, H), "black")
            d = ScaledDraw(img)
            _draw_header(d, "EMV Card")

            lines = []
            if hasattr(emv_data, 'pan') and emv_data.pan:
                masked = "*" * (len(emv_data.pan) - 4) + emv_data.pan[-4:]
                lines.append(("PAN", masked))
            if hasattr(emv_data, 'expiry') and emv_data.expiry:
                lines.append(("Exp", emv_data.expiry))
            if hasattr(emv_data, 'cardholder') and emv_data.cardholder:
                lines.append(("Name", emv_data.cardholder[:20]))
            if hasattr(emv_data, 'app_label') and emv_data.app_label:
                lines.append(("App", emv_data.app_label))
            if hasattr(emv_data, 'aid') and emv_data.aid:
                lines.append(("AID", emv_data.aid))
            if not lines:
                lines.append(("Info", "No EMV data found"))

            y = 18
            for i in range(scroll, min(len(lines), scroll + 8)):
                label, val = lines[i]
                d.text((2, y), f"{label}:", font=_font_sm, fill="#00CCFF")
                d.text((40, y), val[:18], font=_font_sm, fill="#ccc")
                y += 13

            _draw_footer(d, "K3: Back")
            _show(img)
            time.sleep(0.05)

    finally:
        _safe_close(drv)


# ── Write Mode ────────────────────────────────────────────────────────

def _mode_write():
    files = _list_dumps()
    if not files:
        _draw_msg("Write", "No saved cards", "#888")
        time.sleep(2)
        return

    cursor = 0
    while _running:
        btn = _btn()
        if btn == "KEY3":
            return
        if btn == "UP":
            cursor = max(0, cursor - 1)
        if btn == "DOWN":
            cursor = min(len(files) - 1, cursor + 1)
        if btn == "OK":
            try:
                dump = _load_dump(files[cursor])
                _write_dump(dump)
            except Exception as e:
                _draw_msg("Error", str(e)[:20], "#FF4444")
                time.sleep(1)

        img = Image.new("RGB", (W, H), "black")
        d = ScaledDraw(img)
        _draw_header(d, "Write Card")
        y = 16
        vis = (H - y - 14) // 12
        start = max(0, cursor - vis // 2)
        for i in range(start, min(len(files), start + vis)):
            is_sel = i == cursor
            if is_sel:
                d.rectangle((0, y, W - 1, y + 11), fill="#222")
            d.text((4, y), files[i][:20], font=_font_sm, fill="#FFAA00" if is_sel else "#888")
            y += 12
        _draw_footer(d, "OK:Write K3:Back")
        _show(img)
        time.sleep(0.05)


def _write_dump(dump):
    from payloads.nfc_rfid._nfc_driver import MIFARE_AUTH_A
    blocks = dump.get("blocks", {})
    if not blocks:
        _draw_msg("Write", "No block data", "#FF4444")
        time.sleep(1)
        return

    _draw_msg("Write", "Place target card...")
    drv = _open_driver()
    if not drv:
        _draw_msg("Error", "ST25R3916 not found", "#FF4444")
        time.sleep(2)
        return

    try:
        card = drv.read_passive_target(timeout=3.0)
        if not card:
            _draw_msg("Write", "No card", "#FF4444")
            time.sleep(2)
            return

        key = bytes.fromhex("FFFFFFFFFFFF")
        sorted_blocks = sorted(blocks.keys(), key=int)
        written = 0
        total = len(sorted_blocks)

        for blk_str in sorted_blocks:
            blk = int(blk_str)
            if blk == 0:
                continue
            if blk % 4 == 3:
                continue

            pct = (written + 1) * 100 // max(1, total)
            img = Image.new("RGB", (W, H), "black")
            d = ScaledDraw(img)
            _draw_header(d, "Writing", f"{pct}%")
            d.text((4, 30), f"Block {blk}/{max(int(k) for k in sorted_blocks)}", font=_font_sm, fill="#FFAA00")
            bw = max(1, int((W - 8) * pct // 100))
            d.rectangle((4, 50, W - 4, 58), outline="#333")
            d.rectangle((4, 50, 4 + bw, 58), fill="#00CCFF")
            _show(img)

            sector = blk // 4
            first_block = sector * 4
            if blk == first_block or written == 0:
                drv._cmd(0xC2)
                time.sleep(0.003)
                drv._configure_nfc_a()
                drv._activate_nfca()
                if not drv.mifare_auth(first_block, key, card.uid, MIFARE_AUTH_A):
                    written += 1
                    continue

            data = bytes.fromhex(blocks[blk_str])
            drv.mifare_write(blk, data)
            written += 1

        drv._cmd(0xC2)
        _draw_msg("Write Done", f"{written} blocks", "#00FF00")
        time.sleep(2)
    finally:
        _safe_close(drv)


# ── Main Menu ─────────────────────────────────────────────────────────

def main():
    global _lcd, _font, _font_sm, _font_xs, _running

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    _lcd = LCD_1in44.LCD()
    _lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    _lcd.LCD_Clear()

    _font = scaled_font(10)
    _font_sm = scaled_font(9)
    _font_xs = scaled_font(8)

    cursor = 0
    _running = True

    try:
        while _running:
            btn = _btn()
            if btn == "KEY3":
                break
            if btn == "UP":
                cursor = (cursor - 1) % len(MENU_ITEMS)
            if btn == "DOWN":
                cursor = (cursor + 1) % len(MENU_ITEMS)
            if btn == "OK":
                item = MENU_ITEMS[cursor]
                if item == "Read":
                    _mode_read()
                elif item == "Saved":
                    _mode_saved()
                elif item == "Emulate":
                    _mode_emulate()
                elif item == "EMV":
                    _mode_emv()
                elif item == "Write":
                    _mode_write()

            img = Image.new("RGB", (W, H), "black")
            d = ScaledDraw(img)
            _draw_header(d, "NFC Cap HAT")
            y = 20
            for i, item in enumerate(MENU_ITEMS):
                is_sel = i == cursor
                if is_sel:
                    d.rectangle((2, y, W - 3, y + 15), fill="#1a1a00")
                    d.rectangle((2, y, W - 3, y + 15), outline="#FF8C00")
                icons = {"Read": ">", "Saved": "#", "Emulate": "~", "EMV": "$", "Write": "W"}
                d.text((8, y + 1), icons.get(item, ">"), font=_font, fill="#FF8C00" if is_sel else "#555")
                d.text((24, y + 2), item, font=_font_sm, fill="#FFF" if is_sel else "#888")
                y += 18
            _draw_footer(d, "OK:Select K3:Exit")
            _show(img)
            time.sleep(0.05)

    finally:
        _running = False
        try:
            _lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
