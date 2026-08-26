#!/usr/bin/env python3
"""
RaspyJack Payload -- NFC Cap HAT (ST25R3916)
===============================================
MIFARE Classic read/write/clone/emulate via CardputerZero Cap HAT.

Controls:
  UP/DOWN    Navigate menus / scroll data
  OK         Select / confirm
  KEY1       Primary action (save / emulate)
  KEY2       Secondary action (details)
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
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
W, H = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
IS_WIDE = W > 200
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

# ── Theme ────────────────────────────────────────────────────────────
C_BG      = "#0a0a0a"
C_CYAN    = "#00E5FF"
C_ORANGE  = "#FF8C00"
C_GREEN   = "#00FF41"
C_RED     = "#FF3333"
C_WHITE   = "#FFFFFF"
C_DIM     = "#888888"
C_VDIM    = "#555555"
C_DARK    = "#111111"
C_HEADER  = "#0a1a1a"
C_SEL     = "#0d2020"
C_SEL_BRD = "#00E5FF"

# FontAwesome 6 Solid icons
_ICON_READ    = ""
_ICON_SAVED   = ""
_ICON_EMULATE = ""
_ICON_EMV     = ""
_ICON_WRITE   = ""
_ICON_NFC     = ""
_ICON_CARD    = ""
_ICON_CHECK   = ""
_ICON_TIMES   = ""
_ICON_LOCK    = ""
_ICON_UNLOCK  = ""

MENU_ITEMS = [
    ("Read",    _ICON_READ),
    ("Saved",   _ICON_SAVED),
    ("Emulate", _ICON_EMULATE),
    ("EMV",     _ICON_EMV),
    ("Write",   _ICON_WRITE),
]

_lcd = None
_last_btn = 0
_running = True

# Fonts — set in main()
FONT = FONT_SM = FONT_LG = FONT_XS = None
FONT_ICON = FONT_ICON_LG = None

# Layout constants for 320x170
HDR_H = 24 if IS_WIDE else 14
FTR_H = 18 if IS_WIDE else 13
ITEM_H = 26 if IS_WIDE else 18
LINE_H = 16 if IS_WIDE else 9
PAD = 6 if IS_WIDE else 3


def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE:
        return None
    if b:
        _last_btn = now
    return b


def _new_img():
    return Image.new("RGB", (W, H), C_BG)


def _draw(img):
    return ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)


def _show(img):
    _lcd.LCD_ShowImage(img, 0, 0)


def _draw_header(d, title, right="", icon=None):
    d.rectangle((0, 0, W, HDR_H), fill=C_HEADER)
    d.line((0, HDR_H, W, HDR_H), fill=C_CYAN)
    x = PAD
    if icon and FONT_ICON:
        d.text((x, (HDR_H - 14) // 2), icon, font=FONT_ICON, fill=C_CYAN)
        x += 18 if IS_WIDE else 12
    d.text((x, (HDR_H - 13) // 2), title, font=FONT if IS_WIDE else FONT_SM, fill=C_CYAN)
    if right:
        d.text((W - PAD, (HDR_H - 10) // 2), right, font=FONT_SM, fill=C_DIM, anchor="ra")


def _draw_footer(d, text):
    d.rectangle((0, H - FTR_H, W, H), fill=C_DARK)
    d.line((0, H - FTR_H, W, H - FTR_H), fill="#222")
    d.text((W // 2, H - FTR_H // 2), text, font=FONT_SM, fill=C_VDIM, anchor="mm")


def _draw_msg(title, msg, color=C_ORANGE, icon=None):
    img = _new_img()
    d = _draw(img)
    _draw_header(d, "NFC Cap", icon=_ICON_NFC)
    cy = H // 2 - 4
    if icon and FONT_ICON_LG:
        d.text((W // 2, cy - 18), icon, font=FONT_ICON_LG, fill=color, anchor="mm")
        cy += 10
    d.text((W // 2, cy), title, font=FONT_LG if IS_WIDE else FONT, fill=color, anchor="mm")
    d.text((W // 2, cy + (20 if IS_WIDE else 14)), msg,
           font=FONT_SM if IS_WIDE else FONT_XS, fill=C_DIM, anchor="mm")
    _show(img)


def _draw_progress(title, pct, detail="", color=C_CYAN):
    img = _new_img()
    d = _draw(img)
    _draw_header(d, title, f"{pct}%", icon=_ICON_NFC)
    d.text((W // 2, HDR_H + 20), detail, font=FONT, fill=C_WHITE, anchor="mm")
    bx = 20 if IS_WIDE else 8
    by = HDR_H + 40 if IS_WIDE else 50
    bw = W - 2 * bx
    bh = 10 if IS_WIDE else 8
    d.rectangle((bx, by, bx + bw, by + bh), outline="#333")
    fill_w = max(1, int(bw * pct / 100))
    if fill_w > 0:
        d.rectangle((bx, by, bx + fill_w, by + bh), fill=color)
    d.text((W // 2, by + bh + 14), f"{pct}%", font=FONT_SM, fill=C_DIM, anchor="mm")
    _draw_footer(d, "Reading card...")
    _show(img)


# ── Helpers ──────────────────────────────────────────────────────────

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
    types = {0x08: "MIFARE Classic 1K", 0x18: "MIFARE Classic 4K",
             0x09: "MIFARE Mini", 0x00: "MIFARE Ultralight",
             0x20: "ISO14443-4 (EMV)"}
    return types.get(sak, f"Unknown (0x{sak:02X})")


def _is_classic(sak):
    return sak in (0x08, 0x09, 0x18, 0x88, 0x28, 0x01)


# ── Read Mode ────────────────────────────────────────────────────────

def _mode_read():
    _draw_msg("Read", "Initializing...", C_CYAN, _ICON_READ)
    drv = _open_driver()
    if not drv:
        _draw_msg("Error", "ST25R3916 not found", C_RED, _ICON_TIMES)
        time.sleep(2)
        return

    try:
        card = None
        card_data = None
        scroll = 0
        frame = 0

        while _running:
            btn = _btn()
            if btn == "KEY3":
                return

            if btn == "OK" or card is None:
                frame += 1
                dots = "." * ((frame % 3) + 1) + " " * (3 - (frame % 3))
                _draw_msg(f"Scanning{dots}", "Waiting for card...", C_CYAN, _ICON_NFC)
                card = drv.read_passive_target(timeout=2.0)
                if not card:
                    _draw_msg("No Card", "Place card and press OK", C_ORANGE, _ICON_TIMES)
                    time.sleep(0.5)
                    continue
                _draw_msg("Card detected!", card.uid.hex().upper(), C_GREEN, _ICON_CHECK)
                time.sleep(0.5)
                card_type = _card_type_str(card.sak)
                if _is_classic(card.sak):
                    card_data = _read_classic(drv, card)
                else:
                    card_data = {"blocks": {}}
                scroll = 0

            if btn == "KEY1" and card and card_data:
                fname = _save_dump(card, card_data)
                _draw_msg("Saved!", fname[:22], C_GREEN, _ICON_CHECK)
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
    n_sectors = 40 if sak == 0x18 else (5 if sak == 0x09 else 16)

    result = {"blocks": {}, "keys_a": {}, "keys_b": {}, "sectors_ok": 0}
    last_key = None

    for sec in range(n_sectors):
        first_block = sec * 4 if sec < 32 else 128 + (sec - 32) * 16
        n_blocks = 4 if sec < 32 else 16
        pct = (sec + 1) * 100 // n_sectors
        _draw_progress("Reading", pct, f"Sector {sec}/{n_sectors}")

        if sec > 0:
            drv._cmd(0xC2)
            time.sleep(0.003)
            drv._configure_nfc_a()
            if not drv._activate_nfca():
                continue

        key_found = None
        kt_found = MIFARE_AUTH_A

        if last_key and drv.mifare_auth(first_block, last_key[0], uid, last_key[1]):
            key_found, kt_found = last_key

        if not key_found:
            for key in COMMON_KEYS:
                if drv.mifare_auth(first_block, key, uid, MIFARE_AUTH_A):
                    key_found, kt_found = key, MIFARE_AUTH_A
                    break
                drv._cmd(0xC2); time.sleep(0.002)
                drv._configure_nfc_a(); drv._activate_nfca()

        if not key_found:
            for key in COMMON_KEYS[:5]:
                if drv.mifare_auth(first_block, key, uid, MIFARE_AUTH_B):
                    key_found, kt_found = key, MIFARE_AUTH_B
                    break
                drv._cmd(0xC2); time.sleep(0.002)
                drv._configure_nfc_a(); drv._activate_nfca()

        if key_found:
            last_key = (key_found, kt_found)
            result["sectors_ok"] += 1
            k_dict = "keys_a" if kt_found == MIFARE_AUTH_A else "keys_b"
            result[k_dict][str(sec)] = key_found.hex().upper()
            for blk_off in range(n_blocks):
                blk = first_block + blk_off
                data = drv.mifare_read(blk)
                if data:
                    result["blocks"][str(blk)] = data.hex().upper()

    drv._cmd(0xC2)
    return result


def _draw_card_info(card, card_data, scroll):
    img = _new_img()
    d = _draw(img)
    _draw_header(d, "Card Info", icon=_ICON_CARD)

    y = HDR_H + 4
    uid_str = card.uid.hex().upper()
    if FONT_ICON:
        d.text((PAD, y), _ICON_NFC, font=FONT_ICON, fill=C_CYAN)
    d.text((PAD + 20, y), uid_str, font=FONT_LG if IS_WIDE else FONT, fill=C_GREEN)
    y += 22 if IS_WIDE else 13
    d.text((PAD, y), _card_type_str(card.sak), font=FONT_SM, fill=C_WHITE)
    y += 16 if IS_WIDE else 11
    d.text((PAD, y), f"ATQA: {card.atqa:04X}   SAK: {card.sak:02X}", font=FONT_SM, fill=C_VDIM)
    y += 16 if IS_WIDE else 11

    blocks = card_data.get("blocks", {}) if card_data else {}
    ok = card_data.get("sectors_ok", 0) if card_data else 0
    d.rectangle((PAD, y, W - PAD, y + (16 if IS_WIDE else 11)), fill=C_SEL)
    icon = _ICON_UNLOCK if ok > 0 else _ICON_LOCK
    if FONT_ICON:
        d.text((PAD + 2, y + 1), icon, font=FONT_ICON, fill=C_GREEN if ok else C_RED)
    d.text((PAD + 20, y + 1), f"{len(blocks)} blocks  {ok} sectors OK",
           font=FONT_SM, fill=C_ORANGE)
    y += 20 if IS_WIDE else 14

    sorted_blocks = sorted(blocks.keys(), key=int)
    vis = (H - FTR_H - y) // LINE_H
    for i in range(scroll, min(len(sorted_blocks), scroll + vis)):
        blk_num = sorted_blocks[i]
        hex_data = blocks[blk_num]
        is_trailer = int(blk_num) % 4 == 3
        d.text((PAD, y), f"{int(blk_num):02d}", font=FONT_SM, fill=C_CYAN)
        max_hex = 40 if IS_WIDE else 24
        d.text((PAD + 24, y), hex_data[:max_hex], font=FONT_SM,
               fill=C_ORANGE if is_trailer else "#aaa")
        y += LINE_H

    _draw_footer(d, "OK:Scan  K1:Save  K3:Back")
    _show(img)


# ── Save / Load ──────────────────────────────────────────────────────

def _save_dump(card, card_data):
    os.makedirs(LOOT_DIR, exist_ok=True)
    uid_hex = card.uid.hex().upper()
    uid_spaced = ' '.join(f'{b:02X}' for b in card.uid)
    atqa_spaced = f'{card.atqa & 0xFF:02X} {(card.atqa >> 8) & 0xFF:02X}'
    card_type = _card_type_str(card.sak)
    blocks = card_data.get("blocks", {})

    fname_nfc = f"{uid_hex}_{int(time.time())}.nfc"
    lines = [
        "Filetype: Flipper NFC device", "Version: 4",
        f"Device type: {card_type}",
        f"UID: {uid_spaced}", f"ATQA: {atqa_spaced}", f"SAK: {card.sak:02X}",
    ]
    if "Classic" in card_type:
        mf_type = "4K" if card.sak == 0x18 else "1K"
        lines += [f"Mifare Classic type: {mf_type}", "Data format version: 2"]
        total = 256 if mf_type == "4K" else 64
        for i in range(total):
            bdata = blocks.get(str(i))
            spaced = ' '.join(bdata[j:j+2] for j in range(0, len(bdata), 2)) if bdata \
                     else ' '.join(['??'] * 16)
            lines.append(f"Block {i}: {spaced}")
    with open(os.path.join(LOOT_DIR, fname_nfc), "w") as f:
        f.write('\n'.join(lines) + '\n')
    return fname_nfc


def _list_dumps():
    if not os.path.isdir(LOOT_DIR):
        return []
    files = [f for f in os.listdir(LOOT_DIR) if f.endswith(".nfc") or f.endswith(".json")]
    files.sort(reverse=True)
    return files


def _load_dump(fname):
    path = os.path.join(LOOT_DIR, fname)
    if fname.endswith(".nfc"):
        return _load_flipper_nfc(path)
    with open(path) as f:
        return json.load(f)


def _load_flipper_nfc(path):
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


# ── Saved Mode ───────────────────────────────────────────────────────

def _mode_saved():
    files = _list_dumps()
    if not files:
        _draw_msg("No Cards", "Read a card first", C_DIM, _ICON_SAVED)
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
        if btn == "OK" and selected is None:
            try:
                selected = _load_dump(files[cursor])
            except Exception:
                _draw_msg("Error", "Cannot load file", C_RED, _ICON_TIMES)
                time.sleep(1)
                selected = None
        if btn == "KEY1" and selected:
            _emulate_dump(selected)
            selected = None

        img = _new_img()
        d = _draw(img)

        if selected:
            _draw_header(d, "Card Details", icon=_ICON_CARD)
            y = HDR_H + 8
            uid_str = selected.get('uid', '?')
            d.text((W // 2, y), uid_str, font=FONT_LG if IS_WIDE else FONT,
                   fill=C_GREEN, anchor="mm")
            y += 22 if IS_WIDE else 15
            d.text((W // 2, y), selected.get("type", "?"),
                   font=FONT_SM, fill=C_WHITE, anchor="mm")
            y += 18 if IS_WIDE else 13
            n_blk = len(selected.get("blocks", {}))
            d.text((W // 2, y), f"{n_blk} blocks",
                   font=FONT_SM, fill=C_ORANGE, anchor="mm")
            _draw_footer(d, "K1:Emulate  K3:Back")
        else:
            _draw_header(d, "Saved Cards", f"{len(files)}", icon=_ICON_SAVED)
            y = HDR_H + 4
            vis = (H - FTR_H - y) // ITEM_H
            start = max(0, cursor - vis // 2)
            for i in range(start, min(len(files), start + vis)):
                is_sel = i == cursor
                ry = y + (i - start) * ITEM_H
                if is_sel:
                    d.rectangle((PAD, ry, W - PAD, ry + ITEM_H - 4), fill=C_SEL)
                    d.rectangle((PAD, ry, W - PAD, ry + ITEM_H - 4), outline=C_SEL_BRD)
                fname_display = files[i].replace('.nfc', '').replace('.json', '')
                max_len = 28 if IS_WIDE else 18
                if len(fname_display) > max_len:
                    fname_display = fname_display[:max_len - 4] + ".." + fname_display[-4:]
                if FONT_ICON:
                    d.text((PAD + 4, ry + 3), _ICON_CARD, font=FONT_ICON,
                           fill=C_CYAN if is_sel else C_VDIM)
                d.text((PAD + 24, ry + 4), fname_display, font=FONT_SM,
                       fill=C_WHITE if is_sel else C_DIM)
            _draw_footer(d, "OK:Open  K3:Back")

        _show(img)
        time.sleep(0.05)


# ── Emulate Mode ─────────────────────────────────────────────────────

def _mode_emulate():
    files = _list_dumps()
    if not files:
        _draw_msg("No Cards", "Save a card first", C_DIM, _ICON_EMULATE)
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
                _draw_msg("Error", "Emulation failed", C_RED, _ICON_TIMES)
                time.sleep(1)

        img = _new_img()
        d = _draw(img)
        _draw_header(d, "Emulate", icon=_ICON_EMULATE)
        y = HDR_H + 4
        vis = (H - FTR_H - y) // ITEM_H
        start = max(0, cursor - vis // 2)
        for i in range(start, min(len(files), start + vis)):
            is_sel = i == cursor
            ry = y + (i - start) * ITEM_H
            if is_sel:
                d.rectangle((PAD, ry, W - PAD, ry + ITEM_H - 4), fill=C_SEL)
                d.rectangle((PAD, ry, W - PAD, ry + ITEM_H - 4), outline=C_SEL_BRD)
            fname_display = files[i].replace('.nfc', '').replace('.json', '')
            max_len = 28 if IS_WIDE else 18
            if len(fname_display) > max_len:
                fname_display = fname_display[:max_len - 4] + ".." + fname_display[-4:]
            if FONT_ICON:
                d.text((PAD + 4, ry + 3), _ICON_EMULATE, font=FONT_ICON,
                       fill=C_CYAN if is_sel else C_VDIM)
            d.text((PAD + 24, ry + 4), fname_display, font=FONT_SM,
                   fill=C_WHITE if is_sel else C_DIM)
        _draw_footer(d, "OK:Emulate  K3:Back")
        _show(img)
        time.sleep(0.05)


def _emulate_dump(dump):
    uid = bytes.fromhex(dump.get("uid", "00000000"))
    atqa = int(dump.get("atqa", "0004"), 16)
    sak = int(dump.get("sak", "08"), 16)

    drv = _open_driver()
    if not drv:
        _draw_msg("Error", "ST25R3916 not found", C_RED, _ICON_TIMES)
        time.sleep(2)
        return

    try:
        from payloads._nfc_emulator import NFCEmulator
        emu = NFCEmulator(drv)

        blocks_dict = dump.get("blocks", {})
        stop = [False]

        def check_stop():
            b = _btn()
            if b == "KEY3":
                stop[0] = True
            return stop[0]

        frame = [0]

        def draw_emulating():
            frame[0] += 1
            pulse = ["   ", ".  ", ".. ", "..."][frame[0] % 4]
            img = _new_img()
            d = _draw(img)
            _draw_header(d, "Emulating", icon=_ICON_EMULATE)
            cy = H // 2 - 10
            if FONT_ICON_LG:
                d.text((W // 2, cy - 20), _ICON_EMULATE, font=FONT_ICON_LG,
                       fill=C_CYAN, anchor="mm")
                cy += 6
            d.text((W // 2, cy), uid.hex().upper(),
                   font=FONT_LG if IS_WIDE else FONT, fill=C_GREEN, anchor="mm")
            d.text((W // 2, cy + 18), _card_type_str(sak),
                   font=FONT_SM, fill=C_DIM, anchor="mm")
            d.text((W // 2, cy + 36), f"Active{pulse}",
                   font=FONT_SM, fill=C_CYAN, anchor="mm")
            _draw_footer(d, "K3: Stop")
            _show(img)

        draw_emulating()

        if blocks_dict and _is_classic(sak):
            data_blocks = {int(k): bytes.fromhex(v) for k, v in blocks_dict.items()}
            keys_a = {int(k): bytes.fromhex(v) for k, v in dump.get("keys_a", {}).items()}
            keys_b = {int(k): bytes.fromhex(v) for k, v in dump.get("keys_b", {}).items()}
            while not stop[0]:
                emu.emulate_mifare_classic(
                    uid=uid, atqa=atqa, sak=sak,
                    data_blocks=data_blocks, keys_a=keys_a, keys_b=keys_b,
                    timeout=1.0)
                if check_stop():
                    break
                draw_emulating()
        else:
            while not stop[0]:
                emu.emulate_uid_only(uid=uid, atqa=atqa, sak=sak, timeout=1.0)
                if check_stop():
                    break
                draw_emulating()

    except Exception as e:
        _draw_msg("Error", str(e)[:24], C_RED, _ICON_TIMES)
        time.sleep(1)
    finally:
        _safe_close(drv)


# ── EMV Mode ─────────────────────────────────────────────────────────

def _mode_emv():
    _draw_msg("EMV", "Initializing...", C_CYAN, _ICON_EMV)
    drv = _open_driver()
    if not drv:
        _draw_msg("Error", "ST25R3916 not found", C_RED, _ICON_TIMES)
        time.sleep(2)
        return

    try:
        _draw_msg("EMV", "Waiting for card...", C_ORANGE, _ICON_EMV)
        card = drv.read_passive_target(timeout=3.0)
        if not card:
            _draw_msg("No Card", "Place payment card", C_RED, _ICON_TIMES)
            time.sleep(2)
            return

        _draw_msg("Reading", "EMV data...", C_CYAN, _ICON_EMV)
        try:
            from payloads._iso14443_4 import ISO14443_4
            from payloads._emv_reader import EMVReader
            iso = ISO14443_4(drv)
            ats = iso.activate()
            if not ats:
                _draw_msg("Error", "Not an EMV card", C_RED, _ICON_TIMES)
                time.sleep(2)
                return
            reader = EMVReader(iso)
            emv_data = reader.read_card()
        except Exception as e:
            _draw_msg("EMV Error", str(e)[:24], C_RED, _ICON_TIMES)
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
            if btn == "KEY1":
                _save_emv(emv_data)
                _draw_msg("Saved!", "EMV data saved", C_GREEN, _ICON_CHECK)
                time.sleep(1)

            lines = _build_emv_lines(emv_data)

            img = _new_img()
            d = _draw(img)
            _draw_header(d, "EMV Card", icon=_ICON_EMV)

            y = HDR_H + 4
            emv_lh = 18 if IS_WIDE else 12
            vis = (H - FTR_H - y) // emv_lh
            for i in range(scroll, min(len(lines), scroll + vis)):
                label, val, col = lines[i]
                d.text((PAD, y), f"{label}:", font=FONT_XS, fill=C_CYAN)
                lw = 90 if IS_WIDE else 40
                d.text((lw, y), str(val), font=FONT_SM, fill=col)
                y += emv_lh

            _draw_footer(d, "K1:Save  K3:Back")
            _show(img)
            time.sleep(0.05)

    finally:
        _safe_close(drv)


def _build_emv_lines(emv_data):
    lines = []
    if emv_data.pan:
        pan = emv_data.pan
        formatted = ' '.join(pan[i:i+4] for i in range(0, len(pan), 4))
        lines.append(("PAN", formatted, C_GREEN))
    if emv_data.exp_year or emv_data.exp_month:
        lines.append(("Expires", "%02X/%02X" % (emv_data.exp_month, emv_data.exp_year), C_ORANGE))
    if emv_data.effective_year or emv_data.effective_month:
        lines.append(("Effective", "%02X/%02X" % (emv_data.effective_month, emv_data.effective_year), C_WHITE))
    if emv_data.cardholder_name:
        lines.append(("Name", emv_data.cardholder_name, C_WHITE))
    app_display = emv_data.app_name or emv_data.app_label
    if app_display:
        lines.append(("App", app_display, C_CYAN))
    if emv_data.aid:
        aid_label = emv_data.aid_name if emv_data.aid_name else emv_data.aid.hex().upper()
        lines.append(("AID", aid_label, C_CYAN))
    if emv_data.country_code:
        from payloads._emv_reader import country_name
        lines.append(("Country", country_name(emv_data.country_code), C_WHITE))
    if emv_data.currency_code:
        from payloads._emv_reader import currency_name
        lines.append(("Currency", currency_name(emv_data.currency_code), C_WHITE))
    if emv_data.language:
        lines.append(("Language", emv_data.language, C_WHITE))
    if emv_data.atc:
        lines.append(("ATC", str(emv_data.atc), C_ORANGE))
    if emv_data.pin_try_counter >= 0:
        lines.append(("PIN tries", str(emv_data.pin_try_counter), C_RED))
    if not lines:
        lines.append(("Info", "No EMV data found", C_DIM))
    return lines


def _save_emv(emv_data):
    os.makedirs(LOOT_DIR, exist_ok=True)
    data = {
        "pan": emv_data.pan,
        "expires": "%02X/%02X" % (emv_data.exp_month, emv_data.exp_year) if emv_data.exp_year else "",
        "effective": "%02X/%02X" % (emv_data.effective_month, emv_data.effective_year) if emv_data.effective_year else "",
        "name": emv_data.cardholder_name,
        "app": emv_data.app_label,
        "aid": emv_data.aid.hex().upper() if emv_data.aid else "",
        "network": emv_data.aid_name,
        "country": "%04X" % emv_data.country_code if emv_data.country_code else "",
        "currency": "%04X" % emv_data.currency_code if emv_data.currency_code else "",
        "language": emv_data.language,
        "atc": emv_data.atc,
        "pin_tries": emv_data.pin_try_counter,
    }
    last4 = emv_data.pan[-4:] if emv_data.pan else "0000"
    fname = f"EMV_{last4}_{int(time.time())}.json"
    with open(os.path.join(LOOT_DIR, fname), "w") as f:
        json.dump(data, f, indent=2)


# ── Write Mode ───────────────────────────────────────────────────────

def _mode_write():
    files = _list_dumps()
    if not files:
        _draw_msg("No Cards", "Save a card first", C_DIM, _ICON_WRITE)
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
                _draw_msg("Error", str(e)[:24], C_RED, _ICON_TIMES)
                time.sleep(1)

        img = _new_img()
        d = _draw(img)
        _draw_header(d, "Write Card", icon=_ICON_WRITE)
        y = HDR_H + 4
        vis = (H - FTR_H - y) // ITEM_H
        start = max(0, cursor - vis // 2)
        for i in range(start, min(len(files), start + vis)):
            is_sel = i == cursor
            ry = y + (i - start) * ITEM_H
            if is_sel:
                d.rectangle((PAD, ry, W - PAD, ry + ITEM_H - 4), fill=C_SEL)
                d.rectangle((PAD, ry, W - PAD, ry + ITEM_H - 4), outline=C_ORANGE)
            if FONT_ICON:
                d.text((PAD + 4, ry + 3), _ICON_WRITE, font=FONT_ICON,
                       fill=C_ORANGE if is_sel else C_VDIM)
            fname_display = files[i].replace('.nfc', '').replace('.json', '')
            max_len = 28 if IS_WIDE else 16
            if len(fname_display) > max_len:
                fname_display = fname_display[:max_len - 4] + ".." + fname_display[-4:]
            d.text((PAD + 24, ry + 4), fname_display, font=FONT_SM,
                   fill=C_WHITE if is_sel else C_DIM)
        _draw_footer(d, "OK:Write  K3:Back")
        _show(img)
        time.sleep(0.05)


def _write_dump(dump):
    from payloads.nfc_rfid._nfc_driver import MIFARE_AUTH_A
    blocks = dump.get("blocks", {})
    if not blocks:
        _draw_msg("Error", "No block data", C_RED, _ICON_TIMES)
        time.sleep(1)
        return

    _draw_msg("Write", "Place target card...", C_ORANGE, _ICON_WRITE)
    drv = _open_driver()
    if not drv:
        _draw_msg("Error", "ST25R3916 not found", C_RED, _ICON_TIMES)
        time.sleep(2)
        return

    try:
        card = drv.read_passive_target(timeout=3.0)
        if not card:
            _draw_msg("Error", "No card detected", C_RED, _ICON_TIMES)
            time.sleep(2)
            return

        key = bytes.fromhex("FFFFFFFFFFFF")
        sorted_blocks = sorted(blocks.keys(), key=int)
        written = 0
        total = len(sorted_blocks)

        for blk_str in sorted_blocks:
            blk = int(blk_str)
            if blk == 0 or blk % 4 == 3:
                written += 1
                continue

            pct = (written + 1) * 100 // max(1, total)
            _draw_progress("Writing", pct, f"Block {blk}")

            sector = blk // 4
            first_block = sector * 4
            if blk == first_block or written <= 1:
                drv._cmd(0xC2); time.sleep(0.003)
                drv._configure_nfc_a(); drv._activate_nfca()
                if not drv.mifare_auth(first_block, key, card.uid, MIFARE_AUTH_A):
                    written += 1
                    continue

            drv.mifare_write(blk, bytes.fromhex(blocks[blk_str]))
            written += 1

        drv._cmd(0xC2)
        _draw_msg("Complete!", f"{written} blocks written", C_GREEN, _ICON_CHECK)
        time.sleep(2)
    finally:
        _safe_close(drv)


# ── Main Menu ────────────────────────────────────────────────────────

def main():
    global _lcd, _running
    global FONT, FONT_SM, FONT_LG, FONT_XS, FONT_ICON, FONT_ICON_LG

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    _lcd = LCD_1in44.LCD()
    _lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    _lcd.LCD_Clear()

    if IS_WIDE:
        try:
            FONT = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 13)
            FONT_SM = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 11)
            FONT_XS = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 9)
            FONT_LG = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 16)
        except Exception:
            FONT = scaled_font(9)
            FONT_SM = scaled_font(8)
            FONT_XS = scaled_font(7)
            FONT_LG = scaled_font(12)
    else:
        FONT = scaled_font(10)
        FONT_SM = scaled_font(9)
        FONT_XS = scaled_font(8)
        FONT_LG = scaled_font(12)

    try:
        icon_sz = 14 if IS_WIDE else 9
        icon_lg_sz = 22 if IS_WIDE else 16
        FONT_ICON = ImageFont.truetype('/usr/share/fonts/truetype/fontawesome/fa-solid-900.ttf', icon_sz)
        FONT_ICON_LG = ImageFont.truetype('/usr/share/fonts/truetype/fontawesome/fa-solid-900.ttf', icon_lg_sz)
    except Exception:
        FONT_ICON = None
        FONT_ICON_LG = None

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
                label = MENU_ITEMS[cursor][0]
                {"Read": _mode_read, "Saved": _mode_saved,
                 "Emulate": _mode_emulate, "EMV": _mode_emv,
                 "Write": _mode_write}.get(label, lambda: None)()

            img = _new_img()
            d = _draw(img)
            _draw_header(d, "NFC Cap HAT", icon=_ICON_NFC)

            y = HDR_H + 6
            for i, (label, icon) in enumerate(MENU_ITEMS):
                is_sel = i == cursor
                ry = y + i * ITEM_H
                if is_sel:
                    d.rectangle((PAD, ry, W - PAD, ry + ITEM_H - 4), fill=C_SEL)
                    d.rectangle((PAD, ry, W - PAD, ry + ITEM_H - 4), outline=C_SEL_BRD)
                if FONT_ICON:
                    d.text((PAD + 6, ry + 3), icon, font=FONT_ICON,
                           fill=C_CYAN if is_sel else C_VDIM)
                d.text((PAD + 28, ry + 4), label, font=FONT,
                       fill=C_WHITE if is_sel else C_DIM)

            _draw_footer(d, "OK:Select  K3:Exit")
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
