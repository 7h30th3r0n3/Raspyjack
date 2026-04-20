#!/usr/bin/env python3
"""
RaspyJack Payload -- NFC Reader
=================================
Read and identify NFC cards. Supports MIFARE Classic, Ultralight, NTAG, EMV.
Auto-detects PN532 (UART/I2C) and USB readers (ACR122U, SCL3711).

Controls:
  OK         Read card
  UP/DOWN    Scroll data
  KEY1       Switch view (Info / Hex / NDEF)
  KEY2       Save dump
  KEY3       Exit
"""

import os
import sys
import time

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads.nfc_rfid._nfc_driver import auto_detect, CardInfo, is_classic, is_ultralight, is_emv
from payloads.nfc_rfid._nfc_keys import KNOWN_KEYS, try_all_keys
from payloads.nfc_rfid._nfc_cards import (
    parse_ndef, read_ultralight_pages, detect_ntag_type,
    ntag_user_pages, save_dump,
)

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
DEBOUNCE = 0.18
_last_btn = 0
FAST_KEYS = KNOWN_KEYS[:5]


def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE:
        return None
    if b:
        _last_btn = now
    return b


def _read_classic(drv, card, lcd, font, font_sm, font_xs):
    """Read MIFARE Classic sectors with progress."""
    uid = card.uid
    n_sectors = 16 if "1K" in card.card_type or "Classic" in card.card_type else 40
    if "Mini" in card.card_type:
        n_sectors = 5
    if "4K" in card.card_type:
        n_sectors = 40

    sectors = []
    last_good_key = None

    for sec in range(n_sectors):
        # Progress (update every sector)
        pct = sec * 100 // max(1, n_sectors)
        authed_count = sum(1 for s in sectors if s["key"])
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.rectangle((0, 0, 127, 12), fill="#111")
        d.text((2, 1), "READING", font=font_sm, fill="#00CCFF")
        d.text((80, 1), f"{pct}%", font=font_sm, fill="#00FF00")
        d.text((4, 18), f"UID: {card.uid_hex[:16]}", font=font_sm, fill="#00FF00")
        d.text((4, 30), card.card_type, font=font_sm, fill="#ccc")
        d.rectangle((4, 46, 123, 54), outline="#333")
        bw = max(1, int(119 * sec / max(1, n_sectors)))
        d.rectangle((4, 46, 4 + bw, 54), fill="#00CCFF")
        d.text((4, 58), f"Sector {sec}/{n_sectors}", font=font_sm, fill="#FFAA00")
        d.text((4, 72), f"Cracked: {authed_count}  Locked: {sec - authed_count}", font=font_xs, fill="#888")
        if sectors:
            last = sectors[-1]
            col = "#00FF00" if last["key"] else "#FF4444"
            txt = f"S{last['sector']:02d} [{last['key'][:6]}]" if last["key"] else f"S{last['sector']:02d} LOCKED"
            d.text((4, 86), txt, font=font_sm, fill=col)
        lcd.LCD_ShowImage(img, 0, 0)

        block = sec * 4 if sec < 32 else 128 + (sec - 32) * 16
        key_found = None
        kt_found = 0x60

        # Try last successful key first (most cards use same key for all sectors)
        if last_good_key:
            if drv.mifare_auth(block, last_good_key[0], uid, last_good_key[1]):
                key_found = last_good_key[0]
                kt_found = last_good_key[1]

        # Try fast key list - Key A only first
        if not key_found:
            for key in FAST_KEYS:
                if drv.mifare_auth(block, key, uid, 0x60):
                    key_found = key
                    kt_found = 0x60
                    break

        # Key B only if A failed
        if not key_found:
            for key in FAST_KEYS:
                if drv.mifare_auth(block, key, uid, 0x61):
                    key_found = key
                    kt_found = 0x61
                    break

        if key_found:
            last_good_key = (key_found, kt_found)

        blocks = []
        if key_found:
            n_blocks = 4 if sec < 32 else 16
            for b in range(n_blocks):
                data = drv.mifare_read(block + b)
                blocks.append(data.hex() if data else "?" * 32)

        sectors.append({
            "sector": sec,
            "blocks": blocks,
            "key": key_found.hex().upper() if key_found else "",
            "key_type": "A" if kt_found == 0x60 else "B",
        })

    return {"sectors": sectors}


def _read_ultralight(drv, card, lcd, font, font_sm, font_xs):
    """Read Ultralight/NTAG pages with progress."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "READING", font=font_sm, fill="#00CCFF")
    d.text((4, 30), "Reading pages...", font=font_sm, fill="#FFAA00")
    lcd.LCD_ShowImage(img, 0, 0)

    pages = read_ultralight_pages(drv, max_pages=45)
    ntag_type = detect_ntag_type(pages)

    # Rebuild with correct page count
    total_pages = ntag_user_pages(pages) + 4
    if total_pages > 45:
        pages = read_ultralight_pages(drv, max_pages=total_pages)

    page_hexes = []
    for p in pages:
        page_hexes.append(p.hex() if p else None)

    # Parse NDEF from user pages (starting page 4)
    raw = b""
    for p in pages[4:]:
        if p:
            raw += p
        else:
            break
    ndef_records = parse_ndef(raw)

    return {
        "ntag_type": ntag_type,
        "pages": page_hexes,
        "ndef": [{"kind": r["kind"], "parsed": r["parsed"]} for r in ndef_records],
    }


def _read_emv(drv, card):
    """Read EMV contactless card via APDU."""
    # SELECT PPSE (Proximity Payment System Environment)
    select_ppse = bytes.fromhex("00A404000E325041592E5359532E444446303100")
    resp = drv.data_exchange(select_ppse)
    if not resp:
        return {"emv": "No PPSE response"}

    result = {"emv_raw": resp.hex(), "apps": []}

    # Try to parse basic TLV for application names
    # SELECT each application
    select_aid_prefix = bytes.fromhex("00A40400")
    common_aids = [
        ("Visa", "A0000000031010"),
        ("Mastercard", "A0000000041010"),
        ("Amex", "A00000002501"),
        ("CB", "A0000000421010"),
        ("JCB", "A0000000651010"),
    ]

    for name, aid in common_aids:
        aid_bytes = bytes.fromhex(aid)
        apdu = select_aid_prefix + bytes([len(aid_bytes)]) + aid_bytes + b"\x00"
        resp = drv.data_exchange(apdu)
        if resp and len(resp) > 2:
            result["apps"].append({"name": name, "aid": aid, "response": resp.hex()[:40]})

    return result


def main():
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    font = scaled_font(10)
    font_sm = scaled_font(9)
    font_xs = scaled_font(9)

    # Detect reader
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), "Detecting reader...", font=font_sm, fill="#FFAA00")
    lcd.LCD_ShowImage(img, 0, 0)

    drv, drv_desc = auto_detect()

    card = None
    card_data = None
    scroll = 0
    view = 0
    views = ["info", "hex", "ndef"]
    status = drv_desc if drv else "No reader found"

    try:
        while True:
            btn = _btn()

            if btn == "KEY3":
                break

            if btn == "KEY1":
                view = (view + 1) % len(views)
                scroll = 0

            if btn == "OK":
                if drv is None:
                    drv, drv_desc = auto_detect()
                    status = drv_desc
                if drv:
                    status = "Place card..."
                    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                    d = ScaledDraw(img)
                    d.rectangle((0, 0, 127, 12), fill="#111")
                    d.text((2, 1), "NFC READ", font=font_sm, fill="#00CCFF")
                    d.text((4, 50), "Place card on reader", font=font_sm, fill="#FFAA00")
                    lcd.LCD_ShowImage(img, 0, 0)

                    card = drv.read_passive_target(timeout=3.0)
                    if card:
                        if is_classic(card):
                            card_data = _read_classic(drv, card, lcd, font, font_sm, font_xs)
                        elif is_ultralight(card):
                            card_data = _read_ultralight(drv, card, lcd, font, font_sm, font_xs)
                        elif is_emv(card):
                            card_data = _read_emv(drv, card)
                        else:
                            card_data = {}
                        authed = sum(1 for s in card_data.get("sectors", []) if s.get("key"))
                        total_s = len(card_data.get("sectors", []))
                        status = f"{card.card_type}"
                        if total_s:
                            status += f" {authed}/{total_s}"
                        scroll = 0
                        view = 0
                    else:
                        card = None
                        card_data = None
                        status = "No card detected"

            if btn == "KEY2" and card and card_data:
                fname = save_dump(card.uid, card.card_type, card_data)
                status = f"Saved: {fname[:16]}"

            if btn == "UP":
                scroll = max(0, scroll - 1)
            elif btn == "DOWN":
                scroll += 1

            # --- Draw ---
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.rectangle((0, 0, 127, 12), fill="#111")
            d.text((2, 1), "NFC READ", font=font_sm, fill="#00CCFF")
            vname = views[view].upper() if card else ""
            d.text((65, 1), vname, font=font_xs, fill="#888")
            d.text((90, 1), drv_desc[:6] if drv else "NONE", font=font_xs,
                   fill="#00FF00" if drv else "#FF4444")

            y = 16
            d.text((2, y), status[:24], font=font_sm, fill="#FFAA00")
            y += 12

            if card:
                if views[view] == "info":
                    d.text((2, y), f"UID: {card.uid_hex}", font=font_sm, fill="#00FF00")
                    y += 11
                    d.text((2, y), f"Type: {card.card_type}", font=font_sm, fill="#ccc")
                    y += 11
                    d.text((2, y), f"ATQA:{card.atqa:04X} SAK:{card.sak:02X}", font=font_xs, fill="#888")
                    y += 11

                    # Sectors summary
                    sectors = card_data.get("sectors", [])
                    if sectors:
                        authed = sum(1 for s in sectors if s.get("key"))
                        d.text((2, y), f"Sectors: {authed}/{len(sectors)} cracked", font=font_sm, fill="#ccc")
                        y += 13
                        for i in range(scroll, min(len(sectors), scroll + 4)):
                            s = sectors[i]
                            col = "#00FF00" if s.get("key") else "#FF4444"
                            key_txt = s["key"][:6] if s.get("key") else "LOCKED"
                            d.text((2, y), f"S{s['sector']:02d} [{key_txt}]", font=font_sm, fill=col)
                            if s.get("blocks"):
                                d.text((72, y), s["blocks"][0][:10], font=font_xs, fill="#555")
                            y += 10

                    # Pages summary (UL/NTAG)
                    pages = card_data.get("pages", [])
                    if pages:
                        ntag = card_data.get("ntag_type", "")
                        d.text((2, y), f"{ntag}  {len(pages)} pages", font=font_sm, fill="#ccc")
                        y += 12

                    # NDEF
                    ndef = card_data.get("ndef", [])
                    if ndef:
                        d.text((2, y), f"NDEF: {len(ndef)} record(s)", font=font_sm, fill="#00CCFF")
                        y += 11
                        for r in ndef[:2]:
                            d.text((4, y), f"{r['kind']}: {r['parsed'][:18]}", font=font_xs, fill="#ccc")
                            y += 10

                    # EMV
                    apps = card_data.get("apps", [])
                    if apps:
                        d.text((2, y), f"EMV: {len(apps)} app(s)", font=font_sm, fill="#00CCFF")
                        y += 11
                        for a in apps:
                            d.text((4, y), f"{a['name']}: {a['aid'][:14]}", font=font_xs, fill="#ccc")
                            y += 10

                elif views[view] == "hex":
                    sectors = card_data.get("sectors", [])
                    pages = card_data.get("pages", [])
                    hex_lines = []
                    if sectors:
                        for s in sectors:
                            for i, blk in enumerate(s.get("blocks", [])):
                                hex_lines.append(f"B{s['sector']*4+i:03d} {blk[:24]}")
                    elif pages:
                        for i, p in enumerate(pages):
                            if p:
                                hex_lines.append(f"P{i:03d} {p}")
                            else:
                                hex_lines.append(f"P{i:03d} --------")
                    for i in range(scroll, min(len(hex_lines), scroll + 8)):
                        d.text((2, y), hex_lines[i][:24], font=font_xs, fill="#aaa")
                        y += 10

                elif views[view] == "ndef":
                    ndef = card_data.get("ndef", [])
                    if not ndef:
                        d.text((4, 55), "No NDEF data", font=font_sm, fill="#666")
                    else:
                        for i in range(scroll, min(len(ndef), scroll + 5)):
                            r = ndef[i]
                            d.text((2, y), f"[{r['kind']}]", font=font_sm, fill="#00CCFF")
                            y += 10
                            parsed = r["parsed"]
                            while parsed and y < 110:
                                d.text((4, y), parsed[:22], font=font_xs, fill="#ccc")
                                parsed = parsed[22:]
                                y += 9
                            y += 3
            else:
                d.text((4, 55), "Press OK to read card", font=font_sm, fill="#666")
                d.text((4, 70), "K1:scan  K2:save", font=font_xs, fill="#444")

            d.rectangle((0, 116, 127, 127), fill="#111")
            d.text((2, 117), "OK:Read K1:View K2:Save", font=font_xs, fill="#666")
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
