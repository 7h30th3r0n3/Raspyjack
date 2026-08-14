#!/usr/bin/env python3
"""
RaspyJack Payload -- Chameleon Ultra Quick Clone
=================================================
Read a card and store it into a Chameleon slot for emulation.
Supports MIFARE Classic, Ultralight/NTAG, and EM4100.

Controls:
  OK         Read card / Write to slot
  UP/DOWN    Select target slot (0-7)
  KEY1       Toggle HF/LF mode
  KEY2       Clear / Reset
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
from payloads.nfc_rfid._nfc_driver import (
    auto_detect, ChameleonUltraDriver, is_classic, is_ultralight,
    MIFARE_AUTH_A,
)
from payloads.nfc_rfid._nfc_keys import KNOWN_KEYS

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
DEBOUNCE = 0.18
_last_btn = 0
FAST_KEYS = KNOWN_KEYS[:20]


def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE:
        return None
    if b:
        _last_btn = now
    return b


def _read_classic(drv, card, lcd, font_sm):
    """Read MIFARE Classic sectors with progress display."""
    uid = card.uid
    n_sectors = 16
    if "4K" in card.card_type:
        n_sectors = 40
    elif "Mini" in card.card_type:
        n_sectors = 5

    sectors = []
    last_good_key = None

    for sec in range(n_sectors):
        pct = sec * 100 // max(1, n_sectors)
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.rectangle((0, 0, 127, 14), fill="#111")
        d.text((2, 2), "READING", font=font_sm, fill="#FF00FF")
        d.text((90, 2), f"{pct}%", font=font_sm, fill="#FF00FF")
        d.text((4, 20), f"UID: {card.uid_hex[:14]}", font=font_sm, fill="#00FF00")
        d.text((4, 32), card.card_type, font=font_sm, fill="#ccc")
        d.rectangle((4, 48, 123, 56), outline="#333")
        bw = max(1, int(119 * sec / max(1, n_sectors)))
        d.rectangle((4, 48, 4 + bw, 56), fill="#FF00FF")
        d.text((4, 62), f"Sector {sec}/{n_sectors}", font=font_sm, fill="#FFAA00")
        cracked = sum(1 for s in sectors if s["key"])
        d.text((4, 76), f"Cracked: {cracked}", font=font_sm, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)

        block = sec * 4
        key_found = None
        kt_found = MIFARE_AUTH_A

        if last_good_key:
            if drv.mifare_auth(block, last_good_key[0], uid, last_good_key[1]):
                key_found = last_good_key[0]
                kt_found = last_good_key[1]

        if not key_found:
            for key in FAST_KEYS:
                if drv.mifare_auth(block, key, uid, 0x60):
                    key_found = key
                    kt_found = 0x60
                    break

        if not key_found:
            for key in FAST_KEYS[:5]:
                if drv.mifare_auth(block, key, uid, 0x61):
                    key_found = key
                    kt_found = 0x61
                    break

        if key_found:
            last_good_key = (key_found, kt_found)

        blocks = []
        if key_found:
            for b in range(4):
                data = drv.mifare_read(block + b)
                blocks.append(data.hex() if data else "?" * 32)

        sectors.append({
            "sector": sec,
            "blocks": blocks,
            "key": key_found.hex().upper() if key_found else "",
        })

    return sectors


def _read_ultralight(drv, lcd, font_sm):
    """Read Ultralight/NTAG pages with progress."""
    pages = []
    for p in range(0, 45, 4):
        pct = p * 100 // 45
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.rectangle((0, 0, 127, 14), fill="#111")
        d.text((2, 2), "READING UL", font=font_sm, fill="#FF00FF")
        d.text((90, 2), f"{pct}%", font=font_sm, fill="#FF00FF")
        d.rectangle((4, 48, 123, 56), outline="#333")
        bw = max(1, int(119 * p / 45))
        d.rectangle((4, 48, 4 + bw, 56), fill="#FF00FF")
        d.text((4, 62), f"Page {p}/45", font=font_sm, fill="#FFAA00")
        lcd.LCD_ShowImage(img, 0, 0)

        data = drv.mifare_ul_read(p)
        if data:
            for j in range(4):
                pages.append(data[j * 4:(j + 1) * 4].hex())
        else:
            break
    return pages


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

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), "Detecting Chameleon...", font=font_sm, fill="#FFAA00")
    lcd.LCD_ShowImage(img, 0, 0)

    drv, desc = auto_detect()
    if not isinstance(drv, ChameleonUltraDriver):
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 35), "Chameleon Ultra", font=font, fill="#FF4444")
        d.text((4, 55), "Required", font=font, fill="#FF4444")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    target_slot = 0
    mode = "hf"
    card = None
    card_data = None
    status = ""

    try:
        while True:
            btn = _btn()
            if btn == "KEY3":
                break
            elif btn == "UP":
                target_slot = (target_slot - 1) % 8
            elif btn == "DOWN":
                target_slot = (target_slot + 1) % 8
            elif btn == "KEY1":
                mode = "lf" if mode == "hf" else "hf"
                card = None
                card_data = None
                status = f"Mode: {mode.upper()}"
            elif btn == "KEY2":
                card = None
                card_data = None
                status = "Cleared"

            elif btn == "OK" and not card:
                # Phase 1: Read card
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.text((4, 50), "Place card...", font=font_sm, fill="#FFAA00")
                lcd.LCD_ShowImage(img, 0, 0)

                if mode == "hf":
                    drv.command(1001, b"\x01")
                    card = drv.read_passive_target(timeout=5.0)
                    if card:
                        if is_classic(card):
                            sectors = _read_classic(drv, card, lcd, font_sm)
                            cracked = sum(1 for s in sectors if s["key"])
                            card_data = {"type": "classic", "sectors": sectors}
                            status = f"Read {cracked}/{len(sectors)} sectors"
                        elif is_ultralight(card):
                            pages = _read_ultralight(drv, lcd, font_sm)
                            card_data = {"type": "ultralight", "pages": pages}
                            status = f"Read {len(pages)} pages"
                        else:
                            card_data = {"type": "other"}
                            status = card.card_type
                    else:
                        status = "No HF card found"
                else:
                    drv.command(1001, b"\x01")
                    em_id = drv.em410x_scan()
                    if em_id:
                        card_data = {"type": "em4100", "id": em_id.hex().upper()}
                        card = type("LF", (), {"uid_hex": em_id.hex().upper(), "card_type": "EM4100"})()
                        status = f"EM: {card.uid_hex}"
                    else:
                        status = "No LF tag found"

            elif btn == "OK" and card:
                # Phase 2: Write to slot
                drv.set_active_slot(target_slot)

                if card_data and card_data["type"] == "classic":
                    drv.command(1004, bytes([target_slot, 3]))
                    drv.command(1006, bytes([target_slot, 1]))
                    status = f"Slot {target_slot}: Classic"
                elif card_data and card_data["type"] == "ultralight":
                    drv.command(1004, bytes([target_slot, 6]))
                    drv.command(1006, bytes([target_slot, 1]))
                    status = f"Slot {target_slot}: NTAG"
                elif card_data and card_data["type"] == "em4100":
                    drv.command(1004, bytes([target_slot, 1]))
                    drv.command(1006, bytes([target_slot, 1]))
                    status = f"Slot {target_slot}: EM4100"
                else:
                    status = "Unsupported type"

                drv.command(1001, b"\x00")
                card = None
                card_data = None

            # Draw
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)

            # Header
            d.rectangle((0, 0, 127, 14), fill="#111")
            d.text((2, 2), "CLONE TO SLOT", font=font_sm, fill="#FF00FF")
            mode_col = "#00CCFF" if mode == "hf" else "#FFAA00"
            d.text((100, 2), mode.upper(), font=font_sm, fill=mode_col)

            y = 18

            # Status
            if status:
                d.text((2, y), status[:24], font=font_sm, fill="#FFAA00")
            y += 12

            # Slot info
            slots = drv.get_slot_info()
            target_info = slots[target_slot] if target_slot < len(slots) else None
            target_hf = target_info["hf_type"] if target_info and target_info["hf_type"] != "None" else "Empty"
            target_lf = target_info["lf_type"] if target_info and target_info["lf_type"] != "None" else "Empty"
            d.text((2, y), f"Target: Slot {target_slot}", font=font, fill="#ccc")
            y += 14
            d.text((4, y), f"  HF: {target_hf}  LF: {target_lf}", font=font_sm, fill="#555")
            y += 13

            if card:
                # Phase 2: show source card
                d.rectangle((2, y, 125, y + 1), fill="#1a2844")
                y += 4
                d.text((4, y), f"UID: {card.uid_hex}", font=font_sm, fill="#00FF00")
                y += 11
                d.text((4, y), f"Type: {card.card_type}", font=font_sm, fill="#ccc")
                y += 11

                if card_data and card_data["type"] == "classic":
                    cracked = sum(1 for s in card_data["sectors"] if s["key"])
                    total = len(card_data["sectors"])
                    d.text((4, y), f"Sectors: {cracked}/{total} cracked", font=font_sm, fill="#888")
                    y += 12
                elif card_data and card_data["type"] == "ultralight":
                    d.text((4, y), f"Pages: {len(card_data['pages'])}", font=font_sm, fill="#888")
                    y += 12

                d.text((4, y), "OK: Write to slot", font=font_sm, fill="#FF00FF")
            else:
                # Phase 1: prompt
                d.text((4, 80), "OK: Scan card", font=font_sm, fill="#666")
                d.text((4, 93), "K1: HF/LF  ^v: Slot", font=font_sm, fill="#444")

            # Footer
            d.rectangle((0, 116, 127, 127), fill="#111")
            d.text((2, 117), "OK:Scan/Clone K2:Clear", font=font_sm, fill="#666")
            lcd.LCD_ShowImage(img, 0, 0)
            time.sleep(0.03)

    finally:
        drv.close()
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
