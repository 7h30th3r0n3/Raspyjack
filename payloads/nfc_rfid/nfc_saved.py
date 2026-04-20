#!/usr/bin/env python3
"""
RaspyJack Payload -- NFC Card Manager
========================================
Browse, view, delete and export saved NFC card dumps.
Supports Flipper Zero .nfc export format.

Controls:
  OK         View card detail
  UP/DOWN    Navigate / scroll
  KEY1       Export Flipper .nfc
  KEY2       Delete card
  KEY3       Exit / Back
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
from payloads.nfc_rfid._nfc_cards import list_dumps, load_dump, export_flipper_nfc

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
DEBOUNCE = 0.18
_last_btn = 0


def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE:
        return None
    if b:
        _last_btn = now
    return b


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

    scroll = 0
    status = ""

    try:
        while True:
            dumps = list_dumps()

            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.rectangle((0, 0, 127, 12), fill="#111")
            d.text((2, 1), "NFC CARDS", font=font_sm, fill="#00FF00")
            d.text((80, 1), f"{len(dumps)} saved", font=font_xs, fill="#888")

            y = 16
            if status:
                d.text((2, y), status[:24], font=font_xs, fill="#FFAA00")
                y += 10

            if not dumps:
                d.text((4, 50), "No saved cards", font=font_sm, fill="#666")
                d.text((4, 65), "Use NFC Reader first", font=font_sm, fill="#888")
            else:
                scroll = min(scroll, max(0, len(dumps) - 1))
                for i in range(max(0, scroll - 3), min(len(dumps), scroll + 6)):
                    if y > 108:
                        break
                    dm = dumps[i]
                    col = "#00FF00" if i == scroll else "#888"
                    prefix = "> " if i == scroll else "  "
                    d.text((2, y), f"{prefix}{dm['uid'][:10]}", font=font_sm, fill=col)
                    d.text((78, y), dm["type"][:7], font=font_xs, fill="#555")
                    info = f"{dm['sectors']}s" if dm['sectors'] else f"{dm['pages']}p"
                    d.text((112, y), info, font=font_xs, fill="#444")
                    y += 11

            d.rectangle((0, 116, 127, 127), fill="#111")
            d.text((2, 117), "OK:View K1:Flip K2:Del", font=font_xs, fill="#666")
            lcd.LCD_ShowImage(img, 0, 0)

            btn = _btn()
            if btn == "KEY3":
                break
            elif btn == "UP":
                scroll = max(0, scroll - 1)
            elif btn == "DOWN":
                scroll += 1
            elif btn == "KEY2" and dumps:
                idx = min(scroll, len(dumps) - 1)
                try:
                    os.remove(dumps[idx]["path"])
                    status = f"Deleted {dumps[idx]['uid'][:8]}"
                    scroll = min(scroll, max(0, len(dumps) - 2))
                except Exception:
                    status = "Delete failed"
            elif btn == "KEY1" and dumps:
                idx = min(scroll, len(dumps) - 1)
                dump = load_dump(dumps[idx]["path"])
                if dump:
                    path = export_flipper_nfc(dump)
                    if path:
                        status = f"Exported .nfc"
                    else:
                        status = "Export failed"
            elif btn == "OK" and dumps:
                idx = min(scroll, len(dumps) - 1)
                dump = load_dump(dumps[idx]["path"])
                if not dump:
                    status = "Load failed"
                    continue

                # Detail view
                detail_scroll = 0
                while True:
                    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                    d = ScaledDraw(img)
                    d.rectangle((0, 0, 127, 12), fill="#111")
                    d.text((2, 1), "CARD DETAIL", font=font_sm, fill="#00CCFF")

                    y = 16
                    d.text((2, y), f"UID: {dump.get('uid', '?')}", font=font_sm, fill="#00FF00")
                    y += 11
                    d.text((2, y), f"Type: {dump.get('type', '?')}", font=font_sm, fill="#ccc")
                    y += 11
                    d.text((2, y), f"Date: {dump.get('timestamp', '?')[:10]}", font=font_xs, fill="#888")
                    y += 11

                    # Sectors
                    secs = dump.get("sectors", [])
                    pages = dump.get("pages", [])
                    ndef = dump.get("ndef", [])

                    if secs:
                        cracked = sum(1 for s in secs if s.get("key"))
                        d.text((2, y), f"Sectors: {cracked}/{len(secs)}", font=font_sm, fill="#ccc")
                        y += 12
                        for i in range(detail_scroll, min(len(secs), detail_scroll + 3)):
                            s = secs[i]
                            col = "#00FF00" if s.get("key") else "#FF4444"
                            key_txt = s["key"][:12] if s.get("key") else "LOCKED"
                            d.text((2, y), f"S{s['sector']:02d} {key_txt}", font=font_xs, fill=col)
                            y += 9

                    if pages:
                        d.text((2, y), f"Pages: {len(pages)}", font=font_sm, fill="#ccc")
                        y += 12
                        for i in range(detail_scroll, min(len(pages), detail_scroll + 3)):
                            p = pages[i]
                            txt = p if p else "--------"
                            d.text((2, y), f"P{i:03d} {txt[:16]}", font=font_xs, fill="#aaa")
                            y += 9

                    if ndef:
                        for r in ndef[:2]:
                            d.text((2, y), f"[{r['kind']}] {r['parsed'][:16]}", font=font_xs, fill="#00CCFF")
                            y += 9

                    d.rectangle((0, 116, 127, 127), fill="#111")
                    d.text((2, 117), "^v:Scroll KEY3:Back", font=font_xs, fill="#666")
                    lcd.LCD_ShowImage(img, 0, 0)

                    b2 = _btn()
                    if b2 == "KEY3":
                        break
                    elif b2 == "UP":
                        detail_scroll = max(0, detail_scroll - 1)
                    elif b2 == "DOWN":
                        max_items = max(len(secs), len(pages))
                        detail_scroll = min(detail_scroll + 1, max(0, max_items - 3))

    finally:
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
