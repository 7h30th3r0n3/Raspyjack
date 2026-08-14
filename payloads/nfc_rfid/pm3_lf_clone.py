#!/usr/bin/env python3
"""
RaspyJack Payload -- PM3 LF Clone
====================================
Clone 125kHz badges (EM4100, HID, Indala) to T5577 using Proxmark3.
Browse saved LF dumps and write to blank T5577 cards.

Controls:
  OK         Select dump / Start clone
  UP/DOWN    Navigate dumps
  KEY1       Verify clone
  KEY2       Delete dump
  KEY3       Exit
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
from payloads.nfc_rfid._nfc_driver import auto_detect, PM3Driver

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
LOOT_DIR = "/root/Raspyjack/loot/NFC/lf"
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


def _list_lf_dumps():
    if not os.path.isdir(LOOT_DIR):
        return []
    result = []
    for f in sorted(os.listdir(LOOT_DIR), reverse=True):
        if f.endswith(".json"):
            path = os.path.join(LOOT_DIR, f)
            try:
                with open(path) as fh:
                    d = json.load(fh)
                result.append({
                    "file": f, "path": path,
                    "tag_type": d.get("tag_type", "?"),
                    "tag_id": d.get("tag_id", "?"),
                    "raw": d.get("raw", ""),
                    "fc": d.get("fc", ""),
                    "cn": d.get("cn", ""),
                })
            except Exception:
                pass
    return result


def _clone_tag(drv, dump, lcd, font_sm, font_xs):
    tag_type = dump.get("tag_type", "").lower()
    tag_id = dump.get("tag_id", "")
    raw = dump.get("raw", "")

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 14), fill="#111")
    d.text((2, 2), "CLONING LF", font=font_sm, fill="#FF8800")
    d.text((4, 24), f"Type: {dump.get('tag_type', '?')}", font=font_sm, fill="#ccc")
    d.text((4, 38), f"ID: {tag_id[:16]}", font=font_sm, fill="#ccc")
    d.text((4, 56), "Place T5577 on PM3...", font=font_sm, fill="#FFAA00")
    lcd.LCD_ShowImage(img, 0, 0)

    out = None
    if "em4" in tag_type or "em410" in tag_type:
        out = drv.command(f"lf em 410x clone --id {tag_id}")
    elif "hid" in tag_type:
        if raw:
            out = drv.command(f"lf hid clone -r {raw}")
        elif dump.get("fc") and dump.get("cn"):
            out = drv.command(f"lf hid clone --fc {dump['fc']} --cn {dump['cn']}")
    elif "indala" in tag_type:
        if raw:
            out = drv.command(f"lf indala clone --raw {raw}")
    elif raw:
        out = drv.command(f"lf t55xx write -b 0 -d {raw}")

    if not out:
        return False, "No response"
    lower = out.lower()
    if "done" in lower or "ok" in lower or "success" in lower or "written" in lower:
        return True, "Clone OK"
    if "error" in lower or "fail" in lower:
        return False, "Clone failed"
    return True, "Sent"


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

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), "Detecting reader...", font=font_sm, fill="#FFAA00")
    lcd.LCD_ShowImage(img, 0, 0)

    drv, drv_desc = auto_detect()
    scroll = 0
    status = drv_desc if drv else "No reader"

    try:
        while True:
            if not drv or not isinstance(drv, PM3Driver):
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.text((4, 40), "Proxmark3 required!", font=font, fill="#FF4444")
                d.text((4, 60), "Connect PM3 Easy/RDV4", font=font_sm, fill="#888")
                lcd.LCD_ShowImage(img, 0, 0)
                btn = _btn()
                if btn == "KEY3":
                    break
                if btn == "OK":
                    drv, drv_desc = auto_detect()
                    status = drv_desc
                continue

            dumps = _list_lf_dumps()

            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.rectangle((0, 0, 127, 14), fill="#111")
            d.text((2, 2), "LF CLONE", font=font_sm, fill="#FF8800")
            d.text((80, 2), f"{len(dumps)}tags", font=font_xs, fill="#888")

            y = 18
            d.text((2, y), status[:24], font=font_sm, fill="#FFAA00")
            y += 13

            if not dumps:
                d.text((4, 50), "No saved LF tags", font=font_sm, fill="#666")
                d.text((4, 65), "Use LF Reader first", font=font_sm, fill="#888")
            else:
                scroll = min(scroll, max(0, len(dumps) - 1))
                for i in range(max(0, scroll - 2), min(len(dumps), scroll + 5)):
                    if y > 105:
                        break
                    dm = dumps[i]
                    col = "#FF8800" if i == scroll else "#888"
                    prefix = "> " if i == scroll else "  "
                    d.text((2, y), f"{prefix}{dm['tag_id'][:10]}", font=font_sm, fill=col)
                    d.text((80, y), dm["tag_type"][:8], font=font_xs, fill="#555")
                    y += 11

            d.rectangle((0, 116, 127, 127), fill="#111")
            d.text((2, 117), "OK:Clone K1:Vrfy K2:Del", font=font_xs, fill="#666")
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
                    status = f"Deleted {dumps[idx]['tag_id'][:8]}"
                except Exception:
                    status = "Delete failed"
            elif btn == "KEY1" and drv:
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.text((4, 50), "Place tag on PM3...", font=font_sm, fill="#FFAA00")
                lcd.LCD_ShowImage(img, 0, 0)
                out = drv.command("lf search", timeout=10.0)
                if out:
                    import re
                    tag_id = None
                    for pat in [r"Tag\s*ID\s*[:=]\s*([0-9A-Fa-f]+)",
                                r"EM\s*410x.*?:\s*([0-9A-Fa-f]+)",
                                r"HID.*?:\s*([0-9A-Fa-f]+)"]:
                        m = re.search(pat, out, re.IGNORECASE)
                        if m:
                            tag_id = m.group(1)
                            break
                    status = f"Verify: {tag_id}" if tag_id else "No tag found"
                else:
                    status = "No response"
            elif btn == "OK" and dumps:
                idx = min(scroll, len(dumps) - 1)
                dump = dumps[idx]
                ok, msg = _clone_tag(drv, dump, lcd, font_sm, font_xs)
                status = msg
                time.sleep(1)

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
