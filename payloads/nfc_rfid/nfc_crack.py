#!/usr/bin/env python3
"""
RaspyJack Payload -- NFC Key Cracker
======================================
Brute-force MIFARE Classic sector keys with extended dictionary (~100 keys).
Visual progress grid showing cracked/locked/active sectors.

Controls:
  OK         Start crack / Re-read card
  UP/DOWN    Scroll results
  KEY2       Save keymap
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
from payloads.nfc_rfid._nfc_driver import auto_detect, is_classic
from payloads.nfc_rfid._nfc_keys import KNOWN_KEYS, save_keymap, load_keymap
from payloads.nfc_rfid._nfc_cards import save_dump

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

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), "Detecting reader...", font=font_sm, fill="#FFAA00")
    lcd.LCD_ShowImage(img, 0, 0)

    drv, drv_desc = auto_detect()
    status = drv_desc if drv else "No reader"
    results = []
    card = None
    scroll = 0
    cracking = False
    start_time = 0

    try:
        while True:
            btn = _btn()
            if btn == "KEY3":
                if cracking:
                    cracking = False
                else:
                    break

            if btn == "OK" and drv and not cracking:
                # Read card
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.text((4, 50), "Place card...", font=font_sm, fill="#FFAA00")
                lcd.LCD_ShowImage(img, 0, 0)

                card = drv.read_passive_target(timeout=3.0)
                if card and is_classic(card):
                    cracking = True
                    results = []
                    start_time = time.time()
                    n_sectors = 16 if "4K" not in card.card_type else 40

                    # Load saved keymap if exists
                    saved_keys = load_keymap(card.uid_hex)

                    for sec in range(n_sectors):
                        if not cracking:
                            break
                        block = sec * 4

                        # Draw grid
                        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                        d = ScaledDraw(img)
                        d.rectangle((0, 0, 127, 12), fill="#111")
                        d.text((2, 1), "CRACKING", font=font_sm, fill="#FF4444")
                        elapsed = int(time.time() - start_time)
                        d.text((70, 1), f"{elapsed}s", font=font_xs, fill="#888")

                        d.text((2, 16), f"UID: {card.uid_hex[:12]}", font=font_xs, fill="#00FF00")
                        d.text((2, 26), f"Sector {sec}/{n_sectors} - {len(KNOWN_KEYS)} keys", font=font_xs, fill="#FFAA00")

                        # 4x4 sector grid (or 8x5 for 4K)
                        cols = 4 if n_sectors <= 16 else 8
                        rows = (n_sectors + cols - 1) // cols
                        cell = min(12, (80) // cols)
                        gx = (127 - cols * cell) // 2
                        gy = 38

                        for si in range(n_sectors):
                            cx = gx + (si % cols) * cell
                            cy = gy + (si // cols) * cell
                            if si < len(results):
                                col = "#00FF00" if results[si]["cracked"] else "#FF4444"
                            elif si == sec:
                                col = "#FFAA00"
                            else:
                                col = "#222"
                            d.rectangle((cx, cy, cx + cell - 2, cy + cell - 2), fill=col)

                        cracked = sum(1 for r in results if r["cracked"])
                        d.text((2, 108), f"Cracked: {cracked}/{sec}  Keys:{len(KNOWN_KEYS)}", font=font_xs, fill="#888")
                        lcd.LCD_ShowImage(img, 0, 0)

                        # Try saved key first
                        found_key = None
                        found_kt = 0x60
                        if saved_keys:
                            for sk in saved_keys:
                                if sk.get("sector") == sec and sk.get("cracked"):
                                    try:
                                        k = bytes.fromhex(sk["key"])
                                        kt = 0x60 if sk.get("key_type") == "A" else 0x61
                                        if drv.mifare_auth(block, k, card.uid, kt):
                                            found_key = k
                                            found_kt = kt
                                            break
                                    except Exception:
                                        pass

                        # Reuse keys from cracked sectors
                        if not found_key:
                            for r in results:
                                if r["cracked"] and r["key"]:
                                    k = bytes.fromhex(r["key"])
                                    for kt in [0x60, 0x61]:
                                        if drv.mifare_auth(block, k, card.uid, kt):
                                            found_key = k
                                            found_kt = kt
                                            break
                                    if found_key:
                                        break

                        # Full dictionary
                        if not found_key:
                            for key in KNOWN_KEYS:
                                for kt in [0x60, 0x61]:
                                    if drv.mifare_auth(block, key, card.uid, kt):
                                        found_key = key
                                        found_kt = kt
                                        break
                                if found_key:
                                    break

                        results.append({
                            "sector": sec,
                            "key": found_key.hex().upper() if found_key else "",
                            "key_type": "A" if found_kt == 0x60 else "B",
                            "cracked": found_key is not None,
                        })

                    cracking = False
                    cracked = sum(1 for r in results if r["cracked"])
                    elapsed = int(time.time() - start_time)
                    status = f"{cracked}/{len(results)} in {elapsed}s"
                    if results and card:
                        save_keymap(card.uid_hex, results)

                elif card:
                    status = f"Not Classic: {card.card_type}"
                else:
                    status = "No card detected"

            if btn == "KEY2" and results and card:
                save_keymap(card.uid_hex, results)
                status = f"Keys saved: {card.uid_hex[:8]}"

            if btn == "UP":
                scroll = max(0, scroll - 1)
            elif btn == "DOWN" and results:
                scroll = min(scroll + 1, max(0, len(results) - 6))

            if not cracking:
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.rectangle((0, 0, 127, 12), fill="#111")
                d.text((2, 1), "NFC CRACK", font=font_sm, fill="#FF4444")
                d.text((80, 1), drv_desc[:6] if drv else "NONE", font=font_xs,
                       fill="#00FF00" if drv else "#FF4444")

                y = 16
                d.text((2, y), status[:24], font=font_sm, fill="#FFAA00")
                y += 12

                if results:
                    for i in range(scroll, min(len(results), scroll + 6)):
                        r = results[i]
                        col = "#00FF00" if r["cracked"] else "#FF4444"
                        key_txt = f"{r['key'][:12]} ({r['key_type']})" if r["cracked"] else "LOCKED"
                        d.text((2, y), f"S{r['sector']:02d} {key_txt}", font=font_xs, fill=col)
                        y += 10
                else:
                    d.text((4, 50), "Press OK to scan card", font=font_sm, fill="#666")
                    d.text((4, 65), f"{len(KNOWN_KEYS)} keys in dict", font=font_xs, fill="#888")

                d.rectangle((0, 116, 127, 127), fill="#111")
                d.text((2, 117), "OK:Crack K2:Save K3:X", font=font_xs, fill="#666")
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
