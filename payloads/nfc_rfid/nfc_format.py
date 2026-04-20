#!/usr/bin/env python3
"""
RaspyJack Payload -- NFC Card Formatter
=========================================
Erase/format NFC cards. Reset data, keys, or NDEF.

Controls:
  OK         Select mode / Confirm format
  UP/DOWN    Navigate modes
  KEY3       Exit / Cancel
"""
import os, sys, time
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads.nfc_rfid._nfc_driver import auto_detect, is_classic, is_ultralight
from payloads.nfc_rfid._nfc_keys import KNOWN_KEYS

PINS = {"UP":6,"DOWN":19,"LEFT":5,"RIGHT":26,"OK":13,"KEY1":21,"KEY2":20,"KEY3":16}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
DEBOUNCE = 0.18
_last_btn = 0
MODES = [
    ("Quick Format", "Erase data, keep keys"),
    ("Full Format", "Erase all + reset keys"),
    ("NDEF Format", "Write empty NDEF"),
]

def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE: return None
    if b: _last_btn = now
    return b

def _format_classic(drv, uid, mode, lcd, font_sm):
    """Format MIFARE Classic. Returns (formatted_blocks, errors)."""
    key_ff = bytes.fromhex("FFFFFFFFFFFF")
    zeros = b"\x00" * 16
    trailer_default = bytes.fromhex("FFFFFFFFFFFF") + bytes.fromhex("FF078069") + bytes.fromhex("FFFFFFFFFFFF")
    formatted = 0
    errors = 0
    n_sectors = 16

    for sec in range(n_sectors):
        block = sec * 4
        pct = sec * 100 // n_sectors
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.rectangle((0, 0, 127, 14), fill="#111")
        d.text((2, 2), "FORMATTING", font=font_sm, fill="#FF4444")
        d.text((80, 2), f"{pct}%", font=font_sm, fill="#FF4444")
        d.rectangle((4, 30, 123, 38), outline="#333")
        bw = max(1, int(119 * sec / max(1, n_sectors)))
        d.rectangle((4, 30, 4 + bw, 38), fill="#FF4444")
        d.text((4, 50), f"Sector {sec}/{n_sectors}", font=font_sm, fill="#FFAA00")
        d.text((4, 70), f"Done: {formatted} Err: {errors}", font=font_sm, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)

        authed = False
        for key in KNOWN_KEYS[:10]:
            for kt in [0x60, 0x61]:
                if drv.mifare_auth(block, key, uid, kt):
                    authed = True
                    break
            if authed: break

        if not authed:
            errors += 1
            continue

        for b in range(3):
            if block + b == 0: continue
            if drv.mifare_write(block + b, zeros):
                formatted += 1
            else:
                errors += 1

        if mode == 1:
            if drv.mifare_write(block + 3, trailer_default):
                formatted += 1
            else:
                errors += 1

    return formatted, errors

def _format_ultralight(drv, mode, lcd, font_sm):
    """Format Ultralight/NTAG."""
    zeros = b"\x00\x00\x00\x00"
    formatted = 0
    errors = 0

    if mode == 2:
        ndef_empty = b"\x03\x00\xFE\x00"
        if drv.mifare_ul_write(4, ndef_empty):
            formatted += 1
            for p in range(5, 40):
                if drv.mifare_ul_write(p, zeros): formatted += 1
                else: break
        return formatted, errors

    for p in range(4, 40):
        pct = p * 100 // 40
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.rectangle((0, 0, 127, 14), fill="#111")
        d.text((2, 2), "FORMATTING", font=font_sm, fill="#FF4444")
        d.text((80, 2), f"{pct}%", font=font_sm, fill="#FF4444")
        d.rectangle((4, 30, 123, 38), outline="#333")
        bw = max(1, int(119 * p / 40))
        d.rectangle((4, 30, 4 + bw, 38), fill="#FF4444")
        d.text((4, 50), f"Page {p}/40", font=font_sm, fill="#FFAA00")
        lcd.LCD_ShowImage(img, 0, 0)
        if drv.mifare_ul_write(p, zeros):
            formatted += 1
        else:
            errors += 1
            break
    return formatted, errors

def main():
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font = scaled_font(10)
    font_sm = scaled_font(9)

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), "Detecting reader...", font=font_sm, fill="#FFAA00")
    lcd.LCD_ShowImage(img, 0, 0)
    drv, drv_desc = auto_detect()
    sel = 0
    status = drv_desc if drv else "No reader"

    try:
        while True:
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.rectangle((0, 0, 127, 14), fill="#111")
            d.text((2, 2), "NFC FORMAT", font=font_sm, fill="#FF4444")

            y = 20
            d.text((2, y), status[:24], font=font_sm, fill="#FFAA00"); y += 13
            for i, (name, desc) in enumerate(MODES):
                col = "#FF4444" if i == sel else "#888"
                prefix = "> " if i == sel else "  "
                d.text((2, y), f"{prefix}{name}", font=font_sm, fill=col); y += 12
                if i == sel:
                    d.text((10, y), desc[:20], font=font_sm, fill="#555"); y += 10

            d.rectangle((0, 116, 127, 127), fill="#111")
            d.text((2, 117), "OK:Format KEY3:Exit", font=font_sm, fill="#666")
            lcd.LCD_ShowImage(img, 0, 0)

            btn = _btn()
            if btn == "KEY3": break
            elif btn == "UP": sel = (sel - 1) % len(MODES)
            elif btn == "DOWN": sel = (sel + 1) % len(MODES)
            elif btn == "OK" and drv:
                # Confirm
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.text((4, 30), "WARNING!", font=font, fill="#FF4444")
                d.text((4, 50), "This will erase data", font=font_sm, fill="#FFAA00")
                d.text((4, 65), "OK=Confirm KEY3=Cancel", font=font_sm, fill="#888")
                lcd.LCD_ShowImage(img, 0, 0)
                while True:
                    b2 = _btn()
                    if b2 == "KEY3": break
                    if b2 == "OK":
                        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                        d = ScaledDraw(img)
                        d.text((4, 50), "Place card...", font=font_sm, fill="#FFAA00")
                        lcd.LCD_ShowImage(img, 0, 0)
                        card = drv.read_passive_target(timeout=5.0)
                        if card:
                            if is_classic(card):
                                fmt, err = _format_classic(drv, card.uid, sel, lcd, font_sm)
                                status = f"Done: {fmt}blk {err}err"
                            elif is_ultralight(card):
                                fmt, err = _format_ultralight(drv, sel, lcd, font_sm)
                                status = f"Done: {fmt}pg {err}err"
                            else:
                                status = f"Unsupported: {card.card_type}"
                        else:
                            status = "No card"
                        break
    finally:
        if drv: drv.close()
        try: lcd.LCD_Clear()
        except: pass
        GPIO.cleanup()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
