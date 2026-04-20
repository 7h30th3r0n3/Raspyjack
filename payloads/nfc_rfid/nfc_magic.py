#!/usr/bin/env python3
"""
RaspyJack Payload -- Magic Card Detector
==========================================
Detect magic card type: Gen1a, Gen2 (CUID), Gen3 (UFUID), Gen4 (GDM), or Original.

Controls:
  OK         Scan card
  KEY3       Exit
"""
import os, sys, time
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads.nfc_rfid._nfc_driver import auto_detect, is_classic

PINS = {"UP":6,"DOWN":19,"LEFT":5,"RIGHT":26,"OK":13,"KEY1":21,"KEY2":20,"KEY3":16}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
DEBOUNCE = 0.18
_last_btn = 0

def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE: return None
    if b: _last_btn = now
    return b

def _reselect(drv, timeout=1.0):
    """Re-detect card after auth failure (card goes to HALT state)."""
    return drv.read_passive_target(timeout=timeout)


def _detect_magic(drv, uid):
    """Detect magic card generation. Returns (type_name, details)."""
    key_ff = bytes.fromhex("FFFFFFFFFFFF")
    key_rand = bytes.fromhex("DEADBEEF1337")

    # Test 1: Auth block 0 with default key
    auth_ff = drv.mifare_auth(0, key_ff, uid, 0x60)
    if not auth_ff:
        return "Original", "Cannot auth block 0 with default key"

    # Read block 0
    block0 = drv.mifare_read(0)
    if not block0:
        return "Unknown", "Cannot read block 0"

    # Test 2: Try writing block 0 (flip one bit, then restore)
    original_b0 = block0
    test_data = bytes([block0[0] ^ 0x01]) + block0[1:]

    drv.mifare_auth(0, key_ff, uid, 0x60)
    write_ok = drv.mifare_write(0, test_data)

    if write_ok:
        # Restore immediately
        drv.mifare_auth(0, key_ff, uid, 0x60)
        drv.mifare_write(0, original_b0)

        # Test 3: Re-detect card and try random key
        _reselect(drv)
        auth_rand = drv.mifare_auth(0, key_rand, uid, 0x60)

        if auth_rand:
            return "Gen1a", "Any key accepted + Block 0 writable"

        # Re-detect after failed auth
        _reselect(drv)

        # Test 4: Gen4 detection
        if drv.mifare_auth(0, key_ff, uid, 0x60):
            gen4_cmd = bytes.fromhex("CF00000000CE")
            resp = drv.data_exchange(gen4_cmd, timeout=0.3)
            if resp:
                return "Gen4 (GDM)", "Block 0 writable + Gen4 config"

        return "Gen2 (CUID)", "Block 0 writable with default key"
    else:
        # Cannot write block 0 — check SAK for hints
        if uid[0] == 0x04:
            return "Original (NXP)", "Block 0 read-only, genuine NXP"
        return "Original / Gen3 locked", "Block 0 read-only"


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
    result = None
    card = None
    status = drv_desc if drv else "No reader"

    try:
        while True:
            btn = _btn()
            if btn == "KEY3": break
            if btn == "OK" and drv:
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.text((4, 50), "Place card...", font=font_sm, fill="#FFAA00")
                lcd.LCD_ShowImage(img, 0, 0)

                card = drv.read_passive_target(timeout=5.0)
                if card and is_classic(card):
                    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                    d = ScaledDraw(img)
                    d.text((4, 50), "Detecting type...", font=font_sm, fill="#FFAA00")
                    lcd.LCD_ShowImage(img, 0, 0)
                    result = _detect_magic(drv, card.uid)
                    status = result[0]
                elif card:
                    result = None
                    status = f"Not Classic: {card.card_type}"
                else:
                    result = None
                    status = "No card detected"

            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.rectangle((0, 0, 127, 14), fill="#111")
            d.text((2, 2), "MAGIC DETECT", font=font_sm, fill="#FF00FF")

            y = 20
            if result and card:
                d.text((4, y), f"UID: {card.uid_hex}", font=font_sm, fill="#00FF00"); y += 13
                d.text((4, y), f"Type: {card.card_type}", font=font_sm, fill="#ccc"); y += 15

                magic_type, detail = result
                col = "#00FF00" if "Gen" in magic_type else "#FFAA00" if "Original" in magic_type else "#888"
                d.text((4, y), magic_type, font=font, fill=col); y += 15
                d.text((4, y), detail[:22], font=font_sm, fill="#888"); y += 13

                if "Gen1" in magic_type or "Gen2" in magic_type:
                    d.text((4, y), "UID cloning: YES", font=font_sm, fill="#00FF00"); y += 12
                    d.text((4, y), "Full clone possible", font=font_sm, fill="#00FF00")
                elif "Gen4" in magic_type:
                    d.text((4, y), "Advanced clone: YES", font=font_sm, fill="#00FF00"); y += 12
                    d.text((4, y), "Configurable magic", font=font_sm, fill="#00CCFF")
                else:
                    d.text((4, y), "UID cloning: NO", font=font_sm, fill="#FF4444"); y += 12
                    d.text((4, y), "Data-only clone", font=font_sm, fill="#888")
            else:
                d.text((4, 50), "Press OK to scan", font=font_sm, fill="#666")
                if status:
                    d.text((4, 70), status[:22], font=font_sm, fill="#FFAA00")

            d.rectangle((0, 116, 127, 127), fill="#111")
            d.text((2, 117), "OK:Scan KEY3:Exit", font=font_sm, fill="#666")
            lcd.LCD_ShowImage(img, 0, 0)
            time.sleep(0.03)
    finally:
        if drv: drv.close()
        try: lcd.LCD_Clear()
        except: pass
        GPIO.cleanup()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
