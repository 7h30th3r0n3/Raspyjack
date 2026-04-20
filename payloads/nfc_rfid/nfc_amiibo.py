#!/usr/bin/env python3
"""
RaspyJack Payload -- Amiibo Reader/Cloner
============================================
Read, identify and clone Nintendo Amiibo (NTAG215).

Controls:
  OK         Read / Clone
  KEY1       Switch mode (Read/Clone)
  KEY2       Save dump
  KEY3       Exit
"""
import os, sys, time, json
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads.nfc_rfid._nfc_driver import auto_detect, is_ultralight
from payloads.nfc_rfid._nfc_cards import read_ultralight_pages, save_dump

PINS = {"UP":6,"DOWN":19,"LEFT":5,"RIGHT":26,"OK":13,"KEY1":21,"KEY2":20,"KEY3":16}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
DEBOUNCE = 0.18
_last_btn = 0
LOOT_DIR = "/root/Raspyjack/loot/NFC/amiibo"

# Amiibo character database (top 50)
AMIIBO_DB = {
    "0000": "Mario", "0001": "Luigi", "0002": "Peach", "0003": "Yoshi",
    "0004": "Rosalina", "0005": "Bowser", "0006": "Bowser Jr", "0007": "Wario",
    "0008": "Donkey Kong", "0009": "Diddy Kong", "000a": "Toad", "000c": "Zelda",
    "000d": "Sheik", "000e": "Ganondorf", "000f": "Toon Link", "0010": "Samus",
    "0011": "Zero Suit Samus", "0013": "Fox", "0014": "Falco", "0017": "Pikachu",
    "0018": "Charizard", "0019": "Jigglypuff", "001a": "Mewtwo", "001b": "Lucario",
    "001c": "Greninja", "001f": "Marth", "0020": "Ike", "0021": "Lucina",
    "0022": "Robin", "0023": "Captain Falcon", "0024": "Villager",
    "0025": "Isabelle", "0028": "Kirby", "0029": "King Dedede",
    "002a": "Meta Knight", "002c": "Little Mac", "002f": "Pit",
    "0030": "Palutena", "0031": "Dark Pit", "0034": "Olimar",
    "0038": "Ness", "003c": "Shulk", "0100": "Inkling",
    "0101": "Inkling Boy", "0102": "Inkling Girl", "0103": "Callie",
    "0104": "Marie", "0200": "Tom Nook", "0201": "K.K. Slider",
    "0340": "Link", "0341": "Link (Rider)", "0342": "Link (Archer)",
}

GAME_SERIES = {
    "00": "Super Mario", "01": "Legend of Zelda", "02": "Animal Crossing",
    "03": "Star Fox", "04": "Metroid", "05": "F-Zero",
    "06": "Pikmin", "07": "Punch-Out", "08": "Wii Fit",
    "09": "Kid Icarus", "0a": "Fire Emblem", "0c": "Kirby",
    "0d": "Pokemon", "0e": "Splatoon", "0f": "Earthbound",
    "10": "Xenoblade", "19": "Smash Bros",
}

def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE: return None
    if b: _last_btn = now
    return b

def _identify_amiibo(pages):
    """Identify amiibo from NTAG215 pages. Returns (name, series, char_id)."""
    if len(pages) < 23 or pages[21] is None or pages[22] is None:
        return None, None, None
    # Character ID is at pages 21-22 (bytes 84-91)
    char_bytes = pages[21] + pages[22]
    game_id = char_bytes[0:1].hex()
    char_id = char_bytes[0:2].hex()
    name = AMIIBO_DB.get(char_id, f"Unknown ({char_id})")
    series = GAME_SERIES.get(game_id, f"Series {game_id}")
    return name, series, char_id

def _is_amiibo(pages):
    """Check if tag looks like an Amiibo (7-byte UID + data at pages 21-22)."""
    if len(pages) < 23: return False
    if pages[21] is None or pages[22] is None: return False
    # Check page 21-22 have non-zero data (character ID area)
    return any(b != 0 for b in pages[21]) or any(b != 0 for b in pages[22])

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
    mode = 0  # 0=read, 1=clone
    status = drv_desc if drv else "No reader"
    amiibo_data = None
    last_pages = None

    try:
        while True:
            btn = _btn()
            if btn == "KEY3": break
            if btn == "KEY1":
                mode = 1 - mode

            if btn == "OK" and drv:
                if mode == 0:
                    # Read
                    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                    d = ScaledDraw(img)
                    d.text((4, 50), "Place Amiibo...", font=font_sm, fill="#FFAA00")
                    lcd.LCD_ShowImage(img, 0, 0)
                    card = drv.read_passive_target(timeout=5.0)
                    if card and (is_ultralight(card) or len(card.uid) == 7):
                        pages = read_ultralight_pages(drv, max_pages=135)
                        if _is_amiibo(pages):
                            name, series, char_id = _identify_amiibo(pages)
                            amiibo_data = {"name": name, "series": series, "id": char_id, "uid": card.uid_hex}
                            last_pages = [p.hex() if p else None for p in pages]
                            status = name or "Amiibo detected"
                        else:
                            status = "Not an Amiibo"
                            amiibo_data = None
                    elif card:
                        status = f"Not UL: {card.card_type}"
                        amiibo_data = None
                    else:
                        status = "No card"
                        amiibo_data = None

                elif mode == 1 and last_pages:
                    # Clone
                    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                    d = ScaledDraw(img)
                    d.text((4, 40), "Place blank NTAG215", font=font_sm, fill="#FFAA00")
                    d.text((4, 58), "on reader...", font=font_sm, fill="#FFAA00")
                    lcd.LCD_ShowImage(img, 0, 0)
                    card = drv.read_passive_target(timeout=8.0)
                    if card and is_ultralight(card):
                        written = 0
                        for i in range(3, 130):
                            if i < len(last_pages) and last_pages[i]:
                                data = bytes.fromhex(last_pages[i])
                                if drv.mifare_ul_write(i, data):
                                    written += 1
                        status = f"Cloned! {written} pages"
                    else:
                        status = "No target tag"

            if btn == "KEY2" and amiibo_data and last_pages:
                os.makedirs(LOOT_DIR, exist_ok=True)
                from datetime import datetime
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                fname = f"amiibo_{amiibo_data.get('name', 'unknown')}_{ts}.json"
                with open(os.path.join(LOOT_DIR, fname), "w") as f:
                    json.dump({**amiibo_data, "pages": last_pages, "timestamp": ts}, f, indent=2)
                status = f"Saved: {fname[:16]}"

            # Draw
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.rectangle((0, 0, 127, 14), fill="#111")
            mode_txt = "READ" if mode == 0 else "CLONE"
            d.text((2, 2), f"AMIIBO {mode_txt}", font=font_sm, fill="#FF0000")
            y = 20
            d.text((4, y), status[:24], font=font_sm, fill="#FFAA00"); y += 13

            if amiibo_data:
                name = amiibo_data.get("name", "?")
                series = amiibo_data.get("series", "?")
                char_id = amiibo_data.get("id", "?")
                d.text((4, y), name[:20], font=font, fill="#FF0000"); y += 15
                d.text((4, y), series[:20], font=font_sm, fill="#ccc"); y += 12
                d.text((4, y), f"ID: {char_id}", font=font_sm, fill="#888"); y += 12
                d.text((4, y), f"UID: {amiibo_data.get('uid', '')[:14]}", font=font_sm, fill="#888")
            else:
                d.text((4, 55), "Press OK to scan", font=font_sm, fill="#666")

            d.rectangle((0, 116, 127, 127), fill="#111")
            d.text((2, 117), "OK:Scan K1:Mode K2:Save", font=font_sm, fill="#666")
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
