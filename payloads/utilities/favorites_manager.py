#!/usr/bin/env python3
"""
RaspyJack Payload -- Payload Favorites Manager
================================================
Author: 7h30th3r0n3

Browse payloads by category (same arborescence as the Payload menu),
toggle favorites, and launch them. Favorites appear in the main menu.

Controls
--------
  UP / DOWN   Navigate list
  OK          Enter category / toggle fav / launch payload
  KEY1        Toggle favorite for selected payload
  KEY2        Switch to Favorites-only view
  KEY3 / LEFT Back / Exit
"""

import os
import sys
import time
import signal
import subprocess
import json

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROW_H = 12
VISIBLE = 7
PAYLOADS_DIR = os.path.abspath(os.path.join(__file__, "..", ".."))
LOOT_DIR = "/root/Raspyjack/loot/Favorites"
FAVORITES_PATH = os.path.join(LOOT_DIR, "favorites.json")

CATEGORY_ORDER = [
    "reconnaissance", "wifi", "network", "credentials", "bluetooth",
    "usb", "exfiltration", "evasion", "remote_access", "utilities",
    "hardware", "games", "examples",
]

_running = True


def _cleanup(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

def _scan_by_category():
    """Return {category: [{name, path, key}, ...]}."""
    cats = {}
    try:
        for cat in sorted(os.listdir(PAYLOADS_DIR)):
            cat_path = os.path.join(PAYLOADS_DIR, cat)
            if not os.path.isdir(cat_path) or cat.startswith("_") or cat == "__pycache__":
                continue
            items = []
            for fn in sorted(os.listdir(cat_path)):
                if not fn.endswith(".py") or fn.startswith("_"):
                    continue
                name = fn[:-3]
                items.append({
                    "name": name,
                    "path": os.path.join(cat_path, fn),
                    "key": f"{cat}/{fn}",
                })
            if items:
                cats[cat] = items
    except OSError:
        pass
    return cats


def _load_favorites():
    if not os.path.isfile(FAVORITES_PATH):
        return set()
    try:
        with open(FAVORITES_PATH, "r") as f:
            return set(json.load(f).get("favorites", []))
    except Exception:
        return set()


def _save_favorites(favs):
    os.makedirs(LOOT_DIR, exist_ok=True)
    with open(FAVORITES_PATH, "w") as f:
        json.dump({"favorites": sorted(favs)}, f, indent=2)


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_categories(lcd, font, categories, favorites, cursor, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "FAVORITES", font=font, fill="#FFAA00")
    fav_count = len(favorites)
    d.text((90, 1), f"{fav_count} fav", font=font, fill="#888")

    ordered = [c for c in CATEGORY_ORDER if c in categories]
    for c in categories:
        if c not in ordered:
            ordered.append(c)

    visible_items = ordered[scroll:scroll + VISIBLE]
    for i, cat in enumerate(visible_items):
        y = 16 + i * ROW_H
        idx = scroll + i
        prefix = ">" if idx == cursor else " "
        color = "#00FF00" if idx == cursor else "#CCCCCC"

        # Count favorites in this category
        cat_favs = sum(1 for p in categories[cat] if p["key"] in favorites)
        cat_total = len(categories[cat])
        star = f" ({cat_favs})" if cat_favs > 0 else ""

        display = cat.replace("_", " ").title()[:14]
        d.text((2, y), f"{prefix}{display}{star}", font=font, fill=color)
        d.text((110, y), str(cat_total), font=font, fill="#555")

    if not ordered:
        d.text((4, 50), "No payloads found", font=font, fill="#666")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Open K2:Favs K3:Exit", font=font, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)

    return ordered


def _draw_payloads(lcd, font, cat_name, items, favorites, cursor, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#111")
    display_cat = cat_name.replace("_", " ").title()[:16]
    d.text((2, 1), display_cat, font=font, fill="#00CCFF")

    visible_items = items[scroll:scroll + VISIBLE]
    for i, item in enumerate(visible_items):
        y = 16 + i * ROW_H
        idx = scroll + i
        prefix = ">" if idx == cursor else " "
        is_fav = item["key"] in favorites
        star = "*" if is_fav else " "

        if idx == cursor:
            color = "#00FF00"
        elif is_fav:
            color = "#FFAA00"
        else:
            color = "#AAAAAA"

        d.text((2, y), f"{prefix}{star}{item['name'][:17]}", font=font, fill=color)

    if not items:
        d.text((4, 50), "Empty category", font=font, fill="#666")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "K1:Fav OK:Run K3:Back", font=font, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_favs_only(lcd, font, all_favs, favorites_set, cursor, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#442200")
    d.text((2, 1), f"MY FAVORITES ({len(all_favs)})", font=font, fill="#FFAA00")

    visible_items = all_favs[scroll:scroll + VISIBLE]
    for i, item in enumerate(visible_items):
        y = 16 + i * ROW_H
        idx = scroll + i
        prefix = ">" if idx == cursor else " "
        color = "#00FF00" if idx == cursor else "#FFAA00"
        cat_short = item["category"][:4]
        d.text((2, y), f"{prefix}*{item['name'][:14]}", font=font, fill=color)
        d.text((105, y), cat_short, font=font, fill="#555")

    if not all_favs:
        d.text((4, 40), "No favorites yet", font=font, fill="#666")
        d.text((4, 55), "Browse categories", font=font, fill="#888")
        d.text((4, 67), "and press K1 to add", font=font, fill="#888")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Run K1:Rm K2:Browse K3:X", font=font, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_confirm(lcd, font, name):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((10, 30), "Launch payload?", font=font, fill="#00CCFF")
    d.text((10, 48), name[:18], font=font, fill="#00FF00")
    d.text((10, 70), "OK = Yes", font=font, fill="#00FF00")
    d.text((10, 85), "Any = Cancel", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    font = scaled_font()

    categories = _scan_by_category()
    favorites = _load_favorites()

    # Views: "categories" | "payloads" | "favs"
    view = "categories"
    cursor = 0
    scroll = 0
    current_cat = ""
    current_items = []
    ordered_cats = []

    def _build_favs_list():
        result = []
        for cat in CATEGORY_ORDER:
            for item in categories.get(cat, []):
                if item["key"] in favorites:
                    result.append(dict(item, category=cat))
        return result

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if view == "categories":
                if btn == "KEY3":
                    break
                elif btn == "UP":
                    cursor = max(0, cursor - 1)
                    if cursor < scroll:
                        scroll = cursor
                    time.sleep(0.15)
                elif btn == "DOWN":
                    cursor = min(max(0, len(ordered_cats) - 1), cursor + 1)
                    if cursor >= scroll + VISIBLE:
                        scroll = cursor - VISIBLE + 1
                    time.sleep(0.15)
                elif btn == "OK" and ordered_cats and cursor < len(ordered_cats):
                    current_cat = ordered_cats[cursor]
                    current_items = categories.get(current_cat, [])
                    view = "payloads"
                    cursor = 0
                    scroll = 0
                    time.sleep(0.2)
                elif btn == "KEY2":
                    view = "favs"
                    cursor = 0
                    scroll = 0
                    time.sleep(0.2)

                ordered_cats = _draw_categories(lcd, font, categories, favorites, cursor, scroll)

            elif view == "payloads":
                if btn in ("KEY3", "LEFT"):
                    # Back to categories, restore position
                    view = "categories"
                    cursor = ordered_cats.index(current_cat) if current_cat in ordered_cats else 0
                    scroll = max(0, cursor - VISIBLE + 1) if cursor >= VISIBLE else 0
                    time.sleep(0.2)
                elif btn == "UP":
                    cursor = max(0, cursor - 1)
                    if cursor < scroll:
                        scroll = cursor
                    time.sleep(0.15)
                elif btn == "DOWN":
                    cursor = min(max(0, len(current_items) - 1), cursor + 1)
                    if cursor >= scroll + VISIBLE:
                        scroll = cursor - VISIBLE + 1
                    time.sleep(0.15)
                elif btn == "KEY1" and current_items and cursor < len(current_items):
                    key = current_items[cursor]["key"]
                    if key in favorites:
                        favorites = favorites - {key}
                    else:
                        favorites = favorites | {key}
                    _save_favorites(favorites)
                    time.sleep(0.2)
                elif btn == "OK" and current_items and cursor < len(current_items):
                    _draw_confirm(lcd, font, current_items[cursor]["name"])
                    time.sleep(0.1)
                    while _running:
                        b = get_button(PINS, GPIO)
                        if b == "OK":
                            try:
                                subprocess.Popen(
                                    [sys.executable, current_items[cursor]["path"]],
                                    start_new_session=True,
                                )
                            except Exception:
                                pass
                            break
                        elif b:
                            break
                        time.sleep(0.05)
                    time.sleep(0.3)

                _draw_payloads(lcd, font, current_cat, current_items, favorites, cursor, scroll)

            elif view == "favs":
                fav_list = _build_favs_list()
                if btn in ("KEY3", "KEY2"):
                    view = "categories"
                    cursor = 0
                    scroll = 0
                    time.sleep(0.2)
                elif btn == "UP":
                    cursor = max(0, cursor - 1)
                    if cursor < scroll:
                        scroll = cursor
                    time.sleep(0.15)
                elif btn == "DOWN":
                    cursor = min(max(0, len(fav_list) - 1), cursor + 1)
                    if cursor >= scroll + VISIBLE:
                        scroll = cursor - VISIBLE + 1
                    time.sleep(0.15)
                elif btn == "KEY1" and fav_list and cursor < len(fav_list):
                    key = fav_list[cursor]["key"]
                    favorites = favorites - {key}
                    _save_favorites(favorites)
                    cursor = min(cursor, max(0, len(fav_list) - 2))
                    time.sleep(0.2)
                elif btn == "OK" and fav_list and cursor < len(fav_list):
                    _draw_confirm(lcd, font, fav_list[cursor]["name"])
                    time.sleep(0.1)
                    while _running:
                        b = get_button(PINS, GPIO)
                        if b == "OK":
                            try:
                                subprocess.Popen(
                                    [sys.executable, fav_list[cursor]["path"]],
                                    start_new_session=True,
                                )
                            except Exception:
                                pass
                            break
                        elif b:
                            break
                        time.sleep(0.05)
                    time.sleep(0.3)

                _draw_favs_only(lcd, font, fav_list, favorites, cursor, scroll)

            time.sleep(0.05)

    finally:
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
