#!/usr/bin/env python3
"""
RaspyJack Payload -- Payload Favorites Manager
================================================
Author: 7h30th3r0n3

Manages a favorites list for quick access to frequently used payloads.
Browse all payloads or view only favorites, toggle favorites, and
launch payloads directly from the favorites view.

Controls
--------
  UP / DOWN  -- Navigate payload list
  OK         -- Execute selected payload (in Favorites view)
  KEY1       -- Toggle favorite for selected payload
  KEY2       -- Switch between All / Favorites view
  KEY3       -- Exit
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
DEBOUNCE = 0.22
PAYLOADS_DIR = os.path.abspath(os.path.join(__file__, "..", ".."))
LOOT_DIR = "/root/Raspyjack/loot/Favorites"
FAVORITES_PATH = os.path.join(LOOT_DIR, "favorites.json")

_running = True


def _cleanup(*_args):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# Payload discovery
# ---------------------------------------------------------------------------

def _scan_payloads():
    """Scan payloads directory for .py files, return sorted list of dicts."""
    payloads = []
    try:
        for category in sorted(os.listdir(PAYLOADS_DIR)):
            cat_path = os.path.join(PAYLOADS_DIR, category)
            if not os.path.isdir(cat_path):
                continue
            if category.startswith("_") or category == "__pycache__":
                continue
            for fname in sorted(os.listdir(cat_path)):
                if not fname.endswith(".py") or fname.startswith("_"):
                    continue
                full_path = os.path.join(cat_path, fname)
                name = fname[:-3]
                payloads.append({
                    "name": name,
                    "category": category,
                    "path": full_path,
                    "key": f"{category}/{name}",
                })
    except OSError:
        pass
    return payloads


# ---------------------------------------------------------------------------
# Favorites persistence
# ---------------------------------------------------------------------------

def _load_favorites():
    """Load favorites set from disk."""
    if not os.path.isfile(FAVORITES_PATH):
        return set()
    try:
        with open(FAVORITES_PATH, "r") as fh:
            data = json.load(fh)
        return set(data.get("favorites", []))
    except Exception:
        return set()


def _save_favorites(favorites):
    """Save favorites set to disk."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    data = {"favorites": sorted(favorites)}
    with open(FAVORITES_PATH, "w") as fh:
        json.dump(data, fh, indent=2)


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_list(lcd, font, items, favorites, cursor, scroll, view_mode, status):
    """Draw the payload list."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    view_label = "FAVORITES" if view_mode == "fav" else "ALL PAYLOADS"
    d.text((2, 1), view_label, font=font, fill="#00CCFF")
    d.text((105, 1), f"{len(items)}", font=font, fill="#888")

    # List
    visible = 7
    y = 16
    end = min(len(items), scroll + visible)

    if not items:
        msg = "No favorites yet" if view_mode == "fav" else "No payloads"
        d.text((4, 40), msg, font=font, fill="#666")
        if view_mode == "fav":
            d.text((4, 55), "K2 to browse all", font=font, fill="#888")
    else:
        for idx in range(scroll, end):
            item = items[idx]
            is_sel = idx == cursor
            is_fav = item["key"] in favorites
            prefix = ">" if is_sel else " "
            star = "*" if is_fav else " "
            name_short = item["name"][:12]
            cat_short = item["category"][:4]
            label = f"{prefix}{star}{name_short}"
            if is_sel:
                color = "#00FF00"
            elif is_fav:
                color = "#FFAA00"
            else:
                color = "#AAAAAA"
            d.text((2, y), label, font=font, fill=color)
            d.text((100, y), cat_short, font=font, fill="#555")
            y += ROW_H

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if status:
        d.text((2, 117), status[:22], font=font, fill="#FFFF00")
    else:
        foot = "K1:fav K2:view K3:exit"
        if view_mode == "fav":
            foot = "OK:run K1:fav K2:view"
        d.text((2, 117), foot, font=font, fill="#AAA")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_confirm(lcd, font, name):
    """Draw launch confirmation."""
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

    all_payloads = _scan_payloads()
    favorites = _load_favorites()
    view_mode = "all"  # "all" or "fav"
    cursor = 0
    scroll = 0
    status = ""
    last_press = 0.0
    visible = 7
    mode = "browse"  # browse | confirm

    def _get_items():
        if view_mode == "fav":
            return [p for p in all_payloads if p["key"] in favorites]
        return list(all_payloads)

    items = _get_items()

    try:
        while _running:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if mode == "confirm":
                if btn == "OK" and items and cursor < len(items):
                    payload = items[cursor]
                    try:
                        subprocess.Popen(
                            [sys.executable, payload["path"]],
                            start_new_session=True,
                        )
                        status = "Launched!"
                    except Exception as exc:
                        status = f"Err:{str(exc)[:14]}"
                    mode = "browse"
                    time.sleep(0.3)
                    continue
                elif btn:
                    status = "Cancelled"
                    mode = "browse"
                    time.sleep(0.1)
                    continue
                time.sleep(0.08)
                continue

            if btn == "KEY3":
                break
            elif btn == "UP":
                cursor = max(0, cursor - 1)
                if cursor < scroll:
                    scroll = cursor
                status = ""
            elif btn == "DOWN":
                cursor = min(max(0, len(items) - 1), cursor + 1)
                if cursor >= scroll + visible:
                    scroll = cursor - visible + 1
                status = ""
            elif btn == "KEY1":
                if items and cursor < len(items):
                    key = items[cursor]["key"]
                    if key in favorites:
                        favorites = favorites - {key}
                        status = "Removed"
                    else:
                        favorites = favorites | {key}
                        status = "Added *"
                    _save_favorites(favorites)
                    items = _get_items()
                    cursor = min(cursor, max(0, len(items) - 1))
            elif btn == "KEY2":
                view_mode = "fav" if view_mode == "all" else "all"
                items = _get_items()
                cursor = 0
                scroll = 0
                status = ""
            elif btn == "OK":
                if view_mode == "fav" and items and cursor < len(items):
                    _draw_confirm(lcd, font, items[cursor]["name"])
                    mode = "confirm"
                    time.sleep(0.1)
                    continue

            _draw_list(lcd, font, items, favorites, cursor, scroll,
                       view_mode, status)
            time.sleep(0.08)

    finally:
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
