#!/usr/bin/env python3
"""
RaspyJack Payload -- Weather Display
=====================================
Author: 7h30th3r0n3

Fetches and displays current weather conditions from wttr.in.
Supports city selection with a character picker.

Controls:
  UP / DOWN    -- Scroll weather lines
  KEY1         -- Refresh weather data
  KEY2         -- Change city (character picker)
  KEY3         -- Exit

Config: /root/Raspyjack/loot/Weather/config.json
"""

import os
import sys
import json
import time
import signal
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROW_H = 12
CONFIG_DIR = "/root/Raspyjack/loot/Weather"
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
CHARSET = list(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789 -_."
)

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
running = True
city = "Paris"
weather_lines = ["Press KEY1 to fetch"]
scroll_offset = 0


def cleanup(*_args):
    global running
    running = False


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def load_config():
    global city
    try:
        with open(CONFIG_PATH, "r") as f:
            cfg = json.load(f)
        city = cfg.get("city", "Paris")
    except Exception:
        city = "Paris"


def save_config():
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump({"city": city}, f)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Weather fetching
# ---------------------------------------------------------------------------


def fetch_weather(location):
    """Fetch weather from wttr.in using curl. Returns list of display lines."""
    try:
        result = subprocess.run(
            ["curl", "-s", f"wttr.in/{location}?format=%l:+%c+%t+%w+%h+%p"],
            capture_output=True, text=True, timeout=15,
        )
        raw = result.stdout.strip()
        if not raw or "Unknown location" in raw:
            return [f"City: {location}", "Not found or offline"]
    except Exception as exc:
        return [f"Error: {str(exc)[:20]}"]

    # Split long lines to fit 128px wide screen (~20 chars)
    lines = []
    for part in raw.split("\n"):
        while len(part) > 20:
            lines.append(part[:20])
            part = part[20:]
        if part:
            lines.append(part)
    return lines if lines else ["No data"]


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------


def draw_main(lcd, font):
    """Render the main weather display."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), f"Weather: {city[:12]}", font=font, fill="#00CCFF")

    # Weather content area (y 15 to 114)
    max_visible = 8
    visible = weather_lines[scroll_offset:scroll_offset + max_visible]
    for i, line in enumerate(visible):
        y = 15 + i * ROW_H
        d.text((2, y), line[:22], font=font, fill="#FFFFFF")

    # Scroll indicator
    if len(weather_lines) > max_visible:
        total = len(weather_lines)
        indicator = f"{scroll_offset + 1}-{min(scroll_offset + max_visible, total)}/{total}"
        d.text((70, 1), indicator, font=font, fill="#888")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "K1:Ref K2:City K3:X", font=font, fill="#AAA")

    lcd.LCD_ShowImage(img, 0, 0)


def draw_city_picker(lcd, font, chars, char_idx):
    """Render the city name character picker."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "SET CITY", font=font, fill="#FFAA00")

    # Current city name
    city_str = "".join(chars)
    d.text((2, 18), f"City: {city_str[:16]}", font=font, fill="#FFFFFF")

    # Character selector
    current_char = CHARSET[char_idx]
    d.text((2, 40), f"Char: [{current_char}]", font=font, fill="#00FF00")
    d.text((2, 54), f"Len: {len(chars)}", font=font, fill="#888")

    # Instructions
    d.text((2, 72), "UP/DN: char", font=font, fill="#666")
    d.text((2, 84), "OK: add  KEY1: del", font=font, fill="#666")
    d.text((2, 96), "KEY2: confirm", font=font, fill="#666")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "KEY3: cancel", font=font, fill="#AAA")

    lcd.LCD_ShowImage(img, 0, 0)


def draw_fetching(lcd, font):
    """Show a loading screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "WEATHER", font=font, fill="#00CCFF")
    d.text((10, 55), "Fetching...", font=font, fill="#FFFF00")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    global running, city, weather_lines, scroll_offset

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    font = scaled_font()

    load_config()

    # Initial fetch
    draw_fetching(lcd, font)
    weather_lines = fetch_weather(city)
    scroll_offset = 0

    in_picker = False
    picker_chars = []
    picker_char_idx = 0

    try:
        while running:
            btn = get_button(PINS, GPIO)

            if in_picker:
                if btn == "UP":
                    picker_char_idx = (picker_char_idx + 1) % len(CHARSET)
                    time.sleep(0.12)
                elif btn == "DOWN":
                    picker_char_idx = (picker_char_idx - 1) % len(CHARSET)
                    time.sleep(0.12)
                elif btn == "OK":
                    picker_chars = picker_chars + [CHARSET[picker_char_idx]]
                    time.sleep(0.15)
                elif btn == "KEY1":
                    if picker_chars:
                        picker_chars = picker_chars[:-1]
                    time.sleep(0.15)
                elif btn == "KEY2":
                    new_city = "".join(picker_chars).strip()
                    if new_city:
                        city = new_city
                        save_config()
                        draw_fetching(lcd, font)
                        weather_lines = fetch_weather(city)
                        scroll_offset = 0
                    in_picker = False
                    time.sleep(0.2)
                    continue
                elif btn == "KEY3":
                    in_picker = False
                    time.sleep(0.2)
                    continue

                draw_city_picker(lcd, font, picker_chars, picker_char_idx)
                time.sleep(0.05)
                continue

            # Main view controls
            if btn == "UP":
                if scroll_offset > 0:
                    scroll_offset -= 1
                time.sleep(0.15)
            elif btn == "DOWN":
                max_off = max(0, len(weather_lines) - 8)
                if scroll_offset < max_off:
                    scroll_offset += 1
                time.sleep(0.15)
            elif btn == "KEY1":
                draw_fetching(lcd, font)
                weather_lines = fetch_weather(city)
                scroll_offset = 0
                time.sleep(0.3)
            elif btn == "KEY2":
                picker_chars = list(city)
                picker_char_idx = 0
                in_picker = True
                time.sleep(0.2)
                continue
            elif btn == "KEY3":
                break

            draw_main(lcd, font)
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
