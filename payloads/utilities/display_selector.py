#!/usr/bin/env python3
"""
RaspyJack Payload -- Display Type Selector
-------------------------------------------
Switch between supported LCD screens from the device menu.
Changes take effect after reboot.

Controls:
  UP/DOWN  : Navigate
  OK       : Select and apply
  KEY3     : Cancel / Exit
"""

import os
import sys
import time
import json

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
font = scaled_font()
font_big = scaled_font(12)

CONF_PATH = "/root/Raspyjack/gui_conf.json"

DISPLAY_OPTIONS = [
    ("ST7735_128", "1.44\" 128x128"),
    ("ST7789_240", "1.3\"  240x240"),
]


def _get_current_type():
    try:
        with open(CONF_PATH) as f:
            data = json.load(f)
        return data.get("DISPLAY", {}).get("type", "ST7735_128")
    except Exception:
        return "ST7735_128"


def _set_display_type(dtype):
    try:
        with open(CONF_PATH) as f:
            data = json.load(f)
    except Exception:
        data = {}
    if "DISPLAY" not in data:
        data["DISPLAY"] = {}
    data["DISPLAY"]["type"] = dtype
    data["DISPLAY"]["supported_types"] = ["ST7735_128", "ST7789_240"]
    with open(CONF_PATH, "w") as f:
        json.dump(data, f, indent=4)


def _draw(cursor, current_type):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 14), fill="#003366")
    d.text((2, 1), "DISPLAY TYPE", font=font_big, fill="#00CCFF")

    # Options
    for i, (dtype, label) in enumerate(DISPLAY_OPTIONS):
        y = 24 + i * 28
        is_current = dtype == current_type
        is_selected = i == cursor

        if is_selected:
            d.rectangle((2, y - 2, 125, y + 22), fill="#1a1a2e")
            d.rectangle((2, y - 2, 4, y + 22), fill="#00CCFF")

        marker = "*" if is_current else " "
        color = "#00FF00" if is_selected else "#888888"
        d.text((8, y), f"{marker} {dtype}", font=font, fill=color)
        d.text((12, y + 11), label, font=font, fill="#666666" if not is_selected else "#AAAAAA")

    # Footer
    d.rectangle((0, 117, 127, 127), fill="#000000")
    d.text((2, 118), "OK=Apply  K3=Cancel", font=font, fill="#555555")

    LCD.LCD_ShowImage(img, 0, 0)


def main():
    current_type = _get_current_type()
    cursor = 0
    for i, (dtype, _) in enumerate(DISPLAY_OPTIONS):
        if dtype == current_type:
            cursor = i
            break

    try:
        while True:
            _draw(cursor, current_type)
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "UP":
                cursor = (cursor - 1) % len(DISPLAY_OPTIONS)

            elif btn == "DOWN":
                cursor = (cursor + 1) % len(DISPLAY_OPTIONS)

            elif btn == "OK":
                selected_type = DISPLAY_OPTIONS[cursor][0]
                if selected_type == current_type:
                    # Already active
                    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                    d = ScaledDraw(img)
                    d.text((64, 50), "Already active", font=font, fill="#FFFF00", anchor="mm")
                    d.text((64, 70), "No change needed", font=font, fill="#888888", anchor="mm")
                    LCD.LCD_ShowImage(img, 0, 0)
                    time.sleep(1.5)
                else:
                    # Apply change
                    _set_display_type(selected_type)
                    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                    d = ScaledDraw(img)
                    d.text((64, 40), "Display changed!", font=font_big, fill="#00FF00", anchor="mm")
                    d.text((64, 58), f"-> {selected_type}", font=font, fill="#FFFFFF", anchor="mm")
                    d.text((64, 80), "restart UI required", font=font, fill="#FF8800", anchor="mm")
                    d.text((64, 100), "OK=Reboot  K3=Later", font=font, fill="#555555", anchor="mm")
                    LCD.LCD_ShowImage(img, 0, 0)

                    while True:
                        btn2 = get_button(PINS, GPIO)
                        if btn2 == "OK":
                            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                            d = ScaledDraw(img)
                            d.text((64, 64), "Restart UI...", font=font_big, fill="#FF0000", anchor="mm")
                            LCD.LCD_ShowImage(img, 0, 0)
                            time.sleep(1)
                            os.system("sudo systemctl restart raspyjack")
                            return 0
                        elif btn2 == "KEY3":
                            break
                    break

            time.sleep(0.05)
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
