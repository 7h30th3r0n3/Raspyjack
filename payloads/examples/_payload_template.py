#!/usr/bin/env python3
"""
RaspyJack Payload Template (WebUI + GPIO compatible)
---------------------------------------------------
Use this as a starting point for custom payloads.

Optional extension API:

- WAIT_FOR_PRESENT
- WAIT_FOR_NOTPRESENT
- REQUIRE_CAPABILITY
- RUN_PAYLOAD

Those helpers live in `EXTENSIONS.api` and can be used before or during the
main payload loop. The default template behavior below stays interactive and
keeps `KEY3` as the exit button.
"""

import os
import sys
import time

# Allow imports from RaspyJack root
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font

# WebUI + GPIO input helper
from payloads._input_helper import get_button
from payloads._keyboard_helper import lcd_keyboard

# Optional shared extension helpers.
# Uncomment what you need for a given payload.
#
# from EXTENSIONS.api import (
#     WAIT_FOR_PRESENT,
#     WAIT_FOR_NOTPRESENT,
#     REQUIRE_CAPABILITY,
#     RUN_PAYLOAD,
# )

PINS = {
    "UP": 6,
    "DOWN": 19,
    "LEFT": 5,
    "RIGHT": 26,
    "OK": 13,
    "KEY1": 21,
    "KEY2": 20,
    "KEY3": 16,
}

GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
font = scaled_font()


def draw(lines):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    y = 4
    for line in lines:
        d.text((4, y), line[:18], font=font, fill="white")
        y += 12
    LCD.LCD_ShowImage(img, 0, 0)


def main():
    typed_value = ""
    draw(["Payload ready", "KEY1 = text", "KEY3 = exit"])
    while True:
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            break
        if btn == "KEY1":
            result = lcd_keyboard(
                LCD,
                font,
                PINS,
                GPIO,
                title="Example Input",
                default=typed_value,
                charset="full",
                max_len=32,
            )
            if result is not None:
                typed_value = result
                draw(["Saved:", typed_value[-18:] or "<empty>", "KEY1 = edit", "KEY3 = exit"])
            else:
                draw(["Input cancelled", typed_value[-18:] or "<empty>", "KEY1 = text", "KEY3 = exit"])
            time.sleep(0.1)
            continue
        if btn:
            draw([f"Pressed: {btn}", typed_value[-18:] or "<empty>"])
        time.sleep(0.05)

    LCD.LCD_Clear()
    GPIO.cleanup()


if __name__ == "__main__":
    main()
