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
    try:
        # Example gate usage before entering the interactive loop:
        #
        # REQUIRE_CAPABILITY("binary", "bluetoothctl")
        # WAIT_FOR_PRESENT(
        #     name="RJTRIG-A",
        #     service_uuid="7f7b0001-2b7a-4e10-a6be-8e4f9d41c101",
        #     timeout_seconds=30,
        # )
        #
        # Example action chaining:
        # RUN_PAYLOAD("utilities/trigger_marker.py", "template_demo")

        draw(["Payload ready", "KEY3 = exit"])
        while True:
            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                break
            if btn:
                draw([f"Pressed: {btn}"])
            time.sleep(0.05)
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()


if __name__ == "__main__":
    main()
