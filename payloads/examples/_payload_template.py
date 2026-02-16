#!/usr/bin/env python3
"""
RaspyJack Payload Template (WebUI + GPIO compatible)
---------------------------------------------------
Use this as a starting point for custom payloads.
"""

import os
import sys
import time

# Allow imports from RaspyJack root
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# WebUI + GPIO input helper
from payloads._input_helper import get_button

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
WIDTH, HEIGHT = 128, 128
font = ImageFont.load_default()


def draw(lines):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    y = 4
    for line in lines:
        d.text((4, y), line[:18], font=font, fill="white")
        y += 12
    LCD.LCD_ShowImage(img, 0, 0)


def main():
    draw(["Payload ready", "KEY3 = exit"])
    while True:
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            break
        if btn:
            draw([f"Pressed: {btn}"])
        time.sleep(0.05)

    LCD.LCD_Clear()
    GPIO.cleanup()


if __name__ == "__main__":
    main()
