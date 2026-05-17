#!/usr/bin/env python3
"""
RaspyJack Payload -- Brightness Control
==========================================
Author: 7h30th3r0n3

Adjust LCD backlight brightness.

Controls:
  UP/DOWN     Adjust brightness
  OK          Set to default (100%)
  KEY3        Exit (keeps current brightness)
"""

import os
import sys
import time
import signal

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)
for p in PINS.values():
    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)
time.sleep(0.1)
_STUCK_PINS = {name for name, pin in PINS.items() if GPIO.input(pin) == 0}

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
W, H = LCD.width, LCD.height
IS_WIDE = W > 200

if IS_WIDE:
    from PIL import ImageFont
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 16)
        font_sm = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 11)
        font_lg = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 22)
    except Exception:
        font = scaled_font(10)
        font_sm = scaled_font(8)
        font_lg = scaled_font(14)
else:
    font = scaled_font(10)
    font_sm = scaled_font(8)
    font_lg = scaled_font(14)

BL_PATH = "/sys/class/backlight/backlight/brightness"
BL_MAX_PATH = "/sys/class/backlight/backlight/max_brightness"
_running = True

C_BG = (0, 0, 0)
C_WHITE = (255, 255, 255)
C_DIM = (80, 80, 80)
C_YELLOW = (255, 200, 0)
C_DARK = (15, 15, 20)
C_BAR_BG = (30, 30, 40)
C_BAR = (255, 200, 0)


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _get_btn():
    btn = get_button(PINS, GPIO)
    if btn and btn in _STUCK_PINS:
        return None
    return btn


def _get_brightness():
    try:
        with open(BL_PATH, "r") as f:
            return int(f.read().strip())
    except Exception:
        return 100


def _set_brightness(val):
    val = max(1, min(100, val))
    try:
        with open(BL_PATH, "w") as f:
            f.write(str(val))
    except Exception:
        pass
    return val


def _draw(brightness):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    if IS_WIDE:
        d.text((W // 2, 25), "BRIGHTNESS", font=font, fill=C_YELLOW,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 50, 15), "BRIGHTNESS", font=font, fill=C_YELLOW)

        d.text((W // 2, 60), f"{brightness}%", font=font_lg, fill=C_WHITE,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 25, 45), f"{brightness}%", font=font_lg, fill=C_WHITE)

        bar_x, bar_w = 30, W - 60
        bar_y = 90
        bar_h = 20
        d.rectangle([bar_x, bar_y, bar_x + bar_w, bar_y + bar_h], fill=C_BAR_BG)
        fill_w = int(bar_w * brightness / 100)
        if fill_w > 0:
            d.rectangle([bar_x, bar_y, bar_x + fill_w, bar_y + bar_h], fill=C_BAR)

        sun = ""
        if brightness > 70:
            sun = "MAX"
        elif brightness > 30:
            sun = "MED"
        else:
            sun = "LOW"
        d.text((W // 2, 130), sun, font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 12, 125), sun, font=font_sm, fill=C_DIM)

        d.rectangle([0, H - 16, W, H], fill=C_DARK)
        d.text((W // 2, H - 8), "UP/DN:Adjust  OK:Reset  K3:Exit",
               font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (5, H - 13), "UP/DN OK:Reset K3:Exit", font=font_sm, fill=C_DIM)
    else:
        d.text((15, 5), "BRIGHTNESS", font=font_lg, fill=C_YELLOW)
        d.text((40, 40), f"{brightness}%", font=font_lg, fill=C_WHITE)
        d.rectangle([10, 70, 118, 85], fill=C_BAR_BG)
        fill_w = int(108 * brightness / 100)
        if fill_w > 0:
            d.rectangle([10, 70, 10 + fill_w, 85], fill=C_BAR)
        d.text((4, 108), "UP/DN OK:Reset K3:X", font=font_sm, fill=C_DIM)

    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global _running

    if not os.path.exists(BL_PATH):
        img = Image.new("RGB", (W, H), C_BG)
        d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
        if IS_WIDE:
            d.text((W // 2, H // 2), "No backlight control", font=font, fill=(255, 50, 50),
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (10, H // 2 - 7), "No backlight ctrl", font=font, fill=(255, 50, 50))
        else:
            d.text((4, 55), "No backlight", font=font, fill=(255, 50, 50))
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    brightness = _get_brightness()
    last_btn = 0
    _draw(brightness)

    while _running:
        btn = _get_btn()
        now = time.time()

        if btn == "KEY3":
            break

        if btn == "UP" and now - last_btn > 0.08:
            last_btn = now
            brightness = _set_brightness(brightness + 5)
            _draw(brightness)

        if btn == "DOWN" and now - last_btn > 0.08:
            last_btn = now
            brightness = _set_brightness(brightness - 5)
            _draw(brightness)

        if btn == "OK" and now - last_btn > 0.2:
            last_btn = now
            brightness = _set_brightness(100)
            _draw(brightness)

        time.sleep(0.05)

    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
