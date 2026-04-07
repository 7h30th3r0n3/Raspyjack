#!/usr/bin/env python3
"""
RaspyJack Payload -- Alarm Clock
==================================
Author: 7h30th3r0n3

Displays current time with configurable alarm. Flashes the screen
when alarm triggers until dismissed.

Controls:
  UP / DOWN    -- Adjust alarm hour
  LEFT / RIGHT -- Adjust alarm minute
  KEY1         -- Arm / disarm alarm
  KEY2         -- Toggle 12h / 24h format
  KEY3         -- Exit

Config: /root/Raspyjack/loot/Alarm/config.json
"""

import os
import sys
import json
import time
import signal
from datetime import datetime

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
CONFIG_DIR = "/root/Raspyjack/loot/Alarm"
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
running = True
alarm_hour = 7
alarm_minute = 0
alarm_armed = False
use_24h = True
alarm_triggered = False


def cleanup(*_args):
    global running
    running = False


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def load_config():
    global alarm_hour, alarm_minute, alarm_armed, use_24h
    try:
        with open(CONFIG_PATH, "r") as f:
            cfg = json.load(f)
        alarm_hour = cfg.get("hour", 7)
        alarm_minute = cfg.get("minute", 0)
        alarm_armed = cfg.get("armed", False)
        use_24h = cfg.get("use_24h", True)
    except Exception:
        pass


def save_config():
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        cfg = {
            "hour": alarm_hour,
            "minute": alarm_minute,
            "armed": alarm_armed,
            "use_24h": use_24h,
        }
        with open(CONFIG_PATH, "w") as f:
            json.dump(cfg, f)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Time formatting
# ---------------------------------------------------------------------------


def format_time_str(now, is_24h):
    """Format current time for display."""
    if is_24h:
        return now.strftime("%H:%M:%S")
    return now.strftime("%I:%M:%S %p")


def format_alarm_str(hour, minute, is_24h):
    """Format alarm time for display."""
    if is_24h:
        return f"{hour:02d}:{minute:02d}"
    period = "AM" if hour < 12 else "PM"
    display_h = hour % 12
    if display_h == 0:
        display_h = 12
    return f"{display_h:02d}:{minute:02d} {period}"


def format_date_str(now):
    """Format current date for display."""
    return now.strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------


def draw_clock(lcd, font, font_large):
    """Render the main clock display."""
    now = datetime.now()
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "ALARM CLOCK", font=font, fill="#00CCFF")
    fmt_label = "24H" if use_24h else "12H"
    d.text((100, 1), fmt_label, font=font, fill="#888")

    # Large time display
    time_str = format_time_str(now, use_24h)
    d.text((8, 25), time_str, font=font_large, fill="#FFFFFF")

    # Date
    date_str = format_date_str(now)
    d.text((20, 50), date_str, font=font, fill="#888888")

    # Alarm info
    alarm_str = format_alarm_str(alarm_hour, alarm_minute, use_24h)
    arm_status = "ARMED" if alarm_armed else "OFF"
    arm_color = "#00FF00" if alarm_armed else "#FF4444"
    d.text((2, 68), f"Alarm: {alarm_str}", font=font, fill="#CCCCCC")
    d.text((2, 80), f"Status: {arm_status}", font=font, fill=arm_color)

    # Controls hint
    d.text((2, 96), "U/D:Hr L/R:Min", font=font, fill="#555")
    d.text((2, 106), "K1:Arm K2:Fmt", font=font, fill="#555")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), f"Alarm {arm_status}  K3:Exit", font=font, fill="#AAA")

    lcd.LCD_ShowImage(img, 0, 0)


def draw_alarm_flash(lcd, font_large, flash_state):
    """Render the alarm triggered flash screen."""
    bg_color = "#FF0000" if flash_state else "#00FF00"
    text_color = "#FFFFFF" if flash_state else "#000000"

    img = Image.new("RGB", (WIDTH, HEIGHT), bg_color)
    d = ScaledDraw(img)

    d.text((20, 30), "ALARM!", font=font_large, fill=text_color)
    d.text((15, 60), "WAKE UP!", font=font_large, fill=text_color)

    now = datetime.now()
    time_str = format_time_str(now, use_24h)
    d.text((20, 90), time_str, font=font_large, fill=text_color)

    d.text((10, 110), "Press any button", font=scaled_font(8), fill=text_color)

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Alarm check
# ---------------------------------------------------------------------------


def check_alarm():
    """Check if alarm should trigger. Returns True if alarm fires."""
    if not alarm_armed:
        return False
    now = datetime.now()
    return now.hour == alarm_hour and now.minute == alarm_minute


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    global running, alarm_hour, alarm_minute, alarm_armed
    global use_24h, alarm_triggered

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    font = scaled_font()
    font_large = scaled_font(14)

    load_config()

    last_trigger_minute = -1
    flash_state = False

    try:
        while running:
            btn = get_button(PINS, GPIO)

            # Alarm ringing mode
            if alarm_triggered:
                if btn is not None:
                    alarm_triggered = False
                    time.sleep(0.3)
                    continue
                flash_state = not flash_state
                draw_alarm_flash(lcd, font_large, flash_state)
                time.sleep(0.3)
                continue

            # Normal mode controls
            if btn == "UP":
                alarm_hour = (alarm_hour + 1) % 24
                save_config()
                time.sleep(0.2)
            elif btn == "DOWN":
                alarm_hour = (alarm_hour - 1) % 24
                save_config()
                time.sleep(0.2)
            elif btn == "LEFT":
                alarm_minute = (alarm_minute - 1) % 60
                save_config()
                time.sleep(0.15)
            elif btn == "RIGHT":
                alarm_minute = (alarm_minute + 1) % 60
                save_config()
                time.sleep(0.15)
            elif btn == "KEY1":
                alarm_armed = not alarm_armed
                save_config()
                time.sleep(0.3)
            elif btn == "KEY2":
                use_24h = not use_24h
                save_config()
                time.sleep(0.3)
            elif btn == "KEY3":
                break

            # Check alarm trigger (once per minute)
            now = datetime.now()
            current_minute = now.hour * 60 + now.minute
            if current_minute != last_trigger_minute:
                if check_alarm():
                    alarm_triggered = True
                    last_trigger_minute = current_minute
                    continue

            draw_clock(lcd, font, font_large)
            time.sleep(0.1)

    finally:
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
