#!/usr/bin/env python3
"""
RaspyJack Payload -- GPIO Tripwire (Physical Intrusion Detection)
=================================================================
Author: 7h30th3r0n3

Monitors spare GPIO pins for state changes from contact switches, PIR
sensors, or other triggers.

Setup / Prerequisites:
  - Wire sensors to GPIO pins (PIR, door contacts, etc.).
  - Optional: Discord webhook in config for remote alerts.  On trigger: LCD alert, optional Discord
webhook notification, optional buzzer output.

Controls:
  OK          -- Arm / disarm
  UP / DOWN   -- Scroll event log
  KEY1        -- Test alarm
  KEY2        -- Configure pins (cycle preset configs)
  KEY3        -- Exit

Config: /root/Raspyjack/config/tripwire.json
"""

import os
import sys
import json
import time
import threading
import subprocess
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
ROWS_VISIBLE = 5
ROW_H = 12

CONFIG_PATH = "/root/Raspyjack/config/tripwire.json"

# Preset pin configurations
PIN_PRESETS = [
    {"name": "PIR+Door", "pins": [17, 27], "labels": ["PIR", "Door"]},
    {"name": "3-Zone", "pins": [17, 27, 22], "labels": ["Zone1", "Zone2", "Zone3"]},
    {"name": "Single PIR", "pins": [17], "labels": ["PIR"]},
    {"name": "Window+Door", "pins": [22, 27], "labels": ["Window", "Door"]},
]

BUZZER_PIN = 18  # optional buzzer output

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
armed = False
preset_idx = 0
trigger_count = 0
last_trigger_time = ""
event_log = []
scroll = 0
status_msg = "Disarmed"
discord_webhook_url = ""
buzzer_enabled = True
flash_alert = False

# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def _load_config():
    """Load configuration from JSON file."""
    global discord_webhook_url, buzzer_enabled
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        discord_webhook_url = cfg.get("discord_webhook", "")
        buzzer_enabled = cfg.get("buzzer_enabled", True)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Sensor pin setup
# ---------------------------------------------------------------------------

def _setup_sensor_pins(preset):
    """Set up GPIO pins for the current sensor preset."""
    for pin in preset["pins"]:
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)


def _setup_buzzer():
    """Set up buzzer output pin."""
    try:
        GPIO.setup(BUZZER_PIN, GPIO.OUT)
        GPIO.output(BUZZER_PIN, GPIO.LOW)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Alert actions
# ---------------------------------------------------------------------------

def _add_event(label, pin_num):
    """Record a trigger event."""
    global trigger_count, last_trigger_time
    ts = datetime.now().strftime("%H:%M:%S")
    entry = f"{ts} [{label}] pin {pin_num}"
    with lock:
        event_log.append(entry)
        if len(event_log) > 100:
            # Keep only the latest events
            del event_log[:len(event_log) - 100]
        trigger_count += 1
        last_trigger_time = ts


def _buzz_alert(duration=0.5):
    """Sound the buzzer briefly."""
    if not buzzer_enabled:
        return
    try:
        GPIO.output(BUZZER_PIN, GPIO.HIGH)
        time.sleep(duration)
        GPIO.output(BUZZER_PIN, GPIO.LOW)
    except Exception:
        pass


def _send_discord_alert(label, pin_num):
    """Send alert to Discord webhook."""
    if not discord_webhook_url:
        return
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    payload = json.dumps({
        "content": f"**TRIPWIRE ALERT** [{ts}]\nSensor: {label} (GPIO {pin_num})\nTrigger count: {trigger_count}",
    })
    try:
        subprocess.run(
            [
                "curl", "-s", "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", payload,
                discord_webhook_url,
            ],
            capture_output=True, timeout=10,
        )
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Monitor thread
# ---------------------------------------------------------------------------

def _monitor_thread():
    """Continuously monitor sensor pins for state changes."""
    global flash_alert

    preset = PIN_PRESETS[preset_idx]
    pin_states = {}

    # Initialize pin states
    for pin in preset["pins"]:
        pin_states[pin] = GPIO.input(pin)

    # Debounce: ignore triggers within 500ms of each other per pin
    last_trigger = {}

    while _running:
        if not armed:
            time.sleep(0.1)
            # Re-read preset in case it changed while disarmed
            new_preset = PIN_PRESETS[preset_idx]
            if new_preset != preset:
                preset = new_preset
                _setup_sensor_pins(preset)
                pin_states = {p: GPIO.input(p) for p in preset["pins"]}
            continue

        for i, pin in enumerate(preset["pins"]):
            current = GPIO.input(pin)
            prev = pin_states.get(pin, current)

            if current != prev:
                now = time.time()
                if now - last_trigger.get(pin, 0) > 0.5:
                    label = preset["labels"][i] if i < len(preset["labels"]) else f"Pin{pin}"
                    _add_event(label, pin)
                    flash_alert = True

                    # Alert in separate thread to avoid blocking
                    threading.Thread(
                        target=_buzz_alert, args=(0.3,), daemon=True
                    ).start()
                    threading.Thread(
                        target=_send_discord_alert, args=(label, pin),
                        daemon=True,
                    ).start()

                    last_trigger[pin] = now

            pin_states[pin] = current

        time.sleep(0.05)

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_frame(lcd, font_obj):
    """Render current state to the LCD."""
    global flash_alert

    is_flashing = flash_alert
    if is_flashing:
        flash_alert = False

    bg_color = "#330000" if is_flashing else "black"
    img = Image.new("RGB", (WIDTH, HEIGHT), bg_color)
    d = ScaledDraw(img)

    # Header
    header_color = "#FF0000" if armed else "#111"
    d.rectangle((0, 0, 127, 13), fill=header_color)
    d.text((2, 1), "GPIO TRIPWIRE", font=font_obj, fill="#FFFFFF" if armed else "#00CCFF")

    with lock:
        preset = PIN_PRESETS[preset_idx]
        count = trigger_count
        last_t = last_trigger_time
        is_armed = armed
        log = list(event_log)

    # Status
    arm_label = "ARMED" if is_armed else "DISARMED"
    arm_color = "#FF0000" if is_armed else "#00FF00"
    d.text((2, 16), f"Status: {arm_label}", font=font_obj, fill=arm_color)

    # Preset info
    d.text((2, 28), f"Config: {preset['name']}", font=font_obj, fill="#FFAA00")
    pins_str = ", ".join(str(p) for p in preset["pins"])
    d.text((2, 38), f"Pins: {pins_str}", font=font_obj, fill="#888")

    # Stats
    d.text((2, 52), f"Triggers: {count}", font=font_obj, fill="#AAAAAA")
    if last_t:
        d.text((2, 62), f"Last: {last_t}", font=font_obj, fill="#AAAAAA")

    # Event log (last few entries)
    d.text((2, 76), "Events:", font=font_obj, fill="#666")
    visible = log[-(ROWS_VISIBLE):]
    if scroll > 0:
        start = max(0, len(log) - ROWS_VISIBLE - scroll)
        visible = log[start:start + ROWS_VISIBLE]

    for i, entry in enumerate(visible):
        y = 88 + i * ROW_H
        if y > 108:
            break
        d.text((2, y), entry[:24], font=font_obj, fill="#CCCCCC")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if is_armed:
        d.text((2, 117), "OK:Disarm K1:Test K3:X", font=font_obj, fill="#888")
    else:
        d.text((2, 117), "OK:Arm K2:Cfg K3:Quit", font=font_obj, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, armed, preset_idx, scroll, status_msg, flash_alert

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font_obj = scaled_font()

    _load_config()

    # Setup sensor pins for initial preset
    _setup_sensor_pins(PIN_PRESETS[preset_idx])
    _setup_buzzer()

    # Start monitoring thread
    threading.Thread(target=_monitor_thread, daemon=True).start()

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK":
                armed = not armed
                with lock:
                    status_msg = "ARMED" if armed else "Disarmed"
                time.sleep(0.3)

            elif btn == "KEY1":
                # Test alarm
                flash_alert = True
                _add_event("TEST", 0)
                threading.Thread(
                    target=_buzz_alert, args=(0.5,), daemon=True
                ).start()
                time.sleep(0.3)

            elif btn == "KEY2" and not armed:
                preset_idx = (preset_idx + 1) % len(PIN_PRESETS)
                _setup_sensor_pins(PIN_PRESETS[preset_idx])
                time.sleep(0.3)

            elif btn == "UP":
                scroll = min(scroll + 1, max(0, len(event_log) - ROWS_VISIBLE))
                time.sleep(0.15)

            elif btn == "DOWN":
                scroll = max(0, scroll - 1)
                time.sleep(0.15)

            _draw_frame(lcd, font_obj)
            time.sleep(0.05)

    finally:
        _running = False
        armed = False
        try:
            GPIO.output(BUZZER_PIN, GPIO.LOW)
        except Exception:
            pass
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
