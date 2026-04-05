#!/usr/bin/env python3
"""
RaspyJack Payload -- LED Controller
=====================================
Author: 7h30th3r0n3

Pi LED controller for operational feedback.  Controls the ACT (activity)
and PWR (power) LEDs via sysfs with predefined blink patterns and a
custom timing editor.

Setup / Prerequisites
---------------------
- Raspberry Pi with accessible LED sysfs entries:
    /sys/class/leds/ACT/brightness
    /sys/class/leds/PWR/brightness
- Must run as root to write to LED sysfs.
- Some Pi models use 'led0'/'led1' instead of 'ACT'/'PWR'.

Controls
--------
  UP / DOWN  -- Cycle through patterns
  OK         -- Apply selected pattern
  KEY1       -- Toggle ACT LED independently
  KEY2       -- Toggle PWR LED independently
  KEY3       -- Exit (restores default trigger)
"""

import os
import sys
import time
import threading

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
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

DEBOUNCE = 0.22
lock = threading.Lock()
_running = True

# ---------------------------------------------------------------------------
# LED sysfs paths -- try common names
# ---------------------------------------------------------------------------

_LED_CANDIDATES = {
    "ACT": [
        "/sys/class/leds/ACT",
        "/sys/class/leds/led0",
        "/sys/class/leds/default-on",
    ],
    "PWR": [
        "/sys/class/leds/PWR",
        "/sys/class/leds/led1",
        "/sys/class/leds/input0::scrolllock",
    ],
}


def _find_led_path(name):
    """Find a working sysfs LED path."""
    for candidate in _LED_CANDIDATES.get(name, []):
        brightness = os.path.join(candidate, "brightness")
        if os.path.exists(brightness):
            return candidate
    return None


ACT_PATH = _find_led_path("ACT")
PWR_PATH = _find_led_path("PWR")


def _led_set(led_path, value):
    """Write brightness value (0 or 1) to an LED."""
    if led_path is None:
        return
    bpath = os.path.join(led_path, "brightness")
    try:
        with open(bpath, "w") as fh:
            fh.write(str(value))
    except OSError:
        pass


def _led_get(led_path):
    """Read current brightness from an LED."""
    if led_path is None:
        return 0
    bpath = os.path.join(led_path, "brightness")
    try:
        with open(bpath, "r") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return 0


def _led_set_trigger(led_path, trigger):
    """Set the LED trigger (e.g., 'mmc0', 'default-on', 'none')."""
    if led_path is None:
        return
    tpath = os.path.join(led_path, "trigger")
    try:
        with open(tpath, "w") as fh:
            fh.write(trigger)
    except OSError:
        pass


def _led_get_trigger(led_path):
    """Read the current trigger, returning the [active] one."""
    if led_path is None:
        return "none"
    tpath = os.path.join(led_path, "trigger")
    try:
        with open(tpath, "r") as fh:
            content = fh.read()
        for part in content.split():
            if part.startswith("[") and part.endswith("]"):
                return part[1:-1]
    except OSError:
        pass
    return "none"


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

PATTERNS = [
    {"name": "Idle",     "desc": "Slow pulse",         "act": [(0.5, 1), (0.5, 0)],           "pwr": [(0.5, 1), (0.5, 0)]},
    {"name": "Scanning", "desc": "Fast blink",          "act": [(0.1, 1), (0.1, 0)],           "pwr": [(0.1, 1), (0.1, 0)]},
    {"name": "Attacking","desc": "Solid on",            "act": [(1.0, 1)],                     "pwr": [(1.0, 1)]},
    {"name": "Alert",    "desc": "Rapid triple-blink",  "act": [(0.08, 1), (0.08, 0), (0.08, 1), (0.08, 0), (0.08, 1), (0.5, 0)], "pwr": [(0.08, 1), (0.08, 0), (0.08, 1), (0.08, 0), (0.08, 1), (0.5, 0)]},
    {"name": "Stealth",  "desc": "All off",             "act": [(1.0, 0)],                     "pwr": [(1.0, 0)]},
    {"name": "Custom",   "desc": "User-defined timing", "act": [(0.3, 1), (0.7, 0)],           "pwr": [(0.3, 1), (0.7, 0)]},
]

# Active pattern state
active_pattern_idx = 0
pattern_running = False
act_manual = None   # None=pattern-controlled, True/False=manual override
pwr_manual = None


# ---------------------------------------------------------------------------
# Pattern playback thread
# ---------------------------------------------------------------------------

def _pattern_thread():
    """Continuously play the active LED pattern."""
    global pattern_running
    pattern_running = True

    while _running and pattern_running:
        with lock:
            pat = PATTERNS[active_pattern_idx]
            a_manual = act_manual
            p_manual = pwr_manual

        act_steps = pat["act"]
        pwr_steps = pat["pwr"]
        max_steps = max(len(act_steps), len(pwr_steps))

        for step_idx in range(max_steps):
            if not _running or not pattern_running:
                return

            # ACT LED
            if a_manual is None and step_idx < len(act_steps):
                duration, value = act_steps[step_idx]
                _led_set(ACT_PATH, value)
            elif a_manual is not None:
                _led_set(ACT_PATH, 1 if a_manual else 0)

            # PWR LED
            if p_manual is None and step_idx < len(pwr_steps):
                duration, value = pwr_steps[step_idx]
                _led_set(PWR_PATH, value)
            elif p_manual is not None:
                _led_set(PWR_PATH, 1 if p_manual else 0)

            # Wait for the longer duration of the two step lists
            act_dur = act_steps[step_idx][0] if step_idx < len(act_steps) else 0
            pwr_dur = pwr_steps[step_idx][0] if step_idx < len(pwr_steps) else 0
            wait = max(act_dur, pwr_dur)

            deadline = time.time() + wait
            while _running and pattern_running and time.time() < deadline:
                time.sleep(0.02)


_pattern_thread_ref = None


def _start_pattern():
    """Launch the pattern playback thread."""
    global _pattern_thread_ref, pattern_running
    _stop_pattern()
    pattern_running = True
    _pattern_thread_ref = threading.Thread(target=_pattern_thread, daemon=True)
    _pattern_thread_ref.start()


def _stop_pattern():
    """Stop the current pattern thread."""
    global pattern_running
    pattern_running = False
    if _pattern_thread_ref is not None:
        _pattern_thread_ref.join(timeout=2)


# ---------------------------------------------------------------------------
# Custom pattern editing
# ---------------------------------------------------------------------------

custom_on_time = 0.3
custom_off_time = 0.7


def _update_custom_pattern():
    """Apply custom timing to the Custom pattern entry."""
    PATTERNS[-1]["act"] = [(custom_on_time, 1), (custom_off_time, 0)]
    PATTERNS[-1]["pwr"] = [(custom_on_time, 1), (custom_off_time, 0)]


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_main(lcd, cursor, editing_custom):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "LED CONTROL", font=font, fill="#00ccff")
    d.text((108, 1), "K3", font=font, fill="#888")

    y = 16

    # LED state indicators
    act_on = _led_get(ACT_PATH)
    pwr_on = _led_get(PWR_PATH)
    act_color = "#00ff00" if act_on else "#333"
    pwr_color = "#ff2222" if pwr_on else "#333"
    d.ellipse((4, y, 14, y + 10), fill=act_color)
    d.text((18, y), "ACT", font=font, fill="#aaa")
    d.ellipse((54, y, 64, y + 10), fill=pwr_color)
    d.text((68, y), "PWR", font=font, fill="#aaa")
    y += 16

    # Active pattern
    with lock:
        active_name = PATTERNS[active_pattern_idx]["name"]
    d.text((2, y), f"Active: {active_name}", font=font, fill="#ffaa00")
    y += 14

    # Pattern list
    visible = 4
    start = max(0, cursor - 1)
    end = min(len(PATTERNS), start + visible)
    for i in range(start, end):
        pat = PATTERNS[i]
        marker = ">" if i == cursor else " "
        is_active = i == active_pattern_idx
        color = "#00ff00" if is_active else ("#ffaa00" if i == cursor else "#ccc")
        d.text((2, y), f"{marker}{pat['name'][:8]} {pat['desc'][:12]}", font=font, fill=color)
        y += 12

    # Custom timing edit
    if editing_custom and cursor == len(PATTERNS) - 1:
        y += 2
        d.text((2, y), f"On: {custom_on_time:.1f}s Off: {custom_off_time:.1f}s", font=font, fill="#00ccff")
        d.text((2, y + 12), "L/R:on  ^v:off  OK:set", font=font, fill="#888")

    # Manual override indicators
    with lock:
        a_m = act_manual
        p_m = pwr_manual
    if a_m is not None or p_m is not None:
        override_y = 100
        d.text((2, override_y), "Manual override active", font=font, fill="#ff8800")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:apply K1:ACT K2:PWR", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Restore defaults
# ---------------------------------------------------------------------------

_original_act_trigger = None
_original_pwr_trigger = None


def _save_original_triggers():
    global _original_act_trigger, _original_pwr_trigger
    _original_act_trigger = _led_get_trigger(ACT_PATH)
    _original_pwr_trigger = _led_get_trigger(PWR_PATH)


def _restore_defaults():
    """Restore LED triggers to their original state."""
    _stop_pattern()
    if _original_act_trigger:
        _led_set_trigger(ACT_PATH, _original_act_trigger)
    if _original_pwr_trigger:
        _led_set_trigger(PWR_PATH, _original_pwr_trigger)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, active_pattern_idx, act_manual, pwr_manual
    global custom_on_time, custom_off_time

    _save_original_triggers()

    # Disable triggers for manual control
    _led_set_trigger(ACT_PATH, "none")
    _led_set_trigger(PWR_PATH, "none")

    cursor = 0
    last_press = 0.0
    editing_custom = False

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if btn == "KEY3":
                break

            elif btn == "UP":
                if editing_custom:
                    custom_off_time = min(5.0, custom_off_time + 0.1)
                    _update_custom_pattern()
                else:
                    cursor = max(0, cursor - 1)
                    editing_custom = cursor == len(PATTERNS) - 1

            elif btn == "DOWN":
                if editing_custom:
                    custom_off_time = max(0.05, custom_off_time - 0.1)
                    _update_custom_pattern()
                else:
                    cursor = min(len(PATTERNS) - 1, cursor + 1)
                    editing_custom = cursor == len(PATTERNS) - 1

            elif btn == "LEFT" and editing_custom:
                custom_on_time = max(0.05, custom_on_time - 0.1)
                _update_custom_pattern()

            elif btn == "RIGHT" and editing_custom:
                custom_on_time = min(5.0, custom_on_time + 0.1)
                _update_custom_pattern()

            elif btn == "OK":
                with lock:
                    active_pattern_idx = cursor
                    act_manual = None
                    pwr_manual = None
                if cursor == len(PATTERNS) - 1:
                    _update_custom_pattern()
                _start_pattern()

            elif btn == "KEY1":
                # Toggle ACT LED manually
                with lock:
                    if act_manual is None:
                        act_manual = not bool(_led_get(ACT_PATH))
                    else:
                        act_manual = not act_manual
                    _led_set(ACT_PATH, 1 if act_manual else 0)

            elif btn == "KEY2":
                # Toggle PWR LED manually
                with lock:
                    if pwr_manual is None:
                        pwr_manual = not bool(_led_get(PWR_PATH))
                    else:
                        pwr_manual = not pwr_manual
                    _led_set(PWR_PATH, 1 if pwr_manual else 0)

            _draw_main(LCD, cursor, editing_custom)
            time.sleep(0.08)

    finally:
        _running = False
        _restore_defaults()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
