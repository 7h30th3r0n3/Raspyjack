#!/usr/bin/env python3
"""
RaspyJack Payload -- Button Combo Actions
===========================================
Author: 7h30th3r0n3

Configurable button combo to action mapping.  Detects simultaneous
button presses and triggers assigned shell commands.

Setup / Prerequisites
---------------------
- RaspyJack base system with LCD hat.

Controls
--------
  UP / DOWN   -- Navigate combo list / character picker
  OK          -- Edit selected combo command (character picker)
  KEY1        -- Backspace (in edit mode)
  KEY2        -- Confirm edit / toggle monitoring
  KEY3        -- Exit / Back

Config: /root/Raspyjack/loot/ButtonCombo/config.json
"""

import os
import sys
import time
import json
import subprocess
import threading

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button, get_held_buttons

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

LOOT_DIR = "/root/Raspyjack/loot/ButtonCombo"
CONFIG_PATH = os.path.join(LOOT_DIR, "config.json")
DEBOUNCE = 0.22
ROW_H = 12
CHARSET = list("abcdefghijklmnopqrstuvwxyz0123456789 -_./|&;")

DEFAULT_COMBOS = [
    {"combo": "KEY1+KEY2", "action": "scrot /tmp/rj_screenshot.png"},
    {"combo": "UP+DOWN", "action": "airmon-ng check kill"},
    {"combo": "LEFT+RIGHT", "action": "nmap -sn 192.168.1.0/24"},
]

lock = threading.Lock()
_monitoring = False
_last_trigger = ""


def _load_config():
    """Load combo config from disk."""
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as fh:
                data = json.load(fh)
            if isinstance(data, list):
                return data
        except (json.JSONDecodeError, OSError):
            pass
    return [dict(c) for c in DEFAULT_COMBOS]


def _save_config(combos):
    """Persist combo config to disk."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    try:
        with open(CONFIG_PATH, "w") as fh:
            json.dump(combos, fh, indent=2)
    except OSError:
        pass


def _run_action(cmd):
    """Run a combo action in background."""
    global _last_trigger
    try:
        subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with lock:
            _last_trigger = f"Ran: {cmd[:16]}"
    except OSError as exc:
        with lock:
            _last_trigger = f"Err: {str(exc)[:14]}"


def _check_combo(combo_str):
    """Check if a combo's buttons are currently pressed."""
    parts = [p.strip() for p in combo_str.split("+")]
    held = get_held_buttons()
    if held:
        return all(p in held for p in parts)
    # Fallback: check GPIO directly for two-button combos
    for p in parts:
        pin = PINS.get(p)
        if pin is None or GPIO.input(pin) != 0:
            return False
    return True


def _draw_header(d, title):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title[:20], font=font, fill="#00ccff")


def _draw_footer(d, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:26], font=font, fill="#666")


def _draw_list(combos, cursor, scroll, monitoring, trigger_msg):
    """Draw the combo list."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "BUTTON COMBOS")

    mon_color = "#00ff00" if monitoring else "#ff4444"
    d.ellipse((118, 3, 124, 9), fill=mon_color)

    y = 16
    visible = 6
    end = min(len(combos), scroll + visible)
    for i in range(scroll, end):
        c = combos[i]
        is_sel = i == cursor
        color = "#ffff00" if is_sel else "#ccc"
        prefix = ">" if is_sel else " "
        d.text((2, y), f"{prefix}{c['combo']}", font=font, fill=color)
        y += ROW_H
        cmd_preview = c["action"][:20] if c["action"] else "(empty)"
        d.text((10, y), cmd_preview, font=font, fill="#888")
        y += ROW_H

    if trigger_msg:
        d.text((2, 104), trigger_msg[:22], font=font, fill="#ffaa00")

    _draw_footer(d, "OK:edit K2:mon KEY3:ex")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_edit(combo_name, cmd_chars, char_idx):
    """Draw the command character picker."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, f"EDIT: {combo_name}")

    d.text((2, 18), "Command:", font=font, fill="#aaa")
    d.text((2, 30), "".join(cmd_chars)[:20] + "_", font=font, fill="#ffffff")

    current = CHARSET[char_idx]
    d.text((2, 50), f"Char: [ {current} ]", font=font, fill="#00ff00")

    prev_idx = (char_idx - 1) % len(CHARSET)
    next_idx = (char_idx + 1) % len(CHARSET)
    d.text((2, 62), f"  UP: {CHARSET[prev_idx]}  DN: {CHARSET[next_idx]}", font=font, fill="#555")

    d.text((2, 80), "OK: add char", font=font, fill="#666")
    d.text((2, 92), "KEY1: backspace", font=font, fill="#666")

    _draw_footer(d, "KEY2:save KEY3:cancel")
    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global _monitoring, _last_trigger
    combos = _load_config()
    cursor = 0
    scroll = 0
    view = "list"  # list | edit
    cmd_chars = []
    char_idx = 0
    last_press = 0.0
    combo_cooldown = {}

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if btn == "KEY3":
                if view == "edit":
                    view = "list"
                    btn = None
                else:
                    break

            if view == "list":
                if btn == "UP":
                    cursor = max(0, cursor - 1)
                    if cursor < scroll:
                        scroll = cursor
                elif btn == "DOWN":
                    cursor = min(len(combos) - 1, cursor + 1)
                    if cursor >= scroll + 6:
                        scroll = cursor - 5
                elif btn == "OK" and 0 <= cursor < len(combos):
                    cmd_chars = list(combos[cursor]["action"])
                    char_idx = 0
                    view = "edit"
                elif btn == "KEY2":
                    _monitoring = not _monitoring

                # Check combos in monitoring mode
                if _monitoring:
                    for c in combos:
                        combo_key = c["combo"]
                        if _check_combo(combo_key):
                            last_t = combo_cooldown.get(combo_key, 0)
                            if now - last_t > 2.0:
                                combo_cooldown = {**combo_cooldown, combo_key: now}
                                if c["action"]:
                                    threading.Thread(
                                        target=_run_action, args=(c["action"],), daemon=True,
                                    ).start()

                with lock:
                    trigger = _last_trigger
                _draw_list(combos, cursor, scroll, _monitoring, trigger)

            elif view == "edit":
                if btn == "UP":
                    char_idx = (char_idx - 1) % len(CHARSET)
                elif btn == "DOWN":
                    char_idx = (char_idx + 1) % len(CHARSET)
                elif btn == "OK":
                    cmd_chars = cmd_chars + [CHARSET[char_idx]]
                elif btn == "KEY1":
                    if cmd_chars:
                        cmd_chars = cmd_chars[:-1]
                elif btn == "KEY2":
                    new_action = "".join(cmd_chars).strip()
                    updated = [dict(c) for c in combos]
                    updated[cursor] = {**updated[cursor], "action": new_action}
                    combos = updated
                    _save_config(combos)
                    view = "list"

                if view == "edit":
                    _draw_edit(combos[cursor]["combo"], cmd_chars, char_idx)

            time.sleep(0.08)

    finally:
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
