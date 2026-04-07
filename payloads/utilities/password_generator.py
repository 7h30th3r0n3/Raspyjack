#!/usr/bin/env python3
"""
RaspyJack Payload -- Password Generator
=========================================
Author: 7h30th3r0n3

Generate cryptographically secure passwords with configurable length
and character sets.  Passwords can be saved to the loot directory.

Controls
--------
  UP / DOWN    -- Change password length (8-64)
  LEFT / RIGHT -- Toggle character sets (lower, upper, digits, symbols)
  KEY1         -- Generate new password
  KEY2         -- Save password to loot file
  KEY3         -- Exit
"""

import os
import sys
import time
import signal
import secrets
import string

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
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

DEBOUNCE = 0.20
ROW_H = 12
SAVE_DIR = "/root/Raspyjack/loot/Passwords"
SAVE_FILE = os.path.join(SAVE_DIR, "passwords.txt")

CHARSETS = [
    ("lower", string.ascii_lowercase),
    ("UPPER", string.ascii_uppercase),
    ("0-9", string.digits),
    ("!@#$", string.punctuation),
]

_running = True


def _cleanup(*_args):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# Password generation
# ---------------------------------------------------------------------------

def _build_alphabet(enabled):
    """Build the character pool from enabled sets."""
    pool = ""
    for i, (_, chars) in enumerate(CHARSETS):
        if enabled[i]:
            pool += chars
    return pool


def _generate_password(length, alphabet):
    """Generate a cryptographically secure password."""
    if not alphabet:
        return "(no charset)"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _save_password(password):
    """Append password to the loot file. Return status message."""
    try:
        os.makedirs(SAVE_DIR, exist_ok=True)
        with open(SAVE_FILE, "a", encoding="utf-8") as fh:
            fh.write(password + "\n")
        return "Saved!"
    except PermissionError:
        return "Permission denied"
    except OSError as exc:
        return str(exc)[:20]


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(d):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "PASSWD GEN", font=font, fill="#00ccff")
    d.text((108, 1), "K3", font=font, fill="#888")


def _draw_footer(d, message):
    d.rectangle((0, 116, 127, 127), fill="#111")
    text = message if message else "K1:gen K2:save K3:exit"
    color = "#ffaa00" if message else "#666"
    d.text((2, 117), text[:26], font=font, fill=color)


def _draw_screen(length, enabled, setting_cursor, password, status_msg):
    """Render the password generator screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d)

    y = 18

    # Length setting
    is_len_sel = setting_cursor == 0
    len_color = "#ffff00" if is_len_sel else "#ccc"
    marker = ">" if is_len_sel else " "
    d.text((2, y), f"{marker} Length: {length}", font=font, fill=len_color)
    if is_len_sel:
        d.text((90, y), "UP/DN", font=font, fill="#555")
    y += ROW_H + 2

    # Character set toggles
    for i, (label, _chars) in enumerate(CHARSETS):
        is_sel = setting_cursor == i + 1
        on = enabled[i]
        fg = "#ffff00" if is_sel else ("#00ff00" if on else "#ff4444")
        marker = ">" if is_sel else " "
        state = "ON" if on else "OFF"
        d.text((2, y), f"{marker} {label}: {state}", font=font, fill=fg)
        y += ROW_H

    y += 4

    # Alphabet size
    alphabet = _build_alphabet(enabled)
    d.text((2, y), f"Pool: {len(alphabet)} chars", font=font, fill="#888")
    y += ROW_H + 2

    # Generated password display
    if password:
        d.text((2, y), "Password:", font=font, fill="#aaa")
        y += ROW_H
        # Split long passwords across lines
        line1 = password[:20]
        line2 = password[20:40]
        line3 = password[40:60]
        d.text((2, y), line1, font=font, fill="#00ff00")
        if line2:
            y += ROW_H
            d.text((2, y), line2, font=font, fill="#00ff00")
        if line3:
            y += ROW_H
            d.text((2, y), line3, font=font, fill="#00ff00")
    else:
        d.text((2, y), "Press K1 to generate", font=font, fill="#555")

    _draw_footer(d, status_msg)
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running

    length = 16
    enabled = [True, True, True, False]  # lower, upper, digits, symbols
    setting_cursor = 0  # 0=length, 1-4=charsets
    password = ""
    status_msg = ""
    status_expire = 0.0
    last_press = 0.0
    total_settings = 1 + len(CHARSETS)

    try:
        while _running:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if now > status_expire:
                status_msg = ""

            if btn == "KEY3":
                break

            elif btn == "UP":
                if setting_cursor == 0:
                    length = min(64, length + 1)
                else:
                    setting_cursor = (setting_cursor - 1) % total_settings

            elif btn == "DOWN":
                if setting_cursor == 0:
                    length = max(8, length - 1)
                else:
                    setting_cursor = (setting_cursor + 1) % total_settings

            elif btn == "LEFT":
                setting_cursor = (setting_cursor - 1) % total_settings

            elif btn == "RIGHT":
                setting_cursor = (setting_cursor + 1) % total_settings

            elif btn == "OK":
                if setting_cursor > 0:
                    idx = setting_cursor - 1
                    new_enabled = list(enabled)
                    new_enabled[idx] = not new_enabled[idx]
                    enabled = new_enabled

            elif btn == "KEY1":
                alphabet = _build_alphabet(enabled)
                password = _generate_password(length, alphabet)
                status_msg = "Generated!" if alphabet else ""
                status_expire = now + 1.5

            elif btn == "KEY2":
                if password and password != "(no charset)":
                    msg = _save_password(password)
                    status_msg = msg
                    status_expire = now + 2.0
                else:
                    status_msg = "Generate first"
                    status_expire = now + 1.5

            _draw_screen(length, enabled, setting_cursor, password, status_msg)
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
