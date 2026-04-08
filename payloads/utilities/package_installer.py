#!/usr/bin/env python3
"""
RaspyJack Payload -- Package Installer
========================================
Author: 7h30th3r0n3

Install apt or pip packages directly from the LCD interface.
Uses a character picker for package name input, shows install
output scrollable on screen.

Controls
--------
  UP / DOWN   -- Character picker / scroll output
  LEFT/RIGHT  -- Move cursor in character picker
  OK          -- Add character / start install
  KEY1        -- Show installed package count
  KEY2        -- Toggle apt / pip mode
  KEY3        -- Exit / Back
"""

import os
import sys
import time
import signal
import subprocess
import threading

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
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROW_H = 12
DEBOUNCE = 0.22
CHARSET = list(
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-_.+"
)

_running = True
_install_lock = threading.Lock()
_install_output = []
_installing = False


def _cleanup(*_args):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# Package operations
# ---------------------------------------------------------------------------

def _count_installed(pkg_mode):
    """Count installed packages for apt or pip."""
    try:
        if pkg_mode == "apt":
            result = subprocess.run(
                ["dpkg", "--get-selections"],
                capture_output=True, text=True, timeout=15,
            )
            lines = [l for l in result.stdout.splitlines() if "install" in l]
            return len(lines)
        else:
            result = subprocess.run(
                ["pip3", "list", "--format=columns"],
                capture_output=True, text=True, timeout=15,
            )
            # Subtract header lines
            return max(0, len(result.stdout.splitlines()) - 2)
    except (subprocess.TimeoutExpired, OSError):
        return -1


def _install_package(pkg_name, pkg_mode):
    """Install a package in background, capturing output."""
    global _installing, _install_output

    with _install_lock:
        _installing = True
        _install_output = ["Installing " + pkg_name + "..."]

    if pkg_mode == "apt":
        cmd = ["apt-get", "install", "-y", pkg_name]
    else:
        cmd = ["pip3", "install", pkg_name]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in proc.stdout:
            stripped = line.rstrip()[:40]
            if stripped:
                with _install_lock:
                    _install_output = _install_output + [stripped]
        proc.wait(timeout=120)
        rc = proc.returncode
        with _install_lock:
            if rc == 0:
                _install_output = _install_output + ["", "OK: Install complete!"]
            else:
                _install_output = _install_output + ["", "FAIL: exit " + str(rc)]
    except (subprocess.TimeoutExpired, OSError) as exc:
        with _install_lock:
            _install_output = _install_output + ["Err: " + str(exc)[:30]]

    with _install_lock:
        _installing = False


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_input(lcd, fnt, pkg_chars, char_idx, pkg_mode, status):
    """Draw the package name input screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    mode_label = "APT" if pkg_mode == "apt" else "PIP"
    d.text((2, 1), "PKG INSTALL [" + mode_label + "]", font=fnt, fill="#00CCFF")

    # Package name
    d.text((2, 18), "Package:", font=fnt, fill="#AAA")
    name_str = "".join(pkg_chars)
    if len(name_str) > 18:
        name_str = name_str[-18:]
    d.text((2, 30), name_str + "_", font=fnt, fill="#FFFFFF")

    # Character picker
    current = CHARSET[char_idx]
    d.text((2, 48), "Char: [ " + current + " ]", font=fnt, fill="#00FF00")

    prev_idx = (char_idx - 1) % len(CHARSET)
    next_idx = (char_idx + 1) % len(CHARSET)
    d.text((2, 60), "  UP:" + CHARSET[prev_idx] + "  DN:" + CHARSET[next_idx],
           font=fnt, fill="#555")

    # Instructions
    d.text((2, 78), "OK:add RIGHT:install", font=fnt, fill="#666")
    d.text((2, 90), "LEFT:backspace", font=fnt, fill="#666")
    d.text((2, 102), "K2:apt/pip K1:count", font=fnt, fill="#666")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if status:
        d.text((2, 117), status[:22], font=fnt, fill="#FFFF00")
    else:
        d.text((2, 117), "KEY3: exit", font=fnt, fill="#AAA")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_output(lcd, fnt, lines, scroll, installing, pkg_mode):
    """Draw the install output screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    mode_label = "APT" if pkg_mode == "apt" else "PIP"
    title = "INSTALLING [" + mode_label + "]" if installing else "OUTPUT [" + mode_label + "]"
    d.text((2, 1), title, font=fnt, fill="#00CCFF")

    if installing:
        d.ellipse((118, 3, 124, 9), fill="#FFAA00")

    # Output lines
    visible = 8
    y = 16
    end = min(len(lines), scroll + visible)
    for idx in range(scroll, end):
        line = lines[idx][:22]
        color = "#00FF00" if "OK" in line else "#CCCCCC"
        if "FAIL" in line or "Err" in line:
            color = "#FF4444"
        d.text((2, y), line, font=fnt, fill=color)
        y += ROW_H

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if installing:
        d.text((2, 117), "Installing...", font=fnt, fill="#FFAA00")
    else:
        d.text((2, 117), "KEY3: back to input", font=fnt, fill="#AAA")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_count(lcd, fnt, count, pkg_mode):
    """Draw the installed package count screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "PACKAGE STATS", font=fnt, fill="#00CCFF")

    mode_label = "APT" if pkg_mode == "apt" else "PIP"
    d.text((10, 35), mode_label + " packages:", font=fnt, fill="#AAA")

    if count < 0:
        d.text((10, 55), "Error reading", font=fnt, fill="#FF4444")
    else:
        d.text((10, 55), str(count) + " installed", font=fnt, fill="#00FF00")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "Any key: back", font=fnt, fill="#AAA")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    fnt = scaled_font()

    pkg_chars = []
    char_idx = 0
    pkg_mode = "apt"  # "apt" or "pip"
    status = ""
    last_press = 0.0
    scroll = 0
    view = "input"  # input | output | count

    try:
        while _running:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if view == "count":
                if btn:
                    view = "input"
                    time.sleep(0.1)
                    continue
                time.sleep(0.08)
                continue

            if view == "output":
                with _install_lock:
                    lines = list(_install_output)
                    busy = _installing

                if btn == "KEY3" and not busy:
                    view = "input"
                    status = ""
                    time.sleep(0.1)
                    continue
                elif btn == "UP":
                    scroll = max(0, scroll - 1)
                elif btn == "DOWN":
                    max_scroll = max(0, len(lines) - 8)
                    scroll = min(scroll + 1, max_scroll)

                # Auto-scroll while installing
                if busy:
                    scroll = max(0, len(lines) - 8)

                _draw_output(lcd, fnt, lines, scroll, busy, pkg_mode)
                time.sleep(0.12)
                continue

            # Input view
            if btn == "KEY3":
                break
            elif btn == "UP":
                char_idx = (char_idx - 1) % len(CHARSET)
            elif btn == "DOWN":
                char_idx = (char_idx + 1) % len(CHARSET)
            elif btn == "OK":
                pkg_chars = pkg_chars + [CHARSET[char_idx]]
                status = ""
            elif btn == "LEFT":
                if pkg_chars:
                    pkg_chars = pkg_chars[:-1]
                status = ""
            elif btn == "RIGHT":
                pkg_name = "".join(pkg_chars).strip()
                if not pkg_name:
                    status = "Enter a name first"
                else:
                    scroll = 0
                    view = "output"
                    threading.Thread(
                        target=_install_package,
                        args=(pkg_name, pkg_mode),
                        daemon=True,
                    ).start()
                    time.sleep(0.1)
                    continue
            elif btn == "KEY2":
                pkg_mode = "pip" if pkg_mode == "apt" else "apt"
                status = "Mode: " + pkg_mode
            elif btn == "KEY1":
                status = "Counting..."
                _draw_input(lcd, fnt, pkg_chars, char_idx, pkg_mode, status)
                count = _count_installed(pkg_mode)
                _draw_count(lcd, fnt, count, pkg_mode)
                view = "count"
                time.sleep(0.1)
                continue

            _draw_input(lcd, fnt, pkg_chars, char_idx, pkg_mode, status)
            time.sleep(0.08)

    finally:
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
