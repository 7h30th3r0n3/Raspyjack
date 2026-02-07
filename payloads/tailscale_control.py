#!/usr/bin/env python3
"""
===============================================================================
 RaspyJack Payload — Tailscale Control & Status
===============================================================================

PURPOSE
-------
This payload allows you to control and monitor Tailscale directly from the
RaspyJack 1.44" LCD screen using the physical buttons.

It is designed for:
- fast and encrypted out-of-band remote access
- enabling SSH over Tailscale
- safely disabling the tunnel when needed

-------------------------------------------------------------------------------
USAGE (BUTTON MAPPING)
-------------------------------------------------------------------------------
KEY1  →  tailscale up
         - brings the Tailscale interface up
         - automatically enables: tailscale SSH

KEY2  →  tailscale down
         - shuts down the Tailscale interface

KEY3  →  exit the payload cleanly

-------------------------------------------------------------------------------
LCD DISPLAY
-------------------------------------------------------------------------------
- daemon : tailscaled process status (on/off)
- state  : Tailscale BackendState (Running, Stopped, NeedsLogin, ...)
- ip     : assigned Tailscale IPv4 address

A short status message is displayed after each action (UP / DOWN).

-------------------------------------------------------------------------------
REQUIREMENTS
-------------------------------------------------------------------------------
- Tailscale installed on the system

Install Tailscale:
    curl -fsSL https://tailscale.com/install.sh | sh

Initial login (one-time setup):
    sudo tailscale up

-------------------------------------------------------------------------------
OPERATIONAL NOTES
-------------------------------------------------------------------------------
- No interactive login is performed by this payload
- Authentication must be completed beforehand
- Intended for Red Team / lab / emergency access only
- No credentials, tokens, or secrets are stored locally
===============================================================================
"""

import os
import sys
import time
import json
import shutil
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

import RPi.GPIO as GPIO  # type: ignore
import LCD_1in44, LCD_Config  # type: ignore
from PIL import Image, ImageDraw, ImageFont  # type: ignore

WIDTH, HEIGHT = 128, 128

PINS = {
    "KEY1": 21,
    "KEY2": 20,
    "KEY3": 16,
}

REFRESH = 0.6


def _run(cmd, timeout=3):
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return res.returncode, (res.stdout or "").strip(), (res.stderr or "").strip()
    except Exception as exc:
        return 1, "", str(exc)


def _tailscale_installed():
    return shutil.which("tailscale") is not None


def _daemon_running():
    rc, _, _ = _run(["pgrep", "-x", "tailscaled"])
    return rc == 0


def _get_ip():
    rc, out, _ = _run(["tailscale", "ip", "-4"])
    if rc != 0:
        return "-"
    line = out.splitlines()[0].strip() if out else "-"
    return line or "-"


def _get_status():
    rc, out, _ = _run(["tailscale", "status", "--json"])
    if rc != 0:
        return "down"
    try:
        data = json.loads(out)
        return data.get("BackendState", "unknown")
    except Exception:
        return "unknown"


def _truncate(s, n):
    if s is None:
        return ""
    return s if len(s) <= n else s[: n - 1] + "~"


def draw(lcd, lines, message=""):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    font = ImageFont.load_default()

    d.rectangle((0, 0, 127, 12), fill="#1a1a1a")
    d.text((4, 1), "Tailscale", font=font, fill="white")
    d.text((84, 1), "1UP 2DN", font=font, fill="white")

    y = 16
    for line in lines:
        d.text((4, y), _truncate(line, 20), font=font, fill="white")
        y += 12

    if message:
        d.rectangle((0, 112, 127, 127), fill="#1a1a1a")
        d.text((2, 115), _truncate(message, 21), font=font, fill="white")

    lcd.LCD_ShowImage(img, 0, 0)

def draw_error(lcd, title, lines):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    font = ImageFont.load_default()

    d.rectangle((0, 0, 127, 12), fill="#1a1a1a")
    d.text((4, 1), _truncate(title, 16), font=font, fill="white")

    y = 18
    for line in lines:
        d.text((4, y), _truncate(line, 20), font=font, fill="white")
        y += 12

    d.rectangle((0, 112, 127, 127), fill="#1a1a1a")
    d.text((2, 115), "KEY3 exit", font=font, fill="white")
    lcd.LCD_ShowImage(img, 0, 0)


def main():
    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    if not _tailscale_installed():
        draw_error(
            lcd,
            "Error",
            ["Tailscale missing", "Download:", "tailscale.com"],
        )
        while GPIO.input(PINS["KEY3"]) != 0:
            time.sleep(0.1)
        lcd.LCD_Clear()
        GPIO.cleanup()
        return

    last_msg = ""
    last_msg_at = 0.0

    try:
        while True:
            if GPIO.input(PINS["KEY3"]) == 0:
                break

            if GPIO.input(PINS["KEY1"]) == 0:
                if _tailscale_installed():
                    rc, out, err = _run(["tailscale", "up"], timeout=8)
                    msg = out.splitlines()[0] if out else err.splitlines()[0] if err else "ok"
                    last_msg = _truncate(msg, 21)
                    if rc == 0:
                        _run(["tailscale", "set", "--ssh"])
                else:
                    last_msg = "tailscale missing"
                last_msg_at = time.time()
                time.sleep(0.25)

            if GPIO.input(PINS["KEY2"]) == 0:
                if _tailscale_installed():
                    rc, out, err = _run(["tailscale", "down"])
                    msg = out.splitlines()[0] if out else err.splitlines()[0] if err else "ok"
                    last_msg = _truncate(msg, 21)
                else:
                    last_msg = "tailscale missing"
                last_msg_at = time.time()
                time.sleep(0.25)

            lines = [
                f"daemon: {'on' if _daemon_running() else 'off'}",
                f"state: {_get_status()}",
                f"ip: {_get_ip()}",
            ]

            msg = last_msg if (time.time() - last_msg_at) < 4 else "KEY3 exit"
            draw(lcd, lines, msg)
            time.sleep(REFRESH)
    finally:
        lcd.LCD_Clear()
        GPIO.cleanup()


if __name__ == "__main__":
    main()