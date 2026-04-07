#!/usr/bin/env python3
"""
RaspyJack Payload -- LTE/4G Modem Configuration
=================================================
Author: 7h30th3r0n3

Detects and configures LTE/4G modems via ModemManager (mmcli).
Shows modem info, signal strength, and connection status.
Allows APN configuration and connect/disconnect operations.

Setup / Prerequisites
---------------------
- LTE/4G USB modem (Huawei, Quectel, Sierra, etc.)
- ModemManager installed (apt install modemmanager)

Controls
--------
  UP / DOWN   -- Navigate menu / character picker
  OK          -- Select menu item / add character
  KEY1        -- Backspace (in APN input)
  KEY2        -- Confirm APN input
  KEY3        -- Exit / Back

Loot: /root/Raspyjack/loot/LTE/
"""

import os
import sys
import time
import json
import subprocess
import threading

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

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

LOOT_DIR = "/root/Raspyjack/loot/LTE"
CONFIG_PATH = os.path.join(LOOT_DIR, "config.json")
DEBOUNCE = 0.20
ROW_H = 12
CHARSET = list("abcdefghijklmnopqrstuvwxyz0123456789.-_/ ")

MENU_ITEMS = ["Show Status", "Set APN", "Connect", "Disconnect"]

lock = threading.Lock()


def _run_cmd(cmd, timeout=10):
    """Run a shell command and return stdout or error string."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout.strip() if result.returncode == 0 else result.stderr.strip()
    except subprocess.TimeoutExpired:
        return "Timeout"
    except OSError as exc:
        return str(exc)


def _load_config():
    """Load saved config, return new dict if missing."""
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            pass
    return {"apn": "", "modem_idx": 0}


def _save_config(cfg):
    """Persist config to disk."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    try:
        with open(CONFIG_PATH, "w") as fh:
            json.dump(cfg, fh, indent=2)
    except OSError:
        pass


def _detect_modem():
    """Detect modem via mmcli -L, return modem index or -1."""
    out = _run_cmd(["mmcli", "-L"])
    if "ModemManager" not in out and "/Modem/" not in out:
        return -1, "No modem found"
    for line in out.splitlines():
        if "/Modem/" in line:
            try:
                idx = int(line.split("/Modem/")[1].split()[0].rstrip("]"))
                model = line.split("[")[-1].rstrip("]") if "[" in line else "Unknown"
                return idx, model
            except (ValueError, IndexError):
                continue
    return -1, "Parse error"


def _get_modem_info(idx):
    """Fetch modem status details."""
    out = _run_cmd(["mmcli", "-m", str(idx)])
    info = {
        "state": "unknown", "signal": 0, "operator": "N/A",
        "ip": "N/A", "access_tech": "N/A",
    }
    for line in out.splitlines():
        stripped = line.strip()
        if "state:" in stripped.lower():
            info["state"] = stripped.split(":", 1)[1].strip()
        elif "signal quality:" in stripped.lower():
            try:
                info["signal"] = int(stripped.split(":", 1)[1].strip().split("%")[0].strip())
            except ValueError:
                pass
        elif "operator name:" in stripped.lower():
            info["operator"] = stripped.split(":", 1)[1].strip()
        elif "address:" in stripped.lower() and "bearer" not in stripped.lower():
            val = stripped.split(":", 1)[1].strip()
            if val and val != "--":
                info["ip"] = val
        elif "access technologies:" in stripped.lower():
            info["access_tech"] = stripped.split(":", 1)[1].strip()
    return info


def _signal_bars(pct):
    """Return a visual signal bar string from percentage."""
    filled = min(5, pct // 20)
    return "|" * filled + "." * (5 - filled)


def _draw_header(d, title):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title[:20], font=font, fill="#00ccff")


def _draw_footer(d, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:26], font=font, fill="#666")


def _draw_status(modem_idx, model, info):
    """Draw modem status screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "LTE STATUS")

    y = 16
    d.text((2, y), f"Model: {model[:18]}", font=font, fill="#ffaa00"); y += ROW_H
    d.text((2, y), f"State: {info['state'][:16]}", font=font, fill="#00ff00"); y += ROW_H
    bars = _signal_bars(info["signal"])
    d.text((2, y), f"Signal: {bars} {info['signal']}%", font=font, fill="#ccc"); y += ROW_H
    d.text((2, y), f"Op: {info['operator'][:18]}", font=font, fill="#ccc"); y += ROW_H
    d.text((2, y), f"Tech: {info['access_tech'][:16]}", font=font, fill="#888"); y += ROW_H
    d.text((2, y), f"IP: {info['ip'][:18]}", font=font, fill="#888"); y += ROW_H

    _draw_footer(d, "KEY3:back")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_menu(cursor, cfg, status_msg):
    """Draw the main menu."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "LTE CONFIGURE")

    y = 16
    d.text((2, y), status_msg[:22], font=font, fill="#ffaa00"); y += ROW_H + 2

    apn_label = cfg.get("apn", "") or "(not set)"
    d.text((2, y), f"APN: {apn_label[:18]}", font=font, fill="#888"); y += ROW_H + 2

    for i, item in enumerate(MENU_ITEMS):
        color = "#ffff00" if i == cursor else "#ccc"
        prefix = ">" if i == cursor else " "
        d.text((2, y), f"{prefix} {item}", font=font, fill=color)
        y += ROW_H

    _draw_footer(d, "OK:select KEY3:exit")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_apn_input(chars, char_idx):
    """Draw the APN character picker."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "SET APN")

    d.text((2, 18), "APN:", font=font, fill="#aaa")
    d.text((2, 30), "".join(chars)[:20] + "_", font=font, fill="#ffffff")

    current = CHARSET[char_idx]
    d.text((2, 50), f"Char: [ {current} ]", font=font, fill="#00ff00")

    prev_idx = (char_idx - 1) % len(CHARSET)
    next_idx = (char_idx + 1) % len(CHARSET)
    d.text((2, 62), f"  UP: {CHARSET[prev_idx]}  DN: {CHARSET[next_idx]}", font=font, fill="#555")

    d.text((2, 80), "OK: add char", font=font, fill="#666")
    d.text((2, 92), "KEY1: backspace", font=font, fill="#666")

    _draw_footer(d, "KEY2:confirm KEY3:cancel")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_connecting(msg):
    """Draw a simple connecting/disconnecting message."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "LTE CONFIGURE")
    d.text((4, 55), msg[:22], font=font, fill="#ffaa00")
    _draw_footer(d, "Please wait...")
    LCD.LCD_ShowImage(img, 0, 0)


def main():
    cfg = _load_config()
    modem_idx, model = _detect_modem()
    status_msg = f"Modem: {model[:16]}" if modem_idx >= 0 else "No modem detected"
    cursor = 0
    view = "menu"  # menu | status | apn_input
    apn_chars = []
    char_idx = 0
    last_press = 0.0

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if btn == "KEY3":
                if view in ("status", "apn_input"):
                    view = "menu"
                    btn = None
                else:
                    break

            if view == "menu":
                if btn == "UP":
                    cursor = max(0, cursor - 1)
                elif btn == "DOWN":
                    cursor = min(len(MENU_ITEMS) - 1, cursor + 1)
                elif btn == "OK":
                    selected = MENU_ITEMS[cursor]
                    if selected == "Show Status":
                        if modem_idx >= 0:
                            view = "status"
                        else:
                            modem_idx, model = _detect_modem()
                            status_msg = f"Modem: {model[:16]}" if modem_idx >= 0 else "No modem"
                    elif selected == "Set APN":
                        apn_chars = list(cfg.get("apn", ""))
                        char_idx = 0
                        view = "apn_input"
                    elif selected == "Connect":
                        if modem_idx >= 0:
                            apn = cfg.get("apn", "")
                            if apn:
                                _draw_connecting("Connecting...")
                                out = _run_cmd([
                                    "mmcli", "-m", str(modem_idx),
                                    f"--simple-connect=apn={apn}",
                                ], timeout=30)
                                status_msg = "Connected" if "success" in out.lower() else out[:20]
                            else:
                                status_msg = "Set APN first"
                        else:
                            status_msg = "No modem"
                    elif selected == "Disconnect":
                        if modem_idx >= 0:
                            _draw_connecting("Disconnecting...")
                            out = _run_cmd([
                                "mmcli", "-m", str(modem_idx),
                                "--simple-disconnect",
                            ], timeout=15)
                            status_msg = "Disconnected" if "success" in out.lower() else out[:20]
                        else:
                            status_msg = "No modem"

                _draw_menu(cursor, cfg, status_msg)

            elif view == "status":
                info = _get_modem_info(modem_idx) if modem_idx >= 0 else {}
                _draw_status(modem_idx, model, info)
                time.sleep(1.0)

            elif view == "apn_input":
                if btn == "UP":
                    char_idx = (char_idx - 1) % len(CHARSET)
                elif btn == "DOWN":
                    char_idx = (char_idx + 1) % len(CHARSET)
                elif btn == "OK":
                    apn_chars = apn_chars + [CHARSET[char_idx]]
                elif btn == "KEY1":
                    if apn_chars:
                        apn_chars = apn_chars[:-1]
                elif btn == "KEY2":
                    new_apn = "".join(apn_chars).strip()
                    cfg = {**cfg, "apn": new_apn}
                    _save_config(cfg)
                    status_msg = f"APN: {new_apn[:14]}"
                    view = "menu"

                if view == "apn_input":
                    _draw_apn_input(apn_chars, char_idx)

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
