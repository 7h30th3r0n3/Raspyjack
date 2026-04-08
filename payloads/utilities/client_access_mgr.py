#!/usr/bin/env python3
"""
RaspyJack Payload -- Client Access Manager
============================================
Author: 7h30th3r0n3

MAC whitelist/blacklist manager for portal access.  Shows connected
clients from arp -a, allows whitelisting or blacklisting via iptables.

Controls
--------
  UP / DOWN   -- Scroll through client list
  OK          -- Whitelist selected client
  KEY1        -- Blacklist selected client
  KEY2        -- Toggle view (connected / whitelist / blacklist)
  KEY3        -- Exit
"""

import os
import sys
import time
import signal
import subprocess
import json
import re

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
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
CONFIG_DIR = "/root/Raspyjack/loot/AccessMgr"
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
DEBOUNCE = 0.25
MAC_RE = re.compile(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")

GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
font_sm = scaled_font(8)
font_md = scaled_font(10)

_running = True
VIEWS = ["Connected", "Whitelist", "Blacklist"]


def _cleanup(*_args):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# Config persistence
# ---------------------------------------------------------------------------

def _load_config():
    """Load whitelist/blacklist config from JSON."""
    default = {"whitelist": [], "blacklist": []}
    if not os.path.isfile(CONFIG_PATH):
        return dict(default)
    try:
        with open(CONFIG_PATH, "r") as fh:
            data = json.load(fh)
        return {
            "whitelist": list(data.get("whitelist", [])),
            "blacklist": list(data.get("blacklist", [])),
        }
    except (json.JSONDecodeError, OSError):
        return dict(default)


def _save_config(config):
    """Save config to JSON."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_PATH, "w") as fh:
        json.dump(config, fh, indent=2)


# ---------------------------------------------------------------------------
# ARP / network queries
# ---------------------------------------------------------------------------

def _get_connected_clients():
    """Parse arp -a for connected clients."""
    clients = []
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            match = MAC_RE.search(line)
            if match:
                mac = match.group(1).lower()
                parts = line.strip().split()
                hostname = parts[0] if parts else "?"
                ip_match = re.search(r"\(([0-9.]+)\)", line)
                ip = ip_match.group(1) if ip_match else "?"
                clients.append({"mac": mac, "ip": ip, "hostname": hostname})
    except (subprocess.SubprocessError, OSError):
        pass
    return clients


# ---------------------------------------------------------------------------
# iptables rules
# ---------------------------------------------------------------------------

def _apply_iptables_rule(mac, action):
    """Apply iptables rule for MAC. action: 'ACCEPT' or 'DROP'."""
    chain = "FORWARD"
    try:
        subprocess.run(
            ["iptables", "-D", chain, "-m", "mac", "--mac-source", mac, "-j", "ACCEPT"],
            capture_output=True, timeout=5,
        )
        subprocess.run(
            ["iptables", "-D", chain, "-m", "mac", "--mac-source", mac, "-j", "DROP"],
            capture_output=True, timeout=5,
        )
    except (subprocess.SubprocessError, OSError):
        pass

    try:
        subprocess.run(
            ["iptables", "-I", chain, "1", "-m", "mac", "--mac-source", mac, "-j", action],
            capture_output=True, timeout=5,
        )
    except (subprocess.SubprocessError, OSError):
        pass


def _whitelist_mac(mac, config):
    """Add MAC to whitelist and remove from blacklist."""
    new_wl = list(config["whitelist"])
    new_bl = [m for m in config["blacklist"] if m != mac]
    if mac not in new_wl:
        new_wl.append(mac)
    new_config = {"whitelist": new_wl, "blacklist": new_bl}
    _save_config(new_config)
    _apply_iptables_rule(mac, "ACCEPT")
    return new_config


def _blacklist_mac(mac, config):
    """Add MAC to blacklist and remove from whitelist."""
    new_bl = list(config["blacklist"])
    new_wl = [m for m in config["whitelist"] if m != mac]
    if mac not in new_bl:
        new_bl.append(mac)
    new_config = {"whitelist": new_wl, "blacklist": new_bl}
    _save_config(new_config)
    _apply_iptables_rule(mac, "DROP")
    return new_config


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(d, view_name, count):
    """Draw header bar."""
    colors = {
        "Connected": (0, 60, 80),
        "Whitelist": (0, 80, 0),
        "Blacklist": (80, 0, 0),
    }
    bg = colors.get(view_name, (40, 40, 40))
    d.rectangle([0, 0, 127, 13], fill=bg)
    d.text((2, 1), view_name, fill=(255, 255, 255), font=font_md)
    d.text((90, 1), f"({count})", fill=(180, 180, 180), font=font_md)


def _draw_footer(d, text):
    """Draw footer bar."""
    d.rectangle([0, 116, 127, 127], fill=(40, 40, 40))
    d.text((2, 117), text, fill=(180, 180, 180), font=font_sm)


def _draw_mac_list(d, items, scroll_pos, selected, view_idx, config):
    """Draw list of MAC entries."""
    y_start = 16
    visible = 8
    end = min(scroll_pos + visible, len(items))
    for i in range(scroll_pos, end):
        row_y = y_start + (i - scroll_pos) * 12
        is_selected = (i == selected)
        bg = (40, 40, 60) if is_selected else None
        if bg:
            d.rectangle([0, row_y, 127, row_y + 11], fill=bg)

        if view_idx == 0:
            entry = items[i]
            mac = entry["mac"]
            ip = entry["ip"]
            mac_short = mac[-8:]
            in_wl = mac in config["whitelist"]
            in_bl = mac in config["blacklist"]
            label_color = (0, 255, 0) if in_wl else (255, 60, 60) if in_bl else (200, 200, 200)
            d.text((2, row_y), mac_short, fill=label_color, font=font_sm)
            d.text((68, row_y), ip[-12:], fill=(150, 150, 150), font=font_sm)
        else:
            mac = items[i]
            mac_short = mac[-11:]
            color = (0, 255, 0) if view_idx == 1 else (255, 80, 80)
            d.text((2, row_y), mac_short, fill=color, font=font_sm)


def _render(view_idx, items, scroll_pos, selected, status_msg, config):
    """Render full frame."""
    img = Image.new("RGB", (WIDTH, HEIGHT), (0, 0, 0))
    d = ScaledDraw(img)

    view_name = VIEWS[view_idx]
    _draw_header(d, view_name, len(items))
    _draw_mac_list(d, items, scroll_pos, selected, view_idx, config)
    _draw_footer(d, status_msg)

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    config = _load_config()
    view_idx = 0
    scroll_pos = 0
    selected = 0
    status_msg = "OK:WL K1:BL K2:View"
    last_input = 0.0
    last_scan = 0.0
    clients = []

    while _running:
        now = time.time()

        if now - last_scan > 3.0:
            last_scan = now
            if view_idx == 0:
                clients = _get_connected_clients()

        if view_idx == 0:
            items = clients
        elif view_idx == 1:
            items = list(config["whitelist"])
        else:
            items = list(config["blacklist"])

        btn = get_button(PINS, GPIO)
        if btn and (now - last_input) > DEBOUNCE:
            last_input = now

            if btn == "KEY3":
                _cleanup()
                break

            elif btn == "UP":
                selected = max(0, selected - 1)
                if selected < scroll_pos:
                    scroll_pos = selected

            elif btn == "DOWN":
                selected = min(len(items) - 1, selected + 1) if items else 0
                if selected >= scroll_pos + 8:
                    scroll_pos = selected - 7

            elif btn == "KEY2":
                view_idx = (view_idx + 1) % 3
                scroll_pos = 0
                selected = 0
                status_msg = VIEWS[view_idx]

            elif btn == "OK" and view_idx == 0 and items:
                mac = items[selected]["mac"]
                config = _whitelist_mac(mac, config)
                status_msg = f"WL: {mac[-8:]}"

            elif btn == "KEY1" and view_idx == 0 and items:
                mac = items[selected]["mac"]
                config = _blacklist_mac(mac, config)
                status_msg = f"BL: {mac[-8:]}"

        _render(view_idx, items, scroll_pos, selected, status_msg, config)
        time.sleep(0.1)


if __name__ == "__main__":
    try:
        main()
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
