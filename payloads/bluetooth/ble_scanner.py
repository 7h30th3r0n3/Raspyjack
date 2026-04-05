#!/usr/bin/env python3
"""
RaspyJack Payload -- Continuous BLE Scanner Dashboard
=====================================================
Author: 7h30th3r0n3

Scans for BLE devices using hcitool lescan and tracks addresses,
names, RSSI, first/last seen timestamps and seen count.  Provides
a scrollable device list with detail view.

Setup / Prerequisites
---------------------
- Bluetooth adapter (hci0)
- hcitool / hciconfig (bluez package)
- Optional: bluetoothctl for service enumeration

Controls
--------
  OK         -- Start / stop scanning
  UP / DOWN  -- Scroll device list
  RIGHT      -- Show device details (services)
  KEY1       -- Toggle sort (RSSI / name / count)
  KEY2       -- Export JSON to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/BLEScan/
"""

import os
import sys
import time
import json
import re
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
HCI_DEV = "hci0"
LOOT_DIR = "/root/Raspyjack/loot/BLEScan"
ROWS_VISIBLE = 7
ROW_H = 12
SORT_MODES = ["rssi", "name", "count"]
VIEWS = ["list", "detail"]

# ── Shared state ─────────────────────────────────────────────────────────────
lock = threading.Lock()
devices = {}          # addr -> {addr, name, rssi, first_seen, last_seen, count}
scanning = False
scan_proc = None
scroll_pos = 0
selected_idx = 0
sort_idx = 0
view = "list"
detail_lines = []
detail_scroll = 0
status_msg = "Idle"
_running = True


# ── HCI helpers ──────────────────────────────────────────────────────────────

def _hci_up():
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "up"],
                   capture_output=True, timeout=5)


def _hci_reset():
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "reset"],
                   capture_output=True, timeout=5)


# ── RSSI helper ──────────────────────────────────────────────────────────────

def _get_rssi(addr):
    """Attempt to read RSSI for a BLE device via hcitool."""
    try:
        result = subprocess.run(
            ["sudo", "hcitool", "-i", HCI_DEV, "rssi", addr],
            capture_output=True, text=True, timeout=3,
        )
        match = re.search(r"RSSI return value:\s*(-?\d+)", result.stdout)
        if match:
            return int(match.group(1))
    except Exception:
        pass
    return -100


# ── Scan thread ──────────────────────────────────────────────────────────────

def _scan_loop():
    """Run hcitool lescan in a loop, parse output."""
    global scan_proc, status_msg

    _hci_up()
    time.sleep(0.3)

    while True:
        with lock:
            if not scanning:
                break

        try:
            proc = subprocess.Popen(
                ["sudo", "hcitool", "-i", HCI_DEV, "lescan", "--duplicates"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            with lock:
                scan_proc = proc

            for line in proc.stdout:
                with lock:
                    if not scanning:
                        break

                line = line.strip()
                if not line:
                    continue

                # Format: AA:BB:CC:DD:EE:FF DeviceName
                # or:     AA:BB:CC:DD:EE:FF (unknown)
                parts = line.split(None, 1)
                if not parts:
                    continue
                addr = parts[0].upper()
                if not re.match(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$", addr):
                    continue
                name = parts[1] if len(parts) > 1 else "(unknown)"
                if name == "(unknown)":
                    name = ""

                now_str = datetime.now().strftime("%H:%M:%S")

                with lock:
                    if addr in devices:
                        prev = devices[addr]
                        devices[addr] = {
                            **prev,
                            "name": name or prev["name"],
                            "last_seen": now_str,
                            "count": prev["count"] + 1,
                        }
                    else:
                        devices[addr] = {
                            "addr": addr,
                            "name": name,
                            "rssi": -100,
                            "first_seen": now_str,
                            "last_seen": now_str,
                            "count": 1,
                        }

            proc.wait(timeout=2)

        except Exception as exc:
            with lock:
                status_msg = str(exc)[:20]
            time.sleep(1)

    # Cleanup process
    with lock:
        p = scan_proc
        scan_proc = None
    if p:
        try:
            p.terminate()
            p.wait(timeout=3)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass


# ── RSSI updater thread ─────────────────────────────────────────────────────

def _rssi_updater():
    """Periodically update RSSI for known devices."""
    while True:
        with lock:
            if not scanning:
                break
            addrs = list(devices.keys())[:10]  # limit to avoid slowdown

        for addr in addrs:
            with lock:
                if not scanning:
                    return
            rssi = _get_rssi(addr)
            if rssi != -100:
                with lock:
                    if addr in devices:
                        devices[addr] = {**devices[addr], "rssi": rssi}

        time.sleep(5)


# ── Service enumeration ─────────────────────────────────────────────────────

def _enumerate_services(addr):
    """Use bluetoothctl to get services for a BLE device."""
    lines = [f"Device: {addr}"]
    try:
        # Connect and discover services
        proc = subprocess.run(
            ["sudo", "gatttool", "-b", addr, "--primary"],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            for svc_line in proc.stdout.strip().split("\n"):
                lines.append(svc_line.strip()[:22])
        else:
            lines.append("No services found")
            if proc.stderr.strip():
                lines.append(proc.stderr.strip()[:22])
    except subprocess.TimeoutExpired:
        lines.append("Connection timeout")
    except Exception as exc:
        lines.append(f"Error: {str(exc)[:18]}")
    return lines


# ── Start / stop ─────────────────────────────────────────────────────────────

def _start_scan():
    global scanning, status_msg
    with lock:
        if scanning:
            return
        scanning = True
        status_msg = "Scanning..."
    threading.Thread(target=_scan_loop, daemon=True).start()
    threading.Thread(target=_rssi_updater, daemon=True).start()


def _stop_scan():
    global scanning, status_msg
    with lock:
        scanning = False
        p = scan_proc
        status_msg = "Stopped"
    if p:
        try:
            p.terminate()
            p.wait(timeout=3)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    time.sleep(0.3)
    _hci_reset()


# ── Sorted device list ──────────────────────────────────────────────────────

def _sorted_devices():
    with lock:
        items = list(devices.values())
        mode = SORT_MODES[sort_idx]
    if mode == "rssi":
        items.sort(key=lambda d: d["rssi"], reverse=True)
    elif mode == "name":
        items.sort(key=lambda d: d["name"].lower() if d["name"] else "zzz")
    elif mode == "count":
        items.sort(key=lambda d: d["count"], reverse=True)
    return items


# ── Export ───────────────────────────────────────────────────────────────────

def _export_json():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"ble_scan_{ts}.json")
    with lock:
        data = {"timestamp": ts, "devices": list(devices.values())}
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


# ── Drawing ──────────────────────────────────────────────────────────────────

def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        active = scanning
        msg = status_msg
        n_dev = len(devices)
        sp = scroll_pos
        sel = selected_idx
        srt = SORT_MODES[sort_idx]
        cur_view = view
        d_lines = list(detail_lines)
        d_scroll = detail_scroll

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    title = "BLE SCAN" if cur_view == "list" else "BLE DETAIL"
    d.text((2, 1), title, font=font, fill="#2196F3")
    color = "#00FF00" if active else "#FF0000"
    d.ellipse((118, 3, 126, 11), fill=color)

    y = 15

    if cur_view == "detail":
        # Detail view
        end = min(d_scroll + 8, len(d_lines))
        for i in range(d_scroll, end):
            d.text((2, y), d_lines[i][:22], font=font, fill="#CCCCCC")
            y += ROW_H
        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "LEFT=Back U/D=Scroll", font=font, fill="#AAA")
    else:
        # List view
        d.text((2, y), f"Devs:{n_dev} Sort:{srt} {msg[:8]}",
               font=font, fill="#888")
        y += 13

        devs = _sorted_devices()
        end = min(sp + ROWS_VISIBLE, len(devs))
        for i in range(sp, end):
            dev = devs[i]
            prefix = ">" if i == sel else " "
            name = (dev["name"] or dev["addr"][-8:])[:12]
            rssi = dev["rssi"]
            cnt = dev["count"]
            clr = "#FFAA00" if i == sel else "#CCCCCC"
            txt = f"{prefix}{name} {rssi}dB x{cnt}"
            d.text((2, y), txt[:22], font=font, fill=clr)
            y += ROW_H

        if not devs:
            d.text((2, y), "No devices yet", font=font, fill="#555")

        d.rectangle((0, 116, 127, 127), fill="#111")
        lbl = "OK:Stop" if active else "OK:Go"
        d.text((2, 117), f"{lbl} K1:Srt K3:X", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    global scroll_pos, selected_idx, sort_idx, status_msg
    global view, detail_lines, detail_scroll

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 10), "BLE SCANNER", font=font, fill="#2196F3")
    d.text((4, 28), "Continuous BLE device", font=font, fill="#888")
    d.text((4, 40), "scanner dashboard.", font=font, fill="#888")
    d.text((4, 60), "OK=Start  RIGHT=Detail", font=font, fill="#666")
    d.text((4, 72), "K1=Sort  K2=Export", font=font, fill="#666")
    d.text((4, 84), "K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if view == "detail":
                    view = "list"
                    time.sleep(0.25)
                else:
                    break

            elif view == "detail":
                if btn == "LEFT":
                    view = "list"
                    time.sleep(0.25)
                elif btn == "UP":
                    detail_scroll = max(0, detail_scroll - 1)
                    time.sleep(0.2)
                elif btn == "DOWN":
                    detail_scroll = min(detail_scroll + 1,
                                        max(0, len(detail_lines) - 8))
                    time.sleep(0.2)

            else:
                if btn == "OK":
                    with lock:
                        active = scanning
                    if active:
                        _stop_scan()
                    else:
                        _start_scan()
                    time.sleep(0.3)

                elif btn == "UP":
                    with lock:
                        selected_idx = max(0, selected_idx - 1)
                        if selected_idx < scroll_pos:
                            scroll_pos = selected_idx
                    time.sleep(0.2)

                elif btn == "DOWN":
                    devs = _sorted_devices()
                    with lock:
                        selected_idx = min(len(devs) - 1, selected_idx + 1)
                        if selected_idx >= scroll_pos + ROWS_VISIBLE:
                            scroll_pos = selected_idx - ROWS_VISIBLE + 1
                    time.sleep(0.2)

                elif btn == "RIGHT":
                    devs = _sorted_devices()
                    if devs and 0 <= selected_idx < len(devs):
                        addr = devs[selected_idx]["addr"]
                        with lock:
                            status_msg = "Connecting..."
                        detail_lines = _enumerate_services(addr)
                        detail_scroll = 0
                        view = "detail"
                        with lock:
                            status_msg = "Detail view"
                    time.sleep(0.3)

                elif btn == "KEY1":
                    with lock:
                        sort_idx = (sort_idx + 1) % len(SORT_MODES)
                        status_msg = f"Sort: {SORT_MODES[sort_idx]}"
                    time.sleep(0.25)

                elif btn == "KEY2":
                    path = _export_json()
                    with lock:
                        status_msg = "Exported"
                    time.sleep(0.3)

            _draw_screen()
            time.sleep(0.05)

    finally:
        _stop_scan()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
