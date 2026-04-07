#!/usr/bin/env python3
"""
RaspyJack Payload -- BLE Skimmer Scanner
==========================================
Author: 7h30th3r0n3

Scans for Bluetooth Low Energy devices that match known skimmer module
names (HC-05, HC-06, JDY-31, etc.).  Flags suspicious devices with a
red alert and logs results to loot directory.

Controls
--------
  UP / DOWN  -- Scroll device list
  OK         -- Show details for selected device
  KEY1       -- Start / stop scan
  KEY2       -- Export results to loot
  KEY3       -- Exit
"""

import os
import sys
import time
import signal
import subprocess
import threading
import json
from datetime import datetime

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
LOOT_DIR = "/root/Raspyjack/loot/SkimmerScan"

# Known skimmer module name patterns (case-insensitive substrings)
SKIMMER_PATTERNS = [
    "hc-05", "hc-06", "hc05", "hc06",
    "jdy-31", "jdy-30", "jdy31", "jdy30",
    "ble-cc41", "cc41-a", "cc2541",
    "at-09", "at09", "mlt-bt05",
    "hm-10", "hm-11", "hm10", "hm11",
    "blk-md", "db-b10", "spp-ca",
    "rnbt", "firefly", "bolutek",
]

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_running = True
_scanning = False
_scan_proc = None
_scan_lock = threading.Lock()
_devices = []  # list of {"addr": str, "name": str, "rssi": str, "suspicious": bool, "ts": str}


def _cleanup(*_args):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def _is_suspicious(name):
    """Check if device name matches known skimmer module patterns."""
    lower = name.lower()
    for pattern in SKIMMER_PATTERNS:
        if pattern in lower:
            return True
    return False


def _parse_lescan_line(line):
    """Parse a line from hcitool lescan output."""
    parts = line.strip().split(None, 1)
    if len(parts) < 1:
        return None
    addr = parts[0].strip()
    if len(addr) != 17 or addr.count(":") != 5:
        return None
    name = parts[1].strip() if len(parts) > 1 else "(unknown)"
    return {"addr": addr, "name": name}


def _scan_thread():
    """Background BLE scanning thread."""
    global _scan_proc, _scanning
    try:
        # Try hcitool first
        _scan_proc = subprocess.Popen(
            ["hcitool", "lescan", "--passive"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        try:
            _scan_proc = subprocess.Popen(
                ["bluetoothctl", "scan", "le"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError:
            _scanning = False
            return

    try:
        while _scanning and _running and _scan_proc.poll() is None:
            line = _scan_proc.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue
            parsed = _parse_lescan_line(line)
            if parsed is None:
                continue
            with _scan_lock:
                known_addrs = {d["addr"] for d in _devices}
                if parsed["addr"] not in known_addrs:
                    entry = {
                        "addr": parsed["addr"],
                        "name": parsed["name"],
                        "rssi": "N/A",
                        "suspicious": _is_suspicious(parsed["name"]),
                        "ts": datetime.now().strftime("%H:%M:%S"),
                    }
                    _devices.append(entry)
    except Exception:
        pass
    finally:
        _stop_scan_proc()


def _stop_scan_proc():
    """Terminate the scan subprocess if running."""
    global _scan_proc
    if _scan_proc is not None:
        try:
            _scan_proc.terminate()
            _scan_proc.wait(timeout=3)
        except Exception:
            try:
                _scan_proc.kill()
            except Exception:
                pass
        _scan_proc = None


def _start_scan():
    """Start BLE scanning in background."""
    global _scanning
    if _scanning:
        return
    _scanning = True
    t = threading.Thread(target=_scan_thread, daemon=True)
    t.start()


def _stop_scan():
    """Stop BLE scanning."""
    global _scanning
    _scanning = False
    _stop_scan_proc()


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_results(devices):
    """Export scan results to loot directory."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"scan_{ts}.json")
    data = {
        "timestamp": datetime.now().isoformat(),
        "total_devices": len(devices),
        "suspicious_count": sum(1 for d in devices if d["suspicious"]),
        "devices": devices,
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_main(lcd, font, devices, cursor, scroll, scanning, status):
    """Draw the main scanner view."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    label = "SCANNING..." if scanning else "BLE SCANNER"
    d.text((2, 1), label, font=font, fill="#00CCFF")
    susp_count = sum(1 for dev in devices if dev["suspicious"])
    if susp_count > 0:
        d.text((95, 1), f"!{susp_count}", font=font, fill="#FF0000")

    # Device list
    visible = 7
    y = 16
    end = min(len(devices), scroll + visible)

    if not devices:
        d.text((4, 40), "No devices found", font=font, fill="#666")
        d.text((4, 55), "K1 to start scan", font=font, fill="#888")
    else:
        for idx in range(scroll, end):
            dev = devices[idx]
            is_sel = idx == cursor
            prefix = ">" if is_sel else " "
            name_short = dev["name"][:14]
            if dev["suspicious"]:
                color = "#FF4444" if is_sel else "#FF6666"
                prefix = "!" if not is_sel else ">"
            else:
                color = "#00FF00" if is_sel else "#AAAAAA"
            d.text((2, y), f"{prefix}{name_short}", font=font, fill=color)
            y += ROW_H

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if status:
        d.text((2, 117), status[:22], font=font, fill="#FFFF00")
    else:
        total = len(devices)
        d.text((2, 117), f"{total}dev K1:scan K3:exit", font=font, fill="#AAA")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_detail(lcd, font, dev):
    """Draw device detail view."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "DEVICE DETAIL", font=font, fill="#00CCFF")

    color = "#FF4444" if dev["suspicious"] else "#00FF00"
    y = 20
    d.text((2, y), "Name:", font=font, fill="#888")
    y += ROW_H
    d.text((4, y), dev["name"][:20], font=font, fill=color)
    y += ROW_H + 4
    d.text((2, y), "Address:", font=font, fill="#888")
    y += ROW_H
    d.text((4, y), dev["addr"], font=font, fill="#CCCCCC")
    y += ROW_H + 4
    d.text((2, y), f"Seen: {dev['ts']}", font=font, fill="#888")
    y += ROW_H + 4

    if dev["suspicious"]:
        d.text((2, y), "** SUSPICIOUS **", font=font, fill="#FF0000")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "Any key = back", font=font, fill="#AAA")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_alert(lcd, font, dev):
    """Flash red alert for suspicious device."""
    for flash in range(4):
        bg = "#FF0000" if flash % 2 == 0 else "#000000"
        fg = "#FFFFFF" if flash % 2 == 0 else "#FF0000"
        img = Image.new("RGB", (WIDTH, HEIGHT), bg)
        d = ScaledDraw(img)
        d.text((10, 30), "SKIMMER ALERT", font=font, fill=fg)
        d.text((10, 50), dev["name"][:18], font=font, fill=fg)
        d.text((10, 70), dev["addr"], font=font, fill=fg)
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(0.3)


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
    font = scaled_font()

    cursor = 0
    scroll = 0
    status = ""
    last_press = 0.0
    mode = "list"  # list | detail
    visible = 7
    prev_count = 0

    try:
        while _running:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if mode == "detail":
                if btn:
                    mode = "list"
                    time.sleep(0.1)
                    continue

            if btn == "KEY3":
                break
            elif btn == "KEY1":
                if _scanning:
                    _stop_scan()
                    status = "Scan stopped"
                else:
                    _start_scan()
                    status = "Scanning..."
            elif btn == "KEY2":
                with _scan_lock:
                    devs = list(_devices)
                if devs:
                    try:
                        path = _export_results(devs)
                        status = "Exported!"
                    except Exception as exc:
                        status = f"Err:{str(exc)[:14]}"
                else:
                    status = "No data"
            elif btn == "UP":
                cursor = max(0, cursor - 1)
                if cursor < scroll:
                    scroll = cursor
                status = ""
            elif btn == "DOWN":
                with _scan_lock:
                    max_idx = max(0, len(_devices) - 1)
                cursor = min(max_idx, cursor + 1)
                if cursor >= scroll + visible:
                    scroll = cursor - visible + 1
                status = ""
            elif btn == "OK":
                with _scan_lock:
                    if _devices and cursor < len(_devices):
                        dev = dict(_devices[cursor])
                        _draw_detail(lcd, font, dev)
                        mode = "detail"
                        time.sleep(0.1)
                        continue

            # Check for new suspicious devices to flash alert
            with _scan_lock:
                devs = list(_devices)
            if len(devs) > prev_count:
                for dev in devs[prev_count:]:
                    if dev["suspicious"]:
                        _draw_alert(lcd, font, dev)
                prev_count = len(devs)

            _draw_main(lcd, font, devs, cursor, scroll, _scanning, status)
            time.sleep(0.08)

    finally:
        _stop_scan()
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
