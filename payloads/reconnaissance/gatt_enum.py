#!/usr/bin/env python3
"""
RaspyJack Payload -- BLE GATT Enumerator
==========================================
Author: 7h30th3r0n3

Scans for nearby BLE devices using hcitool lescan, lets the user select
one, then connects via gatttool to enumerate all GATT services,
characteristics, and their properties (read/write/notify).

Setup / Prerequisites:
  - Requires Bluetooth adapter.
  - Requires gatttool (from bluez package).

Controls:
  OK        -- Select device / Connect
  UP / DOWN -- Scroll
  KEY1      -- Rescan for BLE devices
  KEY2      -- Export results to loot
  KEY3      -- Exit

Loot: /root/Raspyjack/loot/GATT/<timestamp>.json
"""

import os
import sys
import json
import time
import threading
import subprocess
import re
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
LOOT_DIR = "/root/Raspyjack/loot/GATT"
os.makedirs(LOOT_DIR, exist_ok=True)

ROWS_VISIBLE = 7
ROW_H = 12

# Well-known GATT service UUIDs (short form)
KNOWN_SERVICES = {
    "1800": "Generic Access",
    "1801": "Generic Attribute",
    "180a": "Device Info",
    "180f": "Battery",
    "180d": "Heart Rate",
    "1802": "Immediate Alert",
    "1803": "Link Loss",
    "1804": "Tx Power",
    "1805": "Current Time",
    "1810": "Blood Pressure",
    "1816": "Cycling Speed",
    "181c": "User Data",
}

# Characteristic property bits
CHAR_PROPS = {
    0x01: "Broadcast",
    0x02: "Read",
    0x04: "WriteNoResp",
    0x08: "Write",
    0x10: "Notify",
    0x20: "Indicate",
    0x40: "AuthWrite",
    0x80: "ExtProps",
}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
scanning = False
connecting = False
status_msg = "Idle"

# BLE device list from lescan
ble_devices = []       # [{"addr": str, "name": str}]
selected_idx = 0
scroll_pos = 0

# GATT results for connected device
gatt_target = ""       # addr of connected device
gatt_services = []     # [{"uuid": str, "handle_start": str, "handle_end": str,
                        #   "name": str, "chars": [{"uuid": str, "handle": str,
                        #   "props": str, "props_raw": int}]}]
gatt_scroll = 0
view = "devices"       # "devices" or "gatt"


# ---------------------------------------------------------------------------
# BLE scanning
# ---------------------------------------------------------------------------

def _parse_lescan(output):
    """Parse hcitool lescan output into device list."""
    seen = {}
    for line in output.strip().splitlines():
        line = line.strip()
        match = re.match(r"([0-9A-Fa-f:]{17})\s+(.*)", line)
        if match:
            addr = match.group(1).upper()
            name = match.group(2).strip()
            if name in ("(unknown)", ""):
                name = ""
            if addr not in seen or (name and not seen[addr]):
                seen[addr] = name
    return [{"addr": a, "name": n or "Unknown"} for a, n in seen.items()]


def _do_lescan():
    """Run BLE device discovery in the background."""
    global scanning, status_msg, ble_devices, selected_idx, scroll_pos

    with lock:
        scanning = True
        status_msg = "Scanning BLE..."
        ble_devices = []
        selected_idx = 0
        scroll_pos = 0

    try:
        subprocess.run(
            ["sudo", "hciconfig", "hci0", "up"],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass

    try:
        # lescan runs for a fixed duration; we kill it after timeout
        proc = subprocess.Popen(
            ["sudo", "hcitool", "lescan"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        time.sleep(8)  # scan for 8 seconds
        proc.terminate()
        try:
            out, _ = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()

        found = _parse_lescan(out)
    except Exception as exc:
        found = []
        with lock:
            status_msg = f"Scan error: {str(exc)[:16]}"

    with lock:
        ble_devices = found
        status_msg = f"Found {len(found)} BLE devices"
        scanning = False


def start_lescan():
    """Launch BLE scan in background."""
    with lock:
        if scanning or connecting:
            return
    threading.Thread(target=_do_lescan, daemon=True).start()


# ---------------------------------------------------------------------------
# GATT enumeration
# ---------------------------------------------------------------------------

def _prop_str(prop_val):
    """Convert property bitmask to human-readable string."""
    parts = []
    for bit, name in CHAR_PROPS.items():
        if prop_val & bit:
            parts.append(name)
    return ",".join(parts) if parts else "None"


def _parse_services(output):
    """Parse gatttool --primary output."""
    services = []
    for line in output.splitlines():
        match = re.match(
            r"attr handle\s*=\s*(0x[0-9a-fA-F]+),\s*"
            r"end grp handle\s*=\s*(0x[0-9a-fA-F]+)\s+"
            r"uuid:\s*([0-9a-fA-F-]+)",
            line.strip(),
        )
        if match:
            uuid = match.group(3).lower()
            short = uuid.split("-")[0].lstrip("0") if "-" in uuid else uuid
            name = KNOWN_SERVICES.get(short, "")
            services.append({
                "uuid": uuid,
                "handle_start": match.group(1),
                "handle_end": match.group(2),
                "name": name,
                "chars": [],
            })
    return services


def _parse_characteristics(output):
    """Parse gatttool --characteristics output."""
    chars = []
    for line in output.splitlines():
        match = re.match(
            r"handle\s*=\s*(0x[0-9a-fA-F]+),\s*"
            r"char properties\s*=\s*(0x[0-9a-fA-F]+),\s*"
            r"char value handle\s*=\s*(0x[0-9a-fA-F]+),\s*"
            r"uuid\s*=\s*([0-9a-fA-F-]+)",
            line.strip(),
        )
        if match:
            prop_val = int(match.group(2), 16)
            chars.append({
                "handle": match.group(1),
                "value_handle": match.group(3),
                "props_raw": prop_val,
                "props": _prop_str(prop_val),
                "uuid": match.group(4).lower(),
            })
    return chars


def _do_gatt_enum(addr):
    """Connect to a BLE device and enumerate GATT services/chars."""
    global connecting, status_msg, gatt_target, gatt_services, gatt_scroll, view

    with lock:
        connecting = True
        status_msg = f"Connecting {addr[-8:]}..."
        gatt_services = []
        gatt_target = addr
        gatt_scroll = 0

    try:
        # Primary services
        result = subprocess.run(
            ["gatttool", "-b", addr, "--primary"],
            capture_output=True, text=True, timeout=20,
        )
        services = _parse_services(result.stdout)

        with lock:
            status_msg = f"Found {len(services)} services"
            gatt_services = services

        # Characteristics
        result = subprocess.run(
            ["gatttool", "-b", addr, "--characteristics"],
            capture_output=True, text=True, timeout=20,
        )
        all_chars = _parse_characteristics(result.stdout)

        # Assign characteristics to their parent service
        with lock:
            for svc in gatt_services:
                h_start = int(svc["handle_start"], 16)
                h_end = int(svc["handle_end"], 16)
                svc_chars = []
                for ch in all_chars:
                    ch_handle = int(ch["handle"], 16)
                    if h_start <= ch_handle <= h_end:
                        svc_chars.append(dict(ch))
                svc["chars"] = svc_chars

            total_chars = sum(len(s["chars"]) for s in gatt_services)
            status_msg = f"{len(gatt_services)} svc, {total_chars} chars"
            view = "gatt"

    except subprocess.TimeoutExpired:
        with lock:
            status_msg = "Connection timed out"
    except Exception as exc:
        with lock:
            status_msg = f"Error: {str(exc)[:18]}"
    finally:
        with lock:
            connecting = False


def start_gatt_enum(addr):
    """Launch GATT enumeration in background."""
    with lock:
        if scanning or connecting:
            return
    threading.Thread(target=_do_gatt_enum, args=(addr,), daemon=True).start()


# ---------------------------------------------------------------------------
# Loot export
# ---------------------------------------------------------------------------

def export_loot():
    """Write GATT enumeration results to JSON."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    with lock:
        data = {
            "timestamp": ts,
            "target": gatt_target,
            "services": [dict(s) for s in gatt_services],
            "scanned_devices": [dict(d) for d in ble_devices],
        }
    path = os.path.join(LOOT_DIR, f"gatt_{ts}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    return path


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(d, title):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title, font=font, fill="#AA44FF")
    with lock:
        active = scanning or connecting
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if active else "#FF0000")


def _draw_footer(d, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font, fill="#AAA")


def draw_devices_view():
    """Render BLE device list."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "GATT ENUM")

    with lock:
        devs = [dict(dev) for dev in ble_devices]
        status = status_msg
        sel = selected_idx
        sc = scroll_pos

    d.text((2, 15), status[:22], font=font, fill="#888")

    if not devs:
        d.text((15, 55), "KEY1: Scan for BLE", font=font, fill="#666")
    else:
        visible = devs[sc:sc + ROWS_VISIBLE - 1]
        for i, dev in enumerate(visible):
            y = 28 + i * ROW_H
            actual_idx = sc + i
            name = dev["name"][:11] if dev["name"] else "Unknown"
            addr_short = dev["addr"][-5:]
            color = "#FFFF00" if actual_idx == sel else "#CCCCCC"
            marker = ">" if actual_idx == sel else " "
            d.text((1, y), f"{marker}{name:<11s}{addr_short}", font=font, fill=color)

    _draw_footer(d, "OK:Connect K1:Scan")
    LCD.LCD_ShowImage(img, 0, 0)


def _build_gatt_lines():
    """Build a flat list of display lines from the GATT tree."""
    lines = []
    with lock:
        for svc in gatt_services:
            short_uuid = svc["uuid"][:8]
            name = svc.get("name", "")
            label = name if name else short_uuid
            lines.append({"text": f"[S] {label}", "color": "#44AAFF"})
            for ch in svc.get("chars", []):
                ch_uuid = ch["uuid"][:8]
                props = ch.get("props", "")
                # Abbreviate props
                short_props = props.replace("WriteNoResp", "WnR")
                lines.append({"text": f"  {ch_uuid} {short_props[:12]}", "color": "#CCCCCC"})
    return lines


def draw_gatt_view():
    """Render GATT service/characteristic tree."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "GATT TREE")

    with lock:
        status = status_msg
        target = gatt_target[-8:] if gatt_target else ""
        sc = gatt_scroll

    d.text((2, 15), f"{target} {status[:14]}", font=font, fill="#888")

    lines = _build_gatt_lines()
    if not lines:
        d.text((15, 55), "No GATT data yet", font=font, fill="#666")
    else:
        visible = lines[sc:sc + ROWS_VISIBLE - 1]
        for i, line in enumerate(visible):
            y = 28 + i * ROW_H
            d.text((1, y), line["text"][:22], font=font, fill=line["color"])

        total = len(lines)
        if total > ROWS_VISIBLE - 1:
            bar_h = max(4, int((ROWS_VISIBLE - 1) / total * 88))
            bar_y = 28 + int(sc / total * 88) if total > 0 else 28
            d.rectangle((126, bar_y, 127, bar_y + bar_h), fill="#444")

    _draw_footer(d, "LEFT:Back K2:Export")
    LCD.LCD_ShowImage(img, 0, 0)


def _show_message(line1, line2=""):
    """Show a brief overlay message."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((10, 50), line1, font=font, fill="#00FF00")
    if line2:
        d.text((4, 65), line2, font=font, fill="#888")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global selected_idx, scroll_pos, gatt_scroll, view

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 20), "BLE GATT ENUM", font=font, fill="#AA44FF")
    d.text((4, 40), "Service & char", font=font, fill="#888")
    d.text((4, 52), "enumeration tool", font=font, fill="#888")
    d.text((4, 72), "KEY1  Scan BLE", font=font, fill="#666")
    d.text((4, 84), "OK    Connect", font=font, fill="#666")
    d.text((4, 96), "KEY2  Export", font=font, fill="#666")
    d.text((4, 108), "KEY3  Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.3)

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if gatt_services:
                    export_loot()
                break

            if view == "devices":
                if btn == "KEY1" or (btn == "OK" and not ble_devices):
                    start_lescan()
                    time.sleep(0.3)
                elif btn == "OK" and ble_devices:
                    with lock:
                        if selected_idx < len(ble_devices):
                            addr = ble_devices[selected_idx]["addr"]
                    start_gatt_enum(addr)
                    time.sleep(0.3)
                elif btn == "UP":
                    with lock:
                        selected_idx = max(0, selected_idx - 1)
                        if selected_idx < scroll_pos:
                            scroll_pos = selected_idx
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        max_idx = max(0, len(ble_devices) - 1)
                        selected_idx = min(max_idx, selected_idx + 1)
                        if selected_idx >= scroll_pos + ROWS_VISIBLE - 1:
                            scroll_pos = selected_idx - ROWS_VISIBLE + 2
                    time.sleep(0.15)
                elif btn == "KEY2":
                    if gatt_services or ble_devices:
                        path = export_loot()
                        _show_message("Exported!", path[-20:])
                    time.sleep(0.3)

            elif view == "gatt":
                if btn == "LEFT":
                    view = "devices"
                    time.sleep(0.2)
                elif btn == "UP":
                    gatt_scroll = max(0, gatt_scroll - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    lines = _build_gatt_lines()
                    max_sc = max(0, len(lines) - ROWS_VISIBLE + 1)
                    gatt_scroll = min(max_sc, gatt_scroll + 1)
                    time.sleep(0.15)
                elif btn == "KEY2":
                    path = export_loot()
                    _show_message("Exported!", path[-20:])
                    time.sleep(0.3)
                elif btn == "KEY1":
                    view = "devices"
                    start_lescan()
                    time.sleep(0.3)

            if view == "devices":
                draw_devices_view()
            else:
                draw_gatt_view()

            time.sleep(0.05)

    finally:
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
