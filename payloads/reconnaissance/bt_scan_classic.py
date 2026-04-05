#!/usr/bin/env python3
"""
RaspyJack Payload -- Bluetooth Classic Scanner
================================================
Author: 7h30th3r0n3

Discovers nearby Bluetooth Classic devices using hcitool scan, then
enumerates SDP services for each device with sdptool browse.

Setup / Prerequisites:
  - Requires Bluetooth adapter.

Controls:
  OK        -- Start scan
  UP / DOWN -- Scroll device list
  RIGHT     -- Show services for selected device
  KEY1      -- Rescan
  KEY2      -- Export JSON to loot
  KEY3      -- Exit

Loot: /root/Raspyjack/loot/BTClassic/<timestamp>.json
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
LOOT_DIR = "/root/Raspyjack/loot/BTClassic"
os.makedirs(LOOT_DIR, exist_ok=True)

ROWS_VISIBLE = 7
ROW_H = 12

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
scanning = False
scan_status = "Idle"
devices = []          # list of {"addr": str, "name": str, "services": list}
scroll_pos = 0
selected_idx = 0
view = "list"         # "list" or "services"
svc_scroll = 0


# ---------------------------------------------------------------------------
# Bluetooth scanning
# ---------------------------------------------------------------------------

def _parse_scan_output(output):
    """Parse hcitool scan output into list of (addr, name) tuples."""
    results = []
    for line in output.strip().splitlines():
        line = line.strip()
        match = re.match(r"([0-9A-Fa-f:]{17})\s+(.*)", line)
        if match:
            addr = match.group(1).upper()
            name = match.group(2).strip() or "Unknown"
            results.append((addr, name))
    return results


def _parse_sdp_output(output):
    """Parse sdptool browse output into a list of service dicts."""
    services = []
    current = {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Service Name:"):
            if current:
                services.append(dict(current))
            current = {"name": line.split(":", 1)[1].strip()}
        elif line.startswith("Service Description:"):
            current["description"] = line.split(":", 1)[1].strip()
        elif line.startswith("Service Provider:"):
            current["provider"] = line.split(":", 1)[1].strip()
        elif line.startswith("Protocol Descriptor List:"):
            current["protocols"] = []
        elif line.startswith('"') and "protocols" in current:
            current["protocols"].append(line.strip('"').strip())
        elif line.startswith("Channel:"):
            current["channel"] = line.split(":", 1)[1].strip()
        elif line.startswith("Service RecHandle:"):
            current["handle"] = line.split(":", 1)[1].strip()
        elif line.startswith("Profile Descriptor List:"):
            current["profiles"] = []
    if current:
        services.append(dict(current))
    return services


def _do_scan():
    """Run device discovery and SDP enumeration in background."""
    global scanning, scan_status, devices

    with lock:
        scanning = True
        scan_status = "Discovering..."
        devices = []

    try:
        subprocess.run(
            ["sudo", "hciconfig", "hci0", "up"],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass

    # Device discovery
    try:
        result = subprocess.run(
            ["hcitool", "scan", "--flush"],
            capture_output=True, text=True, timeout=30,
        )
        found = _parse_scan_output(result.stdout)
    except subprocess.TimeoutExpired:
        found = []
        with lock:
            scan_status = "Scan timed out"
    except Exception as exc:
        found = []
        with lock:
            scan_status = f"Error: {str(exc)[:20]}"

    with lock:
        devices = [{"addr": addr, "name": name, "services": []} for addr, name in found]
        scan_status = f"Found {len(found)} devices"

    # SDP enumeration for each device
    for i, dev in enumerate(list(devices)):
        with lock:
            if not scanning:
                break
            scan_status = f"SDP {i + 1}/{len(found)}: {dev['addr'][-8:]}"

        try:
            result = subprocess.run(
                ["sdptool", "browse", dev["addr"]],
                capture_output=True, text=True, timeout=15,
            )
            services = _parse_sdp_output(result.stdout)
        except Exception:
            services = []

        with lock:
            if i < len(devices):
                devices[i] = {**devices[i], "services": services}

    with lock:
        total_svcs = sum(len(d["services"]) for d in devices)
        scan_status = f"Done: {len(found)} dev, {total_svcs} svc"
        scanning = False


def start_scan():
    """Launch scan in a background thread."""
    with lock:
        if scanning:
            return
    threading.Thread(target=_do_scan, daemon=True).start()


# ---------------------------------------------------------------------------
# Loot export
# ---------------------------------------------------------------------------

def export_loot():
    """Write scan results to JSON."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    with lock:
        data = {
            "timestamp": ts,
            "device_count": len(devices),
            "devices": [dict(d) for d in devices],
        }
    path = os.path.join(LOOT_DIR, f"bt_classic_{ts}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(d, title):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title, font=font, fill="#3388FF")
    with lock:
        active = scanning
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if active else "#FF0000")


def _draw_footer(d, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font, fill="#AAA")


def draw_list_view():
    """Render the device list view."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "BT CLASSIC")

    with lock:
        devs = [dict(dev) for dev in devices]
        status = scan_status
        sel = selected_idx
        sc = scroll_pos

    d.text((2, 15), status[:22], font=font, fill="#888")

    if not devs:
        d.text((20, 55), "Press OK to scan", font=font, fill="#666")
    else:
        visible = devs[sc:sc + ROWS_VISIBLE - 1]
        for i, dev in enumerate(visible):
            y = 28 + i * ROW_H
            actual_idx = sc + i
            name = dev["name"][:12] if dev["name"] else dev["addr"][-8:]
            svc_count = len(dev.get("services", []))
            color = "#FFFF00" if actual_idx == sel else "#CCCCCC"
            marker = ">" if actual_idx == sel else " "
            d.text((1, y), f"{marker}{name:<12s} S:{svc_count}", font=font, fill=color)

        # Scroll indicator
        total = len(devs)
        if total > ROWS_VISIBLE - 1:
            bar_h = max(4, int((ROWS_VISIBLE - 1) / total * 88))
            bar_y = 28 + int(sc / total * 88)
            d.rectangle((126, bar_y, 127, bar_y + bar_h), fill="#444")

    _draw_footer(d, "OK:Scan R:Svc K3:Exit")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_services_view():
    """Render the services view for the selected device."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        sel = selected_idx
        if sel < len(devices):
            dev = dict(devices[sel])
            svcs = list(dev.get("services", []))
        else:
            dev = {"addr": "N/A", "name": "N/A"}
            svcs = []
        sc = svc_scroll

    _draw_header(d, "SERVICES")
    addr_short = dev["addr"][-8:] if len(dev.get("addr", "")) > 8 else dev.get("addr", "")
    d.text((2, 15), f"{dev.get('name', '')[:10]} {addr_short}", font=font, fill="#888")

    if not svcs:
        d.text((15, 55), "No services found", font=font, fill="#666")
    else:
        visible = svcs[sc:sc + ROWS_VISIBLE - 1]
        for i, svc in enumerate(visible):
            y = 28 + i * ROW_H
            name = svc.get("name", "Unknown")[:20]
            ch = svc.get("channel", "")
            line = f"{name}"
            if ch:
                line = f"{name[:15]} ch{ch}"
            d.text((2, y), line[:22], font=font, fill="#CCCCCC")

    _draw_footer(d, f"Svc:{len(svcs)} LEFT:Back")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global scroll_pos, selected_idx, view, svc_scroll

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 20), "BT CLASSIC SCAN", font=font, fill="#3388FF")
    d.text((4, 40), "Device discovery +", font=font, fill="#888")
    d.text((4, 52), "SDP enumeration", font=font, fill="#888")
    d.text((4, 72), "OK     Start scan", font=font, fill="#666")
    d.text((4, 84), "U/D    Scroll", font=font, fill="#666")
    d.text((4, 96), "RIGHT  View services", font=font, fill="#666")
    d.text((4, 108), "KEY3   Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.3)

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if devices:
                    export_loot()
                break

            if view == "list":
                if btn == "OK" or btn == "KEY1":
                    start_scan()
                    time.sleep(0.3)
                elif btn == "UP":
                    with lock:
                        selected_idx = max(0, selected_idx - 1)
                        if selected_idx < scroll_pos:
                            scroll_pos = selected_idx
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        max_idx = max(0, len(devices) - 1)
                        selected_idx = min(max_idx, selected_idx + 1)
                        if selected_idx >= scroll_pos + ROWS_VISIBLE - 1:
                            scroll_pos = selected_idx - ROWS_VISIBLE + 2
                    time.sleep(0.15)
                elif btn == "RIGHT":
                    with lock:
                        if devices and selected_idx < len(devices):
                            view = "services"
                            svc_scroll = 0
                    time.sleep(0.2)
                elif btn == "KEY2":
                    if devices:
                        path = export_loot()
                        _show_message(f"Exported!", path[-20:])
                    time.sleep(0.3)

            elif view == "services":
                if btn == "LEFT" or btn == "OK":
                    view = "list"
                    time.sleep(0.2)
                elif btn == "UP":
                    svc_scroll = max(0, svc_scroll - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        sel = selected_idx
                        svc_count = len(devices[sel]["services"]) if sel < len(devices) else 0
                    max_sc = max(0, svc_count - ROWS_VISIBLE + 1)
                    svc_scroll = min(max_sc, svc_scroll + 1)
                    time.sleep(0.15)
                elif btn == "KEY2":
                    if devices:
                        path = export_loot()
                        _show_message("Exported!", path[-20:])
                    time.sleep(0.3)

            if view == "list":
                draw_list_view()
            else:
                draw_services_view()

            time.sleep(0.05)

    finally:
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


def _show_message(line1, line2=""):
    """Show a brief overlay message."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((10, 50), line1, font=font, fill="#00FF00")
    if line2:
        d.text((4, 65), line2, font=font, fill="#888")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)


if __name__ == "__main__":
    raise SystemExit(main())
