#!/usr/bin/env python3
"""
RaspyJack Payload -- WiFi Antenna Diagnostics
================================================
Author: 7h30th3r0n3

Inspect WiFi interfaces: driver, chipset, supported bands, channels,
TX power, signal level, and supported modes (managed, monitor, AP, mesh).

Controls
--------
  UP / DOWN  -- Navigate interfaces / scroll info
  OK         -- Select interface / back to list
  KEY1       -- Signal quality test (scan nearby APs)
  KEY2       -- Toggle interface up/down
  KEY3       -- Exit
"""

import os
import sys
import time
import signal
import subprocess
import threading
import re
from datetime import datetime

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
ROW_H = 12
DEBOUNCE = 0.20
VISIBLE_ROWS = 8

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
app_running = True
iface_list = []             # [{"name": ..., "phy": ..., "addr": ...}]
selected_idx = 0
scroll_pos = 0
view_mode = "list"          # list | detail | scan
detail_lines = []
detail_scroll = 0
status_msg = "Loading..."
scan_results = []           # [{"ssid": ..., "signal": ...}]
scan_scroll = 0


# ---------------------------------------------------------------------------
# Signal handlers
# ---------------------------------------------------------------------------
def _sig_handler(_sig, _frame):
    global app_running
    app_running = False


signal.signal(signal.SIGINT, _sig_handler)
signal.signal(signal.SIGTERM, _sig_handler)


# ---------------------------------------------------------------------------
# WiFi info helpers
# ---------------------------------------------------------------------------
def _run_cmd(args):
    """Run command and return stdout."""
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=15,
        )
        return result.stdout.strip()
    except Exception:
        return ""


def _list_wifi_interfaces():
    """Parse `iw dev` to list WiFi interfaces."""
    output = _run_cmd(["iw", "dev"])
    interfaces = []
    current_phy = ""
    current = {}
    for line in output.splitlines():
        stripped = line.strip()
        if line.startswith("phy#"):
            current_phy = line.strip()
        elif stripped.startswith("Interface "):
            if current.get("name"):
                interfaces.append(dict(current))
            current = {"name": stripped.split()[1], "phy": current_phy, "addr": ""}
        elif stripped.startswith("addr "):
            current["addr"] = stripped.split()[1]
    if current.get("name"):
        interfaces.append(dict(current))
    return interfaces


def _get_iface_detail(iface_name, phy_name):
    """Gather detailed info for a WiFi interface."""
    lines = []

    # iw dev info
    dev_info = _run_cmd(["iw", "dev", iface_name, "info"])
    for line in dev_info.splitlines():
        stripped = line.strip()
        if any(stripped.startswith(k) for k in
               ["type", "channel", "txpower", "addr"]):
            lines.append(stripped[:22])

    # Driver info
    driver_path = f"/sys/class/net/{iface_name}/device/driver"
    if os.path.islink(driver_path):
        driver = os.path.basename(os.readlink(driver_path))
        lines.append(f"driver: {driver}")

    # Interface state
    state = _run_cmd(["cat", f"/sys/class/net/{iface_name}/operstate"])
    lines.append(f"state: {state}")

    # PHY info for supported modes and bands
    phy_num = phy_name.replace("phy#", "")
    phy_label = f"phy{phy_num}"
    phy_info = _run_cmd(["iw", "phy", phy_label, "info"])

    # Extract supported modes
    modes = []
    in_modes = False
    for line in phy_info.splitlines():
        stripped = line.strip()
        if "Supported interface modes:" in stripped:
            in_modes = True
            continue
        if in_modes:
            if stripped.startswith("*"):
                modes.append(stripped.lstrip("* "))
            else:
                in_modes = False
    if modes:
        lines.append("-- Modes --")
        for m in modes:
            lines.append(f"  {m}"[:22])

    # Extract bands
    bands = []
    in_band = False
    band_name = ""
    for line in phy_info.splitlines():
        stripped = line.strip()
        if "Band " in stripped:
            band_name = stripped.rstrip(":")
            in_band = True
            bands.append(band_name)
        elif in_band and "Frequencies:" in stripped:
            continue
        elif in_band and stripped.startswith("*") and "MHz" in stripped:
            freq_match = re.search(r"(\d+)\s*MHz", stripped)
            chan_match = re.search(r"\[(\d+)\]", stripped)
            disabled = "(disabled)" in stripped
            if freq_match and chan_match and not disabled:
                bands.append(f"  ch{chan_match.group(1)} {freq_match.group(1)}M")

    if bands:
        lines.append("-- Bands --")
        for b in bands[:20]:
            lines.append(b[:22])

    return lines if lines else ["No info available"]


def _signal_scan(iface_name):
    """Scan nearby APs and return signal data."""
    output = _run_cmd(["iw", "dev", iface_name, "scan", "ap-force"])
    results = []
    current_bss = {}
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("BSS "):
            if current_bss.get("signal"):
                results.append(dict(current_bss))
            bssid = stripped.split()[1].split("(")[0]
            current_bss = {"bssid": bssid, "ssid": "", "signal": ""}
        elif stripped.startswith("SSID:"):
            current_bss["ssid"] = stripped[5:].strip() or "(hidden)"
        elif stripped.startswith("signal:"):
            current_bss["signal"] = stripped[7:].strip()
    if current_bss.get("signal"):
        results.append(dict(current_bss))
    return results


def _toggle_interface(iface_name):
    """Toggle interface up/down."""
    state = _run_cmd(["cat", f"/sys/class/net/{iface_name}/operstate"])
    if state == "up":
        _run_cmd(["ip", "link", "set", iface_name, "down"])
        return f"{iface_name} DOWN"
    else:
        _run_cmd(["ip", "link", "set", iface_name, "up"])
        return f"{iface_name} UP"


# ---------------------------------------------------------------------------
# Background workers
# ---------------------------------------------------------------------------
def _scan_worker(iface_name):
    """Run AP scan in background."""
    global scan_results, status_msg, view_mode, scan_scroll
    with lock:
        status_msg = "Scanning APs..."
    results = _signal_scan(iface_name)
    with lock:
        scan_results = results
        scan_scroll = 0
        if results:
            signals = []
            for r in results:
                match = re.search(r"(-?\d+)", r.get("signal", ""))
                if match:
                    signals.append(int(match.group(1)))
            avg = sum(signals) / len(signals) if signals else 0
            status_msg = f"{len(results)} APs avg:{avg:.0f}dBm"
        else:
            status_msg = "No APs found"
        view_mode = "scan"


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------
def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "ANTENNA CHECK", font=font, fill="#00ccff")

    with lock:
        vm = view_mode
        sel = selected_idx
        sp = scroll_pos
        msg = status_msg
        ifaces = list(iface_list)
        d_lines = list(detail_lines)
        d_scroll = detail_scroll
        s_results = list(scan_results)
        s_scroll = scan_scroll

    if vm == "list":
        y = 16
        if not ifaces:
            d.text((2, 50), "No WiFi ifaces", font=font, fill="#ff4444")
        else:
            end = min(len(ifaces), sp + 6)
            for i in range(sp, end):
                ifc = ifaces[i]
                prefix = ">" if i == sel else " "
                color = "#ffff00" if i == sel else "#cccccc"
                d.text((2, y), f"{prefix}{ifc['name']}", font=font, fill=color)
                y += ROW_H + 2

        d.text((2, 100), msg[:22], font=font, fill="#aaaaaa")
        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "OK:sel K2:toggle K3:x", font=font, fill="#666")

    elif vm == "detail":
        y = 16
        end = min(len(d_lines), d_scroll + VISIBLE_ROWS)
        for i in range(d_scroll, end):
            line = d_lines[i][:22]
            color = "#00ccff" if line.startswith("--") else "#cccccc"
            d.text((2, y), line, font=font, fill=color)
            y += ROW_H

        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "OK:back K1:scan K3:x", font=font, fill="#666")

    elif vm == "scan":
        d.text((70, 1), "SCAN", font=font, fill="#ffaa00")
        y = 16
        if not s_results:
            d.text((2, 50), msg[:22], font=font, fill="#aaaaaa")
        else:
            end = min(len(s_results), s_scroll + 6)
            for i in range(s_scroll, end):
                r = s_results[i]
                ssid = r.get("ssid", "?")[:12]
                sig = r.get("signal", "?")
                d.text((2, y), f"{ssid} {sig}", font=font, fill="#00ff00")
                y += ROW_H + 2

        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "OK:back ^v:scroll", font=font, fill="#666")

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global app_running, selected_idx, scroll_pos, view_mode
    global detail_lines, detail_scroll, status_msg, iface_list
    global scan_scroll

    iface_list = _list_wifi_interfaces()
    status_msg = f"{len(iface_list)} interface(s)"
    last_press = 0.0

    try:
        while app_running:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if btn == "KEY3":
                break

            elif btn == "UP":
                with lock:
                    if view_mode == "list":
                        selected_idx = max(0, selected_idx - 1)
                        if selected_idx < scroll_pos:
                            scroll_pos = selected_idx
                    elif view_mode == "detail":
                        detail_scroll = max(0, detail_scroll - 1)
                    elif view_mode == "scan":
                        scan_scroll = max(0, scan_scroll - 1)

            elif btn == "DOWN":
                with lock:
                    if view_mode == "list":
                        selected_idx = min(len(iface_list) - 1,
                                           selected_idx + 1)
                        if selected_idx >= scroll_pos + 6:
                            scroll_pos = selected_idx - 5
                    elif view_mode == "detail":
                        max_s = max(0, len(detail_lines) - VISIBLE_ROWS)
                        detail_scroll = min(max_s, detail_scroll + 1)
                    elif view_mode == "scan":
                        max_s = max(0, len(scan_results) - 6)
                        scan_scroll = min(max_s, scan_scroll + 1)

            elif btn == "OK":
                with lock:
                    if view_mode == "list" and iface_list:
                        ifc = iface_list[selected_idx]
                        detail_lines = _get_iface_detail(
                            ifc["name"], ifc["phy"])
                        detail_scroll = 0
                        view_mode = "detail"
                    elif view_mode in ("detail", "scan"):
                        view_mode = "list"

            elif btn == "KEY1":
                with lock:
                    if view_mode == "detail" and iface_list:
                        ifc = iface_list[selected_idx]
                threading.Thread(
                    target=_scan_worker, args=(ifc["name"],), daemon=True,
                ).start()

            elif btn == "KEY2":
                with lock:
                    if view_mode == "list" and iface_list:
                        ifc = iface_list[selected_idx]
                        result = _toggle_interface(ifc["name"])
                        status_msg = result
                        iface_list = _list_wifi_interfaces()

            _draw_screen()
            time.sleep(0.1)

    finally:
        app_running = False
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()


if __name__ == "__main__":
    main()
