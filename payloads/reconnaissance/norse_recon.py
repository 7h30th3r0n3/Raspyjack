#!/usr/bin/env python3
"""
RaspyJack Payload -- Norse Recon Suite
=======================================
Author: 7h30th3r0n3

Multi-tab reconnaissance dashboard combining WiFi AP scanning,
BLE device scanning, and network connection monitoring into a
unified interface on the LCD.

Controls:
  LEFT / RIGHT -- Switch between tabs (WiFi / BLE / Network)
  UP / DOWN    -- Scroll within current tab
  KEY1         -- Force refresh current tab
  KEY2         -- Export all tabs to loot
  KEY3         -- Exit

Loot: /root/Raspyjack/loot/NorseRecon/<timestamp>.json
"""

import os
import sys
import json
import time
import re
import subprocess
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

# ---------------------------------------------------------------------------
# Pin / LCD setup
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT

LOOT_DIR = "/root/Raspyjack/loot/NorseRecon"
ROW_H = 12
ROWS_VISIBLE = 6
TAB_NAMES = ["WiFi", "BLE", "Net"]
TAB_COLORS = ["#00AAFF", "#AA00FF", "#00FF88"]
REFRESH_INTERVAL = 5.0

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True
current_tab = 0  # 0=WiFi, 1=BLE, 2=Network
scroll_pos = 0
refreshing = False

# WiFi data: [{"ssid", "bssid", "signal", "channel", "freq"}]
wifi_aps = []

# BLE data: [{"mac", "name", "rssi"}]
ble_devices = []

# Network data: [{"proto", "local", "remote", "state"}]
net_connections = []
arp_entries = []  # [{"ip", "mac", "iface"}]


# ---------------------------------------------------------------------------
# WiFi scan
# ---------------------------------------------------------------------------
def _scan_wifi():
    """Scan nearby WiFi APs via iw dev wlan0 scan."""
    try:
        result = subprocess.run(
            ["iw", "dev", "wlan0", "scan"],
            capture_output=True, text=True, timeout=15,
        )
    except FileNotFoundError:
        return []
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []

    aps = []
    current = {}

    for line in result.stdout.splitlines():
        stripped = line.strip()

        if stripped.startswith("BSS "):
            if current.get("bssid"):
                aps.append(dict(current))
            bssid_match = re.search(
                r"([\da-fA-F]{2}:){5}[\da-fA-F]{2}", stripped
            )
            current = {
                "bssid": bssid_match.group(0).upper() if bssid_match else "",
                "ssid": "",
                "signal": -100,
                "channel": 0,
                "freq": "",
            }

        elif stripped.startswith("SSID:"):
            ssid = stripped[5:].strip()
            current["ssid"] = ssid if ssid else "<hidden>"

        elif stripped.startswith("signal:"):
            sig_match = re.search(r"-?\d+\.?\d*", stripped)
            if sig_match:
                current["signal"] = int(float(sig_match.group(0)))

        elif stripped.startswith("DS Parameter set: channel"):
            ch_match = re.search(r"\d+", stripped.split("channel")[-1])
            if ch_match:
                current["channel"] = int(ch_match.group(0))

        elif stripped.startswith("freq:"):
            freq_match = re.search(r"\d+", stripped)
            if freq_match:
                current["freq"] = freq_match.group(0)

    if current.get("bssid"):
        aps.append(dict(current))

    # Sort by signal strength (strongest first)
    aps.sort(key=lambda a: a["signal"], reverse=True)
    return aps


# ---------------------------------------------------------------------------
# BLE scan
# ---------------------------------------------------------------------------
def _scan_ble():
    """Scan BLE devices via hcitool lescan --passive."""
    devices = []

    # Use hcitool lescan with a short timeout
    try:
        # Start lescan in background, collect for 3 seconds
        proc = subprocess.Popen(
            ["hcitool", "lescan", "--passive"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        time.sleep(3)
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()

        output = proc.stdout.read()
        seen_macs = set()

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            # Format: XX:XX:XX:XX:XX:XX DeviceName
            mac_match = re.match(
                r"([\da-fA-F]{2}:){5}[\da-fA-F]{2}", stripped
            )
            if mac_match:
                mac = mac_match.group(0).upper()
                if mac in seen_macs:
                    continue
                seen_macs.add(mac)
                name = stripped[len(mac):].strip()
                if not name or name == "(unknown)":
                    name = ""
                devices.append({
                    "mac": mac,
                    "name": name[:20],
                    "rssi": "",
                })

    except FileNotFoundError:
        # hcitool not available, try bluetoothctl
        try:
            result = subprocess.run(
                ["bluetoothctl", "devices"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3 and parts[0] == "Device":
                    mac = parts[1].upper()
                    name = " ".join(parts[2:])[:20]
                    devices.append({"mac": mac, "name": name, "rssi": ""})
        except Exception:
            pass
    except Exception:
        pass

    return devices


# ---------------------------------------------------------------------------
# Network scan
# ---------------------------------------------------------------------------
def _scan_network():
    """Get ARP entries and active connections."""
    arp = []
    conns = []

    # ARP table
    try:
        result = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 4:
                ip = parts[0]
                # Find MAC (lladdr)
                mac = ""
                if "lladdr" in parts:
                    idx = parts.index("lladdr") + 1
                    if idx < len(parts):
                        mac = parts[idx].upper()
                iface = ""
                if "dev" in parts:
                    idx = parts.index("dev") + 1
                    if idx < len(parts):
                        iface = parts[idx]
                state = parts[-1] if parts else ""
                arp.append({
                    "ip": ip,
                    "mac": mac,
                    "iface": iface,
                    "state": state,
                })
    except Exception:
        pass

    # Active connections via ss
    try:
        result = subprocess.run(
            ["ss", "-tulnp"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines()[1:]:  # skip header
            parts = line.split()
            if len(parts) >= 5:
                proto = parts[0]
                local = parts[4]
                state = parts[1] if len(parts) > 1 else ""
                conns.append({
                    "proto": proto,
                    "local": local[:22],
                    "state": state,
                })
    except Exception:
        pass

    return arp, conns


# ---------------------------------------------------------------------------
# Background refresh thread
# ---------------------------------------------------------------------------
def _refresh_tab(tab_idx):
    """Refresh data for a specific tab."""
    global wifi_aps, ble_devices, net_connections, arp_entries, refreshing

    with lock:
        refreshing = True

    try:
        if tab_idx == 0:
            data = _scan_wifi()
            with lock:
                wifi_aps = data
        elif tab_idx == 1:
            data = _scan_ble()
            with lock:
                ble_devices = data
        elif tab_idx == 2:
            arp, conns = _scan_network()
            with lock:
                arp_entries = arp
                net_connections = conns
    except Exception:
        pass
    finally:
        with lock:
            refreshing = False


def _auto_refresh_thread():
    """Auto-refresh current tab every REFRESH_INTERVAL seconds."""
    while running:
        with lock:
            tab = current_tab
        _refresh_tab(tab)
        deadline = time.time() + REFRESH_INTERVAL
        while time.time() < deadline and running:
            time.sleep(0.2)


# ---------------------------------------------------------------------------
# Loot export
# ---------------------------------------------------------------------------
def _export_loot():
    """Export all tab data to JSON loot file."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"norse_{ts}.json")

    with lock:
        data = {
            "timestamp": ts,
            "wifi_aps": list(wifi_aps),
            "ble_devices": list(ble_devices),
            "arp_table": list(arp_entries),
            "network_connections": list(net_connections),
            "summary": {
                "wifi_count": len(wifi_aps),
                "ble_count": len(ble_devices),
                "arp_count": len(arp_entries),
                "conn_count": len(net_connections),
            },
        }

    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)

    return filepath


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------
def _draw_header(d, font):
    """Draw header with tab bar and summary counts."""
    with lock:
        tab = current_tab
        n_wifi = len(wifi_aps)
        n_ble = len(ble_devices)
        n_net = len(arp_entries)
        is_refreshing = refreshing

    # Header background
    d.rectangle((0, 0, 127, 13), fill="#111")

    # Tab indicators
    tab_w = 42
    for i, (name, color) in enumerate(zip(TAB_NAMES, TAB_COLORS)):
        x = i * tab_w + 1
        if i == tab:
            d.rectangle((x, 0, x + tab_w - 2, 13), fill=color)
            d.text((x + 2, 1), name, font=font, fill="#000")
        else:
            d.text((x + 2, 1), name, font=font, fill="#666")

    # Refresh indicator
    if is_refreshing:
        d.ellipse((122, 3, 126, 7), fill="#FFAA00")

    # Summary line
    summary = f"AP:{n_wifi} BLE:{n_ble} Net:{n_net}"
    d.text((2, 15), summary, font=font, fill="#888")


def _draw_footer(d, font, text):
    """Draw footer bar."""
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font, fill="#AAA")


def _draw_wifi_tab(d, font, sc):
    """Draw WiFi AP list."""
    with lock:
        ap_list = list(wifi_aps)

    if not ap_list:
        d.text((6, 40), "No APs found", font=font, fill="#666")
        d.text((6, 52), "Ensure wlan0 is up", font=font, fill="#555")
        return

    visible = ap_list[sc:sc + ROWS_VISIBLE]
    for i, ap in enumerate(visible):
        y = 28 + i * ROW_H
        ssid = ap["ssid"][:10] if ap["ssid"] else "?"
        sig = ap["signal"]
        ch = ap["channel"]

        # Signal strength color
        if sig >= -50:
            color = "#00FF00"
        elif sig >= -70:
            color = "#FFAA00"
        else:
            color = "#FF4444"

        line = f"{ssid:<10s} {sig:>4d} ch{ch}"
        d.text((1, y), line[:22], font=font, fill=color)


def _draw_ble_tab(d, font, sc):
    """Draw BLE device list."""
    with lock:
        dev_list = list(ble_devices)

    if not dev_list:
        d.text((6, 40), "No BLE devices", font=font, fill="#666")
        d.text((6, 52), "found nearby", font=font, fill="#555")
        return

    visible = dev_list[sc:sc + ROWS_VISIBLE]
    for i, dev in enumerate(visible):
        y = 28 + i * ROW_H
        mac_short = dev["mac"][9:]  # last 4 octets
        name = dev["name"][:10] if dev["name"] else "unknown"
        line = f"{mac_short} {name}"
        d.text((1, y), line[:22], font=font, fill="#CC88FF")


def _draw_net_tab(d, font, sc):
    """Draw network info (ARP + connections)."""
    with lock:
        arp_list = list(arp_entries)
        conn_list = list(net_connections)

    # Combine ARP and connections into a single scrollable list
    lines = []

    # ARP section header
    lines.append(("-- ARP Table --", "#666"))
    for entry in arp_list:
        ip = entry["ip"][:15]
        mac_short = entry["mac"][-8:] if entry["mac"] else "???"
        state = entry["state"][:5]
        lines.append((f"{ip} {mac_short}", "#00FF88"))

    # Connections section header
    lines.append(("-- Listening --", "#666"))
    for conn in conn_list:
        proto = conn["proto"][:4]
        local = conn["local"][:17]
        lines.append((f"{proto} {local}", "#88FFCC"))

    if not lines:
        d.text((6, 40), "No network data", font=font, fill="#666")
        return

    visible = lines[sc:sc + ROWS_VISIBLE]
    for i, (text, color) in enumerate(visible):
        y = 28 + i * ROW_H
        d.text((1, y), text[:22], font=font, fill=color)


def _draw_frame(lcd, font):
    """Render the current view."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, font)

    with lock:
        tab = current_tab
        sc = scroll_pos

    if tab == 0:
        _draw_wifi_tab(d, font, sc)
        with lock:
            total = len(wifi_aps)
    elif tab == 1:
        _draw_ble_tab(d, font, sc)
        with lock:
            total = len(ble_devices)
    elif tab == 2:
        _draw_net_tab(d, font, sc)
        with lock:
            total = len(arp_entries) + len(net_connections) + 2  # +2 headers

    # Scroll indicator
    if total > ROWS_VISIBLE:
        area_h = ROWS_VISIBLE * ROW_H
        ind_h = max(4, int(ROWS_VISIBLE / max(total, 1) * area_h))
        ind_y = 28 + int(sc / max(total, 1) * area_h)
        d.rectangle((126, ind_y, 127, ind_y + ind_h), fill="#444")

    footer_tab = TAB_NAMES[tab]
    _draw_footer(d, font, f"[{footer_tab}] LR:Tab K3:Exit")
    lcd.LCD_ShowImage(img, 0, 0)


def _show_message(lcd, font, line1, line2=""):
    """Show a brief message."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((10, 50), line1, font=font, fill="#00FF00")
    if line2:
        d.text((4, 65), line2, font=font, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global running, current_tab, scroll_pos

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font = scaled_font()

    # Splash screen
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 12), "NORSE RECON", font=font, fill="#00AAFF")
    d.text((4, 28), "Unified multi-band", font=font, fill="#888")
    d.text((4, 40), "reconnaissance suite", font=font, fill="#888")
    d.text((4, 56), "Tab 1: WiFi APs", font=font, fill="#00AAFF")
    d.text((4, 68), "Tab 2: BLE Devices", font=font, fill="#AA00FF")
    d.text((4, 80), "Tab 3: Network/ARP", font=font, fill="#00FF88")
    d.text((4, 96), "K1:Refresh K2:Export", font=font, fill="#666")
    d.text((4, 108), "K3:Exit", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)
    time.sleep(2.0)

    running = True

    # Start auto-refresh thread
    threading.Thread(target=_auto_refresh_thread, daemon=True).start()

    # Initial refresh of first tab
    threading.Thread(target=_refresh_tab, args=(0,), daemon=True).start()

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                running = False
                # Auto-export on exit if there is data
                with lock:
                    has_data = (
                        len(wifi_aps) > 0
                        or len(ble_devices) > 0
                        or len(arp_entries) > 0
                    )
                if has_data:
                    _export_loot()
                break

            elif btn == "LEFT":
                with lock:
                    current_tab = (current_tab - 1) % len(TAB_NAMES)
                    scroll_pos = 0
                # Trigger immediate refresh
                with lock:
                    tab = current_tab
                threading.Thread(
                    target=_refresh_tab, args=(tab,), daemon=True
                ).start()
                time.sleep(0.2)

            elif btn == "RIGHT":
                with lock:
                    current_tab = (current_tab + 1) % len(TAB_NAMES)
                    scroll_pos = 0
                with lock:
                    tab = current_tab
                threading.Thread(
                    target=_refresh_tab, args=(tab,), daemon=True
                ).start()
                time.sleep(0.2)

            elif btn == "KEY1":
                with lock:
                    tab = current_tab
                threading.Thread(
                    target=_refresh_tab, args=(tab,), daemon=True
                ).start()
                time.sleep(0.3)

            elif btn == "KEY2":
                with lock:
                    has_data = (
                        len(wifi_aps) > 0
                        or len(ble_devices) > 0
                        or len(arp_entries) > 0
                    )
                if has_data:
                    path = _export_loot()
                    _show_message(lcd, font, "Exported!", path[-20:])
                else:
                    _show_message(lcd, font, "No data yet")
                time.sleep(0.3)

            elif btn == "UP":
                scroll_pos = max(0, scroll_pos - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                with lock:
                    tab = current_tab
                    if tab == 0:
                        total = len(wifi_aps)
                    elif tab == 1:
                        total = len(ble_devices)
                    else:
                        total = len(arp_entries) + len(net_connections) + 2
                max_scroll = max(0, total - ROWS_VISIBLE)
                scroll_pos = min(scroll_pos + 1, max_scroll)
                time.sleep(0.15)

            _draw_frame(lcd, font)
            time.sleep(0.05)

    finally:
        running = False
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
