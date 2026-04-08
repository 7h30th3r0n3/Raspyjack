#!/usr/bin/env python3
"""
RaspyJack Payload -- Client & AP Filter
=========================================
Author: 7h30th3r0n3

Two modes: Connected Clients (station dump) and Open APs (scan).
Filter by signal strength, export results to loot directory.

Controls
--------
  UP / DOWN   -- Scroll through entries
  KEY1        -- Filter weak signals (toggle threshold)
  KEY2        -- Toggle mode (Clients / Open APs)
  OK          -- Export current list
  KEY3        -- Exit
"""

import os
import sys
import time
import signal
import subprocess
import json
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
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
EXPORT_DIR = "/root/Raspyjack/loot/Filters"
DEBOUNCE = 0.25
WLAN_IF = "wlan0"

GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
font_sm = scaled_font(8)
font_md = scaled_font(10)

_running = True


def _cleanup(*_args):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# Data parsers
# ---------------------------------------------------------------------------

def _parse_station_dump():
    """Parse iw station dump output into client entries."""
    clients = []
    try:
        result = subprocess.run(
            ["iw", "dev", WLAN_IF, "station", "dump"],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout
    except (subprocess.SubprocessError, OSError):
        return clients

    current_mac = None
    current_signal = -100
    current_rx = 0
    current_tx = 0

    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Station "):
            if current_mac:
                clients.append({
                    "mac": current_mac,
                    "signal": current_signal,
                    "rx": current_rx,
                    "tx": current_tx,
                })
            parts = stripped.split()
            current_mac = parts[1] if len(parts) > 1 else "?"
            current_signal = -100
            current_rx = 0
            current_tx = 0
        elif "signal:" in stripped:
            try:
                val = stripped.split("signal:")[1].strip().split()[0]
                current_signal = int(val)
            except (IndexError, ValueError):
                pass
        elif "rx bytes:" in stripped:
            try:
                current_rx = int(stripped.split(":")[1].strip())
            except (IndexError, ValueError):
                pass
        elif "tx bytes:" in stripped:
            try:
                current_tx = int(stripped.split(":")[1].strip())
            except (IndexError, ValueError):
                pass

    if current_mac:
        clients.append({
            "mac": current_mac,
            "signal": current_signal,
            "rx": current_rx,
            "tx": current_tx,
        })

    return clients


def _parse_open_aps():
    """Parse iw scan output for open (no encryption) APs."""
    aps = []
    try:
        result = subprocess.run(
            ["iw", "dev", WLAN_IF, "scan"],
            capture_output=True, text=True, timeout=30,
        )
        output = result.stdout
    except (subprocess.SubprocessError, OSError):
        return aps

    current_bssid = None
    current_ssid = ""
    current_signal = -100
    current_channel = 0
    has_crypto = False

    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("BSS "):
            if current_bssid and not has_crypto:
                aps.append({
                    "bssid": current_bssid,
                    "ssid": current_ssid or "<hidden>",
                    "signal": current_signal,
                    "channel": current_channel,
                })
            bss_part = stripped.split("BSS ")[1].split("(")[0].strip()
            current_bssid = bss_part
            current_ssid = ""
            current_signal = -100
            current_channel = 0
            has_crypto = False
        elif stripped.startswith("SSID:"):
            current_ssid = stripped.split("SSID:", 1)[1].strip()
        elif stripped.startswith("signal:"):
            try:
                current_signal = int(float(stripped.split(":")[1].strip().split()[0]))
            except (IndexError, ValueError):
                pass
        elif "primary channel:" in stripped.lower():
            try:
                current_channel = int(stripped.split(":")[1].strip())
            except (IndexError, ValueError):
                pass
        elif "WPA" in stripped or "WEP" in stripped or "RSN" in stripped:
            has_crypto = True

    if current_bssid and not has_crypto:
        aps.append({
            "bssid": current_bssid,
            "ssid": current_ssid or "<hidden>",
            "signal": current_signal,
            "channel": current_channel,
        })

    return aps


def _format_bytes(n):
    """Format byte count to human-readable."""
    if n < 1024:
        return f"{n}B"
    if n < 1048576:
        return f"{n // 1024}K"
    return f"{n // 1048576}M"


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_list(entries, mode_name):
    """Export current list to JSON."""
    os.makedirs(EXPORT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(EXPORT_DIR, f"{mode_name}_{ts}.json")
    with open(path, "w") as fh:
        json.dump({"mode": mode_name, "entries": entries, "timestamp": ts}, fh, indent=2)
    return path


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(d, title, count):
    """Draw header bar with title and entry count."""
    d.rectangle([0, 0, 127, 13], fill=(0, 60, 80))
    d.text((2, 1), title, fill=(0, 220, 255), font=font_md)
    d.text((90, 1), f"({count})", fill=(150, 150, 150), font=font_md)


def _draw_footer(d, text):
    """Draw footer bar."""
    d.rectangle([0, 116, 127, 127], fill=(40, 40, 40))
    d.text((2, 117), text, fill=(180, 180, 180), font=font_sm)


def _draw_client_list(d, clients, scroll_pos):
    """Draw connected clients list."""
    y = 16
    visible = 8
    end = min(scroll_pos + visible, len(clients))
    for i in range(scroll_pos, end):
        c = clients[i]
        row_y = y + (i - scroll_pos) * 12
        mac_short = c["mac"][-8:]
        sig = c["signal"]
        sig_color = (0, 255, 0) if sig > -50 else (255, 255, 0) if sig > -70 else (255, 80, 80)
        d.text((2, row_y), mac_short, fill=(200, 200, 200), font=font_sm)
        d.text((65, row_y), f"{sig}dBm", fill=sig_color, font=font_sm)
        d.text((105, row_y), _format_bytes(c["rx"]), fill=(100, 100, 100), font=font_sm)


def _draw_ap_list(d, aps, scroll_pos):
    """Draw open APs list."""
    y = 16
    visible = 8
    end = min(scroll_pos + visible, len(aps))
    for i in range(scroll_pos, end):
        ap = aps[i]
        row_y = y + (i - scroll_pos) * 12
        ssid_display = ap["ssid"][:10]
        sig = ap["signal"]
        sig_color = (0, 255, 0) if sig > -50 else (255, 255, 0) if sig > -70 else (255, 80, 80)
        d.text((2, row_y), ssid_display, fill=(200, 200, 200), font=font_sm)
        d.text((72, row_y), f"{sig}dBm", fill=sig_color, font=font_sm)
        d.text((108, row_y), f"Ch{ap['channel']}", fill=(100, 100, 100), font=font_sm)


def _render(mode, entries, scroll_pos, status_msg, sig_threshold):
    """Render the full frame."""
    img = Image.new("RGB", (WIDTH, HEIGHT), (0, 0, 0))
    d = ScaledDraw(img)

    filtered = [e for e in entries if e.get("signal", -100) >= sig_threshold]

    if mode == 0:
        _draw_header(d, "Clients", len(filtered))
        _draw_client_list(d, filtered, scroll_pos)
    else:
        _draw_header(d, "Open APs", len(filtered))
        _draw_ap_list(d, filtered, scroll_pos)

    _draw_footer(d, status_msg)
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

SIGNAL_THRESHOLDS = [-100, -80, -70, -60, -50]


def main():
    mode = 0  # 0 = clients, 1 = open APs
    scroll_pos = 0
    sig_idx = 0
    sig_threshold = SIGNAL_THRESHOLDS[sig_idx]
    status_msg = "K1:Filter K2:Mode"
    last_input = 0.0
    last_scan = 0.0
    entries = []
    scan_interval = 5.0

    while _running:
        now = time.time()

        if now - last_scan > scan_interval:
            last_scan = now
            if mode == 0:
                entries = _parse_station_dump()
            else:
                entries = _parse_open_aps()
            entries.sort(key=lambda e: e.get("signal", -100), reverse=True)

        btn = get_button(PINS, GPIO)
        if btn and (now - last_input) > DEBOUNCE:
            last_input = now

            if btn == "KEY3":
                _cleanup()
                break

            elif btn == "UP":
                scroll_pos = max(0, scroll_pos - 1)

            elif btn == "DOWN":
                filtered_count = sum(1 for e in entries if e.get("signal", -100) >= sig_threshold)
                max_scroll = max(0, filtered_count - 8)
                scroll_pos = min(scroll_pos + 1, max_scroll)

            elif btn == "KEY1":
                sig_idx = (sig_idx + 1) % len(SIGNAL_THRESHOLDS)
                sig_threshold = SIGNAL_THRESHOLDS[sig_idx]
                scroll_pos = 0
                if sig_threshold == -100:
                    status_msg = "Filter: OFF"
                else:
                    status_msg = f"Filter: >{sig_threshold}dBm"

            elif btn == "KEY2":
                mode = 1 - mode
                scroll_pos = 0
                last_scan = 0.0
                status_msg = "Clients" if mode == 0 else "Open APs"

            elif btn == "OK":
                mode_name = "clients" if mode == 0 else "open_aps"
                filtered = [e for e in entries if e.get("signal", -100) >= sig_threshold]
                try:
                    _export_list(filtered, mode_name)
                    status_msg = "Exported!"
                except OSError:
                    status_msg = "Export failed"

        _render(mode, entries, scroll_pos, status_msg, sig_threshold)
        time.sleep(0.1)


if __name__ == "__main__":
    try:
        main()
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
