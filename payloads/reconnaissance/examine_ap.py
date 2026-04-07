#!/usr/bin/env python3
"""
RaspyJack Payload -- Detailed AP Examination
=============================================
Author: 7h30th3r0n3

Scans for access points via airodump-ng and provides in-depth examination
of a selected AP including band detection, encryption details, beacon/data
counts, and connected client enumeration.

Controls:
  UP / DOWN  -- Scroll AP list / detail / client list
  OK         -- Select AP for detailed examination
  LEFT       -- Back to AP list from detail or client view
  KEY1       -- Show connected clients for selected AP
  KEY2       -- Export AP report to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/APExamine/ap_YYYYMMDD_HHMMSS.json
"""

import os
import sys
import time
import signal
import subprocess
import threading
import json
import re
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROWS_VISIBLE = 6
ROW_H = 12

LOOT_DIR = "/root/Raspyjack/loot/APExamine"
CSV_PREFIX = "/tmp/rj_apexam"
SCAN_IFACE = "wlan1"
MON_IFACE = "wlan1mon"
PARSE_INTERVAL = 3.0

# Views
VIEW_LIST = "list"
VIEW_DETAIL = "detail"
VIEW_CLIENTS = "clients"

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
ap_list = []
client_map = {}       # bssid -> list of client dicts
status_msg = "Starting..."
scroll = 0
selected = 0
current_view = VIEW_LIST
detail_scroll = 0
client_scroll = 0

# ---------------------------------------------------------------------------
# Band detection
# ---------------------------------------------------------------------------

def _channel_to_band(channel):
    """Determine WiFi band from channel number."""
    if 1 <= channel <= 14:
        return "2.4GHz"
    elif 32 <= channel <= 177:
        return "5GHz"
    elif channel >= 233:
        return "6GHz"
    return "Unknown"

# ---------------------------------------------------------------------------
# Monitor mode helpers
# ---------------------------------------------------------------------------

def _enable_monitor():
    """Put SCAN_IFACE into monitor mode."""
    try:
        subprocess.run(
            ["airmon-ng", "check", "kill"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
        )
        subprocess.run(
            ["airmon-ng", "start", SCAN_IFACE],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
        )
        return MON_IFACE
    except Exception:
        return None


def _disable_monitor():
    """Restore managed mode."""
    try:
        subprocess.run(
            ["airmon-ng", "stop", MON_IFACE],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
        )
    except Exception:
        pass


def _start_airodump(iface):
    """Launch airodump-ng in background."""
    for old in _find_csv_files():
        try:
            os.remove(old)
        except OSError:
            pass
    proc = subprocess.Popen(
        [
            "airodump-ng", iface,
            "--write", CSV_PREFIX,
            "--output-format", "csv",
            "-a",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc


def _find_csv_files():
    """Return CSV files written by airodump-ng."""
    parent = os.path.dirname(CSV_PREFIX)
    prefix = os.path.basename(CSV_PREFIX)
    found = []
    if os.path.isdir(parent):
        for f in os.listdir(parent):
            if f.startswith(prefix) and f.endswith(".csv"):
                found.append(os.path.join(parent, f))
    return sorted(found)

# ---------------------------------------------------------------------------
# CSV parsing
# ---------------------------------------------------------------------------

def _parse_airodump_csv(filepath):
    """Parse airodump-ng CSV into AP list and client map."""
    aps = []
    clients = {}

    try:
        with open(filepath, "r", errors="ignore") as fh:
            raw = fh.read()
    except Exception:
        return aps, clients

    sections = raw.split("\r\n\r\n")
    if len(sections) < 2:
        sections = raw.split("\n\n")

    # --- AP section ---
    if len(sections) >= 1:
        lines = sections[0].strip().splitlines()
        for line in lines[1:]:
            fields = [f.strip() for f in line.split(",")]
            if len(fields) < 14:
                continue
            bssid = fields[0].strip()
            if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
                continue
            try:
                power = int(fields[8].strip()) if fields[8].strip().lstrip("-").isdigit() else -100
            except (ValueError, IndexError):
                power = -100
            try:
                beacons = int(fields[9].strip()) if fields[9].strip().isdigit() else 0
            except (ValueError, IndexError):
                beacons = 0
            try:
                data_pkts = int(fields[10].strip()) if fields[10].strip().isdigit() else 0
            except (ValueError, IndexError):
                data_pkts = 0
            try:
                channel = int(fields[3].strip()) if fields[3].strip().lstrip("-").isdigit() else 0
            except (ValueError, IndexError):
                channel = 0
            encryption = fields[5].strip() if len(fields) > 5 else ""
            cipher = fields[6].strip() if len(fields) > 6 else ""
            auth = fields[7].strip() if len(fields) > 7 else ""
            essid = fields[13].strip() if len(fields) > 13 else ""
            if not essid:
                essid = "<hidden>"

            band = _channel_to_band(channel)

            ap = {
                "bssid": bssid,
                "essid": essid,
                "channel": channel,
                "band": band,
                "power": power,
                "beacons": beacons,
                "data": data_pkts,
                "encryption": encryption,
                "cipher": cipher,
                "auth": auth,
                "clients": 0,
            }
            aps.append(ap)
            if bssid not in clients:
                clients[bssid] = []

    # --- Client section ---
    if len(sections) >= 2:
        lines = sections[1].strip().splitlines()
        for line in lines[1:]:
            fields = [f.strip() for f in line.split(",")]
            if len(fields) < 6:
                continue
            cli_mac = fields[0].strip()
            if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", cli_mac):
                continue
            assoc_bssid = fields[5].strip() if len(fields) > 5 else ""
            try:
                cli_power = int(fields[3].strip()) if fields[3].strip().lstrip("-").isdigit() else -100
            except (ValueError, IndexError):
                cli_power = -100
            try:
                cli_packets = int(fields[4].strip()) if fields[4].strip().isdigit() else 0
            except (ValueError, IndexError):
                cli_packets = 0
            probes_raw = fields[6].strip() if len(fields) > 6 else ""
            cli_entry = {
                "mac": cli_mac,
                "power": cli_power,
                "packets": cli_packets,
                "probes": probes_raw,
            }
            if assoc_bssid in clients:
                clients[assoc_bssid].append(cli_entry)
            elif re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", assoc_bssid):
                clients[assoc_bssid] = [cli_entry]

    # Count clients per AP
    for ap in aps:
        ap["clients"] = len(clients.get(ap["bssid"], []))

    return aps, clients

# ---------------------------------------------------------------------------
# Background scanner thread
# ---------------------------------------------------------------------------

def _scanner_thread():
    """Periodically re-parse the airodump CSV."""
    global ap_list, client_map, status_msg

    while _running:
        csv_files = _find_csv_files()
        if csv_files:
            newest = csv_files[-1]
            parsed_aps, parsed_clients = _parse_airodump_csv(newest)
            with lock:
                ap_list = list(parsed_aps)
                client_map = dict(parsed_clients)
                status_msg = f"{len(parsed_aps)} APs found"
        time.sleep(PARSE_INTERVAL)

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_report():
    """Export selected AP report to JSON."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"ap_{ts}.json")

    with lock:
        snapshot_aps = list(ap_list)
        snapshot_clients = {k: list(v) for k, v in client_map.items()}
        sel = selected

    # If a specific AP is selected, export just that one
    if 0 <= sel < len(snapshot_aps):
        target_ap = snapshot_aps[sel]
        bssid = target_ap["bssid"]
        data = {
            "timestamp": ts,
            "ap": target_ap,
            "connected_clients": snapshot_clients.get(bssid, []),
        }
    else:
        data = {
            "timestamp": ts,
            "total_aps": len(snapshot_aps),
            "access_points": snapshot_aps,
            "clients_by_bssid": snapshot_clients,
        }

    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)

    return os.path.basename(filepath)

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_list_view(lcd, font_obj):
    """Render AP list for selection."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "AP EXAMINE", font=font_obj, fill="#00CCFF")

    with lock:
        aps = sorted(list(ap_list), key=lambda a: a["power"], reverse=True)
        msg = status_msg
        sel = selected
        sc = scroll

    d.text((2, 15), msg[:24], font=font_obj, fill="#AAAAAA")

    if aps:
        visible = aps[sc:sc + ROWS_VISIBLE]
        for i, ap in enumerate(visible):
            y = 28 + i * ROW_H
            idx = sc + i
            color = "#FFAA00" if idx == sel else "#CCCCCC"
            marker = ">" if idx == sel else " "
            essid_short = ap["essid"][:10]
            enc_short = ap["encryption"][:4]
            line = f"{marker}{essid_short} {enc_short}"
            d.text((2, y), line[:24], font=font_obj, fill=color)
    else:
        d.text((2, 40), "Scanning...", font=font_obj, fill="#666")
        d.text((2, 55), "Waiting for APs", font=font_obj, fill="#666")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Select K3:Quit", font=font_obj, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_detail_view(lcd, font_obj):
    """Render detailed AP examination."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        aps = sorted(list(ap_list), key=lambda a: a["power"], reverse=True)
        sel = selected
        ds = detail_scroll

    if sel >= len(aps):
        d.text((2, 40), "AP lost", font=font_obj, fill="#FF4444")
        lcd.LCD_ShowImage(img, 0, 0)
        return

    ap = aps[sel]

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), ap["essid"][:18], font=font_obj, fill="#00CCFF")

    # Scrollable detail lines
    detail_lines = [
        (f"BSSID: {ap['bssid']}", "#CCCCCC"),
        (f"Channel: {ap['channel']}  Band: {ap['band']}", "#CCCCCC"),
        (f"Enc: {ap['encryption']}", "#CCCCCC"),
        (f"Cipher: {ap['cipher']}", "#CCCCCC"),
        (f"Auth: {ap['auth']}", "#CCCCCC"),
        (f"Power: {ap['power']} dBm", "#AAAAAA"),
        (f"Beacons: {ap['beacons']}", "#AAAAAA"),
        (f"Data pkts: {ap['data']}", "#AAAAAA"),
        (f"Clients: {ap['clients']}", "#00FF88"),
    ]

    visible_lines = detail_lines[ds:ds + 8]
    for i, (text, color) in enumerate(visible_lines):
        y = 16 + i * ROW_H
        d.text((2, y), text[:24], font=font_obj, fill=color)

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "K1:Cli K2:Exp LEFT:Bk", font=font_obj, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_clients_view(lcd, font_obj):
    """Render connected clients for the selected AP."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        aps = sorted(list(ap_list), key=lambda a: a["power"], reverse=True)
        sel = selected
        cls = dict(client_map)
        cs = client_scroll

    if sel >= len(aps):
        d.text((2, 40), "AP lost", font=font_obj, fill="#FF4444")
        lcd.LCD_ShowImage(img, 0, 0)
        return

    ap = aps[sel]
    bssid_clients = cls.get(ap["bssid"], [])

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), f"Clients ({len(bssid_clients)})", font=font_obj, fill="#00CCFF")

    d.text((2, 16), f"AP: {ap['essid'][:18]}", font=font_obj, fill="#AAAAAA")

    if bssid_clients:
        visible = bssid_clients[cs:cs + ROWS_VISIBLE]
        for i, cli in enumerate(visible):
            y = 30 + i * ROW_H
            mac_short = cli["mac"][-8:]
            line = f"{mac_short} {cli['power']}dBm {cli['packets']}p"
            d.text((2, y), line[:24], font=font_obj, fill="#FFAA00")
    else:
        d.text((2, 40), "No clients connected", font=font_obj, fill="#666")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "LEFT:Back K2:Export", font=font_obj, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, scroll, selected, status_msg
    global current_view, detail_scroll, client_scroll

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font_obj = scaled_font()

    airodump_proc = None

    try:
        # Enable monitor mode
        with lock:
            status_msg = "Enabling monitor..."
        mon = _enable_monitor()
        if mon is None:
            with lock:
                status_msg = "Monitor mode failed!"
            time.sleep(2)
            return 1

        # Start airodump-ng
        with lock:
            status_msg = "Starting scan..."
        airodump_proc = _start_airodump(mon)

        # Start parser thread
        parser = threading.Thread(target=_scanner_thread, daemon=True)
        parser.start()

        with lock:
            status_msg = "Scanning..."

        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK" and current_view == VIEW_LIST:
                with lock:
                    if ap_list and 0 <= selected < len(ap_list):
                        current_view = VIEW_DETAIL
                        detail_scroll = 0
                time.sleep(0.3)

            elif btn == "LEFT":
                if current_view == VIEW_CLIENTS:
                    current_view = VIEW_DETAIL
                    time.sleep(0.3)
                elif current_view == VIEW_DETAIL:
                    current_view = VIEW_LIST
                    time.sleep(0.3)

            elif btn == "KEY1" and current_view == VIEW_DETAIL:
                current_view = VIEW_CLIENTS
                client_scroll = 0
                time.sleep(0.3)

            elif btn == "KEY2":
                with lock:
                    has_data = len(ap_list) > 0
                if has_data:
                    fname = _export_report()
                    with lock:
                        status_msg = f"Saved: {fname[:16]}"
                else:
                    with lock:
                        status_msg = "No data to export"
                time.sleep(0.3)

            elif btn == "UP":
                if current_view == VIEW_LIST:
                    selected = max(0, selected - 1)
                    if selected < scroll:
                        scroll = selected
                elif current_view == VIEW_DETAIL:
                    detail_scroll = max(0, detail_scroll - 1)
                elif current_view == VIEW_CLIENTS:
                    client_scroll = max(0, client_scroll - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                if current_view == VIEW_LIST:
                    with lock:
                        max_sel = max(0, len(ap_list) - 1)
                    selected = min(selected + 1, max_sel)
                    if selected >= scroll + ROWS_VISIBLE:
                        scroll = selected - ROWS_VISIBLE + 1
                elif current_view == VIEW_DETAIL:
                    detail_scroll = min(detail_scroll + 1, 4)
                elif current_view == VIEW_CLIENTS:
                    with lock:
                        aps = sorted(list(ap_list), key=lambda a: a["power"], reverse=True)
                        if selected < len(aps):
                            n_cli = len(client_map.get(aps[selected]["bssid"], []))
                            max_cs = max(0, n_cli - ROWS_VISIBLE)
                            client_scroll = min(client_scroll + 1, max_cs)
                time.sleep(0.15)

            if current_view == VIEW_LIST:
                _draw_list_view(lcd, font_obj)
            elif current_view == VIEW_DETAIL:
                _draw_detail_view(lcd, font_obj)
            elif current_view == VIEW_CLIENTS:
                _draw_clients_view(lcd, font_obj)

            time.sleep(0.05)

    finally:
        _running = False
        if airodump_proc is not None:
            try:
                airodump_proc.terminate()
                airodump_proc.wait(timeout=5)
            except Exception:
                pass
        _disable_monitor()
        for f in _find_csv_files():
            try:
                os.remove(f)
            except OSError:
                pass
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
