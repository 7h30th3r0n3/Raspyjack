#!/usr/bin/env python3
"""
RaspyJack Payload -- AP Statistics Dashboard
=============================================
Author: 7h30th3r0n3

Puts wlan1 into monitor mode and runs airodump-ng to capture AP
statistics.  Parses the CSV output every 3 seconds and presents a
scrollable dashboard of access points with details.

Controls:
  UP / DOWN  -- Scroll AP list
  OK         -- Show detailed view for selected AP
  LEFT       -- Back to list from detail view
  KEY1       -- Toggle sort mode (clients / power / channel)
  KEY2       -- Export stats to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/APStats/apstats_YYYYMMDD_HHMMSS.json
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

LOOT_DIR = "/root/Raspyjack/loot/APStats"
CSV_PREFIX = "/tmp/rj_apstats"
SCAN_IFACE = "wlan1"
MON_IFACE = "wlan1mon"
PARSE_INTERVAL = 3.0

SORT_MODES = ["clients", "power", "channel"]
SORT_LABELS = {"clients": "Clients", "power": "Power", "channel": "Chan"}

# ---------------------------------------------------------------------------
# Shared state (immutable swap pattern via lock)
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
ap_list = []          # list of dicts
client_map = {}       # bssid -> list of client dicts
status_msg = "Starting..."
sort_mode = "clients"
scroll = 0
selected = 0
detail_view = False
detail_scroll = 0

# ---------------------------------------------------------------------------
# Monitor mode helpers
# ---------------------------------------------------------------------------

def _enable_monitor():
    """Put SCAN_IFACE into monitor mode, return interface name."""
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
    except Exception as exc:
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
    """Launch airodump-ng in background, writing CSV to CSV_PREFIX."""
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
    """Return list of CSV files written by airodump-ng."""
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
    if not sections:
        sections = raw.split("\n\n")

    # --- AP section (first block) ---
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

            ap = {
                "bssid": bssid,
                "essid": essid,
                "channel": channel,
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

    # --- Client section (second block) ---
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
            cli_power = -100
            try:
                cli_power = int(fields[3].strip()) if fields[3].strip().lstrip("-").isdigit() else -100
            except (ValueError, IndexError):
                pass
            cli_packets = 0
            try:
                cli_packets = int(fields[4].strip()) if fields[4].strip().isdigit() else 0
            except (ValueError, IndexError):
                pass
            probes = fields[6].strip() if len(fields) > 6 else ""
            cli_entry = {
                "mac": cli_mac,
                "power": cli_power,
                "packets": cli_packets,
                "probes": probes,
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
# Sorting
# ---------------------------------------------------------------------------

def _sort_aps(aps, mode):
    """Return a new sorted list of APs."""
    if mode == "clients":
        return sorted(aps, key=lambda a: a["clients"], reverse=True)
    elif mode == "power":
        return sorted(aps, key=lambda a: a["power"], reverse=True)
    elif mode == "channel":
        return sorted(aps, key=lambda a: a["channel"])
    return list(aps)

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_stats():
    """Export current AP stats to JSON."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"apstats_{ts}.json")

    with lock:
        snapshot_aps = list(ap_list)
        snapshot_clients = {k: list(v) for k, v in client_map.items()}

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
    """Render AP list view."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "AP STATS", font=font_obj, fill="#00CCFF")
    with lock:
        sm = sort_mode
    d.text((70, 1), f"[{SORT_LABELS[sm]}]", font=font_obj, fill="#FFAA00")

    with lock:
        aps = _sort_aps(list(ap_list), sort_mode)
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
            line = f"{marker}{essid_short} c{ap['channel']} {ap['clients']}cl"
            d.text((2, y), line[:24], font=font_obj, fill=color)
    else:
        d.text((2, 40), "Scanning...", font=font_obj, fill="#666")
        d.text((2, 55), "Waiting for data", font=font_obj, fill="#666")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Det K1:Sort K3:Quit", font=font_obj, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_detail_view(lcd, font_obj):
    """Render detail view for selected AP."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        aps = _sort_aps(list(ap_list), sort_mode)
        sel = selected
        cls = dict(client_map)
        ds = detail_scroll

    if sel >= len(aps):
        d.text((2, 40), "AP not found", font=font_obj, fill="#FF4444")
        lcd.LCD_ShowImage(img, 0, 0)
        return

    ap = aps[sel]

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), ap["essid"][:18], font=font_obj, fill="#00CCFF")

    # AP details
    d.text((2, 16), f"BSSID: {ap['bssid']}", font=font_obj, fill="#CCCCCC")
    d.text((2, 28), f"Ch:{ap['channel']} Pwr:{ap['power']}dBm", font=font_obj, fill="#CCCCCC")
    d.text((2, 40), f"Enc: {ap['encryption']}", font=font_obj, fill="#CCCCCC")
    d.text((2, 52), f"Cipher:{ap['cipher']} Auth:{ap['auth']}", font=font_obj, fill="#AAAAAA")
    d.text((2, 64), f"Bcn:{ap['beacons']} Data:{ap['data']}", font=font_obj, fill="#AAAAAA")

    # Connected clients
    bssid_clients = cls.get(ap["bssid"], [])
    d.text((2, 78), f"-- Clients ({len(bssid_clients)}) --", font=font_obj, fill="#00FF88")

    visible_clients = bssid_clients[ds:ds + 3]
    for i, cli in enumerate(visible_clients):
        y = 90 + i * ROW_H
        mac_short = cli["mac"][-8:]
        d.text((2, y), f"{mac_short} p:{cli['packets']}", font=font_obj, fill="#FFAA00")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "LEFT:Back K2:Export", font=font_obj, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, scroll, selected, status_msg, sort_mode
    global detail_view, detail_scroll

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

            elif btn == "OK" and not detail_view:
                with lock:
                    if ap_list and 0 <= selected < len(ap_list):
                        detail_view = True
                        detail_scroll = 0
                time.sleep(0.3)

            elif btn == "LEFT" and detail_view:
                detail_view = False
                time.sleep(0.3)

            elif btn == "KEY1" and not detail_view:
                idx = SORT_MODES.index(sort_mode)
                sort_mode = SORT_MODES[(idx + 1) % len(SORT_MODES)]
                with lock:
                    status_msg = f"Sort: {SORT_LABELS[sort_mode]}"
                time.sleep(0.3)

            elif btn == "KEY2":
                with lock:
                    has_data = len(ap_list) > 0
                if has_data:
                    fname = _export_stats()
                    with lock:
                        status_msg = f"Saved: {fname[:16]}"
                else:
                    with lock:
                        status_msg = "No data to export"
                time.sleep(0.3)

            elif btn == "UP":
                if detail_view:
                    detail_scroll = max(0, detail_scroll - 1)
                else:
                    selected = max(0, selected - 1)
                    if selected < scroll:
                        scroll = selected
                time.sleep(0.15)

            elif btn == "DOWN":
                if detail_view:
                    with lock:
                        aps = _sort_aps(list(ap_list), sort_mode)
                        if selected < len(aps):
                            max_ds = max(0, len(client_map.get(aps[selected]["bssid"], [])) - 3)
                            detail_scroll = min(detail_scroll + 1, max_ds)
                else:
                    with lock:
                        max_sel = max(0, len(ap_list) - 1)
                    selected = min(selected + 1, max_sel)
                    if selected >= scroll + ROWS_VISIBLE:
                        scroll = selected - ROWS_VISIBLE + 1
                time.sleep(0.15)

            if detail_view:
                _draw_detail_view(lcd, font_obj)
            else:
                _draw_list_view(lcd, font_obj)

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
        # Cleanup temp CSV files
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
