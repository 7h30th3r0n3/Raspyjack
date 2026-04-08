#!/usr/bin/env python3
"""
RaspyJack Payload -- Client Statistics Dashboard
=================================================
Author: 7h30th3r0n3

Focuses on wireless clients detected via airodump-ng.  Shows client MACs,
associated BSSIDs, probe requests, packet counts, and OUI vendor lookups.

Controls:
  UP / DOWN  -- Scroll client list
  OK         -- Show client detail (probed SSIDs, associated AP)
  LEFT       -- Back to list from detail view
  KEY1       -- Toggle sort mode (packets / probes)
  KEY2       -- Export to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/ClientStats/clients_YYYYMMDD_HHMMSS.json
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

LOOT_DIR = "/root/Raspyjack/loot/ClientStats"
CSV_PREFIX = "/tmp/rj_clistats"
SCAN_IFACE = "wlan1"
MON_IFACE = "wlan1mon"
PARSE_INTERVAL = 3.0

SORT_MODES = ["packets", "probes"]
SORT_LABELS = {"packets": "Pkts", "probes": "Probes"}

# ---------------------------------------------------------------------------
# OUI vendor lookup (built-in, ~30 common vendors)
# ---------------------------------------------------------------------------
OUI_TABLE = {
    "00:50:F2": "Microsoft",
    "00:1A:2B": "Ayecom",
    "00:0C:29": "VMware",
    "00:15:5D": "Hyper-V",
    "00:1B:44": "SanDisk",
    "3C:5A:B4": "Google",
    "DC:A6:32": "RPi",
    "B8:27:EB": "RPi",
    "E4:5F:01": "RPi",
    "28:6C:07": "Xiaomi",
    "F8:A2:D6": "Samsung",
    "AC:37:43": "HTC",
    "A4:77:33": "Google",
    "FC:F5:C4": "Apple",
    "F0:D4:F6": "Apple",
    "AC:BC:32": "Apple",
    "00:25:00": "Apple",
    "88:E9:FE": "Apple",
    "3C:22:FB": "Apple",
    "F4:F5:D8": "Google",
    "30:B4:9E": "TP-Link",
    "50:C7:BF": "TP-Link",
    "98:DA:C4": "TP-Link",
    "CC:32:E5": "TP-Link",
    "00:1E:58": "D-Link",
    "00:26:5A": "D-Link",
    "20:AA:4B": "Cisco",
    "00:1B:2F": "Netgear",
    "E0:46:9A": "Netgear",
    "00:24:D7": "Intel",
    "F8:34:41": "Intel",
    "7C:B0:C2": "Intel",
}


def _oui_lookup(mac):
    """Return vendor string for a MAC prefix or empty string."""
    prefix = mac[:8].upper()
    return OUI_TABLE.get(prefix, "")

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
client_list = []      # list of dicts
ap_info = {}          # bssid -> {essid, channel, encryption, ...}
status_msg = "Starting..."
sort_mode = "packets"
scroll = 0
selected = 0
detail_view = False
detail_scroll = 0

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
    """Parse airodump-ng CSV, return client list and AP info dict."""
    clients = []
    aps = {}

    try:
        with open(filepath, "r", errors="ignore") as fh:
            raw = fh.read()
    except Exception:
        return clients, aps

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
                channel = int(fields[3].strip()) if fields[3].strip().lstrip("-").isdigit() else 0
            except (ValueError, IndexError):
                channel = 0
            encryption = fields[5].strip() if len(fields) > 5 else ""
            essid = fields[13].strip() if len(fields) > 13 else ""
            if not essid:
                essid = "<hidden>"
            aps[bssid] = {
                "essid": essid,
                "channel": channel,
                "encryption": encryption,
            }

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
            try:
                cli_power = int(fields[3].strip()) if fields[3].strip().lstrip("-").isdigit() else -100
            except (ValueError, IndexError):
                cli_power = -100
            try:
                cli_packets = int(fields[4].strip()) if fields[4].strip().isdigit() else 0
            except (ValueError, IndexError):
                cli_packets = 0
            assoc_bssid = fields[5].strip() if len(fields) > 5 else ""
            probes_raw = fields[6].strip() if len(fields) > 6 else ""
            probe_list = [p.strip() for p in probes_raw.split(",") if p.strip()] if probes_raw else []
            vendor = _oui_lookup(cli_mac)
            cli = {
                "mac": cli_mac,
                "bssid": assoc_bssid,
                "power": cli_power,
                "packets": cli_packets,
                "probes": probe_list,
                "vendor": vendor,
            }
            clients.append(cli)

    return clients, aps

# ---------------------------------------------------------------------------
# Background scanner thread
# ---------------------------------------------------------------------------

def _scanner_thread():
    """Periodically re-parse the airodump CSV."""
    global client_list, ap_info, status_msg

    while _running:
        csv_files = _find_csv_files()
        if csv_files:
            newest = csv_files[-1]
            parsed_clients, parsed_aps = _parse_airodump_csv(newest)
            with lock:
                client_list = list(parsed_clients)
                ap_info = dict(parsed_aps)
                status_msg = f"{len(parsed_clients)} clients found"
        time.sleep(PARSE_INTERVAL)

# ---------------------------------------------------------------------------
# Sorting
# ---------------------------------------------------------------------------

def _sort_clients(cls, mode):
    """Return a new sorted list of clients."""
    if mode == "packets":
        return sorted(cls, key=lambda c: c["packets"], reverse=True)
    elif mode == "probes":
        return sorted(cls, key=lambda c: len(c["probes"]), reverse=True)
    return list(cls)

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_stats():
    """Export client stats to JSON."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"clients_{ts}.json")

    with lock:
        snapshot_clients = list(client_list)
        snapshot_aps = dict(ap_info)

    data = {
        "timestamp": ts,
        "total_clients": len(snapshot_clients),
        "clients": snapshot_clients,
        "associated_aps": snapshot_aps,
    }

    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)

    return os.path.basename(filepath)

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_list_view(lcd, font_obj):
    """Render client list view."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "CLIENT STATS", font=font_obj, fill="#00CCFF")
    with lock:
        sm = sort_mode
    d.text((90, 1), f"[{SORT_LABELS[sm]}]", font=font_obj, fill="#FFAA00")

    with lock:
        cls = _sort_clients(list(client_list), sort_mode)
        msg = status_msg
        sel = selected
        sc = scroll

    d.text((2, 15), msg[:24], font=font_obj, fill="#AAAAAA")

    if cls:
        visible = cls[sc:sc + ROWS_VISIBLE]
        for i, cli in enumerate(visible):
            y = 28 + i * ROW_H
            idx = sc + i
            color = "#FFAA00" if idx == sel else "#CCCCCC"
            marker = ">" if idx == sel else " "
            mac_short = cli["mac"][-8:]
            vendor_tag = cli["vendor"][:4] if cli["vendor"] else ""
            line = f"{marker}{mac_short} {vendor_tag} {cli['packets']}p"
            d.text((2, y), line[:24], font=font_obj, fill=color)
    else:
        d.text((2, 40), "Scanning...", font=font_obj, fill="#666")
        d.text((2, 55), "Waiting for clients", font=font_obj, fill="#666")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Det K1:Sort K3:Quit", font=font_obj, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_detail_view(lcd, font_obj):
    """Render detail view for selected client."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        cls = _sort_clients(list(client_list), sort_mode)
        sel = selected
        aps = dict(ap_info)
        ds = detail_scroll

    if sel >= len(cls):
        d.text((2, 40), "Client not found", font=font_obj, fill="#FF4444")
        lcd.LCD_ShowImage(img, 0, 0)
        return

    cli = cls[sel]

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "CLIENT DETAIL", font=font_obj, fill="#00CCFF")

    # Client info
    d.text((2, 16), f"MAC: {cli['mac']}", font=font_obj, fill="#CCCCCC")
    vendor = cli["vendor"] if cli["vendor"] else "Unknown"
    d.text((2, 28), f"Vendor: {vendor}", font=font_obj, fill="#CCCCCC")
    d.text((2, 40), f"Packets: {cli['packets']}  Pwr: {cli['power']}dBm", font=font_obj, fill="#CCCCCC")

    # Associated AP info
    bssid = cli["bssid"]
    if bssid and re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
        ap = aps.get(bssid, {})
        essid = ap.get("essid", "?")
        d.text((2, 54), f"AP: {essid[:16]}", font=font_obj, fill="#00FF88")
        d.text((2, 66), f"BSSID: {bssid}", font=font_obj, fill="#AAAAAA")
    else:
        d.text((2, 54), "AP: Not associated", font=font_obj, fill="#FF6644")

    # Probed SSIDs
    probes = cli["probes"]
    d.text((2, 80), f"-- Probes ({len(probes)}) --", font=font_obj, fill="#00FF88")
    visible_probes = probes[ds:ds + 3]
    for i, probe in enumerate(visible_probes):
        y = 92 + i * ROW_H
        d.text((4, y), probe[:22], font=font_obj, fill="#FFAA00")

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
                    if client_list and 0 <= selected < len(client_list):
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
                    has_data = len(client_list) > 0
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
                        cls = _sort_clients(list(client_list), sort_mode)
                        if selected < len(cls):
                            max_ds = max(0, len(cls[selected]["probes"]) - 3)
                            detail_scroll = min(detail_scroll + 1, max_ds)
                else:
                    with lock:
                        max_sel = max(0, len(client_list) - 1)
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
