#!/usr/bin/env python3
"""
RaspyJack Payload -- MAC Address OUI Vendor Lookup
====================================================
Author: 7h30th3r0n3

Resolves MAC addresses to vendor names using an OUI database.  Downloads
the IEEE OUI list if available, otherwise falls back to a built-in dict
of ~200 common vendors.

Setup / Prerequisites:
  - Auto-downloads IEEE OUI database on first run (needs internet).
  - Falls back to built-in ~200 vendors if offline.  Reads discovered MACs from existing Nmap loot
files and performs a live ARP scan of the current subnet.

Controls:
  OK        -- Live ARP scan of current subnet
  UP / DOWN -- Scroll MAC/vendor list
  KEY1      -- Reload from loot files
  KEY2      -- Export results to loot
  KEY3      -- Exit

Loot: /root/Raspyjack/loot/MACLookup/<timestamp>.json
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
LOOT_DIR = "/root/Raspyjack/loot/MACLookup"
NMAP_LOOT = "/root/Raspyjack/loot/Nmap"
OUI_CACHE = "/root/Raspyjack/loot/MACLookup/oui_cache.json"
OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
os.makedirs(LOOT_DIR, exist_ok=True)

ROWS_VISIBLE = 8
ROW_H = 12

# ---------------------------------------------------------------------------
# Built-in OUI fallback (~200 common vendors)
# ---------------------------------------------------------------------------
BUILTIN_OUI = {
    "00:00:0C": "Cisco", "00:01:42": "Cisco", "00:1A:A1": "Cisco",
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware",
    "00:1C:42": "Parallels", "08:00:27": "VirtualBox",
    "00:03:FF": "Microsoft", "00:0D:3A": "Microsoft", "00:12:5A": "Microsoft",
    "00:15:5D": "Microsoft", "00:17:FA": "Microsoft", "00:1D:D8": "Microsoft",
    "00:25:AE": "Microsoft", "28:18:78": "Microsoft",
    "3C:D9:2B": "HP", "00:1A:4B": "HP", "00:21:5A": "HP",
    "00:23:7D": "HP", "00:25:B3": "HP", "D4:85:64": "HP",
    "00:1E:68": "Quanta", "00:26:2D": "Wistron",
    "AC:DE:48": "Private", "00:1A:11": "Google", "3C:5A:B4": "Google",
    "54:60:09": "Google", "F4:F5:D8": "Google", "A4:77:33": "Google",
    "00:1B:63": "Apple", "00:03:93": "Apple", "00:05:02": "Apple",
    "00:0A:27": "Apple", "00:0A:95": "Apple", "00:0D:93": "Apple",
    "00:10:FA": "Apple", "00:11:24": "Apple", "00:14:51": "Apple",
    "00:16:CB": "Apple", "00:17:F2": "Apple", "00:19:E3": "Apple",
    "00:1B:63": "Apple", "00:1C:B3": "Apple", "00:1D:4F": "Apple",
    "00:1E:52": "Apple", "00:1E:C2": "Apple", "00:1F:5B": "Apple",
    "00:1F:F3": "Apple", "00:21:E9": "Apple", "00:22:41": "Apple",
    "00:23:12": "Apple", "00:23:32": "Apple", "00:23:6C": "Apple",
    "00:23:DF": "Apple", "00:24:36": "Apple", "00:25:00": "Apple",
    "00:25:4B": "Apple", "00:25:BC": "Apple", "00:26:08": "Apple",
    "00:26:4A": "Apple", "00:26:B0": "Apple", "00:26:BB": "Apple",
    "28:CF:DA": "Apple", "2C:BE:08": "Apple", "34:15:9E": "Apple",
    "3C:07:54": "Apple", "40:A6:D9": "Apple", "44:2A:60": "Apple",
    "48:60:BC": "Apple", "4C:57:CA": "Apple", "54:26:96": "Apple",
    "58:55:CA": "Apple", "5C:59:48": "Apple", "60:03:08": "Apple",
    "64:A3:CB": "Apple", "68:5B:35": "Apple", "6C:40:08": "Apple",
    "70:DE:E2": "Apple", "78:31:C1": "Apple", "7C:6D:62": "Apple",
    "80:E6:50": "Apple", "84:38:35": "Apple", "88:53:95": "Apple",
    "8C:85:90": "Apple", "90:84:0D": "Apple", "98:01:A7": "Apple",
    "9C:20:7B": "Apple", "A4:D1:8C": "Apple", "A8:88:08": "Apple",
    "AC:87:A3": "Apple", "B0:65:BD": "Apple", "B8:17:C2": "Apple",
    "BC:52:B7": "Apple", "C8:2A:14": "Apple", "CC:08:E0": "Apple",
    "D0:23:DB": "Apple", "D4:F4:6F": "Apple", "DC:2B:2A": "Apple",
    "E0:B9:BA": "Apple", "E4:CE:8F": "Apple", "F0:B4:79": "Apple",
    "F4:5C:89": "Apple", "F8:1E:DF": "Apple",
    "00:04:4B": "Nvidia", "00:1B:21": "Intel", "00:1E:64": "Intel",
    "00:1E:67": "Intel", "00:1F:3B": "Intel", "00:1F:3C": "Intel",
    "00:22:FA": "Intel", "00:24:D6": "Intel", "00:26:C6": "Intel",
    "00:26:C7": "Intel", "00:27:10": "Intel", "34:02:86": "Intel",
    "3C:97:0E": "Intel", "40:25:C2": "Intel", "4C:34:88": "Intel",
    "58:94:6B": "Intel", "5C:51:4F": "Intel", "64:D4:DA": "Intel",
    "68:05:CA": "Intel", "6C:29:95": "Intel", "7C:5C:F8": "Intel",
    "80:86:F2": "Intel", "84:3A:4B": "Intel", "8C:EC:4B": "Intel",
    "A0:36:9F": "Intel", "AC:FD:CE": "Intel", "B4:6B:FC": "Intel",
    "B8:08:CF": "Intel", "C8:5B:76": "Intel", "D0:7E:35": "Intel",
    "DC:53:60": "Intel", "E8:B1:FC": "Intel", "F8:63:3F": "Intel",
    "00:0E:C6": "ASUS", "00:11:2F": "ASUS", "00:15:F2": "ASUS",
    "00:1A:92": "ASUS", "00:1D:60": "ASUS", "00:1E:8C": "ASUS",
    "00:22:15": "ASUS", "00:23:54": "ASUS", "00:24:8C": "ASUS",
    "00:26:18": "ASUS", "1C:87:2C": "ASUS", "2C:56:DC": "ASUS",
    "30:5A:3A": "ASUS", "38:D5:47": "ASUS", "50:46:5D": "ASUS",
    "54:04:A6": "ASUS", "60:45:CB": "ASUS", "74:D0:2B": "ASUS",
    "08:60:6E": "ASUS", "B0:6E:BF": "ASUS", "BC:EE:7B": "ASUS",
    "00:18:E7": "Cameo", "00:1F:1F": "Edimax", "00:0E:2E": "Edimax",
    "00:50:FC": "Edimax", "74:DA:38": "Edimax",
    "00:0F:66": "Cisco-Linksys", "00:12:17": "Cisco-Linksys",
    "00:14:BF": "Cisco-Linksys", "00:16:B6": "Cisco-Linksys",
    "00:18:39": "Cisco-Linksys", "00:18:F8": "Cisco-Linksys",
    "00:1A:70": "Cisco-Linksys", "00:1C:10": "Cisco-Linksys",
    "00:1D:7E": "Cisco-Linksys", "00:1E:E5": "Cisco-Linksys",
    "00:21:29": "Cisco-Linksys", "00:22:6B": "Cisco-Linksys",
    "00:23:69": "Cisco-Linksys", "00:25:9C": "Cisco-Linksys",
    "20:AA:4B": "Cisco-Linksys", "58:6D:8F": "Cisco-Linksys",
    "C0:C1:C0": "Cisco-Linksys",
    "00:18:4D": "Netgear", "00:1B:2F": "Netgear", "00:1E:2A": "Netgear",
    "00:1F:33": "Netgear", "00:22:3F": "Netgear", "00:24:B2": "Netgear",
    "00:26:F2": "Netgear", "20:4E:7F": "Netgear", "2C:B0:5D": "Netgear",
    "30:46:9A": "Netgear", "44:94:FC": "Netgear", "4C:60:DE": "Netgear",
    "6C:B0:CE": "Netgear", "84:1B:5E": "Netgear", "A0:21:B7": "Netgear",
    "A4:2B:8C": "Netgear", "B0:7F:B9": "Netgear", "C0:3F:0E": "Netgear",
    "C4:3D:C7": "Netgear", "CC:40:D0": "Netgear", "E0:46:9A": "Netgear",
    "E0:91:F5": "Netgear",
    "00:09:0F": "Fortinet", "00:60:6E": "Dlink", "00:05:5D": "Dlink",
    "00:0D:88": "Dlink", "00:0F:3D": "Dlink", "00:11:95": "Dlink",
    "00:13:46": "Dlink", "00:15:E9": "Dlink", "00:17:9A": "Dlink",
    "00:19:5B": "Dlink", "00:1B:11": "Dlink", "00:1C:F0": "Dlink",
    "00:1E:58": "Dlink", "00:21:91": "Dlink", "00:22:B0": "Dlink",
    "00:24:01": "Dlink", "00:26:5A": "Dlink", "1C:7E:E5": "Dlink",
    "28:10:7B": "Dlink", "34:08:04": "Dlink", "5C:D9:98": "Dlink",
    "B8:A3:86": "Dlink", "C8:BE:19": "Dlink", "CC:B2:55": "Dlink",
    "FC:75:16": "Dlink",
    "00:1F:CD": "Samsung", "00:21:19": "Samsung", "00:23:39": "Samsung",
    "00:24:54": "Samsung", "00:25:66": "Samsung", "00:26:37": "Samsung",
    "10:1D:C0": "Samsung", "14:49:E0": "Samsung", "18:67:B0": "Samsung",
    "1C:62:B8": "Samsung", "24:4B:81": "Samsung", "28:98:7B": "Samsung",
    "30:CD:A7": "Samsung", "34:23:BA": "Samsung", "38:01:97": "Samsung",
    "40:0E:85": "Samsung", "44:4E:1A": "Samsung", "4C:BC:A5": "Samsung",
    "50:01:BB": "Samsung", "50:B7:C3": "Samsung", "54:92:BE": "Samsung",
    "58:C3:8B": "Samsung", "5C:3C:27": "Samsung", "60:D0:A9": "Samsung",
    "68:27:37": "Samsung", "6C:F3:73": "Samsung", "78:52:1A": "Samsung",
    "80:65:6D": "Samsung", "84:25:DB": "Samsung", "88:32:9B": "Samsung",
    "8C:77:12": "Samsung", "90:18:7C": "Samsung", "94:35:0A": "Samsung",
    "9C:3A:AF": "Samsung", "A0:07:98": "Samsung", "A8:06:00": "Samsung",
    "AC:5F:3E": "Samsung", "B4:79:A7": "Samsung", "BC:72:B1": "Samsung",
    "C4:73:1E": "Samsung", "C8:BA:94": "Samsung", "D0:22:BE": "Samsung",
    "D8:90:E8": "Samsung", "E4:7C:F9": "Samsung", "EC:1F:72": "Samsung",
    "F0:25:B7": "Samsung", "F4:7B:5E": "Samsung",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi", "28:CD:C1": "Raspberry Pi",
    "D8:3A:DD": "Raspberry Pi",
    "00:1A:79": "Ubiquiti", "04:18:D6": "Ubiquiti",
    "18:E8:29": "Ubiquiti", "24:5A:4C": "Ubiquiti",
    "44:D9:E7": "Ubiquiti", "68:72:51": "Ubiquiti",
    "74:83:C2": "Ubiquiti", "78:8A:20": "Ubiquiti",
    "80:2A:A8": "Ubiquiti", "B4:FB:E4": "Ubiquiti",
    "F0:9F:C2": "Ubiquiti", "FC:EC:DA": "Ubiquiti",
    "00:04:F2": "Polycom", "00:09:B0": "Polycom",
    "00:E0:DB": "Polycom", "64:16:7F": "Polycom",
    "00:0F:20": "Hewlett Packard",
    "00:1B:78": "Hewlett Packard", "00:21:5A": "Hewlett Packard",
    "3C:D9:2B": "Hewlett Packard", "A0:D3:C1": "Hewlett Packard",
    "00:0B:82": "Grandstream", "00:0B:46": "Grandstream",
    "00:E0:4C": "Realtek", "48:5D:60": "Realtek",
    "52:54:00": "QEMU/KVM", "00:16:3E": "Xen",
    "00:1C:14": "VMware", "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:1A:8C": "Sophos", "00:1A:6C": "Aruba", "00:0B:86": "Aruba",
    "24:DE:C6": "Aruba", "40:E3:D6": "Aruba",
    "00:1C:DF": "Belkin", "08:86:3B": "Belkin",
    "94:10:3E": "Belkin", "B4:75:0E": "Belkin",
    "C0:56:27": "Belkin", "EC:1A:59": "Belkin",
}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
busy = False
status_msg = "Idle"
scroll_pos = 0

# List of {"mac": str, "vendor": str, "source": str}
mac_entries = []

# OUI database: prefix (upper, colon-separated) -> vendor
oui_db = {}


# ---------------------------------------------------------------------------
# OUI database management
# ---------------------------------------------------------------------------

def _load_oui_db():
    """Load OUI database from cache, download, or fallback."""
    global oui_db

    # Try cached JSON first
    if os.path.isfile(OUI_CACHE):
        try:
            with open(OUI_CACHE, "r") as f:
                oui_db = json.load(f)
            if len(oui_db) > 100:
                return
        except Exception:
            pass

    # Try downloading from IEEE
    try:
        result = subprocess.run(
            ["curl", "-s", "--max-time", "15", OUI_URL],
            capture_output=True, text=True, timeout=20,
        )
        if result.returncode == 0 and len(result.stdout) > 10000:
            parsed = _parse_ieee_oui(result.stdout)
            if len(parsed) > 100:
                oui_db = parsed
                # Cache for next time
                try:
                    with open(OUI_CACHE, "w") as f:
                        json.dump(oui_db, f)
                except Exception:
                    pass
                return
    except Exception:
        pass

    # Fallback to built-in
    oui_db = dict(BUILTIN_OUI)


def _parse_ieee_oui(text):
    """Parse IEEE oui.txt format into {prefix: vendor} dict."""
    db = {}
    for line in text.splitlines():
        if "(hex)" in line:
            parts = line.split("(hex)")
            if len(parts) == 2:
                prefix = parts[0].strip().replace("-", ":").upper()
                vendor = parts[1].strip()
                if prefix and vendor:
                    db[prefix] = vendor
    return db


def lookup_vendor(mac):
    """Look up vendor for a MAC address."""
    mac_upper = mac.upper().replace("-", ":")
    prefix = mac_upper[:8]
    return oui_db.get(prefix, "Unknown")


# ---------------------------------------------------------------------------
# MAC extraction from loot files
# ---------------------------------------------------------------------------

MAC_RE = re.compile(r"([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})")


def _extract_macs_from_file(filepath):
    """Extract all MAC addresses from a text/JSON file."""
    macs = set()
    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()
        for match in MAC_RE.finditer(content):
            mac = match.group(1).upper().replace("-", ":")
            if mac != "FF:FF:FF:FF:FF:FF" and mac != "00:00:00:00:00:00":
                macs.add(mac)
    except Exception:
        pass
    return macs


def _load_from_loot():
    """Scan Nmap loot directory for MAC addresses."""
    global mac_entries, status_msg, busy

    with lock:
        busy = True
        status_msg = "Loading loot files..."
        mac_entries = []

    all_macs = {}  # mac -> source

    # Scan Nmap loot
    if os.path.isdir(NMAP_LOOT):
        for fname in os.listdir(NMAP_LOOT):
            fpath = os.path.join(NMAP_LOOT, fname)
            if os.path.isfile(fpath):
                for mac in _extract_macs_from_file(fpath):
                    if mac not in all_macs:
                        all_macs[mac] = f"Nmap/{fname[:12]}"

    # Also check other loot directories
    loot_root = "/root/Raspyjack/loot"
    if os.path.isdir(loot_root):
        for subdir in os.listdir(loot_root):
            if subdir in ("MACLookup",):
                continue
            subpath = os.path.join(loot_root, subdir)
            if os.path.isdir(subpath):
                for fname in os.listdir(subpath):
                    fpath = os.path.join(subpath, fname)
                    if os.path.isfile(fpath):
                        for mac in _extract_macs_from_file(fpath):
                            if mac not in all_macs:
                                all_macs[mac] = f"{subdir}/{fname[:8]}"

    entries = []
    for mac, source in sorted(all_macs.items()):
        vendor = lookup_vendor(mac)
        entries.append({"mac": mac, "vendor": vendor, "source": source})

    with lock:
        mac_entries = entries
        status_msg = f"Loaded {len(entries)} MACs from loot"
        busy = False


# ---------------------------------------------------------------------------
# ARP scan
# ---------------------------------------------------------------------------

def _get_subnet():
    """Get the current subnet in CIDR notation."""
    try:
        result = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                dev_idx = parts.index("dev") + 1
                if dev_idx < len(parts):
                    iface = parts[dev_idx]
                    # Get subnet for this interface
                    r2 = subprocess.run(
                        ["ip", "-4", "addr", "show", iface],
                        capture_output=True, text=True, timeout=5,
                    )
                    match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", r2.stdout)
                    if match:
                        return match.group(1)
    except Exception:
        pass
    return None


def _do_arp_scan():
    """Perform a live ARP scan of the current subnet."""
    global mac_entries, status_msg, busy

    with lock:
        busy = True
        status_msg = "Getting subnet..."

    subnet = _get_subnet()
    if not subnet:
        with lock:
            status_msg = "Cannot detect subnet"
            busy = False
        return

    with lock:
        status_msg = f"ARP scan {subnet}..."

    new_macs = {}
    try:
        # Try arp-scan first
        result = subprocess.run(
            ["sudo", "arp-scan", "--localnet"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                match = re.match(
                    r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s+(.*)",
                    line.strip(),
                )
                if match:
                    mac = match.group(2).upper()
                    new_macs[mac] = "ARP-scan"
    except (FileNotFoundError, Exception):
        pass

    # Fallback: nmap ping scan + ARP cache
    if not new_macs:
        try:
            subprocess.run(
                ["nmap", "-sn", subnet],
                capture_output=True, text=True, timeout=30,
            )
        except Exception:
            pass

        try:
            result = subprocess.run(
                ["arp", "-an"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                match = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
                if match:
                    mac = match.group(1).upper()
                    if mac not in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                        new_macs[mac] = "ARP-cache"
        except Exception:
            pass

    # Merge with existing entries
    with lock:
        existing = {e["mac"]: e for e in mac_entries}
        for mac, source in new_macs.items():
            if mac not in existing:
                vendor = lookup_vendor(mac)
                mac_entries.append({"mac": mac, "vendor": vendor, "source": source})
        status_msg = f"ARP: +{len(new_macs)} ({len(mac_entries)} total)"
        busy = False


def start_arp_scan():
    """Launch ARP scan in background."""
    with lock:
        if busy:
            return
    threading.Thread(target=_do_arp_scan, daemon=True).start()


def start_loot_reload():
    """Reload MACs from loot in background."""
    with lock:
        if busy:
            return
    threading.Thread(target=_load_from_loot, daemon=True).start()


# ---------------------------------------------------------------------------
# Loot export
# ---------------------------------------------------------------------------

def export_loot():
    """Write MAC lookup results to JSON."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    with lock:
        data = {
            "timestamp": ts,
            "count": len(mac_entries),
            "entries": [dict(e) for e in mac_entries],
        }
    path = os.path.join(LOOT_DIR, f"mac_lookup_{ts}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(d, title):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title, font=font, fill="#FFAA00")
    with lock:
        active = busy
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if active else "#FF0000")


def _draw_footer(d, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font, fill="#AAA")


def draw_screen():
    """Render the MAC lookup list."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "MAC LOOKUP")

    with lock:
        entries = [dict(e) for e in mac_entries]
        status = status_msg
        sc = scroll_pos

    d.text((2, 15), status[:22], font=font, fill="#888")

    if not entries:
        d.text((10, 50), "OK: ARP scan", font=font, fill="#666")
        d.text((10, 62), "K1: Load from loot", font=font, fill="#666")
    else:
        visible = entries[sc:sc + ROWS_VISIBLE - 1]
        for i, entry in enumerate(visible):
            y = 27 + i * ROW_H
            mac_short = entry["mac"][-8:]  # last 8 chars
            vendor = entry["vendor"][:11]
            d.text((1, y), f"{mac_short} {vendor}", font=font, fill="#CCCCCC")

        total = len(entries)
        if total > ROWS_VISIBLE - 1:
            bar_h = max(4, int((ROWS_VISIBLE - 1) / total * 88))
            bar_y = 27 + int(sc / total * 88) if total > 0 else 27
            d.rectangle((126, bar_y, 127, bar_y + bar_h), fill="#444")

    _draw_footer(d, f"Total:{len(entries)} K3:Exit")
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
    global scroll_pos

    # Load OUI database at startup
    _load_oui_db()

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 20), "MAC OUI LOOKUP", font=font, fill="#FFAA00")
    d.text((4, 40), f"OUI DB: {len(oui_db)} entries", font=font, fill="#888")
    d.text((4, 60), "OK    ARP scan", font=font, fill="#666")
    d.text((4, 72), "KEY1  Load from loot", font=font, fill="#666")
    d.text((4, 84), "KEY2  Export JSON", font=font, fill="#666")
    d.text((4, 96), "KEY3  Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.3)

    # Auto-load from loot files on start
    start_loot_reload()

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if mac_entries:
                    export_loot()
                break

            if btn == "OK":
                start_arp_scan()
                time.sleep(0.3)
            elif btn == "KEY1":
                start_loot_reload()
                time.sleep(0.3)
            elif btn == "KEY2":
                if mac_entries:
                    path = export_loot()
                    _show_message("Exported!", path[-20:])
                time.sleep(0.3)
            elif btn == "UP":
                scroll_pos = max(0, scroll_pos - 1)
                time.sleep(0.15)
            elif btn == "DOWN":
                with lock:
                    max_sc = max(0, len(mac_entries) - ROWS_VISIBLE + 1)
                scroll_pos = min(max_sc, scroll_pos + 1)
                time.sleep(0.15)

            draw_screen()
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
