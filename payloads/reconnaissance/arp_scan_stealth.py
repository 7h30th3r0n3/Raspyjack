#!/usr/bin/env python3
"""
RaspyJack Payload -- Stealthy ARP Scanner
==========================================
Author: 7h30th3r0n3

Slow, stealthy ARP scanner for the local subnet.  Randomizes host
order, adds jittered delays (1-3 s between probes), and optionally
spoofs the source MAC.  Displays a progress bar and discovered hosts
on the LCD.

Controls:
  OK         -- Start scan
  UP / DOWN  -- Scroll results
  KEY1       -- Toggle MAC spoof on / off
  KEY2       -- Export results to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/StealthScan/scan_YYYYMMDD_HHMMSS.json
"""

import os
import sys
import json
import time
import random
import struct
import ipaddress
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

try:
    from scapy.all import (
        Ether, ARP, srp, conf, get_if_hwaddr,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

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

LOOT_DIR = "/root/Raspyjack/loot/StealthScan"

# Common OUI prefixes for vendor hint (abbreviated)
OUI_HINTS = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "08:00:27": "VBox",
    "B8:27:EB": "RaspPi",
    "DC:A6:32": "RaspPi",
    "E4:5F:01": "RaspPi",
    "D8:3A:DD": "RaspPi",
    "AA:BB:CC": "Test",
    "00:1A:2B": "Cisco",
    "00:1B:44": "Cisco",
    "00:26:CB": "Cisco",
    "3C:5A:B4": "Google",
    "F4:F5:D8": "Google",
    "AC:DE:48": "Apple",
    "00:1C:B3": "Apple",
    "A4:83:E7": "Apple",
    "F0:18:98": "Apple",
    "34:02:86": "Apple",
    "00:25:00": "Apple",
    "FC:F1:36": "Samsung",
    "A0:CC:2B": "Samsung",
    "8C:F5:A3": "Samsung",
    "78:02:F8": "Xiaomi",
    "50:EC:50": "Xiaomi",
}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = False
scanning = False
mac_spoof = False
scroll = 0
progress = 0.0          # 0.0 to 1.0
total_hosts = 0
scanned_hosts = 0

# List of discovered hosts: [{ip, mac, vendor}]
discovered = []

# ---------------------------------------------------------------------------
# Network detection
# ---------------------------------------------------------------------------

def _detect_iface_and_subnet():
    """Detect active interface and its subnet."""
    for candidate in ["eth0", "wlan0"]:
        try:
            result = subprocess.run(
                ["ip", "-4", "addr", "show", candidate],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("inet "):
                    parts = line.split()
                    cidr = parts[1]  # e.g. "192.168.1.5/24"
                    return candidate, cidr
        except Exception:
            pass
    # Fallback: try any interface
    try:
        result = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                idx = parts.index("dev") + 1
                iface = parts[idx]
                r2 = subprocess.run(
                    ["ip", "-4", "addr", "show", iface],
                    capture_output=True, text=True, timeout=5,
                )
                for ln in r2.stdout.splitlines():
                    ln = ln.strip()
                    if ln.startswith("inet "):
                        return iface, ln.split()[1]
    except Exception:
        pass
    return None, None


def _vendor_hint(mac):
    """Look up vendor hint from OUI prefix."""
    prefix = mac.upper()[:8]
    return OUI_HINTS.get(prefix, "")


def _random_mac():
    """Generate a random locally-administered MAC."""
    octets = [random.randint(0, 255) for _ in range(6)]
    octets[0] = (octets[0] | 0x02) & 0xFE
    return ":".join(f"{b:02x}" for b in octets)

# ---------------------------------------------------------------------------
# Scan thread
# ---------------------------------------------------------------------------

def _scan_thread(iface, cidr):
    """Perform the stealthy ARP scan in background."""
    global scanning, progress, total_hosts, scanned_hosts

    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        scanning = False
        return

    hosts = [str(h) for h in network.hosts()]
    random.shuffle(hosts)

    with lock:
        total_hosts = len(hosts)
        scanned_hosts = 0
        progress = 0.0

    real_mac = None
    try:
        real_mac = get_if_hwaddr(iface)
    except Exception:
        pass

    for i, target_ip in enumerate(hosts):
        if not running:
            break

        src_mac = _random_mac() if mac_spoof else (real_mac or "00:00:00:00:00:00")

        try:
            pkt = (
                Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
                / ARP(
                    op="who-has",
                    hwsrc=src_mac,
                    psrc="0.0.0.0" if mac_spoof else "",
                    pdst=target_ip,
                )
            )
            ans, _ = srp(pkt, iface=iface, timeout=1, verbose=False, retry=0)

            for _, received in ans:
                resp_mac = received[ARP].hwsrc.upper()
                resp_ip = received[ARP].psrc
                vendor = _vendor_hint(resp_mac)
                host_entry = {
                    "ip": resp_ip,
                    "mac": resp_mac,
                    "vendor": vendor,
                }
                with lock:
                    # Avoid duplicates
                    existing_ips = {h["ip"] for h in discovered}
                    if resp_ip not in existing_ips:
                        discovered.append(host_entry)
        except Exception:
            pass

        with lock:
            scanned_hosts = i + 1
            progress = scanned_hosts / max(total_hosts, 1)

        # Jittered delay: 1-3 seconds
        jitter = random.uniform(1.0, 3.0)
        deadline = time.time() + jitter
        while time.time() < deadline and running:
            time.sleep(0.1)

    scanning = False

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_loot():
    """Write scan results to JSON loot file."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{ts}.json"
    filepath = os.path.join(LOOT_DIR, filename)

    with lock:
        data = {
            "timestamp": ts,
            "hosts_found": len(discovered),
            "mac_spoof": mac_spoof,
            "hosts": list(discovered),
        }

    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)

    return filename

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_frame(lcd, font):
    """Render current state to the LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "STEALTH SCAN", font=font, fill="#00AAFF")
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if scanning else "#444")

    with lock:
        prog = progress
        found = len(discovered)
        total = total_hosts
        done = scanned_hosts
        host_list = list(discovered)

    # Progress bar
    bar_x, bar_y, bar_w, bar_h = 4, 18, 120, 8
    d.rectangle((bar_x, bar_y, bar_x + bar_w, bar_y + bar_h), outline="#444")
    fill_w = int(prog * (bar_w - 2))
    if fill_w > 0:
        d.rectangle(
            (bar_x + 1, bar_y + 1, bar_x + 1 + fill_w, bar_y + bar_h - 1),
            fill="#00AAFF",
        )

    # Stats line
    pct = int(prog * 100)
    spoof_tag = "SPOOF" if mac_spoof else "REAL"
    d.text((4, 28), f"{done}/{total} ({pct}%) Found:{found}", font=font, fill="#AAAAAA")
    d.text((4, 40), f"MAC: {spoof_tag}", font=font, fill="#FFAA00")

    # Scrollable host list
    visible = host_list[scroll:scroll + ROWS_VISIBLE]
    for i, host in enumerate(visible):
        y = 54 + i * ROW_H
        ip = host["ip"]
        mac_short = host["mac"][-8:]
        vendor = host["vendor"][:5] if host["vendor"] else ""
        line = f"{ip:<15s} {mac_short}"
        d.text((2, y), line, font=font, fill="#CCCCCC")
        if vendor:
            d.text((110, y), vendor[:3], font=font, fill="#888")

    # Scroll indicator
    total_items = len(host_list)
    if total_items > ROWS_VISIBLE:
        bar_area = 60
        ind_h = max(4, int(ROWS_VISIBLE / total_items * bar_area))
        ind_y = 54 + int(scroll / total_items * bar_area)
        d.rectangle((126, ind_y, 127, ind_y + ind_h), fill="#444")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if scanning:
        d.text((2, 117), "Scanning... K3:Exit", font=font, fill="#888")
    else:
        d.text((2, 117), "OK:Scan K2:Exp K3:Quit", font=font, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running, scanning, scroll, mac_spoof

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font = scaled_font()

    if not SCAPY_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "scapy not found!", font=font, fill="#FF0000")
        d.text((4, 65), "pip install scapy", font=font, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    iface, cidr = _detect_iface_and_subnet()

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 16), "STEALTH ARP SCAN", font=font, fill="#00AAFF")
    d.text((4, 36), "Slow randomized scan", font=font, fill="#888")
    d.text((4, 48), f"Iface: {iface or 'none'}", font=font, fill="#666")
    d.text((4, 60), f"Net: {cidr or 'none'}", font=font, fill="#666")
    d.text((4, 76), "OK    Start scan", font=font, fill="#666")
    d.text((4, 88), "KEY1  Toggle spoof", font=font, fill="#666")
    d.text((4, 100), "KEY2  Export results", font=font, fill="#666")
    d.text((4, 112), "KEY3  Exit", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)

    running = True

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK" and not scanning:
                if not iface or not cidr:
                    iface, cidr = _detect_iface_and_subnet()
                if iface and cidr:
                    scanning = True
                    threading.Thread(
                        target=_scan_thread, args=(iface, cidr), daemon=True
                    ).start()
                else:
                    img2 = Image.new("RGB", (WIDTH, HEIGHT), "black")
                    d2 = ScaledDraw(img2)
                    d2.text((4, 50), "No network found!", font=font, fill="#FF0000")
                    lcd.LCD_ShowImage(img2, 0, 0)
                    time.sleep(1.5)
                time.sleep(0.3)

            elif btn == "KEY1":
                mac_spoof = not mac_spoof
                time.sleep(0.3)

            elif btn == "KEY2":
                with lock:
                    has_data = len(discovered) > 0
                if has_data:
                    fname = _export_loot()
                    img2 = Image.new("RGB", (WIDTH, HEIGHT), "black")
                    d2 = ScaledDraw(img2)
                    d2.text((4, 50), "Exported!", font=font, fill="#00FF00")
                    d2.text((4, 65), fname[:22], font=font, fill="#888")
                    lcd.LCD_ShowImage(img2, 0, 0)
                    time.sleep(1.5)
                else:
                    img2 = Image.new("RGB", (WIDTH, HEIGHT), "black")
                    d2 = ScaledDraw(img2)
                    d2.text((4, 50), "No data to export", font=font, fill="#FF8800")
                    lcd.LCD_ShowImage(img2, 0, 0)
                    time.sleep(1.0)
                time.sleep(0.3)

            elif btn == "UP":
                scroll = max(0, scroll - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                with lock:
                    max_scroll = max(0, len(discovered) - ROWS_VISIBLE)
                scroll = min(scroll + 1, max_scroll)
                time.sleep(0.15)

            _draw_frame(lcd, font)
            time.sleep(0.05)

    finally:
        running = False
        time.sleep(0.5)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
