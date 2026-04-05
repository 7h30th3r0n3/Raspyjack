#!/usr/bin/env python3
"""
RaspyJack Payload -- Visual Network Topology Mapper
=====================================================
Author: 7h30th3r0n3

Combines ARP scan results and Nmap loot to render a simple network
topology on the LCD.  Gateway at top, hosts arranged by
subnet.  Nodes are small labelled boxes with lines to the gateway.

Controls:
  OK          -- Refresh scan (re-discover hosts)
  UP / DOWN   -- Scroll view vertically
  LEFT / RIGHT-- Zoom in / out
  KEY1        -- Toggle labels: IP / MAC / vendor
  KEY2        -- Export text map to loot
  KEY3        -- Exit
"""

import os
import sys
import json
import time
import subprocess
import re
import threading
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
NMAP_LOOT = "/root/Raspyjack/loot/Nmap"
LOOT_DIR = "/root/Raspyjack/loot/NetMap"
os.makedirs(LOOT_DIR, exist_ok=True)

IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
LABEL_MODES = ["ip", "mac", "vendor"]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
busy = False
status_msg = "Idle"
scroll_y = 0
zoom = 1
label_mode_idx = 0
stop_flag = False

# {ip: {"mac": str, "vendor": str, "is_gw": bool, "ports": []}}
hosts = {}
gateway_ip = ""


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def _get_gateway():
    """Return default gateway IP."""
    try:
        out = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in out.stdout.splitlines():
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return ""


def _arp_scan():
    """Gather hosts from ARP table."""
    found = {}
    try:
        out = subprocess.run(
            ["arp", "-an"], capture_output=True, text=True, timeout=5,
        )
        for line in out.stdout.splitlines():
            m_ip = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
            m_mac = re.search(r"(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})", line)
            if m_ip:
                ip = m_ip.group(1)
                mac = m_mac.group(1).lower() if m_mac else ""
                if not ip.endswith(".255") and not ip.endswith(".0"):
                    found[ip] = {"mac": mac, "vendor": _vendor_prefix(mac), "is_gw": False, "ports": []}
    except Exception:
        pass
    return found


def _vendor_prefix(mac):
    """Crude vendor lookup from OUI prefix."""
    oui_map = {
        "dc:a6:32": "RasPi", "b8:27:eb": "RasPi", "e4:5f:01": "RasPi",
        "00:50:56": "VMware", "00:0c:29": "VMware", "08:00:27": "VBox",
        "00:1a:2b": "Cisco", "00:1b:44": "Cisco", "44:38:39": "Cumul",
        "f8:75:a4": "DELL", "d4:be:d9": "DELL", "00:25:b5": "HP",
    }
    prefix = mac[:8].lower() if mac else ""
    return oui_map.get(prefix, "")


def _enrich_from_nmap():
    """Add port info from Nmap loot files."""
    if not os.path.isdir(NMAP_LOOT):
        return
    with lock:
        current = dict(hosts)
    for fname in os.listdir(NMAP_LOOT):
        fpath = os.path.join(NMAP_LOOT, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, "r", errors="ignore") as f:
                content = f.read()
            for ip in current:
                if ip in content:
                    port_matches = re.findall(r"(\d+)/open", content)
                    if port_matches:
                        with lock:
                            if ip in hosts:
                                hosts[ip] = {**hosts[ip], "ports": port_matches[:6]}
        except Exception:
            pass


def _do_refresh():
    """Full discovery refresh."""
    global busy, status_msg, hosts, gateway_ip, stop_flag

    with lock:
        busy = True
        stop_flag = False
        status_msg = "Scanning..."

    gw = _get_gateway()
    with lock:
        gateway_ip = gw

    discovered = _arp_scan()

    if gw and gw not in discovered:
        discovered[gw] = {"mac": "", "vendor": "", "is_gw": True, "ports": []}
    if gw and gw in discovered:
        discovered[gw] = {**discovered[gw], "is_gw": True}

    with lock:
        hosts = discovered
        status_msg = f"Found {len(discovered)} hosts"

    _enrich_from_nmap()

    with lock:
        busy = False
        status_msg = f"{len(hosts)} hosts mapped"


def start_refresh():
    with lock:
        if busy:
            return
    threading.Thread(target=_do_refresh, daemon=True).start()


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _node_label(info, ip):
    """Return label string based on current label mode."""
    mode = LABEL_MODES[label_mode_idx]
    if mode == "ip":
        return ".".join(ip.split(".")[-2:])
    elif mode == "mac":
        return info["mac"][-8:] if info["mac"] else ip.split(".")[-1]
    else:
        return info["vendor"][:6] if info["vendor"] else ip.split(".")[-1]


def draw_topology():
    """Render network topology on LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 11), fill="#111")
    d.text((2, 1), "NET MAP", font=font, fill="#00CCFF")
    with lock:
        active = busy
        status = status_msg
    d.ellipse((118, 2, 122, 6), fill="#00FF00" if active else "#FF0000")

    with lock:
        host_list = sorted(hosts.items(), key=lambda kv: kv[1]["is_gw"], reverse=True)
        gw = gateway_ip
        sy = scroll_y
        z = zoom

    if not host_list:
        d.text((10, 45), "OK: Scan network", font=font, fill="#666")
        d.text((10, 57), status[:20], font=font, fill="#888")
        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "K3:Exit", font=font, fill="#AAA")
        LCD.LCD_ShowImage(img, 0, 0)
        return

    node_w = max(8, 30 * z)
    node_h = max(6, 10 * z)
    spacing_x = max(10, 36 * z)
    spacing_y = max(12, 24 * z)
    cols = max(1, 120 // spacing_x)

    gw_x = 64
    gw_y = 18 - sy

    gw_entry = None
    others = []
    for ip, info in host_list:
        if info["is_gw"]:
            gw_entry = (ip, info)
        else:
            others.append((ip, info))

    if gw_entry:
        gip, ginfo = gw_entry
        rx = int(gw_x - node_w // 2)
        ry = int(gw_y)
        d.rectangle((rx, ry, rx + node_w, ry + node_h), fill="#FF6600", outline="#FF9900")
        lbl = _node_label(ginfo, gip)
        d.text((rx + 2, ry + 1), lbl[:6], font=font, fill="black")

    for idx, (ip, info) in enumerate(others):
        col = idx % cols
        row = idx // cols
        nx = int(4 + col * spacing_x)
        ny = int(36 + row * spacing_y - sy)

        if ny < 12 or ny > 120:
            continue

        if gw_entry:
            d.line([(gw_x, int(gw_y + node_h)), (nx + node_w // 2, ny)], fill="#333")

        port_count = len(info.get("ports", []))
        fill_color = "#00AA44" if port_count > 3 else "#006688" if port_count > 0 else "#333366"
        d.rectangle((nx, ny, nx + node_w, ny + node_h), fill=fill_color, outline="#668888")

        lbl = _node_label(info, ip)
        d.text((nx + 1, ny + 1), lbl[:6], font=font, fill="white")

    d.rectangle((0, 116, 127, 127), fill="#111")
    mode_txt = LABEL_MODES[label_mode_idx].upper()
    d.text((2, 117), f"Z:{z} {mode_txt} [{len(host_list)}]", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Text export
# ---------------------------------------------------------------------------

def export_text_map():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    lines = [f"Network Map - {ts}", "=" * 40]
    with lock:
        gw = gateway_ip
        hlist = dict(hosts)

    if gw:
        gw_info = hlist.get(gw, {})
        lines.append(f"[GATEWAY] {gw}  MAC:{gw_info.get('mac', '?')}")
        lines.append("  |")

    for ip, info in sorted(hlist.items()):
        if info.get("is_gw"):
            continue
        ports = ",".join(info.get("ports", []))
        lines.append(f"  +-- {ip}  MAC:{info['mac']}  Vendor:{info['vendor']}  Ports:[{ports}]")

    lines.append(f"\nTotal hosts: {len(hlist)}")
    path = os.path.join(LOOT_DIR, f"netmap_{ts}.txt")
    with open(path, "w") as f:
        f.write("\n".join(lines))
    return path


def _show_message(line1, line2=""):
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
    global scroll_y, zoom, label_mode_idx, stop_flag

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 20), "NETWORK MAPPER", font=font, fill="#00CCFF")
    d.text((4, 40), "Visual topology", font=font, fill="#888")
    d.text((4, 60), "OK=Refresh  K1=Labels", font=font, fill="#666")
    d.text((4, 72), "L/R=Zoom  K2=Export", font=font, fill="#666")
    d.text((4, 84), "K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.3)

    start_refresh()

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                with lock:
                    stop_flag = True
                break

            if btn == "OK":
                start_refresh()
                time.sleep(0.3)

            elif btn == "KEY1":
                label_mode_idx = (label_mode_idx + 1) % len(LABEL_MODES)
                time.sleep(0.2)

            elif btn == "KEY2":
                if hosts:
                    path = export_text_map()
                    _show_message("Exported!", path[-20:])
                time.sleep(0.3)

            elif btn == "UP":
                scroll_y = max(0, scroll_y - 8)
                time.sleep(0.1)

            elif btn == "DOWN":
                scroll_y = scroll_y + 8
                time.sleep(0.1)

            elif btn == "LEFT":
                zoom = max(1, zoom - 1)
                time.sleep(0.2)

            elif btn == "RIGHT":
                zoom = min(3, zoom + 1)
                time.sleep(0.2)

            draw_topology()
            time.sleep(0.05)

    finally:
        with lock:
            stop_flag = True
        time.sleep(0.3)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
