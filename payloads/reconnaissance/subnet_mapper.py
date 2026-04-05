#!/usr/bin/env python3
"""
RaspyJack Payload -- Subnet Mapper
====================================
Author: 7h30th3r0n3

Complete subnet mapping: ARP scan to discover hosts, then quick SYN scan
of the top 20 ports on each discovered host, plus OS hint derived from
ICMP TTL values.

LCD shows a scrollable host list with IP, MAC, open-port count, and OS
guess.  Drill into any host to see its open ports.

Setup / Prerequisites
---------------------
- Root privileges (for raw sockets / ARP / SYN scan).
- nmap installed (used for SYN scan).

Controls
--------
  OK          -- Start scan
  UP / DOWN   -- Scroll host list
  RIGHT       -- Show host details (port list)
  LEFT        -- Back to host list
  KEY1        -- Rescan
  KEY2        -- Export JSON to loot
  KEY3        -- Exit
"""

import os
import sys
import time
import json
import re
import subprocess
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
LOOT_DIR = "/root/Raspyjack/loot/SubnetMap"
os.makedirs(LOOT_DIR, exist_ok=True)

TOP20_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
DEBOUNCE = 0.22

# ---------------------------------------------------------------------------
# Thread-safe state
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_state = {
    "hosts": [],          # list of dicts
    "status": "Idle",
    "scanning": False,
    "stop": False,
    "scroll": 0,
    "detail_idx": -1,     # -1 = list view
    "detail_scroll": 0,
}


def _get(key):
    with _lock:
        val = _state[key]
        if isinstance(val, list):
            return list(val)
        return val


def _set(**kw):
    with _lock:
        for k, v in kw.items():
            _state[k] = v


# ---------------------------------------------------------------------------
# OS guess from TTL
# ---------------------------------------------------------------------------
def _os_from_ttl(ttl):
    if ttl <= 0:
        return "?"
    if ttl <= 64:
        return "Linux"
    if ttl <= 128:
        return "Windows"
    return "Cisco/Net"


def _ping_ttl(ip):
    """Return TTL from a single ICMP ping, or 0 on failure."""
    try:
        out = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True, text=True, timeout=3,
        )
        m = re.search(r"ttl=(\d+)", out.stdout, re.IGNORECASE)
        if m:
            return int(m.group(1))
    except Exception:
        pass
    return 0


# ---------------------------------------------------------------------------
# ARP scan
# ---------------------------------------------------------------------------
def _arp_scan():
    """Discover hosts via ARP table after a broadcast ping sweep."""
    # Determine local subnet
    subnet = _get_subnet()
    if subnet:
        try:
            subprocess.run(
                ["ping", "-b", "-c", "1", "-W", "1", subnet],
                capture_output=True, timeout=4,
            )
        except Exception:
            pass

    hosts = {}
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
                    hosts[ip] = {"ip": ip, "mac": mac, "ports": [], "ttl": 0, "os": "?"}
    except Exception:
        pass
    return hosts


def _get_subnet():
    """Return broadcast address of default interface."""
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True, text=True, timeout=5,
        )
        for line in out.stdout.splitlines():
            if "brd" in line and "127." not in line:
                parts = line.split()
                idx = parts.index("brd") if "brd" in parts else -1
                if idx >= 0 and idx + 1 < len(parts):
                    return parts[idx + 1]
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# SYN scan via nmap
# ---------------------------------------------------------------------------
def _syn_scan(ip):
    """Quick SYN scan top 20 ports. Returns list of 'port/proto' strings."""
    ports = []
    try:
        out = subprocess.run(
            ["nmap", "-sS", "-Pn", "--top-ports", "20", "-T4",
             "--open", "-oG", "-", ip],
            capture_output=True, text=True, timeout=30,
        )
        for line in out.stdout.splitlines():
            m = re.findall(r"(\d+)/open/(\w+)", line)
            for port_num, proto in m:
                ports.append(f"{port_num}/{proto}")
    except FileNotFoundError:
        # nmap not installed, fall back to simple connect scan
        ports = _connect_scan(ip)
    except Exception:
        pass
    return ports


def _connect_scan(ip):
    """Fallback TCP connect scan of top 20 ports."""
    import socket as _sock
    open_ports = []
    for port_str in TOP20_PORTS.split(","):
        if _get("stop"):
            break
        port = int(port_str)
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(f"{port}/tcp")
        except Exception:
            pass
        finally:
            s.close()
    return open_ports


# ---------------------------------------------------------------------------
# Full scan orchestration
# ---------------------------------------------------------------------------
def _do_scan():
    _set(scanning=True, stop=False, status="ARP scanning...")

    discovered = _arp_scan()
    total = len(discovered)
    _set(status=f"Found {total} hosts")

    results = []
    for idx, (ip, info) in enumerate(sorted(discovered.items())):
        if _get("stop"):
            break
        _set(status=f"Scanning {idx + 1}/{total}: {ip}")

        ttl = _ping_ttl(ip)
        os_guess = _os_from_ttl(ttl)
        ports = _syn_scan(ip)

        entry = {
            "ip": ip,
            "mac": info["mac"],
            "ports": ports,
            "ttl": ttl,
            "os": os_guess,
        }
        results.append(entry)

    _set(hosts=results, scanning=False, scroll=0,
         status=f"Done: {len(results)} hosts")


def _start_scan():
    if _get("scanning"):
        return
    threading.Thread(target=_do_scan, daemon=True).start()


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
def _export_json():
    hosts = _get("hosts")
    if not hosts:
        return None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    data = {
        "scan_time": ts,
        "host_count": len(hosts),
        "hosts": hosts,
    }
    path = os.path.join(LOOT_DIR, f"subnetmap_{ts}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


# ---------------------------------------------------------------------------
# LCD drawing
# ---------------------------------------------------------------------------
def _draw_list():
    """Draw scrollable host list."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "SUBNET MAPPER", font=font, fill="#00CCFF")
    scanning = _get("scanning")
    d.ellipse((118, 3, 124, 9), fill="#00FF00" if scanning else "#666")

    hosts = _get("hosts")
    scroll = _get("scroll")
    status = _get("status")

    if not hosts:
        d.text((4, 40), status[:21], font=font, fill="#888")
        d.text((4, 56), "OK: Start scan", font=font, fill="#666")
        _draw_footer(d)
        LCD.LCD_ShowImage(img, 0, 0)
        return

    # Host list
    visible = 5
    y = 14
    for i in range(scroll, min(scroll + visible, len(hosts))):
        h = hosts[i]
        selected = (i == scroll)
        bg = "#1a1a2e" if selected else "black"
        fg_ip = "#00FF00" if selected else "#AAAAAA"
        d.rectangle((0, y, 127, y + 19), fill=bg)
        port_count = len(h["ports"])
        line1 = f"{h['ip']}"
        line2 = f" {h['mac'][:8]} P:{port_count} {h['os']}"
        d.text((2, y), line1[:21], font=font, fill=fg_ip)
        d.text((2, y + 10), line2[:21], font=font, fill="#888")
        y += 21

    # Status bar
    d.rectangle((0, 106, 127, 115), fill="#0a0a0a")
    d.text((2, 107), status[:21], font=font, fill="#FFCC00")

    _draw_footer(d)
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_detail():
    """Draw detailed port list for selected host."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    hosts = _get("hosts")
    idx = _get("detail_idx")
    ds = _get("detail_scroll")

    if idx < 0 or idx >= len(hosts):
        _set(detail_idx=-1)
        return

    h = hosts[idx]
    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), f"{h['ip']}", font=font, fill="#00CCFF")

    y = 14
    d.text((2, y), f"MAC: {h['mac']}", font=font, fill="#AAAAAA")
    y += 12
    d.text((2, y), f"OS:  {h['os']}  TTL:{h['ttl']}", font=font, fill="#AAAAAA")
    y += 14

    d.text((2, y), "Open ports:", font=font, fill="#00FF88")
    y += 12

    ports = h["ports"]
    if not ports:
        d.text((4, y), "(none found)", font=font, fill="#666")
    else:
        visible = 6
        for i in range(ds, min(ds + visible, len(ports))):
            d.text((4, y), ports[i], font=font, fill="#CCCCCC")
            y += 11

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "LEFT:back U/D:scroll", font=font, fill="#AAA")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_footer(d):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK K1:re K2:exp K3:x", font=font, fill="#AAA")


def _show_msg(line1, line2=""):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), line1[:21], font=font, fill="#00FF00")
    if line2:
        d.text((4, 65), line2[:21], font=font, fill="#888")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 20), "SUBNET MAPPER", font=font, fill="#00CCFF")
    d.text((4, 36), "ARP + SYN scan", font=font, fill="#888")
    d.text((4, 56), "OK=Scan  RIGHT=Detail", font=font, fill="#666")
    d.text((4, 68), "K1=Rescan K2=Export", font=font, fill="#666")
    d.text((4, 80), "K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    last_press = 0.0

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            detail = _get("detail_idx")

            if btn == "KEY3":
                _set(stop=True)
                break

            if detail >= 0:
                # Detail view
                if btn == "LEFT":
                    _set(detail_idx=-1, detail_scroll=0)
                elif btn == "UP":
                    ds = _get("detail_scroll")
                    _set(detail_scroll=max(0, ds - 1))
                elif btn == "DOWN":
                    ds = _get("detail_scroll")
                    hosts = _get("hosts")
                    idx = _get("detail_idx")
                    if idx < len(hosts):
                        max_s = max(0, len(hosts[idx]["ports"]) - 6)
                        _set(detail_scroll=min(max_s, ds + 1))
                _draw_detail()
            else:
                # List view
                if btn == "OK" or btn == "KEY1":
                    _start_scan()
                elif btn == "UP":
                    s = _get("scroll")
                    _set(scroll=max(0, s - 1))
                elif btn == "DOWN":
                    s = _get("scroll")
                    hosts = _get("hosts")
                    _set(scroll=min(max(0, len(hosts) - 1), s + 1))
                elif btn == "RIGHT":
                    hosts = _get("hosts")
                    s = _get("scroll")
                    if hosts and s < len(hosts):
                        _set(detail_idx=s, detail_scroll=0)
                elif btn == "KEY2":
                    path = _export_json()
                    if path:
                        _show_msg("Exported!", path[-20:])
                    else:
                        _show_msg("No data yet")
                _draw_list()

            time.sleep(0.05)

    finally:
        _set(stop=True)
        time.sleep(0.2)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
