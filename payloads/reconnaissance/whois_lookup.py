#!/usr/bin/env python3
"""
RaspyJack Payload -- WHOIS + Reverse DNS Lookup
================================================
Author: 7h30th3r0n3

Performs WHOIS lookups and reverse DNS resolution for external IPs.  Can
load unique IPs from loot/MITM/ pcap summaries or accept manual cycling
through discovered IPs.  Uses socket connections to WHOIS servers directly
(no external libraries required).

Controls:
  OK         -- Lookup selected IP
  UP / DOWN  -- Scroll IP / results list
  KEY1       -- Load IPs from loot directory
  KEY2       -- Export results
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/WHOIS/whois_YYYYMMDD_HHMMSS.json
"""

import os
import sys
import json
import time
import socket
import re
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
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROWS_VISIBLE = 5
ROW_H = 12

LOOT_SRC_DIR = "/root/Raspyjack/loot/MITM"
LOOT_DIR = "/root/Raspyjack/loot/WHOIS"
WHOIS_SERVER = "whois.iana.org"
WHOIS_PORT = 43
WHOIS_TIMEOUT = 10

# Regional WHOIS servers
REGIONAL_SERVERS = {
    "ARIN": "whois.arin.net",
    "RIPE": "whois.ripe.net",
    "APNIC": "whois.apnic.net",
    "LACNIC": "whois.lacnic.net",
    "AFRINIC": "whois.afrinic.net",
}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
looking_up = False
scroll = 0
selected = 0
status_msg = "Ready"

# IP list and results
ip_list = []
# Results: {ip: {"hostname": ..., "org": ..., "country": ..., "whois_raw": ...}}
results = {}

# ---------------------------------------------------------------------------
# IP extraction from loot
# ---------------------------------------------------------------------------

def _is_public_ip(ip_str):
    """Check if an IP is a public (non-RFC1918, non-loopback) address."""
    try:
        parts = ip_str.split(".")
        if len(parts) != 4:
            return False
        octets = [int(p) for p in parts]
        if octets[0] == 10:
            return False
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return False
        if octets[0] == 192 and octets[1] == 168:
            return False
        if octets[0] == 127:
            return False
        if octets[0] == 0 or octets[0] >= 224:
            return False
        return True
    except (ValueError, IndexError):
        return False


def _load_ips_from_loot():
    """Scan loot directory for IP addresses in JSON/text files."""
    found = set()
    ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

    if not os.path.isdir(LOOT_SRC_DIR):
        return list(found)

    for root, _dirs, files in os.walk(LOOT_SRC_DIR):
        for fname in files:
            if not fname.endswith((".json", ".txt", ".log", ".csv")):
                continue
            filepath = os.path.join(root, fname)
            try:
                with open(filepath, "r", errors="ignore") as f:
                    content = f.read(1024 * 512)  # limit read to 512KB
                matches = ip_pattern.findall(content)
                for ip in matches:
                    if _is_public_ip(ip):
                        found.add(ip)
            except Exception:
                pass

    return sorted(found)

# ---------------------------------------------------------------------------
# Reverse DNS
# ---------------------------------------------------------------------------

def _reverse_dns(ip_str):
    """Perform reverse DNS lookup."""
    try:
        hostname = socket.getfqdn(ip_str)
        if hostname == ip_str:
            return ""
        return hostname
    except Exception:
        return ""

# ---------------------------------------------------------------------------
# WHOIS lookup
# ---------------------------------------------------------------------------

def _whois_query(server, query, timeout=WHOIS_TIMEOUT):
    """Send a WHOIS query to a server and return the response."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((server, WHOIS_PORT))
        sock.sendall((query + "\r\n").encode("ascii"))
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        sock.close()
        return response.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _find_regional_server(iana_response):
    """Extract the regional WHOIS server from IANA response."""
    refer_match = re.search(r"refer:\s+(\S+)", iana_response, re.IGNORECASE)
    if refer_match:
        return refer_match.group(1)
    # Try to match known registries
    for name, server in REGIONAL_SERVERS.items():
        if name.lower() in iana_response.lower():
            return server
    return None


def _parse_whois(raw_text):
    """Extract org and country from WHOIS response."""
    org = ""
    country = ""

    org_patterns = [
        r"OrgName:\s+(.+)",
        r"org-name:\s+(.+)",
        r"Organization:\s+(.+)",
        r"descr:\s+(.+)",
        r"netname:\s+(.+)",
    ]
    for pattern in org_patterns:
        match = re.search(pattern, raw_text, re.IGNORECASE)
        if match:
            org = match.group(1).strip()
            break

    country_patterns = [
        r"Country:\s+(\S+)",
        r"country:\s+(\S+)",
    ]
    for pattern in country_patterns:
        match = re.search(pattern, raw_text, re.IGNORECASE)
        if match:
            country = match.group(1).strip().upper()
            break

    return org, country


def _full_whois(ip_str):
    """Perform full WHOIS lookup: IANA -> regional server."""
    # First query IANA
    iana_resp = _whois_query(WHOIS_SERVER, ip_str)
    regional = _find_regional_server(iana_resp)

    raw = iana_resp
    if regional:
        regional_resp = _whois_query(regional, ip_str)
        if regional_resp:
            raw = regional_resp

    org, country = _parse_whois(raw)
    return org, country, raw

# ---------------------------------------------------------------------------
# Lookup thread
# ---------------------------------------------------------------------------

def _lookup_thread(ip_str):
    """Perform reverse DNS + WHOIS for an IP."""
    global looking_up, status_msg

    with lock:
        status_msg = f"Looking up {ip_str}..."

    hostname = _reverse_dns(ip_str)
    org, country, raw = _full_whois(ip_str)

    with lock:
        results[ip_str] = {
            "hostname": hostname,
            "org": org[:40],
            "country": country,
            "whois_raw": raw[:2000],
        }
        looking_up = False
        if org:
            status_msg = f"{ip_str}: {org[:16]}"
        else:
            status_msg = f"{ip_str}: lookup done"

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_loot():
    """Export results to JSON."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"whois_{ts}.json"
    filepath = os.path.join(LOOT_DIR, filename)

    with lock:
        data = {
            "timestamp": ts,
            "lookups": len(results),
            "results": {
                ip: {
                    "hostname": r["hostname"],
                    "org": r["org"],
                    "country": r["country"],
                }
                for ip, r in results.items()
            },
        }

    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)

    return filename

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_frame(lcd, font_obj):
    """Render current state to the LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "WHOIS LOOKUP", font=font_obj, fill="#00CCFF")
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if looking_up else "#444")

    with lock:
        msg = status_msg
        ips = list(ip_list)
        sel = selected
        res = dict(results)

    d.text((2, 16), msg[:24], font=font_obj, fill="#AAAAAA")
    d.text((2, 28), f"IPs: {len(ips)}  Looked up: {len(res)}", font=font_obj, fill="#888")

    if ips:
        # Show IP list with results
        visible = ips[scroll:scroll + ROWS_VISIBLE]
        for i, ip in enumerate(visible):
            y = 42 + i * ROW_H
            idx = scroll + i
            marker = ">" if idx == sel else " "
            color = "#FFAA00" if idx == sel else "#CCCCCC"

            info = res.get(ip)
            if info:
                label = info["country"][:2] if info["country"] else ""
                line = f"{marker}{ip} {label}"
            else:
                line = f"{marker}{ip}"

            d.text((2, y), line[:24], font=font_obj, fill=color)

        # Show details for selected IP
        if 0 <= sel < len(ips):
            sel_ip = ips[sel]
            info = res.get(sel_ip)
            if info:
                y_detail = 42 + ROWS_VISIBLE * ROW_H + 2
                if info["hostname"]:
                    d.text((2, y_detail), info["hostname"][:24], font=font_obj, fill="#00FF88")
                    y_detail += 10
                if info["org"]:
                    d.text((2, y_detail), info["org"][:24], font=font_obj, fill="#FFAA00")
    else:
        d.text((2, 50), "KEY1: Load from loot", font=font_obj, fill="#666")
        d.text((2, 65), "Or wait for scan data", font=font_obj, fill="#666")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Lkup K1:Load K3:Quit", font=font_obj, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, looking_up, scroll, selected, status_msg, ip_list

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font_obj = scaled_font()

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK" and not looking_up:
                with lock:
                    if ip_list and 0 <= selected < len(ip_list):
                        ip = ip_list[selected]
                        looking_up = True
                        threading.Thread(
                            target=_lookup_thread, args=(ip,), daemon=True
                        ).start()
                time.sleep(0.3)

            elif btn == "KEY1":
                with lock:
                    status_msg = "Loading IPs..."
                loaded = _load_ips_from_loot()
                with lock:
                    ip_list = loaded
                    selected = 0
                    scroll = 0
                    status_msg = f"Loaded {len(loaded)} IPs"
                time.sleep(0.3)

            elif btn == "KEY2":
                with lock:
                    has_data = len(results) > 0
                if has_data:
                    fname = _export_loot()
                    with lock:
                        status_msg = f"Exported: {fname[:16]}"
                else:
                    with lock:
                        status_msg = "No data to export"
                time.sleep(0.3)

            elif btn == "UP":
                selected = max(0, selected - 1)
                if selected < scroll:
                    scroll = selected
                time.sleep(0.15)

            elif btn == "DOWN":
                max_sel = max(0, len(ip_list) - 1)
                selected = min(selected + 1, max_sel)
                if selected >= scroll + ROWS_VISIBLE:
                    scroll = selected - ROWS_VISIBLE + 1
                time.sleep(0.15)

            _draw_frame(lcd, font_obj)
            time.sleep(0.05)

    finally:
        _running = False
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
