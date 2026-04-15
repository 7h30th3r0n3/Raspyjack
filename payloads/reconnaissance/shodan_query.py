#!/usr/bin/env python3
"""
RaspyJack Payload -- Shodan InternetDB Query
=============================================
Author: 7h30th3r0n3

Queries the free Shodan InternetDB API (no API key required) for IP
intelligence.  Auto-detects public IP or allows manual entry via a
character picker.  Displays open ports, hostnames, CVEs, CPEs, and tags.

Controls:
  UP / DOWN   -- Scroll results / navigate picker
  LEFT / RIGHT-- Move cursor in IP picker
  OK          -- Query IP / confirm picker selection
  KEY1        -- Load IPs from loot directory
  KEY2        -- Export results to loot
  KEY3        -- Exit

Loot: /root/Raspyjack/loot/Shodan/shodan_YYYYMMDD_HHMMSS.json
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

try:
    import urllib.request
    import urllib.error
except ImportError:
    pass

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button, open_remote_text_session, get_remote_text_event, close_remote_text_session

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROWS_VISIBLE = 7
ROW_H = 12

LOOT_DIR = "/root/Raspyjack/loot/Shodan"
LOOT_SRC_DIR = "/root/Raspyjack/loot"
API_URL = "https://internetdb.shodan.io/"
API_TIMEOUT = 10

IP_CHARS = "0123456789."

# Views
VIEW_INPUT = "input"
VIEW_RESULTS = "results"
VIEW_IPLIST = "iplist"

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
status_msg = "Ready"
current_view = VIEW_INPUT
querying = False

# IP input state
ip_buffer = ""
char_index = 0
cursor_pos = 0

# Results
current_ip = ""
result_data = {}     # raw API response
result_lines = []    # formatted display lines
result_scroll = 0

# IP list from loot
ip_list = []
ip_selected = 0
ip_scroll = 0

# All results for export
all_results = {}     # ip -> result_data

# ---------------------------------------------------------------------------
# Public IP detection
# ---------------------------------------------------------------------------

def _detect_public_ip():
    """Auto-detect public IP via ifconfig.me."""
    try:
        req = urllib.request.Request(
            "https://ifconfig.me",
            headers={"User-Agent": "curl/7.0"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            ip = resp.read().decode("utf-8").strip()
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            return ip
    except Exception:
        pass
    return ""

# ---------------------------------------------------------------------------
# IP extraction from loot
# ---------------------------------------------------------------------------

def _is_public_ip(ip_str):
    """Check if IP is public (non-RFC1918, non-loopback)."""
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
    """Scan loot directory for public IP addresses."""
    found = set()
    ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

    if not os.path.isdir(LOOT_SRC_DIR):
        return sorted(found)

    for root, _dirs, files in os.walk(LOOT_SRC_DIR):
        for fname in files:
            if not fname.endswith((".json", ".txt", ".log", ".csv")):
                continue
            filepath = os.path.join(root, fname)
            try:
                with open(filepath, "r", errors="ignore") as f:
                    content = f.read(512 * 1024)
                matches = ip_pattern.findall(content)
                for ip in matches:
                    if _is_public_ip(ip):
                        found.add(ip)
            except Exception:
                pass

    return sorted(found)

# ---------------------------------------------------------------------------
# Shodan InternetDB query
# ---------------------------------------------------------------------------

def _query_internetdb(ip_str):
    """Query Shodan InternetDB for an IP. Returns dict or error string."""
    url = f"{API_URL}{ip_str}"
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "RaspyJack/1.0", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=API_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8")
        data = json.loads(raw)
        return data
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"error": "No data for this IP"}
        return {"error": f"HTTP {exc.code}"}
    except urllib.error.URLError as exc:
        return {"error": f"Network error: {str(exc.reason)[:30]}"}
    except Exception as exc:
        return {"error": str(exc)[:40]}

# ---------------------------------------------------------------------------
# Format results
# ---------------------------------------------------------------------------

def _format_results(data):
    """Convert API response dict into display lines."""
    lines = []

    if "error" in data:
        lines.append(("Error: " + data["error"], "#FF4444"))
        return lines

    ip = data.get("ip", "?")
    lines.append((f"IP: {ip}", "#00CCFF"))

    # Ports
    ports = data.get("ports", [])
    lines.append((f"-- Ports ({len(ports)}) --", "#00FF88"))
    if ports:
        port_str = ", ".join(str(p) for p in ports[:20])
        # Split long port strings across lines
        while port_str:
            lines.append((f"  {port_str[:22]}", "#CCCCCC"))
            port_str = port_str[22:]
    else:
        lines.append(("  None", "#666666"))

    # Hostnames
    hostnames = data.get("hostnames", [])
    lines.append((f"-- Hostnames ({len(hostnames)}) --", "#00FF88"))
    for h in hostnames[:8]:
        lines.append((f"  {h[:22]}", "#CCCCCC"))
    if not hostnames:
        lines.append(("  None", "#666666"))

    # Vulns (CVEs)
    vulns = data.get("vulns", [])
    lines.append((f"-- Vulns ({len(vulns)}) --", "#FF4444"))
    for v in vulns[:10]:
        lines.append((f"  {v[:22]}", "#FF8800"))
    if not vulns:
        lines.append(("  None", "#00FF00"))

    # CPEs
    cpes = data.get("cpes", [])
    lines.append((f"-- CPEs ({len(cpes)}) --", "#00FF88"))
    for c in cpes[:8]:
        lines.append((f"  {c[:22]}", "#CCCCCC"))
    if not cpes:
        lines.append(("  None", "#666666"))

    # Tags
    tags = data.get("tags", [])
    lines.append((f"-- Tags ({len(tags)}) --", "#00FF88"))
    if tags:
        tag_str = ", ".join(tags[:10])
        lines.append((f"  {tag_str[:22]}", "#CCCCCC"))
    else:
        lines.append(("  None", "#666666"))

    return lines

# ---------------------------------------------------------------------------
# Query thread
# ---------------------------------------------------------------------------

def _query_thread(ip_str):
    """Run InternetDB query in background."""
    global querying, status_msg, result_data, result_lines
    global result_scroll, current_ip, current_view

    with lock:
        status_msg = f"Querying {ip_str}..."

    data = _query_internetdb(ip_str)
    lines = _format_results(data)

    with lock:
        result_data = dict(data)
        result_lines = list(lines)
        result_scroll = 0
        current_ip = ip_str
        all_results[ip_str] = dict(data)
        querying = False
        current_view = VIEW_RESULTS
        if "error" in data:
            status_msg = f"{ip_str}: {data['error'][:20]}"
        else:
            n_ports = len(data.get("ports", []))
            n_vulns = len(data.get("vulns", []))
            status_msg = f"{ip_str}: {n_ports}p {n_vulns}v"

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_results():
    """Export all query results to JSON."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"shodan_{ts}.json")

    with lock:
        data = {
            "timestamp": ts,
            "queries": len(all_results),
            "results": {ip: dict(r) for ip, r in all_results.items()},
        }

    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)

    return os.path.basename(filepath)

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_input_view(lcd, font_obj):
    """Render IP input view with character picker."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "SHODAN QUERY", font=font_obj, fill="#00CCFF")

    with lock:
        msg = status_msg
        buf = ip_buffer
        ci = char_index
        cp = cursor_pos

    d.text((2, 16), msg[:24], font=font_obj, fill="#AAAAAA")

    # IP input field
    d.rectangle((2, 30, 125, 44), outline="#444")
    display_ip = buf if buf else "_._._._ "
    d.text((4, 32), display_ip[:20], font=font_obj, fill="#FFFFFF")

    # Cursor indicator
    if buf:
        cursor_x = 4 + cp * 7
        d.line((cursor_x, 45, cursor_x + 6, 45), fill="#00CCFF")

    # Character picker
    d.text((2, 50), "Character:", font=font_obj, fill="#888")
    for i, ch in enumerate(IP_CHARS):
        x = 4 + i * 10
        color = "#FFAA00" if i == ci else "#666"
        d.text((x, 62), ch, font=font_obj, fill=color)

    # Instructions
    d.text((2, 78), "UP/DN: char  L/R: move", font=font_obj, fill="#666")
    d.text((2, 90), "OK: add char/query", font=font_obj, fill="#666")
    d.text((2, 102), "K1: Load IPs from loot", font=font_obj, fill="#666")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Query K1:Load K3:Qt", font=font_obj, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_results_view(lcd, font_obj):
    """Render scrollable results view."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    with lock:
        ip = current_ip
    d.text((2, 1), f"Shodan: {ip}", font=font_obj, fill="#00CCFF")

    with lock:
        lines = list(result_lines)
        rs = result_scroll

    visible = lines[rs:rs + ROWS_VISIBLE + 1]
    for i, (text, color) in enumerate(visible):
        y = 16 + i * ROW_H
        d.text((2, y), text[:24], font=font_obj, fill=color)

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "LEFT:Bk K2:Exp K3:Qt", font=font_obj, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_iplist_view(lcd, font_obj):
    """Render IP list loaded from loot."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "LOOT IPs", font=font_obj, fill="#00CCFF")

    with lock:
        ips = list(ip_list)
        sel = ip_selected
        sc = ip_scroll
        msg = status_msg

    d.text((2, 15), msg[:24], font=font_obj, fill="#AAAAAA")

    if ips:
        visible = ips[sc:sc + ROWS_VISIBLE]
        for i, ip in enumerate(visible):
            y = 28 + i * ROW_H
            idx = sc + i
            color = "#FFAA00" if idx == sel else "#CCCCCC"
            marker = ">" if idx == sel else " "
            queried = " *" if ip in all_results else ""
            d.text((2, y), f"{marker}{ip}{queried}", font=font_obj, fill=color)
    else:
        d.text((2, 40), "No IPs found in loot", font=font_obj, fill="#666")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Query LEFT:Bk", font=font_obj, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


def _start_query(ip_str):
    global querying
    if querying:
        return False
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_str):
        return False
    querying = True
    threading.Thread(target=_query_thread, args=(ip_str,), daemon=True).start()
    return True


def _apply_remote_ip_event(remote_event):
    global ip_buffer, cursor_pos, status_msg

    special = str(remote_event.get("special") or "")
    if special == "BACKSPACE":
        if ip_buffer:
            ip_buffer = ip_buffer[:-1]
            cursor_pos = len(ip_buffer)
        return

    if special == "ENTER":
        ip = ip_buffer.strip()
        if not _start_query(ip):
            with lock:
                status_msg = "Invalid IP format"
        return

    if special == "ESCAPE":
        return

    key_value = str(remote_event.get("key") or "")
    if not key_value:
        return

    filtered = "".join(ch for ch in key_value if ch in IP_CHARS)
    if not filtered:
        return

    ip_buffer = (ip_buffer + filtered)[:15]
    cursor_pos = len(ip_buffer)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, status_msg, querying, current_view
    global ip_buffer, char_index, cursor_pos
    global result_scroll, ip_list, ip_selected, ip_scroll

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font_obj = scaled_font()
    remote_session_id = None

    try:
        # Auto-detect public IP
        with lock:
            status_msg = "Detecting IP..."
        _draw_input_view(lcd, font_obj)

        detected = _detect_public_ip()
        with lock:
            if detected:
                ip_buffer = detected
                cursor_pos = len(detected)
                status_msg = f"Public IP: {detected}"
            else:
                ip_buffer = ""
                cursor_pos = 0
                status_msg = "Enter IP manually"

        while _running:
            if current_view == VIEW_INPUT and remote_session_id is None:
                remote_session_id = open_remote_text_session(
                    title="SHODAN IP",
                    default=ip_buffer,
                    charset="ip",
                    max_len=15,
                )
            elif current_view != VIEW_INPUT and remote_session_id is not None:
                close_remote_text_session(remote_session_id)
                remote_session_id = None

            if current_view == VIEW_INPUT and remote_session_id is not None:
                remote_event = get_remote_text_event(remote_session_id)
                if remote_event:
                    _apply_remote_ip_event(remote_event)

            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            # --- Input view controls ---
            elif current_view == VIEW_INPUT:
                if btn == "UP":
                    char_index = (char_index - 1) % len(IP_CHARS)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    char_index = (char_index + 1) % len(IP_CHARS)
                    time.sleep(0.15)
                elif btn == "LEFT":
                    if cursor_pos > 0:
                        # Delete character at cursor
                        ip_buffer = ip_buffer[:cursor_pos - 1] + ip_buffer[cursor_pos:]
                        cursor_pos = max(0, cursor_pos - 1)
                    time.sleep(0.2)
                elif btn == "RIGHT":
                    # Add selected character
                    ch = IP_CHARS[char_index]
                    ip_buffer = ip_buffer[:cursor_pos] + ch + ip_buffer[cursor_pos:]
                    cursor_pos += 1
                    time.sleep(0.2)
                elif btn == "OK" and not querying:
                    ip = ip_buffer.strip()
                    if not _start_query(ip):
                        with lock:
                            status_msg = "Invalid IP format"
                    time.sleep(0.3)
                elif btn == "KEY1":
                    with lock:
                        status_msg = "Loading IPs..."
                    loaded = _load_ips_from_loot()
                    with lock:
                        ip_list = loaded
                        ip_selected = 0
                        ip_scroll = 0
                        if loaded:
                            current_view = VIEW_IPLIST
                            status_msg = f"Found {len(loaded)} IPs"
                        else:
                            status_msg = "No IPs in loot"
                    time.sleep(0.3)
                elif btn == "KEY2":
                    with lock:
                        has_data = len(all_results) > 0
                    if has_data:
                        fname = _export_results()
                        with lock:
                            status_msg = f"Saved: {fname[:16]}"
                    else:
                        with lock:
                            status_msg = "No data to export"
                    time.sleep(0.3)

            # --- Results view controls ---
            elif current_view == VIEW_RESULTS:
                if btn == "UP":
                    result_scroll = max(0, result_scroll - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        max_scroll = max(0, len(result_lines) - ROWS_VISIBLE)
                    result_scroll = min(result_scroll + 1, max_scroll)
                    time.sleep(0.15)
                elif btn == "LEFT":
                    current_view = VIEW_INPUT
                    time.sleep(0.3)
                elif btn == "KEY2":
                    with lock:
                        has_data = len(all_results) > 0
                    if has_data:
                        fname = _export_results()
                        with lock:
                            status_msg = f"Saved: {fname[:16]}"
                    time.sleep(0.3)

            # --- IP list view controls ---
            elif current_view == VIEW_IPLIST:
                if btn == "UP":
                    ip_selected = max(0, ip_selected - 1)
                    if ip_selected < ip_scroll:
                        ip_scroll = ip_selected
                    time.sleep(0.15)
                elif btn == "DOWN":
                    max_sel = max(0, len(ip_list) - 1)
                    ip_selected = min(ip_selected + 1, max_sel)
                    if ip_selected >= ip_scroll + ROWS_VISIBLE:
                        ip_scroll = ip_selected - ROWS_VISIBLE + 1
                    time.sleep(0.15)
                elif btn == "LEFT":
                    current_view = VIEW_INPUT
                    time.sleep(0.3)
                elif btn == "OK" and not querying:
                    with lock:
                        if ip_list and 0 <= ip_selected < len(ip_list):
                            target_ip = ip_list[ip_selected]
                            ip_buffer = target_ip
                            cursor_pos = len(target_ip)
                            _start_query(target_ip)
                    time.sleep(0.3)

            # Draw current view
            if current_view == VIEW_INPUT:
                _draw_input_view(lcd, font_obj)
            elif current_view == VIEW_RESULTS:
                _draw_results_view(lcd, font_obj)
            elif current_view == VIEW_IPLIST:
                _draw_iplist_view(lcd, font_obj)

            time.sleep(0.05)

    finally:
        _running = False
        if remote_session_id is not None:
            close_remote_text_session(remote_session_id)
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
