#!/usr/bin/env python3
"""
RaspyJack Payload -- SMB Share Crawler
=======================================
Author: 7h30th3r0n3

Discovers hosts with SMB (port 445) open on the local network, enumerates
accessible shares via null/guest sessions, crawls files recursively (depth 3),
and flags sensitive files (configs, credentials, keys, scripts, backups).

Controls:
  OK        -- Start scan
  UP / DOWN -- Scroll
  KEY1      -- Toggle view (hosts / shares / files)
  KEY3      -- Exit

Loot: /root/Raspyjack/loot/SMBCrawl/crawl_<timestamp>.json
"""

import os
import sys
import json
import time
import socket
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
LOOT_DIR = "/root/Raspyjack/loot/SMBCrawl"
os.makedirs(LOOT_DIR, exist_ok=True)

MAX_DEPTH = 3
SMB_TIMEOUT = 8
PORT_TIMEOUT = 2

SENSITIVE_EXTENSIONS = {
    ".conf", ".config", ".ini", ".txt", ".xml", ".ps1", ".bat",
    ".cmd", ".sql", ".bak", ".key", ".pem", ".pfx", ".env",
    ".cfg", ".json", ".yml", ".yaml",
}
SENSITIVE_KEYWORDS = {
    "password", "credential", "secret", "passwd", "shadow",
    "htpasswd", "wp-config", "web.config", "id_rsa", "authorized_keys",
}

ROWS_VISIBLE = 7
ROW_H = 12

VIEW_HOSTS = 0
VIEW_SHARES = 1
VIEW_FILES = 2
VIEW_NAMES = ["HOSTS", "SHARES", "FILES"]

# ---------------------------------------------------------------------------
# Shared state (protected by lock)
# ---------------------------------------------------------------------------
lock = threading.Lock()
status_msg = "Ready"
busy = False
stop_flag = False
scroll_pos = 0
current_view = VIEW_HOSTS

# Discovered data
hosts = []          # [{"ip": str, "shares": [...]}]
all_shares = []     # [{"host": str, "name": str, "type": str, "files": [...]}]
all_files = []      # [{"host": str, "share": str, "path": str, "sensitive": bool}]


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _get_subnet():
    """Return the local subnet in CIDR notation from the default route."""
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
                    r2 = subprocess.run(
                        ["ip", "-4", "addr", "show", iface],
                        capture_output=True, text=True, timeout=5,
                    )
                    match = re.search(
                        r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", r2.stdout,
                    )
                    if match:
                        return match.group(1)
    except Exception:
        pass
    return None


def _get_arp_hosts():
    """Collect IPs from the ARP table."""
    found = set()
    try:
        result = subprocess.run(
            ["arp", "-an"], capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
            if match:
                ip = match.group(1)
                if not ip.endswith(".255") and not ip.endswith(".0"):
                    found.add(ip)
    except Exception:
        pass
    return found


def _ping_sweep(subnet):
    """Quick nmap ping sweep to populate the ARP table."""
    try:
        subprocess.run(
            ["nmap", "-sn", "-T4", "--max-retries", "1", subnet],
            capture_output=True, text=True, timeout=30,
        )
    except Exception:
        pass


def _check_port_445(ip):
    """Return True if port 445 is open on the given IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(PORT_TIMEOUT)
        result = sock.connect_ex((ip, 445))
        sock.close()
        return result == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# SMB enumeration via smbclient
# ---------------------------------------------------------------------------

def _enumerate_shares(ip):
    """Try null session then guest session to list shares on a host."""
    attempts = [
        ["smbclient", "-L", f"//{ip}", "-N", "--timeout", str(SMB_TIMEOUT)],
        ["smbclient", "-L", f"//{ip}", "-U", "guest%", "--timeout",
         str(SMB_TIMEOUT)],
    ]
    for cmd in attempts:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=SMB_TIMEOUT + 5,
            )
            shares = _parse_share_list(result.stdout)
            if shares:
                return shares
        except Exception:
            continue
    return []


def _parse_share_list(output):
    """Parse smbclient -L output into a list of share dicts."""
    shares = []
    in_share_section = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Sharename") and "Type" in stripped:
            in_share_section = True
            continue
        if in_share_section and stripped.startswith("---"):
            continue
        if in_share_section:
            if not stripped or stripped.startswith("Reconnecting"):
                in_share_section = False
                continue
            parts = stripped.split()
            if len(parts) >= 2:
                name = parts[0]
                share_type = parts[1]
                shares.append({"name": name, "type": share_type})
    return shares


def _is_sensitive(filename):
    """Check whether a filename matches sensitive patterns."""
    lower = filename.lower()
    _, ext = os.path.splitext(lower)
    if ext in SENSITIVE_EXTENSIONS:
        return True
    for keyword in SENSITIVE_KEYWORDS:
        if keyword in lower:
            return True
    return False


def _list_files_recursive(ip, share_name, path="", depth=0):
    """List files in an SMB share recursively up to MAX_DEPTH."""
    if depth >= MAX_DEPTH:
        return []

    with lock:
        if stop_flag:
            return []

    smb_path = f"//{ip}/{share_name}"
    ls_cmd = f'ls "{path}\\*"' if path else 'ls'

    cmd = [
        "smbclient", smb_path, "-N", "--timeout", str(SMB_TIMEOUT),
        "-c", ls_cmd,
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=SMB_TIMEOUT + 5,
        )
    except Exception:
        # Retry with guest credentials
        cmd_guest = [
            "smbclient", smb_path, "-U", "guest%", "--timeout",
            str(SMB_TIMEOUT), "-c", ls_cmd,
        ]
        try:
            result = subprocess.run(
                cmd_guest, capture_output=True, text=True,
                timeout=SMB_TIMEOUT + 5,
            )
        except Exception:
            return []

    entries = _parse_ls_output(result.stdout)
    found_files = []

    for entry in entries:
        name = entry["name"]
        if name in (".", ".."):
            continue

        full_path = f"{path}\\{name}" if path else name

        if entry["is_dir"]:
            sub_files = _list_files_recursive(
                ip, share_name, full_path, depth + 1,
            )
            found_files.extend(sub_files)
        else:
            sensitive = _is_sensitive(name)
            found_files.append({
                "host": ip,
                "share": share_name,
                "path": full_path,
                "sensitive": sensitive,
                "size": entry.get("size", ""),
            })

    return found_files


def _parse_ls_output(output):
    """Parse smbclient ls output into entries."""
    entries = []
    # smbclient ls format:  "  filename       A    1234  Thu Jan  1 00:00:00 2025"
    pattern = re.compile(
        r"^\s\s(.+?)\s{2,}([ADHRNS]+)\s+(\d+)\s+\w{3}\s+\w{3}\s+",
    )
    for line in output.splitlines():
        match = pattern.match(line)
        if match:
            name = match.group(1).strip()
            attrs = match.group(2)
            size = match.group(3)
            is_dir = "D" in attrs
            entries.append({
                "name": name,
                "is_dir": is_dir,
                "size": size,
            })
    return entries


# ---------------------------------------------------------------------------
# Background scan orchestration
# ---------------------------------------------------------------------------

def _do_scan():
    """Main scan routine: discover hosts, enumerate shares, crawl files."""
    global busy, status_msg, hosts, all_shares, all_files, stop_flag

    with lock:
        busy = True
        stop_flag = False
        status_msg = "Discovering hosts..."
        hosts = []
        all_shares = []
        all_files = []

    # Step 1: ARP discovery + ping sweep
    subnet = _get_subnet()
    if subnet:
        with lock:
            status_msg = f"Ping sweep {subnet}"
        _ping_sweep(subnet)

    candidate_ips = sorted(_get_arp_hosts())

    with lock:
        if stop_flag:
            busy = False
            return
        status_msg = f"Checking 445 on {len(candidate_ips)} hosts"

    # Step 2: Filter to hosts with port 445 open
    smb_hosts = []
    for i, ip in enumerate(candidate_ips):
        with lock:
            if stop_flag:
                busy = False
                return
            status_msg = f"Port 445: {ip} ({i + 1}/{len(candidate_ips)})"
        if _check_port_445(ip):
            smb_hosts.append(ip)

    if not smb_hosts:
        with lock:
            status_msg = "No SMB hosts found"
            busy = False
        return

    # Step 3: Enumerate shares on each host
    for i, ip in enumerate(smb_hosts):
        with lock:
            if stop_flag:
                busy = False
                return
            status_msg = f"Enum shares: {ip} ({i + 1}/{len(smb_hosts)})"

        share_list = _enumerate_shares(ip)
        host_entry = {"ip": ip, "shares": []}

        for share_info in share_list:
            share_name = share_info["name"]
            share_type = share_info["type"]

            # Skip IPC$ and printer shares
            if share_name.upper() in ("IPC$",) or share_type == "Printer":
                continue

            with lock:
                status_msg = f"Crawl //{ip}/{share_name}"

            files = _list_files_recursive(ip, share_name)

            share_entry = {
                "host": ip,
                "name": share_name,
                "type": share_type,
                "file_count": len(files),
                "sensitive_count": sum(1 for f in files if f["sensitive"]),
            }
            host_entry["shares"].append(share_entry)

            with lock:
                all_shares.append(share_entry)
                all_files.extend(files)

        with lock:
            hosts.append(host_entry)

    with lock:
        sensitive_total = sum(1 for f in all_files if f["sensitive"])
        status_msg = (
            f"Done: {len(smb_hosts)}h {len(all_shares)}s "
            f"{len(all_files)}f ({sensitive_total} flagged)"
        )
        busy = False

    _save_loot()


def _save_loot():
    """Write scan results to a JSON loot file."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    with lock:
        data = {
            "timestamp": ts,
            "hosts": [dict(h, shares=[dict(s) for s in h["shares"]])
                      for h in hosts],
            "total_shares": len(all_shares),
            "total_files": len(all_files),
            "sensitive_files": [dict(f) for f in all_files if f["sensitive"]],
            "all_files": [dict(f) for f in all_files],
        }
    path = os.path.join(LOOT_DIR, f"crawl_{ts}.json")
    try:
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
    except Exception:
        pass
    return path


def start_scan():
    """Launch the scan in a background thread."""
    with lock:
        if busy:
            return
    threading.Thread(target=_do_scan, daemon=True).start()


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(d, title):
    """Render the header bar with title and activity indicator."""
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title, font=font, fill="#00CCFF")
    with lock:
        active = busy
    indicator_color = "#00FF00" if active else "#FF0000"
    d.ellipse((118, 3, 122, 7), fill=indicator_color)


def _draw_footer(d, text):
    """Render the footer bar."""
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font, fill="#AAA")


def _draw_scrollbar(d, offset, total, area_top=28, area_height=88):
    """Render a simple scrollbar on the right edge."""
    if total <= ROWS_VISIBLE:
        return
    bar_h = max(4, int(ROWS_VISIBLE / total * area_height))
    bar_y = area_top + int(offset / total * area_height) if total > 0 else area_top
    d.rectangle((126, bar_y, 127, bar_y + bar_h), fill="#444")


def draw_hosts_view():
    """Render the hosts list view."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "SMB CRAWLER")

    with lock:
        status = status_msg
        host_list = list(hosts)
        sc = scroll_pos

    d.text((2, 15), status[:22], font=font, fill="#888")

    if not host_list:
        d.text((10, 45), "OK: Start scan", font=font, fill="#666")
        d.text((10, 57), "K1: Toggle view", font=font, fill="#666")
        d.text((10, 69), "K3: Exit", font=font, fill="#666")
    else:
        visible = host_list[sc:sc + ROWS_VISIBLE]
        for i, h in enumerate(visible):
            y = 28 + i * ROW_H
            share_count = len(h["shares"])
            line = f"{h['ip']} [{share_count}s]"
            d.text((1, y), line[:22], font=font, fill="#CCCCCC")
        _draw_scrollbar(d, sc, len(host_list))

    _draw_footer(d, f"Hosts:{len(host_list)} K3:Exit")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_shares_view():
    """Render the shares list view."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "SMB SHARES")

    with lock:
        status = status_msg
        share_list = list(all_shares)
        sc = scroll_pos

    d.text((2, 15), status[:22], font=font, fill="#888")

    if not share_list:
        d.text((10, 50), "No shares found", font=font, fill="#666")
    else:
        visible = share_list[sc:sc + ROWS_VISIBLE]
        for i, s in enumerate(visible):
            y = 28 + i * ROW_H
            host_short = s["host"].split(".")[-1]
            flag = "*" if s["sensitive_count"] > 0 else " "
            line = f"{flag}.{host_short}/{s['name']} {s['file_count']}f"
            d.text((1, y), line[:22], font=font, fill="#CCCCCC")
        _draw_scrollbar(d, sc, len(share_list))

    _draw_footer(d, f"Shares:{len(share_list)} K1:View")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_files_view():
    """Render the files list view (sensitive files highlighted)."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "SMB FILES")

    with lock:
        status = status_msg
        file_list = list(all_files)
        sc = scroll_pos

    d.text((2, 15), status[:22], font=font, fill="#888")

    if not file_list:
        d.text((10, 50), "No files found", font=font, fill="#666")
    else:
        visible = file_list[sc:sc + ROWS_VISIBLE]
        for i, f in enumerate(visible):
            y = 28 + i * ROW_H
            name = f["path"].split("\\")[-1] if "\\" in f["path"] else f["path"]
            color = "#FF4444" if f["sensitive"] else "#CCCCCC"
            marker = "!" if f["sensitive"] else " "
            line = f"{marker}{name}"
            d.text((1, y), line[:22], font=font, fill=color)
        _draw_scrollbar(d, sc, len(file_list))

    with lock:
        sensitive_count = sum(1 for f in all_files if f["sensitive"])
    _draw_footer(d, f"Files:{len(file_list)} Flag:{sensitive_count}")
    LCD.LCD_ShowImage(img, 0, 0)


DRAW_FUNCS = [draw_hosts_view, draw_shares_view, draw_files_view]


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    global scroll_pos, current_view, stop_flag

    # Splash screen
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 20), "SMB CRAWLER", font=font, fill="#00CCFF")
    d.text((4, 38), "Share enumeration &", font=font, fill="#888")
    d.text((4, 50), "sensitive file finder", font=font, fill="#888")
    d.text((4, 70), "OK    Start scan", font=font, fill="#666")
    d.text((4, 82), "KEY1  Toggle view", font=font, fill="#666")
    d.text((4, 94), "KEY3  Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.3)

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                with lock:
                    stop_flag = True
                if all_files or all_shares:
                    _save_loot()
                break

            if btn == "OK":
                start_scan()
                time.sleep(0.3)
            elif btn == "KEY1":
                with lock:
                    current_view = (current_view + 1) % len(VIEW_NAMES)
                    scroll_pos = 0
                time.sleep(0.2)
            elif btn == "UP":
                with lock:
                    scroll_pos = max(0, scroll_pos - 1)
                time.sleep(0.15)
            elif btn == "DOWN":
                with lock:
                    if current_view == VIEW_HOSTS:
                        max_sc = max(0, len(hosts) - ROWS_VISIBLE)
                    elif current_view == VIEW_SHARES:
                        max_sc = max(0, len(all_shares) - ROWS_VISIBLE)
                    else:
                        max_sc = max(0, len(all_files) - ROWS_VISIBLE)
                    scroll_pos = min(max_sc, scroll_pos + 1)
                time.sleep(0.15)

            with lock:
                view = current_view
            DRAW_FUNCS[view]()
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
