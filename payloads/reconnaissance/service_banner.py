#!/usr/bin/env python3
"""
RaspyJack Payload -- Service Banner Grabber
=============================================
Author: 7h30th3r0n3

Fast service banner grabber.  Reads discovered hosts from Nmap loot or
performs its own quick port scan on common ports.  Connects to each open
port, sends a protocol-appropriate probe, and captures the banner
response.

Controls:
  OK        -- Start scan (all ARP-discovered hosts)
  UP / DOWN -- Scroll results
  KEY1      -- Scan single host (scroll ARP-discovered hosts to pick)
  KEY2      -- Export results to loot
  KEY3      -- Exit

Loot: /root/Raspyjack/loot/Banners/<timestamp>.json
"""

import os
import sys
import json
import time
import socket
import threading
import subprocess
import re
import ssl
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
LOOT_DIR = "/root/Raspyjack/loot/Banners"
NMAP_LOOT = "/root/Raspyjack/loot/Nmap"
os.makedirs(LOOT_DIR, exist_ok=True)

COMMON_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 445, 993, 995,
                3306, 3389, 5432, 8080, 8443]

SSL_PORTS = {443, 993, 995, 8443}

ROWS_VISIBLE = 7
ROW_H = 12

# Protocol-specific probes: port -> bytes to send after connect
PROBES = {
    21:   b"",                                          # FTP sends banner
    22:   b"",                                          # SSH sends banner
    23:   b"",                                          # Telnet sends banner
    25:   b"EHLO probe.local\r\n",                      # SMTP
    80:   b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n",    # HTTP
    110:  b"",                                          # POP3 sends banner
    143:  b"",                                          # IMAP sends banner
    443:  b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n",    # HTTPS
    445:  b"",                                          # SMB
    993:  b"",                                          # IMAPS
    995:  b"",                                          # POP3S
    3306: b"",                                          # MySQL sends banner
    3389: b"",                                          # RDP
    5432: b"",                                          # PostgreSQL
    8080: b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n",    # HTTP alt
    8443: b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n",    # HTTPS alt
}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
busy = False
status_msg = "Idle"
scroll_pos = 0
stop_flag = False

# Banner results: [{"host": str, "port": int, "banner": str, "service": str}]
results = []

# Known hosts from ARP / nmap
known_hosts = []         # [str] - IP addresses
host_scroll = 0          # for single-host picker
host_pick_mode = False   # True when in single-host selection

IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


# ---------------------------------------------------------------------------
# Host discovery
# ---------------------------------------------------------------------------

def _discover_hosts_from_loot():
    """Extract IP addresses from Nmap loot files."""
    hosts = set()
    if os.path.isdir(NMAP_LOOT):
        for fname in os.listdir(NMAP_LOOT):
            fpath = os.path.join(NMAP_LOOT, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                with open(fpath, "r", errors="ignore") as f:
                    content = f.read()
                for match in IP_RE.finditer(content):
                    ip = match.group(1)
                    # Skip broadcast / loopback / multicast
                    first_octet = int(ip.split(".")[0])
                    if first_octet not in (0, 127, 224, 225, 226, 227, 228, 229,
                                           230, 231, 232, 233, 234, 235, 236, 237,
                                           238, 239, 240, 255):
                        if not ip.endswith(".255") and not ip.endswith(".0"):
                            hosts.add(ip)
            except Exception:
                pass
    return sorted(hosts)


def _discover_hosts_from_arp():
    """Get hosts from ARP table."""
    hosts = set()
    try:
        result = subprocess.run(
            ["arp", "-an"], capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
            if match:
                ip = match.group(1)
                if not ip.endswith(".255") and not ip.endswith(".0"):
                    hosts.add(ip)
    except Exception:
        pass
    return sorted(hosts)


def _refresh_hosts():
    """Refresh the list of known hosts from all sources."""
    global known_hosts
    arp_hosts = _discover_hosts_from_arp()
    loot_hosts = _discover_hosts_from_loot()
    combined = sorted(set(arp_hosts) | set(loot_hosts))
    with lock:
        known_hosts = combined
    return combined


# ---------------------------------------------------------------------------
# Banner grabbing
# ---------------------------------------------------------------------------

def _grab_banner(host, port, timeout=4):
    """Connect to host:port and grab service banner."""
    banner = ""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Wrap with SSL for known TLS ports
        if port in SSL_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        # Send probe if any
        probe = PROBES.get(port, b"")
        if probe:
            sock.sendall(probe)

        # Receive response
        try:
            data = sock.recv(1024)
            banner = data.decode("utf-8", errors="replace").strip()
        except socket.timeout:
            pass

        sock.close()
    except (ConnectionRefusedError, OSError):
        return None  # Port closed or unreachable
    except Exception:
        return None
    return banner


def _identify_service(port, banner):
    """Try to identify the service from port and banner."""
    port_services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        445: "SMB", 993: "IMAPS", 995: "POP3S", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    }
    service = port_services.get(port, f"Port-{port}")

    if banner:
        bl = banner.lower()
        if "ssh" in bl:
            service = "SSH"
        elif "ftp" in bl:
            service = "FTP"
        elif "smtp" in bl or "postfix" in bl or "exim" in bl:
            service = "SMTP"
        elif "http" in bl or "html" in bl or "nginx" in bl or "apache" in bl:
            service = "HTTP" if port not in SSL_PORTS else "HTTPS"
        elif "mysql" in bl or "mariadb" in bl:
            service = "MySQL"
        elif "postgresql" in bl:
            service = "PostgreSQL"

    return service


def _scan_host(host):
    """Scan a single host on all common ports and grab banners."""
    global status_msg
    host_results = []
    for port in COMMON_PORTS:
        with lock:
            if stop_flag:
                return host_results
            status_msg = f"Probing {host}:{port}"

        banner = _grab_banner(host, port, timeout=3)
        if banner is not None:
            service = _identify_service(port, banner)
            entry = {
                "host": host,
                "port": port,
                "banner": banner[:200],
                "service": service,
            }
            host_results.append(entry)
            with lock:
                results.append(entry)

    return host_results


def _do_scan_all():
    """Scan all known hosts in background."""
    global busy, status_msg, results, stop_flag

    with lock:
        busy = True
        stop_flag = False
        status_msg = "Discovering hosts..."
        results = []

    hosts = _refresh_hosts()
    if not hosts:
        # Try quick nmap ping sweep
        with lock:
            status_msg = "ARP sweep..."

        try:
            subnet = _get_subnet()
            if subnet:
                subprocess.run(
                    ["nmap", "-sn", "-T4", subnet],
                    capture_output=True, text=True, timeout=30,
                )
        except Exception:
            pass

        hosts = _refresh_hosts()

    if not hosts:
        with lock:
            status_msg = "No hosts found"
            busy = False
        return

    with lock:
        status_msg = f"Scanning {len(hosts)} hosts..."

    for i, host in enumerate(hosts):
        with lock:
            if stop_flag:
                break
            status_msg = f"Host {i + 1}/{len(hosts)}: {host}"
        _scan_host(host)

    with lock:
        status_msg = f"Done: {len(results)} banners"
        busy = False


def _do_scan_single(host):
    """Scan a single host in background."""
    global busy, status_msg, stop_flag

    with lock:
        busy = True
        stop_flag = False
        status_msg = f"Scanning {host}..."

    _scan_host(host)

    with lock:
        status_msg = f"Done: {len(results)} banners"
        busy = False


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


def start_scan_all():
    """Launch full scan in background."""
    with lock:
        if busy:
            return
    threading.Thread(target=_do_scan_all, daemon=True).start()


def start_scan_single(host):
    """Launch single-host scan in background."""
    with lock:
        if busy:
            return
    threading.Thread(target=_do_scan_single, args=(host,), daemon=True).start()


# ---------------------------------------------------------------------------
# Loot export
# ---------------------------------------------------------------------------

def export_loot():
    """Write banner grab results to JSON."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    with lock:
        data = {
            "timestamp": ts,
            "total_banners": len(results),
            "results": [dict(r) for r in results],
        }
    path = os.path.join(LOOT_DIR, f"banners_{ts}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(d, title):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title, font=font, fill="#00CCFF")
    with lock:
        active = busy
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if active else "#FF0000")


def _draw_footer(d, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font, fill="#AAA")


def draw_results_view():
    """Render the banner results list."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "BANNERS")

    with lock:
        res = [dict(r) for r in results]
        status = status_msg
        sc = scroll_pos

    d.text((2, 15), status[:22], font=font, fill="#888")

    if not res:
        d.text((10, 45), "OK: Scan all hosts", font=font, fill="#666")
        d.text((10, 57), "K1: Pick single host", font=font, fill="#666")
    else:
        visible = res[sc:sc + ROWS_VISIBLE - 1]
        for i, entry in enumerate(visible):
            y = 28 + i * ROW_H
            host_short = entry["host"].split(".")[-1]  # last octet
            port = entry["port"]
            svc = entry["service"][:6]
            banner_preview = entry["banner"][:8].replace("\n", " ").replace("\r", "")
            line = f".{host_short}:{port} {svc} {banner_preview}"
            d.text((1, y), line[:22], font=font, fill="#CCCCCC")

        total = len(res)
        if total > ROWS_VISIBLE - 1:
            bar_h = max(4, int((ROWS_VISIBLE - 1) / total * 88))
            bar_y = 28 + int(sc / total * 88) if total > 0 else 28
            d.rectangle((126, bar_y, 127, bar_y + bar_h), fill="#444")

    _draw_footer(d, f"Found:{len(res)} K3:Exit")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_host_picker():
    """Render the single-host selection view."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "PICK HOST")

    with lock:
        hosts = list(known_hosts)
        hs = host_scroll

    d.text((2, 15), f"{len(hosts)} hosts found", font=font, fill="#888")

    if not hosts:
        d.text((10, 50), "No hosts known", font=font, fill="#666")
        d.text((10, 62), "Press OK to scan all", font=font, fill="#666")
    else:
        visible = hosts[hs:hs + ROWS_VISIBLE - 1]
        for i, host in enumerate(visible):
            y = 28 + i * ROW_H
            actual_idx = hs + i
            color = "#FFFF00" if actual_idx == hs else "#CCCCCC"
            marker = ">" if actual_idx == hs else " "
            d.text((1, y), f"{marker}{host}", font=font, fill=color)

    _draw_footer(d, "OK:Scan LEFT:Back")
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
    global scroll_pos, host_scroll, host_pick_mode, stop_flag

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 20), "SERVICE BANNERS", font=font, fill="#00CCFF")
    d.text((4, 40), "Port scan & banner", font=font, fill="#888")
    d.text((4, 52), "grab on common ports", font=font, fill="#888")
    d.text((4, 72), "OK    Scan all hosts", font=font, fill="#666")
    d.text((4, 84), "KEY1  Pick one host", font=font, fill="#666")
    d.text((4, 96), "KEY2  Export JSON", font=font, fill="#666")
    d.text((4, 108), "KEY3  Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.3)

    # Pre-discover hosts
    _refresh_hosts()

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                with lock:
                    stop_flag = True
                if results:
                    export_loot()
                break

            if host_pick_mode:
                if btn == "LEFT" or btn == "KEY1":
                    host_pick_mode = False
                    time.sleep(0.2)
                elif btn == "UP":
                    host_scroll = max(0, host_scroll - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        max_hs = max(0, len(known_hosts) - 1)
                    host_scroll = min(max_hs, host_scroll + 1)
                    time.sleep(0.15)
                elif btn == "OK":
                    with lock:
                        if host_scroll < len(known_hosts):
                            target = known_hosts[host_scroll]
                        else:
                            target = None
                    if target:
                        host_pick_mode = False
                        start_scan_single(target)
                    time.sleep(0.3)
                draw_host_picker()

            else:
                if btn == "OK":
                    start_scan_all()
                    time.sleep(0.3)
                elif btn == "KEY1":
                    _refresh_hosts()
                    host_pick_mode = True
                    host_scroll = 0
                    time.sleep(0.2)
                elif btn == "KEY2":
                    if results:
                        path = export_loot()
                        _show_message("Exported!", path[-20:])
                    time.sleep(0.3)
                elif btn == "UP":
                    scroll_pos = max(0, scroll_pos - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        max_sc = max(0, len(results) - ROWS_VISIBLE + 1)
                    scroll_pos = min(max_sc, scroll_pos + 1)
                    time.sleep(0.15)
                draw_results_view()

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
