#!/usr/bin/env python3
"""
RaspyJack Payload -- TLS Certificate Scanner
==============================================
Author: 7h30th3r0n3

Scans discovered hosts on HTTPS-related ports (443, 8443, 993, 995, 465,
636) and extracts certificate details: CN, SAN entries, issuer, validity
dates, key size, and self-signed status.  Highlights internal hostnames
leaked in SAN fields.

Controls:
  OK        -- Start scan (all discovered hosts)
  UP / DOWN -- Scroll results
  RIGHT     -- Drill down into selected cert
  LEFT      -- Back to list
  KEY1      -- Scan single host
  KEY2      -- Export JSON to loot
  KEY3      -- Exit

Loot: /root/Raspyjack/loot/Certs/<timestamp>.json
"""

import os
import sys
import json
import time
import ssl
import socket
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
LOOT_DIR = "/root/Raspyjack/loot/Certs"
NMAP_LOOT = "/root/Raspyjack/loot/Nmap"
os.makedirs(LOOT_DIR, exist_ok=True)

TLS_PORTS = [443, 8443, 993, 995, 465, 636]
ROWS_VISIBLE = 7
ROW_H = 12
INTERNAL_PATTERNS = re.compile(
    r"(\.local$|\.internal$|\.lan$|\.corp$|\.home$|^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\.)"
)
IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# ---------------------------------------------------------------------------
# Shared state (immutable swap pattern with lock)
# ---------------------------------------------------------------------------
lock = threading.Lock()
busy = False
status_msg = "Idle"
scroll_pos = 0
detail_idx = -1
stop_flag = False
results = []
known_hosts = []
host_scroll = 0
host_pick_mode = False


# ---------------------------------------------------------------------------
# Host discovery
# ---------------------------------------------------------------------------

def _discover_hosts():
    """Gather hosts from ARP table and Nmap loot."""
    hosts = set()
    try:
        out = subprocess.run(
            ["arp", "-an"], capture_output=True, text=True, timeout=5,
        )
        for line in out.stdout.splitlines():
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
            if m:
                ip = m.group(1)
                if not ip.endswith(".255") and not ip.endswith(".0"):
                    hosts.add(ip)
    except Exception:
        pass
    if os.path.isdir(NMAP_LOOT):
        for fname in os.listdir(NMAP_LOOT):
            fpath = os.path.join(NMAP_LOOT, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                with open(fpath, "r", errors="ignore") as f:
                    for m in IP_RE.finditer(f.read()):
                        ip = m.group(1)
                        first = int(ip.split(".")[0])
                        if first not in (0, 127) and not ip.endswith(".255"):
                            hosts.add(ip)
            except Exception:
                pass
    return sorted(hosts)


def _refresh_hosts():
    global known_hosts
    found = _discover_hosts()
    with lock:
        known_hosts = found
    return found


# ---------------------------------------------------------------------------
# Certificate extraction
# ---------------------------------------------------------------------------

def _fetch_cert(host, port, timeout=5):
    """Connect via TLS and return parsed certificate info dict or None."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                pem_info = tls.getpeercert()
                cipher = tls.cipher()
    except Exception:
        return None

    if pem_info is None and der is None:
        return None

    cn = ""
    issuer_cn = ""
    san_entries = []
    not_before = ""
    not_after = ""
    self_signed = False

    if pem_info:
        for rdn in pem_info.get("subject", ()):
            for attr, val in rdn:
                if attr == "commonName":
                    cn = val
        for rdn in pem_info.get("issuer", ()):
            for attr, val in rdn:
                if attr == "commonName":
                    issuer_cn = val
        san_entries = [v for _, v in pem_info.get("subjectAltName", ())]
        not_before = pem_info.get("notBefore", "")
        not_after = pem_info.get("notAfter", "")

    if cn and issuer_cn and cn == issuer_cn:
        self_signed = True

    internal_leaks = [s for s in san_entries if INTERNAL_PATTERNS.search(s)]

    key_bits = 0
    if cipher and len(cipher) >= 3:
        key_bits = cipher[2] if isinstance(cipher[2], int) else 0

    return {
        "host": host,
        "port": port,
        "cn": cn,
        "issuer": issuer_cn,
        "san": san_entries,
        "internal_leaks": internal_leaks,
        "not_before": not_before,
        "not_after": not_after,
        "self_signed": self_signed,
        "key_bits": key_bits,
        "cipher": cipher[0] if cipher else "",
    }


def _scan_host(host):
    """Scan all TLS ports on a host."""
    global status_msg
    host_results = []
    for port in TLS_PORTS:
        with lock:
            if stop_flag:
                return host_results
            status_msg = f"TLS {host}:{port}"
        info = _fetch_cert(host, port, timeout=4)
        if info is not None:
            host_results.append(info)
            with lock:
                results.append(info)
    return host_results


def _do_scan_all():
    global busy, status_msg, results, stop_flag
    with lock:
        busy = True
        stop_flag = False
        status_msg = "Discovering hosts..."
        results = []

    hosts = _refresh_hosts()
    if not hosts:
        with lock:
            status_msg = "No hosts found"
            busy = False
        return

    for i, host in enumerate(hosts):
        with lock:
            if stop_flag:
                break
            status_msg = f"Host {i + 1}/{len(hosts)}: {host}"
        _scan_host(host)

    with lock:
        status_msg = f"Done: {len(results)} certs"
        busy = False


def _do_scan_single(host):
    global busy, status_msg, stop_flag
    with lock:
        busy = True
        stop_flag = False
        status_msg = f"Scanning {host}..."
    _scan_host(host)
    with lock:
        status_msg = f"Done: {len(results)} certs"
        busy = False


def start_scan_all():
    with lock:
        if busy:
            return
    threading.Thread(target=_do_scan_all, daemon=True).start()


def start_scan_single(host):
    with lock:
        if busy:
            return
    threading.Thread(target=_do_scan_single, args=(host,), daemon=True).start()


# ---------------------------------------------------------------------------
# Loot export
# ---------------------------------------------------------------------------

def export_loot():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    with lock:
        data = {"timestamp": ts, "total": len(results), "certs": list(results)}
    path = os.path.join(LOOT_DIR, f"certs_{ts}.json")
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


def draw_list_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "TLS CERTS")

    with lock:
        res = list(results)
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
            short_host = entry["host"].split(".")[-1]
            cn_short = entry["cn"][:8] if entry["cn"] else "?"
            ss = "SS" if entry["self_signed"] else ""
            leak = "!" if entry["internal_leaks"] else ""
            line = f".{short_host}:{entry['port']} {cn_short} {ss}{leak}"
            color = "#FF4444" if entry["self_signed"] else "#CCCCCC"
            if entry["internal_leaks"]:
                color = "#FFAA00"
            d.text((1, y), line[:22], font=font, fill=color)

    _draw_footer(d, f"Certs:{len(res)} RIGHT:detail")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_detail_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "CERT DETAIL")

    with lock:
        res = list(results)
        idx = detail_idx

    if idx < 0 or idx >= len(res):
        d.text((10, 50), "No cert selected", font=font, fill="#666")
        LCD.LCD_ShowImage(img, 0, 0)
        return

    cert = res[idx]
    lines = [
        f"Host: {cert['host']}:{cert['port']}",
        f"CN: {cert['cn'][:18]}",
        f"Issuer: {cert['issuer'][:16]}",
        f"Valid: {cert['not_before'][:11]}",
        f"Expiry: {cert['not_after'][:11]}",
        f"Key: {cert['key_bits']}b  {cert['cipher'][:8]}",
        f"SelfSign: {'YES' if cert['self_signed'] else 'No'}",
        f"SANs: {len(cert['san'])}",
    ]
    if cert["internal_leaks"]:
        lines.append(f"LEAK: {cert['internal_leaks'][0][:16]}")

    for i, line in enumerate(lines[:8]):
        y = 16 + i * 12
        color = "#FF4444" if "LEAK" in line or "YES" in line else "#CCCCCC"
        d.text((2, y), line[:22], font=font, fill=color)

    _draw_footer(d, "LEFT:back UP/DN:nav")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_host_picker():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "PICK HOST")

    with lock:
        hosts = list(known_hosts)
        hs = host_scroll

    d.text((2, 15), f"{len(hosts)} hosts", font=font, fill="#888")
    if not hosts:
        d.text((10, 50), "No hosts found", font=font, fill="#666")
    else:
        visible = hosts[hs:hs + ROWS_VISIBLE - 1]
        for i, host in enumerate(visible):
            y = 28 + i * ROW_H
            marker = ">" if i == 0 else " "
            color = "#FFFF00" if i == 0 else "#CCCCCC"
            d.text((1, y), f"{marker}{host}", font=font, fill=color)

    _draw_footer(d, "OK:Scan LEFT:Back")
    LCD.LCD_ShowImage(img, 0, 0)


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
    global scroll_pos, detail_idx, host_scroll, host_pick_mode, stop_flag

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 20), "TLS CERT SCANNER", font=font, fill="#00CCFF")
    d.text((4, 40), "Scan HTTPS/TLS ports", font=font, fill="#888")
    d.text((4, 60), "OK=Scan  K1=Single", font=font, fill="#666")
    d.text((4, 72), "K2=Export K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.3)

    _refresh_hosts()
    in_detail = False

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
                        mx = max(0, len(known_hosts) - 1)
                    host_scroll = min(mx, host_scroll + 1)
                    time.sleep(0.15)
                elif btn == "OK":
                    with lock:
                        target = known_hosts[host_scroll] if host_scroll < len(known_hosts) else None
                    if target:
                        host_pick_mode = False
                        start_scan_single(target)
                    time.sleep(0.3)
                draw_host_picker()

            elif in_detail:
                if btn == "LEFT":
                    in_detail = False
                    time.sleep(0.2)
                elif btn == "UP":
                    detail_idx = max(0, detail_idx - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        mx = max(0, len(results) - 1)
                    detail_idx = min(mx, detail_idx + 1)
                    time.sleep(0.15)
                draw_detail_view()

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
                elif btn == "RIGHT":
                    with lock:
                        if results:
                            detail_idx = scroll_pos
                            in_detail = True
                    time.sleep(0.2)
                elif btn == "UP":
                    scroll_pos = max(0, scroll_pos - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        mx = max(0, len(results) - ROWS_VISIBLE + 1)
                    scroll_pos = min(mx, scroll_pos + 1)
                    time.sleep(0.15)
                draw_list_view()

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
