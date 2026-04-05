#!/usr/bin/env python3
"""
RaspyJack Payload -- Port Scanner
===================================
Author: 7h30th3r0n3

Fast SYN port scanner using scapy (lighter than nmap).
ARP-discovers hosts, then SYN-scans the selected target.

Flow:
  1) ARP scan to discover live hosts
  2) User selects a host
  3) Choose scan mode: top 20, top 100, or custom range
  4) SYN scan — SYN-ACK = open, RST = closed
  5) Display open ports with service names

Controls:
  OK        -- Select host / start scan
  UP / DOWN -- Scroll hosts or results
  KEY1      -- Change scan mode
  KEY2      -- Export results
  KEY3      -- Exit

Loot: /root/Raspyjack/loot/PortScan/
"""

import os
import sys
import time
import json
import threading
import subprocess
import re
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
        ARP, Ether, srp, sr1, IP, TCP, conf,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

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
LOOT_DIR = "/root/Raspyjack/loot/PortScan"
os.makedirs(LOOT_DIR, exist_ok=True)
ROWS_VISIBLE = 6

TOP_20 = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
           143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
TOP_100 = sorted(set(TOP_20 + [
    7, 9, 13, 17, 19, 20, 37, 42, 49, 50, 65, 67, 68, 69, 70, 79, 81, 88,
    100, 106, 113, 119, 123, 137, 138, 144, 161, 162, 179, 199, 389, 427,
    444, 465, 500, 513, 514, 515, 520, 548, 554, 587, 631, 636, 646, 873,
    990, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1521, 1720, 2000, 2001,
    2049, 2121, 2717, 3000, 3128, 3268, 4443, 5000, 5009, 5051, 5060, 5101,
    5190, 5357, 5432, 5631, 5666, 5800, 6000, 6001, 6646, 7070, 8000,
    8008, 8443, 8888, 9090, 9100, 9999, 10000, 32768, 49152, 49154,
]))

SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP-S", 68: "DHCP-C", 69: "TFTP", 80: "HTTP", 88: "Kerberos",
    110: "POP3", 111: "RPC", 119: "NNTP", 123: "NTP", 135: "MSRPC",
    137: "NetBIOS", 139: "SMB", 143: "IMAP", 161: "SNMP", 179: "BGP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    548: "AFP", 554: "RTSP", 587: "SMTP-S", 631: "IPP", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 2049: "NFS", 3000: "Dev", 3128: "Squid",
    3268: "LDAP-GC", 3306: "MySQL", 3389: "RDP", 5060: "SIP",
    5432: "Postgres", 5631: "VNC-PC", 5666: "NRPE", 5800: "VNC-HTTP",
    5900: "VNC", 6000: "X11", 8000: "HTTP-Alt", 8008: "HTTP-Alt",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9090: "WebConsole", 9100: "Print", 10000: "Webmin",
}

SCAN_MODES = ["Top 20", "Top 100", "1-1024"]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
hosts = []               # [{"ip": ..., "mac": ...}]
open_ports = []          # [(port, service_name)]
scroll_pos = 0
selected_idx = 0
scan_mode_idx = 0
view_mode = "hosts"      # hosts | scanning | results
status_msg = "Scanning network..."
scan_progress = 0
scan_total = 0
app_running = True


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _get_default_iface():
    try:
        r = subprocess.run(["ip", "route", "show", "default"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eth0"


def _get_subnet(iface):
    try:
        r = subprocess.run(["ip", "-4", "addr", "show", "dev", iface],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1]
    except Exception:
        pass
    return ""


def _arp_discover(iface, subnet):
    """ARP scan to find live hosts."""
    found = []
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            iface=iface, timeout=3, verbose=False,
        )
        for _, recv in ans:
            found.append({"ip": recv.psrc, "mac": recv.hwsrc})
    except Exception:
        pass
    return found


def _syn_scan(target_ip, ports):
    """SYN scan a list of ports, return list of open ports."""
    global scan_progress
    result = []
    conf.verb = 0
    for port in ports:
        if not app_running:
            break
        with lock:
            scan_progress += 1
        try:
            pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=1, verbose=False)
            if resp and resp.haslayer(TCP):
                if resp[TCP].flags & 0x12:  # SYN-ACK
                    result.append(port)
                    # Send RST to close half-open
                    rst = IP(dst=target_ip) / TCP(
                        dport=port, sport=resp[TCP].dport,
                        flags="R", seq=resp[TCP].ack,
                    )
                    sr1(rst, timeout=0.5, verbose=False)
        except Exception:
            pass
    return result


# ---------------------------------------------------------------------------
# Background threads
# ---------------------------------------------------------------------------

def _discovery_thread():
    """Discover hosts in background."""
    global hosts, status_msg, scroll_pos, selected_idx
    iface = _get_default_iface()
    subnet = _get_subnet(iface)
    if not subnet:
        with lock:
            status_msg = "No subnet found"
        return
    with lock:
        status_msg = f"ARP scan {subnet}..."
    found = _arp_discover(iface, subnet)
    with lock:
        hosts = found
        scroll_pos = 0
        selected_idx = 0
        status_msg = f"Found {len(found)} hosts"


def _scan_thread(target_ip):
    """Run port scan in background."""
    global open_ports, view_mode, status_msg, scan_progress, scan_total

    mode = SCAN_MODES[scan_mode_idx]
    if mode == "Top 20":
        ports = list(TOP_20)
    elif mode == "Top 100":
        ports = list(TOP_100)
    else:
        ports = list(range(1, 1025))

    with lock:
        scan_progress = 0
        scan_total = len(ports)
        open_ports = []
        view_mode = "scanning"
        status_msg = f"Scanning {target_ip}..."

    result = _syn_scan(target_ip, ports)
    port_list = [(p, SERVICE_MAP.get(p, "unknown")) for p in sorted(result)]

    with lock:
        open_ports = port_list
        view_mode = "results"
        status_msg = f"{len(port_list)} open ports"


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_results(target_ip):
    global status_msg
    with lock:
        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": target_ip,
            "scan_mode": SCAN_MODES[scan_mode_idx],
            "open_ports": [{"port": p, "service": s} for p, s in open_ports],
        }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"scan_{target_ip}_{ts}.json")
    try:
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        with lock:
            status_msg = "Exported to loot"
    except Exception as exc:
        with lock:
            status_msg = f"Export err: {exc}"


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------

def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    draw = ScaledDraw(img)
    draw.text((2, 2), "PORT SCANNER", fill="CYAN", font=font)

    with lock:
        st = status_msg
        vm = view_mode
        sp = scroll_pos
        si = selected_idx
        h_list = list(hosts)
        op = list(open_ports)
        prog = scan_progress
        total = scan_total

    draw.text((2, 14), st[:22], fill="WHITE", font=font)
    mode_label = SCAN_MODES[scan_mode_idx]
    draw.text((80, 2), mode_label, fill="YELLOW", font=font)

    if vm == "hosts":
        y = 28
        for i, h in enumerate(h_list[sp:sp + ROWS_VISIBLE]):
            real_i = sp + i
            prefix = ">" if real_i == si else " "
            color = "YELLOW" if real_i == si else "WHITE"
            draw.text((2, y), f"{prefix}{h['ip']}"[:22], fill=color, font=font)
            y += 14
        draw.text((2, 116), "OK=scan K1=mode K3=exit", fill="GRAY", font=font)

    elif vm == "scanning":
        pct = int(prog * 100 / total) if total else 0
        draw.rectangle((10, 60, 118, 72), outline="WHITE")
        bar_w = int(106 * pct / 100)
        if bar_w > 0:
            draw.rectangle((11, 61, 11 + bar_w, 71), fill="GREEN")
        draw.text((40, 46), f"{pct}%", fill="WHITE", font=font)
        draw.text((2, 80), f"{prog}/{total} ports", fill="GRAY", font=font)

    elif vm == "results":
        y = 28
        for port, svc in op[sp:sp + ROWS_VISIBLE]:
            draw.text((2, y), f"{port:>5} {svc}"[:22], fill="GREEN", font=font)
            y += 14
        if not op:
            draw.text((2, 56), "No open ports", fill="GRAY", font=font)
        draw.text((2, 116), "K2=export K3=exit", fill="GRAY", font=font)

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global app_running, scroll_pos, selected_idx, scan_mode_idx
    global view_mode, status_msg

    if not SCAPY_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
        d = ScaledDraw(img)
        d.text((4, 50), "scapy not found!", font=font, fill="RED")
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return

    try:
        threading.Thread(target=_discovery_thread, daemon=True).start()
        _draw_screen()
        target_ip = ""

        while app_running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                app_running = False
                break

            elif btn == "OK":
                with lock:
                    vm = view_mode
                    h_list = list(hosts)
                    si = selected_idx
                if vm == "hosts" and 0 <= si < len(h_list):
                    target_ip = h_list[si]["ip"]
                    threading.Thread(
                        target=_scan_thread, args=(target_ip,), daemon=True,
                    ).start()
                elif vm == "results":
                    with lock:
                        view_mode = "hosts"
                        scroll_pos = 0

            elif btn == "UP":
                with lock:
                    if selected_idx > 0:
                        selected_idx -= 1
                    if selected_idx < scroll_pos:
                        scroll_pos = selected_idx

            elif btn == "DOWN":
                with lock:
                    vm = view_mode
                    if vm == "hosts":
                        if selected_idx < len(hosts) - 1:
                            selected_idx += 1
                        if selected_idx >= scroll_pos + ROWS_VISIBLE:
                            scroll_pos = selected_idx - ROWS_VISIBLE + 1
                    elif vm == "results":
                        max_s = max(0, len(open_ports) - ROWS_VISIBLE)
                        if scroll_pos < max_s:
                            scroll_pos += 1

            elif btn == "KEY1":
                scan_mode_idx = (scan_mode_idx + 1) % len(SCAN_MODES)

            elif btn == "KEY2":
                if view_mode == "results" and target_ip:
                    threading.Thread(
                        target=_export_results, args=(target_ip,), daemon=True,
                    ).start()

            _draw_screen()
            time.sleep(0.15)

    finally:
        app_running = False
        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            d = ScaledDraw(img)
            d.text((10, 56), "Scanner closed", fill="YELLOW", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass
        GPIO.cleanup()


if __name__ == "__main__":
    main()
