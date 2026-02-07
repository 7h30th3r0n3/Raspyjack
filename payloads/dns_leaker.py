#!/usr/bin/env python3
"""
===============================================================================
 RaspyJack Payload — DNS / NBNS Network Leaker
===============================================================================

PURPOSE
-------
Passive monitoring of DNS (UDP/53) and NBNS (UDP/137) traffic to quickly gain
situational awareness of the local network.

This payload is intended to identify:
- active client machines and their source IPs
- internal domains and infrastructure services
- Active Directory and legacy Windows name resolution

-------------------------------------------------------------------------------
FEATURES
-------------------------------------------------------------------------------
- Fully passive sniffing (no injection, no MITM required)
- Live dashboard on RaspyJack 1.44" LCD
- Scrollable TOP queries list (UP / DOWN)
- Persistent logging (one line per request)
- Clean exit and safe return to RaspyJack UI

-------------------------------------------------------------------------------
USAGE (BUTTON MAPPING)
-------------------------------------------------------------------------------
UP     → scroll UP in TOP list
DOWN   → scroll DOWN in TOP list
KEY3   → exit payload

-------------------------------------------------------------------------------
LCD DISPLAY
-------------------------------------------------------------------------------
DNS   : total DNS queries observed
NBNS  : total NetBIOS name queries observed
INT   : unique internal / infrastructure names detected
LAST  : last observed query
TOP   : most frequent queries (scrollable)

INT is incremented when a name matches one of the following:
- internal suffix (.local, .lan, .corp, .internal)
- service record (name starting with "_", e.g. _ldap._tcp)
- NetBIOS hostname (NBNS)

-------------------------------------------------------------------------------
LOGGING
-------------------------------------------------------------------------------
All requests are logged to:
    /root/Raspyjack/loot/MITM/Log-DNS.txt

Format (one line per request):
    [YYYY-MM-DD HH:MM:SS] DNS  SRC=<ip> DST=<ip> QNAME=<name> QTYPE=<type> FLAGS=<flags>
    [YYYY-MM-DD HH:MM:SS] NBNS SRC=<ip> DST=<ip> NAME=<name> FLAGS=internal,netbios

-------------------------------------------------------------------------------
REQUIREMENTS
-------------------------------------------------------------------------------
- Root privileges
- scapy installed
- RaspyJack-compatible Waveshare 1.44" LCD HAT
- Correct network interface selected (eth0 / wlan0 / br0)

-------------------------------------------------------------------------------
OPERATIONAL NOTES
-------------------------------------------------------------------------------
- Designed for authorized audits, labs, and Red Team operations only
- More effective when MITM is activated
===============================================================================
"""


import os, sys, time, signal, threading, datetime
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# Optional WebUI virtual input bridge
try:
    import rj_input  # type: ignore
except Exception:
    rj_input = None

from scapy.all import sniff, DNS, DNSQR, IP
from scapy.layers.netbios import NBNSQueryRequest

# ==================================================
# GPIO MAP — Waveshare 1.44" LCD HAT (BCM)
# ==================================================
PIN_UP   = 6
PIN_DOWN = 19
PIN_KEY3 = 16   # EXIT

GPIO.setmode(GPIO.BCM)
for pin in (PIN_UP, PIN_DOWN, PIN_KEY3):
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

PINS = {
    "UP": PIN_UP,
    "DOWN": PIN_DOWN,
    "KEY3": PIN_KEY3,
}

# ==================================================
# LCD INIT
# ==================================================
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)

WIDTH, HEIGHT = 128, 128
font = ImageFont.load_default()

# ==================================================
# LOG FILE
# ==================================================
LOG_DIR = "/root/Raspyjack/loot/MITM"
LOG_FILE = os.path.join(LOG_DIR, "Log-DNS.txt")
os.makedirs(LOG_DIR, exist_ok=True)

def log_line(line: str):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass  # furtif

# ==================================================
# STATE
# ==================================================
running = True

queries = {}
last_query = ""

dns_count = 0
nbns_count = 0
internal_count = 0

internal_suffixes = (".local", ".lan", ".corp", ".internal")
top_index = 0

# >>> ADJUST IF NEEDED <<<
SNIFF_IFACE = "eth0"

# ==================================================
# CLEAN EXIT
# ==================================================
def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ==================================================
# INPUT (physical + WebUI virtual)
# ==================================================
def _get_virtual_button():
    if rj_input is None:
        return None
    name = rj_input.get_virtual_button()
    mapping = {
        "KEY_UP_PIN": "UP",
        "KEY_DOWN_PIN": "DOWN",
        "KEY3_PIN": "KEY3",
        "KEY_PRESS_PIN": "KEY3",
    }
    return mapping.get(name)

def get_button():
    v = _get_virtual_button()
    if v:
        return v
    for name, pin in PINS.items():
        if GPIO.input(pin) == 0:
            return name
    return None

def wait_release(button):
    if button in PINS:
        while GPIO.input(PINS[button]) == 0:
            time.sleep(0.03)

# ==================================================
# HELPERS
# ==================================================
def normalize(name: str) -> str:
    return name.strip().lower()

def dns_qtype_name(qtype: int) -> str:
    return {
        1: "A",
        28: "AAAA",
        33: "SRV",
        12: "PTR",
        15: "MX",
        16: "TXT"
    }.get(qtype, str(qtype))

# ==================================================
# PACKET HANDLER
# ==================================================
def handle_packet(pkt):
    global last_query
    global dns_count, nbns_count, internal_count

    if not pkt.haslayer(IP):
        return

    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    # ---- DNS
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.dport == 53:
        q = pkt[DNSQR]
        qname = normalize(q.qname.decode(errors="ignore").rstrip("."))
        qtype = dns_qtype_name(q.qtype)

        flags = []
        if qname.endswith(internal_suffixes) or qname.startswith("_"):
            flags.append("internal")
        if qname.startswith("_"):
            flags.append("service")

        last_query = qname
        dns_count += 1

        log_line(
            f"[{ts}] DNS SRC={src_ip} DST={dst_ip} "
            f"QNAME={qname} QTYPE={qtype} FLAGS={','.join(flags) or 'external'}"
        )

        if qname not in queries:
            queries[qname] = 0
            if "internal" in flags:
                internal_count += 1

        queries[qname] += 1

    # ---- NBNS
    elif pkt.haslayer(NBNSQueryRequest):
        name = normalize(
            pkt[NBNSQueryRequest].QUESTION_NAME.decode(errors="ignore")
        )

        last_query = name
        nbns_count += 1
        internal_count += 1 if name not in queries else 0

        log_line(
            f"[{ts}] NBNS SRC={src_ip} DST={dst_ip} "
            f"NAME={name} FLAGS=internal,netbios"
        )

        queries[name] = queries.get(name, 0) + 1

# ==================================================
# SNIFFER THREAD
# ==================================================
def sniff_thread():
    sniff(
        iface=SNIFF_IFACE,
        filter="udp and (port 53 or port 137)",
        prn=handle_packet,
        store=0,
        promisc=True,
        stop_filter=lambda _: not running
    )

threading.Thread(target=sniff_thread, daemon=True).start()

# ==================================================
# UI LOOP
# ==================================================
while running:
    btn = get_button()
    if btn == "KEY3":
        break

    sorted_top = sorted(queries.items(), key=lambda x: x[1], reverse=True)

    if btn == "UP" and top_index > 0:
        top_index -= 1
        wait_release("UP")

    if btn == "DOWN" and top_index < max(0, len(sorted_top) - 2):
        top_index += 1
        wait_release("DOWN")

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)

    d.text((6, 4), "DNS LEAKER", font=font, fill="#00FF88")
    d.ellipse((108, 6, 116, 14), fill="#00FF88")

    d.line((4, 18, 124, 18), fill="#222")
    d.line((4, 46, 124, 46), fill="#222")
    d.line((4, 76, 124, 76), fill="#222")

    d.text((8, 22), f"DNS {dns_count}", font=font, fill="#FFF")
    d.text((64, 22), f"NBNS {nbns_count}", font=font, fill="#FF5555")
    d.text((8, 34), f"INT {internal_count}", font=font, fill="#00BFFF")

    d.text((8, 50), "LAST", font=font, fill="#888")
    d.text((8, 62), last_query[:26], font=font, fill="#00BFFF")

    d.text((8, 80), "TOP", font=font, fill="#888")
    y = 92
    for i in range(2):
        idx = top_index + i
        if idx < len(sorted_top):
            name, cnt = sorted_top[idx]
            d.text((8, y), name[:18], font=font, fill="#FFF")
            d.text((104, y), str(cnt), font=font, fill="#AAA")
            y += 14

    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.1)

cleanup()