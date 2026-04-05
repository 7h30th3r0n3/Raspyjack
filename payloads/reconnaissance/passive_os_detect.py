#!/usr/bin/env python3
"""
RaspyJack Payload -- Passive OS Fingerprinting
================================================
Author: 7h30th3r0n3

p0f-style passive OS detection from network traffic.  Sniffs TCP SYN
packets with scapy and analyses: initial TTL, TCP window size, MSS,
TCP options order, and DF bit to infer the remote operating system.

Controls:
  OK        -- Start / stop sniffing
  UP / DOWN -- Scroll IP -> OS list
  KEY1      -- Clear table
  KEY2      -- Export results to loot
  KEY3      -- Exit

Loot: /root/Raspyjack/loot/OSDetect/<timestamp>.json
"""

import os
import sys
import json
import time
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
LOOT_DIR = "/root/Raspyjack/loot/OSDetect"
os.makedirs(LOOT_DIR, exist_ok=True)

ROWS_VISIBLE = 7
ROW_H = 12

# ---------------------------------------------------------------------------
# OS signature database (TTL, window-size ranges, DF-bit, typical MSS)
# ---------------------------------------------------------------------------
OS_SIGS = [
    {"os": "Linux",   "ttl_range": (32, 64),   "df": True,  "win_hint": (5000, 65535),  "mss_hint": (1360, 1460)},
    {"os": "Windows", "ttl_range": (65, 128),   "df": True,  "win_hint": (8000, 65535),  "mss_hint": (1360, 1460)},
    {"os": "macOS",   "ttl_range": (32, 64),    "df": True,  "win_hint": (65535, 65535), "mss_hint": (1360, 1460)},
    {"os": "iOS",     "ttl_range": (32, 64),    "df": True,  "win_hint": (65535, 65535), "mss_hint": (1360, 1460)},
    {"os": "FreeBSD", "ttl_range": (32, 64),    "df": True,  "win_hint": (65535, 65535), "mss_hint": (1360, 1460)},
    {"os": "Solaris", "ttl_range": (200, 255),  "df": False, "win_hint": (8000, 49640),  "mss_hint": (1360, 1460)},
    {"os": "Cisco",   "ttl_range": (200, 255),  "df": False, "win_hint": (4000, 16384),  "mss_hint": (500, 1460)},
]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
sniffing = False
stop_flag = False
status_msg = "Idle"
scroll_pos = 0
pkt_count = 0

# {ip: {"os": str, "confidence": int, "ttl": int, "win": int, "mss": int, "df": bool}}
os_table = {}


# ---------------------------------------------------------------------------
# Fingerprint logic
# ---------------------------------------------------------------------------

def _initial_ttl(observed_ttl):
    """Round up to the nearest common initial TTL value."""
    for base in [32, 64, 128, 255]:
        if observed_ttl <= base:
            return base
    return 255


def _score_signature(sig, ttl, win, mss, df_bit):
    """Score how well a packet matches a signature (0-100)."""
    score = 0
    init_ttl = _initial_ttl(ttl)

    if sig["ttl_range"][0] <= init_ttl <= sig["ttl_range"][1]:
        score += 40
    elif abs(init_ttl - sig["ttl_range"][1]) <= 10:
        score += 15

    if sig["win_hint"][0] <= win <= sig["win_hint"][1]:
        score += 25
    elif abs(win - sig["win_hint"][1]) < 5000:
        score += 10

    if df_bit == sig["df"]:
        score += 20

    if mss > 0 and sig["mss_hint"][0] <= mss <= sig["mss_hint"][1]:
        score += 15

    return score


def _classify(ttl, win, mss, df_bit):
    """Return (os_name, confidence) for the given TCP SYN parameters."""
    best_os = "Unknown"
    best_score = 0

    for sig in OS_SIGS:
        sc = _score_signature(sig, ttl, win, mss, df_bit)
        if sc > best_score:
            best_score = sc
            best_os = sig["os"]

    confidence = min(100, best_score)
    return best_os, confidence


def _extract_mss(tcp_options):
    """Extract MSS value from scapy TCP options list."""
    if not tcp_options:
        return 0
    for name, val in tcp_options:
        if name == "MSS":
            return val if isinstance(val, int) else 0
    return 0


# ---------------------------------------------------------------------------
# Sniffer thread
# ---------------------------------------------------------------------------

def _sniffer_thread():
    """Sniff TCP SYN packets and classify source OS."""
    global sniffing, status_msg, pkt_count, stop_flag

    try:
        from scapy.all import sniff as scapy_sniff, TCP, IP
    except ImportError:
        with lock:
            status_msg = "scapy not installed"
            sniffing = False
        return

    def _process_pkt(pkt):
        global pkt_count
        if stop_flag:
            return

        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return

        tcp = pkt[TCP]
        ip = pkt[IP]

        if not (tcp.flags & 0x02) or (tcp.flags & 0x10):
            return

        src_ip = ip.src
        ttl = ip.ttl
        win = tcp.window
        df_bit = bool(ip.flags.DF)
        mss = _extract_mss(tcp.options)

        detected_os, confidence = _classify(ttl, win, mss, df_bit)

        with lock:
            pkt_count += 1
            existing = os_table.get(src_ip)
            if existing is None or confidence > existing["confidence"]:
                os_table[src_ip] = {
                    "os": detected_os,
                    "confidence": confidence,
                    "ttl": ttl,
                    "win": win,
                    "mss": mss,
                    "df": df_bit,
                }

    with lock:
        status_msg = "Sniffing SYN packets..."

    try:
        scapy_sniff(
            filter="tcp[tcpflags] & tcp-syn != 0",
            prn=_process_pkt,
            store=False,
            stop_filter=lambda _: stop_flag,
            timeout=600,
        )
    except Exception as exc:
        with lock:
            status_msg = f"Err: {str(exc)[:16]}"

    with lock:
        sniffing = False
        if "Err" not in status_msg:
            status_msg = f"Stopped ({len(os_table)} hosts)"


def start_sniffing():
    global sniffing, stop_flag
    with lock:
        if sniffing:
            return
        sniffing = True
        stop_flag = False
    threading.Thread(target=_sniffer_thread, daemon=True).start()


def stop_sniffing():
    global stop_flag
    with lock:
        stop_flag = True


# ---------------------------------------------------------------------------
# Loot export
# ---------------------------------------------------------------------------

def export_loot():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    with lock:
        data = {
            "timestamp": ts,
            "total_hosts": len(os_table),
            "packets_seen": pkt_count,
            "hosts": {ip: dict(info) for ip, info in os_table.items()},
        }
    path = os.path.join(LOOT_DIR, f"osdetect_{ts}.json")
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
        active = sniffing
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if active else "#FF0000")


def _draw_footer(d, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font, fill="#AAA")


def draw_main_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "OS DETECT")

    with lock:
        status = status_msg
        table = sorted(os_table.items(), key=lambda kv: kv[1]["confidence"], reverse=True)
        sc = scroll_pos
        pkts = pkt_count

    d.text((2, 15), f"{status[:16]}  pkt:{pkts}", font=font, fill="#888")

    if not table:
        d.text((10, 45), "OK: Start sniffing", font=font, fill="#666")
        d.text((10, 57), "Passive TCP SYN", font=font, fill="#666")
        d.text((10, 69), "fingerprinting", font=font, fill="#666")
    else:
        visible = table[sc:sc + ROWS_VISIBLE - 1]
        for i, (ip, info) in enumerate(visible):
            y = 28 + i * ROW_H
            short_ip = ip.split(".")[-2] + "." + ip.split(".")[-1]
            conf = info["confidence"]
            os_name = info["os"][:7]
            color = "#00FF00" if conf >= 70 else "#FFAA00" if conf >= 40 else "#FF4444"
            line = f"{short_ip:>7} {os_name} {conf}%"
            d.text((1, y), line[:22], font=font, fill=color)

        total = len(table)
        if total > ROWS_VISIBLE - 1:
            bar_h = max(4, int((ROWS_VISIBLE - 1) / total * 88))
            bar_y = 28 + int(sc / total * 88) if total > 0 else 28
            d.rectangle((126, bar_y, 127, bar_y + bar_h), fill="#444")

    _draw_footer(d, f"Hosts:{len(table)} K3:Exit")
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
    global scroll_pos, stop_flag, os_table, pkt_count

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 20), "PASSIVE OS DETECT", font=font, fill="#00CCFF")
    d.text((4, 40), "p0f-style TCP SYN", font=font, fill="#888")
    d.text((4, 52), "fingerprinting", font=font, fill="#888")
    d.text((4, 72), "OK=Start/Stop", font=font, fill="#666")
    d.text((4, 84), "K1=Clear K2=Export", font=font, fill="#666")
    d.text((4, 96), "K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.3)

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                stop_sniffing()
                if os_table:
                    export_loot()
                break

            if btn == "OK":
                with lock:
                    currently_sniffing = sniffing
                if currently_sniffing:
                    stop_sniffing()
                else:
                    start_sniffing()
                time.sleep(0.3)

            elif btn == "KEY1":
                with lock:
                    os_table = {}
                    pkt_count = 0
                _show_message("Table cleared")
                time.sleep(0.2)

            elif btn == "KEY2":
                if os_table:
                    path = export_loot()
                    _show_message("Exported!", path[-20:])
                time.sleep(0.3)

            elif btn == "UP":
                scroll_pos = max(0, scroll_pos - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                with lock:
                    mx = max(0, len(os_table) - ROWS_VISIBLE + 1)
                scroll_pos = min(mx, scroll_pos + 1)
                time.sleep(0.15)

            draw_main_view()
            time.sleep(0.05)

    finally:
        stop_sniffing()
        time.sleep(0.3)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
