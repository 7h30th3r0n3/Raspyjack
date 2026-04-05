#!/usr/bin/env python3
"""
RaspyJack Payload -- Traffic Analyzer
=======================================
Author: 7h30th3r0n3

Real-time network traffic analyzer dashboard.
Sniffs on the active interface, tracks bandwidth, protocol breakdown,
top connections, and DNS query log.

Flow:
  1) Sniff packets on active interface
  2) Track bytes/sec, packets/sec per protocol
  3) Log DNS queries and top connections by bandwidth
  4) Display on multi-view LCD dashboard

Controls:
  OK          -- Start / stop capture
  UP / DOWN   -- Scroll within current view
  LEFT / RIGHT -- Switch view (Dashboard / Connections / DNS)
  KEY1        -- Reset counters
  KEY2        -- Export snapshot
  KEY3        -- Exit

Loot: /root/Raspyjack/loot/TrafficAnalyzer/

Setup: No special requirements.
"""

import os
import sys
import time
import json
import threading
import subprocess
from datetime import datetime
from collections import defaultdict

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Ether, conf
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
LOOT_DIR = "/root/Raspyjack/loot/TrafficAnalyzer"
os.makedirs(LOOT_DIR, exist_ok=True)
ROWS_VISIBLE = 6
VIEWS = ["dashboard", "connections", "dns"]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
status_msg = "Ready"
view_idx = 0
scroll_pos = 0
capture_running = False
app_running = True

total_packets = 0
total_bytes = 0
packets_per_sec = 0
bytes_per_sec = 0

proto_packets = defaultdict(int)
proto_bytes = defaultdict(int)

# connection: (src,sport,dst,dport) -> total_bytes
conn_bytes = defaultdict(int)

# DNS query log (last 50)
dns_log = []

_prev_packets = 0
_prev_bytes = 0
_prev_time = 0


# ---------------------------------------------------------------------------
# Helpers
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


def _classify_proto(pkt):
    """Return protocol name for a packet."""
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        if tcp.dport == 80 or tcp.sport == 80:
            return "HTTP"
        if tcp.dport == 443 or tcp.sport == 443:
            return "HTTPS"
        if tcp.dport == 22 or tcp.sport == 22:
            return "SSH"
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(IP):
        ip = pkt[IP]
        if ip.proto == 1:
            return "ICMP"
    return "OTHER"


# ---------------------------------------------------------------------------
# Packet processing
# ---------------------------------------------------------------------------

def _packet_handler(pkt):
    """Process sniffed packet."""
    global total_packets, total_bytes

    pkt_len = len(pkt)
    proto = _classify_proto(pkt)

    with lock:
        total_packets += 1
        total_bytes += pkt_len
        proto_packets[proto] += 1
        proto_bytes[proto] += pkt_len

    # Track connections
    if pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
        ip = pkt[IP]
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        else:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        key = (ip.src, sport, ip.dst, dport)
        with lock:
            conn_bytes[key] += pkt_len

    # DNS logging
    if pkt.haslayer(DNSQR) and pkt.haslayer(DNS):
        dns = pkt[DNS]
        if dns.qr == 0:  # query
            qname = pkt[DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="ignore").rstrip(".")
            entry = {
                "ts": datetime.now().strftime("%H:%M:%S"),
                "src": pkt[IP].src if pkt.haslayer(IP) else "?",
                "query": qname,
            }
            with lock:
                new_log = list(dns_log) + [entry]
                if len(new_log) > 50:
                    new_log = new_log[-50:]
                dns_log.clear()
                dns_log.extend(new_log)


def _sniff_thread(iface):
    """Sniff on interface."""
    global capture_running, status_msg
    capture_running = True
    with lock:
        status_msg = f"Sniffing {iface}..."
    try:
        sniff(
            iface=iface,
            prn=_packet_handler,
            store=False,
            stop_filter=lambda _: not app_running or not capture_running,
        )
    except Exception as exc:
        with lock:
            status_msg = f"Err: {exc}"
    finally:
        capture_running = False


def _rate_thread():
    """Calculate rates every second."""
    global packets_per_sec, bytes_per_sec, _prev_packets, _prev_bytes, _prev_time
    _prev_time = time.time()
    while app_running:
        time.sleep(1)
        now = time.time()
        with lock:
            tp = total_packets
            tb = total_bytes
        elapsed = now - _prev_time
        if elapsed > 0:
            with lock:
                packets_per_sec = int((tp - _prev_packets) / elapsed)
                bytes_per_sec = int((tb - _prev_bytes) / elapsed)
        _prev_packets = tp
        _prev_bytes = tb
        _prev_time = now


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_snapshot():
    global status_msg
    with lock:
        top_conns = sorted(conn_bytes.items(), key=lambda x: x[1], reverse=True)[:20]
        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "pps": packets_per_sec,
            "bps": bytes_per_sec,
            "protocols": {
                k: {"packets": proto_packets[k], "bytes": proto_bytes[k]}
                for k in proto_packets
            },
            "top_connections": [
                {"src": k[0], "sport": k[1], "dst": k[2], "dport": k[3], "bytes": v}
                for k, v in top_conns
            ],
            "dns_queries": list(dns_log),
        }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"traffic_{ts}.json")
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

def _fmt_bytes(b):
    if b >= 1_000_000:
        return f"{b / 1_000_000:.1f}M"
    if b >= 1_000:
        return f"{b / 1_000:.1f}K"
    return f"{b}B"


def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    draw = ScaledDraw(img)

    view = VIEWS[view_idx]
    draw.text((2, 2), "TRAFFIC", fill="CYAN", font=font)

    with lock:
        st = status_msg
        pps = packets_per_sec
        bps = bytes_per_sec
        tp = total_packets
        tb = total_bytes
        pp = dict(proto_packets)
        sp = scroll_pos
        cap = capture_running
        top_c = sorted(conn_bytes.items(), key=lambda x: x[1], reverse=True)[:20]
        d_log = list(dns_log)

    draw.text((60, 2), f"[{view[:4]}]", fill="YELLOW", font=font)
    indicator = "REC" if cap else "---"
    draw.text((100, 2), indicator, fill="RED" if cap else "GRAY", font=font)

    if view == "dashboard":
        draw.text((2, 16), f"PPS: {pps:<6} BPS: {_fmt_bytes(bps)}", fill="GREEN", font=font)
        draw.text((2, 28), f"Pkts: {tp}  Bytes: {_fmt_bytes(tb)}", fill="WHITE", font=font)

        # Protocol bars
        y = 42
        sorted_p = sorted(pp.items(), key=lambda x: x[1], reverse=True)[:5]
        colors = {"TCP": "BLUE", "UDP": "GREEN", "HTTP": "YELLOW",
                  "HTTPS": "ORANGE", "DNS": "CYAN", "ICMP": "RED",
                  "SSH": "MAGENTA"}
        for name, cnt in sorted_p:
            c = colors.get(name, "WHITE")
            pct = int(cnt * 60 / max(tp, 1))
            draw.text((2, y), f"{name:<5}", fill=c, font=font)
            draw.rectangle((42, y + 2, 42 + min(pct, 80), y + 10), fill=c)
            draw.text((105, y), str(cnt)[:5], fill="GRAY", font=font)
            y += 14

    elif view == "connections":
        draw.text((2, 16), st[:22], fill="WHITE", font=font)
        y = 28
        for key, bcount in top_c[sp:sp + ROWS_VISIBLE]:
            src_short = key[0].split(".")[-1]
            dst_short = key[2].split(".")[-1]
            line = f"{src_short}:{key[1]}->{dst_short}:{key[3]} {_fmt_bytes(bcount)}"
            draw.text((2, y), line[:22], fill="WHITE", font=font)
            y += 14
        if not top_c:
            draw.text((2, 56), "No connections", fill="GRAY", font=font)

    elif view == "dns":
        draw.text((2, 16), f"DNS queries: {len(d_log)}", fill="WHITE", font=font)
        y = 28
        visible = d_log[-(sp + ROWS_VISIBLE):][-ROWS_VISIBLE:]
        for entry in visible:
            q = entry["query"]
            # Shorten domain
            parts = q.split(".")
            short = ".".join(parts[-2:]) if len(parts) > 2 else q
            draw.text((2, y), f"{entry['ts'][3:]} {short}"[:22], fill="CYAN", font=font)
            y += 14
        if not d_log:
            draw.text((2, 56), "No DNS queries", fill="GRAY", font=font)

    draw.text((2, 116), "L/R=view K2=exp K3=ex", fill="GRAY", font=font)
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global app_running, capture_running, view_idx, scroll_pos, status_msg
    global total_packets, total_bytes

    if not SCAPY_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
        d = ScaledDraw(img)
        d.text((4, 50), "scapy not found!", font=font, fill="RED")
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return

    iface = _get_default_iface()
    threading.Thread(target=_rate_thread, daemon=True).start()

    try:
        _draw_screen()

        while app_running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                app_running = False
                break

            elif btn == "OK":
                if not capture_running:
                    threading.Thread(
                        target=_sniff_thread, args=(iface,), daemon=True,
                    ).start()
                else:
                    capture_running = False
                    with lock:
                        status_msg = "Stopped"

            elif btn == "LEFT":
                view_idx = (view_idx - 1) % len(VIEWS)
                with lock:
                    scroll_pos = 0

            elif btn == "RIGHT":
                view_idx = (view_idx + 1) % len(VIEWS)
                with lock:
                    scroll_pos = 0

            elif btn == "UP":
                with lock:
                    if scroll_pos > 0:
                        scroll_pos -= 1

            elif btn == "DOWN":
                with lock:
                    scroll_pos += 1

            elif btn == "KEY1":
                with lock:
                    total_packets = 0
                    total_bytes = 0
                    proto_packets.clear()
                    proto_bytes.clear()
                    conn_bytes.clear()
                    dns_log.clear()
                    scroll_pos = 0
                    status_msg = "Counters reset"

            elif btn == "KEY2":
                threading.Thread(target=_export_snapshot, daemon=True).start()

            _draw_screen()
            time.sleep(0.15)

    finally:
        app_running = False
        capture_running = False
        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            d = ScaledDraw(img)
            d.text((10, 50), "Analyzer stopped", fill="YELLOW", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass
        GPIO.cleanup()


if __name__ == "__main__":
    main()
