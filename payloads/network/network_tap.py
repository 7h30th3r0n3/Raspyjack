#!/usr/bin/env python3
"""
RaspyJack Payload -- Network Tap
==================================
Author: 7h30th3r0n3

Pure passive network tap on a transparent bridge interface.
Creates br0 between two Ethernet interfaces with no IP — captures
all traffic and displays real-time protocol statistics.

Flow:
  1) Create transparent bridge (br0) between eth0 + eth1
  2) Capture traffic with tcpdump, parse with tshark
  3) Display live stats: packets/sec, bytes/sec, protocol breakdown
  4) Track top 5 IP pairs by traffic volume

Controls:
  OK         -- Start / stop capture
  UP / DOWN  -- Scroll views
  KEY1       -- Cycle display mode (overview / protocols / top talkers)
  KEY2       -- Export stats snapshot
  KEY3       -- Exit + cleanup bridge

Loot: /root/Raspyjack/loot/NetworkTap/

Setup: Requires 2 Ethernet interfaces (eth0 + eth1), bridge-utils.
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
LOOT_DIR = "/root/Raspyjack/loot/NetworkTap"
os.makedirs(LOOT_DIR, exist_ok=True)
ROWS_VISIBLE = 6
IFACE_A = "eth0"
IFACE_B = "eth1"
BRIDGE = "br0"

DISPLAY_MODES = ["overview", "protocols", "top_talkers"]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
status_msg = "Bridge not started"
display_mode_idx = 0
scroll_pos = 0
capture_running = False
app_running = True
bridge_up = False

total_packets = 0
total_bytes = 0
packets_per_sec = 0
bytes_per_sec = 0

protocol_counts = defaultdict(int)    # proto_name -> packet count
protocol_bytes = defaultdict(int)     # proto_name -> byte count
ip_pair_bytes = defaultdict(int)      # (src_ip, dst_ip) -> total bytes

_capture_proc = None
_last_pps_time = 0
_last_pps_count = 0
_last_bps_count = 0


# ---------------------------------------------------------------------------
# Bridge management
# ---------------------------------------------------------------------------

def _run_cmd(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None


def _setup_bridge():
    """Create transparent bridge between two interfaces."""
    global bridge_up, status_msg
    with lock:
        status_msg = "Setting up bridge..."

    _run_cmd(["sudo", "ip", "link", "set", IFACE_A, "up"])
    _run_cmd(["sudo", "ip", "link", "set", IFACE_B, "up"])
    _run_cmd(["sudo", "ip", "link", "add", "name", BRIDGE, "type", "bridge"])
    _run_cmd(["sudo", "ip", "link", "set", IFACE_A, "master", BRIDGE])
    _run_cmd(["sudo", "ip", "link", "set", IFACE_B, "master", BRIDGE])
    _run_cmd(["sudo", "ip", "link", "set", BRIDGE, "up"])
    # No IP on bridge — pure tap
    _run_cmd(["sudo", "ip", "addr", "flush", "dev", BRIDGE])

    bridge_up = True
    with lock:
        status_msg = "Bridge up (no IP)"


def _teardown_bridge():
    """Remove bridge interface."""
    global bridge_up
    _run_cmd(["sudo", "ip", "link", "set", BRIDGE, "down"])
    _run_cmd(["sudo", "ip", "link", "del", BRIDGE])
    bridge_up = False


# ---------------------------------------------------------------------------
# Capture thread
# ---------------------------------------------------------------------------

def _parse_line(line):
    """Parse a tcpdump line to extract protocol and size info."""
    global total_packets, total_bytes
    parts = line.strip().split()
    if len(parts) < 5:
        return

    # Detect protocol from tcpdump output
    proto = "OTHER"
    line_lower = line.lower()
    if " arp " in line_lower or "arp," in line_lower:
        proto = "ARP"
    elif ".53:" in line or ".53 " in line or " dns " in line_lower:
        proto = "DNS"
    elif ".80:" in line or ".80 " in line:
        proto = "HTTP"
    elif ".443:" in line or ".443 " in line:
        proto = "HTTPS"
    elif " icmp " in line_lower:
        proto = "ICMP"
    elif " udp " in line_lower:
        proto = "UDP"
    elif " tcp " in line_lower or "flags" in line_lower:
        proto = "TCP"

    # Extract packet length from "length N"
    pkt_len = 64  # default estimate
    if "length" in line_lower:
        try:
            idx = line_lower.index("length")
            num_str = parts[line_lower[:idx].count(" ") + 1].rstrip(",:")
            pkt_len = int(num_str) if num_str.isdigit() else 64
        except (IndexError, ValueError):
            pass

    # Extract IPs
    src_ip = ""
    dst_ip = ""
    import re
    ip_matches = re.findall(r"(\d+\.\d+\.\d+\.\d+)", line)
    if len(ip_matches) >= 2:
        src_ip = ip_matches[0]
        dst_ip = ip_matches[1]

    with lock:
        total_packets += 1
        total_bytes += pkt_len
        protocol_counts[proto] += 1
        protocol_bytes[proto] += pkt_len
        if src_ip and dst_ip:
            pair = tuple(sorted([src_ip, dst_ip]))
            ip_pair_bytes[pair] += pkt_len


def _capture_thread():
    """Run tcpdump and parse output."""
    global capture_running, _capture_proc, status_msg
    try:
        _capture_proc = subprocess.Popen(
            ["sudo", "tcpdump", "-i", BRIDGE, "-nn", "-l", "-q", "-e"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
    except Exception as exc:
        with lock:
            status_msg = f"tcpdump err: {exc}"
        capture_running = False
        return

    with lock:
        status_msg = "Capturing..."

    try:
        for line in iter(_capture_proc.stdout.readline, ""):
            if not app_running or not capture_running:
                break
            _parse_line(line)
    except Exception:
        pass
    finally:
        if _capture_proc and _capture_proc.poll() is None:
            _capture_proc.terminate()
        capture_running = False


def _rate_calculator():
    """Periodically compute packets/sec and bytes/sec."""
    global packets_per_sec, bytes_per_sec, _last_pps_time
    global _last_pps_count, _last_bps_count

    while app_running:
        time.sleep(1)
        now = time.time()
        with lock:
            tp = total_packets
            tb = total_bytes
        elapsed = now - _last_pps_time if _last_pps_time else 1
        if elapsed > 0:
            with lock:
                packets_per_sec = int((tp - _last_pps_count) / elapsed)
                bytes_per_sec = int((tb - _last_bps_count) / elapsed)
        _last_pps_time = now
        _last_pps_count = tp
        _last_bps_count = tb


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_stats():
    global status_msg
    with lock:
        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "packets_per_sec": packets_per_sec,
            "bytes_per_sec": bytes_per_sec,
            "protocols": dict(protocol_counts),
            "protocol_bytes": dict(protocol_bytes),
            "top_talkers": [
                {"pair": list(k), "bytes": v}
                for k, v in sorted(ip_pair_bytes.items(),
                                   key=lambda x: x[1], reverse=True)[:10]
            ],
        }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"tap_{ts}.json")
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

def _format_bytes(b):
    if b >= 1_000_000:
        return f"{b / 1_000_000:.1f}MB"
    if b >= 1_000:
        return f"{b / 1_000:.1f}KB"
    return f"{b}B"


def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    draw = ScaledDraw(img)
    draw.text((2, 2), "NETWORK TAP", fill="CYAN", font=font)

    dm = DISPLAY_MODES[display_mode_idx]
    with lock:
        st = status_msg
        pps = packets_per_sec
        bps = bytes_per_sec
        tp = total_packets
        tb = total_bytes
        protos = dict(protocol_counts)
        pairs = sorted(ip_pair_bytes.items(), key=lambda x: x[1], reverse=True)[:5]
        sp = scroll_pos
        cap = capture_running

    indicator = "REC" if cap else "IDLE"
    ind_color = "RED" if cap else "GRAY"
    draw.text((90, 2), indicator, fill=ind_color, font=font)
    draw.text((2, 14), st[:22], fill="WHITE", font=font)

    if dm == "overview":
        draw.text((2, 28), f"Pkts:  {tp}", fill="WHITE", font=font)
        draw.text((2, 42), f"Bytes: {_format_bytes(tb)}", fill="WHITE", font=font)
        draw.text((2, 56), f"PPS:   {pps}", fill="GREEN", font=font)
        draw.text((2, 70), f"BPS:   {_format_bytes(bps)}", fill="GREEN", font=font)
        draw.text((2, 84), f"Bridge: {BRIDGE}", fill="GRAY", font=font)
        draw.text((2, 98), f"Mode: {dm}", fill="GRAY", font=font)

    elif dm == "protocols":
        y = 28
        sorted_protos = sorted(protos.items(), key=lambda x: x[1], reverse=True)
        for name, cnt in sorted_protos[sp:sp + ROWS_VISIBLE]:
            bar_len = min(60, int(cnt * 60 / max(tp, 1)))
            color_map = {
                "TCP": "BLUE", "UDP": "GREEN", "HTTP": "YELLOW",
                "HTTPS": "ORANGE", "DNS": "CYAN", "ARP": "MAGENTA",
                "ICMP": "RED",
            }
            c = color_map.get(name, "WHITE")
            draw.text((2, y), f"{name:<6}{cnt:>6}", fill=c, font=font)
            draw.rectangle((80, y + 2, 80 + bar_len, y + 10), fill=c)
            y += 14

    elif dm == "top_talkers":
        y = 28
        for pair, bcount in pairs[sp:sp + ROWS_VISIBLE]:
            label = f"{pair[0].split('.')[-1]}<>{pair[1].split('.')[-1]}"
            draw.text((2, y), f"{label} {_format_bytes(bcount)}"[:22],
                      fill="WHITE", font=font)
            y += 14
        if not pairs:
            draw.text((2, 56), "No traffic yet", fill="GRAY", font=font)

    draw.text((2, 116), "OK=cap K1=view K3=exit", fill="GRAY", font=font)
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global app_running, capture_running, display_mode_idx, scroll_pos
    global status_msg

    try:
        _setup_bridge()
        threading.Thread(target=_rate_calculator, daemon=True).start()
        _draw_screen()

        while app_running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                app_running = False
                break

            elif btn == "OK":
                if not capture_running:
                    capture_running = True
                    threading.Thread(target=_capture_thread, daemon=True).start()
                else:
                    capture_running = False
                    if _capture_proc and _capture_proc.poll() is None:
                        _capture_proc.terminate()
                    with lock:
                        status_msg = "Capture stopped"

            elif btn == "UP":
                with lock:
                    if scroll_pos > 0:
                        scroll_pos -= 1

            elif btn == "DOWN":
                with lock:
                    scroll_pos += 1

            elif btn == "KEY1":
                display_mode_idx = (display_mode_idx + 1) % len(DISPLAY_MODES)
                with lock:
                    scroll_pos = 0

            elif btn == "KEY2":
                threading.Thread(target=_export_stats, daemon=True).start()

            _draw_screen()
            time.sleep(0.15)

    finally:
        app_running = False
        capture_running = False
        if _capture_proc and _capture_proc.poll() is None:
            _capture_proc.terminate()
        _teardown_bridge()
        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            d = ScaledDraw(img)
            d.text((10, 50), "Bridge removed", fill="YELLOW", font=font)
            d.text((10, 66), "Tap stopped", fill="RED", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass
        GPIO.cleanup()


if __name__ == "__main__":
    main()
