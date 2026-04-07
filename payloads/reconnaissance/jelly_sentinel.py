#!/usr/bin/env python3
"""
RaspyJack Payload -- Passive Traffic Sentinel
===============================================
Author: 7h30th3r0n3

Monitors network traffic passively via tcpdump and displays a live
dashboard with packet counts, unique IPs, top talkers, and protocol
distribution on the LCD.

Controls:
  UP / DOWN  -- Scroll top talkers list
  KEY1       -- Toggle interface (eth0 / wlan0 / wlan1)
  KEY2       -- Export stats to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/Sentinel/<timestamp>.json
"""

import os
import sys
import json
import time
import re
import subprocess
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

# ---------------------------------------------------------------------------
# Pin / LCD setup
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT

LOOT_DIR = "/root/Raspyjack/loot/Sentinel"
INTERFACES = ["eth0", "wlan0", "wlan1"]
ROW_H = 12
ROWS_VISIBLE = 5

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True
capturing = False
current_iface_idx = 0
status_msg = "Idle"
scroll_pos = 0

# Stats
total_packets = 0
unique_ips = set()
# ip -> packet count
ip_counts = {}
# protocol -> packet count
proto_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}

# Reference to the capture process for restart
_capture_proc = None
_capture_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Packet parsing
# ---------------------------------------------------------------------------
_IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")


def _parse_tcpdump_line(line):
    """Parse a tcpdump -q -n line and return (src_ip, dst_ip, proto)."""
    ips = _IP_RE.findall(line)
    src_ip = ips[0] if len(ips) >= 1 else None
    dst_ip = ips[1] if len(ips) >= 2 else None

    proto = "Other"
    line_upper = line.upper()
    if "TCP" in line_upper:
        proto = "TCP"
    elif "UDP" in line_upper:
        proto = "UDP"
    elif "ICMP" in line_upper:
        proto = "ICMP"

    return src_ip, dst_ip, proto


# ---------------------------------------------------------------------------
# Capture thread
# ---------------------------------------------------------------------------
def _capture_thread(iface):
    """Run tcpdump and parse output continuously."""
    global capturing, status_msg, total_packets, _capture_proc

    cmd = ["tcpdump", "-i", iface, "-l", "-q", "-n"]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        with lock:
            status_msg = "tcpdump not found"
            capturing = False
        return
    except Exception as exc:
        with lock:
            status_msg = f"Err: {str(exc)[:14]}"
            capturing = False
        return

    with _capture_lock:
        _capture_proc = proc

    with lock:
        status_msg = f"Listening {iface}"
        capturing = True

    try:
        while running:
            line = proc.stdout.readline()
            if not line:
                break

            src_ip, dst_ip, proto = _parse_tcpdump_line(line)

            with lock:
                total_packets += 1
                proto_counts[proto] = proto_counts.get(proto, 0) + 1

                if src_ip:
                    unique_ips.add(src_ip)
                    ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
                if dst_ip:
                    unique_ips.add(dst_ip)
                    ip_counts[dst_ip] = ip_counts.get(dst_ip, 0) + 1

    except Exception:
        pass
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        with _capture_lock:
            _capture_proc = None
        with lock:
            capturing = False
            if "Err" not in status_msg:
                status_msg = "Stopped"


def _stop_capture():
    """Terminate the current capture process."""
    with _capture_lock:
        proc = _capture_proc
    if proc is not None:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def _start_capture(iface):
    """Start a new capture thread for the given interface."""
    _stop_capture()
    time.sleep(0.2)
    threading.Thread(target=_capture_thread, args=(iface,), daemon=True).start()


# ---------------------------------------------------------------------------
# Loot export
# ---------------------------------------------------------------------------
def _export_loot():
    """Write sentinel stats to JSON loot file."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"sentinel_{ts}.json")

    with lock:
        sorted_talkers = sorted(
            ip_counts.items(), key=lambda kv: kv[1], reverse=True
        )
        data = {
            "timestamp": ts,
            "interface": INTERFACES[current_iface_idx],
            "total_packets": total_packets,
            "unique_ips": len(unique_ips),
            "protocol_distribution": dict(proto_counts),
            "top_talkers": [
                {"ip": ip, "packets": count}
                for ip, count in sorted_talkers[:20]
            ],
        }

    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)

    return filepath


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------
def _draw_header(d, font, active):
    """Draw header bar."""
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "SENTINEL", font=font, fill="#00CCFF")
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if active else "#FF0000")


def _draw_footer(d, font, text):
    """Draw footer bar."""
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font, fill="#AAA")


def _draw_dashboard(lcd, font):
    """Render the live traffic dashboard."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        active = capturing
        st = status_msg
        pkts = total_packets
        n_ips = len(unique_ips)
        protos = dict(proto_counts)
        sorted_talkers = sorted(
            ip_counts.items(), key=lambda kv: kv[1], reverse=True
        )
        sc = scroll_pos
        iface = INTERFACES[current_iface_idx]

    _draw_header(d, font, active)

    # Stats summary
    d.text((2, 15), f"{st[:14]}  Pkt:{pkts}", font=font, fill="#888")
    d.text((2, 27), f"IPs:{n_ips} T:{protos.get('TCP', 0)} U:{protos.get('UDP', 0)}", font=font, fill="#AAA")

    # Protocol bar (simple horizontal bar)
    bar_x, bar_y, bar_w = 2, 39, 124
    total_proto = sum(protos.values()) or 1
    tcp_w = int(protos.get("TCP", 0) / total_proto * bar_w)
    udp_w = int(protos.get("UDP", 0) / total_proto * bar_w)
    icmp_w = int(protos.get("ICMP", 0) / total_proto * bar_w)

    x = bar_x
    if tcp_w > 0:
        d.rectangle((x, bar_y, x + tcp_w, bar_y + 5), fill="#00AAFF")
        x += tcp_w
    if udp_w > 0:
        d.rectangle((x, bar_y, x + udp_w, bar_y + 5), fill="#FFAA00")
        x += udp_w
    if icmp_w > 0:
        d.rectangle((x, bar_y, x + icmp_w, bar_y + 5), fill="#FF4444")
        x += icmp_w
    remaining = bar_x + bar_w - x
    if remaining > 0:
        d.rectangle((x, bar_y, x + remaining, bar_y + 5), fill="#444")

    # Legend
    d.text((2, 46), "TCP", font=font, fill="#00AAFF")
    d.text((30, 46), "UDP", font=font, fill="#FFAA00")
    d.text((58, 46), "ICMP", font=font, fill="#FF4444")

    # Top talkers
    d.text((2, 58), "-- Top Talkers --", font=font, fill="#666")
    visible = sorted_talkers[sc:sc + ROWS_VISIBLE]
    for i, (ip, count) in enumerate(visible):
        y = 70 + i * ROW_H
        short_ip = ip if len(ip) <= 15 else ip[-15:]
        line = f"{short_ip:<15s} {count}"
        d.text((2, y), line[:22], font=font, fill="#CCCCCC")

    # Scroll indicator
    total_items = len(sorted_talkers)
    if total_items > ROWS_VISIBLE:
        area_h = ROWS_VISIBLE * ROW_H
        ind_h = max(4, int(ROWS_VISIBLE / total_items * area_h))
        ind_y = 70 + int(sc / total_items * area_h)
        d.rectangle((126, ind_y, 127, ind_y + ind_h), fill="#444")

    _draw_footer(d, font, f"{iface} K1:Iface K3:Exit")
    lcd.LCD_ShowImage(img, 0, 0)


def _show_message(lcd, font, line1, line2=""):
    """Show a brief message."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((10, 50), line1, font=font, fill="#00FF00")
    if line2:
        d.text((4, 65), line2, font=font, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global running, scroll_pos, current_iface_idx
    global total_packets, unique_ips, ip_counts, proto_counts

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font = scaled_font()

    # Splash screen
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 16), "TRAFFIC SENTINEL", font=font, fill="#00CCFF")
    d.text((4, 32), "Passive network", font=font, fill="#888")
    d.text((4, 44), "traffic monitor", font=font, fill="#888")
    d.text((4, 64), "K1:Switch iface", font=font, fill="#666")
    d.text((4, 76), "K2:Export stats", font=font, fill="#666")
    d.text((4, 88), "K3:Exit", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)

    running = True
    _start_capture(INTERFACES[current_iface_idx])

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                running = False
                _stop_capture()
                if total_packets > 0:
                    _export_loot()
                break

            elif btn == "KEY1":
                # Cycle interface
                running_tmp = running
                _stop_capture()
                with lock:
                    current_iface_idx = (current_iface_idx + 1) % len(INTERFACES)
                    # Reset stats on interface change
                    total_packets = 0
                    unique_ips = set()
                    ip_counts = {}
                    proto_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
                    scroll_pos = 0
                    status_msg = "Switching..."
                time.sleep(0.3)
                _start_capture(INTERFACES[current_iface_idx])
                time.sleep(0.3)

            elif btn == "KEY2":
                if total_packets > 0:
                    path = _export_loot()
                    _show_message(lcd, font, "Exported!", path[-20:])
                else:
                    _show_message(lcd, font, "No data yet")
                time.sleep(0.3)

            elif btn == "UP":
                scroll_pos = max(0, scroll_pos - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                with lock:
                    max_scroll = max(0, len(ip_counts) - ROWS_VISIBLE)
                scroll_pos = min(scroll_pos + 1, max_scroll)
                time.sleep(0.15)

            _draw_dashboard(lcd, font)
            time.sleep(0.05)

    finally:
        running = False
        _stop_capture()
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
