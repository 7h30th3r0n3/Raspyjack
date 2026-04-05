#!/usr/bin/env python3
"""
RaspyJack Payload -- MITM Traffic Shaper
=========================================
Author: 7h30th3r0n3

Uses Linux `tc` (traffic control) to limit and shape traffic on the bridge
interface during MITM operations, keeping latency under suspicious thresholds
to maintain stealth.

Controls:
  OK          -- Enable / disable shaping
  UP / DOWN   -- Adjust bandwidth limit (+/- 1 Mbps)
  KEY1        -- Auto mode (match pre-attack baseline)
  KEY2        -- Show per-protocol stats
  KEY3        -- Exit + remove all tc rules

Requires: iproute2 (tc command)
"""

import os
import sys
import time
import threading
import subprocess
import re
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT

DEFAULT_IFACE = "br0"
FALLBACK_IFACES = ["br0", "eth0", "wlan0"]
MIN_BW_MBIT = 1
MAX_BW_MBIT = 100
DEFAULT_BW_MBIT = 10

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
shaping_active = False
auto_mode = False
show_proto_stats = False
bandwidth_mbit = DEFAULT_BW_MBIT
baseline_latency_ms = 0.0
current_latency_ms = 0.0
iface = DEFAULT_IFACE
status_msg = "Ready"

# Queue stats
queue_stats = {"sent": 0, "dropped": 0, "overlimits": 0, "backlog": 0}
# Per-protocol stats (from iptables counters)
proto_stats = []

# ---------------------------------------------------------------------------
# Interface detection
# ---------------------------------------------------------------------------

def _detect_interface():
    """Detect the best interface for traffic shaping."""
    for candidate in FALLBACK_IFACES:
        try:
            r = subprocess.run(
                ["ip", "link", "show", candidate],
                capture_output=True, text=True, timeout=5,
            )
            if "UP" in r.stdout:
                return candidate
        except Exception:
            pass
    return DEFAULT_IFACE

# ---------------------------------------------------------------------------
# TC (traffic control) commands
# ---------------------------------------------------------------------------

def _run_tc(args):
    """Run a tc command and return (success, output)."""
    try:
        r = subprocess.run(
            ["tc"] + args,
            capture_output=True, text=True, timeout=10,
        )
        return r.returncode == 0, r.stdout + r.stderr
    except Exception as exc:
        return False, str(exc)


def _apply_shaping(iface_name, bw_mbit):
    """Apply HTB qdisc with bandwidth limit."""
    # Remove existing rules first
    _run_tc(["qdisc", "del", "dev", iface_name, "root"])
    time.sleep(0.1)

    # Add root HTB qdisc
    ok, msg = _run_tc([
        "qdisc", "add", "dev", iface_name, "root", "handle", "1:",
        "htb", "default", "10",
    ])
    if not ok:
        return False, msg

    # Add class with bandwidth limit
    rate = f"{bw_mbit}mbit"
    burst = f"{max(bw_mbit * 2, 15)}k"
    ok, msg = _run_tc([
        "class", "add", "dev", iface_name, "parent", "1:",
        "classid", "1:10", "htb",
        "rate", rate, "burst", burst, "cburst", burst,
    ])
    if not ok:
        return False, msg

    # Add SFQ for fairness within the class
    ok, msg = _run_tc([
        "qdisc", "add", "dev", iface_name, "parent", "1:10",
        "handle", "10:", "sfq", "perturb", "10",
    ])
    return ok, msg


def _remove_shaping(iface_name):
    """Remove all tc rules from the interface."""
    return _run_tc(["qdisc", "del", "dev", iface_name, "root"])


def _get_queue_stats(iface_name):
    """Parse tc -s qdisc output for queue statistics."""
    ok, output = _run_tc(["-s", "qdisc", "show", "dev", iface_name])
    stats = {"sent": 0, "dropped": 0, "overlimits": 0, "backlog": 0}
    if not ok:
        return stats

    sent_match = re.search(r"Sent (\d+) bytes (\d+) pkt", output)
    if sent_match:
        stats["sent"] = int(sent_match.group(2))

    dropped_match = re.search(r"dropped (\d+)", output)
    if dropped_match:
        stats["dropped"] = int(dropped_match.group(1))

    overlimits_match = re.search(r"overlimits (\d+)", output)
    if overlimits_match:
        stats["overlimits"] = int(overlimits_match.group(1))

    backlog_match = re.search(r"backlog (\d+)b", output)
    if backlog_match:
        stats["backlog"] = int(backlog_match.group(1))

    return stats

# ---------------------------------------------------------------------------
# Latency measurement
# ---------------------------------------------------------------------------

def _measure_latency(target="8.8.8.8"):
    """Measure round-trip latency using ping."""
    try:
        r = subprocess.run(
            ["ping", "-c", "3", "-W", "2", target],
            capture_output=True, text=True, timeout=10,
        )
        match = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", r.stdout)
        if match:
            return float(match.group(1))
    except Exception:
        pass
    return 0.0

# ---------------------------------------------------------------------------
# Per-protocol stats
# ---------------------------------------------------------------------------

def _get_proto_stats():
    """Get per-protocol traffic stats via /proc/net/snmp."""
    stats = []
    try:
        with open("/proc/net/snmp") as f:
            lines = f.readlines()
        for i in range(0, len(lines) - 1, 2):
            header = lines[i].strip().split()
            values = lines[i + 1].strip().split()
            proto = header[0].rstrip(":")
            if proto in ("Tcp", "Udp", "Icmp"):
                # Find InSegs/InDatagrams/InMsgs and Out equivalents
                for j, field in enumerate(header[1:], 1):
                    if field.startswith("In") and "Seg" in field or field.startswith("In") and "Dat" in field:
                        in_val = int(values[j]) if j < len(values) else 0
                        stats.append(f"{proto}: In={in_val}")
                        break
                else:
                    stats.append(f"{proto}: active")
    except Exception:
        stats.append("Stats unavailable")
    return stats

# ---------------------------------------------------------------------------
# Monitor thread
# ---------------------------------------------------------------------------

def _monitor_thread():
    """Periodically update latency and queue stats."""
    global current_latency_ms, queue_stats, proto_stats

    while _running:
        lat = _measure_latency()
        with lock:
            current_latency_ms = lat

        if shaping_active:
            stats = _get_queue_stats(iface)
            ps = _get_proto_stats()
            with lock:
                queue_stats = stats
                proto_stats = ps

        # Update every 5 seconds
        deadline = time.time() + 5.0
        while time.time() < deadline and _running:
            time.sleep(0.5)

# ---------------------------------------------------------------------------
# Auto-mode: measure baseline then set shaping to match
# ---------------------------------------------------------------------------

def _measure_baseline():
    """Measure baseline latency before shaping."""
    global baseline_latency_ms, status_msg, bandwidth_mbit

    with lock:
        status_msg = "Measuring baseline..."

    latencies = []
    for _ in range(3):
        if not _running:
            return
        lat = _measure_latency()
        if lat > 0:
            latencies.append(lat)
        time.sleep(1)

    if latencies:
        avg = sum(latencies) / len(latencies)
        with lock:
            baseline_latency_ms = avg
            # Set bandwidth to keep latency similar
            # Heuristic: lower bandwidth for higher baseline latency
            if avg < 10:
                bandwidth_mbit = 50
            elif avg < 30:
                bandwidth_mbit = 20
            elif avg < 100:
                bandwidth_mbit = 10
            else:
                bandwidth_mbit = 5
            status_msg = f"Baseline: {avg:.1f}ms -> {bandwidth_mbit}Mbps"
    else:
        with lock:
            status_msg = "Baseline failed"

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_frame(lcd, font_obj):
    """Render current state to the LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "TRAFFIC SHAPER", font=font_obj, fill="#00CCFF")
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if shaping_active else "#444")

    with lock:
        msg = status_msg
        bw = bandwidth_mbit
        lat = current_latency_ms
        base_lat = baseline_latency_ms
        auto = auto_mode
        qs = dict(queue_stats)
        ps = list(proto_stats)
        showing_proto = show_proto_stats

    if showing_proto:
        d.text((2, 16), "Protocol Stats:", font=font_obj, fill="#FFAA00")
        for i, line in enumerate(ps[:7]):
            d.text((2, 28 + i * 12), line[:24], font=font_obj, fill="#CCCCCC")
    else:
        # Latency
        lat_color = "#00FF00" if lat < 50 else "#FFAA00" if lat < 150 else "#FF0000"
        d.text((2, 16), f"Latency: {lat:.1f}ms", font=font_obj, fill=lat_color)
        if base_lat > 0:
            d.text((2, 28), f"Baseline: {base_lat:.1f}ms", font=font_obj, fill="#888")

        # Bandwidth
        d.text((2, 40), f"BW Limit: {bw} Mbps", font=font_obj, fill="#FFAA00")
        auto_tag = " [AUTO]" if auto else ""
        d.text((2, 52), f"Interface: {iface}{auto_tag}", font=font_obj, fill="#888")

        # Queue stats
        d.text((2, 66), "Queue:", font=font_obj, fill="#666")
        d.text((2, 78), f"Pkts: {qs['sent']}  Drop: {qs['dropped']}", font=font_obj, fill="#AAAAAA")
        d.text((2, 88), f"Overlim: {qs['overlimits']}", font=font_obj, fill="#AAAAAA")

        d.text((2, 102), msg[:24], font=font_obj, fill="#888")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Shp U/D:BW K3:Quit", font=font_obj, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, shaping_active, bandwidth_mbit, auto_mode
    global show_proto_stats, status_msg, iface

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font_obj = scaled_font()

    iface = _detect_interface()

    # Start monitoring thread
    threading.Thread(target=_monitor_thread, daemon=True).start()

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK":
                if shaping_active:
                    _remove_shaping(iface)
                    shaping_active = False
                    with lock:
                        status_msg = "Shaping disabled"
                else:
                    ok, msg = _apply_shaping(iface, bandwidth_mbit)
                    shaping_active = ok
                    with lock:
                        status_msg = "Shaping ON" if ok else f"Err: {msg[:16]}"
                time.sleep(0.3)

            elif btn == "UP":
                bandwidth_mbit = min(MAX_BW_MBIT, bandwidth_mbit + 1)
                if shaping_active:
                    _apply_shaping(iface, bandwidth_mbit)
                time.sleep(0.15)

            elif btn == "DOWN":
                bandwidth_mbit = max(MIN_BW_MBIT, bandwidth_mbit - 1)
                if shaping_active:
                    _apply_shaping(iface, bandwidth_mbit)
                time.sleep(0.15)

            elif btn == "KEY1":
                auto_mode = not auto_mode
                if auto_mode:
                    threading.Thread(
                        target=_measure_baseline, daemon=True
                    ).start()
                time.sleep(0.3)

            elif btn == "KEY2":
                show_proto_stats = not show_proto_stats
                time.sleep(0.3)

            _draw_frame(lcd, font_obj)
            time.sleep(0.05)

    finally:
        _running = False
        if shaping_active:
            _remove_shaping(iface)
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
