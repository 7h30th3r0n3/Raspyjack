#!/usr/bin/env python3
"""
RaspyJack Payload -- PCAP Packet Replayer
==========================================
Author: 7h30th3r0n3

Lists .pcap files from the loot directory and replays them using scapy.
Uses PcapReader for streaming to avoid memory issues on 512MB Pi Zero.
Supports original timing, accelerated replay, and optional MAC rewrite.

Controls:
  OK          -- Start / stop replay
  UP / DOWN   -- Select pcap file
  KEY1        -- Toggle speed (1x / 5x / max)
  KEY2        -- Select interface
  KEY3        -- Exit

Requires: scapy
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
    from scapy.all import (
        PcapReader, sendp, Ether, conf, get_if_hwaddr, get_if_list,
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
ROWS_VISIBLE = 6
ROW_H = 12

LOOT_DIR = "/root/Raspyjack/loot"
SPEED_MODES = ["1x", "5x", "max"]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
replaying = False
scroll = 0
selected = 0
speed_idx = 0
iface_idx = 0
status_msg = "Ready"
packets_sent = 0
packets_total = 0
progress = 0.0

# File list and interface list
pcap_files = []
interfaces = []

# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

def _find_pcap_files():
    """Recursively find .pcap files in loot directory."""
    found = []
    if not os.path.isdir(LOOT_DIR):
        return found

    for root, _dirs, files in os.walk(LOOT_DIR):
        for fname in files:
            if fname.endswith((".pcap", ".pcapng", ".cap")):
                filepath = os.path.join(root, fname)
                try:
                    size = os.path.getsize(filepath)
                    found.append({
                        "path": filepath,
                        "name": fname,
                        "size": size,
                    })
                except Exception:
                    pass

    # Sort by modification time (newest first)
    found.sort(key=lambda f: os.path.getmtime(f["path"]), reverse=True)
    return found


def _get_interfaces():
    """Get list of available network interfaces."""
    try:
        ifaces = get_if_list()
        return [i for i in ifaces if i != "lo"]
    except Exception:
        return ["eth0", "wlan0"]


def _format_size(size_bytes):
    """Format file size for display."""
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes // 1024}KB"
    else:
        return f"{size_bytes // (1024 * 1024)}MB"

# ---------------------------------------------------------------------------
# Packet counting (streaming)
# ---------------------------------------------------------------------------

def _count_packets(filepath):
    """Count packets in a pcap file using streaming reader."""
    count = 0
    try:
        reader = PcapReader(filepath)
        for _pkt in reader:
            count += 1
        reader.close()
    except Exception:
        pass
    return count

# ---------------------------------------------------------------------------
# Replay thread
# ---------------------------------------------------------------------------

def _replay_thread(filepath, iface_name, speed_mode):
    """Replay packets from a pcap file."""
    global replaying, packets_sent, packets_total, progress, status_msg

    with lock:
        status_msg = "Counting packets..."

    total = _count_packets(filepath)
    with lock:
        packets_total = total
        packets_sent = 0
        progress = 0.0

    if total == 0:
        with lock:
            status_msg = "Empty pcap file"
            replaying = False
        return

    with lock:
        status_msg = f"Replaying {total} pkts..."

    try:
        reader = PcapReader(filepath)
    except Exception as exc:
        with lock:
            status_msg = f"Err: {str(exc)[:16]}"
            replaying = False
        return

    prev_time = None
    sent = 0

    try:
        for pkt in reader:
            if not _running or not replaying:
                break

            # Timing
            if speed_mode == "1x" and prev_time is not None:
                delta = float(pkt.time) - prev_time
                if delta > 0:
                    time.sleep(min(delta, 5.0))
            elif speed_mode == "5x" and prev_time is not None:
                delta = (float(pkt.time) - prev_time) / 5.0
                if delta > 0:
                    time.sleep(min(delta, 1.0))
            # "max" mode: no delay

            prev_time = float(pkt.time)

            try:
                sendp(pkt, iface=iface_name, verbose=False)
                sent += 1
            except Exception:
                pass

            with lock:
                packets_sent = sent
                progress = sent / max(total, 1)

        reader.close()
    except Exception:
        pass

    with lock:
        replaying = False
        packets_sent = sent
        progress = 1.0
        status_msg = f"Done: {sent}/{total} sent"

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_frame(lcd, font_obj):
    """Render current state to the LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "PACKET REPLAY", font=font_obj, fill="#00CCFF")
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if replaying else "#444")

    with lock:
        msg = status_msg
        files = list(pcap_files)
        sel = selected
        speed = SPEED_MODES[speed_idx]
        iface_name = interfaces[iface_idx] if interfaces else "eth0"
        sent = packets_sent
        total = packets_total
        prog = progress

    if replaying:
        # Replay progress view
        d.text((2, 16), f"Speed: {speed}  Iface: {iface_name}", font=font_obj, fill="#FFAA00")
        d.text((2, 28), f"Pkts: {sent}/{total}", font=font_obj, fill="#AAAAAA")

        # Progress bar
        bar_x, bar_y, bar_w, bar_h = 4, 42, 120, 10
        d.rectangle((bar_x, bar_y, bar_x + bar_w, bar_y + bar_h), outline="#444")
        fill_w = int(prog * (bar_w - 2))
        if fill_w > 0:
            d.rectangle(
                (bar_x + 1, bar_y + 1, bar_x + 1 + fill_w, bar_y + bar_h - 1),
                fill="#00CCFF",
            )

        pct = int(prog * 100)
        d.text((2, 56), f"{pct}%", font=font_obj, fill="#888")

        if sel < len(files):
            d.text((2, 70), files[sel]["name"][:24], font=font_obj, fill="#666")

        d.text((2, 90), msg[:24], font=font_obj, fill="#888")
    else:
        # File selector view
        d.text((2, 16), f"Spd:{speed} If:{iface_name}", font=font_obj, fill="#FFAA00")

        if not files:
            d.text((2, 40), "No pcap files found", font=font_obj, fill="#FF8800")
            d.text((2, 55), f"in {LOOT_DIR}", font=font_obj, fill="#666")
        else:
            visible = files[scroll:scroll + ROWS_VISIBLE]
            for i, f in enumerate(visible):
                y = 30 + i * ROW_H
                idx = scroll + i
                marker = ">" if idx == sel else " "
                color = "#FFAA00" if idx == sel else "#CCCCCC"
                size_str = _format_size(f["size"])
                line = f"{marker}{f['name'][:16]} {size_str}"
                d.text((2, y), line[:24], font=font_obj, fill=color)

        d.text((2, 100), msg[:24], font=font_obj, fill="#888")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if replaying:
        d.text((2, 117), "OK:Stop  K3:Exit", font=font_obj, fill="#888")
    else:
        d.text((2, 117), "OK:Play K1:Spd K3:Quit", font=font_obj, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, replaying, scroll, selected, speed_idx, iface_idx
    global pcap_files, interfaces, status_msg

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

    # Discover files and interfaces
    pcap_files = _find_pcap_files()
    interfaces = _get_interfaces()
    if not interfaces:
        interfaces = ["eth0"]

    with lock:
        status_msg = f"Found {len(pcap_files)} pcap(s)"

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK":
                if replaying:
                    replaying = False
                elif pcap_files and 0 <= selected < len(pcap_files):
                    replaying = True
                    filepath = pcap_files[selected]["path"]
                    iface_name = interfaces[iface_idx]
                    speed = SPEED_MODES[speed_idx]
                    threading.Thread(
                        target=_replay_thread,
                        args=(filepath, iface_name, speed),
                        daemon=True,
                    ).start()
                time.sleep(0.3)

            elif btn == "KEY1" and not replaying:
                speed_idx = (speed_idx + 1) % len(SPEED_MODES)
                time.sleep(0.3)

            elif btn == "KEY2" and not replaying:
                if interfaces:
                    iface_idx = (iface_idx + 1) % len(interfaces)
                time.sleep(0.3)

            elif btn == "UP":
                selected = max(0, selected - 1)
                if selected < scroll:
                    scroll = selected
                time.sleep(0.15)

            elif btn == "DOWN":
                max_sel = max(0, len(pcap_files) - 1)
                selected = min(selected + 1, max_sel)
                if selected >= scroll + ROWS_VISIBLE:
                    scroll = selected - ROWS_VISIBLE + 1
                time.sleep(0.15)

            _draw_frame(lcd, font_obj)
            time.sleep(0.05)

    finally:
        _running = False
        replaying = False
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
