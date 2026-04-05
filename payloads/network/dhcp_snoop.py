#!/usr/bin/env python3
"""
RaspyJack Payload -- DHCP Snoop
=================================
Author: 7h30th3r0n3

Passive DHCP snooping for network reconnaissance.
Sniffs DHCP Discover/Offer/Request/ACK packets to map clients,
hostnames, MAC addresses, lease info, and DHCP server details.

Flow:
  1) Sniff UDP 67/68 (DHCP) packets
  2) Extract: client MAC, hostname, IP, DHCP server, gateway, DNS
  3) Build a table of all DHCP clients
  4) Display on LCD with server details

Controls:
  OK        -- Start / stop sniffing
  UP / DOWN -- Scroll client list
  KEY1      -- Show DHCP server details
  KEY2      -- Export data
  KEY3      -- Exit

Loot: /root/Raspyjack/loot/DHCPSnoop/

Setup: Passive, no special requirements.
"""

import os
import sys
import time
import json
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
    from scapy.all import sniff, DHCP, BOOTP, IP, UDP, Ether, conf
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
LOOT_DIR = "/root/Raspyjack/loot/DHCPSnoop"
os.makedirs(LOOT_DIR, exist_ok=True)
ROWS_VISIBLE = 6

DHCP_MSG_TYPES = {
    1: "Discover", 2: "Offer", 3: "Request",
    4: "Decline", 5: "ACK", 6: "NAK",
    7: "Release", 8: "Inform",
}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
clients = {}           # MAC -> {hostname, ip, server_ip, gateway, dns, lease_time, last_seen}
server_info = {
    "ip": "", "gateway": "", "dns": [],
    "subnet_mask": "", "domain": "",
}
scroll_pos = 0
view_mode = "clients"  # clients | server
status_msg = "Ready"
sniff_active = False
app_running = True
total_packets = 0


# ---------------------------------------------------------------------------
# DHCP packet parser
# ---------------------------------------------------------------------------

def _extract_dhcp_options(pkt):
    """Extract DHCP options into a dict."""
    opts = {}
    if pkt.haslayer(DHCP):
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and len(opt) >= 2:
                opts[opt[0]] = opt[1]
            elif opt == "end":
                break
    return opts


def _mac_from_bootp(pkt):
    """Extract client MAC from BOOTP chaddr."""
    if pkt.haslayer(BOOTP):
        raw_mac = pkt[BOOTP].chaddr[:6]
        return ":".join(f"{b:02x}" for b in raw_mac)
    if pkt.haslayer(Ether):
        return pkt[Ether].src
    return "00:00:00:00:00:00"


def _packet_handler(pkt):
    """Process a DHCP packet."""
    global total_packets

    if not pkt.haslayer(DHCP) or not pkt.haslayer(BOOTP):
        return

    with lock:
        total_packets += 1

    opts = _extract_dhcp_options(pkt)
    msg_type = opts.get("message-type", 0)
    client_mac = _mac_from_bootp(pkt)

    hostname = ""
    if "hostname" in opts:
        h = opts["hostname"]
        hostname = h.decode("utf-8", errors="ignore") if isinstance(h, bytes) else str(h)

    bootp = pkt[BOOTP]
    yiaddr = bootp.yiaddr if bootp.yiaddr != "0.0.0.0" else ""
    siaddr = bootp.siaddr if bootp.siaddr != "0.0.0.0" else ""

    # Extract options
    requested_ip = opts.get("requested_addr", "")
    server_id = opts.get("server_id", "")
    lease_time = opts.get("lease_time", 0)
    subnet_mask = opts.get("subnet_mask", "")
    router = opts.get("router", "")
    dns_servers = opts.get("name_server", "")
    domain = opts.get("domain", "")
    if isinstance(domain, bytes):
        domain = domain.decode("utf-8", errors="ignore")

    with lock:
        # Update client record
        entry = clients.get(client_mac, {
            "hostname": "", "ip": "", "server_ip": "",
            "gateway": "", "dns": [], "lease_time": 0,
            "last_seen": "", "msg_type": "",
        })

        if hostname:
            entry["hostname"] = hostname
        if yiaddr:
            entry["ip"] = yiaddr
        elif requested_ip:
            entry["ip"] = str(requested_ip)
        entry["msg_type"] = DHCP_MSG_TYPES.get(msg_type, f"Type{msg_type}")
        entry["last_seen"] = datetime.now().strftime("%H:%M:%S")

        if server_id:
            entry["server_ip"] = str(server_id)
        if lease_time:
            entry["lease_time"] = int(lease_time)

        new_clients = dict(clients)
        new_clients[client_mac] = entry
        clients.clear()
        clients.update(new_clients)

        # Update server info from Offer/ACK
        if msg_type in (2, 5):
            if server_id:
                server_info["ip"] = str(server_id)
            if router:
                server_info["gateway"] = str(router)
            if subnet_mask:
                server_info["subnet_mask"] = str(subnet_mask)
            if dns_servers:
                if isinstance(dns_servers, (list, tuple)):
                    server_info["dns"] = [str(d) for d in dns_servers]
                else:
                    server_info["dns"] = [str(dns_servers)]
            if domain:
                server_info["domain"] = domain


def _sniff_thread():
    """Sniff DHCP traffic."""
    global sniff_active, status_msg
    sniff_active = True
    with lock:
        status_msg = "Sniffing DHCP..."
    try:
        sniff(
            filter="udp and (port 67 or port 68)",
            prn=_packet_handler,
            store=False,
            stop_filter=lambda _: not app_running or not sniff_active,
        )
    except Exception as exc:
        with lock:
            status_msg = f"Err: {exc}"
    finally:
        sniff_active = False


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_data():
    global status_msg
    with lock:
        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_packets": total_packets,
            "server": dict(server_info),
            "clients": dict(clients),
        }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"dhcp_snoop_{ts}.json")
    try:
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        with lock:
            status_msg = "Exported to loot"
    except Exception:
        pass


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------

def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    draw = ScaledDraw(img)
    draw.text((2, 2), "DHCP SNOOP", fill="CYAN", font=font)

    with lock:
        st = status_msg
        tp = total_packets
        cl = dict(clients)
        si = dict(server_info)
        sp = scroll_pos
        vm = view_mode
        active = sniff_active

    indicator = "REC" if active else "IDLE"
    ind_color = "RED" if active else "GRAY"
    draw.text((90, 2), indicator, fill=ind_color, font=font)
    draw.text((2, 14), f"Pkts:{tp} Hosts:{len(cl)}", fill="WHITE", font=font)

    if vm == "clients":
        y = 28
        mac_list = sorted(cl.keys())
        for mac in mac_list[sp:sp + ROWS_VISIBLE]:
            entry = cl[mac]
            name = entry["hostname"][:8] or mac[-8:]
            ip = entry["ip"] or "?.?.?.?"
            msg = entry["msg_type"][:3]
            line = f"{name:<8} {ip:<15} {msg}"
            draw.text((2, y), line[:22], fill="GREEN", font=font)
            y += 14
        if not mac_list:
            draw.text((2, 56), "No DHCP clients yet", fill="GRAY", font=font)
        draw.text((2, 116), "OK=go K1=srv K3=exit", fill="GRAY", font=font)

    elif vm == "server":
        draw.text((2, 28), f"Server: {si['ip']}", fill="YELLOW", font=font)
        draw.text((2, 42), f"GW:     {si['gateway']}", fill="WHITE", font=font)
        draw.text((2, 56), f"Mask:   {si['subnet_mask']}", fill="WHITE", font=font)
        dns_str = ", ".join(si["dns"][:2]) if si["dns"] else "N/A"
        draw.text((2, 70), f"DNS:    {dns_str}"[:22], fill="WHITE", font=font)
        draw.text((2, 84), f"Domain: {si['domain']}"[:22], fill="WHITE", font=font)
        draw.text((2, 116), "K1=clients K3=exit", fill="GRAY", font=font)

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global app_running, sniff_active, scroll_pos, view_mode, status_msg

    if not SCAPY_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
        d = ScaledDraw(img)
        d.text((4, 50), "scapy not found!", font=font, fill="RED")
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return

    try:
        _draw_screen()

        while app_running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                app_running = False
                break

            elif btn == "OK":
                if not sniff_active:
                    sniff_active = True
                    threading.Thread(target=_sniff_thread, daemon=True).start()
                else:
                    sniff_active = False
                    with lock:
                        status_msg = "Stopped"

            elif btn == "UP":
                with lock:
                    if scroll_pos > 0:
                        scroll_pos -= 1

            elif btn == "DOWN":
                with lock:
                    max_s = max(0, len(clients) - ROWS_VISIBLE)
                    if scroll_pos < max_s:
                        scroll_pos += 1

            elif btn == "KEY1":
                with lock:
                    if view_mode == "clients":
                        view_mode = "server"
                    else:
                        view_mode = "clients"
                    scroll_pos = 0

            elif btn == "KEY2":
                threading.Thread(target=_export_data, daemon=True).start()

            _draw_screen()
            time.sleep(0.15)

    finally:
        app_running = False
        sniff_active = False
        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            d = ScaledDraw(img)
            d.text((10, 50), "DHCP Snoop stopped", fill="YELLOW", font=font)
            d.text((10, 66), f"Clients: {len(clients)}", fill="WHITE", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass
        GPIO.cleanup()


if __name__ == "__main__":
    main()
