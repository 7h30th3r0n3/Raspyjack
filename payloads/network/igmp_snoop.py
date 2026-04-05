#!/usr/bin/env python3
"""
RaspyJack Payload -- IGMP Snoop
=================================
Author: 7h30th3r0n3

IGMP snooping for multicast group discovery.
Sniffs IGMP Membership Reports to discover active multicast groups
and identify VoIP, streaming, surveillance cameras, IPTV, etc.

Flow:
  1) Sniff IGMP packets (Membership Reports type 0x16/0x22)
  2) Map multicast group addresses to known services
  3) Track which hosts are members of each group
  4) Display groups with labels and member counts

Controls:
  OK        -- Start / stop sniffing
  UP / DOWN -- Scroll group list
  KEY1      -- Show members of selected group
  KEY2      -- Export data
  KEY3      -- Exit

Loot: /root/Raspyjack/loot/IGMPSnoop/

Setup: Passive only — no injection.
"""

import os
import sys
import time
import json
import threading
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
    from scapy.all import sniff, IP, conf
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
LOOT_DIR = "/root/Raspyjack/loot/IGMPSnoop"
os.makedirs(LOOT_DIR, exist_ok=True)
ROWS_VISIBLE = 6

# Known multicast group database
KNOWN_GROUPS = {
    "224.0.0.1": "All Hosts",
    "224.0.0.2": "All Routers",
    "224.0.0.5": "OSPF-All",
    "224.0.0.6": "OSPF-DR",
    "224.0.0.9": "RIPv2",
    "224.0.0.10": "EIGRP",
    "224.0.0.13": "PIMv2",
    "224.0.0.18": "VRRP",
    "224.0.0.22": "IGMPv3",
    "224.0.0.100": "HSRP-v2",
    "224.0.0.102": "HSRP",
    "224.0.0.251": "mDNS",
    "224.0.0.252": "LLMNR",
    "224.0.1.1": "NTP",
    "239.255.255.250": "SSDP/UPnP",
    "239.255.255.253": "SRVLOC",
}

# Group prefix labels
PREFIX_LABELS = [
    ("224.0.1.", "VoIP/Media"),
    ("224.0.2.", "Surveillance"),
    ("239.0.", "Admin-scope"),
    ("239.192.", "Organization"),
    ("239.255.", "Site-local"),
    ("232.", "SSM"),
    ("233.", "GLOP"),
    ("234.", "Unicast-GLOP"),
    ("238.", "Reserved"),
]


def _label_group(addr):
    """Return a human-readable label for a multicast group."""
    if addr in KNOWN_GROUPS:
        return KNOWN_GROUPS[addr]
    for prefix, label in PREFIX_LABELS:
        if addr.startswith(prefix):
            return label
    return "Unknown"


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
groups = defaultdict(set)    # group_addr -> set of member IPs
group_list = []              # sorted list of group addrs for display
scroll_pos = 0
selected_idx = 0
view_mode = "groups"         # groups | members
status_msg = "Ready"
sniff_active = False
app_running = True
total_reports = 0


# ---------------------------------------------------------------------------
# Sniffer
# ---------------------------------------------------------------------------

def _packet_handler(pkt):
    """Process IGMP packets."""
    global total_reports

    if not pkt.haslayer(IP):
        return

    ip_layer = pkt[IP]
    # IGMP is protocol 2
    if ip_layer.proto != 2:
        return

    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    # Parse IGMP from raw payload
    raw = bytes(ip_layer.payload)
    if len(raw) < 8:
        return

    igmp_type = raw[0]

    # Type 0x16 = IGMPv2 Membership Report
    # Type 0x22 = IGMPv3 Membership Report
    if igmp_type == 0x16:
        # IGMPv2: group address at bytes 4-8
        import socket
        group_addr = socket.inet_ntoa(raw[4:8])
        with lock:
            total_reports += 1
            groups[group_addr].add(src_ip)
            _rebuild_group_list()

    elif igmp_type == 0x22:
        # IGMPv3: number of group records at bytes 6-8
        if len(raw) < 12:
            return
        import struct
        num_records = struct.unpack(">H", raw[6:8])[0]
        offset = 8
        for _ in range(num_records):
            if offset + 8 > len(raw):
                break
            rec_type = raw[offset]
            aux_len = raw[offset + 1]
            num_sources = (raw[offset + 2] << 8) | raw[offset + 3]
            import socket
            group_addr = socket.inet_ntoa(raw[offset + 4:offset + 8])
            with lock:
                total_reports += 1
                groups[group_addr].add(src_ip)
            offset += 8 + (num_sources * 4) + (aux_len * 4)

        with lock:
            _rebuild_group_list()

    elif igmp_type == 0x12:
        # IGMPv1 Membership Report
        import socket
        if len(raw) >= 8:
            group_addr = socket.inet_ntoa(raw[4:8])
            with lock:
                total_reports += 1
                groups[group_addr].add(src_ip)
                _rebuild_group_list()


def _rebuild_group_list():
    """Rebuild sorted group list — call under lock."""
    global group_list
    group_list = sorted(groups.keys())


def _sniff_thread():
    """Sniff IGMP traffic."""
    global sniff_active, status_msg
    sniff_active = True
    with lock:
        status_msg = "Sniffing IGMP..."
    try:
        sniff(
            filter="igmp",
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
            "total_reports": total_reports,
            "groups": {
                addr: {
                    "label": _label_group(addr),
                    "members": sorted(members),
                    "member_count": len(members),
                }
                for addr, members in groups.items()
            },
        }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"igmp_{ts}.json")
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
    draw.text((2, 2), "IGMP SNOOP", fill="CYAN", font=font)

    with lock:
        st = status_msg
        gl = list(group_list)
        sp = scroll_pos
        si = selected_idx
        tr = total_reports
        vm = view_mode
        grps = dict(groups)

    draw.text((80, 2), f"R:{tr}", fill="YELLOW", font=font)
    draw.text((2, 14), st[:22], fill="WHITE", font=font)

    if vm == "groups":
        y = 28
        for i, addr in enumerate(gl[sp:sp + ROWS_VISIBLE]):
            real_i = sp + i
            prefix = ">" if real_i == si else " "
            color = "YELLOW" if real_i == si else "WHITE"
            label = _label_group(addr)
            members = grps.get(addr, set())
            line = f"{prefix}{addr.split('.')[-1]:>3} {label[:8]} ({len(members)})"
            draw.text((2, y), line[:22], fill=color, font=font)
            y += 14

        if not gl:
            draw.text((2, 56), "No groups seen", fill="GRAY", font=font)
        draw.text((2, 116), "OK=go K1=mbrs K3=exit", fill="GRAY", font=font)

    elif vm == "members":
        sel_addr = gl[si] if 0 <= si < len(gl) else ""
        draw.text((2, 28), f"Group: {sel_addr}", fill="YELLOW", font=font)
        draw.text((2, 42), f"Label: {_label_group(sel_addr)}", fill="CYAN", font=font)
        members = sorted(grps.get(sel_addr, set()))
        y = 56
        for m in members[sp:sp + 4]:
            draw.text((2, y), m[:22], fill="WHITE", font=font)
            y += 14
        if not members:
            draw.text((2, 56), "No members", fill="GRAY", font=font)
        draw.text((2, 116), "OK=back UP/DN=scroll", fill="GRAY", font=font)

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global app_running, sniff_active, scroll_pos, selected_idx
    global view_mode, status_msg

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
                with lock:
                    vm = view_mode
                if vm == "members":
                    with lock:
                        view_mode = "groups"
                        scroll_pos = 0
                elif not sniff_active:
                    sniff_active = True
                    threading.Thread(target=_sniff_thread, daemon=True).start()
                else:
                    sniff_active = False
                    with lock:
                        status_msg = "Stopped"

            elif btn == "UP":
                with lock:
                    if view_mode == "groups":
                        if selected_idx > 0:
                            selected_idx -= 1
                        if selected_idx < scroll_pos:
                            scroll_pos = selected_idx
                    else:
                        if scroll_pos > 0:
                            scroll_pos -= 1

            elif btn == "DOWN":
                with lock:
                    if view_mode == "groups":
                        if selected_idx < len(group_list) - 1:
                            selected_idx += 1
                        if selected_idx >= scroll_pos + ROWS_VISIBLE:
                            scroll_pos = selected_idx - ROWS_VISIBLE + 1
                    else:
                        scroll_pos += 1

            elif btn == "KEY1":
                with lock:
                    if view_mode == "groups" and 0 <= selected_idx < len(group_list):
                        view_mode = "members"
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
            d.text((10, 50), "IGMP Snoop stopped", fill="YELLOW", font=font)
            d.text((10, 66), f"Groups: {len(group_list)}", fill="WHITE", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass
        GPIO.cleanup()


if __name__ == "__main__":
    main()
