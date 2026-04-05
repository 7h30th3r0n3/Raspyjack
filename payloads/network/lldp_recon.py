#!/usr/bin/env python3
"""
RaspyJack Payload -- LLDP/CDP Recon
====================================
Author: 7h30th3r0n3

Passive LLDP/CDP listener for infrastructure reconnaissance.
Sniffs LLDP (EtherType 0x88cc) and CDP (multicast 01:00:0c:cc:cc:cc)
frames, parses device name, model, firmware, management IP, VLAN info,
port description, and capabilities.  Builds a neighbor table over time.

Controls:
  OK         -- Start / Stop listening
  UP / DOWN  -- Scroll discovered devices
  RIGHT      -- Show details of selected device
  KEY2       -- Export JSON to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/LLDPRecon/
"""

import os
import sys
import time
import json
import struct
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

try:
    from scapy.all import (
        Ether, Dot3, LLC, SNAP, Raw,
        sniff as scapy_sniff, conf,
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
LOOT_DIR = "/root/Raspyjack/loot/LLDPRecon"
os.makedirs(LOOT_DIR, exist_ok=True)

LLDP_ETHERTYPE = 0x88CC
CDP_SNAP_CODE = 0x2000
ROWS_VISIBLE = 5

# LLDP capability bit names
LLDP_CAPS = {
    0: "Other", 1: "Repeater", 2: "Bridge", 3: "WLAN AP",
    4: "Router", 5: "Telephone", 6: "DOCSIS", 7: "Station",
}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True
listening = False
devices = []         # list of dicts with parsed fields
scroll_pos = 0
selected_idx = 0
view_mode = "list"   # list | detail
status_msg = "Ready"
my_iface = "eth0"
frames_received = 0

_listen_thread = None

# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _get_default_iface():
    """Get the interface with the default route."""
    try:
        import subprocess
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eth0"


# ---------------------------------------------------------------------------
# CDP parser
# ---------------------------------------------------------------------------

def _parse_cdp_frame(payload):
    """Parse CDP TLVs from raw bytes (skip 4-byte CDP header)."""
    info = {"source": "CDP"}
    if len(payload) < 4:
        return info
    data = payload[4:]
    offset = 0
    while offset + 4 <= len(data):
        tlv_type, tlv_len = struct.unpack("!HH", data[offset:offset + 4])
        if tlv_len < 4:
            break
        value = data[offset + 4:offset + tlv_len]
        if tlv_type == 0x0001:
            info["name"] = value.decode("utf-8", errors="replace")
        elif tlv_type == 0x0002:
            # Address TLV
            try:
                if len(value) >= 13:
                    ip_bytes = value[9:13]
                    info["mgmt_ip"] = ".".join(str(b) for b in ip_bytes)
            except Exception:
                pass
        elif tlv_type == 0x0003:
            info["port_desc"] = value.decode("utf-8", errors="replace")
        elif tlv_type == 0x0004:
            # Capabilities
            if len(value) >= 4:
                caps = struct.unpack("!I", value[:4])[0]
                cap_names = []
                if caps & 0x01:
                    cap_names.append("Router")
                if caps & 0x02:
                    cap_names.append("TBridge")
                if caps & 0x04:
                    cap_names.append("SRBridge")
                if caps & 0x08:
                    cap_names.append("Switch")
                if caps & 0x10:
                    cap_names.append("Host")
                if caps & 0x40:
                    cap_names.append("Phone")
                info["capabilities"] = ", ".join(cap_names) if cap_names else "Unknown"
        elif tlv_type == 0x0005:
            info["firmware"] = value.decode("utf-8", errors="replace")[:80]
        elif tlv_type == 0x0006:
            info["model"] = value.decode("utf-8", errors="replace")
        elif tlv_type == 0x000A:
            # Native VLAN
            if len(value) >= 2:
                info["vlan"] = str(struct.unpack("!H", value[:2])[0])
        offset += tlv_len
    return info


# ---------------------------------------------------------------------------
# LLDP parser
# ---------------------------------------------------------------------------

def _parse_lldp_frame(payload):
    """Parse LLDP TLVs from raw bytes."""
    info = {"source": "LLDP"}
    offset = 0
    while offset + 2 <= len(payload):
        header = struct.unpack("!H", payload[offset:offset + 2])[0]
        tlv_type = (header >> 9) & 0x7F
        tlv_len = header & 0x01FF
        offset += 2
        if tlv_type == 0:
            break
        value = payload[offset:offset + tlv_len]

        if tlv_type == 1 and len(value) > 1:
            # Chassis ID
            subtype = value[0]
            if subtype == 4 and len(value) >= 7:
                info["chassis_mac"] = ":".join(f"{b:02x}" for b in value[1:7])
            elif subtype in (5, 6, 7):
                info["chassis_id"] = value[1:].decode("utf-8", errors="replace")
        elif tlv_type == 2 and len(value) > 1:
            # Port ID
            info["port_desc"] = value[1:].decode("utf-8", errors="replace")
        elif tlv_type == 4:
            # Port Description
            info["port_detail"] = value.decode("utf-8", errors="replace")
        elif tlv_type == 5:
            info["name"] = value.decode("utf-8", errors="replace")
        elif tlv_type == 6:
            info["model"] = value.decode("utf-8", errors="replace")[:60]
        elif tlv_type == 7 and len(value) >= 4:
            # System Capabilities
            caps_val = struct.unpack("!H", value[:2])[0]
            cap_names = []
            for bit, name in LLDP_CAPS.items():
                if caps_val & (1 << bit):
                    cap_names.append(name)
            info["capabilities"] = ", ".join(cap_names) if cap_names else "Unknown"
        elif tlv_type == 8 and len(value) >= 6:
            # Management Address
            addr_len = value[0]
            addr_subtype = value[1] if addr_len > 0 else 0
            if addr_subtype == 1 and addr_len >= 5:
                info["mgmt_ip"] = ".".join(str(b) for b in value[2:6])
        elif tlv_type == 127 and len(value) >= 4:
            # Org-specific: IEEE 802.1 VLAN Name
            oui = (value[0] << 16) | (value[1] << 8) | value[2]
            subtype = value[3]
            if oui == 0x0080C2 and subtype == 3 and len(value) >= 7:
                vlan_id = struct.unpack("!H", value[4:6])[0]
                info["vlan"] = str(vlan_id)

        offset += tlv_len
    return info


# ---------------------------------------------------------------------------
# Listener thread
# ---------------------------------------------------------------------------

def _listener_loop():
    """Sniff for LLDP and CDP frames."""
    global frames_received

    def _process_pkt(pkt):
        if not running or not listening:
            return
        nonlocal _self_frames_received
        info = {}

        # CDP: Dot3/LLC/SNAP with code 0x2000
        if pkt.haslayer(LLC) and pkt.haslayer(SNAP):
            snap_layer = pkt.getlayer(SNAP)
            if snap_layer and snap_layer.code == CDP_SNAP_CODE:
                payload = bytes(pkt.getlayer(Raw).load) if pkt.haslayer(Raw) else b""
                if payload:
                    info = _parse_cdp_frame(payload)

        # LLDP: EtherType 0x88cc
        elif pkt.haslayer(Ether) and pkt[Ether].type == LLDP_ETHERTYPE:
            payload = bytes(pkt.getlayer(Raw).load) if pkt.haslayer(Raw) else b""
            if payload:
                info = _parse_lldp_frame(payload)

        if not info or not (info.get("name") or info.get("model")):
            return

        info.setdefault("name", "Unknown")
        info.setdefault("model", "")
        info.setdefault("firmware", "")
        info.setdefault("mgmt_ip", "")
        info.setdefault("vlan", "")
        info.setdefault("port_desc", "")
        info.setdefault("capabilities", "")
        info["last_seen"] = datetime.now().strftime("%H:%M:%S")

        with lock:
            _self_frames_received += 1
            # Update or add
            existing = None
            for d in devices:
                if d.get("name") == info["name"] and d.get("source") == info.get("source"):
                    existing = d
                    break
            if existing is not None:
                idx = devices.index(existing)
                updated = dict(existing)
                updated.update(info)
                devices[idx] = updated
            else:
                devices.append(dict(info))

    _self_frames_received = 0
    try:
        scapy_sniff(
            iface=my_iface,
            filter="ether dst 01:00:0c:cc:cc:cc or ether proto 0x88cc",
            prn=_process_pkt,
            store=False,
            stop_filter=lambda _: not running or not listening,
        )
    except Exception:
        try:
            scapy_sniff(
                iface=my_iface,
                prn=_process_pkt,
                store=False,
                stop_filter=lambda _: not running or not listening,
            )
        except Exception:
            pass
    finally:
        with lock:
            global frames_received
            frames_received += _self_frames_received


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_json():
    """Export device table to loot."""
    with lock:
        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "interface": my_iface,
            "frames_received": frames_received,
            "devices": [dict(d) for d in devices],
        }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"lldp_recon_{ts}.json")
    try:
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        with lock:
            global status_msg
            status_msg = "Exported to loot"
    except Exception as exc:
        with lock:
            status_msg = f"Export err: {str(exc)[:16]}"


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------

def _draw_list_view(draw):
    """Draw the device list view."""
    with lock:
        st = status_msg
        sp = scroll_pos
        si = selected_idx
        dev_list = list(devices)
        listen = listening
        fr = frames_received

    draw.text((2, 2), "LLDP/CDP RECON", fill="CYAN", font=font)
    indicator = "ON" if listen else "OFF"
    ind_color = "GREEN" if listen else "GRAY"
    draw.text((90, 2), indicator, fill=ind_color, font=font)

    draw.text((2, 14), f"Devices:{len(dev_list)} Frames:{fr}", fill="WHITE", font=font)
    draw.text((2, 26), st[:22], fill="GRAY", font=font)

    y = 40
    visible = dev_list[sp:sp + ROWS_VISIBLE]
    for i, d in enumerate(visible):
        real_i = sp + i
        prefix = ">" if real_i == si else " "
        color = "YELLOW" if real_i == si else "WHITE"
        tag = f"[{d.get('source', '?')[0]}]"
        line = f"{prefix}{tag}{d.get('name', '?')[:14]}"
        draw.text((2, y), line, fill=color, font=font)
        y += 14

    if not visible:
        draw.text((2, 50), "Waiting for frames...", fill="GRAY", font=font)

    draw.text((2, 116), "OK:Listen R:Detail K3:Quit", fill="GRAY", font=font)


def _draw_detail_view(draw):
    """Draw detail view for selected device."""
    with lock:
        si = selected_idx
        dev_list = list(devices)

    draw.text((2, 2), "DEVICE DETAIL", fill="CYAN", font=font)

    if 0 <= si < len(dev_list):
        d = dev_list[si]
        y = 16
        fields = [
            ("Name", d.get("name", "")),
            ("Model", d.get("model", "")),
            ("IP", d.get("mgmt_ip", "")),
            ("Port", d.get("port_desc", "")),
            ("VLAN", d.get("vlan", "")),
            ("Caps", d.get("capabilities", "")),
            ("FW", d.get("firmware", "")[:22]),
            ("Seen", d.get("last_seen", "")),
        ]
        for label, val in fields:
            if val:
                text = f"{label}: {val}"
                draw.text((2, y), text[:22], fill="WHITE", font=font)
                y += 12
                if y > 104:
                    break
    else:
        draw.text((2, 40), "No device selected", fill="GRAY", font=font)

    draw.text((2, 116), "LEFT:Back K2:Export", fill="GRAY", font=font)


def _draw_screen():
    """Render current state on LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    draw = ScaledDraw(img)

    with lock:
        vm = view_mode

    if vm == "list":
        _draw_list_view(draw)
    elif vm == "detail":
        _draw_detail_view(draw)

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running, listening, scroll_pos, selected_idx, view_mode
    global status_msg, my_iface, _listen_thread

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
                    listening = not listening
                if listening:
                    with lock:
                        status_msg = "Listening..."
                    _listen_thread = threading.Thread(
                        target=_listener_loop, daemon=True,
                    )
                    _listen_thread.start()
                else:
                    with lock:
                        status_msg = "Stopped"
                time.sleep(0.3)

            elif btn == "UP":
                with lock:
                    if view_mode == "list":
                        if selected_idx > 0:
                            selected_idx -= 1
                        if selected_idx < scroll_pos:
                            scroll_pos = selected_idx

            elif btn == "DOWN":
                with lock:
                    if view_mode == "list":
                        if selected_idx < len(devices) - 1:
                            selected_idx += 1
                        if selected_idx >= scroll_pos + ROWS_VISIBLE:
                            scroll_pos = selected_idx - ROWS_VISIBLE + 1

            elif btn == "RIGHT":
                with lock:
                    if view_mode == "list" and devices:
                        view_mode = "detail"
                time.sleep(0.3)

            elif btn == "LEFT":
                with lock:
                    if view_mode == "detail":
                        view_mode = "list"
                time.sleep(0.3)

            elif btn == "KEY2":
                threading.Thread(target=_export_json, daemon=True).start()
                time.sleep(0.3)

            _draw_screen()
            time.sleep(0.15)

    finally:
        running = False
        listening = False

        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            draw = ScaledDraw(img)
            draw.text((10, 50), "LLDP Recon stopped", fill="YELLOW", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass

        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
