#!/usr/bin/env python3
"""
RaspyJack Payload -- WiFi Recon Survey Dashboard
=================================================
Author: 7h30th3r0n3

Live WiFi reconnaissance dashboard inspired by PineAP Recon.  Hops
channels on a USB monitor-mode dongle, captures beacons, probe
requests and data frames, and builds a real-time database of access
points and clients.

Setup / Prerequisites
---------------------
- USB WiFi dongle with monitor mode support
- pip install scapy

Controls
--------
  LEFT / RIGHT  -- Switch view (APs / Clients / Channels)
  UP / DOWN     -- Scroll list
  OK            -- Start / stop survey
  KEY1          -- Toggle sort (signal / clients / channel)
  KEY2          -- Export JSON to loot
  KEY3          -- Exit

Loot: /root/Raspyjack/loot/WiFiSurvey/
"""

import os
import sys
import time
import json
import threading
import subprocess
import copy
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
        Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp,
        RadioTap, sniff as scapy_sniff, conf,
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
LOOT_DIR = "/root/Raspyjack/loot/WiFiSurvey"
CHANNELS_24 = list(range(1, 14))
ROWS_VISIBLE = 7
ROW_H = 12
VIEWS = ["APs", "Clients", "Channels"]
SORT_MODES = ["signal", "clients", "channel"]

# ── Shared state ─────────────────────────────────────────────────────────────
lock = threading.Lock()
ap_db = {}           # bssid -> {ssid, bssid, channel, enc, signal, clients: set(), last_seen}
client_db = {}       # mac -> {mac, ap_bssid, probed: set(), last_seen}
channel_usage = defaultdict(int)   # channel -> frame count
surveying = False
mon_iface = None
view_idx = 0
sort_idx = 0
scroll_pos = 0
status_msg = "Idle"
_running = True


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


# ── Encryption parser ───────────────────────────────────────────────────────

def _parse_encryption(pkt):
    """Extract encryption type from a beacon frame."""
    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").lower()
    if "privacy" not in cap:
        return "OPEN"
    crypto = set()
    elt = pkt[Dot11Elt]
    while elt:
        if elt.ID == 48:
            crypto.add("WPA2")
        elif elt.ID == 221 and elt.info and elt.info.startswith(b"\x00\x50\xf2\x01"):
            crypto.add("WPA")
        elt = elt.payload if hasattr(elt, "payload") and isinstance(elt.payload, Dot11Elt) else None
    if not crypto:
        return "WEP"
    return "/".join(sorted(crypto))


# ── Packet handler ──────────────────────────────────────────────────────────

def _pkt_handler(pkt):
    if not pkt.haslayer(Dot11):
        return

    now_str = datetime.now().strftime("%H:%M:%S")

    # Beacon / Probe response  -> AP info
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        bssid = (pkt[Dot11].addr2 or "").upper()
        if not bssid or bssid == "FF:FF:FF:FF:FF:FF":
            return
        ssid = ""
        elt = pkt[Dot11Elt]
        if elt and elt.ID == 0:
            try:
                ssid = elt.info.decode("utf-8", errors="replace")
            except Exception:
                pass
        channel = 0
        e = pkt[Dot11Elt]
        while e:
            if e.ID == 3 and e.info:
                channel = e.info[0]
                break
            e = e.payload if hasattr(e, "payload") and isinstance(e.payload, Dot11Elt) else None

        signal = -100
        if pkt.haslayer(RadioTap):
            try:
                signal = pkt[RadioTap].dBm_AntSignal
            except Exception:
                pass

        enc = "?"
        if pkt.haslayer(Dot11Beacon):
            enc = _parse_encryption(pkt)

        with lock:
            if bssid not in ap_db:
                ap_db[bssid] = {
                    "ssid": ssid, "bssid": bssid, "channel": channel,
                    "enc": enc, "signal": signal, "clients": set(),
                    "last_seen": now_str,
                }
            else:
                entry = ap_db[bssid]
                ap_db[bssid] = {
                    **entry,
                    "ssid": ssid or entry["ssid"],
                    "channel": channel or entry["channel"],
                    "signal": signal if signal > -100 else entry["signal"],
                    "enc": enc if enc != "?" else entry["enc"],
                    "last_seen": now_str,
                }
            if channel:
                channel_usage[channel] += 1

    # Probe request -> client info
    if pkt.haslayer(Dot11ProbeReq):
        src = (pkt[Dot11].addr2 or "").upper()
        if not src or src == "FF:FF:FF:FF:FF:FF":
            return
        ssid = ""
        elt = pkt[Dot11Elt]
        if elt and elt.ID == 0 and elt.info:
            try:
                ssid = elt.info.decode("utf-8", errors="replace")
            except Exception:
                pass
        with lock:
            if src not in client_db:
                client_db[src] = {"mac": src, "ap_bssid": "", "probed": set(), "last_seen": now_str}
            else:
                client_db[src] = {**client_db[src], "last_seen": now_str}
            if ssid:
                client_db[src]["probed"] = client_db[src]["probed"] | {ssid}

    # Data frames -> client-AP association
    frame_type = pkt[Dot11].type
    if frame_type == 2:  # Data
        addr1 = (pkt[Dot11].addr1 or "").upper()
        addr2 = (pkt[Dot11].addr2 or "").upper()
        ds = pkt[Dot11].FCfield & 0x3
        ap_mac = None
        client_mac = None
        if ds == 1:    # To-DS
            ap_mac, client_mac = addr1, addr2
        elif ds == 2:  # From-DS
            ap_mac, client_mac = addr2, addr1

        if ap_mac and client_mac and client_mac != "FF:FF:FF:FF:FF:FF":
            with lock:
                if ap_mac in ap_db:
                    ap_db[ap_mac]["clients"] = ap_db[ap_mac]["clients"] | {client_mac}
                if client_mac not in client_db:
                    client_db[client_mac] = {
                        "mac": client_mac, "ap_bssid": ap_mac,
                        "probed": set(), "last_seen": now_str,
                    }
                else:
                    client_db[client_mac] = {**client_db[client_mac], "ap_bssid": ap_mac, "last_seen": now_str}


# ── Channel hopping ─────────────────────────────────────────────────────────

def _channel_hop():
    idx = 0
    while True:
        with lock:
            if not surveying:
                break
            iface = mon_iface
        if not iface:
            break
        _set_channel(iface, CHANNELS_24[idx])
        idx = (idx + 1) % len(CHANNELS_24)
        time.sleep(0.25)


def _sniff_thread():
    with lock:
        iface = mon_iface
    if not iface:
        return
    try:
        scapy_sniff(
            iface=iface, prn=_pkt_handler, store=False,
            stop_filter=lambda _: not surveying,
        )
    except Exception:
        pass


# ── Start / stop ─────────────────────────────────────────────────────────────

def _start_survey():
    global surveying, mon_iface, status_msg
    ext = _find_external_wifi()
    if not ext:
        with lock:
            status_msg = "No USB WiFi found"
        return
    if not SCAPY_OK:
        with lock:
            status_msg = "scapy not installed"
        return
    iface = _enable_monitor(ext)
    with lock:
        mon_iface = iface
        surveying = True
        status_msg = f"Survey on {iface}"
    threading.Thread(target=_channel_hop, daemon=True).start()
    threading.Thread(target=_sniff_thread, daemon=True).start()


def _stop_survey():
    global surveying, status_msg
    with lock:
        surveying = False
        iface = mon_iface
        status_msg = "Stopped"
    time.sleep(0.5)
    if iface:
        _disable_monitor(iface)


# ── Export ───────────────────────────────────────────────────────────────────

def _export_json():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"survey_{ts}.json")
    with lock:
        aps = []
        for v in ap_db.values():
            aps.append({**v, "clients": list(v["clients"])})
        cls = []
        for v in client_db.values():
            cls.append({**v, "probed": list(v["probed"])})
        ch = dict(channel_usage)
    data = {"timestamp": ts, "access_points": aps, "clients": cls, "channel_usage": ch}
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


# ── Sorted lists ─────────────────────────────────────────────────────────────

def _sorted_aps():
    with lock:
        items = list(ap_db.values())
        mode = SORT_MODES[sort_idx]
    if mode == "signal":
        items.sort(key=lambda a: a["signal"], reverse=True)
    elif mode == "clients":
        items.sort(key=lambda a: len(a["clients"]), reverse=True)
    elif mode == "channel":
        items.sort(key=lambda a: a["channel"])
    return items


def _sorted_clients():
    with lock:
        items = list(client_db.values())
    items.sort(key=lambda c: c["last_seen"], reverse=True)
    return items


# ── Drawing ──────────────────────────────────────────────────────────────────

def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        active = surveying
        view = VIEWS[view_idx]
        smode = SORT_MODES[sort_idx]
        msg = status_msg
        sp = scroll_pos
        n_aps = len(ap_db)
        n_cls = len(client_db)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), f"Survey: {view}", font=font, fill="#00CCFF")
    color = "#00FF00" if active else "#FF0000"
    d.ellipse((118, 3, 126, 11), fill=color)

    y = 15
    d.text((2, y), f"APs:{n_aps} Cls:{n_cls} [{msg[:10]}]", font=font, fill="#888")
    y += 13

    if view == "APs":
        aps = _sorted_aps()
        end = min(sp + ROWS_VISIBLE, len(aps))
        for i in range(sp, end):
            ap = aps[i]
            ssid = (ap["ssid"] or "?")[:9]
            ch = ap["channel"]
            sig = ap["signal"]
            nc = len(ap["clients"])
            txt = f"{ssid} c{ch} {sig}dB {nc}c"
            d.text((2, y), txt[:22], font=font, fill="#CCCCCC")
            y += ROW_H
        if not aps:
            d.text((2, y), "No APs yet", font=font, fill="#555")

    elif view == "Clients":
        cls = _sorted_clients()
        end = min(sp + ROWS_VISIBLE, len(cls))
        for i in range(sp, end):
            c = cls[i]
            mac_short = c["mac"][-8:]
            ap = c["ap_bssid"][-8:] if c["ap_bssid"] else "none"
            probes = len(c["probed"])
            txt = f"{mac_short} -> {ap} P:{probes}"
            d.text((2, y), txt[:22], font=font, fill="#CCCCCC")
            y += ROW_H
        if not cls:
            d.text((2, y), "No clients yet", font=font, fill="#555")

    elif view == "Channels":
        with lock:
            ch_data = dict(channel_usage)
        if ch_data:
            max_val = max(ch_data.values()) or 1
            bar_w = 8
            for ch in CHANNELS_24:
                cnt = ch_data.get(ch, 0)
                bar_h = int((cnt / max_val) * 60) if max_val else 0
                x = 2 + (ch - 1) * (bar_w + 1)
                d.rectangle((x, 100 - bar_h, x + bar_w - 1, 100), fill="#00CCFF")
                d.text((x, 102), str(ch), font=font, fill="#888")
        else:
            d.text((2, y), "No channel data", font=font, fill="#555")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    lbl = "OK:Stop" if active else "OK:Go"
    d.text((2, 117), f"{lbl} K1:Sort K3:X", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    global view_idx, sort_idx, scroll_pos, status_msg

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 10), "WiFi SURVEY", font=font, fill="#00CCFF")
    d.text((4, 28), "PineAP-style recon", font=font, fill="#888")
    d.text((4, 44), "dashboard.", font=font, fill="#888")
    d.text((4, 64), "OK=Start L/R=View", font=font, fill="#666")
    d.text((4, 76), "K1=Sort  K2=Export", font=font, fill="#666")
    d.text((4, 88), "K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            if btn == "OK":
                with lock:
                    active = surveying
                if active:
                    _stop_survey()
                else:
                    _start_survey()
                time.sleep(0.3)

            elif btn == "LEFT":
                with lock:
                    view_idx = (view_idx - 1) % len(VIEWS)
                    scroll_pos = 0
                time.sleep(0.25)

            elif btn == "RIGHT":
                with lock:
                    view_idx = (view_idx + 1) % len(VIEWS)
                    scroll_pos = 0
                time.sleep(0.25)

            elif btn == "UP":
                with lock:
                    scroll_pos = max(0, scroll_pos - 1)
                time.sleep(0.2)

            elif btn == "DOWN":
                with lock:
                    scroll_pos += 1
                time.sleep(0.2)

            elif btn == "KEY1":
                with lock:
                    sort_idx = (sort_idx + 1) % len(SORT_MODES)
                    status_msg = f"Sort: {SORT_MODES[sort_idx]}"
                time.sleep(0.25)

            elif btn == "KEY2":
                path = _export_json()
                with lock:
                    status_msg = "Exported"
                time.sleep(0.3)

            _draw_screen()
            time.sleep(0.05)

    finally:
        _stop_survey()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
