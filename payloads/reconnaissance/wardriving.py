#!/usr/bin/env python3
"""
RaspyJack Payload -- Wardriving
================================
Author: 7h30th3r0n3 / dag nazty

Professional wardriving scanner with multi-card support,
GPS tracking, and Wigle-compatible export.

Views (cycle with KEY1):
  LIVE       Real-time AP discovery with signal bars
  GPS        Coordinates, speed, satellites, movement
  STATS      Security distribution, channel heatmap
  NETWORKS   Scrollable list of discovered APs
  EXPORT     Export status, file counts

Controls:
  OK         Start / Stop scan
  KEY1       Cycle views
  KEY2       Export data now
  KEY3       Exit (hold 2s)
  UP/DOWN    Scroll (in NETWORKS view)
  LEFT/RIGHT Change sort (NETWORKS view)

Exports: Wigle CSV, JSON, KML
Loot: /root/Raspyjack/loot/wardriving/
"""

import os
import sys
import time
import json
import csv
import sqlite3
import signal
import threading
import subprocess
from datetime import datetime
from collections import Counter

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._iface_helper import list_interfaces

try:
    from scapy.all import (
        Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, Dot11ProbeReq,
        RadioTap, sniff as scapy_sniff, conf,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

try:
    import gpsd as gpsd_mod
    GPSD_OK = True
except ImportError:
    GPSD_OK = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT

LOOT_DIR = "/root/Raspyjack/loot/wardriving"
DB_PATH = os.path.join(LOOT_DIR, "networks.db")

CHANNELS_24 = list(range(1, 14))
CHANNELS_5 = [36, 40, 44, 48, 52, 56, 60, 64,
              100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
              149, 153, 157, 161, 165]
DWELL_24 = 0.3       # 300ms like Kismet (was 800ms)
DWELL_5 = 0.4        # slightly longer for DFS channels

VIEWS = ["live", "gps", "channels", "stats", "networks", "export"]
AUTOSAVE_INTERVAL = 20   # auto-save Wigle CSV every 20 seconds

# Known monitor drivers (from _iface_helper)
KNOWN_MONITOR_DRIVERS = {
    "rtl88XXau", "rtl8812au", "rtl8821au", "rtl88x2bu",
    "rtl8188eus", "rtl8187", "rt2800usb", "ath9k_htc",
    "mt76x2u", "mt76x0u", "mt7921u", "rtl8814au",
}

# OUI vendor lookup (top entries)
OUI_DB = {
    "00:1A:2B": "Ayecom", "00:50:F2": "Microsoft", "00:0C:29": "VMware",
    "00:1E:58": "D-Link", "00:14:6C": "Netgear", "00:1B:11": "D-Link",
    "00:24:D7": "Intel", "00:26:5A": "D-Link", "3C:37:86": "Netgear",
    "F8:E4:FB": "Apple", "D8:6C:63": "Apple", "AC:BC:32": "Apple",
    "B0:BE:76": "TP-Link", "50:C7:BF": "TP-Link", "C0:25:E9": "TP-Link",
    "E4:F0:42": "Google", "94:B8:6D": "Google", "00:1F:33": "Netgear",
    "20:CF:30": "ASUSTek", "04:D4:C4": "ASUSTek", "2C:FD:A1": "Intel",
    "DC:A6:32": "Raspberry", "B8:27:EB": "Raspberry",
    "00:23:69": "Cisco", "00:1A:A0": "Dell", "F0:9F:C2": "Ubiquiti",
    "18:E8:29": "Samsung", "00:26:B0": "Apple", "C8:69:CD": "Apple",
    "F4:F5:D8": "Google", "7C:2F:80": "Huawei", "88:71:B1": "Huawei",
    "FC:F5:28": "ZyXEL", "34:31:C4": "AVM/Fritz",
    "A4:91:B1": "Actiontec", "CC:2D:E0": "Routerboard",
    "E0:63:DA": "Ubiquiti", "24:A4:3C": "Ubiquiti",
    "44:D9:E7": "Ubiquiti", "78:8A:20": "Ubiquiti",
    "28:80:23": "SFR", "E8:F7:24": "SFR",
    "14:0C:76": "Freebox", "F4:CA:E5": "Freebox",
    "00:07:CB": "Freebox", "00:24:D4": "Freebox",
    "5C:A6:E6": "Bouygues", "34:8A:AE": "Bouygues",
    "68:A3:78": "Freebox", "24:95:04": "SFR",
    "A4:3E:51": "Orange/Livebox", "E4:5D:51": "Orange/Livebox",
    "84:A1:D1": "Orange/Livebox", "30:23:03": "Belkin",
}

# ---------------------------------------------------------------------------
# Thread-safe state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_shutdown = threading.Event()
_scanning = threading.Event()

# Scan data
networks = {}          # bssid -> {ssid, channel, signal, security, ...}
probes = {}            # client_mac -> {ssids: set, count, last_seen, signal}
gps_data = None        # {lat, lon, alt, speed, sats, mode, ts}
gps_ready = False
current_channel = 0
scan_start_time = 0
total_beacons = 0
total_probes = 0

# Interfaces
mon_ifaces = []        # list of active monitor interfaces
dual_mode = False

# UI
view_idx = 0
scroll = 0
sort_mode = 0          # 0=signal, 1=name, 2=security


def _cleanup_signal(*_):
    _shutdown.set()
    _scanning.clear()


signal.signal(signal.SIGINT, _cleanup_signal)
signal.signal(signal.SIGTERM, _cleanup_signal)


# ---------------------------------------------------------------------------
# GPS
# ---------------------------------------------------------------------------


def _detect_gps_device():
    """Auto-detect GPS device path."""
    for dev in ["/dev/ttyACM0", "/dev/ttyACM1", "/dev/ttyUSB0",
                "/dev/ttyUSB1", "/dev/ttyAMA0"]:
        if os.path.exists(dev):
            return dev
    return None


def _start_gpsd():
    """Start gpsd daemon if not running."""
    try:
        r = subprocess.run(["pgrep", "-x", "gpsd"], capture_output=True)
        if r.returncode == 0:
            return True  # already running

        dev = _detect_gps_device()
        if not dev:
            return False

        subprocess.run(["sudo", "killall", "gpsd"], capture_output=True)
        time.sleep(0.5)
        subprocess.Popen(
            ["sudo", "gpsd", "-n", dev],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(2)
        return True
    except Exception:
        return False


def _gps_updater():
    """Background thread: poll gpsd for position updates."""
    global gps_data, gps_ready

    if not GPSD_OK:
        return

    _start_gpsd()

    try:
        gpsd_mod.connect()
    except Exception:
        return

    gps_ready = True

    while not _shutdown.is_set():
        try:
            pkt = gpsd_mod.get_current()
            if hasattr(pkt, 'mode') and pkt.mode >= 2:
                with lock:
                    gps_data = {
                        "lat": pkt.lat,
                        "lon": pkt.lon,
                        "alt": pkt.alt if pkt.mode >= 3 else 0,
                        "speed": getattr(pkt, 'hspeed', 0),
                        "sats": getattr(pkt, 'sats', 0),
                        "mode": pkt.mode,
                        "ts": time.time(),
                    }
        except Exception:
            pass

        if _shutdown.wait(timeout=1):
            break


# ---------------------------------------------------------------------------
# Monitor mode
# ---------------------------------------------------------------------------


def _get_driver(iface):
    try:
        return os.path.basename(
            os.path.realpath(f"/sys/class/net/{iface}/device/driver"))
    except Exception:
        return ""


def _is_onboard(iface):
    drv = _get_driver(iface)
    if drv == "brcmfmac":
        return True
    try:
        devpath = os.path.realpath(f"/sys/class/net/{iface}/device")
        return "mmc" in devpath
    except Exception:
        return False


def _find_monitor_interfaces():
    """Find all monitor-capable USB WiFi interfaces."""
    result = []
    ifaces = list_interfaces("wifi")
    for i in ifaces:
        if i.get("is_onboard"):
            continue
        if i.get("supports_monitor") or _get_driver(i["name"]) in KNOWN_MONITOR_DRIVERS:
            result.append(i["name"])
    return result


def _monitor_up(iface):
    """Enable monitor mode on interface."""
    for cmd in [
        ["sudo", "ip", "link", "set", iface, "down"],
        ["sudo", "iw", iface, "set", "monitor", "none"],
        ["sudo", "ip", "link", "set", iface, "up"],
    ]:
        subprocess.run(cmd, capture_output=True, timeout=5)
    time.sleep(0.3)

    r = subprocess.run(["iw", "dev", iface, "info"],
                       capture_output=True, text=True, timeout=5)
    if "type monitor" in r.stdout:
        return iface

    # Fallback: airmon-ng
    subprocess.run(["sudo", "airmon-ng", "start", iface],
                   capture_output=True, timeout=15)
    for name in (f"{iface}mon", iface):
        r = subprocess.run(["iw", "dev", name, "info"],
                           capture_output=True, text=True, timeout=5)
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
# Security detection
# ---------------------------------------------------------------------------


def _parse_security(pkt):
    """Parse security type from beacon frame."""
    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").strip()
    privacy = "privacy" in cap.lower() if cap else False

    security = "Open"
    cipher = ""
    auth = ""
    wps = False

    try:
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            # RSN IE (WPA2/WPA3)
            if elt.ID == 48 and elt.info and len(elt.info) >= 8:
                raw = bytes(elt.info)
                # AKM suite
                if len(raw) >= 14:
                    akm_count = int.from_bytes(raw[8:10], "little")
                    for i in range(akm_count):
                        off = 10 + i * 4
                        if off + 4 <= len(raw):
                            akm_type = raw[off + 3]
                            if akm_type == 8:
                                security = "WPA3-SAE"
                                auth = "SAE"
                            elif akm_type == 2:
                                if security != "WPA3-SAE":
                                    security = "WPA2-PSK"
                                    auth = "PSK"
                            elif akm_type == 1:
                                security = "WPA2-EAP"
                                auth = "Enterprise"
                # Cipher
                if len(raw) >= 8:
                    cs = raw[5]
                    cipher = "CCMP" if cs == 4 else "TKIP" if cs == 2 else "AES"

                if security == "Open":
                    security = "WPA2"

            # WPA IE (vendor specific)
            if elt.ID == 221 and elt.info and len(elt.info) >= 8:
                raw = bytes(elt.info)
                if raw[:3] == b'\x00\x50\xf2' and raw[3] == 1:
                    if security == "Open":
                        security = "WPA"
                        cipher = "TKIP"
                        auth = "PSK"

            # WPS
            if elt.ID == 221 and elt.info:
                raw = bytes(elt.info)
                if raw[:4] == b'\x00\x50\xf2\x04':
                    wps = True

            elt = elt.payload.getlayer(Dot11Elt)
    except Exception:
        pass

    if privacy and security == "Open":
        security = "WEP"

    return {"security": security, "cipher": cipher, "auth": auth, "wps": wps}


def _get_vendor(mac):
    """OUI vendor lookup."""
    prefix = mac[:8].upper()
    return OUI_DB.get(prefix, "")


# ---------------------------------------------------------------------------
# Packet handler
# ---------------------------------------------------------------------------


def _packet_handler(pkt):
    global total_beacons, total_probes

    if not pkt.haslayer(Dot11):
        return

    # --- Probe Requests: track client devices ---
    if pkt.haslayer(Dot11ProbeReq):
        try:
            client_mac = (pkt[Dot11].addr2 or "").upper()
            if not client_mac or client_mac == "FF:FF:FF:FF:FF:FF":
                return
            try:
                probe_ssid = pkt[Dot11Elt].info.decode("utf-8", errors="replace")
            except Exception:
                probe_ssid = ""

            sig = getattr(pkt, "dBm_AntSignal", -99)
            now = datetime.now().isoformat()

            with lock:
                total_probes += 1
                if client_mac not in probes:
                    probes[client_mac] = {
                        "ssids": set(),
                        "count": 0,
                        "last_seen": now,
                        "signal": sig,
                    }
                p = probes[client_mac]
                p["count"] += 1
                p["last_seen"] = now
                if probe_ssid:
                    p["ssids"].add(probe_ssid)
                # Signal averaging (rolling)
                p["signal"] = (p["signal"] * 0.7) + (sig * 0.3)
        except Exception:
            pass
        return

    # --- Beacons / Probe Responses: discover APs ---
    if not pkt.haslayer(Dot11Beacon) and not pkt.haslayer(Dot11ProbeResp):
        return

    try:
        bssid = (pkt[Dot11].addr2 or "").upper()
        if not bssid or bssid == "FF:FF:FF:FF:FF:FF":
            return

        # SSID
        try:
            ssid = pkt[Dot11Elt].info.decode("utf-8", errors="replace")
        except Exception:
            ssid = ""
        if not ssid:
            ssid = "<hidden>"

        # Signal
        sig = getattr(pkt, "dBm_AntSignal", -99)

        # Channel from DS Parameter Set IE
        channel = 0
        try:
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 3 and elt.info:
                    channel = elt.info[0]
                    break
                elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            pass
        if channel == 0:
            channel = current_channel

        # Security
        sec = _parse_security(pkt)

        # Vendor
        vendor = _get_vendor(bssid)

        now = datetime.now().isoformat()

        with lock:
            total_beacons += 1
            gps_snap = dict(gps_data) if gps_data else None

            if bssid not in networks:
                networks[bssid] = {
                    "ssid": ssid,
                    "bssid": bssid,
                    "channel": channel,
                    "signal": sig,
                    "_sig_sum": sig,
                    "_sig_count": 1,
                    "security": sec["security"],
                    "cipher": sec["cipher"],
                    "auth": sec["auth"],
                    "wps": sec["wps"],
                    "vendor": vendor,
                    "first_seen": now,
                    "last_seen": now,
                    "gps": gps_snap,
                    "beacon_count": 1,
                }
            else:
                net = networks[bssid]
                net["last_seen"] = now
                net["beacon_count"] += 1
                # Signal averaging (rolling average)
                net["_sig_sum"] += sig
                net["_sig_count"] += 1
                net["signal"] = int(net["_sig_sum"] / net["_sig_count"])
                # Update best GPS (prefer strongest signal position)
                if gps_snap:
                    if not net["gps"] or sig > net["signal"]:
                        net["gps"] = gps_snap
                if ssid != "<hidden>" and net["ssid"] == "<hidden>":
                    net["ssid"] = ssid

    except Exception:
        pass


# ---------------------------------------------------------------------------
# Channel hoppers
# ---------------------------------------------------------------------------


def _channel_hopper_24(iface):
    """Hop 2.4GHz channels on iface."""
    while not _shutdown.is_set() and _scanning.is_set():
        for ch in CHANNELS_24:
            if _shutdown.is_set() or not _scanning.is_set():
                return
            global current_channel
            subprocess.run(
                ["sudo", "iw", "dev", iface, "set", "channel", str(ch)],
                capture_output=True, timeout=3,
            )
            with lock:
                current_channel = ch
            if _shutdown.wait(timeout=DWELL_24):
                return


def _channel_hopper_5(iface):
    """Hop 5GHz channels on iface."""
    while not _shutdown.is_set() and _scanning.is_set():
        for ch in CHANNELS_5:
            if _shutdown.is_set() or not _scanning.is_set():
                return
            r = subprocess.run(
                ["sudo", "iw", "dev", iface, "set", "channel", str(ch)],
                capture_output=True, timeout=3,
            )
            if r.returncode != 0:
                continue
            if _shutdown.wait(timeout=DWELL_5):
                return


def _channel_hopper_all(iface):
    """Hop all channels on single iface."""
    while not _shutdown.is_set() and _scanning.is_set():
        for ch in CHANNELS_24:
            if _shutdown.is_set() or not _scanning.is_set():
                return
            global current_channel
            subprocess.run(
                ["sudo", "iw", "dev", iface, "set", "channel", str(ch)],
                capture_output=True, timeout=3,
            )
            with lock:
                current_channel = ch
            if _shutdown.wait(timeout=DWELL_24):
                return
        for ch in CHANNELS_5:
            if _shutdown.is_set() or not _scanning.is_set():
                return
            subprocess.run(
                ["sudo", "iw", "dev", iface, "set", "channel", str(ch)],
                capture_output=True, timeout=3,
            )
            if _shutdown.wait(timeout=DWELL_5):
                return


def _channel_hopper_split(iface, channels):
    """Hop a specific set of channels on iface (for N-card split)."""
    while not _shutdown.is_set() and _scanning.is_set():
        for ch in channels:
            if _shutdown.is_set() or not _scanning.is_set():
                return
            global current_channel
            r = subprocess.run(
                ["sudo", "iw", "dev", iface, "set", "channel", str(ch)],
                capture_output=True, timeout=3,
            )
            if r.returncode != 0:
                continue
            with lock:
                current_channel = ch
            dwell = DWELL_5 if ch > 14 else DWELL_24
            if _shutdown.wait(timeout=dwell):
                return


def _sniffer(iface):
    """Sniff on monitor interface."""
    try:
        scapy_sniff(
            iface=iface,
            prn=_packet_handler,
            stop_filter=lambda _: _shutdown.is_set() or not _scanning.is_set(),
            store=0,
        )
    except Exception:
        pass


def _iw_scanner(iface):
    """Bulk AP discovery via 'iw dev scan' in managed mode.

    Runs alongside monitor mode sniffing. The firmware handles channel
    scanning internally (faster than hopping), catching APs with slow
    beacon intervals that the monitor sniffer might miss.
    """
    while not _shutdown.is_set() and _scanning.is_set():
        try:
            r = subprocess.run(
                ["sudo", "iw", "dev", iface, "scan", "-u"],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode != 0:
                # Interface might be in monitor mode or busy
                if _shutdown.wait(timeout=10):
                    break
                continue

            _parse_iw_scan(r.stdout)
        except Exception:
            pass

        # Wait 10s between scans
        if _shutdown.wait(timeout=10):
            break


def _parse_iw_scan(output):
    """Parse 'iw dev scan' output and merge into networks dict."""
    global total_beacons

    bssid = None
    ssid = ""
    channel = 0
    signal = -99
    security = "Open"
    cipher = ""
    wps = False

    now = datetime.now().isoformat()

    for line in output.splitlines():
        line = line.strip()

        if line.startswith("BSS "):
            # Save previous AP
            if bssid:
                _merge_iw_network(bssid, ssid, channel, signal, security,
                                  cipher, wps, now)
            # New AP
            parts = line.split()
            bssid = parts[1].split("(")[0].upper() if len(parts) > 1 else None
            ssid = ""
            channel = 0
            signal = -99
            security = "Open"
            cipher = ""
            wps = False

        elif line.startswith("SSID:"):
            ssid = line[5:].strip()
        elif line.startswith("signal:"):
            try:
                signal = int(float(line.split(":")[1].strip().split()[0]))
            except Exception:
                pass
        elif line.startswith("DS Parameter set: channel"):
            try:
                channel = int(line.split("channel")[1].strip())
            except Exception:
                pass
        elif line.startswith("* primary channel:"):
            try:
                channel = int(line.split(":")[1].strip())
            except Exception:
                pass
        elif "WPA:" in line:
            if security == "Open":
                security = "WPA"
        elif "RSN:" in line:
            security = "WPA2-PSK"
        elif "SAE" in line:
            security = "WPA3-SAE"
        elif "CCMP" in line:
            cipher = "CCMP"
        elif "TKIP" in line and not cipher:
            cipher = "TKIP"
        elif "WPS" in line:
            wps = True
        elif "Privacy" in line or "privacy" in line:
            if security == "Open":
                security = "WEP"

    # Save last AP
    if bssid:
        _merge_iw_network(bssid, ssid, channel, signal, security,
                          cipher, wps, now)


def _merge_iw_network(bssid, ssid, channel, signal, security,
                       cipher, wps, now):
    """Merge iw scan result into networks dict."""
    global total_beacons
    if not bssid or bssid == "FF:FF:FF:FF:FF:FF":
        return
    if not ssid:
        ssid = "<hidden>"

    vendor = _get_vendor(bssid)

    with lock:
        total_beacons += 1
        gps_snap = dict(gps_data) if gps_data else None

        if bssid not in networks:
            networks[bssid] = {
                "ssid": ssid,
                "bssid": bssid,
                "channel": channel,
                "signal": signal,
                "_sig_sum": signal,
                "_sig_count": 1,
                "security": security,
                "cipher": cipher,
                "auth": "",
                "wps": wps,
                "vendor": vendor,
                "first_seen": now,
                "last_seen": now,
                "gps": gps_snap,
                "beacon_count": 1,
            }
        else:
            net = networks[bssid]
            net["last_seen"] = now
            net["beacon_count"] += 1
            net["_sig_sum"] += signal
            net["_sig_count"] += 1
            net["signal"] = int(net["_sig_sum"] / net["_sig_count"])
            if gps_snap and not net["gps"]:
                net["gps"] = gps_snap
            if ssid != "<hidden>" and net["ssid"] == "<hidden>":
                net["ssid"] = ssid


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------


def _init_db():
    os.makedirs(LOOT_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS networks (
        bssid TEXT PRIMARY KEY, ssid TEXT, channel INTEGER,
        signal INTEGER, security TEXT, cipher TEXT, auth TEXT,
        wps BOOLEAN, vendor TEXT, first_seen TEXT, last_seen TEXT,
        lat REAL, lon REAL, alt REAL, beacon_count INTEGER)""")
    conn.commit()
    conn.close()


def _save_to_db():
    """Save all networks to SQLite."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        with lock:
            nets = dict(networks)
        for bssid, n in nets.items():
            gps = n.get("gps")
            lat = gps["lat"] if gps else None
            lon = gps["lon"] if gps else None
            alt = gps.get("alt") if gps else None
            c.execute("""INSERT OR REPLACE INTO networks
                (bssid, ssid, channel, signal, security, cipher, auth,
                 wps, vendor, first_seen, last_seen, lat, lon, alt, beacon_count)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (bssid, n["ssid"], n["channel"], n["signal"],
                 n["security"], n["cipher"], n["auth"], n["wps"],
                 n["vendor"], n["first_seen"], n["last_seen"],
                 lat, lon, alt, n["beacon_count"]))
        conn.commit()
        conn.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


def _security_to_wigle(sec, cipher, auth):
    """Convert security to Wigle AuthMode format."""
    if sec == "Open":
        return "[ESS]"
    if sec == "WEP":
        return "[WEP][ESS]"
    if sec == "WPA3-SAE":
        return f"[WPA3-SAE-{cipher or 'CCMP'}][ESS]"
    if sec == "WPA2-EAP":
        return f"[WPA2-EAP-{cipher or 'CCMP'}][ESS]"
    if "WPA2" in sec:
        return f"[WPA2-PSK-{cipher or 'CCMP'}][ESS]"
    if "WPA" in sec:
        return f"[WPA-PSK-{cipher or 'TKIP'}][ESS]"
    return f"[{sec}][ESS]"


def _ch_to_freq(ch):
    if 1 <= ch <= 13:
        return 2407 + ch * 5
    if ch == 14:
        return 2484
    if 36 <= ch <= 165:
        return 5000 + ch * 5
    return 0


def _export_all():
    """Export to Wigle CSV, JSON, KML. Returns list of created files."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(LOOT_DIR, exist_ok=True)
    files = []

    with lock:
        nets = dict(networks)

    if not nets:
        return files

    # Save DB first
    _save_to_db()

    # --- Wigle CSV ---
    wigle_path = os.path.join(LOOT_DIR, f"wigle_{ts}.csv")
    try:
        with open(wigle_path, "w", newline="") as f:
            f.write("WigleWifi-1.4,appRelease=RaspyJack-v2,model=RaspberryPi,"
                    "release=2.0,device=RaspyJack,display=LCD144,"
                    "board=RaspberryPi,brand=7h30th3r0n3\n")
            writer = csv.writer(f)
            writer.writerow([
                "MAC", "SSID", "AuthMode", "FirstSeen", "Channel", "RSSI",
                "CurrentLatitude", "CurrentLongitude", "AltitudeMeters",
                "AccuracyMeters", "Type",
            ])
            for bssid, n in nets.items():
                gps = n.get("gps")
                if not gps:
                    continue
                auth_mode = _security_to_wigle(
                    n["security"], n["cipher"], n["auth"])
                writer.writerow([
                    bssid, n["ssid"], auth_mode, n["first_seen"],
                    n["channel"], n["signal"],
                    f"{gps['lat']:.6f}", f"{gps['lon']:.6f}",
                    f"{gps.get('alt', 0):.1f}", "10", "WIFI",
                ])
        files.append(wigle_path)
    except Exception:
        pass

    # --- JSON ---
    json_path = os.path.join(LOOT_DIR, f"scan_{ts}.json")
    try:
        export = {
            "scan_info": {
                "timestamp": ts,
                "total_networks": len(nets),
                "wigle_ready": sum(1 for n in nets.values() if n.get("gps")),
            },
            "networks": list(nets.values()),
        }
        with open(json_path, "w") as f:
            json.dump(export, f, indent=2)
        files.append(json_path)
    except Exception:
        pass

    # --- KML ---
    kml_path = os.path.join(LOOT_DIR, f"scan_{ts}.kml")
    try:
        kml = ['<?xml version="1.0" encoding="UTF-8"?>',
               '<kml xmlns="http://www.opengis.net/kml/2.2">',
               '<Document><name>RaspyJack Wardriving</name>']
        for bssid, n in nets.items():
            gps = n.get("gps")
            if not gps:
                continue
            kml.append(f'<Placemark><name>{n["ssid"]}</name>')
            kml.append(f'<description>BSSID:{bssid} Sec:{n["security"]} '
                       f'Ch:{n["channel"]} Sig:{n["signal"]}dBm</description>')
            kml.append(f'<Point><coordinates>{gps["lon"]:.6f},'
                       f'{gps["lat"]:.6f},{gps.get("alt", 0):.0f}'
                       f'</coordinates></Point></Placemark>')
        kml.append('</Document></kml>')
        with open(kml_path, "w") as f:
            f.write("\n".join(kml))
        files.append(kml_path)
    except Exception:
        pass

    return files


# ---------------------------------------------------------------------------
# LCD Drawing
# ---------------------------------------------------------------------------


def _signal_bar(sig):
    """Convert dBm to 0-4 bar level."""
    if sig >= -50:
        return 4
    if sig >= -60:
        return 3
    if sig >= -70:
        return 2
    if sig >= -80:
        return 1
    return 0


def _draw_signal_bars(d, x, y, level):
    """Draw mini signal bars."""
    for i in range(4):
        h = 3 + i * 2
        color = "#00FF00" if i < level else "#222"
        d.rectangle((x + i * 4, y + 10 - h, x + i * 4 + 2, y + 10), fill=color)


def _sec_color(sec):
    if sec == "Open":
        return "#FF0000"
    if sec == "WEP":
        return "#FF8800"
    if "WPA3" in sec:
        return "#00FF00"
    if "WPA2" in sec:
        return "#00CCFF"
    if "WPA" in sec:
        return "#FFAA00"
    return "#888"


def _draw_live(lcd, font, font_sm):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        net_count = len(networks)
        cli_count = len(probes)
        beacons = total_beacons
        ch = current_channel
        gps_snap = dict(gps_data) if gps_data else None
        # Get 6 most recent/strongest
        recent = sorted(networks.values(),
                        key=lambda n: n["signal"], reverse=True)[:6]

    scanning = _scanning.is_set()
    dm = dual_mode

    # Header
    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "WARDRIVING", font=font_sm, fill="#00CCFF")
    status = "SCAN" if scanning else "IDLE"
    mode = "2x" if dm else "1x"
    d.text((70, 1), f"{status} {mode}", font=font_sm, fill="#00FF00" if scanning else "#666")
    d.ellipse((120, 3, 126, 9), fill="#00FF00" if scanning else "#444")

    # Stats bar line 1: AP + CLI + CH
    d.text((2, 14), f"AP:{net_count}", font=font_sm, fill="#00FF00")
    d.text((36, 14), f"CLI:{cli_count}", font=font_sm, fill="#00CCFF")
    d.text((72, 14), f"CH:{ch}", font=font_sm, fill="#FFAA00")
    # Stats bar line 2: GPS
    gps_txt = f"GPS:{gps_snap['lat']:.4f},{gps_snap['lon']:.4f}" if gps_snap else "GPS: No fix"
    gps_col = "#00FF00" if gps_snap else "#FF4444"
    d.text((2, 24), gps_txt, font=font_sm, fill=gps_col)

    # Network list
    y = 36
    d.line([(0, 34), (127, 34)], fill="#333")
    if not recent:
        d.text((10, 55), "No networks yet", font=font_sm, fill="#444")
    else:
        for n in recent:
            ssid = n["ssid"][:14]
            sig = n["signal"]
            sec = n["security"]

            d.text((2, y), ssid, font=font_sm, fill="#FFFFFF")
            _draw_signal_bars(d, 88, y, _signal_bar(sig))
            d.text((105, y), f"{sig}", font=font_sm, fill="#888")
            # Security dot
            d.ellipse((82, y + 3, 86, y + 7), fill=_sec_color(sec))
            y += 14
            if y > 110:
                break

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Scan K1:View K2:Exp", font=font_sm, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_gps(lcd, font, font_sm):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "GPS STATUS", font=font_sm, fill="#FFAA00")

    with lock:
        gps_snap = dict(gps_data) if gps_data else None

    y = 16
    if not gps_snap:
        if not GPSD_OK:
            d.text((4, 40), "gpsd-py3 not installed", font=font_sm, fill="#FF4444")
            d.text((4, 55), "pip3 install gpsd-py3", font=font_sm, fill="#888")
        elif not gps_ready:
            d.text((4, 40), "GPS not detected", font=font_sm, fill="#FF4444")
            d.text((4, 55), "Check USB GPS module", font=font_sm, fill="#888")
        else:
            d.text((4, 40), "Waiting for GPS fix", font=font_sm, fill="#FFAA00")
            d.text((4, 55), "Move to clear sky", font=font_sm, fill="#888")
    else:
        lat = gps_snap["lat"]
        lon = gps_snap["lon"]
        alt = gps_snap.get("alt", 0)
        speed = gps_snap.get("speed", 0)
        sats = gps_snap.get("sats", 0)
        mode = gps_snap.get("mode", 0)
        age = time.time() - gps_snap.get("ts", time.time())

        fix_type = f"{mode}D" if mode >= 2 else "No fix"
        d.text((4, y), f"Fix: {fix_type}", font=font_sm, fill="#00FF00")
        y += 14
        d.text((4, y), f"Lat: {lat:.6f}", font=font_sm, fill="#FFFFFF")
        y += 12
        d.text((4, y), f"Lon: {lon:.6f}", font=font_sm, fill="#FFFFFF")
        y += 12
        d.text((4, y), f"Alt: {alt:.1f}m", font=font_sm, fill="#888")
        y += 14
        # Speed in km/h
        speed_kmh = speed * 3.6 if speed else 0
        if speed_kmh < 2:
            mvt = "Stationary"
            mvt_col = "#888"
        elif speed_kmh < 8:
            mvt = "Walking"
            mvt_col = "#00CCFF"
        elif speed_kmh < 30:
            mvt = "Cycling"
            mvt_col = "#FFAA00"
        else:
            mvt = "Driving"
            mvt_col = "#FF4444"
        d.text((4, y), f"Speed: {speed_kmh:.1f} km/h", font=font_sm, fill=mvt_col)
        d.text((90, y), mvt, font=font_sm, fill=mvt_col)
        y += 14
        d.text((4, y), f"Sats: {sats}", font=font_sm, fill="#FFAA00")
        age_txt = f"{age:.0f}s ago" if age < 60 else "old"
        d.text((60, y), age_txt, font=font_sm, fill="#666")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "K1:View K3:Exit", font=font_sm, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_stats(lcd, font, font_sm):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "STATISTICS", font=font_sm, fill="#FF00FF")

    with lock:
        nets = list(networks.values())
        cli_count = len(probes)
        probe_count = total_probes
        gps_snap = dict(gps_data) if gps_data else None

    total = len(nets)
    wigle_ready = sum(1 for n in nets if n.get("gps"))

    # Security breakdown
    sec_count = Counter(n["security"] for n in nets)
    y = 16
    d.text((2, y), f"AP:{total} CLI:{cli_count} Wigle:{wigle_ready}", font=font_sm, fill="#FFFFFF")
    y += 14

    # Security bars
    for sec_name in ["Open", "WEP", "WPA", "WPA2-PSK", "WPA2-EAP", "WPA3-SAE"]:
        count = sec_count.get(sec_name, 0)
        if count == 0 and sec_name not in ("Open", "WPA2-PSK"):
            continue
        pct = count / max(total, 1)
        label = sec_name[:8]
        d.text((2, y), f"{label}", font=font_sm, fill=_sec_color(sec_name))
        bar_w = int(50 * pct)
        if bar_w > 0:
            d.rectangle((52, y + 1, 52 + bar_w, y + 8), fill=_sec_color(sec_name))
        d.text((106, y), f"{count}", font=font_sm, fill="#888")
        y += 11
        if y > 105:
            break

    # Channel distribution (mini heatmap)
    if total > 0 and y < 100:
        y += 2
        ch_count = Counter(n["channel"] for n in nets)
        max_ch = max(ch_count.values()) if ch_count else 1
        d.text((2, y), "CH:", font=font_sm, fill="#666")
        for i, ch in enumerate(CHANNELS_24):
            x = 20 + i * 8
            cnt = ch_count.get(ch, 0)
            h = max(1, int(cnt / max_ch * 10)) if cnt > 0 else 0
            color = "#00FF00" if cnt > max_ch * 0.5 else "#FFAA00" if cnt > 0 else "#181818"
            if h > 0:
                d.rectangle((x, y + 10 - h, x + 6, y + 10), fill=color)

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "K1:View K2:Export K3:X", font=font_sm, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_channels(lcd, font, font_sm):
    """Dashboard: AP count per channel with bar chart."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "CHANNELS", font=font_sm, fill="#FFAA00")

    with lock:
        nets = list(networks.values())

    ch_count = Counter(n["channel"] for n in nets)
    total = len(nets)

    d.text((80, 1), f"AP:{total}", font=font_sm, fill="#00FF00")

    # --- 2.4 GHz bar chart ---
    d.text((2, 15), "2.4 GHz", font=font_sm, fill="#00CCFF")
    bar_top = 27
    bar_h_max = 30
    max_24 = max((ch_count.get(ch, 0) for ch in CHANNELS_24), default=1) or 1
    cell_w = 9

    for i, ch in enumerate(CHANNELS_24):
        x = 2 + i * cell_w
        cnt = ch_count.get(ch, 0)
        bh = max(1, int(cnt / max_24 * bar_h_max)) if cnt > 0 else 0

        if cnt > max_24 * 0.6:
            color = "#00FF00"
        elif cnt > 0:
            color = "#FFAA00"
        else:
            color = "#181818"

        if bh > 0:
            d.rectangle((x, bar_top + bar_h_max - bh,
                          x + cell_w - 2, bar_top + bar_h_max), fill=color)

        # Channel number
        ch_color = "#FFFFFF" if cnt > 0 else "#333"
        d.text((x, bar_top + bar_h_max + 2), str(ch), font=font_sm, fill=ch_color)

        # Count on top of bar
        if cnt > 0:
            d.text((x, bar_top + bar_h_max - bh - 9), str(cnt),
                   font=font_sm, fill=color)

    # --- 5 GHz bar chart ---
    y5 = 72
    d.line([(0, y5 - 2), (127, y5 - 2)], fill="#333")
    d.text((2, y5), "5 GHz", font=font_sm, fill="#FF00FF")

    # Only show channels that have APs or are in the common set
    ch5_active = [ch for ch in CHANNELS_5 if ch_count.get(ch, 0) > 0]
    ch5_show = CHANNELS_5[:8] if not ch5_active else sorted(
        set(CHANNELS_5[:8]) | set(ch5_active))[:13]

    max_5 = max((ch_count.get(ch, 0) for ch in ch5_show), default=1) or 1
    bar_top_5 = y5 + 10
    bar_h_5 = 18
    n5 = len(ch5_show)
    cell_w_5 = max(6, min(9, 124 // max(n5, 1)))

    for i, ch in enumerate(ch5_show):
        x = 2 + i * cell_w_5
        if x + cell_w_5 > 127:
            break
        cnt = ch_count.get(ch, 0)
        bh = max(1, int(cnt / max_5 * bar_h_5)) if cnt > 0 else 0

        color = "#FF00FF" if cnt > max_5 * 0.3 else "#662266" if cnt > 0 else "#181818"

        if bh > 0:
            d.rectangle((x, bar_top_5 + bar_h_5 - bh,
                          x + cell_w_5 - 2, bar_top_5 + bar_h_5), fill=color)

        ch_color = "#FFFFFF" if cnt > 0 else "#333"
        # Short channel label (remove leading digits for compactness)
        ch_label = str(ch) if ch < 100 else str(ch)[-2:]
        d.text((x, bar_top_5 + bar_h_5 + 1), ch_label, font=font_sm, fill=ch_color)

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "K1:View K2:Export K3:X", font=font_sm, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_networks(lcd, font, font_sm, scroll_pos, sort):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    sort_names = ["Signal", "Name", "Security"]
    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), f"NETWORKS [{sort_names[sort]}]", font=font_sm, fill="#00FF00")

    with lock:
        nets = list(networks.values())

    # Sort
    if sort == 0:
        nets.sort(key=lambda n: n["signal"], reverse=True)
    elif sort == 1:
        nets.sort(key=lambda n: n["ssid"].lower())
    elif sort == 2:
        sec_order = {"Open": 0, "WEP": 1, "WPA": 2, "WPA2-PSK": 3,
                     "WPA2-EAP": 4, "WPA3-SAE": 5}
        nets.sort(key=lambda n: sec_order.get(n["security"], 3))

    if not nets:
        d.text((10, 55), "No networks", font=font_sm, fill="#444")
    else:
        visible = nets[scroll_pos:scroll_pos + 8]
        y = 14
        for n in visible:
            ssid = n["ssid"][:13]
            sig = n["signal"]
            sec = n["security"][:5]
            ch = n["channel"]
            has_gps = "*" if n.get("gps") else " "

            d.text((2, y), f"{has_gps}{ssid}", font=font_sm, fill="#FFFFFF")
            d.text((82, y), sec[:5], font=font_sm, fill=_sec_color(n["security"]))
            d.text((112, y), f"{sig}", font=font_sm, fill="#888")
            y += 12

    # Scroll indicator
    if len(nets) > 8:
        d.text((120, 14), "^", font=font_sm, fill="#444" if scroll_pos > 0 else "#111")
        d.text((120, 108), "v", font=font_sm,
               fill="#444" if scroll_pos + 8 < len(nets) else "#111")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "U/D:Scrl L/R:Sort K1:Vw", font=font_sm, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_export(lcd, font, font_sm, export_files):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "EXPORT", font=font_sm, fill="#FFAA00")

    with lock:
        nets = list(networks.values())

    total = len(nets)
    wigle_ready = sum(1 for n in nets if n.get("gps"))

    y = 16
    d.text((4, y), f"Networks: {total}", font=font_sm, fill="#FFFFFF")
    y += 12
    d.text((4, y), f"With GPS: {wigle_ready}", font=font_sm, fill="#00FF00")
    y += 12
    d.text((4, y), f"No GPS: {total - wigle_ready}", font=font_sm, fill="#FF4444")
    y += 16

    if export_files:
        d.text((4, y), "Last export:", font=font_sm, fill="#888")
        y += 12
        for f in export_files[-3:]:
            name = os.path.basename(f)[:22]
            d.text((4, y), name, font=font_sm, fill="#00CCFF")
            y += 11
    else:
        d.text((4, y), "No exports yet", font=font_sm, fill="#666")
        y += 12
        d.text((4, y), "Press KEY2 to export", font=font_sm, fill="#888")

    # Files in loot dir
    try:
        existing = [f for f in os.listdir(LOOT_DIR) if f.endswith((".csv", ".json", ".kml"))]
        d.text((4, 100), f"Files: {len(existing)} in loot", font=font_sm, fill="#666")
    except Exception:
        pass

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "K2:Export K1:View K3:X", font=font_sm, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Auto-save (continuous Wigle CSV update)
# ---------------------------------------------------------------------------

_wigle_path = os.path.join(LOOT_DIR, "wardriving_live.csv")


def _autosave_thread():
    """Background thread: save Wigle CSV every AUTOSAVE_INTERVAL seconds."""
    while not _shutdown.is_set():
        if _shutdown.wait(timeout=AUTOSAVE_INTERVAL):
            break
        if _scanning.is_set():
            _auto_save_wigle()
            _save_to_db()
    # Final save on shutdown
    _auto_save_wigle()
    _save_to_db()


def _auto_save_wigle():
    """Overwrite live Wigle CSV with current data."""
    with lock:
        nets = dict(networks)
    if not nets:
        return
    try:
        with open(_wigle_path, "w", newline="") as f:
            f.write("WigleWifi-1.4,appRelease=RaspyJack-v2,model=RaspberryPi,"
                    "release=2.0,device=RaspyJack,display=LCD144,"
                    "board=RaspberryPi,brand=7h30th3r0n3\n")
            writer = csv.writer(f)
            writer.writerow([
                "MAC", "SSID", "AuthMode", "FirstSeen", "Channel", "RSSI",
                "CurrentLatitude", "CurrentLongitude", "AltitudeMeters",
                "AccuracyMeters", "Type",
            ])
            for bssid, n in nets.items():
                gps = n.get("gps")
                lat = f"{gps['lat']:.6f}" if gps else ""
                lon = f"{gps['lon']:.6f}" if gps else ""
                alt = f"{gps.get('alt', 0):.1f}" if gps else ""
                auth_mode = _security_to_wigle(
                    n["security"], n["cipher"], n["auth"])
                writer.writerow([
                    bssid, n["ssid"], auth_mode, n["first_seen"],
                    n["channel"], n["signal"], lat, lon, alt, "10", "WIFI",
                ])
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    global view_idx, scroll, sort_mode, dual_mode

    os.makedirs(LOOT_DIR, exist_ok=True)

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font = scaled_font(10)
    font_sm = scaled_font(8)

    if not SCAPY_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "scapy not found!", font=font, fill="#FF0000")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    _init_db()

    # Start GPS thread
    gps_thread = threading.Thread(target=_gps_updater, daemon=True)
    gps_thread.start()

    # Show splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((20, 25), "WARDRIVING", font=font, fill="#00CCFF")
    d.text((10, 45), "WiFi Network Scanner", font=font_sm, fill="#888")
    d.text((10, 65), "GPS + Multi-card", font=font_sm, fill="#888")
    d.text((10, 80), "Wigle Compatible", font=font_sm, fill="#00FF00")
    d.text((10, 100), "OK = Start", font=font_sm, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)

    export_files = []
    threads = []

    # Start autosave thread (independent, survives even if main loop lags)
    threading.Thread(target=_autosave_thread, daemon=True).start()

    try:
        while not _shutdown.is_set():
            btn = get_button(PINS, GPIO)

            # KEY3 = exit
            if btn == "KEY3":
                break

            # OK = toggle scan
            if btn == "OK":
                if not _scanning.is_set():
                    # Find monitor-capable USB interfaces
                    ifaces = _find_monitor_interfaces()

                    _scanning.set()
                    global scan_start_time
                    scan_start_time = time.time()
                    mon_ifaces.clear()

                    if ifaces:
                        # Setup monitor mode on ALL USB cards
                        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                        d = ScaledDraw(img)
                        d.text((4, 40), f"Monitor mode...", font=font, fill="#FFAA00")
                        d.text((4, 60), f"{len(ifaces)} card(s) found", font=font_sm, fill="#888")
                        lcd.LCD_ShowImage(img, 0, 0)

                        for iface in ifaces:
                            mon = _monitor_up(iface)
                            if mon:
                                mon_ifaces.append(mon)

                        if mon_ifaces:
                            dual_mode = len(mon_ifaces) >= 2
                            n_cards = len(mon_ifaces)

                            # Start a sniffer on each card
                            for iface in mon_ifaces:
                                t = threading.Thread(target=_sniffer, args=(iface,), daemon=True)
                                t.start()
                                threads.append(t)

                            # Detect 5GHz support per card
                            cards_5g = []
                            cards_24_only = []
                            for iface in mon_ifaces:
                                r = subprocess.run(
                                    ["sudo", "iw", "dev", iface, "set", "channel", "36"],
                                    capture_output=True, timeout=3)
                                if r.returncode == 0:
                                    cards_5g.append(iface)
                                    # Reset back to ch1
                                    subprocess.run(
                                        ["sudo", "iw", "dev", iface, "set", "channel", "1"],
                                        capture_output=True, timeout=3)
                                else:
                                    cards_24_only.append(iface)

                            # Split 2.4GHz channels across all cards
                            all_24_cards = cards_24_only + cards_5g
                            n_24 = len(all_24_cards)
                            for idx, iface in enumerate(all_24_cards):
                                ch_list = [CHANNELS_24[i] for i in range(idx, len(CHANNELS_24), n_24)]
                                t = threading.Thread(
                                    target=_channel_hopper_split,
                                    args=(iface, ch_list),
                                    daemon=True)
                                t.start()
                                threads.append(t)

                            # Split 5GHz channels across 5G-capable cards only
                            if cards_5g:
                                n_5g = len(cards_5g)
                                for idx, iface in enumerate(cards_5g):
                                    ch_list = [CHANNELS_5[i] for i in range(idx, len(CHANNELS_5), n_5g)]
                                    t = threading.Thread(
                                        target=_channel_hopper_split,
                                        args=(iface, ch_list),
                                        daemon=True)
                                    t.start()
                                    threads.append(t)

                    # Always start iw scan on wlan0 (works with or without USB cards)
                    # In scan-only mode: wlan0 alone does bulk discovery
                    # In dual/monitor mode: wlan0 adds bulk discovery on top
                    if os.path.isdir("/sys/class/net/wlan0/wireless"):
                        t = threading.Thread(target=_iw_scanner,
                                             args=("wlan0",), daemon=True)
                        t.start()
                        threads.append(t)

                    if not mon_ifaces:
                        # No USB cards — scan-only mode with wlan0
                        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                        d = ScaledDraw(img)
                        d.text((4, 35), "Scan mode (wlan0)", font=font, fill="#FFAA00")
                        d.text((4, 55), "No monitor card", font=font_sm, fill="#888")
                        d.text((4, 70), "Using iw scan", font=font_sm, fill="#888")
                        lcd.LCD_ShowImage(img, 0, 0)
                        time.sleep(1.5)

                else:
                    # Stop scan
                    _scanning.clear()
                    time.sleep(0.5)
                    _save_to_db()

                time.sleep(0.3)

            # KEY1 = cycle views
            elif btn == "KEY1":
                view_idx = (view_idx + 1) % len(VIEWS)
                scroll = 0
                time.sleep(0.25)

            # KEY2 = export
            elif btn == "KEY2":
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.text((4, 50), "Exporting...", font=font, fill="#FFAA00")
                lcd.LCD_ShowImage(img, 0, 0)
                export_files = _export_all()
                if export_files:
                    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                    d = ScaledDraw(img)
                    d.text((4, 40), f"Exported!", font=font, fill="#00FF00")
                    d.text((4, 60), f"{len(export_files)} files", font=font_sm, fill="#888")
                    lcd.LCD_ShowImage(img, 0, 0)
                else:
                    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                    d = ScaledDraw(img)
                    d.text((4, 50), "Nothing to export", font=font, fill="#FF4444")
                    lcd.LCD_ShowImage(img, 0, 0)
                time.sleep(1.5)

            # UP/DOWN = scroll (networks view)
            elif btn == "UP":
                scroll = max(0, scroll - 1)
                time.sleep(0.12)
            elif btn == "DOWN":
                with lock:
                    max_s = max(0, len(networks) - 8)
                scroll = min(max_s, scroll + 1)
                time.sleep(0.12)

            # LEFT/RIGHT = sort (networks view)
            elif btn == "LEFT" or btn == "RIGHT":
                sort_mode = (sort_mode + 1) % 3
                time.sleep(0.2)

            # Draw current view
            current_view = VIEWS[view_idx]
            if current_view == "live":
                _draw_live(lcd, font, font_sm)
            elif current_view == "gps":
                _draw_gps(lcd, font, font_sm)
            elif current_view == "channels":
                _draw_channels(lcd, font, font_sm)
            elif current_view == "stats":
                _draw_stats(lcd, font, font_sm)
            elif current_view == "networks":
                _draw_networks(lcd, font, font_sm, scroll, sort_mode)
            elif current_view == "export":
                _draw_export(lcd, font, font_sm, export_files)

            time.sleep(0.05)

    finally:
        _shutdown.set()
        _scanning.clear()
        # Show exit screen
        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.text((10, 40), "Saving data...", font=font, fill="#FFAA00")
            lcd.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass
        _save_to_db()
        _auto_save_wigle()
        for iface in mon_ifaces:
            _monitor_down(iface)
        subprocess.run(["sudo", "systemctl", "restart", "NetworkManager"],
                       capture_output=True, timeout=10)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())