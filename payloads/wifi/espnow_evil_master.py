#!/usr/bin/env python3
"""
RaspyJack Payload -- ESP-NOW Receiver (Monitor Mode)
=====================================================
Author: 7h30th3r0n3

Captures ESP-NOW frames over the air using a WiFi adapter in monitor mode.
Receives wardriving AP data and handshake fragments from the ESP32-C5 slave.

ESP-NOW frames are IEEE 802.11 vendor-specific action frames with
Espressif OUI 18:FE:34, transmitted on channel 1.

Modes
-----
  WARD   : Wardriving with GPS support, Wigle-compatible CSV
  SNIFF  : Handshake capture -- reassembles fragments, writes PCAP

Dashboards (LEFT/RIGHT to switch)
----------------------------------
  WARD:  Live Feed | Stats | Channels
  SNIFF: Fragments | Per-Channel Stats

Controls
--------
  LEFT/RIGHT Switch dashboard
  UP/DOWN    Scroll
  KEY1       Clear / reset
  KEY2       Toggle WARD / SNIFF mode
  KEY3       Exit
"""

import os
import sys
import time
import signal
import struct
import csv
import subprocess
import threading
from datetime import datetime
from collections import Counter

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._iface_helper import select_interface

try:
    from scapy.all import sniff as scapy_sniff, conf
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ---------------------------------------------------------------------------
# GPS (optional -- uses gpsd)
# ---------------------------------------------------------------------------
try:
    import gpsd as gpsd_module
    gpsd_module.connect()
    GPS_OK = True
except Exception:
    GPS_OK = False


class GpsReader:
    """Thread-safe GPS reader using gpsd."""

    def __init__(self):
        self.lat = 0.0
        self.lon = 0.0
        self.alt = 0.0
        self.speed = 0.0
        self.sats = 0
        self.fix = False
        self._lock = threading.Lock()
        self._running = True
        self._thread = None

    def start(self):
        if not GPS_OK:
            return
        self._thread = threading.Thread(target=self._poll, daemon=True)
        self._thread.start()

    def _poll(self):
        while self._running:
            try:
                pkt = gpsd_module.get_current()
                with self._lock:
                    self.lat = pkt.lat if hasattr(pkt, 'lat') else 0.0
                    self.lon = pkt.lon if hasattr(pkt, 'lon') else 0.0
                    self.alt = pkt.alt if hasattr(pkt, 'alt') else 0.0
                    self.speed = pkt.speed() if hasattr(pkt, 'speed') else 0.0
                    self.sats = pkt.sats if hasattr(pkt, 'sats') else 0
                    self.fix = pkt.mode >= 2 if hasattr(pkt, 'mode') else False
            except Exception:
                pass
            time.sleep(1)

    def get(self):
        with self._lock:
            return {
                "lat": self.lat, "lon": self.lon, "alt": self.alt,
                "speed": self.speed, "sats": self.sats, "fix": self.fix,
            }

    def stop(self):
        self._running = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
LOOT_DIR = "/root/Raspyjack/loot/ESPNow"
PCAP_DIR = os.path.join(LOOT_DIR, "handshakes")
ESPNOW_CHANNEL = 1
ESPNOW_ELEMENT = b"\x18\xfe\x34\x04"

# struct_message from C5 slave
WARD_STRUCT = struct.Struct("<64s32s16siii")
WARD_STRUCT_SIZE = WARD_STRUCT.size

# wifi_frame_fragment_t header
FRAG_HEADER = struct.Struct("<HBBB")
FRAG_HEADER_SIZE = FRAG_HEADER.size

FONT = scaled_font(8)
FONT_BIG = scaled_font(10)
FONT_SM = scaled_font(7)

# Channel lists (matching C5 slave channelsToHop[])
CHANNELS_2G = list(range(1, 14))
CHANNELS_5G = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
               116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
# C5 uses 1-based index into this list as board_id for fragments
ALL_CHANNELS = CHANNELS_2G + CHANNELS_5G
BOARD_ID_TO_CHANNEL = {i + 1: ch for i, ch in enumerate(ALL_CHANNELS)}

_running = True


def _cleanup(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# Monitor mode helpers
# ---------------------------------------------------------------------------

def set_monitor_mode(iface, channel=1):
    cmds = [
        ["ip", "link", "set", iface, "down"],
        ["iw", iface, "set", "type", "monitor"],
        ["ip", "link", "set", iface, "up"],
        ["iw", iface, "set", "channel", str(channel)],
    ]
    for cmd in cmds:
        r = subprocess.run(cmd, capture_output=True, timeout=10)
        if r.returncode != 0:
            return False, r.stderr.decode(errors="replace")
    return True, "OK"


def restore_managed_mode(iface):
    subprocess.run(["ip", "link", "set", iface, "down"],
                   capture_output=True, timeout=5)
    subprocess.run(["iw", iface, "set", "type", "managed"],
                   capture_output=True, timeout=5)
    subprocess.run(["ip", "link", "set", iface, "up"],
                   capture_output=True, timeout=5)


# ---------------------------------------------------------------------------
# ESP-NOW frame parser
# ---------------------------------------------------------------------------

def extract_espnow_payload(pkt):
    """Extract ESP-NOW payload from a raw 802.11 frame.

    ESP-NOW vendor element: 0xDD + Len + OUI(18:FE:34) + Type(0x04) + Ver + Body
    """
    raw_bytes = bytes(pkt)
    idx = raw_bytes.find(ESPNOW_ELEMENT)
    if idx < 0:
        return None
    payload_start = idx + 3 + 1 + 1  # OUI(3) + Type(1) + Version(1)
    if payload_start >= len(raw_bytes):
        return None
    return raw_bytes[payload_start:]


def _is_ward_payload(data):
    """Heuristic: ward payloads are 128 bytes and start with ASCII BSSID (hex:hex:...)."""
    if len(data) < WARD_STRUCT_SIZE:
        return False
    # Ward struct_message is sent as exactly sizeof(struct_message) = 124 bytes
    # ESP-NOW may add up to 4 bytes padding -> expect 124-132
    if not (124 <= len(data) <= 132):
        return False
    # BSSID field starts with printable hex chars (0-9, A-F, a-f, :)
    first = data[0]
    return (0x30 <= first <= 0x39 or  # 0-9
            0x41 <= first <= 0x46 or  # A-F
            0x61 <= first <= 0x66)    # a-f


def parse_ward_payload(data):
    if not _is_ward_payload(data):
        return None
    try:
        bssid_raw, ssid_raw, enc_raw, channel, rssi, board_id = \
            WARD_STRUCT.unpack_from(data)
        bssid = bssid_raw.split(b"\x00", 1)[0].decode(errors="replace")
        ssid = ssid_raw.split(b"\x00", 1)[0].decode(errors="replace")
        enc = enc_raw.split(b"\x00", 1)[0].decode(errors="replace")
        # Sanity check parsed values
        if ":" not in bssid or len(bssid) < 11:
            return None
        if not (-120 <= rssi <= 0):
            return None
        if not (1 <= channel <= 200):
            return None
        return {
            "bssid": bssid, "ssid": ssid, "enc": enc,
            "ap_ch": channel, "rssi": rssi, "board_id": board_id,
            "time": datetime.now().strftime("%H:%M:%S"),
        }
    except Exception:
        return None


def parse_fragment(data):
    if len(data) < FRAG_HEADER_SIZE:
        return None
    try:
        frame_len, frag_num, last_frag, board_id = FRAG_HEADER.unpack_from(data)
        frame_data = data[FRAG_HEADER_SIZE:FRAG_HEADER_SIZE + frame_len]
        return {
            "frame_len": frame_len, "frag_num": frag_num,
            "last": bool(last_frag), "board_id": board_id, "data": frame_data,
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Wigle-compatible CSV Logger
# ---------------------------------------------------------------------------

class WardLogger:
    WIGLE_HEADER = "WigleWifi-1.4,appRelease=RaspyJack,model=RPi,release=1.0,device=ESPNow,display=LCD,board=RPi,brand=RaspyJack"
    COLUMNS = ["MAC", "SSID", "AuthMode", "FirstSeen", "Channel", "RSSI",
               "CurrentLatitude", "CurrentLongitude", "AltitudeMeters",
               "AccuracyMeters", "Type"]

    def __init__(self):
        os.makedirs(LOOT_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.csv_path = os.path.join(LOOT_DIR, f"ward_{ts}.csv")
        self._file = open(self.csv_path, "w", newline="")
        self._writer = csv.writer(self._file)
        self._writer.writerow([self.WIGLE_HEADER])
        self._writer.writerow(self.COLUMNS)
        self._count = 0
        self._seen_bssids = set()
        self._enc_counter = Counter()
        self._ch_counter = Counter()
        self._ssid_counter = Counter()

    def log(self, ap, gps_data):
        first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        is_new = ap["bssid"] not in self._seen_bssids
        self._writer.writerow([
            ap["bssid"], ap["ssid"], f"[{ap['enc']}]", first_seen,
            ap["ap_ch"], ap["rssi"],
            f"{gps_data['lat']:.8f}" if gps_data["fix"] else "",
            f"{gps_data['lon']:.8f}" if gps_data["fix"] else "",
            f"{gps_data['alt']:.1f}" if gps_data["fix"] else "",
            "", "WIFI",
        ])
        self._file.flush()
        self._count += 1
        self._seen_bssids.add(ap["bssid"])
        self._enc_counter[ap["enc"]] += 1
        self._ch_counter[ap["ap_ch"]] += 1
        if ap["ssid"]:
            self._ssid_counter[ap["ssid"]] += 1
        return is_new

    @property
    def total(self):
        return self._count

    @property
    def unique(self):
        return len(self._seen_bssids)

    def close(self):
        self._file.close()


# ---------------------------------------------------------------------------
# PCAP writer
# ---------------------------------------------------------------------------

class PcapWriter:
    GLOBAL_HEADER = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 0xFFFF, 105)

    def __init__(self):
        os.makedirs(PCAP_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.path = os.path.join(PCAP_DIR, f"hs_{ts}.pcap")
        self._file = open(self.path, "wb")
        self._file.write(self.GLOBAL_HEADER)
        self._count = 0

    def write_frame(self, frame_bytes):
        ts = time.time()
        sec, usec = int(ts), int((ts - int(ts)) * 1_000_000)
        hdr = struct.pack("<IIII", sec, usec, len(frame_bytes), len(frame_bytes))
        self._file.write(hdr + frame_bytes)
        self._file.flush()
        self._count += 1

    @property
    def count(self):
        return self._count

    def close(self):
        self._file.close()


# ---------------------------------------------------------------------------
# Fragment reassembly
# ---------------------------------------------------------------------------

def _extract_ssid_from_beacon(frame_bytes):
    """Extract SSID from a beacon or probe response frame.

    802.11 MAC header (24B) + Fixed params (12B) = 36B, then tagged params.
    Tag 0 = SSID.
    """
    if len(frame_bytes) < 38:
        return ""
    # Check frame type: beacon = type 0 subtype 8, probe resp = type 0 subtype 5
    fc = frame_bytes[0]
    ftype = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    if ftype != 0 or subtype not in (5, 8):
        return ""
    offset = 36  # after MAC header + fixed params
    while offset + 2 <= len(frame_bytes):
        tag_id = frame_bytes[offset]
        tag_len = frame_bytes[offset + 1]
        if offset + 2 + tag_len > len(frame_bytes):
            break
        if tag_id == 0 and tag_len > 0:
            try:
                return frame_bytes[offset + 2:offset + 2 + tag_len].decode(errors="replace")
            except Exception:
                return ""
        offset += 2 + tag_len
    return ""


class FragmentAssembler:
    def __init__(self, pcap_writer):
        self.pcap = pcap_writer
        self._state = {}
        self.frames_complete = 0
        self.ch_frames = Counter()      # board_id -> frame count
        self.last_ssid = ""             # last SSID extracted from beacon
        self.ch_last_ssid = {}          # board_id -> last SSID

    def feed(self, frag):
        bid = frag["board_id"]
        # Convert 1-based board_id index to actual WiFi channel number
        real_ch = BOARD_ID_TO_CHANNEL.get(bid, bid)
        if bid not in self._state:
            self._state[bid] = {"next": 0, "buf": bytearray()}
        st = self._state[bid]
        if frag["frag_num"] != st["next"]:
            st["next"] = 0
            st["buf"] = bytearray()
            return None
        st["buf"].extend(frag["data"])
        st["next"] += 1
        if frag["last"]:
            frame = bytes(st["buf"])
            st["next"] = 0
            st["buf"] = bytearray()
            self.pcap.write_frame(frame)
            self.frames_complete += 1
            self.ch_frames[real_ch] += 1
            # Try to extract SSID from beacon frames
            ssid = _extract_ssid_from_beacon(frame)
            if ssid:
                self.last_ssid = ssid
                self.ch_last_ssid[real_ch] = ssid
            return frame
        return None


# ---------------------------------------------------------------------------
# Sniffer thread
# ---------------------------------------------------------------------------

class EspNowSniffer:
    def __init__(self, iface, gps_reader):
        self.iface = iface
        self.gps = gps_reader
        self.ward_aps = []
        self.ward_logger = WardLogger()
        self.pcap = PcapWriter()
        self.assembler = FragmentAssembler(self.pcap)
        self.sniff_lines = []
        self._lock = threading.Lock()
        self.packets_total = 0
        self.start_time = time.time()

    def _handle_packet(self, pkt):
        payload = extract_espnow_payload(pkt)
        if payload is None:
            return
        self.packets_total += 1

        ap = parse_ward_payload(payload)
        if ap and ap["bssid"]:
            gps_data = self.gps.get()
            with self._lock:
                ap["lat"] = gps_data["lat"]
                ap["lon"] = gps_data["lon"]
                self.ward_aps.insert(0, ap)
                if len(self.ward_aps) > 1000:
                    self.ward_aps.pop()
                self.ward_logger.log(ap, gps_data)
            return

        frag = parse_fragment(payload)
        if frag and frag["frame_len"] > 0:
            real_ch = BOARD_ID_TO_CHANNEL.get(frag["board_id"], frag["board_id"])
            with self._lock:
                result = self.assembler.feed(frag)
                ts = datetime.now().strftime("%H:%M:%S")
                if result:
                    ssid_tag = ""
                    if self.assembler.last_ssid:
                        ssid_tag = f" {self.assembler.last_ssid[:10]}"
                    self.sniff_lines.insert(0,
                        f"{ts} FRAME ch{real_ch} {len(result)}B{ssid_tag}")
                else:
                    self.sniff_lines.insert(0,
                        f"{ts} frag#{frag['frag_num']} ch{real_ch}")
                if len(self.sniff_lines) > 200:
                    self.sniff_lines = self.sniff_lines[:200]

    def start(self):
        def _run():
            conf.iface = self.iface
            try:
                scapy_sniff(
                    iface=self.iface, prn=self._handle_packet,
                    store=False, stop_filter=lambda _: not _running,
                )
            except Exception as e:
                with self._lock:
                    self.sniff_lines.insert(0, f"ERR: {str(e)[:30]}")
        threading.Thread(target=_run, daemon=True).start()

    def elapsed(self):
        s = int(time.time() - self.start_time)
        return f"{s // 3600}:{(s % 3600) // 60:02d}:{s % 60:02d}"

    def stop(self):
        self.ward_logger.close()
        self.pcap.close()


# ---------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------

def _rssi_color(rssi):
    if rssi > -50:
        return "#00FF00"
    if rssi > -70:
        return "#FFAA00"
    return "#FF4444"


def _bar(d, x, y, w, h, pct, fill, bg="#222"):
    """Draw a small filled bar."""
    d.rectangle((x, y, x + w, y + h), fill=bg)
    bar_h = max(1, int(h * min(1.0, pct)))
    d.rectangle((x, y + h - bar_h, x + w, y + h), fill=fill)


# ---------------------------------------------------------------------------
# WARD Dashboards
# ---------------------------------------------------------------------------

def draw_ward_live(lcd, sniffer, gps, scroll):
    """Dashboard 1: Live AP feed."""
    w, h = lcd.width, lcd.height
    img = Image.new("RGB", (w, h), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#002200")
    d.text((2, 1), "WARD", font=FONT_BIG, fill="#00FF00")
    with sniffer._lock:
        u, t = sniffer.ward_logger.unique, sniffer.ward_logger.total
    d.text((32, 2), f"U:{u} T:{t}", font=FONT_SM, fill="#FFAA00")

    # GPS indicator
    g = gps.get()
    if GPS_OK and g["fix"]:
        d.text((100, 2), f"S{g['sats']}", font=FONT_SM, fill="#00FF00")
    elif GPS_OK:
        d.text((100, 2), "noFix", font=FONT_SM, fill="#FF4444")
    else:
        d.text((104, 2), "noGPS", font=FONT_SM, fill="#555")

    # AP list
    with sniffer._lock:
        aps = list(sniffer.ward_aps)
    visible = aps[scroll:scroll + 7]
    for i, ap in enumerate(visible):
        y = 15 + i * 14
        ssid = ap["ssid"][:10] or "Hidden"
        d.text((2, y), ssid, font=FONT, fill="#FFFFFF")
        d.text((66, y), str(ap["rssi"]), font=FONT, fill=_rssi_color(ap["rssi"]))
        d.text((88, y), f"c{ap['ap_ch']}", font=FONT_SM, fill="#58a6ff")
        enc_short = ap["enc"][:4]
        ec = "#00FF00" if "WPA" in ap["enc"] else "#FF4444" if "Open" in ap["enc"] else "#888"
        d.text((108, y), enc_short, font=FONT_SM, fill=ec)

    if not aps:
        d.text((10, 40), "Listening ch1...", font=FONT, fill="#666")
        d.text((10, 55), "Waiting for C5", font=FONT, fill="#444")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "L/R:Dash K2:Sniff K3:X", font=FONT_SM, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)
    return len(aps)


def draw_ward_stats(lcd, sniffer, gps):
    """Dashboard 2: Stats overview."""
    w, h = lcd.width, lcd.height
    img = Image.new("RGB", (w, h), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#002200")
    d.text((2, 1), "STATS", font=FONT_BIG, fill="#00FF00")
    d.text((50, 2), sniffer.elapsed(), font=FONT_SM, fill="#888")

    with sniffer._lock:
        logger = sniffer.ward_logger
        u, t = logger.unique, logger.total
        enc_c = dict(logger._enc_counter.most_common(5))
        top_ssids = logger._ssid_counter.most_common(3)

    y = 16

    # Totals
    d.text((2, y), f"Unique APs: {u}", font=FONT, fill="#00FF00")
    y += 12
    d.text((2, y), f"Total hits: {t}", font=FONT, fill="#CCCCCC")
    y += 12
    d.text((2, y), f"Packets:    {sniffer.packets_total}", font=FONT, fill="#888")
    y += 14

    # Encryption breakdown
    d.text((2, y), "Encryption:", font=FONT, fill="#58a6ff")
    y += 11
    for enc_name, count in enc_c.items():
        pct = int(100 * count / max(1, t))
        ec = "#00FF00" if "WPA" in enc_name else "#FF4444" if "Open" in enc_name else "#FFAA00"
        d.text((6, y), f"{enc_name[:8]}", font=FONT_SM, fill=ec)
        d.text((55, y), f"{count}", font=FONT_SM, fill="#CCC")
        # Mini bar
        _bar(d, 75, y + 1, 50, 7, pct / 100, ec)
        y += 10
        if y > 100:
            break

    # GPS info
    g = gps.get()
    if GPS_OK and g["fix"]:
        d.text((2, 107), f"{g['lat']:.5f},{g['lon']:.5f}", font=FONT_SM, fill="#00FF00")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "L/R:Dash K1:Reset K3:X", font=FONT_SM, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


def draw_ward_2g(lcd, sniffer):
    """Dashboard 3: 2.4 GHz channel bar chart (full screen)."""
    w, h = lcd.width, lcd.height
    img = Image.new("RGB", (w, h), "black")
    d = ScaledDraw(img)

    with sniffer._lock:
        ch_c = dict(sniffer.ward_logger._ch_counter)

    total_2g = sum(ch_c.get(ch, 0) for ch in CHANNELS_2G)
    unique_2g = sum(1 for ch in CHANNELS_2G if ch_c.get(ch, 0) > 0)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#002200")
    d.text((2, 1), "2.4 GHz", font=FONT_BIG, fill="#00CCFF")
    d.text((55, 2), f"APs:{total_2g}", font=FONT_SM, fill="#FFAA00")
    d.text((95, 2), f"{unique_2g}ch", font=FONT_SM, fill="#888")

    # Bar chart - full width, taller bars
    max_count = max((ch_c.get(ch, 0) for ch in CHANNELS_2G), default=1) or 1
    bar_area_y = 18
    bar_area_h = 70
    bar_w = 8
    gap = 1

    for i, ch in enumerate(CHANNELS_2G):
        count = ch_c.get(ch, 0)
        x = 3 + i * (bar_w + gap)
        pct = count / max_count if count > 0 else 0
        bar_h = max(1, int(bar_area_h * pct)) if count > 0 else 0

        # Bar background outline
        d.rectangle((x, bar_area_y, x + bar_w - 1, bar_area_y + bar_area_h),
                     fill="#111")

        # Filled bar
        if bar_h > 0:
            color = "#00FF00" if pct < 0.4 else "#FFAA00" if pct < 0.7 else "#FF4444"
            d.rectangle((x, bar_area_y + bar_area_h - bar_h,
                         x + bar_w - 1, bar_area_y + bar_area_h), fill=color)

        # Count on top of bar
        if count > 0:
            cy = bar_area_y + bar_area_h - bar_h - 8
            if cy < bar_area_y:
                cy = bar_area_y
            d.text((x, cy), str(count), font=FONT_SM, fill="#FFF")

        # Channel number below
        d.text((x + 1, bar_area_y + bar_area_h + 3), str(ch), font=FONT_SM, fill="#888")

    # Top 3 SSIDs on this band
    y = 100
    band_ssids = Counter()
    with sniffer._lock:
        for ap in sniffer.ward_aps:
            if ap["ap_ch"] in CHANNELS_2G and ap["ssid"]:
                band_ssids[ap["ssid"]] += 1
    top3 = band_ssids.most_common(1)
    if top3:
        d.text((2, y), f"Top: {top3[0][0][:14]}({top3[0][1]})", font=FONT_SM, fill="#58a6ff")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "L/R:Dash K2:Sniff K3:X", font=FONT_SM, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


def draw_ward_5g(lcd, sniffer):
    """Dashboard 4: 5 GHz channel bar chart (full screen)."""
    w, h = lcd.width, lcd.height
    img = Image.new("RGB", (w, h), "black")
    d = ScaledDraw(img)

    with sniffer._lock:
        ch_c = dict(sniffer.ward_logger._ch_counter)

    active_5g = [(ch, ch_c.get(ch, 0)) for ch in CHANNELS_5G if ch_c.get(ch, 0) > 0]
    total_5g = sum(c for _, c in active_5g)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#001133")
    d.text((2, 1), "5 GHz", font=FONT_BIG, fill="#FF8800")
    d.text((45, 2), f"APs:{total_5g}", font=FONT_SM, fill="#FFAA00")
    d.text((90, 2), f"{len(active_5g)}ch", font=FONT_SM, fill="#888")

    if not active_5g:
        d.text((10, 40), "No 5GHz APs yet", font=FONT, fill="#666")
        d.text((10, 55), "Waiting for C5 data", font=FONT_SM, fill="#444")
        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "L/R:Dash K2:Sniff K3:X", font=FONT_SM, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)
        return

    # Group 5GHz channels into bands: UNII-1(36-48), UNII-2(52-64),
    # UNII-2e(100-144), UNII-3(149-165)
    bands = [
        ("U1", [36, 40, 44, 48]),
        ("U2", [52, 56, 60, 64]),
        ("U2e", [100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144]),
        ("U3", [149, 153, 157, 161, 165]),
    ]

    max_count = max((c for _, c in active_5g), default=1) or 1
    y = 18

    for band_name, band_channels in bands:
        band_aps = [(ch, ch_c.get(ch, 0)) for ch in band_channels if ch_c.get(ch, 0) > 0]
        band_total = sum(c for _, c in band_aps)
        if band_total == 0:
            continue

        # Band label
        d.text((2, y), f"{band_name}", font=FONT_SM, fill="#FF8800")

        # Horizontal bars for each active channel
        bar_x = 22
        bar_max_w = 80
        for ch, count in band_aps:
            pct = count / max_count
            bar_w = max(2, int(bar_max_w * pct))
            color = "#FF8800" if pct < 0.5 else "#FF4444" if pct < 0.8 else "#FF0000"
            d.rectangle((bar_x, y + 1, bar_x + bar_w, y + 7), fill=color)
            d.text((bar_x + bar_w + 2, y), f"c{ch}:{count}", font=FONT_SM, fill="#CCC")
            y += 10
            if y > 105:
                break

        if y > 105:
            break

    # Top SSID on 5GHz
    band_ssids = Counter()
    with sniffer._lock:
        for ap in sniffer.ward_aps:
            if ap["ap_ch"] in CHANNELS_5G and ap["ssid"]:
                band_ssids[ap["ssid"]] += 1
    top = band_ssids.most_common(1)
    if top:
        d.text((2, 107), f"Top: {top[0][0][:14]}({top[0][1]})", font=FONT_SM, fill="#FF8800")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "L/R:Dash K2:Sniff K3:X", font=FONT_SM, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# SNIFF Dashboards
# ---------------------------------------------------------------------------

def draw_sniff_chanmap(lcd, sniffer):
    """Sniff dashboard 1: Channel grid map -- all channels visible, lights up on capture."""
    w, h = lcd.width, lcd.height
    img = Image.new("RGB", (w, h), "black")
    d = ScaledDraw(img)

    ch_frames = dict(sniffer.assembler.ch_frames)
    fc = sniffer.assembler.frames_complete
    last_ssid = sniffer.assembler.last_ssid

    # Header
    d.rectangle((0, 0, 127, 13), fill="#220022")
    d.text((2, 1), "CHANNEL MAP", font=FONT_BIG, fill="#FF44FF")
    d.text((85, 2), f"T:{fc}", font=FONT_SM, fill="#00FF00")

    all_channels = CHANNELS_2G + CHANNELS_5G  # 13 + 25 = 38 channels
    max_count = max(ch_frames.values()) if ch_frames else 1

    # Grid layout: 8 columns
    cols = 8
    cell_w = 15
    cell_h = 12
    grid_x = 2
    grid_y = 16

    for i, ch in enumerate(all_channels):
        col = i % cols
        row = i // cols
        x = grid_x + col * cell_w
        y = grid_y + row * cell_h

        count = ch_frames.get(ch, 0)

        if count > 0:
            pct = count / max_count
            if pct >= 0.7:
                bg = "#FF0044"
                fg = "#FFFFFF"
            elif pct >= 0.3:
                bg = "#FF44FF"
                fg = "#FFFFFF"
            else:
                bg = "#660066"
                fg = "#FF88FF"
            d.rectangle((x, y, x + cell_w - 2, y + cell_h - 2), fill=bg)
            d.text((x + 1, y + 1), str(ch), font=FONT_SM, fill=fg)
        else:
            d.rectangle((x, y, x + cell_w - 2, y + cell_h - 2), fill="#0D0D0D",
                        outline="#1a1a1a")
            d.text((x + 1, y + 1), str(ch), font=FONT_SM, fill="#222")

    # Active channels list with full SSID
    active = sorted(ch_frames.items(), key=lambda x: -x[1])[:4]
    if active:
        ly = 80
        d.text((2, ly), "Active:", font=FONT_SM, fill="#888")
        ly += 9
        for ch_id, count in active:
            ssid = sniffer.assembler.ch_last_ssid.get(ch_id, "")
            d.text((2, ly), f"ch{ch_id}:{count} {ssid[:16]}", font=FONT_SM, fill="#FF88FF")
            ly += 9
            if ly > 107:
                break

    # Last SSID banner
    if last_ssid:
        d.rectangle((0, 108, 127, 115), fill="#1a001a")
        d.text((2, 109), f"Last: {last_ssid[:20]}", font=FONT_SM, fill="#00FF00")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "L/R:Dash K2:Ward K3:X", font=FONT_SM, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


def draw_sniff_live(lcd, sniffer, scroll):
    """Sniff dashboard 2: Live fragment feed."""
    w, h = lcd.width, lcd.height
    img = Image.new("RGB", (w, h), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#220022")
    d.text((2, 1), "SNIFF", font=FONT_BIG, fill="#FF44FF")
    fc = sniffer.assembler.frames_complete
    d.text((50, 2), f"Frames:{fc}", font=FONT_SM, fill="#00FF00")
    d.text((105, 2), f"P{sniffer.pcap.count}", font=FONT_SM, fill="#888")

    with sniffer._lock:
        lines = list(sniffer.sniff_lines)
    visible = lines[scroll:scroll + 8]
    for i, line in enumerate(visible):
        y = 16 + i * 12
        if "FRAME" in line:
            color = "#00FF00"
        elif "frag" in line:
            color = "#58a6ff"
        elif "ERR" in line:
            color = "#FF4444"
        else:
            color = "#CCCCCC"
        d.text((2, y), line[:24], font=FONT_SM, fill=color)

    if not lines:
        d.text((10, 35), "Listening ch1...", font=FONT, fill="#666")
        d.text((10, 50), "C5 must SNIFF+DEAUTH", font=FONT_SM, fill="#888")
        d.text((10, 65), f"Pkts: {sniffer.packets_total}", font=FONT_SM, fill="#555")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "L/R:Dash K2:Ward K3:X", font=FONT_SM, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)
    return len(lines)


def draw_sniff_stats(lcd, sniffer):
    """Sniff dashboard 2: Per-channel frame stats."""
    w, h = lcd.width, lcd.height
    img = Image.new("RGB", (w, h), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#220022")
    d.text((2, 1), "SNIFF STATS", font=FONT_BIG, fill="#FF44FF")
    d.text((90, 2), sniffer.elapsed(), font=FONT_SM, fill="#888")

    fc = sniffer.assembler.frames_complete
    pc = sniffer.pcap.count
    ch_frames = dict(sniffer.assembler.ch_frames)

    y = 17
    d.text((2, y), f"Complete frames: {fc}", font=FONT, fill="#00FF00")
    y += 12
    d.text((2, y), f"PCAP entries:    {pc}", font=FONT, fill="#CCCCCC")
    y += 12
    d.text((2, y), f"ESP-NOW packets: {sniffer.packets_total}", font=FONT, fill="#888")
    y += 14

    # Per-channel breakdown
    if ch_frames:
        d.text((2, y), "Per channel:", font=FONT, fill="#58a6ff")
        y += 11
        max_f = max(ch_frames.values()) if ch_frames else 1
        for ch_id in sorted(ch_frames.keys()):
            count = ch_frames[ch_id]
            ch_label = f"ch{ch_id}"
            d.text((6, y), ch_label, font=FONT_SM, fill="#CCC")
            d.text((36, y), str(count), font=FONT_SM, fill="#00FF00")
            _bar(d, 55, y + 1, 70, 7, count / max(1, max_f), "#FF44FF")
            y += 10
            if y > 108:
                break

    pcap_name = os.path.basename(sniffer.pcap.path)[:20]
    d.text((2, 108), pcap_name, font=FONT_SM, fill="#555")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "L/R:Dash K1:Reset K3:X", font=FONT_SM, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Splash / message screens
# ---------------------------------------------------------------------------

def draw_splash(lcd, msg, sub="", color="#00CCFF"):
    w, h = lcd.width, lcd.height
    img = Image.new("RGB", (w, h), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "ESP-NOW RX", font=FONT_BIG, fill=color)
    d.text((10, 45), msg[:22], font=FONT, fill="#FFAA00")
    if sub:
        d.text((10, 60), sub[:22], font=FONT_SM, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running

    if not SCAPY_OK:
        print("ERROR: scapy not installed. Run: pip3 install scapy")
        return 1

    GPIO.setmode(GPIO.BCM)
    for p in PINS.values():
        GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    # Interface selection
    draw_splash(lcd, "Select WiFi iface...")
    iface = select_interface(lcd, FONT, PINS, GPIO, iface_type="wifi",
                             title="ESP-NOW IFACE")
    if not iface:
        draw_splash(lcd, "No interface!", color="#FF4444")
        time.sleep(2)
        GPIO.cleanup()
        return 1

    # Monitor mode
    draw_splash(lcd, f"Monitor {iface} ch1...")
    ok, err = set_monitor_mode(iface, ESPNOW_CHANNEL)
    if not ok:
        draw_splash(lcd, "Monitor FAILED", err[:20], "#FF4444")
        time.sleep(3)
        GPIO.cleanup()
        return 1

    # GPS
    gps = GpsReader()
    gps.start()
    gps_status = "GPS OK" if GPS_OK else "No GPS module"
    draw_splash(lcd, "Starting sniffer...", gps_status)
    time.sleep(1)

    # Sniffer
    sniffer = EspNowSniffer(iface, gps)
    sniffer.start()

    # UI state
    mode = "ward"           # "ward" or "sniff"
    ward_dash = 0           # 0=live, 1=stats, 2=channels
    sniff_dash = 0          # 0=live, 1=stats
    scroll = 0
    WARD_DASH_COUNT = 4
    SNIFF_DASH_COUNT = 3

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "KEY2":
                mode = "sniff" if mode == "ward" else "ward"
                scroll = 0
                time.sleep(0.2)

            elif btn == "RIGHT":
                scroll = 0
                if mode == "ward":
                    ward_dash = (ward_dash + 1) % WARD_DASH_COUNT
                else:
                    sniff_dash = (sniff_dash + 1) % SNIFF_DASH_COUNT
                time.sleep(0.2)

            elif btn == "LEFT":
                scroll = 0
                if mode == "ward":
                    ward_dash = (ward_dash - 1) % WARD_DASH_COUNT
                else:
                    sniff_dash = (sniff_dash - 1) % SNIFF_DASH_COUNT
                time.sleep(0.2)

            elif btn == "KEY1":
                with sniffer._lock:
                    if mode == "ward":
                        sniffer.ward_aps.clear()
                    else:
                        sniffer.sniff_lines.clear()
                time.sleep(0.2)

            elif btn == "UP":
                scroll = max(0, scroll - 1)

            elif btn == "DOWN":
                scroll += 1

            # Draw current dashboard
            if mode == "ward":
                if ward_dash == 0:
                    max_items = draw_ward_live(lcd, sniffer, gps, scroll)
                    scroll = min(scroll, max(0, max_items - 7))
                elif ward_dash == 1:
                    draw_ward_stats(lcd, sniffer, gps)
                    scroll = 0
                elif ward_dash == 2:
                    draw_ward_2g(lcd, sniffer)
                    scroll = 0
                elif ward_dash == 3:
                    draw_ward_5g(lcd, sniffer)
                    scroll = 0
            else:
                if sniff_dash == 0:
                    draw_sniff_chanmap(lcd, sniffer)
                    scroll = 0
                elif sniff_dash == 1:
                    max_items = draw_sniff_live(lcd, sniffer, scroll)
                    scroll = min(scroll, max(0, max_items - 8))
                elif sniff_dash == 2:
                    draw_sniff_stats(lcd, sniffer)
                    scroll = 0

            time.sleep(0.05)

    finally:
        _running = False
        sniffer.stop()
        gps.stop()
        restore_managed_mode(iface)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
