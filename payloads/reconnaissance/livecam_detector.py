#!/usr/bin/env python3
"""
RaspyJack LiveCam Detector
================================
Standalone camera detection + live‑view monitoring.
Based on wardriving engine with camera‑specific detection and activity alerts.

Features:
- Camera detection via OUI/SSID patterns (same as cam_finder)
- Passive monitoring of camera traffic for live viewing
- TLS fingerprinting (JA3) and encrypted‑traffic detection
- mDNS/UPnP local camera discovery
- Real‑time alerts on LCD and console

Controls:
  KEY1 - Start / Stop scan
  KEY2 - Exit (WebUI: immediate, device: hold 2 s)
  KEY3 - Export data + alerts

Author: dag nazty
Date: 2026-04-05
"""

import os
import sys
import time
import subprocess
import hashlib
from datetime import datetime

# Add root directory to path
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))
sys.path.append('/root/Raspyjack/wifi/')

# Import wardriving engine (not cam_finder)
try:
    from payloads.reconnaissance.wardriving import (
        WardrivingScanner,
        LCD_AVAILABLE,
        SCAPY_AVAILABLE,
        GPS_AVAILABLE,
    )
except ImportError as e:
    print(f"ERROR: Failed to import wardriving: {e}")
    sys.exit(1)

# Try to import scapy
try:
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, IP, UDP, TCP, Raw, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy not available - live monitoring features will be limited")

# ---------------------------------------------------------------------------
# Camera OUI prefixes (copied from cam_finder.py)
# ---------------------------------------------------------------------------
CAMERA_OUIS = {
    # ---- Flock Safety ----
    "58:8E:81": "Flock Safety", "CC:CC:CC": "Flock Safety",
    "EC:1B:BD": "Flock Safety", "90:35:EA": "Flock Safety",
    "04:0D:84": "Flock Safety", "F0:82:C0": "Flock Safety",
    "1C:34:F1": "Flock Safety", "38:5B:44": "Flock Safety",
    "94:34:69": "Flock Safety", "B4:E3:F9": "Flock Safety",
    "70:C9:4E": "Flock Safety", "3C:91:80": "Flock Safety",
    "D8:F3:BC": "Flock Safety", "80:30:49": "Flock Safety",
    "14:5A:FC": "Flock Safety", "74:4C:A1": "Flock Safety",
    "08:3A:88": "Flock Safety", "9C:2F:9D": "Flock Safety",
    "94:08:53": "Flock Safety", "E4:AA:EA": "Flock Safety",
    # ---- Ring (Amazon) ----
    "50:14:79": "Ring",    "08:62:66": "Ring",    "B4:79:A7": "Ring",
    "DC:4F:22": "Ring",    "FC:E9:98": "Ring",    "74:42:7F": "Ring",
    "48:02:2A": "Ring",    "AC:9F:C3": "Ring",    "64:9A:63": "Ring",
    "B0:72:BF": "Ring",    "34:3E:A4": "Ring",    "54:E0:19": "Ring",
    "5C:47:5E": "Ring",    "90:48:6C": "Ring",    "CC:3B:FB": "Ring",
    "C4:DB:AD": "Ring",    "24:2B:D6": "Ring",    "00:FC:8B": "Ring",
    "B0:09:DA": "Ring",    "3C:24:F0": "Ring",    "D4:03:DC": "Ring",
    "A0:3E:6B": "Ring",    "90:A6:2F": "Ring",
    # ---- Blink (Amazon / Immedia) ----
    "3C:A0:70": "Blink",   "70:AD:43": "Blink",   "74:AB:93": "Blink",
    "50:DC:E7": "Blink",   "68:37:E9": "Blink",   "A0:02:DC": "Blink",
    "38:F7:3D": "Blink",   "18:7F:88": "Blink",   "34:D2:70": "Blink",
    "74:C6:3B": "Blink",   "18:74:2E": "Blink",   "FC:65:DE": "Blink",
    "B4:74:43": "Blink",   "9C:76:13": "Blink",
    # ---- Amazon (generic Ring/Blink/Echo) ----
    "44:73:D6": "Amazon",  "AC:63:BE": "Amazon",
    "E0:B9:4D": "Amazon",  "FC:A1:83": "Amazon",
    # ---- Nest / Google ----
    "00:24:E4": "Nest",    "18:B4:30": "Nest",    "30:8C:FB": "Nest",
    "64:16:66": "Nest",    "F4:F5:D8": "Nest",    "F4:F5:E8": "Nest",
    # ---- Wyze ----
    "78:8B:77": "Wyze",    "2C:AA:8E": "Wyze",
    "D0:3F:27": "Wyze",    "7C:78:B2": "Wyze",
    # ---- Arlo (Netgear) ----
    "00:1F:7A": "Arlo",    "00:0F:B5": "Arlo",
    "28:B3:71": "Arlo",    "9C:34:26": "Arlo",
    "CC:40:D0": "Arlo",    "84:38:35": "Arlo",
    # ---- Eufy (Anker) ----
    "8C:85:80": "Eufy",    "98:8E:79": "Eufy",
    # ---- Hikvision ----
    "00:18:DD": "Hikvision", "C0:56:E3": "Hikvision",
    "4C:BD:8F": "Hikvision", "BC:AD:28": "Hikvision",
    "44:19:B6": "Hikvision", "C4:2F:90": "Hikvision",
    "A4:CF:12": "Hikvision",
    # ---- Dahua ----
    "3C:EF:8C": "Dahua",   "A0:BD:1D": "Dahua",   "E0:50:8B": "Dahua",
    # ---- Reolink ----
    "8C:85:90": "Reolink",  "EC:71:DB": "Reolink",  "B8:A4:4F": "Reolink",
    # ---- Amcrest ----
    "9C:8E:CD": "Amcrest",
    # ---- SimpliSafe ----
    "7C:64:56": "SimpliSafe",
    # ---- TP-Link (Tapo / Kasa cams) ----
    "A0:63:91": "TP-Link",  "B0:4E:26": "TP-Link",
    "CC:32:E5": "TP-Link",  "F4:F2:6D": "TP-Link",
    "60:32:B1": "TP-Link",  "6C:5A:B0": "TP-Link",
    "54:AF:97": "TP-Link",  "5C:62:8B": "TP-Link",
    # ---- Ubiquiti (UniFi Protect) ----
    "74:83:C2": "UniFi",   "04:18:D6": "UniFi",   "18:E8:29": "UniFi",
    "24:A4:3C": "UniFi",   "44:D9:E7": "UniFi",   "68:72:51": "UniFi",
    "68:D7:9A": "UniFi",   "78:45:58": "UniFi",   "80:2A:A8": "UniFi",
    "9C:05:D6": "UniFi",   "AC:8B:A9": "UniFi",   "B4:FB:E4": "UniFi",
    "DC:9F:DB": "UniFi",   "E0:63:DA": "UniFi",   "F4:92:BF": "UniFi",
    "FC:EC:DA": "UniFi",   "24:5A:4C": "UniFi",   "78:8A:20": "UniFi",
    # ---- Axis Communications ----
    "00:40:8C": "Axis",    "AC:CC:8E": "Axis",
    # ---- Samsung SmartCam ----
    "D0:03:9B": "Samsung",
    # ---- FLIR ----
    "00:40:7F": "FLIR",
    # ---- Vivotek ----
    "00:02:D1": "Vivotek",
    # ---- Swann ----
    "7C:2E:BD": "Swann",
    # ---- Lorex ----
    "00:0E:8F": "Lorex",
    # ---- Logitech (Circle) ----
    "C4:AD:34": "Logitech",
    # ---- Foscam ----
    "C0:56:27": "Foscam",
    # ---- ESP32/ESP8266 (DIY cameras) ----
    "24:0A:C4": "ESP32",   "30:AE:A4": "ESP32",   "3C:61:05": "ESP32",
    "80:7D:3A": "ESP32",   "84:0D:8E": "ESP32",   "84:F3:EB": "ESP32",
    "90:97:D5": "ESP32",   "A0:20:A6": "ESP32",   "AC:67:B2": "ESP32",
    "BC:DD:C2": "ESP32",   "C8:C9:A3": "ESP32",   "CC:50:E3": "ESP32",
    "D8:A0:1D": "ESP32",   "E8:DB:84": "ESP32",   "EC:FA:BC": "ESP32",
    "FC:F5:C4": "ESP32",
    # ---- Raspberry Pi (DIY cameras) ----
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
}

# SSID patterns that indicate a camera device
CAMERA_SSID_PATTERNS = [
    # (pattern, vendor/label)
    ("Ring-", "Ring"),       ("Ring_", "Ring"),       ("RING-", "Ring"),
    ("RING_", "Ring"),       ("Ring Setup", "Ring"),   ("RING SETUP", "Ring"),
    ("Blink-", "Blink"),    ("BlinkCam-", "Blink"),  ("BLINK-", "Blink"),
    ("Blink_Up-", "Blink"), ("BLINK_UP-", "Blink"),  ("Blink Setup", "Blink"),
    ("BLINK SETUP", "Blink"),
    ("Arlo-", "Arlo"),
    ("Nest-", "Nest"),
    ("Wyze-", "Wyze"),
    ("Camera-", "Camera"),   ("CAM-", "Camera"),
    ("Doorbell-", "Doorbell"),
    ("IPC-", "IP Camera"),   ("WebCam-", "Camera"),
    ("NVR-", "NVR"),         ("DVR-", "DVR"),
    ("FlockCam-", "Flock Safety"), ("flock", "Flock Safety"),
    ("Flock", "Flock Safety"),     ("FLOCK", "Flock Safety"),
    ("FS Ext Battery", "Flock Safety"), ("FS_", "Flock Safety"),
    ("Penguin", "Flock Safety"),   ("Pigvision", "Flock Safety"),
    ("Amcrest-", "Amcrest"),  ("Reolink-", "Reolink"),
    ("Hikvision-", "Hikvision"), ("Dahua-", "Dahua"),
    ("TP-Link-", "TP-Link"), ("Foscam-", "Foscam"),
    ("Swann-", "Swann"),     ("Lorex-", "Lorex"),
    ("QSee-", "QSee"),       ("ANNKE-", "ANNKE"),
    ("Uniview-", "Uniview"), ("Bosch-", "Bosch"),
    ("Pelco-", "Pelco"),     ("Axis-", "Axis"),
    ("Sony-", "Sony"),       ("Panasonic-", "Panasonic"),
    ("Samsung-", "Samsung"),
    # DIY camera SSIDs
    ("ESP32-CAM", "ESP32"), ("ESP-CAM", "ESP32"), ("ESP_CAM", "ESP32"),
    ("ESP32_CAM", "ESP32"), ("CAM-ESP", "ESP32"), ("ESP-CAMERA", "ESP32"),
    ("RPi-", "Raspberry Pi"), ("RPI-", "Raspberry Pi"), ("raspberrypi", "Raspberry Pi"),
    ("pistream", "Raspberry Pi"), ("rpi-cam", "Raspberry Pi"), ("rpi_cam", "Raspberry Pi"),
]

# mDNS (port 5353) and SSDP/UPnP (port 1900) camera service patterns
MDNS_CAMERA_SERVICES = [
    "_ring._tcp.local",
    "_blink._tcp.local",
    "_camera._tcp.local",
    "_axis-video._tcp.local",
    "_ipcamera._tcp.local",
    "_homekit._tcp.local",
    "_hap._tcp.local",
]

UPNP_CAMERA_DEVICES = [
    "urn:schemas-upnp-org:device:Camera:1",
    "urn:schemas-upnp-org:device:SecurityCamera:1",
    "urn:schemas-upnp-org:device:VideoCamera:1",
    "urn:schemas-upnp-org:service:AVTransport:1",
    "urn:schemas-upnp-org:device:MediaServer:1",
]

# Known TLS JA3 fingerprints for camera vendors (MD5 of JA3 string)
# Format: "ja3_hash": "vendor - description"
KNOWN_JA3_HASHES = {
    # Example (not real):
    # "a387fcf6a6c28f0a6b8a3c6e2e4c1f2a": "Ring Camera - TLS 1.2, ECDHE-RSA-AES128-GCM-SHA256",
    # Add real hashes from research
}


def _is_camera_mac(mac):
    """Return vendor name if MAC matches a known camera OUI, else None."""
    oui = (mac or "")[:8].upper()
    return CAMERA_OUIS.get(oui)


def _is_camera_ssid(ssid):
    """Return vendor/label if SSID matches a known camera pattern, else None."""
    if not ssid:
        return None
    for pattern, label in CAMERA_SSID_PATTERNS:
        if pattern in ssid:
            return label
    # Generic "cam" substring check (case-insensitive)
    if "cam" in ssid.lower():
        return "Camera"
    return None


class LiveCamDetector(WardrivingScanner):
    """
    Standalone camera + live‑view monitor.
    Inherits scanning engine from WardrivingScanner and adds camera detection
    plus live‑view activity alerts.
    """

    def __init__(self):
        # Initialize parent (WardrivingScanner)
        super().__init__()
        # Ensure parent's LCD loop doesn't run
        self.lcd_running = False

        # Redirect loot to LiveCamDetector folder
        self.loot_dir = f"{self.base_dir}/loot/LiveCamDetector"
        os.makedirs(self.loot_dir, exist_ok=True)
        self.db_path = f"{self.loot_dir}/livecam_detector.db"
        self.log_file = os.path.join(self.loot_dir, "livecam_detector.log")

        # Recreate DB with extra tables
        self._init_livecam_db()

        # State for camera and live‑view detection
        self.camera_macs = set()                # MACs identified as cameras
        self.camera_vendors = {}                # MAC → vendor mapping
        self.alerts = []                        # List of alert dicts
        self.live_viewing = {}                  # MAC → last live viewing timestamp
        self.rtp_detected = set()               # MACs with RTP traffic
        self.rtsp_detected = set()              # MACs with RTSP traffic
        self.quic_detected = set()              # MACs with QUIC/WebRTC-like traffic
        self.dtls_detected = set()              # MACs with DTLS traffic
        self.stun_detected = set()              # MACs with STUN traffic
        self.packet_counts = {}                 # MAC → total packet count
        self.packet_timestamps = {}             # MAC → list of timestamps (sliding window)
        self.packet_sizes = {}                  # MAC → list of packet sizes (sliding window)
        self.packet_intervals = {}              # MAC → list of inter-arrival times
        self.debug = False                      # Disable verbose logging (user complained about spam)

        self.log("LiveCam Detector active (wardriving engine)")

    def _init_livecam_db(self):
        """Create DB tables for cameras and live-view alerts."""
        import sqlite3
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            # Cameras table
            c.execute('''CREATE TABLE IF NOT EXISTS cameras (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT UNIQUE,
                vendor TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                ssid TEXT,
                channel INTEGER,
                signal_strength INTEGER,
                gps_lat REAL,
                gps_lon REAL
            )''')
            # Live-view alerts
            c.execute('''CREATE TABLE IF NOT EXISTS live_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                camera_mac TEXT,
                alert_type TEXT,
                detail TEXT,
                timestamp TIMESTAMP,
                FOREIGN KEY (camera_mac) REFERENCES cameras (mac)
            )''')
            c.execute("CREATE INDEX IF NOT EXISTS idx_cameras_mac ON cameras(mac)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_live_alerts_mac ON live_alerts(camera_mac)")
            conn.commit()
            conn.close()
            self.log("LiveCam DB initialized")
        except Exception as e:
            self.log(f"LiveCam DB init error: {e}")

    def store_camera(self, mac, vendor, ssid="", channel=None, signal=None):
        """Insert or update camera in DB."""
        import sqlite3
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            now = datetime.now().isoformat()
            lat = self.gps_data.get("latitude") if self.gps_data else None
            lon = self.gps_data.get("longitude") if self.gps_data else None
            c.execute('''INSERT OR REPLACE INTO cameras
                (mac, vendor, first_seen, last_seen, ssid, channel, signal_strength, gps_lat, gps_lon)
                VALUES (?, ?, COALESCE((SELECT first_seen FROM cameras WHERE mac = ?), ?),
                        ?, ?, ?, ?, ?, ?)''',
                (mac, vendor, mac, now, now, ssid, channel, signal, lat, lon))
            conn.commit()
            conn.close()
        except Exception as e:
            self.log(f"Store camera error: {e}")

    def store_alert(self, camera_mac, alert_type, detail):
        """Record an alert in DB."""
        import sqlite3
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('''INSERT INTO live_alerts
                (camera_mac, alert_type, detail, timestamp)
                VALUES (?, ?, ?, ?)''',
                (camera_mac, alert_type, detail, datetime.now().isoformat()))
            conn.commit()
            conn.close()
        except Exception as e:
            self.log(f"Store alert error: {e}")
        # Also keep in memory for display
        self.alerts.append({
            "mac": camera_mac,
            "type": alert_type,
            "detail": detail,
            "time": datetime.now(),
        })
        self.log(f"ALERT: {camera_mac} - {alert_type} - {detail}")

    def _is_tls_client_hello(self, packet):
        """Return True if packet appears to be a TLS ClientHello."""
        if not packet.haslayer(Raw):
            return False
        raw = packet[Raw].load
        if len(raw) < 5:
            return False
        # TLS handshake: first byte 0x16 (handshake), next two bytes = version
        if raw[0] == 0x16 and raw[1:3] in (b'\x03\x03', b'\x03\x01', b'\x03\x02'):
            # Handshake type (offset 5) should be 0x01 for ClientHello
            if len(raw) >= 6 and raw[5] == 0x01:
                return True
        return False

    def _extract_tls_fingerprint(self, packet):
        """
        Extract JA3 fingerprint from TLS ClientHello.
        Returns (ja3_string, ja3_hash) or (None, None) if not a ClientHello.
        """
        if not packet.haslayer(Raw):
            return None, None
        raw = packet[Raw].load
        if len(raw) < 5:
            return None, None
        # Check TLS record header
        if raw[0] != 0x16:  # handshake
            return None, None
        # TLS versions we care about
        if raw[1:3] not in (b'\x03\x03', b'\x03\x01', b'\x03\x02'):
            return None, None
        # Handshake type at offset 5
        if len(raw) < 6 or raw[5] != 0x01:  # ClientHello
            return None, None
        
        # Start parsing after TLS record header (5 bytes)
        ptr = 5
        # Handshake type must be ClientHello
        if len(raw) < ptr + 1 or raw[ptr] != 0x01:
            return None, None
        ptr += 1
        # Handshake length (3 bytes)
        if len(raw) < ptr + 3:
            return None, None
        hs_len = (raw[ptr] << 16) | (raw[ptr+1] << 8) | raw[ptr+2]
        ptr += 3
        if len(raw) < ptr + hs_len:
            return None, None
        # Handshake version (2 bytes)
        if len(raw) < ptr + 2:
            return None, None
        version = raw[ptr:ptr+2]
        ptr += 2
        # Random (32 bytes)
        if len(raw) < ptr + 32:
            return None, None
        ptr += 32
        # Session ID length (1 byte)
        if len(raw) < ptr + 1:
            return None, None
        session_id_len = raw[ptr]
        ptr += 1
        if len(raw) < ptr + session_id_len:
            return None, None
        ptr += session_id_len
        # Cipher suites length (2 bytes)
        if len(raw) < ptr + 2:
            return None, None
        cipher_len = (raw[ptr] << 8) | raw[ptr+1]
        ptr += 2
        if cipher_len % 2 != 0 or len(raw) < ptr + cipher_len:
            return None, None
        cipher_suites = []
        for i in range(0, cipher_len, 2):
            cipher_suites.append((raw[ptr+i] << 8) | raw[ptr+i+1])
        ptr += cipher_len
        # Compression methods length (1 byte)
        if len(raw) < ptr + 1:
            return None, None
        compression_len = raw[ptr]
        ptr += 1
        if len(raw) < ptr + compression_len:
            return None, None
        ptr += compression_len
        # Extensions length (2 bytes)
        if len(raw) < ptr + 2:
            return None, None
        extensions_len = (raw[ptr] << 8) | raw[ptr+1]
        ptr += 2
        if len(raw) < ptr + extensions_len:
            return None, None
        extensions = []
        elliptic_curves = []
        ec_point_formats = []
        ext_end = ptr + extensions_len
        while ptr < ext_end:
            if len(raw) < ptr + 4:
                break
            ext_type = (raw[ptr] << 8) | raw[ptr+1]
            ext_len = (raw[ptr+2] << 8) | raw[ptr+3]
            ptr += 4
            if len(raw) < ptr + ext_len:
                break
            # Check for supported_groups (0x000A)
            if ext_type == 0x000A:
                # Parse elliptic curve list
                if ext_len >= 2:
                    curve_list_len = (raw[ptr] << 8) | raw[ptr+1]
                    if curve_list_len >= 2 and ext_len >= 2 + curve_list_len:
                        for j in range(2, 2 + curve_list_len, 2):
                            curve = (raw[ptr+j] << 8) | raw[ptr+j+1]
                            elliptic_curves.append(curve)
            # Check for ec_point_formats (0x000B)
            elif ext_type == 0x000B:
                if ext_len >= 1:
                    fmt_len = raw[ptr]
                    if fmt_len >= 1 and ext_len >= 1 + fmt_len:
                        for j in range(1, 1 + fmt_len):
                            ec_point_formats.append(raw[ptr+j])
            extensions.append(ext_type)
            ptr += ext_len
        
        # Build JA3 string
        ja3_parts = []
        # TLS version (decimal)
        ja3_parts.append(str((version[0] << 8) | version[1]))
        # Cipher suites (sorted, decimal)
        cipher_sorted = sorted(set(cipher_suites))
        ja3_parts.append("-".join(str(c) for c in cipher_sorted))
        # Extensions (sorted, decimal)
        ext_sorted = sorted(set(extensions))
        ja3_parts.append("-".join(str(e) for e in ext_sorted))
        # Elliptic curves (if present)
        if elliptic_curves:
            curve_sorted = sorted(set(elliptic_curves))
            ja3_parts.append("-".join(str(c) for c in curve_sorted))
        else:
            ja3_parts.append("")
        # EC point formats (if present)
        if ec_point_formats:
            fmt_sorted = sorted(set(ec_point_formats))
            ja3_parts.append("-".join(str(f) for f in fmt_sorted))
        else:
            ja3_parts.append("")
        
        ja3_string = ",".join(ja3_parts)
        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
        return ja3_string, ja3_hash

    def _process_camera_probe(self, packet):
        """Detect cameras from probe requests."""
        try:
            src_mac = packet[Dot11].addr2  # source MAC
            if not src_mac:
                return

            vendor = _is_camera_mac(src_mac)
            detection = "PROBE"

            # Check probed SSID
            ssid = ""
            try:
                if packet.haslayer(Dot11Elt):
                    ssid = packet[Dot11Elt].info.decode("utf-8", errors="ignore")
            except Exception:
                pass

            if vendor is None:
                vendor = _is_camera_ssid(ssid)
            if vendor is None:
                return

            self._add_camera_from_mac(src_mac, vendor, detection, ssid=ssid,
                                       signal=getattr(packet, "dBm_AntSignal", None))
        except Exception:
            pass

    def _process_data_frame(self, packet):
        """Check source and destination MACs in data frames."""
        try:
            dot11 = packet[Dot11]
            # addr1 = destination, addr2 = source (transmitter)
            for addr, role in [(dot11.addr2, "src"), (dot11.addr1, "dst")]:
                if not addr or addr == "ff:ff:ff:ff:ff:ff":
                    continue
                mac_upper = addr.upper()
                # Count packets for known cameras
                if mac_upper in self.camera_macs:
                    self._add_packet_timestamp(mac_upper, packet_size=len(packet))
                    if self.debug and self.packet_counts.get(mac_upper, 0) <= 5:
                        self.log(f"DATA frame: {mac_upper} {role}")
                # Detect new cameras via OUI
                vendor = _is_camera_mac(addr)
                if vendor:
                    self._add_camera_from_mac(
                        addr, vendor, "DATA",
                        signal=getattr(packet, "dBm_AntSignal", None),
                    )
                    return  # one match per frame is enough
        except Exception:
            pass

    def _add_camera_from_mac(self, mac, vendor, detection, ssid="", signal=None):
        """
        Add or update a camera entry from a MAC match.
        """
        mac_upper = mac.upper()

        # Already seen?
        if mac_upper in self.networks:
            self.networks[mac_upper]["last_seen"] = datetime.now().isoformat()
            if self.gps_data:
                self.networks[mac_upper]["gps_coordinates"] = self.gps_data.copy()
        else:
            network_info = {
                "ssid": ssid,
                "bssid": mac_upper,
                "channel": self.current_channel,
                "frequency": self.channel_to_frequency(self.current_channel),
                "security": {"type": "N/A", "encryption": "N/A",
                             "cipher": "N/A", "authentication": "N/A"},
                "signal_strength": signal,
                "vendor": vendor,
                "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
                "gps_coordinates": self.gps_data.copy() if self.gps_data else None,
            }

            self.networks[mac_upper] = network_info
            self.total_networks += 1
            self.store_network_in_db(network_info)

        # Add to our tracking (if new camera)
        is_new_camera = mac_upper not in self.camera_macs
        self.camera_macs.add(mac_upper)
        self.camera_vendors[mac_upper] = vendor
        self.store_camera(mac_upper, vendor, ssid=ssid, channel=self.current_channel, signal=signal)

        if is_new_camera:
            self.log(f"CAMERA [{detection}]: {vendor} | {ssid or '(hidden)'} | {mac_upper} | Ch {self.current_channel}")
            print(f"CAMERA [{detection}]: {vendor} | {ssid or '(hidden)'} | {mac_upper} | Ch {self.current_channel}")

    def _process_ip_packet(self, packet):
        """Analyze live-view protocol traffic from known camera MACs."""
        if not SCAPY_AVAILABLE:
            return

        # Need to get MAC from Dot11 layer if present
        src_mac = None
        if packet.haslayer(Dot11):
            src_mac = packet[Dot11].addr2
        if not src_mac or src_mac.upper() not in self.camera_macs:
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        mac_upper = src_mac.upper()
        
        if self.debug:
            self.log(f"IP from {mac_upper}: {src_ip} -> {dst_ip}")
        
        # Packet rate detection
        packet_rate = self._add_packet_timestamp(mac_upper, packet_size=len(packet))
        count = self.packet_counts.get(mac_upper, 0)
        
        # Debug logging: first 5 packets, then every 20th
        if self.debug and (count <= 5 or count % 20 == 0):
            proto = packet[IP].proto
            if packet.haslayer(TCP):
                dport = packet[TCP].dport
                sport = packet[TCP].sport
                self.log(f"DEBUG: {mac_upper} -> {dst_ip}:{dport} TCP (pkt#{count}, rate={packet_rate})")
            elif packet.haslayer(UDP):
                dport = packet[UDP].dport
                sport = packet[UDP].sport
                self.log(f"DEBUG: {mac_upper} -> {dst_ip}:{dport} UDP (pkt#{count}, rate={packet_rate})")
            else:
                self.log(f"DEBUG: {mac_upper} -> {dst_ip} proto {proto} (pkt#{count}, rate={packet_rate})")
        # mDNS (port 5353) camera service discovery
        if packet.haslayer(UDP) and packet.dport == 5353:
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                for service in MDNS_CAMERA_SERVICES:
                    if service in payload:
                        self.store_alert(mac_upper, 'MDNS_CAMERA',
                                         f'mDNS service: {service}')
                        break
        
        # SSDP/UPnP (port 1900) device discovery
        if packet.haslayer(UDP) and (packet.dport == 1900 or packet.sport == 1900):
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                # Check for M-SEARCH or NOTIFY with camera device strings
                if 'M-SEARCH' in payload or 'NOTIFY' in payload:
                    for device in UPNP_CAMERA_DEVICES:
                        if device in payload:
                            self.store_alert(mac_upper, 'UPNP_CAMERA',
                                             f'UPnP device: {device}')
                            break

        # Live viewing detection
        # RTSP (port 554)
        if packet.haslayer(TCP) and (packet.dport == 554 or packet.sport == 554):
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                if any(method in payload for method in ['DESCRIBE', 'SETUP', 'PLAY', 'TEARDOWN']):
                    self.rtsp_detected.add(mac_upper)
                    self.live_viewing[mac_upper] = time.time()
                    self.store_alert(mac_upper, 'LIVE_RTSP', f'RTSP traffic to {dst_ip}:{packet.dport}')
        
        # RTP (UDP high ports, typically 16384-32767)
        if packet.haslayer(UDP) and packet.dport >= 16384 and packet.dport < 32768:
            # Check for RTP version 2 (first byte bits 6-7 = 2)
            if packet.haslayer(Raw) and len(packet[Raw].load) >= 12:
                first_byte = packet[Raw].load[0]
                if (first_byte >> 6) == 2:
                    self.rtp_detected.add(mac_upper)
                    self.live_viewing[mac_upper] = time.time()
                    self.store_alert(mac_upper, 'LIVE_RTP', f'RTP traffic to {dst_ip}:{packet.dport}')
        
        # STUN (ports 3478, 5349)
        if packet.haslayer(UDP) and (packet.dport in (3478, 5349) or packet.sport in (3478, 5349)):
            if packet.haslayer(Raw) and len(packet[Raw].load) >= 20:
                # STUN magic cookie 0x2112A442
                if packet[Raw].load[4:8] == b'\x21\x12\xA4\x42':
                    self.stun_detected.add(mac_upper)
                    self.live_viewing[mac_upper] = time.time()
                    self.store_alert(mac_upper, 'LIVE_STUN', f'STUN traffic to {dst_ip}:{packet.dport}')

        # QUIC (UDP 443, often used for WebRTC/HTTP3)
        if packet.haslayer(UDP) and (packet.dport == 443 or packet.sport == 443):
            if packet.haslayer(Raw) and len(packet[Raw].load) >= 5:
                first_byte = packet[Raw].load[0]
                # QUIC long header: first two bits = 0b11
                if (first_byte & 0xC0) == 0xC0:
                    self.quic_detected.add(mac_upper)
                    self.live_viewing[mac_upper] = time.time()
                    self.store_alert(mac_upper, 'LIVE_QUIC', f'QUIC traffic to {dst_ip}:{packet.dport}')

        # DTLS (TLS over UDP, used by WebRTC data channels)
        if packet.haslayer(UDP):
            if packet.haslayer(Raw) and len(packet[Raw].load) >= 3:
                first_byte = packet[Raw].load[0]
                # DTLS handshake: content type 0x16 (22)
                if first_byte == 0x16:
                    # DTLS version 1.x: 0xFE 0xFD - 0xFE 0xFF
                    second_byte = packet[Raw].load[1]
                    third_byte = packet[Raw].load[2]
                    if second_byte == 0xFE and third_byte in (0xFD, 0xFE, 0xFF):
                        self.dtls_detected.add(mac_upper)
                        self.live_viewing[mac_upper] = time.time()
                        self.store_alert(mac_upper, 'LIVE_DTLS', f'DTLS traffic to {dst_ip}:{packet.dport}')

        # Optional TLS fingerprinting for visible 443 handshakes. This stays as a
        # live-stream hint only.
        if packet.haslayer(TCP) and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
            _ja3_string, ja3_hash = self._extract_tls_fingerprint(packet)
            if ja3_hash is not None:
                if not hasattr(self, 'tls_fingerprints'):
                    self.tls_fingerprints = {}
                if mac_upper not in self.tls_fingerprints:
                    self.tls_fingerprints[mac_upper] = set()
                if ja3_hash not in self.tls_fingerprints[mac_upper]:
                    self.tls_fingerprints[mac_upper].add(ja3_hash)
                    vendor_info = KNOWN_JA3_HASHES.get(ja3_hash)
                    if vendor_info:
                        self.store_alert(mac_upper, "TLS_FINGERPRINT",
                                         f"TLS fingerprint {ja3_hash} matches {vendor_info}")

    def _is_camera_live(self, mac):
        """Return True if camera has shown live viewing activity in last 30 seconds."""
        if mac not in self.live_viewing:
            return False
        return time.time() - self.live_viewing[mac] < 30.0

    def _add_packet_timestamp(self, mac, packet_size=None):
        """Record packet timestamp and size for rate/throughput detection; return packets in last 5 seconds."""
        now = time.time()
        
        # Initialize structures if needed
        if mac not in self.packet_timestamps:
            self.packet_timestamps[mac] = []
            self.packet_sizes[mac] = []
            self.packet_intervals[mac] = []
        
        timestamps = self.packet_timestamps[mac]
        sizes = self.packet_sizes[mac]
        intervals = self.packet_intervals[mac]
        
        # Remove data older than 5 seconds
        cutoff = now - 5.0
        while timestamps and timestamps[0] < cutoff:
            timestamps.pop(0)
            if sizes:
                sizes.pop(0)
            if intervals:
                intervals.pop(0)
        
        # Calculate interval since last packet
        if timestamps:
            intervals.append(now - timestamps[-1])
        else:
            intervals.append(0.0)
        
        # Add current timestamp and size
        timestamps.append(now)
        sizes.append(packet_size if packet_size is not None else 0)
        
        # Increment total packet counter
        self.packet_counts[mac] = self.packet_counts.get(mac, 0) + 1
        
        # Calculate throughput (bytes/sec) if we have size data
        throughput = 0
        if packet_size is not None and len(timestamps) >= 2:
            time_window = timestamps[-1] - timestamps[0]
            if time_window > 0:
                total_bytes = sum(sizes)
                throughput = total_bytes / time_window  # bytes/sec
        
        # Detection logic
        packet_rate = len(timestamps)
        
        # High packet rate detection (>10 packets in 5s)
        if packet_rate > 5:
            self.live_viewing[mac] = now
            if mac not in self.rtp_detected and mac not in self.rtsp_detected:
                if not hasattr(self, '_high_rate_alerts'):
                    self._high_rate_alerts = set()
                if mac not in self._high_rate_alerts:
                    self._high_rate_alerts.add(mac)
                    self.store_alert(mac, 'HIGH_RATE', 
                                    f'High packet rate: {packet_rate} packets in 5s ({throughput:.0f} B/s)')
        
        # High throughput detection (>50 KB/s = ~400 kbps)
        if throughput > 10000:  # 10 KB/s
            self.live_viewing[mac] = now
            if not hasattr(self, '_high_throughput_alerts'):
                self._high_throughput_alerts = set()
            if mac not in self._high_throughput_alerts:
                self._high_throughput_alerts.add(mac)
                self.store_alert(mac, 'HIGH_THROUGHPUT',
                                f'High throughput: {throughput/1024:.1f} KB/s ({throughput*8/1000:.1f} kbps)')
        
        # Large packet detection (video-like, >1200 bytes)
        if packet_size is not None and packet_size > 800:
            if not hasattr(self, '_large_packet_alerts'):
                self._large_packet_alerts = {}
            if mac not in self._large_packet_alerts:
                self._large_packet_alerts[mac] = []
            # Record timestamp of large packet
            self._large_packet_alerts[mac].append(now)
            # Clean old timestamps (>5 seconds)
            self._large_packet_alerts[mac] = [ts for ts in self._large_packet_alerts[mac] if now - ts < 5.0]
            # Alert if 3+ large packets in 5 seconds
            if len(self._large_packet_alerts[mac]) >= 3 and len(self._large_packet_alerts[mac]) == 3:  # Only on third
                self.store_alert(mac, 'LARGE_PACKETS',
                                f'Large packets ({packet_size} bytes) typical of video streaming')
        
        # Burst detection (multiple packets within short time)
        if len(timestamps) >= 3:
            # Check if last 3 packets arrived within 200ms
            if timestamps[-1] - timestamps[-3] < 0.2:
                if not hasattr(self, '_burst_alerts'):
                    self._burst_alerts = set()
                if mac not in self._burst_alerts:
                    self._burst_alerts.add(mac)
                    self.store_alert(mac, 'BURST',
                                     f'Burst of 3 packets within {timestamps[-1] - timestamps[-3]:.3f}s')
        
        return packet_rate

    # ------------------------------------------------------------------
    # Override LCD display for LiveCam detection
    # ------------------------------------------------------------------
    def _process_camera_beacon(self, packet):
        """Detect cameras from beacons/probe-responses."""
        try:
            bssid = packet[Dot11].addr3
            if not bssid:
                return
            bssid_upper = bssid.upper()

            # Extract SSID
            ssid = ""
            try:
                if packet.haslayer(Dot11Elt):
                    ssid = packet[Dot11Elt].info.decode("utf-8", errors="ignore")
            except Exception:
                pass

            # Check OUI and SSID patterns
            vendor = _is_camera_mac(bssid)
            if vendor is None:
                vendor = _is_camera_ssid(ssid)
            if vendor is None:
                return   # not a camera

            # Get signal strength from packet (available for both new and seen)
            signal_strength = getattr(packet, "dBm_AntSignal", None)
            
            # Already seen?
            if bssid_upper in self.networks:
                self.networks[bssid_upper]["last_seen"] = datetime.now().isoformat()
                if self.gps_data:
                    self.networks[bssid_upper]["gps_coordinates"] = self.gps_data.copy()
                # Update signal strength if we have it
                if signal_strength is not None:
                    self.networks[bssid_upper]["signal_strength"] = signal_strength
            else:
                # Add to networks (parent's storage)
                channel = self.current_channel
                try:
                    if packet.haslayer(Dot11Elt):
                        elt = packet[Dot11Elt]
                        while elt:
                            if elt.ID == 3 and len(elt.info) >= 1:
                                channel = ord(elt.info[:1])
                                break
                            elt = (
                                elt.payload
                                if hasattr(elt, "payload") and isinstance(elt.payload, Dot11Elt)
                                else None
                            )
                except Exception:
                    pass

                security = self.detect_security(packet) if hasattr(self, 'detect_security') else {"type": "N/A"}

                network_info = {
                    "ssid": ssid,
                    "bssid": bssid_upper,
                    "channel": channel,
                    "frequency": self.channel_to_frequency(channel),
                    "security": security,
                    "signal_strength": signal_strength,
                    "vendor": vendor,
                    "first_seen": datetime.now().isoformat(),
                    "last_seen": datetime.now().isoformat(),
                    "gps_coordinates": self.gps_data.copy() if self.gps_data else None,
                }

                self.networks[bssid_upper] = network_info
                self.total_networks += 1
                self.store_network_in_db(network_info)

            # Add to our camera tracking
            is_new_camera = bssid_upper not in self.camera_macs
            self.camera_macs.add(bssid_upper)
            self.camera_vendors[bssid_upper] = vendor
            self.store_camera(bssid_upper, vendor, ssid=ssid, channel=self.current_channel, signal=signal_strength)

            if is_new_camera:
                self.log(f"CAMERA [BEACON]: {vendor} | {ssid or '(hidden)'} | {bssid} | Ch {self.current_channel}")
                print(f"CAMERA [BEACON]: {vendor} | {ssid or '(hidden)'} | {bssid} | Ch {self.current_channel}")
            # Log camera count periodically
            if hasattr(self, 'camera_detection_count'):
                self.camera_detection_count += 1
                if self.debug and self.camera_detection_count % 5 == 0:
                    self.log(f"Camera detection count: {self.camera_detection_count}, unique cameras: {len(self.camera_macs)}")
            else:
                self.camera_detection_count = 1

        except Exception as e:
            self.log(f"Camera beacon processing error: {e}")

    def packet_capture(self):
        """Capture management + data frames for camera detection."""
        try:
            if self.debug:
                self.log("LiveCam packet capture started")
            print(f"Starting packet capture on {self.monitor_interface}", flush=True)

            result = subprocess.run(
                ['iwconfig', self.monitor_interface],
                capture_output=True, text=True,
            )
            print(f"Interface check: {result.stdout[:100]}", flush=True)

            if "Mode:Monitor" not in result.stdout:
                print("ERROR: Interface not in monitor mode!")
                return

            print("Testing packet capture (5 seconds)...", flush=True)
            test_packets = sniff(iface=self.monitor_interface, timeout=5, count=5)
            print(f"Test captured {len(test_packets)} packets", flush=True)

            if len(test_packets) == 0:
                print("WARNING: No packets in test capture", flush=True)
                test_packets2 = sniff(iface=self.monitor_interface, timeout=3, count=3)
                print(f"Unfiltered test: {len(test_packets2)} packets", flush=True)

            print("Starting main capture (mgt + data frames)...", flush=True)
            packet_count = 0

            def processor(pkt):
                nonlocal packet_count
                packet_count += 1
                if packet_count % 500 == 0:
                    print(f"Processed {packet_count} packets | Cameras: {self.total_networks}", flush=True)
                self.packet_handler(pkt)

            # Capture management AND data frames
            sniff(
                iface=self.monitor_interface,
                prn=processor,
                filter="type mgt or type data",
                stop_filter=lambda x: not self.running,
                store=0,
            )
        except Exception as e:
            print(f"Packet capture error: {e}")
            import traceback
            traceback.print_exc()
    def channel_hopper(self):
        """Channel hopping for camera detection - fast 0.5s dwell (matches parent wardriving)."""
        # 2.4GHz channels (Blink, Ring, Wyze are 2.4GHz)
        channels_2ghz = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        # 5GHz channels (some dual-band Wyze)
        channels_5ghz = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165]
        
        # Combine but prioritize 2.4GHz
        all_channels = channels_2ghz + channels_5ghz
        channel_index = 0
        
        if self.debug:
            self.log(f"LiveCam channel hopper: {len(channels_2ghz)} 2.4GHz + {len(channels_5ghz)} 5GHz channels")
        
        while self.running:
            if self.monitor_interface:
                channel = all_channels[channel_index % len(all_channels)]
                self.set_channel(channel)
                self.current_channel = channel
                channel_index += 1
                
                # Fast scanning: 0.5s on all channels (same as parent wardriving)
                dwell = 0.5
                
                if self.debug and channel_index % 20 == 1:  # Log every 20th channel change
                    self.log(f"Channel hopper: Ch{channel} ({'2.4GHz' if channel in channels_2ghz else '5GHz'})")
                
                # Sleep with periodic checking for self.running
                elapsed = 0
                while elapsed < dwell and self.running:
                    time.sleep(0.5)
                    elapsed += 0.5

    # ------------------------------------------------------------------
    # Override packet_handler to add camera detection + LiveCam detection
    # ------------------------------------------------------------------
    def packet_handler(self, packet):
        """
        Override parent packet handler to detect cameras and live viewing.
        """
        # Let parent handle basic WiFi network detection
        if SCAPY_AVAILABLE and packet.haslayer(Dot11):
            # Camera detection from beacons/probe-responses
            if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
                self._process_camera_beacon(packet)
            # Camera detection from probe requests
            elif packet.haslayer(Dot11ProbeReq):
                self._process_camera_probe(packet)
            # Data frames (camera clients)
            else:
                self._process_data_frame(packet)
        
        # Live‑view detection (IP packets)
        if SCAPY_AVAILABLE and packet.haslayer(IP):
            if self.debug:
                self.log(f"IP packet: {packet.summary()[:80]}")
            self._process_ip_packet(packet)

    # ------------------------------------------------------------------
    # Override LCD display for LiveCam detection
    # ------------------------------------------------------------------
    def update_lcd_display(self):
        """LiveCam‑focused LCD display (no parent interference)."""
        if not self.lcd_ready or not self.lcd_running:
            return
        try:
            from PIL import Image, ImageDraw
            from payloads._display_helper import ScaledDraw, scaled_font
            
            if self.debug:
                self.log("LiveCam LCD display update - our method")
            
            # Live camera count
            live_count = sum(1 for mac in self.camera_macs if self._is_camera_live(mac))
            lines = ["LIVE CAM", f"Cameras: {len(self.camera_macs)}", f"Live: {live_count}"]

            # Recent alerts
            if self.alerts:
                latest = self.alerts[-1]
                lines.append(f"Alert: {latest['type']}")
                detail = latest['detail'][:20]
                lines.append(detail)
            else:
                lines.append("No alerts")

            if self.packet_counts:
                top_mac, top_count = max(self.packet_counts.items(), key=lambda kv: kv[1])
                lines.append(f"Active {top_mac[-6:]}:{top_count} pkts")
            else:
                lines.append("Traffic: waiting")

            if self.gps_data and "latitude" in self.gps_data:
                lat = self.gps_data["latitude"]
                lon = self.gps_data["longitude"]
                lines.append(f"GPS: {lat:.3f},{lon:.3f}")
            else:
                lines.append("GPS: No fix")

            status = "SCANNING" if self.running else "STOPPED"
            lines.append(f"{status} Ch{self.current_channel}")
            lines.append("[KEY1] Start/Stop")
            lines.append("[KEY2] Exit")

            img = Image.new("RGB", (self.WIDTH, self.HEIGHT), "black")
            d = ScaledDraw(img)
            
            # UNMISTAKABLE CLOUD HEADER
            # Bright red bar with yellow border
            d.rectangle((0, 0, 127, 12), fill="#FF0000", outline="#FFFF00", width=1)
            # Larger font for "CLOUD"
            try:
                header_font = scaled_font(size=12)
            except:
                header_font = self.font
            d.text((64, 6), "LIVE CAM", font=header_font, fill="#FFFFFF", anchor="mm")
            
            y = 14
            for line in lines:
                if y > 113:
                    break
                # Left‑aligned text
                d.text((2, y), line, font=self.font, fill="#00FF00")
                y += 12
            
            self.LCD.LCD_ShowImage(img, 0, 0)
            
            # Debug log
            if hasattr(self, 'display_counter'):
                self.display_counter += 1
                if self.debug and self.display_counter % 10 == 0:
                    self.log(f"LiveCam display update {self.display_counter}, cameras: {len(self.camera_macs)}")
            else:
                self.display_counter = 1
                if self.debug:
                    self.log(f"LiveCam display first update, cameras: {len(self.camera_macs)}")
        except Exception as e:
            self.log(f"LiveCam LCD display error: {e}")

    def lcd_update_loop(self):
        """LiveCam LCD update loop."""
        import time
        if self.debug:
            self.log("LiveCam LCD loop started")
        loop_count = 0
        try:
            while self.lcd_running:
                loop_count += 1
                try:
                    if self.lcd_running:
                        self.update_lcd_display()
                    if self.debug and loop_count % 30 == 1:
                        self.log(f"LiveCam LCD loop iteration {loop_count}")
                except Exception as e:
                    self.log(f"LiveCam LCD loop error: {e}")
                time.sleep(1)
        except Exception as e:
            self.log(f"LiveCam LCD loop crashed: {e}")

    def export_data(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.export_json(f"{self.loot_dir}/livecam_detector_{timestamp}.json")
        self.export_csv(f"{self.loot_dir}/livecam_detector_{timestamp}.csv")
        self.export_kml(f"{self.loot_dir}/livecam_detector_{timestamp}.kml")
        # Export alerts separately
        alert_file = f"{self.loot_dir}/livecam_alerts_{timestamp}.txt"
        with open(alert_file, "w") as f:
            f.write(f"LiveCam Detector Alerts - {timestamp}\n")
            f.write("=" * 60 + "\n")
            for alert in self.alerts:
                f.write(f"[{alert['time']}] {alert['mac']} - {alert['type']}: {alert['detail']}\n")
        print(f"Data exported to {self.loot_dir}/livecam_detector_{timestamp}.*")
        print(f"Alerts saved to {alert_file}")

    # ------------------------------------------------------------------
    # Interactive: custom (no parent call)
    # ------------------------------------------------------------------
    def run_interactive(self):
        """Run interactive LiveCam Detector session."""
        try:
            print("RaspyJack LiveCam Detector")
            print("===============================")
            print("Detects security cameras and live viewing activity.")
            print("Use hardware buttons (LCD) or console commands.\n")

            # Replicate the LCD/console mode from WardrivingScanner
            # but ensure our branding is used
            if LCD_AVAILABLE and self.lcd_ready:
                self.log("Starting LCD display thread for LiveCam Detector...")
                import threading
                self.lcd_running = True
                display_thread = threading.Thread(target=self.lcd_update_loop)
                display_thread.daemon = True
                display_thread.start()

                print("LCD Mode - Use hardware buttons:")
                print("  KEY1 - Start/Stop scan")
                print("  KEY2 - Exit (WebUI immediate / hold 2s on device)")
                print("  KEY3 - Export data")
                print("\nPress Ctrl+C to exit")

                try:
                    while True:
                        try:
                            self.handle_gpio_input()
                        except Exception as e:
                            self.log(f"GPIO error: {e}")
                        time.sleep(0.1)
                except KeyboardInterrupt:
                    print("\nShutting down...")
            else:
                self.log("Running in console mode")
                print("Console Mode:")
                print("  s - Start/Stop scan")
                print("  e - Export data")
                print("  q - Quit")

                import sys
                if not sys.stdin.isatty():
                    print("Non-interactive - starting scan automatically...")
                    self.start_scan()
                    try:
                        while True:
                            time.sleep(1)
                    except KeyboardInterrupt:
                        self.stop_scan()
                        return

                while True:
                    try:
                        cmd = input("\nCommand: ").lower().strip()
                        if cmd == "s":
                            if self.running:
                                self.stop_scan()
                            else:
                                self.start_scan()
                        elif cmd == "e":
                            self.export_data()
                        elif cmd == "q":
                            break
                    except (EOFError, KeyboardInterrupt):
                        break

            self.stop_scan()
        except Exception as e:
            print(f"CRITICAL ERROR in run_interactive: {e}")
            import traceback
            traceback.print_exc()
            raise

def main():
    try:
        monitor = LiveCamDetector()
        monitor.run_interactive()
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        try:
            if "monitor" in locals():
                monitor.cleanup()
        except Exception:
            pass


if __name__ == "__main__":
    main()
