#!/usr/bin/env python3
"""
RaspyJack Cam Finder Payload
=============================
Thin wrapper around WardrivingScanner that filters for security
camera OUIs only (Ring, Blink, Nest, Wyze, Arlo, Eufy, etc.).

Same engine, same controls, same GPS, same exports — just only
logs devices whose MAC matches a known camera vendor.

Controls:
  KEY1 - Start / Stop scan
  KEY2 - Exit (hold 2 s)
  KEY3 - Export data

Author: dag nazty
"""

import os
import sys
import time
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

# Import the working wardriving scanner — we inherit everything from it
from payloads.reconnaissance.wardriving import (  # type: ignore
    WardrivingScanner,
    LCD_AVAILABLE,
    SCAPY_AVAILABLE,
    GPS_AVAILABLE,
)

# Scapy layer types (only needed if scapy is available)
if SCAPY_AVAILABLE:
    from scapy.all import (  # type: ignore
        Dot11, Dot11Beacon, Dot11Elt,
        Dot11ProbeReq, Dot11ProbeResp,
        sniff,
    )

# ---------------------------------------------------------------------------
# Known camera / security-device OUI prefixes  (first 3 bytes of MAC)
# Merged from ESP32 camera_scanner.cpp reference + original research
# ---------------------------------------------------------------------------
CAMERA_OUIS: dict[str, str] = {
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
}

# ---------------------------------------------------------------------------
# SSID patterns that indicate a camera device  (case-insensitive prefix/contains)
# Merged from ESP32 camera_scanner.cpp camera_ssid_patterns[]
# ---------------------------------------------------------------------------
CAMERA_SSID_PATTERNS: list[tuple[str, str]] = [
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
]


def _is_camera_mac(mac: str) -> str | None:
    """Return vendor name if MAC matches a known camera OUI, else None."""
    oui = (mac or "")[:8].upper()
    return CAMERA_OUIS.get(oui)


def _is_camera_ssid(ssid: str) -> str | None:
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


class CamFinderScanner(WardrivingScanner):
    """
    Inherits the entire wardriving engine unchanged.
    Only overrides:
      - process_beacon  → skip non-camera MACs
      - update_lcd_display → show CAM FINDER label + vendor counts
      - export_data → use cam_scan_ prefix
      - loot_dir / log_file paths
    """

    def __init__(self):
        # Let the parent do all the heavy lifting
        super().__init__()

        # Redirect loot to CamFinder folder
        self.loot_dir = f"{self.base_dir}/loot/CamFinder"
        os.makedirs(self.loot_dir, exist_ok=True)
        self.db_path = f"{self.loot_dir}/cameras.db"
        self.log_file = os.path.join(self.loot_dir, "cam_finder.log")

        # Recreate DB cleanly (old runs may have different schema)
        self._init_cam_db()

        self.log("Cam Finder mode active (wardriving engine)")
        print("Cam Finder mode active")

    def _init_cam_db(self):
        """Create camera DB tables, wiping stale schema if needed."""
        import sqlite3
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            # Drop old tables from previous cam_finder versions
            c.execute("DROP TABLE IF EXISTS locations")
            c.execute("DROP TABLE IF EXISTS cameras")
            c.execute("DROP TABLE IF EXISTS networks")
            # Recreate with parent-compatible schema
            c.execute('''CREATE TABLE IF NOT EXISTS networks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ssid TEXT, bssid TEXT UNIQUE, channel INTEGER,
                frequency INTEGER, security_type TEXT, encryption TEXT,
                cipher TEXT, authentication TEXT, wps_enabled BOOLEAN,
                signal_strength INTEGER, first_seen TIMESTAMP,
                last_seen TIMESTAMP, vendor TEXT, country_code TEXT
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS locations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network_id INTEGER, latitude REAL, longitude REAL,
                altitude REAL, accuracy REAL, timestamp TIMESTAMP,
                FOREIGN KEY (network_id) REFERENCES networks (id)
            )''')
            c.execute('CREATE INDEX IF NOT EXISTS idx_networks_bssid ON networks(bssid)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_networks_ssid ON networks(ssid)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_locations_network_id ON locations(network_id)')
            conn.commit()
            conn.close()
            self.log("Camera DB initialized successfully")
        except Exception as e:
            self.log(f"Camera DB init error: {e}")

    # ------------------------------------------------------------------
    # Override: pick the interface that actually supports monitor mode
    # Parent hardcodes wlan1, but on some setups the USB adapter is wlan0
    # ------------------------------------------------------------------
    def _find_monitor_capable_interface(self):
        """
        Check each wireless interface's driver to find one that supports
        monitor mode.  Broadcom brcmfmac does NOT.  RTL88xx / Atheros do.
        Scans /sys/class/net/ directly (iwconfig misses some interfaces).
        Returns the best interface name, or None.
        """
        # Discover all wireless interfaces via /sys (more reliable than iwconfig)
        interfaces = []
        try:
            for name in os.listdir("/sys/class/net"):
                if name == "lo":
                    continue
                if os.path.isdir(f"/sys/class/net/{name}/wireless"):
                    interfaces.append(name)
        except Exception:
            pass

        # Fallback to iwconfig if /sys found nothing
        if not interfaces:
            interfaces = self.get_wifi_interfaces()

        if not interfaces:
            return None

        print(f"  Found wireless interfaces: {interfaces}", flush=True)

        # Drivers known NOT to support monitor mode
        no_monitor = {'brcmfmac', 'b43', 'wl'}

        capable = []
        fallback = []
        for iface in interfaces:
            driver = ""
            driver_path = f"/sys/class/net/{iface}/device/driver"
            try:
                real = os.path.realpath(driver_path)
                driver = os.path.basename(real)
            except Exception:
                pass

            print(f"  {iface}: driver={driver or 'unknown'}", flush=True)

            if driver and driver in no_monitor:
                fallback.append(iface)
            else:
                capable.append(iface)

        if capable:
            print(f"Monitor-capable interface: {capable[0]}", flush=True)
            return capable[0]
        if fallback:
            print(f"No confirmed monitor-capable interface, trying: {fallback[0]}", flush=True)
            return fallback[0]
        return None

    def start_scan(self):
        """Override parent to auto-detect monitor-capable interface."""
        if self.running:
            return

        if not SCAPY_AVAILABLE:
            print("Scapy not available - cannot start scan")
            return

        if self.monitor_interface:
            self.log(f"Reusing existing monitor interface: {self.monitor_interface}")
            print(f"Reusing monitor interface: {self.monitor_interface}")
        else:
            print("Detecting monitor-capable WiFi interface...", flush=True)
            iface = self._find_monitor_capable_interface()
            if not iface:
                print("No WiFi interfaces found")
                return

            self.interface = iface
            print(f"Using interface: {self.interface}", flush=True)

            self.monitor_interface = self.setup_monitor_mode(self.interface)
            if not self.monitor_interface:
                print("Failed to setup monitor mode")
                return

            print(f"Monitor mode enabled on {self.monitor_interface}")

        # Start scanning (same as parent from here)
        self.running = True
        self.log("Starting cam finder scan...")

        import threading
        self.channel_thread = threading.Thread(target=self.channel_hopper)
        self.channel_thread.daemon = True
        self.channel_thread.start()

        if GPS_AVAILABLE and getattr(self, 'gps_ready', False):
            self.log("GPS updater already running from initialization")
            print("GPS tracking already active")

        self.scan_thread = threading.Thread(target=self.packet_capture)
        self.scan_thread.daemon = True
        self.scan_thread.start()

        self.log("Cam finder scan started successfully")
        print("Cam finder scan started")
        print("Sniffing for security cameras...")

    # ------------------------------------------------------------------
    # Override: parent's setup_monitor_mode with timeouts added
    # Exact same logic, just won't freeze on systemctl/sudo
    # ------------------------------------------------------------------
    def setup_monitor_mode(self, interface):
        """Parent's monitor-mode setup with timeouts so nothing hangs."""
        print(f"Setting up monitor mode on {interface}", flush=True)

        # Step 1: Kill interfering processes (with timeouts)
        print("Stopping interfering services...", flush=True)
        for cmd_label, cmd in [
            ("NetworkManager", ['sudo', 'systemctl', 'stop', 'NetworkManager']),
            ("wpa_supplicant", ['sudo', 'pkill', '-f', 'wpa_supplicant']),
            ("dhcpcd",         ['sudo', 'pkill', '-f', 'dhcpcd']),
        ]:
            try:
                subprocess.run(cmd, capture_output=True, timeout=5)
                print(f"  {cmd_label} stopped", flush=True)
            except subprocess.TimeoutExpired:
                print(f"  {cmd_label} timed out - skipping", flush=True)
            except Exception:
                print(f"  {cmd_label} not running", flush=True)
        time.sleep(1)

        # Step 2: Check current interface status
        result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
        print(f"Current interface status: {result.stdout[:200]}", flush=True)

        # Step 3: Try airmon-ng method
        print("Attempting airmon-ng setup...", flush=True)
        try:
            cmd = ['sudo', 'airmon-ng', 'start', interface]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            print(f"airmon-ng stdout: {result.stdout}", flush=True)
            if result.stderr:
                print(f"airmon-ng stderr: {result.stderr}", flush=True)

            possible_names = [f"{interface}mon", f"{interface}mon0", interface]
            for mon_name in possible_names:
                check_result = subprocess.run(['iwconfig', mon_name],
                                              capture_output=True, text=True)
                if "Mode:Monitor" in check_result.stdout:
                    print(f"Monitor mode confirmed on {mon_name}", flush=True)
                    return mon_name

        except subprocess.TimeoutExpired:
            print("airmon-ng timed out", flush=True)
        except Exception as e:
            print(f"airmon-ng failed: {e}", flush=True)

        # Step 4: Manual iwconfig method
        print("Trying manual iwconfig method...", flush=True)
        try:
            subprocess.run(['sudo', 'ifconfig', interface, 'down'], check=True, timeout=10)
            time.sleep(1)
            subprocess.run(['sudo', 'iwconfig', interface, 'mode', 'monitor'], check=True, timeout=10)
            time.sleep(1)
            subprocess.run(['sudo', 'ifconfig', interface, 'up'], check=True, timeout=10)
            time.sleep(2)

            result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=5)
            if "Mode:Monitor" in result.stdout:
                print(f"Manual monitor mode successful on {interface}", flush=True)
                return interface

        except subprocess.TimeoutExpired:
            print("Manual method timed out", flush=True)
        except Exception as e:
            print(f"Manual method failed: {e}", flush=True)

        # Step 5: iw command method
        print("Trying iw command method...", flush=True)
        try:
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], check=True, timeout=10)
            subprocess.run(['sudo', 'iw', interface, 'set', 'monitor', 'none'], check=True, timeout=10)
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], check=True, timeout=10)
            time.sleep(2)

            result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=5)
            if "Mode:Monitor" in result.stdout:
                print(f"iw method successful on {interface}", flush=True)
                return interface

        except subprocess.TimeoutExpired:
            print("iw method timed out", flush=True)
        except Exception as e:
            print(f"iw method failed: {e}", flush=True)

        print("All monitor mode methods failed", flush=True)
        return None

    # ------------------------------------------------------------------
    # Override: capture management AND data frames (not just mgt)
    # Parent uses filter="type mgt" which misses camera client traffic.
    # Cameras are WiFi clients — they show up in data frames.
    # ------------------------------------------------------------------
    def packet_capture(self):
        """Capture management + data frames for camera detection."""
        try:
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

    # ------------------------------------------------------------------
    # Override: process all frame types for camera detection
    # Parent only checks Dot11Beacon + Dot11ProbeResp.
    # We also need data frames (camera clients) and probe requests.
    # ------------------------------------------------------------------
    def packet_handler(self, packet):
        """Check beacons, probe-responses, probe-requests, AND data frames."""
        try:
            if not packet.haslayer(Dot11):
                return

            if packet.haslayer(Dot11Beacon):
                self.process_beacon(packet)
            elif packet.haslayer(Dot11ProbeResp):
                self.process_beacon(packet)
            elif packet.haslayer(Dot11ProbeReq):
                self._process_probe_request(packet)
            else:
                # Data frame or other — check source/dest MACs
                self._process_data_frame(packet)
        except Exception as e:
            self.log(f"Packet handler error: {e}")

    # ------------------------------------------------------------------
    # NEW: process probe requests (cameras probing for their home network)
    # ------------------------------------------------------------------
    def _process_probe_request(self, packet):
        """Camera sending probe requests looking for its home AP."""
        try:
            src_mac = packet[Dot11].addr2  # source MAC
            if not src_mac:
                return

            vendor = _is_camera_mac(src_mac)
            detection = "PROBE"

            # Also check the probed SSID for camera patterns
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

    # ------------------------------------------------------------------
    # NEW: process data frames (camera clients transmitting on network)
    # ------------------------------------------------------------------
    def _process_data_frame(self, packet):
        """Check source and destination MACs in data frames."""
        try:
            dot11 = packet[Dot11]
            # addr1 = destination, addr2 = source (transmitter)
            for addr, role in [(dot11.addr2, "src"), (dot11.addr1, "dst")]:
                if not addr or addr == "ff:ff:ff:ff:ff:ff":
                    continue
                vendor = _is_camera_mac(addr)
                if vendor:
                    self._add_camera_from_mac(
                        addr, vendor, "DATA",
                        signal=getattr(packet, "dBm_AntSignal", None),
                    )
                    return  # one match per frame is enough
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Helper: add a camera found via MAC (no SSID/security available)
    # ------------------------------------------------------------------
    def _add_camera_from_mac(self, mac, vendor, detection, ssid="", signal=None):
        """
        Add or update a camera entry from a MAC match.
        Used by probe-request and data-frame handlers where we don't
        have beacon-level info (no security, no channel from IE).
        """
        mac_upper = mac.upper()

        # Already seen?
        if mac_upper in self.networks:
            self.networks[mac_upper]["last_seen"] = datetime.now().isoformat()
            if self.gps_data:
                self.networks[mac_upper]["gps_coordinates"] = self.gps_data.copy()
            return

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

        self.log(f"CAMERA [{detection}]: {vendor} | {ssid or '(hidden)'} | {mac_upper} | Ch {self.current_channel}")
        print(f"CAMERA [{detection}]: {vendor} | {ssid or '(hidden)'} | {mac_upper} | Ch {self.current_channel}")

    # ------------------------------------------------------------------
    # Override: filter beacons/probe-responses to camera OUIs + SSID patterns
    # ------------------------------------------------------------------
    def process_beacon(self, packet):
        """
        Log beacons / probe-responses from known camera vendors.
        Detection: MAC OUI match  OR  SSID pattern match.
        Label: [BEACON] for output.
        """
        try:
            bssid = packet[Dot11].addr3
        except Exception:
            return

        if not bssid:
            return

        # --- Extract SSID early so we can match on it too ---
        ssid = ""
        try:
            if packet.haslayer(Dot11Elt):
                ssid = packet[Dot11Elt].info.decode("utf-8", errors="ignore")
        except Exception:
            pass

        # --- Dual detection: OUI first, then SSID fallback ---
        vendor = _is_camera_mac(bssid)
        if vendor is None:
            vendor = _is_camera_ssid(ssid)
        if vendor is None:
            return   # not a camera — skip silently

        # Already seen?
        if bssid in self.networks:
            self.networks[bssid]["last_seen"] = datetime.now().isoformat()
            if self.gps_data:
                self.networks[bssid]["gps_coordinates"] = self.gps_data.copy()
            return

        # --- New camera found ---
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

        signal_strength = getattr(packet, "dBm_AntSignal", None)
        security = self.detect_security(packet)

        network_info = {
            "ssid": ssid,
            "bssid": bssid,
            "channel": channel,
            "frequency": self.channel_to_frequency(channel),
            "security": security,
            "signal_strength": signal_strength,
            "vendor": vendor,
            "first_seen": datetime.now().isoformat(),
            "last_seen": datetime.now().isoformat(),
            "gps_coordinates": self.gps_data.copy() if self.gps_data else None,
        }

        self.networks[bssid] = network_info
        self.total_networks += 1
        self.store_network_in_db(network_info)

        self.log(f"CAMERA [BEACON]: {vendor} | {ssid or '(hidden)'} | {bssid} | Ch {channel} | {security['type']}")
        print(f"CAMERA [BEACON]: {vendor} | {ssid or '(hidden)'} | {bssid} | Ch {channel} | {security['type']}")

    # ------------------------------------------------------------------
    # LCD: show camera-focused display
    # ------------------------------------------------------------------
    def update_lcd_display(self):
        if not self.lcd_ready or not self.lcd_running:
            return
        try:
            from PIL import Image, ImageDraw  # type: ignore

            lines = ["CAM FINDER", f"Cameras: {self.total_networks}"]

            # Top vendors
            if self.networks:
                counts: dict[str, int] = {}
                for n in self.networks.values():
                    v = n.get("vendor", "?")
                    counts[v] = counts.get(v, 0) + 1
                top = sorted(counts.items(), key=lambda kv: -kv[1])[:2]
                lines.append(" ".join(f"{v[:6]}:{c}" for v, c in top))
            else:
                lines.append("Scanning...")

            if self.gps_data and "latitude" in self.gps_data:
                lat = self.gps_data["latitude"]
                lon = self.gps_data["longitude"]
                speed = self.gps_data.get("speed", 0)
                lines.append(f"GPS: {lat:.4f},{lon:.4f}")
                if speed and speed > 0.2:
                    lines.append(f"Ch{self.current_channel} {speed * 2.237:.0f}mph")
                else:
                    lines.append(f"Ch{self.current_channel} Stationary")
            else:
                lines.append("GPS: No fix")
                lines.append(f"Ch{self.current_channel}")

            status = "SCANNING" if self.running else "STOPPED"
            iface = self.monitor_interface or "No IF"
            lines.append(f"{status} ({iface})")
            lines.append("[KEY1] Start/Stop")
            lines.append("[KEY2] Exit")

            img = Image.new("RGB", (self.WIDTH, self.HEIGHT), "black")
            d = ImageDraw.Draw(img)
            y = 2
            for line in lines:
                if y > self.HEIGHT - 15:
                    break
                if hasattr(d, "textbbox"):
                    w = d.textbbox((0, 0), line, font=self.font)[2]
                else:
                    w, _ = d.textsize(line, font=self.font)
                d.text(((self.WIDTH - w) // 2, y), line, font=self.font, fill="#00FF00")
                y += 12
            self.LCD.LCD_ShowImage(img, 0, 0)
        except Exception as e:
            self.log(f"LCD cam display error: {e}")

    # ------------------------------------------------------------------
    # Export: camera-specific filenames
    # ------------------------------------------------------------------
    def export_data(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.export_json(f"{self.loot_dir}/cam_scan_{timestamp}.json")
        self.export_csv(f"{self.loot_dir}/cam_scan_{timestamp}.csv")
        self.export_kml(f"{self.loot_dir}/cam_scan_{timestamp}.kml")
        print(f"Data exported to {self.loot_dir}/cam_scan_{timestamp}.*")

    # ------------------------------------------------------------------
    # Interactive: just change the banner
    # ------------------------------------------------------------------
    def run_interactive(self):
        print("RaspyJack Cam Finder")
        print("====================")

        if LCD_AVAILABLE and self.lcd_ready:
            self.log("Starting LCD display thread...")
            import threading
            display_thread = threading.Thread(target=self.lcd_update_loop)
            display_thread.daemon = True
            display_thread.start()

            print("LCD Mode - Use hardware buttons:")
            print("  KEY1 - Start/Stop scan")
            print("  KEY2 - Exit (hold 2s)")
            print("  KEY3 - Export data")
            print("\nPress Ctrl+C to exit")

            try:
                while True:
                    try:
                        self.handle_gpio_input()
                    except Exception as e:
                        self.log(f"GPIO error: {e}")
                    import time
                    time.sleep(0.1)
            except KeyboardInterrupt:
                print("\nShutting down...")
        else:
            self.log("Running in console mode")
            print("Console Mode:")
            print("  s - Start/Stop scan")
            print("  e - Export data")
            print("  q - Quit")

            if not sys.stdin.isatty():
                print("Non-interactive - starting scan automatically...")
                self.start_scan()
                try:
                    while True:
                        import time
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


def main():
    try:
        scanner = CamFinderScanner()
        scanner.run_interactive()
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        try:
            if "scanner" in locals():
                scanner.cleanup()
        except Exception:
            pass


if __name__ == "__main__":
    main()