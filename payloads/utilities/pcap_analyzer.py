#!/usr/bin/env python3
"""
RaspyJack Payload -- PCAP Analyzer
====================================
Author: 7h30th3r0n3

Browse and analyze pcap/cap/pcapng files directly on the device.
Supports both WiFi captures and network (ethernet) captures.

Dashboards:
  OVERVIEW    Packet count, duration, file size, capture type
  PROTOCOLS   Protocol distribution bar chart (TCP/UDP/DNS/HTTP/ICMP...)
  TOP TALKERS Top source/destination IPs by packet count
  WIFI        SSIDs, BSSIDs, clients, handshakes, PMKIDs detected
  PORTS       Top destination ports
  DNS         Top DNS queries
  TIMELINE    Packets-per-second sparkline
  CREDENTIALS Detected cleartext credentials / interesting strings

Controls:
  UP / DOWN   Navigate file list or scroll dashboard
  OK          Select file / Analyze
  LEFT/RIGHT  Switch dashboard view
  KEY1        Export analysis to JSON
  KEY2        Re-scan files
  KEY3        Back / Exit
"""

import os
import sys
import time
import json
import subprocess
import threading
from collections import defaultdict, deque, Counter
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

try:
    from scapy.all import (
        PcapReader, Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq,
        Dot11ProbeResp, Dot11Auth, Dot11AssoReq, Dot11Deauth,
        EAPOL, IP, IPv6, TCP, UDP, DNS, DNSQR, ICMP, ARP, Ether,
        Raw, conf,
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

LOOT_DIR = "/root/Raspyjack/loot"
EXPORT_DIR = os.path.join(LOOT_DIR, "PCAPAnalyzer")
PCAP_EXTENSIONS = (".pcap", ".cap", ".pcapng")

# Interesting ports for credential sniffing
CLEARTEXT_PORTS = {21, 23, 25, 80, 110, 143, 389, 445, 587, 993, 995, 8080}
CRED_KEYWORDS = [b"user", b"pass", b"login", b"auth", b"token", b"cookie",
                 b"session", b"api_key", b"apikey", b"secret"]

# Dashboard views
VIEWS = ["overview", "protocols", "talkers", "wifi", "ports", "dns",
         "timeline", "creds", "files"]
VIEW_NAMES = {
    "overview": "OVERVIEW",
    "protocols": "PROTOCOLS",
    "talkers": "TOP TALKERS",
    "wifi": "WIFI",
    "ports": "PORTS",
    "dns": "DNS QUERIES",
    "timeline": "TIMELINE",
    "creds": "CREDENTIALS",
    "files": "FILES",
}

EXTRACT_DIR = os.path.join(LOOT_DIR, "PCAPAnalyzer", "extracted")


# ---------------------------------------------------------------------------
# PCAP file discovery
# ---------------------------------------------------------------------------


def _find_pcap_files():
    found = []
    for root, _dirs, files in os.walk(LOOT_DIR):
        for fname in sorted(files):
            if fname.lower().endswith(PCAP_EXTENSIONS):
                filepath = os.path.join(root, fname)
                try:
                    size = os.path.getsize(filepath)
                    rel = os.path.relpath(filepath, LOOT_DIR)
                    found.append({"path": filepath, "name": fname,
                                  "rel": rel, "size": size})
                except OSError:
                    pass
    found.sort(key=lambda x: x["name"].lower())
    return found


def _fmt_size(nbytes):
    for unit in ("B", "K", "M", "G"):
        if nbytes < 1024:
            return f"{nbytes:.0f}{unit}" if nbytes == int(nbytes) else f"{nbytes:.1f}{unit}"
        nbytes /= 1024
    return f"{nbytes:.1f}T"


# ---------------------------------------------------------------------------
# Analysis engine
# ---------------------------------------------------------------------------


class PcapAnalysis:
    """Analyze a pcap file using tshark (fast C engine) with scapy fallback."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.filesize = os.path.getsize(filepath)

        # General stats
        self.total_packets = 0
        self.total_bytes = 0
        self.first_ts = None
        self.last_ts = None
        self.is_wifi = False
        self.is_network = False

        # Protocol distribution
        self.proto_packets = Counter()
        self.proto_bytes = Counter()

        # IP talkers
        self.src_ips = Counter()
        self.dst_ips = Counter()

        # Ports
        self.dst_ports = Counter()

        # DNS
        self.dns_queries = Counter()

        # WiFi
        self.wifi_ssids = {}
        self.wifi_clients = set()
        self.wifi_probes = Counter()
        self.wifi_deauths = 0
        self.wifi_eapol = 0
        self.wifi_handshakes = set()
        self.wifi_pmkid = 0
        self.wifi_channels = Counter()
        self._eapol_pairs = defaultdict(int)

        # Timeline
        self._timeline_buckets = defaultdict(int)

        # Credentials
        self.credentials = []
        self._max_creds = 50

        # Extracted files
        self.extracted_files = []   # [{"name", "size", "protocol", "src"}]
        self.extract_dir = None

        # Progress
        self.progress = 0
        self.analyzing = False
        self.done = False
        self.error = None

    # Threshold: files under 2MB use scapy (instant), above use tshark
    TSHARK_THRESHOLD = 2 * 1024 * 1024

    def analyze(self):
        self.analyzing = True
        # Small files → scapy (no startup overhead, instant for handshakes)
        # Large files → tshark (C engine, 50-100x faster on big pcaps)
        if self.filesize > self.TSHARK_THRESHOLD and self._has_tshark():
            self._analyze_tshark()
        else:
            self._analyze_scapy()
        self.progress = 100
        self.analyzing = False
        self.done = True

    def _has_tshark(self):
        try:
            r = subprocess.run(["tshark", "--version"], capture_output=True,
                               timeout=5)
            return r.returncode == 0
        except Exception:
            return False

    # ------------------------------------------------------------------
    # TSHARK ENGINE (fast)
    # ------------------------------------------------------------------

    def _analyze_tshark(self):
        """Single-pass tshark field extraction + targeted queries."""
        self.progress = 5

        # --- Pass 1: General stats via capinfos (instant) ---
        self._tshark_capinfos()
        self.progress = 15

        # --- Pass 2: Protocol hierarchy ---
        self._tshark_protocols()
        self.progress = 30

        # --- Pass 3: IP endpoints ---
        self._tshark_endpoints()
        self.progress = 45

        # --- Pass 4: DNS queries ---
        self._tshark_dns()
        self.progress = 55

        # --- Pass 5: Port stats ---
        self._tshark_ports()
        self.progress = 65

        # --- Pass 6: Timeline ---
        self._tshark_timeline()
        self.progress = 75

        # --- Pass 7: WiFi specific ---
        if self.is_wifi:
            self._tshark_wifi()
        self.progress = 85

        # --- Pass 8: Credentials ---
        self._tshark_creds()
        self.progress = 90

        # --- Pass 9: File extraction ---
        self._tshark_extract_files()
        self.progress = 95

    def _run_tshark(self, args, timeout=60):
        """Run tshark with args, return stdout lines.

        Accept non-zero exit codes — tshark returns errors for truncated
        pcaps or warnings but still outputs valid data.
        """
        cmd = ["tshark", "-r", self.filepath, "-n"] + args
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout)
            output = r.stdout.strip()
            if output:
                return output.splitlines()
        except Exception:
            pass
        return []

    def _tshark_capinfos(self):
        """Get basic capture info via capinfos."""
        try:
            r = subprocess.run(
                ["capinfos", "-M", self.filepath],
                capture_output=True, text=True, timeout=30)
            for line in r.stdout.splitlines():
                if "Number of packets:" in line:
                    try:
                        self.total_packets = int(
                            line.split(":")[-1].strip().replace(",", ""))
                    except Exception:
                        pass
                elif "Data size:" in line or "Data byte count:" in line:
                    try:
                        val = line.split(":")[-1].strip().split()[0].replace(",", "")
                        self.total_bytes = int(val)
                    except Exception:
                        pass
                elif "Earliest packet time:" in line:
                    pass  # parsed from tshark below
                elif "File encapsulation:" in line:
                    encap = line.split(":")[-1].strip().lower()
                    if "802.11" in encap or "ieee" in encap or "radiotap" in encap:
                        self.is_wifi = True
                    elif "ether" in encap or "linux" in encap:
                        self.is_network = True
                elif "Capture duration:" in line:
                    try:
                        dur = float(line.split(":")[-1].strip().split()[0])
                        self._capinfos_duration = dur
                    except Exception:
                        pass
        except Exception:
            pass

        # Get first + last timestamps
        lines = self._run_tshark(
            ["-T", "fields", "-e", "frame.time_epoch", "-c", "1"],
            timeout=10)
        if lines:
            try:
                self.first_ts = float(lines[0].strip())
            except Exception:
                pass

        # Last packet: tail approach
        lines = self._run_tshark(
            ["-T", "fields", "-e", "frame.time_epoch", "-e", "frame.len"],
            timeout=60)
        if lines:
            if self.total_packets == 0:
                self.total_packets = len(lines)
            total_b = 0
            for l in lines:
                p = l.split("\t")
                if p[0]:
                    try:
                        self.last_ts = float(p[0])
                    except Exception:
                        pass
                    if self.first_ts is None:
                        try:
                            self.first_ts = float(p[0])
                        except Exception:
                            pass
                if len(p) >= 2 and p[1]:
                    try:
                        total_b += int(p[1])
                    except Exception:
                        pass
            if self.total_bytes == 0:
                self.total_bytes = total_b

        if self.total_bytes == 0:
            self.total_bytes = self.filesize

    def _tshark_protocols(self):
        """Protocol hierarchy via -z io,phs."""
        lines = self._run_tshark(["-q", "-z", "io,phs"], timeout=30)

        PROTO_MAP = {
            "http": "HTTP", "tls": "HTTPS", "dns": "DNS", "ssh": "SSH",
            "ftp": "FTP", "telnet": "TELNET", "smtp": "SMTP", "smb": "SMB",
            "smb2": "SMB", "dhcp": "DHCP", "mdns": "mDNS", "ssdp": "SSDP",
            "arp": "ARP", "icmp": "ICMP", "tcp": "TCP", "udp": "UDP",
            "eapol": "EAPOL", "wlan": "WLAN", "quic": "QUIC",
            "ntp": "NTP", "snmp": "SNMP", "data": "DATA",
        }

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("=") \
               or stripped.startswith("Filter") \
               or stripped.startswith("Protocol"):
                continue
            # Format: "  proto  frames:NNN bytes:NNN"
            if "frames:" not in stripped:
                continue
            # Extract proto name (first word) and frames count
            proto_name = stripped.split()[0].lower()
            try:
                frames_part = stripped.split("frames:")[1]
                frames = int(frames_part.split()[0])
            except Exception:
                continue
            mapped = PROTO_MAP.get(proto_name)
            if mapped and frames > 0:
                self.proto_packets[mapped] = max(
                    self.proto_packets.get(mapped, 0), frames)

    def _tshark_endpoints(self):
        """IP endpoints for top talkers."""
        for proto in ("ip", "ipv6"):
            lines = self._run_tshark(
                ["-q", "-z", f"endpoints,{proto}"], timeout=30)
            in_data = False
            for line in lines:
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped.startswith("=") or stripped.startswith("Filter"):
                    continue
                if "Packets" in stripped or "IPv" in stripped:
                    in_data = True
                    continue
                if not in_data:
                    continue
                parts = stripped.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    if proto == "ipv6":
                        ip = ip[-15:]
                    try:
                        pkts = int(parts[1].replace(",", ""))
                    except Exception:
                        continue
                    self.src_ips[ip] += pkts

    def _tshark_dns(self):
        """Extract DNS query names."""
        lines = self._run_tshark(
            ["-T", "fields", "-e", "dns.qry.name",
             "-Y", "dns", "-c", "5000"],
            timeout=30)
        for line in lines:
            qname = line.strip().rstrip(".")
            if qname:
                self.dns_queries[qname] += 1

    def _tshark_ports(self):
        """Top destination ports."""
        # TCP
        lines = self._run_tshark(
            ["-T", "fields", "-e", "tcp.dstport",
             "-Y", "tcp", "-c", "10000"],
            timeout=30)
        for line in lines:
            try:
                port = int(line.strip())
                self.dst_ports[port] += 1
            except Exception:
                pass

        # UDP
        lines = self._run_tshark(
            ["-T", "fields", "-e", "udp.dstport",
             "-Y", "udp", "-c", "10000"],
            timeout=30)
        for line in lines:
            try:
                port = int(line.strip())
                self.dst_ports[port] += 1
            except Exception:
                pass

    def _tshark_timeline(self):
        """Packets per second via io,stat."""
        # Use 10s buckets for manageable output
        lines = self._run_tshark(
            ["-q", "-z", "io,stat,10"], timeout=30)
        for line in lines:
            stripped = line.strip()
            if not stripped or not stripped.startswith("|"):
                continue
            if "Interval" in stripped or "Col" in stripped or "Frames" in stripped:
                continue
            if "<>" not in stripped:
                continue
            # Format: | start <> end | frames | bytes |
            inner = stripped.replace("|", " ").strip()
            parts = inner.split()
            # parts: [start, <>, end, frames, bytes]
            if len(parts) >= 4:
                try:
                    start = int(float(parts[0]))
                    frames = int(parts[2])
                    self._timeline_buckets[start] = frames
                except Exception:
                    pass

    def _tshark_wifi(self):
        """WiFi-specific analysis."""
        # SSIDs from beacons
        lines = self._run_tshark(
            ["-T", "fields", "-e", "wlan.bssid", "-e", "wlan.ssid",
             "-e", "wlan_radio.channel",
             "-Y", "wlan.fc.type_subtype==0x08", "-c", "2000"],
            timeout=30)
        for line in lines:
            parts = line.split("\t")
            if len(parts) >= 2:
                bssid = (parts[0] or "").upper().replace(":", ":")
                ssid = parts[1] if len(parts) > 1 else ""
                if bssid and ssid:
                    self.wifi_ssids[bssid] = ssid
                if len(parts) >= 3 and parts[2]:
                    try:
                        self.wifi_channels[int(parts[2])] += 1
                    except Exception:
                        pass

        # Clients (data frames: src != bssid)
        lines = self._run_tshark(
            ["-T", "fields", "-e", "wlan.sa", "-e", "wlan.bssid",
             "-Y", "wlan.fc.type==2", "-c", "5000"],
            timeout=30)
        for line in lines:
            parts = line.split("\t")
            if len(parts) >= 2:
                sa = (parts[0] or "").upper()
                bss = (parts[1] or "").upper()
                if sa and bss and sa != bss:
                    self.wifi_clients.add(sa)

        # Deauths
        lines = self._run_tshark(
            ["-T", "fields", "-e", "frame.number",
             "-Y", "wlan.fc.type_subtype==0x0c"],
            timeout=15)
        self.wifi_deauths = len(lines)

        # EAPOL
        lines = self._run_tshark(
            ["-T", "fields", "-e", "wlan.sa", "-e", "wlan.da",
             "-Y", "eapol"],
            timeout=15)
        self.wifi_eapol = len(lines)
        for line in lines:
            parts = line.split("\t")
            if len(parts) >= 2:
                pair = tuple(sorted([
                    (parts[0] or "").upper(),
                    (parts[1] or "").upper()
                ]))
                self._eapol_pairs[pair] += 1

        # Detect handshakes (4+ EAPOL between same pair)
        for pair, count in self._eapol_pairs.items():
            if count >= 4:
                for mac in pair:
                    if mac in self.wifi_ssids:
                        self.wifi_handshakes.add(mac)

        # Half-handshakes (2-3 EAPOL)
        for pair, count in self._eapol_pairs.items():
            if 2 <= count < 4:
                for mac in pair:
                    if mac in self.wifi_ssids:
                        self.wifi_handshakes.add(mac)

        # Probe requests
        lines = self._run_tshark(
            ["-T", "fields", "-e", "wlan.ssid",
             "-Y", "wlan.fc.type_subtype==0x04", "-c", "2000"],
            timeout=15)
        for line in lines:
            ssid = line.strip()
            if ssid:
                self.wifi_probes[ssid] += 1

        # PMKID count via eapol key data
        lines = self._run_tshark(
            ["-T", "fields", "-e", "eapol.keydes.data",
             "-Y", "eapol.keydes.key_info==0x008a"],
            timeout=15)
        for line in lines:
            data = line.strip().replace(":", "")
            if len(data) >= 44:  # KDE header + 16 byte PMKID
                # Search for PMKID KDE: dd 14 00 0f ac 04
                if "dd" in data.lower() and "000fac04" in data.lower():
                    self.wifi_pmkid += 1

    def _tshark_creds(self):
        """Search for cleartext credentials on known ports."""
        ports_filter = " or ".join(
            f"tcp.port=={p}" for p in CLEARTEXT_PORTS)
        # Try http.request.uri and http.authorization first (fast)
        lines = self._run_tshark(
            ["-T", "fields", "-e", "ip.src", "-e", "tcp.dstport",
             "-e", "http.request.uri", "-e", "http.authorization",
             "-e", "http.cookie",
             "-Y", f"http.request",
             "-c", "200"],
            timeout=20)
        for line in lines:
            if len(self.credentials) >= self._max_creds:
                break
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            src = parts[0] or "?"
            try:
                port = int(parts[1]) if parts[1] else 80
            except Exception:
                port = 80
            for field in parts[2:]:
                if not field:
                    continue
                field_lower = field.lower()
                for kw in CRED_KEYWORDS:
                    kw_str = kw.decode() if isinstance(kw, bytes) else kw
                    if kw_str in field_lower:
                        self.credentials.append({
                            "port": port, "src": src,
                            "snippet": field[:60],
                        })
                        break

        # Also try raw TCP payload on cleartext ports
        if len(self.credentials) < self._max_creds:
            lines = self._run_tshark(
                ["-T", "fields", "-e", "ip.src", "-e", "tcp.dstport",
                 "-e", "data.data",
                 "-Y", f"data.data and ({ports_filter})",
                 "-c", "200"],
                timeout=20)
            for line in lines:
                if len(self.credentials) >= self._max_creds:
                    break
                parts = line.split("\t")
                if len(parts) < 3 or not parts[2]:
                    continue
                src = parts[0] or "?"
                try:
                    port = int(parts[1]) if parts[1] else 0
                except Exception:
                    continue
                hex_payload = parts[2].replace(":", "")
                try:
                    raw = bytes.fromhex(hex_payload[:1000])
                except Exception:
                    continue
                raw_lower = raw.lower()
                for kw in CRED_KEYWORDS:
                    if kw in raw_lower:
                        idx = raw_lower.index(kw)
                        start = max(0, idx - 10)
                        end = min(len(raw), idx + 40)
                        try:
                            text = raw[start:end].decode("utf-8", errors="replace")
                        except Exception:
                            text = raw[start:end].hex()
                        text = text.replace("\r", "").replace("\n", " ").strip()
                        if text:
                            self.credentials.append({
                                "port": port, "src": src,
                                "snippet": text[:60],
                            })
                        break

    # ------------------------------------------------------------------
    # FILE EXTRACTION
    # ------------------------------------------------------------------

    def _tshark_extract_files(self):
        """Extract files from pcap using tshark --export-objects."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = os.path.splitext(self.filename)[0][:20]
        self.extract_dir = os.path.join(EXTRACT_DIR, f"{base_name}_{ts}")

        protocols = ["http", "smb", "tftp", "imf"]
        for proto in protocols:
            out_dir = os.path.join(self.extract_dir, proto)
            os.makedirs(out_dir, exist_ok=True)
            try:
                subprocess.run(
                    ["tshark", "-r", self.filepath, "-n",
                     "--export-objects", f"{proto},{out_dir}"],
                    capture_output=True, timeout=60)
            except Exception:
                pass

            # Collect extracted files
            try:
                for fname in os.listdir(out_dir):
                    fpath = os.path.join(out_dir, fname)
                    if os.path.isfile(fpath):
                        size = os.path.getsize(fpath)
                        if size > 0:
                            self.extracted_files.append({
                                "name": fname[:40],
                                "size": size,
                                "protocol": proto.upper(),
                                "path": fpath,
                            })
            except Exception:
                pass

            # Remove empty dirs
            try:
                if not os.listdir(out_dir):
                    os.rmdir(out_dir)
            except Exception:
                pass

        # Sort by size descending
        self.extracted_files.sort(key=lambda x: x["size"], reverse=True)

        # Cleanup empty base dir
        try:
            if os.path.isdir(self.extract_dir) and not os.listdir(self.extract_dir):
                os.rmdir(self.extract_dir)
                self.extract_dir = None
        except Exception:
            pass

    # ------------------------------------------------------------------
    # SCAPY FALLBACK (slow but works without tshark)
    # ------------------------------------------------------------------

    def _analyze_scapy(self):
        """Fallback: stream-parse with scapy if tshark unavailable."""
        try:
            reader = PcapReader(self.filepath)
        except Exception as e:
            self.error = str(e)[:40]
            return

        try:
            for pkt in reader:
                self._scapy_process(pkt)
                self.total_packets += 1
                if self.total_packets % 500 == 0:
                    self.progress = min(95, self.progress + 1)
        except Exception:
            pass
        finally:
            try:
                reader.close()
            except Exception:
                pass

        for pair, count in self._eapol_pairs.items():
            if count >= 2:
                for mac in pair:
                    if mac in self.wifi_ssids:
                        self.wifi_handshakes.add(mac)

    def _scapy_process(self, pkt):
        pkt_len = len(pkt)
        self.total_bytes += pkt_len

        ts = float(pkt.time) if hasattr(pkt, 'time') else None
        if ts:
            if self.first_ts is None:
                self.first_ts = ts
            self.last_ts = ts
            self._timeline_buckets[int(ts)] += 1

        if pkt.haslayer(Dot11):
            self.is_wifi = True
            dot11 = pkt[Dot11]
            if pkt.haslayer(Dot11Beacon):
                bssid = (dot11.addr2 or "").upper()
                try:
                    essid = pkt[Dot11Elt].info.decode("utf-8", errors="replace")
                    if essid:
                        self.wifi_ssids[bssid] = essid
                except Exception:
                    pass
            if pkt.haslayer(Dot11Deauth):
                self.wifi_deauths += 1
            if pkt.haslayer(EAPOL):
                self.wifi_eapol += 1
                src = (dot11.addr2 or "").upper()
                dst = (dot11.addr1 or "").upper()
                pair = tuple(sorted([src, dst]))
                self._eapol_pairs[pair] += 1
            if dot11.type == 0:
                self.proto_packets["MGMT"] += 1
            elif dot11.type == 2:
                self.proto_packets["DATA"] += 1
            return

        if pkt.haslayer(IP):
            self.is_network = True
            ip = pkt[IP]
            self.src_ips[ip.src] += 1
            self.dst_ips[ip.dst] += 1
            if pkt.haslayer(TCP):
                self.dst_ports[pkt[TCP].dport] += 1
                self.proto_packets["TCP"] += 1
            elif pkt.haslayer(UDP):
                self.dst_ports[pkt[UDP].dport] += 1
                self.proto_packets["UDP"] += 1
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                dns = pkt[DNS]
                if dns.qr == 0:
                    try:
                        qname = pkt[DNSQR].qname
                        if isinstance(qname, bytes):
                            qname = qname.decode("utf-8", errors="ignore").rstrip(".")
                        if qname:
                            self.dns_queries[qname] += 1
                    except Exception:
                        pass
                self.proto_packets["DNS"] += 1

    # ------------------------------------------------------------------
    # Common properties
    # ------------------------------------------------------------------

    @property
    def duration(self):
        if self.first_ts and self.last_ts:
            return self.last_ts - self.first_ts
        return 0

    @property
    def capture_type(self):
        parts = []
        if self.is_wifi:
            parts.append("WiFi")
        if self.is_network:
            parts.append("Network")
        return " + ".join(parts) or "Unknown"

    def timeline_data(self, buckets=20):
        if not self._timeline_buckets:
            return [0] * buckets
        times = sorted(self._timeline_buckets.keys())
        start, end = times[0], times[-1]
        span = max(end - start, 1)
        bucket_size = span / buckets
        result = [0] * buckets
        for t, count in self._timeline_buckets.items():
            idx = min(int((t - start) / bucket_size), buckets - 1)
            result[idx] += count
        return result

    def to_dict(self):
        return {
            "filename": self.filename,
            "filesize": self.filesize,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "duration_seconds": round(self.duration, 2),
            "capture_type": self.capture_type,
            "protocols": dict(self.proto_packets.most_common(20)),
            "top_src_ips": dict(self.src_ips.most_common(10)),
            "top_dst_ips": dict(self.dst_ips.most_common(10)),
            "top_ports": dict(self.dst_ports.most_common(15)),
            "top_dns": dict(self.dns_queries.most_common(15)),
            "wifi_ssids": dict(self.wifi_ssids),
            "wifi_clients": len(self.wifi_clients),
            "wifi_deauths": self.wifi_deauths,
            "wifi_eapol": self.wifi_eapol,
            "wifi_handshakes": len(self.wifi_handshakes),
            "wifi_pmkid": self.wifi_pmkid,
            "wifi_channels": dict(self.wifi_channels.most_common(14)),
            "wifi_probes": dict(self.wifi_probes.most_common(10)),
            "credentials_found": len(self.credentials),
            "extracted_files": [
                {"name": f["name"], "size": f["size"], "protocol": f["protocol"]}
                for f in self.extracted_files
            ],
            "extract_dir": self.extract_dir,
            "analyzed_at": datetime.now().isoformat(),
        }


# ---------------------------------------------------------------------------
# LCD Drawing helpers
# ---------------------------------------------------------------------------


def _draw_header(d, font_sm, title, color="#58a6ff"):
    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), title[:22], font=font_sm, fill=color)


def _draw_footer(d, font_sm, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font_sm, fill="#888")


def _draw_bar(d, x, y, w, h, pct, color="#00FF00"):
    d.rectangle((x, y, x + w, y + h), outline="#333")
    bar_w = int(w * min(pct, 1.0))
    if bar_w > 0:
        d.rectangle((x, y, x + bar_w, y + h), fill=color)


def _draw_sparkline(d, x, y, w, h, data):
    if not data or max(data) == 0:
        d.rectangle((x, y, x + w, y + h), outline="#333")
        return
    mx = max(data)
    bar_w = max(1, w // len(data))
    for i, v in enumerate(data):
        bh = max(0, int(v / mx * h))
        bx = x + i * bar_w
        color = "#00FF00" if v > mx * 0.6 else "#FFAA00" if v > mx * 0.2 else "#FF4444"
        if bh > 0:
            d.rectangle((bx, y + h - bh, bx + bar_w - 1, y + h), fill=color)


def _fmt_duration(seconds):
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    m = int(seconds) // 60
    s = int(seconds) % 60
    if m < 60:
        return f"{m}m{s:02d}s"
    h = m // 60
    m = m % 60
    return f"{h}h{m:02d}m"


# ---------------------------------------------------------------------------
# LCD Drawing -- File browser
# ---------------------------------------------------------------------------


def _draw_file_list(lcd, font, font_sm, files, cursor, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, font_sm, f"PCAP FILES ({len(files)})", "#00CCFF")

    if not files:
        d.text((4, 40), "No pcap files found", font=font_sm, fill="#666")
        d.text((4, 55), f"in {LOOT_DIR}", font=font_sm, fill="#444")
        _draw_footer(d, font_sm, "KEY2:Scan KEY3:Exit")
    else:
        visible = files[scroll:scroll + 7]
        for i, f in enumerate(visible):
            y = 14 + i * 14
            idx = scroll + i
            prefix = ">" if idx == cursor else " "
            name = f["name"][:17]
            size = _fmt_size(f["size"])
            color = "#00FF00" if idx == cursor else "#CCCCCC"
            d.text((2, y), f"{prefix}{name}", font=font_sm, fill=color)
            d.text((105, y), size, font=font_sm, fill="#888")

        _draw_footer(d, font_sm, "OK:Analyze KEY2:Scan K3:X")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# LCD Drawing -- Analysis progress
# ---------------------------------------------------------------------------


def _draw_progress(lcd, font, font_sm, analysis):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, font_sm, "ANALYZING...", "#FFAA00")

    d.text((4, 25), analysis.filename[:22], font=font_sm, fill="#FFFFFF")
    d.text((4, 40), f"{_fmt_size(analysis.filesize)}", font=font_sm, fill="#888")
    d.text((4, 55), f"{analysis.total_packets} packets", font=font_sm, fill="#00FF00")

    _draw_bar(d, 4, 75, 120, 8, analysis.progress / 100, "#00CCFF")
    d.text((4, 88), f"{analysis.progress}%", font=font_sm, fill="#FFAA00")

    if analysis.error:
        d.text((4, 100), f"ERR: {analysis.error[:20]}", font=font_sm, fill="#FF0000")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# LCD Drawing -- Dashboard views
# ---------------------------------------------------------------------------


def _draw_overview(lcd, font, font_sm, a, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, font_sm, "OVERVIEW")

    y = 14
    lines = [
        (f"File: {a.filename[:20]}", "#FFFFFF"),
        (f"Size: {_fmt_size(a.filesize)}", "#888"),
        (f"Packets: {a.total_packets:,}", "#00FF00"),
        (f"Bytes: {_fmt_size(a.total_bytes)}", "#00CCFF"),
        (f"Duration: {_fmt_duration(a.duration)}", "#FFAA00"),
        (f"Type: {a.capture_type}", "#FF00FF"),
    ]

    if a.duration > 0:
        pps = a.total_packets / a.duration
        bps = a.total_bytes * 8 / a.duration
        lines.append((f"Avg: {pps:.0f} pkt/s", "#888"))
        lines.append((f"Bw: {_fmt_size(bps/8)}/s", "#888"))

    if a.is_wifi:
        lines.append((f"SSIDs:{len(a.wifi_ssids)} CLI:{len(a.wifi_clients)}", "#00FF00"))
        lines.append((f"HS:{len(a.wifi_handshakes)} PMKID:{a.wifi_pmkid} DTH:{a.wifi_deauths}", "#FFAA00"))

    cred_count = len(a.credentials)
    if cred_count > 0:
        lines.append((f"Creds found: {cred_count}", "#FF0000"))

    visible = lines[scroll:scroll + 8]
    for text, color in visible:
        d.text((4, y), text[:24], font=font_sm, fill=color)
        y += 12

    _draw_footer(d, font_sm, "L/R:View U/D:Scrl K3:Bk")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_protocols(lcd, font, font_sm, a, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, font_sm, "PROTOCOLS")

    top = a.proto_packets.most_common(20)
    if not top:
        d.text((4, 50), "No data", font=font_sm, fill="#666")
    else:
        total = sum(c for _, c in top)
        visible = top[scroll:scroll + 8]
        y = 14
        for proto, count in visible:
            pct = count / max(total, 1)
            d.text((2, y), f"{proto[:7]}", font=font_sm, fill="#FFFFFF")
            _draw_bar(d, 42, y + 1, 60, 8, pct, "#00CCFF")
            d.text((106, y), f"{count}", font=font_sm, fill="#888")
            y += 12

    _draw_footer(d, font_sm, "L/R:View U/D:Scrl K3:Bk")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_talkers(lcd, font, font_sm, a, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, font_sm, "TOP TALKERS")

    # Merge src + dst
    all_ips = Counter()
    for ip, c in a.src_ips.items():
        all_ips[ip] += c
    for ip, c in a.dst_ips.items():
        all_ips[ip] += c

    top = all_ips.most_common(20)
    if not top:
        d.text((4, 50), "No IP data", font=font_sm, fill="#666")
    else:
        mx = top[0][1] if top else 1
        visible = top[scroll:scroll + 8]
        y = 14
        for ip, count in visible:
            ip_short = ip[-15:]
            pct = count / max(mx, 1)
            d.text((2, y), ip_short, font=font_sm, fill="#FFFFFF")
            _draw_bar(d, 85, y + 1, 30, 8, pct, "#00FF00")
            d.text((118, y), f"{count}", font=font_sm, fill="#888")
            y += 12

    _draw_footer(d, font_sm, "L/R:View U/D:Scrl K3:Bk")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_wifi(lcd, font, font_sm, a, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, font_sm, "WIFI ANALYSIS", "#FF00FF")

    if not a.is_wifi:
        d.text((4, 50), "No WiFi data", font=font_sm, fill="#666")
        d.text((4, 65), "Not a WiFi capture", font=font_sm, fill="#444")
    else:
        lines = [
            (f"SSIDs: {len(a.wifi_ssids)}", "#00FF00"),
            (f"Clients: {len(a.wifi_clients)}", "#00CCFF"),
            (f"EAPOL msgs: {a.wifi_eapol}", "#FFAA00"),
            (f"Handshakes: {len(a.wifi_handshakes)}", "#00FF00" if a.wifi_handshakes else "#888"),
            (f"PMKIDs: {a.wifi_pmkid}", "#FF00FF" if a.wifi_pmkid else "#888"),
            (f"Deauths: {a.wifi_deauths}", "#FF4444" if a.wifi_deauths else "#888"),
            (f"Probes: {sum(a.wifi_probes.values())}", "#888"),
        ]

        # Add top SSIDs
        for bssid, essid in list(a.wifi_ssids.items())[:5]:
            hs_mark = "!" if bssid in a.wifi_handshakes else " "
            lines.append((f"{hs_mark}{essid[:15]} {bssid[-8:]}", "#FFFFFF"))

        # Top channels
        if a.wifi_channels:
            ch_str = " ".join(f"{ch}" for ch, _ in a.wifi_channels.most_common(5))
            lines.append((f"CH: {ch_str}", "#FFAA00"))

        visible = lines[scroll:scroll + 8]
        y = 14
        for text, color in visible:
            d.text((4, y), text[:24], font=font_sm, fill=color)
            y += 12

    _draw_footer(d, font_sm, "L/R:View U/D:Scrl K3:Bk")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_ports(lcd, font, font_sm, a, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, font_sm, "TOP PORTS")

    PORT_NAMES = {
        21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
        67: "DHCP", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        445: "SMB", 993: "IMAPS", 995: "POP3S", 3389: "RDP",
        5353: "mDNS", 8080: "HTTP-P", 8443: "HTTPS-A",
    }

    top = a.dst_ports.most_common(20)
    if not top:
        d.text((4, 50), "No port data", font=font_sm, fill="#666")
    else:
        mx = top[0][1] if top else 1
        visible = top[scroll:scroll + 8]
        y = 14
        for port, count in visible:
            name = PORT_NAMES.get(port, "")
            label = f"{port}" if not name else f"{port}/{name}"
            pct = count / max(mx, 1)
            d.text((2, y), label[:10], font=font_sm, fill="#FFFFFF")
            _draw_bar(d, 58, y + 1, 50, 8, pct, "#FFAA00")
            d.text((112, y), f"{count}", font=font_sm, fill="#888")
            y += 12

    _draw_footer(d, font_sm, "L/R:View U/D:Scrl K3:Bk")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_dns(lcd, font, font_sm, a, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, font_sm, "DNS QUERIES")

    top = a.dns_queries.most_common(30)
    if not top:
        d.text((4, 50), "No DNS data", font=font_sm, fill="#666")
    else:
        visible = top[scroll:scroll + 8]
        y = 14
        for domain, count in visible:
            d.text((2, y), domain[:19], font=font_sm, fill="#FFFFFF")
            d.text((112, y), f"{count}", font=font_sm, fill="#00CCFF")
            y += 12

    _draw_footer(d, font_sm, "L/R:View U/D:Scrl K3:Bk")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_timeline(lcd, font, font_sm, a, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, font_sm, "TIMELINE")

    data = a.timeline_data(buckets=24)
    d.text((4, 16), f"Duration: {_fmt_duration(a.duration)}", font=font_sm, fill="#888")
    d.text((4, 28), f"Packets/s", font=font_sm, fill="#666")

    _draw_sparkline(d, 4, 40, 120, 35, data)

    # Stats under sparkline
    if data and max(data) > 0:
        peak = max(data)
        avg = sum(data) / len(data)
        d.text((4, 80), f"Peak: {peak} pkt/bucket", font=font_sm, fill="#00FF00")
        d.text((4, 92), f"Avg: {avg:.1f} pkt/bucket", font=font_sm, fill="#FFAA00")
    else:
        d.text((4, 80), "No timeline data", font=font_sm, fill="#666")

    _draw_footer(d, font_sm, "L/R:View U/D:Scrl K3:Bk")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_creds(lcd, font, font_sm, a, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    count = len(a.credentials)
    _draw_header(d, font_sm, f"CREDENTIALS ({count})", "#FF0000" if count else "#888")

    if not a.credentials:
        d.text((4, 40), "No cleartext creds", font=font_sm, fill="#666")
        d.text((4, 55), "detected in capture", font=font_sm, fill="#444")
    else:
        visible = a.credentials[scroll:scroll + 5]
        y = 14
        for cred in visible:
            d.text((2, y), f":{cred['port']} {cred['src']}", font=font_sm, fill="#FF4444")
            y += 10
            d.text((4, y), cred["snippet"][:22], font=font_sm, fill="#FFAA00")
            y += 12

    _draw_footer(d, font_sm, "L/R:View U/D:Scrl K3:Bk")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# LCD Drawing -- Files view
# ---------------------------------------------------------------------------


def _draw_files(lcd, font, font_sm, a, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    count = len(a.extracted_files)
    _draw_header(d, font_sm, f"FILES ({count})", "#FF00FF" if count else "#888")

    if not a.extracted_files:
        d.text((4, 35), "No files extracted", font=font_sm, fill="#666")
        d.text((4, 50), "from this capture", font=font_sm, fill="#444")
        if a.extract_dir:
            d.text((4, 70), "Check:", font=font_sm, fill="#444")
            d.text((4, 82), a.extract_dir[:22], font=font_sm, fill="#333")
    else:
        # Summary line
        total_size = sum(f["size"] for f in a.extracted_files)
        protos = set(f["protocol"] for f in a.extracted_files)
        d.text((2, 14), f"{count} files {_fmt_size(total_size)} [{','.join(protos)}]",
               font=font_sm, fill="#FF00FF")

        visible = a.extracted_files[scroll:scroll + 7]
        y = 26
        for f in visible:
            name = f["name"][:16]
            size = _fmt_size(f["size"])
            proto = f["protocol"][:4]

            # Color by type
            ext = os.path.splitext(f["name"])[1].lower()
            if ext in (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg"):
                color = "#00FF00"   # images
            elif ext in (".html", ".htm", ".css", ".js", ".json", ".xml"):
                color = "#00CCFF"   # web
            elif ext in (".exe", ".dll", ".bin", ".msi", ".elf"):
                color = "#FF0000"   # executables
            elif ext in (".zip", ".tar", ".gz", ".7z", ".rar"):
                color = "#FFAA00"   # archives
            elif ext in (".pdf", ".doc", ".docx", ".xls", ".xlsx"):
                color = "#FF00FF"   # documents
            else:
                color = "#CCCCCC"

            d.text((2, y), name, font=font_sm, fill=color)
            d.text((95, y), size, font=font_sm, fill="#888")
            d.text((118, y), proto[0], font=font_sm, fill="#555")
            y += 12

    if a.extract_dir and a.extracted_files:
        _draw_footer(d, font_sm, "L/R:View U/D:Scrl K3:Bk")
    else:
        _draw_footer(d, font_sm, "L/R:View K3:Back")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


def _export_analysis(analysis):
    os.makedirs(EXPORT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = os.path.splitext(analysis.filename)[0][:20]
    path = os.path.join(EXPORT_DIR, f"analysis_{name}_{ts}.json")
    with open(path, "w") as f:
        json.dump(analysis.to_dict(), f, indent=2)
    return path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
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

    # --- File browser ---
    screen = "browser"  # browser | analyzing | dashboard
    files = _find_pcap_files()
    cursor = 0
    scroll = 0
    analysis = None
    view_idx = 0
    dash_scroll = 0

    try:
        while True:
            btn = get_button(PINS, GPIO)

            # === FILE BROWSER ===
            if screen == "browser":
                if btn == "KEY3":
                    break
                elif btn == "KEY2":
                    files = _find_pcap_files()
                    cursor = 0
                    scroll = 0
                    time.sleep(0.3)
                elif btn == "UP" and files:
                    cursor = max(0, cursor - 1)
                    if cursor < scroll:
                        scroll = cursor
                    time.sleep(0.15)
                elif btn == "DOWN" and files:
                    cursor = min(len(files) - 1, cursor + 1)
                    if cursor >= scroll + 7:
                        scroll = cursor - 6
                    time.sleep(0.15)
                elif btn == "OK" and files:
                    selected = files[cursor]
                    analysis = PcapAnalysis(selected["path"])
                    screen = "analyzing"
                    threading.Thread(target=analysis.analyze, daemon=True).start()
                    time.sleep(0.3)

                _draw_file_list(lcd, font, font_sm, files, cursor, scroll)

            # === ANALYZING ===
            elif screen == "analyzing":
                if btn == "KEY3":
                    screen = "browser"
                    time.sleep(0.3)
                elif analysis and analysis.done:
                    screen = "dashboard"
                    view_idx = 0
                    dash_scroll = 0
                    # Auto-select WiFi view if WiFi capture
                    if analysis.is_wifi and not analysis.is_network:
                        view_idx = VIEWS.index("wifi")
                    time.sleep(0.3)

                if analysis:
                    _draw_progress(lcd, font, font_sm, analysis)

            # === DASHBOARD ===
            elif screen == "dashboard":
                if btn == "KEY3":
                    screen = "browser"
                    time.sleep(0.3)
                elif btn == "RIGHT":
                    view_idx = (view_idx + 1) % len(VIEWS)
                    dash_scroll = 0
                    time.sleep(0.2)
                elif btn == "LEFT":
                    view_idx = (view_idx - 1) % len(VIEWS)
                    dash_scroll = 0
                    time.sleep(0.2)
                elif btn == "UP":
                    dash_scroll = max(0, dash_scroll - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    dash_scroll += 1
                    time.sleep(0.15)
                elif btn == "KEY1":
                    # Export
                    try:
                        path = _export_analysis(analysis)
                        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                        d = ScaledDraw(img)
                        d.text((4, 40), "Exported!", font=font, fill="#00FF00")
                        d.text((4, 60), os.path.basename(path)[:22], font=font_sm, fill="#888")
                        lcd.LCD_ShowImage(img, 0, 0)
                        time.sleep(2)
                    except Exception as e:
                        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                        d = ScaledDraw(img)
                        d.text((4, 50), f"Export fail", font=font, fill="#FF0000")
                        lcd.LCD_ShowImage(img, 0, 0)
                        time.sleep(2)

                current_view = VIEWS[view_idx]
                draw_funcs = {
                    "overview": _draw_overview,
                    "protocols": _draw_protocols,
                    "talkers": _draw_talkers,
                    "wifi": _draw_wifi,
                    "ports": _draw_ports,
                    "dns": _draw_dns,
                    "timeline": _draw_timeline,
                    "creds": _draw_creds,
                    "files": _draw_files,
                }
                draw_funcs[current_view](lcd, font, font_sm, analysis, dash_scroll)

            time.sleep(0.05)

    finally:
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
