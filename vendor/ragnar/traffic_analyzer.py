# traffic_analyzer.py
"""
Traffic Analysis Module for Ragnar Server Mode

This module provides real-time network traffic analysis capabilities
that are only available when running on a capable server (8GB+ RAM).

Features:
- Real-time packet capture with tcpdump
- Connection tracking and statistics
- Protocol analysis
- Bandwidth monitoring per host
- Suspicious traffic detection
- DNS query logging
- C2 beacon detection patterns
"""

import os
import re
import json
import time
import threading
import subprocess
import signal
import queue
import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from collections import defaultdict, deque
from enum import Enum

from logger import Logger
from server_capabilities import get_server_capabilities, is_server_mode

logger = Logger(name="traffic_analyzer", level=logging.INFO)


class TrafficAlertLevel(Enum):
    """Alert severity levels for traffic anomalies"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertCategory(Enum):
    """Standardized alert categories for filtering and reporting"""
    SUSPICIOUS_PORT = "suspicious_port"
    PORT_SCAN = "port_scan"
    DNS_TUNNELING = "dns_tunneling"
    C2_BEACON = "c2_beacon"
    DATA_EXFIL = "data_exfiltration"
    BRUTE_FORCE = "brute_force"
    HIGH_BANDWIDTH = "high_bandwidth"
    PROTOCOL_ANOMALY = "protocol_anomaly"


@dataclass
class ConnectionStats:
    """Statistics for a single connection"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packets_sent: int = 0
    packets_recv: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    flags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['first_seen'] = self.first_seen.isoformat()
        d['last_seen'] = self.last_seen.isoformat()
        d['duration_seconds'] = (self.last_seen - self.first_seen).total_seconds()
        return d


@dataclass
class TrafficAlert:
    """Alert for suspicious traffic pattern"""
    alert_id: str
    level: TrafficAlertLevel
    category: str
    message: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    acknowledged: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'alert_id': self.alert_id,
            'level': self.level.value,
            'category': self.category,
            'message': self.message,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'details': self.details,
            'timestamp': self.timestamp.isoformat(),
            'acknowledged': self.acknowledged
        }


@dataclass  
class HostTrafficStats:
    """Traffic statistics for a single host"""
    ip: str
    hostname: Optional[str] = None
    mac: Optional[str] = None
    total_packets: int = 0
    total_bytes: int = 0
    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    protocols: Dict[str, int] = field(default_factory=dict)
    ports_contacted: set = field(default_factory=set)
    connections_active: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    dns_queries: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'ip': self.ip,
            'hostname': self.hostname,
            'mac': self.mac,
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'packets_in': self.packets_in,
            'packets_out': self.packets_out,
            'bytes_in': self.bytes_in,
            'bytes_out': self.bytes_out,
            'protocols': self.protocols,
            'ports_contacted': list(self.ports_contacted)[:100],  # Limit for API
            'connections_active': self.connections_active,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'dns_queries': self.dns_queries[-50:],  # Last 50 queries
        }


class TrafficAnalyzer:
    """
    Real-time traffic analyzer for Ragnar server mode.
    
    Uses tcpdump for packet capture and provides:
    - Live connection tracking
    - Per-host bandwidth statistics
    - Protocol distribution analysis
    - Suspicious pattern detection
    """
    
    # Suspicious ports with descriptions for analyst context
    SUSPICIOUS_PORTS = {
        4444: "Metasploit default listener",
        5555: "Android ADB / common backdoor",
        6666: "IRC backdoor / DarkComet",
        1234: "Generic backdoor",
        31337: "Back Orifice / 'elite' port",
        12345: "NetBus trojan",
        65535: "Uncommon max port (evasion)",
        6667: "IRC (C2 channel)",
        6697: "IRC over TLS",
        8080: "HTTP proxy (if unexpected)",
        9001: "Tor default",
        9050: "Tor SOCKS proxy",
        1337: "Common hacker port",
        5900: "VNC (if unauthorized)",
        2222: "SSH alternate (dropbear)",
    }

    # DNS tunneling detection threshold
    DNS_TUNNEL_THRESHOLD = 100  # Queries per minute from single host
    DNS_QUERY_TRACKING_WINDOW = 60  # Seconds to track DNS query rate
    
    # Rate limiting
    MAX_ALERTS_PER_MINUTE = 10
    STATS_RETENTION_HOURS = 24
    
    def __init__(self, shared_data=None, interface: str = None):
        self.shared_data = shared_data
        self.interface = interface or self._detect_interface()
        
        self._running = False
        self._capture_process: Optional[subprocess.Popen] = None
        self._capture_thread: Optional[threading.Thread] = None
        self._analysis_thread: Optional[threading.Thread] = None
        
        self._packet_queue: queue.Queue = queue.Queue(maxsize=10000)
        self._lock = threading.Lock()
        
        # Local IP addresses to exclude from alerts (Ragnar's own IPs)
        self._local_ips: set = self._detect_local_ips()
        
        # Statistics storage
        self.host_stats: Dict[str, HostTrafficStats] = {}
        self.connections: Dict[str, ConnectionStats] = {}
        self.alerts: deque = deque(maxlen=1000)
        self.dns_queries: deque = deque(maxlen=5000)
        
        # Metrics
        self.total_packets = 0
        self.total_bytes = 0
        self._raw_packet_count = 0  # Raw count from capture thread (for debugging)
        self.packets_per_second = 0.0
        self.bytes_per_second = 0.0
        self._last_metrics_time = time.time()
        self._last_packet_count = 0
        self._last_byte_count = 0
        
        # Alert rate limiting and deduplication
        self._alert_timestamps: deque = deque(maxlen=100)
        self._alert_counter = 0
        self._alert_hashes: set = set()  # Track seen alerts to prevent duplicates
        self._alert_hash_expiry: Dict[str, float] = {}  # Expiry time for each hash
        self._alert_dedup_window = 300  # Seconds before same alert can fire again

        # Capture timing
        self._start_time: Optional[datetime] = None

        # DNS query timestamps for rate detection
        self._dns_query_times: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

        # Callbacks
        self._on_alert_callbacks: List[Callable] = []
        
        # Check if feature is available
        caps = get_server_capabilities(shared_data)
        if not caps.capabilities.traffic_analysis_enabled:
            logger.warning("Traffic analysis not available - missing requirements")
    
    def _detect_interface(self) -> str:
        """Detect the primary network interface"""
        try:
            # Try to get default route interface
            result = subprocess.run(
                ['ip', 'route', 'get', '8.8.8.8'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Parse: "8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.100"
                match = re.search(r'dev\s+(\S+)', result.stdout)
                if match:
                    return match.group(1)
        except Exception as e:
            logger.debug(f"Interface detection error: {e}")
        
        # Fallback to common interfaces
        for iface in ['eth0', 'wlan0', 'enp0s3', 'ens33']:
            if os.path.exists(f'/sys/class/net/{iface}'):
                return iface
        
        return 'any'
    
    def _detect_local_ips(self) -> set:
        """Detect all local IP addresses (Ragnar's own IPs to exclude from alerts)"""
        local_ips = {'127.0.0.1', '::1', 'localhost'}

        # Method 1: Try Linux 'ip' command
        try:
            result = subprocess.run(
                ['ip', '-4', 'addr', 'show'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Parse: inet 192.168.1.192/24 ...
                for match in re.finditer(r'inet\s+(\d+\.\d+\.\d+\.\d+)', result.stdout):
                    local_ips.add(match.group(1))
                    logger.debug(f"Detected local IP (ip cmd): {match.group(1)}")
        except Exception as e:
            logger.debug(f"Linux IP detection error: {e}")

        # Method 2: Try hostname resolution (cross-platform)
        try:
            import socket
            hostname = socket.gethostname()
            # Get all IPs for this hostname
            try:
                host_ips = socket.gethostbyname_ex(hostname)[2]
                for ip in host_ips:
                    local_ips.add(ip)
                    logger.debug(f"Detected local IP (hostname): {ip}")
            except socket.gaierror:
                pass

            # Also try to get the IP used for outbound connections
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                outbound_ip = s.getsockname()[0]
                local_ips.add(outbound_ip)
                logger.debug(f"Detected local IP (outbound): {outbound_ip}")
                s.close()
            except Exception:
                pass
        except Exception as e:
            logger.debug(f"Socket IP detection error: {e}")

        # Method 3: Try to get IPs from shared_data if available (Flask config)
        if self.shared_data:
            try:
                # Check if there's a configured host IP
                host = self.shared_data.get('host', '')
                if host and host not in ['0.0.0.0', '']:
                    local_ips.add(host)
                    logger.debug(f"Detected local IP (config): {host}")
            except Exception:
                pass

        # Add common local network ranges that might be Ragnar
        # These are private IP patterns that are likely to be the host
        try:
            for ip in list(local_ips):
                if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                    # This is a private IP, likely the actual machine IP
                    logger.info(f"Ragnar local IP detected: {ip}")
        except Exception:
            pass

        logger.info(f"Local IPs (excluded from alerts): {local_ips}")
        return local_ips
    
    def is_available(self) -> bool:
        """Check if traffic analysis is available"""
        return get_server_capabilities().capabilities.traffic_analysis_enabled
    
    def start(self) -> bool:
        """Start traffic capture and analysis"""
        if not self.is_available():
            logger.error("Traffic analysis not available on this system")
            return False
        
        if self._running:
            logger.warning("Traffic analyzer already running")
            return True
        
        self._running = True
        self._start_time = datetime.now()

        # Start capture thread
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            name="TrafficCapture",
            daemon=True
        )
        self._capture_thread.start()
        
        # Start analysis thread
        self._analysis_thread = threading.Thread(
            target=self._analysis_loop,
            name="TrafficAnalysis",
            daemon=True
        )
        self._analysis_thread.start()
        
        logger.info(f"Traffic analyzer started on interface {self.interface}")
        return True
    
    def stop(self):
        """Stop traffic capture and analysis"""
        self._running = False
        
        if self._capture_process:
            try:
                self._capture_process.terminate()
                self._capture_process.wait(timeout=5)
            except Exception as e:
                logger.error(f"Error stopping capture: {e}")
                try:
                    self._capture_process.kill()
                except Exception:
                    pass
        
        logger.info("Traffic analyzer stopped")
    
    def _capture_loop(self):
        """Main capture loop using tcpdump"""
        try:
            # Build tcpdump command
            # -l: line-buffered, -n: no DNS resolution, -q: quiet (brief output)
            # -tttt: timestamp format
            cmd = [
                'sudo', 'tcpdump',
                '-i', self.interface,
                '-l', '-n', '-q',
                '-tttt',
                'not port 22 and not port 8000'  # Exclude SSH and web UI traffic
            ]
            
            logger.info(f"Starting tcpdump: {' '.join(cmd)}")
            
            self._capture_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            # Start stderr reader thread to capture errors
            def read_stderr():
                try:
                    for line in self._capture_process.stderr:
                        line = line.strip()
                        if line:
                            logger.debug(f"tcpdump stderr: {line}")
                            # Log important messages as warnings
                            if 'error' in line.lower() or 'permission' in line.lower():
                                logger.warning(f"tcpdump: {line}")
                            elif 'listening on' in line.lower():
                                logger.info(f"tcpdump: {line}")
                except Exception as e:
                    logger.debug(f"Stderr reader error: {e}")
            
            stderr_thread = threading.Thread(target=read_stderr, daemon=True)
            stderr_thread.start()
            
            # Wait briefly and check if process started successfully
            time.sleep(0.5)
            if self._capture_process.poll() is not None:
                # Process already terminated
                stderr_output = self._capture_process.stderr.read()
                logger.error(f"tcpdump failed to start: {stderr_output}")
                self._running = False
                return
            
            logger.info("tcpdump capture started successfully")
            
            while self._running and self._capture_process.poll() is None:
                try:
                    line = self._capture_process.stdout.readline()
                    if line:
                        self._raw_packet_count += 1
                        try:
                            self._packet_queue.put_nowait(line.strip())
                        except queue.Full:
                            pass  # Drop packet if queue is full
                except Exception as e:
                    logger.debug(f"Capture read error: {e}")
                    break
            
            # Log exit reason
            if self._capture_process.poll() is not None:
                rc = self._capture_process.returncode
                logger.info(f"tcpdump exited with code {rc}")
                    
        except Exception as e:
            logger.error(f"Capture loop error: {e}")
        finally:
            self._running = False
    
    def _analysis_loop(self):
        """Process captured packets and generate statistics"""
        batch = []
        batch_size = 100
        last_metrics_update = time.time()
        
        while self._running:
            try:
                # Collect batch of packets
                try:
                    packet = self._packet_queue.get(timeout=1)
                    batch.append(packet)
                except queue.Empty:
                    pass
                
                # Process batch when full or on timeout
                if len(batch) >= batch_size or (batch and time.time() - last_metrics_update > 1):
                    self._process_packet_batch(batch)
                    batch = []
                    
                    # Update metrics
                    current_time = time.time()
                    if current_time - last_metrics_update >= 1:
                        self._update_metrics()
                        last_metrics_update = current_time
                    
            except Exception as e:
                logger.error(f"Analysis error: {e}")
    
    def _process_packet_batch(self, packets: List[str]):
        """Process a batch of captured packets"""
        with self._lock:
            for packet_line in packets:
                self._parse_and_record_packet(packet_line)
    
    def _parse_and_record_packet(self, line: str):
        """Parse a tcpdump line and record statistics"""
        # tcpdump -q -tttt output examples:
        # 2024-01-15 10:30:45.123456 IP 192.168.1.100.443 > 192.168.1.1.54321: tcp 52
        # 2024-01-15 10:30:45.123456 IP 192.168.1.100 > 192.168.1.1: ICMP echo request
        # 2024-01-15 10:30:45.123456 ARP, Request who-has 192.168.1.1 tell 192.168.1.100
        try:
            # Always count this as a packet
            self.total_packets += 1
            
            # Skip if too short
            if not line or len(line) < 20:
                return
            
            parts = line.split()
            if len(parts) < 5:
                return
            
            # Find protocol indicator (IP, IP6, ARP, etc.)
            protocol = 'unknown'
            proto_idx = -1
            for i, part in enumerate(parts[2:6], start=2):  # Start after timestamp
                part_upper = part.upper().rstrip(',')
                if part_upper in ['IP', 'IP6', 'ARP', 'ICMP', 'ICMP6']:
                    protocol = part_upper.lower()
                    proto_idx = i
                    break
            
            if proto_idx == -1:
                # Try to detect from content
                if 'tcp' in line.lower():
                    protocol = 'tcp'
                elif 'udp' in line.lower():
                    protocol = 'udp'
                else:
                    protocol = 'other'
            
            # Extract IP addresses with regex - more flexible
            # Match patterns like: 192.168.1.100.443 or 192.168.1.100
            ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\.(\d+))?'
            ip_matches = re.findall(ip_pattern, line)
            
            if len(ip_matches) < 2:
                # At least count the packet
                self.total_bytes += 64  # Estimate
                return
            
            src_ip = ip_matches[0][0]
            src_port = int(ip_matches[0][1]) if ip_matches[0][1] else 0
            dst_ip = ip_matches[1][0]
            dst_port = int(ip_matches[1][1]) if ip_matches[1][1] else 0
            
            # Extract size if available
            size_match = re.search(r'length\s+(\d+)|:\s+(?:tcp|udp)\s+(\d+)|(?:tcp|udp)\s+(\d+)', line.lower())
            if size_match:
                packet_size = int(next(g for g in size_match.groups() if g))
            else:
                packet_size = 64  # Default estimate
            
            # Update global stats  
            self.total_bytes += packet_size
            
            # Update host stats
            self._update_host_stats(src_ip, 'out', packet_size, protocol, dst_port)
            self._update_host_stats(dst_ip, 'in', packet_size, protocol, src_port)
            
            # Update connection tracking
            conn_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            if conn_key not in self.connections:
                self.connections[conn_key] = ConnectionStats(
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port,
                    protocol=protocol
                )
            conn = self.connections[conn_key]
            conn.packets_sent += 1
            conn.bytes_sent += packet_size
            conn.last_seen = datetime.now()
            
            # Check for suspicious patterns
            self._check_suspicious_patterns(src_ip, dst_ip, src_port, dst_port, protocol)
            
            # Check for DNS queries
            if dst_port == 53 or src_port == 53:
                self._record_dns_query(line, src_ip, dst_ip)
                
        except Exception as e:
            logger.debug(f"Packet parse error: {e}")
    
    def _update_host_stats(self, ip: str, direction: str, size: int, protocol: str, port: int):
        """Update statistics for a host"""
        if ip not in self.host_stats:
            self.host_stats[ip] = HostTrafficStats(ip=ip)
        
        stats = self.host_stats[ip]
        stats.total_packets += 1
        stats.total_bytes += size
        stats.last_seen = datetime.now()
        
        if direction == 'in':
            stats.packets_in += 1
            stats.bytes_in += size
        else:
            stats.packets_out += 1
            stats.bytes_out += size
        
        # Protocol tracking
        stats.protocols[protocol] = stats.protocols.get(protocol, 0) + 1
        
        # Port tracking (limit to prevent memory bloat)
        if len(stats.ports_contacted) < 1000:
            stats.ports_contacted.add(port)
    
    def _record_dns_query(self, line: str, src_ip: str, dst_ip: str):
        """Record DNS queries for analysis and check for tunneling"""
        self.dns_queries.append({
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'raw': line[:200]
        })

        # Update host DNS queries
        if src_ip in self.host_stats:
            host = self.host_stats[src_ip]
            if len(host.dns_queries) < 100:
                host.dns_queries.append(line[:100])

        # Check for DNS tunneling (high query rate)
        if src_ip not in self._local_ips:
            self._check_dns_tunneling(src_ip)
    
    def _check_suspicious_patterns(self, src_ip: str, dst_ip: str,
                                   src_port: int, dst_port: int, protocol: str):
        """Check for suspicious traffic patterns"""
        # Skip alerts for traffic from OR to Ragnar itself (local IPs)
        # This prevents false positives from Ragnar's own scanning/network activity
        if src_ip in self._local_ips or dst_ip in self._local_ips:
            return

        # Check suspicious ports (only for external traffic)
        if dst_port in self.SUSPICIOUS_PORTS or src_port in self.SUSPICIOUS_PORTS:
            suspicious_port = dst_port if dst_port in self.SUSPICIOUS_PORTS else src_port
            port_description = self.SUSPICIOUS_PORTS.get(suspicious_port, "Unknown")
            self._create_alert(
                level=TrafficAlertLevel.MEDIUM,
                category=AlertCategory.SUSPICIOUS_PORT.value,
                message=f"Suspicious port {suspicious_port} ({port_description}): {src_ip} -> {dst_ip}",
                src_ip=src_ip,
                dst_ip=dst_ip,
                details={
                    'port': suspicious_port,
                    'port_description': port_description,
                    'protocol': protocol,
                    'direction': 'outbound' if dst_port == suspicious_port else 'inbound'
                }
            )

        # Check for potential port scanning (many ports from same source)
        # Only alert for external IPs doing port scans
        if src_ip in self.host_stats and src_ip not in self._local_ips:
            stats = self.host_stats[src_ip]
            ports_count = len(stats.ports_contacted)
            if ports_count > 50:
                self._create_alert(
                    level=TrafficAlertLevel.HIGH,
                    category=AlertCategory.PORT_SCAN.value,
                    message=f"Port scan detected: {src_ip} probed {ports_count} unique ports",
                    src_ip=src_ip,
                    details={
                        'ports_scanned': ports_count,
                        'sample_ports': list(stats.ports_contacted)[:20],
                        'scan_duration_seconds': (stats.last_seen - stats.first_seen).total_seconds()
                    }
                )

    def _check_dns_tunneling(self, src_ip: str):
        """Detect potential DNS tunneling based on query frequency"""
        current_time = time.time()

        # Track this query timestamp
        self._dns_query_times[src_ip].append(current_time)

        # Count queries in the tracking window
        window_start = current_time - self.DNS_QUERY_TRACKING_WINDOW
        recent_queries = sum(1 for t in self._dns_query_times[src_ip] if t > window_start)

        if recent_queries > self.DNS_TUNNEL_THRESHOLD:
            self._create_alert(
                level=TrafficAlertLevel.HIGH,
                category=AlertCategory.DNS_TUNNELING.value,
                message=f"Potential DNS tunneling: {src_ip} made {recent_queries} queries in {self.DNS_QUERY_TRACKING_WINDOW}s",
                src_ip=src_ip,
                details={
                    'queries_per_minute': recent_queries,
                    'threshold': self.DNS_TUNNEL_THRESHOLD,
                    'window_seconds': self.DNS_QUERY_TRACKING_WINDOW
                }
            )
    
    def _create_alert(self, level: TrafficAlertLevel, category: str,
                      message: str, src_ip: str = None, dst_ip: str = None,
                      details: Dict = None):
        """Create a traffic alert with rate limiting and deduplication"""
        current_time = time.time()

        # Alert deduplication - prevent same alert from firing repeatedly
        alert_hash = f"{category}:{src_ip}:{dst_ip}"
        if alert_hash in self._alert_hashes:
            # Check if dedup window has expired
            if current_time < self._alert_hash_expiry.get(alert_hash, 0):
                return  # Skip duplicate alert within window

        # Rate limiting (global)
        self._alert_timestamps.append(current_time)
        recent_alerts = sum(1 for t in self._alert_timestamps if current_time - t < 60)
        if recent_alerts > self.MAX_ALERTS_PER_MINUTE:
            return  # Skip alert if rate limited

        # Mark this alert as seen with expiry
        self._alert_hashes.add(alert_hash)
        self._alert_hash_expiry[alert_hash] = current_time + self._alert_dedup_window

        # Clean up old hash entries periodically
        if len(self._alert_hash_expiry) > 1000:
            expired = [h for h, exp in self._alert_hash_expiry.items() if exp < current_time]
            for h in expired:
                self._alert_hashes.discard(h)
                del self._alert_hash_expiry[h]

        self._alert_counter += 1
        alert = TrafficAlert(
            alert_id=f"TA-{self._alert_counter:06d}",
            level=level,
            category=category,
            message=message,
            src_ip=src_ip,
            dst_ip=dst_ip,
            details=details or {}
        )

        self.alerts.append(alert)

        # Trigger callbacks
        for callback in self._on_alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")
    
    def _update_metrics(self):
        """Update packets/bytes per second metrics"""
        current_time = time.time()
        elapsed = current_time - self._last_metrics_time
        
        if elapsed > 0:
            packets_delta = self.total_packets - self._last_packet_count
            bytes_delta = self.total_bytes - self._last_byte_count
            
            self.packets_per_second = packets_delta / elapsed
            self.bytes_per_second = bytes_delta / elapsed
            
            self._last_packet_count = self.total_packets
            self._last_byte_count = self.total_bytes
            self._last_metrics_time = current_time
    
    def on_alert(self, callback: Callable):
        """Register a callback for alerts"""
        self._on_alert_callbacks.append(callback)

    def _format_bytes(self, bytes_val: int) -> str:
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.1f} PB"

    def _count_alerts_by_severity(self) -> Dict[str, int]:
        """Count alerts grouped by severity level"""
        counts = {level.value: 0 for level in TrafficAlertLevel}
        for alert in self.alerts:
            counts[alert.level.value] += 1
        return counts

    def _count_alerts_by_category(self) -> Dict[str, int]:
        """Count alerts grouped by category"""
        counts = defaultdict(int)
        for alert in self.alerts:
            counts[alert.category] += 1
        return dict(counts)

    def get_summary(self) -> Dict[str, Any]:
        """Get traffic analysis summary with security-focused metrics"""
        with self._lock:
            unacked_alerts = [a for a in self.alerts if not a.acknowledged]
            uptime_seconds = None
            if self._start_time:
                uptime_seconds = (datetime.now() - self._start_time).total_seconds()

            return {
                # Capture status
                'status': 'running' if self._running else 'stopped',
                'interface': self.interface,
                'capture_started': self._start_time.isoformat() if self._start_time else None,
                'uptime_seconds': uptime_seconds,

                # Traffic metrics
                'total_packets': self.total_packets,
                'total_bytes': self.total_bytes,
                'total_bytes_human': self._format_bytes(self.total_bytes),
                'packets_per_second': round(self.packets_per_second, 2),
                'bytes_per_second': round(self.bytes_per_second, 2),
                'throughput_mbps': round(self.bytes_per_second * 8 / 1_000_000, 2),

                # Network inventory
                'unique_hosts': len(self.host_stats),
                'active_connections': len(self.connections),

                # Security metrics
                'total_alerts': len(self.alerts),
                'unacknowledged_alerts': len(unacked_alerts),
                'alerts_by_severity': self._count_alerts_by_severity(),
                'alerts_by_category': self._count_alerts_by_category(),

                # DNS monitoring
                'dns_queries_captured': len(self.dns_queries),

                # Configuration
                'excluded_local_ips': list(self._local_ips),
                'alert_dedup_window_seconds': self._alert_dedup_window,
            }
    
    def get_top_hosts(self, limit: int = 10, sort_by: str = 'bytes') -> List[Dict]:
        """Get top hosts by traffic"""
        with self._lock:
            hosts = list(self.host_stats.values())
            
            if sort_by == 'bytes':
                hosts.sort(key=lambda h: h.total_bytes, reverse=True)
            elif sort_by == 'packets':
                hosts.sort(key=lambda h: h.total_packets, reverse=True)
            elif sort_by == 'connections':
                hosts.sort(key=lambda h: len(h.ports_contacted), reverse=True)
            
            return [h.to_dict() for h in hosts[:limit]]
    
    def get_active_connections(self, limit: int = 50) -> List[Dict]:
        """Get active connections sorted by last activity"""
        with self._lock:
            conns = list(self.connections.values())
            conns.sort(key=lambda c: c.last_seen, reverse=True)
            return [c.to_dict() for c in conns[:limit]]
    
    def get_alerts(self, limit: int = 100, level: str = None) -> List[Dict]:
        """Get recent alerts"""
        with self._lock:
            alerts = list(self.alerts)
            if level:
                try:
                    level_enum = TrafficAlertLevel(level)
                    alerts = [a for a in alerts if a.level == level_enum]
                except ValueError:
                    pass
            return [a.to_dict() for a in alerts[-limit:]]
    
    def get_protocol_distribution(self) -> Dict[str, int]:
        """Get protocol distribution across all hosts"""
        with self._lock:
            distribution = defaultdict(int)
            for host in self.host_stats.values():
                for proto, count in host.protocols.items():
                    distribution[proto] += count
            return dict(distribution)
    
    def get_host_details(self, ip: str) -> Optional[Dict]:
        """Get detailed stats for a specific host"""
        with self._lock:
            if ip in self.host_stats:
                return self.host_stats[ip].to_dict()
            return None
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert"""
        with self._lock:
            for alert in self.alerts:
                if alert.alert_id == alert_id:
                    alert.acknowledged = True
                    return True
            return False
    
    def clear_stats(self):
        """Clear all statistics and reset state"""
        with self._lock:
            self.host_stats.clear()
            self.connections.clear()
            self.alerts.clear()
            self.dns_queries.clear()
            self.total_packets = 0
            self.total_bytes = 0
            self._last_packet_count = 0
            self._last_byte_count = 0
            # Clear deduplication tracking
            self._alert_hashes.clear()
            self._alert_hash_expiry.clear()
            self._dns_query_times.clear()
            self._alert_counter = 0


# Global instance
_traffic_analyzer: Optional[TrafficAnalyzer] = None


def get_traffic_analyzer(shared_data=None, interface: str = None) -> TrafficAnalyzer:
    """Get or create the global TrafficAnalyzer instance"""
    global _traffic_analyzer
    if _traffic_analyzer is None:
        _traffic_analyzer = TrafficAnalyzer(shared_data, interface)
    return _traffic_analyzer
