#scanning.py
# This script performs a network scan to identify live hosts, their MAC addresses, and open ports.
# MAC/host resolution: SQLITE DB ONLY - CSV logic removed
# All host and scan state is stored and read exclusively via SQLite db_manager API (self.db).
# CSV files are kept for optional result display only, NOT as input or source of truth.

import os
import threading
import csv  # Only used for optional display functionality
import traceback
import tempfile
import shutil
from concurrent.futures import ThreadPoolExecutor
try:
    import pandas as pd
except ImportError:
    pd = None
import socket
import subprocess
import re
# Try to import network interface library
netifaces = None
try:
    import netifaces  # type: ignore
except ImportError:
    try:
        import netifaces_plus as netifaces  # type: ignore
    except ImportError:
        print("Warning: Neither netifaces nor netifaces-plus found. Network discovery may be limited.")
import time
import glob
import logging
from datetime import datetime
try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    from rich.progress import Progress
except ImportError:
    Console = Table = Text = Progress = None
# MAC address getter with fallback
def gma(*args, **kwargs):
    try:
        from getmac import get_mac_address
        result = get_mac_address(*args, **kwargs)
        return result if result else '00:00:00:00:00:00'
    except ImportError:
        try:
            import getmac
            result = getmac.get_mac_address(*args, **kwargs)
            return result if result else '00:00:00:00:00:00'
        except (ImportError, AttributeError):
            return '00:00:00:00:00:00'
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared import SharedData
from logger import Logger
import ipaddress
try:
    import nmap
except ImportError:
    nmap = None
try:
    from nmap_logger import nmap_logger
except ImportError:
    nmap_logger = None
from db_manager import get_db

logger = Logger(name="scanning.py", level=logging.DEBUG)

b_class = "NetworkScanner"
b_module = "scanning"
b_status = "network_scanner"
b_port = None
b_parent = None
b_priority = 1

class NetworkScanner:
    """
    This class handles the entire network scanning process.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.logger = logger
        self.displaying_csv = shared_data.displaying_csv
        self.blacklistcheck = shared_data.blacklistcheck
        self.mac_scan_blacklist = shared_data.mac_scan_blacklist
        self.ip_scan_blacklist = shared_data.ip_scan_blacklist
        self.console = Console() if Console else None
        self.lock = threading.Lock()
        self.currentdir = shared_data.currentdir
        # CRITICAL: Pi Zero W2 has limited resources - use conservative thread count
        # 512MB RAM, 4 cores @ 1GHz can only handle a few concurrent operations
        cpu_count = os.cpu_count() or 1
        # Limit concurrent socket operations aggressively on the Pi Zero 2 W
        self.port_scan_workers = max(2, min(6, cpu_count))
        self.host_scan_workers = max(2, min(6, cpu_count))
        self.semaphore = threading.Semaphore(min(4, max(1, cpu_count // 2 or 1)))
        self.nm = nmap.PortScanner() if nmap else None  # Initialize nmap.PortScanner()
        self.running = False
        self.arp_scan_interface = self._detect_default_interface()
        self._active_scan_network = None
        # Initialize SQLite database manager
        self.db = get_db(currentdir=self.currentdir)

    @staticmethod
    def _detect_default_interface():
        """Detect the active network interface using ip route."""
        try:
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True, text=True, timeout=5
            )
            # Parse: default via 172.16.52.1 dev br-lan ...
            for line in result.stdout.strip().splitlines():
                parts = line.split()
                if 'dev' in parts:
                    idx = parts.index('dev')
                    if idx + 1 < len(parts):
                        return parts[idx + 1]
        except Exception:
            pass
        # Fallback: find first non-lo interface with an IP
        try:
            result = subprocess.run(
                ['ip', '-o', '-4', 'addr', 'show'],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().splitlines():
                # Format: 3: br-lan    inet 172.16.52.1/24 brd ...
                parts = line.split()
                if len(parts) >= 4 and '127.0.0.1' not in line:
                    iface = parts[1].rstrip(':')
                    if iface != 'lo':
                        return iface
        except Exception:
            pass
        return 'wlan0'

    @staticmethod
    def _is_valid_mac(value):
        """Validate MAC address format."""
        if not value:
            return False
        return bool(re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", value.lower()))

    @staticmethod
    def _is_valid_ip(value):
        """Validate IPv4 address format."""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def resolve_hostname(self, ip):
        """Resolve hostname for the given IP address."""
        try:
            if ip and self._is_valid_ip(ip):
                hostname, _, _ = socket.gethostbyaddr(ip)
                return hostname
        except (socket.herror, socket.gaierror):
            return ""
        except Exception as e:
            self.logger.debug(f"Error resolving hostname for {ip}: {e}")
        return ""

    def _parse_arp_scan_output(self, output):
        """Parse arp-scan output into a mapping of IP to metadata."""
        hosts = {}
        if not output:
            return hosts

        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("Interface:") or line.startswith("Starting") or line.startswith("Ending"):
                continue

            parts = re.split(r"\s+", line)
            if len(parts) < 2:
                continue

            ip_candidate, mac_candidate = parts[0], parts[1]
            if not (self._is_valid_ip(ip_candidate) and self._is_valid_mac(mac_candidate)):
                continue

            vendor = " ".join(parts[2:]).strip() if len(parts) > 2 else ""
            hosts[ip_candidate] = {
                "mac": mac_candidate.lower(),
                "vendor": vendor
            }

        return hosts

    def run_arp_scan(self, network=None):
        """Execute arp-scan to get MAC addresses and vendor information for local network hosts."""
        # Try both --localnet and explicit subnet scanning for comprehensive MAC discovery
        subnet = str(network) if network else '192.168.1.0/24'
        commands = [
            ['sudo', 'arp-scan', f'--interface={self.arp_scan_interface}', '--localnet'],
            ['sudo', 'arp-scan', f'--interface={self.arp_scan_interface}', subnet]
        ]
        
        all_hosts = {}
        
        for command in commands:
            self.logger.info(f"Running arp-scan for MAC/vendor discovery: {' '.join(command)}")
            try:
                result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=120)
                hosts = self._parse_arp_scan_output(result.stdout)
                self.logger.info(f"arp-scan command '{' '.join(command)}' discovered {len(hosts)} MACs")
                all_hosts.update(hosts)  # Merge results from both scans
            except FileNotFoundError:
                self.logger.error("arp-scan command not found. Install arp-scan or adjust configuration.")
                continue
            except subprocess.TimeoutExpired as e:
                self.logger.error(f"arp-scan timed out: {e}")
                hosts = self._parse_arp_scan_output(e.stdout or "")
                all_hosts.update(hosts)
            except subprocess.CalledProcessError as e:
                self.logger.warning(f"arp-scan exited with code {e.returncode}: {e.stderr.strip() if e.stderr else 'no stderr'}")
                hosts = self._parse_arp_scan_output(e.stdout or "")
                all_hosts.update(hosts)
            except Exception as e:
                self.logger.error(f"Unexpected error running arp-scan: {e}")
                continue
        
        self.logger.info(f"📋 arp-scan complete: {len(all_hosts)} hosts with MAC addresses discovered")
        
        # Write ARP scan results to SQLite database
        try:
            for ip, metadata in all_hosts.items():
                mac = metadata.get('mac', '').lower().strip()
                vendor = metadata.get('vendor', '')
                
                if mac and mac != '00:00:00:00:00:00':
                    self.db.upsert_host(
                        mac=mac,
                        ip=ip,
                        vendor=vendor
                    )
                    self.db.update_ping_status(mac, success=True)
                    self.db.add_scan_history(mac, ip, 'arp_scan')
            
            self.logger.debug(f"✅ ARP scan results written to database")
        except Exception as e:
            self.logger.error(f"Failed to write ARP scan results to database: {e}")
        
        return all_hosts

    def run_nmap_network_scan(self, network_cidr, portstart, portend, extra_ports):

        self.logger.info(f"🚀 Starting nmap network-wide scan: {network_cidr}")
        
        # Most common ports - top 50 commonly used ports
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 
            143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
            # Add extra_ports for custom services
            *( extra_ports or [] )
        ]
        
        # Remove duplicates while preserving order
        seen_ports = set()
        ordered_ports = []
        for port in common_ports:
            if port not in seen_ports:
                seen_ports.add(port)
                ordered_ports.append(port)
        
        port_list = ','.join(map(str, ordered_ports))
        

        nmap_args = f"-Pn -sS -p{port_list} --open --min-rate 1000 --max-retries 1 --host-timeout 10s -v"
        
        nmap_command = f"nmap {nmap_args} {network_cidr}"
        self.logger.info(f"🔍 Executing: {nmap_command}")
        self.logger.info(f"   Scanning {len(ordered_ports)} ports across entire {network_cidr} network")
        
        nmap_results = {}
        
        try:
            scan_start = time.time()
            self.nm.scan(hosts=network_cidr, arguments=nmap_args)
            scan_duration = time.time() - scan_start
            
            all_hosts = self.nm.all_hosts()
            self.logger.info(f"✅ Network scan complete in {scan_duration:.2f}s - found {len(all_hosts)} hosts with open ports")
            
            for host in all_hosts:
                try:
                    hostname = self.nm[host].hostname() or ''
                    open_ports = []
                    
                    # Extract open TCP ports
                    if 'tcp' in self.nm[host]:
                        tcp_ports = self.nm[host]['tcp']
                        for port in tcp_ports:
                            if tcp_ports[port]['state'] == 'open':
                                open_ports.append(port)
                                self.logger.debug(f"   ✅ {host}: port {port}/tcp open ({tcp_ports[port].get('name', 'unknown')})")
                    
                    # Extract open UDP ports if scanned
                    if 'udp' in self.nm[host]:
                        udp_ports = self.nm[host]['udp']
                        for port in udp_ports:
                            if udp_ports[port]['state'] == 'open':
                                open_ports.append(port)
                                self.logger.debug(f"   ✅ {host}: port {port}/udp open")
                    
                    if open_ports:
                        nmap_results[host] = {
                            'hostname': hostname,
                            'open_ports': sorted(open_ports)
                        }
                        self.logger.info(f"📍 {host} ({hostname or 'no hostname'}): {len(open_ports)} open ports - {sorted(open_ports)}")
                    
                except Exception as e:
                    self.logger.warning(f"Error processing nmap results for {host}: {e}")
                    continue
            
            self.logger.info(f"🎉 NMAP NETWORK SCAN COMPLETE: {len(nmap_results)} hosts with open ports discovered")
            
            # Write nmap scan results to SQLite database
            # MAC/host resolution: SQLITE DB ONLY - CSV logic removed
            # Pseudo-MAC generation: Only here and in update_netkb() via DB operations
            try:
                for host, data in nmap_results.items():
                    mac = data.get('mac', '')
                    if not mac or mac == '00:00:00:00:00:00':
                        # Check if this IP already exists in database with a real MAC
                        existing_mac = next((h['mac'] for h in self.db.get_all_hosts() 
                                           if h.get('ip') == host and not h['mac'].startswith('00:00:c0:a8')), None)
                        
                        if existing_mac:
                            # Use existing real MAC instead of creating pseudo-MAC
                            mac = existing_mac
                            self.logger.info(f"✅ Nmap results: Found existing MAC {mac} for IP {host}, skipping pseudo-MAC creation")
                        else:
                            # Pseudo-MAC generation: ONLY via update_netkb() - defer to that method
                            # This temporary pseudo-MAC will be reconciled in update_netkb()
                            ip_parts = host.split('.')
                            if len(ip_parts) == 4:
                                mac = f"00:00:{int(ip_parts[0]):02x}:{int(ip_parts[1]):02x}:{int(ip_parts[2]):02x}:{int(ip_parts[3]):02x}"
                                self.logger.warning(f"⚠️ Nmap results: Creating temporary pseudo-MAC {mac} for IP {host} (will be reconciled in update_netkb)")
                    
                    if mac:
                        mac = mac.lower().strip()
                        ports_str = ','.join(map(str, sorted(data.get('open_ports', []))))
                        
                        self.db.upsert_host(
                            mac=mac,
                            ip=host,
                            hostname=data.get('hostname', ''),
                            ports=ports_str
                        )
                        self.db.update_ping_status(mac, success=True)
                        self.db.add_scan_history(mac, host, 'nmap_scan', ports_found=ports_str)
                
                self.logger.debug(f"✅ Nmap scan results written to database")
            except Exception as e:
                self.logger.error(f"Failed to write nmap scan results to database: {e}")
            
        except Exception as e:
            self.logger.error(f"💥 Nmap network scan failed: {type(e).__name__}: {e}")
            self.logger.debug(f"Full traceback: {traceback.format_exc()}")
        
        return nmap_results

    def _ping_sweep_missing_hosts(self, arp_hosts, target_cidrs=None, priority_targets=None):
        """Ping sweep to find hosts that don't respond to arp-scan but are alive."""
        ping_discovered = {}
        known_ips = set(arp_hosts.keys())

        if not target_cidrs:
            target_cidrs = ['192.168.1.0/24']

        # CRITICAL TARGET: Always ensure 192.168.1.192 is checked explicitly unless overridden
        if priority_targets is None:
            priority_targets = ['192.168.1.192']

        self.logger.info(f"🔍 Starting ping sweep - ARP found {len(arp_hosts)} hosts, checking {254} additional IPs")

        for cidr in target_cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError as e:
                self.logger.error(f"Invalid network {cidr}: {e}")
                continue

            # First, ping priority targets explicitly
            for priority_ip in priority_targets:
                if priority_ip in known_ips:
                    self.logger.info(f"✅ Priority target {priority_ip} already found by ARP scan")
                    continue
                
                self.logger.info(f"🎯 PRIORITY PING: Testing critical target {priority_ip}")
                try:
                    result = subprocess.run(
                        ['ping', '-c', '3', '-W', '3', priority_ip],  # 3 pings, 3 sec timeout
                        capture_output=True, text=True, timeout=10
                    )

                    if result.returncode == 0:
                        mac = self.get_mac_address(priority_ip, "")
                        if not mac or mac == "00:00:00:00:00:00":
                            # MAC/host resolution: SQLITE DB ONLY
                            # Check if this IP already exists in database with a real MAC
                            existing_hosts = self.db.get_all_hosts()
                            existing_mac = next((h['mac'] for h in existing_hosts if h.get('ip') == priority_ip and not h['mac'].startswith('00:00:c0:a8')), None)
                            
                            if existing_mac:
                                mac = existing_mac
                                self.logger.info(f"✅ Priority target {priority_ip}: Found existing MAC {mac} from DB, skipping pseudo-MAC")
                            else:
                                # Pseudo-MAC generation: temporary, will be reconciled in update_netkb()
                                ip_parts = priority_ip.split('.')
                                pseudo_mac = f"00:00:{int(ip_parts[0]):02x}:{int(ip_parts[1]):02x}:{int(ip_parts[2]):02x}:{int(ip_parts[3]):02x}"
                                mac = pseudo_mac
                                self.logger.warning(f"⚠️ Priority target {priority_ip}: Creating temporary pseudo-MAC {mac} (will be reconciled in update_netkb)")

                        ping_discovered[priority_ip] = {
                            "mac": mac,
                            "vendor": "Priority target (discovered by ping)"
                        }
                        self.logger.info(f"🎉 PRIORITY TARGET FOUND: {priority_ip} (MAC: {mac})")
                    else:
                        self.logger.warning(f"❌ Priority target {priority_ip} not responding to ping")

                except subprocess.TimeoutExpired:
                    self.logger.warning(f"⏰ Priority target {priority_ip} ping timed out")
                except Exception as e:
                    self.logger.error(f"💥 Priority target {priority_ip} ping failed: {e}")

            # Then scan the rest of the network
            for ip in network.hosts():  # skips network/broadcast
                ip_str = str(ip)
                if ip_str in known_ips or ip_str in priority_targets:
                    continue

                try:
                    result = subprocess.run(
                        ['ping', '-c', '1', '-W', '2', ip_str],
                        capture_output=True, text=True, timeout=5
                    )

                    if result.returncode == 0:
                        mac = self.get_mac_address(ip_str, "")
                        if not mac or mac == "00:00:00:00:00:00":
                            # MAC/host resolution: SQLITE DB ONLY
                            # Check if this IP already exists in database with a real MAC
                            existing_hosts = self.db.get_all_hosts()
                            existing_mac = next((h['mac'] for h in existing_hosts if h.get('ip') == ip_str and not h['mac'].startswith('00:00:c0:a8')), None)
                            
                            if existing_mac:
                                mac = existing_mac
                                self.logger.debug(f"✅ Ping sweep {ip_str}: Found existing MAC {mac} from DB, skipping pseudo-MAC")
                            else:
                                # Pseudo-MAC generation: temporary, will be reconciled in update_netkb()
                                ip_parts = ip_str.split('.')
                                pseudo_mac = f"00:00:{int(ip_parts[0]):02x}:{int(ip_parts[1]):02x}:{int(ip_parts[2]):02x}:{int(ip_parts[3]):02x}"
                                mac = pseudo_mac
                                self.logger.debug(f"⚠️ Ping sweep {ip_str}: Creating temporary pseudo-MAC {mac} (will be reconciled in update_netkb)")

                        ping_discovered[ip_str] = {
                            "mac": mac,
                            "vendor": "Unknown (discovered by ping)"
                        }
                        self.logger.info(f"📡 Ping sweep found host: {ip_str} (MAC: {mac})")

                except subprocess.TimeoutExpired:
                    self.logger.debug(f"Ping sweep: {ip_str} timed out")
                except Exception as e:
                    self.logger.debug(f"Ping sweep: {ip_str} failed ({e})")
                    continue

        if ping_discovered:
            self.logger.info(f"🎊 PING SWEEP COMPLETE: Discovered {len(ping_discovered)} additional hosts not found by arp-scan")
            for ip, data in ping_discovered.items():
                self.logger.info(f"   📍 {ip} - MAC: {data['mac']} - {data['vendor']}")
            
            # Write ping sweep results to SQLite database
            try:
                for ip, data in ping_discovered.items():
                    mac = data['mac'].lower().strip()
                    vendor = data.get('vendor', '')
                    
                    self.db.upsert_host(
                        mac=mac,
                        ip=ip,
                        vendor=vendor
                    )
                    self.db.update_ping_status(mac, success=True)
                    self.db.add_scan_history(mac, ip, 'ping_sweep')
                
                self.logger.debug(f"✅ Ping sweep results written to database")
            except Exception as e:
                self.logger.error(f"Failed to write ping sweep results to database: {e}")
        else:
            self.logger.warning(f"❌ Ping sweep found no additional hosts beyond ARP scan results")

        return ping_discovered

    def run_initial_ping_sweep(self, include_arp_scan=True, cidrs=None):
        """Run a lightweight ARP + ping discovery, typically after Wi-Fi connects."""
        try:
            target_cidrs = list(cidrs) if cidrs else []
            if not target_cidrs:
                network = None
                try:
                    network = self.get_network()
                except Exception as network_error:
                    self.logger.warning(f"Unable to determine current network for ping sweep: {network_error}")
                if network:
                    target_cidrs.append(str(network))
                else:
                    target_cidrs.append('192.168.1.0/24')

            self.logger.info(f"🚀 Initial ping sweep requested across {', '.join(target_cidrs)}")
            arp_hosts = self.run_arp_scan(network=network) if include_arp_scan else {}
            ping_results = self._ping_sweep_missing_hosts(
                arp_hosts,
                target_cidrs=target_cidrs
            )

            summary = {
                'arp_hosts': len(arp_hosts),
                'ping_hosts': len(ping_results),
                'target_cidrs': target_cidrs
            }
            self.logger.info(
                f"📡 Initial ping sweep complete: {summary['arp_hosts']} ARP hosts, "
                f"{summary['ping_hosts']} ping-only hosts"
            )
            return summary
        except Exception as exc:
            self.logger.error(f"Initial ping sweep failed: {exc}")
            self.logger.debug(f"Full traceback: {traceback.format_exc()}")
            return None

    def get_current_timestamp(self):
        """
        Returns the current timestamp in a specific format.
        """
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def ip_key(self, ip):
        """
        Converts an IP address to a tuple of integers for sorting.
        """
        if ip == "STANDALONE":
            return (0, 0, 0, 0)
        try:
            return tuple(map(int, ip.split('.')))
        except ValueError as e:
            self.logger.error(f"Error in ip_key: {e}")
            return (0, 0, 0, 0)

    def update_netkb(self, netkbfile, netkb_data, alive_macs):
        """
        Updates the network knowledge base with scan results.
        
        # MAC/host resolution: SQLITE DB ONLY - CSV logic removed
        # All host and scan state is stored and read exclusively via SQLite db_manager API (self.db).
        # This method integrates all scan results via SQLite alone.
        # No CSV fallback for host data - DB is the single source of truth.
        # Only update_netkb() creates pseudo-MACs, and only via DB operations.
        
        netkbfile parameter kept for backward compatibility but CSV is no longer used.
        """
        with self.lock:
            try:
                netkb_entries = {}
                existing_action_columns = []

                # Read existing data from SQLite database
                try:
                    existing_hosts = self.db.get_all_hosts()
                    self.logger.debug(f"Loaded {len(existing_hosts)} existing hosts from SQLite")
                    
                    for host in existing_hosts:
                        mac = host['mac']
                        # Parse IPs (stored as comma-separated in DB, we use ; for compatibility)
                        ips = host['ip'].split(',') if host['ip'] else []
                        hostnames = [host['hostname']] if host['hostname'] else []
                        alive = '1' if host['status'] == 'alive' else '0'
                        ports = host['ports'].split(',') if host['ports'] else []
                        failed_pings = host['failed_ping_count']
                        
                        netkb_entries[mac] = {
                            'IPs': set(ips) if ips else set(),
                            'Hostnames': set(hostnames) if hostnames else set(),
                            'Alive': alive,
                            'Ports': set(ports) if ports else set(),
                            'Failed_Pings': failed_pings,
                            'Deep_Scanned': "",  # TODO: Add to database schema
                            'Deep_Scan_Ports': "",  # TODO: Add to database schema
                            # Preserve action module statuses
                            'Scanner': host.get('scanner_status', ''),
                            'Network Profile': host.get('network_profile', ''),
                            'ssh_connector': host.get('ssh_connector', ''),
                            'rdp_connector': host.get('rdp_connector', ''),
                            'ftp_connector': host.get('ftp_connector', ''),
                            'smb_connector': host.get('smb_connector', ''),
                            'telnet_connector': host.get('telnet_connector', ''),
                            'sql_connector': host.get('sql_connector', ''),
                            'steal_files_ssh': host.get('steal_files_ssh', ''),
                            'steal_files_rdp': host.get('steal_files_rdp', ''),
                            'steal_files_ftp': host.get('steal_files_ftp', ''),
                            'steal_files_smb': host.get('steal_files_smb', ''),
                            'steal_files_telnet': host.get('steal_files_telnet', ''),
                            'steal_data_sql': host.get('steal_data_sql', ''),
                            'nmap_vuln_scanner': host.get('nmap_vuln_scanner', ''),
                            'Notes': host.get('notes', '')
                        }
                    
                    # Track which action columns exist (for new hosts)
                    if netkb_entries:
                        sample_entry = next(iter(netkb_entries.values()))
                        existing_action_columns = [k for k in sample_entry.keys() 
                                                  if k not in ["IPs", "Hostnames", "Alive", "Ports", 
                                                              "Failed_Pings", "Deep_Scanned", "Deep_Scan_Ports"]]
                        
                except Exception as db_error:
                    self.logger.error(f"Error reading from SQLite: {db_error}")
                    self.logger.debug(f"Traceback: {traceback.format_exc()}")
                    # Continue with empty netkb_entries - will create new database entries


                ip_to_mac = {}  # Dictionary to track IP to MAC associations

                for data in netkb_data:
                    mac, ip, hostname, ports = data
                    if not mac or mac == "STANDALONE" or ip == "STANDALONE" or hostname == "STANDALONE":
                        continue

                    hostname = self.db.sanitize_hostname(hostname)
                    
                    # MAC/host resolution: SQLITE DB ONLY - CSV logic removed
                    # Pseudo-MAC generation: ONLY in update_netkb() via DB operations
                    # For hosts with unknown MAC (00:00:00:00:00:00), use IP as unique identifier
                    # This allows tracking hosts across routers or when MAC can't be determined
                    if mac == "00:00:00:00:00:00":
                        # Check if this IP already exists in database with a real MAC
                        existing_mac = next((h['mac'] for h in self.db.get_all_hosts() 
                                           if h.get('ip') == ip and not h['mac'].startswith('00:00:c0:a8')), None)
                        
                        if existing_mac:
                            # Use existing real MAC instead of creating pseudo-MAC
                            mac = existing_mac
                            self.logger.info(f"✅ NetKB merge: Found existing MAC {mac} for IP {ip} from DB, skipping pseudo-MAC creation")
                        else:
                            # Pseudo-MAC generation: ONLY here in update_netkb() - this is the authoritative source
                            # Only create pseudo-MAC if no real MAC exists in database
                            ip_parts = ip.split('.')
                            if len(ip_parts) == 4:
                                # Convert IP to a unique MAC-like identifier: 00:00:ip1:ip2:ip3:ip4
                                pseudo_mac = f"00:00:{int(ip_parts[0]):02x}:{int(ip_parts[1]):02x}:{int(ip_parts[2]):02x}:{int(ip_parts[3]):02x}"
                                mac = pseudo_mac
                                self.logger.warning(f"⚠️ update_netkb: Created authoritative pseudo-MAC {mac} for IP {ip} (MAC address unavailable)")

                    if self.blacklistcheck and (mac in self.mac_scan_blacklist or ip in self.ip_scan_blacklist):
                        continue

                    # Check if IP is already associated with a different MAC
                    if ip in ip_to_mac and ip_to_mac[ip] != mac:
                        # Mark the old MAC as having a failed ping instead of immediately dead
                        old_mac = ip_to_mac[ip]
                        if old_mac in netkb_entries:
                            max_failed_pings = self.shared_data.config.get('network_max_failed_pings', 30)
                            current_failures = netkb_entries[old_mac].get('Failed_Pings', 0) + 1
                            netkb_entries[old_mac]['Failed_Pings'] = current_failures
                            
                            # Only mark as dead after reaching failure threshold
                            if current_failures >= max_failed_pings:
                                netkb_entries[old_mac]['Alive'] = '0'
                                self.logger.info(f"Old MAC {old_mac} marked offline after {current_failures} consecutive failed pings (IP reassigned to {mac})")
                            else:
                                netkb_entries[old_mac]['Alive'] = '1'  # Keep alive per 30-ping rule
                                self.logger.debug(f"Old MAC {old_mac} failed ping {current_failures}/{max_failed_pings} due to IP reassignment - keeping alive")

                    # Update or create entry for the new MAC
                    ip_to_mac[ip] = mac
                    if mac in netkb_entries:
                        netkb_entries[mac]['IPs'].add(ip)
                        netkb_entries[mac]['Hostnames'].add(hostname)
                        netkb_entries[mac]['Alive'] = '1'
                        
                        # CRITICAL: Merge ports instead of replacing to preserve deep scan results
                        # Deep scan discoveries should NOT be lost during regular automated scans
                        netkb_entries[mac]['Ports'].update(map(str, ports))
                        
                        netkb_entries[mac]['Failed_Pings'] = 0  # Reset failures since host is responsive
                        # Preserve deep scan metadata during updates
                        # (these fields are only set by deep_scan_host(), not regular scans)
                    else:
                        netkb_entries[mac] = {
                            'IPs': {ip},
                            'Hostnames': {hostname},
                            'Alive': '1',
                            'Ports': set(map(str, ports)),
                            'Failed_Pings': 0,  # New hosts start with 0 failed pings
                            'Deep_Scanned': "",  # Will be set by deep scan
                            'Deep_Scan_Ports': ""  # Will be set by deep scan
                        }
                        for action in existing_action_columns:
                            netkb_entries[mac][action] = ""

                # Update all existing entries - implement 30-failed-pings rule instead of immediate death
                max_failed_pings = self.shared_data.config.get('network_max_failed_pings', 30)
                for mac in netkb_entries:
                    if mac not in alive_macs:
                        # Host not found in current scan - increment failure count
                        current_failures = netkb_entries[mac].get('Failed_Pings', 0)
                        netkb_entries[mac]['Failed_Pings'] = current_failures + 1
                        
                        # Only mark as dead after reaching the failure threshold
                        if netkb_entries[mac]['Failed_Pings'] >= max_failed_pings:
                            netkb_entries[mac]['Alive'] = '0'
                            self.logger.info(f"Host {mac} marked offline after {netkb_entries[mac]['Failed_Pings']} consecutive failed pings")
                        else:
                            # Keep alive until threshold reached
                            netkb_entries[mac]['Alive'] = '1'  # Keep alive per 30-ping rule
                            self.logger.debug(f"Host {mac} failed ping {netkb_entries[mac]['Failed_Pings']}/{max_failed_pings} - keeping alive per {max_failed_pings}-ping rule")

                # Remove entries with multiple IP addresses for a single MAC address
                netkb_entries = {mac: data for mac, data in netkb_entries.items() if len(data['IPs']) == 1}

                sorted_netkb_entries = sorted(netkb_entries.items(), key=lambda x: self.ip_key(sorted(x[1]['IPs'])[0]))

                # Only write if we have data
                if not sorted_netkb_entries:
                    self.logger.warning("No entries to write to database - skipping write")
                    return
                
                # WRITE TO SQLITE DATABASE (PRIMARY AND ONLY DATA STORE)
                # This ensures all scan data is persisted in the database
                try:
                    self.logger.debug(f"Writing {len(sorted_netkb_entries)} hosts to SQLite database...")
                    
                    for mac, data in sorted_netkb_entries:
                        # Get primary IP (first one if multiple)
                        primary_ip = sorted(data['IPs'], key=self.ip_key)[0] if data['IPs'] else ''
                        hostname = '; '.join(sorted(data['Hostnames'])) if data['Hostnames'] else ''
                        if hostname:
                            hostname = self.db.sanitize_hostname(hostname)
                        
                        # Prepare ports string
                        valid_ports = [p for p in data['Ports'] if p]
                        ports_str = ','.join(sorted(valid_ports, key=int)) if valid_ports else ''
                        
                        # Upsert host to database
                        self.db.upsert_host(
                            mac=mac,
                            ip=primary_ip,
                            hostname=hostname,
                            ports=ports_str,
                            alive_count=data.get('Alive', '0'),
                            scanner_status=data.get('Scanner', ''),
                            network_profile=data.get('Network Profile', ''),
                            ssh_connector=data.get('ssh_connector', ''),
                            rdp_connector=data.get('rdp_connector', ''),
                            ftp_connector=data.get('ftp_connector', ''),
                            smb_connector=data.get('smb_connector', ''),
                            telnet_connector=data.get('telnet_connector', ''),
                            sql_connector=data.get('sql_connector', ''),
                            steal_files_ssh=data.get('steal_files_ssh', ''),
                            steal_files_rdp=data.get('steal_files_rdp', ''),
                            steal_files_ftp=data.get('steal_files_ftp', ''),
                            steal_files_smb=data.get('steal_files_smb', ''),
                            steal_files_telnet=data.get('steal_files_telnet', ''),
                            steal_data_sql=data.get('steal_data_sql', ''),
                            nmap_vuln_scanner=data.get('nmap_vuln_scanner', ''),
                            notes=data.get('Notes', ''),
                            failed_ping_count=data.get('Failed_Pings', 0),
                            status='alive' if data.get('Alive') == '1' else 'degraded'
                        )
                        
                        # Update ping status based on alive state
                        if data.get('Alive') == '1':
                            self.db.update_ping_status(mac, success=True)
                        elif data.get('Failed_Pings', 0) > 0:
                            # Don't call update_ping_status for failed pings here
                            # because we already have the correct failed_ping_count
                            # Just log the degraded state
                            if data.get('Failed_Pings', 0) >= 30:
                                self.logger.debug(f"Host {mac} in degraded state ({data.get('Failed_Pings', 0)} failed pings)")
                    
                    self.logger.info(f"✅ Updated SQLite database with {len(sorted_netkb_entries)} hosts")
                    
                except Exception as db_error:
                    self.logger.error(f"Failed to write to SQLite database: {db_error}")
                    self.logger.debug(f"Traceback: {traceback.format_exc()}")
                    # Don't raise - CSV write succeeded, so continue
                
            except Exception as e:
                self.logger.error(f"Error in update_netkb: {e}")

    def display_csv(self, file_path):
        """
        Displays the contents of the specified CSV file using Rich for enhanced visualization.
        """
        if not Table or not self.console:
            return
        with self.lock:
            try:
                table = Table(title=f"Contents of {file_path}", show_lines=True)
                with open(file_path, 'r') as file:
                    reader = csv.reader(file)
                    headers = next(reader)
                    for header in headers:
                        table.add_column(header, style="cyan", no_wrap=True)
                    for row in reader:
                        formatted_row = [Text(cell, style="green bold") if cell else Text("", style="on red") for cell in row]
                        table.add_row(*formatted_row)
                self.console.print(table)
            except Exception as e:
                self.logger.error(f"Error in display_csv: {e}")

    def get_network(self):
        """
        Retrieves the network information including the default gateway and subnet.
        """
        try:
            if self._active_scan_network:
                network = ipaddress.ip_network(self._active_scan_network, strict=False)
                self.logger.info(f"Network (override): {network}")
                return network
            if netifaces is None:
                # Fallback: detect network from ip commands
                try:
                    result = subprocess.run(
                        ['ip', '-o', '-4', 'addr', 'show', self.arp_scan_interface],
                        capture_output=True, text=True, timeout=5
                    )
                    for line in result.stdout.strip().splitlines():
                        # Format: 3: br-lan    inet 172.16.52.1/24 brd ...
                        parts = line.split()
                        for i, p in enumerate(parts):
                            if p == 'inet' and i + 1 < len(parts):
                                cidr = parts[i + 1]  # e.g. 172.16.52.1/24
                                network = ipaddress.IPv4Network(cidr, strict=False)
                                self.logger.info(f"Network (from {self.arp_scan_interface}): {network}")
                                return network
                except Exception as e:
                    self.logger.warning(f"Failed to detect network from ip command: {e}")
                # Last resort: try any non-loopback interface
                try:
                    result = subprocess.run(
                        ['ip', '-o', '-4', 'addr', 'show'],
                        capture_output=True, text=True, timeout=5
                    )
                    for line in result.stdout.strip().splitlines():
                        if '127.0.0.1' in line:
                            continue
                        parts = line.split()
                        for i, p in enumerate(parts):
                            if p == 'inet' and i + 1 < len(parts):
                                cidr = parts[i + 1]
                                network = ipaddress.IPv4Network(cidr, strict=False)
                                self.logger.info(f"Network (detected): {network}")
                                return network
                except Exception as e:
                    self.logger.warning(f"Failed to detect any network: {e}")
                self.logger.warning("netifaces not available, using default network range")
                network = ipaddress.IPv4Network("192.168.1.0/24", strict=False)
                self.logger.info(f"Network (default): {network}")
                return network
                
            gws = netifaces.gateways()
            default_gateway = gws['default'][netifaces.AF_INET][1]
            iface = netifaces.ifaddresses(default_gateway)[netifaces.AF_INET][0]
            ip_address = iface['addr']
            netmask = iface['netmask']
            cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
            network = ipaddress.IPv4Network(f"{ip_address}/{cidr}", strict=False)
            self.logger.info(f"Network: {network}")
            return network
        except Exception as e:
            self.logger.error(f"Error in get_network: {e}")

    def get_gateway_info(self):
        """Collect gateway IP, MAC, vendor, interface, and subnet CIDR.

        Stores the result on shared_data.gateway_info so the topology API
        can place the router at the center of the network map.
        """
        info = {"gateway_ip": None, "gateway_mac": None, "gateway_vendor": None,
                "interface": None, "subnet": None, "ragnar_ip": None}
        try:
            if netifaces is None:
                return info
            gws = netifaces.gateways()
            gw_tuple = gws.get("default", {}).get(netifaces.AF_INET)
            if not gw_tuple:
                return info
            info["gateway_ip"] = gw_tuple[0]
            info["interface"] = gw_tuple[1]

            iface_addrs = netifaces.ifaddresses(gw_tuple[1]).get(netifaces.AF_INET)
            if iface_addrs:
                my_ip = iface_addrs[0]["addr"]
                netmask = iface_addrs[0]["netmask"]
                cidr = sum(bin(int(x)).count("1") for x in netmask.split("."))
                info["ragnar_ip"] = my_ip
                info["subnet"] = str(ipaddress.IPv4Network(f"{my_ip}/{cidr}", strict=False))

            # Resolve gateway MAC from kernel ARP cache
            try:
                result = subprocess.run(
                    ["ip", "neigh", "show", info["gateway_ip"]],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.strip().splitlines():
                    parts = line.split()
                    # Format: 192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff ...
                    if "lladdr" in parts:
                        idx = parts.index("lladdr")
                        if idx + 1 < len(parts):
                            info["gateway_mac"] = parts[idx + 1]
                            break
            except Exception:
                pass

            # Look up vendor from DB if we have the MAC
            if info["gateway_mac"]:
                try:
                    db = get_db()
                    host = db.get_host(info["gateway_mac"])
                    if host:
                        info["gateway_vendor"] = host.get("vendor", "")
                except Exception:
                    pass

            self.shared_data.gateway_info = info
            self.logger.info(f"Gateway info: {info['gateway_ip']} (MAC={info['gateway_mac']}) via {info['interface']}")
        except Exception as e:
            self.logger.debug(f"Could not collect gateway info: {e}")
        return info

    def get_mac_address(self, ip, hostname):
        """
        Retrieves the MAC address for the given IP address and hostname.
        """
        try:
            mac = None
            retries = 5
            while not mac and retries > 0:
                mac = gma(ip=ip)
                if not mac:
                    time.sleep(2)  # Attendre 2 secondes avant de réessayer
                    retries -= 1
            if not mac:
                mac = f"{ip}_{hostname}" if hostname else f"{ip}_NoHostname"
            return mac
        except Exception as e:
            self.logger.error(f"Error in get_mac_address: {e}")
            return None

    class PortScanner:
        """
        Helper class to perform port scanning on a target IP using nmap.
        """
        def __init__(self, outer_instance, target, open_ports, portstart, portend, extra_ports):
            self.outer_instance = outer_instance
            self.logger = logger
            self.target = target
            self.open_ports = open_ports
            self.portstart = portstart
            self.portend = portend
            self.extra_ports = extra_ports

        def start(self):
            """
            Starts the port scanning process using nmap for reliable scanning.
            """
            scan_start_time = time.time()
            try:
                # Build port list to scan
                ports_to_scan = list(range(self.portstart, self.portend))
                extra_ports = self.extra_ports or []
                ports_to_scan.extend(extra_ports)
                
                # Remove duplicates while preserving order
                seen_ports = set()
                ordered_ports = []
                for port in ports_to_scan:
                    if port in seen_ports:
                        continue
                    seen_ports.add(port)
                    ordered_ports.append(port)

                self.logger.info(f"🎯 PORT SCAN STARTING: {self.target} - {len(ordered_ports)} ports (range: {self.portstart}-{self.portend}, extra: {len(extra_ports)} ports)")
                self.logger.debug(f"Port list preview for {self.target}: {sorted(ordered_ports)[:10]}{'...' if len(ordered_ports) > 10 else ''}")
                
                # Use nmap for more reliable port scanning
                port_list = ','.join(map(str, ordered_ports))
                
                # Nmap arguments: -Pn (skip ping), -sT (TCP connect), --host-timeout (per-host timeout)
                # Removed --open flag to see all port states (open, closed, filtered)
                nmap_args = f"-Pn -sT -p{port_list} --host-timeout 30s"
                
                self.logger.debug(f"🔍 Executing nmap command for {self.target}: nmap {nmap_args} {self.target}")
                
                try:
                    nmap_start_time = time.time()
                    # Use the nmap scanner from the outer instance
                    self.outer_instance.nm.scan(self.target, arguments=nmap_args)
                    nmap_duration = time.time() - nmap_start_time
                    
                    self.logger.debug(f"⏱️ Nmap scan completed for {self.target} in {nmap_duration:.2f}s")
                    
                    # Log detailed nmap results
                    all_hosts = self.outer_instance.nm.all_hosts()
                    self.logger.debug(f"📊 Nmap results for {self.target}: all_hosts={all_hosts}")
                    
                    if self.target in all_hosts:
                        host_data = self.outer_instance.nm[self.target]
                        self.logger.debug(f"📋 Host data keys for {self.target}: {list(host_data.keys())}")
                        
                        # Log scan info if available
                        if 'status' in host_data:
                            self.logger.debug(f"🔄 Host status for {self.target}: {host_data['status']}")
                        
                        # Check TCP ports
                        if 'tcp' in host_data:
                            tcp_ports = host_data['tcp']
                            self.logger.info(f"🔌 TCP scan results for {self.target}: {len(tcp_ports)} ports scanned")
                            open_count = 0
                            closed_count = 0
                            filtered_count = 0
                            for port in tcp_ports:
                                port_state = tcp_ports[port]['state']
                                port_service = tcp_ports[port].get('name', 'unknown')
                                
                                if port_state == 'open':
                                    self.open_ports[self.target].append(port)
                                    self.logger.info(f"✅ OPEN PORT: {port}/tcp on {self.target} ({port_service})")
                                    open_count += 1
                                elif port_state == 'closed':
                                    self.logger.debug(f"🚪 CLOSED PORT: {port}/tcp on {self.target} ({port_service})")
                                    closed_count += 1
                                elif port_state == 'filtered':
                                    self.logger.debug(f"🛡️ FILTERED PORT: {port}/tcp on {self.target} ({port_service})")
                                    filtered_count += 1
                                else:
                                    self.logger.debug(f"❓ UNKNOWN STATE: Port {port}/tcp = {port_state} on {self.target} ({port_service})")
                            
                            self.logger.info(f"📊 Port summary for {self.target}: {open_count} open, {closed_count} closed, {filtered_count} filtered")
                        else:
                            self.logger.warning(f"⚠️ No TCP results in nmap data for {self.target}")
                        
                        # Check UDP ports if scanned
                        if 'udp' in host_data:
                            udp_ports = host_data['udp']
                            self.logger.debug(f"🔌 UDP scan results for {self.target}: {len(udp_ports)} ports scanned")
                            for port in udp_ports:
                                port_state = udp_ports[port]['state']
                                if port_state == 'open':
                                    self.open_ports[self.target].append(port)
                                    self.logger.info(f"✅ OPEN UDP PORT: {port}/udp on {self.target}")
                    else:
                        self.logger.warning(f"❌ Target {self.target} not found in nmap results. Available hosts: {all_hosts}")
                    
                    # Summary logging
                    scan_duration = time.time() - scan_start_time
                    if self.open_ports[self.target]:
                        self.logger.info(f"🎉 SCAN SUCCESS: Found {len(self.open_ports[self.target])} open ports on {self.target} in {scan_duration:.2f}s: {sorted(self.open_ports[self.target])}")
                    else:
                        self.logger.warning(f"❌ SCAN COMPLETE: No open ports found on {self.target} in {scan_duration:.2f}s (scanned {len(ordered_ports)} ports)")
                        # Log sample of scanned ports for debugging
                        sample_ports = sorted(ordered_ports)[:5] if len(ordered_ports) <= 10 else sorted(ordered_ports)[:5] + ['...'] + sorted(ordered_ports)[-5:]
                        self.logger.debug(f"   Scanned ports: {sample_ports}")
                        
                except Exception as nmap_error:
                    scan_duration = time.time() - scan_start_time
                    self.logger.error(f"💥 NMAP SCAN FAILED for {self.target} after {scan_duration:.2f}s: {type(nmap_error).__name__}: {nmap_error}")
                    # Fallback to socket scanning with shorter timeout
                    self.logger.info(f"🔄 FALLBACK: Switching to socket scanning for {self.target}")
                    self._socket_scan_fallback(ordered_ports)
                    
            except Exception as e:
                scan_duration = time.time() - scan_start_time
                self.logger.error(f"💥 PORT SCAN ERROR for {self.target} after {scan_duration:.2f}s: {type(e).__name__}: {e}")
                import traceback
                self.logger.debug(f"Full traceback: {traceback.format_exc()}")

        def _socket_scan_fallback(self, ports_to_scan):
            """Fallback socket scanning with shorter timeout for when nmap fails"""
            fallback_start_time = time.time()
            self.logger.info(f"🔌 SOCKET FALLBACK: Scanning {self.target} with {len(ports_to_scan)} ports")
            
            initial_open_count = len(self.open_ports[self.target])
            
            with ThreadPoolExecutor(max_workers=min(4, self.outer_instance.port_scan_workers)) as executor:
                futures = [executor.submit(self._scan_port_socket, port) for port in ports_to_scan]
                completed_scans = 0
                failed_scans = 0
                
                for future in futures:
                    try:
                        future.result(timeout=5)  # 5 second timeout per port
                        completed_scans += 1
                    except Exception as e:
                        failed_scans += 1
                        self.logger.debug(f"Socket scan future failed: {e}")
            
            fallback_duration = time.time() - fallback_start_time
            final_open_count = len(self.open_ports[self.target])
            new_ports_found = final_open_count - initial_open_count
            
            if new_ports_found > 0:
                self.logger.info(f"🎉 SOCKET FALLBACK SUCCESS: Found {new_ports_found} additional open ports on {self.target} in {fallback_duration:.2f}s")
            else:
                self.logger.warning(f"❌ SOCKET FALLBACK COMPLETE: No additional ports found on {self.target} in {fallback_duration:.2f}s (completed: {completed_scans}, failed: {failed_scans})")
        
        def _scan_port_socket(self, port):
            """Fallback socket scanning method with aggressive timeout"""
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)  # Very short timeout for fallback
            try:
                s.connect((self.target, port))
                self.open_ports[self.target].append(port)
                self.logger.info(f"✅ SOCKET SUCCESS: Port {port} OPEN on {self.target} (socket fallback)")
            except socket.timeout:
                self.logger.debug(f"Socket timeout on {self.target}:{port}")
            except socket.error as e:
                self.logger.debug(f"Socket connection refused on {self.target}:{port}: {e}")
            except Exception as e:
                self.logger.warning(f"Unexpected socket scan error on {self.target}:{port}: {e}")
            finally:
                s.close()

    class ScanPorts:
        """
        Helper class to manage the overall port scanning process for a network.
        """
        def __init__(self, outer_instance, network, portstart, portend, extra_ports):
            self.outer_instance = outer_instance
            self.logger = logger
            self.progress = 0
            self.network = network
            self.portstart = portstart
            self.portend = portend
            self.extra_ports = extra_ports
            self.currentdir = outer_instance.currentdir
            self.scan_results_dir = outer_instance.shared_data.scan_results_dir
            self.timestamp = outer_instance.get_current_timestamp()
            self.csv_scan_file = os.path.join(self.scan_results_dir, f'scan_{network.network_address}_{self.timestamp}.csv')
            self.csv_result_file = os.path.join(self.scan_results_dir, f'result_{network.network_address}_{self.timestamp}.csv')
            self.netkbfile = outer_instance.shared_data.netkbfile
            self.ip_data = None
            self.open_ports = {}
            self.all_ports = []
            self.ip_hostname_list = []
            self.total_ips = 0
            self.arp_hosts = {}
            self.use_nmap_results = False

        def scan_network_and_collect_hosts(self):
            """
            # MAC/host resolution: SQLITE DB ONLY - CSV logic removed
            # Scans network and stores results directly to SQLite database.
            # No intermediate CSV files for host state tracking.
            """
            self.logger.info("🎯 Phase 1: Getting MAC addresses via arp-scan")
            # Get MAC addresses and vendor info from arp-scan (writes to DB internally)
            self.arp_hosts = self.outer_instance.run_arp_scan(network=self.network)
            
            self.logger.info("🎯 Phase 2: Network-wide nmap scan for hosts and ports")
            # Run nmap network-wide scan for host discovery AND port scanning (writes to DB internally)
            network_cidr = str(self.network)
            self.nmap_results = self.outer_instance.run_nmap_network_scan(
                network_cidr, 
                self.portstart, 
                self.portend, 
                self.extra_ports
            )
            
            # Merge results: nmap gives us IPs, hostnames, and ports; arp-scan gives us MACs
            self.logger.info(f"🔗 Merging results: {len(self.nmap_results)} nmap hosts + {len(self.arp_hosts)} arp MACs")
            
            all_ips = set(self.nmap_results.keys()) | set(self.arp_hosts.keys())
            self.logger.info(f"📋 Total unique hosts to process: {len(all_ips)}")
            
            # Store nmap port results for later use
            self.nmap_port_data = {ip: data['open_ports'] for ip, data in self.nmap_results.items()}
            
            # Collect host data for return (reading from what we just wrote to DB)
            # MAC/host resolution: SQLITE DB ONLY - we build the list from scan results
            # that were already written to the database by run_arp_scan() and run_nmap_network_scan()
            for ip in sorted(all_ips, key=self.outer_instance.ip_key):
                # Get hostname from nmap results if available
                hostname = self.nmap_results.get(ip, {}).get('hostname', '')
                if not hostname:
                    hostname = self.outer_instance.resolve_hostname(ip)
                
                # Get MAC from arp-scan results if available
                mac = None
                if ip in self.arp_hosts:
                    mac = self.arp_hosts[ip].get('mac')
                
                if not mac:
                    # Try to get MAC address
                    mac = self.outer_instance.get_mac_address(ip, hostname)
                
                if not mac or mac == "00:00:00:00:00:00":
                    # Check DB for existing MAC before creating pseudo-MAC
                    # MAC/host resolution: SQLITE DB ONLY
                    existing_host = self.outer_instance.db.get_host_by_ip(ip)
                    if existing_host and existing_host['mac'] and not existing_host['mac'].startswith('00:00:c0:a8'):
                        mac = existing_host['mac']
                        self.logger.debug(f"Using existing MAC from DB: {mac} for {ip}")
                    else:
                        # Only create pseudo-MAC if no real MAC exists in DB
                        ip_parts = ip.split('.')
                        if len(ip_parts) == 4:
                            mac = f"00:00:{int(ip_parts[0]):02x}:{int(ip_parts[1]):02x}:{int(ip_parts[2]):02x}:{int(ip_parts[3]):02x}"
                            self.logger.debug(f"Created pseudo-MAC {mac} for {ip}")
                
                mac = mac.lower() if mac else "00:00:00:00:00:00"
                
                # Build in-memory list (no CSV write)
                if not self.outer_instance.blacklistcheck or (mac not in self.outer_instance.mac_scan_blacklist and ip not in self.outer_instance.ip_scan_blacklist):
                    self.ip_hostname_list.append((ip, hostname, mac))
                    self.logger.debug(f"✅ Collected host data: {ip} ({hostname}) - MAC: {mac}")

            self.logger.info(f"✅ Network scan complete: {len(self.ip_hostname_list)} hosts processed")

        def get_progress(self):
            """
            Returns the progress of the scanning process.
            """
            total = self.total_ips if self.total_ips else 1
            return (self.progress / total) * 100

        def start(self):
            """
            Starts the network and port scanning process using nmap for efficiency.
            # MAC/host resolution: SQLITE DB ONLY - CSV logic removed
            # Reads host data from SQLite database, not from CSV files.
            """
            overall_start_time = time.time()
            
            self.logger.info("🚀 STARTING EFFICIENT NETWORK SCAN (nmap network-wide + arp-scan for MACs)")
            
            # Combined discovery and port scan phase
            self.logger.info("📡 Running combined host discovery and port scanning")
            scan_start = time.time()
            self.scan_network_and_collect_hosts()
            scan_duration = time.time() - scan_start
            
            # Build ip_data structure from collected hosts (no CSV read)
            # MAC/host resolution: SQLITE DB ONLY
            class IpDataFromMemory:
                """Simple data structure to hold scan results from database."""
                def __init__(self, ip_hostname_list):
                    self.ip_list = [item[0] for item in ip_hostname_list]
                    self.hostname_list = [item[1] for item in ip_hostname_list]
                    self.mac_list = [item[2] for item in ip_hostname_list]
            
            self.ip_data = IpDataFromMemory(self.ip_hostname_list)
            self.total_ips = len(self.ip_data.ip_list)
            self.logger.info(f"✅ Network scan complete: Found {self.total_ips} hosts in {scan_duration:.2f}s")
            
            if self.total_ips == 0:
                self.logger.warning("❌ No hosts found!")
                return self.ip_data, {}, [], self.csv_result_file, self.netkbfile, set()
            
            # Use nmap port results that were already collected during network scan
            self.logger.info(f"📊 Processing port data from nmap results")
            self.open_ports = {}
            
            for ip in self.ip_data.ip_list:
                # Get ports from nmap results collected during network scan
                if hasattr(self, 'nmap_port_data') and ip in self.nmap_port_data:
                    self.open_ports[ip] = self.nmap_port_data[ip]
                    if self.open_ports[ip]:
                        self.logger.info(f"✅ {ip}: {len(self.open_ports[ip])} open ports - {sorted(self.open_ports[ip])}")
                else:
                    self.open_ports[ip] = []
                    self.logger.debug(f"ℹ️ {ip}: No open ports detected")
            
            # Results summary
            self.all_ports = sorted(list(set(port for ports in self.open_ports.values() for port in ports)))
            total_open_ports = sum(len(ports) for ports in self.open_ports.values())
            hosts_with_ports = len([ip for ip, ports in self.open_ports.items() if ports])
            
            overall_duration = time.time() - overall_start_time
            
            self.logger.info(f"🎉 SCAN COMPLETE!")
            self.logger.info(f"   📈 Total duration: {overall_duration:.2f}s")
            self.logger.info(f"   🎯 Hosts discovered: {self.total_ips}")
            self.logger.info(f"   🔌 Total open ports found: {total_open_ports}")
            self.logger.info(f"   🏠 Hosts with open ports: {hosts_with_ports}")
            self.logger.info(f"   📋 Unique ports discovered: {len(self.all_ports)} - {self.all_ports}")
            
            alive_ips = set(self.ip_data.ip_list)
            return self.ip_data, self.open_ports, self.all_ports, self.csv_result_file, self.netkbfile, alive_ips

    class LiveStatusUpdater:
        """
        Helper class to update the live status of hosts and clean up scan results.
        """
        def __init__(self, source_csv_path, output_csv_path, db=None):
            self.logger = logger
            self.source_csv_path = source_csv_path
            self.output_csv_path = output_csv_path
            self.db = db
            # Initialize default values in case of errors
            self.df = pd.DataFrame() if pd else None
            self.total_open_ports = 0
            self.alive_hosts_count = 0
            self.all_known_hosts_count = 0

        def read_csv(self):
            """
            Reads the source CSV file into a DataFrame (or list of dicts if pandas unavailable).
            """
            if pd is None:
                # Fallback: use csv module
                self._rows = []
                try:
                    if not os.path.exists(self.source_csv_path) or os.path.getsize(self.source_csv_path) == 0:
                        return
                    with open(self.source_csv_path, 'r') as f:
                        reader = csv.DictReader(f)
                        self._rows = list(reader)
                    self.logger.debug(f"Read {len(self._rows)} rows from {self.source_csv_path} (csv fallback)")
                except Exception as e:
                    self.logger.error(f"Error reading CSV (fallback): {e}")
                return
            try:
                if not os.path.exists(self.source_csv_path):
                    self.logger.warning(f"Source CSV file does not exist: {self.source_csv_path}")
                    # Create an empty DataFrame with expected columns
                    self.df = pd.DataFrame(columns=['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive'])
                    return
                
                # Check if file is empty
                if os.path.getsize(self.source_csv_path) == 0:
                    self.logger.warning(f"Source CSV file is empty: {self.source_csv_path}")
                    self.df = pd.DataFrame(columns=['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive'])
                    return
                
                # Try to read the CSV, catching specific pandas errors
                try:
                    self.df = pd.read_csv(self.source_csv_path)
                except pd.errors.EmptyDataError:
                    self.logger.warning(f"Source CSV file has no data to parse: {self.source_csv_path}")
                    self.df = pd.DataFrame(columns=['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive'])
                    return
                except Exception as read_error:
                    # Catch any other CSV reading errors (e.g., "No columns to parse from file")
                    self.logger.warning(f"Could not parse CSV file: {read_error}")
                    self.df = pd.DataFrame(columns=['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive'])
                    return
                
                # Check if DataFrame is empty or missing required columns
                if self.df.empty:
                    self.logger.warning(f"Source CSV file has no data: {self.source_csv_path}")
                    self.df = pd.DataFrame(columns=['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive'])
                    return
                
                # Ensure required columns exist
                required_columns = ['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive']
                missing_columns = [col for col in required_columns if col not in self.df.columns]
                if missing_columns:
                    self.logger.warning(f"Missing columns in CSV: {missing_columns}")
                    for col in missing_columns:
                        self.df[col] = '' if col != 'Alive' else '0'
                
                self.logger.debug(f"Successfully read {len(self.df)} rows from {self.source_csv_path}")
                
            except Exception as e:
                self.logger.error(f"Error in read_csv: {e}")
                # Create empty DataFrame on error
                self.df = pd.DataFrame(columns=['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive'])

        def calculate_open_ports(self):
            """
            Calculates the total number of open ports for alive hosts.
            """
            try:
                self.total_open_ports = 0

                # csv fallback path (no pandas)
                if pd is None:
                    for row in getattr(self, '_rows', []):
                        if row.get('Alive', '0').strip() == '1':
                            ports = row.get('Ports', '')
                            if ports:
                                self.total_open_ports += len([p for p in ports.split(';') if p.strip()])
                    return
                
                # Check if DataFrame is valid and has required columns
                if self.df is None or self.df.empty or 'Alive' not in self.df.columns or 'Ports' not in self.df.columns:
                    self.logger.warning("DataFrame is empty or missing required columns for port calculation")
                    return

                alive_mask = self.df['Alive'].astype(str).str.strip() == '1'
                alive_df = self.df[alive_mask].copy()
                
                if alive_df.empty:
                    self.logger.debug("No alive hosts found for port calculation")
                    return
                
                # Convert Ports column to string type to avoid pandas dtype warning
                alive_df = alive_df.copy()
                alive_df['Ports'] = alive_df['Ports'].fillna('').astype(str)
                # Count non-empty port entries (split by ';' and filter out empty strings)
                alive_df['Port Count'] = alive_df['Ports'].apply(
                    lambda x: len([p for p in x.split(';') if p.strip()]) if x else 0
                )
                self.total_open_ports = int(alive_df['Port Count'].sum())
                
                self.logger.debug(f"Calculated total open ports: {self.total_open_ports}")
                
            except Exception as e:
                self.logger.error(f"Error in calculate_open_ports: {e}")
                self.total_open_ports = 0

        def calculate_hosts_counts(self):
            """
            Calculates the total and alive host counts.
            """
            try:
                self.all_known_hosts_count = 0
                self.alive_hosts_count = 0

                # csv fallback path (no pandas)
                if pd is None:
                    for row in getattr(self, '_rows', []):
                        mac = row.get('MAC Address', '')
                        if mac != 'STANDALONE':
                            self.all_known_hosts_count += 1
                        if row.get('Alive', '0').strip() == '1':
                            self.alive_hosts_count += 1
                    return
                
                # Check if DataFrame is valid and has required columns
                if self.df is None or self.df.empty or 'MAC Address' not in self.df.columns or 'Alive' not in self.df.columns:
                    self.logger.warning("DataFrame is empty or missing required columns for host count calculation")
                    return
                
                # Count all hosts (excluding STANDALONE entries)
                self.all_known_hosts_count = self.df[self.df['MAC Address'] != 'STANDALONE'].shape[0]
                
                # Count alive hosts
                alive_mask = self.df['Alive'].astype(str).str.strip() == '1'
                self.alive_hosts_count = self.df[alive_mask].shape[0]
                
                self.logger.debug(f"Host counts - Total: {self.all_known_hosts_count}, Alive: {self.alive_hosts_count}")
                
            except Exception as e:
                self.logger.error(f"Error in calculate_hosts_counts: {e}")
                self.all_known_hosts_count = 0
                self.alive_hosts_count = 0

        def save_results(self):
            """
            Logs the calculated scan statistics and writes them to the output CSV.
            """
            try:
                # Ensure all required attributes exist with default values
                if not hasattr(self, 'total_open_ports'):
                    self.total_open_ports = 0
                if not hasattr(self, 'alive_hosts_count'):
                    self.alive_hosts_count = 0
                if not hasattr(self, 'all_known_hosts_count'):
                    self.all_known_hosts_count = 0
                
                self.logger.info(f"📊 Scan Results - Total Open Ports: {self.total_open_ports}, "
                               f"Alive Hosts: {self.alive_hosts_count}, "
                               f"All Known Hosts: {self.all_known_hosts_count}")

                # Write to livestatus CSV so the display picks up the values
                try:
                    with open(self.output_csv_path, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['Total Open Ports', 'Alive Hosts Count', 'All Known Hosts Count', 'Vulnerabilities Count'])
                        writer.writerow([self.total_open_ports, self.alive_hosts_count, self.all_known_hosts_count, 0])
                except Exception as csv_err:
                    self.logger.error(f"Error writing livestatus CSV: {csv_err}")
                
            except Exception as e:
                self.logger.error(f"Error in save_results: {e}")


        def update_livestatus(self):
            """
            Updates the live status of hosts and saves the results.
            """
            try:
                # Try SQLite first — more reliable than CSV parsing
                if self.db and self._update_from_db():
                    self.save_results()
                    self.logger.info("Livestatus updated (from database)")
                    self.logger.info(f"Results saved to {self.output_csv_path}")
                    return

                self.read_csv()
                self.calculate_open_ports()
                self.calculate_hosts_counts()
                self.save_results()
                self.logger.info("Livestatus updated")
                self.logger.info(f"Results saved to {self.output_csv_path}")
            except Exception as e:
                self.logger.error(f"Error in update_livestatus: {e}")

        def _update_from_db(self):
            """Calculate stats directly from SQLite database."""
            try:
                hosts = self.db.get_all_hosts()
                if not hosts:
                    return False
                self.all_known_hosts_count = len([h for h in hosts if h.get('mac') != 'STANDALONE'])
                self.alive_hosts_count = len([h for h in hosts if h.get('status') == 'alive'])
                total_ports = 0
                for h in hosts:
                    if h.get('status') == 'alive':
                        ports_str = h.get('ports', '')
                        if ports_str:
                            total_ports += len([p for p in ports_str.split(',') if p.strip()])
                self.total_open_ports = total_ports
                return True
            except Exception as e:
                self.logger.warning(f"Could not read stats from database: {e}")
                return False
        
        def clean_scan_results(self, scan_results_dir):
            """
            Cleans up old scan result files, keeping only the most recent ones.
            """
            try:
                files = glob.glob(scan_results_dir + '/*')
                files.sort(key=os.path.getmtime)
                for file in files[:-20]:
                    os.remove(file)
                self.logger.info("Scan results cleaned up")
            except Exception as e:
                self.logger.error(f"Error in clean_scan_results: {e}")

    def scan(self, job=None):
        """
        Initiates the network scan, updates the netkb file, and displays the results.
        Now also stores results in memory for immediate orchestrator access.
        """
        interface_override = getattr(job, 'interface', None) if job else None
        network_hint = getattr(job, 'network_cidr', None) if job else None
        if not network_hint and job and getattr(job, 'ip_address', None) and getattr(job, 'cidr', None):
            network_hint = f"{job.ip_address}/{job.cidr}"

        previous_interface = self.arp_scan_interface
        previous_network_hint = self._active_scan_network

        if interface_override:
            self.arp_scan_interface = interface_override
        self._active_scan_network = network_hint

        try:
            self.shared_data.ragnarorch_status = "NetworkScanner"
            job_descriptor = ""
            if job and getattr(job, 'ssid', None):
                job_descriptor = f" for {job.ssid} ({self.arp_scan_interface})"
            self.logger.info(f"Starting Network Scanner{job_descriptor}")
            network = self.get_network()
            self.get_gateway_info()
            self.shared_data.bjornstatustext2 = str(network)
            portstart = self.shared_data.portstart
            portend = self.shared_data.portend
            extra_ports = self.shared_data.portlist
            scanner = self.ScanPorts(self, network, portstart, portend, extra_ports)
            ip_data, open_ports, all_ports, csv_result_file, netkbfile, alive_ips = scanner.start()

            # Convert alive MACs to use pseudo-MACs for hosts without real MAC addresses
            alive_macs = set()
            for i, mac in enumerate(ip_data.mac_list):
                if mac == "00:00:00:00:00:00" and i < len(ip_data.ip_list):
                    # Convert to pseudo-MAC using the same logic as update_netkb
                    ip = ip_data.ip_list[i]
                    ip_parts = ip.split('.')
                    if len(ip_parts) == 4:
                        pseudo_mac = f"00:00:{int(ip_parts[0]):02x}:{int(ip_parts[1]):02x}:{int(ip_parts[2]):02x}:{int(ip_parts[3]):02x}"
                        alive_macs.add(pseudo_mac)
                        self.logger.debug(f"Added pseudo-MAC {pseudo_mac} to alive_macs for IP {ip}")
                else:
                    alive_macs.add(mac)

            table = Table(title="Scan Results", show_lines=True) if Table else None
            if table:
                table.add_column("IP", style="cyan", no_wrap=True)
                table.add_column("Hostname", style="cyan", no_wrap=True)
                table.add_column("Alive", style="cyan", no_wrap=True)
                table.add_column("MAC Address", style="cyan", no_wrap=True)
                for port in all_ports:
                    table.add_column(f"{port}", style="green")

            netkb_data = []
            for ip, ports, hostname, mac in zip(ip_data.ip_list, open_ports.values(), ip_data.hostname_list, ip_data.mac_list):
                if self.blacklistcheck and (mac in self.mac_scan_blacklist or ip in self.ip_scan_blacklist):
                    continue
                alive = '1' if mac in alive_macs else '0'
                if table and Text:
                    row = [ip, hostname, alive, mac] + [Text(str(port), style="green bold") if port in ports else Text("", style="on red") for port in all_ports]
                    table.add_row(*row)
                netkb_data.append([mac, ip, hostname, ports])

            with self.lock:
                with open(csv_result_file, 'w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(["IP", "Hostname", "Alive", "MAC Address"] + [str(port) for port in all_ports])
                    for ip, ports, hostname, mac in zip(ip_data.ip_list, open_ports.values(), ip_data.hostname_list, ip_data.mac_list):
                        if self.blacklistcheck and (mac in self.mac_scan_blacklist or ip in self.ip_scan_blacklist):
                            continue
                        alive = '1' if mac in alive_macs else '0'
                        writer.writerow([ip, hostname, alive, mac] + [str(port) if port in ports else '' for port in all_ports])

            self.update_netkb(netkbfile, netkb_data, alive_macs)

            # Log primary-subnet result
            primary_net = str(network) if network else None
            primary_host_count = len(ip_data.ip_list) if ip_data else 0
            self.shared_data.append_subnet_scan_log(
                primary_net or 'primary',
                'ok',
                f"Primary scan complete — {primary_host_count} device(s) found",
                devices=primary_host_count,
            )

            # ----------------------------------------------------------
            # Extra-subnet scanning: scan additional user-configured CIDRs
            # so that devices behind other routers / APs appear on the map.
            # ARP is Layer-2 and won't reach remote subnets, but nmap -Pn
            # works as long as a route exists (e.g. via the gateway).
            # ----------------------------------------------------------
            extra_subnets = getattr(self.shared_data, 'scan_subnets', None) or []
            if not extra_subnets:
                extra_subnets = self.shared_data.config.get('scan_subnets', [])
            for extra_cidr in extra_subnets:
                extra_cidr = str(extra_cidr).strip()
                if not extra_cidr:
                    continue
                # Validate CIDR and skip if it's the same as the primary network
                try:
                    extra_net = ipaddress.ip_network(extra_cidr, strict=False)
                    if str(extra_net) == primary_net:
                        self.logger.debug(f"Skipping extra subnet {extra_cidr} — same as primary network")
                        self.shared_data.append_subnet_scan_log(
                            extra_cidr, 'skip',
                            'Skipped — same as primary subnet',
                        )
                        continue
                except ValueError:
                    self.logger.warning(f"Invalid extra subnet CIDR '{extra_cidr}' — skipping")
                    self.shared_data.append_subnet_scan_log(
                        extra_cidr, 'error',
                        f'Invalid CIDR "{extra_cidr}"',
                    )
                    continue

                self.logger.info(f"🌐 Scanning extra subnet: {extra_net}")
                self.shared_data.append_subnet_scan_log(
                    str(extra_net), 'info',
                    f'Scanning {extra_net}…',
                )
                try:
                    extra_results = self.run_nmap_network_scan(
                        str(extra_net),
                        portstart,
                        portend,
                        extra_ports,
                    )
                    # Merge extra-subnet hosts into netkb_data so they persist in the DB
                    for ip, data in extra_results.items():
                        hostname = data.get('hostname', '')
                        mac = data.get('mac', '') or gma(ip=ip)
                        ports_found = data.get('open_ports', [])
                        netkb_data.append([mac, ip, hostname, ports_found])
                        alive_macs.add(mac)
                    found = len(extra_results)
                    self.logger.info(f"✅ Extra subnet {extra_net}: {found} hosts found")
                    if found > 0:
                        self.shared_data.append_subnet_scan_log(
                            str(extra_net), 'ok',
                            f'{found} device(s) found on {extra_net}',
                            devices=found,
                        )
                    else:
                        self.shared_data.append_subnet_scan_log(
                            str(extra_net), 'error',
                            f'{extra_net} — no devices responded',
                            devices=0,
                        )
                except Exception as e:
                    self.logger.error(f"Extra subnet scan failed for {extra_net}: {e}")
                    self.shared_data.append_subnet_scan_log(
                        str(extra_net), 'error',
                        f'Scan failed for {extra_net}: {e}',
                    )

            # Re-run netkb update with merged data (primary + extra subnets)
            if extra_subnets:
                self.update_netkb(netkbfile, netkb_data, alive_macs)

            # Store fresh scan results in memory for immediate orchestrator access
            # This eliminates race conditions with CSV file writes
            try:
                live_hosts = self.shared_data.read_data()  # Read the just-updated netkb
                self.shared_data.set_latest_scan_results(live_hosts)
                self.logger.info(f"✅ Scan results handed off to memory - orchestrator can proceed immediately")
            except Exception as e:
                self.logger.error(f"Failed to store scan results in memory: {e}")

            if self.displaying_csv:
                self.display_csv(csv_result_file)

            source_csv_path = self.shared_data.netkbfile
            output_csv_path = self.shared_data.livestatusfile

            updater = self.LiveStatusUpdater(source_csv_path, output_csv_path, db=self.db)
            updater.update_livestatus()
            updater.clean_scan_results(self.shared_data.scan_results_dir)
        except Exception as e:
            self.logger.error(f"Error in scan: {e}")
        finally:
            self.arp_scan_interface = previous_interface
            self._active_scan_network = previous_network_hint

    def deep_scan_host(self, ip, portstart=1, portend=65535, progress_callback=None, use_top_ports=True):
        # Debug input parameters (single consolidated line for easier grepping)
        self.logger.info("🔍 DEEP SCAN METHOD CALLED")
        self.logger.info(
            f"🎯 DEEP SCAN PARAMETERS ip={ip} portstart={portstart} portend={portend} use_top_ports={use_top_ports}"
        )
        self.logger.debug(f"   progress_callback={progress_callback}")

        if not ip:
            self.logger.error("❌ CRITICAL ERROR: IP parameter is empty/None!")
            return {
                'success': False,
                'open_ports': [],
                'hostname': '',
                'message': 'IP address is required but was empty'
            }

        scan_mode = 'top3000' if use_top_ports else 'full-range'
        self.logger.info(f"🔍 DEEP SCAN INIT ip={ip} mode={scan_mode} range={portstart}-{portend}")

        # Quick connectivity test (best-effort)
        self.logger.info(f"📡 Testing connectivity to {ip}...")
        try:
            ping_result = subprocess.run(['ping', '-c', '1', '-W', '2', ip], 
                                       capture_output=True, text=True, timeout=5)
            if ping_result.returncode == 0:
                self.logger.info(f"✅ Ping successful to {ip} - host is reachable")
            else:
                self.logger.warning(f"⚠️  Ping failed to {ip} - host may be down or firewalled")
        except Exception as ping_error:
            self.logger.warning(f"⚠️  Ping test failed: {ping_error}")
        
        try:
            # ===== STAGE 1: PORT DISCOVERY SCAN =====
            self.logger.info(f"📡 STAGE 1: Port discovery scan starting...")
            
            # Build nmap args depending on mode
            if use_top_ports:
                # Fast scan of most common ports (top 3000) to honor manual discovery requests
                nmap_args = "-Pn -sT --top-ports 3000 --open -T4 --min-rate 500 --max-retries 1 -v"
                self.logger.info(f"🚀 Port scan mode: TOP 3000 common ports (fast)")
                self.logger.info(f"   Command: nmap {nmap_args} {ip}")
            else:
                # Full range scan (can be slow)
                nmap_args = f"-Pn -sT -p{portstart}-{portend} --open -T4 --min-rate 1000 --max-retries 1 -v"
                total_ports = portend - portstart + 1
                self.logger.info(f"🚀 Port scan mode: FULL RANGE ({total_ports} ports)")
                self.logger.info(f"   Command: nmap {nmap_args} {ip}")
            
            # Notify scan started
            if progress_callback:
                progress_callback('scanning', {'message': 'Stage 1: Port discovery'})
            
            scan_start = time.time()
            self.logger.info(f"⏰ STAGE 1 START: {datetime.now().strftime('%H:%M:%S')}")
            
            # Execute the port discovery scan
            self.nm.scan(hosts=ip, arguments=nmap_args)
            
            scan_duration = time.time() - scan_start
            self.logger.info(f"⏰ STAGE 1 END: {datetime.now().strftime('%H:%M:%S')} - Took {scan_duration:.2f}s")
            
            # Check what hosts nmap found
            all_hosts = self.nm.all_hosts()
            self.logger.info(f"🔎 STAGE 1 RESULTS: {len(all_hosts)} hosts found")
            
            if ip not in all_hosts:
                self.logger.warning(f"❌ STAGE 1 FAILED: {ip} not found in results after {scan_duration:.2f}s")
                self.logger.warning(f"   Possible reasons: host down, no open ports, or firewall blocking")
                return {
                    'success': False,
                    'open_ports': [],
                    'hostname': '',
                    'message': f'No open ports found on {ip}'
                }
            
            # Extract port discovery results from STAGE 1
            hostname = self.nm[ip].hostname() or ''
            if progress_callback and hostname:
                progress_callback('hostname', {'message': f'Name: {hostname[:20]}'})
            
            open_ports = []
            port_details = {}
            
            if 'tcp' in self.nm[ip]:
                tcp_ports = self.nm[ip]['tcp']
                for port in sorted(tcp_ports.keys()):
                    if tcp_ports[port]['state'] == 'open':
                        open_ports.append(port)
                        service = tcp_ports[port].get('name', 'unknown')
                        version = tcp_ports[port].get('version', '')
                        port_details[port] = {
                            'service': service,
                            'version': version,
                            'state': 'open'
                        }
                        self.logger.info(f"   ✅ Port {port}/tcp OPEN - {service} {version}")
                        
                        if progress_callback and len(open_ports) % 5 == 1:
                            progress_callback('port_found', {'message': f'{len(open_ports)} ports found', 'port': port, 'service': service})
            
            self.logger.info(f"✅ STAGE 1 COMPLETE: {len(open_ports)} open ports discovered in {scan_duration:.2f}s")
            
            # ===== STAGE 2: VULNERABILITY SCAN ON DISCOVERED PORTS ONLY =====
            # This is a separate, faster scan using ONLY the vulners script on known open ports
            vulnerabilities = {}
            vuln_count = 0
            
            if open_ports:
                self.logger.info(f"🔐 STAGE 2: Vulnerability scan on {len(open_ports)} discovered ports...")
                if progress_callback:
                    progress_callback('vuln_scanning', {'message': f'Stage 2: Scanning {len(open_ports)} ports for CVEs'})
                
                vuln_start = time.time()
                self.logger.info(f"⏰ STAGE 2 START: {datetime.now().strftime('%H:%M:%S')}")
                
                try:
                    # Run FAST vulnerability scan - NO version detection (-sV), just vulners script
                    # We already have service info from stage 1, so skip -sV to save 90% of the time
                    ports_str = ','.join(map(str, open_ports))
                    vuln_args = f"-Pn --script vulners.nse -p{ports_str} -T4"
                    
                    self.logger.info(f"   Command: nmap {vuln_args} {ip}")
                    self.nm.scan(hosts=ip, arguments=vuln_args)
                    
                    vuln_duration = time.time() - vuln_start
                    self.logger.info(f"⏰ STAGE 2 END: {datetime.now().strftime('%H:%M:%S')} - Took {vuln_duration:.2f}s")
                    vuln_duration = time.time() - vuln_start
                    self.logger.info(f"⏰ STAGE 2 END: {datetime.now().strftime('%H:%M:%S')} - Took {vuln_duration:.2f}s")
                    
                    # Extract vulnerability information from STAGE 2 results
                    if ip in self.nm.all_hosts() and 'tcp' in self.nm[ip]:
                        for port in self.nm[ip]['tcp']:
                            port_data = self.nm[ip]['tcp'][port]
                            
                            # Check if vulners script found anything
                            if 'script' in port_data and 'vulners' in port_data['script']:
                                vulners_output = port_data['script']['vulners']
                                
                                # Parse CVEs from vulners output
                                cve_pattern = r'(CVE-\d{4}-\d+)'
                                cves = re.findall(cve_pattern, vulners_output)
                                
                                if cves:
                                    vulnerabilities[port] = {
                                        'cves': cves,
                                        'service': port_details.get(port, {}).get('service', 'unknown'),
                                        'version': port_details.get(port, {}).get('version', ''),
                                        'raw_output': vulners_output
                                    }
                                    vuln_count += len(cves)
                                    
                                    # Add vulnerabilities to port_details
                                    if port in port_details:
                                        port_details[port]['vulnerabilities'] = cves
                                    
                                    self.logger.info(f"   🔴 Port {port}: {len(cves)} CVEs found")
                                    for cve in cves[:3]:
                                        self.logger.info(f"      - {cve}")
                                    
                                    if progress_callback:
                                        progress_callback('vuln_found', {
                                            'message': f'Port {port}: {len(cves)} CVEs',
                                            'port': port,
                                            'cve_count': len(cves)
                                        })
                    
                    if vuln_count > 0:
                        self.logger.info(f"✅ STAGE 2 COMPLETE: {vuln_count} CVEs found across {len(vulnerabilities)} ports ({vuln_duration:.2f}s)")
                    else:
                        self.logger.info(f"✅ STAGE 2 COMPLETE: No CVEs found ({vuln_duration:.2f}s)")
                        
                except Exception as vuln_error:
                    vuln_duration = time.time() - vuln_start
                    self.logger.error(f"💥 STAGE 2 FAILED after {vuln_duration:.2f}s: {vuln_error}")
                    self.logger.debug(f"Vuln scan traceback: {traceback.format_exc()}")
            else:
                self.logger.info(f"⏭️  STAGE 2 SKIPPED: No open ports to scan for vulnerabilities")
            
            # Now update the NetKB with deep scan results WITHOUT overwriting existing data
            self._merge_deep_scan_results(ip, hostname, open_ports, port_details, vulnerabilities)
            
            self.logger.info(f"✅ DEEP SCAN COMPLETE ip={ip} mode={scan_mode} open_ports={len(open_ports)} vulnerabilities={vuln_count} duration={scan_duration:.2f}s")
            
            return {
                'success': True,
                'open_ports': open_ports,
                'hostname': hostname,
                'port_details': port_details,
                'vulnerabilities': vulnerabilities,
                'vulnerability_count': vuln_count,
                'scan_duration': scan_duration,
                'mode': scan_mode,
                'message': f'Deep scan complete ({scan_mode}): {len(open_ports)} open ports, {vuln_count} vulnerabilities discovered'
            }
            
        except Exception as e:
            self.logger.error(f"💥 Deep scan failed for {ip}: {e}")
            self.logger.debug(f"Full traceback: {traceback.format_exc()}")
            return {
                'success': False,
                'open_ports': [],
                'hostname': '',
                'message': f'Deep scan error: {str(e)}'
            }
    
    def _merge_deep_scan_results(self, ip, hostname, open_ports, port_details, vulnerabilities=None):
        """
        Merge deep scan results into SQLite database (primary) and legacy CSV files.
        Adds new ports while preserving all existing information.
        Includes vulnerability data from vulners.nse script.
        """
        # Local import to satisfy static analysis complaining about 'os' being unbound.
        # (Global import exists at module top; this is a defensive redundancy.)
        import os  # noqa: F401
        netkbfile = self.shared_data.netkbfile
        
        if vulnerabilities is None:
            vulnerabilities = {}
        
        try:
            # ===== PART 0: Update SQLite Database (PRIMARY DATA STORE) =====
            try:
                # Get existing host data from database
                host = self.db.get_host_by_ip(ip)
                
                if host:
                    # Get existing ports
                    existing_ports_str = host.get('ports', '')
                    existing_ports = set()
                    
                    if existing_ports_str:
                        # Database uses comma-separated ports
                        existing_ports = {p.strip() for p in existing_ports_str.split(',') if p.strip()}
                    
                    # Merge with new ports from deep scan
                    new_ports = {str(p) for p in open_ports}
                    merged_ports = existing_ports.union(new_ports)
                    
                    # Sort ports numerically
                    sorted_ports = sorted(merged_ports, key=lambda x: int(x) if x.isdigit() else 0)
                    ports_str = ','.join(sorted_ports)
                    
                    # Build vulnerability summary
                    vuln_summary = ""
                    if vulnerabilities:
                        vuln_entries = []
                        for port, vuln_data in vulnerabilities.items():
                            cves = vuln_data.get('cves', [])
                            service = vuln_data.get('service', 'unknown')
                            for cve in cves[:5]:  # Limit to first 5 CVEs per port
                                vuln_entries.append(f"{port}/{service}: {cve}")
                        vuln_summary = "; ".join(vuln_entries)
                    
                    # Update the database
                    self.db.upsert_host(
                        mac=host['mac'],
                        ip=ip,
                        hostname=hostname if hostname else host.get('hostname', ''),
                        ports=ports_str,
                        vulnerabilities=vuln_summary if vuln_summary else host.get('vulnerabilities', ''),
                        # Mark that this was a deep scan
                        notes=f"Deep scan: {len(open_ports)} ports, {len(vulnerabilities)} vulns found on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    )
                    
                    vuln_msg = f", {len(vulnerabilities)} vulnerable ports" if vulnerabilities else ""
                    self.logger.info(f"✅ Updated SQLite database for {ip}: {len(merged_ports)} total ports ({len(new_ports)} from deep scan{vuln_msg})")
                else:
                    self.logger.warning(f"IP {ip} not found in database - creating new entry")
                    # Create new entry with pseudo-MAC if no existing record
                    pseudo_mac = f"00:00:{':'.join(f'{int(octet):02x}' for octet in ip.split('.'))}"
                    sorted_ports = sorted([str(p) for p in open_ports], key=lambda x: int(x) if x.isdigit() else 0)
                    
                    self.db.upsert_host(
                        mac=pseudo_mac,
                        ip=ip,
                        hostname=hostname if hostname else '',
                        ports=','.join(sorted_ports),
                        notes=f"Deep scan: {len(open_ports)} ports found on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    )
                    
                    self.logger.info(f"✅ Created new SQLite database entry for {ip}: {len(open_ports)} ports from deep scan")
                    
            except Exception as db_error:
                self.logger.error(f"Failed to update SQLite database for {ip}: {db_error}")
                self.logger.debug(f"Database error traceback: {traceback.format_exc()}")
            
            # CSV netkb.csv is no longer used - all data is in SQLite database
            # Deep scan results are persisted via db.upsert_host() above
            self.logger.debug(f"Deep scan database update complete for {ip}")
            
            # ===== PART 2: Update WiFi-specific network file (IP-indexed, comma-separated) =====
            # This is the file the web UI actually displays!
            try:
                # Import function to get wifi network file path
                import sys
                import os
                sys.path.append(os.path.dirname(os.path.dirname(__file__)))  # Add parent directory to path
                from webapp_modern import get_wifi_specific_network_file
                wifi_network_file = get_wifi_specific_network_file()
            except Exception as import_error:
                self.logger.warning(f"Failed to import get_wifi_specific_network_file: {import_error}")
                # Fallback: construct the path manually
                try:
                    import subprocess
                    result = subprocess.run(['iwgetid', '-r'], capture_output=True, text=True, timeout=5)
                    current_ssid = result.stdout.strip() if result.returncode == 0 else "unknown_network"
                except Exception:
                    current_ssid = "unknown_network"
                
                data_dir = os.path.join(self.currentdir, 'data', 'network_data')
                os.makedirs(data_dir, exist_ok=True)
                wifi_network_file = os.path.join(data_dir, f'network_{current_ssid}.csv')
            
            if not os.path.exists(wifi_network_file):
                self.logger.warning(f"WiFi-specific network file not found: {wifi_network_file}")
            else:
                # Read WiFi network file with robust error handling
                wifi_entries = []
                try:
                    # Try pandas first (handles malformed rows)
                    import pandas as pd
                    try:
                        df = pd.read_csv(wifi_network_file, on_bad_lines='warn', encoding='utf-8', encoding_errors='ignore')
                    except TypeError:  # pandas < 1.3
                        df = pd.read_csv(wifi_network_file, on_bad_lines='skip', encoding='utf-8', encoding_errors='ignore')
                    
                    wifi_headers = list(df.columns)
                    wifi_entries = df.to_dict('records')
                except Exception as pandas_error:
                    self.logger.warning(f"Pandas CSV read failed, falling back to csv module: {pandas_error}")
                    # Fallback to csv module with line-by-line error handling
                    with open(wifi_network_file, 'r', encoding='utf-8', errors='ignore') as file:
                        reader = csv.DictReader(file)
                        wifi_headers = reader.fieldnames
                        
                        for line_num, row in enumerate(reader, start=2):  # Start at 2 (after header)
                            try:
                                wifi_entries.append(row)
                            except Exception as row_error:
                                self.logger.warning(f"Skipping malformed row {line_num} in WiFi file: {row_error}")
                                continue
                
                # Find the entry for this IP
                target_entry = None
                for entry in wifi_entries:
                    if entry.get('IP', '').strip() == ip:
                        target_entry = entry
                        break
                
                if not target_entry:
                    self.logger.warning(f"IP {ip} not found in WiFi network file - skipping WiFi file merge")
                else:
                    # Get existing ports
                    existing_ports_str = target_entry.get('Ports', '')
                    existing_ports = set()
                    
                    if existing_ports_str:
                        # Parse existing ports (semicolon separated)
                        existing_ports = {p.strip() for p in existing_ports_str.split(';') if p.strip()}
                    
                    # Merge with new ports from deep scan
                    new_ports = {str(p) for p in open_ports}
                    merged_ports = existing_ports.union(new_ports)
                    
                    # Update the entry
                    target_entry['Ports'] = ';'.join(sorted(merged_ports, key=lambda x: int(x) if x.isdigit() else 0))
                    
                    # Update hostname if we got one and it's not already set
                    if hostname and not target_entry.get('Hostname', '').strip():
                        target_entry['Hostname'] = hostname
                    
                    # Update LastSeen timestamp
                    target_entry['LastSeen'] = datetime.now().isoformat()
                    
                    # Write back to file using atomic write pattern
                    if wifi_headers:  # Ensure headers exist
                        temp_fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(wifi_network_file), suffix='.tmp')
                        try:
                            with os.fdopen(temp_fd, 'w', newline='', encoding='utf-8') as file:
                                writer = csv.DictWriter(file, fieldnames=wifi_headers)
                                writer.writeheader()
                                writer.writerows(wifi_entries)  # type: ignore
                            
                            # Verify temp file has reasonable size before replacing original
                            if os.path.getsize(temp_path) > 50:
                                shutil.move(temp_path, wifi_network_file)
                                self.logger.debug(f"✅ Atomically updated WiFi network file for {ip}")
                            else:
                                self.logger.error(f"Temp WiFi file too small ({os.path.getsize(temp_path)} bytes) - not replacing original")
                                os.unlink(temp_path)
                        except Exception as write_error:
                            self.logger.error(f"Failed to write WiFi network file: {write_error}")
                            if os.path.exists(temp_path):
                                os.unlink(temp_path)
                            raise
                    else:
                        self.logger.warning(f"No headers found for WiFi network file - skipping write")
                    
                    self.logger.info(f"📝 Merged deep scan results into WiFi network file: {ip} now has {len(merged_ports)} total ports ({len(new_ports)} from deep scan)")
            
        except Exception as e:
            self.logger.error(f"Error merging deep scan results for {ip}: {e}")
            self.logger.debug(f"Full traceback: {traceback.format_exc()}")

    def start(self):
        """
        Starts the scanner in a separate thread.
        """
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self.scan)
            self.thread.start()
            logger.info("NetworkScanner started.")

    def stop(self):
        """
        Stops the scanner.
        """
        if self.running:
            self.running = False
            if self.thread.is_alive():
                self.thread.join()
            logger.info("NetworkScanner stopped.")

if __name__ == "__main__":
    shared_data = SharedData()
    scanner = NetworkScanner(shared_data)
    scanner.scan()
