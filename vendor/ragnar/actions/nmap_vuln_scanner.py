# nmap_vuln_scanner.py
# Vulnerability Scanner for Ragnar - Uses Nmap with vulners.nse script
#
# DATA ARCHITECTURE - SINGLE SOURCE OF TRUTH:
# ============================================
# This scanner feeds vulnerability data to Network Intelligence, which is the 
# AUTHORITATIVE SOURCE for all vulnerability information in Ragnar.
#
# Data Flow:
# 1. Nmap scans hosts → parses vulnerability output
# 2. Vulnerabilities fed to Network Intelligence (network_intelligence.py)
# 3. Network Intelligence stores in:
#    - In-memory: active_vulnerabilities dict (by network_id)
#    - Persistent: data/intelligence/active_findings.json
# 4. Web UI reads ONLY from Network Intelligence
#
# Auto-Repopulation:
# - If vulnerabilities are deleted via web UI and still present in scans,
#   they will be automatically re-added on next scan cycle
# - This ensures the system reflects current reality (not stale data)
#
# Legacy Files (DEPRECATED):
# - vulnerability_summary.csv - Kept for backward compatibility only
# - netkb.csv "Nmap Vulnerabilities" column - Will be removed
# - final_vulnerability_summary.csv - Will be removed
#
# TODO: Remove all CSV-based vulnerability storage once fully migrated

import os
import sys

# CRITICAL: Add parent directory to path FIRST to ensure local imports work
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)  # Insert at beginning to prioritize local modules

import re
import json
import pandas as pd
import subprocess
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn

# Import local modules AFTER path is set
from shared import SharedData
from logger import Logger
from nmap_logger import nmap_logger
from db_manager import get_db

logger = Logger(name="nmap_vuln_scanner.py", level=logging.INFO)

b_class = "NmapVulnScanner"
b_module = "nmap_vuln_scanner"
b_status = "vuln_scan"
b_port = None
b_parent = None

class NmapVulnScanner:
    """
    This class handles the Nmap vulnerability scanning process with incremental port scanning.
    
    INCREMENTAL SCANNING LOGIC:
    - Tracks which ports have been scanned for each MAC address
    - Only scans NEW ports discovered since last scan
    - Dramatically reduces resource usage on Pi Zero W2
    - Example: If MAC 4c:ed:fb:d5:fa:c9 has ports 135,139,445 already scanned,
               and port 22 is newly discovered, only port 22 gets scanned
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.scan_results = []
        
        # Incremental scan tracking file
        self.scanned_ports_file = os.path.join(
            self.shared_data.vulnerabilities_dir, 
            'scanned_ports_history.json'
        )
        
        # Initialize SQLite database manager (SINGLE SOURCE OF TRUTH)
        self.db = get_db(currentdir=shared_data.currentdir)
        
        self.load_scanned_ports_history()
        logger.debug("NmapVulnScanner initialized with SQLite database and incremental scanning.")

    def load_scanned_ports_history(self):
        """
        Load the history of which ports have been scanned for each MAC address.
        Format: {
            "4c:ed:fb:d5:fa:c9": {
                "ports": ["135", "139", "445"],
                "last_scan": "2024-01-15T10:30:00"
            },
            "aa:bb:cc:dd:ee:ff": {
                "ports": ["22", "80", "443"],
                "last_scan": "2024-01-15T11:45:00"
            }
        }
        
        Legacy format (auto-converted): {
            "4c:ed:fb:d5:fa:c9": ["135", "139", "445"]
        }
        """
        try:
            if os.path.exists(self.scanned_ports_file):
                with open(self.scanned_ports_file, 'r') as f:
                    data = json.load(f)
                    
                # Convert legacy format (list of ports) to new format (dict with ports and timestamp)
                self.scanned_ports_history = {}
                for mac, value in data.items():
                    if isinstance(value, list):
                        # Legacy format - convert to new format with old timestamp to force rescan
                        self.scanned_ports_history[mac] = {
                            "ports": value,
                            "last_scan": datetime.min.isoformat()
                        }
                        logger.debug(f"Converted legacy format for MAC {mac}")
                    elif isinstance(value, dict) and "ports" in value:
                        # New format - use as-is
                        self.scanned_ports_history[mac] = value
                    else:
                        logger.warning(f"Invalid format for MAC {mac}, skipping")
                        
                logger.info(f"📋 Loaded scanned ports history for {len(self.scanned_ports_history)} MAC addresses")
            else:
                self.scanned_ports_history = {}
                logger.info("🆕 No scanned ports history found - starting fresh")
        except Exception as e:
            logger.error(f"Error loading scanned ports history: {e}")
            self.scanned_ports_history = {}
    
    def save_scanned_ports_history(self):
        """
        Save the history of scanned ports to disk.
        """
        try:
            os.makedirs(self.shared_data.vulnerabilities_dir, exist_ok=True)
            with open(self.scanned_ports_file, 'w') as f:
                json.dump(self.scanned_ports_history, f, indent=2)
            logger.debug(f"💾 Saved scanned ports history ({len(self.scanned_ports_history)} MACs tracked)")
        except Exception as e:
            logger.error(f"Error saving scanned ports history: {e}")
    
    def update_scanned_ports_for_mac(self, mac, scanned_ports):
        """
        Update the list of scanned ports for a given MAC address with timestamp.
        
        Args:
            mac: MAC address (e.g., "4c:ed:fb:d5:fa:c9")
            scanned_ports: List of port numbers that were just scanned
        """
        if mac not in self.scanned_ports_history:
            self.scanned_ports_history[mac] = {
                "ports": [],
                "last_scan": datetime.now().isoformat()
            }
        
        # Ensure the entry has the new format
        if isinstance(self.scanned_ports_history[mac], list):
            self.scanned_ports_history[mac] = {
                "ports": self.scanned_ports_history[mac],
                "last_scan": datetime.now().isoformat()
            }
        
        # Add new ports to the history (avoiding duplicates)
        ports_list = self.scanned_ports_history[mac]["ports"]
        for port in scanned_ports:
            port_str = str(port).strip()
            if port_str and port_str not in ports_list:
                ports_list.append(port_str)
        
        # Sort for cleaner output
        ports_list.sort(key=lambda x: int(x) if x.isdigit() else 0)
        
        # Update timestamp to current time
        self.scanned_ports_history[mac]["last_scan"] = datetime.now().isoformat()
        
        # Save to disk
        self.save_scanned_ports_history()
    
    def get_new_ports_to_scan(self, mac, current_ports):
        """
        Determine which ports are NEW and need scanning.
        Also checks if the last scan was more than 1 hour ago and forces a rescan if needed.
        
        Args:
            mac: MAC address to check
            current_ports: List of currently open ports on this host
            
        Returns:
            List of NEW ports that haven't been scanned before, or ALL ports if 1 hour has passed
        """
        if mac not in self.scanned_ports_history:
            # First time seeing this MAC - scan all ports
            logger.info(f"🆕 NEW MAC {mac} - will scan all {len(current_ports)} ports")
            return current_ports
        
        # Ensure the entry has the new format
        if isinstance(self.scanned_ports_history[mac], list):
            # Legacy format - convert and force rescan
            self.scanned_ports_history[mac] = {
                "ports": self.scanned_ports_history[mac],
                "last_scan": datetime.min.isoformat()
            }
        
        # Check if last scan was more than 1 hour ago
        last_scan_str = self.scanned_ports_history[mac].get("last_scan", datetime.min.isoformat())
        try:
            last_scan_time = datetime.fromisoformat(last_scan_str)
            time_since_last_scan = datetime.now() - last_scan_time
            
            # If more than 1 hour has passed, force a full rescan
            if time_since_last_scan > timedelta(hours=1):
                logger.info(f"⏰ MAC {mac}: Last scan was {time_since_last_scan.total_seconds()/3600:.1f} hours ago - FORCING RESCAN of all {len(current_ports)} ports")
                # Clear the ports history to force rescan, but keep the MAC entry
                self.scanned_ports_history[mac]["ports"] = []
                return current_ports
        except (ValueError, TypeError) as e:
            logger.warning(f"Invalid timestamp for MAC {mac}: {last_scan_str} - forcing rescan. Error: {e}")
            self.scanned_ports_history[mac]["ports"] = []
            return current_ports
        
        previously_scanned = set(self.scanned_ports_history[mac].get("ports", []))
        current_ports_set = set(str(p).strip() for p in current_ports if p)
        
        new_ports = current_ports_set - previously_scanned
        
        if new_ports:
            logger.info(f"🔍 MAC {mac}: {len(new_ports)} NEW ports to scan (out of {len(current_ports_set)} total)")
            logger.info(f"   Previously scanned: {sorted(previously_scanned, key=lambda x: int(x) if x.isdigit() else 0)}")
            logger.info(f"   New ports: {sorted(new_ports, key=lambda x: int(x) if x.isdigit() else 0)}")
        else:
            logger.info(f"✅ MAC {mac}: All {len(current_ports_set)} ports already scanned (last scan: {time_since_last_scan.total_seconds()/60:.1f} minutes ago) - SKIPPING")
        
        return sorted(new_ports, key=lambda x: int(x) if x.isdigit() else 0)
    
    def reset_scan_history(self, mac=None):
        """
        Reset scan history for specific MAC or all MACs.
        
        Args:
            mac: Specific MAC address to reset, or None to reset all
        """
        if mac:
            if mac in self.scanned_ports_history:
                del self.scanned_ports_history[mac]
                self.save_scanned_ports_history()
                logger.info(f"🔄 Reset scan history for MAC {mac}")
                return True
            else:
                logger.warning(f"MAC {mac} not found in scan history")
                return False
        else:
            self.scanned_ports_history = {}
            self.save_scanned_ports_history()
            logger.info("🔄 Reset ALL scan history - next scan will be full rescan")
            return True
    
    def get_scan_history_stats(self):
        """
        Get statistics about the scan history.
        
        Returns:
            dict: Statistics including MAC count, total ports tracked, etc.
        """
        total_ports = 0
        mac_details = {}
        
        for mac, data in self.scanned_ports_history.items():
            # Handle both old and new format
            if isinstance(data, list):
                ports = data
                last_scan = None
            elif isinstance(data, dict):
                ports = data.get("ports", [])
                last_scan = data.get("last_scan")
            else:
                continue
            
            total_ports += len(ports)
            mac_details[mac] = {
                "port_count": len(ports),
                "last_scan": last_scan
            }
        
        return {
            'total_macs_tracked': len(self.scanned_ports_history),
            'total_ports_scanned': total_ports,
            'average_ports_per_mac': total_ports / len(self.scanned_ports_history) if self.scanned_ports_history else 0,
            'mac_details': mac_details
        }

    def update_database_vulnerabilities(self, ip, hostname, mac, port, vulnerabilities):
        """
        Updates the SQLite database with vulnerability scan results.
        Database is the SINGLE SOURCE OF TRUTH - no CSV files.
        """
        try:
            # Write to SQLite database
            if mac and mac.lower() not in ['unknown', '00:00:00:00:00:00', '']:
                self.db.upsert_host(
                    mac=mac.lower().strip(),
                    ip=ip,
                    hostname=hostname,
                    vulnerabilities=vulnerabilities
                )
                logger.debug(f"✅ Updated database with vulnerability data for {mac}")
            else:
                logger.warning(f"Invalid MAC address for {ip}, skipping database update")
            
        except Exception as e:
            logger.error(f"Error updating database with vulnerabilities: {e}")


    def scan_vulnerabilities(self, ip, hostname, mac, ports):
        combined_result = ""
        success = True  # Initialize to True, will become False if an error occurs
        try:
            self.shared_data.bjornstatustext2 = ip

            ports_to_scan = self.prepare_port_list(ports)
            
            # INCREMENTAL SCANNING: Only scan NEW ports for this MAC address
            if mac and mac not in ['Unknown', '00:00:00:00:00:00', '']:
                original_port_count = len(ports_to_scan)
                ports_to_scan = self.get_new_ports_to_scan(mac, ports_to_scan)
                
                if not ports_to_scan and original_port_count > 0:
                    logger.info(f"⏭️ SKIPPING {ip} (MAC {mac}) - All {original_port_count} ports already scanned")
                    return None  # All ports already scanned - skip this host
                elif ports_to_scan and original_port_count > 0:
                    logger.info(f"📍 INCREMENTAL SCAN {ip} (MAC {mac}): {len(ports_to_scan)}/{original_port_count} NEW ports")
            else:
                logger.warning(f"⚠️ No valid MAC for {ip} - cannot use incremental scanning")
            
            # Determine scan strategy based on detected ports
            if not ports_to_scan:
                # Check if scanning hosts without ports is enabled
                scan_vuln_no_ports = getattr(self.shared_data, 'scan_vuln_no_ports', True)
                
                if not scan_vuln_no_ports:
                    logger.info(f"No ports detected for {ip} and scan_vuln_no_ports is disabled. Skipping vulnerability scan.")
                    return None  # Skip scanning this host
                
                # No ports detected - scan top 50 ports for vulnerabilities
                logger.info(f"No ports detected for {ip}. Scanning top 50 ports for vulnerabilities.")
                nmap_command = [
                    "nmap",
                    "-Pn",
                    "-sT",  # TCP connect scan (works on Wi-Fi)
                    "-sV",  # Service version detection
                    "--script",
                    "vulners.nse",
                    "--top-ports",
                    "50",
                    ip,
                ]
            else:
                # Ports detected - scan those specific ports
                logger.info(
                    f"Scanning {ip} on {len(ports_to_scan)} detected ports for vulnerabilities: {','.join(ports_to_scan[:10])}{'...' if len(ports_to_scan) > 10 else ''}"
                )
                nmap_command = [
                    "nmap",
                    "-Pn",  # Treat host as up (skip ping)
                    "-sT",  # TCP connect scan (works on Wi-Fi)
                    "-sV",  # Service version detection
                    "--script",
                    "vulners.nse",
                    "-p",
                    ",".join(ports_to_scan),
                    ip,
                ]
            
            # Execute nmap command with logging
            result = nmap_logger.run_nmap_command(
                nmap_command,
                context=f"Vulnerability scan for {ip}",
                capture_output=True,
                text=True,
            )
            combined_result += result.stdout

            if result.returncode != 0:
                logger.warning(
                    f"nmap returned a non-zero exit code while scanning {ip}: {result.stderr.strip()}"
                )

            vulnerability_summary, port_vulnerabilities, port_services = self.parse_vulnerabilities(result.stdout)
            
            # Log parsing results for debugging
            logger.info(f"Parsed {len(port_vulnerabilities)} ports with vulnerabilities for {ip}")
            for port, vulns in port_vulnerabilities.items():
                logger.debug(f"Port {port}: {len(vulns)} vulnerabilities found")
            
            if not port_vulnerabilities or all(len(v) == 0 for v in port_vulnerabilities.values()):
                logger.warning(f"No vulnerabilities detected in scan output for {ip}")
            
            # SINGLE SOURCE OF TRUTH: Feed vulnerabilities ONLY to Network Intelligence
            # Network Intelligence is the authoritative source - no CSV files needed
            # If vulnerabilities are deleted via web UI and scan finds them again,
            # they will be automatically re-added here
            self.feed_to_network_intelligence(ip, port_vulnerabilities, port_services)
            
            # CRITICAL: Update scanned ports history for incremental scanning
            # This ensures we don't re-scan the same ports on subsequent runs
            if mac and mac not in ['Unknown', '00:00:00:00:00:00', ''] and ports_to_scan:
                self.update_scanned_ports_for_mac(mac, ports_to_scan)
                logger.info(f"✅ Updated scan history for MAC {mac}: Added {len(ports_to_scan)} ports")
            
            # Update SQLite database with vulnerability information
            if ports_to_scan:
                scanned_ports_str = ",".join(ports_to_scan)
            else:
                scanned_ports_str = "top-50"
            self.update_database_vulnerabilities(ip, hostname, mac, scanned_ports_str, vulnerability_summary)
            self.update_database_detailed_vulnerabilities(mac, ip, port_vulnerabilities, port_services)
            
            # Add vulnerability scan to scan history in database
            try:
                if mac and mac.lower() not in ['unknown', '00:00:00:00:00:00', '']:
                    vuln_count = sum(len(vulns) for vulns in port_vulnerabilities.values())
                    self.db.add_scan_history(
                        mac=mac.lower().strip(),
                        ip=ip,
                        scan_type='vuln_scan',
                        ports_found=scanned_ports_str,
                        vulnerabilities_found=vuln_count
                    )
                    logger.debug(f"✅ Added vulnerability scan history for {mac}: {vuln_count} vulnerabilities")
            except Exception as db_error:
                logger.error(f"Failed to add scan history to database: {db_error}")

        except Exception as e:
            logger.error(f"Error scanning {ip}: {e}")
            success = False  # Mark as failed if an error occurs

        return combined_result if success else None

    def execute(self, ip, row, status_key):
        """
        Executes the vulnerability scan for a given IP and row data.
        Returns: 'success' if scan was performed, 'skipped' if already scanned, 'failed' on error
        """
        self.shared_data.ragnarorch_status = "NmapVulnScanner"
        ports = row.get("Ports", "")
        scan_result = self.scan_vulnerabilities(ip, row["Hostnames"], row["MAC Address"], ports)

        if scan_result is not None:
            self.scan_results.append((ip, row["Hostnames"], row["MAC Address"]))
            self.save_results(row["MAC Address"], ip, scan_result)
            return 'success'
        else:
            # Returning 'skipped' to indicate scan was not performed (already scanned)
            # This helps orchestrator track accurate metrics
            return 'skipped'

    def prepare_port_list(self, ports) -> List[str]:
        """Normalize port values from the NetKB row"""
        if isinstance(ports, (list, tuple, set)):
            raw_ports = list(ports)
        elif isinstance(ports, str):
            raw_ports = []
            for separator in [';', ',']:
                if separator in ports:
                    raw_ports = ports.split(separator)
                    break
            if not raw_ports:
                raw_ports = [ports]
        elif ports is None:
            raw_ports = []
        else:
            raw_ports = [str(ports)]

        normalized_ports: Set[str] = set()
        for port in raw_ports:
            if port is None:
                continue
            port = str(port).strip()
            if not port:
                continue
            if '-' in port:
                start, end = port.split('-', 1)
                if start.isdigit() and end.isdigit():
                    start_port, end_port = int(start), int(end)
                    if start_port <= end_port:
                        for value in range(start_port, end_port + 1):
                            normalized_ports.add(str(value))
                    continue
            if port.isdigit():
                normalized_ports.add(port)

        return sorted(normalized_ports, key=lambda x: int(x))

    def get_default_vulnerability_ports(self) -> List[str]:
        """Return default ports to scan when none are supplied"""
        default_ports = self.shared_data.config.get("default_vulnerability_ports")
        if isinstance(default_ports, (list, tuple, set)) and default_ports:
            valid_ports = [str(port) for port in default_ports if str(port).isdigit()]
            if valid_ports:
                return sorted(set(valid_ports), key=int)
        return ["22", "80", "443"]

    def parse_vulnerabilities(self, scan_result):
        """
        Parses the Nmap scan result to extract vulnerabilities per port and service.
        Returns a summary string, a mapping of ports to vulnerabilities, and detected services.
        """
        port_vulnerabilities: Dict[str, List[str]] = {}
        port_services: Dict[str, str] = {}
        summary_entries: Set[str] = set()

        current_port: Optional[str] = None
        current_service: str = "unknown"
        in_vulners_section = False

        for raw_line in scan_result.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            # Detect port lines (e.g., "22/tcp  open   ssh     OpenSSH 9.2p1")
            if "/tcp" in line and any(state in line for state in ["open", "closed", "filtered"]):
                parts = line.split()
                if parts:
                    port_info = parts[0]
                    port_candidate = port_info.split('/')[0] if port_info else ''
                    if not port_candidate:
                        current_port = None
                        continue
                    port_key = port_candidate
                    current_port = port_key
                    # Extract service information (usually at index 2 or later)
                    if len(parts) >= 3:
                        current_service = parts[2]
                    elif len(parts) >= 2:
                        current_service = parts[1]
                    else:
                        current_service = "unknown"
                    port_services[port_key] = current_service
                    port_vulnerabilities.setdefault(port_key, [])
                    in_vulners_section = False
                continue

            if current_port is None:
                continue

            # Detect the start of vulners output section
            if line.startswith('|') and 'vulners:' in line.lower():
                in_vulners_section = True
                continue

            # Parse vulnerability lines (lines starting with |)
            if line.startswith('|'):
                cleaned_line = line.lstrip('|').strip()
                
                # Skip empty lines and section headers
                if not cleaned_line:
                    continue
                
                # Look for vulnerability indicators
                if any(keyword in cleaned_line for keyword in ("CVE-", "VULNERABLE", "*EXPLOIT*", 
                                                                "PACKETSTORM:", "cpe:/", "SNYK:",
                                                                "1337DAY-ID-", "SSV:", "CNVD-")):
                    port_vulnerabilities.setdefault(current_port, []).append(cleaned_line)
                    summary_entries.add(f"{current_port}/{current_service}: {cleaned_line}")
                    continue
                
                # Also capture lines with vulnerability scores (numeric patterns)
                score_pattern = re.search(r'\s+(\d+\.\d+|\d+)\s+https?://', cleaned_line)
                if score_pattern and in_vulners_section:
                    port_vulnerabilities.setdefault(current_port, []).append(cleaned_line)
                    summary_entries.add(f"{current_port}/{current_service}: {cleaned_line}")

        summary = "; ".join(sorted(summary_entries))
        return summary, port_vulnerabilities, port_services

    def determine_severity(self, vulnerability_text: str) -> Tuple[str, str]:
        """Determine severity and normalized description from vulnerability text"""
        normalized_text = vulnerability_text
        severity = "medium"

        cve_match = re.search(r"(CVE-\d{4}-\d+)", vulnerability_text)
        
        # Look for CVSS score AFTER the CVE ID to avoid matching the year in CVE-YYYY-NNNNN
        # CVSS scores are typically 0.0-10.0, so we look for patterns like "7.5" or standalone decimals
        # that appear after any CVE ID in the text
        score_match = None
        if cve_match:
            # Search for score only in the text AFTER the CVE ID
            text_after_cve = vulnerability_text[cve_match.end():]
            score_match = re.search(r'(\d{1,2}\.\d+)', text_after_cve)
        else:
            # No CVE, look for a decimal score pattern anywhere (CVSS scores have decimals)
            score_match = re.search(r'(\d{1,2}\.\d+)', vulnerability_text)

        if cve_match:
            normalized_text = cve_match.group(1)
            if score_match:
                try:
                    score_value = float(score_match.group(1))
                    # Only use the score if it's in valid CVSS range (0.0 - 10.0)
                    if 0.0 <= score_value <= 10.0:
                        normalized_text = f"{normalized_text} (Score: {score_match.group(1)})"
                        if score_value >= 9.0:
                            severity = "critical"
                        elif score_value >= 7.0:
                            severity = "high"
                        elif score_value >= 4.0:
                            severity = "medium"
                        else:
                            severity = "low"
                except ValueError:
                    severity = "medium"
        elif "*EXPLOIT*" in vulnerability_text.upper():
            severity = "high"
        elif "VULNERABLE" in vulnerability_text.upper():
            severity = "medium"

        return severity, normalized_text

    def feed_to_network_intelligence(self, ip, port_vulnerabilities, port_services):
        """
        Feed vulnerability scan results to the network intelligence system
        """
        try:
            # Check if network intelligence is available
            if not hasattr(self.shared_data, 'network_intelligence') or not self.shared_data.network_intelligence:
                logger.debug("Network intelligence not available, skipping vulnerability feed")
                return
            
            for port_str, vulnerabilities in port_vulnerabilities.items():
                if not vulnerabilities:
                    continue

                service = port_services.get(port_str, "unknown")

                for vulnerability in vulnerabilities:
                    # FILTER: Only add real vulnerabilities with identifiers
                    # Skip generic/empty vulnerability entries
                    if not any(keyword in vulnerability for keyword in ["CVE-", "EXPLOIT", "VULNERABLE", 
                                                                         "PACKETSTORM:", "1337DAY", "SSV:", 
                                                                         "CNVD-", "SNYK:"]):
                        logger.debug(f"Skipping non-specific vulnerability entry: {vulnerability[:50]}...")
                        continue
                    
                    severity, normalized_text = self.determine_severity(vulnerability)
                    
                    # Additional filter: normalized_text must not be empty and should have substance
                    if not normalized_text or len(normalized_text.strip()) < 5:
                        logger.debug(f"Skipping empty or too short vulnerability: {normalized_text}")
                        continue

                    try:
                        self.shared_data.network_intelligence.add_vulnerability(
                            host=ip,
                            port=int(port_str),
                            service=service or "unknown",
                            vulnerability=normalized_text,
                            severity=severity,
                            details={
                                'raw_output': vulnerability,
                                'service': service or "unknown",
                                'port': int(port_str),
                            }
                        )
                        logger.info(f"Added VERIFIED vulnerability: {ip}:{port_str} - {normalized_text}")
                    except Exception as e:
                        logger.warning(f"Failed to add vulnerability to network intelligence: {e}")

        except Exception as e:
            logger.error(f"Error feeding vulnerabilities to network intelligence: {e}")

    def update_database_detailed_vulnerabilities(self, mac, ip, port_vulnerabilities, port_services):
        """Persist detailed vulnerability information to SQLite database (SINGLE SOURCE OF TRUTH)"""
        try:
            # Build vulnerability summary
            vulnerability_entries: List[str] = []
            for port_str, vulnerabilities in port_vulnerabilities.items():
                service = port_services.get(port_str, "unknown")
                for vulnerability in vulnerabilities:
                    _, normalized_text = self.determine_severity(vulnerability)
                    vulnerability_entries.append(f"{port_str}/{service}: {normalized_text}")

            if not vulnerability_entries:
                logger.debug(f"No vulnerability entries to update for {ip}")
                return

            summary_text = "; ".join(sorted(set(vulnerability_entries)))
            
            # Update SQLite database (ONLY source of truth)
            if mac and mac.lower() not in ['unknown', '00:00:00:00:00:00', '']:
                try:
                    # Merge ports
                    all_ports = sorted(set(port_vulnerabilities.keys()), key=lambda x: int(x) if x.isdigit() else 0)
                    ports_str = ','.join(all_ports)
                    
                    # Update host with vulnerability and port information
                    self.db.upsert_host(
                        mac=mac.lower().strip(),
                        ip=ip,
                        ports=ports_str,
                        vulnerabilities=summary_text
                    )
                    logger.info(f"✅ Updated database with {len(vulnerability_entries)} vulnerabilities for {mac} ({ip})")
                except Exception as db_error:
                    logger.error(f"Failed to update database with vulnerabilities: {db_error}")
            else:
                logger.warning(f"Invalid MAC address for {ip}, cannot update database")

        except Exception as e:
            logger.error(f"Error updating database with detailed vulnerabilities for {ip}: {e}")

    def save_results(self, mac_address, ip, scan_result):
        """
        Saves the detailed scan results to a file.
        """
        try:
            sanitized_mac_address = mac_address.replace(":", "")
            result_dir = self.shared_data.vulnerabilities_dir
            os.makedirs(result_dir, exist_ok=True)
            result_file = os.path.join(result_dir, f"{sanitized_mac_address}_{ip}_vuln_scan.txt")
            
            # Open the file in write mode to clear its contents if it exists, then close it
            if os.path.exists(result_file):
                open(result_file, 'w').close()
            
            # Write the new scan result to the file
            with open(result_file, 'w') as file:
                file.write(scan_result)
            
            logger.info(f"Results saved to {result_file}")
        except Exception as e:
            logger.error(f"Error saving scan results for {ip}: {e}")


    def save_summary(self):
        """
        Log summary of vulnerability scans - all data is in SQLite database.
        """
        try:
            # Get statistics from database
            all_hosts = self.db.get_all_hosts()
            hosts_with_vulns = [h for h in all_hosts if h.get('vulnerabilities')]
            
            logger.info(f"="*60)
            logger.info(f"VULNERABILITY SCAN SUMMARY")
            logger.info(f"="*60)
            logger.info(f"Total hosts scanned: {len(self.scan_results)}")
            logger.info(f"Hosts with vulnerabilities: {len(hosts_with_vulns)}")
            logger.info(f"All data stored in SQLite database: {self.db.db_path}")
            logger.info(f"="*60)
        except Exception as e:
            logger.error(f"Error generating summary: {e}")

    def force_scan_all_hosts(self, real_time_callback=None):
        """
        Force scan all alive hosts in the database regardless of previous scan status.
        This bypasses the retry delays and previous scan status checks.
        
        Args:
            real_time_callback: Optional callback function for real-time updates
        """
        try:
            # Read alive hosts from SQLite database
            db_hosts = self.db.get_all_hosts()
            if not db_hosts:
                logger.warning("No hosts found in database for vulnerability scanning")
                if real_time_callback:
                    real_time_callback("error", {"message": "No hosts found in database"})
                return 0
            
            # Filter for alive hosts (status == 'alive')
            alive_hosts = [host for host in db_hosts if host.get('status') == 'alive']
            
            if not alive_hosts:
                logger.warning("No alive hosts found in database")
                if real_time_callback:
                    real_time_callback("error", {"message": "No alive hosts found"})
                return 0
            
            scanned_count = 0
            
            logger.info(f"Force scanning {len(alive_hosts)} alive hosts for vulnerabilities...")
            nmap_logger.log_scan_operation(f"Force vulnerability scan", f"Scanning {len(alive_hosts)} hosts")
            
            # Send initial progress update
            if real_time_callback:
                real_time_callback("scan_started", {
                    "total_hosts": len(alive_hosts),
                    "scanned": 0,
                    "current_ip": None
                })
            
            for i, host in enumerate(alive_hosts):
                ip = host.get("ip", "")
                mac = host.get("mac", "")
                if not ip or not mac:
                    continue
                    
                try:
                    # Send progress update
                    if real_time_callback:
                        real_time_callback("scan_progress", {
                            "total_hosts": len(alive_hosts),
                            "scanned": i,
                            "current_ip": ip,
                            "current_host": host.get("hostname", ""),
                            "current_mac": mac,
                            "progress_percent": int((i / len(alive_hosts)) * 100)
                        })
                    
                    # Convert database format to legacy row format for compatibility
                    row = {
                        "IPs": ip,
                        "Hostnames": host.get("hostname", ""),
                        "MAC Address": mac,
                        "Ports": host.get("ports", ""),
                        "Alive": "1"
                    }
                    
                    logger.info(f"Scanning {ip} ({i+1}/{len(alive_hosts)}) for vulnerabilities...")
                    result = self.execute(ip, row, "NmapVulnScanner")
                    
                    if result == 'success':
                        scanned_count += 1
                        # Update scan status in database
                        try:
                            self.db.update_host_action_status(
                                mac=mac.lower().strip(),
                                action_name='NmapVulnScanner',
                                status='success'
                            )
                        except Exception as db_error:
                            logger.error(f"Failed to update scan status in database: {db_error}")
                        
                        # Send real-time update with scan results
                        if real_time_callback:
                            self._send_host_update(real_time_callback, ip, row, "success")
                    
                    elif result == 'skipped':
                        # Host was skipped (already scanned)
                        logger.debug(f"Host {ip} skipped - already scanned")
                        # Don't update database status - keep existing status
                        if real_time_callback:
                            self._send_host_update(real_time_callback, ip, row, "skipped")
                            
                    else:
                        # Scan failed
                        scanned_count += 1  # Count failed attempts
                        # Update failed status in database
                        try:
                            self.db.update_host_action_status(
                                mac=mac.lower().strip(),
                                action_name='NmapVulnScanner',
                                status='failed'
                            )
                        except Exception as db_error:
                            logger.error(f"Failed to update failed status in database: {db_error}")
                        
                        # Send real-time update for failed scan
                        if real_time_callback:
                            self._send_host_update(real_time_callback, ip, row, "failed")
                        
                except Exception as e:
                    logger.error(f"Error force scanning {ip}: {e}")
                    if real_time_callback:
                        real_time_callback("scan_error", {
                            "ip": ip,
                            "error": str(e)
                        })
            
            # Send completion update
            if real_time_callback:
                real_time_callback("scan_completed", {
                    "total_hosts": len(alive_hosts),
                    "scanned": scanned_count,
                    "success_count": scanned_count
                })
                    
            logger.info(f"Force scan completed. Successfully scanned {scanned_count} hosts.")
            return scanned_count
            
        except Exception as e:
            logger.error(f"Error in force_scan_all_hosts: {e}")
            if real_time_callback:
                real_time_callback("error", {"message": str(e)})
            return 0

    def _send_host_update(self, callback, ip, row, status):
        """Send real-time update for a scanned host"""
        try:
            # Get vulnerability data if available
            vulnerabilities = []
            if hasattr(self.shared_data, 'network_intelligence') and self.shared_data.network_intelligence:
                # Get vulnerabilities from network intelligence
                network_id = self.shared_data.network_intelligence.get_current_network_id()
                if network_id in self.shared_data.network_intelligence.active_vulnerabilities:
                    host_vulns = [v for v in self.shared_data.network_intelligence.active_vulnerabilities[network_id].values() 
                                 if v.get('host') == ip]
                    vulnerabilities = host_vulns
            
            host_data = {
                "ip": ip,
                "hostname": row.get("Hostnames", ""),
                "mac": row.get("MAC Address", ""),
                "ports": row.get("Ports", ""),
                "alive": row.get("Alive", "0"),
                "scan_status": status,
                "vulnerabilities": vulnerabilities,
                "last_scan": datetime.now().isoformat()
            }
            
            callback("host_updated", host_data)
            
        except Exception as e:
            logger.error(f"Error sending host update: {e}")

    def scan_single_host_realtime(self, ip, hostname="", mac="", ports="", callback=None):
        """
        Scan a single host in real-time and send updates via callback
        
        Args:
            ip: IP address to scan
            hostname: Hostname of the target
            mac: MAC address of the target
            ports: Ports to scan (string or list)
            callback: Function to call with real-time updates
        """
        try:
            if callback:
                callback("scan_started", {
                    "ip": ip,
                    "hostname": hostname,
                    "mac": mac
                })
            
            # Create a row object for compatibility
            row = {
                "IPs": ip,
                "Hostnames": hostname,
                "MAC Address": mac,
                "Ports": ports,
                "Alive": "1"
            }
            
            # Execute the scan
            result = self.execute(ip, row, "NmapVulnScanner")
            
            # Send completion update
            if callback:
                self._send_host_update(callback, ip, row, result)
                callback("scan_completed", {
                    "ip": ip,
                    "status": result,
                    "timestamp": datetime.now().isoformat()
                })
                
            return result
            
        except Exception as e:
            logger.error(f"Error in single host scan for {ip}: {e}")
            if callback:
                callback("scan_error", {
                    "ip": ip,
                    "error": str(e)
                })
            return "failed"

if __name__ == "__main__":
    shared_data = SharedData()
    try:
        nmap_vuln_scanner = NmapVulnScanner(shared_data)
        logger.info("Starting vulnerability scans from database...")

        # Load alive hosts from SQLite database
        db = get_db(currentdir=shared_data.currentdir)
        db_hosts = db.get_all_hosts()
        alive_hosts = [host for host in db_hosts if host.get('status') == 'alive']
        
        if not alive_hosts:
            logger.warning("No alive hosts found in database")
            exit(0)
        
        logger.info(f"Found {len(alive_hosts)} alive hosts in database")

        # Execute the scan on each IP with concurrency
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.1f}%",
            console=Console()
        ) as progress:
            task = progress.add_task("Scanning vulnerabilities...", total=len(alive_hosts))
            futures = []
            with ThreadPoolExecutor(max_workers=2) as executor:  # Adjust the number of workers for RPi Zero
                for host in alive_hosts:
                    # Convert database format to legacy row format
                    row = {
                        "IPs": host.get("ip", ""),
                        "Hostnames": host.get("hostname", ""),
                        "MAC Address": host.get("mac", ""),
                        "Ports": host.get("ports", ""),
                        "Alive": "1"
                    }
                    ip = row["IPs"]
                    if ip:
                        futures.append(executor.submit(nmap_vuln_scanner.execute, ip, row, b_status))

                for future in as_completed(futures):
                    progress.update(task, advance=1)

        # Log summary (data is in SQLite database)
        nmap_vuln_scanner.save_summary()
        logger.info(f"Total scans performed: {len(nmap_vuln_scanner.scan_results)}")
        logger.info(f"All vulnerability data stored in SQLite database")
        exit(len(nmap_vuln_scanner.scan_results))
    except Exception as e:
        logger.error(f"Error: {e}")
