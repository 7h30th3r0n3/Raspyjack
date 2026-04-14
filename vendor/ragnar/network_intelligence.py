#!/usr/bin/env python3
"""
Network-Based Intelligence System for Ragnar
Tracks vulnerabilities and credentials based on WiFi network context
Maintains active vs resolved states for smart persistence

Features:
- Network-aware vulnerability tracking
- Active vs resolved credential management  
- Dashboard shows current network findings
- NetKB tracks historical and resolved items
- Automatic state transitions based on network presence
"""

import os
import json
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple
from logger import Logger
import logging


class NetworkIntelligence:
    """Manages network-based intelligence for vulnerabilities and credentials"""
    
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.logger = Logger(name="NetworkIntelligence", level=logging.INFO)
        
        # Network context tracking
        self.current_network = None
        self.previous_network = None
        self.network_change_time = None
        self.network_history = {}
        
        # Intelligence storage paths
        self.intelligence_dir = self._resolve_intelligence_dir()
        self._rebuild_file_paths()
        
        # State management
        self.active_vulnerabilities = {}  # network_id -> {vuln_id: vuln_data}
        self.active_credentials = {}      # network_id -> {cred_id: cred_data}
        self.resolved_vulnerabilities = {}
        self.resolved_credentials = {}
        self.network_profiles = {}
        
        # Configuration
        self.resolution_timeout = shared_data.config.get('network_resolution_timeout', 3600)  # 1 hour
        self.confirmation_scans = shared_data.config.get('network_confirmation_scans', 3)
        self.network_change_grace_period = shared_data.config.get('network_change_grace', 300)  # 5 minutes
        
        # Initialize intelligence system
        self.setup_intelligence_directory()
        self.load_intelligence_data()

    def _resolve_intelligence_dir(self) -> str:
        candidate = getattr(self.shared_data, 'network_intelligence_dir', None)
        if candidate:
            return candidate
        return os.path.join(self.shared_data.datadir, 'intelligence')

    def _rebuild_file_paths(self):
        self.network_profiles_file = os.path.join(self.intelligence_dir, 'network_profiles.json')
        self.active_findings_file = os.path.join(self.intelligence_dir, 'active_findings.json')
        self.resolved_findings_file = os.path.join(self.intelligence_dir, 'resolved_findings.json')

    def set_storage_root(self, intelligence_dir: str):
        """Switch to a new intelligence directory (per-network)."""
        if not intelligence_dir or intelligence_dir == self.intelligence_dir:
            return
        self.save_intelligence_data()
        self.intelligence_dir = intelligence_dir
        self._rebuild_file_paths()
        self.setup_intelligence_directory()
        self.load_intelligence_data()
        self.logger.info(f"Network intelligence storage switched to: {self.intelligence_dir}")
        
    def setup_intelligence_directory(self):
        """Create intelligence directory structure"""
        try:
            os.makedirs(self.intelligence_dir, exist_ok=True)
            self.logger.info("Intelligence directory initialized")
        except Exception as e:
            self.logger.error(f"Failed to create intelligence directory: {e}")
    
    def load_intelligence_data(self):
        """Load existing intelligence data"""
        try:
            # Load network profiles
            if os.path.exists(self.network_profiles_file):
                with open(self.network_profiles_file, 'r') as f:
                    self.network_profiles = json.load(f)
            
            # Load active findings
            if os.path.exists(self.active_findings_file):
                with open(self.active_findings_file, 'r') as f:
                    data = json.load(f)
                    self.active_vulnerabilities = data.get('vulnerabilities', {})
                    self.active_credentials = data.get('credentials', {})
            
            # Load resolved findings
            if os.path.exists(self.resolved_findings_file):
                with open(self.resolved_findings_file, 'r') as f:
                    data = json.load(f)
                    self.resolved_vulnerabilities = data.get('vulnerabilities', {})
                    self.resolved_credentials = data.get('credentials', {})
            
            self.logger.info("Intelligence data loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Error loading intelligence data: {e}")
    
    def save_intelligence_data(self):
        """Save intelligence data to files"""
        try:
            # Save network profiles
            with open(self.network_profiles_file, 'w') as f:
                json.dump(self.network_profiles, f, indent=2, default=str)
            
            # Save active findings
            active_data = {
                'vulnerabilities': self.active_vulnerabilities,
                'credentials': self.active_credentials,
                'last_updated': datetime.now().isoformat()
            }
            with open(self.active_findings_file, 'w') as f:
                json.dump(active_data, f, indent=2, default=str)
            
            # Save resolved findings
            resolved_data = {
                'vulnerabilities': self.resolved_vulnerabilities,
                'credentials': self.resolved_credentials,
                'last_updated': datetime.now().isoformat()
            }
            with open(self.resolved_findings_file, 'w') as f:
                json.dump(resolved_data, f, indent=2, default=str)
            
            self.logger.debug("Intelligence data saved successfully")
            
        except Exception as e:
            self.logger.error(f"Error saving intelligence data: {e}")
    
    def get_current_network_id(self) -> Optional[str]:
        """Get current network identifier"""
        try:
            # Try to get SSID from WiFi manager
            if (hasattr(self.shared_data, 'ragnar_instance') and 
                hasattr(self.shared_data.ragnar_instance, 'wifi_manager')):
                
                wifi_mgr = self.shared_data.ragnar_instance.wifi_manager
                if hasattr(wifi_mgr, 'current_ssid') and wifi_mgr.current_ssid:
                    return self.create_network_id(wifi_mgr.current_ssid)
                
                # Fallback to get_current_ssid method
                if hasattr(wifi_mgr, 'get_current_ssid'):
                    ssid = wifi_mgr.get_current_ssid()
                    if ssid:
                        return self.create_network_id(ssid)
            
            # If no WiFi manager or SSID, return default network
            return "default_network"
            
        except Exception as e:
            self.logger.error(f"Error getting current network ID: {e}")
            return "default_network"
    
    def create_network_id(self, ssid: str) -> str:
        """Create a stable network identifier from SSID"""
        # Create a hash-based ID that's stable but doesn't expose the actual SSID
        network_hash = hashlib.md5(ssid.encode()).hexdigest()[:8]
        return f"net_{network_hash}"
    
    def update_network_context(self):
        """Update current network context and handle network changes"""
        try:
            new_network = self.get_current_network_id()
            
            # Check for network change
            if new_network != self.current_network:
                self.logger.info(f"Network change detected: {self.current_network} -> {new_network}")
                
                # Handle network change
                self.handle_network_change(self.current_network, new_network)
                
                # Update network context
                self.previous_network = self.current_network
                self.current_network = new_network
                self.network_change_time = datetime.now()
                
                # Update network profile if we have a valid network
                if new_network:
                    self.update_network_profile(new_network)
                
        except Exception as e:
            self.logger.error(f"Error updating network context: {e}")
    
    def handle_network_change(self, old_network: Optional[str], new_network: Optional[str]):
        """Handle network change by managing finding states"""
        try:
            if old_network and new_network and old_network != new_network:
                # Mark findings from old network as potentially resolved
                self.schedule_resolution_check(old_network)
                
                # Log network transition
                self.logger.info(f"Scheduled resolution check for network: {old_network}")
            
            # Initialize new network if needed
            if new_network:
                if new_network not in self.active_vulnerabilities:
                    self.active_vulnerabilities[new_network] = {}
                if new_network not in self.active_credentials:
                    self.active_credentials[new_network] = {}
                
        except Exception as e:
            self.logger.error(f"Error handling network change: {e}")
    
    def schedule_resolution_check(self, network_id: str):
        """Schedule findings for resolution check"""
        try:
            # Move active findings to pending resolution
            if network_id in self.active_vulnerabilities:
                for vuln_id, vuln_data in self.active_vulnerabilities[network_id].items():
                    vuln_data['pending_resolution'] = True
                    vuln_data['resolution_scheduled'] = datetime.now().isoformat()
            
            if network_id in self.active_credentials:
                for cred_id, cred_data in self.active_credentials[network_id].items():
                    cred_data['pending_resolution'] = True
                    cred_data['resolution_scheduled'] = datetime.now().isoformat()
            
            self.save_intelligence_data()
            
        except Exception as e:
            self.logger.error(f"Error scheduling resolution check: {e}")
    
    def update_network_profile(self, network_id: str):
        """Update network profile information"""
        try:
            if network_id not in self.network_profiles:
                self.network_profiles[network_id] = {
                    'first_seen': datetime.now().isoformat(),
                    'connection_count': 0,
                    'total_vulnerabilities': 0,
                    'total_credentials': 0,
                    'active_vulnerabilities': 0,
                    'active_credentials': 0
                }
            
            profile = self.network_profiles[network_id]
            profile['last_seen'] = datetime.now().isoformat()
            profile['connection_count'] += 1
            
            # Update counts
            profile['active_vulnerabilities'] = len(self.active_vulnerabilities.get(network_id, {}))
            profile['active_credentials'] = len(self.active_credentials.get(network_id, {}))
            
            self.save_intelligence_data()
            
        except Exception as e:
            self.logger.error(f"Error updating network profile: {e}")
    
    def add_vulnerability(self, host: str, port: int, service: str, vulnerability: str, 
                         severity: str = "medium", details: Optional[Dict] = None) -> Optional[str]:
        """Add a new vulnerability finding"""
        try:
            network_id = self.get_current_network_id()
            if not network_id:
                self.logger.error("No network ID available for vulnerability")
                return None
            
            # Create vulnerability ID
            vuln_hash = hashlib.md5(f"{host}:{port}:{service}:{vulnerability}".encode()).hexdigest()[:12]
            vuln_id = f"vuln_{vuln_hash}"
            
            # Create vulnerability data
            vuln_data = {
                'id': vuln_id,
                'host': host,
                'port': port,
                'service': service,
                'vulnerability': vulnerability,
                'severity': severity,
                'details': details or {},
                'discovered': datetime.now().isoformat(),
                'network_id': network_id,
                'status': 'active',
                'confirmation_count': 1,
                'last_confirmed': datetime.now().isoformat()
            }
            
            # Add to active vulnerabilities
            if network_id not in self.active_vulnerabilities:
                self.active_vulnerabilities[network_id] = {}
            
            self.active_vulnerabilities[network_id][vuln_id] = vuln_data
            
            # Update network profile
            self.update_network_profile(network_id)
            
            # Save data
            self.save_intelligence_data()
            
            self.logger.info(f"Added vulnerability: {vuln_id} on network {network_id}")
            return vuln_id
            
        except Exception as e:
            self.logger.error(f"Error adding vulnerability: {e}")
            return None
    
    def add_credential(self, host: str, service: str, username: str, password: str,
                      protocol: str = "unknown", details: Optional[Dict] = None) -> Optional[str]:
        """Add a new credential finding"""
        try:
            network_id = self.get_current_network_id()
            if not network_id:
                self.logger.error("No network ID available for credential")
                return None
            
            # Create credential ID
            cred_hash = hashlib.md5(f"{host}:{service}:{username}:{password}".encode()).hexdigest()[:12]
            cred_id = f"cred_{cred_hash}"
            
            # Create credential data
            cred_data = {
                'id': cred_id,
                'host': host,
                'service': service,
                'username': username,
                'password': password,
                'protocol': protocol,
                'details': details or {},
                'discovered': datetime.now().isoformat(),
                'network_id': network_id,
                'status': 'active',
                'confirmation_count': 1,
                'last_confirmed': datetime.now().isoformat()
            }
            
            # Add to active credentials
            if network_id not in self.active_credentials:
                self.active_credentials[network_id] = {}
            
            self.active_credentials[network_id][cred_id] = cred_data
            
            # Update network profile
            self.update_network_profile(network_id)
            
            # Save data
            self.save_intelligence_data()
            
            self.logger.info(f"Added credential: {cred_id} on network {network_id}")
            return cred_id
            
        except Exception as e:
            self.logger.error(f"Error adding credential: {e}")
            return None
    
    def confirm_finding(self, finding_id: str, finding_type: str = "auto"):
        """Confirm an existing finding (vulnerability or credential)"""
        try:
            network_id = self.get_current_network_id()
            confirmed = False
            
            # Check vulnerabilities
            if network_id in self.active_vulnerabilities:
                if finding_id in self.active_vulnerabilities[network_id]:
                    vuln_data = self.active_vulnerabilities[network_id][finding_id]
                    vuln_data['confirmation_count'] += 1
                    vuln_data['last_confirmed'] = datetime.now().isoformat()
                    vuln_data['pending_resolution'] = False
                    confirmed = True
            
            # Check credentials
            if network_id in self.active_credentials and not confirmed:
                if finding_id in self.active_credentials[network_id]:
                    cred_data = self.active_credentials[network_id][finding_id]
                    cred_data['confirmation_count'] += 1
                    cred_data['last_confirmed'] = datetime.now().isoformat()
                    cred_data['pending_resolution'] = False
                    confirmed = True
            
            if confirmed:
                self.save_intelligence_data()
                self.logger.debug(f"Confirmed finding: {finding_id}")
            else:
                self.logger.warning(f"Finding not found for confirmation: {finding_id}")
                
        except Exception as e:
            self.logger.error(f"Error confirming finding: {e}")
    
    def resolve_finding(self, finding_id: str, reason: str = "no_longer_detected"):
        """Mark a finding as resolved"""
        try:
            network_id = self.get_current_network_id()
            if not network_id:
                self.logger.error("No network ID available for resolution")
                return
                
            resolved = False
            
            # Check and move vulnerability
            if network_id in self.active_vulnerabilities:
                if finding_id in self.active_vulnerabilities[network_id]:
                    vuln_data = self.active_vulnerabilities[network_id].pop(finding_id)
                    vuln_data['status'] = 'resolved'
                    vuln_data['resolved'] = datetime.now().isoformat()
                    vuln_data['resolution_reason'] = reason
                    
                    if network_id not in self.resolved_vulnerabilities:
                        self.resolved_vulnerabilities[network_id] = {}
                    self.resolved_vulnerabilities[network_id][finding_id] = vuln_data
                    resolved = True
            
            # Check and move credential
            if network_id in self.active_credentials and not resolved:
                if finding_id in self.active_credentials[network_id]:
                    cred_data = self.active_credentials[network_id].pop(finding_id)
                    cred_data['status'] = 'resolved'
                    cred_data['resolved'] = datetime.now().isoformat()
                    cred_data['resolution_reason'] = reason
                    
                    if network_id not in self.resolved_credentials:
                        self.resolved_credentials[network_id] = {}
                    self.resolved_credentials[network_id][finding_id] = cred_data
                    resolved = True
            
            if resolved:
                self.update_network_profile(network_id)
                self.save_intelligence_data()
                self.logger.info(f"Resolved finding: {finding_id} - {reason}")
            else:
                self.logger.warning(f"Finding not found for resolution: {finding_id}")
                
        except Exception as e:
            self.logger.error(f"Error resolving finding: {e}")
    
    def get_active_findings_for_dashboard(self) -> Dict:
        """Get active findings for current network (dashboard view)
        
        Checks both the current network ID and 'default_network' as fallback
        to ensure vulnerabilities are displayed even when network ID changes.
        """
        try:
            network_id = self.get_current_network_id()
            
            # Get findings from current network
            vulnerabilities = dict(self.active_vulnerabilities.get(network_id, {}))
            credentials = dict(self.active_credentials.get(network_id, {}))
            
            # If current network has no findings, check default_network as fallback
            if not vulnerabilities and not credentials and network_id != "default_network":
                default_vulns = self.active_vulnerabilities.get("default_network", {})
                default_creds = self.active_credentials.get("default_network", {})
                
                if default_vulns or default_creds:
                    self.logger.info(f"Using default_network findings as fallback (current network: {network_id})")
                    vulnerabilities.update(default_vulns)
                    credentials.update(default_creds)
            
            result = {
                'network_id': network_id,
                'vulnerabilities': vulnerabilities,
                'credentials': credentials,
                'counts': {
                    'vulnerabilities': len(vulnerabilities),
                    'credentials': len(credentials)
                }
            }
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error getting active findings: {e}")
            return {'network_id': 'unknown', 'vulnerabilities': {}, 'credentials': {}, 'counts': {'vulnerabilities': 0, 'credentials': 0}}

    def get_vulnerabilities_for_network(self, status_filter: str = "open") -> Dict:
        """Return vulnerabilities for current network filtered by status.

        status_filter: "open" (default), "resolved", or "all".
        """
        network_id = self.get_current_network_id()
        open_vulns = dict(self.active_vulnerabilities.get(network_id, {}))
        resolved_vulns = dict(self.resolved_vulnerabilities.get(network_id, {}))

        if status_filter == "resolved":
            return resolved_vulns
        if status_filter == "all":
            combined = {}
            combined.update(resolved_vulns)
            combined.update(open_vulns)
            return combined
        # default: open
        return open_vulns

    def resolve_host_findings(self, host: str, reason: str = "host_offline"):
        """Resolve all active findings for a given host across networks."""
        try:
            resolved_any = False
            for network_id, vulns in list(self.active_vulnerabilities.items()):
                for vuln_id, vuln_data in list(vulns.items()):
                    if vuln_data.get('host') == host:
                        self.active_vulnerabilities[network_id].pop(vuln_id, None)
                        vuln_data['status'] = 'resolved'
                        vuln_data['resolved'] = datetime.now().isoformat()
                        vuln_data['resolution_reason'] = reason
                        if network_id not in self.resolved_vulnerabilities:
                            self.resolved_vulnerabilities[network_id] = {}
                        self.resolved_vulnerabilities[network_id][vuln_id] = vuln_data
                        resolved_any = True

            for network_id, creds in list(self.active_credentials.items()):
                for cred_id, cred_data in list(creds.items()):
                    if cred_data.get('host') == host:
                        self.active_credentials[network_id].pop(cred_id, None)
                        cred_data['status'] = 'resolved'
                        cred_data['resolved'] = datetime.now().isoformat()
                        cred_data['resolution_reason'] = reason
                        if network_id not in self.resolved_credentials:
                            self.resolved_credentials[network_id] = {}
                        self.resolved_credentials[network_id][cred_id] = cred_data
                        resolved_any = True

            if resolved_any:
                self.save_intelligence_data()
                self.logger.info(f"Resolved findings for host {host} due to {reason}")
        except Exception as e:
            self.logger.error(f"Error resolving findings for host {host}: {e}")
    
    def get_all_findings_for_netkb(self) -> Dict:
        """Get all findings (active + resolved) for NetKB view"""
        try:
            all_vulnerabilities = {}
            all_credentials = {}
            
            # Combine active vulnerabilities
            for network_id, vulns in self.active_vulnerabilities.items():
                all_vulnerabilities.update(vulns)
            
            # Combine resolved vulnerabilities
            for network_id, vulns in self.resolved_vulnerabilities.items():
                all_vulnerabilities.update(vulns)
            
            # Combine active credentials
            for network_id, creds in self.active_credentials.items():
                all_credentials.update(creds)
            
            # Combine resolved credentials
            for network_id, creds in self.resolved_credentials.items():
                all_credentials.update(creds)
            
            result = {
                'vulnerabilities': all_vulnerabilities,
                'credentials': all_credentials,
                'counts': {
                    'total_vulnerabilities': len(all_vulnerabilities),
                    'total_credentials': len(all_credentials),
                    'active_vulnerabilities': sum(len(vulns) for vulns in self.active_vulnerabilities.values()),
                    'active_credentials': sum(len(creds) for creds in self.active_credentials.values()),
                    'resolved_vulnerabilities': sum(len(vulns) for vulns in self.resolved_vulnerabilities.values()),
                    'resolved_credentials': sum(len(creds) for creds in self.resolved_credentials.values())
                }
            }
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error getting all findings: {e}")
            return {'vulnerabilities': {}, 'credentials': {}, 'counts': {}}
    
    def run_resolution_check(self):
        """Check for findings that should be resolved due to timeout"""
        try:
            current_time = datetime.now()
            resolved_count = 0
            
            # Check all networks for pending resolution
            for network_id in list(self.active_vulnerabilities.keys()):
                for vuln_id, vuln_data in list(self.active_vulnerabilities[network_id].items()):
                    if vuln_data.get('pending_resolution'):
                        scheduled_time = datetime.fromisoformat(vuln_data.get('resolution_scheduled', current_time.isoformat()))
                        if (current_time - scheduled_time).total_seconds() > self.resolution_timeout:
                            self.resolve_finding(vuln_id, "timeout_no_confirmation")
                            resolved_count += 1
            
            for network_id in list(self.active_credentials.keys()):
                for cred_id, cred_data in list(self.active_credentials[network_id].items()):
                    if cred_data.get('pending_resolution'):
                        scheduled_time = datetime.fromisoformat(cred_data.get('resolution_scheduled', current_time.isoformat()))
                        if (current_time - scheduled_time).total_seconds() > self.resolution_timeout:
                            self.resolve_finding(cred_id, "timeout_no_confirmation")
                            resolved_count += 1
            
            if resolved_count > 0:
                self.logger.info(f"Resolved {resolved_count} findings due to timeout")
                
        except Exception as e:
            self.logger.error(f"Error running resolution check: {e}")
    
    def get_network_summary(self) -> Dict:
        """Get summary of all network intelligence"""
        try:
            current_network = self.get_current_network_id()
            
            summary = {
                'current_network': current_network,
                'total_networks': len(self.network_profiles),
                'network_profiles': self.network_profiles,
                'current_network_active': {
                    'vulnerabilities': len(self.active_vulnerabilities.get(current_network, {})),
                    'credentials': len(self.active_credentials.get(current_network, {}))
                },
                'global_totals': {
                    'active_vulnerabilities': sum(len(vulns) for vulns in self.active_vulnerabilities.values()),
                    'active_credentials': sum(len(creds) for creds in self.active_credentials.values()),
                    'resolved_vulnerabilities': sum(len(vulns) for vulns in self.resolved_vulnerabilities.values()),
                    'resolved_credentials': sum(len(creds) for creds in self.resolved_credentials.values())
                }
            }
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error getting network summary: {e}")
            return {}