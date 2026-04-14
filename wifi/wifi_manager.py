#!/usr/bin/env python3
"""
RaspyJack WiFi Management System
===============================
Dual-interface support for RaspyJack - use both eth0 and WiFi dongles

Features:
- WiFi profile management (save/load network credentials)
- Network scanning and connection
- Interface priority and selection
- Integration with RaspyJack LCD interface
- Automatic reconnection and failover

Author: RaspyJack WiFi Integration
"""

import os
import sys
import json
import subprocess
import time
import threading
from datetime import datetime
from pathlib import Path

# Try to import RaspyJack LCD modules
try:
    sys.path.append('/root/Raspyjack/')
    import LCD_1in44, LCD_Config
    from PIL import Image, ImageDraw, ImageFont
    import RPi.GPIO as GPIO
    LCD_AVAILABLE = True
except Exception:
    LCD_AVAILABLE = False

class WiFiManager:
    def __init__(self):
        self.base_dir = "/root/Raspyjack/wifi"
        self.profiles_dir = f"{self.base_dir}/profiles"
        self.current_profile_file = f"{self.base_dir}/current_profile.json"
        self.log_file = f"{self.base_dir}/wifi.log"
        
        # Create directories
        os.makedirs(self.profiles_dir, exist_ok=True)
        
        # Available WiFi interfaces
        self.wifi_interfaces = self.detect_wifi_interfaces()

        # User-selected interface (persists during session)
        self.selected_interface = None

        # Current status
        self.current_interface = None
        self.current_profile = None
        self.connection_status = "disconnected"
        
    def log(self, message):
        """Log messages with timestamp."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"[{timestamp}] {message}"
        print(log_msg)
        
        try:
            with open(self.log_file, 'a') as f:
                f.write(log_msg + "\n")
        except Exception:
            pass
    
    def detect_wifi_interfaces(self):
        """Detect all available WiFi interfaces."""
        interfaces = []
        
        try:
            # Method 1: Check /sys/class/net for wireless directories (most reliable)
            for iface in os.listdir("/sys/class/net"):
                wireless_path = f"/sys/class/net/{iface}/wireless"
                if os.path.exists(wireless_path):
                    interfaces.append(iface)
                    self.log(f"Found wireless interface via /sys: {iface}")
            
            # Method 2: iwconfig as backup
            if not interfaces:
                result = subprocess.run(['iwconfig'], capture_output=True, text=True, stderr=subprocess.DEVNULL)
                for line in result.stdout.split('\n'):
                    if 'IEEE 802.11' in line:
                        interface = line.split()[0]
                        if interface not in interfaces:
                            interfaces.append(interface)
                            self.log(f"Found wireless interface via iwconfig: {interface}")
                        
        except Exception as e:
            self.log(f"Error detecting WiFi interfaces: {e}")
        
        # Sort interfaces (prefer wlan0 built-in for connectivity, wlan1+ for attacks)
        interfaces.sort(key=lambda x: (x != 'wlan0', x != 'wlan1', x))
        
        self.log(f"Final detected WiFi interfaces: {interfaces}")
        return interfaces
    
    def scan_networks(self, interface=None):
        """Scan for available WiFi networks using nmcli (same tool as connect)."""
        if not interface:
            interface = self.get_active_interface()

        if not interface:
            self.log("No WiFi interface available for scanning")
            return []

        try:
            self.log(f"Scanning networks on {interface}...")

            # Trigger a fresh scan on the interface
            subprocess.run(['nmcli', 'device', 'wifi', 'rescan', 'ifname', interface],
                         capture_output=True, check=False, timeout=15)
            time.sleep(2)  # give nmcli time to populate results

            # List networks using nmcli (ensures they are in nmcli's cache for connect)
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'BSSID,SSID,SIGNAL,SECURITY', 'device', 'wifi', 'list',
                 'ifname', interface],
                capture_output=True, text=True, check=False, timeout=15,
            )

            networks = []
            seen_ssids = set()

            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                # nmcli -t uses ':' as separator; BSSID contains '\:'
                # Replace escaped colons in BSSID first
                parts = line.replace('\\:', '#').split(':')
                if len(parts) < 4:
                    continue
                bssid = parts[0].replace('#', ':')
                ssid = parts[1].replace('#', ':')
                try:
                    signal = int(parts[2])
                except ValueError:
                    signal = 0
                security = parts[3].replace('#', ':') if len(parts) > 3 else ""

                if not ssid or ssid in seen_ssids:
                    continue
                seen_ssids.add(ssid)

                encrypted = bool(security and security != "" and security != "--")
                quality = f"{signal}/100"

                networks.append({
                    'bssid': bssid,
                    'ssid': ssid,
                    'quality': quality,
                    'signal': signal,
                    'encrypted': encrypted,
                    'security': security,
                })

            # Sort by signal strength (strongest first)
            networks.sort(key=lambda n: n.get('signal', 0), reverse=True)

            self.log(f"Found {len(networks)} unique networks")
            return networks

        except Exception as e:
            self.log(f"Error scanning networks: {e}")
            return []
    
    def save_profile(self, ssid, password, interface="auto", priority=1, auto_connect=True):
        """Save a WiFi profile."""
        profile = {
            "ssid": ssid,
            "password": password,
            "interface": interface,
            "priority": priority,
            "auto_connect": auto_connect,
            "created": datetime.now().isoformat(),
            "last_used": None
        }
        
        # Safe filename
        safe_name = "".join(c for c in ssid if c.isalnum() or c in (' ', '-', '_')).rstrip()
        profile_file = f"{self.profiles_dir}/{safe_name}.json"
        
        try:
            with open(profile_file, 'w') as f:
                json.dump(profile, f, indent=2)
            
            self.log(f"Saved WiFi profile: {ssid}")
            return True
        except Exception as e:
            self.log(f"Error saving profile: {e}")
            return False
    
    def load_profiles(self):
        """Load all WiFi profiles."""
        profiles = []
        
        try:
            for filename in os.listdir(self.profiles_dir):
                if filename.endswith('.json'):
                    with open(f"{self.profiles_dir}/{filename}", 'r') as f:
                        profile = json.load(f)
                        profile['filename'] = filename
                        profiles.append(profile)
            
            # Sort by priority (higher first)
            profiles.sort(key=lambda x: x.get('priority', 1), reverse=True)
            
        except Exception as e:
            self.log(f"Error loading profiles: {e}")
        
        return profiles
    
    def delete_profile(self, ssid):
        """Delete a WiFi profile."""
        safe_name = "".join(c for c in ssid if c.isalnum() or c in (' ', '-', '_')).rstrip()
        profile_file = f"{self.profiles_dir}/{safe_name}.json"
        
        try:
            if os.path.exists(profile_file):
                os.remove(profile_file)
                self.log(f"Deleted WiFi profile: {ssid}")
                return True
        except Exception as e:
            self.log(f"Error deleting profile: {e}")
        
        return False
    
    def connect_to_network(self, ssid, password=None, interface=None):
        """Connect to a WiFi network."""
        if not interface:
            interface = self.get_active_interface()

        if not interface:
            self.log("No WiFi interface available")
            return False

        self.log(f"Connecting to {ssid} on {interface}...")

        try:
            # Check if already connected to this SSID
            status = self.get_connection_status(interface)
            if status["status"] == "connected" and status.get("ssid") == ssid:
                self.log(f"Already connected to {ssid}")
                return True

            # Ensure nmcli has the network in its cache
            subprocess.run(['nmcli', 'device', 'wifi', 'rescan', 'ifname', interface],
                         capture_output=True, check=False, timeout=10)
            time.sleep(1)

            # Build connect command - nmcli handles disconnect/reconnect internally
            if password:
                cmd = ['nmcli', 'device', 'wifi', 'connect', ssid,
                       'password', password, 'ifname', interface]
            else:
                cmd = ['nmcli', 'device', 'wifi', 'connect', ssid,
                       'ifname', interface]

            self.log(f"Running: nmcli device wifi connect {ssid} ifname {interface}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)

            if result.returncode == 0:
                self.log(f"Successfully connected to {ssid}")
                self.current_interface = interface
                self.current_profile = ssid
                self.connection_status = "connected"

                self.update_profile_last_used(ssid)
                self.save_current_connection(ssid, interface)
                return True
            else:
                err = result.stderr.strip() or result.stdout.strip()
                self.log(f"Failed to connect to {ssid}: {err}")

                # If key-mgmt missing, the network needs a password but none given
                if "key-mgmt" in err and not password:
                    self.log(f"Network {ssid} requires a password")

                return False

        except subprocess.TimeoutExpired:
            self.log(f"Connection to {ssid} timed out")
            return False
        except Exception as e:
            self.log(f"Error connecting to {ssid}: {e}")
            return False
    
    def connect_to_profile(self, profile):
        """Connect using a saved profile."""
        interface = profile.get('interface', 'auto')
        if interface == 'auto':
            interface = self.get_active_interface()
        
        return self.connect_to_network(
            profile['ssid'], 
            profile['password'], 
            interface
        )
    
    def disconnect(self, interface=None):
        """Disconnect from WiFi."""
        if not interface:
            interface = self.current_interface or self.get_active_interface()
        
        if not interface:
            return False
        
        try:
            subprocess.run(['nmcli', 'device', 'disconnect', interface], 
                         capture_output=True, check=True)
            
            self.log(f"Disconnected from WiFi on {interface}")
            self.current_interface = None
            self.current_profile = None
            self.connection_status = "disconnected"
            
            return True
        except Exception as e:
            self.log(f"Error disconnecting: {e}")
            return False
    
    def get_connection_status(self, interface=None):
        """Get current WiFi connection status."""
        if not interface:
            interface = self.current_interface or self.get_active_interface()
        
        if not interface:
            return {"status": "no_interface", "ssid": None, "ip": None}
        
        try:
            # Check connection status
            result = subprocess.run(['nmcli', '-t', '-f', 'ACTIVE,SSID', 'dev', 'wifi'], 
                                  capture_output=True, text=True, check=False)
            
            connected_ssid = None
            for line in result.stdout.split('\n'):
                if line.startswith('yes:'):
                    connected_ssid = line.split(':', 1)[1]
                    break
            
            if connected_ssid:
                # Get IP address
                ip_result = subprocess.run(['ip', '-4', 'addr', 'show', interface], 
                                         capture_output=True, text=True, check=False)
                
                ip_addr = None
                for line in ip_result.stdout.split('\n'):
                    if 'inet ' in line:
                        ip_addr = line.split('inet ')[1].split('/')[0]
                        break
                
                return {
                    "status": "connected",
                    "ssid": connected_ssid,
                    "ip": ip_addr,
                    "interface": interface
                }
            else:
                return {"status": "disconnected", "ssid": None, "ip": None}
                
        except Exception as e:
            self.log(f"Error getting connection status: {e}")
            return {"status": "error", "ssid": None, "ip": None}
    
    def auto_connect(self):
        """Auto-connect to the best available saved network."""
        profiles = self.load_profiles()
        auto_profiles = [p for p in profiles if p.get('auto_connect', True)]
        
        if not auto_profiles:
            self.log("No auto-connect profiles found")
            return False
        
        # Scan for available networks
        available_networks = self.scan_networks()
        available_ssids = [n.get('ssid') for n in available_networks if 'ssid' in n]
        
        # Try to connect to highest priority available network
        for profile in auto_profiles:
            if profile['ssid'] in available_ssids:
                self.log(f"Auto-connecting to {profile['ssid']}")
                if self.connect_to_profile(profile):
                    return True
        
        self.log("No saved networks available for auto-connect")
        return False
    
    def update_profile_last_used(self, ssid):
        """Update the last_used timestamp for a profile."""
        safe_name = "".join(c for c in ssid if c.isalnum() or c in (' ', '-', '_')).rstrip()
        profile_file = f"{self.profiles_dir}/{safe_name}.json"
        
        try:
            if os.path.exists(profile_file):
                with open(profile_file, 'r') as f:
                    profile = json.load(f)
                
                profile['last_used'] = datetime.now().isoformat()
                
                with open(profile_file, 'w') as f:
                    json.dump(profile, f, indent=2)
        except Exception as e:
            self.log(f"Error updating profile: {e}")
    
    def save_current_connection(self, ssid, interface):
        """Save current connection info."""
        current = {
            "ssid": ssid,
            "interface": interface,
            "connected_at": datetime.now().isoformat()
        }
        
        try:
            with open(self.current_profile_file, 'w') as f:
                json.dump(current, f, indent=2)
        except Exception as e:
            self.log(f"Error saving current connection: {e}")
    
    def set_selected_interface(self, iface):
        """Set the user-selected WiFi interface for scan/connect."""
        self.selected_interface = iface
        self.log(f"Active interface set to: {iface}")

    def get_active_interface(self):
        """Return the user-selected interface, or first available."""
        if self.selected_interface and self.selected_interface in self.wifi_interfaces:
            return self.selected_interface
        return self.wifi_interfaces[0] if self.wifi_interfaces else None

    def get_interface_for_tool(self, preferred="auto"):
        """Get the best interface for network tools."""
        if preferred == "auto":
            # Use user-selected interface if set
            if self.selected_interface:
                return self.selected_interface
            # Check current WiFi connection first
            status = self.get_connection_status()
            if status["status"] == "connected":
                return status["interface"]

            # Fall back to ethernet
            return "eth0"
        
        return preferred

# Global WiFi manager instance
wifi_manager = WiFiManager()

def get_available_interfaces():
    """Get list of available network interfaces for RaspyJack tools."""
    interfaces = ["eth0"]  # Always include ethernet
    interfaces.extend(wifi_manager.wifi_interfaces)
    return interfaces

def get_current_interface():
    """Get the currently active interface for tools."""
    return wifi_manager.get_interface_for_tool() 