#!/usr/bin/env python3
"""
RaspyJack Wardriving Payload
===========================
Comprehensive WiFi network discovery and mapping tool

Features:
- Passive WiFi network scanning
- GPS coordinate logging
- Real-time LCD interface
- Multiple export formats (JSON, CSV, KML)
- Security protocol detection
- Channel hopping
- Database storage
- Integration with RaspyJack WiFi manager

Author: dag nazty
"""

import os
import sys
import json
import time
import sqlite3
import threading
import subprocess
import logging
import csv
import socket
from datetime import datetime
from pathlib import Path

# Add RaspyJack modules to path
sys.path.append('/root/Raspyjack/wifi/')
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))  # Add root directory like working examples

try:
    import LCD_1in44, LCD_Config
    from PIL import Image, ImageDraw, ImageFont
    import RPi.GPIO as GPIO
    from payloads._input_helper import get_virtual_button
    LCD_AVAILABLE = True
except ImportError:
    LCD_AVAILABLE = False
    print("LCD modules not available - running in console mode")

try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy not available - install with: pip3 install scapy")

try:
    import gpsd
    GPS_AVAILABLE = True
except ImportError:
    GPS_AVAILABLE = False
    print("GPS not available - install with: pip3 install gpsd-py3")

# Try to import WiFi manager (optional - don't require internet)
try:
    from wifi_manager import WiFiManager
    WIFI_MANAGER_AVAILABLE = True
except ImportError:
    WIFI_MANAGER_AVAILABLE = False
    print("WiFi manager not available - continuing without WiFi management")

class WardrivingScanner:
    def __init__(self):
        self.base_dir = "/root/Raspyjack"
        self.loot_dir = f"{self.base_dir}/loot/wardriving"
        self.db_path = f"{self.loot_dir}/networks.db"
        
        # Create directories
        os.makedirs(self.loot_dir, exist_ok=True)
        
        # Setup logging - replace log file each run
        self.log_file = os.path.join(self.loot_dir, "wardriving.log")
        
        # Exit confirmation tracking
        self.exit_press_count = 0
        self.last_exit_press = 0
        
        # Thread control
        self.lcd_running = True
        
        # Simple logging setup - create/replace log file immediately
        try:
            with open(self.log_file, 'w') as f:
                f.write(f"=== WARDRIVING LOG STARTED {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")
                f.write(f"Log file: {self.log_file}\n")
                f.write(f"LCD Available: {LCD_AVAILABLE}\n")
                f.write(f"Scapy Available: {SCAPY_AVAILABLE}\n")
                f.write(f"GPS Available: {GPS_AVAILABLE}\n")
                f.write(f"WiFi Manager Available: {WIFI_MANAGER_AVAILABLE}\n")
                f.flush()
            print(f"Log file created: {self.log_file}")
        except Exception as e:
            print(f"Failed to create log file: {e}")
        
        # Scanner state
        self.running = False
        self.interface = None
        self.monitor_interface = None
        self.networks = {}
        self.total_networks = 0
        self.current_channel = 1
        self.gps_data = None
        
        # Threading
        self.scan_thread = None
        self.channel_thread = None
        self.gps_thread = None
        
        # LCD and GPIO setup
        if LCD_AVAILABLE:
            self.setup_lcd()
            self.setup_gpio()
            # Test LCD immediately
            self.test_lcd()
        
        # Database setup
        self.setup_database()
        
        # GPS setup
        if GPS_AVAILABLE:
            self.setup_gps()
        
        # WiFi manager (after all other setup)
        self.wifi_manager_available = WIFI_MANAGER_AVAILABLE
        if self.wifi_manager_available:
            try:
                self.wifi_manager = WiFiManager()
                self.log("WiFi manager loaded successfully")
            except Exception as e:
                self.log(f"WiFi manager failed to load: {e}")
                self.wifi_manager_available = False
        else:
            self.log("WiFi manager not available - continuing without WiFi management")
        
        self.log("Wardriving scanner initialized successfully")
        print("Wardriving scanner initialized")
    
    def log(self, message):
        """Log message to file with timestamp - only important events"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_msg = f"[{timestamp}] {message}"
        
        # Always write to file
        try:
            with open(self.log_file, 'a') as f:
                f.write(log_msg + '\n')
                f.flush()
        except Exception as e:
            print(f"Failed to write to log: {e}")
            
        # Only print important messages to console (not LCD spam)
        if any(keyword in message.lower() for keyword in ['error', 'failed', 'success', 'started', 'completed', 'fix', 'network:', 'gps fix']):
            print(log_msg)
    
    def setup_lcd(self):
        """Initialize LCD display - EXACT same as example_show_buttons.py"""
        try:
            self.log("Starting LCD initialization...")
            
            # EXACT same initialization as example_show_buttons.py
            self.LCD = LCD_1in44.LCD()
            self.log("LCD object created")
            
            self.LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
            self.log("LCD initialized with default scan direction")
            
            # CRITICAL: Clear the LCD first (like working examples do)
            self.LCD.LCD_Clear()
            self.log("LCD cleared - this should fix white screen issue")
            
            self.WIDTH, self.HEIGHT = 128, 128
            self.log(f"LCD dimensions set: {self.WIDTH}x{self.HEIGHT}")
            
            self.font = ImageFont.load_default()
            self.log("Default font loaded")
            
            self.lcd_ready = True
            self.log("LCD setup completed successfully")
            print("LCD initialized successfully")
            
        except Exception as e:
            self.log(f"LCD initialization FAILED: {e}")
            print(f"LCD initialization failed: {e}")
            self.lcd_ready = False
    
    def draw(self, text):
        """EXACT copy of example_show_buttons.py draw() function with LCD clear"""
        if not self.lcd_ready:
            return
        try:
            self.log(f"Drawing text to LCD: '{text}'")
            
            # EXACT COPY of example_show_buttons.py draw() function
            img = Image.new("RGB", (self.WIDTH, self.HEIGHT), "black")
            d = ImageDraw.Draw(img)

            # Measure text size (Pillow ≥ 9.2 offers textbbox())
            if hasattr(d, "textbbox"):
                x0, y0, x1, y1 = d.textbbox((0, 0), text, font=self.font)
                w, h = x1 - x0, y1 - y0
            else:  # Pillow < 9.2 fallback
                w, h = d.textsize(text, font=self.font)

            # Centre coordinates
            pos = ((self.WIDTH - w) // 2, (self.HEIGHT - h) // 2)

            # Draw the text and push the image to the LCD
            d.text(pos, text, font=self.font, fill="#00FF00")
            self.LCD.LCD_ShowImage(img, 0, 0)
            self.log("LCD draw completed successfully")
            
        except Exception as e:
            self.log(f"LCD draw ERROR: {e}")
            print(f"LCD draw error: {e}")
            import traceback
            self.log(f"LCD draw traceback: {traceback.format_exc()}")
    
    def test_lcd(self):
        """Test LCD with simple message"""
        self.log("Testing LCD with 'Ready!' message")
        self.draw("Ready!")
        self.log("LCD test completed")
    
    def setup_gpio(self):
        """Initialize GPIO for button controls"""
        try:
            self.log("Starting GPIO initialization...")
            GPIO.setmode(GPIO.BCM)
            self.log("GPIO mode set to BCM")
            
            GPIO.setup(21, GPIO.IN, pull_up_down=GPIO.PUD_UP)  # KEY1
            GPIO.setup(20, GPIO.IN, pull_up_down=GPIO.PUD_UP)  # KEY3
            GPIO.setup(16, GPIO.IN, pull_up_down=GPIO.PUD_UP)  # KEY2
            GPIO.setup(6, GPIO.IN, pull_up_down=GPIO.PUD_UP)   # UP
            GPIO.setup(19, GPIO.IN, pull_up_down=GPIO.PUD_UP)  # DOWN
            GPIO.setup(5, GPIO.IN, pull_up_down=GPIO.PUD_UP)   # LEFT
            GPIO.setup(26, GPIO.IN, pull_up_down=GPIO.PUD_UP)  # RIGHT
            GPIO.setup(13, GPIO.IN, pull_up_down=GPIO.PUD_UP)  # PRESS
            self.log("All GPIO pins configured with pull-up resistors")
            
            self.gpio_ready = True
            self.log("GPIO setup completed successfully")
            print("GPIO initialized successfully")
        except Exception as e:
            self.log(f"GPIO initialization FAILED: {e}")
            print(f"GPIO initialization failed: {e}")
            self.gpio_ready = False
    
    def setup_database(self):
        """Initialize SQLite database for storing networks"""
        try:
            self.log(f"Setting up database at: {self.db_path}")
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create networks table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS networks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ssid TEXT,
                    bssid TEXT UNIQUE,
                    channel INTEGER,
                    frequency INTEGER,
                    security_type TEXT,
                    encryption TEXT,
                    cipher TEXT,
                    authentication TEXT,
                    wps_enabled BOOLEAN,
                    signal_strength INTEGER,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    vendor TEXT,
                    country_code TEXT
                )
            ''')
            self.log("Networks table created/verified")
            
            # Create locations table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS locations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    network_id INTEGER,
                    latitude REAL,
                    longitude REAL,
                    altitude REAL,
                    accuracy REAL,
                    timestamp TIMESTAMP,
                    FOREIGN KEY (network_id) REFERENCES networks (id)
                )
            ''')
            self.log("Locations table created/verified")
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_networks_bssid ON networks(bssid)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_networks_ssid ON networks(ssid)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_locations_network_id ON locations(network_id)')
            self.log("Database indexes created/verified")
            
            conn.commit()
            conn.close()
            self.log("Database setup completed successfully")
            print("Database initialized successfully")
        except Exception as e:
            self.log(f"Database initialization FAILED: {e}")
            print(f"Database initialization failed: {e}")
    
    def setup_gps(self):
        """Initialize GPS connection for u-blox 7 GPS module - Enhanced with u-blox optimization"""
        try:
            self.log("Starting GPS setup for u-blox 7...")
            print("Setting up u-blox 7 GPS module...")
            
            # First, detect available GPS devices (u-blox 7 typically uses ACM0)
            gps_devices = []
            try:
                # Check for common GPS device paths (u-blox 7 priority)
                for device in ['/dev/ttyACM1', '/dev/ttyACM0', '/dev/ttyUSB0', '/dev/ttyUSB1']:
                    if os.path.exists(device):
                        gps_devices.append(device)
                
                # Also check USB devices for u-blox
                usb_check = subprocess.run(['lsusb'], capture_output=True, text=True)
                if 'u-blox' in usb_check.stdout.lower():
                    self.log("u-blox GPS device detected via USB")
                    print("✓ u-blox GPS device detected via USB")
                elif 'gps' in usb_check.stdout.lower():
                    self.log("GPS device detected via USB")
                    print("✓ GPS device detected via USB")
                
                self.log(f"Found GPS devices: {gps_devices}")
                print(f"Found GPS devices: {gps_devices}")
                
            except Exception as e:
                self.log(f"GPS device detection failed: {e}")
            
            # Check if gpsd process is running
            gps_check = subprocess.run(['ps', '-ef'], capture_output=True, text=True)
            if 'gpsd' in gps_check.stdout:
                self.log("GPSD daemon already running")
                print("GPSD daemon already running")
                self.gps_ready = True
            else:
                self.log("Starting GPSD daemon for u-blox 7...")
                print("Starting GPSD daemon for u-blox 7...")
                
                # Try to start gpsd with detected device or default to ACM0 for u-blox
                gps_device = gps_devices[0] if gps_devices else '/dev/ttyACM1'
                
                # Kill any existing gpsd processes first
                subprocess.run(['sudo', 'pkill', '-f', 'gpsd'], capture_output=True)
                time.sleep(1)
                
                # Start gpsd with proper options for u-blox 7 real-time data
                cmd = ['sudo', 'gpsd', '-n', '-b', '-D', '2', gps_device]
                self.log(f"Starting gpsd with: {' '.join(cmd)}")
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(3)
                self.gps_ready = True
            
            # Test GPS connection using gpsd-py3 with enhanced retry logic for u-blox
            try:
                self.log("Testing u-blox 7 GPS connection...")
                # Wait a moment for GPS daemon to be ready
                time.sleep(2)
                gpsd.connect()
                self.log("Connected to GPSD")
                
                # Try to get GPS data with enhanced retries for u-blox
                for attempt in range(5):  # Increased retries for u-blox
                    try:
                        self.log(f"GPS connection attempt {attempt + 1}")
                        packet = gpsd.get_current()
                        
                        # Check if GPS is active and has a fix
                        if hasattr(packet, 'mode') and packet.mode >= 2:
                            self.log("GPS packet received successfully")
                            print("✓ u-blox 7 GPS module initialized successfully")
                            
                            self.log(f"GPS fix acquired: {packet.mode}D fix")
                            print(f"GPS fix acquired: {packet.mode}D fix")
                            if hasattr(packet, 'sats'):
                                self.log(f"Satellites: {packet.sats}")
                                print(f"Satellites: {packet.sats}")
                            
                            # Set initial GPS data so LCD shows coordinates immediately
                            self.gps_data = {
                                'latitude': packet.lat,
                                'longitude': packet.lon,
                                'altitude': packet.alt if packet.mode >= 3 else None,
                                'speed': packet.hspeed if hasattr(packet, 'hspeed') else 0,
                                'satellites': packet.sats if hasattr(packet, 'sats') else 0,
                                'timestamp': datetime.now().isoformat()
                            }
                            self.log(f"Initial GPS coordinates: {packet.lat:.4f},{packet.lon:.4f}")
                            print(f"Initial GPS coordinates: {packet.lat:.4f},{packet.lon:.4f}")
                            
                            # START GPS UPDATER THREAD IMMEDIATELY (not just during scan)
                            self.log("Starting GPS updater thread for continuous tracking")
                            self.gps_thread = threading.Thread(target=self.gps_updater)
                            self.gps_thread.daemon = True
                            self.gps_thread.start()
                            print("GPS updater started - coordinates will update continuously")
                            print("u-blox 7 optimized for real-time wardriving!")
                            break
                        else:
                            packet_mode = getattr(packet, 'mode', 'unknown')
                            self.log(f"GPS not ready - mode: {packet_mode}")
                            if attempt < 4:
                                print(f"GPS not ready (mode {packet_mode}), retrying... (attempt {attempt + 1}/5)")
                                time.sleep(3)  # Longer wait between attempts for u-blox
                            else:
                                self.log("GPS connected but no fix after 5 attempts")
                                print("GPS connected but no fix - continuing without GPS")
                                print("Move to area with clear sky view for GPS fix")
                                print("u-blox 7 will still work for scanning when fix is acquired")
                                
                    except Exception as retry_e:
                        self.log(f"GPS attempt {attempt + 1} failed: {retry_e}")
                        if attempt < 4:
                            print(f"GPS connection attempt {attempt + 1} failed, retrying...")
                            time.sleep(3)
                        else:
                            self.log("All GPS attempts failed")
                            print("GPS connection failed - continuing without GPS")
                    
            except Exception as e:
                self.log(f"GPS connection test failed: {e}")
                print(f"GPS connection test failed: {e}")
                print("GPS daemon running but connection failed - GPS will still work for scanning")
                self.gps_ready = True  # Still mark as ready since daemon is running
                
        except Exception as e:
            self.log(f"u-blox 7 GPS initialization FAILED: {e}")
            print(f"u-blox 7 GPS initialization failed: {e}")
            print("Check: lsusb | grep -i u-blox")
            print("Check: ls -la /dev/ttyUSB* /dev/ttyACM*")
            print("Check: sudo systemctl status gpsd")
            self.gps_ready = False
    
    def get_wifi_interfaces(self):
        """Get available WiFi interfaces"""
        try:
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            interfaces = []
            for line in result.stdout.split('\n'):
                if 'IEEE 802.11' in line:
                    interface = line.split()[0]
                    interfaces.append(interface)
            return interfaces
        except:
            return []
    
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
                # An interface is wireless if /sys/class/net/<name>/wireless exists
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

    def setup_monitor_mode(self, interface):
        """Comprehensive monitor mode setup"""
        print(f"Setting up monitor mode on {interface}")
        
        # Step 1: Kill interfering processes (with timeouts so we never hang)
        print("Stopping interfering services...")
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
        print(f"Current interface status: {result.stdout[:200]}")
        
        # Step 3: Try airmon-ng method
        print("Attempting airmon-ng setup...")
        try:
            # Use airmon-ng with verbose output
            cmd = ['sudo', 'airmon-ng', 'start', interface]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            print(f"airmon-ng stdout: {result.stdout}")
            if result.stderr:
                print(f"airmon-ng stderr: {result.stderr}")
            
            # Check for created monitor interface
            possible_names = [f"{interface}mon", f"{interface}mon0", interface]
            for mon_name in possible_names:
                check_result = subprocess.run(['iwconfig', mon_name], 
                                            capture_output=True, text=True)
                if "Mode:Monitor" in check_result.stdout:
                    print(f"Monitor mode confirmed on {mon_name}")
                    return mon_name
                    
        except subprocess.TimeoutExpired:
            print("airmon-ng timed out")
        except Exception as e:
            print(f"airmon-ng failed: {e}")
        
        # Step 4: Manual iwconfig method
        print("Trying manual iwconfig method...")
        try:
            subprocess.run(['sudo', 'ifconfig', interface, 'down'], check=True)
            time.sleep(1)
            subprocess.run(['sudo', 'iwconfig', interface, 'mode', 'monitor'], check=True)
            time.sleep(1)
            subprocess.run(['sudo', 'ifconfig', interface, 'up'], check=True)
            time.sleep(2)
            
            # Verify
            result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
            if "Mode:Monitor" in result.stdout:
                print(f"Manual monitor mode successful on {interface}")
                return interface
                
        except Exception as e:
            print(f"Manual method failed: {e}")
        
        # Step 5: iw command method
        print("Trying iw command method...")
        try:
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], check=True)
            subprocess.run(['sudo', 'iw', interface, 'set', 'monitor', 'none'], check=True)
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], check=True)
            time.sleep(2)
            
            result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
            if "Mode:Monitor" in result.stdout:
                print(f"iw method successful on {interface}")
                return interface
                
        except Exception as e:
            print(f"iw method failed: {e}")
        
        print("All monitor mode methods failed")
        return None
    
    def stop_monitor_mode(self, monitor_interface):
        """Stop monitor mode"""
        try:
            base_interface = monitor_interface.replace('mon', '')
            subprocess.run(['airmon-ng', 'stop', monitor_interface], capture_output=True)
            print(f"Monitor mode stopped on {monitor_interface}")
        except Exception as e:
            print(f"Failed to stop monitor mode: {e}")
    
    def set_channel(self, channel):
        """Set WiFi channel"""
        try:
            subprocess.run(['iwconfig', self.monitor_interface, 'channel', str(channel)], 
                         capture_output=True)
            self.current_channel = channel
        except Exception as e:
            print(f"Failed to set channel {channel}: {e}")
    
    def channel_hopper(self):
        """Channel hopping thread"""
        channels_2ghz = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        channels_5ghz = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165]
        
        all_channels = channels_2ghz + channels_5ghz
        channel_index = 0
        
        while self.running:
            if self.monitor_interface:
                channel = all_channels[channel_index % len(all_channels)]
                self.set_channel(channel)
                channel_index += 1
            time.sleep(0.5)  # Dwell time per channel
    
    def get_fresh_gps_data(self):
        """Get fresh GPS data by forcing gpsd to update its cache"""
        try:
            # Force gpsd to update its cache by reconnecting
            gpsd.connect()
            
            # Get the current data (should be fresh after reconnect)
            packet = gpsd.get_current()
            
            if packet and hasattr(packet, 'mode') and packet.mode >= 2:
                self.log("Using gpsd-py3 fresh GPS data (forced update)")
                return packet
            else:
                self.log("gpsd-py3 no valid fix")
                return None
                
        except Exception as e:
            self.log(f"gpsd-py3 failed: {e}")
            return None
    
    def gps_updater(self):
        """GPS update thread - using ONLY gpsd with forced cache updates"""
        self.log("GPS updater thread started - using gpsd with forced cache updates")
        print("GPS updater thread started - forcing gpsd cache updates")
        update_count = 0
        
        # Run continuously while LCD is running (app lifecycle)
        while self.lcd_running:
            update_count += 1
            current_time = time.time()
            
            if self.gps_ready:
                try:
                    # METHOD 1: gpsd with forced cache updates
                    packet = None
                    try:
                        packet = self.get_fresh_gps_data()
                        if not packet:
                            self.log("No GPS data available")
                            time.sleep(1)
                            continue
                    except Exception as e:
                        self.log(f"GPS method failed: {e}")
                        time.sleep(1)
                        continue
                    
                    # Only process packets with valid 2D/3D fix
                    if packet and hasattr(packet, 'mode') and packet.mode >= 2:
                        old_coords = None
                        if self.gps_data:
                            old_coords = (self.gps_data['latitude'], self.gps_data['longitude'])
                        
                        # Extract coordinates - handle potential None values
                        lat = getattr(packet, 'lat', None)
                        lon = getattr(packet, 'lon', None)
                        alt = getattr(packet, 'alt', None)
                        speed = getattr(packet, 'hspeed', 0)
                        sats = getattr(packet, 'sats', 0)
                        
                        if lat is not None and lon is not None:
                            # Update GPS data
                            new_gps_data = {
                                'latitude': lat,
                                'longitude': lon,
                                'altitude': alt if packet.mode >= 3 else None,
                                'speed': speed,
                                'satellites': sats,
                                'timestamp': datetime.now().isoformat()
                            }
                            
                            # Check if coordinates actually changed (real-time movement detection)
                            coords_changed = False
                            movement_type = "stationary"
                            if old_coords:
                                lat_diff = abs(lat - old_coords[0])
                                lon_diff = abs(lon - old_coords[1])
                                
                                # More sensitive detection for walking: ~0.3 meters instead of ~1 meter
                                if lat_diff > 0.000003 or lon_diff > 0.000003:
                                    coords_changed = True
                                    speed_mph = speed * 2.237  # Convert m/s to mph
                                    
                                    if speed_mph < 0.5:
                                        movement_type = "walking"
                                        self.log(f"GPS MOVED (walking): {lat:.6f},{lon:.6f} (was {old_coords[0]:.6f},{old_coords[1]:.6f}) Speed: {speed:.1f} m/s")
                                        print(f"GPS MOVED (walking): {lat:.6f},{lon:.6f} Speed: {speed:.1f} m/s")
                                    elif speed_mph < 5:
                                        movement_type = "slow"
                                        self.log(f"GPS MOVED (slow): {lat:.6f},{lon:.6f} (was {old_coords[0]:.6f},{old_coords[1]:.6f}) Speed: {speed_mph:.1f} mph")
                                        print(f"GPS MOVED (slow): {lat:.6f},{lon:.6f} Speed: {speed_mph:.1f} mph")
                                    else:
                                        movement_type = "driving"
                                        self.log(f"GPS MOVED (driving): {lat:.6f},{lon:.6f} (was {old_coords[0]:.6f},{old_coords[1]:.6f}) Speed: {speed_mph:.1f} mph")
                                        print(f"GPS MOVED (driving): {lat:.6f},{lon:.6f} Speed: {speed_mph:.1f} mph")
                                else:
                                    # Only log stationary if speed is significant (> 1.0 m/s) to reduce spam
                                    if speed > 1.0:
                                        self.log(f"GPS STATIONARY: {lat:.6f},{lon:.6f} Speed: {speed:.1f} m/s")
                                        print(f"GPS STATIONARY: {lat:.6f},{lon:.6f} Speed: {speed:.1f} m/s")
                            else:
                                self.log(f"GPS FIRST READ: {lat:.6f},{lon:.6f} Speed: {speed:.1f} m/s")
                                print(f"GPS FIRST READ: {lat:.6f},{lon:.6f} Speed: {speed:.1f} m/s")
                            
                            # ALWAYS update the GPS data (even if stationary)
                            self.gps_data = new_gps_data
                            
                            # Log updates every 10 seconds or when coordinates change significantly
                            if update_count % 10 == 1 or coords_changed:
                                if coords_changed:
                                    self.log(f"GPS {movement_type.upper()}: {lat:.6f},{lon:.6f} Speed: {speed:.1f} Sats: {sats}")
                                else:
                                    self.log(f"GPS update: {lat:.6f},{lon:.6f} Speed: {speed:.1f} Sats: {sats}")
                        else:
                            self.log(f"GPS packet missing coordinates - lat: {lat}, lon: {lon}")
                            
                    else:
                        packet_mode = getattr(packet, 'mode', 'unknown') if packet else 'no packet'
                        self.log(f"GPS no fix - mode: {packet_mode}")
                        if update_count % 10 == 1:
                            print(f"GPS waiting for fix - mode: {packet_mode}")
                            
                except Exception as e:
                    self.log(f"GPS update error: {e}")
                    if update_count % 5 == 1:
                        print(f"GPS update error: {e}")
                    # Small delay on error to prevent spam
                    time.sleep(0.5)
            else:
                self.log("GPS not ready for updates")
                if update_count % 5 == 1:
                    print("GPS not ready for updates")
                time.sleep(1)
            
            # Update every 1 second for real-time tracking
                time.sleep(1)
        
        self.log("GPS updater thread stopped")
        print("GPS updater thread stopped")
    
    def get_vendor_from_mac(self, mac):
        """Get vendor from MAC address OUI"""
        oui_dict = {
            '00:50:56': 'VMware',
            '08:00:27': 'VirtualBox',
            '00:0C:29': 'VMware',
            '00:1B:21': 'Intel',
            '00:23:AB': 'Apple',
            '28:CF:E9': 'Apple',
            '3C:07:54': 'Apple',
            '00:26:BB': 'Apple',
            'B8:E8:56': 'Apple',
            '00:1F:F3': 'Apple',
            '00:25:00': 'Apple',
            '00:03:93': 'Apple',
            '00:D0:B7': 'Intel',
            '00:AA:00': 'Intel',
            '00:02:B3': 'Intel',
            '00:13:02': 'Intel',
            '00:15:00': 'Intel',
            '00:16:76': 'Intel',
            '00:19:D1': 'Intel',
            '00:1B:77': 'Intel',
            '00:1C:BF': 'Intel',
            '00:1E:64': 'Intel',
            '00:1F:3B': 'Intel',
            '00:21:5C': 'Intel',
            '00:22:FB': 'Intel',
            '00:24:D6': 'Intel',
            '00:26:C6': 'Intel',
            '00:27:10': 'Intel'
        }
        
        oui = mac[:8].upper()
        return oui_dict.get(oui, 'Unknown')
    
    def detect_security(self, packet):
        """Detect security protocols from beacon frame"""
        security_info = {
            'type': 'Open',
            'encryption': 'None',
            'cipher': 'None',
            'authentication': 'None',
            'wps_enabled': False
        }
        
        try:
            # Check capability info for privacy bit
            if packet[Dot11Beacon].cap & 0x0010:
                security_info['encryption'] = 'Encrypted'
            
            # Parse information elements
            elt = packet[Dot11Elt]
            while elt:
                if elt.ID == 48:  # RSN Information Element (WPA2/WPA3)
                    security_info.update(self.parse_rsn_ie(elt.info))
                elif elt.ID == 221:  # Vendor Specific
                    if len(elt.info) >= 4:
                        if elt.info[:4] == b'\x00\x50\xf2\x01':  # WPA IE
                            security_info.update(self.parse_wpa_ie(elt.info))
                        elif elt.info[:4] == b'\x00\x50\xf2\x04':  # WPS IE
                            security_info['wps_enabled'] = True
                
                elt = elt.payload if hasattr(elt, 'payload') and isinstance(elt.payload, Dot11Elt) else None
            
            # Determine security type
            if security_info['encryption'] == 'None':
                security_info['type'] = 'Open'
            elif 'WPA3' in security_info.get('authentication', ''):
                security_info['type'] = 'WPA3'
            elif 'WPA2' in security_info.get('authentication', ''):
                security_info['type'] = 'WPA2'
            elif 'WPA' in security_info.get('authentication', ''):
                security_info['type'] = 'WPA'
            elif security_info['encryption'] == 'Encrypted':
                security_info['type'] = 'WEP'
        
        except Exception as e:
            print(f"Security detection error: {e}")
        
        return security_info
    
    def parse_rsn_ie(self, rsn_data):
        """Parse RSN Information Element"""
        security_info = {'authentication': 'WPA2'}
        try:
            # Basic parsing - this is simplified
            if len(rsn_data) >= 8:
                # Check for SAE (WPA3)
                if b'\x00\x0f\xac\x08' in rsn_data:
                    security_info['authentication'] = 'WPA3-SAE'
                elif b'\x00\x0f\xac\x02' in rsn_data:
                    security_info['authentication'] = 'WPA2-PSK'
                elif b'\x00\x0f\xac\x01' in rsn_data:
                    security_info['authentication'] = 'WPA2-Enterprise'
                
                # Check cipher
                if b'\x00\x0f\xac\x04' in rsn_data:
                    security_info['cipher'] = 'CCMP'
                elif b'\x00\x0f\xac\x02' in rsn_data:
                    security_info['cipher'] = 'TKIP'
        except:
            pass
        return security_info
    
    def parse_wpa_ie(self, wpa_data):
        """Parse WPA Information Element"""
        security_info = {'authentication': 'WPA'}
        try:
            if len(wpa_data) >= 8:
                if b'\x00\x50\xf2\x02' in wpa_data:
                    security_info['authentication'] = 'WPA-PSK'
                elif b'\x00\x50\xf2\x01' in wpa_data:
                    security_info['authentication'] = 'WPA-Enterprise'
                
                if b'\x00\x50\xf2\x04' in wpa_data:
                    security_info['cipher'] = 'CCMP'
                elif b'\x00\x50\xf2\x02' in wpa_data:
                    security_info['cipher'] = 'TKIP'
        except:
            pass
        return security_info
    
    def packet_handler(self, packet):
        """Process captured 802.11 frames"""
        try:
            if packet.haslayer(Dot11Beacon):
                self.process_beacon(packet)
            elif packet.haslayer(Dot11ProbeResp):
                self.process_probe_response(packet)
        except Exception as e:
            print(f"Packet processing error: {e}")
    
    def process_beacon(self, packet):
        """Process beacon frame"""
        try:
            bssid = packet[Dot11].addr3
            
            # Get SSID
            ssid = ""
            if packet.haslayer(Dot11Elt):
                ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
            
            # Skip if we've already seen this network recently
            if bssid in self.networks:
                self.networks[bssid]['last_seen'] = datetime.now().isoformat()
                return
            
            # Get channel
            channel = self.current_channel
            if packet.haslayer(Dot11Elt):
                elt = packet[Dot11Elt]
                while elt:
                    if elt.ID == 3:  # DS Parameter Set
                        if len(elt.info) >= 1:
                            channel = ord(elt.info[:1])
                        break
                    elt = elt.payload if hasattr(elt, 'payload') and isinstance(elt.payload, Dot11Elt) else None
            
            # Get signal strength
            signal_strength = None
            if hasattr(packet, 'dBm_AntSignal'):
                signal_strength = packet.dBm_AntSignal
            
            # Detect security
            security = self.detect_security(packet)
            
            # Get vendor
            vendor = self.get_vendor_from_mac(bssid)
            
            # Store network information
            network_info = {
                'ssid': ssid,
                'bssid': bssid,
                'channel': channel,
                'frequency': self.channel_to_frequency(channel),
                'security': security,
                'signal_strength': signal_strength,
                'vendor': vendor,
                'first_seen': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat(),
                'gps_coordinates': self.gps_data.copy() if self.gps_data else None
            }
            
            self.networks[bssid] = network_info
            self.total_networks += 1
            
            # Store in database
            self.store_network_in_db(network_info)
            
            # Log and print discovery
            self.log(f"New network discovered: {ssid} ({bssid}) - {security['type']} - Channel {channel}")
            print(f"New network: {ssid} ({bssid}) - {security['type']} - Channel {channel}")
            
        except Exception as e:
            self.log(f"Beacon processing error: {e}")
            print(f"Beacon processing error: {e}")
    
    def process_probe_response(self, packet):
        """Process probe response frame"""
        # Similar to beacon processing but for probe responses
        self.process_beacon(packet)
    
    def channel_to_frequency(self, channel):
        """Convert channel number to frequency"""
        if 1 <= channel <= 13:
            return 2412 + (channel - 1) * 5
        elif channel == 14:
            return 2484
        elif 36 <= channel <= 165:
            return 5000 + channel * 5
        else:
            return 0
    
    def store_network_in_db(self, network_info):
        """Store network information in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Insert or update network
            cursor.execute('''
                INSERT OR REPLACE INTO networks 
                (ssid, bssid, channel, frequency, security_type, encryption, cipher, 
                 authentication, wps_enabled, signal_strength, first_seen, last_seen, vendor)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                network_info['ssid'],
                network_info['bssid'],
                network_info['channel'],
                network_info['frequency'],
                network_info['security']['type'],
                network_info['security']['encryption'],
                network_info['security']['cipher'],
                network_info['security']['authentication'],
                network_info['security']['wps_enabled'],
                network_info['signal_strength'],
                network_info['first_seen'],
                network_info['last_seen'],
                network_info['vendor']
            ))
            
            # Get network ID
            network_id = cursor.lastrowid
            
            # Store GPS coordinates if available
            if network_info['gps_coordinates']:
                gps = network_info['gps_coordinates']
                cursor.execute('''
                    INSERT INTO locations 
                    (network_id, latitude, longitude, altitude, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    network_id,
                    gps['latitude'],
                    gps['longitude'],
                    gps['altitude'],
                    gps['timestamp']
                ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Database storage error: {e}")
    
    def update_lcd_display(self):
        """Update LCD display - EXACT copy of example_show_buttons.py draw() function"""
        if not self.lcd_ready or not self.lcd_running:
            return
        
        try:
            # Build status text - compact 8-line format
            lines = [
                "WARDRIVING",
                f"Networks: {self.total_networks}"
            ]
            
            # GPS status with real-time updates (compact)
            if self.gps_data and 'latitude' in self.gps_data:
                lat = self.gps_data['latitude']
                lon = self.gps_data['longitude']
                speed = self.gps_data.get('speed', 0)
                
                # Show coordinates (4 decimal places = ~10m accuracy)
                lines.append(f"GPS: {lat:.4f},{lon:.4f}")
                
                # Show speed and channel on same line to save space
                if speed and speed > 0.2:  # Moving faster than 0.2 m/s
                    speed_mph = speed * 2.237  # Convert m/s to mph
                    if speed_mph < 1.0:
                        lines.append(f"Ch{self.current_channel} Walking")
                    else:
                        lines.append(f"Ch{self.current_channel} {speed_mph:.0f}mph")
                else:
                    lines.append(f"Ch{self.current_channel} Stationary")
            else:
                lines.append("GPS: No fix")
                lines.append(f"Ch{self.current_channel} No GPS")
            
            # Status and interface combined
            status = "SCANNING" if self.running else "STOPPED"
            if self.monitor_interface:
                lines.append(f"{status} ({self.monitor_interface})")
            else:
                lines.append(f"{status} (No IF)")
            
            # Additional wardriving info (using our 3 extra lines)
            # Line 1: Security breakdown
            if hasattr(self, 'networks') and self.networks:
                open_count = sum(1 for n in self.networks.values() if n['security']['type'] == 'Open')
                wpa_count = sum(1 for n in self.networks.values() if 'WPA' in n['security']['type'])
                lines.append(f"Open:{open_count} WPA:{wpa_count}")
            else:
                lines.append("Open:0 WPA:0")
            
            # Line 2: GPS quality info
            if self.gps_data:
                # Show time since last GPS update
                try:
                    gps_time = datetime.fromisoformat(self.gps_data['timestamp'])
                    time_diff = (datetime.now() - gps_time).total_seconds()
                    if time_diff < 5:
                        lines.append("GPS: Fresh")
                    else:
                        lines.append(f"GPS: {time_diff:.0f}s old")
                except:
                    lines.append("GPS: Active")
            else:
                lines.append("GPS: No data")
            
            # Line 3: Session stats
            if hasattr(self, 'networks') and self.networks:
                # Count networks with GPS coordinates (ready for Wigle)
                gps_networks = sum(1 for n in self.networks.values() if n.get('gps_coordinates'))
                lines.append(f"Wigle ready: {gps_networks}")
            else:
                lines.append("Wigle ready: 0")
            
            # Controls
            lines.append("[KEY1] Start/Stop")
            lines.append("[KEY2] Exit")
            
            # EXACT COPY of example_show_buttons.py draw() function
            img = Image.new("RGB", (self.WIDTH, self.HEIGHT), "black")
            d = ImageDraw.Draw(img)
            
            # Display multiple lines
            y = 2
            for i, line in enumerate(lines):
                if y > self.HEIGHT - 15:  # Don't overflow
                    break
                
                # Measure text size (EXACT from example_show_buttons.py)
                if hasattr(d, "textbbox"):
                    x0, y0, x1, y1 = d.textbbox((0, 0), line, font=self.font)
                    w, h = x1 - x0, y1 - y0
                else:  # Pillow < 9.2 fallback
                    w, h = d.textsize(line, font=self.font)
                
                # Centre coordinates (EXACT from example_show_buttons.py)
                x = (self.WIDTH - w) // 2
                
                # Draw the text (EXACT from example_show_buttons.py)
                d.text((x, y), line, font=self.font, fill="#00FF00")
                y += 12
            
            # Push image to LCD (EXACT from example_show_buttons.py)
            self.LCD.LCD_ShowImage(img, 0, 0)
            
        except Exception as e:
            self.log(f"LCD display update ERROR: {e}")
            print(f"LCD error: {e}")
            import traceback
            self.log(f"LCD update traceback: {traceback.format_exc()}")
    
    def export_data(self):
        """Export collected data in multiple formats including Wigle"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Export JSON
        self.export_json(f"{self.loot_dir}/scan_{timestamp}.json")
        
        # Export CSV
        self.export_csv(f"{self.loot_dir}/scan_{timestamp}.csv")
        
        # Export KML
        self.export_kml(f"{self.loot_dir}/scan_{timestamp}.kml")
        
        # Export Wigle-compatible CSV
        self.export_wigle_csv(f"{self.loot_dir}/wigle_{timestamp}.csv")
        
        print(f"Data exported to {self.loot_dir}/scan_{timestamp}.*")
        print(f"Wigle upload file: {self.loot_dir}/wigle_{timestamp}.csv")
    
    def export_json(self, filename):
        """Export data as JSON"""
        try:
            export_data = {
                'scan_info': {
                    'start_time': datetime.now().isoformat(),
                    'total_networks': self.total_networks,
                    'gps_enabled': self.gps_ready
                },
                'networks': list(self.networks.values())
            }
            
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
        except Exception as e:
            print(f"JSON export error: {e}")
    
    def export_csv(self, filename):
        """Export data as CSV"""
        try:
            import csv
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['SSID', 'BSSID', 'Security', 'Channel', 'Signal', 'Latitude', 'Longitude', 'FirstSeen', 'LastSeen'])
                
                for network in self.networks.values():
                    gps = network.get('gps_coordinates', {})
                    writer.writerow([
                        network['ssid'],
                        network['bssid'],
                        network['security']['type'],
                        network['channel'],
                        network['signal_strength'],
                        gps.get('latitude', ''),
                        gps.get('longitude', ''),
                        network['first_seen'],
                        network['last_seen']
                    ])
        except Exception as e:
            print(f"CSV export error: {e}")
    
    def export_kml(self, filename):
        """Export data as KML for Google Earth"""
        try:
            kml_content = '''<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>RaspyJack Wardriving Results</name>
'''
            
            for network in self.networks.values():
                if network.get('gps_coordinates'):
                    gps = network['gps_coordinates']
                    kml_content += f'''
    <Placemark>
      <name>{network['ssid']}</name>
      <description>
        BSSID: {network['bssid']}
        Security: {network['security']['type']}
        Channel: {network['channel']}
        Signal: {network['signal_strength']} dBm
        Vendor: {network['vendor']}
      </description>
      <Point>
        <coordinates>{gps['longitude']},{gps['latitude']},0</coordinates>
      </Point>
    </Placemark>'''
            
            kml_content += '''
  </Document>
</kml>'''
            
            with open(filename, 'w') as f:
                f.write(kml_content)
        except Exception as e:
            print(f"KML export error: {e}")
    
    def export_wigle_csv(self, filename):
        """Export data in Wigle-compatible CSV format for upload to wigle.net"""
        try:
            self.log(f"Exporting Wigle-compatible CSV to {filename}")
            
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Wigle CSV header format (required fields)
                writer.writerow([
                    'WigleWifi-1.4',
                    'appRelease=RaspyJack-1.0.2',
                    'model=RaspberryPi',
                    'release=RaspyJack Wardriving',
                    f'device=RaspyJack-{datetime.now().strftime("%Y%m%d")}',
                    'display=RaspyJack',
                    'board=RaspberryPi',
                    'brand=RaspyJack'
                ])
                
                # Column headers (Wigle format)
                writer.writerow([
                    'MAC',              # BSSID of the network
                    'SSID',             # Network name
                    'AuthMode',         # Security type
                    'FirstSeen',        # When we first detected it
                    'Channel',          # WiFi channel
                    'RSSI',             # Signal strength
                    'CurrentLatitude',  # OUR GPS latitude (where we detected it from)
                    'CurrentLongitude', # OUR GPS longitude (where we detected it from)
                    'AltitudeMeters',   # OUR GPS altitude
                    'AccuracyMeters',   # OUR GPS accuracy
                    'Type'              # Network type (always WIFI)
                ])
                
                # Export each network
                for network in self.networks.values():
                    if network.get('gps_coordinates'):
                        gps = network['gps_coordinates']
                        
                        # Convert security type to Wigle format
                        auth_mode = self.convert_security_to_wigle(network['security'])
                        
                        # Convert timestamp to Wigle format (ISO 8601)
                        first_seen = network['first_seen']
                        if 'T' not in first_seen:
                            # Convert from our format to ISO 8601
                            try:
                                dt = datetime.fromisoformat(first_seen)
                                first_seen = dt.strftime('%Y-%m-%dT%H:%M:%S.000Z')
                            except:
                                first_seen = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000Z')
                        
                        writer.writerow([
                            network['bssid'],                    # MAC - The network's BSSID
                            network['ssid'],                     # SSID - The network's name
                            auth_mode,                           # AuthMode - The network's security
                            first_seen,                          # FirstSeen - When we detected it
                            network['channel'],                  # Channel - The network's channel
                            network['signal_strength'] or -50,  # RSSI - Signal strength we received
                            gps['latitude'],                     # CurrentLatitude - OUR location when we detected it
                            gps['longitude'],                    # CurrentLongitude - OUR location when we detected it
                            gps.get('altitude', 0) or 0,        # AltitudeMeters - OUR altitude
                            10,                                  # AccuracyMeters - OUR GPS accuracy
                            'WIFI'                               # Type - Always WIFI
                        ])
            
            networks_exported = len([n for n in self.networks.values() if n.get('gps_coordinates')])
            self.log(f"Wigle CSV export completed: {networks_exported} networks with GPS data")
            print(f"Wigle CSV exported: {networks_exported} networks")
            
        except Exception as e:
            self.log(f"Wigle CSV export error: {e}")
            print(f"Wigle CSV export error: {e}")
    
    def convert_security_to_wigle(self, security):
        """Convert our security format to Wigle AuthMode format"""
        security_type = security.get('type', 'Open').upper()
        
        # Wigle AuthMode mappings
        if security_type == 'OPEN':
            return '[ESS]'
        elif security_type == 'WEP':
            return '[WEP][ESS]'
        elif security_type == 'WPA':
            return '[WPA-PSK-TKIP][ESS]'
        elif security_type == 'WPA2':
            auth = security.get('authentication', '').upper()
            cipher = security.get('cipher', '').upper()
            
            if 'PSK' in auth and 'CCMP' in cipher:
                return '[WPA2-PSK-CCMP][ESS]'
            elif 'PSK' in auth:
                return '[WPA2-PSK-TKIP][ESS]'
            elif 'ENTERPRISE' in auth:
                return '[WPA2-EAP-CCMP][ESS]'
            else:
                return '[WPA2-PSK-CCMP][ESS]'  # Default
        elif security_type == 'WPA3':
            return '[WPA3-SAE-CCMP][ESS]'
        else:
            return '[ESS]'  # Default to open
    
    def start_scan(self):
        """Start wardriving scan - reuse existing monitor interface if available"""
        if self.running:
            return
        
        if not SCAPY_AVAILABLE:
            print("Scapy not available - cannot start scan")
            return
        
        # Check if we already have a monitor interface from previous scan
        if self.monitor_interface:
            self.log(f"Reusing existing monitor interface: {self.monitor_interface}")
            print(f"Reusing monitor interface: {self.monitor_interface}")
        else:
            # Auto-detect which interface supports monitor mode
            print("Detecting monitor-capable WiFi interface...", flush=True)
            iface = self._find_monitor_capable_interface()
            if not iface:
                print("No WiFi interfaces found")
                return
            self.interface = iface
            print(f"Using interface: {self.interface}")
            
            # Setup monitor mode
            self.monitor_interface = self.setup_monitor_mode(self.interface)
            if not self.monitor_interface:
                print("Failed to setup monitor mode")
                return
            
            print(f"Monitor mode enabled on {self.monitor_interface}")
        
        # Start scanning
        self.running = True
        self.log("Starting wardriving scan...")
        
        # Start threads
        self.channel_thread = threading.Thread(target=self.channel_hopper)
        self.channel_thread.daemon = True
        self.channel_thread.start()
        
        # GPS updater thread is now started during GPS initialization, not here
        if GPS_AVAILABLE and self.gps_ready:
            self.log("GPS updater already running from initialization")
            print("GPS tracking already active - coordinates updating continuously")
        
        # Start packet capture
        self.scan_thread = threading.Thread(target=self.packet_capture)
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        self.log("Wardriving scan started successfully")
        print("Wardriving scan started")
        print("Looking for WiFi networks... (this may take a moment)")
        print("Make sure you're in an area with WiFi networks nearby")
    
    def packet_capture(self):
        """Enhanced packet capture with debugging"""
        try:
            print(f"Starting packet capture on {self.monitor_interface}")
            
            # Verify interface
            result = subprocess.run(['iwconfig', self.monitor_interface], 
                                  capture_output=True, text=True)
            print(f"Interface check: {result.stdout[:100]}")
            
            if "Mode:Monitor" not in result.stdout:
                print("ERROR: Interface not in monitor mode!")
                return
            
            # Test capture first
            print("Testing packet capture (5 seconds)...")
            test_packets = sniff(iface=self.monitor_interface, timeout=5, count=5)
            print(f"Test captured {len(test_packets)} packets")
            
            if len(test_packets) == 0:
                print("WARNING: No packets in test capture")
                # Try without filter
                print("Trying capture without filter...")
                test_packets2 = sniff(iface=self.monitor_interface, timeout=3, count=3)
                print(f"Unfiltered test: {len(test_packets2)} packets")
            
            # Main capture loop
            print("Starting main packet capture...")
            packet_count = 0
            
            def packet_processor(packet):
                nonlocal packet_count
                packet_count += 1
                if packet_count % 100 == 0:
                    print(f"Processed {packet_count} packets")
                self.packet_handler(packet)
            
            # Capture with management frame filter
            sniff(iface=self.monitor_interface,
                  prn=packet_processor,
                  filter="type mgt",
                  stop_filter=lambda x: not self.running,
                  store=0)
                  
        except Exception as e:
            print(f"Packet capture error: {e}")
            import traceback
            traceback.print_exc()
    
    def stop_scan(self):
        """Stop wardriving scan without killing the interface"""
        if not self.running:
            return
        
        self.log("Stopping wardriving scan...")
        print("Stopping wardriving scan...")
        self.running = False
        
        # Wait for threads to finish
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=2)
        
        if self.channel_thread and self.channel_thread.is_alive():
            self.channel_thread.join(timeout=2)
        
        if self.gps_thread and self.gps_thread.is_alive():
            self.gps_thread.join(timeout=2)
        
        # DON'T stop monitor mode - keep interface ready for next scan
        # Just log that we're keeping it active
        if self.monitor_interface:
            self.log(f"Keeping {self.monitor_interface} in monitor mode for next scan")
            print(f"Interface {self.monitor_interface} remains in monitor mode")
        
        # Export data ONLY when stopping scan (not during cleanup)
        if self.networks and not getattr(self, 'cleanup_in_progress', False):
            self.export_data()
        
        self.log("Wardriving scan stopped - interface preserved")
        print("Wardriving scan stopped")
    
    def cleanup(self):
        """Comprehensive cleanup with proper thread shutdown - run only once"""
        # Prevent multiple cleanup runs
        if getattr(self, 'cleanup_in_progress', False):
            self.log("Cleanup already in progress, skipping duplicate")
            return
        
        self.cleanup_in_progress = True
        
        try:
            self.log("Starting comprehensive cleanup...")
            
            # FIRST: Stop LCD update loop to prevent GPIO conflicts
            self.log("Stopping LCD update loop...")
            self.lcd_running = False
            time.sleep(2)  # Give LCD thread time to stop
            
            # Stop all scanning activities (without exporting again)
            self.stop_scan()
            
            # Kill any remaining processes (like deauth.py does)
            self.log("Killing any remaining processes...")
            subprocess.run(['pkill', '-f', 'airodump-ng'], capture_output=True)
            subprocess.run(['pkill', '-f', 'aireplay-ng'], capture_output=True)
            subprocess.run(['pkill', '-f', 'airmon-ng'], capture_output=True)
            
            # Stop monitor mode and restore interface (like deauth.py)
            if self.monitor_interface:
                self.log(f"Final cleanup: stopping monitor mode on {self.monitor_interface}")
                self.stop_monitor_mode(self.monitor_interface)
                self.monitor_interface = None
            
            # Try to restart NetworkManager (like deauth.py does)
            self.log("Attempting to restart NetworkManager...")
            try:
                subprocess.run(['systemctl', 'start', 'NetworkManager'], 
                             capture_output=True, timeout=10)
                self.log("NetworkManager restart attempted")
            except Exception as e:
                self.log(f"NetworkManager restart failed: {e}")
            
            # Clear LCD display (like deauth.py does) - AFTER stopping LCD thread
            if LCD_AVAILABLE and hasattr(self, 'lcd_ready') and self.lcd_ready:
                try:
                    self.LCD.LCD_Clear()
                    self.log("LCD cleared")
                except Exception as e:
                    self.log(f"LCD clear failed: {e}")
            
            # Clean up GPIO (like deauth.py does) - LAST step
            if LCD_AVAILABLE and hasattr(self, 'gpio_ready') and self.gpio_ready:
                try:
                    GPIO.cleanup()
                    self.log("GPIO cleaned up")
                    print("GPIO cleaned up")
                except Exception as e:
                    self.log(f"GPIO cleanup failed: {e}")
            
            # NO EXPORT HERE - data was already exported when scan stopped
            if hasattr(self, 'networks') and self.networks:
                self.log(f"Cleanup complete - {len(self.networks)} networks were already exported")
            else:
                self.log("No networks found during session")
                
            self.log("Comprehensive cleanup completed successfully")
            
        except Exception as e:
            self.log(f"Cleanup error: {e}")
            print(f"Cleanup error: {e}")
            # Continue cleanup even if there are errors
            try:
                if LCD_AVAILABLE:
                    GPIO.cleanup()
            except:
                pass
    
    def run_interactive(self):
        """Run interactive wardriving session"""
        print("RaspyJack Wardriving Scanner")
        print("===========================")
        
        # Start LCD display update thread
        if LCD_AVAILABLE and self.lcd_ready:
            self.log("Starting LCD display thread...")
            display_thread = threading.Thread(target=self.lcd_update_loop)
            display_thread.daemon = True
            display_thread.start()
            self.log("LCD display thread started - running in LCD mode")
            
            print("LCD Mode - Use hardware buttons:")
            print("  KEY1 - Start/Stop scan")
            print("  KEY2 - Exit")
            print("  KEY3 - Export data")
            print("\nPress Ctrl+C to exit")
            
            # Simple LCD mode loop - just keep the program running
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
            print("Console Mode - Use keyboard commands:")
            print("  s - Start/Stop scan")
            print("  e - Export data") 
            print("  q - Quit")
            
            # Check if we're in an interactive environment
            import sys
            if not sys.stdin.isatty():
                print("Non-interactive environment detected - starting scan automatically...")
                print("Press Ctrl+C to stop scanning")
                self.start_scan()
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\nStopping scan...")
                    self.stop_scan()
                    return
            
            # Interactive console mode loop
            while True:
                try:
                    cmd = input("\nCommand: ").lower().strip()
                    if cmd == 's':
                        if self.running:
                            self.stop_scan()
                        else:
                            self.start_scan()
                    elif cmd == 'e':
                        self.export_data()
                    elif cmd == 'q':
                        break
                    else:
                        print("Invalid command")
                except (EOFError, KeyboardInterrupt):
                    print("\nExiting...")
                    break
        
        # Cleanup
        self.log("Shutting down wardriving scanner...")
        self.stop_scan()
    
    def lcd_update_loop(self):
        """LCD update loop with proper error handling and shutdown control"""
        self.log("Starting LCD update loop thread")
        loop_count = 0
        
        try:
            while self.lcd_running:  # Check our control flag
                loop_count += 1
                try:
                    if self.lcd_running:  # Double-check before LCD operations
                        self.update_lcd_display()
                    
                    # Log every 30 seconds to show it's working
                    if loop_count % 30 == 1:
                        self.log(f"LCD update loop running (iteration {loop_count})")
                        
                except Exception as e:
                    self.log(f"LCD update loop ERROR: {e}")
                    import traceback
                    self.log(f"LCD loop traceback: {traceback.format_exc()}")
                    # Continue running even if there's an error
                
                time.sleep(1)
                
        except Exception as e:
            self.log(f"LCD update loop CRASHED: {e}")
            import traceback
            self.log(f"LCD loop crash traceback: {traceback.format_exc()}")
        
        self.log("LCD update loop stopped")
    
    def handle_gpio_input(self):
        """Improved GPIO button handling with proper debouncing"""
        if not LCD_AVAILABLE or not hasattr(self, 'gpio_ready') or not self.gpio_ready:
            return
        
        try:
            virtual = get_virtual_button()
            if virtual == "KEY1":
                print("KEY1 pressed - toggling scan (WebUI)")
                if self.running:
                    self.stop_scan()
                else:
                    self.start_scan()
                time.sleep(0.2)
            elif virtual == "KEY2":
                print("KEY2 pressed - exiting (WebUI)")
                self.cleanup()
                sys.exit(0)
            elif virtual == "KEY3":
                print("KEY3 pressed - export data (WebUI)")
                self.export_data()
                time.sleep(0.2)

            # Check KEY1 (Start/Stop) - Pin 21
            if GPIO.input(21) == 0:  # Button pressed (active low)
                time.sleep(0.05)  # Initial debounce
                if GPIO.input(21) == 0:  # Still pressed
                    print("KEY1 pressed - toggling scan")
                    if self.running:
                        self.stop_scan()
                    else:
                        self.start_scan()
                    
                    # Wait for button release with timeout
                    timeout = time.time() + 2  # 2 second timeout
                    while GPIO.input(21) == 0 and time.time() < timeout:
                        time.sleep(0.05)
                    
                    time.sleep(0.2)  # Additional debounce after release
            
            # Check KEY2 (Exit - hold for 2 seconds) - Pin 20
            if GPIO.input(20) == 0:  # Button pressed (active low)
                time.sleep(0.05)  # Initial debounce
                if GPIO.input(20) == 0:  # Still pressed
                    print("KEY2 pressed - Hold for 2 seconds to exit")
                    self.log("Exit button pressed - checking hold duration")
                    
                    # Count how long button is held
                    hold_start = time.time()
                    while GPIO.input(20) == 0:  # While button is held
                        hold_duration = time.time() - hold_start
                        if hold_duration >= 2.0:  # Held for 2 seconds
                            print("KEY2 held - Exiting wardriving scanner")
                            self.log("Exit confirmed - shutting down")
                            self.cleanup()
                            sys.exit(0)
                        time.sleep(0.05)
                    
                    # Button released before 2 seconds
                    hold_duration = time.time() - hold_start
                    if hold_duration < 2.0:
                        print(f"KEY2 released too quickly ({hold_duration:.1f}s) - Hold for 2s to exit")
                        self.log(f"Exit cancelled - held for only {hold_duration:.1f}s")
                    
                    time.sleep(0.2)
            
            # Check KEY3 (Export data) - Pin 16
            if GPIO.input(16) == 0:  # Button pressed (active low)
                time.sleep(0.05)  # Initial debounce
                if GPIO.input(16) == 0:  # Still pressed
                    print("KEY3 pressed - export data")
                    self.export_data()
                    
                    # Wait for button release
                    while GPIO.input(16) == 0:
                        time.sleep(0.05)
                    time.sleep(0.2)
        
        except Exception as e:
            print(f"GPIO handling error: {e}")

def main():
    """Main function"""
    try:
        scanner = WardrivingScanner()
        scanner.run_interactive()
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup
        try:
            if 'scanner' in locals():
                scanner.cleanup()
        except:
            pass

if __name__ == "__main__":
    main()