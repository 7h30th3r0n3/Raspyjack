#display.py
# Description:
# This file, display.py, is responsible for managing the e-ink display of the Ragnar project, updating it with relevant data and statuses.
# It initializes the display, manages multiple threads for updating shared data and vulnerability counts, and handles the rendering of information
# and images on the display.
#
# Key functionalities include:
# - Initializing the e-ink display (EPD) and handling any errors during initialization.
# - Creating and managing threads to periodically update shared data and vulnerability counts.
# - Rendering various statistics, status icons, and images on the e-ink display.
# - Handling updates to shared data from various sources, including CSV files and system commands.
# - Checking and displaying the status of Bluetooth, Wi-Fi, PAN, and USB connections.
# - Providing methods to update the display with comments from an AI (Commentaireia) and generating images dynamically.

import threading
import time
import os
import signal
import glob
import logging
import random
import sys
import csv
from PIL import Image, ImageDraw, ImageFont
from init_shared import shared_data  
from comment import Commentaireia
from logger import Logger
import subprocess  

# Map rotation angle → PIL transpose operation
_ROTATION_TRANSPOSE = {
    90:  Image.Transpose.ROTATE_90,
    180: Image.Transpose.ROTATE_180,
    270: Image.Transpose.ROTATE_270,
}


def _render_dimensions(width, height, rotation):
    """Return (render_w, render_h) for the given rotation.

    For 90°/270° the render canvas is portrait (swapped) so that the
    e-paper getbuffer 'Vertical' path maps it correctly to the landscape
    display buffer.  For 0°/180° dimensions stay as-is.
    """
    if rotation in (90, 270):
        return height, width
    return width, height


def _apply_epd_rotation(image, rotation):
    """Apply rotation for the EPD hardware path.

    * 0°   – no-op
    * 180° – PIL ROTATE_180 (same dims, horizontal getbuffer path)
    * 90°  – no-op (image is already portrait, getbuffer vertical handles it)
    * 270° – PIL ROTATE_180 (flips the portrait image, getbuffer vertical gives opposite orientation)
    """
    if rotation == 180:
        return image.transpose(Image.Transpose.ROTATE_180)
    if rotation == 270:
        return image.transpose(Image.Transpose.ROTATE_180)
    return image


def _apply_web_rotation(image, rotation):
    """Apply rotation for the web preview PNG.

    The web preview should match what the user physically sees on the display.
    * 0°   – landscape, show as-is
    * 90°  – portrait, show as-is (getbuffer + physical mount cancel)
    * 180° – landscape upside-down
    * 270° – portrait upside-down (getbuffer + physical mount cancel, image was flipped)
    """
    if rotation in (180, 270):
        return image.transpose(Image.Transpose.ROTATE_180)
    return image

logger = Logger(name="display.py", level=logging.DEBUG)

# Import button listener (only functional on Pi with GPIO)
try:
    from epd_button import EPDButtonListener, PAGE_MAIN, PAGE_NETWORK, PAGE_VULN, PAGE_DISCOVERED, PAGE_ADVANCED, PAGE_TRAFFIC
except ImportError:
    EPDButtonListener = None
    PAGE_MAIN, PAGE_NETWORK, PAGE_VULN, PAGE_DISCOVERED, PAGE_ADVANCED, PAGE_TRAFFIC = 0, 1, 2, 3, 4, 5

class Display:
    def __init__(self, shared_data):
        """Initialize the display and start the main image and shared data update threads."""
        self.shared_data = shared_data
        self.config = self.shared_data.config
        self.shared_data.ragnarstatustext2 = "Awakening..."
        self.commentaire_ia = Commentaireia()
        self.semaphore = threading.Semaphore(10)
        self.screen_reversed = self.shared_data.screen_reversed
        self.web_screen_reversed = self.shared_data.web_screen_reversed
        self.main_image = None  # Initialize main_image variable

        # Frise position (x=0 since frise is resized to full display width)
        self.frise_positions = {
            "default": {
                "x": 0,
                "y": 160
            }
        }

        try:
            self.epd_helper = self.shared_data.epd_helper
            # MAX7219, LCD1602 and other non-EPD displays set epd_helper to None;
            # skip EPD-specific init — their _run_* method handles setup.
            if self.epd_helper is not None:
                self.epd_helper.init_partial_update()
            logger.info("Display initialization complete.")
        except Exception as e:
            logger.error(f"Error during display initialization: {e}")
            raise

        self.main_image_thread = threading.Thread(target=self.update_main_image)
        self.main_image_thread.daemon = True
        self.main_image_thread.start()

        self.update_shared_data_thread = threading.Thread(target=self.schedule_update_shared_data)
        self.update_shared_data_thread.daemon = True
        self.update_shared_data_thread.start()

        self.update_vuln_count_thread = threading.Thread(target=self.schedule_update_vuln_count)
        self.update_vuln_count_thread.daemon = True
        self.update_vuln_count_thread.start()

        self.scale_factor_x = self.shared_data.scale_factor_x
        self.scale_factor_y = self.shared_data.scale_factor_y

        # Wide display detection (e.g. 2.7" at 176x264 vs reference 122x250)
        self.is_wide = self.scale_factor_x > 1.2
        # y_stretch is no longer needed — scale_factor_y handles vertical spacing
        self.y_stretch = 1.0

        # Hardware button support (2.7" HAT has KEY1-KEY4)
        self.button_listener = None
        if self.is_wide and EPDButtonListener is not None:
            self.button_listener = EPDButtonListener(shared_data)
            self.button_listener.start()

    def get_frise_position(self):
        """Get the frise position based on the display type."""
        display_type = self.config.get("epd_type", "default")
        position = self.frise_positions.get(display_type, self.frise_positions["default"])
        return (
            int(position["x"] * self.scale_factor_x),
            int(position["y"] * self.scale_factor_y)
        )

    def schedule_update_shared_data(self):
        """Periodically update the shared data with the latest system information."""
        while not self.shared_data.display_should_exit:
            self.update_shared_data()
            time.sleep(5)  # Check every 5 seconds for faster WiFi/SSH status updates

    def schedule_update_vuln_count(self):
        """Periodically update the vulnerability count on the display."""
        while not self.shared_data.display_should_exit:
            self.update_vuln_count()
            time.sleep(300)

    def update_main_image(self):
        """Update the main image on the display with the latest immagegen data."""
        while not self.shared_data.display_should_exit:
            try:
                self.shared_data.update_image_randomizer()
                if self.shared_data.imagegen:
                    self.main_image = self.shared_data.imagegen
                else:
                    logger.error("No image generated for current status.")
                time.sleep(random.uniform(self.shared_data.image_display_delaymin, self.shared_data.image_display_delaymax))
            except Exception as e:
                logger.error(f"An error occurred in update_main_image: {e}")

    def get_open_files(self):
        """Get the number of open FD files on the system."""
        try:
            open_files = len(glob.glob('/proc/*/fd/*'))
            logger.debug(f"FD : {open_files}")
            return open_files
        except Exception as e:
            logger.error(f"Error getting open files: {e}")
            return None
        
    def update_vuln_count(self):
        """Update the vulnerability count on the display."""
        import pandas as pd
        with self.semaphore:
            try:
                if not os.path.exists(self.shared_data.vuln_summary_file):
                    df = pd.DataFrame(columns=["IP", "Hostname", "MAC Address", "Port", "Vulnerabilities"])
                    df.to_csv(self.shared_data.vuln_summary_file, index=False)
                    self.shared_data.vulnnbr = 0
                    logger.info("Vulnerability summary file created.")
                else:
                    # Get alive hosts from SQLite database instead of CSV
                    try:
                        db_stats = self.shared_data.db.get_stats()
                        alive_hosts = self.shared_data.db.get_all_hosts()
                        alive_macs = {
                            h['mac'] for h in alive_hosts 
                            if h.get('status') == 'alive' and h.get('mac') != 'STANDALONE'
                        }
                        logger.debug(f"Loaded {len(alive_macs)} alive MACs from database")
                    except Exception as e:
                        logger.warning(f"Could not get alive MACs from database: {e}")
                        alive_macs = set()


                    try:
                        # Check if file is not empty and has content
                        if os.path.getsize(self.shared_data.vuln_summary_file) > 0:
                            with open(self.shared_data.vuln_summary_file, 'r') as file:
                                df = pd.read_csv(file)
                        else:
                            logger.debug("vuln_summary file is empty, initializing with empty DataFrame")
                            df = pd.DataFrame(columns=["IP", "Hostname", "MAC Address", "Port", "Vulnerabilities"])
                    except (pd.errors.EmptyDataError, pd.errors.ParserError) as e:
                        logger.warning(f"Could not parse vuln_summary file: {e}, creating new one")
                        df = pd.DataFrame(columns=["IP", "Hostname", "MAC Address", "Port", "Vulnerabilities"])
                        all_vulnerabilities = set()

                        for index, row in df.iterrows():
                            mac_address = row["MAC Address"]
                            if mac_address in alive_macs and mac_address != "STANDALONE":
                                vulnerabilities = row["Vulnerabilities"]
                                if pd.isna(vulnerabilities) or not isinstance(vulnerabilities, str):
                                    continue

                                if vulnerabilities and isinstance(vulnerabilities, str):
                                    all_vulnerabilities.update(vulnerabilities.split("; "))

                        self.shared_data.vulnnbr = len(all_vulnerabilities)
                        logger.debug(f"Updated vulnerabilities count: {self.shared_data.vulnnbr}")

                    if os.path.exists(self.shared_data.livestatusfile):
                        try:
                            # Check if file is not empty and has content
                            if os.path.getsize(self.shared_data.livestatusfile) > 0:
                                with open(self.shared_data.livestatusfile, 'r+') as livestatus_file:
                                    livestatus_df = pd.read_csv(livestatus_file)
                                    if not livestatus_df.empty:
                                        livestatus_df.loc[0, 'Vulnerabilities Count'] = self.shared_data.vulnnbr
                                        livestatus_df.to_csv(self.shared_data.livestatusfile, index=False)
                                        logger.debug(f"Updated livestatusfile with vulnerability count: {self.shared_data.vulnnbr}")
                            else:
                                logger.debug("livestatus file is empty, skipping update")
                        except (pd.errors.EmptyDataError, pd.errors.ParserError) as e:
                            logger.warning(f"Could not parse livestatus file: {e}")
                    else:
                        logger.error(f"Livestatusfile {self.shared_data.livestatusfile} does not exist.")
            except Exception as e:
                logger.error(f"An error occurred in update_vuln_count: {e}")

    def update_shared_data(self):
        """Update the shared data with the latest system information."""
        import pandas as pd
        with self.semaphore:
            try:
                # Create livestatus file if it doesn't exist
                if not os.path.exists(self.shared_data.livestatusfile):
                    logger.info(f"Creating missing livestatus file: {self.shared_data.livestatusfile}")
                    self.shared_data.create_livestatusfile()
                
                try:
                    # Check if file is not empty and has content
                    if os.path.getsize(self.shared_data.livestatusfile) > 0:
                        with open(self.shared_data.livestatusfile, 'r') as file:
                            livestatus_df = pd.read_csv(file)
                    else:
                        logger.warning("Livestatus file is empty, recreating it")
                        self.shared_data.create_livestatusfile()
                        with open(self.shared_data.livestatusfile, 'r') as file:
                            livestatus_df = pd.read_csv(file)
                except (pd.errors.EmptyDataError, pd.errors.ParserError) as e:
                    logger.warning(f"Could not parse livestatus file: {e}, recreating it")
                    self.shared_data.create_livestatusfile()
                    with open(self.shared_data.livestatusfile, 'r') as file:
                        livestatus_df = pd.read_csv(file)

                    # Check if DataFrame is empty or has the expected columns
                    if livestatus_df.empty:
                        logger.warning("Livestatus file is empty, skipping data update")
                        return

                    # Ensure required columns exist; add them with default 0 if missing
                    required_columns = ['Total Open Ports', 'Alive Hosts Count', 'All Known Hosts Count', 'Vulnerabilities Count']
                    for column in required_columns:
                        if column not in livestatus_df.columns:
                            logger.warning(f"Column '{column}' missing in livestatus file, initializing with 0")
                            livestatus_df[column] = 0

                    # Check if there's at least one row
                    if len(livestatus_df) == 0:
                        logger.warning("Livestatus file has no data rows, skipping data update")
                        return

                    def _safe_int_from_df(df, column_name):
                        try:
                            value = pd.to_numeric(df[column_name].iloc[0], errors='coerce')
                            if pd.isna(value):
                                return 0
                            return int(value)
                        except Exception as e:
                            logger.debug(f"Could not parse column '{column_name}' from livestatus file: {e}")
                            return 0

                    self.shared_data.portnbr = _safe_int_from_df(livestatus_df, 'Total Open Ports')
                    self.shared_data.targetnbr = _safe_int_from_df(livestatus_df, 'Alive Hosts Count')
                    self.shared_data.networkkbnbr = _safe_int_from_df(livestatus_df, 'All Known Hosts Count')
                    self.shared_data.vulnnbr = _safe_int_from_df(livestatus_df, 'Vulnerabilities Count')

                    # Persist any columns we added so other components stay in sync
                    try:
                        livestatus_df.to_csv(self.shared_data.livestatusfile, index=False)
                    except Exception as e:
                        logger.debug(f"Unable to persist normalized livestatus columns: {e}")

                crackedpw_files = glob.glob(f"{self.shared_data.crackedpwddir}/*.csv")

                total_passwords = 0
                for file in crackedpw_files:
                    try:
                        # Check if file is not empty and has content
                        if os.path.getsize(file) > 0:
                            with open(file, 'r') as f:
                                df = pd.read_csv(f, usecols=[0])
                                if not df.empty:
                                    total_passwords += len(df)
                        else:
                            logger.debug(f"Password file {file} is empty, skipping")
                    except (pd.errors.EmptyDataError, pd.errors.ParserError) as e:
                        logger.debug(f"Could not parse password file {file}: {e}")
                        continue
                    except Exception as e:
                        logger.warning(f"Error reading password file {file}: {e}")
                        continue

                self.shared_data.crednbr = total_passwords

                total_data = sum([len(files) for r, d, files in os.walk(self.shared_data.datastolendir)])
                self.shared_data.datanbr = total_data

                total_zombies = sum([len(files) for r, d, files in os.walk(self.shared_data.zombiesdir)])
                self.shared_data.zombiesnbr = total_zombies
                total_attacks = sum([len(files) for r, d, files in os.walk(self.shared_data.actions_dir) if not r.endswith("__pycache__")]) - 2

                self.shared_data.attacksnbr = total_attacks

                self.shared_data.update_stats()
                self.shared_data.manual_mode = self.is_manual_mode()
                if self.shared_data.manual_mode:
                    self.manual_mode_txt = "M"
                else:
                    self.manual_mode_txt = "A"
                
                # Check WiFi connectivity with detailed logging
                wifi_connected = self.is_wifi_connected()
                self.shared_data.wifi_connected = wifi_connected
                logger.info(f"[DISPLAY] WiFi status check: connected={wifi_connected}")

                signal_dbm, signal_quality = self.get_wifi_signal_strength() if wifi_connected else (None, None)
                self.shared_data.wifi_signal_dbm = signal_dbm
                self.shared_data.wifi_signal_quality = signal_quality
                if signal_dbm is not None:
                    logger.debug(f"[DISPLAY] WiFi RSSI: {signal_dbm} dBm, quality={self.shared_data.wifi_signal_quality}%")
                
                self.shared_data.ap_mode_active = self.is_ap_mode_active()
                self.shared_data.ap_client_count = self.get_ap_client_count() if self.shared_data.ap_mode_active else 0
                self.shared_data.usb_active = self.is_usb_connected()
                
                # Update Wi-Fi/AP status text for display
                wifi_status_text = self.get_wifi_status_text()
                self.shared_data.ragnarstatustext2 = wifi_status_text
                logger.info(f"[DISPLAY] WiFi status text: '{wifi_status_text}'")
                
                self.get_open_files()

            except (FileNotFoundError, pd.errors.EmptyDataError) as e:
                logger.error(f"Error: {e}")
            except Exception as e:
                logger.error(f"Error updating shared data: {e}")

    def display_comment(self, status):
        """Display the comment based on the status of the ragnarorch."""
        comment = self.commentaire_ia.get_commentaire(status)
        if comment:
            self.shared_data.ragnarsays = comment
            self.shared_data.ragnarstatustext = self.shared_data.ragnarorch_status
        else:
            pass

    # # # def is_bluetooth_connected(self):
    # # #     """
    # # #     Check if any device is connected to the Bluetooth (pan0) interface by checking the output of 'ip neigh show dev pan0'.
    # # #     """
    # # #     try:
    # # #         result = subprocess.Popen(['ip', 'neigh', 'show', 'dev', 'pan0'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # # #         output, error = result.communicate()
    # # #         if result.returncode != 0:
    # # #             logger.error(f"Error executing 'ip neigh show dev pan0': {error}")
    # # #             return False
    # # #         return bool(output.strip())
    # # #     except Exception as e:
    # # #         logger.error(f"Error checking Bluetooth connection status: {e}")
    # # #         return False

    def is_wifi_connected(self):
        """Check if WiFi is connected by checking the current SSID and network connectivity."""
        try:
            # Method 1: Try iwgetid first
            result = subprocess.Popen(['iwgetid', '-r'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            ssid, error = result.communicate()
            if result.returncode == 0 and ssid.strip():
                logger.debug(f"WiFi connected via iwgetid: SSID={ssid.strip()}")
                return True
            
            # Method 2: Check if we have an active network interface with IP
            result = subprocess.Popen(['ip', 'route', 'get', '8.8.8.8'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            route_output, error = result.communicate()
            if result.returncode == 0 and 'via' in route_output:
                logger.debug(f"WiFi connected via ip route check")
                return True
            
            # Method 3: Check for wlan interface with IP
            result = subprocess.Popen(['ip', 'addr', 'show'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            addr_output, error = result.communicate()
            if result.returncode == 0:
                # Look for wlan interfaces with inet addresses
                for line in addr_output.split('\n'):
                    if ('wlan' in line and 'state UP' in line) or ('inet ' in line and 'scope global' in line and ('wlan' in addr_output)):
                        logger.debug(f"WiFi connected via interface check")
                        return True
            
            logger.debug(f"WiFi not detected by any method")
            return False
            
        except Exception as e:
            logger.error(f"Error checking WiFi status: {e}")
            return False

    def _dbm_to_quality(self, signal_dbm):
        """Convert RSSI (dBm) to an approximate 0-100 quality percentage."""
        if signal_dbm is None:
            return None

        quality = int((signal_dbm - (-90)) * 100 / (-30 - (-90)))
        return max(0, min(100, quality))

    def get_wifi_signal_strength(self):
        """Return a tuple (signal_dbm, quality_percent) if available."""
        # Primary method: use `iw dev wlan0 link`
        try:
            result = subprocess.run(['iw', 'dev', 'wlan0', 'link'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'signal:' in line:
                        try:
                            raw_value = line.split('signal:')[1].split('dBm')[0].strip()
                            signal_dbm = float(raw_value)
                            return signal_dbm, self._dbm_to_quality(signal_dbm)
                        except (ValueError, IndexError):
                            logger.debug(f"Failed to parse iw signal line: {line.strip()}")
                        break
        except FileNotFoundError:
            logger.debug("`iw` command not available for wifi strength measurement")
        except subprocess.TimeoutExpired:
            logger.debug("Timeout while fetching wifi strength via iw")
        except Exception as e:
            logger.debug(f"Unexpected error while using iw for wifi strength: {e}")

        # Fallback: use `iwconfig`
        try:
            result = subprocess.run(['iwconfig', 'wlan0'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                quality = None
                signal_dbm = None
                for line in result.stdout.split('\n'):
                    if 'Link Quality' in line:
                        try:
                            quality_part = line.split('Link Quality=')[1].split(' ')[0]
                            if '/' in quality_part:
                                numerator, denominator = quality_part.split('/')
                                quality = int(float(numerator) / float(denominator) * 100)
                        except (ValueError, IndexError):
                            logger.debug(f"Failed to parse Link Quality line: {line.strip()}")
                    if 'Signal level' in line:
                        try:
                            signal_part = line.split('Signal level=')[1].split(' ')[0]
                            if '/' in signal_part:
                                signal_part = signal_part.split('/')[0]
                            signal_dbm = float(signal_part.replace('dBm', ''))
                        except (ValueError, IndexError):
                            logger.debug(f"Failed to parse Signal level line: {line.strip()}")

                if signal_dbm is not None or quality is not None:
                    if quality is None:
                        quality = self._dbm_to_quality(signal_dbm)
                    if signal_dbm is None and quality is not None:
                        # approximate dbm from quality if needed
                        signal_dbm = (quality / 100) * (-30 - (-90)) + (-90)
                    return signal_dbm, quality
        except FileNotFoundError:
            logger.debug("`iwconfig` command not available for wifi strength measurement")
        except subprocess.TimeoutExpired:
            logger.debug("Timeout while fetching wifi strength via iwconfig")
        except Exception as e:
            logger.debug(f"Unexpected error while using iwconfig for wifi strength: {e}")

        return None, None

    def get_wifi_wave_count(self, quality):
        """Translate a 0-100 quality value into 0-4 wave arcs."""
        if quality is None:
            return 0

        thresholds = [8, 28, 52, 70]
        waves = 0
        for threshold in thresholds:
            if quality >= threshold:
                waves += 1
        return waves

    def render_wifi_wave_indicator(self, image, draw):
        """Render a live Wi-Fi indicator using wave arcs with no dBm text."""
        _sx = getattr(self, 'render_sx', self.scale_factor_x)
        _sy = getattr(self, 'render_sy', self.scale_factor_y)
        base_x = int(3 * _sx)
        base_y = int(8 * _sy)
        scale = min(_sx, _sy)
        signal_dbm = getattr(self.shared_data, 'wifi_signal_dbm', None)
        raw_quality = getattr(self.shared_data, 'wifi_signal_quality', None)
        effective_quality = raw_quality if raw_quality is not None else self._dbm_to_quality(signal_dbm)
        ip_last_octet = self.get_wifi_ip_last_octet()

        waves = self.get_wifi_wave_count(effective_quality)
        if waves <= 0:
            waves = 1  # Always show at least one wave when connected

        base_radius = max(2, int(1.5 * scale))
        wave_spacing = max(2, int(2.5 * scale) + 2)
        line_width = max(1, int(scale) + 1)

        center_x = base_x + base_radius + wave_spacing * 2
        center_y = base_y + base_radius + wave_spacing * 2

        # Draw expanding arcs to mimic Wi-Fi waves
        for i in range(waves):
            radius = max(2, base_radius + (i + 1) * wave_spacing - 4)
            bbox = (
                center_x - radius,
                center_y - radius,
                center_x + radius,
                center_y + radius
            )
            draw.arc(bbox, start=225, end=315, fill=0, width=line_width)

        if ip_last_octet:
            text_x = center_x + wave_spacing + base_radius
            text_y = center_y - base_radius - max(1, int(6 * _sy))
            draw.text((text_x, text_y), ip_last_octet, font=self.shared_data.font_arial9, fill=0)

    def get_wifi_ip_last_octet(self):
        """Get the last octet of the WiFi IP address (e.g., '.211' from '192.168.1.211')."""
        try:
            # Get IP address of wlan0 interface
            result = subprocess.run(['ip', '-4', 'addr', 'show', 'wlan0'], 
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                # Parse the output to find the IP address
                for line in result.stdout.split('\n'):
                    if 'inet ' in line:
                        # Extract IP address (format: "inet 192.168.1.211/24 ...")
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            ip_with_mask = parts[1]
                            ip_address = ip_with_mask.split('/')[0]
                            # Get the last octet
                            octets = ip_address.split('.')
                            if len(octets) == 4:
                                return f".{octets[3]}"
            return None
        except Exception as e:
            logger.error(f"Error getting WiFi IP address: {e}")
            return None

    def is_ap_mode_active(self):
        """Check if AP mode is currently active."""
        try:
            # Check if hostapd is running
            result = subprocess.run(['pgrep', 'hostapd'], capture_output=True, text=True)
            if result.returncode == 0:
                return True
            
            # Alternative check: see if we're listening on AP interface
            result = subprocess.run(['ip', 'addr', 'show', 'wlan0'], capture_output=True, text=True)
            if result.returncode == 0 and '192.168.4.1' in result.stdout:
                return True
                
            return False
        except Exception as e:
            logger.error(f"Error checking AP mode status: {e}")
            return False

    def get_ap_client_count(self):
        """Get the number of clients connected to AP mode."""
        try:
            # Try to get from WiFi manager first
            if (hasattr(self.shared_data, 'ragnar_instance') and 
                self.shared_data.ragnar_instance and 
                hasattr(self.shared_data.ragnar_instance, 'wifi_manager')):
                
                wifi_mgr = self.shared_data.ragnar_instance.wifi_manager
                if hasattr(wifi_mgr, 'ap_clients_count'):
                    return wifi_mgr.ap_clients_count
            
            # Fallback to hostapd_cli
            result = subprocess.run(['hostapd_cli', '-i', 'wlan0', 'list_sta'], 
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                clients = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                return len(clients)
            
            return 0
        except Exception as e:
            logger.error(f"Error getting AP client count: {e}")
            return 0

    def get_wifi_status_text(self):
        """Get descriptive text for current Wi-Fi status."""
        try:
            # FIRST: Try system-level WiFi detection (most reliable)
            # Method 1: Try iwgetid first (get SSID if available)
            try:
                result = subprocess.run(['iwgetid', '-r'], capture_output=True, text=True, timeout=2)
                if result.returncode == 0 and result.stdout.strip():
                    ssid = result.stdout.strip()
                    logger.debug(f"[STATUS] WiFi connected via iwgetid: SSID={ssid}")
                    return f"WiFi: {ssid}"
            except Exception:
                pass
            
            # Method 2: Check if we have network connectivity (WiFi without SSID)
            try:
                result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'], 
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0 and 'via' in result.stdout:
                    logger.debug(f"[STATUS] WiFi connected via ip route check")
                    return "WiFi: Connected"
            except Exception:
                pass
            
            # Method 3: Check for wlan interface with IP
            try:
                result = subprocess.run(['ip', 'addr', 'show'], 
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    # Look for wlan interfaces with inet addresses
                    for line in result.stdout.split('\n'):
                        if ('wlan' in line and 'state UP' in line) or ('inet ' in line and 'scope global' in line and ('wlan' in result.stdout)):
                            logger.debug(f"[STATUS] WiFi connected via interface check")
                            return "WiFi: Connected"
            except Exception:
                pass
            
            # SECONDARY: Try to get status from WiFi manager (if available in same process)
            if (hasattr(self.shared_data, 'ragnar_instance') and 
                self.shared_data.ragnar_instance and 
                hasattr(self.shared_data.ragnar_instance, 'wifi_manager')):
                
                wifi_mgr = self.shared_data.ragnar_instance.wifi_manager
                
                # Check AP mode status first
                if hasattr(wifi_mgr, 'ap_mode_active') and wifi_mgr.ap_mode_active:
                    # Try to get client count
                    client_count = 0
                    if hasattr(wifi_mgr, 'ap_clients_count'):
                        client_count = wifi_mgr.ap_clients_count
                    
                    if client_count > 0:
                        return f"AP: {client_count} client{'s' if client_count != 1 else ''}"
                    else:
                        return "AP: No clients"
                
                # Check Wi-Fi connection status
                if hasattr(wifi_mgr, 'wifi_connected') and wifi_mgr.wifi_connected:
                    if hasattr(wifi_mgr, 'current_ssid') and wifi_mgr.current_ssid:
                        return f"WiFi: {wifi_mgr.current_ssid}"
                    else:
                        return "WiFi: Connected"
                
                # Check if cycling mode is active
                if hasattr(wifi_mgr, 'cycling_mode') and wifi_mgr.cycling_mode:
                    return "WiFi: Cycling"
            
            # TERTIARY: Check if we're in AP mode at system level
            if self.is_ap_mode_active():
                # Try to get AP client count
                try:
                    result = subprocess.run(['hostapd_cli', '-i', 'wlan0', 'list_sta'], 
                                          capture_output=True, text=True, timeout=2)
                    if result.returncode == 0:
                        clients = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                        client_count = len(clients)
                        if client_count > 0:
                            return f"AP: {client_count} client{'s' if client_count != 1 else ''}"
                        else:
                            return "AP: No clients"
                    else:
                        return "AP: Active"
                except Exception:
                    return "AP: Active"
            
            logger.debug(f"[STATUS] WiFi not detected by any method")
            return "WiFi: Disconnected"
            
        except Exception as e:
            logger.error(f"Error getting WiFi status text: {e}")
            return "WiFi: Unknown"

    def is_manual_mode(self):
        """Check if the ragnarorch is in manual mode."""
        return self.shared_data.manual_mode

    def is_interface_connected(self, interface):
        """Check if any device is connected to the specified interface."""
        try:
            result = subprocess.Popen(['ip', 'neigh', 'show', 'dev', interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output, error = result.communicate()
            if result.returncode != 0:
                logger.error(f"Error executing 'ip neigh show dev {interface}': {error}")
                return False
            return bool(output.strip())
        except Exception as e:
            logger.error(f"Error checking connection status on {interface}: {e}")
            return False

    def is_usb_connected(self):
        """Check if any device is connected to the USB interface."""
        try:
            result = subprocess.Popen(['ip', 'neigh', 'show', 'dev', 'usb0'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output, error = result.communicate()
            if result.returncode != 0:
                logger.error(f"Error executing 'ip neigh show dev usb0': {error}")
                return False
            return bool(output.strip())
        except Exception as e:
            logger.error(f"Error checking USB connection status: {e}")
            return False

    def _sleep_interruptible(self, current_page):
        """Sleep for screen_delay but wake early if button changes the page."""
        if not self.button_listener:
            time.sleep(self.shared_data.screen_delay)
            return
        # Check every 0.1s if page changed, otherwise do full sleep
        steps = max(1, int(self.shared_data.screen_delay / 0.1))
        for _ in range(steps):
            if self.button_listener.current_page != current_page:
                return  # Page changed, skip remaining sleep
            time.sleep(0.1)

    def _get_cached_page_data(self, key, fetch_fn, ttl=10):
        """Get cached page data, refreshing if older than ttl seconds."""
        if not hasattr(self, '_page_cache'):
            self._page_cache = {}
        now = time.time()
        cached = self._page_cache.get(key)
        if cached and (now - cached[0]) < ttl:
            return cached[1]
        try:
            data = fetch_fn()
        except Exception as e:
            logger.debug(f"Page data fetch error ({key}): {e}")
            data = cached[1] if cached else None
        self._page_cache[key] = (now, data)
        return data

    def _draw_page_frame(self, draw, title):
        """Draw standard page frame: border, title, divider, footer."""
        w = getattr(self, 'render_w', self.shared_data.width)
        h = getattr(self, 'render_h', self.shared_data.height)
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        font = self.shared_data.font_arial9
        font_title = self.shared_data.font_viking
        draw.rectangle((1, 1, w - 1, h - 1), outline=0)
        draw.text((int(4 * sx), int(4 * sy)), title, font=font_title, fill=0)
        draw.line((1, int(22 * sy), w - 1, int(22 * sy)), fill=0)
        draw.line((1, h - int(18 * sy), w - 1, h - int(18 * sy)), fill=0)
        draw.text((int(4 * sx), h - int(16 * sy)), "K1:Home K2:Flip K3:Next K4:Rst", font=font, fill=0)

    def _draw_stat_rows(self, draw, y, stats):
        """Draw key-value stat rows. Returns final y position."""
        w = getattr(self, 'render_w', self.shared_data.width)
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        font = self.shared_data.font_arial9
        line_h = int(14 * sy)
        pad_x = int(6 * sx)
        for label, value in stats:
            val_str = str(value)[:22]
            draw.text((pad_x, y), label, font=font, fill=0)
            draw.text((w - pad_x - font.getlength(val_str), y), val_str, font=font, fill=0)
            y += line_h
        return y

    def _fetch_network_data(self):
        """Fetch real host data from database."""
        sd = self.shared_data
        try:
            hosts = sd.db.get_all_hosts()
            alive = [h for h in hosts if h.get('status') == 'alive']
            total_ports = 0
            for h in hosts:
                ports_str = h.get('ports', '')
                if ports_str:
                    total_ports += len([p for p in str(ports_str).split(';') if p.strip()])
            return {
                'total': len(hosts),
                'alive': len(alive),
                'ports': total_ports,
                'hosts': hosts[:8],
            }
        except Exception as e:
            logger.debug(f"DB host fetch error: {e}")
            return None

    def _fetch_vuln_intel_data(self):
        """Fetch real vulnerability intelligence from scan files."""
        sd = self.shared_data
        vuln_dir = getattr(sd, 'vulnerabilities_dir', None)
        if not vuln_dir or not os.path.exists(vuln_dir):
            return None
        scans = 0
        hosts_set = set()
        services = 0
        scripts = 0
        recent_targets = []
        try:
            for fname in os.listdir(vuln_dir):
                fpath = os.path.join(vuln_dir, fname)
                if not os.path.isfile(fpath):
                    continue
                if fname.endswith('_vuln_scan.txt'):
                    scans += 1
                    ip = fname.split('_')[0] if '_' in fname else fname
                    hosts_set.add(ip)
                    if len(recent_targets) < 5:
                        recent_targets.append(ip)
                    try:
                        with open(fpath, 'r', errors='ignore') as f:
                            content = f.read()
                        for line in content.split('\n'):
                            if '/tcp' in line or '/udp' in line:
                                services += 1
                            if '|' in line and '_' in line:
                                scripts += 1
                    except Exception:
                        pass
                elif fname.startswith('lynis_') and fname.endswith('_pentest.txt'):
                    scans += 1
                    parts = fname.replace('lynis_', '').replace('_pentest.txt', '')
                    hosts_set.add(parts)
        except Exception as e:
            logger.debug(f"Vuln intel scan error: {e}")
        return {
            'scans': scans,
            'hosts': len(hosts_set),
            'services': services,
            'scripts': scripts,
            'targets': recent_targets,
        }

    def _count_cred_file(self, filepath):
        """Count credential entries in a CSV file."""
        try:
            if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
                return 0
            with open(filepath, 'r') as f:
                reader = csv.reader(f)
                next(reader, None)  # skip header
                return sum(1 for row in reader if row)
        except Exception:
            return 0

    def _fetch_discovered_data(self):
        """Fetch real credentials, loot, and attack data."""
        sd = self.shared_data
        creds = {}
        for svc, attr in [('SSH', 'sshfile'), ('SMB', 'smbfile'), ('FTP', 'ftpfile'),
                          ('Telnet', 'telnetfile'), ('RDP', 'rdpfile'), ('SQL', 'sqlfile')]:
            filepath = getattr(sd, attr, '')
            creds[svc] = self._count_cred_file(filepath) if filepath else 0
        total_creds = sum(creds.values())
        loot_count = 0
        try:
            if os.path.exists(sd.datastolendir):
                for _, _, files in os.walk(sd.datastolendir):
                    loot_count += len([f for f in files if not f.endswith('.log')])
        except Exception:
            pass
        attack_count = 0
        try:
            attacks_dir = os.path.join(sd.logsdir, 'attacks')
            if os.path.exists(attacks_dir):
                import json as json_mod
                for fname in os.listdir(attacks_dir):
                    if fname.endswith('.json'):
                        try:
                            with open(os.path.join(attacks_dir, fname), 'r') as f:
                                data = json_mod.load(f)
                            if isinstance(data, list):
                                attack_count += len(data)
                        except Exception:
                            pass
        except Exception:
            pass
        return {
            'creds': creds,
            'total_creds': total_creds,
            'loot': loot_count,
            'attacks': attack_count,
            'zombies': getattr(sd, 'zombiesnbr', 0),
        }

    def _fetch_advanced_data(self):
        """Fetch real advanced vulnerability scanner data."""
        scanner = getattr(self.shared_data, '_advanced_vuln_scanner', None)
        if not scanner:
            return None
        try:
            available = scanner.get_available_scanners()
            summary = scanner.get_summary()
            active = scanner.get_active_scans_list()
            return {
                'scanners': available,
                'summary': summary,
                'active_scans': active,
            }
        except Exception as e:
            logger.debug(f"Advanced scanner data error: {e}")
            return None

    def _fetch_traffic_data(self):
        """Fetch real traffic analyzer data."""
        analyzer = getattr(self.shared_data, '_traffic_analyzer', None)
        if not analyzer:
            return None
        try:
            summary = analyzer.get_summary()
            return summary
        except Exception as e:
            logger.debug(f"Traffic analyzer data error: {e}")
            return None

    def _render_network_page(self, image, draw):
        """Render Page 2: Network Scanner - real host data from database."""
        self._draw_page_frame(draw, "NETWORK SCAN")
        w = getattr(self, 'render_w', self.shared_data.width)
        h = getattr(self, 'render_h', self.shared_data.height)
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        font = self.shared_data.font_arial9
        sd = self.shared_data
        y = int(28 * sy)
        line_h = int(14 * sy)
        pad_x = int(6 * sx)
        row_h = int(12 * sy)

        data = self._get_cached_page_data('network', self._fetch_network_data)

        if data:
            stats = [
                ("Hosts alive", f"{data['alive']}/{data['total']}"),
                ("Open ports", str(data['ports'])),
                ("Credentials", str(getattr(sd, 'crednbr', 0))),
                ("Status", str(getattr(sd, 'ragnarorch_status', 'IDLE'))),
            ]
            y = self._draw_stat_rows(draw, y, stats)

            # Divider before host list
            y += int(2 * sy)
            draw.line((int(4 * sx), y, w - int(4 * sx), y), fill=0)
            y += int(4 * sy)

            # List actual discovered hosts
            hosts = data.get('hosts', [])
            max_rows = (h - int(18 * sy) - y) // row_h
            for host in hosts[:max_rows]:
                ip = host.get('ip', '?')
                status = host.get('status', '?')
                ports = host.get('ports', '')
                port_count = len([p for p in str(ports).split(';') if p.strip()]) if ports else 0
                line = f"{ip}"
                extra = f"{status[:3]} p:{port_count}"
                draw.text((pad_x, y), line, font=font, fill=0)
                draw.text((w - pad_x - font.getlength(extra), y), extra, font=font, fill=0)
                y += row_h
        else:
            stats = [
                ("Hosts found", str(getattr(sd, 'targetnbr', 0))),
                ("Open ports", str(getattr(sd, 'portnbr', 0))),
                ("Credentials", str(getattr(sd, 'crednbr', 0))),
                ("Network KB", str(getattr(sd, 'networkkbnbr', 0))),
                ("Status", str(getattr(sd, 'ragnarorch_status', 'IDLE'))),
            ]
            self._draw_stat_rows(draw, y, stats)

    def _render_vuln_page(self, image, draw):
        """Render Page 3: Vulnerability Scanner - real scan intel from files."""
        self._draw_page_frame(draw, "VULN INTEL")
        w = getattr(self, 'render_w', self.shared_data.width)
        h = getattr(self, 'render_h', self.shared_data.height)
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        font = self.shared_data.font_arial9
        sd = self.shared_data
        y = int(28 * sy)
        row_h = int(12 * sy)
        pad_x = int(6 * sx)

        data = self._get_cached_page_data('vuln_intel', self._fetch_vuln_intel_data, ttl=30)

        if data:
            stats = [
                ("Vulns found", str(getattr(sd, 'vulnnbr', 0))),
                ("Scan reports", str(data['scans'])),
                ("Hosts scanned", str(data['hosts'])),
                ("Services", str(data['services'])),
                ("Script outputs", str(data['scripts'])),
            ]
            y = self._draw_stat_rows(draw, y, stats)

            # Show recent scan targets
            targets = data.get('targets', [])
            if targets:
                y += int(2 * sy)
                draw.line((int(4 * sx), y, w - int(4 * sx), y), fill=0)
                y += int(4 * sy)
                draw.text((pad_x, y), "Recent targets:", font=font, fill=0)
                y += row_h
                max_rows = (h - int(18 * sy) - y) // row_h
                for ip in targets[:max_rows]:
                    draw.text((int(10 * sx), y), ip, font=font, fill=0)
                    y += row_h
        else:
            stats = [
                ("Vulns found", str(getattr(sd, 'vulnnbr', 0))),
                ("Attacks avail", str(getattr(sd, 'attacksnbr', 0))),
                ("Hosts scanned", str(getattr(sd, 'targetnbr', 0))),
                ("No scan files", ""),
            ]
            self._draw_stat_rows(draw, y, stats)

    def _render_discovered_page(self, image, draw):
        """Render Page 4: Discovered - real credentials, loot, and attack data."""
        self._draw_page_frame(draw, "DISCOVERED")
        w = getattr(self, 'render_w', self.shared_data.width)
        h = getattr(self, 'render_h', self.shared_data.height)
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        font = self.shared_data.font_arial9
        y = int(28 * sy)

        data = self._get_cached_page_data('discovered', self._fetch_discovered_data, ttl=15)

        if data:
            creds = data['creds']
            stats = [
                ("SSH creds", str(creds.get('SSH', 0))),
                ("SMB creds", str(creds.get('SMB', 0))),
                ("FTP creds", str(creds.get('FTP', 0))),
                ("Telnet", str(creds.get('Telnet', 0))),
                ("RDP creds", str(creds.get('RDP', 0))),
                ("SQL creds", str(creds.get('SQL', 0))),
            ]
            y = self._draw_stat_rows(draw, y, stats)
            y += int(2 * sy)
            draw.line((int(4 * sx), y, w - int(4 * sx), y), fill=0)
            y += int(4 * sy)
            summary = [
                ("Data stolen", f"{data['loot']} files"),
                ("Attack logs", str(data['attacks'])),
                ("Zombies", str(data['zombies'])),
            ]
            self._draw_stat_rows(draw, y, summary)
        else:
            stats = [
                ("Credentials", str(getattr(self.shared_data, 'crednbr', 0))),
                ("Data files", str(getattr(self.shared_data, 'datanbr', 0))),
                ("Zombies", str(getattr(self.shared_data, 'zombiesnbr', 0))),
            ]
            self._draw_stat_rows(draw, y, stats)

    def _render_advanced_page(self, image, draw):
        """Render Page 5: Advanced Vuln Scanner - real scanner status and findings."""
        self._draw_page_frame(draw, "ADV SCANNER")
        w = getattr(self, 'render_w', self.shared_data.width)
        h = getattr(self, 'render_h', self.shared_data.height)
        sx = getattr(self, 'render_sx', self.scale_factor_x)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        font = self.shared_data.font_arial9
        y = int(28 * sy)
        line_h = int(14 * sy)
        row_h = int(12 * sy)
        pad_x = int(6 * sx)

        data = self._get_cached_page_data('advanced', self._fetch_advanced_data, ttl=5)

        if data:
            scanners = data.get('scanners', {})
            summary = data.get('summary', {})
            active = data.get('active_scans', [])
            sev = summary.get('severity_counts', {})

            # Scanner availability
            scanner_items = []
            for name in ['nuclei', 'nikto', 'zap']:
                if name == 'zap':
                    running = scanners.get('zap_running', False)
                    status = "Running" if running else ("Ready" if scanners.get(name) else "N/A")
                else:
                    status = "Ready" if scanners.get(name) else "N/A"
                scanner_items.append((name.capitalize(), status))

            for label, value in scanner_items:
                draw.text((pad_x, y), label, font=font, fill=0)
                draw.text((w - pad_x - font.getlength(value), y), value, font=font, fill=0)
                y += line_h

            y += int(2 * sy)
            draw.line((int(4 * sx), y, w - int(4 * sx), y), fill=0)
            y += int(4 * sy)

            # Findings summary
            total = summary.get('total_findings', 0)
            draw.text((pad_x, y), "Findings", font=font, fill=0)
            draw.text((w - pad_x - font.getlength(str(total)), y), str(total), font=font, fill=0)
            y += line_h

            # Severity breakdown on one line each
            crit = sev.get('critical', 0)
            high = sev.get('high', 0)
            med = sev.get('medium', 0)
            low = sev.get('low', 0)
            sev_line = f"C:{crit} H:{high} M:{med} L:{low}"
            draw.text((pad_x, y), sev_line, font=font, fill=0)
            y += line_h

            # Active scans
            active_count = len([s for s in active if s.get('status') == 'running'])
            draw.text((pad_x, y), "Active scans", font=font, fill=0)
            draw.text((w - pad_x - font.getlength(str(active_count)), y), str(active_count), font=font, fill=0)
            y += line_h

            # Show running scan details
            for scan in active:
                if scan.get('status') == 'running' and y < h - int(32 * sy):
                    stype = scan.get('scan_type', '?')[:8]
                    progress = scan.get('progress_percent', 0)
                    line = f"{stype} {progress}%"
                    draw.text((int(10 * sx), y), line, font=font, fill=0)
                    y += row_h
        else:
            stats = [
                ("Scanner", "Not available"),
                ("Vulns found", str(getattr(self.shared_data, 'vulnnbr', 0))),
                ("Status", str(getattr(self.shared_data, 'ragnarstatustext', 'IDLE'))),
            ]
            self._draw_stat_rows(draw, y, stats)

    def _render_traffic_page(self, image, draw):
        """Render Page 6: Traffic Analysis - real capture data."""
        self._draw_page_frame(draw, "TRAFFIC")
        w = getattr(self, 'render_w', self.shared_data.width)
        h = getattr(self, 'render_h', self.shared_data.height)
        sy = getattr(self, 'render_sy', self.scale_factor_y)
        font = self.shared_data.font_arial9
        y = int(28 * sy)

        data = self._get_cached_page_data('traffic', self._fetch_traffic_data, ttl=3)

        if data:
            status = data.get('status', 'stopped')
            pkts_sec = data.get('packets_per_second', 0)
            throughput = data.get('throughput_mbps', 0)
            total_pkts = data.get('total_packets', 0)
            total_bytes_h = data.get('total_bytes_human', '0 B')
            unique_hosts = data.get('unique_hosts', 0)
            connections = data.get('active_connections', 0)
            alerts = data.get('total_alerts', 0)
            dns = data.get('dns_queries_captured', 0)

            status_str = status.upper()
            stats = [
                ("Capture", status_str),
                ("Pkts/sec", f"{pkts_sec:.1f}"),
                ("Throughput", f"{throughput:.2f} Mbps"),
                ("Total pkts", str(total_pkts)),
                ("Total data", str(total_bytes_h)),
                ("Hosts seen", str(unique_hosts)),
                ("Connections", str(connections)),
                ("Alerts", str(alerts)),
                ("DNS queries", str(dns)),
            ]
            self._draw_stat_rows(draw, y, stats)
        else:
            stats = [
                ("Traffic", "Not available"),
                ("WiFi", "On" if self.shared_data.wifi_connected else "Off"),
                ("Status", str(getattr(self.shared_data, 'ragnarorch_status', 'IDLE'))),
            ]
            self._draw_stat_rows(draw, y, stats)

    # ------------------------------------------------------------------
    # GC9A01 round-display renderer
    # ------------------------------------------------------------------

    def _run_gc9a01(self):
        """Dedicated render loop for the GC9A01 1.28″ round colour TFT.

        Animates the existing e-paper BMP frame sequences (resources/images/status/)
        in full colour on the round display, cycling at ~1 fps.  Each status has
        its own tint colour so the mascot visually reflects what Ragnar is doing.

        Layout (240×240 circle):
          ┌──────────────────────┐
          │     RAGNAR  (title)  │  y≈8  – white, Viking font
          │   ┌──────────────┐   │
          │   │  mascot anim │   │  y≈30–175 – tinted BMP frames, animated
          │   └──────────────┘   │
          │   ── STATUS TEXT ──  │  y≈182 – coloured by state
          │      wifi ssid       │  y≈207 – white/dim
          └──────────────────────┘
        Outer ring colour: green=connected, cyan=scanning, amber=AP, red=error/offline
        """
        from PIL import Image as _Image, ImageDraw as _ImageDraw, ImageFont as _ImageFont, ImageOps as _ImageOps

        SIZE       = 240
        MASCOT_SZ  = 140   # px — upscaled from 78×78 source
        ANIM_TICKS = 2     # loop ticks per frame advance (tick = 0.5 s → 1 s/frame)
        TICK_SLEEP = 0.5   # seconds per tick

        # ── colour palette ───────────────────────────────────────────────
        C_BG    = (0,   0,   0)
        C_WHITE = (255, 255, 255)
        C_GRAY  = (160, 160, 160)
        C_GREEN = (50,  200,  80)
        C_RED   = (220,  50,  50)
        C_CYAN  = (0,   200, 220)
        C_AMBER = (220, 160,   0)
        RING_W  = 6

        # Mascot tint colours keyed by partial status name
        TINT_MAP = {
            "IDLE":          (150, 200, 255),  # soft blue
            "NetworkScanner":(0,   220, 220),  # cyan
            "NmapVuln":      (0,   220, 220),  # cyan
            "SSHBrute":      (255,  80,  80),  # red
            "SMBBrute":      (255,  80,  80),
            "FTPBrute":      (255,  80,  80),
            "RDPBrute":      (255,  80,  80),
            "TelnetBrute":   (255,  80,  80),
            "SQLBrute":      (255, 120,  60),
            "StealFiles":    (255, 160,  40),  # amber
            "StealData":     (255, 160,  40),
            "LogStandalone": (180, 180, 180),  # gray
        }

        def _tint_for(status):
            s = status or "IDLE"
            for key, col in TINT_MAP.items():
                if key.lower() in s.lower():
                    return col
            return C_WHITE

        # ── fonts ────────────────────────────────────────────────────────
        fonts_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources", "fonts")
        arial_path  = os.path.join(fonts_dir, "Arial.ttf")
        viking_path = os.path.join(fonts_dir, "Creamy.ttf")
        try:
            font_title  = _ImageFont.truetype(viking_path, 22)
            font_ssid   = _ImageFont.truetype(arial_path,  14)
            _font_status_cache = {}
            def _status_font(text, max_px=200):
                """Return the largest font that fits `text` within max_px."""
                # At y=182 the circle chord is narrower than the full 240px diameter.
                # Compute usable width: 2*sqrt(r^2 - (y - cx)^2) minus ring border.
                import math
                _r, _cx, _cy = 120, 120, 120
                _chord = 2 * math.sqrt(max(0, _r**2 - (182 - _cy)**2))
                max_px = min(max_px, int(_chord) - 2 * RING_W - 8)  # 8px safety margin
                for size in (18, 16, 14, 12, 11, 10, 9):
                    if size not in _font_status_cache:
                        try:
                            _font_status_cache[size] = _ImageFont.truetype(arial_path, size)
                        except Exception:
                            _font_status_cache[size] = _ImageFont.load_default()
                    f = _font_status_cache[size]
                    try:
                        w = f.getbbox(text)[2] - f.getbbox(text)[0]
                    except Exception:
                        w = len(text) * size
                    if w <= max_px:
                        return f
                return _font_status_cache.get(9, _ImageFont.load_default())
        except Exception:
            font_title = font_ssid = _ImageFont.load_default()
            def _status_font(text, max_px=200):
                return _ImageFont.load_default()

        # ── mascot tint colour (user-configurable via web UI) ────────────
        def _parse_hex(hex_str, fallback=(150, 200, 255)):
            try:
                h = hex_str.lstrip("#")
                return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))
            except Exception:
                return fallback

        def _mascot_tint():
            """Return current tint RGB, re-read from config each call so live
            web-UI changes take effect without restarting the service."""
            return _parse_hex(self.config.get("gc9a01_mascot_color", "#96C8FF"))

        # ── frame cache: (status, frame_idx, tint) → RGBA sprite ─────────
        _frame_cache = {}

        def _get_colorized_frame(status, idx, tint):
            key = (status, idx, tint)
            if key in _frame_cache:
                return _frame_cache[key]
            series = getattr(self.shared_data, "image_series", {})
            frames = series.get(status) or series.get("IDLE") or []
            if not frames:
                _frame_cache[key] = None
                return None
            src = frames[idx % len(frames)]
            tint = _tint_for(status)
            try:
                gray  = src.convert("L").resize((MASCOT_SZ, MASCOT_SZ), _Image.LANCZOS)
                alpha = _ImageOps.invert(gray)   # dark pixels → opaque, white → transparent
                sprite = _Image.new("RGBA", (MASCOT_SZ, MASCOT_SZ), tint + (255,))
                sprite.putalpha(alpha)
                _frame_cache[key] = sprite
            except Exception as exc:
                logger.debug("GC9A01: colorize error: %s", exc)
                _frame_cache[key] = None
            return _frame_cache[key]

        def _frame_count(status):
            series = getattr(self.shared_data, "image_series", {})
            frames = series.get(status) or series.get("IDLE") or []
            return max(1, len(frames))

        # ── state helpers ─────────────────────────────────────────────────
        def _text_state():
            sd = self.shared_data
            net_text = getattr(sd, "ragnarstatustext2", "") or ""
            return (
                getattr(sd, "wifi_connected",   False),
                net_text,
                getattr(sd, "ap_mode_active",   False),
                getattr(sd, "ragnarstatustext", "IDLE"),
            )

        def _ring_col(wifi_on, ap_on, status):
            if ap_on:            return C_AMBER
            if not wifi_on:      return C_RED
            s = (status or "").upper()
            if any(k in s for k in ("SCAN", "BRUTE", "STEAL", "INJECT")): return C_CYAN
            if any(k in s for k in ("ERROR", "FAIL")):                     return C_RED
            return C_GREEN

        def _status_col(wifi_on, ap_on, status):
            if ap_on:            return C_AMBER
            if not wifi_on:      return C_RED
            s = (status or "").upper()
            if any(k in s for k in ("SCAN", "BRUTE", "STEAL", "INJECT")): return C_CYAN
            if any(k in s for k in ("ERROR", "FAIL")):                     return C_RED
            return C_GREEN

        def _render(wifi_on, ssid, ap_on, status_text, mascot_rgba, info_label, info_col):
            import math as _math
            img  = _Image.new("RGB", (SIZE, SIZE), C_BG)
            draw = _ImageDraw.Draw(img)

            # Circular clip mask
            mask = _Image.new("L", (SIZE, SIZE), 0)
            _ImageDraw.Draw(mask).ellipse((0, 0, SIZE - 1, SIZE - 1), fill=255)

            # Ring border
            draw.ellipse((0, 0, SIZE - 1, SIZE - 1),
                         outline=_ring_col(wifi_on, ap_on, status_text), width=RING_W)

            # Title
            title = "RAGNAR"
            try:
                tb = font_title.getbbox(title)
                tx = (SIZE - (tb[2] - tb[0])) // 2
            except Exception:
                tx = 80
            draw.text((tx, 8), title, font=font_title, fill=C_WHITE)

            # Mascot sprite
            if mascot_rgba is not None:
                mw, mh = mascot_rgba.size
                mx = (SIZE - mw) // 2
                my = 32 + (MASCOT_SZ - mh) // 2
                img.paste(mascot_rgba, (mx, my), mascot_rgba)

            # ── Left panel: WiFi signal ───────────────────────────────────
            sd = self.shared_data
            rssi  = getattr(sd, "wifi_signal_dbm",     None)
            qual  = getattr(sd, "wifi_signal_quality",  None)
            font_side = font_ssid  # 14px
            panel_y   = 100
            # Compute safe inward x so panels stay inside the circle at panel_y
            _chord = 2 * _math.sqrt(max(0, 120**2 - (panel_y - 120)**2))
            panel_x = int((SIZE - _chord) / 2) + RING_W + 6   # left panel x
            right_x_limit = SIZE - panel_x                     # right panel right edge

            if not wifi_on:
                draw.text((panel_x, panel_y),      "WiFi", font=font_side, fill=C_RED)
                draw.text((panel_x, panel_y + 16), " OFF", font=font_side, fill=C_RED)
            elif rssi is not None:
                # Signal bar indicator (4 bars)
                bars = 1 if rssi >= -90 else 0
                bars = 2 if rssi >= -75 else bars
                bars = 3 if rssi >= -65 else bars
                bars = 4 if rssi >= -55 else bars
                bar_col = C_RED if bars <= 1 else C_AMBER if bars == 2 else C_GREEN
                for b in range(4):
                    bh = 4 + b * 3   # bar heights: 4,7,10,13
                    bx = panel_x + b * 7
                    by = panel_y + 13 - bh
                    col = bar_col if b < bars else C_GRAY
                    draw.rectangle([bx, by, bx + 4, panel_y + 13], fill=col)
                dbm_str = f"{int(rssi)}d"
                draw.text((panel_x, panel_y + 17), dbm_str, font=font_side, fill=C_GRAY)
            else:
                draw.text((panel_x, panel_y), "N/A", font=font_side, fill=C_GRAY)

            # ── Right panel: Target count ─────────────────────────────────
            targets = getattr(sd, "total_targetnbr", 0) or 0
            # Right-align within the right sliver
            tgt_label1 = "TGTS"
            tgt_label2 = str(targets)
            try:
                w1 = font_side.getbbox(tgt_label1)[2] - font_side.getbbox(tgt_label1)[0]
                w2 = font_side.getbbox(tgt_label2)[2] - font_side.getbbox(tgt_label2)[0]
            except Exception:
                w1 = w2 = 28
            rx1 = right_x_limit - w1
            rx2 = right_x_limit - w2
            draw.text((rx1, panel_y),      tgt_label1, font=font_side, fill=C_GRAY)
            draw.text((rx2, panel_y + 16), tgt_label2, font=font_side, fill=C_GREEN)

            # Status text — same size as info line below (font_ssid / 14px)
            st = (status_text or "IDLE").upper()
            s_col = _status_col(wifi_on, ap_on, status_text)
            f_st  = font_ssid
            try:
                sb = f_st.getbbox(st)
                sx = (SIZE - (sb[2] - sb[0])) // 2
            except Exception:
                sx = 60
            draw.text((sx, 182), st, font=f_st, fill=s_col)

            # Rotating info line
            try:
                nb = font_ssid.getbbox(info_label)
                nx = (SIZE - (nb[2] - nb[0])) // 2
            except Exception:
                nx = 60
            draw.text((nx, 207), info_label, font=font_ssid, fill=info_col)

            # Apply circular mask (black corners)
            result = _Image.new("RGB", (SIZE, SIZE), C_BG)
            result.paste(img, mask=mask)
            return result

        # ── main animation loop ───────────────────────────────────────────
        self.epd_helper.init_partial_update()

        _anim_tick   = 0
        _frame_idx   = 0
        _last_status = None
        _last_text   = None
        _last_fidx   = -1
        _info_tick   = 0   # increments each TICK_SLEEP; drives rotating bottom line

        # Info slots cycle every 20 ticks (10 s each); 3 slots = 30 s period
        # Slot 0: scan target / current IP
        # Slot 1: targets found + creds
        # Slot 2: WiFi/network (the "every 30 s" network glimpse)
        INFO_SLOT_TICKS = 20   # 10 s per slot
        INFO_SLOTS      = 3

        def _info_line(slot, wifi_on, ssid, ap_on):
            sd = self.shared_data
            if slot == 2:
                # Network slot
                if ap_on:
                    return ssid if ssid.startswith("AP") else "AP MODE", C_AMBER
                if not wifi_on:
                    return "NOT CONNECTED", C_RED
                return (ssid.removeprefix("WiFi: ") if ssid else "Connected"), C_GRAY
            if slot == 0:
                # Current scan target — bjornstatustext2 holds network or IP being scanned
                target = getattr(sd, "bjornstatustext2", "") or ""
                if target:
                    label = target if len(target) <= 20 else target[-20:]
                    return label, C_CYAN
                # Fallback: gateway
                gw = (getattr(sd, "gateway_info", {}) or {}).get("gateway_ip", "")
                return (f"GW: {gw}" if gw else "Scanning..."), C_CYAN
            # slot == 1: targets + creds
            targets = getattr(sd, "total_targetnbr", 0) or 0
            creds   = getattr(sd, "crednbr",        0) or 0
            vulns   = getattr(sd, "vulnnbr",         0) or 0
            return f"T:{targets} C:{creds} V:{vulns}", C_GREEN

        while not self.shared_data.display_should_exit:
            try:
                wifi_on, ssid, ap_on, status_text = _text_state()
                orch_status = getattr(self.shared_data, "ragnarorch_status", "IDLE") or "IDLE"
                self.shared_data.update_ragnarstatus()

                # Reset animation when status changes
                if orch_status != _last_status:
                    _frame_idx   = 0
                    _anim_tick   = 0
                    _last_status = orch_status
                    _frame_cache.clear()  # tint may change with new status

                # Advance animation frame
                _anim_tick += 1
                if _anim_tick >= ANIM_TICKS:
                    _anim_tick  = 0
                    _frame_idx  = (_frame_idx + 1) % _frame_count(orch_status)

                tint = _mascot_tint()
                info_slot = (_info_tick // INFO_SLOT_TICKS) % INFO_SLOTS
                info_label, info_col = _info_line(info_slot, wifi_on, ssid, ap_on)
                _info_tick += 1

                text_changed  = (wifi_on, ssid, ap_on, status_text, info_label) != _last_text
                frame_changed = _frame_idx != _last_fidx
                color_changed = tint != getattr(self, "_gc9a01_last_tint", None)

                if text_changed or frame_changed or color_changed:
                    sprite = _get_colorized_frame(orch_status, _frame_idx, tint)
                    self._gc9a01_last_tint = tint
                    output = _render(wifi_on, ssid, ap_on, status_text, sprite, info_label, info_col)
                    output = output.transpose(_Image.Transpose.FLIP_LEFT_RIGHT)
                    self.epd_helper.display_partial(output)
                    _last_text  = (wifi_on, ssid, ap_on, status_text, info_label)
                    _last_fidx  = _frame_idx

                    try:
                        web_path = os.path.join(self.shared_data.webdir, "screen.png")
                        web_img = output.transpose(_Image.Transpose.FLIP_LEFT_RIGHT)
                        with open(web_path, "wb") as f:
                            web_img.save(f); f.flush(); os.fsync(f.fileno())
                    except Exception:
                        pass

            except Exception as exc:
                logger.error("GC9A01 render error: %s", exc)

            time.sleep(TICK_SLEEP)

    # ------------------------------------------------------------------
    # LCD1602 16x2 character LCD display loop
    # ------------------------------------------------------------------

    def _run_lcd1602(self):
        """LCD1602 16×2 display loop with two independent rotation timers.

        Top row (15 s each):
          Slot 0 — WiFi SSID          e.g. "Tango Down 5G  "
          Slot 1 — IP address         e.g. "192.168.1.100  "
          Slot 2 — Ragnar status      e.g. "NetworkScanner "

        Bottom row (5 s each, 3 slots):
          Slot 0 — "Targets: 42     "
          Slot 1 — "Vuln: 4         "
          Slot 2 — "Credentials: 0  "

        Handles I2C errors gracefully — forces full re-init on next tick.
        """
        import subprocess
        from resources.waveshare_epd import lcd1602 as _lcd1602_mod

        TOP_INTERVAL    = 15.0  # seconds per top-row slot
        TOP_SLOTS       = 3
        BOTTOM_INTERVAL = 5.0   # seconds per bottom-row slot
        BOTTOM_SLOTS    = 3
        TICK_SLEEP      = 0.5   # polling interval (seconds)

        def _get_ssid():
            try:
                res = subprocess.run(
                    ["iwgetid", "-r"], capture_output=True, text=True, timeout=2
                )
                ssid = res.stdout.strip()
                if ssid:
                    return ssid
            except Exception:
                pass
            if getattr(self.shared_data, "ap_enabled", False):
                return "AP MODE"
            return "No Network"

        def _get_ip():
            try:
                res = subprocess.run(
                    ["hostname", "-I"], capture_output=True, text=True, timeout=2
                )
                ip = res.stdout.strip().split()[0]
                if ip:
                    return ip
            except Exception:
                pass
            return "No IP"

        def _get_status():
            status = getattr(self.shared_data, "ragnarstatustext", None) or "IDLE"
            return str(status)

        def _render_lcd_preview(row0: str, row1: str):
            """Write a simulated LCD1602 image to screen.png for the web preview tab."""
            try:
                # Colours — classic green-on-dark LCD backlit look
                BEZEL_COLOR  = (20, 28, 20)
                BG_COLOR     = (10, 22, 10)
                CHAR_COLOR   = (80, 255, 100)
                CURSOR_COLOR = (40, 120, 50)   # darker fill for empty char cells

                BEZEL       = 14   # px border around the LCD panel
                PAD_X       = 18   # horizontal padding inside the panel
                PAD_Y       = 12   # vertical padding inside the panel
                ROW_GAP     = 10   # gap between the two character rows
                FONT_SIZE   = 28

                # Try common monospace fonts available on the Pi and Windows
                font = None
                for fp in (
                    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
                    "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
                    "/usr/share/fonts/truetype/freefont/FreeMono.ttf",
                    "C:/Windows/Fonts/cour.ttf",
                ):
                    try:
                        font = ImageFont.truetype(fp, size=FONT_SIZE)
                        break
                    except Exception:
                        pass
                if font is None:
                    font = ImageFont.load_default()

                # Measure a single character to size the canvas
                probe = Image.new("RGB", (1, 1))
                bb = ImageDraw.Draw(probe).textbbox((0, 0), "W", font=font)
                char_w = bb[2] - bb[0]
                char_h = bb[3] - bb[1]

                panel_w = PAD_X * 2 + char_w * 16
                panel_h = PAD_Y * 2 + char_h * 2 + ROW_GAP
                img_w   = panel_w + BEZEL * 2
                img_h   = panel_h + BEZEL * 2

                img  = Image.new("RGB", (img_w, img_h), BEZEL_COLOR)
                draw = ImageDraw.Draw(img)

                # LCD panel background
                draw.rectangle(
                    [BEZEL, BEZEL, BEZEL + panel_w - 1, BEZEL + panel_h - 1],
                    fill=BG_COLOR,
                )

                # Draw each row of 16 characters
                for row_idx, text in enumerate((row0, row1)):
                    text = (text or "").ljust(16)[:16]
                    x = BEZEL + PAD_X
                    y = BEZEL + PAD_Y + row_idx * (char_h + ROW_GAP)
                    draw.text((x, y), text, font=font, fill=CHAR_COLOR)

                webdir = getattr(self.shared_data, "webdir", None)
                if webdir:
                    img.save(os.path.join(webdir, "screen.png"))
            except Exception as exc:
                logger.error(f"LCD1602 preview render error: {exc}")

        # ── Initialise display ──────────────────────────────────────────
        _i2c_raw = self.config.get("lcd1602_i2c_address", "0x27")
        i2c_addr = int(_i2c_raw, 16) if isinstance(_i2c_raw, str) else int(_i2c_raw)
        i2c_bus  = int(self.config.get("lcd1602_i2c_bus", 1))

        epd = _lcd1602_mod.EPD(i2c_address=i2c_addr, i2c_bus=i2c_bus)
        try:
            epd.init()
        except Exception as exc:
            logger.error(f"LCD1602 init failed: {exc}")

        _last_line0    = None
        _last_line1    = None
        _top_slot      = 0
        _bottom_slot   = 0
        _top_start     = time.monotonic() - TOP_INTERVAL     # trigger write on first tick
        _bottom_start  = time.monotonic() - BOTTOM_INTERVAL  # trigger write on first tick

        # ── Main loop ───────────────────────────────────────────────────
        _hw_line0 = None   # tracks what is currently written to hardware
        _hw_line1 = None
        while not self.shared_data.display_should_exit:
            # — compute current content (slot timers + data) —
            try:
                sd  = self.shared_data
                now = time.monotonic()

                # — advance top slot —
                if now - _top_start >= TOP_INTERVAL:
                    _top_slot  = (_top_slot + 1) % TOP_SLOTS
                    _top_start = now

                # — advance bottom slot —
                if now - _bottom_start >= BOTTOM_INTERVAL:
                    _bottom_slot  = (_bottom_slot + 1) % BOTTOM_SLOTS
                    _bottom_start = now

                # — gather data —
                targets = getattr(sd, "total_targetnbr", 0) or 0
                vulns   = getattr(sd, "vulnnbr",          0) or 0
                creds   = getattr(sd, "crednbr",          0) or 0

                # — build top line —
                if _top_slot == 0:
                    line0 = _get_ssid()
                elif _top_slot == 1:
                    line0 = _get_ip()
                else:
                    line0 = _get_status()
                line0 = line0.ljust(16)[:16]

                # — build bottom line —
                if _bottom_slot == 0:
                    line1 = f"Targets: {targets}"
                elif _bottom_slot == 1:
                    line1 = f"Vuln: {vulns}"
                else:
                    line1 = f"Credentials: {creds}"
                line1 = line1.ljust(16)[:16]

                # — update web preview whenever content changes —
                if line0 != _last_line0 or line1 != _last_line1:
                    _render_lcd_preview(line0, line1)
                    _last_line0 = line0
                    _last_line1 = line1

            except Exception as exc:
                logger.error(f"LCD1602 data error: {exc}")

            # — write to hardware (isolated so I2C errors don't block preview) —
            try:
                if not epd._initialized:
                    epd.init()
                    _hw_line0 = None   # force full rewrite after reinit
                    _hw_line1 = None
                if _last_line0 is not None and _last_line0 != _hw_line0:
                    epd.write_line(0, _last_line0)
                    _hw_line0 = _last_line0
                if _last_line1 is not None and _last_line1 != _hw_line1:
                    epd.write_line(1, _last_line1)
                    _hw_line1 = _last_line1
            except Exception as exc:
                logger.error(f"LCD1602 hardware write error: {exc}")
                epd._initialized = False
                _hw_line0 = None
                _hw_line1 = None

            time.sleep(TICK_SLEEP)

        # ── Cleanup on exit ─────────────────────────────────────────────
        try:
            epd.Clear()
            epd.sleep()
        except Exception as exc:
            logger.error(f"LCD1602 shutdown error: {exc}")

    # ------------------------------------------------------------------
    # SSD1306 0.96" 128x64 monochrome OLED display loop
    # ------------------------------------------------------------------

    def _run_ssd1306(self):
        """Main display loop for SSD1306 0.96\" 128x64 monochrome OLED.

        Renders a compact status dashboard with header bar, WiFi info,
        target/credential counters, and a cycling info ticker at the bottom.
        """
        from PIL import Image as _Image, ImageDraw as _ImageDraw, ImageFont as _ImageFont
        import os

        W          = 128
        H          = 64
        TICK_SLEEP = 0.5    # seconds between ticks
        PNG_EVERY  = 10     # save screen.png every N ticks

        # ── Initialise display ──────────────────────────────────────────
        from resources.waveshare_epd import ssd1306 as _ssd1306_mod
        _i2c_raw = self.config.get("ssd1306_i2c_address", "0x3C")
        i2c_addr = int(_i2c_raw, 16) if isinstance(_i2c_raw, str) else int(_i2c_raw)
        epd = _ssd1306_mod.EPD(i2c_address=i2c_addr)
        epd.init()
        brightness = int(self.config.get("display_brightness", 8))
        epd.contrast(min(255, brightness * 17))  # map 0-15 → 0-255

        # ── Load fonts once ─────────────────────────────────────────────
        _font_path = os.path.join(
            os.path.dirname(__file__), "resources", "fonts", "Arial.ttf"
        )

        def _load_font(size):
            try:
                return _ImageFont.truetype(_font_path, size)
            except Exception:
                return _ImageFont.load_default()

        font_hdr  = _load_font(10)   # header bar text
        font_body = _load_font(9)    # all other lines

        _png_counter  = 0
        _scroll_pos   = 0   # pixel offset for header scroll

        # Width (px) available in the header beside "RAGNAR " prefix
        _RAGNAR_LABEL = "RAGNAR "
        try:
            _ragnar_w = font_hdr.getbbox(_RAGNAR_LABEL)[2]
        except Exception:
            _ragnar_w = len(_RAGNAR_LABEL) * 6
        _HDR_STATUS_W = W - _ragnar_w - 2   # pixels available for scrolling status

        # ── WiFi helper (same method used by gc9a01) ─────────────────────
        def _get_wifi():
            """Return (connected: bool, ssid: str, ip: str)."""
            import subprocess
            try:
                result = subprocess.run(
                    ["iwgetid", "-r"], capture_output=True, text=True, timeout=2
                )
                ssid = result.stdout.strip()
                if ssid:
                    # Get IP from shared_data
                    ip = getattr(self.shared_data, "ipaddress", "") or ""
                    return True, ssid, ip
            except Exception:
                pass
            if getattr(self.shared_data, "ap_enabled", False):
                return True, "AP MODE", getattr(self.shared_data, "ipaddress", "") or ""
            return False, "", getattr(self.shared_data, "ipaddress", "") or ""

        # ── Render helper ───────────────────────────────────────────────
        def _render(scroll_px):
            sd = self.shared_data

            # --- collect data --------------------------------------------------
            orch_status = (getattr(sd, "ragnarorch_status", "IDLE") or "IDLE").upper()
            wifi_on, ssid, ip = _get_wifi()

            targets = getattr(sd, "total_targetnbr", 0) or 0
            creds   = getattr(sd, "crednbr",        0) or 0
            vulns   = getattr(sd, "vulnnbr",         0) or 0

            status2 = (getattr(sd, "bjornstatustext2", "") or "").strip()

            # --- layout strings ------------------------------------------------
            wifi_line    = ("WiFi: " + ssid[:18]) if wifi_on else "NOT CONNECTED"
            target_line  = (">" + status2[:20]) if status2 else ("IP: " + ip if ip else "Scanning...")
            tc_line      = "TARGETS: {}   CREDS: {}".format(targets, creds)
            vuln_line    = "VULNERABILITIES: {}".format(vulns)

            # --- draw ----------------------------------------------------------
            img  = _Image.new("1", (W, H), 0)
            draw = _ImageDraw.Draw(img)

            # Header bar: white filled rectangle
            draw.rectangle((0, 0, W - 1, 12), fill=255)
            draw.text((2, 1), _RAGNAR_LABEL, font=font_hdr, fill=0)

            # Scrolling status text clipped to right portion of header
            # Build scroll string with padding so it wraps smoothly
            scroll_str = orch_status + "   "
            try:
                full_w = font_hdr.getbbox(scroll_str)[2]
            except Exception:
                full_w = len(scroll_str) * 6
            # Render into a temp image and paste a window of it
            tmp = _Image.new("1", (max(full_w * 2, _HDR_STATUS_W + 4), 12), 255)
            tdraw = _ImageDraw.Draw(tmp)
            tdraw.text((0, 1),        scroll_str, font=font_hdr, fill=0)
            tdraw.text((full_w, 1),   scroll_str, font=font_hdr, fill=0)
            offset = scroll_px % full_w
            crop   = tmp.crop((offset, 0, offset + _HDR_STATUS_W, 12))
            img.paste(crop, (_ragnar_w, 0))

            # Thin divider line at y=13
            draw.line((0, 13, W - 1, 13), fill=255)

            # Body lines
            draw.text((0, 15), wifi_line,   font=font_body, fill=255)
            draw.text((0, 26), target_line, font=font_body, fill=255)
            draw.text((0, 37), tc_line,     font=font_body, fill=255)
            draw.text((0, 48), vuln_line,   font=font_body, fill=255)

            return img

        # ── Main loop ───────────────────────────────────────────────────
        while not self.shared_data.display_should_exit:
            try:
                self.shared_data.update_ragnarstatus()
                img = _render(_scroll_pos)
                epd.init()
                buf = epd.getbuffer(img)
                epd.displayPartial(buf)
                _scroll_pos += 2   # advance scroll 2px per tick (0.5s → ~4px/s)
                # Save screen.png for web preview every PNG_EVERY ticks
                _png_counter += 1
                if _png_counter >= PNG_EVERY:
                    _png_counter = 0
                    try:
                        web_path = os.path.join(self.shared_data.webdir, "screen.png")
                        with open(web_path, "wb") as f:
                            img.save(f)
                            f.flush()
                            os.fsync(f.fileno())
                    except Exception:
                        pass

            except Exception as exc:
                logger.error("SSD1306 render error: %s", exc)

            time.sleep(TICK_SLEEP)

        # ── Cleanup on exit ─────────────────────────────────────────────
        try:
            epd.Clear()
            epd.sleep()
        except Exception as exc:
            logger.error("SSD1306 shutdown error: %s", exc)

    def _run_max7219(self):
        """Scrolling status display for MAX7219 cascaded LED matrix panels."""
        from PIL import Image as _Image, ImageDraw as _ImageDraw, ImageFont as _ImageFont
        from resources.waveshare_epd import max7219 as _max7219_mod
        import os

        epd_type        = self.config.get("epd_type", "max7219_8panel")
        cascaded        = 4 if epd_type == "max7219_4panel" else 8
        brightness      = int(self.config.get("display_brightness", 8))
        spi_port        = int(self.config.get("max7219_spi_port", 0))
        spi_device      = int(self.config.get("max7219_spi_device", 0))
        block_orient    = int(self.config.get("max7219_block_orientation", -90))

        W = cascaded * 8  # 32 or 64
        H = 8
        TICK_SLEEP = 0.1   # seconds per scroll tick
        PNG_EVERY  = 50    # save screen.png every N ticks (~5s)

        epd = _max7219_mod.EPD(
            cascaded=cascaded,
            spi_port=spi_port,
            spi_device=spi_device,
            brightness=brightness,
            block_orientation=block_orient,
        )
        epd.init()

        # ── Font ──────────────────────────────────────────────────────────
        _font_path = os.path.join(os.path.dirname(__file__), "resources", "fonts", "DejaVuSansMono.ttf")

        def _load_font(size):
            try:
                return _ImageFont.truetype(_font_path, size)
            except Exception:
                return _ImageFont.load_default()

        font  = _load_font(9)
        _y_off = -font.getbbox("A")[1]  # shift glyphs up so row 0 is used

        # ── Helpers ───────────────────────────────────────────────────────
        def _text_width(text):
            try:
                return font.getbbox(text)[2]
            except Exception:
                return len(text) * 6

        def _get_wifi():
            try:
                import subprocess
                ssid = subprocess.check_output(
                    ["iwgetid", "-r"], stderr=subprocess.DEVNULL
                ).decode().strip()
                return ("WIFI: " + ssid).upper() if ssid else "WIFI: NONE"
            except Exception:
                return "WIFI: NONE"

        def _get_ip():
            try:
                import socket
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                s.close()
                return f"IP: {ip}"
            except Exception:
                return "IP: NONE"

        def _get_db_stats():
            try:
                db = getattr(self.shared_data, 'db', None)
                if db and callable(getattr(db, 'get_stats', None)):
                    return db.get_stats()
            except Exception:
                pass
            return {}

        def _get_targets():
            try:
                stats = _get_db_stats()
                count = stats.get('total_hosts', 0)
                return f"TARGETS FOUND: {count}"
            except Exception:
                return "TARGETS FOUND: 0"

        def _get_credentials():
            try:
                db = getattr(self.shared_data, 'db', None)
                if db:
                    with db.get_connection() as conn:
                        cursor = conn.cursor()
                        cursor.execute("""
                            SELECT COUNT(*) FROM hosts WHERE (
                                (steal_files_ssh    IS NOT NULL AND steal_files_ssh    != '' AND steal_files_ssh    != '[]') OR
                                (steal_files_rdp    IS NOT NULL AND steal_files_rdp    != '' AND steal_files_rdp    != '[]') OR
                                (steal_files_ftp    IS NOT NULL AND steal_files_ftp    != '' AND steal_files_ftp    != '[]') OR
                                (steal_files_smb    IS NOT NULL AND steal_files_smb    != '' AND steal_files_smb    != '[]') OR
                                (steal_files_telnet IS NOT NULL AND steal_files_telnet != '' AND steal_files_telnet != '[]') OR
                                (steal_data_sql     IS NOT NULL AND steal_data_sql     != '' AND steal_data_sql     != '[]')
                            )
                        """)
                        count = cursor.fetchone()[0]
                        return f"CREDENTIALS STOLEN: {count}"
            except Exception:
                pass
            return "CREDENTIALS STOLEN: 0"

        def _get_vulns():
            try:
                stats = _get_db_stats()
                count = stats.get('hosts_with_vulns', 0)
                return f"VULNERABILITIES: {count}"
            except Exception:
                return "VULNERABILITIES: 0"

        def _get_status():
            try:
                status = getattr(self.shared_data, 'ragnarstatustext', '') or \
                         getattr(self.shared_data, 'current_action', '') or ''
                return status.upper()[:30] if status else "STATUS: IDLE"
            except Exception:
                return "STATUS: IDLE"

        # ── Scroll loop ───────────────────────────────────────────────────
        _tick       = 0
        _scroll_x   = W          # start off-screen right
        _msg_idx    = 0
        _messages   = []
        _msg_refresh_every = 200  # refresh message list every 200 ticks (~20s)

        def _build_messages():
            return [
                "* RAGNAR *",
                _get_targets(),
                _get_credentials(),
                _get_vulns(),
                _get_wifi(),
                _get_ip(),
                _get_status(),
            ]

        _messages = _build_messages()
        _current_msg = _messages[0]
        _msg_w = _text_width(_current_msg)

        while not self.shared_data.display_should_exit:
            # Refresh messages periodically
            if _tick % _msg_refresh_every == 0:
                _messages = _build_messages()

            # Build frame
            img  = _Image.new("1", (W, H), 0)
            draw = _ImageDraw.Draw(img)
            draw.text((_scroll_x, _y_off), _current_msg, font=font, fill=1)

            epd.display(epd.getbuffer(img))

            # Save web thumbnail
            if _tick % PNG_EVERY == 0:
                try:
                    png_path = os.path.join(os.path.dirname(__file__), "web", "screen.png")
                    # Scale up 4× so it's visible in browser
                    img.resize((W * 4, H * 4), _Image.NEAREST).convert("RGB").save(png_path)
                except Exception:
                    pass

            # Advance scroll
            _scroll_x -= 1
            if _scroll_x < -_msg_w:
                # Message fully scrolled off — advance to next
                _msg_idx = (_msg_idx + 1) % len(_messages)
                _current_msg = _messages[_msg_idx]
                _msg_w = _text_width(_current_msg)
                _scroll_x = W  # reset to right edge

            _tick += 1
            import time as _time
            _time.sleep(TICK_SLEEP)

        epd.Clear()
        epd.sleep()

    def run(self):
        """Main loop for updating the EPD display with shared data."""
        if self.config.get("epd_type") == "gc9a01":
            self._run_gc9a01()
            return

        if self.config.get("epd_type") == "ssd1306":
            self._run_ssd1306()
            return

        if self.config.get("epd_type") == "lcd1602":
            self._run_lcd1602()
            return

        if self.config.get("epd_type") in ("max7219_4panel", "max7219_8panel"):
            self._run_max7219()
            return

        # Wait for deferred initialization (fonts, images) to finish
        # before attempting to render anything.
        if hasattr(self.shared_data, 'wait_for_deferred_init'):
            self.shared_data.wait_for_deferred_init(timeout=30)
        self.manual_mode_txt = ""
        while not self.shared_data.display_should_exit:
            try:
                self.epd_helper.init_partial_update()
                # Pull latest orientation settings so web toggles take effect without restarting the service.
                self.screen_reversed = self.shared_data.screen_reversed
                self.web_screen_reversed = self.shared_data.web_screen_reversed
                self.display_comment(self.shared_data.ragnarorch_status)

                # Compute render dimensions — portrait for 90°/270°
                render_w, render_h = _render_dimensions(
                    self.shared_data.width, self.shared_data.height, self.screen_reversed)
                # Store for sub-page renderers
                self.render_w = render_w
                self.render_h = render_h
                ref_w = self.shared_data.config.get('ref_width', 122)
                ref_h = self.shared_data.config.get('ref_height', 250)
                if self.screen_reversed in (90, 270):
                    self.render_sx = render_w / ref_w
                    self.render_sy = render_h / ref_h
                else:
                    self.render_sx = self.scale_factor_x
                    self.render_sy = self.scale_factor_y

                image = Image.new('1', (render_w, render_h))
                draw = ImageDraw.Draw(image)
                draw.rectangle((0, 0, render_w, render_h), fill=255)

                # Check if button listener wants a different page
                current_page = PAGE_MAIN
                if self.button_listener and self.button_listener.available:
                    current_page = self.button_listener.current_page

                if current_page == PAGE_NETWORK:
                    self._render_network_page(image, draw)
                elif current_page == PAGE_VULN:
                    self._render_vuln_page(image, draw)
                elif current_page == PAGE_DISCOVERED:
                    self._render_discovered_page(image, draw)
                elif current_page == PAGE_ADVANCED:
                    self._render_advanced_page(image, draw)
                elif current_page == PAGE_TRAFFIC:
                    self._render_traffic_page(image, draw)
                else:
                    pass  # Fall through to main page rendering below

                if current_page != PAGE_MAIN:
                    # Non-main pages are fully rendered above, skip to display
                    epd_img = _apply_epd_rotation(image, self.screen_reversed)
                    self.epd_helper.display_partial(epd_img)
                    self.epd_helper.display_partial(epd_img)
                    web_img = _apply_web_rotation(image, self.web_screen_reversed)
                    with open(os.path.join(self.shared_data.webdir, "screen.png"), 'wb') as img_file:
                        web_img.save(img_file)
                        img_file.flush()
                        os.fsync(img_file.fileno())
                    self._sleep_interruptible(current_page)
                    continue

                # === PAGE_MAIN: Default Ragnar display ===
                # Scale factors spread positions across the full physical canvas
                # For 90°/270° we render in portrait so W < H.
                W = render_w
                H = render_h
                ref_w = self.shared_data.config.get('ref_width', 122)
                ref_h = self.shared_data.config.get('ref_height', 250)
                if self.screen_reversed in (90, 270):
                    sx = render_w / ref_w   # portrait: 480/122 ≈ 3.93
                    sy = render_h / ref_h   # portrait: 800/250 = 3.2
                else:
                    sx = self.scale_factor_x
                    sy = self.scale_factor_y

                # Check PiSugar once per frame for title sizing + battery text
                _pisugar_available = False
                try:
                    _ri = getattr(self.shared_data, 'ragnar_instance', None)
                    _ps = getattr(_ri, 'pisugar_listener', None) if _ri else None
                    _pisugar_available = _ps and _ps.available
                except Exception:
                    pass
                if _pisugar_available:
                    draw.text((int(40 * sx), int(6 * sy)), "RAGNAR", font=self.shared_data.font_viking_sm, fill=0)
                else:
                    draw.text((int(37 * sx), int(5 * sy)), "RAGNAR", font=self.shared_data.font_viking, fill=0)
                draw.text((int(110 * sx), int(170 * sy)), self.manual_mode_txt, font=self.shared_data.font_arial14, fill=0)
                
                # Show AP status or WiFi status in the top-left corner
                if hasattr(self.shared_data, 'ap_mode_active') and self.shared_data.ap_mode_active:
                    ap_text = "AP"
                    if hasattr(self.shared_data, 'ap_client_count') and self.shared_data.ap_client_count > 0:
                        ap_text = f"AP:{self.shared_data.ap_client_count}"
                    draw.text((int(3 * sx), int(3 * sy)), ap_text, font=self.shared_data.font_arial9, fill=0)
                elif self.shared_data.wifi_connected:
                    self.render_wifi_wave_indicator(image, draw)
                if self.shared_data.pan_connected:
                    image.paste(self.shared_data.connected, (int(104 * sx), int(3 * sy)))
                if self.shared_data.usb_active:
                    image.paste(self.shared_data.usb, (int(90 * sx), int(4 * sy)))

                # Battery percentage (PiSugar) - flush right in header
                if _pisugar_available:
                    try:
                        bat_level = _ps.get_battery_level()
                        if bat_level is not None:
                            bat_level = int(round(bat_level))
                            charging = _ps.is_charging()
                            bat_text = f"{bat_level}%+" if charging else f"{bat_level}%"
                            bbox = self.shared_data.font_arial9.getbbox(bat_text)
                            text_w = bbox[2] - bbox[0]
                            tx = W - text_w - 1
                            draw.text((tx, int(10 * sy)),
                                      bat_text, font=self.shared_data.font_arial9, fill=0)
                    except Exception:
                        pass

                # Stats — positions scaled to fill the physical width/height,
                # but icon images stay at their original pixel size.
                stats = [
                    (self.shared_data.target,    (int(8 * sx),   int(22 * sy)), (int(28 * sx),  int(22 * sy)), str(self.shared_data.targetnbr)),
                    (self.shared_data.port,      (int(47 * sx),  int(22 * sy)), (int(67 * sx),  int(22 * sy)), str(self.shared_data.portnbr)),
                    (self.shared_data.vuln,      (int(86 * sx),  int(22 * sy)), (int(106 * sx), int(22 * sy)), str(self.shared_data.vulnnbr)),
                    (self.shared_data.cred,      (int(8 * sx),   int(41 * sy)), (int(28 * sx),  int(41 * sy)), str(self.shared_data.crednbr)),
                    (self.shared_data.money,     (int(3 * sx),   int(172 * sy)), (int(3 * sx),  int(192 * sy)), str(self.shared_data.coinnbr)),
                    (self.shared_data.level,     (int(2 * sx),   int(217 * sy)), (int(4 * sx),  int(237 * sy)), str(self.shared_data.levelnbr)),
                    (self.shared_data.zombie,    (int(47 * sx),  int(41 * sy)), (int(67 * sx),  int(41 * sy)), str(self.shared_data.zombiesnbr)),
                    (self.shared_data.networkkb, (int(102 * sx), int(190 * sy)), (int(102 * sx), int(208 * sy)), str(self.shared_data.networkkbnbr)),
                    (self.shared_data.data,      (int(86 * sx),  int(41 * sy)), (int(106 * sx), int(41 * sy)), str(self.shared_data.datanbr)),
                    (self.shared_data.attacks,   (int(100 * sx), int(218 * sy)), (int(102 * sx), int(237 * sy)), str(self.shared_data.attacksnbr)),
                ]

                for img, img_pos, text_pos, text in stats:
                    image.paste(img, img_pos)
                    draw.text(text_pos, text, font=self.shared_data.font_arial9, fill=0)

                self.shared_data.update_ragnarstatus()
                image.paste(self.shared_data.ragnarstatusimage, (int(3 * sx), int(60 * sy)))
                draw.text((int(35 * sx), int(65 * sy)), self.shared_data.ragnarstatustext, font=self.shared_data.font_arial9, fill=0)
                draw.text((int(35 * sx), int(75 * sy)), self.shared_data.ragnarstatustext2, font=self.shared_data.font_arial9, fill=0)

                # Frise ribbon
                if self.shared_data.frise is not None:
                    frise_img = self.shared_data.frise
                    if frise_img.width != W - 2:
                        frise_img = frise_img.resize((W - 2, frise_img.height), Image.NEAREST)
                    image.paste(frise_img, (1, int(160 * sy)))

                # Frame & dividers — span full physical width
                draw.rectangle((1, 1, W - 1, H - 1), outline=0)
                draw.line((1, int(20 * sy), W - 1, int(20 * sy)), fill=0)
                draw.line((1, int(59 * sy), W - 1, int(59 * sy)), fill=0)
                draw.line((1, int(87 * sy), W - 1, int(87 * sy)), fill=0)

                lines = self.shared_data.wrap_text(self.shared_data.ragnarsays, self.shared_data.font_arialbold, W - 4)
                y_text = int(90 * sy)

                # Character image — centred on the full canvas
                if self.main_image is not None:
                    cx = (W - self.main_image.width) // 2
                    cy = H - self.main_image.height
                    image.paste(self.main_image, (cx, cy))
                else:
                    logger.error("Main image not found in shared_data.")

                for line in lines:
                    draw.text((int(4 * sx), y_text), line, font=self.shared_data.font_arialbold, fill=0)
                    y_text += (self.shared_data.font_arialbold.getbbox(line)[3] - self.shared_data.font_arialbold.getbbox(line)[1]) + 3

                if self.screen_reversed and self.screen_reversed in _ROTATION_TRANSPOSE:
                    epd_img = _apply_epd_rotation(image, self.screen_reversed)
                else:
                    epd_img = image

                self.epd_helper.display_partial(epd_img)
                self.epd_helper.display_partial(epd_img)

                web_img = _apply_web_rotation(image, self.web_screen_reversed)
                with open(os.path.join(self.shared_data.webdir, "screen.png"), 'wb') as img_file:
                    web_img.save(img_file)
                    img_file.flush()
                    os.fsync(img_file.fileno())

                self._sleep_interruptible(PAGE_MAIN)
            except Exception as e:
                logger.error(f"An error occurred: {e}")

def handle_exit_display(signum, frame, display_thread, exit_process=True):
    """Handle the exit signal and close the display."""
    global should_exit
    shared_data.display_should_exit = True
    logger.info("Exit signal received. Waiting for the main loop to finish...")
    try:
        if main_loop and hasattr(main_loop, 'epd_helper') and main_loop.epd_helper:
            main_loop.epd_helper.sleep()
    except Exception as e:
        logger.error(f"Error while closing the display: {e}")

    if display_thread and display_thread.is_alive():
        display_thread.join()

    logger.info("Main loop finished. Clean exit.")

    if exit_process:
        sys.exit(0)

# Declare main_loop globally
main_loop = None

if __name__ == "__main__":
    try:
        logger.info("Starting main loop...")
        main_loop = Display(shared_data)
        display_thread = threading.Thread(target=main_loop.run)
        display_thread.start()
        logger.info("Main loop started.")
        
        signal.signal(signal.SIGINT, lambda signum, frame: handle_exit_display(signum, frame, display_thread))
        signal.signal(signal.SIGTERM, lambda signum, frame: handle_exit_display(signum, frame, display_thread))
    except Exception as e:
        logger.error(f"An exception occurred during program execution: {e}")
        handle_exit_display(signal.SIGINT, None, display_thread)
        sys.exit(1)
