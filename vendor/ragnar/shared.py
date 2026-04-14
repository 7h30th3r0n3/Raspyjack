#shared.py
# Description:
# This file, shared.py, is a core component responsible for managing shared resources and data for different modules in the Ragnar project.
# It handles the initialization and configuration of paths, logging, fonts, and images. Additionally, it sets up the environment, 
# creates necessary directories and files, and manages the loading and saving of configuration settings.
# 
# Key functionalities include:
# - Initializing various paths used by the application, including directories for configuration, data, actions, web resources, and logs.
# - Setting up the environment, including the e-paper display, network knowledge base, and actions JSON configuration.
# - Loading and managing fonts and images required for the application's display.
# - Handling the creation and management of a live status file to store the current status of network scans.
# - Managing configuration settings, including loading default settings, updating, and saving configurations to a JSON file.
# - Providing utility functions for reading and writing data to CSV files and DB, updating statistics, and wrapping text for display purposes.

import os
import re
import json
import importlib
import random
import time
import csv
import logging
import subprocess
import threading
import traceback


def normalize_rotation(value):
    """Normalize a screen_reversed config value to a rotation angle (0, 90, 180, 270).

    Accepts booleans (legacy: True→180, False→0), integers, or string representations.
    """
    if isinstance(value, bool):
        return 180 if value else 0
    try:
        angle = int(value)
        if angle in (0, 90, 180, 270):
            return angle
    except (ValueError, TypeError):
        pass
    if str(value).lower() in ('true', '1'):
        return 180
    return 0
from datetime import datetime
try:
    from PIL import Image, ImageFont
except ImportError:
    Image = None  # type: ignore[assignment]
    ImageFont = None  # type: ignore[assignment]
from logger import Logger

try:
    from epd_helper import EPDHelper
except ImportError:
    EPDHelper = None

try:
    from db_manager import get_db
except ImportError:
    get_db = None

try:
    from network_storage import NetworkStorageManager
except ImportError:
    NetworkStorageManager = None

try:
    from multi_interface import MultiInterfaceState, NetworkContextRegistry
except ImportError:
    MultiInterfaceState = None
    NetworkContextRegistry = None

DEFAULT_EPD_TYPE = "epd2in13_V4"
DESIGN_REF_WIDTH = 122   # All layout coordinates are designed for this width
DESIGN_REF_HEIGHT = 250  # All layout coordinates are designed for this height

# Map web UI size keys to default driver names
SIZE_KEY_TO_DEFAULT_DRIVER = {
    "2in13":    "epd2in13_V4",
    "2in7":     "epd2in7_V2",
    "2in9":     "epd2in9_V2",
    "3in7":     "epd3in7",
    "4in26":    "epd4in26",
    "1in28_tft": "gc9a01",
    "0in96_oled": "ssd1306",
    "1602_lcd": "lcd1602",
}

def resolve_epd_type(size_key, current_epd_type=None):
    """Resolve a web UI size key to the correct driver name.

    If the current driver is already the same size family (e.g. epd2in13_V3 for 2in13),
    keep it. Otherwise, switch to the default driver for the new size.
    """
    if size_key == "auto" or size_key in DISPLAY_PROFILES:
        return size_key  # Already a valid driver name or auto

    default_driver = SIZE_KEY_TO_DEFAULT_DRIVER.get(size_key)
    if not default_driver:
        return size_key  # Unknown key, return as-is

    # If current driver is the same size family AND is a known valid profile, keep it
    if current_epd_type and current_epd_type.startswith(f"epd{size_key}"):
        if current_epd_type in DISPLAY_PROFILES:
            return current_epd_type

    return default_driver

DISPLAY_PROFILES = {
    "epd2in13":    {"ref_width": DESIGN_REF_WIDTH, "ref_height": DESIGN_REF_HEIGHT, "default_flip": False},
    "epd2in7":     {"ref_width": DESIGN_REF_WIDTH, "ref_height": DESIGN_REF_HEIGHT, "default_flip": False},
    "epd2in7_V2":  {"ref_width": DESIGN_REF_WIDTH, "ref_height": DESIGN_REF_HEIGHT, "default_flip": False},
    "epd2in9_V2":  {"ref_width": DESIGN_REF_WIDTH, "ref_height": DESIGN_REF_HEIGHT, "default_flip": False},
    "epd3in7":     {"ref_width": DESIGN_REF_WIDTH, "ref_height": DESIGN_REF_HEIGHT, "default_flip": False},
    "epd2in13_V2": {"ref_width": DESIGN_REF_WIDTH, "ref_height": DESIGN_REF_HEIGHT, "default_flip": False},
    "epd2in13_V3": {"ref_width": DESIGN_REF_WIDTH, "ref_height": DESIGN_REF_HEIGHT, "default_flip": True},
    "epd2in13_V4": {"ref_width": DESIGN_REF_WIDTH, "ref_height": DESIGN_REF_HEIGHT, "default_flip": False},
    # Waveshare 4.26" 800x480 e-paper (landscape) — use DESIGN_REF so the
    # scale-factor system uniformly scales the 122×250 layout up.  The
    # vertical factor (480/250 = 1.92) dominates; we use that for the
    # horizontal reference too so that icons/text aren't stretched.
    "epd4in26":    {"ref_width": DESIGN_REF_WIDTH, "ref_height": DESIGN_REF_HEIGHT, "default_flip": False},
    # GC9A01 1.28" 240x240 round colour TFT LCD
    "gc9a01":      {"ref_width": DESIGN_REF_WIDTH, "ref_height": DESIGN_REF_WIDTH, "default_flip": False},
    # SSD1306 0.96" 128x64 monochrome OLED
    "ssd1306":     {"ref_width": 128, "ref_height": 64,  "default_flip": False},
    # LCD1602 16x2 character LCD (I2C via PCF8574 backpack)
    "lcd1602":     {"ref_width": 16,  "ref_height": 2,   "default_flip": False},
    # MAX7219 LED matrix displays
    "max7219_4panel": {"ref_width": 32,  "ref_height": 8, "default_flip": False},
    "max7219_8panel": {"ref_width": 64,  "ref_height": 8, "default_flip": False},
}


logger = Logger(name="shared.py", level=logging.DEBUG) # Create a logger object 

class SharedData:
    """Shared data between the different modules."""
    def __init__(self):
        # Detect Pager mode (set by pager_payload.sh before Python launch)
        self._pager_mode = os.environ.get('RAGNAR_PAGER_MODE') == '1'

        self.initialize_paths() # Initialize the paths used by the application

        # --- Network storage & context (not available on Pager) ---
        if not self._pager_mode and NetworkStorageManager is not None:
            self.storage_manager = NetworkStorageManager(self.datadir)
        else:
            self.storage_manager = None
        self.active_network_ssid = None
        self.active_network_slug = None
        self.current_network_dir = None
        self.current_network_db_path = None
        self.network_intelligence_dir = None
        self.network_threat_dir = None
        if self.storage_manager is not None:
            self._apply_network_context(
                self.storage_manager.get_active_context(),
                configure_db=False
            )
        if not self._pager_mode and NetworkContextRegistry is not None:
            self.context_registry = NetworkContextRegistry(self)
        else:
            self.context_registry = None

        self.status_list = []
        self.last_comment_time = time.time() # Last time a comment was displayed
        self._stats_lock = threading.Lock()  # Thread-safe lock for update_stats()
        self.default_config = self.get_default_config() # Default configuration of the application
        self.config = self.default_config.copy() # Configuration of the application
        # Load existing configuration first
        self.load_config()

        if not self._pager_mode and MultiInterfaceState is not None:
            self.multi_interface_state = MultiInterfaceState(self)
        else:
            self.multi_interface_state = None

        # Ensure the selected EPD profile is consistent and expose flip settings early
        self.config.setdefault('epd_type', DEFAULT_EPD_TYPE)
        self.apply_display_profile(self.config['epd_type'], set_orientation_if_missing=True, persist=not self._pager_mode)
        self.screen_reversed = normalize_rotation(self.config.get('screen_reversed', 0))
        self.web_screen_reversed = self.screen_reversed

        # Check if auth is configured and DB might be encrypted
        if not self._pager_mode:
            self.auth_configured = self._check_auth_configured()
        else:
            self.auth_configured = False

        # Initialize SQLite database manager
        # If auth is configured and DB is encrypted, db may be None until login
        if get_db is not None:
            try:
                self.db = get_db(currentdir=self.currentdir)
                self._configure_database()
            except Exception as e:
                logger.warning(f"Database initialization failed: {e}")
                self.db = None
        else:
            self.db = None

        # Update MAC blacklist without immediate save
        self.update_mac_blacklist()
        self.setup_environment(clear_console=False) # Setup the environment without clearing console
        self.initialize_variables() # Initialize the variables used by the application
        self.load_gamification_data()  # Load persistent gamification progress

        # Initialize network intelligence and AI service in background
        # to avoid blocking startup (these are not needed immediately)
        self.network_intelligence = None
        self.threat_intelligence = None  # type: ignore
        self.ai_service = None
        self.scanned_networks_count = 0
        self._deferred_init_done = threading.Event()

        self.create_livestatusfile()

        # Defer heavy I/O (fonts, images, AI, network intelligence) to a
        # background thread so the main thread can continue to start the
        # display and web server sooner.
        if not self._pager_mode:
            threading.Thread(target=self._deferred_init, daemon=True).start()
        else:
            # Pager mode: load fonts/images synchronously (lightweight)
            self.load_fonts()
            self.load_images()
            self._deferred_init_done.set()

        # Start background cleanup task for old hosts (needs DB)
        if not self._pager_mode and self.db is not None:
            self._start_cleanup_task()
        
    def _deferred_init(self):
        """Run heavy initialization tasks in a background thread.

        Loads fonts, images, network intelligence, AI service, and
        network counts without blocking the main startup path.
        """
        try:
            self.load_fonts()
            self.load_images()
            self.initialize_network_intelligence()
            self.initialize_ai_service()
            self.scanned_networks_count = self._calculate_scanned_networks_count()
            logger.info("Deferred initialization completed")
        except Exception as e:
            logger.error(f"Deferred initialization error: {e}")
        finally:
            self._deferred_init_done.set()

    def wait_for_deferred_init(self, timeout: float = 30.0) -> bool:
        """Wait for deferred init to finish (used by display before first render)."""
        return self._deferred_init_done.wait(timeout=timeout)

    def initialize_network_intelligence(self):
        """Initialize the network intelligence system"""
        try:
            from network_intelligence import NetworkIntelligence
            self.network_intelligence = NetworkIntelligence(self)
            logger.info("Network intelligence system initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize network intelligence: {e}")
            self.network_intelligence = None
    
    def initialize_ai_service(self):
        """Initialize the AI service"""
        try:
            from ai_service import AIService
            logger.info("Attempting to initialize AI service...")
            self.ai_service = AIService(self)
            if self.ai_service.is_enabled():
                logger.info("AI service initialized successfully with GPT-5 Nano")
            else:
                init_error = getattr(self.ai_service, 'initialization_error', None)
                if init_error:
                    logger.warning(f"AI service initialized but not enabled: {init_error}")
                else:
                    logger.info("AI service initialized but not enabled (check configuration)")
        except ImportError as e:
            logger.error(f"Failed to import AI service module: {e}")
            import traceback
            logger.error(traceback.format_exc())
            self.ai_service = None
        except Exception as e:
            logger.error(f"Failed to initialize AI service: {e}")
            import traceback
            logger.error(traceback.format_exc())
            self.ai_service = None

    def _calculate_scanned_networks_count(self) -> int:
        """Calculate the number of scanned networks (excluding defaults)."""
        manager = getattr(self, 'storage_manager', None)
        networks_dir = None
        default_slug = 'default'

        if manager is not None:
            networks_dir = getattr(manager, 'networks_dir', None)
            default_ssid = getattr(manager, 'default_ssid', None)
            slugify = getattr(manager, '_slugify', None)
            if callable(slugify) and default_ssid is not None:
                try:
                    default_slug = slugify(default_ssid)
                except Exception:
                    default_slug = 'default'

        if not networks_dir:
            networks_dir = os.path.join(self.datadir, 'networks')

        logger.debug(f"SCANNED_NETWORKS: Calculating using directory {networks_dir}, default_slug={default_slug}")

        try:
            entries = os.listdir(networks_dir)
        except OSError as exc:
            logger.warning(f"SCANNED_NETWORKS: Unable to read {networks_dir}: {exc}")
            return 0

        count = 0
        for entry in entries:
            if entry.startswith('.'):
                continue
            path = os.path.join(networks_dir, entry)
            if not os.path.isdir(path):
                continue
            if entry in (default_slug, 'default'):
                continue
            count += 1

        logger.info(f"SCANNED_NETWORKS: Calculated count {count} (excluding {default_slug})")
        return count

    def initialize_paths(self):
        """Initialize the paths used by the application."""
        """Folders paths"""
        self.currentdir = os.path.dirname(os.path.abspath(__file__))
        # Directories directly under currentdir
        self.configdir = os.path.join(self.currentdir, 'config')
        self.datadir = os.path.join(self.currentdir, 'data')
        self.actions_dir = os.path.join(self.currentdir, 'actions')
        self.webdir = os.path.join(self.currentdir, 'web')
        self.resourcesdir = os.path.join(self.currentdir, 'resources')
        self.backupbasedir = os.path.join(self.currentdir, 'backup')
        # Directories under backupbasedir
        self.backupdir = os.path.join(self.backupbasedir, 'backups')
        self.upload_dir = os.path.join(self.backupbasedir, 'uploads')

        # Directories under datadir
        self.logsdir = os.path.join(self.datadir, 'logs')
        self.output_dir = os.path.join(self.datadir, 'output')
        self.input_dir = os.path.join(self.datadir, 'input')
        # Directories under output_dir
        self._default_crackedpwddir = os.path.join(self.output_dir, 'crackedpwd')
        self._default_datastolendir = os.path.join(self.output_dir, 'data_stolen')
        self.crackedpwddir = self._default_crackedpwddir
        self.datastolendir = self._default_datastolendir
        self.zombiesdir = os.path.join(self.output_dir, 'zombies')
        self._default_vulnerabilities_dir = os.path.join(self.output_dir, 'vulnerabilities')
        self._default_scan_results_dir = os.path.join(self.output_dir, "scan_results")
        self.vulnerabilities_dir = self._default_vulnerabilities_dir
        self.scan_results_dir = self._default_scan_results_dir
        # Directories under resourcesdir
        self.picdir = os.path.join(self.resourcesdir, 'images')
        self.fontdir = os.path.join(self.resourcesdir, 'fonts')
        self.commentsdir = os.path.join(self.resourcesdir, 'comments')
        # Directories under picdir
        self.statuspicdir = os.path.join(self.picdir, 'status')
        self.staticpicdir = os.path.join(self.picdir, 'static')
        # Directory under input_dir
        self.dictionarydir = os.path.join(self.input_dir, "dictionary")
        """Files paths"""
        # Files directly under configdir
        self.shared_config_json = os.path.join(self.configdir, 'shared_config.json')
        self.actions_file = os.path.join(self.configdir, 'actions.json')
        # Files directly under resourcesdir
        self.commentsfile = os.path.join(self.commentsdir, 'comments.json')
        # Files directly under datadir
        self.netkbfile = os.path.join(self.datadir, "netkb.csv")
        self.livestatusfile = os.path.join(self.datadir, 'livestatus.csv')
        self.gamification_file = os.path.join(self.datadir, 'gamification.json')
        self.pwnagotchi_status_file = os.path.join(self.datadir, 'pwnagotchi_status.json')
        # Files directly under vulnerabilities_dir (kept in sync via _update_output_paths)
        self.vuln_summary_file = os.path.join(self.vulnerabilities_dir, 'vulnerability_summary.csv')
        self.vuln_scan_progress_file = os.path.join(self.vulnerabilities_dir, 'scan_progress.json')
        # Files directly under dictionarydir
        self.usersfile = os.path.join(self.dictionarydir, "users.txt")
        self.passwordsfile = os.path.join(self.dictionarydir, "passwords.txt")
        # Files directly under crackedpwddir
        self._refresh_credential_files()
        self.crackedpwd_dir = self.crackedpwddir
        #Files directly under logsdir
        self.webconsolelog = os.path.join(self.logsdir, 'temp_log.txt')

    def _apply_network_context(self, context, configure_db=True):
        """Store active network metadata and optionally reconfigure storage."""
        if not context:
            return
        self.active_network_ssid = context.get('ssid')
        self.active_network_slug = context.get('slug')
        self.current_network_dir = context.get('network_dir')
        self.current_network_db_path = context.get('db_path')
        self.network_intelligence_dir = context.get('intelligence_dir')
        self.network_threat_dir = context.get('threat_intelligence_dir')
        loot_data_dir = context.get('data_stolen_dir') or self._default_datastolendir
        loot_credentials_dir = context.get('credentials_dir') or self._default_crackedpwddir
        self._update_loot_paths(loot_data_dir, loot_credentials_dir)
        scan_results_dir = context.get('scan_results_dir') or self._default_scan_results_dir
        vulnerabilities_dir = context.get('vulnerabilities_dir') or self._default_vulnerabilities_dir
        self._update_output_paths(scan_results_dir, vulnerabilities_dir)
        if configure_db and hasattr(self, 'db'):
            self._configure_database()

    def _configure_database(self):
        """Point the singleton database at the active network store."""
        if get_db is None or self._pager_mode:
            return
        if not self.current_network_dir or not self.current_network_db_path:
            return
        db = get_db(currentdir=self.currentdir)
        db.configure_storage(self.current_network_dir, self.current_network_db_path)
        self.db = db

    def _check_auth_configured(self):
        """Check if authentication is configured by looking for the auth database."""
        import sqlite3
        auth_db_path = os.path.join(self.datadir, 'ragnar_auth.db')
        if not os.path.exists(auth_db_path):
            return False
        try:
            conn = sqlite3.connect(auth_db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM auth")
            count = cursor.fetchone()[0]
            conn.close()
            return count > 0
        except Exception:
            return False

    def _refresh_network_components(self):
        """Ensure dependent subsystems follow the current network context."""
        self._configure_database()
        if self.network_intelligence and self.network_intelligence_dir:
            self.network_intelligence.set_storage_root(self.network_intelligence_dir)
        if self.threat_intelligence and self.network_threat_dir:
            self.threat_intelligence.set_storage_root(self.network_threat_dir)

    def _update_loot_paths(self, data_stolen_dir, credentials_dir):
        """Ensure per-network loot directories exist and refresh file pointers."""
        if data_stolen_dir:
            os.makedirs(data_stolen_dir, exist_ok=True)
            self.datastolendir = data_stolen_dir
        if credentials_dir:
            os.makedirs(credentials_dir, exist_ok=True)
            self.crackedpwddir = credentials_dir
        self.crackedpwd_dir = self.crackedpwddir  # legacy attribute name used by web UI
        self._refresh_credential_files()

    def _update_output_paths(self, scan_results_dir, vulnerabilities_dir):
        """Switch scan result and vulnerability dirs to the active network's paths."""
        if scan_results_dir:
            os.makedirs(scan_results_dir, exist_ok=True)
            self.scan_results_dir = scan_results_dir
        if vulnerabilities_dir:
            os.makedirs(vulnerabilities_dir, exist_ok=True)
            self.vulnerabilities_dir = vulnerabilities_dir
            self.vuln_summary_file = os.path.join(vulnerabilities_dir, 'vulnerability_summary.csv')
            self.vuln_scan_progress_file = os.path.join(vulnerabilities_dir, 'scan_progress.json')

    def _refresh_credential_files(self):
        """Keep credential CSV paths aligned with the active credential directory."""
        self.sshfile = os.path.join(self.crackedpwddir, 'ssh.csv')
        self.smbfile = os.path.join(self.crackedpwddir, "smb.csv")
        self.telnetfile = os.path.join(self.crackedpwddir, "telnet.csv")
        self.ftpfile = os.path.join(self.crackedpwddir, "ftp.csv")
        self.sqlfile = os.path.join(self.crackedpwddir, "sql.csv")
        self.rdpfile = os.path.join(self.crackedpwddir, "rdp.csv")

    def set_active_network(self, ssid):
        """Public entry point for Wi-Fi manager to switch all storage."""
        if not hasattr(self, 'storage_manager'):
            return

        # Guard against transient Wi-Fi blips: if the new SSID is None
        # (Wi-Fi momentarily lost) but we already have an active real
        # network, do NOT switch.  A genuine disconnection will be
        # handled by the Wi-Fi monitoring loop which performs sustained
        # validation before acting.  Without this guard, a single
        # failed check_wifi_connection() call (common on the resource-
        # constrained Pi Zero W2) would call mark_all_hosts_degraded()
        # and wipe the entire target list to zero.
        if not ssid and self.active_network_ssid:
            logger.debug(
                f"Ignoring transient SSID=None switch (current network: "
                f"{self.active_network_ssid})"
            )
            return

        try:
            if self.network_intelligence:
                self.network_intelligence.save_intelligence_data()
            if self.threat_intelligence:
                self.threat_intelligence.persist_state()
        except Exception as exc:
            logger.warning(f"Failed to persist data before network switch: {exc}")

        try:
            if self.storage_manager is None:
                logger.error("Storage manager not available, cannot switch network")
                return
            context = self.storage_manager.activate_network(ssid)
        except Exception as exc:
            logger.error(f"Unable to activate network storage for '{ssid}': {exc}")
            return

        # Skip reconfiguration if the slug did not change
        if (context.get('slug') == self.active_network_slug and
                context.get('ssid') == self.active_network_ssid):
            return

        # Mark every alive host in the OUTGOING database as degraded so
        # that hosts from the old network never linger as "alive" inside
        # the new network's store (race-condition safety net) and so
        # that stale hosts are immediately visible as offline if the
        # user switches back later.
        try:
            if get_db is not None and not self._pager_mode:
                outgoing_db = get_db(currentdir=self.currentdir)
                outgoing_db.mark_all_hosts_degraded()
        except Exception as exc:
            logger.warning(f"Failed to mark outgoing hosts as degraded: {exc}")

        self._apply_network_context(context, configure_db=False)
        self._refresh_network_components()
        logger.info(
            f"Active network context updated: ssid={self.active_network_ssid or 'default'} "
            f"slug={self.active_network_slug}"
        )

    def get_default_config(self):
        """ The configuration below is used to set the default values of the configuration settings."""
        """ It can be used to reset the configuration settings to their default values."""
        """ You can mofify the json file shared_config.json or on the web page to change the default values of the configuration settings."""
        default_profile = DISPLAY_PROFILES.get(DEFAULT_EPD_TYPE, {"ref_width": 122, "ref_height": 250, "default_flip": False})
        return {
            "__title_Ragnar__": "Settings",
            "manual_mode": False,
            "websrv": True,
            "web_bind_interface": "",
            "web_increment": False,
            "debug_mode": False,
            "scan_vuln_running": True,
            "scan_vuln_no_ports": False,
            "enable_attacks": False,
            "release_gate_enabled": False,
            "release_gate_message": "",
            "retry_success_actions": True,
            "retry_failed_actions": True,
            "blacklistcheck": True,
            "displaying_csv": True,
            "log_debug": False,
            "log_info": False,
            "log_warning": True,
            "log_error": True,
            "log_critical": True,
            "terminal_log_level": "all",
            
            "startup_delay": 2,
            "web_delay": 2,
            "screen_delay": 1,
            "comment_delaymin": 15,
            "comment_delaymax": 30,
            "livestatus_delay": 8,
            "image_display_delaymin": 2,
            "image_display_delaymax": 8,
            "scan_interval": 180,
            "scan_vuln_interval": 300,
            "failed_retry_delay": 180,
            "success_retry_delay": 300,
            "action_timeout": 300,
            "vuln_scan_timeout": 1800,
            "ref_width": default_profile["ref_width"],
            "ref_height": default_profile["ref_height"],
            "epd_type": DEFAULT_EPD_TYPE,
            "screen_reversed": 180 if default_profile.get("default_flip", False) else 0,
            "gc9a01_mascot_color": "#96C8FF",
            "ssd1306_i2c_address": "0x3C",
            "lcd1602_i2c_address": "0x27",
            "lcd1602_i2c_bus": 1,
            "display_brightness": 8,
            "spi_clock_mhz": 2,
            "max7219_spi_port":         0,
            "max7219_spi_device":        0,
            "max7219_block_orientation": -90,
            
            
            "__title_lists__": "List Settings",
            "portlist": [20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123, 135, 137, 138, 139, 143, 161, 162, 179, 389, 443, 445, 465, 514, 515, 520, 554, 587, 631, 636, 993, 995, 1024, 1025, 1080, 1194, 1433, 1434, 1521, 1723, 1812, 1813, 1883, 1900, 2049, 2082, 2083, 2181, 2375, 2376, 2483, 2484, 25565, 3000, 3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009, 4000, 5000, 5003, 5004, 5060, 5061, 5432, 5500, 5555, 5631, 5632, 5900, 5985, 5986, 6000, 6379, 6667, 6881, 6969, 7000, 7070, 8080, 8081, 8086, 8181, 8443, 8888, 9000, 9090, 9100, 9200, 9418, 9999, 10000],
            "mac_scan_blacklist": [],
            "ip_scan_blacklist": [],
            "steal_file_names": ["ssh.csv","hack.txt","password","passwd","credential","key","secret","config","backup","settings","credentials","auth","environment","docker-compose","kubeconfig"],
            "steal_file_extensions": [".txt",".conf",".xml",".db",".sql",".key",".pem",".crt",".yaml",".yml",".config",".ini",".env",".cfg"],
            
            "__title_network__": "Network",
            "nmap_scan_aggressivity": "-T4",
            "portstart": 1,
            "portend": 5500,
            "scan_subnets": [],
            "default_vulnerability_ports": [22, 80, 443],
            "network_max_failed_pings": 15,
            "network_device_retention_days": 14,
            "network_device_retention_hours": 8,  # Legacy data cleanup after 8 hours
            "network_ping_grace_period_minutes": 30,
            
            "__title_timewaits__": "Time Wait Settings",
            "timewait_smb": 0,
            "timewait_ssh": 0,
            "timewait_telnet": 0,
            "timewait_ftp": 0,
            "timewait_sql": 0,
            "timewait_rdp": 0,
            
            "__title_wifi__": "Wi-Fi Management",
            "wifi_known_networks": [],
            "wifi_default_interface": "wlan0",
            "wifi_ap_ssid": "Ragnar",
            "wifi_ap_password": "ragnarconnect",
            "wifi_connection_timeout": 60,
            "wifi_max_attempts": 3,
            "wifi_scan_interval": 300,
            "wifi_monitor_enabled": True,
            "wifi_auto_ap_fallback": True,
            "wifi_ap_timeout": 180,
            "wifi_multi_network_scans_enabled": True,
            "wifi_multi_scan_mode": "multi",
            "wifi_multi_scan_focus_interface": "",
            "wifi_multi_scan_max_interfaces": 2,
            "wifi_multi_scan_max_parallel": 1,
            "wifi_allowed_scan_interfaces": [],
            "wifi_scan_interface_overrides": {},
            "wifi_external_interface_hint": "",
            "wifi_ap_idle_timeout": 180,
            "wifi_reconnect_interval": 20,
            "wifi_ap_cycle_enabled": True,
            "wifi_initial_connection_timeout": 60,
            "wifi_failsafe_cycle_limit": 10,

            "__title_ethernet__": "Ethernet/LAN Settings",
            "ethernet_default_interface": "eth0",
            "ethernet_scan_enabled": True,
            "ethernet_prefer_over_wifi": True,
            "ethernet_auto_detect": True,

            "network_device_retention_days": 14,

            "__title_network_intelligence__": "Network Intelligence",
            "network_resolution_timeout": 3600,
            "network_confirmation_scans": 3,
            "network_change_grace": 300,
            "network_intelligence_enabled": True,
            "network_auto_resolution": True,

            "__title_ai__": "AI Integration (GPT-5 Nano)",
            "ai_enabled": False,
            "openai_api_token": "",
            "ai_model": "gpt-5-nano",
            "ai_analysis_enabled": True,
            "ai_vulnerability_summaries": True,
            "ai_network_insights": True,
            "ai_max_tokens": 500,
            "ai_temperature": 0.7,

            "__title_pushover__": "Pushover Notifications",
            "pushover_enabled": False,
            "pushover_notify_new_device": True,
            "pushover_notify_new_vulnerability": True,
            "pushover_notify_new_credential": True,
            "pushover_notify_device_lost": False,
            "pushover_notify_device_back_online": False,

            "__title_pwnagotchi__": "Pwnagotchi Integration",
            "pwnagotchi_installed": False,
            "pwnagotchi_mode": "ragnar",
            "pwnagotchi_last_switch": "",
            "pwnagotchi_last_status": "Not installed"
        }

    def apply_display_profile(self, epd_type=None, set_orientation_if_missing=False, persist=False):
        """Align reference dimensions (and optional orientation) with the chosen EPD profile."""
        epd_key = epd_type or self.config.get('epd_type') or DEFAULT_EPD_TYPE
        profile = DISPLAY_PROFILES.get(epd_key)
        if not profile:
            logger.warning(f"Unknown EPD profile '{epd_key}' – skipping display calibration")
            return False

        changed = False
        if self.config.get('ref_width') != profile['ref_width']:
            self.config['ref_width'] = profile['ref_width']
            changed = True
        if self.config.get('ref_height') != profile['ref_height']:
            self.config['ref_height'] = profile['ref_height']
            changed = True

        needs_orientation = set_orientation_if_missing and 'screen_reversed' not in self.config
        if needs_orientation:
            desired_orientation = 180 if profile.get('default_flip', False) else 0
            if self.config.get('screen_reversed') != desired_orientation:
                self.config['screen_reversed'] = desired_orientation
                changed = True

        if persist and changed:
            self.save_config()

        return changed

    def _normalize_config_keys(self, config):
        """Ensure legacy or malformed configuration keys are aligned with the current schema."""
        if 'web_increment ' in config:
            if 'web_increment' not in config:
                config['web_increment'] = config['web_increment ']
            del config['web_increment ']
        return config

    def _remove_legacy_attributes(self):
        """Drop attributes created from legacy configuration keys that cannot be accessed normally."""
        legacy_attrs = ['web_increment ']
        for attr in legacy_attrs:
            if hasattr(self, attr):
                delattr(self, attr)

    def update_mac_blacklist(self):
        """Update the MAC blacklist without immediate save."""
        mac_address = self.get_raspberry_mac()
        if mac_address:
            if 'mac_scan_blacklist' not in self.config:
                self.config['mac_scan_blacklist'] = []
            
            if mac_address not in self.config['mac_scan_blacklist']:
                self.config['mac_scan_blacklist'].append(mac_address)
                logger.info(f"Added local MAC address {mac_address} to blacklist")
            else:
                logger.info(f"Local MAC address {mac_address} already in blacklist")
        else:
            logger.warning("Could not add local MAC to blacklist: MAC address not found")



    def get_raspberry_mac(self):
        """Get the MAC address of the primary network interface (usually wlan0 or eth0)."""
        try:
            # First try wlan0 (wireless interface)
            result = subprocess.run(['cat', '/sys/class/net/wlan0/address'], 
                                 capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip().lower()
            
            # If wlan0 fails, try eth0 (ethernet interface)
            result = subprocess.run(['cat', '/sys/class/net/eth0/address'], 
                                 capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip().lower()
            
            logger.warning("Could not find MAC address for wlan0 or eth0")
            return None
            
        except Exception as e:
            logger.error(f"Error getting Raspberry Pi MAC address: {e}")
            return None



    def setup_environment(self, clear_console=False):
        """Setup the environment with the necessary directories and files."""
        if clear_console:
            os.system('cls' if os.name == 'nt' else 'clear')
        self.create_directories()  # Create all necessary directories first
        self.save_config()
        if self._pager_mode:
            # On Pager: try to regenerate actions.json (works if deps are available),
            # fall back to loading existing file if generation fails.
            if not os.path.exists(self.actions_file):
                try:
                    self.generate_actions_json()
                except Exception as e:
                    logger.warning(f"Could not generate actions.json: {e}")
            self._load_status_list_from_actions_json()
        else:
            # Skip costly re-import of every action module if actions.json
            # is already up to date (same set of .py files in actions/).
            self._generate_actions_json_if_needed()
        self.delete_webconsolelog()
        self.initialize_csv()
        self.initialize_epd_display()
    
    def create_directories(self):
        """Create all necessary directories for the application."""
        directories_to_create = [
            self.configdir,
            self.datadir,
            self.actions_dir,
            self.webdir,
            self.resourcesdir,
            self.backupbasedir,
            self.backupdir,
            self.upload_dir,
            self.logsdir,
            self.output_dir,
            self.input_dir,
            self.crackedpwddir,
            self.datastolendir,
            self.zombiesdir,
            self.vulnerabilities_dir,
            self.scan_results_dir,
            self.picdir,
            self.fontdir,
            self.commentsdir,
            self.statuspicdir,
            self.staticpicdir,
            self.dictionarydir
        ]
        
        for directory in directories_to_create:
            try:
                if not os.path.exists(directory):
                    os.makedirs(directory, exist_ok=True)
                    logger.info(f"Created directory: {directory}")
            except Exception as e:
                logger.error(f"Failed to create directory {directory}: {e}")
    

    # def initialize_epd_display(self):
    #     """Initialize the e-paper display."""
    #     try:
    #         logger.info("Initializing EPD display...")
    #         time.sleep(1)
    #         self.epd_helper = EPDHelper(self.config["epd_type"])
    #         self.epd_helper = EPDHelper(self.epd_type)
    #         if self.config["epd_type"] == "epd2in13_V2":
    #             logger.info("EPD type: epd2in13_V2 screen reversed")
    #             self.screen_reversed = False
    #             self.web_screen_reversed = False
    #         elif self.config["epd_type"] == "epd2in13_V3":
    #             logger.info("EPD type: epd2in13_V3 screen reversed")
    #             self.screen_reversed = False
    #             self.web_screen_reversed = False
    #         elif self.config["epd_type"] == "epd2in13_V4":
    #             logger.info("EPD type: epd2in13_V4 screen reversed")
    #             self.screen_reversed = True
    #             self.web_screen_reversed = True
    #         self.epd_helper.init_full_update()
    #         self.width, self.height = self.epd_helper.epd.width, self.epd_helper.epd.height
    #         logger.info(f"EPD {self.config['epd_type']} initialized with size: {self.width}x{self.height}")
    #     except Exception as e:
    #         logger.error(f"Error initializing EPD display: {e}")
    #         raise
    def initialize_epd_display(self):
        """Initialize the e-paper display."""
        if EPDHelper is None or self._pager_mode:
            logger.info("EPD not available (Pager mode or missing module) - skipping EPD init")
            self.epd_helper = None
            fallback_profile = DISPLAY_PROFILES.get(DEFAULT_EPD_TYPE, {"ref_width": 122, "ref_height": 250, "default_flip": False})
            epd_type = self.config.get('epd_type') or DEFAULT_EPD_TYPE
            profile = DISPLAY_PROFILES.get(epd_type, fallback_profile) or fallback_profile
            self.width = self.config.get('ref_width', profile['ref_width'])
            self.height = self.config.get('ref_height', profile['ref_height'])
            self.screen_reversed = normalize_rotation(self.config.get('screen_reversed', 0))
            self.web_screen_reversed = self.screen_reversed
            return

        # Non-EPD displays (character LCDs and LED matrices) have no PIL buffer
        # interface — skip EPDHelper init entirely for these types.
        _NON_EPD_DISPLAYS = {"lcd1602", "max7219_4panel", "max7219_8panel"}
        epd_type_cfg = self.config.get("epd_type", DEFAULT_EPD_TYPE)
        if epd_type_cfg in _NON_EPD_DISPLAYS:
            profile = DISPLAY_PROFILES.get(epd_type_cfg, {})
            self.width  = profile.get("ref_width",  16)
            self.height = profile.get("ref_height",  2)
            self.epd_helper = None
            self.screen_reversed     = normalize_rotation(self.config.get("screen_reversed", 0))
            self.web_screen_reversed = self.screen_reversed
            self.apply_display_profile(epd_type_cfg)
            logger.info(
                f"Non-EPD display '{epd_type_cfg}' configured: {self.width}x{self.height}"
                " — skipping EPD buffer init"
            )
            return

        try:
            logger.info("Initializing EPD display...")
            epd_type = self.config.get("epd_type", DEFAULT_EPD_TYPE)

            # Auto-detect if set to "auto" OR if still on factory default (user never ran installer with detection)
            needs_detect = epd_type == "auto"
            if not needs_detect:
                # Also auto-detect if the configured driver doesn't exist or can't load
                try:
                    EPDHelper(epd_type)
                except Exception:
                    logger.warning(f"Configured EPD driver '{epd_type}' failed to load, switching to auto-detect")
                    needs_detect = True

            if needs_detect:
                logger.info("EPD auto-detection running...")
                result = EPDHelper.auto_detect()
                if result:
                    epd_type = result[0]
                    logger.info(f"Auto-detected EPD: {epd_type} ({result[1]}x{result[2]})")
                    self.config['epd_type'] = epd_type
                    self.save_config()
                else:
                    logger.warning("Auto-detection found no display, using default")
                    epd_type = DEFAULT_EPD_TYPE

            self.epd_helper = EPDHelper(epd_type)
            self.apply_display_profile(epd_type)
            self.screen_reversed = normalize_rotation(self.config.get("screen_reversed", 0))
            self.web_screen_reversed = self.screen_reversed
            logger.info(f"EPD type: {epd_type} | size: {self.epd_helper.epd.width}x{self.epd_helper.epd.height} | rotation: {self.screen_reversed}°")
            self.epd_helper.init_full_update()
            self.width, self.height = self.epd_helper.epd.width, self.epd_helper.epd.height

            # Validate the driver works by doing a test getbuffer with a blank image
            try:
                assert Image is not None
                test_img = Image.new('1', (self.width, self.height), 255)
                test_buf = self.epd_helper.epd.getbuffer(test_img)
                expected_size = int(self.width / 8) * self.height
                if len(test_buf) < expected_size:
                    raise ValueError(f"Buffer size mismatch: got {len(test_buf)}, expected {expected_size}")
            except Exception as ve:
                logger.warning(f"EPD driver '{epd_type}' buffer validation failed: {ve}, trying auto-detect...")
                raise  # Fall through to the auto-detect fallback below

            logger.info(f"EPD {self.config['epd_type']} initialized with size: {self.width}x{self.height}")
        except Exception as e:
            logger.error(f"Error initializing EPD display: {e}")
            # Try auto-detection as fallback before giving up
            logger.info("Attempting auto-detection as fallback...")
            try:
                result = EPDHelper.auto_detect()
                if result:
                    epd_type = result[0]
                    logger.info(f"Fallback auto-detected EPD: {epd_type} ({result[1]}x{result[2]})")
                    self.config['epd_type'] = epd_type
                    self.apply_display_profile(epd_type)
                    self.epd_helper = EPDHelper(epd_type)
                    self.epd_helper.init_full_update()
                    self.width, self.height = self.epd_helper.epd.width, self.epd_helper.epd.height
                    self.screen_reversed = normalize_rotation(self.config.get("screen_reversed", 0))
                    self.web_screen_reversed = self.screen_reversed
                    self.save_config()
                    logger.info(f"EPD {epd_type} initialized via fallback with size: {self.width}x{self.height}")
                    return
            except Exception as e2:
                logger.error(f"Fallback auto-detection also failed: {e2}")
            logger.warning("Continuing without EPD display support")
            self.epd_helper = None
            fallback_profile = DISPLAY_PROFILES.get(DEFAULT_EPD_TYPE, {"ref_width": 122, "ref_height": 250, "default_flip": False})
            epd_type = self.config.get('epd_type') or DEFAULT_EPD_TYPE
            profile = DISPLAY_PROFILES.get(epd_type, fallback_profile) or fallback_profile
            self.width = self.config.get('ref_width', profile['ref_width'])
            self.height = self.config.get('ref_height', profile['ref_height'])
            self.screen_reversed = normalize_rotation(self.config.get('screen_reversed', 0))
            self.web_screen_reversed = self.screen_reversed
            
            # NOTE: Test image code below was used to verify EPD hardware. 
            # Commented out to allow normal Ragnar display to show.
            # Uncomment if you need to test the display again.
            # from PIL import ImageDraw
            # test_image = Image.new('1', (self.width, self.height), 255)
            # draw = ImageDraw.Draw(test_image)
            # draw.text((10, 10), "EPD Test", fill=0)
            # if self.config.get("reversed", False):
            #     test_image = test_image.rotate(180)
            # self.epd_helper.epd.display(self.epd_helper.epd.getbuffer(test_image))
            # logger.info("Test image displayed on EPD.")
        
    def initialize_variables(self):
        """Initialize the variables."""
        self.should_exit = False
        self.display_should_exit = False
        self.orchestrator_should_exit = False
        self.webapp_should_exit = False 
        self.ragnar_instance = None
        self.gateway_info = {}  # Populated by NetworkScanner.get_gateway_info()
        self.wifichanged = False
        self.bluetooth_active = False
        self.bluetooth_scan_active = False
        self.bluetooth_scan_start_time = 0.0
        self.wifi_connected = False
        self.wifi_signal_dbm = None  # Latest RSSI value for display
        self.wifi_signal_quality = None  # Normalized 0-100 quality percentage
        self.pan_connected = False
        self.usb_active = False
        self.ragnarsays = "Hacking away..."
        self.ragnarorch_status = "IDLE"
        self.ragnarstatustext = "IDLE"
        self.ragnarstatustext2 = "Awakening..."
        self.scale_factor_x = self.width / self.config['ref_width']
        self.scale_factor_y = self.height / self.config['ref_height']
        self.text_frame_top = int(88 * self.scale_factor_y)
        self.text_frame_bottom = int(159 * self.scale_factor_y)
        self.y_text = self.text_frame_top + 2
        self.targetnbr = 0
        self.portnbr = 0
        self.vulnnbr = 0
        self.crednbr = 0
        self.datanbr = 0
        self.zombiesnbr = 0
        self.coinnbr = 0
        self.levelnbr = 0
        self.networkkbnbr = 0
        self.attacksnbr = 0
        self.vulnerable_host_count = 0
        self.gamification_data = {}
        self.points_per_level = 200
        self.points_per_mac = 15
        self.points_per_credential = 25
        self.points_per_data_file = 10
        self.points_per_zombie = 40
        self.points_per_vulnerability = 20
        self.show_first_image = True
        self.network_hosts_snapshot = {}
        self.total_targetnbr = 0
        self.inactive_targetnbr = 0
        self.new_targets = 0
        self.lost_targets = 0
        self.new_target_ips = []
        self.lost_target_ips = []
        self.last_sync_timestamp = 0.0
        self.imagegen = None  # Initialize imagegen variable
        self.x_center = 0  # Initialize x_center for image positioning
        self.y_bottom = 0  # Initialize y_bottom for image positioning
        self.x_center1 = 0  # Alternative positioning
        self.y_bottom1 = 0  # Alternative positioning
        
        # In-memory scan results keyed per active network for orchestrator access
        self._latest_scan_results = {}
        self._scan_results_lock = threading.Lock()

        # Subnet scan log – ring buffer of recent scan events for the UI
        self._subnet_scan_log = []          # list of dicts
        self._subnet_scan_log_lock = threading.Lock()
        self._SUBNET_LOG_MAX = 50           # keep last 50 entries

    def load_gamification_data(self):
        """Load persistent gamification progress from disk."""
        os.makedirs(self.datadir, exist_ok=True)

        default_data = {
            "version": 1,
            "total_points": 0,
            "level": 1,
            "mac_points": {},
            "lifetime_counts": {}
        }

        loaded_data = {}
        if os.path.exists(self.gamification_file):
            try:
                with open(self.gamification_file, 'r', encoding='utf-8') as fp:
                    raw_data = json.load(fp)
                    if isinstance(raw_data, dict):
                        loaded_data = raw_data
            except json.JSONDecodeError:
                logger.warning("Gamification file is corrupted; starting with defaults")
            except Exception as exc:
                logger.warning(f"Unable to load gamification file: {exc}")

        self.gamification_data = {**default_data, **loaded_data}
        if not isinstance(self.gamification_data.get("mac_points"), dict):
            self.gamification_data["mac_points"] = {}
        if not isinstance(self.gamification_data.get("lifetime_counts"), dict):
            self.gamification_data["lifetime_counts"] = {}

        self._update_gamification_state()

    def save_gamification_data(self):
        """Persist gamification progress to disk."""
        try:
            os.makedirs(os.path.dirname(self.gamification_file), exist_ok=True)
            data_to_save = dict(self.gamification_data)
            data_to_save["total_points"] = int(self.gamification_data.get("total_points", 0) or 0)
            data_to_save["level"] = int(self.gamification_data.get("level", 1) or 1)
            with open(self.gamification_file, 'w', encoding='utf-8') as fp:
                json.dump(data_to_save, fp, indent=4)
        except Exception as exc:
            logger.error(f"Failed to save gamification data: {exc}")

    def calculate_level(self, total_points: int) -> int:
        """Calculate the level from total points using a slower progression curve."""
        if total_points < 0:
            total_points = 0
        return max(1, 1 + total_points // max(self.points_per_level, 1))

    def _update_gamification_state(self):
        """Synchronize in-memory level/points from gamification data."""
        total_points = int(self.gamification_data.get("total_points", 0) or 0)
        self.coinnbr = total_points
        self.levelnbr = self.calculate_level(total_points)
        self.gamification_data["level"] = self.levelnbr

    def normalize_mac(self, mac_address: str) -> str:
        """Return a normalized MAC address suitable for persistence."""
        if not mac_address:
            return ""

        mac = mac_address.strip().upper()
        if mac in {"UNKNOWN", "N/A", "NONE"}:
            return ""

        mac = mac.replace('-', ':')
        if '.' in mac:
            mac = mac.replace('.', '')
        mac = mac.replace(' ', '')

        if ':' not in mac and len(mac) == 12:
            mac = ':'.join(mac[i:i + 2] for i in range(0, 12, 2))

        if mac.count(':') == 5:
            if mac in {"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}:
                return ""
            return mac

        return ""

    def process_discovered_macs(self, mac_addresses):
        """Track newly discovered MAC addresses and award points once per device."""
        normalized = {self.normalize_mac(mac) for mac in mac_addresses}
        normalized.discard("")

        if not normalized:
            return 0, 0

        with self._stats_lock:
            mac_points = self.gamification_data.setdefault("mac_points", {})
            new_mac_count = 0
            points_awarded = 0

            for mac in normalized:
                if mac in mac_points:
                    continue
                mac_points[mac] = {
                    "points": self.points_per_mac,
                    "first_seen": datetime.utcnow().isoformat() + "Z"
                }
                new_mac_count += 1
                points_awarded += self.points_per_mac

            if points_awarded:
                previous_points = self.gamification_data.get("total_points", 0)
                self.gamification_data["total_points"] = int(previous_points) + points_awarded
                prev_level = self.levelnbr
                self._update_gamification_state()
                self.save_gamification_data()
                logger.info(
                    f"Awarded {points_awarded} points for {new_mac_count} new MAC address(es). "
                    f"Level {prev_level} -> {self.levelnbr}"
                )

            return new_mac_count, points_awarded

    def delete_webconsolelog(self):
            """Delete the web console log file."""
            try:
                if os.path.exists(self.webconsolelog):
                    os.remove(self.webconsolelog)
                    logger.info(f"Deleted web console log file at {self.webconsolelog}")
                    #recreate the file

                else:
                    logger.info(f"Web console log file not found at {self.webconsolelog} ...")

            except OSError as e:
                logger.error(f"OS error occurred while deleting web console log file: {e}")
            except Exception as e:
                logger.error(f"Unexpected error occurred while deleting web console log file: {e}")

    def create_livestatusfile(self):
        """Create the live status file, it will be used to store the current status of the scan."""
        try:
            if not os.path.exists(self.livestatusfile):
                with open(self.livestatusfile, 'w', newline='') as csvfile:
                    csvwriter = csv.writer(csvfile)
                    csvwriter.writerow(['Total Open Ports', 'Alive Hosts Count', 'All Known Hosts Count', 'Vulnerabilities Count'])
                    csvwriter.writerow([0, 0, 0, 0])
                logger.info(f"Created live status file at {self.livestatusfile}")
            else:
                logger.info(f"Live status file already exists at {self.livestatusfile}")
        except OSError as e:
            logger.error(f"OS error occurred while creating live status file: {e}")
        except Exception as e:
            logger.error(f"Unexpected error occurred while creating live status file: {e}")


    def _generate_actions_json_if_needed(self):
        """Only regenerate actions.json if the action modules have changed.

        Compares the modification time of the actions directory against the
        existing actions.json file.  If no .py file is newer, we also verify
        that every action .py has a corresponding entry in the JSON — a
        previous generation may have missed modules due to transient import
        errors (e.g. scanning.py failing once).
        """
        try:
            if os.path.exists(self.actions_file):
                json_mtime = os.path.getmtime(self.actions_file)
                # Check if any action .py file is newer than actions.json
                needs_regen = False
                py_modules = set()
                for filename in os.listdir(self.actions_dir):
                    if filename.endswith('.py') and filename != '__init__.py':
                        py_modules.add(filename[:-3])
                        py_path = os.path.join(self.actions_dir, filename)
                        if os.path.getmtime(py_path) > json_mtime:
                            needs_regen = True

                if not needs_regen:
                    # Timestamps match — but verify no modules are missing
                    try:
                        with open(self.actions_file, 'r') as f:
                            existing = json.load(f)
                        json_modules = {a.get('b_module') for a in existing}
                        # Modules that have .py files but no JSON entry may have
                        # been skipped due to a transient import failure.  Some
                        # .py files are intentionally excluded (helpers without
                        # b_class/b_status), so only flag if the count differs
                        # significantly — or specifically if critical modules
                        # like 'scanning' are absent.
                        missing = py_modules - json_modules
                        if missing:
                            logger.info(f"actions.json missing modules {missing} — regenerating")
                            needs_regen = True
                    except Exception as e:
                        logger.debug(f"Could not validate actions.json contents: {e}")
                        needs_regen = True

                if not needs_regen:
                    # actions.json is up to date — just load status_list from it
                    self._load_status_list_from_actions_json()
                    logger.info("actions.json is up to date — skipped regeneration")
                    return
        except Exception as e:
            logger.debug(f"Actions freshness check failed, regenerating: {e}")
        # Fall through: regenerate
        self.generate_actions_json()

    def generate_actions_json(self):
        """Generate the actions JSON file, it will be used to store the actions configuration."""
        actions_dir = self.actions_dir
        actions_config = []
        try:
            for filename in os.listdir(actions_dir):
                if filename.endswith('.py') and filename != '__init__.py':
                    module_name = filename[:-3]
                    try:
                        module = importlib.import_module(f'actions.{module_name}')
                        if getattr(module, 'BYPASS_ACTION_MODULE', False):
                            logger.debug(f"Skipping helper module {module_name} (BYPASS_ACTION_MODULE)")
                            continue

                        b_class = getattr(module, 'b_class', None)
                        b_status = getattr(module, 'b_status', None)
                        if not b_class or not b_status:
                            logger.debug(f"Skipping module {module_name} without action metadata")
                            continue

                        b_port = getattr(module, 'b_port', None)
                        b_parent = getattr(module, 'b_parent', None)
                        actions_config.append({
                            "b_module": module_name,
                            "b_class": b_class,
                            "b_port": b_port,
                            "b_status": b_status,
                            "b_parent": b_parent
                        })
                        #add each b_class to the status list
                        self.status_list.append(b_class)
                    except AttributeError as e:
                        logger.error(f"Module {module_name} is missing required attributes: {e}")
                    except ImportError as e:
                        logger.error(f"Error importing module {module_name}: {e}")
                    except Exception as e:
                        logger.error(f"Unexpected error while processing module {module_name}: {e}")
            
            try:
                with open(self.actions_file, 'w') as file:
                    json.dump(actions_config, file, indent=4)
            except IOError as e:
                logger.error(f"Error writing to file {self.actions_file}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error while writing to file {self.actions_file}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in generate_actions_json: {e}")

    def _load_status_list_from_actions_json(self):
        """Load status_list from an existing actions.json (Pager mode).
        On the Pager, action modules can't be imported (missing pandas/rich),
        so we read the pre-deployed actions.json instead of regenerating it."""
        try:
            if os.path.exists(self.actions_file):
                with open(self.actions_file, 'r') as f:
                    actions = json.load(f)
                    for action in actions:
                        b_class = action.get('b_class')
                        if b_class and b_class not in self.status_list:
                            self.status_list.append(b_class)
                logger.info(f"Loaded {len(self.status_list)} action statuses from actions.json")
            else:
                logger.warning("actions.json not found - status animations will be unavailable")
        except Exception as e:
            logger.error(f"Error loading actions.json: {e}")

    def initialize_csv(self):
        """Initialize the network knowledge base CSV file with headers."""
        logger.info("Initializing the network knowledge base CSV file with headers")
        try:
            if not os.path.exists(self.netkbfile):
                try:
                    with open(self.actions_file, 'r') as file:
                        actions = json.load(file)
                    action_names = [action["b_class"] for action in actions if "b_class" in action]
                except FileNotFoundError as e:
                    logger.error(f"Actions file not found: {e}")
                    return
                except json.JSONDecodeError as e:
                    logger.error(f"Error decoding JSON from actions file: {e}")
                    return
                except Exception as e:
                    logger.error(f"Unexpected error reading actions file: {e}")
                    return

                headers = ["MAC Address", "IPs", "Hostnames", "Alive", "Ports", "Failed_Pings"] + action_names

                try:
                    with open(self.netkbfile, 'w', newline='') as file:
                        writer = csv.writer(file)
                        writer.writerow(headers)
                    logger.info(f"Network knowledge base CSV file created at {self.netkbfile}")
                except IOError as e:
                    logger.error(f"Error writing to netkbfile: {e}")
                except Exception as e:
                    logger.error(f"Unexpected error while writing to netkbfile: {e}")
            else:
                logger.info(f"Network knowledge base CSV file already exists at {self.netkbfile}")
        except Exception as e:
            logger.error(f"Unexpected error in initialize_csv: {e}")


    def load_config(self):
        """Load the configuration from the shared configuration JSON file."""
        try:
            logger.info("Loading configuration...")
            if os.path.exists(self.shared_config_json):
                # Check if file is empty before attempting to parse
                if os.path.getsize(self.shared_config_json) == 0:
                    logger.warning("Configuration file is empty, creating new one with default values...")
                    self.save_config()
                    return
                with open(self.shared_config_json, 'r') as f:
                    config = json.load(f)
                    config = self._normalize_config_keys(config)
                    self.config.update(config)
                    self.config = self._normalize_config_keys(self.config)
                    for key, value in self.config.items():
                        setattr(self, key, value)
                    self._remove_legacy_attributes()
            else:
                logger.warning("Configuration file not found, creating new one with default values...")
                self.save_config()
                self.load_config()
                time.sleep(2)
        except json.JSONDecodeError as e:
            logger.error(f"Configuration file is corrupted or invalid JSON: {e}")
            logger.warning("Recreating configuration file with default values...")
            self.save_config()
        except FileNotFoundError:
            logger.error("Error loading configuration: File not found.")
            self.save_config()

    def save_config(self):
        """Save the configuration to the shared configuration JSON file."""
        logger.info("Saving configuration...")
        try:
            if not os.path.exists(self.configdir):
                os.makedirs(self.configdir)
                logger.info(f"Created configuration directory at {self.configdir}")
            try:
                self.config = self._normalize_config_keys(self.config)
                with open(self.shared_config_json, 'w') as f:
                    json.dump(self.config, f, indent=4)
                logger.info(f"Configuration saved to {self.shared_config_json}")
            except IOError as e:
                logger.error(f"Error writing to configuration file: {e}")
            except Exception as e:
                logger.error(f"Unexpected error while writing to configuration file: {e}")
        except OSError as e:
            logger.error(f"OS error while creating configuration directory: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in save_config: {e}")

    def load_fonts(self):
        """Load the fonts, scaled for the current display size."""
        if ImageFont is None:
            logger.info("PIL not available - skipping font loading (Pager uses file paths)")
            return
        try:
            logger.info("Loading fonts...")
            sf = getattr(self, 'scale_factor_y', 1.0)
            sx = getattr(self, 'scale_factor_x', 1.0)
            is_wide = sx > 1.2  # Display is significantly wider than 2.13" (e.g. 2.7")

            self.font_arial14 = self.load_font('Arial.ttf', max(9, int(14 * sf)))
            self.font_arial11 = self.load_font('Arial.ttf', max(8, int(11 * sf)))
            self.font_arial9 = self.load_font('Arial.ttf', max(7, int(9 * sf)))
            self.font_arialbold = self.load_font('Arial.ttf', max(9, int(12 * sf)))

            # Viking title font: keep same size on wider displays (no reduction needed)
            if is_wide:
                viking_size = max(10, int(13 * sf))
                viking_sm_size = max(8, int(10 * sf))
            else:
                viking_size = max(10, int(13 * sf))
                viking_sm_size = max(8, int(10 * sf))
            self.font_viking = self.load_font('Viking.TTF', viking_size)
            self.font_viking_sm = self.load_font('Viking.TTF', viking_sm_size)

        except Exception as e:
            logger.error(f"Error loading fonts: {e}")
            raise

    def load_font(self, font_name, size):
        """Load a font."""
        if ImageFont is None:
            return None
        try:
            return ImageFont.truetype(os.path.join(self.fontdir, font_name), size)
        except Exception as e:
            logger.error(f"Error loading font {font_name}: {e}")
            raise

    def _get_image_scale(self):
        """Get the image scale factor for the current display.
        For small displays (2.13", 2.7") icons stay at native size.
        For large displays (4.26" 800x480) icons scale up proportionally."""
        sy = getattr(self, 'scale_factor_y', 1.0)
        if sy > 1.5:  # Large display (e.g. 4.26")
            return sy
        return 1.0

    def load_images(self):
        """Load the images for the e-paper display, scaled for display size."""
        try:
            logger.info("Loading images...")
            img_scale = self._get_image_scale()

            # Load static images from the root of staticpicdir
            self.ragnarstatusimage = None
            self.ragnar1 = self.load_image(os.path.join(self.staticpicdir, 'ragnar1.bmp'), scale=img_scale)
            self.port = self.load_image(os.path.join(self.staticpicdir, 'port.bmp'), scale=img_scale)
            self.frise = self.load_image(os.path.join(self.staticpicdir, 'frise.bmp'))
            self.target = self.load_image(os.path.join(self.staticpicdir, 'target.bmp'), scale=img_scale)
            self.vuln = self.load_image(os.path.join(self.staticpicdir, 'vuln.bmp'), scale=img_scale)
            self.connected = self.load_image(os.path.join(self.staticpicdir, 'connected.bmp'), scale=img_scale)
            self.bluetooth = self.load_image(os.path.join(self.staticpicdir, 'bluetooth.bmp'), scale=img_scale)
            self.wifi = self.load_image(os.path.join(self.staticpicdir, 'wifi.bmp'), scale=img_scale)
            self.ethernet = self.load_image(os.path.join(self.staticpicdir, 'ethernet.bmp'), scale=img_scale)
            self.usb = self.load_image(os.path.join(self.staticpicdir, 'usb.bmp'), scale=img_scale)
            self.level = self.load_image(os.path.join(self.staticpicdir, 'level.bmp'), scale=img_scale)
            self.cred = self.load_image(os.path.join(self.staticpicdir, 'cred.bmp'), scale=img_scale)
            self.attack = self.load_image(os.path.join(self.staticpicdir, 'attack.bmp'), scale=img_scale)
            self.attacks = self.load_image(os.path.join(self.staticpicdir, 'attacks.bmp'), scale=img_scale)
            self.gold = self.load_image(os.path.join(self.staticpicdir, 'gold.bmp'), scale=img_scale)
            self.networkkb = self.load_image(os.path.join(self.staticpicdir, 'networkkb.bmp'), scale=img_scale)
            self.zombie = self.load_image(os.path.join(self.staticpicdir, 'zombie.bmp'), scale=img_scale)
            self.data = self.load_image(os.path.join(self.staticpicdir, 'data.bmp'), scale=img_scale)
            self.money = self.load_image(os.path.join(self.staticpicdir, 'money.bmp'), scale=img_scale)
            self.zombie_status = self.load_image(os.path.join(self.staticpicdir, 'zombie.bmp'), scale=img_scale)
            self.attack = self.load_image(os.path.join(self.staticpicdir, 'attack.bmp'), scale=img_scale)

            # Resize frise to span full display width (and scale height on large displays)
            if self.frise is not None and Image is not None and hasattr(self, 'width') and self.frise.width < self.width:
                new_h = max(self.frise.height, int(self.frise.height * img_scale)) if img_scale > 1.0 else self.frise.height
                self.frise = self.frise.resize((self.width - 2, new_h), Image.Resampling.NEAREST)

            """ Load the images for the different actions status"""
            # Dynamically load status images based on actions.json
            try:
                with open(self.actions_file, 'r') as f:
                    actions = json.load(f)
                    for action in actions:
                        b_class = action.get('b_class')
                        if b_class:
                            indiv_status_path = os.path.join(self.statuspicdir, b_class)
                            image_path = os.path.join(indiv_status_path, f'{b_class}.bmp')
                            image = self.load_image(image_path, scale=img_scale)
                            setattr(self, b_class, image)
                            logger.info(f"Loaded image for {b_class} from {image_path}")
            except Exception as e:
                logger.error(f"Error loading images from actions file: {e}")

            # Load image series dynamically from subdirectories
            self.image_series = {}
            for status in self.status_list:
                self.image_series[status] = []
                status_dir = os.path.join(self.statuspicdir, status)
                if not os.path.isdir(status_dir):
                    os.makedirs(status_dir)
                    logger.warning(f"Directory {status_dir} did not exist and was created.")
                    logger.warning(f" {status} wil use the IDLE images till you add some images in the {status} folder")

                for image_name in os.listdir(status_dir):
                    if image_name.endswith('.bmp') and re.search(r'\d', image_name):
                        image = self.load_image(os.path.join(status_dir, image_name), scale=img_scale)
                        if image:
                            self.image_series[status].append(image)

            if not self.image_series:
                logger.error("No images loaded.")
            else:
                for status, images in self.image_series.items():
                    logger.info(f"Loaded {len(images)} images for status {status}.")


            """Calculate the position of the Ragnar image on the screen to center it"""
            if self.ragnar1 is not None:
                self.x_center1 = (self.width - self.ragnar1.width) // 2
                self.y_bottom1 = self.height - self.ragnar1.height
            else:
                logger.warning("ragnar1.bmp image not found, using default positioning")
                self.x_center1 = self.width // 2  # Center horizontally
                self.y_bottom1 = self.height - 20  # Default bottom position

        except Exception as e:
            logger.error(f"Error loading images: {e}")
            raise

    def update_ragnarstatus(self):
        """ Using getattr to obtain the reference of the attribute with the name stored in self.ragnarorch_status"""
        try:
            self.ragnarstatusimage = getattr(self, self.ragnarorch_status)
            if self.ragnarstatusimage is None:
                raise AttributeError
        except AttributeError:
            logger.warning(f"The image for status {self.ragnarorch_status} is not available, using IDLE image by default.")
            self.ragnarstatusimage = self.attack
        
        self.ragnarstatustext = self.ragnarorch_status  # Mettre à jour le texte du statut


    def load_image(self, image_path, scale=None):
        """Load an image, optionally resizing it by the given scale factor."""
        if Image is None:
            return None
        try:
            if not os.path.exists(image_path):
                logger.warning(f"Warning: {image_path} does not exist.")
                return None
            img = Image.open(image_path)
            if scale is not None and scale != 1.0 and scale > 1.05:
                new_w = max(1, int(img.width * scale))
                new_h = max(1, int(img.height * scale))
                img = img.resize((new_w, new_h), Image.Resampling.NEAREST)
            return img
        except Exception as e:
            logger.error(f"Error loading image {image_path}: {e}")
            raise

    def update_image_randomizer(self):
        """Update the image randomizer and the imagegen variable."""
        try:
            status = self.ragnarstatustext
            if status in self.image_series and self.image_series[status]:
                random_index = random.randint(0, len(self.image_series[status]) - 1)
                self.imagegen = self.image_series[status][random_index]
                self.x_center = (self.width - self.imagegen.width) // 2
                self.y_bottom = self.height - self.imagegen.height
            else:
                logger.warning(f"Warning: No images available for status {status}, defaulting to IDLE images.")
                if "IDLE" in self.image_series and self.image_series["IDLE"]:
                    random_index = random.randint(0, len(self.image_series["IDLE"]) - 1)
                    self.imagegen = self.image_series["IDLE"][random_index]
                    self.x_center = (self.width - self.imagegen.width) // 2
                    self.y_bottom = self.height - self.imagegen.height
                else:
                    logger.error("No IDLE images available either.")
                    self.imagegen = None
        except Exception as e:
            logger.error(f"Error updating image randomizer: {e}")
            self.imagegen = None

    def wrap_text(self, text, font, max_width):
        """Wrap text to fit within a specified width when rendered.
        On Pager, this is monkey-patched by PagerRagnar.setup_pager_shared_data()
        to use character-based wrapping instead of PIL fonts."""
        if font is None or ImageFont is None:
            # Fallback: character-based wrapping (no PIL)
            lines = []
            for line in text.split('\n'):
                while len(line) > 40:
                    lines.append(line[:40])
                    line = line[40:]
                lines.append(line)
            return lines
        try:
            lines = []
            words = text.split()
            while words:
                line = ''
                while words and font.getlength(line + words[0]) <= max_width:
                    line = line + (words.pop(0) + ' ')
                lines.append(line)
            return lines
        except Exception as e:
            logger.error(f"Error wrapping text: {e}")
            raise


    def _slug_for_ssid(self, ssid):
        if self.storage_manager is not None and hasattr(self.storage_manager, '_slugify'):
            try:
                return self.storage_manager._slugify(ssid)
            except Exception:
                return self.storage_manager.default_ssid
        if self.storage_manager is not None:
            return (ssid or self.storage_manager.default_ssid or 'default')
        return ssid or 'default'

    # ── Subnet scan log helpers ──────────────────────────────────
    def append_subnet_scan_log(self, cidr, status, message, devices=None):
        """Append an entry to the subnet scan log visible in the UI.

        Args:
            cidr:    The subnet that was scanned (or 'primary').
            status:  'ok' | 'error' | 'info' | 'skip'
            message: Human-readable description.
            devices: Number of devices found (optional).
        """
        import datetime as _dt
        entry = {
            'ts': _dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'cidr': str(cidr),
            'status': status,
            'msg': message,
        }
        if devices is not None:
            entry['devices'] = int(devices)
        with self._subnet_scan_log_lock:
            self._subnet_scan_log.append(entry)
            # trim to ring-buffer size
            if len(self._subnet_scan_log) > self._SUBNET_LOG_MAX:
                self._subnet_scan_log = self._subnet_scan_log[-self._SUBNET_LOG_MAX:]

    def get_subnet_scan_log(self):
        """Return a copy of the scan log (newest last)."""
        with self._subnet_scan_log_lock:
            return list(self._subnet_scan_log)

    def set_latest_scan_results(self, scan_data):
        """Store fresh scan results scoped to the currently active network."""
        slug = self._slug_for_ssid(self.active_network_ssid)
        with self._scan_results_lock:
            self._latest_scan_results[slug] = {
                'data': scan_data,
                'timestamp': time.time(),
                'ssid': self.active_network_ssid,
            }
            logger.info(
                f"📋 Stored {len(scan_data or []) if scan_data else 0} hosts for network slug '{slug}'"
            )
    
    def get_latest_scan_results(self, ssid=None):
        """Retrieve fresh scan results from memory for a specific SSID (defaults to active)."""
        slug = self._slug_for_ssid(ssid or self.active_network_ssid)
        with self._scan_results_lock:
            entry = self._latest_scan_results.get(slug)
            if not entry:
                return None
            data = entry.get('data')
            age_seconds = time.time() - entry.get('timestamp', 0)
            logger.info(
                f"📋 Retrieved {len(data or []) if data else 0} hosts from cache (slug={slug}, age={age_seconds:.1f}s)"
            )
            return data

    def get_cached_network_slugs(self):
        with self._scan_results_lock:
            return list(self._latest_scan_results.keys())
    
    def read_data(self):
        """
        Read data from SQLite database.
        Returns data in the same format as CSV for backward compatibility.
        """
        data = []
        
        try:
            if self.db is None:
                return []
            # Read from SQLite database (PRIMARY AND ONLY DATA SOURCE)
            hosts = self.db.get_all_hosts()
            
            if not hosts:
                logger.debug("No hosts found in database")
                return []
            
            # Convert database format to CSV-compatible format
            for host in hosts:
                # Convert to format expected by orchestrator
                row = {
                    'MAC Address': host.get('mac', ''),
                    'IPs': host.get('ip', ''),
                    'Hostnames': host.get('hostname', ''),
                    'Alive': '1' if host.get('status') == 'alive' else '0',
                    'Ports': host.get('ports', ''),
                    'Failed_Pings': str(host.get('failed_ping_count', 0)),
                    'Services': host.get('services', ''),
                    'Nmap Vulnerabilities': host.get('vulnerabilities', ''),
                    'Alive Count': str(host.get('alive_count', 0)),
                    'Network Profile': host.get('network_profile', ''),
                    'Scanner': host.get('scanner_status', ''),
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
                    'Notes': host.get('notes', ''),
                    'Deep_Scanned': '',  # TODO: Add to database schema
                    'Deep_Scan_Ports': '',  # TODO: Add to database schema
                }
                data.append(row)
            
            logger.debug(f"✅ Read {len(data)} hosts from SQLite database")
            return data
            
        except Exception as e:
            logger.error(f"Error reading from database: {e}")
            logger.debug(f"Traceback: {traceback.format_exc()}")
            return []  # Return empty list on database error
    

    def _start_cleanup_task(self):
        """Start background task to cleanup old hosts (not seen in 24 hours)."""
        def cleanup_worker():
            import time
            while True:
                try:
                    # Run cleanup every hour
                    time.sleep(3600)
                    if self.db is None:
                        continue
                    removed = self.db.cleanup_old_hosts(hours=24)
                    if removed > 0:
                        logger.info(f"🧹 Cleanup: Removed {removed} hosts not seen in 24 hours")
                except Exception as e:
                    logger.error(f"Error in cleanup task: {e}")
        
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True, name="HostCleanup")
        cleanup_thread.start()
        logger.info("Started background host cleanup task (runs hourly)")

    def write_data(self, data):
        """
        DEPRECATED: CSV write operations no longer supported.
        All data is now stored in SQLite database.
        Use db.upsert_host() to write host data.
        This method is kept for backward compatibility but does nothing.
        """
        logger.warning("write_data() is deprecated - all data is now stored in SQLite database")
        logger.debug(f"Ignoring write_data call with {len(data) if data else 0} entries")
        pass

    def update_stats(self, persist=True):
        """Update gamification stats using lifetime achievements and SQLite database statistics."""
        with self._stats_lock:
            # Get current statistics from SQLite database
            try:
                if self.db is None:
                    db_stats = {}
                else:
                    db_stats = self.db.get_stats()
                # NOTE: Do NOT update vulnnbr here - it's managed by sync_vulnerability_count()
                # which uses network intelligence (114 vulns) instead of just database hosts_with_vulns (3)
                
                # Update zombie count from database (could be hosts with successful attacks)
                if 'total_hosts' in db_stats:
                    # This is a placeholder - adjust based on actual zombie logic
                    pass
            except Exception as e:
                logger.error(f"Failed to get stats from database: {e}")
            
            lifetime_counts = self.gamification_data.setdefault("lifetime_counts", {})
            total_added = 0
            awarded_breakdown = {}

            metrics = {
                "crednbr": (int(self.crednbr or 0), self.points_per_credential),
                "datanbr": (int(self.datanbr or 0), self.points_per_data_file),
                "zombiesnbr": (int(self.zombiesnbr or 0), self.points_per_zombie),
                "vulnnbr": (int(self.vulnnbr or 0), self.points_per_vulnerability),
            }

            for key, (current_value, points_value) in metrics.items():
                recorded_value = int(lifetime_counts.get(key, 0) or 0)
                if current_value > recorded_value:
                    delta = current_value - recorded_value
                    lifetime_counts[key] = current_value
                    points_gained = delta * points_value
                    total_added += points_gained
                    awarded_breakdown[key] = {
                        "delta": delta,
                        "points": points_gained
                    }
                else:
                    lifetime_counts[key] = max(recorded_value, current_value)

            if total_added:
                self.gamification_data["total_points"] = int(self.gamification_data.get("total_points", 0)) + total_added
                logger.info(f"Awarded {total_added} points from new achievements: {awarded_breakdown}")

            previous_points = self.coinnbr
            previous_level = self.levelnbr
            self._update_gamification_state()

            if persist and (total_added or self.coinnbr != previous_points or self.levelnbr != previous_level):
                self.save_gamification_data()

            return total_added


    def print(self, message):
        """Print a debug message if debug mode is enabled."""
        if self.config['debug_mode']:
            logger.debug(message)
