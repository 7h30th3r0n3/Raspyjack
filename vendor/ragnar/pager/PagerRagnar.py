#PagerRagnar.py
# Entry point for Ragnar on the WiFi Pineapple Pager.
# Combines Ragnar's orchestrator with the Pager LCD display.
# Adapted from pineapple_pager_bjorn's Bjorn.py for Ragnar.

# Add local lib directory to Python path for self-contained payload
import sys
import os
_lib_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib')
if os.path.exists(_lib_path) and _lib_path not in sys.path:
    sys.path.insert(0, _lib_path)

# Fix OpenSSL legacy provider issue for cryptography/paramiko
os.environ['CRYPTOGRAPHY_OPENSSL_NO_LEGACY'] = '1'

import threading
import signal
import logging
import time
import subprocess
import re
import json
import random
from logger import Logger

logger = Logger(name="PagerRagnar.py", level=logging.INFO)


def setup_pager_shared_data(shared_data):
    """Patch shared_data with Pager-specific attributes needed by pager_display.py.
    Ragnar's shared.py loads PIL Images; the Pager needs file paths instead."""

    currentdir = shared_data.currentdir
    fontdir = shared_data.fontdir
    staticpicdir = shared_data.staticpicdir
    statuspicdir = shared_data.statuspicdir

    # Font paths (pager_display uses pagerctl TTF rendering, not PIL)
    shared_data.font_arial_path = os.path.join(fontdir, 'Arial.ttf')
    shared_data.font_viking_path = os.path.join(fontdir, 'Viking.TTF')

    # Status image path (updated by update_ragnarstatus_pager)
    shared_data.ragnarstatusimage_path = None

    # Static image paths dict (icon_name -> file_path)
    shared_data.static_images = {}
    static_names = ['ragnar1', 'port', 'frise', 'target', 'vuln', 'connected',
                    'bluetooth', 'wifi', 'ethernet', 'usb', 'level', 'cred',
                    'attack', 'attacks', 'gold', 'networkkb', 'zombie', 'data', 'money']
    for name in static_names:
        path = os.path.join(staticpicdir, f'{name}.bmp')
        if os.path.exists(path):
            shared_data.static_images[name] = path

    # Status images dict (b_class -> file_path)
    shared_data.status_images = {}
    try:
        if os.path.exists(shared_data.actions_file):
            with open(shared_data.actions_file, 'r') as f:
                actions = json.load(f)
                for action in actions:
                    b_class = action.get('b_class')
                    if b_class:
                        status_dir = os.path.join(statuspicdir, b_class)
                        image_path = os.path.join(status_dir, f'{b_class}.bmp')
                        if os.path.exists(image_path):
                            shared_data.status_images[b_class] = image_path
    except Exception as e:
        logger.error(f"Error loading status image paths: {e}")

    # Image series paths for animations (b_class -> list of file paths)
    shared_data.pager_image_series = {}
    for status in shared_data.status_list:
        shared_data.pager_image_series[status] = []
        status_dir = os.path.join(statuspicdir, status)
        if os.path.isdir(status_dir):
            for image_name in sorted(os.listdir(status_dir)):
                if image_name.endswith('.bmp') and re.search(r'\d', image_name):
                    image_path = os.path.join(status_dir, image_name)
                    shared_data.pager_image_series[status].append(image_path)

    # Current animation frame path
    shared_data.current_image_path = None

    # Monkey-patch update_ragnarstatus to use file paths
    original_update = shared_data.update_ragnarstatus

    def update_ragnarstatus_pager():
        """Update current status image path for Pager display."""
        try:
            if shared_data.ragnarorch_status in shared_data.status_images:
                shared_data.ragnarstatusimage_path = shared_data.status_images[shared_data.ragnarorch_status]
            else:
                shared_data.ragnarstatusimage_path = shared_data.status_images.get('IDLE')
            shared_data.ragnarstatustext = shared_data.ragnarorch_status
        except Exception as e:
            logger.error(f"Error updating ragnar status: {e}")

    shared_data.update_ragnarstatus = update_ragnarstatus_pager

    # Monkey-patch update_image_randomizer to use file paths
    def update_image_randomizer_pager():
        """Select a random animation frame path for current status."""
        try:
            status = shared_data.ragnarstatustext
            series = shared_data.pager_image_series
            if status in series and series[status]:
                idx = random.randint(0, len(series[status]) - 1)
                shared_data.current_image_path = series[status][idx]
            else:
                if "IDLE" in series and series["IDLE"]:
                    idx = random.randint(0, len(series["IDLE"]) - 1)
                    shared_data.current_image_path = series["IDLE"][idx]
                else:
                    shared_data.current_image_path = None
        except Exception as e:
            logger.error(f"Error updating image randomizer: {e}")

    shared_data.update_image_randomizer = update_image_randomizer_pager

    # Add a simple char-based wrap_text if the existing one requires PIL fonts
    original_wrap = shared_data.wrap_text

    def wrap_text_pager(text, max_chars=40, **kwargs):
        """Wrap text by character count (no PIL font needed)."""
        lines = []
        words = text.split()
        line = ''
        for word in words:
            if len(line) + len(word) + 1 <= max_chars:
                line = line + (' ' if line else '') + word
            else:
                if line:
                    lines.append(line)
                line = word
        if line:
            lines.append(line)
        return lines

    shared_data.wrap_text = wrap_text_pager

    logger.info("Pager shared_data attributes initialized")


class PagerRagnar:
    """Main class for Ragnar on Pineapple Pager."""

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.orchestrator_thread = None
        self.orchestrator = None
        self._orchestrator_lock = threading.Lock()

        self.shared_data.ragnar_instance = self
        self.shared_data.headless_mode = False

    def run(self):
        """Main loop - waits for Wi-Fi connection and starts Orchestrator."""
        if hasattr(self.shared_data, 'startup_delay') and self.shared_data.startup_delay > 0:
            logger.info(f"Waiting for startup delay: {self.shared_data.startup_delay} seconds")
            time.sleep(self.shared_data.startup_delay)

        while not self.shared_data.should_exit:
            if not self.shared_data.manual_mode:
                self.check_and_start_orchestrator()
            time.sleep(10)

    def check_and_start_orchestrator(self):
        if self.is_wifi_connected():
            self.shared_data.wifi_connected = True
            if self.orchestrator_thread is None or not self.orchestrator_thread.is_alive():
                self.start_orchestrator()
        else:
            self.shared_data.wifi_connected = False
            logger.info("Waiting for Wi-Fi connection to start Orchestrator...")

    def start_orchestrator(self):
        with self._orchestrator_lock:
            if self.is_wifi_connected():
                self.shared_data.wifi_connected = True
                if self.orchestrator_thread is None or not self.orchestrator_thread.is_alive():
                    logger.info("Starting Orchestrator thread...")
                    self.shared_data.orchestrator_should_exit = False
                    self.shared_data.manual_mode = False
                    from orchestrator import Orchestrator
                    self.orchestrator = Orchestrator()
                    self.orchestrator_thread = threading.Thread(target=self.orchestrator.run)
                    self.orchestrator_thread.start()
                    logger.info("Orchestrator thread started, automatic mode activated.")

    def stop_orchestrator(self):
        self.shared_data.manual_mode = True
        logger.info("Stopping Orchestrator...")
        if self.orchestrator_thread is not None and self.orchestrator_thread.is_alive():
            self.shared_data.orchestrator_should_exit = True
            self.orchestrator_thread.join()
            self.shared_data.ragnarorch_status = "IDLE"
            self.shared_data.ragnarstatustext2 = ""

    def is_wifi_connected(self):
        """Check Wi-Fi connectivity (Pager + Pi compatible)."""
        try:
            for iface in ['wlan0cli', 'br-lan', 'wlan0', 'eth0']:
                result = subprocess.run(['ip', 'link', 'show', iface],
                                        capture_output=True, text=True, timeout=5)
                if 'state UP' in result.stdout:
                    return True
            return False
        except Exception as e:
            logger.debug(f"WiFi check error: {e}")
            return False


def handle_exit(sig, frame, display_thread, ragnar_thread, web_thread=None):
    from init_shared import shared_data
    shared_data.should_exit = True
    shared_data.orchestrator_should_exit = True
    shared_data.display_should_exit = True
    shared_data.webapp_should_exit = True

    from pager_display import handle_exit_pager_display
    display_inst = getattr(shared_data, 'display_instance', None)
    handle_exit_pager_display(sig, frame, display_inst, exit_process=False)

    if display_thread and display_thread.is_alive():
        display_thread.join(timeout=5)
    if ragnar_thread and ragnar_thread.is_alive():
        ragnar_thread.join(timeout=5)
    if web_thread and web_thread.is_alive():
        web_thread.join(timeout=5)
    logger.info("Clean exit.")
    sys.exit(0)


if __name__ == "__main__":
    logger.info("Starting Pager Ragnar...")

    try:
        from init_shared import shared_data

        # Apply interface/IP from pager_menu environment variables
        ragnar_interface = os.environ.get('RAGNAR_INTERFACE')
        ragnar_ip = os.environ.get('RAGNAR_IP')
        if ragnar_interface:
            shared_data.config['wifi_default_interface'] = ragnar_interface
            logger.info(f"Using interface from menu: {ragnar_interface}")
        if ragnar_ip:
            logger.info(f"Using IP from menu: {ragnar_ip}")

        # Setup Pager-specific attributes on shared_data
        setup_pager_shared_data(shared_data)

        # Start display thread
        logger.info("Starting pager display thread...")
        shared_data.display_should_exit = False

        from pager_display import PagerDisplay
        display = PagerDisplay(shared_data)
        display_thread = threading.Thread(target=display.run)
        display_thread.start()
        shared_data.display_instance = display

        # Start Ragnar thread
        logger.info("Starting PagerRagnar thread...")
        ragnar = PagerRagnar(shared_data)
        shared_data.ragnar_instance = ragnar
        ragnar_thread = threading.Thread(target=ragnar.run)
        ragnar_thread.start()

        # Start web server (conditional on RAGNAR_WEB_UI env var)
        web_thread = None
        web_ui_setting = os.environ.get('RAGNAR_WEB_UI', 'on').lower()
        if web_ui_setting != 'off':
            logger.info("Starting the web server...")
            shared_data.webapp_should_exit = False
            try:
                from webapp_modern import run_server
                web_thread = threading.Thread(target=run_server, daemon=True)
                web_thread.start()
            except ImportError:
                # Fall back to simple webapp if modern not available
                try:
                    from webapp import web_thread as wt
                    wt.start()
                    web_thread = wt
                except ImportError:
                    logger.warning("No web server module available")
        else:
            logger.info("Web server disabled by menu setting")

        signal.signal(signal.SIGINT, lambda sig, frame: handle_exit(sig, frame, display_thread, ragnar_thread, web_thread))
        signal.signal(signal.SIGTERM, lambda sig, frame: handle_exit(sig, frame, display_thread, ragnar_thread, web_thread))

        # Keep main thread alive
        while not shared_data.should_exit:
            time.sleep(1)

    except Exception as e:
        logger.error(f"An exception occurred during thread start: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
