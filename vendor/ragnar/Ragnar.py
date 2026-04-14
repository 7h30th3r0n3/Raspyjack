#ragnar.py
# This script defines the main execution flow for the Ragnar application. It initializes and starts
# various components such as network scanning, display, and web server functionalities. The Ragnar 
# application serves as a comprehensive IoT security tool designed for network analysis and penetration testing.
# It integrates various modules to provide a unified platform for cybersecurity professionals and enthusiasts.

# Essential imports for the application
import asyncio
import os
import signal
import threading
import time
import atexit
try:
    import fcntl  # Unix only
except ImportError:
    fcntl = None
import logging
from collections import defaultdict

# ragnar.py


import threading
import signal
import logging
import time
import sys
import subprocess
from init_shared import shared_data
from display import Display, handle_exit_display
from comment import Commentaireia
from orchestrator import Orchestrator
from logger import Logger
from wifi_manager import WiFiManager
from env_manager import load_env

logger = Logger(name="Ragnar.py", level=logging.DEBUG)

class Ragnar:
    """Main class for Ragnar. Manages the primary operations of the application."""
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.commentaire_ia = Commentaireia()
        self.orchestrator_thread = None
        self.orchestrator = None
        self.wifi_manager = WiFiManager(shared_data)

        # Set reference to this instance in shared_data for other modules
        self.shared_data.ragnar_instance = self
        self.shared_data.headless_mode = False

        # Reference to display instance (will be set when display is started)
        self.display = None

        # PiSugar button listener (for Ragnar/Pwnagotchi swap via hardware button)
        self.pisugar_listener = None
        try:
            from pisugar_button import PiSugarButtonListener
            self.pisugar_listener = PiSugarButtonListener(shared_data)
        except ImportError:
            pass

    def run(self):
        """Main loop for Ragnar. Waits for Wi-Fi connection and starts Orchestrator."""
        logger.info("=" * 70)
        logger.info("RAGNAR MAIN THREAD STARTING")
        logger.info("=" * 70)
        
        # Start PiSugar button listener (if available)
        if self.pisugar_listener:
            self.pisugar_listener.start()

        # Initialize Wi-Fi management system
        logger.info("Starting Wi-Fi management system...")
        self.wifi_manager.start()
        logger.info("Wi-Fi management system started")
        
        # Main loop to keep Ragnar running
        logger.info("Entering main Ragnar loop...")
        loop_count = 0
        while not self.shared_data.should_exit:
            loop_count += 1
            if loop_count % 6 == 1:  # Log every 60 seconds (6 iterations * 10 sec)
                logger.info(f"Ragnar main loop iteration {loop_count}, manual_mode={self.shared_data.manual_mode}")
            
            if not self.shared_data.manual_mode:
                self.check_and_start_orchestrator()
            # Sleep in 1-second chunks so should_exit is checked quickly
            for _ in range(10):
                if self.shared_data.should_exit:
                    break
                time.sleep(1)
        
        logger.info("Ragnar main loop exited")



    def check_and_start_orchestrator(self):
        """Check Wi-Fi and start the orchestrator if connected."""
        wifi_connected = self.wifi_manager.check_wifi_connection()
        logger.debug(f"WiFi connection check: {wifi_connected}")
        
        if wifi_connected:
            self.shared_data.wifi_connected = True
            if self.orchestrator_thread is None or not self.orchestrator_thread.is_alive():
                logger.info("WiFi detected - attempting to start Orchestrator...")
                self.start_orchestrator()
        else:
            self.shared_data.wifi_connected = False
            if not self.wifi_manager.startup_complete:
                logger.info("Waiting for Wi-Fi management system to complete startup...")
            else:
                logger.debug("Waiting for Wi-Fi connection to start Orchestrator...")

    def start_orchestrator(self):
        """Start the orchestrator thread."""
        # Always clear manual mode so the main loop will auto-start
        # the orchestrator when Wi-Fi becomes available
        self.shared_data.manual_mode = False
        self.shared_data.orchestrator_should_exit = False

        # Use Wi-Fi manager's connection check
        if self.wifi_manager.check_wifi_connection():
            self.shared_data.wifi_connected = True
            if self.orchestrator_thread is None or not self.orchestrator_thread.is_alive():
                logger.info("Starting Orchestrator thread...")
                self.orchestrator = Orchestrator()
                self.orchestrator_thread = threading.Thread(target=self.orchestrator.run)
                self.orchestrator_thread.start()
                logger.info("Orchestrator thread started, automatic mode activated.")
            else:
                logger.info("Orchestrator thread is already running.")
        else:
            logger.warning("Cannot start Orchestrator yet: Wi-Fi is not connected. Will auto-start when connected.")

    def stop_orchestrator(self):
        """Stop the orchestrator thread."""
        self.shared_data.manual_mode = True
        logger.info("Stop button pressed. Manual mode activated & Stopping Orchestrator...")
        if self.orchestrator_thread is not None and self.orchestrator_thread.is_alive():
            logger.info("Stopping Orchestrator thread...")
            self.shared_data.orchestrator_should_exit = True
            self.orchestrator_thread.join(timeout=3)
            logger.info("Orchestrator thread stopped.")
            self.shared_data.ragnarorch_status = "IDLE"
            self.shared_data.ragnarstatustext2 = ""
            self.shared_data.manual_mode = True
        else:
            logger.info("Orchestrator thread is not running.")

    def stop(self):
        """Stop Ragnar and cleanup all resources."""
        logger.info("Stopping Ragnar...")

        # Stop PiSugar listener
        if self.pisugar_listener:
            self.pisugar_listener.stop()

        # Stop orchestrator
        self.stop_orchestrator()

        # Stop Wi-Fi manager
        if hasattr(self, 'wifi_manager'):
            self.wifi_manager.stop()
        
        # Set exit flags
        self.shared_data.should_exit = True
        self.shared_data.orchestrator_should_exit = True
        self.shared_data.display_should_exit = True
        self.shared_data.webapp_should_exit = True
        
        logger.info("Ragnar stopped successfully")

    def is_wifi_connected(self):
        """Legacy method - use wifi_manager for new code."""
        if hasattr(self, 'wifi_manager'):
            return self.wifi_manager.check_wifi_connection()
        else:
            # Fallback to original method
            result = subprocess.Popen(['nmcli', '-t', '-f', 'active', 'dev', 'wifi'], stdout=subprocess.PIPE, text=True).communicate()[0]
            return 'yes' in result

    
    @staticmethod
    def start_display():
        """Start the display thread"""
        display = Display(shared_data)
        display_thread = threading.Thread(target=display.run)
        display_thread.start()
        
        # Store display instance in shared_data for access by other modules
        shared_data.display_instance = display
        
        return display_thread

def handle_exit(sig, frame, display_thread, ragnar_thread, web_thread):
    """Handles the termination of the main, display, and web threads."""
    logger.info("Received exit signal, initiating clean shutdown...")

    # Stop Ragnar instance first
    if hasattr(shared_data, 'ragnar_instance') and shared_data.ragnar_instance:
        shared_data.ragnar_instance.stop()

    # Set all exit flags
    shared_data.should_exit = True
    shared_data.orchestrator_should_exit = True
    shared_data.display_should_exit = True
    shared_data.webapp_should_exit = True

    # Encrypt database on shutdown if auth is configured
    try:
        from webapp_modern import auth_mgr
        auth_mgr.shutdown_encrypt()
    except Exception as e:
        logger.error(f"Shutdown encryption failed: {e}")

    # Stop individual threads (fast timeouts - systemd will SIGKILL after 5s anyway)
    handle_exit_display(sig, frame, display_thread, exit_process=False)

    if display_thread and display_thread.is_alive():
        display_thread.join(timeout=1)
    if ragnar_thread and ragnar_thread.is_alive():
        ragnar_thread.join(timeout=1)
    if web_thread and web_thread.is_alive():
        web_thread.join(timeout=1)

    logger.info("Main loop finished. Clean exit.")
    sys.exit(0)



def _atexit_encrypt():
    """Safety net: encrypt DB on process exit if auth is configured."""
    try:
        from webapp_modern import auth_mgr
        auth_mgr.shutdown_encrypt()
    except Exception:
        pass

atexit.register(_atexit_encrypt)

if __name__ == "__main__":
    # Load environment variables from .env file at the very beginning
    load_env()

    logger.info("Starting threads")

    try:
        logger.info("Loading shared data config...")
        shared_data.load_config()

        # Always reset pwnagotchi_mode on Ragnar startup so Ragnar
        # is the canonical mode after every boot / service restart.
        shared_data.config['pwnagotchi_mode'] = 'ragnar'
        shared_data.config['pwnagotchi_last_status'] = 'Ragnar service is running'
        shared_data.save_config()

        # Clean up leftover pwnagotchi state (mon0, services)
        # Run all cleanup commands in parallel to avoid sequential timeouts
        logger.info("Cleaning up leftover pwnagotchi state...")
        cleanup_cmds = [
            (['ip', 'link', 'set', 'mon0', 'down'], 5),
            (['iw', 'mon0', 'del'], 5),
            (['systemctl', 'stop', 'pwnagotchi'], 10),
            (['systemctl', 'stop', 'bettercap'], 10),
            (['systemctl', 'stop', 'ragnar-swap-button'], 5),
        ]
        cleanup_procs = []
        for cmd, _ in cleanup_cmds:
            try:
                cleanup_procs.append(
                    (cmd, subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
                )
            except Exception:
                pass
        # Wait for all with a single combined timeout (10s max instead of 30s sequential)
        for cmd, proc in cleanup_procs:
            try:
                proc.wait(timeout=10)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        # wipe_epd stays as ExecStartPre (separate process) to avoid GPIO conflicts
        # with the Display's EPDHelper instance that shares the same pins.

        # Start the web server first so it becomes available even if the
        # EPD display initialisation is slow (e-paper displays can take
        # 10-30 seconds to initialise, especially larger panels like the 4.26").
        if shared_data.config["websrv"]:
            logger.info("Starting the web server...")
            from webapp_modern import run_server
            web_thread = threading.Thread(target=run_server, daemon=True)
            web_thread.start()
        else:
            web_thread = None

        logger.info("Starting display thread...")
        shared_data.display_should_exit = False  # Initialize display should_exit
        display_thread = Ragnar.start_display()

        logger.info("Starting Ragnar thread...")
        ragnar = Ragnar(shared_data)
        shared_data.ragnar_instance = ragnar  # Assigner l'instance de Ragnar à shared_data

        # Link display instance to ragnar instance
        if hasattr(shared_data, 'display_instance'):
            ragnar.display = shared_data.display_instance

        ragnar_thread = threading.Thread(target=ragnar.run)
        ragnar_thread.start()

        signal.signal(signal.SIGINT, lambda sig, frame: handle_exit(sig, frame, display_thread, ragnar_thread, web_thread))
        signal.signal(signal.SIGTERM, lambda sig, frame: handle_exit(sig, frame, display_thread, ragnar_thread, web_thread))

    except Exception as e:
        logger.error(f"An exception occurred during thread start: {e}")
        if 'display_thread' in locals():
            handle_exit_display(signal.SIGINT, None, display_thread)
        exit(1)
