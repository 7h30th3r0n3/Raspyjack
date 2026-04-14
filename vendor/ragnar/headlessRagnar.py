#!/usr/bin/env python3
"""
Ragnar main entrypoint (Hackberry / no-EPD version)
This version removes all e-paper / Display dependencies so Ragnar can run
cleanly on any Linux box (Pi, Hackberry, etc.) with just the web UI.

hbp0_ragnar by DezusAZ  (DZ_AZ)
"""

import os
import signal
import threading
import time
import sys
import subprocess
import logging

from init_shared import shared_data
from comment import Commentaireia
from webapp_modern import run_server
from orchestrator import Orchestrator
from logger import Logger
from wifi_manager import WiFiManager
from env_manager import load_env

_log_level = logging.DEBUG if os.environ.get("RAGNAR_DEBUG") else logging.INFO
logger = Logger(name="hbp0.py", level=_log_level)


class Ragnar:
    """Main class for Ragnar. Manages the primary operations of the application."""

    def __init__(self, shared_data_obj):
        self.shared_data = shared_data_obj
        self.commentaire_ia = Commentaireia()
        self.orchestrator_thread = None
        self.orchestrator = None
        self.wifi_manager = WiFiManager(self.shared_data)

        # Expose this instance to other modules
        self.shared_data.ragnar_instance = self
        self.shared_data.headless_mode = True

    # ---------------------------------------------------------------------
    # Main loop
    # ---------------------------------------------------------------------
    def run(self):
        """Main loop for Ragnar. Starts Wi-Fi manager and orchestrator as needed."""
        logger.info("=" * 70)
        logger.info("RAGNAR MAIN THREAD STARTING (no EPD display)")
        logger.info("=" * 70)

        # Initialize Wi-Fi management system
        logger.info("Starting Wi-Fi management system...")
        self.wifi_manager.start()
        logger.info("Wi-Fi management system started")

        # Main loop to keep Ragnar running
        logger.info("Entering main Ragnar loop...")
        loop_count = 0
        while not self.shared_data.should_exit:
            loop_count += 1
            if loop_count % 6 == 1:  # roughly every 60 seconds if sleep(10)
                logger.info(
                    f"Ragnar main loop iteration {loop_count}, "
                    f"manual_mode={self.shared_data.manual_mode}"
                )

            if not self.shared_data.manual_mode:
                self.check_and_start_orchestrator()

            time.sleep(10)

        logger.info("Ragnar main loop exited")

    # ---------------------------------------------------------------------
    # Orchestrator control
    # ---------------------------------------------------------------------
    def check_and_start_orchestrator(self):
        """Check connectivity and start the orchestrator if connected."""
        network_connected = self.wifi_manager.check_network_connectivity()
        connection_type = getattr(self.wifi_manager, "last_connection_type", None)
        logger.debug(f"Network connection check: {network_connected} (type={connection_type})")

        self.shared_data.network_connected = network_connected
        self.shared_data.wifi_connected = connection_type == "wifi"
        self.shared_data.lan_connected = connection_type == "ethernet"

        if network_connected:
            if self.orchestrator_thread is None or not self.orchestrator_thread.is_alive():
                logger.info("Connectivity detected - attempting to start Orchestrator...")
                self.start_orchestrator()
        else:
            if not self.wifi_manager.startup_complete:
                logger.info("Waiting for Wi-Fi management system to complete startup...")
            else:
                logger.debug("Waiting for connection to start Orchestrator...")

    def start_orchestrator(self):
        """Start the orchestrator thread."""
        # Always clear manual mode so the main loop will auto-start
        # the orchestrator when connectivity becomes available
        self.shared_data.manual_mode = False
        self.shared_data.orchestrator_should_exit = False

        if self.wifi_manager.check_network_connectivity():
            connection_type = getattr(self.wifi_manager, "last_connection_type", None)
            self.shared_data.network_connected = True
            self.shared_data.wifi_connected = connection_type == "wifi"
            self.shared_data.lan_connected = connection_type == "ethernet"
            if self.orchestrator_thread is None or not self.orchestrator_thread.is_alive():
                logger.info("Starting Orchestrator thread...")
                self.orchestrator = Orchestrator()
                self.orchestrator_thread = threading.Thread(
                    target=self.orchestrator.run, name="RagnarOrchestrator"
                )
                self.orchestrator_thread.start()
                logger.info("Orchestrator thread started, automatic mode activated.")
            else:
                logger.info("Orchestrator thread is already running.")
        else:
            logger.warning("Cannot start Orchestrator yet: no network. Will auto-start when connected.")

    def stop_orchestrator(self):
        """Stop the orchestrator thread."""
        self.shared_data.manual_mode = True
        logger.info("Stopping Orchestrator and switching to manual mode...")
        if self.orchestrator_thread is not None and self.orchestrator_thread.is_alive():
            logger.info("Stopping Orchestrator thread...")
            self.shared_data.orchestrator_should_exit = True
            self.orchestrator_thread.join(timeout=10)
            logger.info("Orchestrator thread stopped.")
            self.shared_data.ragnarorch_status = "IDLE"
            self.shared_data.ragnarstatustext2 = ""
            self.shared_data.manual_mode = True
        else:
            logger.info("Orchestrator thread is not running.")

    # ---------------------------------------------------------------------
    # Shutdown / helpers
    # ---------------------------------------------------------------------
    def stop(self):
        """Stop Ragnar and cleanup all resources."""
        logger.info("Stopping Ragnar...")

        # Stop orchestrator
        self.stop_orchestrator()

        # Stop Wi-Fi manager
        if hasattr(self, "wifi_manager"):
            try:
                self.wifi_manager.stop()
            except Exception as e:
                logger.error(f"Error stopping WiFiManager: {e}")

        # Set exit flags
        self.shared_data.should_exit = True
        self.shared_data.orchestrator_should_exit = True
        # No display thread in this version, but keep the flag consistent
        self.shared_data.display_should_exit = True
        self.shared_data.webapp_should_exit = True

        logger.info("Ragnar stopped successfully")

    def is_wifi_connected(self):
        """Legacy method - prefer wifi_manager for new code."""
        if hasattr(self, "wifi_manager"):
            return self.wifi_manager.check_wifi_connection()
        # Fallback to nmcli (wired/wifi)
        try:
            result = subprocess.Popen(
                ["nmcli", "-t", "-f", "STATE", "g"],
                stdout=subprocess.PIPE,
                text=True,
            ).communicate()[0]
            return "connected" in result
        except Exception:
            return False


# -------------------------------------------------------------------------
# Signal handling / entrypoint
# -------------------------------------------------------------------------
def handle_exit(sig, frame, ragnar_thread, web_thread):
    """Handles clean shutdown of Ragnar and the web server."""
    logger.info("Received exit signal, initiating clean shutdown...")

    # Stop Ragnar instance first
    if hasattr(shared_data, "ragnar_instance") and shared_data.ragnar_instance:
        try:
            shared_data.ragnar_instance.stop()
        except Exception as e:
            logger.error(f"Error while stopping Ragnar instance: {e}")

    # Set global flags
    shared_data.should_exit = True
    shared_data.orchestrator_should_exit = True
    shared_data.display_should_exit = True
    shared_data.webapp_should_exit = True

    # Join threads
    if ragnar_thread and ragnar_thread.is_alive():
        logger.info("Waiting for Ragnar thread to stop...")
        ragnar_thread.join(timeout=10)

    if web_thread and web_thread.is_alive():
        logger.info("Waiting for web server thread to stop...")
        # We don't have a direct stop hook; letting it die with process exit
        web_thread.join(timeout=5)

    logger.info("Main loop finished. Clean exit.")
    sys.exit(0)


if __name__ == "__main__":
    # Load environment variables from .env file at the very beginning
    load_env()

    logger.info("Starting Ragnar (no EPD display version)")

    try:
        logger.info("Loading shared data config...")
        shared_data.load_config()

        # Always reset pwnagotchi_mode on Ragnar startup so Ragnar
        # is the canonical mode after every boot / service restart.
        shared_data.config['pwnagotchi_mode'] = 'ragnar'
        shared_data.config['pwnagotchi_last_status'] = 'Ragnar service is running'
        shared_data.save_config()

        # Stop the swap-button listener if it was left running
        subprocess.Popen(
            ['systemctl', 'stop', 'ragnar-swap-button'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        # Start Ragnar core logic
        logger.info("Starting Ragnar thread...")
        ragnar = Ragnar(shared_data)
        shared_data.ragnar_instance = ragnar

        ragnar_thread = threading.Thread(
            target=ragnar.run, name="RagnarMain", daemon=True
        )
        ragnar_thread.start()

        # Start web server if enabled
        if shared_data.config.get("websrv", True):
            logger.info("Starting the web server...")
            web_thread = threading.Thread(
                target=run_server, name="RagnarWeb", daemon=True
            )
            web_thread.start()
        else:
            web_thread = None
            logger.info("Web server disabled in configuration.")

        # Setup signal handlers for clean exit
        signal.signal(
            signal.SIGINT,
            lambda sig, frame: handle_exit(sig, frame, ragnar_thread, web_thread),
        )
        signal.signal(
            signal.SIGTERM,
            lambda sig, frame: handle_exit(sig, frame, ragnar_thread, web_thread),
        )

        # Keep main thread alive while background threads do the work
        while True:
            time.sleep(1)

    except Exception as e:
        logger.error(f"An exception occurred during startup: {e}")
        # Best-effort stop
        if "ragnar" in locals():
            try:
                ragnar.stop()
            except Exception:
                pass
        sys.exit(1)