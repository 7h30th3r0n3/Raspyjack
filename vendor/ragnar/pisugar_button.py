# pisugar_button.py
"""
PiSugar 3 button listener for Ragnar.

Monitors the PiSugar button and triggers mode swaps between Ragnar and Pwnagotchi:
  - Double tap:  Switch to Pwnagotchi (from Ragnar) or switch to Ragnar (from Pwnagotchi)
  - Long press:  Same as double tap (alternative trigger for reliability)
  - Single tap:  Toggle Ragnar manual mode on/off

Requires pisugar-server running and the `pisugar` Python package.
Connection is via TCP to localhost (default pisugar-server setup).
"""

import os
import threading
import logging
import time
import math

try:
    from logger import Logger
    logger = Logger(name="pisugar_button.py", level=logging.DEBUG)
except Exception:
    import logging as _logging
    logger = _logging.getLogger("pisugar_button")


class PiSugarButtonListener:
    """Listens to PiSugar 3 button events and triggers Ragnar/Pwnagotchi swap."""

    MOCK_ENV = 'PISUGAR_MOCK'  # Set to "1" to simulate a PiSugar for UI testing

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self._thread = None
        self._stop_event = threading.Event()
        self._server = None
        self._swap_cooldown = 0  # Timestamp of last swap to prevent double triggers
        self.available = False
        self._mock = os.environ.get(self.MOCK_ENV, '') == '1'

    def start(self):
        """Start the button listener in a background thread."""
        if self._mock:
            self.available = True
            self._mock_start = time.time()
            logger.info("PiSugar MOCK mode active (set PISUGAR_MOCK=1)")
            return
        self._thread = threading.Thread(target=self._run, name="pisugar-button", daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the listener."""
        self._stop_event.set()

    def _run(self):
        """Main loop: connect to pisugar-server and register button handlers."""
        try:
            from pisugar import connect_tcp, PiSugarServer
        except ImportError:
            logger.info("pisugar package not installed - button listener disabled")
            return

        # Retry connection with backoff (pisugar-server may start after Ragnar)
        for attempt in range(5):
            if self._stop_event.is_set():
                return
            try:
                conn, event_conn = connect_tcp('127.0.0.1')
                self._server = PiSugarServer(conn, event_conn)
                model = self._server.get_model()
                logger.info(f"PiSugar connected: {model}")
                self.available = True
                break
            except Exception as e:
                wait = 5 * (attempt + 1)
                logger.debug(f"PiSugar not available (attempt {attempt + 1}/5): {e}. Retry in {wait}s")
                self._stop_event.wait(wait)
        else:
            logger.info("PiSugar not detected after 5 attempts - button listener disabled")
            return

        # Register button event handlers
        try:
            self._server.register_single_tap_handler(self._on_single_tap)
            self._server.register_double_tap_handler(self._on_double_tap)
            self._server.register_long_tap_handler(self._on_long_tap)
            logger.info("PiSugar button handlers registered (single=manual_mode, double/long=swap)")
        except Exception as e:
            logger.error(f"Failed to register PiSugar button handlers: {e}")
            return

        # Keep thread alive to receive events (pisugar library uses the event connection)
        while not self._stop_event.is_set():
            self._stop_event.wait(1)

    def _on_single_tap(self):
        """Single tap: toggle Ragnar manual mode."""
        try:
            current = self.shared_data.config.get('manual_mode', False)
            new_mode = not current
            self.shared_data.config['manual_mode'] = new_mode

            ragnar = getattr(self.shared_data, 'ragnar_instance', None)
            if ragnar:
                if new_mode:
                    ragnar.stop_orchestrator()
                    logger.info("PiSugar tap: manual mode ON (orchestrator stopped)")
                else:
                    ragnar.start_orchestrator()
                    logger.info("PiSugar tap: manual mode OFF (orchestrator started)")
        except Exception as e:
            logger.error(f"PiSugar single tap handler error: {e}")

    def _on_double_tap(self):
        """Double tap: swap between Ragnar and Pwnagotchi."""
        self._trigger_swap()

    def _on_long_tap(self):
        """Long press: swap between Ragnar and Pwnagotchi (alternative trigger)."""
        self._trigger_swap()

    def _trigger_swap(self):
        """Trigger a mode swap with cooldown to prevent double triggers."""
        now = time.time()
        if now - self._swap_cooldown < 10:
            logger.debug("PiSugar swap ignored - cooldown active")
            return
        self._swap_cooldown = now

        try:
            # Determine current mode and swap to the other
            current_mode = self.shared_data.config.get('pwnagotchi_mode', 'ragnar')
            target = 'pwnagotchi' if current_mode != 'pwnagotchi' else 'ragnar'

            logger.info(f"PiSugar button: swapping to {target}")

            # Import the swap function from webapp_modern
            from webapp_modern import _schedule_pwn_mode_switch, _write_pwn_status_file, _update_pwn_config, _emit_pwn_status_update
            _write_pwn_status_file('switching', f'Button-triggered swap to {target}', 'swap', {'target_mode': target})
            _update_pwn_config({'pwnagotchi_mode': target, 'pwnagotchi_last_status': f'Swapping to {target} (button)'})
            _emit_pwn_status_update()
            _schedule_pwn_mode_switch(target)

        except Exception as e:
            logger.error(f"PiSugar swap trigger failed: {e}")

    # ── Mock helpers (sinusoidal cycle: drains then charges over ~2 min) ──

    def _mock_level(self):
        """Simulate battery level oscillating between 15% and 95%."""
        elapsed = time.time() - self._mock_start
        return 55 + 40 * math.sin(elapsed * math.pi / 60)  # ~2 min full cycle

    def _mock_charging(self):
        """Charging when the simulated level is rising."""
        elapsed = time.time() - self._mock_start
        return math.cos(elapsed * math.pi / 60) < 0  # rising half of sine

    # ── Public getters (real or mock) ──────────────────────────────────

    def get_battery_level(self):
        """Get battery percentage (for display/status use)."""
        if self._mock:
            return self._mock_level()
        if not self._server:
            return None
        try:
            return self._server.get_battery_level()
        except Exception:
            return None

    def is_charging(self):
        """Check if battery is charging (uses power_plugged with fallback to charging flag)."""
        if self._mock:
            return self._mock_charging()
        if not self._server:
            return None
        try:
            return self._server.get_battery_power_plugged()
        except Exception:
            pass
        try:
            return self._server.get_battery_charging()
        except Exception:
            return None

    def get_battery_voltage(self):
        """Get battery voltage in volts."""
        if self._mock:
            return 3.7 + (self._mock_level() - 50) * 0.012  # ~3.1V–4.3V range
        if not self._server:
            return None
        try:
            return self._server.get_battery_voltage()
        except Exception:
            return None

    def get_model(self):
        """Get PiSugar model name."""
        if self._mock:
            return 'PiSugar 3 (Mock)'
        if not self._server:
            return None
        try:
            return self._server.get_model()
        except Exception:
            return None
