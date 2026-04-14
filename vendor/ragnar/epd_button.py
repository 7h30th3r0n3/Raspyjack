# epd_button.py - Hardware button support for 2.7" e-Paper HAT
# GPIO pins: KEY1=5, KEY2=6, KEY3=13, KEY4=19
# Uses gpiozero (same library as the Waveshare EPD driver) to avoid conflicts
#
# KEY1: Swap to Pwnagotchi (with 10s cooldown)
# KEY2: Flip screen upside down (toggle)
# KEY3: Next page - rotate through all pages
# KEY4: Restart Ragnar service

import logging
import threading
import time
import os

logger = logging.getLogger(__name__)

# GPIO pin assignments for 2.7" e-Paper HAT buttons
KEY1_PIN = 5
KEY2_PIN = 6
KEY3_PIN = 13
KEY4_PIN = 19

# Display pages
PAGE_MAIN = 0         # Default Ragnar display
PAGE_NETWORK = 1      # Network scanner stats
PAGE_VULN = 2         # Vulnerability scanner stats
PAGE_DISCOVERED = 3   # Discovered hosts
PAGE_ADVANCED = 4     # Advanced scan results
PAGE_TRAFFIC = 5      # Traffic analysis
PAGE_COUNT = 6        # Total number of pages


class EPDButtonListener:
    """Listens for hardware button presses on the 2.7" e-Paper HAT using gpiozero."""

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.current_page = PAGE_MAIN
        self.flip_screen = False
        self.available = False
        self._buttons = []
        self._swap_cooldown = 0  # timestamp of last swap to prevent double triggers

    def start(self):
        """Start the button listener using gpiozero callbacks."""
        try:
            from gpiozero import Button

            btn1 = Button(KEY1_PIN, pull_up=True, bounce_time=0.3)
            btn2 = Button(KEY2_PIN, pull_up=True, bounce_time=0.3)
            btn3 = Button(KEY3_PIN, pull_up=True, bounce_time=0.3)
            btn4 = Button(KEY4_PIN, pull_up=True, bounce_time=0.3)

            btn1.when_pressed = self._on_key1
            btn2.when_pressed = self._on_key2
            btn3.when_pressed = self._on_key3
            btn4.when_pressed = self._on_key4

            # Keep references so they don't get garbage collected
            self._buttons = [btn1, btn2, btn3, btn4]
            self.available = True
            logger.info(f"EPD button listener started via gpiozero (GPIO {KEY1_PIN},{KEY2_PIN},{KEY3_PIN},{KEY4_PIN})")
        except ImportError:
            logger.info("gpiozero not available - button listener disabled")
        except Exception as e:
            logger.warning(f"Could not start button listener: {e}")

    def stop(self):
        """Stop the button listener and release GPIO."""
        for btn in self._buttons:
            try:
                btn.close()
            except Exception:
                pass
        self._buttons = []

    def _on_key1(self):
        """KEY1: Swap to Pwnagotchi (with 10s cooldown)."""
        now = time.time()
        if now - self._swap_cooldown < 10:
            logger.debug("KEY1 swap ignored - cooldown active")
            return
        self._swap_cooldown = now

        try:
            current_mode = self.shared_data.config.get('pwnagotchi_mode', 'ragnar')
            target = 'pwnagotchi' if current_mode != 'pwnagotchi' else 'ragnar'
            logger.info(f"Button KEY1: swapping to {target}")

            from webapp_modern import _schedule_pwn_mode_switch, _write_pwn_status_file, _update_pwn_config, _emit_pwn_status_update
            _write_pwn_status_file('switching', f'Button-triggered swap to {target}', 'swap', {'target_mode': target})
            _update_pwn_config({'pwnagotchi_mode': target, 'pwnagotchi_last_status': f'Swapping to {target} (KEY1 button)'})
            _emit_pwn_status_update()
            _schedule_pwn_mode_switch(target)
        except Exception as e:
            logger.error(f"KEY1 swap trigger failed: {e}")

    def _on_key2(self):
        """KEY2: Cycle display rotation (0° → 90° → 180° → 270°)."""
        _rotations = [0, 90, 180, 270]
        current = getattr(self.shared_data, 'screen_reversed', 0) or 0
        idx = _rotations.index(current) if current in _rotations else 0
        new_rotation = _rotations[(idx + 1) % len(_rotations)]
        self.shared_data.screen_reversed = new_rotation
        self.shared_data.web_screen_reversed = new_rotation
        logger.info(f"Button KEY2: Display rotation set to {new_rotation}°")

    def _on_key3(self):
        """KEY3: Next page - rotate through all pages."""
        self.current_page = (self.current_page + 1) % PAGE_COUNT
        page_names = ["Main", "Network", "Vuln", "Discovered", "Advanced", "Traffic"]
        name = page_names[self.current_page] if self.current_page < len(page_names) else str(self.current_page)
        logger.info(f"Button KEY3: Next page -> {name} ({self.current_page})")

    def _on_key4(self):
        """KEY4: Restart Ragnar service."""
        logger.info("Button KEY4: Restarting Ragnar service...")
        threading.Thread(target=self._do_restart, daemon=True).start()

    @staticmethod
    def _do_restart():
        """Restart the ragnar service after a short delay."""
        time.sleep(1)
        os.system('systemctl restart ragnar.service')
