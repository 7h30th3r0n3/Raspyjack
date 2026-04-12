#!/usr/bin/env python3
"""
Pwnagotchi-side button listener for swapping back to Ragnar.

This script runs alongside Pwnagotchi (started by ragnar-swap-button.service).
It listens on TWO input sources:
  1. PiSugar button (double-tap or long-press) — if pisugar-server is available
  2. 2.7" EPD HAT KEY1 (GPIO 5) — if gpiozero is available

Either trigger stops Pwnagotchi/bettercap and starts Ragnar using systemd-run
so the command survives pwnagotchi's cgroup teardown.

Installed to /usr/local/bin/ragnar-swap-button by the pwnagotchi installer.
Managed by ragnar-swap-button.service.
"""

import subprocess
import time
import sys
import logging

logging.basicConfig(level=logging.INFO, format='[ragnar-swap] %(message)s')
log = logging.getLogger()

COOLDOWN = 10  # seconds between swap attempts
KEY1_PIN = 5   # GPIO pin for 2.7" EPD HAT KEY1

last_swap = 0


def swap_to_ragnar():
    """Stop Pwnagotchi/bettercap and start Ragnar via systemd-run.

    systemd-run creates a transient cgroup so the stop/start sequence
    survives even if this process gets killed alongside pwnagotchi.
    """
    global last_swap
    now = time.time()
    if now - last_swap < COOLDOWN:
        log.debug("Swap ignored - cooldown active")
        return
    last_swap = now

    log.info("Button triggered: swapping to Ragnar...")
    try:
        subprocess.Popen(
            ['systemd-run', '--no-block', '--collect',
             '--unit=pwnagotchi-to-ragnar-swap',
             'bash', '-c',
             'sleep 1 && systemctl stop pwnagotchi.service'
             ' && systemctl stop bettercap.service'
             ' && systemctl stop ragnar-swap-button.service'
             ' && sleep 2'
             ' && systemctl start ragnar.service'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        log.info("Scheduled systemd-run swap: stop pwnagotchi -> start ragnar")
    except Exception as e:
        log.error(f"Swap failed: {e}")


def start_gpio_listener():
    """Start listening on GPIO KEY1 (pin 5) for 2.7 inch EPD HAT button."""
    try:
        from gpiozero import Button
    except ImportError:
        log.info("gpiozero not available - GPIO button listener disabled")
        return False

    try:
        btn = Button(KEY1_PIN, pull_up=True, bounce_time=0.3)
        btn.when_pressed = lambda: swap_to_ragnar()
        # prevent garbage collection
        start_gpio_listener._btn = btn
        log.info(f"GPIO KEY1 (pin {KEY1_PIN}) listener started")
        return True
    except Exception as e:
        log.warning(f"Could not start GPIO listener on pin {KEY1_PIN}: {e}")
        return False


def start_pisugar_listener():
    """Start listening on PiSugar button (double-tap / long-press)."""
    try:
        from pisugar import connect_tcp, PiSugarServer
    except ImportError:
        log.info("pisugar package not available - PiSugar button listener disabled")
        return False

    server = None
    for attempt in range(5):
        try:
            conn, event_conn = connect_tcp('127.0.0.1')
            server = PiSugarServer(conn, event_conn)
            model = server.get_model()
            log.info(f"PiSugar connected: {model}")
            break
        except Exception as e:
            log.info(f"PiSugar not ready (attempt {attempt + 1}/5): {e}")
            time.sleep(5)

    if not server:
        log.info("PiSugar not detected after 5 attempts - PiSugar listener disabled")
        return False

    server.register_double_tap_handler(swap_to_ragnar)
    server.register_long_tap_handler(swap_to_ragnar)
    log.info("PiSugar button handlers registered (double tap / long press = swap)")
    return True


def main():
    gpio_ok = start_gpio_listener()
    pisugar_ok = start_pisugar_listener()

    if not gpio_ok and not pisugar_ok:
        log.error("No input sources available (neither GPIO nor PiSugar). Exiting.")
        sys.exit(1)

    sources = []
    if gpio_ok:
        sources.append("GPIO KEY1")
    if pisugar_ok:
        sources.append("PiSugar button")
    log.info(f"Listening for swap triggers: {', '.join(sources)}")

    # Keep alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Stopped.")


if __name__ == '__main__':
    main()
