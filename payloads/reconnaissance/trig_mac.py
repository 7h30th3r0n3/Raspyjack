#!/usr/bin/env python3
"""
RaspyJack Payload -- MAC Address Trigger
==========================================
Author: 7h30th3r0n3

Continuously monitors the local network for a specific MAC address.
Uses `ip neigh show` and optionally `arp-scan -l` to detect when the
target device appears.  Flashes the screen and logs every detection
with timestamp and IP address.

Controls:
  UP / DOWN  -- Navigate character picker (MAC input)
  LEFT       -- Delete last character
  RIGHT      -- Add character
  OK         -- Confirm MAC input
  KEY1       -- Start / stop monitoring
  KEY2       -- Change target MAC (return to input)
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/MACTrigger/detections.log
"""

import os
import sys
import time
import signal
import subprocess
import threading
import re
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROW_H = 12
DEBOUNCE = 0.18
LOOT_DIR = "/root/Raspyjack/loot/MACTrigger"
LOG_FILE = os.path.join(LOOT_DIR, "detections.log")
SCAN_INTERVAL = 3.0

MAC_CHARSET = list("0123456789ABCDEFabcdef:")

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
monitoring = False
target_mac = ""
last_seen_time = ""
last_seen_ip = ""
detection_count = 0
status_msg = "Enter target MAC"
flash_until = 0.0


def _cleanup(*_args):
    global _running, monitoring
    _running = False
    monitoring = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# MAC validation
# ---------------------------------------------------------------------------

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def _validate_mac(mac_str):
    """Return True if mac_str looks like AA:BB:CC:DD:EE:FF."""
    return bool(MAC_RE.match(mac_str))


# ---------------------------------------------------------------------------
# Network scanning
# ---------------------------------------------------------------------------

def _scan_ip_neigh():
    """Parse `ip neigh show` and return {mac_upper: ip} mapping."""
    found = {}
    try:
        result = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            # Format: IP dev IFACE lladdr MAC state
            if "lladdr" in parts:
                idx = parts.index("lladdr")
                if idx + 1 < len(parts) and len(parts) >= 1:
                    mac = parts[idx + 1].upper()
                    ip_addr = parts[0]
                    found[mac] = ip_addr
    except Exception:
        pass
    return found


def _scan_arp_scan():
    """Run `arp-scan -l` and return {mac_upper: ip} mapping."""
    found = {}
    try:
        result = subprocess.run(
            ["sudo", "arp-scan", "-l"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                match = re.match(
                    r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})",
                    line.strip(),
                )
                if match:
                    found[match.group(2).upper()] = match.group(1)
    except (FileNotFoundError, Exception):
        pass
    return found


def _log_detection(mac, ip_addr, timestamp):
    """Append a detection entry to the log file."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    entry = f"[{timestamp}] MAC={mac} IP={ip_addr}\n"
    with open(LOG_FILE, "a") as fh:
        fh.write(entry)


# ---------------------------------------------------------------------------
# Monitor thread
# ---------------------------------------------------------------------------

def _monitor_thread():
    """Continuously scan for the target MAC address."""
    global monitoring, detection_count, last_seen_time
    global last_seen_ip, status_msg, flash_until

    with lock:
        target = target_mac.upper()

    while _running and monitoring:
        with lock:
            msg_prefix = "Watching"

        # Try ip neigh first
        neighbours = _scan_ip_neigh()
        detected_ip = neighbours.get(target)

        # If not found, try arp-scan
        if detected_ip is None:
            arp_results = _scan_arp_scan()
            detected_ip = arp_results.get(target)

        if detected_ip is not None:
            now_str = datetime.now().strftime("%H:%M:%S")
            _log_detection(target, detected_ip, now_str)
            with lock:
                detection_count += 1
                last_seen_time = now_str
                last_seen_ip = detected_ip
                status_msg = f"DETECTED! IP:{detected_ip}"
                flash_until = time.time() + 2.0
        else:
            with lock:
                status_msg = f"{msg_prefix} {target[-8:]}"

        # Wait before next scan
        wait_end = time.time() + SCAN_INTERVAL
        while _running and monitoring and time.time() < wait_end:
            time.sleep(0.2)

    with lock:
        if not monitoring:
            status_msg = "Stopped"


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(d, font_obj, title):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title[:22], font=font_obj, fill="#FF6600")


def _draw_footer(d, font_obj, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:26], font=font_obj, fill="#888")


def _draw_input_screen(lcd, font_obj, mac_chars, char_idx):
    """Draw the MAC address character picker."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, font_obj, "MAC TRIGGER")

    mac_str = "".join(mac_chars)
    d.text((2, 18), "Target MAC:", font=font_obj, fill="#888")
    d.text((2, 30), mac_str[-17:] if mac_str else "_", font=font_obj, fill="#00FF00")

    # Format hint
    d.text((2, 44), "AA:BB:CC:DD:EE:FF", font=font_obj, fill="#555")

    # Character selector
    current_char = MAC_CHARSET[char_idx]
    prev_char = MAC_CHARSET[(char_idx - 1) % len(MAC_CHARSET)]
    next_char = MAC_CHARSET[(char_idx + 1) % len(MAC_CHARSET)]

    d.text((2, 60), f"  UP: {prev_char}", font=font_obj, fill="#555")
    d.text((2, 72), f"  >> {current_char} <<", font=font_obj, fill="#FFAA00")
    d.text((2, 84), f"  DN: {next_char}", font=font_obj, fill="#555")

    d.text((2, 100), "RIGHT:Add LEFT:Del", font=font_obj, fill="#666")
    _draw_footer(d, font_obj, "OK:Confirm K3:Exit")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_monitor_screen(lcd, font_obj):
    """Draw the monitoring status screen."""
    with lock:
        msg = status_msg
        target = target_mac
        count = detection_count
        seen_time = last_seen_time
        seen_ip = last_seen_ip
        is_monitoring = monitoring
        is_flash = time.time() < flash_until

    bg_color = "#330000" if is_flash else "black"
    img = Image.new("RGB", (WIDTH, HEIGHT), bg_color)
    d = ScaledDraw(img)

    # Header with status indicator
    d.rectangle((0, 0, 127, 13), fill="#220000" if is_flash else "#111")
    d.text((2, 1), "MAC TRIGGER", font=font_obj, fill="#FF6600")
    indicator_color = "#00FF00" if is_monitoring else "#FF0000"
    d.ellipse((118, 3, 122, 7), fill=indicator_color)

    # Status
    state_label = "MONITORING" if is_monitoring else "STOPPED"
    state_color = "#00FF00" if is_monitoring else "#FF4444"
    d.text((2, 18), state_label, font=font_obj, fill=state_color)

    # Target MAC
    d.text((2, 32), "Target:", font=font_obj, fill="#888")
    d.text((2, 44), target[-17:], font=font_obj, fill="#FFAA00")

    # Detection info
    d.text((2, 60), f"Detections: {count}", font=font_obj, fill="#CCCCCC")

    if seen_time:
        d.text((2, 74), f"Last: {seen_time}", font=font_obj, fill="#00FF88")
        d.text((2, 86), f"IP:   {seen_ip}", font=font_obj, fill="#00FF88")
    else:
        d.text((2, 74), "Waiting...", font=font_obj, fill="#666")

    # Status message
    d.text((2, 100), msg[:24], font=font_obj, fill="#AAAAAA")

    _draw_footer(d, font_obj, "K1:Start/Stop K2:NewMAC")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, monitoring, target_mac, status_msg
    global detection_count, last_seen_time, last_seen_ip

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font_obj = scaled_font()

    mac_chars = []
    char_idx = 0
    mode = "input"  # "input" or "monitor"

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            if mode == "input":
                if btn == "UP":
                    char_idx = (char_idx - 1) % len(MAC_CHARSET)
                    time.sleep(DEBOUNCE)
                elif btn == "DOWN":
                    char_idx = (char_idx + 1) % len(MAC_CHARSET)
                    time.sleep(DEBOUNCE)
                elif btn == "RIGHT":
                    if len(mac_chars) < 17:
                        mac_chars = list(mac_chars) + [MAC_CHARSET[char_idx]]
                    time.sleep(DEBOUNCE)
                elif btn == "LEFT":
                    if mac_chars:
                        mac_chars = list(mac_chars[:-1])
                    time.sleep(DEBOUNCE)
                elif btn == "OK":
                    candidate = "".join(mac_chars).strip()
                    if _validate_mac(candidate):
                        with lock:
                            target_mac = candidate.upper()
                            detection_count = 0
                            last_seen_time = ""
                            last_seen_ip = ""
                            status_msg = "Ready - K1 to start"
                        mode = "monitor"
                        time.sleep(0.3)
                    else:
                        with lock:
                            status_msg = "Invalid MAC format"
                        time.sleep(0.3)

                _draw_input_screen(lcd, font_obj, mac_chars, char_idx)

            elif mode == "monitor":
                if btn == "KEY1":
                    with lock:
                        if monitoring:
                            monitoring = False
                            status_msg = "Stopping..."
                        else:
                            monitoring = True
                            status_msg = "Starting..."
                            threading.Thread(
                                target=_monitor_thread,
                                daemon=True,
                            ).start()
                    time.sleep(0.3)

                elif btn == "KEY2":
                    with lock:
                        monitoring = False
                        status_msg = "Enter target MAC"
                    mode = "input"
                    mac_chars = []
                    char_idx = 0
                    time.sleep(0.3)

                _draw_monitor_screen(lcd, font_obj)

            time.sleep(0.05)

    finally:
        _running = False
        monitoring = False
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
