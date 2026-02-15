#!/usr/bin/env python3
"""
RaspyJack Flipper Hunter
--------------------------------------------------
Detect nearby BLE devices whose MAC OUI matches Flipper.

Controls:
  KEY1 - Toggle scanning on/off
  KEY2 - Clear seen list
  KEY3 - Exit
"""

import os
import re
import signal
import subprocess
import sys
import time

# Allow imports from RaspyJack root
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

try:
    import RPi.GPIO as GPIO
    import LCD_1in44, LCD_Config
    from PIL import Image, ImageDraw, ImageFont
    LCD_AVAILABLE = True
except Exception:
    LCD_AVAILABLE = False
    GPIO = None

from payloads._input_helper import get_button

FLIPPER_OUI = "80:E1:26"
PINS = {
    "UP": 6,
    "DOWN": 19,
    "LEFT": 5,
    "RIGHT": 26,
    "OK": 13,
    "KEY1": 21,
    "KEY2": 20,
    "KEY3": 16,
}

running = True
scanning = False
scanner_proc = None
seen = set()
last_hit = ""
last_name = ""


def _handle_signal(_signum, _frame):
    global running
    running = False


def _setup_display():
    if not LCD_AVAILABLE:
        return None, None, None
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    width, height = 128, 128
    font = ImageFont.load_default()
    return lcd, (width, height), font


def _draw(lcd, size, font, lines):
    if lcd is None:
        # Console fallback for dev/debug environments.
        print(" | ".join(lines))
        return
    img = Image.new("RGB", size, "black")
    d = ImageDraw.Draw(img)
    y = 4
    for line in lines:
        d.text((4, y), str(line)[:18], font=font, fill="white")
        y += 12
    lcd.LCD_ShowImage(img, 0, 0)


def _run_quiet(cmd):
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
    except Exception:
        pass


def start_scan():
    global scanner_proc, scanning
    if scanning:
        return
    # Bring adapter up if available.
    _run_quiet(["hciconfig", "hci0", "up"])
    try:
        scanner_proc = subprocess.Popen(
            ["bluetoothctl"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if scanner_proc.stdin:
            scanner_proc.stdin.write("scan on\n")
            scanner_proc.stdin.flush()
        scanning = True
    except Exception:
        scanner_proc = None
        scanning = False


def stop_scan():
    global scanner_proc, scanning
    if scanner_proc:
        try:
            if scanner_proc.stdin:
                scanner_proc.stdin.write("scan off\n")
                scanner_proc.stdin.flush()
        except Exception:
            pass
        try:
            scanner_proc.terminate()
            scanner_proc.wait(timeout=2)
        except Exception:
            try:
                scanner_proc.kill()
            except Exception:
                pass
    scanner_proc = None
    scanning = False


def read_devices():
    try:
        proc = subprocess.run(
            ["bluetoothctl", "devices"],
            capture_output=True,
            text=True,
            timeout=4,
        )
        return proc.stdout or ""
    except Exception:
        return ""


def parse_flippers(devices_output):
    matches = []
    for line in devices_output.splitlines():
        # Expected line: "Device AA:BB:CC:DD:EE:FF Name..."
        m = re.match(r"^Device\s+([0-9A-Fa-f:]{17})\s*(.*)$", line.strip())
        if not m:
            continue
        mac = m.group(1).upper()
        name = m.group(2).strip() or "Unknown"
        if mac.startswith(FLIPPER_OUI):
            matches.append((mac, name))
    return matches


def main():
    global running, last_hit, last_name

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    if GPIO is not None:
        GPIO.setmode(GPIO.BCM)
        for pin in PINS.values():
            GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd, size, font = _setup_display()
    _draw(lcd, size, font, ["FLIPPER HUNTER", "KEY1 scan on/off", "KEY3 exit"])
    time.sleep(1.0)

    start_scan()

    while running:
        btn = get_button(PINS, GPIO) if GPIO is not None else None
        if btn == "KEY3":
            running = False
            break
        if btn == "KEY1":
            if scanning:
                stop_scan()
            else:
                start_scan()
            time.sleep(0.2)
        elif btn == "KEY2":
            seen.clear()
            last_hit = ""
            last_name = ""
            time.sleep(0.2)

        found_now = 0
        if scanning:
            for mac, name in parse_flippers(read_devices()):
                if mac not in seen:
                    seen.add(mac)
                    last_hit = mac
                    last_name = name
                    found_now += 1

        state = "SCANNING" if scanning else "PAUSED"
        lines = [
            "FLIPPER HUNTER",
            f"{state}",
            f"Seen: {len(seen)}",
            f"New: {found_now}",
            (last_hit[-8:] if last_hit else "No hit yet"),
            (last_name[:18] if last_name else ""),
        ]
        _draw(lcd, size, font, lines)
        time.sleep(0.35)

    stop_scan()
    if lcd is not None:
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
    if GPIO is not None:
        try:
            GPIO.cleanup()
        except Exception:
            pass


if __name__ == "__main__":
    main()

