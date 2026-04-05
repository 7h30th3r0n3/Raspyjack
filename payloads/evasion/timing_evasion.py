#!/usr/bin/env python3
"""
RaspyJack Payload -- Network Timing Randomizer
================================================
Author: 7h30th3r0n3

Configures ``tc`` (traffic control) qdisc on the active network interface
to add random jitter to outgoing packets.  Prevents IDS/IPS from
detecting scan patterns by adding randomised latency.

Presets: Light (1-10ms), Medium (10-50ms), Heavy (50-200ms).

Setup / Prerequisites
---------------------
- Root privileges.
- ``tc`` (iproute2) installed.
- Active network interface.

Controls
--------
  OK          -- Apply / remove timing profile
  UP / DOWN   -- Cycle presets
  KEY1        -- Custom delay (cycle through predefined values)
  KEY3        -- Exit (cleans up qdisc)
"""

import os
import sys
import time
import re
import subprocess
import threading

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
font = scaled_font()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEBOUNCE = 0.22

# Presets: (name, base_delay_ms, jitter_ms)
# netem adds delay +/- jitter with uniform distribution
PRESETS = [
    {"name": "Light",   "delay": 5,   "jitter": 5,   "desc": "1-10ms"},
    {"name": "Medium",  "delay": 30,  "jitter": 20,  "desc": "10-50ms"},
    {"name": "Heavy",   "delay": 125, "jitter": 75,  "desc": "50-200ms"},
]

CUSTOM_DELAYS = [15, 25, 50, 75, 100, 150, 250, 500]

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_state = {
    "preset_idx": 0,
    "custom_idx": 0,
    "active": False,
    "interface": "",
    "status": "Inactive",
    "current_delay": "",
    "current_jitter": "",
}


def _get(key):
    with _lock:
        return _state[key]


def _set(**kw):
    with _lock:
        for k, v in kw.items():
            _state[k] = v


# ---------------------------------------------------------------------------
# Network interface detection
# ---------------------------------------------------------------------------
def _get_active_interface():
    """Return the name of the default-route interface."""
    try:
        out = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in out.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                idx = parts.index("dev")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
    except Exception:
        pass

    # Fallback: look for any non-lo interface that is UP
    try:
        out = subprocess.run(
            ["ip", "link", "show", "up"],
            capture_output=True, text=True, timeout=5,
        )
        for line in out.stdout.splitlines():
            m = re.match(r"\d+:\s+(\S+):", line)
            if m and m.group(1) != "lo":
                return m.group(1)
    except Exception:
        pass
    return "eth0"


# ---------------------------------------------------------------------------
# tc (traffic control) commands
# ---------------------------------------------------------------------------
def _tc_add_netem(iface, delay_ms, jitter_ms):
    """Add netem qdisc with delay and jitter."""
    # Remove existing qdisc first
    _tc_remove(iface)

    cmd = [
        "tc", "qdisc", "add", "dev", iface, "root", "netem",
        "delay", f"{delay_ms}ms", f"{jitter_ms}ms",
        "distribution", "normal",
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def _tc_remove(iface):
    """Remove netem qdisc from interface."""
    try:
        subprocess.run(
            ["tc", "qdisc", "del", "dev", iface, "root"],
            capture_output=True, text=True, timeout=10,
        )
    except Exception:
        pass


def _tc_show(iface):
    """Show current qdisc config."""
    try:
        out = subprocess.run(
            ["tc", "qdisc", "show", "dev", iface],
            capture_output=True, text=True, timeout=5,
        )
        return out.stdout.strip()
    except Exception:
        return ""


def _parse_netem_status(text):
    """Parse tc qdisc show output for delay values."""
    m = re.search(r"delay\s+([\d.]+)(ms|us|s)", text)
    delay = m.group(1) + m.group(2) if m else ""
    m2 = re.search(r"([\d.]+)(ms|us|s)\s", text[text.find("delay"):] if "delay" in text else "")
    return delay


# ---------------------------------------------------------------------------
# Apply / Remove
# ---------------------------------------------------------------------------
def _apply_preset():
    """Apply the selected timing preset."""
    iface = _get("interface")
    if not iface:
        iface = _get_active_interface()
        _set(interface=iface)

    preset = PRESETS[_get("preset_idx")]
    _set(status=f"Applying {preset['name']}...")

    ok = _tc_add_netem(iface, preset["delay"], preset["jitter"])
    if ok:
        _set(active=True, status=f"Active: {preset['name']}",
             current_delay=f"{preset['delay']}ms",
             current_jitter=f"{preset['jitter']}ms")
    else:
        _set(status="Failed to apply")


def _apply_custom():
    """Apply a custom delay value."""
    iface = _get("interface")
    if not iface:
        iface = _get_active_interface()
        _set(interface=iface)

    delay = CUSTOM_DELAYS[_get("custom_idx")]
    jitter = max(1, delay // 3)
    _set(status=f"Custom: {delay}ms...")

    ok = _tc_add_netem(iface, delay, jitter)
    if ok:
        _set(active=True, status=f"Custom: {delay}+/-{jitter}ms",
             current_delay=f"{delay}ms", current_jitter=f"{jitter}ms")
    else:
        _set(status="Failed to apply")


def _remove_evasion():
    """Remove timing evasion."""
    iface = _get("interface")
    if iface:
        _tc_remove(iface)
    _set(active=False, status="Removed",
         current_delay="", current_jitter="")


# ---------------------------------------------------------------------------
# LCD drawing
# ---------------------------------------------------------------------------
def _draw_lcd():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    idx = _get("preset_idx")
    active = _get("active")
    status = _get("status")
    iface = _get("interface") or _get_active_interface()
    cur_delay = _get("current_delay")
    cur_jitter = _get("current_jitter")

    # Header
    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "TIMING EVASION", font=font, fill="#AA00FF")
    d.ellipse((118, 3, 124, 9), fill="#00FF00" if active else "#666")

    y = 16
    d.text((2, y), f"Interface: {iface}", font=font, fill="#AAAAAA")
    y += 14

    # Presets
    for i, preset in enumerate(PRESETS):
        sel = (i == idx)
        prefix = ">" if sel else " "
        fg = "#00FF00" if sel else "#888"
        if active and i == idx:
            fg = "#FFFF00"
        d.text((2, y), f"{prefix}{preset['name']}: {preset['desc']}", font=font, fill=fg)
        y += 12

    y += 4
    # Current state
    if active:
        d.text((2, y), f"Delay: {cur_delay}", font=font, fill="#00CCFF")
        y += 11
        d.text((2, y), f"Jitter: {cur_jitter}", font=font, fill="#00CCFF")
    else:
        d.text((2, y), "No jitter active", font=font, fill="#666")

    # Status
    d.rectangle((0, 106, 127, 115), fill="#0a0a0a")
    d.text((2, 107), status[:21], font=font, fill="#FFCC00")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    action = "REMOVE" if active else "APPLY"
    d.text((2, 117), f"OK:{action} K1:cust K3:x", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    iface = _get_active_interface()
    _set(interface=iface)

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 16), "TIMING EVASION", font=font, fill="#AA00FF")
    d.text((4, 32), "Network jitter", font=font, fill="#888")
    d.text((4, 52), "OK=Apply/Remove", font=font, fill="#666")
    d.text((4, 64), "U/D=Presets K1=Custom", font=font, fill="#666")
    d.text((4, 76), "K3=Exit (cleanup)", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    last_press = 0.0

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if btn == "KEY3":
                break

            elif btn == "OK":
                if _get("active"):
                    _remove_evasion()
                else:
                    _apply_preset()

            elif btn == "UP":
                i = _get("preset_idx")
                _set(preset_idx=(i - 1) % len(PRESETS))

            elif btn == "DOWN":
                i = _get("preset_idx")
                _set(preset_idx=(i + 1) % len(PRESETS))

            elif btn == "KEY1":
                ci = _get("custom_idx")
                _set(custom_idx=(ci + 1) % len(CUSTOM_DELAYS))
                _apply_custom()

            _draw_lcd()
            time.sleep(0.05)

    finally:
        # Always clean up qdisc on exit
        _remove_evasion()
        time.sleep(0.2)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
