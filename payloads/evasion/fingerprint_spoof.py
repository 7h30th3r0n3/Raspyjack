#!/usr/bin/env python3
"""
RaspyJack Payload -- TCP/IP Fingerprint Spoofer
=================================================
Author: 7h30th3r0n3

Spoof the TCP/IP stack fingerprint via sysctl to impersonate different
operating systems.  Changes: net.ipv4.ip_default_ttl, TCP window size,
and DF bit behaviour.

Presets: Linux, Windows 10, macOS, Cisco IOS, Printer.

Setup / Prerequisites
---------------------
- Root privileges (for sysctl writes).
- Linux kernel with sysctl support.

Controls
--------
  OK          -- Apply selected profile
  UP / DOWN   -- Cycle through profiles
  KEY1        -- Show current system values
  KEY2        -- Restore defaults
  KEY3        -- Exit
"""

import os
import sys
import time
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

# Profile definitions: (name, ttl, tcp_window, df_bit_pmtu)
# df_bit_pmtu: "want" = set DF (pmtu discovery on), "dont" = clear DF
PROFILES = [
    {
        "name": "Linux",
        "ttl": 64,
        "tcp_rmem": "4096 87380 6291456",
        "tcp_wmem": "4096 16384 4194304",
        "ip_no_pmtu_disc": 0,      # DF bit ON
        "tcp_sack": 1,
        "tcp_timestamps": 1,
        "tcp_window_scaling": 1,
    },
    {
        "name": "Windows 10",
        "ttl": 128,
        "tcp_rmem": "4096 65535 65535",
        "tcp_wmem": "4096 65535 65535",
        "ip_no_pmtu_disc": 1,      # DF bit OFF
        "tcp_sack": 1,
        "tcp_timestamps": 0,
        "tcp_window_scaling": 1,
    },
    {
        "name": "macOS",
        "ttl": 64,
        "tcp_rmem": "4096 131072 6291456",
        "tcp_wmem": "4096 16384 4194304",
        "ip_no_pmtu_disc": 0,
        "tcp_sack": 1,
        "tcp_timestamps": 1,
        "tcp_window_scaling": 1,
    },
    {
        "name": "Cisco IOS",
        "ttl": 255,
        "tcp_rmem": "4096 4128 4128",
        "tcp_wmem": "4096 4128 4128",
        "ip_no_pmtu_disc": 1,
        "tcp_sack": 0,
        "tcp_timestamps": 0,
        "tcp_window_scaling": 0,
    },
    {
        "name": "Printer",
        "ttl": 64,
        "tcp_rmem": "4096 2048 2048",
        "tcp_wmem": "4096 2048 2048",
        "ip_no_pmtu_disc": 1,
        "tcp_sack": 0,
        "tcp_timestamps": 0,
        "tcp_window_scaling": 0,
    },
]

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_state = {
    "profile_idx": 0,
    "status": "Select profile",
    "active_profile": "",
    "original_values": {},
    "current_values": {},
}


def _get(key):
    with _lock:
        val = _state[key]
        if isinstance(val, dict):
            return dict(val)
        return val


def _set(**kw):
    with _lock:
        for k, v in kw.items():
            _state[k] = v


# ---------------------------------------------------------------------------
# Sysctl helpers
# ---------------------------------------------------------------------------
def _sysctl_read(key):
    """Read a sysctl value."""
    try:
        out = subprocess.run(
            ["sysctl", "-n", key],
            capture_output=True, text=True, timeout=5,
        )
        return out.stdout.strip()
    except Exception:
        return "?"


def _sysctl_write(key, value):
    """Write a sysctl value. Returns True on success."""
    try:
        result = subprocess.run(
            ["sysctl", "-w", f"{key}={value}"],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def _read_current_values():
    """Read all relevant sysctl values."""
    values = {
        "ttl": _sysctl_read("net.ipv4.ip_default_ttl"),
        "tcp_rmem": _sysctl_read("net.ipv4.tcp_rmem"),
        "tcp_wmem": _sysctl_read("net.ipv4.tcp_wmem"),
        "ip_no_pmtu_disc": _sysctl_read("net.ipv4.ip_no_pmtu_disc"),
        "tcp_sack": _sysctl_read("net.ipv4.tcp_sack"),
        "tcp_timestamps": _sysctl_read("net.ipv4.tcp_timestamps"),
        "tcp_window_scaling": _sysctl_read("net.ipv4.tcp_window_scaling"),
    }
    _set(current_values=values)
    return values


def _save_originals():
    """Save original values for restoration."""
    if _get("original_values"):
        return  # Already saved
    values = _read_current_values()
    _set(original_values=dict(values))


def _apply_profile(profile):
    """Apply a fingerprint profile via sysctl."""
    _set(status=f"Applying {profile['name']}...")
    _save_originals()

    success = True
    success = _sysctl_write("net.ipv4.ip_default_ttl", profile["ttl"]) and success
    success = _sysctl_write("net.ipv4.tcp_rmem", profile["tcp_rmem"]) and success
    success = _sysctl_write("net.ipv4.tcp_wmem", profile["tcp_wmem"]) and success
    success = _sysctl_write("net.ipv4.ip_no_pmtu_disc", profile["ip_no_pmtu_disc"]) and success
    success = _sysctl_write("net.ipv4.tcp_sack", profile["tcp_sack"]) and success
    success = _sysctl_write("net.ipv4.tcp_timestamps", profile["tcp_timestamps"]) and success
    success = _sysctl_write("net.ipv4.tcp_window_scaling", profile["tcp_window_scaling"]) and success

    if success:
        _set(status=f"Applied: {profile['name']}",
             active_profile=profile["name"])
    else:
        _set(status=f"Partial: {profile['name']}")

    _read_current_values()


def _restore_defaults():
    """Restore original sysctl values."""
    originals = _get("original_values")
    if not originals:
        _set(status="No originals saved")
        return

    _set(status="Restoring defaults...")

    _sysctl_write("net.ipv4.ip_default_ttl", originals.get("ttl", "64"))
    _sysctl_write("net.ipv4.tcp_rmem", originals.get("tcp_rmem", "4096 87380 6291456"))
    _sysctl_write("net.ipv4.tcp_wmem", originals.get("tcp_wmem", "4096 16384 4194304"))
    _sysctl_write("net.ipv4.ip_no_pmtu_disc", originals.get("ip_no_pmtu_disc", "0"))
    _sysctl_write("net.ipv4.tcp_sack", originals.get("tcp_sack", "1"))
    _sysctl_write("net.ipv4.tcp_timestamps", originals.get("tcp_timestamps", "1"))
    _sysctl_write("net.ipv4.tcp_window_scaling", originals.get("tcp_window_scaling", "1"))

    _read_current_values()
    _set(status="Defaults restored", active_profile="")


# ---------------------------------------------------------------------------
# LCD drawing
# ---------------------------------------------------------------------------
def _draw_lcd():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    idx = _get("profile_idx")
    status = _get("status")
    active = _get("active_profile")
    current = _get("current_values")

    # Header
    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "FINGERPRINT SPOOF", font=font, fill="#FF6600")

    y = 16

    # Profile selector
    for i, prof in enumerate(PROFILES):
        sel = (i == idx)
        prefix = ">" if sel else " "
        fg = "#00FF00" if sel else "#888"
        if prof["name"] == active:
            fg = "#FFFF00" if sel else "#AAAA00"
            prefix = "*" if not sel else ">"
        d.text((2, y), f"{prefix}{prof['name'][:14]} TTL:{prof['ttl']}", font=font, fill=fg)
        y += 12

    y += 4
    # Current values
    if current:
        d.text((2, y), f"CurTTL:{current.get('ttl', '?')}", font=font, fill="#666")
        y += 11
        sack = current.get("tcp_sack", "?")
        ts_val = current.get("tcp_timestamps", "?")
        d.text((2, y), f"SACK:{sack} TS:{ts_val}", font=font, fill="#666")

    # Status
    d.rectangle((0, 106, 127, 115), fill="#0a0a0a")
    d.text((2, 107), status[:21], font=font, fill="#FFCC00")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:apply K2:reset K3x", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_current_values():
    """Show all current sysctl values."""
    current = _read_current_values()
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.text((2, 2), "Current Stack Values", font=font, fill="#FF6600")
    y = 18
    for key, val in current.items():
        label = key.replace("tcp_", "").replace("ip_", "")[:8]
        val_str = str(val)[:14]
        d.text((2, y), f"{label}: {val_str}", font=font, fill="#AAAAAA")
        y += 12

    active = _get("active_profile")
    if active:
        d.text((2, y + 4), f"Profile: {active}", font=font, fill="#FFFF00")

    d.text((2, 116), "Press any key...", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)

    while True:
        btn = get_button(PINS, GPIO)
        if btn:
            break
        time.sleep(0.1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    _read_current_values()
    _save_originals()

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 16), "FINGERPRINT SPOOF", font=font, fill="#FF6600")
    d.text((4, 32), "TCP/IP stack spoofer", font=font, fill="#888")
    d.text((4, 52), "OK=Apply profile", font=font, fill="#666")
    d.text((4, 64), "U/D=Select  K1=Show", font=font, fill="#666")
    d.text((4, 76), "K2=Restore  K3=Exit", font=font, fill="#666")
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
                idx = _get("profile_idx")
                _apply_profile(PROFILES[idx])

            elif btn == "UP":
                idx = _get("profile_idx")
                _set(profile_idx=(idx - 1) % len(PROFILES))

            elif btn == "DOWN":
                idx = _get("profile_idx")
                _set(profile_idx=(idx + 1) % len(PROFILES))

            elif btn == "KEY1":
                _draw_current_values()

            elif btn == "KEY2":
                _restore_defaults()

            _draw_lcd()
            time.sleep(0.05)

    finally:
        # Restore on exit
        _restore_defaults()
        time.sleep(0.2)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
