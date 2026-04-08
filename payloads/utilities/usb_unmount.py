#!/usr/bin/env python3
"""
RaspyJack Payload -- USB Safe Unmount
======================================
Author: 7h30th3r0n3

Lists connected USB storage devices and provides safe unmount
with filesystem sync and power-off.

Controls
--------
  UP / DOWN   -- Navigate device list
  OK          -- Unmount selected device
  KEY1        -- Refresh device list
  KEY3        -- Exit
"""

import os
import sys
import time
import json
import signal
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROW_H = 12
DEBOUNCE = 0.22

_running = True


def _cleanup(*_args):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# Device discovery
# ---------------------------------------------------------------------------

def _list_usb_devices():
    """List USB block devices using lsblk."""
    try:
        result = subprocess.run(
            ["lsblk", "-J", "-o", "NAME,SIZE,MOUNTPOINT,TRAN"],
            capture_output=True, text=True, timeout=10,
        )
        data = json.loads(result.stdout)
    except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError):
        return []

    devices = []
    for blk in data.get("blockdevices", []):
        if blk.get("tran") == "usb":
            children = blk.get("children", [])
            if children:
                for child in children:
                    devices.append({
                        "name": child.get("name", "?"),
                        "size": child.get("size", "?"),
                        "mount": child.get("mountpoint", ""),
                        "parent": blk.get("name", ""),
                    })
            else:
                devices.append({
                    "name": blk.get("name", "?"),
                    "size": blk.get("size", "?"),
                    "mount": blk.get("mountpoint", ""),
                    "parent": "",
                })
    return devices


def _unmount_device(device):
    """Unmount a USB device and power it off safely."""
    dev_path = "/dev/" + device["name"]
    mount = device.get("mount", "")
    parent_name = device.get("parent", "") or device["name"]
    parent_path = "/dev/" + parent_name

    # Sync first
    try:
        subprocess.run(["sync"], timeout=10)
    except (subprocess.TimeoutExpired, OSError):
        pass

    # Unmount if mounted
    if mount:
        try:
            result = subprocess.run(
                ["umount", dev_path],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                return "umount: " + result.stderr.strip()[:14]
        except (subprocess.TimeoutExpired, OSError) as exc:
            return "Err: " + str(exc)[:16]

    # Power off the device
    try:
        result = subprocess.run(
            ["udisksctl", "power-off", "-b", parent_path],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return "Unmounted (no poff)"
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return "Unmounted (no poff)"

    return "Safe to remove!"


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_screen(lcd, fnt, devices, cursor, scroll, status):
    """Draw the USB device list."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "USB UNMOUNT", font=fnt, fill="#00CCFF")
    d.text((100, 1), str(len(devices)), font=fnt, fill="#888")

    # Device list
    visible = 6
    y = 16
    end = min(len(devices), scroll + visible)

    if not devices:
        d.text((4, 40), "No USB devices", font=fnt, fill="#666")
        d.text((4, 55), "KEY1 to refresh", font=fnt, fill="#888")
    else:
        for idx in range(scroll, end):
            dev = devices[idx]
            is_sel = idx == cursor
            prefix = ">" if is_sel else " "
            mounted = "M" if dev["mount"] else "-"
            label = prefix + dev["name"] + " " + dev["size"] + " " + mounted
            color = "#00FF00" if is_sel else "#AAAAAA"
            d.text((2, y), label[:22], font=fnt, fill=color)
            y += ROW_H

            if is_sel and dev["mount"]:
                mp = dev["mount"]
                if len(mp) > 20:
                    mp = "..." + mp[-17:]
                d.text((10, y), mp, font=fnt, fill="#888")
                y += ROW_H

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if status:
        d.text((2, 117), status[:22], font=fnt, fill="#FFFF00")
    else:
        d.text((2, 117), "OK:eject K1:ref K3:ex", font=fnt, fill="#AAA")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_confirm(lcd, fnt, dev_name):
    """Draw unmount confirmation dialog."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.text((10, 30), "Unmount device?", font=fnt, fill="#00CCFF")
    d.text((10, 48), dev_name[:18], font=fnt, fill="#FFAA00")
    d.text((10, 70), "OK = Yes", font=fnt, fill="#00FF00")
    d.text((10, 85), "Any = Cancel", font=fnt, fill="#666")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    fnt = scaled_font()

    devices = _list_usb_devices()
    cursor = 0
    scroll = 0
    status = ""
    last_press = 0.0
    visible = 6
    mode = "browse"  # browse | confirm

    try:
        while _running:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if mode == "confirm":
                if btn == "OK" and devices and cursor < len(devices):
                    status = "Unmounting..."
                    _draw_screen(lcd, fnt, devices, cursor, scroll, status)
                    result = _unmount_device(devices[cursor])
                    status = result
                    devices = _list_usb_devices()
                    cursor = min(cursor, max(0, len(devices) - 1))
                    mode = "browse"
                    time.sleep(0.3)
                    continue
                elif btn:
                    status = "Cancelled"
                    mode = "browse"
                    time.sleep(0.1)
                    continue
                time.sleep(0.08)
                continue

            if btn == "KEY3":
                break
            elif btn == "UP":
                cursor = max(0, cursor - 1)
                if cursor < scroll:
                    scroll = cursor
                status = ""
            elif btn == "DOWN":
                cursor = min(max(0, len(devices) - 1), cursor + 1)
                if cursor >= scroll + visible:
                    scroll = cursor - visible + 1
                status = ""
            elif btn == "KEY1":
                status = "Refreshing..."
                _draw_screen(lcd, fnt, devices, cursor, scroll, status)
                devices = _list_usb_devices()
                cursor = 0
                scroll = 0
                status = "Found " + str(len(devices)) + " device(s)"
            elif btn == "OK" and devices:
                if cursor < len(devices):
                    _draw_confirm(lcd, fnt, devices[cursor]["name"])
                    mode = "confirm"
                    time.sleep(0.1)
                    continue

            _draw_screen(lcd, fnt, devices, cursor, scroll, status)
            time.sleep(0.08)

    finally:
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
