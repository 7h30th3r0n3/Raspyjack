#!/usr/bin/env python3
"""
RaspyJack Payload -- MAC Address Randomizer
--------------------------------------------
Author: 7h30th3r0n3

Randomize, restore, or clone MAC addresses on network interfaces.

Controls:
  UP/DOWN  = select interface
  OK       = randomize MAC on selected interface
  KEY1     = restore original MAC
  KEY2     = clone mode (scan nearby devices, pick one)
  KEY3     = exit
"""

import os
import sys
import time
import random
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
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

INTERFACES = ["eth0", "wlan0", "wlan1"]
DEBOUNCE = 0.25


def _run(cmd):
    """Run a shell command and return (returncode, stdout)."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return res.returncode, res.stdout.strip()
    except Exception as exc:
        return 1, str(exc)


def _get_mac(iface):
    """Read current MAC address for an interface."""
    path = f"/sys/class/net/{iface}/address"
    try:
        with open(path, "r") as fh:
            return fh.read().strip()
    except Exception:
        return "N/A"


def _iface_exists(iface):
    """Check if a network interface exists."""
    return os.path.isdir(f"/sys/class/net/{iface}")


def _generate_random_mac():
    """Generate a random locally-administered unicast MAC."""
    octets = [random.randint(0x00, 0xFF) for _ in range(6)]
    octets[0] = (octets[0] & 0xFE) | 0x02  # unicast + locally administered
    return ":".join(f"{b:02x}" for b in octets)


def _set_mac(iface, new_mac):
    """Bring interface down, set MAC, bring back up. Returns (ok, msg)."""
    rc1, _ = _run(["ip", "link", "set", iface, "down"])
    rc2, out = _run(["ip", "link", "set", iface, "address", new_mac])
    rc3, _ = _run(["ip", "link", "set", iface, "up"])
    if rc2 != 0:
        return False, out[:60]
    return True, ""


def _scan_nearby_macs():
    """Scan ARP table and wifi neighbors for MAC addresses."""
    found = []
    rc, out = _run(["ip", "neigh", "show"])
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            for i, part in enumerate(parts):
                if part == "lladdr" and i + 1 < len(parts):
                    mac = parts[i + 1]
                    ip_addr = parts[0] if parts else "?"
                    entry = f"{ip_addr} {mac}"
                    if entry not in found:
                        found.append(entry)
    return found if found else ["No neighbors found"]


def _draw_main(lcd, interfaces, macs, selected, status_msg=""):
    """Draw main interface list with MACs."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#1a1a1a")
    d.text((2, 1), "MAC Randomizer", font=font, fill="#00ff00")
    d.text((100, 1), "K3", font=font, fill="white")

    y = 16
    for idx, iface in enumerate(interfaces):
        exists = _iface_exists(iface)
        prefix = ">" if idx == selected else " "
        color = "#00ff00" if idx == selected else "#888888"
        if not exists:
            color = "#444444"

        label = f"{prefix}{iface}"
        d.text((2, y), label, font=font, fill=color)
        y += 11

        mac_str = macs.get(iface, "N/A")
        if len(mac_str) > 17:
            mac_str = mac_str[:17]
        d.text((8, y), mac_str, font=font, fill="#aaaaaa" if exists else "#444444")
        y += 13

    d.line((0, y, 127, y), fill="#333333")
    y += 3

    d.text((2, y), "OK=rand K1=restore", font=font, fill="#666666")
    y += 11
    d.text((2, y), "K2=clone", font=font, fill="#666666")
    y += 13

    if status_msg:
        lines = [status_msg[i:i + 20] for i in range(0, len(status_msg), 20)]
        for line in lines[:3]:
            d.text((2, y), line, font=font, fill="#ffff00")
            y += 11

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_clone_menu(lcd, entries, selected, title="Clone MAC"):
    """Draw list of nearby devices to clone."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#1a1a1a")
    d.text((2, 1), title, font=font, fill="#00ff00")
    d.text((100, 1), "K3", font=font, fill="white")

    y = 16
    visible_count = 8
    start = max(0, selected - visible_count + 1)
    end = min(len(entries), start + visible_count)

    for idx in range(start, end):
        prefix = ">" if idx == selected else " "
        color = "#00ff00" if idx == selected else "#aaaaaa"
        text = f"{prefix}{entries[idx]}"
        d.text((2, y), text[:20], font=font, fill=color)
        y += 12

    d.text((2, 116), "OK=select K3=back", font=font, fill="#666666")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_status(lcd, msg, color="#00ff00"):
    """Show a temporary status message."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    lines = [msg[i:i + 18] for i in range(0, len(msg), 18)]
    y = 40
    for line in lines[:5]:
        d.text((4, y), line, font=font, fill=color)
        y += 14
    lcd.LCD_ShowImage(img, 0, 0)


def main():
    """Main entry point."""
    original_macs = {}
    for iface in INTERFACES:
        original_macs[iface] = _get_mac(iface)

    selected = 0
    status_msg = ""
    clone_mode = False
    clone_entries = []
    clone_selected = 0
    last_press = 0.0

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()

            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if clone_mode:
                if btn == "KEY3":
                    clone_mode = False
                elif btn == "UP":
                    clone_selected = max(0, clone_selected - 1)
                elif btn == "DOWN":
                    clone_selected = min(len(clone_entries) - 1, clone_selected + 1)
                elif btn == "OK" and clone_entries:
                    entry = clone_entries[clone_selected]
                    parts = entry.split()
                    if len(parts) >= 2:
                        target_mac = parts[-1]
                        iface = INTERFACES[selected]
                        if _iface_exists(iface):
                            ok, err = _set_mac(iface, target_mac)
                            if ok:
                                status_msg = f"Cloned {target_mac}"
                            else:
                                status_msg = f"Fail: {err}"
                    clone_mode = False

                _draw_clone_menu(LCD, clone_entries, clone_selected)
                time.sleep(0.05)
                continue

            if btn == "KEY3":
                break
            elif btn == "UP":
                selected = max(0, selected - 1)
            elif btn == "DOWN":
                selected = min(len(INTERFACES) - 1, selected + 1)
            elif btn == "OK":
                iface = INTERFACES[selected]
                if _iface_exists(iface):
                    old_mac = _get_mac(iface)
                    new_mac = _generate_random_mac()
                    ok, err = _set_mac(iface, new_mac)
                    if ok:
                        status_msg = f"{old_mac[:8]}..>{new_mac[:8]}.."
                    else:
                        status_msg = f"Fail: {err}"
                else:
                    status_msg = f"{iface} not found"
            elif btn == "KEY1":
                iface = INTERFACES[selected]
                orig = original_macs.get(iface, "")
                if orig and orig != "N/A" and _iface_exists(iface):
                    ok, err = _set_mac(iface, orig)
                    if ok:
                        status_msg = f"Restored {orig[:11]}.."
                    else:
                        status_msg = f"Fail: {err}"
                else:
                    status_msg = "No original saved"
            elif btn == "KEY2":
                _draw_status(LCD, "Scanning ARP...")
                clone_entries = _scan_nearby_macs()
                clone_selected = 0
                clone_mode = True

            current_macs = {}
            for iface in INTERFACES:
                current_macs[iface] = _get_mac(iface)

            _draw_main(LCD, INTERFACES, current_macs, selected, status_msg)
            time.sleep(0.08)

    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
