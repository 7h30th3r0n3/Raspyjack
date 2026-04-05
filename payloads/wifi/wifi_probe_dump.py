#!/usr/bin/env python3
"""
RaspyJack Payload -- WiFi Probe Request Dump
=============================================
Author: 7h30th3r0n3

Passive WiFi probe request logger.  Puts a USB WiFi dongle into
monitor mode and sniffs Dot11ProbeReq frames with scapy.  Builds a
dictionary of {MAC: set(SSIDs)} and displays live stats on the LCD.

Setup / Prerequisites
---------------------
- USB WiFi dongle with monitor mode support (e.g. Alfa AWUS036ACH)

Controls:
  UP / DOWN  -- Scroll device list
  KEY1       -- Start / Stop capture
  KEY2       -- Export to JSON loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/ProbesDump/probes_YYYYMMDD_HHMMSS.json
"""

import os
import sys
import json
import time
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

try:
    from scapy.all import Dot11, Dot11Elt, Dot11ProbeReq, sniff as scapy_sniff
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROWS_VISIBLE = 7
ROW_H = 12

LOOT_DIR = "/root/Raspyjack/loot/ProbesDump"

# Channels to hop through (2.4 GHz)
CHANNELS_24 = list(range(1, 14))

# ---------------------------------------------------------------------------
# Shared state (protected by lock)
# ---------------------------------------------------------------------------
lock = threading.Lock()
probes = {}          # {mac_upper: set(ssid_strings)}
signal_map = {}      # {mac_upper: last_rssi}
running = False
scroll = 0
mon_iface = None

# ---------------------------------------------------------------------------
# Onboard WiFi detection
# ---------------------------------------------------------------------------

def _is_onboard_wifi_iface(iface):
    """True for the onboard Pi WiFi (SDIO/mmc or brcmfmac driver)."""
    try:
        devpath = os.path.realpath(f"/sys/class/net/{iface}/device")
        if "mmc" in devpath:
            return True
    except Exception:
        pass
    try:
        driver = os.path.basename(
            os.path.realpath(f"/sys/class/net/{iface}/device/driver")
        )
        if driver == "brcmfmac":
            return True
    except Exception:
        pass
    return False


def _find_usb_wifi():
    """Find a USB WiFi dongle suitable for monitor mode."""
    candidates = []
    try:
        for name in os.listdir("/sys/class/net"):
            if name == "lo":
                continue
            if os.path.isdir(f"/sys/class/net/{name}/wireless"):
                if not _is_onboard_wifi_iface(name):
                    candidates.append(name)
    except Exception:
        pass
    # Prefer interfaces whose driver is NOT in the no-monitor set
    no_mon = {"brcmfmac", "b43", "wl"}
    good, fallback = [], []
    for iface in candidates:
        drv = ""
        try:
            drv = os.path.basename(
                os.path.realpath(f"/sys/class/net/{iface}/device/driver"))
        except Exception:
            pass
        (fallback if drv in no_mon else good).append(iface)
    return (good or fallback or [None])[0]


def _monitor_up(iface):
    """Put iface into monitor mode. Returns monitor interface name or None."""
    for cmd in [
        ["nmcli", "device", "set", iface, "managed", "no"],
        ["sudo", "pkill", "-f", f"wpa_supplicant.*{iface}"],
        ["sudo", "pkill", "-f", f"dhcpcd.*{iface}"],
    ]:
        try:
            subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception:
            pass
    time.sleep(0.5)

    # airmon-ng
    try:
        subprocess.run(["sudo", "airmon-ng", "start", iface],
                       capture_output=True, timeout=30)
        for name in (f"{iface}mon", iface):
            r = subprocess.run(["iwconfig", name],
                               capture_output=True, text=True, timeout=5)
            if "Mode:Monitor" in r.stdout:
                return name
    except Exception:
        pass

    # iwconfig fallback
    try:
        subprocess.run(["sudo", "ifconfig", iface, "down"],
                       check=True, timeout=10)
        subprocess.run(["sudo", "iwconfig", iface, "mode", "monitor"],
                       check=True, timeout=10)
        subprocess.run(["sudo", "ifconfig", iface, "up"],
                       check=True, timeout=10)
        time.sleep(0.5)
        r = subprocess.run(["iwconfig", iface],
                           capture_output=True, text=True, timeout=5)
        if "Mode:Monitor" in r.stdout:
            return iface
    except Exception:
        pass

    # iw fallback
    try:
        subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                       check=True, timeout=10)
        subprocess.run(["sudo", "iw", iface, "set", "monitor", "none"],
                       check=True, timeout=10)
        subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                       check=True, timeout=10)
        time.sleep(0.5)
        r = subprocess.run(["iwconfig", iface],
                           capture_output=True, text=True, timeout=5)
        if "Mode:Monitor" in r.stdout:
            return iface
    except Exception:
        pass

    return None


def _monitor_down(iface):
    """Restore interface to managed mode."""
    if not iface:
        return
    base = iface.replace("mon", "")
    try:
        subprocess.run(["sudo", "airmon-ng", "stop", iface],
                       capture_output=True, timeout=10)
    except Exception:
        pass
    for cmd in [
        ["sudo", "ip", "link", "set", base, "down"],
        ["sudo", "iw", base, "set", "type", "managed"],
        ["sudo", "ip", "link", "set", base, "up"],
        ["nmcli", "device", "set", base, "managed", "yes"],
    ]:
        try:
            subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Capture threads
# ---------------------------------------------------------------------------

def _hop_thread():
    """Channel hopper for 2.4 GHz bands."""
    idx = 0
    while running:
        if mon_iface:
            ch = CHANNELS_24[idx % len(CHANNELS_24)]
            try:
                subprocess.run(
                    ["sudo", "iw", "dev", mon_iface, "set", "channel", str(ch)],
                    capture_output=True, timeout=3)
            except Exception:
                pass
            idx += 1
        time.sleep(0.3)


def _packet_handler(pkt):
    """Scapy callback for each captured packet."""
    if not pkt.haslayer(Dot11ProbeReq):
        return
    dot = pkt[Dot11]
    src = dot.addr2
    if not src or src == "ff:ff:ff:ff:ff:ff":
        return

    ssid = ""
    if pkt.haslayer(Dot11Elt):
        try:
            raw = pkt[Dot11Elt].info
            if raw:
                ssid = raw.decode("utf-8", errors="ignore")
        except Exception:
            pass

    rssi = getattr(pkt, "dBm_AntSignal", None)
    mac = src.upper()

    with lock:
        if mac not in probes:
            probes[mac] = set()
        if ssid:
            probes[mac].add(ssid)
        if rssi is not None:
            signal_map[mac] = rssi


def _sniff_thread():
    """Scapy capture loop."""
    if not SCAPY_OK or not mon_iface:
        return
    try:
        scapy_sniff(
            iface=mon_iface,
            prn=_packet_handler,
            stop_filter=lambda _: not running,
            store=0,
        )
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_loot():
    """Write probe data to JSON loot file. Returns filename."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"probes_{ts}.json"
    filepath = os.path.join(LOOT_DIR, filename)

    with lock:
        data = {
            mac: {
                "ssids": sorted(ssids),
                "rssi": signal_map.get(mac),
            }
            for mac, ssids in probes.items()
        }

    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)

    return filename

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_frame(lcd, font):
    """Render current state to the LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "PROBE DUMP", font=font, fill="#00FF00")
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if running else "#FF0000")

    with lock:
        total_devs = len(probes)
        all_ssids = set()
        for ssids in probes.values():
            all_ssids.update(ssids)
        total_ssids = len(all_ssids)
        device_list = sorted(probes.items(), key=lambda kv: len(kv[1]), reverse=True)

    # Summary line
    d.text((2, 16), f"Dev:{total_devs}  SSID:{total_ssids}", font=font, fill="#AAAAAA")

    # Scrollable device list
    visible = device_list[scroll:scroll + ROWS_VISIBLE]
    for i, (mac, ssids) in enumerate(visible):
        y = 28 + i * ROW_H
        short_mac = mac[-8:]
        ssid_preview = ", ".join(sorted(ssids))[:12] if ssids else "<hidden>"
        line = f"{short_mac} {ssid_preview}"
        d.text((2, y), line, font=font, fill="#CCCCCC")

    # Scroll indicator
    total = len(device_list)
    if total > ROWS_VISIBLE:
        bar_h = max(4, int(ROWS_VISIBLE / total * 80))
        bar_y = 28 + int(scroll / total * 80)
        d.rectangle((126, bar_y, 127, bar_y + bar_h), fill="#444")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    status = "K1:Stop" if running else "K1:Start"
    d.text((2, 117), f"{status} K2:Exp K3:Quit", font=font, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running, scroll, mon_iface

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font = scaled_font()

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 20), "WIFI PROBE DUMP", font=font, fill="#00FF00")
    d.text((4, 40), "Passive probe logger", font=font, fill="#888")
    d.text((4, 60), "KEY1  Start / Stop", font=font, fill="#666")
    d.text((4, 72), "KEY2  Export JSON", font=font, fill="#666")
    d.text((4, 84), "KEY3  Exit", font=font, fill="#666")
    d.text((4, 96), "U/D   Scroll list", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "KEY1":
                if running:
                    running = False
                    time.sleep(0.5)
                else:
                    if not mon_iface:
                        raw = _find_usb_wifi()
                        if raw:
                            mon_iface = _monitor_up(raw)
                    if mon_iface:
                        running = True
                        threading.Thread(target=_hop_thread, daemon=True).start()
                        threading.Thread(target=_sniff_thread, daemon=True).start()
                    else:
                        img2 = Image.new("RGB", (WIDTH, HEIGHT), "black")
                        d2 = ScaledDraw(img2)
                        d2.text((4, 50), "No USB WiFi found!", font=font, fill="#FF0000")
                        lcd.LCD_ShowImage(img2, 0, 0)
                        time.sleep(1.5)
                time.sleep(0.3)

            elif btn == "KEY2":
                fname = _export_loot()
                img2 = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d2 = ScaledDraw(img2)
                d2.text((4, 50), "Exported!", font=font, fill="#00FF00")
                d2.text((4, 65), fname[:22], font=font, fill="#888")
                lcd.LCD_ShowImage(img2, 0, 0)
                time.sleep(1.5)

            elif btn == "UP":
                scroll = max(0, scroll - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                with lock:
                    max_scroll = max(0, len(probes) - ROWS_VISIBLE)
                scroll = min(scroll + 1, max_scroll)
                time.sleep(0.15)

            _draw_frame(lcd, font)
            time.sleep(0.05)

    finally:
        running = False
        time.sleep(0.3)
        _monitor_down(mon_iface)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
