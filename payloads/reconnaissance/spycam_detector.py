#!/usr/bin/env python3
"""
RaspyJack Payload -- Hidden Camera / Spy-cam Detector
=======================================================
Author: 7h30th3r0n3

Scans WiFi SSIDs and probe requests for patterns associated with hidden
cameras: IPCAM*, IPC-*, PV-*, CAMERA*, CAM-*.  Also checks for known
camera manufacturer OUIs in nearby device MAC addresses.

Estimates proximity via RSSI signal strength.

Requires a USB WiFi dongle capable of monitor mode for passive scanning.

Setup / Prerequisites
---------------------
- USB WiFi dongle with monitor mode support.
- ``iw``, ``iwconfig``, ``airodump-ng`` or ``tshark`` available.
- Root privileges.

Controls
--------
  OK          -- Start / stop scan
  UP / DOWN   -- Scroll detected devices
  KEY1        -- Toggle alert mode (LCD flash on detection)
  KEY2        -- Export results
  KEY3        -- Exit
"""

import os
import sys
import time
import re
import json
import subprocess
import threading
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
LOOT_DIR = "/root/Raspyjack/loot/SpyCam"
os.makedirs(LOOT_DIR, exist_ok=True)

DEBOUNCE = 0.22

# SSID patterns that suggest IP cameras
SSID_PATTERNS = [
    re.compile(r"^IPCAM", re.IGNORECASE),
    re.compile(r"^IPC[-_]", re.IGNORECASE),
    re.compile(r"^PV[-_]", re.IGNORECASE),
    re.compile(r"^CAMERA", re.IGNORECASE),
    re.compile(r"^CAM[-_]", re.IGNORECASE),
    re.compile(r"^YI[-_]", re.IGNORECASE),
    re.compile(r"^WYZE", re.IGNORECASE),
    re.compile(r"^EZVIZ", re.IGNORECASE),
    re.compile(r"^REOLINK", re.IGNORECASE),
    re.compile(r"^HIPCAM", re.IGNORECASE),
    re.compile(r"^VSTARCAM", re.IGNORECASE),
    re.compile(r"^WIFICAM", re.IGNORECASE),
    re.compile(r"^4G[-_]?CAM", re.IGNORECASE),
    re.compile(r"^MINI[-_]?CAM", re.IGNORECASE),
    re.compile(r"^SPY[-_]?CAM", re.IGNORECASE),
]

# Known camera manufacturer OUIs
CAMERA_OUIS = {
    "00:12:17": "Cisco-Linksys/Camera",
    "00:62:6e": "Dahua",
    "3c:ef:8c": "Dahua",
    "4c:11:bf": "Dahua",
    "a0:bd:1d": "Dahua",
    "28:57:be": "Hangzhou Hikvision",
    "44:47:cc": "Hangzhou Hikvision",
    "54:c4:15": "Hangzhou Hikvision",
    "c0:56:e3": "Hangzhou Hikvision",
    "84:3e:79": "Shenzhen Reolink",
    "d4:da:21": "Reolink",
    "2c:aa:8e": "Wyze",
    "7c:78:b2": "Wyze",
    "a4:da:22": "Ezviz",
    "cc:32:e5": "TP-Link/Camera",
    "00:1c:63": "Axis",
    "00:40:8c": "Axis",
    "ac:cc:8e": "Axis",
    "b8:a4:4f": "Axis",
    "48:02:2a": "B-Link/Camera",
    "7c:dd:90": "Shenzhen Foscam",
    "c0:56:27": "Belkin/NetCam",
    "f0:b4:29": "Yi Technology",
}

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_state = {
    "scanning": False,
    "stop": False,
    "devices": [],        # list of dicts: ssid, mac, rssi, distance, source, oui_match
    "status": "Idle",
    "scroll": 0,
    "alert_mode": False,
    "alert_flash": False,
    "mon_iface": "",
}


def _get(key):
    with _lock:
        val = _state[key]
        if isinstance(val, list):
            return list(val)
        return val


def _set(**kw):
    with _lock:
        for k, v in kw.items():
            _state[k] = v


def _add_device(dev):
    """Add or update a detected device."""
    with _lock:
        existing = list(_state["devices"])
        for i, d in enumerate(existing):
            if d["mac"] == dev["mac"]:
                # Update RSSI
                updated = dict(d)
                updated["rssi"] = dev["rssi"]
                updated["distance"] = dev["distance"]
                existing[i] = updated
                _state["devices"] = existing
                return
        _state["devices"] = existing + [dev]


# ---------------------------------------------------------------------------
# RSSI to distance estimation
# ---------------------------------------------------------------------------
def _rssi_to_distance(rssi):
    """Estimate distance in meters from RSSI using log-distance model."""
    if rssi >= 0:
        return "?"
    # Free-space path loss model (rough estimate)
    # Reference: -30 dBm at 1 meter
    n = 2.5  # path loss exponent (indoor)
    ref_rssi = -30
    try:
        distance = 10 ** ((ref_rssi - rssi) / (10 * n))
        if distance < 1:
            return f"<1m"
        if distance < 100:
            return f"~{distance:.0f}m"
        return f">100m"
    except (ValueError, OverflowError):
        return "?"


# ---------------------------------------------------------------------------
# Monitor mode management
# ---------------------------------------------------------------------------
def _find_wifi_dongle():
    """Find a USB WiFi interface (not the built-in wlan0)."""
    try:
        out = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True, timeout=5,
        )
        ifaces = re.findall(r"Interface\s+(\S+)", out.stdout)
        # Prefer wlan1 (USB dongle), fallback to wlan0
        for iface in ifaces:
            if iface != "wlan0":
                return iface
        if ifaces:
            return ifaces[0]
    except Exception:
        pass
    return "wlan1"


def _enable_monitor(iface):
    """Enable monitor mode on interface."""
    mon_iface = f"{iface}mon"

    try:
        # Try airmon-ng first
        subprocess.run(
            ["airmon-ng", "start", iface],
            capture_output=True, timeout=10,
        )
        # Check if mon interface was created
        result = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True, timeout=5,
        )
        if mon_iface in result.stdout:
            return mon_iface
        if f"{iface}mon" in result.stdout:
            return f"{iface}mon"
        # Maybe it stayed as same name
        if iface in result.stdout:
            return iface
    except FileNotFoundError:
        pass

    # Manual method
    try:
        subprocess.run(["ip", "link", "set", iface, "down"],
                        capture_output=True, timeout=5)
        subprocess.run(["iw", iface, "set", "type", "monitor"],
                        capture_output=True, timeout=5)
        subprocess.run(["ip", "link", "set", iface, "up"],
                        capture_output=True, timeout=5)
        return iface
    except Exception:
        pass

    return ""


def _disable_monitor(iface):
    """Restore managed mode."""
    base = iface.replace("mon", "")
    try:
        subprocess.run(["airmon-ng", "stop", iface],
                        capture_output=True, timeout=10)
    except FileNotFoundError:
        try:
            subprocess.run(["ip", "link", "set", iface, "down"],
                            capture_output=True, timeout=5)
            subprocess.run(["iw", iface, "set", "type", "managed"],
                            capture_output=True, timeout=5)
            subprocess.run(["ip", "link", "set", iface, "up"],
                            capture_output=True, timeout=5)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Scanning methods
# ---------------------------------------------------------------------------
def _scan_iwlist():
    """Scan visible SSIDs using iwlist (managed mode scan)."""
    iface = _find_wifi_dongle()
    try:
        out = subprocess.run(
            ["iwlist", iface, "scan"],
            capture_output=True, text=True, timeout=30,
        )
        cells = out.stdout.split("Cell ")
        for cell in cells[1:]:
            if _get("stop"):
                return
            ssid_m = re.search(r'ESSID:"(.+?)"', cell)
            mac_m = re.search(r"Address:\s+([0-9A-Fa-f:]+)", cell)
            rssi_m = re.search(r"Signal level[=:](-?\d+)", cell)

            ssid = ssid_m.group(1) if ssid_m else ""
            mac = mac_m.group(1).lower() if mac_m else ""
            rssi = int(rssi_m.group(1)) if rssi_m else -100

            _check_device(ssid, mac, rssi)
    except Exception:
        pass


def _scan_tshark(mon_iface):
    """Passive scan using tshark on monitor interface."""
    _set(status="tshark scanning...")

    cmd = [
        "tshark", "-i", mon_iface, "-a", "duration:10",
        "-T", "fields",
        "-e", "wlan.sa",
        "-e", "wlan_mgt.ssid",
        "-e", "radiotap.dbm_antsignal",
        "-Y", "wlan.fc.type_subtype == 0x04 || wlan.fc.type_subtype == 0x08",
    ]
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30,
        )
        for line in out.stdout.splitlines():
            if _get("stop"):
                return
            parts = line.split("\t")
            mac = parts[0].strip().lower() if len(parts) > 0 else ""
            ssid = parts[1].strip() if len(parts) > 1 else ""
            rssi_str = parts[2].strip() if len(parts) > 2 else "-100"
            try:
                rssi = int(rssi_str.split(",")[0])
            except (ValueError, IndexError):
                rssi = -100
            _check_device(ssid, mac, rssi)
    except FileNotFoundError:
        _set(status="tshark not found")
    except Exception as exc:
        _set(status=f"Scan err: {str(exc)[:14]}")


def _check_device(ssid, mac, rssi):
    """Check if device matches camera patterns."""
    is_suspicious = False
    source = ""

    # Check SSID patterns
    for pattern in SSID_PATTERNS:
        if ssid and pattern.search(ssid):
            is_suspicious = True
            source = "SSID"
            break

    # Check OUI
    oui = mac[:8] if mac else ""
    oui_match = CAMERA_OUIS.get(oui, "")
    if oui_match:
        is_suspicious = True
        if source:
            source += "+OUI"
        else:
            source = "OUI"

    if is_suspicious:
        distance = _rssi_to_distance(rssi)
        dev = {
            "ssid": ssid or "(hidden)",
            "mac": mac,
            "rssi": rssi,
            "distance": distance,
            "source": source,
            "oui_match": oui_match,
        }
        _add_device(dev)

        if _get("alert_mode"):
            _set(alert_flash=True)


def _do_scan():
    """Main scan loop."""
    _set(scanning=True, stop=False, status="Starting scan...")

    iface = _find_wifi_dongle()
    _set(status=f"Using {iface}")

    # Try monitor mode first
    mon = _enable_monitor(iface)
    _set(mon_iface=mon)

    if mon:
        _set(status=f"Monitor: {mon}")
        while not _get("stop"):
            _scan_tshark(mon)
            if not _get("stop"):
                _set(status=f"Found {len(_get('devices'))} suspects")
                time.sleep(1)
    else:
        # Fallback to managed mode scan
        _set(status="Managed mode scan")
        while not _get("stop"):
            _scan_iwlist()
            _set(status=f"Found {len(_get('devices'))} suspects")
            time.sleep(5)

    # Cleanup
    if mon:
        _disable_monitor(mon)
    _set(scanning=False, status="Scan stopped")


def _start_scan():
    if _get("scanning"):
        return
    threading.Thread(target=_do_scan, daemon=True).start()


def _stop_scan():
    _set(stop=True)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
def _export_results():
    devices = _get("devices")
    if not devices:
        return None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    data = {
        "scan_time": ts,
        "detected_count": len(devices),
        "devices": devices,
    }
    path = os.path.join(LOOT_DIR, f"spycam_{ts}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


# ---------------------------------------------------------------------------
# LCD drawing
# ---------------------------------------------------------------------------
def _draw_lcd():
    devices = _get("devices")
    scroll = _get("scroll")
    scanning = _get("scanning")
    status = _get("status")
    alert = _get("alert_mode")
    flash = _get("alert_flash")

    # Flash effect on new detection
    bg = "#330000" if flash else "black"
    if flash:
        _set(alert_flash=False)

    img = Image.new("RGB", (WIDTH, HEIGHT), bg)
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 12), fill="#111")
    alert_ind = "!" if alert else ""
    d.text((2, 1), f"SPYCAM DETECT {alert_ind}", font=font, fill="#FF0044")
    d.ellipse((118, 3, 124, 9), fill="#00FF00" if scanning else "#666")

    y = 14
    d.text((2, y), f"Suspects: {len(devices)}", font=font, fill="#AAAAAA")
    y += 13

    if not devices:
        d.text((4, y + 10), "No cameras detected", font=font, fill="#666")
        d.text((4, y + 24), "OK=Start scan", font=font, fill="#666")
    else:
        visible = 4
        for i in range(scroll, min(scroll + visible, len(devices))):
            dev = devices[i]
            sel = (i == scroll)
            fg = "#FF0044" if sel else "#AAAAAA"

            ssid_short = dev["ssid"][:12]
            d.text((2, y), f"{ssid_short}", font=font, fill=fg)
            y += 10
            mac_short = dev["mac"][:17]
            d.text((4, y), f"{mac_short} {dev['rssi']}dBm", font=font, fill="#888")
            y += 10
            d.text((4, y), f"{dev['distance']} [{dev['source']}]", font=font, fill="#666")
            y += 12

    # Status
    d.rectangle((0, 106, 127, 115), fill="#0a0a0a")
    d.text((2, 107), status[:21], font=font, fill="#FFCC00")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    action = "STOP" if scanning else "SCAN"
    d.text((2, 117), f"OK:{action} K1:alrt K3:x", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


def _show_msg(line1, line2=""):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), line1[:21], font=font, fill="#00FF00")
    if line2:
        d.text((4, 65), line2[:21], font=font, fill="#888")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 16), "SPYCAM DETECTOR", font=font, fill="#FF0044")
    d.text((4, 32), "Hidden camera finder", font=font, fill="#888")
    d.text((4, 52), "OK=Start/Stop", font=font, fill="#666")
    d.text((4, 64), "K1=Alert mode", font=font, fill="#666")
    d.text((4, 76), "K2=Export  K3=Exit", font=font, fill="#666")
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
                _stop_scan()
                break

            elif btn == "OK":
                if _get("scanning"):
                    _stop_scan()
                else:
                    _start_scan()

            elif btn == "KEY1":
                alert = _get("alert_mode")
                _set(alert_mode=not alert)

            elif btn == "KEY2":
                path = _export_results()
                if path:
                    _show_msg("Exported!", path[-20:])
                else:
                    _show_msg("No data yet")

            elif btn == "UP":
                s = _get("scroll")
                _set(scroll=max(0, s - 1))

            elif btn == "DOWN":
                s = _get("scroll")
                devices = _get("devices")
                _set(scroll=min(max(0, len(devices) - 1), s + 1))

            _draw_lcd()
            time.sleep(0.05)

    finally:
        _stop_scan()
        # Wait for scan thread
        for _ in range(20):
            if not _get("scanning"):
                break
            time.sleep(0.1)
        # Restore monitor mode interface
        mon = _get("mon_iface")
        if mon:
            _disable_monitor(mon)
        time.sleep(0.2)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
