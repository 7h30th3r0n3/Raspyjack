#!/usr/bin/env python3
"""
RaspyJack Payload – Universal WiFi Adapter Installer
======================================================
Plug in your dongle, press KEY1, done.

FLOW:
  1. Scan USB dongles (lsusb + /sys)
  2. Identify VID:PID against built-in driver database
  3. Automatic install (apt / DKMS apt / GitHub build)
  4. Monitor mode test
  5. LCD result screen

CONTROLS:
  UP / DOWN   – Navigate dongle list
  OK / →      – View dongle details
  KEY1        – Install selected dongle
  KEY2        – Re-scan dongles
  KEY3        – Exit
"""

import os
import sys
import time
import subprocess
import threading
import re

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

# ══════════════════════════════════════════════════════════════════════════════
#  DRIVER DATABASE  –  VID:PID → driver / install method
# ══════════════════════════════════════════════════════════════════════════════

DRIVER_DB: dict = {

    # ── Alfa AWUS036AXM  (WiFi 6 AX1800 – MT7921AU) ──────────────────────────
    "0e8d:7961": {
        "name": "Alfa AWUS036AXM (AX1800 WiFi6)",
        "driver": "mt7921u",
        "package": "firmware-misc-nonfree",
        "dkms_repo": None,
        "dkms_pkg": None,
        "monitor": True, "injection": True,
        "bands": ["2.4GHz", "5GHz", "6GHz"],
        "notes": "In-kernel since Linux 5.18 – needs firmware-misc-nonfree",
    },
    # Same chip, alternate PID seen on some units
    "0e8d:7962": {
        "name": "Alfa AWUS036AXM v2 (AX1800)",
        "driver": "mt7921u",
        "package": "firmware-misc-nonfree",
        "dkms_repo": None,
        "dkms_pkg": None,
        "monitor": True, "injection": True,
        "bands": ["2.4GHz", "5GHz", "6GHz"],
        "notes": "MT7921AU variant",
    },

    # ── Realtek RTL8812AU (AC1200 dual-band) ──────────────────────────────────
    "0bda:8812": {
        "name": "Realtek RTL8812AU (AC1200)",
        "driver": "rtl8812au",
        "package": None,
        "dkms_repo": "https://github.com/aircrack-ng/rtl8812au",
        "dkms_pkg": "realtek-rtl88xxau-dkms",
        "monitor": True, "injection": True,
        "bands": ["2.4GHz", "5GHz"],
        "notes": "Alfa AWUS036ACH, AWUS036EAC, TP-Link T4U v1",
    },
    "0bda:a812": {
        "name": "Realtek RTL8812AU variant",
        "driver": "rtl8812au",
        "package": None,
        "dkms_repo": "https://github.com/aircrack-ng/rtl8812au",
        "dkms_pkg": "realtek-rtl88xxau-dkms",
        "monitor": True, "injection": True,
        "bands": ["2.4GHz", "5GHz"],
        "notes": "",
    },

    # ── Realtek RTL8814AU (AC1900) ────────────────────────────────────────────
    "0bda:8813": {
        "name": "Realtek RTL8814AU (AC1900)",
        "driver": "rtl8814au",
        "package": None,
        "dkms_repo": "https://github.com/morrownr/8814au",
        "dkms_pkg": None,
        "monitor": True, "injection": True,
        "bands": ["2.4GHz", "5GHz"],
        "notes": "Alfa AWUS1900",
    },

    # ── Realtek RTL8821AU / RTL8811AU (AC600) ─────────────────────────────────
    "0bda:0811": {
        "name": "Realtek RTL8811AU (AC600)",
        "driver": "rtl8821au",
        "package": None,
        "dkms_repo": "https://github.com/aircrack-ng/rtl8812au",
        "dkms_pkg": "realtek-rtl88xxau-dkms",
        "monitor": True, "injection": True,
        "bands": ["2.4GHz", "5GHz"],
        "notes": "",
    },
    "0bda:0820": {
        "name": "Realtek RTL8821AU (AC600)",
        "driver": "rtl8821au",
        "package": None,
        "dkms_repo": "https://github.com/aircrack-ng/rtl8812au",
        "dkms_pkg": "realtek-rtl88xxau-dkms",
        "monitor": True, "injection": True,
        "bands": ["2.4GHz", "5GHz"],
        "notes": "Alfa AWUS036ACS",
    },

    # ── Realtek RTL8822BU / RTL8822CU (AC1200) ───────────────────────────────
    "0bda:b812": {
        "name": "Realtek RTL8822BU (AC1200)",
        "driver": "rtl88x2bu",
        "package": None,
        "dkms_repo": "https://github.com/morrownr/88x2bu-20210702",
        "dkms_pkg": "realtek-rtl88x2bu-dkms",
        "monitor": True, "injection": True,
        "bands": ["2.4GHz", "5GHz"],
        "notes": "TP-Link Archer T3U, Edimax EW-7822UTC",
    },
    "0bda:c812": {
        "name": "Realtek RTL8822CU (AC1300)",
        "driver": "rtl88x2bu",
        "package": None,
        "dkms_repo": "https://github.com/morrownr/88x2bu-20210702",
        "dkms_pkg": "realtek-rtl88x2bu-dkms",
        "monitor": True, "injection": True,
        "bands": ["2.4GHz", "5GHz"],
        "notes": "",
    },

    # ── Realtek RTL8188EUS / RTL8188CUS (N150) ────────────────────────────────
    "0bda:8179": {
        "name": "Realtek RTL8188EUS (N150)",
        "driver": "rtl8188eus",
        "package": None,
        "dkms_repo": "https://github.com/aircrack-ng/rtl8188eus",
        "dkms_pkg": "realtek-rtl8188eus-dkms",
        "monitor": True, "injection": True,
        "bands": ["2.4GHz"],
        "notes": "Alfa AWUS036ELS, many cheap N150 adapters",
    },
    "0bda:8176": {
        "name": "Realtek RTL8188CUS (N150)",
        "driver": "rtl8192cu",
        "package": "firmware-realtek",
        "dkms_repo": None,
        "dkms_pkg": None,
        "monitor": True, "injection": False,
        "bands": ["2.4GHz"],
        "notes": "In-kernel driver, limited monitor mode",
    },
    "0bda:8178": {
        "name": "Realtek RTL8192CU (N300)",
        "driver": "rtl8192cu",
        "package": "firmware-realtek",
        "dkms_repo": None,
        "dkms_pkg": None,
        "monitor": True, "injection": False,
        "bands": ["2.4GHz"],
        "notes": "",
    },
    "0bda:0179": {
        "name": "Realtek RTL8188ETV (N150)",
        "driver": "rtl8188eus",
        "package": None,
        "dkms_repo": "https://github.com/aircrack-ng/rtl8188eus",
        "dkms_pkg": "realtek-rtl8188eus-dkms",
        "monitor": True, "injection": True,
        "bands": ["2.4GHz"],
        "notes": "",
    },

    # ── Realtek RTL8187 ───────────────────────────────────────────────────────
    "0bda:8187": {
        "name": "Alfa AWUS036H (RTL8187)",
        "driver": "rtl8187",
        "package": "firmware-realtek",
        "dkms_repo": None,
        "dkms_pkg": None,
        "monitor": True, "injection": True,
        "bands": ["2.4GHz"],
        "notes": "Classic adapter, in-kernel driver",
    },

    # ── Realtek RTL8723BU (N150 + BT) ─────────────────────────────────────────
    "0bda:b720": {
        "name": "Realtek RTL8723BU (N150+BT)",
        "driver": "rtl8723bu",
        "package": None,
        "dkms_repo": "https://github.com/lwfinger/rtl8723bu",
        "dkms_pkg": None,
        "monitor": False, "injection": False,
        "bands": ["2.4GHz"],
        "notes": "No monitor mode support",
    },

    # ── Ralink / MediaTek (in-kernel rt2800usb) ───────────────────────────────
    "148f:3070": {
        "name": "Ralink RT3070 (N150)",
        "driver": "rt2800usb",
        "package": "firmware-ralink",
        "dkms_repo": None,
        "dkms_pkg": None,
        "monitor": True, "injection": True,
        "bands": ["2.4GHz"],
        "notes": "Alfa AWUS036NH – in-kernel driver",
    },
    "148f:5370": {
        "name": "Ralink RT5370 (N150)",
        "driver": "rt2800usb",
        "package": "firmware-ralink",
        "dkms_repo": None,
        "dkms_pkg": None,
        "monitor": True, "injection": True,
        "bands": ["2.4GHz"],
        "notes": "Panda PAU05 – in-kernel driver",
    },
    "148f:5572": {
        "name": "Ralink RT5572 (N300 dual-band)",
        "driver": "rt2800usb",
        "package": "firmware-ralink",
        "dkms_repo": None,
        "dkms_pkg": None,
        "monitor": True, "injection": True,
        "bands": ["2.4GHz", "5GHz"],
        "notes": "Alfa AWUS052NH – in-kernel driver",
    },
    "148f:2870": {
        "name": "Ralink RT2870 (N150)",
        "driver": "rt2800usb",
        "package": "firmware-ralink",
        "dkms_repo": None,
        "dkms_pkg": None,
        "monitor": True, "injection": True,
        "bands": ["2.4GHz"],
        "notes": "In-kernel driver",
    },
    "0df6:0059": {
        "name": "Sitecom WLA-2000 (RT5572)",
        "driver": "rt2800usb",
        "package": "firmware-ralink",
        "dkms_repo": None,
        "dkms_pkg": None,
        "monitor": True, "injection": True,
        "bands": ["2.4GHz", "5GHz"],
        "notes": "",
    },

    # ── MediaTek MT7601U (N150) ───────────────────────────────────────────────
    "0e8d:760b": {
        "name": "MediaTek MT7601U (N150)",
        "driver": "mt7601u",
        "package": "firmware-misc-nonfree",
        "dkms_repo": None,
        "dkms_pkg": None,
        "monitor": True, "injection": False,
        "bands": ["2.4GHz"],
        "notes": "In-kernel driver, limited injection",
    },
    "2717:4106": {
        "name": "Xiaomi Mi WiFi (MT7601U)",
        "driver": "mt7601u",
        "package": "firmware-misc-nonfree",
        "dkms_repo": None,
        "dkms_pkg": None,
        "monitor": True, "injection": False,
        "bands": ["2.4GHz"],
        "notes": "",
    },

    # ── MediaTek MT7612U (AC1200) ─────────────────────────────────────────────
    "0e8d:7612": {
        "name": "MediaTek MT7612U (AC1200)",
        "driver": "mt76x2u",
        "package": "firmware-misc-nonfree",
        "dkms_repo": None,
        "dkms_pkg": None,
        "monitor": True, "injection": True,
        "bands": ["2.4GHz", "5GHz"],
        "notes": "In-kernel since Linux 4.19",
    },

    # ── MediaTek MT7610U (AC600) ──────────────────────────────────────────────
    "148f:761a": {
        "name": "Panda PAU0A (MT7610U AC600)",
        "driver": "mt76x0u",
        "package": "firmware-misc-nonfree",
        "dkms_repo": None,
        "dkms_pkg": None,
        "monitor": True, "injection": True,
        "bands": ["2.4GHz", "5GHz"],
        "notes": "In-kernel since Linux 4.19",
    },

    # ── MediaTek MT7921AU (WiFi 6 AX1800) – generic PIDs ─────────────────────
    "0e8d:7925": {
        "name": "MediaTek MT7921AU (AX1800)",
        "driver": "mt7921u",
        "package": "firmware-misc-nonfree",
        "dkms_repo": None,
        "dkms_pkg": None,
        "monitor": True, "injection": True,
        "bands": ["2.4GHz", "5GHz", "6GHz"],
        "notes": "In-kernel since Linux 5.18",
    },

    # ── Atheros AR9271 (N150) ─────────────────────────────────────────────────
    "0cf3:9271": {
        "name": "Atheros AR9271 (N150)",
        "driver": "ath9k_htc",
        "package": "firmware-atheros",
        "dkms_repo": None,
        "dkms_pkg": None,
        "monitor": True, "injection": True,
        "bands": ["2.4GHz"],
        "notes": "Alfa AWUS036NHA, TP-Link TL-WN722N v1",
    },
    "0cf3:7015": {
        "name": "Atheros AR7010+AR9280 (N300 dual)",
        "driver": "ath9k_htc",
        "package": "firmware-atheros",
        "dkms_repo": None,
        "dkms_pkg": None,
        "monitor": True, "injection": True,
        "bands": ["2.4GHz", "5GHz"],
        "notes": "",
    },

    # ── TP-Link ───────────────────────────────────────────────────────────────
    "2357:010c": {
        "name": "TP-Link TL-WN722N v2/v3",
        "driver": "rtl8188eus",
        "package": None,
        "dkms_repo": "https://github.com/aircrack-ng/rtl8188eus",
        "dkms_pkg": "realtek-rtl8188eus-dkms",
        "monitor": True, "injection": True,
        "bands": ["2.4GHz"],
        "notes": "v2/v3 use Realtek chip (v1=AR9271)",
    },
    "2357:011e": {
        "name": "TP-Link Archer T2U (RTL8821AU)",
        "driver": "rtl8821au",
        "package": None,
        "dkms_repo": "https://github.com/aircrack-ng/rtl8812au",
        "dkms_pkg": "realtek-rtl88xxau-dkms",
        "monitor": True, "injection": True,
        "bands": ["2.4GHz", "5GHz"],
        "notes": "",
    },
    "2357:0120": {
        "name": "TP-Link Archer T3U (RTL8812BU)",
        "driver": "rtl88x2bu",
        "package": None,
        "dkms_repo": "https://github.com/morrownr/88x2bu-20210702",
        "dkms_pkg": "realtek-rtl88x2bu-dkms",
        "monitor": True, "injection": True,
        "bands": ["2.4GHz", "5GHz"],
        "notes": "",
    },
    "2357:0109": {
        "name": "TP-Link TL-WN823N v2 (RTL8192EU)",
        "driver": "rtl8192eu",
        "package": None,
        "dkms_repo": "https://github.com/Mange/rtl8192eu-linux-driver",
        "dkms_pkg": None,
        "monitor": True, "injection": False,
        "bands": ["2.4GHz"],
        "notes": "Limited monitor mode",
    },

    # ── Panda ─────────────────────────────────────────────────────────────────
    "0b05:17ba": {
        "name": "Panda PAU06 (RT2870)",
        "driver": "rt2800usb",
        "package": "firmware-ralink",
        "dkms_repo": None,
        "dkms_pkg": None,
        "monitor": True, "injection": True,
        "bands": ["2.4GHz"],
        "notes": "In-kernel driver",
    },
}


def db_lookup(vid: str, pid: str) -> dict | None:
    return DRIVER_DB.get(f"{vid.lower()}:{pid.lower()}")


# ══════════════════════════════════════════════════════════════════════════════
#  HARDWARE INIT
# ══════════════════════════════════════════════════════════════════════════════

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
LOG_FILE = "/root/Raspyjack/loot/network/wifi_installer.log"
ONBOARD_DRIVERS = {"brcmfmac", "brcmsmac", "b43", "b43legacy"}

GPIO.setmode(GPIO.BCM)
for _pin in PINS.values():
    GPIO.setup(_pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
LCD.LCD_Clear()
WIDTH, HEIGHT = LCD.width, LCD.height

try:
    FONT    = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", int(10 * LCD_1in44.LCD_SCALE))
    FONT_SM = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", int(8 * LCD_1in44.LCD_SCALE))
except Exception:
    FONT = FONT_SM = scaled_font()

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# ══════════════════════════════════════════════════════════════════════════════
#  LOGGING + DISPLAY
# ══════════════════════════════════════════════════════════════════════════════

def log(msg: str):
    ts   = time.strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def show(lines: list, title: str = "WiFi Installer",
         title_col: str = "#00BFFF", progress: int = -1):
    """
    Render LCD screen.
    lines    : list of (text, color) or plain str -> white
    progress : 0-100 draws a progress bar; -1 = no bar
    """
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d   = ScaledDraw(img)

    d.rectangle((0, 0, 127, 14), fill="#0d1b2a")
    d.text((3, 2), title[:20], font=FONT_SM, fill=title_col)

    y_start = 16
    if progress >= 0:
        bar_w = int((WIDTH - 6) * min(progress, 100) / 100)
        d.rectangle((3, 16, 125, 23), outline="#333333")
        if bar_w > 0:
            d.rectangle((3, 16, 3 + bar_w, 23), fill="#00FF88")
        y_start = 26

    y = y_start
    for item in lines:
        if y > 1272:
            break
        text, color = item if isinstance(item, tuple) else (str(item), "white")
        d.text((3, y), str(text)[:21], font=FONT_SM, fill=color)
        y += 12

    LCD.LCD_ShowImage(img, 0, 0)


# ══════════════════════════════════════════════════════════════════════════════
#  USB DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def _read_sysfs(path: str) -> str:
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return ""


def _iface_driver(iface: str) -> str:
    try:
        return os.path.basename(
            os.path.realpath(f"/sys/class/net/{iface}/device/driver"))
    except Exception:
        return "unknown"


def _find_iface_for_vidpid(vid: str, pid: str) -> str | None:
    try:
        for iface in os.listdir("/sys/class/net"):
            if not os.path.isdir(f"/sys/class/net/{iface}/wireless"):
                continue
            dev = os.path.realpath(f"/sys/class/net/{iface}/device")
            for _ in range(5):
                v = _read_sysfs(os.path.join(dev, "idVendor")).lower()
                p = _read_sysfs(os.path.join(dev, "idProduct")).lower()
                if v == vid and p == pid:
                    return iface
                dev = os.path.dirname(dev)
    except Exception:
        pass
    return None


def detect_usb_wifi_dongles() -> list[dict]:
    """Return list of detected USB WiFi dongles."""
    dongles = []
    try:
        out = subprocess.check_output(
            ["lsusb"], text=True, stderr=subprocess.DEVNULL, timeout=5)
    except Exception:
        return []

    seen = set()
    for line in out.splitlines():
        m = re.search(r"ID\s+([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\s+(.*)", line)
        if not m:
            continue
        vid, pid = m.group(1).lower(), m.group(2).lower()
        usb_name = m.group(3).strip()
        key = f"{vid}:{pid}"

        if key in seen:
            continue
        seen.add(key)

        entry  = db_lookup(vid, pid)
        iface  = _find_iface_for_vidpid(vid, pid)
        driver = _iface_driver(iface) if iface else (
            entry["driver"] if entry else "unknown")

        if driver in ONBOARD_DRIVERS:
            continue

        if entry is None and iface is None:
            continue

        dongles.append({
            "vid": vid, "pid": pid, "key": key,
            "usb_name": usb_name[:30],
            "db_entry": entry,
            "iface": iface,
            "driver": driver,
            "is_new": iface is None,
        })

    return dongles


# ══════════════════════════════════════════════════════════════════════════════
#  INSTALLATION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class Installer:

    def __init__(self, dongle: dict, progress_cb=None):
        self.dongle       = dongle
        self.entry        = dongle.get("db_entry") or {}
        self.progress_cb  = progress_cb or (lambda p, m: None)
        self.success      = False
        self.result_iface = None

    def run(self) -> bool:
        d     = self.dongle
        entry = self.entry

        self._p(2, "Checking module...")
        driver_name = d["driver"]

        # Check if already loaded
        if self._driver_loaded(driver_name):
            self._p(40, "Already loaded")
            iface = self._wait_iface(d["vid"], d["pid"], 5)
            if iface:
                self.result_iface = iface
                self.success = True
                self._p(100, f"Ready: {iface}")
                return True

        # Check if .ko exists on disk but not loaded — just modprobe it
        # Also check common alternate names (88XXau for rtl8812au, etc.)
        alt_names = [driver_name, driver_name.replace("rtl", ""),
                     "88XXau", "rtl88XXau"]
        for name in alt_names:
            if self._driver_installed(name):
                self._p(10, f"Found {name}, loading...")
                log(f"Driver {name} found on disk, loading")
                self._modprobe(name)
                iface = self._wait_iface(d["vid"], d["pid"], 10)
                if iface:
                    return self._done(iface)

        self._p(5, "apt update...")
        self._cmd(["apt-get", "update", "-qq"], timeout=120)

        # 1. Standard apt package
        pkg = entry.get("package")
        if pkg:
            self._p(15, f"apt install {pkg}")
            if self._apt([pkg]):
                self._p(60, "modprobe...")
                self._modprobe(d["driver"])
                iface = self._wait_iface(d["vid"], d["pid"], 15)
                if iface:
                    return self._done(iface)

        # 2. DKMS apt package
        dkms_pkg = entry.get("dkms_pkg")
        if dkms_pkg:
            self._p(20, "DKMS apt pkg...")
            self._add_kali_repo()
            self._cmd(["apt-get", "update", "-qq"], timeout=60)
            if self._apt([dkms_pkg]):
                self._p(70, "modprobe...")
                self._modprobe(d["driver"])
                iface = self._wait_iface(d["vid"], d["pid"], 20)
                if iface:
                    return self._done(iface)

        # 3. Build from GitHub
        repo = entry.get("dkms_repo")
        if repo:
            self._p(25, "Build deps...")
            self._build_deps()
            self._p(35, "git clone...")
            if self._build_github(repo, d["driver"]):
                self._p(85, "modprobe...")
                self._modprobe(d["driver"])
                iface = self._wait_iface(d["vid"], d["pid"], 25)
                if iface:
                    return self._done(iface)

        # 4. Fallback: try driver name from DB, then modalias probe
        driver_name = entry.get("driver", d.get("driver", ""))
        if driver_name and driver_name != "unknown":
            self._p(30, f"modprobe {driver_name}...")
            ok, out = self._cmd(["modprobe", driver_name], timeout=15)
            if not ok:
                log(f"modprobe {driver_name} failed: {out[:200]}")
            iface = self._wait_iface(d["vid"], d["pid"], 10)
            if iface:
                return self._done(iface)

        # 5. Last resort: unbind/rebind USB device to trigger kernel auto-probe
        self._p(40, "USB re-probe...")
        self._usb_reprobe(d["vid"], d["pid"])
        iface = self._wait_iface(d["vid"], d["pid"], 15)
        if iface:
            return self._done(iface)

        self._p(0, "FAILED - check log")
        log(f"All install methods failed for {d['key']} ({driver_name})")
        return False

    def _done(self, iface: str) -> bool:
        self.result_iface = iface
        self.success = True
        self._p(100, f"Ready: {iface}")
        return True

    def _p(self, pct: int, msg: str):
        log(f"[{pct:3d}%] {msg}")
        self.progress_cb(pct, msg)

    def _cmd(self, cmd: list, timeout: int = 60,
             ok_err: bool = False) -> tuple[bool, str]:
        try:
            env = os.environ.copy()
            env["DEBIAN_FRONTEND"] = "noninteractive"
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout, env=env)
            log(f"  $ {' '.join(cmd[:4])} -> rc={r.returncode}")
            return r.returncode == 0, r.stdout + r.stderr
        except subprocess.TimeoutExpired:
            log(f"  TIMEOUT: {cmd[0]}")
            return False, "timeout"
        except Exception as e:
            return False, str(e)

    def _driver_loaded(self, driver: str) -> bool:
        """Check if driver module is loaded in kernel."""
        try:
            out = subprocess.check_output(["lsmod"], text=True, timeout=5)
            return driver.replace("-", "_") in out
        except Exception:
            return False

    def _driver_installed(self, driver: str) -> bool:
        """Check if driver .ko exists on disk (even if not loaded)."""
        try:
            uname = subprocess.check_output(["uname", "-r"],
                                             text=True, timeout=5).strip()
            mod_dir = f"/lib/modules/{uname}"
            # Search for the module file
            r = subprocess.run(
                ["find", mod_dir, "-name", f"{driver}*", "-name", "*.ko*"],
                capture_output=True, text=True, timeout=10)
            return bool(r.stdout.strip())
        except Exception:
            return False

    def _modprobe(self, driver: str):
        ok, out = self._cmd(["modprobe", driver], timeout=15)
        if not ok:
            log(f"modprobe {driver} failed: {out[:200]}")
            # Try removing conflicting module first, then reload
            self._cmd(["modprobe", "-r", driver], timeout=10, ok_err=True)
            ok, out = self._cmd(["modprobe", driver], timeout=15)
            if not ok:
                log(f"modprobe {driver} retry failed: {out[:200]}")
                return
        log(f"modprobe {driver} OK")
        # Persist across reboots
        conf_file = f"/etc/modules-load.d/rj_{driver}.conf"
        try:
            with open(conf_file, "w") as f:
                f.write(f"{driver}\n")
            log(f"Driver {driver} persisted in {conf_file}")
        except Exception as e:
            log(f"Could not persist driver: {e}")

    def _apt(self, pkgs: list) -> bool:
        ok, _ = self._cmd(
            ["apt-get", "install", "-y", "--no-install-recommends"] + pkgs,
            timeout=300)
        return ok

    def _build_deps(self):
        uname = subprocess.check_output(["uname", "-r"], text=True).strip()
        # Install base build tools first (always available)
        self._apt(["build-essential", "git", "bc", "libelf-dev"])
        # linux-headers: try standard name, then raspberrypi-kernel-headers
        ok = self._apt([f"linux-headers-{uname}"])
        if not ok:
            log(f"linux-headers-{uname} not found, trying raspberrypi-kernel-headers")
            self._apt(["raspberrypi-kernel-headers"])
        # DKMS (may fail on minimal installs, not fatal)
        self._apt(["dkms"])

    def _add_kali_repo(self):
        list_file = "/etc/apt/sources.list.d/kali-rolling.list"
        if os.path.exists(list_file):
            return
        try:
            with open(list_file, "w") as f:
                f.write("deb http://http.kali.org/kali kali-rolling "
                        "main contrib non-free non-free-firmware\n")
            self._cmd([
                "bash", "-c",
                "wget -qO - https://archive.kali.org/archive-key.asc | apt-key add -"
            ], timeout=30, ok_err=True)
            log("Kali rolling repo added")
        except Exception as e:
            log(f"Kali repo error: {e}")

    def _build_github(self, repo_url: str, driver: str) -> bool:
        build_dir = f"/tmp/rj_drv_{driver}"
        self._cmd(["rm", "-rf", build_dir], timeout=10, ok_err=True)
        self._p(40, "git clone...")
        ok, _ = self._cmd(["git", "clone", "--depth=1", repo_url, build_dir],
                          timeout=120)
        if not ok:
            log(f"git clone failed for {repo_url}")
            return False

        # Check if dkms.conf exists before trying DKMS
        dkms_conf = os.path.join(build_dir, "dkms.conf")
        if os.path.isfile(dkms_conf):
            self._p(55, "DKMS install...")
            # Extract version from dkms.conf for proper dkms add
            version = "1.0"
            try:
                with open(dkms_conf) as f:
                    for line in f:
                        if line.strip().startswith("PACKAGE_VERSION"):
                            version = line.split("=")[1].strip().strip('"')
                            break
            except Exception:
                pass
            ok, out = self._cmd(
                ["bash", "-c",
                 f"cd {build_dir} && dkms add . 2>/dev/null; "
                 f"dkms build {driver}/{version} && "
                 f"dkms install {driver}/{version}"],
                timeout=600)
            if ok:
                return True
            log(f"DKMS failed: {out[:300]}")

        # Fallback: make install (works for aircrack-ng repos)
        self._p(60, "make install...")
        ok, out = self._cmd(
            ["bash", "-c",
             f"cd {build_dir} && "
             f"make -j$(nproc) KVER=$(uname -r) 2>&1 | tail -20 && "
             f"make install KVER=$(uname -r)"],
            timeout=600)
        if not ok:
            log(f"make install failed: {out[:300]}")
        return ok

    def _usb_reprobe(self, vid: str, pid: str):
        """Unbind and rebind USB device to trigger kernel auto-probe.

        Uses shell commands with sudo for reliable sysfs writes.
        Falls back to udevadm trigger if direct sysfs fails.
        """
        # Find the USB device path
        target_dev = None
        try:
            for usb_dev in os.listdir("/sys/bus/usb/devices"):
                dev_path = f"/sys/bus/usb/devices/{usb_dev}"
                v = _read_sysfs(os.path.join(dev_path, "idVendor")).lower()
                p = _read_sysfs(os.path.join(dev_path, "idProduct")).lower()
                if v == vid and p == pid:
                    target_dev = usb_dev
                    break
        except Exception as e:
            log(f"USB scan failed: {e}")

        if not target_dev:
            log(f"USB device {vid}:{pid} not found in sysfs")
            # Fallback: trigger udev for all USB
            self._cmd(["udevadm", "trigger", "--subsystem-match=usb"],
                      timeout=10, ok_err=True)
            self._cmd(["udevadm", "settle", "--timeout=5"],
                      timeout=10, ok_err=True)
            return

        log(f"Found USB device: {target_dev}")

        # Method 1: authorize off/on (safest, doesn't need driver info)
        auth_path = f"/sys/bus/usb/devices/{target_dev}/authorized"
        if os.path.exists(auth_path):
            ok1, _ = self._cmd(
                ["bash", "-c", f"echo 0 > {auth_path}"],
                timeout=5, ok_err=True)
            time.sleep(1)
            ok2, _ = self._cmd(
                ["bash", "-c", f"echo 1 > {auth_path}"],
                timeout=5, ok_err=True)
            if ok1 and ok2:
                log(f"USB re-authorized {target_dev}")
                return

        # Method 2: udevadm trigger on this specific device
        self._cmd(
            ["udevadm", "trigger", "--action=change",
             f"--sysname-match={target_dev}"],
            timeout=10, ok_err=True)
        self._cmd(["udevadm", "settle", "--timeout=5"],
                  timeout=10, ok_err=True)
        log(f"udevadm triggered for {target_dev}")

    def _wait_iface(self, vid: str, pid: str, timeout: int = 20) -> str | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            iface = _find_iface_for_vidpid(vid, pid)
            if iface:
                return iface
            time.sleep(1)
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  MONITOR MODE TEST
# ══════════════════════════════════════════════════════════════════════════════

def test_monitor_mode(iface: str) -> bool:
    """Test if interface supports monitor mode.

    Tries iw first (in-kernel drivers), then airmon-ng (out-of-tree
    Realtek drivers like rtl88XXau that don't support iw set type).
    """
    # Method 1: iw set type monitor (works for in-kernel drivers)
    try:
        subprocess.run(["ip", "link", "set", iface, "down"],
                       capture_output=True, timeout=5)
        subprocess.run(["iw", "dev", iface, "set", "type", "monitor"],
                       capture_output=True, timeout=5)
        subprocess.run(["ip", "link", "set", iface, "up"],
                       capture_output=True, timeout=5)
        out = subprocess.check_output(["iw", "dev", iface, "info"],
                                       text=True, timeout=5)
        if "type monitor" in out:
            # Restore managed mode
            subprocess.run(["ip", "link", "set", iface, "down"],
                           capture_output=True, timeout=5)
            subprocess.run(["iw", "dev", iface, "set", "type", "managed"],
                           capture_output=True, timeout=5)
            subprocess.run(["ip", "link", "set", iface, "up"],
                           capture_output=True, timeout=5)
            return True
    except Exception:
        pass

    # Method 2: airmon-ng (works for Realtek out-of-tree drivers)
    try:
        subprocess.run(["ip", "link", "set", iface, "down"],
                       capture_output=True, timeout=5)
        subprocess.run(["ip", "link", "set", iface, "up"],
                       capture_output=True, timeout=5)
        r = subprocess.run(["airmon-ng", "start", iface],
                           capture_output=True, text=True, timeout=15)
        # Check if monitor interface exists
        for mon_name in (f"{iface}mon", iface):
            try:
                out = subprocess.check_output(["iw", "dev", mon_name, "info"],
                                               text=True, timeout=5)
                if "type monitor" in out:
                    # Restore
                    subprocess.run(["airmon-ng", "stop", mon_name],
                                   capture_output=True, timeout=10)
                    subprocess.run(["ip", "link", "set", iface, "up"],
                                   capture_output=True, timeout=5)
                    return True
            except Exception:
                pass
        # Restore in case airmon-ng changed things
        subprocess.run(["airmon-ng", "stop", f"{iface}mon"],
                       capture_output=True, timeout=10)
        subprocess.run(["ip", "link", "set", iface, "up"],
                       capture_output=True, timeout=5)
    except Exception:
        pass

    # Method 3: known driver check (driver is known to support monitor)
    try:
        drv = os.path.basename(
            os.path.realpath(f"/sys/class/net/{iface}/device/driver"))
        known_monitor = {
            "rtl88XXau", "rtl8812au", "rtl8821au", "rtl88x2bu",
            "rtl8188eus", "rtl8187", "rt2800usb", "ath9k_htc",
            "mt76x2u", "mt76x0u", "mt7921u", "rtl8814au",
        }
        if drv in known_monitor:
            log(f"Driver {drv} known to support monitor mode")
            return True
    except Exception:
        pass

    return False


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN PAYLOAD
# ══════════════════════════════════════════════════════════════════════════════

def main():
    log("=== WiFi Installer started ===")

    dongles: list[dict]                     = []
    cursor: int                             = 0
    install_progress: int                   = 0
    install_msg: str                        = ""
    install_thread: threading.Thread | None = None
    install_result: dict                    = {}
    screen: str                             = "list"

    def do_scan():
        nonlocal dongles, cursor
        show([("Scanning USB...", "#00BFFF")], title="WiFi Installer")
        dongles = detect_usb_wifi_dongles()
        cursor  = 0
        log(f"{len(dongles)} dongle(s) detected")

    do_scan()

    def draw_list():
        if not dongles:
            show([
                ("No USB dongle found", "#FF8800"),
                ("", "white"),
                ("Plug in a WiFi", "white"),
                ("adapter, then press", "white"),
                ("KEY2 to rescan", "#00BFFF"),
                ("", "white"),
                ("KEY3 : Exit", "#555555"),
            ], title="WiFi Installer")
            return

        lines = []
        for i, d in enumerate(dongles):
            is_cur = (i == cursor)
            entry  = d.get("db_entry")
            badge  = f"[{d['iface']}]" if d["iface"] else ("[DB]" if entry else "[?]")
            col_b  = "#00FF88" if d["iface"] else ("#00BFFF" if entry else "#FF8800")
            name   = (entry["name"] if entry else d["usb_name"])[:16]
            prefix = ">" if is_cur else " "
            lines.append((f"{prefix}{badge} {d['key']}", col_b if is_cur else "#555555"))
            lines.append((f"  {name}",                   "white" if is_cur else "#444444"))

        lines += [
            ("", "white"),
            ("KEY1:Install  KEY2:Scan", "#333333"),
            ("OK:Details    KEY3:Exit", "#333333"),
        ]
        show(lines, title=f"Dongles ({len(dongles)})")

    def draw_detail(d: dict):
        entry = d.get("db_entry")
        lines = []
        if entry:
            lines.append((entry["name"][:21], "#00BFFF"))
            lines.append((f"Monitor : {'YES' if entry['monitor'] else 'NO'}",
                          "#00FF88" if entry["monitor"] else "#FF3333"))
            lines.append((f"Inject  : {'YES' if entry['injection'] else 'NO'}",
                          "#00FF88" if entry["injection"] else "#FF3333"))
            lines.append((f"Bands   : {', '.join(entry['bands'])}", "white"))
            lines.append((f"Driver  : {entry['driver']}", "white"))
            if entry.get("notes"):
                lines.append((entry["notes"][:21], "#888888"))
        else:
            lines += [
                (d["usb_name"][:21], "#FF8800"),
                ("Not in database", "#FF8800"),
                ("Will attempt auto", "white"),
                ("install anyway", "white"),
            ]
        lines += [
            (f"Iface: {d['iface']}" if d["iface"] else "Not loaded yet",
             "#00FF88" if d["iface"] else "#555555"),
            ("", "white"),
            ("KEY1:Install  KEY3:Back", "#333333"),
        ]
        show(lines, title=f"{d['key']}")

    def draw_installing():
        show([(install_msg[:21], "white")],
             title="Installing...", progress=install_progress)

    def draw_result(d: dict, success: bool, iface: str | None, mon_ok: bool):
        entry = d.get("db_entry") if d else None
        name  = (entry["name"] if entry else d.get("usb_name", "Unknown"))[:18] if d else "Unknown"
        if success:
            lines = [("INSTALLED!", "#00FF88"), (name, "white")]
            if iface:
                lines.append((f"Interface: {iface}", "#00BFFF"))
            lines.append((f"Monitor : {'OK' if mon_ok else 'FAIL'}",
                          "#00FF88" if mon_ok else "#FF8800"))
            lines += [("", "white"), ("KEY3 : Back", "#555555")]
            show(lines, title="Success!", title_col="#00FF88")
        else:
            show([
                ("FAILED", "#FF3333"),
                (name, "white"),
                ("", "white"),
                ("Check logs:", "#888888"),
                (LOG_FILE[-22:], "#444444"),
                ("", "white"),
                ("KEY3 : Back", "#555555"),
            ], title="Install Failed", title_col="#FF3333")

    def start_install(d: dict):
        nonlocal screen, install_progress, install_msg, install_thread
        screen           = "installing"
        install_progress = 0
        install_msg      = "Preparing..."
        install_result.clear()

        def _progress(pct, msg):
            nonlocal install_progress, install_msg
            install_progress = pct
            install_msg      = msg

        def _run():
            inst = Installer(d, progress_cb=_progress)
            inst.run()
            install_result["success"] = inst.success
            install_result["iface"]   = inst.result_iface

        install_thread = threading.Thread(target=_run, daemon=True)
        install_thread.start()
        draw_installing()

    draw_list()
    running = True

    while running:
        btn = get_button(PINS, GPIO)

        if screen == "installing":
            draw_installing()
            if install_thread and not install_thread.is_alive():
                success = install_result.get("success", False)
                iface   = install_result.get("iface")
                mon_ok  = False
                if success and iface:
                    show([("Testing monitor...", "#00BFFF")], title="Checking")
                    time.sleep(0.5)
                    mon_ok = test_monitor_mode(iface)
                screen = "result"
                draw_result(dongles[cursor] if dongles else {}, success, iface, mon_ok)
            time.sleep(0.1)
            continue

        if screen == "result":
            if btn in ("KEY3", "KEY1"):
                do_scan()
                screen = "list"
                draw_list()
            time.sleep(0.05)
            continue

        if screen == "detail":
            if btn == "KEY3":
                screen = "list"
                draw_list()
            elif btn == "KEY1":
                start_install(dongles[cursor])
            time.sleep(0.05)
            continue

        if screen == "list":
            if btn == "KEY3":
                running = False
            elif btn == "KEY2":
                do_scan()
                draw_list()
            elif btn == "UP":
                while get_button(PINS, GPIO) == "UP":
                    time.sleep(0.05)
                if dongles:
                    cursor = (cursor - 1) % len(dongles)
                    draw_list()
            elif btn == "DOWN":
                while get_button(PINS, GPIO) == "DOWN":
                    time.sleep(0.05)
                if dongles:
                    cursor = (cursor + 1) % len(dongles)
                    draw_list()
            elif btn in ("OK", "RIGHT"):
                if dongles:
                    screen = "detail"
                    draw_detail(dongles[cursor])
            elif btn == "KEY1":
                if dongles:
                    start_install(dongles[cursor])

        time.sleep(0.05)

    LCD.LCD_Clear()
    GPIO.cleanup()
    log("=== WiFi Installer exited ===")


if __name__ == "__main__":
    main()