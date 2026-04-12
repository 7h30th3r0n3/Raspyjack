#!/usr/bin/env python3
"""
RaspyJack Payload -- Smart Glasses Detector
============================================
Author: 7h30th3r0n3

Continuous BLE surveillance to detect smart glasses (Meta Ray-Ban,
Snap Spectacles, etc.) via manufacturer Company IDs and service UUIDs.
Full-screen FLASH alert on detection.

Based on research from:
  - Nearby Glasses (BLE Company ID detection)
  - Ban-Rays (IR + BLE fingerprinting)

Setup / Prerequisites
---------------------
- Bluetooth adapter (hci0 or USB)
- bleak (preferred) or bluepy for BLE scanning

Controls
--------
  OK          -- Start / stop scanning
  LEFT/RIGHT  -- Navigate screens (monitor / list / detail)
  UP / DOWN   -- Scroll device list
  KEY1        -- Toggle sort (RSSI / last_seen / brand)
  KEY2        -- Export JSON to loot
  KEY3        -- Exit (or back from sub-screen)

Loot: /root/Raspyjack/loot/GlassesDetect/
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

try:
    import RPi.GPIO as GPIO
    import LCD_1in44
    from PIL import Image, ImageFont
    from payloads._display_helper import ScaledDraw, scaled_font

    LCD_AVAILABLE = True
except Exception:
    GPIO = None
    LCD_1in44 = None
    Image = None
    ImageFont = None
    LCD_AVAILABLE = False

from payloads._input_helper import get_button
from payloads._iface_helper import select_bt_interface

try:
    from bleak import BleakScanner
except Exception:
    BleakScanner = None

try:
    from bluepy.btle import Scanner as BluepyScanner
except Exception:
    BluepyScanner = None

# ── Pin / LCD setup ──────────────────────────────────────────────────────────
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}

WIDTH = LCD_1in44.LCD_WIDTH if LCD_1in44 else 128
HEIGHT = LCD_1in44.LCD_HEIGHT if LCD_1in44 else 128
FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
LOOT_DIR = "/root/Raspyjack/loot/GlassesDetect"

# ── Smart Glasses BLE Identifiers ────────────────────────────────────────────

GLASSES_COMPANY_IDS = {
    0x01AB: ("Meta Platforms", "Meta Glasses"),
    0x058E: ("Meta Platforms Tech", "Meta Glasses"),
    0x0D53: ("Luxottica", "Ray-Ban Meta"),
    0x03C2: ("Snapchat", "Spectacles"),
}

GLASSES_SERVICE_UUIDS = {
    "0000fd5f-0000-1000-8000-00805f9b34fb": ("Meta", "Meta Glasses"),
}

# Known name prefixes for smart glasses
GLASSES_NAME_PREFIXES = (
    "ray-ban", "meta", "spectacles", "snap ",
    "stories", "wayfarer",
)

SORT_MODES = ["rssi", "last_seen", "brand"]
SCREENS = ["monitor", "list", "detail"]
OFFLINE_TIMEOUT = 30  # seconds before device considered offline
FLASH_CYCLES = 5
FLASH_DURATION_MS = 200


# ── RSSI to distance estimation ─────────────────────────────────────────────

def estimate_distance(rssi: int) -> str:
    if rssi >= -50:
        return "< 1m"
    if rssi >= -60:
        return "1-3m"
    if rssi >= -70:
        return "3-10m"
    if rssi >= -75:
        return "10-15m"
    if rssi >= -80:
        return "15-20m"
    return "> 20m"


def _short(s: str, n: int) -> str:
    s = str(s or "")
    if len(s) <= n:
        return s
    return s[: n - 1] + "." if n > 1 else s[:n]


def _age_text(ts: int) -> str:
    diff = max(0, int(time.time()) - int(ts))
    m, s = divmod(diff, 60)
    if m >= 60:
        h, m = divmod(m, 60)
        return f"{h}h{m}m"
    return f"{m}m{s}s"


# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class GlassesRecord:
    mac: str
    name: str
    brand: str
    model: str
    rssi: int
    company_id: int
    detection_method: str  # "company_id", "service_uuid", "name"
    first_seen: int
    last_seen: int
    seen_count: int = 1

    @property
    def distance(self) -> str:
        return estimate_distance(self.rssi)

    @property
    def is_live(self) -> bool:
        return (int(time.time()) - self.last_seen) <= OFFLINE_TIMEOUT


@dataclass
class GlassesState:
    glasses: Dict[str, GlassesRecord] = field(default_factory=dict)
    scan_enabled: bool = True
    total_ble_devices: int = 0
    scanner_backend: str = "init"
    scanner_health: str = "starting"
    last_error: str = ""
    current_screen: str = "monitor"
    selected_idx: int = 0
    scroll_pos: int = 0
    sort_mode: str = "rssi"
    alert_pending: bool = False
    alert_brand: str = ""
    alert_distance: str = ""
    events: deque = field(default_factory=lambda: deque(maxlen=50))
    running_since: int = field(default_factory=lambda: int(time.time()))

    def live_glasses(self) -> List[GlassesRecord]:
        return [g for g in self.glasses.values() if g.is_live]

    def all_sorted(self, mode: str) -> List[GlassesRecord]:
        items = list(self.glasses.values())
        if mode == "rssi":
            return sorted(items, key=lambda g: g.rssi, reverse=True)
        if mode == "last_seen":
            return sorted(items, key=lambda g: g.last_seen, reverse=True)
        return sorted(items, key=lambda g: g.brand.lower())


state = GlassesState()
state_lock = threading.RLock()
running = True


# ── Scanner Worker ───────────────────────────────────────────────────────────

class ScannerWorker:
    """BLE scanner that detects smart glasses via Company IDs and Service UUIDs."""

    def __init__(self) -> None:
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=3.0)

    def _run(self) -> None:
        # Try bleak first (preferred, async)
        if BleakScanner is not None:
            with state_lock:
                state.scanner_backend = "bleak"
                state.scanner_health = "running"
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(self._run_bleak())
                return
            except Exception as exc:
                with state_lock:
                    state.last_error = f"Bleak: {str(exc)[:30]}"
                    state.scanner_health = "degraded"

        # Fallback to bluetoothctl (always available, no library needed)
        with state_lock:
            state.scanner_backend = "bluetoothctl"
            state.scanner_health = "running"
        self._run_bluetoothctl()

    async def _run_bleak(self) -> None:
        async def on_detect(device, adv_data) -> None:
            if self.stop_event.is_set() or not state.scan_enabled:
                return
            mac = str(device.address or "").lower()
            name = str(device.name or getattr(adv_data, "local_name", None) or "Unknown")
            rssi = int(getattr(adv_data, "rssi", None) or getattr(device, "rssi", -100))

            with state_lock:
                state.total_ble_devices += 1

            # Check manufacturer data for known Company IDs
            for company_id, mbytes in (adv_data.manufacturer_data or {}).items():
                if company_id in GLASSES_COMPANY_IDS:
                    brand, model = GLASSES_COMPANY_IDS[company_id]
                    self._record_glasses(mac, name, brand, model, rssi, company_id, "company_id")
                    return

            # Check service UUIDs
            for uid in (adv_data.service_uuids or []):
                uid_lower = str(uid).lower()
                if uid_lower in GLASSES_SERVICE_UUIDS:
                    brand, model = GLASSES_SERVICE_UUIDS[uid_lower]
                    self._record_glasses(mac, name, brand, model, rssi, 0, "service_uuid")
                    return

            # Check device name
            name_lower = name.lower()
            for prefix in GLASSES_NAME_PREFIXES:
                if name_lower.startswith(prefix):
                    self._record_glasses(mac, name, "Unknown", name, rssi, 0, "name")
                    return

        while not self.stop_event.is_set():
            try:
                scanner = BleakScanner(detection_callback=on_detect)
                async with scanner:
                    t_end = time.monotonic() + 2.0
                    while time.monotonic() < t_end and not self.stop_event.is_set():
                        await asyncio.sleep(0.05)
            except Exception as exc:
                with state_lock:
                    state.last_error = f"scan: {_short(str(exc), 30)}"
                    state.scanner_health = "retrying"
                await asyncio.sleep(1.0)

    def _run_bluepy(self) -> None:
        while not self.stop_event.is_set():
            if not state.scan_enabled:
                time.sleep(0.2)
                continue
            try:
                scanner = BluepyScanner()
                devices = scanner.scan(2.0)
                with state_lock:
                    state.scanner_health = "running"
                for dev in devices:
                    if self.stop_event.is_set():
                        break
                    with state_lock:
                        state.total_ble_devices += 1
                    name = "Unknown"
                    for ad_type, desc, value in dev.getScanData():
                        sval = str(value or "").strip()
                        if desc in ("Complete Local Name", "Short Local Name") and sval:
                            name = sval
                        # Check manufacturer specific data (ad_type 0xFF)
                        if ad_type == 0xFF and len(sval) >= 4:
                            try:
                                raw = bytes.fromhex(sval)
                                if len(raw) >= 2:
                                    cid = int.from_bytes(raw[:2], "little")
                                    if cid in GLASSES_COMPANY_IDS:
                                        brand, model = GLASSES_COMPANY_IDS[cid]
                                        mac = str(getattr(dev, "addr", "")).lower()
                                        rssi = int(getattr(dev, "rssi", -100))
                                        self._record_glasses(mac, name, brand, model, rssi, cid, "company_id")
                            except (ValueError, TypeError):
                                pass
                    # Also check by name
                    name_lower = name.lower()
                    for prefix in GLASSES_NAME_PREFIXES:
                        if name_lower.startswith(prefix):
                            mac = str(getattr(dev, "addr", "")).lower()
                            rssi = int(getattr(dev, "rssi", -100))
                            self._record_glasses(mac, name, "Unknown", name, rssi, 0, "name")
                            break
            except Exception as exc:
                with state_lock:
                    state.last_error = f"bluepy: {_short(str(exc), 30)}"
                    state.scanner_health = "retrying"
                time.sleep(1.0)

    def _run_bluetoothctl(self) -> None:
        """Fallback: use bluetoothctl for basic scanning (no Company ID info)."""
        btctl_proc = None
        try:
            subprocess.run(["hciconfig", "hci0", "up"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
        except Exception:
            pass

        while not self.stop_event.is_set():
            if not state.scan_enabled:
                time.sleep(0.2)
                continue
            try:
                if btctl_proc is None:
                    btctl_proc = subprocess.Popen(
                        ["bluetoothctl"], stdin=subprocess.PIPE,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True,
                    )
                    if btctl_proc.stdin:
                        btctl_proc.stdin.write("scan on\n")
                        btctl_proc.stdin.flush()

                proc = subprocess.run(
                    ["bluetoothctl", "devices"],
                    capture_output=True, text=True, timeout=8,
                )
                for line in (proc.stdout or "").splitlines():
                    parts = line.strip().split(None, 2)
                    if len(parts) >= 3 and parts[0] == "Device":
                        name = parts[2]
                        name_lower = name.lower()
                        for prefix in GLASSES_NAME_PREFIXES:
                            if name_lower.startswith(prefix):
                                mac = parts[1].lower()
                                self._record_glasses(mac, name, "Unknown", name, -99, 0, "name")
                                break
                        with state_lock:
                            state.total_ble_devices += 1
                with state_lock:
                    state.scanner_health = "running"
            except Exception as exc:
                with state_lock:
                    state.last_error = f"btctl: {_short(str(exc), 30)}"
                    state.scanner_health = "retrying"
            time.sleep(2.0)

        # Cleanup
        if btctl_proc:
            try:
                if btctl_proc.stdin:
                    btctl_proc.stdin.write("scan off\n")
                    btctl_proc.stdin.flush()
                btctl_proc.terminate()
                btctl_proc.wait(timeout=2)
            except Exception:
                try:
                    btctl_proc.kill()
                except Exception:
                    pass

    def _record_glasses(self, mac: str, name: str, brand: str, model: str,
                        rssi: int, company_id: int, method: str) -> None:
        now = int(time.time())
        with state_lock:
            if mac in state.glasses:
                rec = state.glasses[mac]
                rec.last_seen = now
                rec.rssi = rssi
                rec.seen_count += 1
                if name != "Unknown" and rec.name == "Unknown":
                    rec.name = name
                if brand != "Unknown" and rec.brand == "Unknown":
                    rec.brand = brand
            else:
                state.glasses[mac] = GlassesRecord(
                    mac=mac, name=name, brand=brand, model=model,
                    rssi=rssi, company_id=company_id,
                    detection_method=method,
                    first_seen=now, last_seen=now,
                )
                # Trigger alert for NEW glasses
                state.alert_pending = True
                state.alert_brand = brand
                state.alert_distance = estimate_distance(rssi)

            state.events.appendleft({
                "t": now, "mac": mac, "brand": brand,
                "model": model, "rssi": rssi, "method": method,
            })


# ── UI ───────────────────────────────────────────────────────────────────────

class Ui:
    def __init__(self) -> None:
        self.lcd = None
        self.font_small = None
        self.font_med = None
        self.font_big = None
        if LCD_AVAILABLE:
            self.lcd = LCD_1in44.LCD()
            self.lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
            _s = getattr(LCD_1in44, "LCD_SCALE", 1.0)
            self.font_small = self._load_font(int(8 * _s))
            self.font_med = self._load_font(int(10 * _s))
            self.font_big = self._load_font(int(12 * _s), bold=True)

    def _load_font(self, size: int, bold: bool = False):
        try:
            return ImageFont.truetype(FONT_BOLD if bold else FONT_PATH, size)
        except Exception:
            return scaled_font()

    def flash_alert(self, brand: str, distance: str) -> None:
        """Full-screen RED/YELLOW flash alert when glasses are detected."""
        if self.lcd is None:
            return
        for i in range(FLASH_CYCLES):
            # RED flash
            img = Image.new("RGB", (WIDTH, HEIGHT), "#FF0000")
            d = ScaledDraw(img)
            d.text((10, 30), "!! ALERT !!", font=self.font_big, fill="#FFFFFF")
            d.text((6, 55), "GLASSES DETECTED", font=self.font_med, fill="#FFFF00")
            d.text((10, 75), f"{_short(brand, 18)}", font=self.font_med, fill="#FFFFFF")
            d.text((10, 92), f"Distance: {distance}", font=self.font_small, fill="#FFFFFF")
            self.lcd.LCD_ShowImage(img, 0, 0)
            time.sleep(FLASH_DURATION_MS / 1000.0)

            # YELLOW flash
            img = Image.new("RGB", (WIDTH, HEIGHT), "#FFAA00")
            d = ScaledDraw(img)
            d.text((10, 30), "!! ALERT !!", font=self.font_big, fill="#000000")
            d.text((6, 55), "GLASSES DETECTED", font=self.font_med, fill="#CC0000")
            d.text((10, 75), f"{_short(brand, 18)}", font=self.font_med, fill="#000000")
            d.text((10, 92), f"Distance: {distance}", font=self.font_small, fill="#000000")
            self.lcd.LCD_ShowImage(img, 0, 0)
            time.sleep(FLASH_DURATION_MS / 1000.0)

    def draw(self) -> None:
        if self.lcd is None:
            return
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)

        with state_lock:
            screen = state.current_screen
            if screen == "monitor":
                self._screen_monitor(d)
            elif screen == "list":
                self._screen_list(d)
            elif screen == "detail":
                self._screen_detail(d)
            else:
                self._screen_monitor(d)

        self.lcd.LCD_ShowImage(img, 0, 0)

    def _header(self, d, title: str) -> None:
        with state_lock:
            scan_on = state.scan_enabled
            health = state.scanner_health
        d.rectangle((0, 0, 127, 13), fill="#1A0A2E")
        d.text((2, 2), _short(title, 15), font=self.font_med, fill="#FF6B6B")
        color = "#00FF00" if scan_on and health == "running" else "#FF0000"
        d.ellipse((118, 3, 126, 11), fill=color)

    def _footer(self, d, txt: str) -> None:
        d.rectangle((0, 117, 127, 127), fill="#111111")
        d.text((1, 118), _short(txt, 26), font=self.font_small, fill="#A0A0A0")

    def _screen_monitor(self, d) -> None:
        self._header(d, "GLASSES DETECT")

        live = state.live_glasses()
        total = len(state.glasses)
        scanned = state.total_ble_devices
        backend = state.scanner_backend

        # Stats line
        y = 16
        d.text((3, y), f"Live: {len(live)}", font=self.font_med,
               fill="#FF4444" if live else "#00FF7F")
        d.text((60, y), f"Total: {total}", font=self.font_med, fill="#CCCCCC")
        y += 14

        d.text((3, y), f"Scanned: {scanned}", font=self.font_small, fill="#888888")
        d.text((75, y), backend[:8], font=self.font_small, fill="#888888")
        y += 12

        # Separator
        d.line([(0, y), (127, y)], fill="#333333")
        y += 4

        if live:
            # Show most recent / closest glasses
            closest = max(live, key=lambda g: g.rssi)
            d.rectangle((2, y - 1, 125, y + 35), fill="#330000", outline="#FF4444")
            y += 2
            d.text((5, y), f"{_short(closest.brand, 10)} {_short(closest.model, 10)}",
                   font=self.font_med, fill="#FF6666")
            y += 13
            d.text((5, y), f"RSSI: {closest.rssi}dBm  {closest.distance}",
                   font=self.font_small, fill="#FFAA00")
            y += 11
            d.text((5, y), f"MAC: {closest.mac[-8:]}", font=self.font_small, fill="#888888")
        elif state.events:
            # Show last event
            evt = state.events[0]
            age = _age_text(evt["t"])
            d.text((3, y), "Last seen:", font=self.font_small, fill="#666666")
            y += 12
            d.text((3, y), f"{_short(evt['brand'], 12)} {evt['rssi']}dBm",
                   font=self.font_med, fill="#888888")
            y += 13
            d.text((3, y), f"{age} ago", font=self.font_small, fill="#555555")
        else:
            d.text((3, y + 8), "No glasses detected", font=self.font_med, fill="#555555")
            d.text((3, y + 24), "Scanning...", font=self.font_small, fill="#333333")

        # Error
        if state.last_error:
            d.text((3, 104), _short(state.last_error, 24), font=self.font_small, fill="#FF4444")

        # Uptime
        d.text((85, 106), f"Up {_age_text(state.running_since)}",
               font=self.font_small, fill="#555555")

        lbl = "OK:Stop" if state.scan_enabled else "OK:Scan"
        self._footer(d, f"{lbl} R:List K3:Exit")

    def _screen_list(self, d) -> None:
        self._header(d, "DETECTED LIST")

        glasses_list = state.all_sorted(state.sort_mode)
        total = len(glasses_list)

        if not glasses_list:
            d.text((4, 40), "No glasses found", font=self.font_med, fill="#888888")
            self._footer(d, "L:Monitor K3:Exit")
            return

        state.selected_idx = max(0, min(state.selected_idx, total - 1))

        # Sort indicator
        d.text((2, 15), f"Sort:{state.sort_mode} ({total})",
               font=self.font_small, fill="#888888")

        # List
        rows_visible = 6
        start = (state.selected_idx // rows_visible) * rows_visible
        y = 27
        now = int(time.time())

        for i in range(start, min(start + rows_visible, total)):
            rec = glasses_list[i]
            sel = i == state.selected_idx
            is_live = rec.is_live

            if sel:
                d.rectangle((0, y - 1, 127, y + 12), fill="#1A2B3A")

            status_dot = "#00FF00" if is_live else "#666666"
            d.ellipse((2, y + 3, 6, y + 7), fill=status_dot)

            brand_txt = _short(rec.brand, 8)
            rssi_txt = f"{rec.rssi}dB"
            dist_txt = _short(rec.distance, 6)

            color = "#FFFFFF" if sel else "#CCCCCC"
            d.text((9, y), brand_txt, font=self.font_small, fill=color)
            d.text((58, y), rssi_txt, font=self.font_small, fill="#FFAA00")
            d.text((92, y), dist_txt, font=self.font_small, fill="#88CCFF")
            y += 14

        # Page indicator
        total_pages = max(1, (total + rows_visible - 1) // rows_visible)
        cur_page = (state.selected_idx // rows_visible) + 1
        d.text((100, 15), f"{cur_page}/{total_pages}", font=self.font_small, fill="#666666")

        self._footer(d, "OK:Detail K1:Sort K2:Export")

    def _screen_detail(self, d) -> None:
        self._header(d, "DEVICE DETAIL")

        glasses_list = state.all_sorted(state.sort_mode)
        if not glasses_list or state.selected_idx >= len(glasses_list):
            d.text((4, 40), "No device selected", font=self.font_small, fill="#888888")
            self._footer(d, "L:Back")
            return

        rec = glasses_list[state.selected_idx]
        y = 18

        d.text((3, y), f"Brand: {_short(rec.brand, 16)}", font=self.font_med, fill="#FF6666")
        y += 14
        d.text((3, y), f"Model: {_short(rec.model, 16)}", font=self.font_small, fill="#CCCCCC")
        y += 12
        d.text((3, y), f"MAC: {rec.mac}", font=self.font_small, fill="#88CCFF")
        y += 12
        d.text((3, y), f"RSSI: {rec.rssi}dBm", font=self.font_small, fill="#FFAA00")
        d.text((70, y), rec.distance, font=self.font_small, fill="#FFAA00")
        y += 12
        d.text((3, y), f"Method: {rec.detection_method}", font=self.font_small, fill="#888888")
        y += 12

        if rec.company_id:
            d.text((3, y), f"CID: 0x{rec.company_id:04X}", font=self.font_small, fill="#888888")
            y += 12

        d.text((3, y), f"First: {_age_text(rec.first_seen)} ago",
               font=self.font_small, fill="#666666")
        y += 12
        d.text((3, y), f"Last:  {_age_text(rec.last_seen)} ago",
               font=self.font_small, fill="#666666")
        y += 12
        d.text((3, y), f"Seen: {rec.seen_count}x", font=self.font_small, fill="#666666")

        status = "LIVE" if rec.is_live else "OFFLINE"
        color = "#00FF00" if rec.is_live else "#FF4444"
        d.text((80, y), status, font=self.font_small, fill=color)

        self._footer(d, "LEFT:Back K3:Exit")


# ── Export ───────────────────────────────────────────────────────────────────

def export_json() -> str:
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"glasses_{ts}.json")
    with state_lock:
        data = {
            "timestamp": ts,
            "total_ble_scanned": state.total_ble_devices,
            "glasses": [
                {
                    "mac": g.mac,
                    "name": g.name,
                    "brand": g.brand,
                    "model": g.model,
                    "rssi": g.rssi,
                    "distance": g.distance,
                    "company_id": f"0x{g.company_id:04X}" if g.company_id else None,
                    "detection_method": g.detection_method,
                    "first_seen": g.first_seen,
                    "last_seen": g.last_seen,
                    "seen_count": g.seen_count,
                }
                for g in state.glasses.values()
            ],
        }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    global running

    if LCD_AVAILABLE:
        GPIO.setmode(GPIO.BCM)
        for pin in PINS.values():
            GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    ui = Ui()

    # Select BT adapter
    if ui.lcd:
        hci_dev = select_bt_interface(ui.lcd, ui.font_med, PINS, GPIO)
        if not hci_dev:
            GPIO.cleanup()
            return 1

    # Splash screen
    if ui.lcd:
        img = Image.new("RGB", (WIDTH, HEIGHT), "#0A0A1A")
        d = ScaledDraw(img)
        d.text((8, 8), "SMART GLASSES", font=ui.font_big, fill="#FF4444")
        d.text((14, 24), "DETECTOR", font=ui.font_big, fill="#FF6666")
        d.text((4, 48), "Detects nearby smart", font=ui.font_small, fill="#888888")
        d.text((4, 60), "glasses via BLE scan", font=ui.font_small, fill="#888888")
        d.text((4, 78), "Meta Ray-Ban", font=ui.font_small, fill="#FFAA00")
        d.text((4, 90), "Snap Spectacles", font=ui.font_small, fill="#FFAA00")
        d.text((4, 108), "OK=Start  K3=Exit", font=ui.font_small, fill="#555555")
        ui.lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(1.5)

    # Ensure BT adapter is up
    subprocess.run(["hciconfig", "hci0", "up"], capture_output=True, timeout=5)
    time.sleep(0.5)

    # Start scanner
    scanner = ScannerWorker()
    scanner.start()

    try:
        while running:
            # Check for pending alert
            with state_lock:
                if state.alert_pending:
                    brand = state.alert_brand
                    distance = state.alert_distance
                    state.alert_pending = False
                else:
                    brand = None

            if brand:
                ui.flash_alert(brand, distance)

            # Handle input
            if LCD_AVAILABLE:
                btn = get_button(PINS, GPIO)
            else:
                btn = None

            with state_lock:
                screen = state.current_screen

            if btn == "KEY3":
                if screen in ("list", "detail"):
                    with state_lock:
                        state.current_screen = "monitor"
                    time.sleep(0.2)
                else:
                    break

            elif btn == "OK":
                with state_lock:
                    state.scan_enabled = not state.scan_enabled
                time.sleep(0.3)

            elif btn == "RIGHT":
                with state_lock:
                    if state.current_screen == "monitor":
                        state.current_screen = "list"
                    elif state.current_screen == "list":
                        # Go to detail if items exist
                        if state.glasses:
                            state.current_screen = "detail"
                time.sleep(0.2)

            elif btn == "LEFT":
                with state_lock:
                    if state.current_screen == "detail":
                        state.current_screen = "list"
                    elif state.current_screen == "list":
                        state.current_screen = "monitor"
                time.sleep(0.2)

            elif btn == "UP":
                with state_lock:
                    if state.current_screen in ("list", "detail"):
                        state.selected_idx = max(0, state.selected_idx - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                with state_lock:
                    if state.current_screen in ("list", "detail"):
                        max_idx = max(0, len(state.glasses) - 1)
                        state.selected_idx = min(max_idx, state.selected_idx + 1)
                time.sleep(0.15)

            elif btn == "KEY1":
                with state_lock:
                    idx = SORT_MODES.index(state.sort_mode)
                    state.sort_mode = SORT_MODES[(idx + 1) % len(SORT_MODES)]
                time.sleep(0.25)

            elif btn == "KEY2":
                export_json()
                time.sleep(0.3)

            ui.draw()
            time.sleep(0.05)

    finally:
        scanner.stop()
        if ui.lcd:
            try:
                ui.lcd.LCD_Clear()
            except Exception:
                pass
        if LCD_AVAILABLE:
            GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
