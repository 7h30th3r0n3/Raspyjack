#!/usr/bin/env python3
"""
RaspyJack payload - Wall of Flippers
------------------------------------------------
A RaspyJack-native version of Wall of Flippers
- Live BLE scanning
- Threat summaries, nearby WoF detection, history persistence, settings
- Credits: https://github.com/K3YOMI/Wall-of-Flippers
- Device Port Author: @h0ss310s https://github.com/Hosseios
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Allow imports from RaspyJack root
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

try:
    import RPi.GPIO as GPIO
    import LCD_1in44
    from PIL import Image, ImageDraw, ImageFont

    LCD_AVAILABLE = True
except Exception:
    GPIO = None
    LCD_1in44 = None
    Image = None
    ImageDraw = None
    ImageFont = None
    LCD_AVAILABLE = False

from payloads._input_helper import get_button

try:
    from bleak import BleakScanner
except Exception:
    BleakScanner = None

try:
    from bluepy.btle import Scanner as BluepyScanner
except Exception:
    BluepyScanner = None


PINS = {
    "UP": 6,
    "DOWN": 19,
    "LEFT": 5,
    "RIGHT": 26,
    "OK": 13,
    "KEY1": 21,
    "KEY2": 20,
    "KEY3": 16,
}

WIDTH = 128
HEIGHT = 128
FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
BASE_DIR = os.path.abspath(os.path.join(__file__, "..", ".."))
LOOT_DIR = os.path.join(BASE_DIR, "loot")
WOF_LOOT_DIR = os.path.join(LOOT_DIR, "WOF")
HISTORY_PATH = os.path.join(WOF_LOOT_DIR, "history.json")

FLIPPER_TYPES = {
    "00003081-0000-1000-8000-00805f9b34fb": "B",
    "00003082-0000-1000-8000-00805f9b34fb": "W",
    "00003083-0000-1000-8000-00805f9b34fb": "T",
}
FLIPPER_OUIS = ("80:e1:26", "80:e1:27", "0c:fa:22")

FORBIDDEN_PACKETS = [
    {"PCK": "00001812-0000-1000-8000-00805f9b34fb", "TYPE": "BLE_HUMAN_INTERFACE_DEVICE"},
    {"PCK": "4c000719010_2055_______________", "TYPE": "BLE_APPLE_DEVICE_POPUP_CLOSE"},
    {"PCK": "4c000f05c00____________________", "TYPE": "BLE_APPLE_ACTION_MODAL_LONG"},
    {"PCK": "4c00071907_____________________", "TYPE": "BLE_APPLE_DEVICE_CONNECT"},
    {"PCK": "4c0004042a0000000f05c1__604c950", "TYPE": "BLE_APPLE_DEVICE_SETUP"},
    {"PCK": "2cfe___________________________", "TYPE": "BLE_ANDROID_DEVICE_CONNECT"},
    {"PCK": "750042098102141503210109____01_", "TYPE": "BLE_SAMSUNG_BUDS_POPUP_LONG"},
    {"PCK": "7500010002000101ff000043_______", "TYPE": "BLE_SAMSUNG_WATCH_PAIR_LONG"},
    {"PCK": "0600030080_____________________", "TYPE": "BLE_WINDOWS_SWIFT_PAIR_SHORT"},
    {"PCK": "ff006db643ce97fe427c___________", "TYPE": "BLE_LOVE_TOYS_SHORT_DISTANCE"},
]

WOF_ADVERTISER_RAW = "2c2222222222"
MIN_BYTE_LENGTH = 3
MAX_BYTE_LENGTH = 450
MAX_FLIPPERS_RATELIMITED = 3
RATELIMIT_SECONDS = 5
FLIPPER_UID_PREFIX = "0000308"
FLIPPER_UID_SUFFIX = "0000-1000-8000-00805f9b34fb"


def _available_hci_adapters() -> List[int]:
    if os.name != "posix":
        return [0]
    adapters = []
    try:
        for item in os.listdir("/sys/class/bluetooth/"):
            if item.startswith("hci"):
                try:
                    adapters.append(int(item.replace("hci", "")))
                except Exception:
                    continue
    except Exception:
        pass
    return sorted(adapters) if adapters else [0]


def _match_packet(packet: str, pattern: str) -> bool:
    """
    Match behavior aligned with original WoF:
    - Compare only zipped chars (pattern may be longer)
    - "_" in pattern acts as wildcard
    - Require packet to include at least as many non-wildcard chars as pattern
    """
    if not all((p1 == p2 or p2 == "_") for p1, p2 in zip(packet, pattern)):
        return False
    needed = len(pattern.replace("_", ""))
    found = sum(ch != "_" for ch in packet)
    return found >= needed


def _short(s: str, n: int) -> str:
    s = str(s or "")
    if len(s) <= n:
        return s
    if n <= 1:
        return s[:n]
    return s[: n - 1] + "."


def _mac_tail(mac: str) -> str:
    mac = str(mac or "").upper()
    return mac[-8:] if len(mac) >= 8 else mac


def _age_text(ts: int) -> str:
    diff = max(0, int(time.time()) - int(ts))
    m, s = divmod(diff, 60)
    if m >= 60:
        h, m = divmod(m, 60)
        if h >= 24:
            d, h = divmod(h, 24)
            return f"{d}d{h}h"
        return f"{h}h{m}m"
    return f"{m}m{s}s"


@dataclass
class Settings:
    scan_interval: float = 1.0
    offline_timeout: int = 25
    sort_mode: str = "last_seen"  # last_seen | rssi
    badge_mode: bool = False
    hci_adapter: int = 0


@dataclass
class DeviceRecord:
    name: str
    mac: str
    rssi: int
    dtype: str
    uid: str
    detection: str
    first_seen: int
    last_seen: int


@dataclass
class WoFState:
    devices: Dict[str, DeviceRecord] = field(default_factory=dict)
    packet_total: int = 0
    forbidden_total: int = 0
    forbidden_by_type: Dict[str, int] = field(default_factory=dict)
    nearby_wof: Dict[str, dict] = field(default_factory=dict)
    all_packets: int = 0
    live_count: int = 0
    offline_count: int = 0
    is_ratelimited: bool = False
    last_ratelimit_until: int = 0
    suspicious_dropped: int = 0
    scan_enabled: bool = True
    scanner_backend: str = "init"
    scanner_health: str = "starting"
    last_error: str = ""
    new_events: deque = field(default_factory=lambda: deque(maxlen=40))
    threat_events: deque = field(default_factory=lambda: deque(maxlen=80))
    history_sessions: List[dict] = field(default_factory=list)
    running_since: int = field(default_factory=lambda: int(time.time()))
    selected_live: int = 0
    selected_threat: int = 0
    selected_history: int = 0
    selected_setting: int = 0
    selected_nearby: int = 0
    detail_mac: str = ""
    current_screen: str = "dashboard"

    def live_devices(self) -> List[DeviceRecord]:
        now = int(time.time())
        return [d for d in self.devices.values() if (now - d.last_seen) <= settings.offline_timeout]

    def offline_devices(self) -> List[DeviceRecord]:
        now = int(time.time())
        return [d for d in self.devices.values() if (now - d.last_seen) > settings.offline_timeout]


settings = Settings()
state = WoFState()
running = True
state_lock = threading.Lock()


class ScannerWorker:
    def __init__(self) -> None:
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.new_flipper_times: deque = deque(maxlen=20)
        self.btctl_proc: Optional[subprocess.Popen] = None

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self._btctl_stop_scan()
        if self.thread:
            self.thread.join(timeout=2.0)

    def _run(self) -> None:
        if os.name == "posix" and BluepyScanner is not None:
            with state_lock:
                state.scanner_backend = "bluepy"
                state.scanner_health = "running"
            try:
                self._run_bluepy()
                return
            except Exception as exc:
                with state_lock:
                    state.last_error = f"Bluepy failed: {exc}"
                    state.scanner_health = "degraded"
        if BleakScanner is not None:
            with state_lock:
                state.scanner_backend = "bleak"
                state.scanner_health = "running"
            try:
                asyncio.run(self._run_bleak())
                return
            except Exception as exc:
                with state_lock:
                    state.last_error = f"Bleak failed: {exc}"
                    state.scanner_health = "degraded"
        with state_lock:
            state.scanner_backend = "bluetoothctl"
            state.scanner_health = "running"
        self._run_bluetoothctl()

    async def _run_bleak(self) -> None:
        async def on_detect(device, adv_data) -> None:
            if self.stop_event.is_set():
                return
            if not state.scan_enabled:
                return
            packets = []
            uuids = list(adv_data.service_uuids or [])
            for uid in uuids:
                packets.append(str(uid).lower())
            for company_id, mbytes in (adv_data.manufacturer_data or {}).items():
                try:

                    packets.append(f"{int(company_id):04x}{bytes(mbytes).hex()}".lower())
                except Exception:
                    pass
            for suid, sbytes in (adv_data.service_data or {}).items():
                try:
                    packets.append(str(suid).lower())
                    packets.append(bytes(sbytes).hex().lower())
                except Exception:
                    pass
            self._consume_observation(
                mac=str(device.address or "").lower(),
                name=str(device.name or adv_data.local_name or "Unknown"),
                rssi=int(getattr(device, "rssi", -100)),
                packets=packets,
                from_backend="bleak",
            )

        while not self.stop_event.is_set():
            try:
                scanner = BleakScanner(detection_callback=on_detect)
                async with scanner:
                    t_end = time.monotonic() + max(0.2, settings.scan_interval)
                    while time.monotonic() < t_end and not self.stop_event.is_set():
                        await asyncio.sleep(0.05)
            except Exception as exc:
                with state_lock:
                    state.last_error = f"scan loop: {exc}"
                    state.scanner_health = "retrying"
                await asyncio.sleep(1.0)

    def _run_bluepy(self) -> None:
        adapters = _available_hci_adapters()
        if settings.hci_adapter not in adapters:
            settings.hci_adapter = adapters[0]
            with state_lock:
                state.last_error = f"bluepy: switched to hci{settings.hci_adapter}"
        while not self.stop_event.is_set():
            if not state.scan_enabled:
                time.sleep(0.1)
                continue
            try:
                scanner = BluepyScanner(int(settings.hci_adapter))
                scan_seconds = max(1.0, float(settings.scan_interval))
                devices = scanner.scan(scan_seconds)
                with state_lock:
                    state.scanner_health = "running"
                    if state.last_error.startswith("bluepy:"):
                        state.last_error = ""
                for dev in devices:
                    if self.stop_event.is_set():
                        break
                    packets = []
                    name = "Unknown"
                    for ad_type, desc, value in dev.getScanData():
                        sval = str(value or "").strip()
                        if sval:
                            packets.append(sval.lower())
                        if desc in ("Complete Local Name", "Short Local Name") and sval:
                            name = sval
                    self._consume_observation(
                        mac=str(getattr(dev, "addr", "")).lower(),
                        name=name,
                        rssi=int(getattr(dev, "rssi", -100)),
                        packets=packets,
                        from_backend="bluepy",
                    )
            except Exception as exc:
                err = str(exc)
                # If selected adapter is bad/busy, try another available adapter.
                if "MgmtError" in err or "Failed to execute mgmt cmd" in err:
                    adapters = _available_hci_adapters()
                    if len(adapters) > 1:
                        cur = adapters.index(settings.hci_adapter) if settings.hci_adapter in adapters else 0
                        settings.hci_adapter = adapters[(cur + 1) % len(adapters)]
                        err = f"{err}; retrying hci{settings.hci_adapter}"
                with state_lock:
                    state.last_error = _short(f"bluepy: {err}", 120)
                    state.scanner_health = "retrying"
                time.sleep(1.0)

    def _run_bluetoothctl(self) -> None:
        while not self.stop_event.is_set():
            try:
                if state.scan_enabled:
                    if self.btctl_proc is None:
                        self._btctl_start_scan()
                    elif self.btctl_proc.poll() is not None:
                        # Scanner process exited unexpectedly; recreate it.
                        self.btctl_proc = None
                        self._btctl_start_scan()
                    text = self._btctl_read_devices()
                    if text:
                        with state_lock:
                            if state.scanner_health != "running":
                                state.scanner_health = "running"
                            # Clear stale soft warning when reads recover.
                            if state.last_error.startswith("btctl timeout"):
                                state.last_error = ""
                    for line in text.splitlines():
                        m = re.match(r"^Device\s+([0-9A-Fa-f:]{17})\s*(.*)$", line.strip())
                        if not m:
                            continue
                        mac = m.group(1).lower()
                        name = m.group(2).strip() or "Unknown"
                        self._consume_observation(mac=mac, name=name, rssi=-99, packets=[], from_backend="btctl")
                else:
                    # If user paused scanning, stop discovery immediately.
                    if self.btctl_proc is not None:
                        self._btctl_stop_scan()
            except Exception as exc:
                with state_lock:
                    state.last_error = f"btctl: {exc}"
                    state.scanner_health = "retrying"
                self._btctl_stop_scan()
            time.sleep(max(0.5, settings.scan_interval))
        self._btctl_stop_scan()

    def _btctl_start_scan(self) -> None:
        # Best effort: ensure adapter is up.
        try:
            subprocess.run(
                ["hciconfig", f"hci{int(settings.hci_adapter)}", "up"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=4,
            )
        except Exception:
            pass
        self.btctl_proc = subprocess.Popen(
            ["bluetoothctl"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if self.btctl_proc.stdin:
            self.btctl_proc.stdin.write("scan on\n")
            self.btctl_proc.stdin.flush()
        with state_lock:
            state.scanner_health = "running"

    def _btctl_stop_scan(self) -> None:
        if self.btctl_proc is None:
            return
        try:
            if self.btctl_proc.stdin:
                self.btctl_proc.stdin.write("scan off\n")
                self.btctl_proc.stdin.flush()
        except Exception:
            pass
        try:
            self.btctl_proc.terminate()
            self.btctl_proc.wait(timeout=2)
        except Exception:
            try:
                self.btctl_proc.kill()
            except Exception:
                pass
        self.btctl_proc = None

    def _btctl_read_devices(self) -> str:
        try:
            proc = subprocess.run(
                ["bluetoothctl", "devices"],
                capture_output=True,
                text=True,
                timeout=8,
            )
            return proc.stdout or ""
        except subprocess.TimeoutExpired:
            # Under heavy BLE noise, this call can timeout. Keep scanner alive.
            with state_lock:
                state.last_error = "btctl timeout (high BLE load)"
                if state.scanner_health == "running":
                    state.scanner_health = "degraded"
            return ""

    def _classify_flipper(self, mac: str, name: str, packets: List[str]) -> Tuple[bool, str, str, str]:
        uid = "UNK"
        dtype = "UNK"
        is_flipper = False
        detection = "Unknown"
        key_found = False

        for packet in packets:
            p_low = str(packet).lower()
            if p_low in FLIPPER_TYPES:
                uid = p_low
                dtype = FLIPPER_TYPES[p_low]
                key_found = True
                is_flipper = True
                detection = "Identifier"
                break

        if not key_found:
            for packet in packets:
                p_low = str(packet).lower()
                if p_low.startswith(FLIPPER_UID_PREFIX) and p_low.endswith(FLIPPER_UID_SUFFIX):
                    uid = p_low
                    dtype = "SPF"
                    is_flipper = True
                    detection = "Identifier"
                    break

        if name.lower().startswith("flipper"):
            is_flipper = True
            detection = "Name"
            if uid == "UNK":
                uid = "name-only"
            if dtype == "UNK":
                dtype = "N"
        elif mac.startswith(FLIPPER_OUIS):
            is_flipper = True
            if detection == "Unknown":
                detection = "Address"
            if uid == "UNK":
                uid = "oui-only"
            if dtype == "UNK":
                dtype = "O"
        elif is_flipper and detection == "Unknown":
            detection = "Identifier"

        return is_flipper, uid, dtype, detection

    def _consume_observation(self, mac: str, name: str, rssi: int, packets: List[str], from_backend: str) -> None:
        now = int(time.time())
        mac = (mac or "unknown").lower()
        is_flipper, uid, dtype, detection = self._classify_flipper(mac, name, packets)

        with state_lock:
            state.packet_total += len(packets)
            for packet in packets:
                packet = str(packet).lower()
                if len(packet) > MIN_BYTE_LENGTH:
                    state.all_packets += 1
                if packet.startswith(WOF_ADVERTISER_RAW):
                    try:
                        decoded = bytes.fromhex(packet.replace(WOF_ADVERTISER_RAW, "")).decode("utf-8").replace("\x00", "")
                        decoded = decoded.strip() or "WoF"
                    except Exception:
                        decoded = "WoF"
                    prev = state.nearby_wof.get(decoded, {"count": 0, "last_seen": 0})
                    prev["count"] = int(prev.get("count", 0)) + 1
                    prev["last_seen"] = now
                    state.nearby_wof[decoded] = prev
                for fp in FORBIDDEN_PACKETS:
                    if _match_packet(packet, fp["PCK"]):
                        t = fp["TYPE"]
                        state.forbidden_total += 1
                        state.forbidden_by_type[t] = state.forbidden_by_type.get(t, 0) + 1
                        state.threat_events.appendleft(
                            {"t": now, "type": t, "mac": mac, "pkt": _short(packet, 24)}
                        )
                if len(packet) > MAX_BYTE_LENGTH:
                    t = "SUSPICIOUS_PACKET"
                    state.forbidden_total += 1
                    state.forbidden_by_type[t] = state.forbidden_by_type.get(t, 0) + 1
                    state.threat_events.appendleft(
                        {"t": now, "type": t, "mac": mac, "pkt": _short(packet, 24)}
                    )

            if is_flipper:
                is_new = mac not in state.devices
                if is_new:
                    self.new_flipper_times.append(now)
                    recent_new = [t for t in self.new_flipper_times if now - t <= RATELIMIT_SECONDS]
                    if len(recent_new) >= MAX_FLIPPERS_RATELIMITED:
                        state.is_ratelimited = True
                        state.last_ratelimit_until = now + RATELIMIT_SECONDS
                if state.is_ratelimited and is_new:
                    state.suspicious_dropped += 1
                else:
                    if mac in state.devices:
                        rec = state.devices[mac]
                        rec.last_seen = now
                        rec.rssi = rssi
                        if name and rec.name in ("Unknown", "UNK"):
                            rec.name = name
                    else:
                        state.devices[mac] = DeviceRecord(
                            name=name or "Unknown",
                            mac=mac,
                            rssi=rssi,
                            dtype=dtype,
                            uid=uid,
                            detection=detection,
                            first_seen=now,
                            last_seen=now,
                        )
                    state.new_events.appendleft(
                        {
                            "t": now,
                            "name": name or "Unknown",
                            "mac": mac,
                            "det": detection,
                            "dtype": dtype,
                            "backend": from_backend,
                        }
                    )
            if state.is_ratelimited and now >= state.last_ratelimit_until:
                state.is_ratelimited = False


class Ui:
    def __init__(self) -> None:
        self.lcd = None
        self.font_small = None
        self.font_med = None
        self.font_big = None
        self._last_console = ""
        if LCD_AVAILABLE:
            self.lcd = LCD_1in44.LCD()
            self.lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
            self.font_small = self._load_font(8)
            self.font_med = self._load_font(10)
            self.font_big = self._load_font(11, bold=True)

    def _load_font(self, size: int, bold: bool = False):
        try:
            return ImageFont.truetype(FONT_BOLD if bold else FONT_PATH, size)
        except Exception:
            return ImageFont.load_default()

    def draw(self) -> None:
        if self.lcd is None:
            self._draw_console()
            return
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ImageDraw.Draw(img)
        with state_lock:
            screen = state.current_screen
            live = state.live_devices()
            offline = state.offline_devices()
            state.live_count = len(live)
            state.offline_count = len(offline)

            if screen == "dashboard":
                self._screen_dashboard(d, live, offline)
            elif screen == "live":
                self._screen_live(d, live, offline)
            elif screen == "detail":
                self._screen_detail(d)
            elif screen == "threats":
                self._screen_threats(d)
            elif screen == "nearby":
                self._screen_nearby(d)
            elif screen == "history":
                self._screen_history(d)
            elif screen == "settings":
                self._screen_settings(d)
            else:
                self._screen_dashboard(d, live, offline)
        self.lcd.LCD_ShowImage(img, 0, 0)

    def _header(self, d, title: str, status: str = "") -> None:
        d.rectangle((0, 0, WIDTH, 13), fill="#09324A")
        d.text((2, 2), _short(title, 13), font=self.font_med, fill="#D6F4FF")
        if status:
            badge_color = "#1F5E24"
            if "PAUSE" in status:
                badge_color = "#4C4C1E"
            elif "ERR" in status:
                badge_color = "#6B2424"
            d.rectangle((86, 1, 127, 12), fill=badge_color)
            d.text((89, 2), _short(status, 7), font=self.font_small, fill="#E8F8E8")

    def _footer(self, d, txt: str) -> None:
        d.rectangle((0, HEIGHT - 11, WIDTH, HEIGHT), fill="#111111")
        limit = 18 if settings.badge_mode else 26
        d.text((1, HEIGHT - 10), _short(txt, limit), font=self.font_small, fill="#A0A0A0")

    def _screen_dashboard(self, d, live: List[DeviceRecord], offline: List[DeviceRecord]) -> None:
        self._header(d, "WallOfFlippers", "RUN" if state.scan_enabled else "PAUSE")
        d.text((3, 16), f"L:{len(live)}", font=self.font_med, fill="#00FF7F")
        d.text((42, 16), f"O:{len(offline)}", font=self.font_med, fill="#D0D0D0")
        d.text((82, 16), f"T:{state.forbidden_total}", font=self.font_med, fill="#FFA66B")
        d.text((3, 30), f"N:{len(state.nearby_wof)}", font=self.font_med, fill="#6FDBFF")
        d.text((42, 30), f"P:{state.all_packets}", font=self.font_med, fill="#A9A9A9")
        backend = state.scanner_backend
        d.text((3, 44), f"Backend:{_short(backend, 6)} h{settings.hci_adapter}", font=self.font_small, fill="#A9A9A9")
        if state.is_ratelimited:
            ttl = max(0, state.last_ratelimit_until - int(time.time()))
            d.text((3, 55), f"Ratelimit {ttl}s", font=self.font_small, fill="#FF6666")
        elif state.last_error:
            d.text((3, 55), _short(state.last_error, 22), font=self.font_small, fill="#FF9999")

        if state.new_events:
            e = state.new_events[0]
            d.text((3, 70), _short(e["name"], 19), font=self.font_small, fill="#FFFFFF")
            d.text((3, 80), _short(f"{_mac_tail(e['mac'])} {e['det']}", 22), font=self.font_small, fill="#7FD9FF")
            d.text((3, 92), _short(f"Last: {_age_text(int(e['t']))}", 19), font=self.font_small, fill="#98BCCA")
        else:
            d.text((3, 74), "No flippers yet", font=self.font_small, fill="#909090")
        d.text((74, 92), _short(f"Up {_age_text(state.running_since)}", 10), font=self.font_small, fill="#7E97A4")
        self._footer(d, "L/R view  K1 scan  K3 exit")

    def _sorted_live(self, live: List[DeviceRecord]) -> List[DeviceRecord]:
        if settings.sort_mode == "rssi":
            return sorted(live, key=lambda x: x.rssi, reverse=True)
        return sorted(live, key=lambda x: x.last_seen, reverse=True)

    def _screen_live(self, d, live: List[DeviceRecord], offline: List[DeviceRecord]) -> None:
        self._header(d, "Live Devices", f"{len(live)}")
        merged = self._sorted_live(live) + sorted(offline, key=lambda x: x.last_seen, reverse=True)
        if not merged:
            d.text((4, 34), "No devices", font=self.font_med, fill="#BBBBBB")
            self._footer(d, "L/R view  K1 scan  K3 exit")
            return
        state.selected_live = max(0, min(state.selected_live, len(merged) - 1))
        start = (state.selected_live // 6) * 6
        rows = merged[start : start + 6]
        y = 16
        now = int(time.time())
        total_pages = max(1, (len(merged) + 5) // 6)
        cur_page = (state.selected_live // 6) + 1
        d.text((97, 2), f"{cur_page}/{total_pages}", font=self.font_small, fill="#A9C9DA")
        for idx, rec in enumerate(rows):
            gi = start + idx
            sel = gi == state.selected_live
            if sel:
                d.rectangle((0, y - 1, WIDTH, y + 10), fill="#1A2B3A")
            is_live = (now - rec.last_seen) <= settings.offline_timeout
            status = rec.rssi if is_live else "off"
            flag = "L" if is_live else "O"
            caret = ">" if sel else " "
            left = f"{caret}{flag} {_short(rec.name.replace('Flipper ', ''), 8)}"
            right = f"{str(status):>4} {_short(_mac_tail(rec.mac), 8)}"
            d.text((2, y), left, font=self.font_small, fill="#FFFFFF" if sel else "#D6D6D6")
            d.text((58, y), _short(right, 13), font=self.font_small, fill="#9FD3FF")
            y += 11
        self._footer(d, "OK detail  UP/DN select")

    def _screen_detail(self, d) -> None:
        self._header(d, "Device Detail")
        rec = state.devices.get(state.detail_mac)
        if rec is None:
            d.text((4, 32), "No device selected", font=self.font_small, fill="#A8A8A8")
            self._footer(d, "LEFT back")
            return
        d.text((2, 16), _short(rec.name, 20), font=self.font_med, fill="#FFFFFF")
        d.text((2, 28), _short(rec.mac.upper(), 20), font=self.font_small, fill="#88CCFF")
        d.text((2, 40), f"RSSI:{rec.rssi} Type:{rec.dtype}", font=self.font_small, fill="#CFCFCF")
        d.text((2, 52), f"Det:{_short(rec.detection, 15)}", font=self.font_small, fill="#CFCFCF")
        d.text((2, 64), f"UID:{_short(rec.uid, 18)}", font=self.font_small, fill="#A7E2FF")
        d.text((2, 78), f"First:{_age_text(rec.first_seen)}", font=self.font_small, fill="#CFCFCF")
        d.text((2, 90), f"Last:{_age_text(rec.last_seen)}", font=self.font_small, fill="#CFCFCF")
        self._footer(d, "LEFT back  K3 exit")

    def _screen_threats(self, d) -> None:
        self._header(d, "Threats", f"{state.forbidden_total}")
        if state.scanner_backend == "bluetoothctl":
            d.text((4, 20), "Backend: btctl", font=self.font_small, fill="#FFB3B3")
            d.text((4, 30), "Packet signatures", font=self.font_small, fill="#FFB3B3")
            d.text((4, 40), "limited on btctl.", font=self.font_small, fill="#FFB3B3")
            d.text((4, 52), "Use bluepy/bleak", font=self.font_small, fill="#CFCFCF")
            d.text((4, 62), "for threat parity.", font=self.font_small, fill="#CFCFCF")
        items = sorted(state.forbidden_by_type.items(), key=lambda kv: kv[1], reverse=True)
        if not items:
            d.text((4, 78), "No threats", font=self.font_med, fill="#A8A8A8")
            d.text((4, 92), "detected", font=self.font_med, fill="#A8A8A8")
            self._footer(d, "K2 clear  L/R view")
            return
        state.selected_threat = max(0, min(state.selected_threat, len(items) - 1))
        start = (state.selected_threat // 6) * 6
        y = 16
        total_pages = max(1, (len(items) + 5) // 6)
        cur_page = (state.selected_threat // 6) + 1
        d.text((97, 2), f"{cur_page}/{total_pages}", font=self.font_small, fill="#DDAFAF")
        for idx, (tt, cnt) in enumerate(items[start : start + 6]):
            gi = start + idx
            sel = gi == state.selected_threat
            if sel:
                d.rectangle((0, y - 1, WIDTH, y + 10), fill="#3A2020")
            caret = ">" if sel else " "
            d.text((2, y), _short(f"{caret}{tt.replace('BLE_', '')}", 13), font=self.font_small, fill="#FFD7C0")
            d.text((102, y), str(cnt).rjust(3), font=self.font_small, fill="#FF8C8C")
            y += 11
        # Show details for the selected threat type (latest matching event).
        sel_type = items[state.selected_threat][0]
        ev = None
        for x in state.threat_events:
            if x.get("type") == sel_type:
                ev = x
                break
        if ev:
            d.text((2, 84), _short(f"{_mac_tail(ev.get('mac', ''))}", 21), font=self.font_small, fill="#A8A8A8")
            d.text((2, 95), _short(f"{_age_text(int(ev.get('t', 0)))} {ev.get('pkt', '')}", 22), font=self.font_small, fill="#A8A8A8")
        self._footer(d, "UP/DN select  K2 clear")

    def _screen_nearby(self, d) -> None:
        self._header(d, "Nearby WoF", f"{len(state.nearby_wof)}")
        items = sorted(
            state.nearby_wof.items(),
            key=lambda kv: int(kv[1].get("count", 0)),
            reverse=True,
        )
        if not items:
            d.text((4, 40), "No nearby WoF", font=self.font_med, fill="#A8A8A8")
            self._footer(d, "L/R view")
            return
        state.selected_nearby = max(0, min(state.selected_nearby, len(items) - 1))
        start = (state.selected_nearby // 7) * 7
        y = 16
        total_pages = max(1, (len(items) + 6) // 7)
        cur_page = (state.selected_nearby // 7) + 1
        d.text((97, 2), f"{cur_page}/{total_pages}", font=self.font_small, fill="#A9D3E8")
        for idx, (name, meta) in enumerate(items[start : start + 7]):
            gi = start + idx
            sel = gi == state.selected_nearby
            if sel:
                d.rectangle((0, y - 1, WIDTH, y + 10), fill="#143040")
            caret = ">" if sel else " "
            d.text((2, y), _short(f"{caret}{name}", 13), font=self.font_small, fill="#BDEEFF")
            d.text((89, y), str(meta.get("count", 0)).rjust(3), font=self.font_small, fill="#80D5FF")
            d.text((110, y), _short(_age_text(int(meta.get("last_seen", 0))), 5), font=self.font_small, fill="#7ABBDD")
            y += 11
        self._footer(d, "UP/DN select  L/R view")

    def _screen_history(self, d) -> None:
        self._header(d, "History", f"{len(state.history_sessions)}")
        if not state.history_sessions:
            d.text((5, 38), "No sessions", font=self.font_med, fill="#A8A8A8")
            self._footer(d, "K2 save now  L/R view")
            return
        state.selected_history = max(0, min(state.selected_history, len(state.history_sessions) - 1))
        start = (state.selected_history // 5) * 5
        y = 16
        sessions = list(reversed(state.history_sessions))
        total_pages = max(1, (len(sessions) + 4) // 5)
        cur_page = (state.selected_history // 5) + 1
        d.text((97, 2), f"{cur_page}/{total_pages}", font=self.font_small, fill="#B8B8B8")
        for idx, sess in enumerate(sessions[start : start + 5]):
            gi = start + idx
            sel = gi == state.selected_history
            if sel:
                d.rectangle((0, y - 1, WIDTH, y + 12), fill="#262626")
            caret = ">" if sel else " "
            line1 = f"{caret}{_short(sess.get('ts', ''), 9)} L{sess.get('live', 0)} T{sess.get('threats', 0)}"
            line2 = f"N{sess.get('nearby', 0)} P{sess.get('packets', 0)} {_short(sess.get('backend', ''), 4)}"
            d.text((2, y), _short(line1, 21), font=self.font_small, fill="#D8D8D8")
            d.text((2, y + 8), _short(line2, 21), font=self.font_small, fill="#A8A8A8")
            y += 20
        # Show extra context for the selected history row.
        selected_sess = sessions[state.selected_history] if sessions else {}
        if selected_sess.get("latest"):
            d.text((2, 104), _short(f"E {selected_sess.get('latest')}", 22), font=self.font_small, fill="#9FC3D1")
        elif selected_sess.get("top_threat"):
            d.text((2, 104), _short(f"T {selected_sess.get('top_threat')}", 22), font=self.font_small, fill="#D1B79F")
        self._footer(d, "K2 snapshot  L/R view")

    def _screen_settings(self, d) -> None:
        self._header(d, "Settings")
        items = [
            f"Scan: {settings.scan_interval:.1f}s",
            f"Offline: {settings.offline_timeout}s",
            f"Sort: {settings.sort_mode}",
            f"Badge: {'on' if settings.badge_mode else 'off'}",
            f"HCI: hci{settings.hci_adapter}",
        ]
        state.selected_setting = max(0, min(state.selected_setting, len(items) - 1))
        y = 18
        for i, txt in enumerate(items):
            sel = i == state.selected_setting
            if sel:
                d.rectangle((0, y - 1, WIDTH, y + 10), fill="#1D3021")
            d.text((2, y), _short(txt, 21), font=self.font_small, fill="#D6FFD9")
            y += 12
        d.text((2, 86), f"Health: {_short(state.scanner_health, 12)}", font=self.font_small, fill="#A8A8A8")
        d.text((2, 96), f"Dropped: {state.suspicious_dropped}", font=self.font_small, fill="#A8A8A8")
        if state.last_error:
            d.text((2, 106), _short(state.last_error, 22), font=self.font_small, fill="#FF9E9E")
        self._footer(d, "OK edit  K2 save  L/R view")

    def _draw_console(self) -> None:
        with state_lock:
            s = (
                f"WoF {state.current_screen} "
                f"scan={'on' if state.scan_enabled else 'off'} "
                f"live={state.live_count} off={state.offline_count} "
                f"threat={state.forbidden_total}"
            )
        if s != self._last_console:
            print(s)
            self._last_console = s


def _now_stamp() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def load_history() -> None:
    os.makedirs(WOF_LOOT_DIR, exist_ok=True)
    try:
        with open(HISTORY_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            state.history_sessions = list(data.get("sessions", []))[-40:]
            saved = data.get("settings", {})
            settings.scan_interval = float(saved.get("scan_interval", settings.scan_interval))
            settings.offline_timeout = int(saved.get("offline_timeout", settings.offline_timeout))
            settings.sort_mode = str(saved.get("sort_mode", settings.sort_mode))
            settings.badge_mode = bool(saved.get("badge_mode", settings.badge_mode))
            settings.hci_adapter = int(saved.get("hci_adapter", settings.hci_adapter))
            # Restore archived devices so users keep historical visibility between runs.
            devices = data.get("devices", [])
            if isinstance(devices, list):
                restored: Dict[str, DeviceRecord] = {}
                for row in devices:
                    try:
                        mac = str(row.get("mac", "")).lower()
                        if not mac:
                            continue
                        restored[mac] = DeviceRecord(
                            name=str(row.get("name", "Unknown")),
                            mac=mac,
                            rssi=int(row.get("rssi", -100)),
                            dtype=str(row.get("dtype", "UNK")),
                            uid=str(row.get("uid", "UNK")),
                            detection=str(row.get("detection", "Unknown")),
                            first_seen=int(row.get("first_seen", int(time.time()))),
                            last_seen=int(row.get("last_seen", int(time.time()))),
                        )
                    except Exception:
                        continue
                if restored:
                    state.devices.update(restored)
            # Backward compatibility: nearby values used to be plain counts.
            legacy_nearby = data.get("nearby_wof", {})
            if isinstance(legacy_nearby, dict):
                converted = {}
                now = int(time.time())
                for k, v in legacy_nearby.items():
                    if isinstance(v, dict):
                        converted[str(k)] = {
                            "count": int(v.get("count", 0)),
                            "last_seen": int(v.get("last_seen", now)),
                        }
                    else:
                        converted[str(k)] = {"count": int(v), "last_seen": now}
                state.nearby_wof = converted
            state.forbidden_total = int(data.get("forbidden_total", state.forbidden_total))
            state.forbidden_by_type = dict(data.get("forbidden_by_type", state.forbidden_by_type))
            state.suspicious_dropped = int(data.get("suspicious_dropped", state.suspicious_dropped))
    except Exception:
        pass


def save_history_snapshot() -> None:
    os.makedirs(WOF_LOOT_DIR, exist_ok=True)
    with state_lock:
        sess = {
            "ts": _now_stamp(),
            "live": len(state.live_devices()),
            "offline": len(state.offline_devices()),
            "threats": state.forbidden_total,
            "nearby": len(state.nearby_wof),
            "packets": state.all_packets,
            "backend": state.scanner_backend,
        }
        if state.new_events:
            latest = state.new_events[0]
            sess["latest"] = f"{latest.get('name', 'Unknown')}@{latest.get('mac', '')[-5:]}"
        top_threat = sorted(state.forbidden_by_type.items(), key=lambda kv: kv[1], reverse=True)
        if top_threat:
            sess["top_threat"] = f"{top_threat[0][0]}:{top_threat[0][1]}"
        state.history_sessions.append(sess)
        state.history_sessions = state.history_sessions[-40:]
        device_archive = []
        for rec in sorted(state.devices.values(), key=lambda x: x.last_seen, reverse=True)[:300]:
            device_archive.append(
                {
                    "name": rec.name,
                    "mac": rec.mac,
                    "rssi": rec.rssi,
                    "dtype": rec.dtype,
                    "uid": rec.uid,
                    "detection": rec.detection,
                    "first_seen": rec.first_seen,
                    "last_seen": rec.last_seen,
                }
            )
        payload = {
            "schema_version": 2,
            "saved_at": _now_stamp(),
            "sessions": state.history_sessions,
            "settings": {
                "scan_interval": settings.scan_interval,
                "offline_timeout": settings.offline_timeout,
                "sort_mode": settings.sort_mode,
                "badge_mode": settings.badge_mode,
                "hci_adapter": settings.hci_adapter,
            },
            "devices": device_archive,
            "nearby_wof": state.nearby_wof,
            "forbidden_total": state.forbidden_total,
            "forbidden_by_type": state.forbidden_by_type,
            "suspicious_dropped": state.suspicious_dropped,
        }
    try:
        with open(HISTORY_PATH, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
    except Exception:
        pass


def _signal_handler(_signum, _frame) -> None:
    global running
    running = False


def _handle_button(btn: str) -> None:
    if not btn:
        return
    request_snapshot = False
    handled = False
    with state_lock:
        if btn == "KEY3":
            if state.current_screen == "detail":
                state.current_screen = "live"
                return
            global running
            running = False
            return
        if btn == "KEY1":
            state.scan_enabled = not state.scan_enabled
            return
        if btn == "LEFT":
            if state.current_screen == "detail":
                state.current_screen = "live"
                return
            order = ["dashboard", "live", "threats", "nearby", "history", "settings"]
            i = order.index(state.current_screen) if state.current_screen in order else 0
            state.current_screen = order[(i - 1) % len(order)]
            return
        if btn == "RIGHT":
            if state.current_screen == "detail":
                return
            order = ["dashboard", "live", "threats", "nearby", "history", "settings"]
            i = order.index(state.current_screen) if state.current_screen in order else 0
            state.current_screen = order[(i + 1) % len(order)]
            return

        if btn == "KEY2":
            handled = True
            if state.current_screen == "threats":
                state.forbidden_total = 0
                state.forbidden_by_type = {}
                state.suspicious_dropped = 0
                state.threat_events.clear()
            elif state.current_screen == "dashboard":
                state.nearby_wof = {}
                state.new_events.clear()
            else:
                request_snapshot = True
        
        if handled:
            # KEY2 actions should not fall through to navigation handlers.
            pass

        elif state.current_screen == "live":
            total = len(state.live_devices()) + len(state.offline_devices())
            if btn == "UP":
                state.selected_live = max(0, state.selected_live - 1)
            elif btn == "DOWN":
                state.selected_live = min(max(0, total - 1), state.selected_live + 1)
            elif btn == "OK" and total > 0:
                merged = (
                    sorted(state.live_devices(), key=lambda x: x.last_seen, reverse=True)
                    + sorted(state.offline_devices(), key=lambda x: x.last_seen, reverse=True)
                )
                state.detail_mac = merged[state.selected_live].mac
                state.current_screen = "detail"
        elif state.current_screen == "threats":
            total = len(state.forbidden_by_type)
            if btn == "UP":
                state.selected_threat = max(0, state.selected_threat - 1)
            elif btn == "DOWN":
                state.selected_threat = min(max(0, total - 1), state.selected_threat + 1)
        elif state.current_screen == "nearby":
            total = len(state.nearby_wof)
            if btn == "UP":
                state.selected_nearby = max(0, state.selected_nearby - 1)
            elif btn == "DOWN":
                state.selected_nearby = min(max(0, total - 1), state.selected_nearby + 1)
        elif state.current_screen == "history":
            total = len(state.history_sessions)
            if btn == "UP":
                state.selected_history = max(0, state.selected_history - 1)
            elif btn == "DOWN":
                state.selected_history = min(max(0, total - 1), state.selected_history + 1)
        elif state.current_screen == "settings":
            options = 5
            if btn == "UP":
                state.selected_setting = max(0, state.selected_setting - 1)
            elif btn == "DOWN":
                state.selected_setting = min(options - 1, state.selected_setting + 1)
            elif btn == "OK":
                idx = state.selected_setting
                if idx == 0:
                    vals = [0.5, 1.0, 1.5, 2.0]
                    cur = vals.index(settings.scan_interval) if settings.scan_interval in vals else 1
                    settings.scan_interval = vals[(cur + 1) % len(vals)]
                elif idx == 1:
                    vals = [15, 25, 40, 60]
                    cur = vals.index(settings.offline_timeout) if settings.offline_timeout in vals else 1
                    settings.offline_timeout = vals[(cur + 1) % len(vals)]
                elif idx == 2:
                    settings.sort_mode = "rssi" if settings.sort_mode == "last_seen" else "last_seen"
                elif idx == 3:
                    settings.badge_mode = not settings.badge_mode
                elif idx == 4:
                    settings.hci_adapter = (settings.hci_adapter + 1) % 4
                request_snapshot = True
    if request_snapshot:
        save_history_snapshot()


def _setup_gpio() -> None:
    if GPIO is None:
        return
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)


def _cleanup(ui: Ui, scanner: ScannerWorker) -> None:
    scanner.stop()
    save_history_snapshot()
    if ui.lcd is not None:
        try:
            ui.lcd.LCD_Clear()
        except Exception:
            pass
    if GPIO is not None:
        try:
            GPIO.cleanup()
        except Exception:
            pass


def main() -> None:
    global running
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    load_history()
    _setup_gpio()
    ui = Ui()
    scanner = ScannerWorker()
    scanner.start()

    frame_sleep = 0.1 if settings.badge_mode else 0.08
    last_btn = None
    last_btn_t = 0.0
    last_snapshot_t = time.monotonic()

    try:
        while running:
            btn = get_button(PINS, GPIO) if GPIO is not None else None
            now = time.time()
            if btn:
                if btn != last_btn or (now - last_btn_t) > 0.15:
                    _handle_button(btn)
                    last_btn = btn
                    last_btn_t = now
            else:
                last_btn = None
            ui.draw()
            frame_sleep = 0.13 if settings.badge_mode else 0.08
            # Periodic snapshot keeps history meaningful across long sessions.
            if time.monotonic() - last_snapshot_t >= 60.0:
                save_history_snapshot()
                last_snapshot_t = time.monotonic()
            time.sleep(frame_sleep)
    finally:
        _cleanup(ui, scanner)


if __name__ == "__main__":
    main()

