#!/usr/bin/env python3
"""
RaspyJack Payload -- Kismet Scanner
=====================================
Author: 7h30th3r0n3

Multi-protocol wireless scanner using Kismet as backend.
LCD shows detected devices (WiFi, BT, BLE, etc.) with live stats.
Full WebUI available via RaspyJack WebUI → Kismet.

Controls:
  UP/DOWN     Scroll device list
  OK          Toggle scan start/stop
  KEY1        Cycle views (Devices / WiFi / BT / Stats)
  KEY2        Export/save session
  KEY3        Exit (daemon keeps running)
  LEFT/RIGHT  Change sort (RSSI / Last seen / Type)
"""

import os
import sys
import time
import signal
import subprocess
import json
import shutil
import urllib.request
import urllib.error

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for p in PINS.values():
    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
W, H = LCD.width, LCD.height

FONT = scaled_font(9)
FONT_SM = scaled_font(7)
FONT_LG = scaled_font(12)

C_BG = "#000000"
C_CYAN = "#00E5FF"
C_GREEN = "#00FF00"
C_RED = "#FF4444"
C_ORANGE = "#FF8C00"
C_WHITE = "#FFFFFF"
C_DIM = "#666666"
C_DARK = "#111111"
C_SEL = "#003366"
C_PURPLE = "#C084FC"
C_BLUE = "#3B82F6"

DEBOUNCE = 0.18
_running = True

KISMET_URL = "http://127.0.0.1:2501"
KISMET_API_KEY = ""
LOOT_DIR = "/root/Raspyjack/loot/kismet"
KISMET_LOG_DIR = "/root/Raspyjack/loot/kismet/logs"

VIEWS = ["All", "WiFi", "BT/BLE", "Stats"]
SORTS = ["signal", "last", "type"]
SORT_LABELS = ["RSSI", "Recent", "Type"]

TYPE_COLORS = {
    "Wi-Fi AP": C_CYAN,
    "Wi-Fi Client": C_BLUE,
    "Wi-Fi Ad-Hoc": C_ORANGE,
    "Bluetooth": C_PURPLE,
    "BTLE": C_GREEN,
    "Other": C_DIM,
}


def _sig_handler(sig, frame):
    global _running
    _running = False

signal.signal(signal.SIGINT, _sig_handler)
signal.signal(signal.SIGTERM, _sig_handler)


def _show(img):
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_msg(line1, line2="", color=C_CYAN):
    img = Image.new("RGB", (W, H), C_BG)
    d = ScaledDraw(img)
    d.text((64, 50), line1, font=FONT, fill=color, anchor="mm")
    if line2:
        d.text((64, 68), line2, font=FONT_SM, fill=C_DIM, anchor="mm")
    _show(img)


def _install_kismet():
    try:
        subprocess.run(
            ["bash", "-c",
             'wget -O - https://www.kismetwireless.net/repos/kismet-release.gpg.key --quiet | gpg --dearmor | tee /usr/share/keyrings/kismet-archive-keyring.gpg >/dev/null && '
             'echo "deb [signed-by=/usr/share/keyrings/kismet-archive-keyring.gpg] https://www.kismetwireless.net/repos/apt/release/trixie trixie main" > /etc/apt/sources.list.d/kismet.list && '
             'apt-get update -qq && apt-get install -y kismet'],
            capture_output=True, timeout=300)
        return shutil.which("kismet") is not None
    except Exception:
        return False


def _ensure_kismet():
    if not shutil.which("kismet"):
        _draw_msg("Installing", "kismet...", C_ORANGE)
        if not _install_kismet():
            _draw_msg("Install failed", "kismet not found", C_RED)
            time.sleep(3)
            return False

    try:
        subprocess.run(["pgrep", "-x", "kismet"], capture_output=True, check=True)
        return True
    except subprocess.CalledProcessError:
        pass

    os.makedirs(KISMET_LOG_DIR, exist_ok=True)

    conf_path = "/etc/kismet/kismet_raspyjack.conf"
    if not os.path.isfile(conf_path):
        os.makedirs("/etc/kismet", exist_ok=True)
        with open(conf_path, "w") as f:
            f.write(f"httpd_bind_address=127.0.0.1\nhttpd_port=2501\nlog_prefix={KISMET_LOG_DIR}\n")

    _draw_msg("Starting", "kismet daemon...")
    cmd = [
        "kismet", "--no-ncurses",
        "--override", "raspyjack",
        "--daemonize",
    ]
    try:
        subprocess.run(cmd, capture_output=True, timeout=10)
        time.sleep(4)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _api(endpoint, method="GET", data=None):
    url = f"{KISMET_URL}{endpoint}"
    headers = {"Content-Type": "application/json"}
    if KISMET_API_KEY:
        headers["KISMET"] = KISMET_API_KEY
    body = json.dumps(data).encode() if data else None
    try:
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def _get_status():
    return _api("/system/status.json")


def _get_devices(view="All", limit=50):
    fields = [
        "kismet.device.base.macaddr",
        "kismet.device.base.name",
        "kismet.device.base.type",
        "kismet.device.base.signal/kismet.common.signal.last_signal",
        "kismet.device.base.last_time",
        "kismet.device.base.packets.total",
        "kismet.device.base.manuf",
        "kismet.device.base.channel",
        "kismet.device.base.crypt",
    ]
    body = {
        "fields": fields,
    }
    if view == "WiFi":
        body["regex"] = [["kismet.device.base.phyname", "IEEE802.11"]]
    elif view == "BT/BLE":
        body["regex"] = [["kismet.device.base.phyname", "Bluetooth|BTLE"]]

    resp = _api("/devices/last-time/-300/devices.json", method="POST", data=body)
    if not resp:
        return []

    devices = []
    for d in resp:
        base = d.get("kismet.device.base.macaddr", "??:??:??")
        name = d.get("kismet.device.base.name", "")
        dtype = d.get("kismet.device.base.type", "Other")
        signal_data = d.get("kismet.device.base.signal", {})
        if isinstance(signal_data, dict):
            signal = signal_data.get("kismet.common.signal.last_signal", 0)
        else:
            signal = 0
        last_time = d.get("kismet.device.base.last_time", 0)
        packets = d.get("kismet.device.base.packets.total", 0)
        manuf = d.get("kismet.device.base.manuf", "")
        channel = d.get("kismet.device.base.channel", "")
        crypt = d.get("kismet.device.base.crypt", "")
        label = name if name and name != base else manuf if manuf else base
        devices.append({
            "mac": base,
            "name": label,
            "type": dtype,
            "signal": signal,
            "last": last_time,
            "packets": packets,
            "channel": channel,
            "crypt": crypt,
        })
    return devices[:limit]


def _sort_devices(devices, sort_key):
    if sort_key == "signal":
        return sorted(devices, key=lambda d: d["signal"], reverse=False)
    if sort_key == "last":
        return sorted(devices, key=lambda d: d["last"], reverse=True)
    if sort_key == "type":
        return sorted(devices, key=lambda d: d["type"])
    return devices


def _type_color(dtype):
    for key, color in TYPE_COLORS.items():
        if key.lower() in dtype.lower():
            return color
    return C_DIM


def _draw_ui(devices, cursor, view_idx, sort_idx, status):
    img = Image.new("RGB", (W, H), C_BG)
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#0a0a1a")
    view_label = VIEWS[view_idx]
    sort_label = SORT_LABELS[sort_idx]
    dev_count = len(devices)

    if status:
        mem_mb = status.get("kismet.system.memory.rss", 0) // 1024
        d.text((2, 1), f"Kismet [{view_label}]", font=FONT_SM, fill=C_CYAN)
        d.text((95, 1), f"{dev_count}d", font=FONT_SM, fill=C_GREEN)
    else:
        d.text((2, 1), "Kismet [offline]", font=FONT_SM, fill=C_RED)

    d.rectangle((0, 13, 127, 21), fill="#050510")
    d.text((2, 13), f"Sort:{sort_label}", font=FONT_SM, fill=C_DIM)
    if status:
        pkt = status.get("kismet.system.packets.rate", 0)
        d.text((80, 13), f"{pkt}pkt/s", font=FONT_SM, fill=C_DIM)

    if not devices:
        d.text((64, 65), "No devices", font=FONT, fill=C_DIM, anchor="mm")
        d.text((64, 82), "OK:Start scan", font=FONT_SM, fill=C_DIM, anchor="mm")
    else:
        y_start = 23
        row_h = 19
        vis = (116 - y_start) // row_h
        scroll = max(0, min(cursor - vis // 2, max(0, len(devices) - vis)))

        for i in range(scroll, min(scroll + vis, len(devices))):
            dev = devices[i]
            y = y_start + (i - scroll) * row_h
            is_sel = i == cursor

            if is_sel:
                d.rectangle((0, y, 127, y + row_h - 1), fill=C_SEL)

            tc = _type_color(dev["type"])
            d.rectangle((2, y + 2, 4, y + row_h - 3), fill=tc)

            name = dev["name"][:16]
            d.text((7, y), name, font=FONT_SM, fill=C_WHITE if is_sel else C_DIM)

            sig = dev["signal"]
            if sig != 0:
                sig_str = f"{sig}dB"
                sig_color = C_GREEN if sig > -50 else C_ORANGE if sig > -70 else C_RED
                d.text((100, y), sig_str, font=FONT_SM, fill=sig_color)

            info = dev["type"][:10]
            ch = dev["channel"]
            if ch:
                info = f"ch{ch}"
            d.text((7, y + 9), info, font=FONT_SM, fill=tc)

    d.rectangle((0, 117, 127, 127), fill="#0a0a1a")
    d.text((2, 118), "K1:View K2:Save <>:Sort K3:Exit", font=FONT_SM, fill=C_DIM)

    _show(img)


def main():
    if not _ensure_kismet():
        GPIO.cleanup()
        return 1

    _draw_msg("Connected", "to kismet")
    time.sleep(0.5)

    cursor = 0
    view_idx = 0
    sort_idx = 0
    last_btn = 0
    last_refresh = 0
    devices = []
    status = None

    while _running:
        now = time.time()

        if now - last_refresh > 3:
            last_refresh = now
            status = _get_status()
            raw_devices = _get_devices(VIEWS[view_idx])
            devices = _sort_devices(raw_devices, SORTS[sort_idx])
            if cursor >= len(devices):
                cursor = max(0, len(devices) - 1)

        _draw_ui(devices, cursor, view_idx, sort_idx, status)

        btn = get_button(PINS, GPIO)

        if btn == "KEY3":
            break

        if btn == "UP" and now - last_btn > DEBOUNCE:
            last_btn = now
            if devices:
                cursor = (cursor - 1) % len(devices)

        if btn == "DOWN" and now - last_btn > DEBOUNCE:
            last_btn = now
            if devices:
                cursor = (cursor + 1) % len(devices)

        if btn == "LEFT" and now - last_btn > DEBOUNCE:
            last_btn = now
            sort_idx = (sort_idx - 1) % len(SORTS)
            last_refresh = 0

        if btn == "RIGHT" and now - last_btn > DEBOUNCE:
            last_btn = now
            sort_idx = (sort_idx + 1) % len(SORTS)
            last_refresh = 0

        if btn == "KEY1" and now - last_btn > 0.3:
            last_btn = now
            view_idx = (view_idx + 1) % len(VIEWS)
            cursor = 0
            last_refresh = 0

        if btn == "OK" and now - last_btn > 0.3:
            last_btn = now
            datasources = _api("/datasource/all_sources.json")
            if datasources:
                active = any(
                    ds.get("kismet.datasource.running", False)
                    for ds in datasources
                )
                if active:
                    for ds in datasources:
                        uuid = ds.get("kismet.datasource.uuid", "")
                        if uuid:
                            _api(f"/datasource/by-uuid/{uuid}/close_source.cmd",
                                 method="POST", data={})
                    _draw_msg("Scan stopped", "", C_ORANGE)
                else:
                    for ds in datasources:
                        uuid = ds.get("kismet.datasource.uuid", "")
                        if uuid:
                            _api(f"/datasource/by-uuid/{uuid}/open_source.cmd",
                                 method="POST", data={})
                    _draw_msg("Scanning...", "", C_GREEN)
                time.sleep(0.5)
                last_refresh = 0

        if btn == "KEY2" and now - last_btn > 0.3:
            last_btn = now
            os.makedirs(LOOT_DIR, exist_ok=True)
            ts = time.strftime("%Y%m%d_%H%M%S")
            path = os.path.join(LOOT_DIR, f"kismet_export_{ts}.json")
            try:
                with open(path, "w") as f:
                    json.dump(devices, f, indent=2)
                _draw_msg("Exported!", os.path.basename(path), C_GREEN)
            except Exception:
                _draw_msg("Export failed", "", C_RED)
            time.sleep(1)

        time.sleep(0.05)

    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
