#!/usr/bin/env python3
"""
RaspyJack Payload – Device Scout
==================================
Wireless device scanner combining Bluetooth and WiFi detection with
anti-surveillance capabilities.  Discovers nearby devices and ranks
by persistence to identify trackers following you.

Views (cycle with LEFT / RIGHT):
  DEVICES – All detected devices sorted by persistence
  ALERTS  – Flagged potential trackers only
  STATS   – Dashboard with scan duration, counts, top threat

Controls:
  LEFT / RIGHT – Cycle view
  UP / DOWN    – Scroll device list
  KEY1         – Start / Stop scan
  KEY2         – Exit
  KEY3         – Export data to loot/DeviceScout/

Author: dag nazty
"""

import os
import sys
import csv
import json
import time
import struct
import socket
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

import RPi.GPIO as GPIO                          # type: ignore
import LCD_1in44, LCD_Config                      # type: ignore
from PIL import Image, ImageDraw, ImageFont       # type: ignore
from payloads._input_helper import get_button

# Scapy (optional – WiFi capture won't work without it)
try:
    from scapy.all import Dot11, Dot11Elt, Dot11Beacon  # type: ignore
    from scapy.all import Dot11ProbeReq, Dot11ProbeResp  # type: ignore
    from scapy.all import sniff as scapy_sniff            # type: ignore
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# BLE HCI socket constants
AF_BT   = getattr(socket, "AF_BLUETOOTH", 31)
BT_HCI  = getattr(socket, "BTPROTO_HCI", 1)
SOL_HCI = getattr(socket, "SOL_HCI", 0)
HCI_FLT = getattr(socket, "HCI_FILTER", 2)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
W, H = 128, 128

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}

VIEWS = ["DEVICES", "ALERTS", "STATS"]

CH24 = list(range(1, 14))
CH5  = [36, 40, 44, 48, 52, 56, 60, 64,
        100, 104, 108, 112, 116, 120, 124, 128,
        132, 136, 140, 149, 153, 157, 161, 165]
CHALL = CH24 + CH5

# Known tracker company IDs (from BLE Manufacturer Specific Data, AD type 0xFF)
TRACKER_COMPANY = {
    0x004C: "AirTag",       # Apple (AirTag / Find My)
    0xFFFE: "Tile",         # Tile Inc.
    0x0075: "SmartTag",     # Samsung
}

import os
paths = [
    "/root/Raspyjack/loot/DeviceScout",
    "/root/raspyjack/loot/DeviceScout"
]

LOOT_DIR = next((p for p in paths if os.path.exists(os.path.dirname(p))), paths[0])

os.makedirs(LOOT_DIR, exist_ok=True)

# Persistence tuning
PERSIST_MIN_OBS  = 60      # seconds before scoring begins
PERSIST_ALERT_TH = 0.70    # score threshold for alert
PERSIST_ALERT_DUR = 300    # must be observed 5 min before score-alert

# Display
ROWS_VISIBLE = 7           # device rows that fit on LCD
ROW_H        = 12          # pixel height per row

# ---------------------------------------------------------------------------
# Mutable global state  (threads share via `lock`)
# ---------------------------------------------------------------------------
running   = False
view_idx  = 0
scroll    = 0              # list scroll offset
cur_ch    = 1
mon_iface = None
ble_ready = False
scan_start = 0.0           # epoch when scan started

# Unified device dict:  mac → { type, name, rssi, first_seen, last_seen,
#                                sightings, persistence, alert, tracker_type }
devices = {}

lock = threading.Lock()

# ===================================================================
# LCD init
# ===================================================================

def lcd_init():
    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    return lcd

# ===================================================================
# WiFi monitor-mode setup  (from analyzer.py)
# ===================================================================

def find_iface():
    """Find a monitor-mode capable wireless interface.
    
    wlan0 is reserved for the WebUI and is never selected here.
    """
    ifs = []
    try:
        for n in os.listdir("/sys/class/net"):
            if n == "lo" or n == "wlan0":
                continue  # wlan0 reserved for WebUI
            if os.path.isdir(f"/sys/class/net/{n}/wireless"):
                ifs.append(n)
    except Exception:
        pass
    no_mon = {"brcmfmac", "b43", "wl"}
    good, fall = [], []
    for i in ifs:
        drv = ""
        try:
            drv = os.path.basename(
                os.path.realpath(f"/sys/class/net/{i}/device/driver"))
        except Exception:
            pass
        (fall if drv in no_mon else good).append(i)
    return (good or fall or [None])[0]


def monitor_up(iface):
    """Put *iface* into monitor mode. Returns interface name or None.
    
    Only stops services for this specific interface — wlan0/WebUI is never touched.
    """
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
                               capture_output=True, text=True)
            if "Mode:Monitor" in r.stdout:
                return name
    except Exception:
        pass

    # iwconfig
    try:
        subprocess.run(["sudo", "ifconfig", iface, "down"],
                       check=True, timeout=10)
        subprocess.run(["sudo", "iwconfig", iface, "mode", "monitor"],
                       check=True, timeout=10)
        subprocess.run(["sudo", "ifconfig", iface, "up"],
                       check=True, timeout=10)
        time.sleep(1)
        r = subprocess.run(["iwconfig", iface],
                           capture_output=True, text=True, timeout=5)
        if "Mode:Monitor" in r.stdout:
            return iface
    except Exception:
        pass

    # iw
    try:
        subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                       check=True, timeout=10)
        subprocess.run(["sudo", "iw", iface, "set", "monitor", "none"],
                       check=True, timeout=10)
        subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                       check=True, timeout=10)
        time.sleep(1)
        r = subprocess.run(["iwconfig", iface],
                           capture_output=True, text=True, timeout=5)
        if "Mode:Monitor" in r.stdout:
            return iface
    except Exception:
        pass

    return None


def monitor_down(iface):
    """Best-effort restore to managed mode.
    
    Re-manages the interface in NetworkManager instead of restarting the service
    (which would disrupt wlan0/WebUI).
    """
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

# ===================================================================
# WiFi threads
# ===================================================================

def _hop_thread():
    """Channel hopper: cycles all WiFi channels."""
    global cur_ch
    idx = 0
    while running:
        if mon_iface:
            ch = CHALL[idx % len(CHALL)]
            try:
                subprocess.run(
                    ["sudo", "iw", "dev", mon_iface, "set", "channel", str(ch)],
                    capture_output=True, timeout=3)
                cur_ch = ch
            except Exception:
                pass
            idx += 1
        time.sleep(0.3)


def _add_wifi_device(mac, rssi, ssid):
    """Insert or update a WiFi device in the unified dict."""
    mac = mac.upper()
    now = time.time()
    with lock:
        if mac in devices:
            devices[mac]["rssi"] = rssi
            devices[mac]["last_seen"] = now
            devices[mac]["sightings"] += 1
            if ssid and not devices[mac]["name"]:
                devices[mac]["name"] = ssid
        else:
            devices[mac] = {
                "type": "WiFi",
                "name": ssid or "",
                "rssi": rssi,
                "first_seen": now,
                "last_seen": now,
                "sightings": 1,
                "persistence": 0.0,
                "alert": False,
                "tracker_type": "",
            }


def _wifi_cb(pkt):
    """Scapy per-packet callback – extract source MAC, RSSI, SSID."""
    if not pkt.haslayer(Dot11):
        return
    dot = pkt[Dot11]
    src = dot.addr2
    if not src or src == "ff:ff:ff:ff:ff:ff":
        return

    rssi = getattr(pkt, "dBm_AntSignal", None)

    # Try to extract SSID from beacons / probe requests / responses
    ssid = ""
    if pkt.haslayer(Dot11Elt):
        try:
            ssid = pkt[Dot11Elt].info.decode("utf-8", errors="ignore")
        except Exception:
            pass

    _add_wifi_device(src, rssi, ssid)


def _sniff_thread():
    """Scapy capture loop (management + data frames)."""
    if not SCAPY_OK or not mon_iface:
        return
    try:
        scapy_sniff(iface=mon_iface, prn=_wifi_cb,
                    filter="type mgt or type data",
                    stop_filter=lambda x: not running, store=0)
    except Exception:
        pass

# ===================================================================
# BLE scanner  (raw HCI socket – no extra pip packages)
# ===================================================================

def _hci_opcode(ogf, ocf):
    return (ogf << 10) | ocf


def _ble_open():
    """Open HCI socket, enable LE passive scan. Returns socket or None."""
    try:
        subprocess.run(["sudo", "hciconfig", "hci0", "up"],
                       capture_output=True, timeout=5)
        time.sleep(0.3)
    except Exception:
        return None

    try:
        s = socket.socket(AF_BT, socket.SOCK_RAW, BT_HCI)
        s.bind((0,))
        s.settimeout(1.0)

        # HCI filter: HCI_EVENT_PKT, CMD_COMPLETE + LE_META
        s.setsockopt(SOL_HCI, HCI_FLT,
                     struct.pack("<IIIH", 1 << 4, 1 << 14, 1 << 30, 0))

        # LE Set Scan Parameters: passive, 10 ms interval/window
        op = _hci_opcode(0x08, 0x000B)
        p = struct.pack("<BHHBB", 0x00, 0x0010, 0x0010, 0x00, 0x00)
        s.send(struct.pack("<BHB", 0x01, op, len(p)) + p)
        try:
            s.recv(256)
        except socket.timeout:
            pass

        # LE Set Scan Enable: on, no duplicate filter
        op = _hci_opcode(0x08, 0x000C)
        p = struct.pack("<BB", 0x01, 0x00)
        s.send(struct.pack("<BHB", 0x01, op, len(p)) + p)
        try:
            s.recv(256)
        except socket.timeout:
            pass

        return s
    except Exception:
        return None


def _ble_close(s):
    """Disable scan and close socket."""
    if not s:
        return
    try:
        op = _hci_opcode(0x08, 0x000C)
        p = struct.pack("<BB", 0x00, 0x00)
        s.send(struct.pack("<BHB", 0x01, op, len(p)) + p)
    except Exception:
        pass
    try:
        s.close()
    except Exception:
        pass


def _parse_adv(data):
    """Parse LE Advertising Report.

    Returns list of ``(mac, rssi, name, tracker_type)`` tuples.
    *tracker_type* is a string like ``"AirTag"`` or ``""`` if unknown.
    """
    out = []
    if len(data) < 5 or data[0] != 0x04 or data[1] != 0x3E:
        return out
    if data[3] != 0x02:
        return out
    try:
        num = data[4]
        off = 5
        for _ in range(num):
            if off + 9 > len(data):
                break
            addr = data[off + 2:off + 8]
            dlen = data[off + 8]
            off += 9

            mac = ":".join(f"{b:02X}" for b in reversed(addr))

            name = ""
            tracker = ""
            ad = data[off:off + dlen]
            j = 0
            while j < len(ad) - 1:
                al = ad[j]
                if al == 0 or j + al >= len(ad):
                    break
                ad_type = ad[j + 1]

                # 0x08 / 0x09 = Shortened / Complete Local Name
                if ad_type in (0x08, 0x09):
                    try:
                        name = bytes(ad[j + 2:j + 1 + al]).decode(
                            "utf-8", errors="ignore")
                    except Exception:
                        pass

                # 0xFF = Manufacturer Specific Data (first 2 bytes = company ID)
                if ad_type == 0xFF and al >= 3:
                    company_id = ad[j + 2] | (ad[j + 3] << 8)
                    t = TRACKER_COMPANY.get(company_id)
                    if t:
                        tracker = t

                j += al + 1
            off += dlen

            rssi = (struct.unpack("b", bytes([data[off]]))[0]
                    if off < len(data) else -127)
            off += 1
            out.append((mac, rssi, name, tracker))
    except Exception:
        pass
    return out


def _ble_thread():
    """BLE scanner thread – reads advertising reports via HCI socket."""
    global ble_ready
    s = _ble_open()
    if not s:
        return
    ble_ready = True
    try:
        while running:
            try:
                data = s.recv(256)
            except socket.timeout:
                continue
            except Exception:
                continue

            now = time.time()
            for mac, rssi, name, tracker in _parse_adv(data):
                with lock:
                    if mac in devices:
                        devices[mac]["rssi"] = rssi
                        devices[mac]["last_seen"] = now
                        devices[mac]["sightings"] += 1
                        if name:
                            devices[mac]["name"] = name
                        if tracker and not devices[mac]["tracker_type"]:
                            devices[mac]["tracker_type"] = tracker
                            devices[mac]["alert"] = True
                    else:
                        is_tracker = bool(tracker)
                        devices[mac] = {
                            "type": "BLE",
                            "name": name,
                            "rssi": rssi,
                            "first_seen": now,
                            "last_seen": now,
                            "sightings": 1,
                            "persistence": 0.0,
                            "alert": is_tracker,
                            "tracker_type": tracker,
                        }
    finally:
        ble_ready = False
        _ble_close(s)

# ===================================================================
# Persistence calculator thread
# ===================================================================

def _persist_thread():
    """Recalculate persistence scores every 2 seconds."""
    while running:
        now = time.time()
        with lock:
            for mac, d in devices.items():
                duration = now - d["first_seen"]
                if duration < PERSIST_MIN_OBS:
                    continue   # too early to score

                # Sighting rate: 10 sightings/min = max
                rate = min(1.0, (d["sightings"] / (duration / 60.0)) / 10.0)

                # Recency: drops to 0 after 120 s of silence
                age = now - d["last_seen"]
                recency = max(0.0, 1.0 - age / 120.0)

                # Duration: maxes at 30 min
                dur = min(1.0, duration / 1800.0)

                score = rate * 0.4 + recency * 0.3 + dur * 0.3
                d["persistence"] = round(score, 2)

                # Alert on high persistence (if not already flagged by tracker ID)
                if (not d["alert"]
                        and score > PERSIST_ALERT_TH
                        and duration > PERSIST_ALERT_DUR):
                    d["alert"] = True
        time.sleep(2)

# ===================================================================
# Drawing helpers
# ===================================================================

def _header(d, font, view_name):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "SCOUT", font=font, fill="#00FF00")
    if hasattr(d, "textbbox"):
        tw = d.textbbox((0, 0), view_name, font=font)[2]
    else:
        tw, _ = d.textsize(view_name, font=font)
    d.text((125 - tw, 1), view_name, font=font, fill="white")
    d.ellipse((108, 3, 112, 7), fill="#00FF00" if running else "#FF0000")


def _footer(d, font, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font, fill="#AAA")


def _draw_persist_bar(d, x, y, ratio, alert):
    """Draw a small 16x6 persistence bar at (x, y)."""
    w, h = 16, 6
    d.rectangle((x, y + 3, x + w - 1, y + h + 2), outline="#444")
    filled = int(ratio * (w - 2))
    if filled > 0:
        color = "#FF4444" if alert else "#00FF00"
        d.rectangle((x + 1, y + 4, x + filled, y + h + 1), fill=color)


def _sorted_devices(alert_only=False):
    """Return devices as list of (mac, info) sorted by persistence desc."""
    with lock:
        items = [(m, dict(d)) for m, d in devices.items()
                 if not alert_only or d["alert"]]
    items.sort(key=lambda kv: kv[1]["persistence"], reverse=True)
    return items


def _draw_device_list(d, font, devs, y0, alert_color=False):
    """Draw a scrollable device list starting at *y0*."""
    visible = devs[scroll:scroll + ROWS_VISIBLE]
    for i, (mac, info) in enumerate(visible):
        y = y0 + i * ROW_H
        typ = "B" if info["type"] == "BLE" else "W"
        name = (info["name"] or mac[-8:])[:9]
        rssi = info["rssi"]
        rssi_s = f"{rssi}" if rssi is not None else "?"

        # Color: red tint for alerts, green for normal
        if info["alert"]:
            color = "#FF4444" if alert_color else "#FF8800"
        else:
            color = "#CCCCCC"

        line = f"{typ} {name:<9s}{rssi_s:>4s}"
        d.text((1, y), line, font=font, fill=color)
        # Persistence bar (graphical, right side)
        _draw_persist_bar(d, 102, y, info["persistence"], info["alert"])
        # Alert marker
        if info["alert"]:
            d.text((120, y), "!", font=font, fill="#FF0000")

    # Scroll indicator
    total = len(devs)
    if total > ROWS_VISIBLE:
        bar_h = max(4, int(ROWS_VISIBLE / total * 88))
        bar_y = y0 + int(scroll / total * 88)
        d.rectangle((126, bar_y, 127, bar_y + bar_h), fill="#444")


def _draw_devices_view(d, font):
    """DEVICES view: all detected devices."""
    devs = _sorted_devices(alert_only=False)
    if not devs:
        msg = "Scanning..." if running else "Press KEY1"
        d.text((25, 55), msg, font=font, fill="#666")
    else:
        _draw_device_list(d, font, devs, 15)

    n_wifi = sum(1 for _, v in devs if v["type"] == "WiFi")
    n_ble  = sum(1 for _, v in devs if v["type"] == "BLE")
    n_alert = sum(1 for _, v in devs if v["alert"])
    _footer(d, font, f"W:{n_wifi} B:{n_ble} Alert:{n_alert}")


def _draw_alerts_view(d, font):
    """ALERTS view: only flagged devices."""
    devs = _sorted_devices(alert_only=True)
    if not devs:
        d.text((20, 45), "All clear", font=font, fill="#00FF00")
        d.text((12, 60), "No trackers found", font=font, fill="#666")
    else:
        _draw_device_list(d, font, devs, 15, alert_color=True)

    n = len(devs)
    _footer(d, font, f"Alerts: {n} device{'s' if n != 1 else ''}")


def _draw_stats_view(d, font):
    """STATS view: scan dashboard."""
    with lock:
        total = len(devices)
        n_wifi  = sum(1 for v in devices.values() if v["type"] == "WiFi")
        n_ble   = sum(1 for v in devices.values() if v["type"] == "BLE")
        n_alert = sum(1 for v in devices.values() if v["alert"])
        # Most persistent device
        top_mac, top_info = "", None
        for m, v in devices.items():
            if top_info is None or v["persistence"] > top_info["persistence"]:
                top_mac, top_info = m, v

    # Scan duration
    if scan_start > 0:
        elapsed = int(time.time() - scan_start)
        mins, secs = divmod(elapsed, 60)
        dur_s = f"{mins}m {secs:02d}s"
    else:
        dur_s = "not started"

    y = 18
    lines = [
        f"Scan: {dur_s}",
        f"WiFi:  {n_wifi} devices",
        f"BLE:   {n_ble} devices",
        f"Total: {total}",
        f"Alerts: {n_alert} active",
    ]
    for line in lines:
        d.text((4, y), line, font=font, fill="#CCCCCC")
        y += 12

    if top_info and top_info["persistence"] > 0:
        d.text((4, y + 4), "Most persistent:", font=font, fill="#888")
        name = (top_info["name"] or top_mac[-8:])[:14]
        score = top_info["persistence"]
        color = "#FF4444" if top_info["alert"] else "#FFAA00"
        d.text((4, y + 16), f" {name} ({score:.2f})", font=font, fill=color)

    status = "KEY1:Stop" if running else "KEY1:Start"
    _footer(d, font, f"{status}  KEY3:Export")


def draw_frame(lcd, font):
    """Render one frame to the LCD."""
    img = Image.new("RGB", (W, H), "black")
    d = ImageDraw.Draw(img)

    view = VIEWS[view_idx]
    _header(d, font, view)

    if   view == "DEVICES":  _draw_devices_view(d, font)
    elif view == "ALERTS":   _draw_alerts_view(d, font)
    elif view == "STATS":    _draw_stats_view(d, font)

    lcd.LCD_ShowImage(img, 0, 0)

# ===================================================================
# Export
# ===================================================================

def export_data():
    """Write JSON + CSV to loot/DeviceScout/."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    with lock:
        snapshot = {m: dict(d) for m, d in devices.items()}

    # JSON
    jpath = os.path.join(LOOT_DIR, f"scout_{ts}.json")
    with open(jpath, "w") as f:
        json.dump(snapshot, f, indent=2, default=str)

    # CSV
    cpath = os.path.join(LOOT_DIR, f"scout_{ts}.csv")
    fields = ["mac", "type", "name", "rssi", "persistence",
              "alert", "tracker_type", "first_seen", "last_seen", "sightings"]
    with open(cpath, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for mac, info in snapshot.items():
            row = {"mac": mac}
            row.update({k: info.get(k, "") for k in fields if k != "mac"})
            w.writerow(row)

    return f"{LOOT_DIR}/scout_{ts}.*"

# ===================================================================
# Start / stop
# ===================================================================

def start_all():
    global running, mon_iface, scan_start
    if running:
        return
    if not mon_iface:
        iface = find_iface()
        if iface:
            mon_iface = monitor_up(iface)
    running = True
    scan_start = time.time()
    for fn in (_hop_thread, _sniff_thread, _ble_thread, _persist_thread):
        threading.Thread(target=fn, daemon=True).start()


def stop_all():
    global running
    running = False
    time.sleep(0.5)

# ===================================================================
# Main
# ===================================================================

def main():
    global view_idx, scroll

    lcd = lcd_init()
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    font = ImageFont.load_default()

    # Splash screen
    img = Image.new("RGB", (W, H), "black")
    d = ImageDraw.Draw(img)
    d.text((12, 20), "DEVICE SCOUT", font=font, fill="#00FF00")
    d.text((4, 42), "Anti-surveillance", font=font, fill="#888")
    d.text((4, 54), "tracker detector", font=font, fill="#888")
    d.text((4, 72), "KEY1  Start / Stop", font=font, fill="#666")
    d.text((4, 84), "KEY2  Exit", font=font, fill="#666")
    d.text((4, 96), "KEY3  Export data", font=font, fill="#666")
    d.text((4, 108), "L/R Views  U/D Scroll", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY2":
                break
            elif btn == "KEY1":
                if running:
                    stop_all()
                else:
                    start_all()
                time.sleep(0.3)
            elif btn == "LEFT":
                view_idx = (view_idx - 1) % len(VIEWS)
                scroll = 0
                time.sleep(0.2)
            elif btn == "RIGHT":
                view_idx = (view_idx + 1) % len(VIEWS)
                scroll = 0
                time.sleep(0.2)
            elif btn == "UP":
                scroll = max(0, scroll - 1)
                time.sleep(0.15)
            elif btn == "DOWN":
                scroll += 1
                time.sleep(0.15)
            elif btn == "KEY3":
                path = export_data()
                # Brief confirmation on LCD
                img2 = Image.new("RGB", (W, H), "black")
                d2 = ImageDraw.Draw(img2)
                d2.text((10, 50), "Data exported!", font=font, fill="#00FF00")
                d2.text((4, 65), path[-22:], font=font, fill="#888")
                lcd.LCD_ShowImage(img2, 0, 0)
                time.sleep(1.5)

            draw_frame(lcd, font)
            time.sleep(0.05)

    finally:
        stop_all()
        monitor_down(mon_iface)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())