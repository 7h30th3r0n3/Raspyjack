#!/usr/bin/env python3
"""
RaspyJack Payload -- Device Scout
===================================
Author: 7h30th3r0n3

Anti-surveillance scanner. Detects nearby WiFi + BLE devices and
flags trackers (AirTag, Tile, SmartTag) or persistent followers.

Views (KEY1 to cycle):
  RADAR    Threat gauge + live device count + scan animation
  THREATS  Flagged devices only with threat score bars
  DEVICES  Full device list sorted by persistence
  BLE      Bluetooth-only view

Controls:
  OK         Start / Stop scan
  KEY1       Cycle views
  UP/DOWN    Scroll
  KEY2       Export data
  KEY3       Exit
"""

import os
import sys
import csv
import json
import math
import time
import subprocess
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._iface_helper import list_interfaces

try:
    from scapy.all import (
        Dot11, Dot11Elt, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp,
        sniff as scapy_sniff,
    )
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
LOOT_DIR = "/root/Raspyjack/loot/DeviceScout"
VIEWS = ["RADAR", "THREATS", "DEVICES", "BLE"]

ALL_CHANNELS = list(range(1, 14)) + [
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
    149, 153, 157, 161, 165]

TRACKER_NAMES = {"apple": "AirTag", "tile": "Tile", "samsung": "SmartTag",
                 "chipolo": "Chipolo", "pebblebee": "Pebble"}

PERSIST_MIN = 60
PERSIST_ALERT = 0.70
PERSIST_ALERT_DUR = 300

KNOWN_MONITOR_DRIVERS = {
    "rtl88XXau", "rtl8812au", "rtl8821au", "rtl88x2bu",
    "rtl8188eus", "rtl8187", "rt2800usb", "ath9k_htc",
    "mt76x2u", "mt76x0u", "mt7921u", "rtl8814au",
}

# Theme colors
C_BG = "#000000"
C_SAFE = "#00FF88"
C_WARN = "#FFAA00"
C_DANGER = "#FF3333"
C_BLE = "#0099FF"
C_WIFI = "#00CC66"
C_BT_CLASSIC = "#8844FF"
C_DIM = "#333333"
C_TEXT = "#CCCCCC"
C_MUTED = "#666666"
C_ACCENT = "#00DDFF"
C_HEADER_BG = "#0a0a14"
C_PANEL_BG = "#0d0d1a"

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = False
scan_start = 0.0
view_idx = 0
scroll = 0
_frame = 0      # animation frame counter

devices = {}
mon_ifaces = []
hci_ifaces = []
cur_ch = 1


# ---------------------------------------------------------------------------
# Device helpers
# ---------------------------------------------------------------------------


def _get_driver(iface):
    try:
        return os.path.basename(
            os.path.realpath(f"/sys/class/net/{iface}/device/driver"))
    except Exception:
        return ""


def _add_device(mac, dev_type, rssi, name="", tracker=""):
    mac = mac.upper()
    now = time.time()
    with lock:
        if mac in devices:
            d = devices[mac]
            if rssi and rssi > -99:
                d["rssi"] = rssi
            d["last_seen"] = now
            d["sightings"] += 1
            if name and not d["name"]:
                d["name"] = name
            if tracker and not d["tracker_type"]:
                d["tracker_type"] = tracker
                d["alert"] = True
        else:
            devices[mac] = {
                "type": dev_type,
                "name": name,
                "rssi": rssi or -99,
                "first_seen": now,
                "last_seen": now,
                "sightings": 1,
                "persistence": 0.0,
                "alert": bool(tracker),
                "tracker_type": tracker,
            }


# ---------------------------------------------------------------------------
# Monitor mode
# ---------------------------------------------------------------------------


def _monitor_up(iface):
    for cmd in [
        ["sudo", "ip", "link", "set", iface, "down"],
        ["sudo", "iw", iface, "set", "monitor", "none"],
        ["sudo", "ip", "link", "set", iface, "up"],
    ]:
        subprocess.run(cmd, capture_output=True, timeout=5)
    time.sleep(0.3)
    r = subprocess.run(["iw", "dev", iface, "info"],
                       capture_output=True, text=True, timeout=5)
    if "type monitor" in r.stdout:
        return iface
    subprocess.run(["sudo", "airmon-ng", "start", iface],
                   capture_output=True, timeout=15)
    for name in (f"{iface}mon", iface):
        r = subprocess.run(["iw", "dev", name, "info"],
                           capture_output=True, text=True, timeout=5)
        if "type monitor" in r.stdout:
            return name
    return None


def _monitor_down(iface):
    if not iface:
        return
    base = iface.replace("mon", "")
    subprocess.run(["sudo", "airmon-ng", "stop", iface],
                   capture_output=True, timeout=10)
    for cmd in [
        ["sudo", "ip", "link", "set", base, "down"],
        ["sudo", "iw", base, "set", "type", "managed"],
        ["sudo", "ip", "link", "set", base, "up"],
    ]:
        subprocess.run(cmd, capture_output=True, timeout=5)


# ---------------------------------------------------------------------------
# WiFi scanner threads
# ---------------------------------------------------------------------------


def _wifi_cb(pkt):
    if not pkt.haslayer(Dot11):
        return
    src = (pkt[Dot11].addr2 or "").upper()
    if not src or src == "FF:FF:FF:FF:FF:FF":
        return
    rssi = getattr(pkt, "dBm_AntSignal", None)
    ssid = ""
    if pkt.haslayer(Dot11Elt):
        try:
            ssid = pkt[Dot11Elt].info.decode("utf-8", errors="ignore")
        except Exception:
            pass
    _add_device(src, "WiFi", rssi, ssid)


def _sniff_worker(iface):
    if not SCAPY_OK:
        return
    try:
        scapy_sniff(iface=iface, prn=_wifi_cb,
                    stop_filter=lambda _: not running, store=0)
    except Exception:
        pass


def _hop_worker(iface, channels):
    global cur_ch
    idx = 0
    while running:
        ch = channels[idx % len(channels)]
        r = subprocess.run(
            ["sudo", "iw", "dev", iface, "set", "channel", str(ch)],
            capture_output=True, timeout=3)
        if r.returncode == 0:
            cur_ch = ch
        idx += 1
        time.sleep(0.3)


def _iw_scan_worker():
    while running:
        try:
            r = subprocess.run(
                ["sudo", "iw", "dev", "wlan0", "scan", "-u"],
                capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                cur_mac = None
                cur_ssid = ""
                cur_sig = -80
                for line in r.stdout.splitlines():
                    s = line.strip()
                    if s.startswith("BSS "):
                        if cur_mac:
                            _add_device(cur_mac, "WiFi", cur_sig, cur_ssid)
                        parts = s.split()
                        cur_mac = parts[1].split("(")[0].upper() if len(parts) > 1 else None
                        cur_ssid = ""
                        cur_sig = -80
                    elif s.startswith("SSID:"):
                        cur_ssid = s[5:].strip()
                    elif s.startswith("signal:"):
                        try:
                            cur_sig = int(float(s.split(":")[1].strip().split()[0]))
                        except Exception:
                            pass
                if cur_mac:
                    _add_device(cur_mac, "WiFi", cur_sig, cur_ssid)
        except Exception:
            pass
        for _ in range(50):
            if not running:
                return
            time.sleep(0.1)


# ---------------------------------------------------------------------------
# BLE scanner (btmgmt)
# ---------------------------------------------------------------------------


def _ble_worker(hci="hci0"):
    """BLE scan using btmgmt find — reads output line by line in real-time."""
    while running:
        try:
            idx = hci.replace("hci", "")
            proc = subprocess.Popen(
                ["sudo", "btmgmt", "--index", idx, "find"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True)

            deadline = time.time() + 10
            for line in iter(proc.stdout.readline, ""):
                if not running or time.time() > deadline:
                    break
                line = line.strip()
                if "dev_found:" not in line:
                    continue
                parts = line.split()
                try:
                    mac_idx = parts.index("dev_found:") + 1
                    mac = parts[mac_idx].upper()
                except (ValueError, IndexError):
                    continue
                rssi = -99
                try:
                    rssi_idx = parts.index("rssi") + 1
                    rssi = int(parts[rssi_idx])
                except (ValueError, IndexError):
                    pass
                dev_type = "BT" if "BR/EDR" in line else "BLE"
                tracker = ""
                for key, tname in TRACKER_NAMES.items():
                    if key in line.lower():
                        tracker = tname
                _add_device(mac, dev_type, rssi, tracker=tracker)

            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        except Exception:
            pass
        for _ in range(20):
            if not running:
                return
            time.sleep(0.1)


def _find_all_hci():
    result = []
    bt_path = "/sys/class/bluetooth"
    if os.path.isdir(bt_path):
        for name in sorted(os.listdir(bt_path)):
            if name.startswith("hci"):
                subprocess.run(["sudo", "hciconfig", name, "up"],
                               capture_output=True, timeout=5)
                result.append(name)
    return result


# ---------------------------------------------------------------------------
# Persistence calculator
# ---------------------------------------------------------------------------


def _persist_worker():
    while running:
        now = time.time()
        with lock:
            for d in devices.values():
                dur = now - d["first_seen"]
                if dur < PERSIST_MIN:
                    continue
                rate = min(1.0, (d["sightings"] / (dur / 60.0)) / 10.0)
                age = now - d["last_seen"]
                recency = max(0.0, 1.0 - age / 120.0)
                dur_score = min(1.0, dur / 1800.0)
                score = rate * 0.4 + recency * 0.3 + dur_score * 0.3
                d["persistence"] = round(score, 2)
                if (not d["alert"] and score > PERSIST_ALERT
                        and dur > PERSIST_ALERT_DUR):
                    d["alert"] = True
        time.sleep(2)


# ---------------------------------------------------------------------------
# Start / Stop
# ---------------------------------------------------------------------------


def start_all():
    global running, scan_start
    if running:
        return
    running = True
    scan_start = time.time()

    # WiFi
    wifi_all = list_interfaces("wifi")
    usb_wifi = [i["name"] for i in wifi_all
                if not i.get("is_onboard") and
                (i.get("supports_monitor") or
                 _get_driver(i["name"]) in KNOWN_MONITOR_DRIVERS)]

    mon_ifaces.clear()
    for iface in usb_wifi:
        m = _monitor_up(iface)
        if m:
            mon_ifaces.append(m)

    if mon_ifaces:
        n = len(mon_ifaces)
        for idx, iface in enumerate(mon_ifaces):
            threading.Thread(target=_sniff_worker, args=(iface,), daemon=True).start()
            chs = [ALL_CHANNELS[i] for i in range(idx, len(ALL_CHANNELS), n)]
            threading.Thread(target=_hop_worker, args=(iface, chs), daemon=True).start()

    if os.path.isdir("/sys/class/net/wlan0/wireless"):
        threading.Thread(target=_iw_scan_worker, daemon=True).start()

    # BLE
    hci_list = _find_all_hci()
    hci_ifaces.clear()
    hci_ifaces.extend(hci_list)
    for hci in hci_list:
        threading.Thread(target=_ble_worker, args=(hci,), daemon=True).start()

    threading.Thread(target=_persist_worker, daemon=True).start()


def stop_all():
    global running
    running = False
    time.sleep(0.5)


# ---------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------


def _signal_level(rssi):
    if rssi is None or rssi <= -90:
        return 0
    if rssi >= -50:
        return 4
    if rssi >= -60:
        return 3
    if rssi >= -70:
        return 2
    return 1


def _threat_color(score, alert):
    if alert:
        return C_DANGER
    if score > 0.5:
        return C_WARN
    return C_SAFE


def _sorted_devs(alert_only=False, type_filter=None):
    with lock:
        items = []
        for m, d in devices.items():
            if alert_only and not d["alert"]:
                continue
            if type_filter and d["type"] not in (type_filter if isinstance(type_filter, (list, tuple)) else [type_filter]):
                continue
            items.append((m, dict(d)))
    items.sort(key=lambda x: x[1]["persistence"], reverse=True)
    return items


# ---------------------------------------------------------------------------
# RADAR view — main threat overview
# ---------------------------------------------------------------------------


def _draw_radar(lcd, font, font_sm):
    global _frame
    _frame += 1
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)

    with lock:
        total = len(devices)
        n_wifi = sum(1 for v in devices.values() if v["type"] == "WiFi")
        n_ble = sum(1 for v in devices.values() if v["type"] in ("BLE", "BT"))
        n_alert = sum(1 for v in devices.values() if v["alert"])
        max_persist = max((v["persistence"] for v in devices.values()), default=0)

    # Header bar
    d.rectangle((0, 0, 127, 13), fill=C_HEADER_BG)
    d.text((2, 1), "SCOUT", font=font_sm, fill=C_ACCENT)
    if running:
        # Scanning animation dots
        dots = "." * ((_frame // 3) % 4)
        d.text((38, 1), f"SCAN{dots}", font=font_sm, fill=C_SAFE)
    else:
        d.text((38, 1), "IDLE", font=font_sm, fill=C_MUTED)
    d.text((90, 1), f"CH:{cur_ch}", font=font_sm, fill=C_MUTED)

    # --- Threat gauge (arc) ---
    cx, cy = 64, 52
    radius = 28

    # Background arc
    d.arc((cx - radius, cy - radius, cx + radius, cy + radius),
          180, 360, fill=C_DIM, width=2)

    # Threat level arc (0-180 degrees based on max persistence)
    if max_persist > 0:
        angle = int(max_persist * 180)
        if n_alert > 0:
            arc_color = C_DANGER
        elif max_persist > 0.5:
            arc_color = C_WARN
        else:
            arc_color = C_SAFE
        d.arc((cx - radius, cy - radius, cx + radius, cy + radius),
              180, 180 + angle, fill=arc_color, width=3)

    # Threat level text in center
    if n_alert > 0:
        level_text = "THREAT"
        level_color = C_DANGER
    elif max_persist > 0.5:
        level_text = "CAUTION"
        level_color = C_WARN
    elif total > 0:
        level_text = "CLEAR"
        level_color = C_SAFE
    else:
        level_text = "---"
        level_color = C_MUTED

    d.text((cx, cy - 5), level_text, font=font_sm, fill=level_color, anchor="mm")

    # Alert count below gauge
    if n_alert > 0:
        d.text((cx, cy + 10), f"{n_alert} ALERT{'S' if n_alert > 1 else ''}",
               font=font_sm, fill=C_DANGER, anchor="mm")

    # --- Device counters (bottom panels) ---
    panel_y = 82
    panel_h = 28

    # WiFi panel
    d.rectangle((2, panel_y, 41, panel_y + panel_h), fill=C_PANEL_BG, outline=C_DIM)
    d.text((6, panel_y + 2), "WiFi", font=font_sm, fill=C_WIFI)
    d.text((6, panel_y + 14), str(n_wifi), font=font, fill="#FFFFFF")

    # BLE panel
    d.rectangle((44, panel_y, 83, panel_y + panel_h), fill=C_PANEL_BG, outline=C_DIM)
    d.text((48, panel_y + 2), "BLE", font=font_sm, fill=C_BLE)
    d.text((48, panel_y + 14), str(n_ble), font=font, fill="#FFFFFF")

    # Alerts panel
    alert_bg = "#1a0a0a" if n_alert > 0 else C_PANEL_BG
    alert_border = C_DANGER if n_alert > 0 else C_DIM
    d.rectangle((86, panel_y, 125, panel_y + panel_h), fill=alert_bg, outline=alert_border)
    d.text((90, panel_y + 2), "Alert", font=font_sm, fill=C_DANGER if n_alert else C_MUTED)
    d.text((90, panel_y + 14), str(n_alert), font=font,
           fill=C_DANGER if n_alert else C_MUTED)

    # Footer
    d.rectangle((0, 116, 127, 127), fill=C_HEADER_BG)
    action = "STOP" if running else "START"
    d.text((2, 117), f"OK:{action} K1:View K2:Exp", font=font_sm, fill=C_MUTED)

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# THREATS view
# ---------------------------------------------------------------------------


def _draw_threats(lcd, font, font_sm):
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)

    devs = _sorted_devs(alert_only=True)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#1a0808")
    d.text((2, 1), "THREATS", font=font_sm, fill=C_DANGER)
    d.text((90, 1), f"{len(devs)}", font=font_sm,
           fill=C_DANGER if devs else C_MUTED)

    if not devs:
        # Safe screen
        d.text((64, 50), "ALL CLEAR", font=font, fill=C_SAFE, anchor="mm")
        d.text((64, 68), "No trackers detected", font=font_sm,
               fill=C_MUTED, anchor="mm")
        # Checkmark
        d.ellipse((52, 30, 76, 40), outline=C_SAFE)
    else:
        y = 16
        visible = devs[scroll:scroll + 7]
        for mac, info in visible:
            name = (info["name"] or info.get("tracker_type", "") or mac[-8:])[:11]
            score = info["persistence"]
            rssi = info["rssi"]
            tracker = info.get("tracker_type", "")[:5]

            # Red gradient row background based on score
            row_bg = f"#{min(255, int(score * 40)):02x}0000"
            d.rectangle((0, y, 127, y + 13), fill=row_bg)

            # Threat bar
            bar_w = int(score * 30)
            if bar_w > 0:
                d.rectangle((2, y + 2, 2 + bar_w, y + 10), fill=C_DANGER)

            # Name + info
            d.text((36, y + 1), name, font=font_sm, fill="#FFFFFF")
            if tracker:
                d.text((100, y + 1), tracker, font=font_sm, fill=C_WARN)
            else:
                d.text((108, y + 1), f"{rssi}", font=font_sm, fill=C_MUTED)

            y += 14

    d.rectangle((0, 116, 127, 127), fill=C_HEADER_BG)
    d.text((2, 117), "K1:View U/D:Scroll K3:X", font=font_sm, fill=C_MUTED)
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# DEVICES view
# ---------------------------------------------------------------------------


def _draw_devices(lcd, font, font_sm):
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)

    devs = _sorted_devs()

    # Header
    d.rectangle((0, 0, 127, 13), fill=C_HEADER_BG)
    d.text((2, 1), "DEVICES", font=font_sm, fill=C_ACCENT)
    d.text((65, 1), f"{len(devs)}", font=font_sm, fill="#FFFFFF")

    if not devs:
        msg = "Scanning..." if running else "OK to start"
        d.text((64, 60), msg, font=font_sm, fill=C_MUTED, anchor="mm")
    else:
        y = 15
        visible = devs[scroll:scroll + 8]
        for mac, info in visible:
            typ = info["type"]
            name = (info["name"] or mac[-8:])[:11]
            rssi = info["rssi"]
            score = info["persistence"]

            # Type indicator dot
            if typ == "BLE":
                dot_col = C_BLE
            elif typ == "BT":
                dot_col = C_BT_CLASSIC
            else:
                dot_col = C_WIFI
            d.ellipse((2, y + 3, 6, y + 7), fill=dot_col)

            # Name
            name_col = C_DANGER if info["alert"] else C_TEXT
            d.text((9, y), name, font=font_sm, fill=name_col)

            # Mini signal dots
            lvl = _signal_level(rssi)
            for i in range(4):
                sx = 76 + i * 4
                sh = 2 + i * 2
                col = C_SAFE if i < lvl else "#1a1a1a"
                d.rectangle((sx, y + 8 - sh, sx + 2, y + 8), fill=col)

            # Persistence mini bar
            bar_x = 96
            d.rectangle((bar_x, y + 3, bar_x + 20, y + 7), outline="#222")
            pw = int(score * 18)
            if pw > 0:
                d.rectangle((bar_x + 1, y + 4, bar_x + pw, y + 6),
                             fill=_threat_color(score, info["alert"]))

            # Alert icon
            if info["alert"]:
                d.text((120, y), "!", font=font_sm, fill=C_DANGER)

            y += 12

        # Scroll bar
        if len(devs) > 8:
            sb_h = max(4, int(8 / len(devs) * 98))
            sb_y = 15 + int(scroll / max(len(devs), 1) * 98)
            d.rectangle((126, sb_y, 127, sb_y + sb_h), fill=C_DIM)

    d.rectangle((0, 116, 127, 127), fill=C_HEADER_BG)
    d.text((2, 117), "K1:View U/D:Scrl K2:Exp", font=font_sm, fill=C_MUTED)
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# BLE view
# ---------------------------------------------------------------------------


def _draw_ble(lcd, font, font_sm):
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)

    devs = _sorted_devs(type_filter=("BLE", "BT"))

    # Header
    d.rectangle((0, 0, 127, 13), fill="#080814")
    d.text((2, 1), "BLUETOOTH", font=font_sm, fill=C_BLE)
    d.text((80, 1), f"{len(devs)} dev", font=font_sm, fill=C_MUTED)

    if not devs:
        if running:
            d.text((64, 45), "Scanning...", font=font_sm, fill=C_BLE, anchor="mm")
            d.text((64, 60), f"{len(hci_ifaces)} adapter(s)",
                   font=font_sm, fill=C_MUTED, anchor="mm")
        else:
            d.text((64, 55), "OK to start", font=font_sm,
                   fill=C_MUTED, anchor="mm")
    else:
        y = 15
        visible = devs[scroll:scroll + 8]
        for mac, info in visible:
            name = (info["name"] or mac[-8:])[:12]
            rssi = info["rssi"]
            is_classic = info["type"] == "BT"

            # Type badge
            badge_col = C_BT_CLASSIC if is_classic else C_BLE
            badge_txt = "C" if is_classic else "L"
            d.rectangle((1, y + 1, 8, y + 9), fill=badge_col)
            d.text((2, y), badge_txt, font=font_sm, fill="#FFF")

            # Name
            d.text((11, y), name, font=font_sm,
                   fill=C_DANGER if info["alert"] else C_TEXT)

            # Signal
            lvl = _signal_level(rssi)
            for i in range(4):
                sx = 88 + i * 4
                sh = 2 + i * 2
                col = C_BLE if i < lvl else "#111"
                d.rectangle((sx, y + 8 - sh, sx + 2, y + 8), fill=col)

            d.text((108, y), str(rssi), font=font_sm, fill=C_MUTED)

            if info["alert"]:
                t = info.get("tracker_type", "!")[:4]
                d.text((108, y), t, font=font_sm, fill=C_DANGER)

            y += 12

    d.rectangle((0, 116, 127, 127), fill=C_HEADER_BG)
    d.text((2, 117), "K1:View U/D:Scroll", font=font_sm, fill=C_MUTED)
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


def _export():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    with lock:
        snapshot = {m: dict(d) for m, d in devices.items()}

    jpath = os.path.join(LOOT_DIR, f"scout_{ts}.json")
    with open(jpath, "w") as f:
        json.dump(snapshot, f, indent=2, default=str)

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
    return f"scout_{ts}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    global view_idx, scroll

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font = scaled_font(10)
    font_sm = scaled_font(8)

    os.makedirs(LOOT_DIR, exist_ok=True)

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 127), fill=C_BG)
    d.text((64, 25), "DEVICE", font=font, fill=C_ACCENT, anchor="mm")
    d.text((64, 40), "SCOUT", font=font, fill=C_ACCENT, anchor="mm")
    d.line([(20, 50), (108, 50)], fill=C_DIM)
    d.text((64, 60), "Anti-Surveillance", font=font_sm, fill=C_MUTED, anchor="mm")
    d.text((64, 74), "Tracker Detection", font=font_sm, fill=C_MUTED, anchor="mm")
    d.text((64, 95), "OK = Start Scan", font=font_sm, fill=C_SAFE, anchor="mm")
    d.text((64, 108), "KEY3 = Exit", font=font_sm, fill=C_MUTED, anchor="mm")
    lcd.LCD_ShowImage(img, 0, 0)

    # Wait for button release
    time.sleep(0.3)
    while get_button(PINS, GPIO) is not None:
        time.sleep(0.05)

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break
            elif btn == "OK":
                if running:
                    stop_all()
                else:
                    start_all()
                time.sleep(0.3)
            elif btn == "KEY1":
                view_idx = (view_idx + 1) % len(VIEWS)
                scroll = 0
                time.sleep(0.2)
            elif btn == "UP":
                scroll = max(0, scroll - 1)
                time.sleep(0.12)
            elif btn == "DOWN":
                scroll += 1
                time.sleep(0.12)
            elif btn == "KEY2":
                name = _export()
                img2 = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
                d2 = ScaledDraw(img2)
                d2.text((64, 50), "Exported!", font=font, fill=C_SAFE, anchor="mm")
                d2.text((64, 68), name[:22], font=font_sm, fill=C_MUTED, anchor="mm")
                lcd.LCD_ShowImage(img2, 0, 0)
                time.sleep(1.5)

            view = VIEWS[view_idx]
            if view == "RADAR":
                _draw_radar(lcd, font, font_sm)
            elif view == "THREATS":
                _draw_threats(lcd, font, font_sm)
            elif view == "DEVICES":
                _draw_devices(lcd, font, font_sm)
            elif view == "BLE":
                _draw_ble(lcd, font, font_sm)

            time.sleep(0.05)

    finally:
        stop_all()
        for iface in mon_ifaces:
            _monitor_down(iface)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
