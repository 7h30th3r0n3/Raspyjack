#!/usr/bin/env python3
"""
RaspyJack Payload -- WiFi Airspace Alert Monitor
=================================================
Author: 7h30th3r0n3

Monitors the WiFi airspace for target MACs and SSIDs defined in a
watchlist.  When a target appears or disappears the LCD flashes red
and an optional Discord webhook notification is sent.

Setup / Prerequisites
---------------------
- USB WiFi dongle with monitor mode support (e.g. Alfa AWUS036ACH)
- pip install scapy requests
- Watchlist: /root/Raspyjack/config/wifi_alert/watchlist.json
  Format: {"targets": [{"mac": "AA:BB:CC:DD:EE:FF", "label": "Phone"},
                         {"ssid": "EvilCorp", "label": "Corp AP"}],
            "discord_webhook": "https://discord.com/api/webhooks/..."}

Controls
--------
  OK         -- Start / stop monitoring
  UP / DOWN  -- Scroll watchlist
  KEY1       -- Add currently visible APs to watchlist
  KEY2       -- Export alert log to loot
  KEY3       -- Exit
"""

import os
import sys
import time
import json
import threading
import subprocess
import copy
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

try:
    from scapy.all import (
        Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq,
        RadioTap, sniff as scapy_sniff, conf,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

# ── Pin / LCD setup ──────────────────────────────────────────────────────────
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

# ── Constants ────────────────────────────────────────────────────────────────
CONFIG_DIR = "/root/Raspyjack/config/wifi_alert"
CONFIG_FILE = os.path.join(CONFIG_DIR, "watchlist.json")
LOOT_DIR = "/root/Raspyjack/loot/WiFiAlert"
CHANNELS_24 = list(range(1, 14))
ROWS_VISIBLE = 7
ROW_H = 12

# ── Shared state ─────────────────────────────────────────────────────────────
lock = threading.Lock()
watchlist = []           # [{"mac": ..., "ssid": ..., "label": ...}]
discord_webhook = ""
seen_status = {}         # label -> {"seen": bool, "last_ts": str}
visible_aps = {}         # bssid -> {"ssid": ..., "bssid": ...}
alert_log = []           # [{"ts": ..., "event": ..., "label": ...}]
monitoring = False
mon_iface = None
scroll_pos = 0
status_msg = "Idle"
flash_until = 0.0
_running = True


# ── Onboard WiFi detection ──────────────────────────────────────────────────

def _is_onboard_wifi_iface(iface):
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


def _find_external_wifi():
    """Return the first external wireless interface name."""
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if not name.startswith("wlan"):
                continue
            if not os.path.isdir(f"/sys/class/net/{name}/wireless"):
                continue
            if _is_onboard_wifi_iface(name):
                continue
            return name
    except Exception:
        pass
    return None


# ── Monitor mode helpers ────────────────────────────────────────────────────

def _enable_monitor(iface):
    """Put *iface* into monitor mode, return monitor interface name."""
    subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "iw", iface, "set", "type", "monitor"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                   capture_output=True, timeout=5)
    return iface


def _disable_monitor(iface):
    """Restore managed mode on *iface*."""
    try:
        subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                       capture_output=True, timeout=5)
        subprocess.run(["sudo", "iw", iface, "set", "type", "managed"],
                       capture_output=True, timeout=5)
        subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                       capture_output=True, timeout=5)
    except Exception:
        pass


def _set_channel(iface, ch):
    subprocess.run(["sudo", "iw", "dev", iface, "set", "channel", str(ch)],
                   capture_output=True, timeout=3)


# ── Config helpers ───────────────────────────────────────────────────────────

def _load_config():
    global watchlist, discord_webhook
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if not os.path.isfile(CONFIG_FILE):
        _save_config()
        return
    try:
        with open(CONFIG_FILE, "r") as fh:
            data = json.load(fh)
        with lock:
            watchlist = list(data.get("targets", []))
            discord_webhook = data.get("discord_webhook", "")
            for entry in watchlist:
                label = entry.get("label", entry.get("mac", entry.get("ssid", "?")))
                if label not in seen_status:
                    seen_status[label] = {"seen": False, "last_ts": "never"}
    except Exception:
        pass


def _save_config():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with lock:
        data = {"targets": list(watchlist), "discord_webhook": discord_webhook}
    with open(CONFIG_FILE, "w") as fh:
        json.dump(data, fh, indent=2)


def _send_discord(message):
    if not REQUESTS_OK:
        return
    with lock:
        url = discord_webhook
    if not url:
        return
    try:
        requests.post(url, json={"content": message}, timeout=5)
    except Exception:
        pass


# ── Sniff callback ───────────────────────────────────────────────────────────

def _pkt_handler(pkt):
    global flash_until
    if not pkt.haslayer(Dot11):
        return

    bssid = None
    ssid = None
    src_mac = None

    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        elt = pkt[Dot11Elt]
        if elt and elt.ID == 0:
            try:
                ssid = elt.info.decode("utf-8", errors="replace")
            except Exception:
                ssid = ""
        if bssid:
            with lock:
                visible_aps[bssid.upper()] = {"ssid": ssid or "", "bssid": bssid.upper()}

    if pkt.haslayer(Dot11ProbeReq):
        src_mac = pkt[Dot11].addr2

    with lock:
        targets = list(watchlist)

    now_str = datetime.now().strftime("%H:%M:%S")

    for t in targets:
        label = t.get("label", t.get("mac", t.get("ssid", "?")))
        matched = False

        target_mac = t.get("mac", "").upper()
        target_ssid = t.get("ssid", "")

        if target_mac and bssid and bssid.upper() == target_mac:
            matched = True
        if target_mac and src_mac and src_mac.upper() == target_mac:
            matched = True
        if target_ssid and ssid and target_ssid.lower() in ssid.lower():
            matched = True

        if matched:
            with lock:
                prev = seen_status.get(label, {}).get("seen", False)
                seen_status[label] = {"seen": True, "last_ts": now_str}
                if not prev:
                    alert_log.append({"ts": now_str, "event": "APPEARED", "label": label})
                    flash_until = time.time() + 2.0
            if not prev:
                threading.Thread(
                    target=_send_discord,
                    args=(f"[WiFi Alert] {label} APPEARED at {now_str}",),
                    daemon=True,
                ).start()


# ── Channel hopping thread ──────────────────────────────────────────────────

def _channel_hop():
    ch_idx = 0
    while True:
        with lock:
            if not monitoring:
                break
            iface = mon_iface
        if iface is None:
            break
        _set_channel(iface, CHANNELS_24[ch_idx])
        ch_idx = (ch_idx + 1) % len(CHANNELS_24)
        time.sleep(0.3)


# ── Sniff thread ────────────────────────────────────────────────────────────

def _sniff_thread():
    with lock:
        iface = mon_iface
    if iface is None:
        return
    try:
        scapy_sniff(
            iface=iface,
            prn=_pkt_handler,
            store=False,
            stop_filter=lambda _: not monitoring,
        )
    except Exception:
        pass


# ── Disappearance checker thread ────────────────────────────────────────────

def _disappearance_checker():
    """Mark targets as MISSING if not seen for 30 seconds."""
    global flash_until
    while True:
        with lock:
            if not monitoring:
                break
        time.sleep(5)
        now = time.time()
        now_str = datetime.now().strftime("%H:%M:%S")
        with lock:
            for label, info in seen_status.items():
                if info["seen"] and info["last_ts"] != "never":
                    try:
                        last = datetime.strptime(info["last_ts"], "%H:%M:%S")
                        today = datetime.now().replace(
                            hour=last.hour, minute=last.minute, second=last.second
                        )
                        if (datetime.now() - today).total_seconds() > 30:
                            info["seen"] = False
                            alert_log.append({"ts": now_str, "event": "MISSING", "label": label})
                            flash_until = now + 2.0
                            threading.Thread(
                                target=_send_discord,
                                args=(f"[WiFi Alert] {label} MISSING at {now_str}",),
                                daemon=True,
                            ).start()
                    except Exception:
                        pass


# ── Start / stop ─────────────────────────────────────────────────────────────

def _start_monitoring():
    global monitoring, mon_iface, status_msg

    ext = _find_external_wifi()
    if ext is None:
        with lock:
            status_msg = "No USB WiFi found"
        return
    if not SCAPY_OK:
        with lock:
            status_msg = "scapy not installed"
        return

    iface = _enable_monitor(ext)
    with lock:
        mon_iface = iface
        monitoring = True
        status_msg = f"Monitoring on {iface}"

    threading.Thread(target=_channel_hop, daemon=True).start()
    threading.Thread(target=_sniff_thread, daemon=True).start()
    threading.Thread(target=_disappearance_checker, daemon=True).start()


def _stop_monitoring():
    global monitoring, status_msg
    with lock:
        monitoring = False
        iface = mon_iface
        status_msg = "Stopped"
    time.sleep(0.5)
    if iface:
        _disable_monitor(iface)


# ── Add visible APs to watchlist ─────────────────────────────────────────────

def _add_visible_to_watchlist():
    with lock:
        current_macs = {t.get("mac", "").upper() for t in watchlist}
        current_ssids = {t.get("ssid", "").lower() for t in watchlist}
        added = 0
        for bssid, info in visible_aps.items():
            if bssid not in current_macs:
                entry = {"mac": bssid, "label": info.get("ssid", bssid)[:16] or bssid}
                watchlist.append(entry)
                label = entry["label"]
                seen_status[label] = {"seen": True, "last_ts": datetime.now().strftime("%H:%M:%S")}
                added += 1
    if added > 0:
        _save_config()
    return added


# ── Export log ───────────────────────────────────────────────────────────────

def _export_log():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"wifi_alert_{ts}.json")
    with lock:
        data = {
            "watchlist": list(watchlist),
            "status": dict(seen_status),
            "alert_log": list(alert_log),
        }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


# ── Drawing ──────────────────────────────────────────────────────────────────

def _draw_screen():
    bg = "#200000" if time.time() < flash_until else "black"
    img = Image.new("RGB", (WIDTH, HEIGHT), bg)
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "WiFi ALERT", font=font, fill="#FF4444")
    with lock:
        active = monitoring
    color = "#00FF00" if active else "#FF0000"
    d.ellipse((118, 3, 126, 11), fill=color)

    with lock:
        msg = status_msg
        wl = list(watchlist)
        ss = dict(seen_status)
        sp = scroll_pos
        log_count = len(alert_log)

    y = 16
    d.text((2, y), msg[:22], font=font, fill="#888")
    y += 12
    d.text((2, y), f"Alerts: {log_count}", font=font, fill="#FFAA00")
    y += 14

    # Watchlist
    end = min(sp + ROWS_VISIBLE, len(wl))
    for i in range(sp, end):
        entry = wl[i]
        label = entry.get("label", "?")[:14]
        info = ss.get(entry.get("label", "?"), {})
        seen = info.get("seen", False)
        ts_str = info.get("last_ts", "never")
        tag = "SEEN" if seen else "MISS"
        tag_color = "#00FF00" if seen else "#FF4444"
        d.text((2, y), f"{label}", font=font, fill="#CCCCCC")
        d.text((90, y), tag, font=font, fill=tag_color)
        y += ROW_H

    if not wl:
        d.text((2, y), "No targets", font=font, fill="#555")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    lbl = "OK:Stop" if active else "OK:Start"
    d.text((2, 117), f"{lbl} K1:Add K3:X", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    global scroll_pos, status_msg

    _load_config()

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 10), "WiFi ALERT", font=font, fill="#FF4444")
    d.text((4, 28), "Airspace watchlist", font=font, fill="#888")
    d.text((4, 44), "monitor with alerts.", font=font, fill="#888")
    d.text((4, 64), "OK=Start  K1=Add APs", font=font, fill="#666")
    d.text((4, 76), "K2=Export  K3=Exit", font=font, fill="#666")
    d.text((4, 92), f"Targets: {len(watchlist)}", font=font, fill="#FFAA00")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            if btn == "OK":
                with lock:
                    active = monitoring
                if active:
                    _stop_monitoring()
                else:
                    _start_monitoring()
                time.sleep(0.3)

            elif btn == "UP":
                with lock:
                    scroll_pos = max(0, scroll_pos - 1)
                time.sleep(0.2)

            elif btn == "DOWN":
                with lock:
                    mx = max(0, len(watchlist) - ROWS_VISIBLE)
                    scroll_pos = min(scroll_pos + 1, mx)
                time.sleep(0.2)

            elif btn == "KEY1":
                added = _add_visible_to_watchlist()
                with lock:
                    status_msg = f"Added {added} APs"
                time.sleep(0.3)

            elif btn == "KEY2":
                path = _export_log()
                with lock:
                    status_msg = "Log exported"
                time.sleep(0.3)

            _draw_screen()
            time.sleep(0.05)

    finally:
        _stop_monitoring()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
