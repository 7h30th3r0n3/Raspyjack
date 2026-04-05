#!/usr/bin/env python3
"""
RaspyJack Payload -- WiFi Client-AP Association Mapper
=======================================================
Author: 7h30th3r0n3

Passive 802.11 sniffer on a USB WiFi dongle in monitor mode.

Setup / Prerequisites:
  - Requires USB WiFi dongle capable of monitor mode.  Extracts
FromDS/ToDS bits from data frames to build a real-time map of which
client stations are associated with which access points (BSSIDs).

Controls:
  OK          -- Start / stop sniffing
  UP / DOWN   -- Scroll AP list
  RIGHT       -- Drill down: show clients for selected AP
  LEFT        -- Back to AP list
  KEY1        -- Rescan (clear + restart)
  KEY2        -- Export results to loot
  KEY3        -- Exit

Loot: /root/Raspyjack/loot/ClientMap/<timestamp>.json
"""

import os
import sys
import json
import time
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
LOOT_DIR = "/root/Raspyjack/loot/ClientMap"
os.makedirs(LOOT_DIR, exist_ok=True)

ROWS_VISIBLE = 7
ROW_H = 12
BROADCAST = "ff:ff:ff:ff:ff:ff"

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
sniffing = False
stop_flag = False
status_msg = "Idle"
scroll_pos = 0
client_scroll = 0
pkt_count = 0
mon_iface = None

# {bssid: set(client_macs)}
ap_clients = {}


# ---------------------------------------------------------------------------
# Onboard WiFi detection (skip Pi built-in)
# ---------------------------------------------------------------------------

def _is_onboard_wifi_iface(iface):
    """True for the onboard Pi WiFi device (SDIO/mmc or brcmfmac driver)."""
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


def _find_monitor_iface():
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
    no_mon = {"brcmfmac", "b43", "wl"}
    good, fallback = [], []
    for iface in candidates:
        drv = ""
        try:
            drv = os.path.basename(
                os.path.realpath(f"/sys/class/net/{iface}/device/driver")
            )
        except Exception:
            pass
        (fallback if drv in no_mon else good).append(iface)
    return (good or fallback or [None])[0]


def _enable_monitor(iface):
    """Put interface into monitor mode. Returns monitor interface name."""
    try:
        subprocess.run(["ip", "link", "set", iface, "down"],
                        capture_output=True, timeout=5)
        subprocess.run(["iw", "dev", iface, "set", "type", "monitor"],
                        capture_output=True, timeout=5)
        subprocess.run(["ip", "link", "set", iface, "up"],
                        capture_output=True, timeout=5)
        return iface
    except Exception:
        return None


def _disable_monitor(iface):
    """Restore interface to managed mode."""
    try:
        subprocess.run(["ip", "link", "set", iface, "down"],
                        capture_output=True, timeout=5)
        subprocess.run(["iw", "dev", iface, "set", "type", "managed"],
                        capture_output=True, timeout=5)
        subprocess.run(["ip", "link", "set", iface, "up"],
                        capture_output=True, timeout=5)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Sniffer thread
# ---------------------------------------------------------------------------

def _channel_hopper(iface):
    """Hop across 2.4 GHz channels while sniffing."""
    channels = [1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13]
    idx = 0
    while not stop_flag:
        try:
            subprocess.run(
                ["iw", "dev", iface, "set", "channel", str(channels[idx])],
                capture_output=True, timeout=3,
            )
        except Exception:
            pass
        idx = (idx + 1) % len(channels)
        time.sleep(0.3)


def _sniffer_thread():
    """Sniff 802.11 frames and extract client-AP associations."""
    global sniffing, status_msg, pkt_count, stop_flag, mon_iface

    try:
        from scapy.all import sniff as scapy_sniff, Dot11
    except ImportError:
        with lock:
            status_msg = "scapy not installed"
            sniffing = False
        return

    iface = _find_monitor_iface()
    if iface is None:
        with lock:
            status_msg = "No USB WiFi found"
            sniffing = False
        return

    mon = _enable_monitor(iface)
    if mon is None:
        with lock:
            status_msg = "Monitor mode failed"
            sniffing = False
        return

    with lock:
        mon_iface = mon
        status_msg = f"Sniffing on {mon}"

    hopper = threading.Thread(target=_channel_hopper, args=(mon,), daemon=True)
    hopper.start()

    def _process(pkt):
        global pkt_count
        if stop_flag:
            return
        if not pkt.haslayer(Dot11):
            return

        dot11 = pkt[Dot11]
        ds = dot11.FCfield & 0x3

        bssid = None
        client = None

        if ds == 0x01:
            bssid = dot11.addr1
            client = dot11.addr2
        elif ds == 0x02:
            bssid = dot11.addr2
            client = dot11.addr1
        elif ds == 0x00:
            bssid = dot11.addr3
            client = dot11.addr2
        else:
            return

        if bssid is None or client is None:
            return
        bssid = bssid.lower()
        client = client.lower()

        if client == BROADCAST or bssid == BROADCAST:
            return
        if client == bssid:
            return

        with lock:
            pkt_count += 1
            if bssid not in ap_clients:
                ap_clients[bssid] = set()
            ap_clients[bssid].add(client)

    try:
        scapy_sniff(
            iface=mon,
            prn=_process,
            store=False,
            stop_filter=lambda _: stop_flag,
            timeout=600,
        )
    except Exception as exc:
        with lock:
            status_msg = f"Err: {str(exc)[:16]}"

    _disable_monitor(iface)
    with lock:
        sniffing = False
        mon_iface = None
        if "Err" not in status_msg:
            status_msg = f"Stopped ({len(ap_clients)} APs)"


def start_sniffing():
    global sniffing, stop_flag
    with lock:
        if sniffing:
            return
        sniffing = True
        stop_flag = False
    threading.Thread(target=_sniffer_thread, daemon=True).start()


def stop_sniffing():
    global stop_flag
    with lock:
        stop_flag = True


# ---------------------------------------------------------------------------
# Loot export
# ---------------------------------------------------------------------------

def export_loot():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    with lock:
        data = {
            "timestamp": ts,
            "total_aps": len(ap_clients),
            "associations": {
                bssid: sorted(clients) for bssid, clients in ap_clients.items()
            },
        }
    path = os.path.join(LOOT_DIR, f"clientmap_{ts}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(d, title):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title, font=font, fill="#00CCFF")
    with lock:
        active = sniffing
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if active else "#FF0000")


def _draw_footer(d, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font, fill="#AAA")


def _sorted_aps():
    """Return AP list sorted by client count descending."""
    with lock:
        items = [(bssid, set(clients)) for bssid, clients in ap_clients.items()]
    return sorted(items, key=lambda kv: len(kv[1]), reverse=True)


def draw_ap_list():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "CLIENT MAP")

    with lock:
        status = status_msg
        sc = scroll_pos
        pkts = pkt_count

    d.text((2, 15), f"{status[:16]}  p:{pkts}", font=font, fill="#888")

    aps = _sorted_aps()
    if not aps:
        d.text((10, 45), "OK: Start sniffing", font=font, fill="#666")
        d.text((10, 57), "Passive 802.11 map", font=font, fill="#666")
    else:
        visible = aps[sc:sc + ROWS_VISIBLE - 1]
        for i, (bssid, clients) in enumerate(visible):
            y = 28 + i * ROW_H
            short = bssid[-8:]
            cnt = len(clients)
            marker = ">" if (sc + i) == sc else " "
            color = "#FFFF00" if i == 0 else "#CCCCCC"
            d.text((1, y), f"{marker}{short} [{cnt}]", font=font, fill=color)

        total = len(aps)
        if total > ROWS_VISIBLE - 1:
            bar_h = max(4, int((ROWS_VISIBLE - 1) / total * 88))
            bar_y = 28 + int(sc / total * 88) if total > 0 else 28
            d.rectangle((126, bar_y, 127, bar_y + bar_h), fill="#444")

    _draw_footer(d, f"APs:{len(aps)} RIGHT:clients")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_client_list(bssid, clients):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "CLIENTS")

    d.text((2, 15), f"AP: {bssid[-11:]}", font=font, fill="#FFFF00")
    d.text((80, 15), f"[{len(clients)}]", font=font, fill="#888")

    sorted_clients = sorted(clients)
    cs = client_scroll
    visible = sorted_clients[cs:cs + ROWS_VISIBLE - 1]
    for i, mac in enumerate(visible):
        y = 28 + i * ROW_H
        d.text((2, y), mac, font=font, fill="#CCCCCC")

    _draw_footer(d, "LEFT:back UP/DN:scroll")
    LCD.LCD_ShowImage(img, 0, 0)


def _show_message(line1, line2=""):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((10, 50), line1, font=font, fill="#00FF00")
    if line2:
        d.text((4, 65), line2, font=font, fill="#888")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global scroll_pos, client_scroll, stop_flag, ap_clients, pkt_count

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 20), "WIFI CLIENT MAP", font=font, fill="#00CCFF")
    d.text((4, 40), "Passive 802.11", font=font, fill="#888")
    d.text((4, 52), "association mapper", font=font, fill="#888")
    d.text((4, 72), "OK=Start/Stop", font=font, fill="#666")
    d.text((4, 84), "K1=Rescan K2=Export", font=font, fill="#666")
    d.text((4, 96), "K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.3)

    in_clients = False
    selected_bssid = None

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                stop_sniffing()
                if ap_clients:
                    export_loot()
                break

            if in_clients:
                if btn == "LEFT":
                    in_clients = False
                    client_scroll = 0
                    time.sleep(0.2)
                elif btn == "UP":
                    client_scroll = max(0, client_scroll - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        cl = ap_clients.get(selected_bssid, set())
                        mx = max(0, len(cl) - ROWS_VISIBLE + 1)
                    client_scroll = min(mx, client_scroll + 1)
                    time.sleep(0.15)

                with lock:
                    cl = set(ap_clients.get(selected_bssid, set()))
                draw_client_list(selected_bssid or "", cl)

            else:
                if btn == "OK":
                    with lock:
                        currently = sniffing
                    if currently:
                        stop_sniffing()
                    else:
                        start_sniffing()
                    time.sleep(0.3)

                elif btn == "KEY1":
                    stop_sniffing()
                    time.sleep(0.5)
                    with lock:
                        ap_clients = {}
                        pkt_count = 0
                    start_sniffing()
                    scroll_pos = 0
                    time.sleep(0.3)

                elif btn == "KEY2":
                    if ap_clients:
                        path = export_loot()
                        _show_message("Exported!", path[-20:])
                    time.sleep(0.3)

                elif btn == "RIGHT":
                    aps = _sorted_aps()
                    if aps and scroll_pos < len(aps):
                        selected_bssid = aps[scroll_pos][0]
                        in_clients = True
                        client_scroll = 0
                    time.sleep(0.2)

                elif btn == "UP":
                    scroll_pos = max(0, scroll_pos - 1)
                    time.sleep(0.15)

                elif btn == "DOWN":
                    mx = max(0, len(_sorted_aps()) - 1)
                    scroll_pos = min(mx, scroll_pos + 1)
                    time.sleep(0.15)

                draw_ap_list()

            time.sleep(0.05)

    finally:
        stop_sniffing()
        time.sleep(0.5)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
