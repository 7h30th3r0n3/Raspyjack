#!/usr/bin/env python3
"""
RaspyJack Payload -- Device Flock Detector
===========================================
Author: 7h30th3r0n3

Monitors WiFi probe requests via tcpdump on a monitor-mode interface
(wlan1mon) and detects "flocks" -- groups of devices that consistently
appear and disappear together within a correlation window.

Controls:
  UP / DOWN  -- Scroll flock list
  OK         -- View member MACs of selected flock
  KEY1       -- Reset all detection data
  KEY2       -- Export flocks to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/FlockDetect/<timestamp>.json
"""

import os
import sys
import json
import time
import re
import subprocess
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

# ---------------------------------------------------------------------------
# Pin / LCD setup
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT

LOOT_DIR = "/root/Raspyjack/loot/FlockDetect"
IFACE = "wlan1mon"
CORRELATION_WINDOW = 30  # seconds
ROW_H = 12
ROWS_VISIBLE = 6

# ---------------------------------------------------------------------------
# Common OUI vendor lookup (~30 vendors)
# ---------------------------------------------------------------------------
OUI_DB = {
    "00:50:56": "VMware",   "00:0C:29": "VMware",   "08:00:27": "VBox",
    "B8:27:EB": "RaspPi",   "DC:A6:32": "RaspPi",   "E4:5F:01": "RaspPi",
    "D8:3A:DD": "RaspPi",   "AC:DE:48": "Apple",    "00:1C:B3": "Apple",
    "A4:83:E7": "Apple",    "F0:18:98": "Apple",     "34:02:86": "Apple",
    "00:25:00": "Apple",    "FC:F1:36": "Samsung",   "A0:CC:2B": "Samsung",
    "8C:F5:A3": "Samsung",  "78:02:F8": "Xiaomi",   "50:EC:50": "Xiaomi",
    "3C:5A:B4": "Google",   "F4:F5:D8": "Google",   "00:1A:2B": "Cisco",
    "00:1B:44": "Cisco",    "00:26:CB": "Cisco",     "00:17:C4": "Quanta",
    "40:B0:76": "ASUSTek",  "1C:87:2C": "ECSI",     "E8:48:B8": "Dell",
    "00:0D:93": "Apple",    "F8:1E:DF": "Apple",     "CC:08:E0": "Apple",
    "88:E9:FE": "Apple",    "00:03:93": "Apple",
}


def _oui_lookup(mac):
    """Return vendor name for a MAC address or empty string."""
    prefix = mac.upper()[:8]
    return OUI_DB.get(prefix, "")


# ---------------------------------------------------------------------------
# Shared state (protected by lock)
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True
capturing = False
status_msg = "Idle"
scroll_pos = 0
selected_idx = 0

# mac -> list of timestamps (floats)
mac_timestamps = {}
# Computed flocks: list of {"members": [mac, ...], "first_seen": str,
#                            "score": int, "last_update": float}
flocks = []


# ---------------------------------------------------------------------------
# Probe capture thread
# ---------------------------------------------------------------------------
def _parse_mac(line):
    """Extract source MAC from a tcpdump -e line."""
    match = re.search(r"([\da-fA-F]{2}:){5}[\da-fA-F]{2}", line)
    if match:
        return match.group(0).upper()
    return None


def _capture_thread():
    """Run tcpdump and record MAC timestamps."""
    global capturing, status_msg

    cmd = [
        "tcpdump", "-i", IFACE, "-e", "-l",
        "type", "mgt", "subtype", "probe-req",
    ]
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        with lock:
            status_msg = "tcpdump not found"
            capturing = False
        return
    except Exception as exc:
        with lock:
            status_msg = f"Err: {str(exc)[:14]}"
            capturing = False
        return

    with lock:
        status_msg = "Capturing probes..."
        capturing = True

    try:
        while running:
            line = proc.stdout.readline()
            if not line:
                break
            mac = _parse_mac(line)
            if mac and mac != "FF:FF:FF:FF:FF:FF":
                now = time.time()
                with lock:
                    timestamps = mac_timestamps.get(mac, [])
                    timestamps = [*timestamps, now]
                    mac_timestamps[mac] = timestamps
    except Exception:
        pass
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        with lock:
            capturing = False
            if "Err" not in status_msg:
                status_msg = "Capture stopped"


# ---------------------------------------------------------------------------
# Flock correlation algorithm
# ---------------------------------------------------------------------------
def _compute_flocks():
    """Group MACs that appear/disappear within CORRELATION_WINDOW."""
    with lock:
        snapshot = {
            mac: list(ts) for mac, ts in mac_timestamps.items()
        }

    if len(snapshot) < 2:
        return []

    macs = list(snapshot.keys())
    now = time.time()

    # Build presence windows (simplified: group timestamps into buckets)
    bucket_size = CORRELATION_WINDOW
    all_times = []
    for ts_list in snapshot.values():
        all_times.extend(ts_list)
    if not all_times:
        return []

    min_t = min(all_times)
    max_t = max(all_times)
    num_buckets = max(1, int((max_t - min_t) / bucket_size) + 1)

    # For each MAC, compute which buckets it was active in
    mac_buckets = {}
    for mac, ts_list in snapshot.items():
        buckets = set()
        for t in ts_list:
            b = int((t - min_t) / bucket_size)
            buckets.add(b)
        mac_buckets[mac] = frozenset(buckets)

    # Find MACs with overlapping bucket patterns
    # Jaccard similarity >= 0.5 means they move together
    used = set()
    computed = []

    for i, mac_a in enumerate(macs):
        if mac_a in used:
            continue
        group = [mac_a]
        buckets_a = mac_buckets[mac_a]
        if not buckets_a:
            continue

        for j in range(i + 1, len(macs)):
            mac_b = macs[j]
            if mac_b in used:
                continue
            buckets_b = mac_buckets[mac_b]
            if not buckets_b:
                continue

            intersection = len(buckets_a & buckets_b)
            union = len(buckets_a | buckets_b)
            if union == 0:
                continue
            jaccard = intersection / union
            if jaccard >= 0.5:
                group.append(mac_b)

        if len(group) >= 2:
            for m in group:
                used.add(m)

            # Find first seen time
            first_ts = min(
                snapshot[m][0] for m in group if snapshot[m]
            )
            first_seen_str = datetime.fromtimestamp(first_ts).strftime(
                "%H:%M:%S"
            )

            # Consistency score (average Jaccard within group)
            scores = []
            for gi in range(len(group)):
                for gj in range(gi + 1, len(group)):
                    ba = mac_buckets[group[gi]]
                    bb = mac_buckets[group[gj]]
                    union_sz = len(ba | bb)
                    if union_sz > 0:
                        scores.append(len(ba & bb) / union_sz)
            avg_score = int(sum(scores) / max(len(scores), 1) * 100)

            computed.append({
                "members": group,
                "first_seen": first_seen_str,
                "score": avg_score,
                "last_update": now,
            })

    return computed


# ---------------------------------------------------------------------------
# Loot export
# ---------------------------------------------------------------------------
def _export_loot():
    """Write flock data to JSON loot file."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"flock_{ts}.json")

    with lock:
        flock_data = []
        for f in flocks:
            entry = {
                "members": [
                    {"mac": m, "vendor": _oui_lookup(m)} for m in f["members"]
                ],
                "device_count": len(f["members"]),
                "first_seen": f["first_seen"],
                "consistency_score": f["score"],
            }
            flock_data.append(entry)

        total_macs = len(mac_timestamps)

    data = {
        "timestamp": ts,
        "interface": IFACE,
        "total_macs_seen": total_macs,
        "flocks_detected": len(flock_data),
        "flocks": flock_data,
    }

    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)

    return filepath


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------
def _draw_header(d, font, active):
    """Draw header bar."""
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "FLOCK DETECT", font=font, fill="#FF6600")
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if active else "#FF0000")


def _draw_footer(d, font, text):
    """Draw footer bar."""
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font, fill="#AAA")


def _draw_main(lcd, font):
    """Render the main flock list view."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        active = capturing
        st = status_msg
        total_macs = len(mac_timestamps)
        flock_list = list(flocks)
        sel = selected_idx
        sc = scroll_pos

    _draw_header(d, font, active)

    d.text((2, 15), f"{st[:18]} MACs:{total_macs}", font=font, fill="#888")

    if not flock_list:
        d.text((6, 40), "Waiting for probes", font=font, fill="#666")
        d.text((6, 52), "Detecting correlated", font=font, fill="#666")
        d.text((6, 64), "device groups...", font=font, fill="#666")
        d.text((6, 80), f"Window: {CORRELATION_WINDOW}s", font=font, fill="#555")
    else:
        visible = flock_list[sc:sc + ROWS_VISIBLE]
        for i, flock in enumerate(visible):
            y = 28 + i * ROW_H
            idx = sc + i
            prefix = ">" if idx == sel else " "
            count = len(flock["members"])
            score = flock["score"]
            first = flock["first_seen"]
            color = "#00FF00" if score >= 70 else "#FFAA00" if score >= 40 else "#FF4444"
            line = f"{prefix}{count}dev {first} {score}%"
            d.text((1, y), line[:22], font=font, fill=color)

        total_items = len(flock_list)
        if total_items > ROWS_VISIBLE:
            bar_h = max(4, int(ROWS_VISIBLE / total_items * 80))
            bar_y = 28 + int(sc / total_items * 80)
            d.rectangle((126, bar_y, 127, bar_y + bar_h), fill="#444")

    _draw_footer(d, font, f"Flk:{len(flock_list)} OK:View K3:Exit")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_flock_detail(lcd, font, flock):
    """Show member MACs of a single flock."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), f"FLOCK ({len(flock['members'])} dev)", font=font, fill="#FF6600")

    d.text((2, 16), f"Score: {flock['score']}%  @{flock['first_seen']}", font=font, fill="#AAA")

    members = flock["members"]
    for i, mac in enumerate(members[:7]):
        y = 30 + i * ROW_H
        vendor = _oui_lookup(mac)
        short_mac = mac[6:]  # remove first 3 octets for space
        vendor_str = vendor[:6] if vendor else "???"
        d.text((2, y), f"{short_mac} {vendor_str}", font=font, fill="#00CCFF")

    if len(members) > 7:
        d.text((2, 30 + 7 * ROW_H), f"+{len(members) - 7} more", font=font, fill="#888")

    _draw_footer(d, font, "Any key: back")
    lcd.LCD_ShowImage(img, 0, 0)


def _show_message(lcd, font, line1, line2=""):
    """Show a brief message."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((10, 50), line1, font=font, fill="#00FF00")
    if line2:
        d.text((4, 65), line2, font=font, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global running, scroll_pos, selected_idx, flocks
    global mac_timestamps

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font = scaled_font()

    # Splash screen
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 16), "FLOCK DETECTOR", font=font, fill="#FF6600")
    d.text((4, 32), "Finds device groups", font=font, fill="#888")
    d.text((4, 44), "moving together via", font=font, fill="#888")
    d.text((4, 56), "WiFi probe requests", font=font, fill="#888")
    d.text((4, 72), f"Iface: {IFACE}", font=font, fill="#666")
    d.text((4, 84), "K1:Reset K2:Export", font=font, fill="#666")
    d.text((4, 96), "K3:Exit", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)

    # Start capture thread
    running = True
    threading.Thread(target=_capture_thread, daemon=True).start()

    last_flock_update = 0.0
    detail_view = False

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                running = False
                if flocks:
                    _export_loot()
                break

            if detail_view:
                if btn is not None:
                    detail_view = False
                    time.sleep(0.2)
            else:
                if btn == "OK":
                    with lock:
                        flock_list = list(flocks)
                        sel = selected_idx
                    if flock_list and 0 <= sel < len(flock_list):
                        _draw_flock_detail(lcd, font, flock_list[sel])
                        detail_view = True
                    time.sleep(0.3)

                elif btn == "KEY1":
                    with lock:
                        mac_timestamps = {}
                        flocks = []
                        scroll_pos = 0
                        selected_idx = 0
                    _show_message(lcd, font, "Data reset")
                    time.sleep(0.2)

                elif btn == "KEY2":
                    with lock:
                        has_data = len(flocks) > 0 or len(mac_timestamps) > 0
                    if has_data:
                        path = _export_loot()
                        _show_message(lcd, font, "Exported!", path[-20:])
                    else:
                        _show_message(lcd, font, "No data yet")
                    time.sleep(0.3)

                elif btn == "UP":
                    with lock:
                        selected_idx = max(0, selected_idx - 1)
                        if selected_idx < scroll_pos:
                            scroll_pos = selected_idx
                    time.sleep(0.15)

                elif btn == "DOWN":
                    with lock:
                        max_sel = max(0, len(flocks) - 1)
                        selected_idx = min(selected_idx + 1, max_sel)
                        if selected_idx >= scroll_pos + ROWS_VISIBLE:
                            scroll_pos = selected_idx - ROWS_VISIBLE + 1
                    time.sleep(0.15)

            # Periodically recompute flocks
            now = time.time()
            if now - last_flock_update > 5.0:
                new_flocks = _compute_flocks()
                with lock:
                    flocks = new_flocks
                last_flock_update = now

            if not detail_view:
                _draw_main(lcd, font)

            time.sleep(0.05)

    finally:
        running = False
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
