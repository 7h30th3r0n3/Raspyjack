#!/usr/bin/env python3
"""
RaspyJack Payload -- Attack Statistics Dashboard
=================================================
Author: 7h30th3r0n3

Aggregates statistics from /root/Raspyjack/loot/ subdirectories.
Shows total handshakes, credentials, scans, hosts, file counts by
extension, and a 24-hour activity timeline bar chart.

Controls
--------
  UP / DOWN   -- Scroll through stat categories
  KEY1        -- Refresh stats
  KEY2        -- Export summary to loot dir
  KEY3        -- Exit
"""

import os
import sys
import time
import signal
import json
import threading
from datetime import datetime
from collections import defaultdict

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
LOOT_DIR = "/root/Raspyjack/loot"
EXPORT_DIR = os.path.join(LOOT_DIR, "Stats")
DEBOUNCE = 0.20

GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
font_sm = scaled_font(8)
font_md = scaled_font(10)

_running = True
_lock = threading.Lock()


def _cleanup(*_args):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# Stats collection
# ---------------------------------------------------------------------------

def _walk_loot():
    """Walk loot directory and collect file metadata."""
    files_by_ext = defaultdict(int)
    timestamps = []
    total_files = 0

    if not os.path.isdir(LOOT_DIR):
        return dict(files_by_ext), timestamps, total_files

    for root, _dirs, filenames in os.walk(LOOT_DIR):
        for fname in filenames:
            total_files += 1
            ext = os.path.splitext(fname)[1].lower()
            if ext:
                files_by_ext[ext] += 1
            fpath = os.path.join(root, fname)
            try:
                mtime = os.path.getmtime(fpath)
                timestamps.append(mtime)
            except OSError:
                pass

    return dict(files_by_ext), timestamps, total_files


def _count_by_ext(files_by_ext, extensions):
    """Sum counts for a list of extensions."""
    return sum(files_by_ext.get(e, 0) for e in extensions)


def _build_hourly_histogram(timestamps):
    """Build 24-element list of activity counts per hour (last 24h)."""
    now = time.time()
    cutoff = now - 86400
    histogram = [0] * 24
    for ts in timestamps:
        if ts >= cutoff:
            hour = int((ts - cutoff) / 3600)
            if 0 <= hour < 24:
                histogram[hour] += 1
    return histogram


def _gather_stats():
    """Gather all attack statistics from loot directory."""
    files_by_ext, timestamps, total_files = _walk_loot()
    handshakes = _count_by_ext(files_by_ext, [".cap", ".pcap", ".hccapx"])
    credentials = _count_by_ext(files_by_ext, [".txt", ".creds", ".hash"])
    scans = _count_by_ext(files_by_ext, [".xml", ".nmap", ".gnmap"])
    hosts = _count_by_ext(files_by_ext, [".host", ".csv"])
    histogram = _build_hourly_histogram(timestamps)

    categories = [
        ("Total Files", str(total_files)),
        ("Handshakes", str(handshakes)),
        ("Credentials", str(credentials)),
        ("Scan Results", str(scans)),
        ("Host Files", str(hosts)),
    ]

    top_exts = sorted(files_by_ext.items(), key=lambda kv: kv[1], reverse=True)[:5]
    for ext, count in top_exts:
        categories.append((f"  {ext}", str(count)))

    return categories, histogram, total_files


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_summary(categories, histogram):
    """Write a JSON summary to the export directory."""
    os.makedirs(EXPORT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(EXPORT_DIR, f"stats_{ts}.json")
    data = {
        "timestamp": ts,
        "categories": {k: v for k, v in categories},
        "hourly_activity_24h": histogram,
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(d, text):
    """Draw header bar."""
    d.rectangle([0, 0, 127, 13], fill=(0, 80, 0))
    d.text((2, 1), text, fill=(0, 255, 0), font=font_md)


def _draw_footer(d, text):
    """Draw footer bar."""
    d.rectangle([0, 116, 127, 127], fill=(40, 40, 40))
    d.text((2, 117), text, fill=(180, 180, 180), font=font_sm)


def _draw_categories(d, categories, scroll_pos):
    """Draw scrollable category list."""
    y_start = 16
    visible = 4
    end = min(scroll_pos + visible, len(categories))
    for i in range(scroll_pos, end):
        label, value = categories[i]
        row_y = y_start + (i - scroll_pos) * 11
        d.text((2, row_y), label, fill=(200, 200, 200), font=font_sm)
        d.text((80, row_y), value, fill=(0, 255, 0), font=font_sm)


def _draw_histogram(d, histogram):
    """Draw a 24-bar activity chart in the lower area."""
    if not histogram:
        return
    max_val = max(histogram) if max(histogram) > 0 else 1
    bar_area_top = 70
    bar_area_bottom = 114
    bar_height = bar_area_bottom - bar_area_top
    bar_w = 4
    gap = 1
    start_x = 4

    d.text((2, 62), "24h Activity", fill=(0, 200, 200), font=font_sm)

    for i, count in enumerate(histogram):
        x = start_x + i * (bar_w + gap)
        h = int((count / max_val) * bar_height) if count > 0 else 0
        if h < 1 and count > 0:
            h = 1
        y_top = bar_area_bottom - h
        color = (0, 200, 200) if i % 2 == 0 else (0, 150, 150)
        d.rectangle([x, y_top, x + bar_w - 1, bar_area_bottom], fill=color)


def _render(categories, histogram, scroll_pos, status_msg):
    """Render the full dashboard frame."""
    img = Image.new("RGB", (WIDTH, HEIGHT), (0, 0, 0))
    d = ScaledDraw(img)

    _draw_header(d, "HackStats")
    _draw_categories(d, categories, scroll_pos)
    _draw_histogram(d, histogram)
    _draw_footer(d, status_msg)

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Background refresh
# ---------------------------------------------------------------------------

_stats_cache = ([], [], 0)


def _refresh_worker():
    """Background stats refresh."""
    global _stats_cache
    while _running:
        result = _gather_stats()
        with _lock:
            _stats_cache = result
        for _ in range(100):
            if not _running:
                return
            time.sleep(0.1)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    global _stats_cache

    categories, histogram, total = _gather_stats()
    with _lock:
        _stats_cache = (categories, histogram, total)

    worker = threading.Thread(target=_refresh_worker, daemon=True)
    worker.start()

    scroll_pos = 0
    status_msg = "K1:Refresh K2:Export"
    last_input = 0.0

    while _running:
        now = time.time()

        btn = get_button(PINS, GPIO)
        if btn and (now - last_input) > DEBOUNCE:
            last_input = now

            if btn == "KEY3":
                _cleanup()
                break

            elif btn == "UP":
                scroll_pos = max(0, scroll_pos - 1)

            elif btn == "DOWN":
                with _lock:
                    max_scroll = max(0, len(_stats_cache[0]) - 4)
                scroll_pos = min(scroll_pos + 1, max_scroll)

            elif btn == "KEY1":
                status_msg = "Refreshing..."
                new_stats = _gather_stats()
                with _lock:
                    _stats_cache = new_stats
                scroll_pos = 0
                status_msg = "Updated " + datetime.now().strftime("%H:%M")

            elif btn == "KEY2":
                with _lock:
                    cats = list(_stats_cache[0])
                    hist = list(_stats_cache[1])
                try:
                    _export_summary(cats, hist)
                    status_msg = "Exported!"
                except OSError:
                    status_msg = "Export failed"

        with _lock:
            cats = list(_stats_cache[0])
            hist = list(_stats_cache[1])

        _render(cats, hist, scroll_pos, status_msg)
        time.sleep(0.1)


if __name__ == "__main__":
    try:
        main()
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
