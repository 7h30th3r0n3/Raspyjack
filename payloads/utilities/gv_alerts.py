#!/usr/bin/env python3
"""
RaspyJack Payload -- Webhook Notification Alerts
==================================================
Author: 7h30th3r0n3

Monitors loot directory for new files and sends webhook notifications
(Slack, Discord, or generic JSON) when new loot is detected.

Controls
--------
  UP / DOWN   -- Scroll log messages
  KEY1        -- Start / stop monitoring
  KEY2        -- Send test alert
  KEY3        -- Exit
"""

import os
import sys
import time
import signal
import json
import threading
import urllib.request
import urllib.error
from datetime import datetime

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
CONFIG_DIR = "/root/Raspyjack/loot/Alerts"
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
LOOT_DIR = "/root/Raspyjack/loot"
DEBOUNCE = 0.25
MAX_LOG = 50

GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
font_sm = scaled_font(8)
font_md = scaled_font(10)

_running = True
_monitoring = False
_lock = threading.Lock()
_log_lines = []


def _cleanup(*_args):
    global _running, _monitoring
    _running = False
    _monitoring = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG = {
    "webhook_url": "",
    "webhook_type": "generic",
    "alert_types": [".cap", ".txt", ".creds", ".hash", ".xml"],
    "poll_interval": 10,
}


def _load_config():
    """Load webhook config from JSON."""
    if not os.path.isfile(CONFIG_PATH):
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(CONFIG_PATH, "w") as fh:
            json.dump(_DEFAULT_CONFIG, fh, indent=2)
        return dict(_DEFAULT_CONFIG)
    try:
        with open(CONFIG_PATH, "r") as fh:
            data = json.load(fh)
        return {
            "webhook_url": str(data.get("webhook_url", "")),
            "webhook_type": str(data.get("webhook_type", "generic")),
            "alert_types": list(data.get("alert_types", _DEFAULT_CONFIG["alert_types"])),
            "poll_interval": int(data.get("poll_interval", 10)),
        }
    except (json.JSONDecodeError, OSError, ValueError):
        return dict(_DEFAULT_CONFIG)


def _add_log(msg):
    """Thread-safe log append."""
    ts = datetime.now().strftime("%H:%M:%S")
    with _lock:
        _log_lines.append(f"{ts} {msg}")
        if len(_log_lines) > MAX_LOG:
            _log_lines.pop(0)


# ---------------------------------------------------------------------------
# Webhook sending
# ---------------------------------------------------------------------------

def _send_webhook(config, message):
    """Send webhook notification. Returns True on success."""
    url = config["webhook_url"]
    if not url:
        _add_log("No webhook URL set")
        return False

    wh_type = config["webhook_type"]
    if wh_type == "slack":
        payload = {"text": message}
    elif wh_type == "discord":
        payload = {"content": message}
    else:
        payload = {"message": message, "source": "raspyjack", "timestamp": datetime.now().isoformat()}

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.getcode()
        if 200 <= status < 300:
            _add_log(f"Sent OK ({status})")
            return True
        _add_log(f"HTTP {status}")
        return False
    except urllib.error.URLError as exc:
        _add_log(f"Err: {str(exc)[:30]}")
        return False
    except OSError as exc:
        _add_log(f"Err: {str(exc)[:30]}")
        return False


# ---------------------------------------------------------------------------
# File monitoring
# ---------------------------------------------------------------------------

def _snapshot_loot(alert_types):
    """Return set of (path, mtime) for matching files in loot dir."""
    snapshot = set()
    if not os.path.isdir(LOOT_DIR):
        return snapshot
    for root, _dirs, filenames in os.walk(LOOT_DIR):
        if "Alerts" in root or "Stats" in root:
            continue
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if not alert_types or ext in alert_types:
                fpath = os.path.join(root, fname)
                try:
                    mtime = os.path.getmtime(fpath)
                    snapshot.add((fpath, mtime))
                except OSError:
                    pass
    return snapshot


def _monitor_worker(config):
    """Background monitoring thread."""
    global _monitoring
    alert_types = config["alert_types"]
    interval = max(3, config["poll_interval"])

    _add_log("Monitoring started")
    baseline = _snapshot_loot(alert_types)

    while _running and _monitoring:
        for _ in range(int(interval * 10)):
            if not _running or not _monitoring:
                return
            time.sleep(0.1)

        current = _snapshot_loot(alert_types)
        new_files = current - baseline

        if new_files:
            count = len(new_files)
            names = [os.path.basename(p) for p, _ in list(new_files)[:3]]
            msg = f"RaspyJack: {count} new loot file(s): {', '.join(names)}"
            _add_log(f"New: {count} file(s)")
            _send_webhook(config, msg)

        baseline = current

    _add_log("Monitoring stopped")


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(d, monitoring):
    """Draw header bar."""
    bg = (0, 80, 0) if monitoring else (80, 40, 0)
    d.rectangle([0, 0, 127, 13], fill=bg)
    status = "ACTIVE" if monitoring else "STOPPED"
    d.text((2, 1), f"Alerts [{status}]", fill=(255, 255, 255), font=font_md)


def _draw_footer(d, text):
    """Draw footer bar."""
    d.rectangle([0, 116, 127, 127], fill=(40, 40, 40))
    d.text((2, 117), text, fill=(180, 180, 180), font=font_sm)


def _draw_log(d, scroll_pos):
    """Draw log messages."""
    with _lock:
        lines = list(_log_lines)
    y_start = 16
    visible = 8
    end = min(scroll_pos + visible, len(lines))
    for i in range(scroll_pos, end):
        row_y = y_start + (i - scroll_pos) * 12
        line = lines[i][:22]
        d.text((2, row_y), line, fill=(180, 180, 180), font=font_sm)


def _render(scroll_pos, status_msg):
    """Render full frame."""
    img = Image.new("RGB", (WIDTH, HEIGHT), (0, 0, 0))
    d = ScaledDraw(img)

    _draw_header(d, _monitoring)
    _draw_log(d, scroll_pos)
    _draw_footer(d, status_msg)

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    global _monitoring

    config = _load_config()
    scroll_pos = 0
    status_msg = "K1:Start K2:Test"
    last_input = 0.0
    monitor_thread = None

    if not config["webhook_url"]:
        _add_log("Edit config.json")
        _add_log(CONFIG_PATH)
    else:
        _add_log(f"Type: {config['webhook_type']}")
        _add_log(f"URL: ...{config['webhook_url'][-20:]}")

    while _running:
        now = time.time()

        btn = get_button(PINS, GPIO)
        if btn and (now - last_input) > DEBOUNCE:
            last_input = now

            if btn == "KEY3":
                _monitoring = False
                _cleanup()
                break

            elif btn == "UP":
                scroll_pos = max(0, scroll_pos - 1)

            elif btn == "DOWN":
                with _lock:
                    max_scroll = max(0, len(_log_lines) - 8)
                scroll_pos = min(scroll_pos + 1, max_scroll)

            elif btn == "KEY1":
                if _monitoring:
                    _monitoring = False
                    _add_log("Stopping...")
                    status_msg = "Stopped"
                else:
                    config = _load_config()
                    _monitoring = True
                    monitor_thread = threading.Thread(
                        target=_monitor_worker, args=(config,), daemon=True,
                    )
                    monitor_thread.start()
                    status_msg = "Monitoring..."

            elif btn == "KEY2":
                config = _load_config()
                _add_log("Sending test...")
                ok = _send_webhook(config, "RaspyJack test alert - webhook configured successfully.")
                status_msg = "Test OK" if ok else "Test failed"

        _render(scroll_pos, status_msg)
        time.sleep(0.1)


if __name__ == "__main__":
    try:
        main()
    finally:
        _monitoring = False
        LCD.LCD_Clear()
        GPIO.cleanup()
