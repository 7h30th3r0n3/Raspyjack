#!/usr/bin/env python3
"""
RaspyJack Payload -- Notification Center
==========================================
Author: 7h30th3r0n3

Aggregates notifications from all payloads.  Watches the loot directory
for new files and reads a structured notification log where payloads
append JSON-line events.

Setup / Prerequisites
---------------------
- RaspyJack base system with LCD hat.
- Payloads append events to /root/Raspyjack/loot/.notifications.jsonl
  Format: {"timestamp": ..., "source": ..., "message": ..., "severity": ...}
- Discord webhook URL in /root/Raspyjack/discord_webhook.txt (optional).

Controls
--------
  UP / DOWN  -- Scroll notifications (newest first)
  OK         -- Mark selected notification as read
  KEY1       -- Clear all notifications
  KEY2       -- Push unread notifications to Discord webhook
  KEY3       -- Exit
"""

import os
import sys
import json
import time
import threading
import urllib.request
import urllib.error

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
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
font = scaled_font()

LOOT_ROOT = "/root/Raspyjack/loot"
NOTIF_FILE = os.path.join(LOOT_ROOT, ".notifications.jsonl")
WEBHOOK_FILE = "/root/Raspyjack/discord_webhook.txt"
POLL_INTERVAL = 10
DEBOUNCE = 0.22

lock = threading.Lock()
_running = True

# Notifications: list of dicts, newest first
notifications = []
read_set = set()   # timestamps of read notifications
status_msg = ""


# ---------------------------------------------------------------------------
# Notification loading
# ---------------------------------------------------------------------------

def _load_notifications():
    """Parse the JSONL file and return a list sorted newest-first."""
    items = []
    if not os.path.isfile(NOTIF_FILE):
        return items
    try:
        with open(NOTIF_FILE, "r") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict) and "timestamp" in obj:
                        items.append(obj)
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    items.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return items


def _scan_new_loot_files():
    """Find loot files created in the last 5 minutes and generate notifications."""
    now = time.time()
    new_items = []
    try:
        for root, _dirs, files in os.walk(LOOT_ROOT):
            for fname in files:
                if fname.startswith("."):
                    continue
                full = os.path.join(root, fname)
                try:
                    mtime = os.path.getmtime(full)
                except OSError:
                    continue
                if (now - mtime) < 300:
                    rel = os.path.relpath(full, LOOT_ROOT)
                    ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(mtime))
                    new_items.append({
                        "timestamp": ts,
                        "source": "loot-watcher",
                        "message": f"New: {rel[:30]}",
                        "severity": "info",
                    })
    except OSError:
        pass
    return new_items


def _merge_notifications(base, extra):
    """Merge two notification lists, deduplicate by timestamp+message, newest first."""
    seen = set()
    merged = []
    for item in base + extra:
        key = (item.get("timestamp", ""), item.get("message", ""))
        if key not in seen:
            seen.add(key)
            merged.append(item)
    merged.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return merged


def _poll_thread():
    """Periodically reload notifications and scan for new loot."""
    global notifications, status_msg
    while _running:
        jsonl_items = _load_notifications()
        loot_items = _scan_new_loot_files()
        merged = _merge_notifications(jsonl_items, loot_items)
        with lock:
            notifications = merged

        deadline = time.time() + POLL_INTERVAL
        while _running and time.time() < deadline:
            time.sleep(0.5)


# ---------------------------------------------------------------------------
# Discord webhook
# ---------------------------------------------------------------------------

def _load_webhook_url():
    """Read webhook URL from file, or return None."""
    try:
        with open(WEBHOOK_FILE, "r") as fh:
            url = fh.read().strip()
        if url.startswith("http"):
            return url
    except OSError:
        pass
    return None


def _push_discord(items):
    """Send notification summaries to Discord webhook."""
    url = _load_webhook_url()
    if not url:
        return "No webhook URL"

    lines = []
    for item in items[:20]:
        sev = item.get("severity", "info").upper()
        src = item.get("source", "?")[:12]
        msg = item.get("message", "")[:60]
        lines.append(f"[{sev}] {src}: {msg}")

    payload = json.dumps({
        "content": f"**RaspyJack Notifications** ({len(items)} unread)\n```\n"
                   + "\n".join(lines) + "\n```"
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10):
            pass
        return f"Sent {len(items)} to Discord"
    except (urllib.error.URLError, OSError) as exc:
        return f"Err: {str(exc)[:16]}"


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

_SEV_COLORS = {
    "critical": "#ff2222",
    "warning": "#ffaa00",
    "info": "#00ff00",
}


def _draw_notifications(lcd, notifs, cursor, scroll, status=""):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#111")
    unread = sum(1 for n in notifs if n.get("timestamp", "") not in read_set)
    d.text((2, 1), f"NOTIF ({unread} new)", font=font, fill="#ffaa00")
    d.text((108, 1), "K3", font=font, fill="#888")

    y = 16
    visible = 6
    if not notifs:
        d.text((4, 50), "No notifications", font=font, fill="#666")
    else:
        end = min(len(notifs), scroll + visible)
        for i in range(scroll, end):
            n = notifs[i]
            marker = ">" if i == cursor else " "
            sev = n.get("severity", "info")
            color = _SEV_COLORS.get(sev, "#ccc")
            is_read = n.get("timestamp", "") in read_set
            if is_read:
                color = "#555"

            src = n.get("source", "?")[:6]
            msg = n.get("message", "")[:12]
            ts = n.get("timestamp", "")[-8:-3]  # HH:MM
            line = f"{marker}{ts} {src}: {msg}"
            d.text((2, y), line[:22], font=font, fill=color)
            y += 13

        # Scrollbar indicator
        if len(notifs) > visible:
            bar_h = max(10, int(visible / len(notifs) * 90))
            bar_y = 16 + int(scroll / max(1, len(notifs) - visible) * (90 - bar_h))
            d.rectangle((125, bar_y, 127, bar_y + bar_h), fill="#444")

    if status:
        d.rectangle((0, 92, 127, 105), fill="#222200")
        d.text((2, 94), status[:22], font=font, fill="#ffaa00")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:read K1:clr K2:push", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_confirm(lcd, message):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((10, 40), message, font=font, fill="#ff4444")
    d.text((10, 60), "OK = Yes", font=font, fill="#00ff00")
    d.text((10, 75), "Any = Cancel", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, notifications, read_set, status_msg

    initial = _load_notifications()
    loot_initial = _scan_new_loot_files()
    with lock:
        notifications = _merge_notifications(initial, loot_initial)

    poller = threading.Thread(target=_poll_thread, daemon=True)
    poller.start()

    cursor = 0
    scroll = 0
    last_press = 0.0
    visible = 6
    mode = "list"   # list | confirm_clear

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if mode == "confirm_clear":
                if btn == "OK":
                    with lock:
                        notifications = []
                    read_set = set()
                    # Truncate the file
                    try:
                        with open(NOTIF_FILE, "w") as fh:
                            pass
                    except OSError:
                        pass
                    status_msg = "Cleared all"
                    cursor = 0
                    scroll = 0
                    mode = "list"
                elif btn:
                    status_msg = "Cancelled"
                    mode = "list"
                if mode == "confirm_clear":
                    _draw_confirm(LCD, "Clear all notifs?")
                    time.sleep(0.08)
                    continue

            if btn == "KEY3":
                break
            elif btn == "UP":
                cursor = max(0, cursor - 1)
                if cursor < scroll:
                    scroll = cursor
                status_msg = ""
            elif btn == "DOWN":
                with lock:
                    max_idx = max(0, len(notifications) - 1)
                cursor = min(cursor + 1, max_idx)
                if cursor >= scroll + visible:
                    scroll = cursor - visible + 1
                status_msg = ""
            elif btn == "OK":
                with lock:
                    if notifications and 0 <= cursor < len(notifications):
                        ts = notifications[cursor].get("timestamp", "")
                        read_set = read_set | {ts}
                        status_msg = "Marked read"
            elif btn == "KEY1":
                mode = "confirm_clear"
                _draw_confirm(LCD, "Clear all notifs?")
                time.sleep(0.08)
                continue
            elif btn == "KEY2":
                with lock:
                    unread = [
                        n for n in notifications
                        if n.get("timestamp", "") not in read_set
                    ]
                if unread:
                    status_msg = "Sending..."
                    _draw_notifications(LCD, notifications, cursor, scroll, status_msg)
                    result = _push_discord(unread)
                    status_msg = result
                else:
                    status_msg = "Nothing to push"

            with lock:
                snap = list(notifications)
            _draw_notifications(LCD, snap, cursor, scroll, status_msg)
            time.sleep(0.08)

    finally:
        _running = False
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
