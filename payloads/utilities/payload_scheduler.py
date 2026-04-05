#!/usr/bin/env python3
"""
RaspyJack Payload -- Payload Scheduler
=======================================
Author: 7h30th3r0n3

Cron-like payload scheduler.  Configure payload path and schedule
(once at a specific time, or repeat every N minutes).  Stores the
schedule in a JSON file and launches payloads as subprocesses.

Setup / Prerequisites
---------------------
- RaspyJack base system with LCD hat.
- Payloads located under /root/Raspyjack/payloads/.

Controls
--------
  UP / DOWN  -- Scroll schedule entries
  OK         -- Toggle selected entry on / off
  KEY1       -- Add new entry (scroll available payloads)
  KEY2       -- Remove selected entry
  KEY3       -- Exit
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

SCHEDULE_DIR = "/root/Raspyjack/config/scheduler"
SCHEDULE_FILE = os.path.join(SCHEDULE_DIR, "schedule.json")
PAYLOADS_ROOT = "/root/Raspyjack/payloads"
CHECK_INTERVAL = 30
DEBOUNCE = 0.22

lock = threading.Lock()
_running = True

def _load_schedule():
    """Load schedule entries from disk, returning a new list."""
    if not os.path.isfile(SCHEDULE_FILE):
        return []
    try:
        with open(SCHEDULE_FILE, "r") as fh:
            data = json.load(fh)
        if not isinstance(data, list):
            return []
        return data
    except (json.JSONDecodeError, OSError):
        return []

def _save_schedule(entries):
    """Persist schedule entries to disk."""
    os.makedirs(SCHEDULE_DIR, exist_ok=True)
    try:
        with open(SCHEDULE_FILE, "w") as fh:
            json.dump(entries, fh, indent=2)
    except OSError:
        pass

def _discover_payloads():
    """Scan payloads directory for .py files."""
    found = []
    if not os.path.isdir(PAYLOADS_ROOT):
        return found
    for root, _dirs, files in os.walk(PAYLOADS_ROOT):
        for fname in sorted(files):
            if fname.endswith(".py") and not fname.startswith("_"):
                rel = os.path.relpath(os.path.join(root, fname), PAYLOADS_ROOT)
                found.append(rel)
    return found

running_procs = {}   # entry_id -> subprocess.Popen

def _next_run_str(entry):
    """Compute a human-readable next-run string."""
    mode = entry.get("mode", "repeat")
    if mode == "once":
        target = entry.get("at", "??:??")
        return f"@{target}"
    interval = entry.get("interval_min", 10)
    last = entry.get("_last_run", 0)
    if last == 0:
        return "now"
    remaining = max(0, int(interval * 60 - (time.time() - last)))
    return f"{remaining}s"

def _should_run(entry):
    """Check whether an entry should fire now."""
    if not entry.get("enabled", True):
        return False
    eid = entry.get("id", "")
    if eid in running_procs:
        proc = running_procs[eid]
        if proc.poll() is None:
            return False
        del running_procs[eid]

    mode = entry.get("mode", "repeat")
    now = time.time()

    if mode == "once":
        if entry.get("_done"):
            return False
        target = entry.get("at", "")
        try:
            hh, mm = target.split(":")
            today = datetime.now().replace(hour=int(hh), minute=int(mm), second=0, microsecond=0)
            diff = abs(now - today.timestamp())
            return diff < CHECK_INTERVAL
        except (ValueError, AttributeError):
            return False

    interval = entry.get("interval_min", 10) * 60
    last = entry.get("_last_run", 0)
    return (now - last) >= interval

def _launch_payload(entry):
    """Start the payload as a subprocess."""
    path = os.path.join(PAYLOADS_ROOT, entry.get("payload", ""))
    if not os.path.isfile(path):
        return
    try:
        proc = subprocess.Popen(
            ["python3", path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        eid = entry.get("id", "")
        running_procs[eid] = proc
    except OSError:
        pass

def _scheduler_thread(entries_ref):
    """Background loop that checks and launches payloads."""
    while _running:
        with lock:
            entries = list(entries_ref)

        now = time.time()
        changed = False
        for entry in entries:
            if _should_run(entry):
                _launch_payload(entry)
                entry["_last_run"] = now
                if entry.get("mode") == "once":
                    entry["_done"] = True
                changed = True

        if changed:
            with lock:
                entries_ref.clear()
                entries_ref.extend(entries)
            _save_schedule(entries)

        deadline = time.time() + CHECK_INTERVAL
        while _running and time.time() < deadline:
            time.sleep(0.5)

class AddWizard:
    """State for the add-entry sub-screen."""
    __slots__ = ("active", "step", "payloads", "sel", "mode", "interval", "at_hh", "at_mm")

    def __init__(self):
        self.active = False
        self.step = 0          # 0=pick payload, 1=pick mode, 2=params, 3=confirm
        self.payloads = []
        self.sel = 0
        self.mode = "repeat"
        self.interval = 10
        self.at_hh = 12
        self.at_mm = 0

    def reset(self):
        self.active = False
        self.step = 0
        self.sel = 0
        self.mode = "repeat"
        self.interval = 10

def _draw_schedule(lcd, entries, cursor, scroll, status=""):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "SCHEDULER", font=font, fill="#00ccff")
    d.text((108, 1), "K3", font=font, fill="#888")

    y = 16
    visible = 6
    if not entries:
        d.text((4, 50), "No entries", font=font, fill="#666")
        d.text((4, 64), "K1 to add", font=font, fill="#888")
    else:
        end = min(len(entries), scroll + visible)
        for i in range(scroll, end):
            e = entries[i]
            marker = ">" if i == cursor else " "
            enabled_c = "#00ff00" if e.get("enabled", True) else "#ff4444"
            name = os.path.basename(e.get("payload", "?"))[:10]
            nxt = _next_run_str(e)
            eid = e.get("id", "")[: 0]  # not shown
            is_running = e.get("id", "") in running_procs
            run_mark = "*" if is_running else " "
            line = f"{marker}{run_mark}{name} {nxt}"
            d.text((2, y), line[:21], font=font, fill=enabled_c)
            y += 13

    if status:
        d.rectangle((0, 92, 127, 105), fill="#222200")
        d.text((2, 94), status[:22], font=font, fill="#ffaa00")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:tog K1+ K2- K3:ex", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)

def _draw_wizard(lcd, wiz):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "ADD ENTRY", font=font, fill="#ffaa00")

    if wiz.step == 0:
        d.text((2, 16), "Select payload:", font=font, fill="#aaa")
        y = 30
        visible = 5
        start = max(0, wiz.sel - 2)
        end = min(len(wiz.payloads), start + visible)
        for i in range(start, end):
            marker = ">" if i == wiz.sel else " "
            name = os.path.basename(wiz.payloads[i])[:18]
            color = "#ffaa00" if i == wiz.sel else "#ccc"
            d.text((2, y), f"{marker}{name}", font=font, fill=color)
            y += 13
        d.text((2, 110), "^v:pick OK:select", font=font, fill="#666")

    elif wiz.step == 1:
        d.text((2, 20), "Mode:", font=font, fill="#aaa")
        modes = ["repeat", "once"]
        for idx, m in enumerate(modes):
            marker = ">" if modes[idx] == wiz.mode else " "
            color = "#ffaa00" if modes[idx] == wiz.mode else "#ccc"
            d.text((2, 36 + idx * 14), f"{marker}{m}", font=font, fill=color)
        d.text((2, 110), "^v:pick OK:next", font=font, fill="#666")

    elif wiz.step == 2:
        if wiz.mode == "repeat":
            d.text((2, 30), f"Every {wiz.interval} min", font=font, fill="#00ff00")
            d.text((2, 50), "UP/DOWN to adjust", font=font, fill="#aaa")
        else:
            d.text((2, 30), f"At {wiz.at_hh:02d}:{wiz.at_mm:02d}", font=font, fill="#00ff00")
            d.text((2, 50), "UP/DN=hour L/R=min", font=font, fill="#aaa")
        d.text((2, 110), "OK:confirm", font=font, fill="#666")

    d.text((108, 1), "K3", font=font, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)

def main():
    global _running

    entries = _load_schedule()
    for e in entries:
        if "id" not in e:
            e["id"] = f"{e.get('payload', 'x')}_{id(e)}"

    sched_thread = threading.Thread(
        target=_scheduler_thread, args=(entries,), daemon=True,
    )
    sched_thread.start()

    cursor = 0
    scroll = 0
    status = ""
    last_press = 0.0
    wiz = AddWizard()
    visible = 6

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            # -- Wizard mode --------------------------------------------------
            if wiz.active:
                if btn == "KEY3":
                    wiz.reset()
                elif wiz.step == 0:
                    if btn == "UP":
                        wiz.sel = max(0, wiz.sel - 1)
                    elif btn == "DOWN":
                        wiz.sel = min(len(wiz.payloads) - 1, wiz.sel + 1)
                    elif btn == "OK" and wiz.payloads:
                        wiz.step = 1
                elif wiz.step == 1:
                    if btn == "UP" or btn == "DOWN":
                        wiz.mode = "once" if wiz.mode == "repeat" else "repeat"
                    elif btn == "OK":
                        wiz.step = 2
                elif wiz.step == 2:
                    if wiz.mode == "repeat":
                        if btn == "UP":
                            wiz.interval = min(1440, wiz.interval + 5)
                        elif btn == "DOWN":
                            wiz.interval = max(1, wiz.interval - 5)
                    else:
                        if btn == "UP":
                            wiz.at_hh = (wiz.at_hh + 1) % 24
                        elif btn == "DOWN":
                            wiz.at_hh = (wiz.at_hh - 1) % 24
                        elif btn == "LEFT":
                            wiz.at_mm = (wiz.at_mm - 5) % 60
                        elif btn == "RIGHT":
                            wiz.at_mm = (wiz.at_mm + 5) % 60
                    if btn == "OK":
                        new_entry = {
                            "id": f"sched_{int(time.time())}",
                            "payload": wiz.payloads[wiz.sel],
                            "enabled": True,
                            "mode": wiz.mode,
                            "_last_run": 0,
                        }
                        if wiz.mode == "repeat":
                            new_entry["interval_min"] = wiz.interval
                        else:
                            new_entry["at"] = f"{wiz.at_hh:02d}:{wiz.at_mm:02d}"
                        with lock:
                            entries.append(new_entry)
                        _save_schedule(entries)
                        status = "Entry added"
                        wiz.reset()

                if wiz.active:
                    _draw_wizard(LCD, wiz)
                else:
                    _draw_schedule(LCD, entries, cursor, scroll, status)
                time.sleep(0.08)
                continue

            # -- Normal mode ---------------------------------------------------
            if btn == "KEY3":
                break
            elif btn == "UP":
                cursor = max(0, cursor - 1)
                if cursor < scroll:
                    scroll = cursor
                status = ""
            elif btn == "DOWN":
                cursor = min(max(0, len(entries) - 1), cursor + 1)
                if cursor >= scroll + visible:
                    scroll = cursor - visible + 1
                status = ""
            elif btn == "OK" and entries:
                entries[cursor]["enabled"] = not entries[cursor].get("enabled", True)
                st = "ON" if entries[cursor]["enabled"] else "OFF"
                status = f"Toggled {st}"
                _save_schedule(entries)
            elif btn == "KEY1":
                wiz.active = True
                wiz.step = 0
                wiz.payloads = _discover_payloads()
                wiz.sel = 0
                if not wiz.payloads:
                    status = "No payloads found"
                    wiz.active = False
            elif btn == "KEY2" and entries:
                removed = entries.pop(cursor)
                cursor = min(cursor, max(0, len(entries) - 1))
                if cursor < scroll:
                    scroll = cursor
                status = f"Removed"
                _save_schedule(entries)

            _draw_schedule(LCD, entries, cursor, scroll, status)
            time.sleep(0.08)

    finally:
        _running = False
        for proc in running_procs.values():
            try:
                proc.terminate()
            except OSError:
                pass
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
