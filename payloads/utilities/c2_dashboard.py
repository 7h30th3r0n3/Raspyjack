#!/usr/bin/env python3
"""
RaspyJack Payload -- C2 Dashboard
==================================
Author: 7h30th3r0n3

Command & Control dashboard on LCD.  Displays running payloads, loot
statistics, network interfaces, service health, and recent alerts in a
multi-view layout with auto-refresh.

Setup / Prerequisites
---------------------
- RaspyJack base system with LCD hat.
- systemd services: raspyjack, raspyjack-device, raspyjack-webui, caddy.
- Discord webhook URL in /root/Raspyjack/discord_webhook.txt (optional).

Controls
--------
  LEFT / RIGHT  -- Switch view (Overview, Payloads, Loot, Network)
  UP / DOWN     -- Scroll within a view
  OK            -- Force refresh
  KEY1          -- Kill selected payload (in Payloads view)
  KEY3          -- Exit
"""

import os
import sys
import time
import signal
import subprocess
import threading

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
WEBHOOK_FILE = "/root/Raspyjack/discord_webhook.txt"
SERVICES = ["raspyjack", "raspyjack-device", "raspyjack-webui", "caddy"]
VIEWS = ["Overview", "Payloads", "Loot", "Network"]
REFRESH_INTERVAL = 5.0
DEBOUNCE = 0.22

lock = threading.Lock()
_running = True


# ---------------------------------------------------------------------------
# Data collection helpers
# ---------------------------------------------------------------------------

def _get_running_payloads():
    """Return list of dicts with pid and cmdline for payload processes."""
    results = []
    try:
        for pid_dir in os.listdir("/proc"):
            if not pid_dir.isdigit():
                continue
            cmdline_path = os.path.join("/proc", pid_dir, "cmdline")
            try:
                with open(cmdline_path, "r") as fh:
                    cmdline = fh.read().replace("\x00", " ").strip()
            except OSError:
                continue
            if "python3" in cmdline and "payloads/" in cmdline:
                name = cmdline.split("payloads/")[-1].split(" ")[0].split("\x00")[0]
                results.append({"pid": int(pid_dir), "name": name[:20]})
    except OSError:
        pass
    return results


def _get_loot_stats():
    """Return dict of subdir_name -> file_count."""
    stats = {}
    if not os.path.isdir(LOOT_ROOT):
        return stats
    try:
        for entry in sorted(os.listdir(LOOT_ROOT)):
            full = os.path.join(LOOT_ROOT, entry)
            if os.path.isdir(full) and not entry.startswith("."):
                count = sum(1 for f in os.listdir(full) if os.path.isfile(os.path.join(full, f)))
                stats[entry] = count
    except OSError:
        pass
    return stats


def _get_network_interfaces():
    """Return list of dicts with iface name and IP."""
    interfaces = []
    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True, text=True, timeout=3,
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 4:
                iface = parts[1]
                addr = parts[3].split("/")[0]
                if iface != "lo":
                    interfaces.append({"iface": iface, "ip": addr})
    except Exception:
        pass
    return interfaces


def _get_service_status(name):
    """Return 'active', 'inactive', or 'error'."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True, text=True, timeout=3,
        )
        return result.stdout.strip()
    except Exception:
        return "error"


def _get_uptime_str():
    """Return human-readable uptime."""
    try:
        with open("/proc/uptime", "r") as fh:
            secs = int(float(fh.read().split()[0]))
        hours = secs // 3600
        mins = (secs % 3600) // 60
        return f"{hours}h{mins:02d}m"
    except OSError:
        return "???"


def _count_recent_loot(seconds=300):
    """Count loot files modified within the last N seconds."""
    count = 0
    now = time.time()
    try:
        for root, _dirs, files in os.walk(LOOT_ROOT):
            for fname in files:
                if fname.startswith("."):
                    continue
                full = os.path.join(root, fname)
                try:
                    if (now - os.path.getmtime(full)) < seconds:
                        count += 1
                except OSError:
                    pass
    except OSError:
        pass
    return count


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class DashState:
    """Immutable-style snapshot replaced atomically under lock."""
    __slots__ = (
        "payloads", "loot_stats", "interfaces", "services",
        "uptime", "recent_loot", "total_loot",
    )

    def __init__(self):
        self.payloads = []
        self.loot_stats = {}
        self.interfaces = []
        self.services = {}
        self.uptime = "???"
        self.recent_loot = 0
        self.total_loot = 0


state = DashState()


def _refresh_data():
    """Collect all data and replace state snapshot."""
    global state
    new = DashState()
    new.payloads = _get_running_payloads()
    new.loot_stats = _get_loot_stats()
    new.interfaces = _get_network_interfaces()
    new.services = {s: _get_service_status(s) for s in SERVICES}
    new.uptime = _get_uptime_str()
    new.recent_loot = _count_recent_loot()
    new.total_loot = sum(new.loot_stats.values())
    with lock:
        state = new


def _auto_refresh():
    """Background thread that refreshes data periodically."""
    while _running:
        _refresh_data()
        deadline = time.time() + REFRESH_INTERVAL
        while _running and time.time() < deadline:
            time.sleep(0.3)


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(d, view_name):
    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), f"C2: {view_name}", font=font, fill="#00ccff")
    d.text((108, 1), "K3", font=font, fill="#888")


def _draw_footer(d, hint):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), hint, font=font, fill="#666")


def _draw_overview(lcd, snap):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "Overview")

    y = 16
    d.text((2, y), f"Uptime: {snap.uptime}", font=font, fill="#00ff00"); y += 13
    d.text((2, y), f"Payloads: {len(snap.payloads)} running", font=font, fill="white"); y += 13
    d.text((2, y), f"Loot: {snap.total_loot} files", font=font, fill="white"); y += 13
    d.text((2, y), f"New (5m): {snap.recent_loot}", font=font, fill="#ffaa00"); y += 13

    y += 4
    d.text((2, y), "Services:", font=font, fill="#aaa"); y += 12
    for svc, st in snap.services.items():
        color = "#00ff00" if st == "active" else "#ff4444"
        short = svc.replace("raspyjack-", "rj-")[:12]
        d.text((2, y), f" {short}: {st}", font=font, fill=color); y += 11
        if y > 112:
            break

    _draw_footer(d, "</>:view OK:refresh")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_payloads(lcd, snap, scroll, cursor):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "Payloads")

    plist = snap.payloads
    if not plist:
        d.text((4, 50), "No running payloads", font=font, fill="#666")
    else:
        y = 16
        visible = 7
        end = min(len(plist), scroll + visible)
        for i in range(scroll, end):
            p = plist[i]
            marker = ">" if i == cursor else " "
            color = "#ffaa00" if i == cursor else "#ccc"
            d.text((2, y), f"{marker}{p['pid']} {p['name'][:14]}", font=font, fill=color)
            y += 13

    _draw_footer(d, "K1:kill  ^v:scroll")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_loot(lcd, snap, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "Loot")

    items = list(snap.loot_stats.items())
    if not items:
        d.text((4, 50), "No loot found", font=font, fill="#666")
    else:
        y = 16
        visible = 7
        end = min(len(items), scroll + visible)
        for i in range(scroll, end):
            name, count = items[i]
            d.text((2, y), f" {name[:14]}: {count}", font=font, fill="#ccc")
            y += 13

    d.text((2, 104), f"Total: {snap.total_loot}", font=font, fill="#00ff00")
    _draw_footer(d, "^v:scroll  OK:ref")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_network(lcd, snap, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "Network")

    ifaces = snap.interfaces
    if not ifaces:
        d.text((4, 50), "No interfaces", font=font, fill="#666")
    else:
        y = 16
        visible = 4
        end = min(len(ifaces), scroll + visible)
        for i in range(scroll, end):
            ifc = ifaces[i]
            d.text((2, y), ifc["iface"], font=font, fill="#00ccff"); y += 12
            d.text((6, y), ifc["ip"], font=font, fill="#ccc"); y += 14

    _draw_footer(d, "^v:scroll  OK:ref")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running

    _refresh_data()
    t = threading.Thread(target=_auto_refresh, daemon=True)
    t.start()

    view_idx = 0
    scroll = 0
    cursor = 0
    last_press = 0.0
    status = ""

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if btn == "KEY3":
                break
            elif btn == "RIGHT":
                view_idx = (view_idx + 1) % len(VIEWS)
                scroll = 0
                cursor = 0
            elif btn == "LEFT":
                view_idx = (view_idx - 1) % len(VIEWS)
                scroll = 0
                cursor = 0
            elif btn == "UP":
                if cursor > 0:
                    cursor -= 1
                if cursor < scroll:
                    scroll = cursor
            elif btn == "DOWN":
                cursor += 1
                with lock:
                    snap = state
                max_idx = max(0, len(snap.payloads) - 1) if view_idx == 1 else 20
                cursor = min(cursor, max_idx)
                if cursor >= scroll + 7:
                    scroll = cursor - 6
            elif btn == "OK":
                _refresh_data()
            elif btn == "KEY1" and view_idx == 1:
                with lock:
                    snap = state
                if snap.payloads and 0 <= cursor < len(snap.payloads):
                    pid = snap.payloads[cursor]["pid"]
                    try:
                        os.kill(pid, signal.SIGTERM)
                        status = f"Killed {pid}"
                    except OSError as exc:
                        status = f"Err: {str(exc)[:14]}"
                    time.sleep(0.5)
                    _refresh_data()

            with lock:
                snap = state

            view = VIEWS[view_idx]
            if view == "Overview":
                _draw_overview(LCD, snap)
            elif view == "Payloads":
                _draw_payloads(LCD, snap, scroll, cursor)
            elif view == "Loot":
                _draw_loot(LCD, snap, scroll)
            elif view == "Network":
                _draw_network(LCD, snap, scroll)

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
