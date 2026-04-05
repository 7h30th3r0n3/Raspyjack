#!/usr/bin/env python3
"""
RaspyJack Payload -- System Monitor
=====================================
Author: 7h30th3r0n3

Real-time system resource dashboard.  Reads CPU, RAM, temperature, disk,
uptime, network throughput, and service status from /proc and /sys.

Setup / Prerequisites
---------------------
- RaspyJack base system with LCD hat.
- Thermal zone at /sys/class/thermal/thermal_zone0/temp.

Controls
--------
  LEFT / RIGHT  -- Switch view (Dashboard, CPU Graph, Network)
  UP / DOWN     -- Scroll within a view
  OK            -- Force refresh
  KEY3          -- Exit
"""

import os
import sys
import time
import subprocess
import threading
from collections import deque

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

VIEWS = ["Dashboard", "CPU Graph", "Network"]
REFRESH_INTERVAL = 2.0
DEBOUNCE = 0.20
SERVICES = ["raspyjack", "raspyjack-device", "raspyjack-webui", "caddy"]

lock = threading.Lock()
_running = True

# Rolling CPU history for graph (60 values)
cpu_history = deque(maxlen=60)


# ---------------------------------------------------------------------------
# System readers
# ---------------------------------------------------------------------------

_prev_cpu = None


def _read_cpu_percent():
    """Compute CPU usage % from /proc/stat delta."""
    global _prev_cpu
    try:
        with open("/proc/stat", "r") as fh:
            parts = fh.readline().split()
        values = [int(v) for v in parts[1:8]]
        idle = values[3] + values[4]
        total = sum(values)
    except (OSError, ValueError, IndexError):
        return 0.0

    if _prev_cpu is None:
        _prev_cpu = (idle, total)
        return 0.0

    prev_idle, prev_total = _prev_cpu
    _prev_cpu = (idle, total)
    d_idle = idle - prev_idle
    d_total = total - prev_total
    if d_total == 0:
        return 0.0
    return round((1.0 - d_idle / d_total) * 100, 1)


def _read_load_avg():
    """Return 1-min load average string."""
    try:
        with open("/proc/loadavg", "r") as fh:
            return fh.read().split()[0]
    except (OSError, IndexError):
        return "?"


def _read_memory():
    """Return (used_mb, total_mb) from /proc/meminfo."""
    info = {}
    try:
        with open("/proc/meminfo", "r") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2:
                    key = parts[0].rstrip(":")
                    info[key] = int(parts[1])
    except (OSError, ValueError):
        return (0, 0)
    total = info.get("MemTotal", 0)
    avail = info.get("MemAvailable", info.get("MemFree", 0))
    used = total - avail
    return (used // 1024, total // 1024)


def _read_temperature():
    """Return CPU temperature in Celsius."""
    try:
        with open("/sys/class/thermal/thermal_zone0/temp", "r") as fh:
            return int(fh.read().strip()) / 1000.0
    except (OSError, ValueError):
        return 0.0


def _read_disk():
    """Return (used_gb, total_gb) for /."""
    try:
        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        free = st.f_bfree * st.f_frsize
        used = total - free
        return (round(used / 1e9, 1), round(total / 1e9, 1))
    except OSError:
        return (0.0, 0.0)


def _read_uptime():
    """Return uptime string."""
    try:
        with open("/proc/uptime", "r") as fh:
            secs = int(float(fh.read().split()[0]))
        h = secs // 3600
        m = (secs % 3600) // 60
        return f"{h}h{m:02d}m"
    except (OSError, ValueError):
        return "?"


_prev_net = {}


def _read_net_bytes():
    """Return dict of iface -> (rx_bps, tx_bps)."""
    global _prev_net
    current = {}
    try:
        with open("/proc/net/dev", "r") as fh:
            for line in fh:
                if ":" not in line:
                    continue
                iface, rest = line.split(":", 1)
                iface = iface.strip()
                if iface == "lo":
                    continue
                parts = rest.split()
                if len(parts) >= 9:
                    rx = int(parts[0])
                    tx = int(parts[8])
                    current[iface] = (rx, tx, time.time())
    except (OSError, ValueError):
        pass

    rates = {}
    for iface, (rx, tx, ts) in current.items():
        if iface in _prev_net:
            prx, ptx, pts = _prev_net[iface]
            dt = max(0.1, ts - pts)
            rates[iface] = (
                int((rx - prx) / dt),
                int((tx - ptx) / dt),
            )
        else:
            rates[iface] = (0, 0)
    _prev_net = current
    return rates


def _service_status(name):
    """Check systemd service status."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True, text=True, timeout=3,
        )
        return result.stdout.strip()
    except Exception:
        return "error"


class SysState:
    __slots__ = (
        "cpu_pct", "load", "mem_used", "mem_total", "temp",
        "disk_used", "disk_total", "uptime", "net_rates", "services",
    )

    def __init__(self):
        self.cpu_pct = 0.0
        self.load = "?"
        self.mem_used = 0
        self.mem_total = 0
        self.temp = 0.0
        self.disk_used = 0.0
        self.disk_total = 0.0
        self.uptime = "?"
        self.net_rates = {}
        self.services = {}


state = SysState()


def _refresh():
    """Collect all metrics into a new state snapshot."""
    global state
    s = SysState()
    s.cpu_pct = _read_cpu_percent()
    s.load = _read_load_avg()
    s.mem_used, s.mem_total = _read_memory()
    s.temp = _read_temperature()
    s.disk_used, s.disk_total = _read_disk()
    s.uptime = _read_uptime()
    s.net_rates = _read_net_bytes()
    s.services = {svc: _service_status(svc) for svc in SERVICES}
    with lock:
        state = s
        cpu_history.append(s.cpu_pct)


def _auto_refresh():
    while _running:
        _refresh()
        deadline = time.time() + REFRESH_INTERVAL
        while _running and time.time() < deadline:
            time.sleep(0.2)


def _fmt_bytes(b):
    """Format bytes/sec to human-readable."""
    if b < 1024:
        return f"{b}B/s"
    if b < 1024 * 1024:
        return f"{b // 1024}K/s"
    return f"{b // (1024 * 1024)}M/s"


def _temp_color(t):
    if t >= 75:
        return "#ff2222"
    if t >= 60:
        return "#ffaa00"
    return "#00ff00"


def _draw_header(d, view_name):
    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), f"MON: {view_name}", font=font, fill="#00ccff")
    d.text((108, 1), "K3", font=font, fill="#888")


def _draw_dashboard(lcd, snap):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "Dashboard")

    y = 16
    # CPU bar
    d.text((2, y), f"CPU {snap.cpu_pct:.0f}%", font=font, fill="#00ff00")
    bar_x = 60
    bar_w = 64
    d.rectangle((bar_x, y + 1, bar_x + bar_w, y + 9), outline="#444")
    fill_w = int(snap.cpu_pct / 100 * bar_w)
    if fill_w > 0:
        c = "#ff2222" if snap.cpu_pct > 80 else "#ffaa00" if snap.cpu_pct > 50 else "#00ff00"
        d.rectangle((bar_x + 1, y + 2, bar_x + fill_w, y + 8), fill=c)
    y += 14

    # RAM
    d.text((2, y), f"RAM {snap.mem_used}/{snap.mem_total}M", font=font, fill="#ccc")
    y += 13

    # Temp
    tc = _temp_color(snap.temp)
    d.text((2, y), f"Temp {snap.temp:.1f}C", font=font, fill=tc)
    y += 13

    # Disk
    d.text((2, y), f"Disk {snap.disk_used}/{snap.disk_total}G", font=font, fill="#ccc")
    y += 13

    # Uptime & load
    d.text((2, y), f"Up {snap.uptime}  Load {snap.load}", font=font, fill="#888")
    y += 15

    # Services
    d.text((2, y), "Services:", font=font, fill="#aaa"); y += 12
    for svc, st in snap.services.items():
        color = "#00ff00" if st == "active" else "#ff4444"
        short = svc.replace("raspyjack-", "rj-")[:12]
        d.text((2, y), f" {short}: {st}", font=font, fill=color); y += 11
        if y > 112:
            break

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "</>:view OK:refresh", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_cpu_graph(lcd, history):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "CPU Graph")

    graph_top = 18
    graph_bottom = 108
    graph_h = graph_bottom - graph_top
    graph_left = 20
    graph_right = 126

    # Y-axis labels
    for pct in (0, 50, 100):
        y_pos = graph_bottom - int(pct / 100 * graph_h)
        d.text((0, y_pos - 4), f"{pct:>3}", font=font, fill="#555")
        d.line((graph_left, y_pos, graph_right, y_pos), fill="#222")

    # Plot
    vals = list(history)
    if len(vals) > 1:
        w = graph_right - graph_left
        step = w / max(1, len(vals) - 1)
        points = []
        for i, v in enumerate(vals):
            x = graph_left + int(i * step)
            y = graph_bottom - int(min(v, 100) / 100 * graph_h)
            points.append((x, y))
        for i in range(len(points) - 1):
            d.line([points[i], points[i + 1]], fill="#00ccff", width=1)

    # Current value
    if vals:
        d.text((2, 110), f"Now: {vals[-1]:.0f}%", font=font, fill="#00ff00")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "</>:view OK:refresh", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_network(lcd, snap, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "Network")

    ifaces = list(snap.net_rates.items())
    if not ifaces:
        d.text((4, 50), "No interfaces", font=font, fill="#666")
    else:
        y = 16
        visible = 4
        end = min(len(ifaces), scroll + visible)
        for i in range(scroll, end):
            iface, (rx, tx) = ifaces[i]
            d.text((2, y), iface, font=font, fill="#00ccff"); y += 12
            d.text((6, y), f"RX {_fmt_bytes(rx)}", font=font, fill="#00ff00"); y += 11
            d.text((6, y), f"TX {_fmt_bytes(tx)}", font=font, fill="#ffaa00"); y += 14

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "</>:view ^v:scroll", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)


def main():
    global _running

    _refresh()
    t = threading.Thread(target=_auto_refresh, daemon=True)
    t.start()

    view_idx = 0
    scroll = 0
    last_press = 0.0

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
            elif btn == "LEFT":
                view_idx = (view_idx - 1) % len(VIEWS)
                scroll = 0
            elif btn == "UP":
                scroll = max(0, scroll - 1)
            elif btn == "DOWN":
                scroll += 1
            elif btn == "OK":
                _refresh()

            with lock:
                snap = state
                hist = list(cpu_history)

            view = VIEWS[view_idx]
            if view == "Dashboard":
                _draw_dashboard(LCD, snap)
            elif view == "CPU Graph":
                _draw_cpu_graph(LCD, hist)
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
