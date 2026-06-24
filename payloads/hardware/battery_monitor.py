#!/usr/bin/env python3
"""
RaspyJack Payload -- Battery Monitor
======================================
Author: 7h30th3r0n3

Real-time battery fuel gauge monitor for the CardputerZero.
Reads from the kernel power_supply sysfs interface (bq27500 driver).

Controls:
  OK         -- Start / Stop monitoring
  KEY1       -- Cycle views (GAUGE / GRAPH / DETAIL)
  UP / DOWN  -- Scroll in detail view
  KEY2       -- Export snapshot to loot
  KEY3       -- Exit
"""

import os
import sys
import json
import math
import time
import threading
from datetime import datetime
from collections import deque

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT

LOOT_DIR = "/root/Raspyjack/loot/Battery"
POLL_INTERVAL = 1.0
GRAPH_HISTORY = 300

C_BG = "#0a0a12"
C_CYAN = "#00E5FF"
C_GREEN = "#00E676"
C_RED = "#FF5252"
C_YELLOW = "#FFD740"
C_PURPLE = "#7C4DFF"
C_MUTED = "#888888"
C_DIM = "#555555"
C_HEADER = "#0d1117"

VIEWS = ["GAUGE", "GRAPH", "DETAIL"]

DESIGN_CAP_MAH = 1500


# ---------------------------------------------------------------------------
# sysfs battery reader
# ---------------------------------------------------------------------------

_PS_PATH = None

def _find_power_supply():
    global _PS_PATH
    base = "/sys/class/power_supply"
    if not os.path.isdir(base):
        return False
    for name in os.listdir(base):
        tp = os.path.join(base, name, "type")
        try:
            with open(tp) as f:
                if f.read().strip() == "Battery":
                    _PS_PATH = os.path.join(base, name)
                    return True
        except Exception:
            continue
    return False


def _read_sysfs(attr):
    if not _PS_PATH:
        return None
    try:
        with open(os.path.join(_PS_PATH, attr)) as f:
            return f.read().strip()
    except Exception:
        return None


def _read_int(attr):
    val = _read_sysfs(attr)
    if val is None:
        return None
    try:
        return int(val)
    except ValueError:
        return None


def _voltage_to_soc(mv):
    """Estimate SOC from Li-ion voltage (3.0V=0%, 4.2V=100%)."""
    if mv is None:
        return None
    return max(0, min(100, int((mv - 3000) / 12)))


def _read_battery():
    data = {}

    voltage_uv = _read_int("voltage_now")
    data["voltage_mv"] = voltage_uv // 1000 if voltage_uv is not None else None

    current_ua = _read_int("current_now")
    data["current_ma"] = current_ua // 1000 if current_ua is not None else None

    temp_raw = _read_int("temp")
    if temp_raw is not None:
        data["temp_c"] = temp_raw / 10.0
    else:
        data["temp_c"] = None

    data["soc"] = _voltage_to_soc(data["voltage_mv"])

    data["status"] = _read_sysfs("status") or "Unknown"
    data["health"] = _read_sysfs("health") or "Unknown"
    data["technology"] = _read_sysfs("technology") or "Unknown"
    data["cycle_count"] = _read_int("cycle_count")
    data["present"] = _read_sysfs("present") == "1"
    data["capacity_level"] = _read_sysfs("capacity_level") or "Unknown"

    return data


DETAIL_FIELDS = [
    ("Status", "status", ""),
    ("Voltage", "voltage_mv", "mV"),
    ("Current", "current_ma", "mA"),
    ("SOC", "soc", "%"),
    ("Temperature", "temp_c", "C"),
    ("Health", "health", ""),
    ("Technology", "technology", ""),
    ("Cycles", "cycle_count", ""),
    ("Level", "capacity_level", ""),
    ("Present", "present", ""),
]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_running = True
_monitoring = False

_current_data = {}
_voltage_history = deque(maxlen=GRAPH_HISTORY)
_current_history = deque(maxlen=GRAPH_HISTORY)
_soc_history = deque(maxlen=GRAPH_HISTORY)
_read_count = 0
_last_error = ""


def _poll_thread():
    global _current_data, _read_count, _last_error

    while _running:
        with _lock:
            active = _monitoring
        if not active:
            time.sleep(0.1)
            continue

        data = _read_battery()
        with _lock:
            _current_data = data
            _read_count += 1
            v = data.get("voltage_mv")
            c = data.get("current_ma")
            s = data.get("soc")
            if v is not None:
                _voltage_history.append(v)
            if c is not None:
                _current_history.append(c)
            if s is not None:
                _soc_history.append(s)
            if not data.get("present"):
                _last_error = "No battery detected"
            else:
                _last_error = ""

        time.sleep(POLL_INTERVAL)


# ---------------------------------------------------------------------------
# Drawing: GAUGE view
# ---------------------------------------------------------------------------

def _draw_gauge(d, data, fonts):
    font, font_sm, font_xs, font_lg = fonts

    soc = data.get("soc")
    voltage = data.get("voltage_mv")
    current = data.get("current_ma")
    temp = data.get("temp_c")
    status = data.get("status", "Unknown")

    is_charging = status == "Charging"
    soc_val = soc if soc is not None else 0

    if soc is None:
        gauge_color = C_DIM
    elif soc_val >= 60:
        gauge_color = C_GREEN
    elif soc_val >= 20:
        gauge_color = C_YELLOW
    else:
        gauge_color = C_RED

    cx, cy, r = 40, 50, 28
    d.ellipse((cx - r, cy - r, cx + r, cy + r), outline="#1a1a2e", width=2)

    if soc is not None and soc_val > 0:
        start_angle = -90
        end_angle = -90 + int(3.6 * soc_val)
        d.arc(
            (cx - r, cy - r, cx + r, cy + r),
            start_angle, end_angle,
            fill=gauge_color, width=3,
        )

    inner_r = r - 6
    d.ellipse(
        (cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r),
        outline="#1a1a2e", width=1,
    )

    soc_text = f"{soc_val}%" if soc is not None else "--"
    d.text((cx, cy - 5), soc_text, font=font, fill=gauge_color, anchor="mm")

    ind_color = C_GREEN if is_charging else C_CYAN
    d.text((cx, cy + 7), status[:6], font=font_xs, fill=ind_color, anchor="mm")

    rx = 74
    ry = 20

    v_text = f"{voltage}mV" if voltage is not None else "-- mV"
    d.text((rx, ry), "VOLT", font=font_xs, fill=C_MUTED)
    d.text((rx, ry + 9), v_text, font=font_sm, fill="#ffffff")
    ry += 22

    if current is not None:
        cur_color = C_GREEN if is_charging else C_RED if current < 0 else C_MUTED
        c_text = f"{current}mA"
    else:
        cur_color = C_DIM
        c_text = "-- mA"
    d.text((rx, ry), "CURR", font=font_xs, fill=C_MUTED)
    d.text((rx, ry + 9), c_text, font=font_sm, fill=cur_color)
    ry += 22

    if temp is not None:
        t_color = C_RED if temp > 45 else C_YELLOW if temp > 40 else C_CYAN
        t_text = f"{temp:.1f}C"
    else:
        t_color = C_DIM
        t_text = "-- C"
    d.text((rx, ry), "TEMP", font=font_xs, fill=C_MUTED)
    d.text((rx, ry + 9), t_text, font=font_sm, fill=t_color)
    ry += 22

    d.text((rx, ry), "HEALTH", font=font_xs, fill=C_MUTED)
    d.text((rx, ry + 9), data.get("health", "--")[:8], font=font_sm, fill=C_PURPLE)

    if soc is not None:
        bar_y = 108
        bar_x = 4
        bar_w = 120
        bar_h = 6
        d.rectangle((bar_x, bar_y, bar_x + bar_w, bar_y + bar_h), outline="#1a1a2e")
        fill_w = int((soc_val / 100) * (bar_w - 2))
        if fill_w > 0:
            d.rectangle(
                (bar_x + 1, bar_y + 1, bar_x + 1 + fill_w, bar_y + bar_h - 1),
                fill=gauge_color,
            )
        est_mah = int(DESIGN_CAP_MAH * soc_val / 100)
        d.text((64, bar_y - 2), f"{est_mah}/{DESIGN_CAP_MAH}mAh", font=font_xs, fill=C_MUTED, anchor="mb")


# ---------------------------------------------------------------------------
# Drawing: GRAPH view
# ---------------------------------------------------------------------------

def _draw_graph(d, fonts):
    font, font_sm, font_xs, font_lg = fonts

    with _lock:
        v_hist = list(_voltage_history)
        c_hist = list(_current_history)

    gx, gy, gw, gh = 4, 22, 119, 55
    gx2, gy2 = gx + gw, gy + gh

    d.rectangle((gx, gy, gx2, gy2), fill="#0d0d1a", outline="#1a1a2e")

    for i in range(1, 4):
        y_line = gy + int(gh * i / 4)
        d.line((gx, y_line, gx2, y_line), fill="#1a1a2e")

    d.text((2, 16), "VOLTAGE", font=font_xs, fill=C_CYAN)
    d.text((68, 16), "CURRENT", font=font_xs, fill=C_PURPLE)

    if len(v_hist) < 2:
        d.text((64, 45), "Collecting...", font=font_sm, fill=C_DIM, anchor="mm")
        return

    v_min = max(2500, min(v_hist) - 100)
    v_max = min(4500, max(v_hist) + 100)
    v_range = max(1, v_max - v_min)

    points_v = []
    n = min(len(v_hist), gw)
    for i in range(n):
        idx = len(v_hist) - n + i
        x = gx + i
        val = v_hist[idx]
        y = gy2 - int((val - v_min) / v_range * gh)
        y = max(gy, min(gy2, y))
        points_v.append((x, y))

    if len(points_v) >= 2:
        d.line(points_v, fill=C_CYAN, width=1)

    if len(c_hist) >= 2:
        c_vals = [abs(c) for c in c_hist]
        c_max_abs = max(max(c_vals), 50)

        points_c = []
        n_c = min(len(c_hist), gw)
        for i in range(n_c):
            idx = len(c_hist) - n_c + i
            x = gx + i
            val = c_hist[idx]
            mid_y = gy + gh // 2
            y = mid_y - int((val / c_max_abs) * (gh // 2))
            y = max(gy, min(gy2, y))
            points_c.append((x, y))

        if len(points_c) >= 2:
            d.line(points_c, fill=C_PURPLE, width=1)

        d.line((gx, gy + gh // 2, gx2, gy + gh // 2), fill="#333333")

    d.text((gx, gy2 + 2), f"{v_min}mV", font=font_xs, fill=C_DIM)
    d.text((gx2 - 2, gy2 + 2), f"{v_max}mV", font=font_xs, fill=C_DIM, anchor="ra")

    if v_hist:
        d.text((4, 90), f"V:{v_hist[-1]}mV", font=font_sm, fill=C_CYAN)
    if c_hist:
        c_last = c_hist[-1]
        c_color = C_GREEN if c_last > 0 else C_RED if c_last < 0 else C_MUTED
        d.text((68, 90), f"I:{c_last}mA", font=font_sm, fill=c_color)

    span_sec = len(v_hist)
    if span_sec >= 60:
        span_text = f"{span_sec // 60}m{span_sec % 60:02d}s"
    else:
        span_text = f"{span_sec}s"
    d.text((4, 100), f"Span: {span_text}", font=font_xs, fill=C_DIM)
    d.text((80, 100), f"N={len(v_hist)}", font=font_xs, fill=C_DIM)


# ---------------------------------------------------------------------------
# Drawing: DETAIL view
# ---------------------------------------------------------------------------

def _draw_detail(d, data, scroll, fonts):
    font, font_sm, font_xs, font_lg = fonts

    row_h = 11
    visible_rows = 7
    total_rows = len(DETAIL_FIELDS)

    y = 18
    for i in range(scroll, min(scroll + visible_rows, total_rows)):
        label, key, unit = DETAIL_FIELDS[i]

        d.text((2, y), label[:12], font=font_xs, fill=C_MUTED)

        val = data.get(key)
        if val is None:
            val_text = "N/A"
            val_color = C_DIM
        elif isinstance(val, bool):
            val_text = "Yes" if val else "No"
            val_color = C_GREEN if val else C_RED
        elif isinstance(val, float):
            val_text = f"{val:.1f}{unit}"
            val_color = C_CYAN
        elif isinstance(val, int):
            val_text = f"{val}{unit}"
            if key == "soc":
                val_color = C_GREEN if val >= 60 else C_YELLOW if val >= 20 else C_RED
            elif key == "current_ma":
                val_color = C_GREEN if val > 0 else C_RED
            else:
                val_color = "#ffffff"
        else:
            val_text = str(val)[:12]
            val_color = C_PURPLE

        d.text((75, y), val_text, font=font_xs, fill=val_color)
        y += row_h

    if total_rows > visible_rows:
        indicator_h = max(4, int(visible_rows / total_rows * 80))
        indicator_y = 18 + int(scroll / max(1, total_rows - visible_rows) * (80 - indicator_h))
        d.rectangle((125, indicator_y, 127, indicator_y + indicator_h), fill=C_DIM)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_snapshot():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"battery_{ts}.json"
    filepath = os.path.join(LOOT_DIR, filename)

    with _lock:
        data = dict(_current_data)
        v_hist = list(_voltage_history)
        c_hist = list(_current_history)
        reads = _read_count

    export = {
        "timestamp": ts,
        "power_supply": os.path.basename(_PS_PATH) if _PS_PATH else "unknown",
        "read_count": reads,
        "data": data,
        "voltage_history_last60": v_hist[-60:],
        "current_history_last60": c_hist[-60:],
    }

    with open(filepath, "w") as fh:
        json.dump(export, fh, indent=2, default=str)

    return filename


# ---------------------------------------------------------------------------
# Main render
# ---------------------------------------------------------------------------

def _draw_frame(lcd, view_idx, detail_scroll, fonts):
    font, font_sm, font_xs, font_lg = fonts

    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)

    view_name = VIEWS[view_idx]

    d.rectangle((0, 0, 127, 13), fill=C_HEADER)
    d.text((2, 1), f"BAT {view_name}", font=font_sm, fill=C_CYAN)

    with _lock:
        active = _monitoring
        data = dict(_current_data)
        error = _last_error
        reads = _read_count

    dot_color = C_GREEN if active else C_RED
    d.ellipse((118, 3, 122, 7), fill=dot_color)

    if active and reads > 0:
        d.text((100, 1), f"#{reads}", font=font_xs, fill=C_DIM)

    if error and not data:
        d.text((4, 55), error[:24], font=font_sm, fill=C_RED)
        d.text((4, 70), "Check battery", font=font_xs, fill=C_MUTED)
    elif not active and not data:
        d.text((14, 45), "BATTERY MONITOR", font=font_sm, fill=C_CYAN)
        ps_name = os.path.basename(_PS_PATH) if _PS_PATH else "not found"
        d.text((20, 60), ps_name, font=font_xs, fill=C_DIM)
        d.text((16, 75), "Press OK to start", font=font_xs, fill=C_MUTED)
    else:
        if view_name == "GAUGE":
            _draw_gauge(d, data, fonts)
        elif view_name == "GRAPH":
            _draw_graph(d, fonts)
        elif view_name == "DETAIL":
            _draw_detail(d, data, detail_scroll, fonts)

    d.rectangle((0, 116, 127, 127), fill=C_HEADER)
    if view_name == "DETAIL":
        d.text((2, 117), "^v:Scrl K2:Exp K3:Exit", font=font_xs, fill=C_DIM)
    else:
        d.text((2, 117), "OK:Mon K1:View K3:Exit", font=font_xs, fill=C_DIM)

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, _monitoring

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    font = scaled_font(10)
    font_sm = scaled_font(9)
    font_xs = scaled_font(8)
    font_lg = scaled_font(14)
    fonts = (font, font_sm, font_xs, font_lg)

    if not _find_power_supply():
        img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
        d = ScaledDraw(img)
        d.text((64, 50), "No battery found", font=font_sm, fill=C_RED, anchor="mm")
        d.text((64, 65), "No power_supply sysfs", font=font_xs, fill=C_MUTED, anchor="mm")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    view_idx = 0
    detail_scroll = 0

    poll = threading.Thread(target=_poll_thread, daemon=True)
    poll.start()

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK":
                with _lock:
                    _monitoring = not _monitoring
                time.sleep(0.2)

            elif btn == "KEY1":
                view_idx = (view_idx + 1) % len(VIEWS)
                detail_scroll = 0
                time.sleep(0.2)

            elif btn == "UP":
                if VIEWS[view_idx] == "DETAIL":
                    detail_scroll = max(0, detail_scroll - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                if VIEWS[view_idx] == "DETAIL":
                    max_scroll = max(0, len(DETAIL_FIELDS) - 7)
                    detail_scroll = min(detail_scroll + 1, max_scroll)
                time.sleep(0.15)

            elif btn == "KEY2":
                with _lock:
                    has_data = bool(_current_data)
                if has_data:
                    fname = _export_snapshot()
                    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
                    d = ScaledDraw(img)
                    d.rectangle((20, 40, 108, 75), fill=C_HEADER, outline=C_CYAN)
                    d.text((64, 50), "Exported!", font=font_sm, fill=C_GREEN, anchor="mm")
                    d.text((64, 63), fname[:20], font=font_xs, fill=C_MUTED, anchor="mm")
                    lcd.LCD_ShowImage(img, 0, 0)
                    time.sleep(1.2)

            _draw_frame(lcd, view_idx, detail_scroll, fonts)
            time.sleep(0.05)

    finally:
        _running = False
        _monitoring = False
        poll.join(timeout=3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
