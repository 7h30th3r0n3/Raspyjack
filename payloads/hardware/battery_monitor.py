#!/usr/bin/env python3
"""
RaspyJack Payload -- Battery Monitor (BQ27220)
================================================
Author: 7h30th3r0n3

Real-time battery fuel gauge monitor for the CardputerZero using
the BQ27220 chip on I2C bus 1 at address 0x55.

Displays state of charge, voltage, current, temperature, capacity,
and estimated time remaining with a modern dark UI. Includes a
rolling graph view and full register detail view.

Setup / Prerequisites:
  - BQ27220 fuel gauge connected on I2C bus 1 (address 0x55).
  - i2c-tools installed (i2cget command).
  - I2C enabled (dtparam=i2c_arm=on in config.txt).

Controls:
  OK         -- Start / Stop monitoring
  KEY1       -- Cycle views (GAUGE / GRAPH / DETAIL)
  UP / DOWN  -- Scroll in detail view
  KEY2       -- Export snapshot to loot
  KEY3       -- Exit

Views:
  GAUGE   -- Circular battery gauge, voltage, current, time remaining
  GRAPH   -- Rolling 5-minute voltage and current graph
  DETAIL  -- All BQ27220 register values

Loot: /root/Raspyjack/loot/Battery/battery_YYYYMMDD_HHMMSS.json
"""

import os
import sys
import json
import math
import time
import subprocess
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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT

I2C_BUS = 1
I2C_ADDR = 0x55
LOOT_DIR = "/root/Raspyjack/loot/Battery"
POLL_INTERVAL = 1.0
GRAPH_HISTORY = 300  # 5 minutes at 1 sample/sec

# Theme colors
C_BG = "#0a0a12"
C_CYAN = "#00E5FF"
C_GREEN = "#00E676"
C_RED = "#FF5252"
C_YELLOW = "#FFD740"
C_PURPLE = "#7C4DFF"
C_MUTED = "#888888"
C_DIM = "#555555"
C_HEADER = "#0d1117"

# BQ27220 register map: (register_addr, name, unit, signed)
REGISTERS = [
    (0x02, "Temperature", "C", False),
    (0x04, "Voltage", "mV", False),
    (0x06, "Flags", "", False),
    (0x08, "NomAvailCap", "mAh", False),
    (0x0A, "FullAvailCap", "mAh", False),
    (0x0C, "RemCapacity", "mAh", False),
    (0x0E, "FullChgCap", "mAh", False),
    (0x10, "AvgCurrent", "mA", True),
    (0x12, "StbyCurrent", "mA", False),
    (0x14, "MaxLoadCur", "mA", False),
    (0x18, "AvgTimeEmpty", "min", False),
    (0x1A, "AvgTimeFull", "min", False),
    (0x1C, "StbyTimeEmpty", "min", False),
    (0x2C, "SOC", "%", False),
    (0x30, "DesignCap", "mAh", False),
]

VIEWS = ["GAUGE", "GRAPH", "DETAIL"]

# ---------------------------------------------------------------------------
# I2C read helpers
# ---------------------------------------------------------------------------


def _read_word(reg):
    """Read a 16-bit little-endian word from the BQ27220 via i2cget."""
    try:
        result = subprocess.run(
            ["i2cget", "-f", "-y", str(I2C_BUS), hex(I2C_ADDR), hex(reg), "w"],
            capture_output=True, text=True, timeout=2,
        )
        if result.returncode != 0:
            return None
        raw = result.stdout.strip()
        if not raw.startswith("0x"):
            return None
        return int(raw, 16)
    except Exception:
        return None


def _to_signed16(val):
    """Convert a 16-bit unsigned value to signed (two's complement)."""
    if val >= 0x8000:
        return val - 0x10000
    return val


def _read_all_registers():
    """Read all BQ27220 registers and return a dict of parsed values."""
    data = {}
    for reg_addr, name, unit, signed in REGISTERS:
        raw = _read_word(reg_addr)
        if raw is None:
            data[name] = None
            continue
        if name == "Temperature":
            # 0.1K units, subtract 2731 for deciCelsius
            deci_c = raw - 2731
            data[name] = deci_c / 10.0
        elif signed:
            data[name] = _to_signed16(raw)
        else:
            data[name] = raw
    return data


# ---------------------------------------------------------------------------
# Shared state (protected by lock)
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_running = True
_monitoring = False

_current_data = {}
_voltage_history = deque(maxlen=GRAPH_HISTORY)
_current_history = deque(maxlen=GRAPH_HISTORY)
_read_count = 0
_last_error = ""


def _poll_thread():
    """Continuously read BQ27220 registers while monitoring is active."""
    global _current_data, _read_count, _last_error

    while _running:
        with _lock:
            active = _monitoring
        if not active:
            time.sleep(0.1)
            continue

        data = _read_all_registers()
        with _lock:
            _current_data = data
            _read_count += 1
            voltage = data.get("Voltage")
            current = data.get("AvgCurrent")
            if voltage is not None:
                _voltage_history.append(voltage)
            if current is not None:
                _current_history.append(current)
            # Check for read failures
            if all(v is None for v in data.values()):
                _last_error = "No response from BQ27220"
            else:
                _last_error = ""

        time.sleep(POLL_INTERVAL)


# ---------------------------------------------------------------------------
# Drawing: GAUGE view
# ---------------------------------------------------------------------------


def _draw_gauge(d, data, fonts):
    """Draw the circular battery gauge view."""
    font, font_sm, font_xs, font_lg = fonts

    soc = data.get("SOC")
    voltage = data.get("Voltage")
    current = data.get("AvgCurrent")
    temp = data.get("Temperature")
    tte = data.get("AvgTimeEmpty")
    ttf = data.get("AvgTimeFull")

    # Determine charging state
    is_charging = current is not None and current > 0
    soc_val = soc if soc is not None else 0

    # Choose gauge color based on SOC
    if soc is None:
        gauge_color = C_DIM
    elif soc_val >= 60:
        gauge_color = C_GREEN
    elif soc_val >= 20:
        gauge_color = C_YELLOW
    else:
        gauge_color = C_RED

    # Draw arc gauge (center at 40, 52 on 128-base)
    cx, cy, r = 40, 50, 28
    # Background arc (full circle outline)
    d.ellipse((cx - r, cy - r, cx + r, cy + r), outline="#1a1a2e", width=2)

    # Filled arc representing SOC: draw from -90 degrees (top), clockwise
    if soc is not None and soc_val > 0:
        start_angle = -90
        end_angle = -90 + int(3.6 * soc_val)
        d.arc(
            (cx - r, cy - r, cx + r, cy + r),
            start_angle, end_angle,
            fill=gauge_color, width=3,
        )

    # Inner decorative ring
    inner_r = r - 6
    d.ellipse(
        (cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r),
        outline="#1a1a2e", width=1,
    )

    # SOC text in center
    soc_text = f"{soc_val}%" if soc is not None else "--"
    d.text((cx, cy - 5), soc_text, font=font, fill=gauge_color, anchor="mm")

    # Charging/discharging indicator
    if current is not None:
        indicator = "CHG" if is_charging else "DSC"
        ind_color = C_GREEN if is_charging else C_CYAN
        d.text((cx, cy + 7), indicator, font=font_xs, fill=ind_color, anchor="mm")

    # Right panel: voltage, current, temp, time
    rx = 74
    ry = 20

    # Voltage
    v_text = f"{voltage}mV" if voltage is not None else "-- mV"
    d.text((rx, ry), "VOLT", font=font_xs, fill=C_MUTED)
    d.text((rx, ry + 9), v_text, font=font_sm, fill="#ffffff")
    ry += 22

    # Current
    if current is not None:
        cur_color = C_GREEN if current > 0 else C_RED if current < 0 else C_MUTED
        c_text = f"{current:+d}mA"
    else:
        cur_color = C_DIM
        c_text = "-- mA"
    d.text((rx, ry), "CURR", font=font_xs, fill=C_MUTED)
    d.text((rx, ry + 9), c_text, font=font_sm, fill=cur_color)
    ry += 22

    # Temperature
    if temp is not None:
        t_color = C_RED if temp > 45 else C_YELLOW if temp > 40 else C_CYAN
        t_text = f"{temp:.1f}C"
    else:
        t_color = C_DIM
        t_text = "-- C"
    d.text((rx, ry), "TEMP", font=font_xs, fill=C_MUTED)
    d.text((rx, ry + 9), t_text, font=font_sm, fill=t_color)
    ry += 22

    # Time remaining
    if is_charging and ttf is not None and ttf < 65535:
        hrs = ttf // 60
        mins = ttf % 60
        time_text = f"{hrs}h{mins:02d}m" if hrs > 0 else f"{mins}m"
        time_label = "TO FULL"
    elif not is_charging and tte is not None and tte < 65535:
        hrs = tte // 60
        mins = tte % 60
        time_text = f"{hrs}h{mins:02d}m" if hrs > 0 else f"{mins}m"
        time_label = "TO EMPTY"
    else:
        time_text = "--:--"
        time_label = "TIME"
    d.text((rx, ry), time_label, font=font_xs, fill=C_MUTED)
    d.text((rx, ry + 9), time_text, font=font_sm, fill=C_PURPLE)

    # Bottom: capacity bar
    rem_cap = data.get("RemCapacity")
    full_cap = data.get("FullChgCap")
    if rem_cap is not None and full_cap is not None and full_cap > 0:
        bar_y = 108
        bar_x = 4
        bar_w = 120
        bar_h = 6
        d.rectangle((bar_x, bar_y, bar_x + bar_w, bar_y + bar_h), outline="#1a1a2e")
        fill_w = int((rem_cap / full_cap) * (bar_w - 2))
        fill_w = max(0, min(fill_w, bar_w - 2))
        if fill_w > 0:
            d.rectangle(
                (bar_x + 1, bar_y + 1, bar_x + 1 + fill_w, bar_y + bar_h - 1),
                fill=gauge_color,
            )
        cap_text = f"{rem_cap}/{full_cap}mAh"
        d.text((64, bar_y - 2), cap_text, font=font_xs, fill=C_MUTED, anchor="mb")


# ---------------------------------------------------------------------------
# Drawing: GRAPH view
# ---------------------------------------------------------------------------


def _draw_graph(d, fonts):
    """Draw the rolling voltage and current graph."""
    font, font_sm, font_xs, font_lg = fonts

    with _lock:
        v_hist = list(_voltage_history)
        c_hist = list(_current_history)

    # Graph area: x=4..123, y=18..80 (128-base)
    gx, gy, gw, gh = 4, 22, 119, 55
    gx2, gy2 = gx + gw, gy + gh

    # Draw graph background
    d.rectangle((gx, gy, gx2, gy2), fill="#0d0d1a", outline="#1a1a2e")

    # Grid lines (horizontal)
    for i in range(1, 4):
        y_line = gy + int(gh * i / 4)
        d.line((gx, y_line, gx2, y_line), fill="#1a1a2e")

    # Labels
    d.text((2, 16), "VOLTAGE", font=font_xs, fill=C_CYAN)
    d.text((68, 16), "CURRENT", font=font_xs, fill=C_PURPLE)

    if len(v_hist) < 2:
        d.text((40, 45), "Collecting...", font=font_sm, fill=C_DIM, anchor="mm")
        return

    # Voltage graph (cyan)
    v_min = max(2500, min(v_hist) - 100)
    v_max = min(4500, max(v_hist) + 100)
    v_range = max(1, v_max - v_min)

    points_v = []
    step = max(1, len(v_hist) // gw)
    for i in range(0, min(len(v_hist), gw)):
        idx = len(v_hist) - min(len(v_hist), gw) + i
        if idx < 0 or idx >= len(v_hist):
            continue
        x = gx + i
        val = v_hist[idx]
        y = gy2 - int((val - v_min) / v_range * gh)
        y = max(gy, min(gy2, y))
        points_v.append((x, y))

    if len(points_v) >= 2:
        d.line(points_v, fill=C_CYAN, width=1)

    # Current graph (purple), using separate scale
    if len(c_hist) >= 2:
        c_vals = [abs(c) for c in c_hist]
        c_max_abs = max(c_vals) if c_vals else 100
        c_max_abs = max(c_max_abs, 50)

        points_c = []
        for i in range(0, min(len(c_hist), gw)):
            idx = len(c_hist) - min(len(c_hist), gw) + i
            if idx < 0 or idx >= len(c_hist):
                continue
            x = gx + i
            val = c_hist[idx]
            # Map current: center line at middle of graph
            mid_y = gy + gh // 2
            y = mid_y - int((val / c_max_abs) * (gh // 2))
            y = max(gy, min(gy2, y))
            points_c.append((x, y))

        if len(points_c) >= 2:
            d.line(points_c, fill=C_PURPLE, width=1)

        # Zero line for current
        d.line((gx, gy + gh // 2, gx2, gy + gh // 2), fill="#333333")

    # Scale labels
    d.text((gx, gy2 + 2), f"{v_min}mV", font=font_xs, fill=C_DIM)
    d.text((gx2 - 2, gy2 + 2), f"{v_max}mV", font=font_xs, fill=C_DIM, anchor="ra")

    # Current values at bottom
    if v_hist:
        d.text((4, 90), f"V:{v_hist[-1]}mV", font=font_sm, fill=C_CYAN)
    if c_hist:
        c_last = c_hist[-1]
        c_color = C_GREEN if c_last > 0 else C_RED if c_last < 0 else C_MUTED
        d.text((68, 90), f"I:{c_last:+d}mA", font=font_sm, fill=c_color)

    # Sample count and time span
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
    """Draw the full register detail view."""
    font, font_sm, font_xs, font_lg = fonts

    row_h = 11
    visible_rows = 7
    total_rows = len(REGISTERS)

    y = 18
    for i in range(scroll, min(scroll + visible_rows, total_rows)):
        reg_addr, name, unit, signed = REGISTERS[i]
        val = data.get(name)

        # Register address
        d.text((2, y), f"0x{reg_addr:02X}", font=font_xs, fill=C_DIM)

        # Name (truncated)
        label = name[:11]
        d.text((22, y), label, font=font_xs, fill=C_MUTED)

        # Value with color coding
        if val is None:
            val_text = "ERR"
            val_color = C_RED
        elif name == "Flags":
            val_text = f"0x{val:04X}"
            val_color = C_PURPLE
        elif name == "Temperature":
            val_text = f"{val:.1f}{unit}"
            val_color = C_RED if val > 45 else C_YELLOW if val > 40 else C_CYAN
        elif name == "SOC":
            val_text = f"{val}{unit}"
            val_color = C_GREEN if val >= 60 else C_YELLOW if val >= 20 else C_RED
        elif name == "AvgCurrent":
            val_text = f"{val:+d}{unit}"
            val_color = C_GREEN if val > 0 else C_RED if val < 0 else C_MUTED
        elif unit == "min" and val >= 65535:
            val_text = "N/A"
            val_color = C_DIM
        else:
            val_text = f"{val}{unit}"
            val_color = "#ffffff"

        d.text((80, y), val_text, font=font_xs, fill=val_color)
        y += row_h

    # Scroll indicator
    if total_rows > visible_rows:
        indicator_h = max(4, int(visible_rows / total_rows * 80))
        indicator_y = 18 + int(scroll / max(1, total_rows - visible_rows) * (80 - indicator_h))
        d.rectangle((125, indicator_y, 127, indicator_y + indicator_h), fill=C_DIM)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


def _export_snapshot():
    """Export current battery data to a JSON loot file."""
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
        "i2c_bus": I2C_BUS,
        "i2c_addr": hex(I2C_ADDR),
        "read_count": reads,
        "registers": data,
        "voltage_history_last60": v_hist[-60:],
        "current_history_last60": c_hist[-60:],
    }

    with open(filepath, "w") as fh:
        json.dump(export, fh, indent=2)

    return filename


# ---------------------------------------------------------------------------
# Main render
# ---------------------------------------------------------------------------


def _draw_frame(lcd, view_idx, detail_scroll, fonts):
    """Render the current view to the LCD."""
    font, font_sm, font_xs, font_lg = fonts

    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)

    view_name = VIEWS[view_idx]

    # Header bar
    d.rectangle((0, 0, 127, 13), fill=C_HEADER)
    d.text((2, 1), f"BAT {view_name}", font=font_sm, fill=C_CYAN)

    with _lock:
        active = _monitoring
        data = dict(_current_data)
        error = _last_error
        reads = _read_count

    # Status indicator (pulsing dot)
    dot_color = C_GREEN if active else C_RED
    d.ellipse((118, 3, 122, 7), fill=dot_color)

    # Read counter
    if active and reads > 0:
        d.text((100, 1), f"#{reads}", font=font_xs, fill=C_DIM)

    # Error overlay
    if error and not data:
        d.text((4, 55), error[:24], font=font_sm, fill=C_RED)
        d.text((4, 70), "Check I2C connection", font=font_xs, fill=C_MUTED)
    elif not active and not data:
        d.text((14, 45), "BATTERY MONITOR", font=font_sm, fill=C_CYAN)
        d.text((20, 60), "BQ27220 @ 0x55", font=font_xs, fill=C_DIM)
        d.text((16, 75), "Press OK to start", font=font_xs, fill=C_MUTED)
    else:
        # Render active view
        if view_name == "GAUGE":
            _draw_gauge(d, data, fonts)
        elif view_name == "GRAPH":
            _draw_graph(d, fonts)
        elif view_name == "DETAIL":
            _draw_detail(d, data, detail_scroll, fonts)

    # Footer bar
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

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    font = scaled_font(10)
    font_sm = scaled_font(9)
    font_xs = scaled_font(7)
    font_lg = scaled_font(14)
    fonts = (font, font_sm, font_xs, font_lg)

    view_idx = 0
    detail_scroll = 0

    # Start the polling thread (it only reads when _monitoring is True)
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
                    max_scroll = max(0, len(REGISTERS) - 7)
                    detail_scroll = min(detail_scroll + 1, max_scroll)
                time.sleep(0.15)

            elif btn == "KEY2":
                with _lock:
                    has_data = bool(_current_data)
                if has_data:
                    fname = _export_snapshot()
                    # Brief feedback: show export confirmation
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
