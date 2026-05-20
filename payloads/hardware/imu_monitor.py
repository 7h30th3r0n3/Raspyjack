#!/usr/bin/env python3
"""
RaspyJack Payload -- IMU Monitor (LSM6DS3TR)
==============================================
Author: 7h30th3r0n3

Real-time 6-axis IMU visualisation for the LSM6DS3TR accelerometer +
gyroscope.  Four selectable views: 3-D rotating cube, oscilloscope
waveforms, spirit-level bubble, and raw numeric readout.

Sensor access
-------------
Primary:  Linux IIO sysfs  (/sys/bus/iio/devices/iio:deviceX)
Fallback: smbus2 direct I2C at 0x6A / 0x6B

Setup / Prerequisites
---------------------
- LSM6DS3TR connected on I2C bus 1.
- Overlay ``lsm6ds3tr-overlay`` loaded in config.txt.
- ``smbus2`` pip package for the I2C fallback path.

Controls
--------
  OK          -- Start / Stop monitoring
  KEY1        -- Cycle views (3D -> SCOPE -> LEVEL -> RAW)
  UP / DOWN   -- Scroll in RAW view, adjust sensitivity in SCOPE
  KEY2        -- Export snapshot + recent history to loot
  KEY3        -- Exit

Loot: /root/Raspyjack/loot/IMU/imu_YYYYMMDD_HHMMSS.json

Views
-----
1. 3D    -- Cube rotating with accelerometer tilt (pitch / roll)
2. SCOPE -- Rolling oscilloscope: accel X/Y/Z as coloured traces
3. LEVEL -- Spirit-level bubble + pitch / roll angles
4. RAW   -- Numeric readout: accel (g), gyro (deg/s), temperature
"""

import os
import sys
import math
import json
import time
import glob
import threading
from collections import deque
from datetime import datetime

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

LOOT_DIR = "/root/Raspyjack/loot/IMU"
SAMPLE_RATE_HZ = 50
HISTORY_LEN = 300
VIEW_NAMES = ("3D", "SCOPE", "LEVEL", "RAW")

# Theme colours (128-base dark modern palette)
C_BG = "#0a0a12"
C_HEADER = "#0d1117"
C_CYAN = "#00E5FF"
C_RED = "#FF5252"
C_GREEN = "#00E676"
C_BLUE = "#448AFF"
C_RED_L = "#FF8A80"
C_GREEN_L = "#B9F6CA"
C_BLUE_L = "#82B1FF"
C_PURPLE = "#7C4DFF"
C_MUTED = "#888888"
C_DIM = "#555555"
C_WHITE = "#EEEEEE"

# ---------------------------------------------------------------------------
# IIO sysfs sensor backend
# ---------------------------------------------------------------------------

def _find_iio_device():
    """Locate the LSM6DS3 IIO device directory, or return None."""
    for dev_path in sorted(glob.glob("/sys/bus/iio/devices/iio:device*")):
        name_file = os.path.join(dev_path, "name")
        if not os.path.isfile(name_file):
            continue
        try:
            with open(name_file, "r") as fh:
                name = fh.read().strip().lower()
            if "lsm6ds3" in name:
                return dev_path
        except OSError:
            continue
    return None


def _read_sysfs(path):
    """Read a single sysfs file and return its stripped content."""
    try:
        with open(path, "r") as fh:
            return fh.read().strip()
    except OSError:
        return None


class IIOBackend:
    """Read IMU data through the Linux IIO sysfs interface."""

    def __init__(self, dev_path):
        self._base = dev_path
        self._accel_scale = self._read_float("in_accel_scale", 0.000598)
        self._gyro_scale = self._read_float("in_anglvel_scale", 0.001065)

    def _read_float(self, name, default):
        val = _read_sysfs(os.path.join(self._base, name))
        if val is not None:
            try:
                return float(val)
            except ValueError:
                pass
        return default

    def _raw(self, name):
        val = _read_sysfs(os.path.join(self._base, name))
        if val is not None:
            try:
                return int(val)
            except ValueError:
                pass
        return 0

    def read(self):
        """Return (ax, ay, az, gx, gy, gz, temp) in SI units.
        Axes swapped to match CardputerZero physical orientation."""
        raw_x = self._raw("in_accel_x_raw") * self._accel_scale / 9.80665
        raw_y = self._raw("in_accel_y_raw") * self._accel_scale / 9.80665
        az = self._raw("in_accel_z_raw") * self._accel_scale / 9.80665
        ax, ay = raw_y, -raw_x
        raw_gx = self._raw("in_anglvel_x_raw") * self._gyro_scale * (180.0 / math.pi)
        raw_gy = self._raw("in_anglvel_y_raw") * self._gyro_scale * (180.0 / math.pi)
        gz = self._raw("in_anglvel_z_raw") * self._gyro_scale * (180.0 / math.pi)
        gx, gy = raw_gy, raw_gx
        temp_raw = self._raw("in_temp_raw")
        temp_scale = self._read_float("in_temp_scale", 0.00390625)
        temp_offset = self._read_float("in_temp_offset", 6400)
        temp_c = (temp_raw + temp_offset) * temp_scale
        return (ax, ay, az, gx, gy, gz, temp_c)


# ---------------------------------------------------------------------------
# smbus2 direct I2C fallback
# ---------------------------------------------------------------------------

class SMBusBackend:
    """Read LSM6DS3TR registers directly over I2C."""

    _WHO_AM_I = 0x0F
    _CTRL1_XL = 0x10
    _CTRL2_G = 0x11
    _OUT_TEMP_L = 0x20
    _OUTX_L_G = 0x22
    _OUTX_L_XL = 0x28

    def __init__(self, bus_num=1, addr=0x6A):
        import smbus2
        self._bus = smbus2.SMBus(bus_num)
        self._addr = addr
        # Verify WHO_AM_I
        wai = self._bus.read_byte_data(self._addr, self._WHO_AM_I)
        if wai not in (0x69, 0x6A, 0x6C):
            raise RuntimeError(f"Unexpected WHO_AM_I: 0x{wai:02X}")
        # Enable accel 104 Hz, +/-2g  and gyro 104 Hz, 245 dps
        self._bus.write_byte_data(self._addr, self._CTRL1_XL, 0x40)
        self._bus.write_byte_data(self._addr, self._CTRL2_G, 0x40)
        self._accel_sens = 0.000061  # g / LSB for +/-2g
        self._gyro_sens = 0.00875   # dps / LSB for 245 dps

    def _read_i16(self, reg):
        low = self._bus.read_byte_data(self._addr, reg)
        high = self._bus.read_byte_data(self._addr, reg + 1)
        val = (high << 8) | low
        if val >= 0x8000:
            val -= 0x10000
        return val

    def read(self):
        raw_x = self._read_i16(self._OUTX_L_XL) * self._accel_sens
        raw_y = self._read_i16(self._OUTX_L_XL + 2) * self._accel_sens
        az = self._read_i16(self._OUTX_L_XL + 4) * self._accel_sens
        ax, ay = raw_y, -raw_x
        raw_gx = self._read_i16(self._OUTX_L_G) * self._gyro_sens
        raw_gy = self._read_i16(self._OUTX_L_G + 2) * self._gyro_sens
        gz = self._read_i16(self._OUTX_L_G + 4) * self._gyro_sens
        gx, gy = raw_gy, raw_gx
        temp_raw = self._read_i16(self._OUT_TEMP_L)
        temp_c = 25.0 + temp_raw / 256.0
        return (ax, ay, az, gx, gy, gz, temp_c)

    def close(self):
        try:
            self._bus.close()
        except Exception:
            pass


def _create_backend():
    """Try IIO first, then smbus2 at 0x6A / 0x6B."""
    iio_path = _find_iio_device()
    if iio_path is not None:
        try:
            return IIOBackend(iio_path), "IIO"
        except Exception:
            pass
    try:
        return SMBusBackend(1, 0x6A), "I2C:0x6A"
    except Exception:
        pass
    try:
        return SMBusBackend(1, 0x6B), "I2C:0x6B"
    except Exception:
        pass
    return None, "NONE"


# ---------------------------------------------------------------------------
# Shared state (protected by _lock)
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_running = True
_monitoring = False

# Latest reading
_latest = (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 25.0)

# Rolling history for scope view
_hist_ax = deque(maxlen=HISTORY_LEN)
_hist_ay = deque(maxlen=HISTORY_LEN)
_hist_az = deque(maxlen=HISTORY_LEN)

# Full snapshot list for export (last HISTORY_LEN samples)
_snapshot_buf = deque(maxlen=HISTORY_LEN)

_status_msg = "Ready"
_backend_label = ""


# ---------------------------------------------------------------------------
# Reader thread
# ---------------------------------------------------------------------------

def _reader_thread(backend):
    """Continuously read the IMU at ~SAMPLE_RATE_HZ."""
    global _latest, _monitoring, _status_msg
    interval = 1.0 / SAMPLE_RATE_HZ

    while _running:
        if not _monitoring:
            time.sleep(0.05)
            continue
        t0 = time.monotonic()
        try:
            sample = backend.read()
        except Exception as exc:
            with _lock:
                _status_msg = f"Read err: {str(exc)[:14]}"
            time.sleep(0.1)
            continue

        ts = time.time()
        with _lock:
            _latest = sample
            _hist_ax.append(sample[0])
            _hist_ay.append(sample[1])
            _hist_az.append(sample[2])
            _snapshot_buf.append({
                "t": round(ts, 3),
                "ax": round(sample[0], 4),
                "ay": round(sample[1], 4),
                "az": round(sample[2], 4),
                "gx": round(sample[3], 2),
                "gy": round(sample[4], 2),
                "gz": round(sample[5], 2),
                "tc": round(sample[6], 1),
            })
        elapsed = time.monotonic() - t0
        sleep_time = interval - elapsed
        if sleep_time > 0:
            time.sleep(sleep_time)


# ---------------------------------------------------------------------------
# 3-D cube projection
# ---------------------------------------------------------------------------

# Unit cube vertices centred on origin (half-edge = 0.5)
_CUBE_VERTS = [
    (-1, -1, -1), (1, -1, -1), (1, 1, -1), (-1, 1, -1),
    (-1, -1, 1), (1, -1, 1), (1, 1, 1), (-1, 1, 1),
]

# Edges: pairs of vertex indices
_CUBE_EDGES = [
    (0, 1), (1, 2), (2, 3), (3, 0),
    (4, 5), (5, 6), (6, 7), (7, 4),
    (0, 4), (1, 5), (2, 6), (3, 7),
]

# Front face (for shading)
_CUBE_FRONT = [(0, 1, 2, 3)]
_CUBE_TOP = [(3, 2, 6, 7)]


def _rotate_y(verts, angle):
    """Rotate vertices around Y axis."""
    c, s = math.cos(angle), math.sin(angle)
    return [(x * c + z * s, y, -x * s + z * c) for (x, y, z) in verts]


def _rotate_x(verts, angle):
    """Rotate vertices around X axis."""
    c, s = math.cos(angle), math.sin(angle)
    return [(x, y * c - z * s, y * s + z * c) for (x, y, z) in verts]


def _rotate_z(verts, angle):
    """Rotate vertices around Z axis."""
    c, s = math.cos(angle), math.sin(angle)
    return [(x * c - y * s, x * s + y * c, z) for (x, y, z) in verts]


def _project(verts, cx, cy, scale, dist=5.0):
    """Perspective project 3-D vertices to 2-D screen coords."""
    pts = []
    for (x, y, z) in verts:
        factor = dist / (dist + z) if (dist + z) != 0 else 1.0
        px = cx + x * scale * factor
        py = cy + y * scale * factor
        pts.append((px, py))
    return pts


def _draw_3d_view(d, fonts, ax, ay, az):
    """Render the 3-D cube view."""
    font_s, font_t = fonts

    # Calculate pitch and roll from accelerometer
    pitch = math.atan2(-ax, math.sqrt(ay * ay + az * az))
    roll = math.atan2(ay, az)

    # Rotate cube to match physical tilt
    verts = list(_CUBE_VERTS)
    verts = _rotate_y(verts, roll)
    verts = _rotate_x(verts, pitch)

    # Project to 2-D (cube centre at 64, 48 in 128-base)
    cx, cy = 64, 44
    cube_scale = 18
    pts = _project(verts, cx, cy, cube_scale)

    # Draw filled faces (back faces first for simple depth)
    # Sort edges by average z for basic depth ordering
    edge_z = []
    for (i, j) in _CUBE_EDGES:
        avg_z = (verts[i][2] + verts[j][2]) / 2.0
        edge_z.append((avg_z, i, j))
    edge_z.sort(key=lambda t: t[0])

    # Draw back edges first (dimmer), then front edges (brighter)
    half = len(edge_z) // 2
    for idx, (_, i, j) in enumerate(edge_z):
        colour = C_DIM if idx < half else C_CYAN
        d.line([pts[i], pts[j]], fill=colour, width=1)

    # Draw vertices as dots
    for pt in pts:
        r = 1
        d.ellipse((pt[0] - r, pt[1] - r, pt[0] + r, pt[1] + r), fill=C_PURPLE)

    # Accel values below cube
    y_val = 82
    d.text((4, y_val), f"X:{ax:+.2f}g", font=font_s, fill=C_RED)
    d.text((46, y_val), f"Y:{ay:+.2f}g", font=font_s, fill=C_GREEN)
    d.text((88, y_val), f"Z:{az:+.2f}g", font=font_s, fill=C_BLUE)

    # Pitch / Roll
    y_val += 12
    p_deg = math.degrees(pitch)
    r_deg = math.degrees(roll)
    d.text((4, y_val), f"P:{p_deg:+5.1f}", font=font_t, fill=C_MUTED)
    d.text((56, y_val), f"R:{r_deg:+5.1f}", font=font_t, fill=C_MUTED)


# ---------------------------------------------------------------------------
# Scope view
# ---------------------------------------------------------------------------

def _draw_scope_view(d, fonts, sensitivity):
    """Render rolling oscilloscope traces for accel X/Y/Z."""
    font_s, font_t = fonts

    # Graph area: x 4..123, y 16..95 (128-base)
    gx0, gx1 = 4, 123
    gy0, gy1 = 18, 93
    g_w = gx1 - gx0
    g_h = gy1 - gy0
    g_mid = gy0 + g_h // 2

    # Grid lines
    d.line([(gx0, g_mid), (gx1, g_mid)], fill="#1a1a2e", width=1)
    q1 = gy0 + g_h // 4
    q3 = gy0 + 3 * g_h // 4
    d.line([(gx0, q1), (gx1, q1)], fill="#111122", width=1)
    d.line([(gx0, q3), (gx1, q3)], fill="#111122", width=1)

    # Border
    d.rectangle((gx0, gy0, gx1, gy1), outline="#1c1c2e")

    # Draw traces
    with _lock:
        hx = list(_hist_ax)
        hy = list(_hist_ay)
        hz = list(_hist_az)

    scale = (g_h / 2.0) / max(sensitivity, 0.1)
    traces = [(hx, C_RED), (hy, C_GREEN), (hz, C_BLUE)]

    for data, colour in traces:
        n = len(data)
        if n < 2:
            continue
        # Use the most recent g_w samples
        start = max(0, n - g_w)
        points = []
        for i in range(start, n):
            px = gx0 + (i - start)
            if px > gx1:
                break
            val = data[i]
            py = g_mid - val * scale
            py = max(gy0, min(gy1, py))
            points.append((px, py))
        if len(points) >= 2:
            d.line(points, fill=colour, width=1)

    # Legend
    d.text((4, 96), "X", font=font_t, fill=C_RED)
    d.text((14, 96), "Y", font=font_t, fill=C_GREEN)
    d.text((24, 96), "Z", font=font_t, fill=C_BLUE)
    d.text((38, 96), f"sens:{sensitivity:.1f}g", font=font_t, fill=C_MUTED)

    # Latest values
    if hx:
        d.text((4, 106), f"{hx[-1]:+.2f}", font=font_t, fill=C_RED)
    if hy:
        d.text((42, 106), f"{hy[-1]:+.2f}", font=font_t, fill=C_GREEN)
    if hz:
        d.text((80, 106), f"{hz[-1]:+.2f}", font=font_t, fill=C_BLUE)


# ---------------------------------------------------------------------------
# Spirit-level view
# ---------------------------------------------------------------------------

def _draw_level_view(d, fonts, ax, ay, az):
    """Render a spirit-level bubble with pitch/roll angles."""
    font_s, font_t = fonts

    # Calculate pitch and roll
    pitch = math.atan2(-ax, math.sqrt(ay * ay + az * az))
    roll = math.atan2(ay, az)
    p_deg = math.degrees(pitch)
    r_deg = math.degrees(roll)

    # Level circle: centre at (64, 50), radius 30 (128-base)
    cx, cy = 64, 48
    radius = 28

    # Outer ring
    d.ellipse(
        (cx - radius, cy - radius, cx + radius, cy + radius),
        outline=C_DIM, width=1,
    )
    # Inner rings for reference
    for r_frac in (0.5, 0.25):
        r = int(radius * r_frac)
        d.ellipse(
            (cx - r, cy - r, cx + r, cy + r),
            outline="#1a1a2e", width=1,
        )

    # Crosshair
    d.line([(cx - radius, cy), (cx + radius, cy)], fill="#1a1a2e", width=1)
    d.line([(cx, cy - radius), (cx, cy + radius)], fill="#1a1a2e", width=1)

    # Bubble position: map tilt to position (max 90 deg -> edge)
    max_angle = 45.0
    bx = cx + (r_deg / max_angle) * radius
    by = cy - (p_deg / max_angle) * radius
    # Clamp inside circle
    dx = bx - cx
    dy = by - cy
    dist = math.sqrt(dx * dx + dy * dy)
    if dist > radius - 3:
        scale_f = (radius - 3) / max(dist, 0.001)
        bx = cx + dx * scale_f
        by = cy + dy * scale_f
        dist = radius - 3

    # Bubble colour: green when level, yellow when tilted, red when extreme
    if dist < radius * 0.15:
        bubble_col = C_GREEN
    elif dist < radius * 0.5:
        bubble_col = "#FFAB40"
    else:
        bubble_col = C_RED

    bubble_r = 4
    d.ellipse(
        (bx - bubble_r, by - bubble_r, bx + bubble_r, by + bubble_r),
        fill=bubble_col,
    )
    # Inner highlight
    d.ellipse(
        (bx - 1, by - 2, bx + 1, by),
        fill=C_WHITE,
    )

    # Centre dot
    d.ellipse((cx - 1, cy - 1, cx + 1, cy + 1), fill=C_PURPLE)

    # Angle readout
    y_info = 82
    d.text((4, y_info), "PITCH", font=font_t, fill=C_MUTED)
    d.text((4, y_info + 10), f"{p_deg:+6.1f}\xb0", font=font_s, fill=C_CYAN)
    d.text((70, y_info), "ROLL", font=font_t, fill=C_MUTED)
    d.text((70, y_info + 10), f"{r_deg:+6.1f}\xb0", font=font_s, fill=C_CYAN)

    # Level indicator text
    if abs(p_deg) < 2.0 and abs(r_deg) < 2.0:
        d.text((44, y_info + 22), "LEVEL", font=font_t, fill=C_GREEN)


# ---------------------------------------------------------------------------
# Raw data view
# ---------------------------------------------------------------------------

def _draw_raw_view(d, fonts, sample, scroll_offset):
    """Render numeric readout of all sensor axes."""
    font_s, font_t = fonts
    ax, ay, az, gx, gy, gz, temp = sample

    lines = [
        ("ACCELEROMETER", None, C_PURPLE),
        ("  X", f"{ax:+8.4f} g", C_RED),
        ("  Y", f"{ay:+8.4f} g", C_GREEN),
        ("  Z", f"{az:+8.4f} g", C_BLUE),
        ("GYROSCOPE", None, C_PURPLE),
        ("  X", f"{gx:+8.2f} \xb0/s", C_RED_L),
        ("  Y", f"{gy:+8.2f} \xb0/s", C_GREEN_L),
        ("  Z", f"{gz:+8.2f} \xb0/s", C_BLUE_L),
        ("TEMPERATURE", None, C_PURPLE),
        ("  T", f"{temp:6.1f} \xb0C", C_CYAN),
    ]

    row_h = 10
    visible_rows = 8
    max_scroll = max(0, len(lines) - visible_rows)
    offset = min(scroll_offset, max_scroll)

    y = 16
    for idx in range(offset, min(offset + visible_rows, len(lines))):
        label, value, colour = lines[idx]
        if value is None:
            # Section header
            d.text((4, y), label, font=font_t, fill=colour)
        else:
            d.text((4, y), label, font=font_t, fill=C_MUTED)
            d.text((28, y), value, font=font_s, fill=colour)
        y += row_h

    # Scroll indicator
    if max_scroll > 0:
        bar_h = max(4, int(60 * visible_rows / len(lines)))
        bar_y = 18 + int((60 - bar_h) * offset / max(max_scroll, 1))
        d.rectangle((124, bar_y, 126, bar_y + bar_h), fill=C_DIM)

    return offset


# ---------------------------------------------------------------------------
# Export to loot
# ---------------------------------------------------------------------------

def _export_loot(latest_sample):
    """Write current snapshot and recent history to JSON."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"imu_{ts}.json")

    ax, ay, az, gx, gy, gz, temp = latest_sample

    with _lock:
        history = list(_snapshot_buf)

    data = {
        "timestamp": ts,
        "sensor": "LSM6DS3TR",
        "backend": _backend_label,
        "snapshot": {
            "accel_g": {"x": round(ax, 4), "y": round(ay, 4), "z": round(az, 4)},
            "gyro_dps": {"x": round(gx, 2), "y": round(gy, 2), "z": round(gz, 2)},
            "temp_c": round(temp, 1),
        },
        "history_samples": len(history),
        "history": history,
    }

    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)

    return os.path.basename(filepath)


# ---------------------------------------------------------------------------
# Main frame renderer
# ---------------------------------------------------------------------------

def _draw_frame(lcd, fonts, view_idx, sensitivity, raw_scroll):
    """Compose and display a single frame."""
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)
    font_s, font_t = fonts

    with _lock:
        sample = _latest
        monitoring = _monitoring
        msg = _status_msg
        bl = _backend_label

    ax, ay, az, gx, gy, gz, temp = sample
    view_name = VIEW_NAMES[view_idx]

    # Header bar
    d.rectangle((0, 0, 127, 13), fill=C_HEADER)
    d.text((2, 1), f"IMU {view_name}", font=font_s, fill=C_CYAN)
    # Status dot
    dot_col = C_GREEN if monitoring else C_RED
    d.ellipse((110, 3, 115, 8), fill=dot_col)
    # Backend label
    d.text((80, 1), bl[:6], font=font_t, fill=C_DIM)

    # Status message line
    if msg and msg != "OK":
        d.text((2, 108), msg[:26], font=font_t, fill=C_MUTED)

    # View content
    if view_idx == 0:
        _draw_3d_view(d, fonts, ax, ay, az)
    elif view_idx == 1:
        _draw_scope_view(d, fonts, sensitivity)
    elif view_idx == 2:
        _draw_level_view(d, fonts, ax, ay, az)
    elif view_idx == 3:
        raw_scroll = _draw_raw_view(d, fonts, sample, raw_scroll)

    # Footer bar
    d.rectangle((0, 117, 127, 127), fill=C_HEADER)
    footer = "OK:run K1:view K3:exit"
    d.text((2, 118), footer, font=font_t, fill=C_DIM)

    lcd.LCD_ShowImage(img, 0, 0)
    return raw_scroll


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, _monitoring, _status_msg, _backend_label

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    font_s = scaled_font(9)
    font_t = scaled_font(8)
    fonts = (font_s, font_t)

    # Try to initialise sensor backend
    backend, label = _create_backend()
    _backend_label = label

    if backend is None:
        _status_msg = "No IMU found!"
        _draw_frame(lcd, fonts, 0, 2.0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    _status_msg = f"IMU: {label}"

    # Start reader thread
    reader = threading.Thread(target=_reader_thread, args=(backend,), daemon=True)
    reader.start()

    view_idx = 0
    sensitivity = 2.0   # +/- g range for scope view
    raw_scroll = 0

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK":
                with _lock:
                    _monitoring = not _monitoring
                    _status_msg = "Monitoring" if _monitoring else "Paused"
                time.sleep(0.2)

            elif btn == "KEY1":
                view_idx = (view_idx + 1) % len(VIEW_NAMES)
                raw_scroll = 0
                with _lock:
                    _status_msg = f"View: {VIEW_NAMES[view_idx]}"
                time.sleep(0.2)

            elif btn == "UP":
                if view_idx == 3:
                    raw_scroll = max(0, raw_scroll - 1)
                elif view_idx == 1:
                    sensitivity = min(16.0, sensitivity + 0.5)
                    with _lock:
                        _status_msg = f"Sens: {sensitivity:.1f}g"
                time.sleep(0.15)

            elif btn == "DOWN":
                if view_idx == 3:
                    raw_scroll += 1
                elif view_idx == 1:
                    sensitivity = max(0.5, sensitivity - 0.5)
                    with _lock:
                        _status_msg = f"Sens: {sensitivity:.1f}g"
                time.sleep(0.15)

            elif btn == "KEY2":
                with _lock:
                    sample_now = _latest
                fname = _export_loot(sample_now)
                with _lock:
                    _status_msg = f"Saved: {fname[:16]}"
                time.sleep(0.3)

            raw_scroll = _draw_frame(lcd, fonts, view_idx, sensitivity, raw_scroll)
            time.sleep(0.03)

    finally:
        _running = False
        _monitoring = False
        time.sleep(0.2)
        if hasattr(backend, "close"):
            backend.close()
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
