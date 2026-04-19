#!/usr/bin/env python3
"""
RaspyJack Payload -- GPS Tracker
==================================
Author: 7h30th3r0n3

GPS tracking and logging via serial GPS module.  Parses NMEA sentences
($GPGGA and $GPRMC) for position, speed, altitude, and satellite info.
Logs to CSV and can export GPX.

Setup / Prerequisites
---------------------
- Serial GPS module (e.g., NEO-6M) connected to /dev/ttyUSB0 or
  /dev/serial0 at 9600 baud.
- pyserial installed (pip install pyserial).

Controls
--------
  OK         -- Start / stop logging
  UP / DOWN  -- Scroll log entries
  KEY1       -- Toggle display mode (coordinates / map grid)
  KEY2       -- Export GPX file
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/GPS/
"""

import os
import sys
import time
import math
import threading
import urllib.request
from io import BytesIO
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont, ImageEnhance
from payloads._display_helper import ScaledDraw, scaled_font, S
from payloads._input_helper import get_button

try:
    import gpsd as gpsd_mod
    GPSD_OK = True
except ImportError:
    gpsd_mod = None
    GPSD_OK = False

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

LOOT_DIR = "/root/Raspyjack/loot/GPS"
DEBOUNCE = 0.22

lock = threading.Lock()
_running = True

class GPSFix:
    __slots__ = (
        "latitude", "longitude", "altitude", "speed_knots",
        "satellites", "fix_quality", "utc_time", "valid",
    )

    def __init__(self):
        self.latitude = 0.0
        self.longitude = 0.0
        self.altitude = 0.0
        self.speed_knots = 0.0
        self.satellites = 0
        self.fix_quality = 0
        self.utc_time = ""
        self.valid = False

current_fix = GPSFix()
log_entries = []
logging_active = False
status_msg = "Searching..."
_sats_used = 0
_sats_visible = 0


def _sat_poller():
    """Poll gpsd JSON socket for satellite counts."""
    global _sats_used, _sats_visible
    import socket as _sock
    import json as _j
    while _running:
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(5)
            s.connect(("127.0.0.1", 2947))
            s.sendall(b'?WATCH={"enable":true,"json":true}\n')
            buf = ""
            while _running:
                data = s.recv(4096).decode("utf-8", errors="ignore")
                if not data:
                    break
                buf += data
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    if '"class":"SKY"' not in line:
                        continue
                    try:
                        sky = _j.loads(line)
                        n = sky.get("nSat", -1)
                        if n < 0:
                            continue
                        _sats_visible = n
                        u = sky.get("uSat", 0)
                        if u == 0 and "satellites" in sky:
                            u = sum(1 for sat in sky["satellites"] if sat.get("used"))
                        _sats_used = u
                    except Exception:
                        pass
            s.close()
        except Exception:
            pass
        time.sleep(3)


def _reader_thread():
    """Poll gpsd for position updates."""
    global current_fix, status_msg, log_entries, logging_active

    try:
        gpsd_mod.connect()
    except Exception:
        with lock:
            status_msg = "gpsd connect failed"
        return

    with lock:
        status_msg = "Connected to gpsd"

    threading.Thread(target=_sat_poller, daemon=True).start()

    while _running:
        try:
            pkt = gpsd_mod.get_current()
            fix = GPSFix()
            if hasattr(pkt, 'mode') and pkt.mode >= 2:
                fix.latitude = pkt.lat
                fix.longitude = pkt.lon
                fix.altitude = pkt.alt if pkt.mode >= 3 else 0.0
                fix.speed_knots = getattr(pkt, 'hspeed', 0) / 1.852
                fix.satellites = _sats_used
                fix.fix_quality = pkt.mode
                fix.valid = True
                with lock:
                    current_fix = fix
                    status_msg = f"Fix {pkt.mode}D: {_sats_used}/{_sats_visible} sats"
                    if logging_active:
                        ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                        log_entries = log_entries + [(
                            ts, fix.latitude, fix.longitude,
                            fix.altitude, fix.speed_knots,
                        )]
            else:
                with lock:
                    fix.satellites = _sats_visible
                    current_fix = fix
                    status_msg = f"No fix ({_sats_visible} sats)"
        except Exception:
            pass

        time.sleep(1)

def _export_csv(entries):
    """Write log entries to CSV."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"gps_log_{ts}.csv"
    fpath = os.path.join(LOOT_DIR, fname)
    try:
        with open(fpath, "w") as fh:
            fh.write("timestamp,latitude,longitude,altitude,speed_knots\n")
            for e in entries:
                fh.write(f"{e[0]},{e[1]},{e[2]},{e[3]},{e[4]}\n")
        return f"CSV: {fname[:16]}"
    except OSError as exc:
        return f"Err: {str(exc)[:16]}"

def _export_gpx(entries):
    """Write log entries as GPX file."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"gps_track_{ts}.gpx"
    fpath = os.path.join(LOOT_DIR, fname)
    try:
        lines = ['<?xml version="1.0" encoding="UTF-8"?>',
                 '<gpx version="1.1" creator="RaspyJack">',
                 '  <trk><name>RaspyJack Track</name><trkseg>']
        for e in entries:
            lines.append(f'    <trkpt lat="{e[1]}" lon="{e[2]}"><ele>{e[3]}</ele><time>{e[0]}</time></trkpt>')
        lines += ['  </trkseg></trk>', '</gpx>']
        with open(fpath, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        return f"GPX: {fname[:16]}"
    except OSError as exc:
        return f"Err: {str(exc)[:16]}"

def _speed_kmh(knots):
    return knots * 1.852

def _draw_coords(lcd, fix, logging, entries, scr, status):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#111")
    rec_color = "#ff2222" if logging else "#444"
    d.ellipse((118, 3, 122, 7), fill=rec_color)
    d.text((2, 1), "GPS TRACKER", font=font, fill="#00ccff")

    y = 16
    d.text((2, y), status[:22], font=font, fill="#ffaa00"); y += 13

    if fix.valid:
        d.text((2, y), f"Lat: {fix.latitude:11.6f}", font=font, fill="#00ff00"); y += 12
        d.text((2, y), f"Lon: {fix.longitude:11.6f}", font=font, fill="#00ff00"); y += 12
        d.text((2, y), f"Alt: {fix.altitude:.1f}m", font=font, fill="#ccc"); y += 12
        d.text((2, y), f"Spd: {_speed_kmh(fix.speed_knots):.1f}km/h", font=font, fill="#ccc"); y += 12
        d.text((2, y), f"Sat: {fix.satellites}  Q: {fix.fix_quality}", font=font, fill="#888"); y += 14
    else:
        d.text((4, 40), "Waiting for fix...", font=font, fill="#666")
        d.text((4, 55), f"Sats: {fix.satellites}", font=font, fill="#888")
        y = 75

    d.text((2, y), f"Log: {len(entries)} pts", font=font, fill="#888")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:log K1:mode K2:gpx", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# OSM tile map view
# ---------------------------------------------------------------------------

_TILE_CACHE = "/root/Raspyjack/loot/GPS/.tilecache"
_TILE_URL = "https://tile.openstreetmap.org/{z}/{x}/{y}.png"
_map_bg_img = None
_map_bg_bbox = None


def _lat_to_merc(lat):
    lat = max(-85.0, min(85.0, lat))
    return math.log(math.tan(math.pi / 4 + math.radians(lat) / 2))


def _fetch_tile(z, x, y):
    os.makedirs(_TILE_CACHE, exist_ok=True)
    cache_path = os.path.join(_TILE_CACHE, f"{z}_{x}_{y}.png")
    if os.path.isfile(cache_path):
        try:
            return Image.open(cache_path).convert("RGB")
        except Exception:
            pass
    try:
        req = urllib.request.Request(_TILE_URL.format(z=z, x=x, y=y),
                                     headers={"User-Agent": "RaspyJack/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = resp.read()
        with open(cache_path, "wb") as f:
            f.write(data)
        return Image.open(BytesIO(data)).convert("RGB")
    except Exception:
        return None


def _build_map(lat, lon, w, h):
    """Download 3x3 tile grid centered on position. Returns (image, bbox)."""
    z = 16
    n = 2 ** z
    xc = int((lon + 180.0) / 360.0 * n)
    lat_r = math.radians(max(-85, min(85, lat)))
    yc = int((1.0 - math.log(math.tan(lat_r) + 1.0 / math.cos(lat_r)) / math.pi) / 2.0 * n)

    big = Image.new("RGB", (3 * 256, 3 * 256), (10, 14, 20))
    for dx in range(-1, 2):
        for dy in range(-1, 2):
            tile = _fetch_tile(z, xc + dx, yc + dy)
            if tile:
                big.paste(tile, ((dx + 1) * 256, (dy + 1) * 256))

    nw_lon = (xc - 1) / n * 360.0 - 180.0
    se_lon = (xc + 2) / n * 360.0 - 180.0
    nw_lat = math.degrees(math.atan(math.sinh(math.pi * (1 - 2 * (yc - 1) / n))))
    se_lat = math.degrees(math.atan(math.sinh(math.pi * (1 - 2 * (yc + 2) / n))))

    nw_merc = _lat_to_merc(nw_lat)
    se_merc = _lat_to_merc(se_lat)

    darkened = ImageEnhance.Brightness(big).enhance(0.5)
    resized = darkened.resize((w, h), Image.LANCZOS)
    return resized, (nw_merc, se_merc, nw_lon, se_lon)


def _project(lat, lon, bbox, w, h):
    nw_merc, se_merc, nw_lon, se_lon = bbox
    merc_span = nw_merc - se_merc
    lon_span = se_lon - nw_lon
    if merc_span == 0 or lon_span == 0:
        return w // 2, h // 2
    x = int((lon - nw_lon) / lon_span * w)
    y = int((nw_merc - _lat_to_merc(lat)) / merc_span * h)
    return x, y


def _draw_map(lcd, fix, entries, is_logging):
    global _map_bg_img, _map_bg_bbox

    if not fix.valid:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.rectangle((0, 0, 127, 12), fill="#111")
        d.text((2, 1), "GPS MAP", font=font, fill="#00ccff")
        d.text((10, 55), "Waiting for GPS fix", font=font, fill="#ff4444")
        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "OK:log K1:mode K2:gpx", font=font, fill="#666")
        lcd.LCD_ShowImage(img, 0, 0)
        return

    # Load or reload tiles when near edge
    need_load = _map_bg_img is None or _map_bg_bbox is None
    if not need_load:
        cx, cy = _project(fix.latitude, fix.longitude, _map_bg_bbox, WIDTH, HEIGHT)
        margin = WIDTH // 5
        if cx < margin or cx > WIDTH - margin or cy < margin or cy > HEIGHT - margin:
            need_load = True

    if need_load:
        loading = Image.new("RGB", (WIDTH, HEIGHT), "black")
        ld = ScaledDraw(loading)
        ld.rectangle((0, 0, 127, 12), fill="#111")
        ld.text((2, 1), "GPS MAP", font=font, fill="#00ccff")
        ld.text((10, 50), "Loading tiles...", font=font, fill="#ffaa00")
        ld.text((10, 65), f"{fix.latitude:.4f}, {fix.longitude:.4f}", font=font, fill="#666")
        lcd.LCD_ShowImage(loading, 0, 0)
        try:
            _map_bg_img, _map_bg_bbox = _build_map(fix.latitude, fix.longitude, WIDTH, HEIGHT)
        except Exception:
            _map_bg_img = None
            _map_bg_bbox = None

    if _map_bg_img is None or _map_bg_bbox is None:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((10, 55), "Map unavailable", font=font, fill="#ff4444")
        lcd.LCD_ShowImage(img, 0, 0)
        return

    img = _map_bg_img.copy()
    d = ImageDraw.Draw(img)

    # Draw track
    if len(entries) >= 2:
        pts = [_project(e[1], e[2], _map_bg_bbox, WIDTH, HEIGHT) for e in entries]
        for i in range(len(pts) - 1):
            x1, y1 = pts[i]
            x2, y2 = pts[i + 1]
            if (-10 <= x1 <= WIDTH + 10 and -10 <= y1 <= HEIGHT + 10) or \
               (-10 <= x2 <= WIDTH + 10 and -10 <= y2 <= HEIGHT + 10):
                ratio = i / max(1, len(pts) - 1)
                r = int(100 * (1 - ratio))
                g = int(100 * ratio)
                d.line([(x1, y1), (x2, y2)], fill=(r, g, 80), width=2)

    # Draw trail dots
    for e in entries[-50:]:
        x, y = _project(e[1], e[2], _map_bg_bbox, WIDTH, HEIGHT)
        if 0 <= x <= WIDTH and 0 <= y <= HEIGHT:
            d.ellipse([x - 1, y - 1, x + 1, y + 1], fill="#00ff00")

    # Current position
    cx, cy = _project(fix.latitude, fix.longitude, _map_bg_bbox, WIDTH, HEIGHT)
    d.line([(cx - 6, cy), (cx + 6, cy)], fill="#ffffff", width=1)
    d.line([(cx, cy - 6), (cx, cy + 6)], fill="#ffffff", width=1)
    d.ellipse([cx - 4, cy - 4, cx + 4, cy + 4], outline="#ff2222" if is_logging else "#00ccff", width=1)

    # Header overlay
    s = max(1, S(1))
    d.rectangle([(0, 0), (WIDTH, 12 * s)], fill="#111111")
    d.text((2 * s, 1 * s), "GPS MAP", font=font, fill="#00ccff")
    spd = fix.speed_knots * 1.852
    d.text((50 * s, 1 * s), f"{spd:.0f}km/h {fix.satellites}sat {len(entries)}pts", font=font, fill="#888")

    # Recording indicator
    if is_logging:
        d.ellipse([WIDTH - 8 * s, 3 * s, WIDTH - 4 * s, 7 * s], fill="#ff2222")

    lcd.LCD_ShowImage(img, 0, 0)

def _draw_log(lcd, entries, scr):
    """Show scrollable log entries."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), f"LOG ({len(entries)} pts)", font=font, fill="#00ccff")

    y = 16
    visible = 7
    if not entries:
        d.text((4, 50), "No entries yet", font=font, fill="#666")
    else:
        end = min(len(entries), scr + visible)
        for i in range(scr, end):
            e = entries[i]
            ts = e[0][-9:-1]  # HH:MM:SS
            d.text((2, y), f"{ts} {e[1]:.4f},{e[2]:.4f}", font=font, fill="#ccc")
            y += 13

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "^v:scroll K1:mode", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)

DISPLAY_MODES = ["coords", "map", "log"]

def main():
    global _running, logging_active, log_entries, status_msg

    if not GPSD_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "gpsd module missing!", font=font, fill="#ff0000")
        d.text((4, 65), "pip install gpsd-py3", font=font, fill="#888")
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        LCD.LCD_Clear()
        GPIO.cleanup()
        return 1

    reader = threading.Thread(target=_reader_thread, daemon=True)
    reader.start()

    mode_idx = 0
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
            elif btn == "OK":
                with lock:
                    logging_active = not logging_active
                    if logging_active:
                        status_msg = "Logging started"
                    else:
                        status_msg = "Logging stopped"
                        # Auto-save CSV
                        if log_entries:
                            result = _export_csv(log_entries)
                            status_msg = result
            elif btn == "KEY1":
                mode_idx = (mode_idx + 1) % len(DISPLAY_MODES)
                scroll = 0
            elif btn == "KEY2":
                with lock:
                    entries_snap = list(log_entries)
                if entries_snap:
                    result = _export_gpx(entries_snap)
                    with lock:
                        status_msg = result
                else:
                    with lock:
                        status_msg = "No data to export"
            elif btn == "UP":
                scroll = max(0, scroll - 1)
            elif btn == "DOWN":
                with lock:
                    max_s = max(0, len(log_entries) - 7)
                scroll = min(scroll + 1, max_s)

            with lock:
                fix_snap = current_fix
                entries_snap = list(log_entries)
                st = status_msg
                is_logging = logging_active

            mode = DISPLAY_MODES[mode_idx]
            if mode == "coords":
                _draw_coords(LCD, fix_snap, is_logging, entries_snap, scroll, st)
            elif mode == "map":
                _draw_map(LCD, fix_snap, entries_snap, is_logging)
            elif mode == "log":
                _draw_log(LCD, entries_snap, scroll)

            time.sleep(0.08)

    finally:
        _running = False
        if log_entries:
            _export_csv(log_entries)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
