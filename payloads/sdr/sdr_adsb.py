#!/usr/bin/env python3
"""
RaspyJack Payload -- ADS-B Aircraft Tracker
=============================================
Track aircraft via ADS-B (1090 MHz) using RTL-SDR.
Decodes Mode-S messages: callsign, position, altitude, speed.
Enriches with offline aircraft database (registration, type, operator).
Displays on LCD + writes live JSON for WebUI integration.

Controls:
  OK         Start/Stop tracking
  UP/DOWN    Scroll aircraft list
  KEY1       Switch view (List / Detail / Map / Stats)
  KEY2       Save session
  KEY3       Exit
"""

import os
import sys
import time
import math
import json
import sqlite3
import struct
import subprocess
import threading
from datetime import datetime
import urllib.request
from io import BytesIO
from PIL import ImageEnhance

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font, S
from payloads._input_helper import get_button
from payloads.sdr._sdr_core import detect_sdr

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
LOOT_DIR = "/root/Raspyjack/loot/SDR/adsb"
DEBOUNCE = 0.18
_last_btn = 0
VIEWS = ["list", "detail", "map", "stats"]

LIVE_JSON_PATH = "/dev/shm/rj_adsb_live.json"
SESSION_DIR = "/root/Raspyjack/loot/SDR/adsb/sessions"

# ADS-B constants
ADSB_FREQ = 1090000000
ADSB_RATE = 2000000
MODES_PREAMBLE = [1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0]

# Aircraft state
aircraft = {}
lock = threading.Lock()
_shutdown = threading.Event()
_session_path = ""

# ---------------------------------------------------------------------------
# Aircraft database lookup
# ---------------------------------------------------------------------------

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
_DB_PATH = os.path.join(_DATA_DIR, "aircraft.db")
_db_cache = {}

_airlines = None
_airports = None
_route_cache = {}
_route_queue = []
_route_lock = threading.Lock()


def _load_airlines():
    global _airlines
    if _airlines is not None:
        return
    path = os.path.join(_DATA_DIR, "airlines.json")
    try:
        with open(path) as f:
            _airlines = json.load(f)
    except Exception:
        _airlines = {}


def _load_airports():
    global _airports
    if _airports is not None:
        return
    path = os.path.join(_DATA_DIR, "airports.json")
    try:
        with open(path) as f:
            _airports = json.load(f)
    except Exception:
        _airports = {}


def _lookup_airline(callsign):
    """Extract airline info from callsign prefix (first 3 alpha chars)."""
    _load_airlines()
    if not callsign or not _airlines:
        return {"airline": "", "airline_country": ""}
    prefix = ""
    for c in callsign:
        if c.isalpha():
            prefix += c
        else:
            break
    if len(prefix) < 2:
        return {"airline": "", "airline_country": ""}
    info = _airlines.get(prefix[:3], {})
    return {"airline": info.get("name", ""), "airline_country": info.get("country", "")}


def _lookup_airport(icao_code):
    """Look up airport by ICAO 4-letter code."""
    _load_airports()
    if not _airports or not icao_code:
        return {}
    return _airports.get(icao_code.upper(), {})


def _format_airport(icao_code):
    """Format airport as 'City Name (ICAO)' or just the code."""
    info = _lookup_airport(icao_code)
    if info:
        return f"{info.get('city', '')} {info.get('name', '')} ({icao_code})".strip()
    return icao_code


def _lookup_route(callsign):
    """Look up flight route via OpenSky API (cached, non-blocking result)."""
    if not callsign:
        return {"departure": "", "arrival": ""}
    cs = callsign.strip()
    if cs in _route_cache:
        return _route_cache[cs]
    with _route_lock:
        if cs not in _route_queue:
            _route_queue.append(cs)
    return {"departure": "", "arrival": ""}


def _route_resolver():
    """Background thread that resolves flight routes via OpenSky API."""
    while not _shutdown.is_set():
        cs = None
        with _route_lock:
            if _route_queue:
                cs = _route_queue.pop(0)
        if not cs:
            _shutdown.wait(2)
            continue
        result = {"departure": "", "arrival": ""}
        try:
            url = f"https://opensky-network.org/api/routes?callsign={cs}"
            req = urllib.request.Request(url, headers={"User-Agent": "RaspyJack/1.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode())
            route = data.get("route", [])
            if len(route) >= 2:
                result["departure"] = _format_airport(route[0])
                result["arrival"] = _format_airport(route[-1])
        except Exception:
            pass
        _route_cache[cs] = result
        if len(_route_cache) > 500:
            oldest = next(iter(_route_cache))
            del _route_cache[oldest]
        with lock:
            for ac in aircraft.values():
                if ac.get("callsign", "").strip() == cs:
                    ac["departure"] = result["departure"]
                    ac["arrival"] = result["arrival"]
        _shutdown.wait(0.5)


def _lookup_aircraft(icao_hex):
    """Look up enrichment data from the offline SQLite database."""
    icao_lower = icao_hex.lower()
    if icao_lower in _db_cache:
        return _db_cache[icao_lower]
    result = {"registration": "", "typecode": "", "type_desc": "", "operator": "", "country": ""}
    try:
        if not os.path.isfile(_DB_PATH):
            _db_cache[icao_lower] = result
            return result
        conn = sqlite3.connect(_DB_PATH, timeout=2)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT registration, typecode, type_desc, operator, country FROM aircraft WHERE icao=?",
            (icao_lower,),
        ).fetchone()
        conn.close()
        if row:
            result = {k: (row[k] or "") for k in ("registration", "typecode", "type_desc", "operator", "country")}
    except Exception:
        pass
    _db_cache[icao_lower] = result
    return result


def _btn():
    global _last_btn
    btn = get_button(PINS, GPIO)
    if btn:
        now = time.time()
        if now - _last_btn < DEBOUNCE:
            return None
        _last_btn = now
    return btn


# ---------------------------------------------------------------------------
# Mode-S decoder (pure Python, no pyModeS)
# ---------------------------------------------------------------------------

def _hex_to_bin(hexstr):
    return bin(int(hexstr, 16))[2:].zfill(len(hexstr) * 4)


def _crc(msg_hex):
    """CRC-24 for Mode-S messages."""
    msg_bin = _hex_to_bin(msg_hex)
    n_bits = len(msg_bin)
    gen = 0x1FFF409
    msg_int = int(msg_bin, 2)
    for i in range(n_bits - 24):
        if msg_int & (1 << (n_bits - 1 - i)):
            msg_int ^= gen << (n_bits - 25 - i)
    return msg_int & 0xFFFFFF


def _decode_callsign(msg_hex):
    """Decode aircraft callsign from TC=1-4."""
    chars = "?ABCDEFGHIJKLMNOPQRSTUVWXYZ????? 0123456789??????"
    msg_bin = _hex_to_bin(msg_hex)
    data = msg_bin[40:88]
    cs = ""
    for i in range(8):
        idx = int(data[8 + i * 6:8 + i * 6 + 6], 2)
        if idx < len(chars):
            cs += chars[idx]
    return cs.strip()


def _decode_altitude(msg_hex):
    """Decode altitude from TC=9-18 (airborne position)."""
    msg_bin = _hex_to_bin(msg_hex)
    alt_bits = msg_bin[40:52]
    q_bit = alt_bits[7]
    if q_bit == "1":
        alt_code = alt_bits[:7] + alt_bits[8:]
        alt = int(alt_code, 2) * 25 - 1000
        return alt
    return None


def _decode_cpr_position(msg_hex):
    """Extract CPR latitude/longitude from TC=9-18. Returns (lat_cpr, lon_cpr, odd_flag)."""
    msg_bin = _hex_to_bin(msg_hex)
    flag = int(msg_bin[53])
    lat_cpr = int(msg_bin[54:71], 2) / 131072.0
    lon_cpr = int(msg_bin[71:88], 2) / 131072.0
    return lat_cpr, lon_cpr, flag


def _decode_velocity(msg_hex):
    """Decode velocity from TC=19."""
    msg_bin = _hex_to_bin(msg_hex)
    sub = int(msg_bin[37:40], 2)
    if sub in (1, 2):
        ew_dir = int(msg_bin[45])
        ew_vel = int(msg_bin[46:56], 2) - 1
        ns_dir = int(msg_bin[56])
        ns_vel = int(msg_bin[57:67], 2) - 1
        if ew_dir:
            ew_vel = -ew_vel
        if ns_dir:
            ns_vel = -ns_vel
        speed = int((ew_vel ** 2 + ns_vel ** 2) ** 0.5)
        heading = int(math.degrees(math.atan2(ew_vel, ns_vel)) % 360)
        return speed, heading
    return None, None


def _cpr_global_position(lat0, lon0, lat1, lon1):
    """Decode global position from even (0) and odd (1) CPR frames."""
    dLat0 = 360.0 / 60
    dLat1 = 360.0 / 59
    j = int(math.floor(59 * lat0 - 60 * lat1 + 0.5))
    lat_even = dLat0 * (j % 60 + lat0)
    lat_odd = dLat1 * (j % 59 + lat1)
    if lat_even >= 270:
        lat_even -= 360
    if lat_odd >= 270:
        lat_odd -= 360

    # Use even frame for now
    lat = lat_even
    try:
        nl = max(1, int(math.floor(2 * math.pi / (math.acos(1 - (1 - math.cos(math.pi / 30)) / (math.cos(math.radians(lat)) ** 2))))))
    except (ValueError, ZeroDivisionError):
        nl = 1
    m = int(math.floor(lon0 * (nl - 1) - lon1 * nl + 0.5))
    lon = (360.0 / nl) * (m % nl + lon0)
    if lon > 180:
        lon -= 360
    return lat, lon


def _process_message(msg_hex):
    """Process a Mode-S message. Update aircraft dict."""
    if len(msg_hex) < 28:
        return
    df = int(msg_hex[0:2], 16) >> 3
    if df != 17:
        return
    if _crc(msg_hex) != 0:
        return

    icao = msg_hex[2:8].upper()
    tc = int(_hex_to_bin(msg_hex)[32:37], 2)

    with lock:
        if icao not in aircraft:
            aircraft[icao] = {
                "icao": icao, "callsign": "", "alt": 0, "lat": 0, "lon": 0,
                "speed": 0, "heading": 0, "seen": time.time(),
                "cpr_even": None, "cpr_odd": None, "messages": 0,
            }
            db_info = _lookup_aircraft(icao)
            aircraft[icao].update(db_info)
            aircraft[icao].update({"airline": "", "airline_country": "", "departure": "", "arrival": ""})
        ac = aircraft[icao]
        ac["seen"] = time.time()
        ac["messages"] += 1

        if 1 <= tc <= 4:
            new_cs = _decode_callsign(msg_hex)
            if new_cs and new_cs != ac["callsign"]:
                ac["callsign"] = new_cs
                al = _lookup_airline(new_cs)
                ac["airline"] = al["airline"]
                ac["airline_country"] = al["airline_country"]
                _lookup_route(new_cs)
        elif 9 <= tc <= 18:
            alt = _decode_altitude(msg_hex)
            if alt is not None:
                ac["alt"] = alt
            lat_cpr, lon_cpr, flag = _decode_cpr_position(msg_hex)
            if flag == 0:
                ac["cpr_even"] = (lat_cpr, lon_cpr, time.time())
            else:
                ac["cpr_odd"] = (lat_cpr, lon_cpr, time.time())
            if ac["cpr_even"] and ac["cpr_odd"]:
                t0 = ac["cpr_even"][2]
                t1 = ac["cpr_odd"][2]
                if abs(t0 - t1) < 10:
                    lat, lon = _cpr_global_position(
                        ac["cpr_even"][0], ac["cpr_even"][1],
                        ac["cpr_odd"][0], ac["cpr_odd"][1],
                    )
                    if -90 <= lat <= 90 and -180 <= lon <= 180:
                        ac["lat"] = round(lat, 5)
                        ac["lon"] = round(lon, 5)
        elif tc == 19:
            speed, heading = _decode_velocity(msg_hex)
            if speed is not None:
                ac["speed"] = speed
                ac["heading"] = heading




def _draw_plane(draw, x, y, heading, size=6, color="#00FF88"):
    """Draw a small plane icon rotated to heading."""
    rad = math.radians(heading)
    sin_h = math.sin(rad)
    cos_h = math.cos(rad)
    # Nose
    nx = x + int(sin_h * size)
    ny = y - int(cos_h * size)
    # Tail
    tx = x - int(sin_h * size * 0.6)
    ty = y + int(cos_h * size * 0.6)
    # Left wing
    lx = x - int(cos_h * size * 0.7) - int(sin_h * size * 0.2)
    ly = y - int(sin_h * size * 0.7) + int(cos_h * size * 0.2)
    # Right wing
    rx = x + int(cos_h * size * 0.7) - int(sin_h * size * 0.2)
    ry = y + int(sin_h * size * 0.7) + int(cos_h * size * 0.2)
    # Body line
    draw.line([(nx, ny), (tx, ty)], fill=color, width=2)
    # Wings
    draw.line([(lx, ly), (rx, ry)], fill=color, width=2)
    # Tail wings (smaller)
    tw = size * 0.35
    tlx = tx - int(cos_h * tw)
    tly = ty - int(sin_h * tw)
    trx = tx + int(cos_h * tw)
    tr_y = ty + int(sin_h * tw)
    draw.line([(tlx, tly), (trx, tr_y)], fill=color, width=1)

# ---------------------------------------------------------------------------
# Map tile system (OSM)
# ---------------------------------------------------------------------------
_TILE_CACHE = "/root/Raspyjack/loot/SDR/adsb/.tilecache"
_TILE_URL = "https://tile.openstreetmap.org/{z}/{x}/{y}.png"
_map_bg = None
_map_bbox = None


def _lat_to_merc(lat):
    lat = max(-85.0, min(85.0, lat))
    return math.log(math.tan(math.pi / 4 + math.radians(lat) / 2))


def _fetch_tile(z, x, y):
    os.makedirs(_TILE_CACHE, exist_ok=True)
    path = os.path.join(_TILE_CACHE, f"{z}_{x}_{y}.png")
    if os.path.isfile(path):
        try:
            return Image.open(path).convert("RGB")
        except Exception:
            pass
    try:
        req = urllib.request.Request(
            _TILE_URL.format(z=z, x=x, y=y),
            headers={"User-Agent": "RaspyJack/1.0"},
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = resp.read()
        with open(path, "wb") as f:
            f.write(data)
        return Image.open(BytesIO(data)).convert("RGB")
    except Exception:
        return None


def _build_map(center_lat, center_lon, width, height, zoom=7):
    n = 2 ** zoom
    x_center = int((center_lon + 180.0) / 360.0 * n)
    lat_rad = math.radians(max(-85, min(85, center_lat)))
    y_center = int((1.0 - math.log(math.tan(lat_rad) + 1.0 / math.cos(lat_rad)) / math.pi) / 2.0 * n)

    big = Image.new("RGB", (3 * 256, 3 * 256), (10, 14, 24))
    for dx in range(-1, 2):
        for dy in range(-1, 2):
            tile = _fetch_tile(zoom, x_center + dx, y_center + dy)
            if tile:
                big.paste(tile, ((dx + 1) * 256, (dy + 1) * 256))

    nw_lon = (x_center - 1) / n * 360.0 - 180.0
    se_lon = (x_center + 2) / n * 360.0 - 180.0
    nw_lat = math.degrees(math.atan(math.sinh(math.pi * (1 - 2 * (y_center - 1) / n))))
    se_lat = math.degrees(math.atan(math.sinh(math.pi * (1 - 2 * (y_center + 2) / n))))

    darkened = ImageEnhance.Brightness(big).enhance(0.4)
    resized = darkened.resize((width, height), Image.LANCZOS)
    bbox = (_lat_to_merc(nw_lat), _lat_to_merc(se_lat), nw_lon, se_lon)
    return resized, bbox


def _map_project(lat, lon, bbox, width, height):
    nw_merc, se_merc, nw_lon, se_lon = bbox
    merc_span = nw_merc - se_merc
    lon_span = se_lon - nw_lon
    if merc_span == 0 or lon_span == 0:
        return width // 2, height // 2
    merc = _lat_to_merc(lat)
    x = int((lon - nw_lon) / lon_span * width)
    y = int((nw_merc - merc) / merc_span * height)
    return max(0, min(width - 1, x)), max(0, min(height - 1, y))

# ---------------------------------------------------------------------------
# RTL-SDR ADS-B receiver thread
# ---------------------------------------------------------------------------

def _adsb_receiver():
    """Capture 1090 MHz using rtl_adsb and decode Mode-S messages."""
    while not _shutdown.is_set():
        try:
            subprocess.run(["pkill", "-9", "rtl_adsb"], capture_output=True)
            time.sleep(0.3)
            proc = subprocess.Popen(
                ["rtl_adsb", "-g", "50"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1,
            )

            for line in proc.stdout:
                if _shutdown.is_set():
                    break
                line = line.strip()
                if not line or not line.startswith("*"):
                    continue
                msg_hex = line.strip("*;").strip()
                if len(msg_hex) >= 28:
                    _process_message(msg_hex)

            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        except Exception:
            pass
        if not _shutdown.is_set():
            time.sleep(1)


# ---------------------------------------------------------------------------
# Live JSON writer + session persistence
# ---------------------------------------------------------------------------

_EXPORT_FIELDS = ("icao", "callsign", "alt", "lat", "lon", "speed", "heading",
                  "messages", "registration", "typecode", "type_desc", "operator", "country",
                  "airline", "airline_country", "departure", "arrival")


def _build_aircraft_list(active_only=True):
    with lock:
        now = time.time()
        src = aircraft.values()
        if active_only:
            src = [ac for ac in src if now - ac["seen"] < 60]
        return [{k: ac.get(k, "") for k in _EXPORT_FIELDS} for ac in src]


def _write_live_json():
    """Periodically write active aircraft to shared memory JSON for the WebUI."""
    while not _shutdown.is_set():
        try:
            data = _build_aircraft_list(active_only=True)
            with lock:
                total_msg = sum(ac["messages"] for ac in aircraft.values())
            output = {
                "ts": time.time(),
                "count": len(data),
                "total_messages": total_msg,
                "aircraft": data,
            }
            tmp_path = LIVE_JSON_PATH + ".tmp"
            with open(tmp_path, "w") as f:
                json.dump(output, f)
            os.replace(tmp_path, LIVE_JSON_PATH)
        except Exception:
            pass
        _shutdown.wait(1.5)


def _init_session():
    global _session_path
    os.makedirs(SESSION_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    _session_path = os.path.join(SESSION_DIR, f"adsb_session_{ts}.json")


def _save_session():
    if not _session_path:
        return
    try:
        data = _build_aircraft_list(active_only=False)
        with lock:
            total_msg = sum(ac["messages"] for ac in aircraft.values())
        output = {
            "session_end": datetime.now().isoformat(),
            "total_seen": len(aircraft),
            "total_messages": total_msg,
            "aircraft": data,
        }
        with open(_session_path, "w") as f:
            json.dump(output, f, indent=2)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    font = scaled_font(10)
    font_sm = scaled_font(9)
    real_w, real_h = lcd.width, lcd.height

    _map_bg = None
    _map_bbox = None

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), "Detecting SDR...", font=font_sm, fill="#FFAA00")
    lcd.LCD_ShowImage(img, 0, 0)

    found, desc, _backend = detect_sdr()
    if not found:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "No RTL-SDR!", font=font, fill="#FF4444")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1



    _map_bg = None
    _map_bbox = None
    _map_zoom = 7
    _map_lat = 46.8  # Default France center
    _map_lon = 2.3
    _map_manual = False  # True when user has panned/zoomed manually
    auto_mode = "--auto" in sys.argv
    tracking = False
    receiver_thread = None
    writer_thread = None
    resolver_thread = None
    view_idx = 0
    scroll = 0
    status = desc[:20]

    if auto_mode:
        tracking = True
        _shutdown.clear()
        _init_session()
        receiver_thread = threading.Thread(target=_adsb_receiver, daemon=True)
        receiver_thread.start()
        writer_thread = threading.Thread(target=_write_live_json, daemon=True)
        writer_thread.start()
        resolver_thread = threading.Thread(target=_route_resolver, daemon=True)
        resolver_thread.start()
        status = "Tracking..."

    try:
        while True:
            btn = _btn()
            if btn == "KEY3":
                break
            if btn == "KEY1":
                view_idx = (view_idx + 1) % len(VIEWS)
                scroll = 0

            view = VIEWS[view_idx]
            if view == "map":
                if btn == "UP":
                    _map_lat += 0.5 / (2 ** (_map_zoom - 5))
                    _map_manual = True
                    _map_bg = None
                elif btn == "DOWN":
                    _map_lat -= 0.5 / (2 ** (_map_zoom - 5))
                    _map_manual = True
                    _map_bg = None
                elif btn == "LEFT":
                    _map_lon -= 0.7 / (2 ** (_map_zoom - 5))
                    _map_manual = True
                    _map_bg = None
                elif btn == "RIGHT":
                    _map_lon += 0.7 / (2 ** (_map_zoom - 5))
                    _map_manual = True
                    _map_bg = None
                elif btn == "KEY2":
                    _map_zoom = min(15, _map_zoom + 1)
                    _map_bg = None
                elif btn == "OK" and not tracking:
                    pass  # handled below
                elif btn == "OK" and tracking:
                    pass  # handled below
            else:
                if btn == "UP":
                    scroll = max(0, scroll - 1)
                elif btn == "DOWN":
                    scroll += 1

            if btn == "OK":
                if view == "map" and tracking:
                    _map_zoom = max(3, _map_zoom - 1)
                    _map_bg = None
                elif not tracking:
                    tracking = True
                    _shutdown.clear()
                    _init_session()
                    receiver_thread = threading.Thread(target=_adsb_receiver, daemon=True)
                    receiver_thread.start()
                    writer_thread = threading.Thread(target=_write_live_json, daemon=True)
                    writer_thread.start()
                    resolver_thread = threading.Thread(target=_route_resolver, daemon=True)
                    resolver_thread.start()
                    status = "Tracking..."
                elif view != "map":
                    tracking = False
                    _shutdown.set()
                    _save_session()
                    status = "Stopped"

            if btn == "KEY2" and view != "map":
                _save_session()
                status = "Session saved"

            with lock:
                now = time.time()
                active = [ac for ac in aircraft.values() if now - ac["seen"] < 60]
                active.sort(key=lambda a: -a["messages"])
                total_msg = sum(ac["messages"] for ac in aircraft.values())
                with_pos = sum(1 for ac in active if ac["lat"] != 0)

            view = VIEWS[view_idx]

            # === LIST VIEW ===
            if view == "list":
                img = Image.new("RGB", (real_w, real_h), "black")
                draw = ImageDraw.Draw(img)
                s = max(1, S(1))

                # Header
                draw.rectangle([(0, 0), (real_w, 14*s)], fill="#111111")
                draw.text((2*s, 2*s), "ADS-B TRACKER", font=font_sm, fill="#00CCFF")
                draw.text((real_w - 80*s, 2*s), f"{len(active)}ac  {total_msg}msg", font=font_sm, fill="#888888")
                if tracking:
                    draw.ellipse([real_w - 8*s, 4*s, real_w - 2*s, 10*s], fill="#00FF00")

                # Column positions scaled to screen width
                cw = real_w
                C = [int(cw*0.01), int(cw*0.18), int(cw*0.34), int(cw*0.48), int(cw*0.60), int(cw*0.72), int(cw*0.85)]

                # Column headers
                y = 16
                draw.rectangle([(0, y), (real_w, y + 10)], fill="#0a1525")
                for label, cx in zip(["CALL","ICAO","ALT","SPD","HDG","SQK","POS"], C):
                    draw.text((cx, y + 1), label, font=font_sm, fill="#4a6080")

                y = 28
                if not active:
                    draw.text((real_w // 2, real_h // 2), "Press OK to track", font=font_sm, fill="#666666", anchor="mm")
                else:
                    row_h = 12
                    visible = max(1, (real_h - 42) // row_h)
                    for i in range(scroll, min(len(active), scroll + visible)):
                        if y + row_h > real_h - 14:
                            break
                        ac = active[i]
                        cs = ac["callsign"] or "-"
                        has_pos = ac["lat"] != 0

                        # Alternate row bg
                        if i % 2 == 0:
                            draw.rectangle([(0, y), (real_w, y + row_h)], fill="#0a0e18")

                        draw.text((C[0], y), cs[:7], font=font_sm, fill="#00FF88")
                        draw.text((C[1], y), ac["icao"][:6], font=font_sm, fill="#4488AA")
                        draw.text((C[2], y), f"{ac['alt']}", font=font_sm, fill="#FFAA00")
                        draw.text((C[3], y), f"{ac['speed']}", font=font_sm, fill="#00BBFF")
                        draw.text((C[4], y), f"{ac['heading']}°", font=font_sm, fill="#AAAAAA")
                        sq = ac.get("squawk", "")
                        sq_col = "#FF4444" if sq == "7700" else "#FFAA00" if sq in ("7600", "7500") else "#666666"
                        draw.text((C[5], y), sq if sq else "-", font=font_sm, fill=sq_col)
                        pos_icon = "●" if has_pos else "○"
                        draw.text((C[6], y), pos_icon, font=font_sm, fill="#00FF00" if has_pos else "#333333")
                        y += row_h

                # Footer
                draw.rectangle([(0, real_h - 12*s), (real_w, real_h)], fill="#111111")
                draw.text((2*s, real_h - 11*s), "OK:Track K1:View K2:Save", font=font_sm, fill="#666666")
                lcd.LCD_ShowImage(img, 0, 0)

            # === DETAIL VIEW (single aircraft) ===
            elif view == "detail":
                img = Image.new("RGB", (real_w, real_h), "#0a0e18")
                draw = ImageDraw.Draw(img)
                s = max(1, S(1))

                draw.rectangle([(0, 0), (real_w, 14*s)], fill="#111111")
                draw.text((2*s, 2*s), "AIRCRAFT DETAIL", font=font_sm, fill="#00CCFF")
                draw.text((real_w - 40*s, 2*s), f"{scroll + 1}/{len(active)}", font=font_sm, fill="#888888")

                if not active:
                    draw.text((real_w // 2, real_h // 2), "No aircraft", font=font, fill="#666666", anchor="mm")
                else:
                    idx = min(scroll, len(active) - 1)
                    ac = active[idx]
                    cs = ac["callsign"] or "Unknown"
                    y = 18*s

                    # Callsign big
                    draw.text((real_w // 2, y + 2*s), cs, font=font, fill="#00FF88", anchor="mm")
                    y += 20

                    # ICAO + Registration
                    draw.text((4*s, y), f"ICAO: {ac['icao']}", font=font_sm, fill="#4488AA")
                    reg = ac.get("registration", "")
                    if reg:
                        draw.text((real_w - 60*s, y), reg, font=font_sm, fill="#00CCFF")
                    y += 16

                    # Separator
                    draw.line([(4*s, y), (real_w - 4*s, y)], fill="#1a2844")
                    y += 6

                    # Data rows (enriched with DB + airline + route info)
                    rows = []
                    airline = ac.get("airline", "")
                    if airline:
                        rows.append(("Airline", airline[:20], "#FF88FF"))
                    type_desc = ac.get("type_desc", "")
                    if type_desc:
                        rows.append(("Type", type_desc[:20], "#CC88FF"))
                    dep = ac.get("departure", "")
                    arr = ac.get("arrival", "")
                    if dep or arr:
                        rows.append(("Route", f"{dep[:12]} -> {arr[:12]}", "#00FFAA"))
                    rows.extend([
                        ("Altitude", f"{ac['alt']:,} ft", "#FFAA00"),
                        ("Speed", f"{ac['speed']} kt", "#00BBFF"),
                        ("Heading", f"{ac['heading']}°", "#AAAAAA"),
                        ("Position", f"{ac['lat']:.4f}, {ac['lon']:.4f}" if ac['lat'] else "No position", "#00FF88" if ac['lat'] else "#666666"),
                    ])
                    operator = ac.get("operator", "")
                    if operator:
                        rows.append(("Operator", operator[:20], "#FFAA00"))
                    country = ac.get("country", "")
                    if country:
                        rows.append(("Country", country[:16], "#888888"))
                    rows.append(("Messages", f"{ac['messages']}", "#888888"))

                    for label, value, col in rows:
                        if y + 14 > real_h - 14:
                            break
                        draw.text((10, y), f"{label}:", font=font_sm, fill="#4a6080")
                        draw.text((real_w // 3, y), value, font=font_sm, fill=col)
                        y += 14

                # Footer
                draw.rectangle([(0, real_h - 12*s), (real_w, real_h)], fill="#111111")
                draw.text((2*s, real_h - 11*s), "UD:Prev/Next K1:View K2:Save", font=font_sm, fill="#666666")
                lcd.LCD_ShowImage(img, 0, 0)

            # === MAP VIEW ===
            elif view == "map":
                pos_acs = [ac for ac in active if ac["lat"] != 0 and ac["lon"] != 0]
                s = max(1, S(1))

                # Auto-center on aircraft if not manually panned
                if pos_acs and not _map_manual:
                    lats = [ac["lat"] for ac in pos_acs]
                    lons = [ac["lon"] for ac in pos_acs]
                    _map_lat = sum(lats) / len(lats)
                    _map_lon = sum(lons) / len(lons)

                # Build/rebuild map tiles when needed
                if _map_bg is None or _map_bbox is None:
                    _map_bg, _map_bbox = _build_map(_map_lat, _map_lon, real_w, real_h, zoom=_map_zoom)

                img = _map_bg.copy()
                draw = ImageDraw.Draw(img)

                # Plot aircraft
                for ac in pos_acs:
                    px, py = _map_project(ac["lat"], ac["lon"], _map_bbox, real_w, real_h)
                    if 0 <= px < real_w and 0 <= py < real_h:
                        hdg = ac.get("heading", 0)
                        _draw_plane(draw, px, py, hdg, size=7, color="#00FF88")
                        cs = ac["callsign"] or ac["icao"][:4]
                        draw.text((px + 10, py - 4), cs[:6], font=font_sm, fill="#00CCFF")
                        if ac["alt"] > 0:
                            draw.text((px + 10, py + 6), f"{ac['alt']}ft", font=font_sm, fill="#888888")

                # Crosshair center
                cx, cy = real_w // 2, real_h // 2
                draw.line([(cx - 4, cy), (cx + 4, cy)], fill="#ffffff40")
                draw.line([(cx, cy - 4), (cx, cy + 4)], fill="#ffffff40")

                # Header
                draw.rectangle([(0, 0), (real_w, 14*s)], fill="#000000")
                draw.text((2*s, 2*s), f"MAP z{_map_zoom} {len(pos_acs)}/{len(active)}ac", font=font_sm, fill="#00CCFF")
                if tracking:
                    draw.ellipse([real_w - 8*s, 4*s, real_w - 2*s, 10*s], fill="#00FF00")

                # Footer controls
                draw.rectangle([(0, real_h - 12*s), (real_w, real_h)], fill="#000000")
                draw.text((2*s, real_h - 11*s), "Pad:Move K2:Zoom+ OK:Zoom-", font=font_sm, fill="#666666")

                lcd.LCD_ShowImage(img, 0, 0)

            # === STATS VIEW ===
            elif view == "stats":
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.rectangle((0, 0, 127, 14), fill="#111")
                d.text((2, 2), "ADS-B STATS", font=font_sm, fill="#00CCFF")

                y = 20
                d.text((4, y), f"Aircraft: {len(active)}", font=font, fill="#00FF00")
                y += 15
                d.text((4, y), f"With position: {with_pos}", font=font_sm, fill="#ccc")
                y += 12
                d.text((4, y), f"Messages: {total_msg}", font=font_sm, fill="#ccc")
                y += 12
                d.text((4, y), f"Total seen: {len(aircraft)}", font=font_sm, fill="#888")
                y += 15

                db_status = "loaded" if os.path.isfile(_DB_PATH) else "not found"
                d.text((4, y), f"Aircraft DB: {db_status}", font=font_sm, fill="#00CCFF" if db_status == "loaded" else "#FF4444")
                y += 12

                if active:
                    highest = max(active, key=lambda a: a["alt"])
                    fastest = max(active, key=lambda a: a["speed"])
                    d.text((4, y), f"Highest: {highest['alt']}ft", font=font_sm, fill="#FFAA00")
                    y += 11
                    d.text((4, y), f"Fastest: {fastest['speed']}kt", font=font_sm, fill="#FFAA00")

                d.rectangle((0, 116, 127, 127), fill="#111")
                d.text((2, 117), "OK:Track K1:View K2:Save", font=font_sm, fill="#666")
                lcd.LCD_ShowImage(img, 0, 0)

            time.sleep(0.05)

    finally:
        _shutdown.set()
        _save_session()
        try:
            os.remove(LIVE_JSON_PATH)
        except OSError:
            pass
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
