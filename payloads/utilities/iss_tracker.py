#!/usr/bin/env python3
"""
RaspyJack Payload -- ISS Tracker
==================================
Author: 7h30th3r0n3

Real-time ISS tracker with world map, orbit prediction,
next visible passes, crew info, and satellite data.

Controls:
  UP/DOWN     Switch view (Map / Orbit / Passes / Crew / Satellites)
  OK          Refresh data
  KEY1        Toggle auto-refresh
  LEFT/RIGHT  Scroll in lists
  KEY3        Exit
"""

import os
import sys
import time
import signal
import subprocess
import json
import math
import threading
from datetime import datetime, timezone, timedelta

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)
for p in PINS.values():
    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

time.sleep(0.1)
_STUCK_PINS = {name for name, pin in PINS.items() if GPIO.input(pin) == 0}

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
W, H = LCD.width, LCD.height
IS_WIDE = W > 200

if IS_WIDE:
    from PIL import ImageFont
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 13)
        font_sm = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 10)
        font_lg = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 15)
    except Exception:
        font = scaled_font(9)
        font_sm = scaled_font(7)
        font_lg = scaled_font(12)
else:
    font = scaled_font(10)
    font_sm = scaled_font(8)
    font_lg = scaled_font(12)

ISS_API = "http://api.open-notify.org/iss-now.json"
PEOPLE_API = "http://api.open-notify.org/astros.json"
TILE_URL = "https://tile.openstreetmap.org/{z}/{x}/{y}.png"
TILE_CACHE = "/root/Raspyjack/loot/wardriving/.tilecache"
MAP_ZOOM = 1
DEBOUNCE = 0.20

ISS_ALTITUDE_KM = 408
ISS_SPEED_KMH = 27600
ISS_ORBIT_MINUTES = 92
EARTH_RADIUS_KM = 6371

_running = True

C_BG = (0, 0, 15)
C_HEAD = (0, 20, 50)
C_BLUE = (50, 150, 255)
C_WHITE = (255, 255, 255)
C_DIM = (80, 80, 80)
C_DARK = (10, 10, 20)
C_GREEN = (0, 220, 80)
C_RED = (255, 50, 50)
C_YELLOW = (255, 200, 0)
C_CYAN = (0, 200, 220)
C_OCEAN = (10, 20, 50)
C_ISS = (255, 255, 0)
C_TRACK = (100, 100, 0)
C_PREDICT = (0, 150, 255)
C_ORBIT = (80, 0, 200)


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _get_btn():
    btn = get_button(PINS, GPIO)
    if btn and btn in _STUCK_PINS:
        return None
    return btn


def _lat_lon_to_tile(lat, lon, z):
    n = 2 ** z
    x = int((lon + 180.0) / 360.0 * n)
    lat_r = math.radians(max(-85, min(85, lat)))
    y = int((1.0 - math.log(math.tan(lat_r) + 1.0 / math.cos(lat_r)) / math.pi) / 2.0 * n)
    return x, y


def _get_tile(z, x, y):
    import urllib.request
    os.makedirs(TILE_CACHE, exist_ok=True)
    n = 2 ** z
    x = x % n
    fname = f"{z}_{x}_{y}.png"
    path = os.path.join(TILE_CACHE, fname)
    if os.path.isfile(path):
        try:
            return Image.open(path)
        except Exception:
            pass
    url = TILE_URL.format(z=z, x=x, y=y)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Raspyjack/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            with open(path, "wb") as f:
                f.write(resp.read())
        return Image.open(path)
    except Exception:
        return None


_world_map_cache = None


def _get_world_map(w, h):
    global _world_map_cache
    if _world_map_cache and _world_map_cache.size == (w, h):
        return _world_map_cache
    z = MAP_ZOOM
    n = 2 ** z
    tile_size = 256
    world = Image.new("RGB", (n * tile_size, n * tile_size), C_OCEAN)
    for tx in range(n):
        for ty in range(n):
            tile = _get_tile(z, tx, ty)
            if tile:
                world.paste(tile.convert("RGB"), (tx * tile_size, ty * tile_size))
    _world_map_cache = world.resize((w, h), Image.LANCZOS)
    return _world_map_cache


def _lat_lon_to_xy(lat, lon, w, h):
    x = int((lon + 180) / 360 * w)
    lat_r = math.radians(max(-85, min(85, lat)))
    y = int((1.0 - math.log(math.tan(lat_r) + 1.0 / math.cos(lat_r)) / math.pi) / 2.0 * h)
    return max(0, min(w - 1, x)), max(0, min(h - 1, y))


def _fetch_json(url):
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Raspyjack"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def _fetch_iss():
    data = _fetch_json(ISS_API)
    if data and data.get("message") == "success":
        pos = data["iss_position"]
        return {
            "lat": float(pos["latitude"]),
            "lon": float(pos["longitude"]),
            "timestamp": data.get("timestamp", int(time.time())),
        }
    return None


def _fetch_crew():
    data = _fetch_json(PEOPLE_API)
    if data and data.get("message") == "success":
        people = data.get("people", [])
        iss_crew = [p["name"] for p in people if p.get("craft") == "ISS"]
        crafts = {}
        for p in people:
            craft = p.get("craft", "Unknown")
            crafts.setdefault(craft, []).append(p["name"])
        return iss_crew, data.get("number", 0), crafts
    return [], 0, {}


def _predict_orbit(current_pos, minutes_ahead=92, step_min=2):
    """Predict ISS ground track using simplified circular orbit model."""
    predictions = []
    if not current_pos:
        return predictions

    lat = current_pos["lat"]
    lon = current_pos["lon"]
    inclination = 51.6
    period = ISS_ORBIT_MINUTES

    for t in range(0, minutes_ahead, step_min):
        angle = (t / period) * 360.0
        orbit_lat = inclination * math.sin(math.radians(angle + math.asin(lat / inclination) * 180 / math.pi if abs(lat) < inclination else 0))
        orbit_lon = lon + (t / period) * 360.0
        orbit_lon = ((orbit_lon + 180) % 360) - 180
        orbit_lat = max(-85, min(85, orbit_lat))
        predictions.append({
            "lat": orbit_lat,
            "lon": orbit_lon,
            "minutes": t,
        })
    return predictions


def _calculate_visibility(iss_lat, iss_lon, obs_lat, obs_lon):
    """Calculate if ISS is potentially visible from observer location."""
    dlat = math.radians(iss_lat - obs_lat)
    dlon = math.radians(iss_lon - obs_lon)
    a = math.sin(dlat / 2) ** 2 + math.cos(math.radians(obs_lat)) * \
        math.cos(math.radians(iss_lat)) * math.sin(dlon / 2) ** 2
    distance_km = EARTH_RADIUS_KM * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    max_visible_dist = math.sqrt((EARTH_RADIUS_KM + ISS_ALTITUDE_KM) ** 2 - EARTH_RADIUS_KM ** 2)

    elevation = math.degrees(math.atan2(
        ISS_ALTITUDE_KM - distance_km * math.tan(math.radians(0)),
        distance_km)) if distance_km > 0 else 90

    return {
        "distance_km": distance_km,
        "max_range_km": max_visible_dist,
        "in_range": distance_km < max_visible_dist,
        "elevation_approx": max(0, elevation),
    }


def _next_passes(current_pos, obs_lat=48.86, obs_lon=2.35, count=5):
    """Estimate next ISS passes over observer (simplified)."""
    passes = []
    if not current_pos:
        return passes

    for orbit in range(20):
        t_min = orbit * ISS_ORBIT_MINUTES
        pred = _predict_orbit(current_pos, minutes_ahead=t_min + ISS_ORBIT_MINUTES, step_min=1)
        for p in pred:
            if p["minutes"] <= t_min:
                continue
            vis = _calculate_visibility(p["lat"], p["lon"], obs_lat, obs_lon)
            if vis["in_range"] and vis["distance_km"] < 1500:
                pass_time = datetime.now() + timedelta(minutes=p["minutes"])
                passes.append({
                    "time": pass_time.strftime("%H:%M"),
                    "date": pass_time.strftime("%m/%d"),
                    "distance_km": int(vis["distance_km"]),
                    "minutes_from_now": p["minutes"],
                })
                break
        if len(passes) >= count:
            break
    return passes


def _sun_position():
    """Simple sun position calculation."""
    now = datetime.now(timezone.utc)
    day_of_year = now.timetuple().tm_yday
    hour = now.hour + now.minute / 60.0
    declination = 23.45 * math.sin(math.radians((284 + day_of_year) / 365 * 360))
    lon = -((hour - 12) / 24 * 360)
    return declination, lon


def _is_nighttime(lat, lon):
    """Check if a location is in nighttime."""
    dec, sun_lon = _sun_position()
    hour_angle = lon - sun_lon
    cos_zenith = (math.sin(math.radians(lat)) * math.sin(math.radians(dec)) +
                  math.cos(math.radians(lat)) * math.cos(math.radians(dec)) *
                  math.cos(math.radians(hour_angle)))
    return cos_zenith < 0


# ============ VIEWS ============

def _draw_map_view(iss_pos, track, predictions):
    if IS_WIDE:
        map_w, map_h = W, H - 36
        map_y = 20
    else:
        map_w, map_h = 128, 92
        map_y = 14

    world = _get_world_map(map_w, map_h)
    img = Image.new("RGB", (W, H), C_BG)
    img.paste(world, (0, map_y))
    d = ImageDraw.Draw(img)

    if IS_WIDE:
        d.rectangle([0, 0, W, 20], fill=C_HEAD)
        d.text((W // 2, 10), "ISS TRACKER - MAP", font=font_lg, fill=C_CYAN,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 65, 1), "ISS TRACKER - MAP", font=font_lg, fill=C_CYAN)
    else:
        d.rectangle([0, 0, 128, 14], fill=C_HEAD)
        d.text((15, 1), "ISS MAP", font=font_lg, fill=C_CYAN)

    for p in predictions[:30]:
        px, py = _lat_lon_to_xy(p["lat"], p["lon"], map_w, map_h)
        d.rectangle([px, map_y + py, px + 1, map_y + py + 1], fill=C_PREDICT)

    for pos in track[-40:]:
        px, py = _lat_lon_to_xy(pos["lat"], pos["lon"], map_w, map_h)
        d.rectangle([px - 1, map_y + py - 1, px + 1, map_y + py + 1], fill=C_TRACK)

    if iss_pos:
        px, py = _lat_lon_to_xy(iss_pos["lat"], iss_pos["lon"], map_w, map_h)
        r = 5 if IS_WIDE else 3
        d.ellipse([px - r, map_y + py - r, px + r, map_y + py + r], fill=C_ISS)
        if IS_WIDE:
            d.text((px + r + 2, map_y + py - r), "ISS", font=font_sm, fill=C_ISS)

    if IS_WIDE:
        d.rectangle([0, H - 16, W, H], fill=C_DARK)
        if iss_pos:
            night = "Night" if _is_nighttime(iss_pos["lat"], iss_pos["lon"]) else "Day"
            info = f"Lat:{iss_pos['lat']:.2f} Lon:{iss_pos['lon']:.2f} [{night}]"
        else:
            info = "No data - OK to refresh"
        d.text((W // 2, H - 8), info, font=font_sm, fill=C_WHITE,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (5, H - 14), info, font=font_sm, fill=C_WHITE)
    else:
        if iss_pos:
            d.text((4, 108), f"{iss_pos['lat']:.1f},{iss_pos['lon']:.1f}", font=font_sm, fill=C_WHITE)

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_orbit_view(iss_pos, predictions):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    if IS_WIDE:
        d.rectangle([0, 0, W, 20], fill=C_HEAD)
        d.text((W // 2, 10), "ORBIT PREDICTION", font=font_lg, fill=C_ORBIT,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 60, 1), "ORBIT PREDICTION", font=font_lg, fill=C_ORBIT)

        y = 24
        d.text((8, y), f"Altitude: {ISS_ALTITUDE_KM} km", font=font, fill=C_WHITE)
        y += 16
        d.text((8, y), f"Speed: {ISS_SPEED_KMH:,} km/h", font=font, fill=C_WHITE)
        y += 16
        d.text((8, y), f"Orbit period: {ISS_ORBIT_MINUTES} min", font=font, fill=C_WHITE)
        y += 16
        d.text((8, y), f"Inclination: 51.6 deg", font=font, fill=C_WHITE)
        y += 20

        if iss_pos:
            night = _is_nighttime(iss_pos["lat"], iss_pos["lon"])
            d.text((8, y), f"Currently over: {'Night side' if night else 'Day side'}", font=font, fill=C_YELLOW)
            y += 16

        d.text((8, y), "Next positions:", font=font_sm, fill=C_DIM)
        y += 14
        for p in predictions[:4]:
            d.text((12, y), f"+{p['minutes']}min: {p['lat']:.1f}, {p['lon']:.1f}", font=font_sm, fill=C_PREDICT)
            y += 13
    else:
        d.rectangle([0, 0, 128, 14], fill=C_HEAD)
        d.text((25, 1), "ORBIT", font=font_lg, fill=C_ORBIT)
        y = 18
        d.text((4, y), f"Alt: {ISS_ALTITUDE_KM}km", font=font, fill=C_WHITE)
        y += 15
        d.text((4, y), f"Spd: 27600km/h", font=font_sm, fill=C_WHITE)
        y += 13
        d.text((4, y), f"Period: {ISS_ORBIT_MINUTES}min", font=font_sm, fill=C_WHITE)
        y += 15
        for p in predictions[:3]:
            d.text((4, y), f"+{p['minutes']}m:{p['lat']:.0f},{p['lon']:.0f}", font=font_sm, fill=C_PREDICT)
            y += 13

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_passes_view(passes, scroll):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    if IS_WIDE:
        d.rectangle([0, 0, W, 20], fill=C_HEAD)
        d.text((W // 2, 10), "NEXT VISIBLE PASSES", font=font_lg, fill=C_GREEN,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 70, 1), "NEXT VISIBLE PASSES", font=font_lg, fill=C_GREEN)

        y = 26
        if not passes:
            d.text((8, y), "No passes predicted", font=font, fill=C_DIM)
            d.text((8, y + 18), "ISS needs to be in sunlight", font=font_sm, fill=C_DIM)
            d.text((8, y + 32), "while you are in darkness", font=font_sm, fill=C_DIM)
        else:
            d.text((8, y), "Date     Time   Dist    In", font=font_sm, fill=C_DIM)
            y += 16
            for i, p in enumerate(passes[scroll:scroll + 5]):
                color = C_GREEN if p["distance_km"] < 800 else C_YELLOW
                d.text((8, y), f"{p['date']}   {p['time']}   {p['distance_km']:>4}km   +{p['minutes_from_now']}min",
                       font=font_sm, fill=color)
                y += 15

        d.rectangle([0, H - 16, W, H], fill=C_DARK)
        d.text((W // 2, H - 8), "Observer: Paris (48.86, 2.35) | L/R:Scroll",
               font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (5, H - 14), "Paris 48.86,2.35 L/R:Scroll", font=font_sm, fill=C_DIM)
    else:
        d.rectangle([0, 0, 128, 14], fill=C_HEAD)
        d.text((20, 1), "PASSES", font=font_lg, fill=C_GREEN)
        y = 18
        if not passes:
            d.text((4, y), "No passes", font=font, fill=C_DIM)
        else:
            for p in passes[scroll:scroll + 4]:
                d.text((4, y), f"{p['time']} {p['distance_km']}km", font=font_sm, fill=C_GREEN)
                y += 15

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_crew_view(crew, total, crafts, scroll):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    if IS_WIDE:
        d.rectangle([0, 0, W, 20], fill=C_HEAD)
        d.text((W // 2, 10), f"PEOPLE IN SPACE: {total}", font=font_lg, fill=C_YELLOW,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 65, 1), f"PEOPLE IN SPACE: {total}", font=font_lg, fill=C_YELLOW)

        y = 26
        all_people = []
        for craft, names in crafts.items():
            all_people.append((craft, None))
            for name in names:
                all_people.append((None, name))

        for item in all_people[scroll:scroll + 8]:
            if item[0]:
                d.text((8, y), f"--- {item[0]} ---", font=font_sm, fill=C_CYAN)
            else:
                d.text((16, y), item[1][:30], font=font_sm, fill=C_WHITE)
            y += 14

        d.rectangle([0, H - 16, W, H], fill=C_DARK)
        d.text((W // 2, H - 8), f"ISS crew: {len(crew)} | L/R:Scroll",
               font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (5, H - 14), f"ISS:{len(crew)} L/R:Scroll", font=font_sm, fill=C_DIM)
    else:
        d.rectangle([0, 0, 128, 14], fill=C_HEAD)
        d.text((15, 1), f"CREW ({total})", font=font_lg, fill=C_YELLOW)
        y = 18
        for name in crew[scroll:scroll + 5]:
            d.text((4, y), name[:16], font=font_sm, fill=C_WHITE)
            y += 14

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_satellites_view():
    """Show notable satellites and space objects."""
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    satellites = [
        ("ISS (Zarya)", "408 km", "51.6 deg", "92 min"),
        ("Tiangong", "390 km", "41.5 deg", "91 min"),
        ("Hubble", "547 km", "28.5 deg", "95 min"),
        ("Starlink (gen)", "550 km", "53.0 deg", "95 min"),
        ("GPS (avg)", "20,200 km", "55.0 deg", "12 hr"),
        ("Moon", "384,400 km", "5.1 deg", "27.3 d"),
    ]

    if IS_WIDE:
        d.rectangle([0, 0, W, 20], fill=C_HEAD)
        d.text((W // 2, 10), "SPACE OBJECTS", font=font_lg, fill=C_BLUE,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 50, 1), "SPACE OBJECTS", font=font_lg, fill=C_BLUE)

        y = 24
        d.text((8, y), "Name              Alt         Inc      Period", font=font_sm, fill=C_DIM)
        y += 15
        for name, alt, inc, period in satellites:
            d.text((8, y), f"{name:<17} {alt:<11} {inc:<9} {period}", font=font_sm, fill=C_WHITE)
            y += 14

        d.rectangle([0, H - 16, W, H], fill=C_DARK)
        now = datetime.now(timezone.utc)
        d.text((W // 2, H - 8), f"UTC: {now.strftime('%Y-%m-%d %H:%M:%S')}",
               font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (5, H - 14), f"UTC:{now.strftime('%H:%M:%S')}", font=font_sm, fill=C_DIM)
    else:
        d.rectangle([0, 0, 128, 14], fill=C_HEAD)
        d.text((15, 1), "SPACE", font=font_lg, fill=C_BLUE)
        y = 18
        for name, alt, _, _ in satellites[:5]:
            d.text((4, y), f"{name[:10]} {alt}", font=font_sm, fill=C_WHITE)
            y += 15

    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global _running

    views = ["map", "orbit", "passes", "crew", "satellites"]
    view_idx = 0
    last_btn = 0
    auto_refresh = True
    last_fetch = 0
    refresh_interval = 5
    iss_pos = None
    track = []
    predictions = []
    crew = []
    total_people = 0
    crafts = {}
    passes = []
    scroll = 0

    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
    if IS_WIDE:
        d.text((W // 2, H // 2 - 10), "Loading ISS data...", font=font, fill=C_CYAN,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 60, H // 2 - 10), "Loading ISS data...", font=font, fill=C_CYAN)
        d.text((W // 2, H // 2 + 10), "Downloading map tiles...", font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 70, H // 2 + 10), "Downloading map tiles...", font=font_sm, fill=C_DIM)
    else:
        d.text((10, 50), "Loading...", font=font, fill=C_CYAN)
        d.text((10, 68), "Map tiles...", font=font_sm, fill=C_DIM)
    LCD.LCD_ShowImage(img, 0, 0)

    iss_pos = _fetch_iss()
    if iss_pos:
        track.append(iss_pos)
        predictions = _predict_orbit(iss_pos)
        passes = _next_passes(iss_pos)
    crew, total_people, crafts = _fetch_crew()
    last_fetch = time.time()

    while _running:
        btn = _get_btn()
        now = time.time()

        if btn == "KEY3":
            break

        if btn == "UP" and now - last_btn > DEBOUNCE:
            last_btn = now
            view_idx = (view_idx - 1) % len(views)
            scroll = 0

        if btn == "DOWN" and now - last_btn > DEBOUNCE:
            last_btn = now
            view_idx = (view_idx + 1) % len(views)
            scroll = 0

        if btn == "LEFT" and now - last_btn > DEBOUNCE:
            last_btn = now
            scroll = max(0, scroll - 1)

        if btn == "RIGHT" and now - last_btn > DEBOUNCE:
            last_btn = now
            scroll += 1

        if btn == "OK" and now - last_btn > DEBOUNCE:
            last_btn = now
            iss_pos = _fetch_iss()
            if iss_pos:
                track.append(iss_pos)
                predictions = _predict_orbit(iss_pos)
                passes = _next_passes(iss_pos)
            crew, total_people, crafts = _fetch_crew()
            last_fetch = now

        if btn == "KEY1" and now - last_btn > DEBOUNCE:
            last_btn = now
            auto_refresh = not auto_refresh

        if auto_refresh and now - last_fetch > refresh_interval:
            iss_pos = _fetch_iss()
            if iss_pos:
                track.append(iss_pos)
                if len(track) > 200:
                    track = track[-200:]
                predictions = _predict_orbit(iss_pos)
            last_fetch = now

        view = views[view_idx]
        if view == "map":
            _draw_map_view(iss_pos, track, predictions)
        elif view == "orbit":
            _draw_orbit_view(iss_pos, predictions)
        elif view == "passes":
            _draw_passes_view(passes, scroll)
        elif view == "crew":
            _draw_crew_view(crew, total_people, crafts, scroll)
        elif view == "satellites":
            _draw_satellites_view()

        time.sleep(0.3)

    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
