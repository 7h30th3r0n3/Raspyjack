#!/usr/bin/env python3
"""
RaspyJack Payload -- APRS Station Tracker
==========================================
Author: 7h30th3r0n3

Receive and decode APRS packets on 144.800 MHz using RTL-SDR + Direwolf.
Displays stations on LCD map with distance/bearing from observer.

Controls:
  OK    : Start/Stop reception
  KEY1  : Switch view (Map / Stations / Detail / Stats)
  UP/DN : Scroll / select station
  KEY3  : Exit

Requires: rtl-sdr, direwolf
"""

import os
import sys
import math
import time
import json
import signal
import re
import subprocess
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font, S, SX, SY
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for p in PINS.values():
    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
W, H = LCD.width, LCD.height

font = scaled_font(9)
font_sm = scaled_font(7)
font_xs = scaled_font(6)
font_lg = scaled_font(12)

LIVE_PATH = "/dev/shm/rj_aprs_live.json"
APRS_FREQ = 144.800
DEBOUNCE = 0.18
VIEWS = ["Map", "Stations", "Detail", "Stats"]
_last_btn = 0
_running = True
_receiving = False
_rtl_proc = None
_dw_proc = None

_stations = {}
_recent_packets = []
_total_packets = 0
_start_time = 0
_lock = threading.Lock()

TYPE_COLORS = {
    "digi": (0, 255, 100),
    "tracker": (0, 200, 255),
    "weather": (255, 200, 0),
    "igate": (200, 100, 255),
    "other": (150, 150, 150),
}


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    if b:
        now = time.time()
        if now - _last_btn < DEBOUNCE:
            return None
        _last_btn = now
    return b


def _get_observer():
    try:
        with open("/dev/shm/rj_gnss_live.json") as f:
            d = json.load(f)
        fix = d.get("fix", {})
        if fix.get("lat"):
            return fix["lat"], fix["lon"], fix.get("alt", 50)
    except Exception:
        pass
    return 0.0, 0.0, 0


def _haversine(lat1, lon1, lat2, lon2):
    R = 6371
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon / 2) ** 2)
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _bearing(lat1, lon1, lat2, lon2):
    dlon = math.radians(lon2 - lon1)
    lat1r, lat2r = math.radians(lat1), math.radians(lat2)
    x = math.sin(dlon) * math.cos(lat2r)
    y = (math.cos(lat1r) * math.sin(lat2r) -
         math.sin(lat1r) * math.cos(lat2r) * math.cos(dlon))
    return (math.degrees(math.atan2(x, y)) + 360) % 360


def _bearing_arrow(deg):
    arrows = "↑↗→↘↓↙←↖"
    return arrows[int(((deg + 22.5) % 360) / 45)]


_APRS_POS_RE = re.compile(
    r'(\d{4}\.\d{2})([NS])[/\\I](\d{5}\.\d{2})([EW])'
)


def _parse_aprs_position(data):
    m = _APRS_POS_RE.search(data)
    if m:
        lat = int(m.group(1)[:2]) + float(m.group(1)[2:]) / 60
        if m.group(2) == "S":
            lat = -lat
        lon = int(m.group(3)[:3]) + float(m.group(3)[3:]) / 60
        if m.group(4) == "W":
            lon = -lon
        return lat, lon
    return None, None


def _detect_type(callsign, path, comment):
    cs = callsign.upper()
    path_str = (path or "").upper()
    comment_str = (comment or "").lower()
    if any(x in path_str for x in ["RELAY", "WIDE"]) and "-" not in cs:
        return "digi"
    if "igate" in comment_str or "igat" in comment_str:
        return "igate"
    if any(x in comment_str for x in ["wx", "weather", "temp", "wind", "rain", "baro"]):
        return "weather"
    if any(x in comment_str for x in ["tracker", "tinytrak", "aprs"]):
        return "tracker"
    ssid = cs.split("-")[-1] if "-" in cs else ""
    if ssid in ("1", "2", "3", "4"):
        return "digi"
    if ssid in ("9", "14"):
        return "tracker"
    if ssid in ("13",):
        return "weather"
    return "tracker"


def _parse_direwolf_line(line):
    line = line.strip()
    if not line:
        return None
    m = re.match(r'\[\d+[\.\d]*\]\s+(\S+?)>(\S+?):(.*)', line)
    if not m:
        return None
    from_call = m.group(1)
    to_via = m.group(2)
    data = m.group(3)
    parts = to_via.split(",")
    to_call = parts[0] if parts else ""
    path = ",".join(parts[1:]) if len(parts) > 1 else ""
    lat, lon = _parse_aprs_position(data)
    comment = ""
    if lat is not None:
        pos_end = _APRS_POS_RE.search(data)
        if pos_end:
            comment = data[pos_end.end():].strip()[:80]
    return {
        "from": from_call,
        "to": to_call,
        "path": path,
        "data": data,
        "lat": lat,
        "lon": lon,
        "comment": comment,
    }


def _receiver_thread():
    global _rtl_proc, _dw_proc, _total_packets
    try:
        subprocess.run(["pkill", "-9", "rtl_fm"], capture_output=True)
        subprocess.run(["pkill", "-9", "direwolf"], capture_output=True)
        time.sleep(0.5)
        script = os.path.join(os.path.dirname(__file__), "_aprs_rx.sh")
        _dw_proc = subprocess.Popen(
            ["bash", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1,
            start_new_session=True,
        )
        time.sleep(1.5)
        for line in _dw_proc.stdout:
            if not _receiving or not _running:
                break
            parsed = _parse_direwolf_line(line)
            if not parsed:
                continue
            with _lock:
                _total_packets += 1
                _recent_packets.append({
                    "ts": time.time(),
                    "from": parsed["from"],
                    "to": parsed["to"],
                    "data": parsed["data"][:120],
                })
                if len(_recent_packets) > 200:
                    del _recent_packets[:-200]
                if parsed["lat"] is not None:
                    obs = _get_observer()
                    dist = _haversine(obs[0], obs[1], parsed["lat"], parsed["lon"])
                    bear = _bearing(obs[0], obs[1], parsed["lat"], parsed["lon"])
                    stype = _detect_type(parsed["from"], parsed["path"], parsed["comment"])
                    existing = _stations.get(parsed["from"], {"packets": 0, "first_seen": time.time()})
                    _stations[parsed["from"]] = {
                        "callsign": parsed["from"],
                        "lat": parsed["lat"],
                        "lon": parsed["lon"],
                        "comment": parsed["comment"],
                        "path": parsed["path"],
                        "distance_km": round(dist, 1),
                        "bearing": round(bear),
                        "type": stype,
                        "packets": existing["packets"] + 1,
                        "first_seen": existing["first_seen"],
                        "last_seen": time.time(),
                    }
                    if len(_stations) > 500:
                        oldest = min(_stations, key=lambda k: _stations[k]["last_seen"])
                        del _stations[oldest]
    except Exception:
        pass
    finally:
        if _dw_proc:
            try:
                _dw_proc.terminate()
            except Exception:
                pass
        if _rtl_proc:
            try:
                _rtl_proc.terminate()
            except Exception:
                pass
        subprocess.run(["pkill", "-9", "rtl_fm"], capture_output=True)
        subprocess.run(["pkill", "-9", "direwolf"], capture_output=True)


def _start_receiver():
    global _receiving, _start_time
    _stop_receiver()
    _receiving = True
    _start_time = time.time()
    threading.Thread(target=_receiver_thread, daemon=True).start()


def _stop_receiver():
    global _receiving, _rtl_proc, _dw_proc
    _receiving = False
    if _dw_proc:
        try:
            _dw_proc.terminate()
        except Exception:
            pass
        _dw_proc = None
    if _rtl_proc:
        try:
            _rtl_proc.terminate()
        except Exception:
            pass
        _rtl_proc = None
    subprocess.run(["pkill", "-9", "rtl_fm"], capture_output=True)
    subprocess.run(["pkill", "-9", "direwolf"], capture_output=True)


def _write_live():
    while _running:
        try:
            obs = _get_observer()
            with _lock:
                station_list = sorted(
                    _stations.values(),
                    key=lambda s: s.get("last_seen", 0),
                    reverse=True,
                )[:100]
                recent = list(_recent_packets[-50:])
                total = _total_packets
            uptime = int(time.time() - _start_time) if _start_time else 0
            ppm = total / max(1, uptime / 60) if uptime > 0 else 0
            farthest = max((s["distance_km"] for s in station_list), default=0)
            payload = {
                "ts": time.time(),
                "running": _receiving,
                "total_stations": len(_stations),
                "total_packets": total,
                "packets_per_min": round(ppm, 1),
                "uptime": uptime,
                "farthest_km": round(farthest, 1),
                "observer": {"lat": obs[0], "lon": obs[1], "alt": obs[2]},
                "stations": station_list,
                "recent_packets": recent,
            }
            tmp = LIVE_PATH + ".tmp"
            with open(tmp, "w") as f:
                json.dump(payload, f)
            os.replace(tmp, LIVE_PATH)
        except Exception:
            pass
        time.sleep(2)


_MAP_TILE_CACHE = "/root/Raspyjack/loot/SDR/aprs/.tilecache"
_MAP_TILE_URL = "https://tile.openstreetmap.org/{z}/{x}/{y}.png"
_tile_download_lock = threading.Lock()
_map_bg = None
_map_bbox = None


def _lat_to_merc(lat):
    lat = max(-85.0, min(85.0, lat))
    return math.log(math.tan(math.pi / 4 + math.radians(lat) / 2))


def _fetch_map_tile(z, x, y):
    os.makedirs(_MAP_TILE_CACHE, exist_ok=True)
    cache_path = os.path.join(_MAP_TILE_CACHE, f"{z}_{x}_{y}.png")
    if os.path.isfile(cache_path):
        try:
            return Image.open(cache_path).convert("RGB")
        except Exception:
            pass
    url = _MAP_TILE_URL.format(z=z, x=x, y=y)
    try:
        import urllib.request
        from io import BytesIO
        with _tile_download_lock:
            if os.path.isfile(cache_path):
                return Image.open(cache_path).convert("RGB")
            req = urllib.request.Request(url, headers={"User-Agent": "RaspyJack/1.0"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                data = resp.read()
            with open(cache_path, "wb") as f:
                f.write(data)
            return Image.open(BytesIO(data)).convert("RGB")
    except Exception:
        return None


def _build_map_bg(lat, lon, width, height, zoom=12):
    from PIL import ImageEnhance
    n = 2 ** zoom
    x_center = int((lon + 180.0) / 360.0 * n)
    lat_rad = math.radians(max(-85, min(85, lat)))
    y_center = int((1.0 - math.log(math.tan(lat_rad) + 1.0 / math.cos(lat_rad)) / math.pi) / 2.0 * n)
    big = Image.new("RGB", (3 * 256, 3 * 256), (10, 14, 20))
    for dx in range(-1, 2):
        for dy in range(-1, 2):
            tile = _fetch_map_tile(zoom, x_center + dx, y_center + dy)
            if tile:
                big.paste(tile, ((dx + 1) * 256, (dy + 1) * 256))
    nw_lon = (x_center - 1) / n * 360.0 - 180.0
    se_lon = (x_center + 2) / n * 360.0 - 180.0
    nw_lat = math.degrees(math.atan(math.sinh(math.pi * (1 - 2 * (y_center - 1) / n))))
    se_lat = math.degrees(math.atan(math.sinh(math.pi * (1 - 2 * (y_center + 2) / n))))
    darkened = ImageEnhance.Brightness(big).enhance(0.45)
    resized = darkened.resize((width, height), Image.LANCZOS)
    return resized, (_lat_to_merc(nw_lat), _lat_to_merc(se_lat), nw_lon, se_lon)


def _map_project(lat, lon, bbox, width, height):
    nw_merc, se_merc, nw_lon, se_lon = bbox
    merc_span = nw_merc - se_merc
    lon_span = se_lon - nw_lon
    if merc_span == 0 or lon_span == 0:
        return width // 2, height // 2
    merc = _lat_to_merc(lat)
    x = int((lon - nw_lon) / lon_span * width)
    y = int((nw_merc - merc) / merc_span * height)
    return x, y


_map_last_count = 0


def _best_zoom(obs, stations):
    if not stations:
        return 12
    lats = [obs[0]] + [s["lat"] for s in stations if s.get("lat")]
    lons = [obs[1]] + [s["lon"] for s in stations if s.get("lon")]
    if len(lats) < 2:
        return 12
    lat_span = max(lats) - min(lats)
    lon_span = max(lons) - min(lons)
    span = max(lat_span, lon_span)
    if span > 8:
        return 5
    if span > 4:
        return 6
    if span > 2:
        return 7
    if span > 1:
        return 8
    if span > 0.5:
        return 9
    if span > 0.2:
        return 10
    if span > 0.1:
        return 11
    return 12


def _draw_map(selected):
    global _map_bg, _map_bbox, _map_last_count
    img = Image.new("RGB", (W, H), (5, 8, 15))
    draw = ImageDraw.Draw(img)

    obs = _get_observer()

    with _lock:
        slist = [s for s in _stations.values() if s.get("lat")]
    cur_count = len(slist)

    if obs[0] and (_map_bg is None or cur_count != _map_last_count):
        z = _best_zoom(obs, slist)
        _map_bg, _map_bbox = _build_map_bg(obs[0], obs[1], W, H - SY(22), zoom=z)
        _map_last_count = cur_count

    if _map_bg and _map_bbox:
        img.paste(_map_bg, (0, SY(12)))

    draw.rectangle([(0, 0), (W, SY(12))], fill=(10, 15, 25))
    draw.text((SX(2), SY(2)), "APRS MAP", font=font_sm, fill=(0, 200, 255))
    n = len(_stations)
    draw.text((W - SX(2), SY(2)), f"{n} stn", font=font_xs, fill=(0, 255, 100), anchor="ra")
    if _receiving:
        draw.ellipse([W - SX(12), SY(3), W - SX(6), SY(9)], fill=(255, 0, 0))

    if obs[0] and _map_bbox:
        ox, oy = _map_project(obs[0], obs[1], _map_bbox, W, H - SY(22))
        oy += SY(12)
        draw.ellipse([ox - 3, oy - 3, ox + 3, oy + 3], fill=(0, 200, 255))

        with _lock:
            slist = list(_stations.values())
        for s in slist:
            if s.get("lat") is None:
                continue
            sx, sy = _map_project(s["lat"], s["lon"], _map_bbox, W, H - SY(22))
            sy += SY(12)
            if 0 <= sx < W and SY(12) <= sy < H - SY(10):
                col = TYPE_COLORS.get(s["type"], (150, 150, 150))
                draw.ellipse([sx - 2, sy - 2, sx + 2, sy + 2], fill=col)
                draw.text((sx + SX(3), sy - SY(2)), s["callsign"][:6], font=font_xs, fill=col)

    draw.rectangle([(0, H - SY(10)), (W, H)], fill=(10, 15, 25))
    draw.text((SX(2), H - SY(9)), "OK:Rec K1:View K3:Exit", font=font_xs, fill=(40, 50, 65))
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_stations(scroll):
    img = Image.new("RGB", (W, H), (5, 8, 15))
    draw = ImageDraw.Draw(img)

    draw.rectangle([(0, 0), (W, SY(12))], fill=(10, 15, 25))
    draw.text((SX(2), SY(2)), "STATIONS", font=font_sm, fill=(0, 200, 255))
    draw.text((W - SX(2), SY(2)), f"{len(_stations)}", font=font_xs, fill=(0, 255, 100), anchor="ra")

    with _lock:
        slist = sorted(_stations.values(), key=lambda s: s.get("distance_km", 0))

    row_h = SY(14)
    y = SY(14)
    max_vis = (H - SY(24)) // row_h

    for i in range(scroll, min(len(slist), scroll + max_vis)):
        s = slist[i]
        col = TYPE_COLORS.get(s["type"], (150, 150, 150))
        bg = (12, 18, 28) if i % 2 == 0 else (8, 12, 20)
        draw.rectangle([(0, y), (W, y + row_h - 1)], fill=bg)
        draw.text((SX(2), y + SY(1)), s["callsign"][:8], font=font_sm, fill=col)
        draw.text((SX(55), y + SY(1)), f"{s['distance_km']:.1f}km", font=font_xs, fill=(150, 150, 170))
        draw.text((SX(85), y + SY(1)), _bearing_arrow(s["bearing"]), font=font_xs, fill=(100, 120, 150))
        ago = int(time.time() - s["last_seen"])
        ago_str = f"{ago}s" if ago < 60 else f"{ago // 60}m"
        draw.text((W - SX(2), y + SY(1)), ago_str, font=font_xs, fill=(60, 70, 90), anchor="ra")
        y += row_h

    draw.rectangle([(0, H - SY(10)), (W, H)], fill=(10, 15, 25))
    draw.text((SX(2), H - SY(9)), "UD:Scroll OK:Rec K3:Exit", font=font_xs, fill=(40, 50, 65))
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_detail(selected):
    img = Image.new("RGB", (W, H), (5, 8, 15))
    draw = ImageDraw.Draw(img)

    draw.rectangle([(0, 0), (W, SY(12))], fill=(10, 15, 25))
    draw.text((SX(2), SY(2)), "DETAIL", font=font_sm, fill=(0, 200, 255))

    with _lock:
        slist = sorted(_stations.values(), key=lambda s: s.get("distance_km", 0))

    if not slist:
        draw.text((W // 2, H // 2), "No stations", font=font, fill=(40, 50, 65), anchor="mm")
        LCD.LCD_ShowImage(img, 0, 0)
        return

    idx = min(selected, len(slist) - 1)
    s = slist[idx]
    col = TYPE_COLORS.get(s["type"], (150, 150, 150))

    y = SY(16)
    items = [
        ("CALL", s["callsign"], col),
        ("TYPE", s["type"].upper(), col),
        ("DIST", f"{s['distance_km']:.1f} km {_bearing_arrow(s['bearing'])} {s['bearing']}°", (0, 200, 255)),
        ("LAT", f"{s['lat']:.5f}°", (200, 200, 200)),
        ("LON", f"{s['lon']:.5f}°", (200, 200, 200)),
        ("PKTS", str(s["packets"]), (0, 255, 100)),
        ("PATH", (s["path"] or "--")[:25], (100, 120, 150)),
        ("INFO", (s["comment"] or "--")[:25], (150, 150, 170)),
    ]
    for label, value, c in items:
        draw.text((SX(4), y), label, font=font_xs, fill=(60, 70, 90))
        draw.text((SX(28), y), value, font=font_sm, fill=c)
        y += SY(11)

    draw.rectangle([(0, H - SY(10)), (W, H)], fill=(10, 15, 25))
    draw.text((SX(2), H - SY(9)), f"UD:Select ({idx + 1}/{len(slist)})", font=font_xs, fill=(40, 50, 65))
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_stats():
    img = Image.new("RGB", (W, H), (5, 8, 15))
    draw = ImageDraw.Draw(img)

    draw.rectangle([(0, 0), (W, SY(12))], fill=(10, 15, 25))
    draw.text((SX(2), SY(2)), "APRS STATS", font=font_sm, fill=(0, 200, 255))

    y = SY(18)
    uptime = int(time.time() - _start_time) if _start_time else 0
    ppm = _total_packets / max(1, uptime / 60) if uptime > 0 else 0

    with _lock:
        slist = list(_stations.values())
    farthest = max((s["distance_km"] for s in slist), default=0)
    farthest_name = ""
    if slist:
        far_s = max(slist, key=lambda s: s["distance_km"])
        farthest_name = far_s["callsign"]

    by_type = {}
    for s in slist:
        by_type[s["type"]] = by_type.get(s["type"], 0) + 1

    items = [
        ("Stations", str(len(slist)), (0, 255, 100)),
        ("Packets", str(_total_packets), (0, 200, 255)),
        ("Rate", f"{ppm:.1f}/min", (255, 200, 0)),
        ("Uptime", f"{uptime // 60}m{uptime % 60:02d}s", (150, 150, 170)),
        ("Farthest", f"{farthest:.1f}km", (255, 100, 0)),
        ("", farthest_name[:15], (100, 120, 150)),
        ("Freq", f"{APRS_FREQ} MHz", (0, 200, 255)),
    ]
    for label, value, c in items:
        if label:
            draw.text((SX(4), y), label, font=font_xs, fill=(60, 70, 90))
        draw.text((SX(45), y), value, font=font_sm, fill=c)
        y += SY(12)

    y += SY(4)
    for t, count in sorted(by_type.items(), key=lambda x: -x[1]):
        col = TYPE_COLORS.get(t, (150, 150, 150))
        draw.rectangle([(SX(4), y + SY(1)), (SX(10), y + SY(7))], fill=col)
        draw.text((SX(13), y), f"{t}: {count}", font=font_xs, fill=col)
        y += SY(10)

    draw.rectangle([(0, H - SY(10)), (W, H)], fill=(10, 15, 25))
    draw.text((SX(2), H - SY(9)), "OK:Rec K1:View K3:Exit", font=font_xs, fill=(40, 50, 65))
    LCD.LCD_ShowImage(img, 0, 0)


def main():
    auto_mode = "--auto" in sys.argv

    r = subprocess.run(["which", "direwolf"], capture_output=True)
    if r.returncode != 0:
        img = Image.new("RGB", (W, H), "black")
        d = ScaledDraw(img)
        d.text((W // 2, 40), "direwolf not found!", font=font, fill=(255, 60, 60), anchor="mm")
        d.text((W // 2, 60), "apt install direwolf", font=font_sm, fill=(150, 150, 150), anchor="mm")
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    threading.Thread(target=_write_live, daemon=True).start()

    if auto_mode:
        _start_receiver()

    view = 0
    scroll = 0
    selected = 0

    try:
        while _running:
            if view == 0:
                _draw_map(selected)
            elif view == 1:
                _draw_stations(scroll)
            elif view == 2:
                _draw_detail(selected)
            elif view == 3:
                _draw_stats()

            btn = _btn()
            if btn == "KEY3":
                break
            elif btn == "KEY1":
                view = (view + 1) % len(VIEWS)
                scroll = 0
            elif btn == "OK":
                if _receiving:
                    _stop_receiver()
                else:
                    _start_receiver()
            elif btn == "UP":
                if view == 1:
                    scroll = max(0, scroll - 1)
                elif view == 2:
                    selected = max(0, selected - 1)
            elif btn == "DOWN":
                if view == 1:
                    scroll += 1
                elif view == 2:
                    selected += 1

            time.sleep(0.15)
    finally:
        _stop_receiver()
        try:
            os.unlink(LIVE_PATH)
        except OSError:
            pass
        LCD.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
