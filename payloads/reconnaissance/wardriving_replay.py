#!/usr/bin/env python3
"""
RaspyJack Payload -- Wardriving Replay
=======================================
Replay wardriving sessions on the LCD screen.
Shows AP positions on a mini-map with OSM tile background.

Views:
  MAP        All APs at once, colored by security
  REPLAY     Chronological playback with moving cursor
  STATS      Session summary

Controls (MAP):
  OK         Zoom in
  KEY2       Zoom out
  Arrows     Pan
  KEY1       Next view
  KEY3       Exit

Controls (REPLAY):
  OK         Play / Pause
  UP/DOWN    Speed
  LEFT/RIGHT Seek
  KEY2       Reset
"""

import os
import sys
import csv
import time
import math
import urllib.request
from io import BytesIO

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageEnhance
from payloads._display_helper import ScaledDraw, scaled_font, S
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT

SESSION_DIR = "/root/Raspyjack/loot/wardriving/sessions"
LOOT_DIR = "/root/Raspyjack/loot/wardriving"

SEC_COLORS = {
    "WPA3": "#00ff88",
    "WPA2": "#00ccff",
    "WPA":  "#ffaa00",
    "WEP":  "#ff8800",
    "OPEN": "#ff3333",
    "?":    "#666666",
}

VIEWS = ["map", "replay", "stats"]
DEBOUNCE = 0.18
_last_btn_time = 0


def _debounced_btn():
    global _last_btn_time
    btn = get_button(PINS, GPIO)
    now = time.time()
    if btn and now - _last_btn_time < DEBOUNCE:
        return None
    if btn:
        _last_btn_time = now
    return btn
TILE_CACHE = "/root/Raspyjack/loot/wardriving/.tilecache"
TILE_URL = "https://tile.openstreetmap.org/{z}/{x}/{y}.png"
TILE_SIZE = 256
MAX_TILE_DOWNLOADS = 20


def _sec_type(auth):
    if not auth:
        return "?"
    a = auth.upper()
    if "WPA3" in a:
        return "WPA3"
    if "WPA2" in a:
        return "WPA2"
    if "WPA" in a:
        return "WPA"
    if "WEP" in a:
        return "WEP"
    if "ESS" in a and "WPA" not in a and "WEP" not in a:
        return "OPEN"
    return "?"


def _parse_session(path):
    """Parse a Wigle CSV file, return list of AP dicts sorted by time."""
    aps = []
    try:
        with open(path, "r", encoding="utf-8-sig", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return aps
    if len(lines) < 3:
        return aps
    header = lines[1].strip().split(",")
    idx = {k: i for i, k in enumerate(header)}
    lat_i = idx.get("CurrentLatitude")
    lon_i = idx.get("CurrentLongitude")
    if lat_i is None or lon_i is None:
        return aps
    mac_i = idx.get("MAC", 0)
    ssid_i = idx.get("SSID", 1)
    auth_i = idx.get("AuthMode", 2)
    ch_i = idx.get("Channel", 4)
    rssi_i = idx.get("RSSI", 5)
    time_i = idx.get("FirstSeen", 3)
    for line in lines[2:]:
        cols = line.strip().split(",")
        if len(cols) <= max(lat_i, lon_i):
            continue
        try:
            lat = float(cols[lat_i])
            lon = float(cols[lon_i])
        except (ValueError, IndexError):
            continue
        if lat == 0 and lon == 0:
            continue
        auth_val = cols[auth_i] if auth_i < len(cols) else ""
        aps.append({
            "mac": cols[mac_i] if mac_i < len(cols) else "",
            "ssid": cols[ssid_i] if ssid_i < len(cols) else "",
            "auth": auth_val,
            "channel": cols[ch_i] if ch_i < len(cols) else "?",
            "rssi": cols[rssi_i] if rssi_i < len(cols) else "?",
            "lat": lat,
            "lon": lon,
            "time": cols[time_i] if time_i < len(cols) else "",
            "sec": _sec_type(auth_val),
        })
    aps.sort(key=lambda a: a["time"])
    return aps


def _list_sessions():
    """Return list of (name, path) tuples for available sessions."""
    sessions = []
    if os.path.isdir(SESSION_DIR):
        for f in sorted(os.listdir(SESSION_DIR), reverse=True):
            if f.endswith("_wigle.csv"):
                sessions.append((f.replace("_wigle.csv", ""), os.path.join(SESSION_DIR, f)))
    live = os.path.join(LOOT_DIR, "wardriving_live.csv")
    if os.path.isfile(live):
        sessions.insert(0, ("Live (last)", live))
    return sessions


# ---------------------------------------------------------------------------
# OSM tile helpers
# ---------------------------------------------------------------------------

def _lat_to_merc(lat):
    lat = max(-85.0, min(85.0, lat))
    return math.log(math.tan(math.pi / 4 + math.radians(lat) / 2))


def _lat_lon_to_tile(lat, lon, zoom):
    n = 2 ** zoom
    x_tile = int((lon + 180.0) / 360.0 * n)
    lat_rad = math.radians(max(-85, min(85, lat)))
    y_tile = int((1.0 - math.log(math.tan(lat_rad) + 1.0 / math.cos(lat_rad)) / math.pi) / 2.0 * n)
    return x_tile, y_tile


def _tile_to_lat_lon(x_tile, y_tile, zoom):
    n = 2 ** zoom
    lon = x_tile / n * 360.0 - 180.0
    lat = math.degrees(math.atan(math.sinh(math.pi * (1 - 2 * y_tile / n))))
    return lat, lon


_tile_dl_count = 0


def _fetch_tile(z, x, y):
    global _tile_dl_count
    os.makedirs(TILE_CACHE, exist_ok=True)
    cache_path = os.path.join(TILE_CACHE, f"{z}_{x}_{y}.png")
    if os.path.isfile(cache_path):
        try:
            return Image.open(cache_path).convert("RGB")
        except Exception:
            pass
    if _tile_dl_count >= MAX_TILE_DOWNLOADS:
        return None
    url = TILE_URL.format(z=z, x=x, y=y)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "RaspyJack/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = resp.read()
        with open(cache_path, "wb") as f:
            f.write(data)
        _tile_dl_count += 1
        return Image.open(BytesIO(data)).convert("RGB")
    except Exception as e:
        print(f"[REPLAY] Tile fetch failed {z}/{x}/{y}: {e}")
        return None


def _build_bg(lat_min, lat_max, lon_min, lon_max, out_w, out_h):
    """Build a background map image from OSM tiles for the given bbox."""
    for z in range(15, 8, -1):
        x0, y0 = _lat_lon_to_tile(lat_max, lon_min, z)
        x1, y1 = _lat_lon_to_tile(lat_min, lon_max, z)
        n_tiles = (x1 - x0 + 1) * (y1 - y0 + 1)
        if n_tiles <= 12:
            break

    x0, y0 = _lat_lon_to_tile(lat_max, lon_min, z)
    x1, y1 = _lat_lon_to_tile(lat_min, lon_max, z)

    cols = x1 - x0 + 1
    rows = y1 - y0 + 1
    big = Image.new("RGB", (cols * TILE_SIZE, rows * TILE_SIZE), (10, 14, 20))

    for tx in range(x0, x1 + 1):
        for ty in range(y0, y1 + 1):
            tile = _fetch_tile(z, tx, ty)
            if tile:
                big.paste(tile, ((tx - x0) * TILE_SIZE, (ty - y0) * TILE_SIZE))

    nw_lat, nw_lon = _tile_to_lat_lon(x0, y0, z)
    se_lat, se_lon = _tile_to_lat_lon(x1 + 1, y1 + 1, z)

    nw_merc = _lat_to_merc(nw_lat)
    se_merc = _lat_to_merc(se_lat)
    lon_span = se_lon - nw_lon
    merc_span = nw_merc - se_merc
    if lon_span == 0 or merc_span == 0:
        return None

    px_left = int((lon_min - nw_lon) / lon_span * big.width)
    px_right = int((lon_max - nw_lon) / lon_span * big.width)
    px_top = int((nw_merc - _lat_to_merc(lat_max)) / merc_span * big.height)
    px_bottom = int((nw_merc - _lat_to_merc(lat_min)) / merc_span * big.height)

    px_left = max(0, px_left)
    px_top = max(0, px_top)
    px_right = min(big.width, max(px_left + 1, px_right))
    px_bottom = min(big.height, max(px_top + 1, px_bottom))

    cropped = big.crop((px_left, px_top, px_right, px_bottom))
    cropped = ImageEnhance.Brightness(cropped).enhance(0.45)
    return cropped.resize((out_w, out_h), Image.LANCZOS)


# ---------------------------------------------------------------------------
# Map renderer
# ---------------------------------------------------------------------------

class MapRenderer:

    def __init__(self, aps, width, height):
        self.width = width
        self.height = height

        lats = [a["lat"] for a in aps]
        lons = [a["lon"] for a in aps]
        self.base_lat_min, self.base_lat_max = min(lats), max(lats)
        self.base_lon_min, self.base_lon_max = min(lons), max(lons)

        dlat = self.base_lat_max - self.base_lat_min
        dlon = self.base_lon_max - self.base_lon_min
        if dlat < 0.0001:
            dlat = 0.001
        if dlon < 0.0001:
            dlon = 0.001
        self.base_lat_min -= dlat * 0.1
        self.base_lat_max += dlat * 0.1
        self.base_lon_min -= dlon * 0.1
        self.base_lon_max += dlon * 0.1

        self.zoom_level = 1.0
        self.pan_x = 0.0
        self.pan_y = 0.0

        self.base_merc_min = _lat_to_merc(self.base_lat_min)
        self.base_merc_max = _lat_to_merc(self.base_lat_max)

        # Background covering 2x the data area for pan/zoom headroom
        self._bg_full = None
        ex_lat = (self.base_lat_max - self.base_lat_min) * 0.5
        ex_lon = (self.base_lon_max - self.base_lon_min) * 0.5
        self._bg_lat_min = self.base_lat_min - ex_lat
        self._bg_lat_max = self.base_lat_max + ex_lat
        self._bg_lon_min = self.base_lon_min - ex_lon
        self._bg_lon_max = self.base_lon_max + ex_lon
        self._bg_merc_min = _lat_to_merc(self._bg_lat_min)
        self._bg_merc_max = _lat_to_merc(self._bg_lat_max)
        self._bg_merc_span = self._bg_merc_max - self._bg_merc_min
        self._bg_lon_span = self._bg_lon_max - self._bg_lon_min
        try:
            self._bg_full = _build_bg(
                self._bg_lat_min, self._bg_lat_max,
                self._bg_lon_min, self._bg_lon_max,
                width * 2, height * 2,
            )
        except Exception as e:
            print(f"[REPLAY] Background build failed: {e}")

    def _clamp_pan(self):
        limit = 0.8 / self.zoom_level
        self.pan_x = max(-limit, min(limit, self.pan_x))
        self.pan_y = max(-limit, min(limit, self.pan_y))

    def _visible_viewport(self):
        merc_range = self.base_merc_max - self.base_merc_min
        lon_range = self.base_lon_max - self.base_lon_min
        if merc_range == 0:
            merc_range = 0.001
        if lon_range == 0:
            lon_range = 0.001

        vis_merc = merc_range / self.zoom_level
        vis_lon = lon_range / self.zoom_level

        center_merc = (self.base_merc_min + self.base_merc_max) / 2 - self.pan_y * merc_range
        center_lon = (self.base_lon_min + self.base_lon_max) / 2 + self.pan_x * lon_range

        return (
            center_merc - vis_merc / 2,
            center_merc + vis_merc / 2,
            center_lon - vis_lon / 2,
            center_lon + vis_lon / 2,
        )

    def get_bg(self):
        if not self._bg_full or self._bg_lon_span == 0 or self._bg_merc_span == 0:
            return Image.new("RGB", (self.width, self.height), "#0a0e18")

        v_merc_min, v_merc_max, v_lon_min, v_lon_max = self._visible_viewport()
        bg_w, bg_h = self._bg_full.size

        px_left = (v_lon_min - self._bg_lon_min) / self._bg_lon_span * bg_w
        px_right = (v_lon_max - self._bg_lon_min) / self._bg_lon_span * bg_w
        px_top = (self._bg_merc_max - v_merc_max) / self._bg_merc_span * bg_h
        px_bottom = (self._bg_merc_max - v_merc_min) / self._bg_merc_span * bg_h

        px_left = max(0, int(px_left))
        px_top = max(0, int(px_top))
        px_right = min(bg_w, max(px_left + 1, int(px_right)))
        px_bottom = min(bg_h, max(px_top + 1, int(px_bottom)))

        cropped = self._bg_full.crop((px_left, px_top, px_right, px_bottom))
        return cropped.resize((self.width, self.height), Image.LANCZOS)

    def project(self, lat, lon):
        v_merc_min, v_merc_max, v_lon_min, v_lon_max = self._visible_viewport()
        lon_span = v_lon_max - v_lon_min
        merc_span = v_merc_max - v_merc_min
        if lon_span == 0 or merc_span == 0:
            return self.width // 2, self.height // 2

        nx = (lon - v_lon_min) / lon_span
        merc = _lat_to_merc(lat)
        ny = 1.0 - (merc - v_merc_min) / merc_span

        return int(nx * self.width), int(ny * self.height)

    def zoom_in(self):
        self.zoom_level = min(6.0, self.zoom_level * 1.5)
        self._clamp_pan()

    def zoom_out(self):
        self.zoom_level = max(0.5, self.zoom_level / 1.5)
        self._clamp_pan()

    def pan(self, dx, dy):
        self.pan_x += dx * 0.12 / self.zoom_level
        self.pan_y += dy * 0.12 / self.zoom_level
        self._clamp_pan()

    def draw_map(self, draw, aps_to_show, cursor_idx=-1):
        if len(aps_to_show) >= 2:
            pts = [self.project(a["lat"], a["lon"]) for a in aps_to_show]
            for i in range(len(pts) - 1):
                x1, y1 = pts[i]
                x2, y2 = pts[i + 1]
                if (0 <= x1 <= self.width and 0 <= y1 <= self.height) or \
                   (0 <= x2 <= self.width and 0 <= y2 <= self.height):
                    ratio = i / max(1, len(pts) - 1)
                    r = int(120 * (1 - ratio))
                    g = int(120 * ratio)
                    draw.line([(x1, y1), (x2, y2)], fill=(r, g, 80), width=1)

        for i, a in enumerate(aps_to_show):
            x, y = self.project(a["lat"], a["lon"])
            if x < -5 or x > self.width + 5 or y < -5 or y > self.height + 5:
                continue
            color = SEC_COLORS.get(a["sec"], "#666")
            dot_r = 3 if self.zoom_level >= 2.0 else 2
            if i == cursor_idx:
                draw.ellipse([x - 6, y - 6, x + 6, y + 6], outline="#ffffff", width=1)
                dot_r = 4
            draw.ellipse([x - dot_r, y - dot_r, x + dot_r, y + dot_r], fill=color)

    def draw_legend(self, draw, font):
        s = max(1, S(1))
        y = 2 * s
        for sec, color in [("WPA3", "#00ff88"), ("WPA2", "#00ccff"), ("OPEN", "#ff3333")]:
            draw.rectangle([2*s, y, 6*s, y + 4*s], fill=color)
            draw.text((9*s, y - s), sec, font=font, fill="#888")
            y += 8 * s


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
    font_sm = scaled_font(8)
    font_xs = scaled_font(7)

    sessions = _list_sessions()
    if not sessions:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "No sessions found", font=font, fill="#FF4444")
        d.text((4, 70), "Run wardriving first", font=font_sm, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return

    sel = 0
    while True:
        # --- Session selection ---
        while True:
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.text((4, 2), "SELECT SESSION", font=font, fill="#00CCFF")
            d.line([(0, 14), (127, 14)], fill="#0f1a2a")

            visible = 7
            start = max(0, sel - visible // 2)
            for i in range(start, min(len(sessions), start + visible)):
                y = 18 + (i - start) * 15
                name = sessions[i][0]
                if len(name) > 22:
                    name = name[:22] + ".."
                color = "#00CCFF" if i == sel else "#888"
                prefix = "> " if i == sel else "  "
                d.text((4, y), prefix + name, font=font_sm, fill=color)

            d.text((4, 116), "OK=Load  KEY3=Exit", font=font_xs, fill="#555")
            lcd.LCD_ShowImage(img, 0, 0)

            btn = _debounced_btn()
            if btn == "KEY3":
                GPIO.cleanup()
                return
            elif btn == "UP":
                sel = (sel - 1) % len(sessions)
            elif btn == "DOWN":
                sel = (sel + 1) % len(sessions)
            elif btn == "OK":
                break

        # --- Load session ---
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((10, 55), "Loading...", font=font, fill="#FFAA00")
        lcd.LCD_ShowImage(img, 0, 0)

        aps = _parse_session(sessions[sel][1])
        if not aps:
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.text((4, 50), "No GPS data", font=font, fill="#FF4444")
            d.text((4, 70), "in this session", font=font_sm, fill="#888")
            lcd.LCD_ShowImage(img, 0, 0)
            time.sleep(3)
            continue

        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((10, 45), "Downloading map...", font=font_sm, fill="#00CCFF")
        d.text((10, 60), f"{len(aps)} APs loaded", font=font_xs, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)

        renderer = MapRenderer(aps, WIDTH, HEIGHT)

        # --- Main display loop ---
        view_idx = 0
        replay_idx = 0
        replay_playing = False
        replay_speed = 1
        speeds = [1, 2, 5, 10, 25, 50]
        speed_idx = 0
        last_replay_time = 0

        while True:
            btn = _debounced_btn()

            if btn == "KEY3":
                break

            if btn == "KEY1":
                view_idx = (view_idx + 1) % len(VIEWS)
                if VIEWS[view_idx] == "replay":
                    replay_idx = 0
                    replay_playing = False

            view = VIEWS[view_idx]

            if view == "map":
                if btn == "OK":
                    renderer.zoom_in()
                elif btn == "KEY2":
                    renderer.zoom_out()
                elif btn == "UP":
                    renderer.pan(0, -1)
                elif btn == "DOWN":
                    renderer.pan(0, 1)
                elif btn == "LEFT":
                    renderer.pan(-1, 0)
                elif btn == "RIGHT":
                    renderer.pan(1, 0)

                img = renderer.get_bg()
                d = ImageDraw.Draw(img)
                renderer.draw_map(d, aps)
                renderer.draw_legend(d, font_xs)
                d.text((WIDTH - S(60), HEIGHT - S(10)), f"{len(aps)} APs", font=font_xs, fill="#aaa")
                lcd.LCD_ShowImage(img, 0, 0)

            elif view == "replay":
                if btn == "OK":
                    replay_playing = not replay_playing
                elif btn == "UP":
                    speed_idx = min(len(speeds) - 1, speed_idx + 1)
                    replay_speed = speeds[speed_idx]
                elif btn == "DOWN":
                    speed_idx = max(0, speed_idx - 1)
                    replay_speed = speeds[speed_idx]
                elif btn == "LEFT":
                    replay_idx = max(0, replay_idx - max(1, len(aps) // 20))
                elif btn == "RIGHT":
                    replay_idx = min(len(aps), replay_idx + max(1, len(aps) // 20))
                elif btn == "KEY2":
                    replay_idx = 0
                    replay_playing = False

                now = time.time()
                if replay_playing and now - last_replay_time > 0.08 / replay_speed:
                    replay_idx = min(len(aps), replay_idx + 1)
                    last_replay_time = now
                    if replay_idx >= len(aps):
                        replay_playing = False

                visible = aps[:replay_idx]
                img = renderer.get_bg()
                d = ImageDraw.Draw(img)

                cursor = replay_idx - 1 if replay_idx > 0 else -1
                renderer.draw_map(d, visible, cursor_idx=cursor)

                bar_h = S(14)
                d.rectangle([(0, HEIGHT - bar_h), (WIDTH, HEIGHT)], fill="#0a0e18")
                pct = replay_idx / max(1, len(aps))
                bw = int((WIDTH - S(4)) * pct)
                d.rectangle([(S(2), HEIGHT - bar_h + S(2)), (S(2) + bw, HEIGHT - bar_h + S(6))], fill="#00ccff")
                d.rectangle([(S(2), HEIGHT - bar_h + S(2)), (WIDTH - S(2), HEIGHT - bar_h + S(6))], outline="#1a2844")

                status = ">" if replay_playing else "||"
                t_str = "--:--"
                if replay_idx > 0:
                    raw_t = aps[min(replay_idx, len(aps) - 1)].get("time", "")
                    parts = raw_t.split(" ")
                    t_str = parts[-1][:5] if parts[-1] else raw_t[:5]
                d.text((S(2), HEIGHT - S(7)), f"{status} {t_str}", font=font_xs, fill="#00ccff")
                d.text((WIDTH - S(50), HEIGHT - S(7)), f"{replay_idx}/{len(aps)}", font=font_xs, fill="#555")
                d.text((WIDTH // 2 - S(8), HEIGHT - S(7)), f"x{replay_speed}", font=font_xs, fill="#888")

                lcd.LCD_ShowImage(img, 0, 0)

            elif view == "stats":
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.text((4, 2), "SESSION STATS", font=font, fill="#00CCFF")
                d.line([(0, 14), (127, 14)], fill="#0f1a2a")

                name = sessions[sel][0]
                if len(name) > 24:
                    name = name[:24] + ".."
                d.text((4, 18), name, font=font_xs, fill="#888")

                total = len(aps)
                sec_count = {}
                channels = {}
                for a in aps:
                    sec_count[a["sec"]] = sec_count.get(a["sec"], 0) + 1
                    ch = a.get("channel", "?")
                    channels[ch] = channels.get(ch, 0) + 1

                d.text((4, 32), f"Total APs: {total}", font=font_sm, fill="#fff")

                y = 46
                for sec in ["WPA3", "WPA2", "WPA", "WEP", "OPEN"]:
                    cnt = sec_count.get(sec, 0)
                    if cnt == 0:
                        continue
                    color = SEC_COLORS[sec]
                    bar_w = max(1, cnt * 68 // total)
                    d.rectangle([(50, y + 1), (50 + bar_w, y + 7)], fill=color)
                    d.text((4, y), sec, font=font_xs, fill=color)
                    d.text((98, y), f"{cnt}", font=font_xs, fill="#888")
                    y += 11

                if aps[0].get("time") and aps[-1].get("time"):
                    t0_parts = aps[0]["time"].split(" ")
                    t1_parts = aps[-1]["time"].split(" ")
                    t0 = t0_parts[-1][:5] if t0_parts[-1] else "?"
                    t1 = t1_parts[-1][:5] if t1_parts[-1] else "?"
                    d.text((4, y + 4), f"Time: {t0} - {t1}", font=font_xs, fill="#555")

                top_ch = sorted(channels.items(), key=lambda x: -x[1])[:5]
                ch_str = " ".join(f"ch{c}:{n}" for c, n in top_ch)
                d.text((4, y + 16), ch_str, font=font_xs, fill="#555")

                d.text((4, 116), "KEY1=Views  KEY3=Back", font=font_xs, fill="#444")
                lcd.LCD_ShowImage(img, 0, 0)

            time.sleep(0.03)
        # KEY3 in display loop → back to session list

    # Should not reach here, but cleanup just in case
    try:
        lcd.LCD_Clear()
    except Exception:
        pass
    GPIO.cleanup()


if __name__ == "__main__":
    raise SystemExit(main() or 0)
