#!/usr/bin/env python3
"""
RaspyJack Payload -- Offline Map Downloader
=============================================
Pre-download OSM map tiles for wardriving & GPS tracker.
Select a region and zoom level, tiles are cached for offline use.

Controls:
  OK         Start download / Select
  UP/DOWN    Navigate regions / zoom
  KEY1       Switch: Presets / GPS / Custom
  KEY2       Clear cache
  KEY3       Exit
"""

import os
import sys
import time
import math
import threading
import urllib.request

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
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
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
TILE_CACHE = "/root/Raspyjack/loot/wardriving/.tilecache"
TILE_URL = "https://tile.openstreetmap.org/{z}/{x}/{y}.png"
DEBOUNCE = 0.18
_last_btn = 0

REGIONS = [
    ("GPS Position 5km", None, None, 5),
    ("GPS Position 10km", None, None, 10),
    ("GPS Position 20km", None, None, 20),
    ("Paris", 48.8566, 2.3522, 15),
    ("Lyon", 45.7640, 4.8357, 10),
    ("Marseille", 43.2965, 5.3698, 10),
    ("Toulouse", 43.6047, 1.4442, 10),
    ("Bordeaux", 44.8378, -0.5792, 10),
    ("Lille", 50.6292, 3.0573, 10),
    ("Nantes", 47.2184, -1.5536, 10),
    ("Strasbourg", 48.5734, 7.7521, 10),
    ("Montpellier", 43.6108, 3.8767, 10),
    ("Rennes", 48.1173, -1.6778, 10),
    ("Caen", 49.1829, -0.3707, 10),
    ("Rouen", 49.4432, 1.0999, 10),
    ("London", 51.5074, -0.1278, 15),
    ("Brussels", 50.8503, 4.3517, 10),
    ("Amsterdam", 52.3676, 4.9041, 10),
    ("Berlin", 52.5200, 13.4050, 15),
    ("Madrid", 40.4168, -3.7038, 15),
    ("Rome", 41.9028, 12.4964, 15),
    ("New York", 40.7128, -74.0060, 15),
    ("San Francisco", 37.7749, -122.4194, 10),
    ("Tokyo", 35.6762, 139.6503, 15),
]

ZOOM_LEVELS = [13, 14, 15, 16]


def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE:
        return None
    if b:
        _last_btn = now
    return b


def _lat_lon_to_tile(lat, lon, z):
    n = 2 ** z
    x = int((lon + 180.0) / 360.0 * n)
    lat_r = math.radians(max(-85, min(85, lat)))
    y = int((1.0 - math.log(math.tan(lat_r) + 1.0 / math.cos(lat_r)) / math.pi) / 2.0 * n)
    return x, y


def _tiles_for_region(lat, lon, radius_km, zoom):
    """Calculate tile range for a circular region."""
    deg_per_km = 1 / 111.0
    dlat = radius_km * deg_per_km
    dlon = radius_km * deg_per_km / max(0.1, math.cos(math.radians(lat)))

    x_min, y_max = _lat_lon_to_tile(lat - dlat, lon - dlon, zoom)
    x_max, y_min = _lat_lon_to_tile(lat + dlat, lon + dlon, zoom)

    tiles = []
    for x in range(x_min, x_max + 1):
        for y in range(y_min, y_max + 1):
            tiles.append((zoom, x, y))
    return tiles


def _count_cached():
    """Count existing cached tiles."""
    if not os.path.isdir(TILE_CACHE):
        return 0
    return sum(1 for f in os.listdir(TILE_CACHE) if f.endswith(".png"))


def _cache_size_mb():
    """Get cache size in MB."""
    if not os.path.isdir(TILE_CACHE):
        return 0
    total = sum(os.path.getsize(os.path.join(TILE_CACHE, f))
                for f in os.listdir(TILE_CACHE) if f.endswith(".png"))
    return total / (1024 * 1024)


def _download_tiles(tiles, lcd, font, font_sm, stop_event):
    """Download tiles with progress display."""
    os.makedirs(TILE_CACHE, exist_ok=True)
    total = len(tiles)
    downloaded = 0
    skipped = 0
    errors = 0

    for i, (z, x, y) in enumerate(tiles):
        if stop_event.is_set():
            break

        cache_path = os.path.join(TILE_CACHE, f"{z}_{x}_{y}.png")
        if os.path.isfile(cache_path):
            skipped += 1
            continue

        url = TILE_URL.format(z=z, x=x, y=y)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "RaspyJack/2.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = resp.read()
            with open(cache_path, "wb") as f:
                f.write(data)
            downloaded += 1
        except Exception:
            errors += 1

        # Update display every 5 tiles
        if i % 5 == 0 or i == total - 1:
            pct = (i + 1) * 100 // total
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.rectangle((0, 0, 127, 14), fill="#111")
            d.text((2, 2), "DOWNLOADING", font=font_sm, fill="#00CCFF")
            d.text((90, 2), f"{pct}%", font=font_sm, fill="#00FF00")

            d.rectangle((4, 24, 123, 34), outline="#333")
            bw = max(1, int(119 * (i + 1) / total))
            d.rectangle((4, 24, 4 + bw, 34), fill="#00CCFF")

            d.text((4, 42), f"Tile {i+1}/{total}", font=font_sm, fill="#ccc")
            d.text((4, 56), f"Downloaded: {downloaded}", font=font_sm, fill="#00FF00")
            d.text((4, 70), f"Cached: {skipped}", font=font_sm, fill="#888")
            if errors:
                d.text((4, 84), f"Errors: {errors}", font=font_sm, fill="#FF4444")
            d.text((4, 100), "KEY3 to cancel", font=font_sm, fill="#555")
            lcd.LCD_ShowImage(img, 0, 0)

        # Rate limit to be polite to OSM servers
        time.sleep(0.1)

    return downloaded, skipped, errors


def _get_gps_position():
    """Get current GPS position via gpsd."""
    if not GPSD_OK:
        return None, None
    try:
        gpsd_mod.connect()
        pkt = gpsd_mod.get_current()
        if hasattr(pkt, 'mode') and pkt.mode >= 2:
            return pkt.lat, pkt.lon
    except Exception:
        pass
    return None, None


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

    sel = 0
    zoom_min = 1  # index into ZOOM_LEVELS (14)
    zoom_max = 2  # index into ZOOM_LEVELS (15)
    editing_zoom = 0  # 0=min, 1=max
    scroll = 0
    status = ""
    stop_event = threading.Event()

    try:
        while True:
            btn = _btn()
            if btn == "KEY3":
                if not stop_event.is_set():
                    stop_event.set()
                else:
                    break

            if btn == "UP":
                sel = (sel - 1) % len(REGIONS)
            elif btn == "DOWN":
                sel = (sel + 1) % len(REGIONS)
            elif btn == "LEFT":
                if editing_zoom == 0:
                    zoom_min = max(0, zoom_min - 1)
                    if zoom_min > zoom_max:
                        zoom_max = zoom_min
                else:
                    zoom_max = max(0, zoom_max - 1)
                    if zoom_max < zoom_min:
                        zoom_min = zoom_max
            elif btn == "RIGHT":
                if editing_zoom == 0:
                    zoom_min = min(len(ZOOM_LEVELS) - 1, zoom_min + 1)
                    if zoom_min > zoom_max:
                        zoom_max = zoom_min
                else:
                    zoom_max = min(len(ZOOM_LEVELS) - 1, zoom_max + 1)
                    if zoom_max < zoom_min:
                        zoom_min = zoom_max
            elif btn == "KEY1":
                editing_zoom = 1 - editing_zoom

            elif btn == "KEY2":
                # Clear cache
                if os.path.isdir(TILE_CACHE):
                    for f in os.listdir(TILE_CACHE):
                        if f.endswith(".png"):
                            os.remove(os.path.join(TILE_CACHE, f))
                status = "Cache cleared"

            elif btn == "OK":
                name, lat, lon, radius = REGIONS[sel]

                # GPS position regions
                if lat is None:
                    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                    d = ScaledDraw(img)
                    d.text((4, 50), "Getting GPS fix...", font=font_sm, fill="#FFAA00")
                    lcd.LCD_ShowImage(img, 0, 0)

                    lat, lon = _get_gps_position()
                    if lat is None:
                        status = "No GPS fix"
                        continue

                z_lo = ZOOM_LEVELS[zoom_min]
                z_hi = ZOOM_LEVELS[zoom_max]
                all_tiles = []
                for z in range(z_lo, z_hi + 1):
                    all_tiles.extend(_tiles_for_region(lat, lon, radius, z))

                already = sum(1 for z, x, y in all_tiles
                             if os.path.isfile(os.path.join(TILE_CACHE, f"{z}_{x}_{y}.png")))
                to_download = len(all_tiles) - already
                est_mb = to_download * 0.015
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.text((4, 18), name[:20], font=font, fill="#00CCFF")
                d.text((4, 36), f"{len(all_tiles)} tiles total", font=font_sm, fill="#ccc")
                d.text((4, 50), f"{already} already cached", font=font_sm, fill="#00FF00")
                d.text((4, 64), f"{to_download} to download (~{est_mb:.0f}MB)", font=font_sm, fill="#FFAA00")
                d.text((4, 78), f"Zoom {z_lo}-{z_hi} / {radius}km", font=font_sm, fill="#888")
                d.text((4, 95), "OK=Download KEY3=Cancel", font=font_sm, fill="#888")
                lcd.LCD_ShowImage(img, 0, 0)

                while True:
                    b2 = _btn()
                    if b2 == "KEY3":
                        break
                    if b2 == "OK":
                        stop_event.clear()
                        dl, sk, err = _download_tiles(all_tiles, lcd, font, font_sm, stop_event)
                        status = f"Done: {dl} new {sk} cached {err} err"
                        break

            # Draw main screen
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.rectangle((0, 0, 127, 14), fill="#111")
            d.text((2, 2), "MAP DOWNLOAD", font=font_sm, fill="#00CCFF")
            cached = _count_cached()
            size = _cache_size_mb()
            d.text((85, 2), f"{size:.0f}MB", font=font_sm, fill="#888")

            y = 18
            if status:
                d.text((2, y), status[:24], font=font_sm, fill="#FFAA00")
                y += 12

            # Region list
            visible = 5
            start = max(0, sel - visible // 2)
            for i in range(start, min(len(REGIONS), start + visible)):
                if y > 95:
                    break
                name, lat, lon, radius = REGIONS[i]
                col = "#00CCFF" if i == sel else "#888"
                pre = "> " if i == sel else "  "
                d.text((2, y), f"{pre}{name[:18]}", font=font_sm, fill=col)
                if i == sel:
                    z_lo = ZOOM_LEVELS[zoom_min]
                    z_hi = ZOOM_LEVELS[zoom_max]
                    total_t = sum(len(_tiles_for_region(lat or 48.8, lon or 2.3, radius, z)) for z in range(z_lo, z_hi + 1))
                    d.text((4, y + 11), f"z{z_lo}-{z_hi} ~{total_t}tiles {radius}km", font=font_sm, fill="#555")
                    y += 11
                y += 12

            z_lo = ZOOM_LEVELS[zoom_min]
            z_hi = ZOOM_LEVELS[zoom_max]
            min_col = "#00CCFF" if editing_zoom == 0 else "#888"
            max_col = "#00CCFF" if editing_zoom == 1 else "#888"
            d.rectangle((0, 116, 127, 127), fill="#111")
            d.text((2, 117), f"<>:Z {z_lo}-{z_hi} K1:min/max K2:Clr", font=font_sm, fill="#666")
            lcd.LCD_ShowImage(img, 0, 0)

            time.sleep(0.03)

    finally:
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
