#!/usr/bin/env python3
"""
RaspyJack Payload -- Offline Map Viewer
=========================================
Browse downloaded map tiles on the LCD. Pan, zoom, GPS center.

Controls:
  OK         Center on GPS position
  UP/DOWN    Pan North/South
  LEFT/RIGHT Pan East/West
  KEY1       Zoom in
  KEY2       Zoom out
  KEY3       Exit
"""

import os
import sys
import time
import math
import glob

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw
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
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
TILE_CACHE = "/root/Raspyjack/loot/wardriving/.tilecache"
TILE_SIZE = 256
DEBOUNCE = 0.15
_last_btn = 0


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
    x = (lon + 180.0) / 360.0 * n
    lat_r = math.radians(max(-85, min(85, lat)))
    y = (1.0 - math.log(math.tan(lat_r) + 1.0 / math.cos(lat_r)) / math.pi) / 2.0 * n
    return x, y


def _tile_to_lat_lon(x, y, z):
    n = 2 ** z
    lon = x / n * 360.0 - 180.0
    lat = math.degrees(math.atan(math.sinh(math.pi * (1 - 2 * y / n))))
    return lat, lon


def _load_tile(z, x, y):
    path = os.path.join(TILE_CACHE, f"{z}_{x}_{y}.png")
    if os.path.isfile(path):
        try:
            return Image.open(path).convert("RGB")
        except Exception:
            pass
    return None


def _get_cache_stats():
    """Get stats about cached tiles."""
    if not os.path.isdir(TILE_CACHE):
        return 0, 0, {}
    files = [f for f in os.listdir(TILE_CACHE) if f.endswith(".png")]
    total_size = sum(os.path.getsize(os.path.join(TILE_CACHE, f)) for f in files)
    zoom_counts = {}
    for f in files:
        parts = f.replace(".png", "").split("_")
        if len(parts) >= 1:
            z = parts[0]
            zoom_counts[z] = zoom_counts.get(z, 0) + 1
    return len(files), total_size, zoom_counts


def _get_gps():
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


def _render_map(center_x, center_y, zoom, lcd_w, lcd_h):
    """Render map tiles into an image centered on tile coordinates (float)."""
    from PIL import ImageEnhance

    img = Image.new("RGB", (lcd_w, lcd_h), (10, 14, 20))

    # How many tiles we need to cover the LCD
    tiles_x = lcd_w // TILE_SIZE + 2
    tiles_y = lcd_h // TILE_SIZE + 2

    # Pixel offset within the center tile
    cx_tile = int(center_x)
    cy_tile = int(center_y)
    px_off = int((center_x - cx_tile) * TILE_SIZE)
    py_off = int((center_y - cy_tile) * TILE_SIZE)

    # Starting tile
    start_tx = cx_tile - tiles_x // 2
    start_ty = cy_tile - tiles_y // 2

    # Compose tiles into a big image then crop
    big_w = tiles_x * TILE_SIZE
    big_h = tiles_y * TILE_SIZE
    big = Image.new("RGB", (big_w, big_h), (10, 14, 20))

    tiles_loaded = 0
    tiles_missing = 0
    for dx in range(tiles_x):
        for dy in range(tiles_y):
            tx = start_tx + dx
            ty = start_ty + dy
            tile = _load_tile(zoom, tx, ty)
            if tile:
                big.paste(tile, (dx * TILE_SIZE, dy * TILE_SIZE))
                tiles_loaded += 1
            else:
                tiles_missing += 1

    # Crop to LCD size centered on the offset
    crop_x = (tiles_x // 2) * TILE_SIZE + px_off - lcd_w // 2
    crop_y = (tiles_y // 2) * TILE_SIZE + py_off - lcd_h // 2
    crop_x = max(0, min(big_w - lcd_w, crop_x))
    crop_y = max(0, min(big_h - lcd_h, crop_y))

    cropped = big.crop((crop_x, crop_y, crop_x + lcd_w, crop_y + lcd_h))

    # Darken slightly for overlay readability
    cropped = ImageEnhance.Brightness(cropped).enhance(0.7)

    return cropped, tiles_loaded, tiles_missing


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
    rw, rh = lcd.width, lcd.height
    s = max(1, S(1))

    # Default: Caen
    zoom = 15
    cx, cy = _lat_lon_to_tile(49.1829, -0.3707, zoom)

    # Try GPS
    gps_lat, gps_lon = _get_gps()
    if gps_lat:
        cx, cy = _lat_lon_to_tile(gps_lat, gps_lon, zoom)

    # Cache stats
    n_tiles, cache_size, zoom_counts = _get_cache_stats()
    show_info = True
    info_timer = time.time()

    try:
        while True:
            btn = _btn()
            if btn == "KEY3":
                break

            pan_speed = 0.3 / (2 ** (zoom - 13))
            if btn == "UP":
                cy -= pan_speed
            elif btn == "DOWN":
                cy += pan_speed
            elif btn == "LEFT":
                cx -= pan_speed
            elif btn == "RIGHT":
                cx += pan_speed
            elif btn == "KEY1":
                if zoom < 17:
                    lat, lon = _tile_to_lat_lon(cx, cy, zoom)
                    zoom += 1
                    cx, cy = _lat_lon_to_tile(lat, lon, zoom)
            elif btn == "KEY2":
                if zoom > 10:
                    lat, lon = _tile_to_lat_lon(cx, cy, zoom)
                    zoom -= 1
                    cx, cy = _lat_lon_to_tile(lat, lon, zoom)
            elif btn == "OK":
                gps_lat, gps_lon = _get_gps()
                if gps_lat:
                    cx, cy = _lat_lon_to_tile(gps_lat, gps_lon, zoom)
                    show_info = True
                    info_timer = time.time()

            if btn:
                show_info = True
                info_timer = time.time()

            # Render map
            map_img, loaded, missing = _render_map(cx, cy, zoom, rw, rh)
            draw = ImageDraw.Draw(map_img)

            # Current position (center crosshair)
            mid_x, mid_y = rw // 2, rh // 2
            draw.line([(mid_x - 6, mid_y), (mid_x + 6, mid_y)], fill=(255, 255, 255), width=1)
            draw.line([(mid_x, mid_y - 6), (mid_x, mid_y + 6)], fill=(255, 255, 255), width=1)

            # GPS marker
            if gps_lat:
                gx, gy = _lat_lon_to_tile(gps_lat, gps_lon, zoom)
                # Convert to pixel offset from center
                px = mid_x + int((gx - cx) * TILE_SIZE)
                py = mid_y + int((gy - cy) * TILE_SIZE)
                if 0 <= px < rw and 0 <= py < rh:
                    draw.ellipse([px - 4, py - 4, px + 4, py + 4], fill=(0, 255, 0), outline=(255, 255, 255))

            # Info overlay (fades after 3s)
            if show_info and time.time() - info_timer < 3:
                lat, lon = _tile_to_lat_lon(cx, cy, zoom)
                draw.rectangle([(0, 0), (rw, 16 * s)], fill=(0, 0, 0, 180))
                draw.text((3 * s, 2 * s), f"Z{zoom} {lat:.4f},{lon:.4f}", font=font_sm, fill=(0, 200, 255))
                draw.text((rw - 45 * s, 2 * s), f"{loaded}t", font=font_sm, fill=(0, 255, 0) if missing == 0 else (255, 170, 0))

                draw.rectangle([(0, rh - 14 * s), (rw, rh)], fill=(0, 0, 0, 180))
                draw.text((2 * s, rh - 12 * s), "K1:Z+ K2:Z- OK:GPS ^v<>:Pan", font=font_sm, fill=(100, 100, 100))
            elif show_info:
                show_info = False

            # Missing tiles indicator
            if missing > 0 and loaded == 0:
                draw.text((rw // 2 - 30 * s, rh // 2 - 5 * s), "No tiles here", font=font_sm, fill=(255, 100, 100))
                draw.text((rw // 2 - 35 * s, rh // 2 + 8 * s), "Use Map Downloader", font=font_sm, fill=(150, 150, 150))

            lcd.LCD_ShowImage(map_img, 0, 0)
            time.sleep(0.05)

    finally:
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
