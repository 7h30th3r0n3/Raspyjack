#!/usr/bin/env python3
"""
RaspyJack Payload -- Apple WiFi Geolocation
=============================================
Geolocate without GPS using Apple's WiFi positioning database.

Scans nearby WiFi APs, queries Apple's gs-loc.apple.com endpoint,
triangulates position via RSSI-weighted average, and displays
on a live map with OSM tiles.

Controls:
  OK    -- Rescan + relocate
  KEY1  -- Toggle map/detail view
  KEY3  -- Exit
"""

import os
import sys
import time
import struct
import math
import threading
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont, ImageEnhance
from payloads._display_helper import ScaledDraw, scaled_font, S
from payloads._input_helper import get_button

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
LCD.LCD_Clear()
WIDTH, HEIGHT = LCD.width, LCD.height
font = scaled_font(9)
font_sm = scaled_font(8)
font_bold = scaled_font(10)

TILE_CACHE = "/root/Raspyjack/loot/wardriving/.tilecache"
TILE_URL = "https://tile.openstreetmap.org/{z}/{x}/{y}.png"
APPLE_URL = "https://gs-loc.apple.com/clls/wloc"
APPLE_UA = "locationd/1753.17 CFNetwork/711.1.12 Darwin/14.0.0"


# ---------------------------------------------------------------------------
# Protobuf encoding (manual, no protoc needed)
# ---------------------------------------------------------------------------

def _pb_varint(value):
    out = []
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value & 0x7F)
    return bytes(out)


def _pb_signed_varint(value):
    if value < 0:
        value += (1 << 64)
    return _pb_varint(value)


def _pb_field(field_num, wire_type, data):
    tag = _pb_varint((field_num << 3) | wire_type)
    return tag + data


def _pb_string(field_num, s):
    encoded = s.encode("utf-8") if isinstance(s, str) else s
    return _pb_field(field_num, 2, _pb_varint(len(encoded)) + encoded)


def _pb_int32(field_num, value):
    return _pb_field(field_num, 0, _pb_varint(value))


def _encode_apple_request(bssids):
    devices = b""
    for bssid in bssids:
        device = _pb_string(1, bssid)
        devices += _pb_field(2, 2, _pb_varint(len(device)) + device)
    devices += _pb_int32(5, 0)
    return devices


def _decode_varint(data, pos):
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def _decode_signed_int64(value):
    if value >= (1 << 63):
        value -= (1 << 64)
    return value


def _parse_apple_response(data):
    results = []
    pos = 0
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07

        if wire_type == 0:
            _, pos = _decode_varint(data, pos)
        elif wire_type == 2:
            length, pos = _decode_varint(data, pos)
            chunk = data[pos:pos + length]
            pos += length
            if field_num == 2:
                ap = _parse_wifi_device(chunk)
                if ap:
                    results.append(ap)
        elif wire_type == 5:
            pos += 4
        elif wire_type == 1:
            pos += 8
    return results


def _parse_wifi_device(data):
    bssid = None
    lat = lon = None
    accuracy = 0
    pos = 0
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07

        if wire_type == 0:
            val, pos = _decode_varint(data, pos)
            pass
        elif wire_type == 2:
            length, pos = _decode_varint(data, pos)
            chunk = data[pos:pos + length]
            pos += length
            if field_num == 1:
                bssid = chunk.decode("utf-8", errors="ignore")
            elif field_num == 2:
                lat, lon, accuracy = _parse_location(chunk)
        elif wire_type == 5:
            pos += 4
        elif wire_type == 1:
            pos += 8

    if bssid and lat is not None and lon is not None:
        lat_f = _decode_signed_int64(lat) / 1e8
        lon_f = _decode_signed_int64(lon) / 1e8
        if lat_f < -90 or lat_f > 90 or lon_f < -180 or lon_f > 180:
            return None
        return {"bssid": bssid, "lat": lat_f, "lon": lon_f, "accuracy": accuracy}
    return None


def _parse_location(data):
    lat = lon = None
    accuracy = 0
    pos = 0
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:
            val, pos = _decode_varint(data, pos)
            if field_num == 1:
                lat = val
            elif field_num == 2:
                lon = val
            elif field_num == 3:
                accuracy = val
        elif wire_type == 2:
            length, pos = _decode_varint(data, pos)
            pos += length
        elif wire_type == 5:
            pos += 4
        elif wire_type == 1:
            pos += 8
    return lat, lon, accuracy


# ---------------------------------------------------------------------------
# WiFi scanning
# ---------------------------------------------------------------------------

def _scan_wifi():
    ifaces = []
    try:
        out = subprocess.check_output(["iw", "dev"], text=True, timeout=5)
        for line in out.splitlines():
            if "Interface" in line:
                ifaces.append(line.strip().split()[-1])
    except Exception:
        pass

    if not ifaces:
        return []

    iface = ifaces[0]
    for i in ifaces:
        if "wlan0" in i:
            iface = i
            break

    try:
        subprocess.run(["ip", "link", "set", iface, "up"],
                       capture_output=True, timeout=5)
    except Exception:
        pass

    aps = []
    try:
        out = subprocess.check_output(
            ["iw", "dev", iface, "scan", "-u"],
            text=True, timeout=15, stderr=subprocess.DEVNULL,
        )
        bssid = ssid = None
        signal = -100
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("BSS "):
                if bssid:
                    aps.append({"bssid": bssid, "ssid": ssid or "", "signal": signal})
                bssid = line.split()[1].split("(")[0].lower()
                ssid = None
                signal = -100
            elif line.startswith("SSID:"):
                ssid = line[5:].strip()
            elif line.startswith("signal:"):
                try:
                    signal = float(line.split(":")[1].strip().split()[0])
                except (ValueError, IndexError):
                    pass
        if bssid:
            aps.append({"bssid": bssid, "ssid": ssid or "", "signal": signal})
    except Exception:
        pass

    aps.sort(key=lambda a: a["signal"], reverse=True)
    return aps


# ---------------------------------------------------------------------------
# Apple geolocation query
# ---------------------------------------------------------------------------

def _query_apple(bssids):
    if not REQUESTS_OK or not bssids:
        return []

    payload = _encode_apple_request(bssids)

    header = (
        b"\x00\x01\x00\x05" + b"en_US"
        + b"\x00\x13" + b"com.apple.locationd"
        + b"\x00\x0c" + b"17.4.1.21G101"
        + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00"
        + b"\x00\x00\x00\x01\x00\x00\x00"
        + struct.pack(">H", len(payload))
    )
    body = header + payload

    try:
        r = requests.post(
            APPLE_URL,
            headers={
                "User-Agent": APPLE_UA,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data=body,
            timeout=10,
        )
        if r.status_code != 200:
            return []
        return _parse_apple_response(r.content[10:])
    except Exception:
        return []


def _triangulate(scanned_aps, apple_results):
    apple_map = {r["bssid"].lower(): r for r in apple_results}

    points = []
    for ap in scanned_aps:
        bssid = ap["bssid"].lower()
        if bssid in apple_map:
            r = apple_map[bssid]
            weight = 10 ** (ap["signal"] / 10.0)
            points.append((r["lat"], r["lon"], weight, ap))

    if not points:
        return None

    total_w = sum(w for _, _, w, _ in points)
    lat = sum(la * w for la, _, w, _ in points) / total_w
    lon = sum(lo * w for _, lo, w, _ in points) / total_w

    return {
        "lat": lat,
        "lon": lon,
        "points": len(points),
        "total_scanned": len(scanned_aps),
        "total_apple": len(apple_results),
        "details": points,
    }


# ---------------------------------------------------------------------------
# Map tiles (reuses wardriving tile cache)
# ---------------------------------------------------------------------------

def _fetch_tile(z, x, y):
    os.makedirs(TILE_CACHE, exist_ok=True)
    cache_path = os.path.join(TILE_CACHE, f"{z}_{x}_{y}.png")
    if os.path.isfile(cache_path):
        try:
            return Image.open(cache_path).convert("RGB")
        except Exception:
            pass
    if not REQUESTS_OK:
        return None
    try:
        url = TILE_URL.format(z=z, x=x, y=y)
        r = requests.get(url, headers={"User-Agent": "RaspyJack/1.0"}, timeout=6)
        if r.status_code == 200:
            with open(cache_path, "wb") as f:
                f.write(r.content)
            from io import BytesIO
            return Image.open(BytesIO(r.content)).convert("RGB")
    except Exception:
        pass
    return None


def _build_map(lat, lon, width, height, zoom=16):
    n = 2 ** zoom
    x_center = int((lon + 180.0) / 360.0 * n)
    lat_rad = math.radians(max(-85, min(85, lat)))
    y_center = int((1.0 - math.log(math.tan(lat_rad) + 1.0 / math.cos(lat_rad)) / math.pi) / 2.0 * n)

    big = Image.new("RGB", (3 * 256, 3 * 256), (10, 14, 20))
    for dx in range(-1, 2):
        for dy in range(-1, 2):
            tile = _fetch_tile(zoom, x_center + dx, y_center + dy)
            if tile:
                big.paste(tile, ((dx + 1) * 256, (dy + 1) * 256))

    nw_lon = (x_center - 1) / n * 360.0 - 180.0
    se_lon = (x_center + 2) / n * 360.0 - 180.0
    nw_lat = math.degrees(math.atan(math.sinh(math.pi * (1 - 2 * (y_center - 1) / n))))
    se_lat = math.degrees(math.atan(math.sinh(math.pi * (1 - 2 * (y_center + 2) / n))))

    darkened = ImageEnhance.Brightness(big).enhance(0.5)
    resized = darkened.resize((width, height), Image.LANCZOS)

    def _lat_to_merc(la):
        la = max(-85.0, min(85.0, la))
        return math.log(math.tan(math.pi / 4 + math.radians(la) / 2))

    bbox = (_lat_to_merc(nw_lat), _lat_to_merc(se_lat), nw_lon, se_lon)
    return resized, bbox


def _project(lat, lon, bbox, width, height):
    nw_merc, se_merc, nw_lon, se_lon = bbox

    def _lat_to_merc(la):
        la = max(-85.0, min(85.0, la))
        return math.log(math.tan(math.pi / 4 + math.radians(la) / 2))

    merc_span = nw_merc - se_merc
    lon_span = se_lon - nw_lon
    if merc_span == 0 or lon_span == 0:
        return width // 2, height // 2
    merc = _lat_to_merc(lat)
    x = int((lon - nw_lon) / lon_span * width)
    y = int((nw_merc - merc) / merc_span * height)
    return x, y


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_status(text, sub=""):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "APPLE LOCATE", font=font_bold, fill="#00CCFF")
    d.text((10, 50), text, font=font, fill="#FFAA00")
    if sub:
        d.text((10, 65), sub, font=font_sm, fill="#666")
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "K3:Exit", font=font_sm, fill="#888")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_map_view(result):
    lat, lon = result["lat"], result["lon"]
    try:
        bg, bbox = _build_map(lat, lon, WIDTH, HEIGHT)
    except Exception:
        bg = Image.new("RGB", (WIDTH, HEIGHT), "#0a0e14")
        bbox = None

    img = bg.copy() if bg else Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)

    if bbox and result.get("details"):
        for la, lo, w, ap in result["details"]:
            px, py = _project(la, lo, bbox, WIDTH, HEIGHT)
            if 0 <= px < WIDTH and 0 <= py < HEIGHT:
                d.ellipse([px - 2, py - 2, px + 2, py + 2], fill="#00CCFF")

    if bbox:
        cx, cy = _project(lat, lon, bbox, WIDTH, HEIGHT)
        d.line([(cx - 6, cy), (cx + 6, cy)], fill="#FF0000", width=2)
        d.line([(cx, cy - 6), (cx, cy + 6)], fill="#FF0000", width=2)
        d.ellipse([cx - 4, cy - 4, cx + 4, cy + 4], outline="#FF0000", width=1)

    s = S(1)
    d.rectangle([(0, 0), (WIDTH, 12 * s)], fill=(0, 0, 0, 200))
    d.text((2 * s, 1 * s), "APPLE LOCATE", font=font_sm, fill="#00CCFF")
    pts = result["points"]
    d.text((80 * s, 1 * s), f"{pts}AP", font=font_sm, fill="#00FF00")

    d.rectangle([(0, 116 * s), (WIDTH, HEIGHT)], fill=(0, 0, 0, 200))
    d.text((2 * s, 117 * s), f"{lat:.5f},{lon:.5f}", font=font_sm, fill="#FFFFFF")

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_detail_view(result, scanned_aps):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "APPLE LOCATE", font=font_bold, fill="#00CCFF")

    y = 15
    d.text((2, y), f"Lat: {result['lat']:.6f}", font=font, fill="#FFFFFF")
    y += 12
    d.text((2, y), f"Lon: {result['lon']:.6f}", font=font, fill="#FFFFFF")
    y += 14

    d.text((2, y), f"Scanned: {result['total_scanned']}", font=font_sm, fill="#888")
    y += 10
    d.text((2, y), f"Apple DB: {result['total_apple']}", font=font_sm, fill="#888")
    y += 10
    d.text((2, y), f"Matched: {result['points']}", font=font_sm, fill="#00FF00")
    y += 14

    if result.get("details"):
        d.text((2, y), "Top APs:", font=font_sm, fill="#FFAA00")
        y += 10
        for la, lo, w, ap in result["details"][:3]:
            ssid = (ap.get("ssid") or ap["bssid"])[:14]
            sig = int(ap["signal"])
            d.text((4, y), f"{ssid} {sig}dBm", font=font_sm, fill="#00CCFF")
            y += 10

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Scan K1:Map K3:X", font=font_sm, fill="#888")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_no_result(reason):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "APPLE LOCATE", font=font_bold, fill="#00CCFF")
    d.text((10, 45), reason, font=font, fill="#FF4444")
    d.text((10, 60), "Press OK to retry", font=font_sm, fill="#666")
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Scan K3:Exit", font=font_sm, fill="#888")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if not REQUESTS_OK:
        _draw_status("pip install requests")
        time.sleep(3)
        GPIO.cleanup()
        return 1

    view = 0  # 0=detail, 1=map
    result = None
    scanned = []

    def do_scan():
        nonlocal result, scanned
        _draw_status("Scanning WiFi...", "iw scan")

        scanned = _scan_wifi()
        if not scanned:
            _draw_no_result("No WiFi found")
            return

        top = scanned[:10]
        bssids = [ap["bssid"] for ap in top]

        _draw_status("Querying Apple...", f"{len(bssids)} BSSIDs")

        apple_data = _query_apple(bssids)
        if not apple_data:
            _draw_no_result("Apple API failed")
            return

        _draw_status("Triangulating...", f"{len(apple_data)} results")
        result = _triangulate(top, apple_data)

        if not result:
            _draw_no_result("No match in DB")
            return

        if view == 0:
            _draw_detail_view(result, scanned)
        else:
            _draw_map_view(result)

    do_scan()

    debounce = 0.25
    last_press = 0.0

    while True:
        btn = get_button(PINS, GPIO)
        now = time.time()

        if btn and (now - last_press) >= debounce:
            last_press = now

            if btn == "KEY3":
                break

            if btn == "OK":
                do_scan()

            if btn == "KEY1":
                view = 1 - view
                if result:
                    if view == 0:
                        _draw_detail_view(result, scanned)
                    else:
                        _draw_map_view(result)

        time.sleep(0.05)

    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
