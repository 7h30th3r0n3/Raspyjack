#!/usr/bin/env python3
"""
RaspyJack Payload -- GNSS Satellite Tracker Pro
=================================================
Author: 7h30th3r0n3

Professional GNSS tracker with 5 views on 1.44" LCD:
  1. Skyplot   — polar view of all visible satellites
  2. Signals   — signal strength bars sorted by SNR
  3. Position  — coordinates, altitude, speed, heading
  4. Stats     — per-constellation breakdown, DOP values
  5. Compass   — heading display with satellite count ring

Reads from gpsd via gpspipe. Writes live JSON for WebUI.

Controls:
  OK        : Cycle view
  KEY1      : Cycle constellation filter
  UP/DOWN   : Scroll (in stats/signal views)
  KEY3      : Exit
"""

import os
import sys
import math
import time
import json
import signal
import threading
import subprocess
from datetime import datetime
from collections import deque

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
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
font_xl = scaled_font(16)

LIVE_PATH = "/dev/shm/rj_gnss_live.json"
DEBOUNCE = 0.18
_last_btn = 0
_running = True

CONSTELLATIONS = {
    "GP": {"name": "GPS", "color": (0, 200, 255), "short": "G"},
    "GL": {"name": "GLONASS", "color": (255, 100, 0), "short": "R"},
    "GA": {"name": "Galileo", "color": (0, 255, 100), "short": "E"},
    "BD": {"name": "BeiDou", "color": (255, 200, 0), "short": "C"},
    "GN": {"name": "Multi", "color": (200, 200, 200), "short": "X"},
}
FILTERS = ["All", "GPS", "GLO", "GAL", "BDS"]
FILT_MAP = {"GPS": "GP", "GLO": "GL", "GAL": "GA", "BDS": "BD"}
VIEWS = ["Skyplot", "Signals", "Position", "Stats", "Compass"]

SAT_ALTITUDES = {"GP": 20180, "GL": 19130, "GA": 23222, "BD": 21528}

SAT_DB = {
    "GP": {
        1: "USA-232 IIR-M", 2: "USA-180 IIR", 3: "USA-258 IIF",
        5: "USA-206 IIF", 6: "USA-251 IIF", 7: "USA-201 IIR-M",
        8: "USA-262 IIF", 9: "USA-256 IIF", 10: "USA-265 IIF",
        11: "USA-145 IIR", 12: "USA-192 IIR-M", 13: "USA-132 IIR",
        14: "USA-154 IIR", 15: "USA-196 IIR-M", 16: "USA-166 IIR",
        17: "USA-183 IIR-M", 18: "USA-309 III", 19: "USA-177 IIR",
        20: "USA-150 IIR", 21: "USA-168 IIR", 22: "USA-175 IIR",
        23: "USA-304 III", 24: "USA-239 IIF", 25: "USA-213 IIF",
        26: "USA-260 IIF", 27: "USA-242 IIF", 28: "USA-151 IIR",
        29: "USA-199 IIR-M", 30: "USA-248 IIF", 31: "USA-190 IIR-M",
        32: "USA-266 IIF",
    },
}


def _sat_ground_pos(obs_lat, obs_lon, elev, azim, alt_km):
    Re = 6371
    el = math.radians(max(1, elev))
    az = math.radians(azim)
    lat1 = math.radians(obs_lat)
    lon1 = math.radians(obs_lon)
    gamma = math.acos(Re * math.cos(el) / (Re + alt_km)) - el
    lat2 = math.asin(math.sin(lat1) * math.cos(gamma) + math.cos(lat1) * math.sin(gamma) * math.cos(az))
    lon2 = lon1 + math.atan2(math.sin(az) * math.sin(gamma) * math.cos(lat1),
                              math.cos(gamma) - math.sin(lat1) * math.sin(lat2))
    return round(math.degrees(lat2), 4), round(math.degrees(lon2), 4)


_position_history = deque(maxlen=200)
_track_distance = 0.0
_max_speed = 0.0
_max_alt = -9999
_min_alt = 9999
_session_start = time.time()


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


def _parse_gsv(satellites, line):
    parts = line.split(",")
    if len(parts) < 4:
        return
    talker = parts[0][1:3]
    i = 4
    while i + 3 < len(parts):
        try:
            prn = int(parts[i]) if parts[i] else 0
            elev = int(parts[i + 1]) if parts[i + 1] else 0
            azim = int(parts[i + 2]) if parts[i + 2] else 0
            snr_str = parts[i + 3].split("*")[0] if i + 3 < len(parts) else ""
            snr = int(snr_str) if snr_str else 0
        except (ValueError, IndexError):
            i += 4
            continue
        if prn > 0:
            satellites[f"{talker}{prn}"] = {
                "prn": prn, "elev": elev, "azim": azim, "snr": snr,
                "constellation": talker, "ts": time.time(),
            }
        i += 4


def _parse_gga(fix_data, line):
    parts = line.split(",")
    if len(parts) < 10:
        return
    try:
        fix_data["fix_quality"] = int(parts[6]) if parts[6] else 0
        fix_data["num_sats"] = int(parts[7]) if parts[7] else 0
        fix_data["hdop"] = float(parts[8]) if parts[8] else 0
        fix_data["alt"] = float(parts[9]) if parts[9] else 0
        if len(parts) > 11 and parts[11]:
            fix_data["geoid_sep"] = float(parts[11])
        if parts[2] and parts[4]:
            lat = float(parts[2][:2]) + float(parts[2][2:]) / 60
            if parts[3] == "S":
                lat = -lat
            lon = float(parts[4][:3]) + float(parts[4][3:]) / 60
            if parts[5] == "W":
                lon = -lon
            fix_data["lat"] = round(lat, 6)
            fix_data["lon"] = round(lon, 6)
    except (ValueError, IndexError):
        pass


def _parse_rmc(fix_data, line):
    parts = line.split(",")
    if len(parts) < 9:
        return
    try:
        fix_data["valid"] = parts[2] == "A"
        if parts[7]:
            fix_data["speed_knots"] = float(parts[7])
            fix_data["speed_kmh"] = round(float(parts[7]) * 1.852, 1)
        if parts[8]:
            fix_data["heading"] = float(parts[8])
    except (ValueError, IndexError):
        pass


def _parse_gsa(fix_data, line):
    parts = line.split(",")
    if len(parts) < 17:
        return
    try:
        fix_data["fix_mode"] = int(parts[2]) if parts[2] else 1
        pdop_str = parts[15].split("*")[0] if len(parts) > 15 else ""
        if pdop_str:
            fix_data["pdop"] = float(pdop_str)
        if parts[16]:
            vdop_str = parts[16].split("*")[0]
            fix_data["vdop"] = float(vdop_str) if vdop_str else 0
        active = []
        for i in range(3, 15):
            if i < len(parts) and parts[i]:
                try:
                    active.append(int(parts[i]))
                except ValueError:
                    pass
        if active:
            prev = fix_data.get("active_sats", [])
            fix_data["active_sats"] = list(set(prev + active))
    except (ValueError, IndexError):
        pass


def _parse_vtg(fix_data, line):
    parts = line.split(",")
    if len(parts) < 8:
        return
    try:
        if parts[1]:
            fix_data["heading_true"] = float(parts[1])
        if parts[3]:
            fix_data["heading_mag"] = float(parts[3])
        if parts[7]:
            fix_data["speed_kmh"] = float(parts[7].split("*")[0])
    except (ValueError, IndexError):
        pass


def _parse_zda(fix_data, line):
    parts = line.split(",")
    if len(parts) < 5:
        return
    try:
        t = parts[1]
        if t and len(t) >= 6:
            fix_data["utc_time"] = f"{t[:2]}:{t[2:4]}:{t[4:6]}"
        if parts[2] and parts[3] and parts[4]:
            fix_data["utc_date"] = f"{parts[4]}-{parts[3]}-{parts[2]}"
    except (ValueError, IndexError):
        pass


def _parse_txt(fix_data, line):
    parts = line.split(",")
    if len(parts) >= 5:
        msg = parts[4].split("*")[0] if parts[4] else ""
        fix_data["antenna_status"] = msg


def _gnss_reader(satellites, fix_data):
    global _max_speed, _max_alt, _min_alt, _track_distance
    try:
        proc = subprocess.Popen(
            ["gpspipe", "-r"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1,
        )
        last_pos = None
        while _running:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            fix_data["active_sats"] = []
            if "GSV" in line:
                _parse_gsv(satellites, line)
            elif "GGA" in line:
                _parse_gga(fix_data, line)
            elif "RMC" in line:
                _parse_rmc(fix_data, line)
            elif "GSA" in line:
                _parse_gsa(fix_data, line)
            elif "VTG" in line:
                _parse_vtg(fix_data, line)
            elif "ZDA" in line:
                _parse_zda(fix_data, line)
            elif "TXT" in line:
                _parse_txt(fix_data, line)

            if fix_data.get("lat") and fix_data.get("valid"):
                spd = fix_data.get("speed_kmh", 0)
                alt = fix_data.get("alt", 0)
                if spd > _max_speed:
                    _max_speed = spd
                if alt > _max_alt:
                    _max_alt = alt
                if alt < _min_alt:
                    _min_alt = alt

                pos = (fix_data["lat"], fix_data["lon"])
                if last_pos and last_pos != pos:
                    d = _haversine(last_pos[0], last_pos[1], pos[0], pos[1])
                    if d > 0.001:
                        _track_distance += d
                        _position_history.append({
                            "lat": pos[0], "lon": pos[1],
                            "alt": alt, "speed": spd,
                            "ts": time.time(),
                        })
                last_pos = pos

        proc.terminate()
    except Exception:
        pass


def _haversine(lat1, lon1, lat2, lon2):
    R = 6371
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _write_live(satellites, fix_data):
    while _running:
        try:
            now = time.time()
            active = {k: v for k, v in satellites.items() if now - v["ts"] < 30}
            obs_lat = fix_data.get("lat")
            obs_lon = fix_data.get("lon")
            enriched = []
            for s in active.values():
                entry = dict(s)
                c = s["constellation"]
                entry["altitude_km"] = SAT_ALTITUDES.get(c, 20000)
                db = SAT_DB.get(c, {})
                entry["name"] = db.get(s["prn"], "")
                entry["used_in_fix"] = s["prn"] in fix_data.get("active_sats", [])
                if obs_lat and obs_lon and s["elev"] > 0:
                    glat, glon = _sat_ground_pos(obs_lat, obs_lon, s["elev"], s["azim"], entry["altitude_km"])
                    entry["ground_lat"] = glat
                    entry["ground_lon"] = glon
                enriched.append(entry)
            payload = {
                "ts": now,
                "satellites": enriched,
                "total": len(active),
                "fix": dict(fix_data),
                "by_constellation": {},
                "track_distance_km": round(_track_distance, 3),
                "max_speed_kmh": round(_max_speed, 1),
                "max_alt": round(_max_alt, 1) if _max_alt > -9000 else 0,
                "session_duration": int(now - _session_start),
                "position_history": list(_position_history)[-50:],
                "utc_time": fix_data.get("utc_time", ""),
                "utc_date": fix_data.get("utc_date", ""),
                "antenna_status": fix_data.get("antenna_status", ""),
                "active_sats": fix_data.get("active_sats", []),
                "heading_true": fix_data.get("heading_true", 0),
                "heading_mag": fix_data.get("heading_mag", 0),
            }
            for key, info in CONSTELLATIONS.items():
                if key == "GN":
                    continue
                sats = [s for s in active.values() if s["constellation"] == key]
                payload["by_constellation"][info["name"]] = {
                    "count": len(sats),
                    "tracked": len([s for s in sats if s["snr"] > 0]),
                    "avg_snr": round(sum(s["snr"] for s in sats if s["snr"] > 0) / max(1, len([s for s in sats if s["snr"] > 0])), 1),
                }
            tmp = LIVE_PATH + ".tmp"
            with open(tmp, "w") as f:
                json.dump(payload, f)
            os.replace(tmp, LIVE_PATH)
        except Exception:
            pass
        time.sleep(1.5)


def _polar_xy(cx, cy, radius, elev, azim):
    r = radius * (90 - elev) / 90
    angle = math.radians(azim - 90)
    return int(cx + r * math.cos(angle)), int(cy + r * math.sin(angle))


def _filter_sats(satellites, filt_idx):
    now = time.time()
    active = {k: v for k, v in satellites.items() if now - v["ts"] < 30}
    if FILTERS[filt_idx] == "All":
        return active
    target = FILT_MAP.get(FILTERS[filt_idx], "")
    return {k: v for k, v in active.items() if v["constellation"] == target}


def _draw_skyplot(satellites, fix_data, filt_idx):
    img = Image.new("RGB", (W, H), (5, 8, 15))
    draw = ImageDraw.Draw(img)

    cx, cy = W // 2, H // 2 + SY(2)
    R = min(W, H) // 2 - SY(14)

    for ring in [1.0, 0.66, 0.33]:
        r = int(R * ring)
        draw.ellipse([cx - r, cy - r, cx + r, cy + r], outline=(20, 30, 45))
    draw.line([(cx - R, cy), (cx + R, cy)], fill=(15, 25, 38))
    draw.line([(cx, cy - R), (cx, cy + R)], fill=(15, 25, 38))

    for lbl, angle in [("N", -90), ("E", 0), ("S", 90), ("W", 180)]:
        ax = cx + int((R + SX(6)) * math.cos(math.radians(angle)))
        ay = cy + int((R + SY(6)) * math.sin(math.radians(angle)))
        col = (255, 80, 80) if lbl == "N" else (60, 70, 90)
        draw.text((ax, ay), lbl, font=font_xs, fill=col, anchor="mm")

    visible = _filter_sats(satellites, filt_idx)
    tracked = 0
    for key, sat in visible.items():
        info = CONSTELLATIONS.get(sat["constellation"], CONSTELLATIONS["GN"])
        sx, sy = _polar_xy(cx, cy, R, sat["elev"], sat["azim"])
        col = info["color"]
        if sat["snr"] > 0:
            tracked += 1
            brightness = min(255, 100 + sat["snr"] * 3)
            col = tuple(min(255, c * brightness // 200) for c in col)
            sz = max(SX(3), min(SX(6), SX(2) + sat["snr"] // 10))
            draw.ellipse([sx - sz, sy - sz, sx + sz, sy + sz], fill=col)
        else:
            sz = SX(2)
            draw.ellipse([sx - sz, sy - sz, sx + sz, sy + sz], outline=col)
        draw.text((sx + SX(4), sy - SY(2)), str(sat["prn"]), font=font_xs, fill=col)

    # Header
    draw.rectangle([(0, 0), (W, SY(10))], fill=(10, 15, 25))
    fix_q = fix_data.get("fix_quality", 0)
    draw.ellipse([SX(2), SY(2), SX(8), SY(8)], fill=(0, 255, 0) if fix_q else (255, 50, 50))
    draw.text((SX(10), SY(1)), f"{tracked}/{len(visible)}", font=font_xs, fill=(0, 200, 255))
    draw.text((SX(40), SY(1)), f"HDOP:{fix_data.get('hdop', 0):.1f}", font=font_xs, fill=(100, 120, 150))
    draw.text((W - SX(2), SY(1)), FILTERS[filt_idx], font=font_xs, fill=(255, 200, 0), anchor="ra")

    # Footer
    draw.rectangle([(0, H - SY(10)), (W, H)], fill=(10, 15, 25))
    draw.text((SX(2), H - SY(9)), "OK:View K1:Filt K3:Exit", font=font_xs, fill=(40, 50, 65))
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_signals(satellites, fix_data, filt_idx, scroll):
    img = Image.new("RGB", (W, H), (5, 8, 15))
    draw = ImageDraw.Draw(img)

    draw.rectangle([(0, 0), (W, SY(12))], fill=(10, 15, 25))
    draw.text((SX(2), SY(2)), "SIGNAL STRENGTH", font=font_sm, fill=(0, 200, 255))
    draw.text((W - SX(2), SY(2)), FILTERS[filt_idx], font=font_xs, fill=(255, 200, 0), anchor="ra")

    visible = _filter_sats(satellites, filt_idx)
    sats = sorted(visible.values(), key=lambda s: -s["snr"])

    bar_y = SY(14)
    bar_h = H - SY(26)
    max_snr = 50
    n = len(sats)
    if n == 0:
        draw.text((W // 2, H // 2), "No satellites", font=font, fill=(40, 50, 65), anchor="mm")
    else:
        bar_w = max(SX(4), min(SX(12), (W - SX(4)) // n))
        start_x = (W - n * bar_w) // 2
        for i, sat in enumerate(sats):
            info = CONSTELLATIONS.get(sat["constellation"], CONSTELLATIONS["GN"])
            x = start_x + i * bar_w
            h = int(bar_h * min(sat["snr"], max_snr) / max_snr) if sat["snr"] > 0 else SY(1)
            col = info["color"] if sat["snr"] > 0 else (20, 30, 40)
            draw.rectangle([(x, bar_y + bar_h - h), (x + bar_w - 2, bar_y + bar_h)], fill=col)
            if bar_w >= SX(8):
                draw.text((x + bar_w // 2, bar_y + bar_h + SY(2)), str(sat["prn"]),
                          font=font_xs, fill=info["color"], anchor="ma")
                if sat["snr"] > 0:
                    draw.text((x + bar_w // 2, bar_y + bar_h - h - SY(7)),
                              str(sat["snr"]), font=font_xs, fill=col, anchor="ma")

    draw.rectangle([(0, H - SY(10)), (W, H)], fill=(10, 15, 25))
    draw.text((SX(2), H - SY(9)), "OK:View K1:Filt K3:Exit", font=font_xs, fill=(40, 50, 65))
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_position(satellites, fix_data, filt_idx):
    img = Image.new("RGB", (W, H), (5, 8, 15))
    draw = ImageDraw.Draw(img)

    draw.rectangle([(0, 0), (W, SY(14))], fill=(10, 15, 25))
    fix_q = fix_data.get("fix_quality", 0)
    fix_mode = fix_data.get("fix_mode", 1)
    fix_label = ["No fix", "No fix", "2D", "3D"][min(fix_mode, 3)]
    fix_col = (0, 255, 0) if fix_q else (255, 50, 50)
    draw.text((SX(2), SY(2)), f"FIX: {fix_label}", font=font, fill=fix_col)
    draw.text((W - SX(2), SY(3)), f"{fix_data.get('num_sats', 0)} sats", font=font_sm, fill=(0, 200, 255), anchor="ra")

    y = SY(18)
    items = [
        ("LAT", f"{fix_data.get('lat', 0):.6f}°" if fix_data.get("lat") else "---", (0, 200, 255)),
        ("LON", f"{fix_data.get('lon', 0):.6f}°" if fix_data.get("lon") else "---", (0, 200, 255)),
        ("ALT", f"{fix_data.get('alt', 0):.1f} m", (255, 200, 0)),
        ("SPEED", f"{fix_data.get('speed_kmh', 0):.1f} km/h", (0, 255, 100)),
        ("HEAD", f"{fix_data.get('heading', 0):.0f}°" if fix_data.get("heading") else "---", (255, 100, 0)),
        ("HDOP", f"{fix_data.get('hdop', 0):.1f}", (150, 150, 170)),
        ("PDOP", f"{fix_data.get('pdop', 0):.1f}" if fix_data.get("pdop") else "---", (150, 150, 170)),
        ("DIST", f"{_track_distance:.2f} km", (200, 100, 255)),
        ("MAX V", f"{_max_speed:.1f} km/h", (255, 150, 0)),
        ("TIME", f"{int(time.time() - _session_start) // 60}m{int(time.time() - _session_start) % 60:02d}s", (100, 150, 200)),
    ]
    for label, value, col in items:
        draw.text((SX(4), y), label, font=font_xs, fill=(60, 70, 90))
        draw.text((SX(38), y), value, font=font_sm, fill=col)
        y += SY(10)

    draw.rectangle([(0, H - SY(10)), (W, H)], fill=(10, 15, 25))
    draw.text((SX(2), H - SY(9)), "OK:View K3:Exit", font=font_xs, fill=(40, 50, 65))
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_stats(satellites, fix_data, filt_idx):
    img = Image.new("RGB", (W, H), (5, 8, 15))
    draw = ImageDraw.Draw(img)

    draw.rectangle([(0, 0), (W, SY(12))], fill=(10, 15, 25))
    draw.text((SX(2), SY(2)), "CONSTELLATION STATS", font=font_sm, fill=(0, 200, 255))

    now = time.time()
    y = SY(16)
    total_vis = 0
    total_trk = 0

    for key, info in CONSTELLATIONS.items():
        if key == "GN":
            continue
        sats = [s for s in satellites.values() if s["constellation"] == key and now - s["ts"] < 30]
        tracked = [s for s in sats if s["snr"] > 0]
        avg_snr = sum(s["snr"] for s in tracked) / max(1, len(tracked))
        total_vis += len(sats)
        total_trk += len(tracked)

        draw.rectangle([(SX(3), y + SY(1)), (SX(11), y + SY(9))], fill=info["color"])
        draw.text((SX(13), y), info["name"], font=font_sm, fill=info["color"])
        draw.text((SX(55), y), f"{len(tracked)}/{len(sats)}", font=font_sm, fill=(200, 200, 200))
        # SNR bar
        bar_x = SX(80)
        bar_w = W - SX(84)
        draw.rectangle([(bar_x, y + SY(2)), (bar_x + bar_w, y + SY(8))], fill=(15, 20, 30))
        if avg_snr > 0:
            fill_w = int(bar_w * min(avg_snr, 50) / 50)
            draw.rectangle([(bar_x, y + SY(2)), (bar_x + fill_w, y + SY(8))], fill=info["color"])
            draw.text((bar_x + fill_w + SX(2), y), f"{avg_snr:.0f}", font=font_xs, fill=info["color"])
        y += SY(16)

    y += SY(4)
    draw.text((SX(4), y), f"Total: {total_trk}/{total_vis} tracked", font=font, fill=(200, 200, 200))
    y += SY(14)

    if _max_alt > -9000:
        draw.text((SX(4), y), f"Alt range: {_min_alt:.0f}m — {_max_alt:.0f}m", font=font_sm, fill=(150, 150, 170))
        y += SY(11)
    draw.text((SX(4), y), f"Track: {_track_distance:.2f} km", font=font_sm, fill=(200, 100, 255))

    draw.rectangle([(0, H - SY(10)), (W, H)], fill=(10, 15, 25))
    draw.text((SX(2), H - SY(9)), "OK:View K3:Exit", font=font_xs, fill=(40, 50, 65))
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_compass(satellites, fix_data, filt_idx):
    img = Image.new("RGB", (W, H), (5, 8, 15))
    draw = ImageDraw.Draw(img)

    cx, cy = W // 2, H // 2
    R = min(W, H) // 2 - SY(8)

    # Compass ring
    draw.ellipse([cx - R, cy - R, cx + R, cy + R], outline=(30, 45, 65))
    draw.ellipse([cx - R + SX(2), cy - R + SY(2), cx + R - SX(2), cy + R - SY(2)], outline=(20, 30, 45))

    # Cardinal directions
    heading = fix_data.get("heading", 0)
    for lbl, deg, col in [("N", 0, (255, 80, 80)), ("E", 90, (100, 120, 150)),
                           ("S", 180, (100, 120, 150)), ("W", 270, (100, 120, 150))]:
        a = math.radians(deg - heading - 90)
        ax = cx + int((R - SX(8)) * math.cos(a))
        ay = cy + int((R - SY(8)) * math.sin(a))
        draw.text((ax, ay), lbl, font=font, fill=col, anchor="mm")

    # Heading arrow
    ha = math.radians(-90)
    tip_x = cx + int((R - SX(20)) * math.cos(ha))
    tip_y = cy + int((R - SY(20)) * math.sin(ha))
    draw.line([(cx, cy), (tip_x, tip_y)], fill=(0, 255, 100), width=2)
    draw.ellipse([cx - SX(3), cy - SY(3), cx + SX(3), cy + SY(3)], fill=(0, 255, 100))

    # Heading text
    draw.text((cx, cy + SY(15)), f"{heading:.0f}°", font=font_lg, fill=(0, 255, 100), anchor="mm")

    # Speed
    spd = fix_data.get("speed_kmh", 0)
    draw.text((cx, cy - SY(15)), f"{spd:.1f}", font=font_xl, fill=(255, 255, 255), anchor="mm")
    draw.text((cx, cy - SY(5)), "km/h", font=font_xs, fill=(80, 100, 130), anchor="mm")

    # Satellite count ring dots
    now = time.time()
    active = [s for s in satellites.values() if now - s["ts"] < 30 and s["snr"] > 0]
    for i, sat in enumerate(active[:16]):
        a = math.radians(i * 360 / max(1, len(active)) - 90)
        dx = cx + int((R + SX(1)) * math.cos(a))
        dy = cy + int((R + SY(1)) * math.sin(a))
        info = CONSTELLATIONS.get(sat["constellation"], CONSTELLATIONS["GN"])
        draw.ellipse([dx - 1, dy - 1, dx + 1, dy + 1], fill=info["color"])

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_sat_cards(satellites, fix_data, filt_idx, scroll):
    img = Image.new("RGB", (W, H), (5, 8, 15))
    draw = ImageDraw.Draw(img)

    draw.rectangle([(0, 0), (W, SY(12))], fill=(10, 15, 25))
    draw.text((SX(2), SY(2)), "SATELLITE DETAIL", font=font_sm, fill=(0, 200, 255))
    draw.text((W - SX(2), SY(2)), FILTERS[filt_idx], font=font_xs, fill=(255, 200, 0), anchor="ra")

    visible = _filter_sats(satellites, filt_idx)
    sats = sorted(visible.values(), key=lambda s: -s["snr"])

    if not sats:
        draw.text((W // 2, H // 2), "No satellites", font=font, fill=(40, 50, 65), anchor="mm")
        LCD.LCD_ShowImage(img, 0, 0)
        return

    card_h = SY(28)
    y = SY(14)
    max_visible = (H - SY(24)) // card_h
    start = min(scroll, max(0, len(sats) - max_visible))

    obs_lat = fix_data.get("lat")
    obs_lon = fix_data.get("lon")

    for i in range(start, min(len(sats), start + max_visible)):
        sat = sats[i]
        info = CONSTELLATIONS.get(sat["constellation"], CONSTELLATIONS["GN"])
        col = info["color"]
        alt_km = SAT_ALTITUDES.get(sat["constellation"], 20000)

        bg = (12, 18, 28) if i % 2 == 0 else (8, 12, 20)
        draw.rectangle([(0, y), (W, y + card_h - 1)], fill=bg)

        # Constellation dot + PRN
        draw.rectangle([(SX(2), y + SY(2)), (SX(4), y + card_h - SY(2))], fill=col)
        draw.text((SX(6), y + SY(1)), f"{info['short']}{sat['prn']}", font=font_sm, fill=col)

        # Name
        name = SAT_DB.get(sat["constellation"], {}).get(sat["prn"], "")
        if name:
            draw.text((SX(30), y + SY(1)), name[:16], font=font_xs, fill=(150, 150, 170))

        # SNR bar
        snr_w = int((W - SX(30)) * min(sat["snr"], 50) / 50) if sat["snr"] > 0 else 0
        draw.rectangle([(SX(28), y + SY(10)), (SX(28) + snr_w, y + SY(14))], fill=col)
        draw.text((SX(28) + snr_w + SX(2), y + SY(9)), f"{sat['snr']}dB", font=font_xs, fill=col)

        # Elev / Azim / Alt
        draw.text((SX(6), y + SY(17)), f"El:{sat['elev']}°", font=font_xs, fill=(80, 100, 130))
        draw.text((SX(38), y + SY(17)), f"Az:{sat['azim']}°", font=font_xs, fill=(80, 100, 130))
        draw.text((SX(70), y + SY(17)), f"{alt_km//1000}k km", font=font_xs, fill=(80, 100, 130))

        # Ground position
        if obs_lat and obs_lon and sat["elev"] > 0:
            glat, glon = _sat_ground_pos(obs_lat, obs_lon, sat["elev"], sat["azim"], alt_km)
            draw.text((W - SX(2), y + SY(17)), f"{glat:.1f},{glon:.1f}", font=font_xs, fill=(60, 70, 90), anchor="ra")

        y += card_h

    # Scroll indicator
    if len(sats) > max_visible:
        draw.text((W - SX(4), H - SY(9)), f"{start + 1}-{min(start + max_visible, len(sats))}/{len(sats)}", font=font_xs, fill=(60, 70, 90), anchor="ra")

    draw.rectangle([(0, H - SY(10)), (W, H)], fill=(10, 15, 25))
    draw.text((SX(2), H - SY(9)), "UD:Scroll OK:View K1:Filt", font=font_xs, fill=(40, 50, 65))
    LCD.LCD_ShowImage(img, 0, 0)


def main():
    satellites = {}
    fix_data = {
        "fix_quality": 0, "num_sats": 0, "hdop": 0, "alt": 0,
        "lat": None, "lon": None, "speed_kmh": 0, "heading": 0,
        "pdop": 0, "vdop": 0, "fix_mode": 1,
    }

    threading.Thread(target=_gnss_reader, args=(satellites, fix_data), daemon=True).start()
    threading.Thread(target=_write_live, args=(satellites, fix_data), daemon=True).start()

    view = 0
    filt_idx = 0
    scroll = 0
    VIEWS_LIST = ["Skyplot", "Signals", "Position", "Stats", "Compass", "Detail"]
    draw_funcs = [_draw_skyplot, _draw_signals, _draw_position, _draw_stats, _draw_compass, _draw_sat_cards]

    try:
        while _running:
            if view in (1, 5):
                draw_funcs[view](satellites, fix_data, filt_idx, scroll)
            else:
                draw_funcs[view](satellites, fix_data, filt_idx)

            btn = _btn()
            if btn == "KEY3":
                break
            elif btn == "OK":
                view = (view + 1) % len(VIEWS)
                scroll = 0
            elif btn == "KEY1":
                filt_idx = (filt_idx + 1) % len(FILTERS)
            elif btn == "UP":
                scroll = max(0, scroll - 1)
            elif btn == "DOWN":
                scroll += 1
            time.sleep(0.15)
    finally:
        try:
            os.unlink(LIVE_PATH)
        except OSError:
            pass
        LCD.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
