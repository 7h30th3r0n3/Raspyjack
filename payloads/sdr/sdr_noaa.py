#!/usr/bin/env python3
"""
RaspyJack Payload -- NOAA Satellite Image Receiver
====================================================
Author: 7h30th3r0n3

Receive weather satellite images from space using RTL-SDR.
Predicts NOAA-15/18/19 passes, captures APT signal, decodes
images line-by-line in real time.

Controls:
  OK    : Start capture / Auto-capture next pass
  KEY1  : Switch view (Passes / Live / Gallery / Status)
  UP/DN : Scroll
  KEY2  : Update TLE (needs internet)
  KEY3  : Exit

Requires: rtl-sdr, python3-scipy, python3-sgp4
"""

import os
import sys
import math
import time
import json
import signal
import subprocess
import threading
from datetime import datetime, timezone, timedelta
from collections import deque

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import numpy as np
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

LIVE_PATH = "/dev/shm/rj_noaa_live.json"
LOOT_DIR = "/root/Raspyjack/loot/SDR/noaa"
TLE_PATH = os.path.join(os.path.dirname(__file__), "data", "noaa_tle.txt")
TLE_URL = "https://celestrak.org/NORAD/elements/gp.php?GROUP=noaa&FORMAT=tle"
DEBOUNCE = 0.18
_last_btn = 0
_running = True

NOAA_SATS = {
    "NOAA 15": {"freq": 137.6200, "norad": 25338},
    "NOAA 18": {"freq": 137.9125, "norad": 28654},
    "NOAA 19": {"freq": 137.1000, "norad": 33591},
}

VIEWS = ["Passes", "Live", "Gallery", "Status"]


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


OBSERVER_CONFIG = "/root/Raspyjack/config/observer.json"


def _get_observer():
    # 1. Try GNSS live
    try:
        with open("/dev/shm/rj_gnss_live.json") as f:
            d = json.load(f)
        fix = d.get("fix", {})
        if fix.get("lat") and fix.get("lon"):
            return fix["lat"], fix["lon"], fix.get("alt", 0)
    except Exception:
        pass
    # 2. Try user config file
    try:
        with open(OBSERVER_CONFIG) as f:
            cfg = json.load(f)
        if cfg.get("lat") and cfg.get("lon"):
            return cfg["lat"], cfg["lon"], cfg.get("alt", 0)
    except Exception:
        pass
    # 3. Fallback
    return 0.0, 0.0, 0


def _save_observer(lat, lon, alt=0):
    os.makedirs(os.path.dirname(OBSERVER_CONFIG), exist_ok=True)
    with open(OBSERVER_CONFIG, "w") as f:
        json.dump({"lat": lat, "lon": lon, "alt": alt}, f)


def _download_tle():
    os.makedirs(os.path.dirname(TLE_PATH), exist_ok=True)
    try:
        import urllib.request
        urllib.request.urlretrieve(TLE_URL, TLE_PATH + ".tmp")
        if os.path.getsize(TLE_PATH + ".tmp") > 100:
            os.replace(TLE_PATH + ".tmp", TLE_PATH)
            return True
    except Exception:
        pass
    return False


def _load_tle():
    sats = {}
    if not os.path.isfile(TLE_PATH):
        return sats
    try:
        from sgp4.api import Satrec, WGS72
        with open(TLE_PATH) as f:
            lines = [l.strip() for l in f if l.strip()]
        i = 0
        while i + 2 < len(lines):
            name = lines[i].upper()
            l1, l2 = lines[i + 1], lines[i + 2]
            if not l1.startswith("1") or not l2.startswith("2"):
                i += 1
                continue
            for sat_name, info in NOAA_SATS.items():
                if sat_name.upper() in name or str(info["norad"]) in l1:
                    try:
                        sat = Satrec.twoline2rv(l1, l2, WGS72)
                        sats[sat_name] = {"sat": sat, "freq": info["freq"], "l1": l1, "l2": l2}
                    except Exception:
                        pass
            i += 3
    except Exception:
        pass
    return sats


def _predict_passes(tle_sats, obs_lat, obs_lon, obs_alt, hours=24):
    from sgp4.api import jday
    passes = []
    now = datetime.now(timezone.utc)

    for sat_name, data in tle_sats.items():
        sat = data["sat"]
        freq = data["freq"]
        step_min = 0.5
        in_pass = False
        pass_start = None
        max_el = 0
        start_az = 0

        t = now
        end_t = now + timedelta(hours=hours)
        while t < end_t:
            jd, fr = jday(t.year, t.month, t.day, t.hour, t.minute, t.second + t.microsecond / 1e6)
            e, r, v = sat.sgp4(jd, fr)
            if e != 0:
                t += timedelta(minutes=step_min)
                continue

            el, az = _ecef_to_azel(r, obs_lat, obs_lon, obs_alt, jd, fr)

            if el > 0:
                if not in_pass:
                    in_pass = True
                    pass_start = t
                    start_az = az
                    max_el = el
                else:
                    if el > max_el:
                        max_el = el
            else:
                if in_pass:
                    if max_el >= 15:
                        end_az = az
                        dur = (t - pass_start).total_seconds()
                        direction = _az_to_dir(start_az) + "→" + _az_to_dir(end_az)
                        local_start = pass_start.astimezone()
                        local_end = t.astimezone()
                        passes.append({
                            "satellite": sat_name,
                            "start": local_start.strftime("%H:%M"),
                            "start_utc": pass_start.strftime("%H:%M UTC"),
                            "start_ts": pass_start.timestamp(),
                            "end": local_end.strftime("%H:%M"),
                            "end_ts": t.timestamp(),
                            "max_el": round(max_el),
                            "direction": direction,
                            "duration": round(dur),
                            "freq": freq,
                        })
                    in_pass = False
                    max_el = 0

            t += timedelta(minutes=step_min)

    passes.sort(key=lambda p: p["start_ts"])
    return passes


def _ecef_to_latlon(r_sat, jd, fr):
    gmst = _gmst(jd, fr)
    x, y, z = r_sat
    lon = math.atan2(y, x) - gmst
    lon = math.degrees(lon)
    lon = ((lon + 180) % 360) - 180
    r = math.sqrt(x * x + y * y + z * z)
    lat = math.degrees(math.asin(z / r))
    alt = r - 6371
    return round(lat, 4), round(lon, 4), round(alt, 1)


def _get_sat_positions(tle_sats):
    from sgp4.api import jday
    now = datetime.now(timezone.utc)
    jd, fr = jday(now.year, now.month, now.day, now.hour, now.minute,
                  now.second + now.microsecond / 1e6)
    positions = []
    for name, data in tle_sats.items():
        sat = data["sat"]
        e, r, v = sat.sgp4(jd, fr)
        if e != 0:
            continue
        lat, lon, alt = _ecef_to_latlon(r, jd, fr)
        positions.append({
            "satellite": name,
            "lat": lat,
            "lon": lon,
            "alt_km": alt,
            "freq": data["freq"],
        })
    return positions


_orbit_cache = {"ts": 0, "tracks": {}}


def _get_orbit_tracks(tle_sats, hours=2, step_min=1):
    now_ts = time.time()
    if now_ts - _orbit_cache["ts"] < 300 and _orbit_cache["tracks"]:
        return _orbit_cache["tracks"]

    from sgp4.api import jday
    now = datetime.now(timezone.utc)
    tracks = {}
    for name, data in tle_sats.items():
        sat = data["sat"]
        pts = []
        for i in range(0, hours * 60, step_min):
            t = now + timedelta(minutes=i)
            jd, fr = jday(t.year, t.month, t.day, t.hour, t.minute, t.second)
            e, r, v = sat.sgp4(jd, fr)
            if e != 0:
                continue
            lat, lon, _ = _ecef_to_latlon(r, jd, fr)
            local_t = t.astimezone()
            pts.append([lat, lon, local_t.strftime("%H:%M")])
        tracks[name] = pts
    _orbit_cache["ts"] = now_ts
    _orbit_cache["tracks"] = tracks
    return tracks


def _ecef_to_azel(r_sat, obs_lat, obs_lon, obs_alt, jd, fr):
    lat_r = math.radians(obs_lat)
    lon_r = math.radians(obs_lon)
    gmst = _gmst(jd, fr)
    theta = gmst + lon_r

    cos_lat = math.cos(lat_r)
    sin_lat = math.sin(lat_r)
    Re = 6378.137
    f = 1 / 298.257223563
    C = 1 / math.sqrt(1 - (2 * f - f * f) * sin_lat * sin_lat)
    S_val = C * (1 - f) * (1 - f)
    r_obs = [
        (Re * C + obs_alt / 1000) * cos_lat * math.cos(theta),
        (Re * C + obs_alt / 1000) * cos_lat * math.sin(theta),
        (Re * S_val + obs_alt / 1000) * sin_lat,
    ]

    rx = r_sat[0] - r_obs[0]
    ry = r_sat[1] - r_obs[1]
    rz = r_sat[2] - r_obs[2]

    sin_t = math.sin(theta)
    cos_t = math.cos(theta)

    rs = sin_lat * cos_t * rx + sin_lat * sin_t * ry - cos_lat * rz
    re = -sin_t * rx + cos_t * ry
    rz2 = cos_lat * cos_t * rx + cos_lat * sin_t * ry + sin_lat * rz

    rng = math.sqrt(rs * rs + re * re + rz2 * rz2)
    el = math.degrees(math.asin(rz2 / rng)) if rng > 0 else 0
    az = math.degrees(math.atan2(re, -rs)) % 360

    return el, az


def _gmst(jd, fr):
    T = (jd + fr - 2451545.0) / 36525.0
    g = 1.7533685592 + 6.2831853072 * (jd - 2451545.0 + fr) + 6.77e-6 * T * T
    return g % (2 * math.pi)


def _az_to_dir(az):
    dirs = ["N", "NE", "E", "SE", "S", "SW", "W", "NW"]
    return dirs[round(az / 45) % 8]


def _decode_apt_partial(raw_path, sample_rate=20800):
    try:
        file_size = os.path.getsize(raw_path)
        if file_size < sample_rate * 4:
            return None

        samples_per_line = int(sample_rate / 2)
        chunk_lines = 8
        chunk_samples = samples_per_line * chunk_lines
        pixels_per_line = 2080

        result_lines = []
        offset = 0
        total_samples = file_size // 2

        while offset + chunk_samples <= total_samples:
            with open(raw_path, "rb") as f:
                f.seek(offset * 2)
                raw = f.read(chunk_samples * 2)
            chunk = np.frombuffer(raw, dtype=np.int16).astype(np.float32)

            from scipy.signal import hilbert
            envelope = np.abs(hilbert(chunk))

            ratio = pixels_per_line / samples_per_line
            for line_i in range(chunk_lines):
                start = line_i * samples_per_line
                end = start + samples_per_line
                if end > len(envelope):
                    break
                line_env = envelope[start:end]
                indices = np.linspace(0, len(line_env) - 1, pixels_per_line).astype(int)
                row = line_env[indices]
                result_lines.append(row)

            offset += chunk_samples

        if len(result_lines) < 2:
            return None

        image = np.stack(result_lines)
        mn, mx = image.min(), image.max()
        if mx - mn < 1:
            return None
        image = ((image - mn) / (mx - mn) * 255).astype(np.uint8)
        return image
    except Exception:
        return None


def _capture_thread(freq, duration, raw_path, state):
    cmd = [
        "rtl_fm", "-f", f"{freq}M", "-s", "20800",
        "-g", "20", "-E", "deemp", "-p", "0",
    ]
    try:
        subprocess.run(["pkill", "-9", "rtl_fm"], capture_output=True)
        time.sleep(0.5)
        with open(raw_path, "wb") as out:
            proc = subprocess.Popen(cmd, stdout=out, stderr=subprocess.DEVNULL)
            state["proc"] = proc
            state["start_time"] = time.time()
            deadline = time.time() + duration + 30
            while _running and time.time() < deadline and state.get("capturing"):
                time.sleep(1)
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
    except Exception:
        pass
    state["capturing"] = False
    state["proc"] = None


def _save_image(image_array, sat_name):
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = sat_name.replace(" ", "")
    path = os.path.join(LOOT_DIR, f"{name}_{ts}.png")
    img = Image.fromarray(image_array, "L")
    img.save(path)
    return path


def _list_captures():
    if not os.path.isdir(LOOT_DIR):
        return []
    files = sorted(
        [f for f in os.listdir(LOOT_DIR) if f.endswith(".png")],
        reverse=True,
    )
    return [{"file": f, "path": os.path.join(LOOT_DIR, f)} for f in files[:20]]


def _write_live(state, passes, tle_sats=None):
    while _running:
        try:
            obs = _get_observer()
            sat_positions = _get_sat_positions(tle_sats) if tle_sats else []
            orbit_tracks = _get_orbit_tracks(tle_sats) if tle_sats else {}
            payload = {
                "ts": time.time(),
                "sat_positions": sat_positions,
                "orbit_tracks": orbit_tracks,
                "capturing": state.get("capturing", False),
                "satellite": state.get("satellite", ""),
                "frequency": state.get("frequency", 0),
                "progress_pct": 0,
                "elapsed": 0,
                "duration": state.get("duration", 0),
                "signal_detected": state.get("signal_detected", False),
                "image_path": state.get("image_path", ""),
                "image_width": 2080,
                "image_lines": state.get("image_lines", 0),
                "passes": passes[:10],
                "observer": {"lat": obs[0], "lon": obs[1], "alt": obs[2]},
                "captures": _list_captures(),
                "tle_age": "",
                "auto_mode": "--auto" in sys.argv,
                "next_pass": state.get("next_pass"),
                "next_pass_seconds": state.get("next_pass_seconds", 0),
            }
            if state.get("start_time") and state.get("capturing"):
                elapsed = time.time() - state["start_time"]
                dur = state.get("duration", 600)
                payload["elapsed"] = int(elapsed)
                payload["progress_pct"] = min(100, int(elapsed / max(1, dur) * 100))

            if os.path.isfile(TLE_PATH):
                age = time.time() - os.path.getmtime(TLE_PATH)
                if age < 3600:
                    payload["tle_age"] = f"{int(age / 60)}m ago"
                elif age < 86400:
                    payload["tle_age"] = f"{int(age / 3600)}h ago"
                else:
                    payload["tle_age"] = f"{int(age / 86400)}d ago"

            tmp = LIVE_PATH + ".tmp"
            with open(tmp, "w") as f:
                json.dump(payload, f)
            os.replace(tmp, LIVE_PATH)
        except Exception:
            pass
        time.sleep(2)


def _draw_passes(passes, scroll):
    img = Image.new("RGB", (W, H), (5, 8, 15))
    draw = ImageDraw.Draw(img)

    draw.rectangle([(0, 0), (W, SY(12))], fill=(10, 15, 25))
    draw.text((SX(2), SY(2)), "NEXT PASSES", font=font_sm, fill=(0, 200, 255))
    draw.text((W - SX(2), SY(2)), f"{len(passes)}", font=font_xs, fill=(100, 120, 150), anchor="ra")

    if not passes:
        draw.text((W // 2, H // 2), "No passes predicted", font=font, fill=(40, 50, 65), anchor="mm")
        draw.text((W // 2, H // 2 + SY(14)), "KEY2: Update TLE", font=font_sm, fill=(40, 50, 65), anchor="mm")
    else:
        y = SY(14)
        row_h = SY(22)
        visible = (H - SY(24)) // row_h
        start = min(scroll, max(0, len(passes) - visible))

        for i in range(start, min(len(passes), start + visible)):
            p = passes[i]
            bg = (12, 18, 28) if i % 2 == 0 else (8, 12, 20)
            draw.rectangle([(0, y), (W, y + row_h - 1)], fill=bg)

            el = p["max_el"]
            el_col = (0, 255, 0) if el >= 60 else (255, 200, 0) if el >= 30 else (255, 80, 80)

            draw.text((SX(2), y + SY(1)), p["satellite"].replace("NOAA ", "N"), font=font_sm, fill=(0, 200, 255))
            draw.text((SX(22), y + SY(1)), p["start"], font=font_sm, fill=(200, 200, 200))
            draw.text((SX(50), y + SY(1)), f"{el}°", font=font_sm, fill=el_col)
            draw.text((SX(70), y + SY(1)), p["direction"], font=font_xs, fill=(100, 120, 150))
            draw.text((SX(2), y + SY(11)), f"{p['freq']}MHz", font=font_xs, fill=(80, 100, 130))
            draw.text((SX(50), y + SY(11)), f"{p['duration'] // 60}m{p['duration'] % 60:02d}s", font=font_xs, fill=(80, 100, 130))

            y += row_h

    draw.rectangle([(0, H - SY(10)), (W, H)], fill=(10, 15, 25))
    draw.text((SX(2), H - SY(9)), "OK:Capture K1:View K2:TLE", font=font_xs, fill=(40, 50, 65))
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_live(state):
    img = Image.new("RGB", (W, H), (5, 8, 15))
    draw = ImageDraw.Draw(img)

    draw.rectangle([(0, 0), (W, SY(12))], fill=(10, 15, 25))
    sat = state.get("satellite", "--")
    if state.get("capturing"):
        draw.ellipse([SX(2), SY(3), SX(8), SY(9)], fill=(255, 0, 0))
        draw.text((SX(10), SY(2)), f"REC {sat}", font=font_sm, fill=(255, 80, 80))
    else:
        draw.text((SX(2), SY(2)), "WAITING", font=font_sm, fill=(80, 100, 130))

    if state.get("image_path") and os.path.isfile(state["image_path"]):
        try:
            sat_img = Image.open(state["image_path"]).convert("L")
            display_h = H - SY(24)
            ratio = min(W / sat_img.width, display_h / sat_img.height)
            new_w = int(sat_img.width * ratio)
            new_h = int(sat_img.height * ratio)
            sat_img = sat_img.resize((new_w, new_h), Image.NEAREST)
            x_off = (W - new_w) // 2
            img.paste(sat_img.convert("RGB"), (x_off, SY(14)))
        except Exception:
            pass
    elif state.get("capturing"):
        elapsed = time.time() - state.get("start_time", time.time())
        dur = state.get("duration", 600)
        pct = min(100, int(elapsed / max(1, dur) * 100))
        draw.text((W // 2, H // 2 - SY(5)), f"{pct}%", font=font_lg, fill=(0, 200, 255), anchor="mm")
        bar_w = W - SX(20)
        draw.rectangle([(SX(10), H // 2 + SY(5)), (SX(10) + bar_w, H // 2 + SY(11))], fill=(15, 20, 30))
        draw.rectangle([(SX(10), H // 2 + SY(5)), (SX(10) + int(bar_w * pct / 100), H // 2 + SY(11))], fill=(0, 200, 255))
        draw.text((W // 2, H // 2 + SY(18)), f"{int(elapsed)}s / {dur}s", font=font_xs, fill=(80, 100, 130), anchor="mm")
    else:
        draw.text((W // 2, H // 2), "OK to start capture", font=font_sm, fill=(40, 50, 65), anchor="mm")

    draw.rectangle([(0, H - SY(10)), (W, H)], fill=(10, 15, 25))
    draw.text((SX(2), H - SY(9)), "OK:Start/Stop K1:View", font=font_xs, fill=(40, 50, 65))
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_gallery(captures, scroll):
    img = Image.new("RGB", (W, H), (5, 8, 15))
    draw = ImageDraw.Draw(img)

    draw.rectangle([(0, 0), (W, SY(12))], fill=(10, 15, 25))
    draw.text((SX(2), SY(2)), f"GALLERY ({len(captures)})", font=font_sm, fill=(0, 200, 255))

    if not captures:
        draw.text((W // 2, H // 2), "No captures yet", font=font, fill=(40, 50, 65), anchor="mm")
    else:
        y = SY(14)
        row_h = SY(12)
        visible = (H - SY(24)) // row_h
        start = min(scroll, max(0, len(captures) - visible))
        for i in range(start, min(len(captures), start + visible)):
            c = captures[i]
            bg = (12, 18, 28) if i % 2 == 0 else (8, 12, 20)
            draw.rectangle([(0, y), (W, y + row_h - 1)], fill=bg)
            name = c["file"].replace(".png", "")
            draw.text((SX(2), y + SY(1)), name[:24], font=font_xs, fill=(200, 200, 200))
            y += row_h

    draw.rectangle([(0, H - SY(10)), (W, H)], fill=(10, 15, 25))
    draw.text((SX(2), H - SY(9)), "K1:View K3:Exit", font=font_xs, fill=(40, 50, 65))
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_status(state, passes):
    img = Image.new("RGB", (W, H), (5, 8, 15))
    draw = ImageDraw.Draw(img)

    draw.rectangle([(0, 0), (W, SY(12))], fill=(10, 15, 25))
    draw.text((SX(2), SY(2)), "STATUS", font=font_sm, fill=(0, 200, 255))

    y = SY(16)
    obs = _get_observer()
    items = [
        ("Position", f"{obs[0]:.4f}, {obs[1]:.4f}"),
        ("Altitude", f"{obs[2]:.0f} m"),
        ("TLE file", "OK" if os.path.isfile(TLE_PATH) else "MISSING"),
        ("TLE age", ""),
        ("Passes", f"{len(passes)} upcoming"),
        ("Captures", f"{len(_list_captures())}"),
        ("Capturing", "YES" if state.get("capturing") else "NO"),
        ("RTL-SDR", ""),
    ]

    if os.path.isfile(TLE_PATH):
        age = time.time() - os.path.getmtime(TLE_PATH)
        items[3] = ("TLE age", f"{int(age / 3600)}h" if age < 86400 else f"{int(age / 86400)}d")

    r = subprocess.run(["rtl_test", "-t"], capture_output=True, timeout=3)
    items[7] = ("RTL-SDR", "Found" if r.returncode == 0 else "Not found")

    for label, value in items:
        draw.text((SX(4), y), label, font=font_xs, fill=(60, 70, 90))
        col = (0, 255, 0) if value in ("OK", "Found", "YES") else (200, 200, 200)
        if value in ("MISSING", "Not found", "NO"):
            col = (255, 80, 80)
        draw.text((SX(55), y), value, font=font_sm, fill=col)
        y += SY(11)

    draw.rectangle([(0, H - SY(10)), (W, H)], fill=(10, 15, 25))
    draw.text((SX(2), H - SY(9)), "K1:View K2:Update TLE", font=font_xs, fill=(40, 50, 65))
    LCD.LCD_ShowImage(img, 0, 0)


def main():
    auto_mode = "--auto" in sys.argv

    if not os.path.isfile(TLE_PATH):
        img = Image.new("RGB", (W, H), (5, 8, 15))
        d = ScaledDraw(img)
        d.text((W // 2, H // 2 - SY(10)), "Downloading TLE...", font=font, fill=(255, 200, 0), anchor="mm")
        LCD.LCD_ShowImage(img, 0, 0)
        if _download_tle():
            d.text((W // 2, H // 2 + SY(5)), "OK", font=font, fill=(0, 255, 0), anchor="mm")
        else:
            d.text((W // 2, H // 2 + SY(5)), "Failed (no internet?)", font=font_sm, fill=(255, 80, 80), anchor="mm")
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(1.5)

    tle_sats = _load_tle()
    obs = _get_observer()
    passes = _predict_passes(tle_sats, obs[0], obs[1], obs[2]) if tle_sats else []

    state = {
        "capturing": False,
        "satellite": "",
        "frequency": 0,
        "duration": 0,
        "start_time": 0,
        "image_path": "",
        "image_lines": 0,
        "signal_detected": False,
        "proc": None,
    }

    threading.Thread(target=_write_live, args=(state, passes, tle_sats), daemon=True).start()

    view = 0
    scroll = 0

    _auto_thread = None
    if auto_mode:
        def _auto_scheduler():
            while _running:
                obs = _get_observer()
                _passes = _predict_passes(tle_sats, obs[0], obs[1], obs[2]) if tle_sats else []
                passes.clear()
                passes.extend(_passes)

                now_ts = time.time()
                next_pass = None
                for p in passes:
                    start_ts = p.get("start_ts", 0)
                    end_ts = p.get("end_ts", 0)
                    if end_ts > now_ts and not state.get("capturing"):
                        next_pass = p
                        break

                if next_pass:
                    wait = next_pass["start_ts"] - now_ts
                    state["next_pass"] = next_pass
                    state["next_pass_seconds"] = max(0, int(wait))

                    if wait <= 30 and not state.get("capturing"):
                        state["capturing"] = True
                        state["satellite"] = next_pass["satellite"]
                        state["frequency"] = next_pass["freq"]
                        state["duration"] = next_pass["duration"]
                        state["image_path"] = ""
                        state["image_lines"] = 0

                        os.makedirs(LOOT_DIR, exist_ok=True)
                        raw_path = os.path.join(LOOT_DIR, "capture_raw.s16")

                        def _auto_capture(p=next_pass):
                            _capture_thread(p["freq"], p["duration"], raw_path, state)
                            arr = _decode_apt_partial(raw_path, 20800)
                            if arr is not None:
                                path = _save_image(arr, p["satellite"])
                                state["image_path"] = path
                                state["image_lines"] = arr.shape[0]
                                current_png = os.path.join(LOOT_DIR, "current.png")
                                Image.fromarray(arr, "L").save(current_png)
                            state["capturing"] = False

                        threading.Thread(target=_auto_capture, daemon=True).start()

                        def _auto_live():
                            while state.get("capturing") and _running:
                                time.sleep(5)
                                arr = _decode_apt_partial(raw_path, 20800)
                                if arr is not None:
                                    current_png = os.path.join(LOOT_DIR, "current.png")
                                    Image.fromarray(arr, "L").save(current_png)
                                    state["image_path"] = current_png
                                    state["image_lines"] = arr.shape[0]

                        threading.Thread(target=_auto_live, daemon=True).start()

                time.sleep(10)

        _auto_thread = threading.Thread(target=_auto_scheduler, daemon=True)
        _auto_thread.start()

    try:
        while _running:
            if view == 0:
                _draw_passes(passes, scroll)
            elif view == 1:
                _draw_live(state)
            elif view == 2:
                _draw_gallery(_list_captures(), scroll)
            elif view == 3:
                _draw_status(state, passes)

            btn = _btn()

            if btn == "KEY3":
                if state.get("capturing"):
                    state["capturing"] = False
                    time.sleep(0.5)
                break
            elif btn == "KEY1":
                view = (view + 1) % len(VIEWS)
                scroll = 0
            elif btn == "UP":
                scroll = max(0, scroll - 1)
            elif btn == "DOWN":
                scroll += 1
            elif btn == "KEY2":
                img = Image.new("RGB", (W, H), (5, 8, 15))
                d = ScaledDraw(img)
                d.text((W // 2, H // 2), "Updating TLE...", font=font, fill=(255, 200, 0), anchor="mm")
                LCD.LCD_ShowImage(img, 0, 0)
                if _download_tle():
                    tle_sats = _load_tle()
                    obs = _get_observer()
                    passes = _predict_passes(tle_sats, obs[0], obs[1], obs[2])
                time.sleep(0.5)
            elif btn == "OK":
                if state.get("capturing"):
                    state["capturing"] = False
                elif passes and not state.get("capturing"):
                    p = passes[0]
                    state["capturing"] = True
                    state["satellite"] = p["satellite"]
                    state["frequency"] = p["freq"]
                    state["duration"] = p["duration"]
                    state["image_path"] = ""
                    state["image_lines"] = 0
                    view = 1

                    os.makedirs(LOOT_DIR, exist_ok=True)
                    raw_path = os.path.join(LOOT_DIR, "capture_raw.s16")

                    def _capture_and_decode():
                        _capture_thread(p["freq"], p["duration"], raw_path, state)
                        arr = _decode_apt_partial(raw_path, 20800)
                        if arr is not None:
                            path = _save_image(arr, p["satellite"])
                            state["image_path"] = path
                            state["image_lines"] = arr.shape[0]
                            current_png = os.path.join(LOOT_DIR, "current.png")
                            Image.fromarray(arr, "L").save(current_png)

                    threading.Thread(target=_capture_and_decode, daemon=True).start()

                    def _live_decode():
                        while state.get("capturing") and _running:
                            time.sleep(5)
                            arr = _decode_apt_partial(raw_path, 20800)
                            if arr is not None:
                                current_png = os.path.join(LOOT_DIR, "current.png")
                                Image.fromarray(arr, "L").save(current_png)
                                state["image_path"] = current_png
                                state["image_lines"] = arr.shape[0]

                    threading.Thread(target=_live_decode, daemon=True).start()

            time.sleep(0.15)
    finally:
        state["capturing"] = False
        subprocess.run(["pkill", "-9", "rtl_fm"], capture_output=True)
        try:
            os.unlink(LIVE_PATH)
        except OSError:
            pass
        LCD.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
