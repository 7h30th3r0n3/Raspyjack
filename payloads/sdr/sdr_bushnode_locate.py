#!/usr/bin/env python3
"""
RaspyJack Payload -- Bushnode Locator (RTL-SDR)
=================================================
Signal-strength "hot/cold" direction-finder for a fixed target frequency,
with GPS-tagged logging and a weighted-centroid position estimate so the
same unit works both planted (end of driveway) and grab-and-go (walk it
around and let it home in on a source).

An omnidirectional RTL-SDR dongle can't give you a bearing from a single
point — no directional antenna, no phase array. What it *can* give you,
once you've got several GPS-tagged readings, is a signal-weighted centroid:
strong readings pull the estimate hard, weak ones barely count. Walk a
rough loop around the area and the estimate converges toward the source.
Feed the output lat/lon into map_viewer.py / gps_tracker.py to actually
navigate to it — not reinventing a map UI here.

Still NOT built (future passes, not in scope for this one):
  - Kismet alert / webhook integration for auto-flagging
  - Pressure-sensor or other out-of-band trip-event correlation

Controls:
  OK          : Start/Stop live RSSI monitoring
  UP/DOWN     : Adjust target frequency (coarse, 1 MHz steps)
  LEFT/RIGHT  : Adjust target frequency (fine, 10 kHz steps)
  KEY1 (SPACE): Cycle view (Live / Estimate) — Estimate resets on entry to Live
  KEY2 (BKSP) : Log current reading (freq, dB, GPS, timestamp) to file
  KEY3 (ESC)  : Exit

Requires: rtl-sdr (same backend as the rest of payloads/sdr/*), gpsd-py3
          for GPS tagging (optional — logs with gps=null if unavailable).
"""

import os
import sys
import time
import json
import math
import threading
from datetime import datetime
from collections import deque

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font, S, SX, SY
from payloads._input_helper import get_button
from payloads._gps_helper import start_gps
from payloads.sdr._sdr_core import SDRDevice, detect_sdr

try:
    import gpsd as gpsd_mod
    GPSD_OK = True
except Exception:
    GPSD_OK = False

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for p in PINS.values():
    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD_Config.LCD_Init = getattr(LCD_Config, "LCD_Init", None)
LCD.LCD_Init()
W, H = LCD.width, LCD.height

font = scaled_font(9)
font_sm = scaled_font(7)
font_lg = scaled_font(12)
font_xs = scaled_font(6)

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "loot", "SDR", "bushnode_locate")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_PATH = os.path.join(LOG_DIR, "readings.jsonl")

HISTORY_LEN = 96  # one strip-chart's worth of samples at the render width

freq_hz = 433_920_000  # default target — change with UP/DOWN/LEFT/RIGHT before starting
running = False
view = "live"  # "live" | "estimate"
history = deque(maxlen=HISTORY_LEN)
peak_db = -120.0
sdr = SDRDevice()

# --- GPS state, mirrors payloads/reconnaissance/wardriving.py's pattern ---
gps_lock = threading.Lock()
gps_data = None  # {"lat":, "lon":, "alt":, "mode":, "ts":}
gps_ready = False
_shutdown = threading.Event()


def _gps_updater():
    global gps_data, gps_ready
    if not GPSD_OK:
        return
    if not start_gps():
        return
    try:
        gpsd_mod.connect()
    except Exception:
        return
    gps_ready = True
    while not _shutdown.is_set():
        try:
            pkt = gpsd_mod.get_current()
            if hasattr(pkt, "mode") and pkt.mode >= 2:
                with gps_lock:
                    gps_data = {
                        "lat": pkt.lat,
                        "lon": pkt.lon,
                        "alt": pkt.alt if pkt.mode >= 3 else 0,
                        "mode": pkt.mode,
                        "ts": time.time(),
                    }
        except Exception:
            pass
        time.sleep(1)


def current_gps():
    with gps_lock:
        return dict(gps_data) if gps_data else None


def db_to_bar_height(db, max_h):
    lo, hi = -100.0, -20.0
    frac = max(0.0, min(1.0, (db - lo) / (hi - lo)))
    return int(frac * max_h)


def color_for_db(db):
    if db > -40:
        return (255, 60, 60)
    if db > -60:
        return (255, 180, 0)
    if db > -80:
        return (255, 255, 0)
    return (60, 120, 255)


def log_reading():
    gps = current_gps()
    entry = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "freq_hz": freq_hz,
        "db": round(history[-1], 1) if history else None,
        "peak_db": round(peak_db, 1),
        "gps": gps,
    }
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def estimate_position():
    """
    Signal-weighted centroid over all GPS-tagged readings logged so far.
    Not a real multilateration fix — an omnidirectional dongle at a single
    point gives no bearing. This is the honest version: strong readings
    pull the estimate, weak ones barely count, more points converge tighter.
    Returns (lat, lon, n_points, spread_m) or None if not enough data.
    """
    pts = []
    if not os.path.exists(LOG_PATH):
        return None
    with open(LOG_PATH) as f:
        for line in f:
            try:
                e = json.loads(line)
            except Exception:
                continue
            g = e.get("gps")
            db = e.get("db")
            if g and db is not None:
                pts.append((g["lat"], g["lon"], db))

    if len(pts) < 2:
        return None

    # linear-power weighting: 10^(db/10), normalized
    weights = [10 ** (db / 10.0) for _, _, db in pts]
    wsum = sum(weights)
    if wsum <= 0:
        return None
    lat_est = sum(lat * w for (lat, _, _), w in zip(pts, weights)) / wsum
    lon_est = sum(lon * w for (_, lon, _), w in zip(pts, weights)) / wsum

    # rough spread in meters (equirectangular approx, fine at this scale)
    def dist_m(lat1, lon1, lat2, lon2):
        R = 6371000
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = (math.sin(dlat / 2) ** 2 +
             math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2)
        return 2 * R * math.asin(math.sqrt(a))

    spread = max(dist_m(lat_est, lon_est, lat, lon) for lat, lon, _ in pts)
    return lat_est, lon_est, len(pts), spread


def draw_live(draw):
    draw.text((SX(2), SY(16)), f"{freq_hz/1e6:.3f} MHz", font=font_lg, fill=(255, 200, 0))

    cur_db = history[-1] if history else -120.0
    draw.text((SX(2), SY(32)), f"{cur_db:6.1f} dB", font=font_lg, fill=color_for_db(cur_db))
    draw.text((SX(2), SY(46)), f"peak {peak_db:6.1f} dB", font=font_xs, fill=(150, 150, 170))

    gps = current_gps()
    gps_txt = f"GPS {gps['lat']:.5f},{gps['lon']:.5f}" if gps else ("GPS searching..." if GPSD_OK else "GPS n/a")
    draw.text((SX(2), SY(56)), gps_txt, font=font_xs, fill=(0, 200, 255) if gps else (100, 100, 120))

    chart_top, chart_h = SY(68), H - SY(80)
    draw.rectangle([(0, chart_top), (W, chart_top + chart_h)], fill=(10, 12, 20))
    for i, db in enumerate(history):
        x = SX(i)
        bar_h = db_to_bar_height(db, chart_h)
        draw.line([(x, chart_top + chart_h), (x, chart_top + chart_h - bar_h)], fill=color_for_db(db))


def draw_estimate(draw):
    est = estimate_position()
    draw.text((SX(2), SY(20)), "POSITION ESTIMATE", font=font_sm, fill=(0, 255, 100))
    if not est:
        draw.text((SX(2), SY(40)), "Need >=2 logged", font=font_xs, fill=(150, 150, 170))
        draw.text((SX(2), SY(50)), "GPS-tagged readings", font=font_xs, fill=(150, 150, 170))
        draw.text((SX(2), SY(60)), "(K2 to log while live)", font=font_xs, fill=(100, 100, 120))
        return
    lat, lon, n, spread = est
    draw.text((SX(2), SY(38)), f"{lat:.6f}", font=font, fill=(255, 200, 0))
    draw.text((SX(2), SY(50)), f"{lon:.6f}", font=font, fill=(255, 200, 0))
    draw.text((SX(2), SY(66)), f"n={n} pts  spread~{spread:.0f}m", font=font_xs, fill=(150, 150, 170))
    conf = "low" if n < 4 or spread > 100 else ("med" if n < 8 else "high")
    conf_color = {"low": (255, 60, 60), "med": (255, 180, 0), "high": (0, 255, 100)}[conf]
    draw.text((SX(2), SY(78)), f"confidence: {conf}", font=font_xs, fill=conf_color)
    draw.text((SX(2), SY(90)), "open in map_viewer /", font=font_xs, fill=(100, 100, 120))
    draw.text((SX(2), SY(98)), "gps_tracker to navigate", font=font_xs, fill=(100, 100, 120))


def draw_frame():
    img = Image.new("RGB", (W, H), (5, 6, 12))
    draw = ImageDraw.Draw(img)

    draw.rectangle([(0, 0), (W, SY(14))], fill=(15, 20, 35))
    draw.text((SX(2), SY(2)), "BUSHNODE LOCATE", font=font_sm, fill=(0, 255, 100))
    state_color = (0, 255, 100) if running else (120, 120, 120)
    draw.ellipse([W - SX(10), SY(4), W - SX(4), SY(10)], fill=state_color)

    if view == "live":
        draw_live(draw)
    else:
        draw_estimate(draw)

    draw.rectangle([(0, H - SY(12)), (W, H)], fill=(15, 20, 35))
    hint = "OK start" if not running else "OK stop"
    draw.text((SX(2), H - SY(10)), f"{hint}  K1 view  K2 log", font=font_xs, fill=(100, 100, 120))

    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global freq_hz, running, peak_db, view

    ok, label, backend = detect_sdr()
    if not ok:
        img = Image.new("RGB", (W, H), (10, 5, 5))
        d = ImageDraw.Draw(img)
        d.text((SX(4), SY(50)), "No RTL-SDR found", font=font, fill=(255, 60, 60))
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(2)
        return

    threading.Thread(target=_gps_updater, daemon=True).start()

    draw_frame()
    while True:
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            break
        elif btn == "OK":
            running = not running
            if running:
                sdr.start(freq_hz)
            else:
                sdr.stop()
        elif btn == "UP":
            freq_hz += 1_000_000
        elif btn == "DOWN":
            freq_hz -= 1_000_000
        elif btn == "RIGHT":
            freq_hz += 10_000
        elif btn == "LEFT":
            freq_hz -= 10_000
        elif btn == "KEY1":
            view = "estimate" if view == "live" else "live"
        elif btn == "KEY2" and history:
            log_reading()

        if running:
            db = sdr.get_signal_db()
            history.append(db)
            if db > peak_db:
                peak_db = db

        draw_frame()
        time.sleep(0.1)

    _shutdown.set()
    sdr.stop()


if __name__ == "__main__":
    main()
