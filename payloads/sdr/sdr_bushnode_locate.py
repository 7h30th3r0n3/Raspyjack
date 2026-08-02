#!/usr/bin/env python3
"""
RaspyJack Payload -- Bushnode Locator (RTL-SDR)
=================================================
Signal-strength "hot/cold" direction-finder for a fixed target frequency.
Tune to a known transmitter (a lost/misbehaving bushnode, a beacon, whatever
you've pointed it at) and walk around watching the live dB reading and
strip-chart history to home in on it.

This is the v1 foundation: live RSSI readout + peak tracking only.
Deliberately NOT built yet (next steps, not in scope for this pass):
  - Multi-point logging + real triangulation math (need >=2 fixed readings
    with known positions to actually solve a bearing/fix, not just "warmer")
  - GPS tagging of logged points (see payloads/_gps_helper.py to wire in)
  - Kismet alert / webhook integration for auto-flagging
  - Correlating with pressure-sensor or other out-of-band trip events

Controls:
  OK          : Start/Stop live RSSI monitoring
  UP/DOWN     : Adjust target frequency (coarse, 1 MHz steps)
  LEFT/RIGHT  : Adjust target frequency (fine, 10 kHz steps)
  KEY1 (SPACE): Reset peak/history
  KEY2 (BKSP) : Log current reading (freq, dB, timestamp) to file — no GPS yet
  KEY3 (ESC)  : Exit

Requires: rtl-sdr (same backend as the rest of payloads/sdr/*)
"""

import os
import sys
import time
import json
from datetime import datetime
from collections import deque

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font, S, SX, SY
from payloads._input_helper import get_button
from payloads.sdr._sdr_core import SDRDevice, detect_sdr

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

HISTORY_LEN = 96  # one strip-chart's worth of samples at the render width

freq_hz = 433_920_000  # default target — change with UP/DOWN/LEFT/RIGHT before starting
running = False
history = deque(maxlen=HISTORY_LEN)
peak_db = -120.0
peak_time = None
sdr = SDRDevice()


def db_to_bar_height(db, max_h):
    # RTL-SDR noise floor to strong-signal range, tuned loosely — not calibrated hardware dB
    lo, hi = -100.0, -20.0
    frac = max(0.0, min(1.0, (db - lo) / (hi - lo)))
    return int(frac * max_h)


def color_for_db(db):
    if db > -40:
        return (255, 60, 60)      # hot
    if db > -60:
        return (255, 180, 0)      # warm
    if db > -80:
        return (255, 255, 0)      # cool
    return (60, 120, 255)         # cold


def log_reading():
    entry = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "freq_hz": freq_hz,
        "db": round(history[-1], 1) if history else None,
        "peak_db": round(peak_db, 1),
        "gps": None,  # TODO: wire payloads/_gps_helper.py here once bushnode has a GPS source
    }
    path = os.path.join(LOG_DIR, "readings.jsonl")
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return path


def draw_frame():
    img = Image.new("RGB", (W, H), (5, 6, 12))
    draw = ImageDraw.Draw(img)

    draw.rectangle([(0, 0), (W, SY(14))], fill=(15, 20, 35))
    draw.text((SX(2), SY(2)), "BUSHNODE LOCATE", font=font_sm, fill=(0, 255, 100))
    state_color = (0, 255, 100) if running else (120, 120, 120)
    draw.ellipse([W - SX(10), SY(4), W - SX(4), SY(10)], fill=state_color)

    draw.text((SX(2), SY(16)), f"{freq_hz/1e6:.3f} MHz", font=font_lg, fill=(255, 200, 0))

    cur_db = history[-1] if history else -120.0
    draw.text((SX(2), SY(32)), f"{cur_db:6.1f} dB", font=font_lg, fill=color_for_db(cur_db))
    draw.text((SX(2), SY(46)), f"peak {peak_db:6.1f} dB", font=font_xs, fill=(150, 150, 170))

    # strip-chart history
    chart_top, chart_h = SY(58), H - SY(70)
    draw.rectangle([(0, chart_top), (W, chart_top + chart_h)], fill=(10, 12, 20))
    for i, db in enumerate(history):
        x = SX(i)
        bar_h = db_to_bar_height(db, chart_h)
        draw.line(
            [(x, chart_top + chart_h), (x, chart_top + chart_h - bar_h)],
            fill=color_for_db(db),
        )

    draw.rectangle([(0, H - SY(12)), (W, H)], fill=(15, 20, 35))
    hint = "OK start" if not running else "OK stop"
    draw.text((SX(2), H - SY(10)), f"{hint}  UP/DN 1M  L/R 10k  K2 log", font=font_xs, fill=(100, 100, 120))

    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global freq_hz, running, peak_db, peak_time

    ok, label, backend = detect_sdr()
    if not ok:
        img = Image.new("RGB", (W, H), (10, 5, 5))
        d = ImageDraw.Draw(img)
        d.text((SX(4), SY(50)), "No RTL-SDR found", font=font, fill=(255, 60, 60))
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(2)
        return

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
            history.clear()
            peak_db = -120.0
            peak_time = None
        elif btn == "KEY2" and history:
            log_reading()

        if running:
            db = sdr.get_signal_db()
            history.append(db)
            if db > peak_db:
                peak_db = db
                peak_time = datetime.now()

        draw_frame()
        time.sleep(0.1)

    sdr.stop()


if __name__ == "__main__":
    main()
