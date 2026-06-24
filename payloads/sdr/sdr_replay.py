#!/usr/bin/env python3
"""
RaspyJack Payload -- SDR Capture & Replay
==========================================
Author: 7h30th3r0n3

Flipper Zero-style capture and replay for ISM bands (315/433/868/915 MHz).
Record raw IQ signals, browse a capture library, and replay via rpitx.

Controls:
  OK          : Record (capture) / Select (library) / Transmit (replay)
  KEY1 (SPACE): Cycle views (Capture / Library / Replay)
  UP/DOWN     : Adjust gain (capture) / Scroll (library)
  LEFT/RIGHT  : Change frequency band
  KEY2 (BKSP) : Delete selected capture
  KEY3 (ESC)  : Exit

Requires: apt install rtl-sdr
Optional: rpitx (for TX replay)
"""

import os
import sys
import time
import signal
import subprocess
import threading
import json
from datetime import datetime
from collections import deque

import numpy as np

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font, S, SX, SY
from payloads._input_helper import get_button
from payloads.sdr._sdr_core import SDRDevice, detect_sdr, compute_fft

# ---------------------------------------------------------------------------
# Pin & LCD setup
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT

# ---------------------------------------------------------------------------
# Theme colors
# ---------------------------------------------------------------------------
COL_BG = (10, 10, 18)
COL_HEADER = (13, 17, 23)
COL_CAPTURE = (0, 230, 118)
COL_REPLAY = (255, 82, 82)
COL_SIGNAL = (0, 229, 255)
COL_PURPLE = (124, 77, 255)
COL_MUTED = (136, 136, 136)
COL_DIM = (85, 85, 85)
COL_SELECTED = (20, 30, 50)

# Waterfall gradient stops: blue -> cyan -> green -> yellow -> red
_WF_STOPS = [
    (0.00, (0, 0, 40)),
    (0.20, (0, 0, 180)),
    (0.40, (0, 180, 255)),
    (0.60, (0, 220, 80)),
    (0.80, (255, 220, 0)),
    (1.00, (255, 30, 0)),
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = "/root/Raspyjack/loot/SDR/replay"
DEBOUNCE = 0.18
SAMPLE_RATE = 2_048_000
SIGNAL_THRESHOLD_DB = -30.0
VIEWS = ["capture", "library", "replay"]

BANDS = [
    {"name": "300 MHz", "freq": 300_000_000, "desc": "Gate/Alarm"},
    {"name": "315 MHz", "freq": 315_000_000, "desc": "US Remotes"},
    {"name": "390 MHz", "freq": 390_000_000, "desc": "Car Keys"},
    {"name": "418 MHz", "freq": 418_000_000, "desc": "EU Remote"},
    {"name": "433 MHz", "freq": 433_920_000, "desc": "EU ISM"},
    {"name": "434 MHz", "freq": 434_000_000, "desc": "EU Sensors"},
    {"name": "868 MHz", "freq": 868_000_000, "desc": "EU LoRa"},
    {"name": "915 MHz", "freq": 915_000_000, "desc": "US ISM"},
    {"name": "Custom", "freq": 433_920_000, "desc": "Manual"},
]

FREQ_STEP = 100_000  # 100 kHz step for custom frequency tuning

GAIN_STEPS = [0, 10, 20, 30, 40, 49]

# ---------------------------------------------------------------------------
# Fonts
# ---------------------------------------------------------------------------
font = scaled_font(10)
font_sm = scaled_font(9)
font_lg = scaled_font(13)
font_xs = scaled_font(8)

# ---------------------------------------------------------------------------
# Module state (immutable replacement pattern: new dicts when updating)
# ---------------------------------------------------------------------------
_running = True
_last_btn = 0


def _sig_handler(_s, _f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig_handler)
signal.signal(signal.SIGTERM, _sig_handler)


def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    if b is None:
        return None
    now = time.time()
    if now - _last_btn < DEBOUNCE:
        return None
    _last_btn = now
    return b


# ---------------------------------------------------------------------------
# Waterfall LUT builder
# ---------------------------------------------------------------------------
def _interp_color(c1, c2, t):
    return tuple(int(c1[i] + (c2[i] - c1[i]) * t) for i in range(3))


def _build_waterfall_lut():
    lut = []
    for i in range(256):
        t = i / 255.0
        for j in range(len(_WF_STOPS) - 1):
            t0 = _WF_STOPS[j][0]
            t1 = _WF_STOPS[j + 1][0]
            if t0 <= t <= t1:
                seg_t = (t - t0) / (t1 - t0) if t1 > t0 else 0.0
                lut.append(_interp_color(_WF_STOPS[j][1], _WF_STOPS[j + 1][1], seg_t))
                break
        else:
            lut.append(_WF_STOPS[-1][1])
    return lut


_WF_LUT = _build_waterfall_lut()

# ---------------------------------------------------------------------------
# Waterfall buffer
# ---------------------------------------------------------------------------
DB_MIN = -70.0
DB_MAX = -5.0


class _WaterfallBuf:
    """Ring buffer of FFT rows for the mini waterfall display."""

    def __init__(self, width, height):
        self.width = width
        self.height = height
        self._rows = deque(maxlen=height)

    def push(self, fft_db):
        resampled = np.interp(
            np.linspace(0, len(fft_db) - 1, self.width),
            np.arange(len(fft_db)),
            fft_db,
        )
        indices = np.clip(
            ((resampled - DB_MIN) / max(0.1, DB_MAX - DB_MIN) * 255),
            0, 255,
        ).astype(np.uint8)
        self._rows.append(indices)

    def render(self, image, x0, y0, w, h):
        rows = list(self._rows)
        if not rows:
            return
        n = min(len(rows), h)
        last_rows = rows[-n:]
        stacked = np.array(last_rows, dtype=np.uint8)
        if stacked.shape[1] != w:
            x_old = np.linspace(0, stacked.shape[1] - 1, stacked.shape[1])
            x_new = np.linspace(0, stacked.shape[1] - 1, w)
            resampled = np.zeros((n, w), dtype=np.uint8)
            for i in range(n):
                resampled[i] = np.interp(x_new, x_old, stacked[i]).astype(np.uint8)
            stacked = resampled
        lut_arr = np.array(_WF_LUT, dtype=np.uint8)
        pixels = lut_arr[stacked]
        wf_img = Image.fromarray(pixels, "RGB")
        image.paste(wf_img, (x0, y0 + h - n))


# ---------------------------------------------------------------------------
# rpitx availability
# ---------------------------------------------------------------------------
def _rpitx_available():
    try:
        r = subprocess.run(["which", "rpitx"], capture_output=True, timeout=3)
        return r.returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Capture metadata helpers
# ---------------------------------------------------------------------------
def _make_capture_path(freq_hz):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    freq_mhz = freq_hz / 1e6
    filename = f"replay_{freq_mhz:.3f}MHz_{ts}.iq"
    return os.path.join(LOOT_DIR, filename)


def _write_metadata(iq_path, freq_hz, sample_rate, gain, duration):
    meta = {
        "freq_hz": freq_hz,
        "freq_mhz": freq_hz / 1e6,
        "sample_rate": sample_rate,
        "gain": gain,
        "duration_s": round(duration, 2),
        "timestamp": datetime.now().isoformat(),
        "filename": os.path.basename(iq_path),
    }
    meta_path = iq_path.replace(".iq", ".json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    return meta_path


def _read_metadata(iq_path):
    meta_path = iq_path.replace(".iq", ".json")
    if os.path.isfile(meta_path):
        try:
            with open(meta_path, "r") as f:
                return json.load(f)
        except Exception:
            pass
    # Fallback: parse filename
    base = os.path.basename(iq_path)
    parts = base.replace(".iq", "").split("_")
    freq_str = ""
    for p in parts:
        if "MHz" in p:
            freq_str = p.replace("MHz", "")
            break
    freq_mhz = float(freq_str) if freq_str else 433.92
    size = os.path.getsize(iq_path)
    duration = size / (SAMPLE_RATE * 2)  # uint8 IQ = 2 bytes per sample
    return {
        "freq_hz": int(freq_mhz * 1e6),
        "freq_mhz": freq_mhz,
        "sample_rate": SAMPLE_RATE,
        "gain": 30,
        "duration_s": round(duration, 2),
        "timestamp": "",
        "filename": base,
    }


def _list_captures():
    if not os.path.isdir(LOOT_DIR):
        return []
    entries = []
    for f in sorted(os.listdir(LOOT_DIR), reverse=True):
        if f.endswith(".iq"):
            path = os.path.join(LOOT_DIR, f)
            meta = _read_metadata(path)
            entries.append({"path": path, "meta": meta})
    return entries


def _delete_capture(path):
    try:
        os.remove(path)
    except OSError:
        pass
    meta_path = path.replace(".iq", ".json")
    try:
        os.remove(meta_path)
    except OSError:
        pass


def _format_duration(seconds):
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    m = int(seconds) // 60
    s = int(seconds) % 60
    return f"{m}m{s:02d}s"


def _format_size(path):
    try:
        sz = os.path.getsize(path)
    except OSError:
        return "?"
    if sz < 1024:
        return f"{sz}B"
    if sz < 1024 * 1024:
        return f"{sz / 1024:.1f}K"
    return f"{sz / (1024 * 1024):.1f}M"


# ---------------------------------------------------------------------------
# Drawing: signal strength bar
# ---------------------------------------------------------------------------
def _draw_signal_bar(draw, db, x0, y0, w, h):
    """Draw a horizontal signal strength meter bar with dB label."""
    draw.rectangle([(x0, y0), (x0 + w, y0 + h)], fill=(20, 20, 30), outline=COL_DIM)
    fill_pct = min(1.0, max(0.0, (db - DB_MIN) / (DB_MAX - DB_MIN)))
    bar_w = int((w - 4) * fill_pct)

    if fill_pct < 0.3:
        bar_color = (0, 80, 200)
    elif fill_pct < 0.5:
        bar_color = COL_SIGNAL
    elif fill_pct < 0.7:
        bar_color = COL_CAPTURE
    elif fill_pct < 0.85:
        bar_color = (255, 220, 0)
    else:
        bar_color = COL_REPLAY

    if bar_w > 0:
        draw.rectangle(
            [(x0 + 2, y0 + 2), (x0 + 2 + bar_w, y0 + h - 2)],
            fill=bar_color,
        )

    # Threshold marker
    thresh_x = x0 + 2 + int((w - 4) * max(0.0, (SIGNAL_THRESHOLD_DB - DB_MIN) / (DB_MAX - DB_MIN)))
    draw.line([(thresh_x, y0 + 1), (thresh_x, y0 + h - 1)], fill=COL_REPLAY, width=1)

    # dB text
    draw.text(
        (x0 + w + 3, y0 + 1),
        f"{db:.0f}dB",
        font=font_xs,
        fill=COL_SIGNAL if db > SIGNAL_THRESHOLD_DB else COL_MUTED,
    )


# ---------------------------------------------------------------------------
# Drawing: CAPTURE view
# ---------------------------------------------------------------------------
def _draw_capture(lcd, sdr, band_idx, gain_idx, recording, rec_start, wf_buf):
    img = Image.new("RGB", (WIDTH, HEIGHT), COL_BG)
    draw = ImageDraw.Draw(img)
    d = ScaledDraw(img)
    band = BANDS[band_idx]

    # -- Header --
    d.rectangle([(0, 0), (128, 13)], fill=COL_HEADER)
    d.text((2, 2), "CAPTURE", font=font_sm, fill=COL_CAPTURE)
    d.text((50, 2), band["name"], font=font_sm, fill=(255, 200, 0))

    if recording:
        # Blinking red dot
        if int(time.time() * 3) % 2 == 0:
            d.ellipse([(110, 3), (116, 9)], fill=COL_REPLAY)
        elapsed = time.time() - rec_start
        d.text((90, 2), f"REC {elapsed:.1f}s", font=font_xs, fill=COL_REPLAY)

    # -- Frequency + band --
    freq_mhz = band["freq"] / 1e6
    d.text((2, 15), f"{freq_mhz:.3f} MHz", font=font, fill=COL_SIGNAL)
    gain_val = GAIN_STEPS[gain_idx]
    d.text((80, 15), f"G:{gain_val}", font=font_xs, fill=COL_MUTED)
    d.text((100, 15), band["desc"], font=font_xs, fill=COL_DIM)

    # -- Signal strength bar --
    db = sdr.get_signal_db() if sdr.is_running else -100.0
    _draw_signal_bar(d, db, 4, 26, 85, 8)

    # -- Status text --
    above_thresh = db > SIGNAL_THRESHOLD_DB
    if above_thresh and not recording:
        d.text((2, 36), "SIGNAL DETECTED", font=font_xs, fill=COL_CAPTURE)
    elif recording:
        d.text((2, 36), "RECORDING...", font=font_xs, fill=COL_REPLAY)
    else:
        d.text((2, 36), "Listening...", font=font_xs, fill=COL_DIM)

    # -- Waterfall display --
    wf_y = SY(46)
    wf_h = SY(113) - wf_y
    wf_w = WIDTH

    if sdr.is_running:
        iq = sdr.get_iq_block(256)
        fft_db = compute_fft(iq, 256)
        wf_buf.push(fft_db)

    wf_buf.render(img, 0, wf_y, wf_w, wf_h)

    # Spectrum overlay on waterfall
    if sdr.is_running:
        iq = sdr.get_iq_block(256)
        fft_db = compute_fft(iq, 256)
        resampled = np.interp(
            np.linspace(0, len(fft_db) - 1, wf_w),
            np.arange(len(fft_db)),
            fft_db,
        )
        points = []
        for i in range(wf_w):
            norm = max(0.0, min(1.0, (resampled[i] - DB_MIN) / (DB_MAX - DB_MIN)))
            py = int(wf_y + wf_h - norm * wf_h)
            points.append((i, py))
        if len(points) > 1:
            draw.line(points, fill=COL_SIGNAL, width=1)

    # -- Footer (drawn last, covers any overflow) --
    d.rectangle([(0, 114), (128, 128)], fill=COL_HEADER)
    is_custom = band["name"] == "Custom"
    if recording:
        d.text((2, 115), "OK:Stop  LR:Band  K3:Exit", font=font_xs, fill=COL_DIM)
    elif is_custom:
        d.text((2, 115), "OK:Rec UD:Freq LR:Band", font=font_xs, fill=COL_DIM)
    else:
        d.text((2, 115), "OK:Rec UD:Gain LR:Band", font=font_xs, fill=COL_DIM)

    lcd.LCD_ShowImage(img, 0, 0)
    return db


# ---------------------------------------------------------------------------
# Drawing: LIBRARY view
# ---------------------------------------------------------------------------
def _draw_library(lcd, captures, scroll, selected):
    img = Image.new("RGB", (WIDTH, HEIGHT), COL_BG)
    d = ScaledDraw(img)

    # -- Header --
    d.rectangle([(0, 0), (128, 13)], fill=COL_HEADER)
    d.text((2, 2), "LIBRARY", font=font_sm, fill=COL_PURPLE)
    d.text((55, 2), f"{len(captures)} files", font=font_xs, fill=COL_MUTED)

    if not captures:
        d.text((64, 55), "No captures yet", font=font, fill=COL_DIM, anchor="mm")
        d.text((64, 70), "Use CAPTURE to record", font=font_xs, fill=COL_DIM, anchor="mm")
        d.rectangle([(0, 115), (128, 128)], fill=COL_HEADER)
        d.text((2, 116), "K1:View  K3:Exit", font=font_xs, fill=COL_DIM)
        lcd.LCD_ShowImage(img, 0, 0)
        return

    row_h = SY(20)
    y = SY(15)
    visible = max(1, (HEIGHT - SY(30)) // row_h)

    for i in range(scroll, min(len(captures), scroll + visible)):
        cap = captures[i]
        meta = cap["meta"]
        is_sel = i == selected

        if y + row_h > HEIGHT - SY(14):
            break

        # Row background
        if is_sel:
            d.rectangle([(0, int(y / SY(1))), (128, int(y / SY(1)) + 19)], fill=COL_SELECTED)
            # Selection indicator
            d.rectangle([(0, int(y / SY(1))), (2, int(y / SY(1)) + 19)], fill=COL_PURPLE)

        freq_str = f"{meta.get('freq_mhz', 0):.1f}MHz"
        dur_str = _format_duration(meta.get("duration_s", 0))
        size_str = _format_size(cap["path"])

        # Frequency
        freq_color = COL_SIGNAL if is_sel else COL_MUTED
        draw_raw = ImageDraw.Draw(img)
        draw_raw.text((SX(4), y + SY(1)), freq_str, font=font_sm, fill=freq_color)

        # Duration + size
        draw_raw.text((SX(50), y + SY(1)), dur_str, font=font_xs, fill=COL_CAPTURE if is_sel else COL_DIM)
        draw_raw.text((SX(80), y + SY(1)), size_str, font=font_xs, fill=COL_DIM)

        # Timestamp
        ts = meta.get("timestamp", "")
        if ts:
            try:
                dt = datetime.fromisoformat(ts)
                ts_short = dt.strftime("%m/%d %H:%M")
            except (ValueError, TypeError):
                ts_short = ts[:16]
        else:
            ts_short = os.path.basename(cap["path"])[:20]
        draw_raw.text((SX(4), y + SY(10)), ts_short, font=font_xs, fill=COL_DIM)

        y += row_h

    # Scrollbar
    if len(captures) > visible:
        sb_h = max(SY(5), int((HEIGHT - SY(30)) * visible / len(captures)))
        sb_y = SY(15) + int((HEIGHT - SY(30) - sb_h) * scroll / max(1, len(captures) - visible))
        draw_raw = ImageDraw.Draw(img)
        draw_raw.rectangle(
            [(WIDTH - SX(2), sb_y), (WIDTH, sb_y + sb_h)],
            fill=COL_PURPLE,
        )

    # -- Footer --
    d.rectangle([(0, 115), (128, 128)], fill=COL_HEADER)
    d.text((2, 116), "OK:Select K2:Del K1:View", font=font_xs, fill=COL_DIM)

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Drawing: REPLAY view
# ---------------------------------------------------------------------------
def _draw_replay(lcd, selected_cap, transmitting, tx_progress):
    img = Image.new("RGB", (WIDTH, HEIGHT), COL_BG)
    d = ScaledDraw(img)
    draw_raw = ImageDraw.Draw(img)

    # -- Header --
    d.rectangle([(0, 0), (128, 13)], fill=COL_HEADER)
    d.text((2, 2), "REPLAY", font=font_sm, fill=COL_REPLAY)

    if selected_cap is None:
        d.text((64, 50), "No signal selected", font=font, fill=COL_DIM, anchor="mm")
        d.text((64, 65), "Select from Library", font=font_xs, fill=COL_DIM, anchor="mm")
        d.rectangle([(0, 115), (128, 128)], fill=COL_HEADER)
        d.text((2, 116), "K1:View  K3:Exit", font=font_xs, fill=COL_DIM)
        lcd.LCD_ShowImage(img, 0, 0)
        return

    meta = selected_cap["meta"]
    freq_mhz = meta.get("freq_mhz", 0)
    duration = meta.get("duration_s", 0)
    sample_rate = meta.get("sample_rate", SAMPLE_RATE)

    # -- Signal info card --
    d.rectangle([(4, 18), (124, 65)], fill=(15, 20, 30), outline=COL_DIM)

    d.text((8, 20), f"{freq_mhz:.3f} MHz", font=font_lg, fill=COL_SIGNAL)
    d.text((8, 36), f"Duration: {_format_duration(duration)}", font=font_sm, fill=COL_MUTED)
    d.text((8, 46), f"Rate: {sample_rate / 1e6:.1f} MS/s", font=font_xs, fill=COL_DIM)
    d.text((8, 55), f"Size: {_format_size(selected_cap['path'])}", font=font_xs, fill=COL_DIM)

    # -- Signal waveform visualization --
    wv_y = SY(70)
    wv_h = SY(25)
    wv_w = WIDTH - SX(8)
    x_off = SX(4)

    try:
        with open(selected_cap["path"], "rb") as fh:
            # Read a small chunk for visualization
            raw = fh.read(min(4096, os.path.getsize(selected_cap["path"])))
        if raw:
            samples = np.frombuffer(raw, dtype=np.uint8)
            floats = (samples.astype(np.float32) - 127.5) / 127.5
            # Resample to display width
            resampled = np.interp(
                np.linspace(0, len(floats) - 1, wv_w),
                np.arange(len(floats)),
                floats,
            )
            center_y = wv_y + wv_h // 2
            points = []
            for i in range(wv_w):
                py = int(center_y - resampled[i] * (wv_h // 2))
                points.append((x_off + i, py))
            if len(points) > 1:
                draw_raw.line(points, fill=COL_PURPLE, width=1)
            # Center line
            draw_raw.line(
                [(x_off, center_y), (x_off + wv_w, center_y)],
                fill=COL_DIM, width=1,
            )
    except Exception:
        pass

    # -- TX status --
    if transmitting:
        # Blinking TX indicator
        if int(time.time() * 4) % 2 == 0:
            d.text((64, 100), "TRANSMITTING", font=font, fill=COL_REPLAY, anchor="mm")
        else:
            d.text((64, 100), "TRANSMITTING", font=font, fill=(180, 40, 40), anchor="mm")

        # Progress bar
        bar_x = SX(10)
        bar_w = SX(108)
        bar_y = SY(106)
        bar_h = SY(5)
        draw_raw.rectangle(
            [(bar_x, bar_y), (bar_x + bar_w, bar_y + bar_h)],
            fill=(30, 30, 40), outline=COL_DIM,
        )
        prog_w = int(bar_w * min(1.0, tx_progress))
        if prog_w > 0:
            draw_raw.rectangle(
                [(bar_x + 1, bar_y + 1), (bar_x + 1 + prog_w, bar_y + bar_h - 1)],
                fill=COL_REPLAY,
            )
    else:
        has_rpitx = _rpitx_available()
        if has_rpitx:
            d.text((64, 100), "OK to transmit", font=font_sm, fill=COL_CAPTURE, anchor="mm")
        else:
            d.text((64, 97), "rpitx not installed", font=font_sm, fill=COL_REPLAY, anchor="mm")
            d.text((64, 108), "apt install rpitx", font=font_xs, fill=COL_DIM, anchor="mm")

    # -- Footer --
    d.rectangle([(0, 115), (128, 128)], fill=COL_HEADER)
    if transmitting:
        d.text((2, 116), "OK:Stop  K3:Exit", font=font_xs, fill=COL_DIM)
    else:
        d.text((2, 116), "OK:TX  K1:View  K3:Exit", font=font_xs, fill=COL_DIM)

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Splash / status screens
# ---------------------------------------------------------------------------
def _draw_splash(lcd, msg, sub="", color=COL_CAPTURE):
    img = Image.new("RGB", (WIDTH, HEIGHT), COL_BG)
    d = ScaledDraw(img)
    d.text((64, 55), msg, font=font, fill=color, anchor="mm")
    if sub:
        d.text((64, 70), sub, font=font_xs, fill=COL_MUTED, anchor="mm")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_confirm(lcd, msg, sub=""):
    img = Image.new("RGB", (WIDTH, HEIGHT), COL_BG)
    d = ScaledDraw(img)
    d.rectangle([(10, 35), (118, 90)], fill=(20, 15, 25), outline=COL_REPLAY)
    d.text((64, 48), msg, font=font_sm, fill=COL_REPLAY, anchor="mm")
    if sub:
        d.text((64, 60), sub, font=font_xs, fill=COL_MUTED, anchor="mm")
    d.text((64, 78), "OK:Yes  KEY2:No", font=font_xs, fill=COL_DIM, anchor="mm")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# TX via rpitx
# ---------------------------------------------------------------------------
_tx_proc = None
_tx_lock = threading.Lock()


def _start_tx(iq_path, freq_hz, sample_rate):
    global _tx_proc
    _stop_tx()
    freq_khz = freq_hz / 1000.0
    cmd = [
        "rpitx", "-m", "IQ",
        "-i", iq_path,
        "-f", str(freq_khz),
        "-s", str(sample_rate),
    ]
    with _tx_lock:
        try:
            _tx_proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid,
            )
        except FileNotFoundError:
            _tx_proc = None
            return False
    return True


def _stop_tx():
    global _tx_proc
    with _tx_lock:
        if _tx_proc is not None:
            try:
                os.killpg(os.getpgid(_tx_proc.pid), signal.SIGKILL)
            except Exception:
                pass
            _tx_proc = None


def _is_tx_running():
    with _tx_lock:
        if _tx_proc is None:
            return False
        poll = _tx_proc.poll()
        if poll is not None:
            return False
        return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    GPIO.setmode(GPIO.BCM)
    for p in PINS.values():
        GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)

    # Detect SDR hardware
    _draw_splash(lcd, "Detecting SDR...", "Please wait", COL_SIGNAL)
    found, label, backend = detect_sdr()

    if not found:
        _draw_splash(lcd, "No SDR found!", label, COL_REPLAY)
        time.sleep(3)
        GPIO.cleanup()
        return 0

    _draw_splash(lcd, f"Found: {label}", "Initializing...", COL_CAPTURE)
    time.sleep(0.8)

    sdr = SDRDevice()
    wf_buf = _WaterfallBuf(WIDTH, SY(60))

    # State
    view_idx = 0
    band_idx = 0
    gain_idx = 3  # default gain=30
    recording = False
    rec_start = 0.0
    rec_path = ""
    lib_scroll = 0
    lib_selected = 0
    captures = []
    selected_cap = None
    transmitting = False
    tx_start = 0.0

    # Start SDR listening on default band
    sdr.start(BANDS[band_idx]["freq"], SAMPLE_RATE, GAIN_STEPS[gain_idx], backend)

    try:
        while _running:
            view = VIEWS[view_idx]

            # -- Draw current view --
            if view == "capture":
                _draw_capture(
                    lcd, sdr, band_idx, gain_idx,
                    recording, rec_start, wf_buf,
                )
            elif view == "library":
                _draw_library(lcd, captures, lib_scroll, lib_selected)
            elif view == "replay":
                tx_progress = 0.0
                if transmitting and selected_cap:
                    elapsed = time.time() - tx_start
                    dur = selected_cap["meta"].get("duration_s", 1)
                    tx_progress = min(1.0, elapsed / max(0.01, dur))
                    if not _is_tx_running():
                        transmitting = False
                _draw_replay(lcd, selected_cap, transmitting, tx_progress)

            # -- Handle input --
            btn = _btn()

            if btn == "KEY3":
                # Exit
                break

            elif btn == "KEY1":
                # Cycle views
                old_view = view
                view_idx = (view_idx + 1) % len(VIEWS)
                new_view = VIEWS[view_idx]

                # Refresh library when entering library view
                if new_view == "library":
                    captures = _list_captures()
                    lib_scroll = 0
                    lib_selected = min(lib_selected, max(0, len(captures) - 1))

                # Ensure SDR runs in capture mode
                if new_view == "capture" and not sdr.is_running:
                    sdr.start(BANDS[band_idx]["freq"], SAMPLE_RATE, GAIN_STEPS[gain_idx], backend)

            elif btn == "OK":
                if view == "capture":
                    if recording:
                        # Stop recording
                        sdr.stop_recording()
                        duration = time.time() - rec_start
                        _write_metadata(
                            rec_path,
                            BANDS[band_idx]["freq"],
                            SAMPLE_RATE,
                            GAIN_STEPS[gain_idx],
                            duration,
                        )
                        recording = False
                        _draw_splash(
                            lcd,
                            f"Saved {_format_duration(duration)}",
                            os.path.basename(rec_path),
                            COL_CAPTURE,
                        )
                        time.sleep(1.2)
                    else:
                        # Start recording
                        os.makedirs(LOOT_DIR, exist_ok=True)
                        rec_path = _make_capture_path(BANDS[band_idx]["freq"])
                        sdr.start_recording(rec_path)
                        rec_start = time.time()
                        recording = True

                elif view == "library":
                    if captures and 0 <= lib_selected < len(captures):
                        selected_cap = captures[lib_selected]
                        view_idx = VIEWS.index("replay")

                elif view == "replay":
                    if transmitting:
                        _stop_tx()
                        transmitting = False
                        _draw_splash(lcd, "TX Stopped", "", COL_REPLAY)
                        time.sleep(0.8)
                    elif selected_cap is not None:
                        if not _rpitx_available():
                            _draw_splash(
                                lcd,
                                "rpitx not found!",
                                "apt install rpitx",
                                COL_REPLAY,
                            )
                            time.sleep(2)
                        else:
                            # Stop SDR RX before TX
                            sdr.stop()
                            meta = selected_cap["meta"]
                            ok = _start_tx(
                                selected_cap["path"],
                                meta.get("freq_hz", BANDS[band_idx]["freq"]),
                                meta.get("sample_rate", SAMPLE_RATE),
                            )
                            if ok:
                                transmitting = True
                                tx_start = time.time()
                            else:
                                _draw_splash(lcd, "TX Failed!", "", COL_REPLAY)
                                time.sleep(1.5)
                                sdr.start(
                                    BANDS[band_idx]["freq"],
                                    SAMPLE_RATE,
                                    GAIN_STEPS[gain_idx],
                                    backend,
                                )

            elif btn == "UP":
                if view == "capture":
                    if BANDS[band_idx]["name"] == "Custom" and not recording:
                        BANDS[band_idx]["freq"] += FREQ_STEP
                        BANDS[band_idx]["desc"] = f"{BANDS[band_idx]['freq']/1e6:.1f}M"
                        sdr.stop()
                        sdr.start(BANDS[band_idx]["freq"], SAMPLE_RATE, GAIN_STEPS[gain_idx], backend)
                        wf_buf = _WaterfallBuf(WIDTH, SY(60))
                    else:
                        gain_idx = min(len(GAIN_STEPS) - 1, gain_idx + 1)
                        sdr.set_gain(GAIN_STEPS[gain_idx])
                elif view == "library":
                    lib_selected = max(0, lib_selected - 1)
                    visible = max(1, (HEIGHT - SY(30)) // SY(20))
                    if lib_selected < lib_scroll:
                        lib_scroll = lib_selected

            elif btn == "DOWN":
                if view == "capture":
                    if BANDS[band_idx]["name"] == "Custom" and not recording:
                        BANDS[band_idx]["freq"] = max(24_000_000, BANDS[band_idx]["freq"] - FREQ_STEP)
                        BANDS[band_idx]["desc"] = f"{BANDS[band_idx]['freq']/1e6:.1f}M"
                        sdr.stop()
                        sdr.start(BANDS[band_idx]["freq"], SAMPLE_RATE, GAIN_STEPS[gain_idx], backend)
                        wf_buf = _WaterfallBuf(WIDTH, SY(60))
                    else:
                        gain_idx = max(0, gain_idx - 1)
                        sdr.set_gain(GAIN_STEPS[gain_idx])
                elif view == "library":
                    if captures:
                        lib_selected = min(len(captures) - 1, lib_selected + 1)
                        visible = max(1, (HEIGHT - SY(30)) // SY(20))
                        if lib_selected >= lib_scroll + visible:
                            lib_scroll = lib_selected - visible + 1

            elif btn == "LEFT":
                if view == "capture" and not recording:
                    band_idx = (band_idx - 1) % len(BANDS)
                    sdr.stop()
                    sdr.start(
                        BANDS[band_idx]["freq"],
                        SAMPLE_RATE,
                        GAIN_STEPS[gain_idx],
                        backend,
                    )
                    wf_buf = _WaterfallBuf(WIDTH, SY(60))

            elif btn == "RIGHT":
                if view == "capture" and not recording:
                    band_idx = (band_idx + 1) % len(BANDS)
                    sdr.stop()
                    sdr.start(
                        BANDS[band_idx]["freq"],
                        SAMPLE_RATE,
                        GAIN_STEPS[gain_idx],
                        backend,
                    )
                    wf_buf = _WaterfallBuf(WIDTH, SY(60))

            elif btn == "KEY2":
                if view == "library" and captures and 0 <= lib_selected < len(captures):
                    cap = captures[lib_selected]
                    fname = os.path.basename(cap["path"])[:20]
                    _draw_confirm(lcd, "Delete capture?", fname)
                    # Wait for confirmation
                    confirmed = None
                    t0 = time.time()
                    while _running and confirmed is None and (time.time() - t0) < 10:
                        cb = _btn()
                        if cb == "OK":
                            confirmed = True
                        elif cb in ("KEY2", "KEY3"):
                            confirmed = False
                        time.sleep(0.05)
                    if confirmed:
                        _delete_capture(cap["path"])
                        captures = _list_captures()
                        lib_selected = min(lib_selected, max(0, len(captures) - 1))
                        _draw_splash(lcd, "Deleted", "", COL_REPLAY)
                        time.sleep(0.8)

            time.sleep(0.05)

    finally:
        # Cleanup
        if recording:
            sdr.stop_recording()
            duration = time.time() - rec_start
            if rec_path:
                _write_metadata(
                    rec_path,
                    BANDS[band_idx]["freq"],
                    SAMPLE_RATE,
                    GAIN_STEPS[gain_idx],
                    duration,
                )
        _stop_tx()
        sdr.stop()
        lcd.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
