#!/usr/bin/env python3
"""
RaspyJack Payload -- SDR Radio Suite
======================================
Author: 7h30th3r0n3

Full-featured SDR radio suite with waterfall display, FM radio,
frequency scanner, band presets, settings, and IQ recording.

Supports RTL-SDR, HackRF, and any SoapySDR-compatible device.

Controls:
  UP/DOWN     : Adjust frequency / navigate menus
  LEFT/RIGHT  : Adjust bandwidth / change values
  OK (ENTER)  : Start/Stop / Select
  KEY1 (SPACE): Switch mode
  KEY2 (BKSP) : Direct freq entry / secondary action
  KEY3 (ESC)  : Exit / Back

Requires: apt install rtl-sdr
Optional: python3-soapysdr soapysdr-module-hackrf
"""

import os
import sys
import time
import signal
import threading
import json
from datetime import datetime
import numpy as np

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font, S, SX, SY

try:
    from payloads._input_helper import get_button
except ImportError:
    from payloads._input_helper import get_button

import evdev_keys
from payloads.sdr._sdr_core import SDRDevice, detect_sdr, compute_fft, start_fm_audio, stop_fm_audio
from payloads.sdr._waterfall import WaterfallBuffer, draw_spectrum, draw_signal_meter, draw_freq_scale, COLORMAPS
from payloads.sdr._presets import (
    BAND_PRESETS, FM_STATIONS, NOAA_CHANNELS,
    load_settings, save_settings, format_freq, format_freq_short,
)

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}

MODES = ["Waterfall", "FM Radio", "Scanner", "Presets", "Settings"]
MODE_COLORS = {
    "Waterfall": (0, 200, 255),
    "FM Radio": (0, 255, 100),
    "Scanner": (255, 200, 0),
    "Presets": (200, 100, 255),
    "Settings": (150, 150, 150),
}
DEBOUNCE = 0.15
_running = True


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGTERM, _sig)
signal.signal(signal.SIGINT, _sig)

GPIO.setmode(GPIO.BCM)
for p in PINS.values():
    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
font = scaled_font(9)
font_sm = scaled_font(7)
font_lg = scaled_font(14)
font_xl = scaled_font(22)


def _btn():
    return get_button(PINS, GPIO)


# ═══════════════════════════════════════════════════════════════
# SPLASH / DETECTION
# ═══════════════════════════════════════════════════════════════
def _splash(text, sub="", color=(0, 200, 255)):
    img = Image.new("RGB", (WIDTH, HEIGHT), (0, 0, 0))
    d = ScaledDraw(img)
    d.text((64, 45), text, font=font_lg, fill=color, anchor="mm")
    if sub:
        d.text((64, 65), sub, font=font_sm, fill=(100, 100, 100), anchor="mm")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_header(d, mode_name, extra=""):
    col = MODE_COLORS.get(mode_name, (200, 200, 200))
    d.rectangle((0, 0, 127, 11), fill=(10, 15, 25))
    d.text((2, 1), mode_name.upper(), font=font_sm, fill=col)
    if extra:
        d.text((80, 1), extra, font=font_sm, fill=(100, 100, 100))


def _draw_footer(d, text):
    d.rectangle((0, 117, 127, 127), fill=(10, 10, 15))
    d.text((2, 118), text, font=font_sm, fill=(60, 70, 90))


# ═══════════════════════════════════════════════════════════════

def _input_frequency(current_hz):
    """Direct frequency input screen. Returns frequency in Hz or None."""
    mhz_str = f"{current_hz / 1e6:.3f}"
    digits = list(mhz_str.replace(".", ""))
    cursor = 0
    dot_pos = mhz_str.index(".")

    while _running:
        img = Image.new("RGB", (WIDTH, HEIGHT), (0, 0, 0))
        d = ScaledDraw(img)
        d.rectangle((0, 0, 127, 11), fill=(10, 15, 25))
        d.text((2, 1), "ENTER FREQUENCY", font=font_sm, fill=(0, 200, 255))

        display = ""
        for i, ch in enumerate(digits):
            if i == dot_pos:
                display += "."
            display += ch

        char_w = SX(10)
        total_w = len(display) * char_w
        start_x = (WIDTH - total_w) // 2
        y = SY(40)

        for i, ch in enumerate(display):
            x = start_x + i * char_w
            real_idx = i if i < dot_pos else (i - 1 if i > dot_pos else -1)
            is_sel = real_idx == cursor and ch != "."
            if is_sel:
                pass
            c = (255, 255, 0) if is_sel else (150, 150, 150)
            d.text((x, y), ch, font=font_lg, fill=c)
            if is_sel:
                pass

        d.text((64, SY(75)), "MHz", font=font, fill=(0, 150, 100), anchor="mm")
        d.text((64, SY(90)), "^v:Digit L/R:Move", font=font_sm, fill=(80, 80, 100), anchor="mm")
        d.text((64, SY(100)), "OK:Confirm ESC:Cancel", font=font_sm, fill=(80, 80, 100), anchor="mm")

        LCD.LCD_ShowImage(img, 0, 0)

        btn = _btn()
        if btn == "KEY3":
            time.sleep(0.15)
            return None
        elif btn == "OK":
            try:
                rebuilt = ""
                for i, ch in enumerate(digits):
                    if i == dot_pos:
                        rebuilt += "."
                    rebuilt += ch
                freq_mhz = float(rebuilt)
                time.sleep(0.15)
                return int(freq_mhz * 1_000_000)
            except ValueError:
                pass
        elif btn == "UP":
            d_val = int(digits[cursor])
            digits[cursor] = str((d_val + 1) % 10)
            time.sleep(0.12)
        elif btn == "DOWN":
            d_val = int(digits[cursor])
            digits[cursor] = str((d_val - 1) % 10)
            time.sleep(0.12)
        elif btn == "LEFT":
            cursor = min(len(digits) - 1, cursor + 1)
            time.sleep(0.15)
        elif btn == "RIGHT":
            cursor = max(0, cursor - 1)
            time.sleep(0.15)
        time.sleep(0.03)
    return None

# MODE 1: WATERFALL
# ═══════════════════════════════════════════════════════════════
def _mode_waterfall(sdr, settings, wf_buf):
    freq = settings["center_freq"]
    bw = settings["sample_rate"]
    fft_size = settings["fft_size"]
    streaming = False
    recording = False
    rec_path = None
    step = 100_000
    last_fft = time.monotonic()
    fft_interval = 1.0 / settings["waterfall_fps"]
    current_fft = None

    img = Image.new("RGB", (WIDTH, HEIGHT), (0, 0, 0))
    spec_y0 = SY(14)
    spec_h = SY(30)
    wf_y0 = SY(46)
    wf_h = HEIGHT - wf_y0 - SY(20)
    meter_y = HEIGHT - SY(18)
    sig_db = -100.0
    frame_time = 1.0 / 12

    while _running:
        t0 = time.monotonic()
        img.paste((0, 0, 0), (0, 0, WIDTH, HEIGHT))
        d = ScaledDraw(img)
        raw_draw = ImageDraw.Draw(img)

        indicator = "●" if streaming else "○"
        rec_tag = " REC" if recording else ""
        _draw_header(d, "Waterfall", f"{indicator} {format_freq_short(freq)}{rec_tag}")

        if streaming and sdr.is_running:
            now = time.monotonic()
            if now - last_fft >= fft_interval:
                iq = sdr.get_iq_block(fft_size)
                current_fft = compute_fft(iq, fft_size)
                wf_buf.push_fft(current_fft)
                sig_db = 20 * np.log10(np.sqrt(np.mean(np.abs(iq) ** 2)) + 1e-10)
                last_fft = now

        if current_fft is not None:
            draw_spectrum(
                raw_draw, current_fft, SX(0), spec_y0, WIDTH, spec_h,
                color=(0, 255, 100), fill_color=(0, 40, 10),
                db_min=settings["db_min"], db_max=settings["db_max"],
            )
            wf_buf.render(img, SX(0), wf_y0, WIDTH, wf_h)
            draw_signal_meter(raw_draw, sig_db, SX(2), meter_y, SX(70), SY(8), font_sm)
        else:
            d.text((64, 60), "Press OK to start", font=font, fill=(60, 60, 80), anchor="mm")

        draw_freq_scale(raw_draw, freq, bw, SX(0), spec_y0 - SY(2), WIDTH, font_sm)
        # Draw frequency with active digit highlighted based on step
        mhz = freq / 1e6
        freq_str = f"{mhz:.3f} MHz"
        # Find which char index matches the step
        # "XXX.XXX MHz" - dot is at position where int part ends
        num_part = f"{mhz:.3f}"
        dot_idx = num_part.index(".")
        # step -> digit offset from dot: 100k=1st after, 10k=2nd, 1k=3rd, 1M=1st before, etc.
        step_to_offset = {
            1_000: 3, 10_000: 2, 100_000: 1,
            1_000_000: -1, 10_000_000: -2, 100_000_000: -3,
        }
        offset = step_to_offset.get(step)
        if offset is not None:
            if offset > 0:
                active_idx = dot_idx + offset
            else:
                active_idx = dot_idx + offset
        else:
            active_idx = -1
        try:
            total_w = int(font.getlength(freq_str))
        except Exception:
            total_w = len(freq_str) * SX(6)
        fx = (WIDTH - total_w) // 2
        fy = SY(13) - SY(5)
        for ci, ch in enumerate(freq_str):
            try:
                cw = int(font.getlength(ch))
            except Exception:
                cw = SX(6)
            c = (255, 255, 0) if ci == active_idx else (0, 255, 200)
            raw_draw.text((fx, fy), ch, fill=c, font=font)
            fx += cw
        footer = "^v:Freq OK:Run K1:Mode R:Rec" if streaming else "^v:Freq OK:Run K1:Mode"
        _draw_footer(d, footer)
        LCD.LCD_ShowImage(img, 0, 0)

        elapsed = time.monotonic() - t0
        if elapsed < frame_time:
            time.sleep(frame_time - elapsed)

        btn = _btn()
        if btn == "KEY3":
            if recording:
                sdr.stop_recording()
            if streaming:
                sdr.stop()
            return "exit"
        elif btn == "KEY1":
            if recording:
                sdr.stop_recording()
            if streaming:
                sdr.stop()
            time.sleep(0.25)
            return "next"
        elif btn == "OK":
            if streaming:
                sdr.stop()
                streaming = False
            else:
                sdr.start(freq, bw, settings["gain"])
                streaming = True
            time.sleep(DEBOUNCE)
        elif btn == "UP":
            freq += step
            settings["center_freq"] = freq
            if streaming:
                sdr.set_freq(freq)
            time.sleep(DEBOUNCE)
        elif btn == "DOWN":
            freq = max(24_000_000, freq - step)
            settings["center_freq"] = freq
            if streaming:
                sdr.set_freq(freq)
            time.sleep(DEBOUNCE)
        elif btn == "LEFT":
            step = min(100_000_000, step * 10)
            time.sleep(DEBOUNCE)
        elif btn == "RIGHT":
            step = max(1_000, step // 10)
            time.sleep(DEBOUNCE)
        elif btn == "KEY2":
            new_freq = _input_frequency(freq)
            if new_freq:
                freq = new_freq
                settings["center_freq"] = freq
                if streaming:
                    sdr.set_freq(freq)
            time.sleep(DEBOUNCE)
        # R key (evdev 19) = toggle recording
        if evdev_keys.is_key_pressed(19):
            if not recording and streaming:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                rec_path = f"/root/Raspyjack/loot/SDR/recordings/iq_{format_freq_short(freq)}_{ts}.raw"
                sdr.start_recording(rec_path)
                recording = True
            elif recording:
                sdr.stop_recording()
                recording = False
                rec_path = None
            time.sleep(0.3)

        time.sleep(0.02)
    return "exit"


# ═══════════════════════════════════════════════════════════════
# MODE 2: FM RADIO
# ═══════════════════════════════════════════════════════════════
def _mode_fm(sdr, settings):
    freq = settings.get("center_freq", 97_750_000)
    if freq < 87_500_000 or freq > 108_000_000:
        freq = 97_750_000
    playing = False
    fm_proc = None
    preset_idx = 0
    step = 100_000

    while _running:
        img = Image.new("RGB", (WIDTH, HEIGHT), (0, 0, 0))
        d = ScaledDraw(img)

        indicator = "▶" if playing else "■"
        _draw_header(d, "FM Radio", indicator)

        mhz = freq / 1_000_000
        d.text((64, 40), f"{mhz:.1f}", font=font_xl, fill=(0, 255, 100), anchor="mm")
        d.text((64, 55), "MHz", font=font_sm, fill=(0, 150, 60), anchor="mm")

        station = ""
        for name, f in FM_STATIONS:
            if abs(f - freq) < 50_000:
                station = name
                break
        if station:
            d.text((64, 68), station, font=font, fill=(255, 180, 0), anchor="mm")

        dial_y = 78
        dial_x = 4
        dial_w = 120
        d.rectangle((dial_x, dial_y, dial_x + dial_w, dial_y + 6), fill=(20, 20, 30), outline=(40, 40, 50))
        pos = (freq - 87_500_000) / (108_000_000 - 87_500_000)
        cursor_x = dial_x + int(dial_w * pos)
        d.rectangle((cursor_x - 1, dial_y - 1, cursor_x + 2, dial_y + 7), fill=(0, 255, 100))
        d.text((dial_x, dial_y + 9), "87.5", font=font_sm, fill=(60, 60, 80))
        d.text((dial_x + dial_w - 15, dial_y + 9), "108", font=font_sm, fill=(60, 60, 80))

        if playing:
            d.text((64, 100), "PLAYING", font=font_sm, fill=(0, 200, 0), anchor="mm")
        else:
            d.text((64, 100), "STOPPED", font=font_sm, fill=(100, 100, 100), anchor="mm")

        _draw_footer(d, "^v:Tune OK:Play K1:Mode")
        LCD.LCD_ShowImage(img, 0, 0)

        btn = _btn()
        if btn == "KEY3":
            if fm_proc:
                stop_fm_audio(fm_proc)
            return "exit"
        elif btn == "KEY1":
            if fm_proc:
                stop_fm_audio(fm_proc)
            time.sleep(0.25)
            return "next"
        elif btn == "OK":
            if playing:
                stop_fm_audio(fm_proc)
                fm_proc = None
                playing = False
            else:
                fm_proc = start_fm_audio(freq, settings.get("audio_device", "default"))
                playing = True
            time.sleep(DEBOUNCE)
        elif btn == "UP":
            freq = min(108_000_000, freq + step)
            settings["center_freq"] = freq
            if playing:
                stop_fm_audio(fm_proc)
                fm_proc = start_fm_audio(freq, settings.get("audio_device", "default"))
            time.sleep(DEBOUNCE)
        elif btn == "DOWN":
            freq = max(87_500_000, freq - step)
            settings["center_freq"] = freq
            if playing:
                stop_fm_audio(fm_proc)
                fm_proc = start_fm_audio(freq, settings.get("audio_device", "default"))
            time.sleep(DEBOUNCE)
        elif btn == "RIGHT":
            preset_idx = (preset_idx + 1) % len(FM_STATIONS)
            freq = FM_STATIONS[preset_idx][1]
            settings["center_freq"] = freq
            if playing:
                stop_fm_audio(fm_proc)
                fm_proc = start_fm_audio(freq, settings.get("audio_device", "default"))
            time.sleep(DEBOUNCE)
        elif btn == "LEFT":
            preset_idx = (preset_idx - 1) % len(FM_STATIONS)
            freq = FM_STATIONS[preset_idx][1]
            settings["center_freq"] = freq
            if playing:
                stop_fm_audio(fm_proc)
                fm_proc = start_fm_audio(freq, settings.get("audio_device", "default"))
            time.sleep(DEBOUNCE)
        time.sleep(0.05)
    if fm_proc:
        stop_fm_audio(fm_proc)
    return "exit"


# ═══════════════════════════════════════════════════════════════
# MODE 3: SCANNER
# ═══════════════════════════════════════════════════════════════
def _mode_scanner(sdr, settings):
    import subprocess, numpy as np
    preset_idx = settings.get("last_preset", 0) % len(BAND_PRESETS)
    scanning = False
    spectrum = None       # array of dB values across the band
    peak_hold = None      # max dB seen at each bin
    cursor_bin = 0        # selected frequency bin
    _scan_active = [False]

    def _sweep_loop(preset, result, active):
        """Continuous rtl_power sweep in background."""
        while active[0] and _running:
            try:
                cmd = [
                    "rtl_power", "-f",
                    f"{preset['start']}:{preset['end']}:{max(preset['step'], 25000)}",
                    "-g", "49.6", "-i", "1", "-1",
                ]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                bins = []
                for line in proc.stdout.strip().splitlines():
                    parts = line.split(",")
                    if len(parts) >= 7:
                        db_vals = [float(x.strip()) for x in parts[6:] if x.strip()]
                        bins.extend(db_vals)
                if bins:
                    result[0] = bins
            except Exception:
                pass

    sweep_result = [None]
    sweep_thread = None

    while _running:
        preset = BAND_PRESETS[preset_idx]
        img = Image.new("RGB", (WIDTH, HEIGHT), (0, 0, 0))
        d = ScaledDraw(img)

        indicator = "●" if scanning else "○"
        _draw_header(d, "Scanner", f"{indicator} {preset['name']}")

        # Spectrum display area (128-base coords, ScaledDraw scales them)
        spec_x, spec_y = 2, 14
        spec_w, spec_h = 124, 60

        # Update spectrum from sweep result
        if sweep_result[0] is not None:
            spectrum = sweep_result[0]
            sweep_result[0] = None
            if peak_hold is None or len(peak_hold) != len(spectrum):
                peak_hold = list(spectrum)
            else:
                for i in range(len(spectrum)):
                    peak_hold[i] = max(peak_hold[i], spectrum[i])

        # Draw spectrum bars
        if spectrum and len(spectrum) > 0:
            n = len(spectrum)
            threshold = settings["scanner_threshold"]
            # Auto-scale dB range from actual data
            db_min = min(spectrum) - 5
            db_max = max(spectrum) + 5

            for i in range(min(spec_w, n)):
                bin_idx = int(i * n / spec_w)
                db = spectrum[bin_idx]
                norm = max(0, min(1, (db - db_min) / (db_max - db_min)))
                bar_h = int(norm * spec_h)
                x = spec_x + i
                y_bottom = spec_y + spec_h

                # Color: blue below threshold, green above, red for strong
                if db > -25:
                    col = (255, 50, 50)
                elif db > threshold:
                    col = (0, 200, 0)
                else:
                    col = (30, 40, 60)
                if bar_h > 0:
                    d.line([(x, y_bottom), (x, y_bottom - bar_h)], fill=col)

                # Peak hold dots
                if peak_hold:
                    pk = peak_hold[bin_idx]
                    pk_norm = max(0, min(1, (pk - db_min) / (db_max - db_min)))
                    pk_y = y_bottom - int(pk_norm * spec_h)
                    d.rectangle((x, pk_y, x, pk_y), fill=(255, 255, 0))

            # Threshold line
            thr_norm = max(0, min(1, (threshold - db_min) / (db_max - db_min)))
            thr_y = spec_y + spec_h - int(thr_norm * spec_h)
            d.line([(spec_x, thr_y), (spec_x + spec_w, thr_y)], fill=(255, 100, 0))

            # Cursor
            cx = spec_x + int(cursor_bin * spec_w / max(1, n))
            d.line([(cx, spec_y), (cx, spec_y + spec_h)], fill=(255, 255, 255))

            # Cursor frequency + dB info
            cursor_freq = preset["start"] + int(cursor_bin * (preset["end"] - preset["start"]) / max(1, n))
            cursor_db = spectrum[min(cursor_bin, n - 1)]
            d.text((2, 76), f"{format_freq(cursor_freq)}", font=font_sm, fill=(0, 255, 200))
            d.text((70, 76), f"{cursor_db:.1f}dB", font=font_sm, fill=(200, 200, 200))

            # Count signals above threshold
            above = sum(1 for db in spectrum if db > threshold)
            d.text((2, 86), f"{above} active | Thr:{threshold}dB", font=font_sm, fill=(100, 100, 100))

            # Frequency scale
            d.text((2, 96), format_freq_short(preset["start"]), font=font_sm, fill=(60, 60, 80))
            mid = (preset["start"] + preset["end"]) // 2
            d.text((50, 96), format_freq_short(mid), font=font_sm, fill=(60, 60, 80))
            d.text((100, 96), format_freq_short(preset["end"]), font=font_sm, fill=(60, 60, 80))
        else:
            d.text((64, 50), "OK to scan" if not scanning else "Scanning...", font=font, fill=(60, 60, 80), anchor="mm")

        _draw_footer(d, "OK:Scan UD:Band LR:Cursor")
        LCD.LCD_ShowImage(img, 0, 0)

        btn = _btn()
        if btn == "KEY3":
            _scan_active[0] = False
            sdr.stop()
            return "exit"
        elif btn == "KEY1":
            _scan_active[0] = False
            sdr.stop()
            time.sleep(0.25)
            return "next"
        elif btn == "OK":
            if scanning:
                scanning = False
                _scan_active[0] = False
            else:
                scanning = True
                _scan_active[0] = True
                peak_hold = None
                sweep_thread = threading.Thread(target=_sweep_loop, args=(preset, sweep_result, _scan_active), daemon=True)
                sweep_thread.start()
            time.sleep(DEBOUNCE)
        elif btn == "UP":
            preset_idx = (preset_idx - 1) % len(BAND_PRESETS)
            settings["last_preset"] = preset_idx
            spectrum = None
            peak_hold = None
            if scanning:
                _scan_active[0] = False
                scanning = False
            time.sleep(DEBOUNCE)
        elif btn == "DOWN":
            preset_idx = (preset_idx + 1) % len(BAND_PRESETS)
            settings["last_preset"] = preset_idx
            spectrum = None
            peak_hold = None
            if scanning:
                _scan_active[0] = False
                scanning = False
            time.sleep(DEBOUNCE)
        elif btn == "LEFT":
            if spectrum:
                cursor_bin = max(0, cursor_bin - max(1, len(spectrum) // 20))
            time.sleep(DEBOUNCE)
        elif btn == "RIGHT":
            if spectrum:
                cursor_bin = min(len(spectrum) - 1, cursor_bin + max(1, len(spectrum) // 20))
            time.sleep(DEBOUNCE)
        time.sleep(0.05)
    return "exit"


    return "exit"


_scan_pct = [0.0]
_scan_thread = None

def _set_progress(p):
    _scan_pct[0] = p

def _scan_band(sdr, settings, preset, signals, progress_cb):
    """Scan using rtl_power for fast wideband sweep."""
    import subprocess, csv, io
    start = preset["start"]
    end = preset["end"]
    step = max(preset["step"], 25_000)
    threshold = settings["scanner_threshold"]
    bw = min(2_048_000, end - start + step)

    # rtl_power does a single fast sweep across the entire band
    cmd = [
        "rtl_power", "-f", f"{start}:{end}:{step}",
        "-g", "49.6", "-i", "1", "-1", "-F", "csv",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        lines = proc.stdout.strip().splitlines()
        total = max(1, len(lines))
        for i, line in enumerate(lines):
            if not _running:
                break
            try:
                parts = line.split(",")
                if len(parts) >= 7:
                    freq_low = int(float(parts[2].strip()))
                    freq_step = float(parts[4].strip())
                    db_values = [float(x.strip()) for x in parts[6:] if x.strip()]
                    for j, db in enumerate(db_values):
                        f = freq_low + int(j * freq_step)
                        if db > threshold:
                            signals.append({"freq": f, "db": round(db, 1)})
            except Exception:
                pass
            progress_cb((i + 1) / total)
    except subprocess.TimeoutExpired:
        pass
    except FileNotFoundError:
        # Fallback to slow method if rtl_power not available
        freq = start
        total_steps = max(1, (end - start) // step)
        idx = 0
        sdr.start(start, 2_048_000, settings.get("gain", 30))
        time.sleep(0.3)
        while freq <= end and _running:
            sdr.set_freq(freq)
            time.sleep(0.1)
            sig_db = sdr.get_signal_db()
            if sig_db > threshold:
                signals.append({"freq": freq, "db": sig_db})
            idx += 1
            progress_cb(idx / total_steps)
            freq += step
        sdr.stop()
    progress_cb(1.0)


# ═══════════════════════════════════════════════════════════════
# MODE 4: PRESETS
# ═══════════════════════════════════════════════════════════════
def _mode_presets(settings):
    cursor = settings.get("last_preset", 0)
    scroll = 0

    while _running:
        img = Image.new("RGB", (WIDTH, HEIGHT), (0, 0, 0))
        d = ScaledDraw(img)
        _draw_header(d, "Presets")

        visible = max(1, (HEIGHT - SY(24)) // SY(13))
        for i in range(min(visible, len(BAND_PRESETS) - scroll)):
            idx = scroll + i
            p = BAND_PRESETS[idx]
            y = SY(14) + i * SY(13)
            is_sel = idx == cursor
            if is_sel:
                d.rectangle((0, y - 1, 127, y + SY(11)), fill=(0, 30, 60))
            col = (255, 255, 255) if is_sel else (100, 150, 200)
            d.text((SX(3), y), p["name"][:14], font=font_sm, fill=col)
            d.text((SX(75), y), format_freq_short(p["freq"]), font=font_sm, fill=(0, 200, 100) if is_sel else (60, 100, 60))
            d.text((SX(110), y), p["mode"][:3], font=font_sm, fill=(150, 150, 150))

        _draw_footer(d, "OK:Select ^v:Scroll K3:Back")
        LCD.LCD_ShowImage(img, 0, 0)

        btn = _btn()
        if btn == "KEY3":
            return "exit", None
        elif btn == "KEY1":
            time.sleep(0.25)
            return "next", None
        elif btn == "UP":
            cursor = max(0, cursor - 1)
            if cursor < scroll:
                scroll = cursor
            time.sleep(DEBOUNCE)
        elif btn == "DOWN":
            cursor = min(len(BAND_PRESETS) - 1, cursor + 1)
            if cursor >= scroll + visible:
                scroll = cursor - visible + 1
            time.sleep(DEBOUNCE)
        elif btn in ("OK", "RIGHT"):
            p = BAND_PRESETS[cursor]
            settings["center_freq"] = p["freq"]
            settings["sample_rate"] = min(2_048_000, max(250_000, p["end"] - p["start"]))
            settings["last_preset"] = cursor
            return "waterfall", p
        time.sleep(0.05)
    return "exit", None


# ═══════════════════════════════════════════════════════════════
# MODE 5: SETTINGS
# ═══════════════════════════════════════════════════════════════
def _mode_settings(settings):
    items = [
        ("Gain", "gain", 0, 49, 1),
        ("FFT Size", "fft_size", 0, 0, 0),
        ("Colormap", "colormap", 0, 0, 0),
        ("dB Min", "db_min", -100, -20, 5),
        ("dB Max", "db_max", -40, 0, 5),
        ("WF FPS", "waterfall_fps", 4, 20, 2),
        ("Scan Thr", "scanner_threshold", -80, -10, 5),
        ("Scan Dwell", "scanner_dwell", 0, 0, 0),
    ]
    fft_opts = [64, 128, 256, 512, 1024]
    cmap_opts = list(COLORMAPS.keys())
    dwell_opts = [0.1, 0.2, 0.3, 0.5, 1.0]
    cursor = 0

    while _running:
        img = Image.new("RGB", (WIDTH, HEIGHT), (0, 0, 0))
        d = ScaledDraw(img)
        _draw_header(d, "Settings")

        visible = max(1, (HEIGHT - SY(24)) // SY(13))
        scroll = max(0, cursor - visible + 1) if cursor >= visible else 0
        for i in range(min(visible, len(items) - scroll)):
            idx = scroll + i
            label, key, _, _, _ = items[idx]
            y = SY(14) + i * SY(13)
            is_sel = idx == cursor

            if is_sel:
                d.rectangle((0, y - 1, 127, y + SY(11)), fill=(0, 30, 60))

            val = settings.get(key, "?")
            if key == "colormap":
                val_str = str(val)
            elif key == "scanner_dwell":
                val_str = f"{val}s"
            else:
                val_str = str(val)

            col = (255, 255, 255) if is_sel else (100, 150, 200)
            d.text((SX(3), y), f"{label}:", font=font_sm, fill=col)
            val_col = (0, 255, 100) if is_sel else (60, 150, 60)
            d.text((SX(70), y), f"< {val_str} >", font=font_sm, fill=val_col)

        _draw_footer(d, "L/R:Change K2:Save K3:Back")
        LCD.LCD_ShowImage(img, 0, 0)

        btn = _btn()
        if btn == "KEY3":
            return "exit"
        elif btn == "KEY1":
            time.sleep(0.25)
            return "next"
        elif btn == "UP":
            cursor = max(0, cursor - 1)
            time.sleep(DEBOUNCE)
        elif btn == "DOWN":
            cursor = min(len(items) - 1, cursor + 1)
            time.sleep(DEBOUNCE)
        elif btn in ("RIGHT", "OK"):
            label, key, mn, mx, step = items[cursor]
            if key == "fft_size":
                ci = fft_opts.index(settings[key]) if settings[key] in fft_opts else 2
                settings[key] = fft_opts[(ci + 1) % len(fft_opts)]
            elif key == "colormap":
                ci = cmap_opts.index(settings[key]) if settings[key] in cmap_opts else 0
                settings[key] = cmap_opts[(ci + 1) % len(cmap_opts)]
            elif key == "scanner_dwell":
                ci = dwell_opts.index(settings[key]) if settings[key] in dwell_opts else 2
                settings[key] = dwell_opts[(ci + 1) % len(dwell_opts)]
            elif step > 0:
                settings[key] = min(mx, settings[key] + step)
            time.sleep(0.2)
        elif btn == "LEFT":
            label, key, mn, mx, step = items[cursor]
            if key == "fft_size":
                ci = fft_opts.index(settings[key]) if settings[key] in fft_opts else 2
                settings[key] = fft_opts[(ci - 1) % len(fft_opts)]
            elif key == "colormap":
                ci = cmap_opts.index(settings[key]) if settings[key] in cmap_opts else 0
                settings[key] = cmap_opts[(ci - 1) % len(cmap_opts)]
            elif key == "scanner_dwell":
                ci = dwell_opts.index(settings[key]) if settings[key] in dwell_opts else 2
                settings[key] = dwell_opts[(ci - 1) % len(dwell_opts)]
            elif step > 0:
                settings[key] = max(mn, settings[key] - step)
            time.sleep(0.2)
        elif btn == "KEY2":
            save_settings(settings)
            _splash("Settings saved!", color=(0, 255, 100))
            time.sleep(1)
        time.sleep(0.05)
    return "exit"


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════
def main():
    _splash("SDR Radio Suite", "Detecting hardware...")

    found, hw_name, backend = detect_sdr()
    if not found:
        _splash("No SDR found!", "Connect RTL-SDR/HackRF", color=(255, 60, 60))
        time.sleep(0.5)
        _splash("No SDR found!", "Press any key to exit", color=(255, 60, 60))
        _btn()
        LCD.LCD_Clear()
        GPIO.cleanup()
        return 0

    _splash(f"Found: {hw_name}", f"Backend: {backend}", color=(0, 255, 100))
    time.sleep(1.5)

    settings = load_settings()
    sdr = SDRDevice()

    wf_w = WIDTH
    wf_h = HEIGHT - SY(60)
    wf_buf = WaterfallBuffer(wf_w, max(10, wf_h), settings["colormap"])
    wf_buf.set_range(settings["db_min"], settings["db_max"])

    mode_idx = 0

    try:
        while _running:
            mode = MODES[mode_idx]
            wf_buf.set_colormap(settings["colormap"])
            wf_buf.set_range(settings["db_min"], settings["db_max"])

            if mode == "Waterfall":
                result = _mode_waterfall(sdr, settings, wf_buf)
            elif mode == "FM Radio":
                result = _mode_fm(sdr, settings)
            elif mode == "Scanner":
                result = _mode_scanner(sdr, settings)
            elif mode == "Presets":
                result, preset = _mode_presets(settings)
                if result == "waterfall" and preset:
                    mode_idx = 0
                    continue
            elif mode == "Settings":
                result = _mode_settings(settings)
            else:
                result = "next"

            if result == "exit":
                break
            elif result == "next":
                mode_idx = (mode_idx + 1) % len(MODES)

    finally:
        sdr.stop()
        save_settings(settings)
        LCD.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
