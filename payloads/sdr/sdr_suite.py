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

        dial_y = SY(80)
        dial_w = SX(120)
        dial_x = SX(4)
        d.rectangle((dial_x, dial_y, dial_x + dial_w, dial_y + SY(6)), fill=(20, 20, 30), outline=(40, 40, 50))
        pos = (freq - 87_500_000) / (108_000_000 - 87_500_000)
        cursor_x = dial_x + int(dial_w * pos)
        d.rectangle((cursor_x - 1, dial_y - 1, cursor_x + 2, dial_y + SY(7)), fill=(0, 255, 100))
        d.text((dial_x, dial_y + SY(8)), "87.5", font=font_sm, fill=(60, 60, 80))
        d.text((dial_x + dial_w - SX(15), dial_y + SY(8)), "108", font=font_sm, fill=(60, 60, 80))

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
                fm_proc = start_fm_audio(freq, settings.get("audio_device", "plughw:1,0"))
                playing = True
            time.sleep(DEBOUNCE)
        elif btn == "UP":
            freq = min(108_000_000, freq + step)
            settings["center_freq"] = freq
            if playing:
                stop_fm_audio(fm_proc)
                fm_proc = start_fm_audio(freq, settings.get("audio_device", "plughw:1,0"))
            time.sleep(DEBOUNCE)
        elif btn == "DOWN":
            freq = max(87_500_000, freq - step)
            settings["center_freq"] = freq
            if playing:
                stop_fm_audio(fm_proc)
                fm_proc = start_fm_audio(freq, settings.get("audio_device", "plughw:1,0"))
            time.sleep(DEBOUNCE)
        elif btn == "RIGHT":
            preset_idx = (preset_idx + 1) % len(FM_STATIONS)
            freq = FM_STATIONS[preset_idx][1]
            settings["center_freq"] = freq
            if playing:
                stop_fm_audio(fm_proc)
                fm_proc = start_fm_audio(freq, settings.get("audio_device", "plughw:1,0"))
            time.sleep(DEBOUNCE)
        elif btn == "LEFT":
            preset_idx = (preset_idx - 1) % len(FM_STATIONS)
            freq = FM_STATIONS[preset_idx][1]
            settings["center_freq"] = freq
            if playing:
                stop_fm_audio(fm_proc)
                fm_proc = start_fm_audio(freq, settings.get("audio_device", "plughw:1,0"))
            time.sleep(DEBOUNCE)
        time.sleep(0.05)
    if fm_proc:
        stop_fm_audio(fm_proc)
    return "exit"


# ═══════════════════════════════════════════════════════════════
# MODE 3: SCANNER
# ═══════════════════════════════════════════════════════════════
def _mode_scanner(sdr, settings):
    preset_idx = settings.get("last_preset", 0) % len(BAND_PRESETS)
    scanning = False
    signals = []
    scan_progress = 0.0
    scroll = 0

    while _running:
        preset = BAND_PRESETS[preset_idx]
        img = Image.new("RGB", (WIDTH, HEIGHT), (0, 0, 0))
        d = ScaledDraw(img)

        status = "SCANNING" if scanning else "IDLE"
        _draw_header(d, "Scanner", status)

        d.text((2, 13), preset["name"], font=font, fill=(255, 200, 0))
        d.text((2, 24), f"{format_freq_short(preset['start'])} - {format_freq_short(preset['end'])}", font=font_sm, fill=(100, 100, 100))

        if scanning:
            bar_y = SY(34)
            d.rectangle((SX(2), bar_y, SX(125), bar_y + SY(5)), fill=(20, 20, 30), outline=(40, 40, 50))
            d.rectangle((SX(2), bar_y, SX(2) + int(SX(123) * scan_progress), bar_y + SY(5)), fill=(255, 200, 0))

        list_y = SY(42)
        visible = max(1, (HEIGHT - list_y - SY(12)) // SY(11))
        if signals:
            for i in range(min(visible, len(signals) - scroll)):
                idx = scroll + i
                sig = signals[idx]
                y = list_y + i * SY(11)
                strength = min(SX(30), max(1, int((sig["db"] + 80) / 60 * SX(30))))
                d.text((SX(2), y), format_freq_short(sig["freq"]), font=font_sm, fill=(0, 255, 0))
                d.text((SX(45), y), f"{sig['db']:.0f}dB", font=font_sm, fill=(200, 200, 200))
                bar_col = (0, 200, 0) if sig["db"] > -30 else (0, 100, 200)
                d.rectangle((SX(75), y + 1, SX(75) + strength, y + SY(7)), fill=bar_col)
        else:
            d.text((64, 70), "No signals" if not scanning else "Scanning...", font=font, fill=(60, 60, 80), anchor="mm")

        d.text((SX(2), HEIGHT - SY(18)), f"Found: {len(signals)} | Thr: {settings['scanner_threshold']}dB", font=font_sm, fill=(100, 100, 100))
        _draw_footer(d, "^v:Band OK:Scan K1:Mode")
        LCD.LCD_ShowImage(img, 0, 0)

        btn = _btn()
        if btn == "KEY3":
            sdr.stop()
            return "exit"
        elif btn == "KEY1":
            sdr.stop()
            time.sleep(0.25)
            return "next"
        elif btn == "OK":
            if scanning:
                scanning = False
                sdr.stop()
            else:
                scanning = True
                signals = []
                scan_progress = 0
                threading.Thread(target=_scan_band, args=(sdr, settings, preset, signals, lambda p: _set_progress(p)), daemon=True).start()
            time.sleep(DEBOUNCE)
        elif btn == "UP":
            preset_idx = (preset_idx - 1) % len(BAND_PRESETS)
            settings["last_preset"] = preset_idx
            time.sleep(DEBOUNCE)
        elif btn == "DOWN":
            preset_idx = (preset_idx + 1) % len(BAND_PRESETS)
            settings["last_preset"] = preset_idx
            time.sleep(DEBOUNCE)
        elif btn == "RIGHT":
            settings["scanner_threshold"] = min(-10, settings["scanner_threshold"] + 5)
            time.sleep(DEBOUNCE)
        elif btn == "LEFT":
            settings["scanner_threshold"] = max(-80, settings["scanner_threshold"] - 5)
            time.sleep(DEBOUNCE)
        time.sleep(0.05)
    return "exit"


_scan_pct = [0.0]

def _set_progress(p):
    _scan_pct[0] = p

def _scan_band(sdr, settings, preset, signals, progress_cb):
    start = preset["start"]
    end = preset["end"]
    step = max(preset["step"], 25_000)
    threshold = settings["scanner_threshold"]
    dwell = settings["scanner_dwell"]
    freq = start
    total_steps = max(1, (end - start) // step)
    i = 0

    sdr.start(start, 2_048_000, settings["gain"])
    time.sleep(0.5)

    while freq <= end and _running:
        sdr.set_freq(freq)
        time.sleep(dwell)
        sig_db = sdr.get_signal_db()
        if sig_db > threshold:
            signals.append({"freq": freq, "db": sig_db})
        i += 1
        progress_cb(i / total_steps)
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
