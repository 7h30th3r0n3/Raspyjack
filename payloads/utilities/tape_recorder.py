#!/usr/bin/env python3
"""
RaspyJack Payload -- Tape Recorder
====================================
Author: 7h30th3r0n3

Audio recorder using the ES8389 built-in microphone.
Enables PIO_G9 (AU_EN) LOW to activate analog mic input.

Controls:
  OK          Start/Stop recording
  UP/DOWN     Navigate recordings list
  KEY1        Play/Stop selected recording
  KEY2        Delete selected recording
  KEY3        Exit
"""

import os
import sys
import time
import signal
import subprocess
import struct
import math
import threading
import json
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font, SX, SY
from payloads._input_helper import get_button
from payloads._audio_helper import get_audio_card, get_alsa_dev

try:
    import evdev_keys
    EVDEV_OK = True
except ImportError:
    EVDEV_OK = False

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
IS_WIDE = W > 200

if IS_WIDE:
    from PIL import ImageFont
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 16)
        font_sm = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 12)
        font_lg = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 20)
    except Exception:
        font = scaled_font(9)
        font_sm = scaled_font(7)
        font_lg = scaled_font(14)
else:
    font = scaled_font(9)
    font_sm = scaled_font(7)
    font_lg = font

LOOT_DIR = "/root/Raspyjack/loot/Recordings"
RATE = 16000
CHANNELS = 1
FORMAT = "S16_LE"
DEBOUNCE = 0.20

_running = True
_recording = False
_playing = False
_rec_proc = None
_play_proc = None
_rec_start = 0.0
_play_start = 0.0
_level_rms = 0
_alsa_dev = "default"
_volume = 25

C_BG = (10, 10, 15)
C_HEAD = (40, 0, 0)
C_RED = (255, 50, 50)
C_RED_BRIGHT = (255, 0, 0)
C_GREEN = (0, 200, 80)
C_WHITE = (255, 255, 255)
C_DIM = (100, 100, 100)
C_DARK = (30, 30, 35)
C_SEL = (50, 15, 15)
C_METER_LO = (0, 200, 80)
C_METER_MID = (200, 200, 0)
C_METER_HI = (255, 50, 50)
C_TAPE = (80, 60, 40)


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _detect_alsa_dev():
    global _alsa_dev
    try:
        r = subprocess.run(["aplay", "-l"], capture_output=True, text=True, timeout=3)
        for line in r.stdout.split("\n"):
            if "card" in line.lower() and ":" in line:
                card_num = line.split(":")[0].replace("card", "").strip()
                if any(k in line.upper() for k in ["ES8388", "ES8389", "ES8390"]):
                    _alsa_dev = f"plughw:{card_num},0"
                    return
                elif "HDMI" not in line.upper():
                    _alsa_dev = f"plughw:{card_num},0"
    except Exception:
        pass


def _enable_mic():
    """Enable analog mic: PIO_G9 LOW + AMIC mode + gain up."""
    subprocess.run(
        ["i2cset", "-f", "-y", "1", "0x4f", "0x06", "0x01"],
        capture_output=True, timeout=2)
    subprocess.run(
        ["amixer", "-c", get_audio_card(), "cset", "name=ADC MUX", "0"],
        capture_output=True, timeout=2)
    subprocess.run(
        ["amixer", "-c", get_audio_card(), "cset", "name=ADCL PGA Volume", "12"],
        capture_output=True, timeout=2)
    subprocess.run(
        ["amixer", "-c", get_audio_card(), "cset", "name=ADCR PGA Volume", "12"],
        capture_output=True, timeout=2)
    subprocess.run(
        ["amixer", "-c", get_audio_card(), "cset", "name=ADCL Capture Volume", "220"],
        capture_output=True, timeout=2)
    subprocess.run(
        ["amixer", "-c", get_audio_card(), "cset", "name=ADCR Capture Volume", "220"],
        capture_output=True, timeout=2)


def _disable_mic():
    """Restore PIO_G9 HIGH (default state)."""
    subprocess.run(
        ["i2cset", "-f", "-y", "1", "0x4f", "0x06", "0x03"],
        capture_output=True, timeout=2)


def _ensure_loot_dir():
    os.makedirs(LOOT_DIR, exist_ok=True)


def _list_recordings():
    _ensure_loot_dir()
    files = sorted(
        [f for f in os.listdir(LOOT_DIR) if f.endswith(".wav")],
        reverse=True)
    return files


def _get_wav_duration(path):
    try:
        r = subprocess.run(
            ["soxi", "-D", path],
            capture_output=True, text=True, timeout=3)
        return float(r.stdout.strip())
    except Exception:
        pass
    try:
        import wave
        with wave.open(path, "rb") as w:
            return w.getnframes() / w.getframerate()
    except Exception:
        return 0.0


def _fmt_duration(secs):
    m = int(secs) // 60
    s = int(secs) % 60
    return f"{m}:{s:02d}"


def _fmt_size(path):
    try:
        sz = os.path.getsize(path)
        if sz < 1024:
            return f"{sz}B"
        if sz < 1024 * 1024:
            return f"{sz // 1024}KB"
        return f"{sz // (1024 * 1024)}MB"
    except Exception:
        return "?"


_level_lock = threading.Lock()
_rec_path = ""
_wav_file = None


def _start_recording():
    global _recording, _rec_proc, _rec_start, _level_rms, _rec_path, _wav_file
    _ensure_loot_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    _rec_path = os.path.join(LOOT_DIR, f"rec_{ts}.wav")
    _enable_mic()
    time.sleep(0.2)
    _rec_proc = subprocess.Popen(
        ["arecord", "-D", _alsa_dev, "-f", FORMAT, "-r", str(RATE),
         "-c", str(CHANNELS), "-t", "raw"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    _rec_start = time.time()
    _level_rms = 0
    _recording = True

    import wave
    _wav_file = wave.open(_rec_path, "wb")
    _wav_file.setnchannels(CHANNELS)
    _wav_file.setsampwidth(2)
    _wav_file.setframerate(RATE)

    t = threading.Thread(target=_rec_writer_thread, daemon=True)
    t.start()
    return _rec_path


def _rec_writer_thread():
    global _level_rms
    chunk_size = RATE * 2 // 10
    try:
        while _recording and _running and _rec_proc and _rec_proc.poll() is None:
            raw = _rec_proc.stdout.read(chunk_size)
            if not raw:
                break
            if _wav_file:
                _wav_file.writeframes(raw)
            n = len(raw) // 2
            if n > 0:
                samples = struct.unpack(f"<{n}h", raw)
                rms = math.sqrt(sum(s * s for s in samples) / n)
                with _level_lock:
                    _level_rms = min(int(rms), 32768)
    except Exception:
        pass


def _stop_recording():
    global _recording, _rec_proc, _wav_file
    _recording = False
    if _rec_proc and _rec_proc.poll() is None:
        _rec_proc.terminate()
        try:
            _rec_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            _rec_proc.kill()
    _rec_proc = None
    if _wav_file:
        try:
            _wav_file.close()
        except Exception:
            pass
        _wav_file = None
    _disable_mic()


def _set_volume(vol):
    global _volume
    _volume = max(0, min(63, vol))
    card = get_audio_card()
    dac_val = int(75 + (_volume / 63 * 180))
    subprocess.run(["amixer", "-c", card, "sset", "Headphone", str(_volume)],
                   capture_output=True, timeout=2)
    subprocess.run(["amixer", "-c", card, "sset", "DACL", str(dac_val)],
                   capture_output=True, timeout=2)
    subprocess.run(["amixer", "-c", card, "sset", "DACR", str(dac_val)],
                   capture_output=True, timeout=2)
    try:
        import smbus2
        bus = smbus2.SMBus(1)
        bus.write_byte_data(0x60, 0x01, 0xC0, force=True)
        bus.close()
    except Exception:
        pass


def _start_playback(path):
    global _playing, _play_proc, _play_start
    _disable_mic()
    _set_volume(_volume)
    subprocess.run(
        ["amixer", "-c", get_audio_card(), "sset", "DACL", "180"],
        capture_output=True, timeout=2)
    subprocess.run(
        ["amixer", "-c", get_audio_card(), "sset", "DACR", "180"],
        capture_output=True, timeout=2)
    _play_proc = subprocess.Popen(
        ["aplay", "-D", _alsa_dev, path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _play_start = time.time()
    _playing = True


def _stop_playback():
    global _playing, _play_proc
    if _play_proc and _play_proc.poll() is None:
        _play_proc.terminate()
        try:
            _play_proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            _play_proc.kill()
    _play_proc = None
    _playing = False


def _delete_recording(path):
    try:
        os.remove(path)
    except Exception:
        pass


def _draw_meter(d, x, y, w_bar, h_bar, level):
    d.rectangle([x, y, x + w_bar, y + h_bar], fill=C_DARK)
    if level <= 0:
        return
    ratio = min(level / 20000, 1.0)
    fill_w = int(w_bar * ratio)
    if fill_w < 1:
        return
    if ratio < 0.5:
        color = C_METER_LO
    elif ratio < 0.8:
        color = C_METER_MID
    else:
        color = C_METER_HI
    d.rectangle([x, y, x + fill_w, y + h_bar], fill=color)


def _draw_tape_reels(d, cx1, cx2, cy, r, angle):
    for cx in (cx1, cx2):
        d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=C_TAPE, width=2)
        d.ellipse([cx - r // 3, cy - r // 3, cx + r // 3, cy + r // 3],
                  outline=C_DIM, width=1)
        spoke_len = r - 2
        for i in range(3):
            a = angle + i * 2.094
            ex = cx + int(spoke_len * math.cos(a))
            ey = cy + int(spoke_len * math.sin(a))
            d.line([(cx, cy), (ex, ey)], fill=C_DIM, width=1)


def _draw_recording_screen(elapsed, level):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    if IS_WIDE:
        d.rectangle([0, 0, W, 28], fill=C_HEAD)
        d.text((W // 2, 14), "RECORDING", font=font_lg, fill=C_RED_BRIGHT,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 60, 2), "RECORDING", font=font_lg, fill=C_RED_BRIGHT)

        blink = int(time.time() * 2) % 2
        if blink:
            d.ellipse([12, 8, 28, 24], fill=C_RED_BRIGHT)

        tape_y = 70
        angle = elapsed * 2.0
        _draw_tape_reels(d, W // 2 - 50, W // 2 + 50, tape_y, 25, angle)
        d.line([(W // 2 - 25, tape_y - 25), (W // 2 + 25, tape_y - 25)],
               fill=C_TAPE, width=1)

        d.text((W // 2, 110), _fmt_duration(elapsed), font=font_lg,
               fill=C_WHITE, anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 20, 100), _fmt_duration(elapsed), font=font_lg, fill=C_WHITE)

        _draw_meter(d, 30, 130, W - 60, 10, level)

        d.text((W // 2, H - 14), "OK: Stop", font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 20, H - 20), "OK: Stop", font=font_sm, fill=C_DIM)
    else:
        d.rectangle([0, 0, 128, 18], fill=C_HEAD)
        d.text((64, 2), "REC", font=font_lg, fill=C_RED_BRIGHT)

        blink = int(time.time() * 2) % 2
        if blink:
            d.ellipse([5, 4, 13, 12], fill=C_RED_BRIGHT)

        d.text((64, 50), _fmt_duration(elapsed), font=font_lg, fill=C_WHITE)
        _draw_meter(d, 10, 75, 108, 6, level)
        d.text((64, 110), "OK: Stop", font=font_sm, fill=C_DIM)

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_playback_screen(filename, elapsed, duration):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    if IS_WIDE:
        d.rectangle([0, 0, W, 28], fill=(0, 30, 0))
        d.text((W // 2, 14), "PLAYBACK", font=font_lg, fill=C_GREEN,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 50, 2), "PLAYBACK", font=font_lg, fill=C_GREEN)

        name = filename.replace(".wav", "")
        if len(name) > 30:
            name = name[:27] + "..."
        d.text((W // 2, 50), name, font=font_sm, fill=C_WHITE,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (10, 42), name, font=font_sm, fill=C_WHITE)

        tape_y = 85
        angle = elapsed * 2.0
        _draw_tape_reels(d, W // 2 - 50, W // 2 + 50, tape_y, 20, angle)

        time_str = f"{_fmt_duration(elapsed)} / {_fmt_duration(duration)}"
        d.text((W // 2, 120), time_str, font=font, fill=C_WHITE,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 45, 112), time_str, font=font, fill=C_WHITE)

        if duration > 0:
            bar_x, bar_w = 30, W - 60
            bar_y = 140
            d.rectangle([bar_x, bar_y, bar_x + bar_w, bar_y + 6], fill=C_DARK)
            prog = min(elapsed / duration, 1.0)
            d.rectangle([bar_x, bar_y, bar_x + int(bar_w * prog), bar_y + 6],
                        fill=C_GREEN)

        vol_pct = int(_volume * 100 / 63)
        d.text((W // 2, H - 14), f"KEY1:Stop  Vol:{vol_pct}%  UP/DOWN", font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (5, H - 20), f"K1:Stop Vol:{vol_pct}% UP/DN", font=font_sm, fill=C_DIM)
    else:
        d.rectangle([0, 0, 128, 18], fill=(0, 30, 0))
        d.text((64, 2), "PLAY", font=font_lg, fill=C_GREEN)
        name = filename.replace(".wav", "")[:16]
        d.text((64, 30), name, font=font_sm, fill=C_WHITE)
        time_str = f"{_fmt_duration(elapsed)}/{_fmt_duration(duration)}"
        d.text((64, 55), time_str, font=font, fill=C_WHITE)
        if duration > 0:
            prog = min(elapsed / duration, 1.0)
            d.rectangle([10, 80, 118, 84], fill=C_DARK)
            d.rectangle([10, 80, 10 + int(108 * prog), 84], fill=C_GREEN)
        vol_pct = int(_volume * 100 / 63)
        d.text((64, 100), f"Vol:{vol_pct}%", font=font_sm, fill=C_DIM)
        d.text((64, 113), "K1:Stop UP/DN", font=font_sm, fill=C_DIM)

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_main_menu(recordings, sel, page_offset):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    if IS_WIDE:
        d.rectangle([0, 0, W, 28], fill=C_HEAD)
        d.text((W // 2, 14), "TAPE RECORDER", font=font_lg, fill=C_RED,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 70, 2), "TAPE RECORDER", font=font_lg, fill=C_RED)

        max_visible = 5
        y = 34
        row_h = 24
        if not recordings:
            d.text((W // 2, H // 2), "No recordings", font=font, fill=C_DIM,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (W // 2 - 50, H // 2 - 8), "No recordings", font=font, fill=C_DIM)
        else:
            for i in range(max_visible):
                idx = page_offset + i
                if idx >= len(recordings):
                    break
                fname = recordings[idx]
                is_sel = idx == sel
                ry = y + i * row_h
                if is_sel:
                    d.rectangle([4, ry, W - 4, ry + row_h - 2], fill=C_SEL)

                name = fname.replace(".wav", "").replace("rec_", "")
                fpath = os.path.join(LOOT_DIR, fname)
                dur = _get_wav_duration(fpath)
                size = _fmt_size(fpath)
                label = f"{name}  {_fmt_duration(dur)}  {size}"
                if len(label) > 38:
                    label = label[:35] + "..."
                color = C_WHITE if is_sel else C_DIM
                d.text((10, ry + 4), label, font=font_sm, fill=color)

        d.rectangle([0, H - 22, W, H], fill=C_DARK)
        d.text((W // 2, H - 11),
               "OK:Rec  KEY1:Play  KEY2:Del  KEY3:Exit",
               font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (5, H - 18), "OK:Rec K1:Play K2:Del K3:Exit",
                   font=font_sm, fill=C_DIM)
    else:
        d.rectangle([0, 0, 128, 16], fill=C_HEAD)
        d.text((64, 1), "RECORDER", font=font, fill=C_RED)
        max_visible = 5
        y = 20
        row_h = 16
        if not recordings:
            d.text((64, 60), "No recordings", font=font_sm, fill=C_DIM)
        else:
            for i in range(max_visible):
                idx = page_offset + i
                if idx >= len(recordings):
                    break
                fname = recordings[idx]
                is_sel = idx == sel
                ry = y + i * row_h
                if is_sel:
                    d.rectangle([2, ry, 126, ry + row_h - 1], fill=C_SEL)
                name = fname.replace(".wav", "").replace("rec_", "")[:14]
                color = C_WHITE if is_sel else C_DIM
                d.text((4, ry + 1), name, font=font_sm, fill=color)

        d.text((64, 115), "OK:Rec K1:Play", font=font_sm, fill=C_DIM)

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_confirm_delete(fname):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    if IS_WIDE:
        d.text((W // 2, 40), "Delete?", font=font_lg, fill=C_RED,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 40, 30), "Delete?", font=font_lg, fill=C_RED)
        name = fname.replace(".wav", "")
        if len(name) > 30:
            name = name[:27] + "..."
        d.text((W // 2, 75), name, font=font_sm, fill=C_WHITE,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (10, 68), name, font=font_sm, fill=C_WHITE)
        d.text((W // 2, 120), "OK: Yes   KEY2: No", font=font, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 60, 112), "OK: Yes   KEY2: No", font=font, fill=C_DIM)
    else:
        d.text((64, 20), "Delete?", font=font_lg, fill=C_RED)
        name = fname.replace(".wav", "")[:16]
        d.text((64, 50), name, font=font_sm, fill=C_WHITE)
        d.text((64, 90), "OK:Yes K2:No", font=font_sm, fill=C_DIM)

    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global _running, _recording, _playing

    _detect_alsa_dev()

    sel = 0
    page_offset = 0
    max_visible = 5
    last_btn = 0
    state = "menu"
    current_file = ""
    play_duration = 0.0

    recordings = _list_recordings()
    _draw_main_menu(recordings, sel, page_offset)

    while _running:
        btn = get_button(PINS, GPIO)
        now = time.time()

        if state == "menu":
            if btn == "KEY3":
                break

            if btn == "OK" and now - last_btn > DEBOUNCE:
                last_btn = now
                current_file = _start_recording()
                state = "recording"
                continue

            if btn == "KEY1" and recordings and now - last_btn > DEBOUNCE:
                last_btn = now
                fpath = os.path.join(LOOT_DIR, recordings[sel])
                play_duration = _get_wav_duration(fpath)
                _start_playback(fpath)
                state = "playing"
                continue

            if btn == "KEY2" and recordings and now - last_btn > DEBOUNCE:
                last_btn = now
                state = "confirm_delete"
                _draw_confirm_delete(recordings[sel])
                continue

            if btn == "UP" and now - last_btn > DEBOUNCE:
                last_btn = now
                if recordings:
                    sel = (sel - 1) % len(recordings)
                    if sel < page_offset:
                        page_offset = sel
                    elif sel >= page_offset + max_visible:
                        page_offset = sel - max_visible + 1
                    _draw_main_menu(recordings, sel, page_offset)

            if btn == "DOWN" and now - last_btn > DEBOUNCE:
                last_btn = now
                if recordings:
                    sel = (sel + 1) % len(recordings)
                    if sel >= page_offset + max_visible:
                        page_offset = sel - max_visible + 1
                    elif sel < page_offset:
                        page_offset = sel
                    _draw_main_menu(recordings, sel, page_offset)

            if not btn:
                time.sleep(0.05)

        elif state == "recording":
            if btn == "OK" and now - last_btn > DEBOUNCE:
                last_btn = now
                _stop_recording()
                recordings = _list_recordings()
                sel = 0
                page_offset = 0
                state = "menu"
                _draw_main_menu(recordings, sel, page_offset)
                continue

            if btn == "KEY3":
                _stop_recording()
                break

            elapsed = now - _rec_start
            with _level_lock:
                level = _level_rms
            _draw_recording_screen(elapsed, level)
            time.sleep(0.1)

        elif state == "playing":
            if _play_proc and _play_proc.poll() is not None:
                _playing = False
                state = "menu"
                _draw_main_menu(recordings, sel, page_offset)
                continue

            if btn == "KEY1" and now - last_btn > DEBOUNCE:
                last_btn = now
                _stop_playback()
                state = "menu"
                _draw_main_menu(recordings, sel, page_offset)
                continue

            if btn == "UP" and now - last_btn > 0.10:
                last_btn = now
                _set_volume(_volume + 3)

            if btn == "DOWN" and now - last_btn > 0.10:
                last_btn = now
                _set_volume(_volume - 3)

            if btn == "KEY3":
                _stop_playback()
                break

            elapsed = now - _play_start
            _draw_playback_screen(
                recordings[sel] if sel < len(recordings) else "?",
                elapsed, play_duration)
            time.sleep(0.15)

        elif state == "confirm_delete":
            if btn == "OK" and now - last_btn > DEBOUNCE:
                last_btn = now
                fpath = os.path.join(LOOT_DIR, recordings[sel])
                _delete_recording(fpath)
                recordings = _list_recordings()
                if sel >= len(recordings) and sel > 0:
                    sel -= 1
                page_offset = max(0, min(page_offset, len(recordings) - max_visible))
                state = "menu"
                _draw_main_menu(recordings, sel, page_offset)

            if btn in ("KEY2", "KEY3") and now - last_btn > DEBOUNCE:
                last_btn = now
                state = "menu"
                _draw_main_menu(recordings, sel, page_offset)

            if not btn:
                time.sleep(0.05)

    _stop_recording()
    _stop_playback()
    _disable_mic()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
