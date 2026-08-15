#!/usr/bin/env python3
"""
RaspyJack Payload -- Voice Journal
==================================

Offline voice-to-text recorder for journaling, blogging, and notes.

Controls:
  OK          Start/stop a new voice entry
  UP/DOWN     Navigate saved entries
  KEY1        Play/stop selected recording
  KEY2        Preview selected transcript
  KEY3        Back/exit
"""

import json
import math
import os
import signal
import struct
import subprocess
import sys
import threading
import time
import wave
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import LCD_1in44
import LCD_Config
import RPi.GPIO as GPIO
from PIL import Image, ImageDraw

from payloads._audio_helper import (
    disable_capture,
    enable_capture,
    get_alsa_dev,
    get_capture_dev,
    get_capture_label,
)
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6,
    "DOWN": 19,
    "LEFT": 5,
    "RIGHT": 26,
    "OK": 13,
    "KEY1": 21,
    "KEY2": 20,
    "KEY3": 16,
}

GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

time.sleep(0.1)
_STUCK_PINS = {name for name, pin in PINS.items() if GPIO.input(pin) == 0}

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
W, H = LCD.width, LCD.height
IS_WIDE = W > 200

if IS_WIDE:
    from PIL import ImageFont

    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 13)
        font_sm = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 10)
        font_lg = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 16)
    except Exception:
        font = scaled_font(9)
        font_sm = scaled_font(7)
        font_lg = scaled_font(12)
else:
    font = scaled_font(9)
    font_sm = scaled_font(7)
    font_lg = scaled_font(11)

MODEL_DIR = "/root/Raspyjack/models/vosk"
LOOT_DIR = "/root/Raspyjack/loot/VoiceJournal"
RATE = 16000
CHANNELS = 1
FORMAT = "S16_LE"
LANG = "en"
DEBOUNCE = 0.20

LANGUAGES = {
    "en": {
        "name": "English",
        "model": "vosk-model-small-en-us-0.15",
        "url": "https://alphacephei.com/vosk/models/vosk-model-small-en-us-0.15.zip",
    },
    "fr": {
        "name": "Francais",
        "model": "vosk-model-small-fr-0.22",
        "url": "https://alphacephei.com/vosk/models/vosk-model-small-fr-0.22.zip",
    },
    "de": {
        "name": "Deutsch",
        "model": "vosk-model-small-de-0.15",
        "url": "https://alphacephei.com/vosk/models/vosk-model-small-de-0.15.zip",
    },
    "es": {
        "name": "Espanol",
        "model": "vosk-model-small-es-0.42",
        "url": "https://alphacephei.com/vosk/models/vosk-model-small-es-0.42.zip",
    },
}

C_BG = (8, 12, 18)
C_HEAD = (10, 34, 42)
C_SEL = (22, 54, 58)
C_DARK = (16, 20, 28)
C_WHITE = (245, 245, 245)
C_DIM = (110, 118, 124)
C_GREEN = (40, 220, 135)
C_RED = (245, 70, 70)
C_YELLOW = (245, 190, 70)
C_CYAN = (70, 210, 220)

_running = True
_recording = False
_playing = False
_rec_proc = None
_play_proc = None
_rec_thread = None
_wav_file = None
_rec_start = 0.0
_play_start = 0.0
_level_rms = 0
_level_lock = threading.Lock()
_capture_dev = "default"
_playback_dev = "default"
_mic_label = ""


def _sig(_signum, _frame):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _get_btn():
    btn = get_button(PINS, GPIO)
    if btn and btn in _STUCK_PINS:
        return None
    return btn


def _ensure_loot_dir():
    os.makedirs(LOOT_DIR, exist_ok=True)


def _fmt_duration(secs):
    secs = max(0, int(secs))
    return f"{secs // 60}:{secs % 60:02d}"


def _text(d, xy, msg, fill=C_WHITE, use_font=None, anchor=None):
    kwargs = {"font": use_font or font, "fill": fill}
    if anchor and hasattr(d, "textbbox"):
        kwargs["anchor"] = anchor
    d.text(xy, msg, **kwargs)


def _show_status(title, detail="", color=C_CYAN):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
    if IS_WIDE:
        _text(d, (W // 2, H // 2 - 10), title[:30], color, font_lg, "mm")
        if detail:
            _text(d, (W // 2, H // 2 + 14), detail[:36], C_DIM, font_sm, "mm")
    else:
        _text(d, (64, 46), title[:17], color, font, "mm")
        if detail:
            _text(d, (64, 66), detail[:17], C_DIM, font_sm, "mm")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_meter(d, x, y, w_bar, h_bar, level):
    d.rectangle([x, y, x + w_bar, y + h_bar], fill=C_DARK)
    ratio = min(max(level, 0) / 20000, 1.0)
    fill_w = int(w_bar * ratio)
    if fill_w <= 0:
        return
    color = C_GREEN if ratio < 0.55 else C_YELLOW if ratio < 0.82 else C_RED
    d.rectangle([x, y, x + fill_w, y + h_bar], fill=color)


def _entry_stamp(base):
    return base.replace("journal_", "").replace("_", " ")


def _list_entries():
    _ensure_loot_dir()
    entries = []
    for name in sorted(os.listdir(LOOT_DIR), reverse=True):
        if not name.endswith(".wav"):
            continue
        base = name[:-4]
        wav_path = os.path.join(LOOT_DIR, name)
        txt_path = os.path.join(LOOT_DIR, f"{base}.txt")
        md_path = os.path.join(LOOT_DIR, f"{base}.md")
        entries.append({
            "base": base,
            "wav": wav_path,
            "txt": txt_path,
            "md": md_path,
            "name": name,
        })
    return entries


def _read_preview(path, max_lines=7):
    if not os.path.exists(path):
        return ["No transcript yet."]
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read().strip()
    except Exception:
        return ["Could not read transcript."]
    if not text:
        return ["No speech recognized."]
    words = text.replace("\n", " ").split()
    width = 38 if IS_WIDE else 17
    lines = []
    line = ""
    for word in words:
        next_line = f"{line} {word}".strip()
        if len(next_line) > width:
            if line:
                lines.append(line)
            line = word[:width]
        else:
            line = next_line
        if len(lines) >= max_lines:
            break
    if line and len(lines) < max_lines:
        lines.append(line)
    return lines or ["No speech recognized."]


def _get_wav_duration(path):
    try:
        with wave.open(path, "rb") as wav:
            return wav.getnframes() / float(wav.getframerate())
    except Exception:
        return 0.0


def _ensure_vosk():
    try:
        import vosk  # noqa: F401
        return True
    except ImportError:
        pass
    _show_status("Installing Vosk", "Needs network once", C_YELLOW)
    result = subprocess.run(
        ["pip3", "install", "--break-system-packages", "vosk"],
        capture_output=True,
        timeout=300,
    )
    return result.returncode == 0


def _ensure_model(lang):
    info = LANGUAGES[lang]
    model_path = os.path.join(MODEL_DIR, info["model"])
    if os.path.isdir(model_path):
        return model_path

    os.makedirs(MODEL_DIR, exist_ok=True)
    zip_path = os.path.join(MODEL_DIR, f"{info['model']}.zip")
    _show_status("Downloading model", info["name"], C_YELLOW)
    result = subprocess.run(
        ["wget", "--no-check-certificate", "-q", "-O", zip_path, info["url"]],
        capture_output=True,
        timeout=300,
    )
    if result.returncode != 0:
        return None

    _show_status("Extracting model", info["name"], C_YELLOW)
    subprocess.run(["unzip", "-q", "-o", zip_path, "-d", MODEL_DIR], capture_output=True, timeout=120)
    try:
        os.remove(zip_path)
    except Exception:
        pass
    return model_path if os.path.isdir(model_path) else None


def _detect_audio_devices():
    global _capture_dev, _playback_dev, _mic_label
    _capture_dev = get_capture_dev()
    _playback_dev = get_alsa_dev()
    _mic_label = get_capture_label()


def _start_recording():
    global _recording, _rec_proc, _rec_start, _level_rms, _wav_file, _rec_thread
    _ensure_loot_dir()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    wav_path = os.path.join(LOOT_DIR, f"journal_{stamp}.wav")

    enable_capture()
    time.sleep(0.2)
    _rec_proc = subprocess.Popen(
        [
            "arecord",
            "-D",
            _capture_dev,
            "-f",
            FORMAT,
            "-r",
            str(RATE),
            "-c",
            str(CHANNELS),
            "-t",
            "raw",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    _wav_file = wave.open(wav_path, "wb")
    _wav_file.setnchannels(CHANNELS)
    _wav_file.setsampwidth(2)
    _wav_file.setframerate(RATE)
    _level_rms = 0
    _rec_start = time.time()
    _recording = True
    _rec_thread = threading.Thread(target=_rec_writer_thread, daemon=True)
    _rec_thread.start()
    return wav_path


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
            sample_count = len(raw) // 2
            if sample_count:
                samples = struct.unpack(f"<{sample_count}h", raw)
                rms = math.sqrt(sum(s * s for s in samples) / sample_count)
                with _level_lock:
                    _level_rms = min(int(rms), 32768)
    except Exception:
        pass


def _stop_recording():
    global _recording, _rec_proc, _wav_file, _rec_thread
    _recording = False
    if _rec_proc and _rec_proc.poll() is None:
        _rec_proc.terminate()
        try:
            _rec_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            _rec_proc.kill()
    if _rec_thread:
        _rec_thread.join(timeout=2)
    _rec_proc = None
    _rec_thread = None
    if _wav_file:
        try:
            _wav_file.close()
        except Exception:
            pass
    _wav_file = None
    disable_capture()


def _transcribe_wav(wav_path, model_path):
    import vosk

    vosk.SetLogLevel(-1)
    model = vosk.Model(model_path)
    with wave.open(wav_path, "rb") as wav:
        rec = vosk.KaldiRecognizer(model, wav.getframerate())
        chunks = []
        while True:
            data = wav.readframes(4000)
            if not data:
                break
            if rec.AcceptWaveform(data):
                result = json.loads(rec.Result())
                text = result.get("text", "").strip()
                if text:
                    chunks.append(text)
        final = json.loads(rec.FinalResult())
        text = final.get("text", "").strip()
        if text:
            chunks.append(text)
    return "\n".join(chunks).strip()


def _save_transcript(wav_path, transcript):
    base = os.path.splitext(os.path.basename(wav_path))[0]
    txt_path = os.path.join(LOOT_DIR, f"{base}.txt")
    md_path = os.path.join(LOOT_DIR, f"{base}.md")
    created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    body = transcript.strip() or "No speech recognized."

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(body + "\n")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# Voice Journal {created}\n\n")
        f.write(f"- Audio: {os.path.basename(wav_path)}\n")
        f.write(f"- Created: {created}\n\n")
        f.write(body + "\n")
    return txt_path, md_path


def _start_playback(path):
    global _playing, _play_proc, _play_start
    disable_capture()
    _play_proc = subprocess.Popen(
        ["aplay", "-D", _playback_dev, path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
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


def _draw_menu(entries, sel, offset):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
    max_visible = 5

    if IS_WIDE:
        d.rectangle([0, 0, W, 24], fill=C_HEAD)
        _text(d, (W // 2, 12), "VOICE JOURNAL", C_CYAN, font_lg, "mm")
        y = 30
        row_h = 24
        if not entries:
            _text(d, (W // 2, H // 2), "No entries yet", C_DIM, font, "mm")
        for i in range(max_visible):
            idx = offset + i
            if idx >= len(entries):
                break
            entry = entries[idx]
            ry = y + i * row_h
            if idx == sel:
                d.rectangle([4, ry, W - 4, ry + row_h - 2], fill=C_SEL)
            duration = _fmt_duration(_get_wav_duration(entry["wav"]))
            has_text = "txt" if os.path.exists(entry["txt"]) else "wav"
            label = f"{_entry_stamp(entry['base'])}  {duration}  {has_text}"
            _text(d, (10, ry + 4), label[:40], C_WHITE if idx == sel else C_DIM, font_sm)
        d.rectangle([0, H - 20, W, H], fill=C_DARK)
        _text(d, (W // 2, H - 10), "OK:Rec  K1:Play  K2:Text  K3:Exit", C_DIM, font_sm, "mm")
    else:
        d.rectangle([0, 0, 128, 16], fill=C_HEAD)
        _text(d, (64, 8), "VOICE NOTES", C_CYAN, font, "mm")
        y = 20
        row_h = 16
        if not entries:
            _text(d, (64, 60), "No entries", C_DIM, font_sm, "mm")
        for i in range(max_visible):
            idx = offset + i
            if idx >= len(entries):
                break
            entry = entries[idx]
            ry = y + i * row_h
            if idx == sel:
                d.rectangle([2, ry, 126, ry + row_h - 1], fill=C_SEL)
            _text(d, (4, ry + 1), _entry_stamp(entry["base"])[:16], C_WHITE if idx == sel else C_DIM, font_sm)
        _text(d, (64, 114), "OK:Rec K1:Play K2:Txt", C_DIM, font_sm, "mm")

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_recording(elapsed, level):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
    if IS_WIDE:
        d.rectangle([0, 0, W, 28], fill=(48, 16, 20))
        _text(d, (W // 2, 14), "RECORDING", C_RED, font_lg, "mm")
        if int(time.time() * 2) % 2:
            d.ellipse([12, 8, 24, 20], fill=C_RED)
        _text(d, (W // 2, 74), _fmt_duration(elapsed), C_WHITE, font_lg, "mm")
        _draw_meter(d, 24, 102, W - 48, 10, level)
        _text(d, (W // 2, 124), _mic_label[:36], C_DIM, font_sm, "mm")
        _text(d, (W // 2, H - 14), "OK: Stop and transcribe", C_DIM, font_sm, "mm")
    else:
        d.rectangle([0, 0, 128, 18], fill=(48, 16, 20))
        _text(d, (64, 9), "REC", C_RED, font, "mm")
        _text(d, (64, 52), _fmt_duration(elapsed), C_WHITE, font_lg, "mm")
        _draw_meter(d, 10, 76, 108, 6, level)
        _text(d, (64, 94), _mic_label[:17], C_DIM, font_sm, "mm")
        _text(d, (64, 112), "OK:Stop", C_DIM, font_sm, "mm")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_playback(entry, elapsed, duration):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
    if IS_WIDE:
        d.rectangle([0, 0, W, 26], fill=(12, 40, 24))
        _text(d, (W // 2, 13), "PLAYBACK", C_GREEN, font_lg, "mm")
        _text(d, (W // 2, 54), _entry_stamp(entry["base"])[:32], C_WHITE, font_sm, "mm")
        _text(d, (W // 2, 92), f"{_fmt_duration(elapsed)} / {_fmt_duration(duration)}", C_WHITE, font, "mm")
        if duration > 0:
            d.rectangle([24, 118, W - 24, 124], fill=C_DARK)
            d.rectangle([24, 118, 24 + int((W - 48) * min(elapsed / duration, 1.0)), 124], fill=C_GREEN)
        _text(d, (W // 2, H - 14), "KEY1:Stop  KEY3:Exit", C_DIM, font_sm, "mm")
    else:
        d.rectangle([0, 0, 128, 18], fill=(12, 40, 24))
        _text(d, (64, 9), "PLAY", C_GREEN, font, "mm")
        _text(d, (64, 36), _entry_stamp(entry["base"])[:16], C_WHITE, font_sm, "mm")
        _text(d, (64, 64), f"{_fmt_duration(elapsed)}/{_fmt_duration(duration)}", C_WHITE, font_sm, "mm")
        _text(d, (64, 112), "K1:Stop", C_DIM, font_sm, "mm")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_preview(entry):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
    lines = _read_preview(entry["txt"], 7 if IS_WIDE else 5)
    if IS_WIDE:
        d.rectangle([0, 0, W, 24], fill=C_HEAD)
        _text(d, (W // 2, 12), "TRANSCRIPT", C_CYAN, font_lg, "mm")
        y = 32
        for line in lines:
            _text(d, (8, y), line, C_WHITE, font_sm)
            y += 15
        d.rectangle([0, H - 18, W, H], fill=C_DARK)
        _text(d, (W // 2, H - 9), "K3:Back  Download txt/md from WebUI loot", C_DIM, font_sm, "mm")
    else:
        d.rectangle([0, 0, 128, 16], fill=C_HEAD)
        _text(d, (64, 8), "TEXT", C_CYAN, font, "mm")
        y = 22
        for line in lines:
            _text(d, (4, y), line[:17], C_WHITE, font_sm)
            y += 15
        _text(d, (64, 114), "K3:Back", C_DIM, font_sm, "mm")
    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global _recording, _playing

    _detect_audio_devices()

    if not _ensure_vosk():
        _show_status("Vosk failed", "Check payload.log", C_RED)
        time.sleep(2)
        GPIO.cleanup()
        return 1

    model_path = _ensure_model(LANG)
    if not model_path:
        _show_status("Model failed", "Network needed once", C_RED)
        time.sleep(2)
        GPIO.cleanup()
        return 1

    entries = _list_entries()
    sel = 0
    offset = 0
    max_visible = 5
    last_btn = 0.0
    state = "menu"
    current_wav = None
    play_duration = 0.0

    _draw_menu(entries, sel, offset)

    while _running:
        btn = _get_btn()
        now = time.time()

        if state == "menu":
            if btn == "KEY3":
                break

            if btn == "OK" and now - last_btn > DEBOUNCE:
                last_btn = now
                current_wav = _start_recording()
                state = "recording"
                continue

            if btn == "KEY1" and entries and now - last_btn > DEBOUNCE:
                last_btn = now
                play_duration = _get_wav_duration(entries[sel]["wav"])
                _start_playback(entries[sel]["wav"])
                state = "playing"
                continue

            if btn == "KEY2" and entries and now - last_btn > DEBOUNCE:
                last_btn = now
                state = "preview"
                _draw_preview(entries[sel])
                continue

            if btn == "UP" and entries and now - last_btn > DEBOUNCE:
                last_btn = now
                sel = (sel - 1) % len(entries)
                if sel < offset:
                    offset = sel
                elif sel >= offset + max_visible:
                    offset = sel - max_visible + 1
                _draw_menu(entries, sel, offset)

            if btn == "DOWN" and entries and now - last_btn > DEBOUNCE:
                last_btn = now
                sel = (sel + 1) % len(entries)
                if sel >= offset + max_visible:
                    offset = sel - max_visible + 1
                elif sel < offset:
                    offset = sel
                _draw_menu(entries, sel, offset)

            if not btn:
                time.sleep(0.05)

        elif state == "recording":
            if btn == "OK" and now - last_btn > DEBOUNCE:
                last_btn = now
                _stop_recording()
                _show_status("Transcribing", "Please wait", C_YELLOW)
                try:
                    transcript = _transcribe_wav(current_wav, model_path)
                    _save_transcript(current_wav, transcript)
                    _show_status("Saved", "VoiceJournal loot", C_GREEN)
                    time.sleep(1)
                except Exception:
                    _show_status("Transcript failed", "Audio was saved", C_RED)
                    time.sleep(2)
                entries = _list_entries()
                sel = 0
                offset = 0
                state = "menu"
                _draw_menu(entries, sel, offset)
                continue

            if btn == "KEY3":
                _stop_recording()
                break

            elapsed = now - _rec_start
            with _level_lock:
                level = _level_rms
            _draw_recording(elapsed, level)
            time.sleep(0.1)

        elif state == "playing":
            if _play_proc and _play_proc.poll() is not None:
                _playing = False
                state = "menu"
                _draw_menu(entries, sel, offset)
                continue

            if btn == "KEY1" and now - last_btn > DEBOUNCE:
                last_btn = now
                _stop_playback()
                state = "menu"
                _draw_menu(entries, sel, offset)
                continue

            if btn == "KEY3":
                _stop_playback()
                break

            elapsed = now - _play_start
            _draw_playback(entries[sel], elapsed, play_duration)
            time.sleep(0.15)

        elif state == "preview":
            if btn == "KEY3" and now - last_btn > DEBOUNCE:
                last_btn = now
                state = "menu"
                _draw_menu(entries, sel, offset)
                continue
            if not btn:
                time.sleep(0.05)

    _stop_recording()
    _stop_playback()
    disable_capture()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
