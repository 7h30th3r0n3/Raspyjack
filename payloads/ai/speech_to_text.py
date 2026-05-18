#!/usr/bin/env python3
"""
RaspyJack Payload -- Speech to Text
=====================================
Author: 7h30th3r0n3

Offline speech recognition using Vosk.
Records from microphone and transcribes in real-time.
Supports multiple languages.

Controls:
  OK          Start/Stop recording & transcription
  UP/DOWN     Scroll transcript
  KEY1        Change language
  KEY2        Save transcript to file
  KEY3        Exit
"""

import os
import sys
import time
import signal
import subprocess
import threading
import json
import struct
import wave
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._audio_helper import get_audio_card, get_alsa_dev

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)
for p in PINS.values():
    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

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
    font = scaled_font(10)
    font_sm = scaled_font(8)
    font_lg = scaled_font(12)

MODEL_DIR = "/root/Raspyjack/models/vosk"
LOOT_DIR = "/root/Raspyjack/loot/AI/transcripts"
DEBOUNCE = 0.20
SAMPLE_RATE = 16000

LANGUAGES = {
    "en": {"name": "English", "model": "vosk-model-small-en-us-0.15", "url": "https://alphacephei.com/vosk/models/vosk-model-small-en-us-0.15.zip"},
    "fr": {"name": "Francais", "model": "vosk-model-small-fr-0.22", "url": "https://alphacephei.com/vosk/models/vosk-model-small-fr-0.22.zip"},
    "de": {"name": "Deutsch", "model": "vosk-model-small-de-0.15", "url": "https://alphacephei.com/vosk/models/vosk-model-small-de-0.15.zip"},
    "es": {"name": "Espanol", "model": "vosk-model-small-es-0.42", "url": "https://alphacephei.com/vosk/models/vosk-model-small-es-0.42.zip"},
    "it": {"name": "Italiano", "model": "vosk-model-small-it-0.22", "url": "https://alphacephei.com/vosk/models/vosk-model-small-it-0.22.zip"},
}

_running = True
_recording = False
_lang = "fr"
_transcript = []
_partial = ""
_lock = threading.Lock()
_alsa_dev = "default"

C_BG = (5, 5, 15)
C_HEAD = (20, 0, 40)
C_PURPLE = (180, 80, 255)
C_WHITE = (255, 255, 255)
C_DIM = (80, 80, 80)
C_DARK = (12, 12, 20)
C_GREEN = (0, 220, 80)
C_RED = (255, 50, 50)
C_YELLOW = (255, 200, 0)
C_CYAN = (0, 200, 220)
C_PARTIAL = (120, 120, 180)


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _get_btn():
    btn = get_button(PINS, GPIO)
    if btn and btn in _STUCK_PINS:
        return None
    return btn


def _show_status(msg, color=C_PURPLE):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
    if IS_WIDE:
        d.text((W // 2, H // 2), msg, font=font, fill=color,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (10, H // 2 - 7), msg, font=font, fill=color)
    else:
        d.text((4, 55), msg[:17], font=font, fill=color)
    LCD.LCD_ShowImage(img, 0, 0)


def _ensure_vosk():
    try:
        import vosk  # noqa: F401
        return True
    except ImportError:
        pass
    _show_status("Installing vosk...", C_YELLOW)
    r = subprocess.run(
        ["pip3", "install", "--break-system-packages", "vosk"],
        capture_output=True, timeout=300)
    return r.returncode == 0


def _ensure_model(lang):
    """Download and extract Vosk model if missing."""
    if lang not in LANGUAGES:
        return None
    info = LANGUAGES[lang]
    model_path = os.path.join(MODEL_DIR, info["model"])
    if os.path.isdir(model_path):
        return model_path

    os.makedirs(MODEL_DIR, exist_ok=True)
    zip_path = os.path.join(MODEL_DIR, f"{info['model']}.zip")

    _show_status(f"Downloading {info['name']}...", C_YELLOW)
    r = subprocess.run(
        ["wget", "--no-check-certificate", "-q", "-O", zip_path, info["url"]],
        capture_output=True, timeout=300)
    if r.returncode != 0:
        _show_status("Download failed!", C_RED)
        time.sleep(2)
        return None

    _show_status("Extracting model...", C_YELLOW)
    subprocess.run(["unzip", "-q", "-o", zip_path, "-d", MODEL_DIR],
                   capture_output=True, timeout=120)
    try:
        os.remove(zip_path)
    except Exception:
        pass

    return model_path if os.path.isdir(model_path) else None


def _enable_mic():
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
        ["amixer", "-c", get_audio_card(), "cset", "name=ADCL Capture Volume", "220"],
        capture_output=True, timeout=2)


def _disable_mic():
    subprocess.run(
        ["i2cset", "-f", "-y", "1", "0x4f", "0x06", "0x03"],
        capture_output=True, timeout=2)


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
    except Exception:
        pass


_vosk_model = None
_vosk_rec = None


def _load_vosk_model(model_path):
    global _vosk_model, _vosk_rec
    import vosk
    vosk.SetLogLevel(-1)
    _vosk_model = vosk.Model(model_path)
    _vosk_rec = vosk.KaldiRecognizer(_vosk_model, SAMPLE_RATE)


def _recognition_thread(model_path):
    """Record audio and run Vosk recognition."""
    global _recording, _partial, _vosk_rec
    import vosk

    if _vosk_rec is None:
        _load_vosk_model(model_path)

    _vosk_rec = vosk.KaldiRecognizer(_vosk_model, SAMPLE_RATE)

    _enable_mic()
    time.sleep(0.5)

    proc = subprocess.Popen(
        ["arecord", "-D", _alsa_dev, "-f", "S16_LE", "-r", str(SAMPLE_RATE),
         "-c", "1", "-t", "raw"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    chunk_size = SAMPLE_RATE * 2 // 5
    try:
        while _recording and _running:
            raw = proc.stdout.read(chunk_size)
            if not raw:
                break

            if _vosk_rec.AcceptWaveform(raw):
                result = json.loads(_vosk_rec.Result())
                text = result.get("text", "").strip()
                if text:
                    with _lock:
                        _transcript.append(text)
                        _partial = ""
            else:
                partial = json.loads(_vosk_rec.PartialResult())
                with _lock:
                    _partial = partial.get("partial", "")
    except Exception:
        pass
    finally:
        proc.kill()
        _disable_mic()
        final = json.loads(_vosk_rec.FinalResult())
        text = final.get("text", "").strip()
        if text:
            with _lock:
                _transcript.append(text)
        _recording = False


def _save_transcript():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"transcript_{ts}.txt")
    with _lock:
        text = "\n".join(_transcript)
    with open(path, "w") as f:
        f.write(text)
    return path


def _draw_main(scroll):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    status_color = C_RED if _recording else C_DIM
    lang_name = LANGUAGES.get(_lang, {}).get("name", _lang)

    if IS_WIDE:
        d.rectangle([0, 0, W, 20], fill=C_HEAD)
        d.text((W // 2, 10), "SPEECH TO TEXT", font=font_lg, fill=C_PURPLE,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 55, 1), "SPEECH TO TEXT", font=font_lg, fill=C_PURPLE)

        if _recording:
            blink = int(time.time() * 2) % 2
            if blink:
                d.ellipse([8, 5, 18, 15], fill=C_RED)

        d.text((W - 8, 5), lang_name, font=font_sm, fill=C_CYAN,
               anchor="ra") if hasattr(d, 'textbbox') else d.text(
                   (W - 60, 5), lang_name, font=font_sm, fill=C_CYAN)

        y = 24
        with _lock:
            lines = list(_transcript)
            partial = _partial

        visible = lines[scroll:scroll + 7]
        for ln in visible:
            wrapped = ln[:42]
            d.text((6, y), wrapped, font=font_sm, fill=C_WHITE)
            y += 14

        if partial:
            d.text((6, y), partial[:42], font=font_sm, fill=C_PARTIAL)

        d.rectangle([0, H - 16, W, H], fill=C_DARK)
        bar = f"OK:{'Stop' if _recording else 'Start'} K1:Lang K2:Save K3:Exit [{len(lines)} lines]"
        d.text((W // 2, H - 8), bar, font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (2, H - 13), bar[:44], font=font_sm, fill=C_DIM)
    else:
        d.rectangle([0, 0, 128, 14], fill=C_HEAD)
        d.text((8, 1), "SPEECH2TEXT", font=font_lg, fill=C_PURPLE)

        if _recording:
            blink = int(time.time() * 2) % 2
            if blink:
                d.ellipse([115, 3, 123, 11], fill=C_RED)

        y = 18
        with _lock:
            lines = list(_transcript)
            partial = _partial

        visible = lines[scroll:scroll + 5]
        for ln in visible:
            d.text((4, y), ln[:17], font=font_sm, fill=C_WHITE)
            y += 14

        if partial:
            d.text((4, y), partial[:17], font=font_sm, fill=C_PARTIAL)

        d.text((4, 108), f"OK K1:Lang {lang_name[:4]}", font=font_sm, fill=C_DIM)

    LCD.LCD_ShowImage(img, 0, 0)


def _is_model_downloaded(lang):
    """Check if a language model is already downloaded."""
    if lang not in LANGUAGES:
        return False
    info = LANGUAGES[lang]
    model_path = os.path.join(MODEL_DIR, info["model"])
    return os.path.isdir(model_path)


def _show_lang_menu():
    """Show language selection menu. Downloaded models in white, others in grey."""
    langs = list(LANGUAGES.keys())
    sel = langs.index(_lang) if _lang in langs else 0
    last_btn = 0

    while _running:
        img = Image.new("RGB", (W, H), C_BG)
        d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

        if IS_WIDE:
            d.rectangle([0, 0, W, 20], fill=C_HEAD)
            d.text((W // 2, 10), "SELECT LANGUAGE", font=font_lg, fill=C_PURPLE,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (W // 2 - 60, 1), "SELECT LANGUAGE", font=font_lg, fill=C_PURPLE)

            y = 26
            for i, code in enumerate(langs):
                ry = y + i * 22
                info = LANGUAGES[code]
                downloaded = _is_model_downloaded(code)
                is_sel = i == sel
                is_current = code == _lang

                if is_sel:
                    d.rectangle([4, ry, W - 4, ry + 20], fill=(30, 20, 50))

                if is_current:
                    mark = " *"
                else:
                    mark = ""

                if downloaded:
                    color = C_WHITE if is_sel else C_CYAN
                else:
                    color = C_DIM

                status = "" if downloaded else " (download)"
                d.text((10, ry + 3), f"{info['name']}{mark}{status}",
                       font=font_sm, fill=color)

            d.rectangle([0, H - 16, W, H], fill=C_DARK)
            d.text((W // 2, H - 8), "UP/DN:Select OK:Choose KEY3:Back",
                   font=font_sm, fill=C_DIM,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (2, H - 13), "OK:Choose K3:Back", font=font_sm, fill=C_DIM)
        else:
            d.rectangle([0, 0, 128, 14], fill=C_HEAD)
            d.text((20, 1), "LANGUAGE", font=font_lg, fill=C_PURPLE)
            y = 18
            for i, code in enumerate(langs):
                ry = y + i * 18
                info = LANGUAGES[code]
                downloaded = _is_model_downloaded(code)
                is_sel = i == sel
                is_current = code == _lang

                if is_sel:
                    d.rectangle([2, ry, 126, ry + 16], fill=(30, 20, 50))

                mark = "*" if is_current else ""
                color = C_WHITE if downloaded else C_DIM
                d.text((4, ry + 2), f"{info['name'][:10]} {mark}",
                       font=font_sm, fill=color)

        LCD.LCD_ShowImage(img, 0, 0)

        btn = _get_btn()
        now = time.time()

        if btn == "KEY3" and now - last_btn > DEBOUNCE:
            return None

        if btn == "UP" and now - last_btn > DEBOUNCE:
            last_btn = now
            sel = (sel - 1) % len(langs)

        if btn == "DOWN" and now - last_btn > DEBOUNCE:
            last_btn = now
            sel = (sel + 1) % len(langs)

        if btn == "OK" and now - last_btn > DEBOUNCE:
            last_btn = now
            chosen = langs[sel]
            if not _is_model_downloaded(chosen):
                _show_status(f"Downloading {LANGUAGES[chosen]['name']}...", C_YELLOW)
                model_path = _ensure_model(chosen)
                if not model_path:
                    _show_status("Download failed!", C_RED)
                    time.sleep(1)
                    continue
            return chosen

        time.sleep(0.08)

    return None


def main():
    global _running, _recording, _lang

    _detect_alsa_dev()

    if not _ensure_vosk():
        _show_status("Vosk install failed!", C_RED)
        time.sleep(2)
        GPIO.cleanup()
        return 1

    model_path = _ensure_model(_lang)
    if not model_path:
        GPIO.cleanup()
        return 1

    _show_status("Loading model...", C_PURPLE)
    _load_vosk_model(model_path)

    scroll = 0
    last_btn = 0
    rec_thread = None

    while _running:
        btn = _get_btn()
        now = time.time()

        if btn == "KEY3":
            _recording = False
            if rec_thread:
                rec_thread.join(timeout=3)
            break

        if btn == "OK" and now - last_btn > DEBOUNCE:
            last_btn = now
            if not _recording:
                _recording = True
                rec_thread = threading.Thread(
                    target=_recognition_thread, args=(model_path,), daemon=True)
                rec_thread.start()
            else:
                _recording = False
                if rec_thread:
                    rec_thread.join(timeout=3)

        if btn == "KEY1" and now - last_btn > DEBOUNCE and not _recording:
            last_btn = now
            result = _show_lang_menu()
            if result:
                _lang = result
                model_path = _ensure_model(_lang)
                if model_path:
                    _show_status(f"Loading {LANGUAGES[_lang]['name']}...", C_PURPLE)
                    _load_vosk_model(model_path)
                    _show_status("Ready!", C_GREEN)
                    time.sleep(0.5)
                else:
                    _show_status("Model failed!", C_RED)
                    time.sleep(1)

        if btn == "KEY2" and now - last_btn > DEBOUNCE:
            last_btn = now
            if _transcript:
                path = _save_transcript()
                _show_status(f"Saved!", C_GREEN)
                time.sleep(1)

        if btn == "UP" and now - last_btn > 0.1:
            last_btn = now
            scroll = max(0, scroll - 1)

        if btn == "DOWN" and now - last_btn > 0.1:
            last_btn = now
            with _lock:
                max_scroll = max(0, len(_transcript) - 5)
            scroll = min(scroll + 1, max_scroll)

        _draw_main(scroll)
        time.sleep(0.15)

    _recording = False
    _disable_mic()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
