#!/usr/bin/env python3
"""
RaspyJack Payload -- BirdNET Live
==================================
Author: 7h30th3r0n3

Real-time bird species detection using BirdNET AI model
and the ES8389 built-in microphone.

Controls:
  OK          Start/Stop listening
  UP/DOWN     Scroll detection history
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
import wave
import json
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
import numpy as np
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font, SX, SY
from payloads._input_helper import get_button
from payloads._audio_helper import get_audio_card, get_alsa_dev

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
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 14)
        font_sm = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 11)
        font_lg = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 18)
    except Exception:
        font = scaled_font(9)
        font_sm = scaled_font(7)
        font_lg = scaled_font(14)
else:
    font = scaled_font(9)
    font_sm = scaled_font(7)
    font_lg = font

MODEL_DIR = "/root/Raspyjack/models/birdnet"
MODEL_PATH = os.path.join(MODEL_DIR, "model.tflite")
LABELS_PATH = os.path.join(MODEL_DIR, "labels.txt")
L18N_DIR = os.path.join(MODEL_DIR, "l18n")
LOOT_DIR = "/root/Raspyjack/loot/BirdNET"
SETTINGS_PATH = os.path.join(LOOT_DIR, "settings.json")
RECORD_RATE = 16000
MODEL_RATE = 48000
CHUNK_SECS = 3
CHUNK_SAMPLES = MODEL_RATE * CHUNK_SECS
MIN_CONFIDENCE = 0.25
DEBOUNCE = 0.20
AVAILABLE_LANGS = [
    "en", "fr", "de", "es", "it", "pt", "nl", "pl", "ru", "ja",
    "ko", "zh_CN", "ar", "tr", "sv", "da", "no", "fi", "cs", "hu",
]

_running = True
_listening = False
_alsa_dev = "default"
_interpreter = None
_labels = []
_lang_map = {}
_lang = "fr"
_detections = []
_detections_lock = threading.Lock()
_current_status = "Ready"
_status_lock = threading.Lock()

C_BG = (5, 15, 5)
C_HEAD = (0, 40, 0)
C_GREEN = (0, 220, 80)
C_GREEN_DIM = (0, 120, 40)
C_WHITE = (255, 255, 255)
C_DIM = (100, 100, 100)
C_DARK = (20, 25, 20)
C_SEL = (15, 50, 15)
C_BIRD = (255, 220, 50)
C_CONF_HI = (0, 255, 80)
C_CONF_MID = (200, 200, 0)
C_CONF_LO = (180, 100, 0)


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


def _load_settings():
    global _lang
    os.makedirs(LOOT_DIR, exist_ok=True)
    if os.path.isfile(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, "r") as f:
                s = json.load(f)
            _lang = s.get("lang", "fr")
        except Exception:
            pass


def _save_settings():
    os.makedirs(LOOT_DIR, exist_ok=True)
    try:
        with open(SETTINGS_PATH, "w") as f:
            json.dump({"lang": _lang}, f)
    except Exception:
        pass


def _load_lang_map():
    global _lang_map
    path = os.path.join(L18N_DIR, f"labels_{_lang}.json")
    if os.path.isfile(path):
        try:
            with open(path, "r") as f:
                _lang_map = json.load(f)
        except Exception:
            _lang_map = {}
    else:
        _lang_map = {}


def _get_common_name(sci_name):
    if _lang_map and sci_name in _lang_map:
        return _lang_map[sci_name]
    return sci_name


def _load_model():
    global _interpreter, _labels
    try:
        from ai_edge_litert.interpreter import Interpreter
    except ImportError:
        return False
    if not os.path.isfile(MODEL_PATH) or not os.path.isfile(LABELS_PATH):
        return False
    _interpreter = Interpreter(model_path=MODEL_PATH)
    _interpreter.allocate_tensors()
    with open(LABELS_PATH, "r") as f:
        _labels = [line.strip() for line in f if line.strip()]
    _load_settings()
    _load_lang_map()
    return True


def _resample_16k_to_48k(samples_16k):
    n = len(samples_16k)
    indices = np.arange(n * 3) / 3.0
    indices = np.clip(indices, 0, n - 1)
    idx_floor = indices.astype(np.int32)
    idx_ceil = np.minimum(idx_floor + 1, n - 1)
    frac = indices - idx_floor
    return samples_16k[idx_floor] * (1.0 - frac) + samples_16k[idx_ceil] * frac


def _sigmoid(x):
    return 1.0 / (1.0 + np.exp(-np.clip(x, -15, 15)))


def _analyze_chunk(audio_48k):
    if _interpreter is None:
        return []
    inp_details = _interpreter.get_input_details()[0]
    out_details = _interpreter.get_output_details()[0]

    chunk = np.zeros(CHUNK_SAMPLES, dtype=np.float32)
    n = min(len(audio_48k), CHUNK_SAMPLES)
    chunk[:n] = audio_48k[:n]

    _interpreter.set_tensor(inp_details["index"], chunk.reshape(1, -1))
    _interpreter.invoke()
    logits = _interpreter.get_tensor(out_details["index"])[0]
    preds = _sigmoid(logits)

    results = []
    top_indices = np.argsort(preds)[::-1][:5]
    for idx in top_indices:
        conf = float(preds[idx])
        if conf >= MIN_CONFIDENCE and idx < len(_labels):
            label = _labels[idx]
            sci_name = label.split("_")[0]
            common_name = _get_common_name(sci_name)
            results.append({
                "species": common_name,
                "scientific": sci_name,
                "confidence": conf,
                "time": datetime.now().strftime("%H:%M"),
            })
    return results


def _set_status(msg):
    global _current_status
    with _status_lock:
        _current_status = msg


def _get_status():
    with _status_lock:
        return _current_status


def _listen_thread():
    global _listening
    _enable_mic()
    time.sleep(0.3)

    rec_proc = subprocess.Popen(
        ["arecord", "-D", _alsa_dev, "-f", "S16_LE", "-r", str(RECORD_RATE),
         "-c", "1", "-t", "raw"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    chunk_bytes = RECORD_RATE * 2 * CHUNK_SECS
    try:
        while _listening and _running:
            _set_status("Listening...")
            raw = b""
            while len(raw) < chunk_bytes and _listening and _running:
                piece = rec_proc.stdout.read(chunk_bytes - len(raw))
                if not piece:
                    break
                raw += piece

            if len(raw) < chunk_bytes // 2:
                break

            _set_status("Analyzing...")
            n_samples = len(raw) // 2
            samples_16k = np.array(
                struct.unpack(f"<{n_samples}h", raw),
                dtype=np.float32) / 32768.0

            audio_48k = _resample_16k_to_48k(samples_16k)

            results = _analyze_chunk(audio_48k)
            if results:
                with _detections_lock:
                    for r in results:
                        _detections.insert(0, r)
                    if len(_detections) > 50:
                        _detections[:] = _detections[:50]
                _save_detections(results)
    except Exception:
        pass
    finally:
        if rec_proc.poll() is None:
            rec_proc.kill()
        _disable_mic()
        _listening = False
        _set_status("Stopped")


def _save_detections(results):
    os.makedirs(LOOT_DIR, exist_ok=True)
    log_path = os.path.join(LOOT_DIR, f"detections_{datetime.now().strftime('%Y%m%d')}.json")
    entries = []
    if os.path.isfile(log_path):
        try:
            with open(log_path, "r") as f:
                entries = json.load(f)
        except Exception:
            entries = []
    for r in results:
        entries.append({
            "species": r["species"],
            "scientific": r["scientific"],
            "confidence": r["confidence"],
            "time": r["time"],
            "date": datetime.now().strftime("%Y-%m-%d"),
        })
    try:
        with open(log_path, "w") as f:
            json.dump(entries, f, indent=2)
    except Exception:
        pass


def _conf_color(conf):
    if conf >= 0.7:
        return C_CONF_HI
    if conf >= 0.4:
        return C_CONF_MID
    return C_CONF_LO


def _draw_main(scroll):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    status = _get_status()

    if IS_WIDE:
        d.rectangle([0, 0, W, 26], fill=C_HEAD)
        title = "BIRDNET LIVE"
        d.text((W // 2, 13), title, font=font_lg, fill=C_GREEN,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 65, 2), title, font=font_lg, fill=C_GREEN)

        blink = int(time.time() * 2) % 2
        if _listening and blink:
            d.ellipse([8, 7, 22, 21], fill=(255, 50, 50))
        elif _listening:
            d.ellipse([8, 7, 22, 21], fill=(100, 20, 20))

        d.text((W - 10, 13), status, font=font_sm, fill=C_DIM,
               anchor="rm") if hasattr(d, 'textbbox') else d.text(
                   (W - 90, 5), status, font=font_sm, fill=C_DIM)

        with _detections_lock:
            dets = list(_detections)

        if not dets:
            msg = "OK: Start listening" if not _listening else "Waiting for birds..."
            d.text((W // 2, H // 2), msg, font=font, fill=C_DIM,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (W // 2 - 70, H // 2 - 8), msg, font=font, fill=C_DIM)
        else:
            max_visible = 5
            y = 30
            row_h = 26
            for i in range(max_visible):
                idx = scroll + i
                if idx >= len(dets):
                    break
                det = dets[idx]
                ry = y + i * row_h

                if i == 0 and scroll == 0:
                    d.rectangle([2, ry, W - 2, ry + row_h - 1], fill=C_SEL)

                conf_pct = int(det["confidence"] * 100)
                name = det["species"]
                if len(name) > 22:
                    name = name[:19] + "..."
                color = C_BIRD if i == 0 and scroll == 0 else C_WHITE
                d.text((8, ry + 2), name, font=font_sm, fill=color)

                right_str = f"{conf_pct}% {det['time']}"
                cc = _conf_color(det["confidence"])
                d.text((W - 8, ry + 2), right_str, font=font_sm, fill=cc,
                       anchor="ra") if hasattr(d, 'textbbox') else d.text(
                           (W - len(right_str) * 7 - 4, ry + 2), right_str, font=font_sm, fill=cc)

        d.rectangle([0, H - 18, W, H], fill=C_DARK)
        n = len(dets)
        bar = f"OK:{'Stop' if _listening else 'Start'} K2:Lang({_lang}) Birds:{n} K3:Exit"
        d.text((W // 2, H - 9), bar, font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (5, H - 15), bar, font=font_sm, fill=C_DIM)
    else:
        d.rectangle([0, 0, 128, 14], fill=C_HEAD)
        d.text((64, 1), "BIRDNET", font=font, fill=C_GREEN)

        with _detections_lock:
            dets = list(_detections)

        if not dets:
            msg = "OK:Start" if not _listening else "Listening..."
            d.text((64, 60), msg, font=font_sm, fill=C_DIM)
        else:
            max_visible = 5
            y = 18
            row_h = 16
            for i in range(max_visible):
                idx = scroll + i
                if idx >= len(dets):
                    break
                det = dets[idx]
                ry = y + i * row_h
                name = det["species"][:12]
                conf_pct = int(det["confidence"] * 100)
                color = C_BIRD if i == 0 and scroll == 0 else C_WHITE
                d.text((2, ry), f"{name} {conf_pct}%", font=font_sm, fill=color)

        d.text((64, 115), "OK/KEY3", font=font_sm, fill=C_DIM)

    LCD.LCD_ShowImage(img, 0, 0)


LANG_NAMES = {
    "en": "English", "fr": "Francais", "de": "Deutsch", "es": "Espanol",
    "it": "Italiano", "pt": "Portugues", "nl": "Nederlands", "pl": "Polski",
    "ru": "Russkij", "ja": "Nihongo", "ko": "Hangugeo", "zh_CN": "Zhongwen",
    "ar": "Arabiya", "tr": "Turkce", "sv": "Svenska", "da": "Dansk",
    "no": "Norsk", "fi": "Suomi", "cs": "Cestina", "hu": "Magyar",
}


def _show_lang_menu():
    global _lang
    langs = [l for l in AVAILABLE_LANGS if os.path.isfile(
        os.path.join(L18N_DIR, f"labels_{l}.json")) or True]
    sel = langs.index(_lang) if _lang in langs else 0
    page = sel // 6
    last_btn = 0

    while _running:
        img = Image.new("RGB", (W, H), C_BG)
        d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

        if IS_WIDE:
            d.rectangle([0, 0, W, 26], fill=(40, 30, 0))
            d.text((W // 2, 13), "LANGUAGE", font=font_lg, fill=C_BIRD,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (W // 2 - 45, 2), "LANGUAGE", font=font_lg, fill=C_BIRD)
            y = 32
            row_h = 22
            per_page = 6
            for i in range(per_page):
                idx = page * per_page + i
                if idx >= len(langs):
                    break
                ry = y + i * row_h
                is_sel = idx == sel
                if is_sel:
                    d.rectangle([4, ry, W - 4, ry + row_h - 1], fill=C_SEL)
                code = langs[idx]
                name = LANG_NAMES.get(code, code)
                mark = " *" if code == _lang else ""
                color = C_BIRD if is_sel else C_WHITE
                d.text((12, ry + 3), f"{code.upper()} - {name}{mark}", font=font_sm, fill=color)
        else:
            d.rectangle([0, 0, 128, 14], fill=(40, 30, 0))
            d.text((64, 1), "LANG", font=font, fill=C_BIRD)
            y = 18
            row_h = 16
            per_page = 6
            for i in range(per_page):
                idx = page * per_page + i
                if idx >= len(langs):
                    break
                ry = y + i * row_h
                is_sel = idx == sel
                code = langs[idx]
                mark = "*" if code == _lang else ""
                color = C_BIRD if is_sel else C_WHITE
                d.text((4, ry), f"{code} {mark}", font=font_sm, fill=color)

        d.rectangle([0, H - 18, W, H], fill=C_DARK)
        hint = "OK:Select  KEY3:Back"
        if IS_WIDE:
            d.text((W // 2, H - 9), hint, font=font_sm, fill=C_DIM,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (5, H - 15), hint, font=font_sm, fill=C_DIM)
        else:
            d.text((64, H - 14), "OK/K3", font=font_sm, fill=C_DIM)

        LCD.LCD_ShowImage(img, 0, 0)

        btn = get_button(PINS, GPIO)
        now = time.time()

        if btn == "KEY3" and now - last_btn > DEBOUNCE:
            return

        if btn == "OK" and now - last_btn > DEBOUNCE:
            last_btn = now
            new_lang = langs[sel]
            _draw_loading(f"Loading {new_lang}...")
            _ensure_lang_labels(new_lang)
            _lang = new_lang
            _load_lang_map()
            _save_settings()
            return

        if btn == "UP" and now - last_btn > DEBOUNCE:
            last_btn = now
            sel = (sel - 1) % len(langs)
            page = sel // per_page

        if btn == "DOWN" and now - last_btn > DEBOUNCE:
            last_btn = now
            sel = (sel + 1) % len(langs)
            page = sel // per_page

        time.sleep(0.08)


MODEL_URL = "https://github.com/kahst/BirdNET-Analyzer/raw/main/checkpoints/V2.4/BirdNET_GLOBAL_6K_V2.4_Model_FP16.tflite"
LABELS_URL = "https://github.com/kahst/BirdNET-Analyzer/raw/main/checkpoints/V2.4/BirdNET_GLOBAL_6K_V2.4_Model_FP16_Labels.txt"
L18N_BASE_URL = "https://github.com/kahst/BirdNET-Analyzer/raw/main/labels/V2.4"


def _ensure_deps():
    try:
        from ai_edge_litert.interpreter import Interpreter  # noqa: F401
        return True
    except ImportError:
        pass
    _draw_loading("Installing TFLite...")
    r = subprocess.run(
        ["pip3", "install", "--break-system-packages", "ai-edge-litert"],
        capture_output=True, timeout=300)
    if r.returncode != 0:
        _draw_error("Install failed", "ai-edge-litert")
        time.sleep(3)
        return False
    return True


def _ensure_model():
    os.makedirs(MODEL_DIR, exist_ok=True)
    if not os.path.isfile(MODEL_PATH):
        _draw_loading("Downloading model (25MB)...")
        r = subprocess.run(
            ["wget", "-q", "-O", MODEL_PATH, MODEL_URL],
            capture_output=True, timeout=120)
        if r.returncode != 0 or not os.path.isfile(MODEL_PATH):
            _draw_error("Download failed", "BirdNET model")
            time.sleep(3)
            return False
    if not os.path.isfile(LABELS_PATH):
        _draw_loading("Downloading labels...")
        subprocess.run(
            ["wget", "-q", "-O", LABELS_PATH, LABELS_URL],
            capture_output=True, timeout=30)
    return os.path.isfile(MODEL_PATH) and os.path.isfile(LABELS_PATH)


def _ensure_lang_labels(lang):
    os.makedirs(L18N_DIR, exist_ok=True)
    path = os.path.join(L18N_DIR, f"labels_{lang}.json")
    if os.path.isfile(path):
        return True
    txt_url = f"{L18N_BASE_URL}/BirdNET_GLOBAL_6K_V2.4_Labels_{lang}.txt"
    tmp = path + ".tmp"
    r = subprocess.run(
        ["wget", "-q", "-O", tmp, txt_url],
        capture_output=True, timeout=30)
    if r.returncode != 0 or not os.path.isfile(tmp):
        try:
            os.remove(tmp)
        except Exception:
            pass
        return False
    try:
        mapping = {}
        with open(tmp, "r") as f:
            for line in f:
                parts = line.strip().split("_", 1)
                if len(parts) == 2:
                    mapping[parts[0]] = parts[1]
        with open(path, "w") as f:
            json.dump(mapping, f, ensure_ascii=False, indent=2)
        os.remove(tmp)
        return True
    except Exception:
        return False


def main():
    global _running, _listening

    _detect_alsa_dev()

    if not _ensure_deps():
        GPIO.cleanup()
        return 1

    _draw_loading("Checking model...")
    if not _ensure_model():
        GPIO.cleanup()
        return 1

    _draw_loading("Loading model...")
    if not _load_model():
        _draw_error("Model load failed", "Check files")
        time.sleep(3)
        GPIO.cleanup()
        return 1

    _ensure_lang_labels(_lang)
    _load_lang_map()

    scroll = 0
    last_btn = 0
    listen_thread = None

    _draw_main(scroll)

    while _running:
        btn = get_button(PINS, GPIO)
        now = time.time()

        if btn == "KEY3":
            if _listening:
                _listening = False
                if listen_thread:
                    listen_thread.join(timeout=5)
            break

        if btn == "OK" and now - last_btn > DEBOUNCE:
            last_btn = now
            if not _listening:
                _listening = True
                listen_thread = threading.Thread(target=_listen_thread, daemon=True)
                listen_thread.start()
            else:
                _listening = False
                if listen_thread:
                    listen_thread.join(timeout=5)
                    listen_thread = None

        if btn == "KEY2" and now - last_btn > DEBOUNCE and not _listening:
            last_btn = now
            _show_lang_menu()
            _draw_main(scroll)
            continue

        if btn == "UP" and now - last_btn > DEBOUNCE:
            last_btn = now
            scroll = max(0, scroll - 1)

        if btn == "DOWN" and now - last_btn > DEBOUNCE:
            last_btn = now
            with _detections_lock:
                max_scroll = max(0, len(_detections) - 5)
            scroll = min(scroll + 1, max_scroll)

        _draw_main(scroll)
        time.sleep(0.2)

    _listening = False
    _disable_mic()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


def _draw_loading(msg):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
    if IS_WIDE:
        d.text((W // 2, H // 2 - 10), "BirdNET", font=font_lg, fill=C_GREEN,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 45, H // 2 - 20), "BirdNET", font=font_lg, fill=C_GREEN)
        d.text((W // 2, H // 2 + 15), msg, font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 45, H // 2 + 8), msg, font=font_sm, fill=C_DIM)
    else:
        d.text((64, 50), "BirdNET", font=font, fill=C_GREEN)
        d.text((64, 70), msg, font=font_sm, fill=C_DIM)
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_error(msg, sub=""):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
    if IS_WIDE:
        d.text((W // 2, H // 2 - 10), msg, font=font, fill=(255, 50, 50),
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 60, H // 2 - 20), msg, font=font, fill=(255, 50, 50))
        if sub:
            d.text((W // 2, H // 2 + 15), sub, font=font_sm, fill=C_DIM,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (W // 2 - 60, H // 2 + 8), sub, font=font_sm, fill=C_DIM)
    else:
        d.text((64, 50), msg, font=font_sm, fill=(255, 50, 50))
        if sub:
            d.text((64, 70), sub, font=font_sm, fill=C_DIM)
    LCD.LCD_ShowImage(img, 0, 0)


if __name__ == "__main__":
    raise SystemExit(main())
