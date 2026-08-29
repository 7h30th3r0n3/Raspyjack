#!/usr/bin/env python3
"""
RaspyJack Payload -- Sub-GHz Analyzer
=======================================
Author: 7h30th3r0n3

Flipper Zero-style ISM band analyzer for 433/868 MHz.
Decodes 200+ protocols: remotes (CAME, NICE, etc.), weather stations,
doorbells, car keys, home automation sensors, tire pressure monitors.

Uses rtl_433 for protocol decoding + raw signal capture.

Controls:
  OK          : Start/Stop capture
  UP/DOWN     : Scroll signals / change view
  LEFT/RIGHT  : Change frequency band
  KEY1 (SPACE): Switch view (Live / Log / Raw / Stats)
  KEY2 (BKSP) : Save current signal / Export log
  KEY3 (ESC)  : Exit

Requires: apt install rtl-433
"""

import os
import sys
import time
import signal
import subprocess
import threading
import json
from datetime import datetime
from collections import defaultdict

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

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
font_lg = scaled_font(12)
font_xs = scaled_font(6)

LOOT_DIR = "/root/Raspyjack/loot/SDR/subghz"
DEBOUNCE = 0.18
VIEWS = ["live", "log", "stats"]
BANDS = [
    {"name": "433 MHz", "freq": 433920000, "desc": "EU ISM / Remotes"},
    {"name": "315 MHz", "freq": 315000000, "desc": "US Remotes / TPMS"},
    {"name": "868 MHz", "freq": 868000000, "desc": "EU ISM / LoRa"},
    {"name": "345 MHz", "freq": 345000000, "desc": "Honeywell Security"},
    {"name": "915 MHz", "freq": 915000000, "desc": "US ISM"},
]

# Protocol filter presets (rtl_433 -R numbers)
PROTO_FILTERS = [
    {"name": "ALL protocols", "args": []},
    {"name": "Weather only", "args": ["-R", "2", "-R", "3", "-R", "8", "-R", "10", "-R", "11", "-R", "12", "-R", "16", "-R", "18", "-R", "19", "-R", "20", "-R", "31", "-R", "32", "-R", "34", "-R", "40", "-R", "41", "-R", "42", "-R", "51", "-R", "56", "-R", "71", "-R", "78"]},
    {"name": "Remotes/Gates", "args": ["-R", "1", "-R", "4", "-R", "15", "-R", "17", "-R", "22", "-R", "30", "-R", "67", "-R", "169"]},
    {"name": "Security/Alarm", "args": ["-R", "23", "-R", "29", "-R", "58", "-R", "63", "-R", "86", "-R", "102", "-R", "162", "-R", "266"]},
    {"name": "TPMS (tires)", "args": ["-R", "59", "-R", "60", "-R", "82", "-R", "88", "-R", "104", "-R", "109", "-R", "110", "-R", "123", "-R", "140", "-R", "180", "-R", "275"]},
    {"name": "Car keys/Fobs", "args": ["-R", "30", "-R", "67", "-R", "101", "-R", "189"]},
]
_proto_filter_idx = 0

# Protocol categories and icons
PROTO_CATEGORIES = {
    "remote": {"icon": "R", "color": (255, 100, 0), "keywords": ["remote", "came", "nice", "gate", "garage", "button", "keyfob"]},
    "weather": {"icon": "W", "color": (0, 200, 255), "keywords": ["weather", "temp", "humid", "rain", "wind", "baro", "thermo"]},
    "sensor": {"icon": "S", "color": (0, 255, 100), "keywords": ["sensor", "motion", "door", "window", "alarm", "smoke", "pir"]},
    "tpms": {"icon": "T", "color": (255, 200, 0), "keywords": ["tpms", "tire", "pressure"]},
    "car": {"icon": "C", "color": (255, 50, 50), "keywords": ["car", "auto", "key", "fob", "vehicle"]},
    "other": {"icon": "?", "color": (150, 150, 150), "keywords": []},
}

ISM_LIVE_PATH = "/dev/shm/rj_ism_live.json"
ISM_CONTROL_PATH = "/dev/shm/rj_ism_control.json"

_running = True
_capturing = False
_rtl_proc = None
_signals = []
_signal_lock = threading.Lock()
_proto_counts = defaultdict(int)
_devices = {}
_last_btn = 0
_start_time = 0


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _btn():
    global _last_btn
    btn = get_button(PINS, GPIO)
    if btn:
        now = time.time()
        if now - _last_btn < DEBOUNCE:
            return None
        _last_btn = now
    return btn


def _categorize(model, protocol_name):
    text = (model + " " + protocol_name).lower()
    for cat, info in PROTO_CATEGORIES.items():
        if cat == "other":
            continue
        for kw in info["keywords"]:
            if kw in text:
                return cat
    return "other"


def _format_signal(sig):
    model = sig.get("model", "Unknown")
    # Show ALL fields from rtl_433, skip internal/meta keys
    skip = {"model", "time", "mic", "mod", "freq", "freq1", "freq2",
            "rssi", "snr", "noise", "protocol", "_time_local", "_category",
            "rows", "num_rows", "count"}
    parts = []
    for key, val in sig.items():
        if key in skip or key.startswith("_"):
            continue
        if val is None or val == "":
            continue
        # Format key nicely
        k = key.replace("_", " ").replace("C", "°C") if key == "temperature_C" else key.replace("_", " ")
        if isinstance(val, float):
            parts.append(f"{k}:{val:.1f}")
        elif isinstance(val, list):
            if key == "codes" and val:
                parts.append(f"code:{val[-1]}")
            continue
        elif isinstance(val, dict):
            continue
        else:
            parts.append(f"{k}:{val}")
    return model, " ".join(parts)


# ---------------------------------------------------------------------------
# rtl_433 capture thread
# ---------------------------------------------------------------------------
def _capture_thread(freq):
    global _rtl_proc
    os.makedirs(LOOT_DIR, exist_ok=True)

    filt = PROTO_FILTERS[_proto_filter_idx]
    cmd = [
        "rtl_433", "-f", str(freq), "-g", "20",
        "-s", "1024000",
        "-F", "json", "-F", "log",
        "-M", "time:unix", "-M", "protocol", "-M", "level",
        "-X", "n=CAME-12,m=OOK_PWM,s=320,l=640,r=15000,g=800,t=0,y=1650,bits>=12",
        "-X", "n=Princeton,m=OOK_PWM,s=320,l=640,r=15000,g=800,t=0,y=1650,bits>=24",
        "-X", "n=NiceFLO,m=OOK_PWM,s=700,l=1400,r=15000,g=1600,t=0,y=0,bits>=12",
    ] + filt["args"]

    try:
        _rtl_proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1,
        )

        _last_sig = {}  # dedup: model+id+channel → last data hash
        for line in _rtl_proc.stdout:
            if not _capturing:
                break
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                # Dedup: skip if same model+id+channel with same data within 2s
                model = data.get("model", "")
                sig_key = f"{model}_{data.get('id','')}_{data.get('channel','')}"
                # Build a hash of the interesting data (skip time/rssi)
                sig_vals = {k: v for k, v in data.items() if k not in ("time", "rssi", "snr", "noise", "mic")}
                sig_hash = str(sig_vals)
                now = time.time()
                if sig_key in _last_sig:
                    last_hash, last_time = _last_sig[sig_key]
                    if sig_hash == last_hash and (now - last_time) < 2.0:
                        continue
                _last_sig[sig_key] = (sig_hash, now)

                data["_time_local"] = datetime.now().strftime("%H:%M:%S")
                data["_category"] = _categorize(
                    model, data.get("protocol", "")
                )
                with _signal_lock:
                    _signals.append(data)
                    if len(_signals) > 500:
                        _signals.pop(0)
                    _proto_counts[data.get("model", "Unknown")] += 1
                    _update_device(data)
            except json.JSONDecodeError:
                pass

        _rtl_proc.terminate()
        try:
            _rtl_proc.wait(timeout=3)
        except Exception:
            _rtl_proc.kill()
    except Exception:
        pass
    _rtl_proc = None


def _start_capture(freq):
    global _capturing
    _stop_capture()
    _capturing = True
    threading.Thread(target=_capture_thread, args=(freq,), daemon=True).start()


def _stop_capture():
    global _capturing, _rtl_proc
    _capturing = False
    if _rtl_proc:
        try:
            _rtl_proc.terminate()
            _rtl_proc.wait(timeout=2)
        except Exception:
            try:
                _rtl_proc.kill()
            except Exception:
                pass
        _rtl_proc = None
    subprocess.run(["pkill", "-9", "rtl_433"], capture_output=True)


def _save_signal(sig):
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    model = sig.get("model", "unknown").replace(" ", "_")[:20]
    path = os.path.join(LOOT_DIR, f"{model}_{ts}.json")
    with open(path, "w") as f:
        json.dump(sig, f, indent=2)
    return path


def _export_log():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"capture_log_{ts}.json")
    with _signal_lock:
        data = list(_signals)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path, len(data)


_HISTORY_METRICS = ("temperature_C", "humidity", "pressure_kPa",
                    "wind_avg_km_h", "rain_mm", "pressure_PSI",
                    "temperature_F", "uv", "light_lux", "power_W",
                    "energy_kWh", "moisture", "rssi")
_MAX_HISTORY = 60


def _update_device(data):
    model = data.get("model", "Unknown")
    dev_id = data.get("id", "")
    channel = data.get("channel", "")
    key = f"{model}_{dev_id}_{channel}"
    now = time.time()
    entry = _devices.get(key, {"first_seen": now, "count": 0, "history": {}})
    rssi = data.get("rssi", data.get("snr", None))
    entry.update({
        "model": model, "id": dev_id, "channel": channel,
        "category": data.get("_category", "other"),
        "last_seen": now, "count": entry["count"] + 1,
        "rssi": rssi,
    })
    for k in ("temperature_C", "humidity", "battery_ok", "pressure_kPa",
              "wind_avg_km_h", "rain_mm", "code", "button", "status",
              "pressure_PSI", "temperature_F", "uv", "light_lux",
              "moisture", "depth_cm", "power_W", "energy_kWh"):
        if k in data:
            entry[k] = data[k]
    hist = entry.get("history", {})
    for k in _HISTORY_METRICS:
        val = data.get(k) if k != "rssi" else rssi
        if val is not None and isinstance(val, (int, float)):
            pts = hist.get(k, [])
            pts.append([round(now, 1), round(val, 2)])
            if len(pts) > _MAX_HISTORY:
                pts = pts[-_MAX_HISTORY:]
            hist[k] = pts
    entry["history"] = hist
    _devices[key] = entry


def _write_live_json():
    while _running:
        try:
            with _signal_lock:
                recent = [s for s in _signals[-50:]]
                dev_list = sorted(_devices.values(), key=lambda d: d.get("last_seen", 0), reverse=True)
            filt = PROTO_FILTERS[_proto_filter_idx]
            cmd_parts = ["rtl_433", "-f", str(BANDS[_current_band]["freq"]),
                         "-g", "49.6", "-F", "json", "-M", "time:unix",
                         "-M", "protocol", "-M", "level"] + filt["args"]
            payload = {
                "ts": time.time(),
                "running": _capturing,
                "total_signals": len(_signals),
                "unique_devices": len(_devices),
                "uptime": int(time.time() - _start_time) if _start_time else 0,
                "proto_counts": dict(_proto_counts),
                "devices": dev_list[:100],
                "recent": recent,
                "band": BANDS[_current_band]["name"] if _capturing else "",
                "freq": BANDS[_current_band]["freq"] if _capturing else 0,
                "filter": PROTO_FILTERS[_proto_filter_idx]["name"],
                "command": " ".join(cmd_parts) if _capturing else "",
                "bands": [{"name": b["name"], "freq": b["freq"], "desc": b["desc"]} for b in BANDS],
                "filters": [f["name"] for f in PROTO_FILTERS],
                "filter_idx": _proto_filter_idx,
            }
            tmp = ISM_LIVE_PATH + ".tmp"
            with open(tmp, "w") as f:
                json.dump(payload, f)
            os.replace(tmp, ISM_LIVE_PATH)
        except Exception:
            pass
        time.sleep(1.5)


def _check_web_control():
    try:
        if os.path.exists(ISM_CONTROL_PATH):
            with open(ISM_CONTROL_PATH) as f:
                ctrl = json.load(f)
            os.unlink(ISM_CONTROL_PATH)
            return ctrl
    except Exception:
        pass
    return None


_current_band = 0


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------
def _draw_live(band_idx, scroll):
    img = Image.new("RGB", (W, H), (8, 10, 16))
    draw = ImageDraw.Draw(img)
    band = BANDS[band_idx]

    # Header
    draw.rectangle([(0, 0), (W, SY(14))], fill=(15, 20, 35))
    draw.text((SX(2), SY(2)), "SUB-GHZ", font=font_sm, fill=(0, 255, 100))
    draw.text((SX(50), SY(2)), band["name"], font=font_sm, fill=(255, 200, 0))
    if _capturing:
        draw.ellipse([W - SX(10), SY(4), W - SX(4), SY(10)], fill=(255, 0, 0))
        draw.text((W - SX(30), SY(2)), "REC", font=font_xs, fill=(255, 0, 0))

    with _signal_lock:
        signals = list(_signals)

    if not signals:
        draw.text((W // 2, H // 2 - SY(5)), "No signals yet", font=font, fill=(60, 60, 80), anchor="mm")
        draw.text((W // 2, H // 2 + SY(10)), "OK to start capture", font=font_sm, fill=(40, 40, 60), anchor="mm")
    else:
        row_h = SY(22)
        y = SY(16)
        visible = max(1, (H - SY(30)) // row_h)

        for i in range(scroll, min(len(signals), scroll + visible)):
            if y + row_h > H - SY(14):
                break
            sig = signals[-(i + 1)] if i < len(signals) else None
            if not sig:
                break

            cat = sig.get("_category", "other")
            cat_info = PROTO_CATEGORIES.get(cat, PROTO_CATEGORIES["other"])
            model, details = _format_signal(sig)

            # Row background
            draw.rectangle([(0, y), (W, y + row_h - 1)], fill=(12, 16, 24) if i % 2 == 0 else (8, 10, 16))

            # Category icon
            draw.rectangle([(SX(2), y + SY(2)), (SX(12), y + row_h - SY(2))], fill=cat_info["color"])
            draw.text((SX(4), y + SY(3)), cat_info["icon"], font=font_xs, fill=(0, 0, 0))

            # Time
            draw.text((SX(15), y + SY(1)), sig.get("_time_local", ""), font=font_xs, fill=(80, 80, 100))

            # Model
            draw.text((SX(42), y + SY(1)), model[:20], font=font_sm, fill=cat_info["color"])

            # Details
            draw.text((SX(15), y + SY(11)), details[:40], font=font_xs, fill=(120, 130, 150))

            # RSSI
            rssi = sig.get("rssi", sig.get("snr", ""))
            if rssi:
                draw.text((W - SX(30), y + SY(1)), f"{rssi}dB", font=font_xs, fill=(100, 100, 120))

            y += row_h

    # Footer
    draw.rectangle([(0, H - SY(12)), (W, H)], fill=(15, 20, 35))
    footer = "OK:Rec LR:Band K1:View K2:Filter" if not _capturing else "OK:Stop LR:Band K1:View K2:Save"
    draw.text((SX(2), H - SY(11)), footer, font=font_xs, fill=(50, 60, 80))

    # Signal count
    draw.text((W - SX(30), H - SY(11)), f"{len(signals)}", font=font_xs, fill=(0, 200, 100))

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_log(scroll):
    img = Image.new("RGB", (W, H), (8, 10, 16))
    draw = ImageDraw.Draw(img)

    draw.rectangle([(0, 0), (W, SY(14))], fill=(15, 20, 35))
    draw.text((SX(2), SY(2)), "SIGNAL LOG", font=font_sm, fill=(0, 200, 255))

    with _signal_lock:
        signals = list(_signals)

    row_h = SY(11)
    y = SY(16)
    visible = max(1, (H - SY(28)) // row_h)

    for i in range(scroll, min(len(signals), scroll + visible)):
        sig = signals[-(i + 1)] if i < len(signals) else None
        if not sig or y + row_h > H - SY(14):
            break

        cat = sig.get("_category", "other")
        col = PROTO_CATEGORIES.get(cat, PROTO_CATEGORIES["other"])["color"]
        model = sig.get("model", "?")[:15]
        t = sig.get("_time_local", "")

        draw.text((SX(2), y), t, font=font_xs, fill=(60, 60, 80))
        draw.text((SX(35), y), model, font=font_xs, fill=col)

        # Key data
        code = sig.get("code", sig.get("id", sig.get("data", "")))
        draw.text((W - SX(60), y), str(code)[:10], font=font_xs, fill=(100, 100, 120))
        y += row_h

    draw.rectangle([(0, H - SY(12)), (W, H)], fill=(15, 20, 35))
    draw.text((SX(2), H - SY(11)), f"Total: {len(signals)} signals  K2:Export", font=font_xs, fill=(50, 60, 80))
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_stats(band_idx):
    img = Image.new("RGB", (W, H), (8, 10, 16))
    draw = ImageDraw.Draw(img)

    draw.rectangle([(0, 0), (W, SY(14))], fill=(15, 20, 35))
    draw.text((SX(2), SY(2)), "STATISTICS", font=font_sm, fill=(200, 100, 255))

    with _signal_lock:
        total = len(_signals)
        counts = dict(_proto_counts)

    y = SY(18)

    # Category summary
    cat_counts = defaultdict(int)
    for model, count in counts.items():
        for sig in _signals:
            if sig.get("model") == model:
                cat_counts[sig.get("_category", "other")] += count
                break

    draw.text((SX(4), y), f"Total signals: {total}", font=font, fill=(0, 255, 100))
    y += SY(16)

    # Per-category
    for cat, info in PROTO_CATEGORIES.items():
        if cat == "other" and cat_counts.get(cat, 0) == 0:
            continue
        c = cat_counts.get(cat, 0)
        if c > 0:
            draw.rectangle([(SX(4), y + SY(1)), (SX(14), y + SY(9))], fill=info["color"])
            draw.text((SX(16), y), f"{cat.upper()}: {c}", font=font_sm, fill=info["color"])
            y += SY(12)

    y += SY(5)

    # Top protocols
    draw.text((SX(4), y), "Top protocols:", font=font_sm, fill=(100, 100, 130))
    y += SY(12)
    sorted_protos = sorted(counts.items(), key=lambda x: -x[1])[:6]
    for model, count in sorted_protos:
        draw.text((SX(8), y), f"{model[:18]}", font=font_xs, fill=(150, 150, 170))
        draw.text((W - SX(30), y), f"x{count}", font=font_xs, fill=(0, 200, 100))
        y += SY(10)

    draw.rectangle([(0, H - SY(12)), (W, H)], fill=(15, 20, 35))
    draw.text((SX(2), H - SY(11)), f"Band: {BANDS[band_idx]['name']}", font=font_xs, fill=(50, 60, 80))
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def _select_filter():
    """Pre-launch screen to select protocol filter and band."""
    global _proto_filter_idx
    band_idx = 0
    sel = 0  # 0=filter, 1=band, 2=start

    while _running:
        img = Image.new("RGB", (W, H), (8, 10, 16))
        draw = ImageDraw.Draw(img)
        s = max(1, S(1))

        draw.rectangle([(0, 0), (W, SY(14))], fill=(15, 20, 35))
        draw.text((SX(2), SY(2)), "SUB-GHZ CONFIG", font=font_sm, fill=(0, 255, 100))

        y = SY(20)
        items = [
            ("Filter", PROTO_FILTERS[_proto_filter_idx]["name"]),
            ("Band", BANDS[band_idx]["name"]),
            ("", ">>> START CAPTURE <<<"),
        ]
        for i, (label, value) in enumerate(items):
            is_sel = i == sel
            if is_sel:
                draw.rectangle([(0, y), (W, y + SY(18))], fill=(0, 30, 60))
            if label:
                draw.text((SX(4), y + SY(2)), f"{label}:", font=font_sm, fill=(100, 150, 200) if not is_sel else (255, 255, 255))
                col = (0, 255, 100) if is_sel else (0, 150, 80)
                draw.text((SX(50), y + SY(2)), f"< {value} >", font=font_sm, fill=col)
            else:
                col = (0, 255, 100) if is_sel else (100, 100, 100)
                draw.text((W // 2, y + SY(4)), value, font=font_sm, fill=col, anchor="mm")
            y += SY(22)

        # Show filter details
        y += SY(5)
        filt = PROTO_FILTERS[_proto_filter_idx]
        n_protos = len(filt["args"]) // 2 if filt["args"] else 273
        draw.text((SX(4), y), f"Protocols: {n_protos}", font=font_xs, fill=(80, 80, 100))
        draw.text((SX(4), y + SY(10)), f"Freq: {BANDS[band_idx]['desc']}", font=font_xs, fill=(80, 80, 100))

        draw.rectangle([(0, H - SY(12)), (W, H)], fill=(15, 20, 35))
        draw.text((SX(2), H - SY(11)), "UD:Select LR:Change OK:Go K3:Exit", font=font_xs, fill=(50, 60, 80))

        LCD.LCD_ShowImage(img, 0, 0)

        btn = _btn()
        if btn == "KEY3":
            return -1, -1
        elif btn == "UP":
            sel = max(0, sel - 1)
            time.sleep(DEBOUNCE)
        elif btn == "DOWN":
            sel = min(2, sel + 1)
            time.sleep(DEBOUNCE)
        elif btn in ("RIGHT", "KEY2"):
            if sel == 0:
                _proto_filter_idx = (_proto_filter_idx + 1) % len(PROTO_FILTERS)
            elif sel == 1:
                band_idx = (band_idx + 1) % len(BANDS)
            time.sleep(DEBOUNCE)
        elif btn in ("LEFT", "KEY1"):
            if sel == 0:
                _proto_filter_idx = (_proto_filter_idx - 1) % len(PROTO_FILTERS)
            elif sel == 1:
                band_idx = (band_idx - 1) % len(BANDS)
            time.sleep(DEBOUNCE)
        elif btn == "OK":
            if sel == 2:
                return _proto_filter_idx, band_idx
            else:
                sel = min(2, sel + 1)
            time.sleep(DEBOUNCE)

        time.sleep(0.05)
    return -1, -1


def main():
    auto_mode = "--auto" in sys.argv

    import shutil
    if not shutil.which("rtl_433"):
        from payloads._dep_helper import ensure_bin
        img = Image.new("RGB", (W, H), "black")
        d = ScaledDraw(img)
        d.text((64, 40), "Installing rtl_433...", font=font, fill=(255, 200, 0), anchor="mm")
        LCD.LCD_ShowImage(img, 0, 0)
        if not ensure_bin("rtl_433"):
            d.text((64, 60), "Install failed!", font=font_sm, fill=(255, 60, 60), anchor="mm")
            LCD.LCD_ShowImage(img, 0, 0)
            time.sleep(3)
            GPIO.cleanup()
            return 1

    if auto_mode:
        filt_idx, band_idx = 0, 0
        _start_capture(BANDS[0]["freq"])
    else:
        filt_idx, band_idx = _select_filter()
        if filt_idx < 0:
            GPIO.cleanup()
            return 0

    global _current_band, _start_time, _proto_filter_idx
    _current_band = band_idx
    view_idx = 0
    scroll = 0
    _start_time = time.time()

    threading.Thread(target=_write_live_json, daemon=True).start()

    try:
        while _running:
            view = VIEWS[view_idx]

            if view == "live":
                _draw_live(band_idx, scroll)
            elif view == "log":
                _draw_log(scroll)
            elif view == "stats":
                _draw_stats(band_idx)

            web_ctrl = _check_web_control()
            if web_ctrl:
                action = web_ctrl.get("action", "")
                if action == "start" and not _capturing:
                    _start_capture(BANDS[band_idx]["freq"])
                elif action == "stop" and _capturing:
                    _stop_capture()
                elif action == "set_band":
                    bi = web_ctrl.get("value", 0)
                    if 0 <= bi < len(BANDS):
                        band_idx = bi
                        _current_band = bi
                        if _capturing:
                            _start_capture(BANDS[band_idx]["freq"])
                elif action == "set_filter":
                    fi = web_ctrl.get("value", 0)
                    if 0 <= fi < len(PROTO_FILTERS):
                        _proto_filter_idx = fi

            btn = _btn()

            if btn == "KEY3":
                break
            elif btn == "KEY1":
                view_idx = (view_idx + 1) % len(VIEWS)
                scroll = 0
                time.sleep(DEBOUNCE)
            elif btn == "OK":
                if _capturing:
                    _stop_capture()
                else:
                    _start_capture(BANDS[band_idx]["freq"])
                time.sleep(DEBOUNCE)
            elif btn == "UP":
                scroll = max(0, scroll - 1)
                time.sleep(DEBOUNCE)
            elif btn == "DOWN":
                scroll += 1
                time.sleep(DEBOUNCE)
            elif btn == "RIGHT":
                band_idx = (band_idx + 1) % len(BANDS)
                _current_band = band_idx
                if _capturing:
                    _start_capture(BANDS[band_idx]["freq"])
                scroll = 0
                time.sleep(DEBOUNCE)
            elif btn == "LEFT":
                band_idx = (band_idx - 1) % len(BANDS)
                _current_band = band_idx
                if _capturing:
                    _start_capture(BANDS[band_idx]["freq"])
                scroll = 0
                time.sleep(DEBOUNCE)
            elif btn == "KEY2" and view == "live" and not _capturing:
                _proto_filter_idx = (_proto_filter_idx + 1) % len(PROTO_FILTERS)
                time.sleep(DEBOUNCE)
            elif btn == "KEY2":
                with _signal_lock:
                    if _signals:
                        if view == "log":
                            path, count = _export_log()
                            img = Image.new("RGB", (W, H), (8, 10, 16))
                            d = ScaledDraw(img)
                            d.text((64, 50), f"Exported {count} signals", font=font_sm, fill=(0, 255, 100), anchor="mm")
                            d.text((64, 65), path[-30:], font=font_xs, fill=(100, 100, 100), anchor="mm")
                            LCD.LCD_ShowImage(img, 0, 0)
                            time.sleep(1.5)
                        else:
                            last = _signals[-1]
                            path = _save_signal(last)
                            model, _ = _format_signal(last)
                            img = Image.new("RGB", (W, H), (8, 10, 16))
                            d = ScaledDraw(img)
                            d.text((64, 50), f"Saved: {model[:18]}", font=font_sm, fill=(0, 255, 100), anchor="mm")
                            LCD.LCD_ShowImage(img, 0, 0)
                            time.sleep(1)
                time.sleep(DEBOUNCE)

            time.sleep(0.05)

    finally:
        _stop_capture()
        try:
            os.unlink(ISM_LIVE_PATH)
        except OSError:
            pass
        LCD.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
