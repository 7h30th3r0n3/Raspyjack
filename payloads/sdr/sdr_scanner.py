#!/usr/bin/env python3
"""
RaspyJack Payload -- Radio Scanner
====================================
Author: 7h30th3r0n3

Multi-band radio scanner with squelch-based signal detection.
Listens to Airband (AM), Marine VHF, PMR446, FM Broadcast, Emergency.
Scans frequencies and pauses on active signals.

Controls:
  OK          : Start/Stop scanning
  UP/DOWN     : Adjust squelch
  LEFT/RIGHT  : Change band
  KEY1 (SPACE): Toggle Scan/Manual mode
  KEY2 (BKSP) : Step frequency (manual mode)
  KEY3 (ESC)  : Exit
"""

import os
import sys
import time
import math
import struct
import signal
import subprocess
import threading
import json
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
from PIL import Image, ImageDraw
from payloads._display_helper import scaled_font, S, SX, SY
from payloads._input_helper import get_button
from payloads.sdr._sdr_core import recommended_gain

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
font_xl = scaled_font(16)
font_xs = scaled_font(6)

LOOT_DIR = "/root/Raspyjack/loot/SDR/scanner"
LIVE_PATH = "/dev/shm/rj_scanner_live.json"
DEBOUNCE = 0.18

BANDS = [
    {"name": "Airband", "start": 118000000, "end": 137000000, "mod": "usb",
     "rate": 16000, "step": 25000, "desc": "Aviation USB",
     "sdr_rate": 48000},
    {"name": "Marine", "start": 156000000, "end": 163000000, "mod": "fm",
     "rate": 16000, "step": 25000, "desc": "VHF Marine",
     "sdr_rate": 24000},
    {"name": "PMR446", "start": 446006250, "end": 446193750, "mod": "fm",
     "rate": 16000, "step": 12500, "desc": "PMR Walkie",
     "sdr_rate": 24000},
    {"name": "FM Radio", "start": 87500000, "end": 108000000, "mod": "wbfm",
     "rate": 32000, "step": 100000, "desc": "FM Broadcast",
     "sdr_rate": 170000},
    {"name": "Emergency", "start": 150000000, "end": 174000000, "mod": "fm",
     "rate": 16000, "step": 12500, "desc": "SAMU/Pompiers",
     "sdr_rate": 24000},
]

_running = True
_scanning = False
_listening = False
_mode = "scan"
_band_idx = 0
_freq = 118000000
_squelch = 40
_signal_level = 0.0
_paused_on_signal = False
_rtl_proc = None
_lock = threading.Lock()
_activity_log = []
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


def _kill_sdr():
    for prog in ("rtl_fm", "rtl_433", "rtl_adsb", "rtl_sdr", "rtl_power"):
        subprocess.run(["pkill", "-9", prog], capture_output=True)


def _start_rtl_fm():
    global _rtl_proc
    _stop_rtl_fm()
    band = BANDS[_band_idx]
    mod_flag = band["mod"]
    sdr_rate = band.get("sdr_rate", band["rate"])
    out_rate = band["rate"]

    cmd = [
        "rtl_fm", "-M", mod_flag,
        "-f", str(_freq), "-s", str(sdr_rate),
        "-r", str(out_rate), "-l", "0", "-g", str(recommended_gain(_freq)),
    ]

    try:
        _rtl_proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        threading.Thread(target=_reader_thread, daemon=True).start()
    except Exception:
        _rtl_proc = None


def _stop_rtl_fm():
    global _rtl_proc
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
    subprocess.run(["pkill", "-9", "rtl_fm"], capture_output=True)


def _reader_thread():
    global _signal_level
    proc = _rtl_proc
    if not proc:
        return
    try:
        while _running and _listening and proc.poll() is None:
            chunk = proc.stdout.read(4096)
            if not chunk:
                break
            try:
                n = len(chunk) // 2
                if n > 0:
                    samples = struct.unpack(f"<{n}h", chunk[:n * 2])
                    rms = math.sqrt(sum(s * s for s in samples) / n)
                    level = min(100.0, rms / 250.0 * 100.0)
                    with _lock:
                        _signal_level = round(level, 1)
            except Exception:
                pass
    except Exception:
        pass


def _step_freq(direction):
    global _freq
    band = BANDS[_band_idx]
    _freq += band["step"] * direction
    if _freq > band["end"]:
        _freq = band["start"]
    elif _freq < band["start"]:
        _freq = band["end"]
    _retune()


def _retune():
    _stop_rtl_fm()
    time.sleep(0.05)
    _start_rtl_fm()


def _log_activity(duration):
    entry = {
        "ts": time.time(),
        "freq": _freq,
        "freq_display": f"{_freq / 1e6:.3f}",
        "signal": _signal_level,
        "band": BANDS[_band_idx]["name"],
        "duration": round(duration, 1),
    }
    with _lock:
        _activity_log.append(entry)
        if len(_activity_log) > 100:
            _activity_log.pop(0)


def _quick_sweep():
    global _freq
    band = BANDS[_band_idx]
    _stop_rtl_fm()

    cmd = [
        "rtl_power",
        "-f", f"{band['start']}:{band['end']}:{band['step']}",
        "-g", "40", "-i", "1", "-e", "2", "-1",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except (subprocess.TimeoutExpired, Exception):
        return []

    if not result.stdout:
        return []

    all_powers = []
    for line in result.stdout.strip().splitlines():
        parts = line.split(",")
        if len(parts) < 7:
            continue
        try:
            f_start = float(parts[2])
            f_step = float(parts[4])
            powers = [float(x) for x in parts[6:]]
            for i, p in enumerate(powers):
                freq = int(f_start + i * f_step)
                all_powers.append((freq, p))
        except (ValueError, IndexError):
            continue

    if not all_powers:
        return []

    sorted_p = sorted(p for _, p in all_powers)
    median = sorted_p[len(sorted_p) // 2]
    threshold = median + 8.0
    active = sorted(
        [(f, p) for f, p in all_powers if p > threshold],
        key=lambda x: -x[1],
    )
    return [f for f, _ in active[:10]]


def _scan_loop():
    global _paused_on_signal, _freq

    while _running and _listening and _mode == "scan":
        active_freqs = _quick_sweep()

        if not _running or not _listening or _mode != "scan":
            break

        if not active_freqs:
            _paused_on_signal = False
            time.sleep(1.0)
            continue

        for freq in active_freqs:
            if not _running or not _listening or _mode != "scan":
                break
            _freq = freq
            _paused_on_signal = True
            signal_start = time.time()
            _start_rtl_fm()

            quiet_since = 0.0
            listen_start = time.time()
            while _running and _listening and _mode == "scan":
                time.sleep(0.3)
                if not _paused_on_signal:
                    break
                if time.time() - listen_start > 15.0:
                    break
                with _lock:
                    level = _signal_level
                    sq = _squelch
                if level > sq:
                    quiet_since = 0.0
                else:
                    if quiet_since == 0.0:
                        quiet_since = time.time()
                    elif time.time() - quiet_since > 2.0:
                        break

            if _running and _listening and _mode == "scan":
                _log_activity(time.time() - signal_start)
                _paused_on_signal = False
                _stop_rtl_fm()


def _write_live_json():
    while _running:
        try:
            band = BANDS[_band_idx]
            with _lock:
                payload = {
                    "ts": time.time(),
                    "running": _listening,
                    "mode": _mode,
                    "band": band["name"],
                    "band_idx": _band_idx,
                    "freq": _freq,
                    "freq_display": f"{_freq / 1e6:.3f}",
                    "modulation": band["mod"],
                    "squelch": _squelch,
                    "signal_level": _signal_level,
                    "scanning": _mode == "scan" and not _paused_on_signal,
                    "paused_on_signal": _paused_on_signal,
                    "sample_rate": band["rate"],
                    "activity_log": list(_activity_log[-100:]),
                    "bands": [
                        {"name": b["name"], "desc": b["desc"],
                         "start": b["start"], "end": b["end"], "mod": b["mod"]}
                        for b in BANDS
                    ],
                }
            tmp = LIVE_PATH + ".tmp"
            with open(tmp, "w") as f:
                json.dump(payload, f)
            os.replace(tmp, LIVE_PATH)
        except Exception:
            pass
        time.sleep(1.0)


# ---------------------------------------------------------------------------
# LCD Drawing
# ---------------------------------------------------------------------------
def _color_for_level(level):
    if level < 30:
        return (0, 180, 60)
    if level < 60:
        return (200, 180, 0)
    return (255, 50, 50)


def _draw_main():
    img = Image.new("RGB", (W, H), (8, 10, 16))
    draw = ImageDraw.Draw(img)
    band = BANDS[_band_idx]

    # Header bar
    draw.rectangle([(0, 0), (W, SY(14))], fill=(15, 20, 35))
    draw.text((SX(2), SY(2)), "SCANNER", font=font_sm, fill=(0, 200, 255))
    draw.text((SX(50), SY(2)), band["name"], font=font_sm, fill=(255, 200, 0))
    if _listening:
        if _paused_on_signal:
            draw.ellipse([W - SX(10), SY(4), W - SX(4), SY(10)],
                         fill=(0, 255, 0))
        elif _mode == "scan":
            col = (0, 200, 255) if int(time.time() * 2) % 2 else (0, 80, 120)
            draw.ellipse([W - SX(10), SY(4), W - SX(4), SY(10)], fill=col)
        else:
            draw.ellipse([W - SX(10), SY(4), W - SX(4), SY(10)],
                         fill=(100, 100, 100))

    # Frequency display (big)
    freq_str = f"{_freq / 1e6:.3f}"
    y_freq = SY(20)
    draw.text((W // 2, y_freq), freq_str, font=font_xl,
              fill=(0, 220, 255), anchor="mt")
    draw.text((W // 2, y_freq + SY(18)), "MHz", font=font_sm,
              fill=(60, 80, 100), anchor="mt")

    # Modulation badge
    mod_str = band["mod"].upper()
    draw.text((W - SX(20), y_freq + SY(18)), mod_str, font=font_xs,
              fill=(255, 150, 0))

    # Status
    y_status = y_freq + SY(30)
    if not _listening:
        status = "IDLE"
        status_col = (80, 80, 100)
    elif _paused_on_signal:
        status = "SIGNAL"
        status_col = (0, 255, 100)
    elif _mode == "scan":
        status = "SCANNING"
        status_col = (0, 200, 255)
    else:
        status = "LISTENING"
        status_col = (150, 150, 180)
    draw.text((W // 2, y_status), status, font=font, fill=status_col,
              anchor="mt")

    # Signal meter bar
    y_meter = y_status + SY(14)
    bar_x = SX(4)
    bar_w = W - SX(8)
    bar_h = SY(8)
    draw.rectangle([(bar_x, y_meter), (bar_x + bar_w, y_meter + bar_h)],
                   fill=(20, 25, 40))

    with _lock:
        level = _signal_level
    fill_w = int(bar_w * min(100, level) / 100.0)
    if fill_w > 0:
        col = _color_for_level(level)
        draw.rectangle([(bar_x, y_meter),
                        (bar_x + fill_w, y_meter + bar_h)], fill=col)

    # Squelch marker
    sq_x = bar_x + int(bar_w * _squelch / 100.0)
    draw.rectangle([(sq_x, y_meter - SY(2)),
                    (sq_x + 1, y_meter + bar_h + SY(2))],
                   fill=(255, 50, 50))

    # Signal value
    draw.text((W - SX(4), y_meter - SY(1)), f"{int(level)}%",
              font=font_xs, fill=(150, 150, 170), anchor="rt")

    # Squelch value
    draw.text((SX(4), y_meter + bar_h + SY(2)),
              f"SQ:{_squelch}", font=font_xs, fill=(180, 60, 60))

    # Scan position bar
    if _mode == "scan" and _listening:
        y_scan = y_meter + bar_h + SY(12)
        draw.rectangle([(bar_x, y_scan), (bar_x + bar_w, y_scan + SY(3))],
                       fill=(15, 20, 35))
        if band["end"] > band["start"]:
            pct = (_freq - band["start"]) / (band["end"] - band["start"])
            pos_x = bar_x + int(bar_w * pct)
            draw.rectangle([(pos_x - 1, y_scan - SY(1)),
                            (pos_x + 1, y_scan + SY(4))],
                           fill=(0, 200, 255))
        range_str = (f"{band['start']/1e6:.1f}-"
                     f"{band['end']/1e6:.1f} MHz")
        draw.text((W // 2, y_scan + SY(6)), range_str, font=font_xs,
                  fill=(50, 60, 80), anchor="mt")

    # Activity log (last 2 entries)
    y_log = H - SY(34)
    draw.line([(SX(4), y_log), (W - SX(4), y_log)], fill=(25, 30, 50))
    with _lock:
        log_items = list(_activity_log[-2:])
    if log_items:
        for i, entry in enumerate(reversed(log_items)):
            y_e = y_log + SY(2) + i * SY(10)
            t_str = datetime.fromtimestamp(
                entry["ts"]).strftime("%H:%M:%S")
            draw.text((SX(2), y_e), t_str, font=font_xs,
                      fill=(60, 60, 80))
            draw.text((SX(42), y_e),
                      f"{entry['freq_display']} MHz", font=font_xs,
                      fill=(0, 200, 255))
            draw.text((W - SX(30), y_e),
                      f"{entry['duration']}s", font=font_xs,
                      fill=(100, 100, 120))
    else:
        draw.text((W // 2, y_log + SY(8)), "No activity yet",
                  font=font_xs, fill=(40, 40, 60), anchor="mm")

    # Footer
    draw.rectangle([(0, H - SY(12)), (W, H)], fill=(15, 20, 35))
    if _listening:
        footer = "OK:Stop UD:SQ LR:Band K1:Mode"
    else:
        footer = "OK:Start UD:SQ LR:Band K3:Exit"
    draw.text((SX(2), H - SY(11)), footer, font=font_xs,
              fill=(50, 60, 80))

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global _listening, _mode, _band_idx, _freq, _squelch
    global _scanning, _paused_on_signal, _start_time, _signal_level

    auto_mode = "--auto" in sys.argv

    import shutil
    if not shutil.which("rtl_fm"):
        from payloads._dep_helper import ensure_bin
        img = Image.new("RGB", (W, H), "black")
        draw = ImageDraw.Draw(img)
        draw.text((W // 2, H // 2), "Installing rtl-sdr...",
                  font=font, fill=(255, 200, 0), anchor="mm")
        LCD.LCD_ShowImage(img, 0, 0)
        if not ensure_bin("rtl_fm", "rtl-sdr"):
            draw.text((W // 2, H // 2 + SY(15)), "Install failed!",
                      font=font_sm, fill=(255, 60, 60), anchor="mm")
            LCD.LCD_ShowImage(img, 0, 0)
            time.sleep(3)
            GPIO.cleanup()
            return 1

    _kill_sdr()
    time.sleep(0.3)

    _band_idx = 0
    _freq = BANDS[0]["start"]
    _start_time = time.time()

    threading.Thread(target=_write_live_json, daemon=True).start()

    if auto_mode:
        _listening = True
        _start_rtl_fm()
        if _mode == "scan":
            threading.Thread(target=_scan_loop, daemon=True).start()

    try:
        while _running:
            _draw_main()

            btn = _btn()
            if btn == "KEY3":
                break

            elif btn == "OK":
                if _listening:
                    _listening = False
                    _paused_on_signal = False
                    _stop_rtl_fm()
                else:
                    _listening = True
                    _paused_on_signal = False
                    _signal_level = 0.0
                    _start_rtl_fm()
                    if _mode == "scan":
                        threading.Thread(target=_scan_loop,
                                         daemon=True).start()
                time.sleep(DEBOUNCE)

            elif btn == "KEY1":
                if _mode == "scan":
                    _mode = "manual"
                    _paused_on_signal = False
                else:
                    _mode = "scan"
                    _paused_on_signal = False
                    if _listening:
                        threading.Thread(target=_scan_loop,
                                         daemon=True).start()
                time.sleep(DEBOUNCE)

            elif btn == "KEY2":
                if _listening and _mode == "manual":
                    _step_freq(1)
                elif not _listening and _activity_log:
                    os.makedirs(LOOT_DIR, exist_ok=True)
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    path = os.path.join(LOOT_DIR, f"scan_log_{ts}.json")
                    with _lock:
                        data = list(_activity_log)
                    with open(path, "w") as f:
                        json.dump(data, f, indent=2)
                time.sleep(DEBOUNCE)

            elif btn == "UP":
                _squelch = min(100, _squelch + 5)
                time.sleep(DEBOUNCE)

            elif btn == "DOWN":
                _squelch = max(0, _squelch - 5)
                time.sleep(DEBOUNCE)

            elif btn == "RIGHT":
                _band_idx = (_band_idx + 1) % len(BANDS)
                _freq = BANDS[_band_idx]["start"]
                _paused_on_signal = False
                if _listening:
                    _retune()
                    if _mode == "scan":
                        threading.Thread(target=_scan_loop,
                                         daemon=True).start()
                time.sleep(DEBOUNCE)

            elif btn == "LEFT":
                _band_idx = (_band_idx - 1) % len(BANDS)
                _freq = BANDS[_band_idx]["start"]
                _paused_on_signal = False
                if _listening:
                    _retune()
                    if _mode == "scan":
                        threading.Thread(target=_scan_loop,
                                         daemon=True).start()
                time.sleep(DEBOUNCE)

            time.sleep(0.05)

    finally:
        _stop_rtl_fm()
        _kill_sdr()
        try:
            os.unlink(LIVE_PATH)
        except OSError:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    sys.exit(main())
