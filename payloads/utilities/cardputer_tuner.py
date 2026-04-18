#!/usr/bin/env python3
"""
RaspyJack Payload -- Cardputer Tuner
==========================================

Adjust the Cardputer frame generation settings used by raspyjack.py.
Settings are persisted as a systemd override for raspyjack.service and
take effect after the service is restarted.

Controls:
  UP / DOWN    -- Navigate rows
  LEFT / RIGHT -- Change selected value
  OK           -- Run selected action
  KEY3         -- Exit
"""

import os
import sys
import time
import shlex
import signal
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROW_H = 12
DEBOUNCE = 0.18

SERVICE_NAME = "raspyjack.service"
OVERRIDE_DIR = "/etc/systemd/system/raspyjack.service.d"
OVERRIDE_PATH = os.path.join(OVERRIDE_DIR, "cardputer-frame.conf")

ENV_MODE = "RJ_CARDPUTER_FRAME_MODE"
ENV_QUALITY = "RJ_CARDPUTER_FRAME_QUALITY"
ENV_SUBSAMPLING = "RJ_CARDPUTER_FRAME_SUBSAMPLING"
ENV_FPS = "RJ_CARDPUTER_FRAME_FPS"

MODE_OPTIONS = ["stretch", "contain", "fit"]
FPS_MIN = 1.0
FPS_MAX = 12.0
FPS_STEP = 0.5

DEFAULT_CONFIG = {
    "mode": "stretch",
    "quality": 60,
    "subsampling": 2,
    "fps": 4.0,
}

MENU_ROWS = [
    "mode",
    "quality",
    "subsampling",
    "fps",
    "save",
    "apply",
    "defaults",
]

running = True


def _cleanup(*_args):
    global running
    running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


def _clamp_int(value, low, high):
    return max(low, min(high, int(value)))


def _clamp_float(value, low, high):
    return max(low, min(high, float(value)))


def _normalize_mode(value):
    mode = str(value or DEFAULT_CONFIG["mode"]).strip().lower()
    return mode if mode in MODE_OPTIONS else DEFAULT_CONFIG["mode"]


def _normalize_quality(value):
    try:
        return _clamp_int(int(value), 1, 100)
    except Exception:
        return DEFAULT_CONFIG["quality"]


def _normalize_subsampling(value):
    try:
        return _clamp_int(int(value), 0, 2)
    except Exception:
        return DEFAULT_CONFIG["subsampling"]


def _normalize_fps(value):
    try:
        fps = _clamp_float(float(value), FPS_MIN, FPS_MAX)
        return round(round(fps / FPS_STEP) * FPS_STEP, 1)
    except Exception:
        return DEFAULT_CONFIG["fps"]


def _format_fps(value):
    numeric = float(value)
    if abs(numeric - round(numeric)) < 0.05:
        return str(int(round(numeric)))
    return f"{numeric:.1f}".rstrip("0").rstrip(".")


def _default_config():
    return dict(DEFAULT_CONFIG)


def _service_status():
    try:
        result = subprocess.run(
            ["systemctl", "is-active", SERVICE_NAME],
            capture_output=True,
            text=True,
            timeout=5,
        )
        status = result.stdout.strip() or result.stderr.strip()
        return status or "unknown"
    except Exception:
        return "unknown"


def _load_override_values():
    values = {}
    if not os.path.isfile(OVERRIDE_PATH):
        return values
    try:
        with open(OVERRIDE_PATH, "r") as handle:
            for raw_line in handle:
                stripped = raw_line.strip()
                if not stripped.startswith("Environment="):
                    continue
                payload = stripped.split("=", 1)[1].strip()
                for token in shlex.split(payload):
                    if "=" not in token:
                        continue
                    key, value = token.split("=", 1)
                    values[key] = value
    except Exception:
        return {}
    return values


def _load_config():
    values = _load_override_values()
    cfg = _default_config()
    cfg["mode"] = _normalize_mode(values.get(ENV_MODE, cfg["mode"]))
    cfg["quality"] = _normalize_quality(values.get(ENV_QUALITY, cfg["quality"]))
    cfg["subsampling"] = _normalize_subsampling(values.get(ENV_SUBSAMPLING, cfg["subsampling"]))
    cfg["fps"] = _normalize_fps(values.get(ENV_FPS, cfg["fps"]))
    return cfg


def _build_override_content(cfg):
    return "\n".join([
        "[Service]",
        f"Environment={ENV_MODE}={cfg['mode']}",
        f"Environment={ENV_QUALITY}={cfg['quality']}",
        f"Environment={ENV_SUBSAMPLING}={cfg['subsampling']}",
        f"Environment={ENV_FPS}={_format_fps(cfg['fps'])}",
        "",
    ])


def _write_override(cfg):
    try:
        os.makedirs(OVERRIDE_DIR, exist_ok=True)
        temp_path = OVERRIDE_PATH + ".tmp"
        with open(temp_path, "w") as handle:
            handle.write(_build_override_content(cfg))
        os.replace(temp_path, OVERRIDE_PATH)
        return True, "Saved override"
    except Exception as exc:
        return False, f"Save failed: {str(exc)[:24]}"


def _delete_override():
    try:
        if os.path.exists(OVERRIDE_PATH):
            os.remove(OVERRIDE_PATH)
        return True, "Defaults restored"
    except Exception as exc:
        return False, f"Delete failed: {str(exc)[:22]}"


def _reload_and_restart():
    try:
        subprocess.run(["systemctl", "daemon-reload"], check=True, timeout=10)
        subprocess.run(["systemctl", "restart", SERVICE_NAME], check=True, timeout=20)
        return True, "Applied and restarted"
    except Exception as exc:
        return False, f"Restart failed: {str(exc)[:20]}"


def _draw_header(draw, title):
    draw.rectangle((0, 0, 127, 13), fill="#111")
    draw.text((2, 1), title[:22], font=FONT, fill="#00CCFF")


def _draw_footer(draw, text):
    draw.rectangle((0, 116, 127, 127), fill="#111")
    draw.text((2, 117), text[:26], font=FONT, fill="#666")


def _row_text(row_name, cfg):
    if row_name == "mode":
        return f"Mode: {cfg['mode']}"
    if row_name == "quality":
        return f"Quality: {cfg['quality']}"
    if row_name == "subsampling":
        return f"Subsample: {cfg['subsampling']}"
    if row_name == "fps":
        return f"FPS: {_format_fps(cfg['fps'])}"
    if row_name == "save":
        return "Save override"
    if row_name == "apply":
        return "Apply + restart"
    return "Restore defaults"


def _draw_screen(lcd, cfg, cursor, status_text, saved_cfg, service_status):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    draw = ScaledDraw(img)
    _draw_header(draw, "CARDPUTER FRAME")

    is_dirty = cfg != saved_cfg
    dirty_label = "*dirty" if is_dirty else "saved"
    service_label = service_status[:10]
    draw.text((2, 16), f"Svc:{service_label} {dirty_label}", font=FONT, fill="#888")

    y = 30
    for index, row_name in enumerate(MENU_ROWS):
        selected = index == cursor
        prefix = ">" if selected else " "
        color = "#FFFF00" if selected else "#CCCCCC"
        if row_name in ("save", "apply", "defaults"):
            color = "#00FF99" if selected else "#88AA88"
        draw.text((2, y), f"{prefix} {_row_text(row_name, cfg)[:22]}", font=FONT, fill=color)
        y += ROW_H

    _draw_footer(draw, status_text)
    lcd.LCD_ShowImage(img, 0, 0)


def _adjust_config(cfg, row_name, delta):
    if row_name == "mode":
        current_index = MODE_OPTIONS.index(cfg["mode"])
        cfg["mode"] = MODE_OPTIONS[(current_index + delta) % len(MODE_OPTIONS)]
    elif row_name == "quality":
        cfg["quality"] = _clamp_int(cfg["quality"] + delta, 1, 100)
    elif row_name == "subsampling":
        cfg["subsampling"] = _clamp_int(cfg["subsampling"] + delta, 0, 2)
    elif row_name == "fps":
        cfg["fps"] = _normalize_fps(cfg["fps"] + (delta * FPS_STEP))


GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD_Config.GPIO_Init()
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
LCD.LCD_Clear()
FONT = scaled_font()


def main():
    saved_cfg = _load_config()
    cfg = dict(saved_cfg)
    cursor = 0
    status_text = "Edit values, OK=action"
    service_status = _service_status()
    next_status_refresh = 0.0

    try:
        while running:
            now = time.monotonic()
            if now >= next_status_refresh:
                service_status = _service_status()
                next_status_refresh = now + 1.0

            _draw_screen(LCD, cfg, cursor, status_text, saved_cfg, service_status)
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break
            if btn == "UP":
                cursor = (cursor - 1) % len(MENU_ROWS)
                time.sleep(DEBOUNCE)
                continue
            if btn == "DOWN":
                cursor = (cursor + 1) % len(MENU_ROWS)
                time.sleep(DEBOUNCE)
                continue

            row_name = MENU_ROWS[cursor]

            if btn == "LEFT" and row_name in ("mode", "quality", "subsampling", "fps"):
                _adjust_config(cfg, row_name, -1)
                status_text = f"Updated {row_name}"
                time.sleep(DEBOUNCE)
                continue
            if btn == "RIGHT" and row_name in ("mode", "quality", "subsampling", "fps"):
                _adjust_config(cfg, row_name, 1)
                status_text = f"Updated {row_name}"
                time.sleep(DEBOUNCE)
                continue

            if btn == "OK":
                if row_name == "save":
                    ok, message = _write_override(cfg)
                    status_text = message
                    if ok:
                        saved_cfg = dict(cfg)
                elif row_name == "apply":
                    ok, message = _write_override(cfg)
                    if ok:
                        saved_cfg = dict(cfg)
                        ok, message = _reload_and_restart()
                        service_status = _service_status()
                        next_status_refresh = 0.0
                    status_text = message
                elif row_name == "defaults":
                    ok, message = _delete_override()
                    if ok:
                        cfg = _default_config()
                        saved_cfg = _default_config()
                        ok, message = _reload_and_restart()
                        service_status = _service_status()
                        next_status_refresh = 0.0
                    status_text = message
                time.sleep(0.25)

            time.sleep(0.05)
    finally:
        time.sleep(0.2)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
