#!/usr/bin/env python3
"""
RaspyJack Payload -- Surveillance
===================================
Author: 7h30th3r0n3

Motion detection with auto-capture and video recording.
Monitors camera feed, triggers on movement.

Controls:
  OK          Start/Stop monitoring
  UP/DOWN     Adjust sensitivity
  KEY1        Toggle auto-record (photo vs video on trigger)
  KEY2        View captures
  KEY3        Exit
"""

import os
import sys
import time
import signal
import subprocess
import threading
import mmap
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
import numpy as np
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

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

FB_DEVICE = "/dev/fb1" if os.path.exists("/dev/fb1") else "/dev/fb0"
FB_SIZE = W * H * 2
LOOT_DIR = "/root/Raspyjack/loot/Camera/Surveillance"
DEBOUNCE = 0.20

SENSITIVITIES = [
    ("Low", 0.08),
    ("Medium", 0.04),
    ("High", 0.02),
    ("Very High", 0.01),
]

_running = True
_monitoring = False
_motion_level = 0.0
_triggers = 0
_last_trigger = 0
_mode = "photo"

C_BG = (5, 0, 0)
C_HEAD = (30, 0, 0)
C_GREEN = (0, 220, 80)
C_WHITE = (255, 255, 255)
C_DIM = (80, 80, 80)
C_DARK = (15, 10, 10)
C_RED = (255, 50, 50)
C_YELLOW = (255, 200, 0)
C_CYAN = (0, 200, 220)


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


def _capture_photo():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"motion_{ts}.jpg")
    subprocess.run(
        ["rpicam-still", "-o", path, "--width", "1920", "--height", "1080",
         "-t", "300", "--nopreview", "-q", "85", "--rotation", "180"],
        capture_output=True, timeout=10)
    return path if os.path.isfile(path) else None


def _capture_video(duration=10):
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"motion_{ts}.h264")
    subprocess.run(
        ["rpicam-vid", "-o", path, "--width", "1280", "--height", "720",
         "--framerate", "30", f"-t", str(duration * 1000),
         "--nopreview", "--rotation", "180", "--codec", "h264"],
        capture_output=True, timeout=duration + 5)
    return path if os.path.isfile(path) else None


def _monitor_thread(sensitivity_idx):
    """Monitor camera for motion, trigger on movement."""
    global _monitoring, _motion_level, _triggers, _last_trigger

    threshold = SENSITIVITIES[sensitivity_idx][1]

    proc = subprocess.Popen(
        ["rpicam-vid", "--width", str(W), "--height", str(H),
         "--framerate", "8", "--codec", "yuv420",
         "--rotation", "180", "-t", "0", "--nopreview", "-o", "-"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)

    frame_size = W * H * 3 // 2
    prev_frame = None
    fb_fd = None
    fb_map = None

    try:
        fb_fd = os.open(FB_DEVICE, os.O_RDWR)
        fb_map = mmap.mmap(fb_fd, FB_SIZE, mmap.MAP_SHARED,
                           mmap.PROT_WRITE | mmap.PROT_READ)
    except Exception:
        pass

    try:
        while _monitoring and _running and proc.poll() is None:
            raw = b""
            while len(raw) < frame_size and _monitoring:
                chunk = proc.stdout.read(frame_size - len(raw))
                if not chunk:
                    break
                raw += chunk
            if len(raw) < frame_size:
                break

            yuv = np.frombuffer(raw, dtype=np.uint8)
            gray = yuv[:W * H].reshape(H, W)

            if fb_map:
                y16 = gray.astype(np.int16)
                u_raw = yuv[W * H:W * H + W * H // 4].reshape(H // 2, W // 2)
                v_raw = yuv[W * H + W * H // 4:].reshape(H // 2, W // 2)
                u = np.repeat(np.repeat(u_raw, 2, axis=0), 2, axis=1).astype(np.int16) - 128
                v = np.repeat(np.repeat(v_raw, 2, axis=0), 2, axis=1).astype(np.int16) - 128
                r = np.clip(y16 + ((359 * v) >> 8), 0, 255).astype(np.uint8)
                g = np.clip(y16 - ((88 * u + 183 * v) >> 8), 0, 255).astype(np.uint8)
                b_ch = np.clip(y16 + ((454 * u) >> 8), 0, 255).astype(np.uint8)
                rgb565 = ((r.astype(np.uint16) >> 3) << 11) | \
                         ((g.astype(np.uint16) >> 2) << 5) | \
                         (b_ch.astype(np.uint16) >> 3)
                fb_map.seek(0)
                fb_map.write(rgb565.tobytes())

            if prev_frame is not None:
                diff = np.abs(gray.astype(np.int16) - prev_frame.astype(np.int16))
                motion_pixels = np.sum(diff > 25)
                _motion_level = motion_pixels / diff.size

                if _motion_level > threshold and time.time() - _last_trigger > 5:
                    _last_trigger = time.time()
                    _triggers += 1

                    proc.send_signal(signal.SIGSTOP)
                    if _mode == "photo":
                        _capture_photo()
                    else:
                        _capture_video(10)
                    proc.send_signal(signal.SIGCONT)

            prev_frame = gray.copy()
    except Exception:
        pass
    finally:
        proc.kill()
        try:
            if fb_map:
                fb_map.close()
            if fb_fd is not None:
                os.close(fb_fd)
        except Exception:
            pass
        _monitoring = False


def _draw_screen(sensitivity_idx, elapsed):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    sens_name = SENSITIVITIES[sensitivity_idx][0]
    status = "ARMED" if _monitoring else "DISARMED"
    sc = C_RED if _monitoring else C_DIM

    if IS_WIDE:
        d.rectangle([0, 0, W, 22], fill=C_HEAD)
        d.text((W // 2, 11), "SURVEILLANCE", font=font_lg, fill=C_RED,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 50, 2), "SURVEILLANCE", font=font_lg, fill=C_RED)

        y = 28
        d.text((8, y), f"Status: {status}", font=font, fill=sc)
        y += 18
        d.text((8, y), f"Sensitivity: {sens_name}", font=font, fill=C_WHITE)
        y += 18
        d.text((8, y), f"Mode: {'Photo' if _mode == 'photo' else 'Video 10s'}", font=font, fill=C_CYAN)
        y += 18
        d.text((8, y), f"Triggers: {_triggers}", font=font, fill=C_YELLOW)
        y += 18
        motion_pct = int(_motion_level * 100)
        bar_w = int((W - 80) * min(_motion_level * 10, 1.0))
        d.text((8, y), f"Motion: {motion_pct}%", font=font_sm, fill=C_WHITE)
        d.rectangle([80, y + 2, W - 8, y + 12], fill=C_DARK)
        if bar_w > 0:
            color = C_GREEN if _motion_level < SENSITIVITIES[sensitivity_idx][1] else C_RED
            d.rectangle([80, y + 2, 80 + bar_w, y + 12], fill=color)

        if _monitoring and elapsed > 0:
            y += 18
            m = int(elapsed) // 60
            s = int(elapsed) % 60
            d.text((8, y), f"Uptime: {m}m{s:02d}s", font=font_sm, fill=C_DIM)

        d.rectangle([0, H - 16, W, H], fill=C_DARK)
        d.text((W // 2, H - 8), f"OK:{'Disarm' if _monitoring else 'Arm'}  UP/DN:Sens  K1:Mode  K3:Exit",
               font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (2, H - 13), "OK K1:Mode K3:X", font=font_sm, fill=C_DIM)
    else:
        d.rectangle([0, 0, 128, 14], fill=C_HEAD)
        d.text((10, 1), "SURVEIL", font=font_lg, fill=C_RED)
        y = 18
        d.text((4, y), f"{status} {sens_name}", font=font_sm, fill=sc)
        y += 14
        d.text((4, y), f"Trig:{_triggers} {_mode}", font=font_sm, fill=C_YELLOW)
        y += 14
        d.text((4, y), f"Mot:{int(_motion_level*100)}%", font=font_sm, fill=C_WHITE)
        d.text((4, 108), "OK K1:Mode K3:X", font=font_sm, fill=C_DIM)

    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global _running, _monitoring, _mode, _triggers

    os.makedirs(LOOT_DIR, exist_ok=True)
    sensitivity_idx = 1
    last_btn = 0
    start_time = 0
    mon_thread = None

    while _running:
        btn = _get_btn()
        now = time.time()

        if btn == "KEY3":
            _monitoring = False
            break

        if btn == "OK" and now - last_btn > DEBOUNCE:
            last_btn = now
            if not _monitoring:
                _monitoring = True
                _triggers = 0
                start_time = now
                mon_thread = threading.Thread(
                    target=_monitor_thread, args=(sensitivity_idx,), daemon=True)
                mon_thread.start()
            else:
                _monitoring = False
                if mon_thread:
                    mon_thread.join(timeout=3)

        if btn == "UP" and now - last_btn > DEBOUNCE and not _monitoring:
            last_btn = now
            sensitivity_idx = (sensitivity_idx + 1) % len(SENSITIVITIES)

        if btn == "DOWN" and now - last_btn > DEBOUNCE and not _monitoring:
            last_btn = now
            sensitivity_idx = (sensitivity_idx - 1) % len(SENSITIVITIES)

        if btn == "KEY1" and now - last_btn > DEBOUNCE:
            last_btn = now
            _mode = "video" if _mode == "photo" else "photo"

        elapsed = now - start_time if _monitoring else 0
        if not _monitoring:
            _draw_screen(sensitivity_idx, elapsed)
        time.sleep(0.2)

    _monitoring = False
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
