#!/usr/bin/env python3
"""
RaspyJack Payload -- Object Detector
=======================================
Author: 7h30th3r0n3

Real-time object detection using MobileNet SSD TFLite.
Detects 90 COCO classes: persons, cars, animals, etc.

Controls:
  OK          Start/Stop detection
  UP/DOWN     Adjust confidence threshold
  KEY1        Take screenshot with detections
  KEY3        Exit
"""

import os
import sys
import time
import signal
import subprocess
import threading
import mmap

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
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 12)
        font_sm = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 10)
        font_lg = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 14)
    except Exception:
        font = scaled_font(9)
        font_sm = scaled_font(7)
        font_lg = scaled_font(12)
else:
    font = scaled_font(10)
    font_sm = scaled_font(8)
    font_lg = scaled_font(12)

MODEL_DIR = "/root/Raspyjack/models/mobilenet"
MODEL_PATH = os.path.join(MODEL_DIR, "detect.tflite")
LABELS_PATH = os.path.join(MODEL_DIR, "labelmap.txt")
MODEL_URL = "https://storage.googleapis.com/download.tensorflow.org/models/tflite/coco_ssd_mobilenet_v1_1.0_quant_2018_06_29.zip"
LOOT_DIR = "/root/Raspyjack/loot/Camera/Detections"
FB_DEVICE = "/dev/fb1" if os.path.exists("/dev/fb1") else "/dev/fb0"
FB_SIZE = W * H * 2
DEBOUNCE = 0.20
INPUT_SIZE = 300

_running = True
_detecting = False
_detections = []
_det_lock = threading.Lock()
_fps = 0.0
_conf_threshold = 0.4

COLORS = [
    (255, 50, 50), (50, 255, 50), (50, 50, 255), (255, 255, 50),
    (255, 50, 255), (50, 255, 255), (255, 150, 50), (150, 255, 50),
]

C_BG = (5, 0, 10)
C_HEAD = (30, 0, 30)
C_WHITE = (255, 255, 255)
C_DIM = (80, 80, 80)
C_GREEN = (0, 220, 80)
C_RED = (255, 50, 50)
C_YELLOW = (255, 200, 0)
C_CYAN = (0, 200, 220)
C_DARK = (12, 12, 20)


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _get_btn():
    btn = get_button(PINS, GPIO)
    if btn and btn in _STUCK_PINS and btn not in ("OK", "UP", "DOWN", "LEFT", "RIGHT"):
        return None
    return btn


def _show_msg(text, sub="", color=C_CYAN):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
    if IS_WIDE:
        d.text((W // 2, H // 2 - 10), text, font=font, fill=color,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (10, H // 2 - 15), text, font=font, fill=color)
        if sub:
            d.text((W // 2, H // 2 + 10), sub, font=font_sm, fill=C_DIM,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (10, H // 2 + 5), sub, font=font_sm, fill=C_DIM)
    else:
        d.text((4, 50), text[:17], font=font, fill=color)
        if sub:
            d.text((4, 68), sub[:17], font=font_sm, fill=C_DIM)
    LCD.LCD_ShowImage(img, 0, 0)


def _ensure_model():
    os.makedirs(MODEL_DIR, exist_ok=True)
    if os.path.isfile(MODEL_PATH):
        return True
    _show_msg("Downloading model...", "MobileNet SSD (~4MB)")
    r = subprocess.run(
        ["wget", "--no-check-certificate", "-q", "-O", "/tmp/ssd.zip", MODEL_URL],
        capture_output=True, timeout=60)
    if r.returncode != 0:
        return False
    subprocess.run(["unzip", "-q", "-o", "/tmp/ssd.zip", "-d", MODEL_DIR],
                   capture_output=True, timeout=30)
    os.remove("/tmp/ssd.zip")
    return os.path.isfile(MODEL_PATH)


def _load_labels():
    if not os.path.isfile(LABELS_PATH):
        return {}
    labels = {}
    with open(LABELS_PATH, "r") as f:
        for i, line in enumerate(f):
            labels[i] = line.strip()
    return labels


def _detect_thread():
    """Capture frames, run inference, display with bounding boxes."""
    global _detecting, _detections, _fps
    from ai_edge_litert.interpreter import Interpreter

    interp = Interpreter(model_path=MODEL_PATH)
    interp.allocate_tensors()
    inp_detail = interp.get_input_details()[0]
    out_details = interp.get_output_details()
    labels = _load_labels()

    proc = subprocess.Popen(
        ["rpicam-vid", "--width", str(W), "--height", str(H),
         "--framerate", "8", "--codec", "yuv420",
         "--rotation", "180", "-t", "0", "--nopreview", "-o", "-"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)

    frame_size = W * H * 3 // 2
    fb_fd = None
    fb_map = None
    try:
        fb_fd = os.open(FB_DEVICE, os.O_RDWR)
        fb_map = mmap.mmap(fb_fd, FB_SIZE, mmap.MAP_SHARED,
                           mmap.PROT_WRITE | mmap.PROT_READ)
    except Exception:
        pass

    frame_count = 0
    t_start = time.time()

    try:
        while _detecting and _running and proc.poll() is None:
            raw = b""
            while len(raw) < frame_size and _detecting:
                chunk = proc.stdout.read(frame_size - len(raw))
                if not chunk:
                    break
                raw += chunk
            if len(raw) < frame_size:
                break

            yuv = np.frombuffer(raw, dtype=np.uint8)
            y_plane = yuv[:W * H].reshape(H, W)
            u_raw = yuv[W * H:W * H + W * H // 4].reshape(H // 2, W // 2)
            v_raw = yuv[W * H + W * H // 4:].reshape(H // 2, W // 2)
            u = np.repeat(np.repeat(u_raw, 2, axis=0), 2, axis=1).astype(np.int16) - 128
            v = np.repeat(np.repeat(v_raw, 2, axis=0), 2, axis=1).astype(np.int16) - 128
            y16 = y_plane.astype(np.int16)

            r = np.clip(y16 + ((359 * v) >> 8), 0, 255).astype(np.uint8)
            g = np.clip(y16 - ((88 * u + 183 * v) >> 8), 0, 255).astype(np.uint8)
            b = np.clip(y16 + ((454 * u) >> 8), 0, 255).astype(np.uint8)

            rgb_frame = np.stack([r, g, b], axis=-1)

            input_img = Image.fromarray(rgb_frame).resize((INPUT_SIZE, INPUT_SIZE))
            input_data = np.expand_dims(np.array(input_img, dtype=np.uint8), axis=0)

            interp.set_tensor(inp_detail["index"], input_data)
            interp.invoke()

            boxes = interp.get_tensor(out_details[0]["index"])[0]
            classes = interp.get_tensor(out_details[1]["index"])[0]
            scores = interp.get_tensor(out_details[2]["index"])[0]

            dets = []
            for i in range(len(scores)):
                if scores[i] >= _conf_threshold:
                    ymin, xmin, ymax, xmax = boxes[i]
                    cls_id = int(classes[i])
                    label = labels.get(cls_id, f"class{cls_id}")
                    dets.append({
                        "label": label,
                        "score": float(scores[i]),
                        "box": (int(xmin * W), int(ymin * H), int(xmax * W), int(ymax * H)),
                        "color": COLORS[cls_id % len(COLORS)],
                    })

            with _det_lock:
                _detections = dets

            if fb_map:
                fb_map.seek(0)
                fb_map.write(rgb565.tobytes())

            # Flush accumulated frames during inference to stay in sync
            try:
                import select
                while select.select([proc.stdout], [], [], 0)[0]:
                    discard = proc.stdout.read(frame_size)
                    if not discard:
                        break
            except Exception:
                pass

            frame_count += 1
            elapsed = time.time() - t_start
            if elapsed > 0:
                _fps = frame_count / elapsed
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
        _detecting = False


def _draw_status():
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    with _det_lock:
        dets = list(_detections)

    if IS_WIDE:
        d.rectangle([0, 0, W, 20], fill=C_HEAD)
        d.text((W // 2, 10), "OBJECT DETECTOR", font=font_lg, fill=C_CYAN,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 55, 1), "OBJECT DETECTOR", font=font_lg, fill=C_CYAN)

        y = 26
        status = "DETECTING" if _detecting else "STOPPED"
        sc = C_GREEN if _detecting else C_RED
        d.text((8, y), f"Status: {status}  FPS: {_fps:.1f}", font=font, fill=sc)
        y += 18
        d.text((8, y), f"Threshold: {int(_conf_threshold*100)}%", font=font, fill=C_WHITE)
        y += 18
        d.text((8, y), f"Objects: {len(dets)}", font=font, fill=C_YELLOW)
        y += 18
        for det in dets[:4]:
            d.text((12, y), f"{det['label']} ({int(det['score']*100)}%)",
                   font=font_sm, fill=det['color'])
            y += 14

        d.rectangle([0, H - 16, W, H], fill=C_DARK)
        d.text((W // 2, H - 8), "OK:Detect  UP/DN:Threshold  K1:Screenshot  K3:Exit",
               font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (2, H - 13), "OK UP/DN K1:Shot K3:X", font=font_sm, fill=C_DIM)
    else:
        d.rectangle([0, 0, 128, 14], fill=C_HEAD)
        d.text((10, 1), "OBJ DETECT", font=font_lg, fill=C_CYAN)
        y = 18
        d.text((4, y), f"{'ON' if _detecting else 'OFF'} {_fps:.1f}fps", font=font_sm, fill=C_GREEN if _detecting else C_RED)
        y += 14
        d.text((4, y), f"Thr:{int(_conf_threshold*100)}% Obj:{len(dets)}", font=font_sm, fill=C_WHITE)
        y += 14
        for det in dets[:3]:
            d.text((4, y), f"{det['label'][:10]} {int(det['score']*100)}%", font=font_sm, fill=C_CYAN)
            y += 13
        d.text((4, 108), "OK K3:X", font=font_sm, fill=C_DIM)

    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global _running, _detecting, _conf_threshold

    if not _ensure_model():
        _show_msg("Model download failed!", "Check internet")
        time.sleep(3)
        GPIO.cleanup()
        return 1

    _show_msg("Loading model...", "MobileNet SSD")
    try:
        from ai_edge_litert.interpreter import Interpreter
    except ImportError:
        _show_msg("TFLite not installed!", "Run BirdNET first")
        time.sleep(3)
        GPIO.cleanup()
        return 1

    last_btn = 0
    det_thread = None
    _draw_status()

    while _running:
        btn = _get_btn()
        now = time.time()

        if btn == "KEY3":
            _detecting = False
            break

        if btn == "OK" and now - last_btn > DEBOUNCE:
            last_btn = now
            if not _detecting:
                _detecting = True
                det_thread = threading.Thread(target=_detect_thread, daemon=True)
                det_thread.start()
            else:
                _detecting = False
                if det_thread:
                    det_thread.join(timeout=3)

        if btn == "UP" and now - last_btn > DEBOUNCE:
            last_btn = now
            _conf_threshold = min(0.9, _conf_threshold + 0.05)

        if btn == "DOWN" and now - last_btn > DEBOUNCE:
            last_btn = now
            _conf_threshold = max(0.1, _conf_threshold - 0.05)

        if btn == "KEY1" and now - last_btn > DEBOUNCE:
            last_btn = now
            os.makedirs(LOOT_DIR, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S") if True else ""
            from datetime import datetime
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = os.path.join(LOOT_DIR, f"detect_{ts}.jpg")
            subprocess.run(
                ["rpicam-still", "-o", path, "--width", "1920", "--height", "1080",
                 "-t", "300", "--nopreview", "--rotation", "180"],
                capture_output=True, timeout=10)

        if not _detecting:
            _draw_status()

        time.sleep(0.15)

    _detecting = False
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
