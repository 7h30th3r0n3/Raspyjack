#!/usr/bin/env python3
"""
RaspyJack Payload -- CCTV Live MJPEG Viewer
=============================================
Author: 7h30th3r0n3

Streams MJPEG video feeds to the 128x128 LCD.  Loads camera URLs from
``/root/Raspyjack/loot/CCTV/cctv_live.txt`` (format: ``Name | URL``).
Also accepts manual URL input via config file.

Reads the HTTP multipart/x-mixed-replace stream, extracts JPEG frames,
resizes them to 128x128, and displays on the LCD in real time.

Setup / Prerequisites
---------------------
- ``requests`` Python package.
- Populated ``cctv_live.txt`` from the CCTV Scanner payload, or manual
  URL entries in config.

Controls
--------
  LEFT / RIGHT  -- Previous / next camera
  OK            -- Pause / resume stream
  KEY1          -- Toggle overlay (camera name, FPS, URL)
  KEY2          -- Screenshot to loot
  KEY3          -- Exit
"""

import os
import sys
import time
import re
import threading
from io import BytesIO
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
font = ImageFont.load_default()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LIVE_FILE = "/root/Raspyjack/loot/CCTV/cctv_live.txt"
CONFIG_DIR = "/root/Raspyjack/config/cctv_viewer"
SCREENSHOT_DIR = "/root/Raspyjack/loot/CCTV/screenshots"
MANUAL_URLS_FILE = os.path.join(CONFIG_DIR, "manual_urls.txt")
os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

DEBOUNCE = 0.22

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_state = {
    "cameras": [],            # list of (name, url)
    "cam_idx": 0,
    "paused": False,
    "show_overlay": True,
    "frame": None,            # current PIL Image (128x128)
    "fps": 0.0,
    "status": "Loading...",
    "streaming": False,
    "stop": False,
}


def _get(key):
    with _lock:
        val = _state[key]
        if isinstance(val, list):
            return list(val)
        return val


def _set(**kw):
    with _lock:
        for k, v in kw.items():
            _state[k] = v


# ---------------------------------------------------------------------------
# Camera list loading
# ---------------------------------------------------------------------------
def _load_cameras():
    """Load camera list from loot file and manual config."""
    cameras = []

    for path in [LIVE_FILE, MANUAL_URLS_FILE]:
        if os.path.isfile(path):
            try:
                with open(path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "|" in line:
                            parts = line.split("|", 1)
                            name = parts[0].strip()
                            url = parts[1].strip()
                        else:
                            name = f"Cam{len(cameras) + 1}"
                            url = line
                        if url:
                            cameras.append((name, url))
            except Exception:
                pass

    _set(cameras=cameras)
    if not cameras:
        _set(status="No cameras found")
    return cameras


# ---------------------------------------------------------------------------
# MJPEG stream reader
# ---------------------------------------------------------------------------
def _stream_mjpeg(url):
    """
    Connect to MJPEG stream and continuously decode frames.
    Handles multipart/x-mixed-replace boundary protocol.
    """
    try:
        import requests
    except ImportError:
        _set(status="requests not installed")
        return

    _set(streaming=True, status="Connecting...")

    try:
        resp = requests.get(url, stream=True, timeout=10, verify=False)
        resp.raise_for_status()
    except Exception as exc:
        _set(streaming=False, status=f"Err: {str(exc)[:16]}")
        return

    content_type = resp.headers.get("Content-Type", "")

    # Extract boundary
    boundary = None
    m = re.search(r"boundary=(.+?)(?:;|$)", content_type)
    if m:
        boundary = m.group(1).strip().encode()
    else:
        boundary = b"--myboundary"

    if not boundary.startswith(b"--"):
        boundary = b"--" + boundary

    _set(status="Streaming...")
    buf = b""
    frame_count = 0
    fps_start = time.time()

    try:
        for chunk in resp.iter_content(chunk_size=4096):
            if _get("stop"):
                break
            if _get("paused"):
                time.sleep(0.1)
                continue

            buf += chunk

            while True:
                # Find JPEG start
                jpg_start = buf.find(b"\xff\xd8")
                if jpg_start < 0:
                    break

                # Find JPEG end
                jpg_end = buf.find(b"\xff\xd9", jpg_start + 2)
                if jpg_end < 0:
                    break

                jpg_end += 2
                jpg_data = buf[jpg_start:jpg_end]
                buf = buf[jpg_end:]

                try:
                    img = Image.open(BytesIO(jpg_data))
                    img = img.resize((WIDTH, HEIGHT), Image.LANCZOS)
                    _set(frame=img)
                    frame_count += 1

                    elapsed = time.time() - fps_start
                    if elapsed >= 1.0:
                        _set(fps=round(frame_count / elapsed, 1))
                        frame_count = 0
                        fps_start = time.time()
                except Exception:
                    pass

            # Prevent buffer from growing unbounded
            if len(buf) > 500000:
                buf = buf[-100000:]

    except Exception as exc:
        _set(status=f"Stream err: {str(exc)[:14]}")
    finally:
        try:
            resp.close()
        except Exception:
            pass
        _set(streaming=False)


def _stream_single_jpeg(url):
    """
    Fallback for non-MJPEG: repeatedly fetch a single JPEG snapshot.
    """
    try:
        import requests
    except ImportError:
        _set(status="requests not installed")
        return

    _set(streaming=True, status="Snapshot mode...")
    frame_count = 0
    fps_start = time.time()

    while not _get("stop"):
        if _get("paused"):
            time.sleep(0.2)
            continue

        try:
            resp = requests.get(url, timeout=5, verify=False)
            if resp.status_code == 200:
                img = Image.open(BytesIO(resp.content))
                img = img.resize((WIDTH, HEIGHT), Image.LANCZOS)
                _set(frame=img)
                frame_count += 1
                elapsed = time.time() - fps_start
                if elapsed >= 1.0:
                    _set(fps=round(frame_count / elapsed, 1))
                    frame_count = 0
                    fps_start = time.time()
        except Exception:
            pass
        time.sleep(0.2)

    _set(streaming=False)


def _start_stream(url):
    """Start streaming in background thread."""
    _set(stop=False, streaming=False, frame=None, fps=0.0)

    def _worker():
        # Determine stream type
        content_type = ""
        try:
            import requests
            resp = requests.head(url, timeout=5, verify=False)
            content_type = resp.headers.get("Content-Type", "").lower()
        except Exception:
            pass

        if "multipart" in content_type or "mjpeg" in url.lower():
            _stream_mjpeg(url)
        elif "image" in content_type or url.endswith((".jpg", ".jpeg", ".png")):
            _stream_single_jpeg(url)
        else:
            # Try MJPEG first
            _stream_mjpeg(url)

    threading.Thread(target=_worker, daemon=True).start()


def _stop_stream():
    """Signal current stream to stop."""
    _set(stop=True)
    # Wait briefly for thread to finish
    for _ in range(20):
        if not _get("streaming"):
            break
        time.sleep(0.05)


# ---------------------------------------------------------------------------
# LCD drawing
# ---------------------------------------------------------------------------
def _draw_lcd():
    frame = _get("frame")
    show_overlay = _get("show_overlay")
    cameras = _get("cameras")
    cam_idx = _get("cam_idx")
    paused = _get("paused")
    fps = _get("fps")
    status = _get("status")

    if frame is not None:
        img = frame.copy().convert("RGB")
    else:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ImageDraw.Draw(img)
        d.text((10, 55), status[:20], font=font, fill="#888")

    if show_overlay and cameras:
        d = ImageDraw.Draw(img)
        # Semi-transparent top bar
        d.rectangle((0, 0, 127, 12), fill="#000000")
        name = cameras[cam_idx][0] if cam_idx < len(cameras) else "?"
        d.text((2, 1), f"{name[:14]}", font=font, fill="#00FF00")
        d.text((100, 1), f"{fps}fps", font=font, fill="#FFFF00")

        # Bottom bar
        d.rectangle((0, 116, 127, 127), fill="#000000")
        idx_str = f"{cam_idx + 1}/{len(cameras)}"
        pause_str = "||" if paused else ">"
        d.text((2, 117), f"{pause_str} {idx_str}", font=font, fill="#AAA")

        # Show URL snippet
        if cameras and cam_idx < len(cameras):
            url = cameras[cam_idx][1]
            d.text((50, 117), url[-12:], font=font, fill="#666")

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_no_cameras():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    d.text((4, 20), "CCTV VIEWER", font=font, fill="#00CCFF")
    d.text((4, 40), "No cameras loaded", font=font, fill="#FF4444")
    d.text((4, 56), "Run CCTV Scanner", font=font, fill="#888")
    d.text((4, 68), "or add URLs to:", font=font, fill="#888")
    d.text((4, 80), MANUAL_URLS_FILE[-20:], font=font, fill="#666")
    d.text((4, 100), "K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Screenshot
# ---------------------------------------------------------------------------
def _take_screenshot():
    frame = _get("frame")
    if frame is None:
        return None
    cameras = _get("cameras")
    cam_idx = _get("cam_idx")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = cameras[cam_idx][0] if cam_idx < len(cameras) else "cam"
    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "", name)
    path = os.path.join(SCREENSHOT_DIR, f"{safe_name}_{ts}.jpg")
    frame.save(path, "JPEG", quality=90)
    return path


def _show_msg(line1, line2=""):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    d.text((4, 50), line1[:21], font=font, fill="#00FF00")
    if line2:
        d.text((4, 65), line2[:21], font=font, fill="#888")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    d.text((4, 16), "CCTV VIEWER", font=font, fill="#00CCFF")
    d.text((4, 32), "MJPEG LCD streamer", font=font, fill="#888")
    d.text((4, 52), "L/R=Switch  OK=Pause", font=font, fill="#666")
    d.text((4, 64), "K1=Overlay K2=Snap", font=font, fill="#666")
    d.text((4, 76), "K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    cameras = _load_cameras()
    if not cameras:
        _draw_no_cameras()
        # Wait for exit
        try:
            while True:
                btn = get_button(PINS, GPIO)
                if btn == "KEY3":
                    break
                time.sleep(0.1)
        finally:
            try:
                LCD.LCD_Clear()
            except Exception:
                pass
            GPIO.cleanup()
        return 0

    # Start first stream
    _start_stream(cameras[0][1])
    last_press = 0.0

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if btn == "KEY3":
                _stop_stream()
                break

            elif btn == "OK":
                paused = _get("paused")
                _set(paused=not paused)

            elif btn == "LEFT":
                cameras = _get("cameras")
                idx = _get("cam_idx")
                new_idx = (idx - 1) % len(cameras)
                _set(cam_idx=new_idx)
                _stop_stream()
                _start_stream(cameras[new_idx][1])

            elif btn == "RIGHT":
                cameras = _get("cameras")
                idx = _get("cam_idx")
                new_idx = (idx + 1) % len(cameras)
                _set(cam_idx=new_idx)
                _stop_stream()
                _start_stream(cameras[new_idx][1])

            elif btn == "KEY1":
                overlay = _get("show_overlay")
                _set(show_overlay=not overlay)

            elif btn == "KEY2":
                path = _take_screenshot()
                if path:
                    _show_msg("Screenshot!", path[-18:])
                else:
                    _show_msg("No frame yet")

            _draw_lcd()
            time.sleep(0.03)

    finally:
        _stop_stream()
        time.sleep(0.2)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
