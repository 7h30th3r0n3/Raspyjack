#!/usr/bin/env python3
"""
RaspyJack Payload -- RTSP Live Viewer
======================================
Author: 7h30th3r0n3

Streams RTSP (H.264/H.265) video feeds to the LCD using OpenCV.

Loads cameras from:
  ``/root/Raspyjack/loot/CCTV/cctv_live.txt``        (scanner output)
  ``/root/Raspyjack/config/rtsp_viewer/manual_urls.txt``  (manual)

URL format: ``Name | rtsp://...`` or ``Name | rtsp://... | user:pass``

Requires:
  ``pip install opencv-python-headless``

Settings menu (shown before streaming)
---------------------------------------
  UP / DOWN     -- Navigate menu items
  LEFT / RIGHT  -- Change value
  OK            -- Start streaming with current settings
  KEY3          -- Start with defaults

Menu options:
  Transport     -- RTSP transport protocol
                   TCP (reliable) | UDP (fast) | AUTO
  Cam Res       -- Request resolution via URL substream
                   Default | Main | Sub
  Resize Filter -- Local downscale algorithm to LCD
                   LANCZOS (sharp) | BILINEAR (fast) | NEAREST (turbo)
  Enhance       -- Local post-processing on each frame
                   Off | AutoContrast | Sharpen | Both
  Frame Skip    -- Decode every Nth frame (for slow HW)
                   1 (all) | 2 | 3 | 5

Stream controls
---------------
  LEFT / RIGHT  -- Previous / next camera
  UP            -- Cycle zoom (1x -> 2x -> 4x -> 1x)
  DOWN          -- Grid 2x2 (press again to exit)
  OK            -- Back to settings menu (re-apply and resume)
  KEY1          -- Cycle overlay: full -> minimal -> off
  KEY2          -- Screenshot (long-press = toggle recording)
  KEY3          -- Exit
"""

import os
import sys
import time
import re
import threading
from datetime import datetime
from collections import deque

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont, ImageFilter, ImageOps
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

_cv2_error = None
try:
    import cv2
except Exception as _e:
    cv2 = None
    _cv2_error = str(_e)

# -- GPIO / LCD ----------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
font = scaled_font()

# -- Paths ---------------------------------------------------------------------
LIVE_FILE = "/root/Raspyjack/loot/CCTV/cctv_live.txt"
CONFIG_DIR = "/root/Raspyjack/config/rtsp_viewer"
SCREENSHOT_DIR = "/root/Raspyjack/loot/CCTV/screenshots"
RECORDING_DIR = "/root/Raspyjack/loot/CCTV/recordings"
MANUAL_URLS_FILE = os.path.join(CONFIG_DIR, "manual_urls.txt")
for d in (CONFIG_DIR, SCREENSHOT_DIR, RECORDING_DIR):
    os.makedirs(d, exist_ok=True)

DEBOUNCE = 0.20
RECONNECT_DELAYS = (1, 2, 4, 8, 15)
ZOOM_LEVELS = (1, 2, 4, 8)
OVERLAY_MODES = ("full", "minimal", "off")
LCD_REFRESH = 0.025
LONG_PRESS = 0.6
STABLE_STREAM_SECS = 10.0

# -- RTSP transport map --------------------------------------------------------
RTSP_TRANSPORT = {
    "TCP": cv2.CAP_PROP_OPEN_TIMEOUT_MSEC if cv2 else 0,
    "UDP": 0,
    "AUTO": 0,
}

# =============================================================================
# Settings menu definitions
# =============================================================================
RESIZE_FILTERS = {
    "LANCZOS": Image.LANCZOS,
    "BILINEAR": Image.BILINEAR,
    "NEAREST": Image.NEAREST,
}

MENU_ITEMS = [
    (
        "transport",
        "Transport",
        [
            ("TCP", "tcp"),
            ("UDP", "udp"),
            ("AUTO", "auto"),
        ],
        0,
    ),
    (
        "cam_substream",
        "Cam Res",
        [
            ("Default", None),
            ("Main (HD)", "main"),
            ("Sub (low)", "sub"),
        ],
        0,
    ),
    (
        "resize_filter",
        "Resize Algo",
        [
            ("LANCZOS", "LANCZOS"),
            ("BILINEAR", "BILINEAR"),
            ("NEAREST", "NEAREST"),
        ],
        0,
    ),
    (
        "enhance",
        "Enhance",
        [
            ("Off", "off"),
            ("AutoContrast", "autocontrast"),
            ("Sharpen", "sharpen"),
            ("Both", "both"),
        ],
        0,
    ),
    (
        "frame_skip",
        "Frame Skip",
        [
            ("1 (all)", 1),
            ("2", 2),
            ("3", 3),
            ("5", 5),
        ],
        0,
    ),
]

_settings = {
    "transport": "tcp",
    "cam_substream": None,
    "resize_filter": "LANCZOS",
    "enhance": "off",
    "frame_skip": 1,
}


# =============================================================================
# Settings menu UI
# =============================================================================
_last_settings_choices = None

def _run_settings_menu():
    global _last_settings_choices
    if _last_settings_choices is not None and len(_last_settings_choices) == len(MENU_ITEMS):
        choices = list(_last_settings_choices)
    else:
        choices = [item[3] for item in MENU_ITEMS]
    cursor = 0
    last_press = 0.0

    while True:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)

        d.rectangle((0, 0, 127, 12), fill="#003366")
        d.text((2, 1), "RTSP SETTINGS", font=font, fill="#00CCFF")
        d.text((90, 1), "OK=Go", font=font, fill="#888")

        visible_count = 5
        scroll_offset = max(0, cursor - visible_count + 1)
        y_start = 16

        for i in range(scroll_offset, min(scroll_offset + visible_count, len(MENU_ITEMS))):
            key, label, options, _ = MENU_ITEMS[i]
            chosen_idx = choices[i]
            chosen_name = options[chosen_idx][0]
            y = y_start + (i - scroll_offset) * 20
            is_selected = (i == cursor)

            if is_selected:
                d.rectangle((0, y, 127, y + 18), fill="#1a1a2e")
                d.rectangle((0, y, 2, y + 18), fill="#00CCFF")

            label_color = "#FFFFFF" if is_selected else "#888888"
            d.text((5, y + 1), label[:12], font=font, fill=label_color)

            val_color = "#00FF00" if is_selected else "#666666"
            if is_selected:
                d.text((62, y + 1), "<", font=font, fill="#00CCFF")
            d.text((70, y + 1), chosen_name[:8], font=font, fill=val_color)
            if is_selected:
                d.text((120, y + 1), ">", font=font, fill="#00CCFF")

        d.rectangle((0, 117, 127, 127), fill="#000000")
        d.text((2, 118), "U/D=Nav L/R=Set", font=font, fill="#555")
        LCD.LCD_ShowImage(img, 0, 0)

        btn = get_button(PINS, GPIO)
        now = time.time()
        if btn and (now - last_press) < DEBOUNCE:
            btn = None
        if btn:
            last_press = now

        if btn == "UP":
            cursor = (cursor - 1) % len(MENU_ITEMS)
        elif btn == "DOWN":
            cursor = (cursor + 1) % len(MENU_ITEMS)
        elif btn == "LEFT":
            _, _, options, _ = MENU_ITEMS[cursor]
            choices[cursor] = (choices[cursor] - 1) % len(options)
        elif btn == "RIGHT":
            _, _, options, _ = MENU_ITEMS[cursor]
            choices[cursor] = (choices[cursor] + 1) % len(options)
        elif btn == "OK":
            _last_settings_choices = list(choices)
            result = {}
            for i, (key, _, options, _) in enumerate(MENU_ITEMS):
                result[key] = options[choices[i]][1]
            return result
        elif btn == "KEY3":
            _last_settings_choices = list(choices)
            result = {}
            for i, (key, _, options, _) in enumerate(MENU_ITEMS):
                result[key] = options[choices[i]][1]
            return result

        time.sleep(0.03)


# =============================================================================
# State
# =============================================================================
_lock = threading.Lock()
_frame_slot = deque(maxlen=1)

_state = {
    "cameras": [],
    "cam_idx": 0,
    "overlay_mode": 0,
    "zoom": 0,
    "pan_x": 0.5,
    "pan_y": 0.5,
    "fps": 0.0,
    "status": "Loading...",
    "streaming": False,
    "stop": False,
    "grid_mode": False,
    "recording": False,
    "rec_writer": None,
    "reconnects": 0,
    "switching": False,
    "last_frame": None,
    "stream_gen": 0,
}

_grid_lock = threading.Lock()


def _get(key):
    with _lock:
        val = _state[key]
        return list(val) if isinstance(val, list) else val


def _set(**kw):
    with _lock:
        for k, v in kw.items():
            _state[k] = v


def _get_frame():
    try:
        return _frame_slot[-1]
    except IndexError:
        return None


def _push_frame(img, gen=None):
    if gen is not None and gen != _get("stream_gen"):
        return
    _frame_slot.append(img)


# =============================================================================
# Camera list loading (filter RTSP URLs only)
# =============================================================================
def _load_cameras():
    cameras = []
    for path in (LIVE_FILE, MANUAL_URLS_FILE):
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 2:
                        name, url = parts[0], parts[1]
                        auth = parts[2] if len(parts) >= 3 else None
                    else:
                        name = f"Cam{len(cameras) + 1}"
                        url = parts[0]
                        auth = None
                    # Accept only rtsp:// URLs
                    if url and url.lower().startswith("rtsp://"):
                        cameras.append((name, url, auth))
        except Exception:
            pass

    _set(cameras=cameras)
    if not cameras:
        _set(status="No RTSP cameras")
    return cameras


def _parse_auth(url, auth_field):
    if auth_field and ":" in auth_field:
        user, passwd = auth_field.split(":", 1)
        # Inject user:pass into rtsp:// URL
        if "@" not in url:
            url = url.replace("rtsp://", f"rtsp://{user}:{passwd}@", 1)
        return url
    m = re.match(r"(rtsp://)([^@]+)@(.+)", url)
    if m:
        return url  # already has auth
    return url


def _apply_substream(url):
    """Modify URL for main/sub stream based on settings.

    Common patterns:
      Hikvision: /Streaming/Channels/101 (sub) vs /Channels/1 (main)
      Dahua:     /cam/realmonitor?subtype=1 (sub) vs subtype=0 (main)
    """
    sub = _settings.get("cam_substream")
    if sub is None:
        return url

    lower = url.lower()

    if sub == "sub":
        # Try to switch to substream
        if "/streaming/channels/" in lower:
            url = re.sub(r"(/Streaming/Channels/\d)(\d{2})?",
                         r"\g<1>01", url, flags=re.IGNORECASE)
        elif "subtype=" in lower:
            url = re.sub(r"subtype=\d", "subtype=1", url, flags=re.IGNORECASE)
        elif "?" in url:
            url += "&subtype=1"
        else:
            url += "?subtype=1"
    elif sub == "main":
        if "/streaming/channels/" in lower:
            url = re.sub(r"(/Streaming/Channels/\d)(\d{2})?",
                         r"\g<1>", url, flags=re.IGNORECASE)
        elif "subtype=" in lower:
            url = re.sub(r"subtype=\d", "subtype=0", url, flags=re.IGNORECASE)
        elif "?" in url:
            url += "&subtype=0"
        else:
            url += "?subtype=0"

    return url


# =============================================================================
# Image processing (shared with MJPEG viewer)
# =============================================================================
def _get_resize_filter():
    return RESIZE_FILTERS.get(_settings["resize_filter"], Image.LANCZOS)


def _apply_enhance(img):
    mode = _settings["enhance"]
    if mode == "off":
        return img
    if mode in ("autocontrast", "both"):
        img = ImageOps.autocontrast(img, cutoff=1)
    if mode in ("sharpen", "both"):
        img = img.filter(ImageFilter.SHARPEN)
    return img


def _resize_with_zoom(img, zoom_level):
    resample = _get_resize_filter()
    if zoom_level <= 1:
        result = img.resize((WIDTH, HEIGHT), resample)
    else:
        w, h = img.size
        crop_w, crop_h = w // zoom_level, h // zoom_level
        pan_x, pan_y = _get("pan_x"), _get("pan_y")
        left = int((w - crop_w) * pan_x)
        top = int((h - crop_h) * pan_y)
        left = max(0, min(left, w - crop_w))
        top = max(0, min(top, h - crop_h))
        cropped = img.crop((left, top, left + crop_w, top + crop_h))
        result = cropped.resize((WIDTH, HEIGHT), resample)
    return _apply_enhance(result)


def _cv2_frame_to_pil(frame):
    """Convert OpenCV BGR numpy array to PIL RGB Image."""
    rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    return Image.fromarray(rgb)


# =============================================================================
# RTSP stream reader (OpenCV VideoCapture)
# =============================================================================
def _build_capture(url):
    """Create an OpenCV VideoCapture with RTSP transport settings."""
    transport = _settings.get("transport", "tcp")

    if transport == "tcp":
        os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = "rtsp_transport;tcp"
    elif transport == "udp":
        os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = "rtsp_transport;udp"
    else:
        os.environ.pop("OPENCV_FFMPEG_CAPTURE_OPTIONS", None)

    cap = cv2.VideoCapture(url, cv2.CAP_FFMPEG)
    # Reduce internal buffer to 1 frame for lowest latency
    cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
    return cap


def _stream_rtsp(url, gen):
    """Read frames from RTSP stream via OpenCV."""
    if gen != _get("stream_gen"):
        _set(streaming=False)
        return

    _set(status="Connecting...")

    cap = _build_capture(url)
    if not cap.isOpened():
        _set(streaming=False, status="RTSP open failed")
        return

    _set(status="Streaming...")
    frame_count = 0
    raw_frame_idx = 0
    fps_start = time.time()
    stream_start = time.time()
    reconnects_reset = False
    skip = _settings["frame_skip"]

    try:
        while not _get("stop") and gen == _get("stream_gen"):
            ret, frame = cap.read()
            if not ret:
                _set(status="Stream lost")
                break

            raw_frame_idx += 1
            if skip > 1 and (raw_frame_idx % skip) != 0:
                continue

            # Only reset reconnect counter after stable stream
            if not reconnects_reset and (time.time() - stream_start) >= STABLE_STREAM_SECS:
                _set(reconnects=0)
                reconnects_reset = True

            # Recording
            rec_writer = _get("rec_writer")
            if rec_writer is not None:
                try:
                    rec_writer.write(frame)
                except Exception:
                    pass

            try:
                pil_img = _cv2_frame_to_pil(frame)
                zoom = ZOOM_LEVELS[_get("zoom")]
                pil_img = _resize_with_zoom(pil_img, zoom)
                _push_frame(pil_img, gen)
                frame_count += 1

                elapsed = time.time() - fps_start
                if elapsed >= 1.0:
                    _set(fps=round(frame_count / elapsed, 1))
                    frame_count = 0
                    fps_start = time.time()
            except Exception:
                pass

    except Exception as exc:
        _set(status=f"Err: {str(exc)[:16]}")
    finally:
        cap.release()
        _set(streaming=False)


# =============================================================================
# Stream lifecycle
# =============================================================================
def _start_stream(url):
    new_gen = _get("stream_gen") + 1
    _set(stop=False, streaming=True, fps=0.0, last_frame=None,
         switching=False, stream_gen=new_gen)
    _frame_slot.clear()

    def _worker():
        _stream_rtsp(url, new_gen)

    threading.Thread(target=_worker, daemon=True).start()


def _stop_stream():
    _set(stop=True, switching=True)
    if _get("recording"):
        _toggle_recording()
    for _ in range(30):
        if not _get("streaming"):
            break
        time.sleep(0.05)


def _auto_reconnect():
    cameras = _get("cameras")
    idx = _get("cam_idx")
    if not cameras or _get("stop") or _get("switching"):
        return

    reconnects = _get("reconnects")
    delay_idx = min(reconnects, len(RECONNECT_DELAYS) - 1)
    delay = RECONNECT_DELAYS[delay_idx]
    _set(status=f"Reconnect {delay}s...", reconnects=reconnects + 1)

    for _ in range(delay * 10):
        if _get("stop") or _get("switching"):
            return
        time.sleep(0.1)

    if _get("stop") or _get("switching"):
        return

    cam = cameras[idx]
    url = _parse_auth(cam[1], cam[2] if len(cam) > 2 else None)
    url = _apply_substream(url)
    _start_stream(url)


# =============================================================================
# Grid view (2x2)
# =============================================================================
_grid_frames = {}
_grid_threads = {}


def _start_grid(cameras):
    _grid_frames.clear()
    start = _get("cam_idx")
    count = min(4, len(cameras))
    for i in range(count):
        idx = (start + i) % len(cameras)
        cam = cameras[idx]
        url = _parse_auth(cam[1], cam[2] if len(cam) > 2 else None)
        url = _apply_substream(url)
        t = threading.Thread(
            target=_grid_stream_worker, args=(idx, url), daemon=True
        )
        _grid_threads[idx] = t
        t.start()


def _grid_stream_worker(idx, url):
    if cv2 is None:
        return
    cap = _build_capture(url)
    if not cap.isOpened():
        return

    cell_size = WIDTH // 2
    resample = _get_resize_filter()

    try:
        while not _get("stop") and _get("grid_mode"):
            ret, frame = cap.read()
            if not ret:
                break
            try:
                pil_img = _cv2_frame_to_pil(frame)
                pil_img = pil_img.resize((cell_size, cell_size), resample)
                pil_img = _apply_enhance(pil_img)
                with _grid_lock:
                    _grid_frames[idx] = pil_img
            except Exception:
                pass
    except Exception:
        pass
    finally:
        cap.release()


def _stop_grid():
    _set(grid_mode=False)
    for t in list(_grid_threads.values()):
        t.join(timeout=2.0)
    with _grid_lock:
        _grid_frames.clear()
    _grid_threads.clear()


def _draw_grid():
    cameras = _get("cameras")
    start = _get("cam_idx")
    count = min(4, len(cameras))
    canvas = Image.new("RGB", (WIDTH, HEIGHT), "black")
    cell = WIDTH // 2
    positions = [(0, 0), (cell, 0), (0, cell), (cell, cell)]
    d = ImageDraw.Draw(canvas)

    for i in range(count):
        idx = (start + i) % len(cameras)
        px, py = positions[i]
        with _grid_lock:
            frame = _grid_frames.get(idx)
        if frame is not None:
            canvas.paste(frame, (px, py))
        else:
            d.rectangle((px, py, px + cell - 1, py + cell - 1), outline="#333")
            d.text((px + 2, py + cell // 2), "...", font=font, fill="#666")
        name = cameras[idx][0][:7]
        d.text((px + 1, py + 1), name, font=font, fill="#0F0")

    d.text((2, HEIGHT - 11), "GRID  DOWN=back", font=font, fill="#888")
    LCD.LCD_ShowImage(canvas, 0, 0)


# =============================================================================
# LCD rendering
# =============================================================================
def _draw_lcd():
    frame = _get_frame()
    overlay_idx = _get("overlay_mode")
    overlay = OVERLAY_MODES[overlay_idx]
    cameras = _get("cameras")
    cam_idx = _get("cam_idx")
    fps = _get("fps")
    status = _get("status")
    zoom_idx = _get("zoom")
    recording = _get("recording")

    if frame is not None:
        img = frame.copy()
        _set(last_frame=frame)
    elif _get("last_frame") is not None:
        img = _get("last_frame").copy()
    else:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((10, 55), status[:20], font=font, fill="#888")
        LCD.LCD_ShowImage(img, 0, 0)
        return

    if overlay != "off" and cameras:
        d = ScaledDraw(img)
        name = cameras[cam_idx][0] if cam_idx < len(cameras) else "?"

        d.rectangle((0, 0, 127, 12), fill="#000000")
        d.text((2, 1), name[:14], font=font, fill="#00FF00")
        d.text((90, 1), f"{fps}fps", font=font, fill="#FFFF00")

        if recording:
            d.ellipse((82, 2, 88, 8), fill="#FF0000")
        if zoom_idx > 0:
            d.text((70, 1), f"{ZOOM_LEVELS[zoom_idx]}x", font=font, fill="#FF8800")

        if overlay == "full":
            d.rectangle((0, 116, 127, 127), fill="#000000")
            idx_str = f"{cam_idx + 1}/{len(cameras)}"
            d.text((2, 117), f"> {idx_str}", font=font, fill="#AAA")
            if cam_idx < len(cameras):
                url = cameras[cam_idx][1]
                d.text((50, 117), url[-12:], font=font, fill="#666")

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_no_cameras():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 16), "RTSP VIEWER", font=font, fill="#00CCFF")
    d.text((4, 36), "No RTSP cameras", font=font, fill="#FF4444")
    d.text((4, 52), "Run CCTV Scanner", font=font, fill="#888")
    d.text((4, 64), "or add URLs to:", font=font, fill="#888")
    d.text((4, 76), MANUAL_URLS_FILE[-22:], font=font, fill="#666")
    d.text((4, 96), "Format:", font=font, fill="#666")
    d.text((4, 108), "Name|rtsp://...", font=font, fill="#555")
    LCD.LCD_ShowImage(img, 0, 0)


# =============================================================================
# Screenshot / recording
# =============================================================================
def _take_screenshot():
    frame = _get_frame()
    if frame is None:
        frame = _get("last_frame")
    if frame is None:
        return None
    cameras = _get("cameras")
    cam_idx = _get("cam_idx")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = cameras[cam_idx][0] if cam_idx < len(cameras) else "cam"
    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "", name)
    path = os.path.join(SCREENSHOT_DIR, f"{safe_name}_{ts}.jpg")
    frame.save(path, "JPEG", quality=95)
    return path


def _toggle_recording():
    """Toggle AVI recording via OpenCV VideoWriter."""
    recording = _get("recording")
    if recording:
        rec_writer = _get("rec_writer")
        if rec_writer is not None:
            try:
                rec_writer.release()
            except Exception:
                pass
        _set(recording=False, rec_writer=None)
        return False
    else:
        cameras = _get("cameras")
        cam_idx = _get("cam_idx")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = cameras[cam_idx][0] if cam_idx < len(cameras) else "cam"
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "", name)
        path = os.path.join(RECORDING_DIR, f"{safe_name}_{ts}.avi")
        try:
            fourcc = cv2.VideoWriter_fourcc(*"MJPG")
            writer = cv2.VideoWriter(path, fourcc, 15.0, (WIDTH, HEIGHT))
            _set(recording=True, rec_writer=writer)
            return True
        except Exception:
            return False


def _show_msg(line1, line2=""):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), line1[:21], font=font, fill="#00FF00")
    if line2:
        d.text((4, 65), line2[:21], font=font, fill="#888")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.8)


# =============================================================================
# Main
# =============================================================================
def main():
    # Check OpenCV
    if cv2 is None:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 12), "RTSP VIEWER", font=font, fill="#FF4444")
        d.text((4, 28), "OpenCV missing!", font=font, fill="#FF8800")
        err_msg = _cv2_error or "not installed"
        # Show error on multiple lines (18 chars per line)
        for i, start in enumerate(range(0, len(err_msg), 18)):
            if i > 2:
                break
            d.text((4, 44 + i * 12), err_msg[start:start + 18], font=font, fill="#AA6600")
        d.text((4, 88), "pip install", font=font, fill="#888")
        d.text((4, 100), "opencv-python-", font=font, fill="#888")
        d.text((4, 112), "headless   K3=Exit", font=font, fill="#666")
        LCD.LCD_ShowImage(img, 0, 0)
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
        return 1

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 8), "RTSP VIEWER", font=font, fill="#00CCFF")
    d.text((4, 24), "OpenCV:", font=font, fill="#888")
    d.text((55, 24), cv2.__version__, font=font, fill="#00FF00")
    d.text((4, 44), "L/R=Cam  UP=Zoom", font=font, fill="#666")
    d.text((4, 56), "OK=Menu  K1=Overlay", font=font, fill="#666")
    d.text((4, 68), "DOWN=Grid K2=Snap", font=font, fill="#666")
    d.text((4, 84), "Press OK for menu", font=font, fill="#00FF00")
    d.text((4, 96), "K3 = skip (defaults)", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)

    while True:
        btn = get_button(PINS, GPIO)
        if btn == "OK":
            chosen = _run_settings_menu()
            _settings.update(chosen)
            break
        elif btn == "KEY3":
            break
        time.sleep(0.05)

    # Config summary
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 4), "Config:", font=font, fill="#00CCFF")
    d.text((4, 18), f"Transport: {_settings['transport']}", font=font, fill="#AAA")
    sub_label = _settings["cam_substream"] or "Default"
    d.text((4, 30), f"Stream: {sub_label}", font=font, fill="#AAA")
    d.text((4, 42), f"Filter: {_settings['resize_filter']}", font=font, fill="#AAA")
    d.text((4, 54), f"Enhance: {_settings['enhance']}", font=font, fill="#AAA")
    d.text((4, 66), f"Skip: {_settings['frame_skip']}", font=font, fill="#AAA")
    d.text((4, 84), "Loading cameras...", font=font, fill="#888")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.8)

    cameras = _load_cameras()
    if not cameras:
        _draw_no_cameras()
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

    # Start first camera
    cam = cameras[0]
    url = _parse_auth(cam[1], cam[2] if len(cam) > 2 else None)
    url = _apply_substream(url)
    _start_stream(url)

    last_press = 0.0
    key2_down_time = 0.0
    reconnect_thread = None

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()

            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            # KEY2 long-press -> recording
            if key2_down_time > 0 and GPIO.input(PINS["KEY2"]) == 0:
                if (now - key2_down_time) >= LONG_PRESS:
                    key2_down_time = 0.0
                    is_rec = _toggle_recording()
                    _show_msg("REC ON" if is_rec else "REC OFF")
                    continue
            elif key2_down_time > 0:
                key2_down_time = 0.0

            if btn == "KEY2":
                key2_down_time = now

            # -- Grid mode --
            if _get("grid_mode"):
                if btn == "DOWN":
                    _stop_grid()
                    cameras = _get("cameras")
                    idx = _get("cam_idx")
                    cam = cameras[idx]
                    url = _parse_auth(cam[1], cam[2] if len(cam) > 2 else None)
                    url = _apply_substream(url)
                    _start_stream(url)

                elif btn == "LEFT":
                    cameras = _get("cameras")
                    idx = (_get("cam_idx") - 4) % len(cameras)
                    _set(cam_idx=idx)
                    _stop_grid()
                    _set(grid_mode=True, stop=False)
                    _start_grid(cameras)

                elif btn == "RIGHT":
                    cameras = _get("cameras")
                    idx = (_get("cam_idx") + 4) % len(cameras)
                    _set(cam_idx=idx)
                    _stop_grid()
                    _set(grid_mode=True, stop=False)
                    _start_grid(cameras)

                elif btn == "KEY3":
                    _stop_grid()
                    break

                _draw_grid()
                time.sleep(LCD_REFRESH)
                continue

            # -- Single camera --
            if btn == "KEY3":
                _stop_stream()
                break

            elif btn == "OK":
                _stop_stream()
                chosen = _run_settings_menu()
                _settings.update(chosen)
                cameras = _get("cameras")
                idx = _get("cam_idx")
                cam = cameras[idx]
                url = _parse_auth(cam[1], cam[2] if len(cam) > 2 else None)
                url = _apply_substream(url)
                _start_stream(url)

            elif btn == "LEFT":
                if _get("zoom") > 0:
                    _set(pan_x=max(0.0, _get("pan_x") - 0.15))
                else:
                    cameras = _get("cameras")
                    idx = _get("cam_idx")
                    new_idx = (idx - 1) % len(cameras)
                    _set(cam_idx=new_idx, zoom=0, pan_x=0.5, pan_y=0.5)
                    _stop_stream()
                    cam = cameras[new_idx]
                    url = _parse_auth(cam[1], cam[2] if len(cam) > 2 else None)
                    url = _apply_substream(url)
                    _start_stream(url)

            elif btn == "RIGHT":
                if _get("zoom") > 0:
                    _set(pan_x=min(1.0, _get("pan_x") + 0.15))
                else:
                    cameras = _get("cameras")
                    idx = _get("cam_idx")
                    new_idx = (idx + 1) % len(cameras)
                    _set(cam_idx=new_idx, zoom=0, pan_x=0.5, pan_y=0.5)
                    _stop_stream()
                    cam = cameras[new_idx]
                    url = _parse_auth(cam[1], cam[2] if len(cam) > 2 else None)
                    url = _apply_substream(url)
                    _start_stream(url)

            elif btn == "UP":
                if _get("zoom") > 0:
                    _set(pan_y=max(0.0, _get("pan_y") - 0.15))
                else:
                    _set(zoom=1, pan_x=0.5, pan_y=0.5)

            elif btn == "DOWN":
                if _get("zoom") > 0:
                    _set(pan_y=min(1.0, _get("pan_y") + 0.15))
                else:
                    _stop_stream()
                    _set(grid_mode=True, stop=False)
                    _start_grid(_get("cameras"))

            elif btn == "KEY1":
                if _get("zoom") > 0:
                    z = (_get("zoom") + 1) % len(ZOOM_LEVELS)
                    _set(zoom=z, pan_x=0.5, pan_y=0.5)
                else:
                    o = (_get("overlay_mode") + 1) % len(OVERLAY_MODES)
                    _set(overlay_mode=o)

            elif btn == "KEY2":
                path = _take_screenshot()
                if path:
                    _show_msg("Screenshot!", path[-18:])
                else:
                    _show_msg("No frame yet")

            # Auto-reconnect
            if (
                not _get("streaming")
                and not _get("stop")
                and not _get("switching")
                and _get("cameras")
                and (reconnect_thread is None or not reconnect_thread.is_alive())
            ):
                reconnect_thread = threading.Thread(
                    target=_auto_reconnect, daemon=True
                )
                reconnect_thread.start()

            _draw_lcd()
            time.sleep(LCD_REFRESH)

    finally:
        _stop_stream()
        if _get("recording"):
            _toggle_recording()
        time.sleep(0.2)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
