#!/usr/bin/env python3
"""
RaspyJack Payload -- CCTV Live Viewer
=========================================
Author: 7h30th3r0n3

Streams MJPEG video feeds to the LCD.  Loads camera URLs from
``/root/Raspyjack/loot/CCTV/cctv_live.txt`` (format: ``Name | URL``).
Also accepts manual URL input via config file.

Reads the HTTP multipart/x-mixed-replace stream, extracts JPEG frames,
resizes them to LCD, and displays on the LCD in real time.
------------------------
- **TurboJPEG** accelerated decoding (3-5x faster, PIL fallback)
- **32 KB chunk reads** (8x larger than V1) for fewer syscalls
- **Double-buffered frames** -- stream thread writes, LCD reads, no stalls
- **Intelligent frame dropping** -- always display the *latest* frame
- **Auto-reconnect** with exponential back-off on stream loss
- **HTTP Basic Auth** support (``user:pass@host`` in URL)
- **Grid view** (2×2) to monitor up to 4 cameras simultaneously
- **Digital zoom** -- crop center then upscale for more detail
- **Recording mode** -- save raw MJPEG to loot for later review
- **Adaptive render rate** -- LCD refresh decoupled from stream FPS

Loads cameras from:
  ``/root/Raspyjack/loot/CCTV/cctv_live.txt``        (scanner output)
  ``/root/Raspyjack/config/cctv_viewer/manual_urls.txt``  (manual)

URL format: ``Name | URL`` or ``Name | URL | user:pass``

Settings menu (shown before streaming)
---------------------------------------
  UP / DOWN     -- Navigate menu items
  LEFT / RIGHT  -- Change value
  OK            -- Start streaming with current settings
  KEY3          -- Start with defaults

Menu options:
  Cam Res       -- Request resolution from camera (URL param)
                   Default | 1920x1080 | 1280x960 | 640x480 | 320x240
  Compression   -- Request compression level from camera (URL param)
                   Default | 0 (none) | 20 | 50 | 70 | 90 (max)
  Resize Filter -- Local downscale algorithm to LCD
                   LANCZOS (sharp) | BILINEAR (fast) | NEAREST (turbo)
  Enhance       -- Local post-processing on each frame
                   Off | AutoContrast | Sharpen | Both
  Frame Skip    -- Decode every Nth frame (for slow HW)
                   1 (all) | 2 | 3 | 5

Stream controls
---------------
  LEFT / RIGHT  -- Previous / next camera
  UP            -- Cycle zoom (1x → 2x → 4x → 1x)
  DOWN          -- Grid 2×2 (press again to exit)
  OK            -- Back to settings menu (re-apply and resume)
  KEY1          -- Cycle overlay: full → minimal → off
  KEY2          -- Screenshot (long-press = toggle recording)
  KEY3          -- Exit
"""


import os
import sys
import time
import re
import threading
from io import BytesIO
from datetime import datetime
from collections import deque

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont, ImageEnhance, ImageFilter, ImageOps
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

# -- TurboJPEG (optional, ~3-5x faster decode) --------------------------------
try:
    from turbojpeg import TurboJPEG, TJPF_RGB
    _tj = TurboJPEG()
except Exception:
    _tj = None

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
CONFIG_DIR = "/root/Raspyjack/config/cctv_viewer"
SCREENSHOT_DIR = "/root/Raspyjack/loot/CCTV/screenshots"
RECORDING_DIR = "/root/Raspyjack/loot/CCTV/recordings"
MANUAL_URLS_FILE = os.path.join(CONFIG_DIR, "manual_urls.txt")
for d in (CONFIG_DIR, SCREENSHOT_DIR, RECORDING_DIR):
    os.makedirs(d, exist_ok=True)

DEBOUNCE = 0.20
CHUNK_SIZE = 32768          # 32 KB -- 8x V1
MAX_BUF = 512000            # ~500 KB safety cap
RECONNECT_DELAYS = (1, 2, 4, 8, 15)  # exponential back-off seconds
ZOOM_LEVELS = (1, 2, 4, 8)
OVERLAY_MODES = ("full", "minimal", "off")
LCD_REFRESH = 0.025         # ~40 Hz target refresh
LONG_PRESS = 0.6            # seconds for long-press detection

# Suppress urllib3 InsecureRequestWarning (CCTV cameras rarely have valid certs)
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass
VERIFY_SSL = False

# =============================================================================
# Settings menu definitions
# =============================================================================
# Each setting: (key, label, [(display_name, value), ...], default_index)
RESIZE_FILTERS = {
    "LANCZOS": Image.LANCZOS,
    "BILINEAR": Image.BILINEAR,
    "NEAREST": Image.NEAREST,
}

MENU_ITEMS = [
    (
        "cam_resolution",
        "Cam Res",
        [
            ("Default", None),           # don't touch URL
            ("1920x1080", "1920x1080"),
            ("1280x960", "1280x960"),
            ("1280x720", "1280x720"),
            ("640x480", "640x480"),
            ("320x240", "320x240"),
        ],
        0,
    ),
    (
        "cam_compression",
        "Compression",
        [
            ("Default", None),           # don't touch URL
            ("0 (none)", 0),
            ("20 (low)", 20),
            ("50 (med)", 50),
            ("70 (high)", 70),
            ("90 (max)", 90),
        ],
        0,
    ),
    (
        "resize_filter",
        "Resize Algo",
        [
            ("LANCZOS", "LANCZOS"),      # sharpest, slowest
            ("BILINEAR", "BILINEAR"),    # good balance
            ("NEAREST", "NEAREST"),      # fastest, pixelated
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

# Runtime settings populated by menu (defaults)
_settings = {
    "cam_resolution": None,
    "cam_compression": None,
    "resize_filter": "LANCZOS",
    "enhance": "off",
    "frame_skip": 1,
}


# =============================================================================
# Settings menu UI
# =============================================================================
_last_settings_choices = None  # persists menu selections between calls

def _run_settings_menu():
    """Interactive settings menu on LCD. Returns dict of chosen settings."""
    global _last_settings_choices
    # Restore previous selections or use defaults
    if _last_settings_choices is not None and len(_last_settings_choices) == len(MENU_ITEMS):
        choices = list(_last_settings_choices)
    else:
        choices = [item[3] for item in MENU_ITEMS]
    cursor = 0  # which menu item is highlighted
    last_press = 0.0

    while True:
        # -- Draw menu --
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)

        # Title bar
        d.rectangle((0, 0, 127, 12), fill="#003366")
        d.text((2, 1), "SETTINGS", font=font, fill="#00CCFF")
        d.text((70, 1), "OK=Start", font=font, fill="#888")

        # Menu items (show up to 5 items, scrollable)
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
                # Highlight bar
                d.rectangle((0, y, 127, y + 18), fill="#1a1a2e")
                d.rectangle((0, y, 2, y + 18), fill="#00CCFF")

            # Label
            label_color = "#FFFFFF" if is_selected else "#888888"
            d.text((5, y + 1), label[:12], font=font, fill=label_color)

            # Value with arrows
            val_color = "#00FF00" if is_selected else "#666666"
            arrow_color = "#00CCFF" if is_selected else "#333333"

            # Left arrow
            if is_selected:
                d.text((62, y + 1), "<", font=font, fill=arrow_color)

            # Value (truncated)
            val_text = chosen_name[:8]
            d.text((70, y + 1), val_text, font=font, fill=val_color)

            # Right arrow
            if is_selected:
                d.text((120, y + 1), ">", font=font, fill=arrow_color)

        # Footer
        d.rectangle((0, 117, 127, 127), fill="#000000")
        d.text((2, 118), "U/D=Nav L/R=Set", font=font, fill="#555")

        LCD.LCD_ShowImage(img, 0, 0)

        # -- Handle input --
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
            # Confirm and return settings
            _last_settings_choices = list(choices)
            result = {}
            for i, (key, _, options, _) in enumerate(MENU_ITEMS):
                result[key] = options[choices[i]][1]
            return result

        elif btn == "KEY3":
            # Keep current selections
            _last_settings_choices = list(choices)
            result = {}
            for i, (key, _, options, _) in enumerate(MENU_ITEMS):
                result[key] = options[choices[i]][1]
            return result

        time.sleep(0.03)

# =============================================================================
# State (double-buffered frame via deque(maxlen=1))
# =============================================================================
_lock = threading.Lock()
_frame_slot = deque(maxlen=1)  # latest decoded frame, non-blocking swap

_state = {
    "cameras": [],          # list of (name, url, auth|None)
    "cam_idx": 0,
    "paused": False,
    "overlay_mode": 0,      # index into OVERLAY_MODES
    "zoom": 0,              # index into ZOOM_LEVELS
    "pan_x": 0.5,           # pan offset 0.0-1.0 (0.5 = center)
    "pan_y": 0.5,           # pan offset 0.0-1.0 (0.5 = center)
    "fps": 0.0,
    "status": "Loading...",
    "streaming": False,
    "stop": False,
    "grid_mode": False,
    "recording": False,
    "rec_file": None,
    "reconnects": 0,
    "switching": False,     # True during camera switch to block auto-reconnect
    "last_frame": None,     # cached last displayed frame (replaces _last_frame_cache)
    "stream_gen": 0,        # incremented on each _start_stream; old threads auto-stop
}

_grid_lock = threading.Lock()  # protects _grid_frames dict


def _get(key):
    with _lock:
        val = _state[key]
        return list(val) if isinstance(val, list) else val


def _set(**kw):
    with _lock:
        for k, v in kw.items():
            _state[k] = v


def _get_frame():
    """Pop latest frame (non-blocking). Returns PIL Image or None."""
    try:
        return _frame_slot[-1]
    except IndexError:
        return None


def _push_frame(img, gen=None):
    """Push a decoded frame if gen matches current stream generation."""
    if gen is not None and gen != _get("stream_gen"):
        return  # stale thread, discard
    _frame_slot.append(img)


# =============================================================================
# Camera list loading
# =============================================================================
def _load_cameras():
    cameras = []
    for path in (LIVE_FILE, MANUAL_URLS_FILE):
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r") as f:
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
                    if url:
                        cameras.append((name, url, auth))
        except Exception:
            pass

    _set(cameras=cameras)
    if not cameras:
        _set(status="No cameras found")
    return cameras


def _parse_auth(url, auth_field):
    """Return (clean_url, (user, pass) | None)."""
    if auth_field and ":" in auth_field:
        user, passwd = auth_field.split(":", 1)
        return url, (user, passwd)
    # Check user:pass@host in URL
    m = re.match(r"(https?://)([^:]+):([^@]+)@(.+)", url)
    if m:
        clean = m.group(1) + m.group(4)
        return clean, (m.group(2), m.group(3))
    return url, None


def _apply_cam_params(url):
    """Append resolution/compression query params to camera URL.

    Works with most MJPEG cameras (Axis, Hikvision, Dahua, generic).
    Adds ``resolution=WxH`` and ``compression=N`` (or ``quality=N``)
    as query parameters.  The camera ignores params it doesn't support.
    """
    params = []
    res = _settings.get("cam_resolution")
    if res is not None:
        params.append(f"resolution={res}")
    comp = _settings.get("cam_compression")
    if comp is not None:
        params.append(f"compression={comp}")
        # Some cameras use 'quality' instead (inverted: quality = 100-compression)
        params.append(f"quality={100 - comp}")
    if not params:
        return url
    sep = "&" if "?" in url else "?"
    return url + sep + "&".join(params)


# =============================================================================
# JPEG decoding (TurboJPEG → PIL fallback)
# =============================================================================
def _decode_jpeg(data):
    """Decode JPEG bytes to PIL RGB Image. Uses TurboJPEG if available."""
    if _tj is not None:
        try:
            rgb = _tj.decode(data, pixel_format=TJPF_RGB)
            return Image.fromarray(rgb)
        except Exception:
            pass
    return Image.open(BytesIO(data)).convert("RGB")


def _get_resize_filter():
    """Return the PIL resampling filter from settings."""
    return RESIZE_FILTERS.get(_settings["resize_filter"], Image.LANCZOS)


def _apply_enhance(img):
    """Apply post-processing enhancement based on settings."""
    mode = _settings["enhance"]
    if mode == "off":
        return img
    if mode in ("autocontrast", "both"):
        img = ImageOps.autocontrast(img, cutoff=1)
    if mode in ("sharpen", "both"):
        img = img.filter(ImageFilter.SHARPEN)
    return img


def _resize_with_zoom(img, zoom_level):
    """Resize image to LCD, applying digital zoom + pan + settings filter + enhance."""
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


# =============================================================================
# MJPEG stream reader (V2: larger chunks, TurboJPEG, reconnect, recording)
# =============================================================================
def _stream_mjpeg(url, auth=None, gen=None):
    try:
        import requests
    except ImportError:
        _set(status="requests missing")
        return

    # If our generation is already stale, bail out immediately
    if gen is not None and gen != _get("stream_gen"):
        _set(streaming=False)
        return

    _set(status="Connecting...")

    session = requests.Session()
    if auth:
        session.auth = auth

    try:
        resp = session.get(url, stream=True, timeout=10, verify=VERIFY_SSL)
        resp.raise_for_status()
    except Exception as exc:
        _set(streaming=False, status=f"Err: {str(exc)[:16]}")
        return

    _set(status="Streaming...")
    buf = bytearray()
    frame_count = 0
    raw_frame_idx = 0
    fps_start = time.time()
    stream_start = time.time()
    reconnects_reset = False
    skip = _settings["frame_skip"]

    try:
        for chunk in resp.iter_content(chunk_size=CHUNK_SIZE):
            if _get("stop") or (gen is not None and gen != _get("stream_gen")):
                break
            if _get("paused"):
                time.sleep(0.05)
                continue

            # Only reset reconnect counter after stream is stable (10s)
            if not reconnects_reset and (time.time() - stream_start) >= 10.0:
                _set(reconnects=0)
                reconnects_reset = True

            buf.extend(chunk)

            # Recording: write raw bytes
            rec_file = _get("rec_file")
            if rec_file is not None:
                try:
                    rec_file.write(chunk)
                except Exception:
                    pass

            while True:
                jpg_start = buf.find(b"\xff\xd8")
                if jpg_start < 0:
                    break
                jpg_end = buf.find(b"\xff\xd9", jpg_start + 2)
                if jpg_end < 0:
                    break

                jpg_end += 2
                jpg_data = bytes(buf[jpg_start:jpg_end])
                del buf[:jpg_end]

                raw_frame_idx += 1
                if skip > 1 and (raw_frame_idx % skip) != 0:
                    continue

                try:
                    img = _decode_jpeg(jpg_data)
                    zoom = ZOOM_LEVELS[_get("zoom")]
                    img = _resize_with_zoom(img, zoom)
                    _push_frame(img, gen)
                    frame_count += 1

                    elapsed = time.time() - fps_start
                    if elapsed >= 1.0:
                        _set(fps=round(frame_count / elapsed, 1))
                        frame_count = 0
                        fps_start = time.time()
                except Exception:
                    pass

            if len(buf) > MAX_BUF:
                last_soi = buf.rfind(b"\xff\xd8")
                if last_soi > 0:
                    del buf[:last_soi]
                else:
                    del buf[:len(buf) - 65536]

    except Exception as exc:
        _set(status=f"Stream err: {str(exc)[:14]}")
    finally:
        try:
            resp.close()
        except Exception:
            pass
        session.close()
        _set(streaming=False)


def _stream_single_jpeg(url, auth=None, gen=None):
    """Fallback: repeatedly fetch single JPEG snapshots."""
    try:
        import requests
    except ImportError:
        _set(status="requests missing")
        return

    if gen is not None and gen != _get("stream_gen"):
        _set(streaming=False)
        return

    _set(status="Snapshot mode...")
    session = requests.Session()
    if auth:
        session.auth = auth

    frame_count = 0
    fps_start = time.time()

    try:
        while not _get("stop"):
            if gen is not None and gen != _get("stream_gen"):
                break
            if _get("paused"):
                time.sleep(0.1)
                continue
            try:
                resp = session.get(url, timeout=5, verify=VERIFY_SSL)
                if resp.status_code == 200:
                    img = _decode_jpeg(resp.content)
                    zoom = ZOOM_LEVELS[_get("zoom")]
                    img = _resize_with_zoom(img, zoom)
                    _push_frame(img, gen)
                    frame_count += 1
                    elapsed = time.time() - fps_start
                    if elapsed >= 1.0:
                        _set(fps=round(frame_count / elapsed, 1))
                        frame_count = 0
                        fps_start = time.time()
            except Exception:
                pass
            time.sleep(0.15)
    finally:
        session.close()
        _set(streaming=False)


# =============================================================================
# Stream lifecycle (start / stop / reconnect)
# =============================================================================
def _start_stream(url, auth=None):
    new_gen = _get("stream_gen") + 1
    _set(stop=False, streaming=True, fps=0.0, last_frame=None,
         switching=False, stream_gen=new_gen)
    _frame_slot.clear()
    url = _apply_cam_params(url)

    def _worker():
        gen = new_gen  # capture for this thread
        # Detect stream type
        content_type = ""
        try:
            import requests
            s = requests.Session()
            if auth:
                s.auth = auth
            r = s.head(url, timeout=5, verify=VERIFY_SSL, allow_redirects=True)
            content_type = r.headers.get("Content-Type", "").lower()
            s.close()
        except Exception:
            pass

        if "multipart" in content_type or "mjpeg" in url.lower():
            _stream_mjpeg(url, auth, gen)
        elif "image" in content_type or url.lower().endswith(
            (".jpg", ".jpeg", ".png", ".bmp")
        ):
            _stream_single_jpeg(url, auth, gen)
        else:
            _stream_mjpeg(url, auth, gen)

    threading.Thread(target=_worker, daemon=True).start()


def _stop_stream():
    _set(stop=True, switching=True)
    # Close recording file if active to prevent handle leak
    if _get("recording"):
        _toggle_recording()
    for _ in range(30):
        if not _get("streaming"):
            break
        time.sleep(0.05)


def _auto_reconnect():
    """Called when stream drops -- reconnect with exponential back-off."""
    cameras = _get("cameras")
    idx = _get("cam_idx")
    if not cameras or _get("stop") or _get("switching"):
        return

    reconnects = _get("reconnects")
    delay_idx = min(reconnects, len(RECONNECT_DELAYS) - 1)
    delay = RECONNECT_DELAYS[delay_idx]
    _set(status=f"Reconnect {delay}s...", reconnects=reconnects + 1)

    # Interruptible sleep (check stop every 100ms)
    for _ in range(delay * 10):
        if _get("stop") or _get("switching"):
            return
        time.sleep(0.1)

    if _get("stop") or _get("switching"):
        return

    cam = cameras[idx]
    url, auth = _parse_auth(cam[1], cam[2] if len(cam) > 2 else None)
    _start_stream(url, auth)


# =============================================================================
# Grid view (2×2 mosaic)
# =============================================================================
_grid_frames = {}  # cam_idx -> latest PIL Image
_grid_threads = {}


def _start_grid(cameras):
    """Start up to 4 streams for grid view."""
    _grid_frames.clear()
    start = _get("cam_idx")
    count = min(4, len(cameras))

    for i in range(count):
        idx = (start + i) % len(cameras)
        cam = cameras[idx]
        url, auth = _parse_auth(cam[1], cam[2] if len(cam) > 2 else None)
        url = _apply_cam_params(url)
        t = threading.Thread(
            target=_grid_stream_worker, args=(idx, url, auth), daemon=True
        )
        _grid_threads[idx] = t
        t.start()


def _grid_stream_worker(idx, url, auth):
    """Lightweight MJPEG reader for one grid cell."""
    try:
        import requests
    except ImportError:
        return

    session = requests.Session()
    if auth:
        session.auth = auth

    try:
        resp = session.get(url, stream=True, timeout=10, verify=VERIFY_SSL)
        resp.raise_for_status()
    except Exception:
        return

    buf = bytearray()
    cell_size = WIDTH // 2  # 64x64

    try:
        for chunk in resp.iter_content(chunk_size=CHUNK_SIZE):
            if _get("stop") or not _get("grid_mode"):
                break
            buf.extend(chunk)
            while True:
                js = buf.find(b"\xff\xd8")
                if js < 0:
                    break
                je = buf.find(b"\xff\xd9", js + 2)
                if je < 0:
                    break
                je += 2
                jpg = bytes(buf[js:je])
                del buf[:je]
                try:
                    img = _decode_jpeg(jpg)
                    resample = _get_resize_filter()
                    img = img.resize((cell_size, cell_size), resample)
                    img = _apply_enhance(img)
                    with _grid_lock:
                        _grid_frames[idx] = img
                except Exception:
                    pass
            if len(buf) > MAX_BUF:
                last_soi = buf.rfind(b"\xff\xd8")
                if last_soi > 0:
                    del buf[:last_soi]
                else:
                    del buf[:len(buf) - 65536]
    except Exception:
        pass
    finally:
        try:
            resp.close()
        except Exception:
            pass
        session.close()


def _stop_grid():
    _set(grid_mode=False)
    # Wait for worker threads to finish before clearing state
    for t in list(_grid_threads.values()):
        t.join(timeout=1.5)
    with _grid_lock:
        _grid_frames.clear()
    _grid_threads.clear()


def _draw_grid():
    """Compose a 2×2 grid image from up to 4 camera feeds."""
    cameras = _get("cameras")
    start = _get("cam_idx")
    count = min(4, len(cameras))
    canvas = Image.new("RGB", (WIDTH, HEIGHT), "black")
    cell = WIDTH // 2  # 64

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
        # Camera label
        name = cameras[idx][0][:7]
        d.text((px + 1, py + 1), name, font=font, fill="#0F0")

    d.text((2, HEIGHT - 11), "GRID  DOWN=back", font=font, fill="#888")
    LCD.LCD_ShowImage(canvas, 0, 0)


# =============================================================================
# LCD rendering (single camera)
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

        # Top bar
        d.rectangle((0, 0, 127, 12), fill="#000000")
        d.text((2, 1), name[:14], font=font, fill="#00FF00")
        d.text((90, 1), f"{fps}fps", font=font, fill="#FFFF00")

        if recording:
            d.ellipse((82, 2, 88, 8), fill="#FF0000")

        if zoom_idx > 0:
            d.text((70, 1), f"{ZOOM_LEVELS[zoom_idx]}x", font=font, fill="#FF8800")

        if overlay == "full":
            # Bottom bar
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
    d.text((4, 16), "CCTV VIEWER V2", font=font, fill="#00CCFF")
    d.text((4, 36), "No cameras loaded", font=font, fill="#FF4444")
    d.text((4, 52), "Run CCTV Scanner", font=font, fill="#888")
    d.text((4, 64), "or add URLs to:", font=font, fill="#888")
    d.text((4, 76), MANUAL_URLS_FILE[-22:], font=font, fill="#666")
    d.text((4, 96), "Format:", font=font, fill="#666")
    d.text((4, 108), "Name|URL|user:pass", font=font, fill="#555")
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
    recording = _get("recording")
    if recording:
        # Stop recording
        rec_file = _get("rec_file")
        if rec_file is not None:
            try:
                rec_file.close()
            except Exception:
                pass
        _set(recording=False, rec_file=None)
        return False
    else:
        # Start recording
        cameras = _get("cameras")
        cam_idx = _get("cam_idx")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = cameras[cam_idx][0] if cam_idx < len(cameras) else "cam"
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "", name)
        path = os.path.join(RECORDING_DIR, f"{safe_name}_{ts}.mjpeg")
        try:
            rec_file = open(path, "wb")
            _set(recording=True, rec_file=rec_file)
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
    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 8), "CCTV VIEWER V2", font=font, fill="#00CCFF")
    d.text((4, 24), "TurboJPEG:", font=font, fill="#888")
    tj_status = "YES" if _tj else "no (PIL)"
    tj_color = "#00FF00" if _tj else "#FF8800"
    d.text((75, 24), tj_status, font=font, fill=tj_color)
    d.text((4, 44), "L/R=Cam  U/D=Zoom", font=font, fill="#666")
    d.text((4, 56), "OK=Menu  K1=Overlay", font=font, fill="#666")
    d.text((4, 68), "K2=Snap  K3=Exit", font=font, fill="#666")
    d.text((4, 84), "Press OK for menu", font=font, fill="#00FF00")
    d.text((4, 96), "K3 = skip (defaults)", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)

    # Wait for user choice: OK = settings menu, KEY3 = skip with defaults
    while True:
        btn = get_button(PINS, GPIO)
        if btn == "OK":
            chosen = _run_settings_menu()
            _settings.update(chosen)
            break
        elif btn == "KEY3":
            break  # keep defaults
        time.sleep(0.05)

    # Show chosen settings briefly
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 4), "Config:", font=font, fill="#00CCFF")
    res_label = _settings["cam_resolution"] or "Default"
    comp_label = str(_settings["cam_compression"]) if _settings["cam_compression"] is not None else "Default"
    d.text((4, 18), f"Cam Res: {res_label}", font=font, fill="#AAA")
    d.text((4, 30), f"Compress: {comp_label}", font=font, fill="#AAA")
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
    url, auth = _parse_auth(cam[1], cam[2] if len(cam) > 2 else None)
    _start_stream(url, auth)

    last_press = 0.0
    key2_down_time = 0.0
    reconnect_thread = None

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()

            # Debounce
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            # KEY2 long-press → toggle recording
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

            # -- Grid mode handling --------------------------------------------
            if _get("grid_mode"):
                if btn == "DOWN":
                    _stop_grid()
                    # Restart single stream
                    cameras = _get("cameras")
                    idx = _get("cam_idx")
                    cam = cameras[idx]
                    url, auth = _parse_auth(
                        cam[1], cam[2] if len(cam) > 2 else None
                    )
                    _start_stream(url, auth)

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

                _draw_grid()
                time.sleep(LCD_REFRESH)
                continue

            # -- Single camera controls ----------------------------------------
            if btn == "KEY3":
                # Short press = exit
                _stop_stream()
                break

            elif btn == "OK":
                # Return to settings menu
                _stop_stream()
                chosen = _run_settings_menu()
                _settings.update(chosen)
                # Resume stream with new settings
                cameras = _get("cameras")
                idx = _get("cam_idx")
                cam = cameras[idx]
                url, auth = _parse_auth(
                    cam[1], cam[2] if len(cam) > 2 else None
                )
                _start_stream(url, auth)

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
                    url, auth = _parse_auth(
                        cam[1], cam[2] if len(cam) > 2 else None
                    )
                    _start_stream(url, auth)

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
                    url, auth = _parse_auth(
                        cam[1], cam[2] if len(cam) > 2 else None
                    )
                    _start_stream(url, auth)

            elif btn == "UP":
                if _get("zoom") > 0:
                    _set(pan_y=max(0.0, _get("pan_y") - 0.15))
                else:
                    # Enter zoom 2x
                    _set(zoom=1, pan_x=0.5, pan_y=0.5)

            elif btn == "DOWN":
                if _get("zoom") > 0:
                    _set(pan_y=min(1.0, _get("pan_y") + 0.15))
                else:
                    # Enter grid 2x2
                    _stop_stream()
                    _set(grid_mode=True, stop=False)
                    _start_grid(_get("cameras"))

            elif btn == "KEY1":
                if _get("zoom") > 0:
                    # Cycle zoom level or back to 1x
                    z = (_get("zoom") + 1) % len(ZOOM_LEVELS)
                    _set(zoom=z, pan_x=0.5, pan_y=0.5)
                else:
                    # Cycle overlay
                    o = (_get("overlay_mode") + 1) % len(OVERLAY_MODES)
                    _set(overlay_mode=o)

            elif btn == "KEY2":
                path = _take_screenshot()
                if path:
                    _show_msg("Screenshot!", path[-18:])
                else:
                    _show_msg("No frame yet")

            # -- Auto-reconnect on stream drop ---------------------------------
            if (
                not _get("streaming")
                and not _get("stop")
                and not _get("switching")
                and not _get("paused")
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
        # Stop recording if active
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
