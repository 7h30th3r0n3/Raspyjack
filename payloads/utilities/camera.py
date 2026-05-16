#!/usr/bin/env python3
"""
RaspyJack Payload -- Camera
==============================
Author: 7h30th3r0n3

Photo and video capture with IMX219 camera.

Flow: Menu -> Photo/Video/Gallery/Settings
  Photo: live preview + OK to snap (instant from preview frame)
         KEY2 for hi-res capture (brief preview pause)
  Video: OK to start rec (preview stops), OK to stop (preview resumes)
  Gallery: browse + view photos, play videos
  Settings: resolution

Controls per state:
  Menu:     UP/DN navigate, OK enter, KEY3 exit
  Photo:    OK snap, KEY2 hi-res, KEY3 back to menu
  Video:    OK start/stop rec, KEY3 back to menu
  Gallery:  UP/DN navigate, OK view, KEY3 back to menu
  Settings: UP/DN navigate, OK change, KEY3 back to menu
"""

import os
import sys
import time
import signal
import subprocess
import threading
import mmap
import glob
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
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

LOOT_DIR = "/root/Raspyjack/loot/Camera"
PHOTO_DIR = os.path.join(LOOT_DIR, "Photos")
VIDEO_DIR = os.path.join(LOOT_DIR, "Videos")
FB_DEVICE = "/dev/fb1" if os.path.exists("/dev/fb1") else "/dev/fb0"
FB_SIZE = W * H * 2
DEBOUNCE = 0.20

RESOLUTIONS = [
    ("VGA", 640, 480),
    ("HD", 1280, 720),
    ("FHD", 1920, 1080),
    ("8MP", 3280, 2464),
]

_running = True
_recording = False
_previewing = False
_preview_proc = None
_last_frame = None
_frame_lock = threading.Lock()

C_BG = (5, 5, 10)
C_HEAD = (20, 20, 40)
C_WHITE = (255, 255, 255)
C_DIM = (80, 80, 80)
C_DARK = (12, 12, 20)
C_GREEN = (0, 220, 80)
C_RED = (255, 50, 50)
C_YELLOW = (255, 200, 0)
C_CYAN = (0, 180, 220)


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


def _check_camera():
    try:
        r = subprocess.run(
            ["rpicam-hello", "--list-cameras"],
            capture_output=True, text=True, timeout=5)
        return "imx219" in r.stdout.lower()
    except Exception:
        return False


def _show_msg(line1, line2="", color=C_CYAN):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
    if IS_WIDE:
        d.text((W // 2, H // 2 - 10), line1, font=font, fill=color,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (10, H // 2 - 15), line1, font=font, fill=color)
        if line2:
            d.text((W // 2, H // 2 + 10), line2, font=font_sm, fill=C_DIM,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (10, H // 2 + 5), line2, font=font_sm, fill=C_DIM)
    else:
        d.text((4, 50), line1[:17], font=font, fill=color)
        if line2:
            d.text((4, 68), line2[:17], font=font_sm, fill=C_DIM)
    LCD.LCD_ShowImage(img, 0, 0)


# ─── Preview ───

def _start_preview():
    global _preview_proc, _previewing
    if _previewing:
        return
    _previewing = True
    _preview_proc = subprocess.Popen(
        ["rpicam-vid", "--width", str(W), "--height", str(H),
         "--framerate", "15", "--codec", "yuv420",
         "--rotation", "180",
         "-t", "0", "--nopreview", "-o", "-"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    threading.Thread(target=_preview_thread, daemon=True).start()


def _preview_thread():
    global _previewing, _last_frame
    import numpy as np

    frame_size = W * H * 3 // 2
    fb_fd = None
    fb_map = None
    try:
        fb_fd = os.open(FB_DEVICE, os.O_RDWR)
        fb_map = mmap.mmap(fb_fd, FB_SIZE, mmap.MAP_SHARED,
                           mmap.PROT_WRITE | mmap.PROT_READ)
    except Exception:
        _previewing = False
        return

    try:
        while _previewing and _running and _preview_proc and _preview_proc.poll() is None:
            raw = b""
            while len(raw) < frame_size and _previewing:
                chunk = _preview_proc.stdout.read(frame_size - len(raw))
                if not chunk:
                    break
                raw += chunk
            if len(raw) < frame_size:
                break

            yuv = np.frombuffer(raw, dtype=np.uint8)
            y = yuv[:W * H].reshape(H, W).astype(np.int16)
            u_raw = yuv[W * H:W * H + W * H // 4].reshape(H // 2, W // 2)
            v_raw = yuv[W * H + W * H // 4:].reshape(H // 2, W // 2)
            u = np.repeat(np.repeat(u_raw, 2, axis=0), 2, axis=1).astype(np.int16) - 128
            v = np.repeat(np.repeat(v_raw, 2, axis=0), 2, axis=1).astype(np.int16) - 128

            r = np.clip(y + ((359 * v) >> 8), 0, 255).astype(np.uint8)
            g = np.clip(y - ((88 * u + 183 * v) >> 8), 0, 255).astype(np.uint8)
            b = np.clip(y + ((454 * u) >> 8), 0, 255).astype(np.uint8)

            rgb565 = ((r.astype(np.uint16) >> 3) << 11) | \
                     ((g.astype(np.uint16) >> 2) << 5) | \
                     (b.astype(np.uint16) >> 3)
            fb_map.seek(0)
            fb_map.write(rgb565.tobytes())

            with _frame_lock:
                _last_frame = np.stack([r, g, b], axis=-1)
    except Exception:
        pass
    finally:
        try:
            if fb_map:
                fb_map.close()
            if fb_fd is not None:
                os.close(fb_fd)
        except Exception:
            pass
        _previewing = False


def _stop_preview():
    global _preview_proc, _previewing
    _previewing = False
    if _preview_proc and _preview_proc.poll() is None:
        _preview_proc.kill()
        try:
            _preview_proc.wait(timeout=2)
        except Exception:
            pass
    _preview_proc = None
    time.sleep(0.3)


# ─── Capture ───

def _snap_photo():
    """Instant capture from preview frame (no interruption)."""
    os.makedirs(PHOTO_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(PHOTO_DIR, f"photo_{ts}.jpg")
    with _frame_lock:
        frame = _last_frame
    if frame is None:
        return None, 0
    try:
        Image.fromarray(frame, "RGB").save(path, "JPEG", quality=90)
        return path, os.path.getsize(path) // 1024
    except Exception:
        return None, 0


def _snap_hires(res_idx):
    """Hi-res capture via rpicam-still (pauses preview)."""
    os.makedirs(PHOTO_DIR, exist_ok=True)
    _, w, h = RESOLUTIONS[res_idx]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(PHOTO_DIR, f"hires_{ts}.jpg")
    _stop_preview()
    subprocess.run(
        ["rpicam-still", "-o", path, "--width", str(w), "--height", str(h),
         "-t", "500", "--nopreview", "-q", "90", "--rotation", "180"],
        capture_output=True, timeout=10)
    _start_preview()
    if os.path.isfile(path):
        return path, os.path.getsize(path) // 1024
    return None, 0


def _start_recording(res_idx):
    global _recording
    os.makedirs(VIDEO_DIR, exist_ok=True)
    _, w, h = RESOLUTIONS[min(res_idx, 2)]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(VIDEO_DIR, f"video_{ts}.h264")
    _recording = True
    subprocess.Popen(
        ["rpicam-vid", "-o", path, "--width", str(w), "--height", str(h),
         "--framerate", "30", "-t", "0", "--nopreview", "--rotation", "180",
         "--codec", "h264"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return path


def _stop_recording():
    global _recording
    subprocess.run(["pkill", "-INT", "rpicam-vid"], capture_output=True)
    time.sleep(0.5)
    _recording = False


# ─── File lists ───

def _list_photos():
    if not os.path.isdir(PHOTO_DIR):
        return []
    return sorted(glob.glob(os.path.join(PHOTO_DIR, "*.jpg")), reverse=True)


def _list_videos():
    if not os.path.isdir(VIDEO_DIR):
        return []
    return sorted(glob.glob(os.path.join(VIDEO_DIR, "*.h264")), reverse=True)


def _show_photo(path):
    try:
        img = Image.open(path).resize((W, H), Image.LANCZOS)
        LCD.LCD_ShowImage(img, 0, 0)
        return True
    except Exception:
        return False


def _play_video(path):
    """Play h264 video via ffmpeg to framebuffer."""
    try:
        fb = FB_DEVICE
        proc = subprocess.Popen(
            ["ffmpeg", "-hide_banner", "-loglevel", "quiet",
             "-i", path,
             "-vf", f"scale={W}:{H}",
             "-pix_fmt", "rgb565le", "-f", "rawvideo", "pipe:1"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        fb_fd = os.open(fb, os.O_RDWR)
        fb_map = mmap.mmap(fb_fd, FB_SIZE, mmap.MAP_SHARED,
                           mmap.PROT_WRITE | mmap.PROT_READ)
        while _running:
            raw = proc.stdout.read(FB_SIZE)
            if not raw or len(raw) < FB_SIZE:
                break
            fb_map.seek(0)
            fb_map.write(raw)
            btn = _get_btn()
            if btn == "KEY3" or btn == "OK":
                break
        proc.kill()
        fb_map.close()
        os.close(fb_fd)
    except Exception:
        pass


# ─── Draw screens ───

def _draw_menu(sel):
    items = [" Photo", " Video", " Gallery", " Settings"]
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    if IS_WIDE:
        d.rectangle([0, 0, W, 24], fill=C_HEAD)
        d.text((W // 2, 12), "CAMERA", font=font_lg, fill=C_CYAN,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 30, 3), "CAMERA", font=font_lg, fill=C_CYAN)
        y = 38
        for i, item in enumerate(items):
            ry = y + i * 28
            if i == sel:
                d.rectangle([30, ry, W - 30, ry + 26], fill=C_DARK)
            color = C_WHITE if i == sel else C_DIM
            d.text((W // 2, ry + 13), item, font=font, fill=color,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (50, ry + 5), item, font=font, fill=color)
        d.rectangle([0, H - 16, W, H], fill=C_DARK)
        d.text((W // 2, H - 8), "UP/DN:Select  OK:Enter  K3:Exit",
               font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (5, H - 13), "UP/DN OK K3:Exit", font=font_sm, fill=C_DIM)
    else:
        d.rectangle([0, 0, 128, 16], fill=C_HEAD)
        d.text((30, 1), "CAMERA", font=font_lg, fill=C_CYAN)
        y = 22
        for i, item in enumerate(items):
            ry = y + i * 22
            if i == sel:
                d.rectangle([4, ry, 124, ry + 20], fill=C_DARK)
            color = C_WHITE if i == sel else C_DIM
            d.text((4, ry + 3), item, font=font, fill=color)
        d.text((4, 112), "OK:Enter K3:Exit", font=font_sm, fill=C_DIM)

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_gallery(files, sel):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    if IS_WIDE:
        d.rectangle([0, 0, W, 20], fill=C_HEAD)
        d.text((W // 2, 10), f"GALLERY ({len(files)})", font=font_lg, fill=C_CYAN,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 40, 1), f"GALLERY ({len(files)})", font=font_lg, fill=C_CYAN)
        if not files:
            d.text((W // 2, H // 2), "No files yet", font=font, fill=C_DIM,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (W // 2 - 40, H // 2 - 7), "No files yet", font=font, fill=C_DIM)
        else:
            y = 24
            start = max(0, sel - 2)
            for i in range(5):
                idx = start + i
                if idx >= len(files):
                    break
                ry = y + i * 24
                is_sel = idx == sel
                if is_sel:
                    d.rectangle([4, ry, W - 4, ry + 22], fill=C_DARK)
                name = os.path.basename(files[idx])
                sz = os.path.getsize(files[idx]) // 1024
                ext = "IMG" if files[idx].endswith(".jpg") else "VID"
                color = C_WHITE if is_sel else C_DIM
                d.text((8, ry + 4), f"[{ext}] {name[:22]} ({sz}KB)", font=font_sm, fill=color)
        d.rectangle([0, H - 16, W, H], fill=C_DARK)
        d.text((W // 2, H - 8), "OK:View/Play  UP/DN:Nav  K3:Back",
               font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (2, H - 13), "OK:View UP/DN K3:Back", font=font_sm, fill=C_DIM)
    else:
        d.rectangle([0, 0, 128, 14], fill=C_HEAD)
        d.text((10, 1), f"GALLERY({len(files)})", font=font_lg, fill=C_CYAN)
        y = 18
        if not files:
            d.text((4, 50), "No files", font=font, fill=C_DIM)
        else:
            start = max(0, sel - 1)
            for i in range(4):
                idx = start + i
                if idx >= len(files):
                    break
                ry = y + i * 20
                is_sel = idx == sel
                name = os.path.basename(files[idx])[:14]
                color = C_WHITE if is_sel else C_DIM
                d.text((4, ry), name, font=font_sm, fill=color)
        d.text((4, 108), "OK:View K3:Back", font=font_sm, fill=C_DIM)

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_settings(res_idx, sel):
    items = [
        f"Resolution: {RESOLUTIONS[res_idx][0]}",
        f"Photos: {len(_list_photos())}",
        f"Videos: {len(_list_videos())}",
        "Back",
    ]
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    if IS_WIDE:
        d.rectangle([0, 0, W, 20], fill=C_HEAD)
        d.text((W // 2, 10), "SETTINGS", font=font_lg, fill=C_YELLOW,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 35, 1), "SETTINGS", font=font_lg, fill=C_YELLOW)
        y = 28
        for i, item in enumerate(items):
            ry = y + i * 26
            if i == sel:
                d.rectangle([4, ry, W - 4, ry + 24], fill=C_DARK)
            color = C_WHITE if i == sel else C_DIM
            d.text((10, ry + 5), item, font=font_sm, fill=color)
        d.rectangle([0, H - 16, W, H], fill=C_DARK)
        d.text((W // 2, H - 8), "OK:Change  UP/DN:Nav  K3:Back",
               font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (5, H - 13), "OK UP/DN K3:Back", font=font_sm, fill=C_DIM)
    else:
        d.rectangle([0, 0, 128, 14], fill=C_HEAD)
        d.text((20, 1), "SETTINGS", font=font_lg, fill=C_YELLOW)
        y = 18
        for i, item in enumerate(items):
            ry = y + i * 18
            color = C_WHITE if i == sel else C_DIM
            d.text((4, ry), item[:17], font=font_sm, fill=color)

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_rec_screen(rec_time, res_idx):
    """Screen shown during video recording (no preview)."""
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    if IS_WIDE:
        d.rectangle([0, 0, W, 24], fill=C_HEAD)
        blink = int(time.time() * 2) % 2
        if blink:
            d.ellipse([8, 5, 22, 19], fill=C_RED)
        d.text((30, 4), "RECORDING", font=font_lg, fill=C_RED)
        d.text((W // 2, 50), f"{int(rec_time)}s", font=font_lg, fill=C_WHITE,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 15, 42), f"{int(rec_time)}s", font=font_lg, fill=C_WHITE)
        res_name = RESOLUTIONS[min(res_idx, 2)][0]
        d.text((W // 2, 80), f"{res_name} 30fps", font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 30, 75), f"{res_name} 30fps", font=font_sm, fill=C_DIM)
        d.rectangle([0, H - 16, W, H], fill=C_DARK)
        d.text((W // 2, H - 8), "OK:Stop Recording",
               font=font_sm, fill=C_RED,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 50, H - 13), "OK:Stop Recording", font=font_sm, fill=C_RED)
    else:
        d.rectangle([0, 0, 128, 14], fill=C_HEAD)
        blink = int(time.time() * 2) % 2
        if blink:
            d.ellipse([4, 3, 12, 11], fill=C_RED)
        d.text((16, 1), "REC", font=font_lg, fill=C_RED)
        d.text((4, 50), f"{int(rec_time)}s", font=font_lg, fill=C_WHITE)
        d.text((4, 108), "OK:Stop", font=font_sm, fill=C_RED)

    LCD.LCD_ShowImage(img, 0, 0)


# ─── Main ───

def main():
    global _running, _recording

    if not _check_camera():
        _show_msg("No camera!", "Check connection")
        time.sleep(3)
        GPIO.cleanup()
        return 1

    os.makedirs(PHOTO_DIR, exist_ok=True)
    os.makedirs(VIDEO_DIR, exist_ok=True)

    state = "menu"
    menu_sel = 0
    gallery_sel = 0
    settings_sel = 0
    res_idx = 3
    last_btn = 0
    rec_start = 0

    while _running:
        btn = _get_btn()
        now = time.time()

        # ── Menu ──
        if state == "menu":
            if btn == "KEY3":
                break
            if btn == "UP" and now - last_btn > DEBOUNCE:
                last_btn = now
                menu_sel = (menu_sel - 1) % 4
            if btn == "DOWN" and now - last_btn > DEBOUNCE:
                last_btn = now
                menu_sel = (menu_sel + 1) % 4
            if btn == "OK" and now - last_btn > DEBOUNCE:
                last_btn = now
                if menu_sel == 0:
                    state = "photo"
                    _start_preview()
                elif menu_sel == 1:
                    state = "video"
                    _start_preview()
                elif menu_sel == 2:
                    state = "gallery"
                    gallery_sel = 0
                elif menu_sel == 3:
                    state = "settings"
                    settings_sel = 0
                continue
            _draw_menu(menu_sel)

        # ── Photo (preview running) ──
        elif state == "photo":
            if btn == "KEY3":
                _stop_preview()
                state = "menu"
                continue
            if btn == "OK" and now - last_btn > 0.5:
                last_btn = now
                path, size = _snap_photo()
                if path:
                    _show_msg(f"Photo saved! {size}KB", os.path.basename(path), C_GREEN)
                    time.sleep(2)
                    _start_preview()
                else:
                    _show_msg("Capture failed!", "No frame available", C_RED)
                    time.sleep(2)
            if btn == "KEY2" and now - last_btn > 0.5:
                last_btn = now
                _show_msg("Hi-res capture...", RESOLUTIONS[res_idx][0], C_YELLOW)
                path, size = _snap_hires(res_idx)
                if path:
                    _show_msg(f"HiRes saved! {size}KB", os.path.basename(path), C_GREEN)
                    time.sleep(2)
                else:
                    _show_msg("Capture failed!", "", C_RED)
                    time.sleep(2)

        # ── Video ──
        elif state == "video":
            if btn == "KEY3" and not _recording:
                _stop_preview()
                state = "menu"
                continue
            if btn == "OK" and now - last_btn > DEBOUNCE:
                last_btn = now
                if not _recording:
                    _stop_preview()
                    _start_recording(res_idx)
                    rec_start = now
                else:
                    _stop_recording()
                    _show_msg("Video saved!", "", C_GREEN)
                    time.sleep(1)
                    _start_preview()
            if _recording:
                _draw_rec_screen(now - rec_start, res_idx)

        # ── Gallery ──
        elif state == "gallery":
            files = _list_photos() + _list_videos()
            if btn == "KEY3":
                state = "menu"
                continue
            if btn == "UP" and now - last_btn > DEBOUNCE and files:
                last_btn = now
                gallery_sel = (gallery_sel - 1) % len(files)
            if btn == "DOWN" and now - last_btn > DEBOUNCE and files:
                last_btn = now
                gallery_sel = (gallery_sel + 1) % len(files)
            if btn == "OK" and now - last_btn > DEBOUNCE and files:
                last_btn = now
                f = files[gallery_sel]
                if f.endswith(".jpg"):
                    photos = [p for p in files if p.endswith(".jpg")]
                    photo_idx = photos.index(f) if f in photos else 0
                    _show_photo(photos[photo_idx])
                    while _running:
                        b = _get_btn()
                        if b == "KEY3":
                            break
                        if b == "LEFT" and photo_idx > 0:
                            photo_idx -= 1
                            _show_photo(photos[photo_idx])
                            time.sleep(0.2)
                        if b == "RIGHT" and photo_idx < len(photos) - 1:
                            photo_idx += 1
                            _show_photo(photos[photo_idx])
                            time.sleep(0.2)
                        if b == "KEY2":
                            _show_msg("Delete?", "OK:Yes  KEY3:No", C_RED)
                            while _running:
                                c = _get_btn()
                                if c == "OK":
                                    os.remove(photos[photo_idx])
                                    photos.pop(photo_idx)
                                    if not photos:
                                        break
                                    photo_idx = min(photo_idx, len(photos) - 1)
                                    _show_photo(photos[photo_idx])
                                    break
                                if c == "KEY3":
                                    _show_photo(photos[photo_idx])
                                    break
                                time.sleep(0.08)
                            if not photos:
                                break
                            time.sleep(0.3)
                        time.sleep(0.08)
                elif f.endswith(".h264"):
                    _play_video(f)
            if btn == "KEY2" and now - last_btn > 0.4 and files:
                last_btn = now
                _show_msg("Delete?", "OK:Yes  KEY3:No", C_RED)
                while _running:
                    c = _get_btn()
                    if c == "OK":
                        os.remove(files[gallery_sel])
                        files = _list_photos() + _list_videos()
                        if gallery_sel >= len(files):
                            gallery_sel = max(0, len(files) - 1)
                        break
                    if c == "KEY3":
                        break
                    time.sleep(0.08)
            _draw_gallery(files, gallery_sel)

        # ── Settings ──
        elif state == "settings":
            if btn == "KEY3":
                state = "menu"
                continue
            if btn == "UP" and now - last_btn > DEBOUNCE:
                last_btn = now
                settings_sel = (settings_sel - 1) % 4
            if btn == "DOWN" and now - last_btn > DEBOUNCE:
                last_btn = now
                settings_sel = (settings_sel + 1) % 4
            if btn == "OK" and now - last_btn > DEBOUNCE:
                last_btn = now
                if settings_sel == 0:
                    res_idx = (res_idx + 1) % len(RESOLUTIONS)
                elif settings_sel == 3:
                    state = "menu"
                    continue
            _draw_settings(res_idx, settings_sel)

        time.sleep(0.08)

    _stop_preview()
    if _recording:
        _stop_recording()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
