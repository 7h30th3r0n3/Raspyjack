#!/usr/bin/env python3
"""
RaspyJack Payload -- Video Player
===================================
Author: 7h30th3r0n3

Single-process video player: ffmpeg handles audio+video decode & sync.
Video frames → pipe → fb0 mmap. Audio → ALSA directly from ffmpeg.
"""

import os
import sys
import time
import signal
import subprocess
import mmap

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font, S
import struct
import numpy as np
from payloads._input_helper import get_button

try:
    import cv2
    CV2_OK = True
except ImportError:
    CV2_OK = False

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for p in PINS.values():
    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
font = scaled_font(11)
font_sm = scaled_font(9)

VIDEO_EXTENSIONS = {".mp4", ".avi", ".mkv", ".mov", ".webm", ".flv", ".m4v"}
START_DIR = "/root/Raspyjack/loot"
DEBOUNCE = 0.18
FB_DEVICE = "/dev/fb1" if os.path.exists("/dev/fb1") else "/dev/fb0"
FB_SIZE = WIDTH * HEIGHT * 2

_running = True
def _get_card():
    try:
        r = subprocess.run(["aplay", "-l"], capture_output=True, text=True, timeout=3)
        for line in r.stdout.split("\n"):
            if "ES8388" in line or "ES8389" in line:
                return line.split(":")[0].replace("card", "").strip()
    except Exception:
        pass
    return "0"

_volume = 40
_loop = False


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _check_button():
    for name, pin in PINS.items():
        if GPIO.input(pin) == 0:
            return name
    return None


def _tpa_enable():
    try:
        import smbus2
        bus = smbus2.SMBus(1)
        bus.write_byte_data(0x60, 0x01, 0xC0, force=True)
        bus.close()
    except Exception:
        pass

def _set_volume(vol):
    global _volume
    _volume = max(0, min(100, vol))
    dac_val = int(75 + (_volume * 180 / 100))
    hp_val = int(19 + (_volume * 44 / 100))
    card = _get_card()
    subprocess.Popen(["amixer", "-c", card, "sset", "Headphone", str(hp_val)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.Popen(["amixer", "-c", card, "sset", "DACL", str(dac_val)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.Popen(["amixer", "-c", card, "sset", "DACR", str(dac_val)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _tpa_enable()


def _format_time(seconds):
    if not seconds or seconds < 0:
        seconds = 0
    h, m, s = int(seconds) // 3600, (int(seconds) % 3600) // 60, int(seconds) % 60
    return f"{h}:{m:02d}:{s:02d}" if h > 0 else f"{m:02d}:{s:02d}"


def _human_size(size):
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.0f}{unit}"
        size /= 1024
    return f"{size:.0f}TB"


def _list_dir(path):
    items = []
    try:
        entries = sorted(os.listdir(path))
    except PermissionError:
        return items
    dirs, files = [], []
    for e in entries:
        if e.startswith("."):
            continue
        full = os.path.join(path, e)
        if os.path.isdir(full):
            dirs.append({"name": e + "/", "path": full, "is_dir": True})
        elif os.path.splitext(e)[1].lower() in VIDEO_EXTENSIONS:
            files.append({"name": e, "path": full, "is_dir": False, "size": os.path.getsize(full)})
    return dirs + files


def _draw_browser(items, cursor, scroll, current_dir):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 12), fill=(15, 25, 40))
    dirname = os.path.basename(current_dir) or current_dir
    d.text((2, 1), f"VIDEO  {dirname[:12]}", font=font_sm, fill=(0, 200, 255))
    if not items:
        d.text((4, 40), "No videos found", font=font, fill=(100, 100, 100))
        d.text((4, 55), "Copy .mp4 to:", font=font_sm, fill=(80, 80, 80))
        d.text((4, 67), START_DIR, font=font_sm, fill=(0, 150, 100))
    else:
        visible = 7
        for i in range(min(visible, len(items) - scroll)):
            idx = scroll + i
            item = items[idx]
            y = 15 + i * 13
            is_sel = idx == cursor
            if is_sel:
                d.rectangle((0, y - 1, 127, y + 11), fill=(0, 40, 60))
                d.rectangle((0, y - 1, 2, y + 11), fill=(0, 200, 255))
            name = os.path.splitext(item["name"])[0] if not item["is_dir"] else item["name"]
            col = ((255, 180, 0) if is_sel else (180, 120, 0)) if item["is_dir"] else ((255, 255, 255) if is_sel else (0, 180, 0))
            d.text((5, y), name[:18], font=font_sm, fill=col)
            if not item["is_dir"]:
                d.text((105, y), _human_size(item.get("size", 0)), font=font_sm, fill=(80, 80, 80))
    d.rectangle((0, 117, 127, 127), fill=(10, 15, 20))
    d.text((2, 118), "OK:Play L:Back K1:Info", font=font_sm, fill=(50, 70, 90))
    LCD.LCD_ShowImage(img, 0, 0)
    _set_volume(_volume)


def _show_info_screen(filepath):
    if not CV2_OK:
        return
    try:
        cap = cv2.VideoCapture(filepath)
        w, h = int(cap.get(3)), int(cap.get(4))
        fps = cap.get(5) or 0
        dur = int(cap.get(7)) / fps if fps > 0 else 0
        cap.release()
    except Exception:
        return
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 12), fill=(15, 25, 40))
    d.text((2, 1), "FILE INFO", font=font_sm, fill=(0, 200, 255))
    d.text((4, 18), os.path.basename(filepath)[:22], font=font_sm, fill=(255, 255, 255))
    y = 34
    for t in [f"Res: {w}x{h}", f"FPS: {fps:.1f}", f"Dur: {_format_time(dur)}", f"Size: {_human_size(os.path.getsize(filepath))}"]:
        d.text((4, y), t, font=font_sm, fill=(0, 200, 100))
        y += 12
    d.text((4, 117), "Any key to close", font=font_sm, fill=(50, 70, 90))
    LCD.LCD_ShowImage(img, 0, 0)
    _set_volume(_volume)
    get_button(PINS, GPIO)


def _get_duration(filepath):
    """Get video duration in seconds via ffprobe."""
    try:
        r = subprocess.run(
            ["ffprobe", "-v", "quiet", "-show_entries", "format=duration",
             "-of", "csv=p=0", filepath],
            capture_output=True, text=True, timeout=5)
        return float(r.stdout.strip())
    except Exception:
        return 0


def _read_frame(proc):
    """Read exactly one RGB565 frame from pipe. Returns bytes or None."""
    raw = b""
    while len(raw) < FB_SIZE:
        chunk = proc.stdout.read(FB_SIZE - len(raw))
        if not chunk:
            return None
        raw += chunk
    return raw


_osd_img = None
_osd_raw = None


def _build_osd(fname, paused, elapsed, duration):
    """Build OSD overlay as PIL image."""
    global _osd_img
    h = 16
    img = Image.new("RGBA", (WIDTH, h), (0, 0, 0, 150))
    d = ImageDraw.Draw(img)

    # Line 1: [>||] filename     LP V40  00:12/02:26
    icon = ">" if paused else "||"
    x = 2
    d.text((x, 1), icon, font=font_sm, fill=(255, 255, 255))
    x = 16
    d.text((x, 1), fname[:12], font=font_sm, fill=(220, 220, 220))

    # Right side: loop + volume + time
    right = ""
    if _loop:
        right += "LP "
    right += f"V{_volume}"
    if duration > 0:
        right += f" {_format_time(elapsed)}/{_format_time(duration)}"
    rw = len(right) * 6
    d.text((WIDTH - rw - 2, 1), right, font=font_sm, fill=(100, 200, 255))

    # Progress bar at bottom of OSD
    d.rectangle((0, h - 3, WIDTH, h - 1), fill=(40, 40, 40, 180))
    if duration > 0:
        prog = min(1.0, elapsed / duration)
        px = int(WIDTH * prog)
        d.rectangle((0, h - 3, px, h - 1), fill=(0, 200, 255))

    _osd_img = img


def _write_frame_with_osd(fb_map, frame_raw, show_osd):
    """Write frame to framebuffer, compositing OSD if needed."""
    if not show_osd or _osd_img is None:
        fb_map.seek(0)
        fb_map.write(frame_raw)
        return

    arr = np.frombuffer(frame_raw, dtype=np.uint16).reshape(HEIGHT, WIDTH).copy()
    osd_h = _osd_img.height
    osd_y = HEIGHT - osd_h

    osd_rgba = np.array(_osd_img)
    alpha = osd_rgba[:, :, 3:4].astype(np.float32) / 255.0

    vid_r = ((arr[osd_y:, :] >> 11) & 0x1F).astype(np.float32) * 8
    vid_g = ((arr[osd_y:, :] >> 5) & 0x3F).astype(np.float32) * 4
    vid_b = (arr[osd_y:, :] & 0x1F).astype(np.float32) * 8

    osd_r = osd_rgba[:, :, 0].astype(np.float32)
    osd_g = osd_rgba[:, :, 1].astype(np.float32)
    osd_b = osd_rgba[:, :, 2].astype(np.float32)

    a = alpha[:, :, 0]
    r = (osd_r * a + vid_r * (1 - a)).astype(np.uint16) >> 3
    g = (osd_g * a + vid_g * (1 - a)).astype(np.uint16) >> 2
    b = (osd_b * a + vid_b * (1 - a)).astype(np.uint16) >> 3

    arr[osd_y:, :] = (r << 11) | (g << 5) | b

    fb_map.seek(0)
    fb_map.write(arr.tobytes())


def _has_audio(filepath):
    """Check if file has an audio stream."""
    try:
        r = subprocess.run(
            ["ffprobe", "-v", "error", "-select_streams", "a",
             "-show_entries", "stream=codec_type", "-of", "csv=p=0", filepath],
            capture_output=True, text=True, timeout=5)
        return "audio" in r.stdout
    except Exception:
        return False


def _get_resolution(filepath):
    try:
        r = subprocess.run(
            ["ffprobe", "-v", "error", "-select_streams", "v:0",
             "-show_entries", "stream=height", "-of", "csv=p=0", filepath],
            capture_output=True, text=True, timeout=5)
        return int(r.stdout.strip())
    except Exception:
        return 0


def _start_playback(filepath, seek=0):
    """Start ffmpeg with video pipe + audio output, synced from seek position."""
    cmd = [
        "ffmpeg", "-hide_banner", "-loglevel", "quiet",
        "-re",
        "-ss", str(seek),
        "-fflags", "+nobuffer+fastseek",
        "-analyzeduration", "0", "-probesize", "32768",
        "-i", filepath,
        "-map", "0:v:0",
        "-vf", f"scale={WIDTH}:{HEIGHT}:force_original_aspect_ratio=decrease,pad={WIDTH}:{HEIGHT}:(ow-iw)/2:(oh-ih)/2,fps=15",
        "-pix_fmt", "rgb565le",
        "-f", "rawvideo", "pipe:1",
    ]
    if _has_audio(filepath):
        cmd += ["-map", "0:a:0", "-ac", "2", "-ar", "44100", "-f", "alsa", "default"]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=FB_SIZE)


def _kill_proc(p):
    if p:
        try:
            p.kill()
            p.wait(timeout=2)
        except Exception:
            pass


def _play_video(filepath):
    global _loop

    res = _get_resolution(filepath)
    if res > 1080:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((64, 40), "Resolution too high", font=font, fill="#FF5252", anchor="mm")
        d.text((64, 58), f"{res}p > 1080p max", font=font_sm, fill="#888888", anchor="mm")
        d.text((64, 75), "Re-download in 720p", font=font_sm, fill="#888888", anchor="mm")
        d.text((64, 95), "OK to go back", font=font_sm, fill="#555555", anchor="mm")
        LCD.LCD_ShowImage(img, 0, 0)
        while _running:
            b = get_button(PINS, GPIO)
            if b in ("OK", "KEY3"):
                break
            time.sleep(0.05)
        return

    fname = os.path.splitext(os.path.basename(filepath))[0]
    duration = _get_duration(filepath)
    _set_volume(_volume)

    proc = _start_playback(filepath)

    fb_fd = os.open(FB_DEVICE, os.O_RDWR)
    fb_map = mmap.mmap(fb_fd, FB_SIZE, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)
    paused = False
    start_time = time.time()
    pause_offset = 0
    osd_until = time.time() + 3.0
    last_osd_rebuild = 0
    last_frame = None

    try:
        while _running:
            btn = _check_button()
            now = time.time()

            if btn == "KEY3":
                break
            elif btn == "OK":
                paused = not paused
                osd_until = now + 3.0
                last_osd_rebuild = 0
                if paused:
                    pause_offset = now - start_time
                    _kill_proc(proc)
                    proc = None
                    if last_frame:
                        _build_osd(fname, True, pause_offset, duration)
                        _write_frame_with_osd(fb_map, last_frame, True)
                else:
                    proc = _start_playback(filepath, pause_offset)
                    start_time = now - pause_offset
                time.sleep(DEBOUNCE)
                continue
            elif btn == "UP":
                _set_volume(_volume + 10)
                osd_until = now + 2.0
                last_osd_rebuild = 0
                time.sleep(DEBOUNCE)
            elif btn == "DOWN":
                _set_volume(_volume - 10)
                osd_until = now + 2.0
                last_osd_rebuild = 0
                time.sleep(DEBOUNCE)
            elif btn == "LEFT":
                elapsed = now - start_time
                seek_to = max(0, elapsed - 10)
                _kill_proc(proc)
                proc = _start_playback(filepath, seek_to)
                start_time = now - seek_to
                osd_until = now + 2.0
                last_osd_rebuild = 0
                time.sleep(DEBOUNCE)
            elif btn == "RIGHT":
                elapsed = now - start_time
                seek_to = min(duration, elapsed + 10) if duration else elapsed + 10
                _kill_proc(proc)
                proc = _start_playback(filepath, seek_to)
                start_time = now - seek_to
                osd_until = now + 2.0
                last_osd_rebuild = 0
                time.sleep(DEBOUNCE)
            elif btn == "KEY1":
                _loop = not _loop
                osd_until = now + 2.0
                last_osd_rebuild = 0
                time.sleep(DEBOUNCE)
            elif btn:
                osd_until = now + 2.0

            if paused:
                time.sleep(0.05)
                continue

            raw = _read_frame(proc)
            if raw is None:
                if _loop:
                    _kill_proc(proc)
                    proc = _start_playback(filepath)
                    start_time = now
                    continue
                break

            last_frame = raw
            show_osd = now < osd_until

            if show_osd:
                if now - last_osd_rebuild > 0.5:
                    _build_osd(fname, paused, now - start_time, duration)
                    last_osd_rebuild = now
                _write_frame_with_osd(fb_map, raw, True)
            else:
                fb_map.seek(0)
                fb_map.write(raw)

    finally:
        _kill_proc(proc)
        fb_map.close()
        os.close(fb_fd)
        subprocess.run(["pkill", "-9", "ffmpeg"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.3)
        LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)


def main():
    _set_volume(_volume)
    current_dir = START_DIR
    cursor, scroll, dir_stack = 0, 0, []

    try:
        while _running:
            items = _list_dir(current_dir)
            _draw_browser(items, cursor, scroll, current_dir)
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if dir_stack:
                    current_dir, cursor, scroll = dir_stack.pop()
                else:
                    break
                time.sleep(DEBOUNCE)
            elif btn == "LEFT":
                if dir_stack:
                    current_dir, cursor, scroll = dir_stack.pop()
                else:
                    parent = os.path.dirname(current_dir)
                    if parent != current_dir:
                        dir_stack.append((current_dir, cursor, scroll))
                        current_dir, cursor, scroll = parent, 0, 0
                time.sleep(DEBOUNCE)
            elif btn == "UP":
                if cursor == 0 and items:
                    cursor = len(items) - 1
                    scroll = max(0, cursor - 6)
                else:
                    cursor -= 1
                    if cursor < scroll:
                        scroll = cursor
                time.sleep(DEBOUNCE)
            elif btn == "DOWN":
                if items and cursor >= len(items) - 1:
                    cursor = 0
                    scroll = 0
                else:
                    cursor += 1
                    if cursor >= scroll + 7:
                        scroll = cursor - 6
                time.sleep(DEBOUNCE)
            elif btn in ("OK", "RIGHT") and items and cursor < len(items):
                item = items[cursor]
                if item["is_dir"]:
                    dir_stack.append((current_dir, cursor, scroll))
                    current_dir, cursor, scroll = item["path"], 0, 0
                else:
                    _play_video(item["path"])
                time.sleep(DEBOUNCE)
            elif btn == "KEY1" and items and cursor < len(items):
                if not items[cursor]["is_dir"]:
                    _show_info_screen(items[cursor]["path"])
                time.sleep(DEBOUNCE)
            time.sleep(0.03)
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
