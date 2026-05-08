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
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font, S
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
font = scaled_font(9)
font_sm = scaled_font(7)

VIDEO_EXTENSIONS = {".mp4", ".avi", ".mkv", ".mov", ".webm", ".flv", ".m4v"}
START_DIR = "/root/Raspyjack/loot"
DEBOUNCE = 0.18
FB_DEVICE = "/dev/fb0"
FB_SIZE = WIDTH * HEIGHT * 2

_running = True
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


def _set_volume(vol):
    global _volume
    _volume = max(0, min(100, vol))
    subprocess.Popen(["amixer", "-c", "1", "sset", "Headphone", str(int(_volume * 63 / 100))], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.Popen(["amixer", "-c", "1", "sset", "DACL", "180"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.Popen(["amixer", "-c", "1", "sset", "DACR", "180"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


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


def _play_video(filepath):
    global _loop

    # volume set after loading
    target_fps = 15

    # Single ffmpeg: video to pipe (RGB565) + audio to ALSA
    # ffmpeg handles A/V sync internally
    cmd = [
        "ffmpeg", "-hide_banner", "-loglevel", "quiet",
        "-re",
        "-ss", "0",
        "-fflags", "+nobuffer+fastseek",
        "-analyzeduration", "0", "-probesize", "32768",
        "-i", filepath,
        "-map", "0:v:0",
        "-vf", f"scale={WIDTH}:{HEIGHT}:force_original_aspect_ratio=decrease,pad={WIDTH}:{HEIGHT}:(ow-iw)/2:(oh-ih)/2,fps={target_fps}",
        "-pix_fmt", "rgb565le",
        "-f", "rawvideo", "pipe:1",
        "-map", "0:a:0?",
        "-ac", "2", "-ar", "44100",
        "-f", "alsa", "plughw:1,0",
    ]

    # Loading screen
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((64, 50), "Loading...", font=font, fill=(0, 200, 255), anchor="mm")
    fname = os.path.splitext(os.path.basename(filepath))[0]
    d.text((64, 68), fname[:20], font=font_sm, fill=(150, 150, 150), anchor="mm")
    LCD.LCD_ShowImage(img, 0, 0)
    _set_volume(_volume)

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        bufsize=FB_SIZE,
    )

    fb_fd = os.open(FB_DEVICE, os.O_RDWR)
    fb_map = mmap.mmap(fb_fd, FB_SIZE, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)
    paused = False

    try:
        while _running:
            btn = _check_button()

            if btn == "KEY3":
                break
            elif btn == "OK":
                paused = not paused
                if paused:
                    proc.send_signal(signal.SIGSTOP)
                else:
                    proc.send_signal(signal.SIGCONT)
                time.sleep(DEBOUNCE)
                continue
            elif btn == "UP":
                _set_volume(_volume + 10)
                time.sleep(DEBOUNCE)
            elif btn == "DOWN":
                _set_volume(_volume - 10)
                time.sleep(DEBOUNCE)
            elif btn == "LEFT":
                # Restart 10s earlier
                proc.kill()
                proc.wait()
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    bufsize=FB_SIZE,
                )
                time.sleep(DEBOUNCE)
            elif btn == "KEY1":
                _loop = not _loop
                time.sleep(DEBOUNCE)

            if paused:
                time.sleep(0.05)
                continue

            raw = proc.stdout.read(FB_SIZE)
            if not raw or len(raw) < FB_SIZE:
                if _loop:
                    proc.kill()
                    proc.wait()
                    proc = subprocess.Popen(
                        cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                        bufsize=FB_SIZE,
                    )
                    continue
                break

            fb_map.seek(0)
            fb_map.write(raw)

    finally:
        try:
            proc.kill()
            proc.wait(timeout=2)
        except Exception:
            pass
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
                cursor = max(0, cursor - 1)
                if cursor < scroll:
                    scroll = cursor
                time.sleep(DEBOUNCE)
            elif btn == "DOWN":
                cursor = min(max(0, len(items) - 1), cursor + 1)
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
