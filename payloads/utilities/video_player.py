#!/usr/bin/env python3
"""
RaspyJack Payload -- Video Player
===================================
Author: 7h30th3r0n3

Play MP4/AVI/MKV videos on the LCD screen. Browse filesystem to select
a video file, plays with frame-by-frame rendering resized to LCD.

Controls:
  UP / DOWN   Browse files
  OK          Play selected / pause-resume
  LEFT        Back to parent directory
  KEY1        Rewind 10 seconds
  KEY2        Fast forward 10 seconds
  KEY3        Stop / Exit
"""

import os
import sys
import time
import signal

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
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
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROW_H = 12
VISIBLE = 7
VIDEO_EXTENSIONS = {".mp4", ".avi", ".mkv", ".mov", ".webm", ".flv"}
START_DIR = "/root/Raspyjack/loot"

_running = True


def _cleanup(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# File browser
# ---------------------------------------------------------------------------

def _list_dir(path):
    """List directories first, then video files."""
    items = []
    try:
        entries = sorted(os.listdir(path))
    except PermissionError:
        return items

    dirs = []
    files = []
    for e in entries:
        if e.startswith("."):
            continue
        full = os.path.join(path, e)
        if os.path.isdir(full):
            dirs.append({"name": e + "/", "path": full, "is_dir": True})
        elif os.path.splitext(e)[1].lower() in VIDEO_EXTENSIONS:
            size = os.path.getsize(full)
            files.append({"name": e, "path": full, "is_dir": False, "size": size})

    return dirs + files


def _human_size(size):
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.0f}{unit}"
        size /= 1024
    return f"{size:.0f}TB"


def _draw_browser(lcd, font, font_sm, items, cursor, scroll, current_dir):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#111")
    dirname = os.path.basename(current_dir) or current_dir
    d.text((2, 1), f"VIDEO {dirname[:14]}", font=font_sm, fill="#00CCFF")

    if not items:
        d.text((4, 40), "No videos found", font=font, fill="#666")
        d.text((4, 55), "Copy .mp4 files to", font=font_sm, fill="#888")
        d.text((4, 67), START_DIR[:22], font=font_sm, fill="#444")
    else:
        visible = items[scroll:scroll + VISIBLE]
        for i, item in enumerate(visible):
            y = 16 + i * ROW_H
            idx = scroll + i
            prefix = ">" if idx == cursor else " "
            color = "#FFAA00" if item["is_dir"] else "#00FF00"
            if idx == cursor:
                color = "#FFFFFF"

            name = item["name"][:16]
            d.text((2, y), f"{prefix}{name}", font=font_sm, fill=color)

            if not item["is_dir"]:
                sz = _human_size(item.get("size", 0))
                d.text((105, y), sz[:6], font=font_sm, fill="#666")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Play LEFT:Back K3:X", font=font_sm, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Video player
# ---------------------------------------------------------------------------

def _format_time(seconds):
    m = int(seconds) // 60
    s = int(seconds) % 60
    return f"{m:02d}:{s:02d}"


def _play_video(lcd, font, font_sm, filepath):
    """Play video file on LCD."""
    cap = cv2.VideoCapture(filepath)
    if not cap.isOpened():
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "Cannot open video", font=font, fill="#FF4444")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(2)
        return

    fps = cap.get(cv2.CAP_PROP_FPS) or 24
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    duration = total_frames / fps if fps > 0 else 0

    # Target ~12 FPS max on RPi (SPI LCD bottleneck)
    target_fps = min(fps, 12)
    frame_skip = max(1, int(fps / target_fps))
    frame_time = 1.0 / target_fps

    # Pre-compute resize dimensions once
    sample_w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    sample_h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    ratio = min(WIDTH / max(1, sample_w), HEIGHT / max(1, sample_h))
    new_w = max(1, int(sample_w * ratio))
    new_h = max(1, int(sample_h * ratio))
    x_offset = (WIDTH - new_w) // 2
    y_offset = (HEIGHT - new_h) // 2

    paused = False
    frame_count = 0
    from PIL import ImageDraw as _ImageDraw

    try:
        while _running:
            start = time.monotonic()

            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break
            elif btn == "OK":
                paused = not paused
                time.sleep(0.2)
            elif btn == "KEY1":
                pos = cap.get(cv2.CAP_PROP_POS_FRAMES)
                cap.set(cv2.CAP_PROP_POS_FRAMES, max(0, pos - fps * 10))
                time.sleep(0.15)
            elif btn == "KEY2":
                pos = cap.get(cv2.CAP_PROP_POS_FRAMES)
                cap.set(cv2.CAP_PROP_POS_FRAMES, min(total_frames - 1, pos + fps * 10))
                time.sleep(0.15)

            if paused:
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.text((50, 55), "II", font=font, fill="#FFAA00")
                current_pos = cap.get(cv2.CAP_PROP_POS_FRAMES) / fps
                d.text((2, 117), f"{_format_time(current_pos)}/{_format_time(duration)}", font=font_sm, fill="#888")
                lcd.LCD_ShowImage(img, 0, 0)
                time.sleep(0.1)
                continue

            ret, frame = cap.read()
            if not ret:
                cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
                frame_count = 0
                continue

            frame_count += 1

            # Skip frames to maintain target FPS
            if frame_count % frame_skip != 0:
                continue

            # Resize directly with opencv (much faster than PIL)
            frame_small = cv2.resize(frame, (new_w, new_h), interpolation=cv2.INTER_NEAREST)
            frame_rgb = cv2.cvtColor(frame_small, cv2.COLOR_BGR2RGB)

            # Build canvas
            canvas = Image.new("RGB", (WIDTH, HEIGHT), "black")
            pil_frame = Image.fromarray(frame_rgb)
            canvas.paste(pil_frame, (x_offset, y_offset))

            # Thin progress bar
            current_frame = cap.get(cv2.CAP_PROP_POS_FRAMES)
            if total_frames > 0:
                bar_w = int(WIDTH * current_frame / total_frames)
                draw = _ImageDraw.Draw(canvas)
                draw.rectangle((0, HEIGHT - 2, bar_w, HEIGHT - 1), fill="#00FF00")

            lcd.LCD_ShowImage(canvas, 0, 0)

            # Frame rate control
            elapsed = time.monotonic() - start
            if frame_time > elapsed:
                time.sleep(frame_time - elapsed)

    finally:
        cap.release()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font = scaled_font(10)
    font_sm = scaled_font(8)

    if not CV2_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 40), "opencv not found!", font=font, fill="#FF4444")
        d.text((4, 55), "pip install", font=font_sm, fill="#888")
        d.text((4, 67), "opencv-python-headless", font=font_sm, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    current_dir = START_DIR
    cursor = 0
    scroll = 0
    dir_stack = []

    try:
        while _running:
            items = _list_dir(current_dir)
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if dir_stack:
                    current_dir, cursor, scroll = dir_stack.pop()
                else:
                    break
                time.sleep(0.2)

            elif btn == "LEFT":
                if dir_stack:
                    current_dir, cursor, scroll = dir_stack.pop()
                else:
                    parent = os.path.dirname(current_dir)
                    if parent != current_dir:
                        dir_stack.append((current_dir, cursor, scroll))
                        current_dir = parent
                        cursor = 0
                        scroll = 0
                time.sleep(0.2)

            elif btn == "UP":
                cursor = max(0, cursor - 1)
                if cursor < scroll:
                    scroll = cursor
                time.sleep(0.15)

            elif btn == "DOWN":
                cursor = min(max(0, len(items) - 1), cursor + 1)
                if cursor >= scroll + VISIBLE:
                    scroll = cursor - VISIBLE + 1
                time.sleep(0.15)

            elif btn == "OK" and items and cursor < len(items):
                item = items[cursor]
                if item["is_dir"]:
                    dir_stack.append((current_dir, cursor, scroll))
                    current_dir = item["path"]
                    cursor = 0
                    scroll = 0
                else:
                    _play_video(lcd, font, font_sm, item["path"])
                time.sleep(0.2)

            _draw_browser(lcd, font, font_sm, items, cursor, scroll, current_dir)
            time.sleep(0.05)

    finally:
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
