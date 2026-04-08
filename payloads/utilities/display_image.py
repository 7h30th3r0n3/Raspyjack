#!/usr/bin/env python3
"""
RaspyJack Payload -- LCD Image Viewer
=======================================
Author: 7h30th3r0n3

Browse the filesystem and display images on the LCD.  Supports PNG,
JPG, GIF, and BMP files with fit/fill/stretch resize modes.

Controls
--------
  UP / DOWN    -- Navigate files
  OK           -- Open directory or display image
  LEFT         -- Go back to parent directory
  KEY1         -- Toggle fit / fill / stretch mode
  KEY2         -- Set image as screensaver
  KEY3         -- Exit
"""

import os
import sys
import time
import signal
import shutil

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
DEBOUNCE = 0.22
START_DIR = "/root/Raspyjack"
SCREENSAVER_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "img", "screensaver"
)
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp"}
RESIZE_MODES = ["fit", "fill", "stretch"]

_running = True


def _cleanup(*_args):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# File listing
# ---------------------------------------------------------------------------

def _is_image(name):
    """Check if filename has an image extension."""
    return os.path.splitext(name)[1].lower() in IMAGE_EXTS


def _list_dir(path):
    """List directory entries sorted: dirs first, then files."""
    dirs = []
    files = []
    try:
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            if os.path.isdir(full):
                dirs.append({"name": name, "path": full, "is_dir": True})
            elif _is_image(name):
                files.append({"name": name, "path": full, "is_dir": False})
    except OSError:
        pass
    return dirs + files


# ---------------------------------------------------------------------------
# Image loading
# ---------------------------------------------------------------------------

def _load_image_fit(path, width, height):
    """Load and resize image maintaining aspect ratio (letterbox)."""
    img = Image.open(path).convert("RGB")
    img.thumbnail((width, height), Image.LANCZOS)
    result = Image.new("RGB", (width, height), "black")
    x_off = (width - img.width) // 2
    y_off = (height - img.height) // 2
    result.paste(img, (x_off, y_off))
    return result


def _load_image_fill(path, width, height):
    """Load and resize image cropping to fill (no letterbox)."""
    img = Image.open(path).convert("RGB")
    img_ratio = img.width / img.height
    target_ratio = width / height
    if img_ratio > target_ratio:
        new_h = height
        new_w = int(height * img_ratio)
    else:
        new_w = width
        new_h = int(width / img_ratio)
    img = img.resize((new_w, new_h), Image.LANCZOS)
    x_off = (new_w - width) // 2
    y_off = (new_h - height) // 2
    return img.crop((x_off, y_off, x_off + width, y_off + height))


def _load_image_stretch(path, width, height):
    """Load and resize image stretching to fill."""
    img = Image.open(path).convert("RGB")
    return img.resize((width, height), Image.LANCZOS)


def _load_image(path, width, height, mode):
    """Load image with selected resize mode."""
    loaders = {
        "fit": _load_image_fit,
        "fill": _load_image_fill,
        "stretch": _load_image_stretch,
    }
    loader = loaders.get(mode, _load_image_fit)
    return loader(path, width, height)


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_browser(lcd, font, cwd, entries, cursor, scroll, mode, status):
    """Draw the file browser."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    dirname = os.path.basename(cwd) or cwd
    if len(dirname) > 14:
        dirname = dirname[:11] + "..."
    d.text((2, 1), dirname, font=font, fill="#00CCFF")
    d.text((100, 1), mode[:3], font=font, fill="#888")

    # File list
    visible = 7
    y = 16
    end = min(len(entries), scroll + visible)

    if not entries:
        d.text((4, 40), "(empty)", font=font, fill="#666")
    else:
        for idx in range(scroll, end):
            entry = entries[idx]
            is_sel = idx == cursor
            prefix = ">" if is_sel else " "
            if entry["is_dir"]:
                label = f"{prefix}[{entry['name'][:13]}]"
                color = "#00AAFF" if is_sel else "#5588BB"
            else:
                label = f"{prefix}{entry['name'][:16]}"
                color = "#00FF00" if is_sel else "#AAAAAA"
            d.text((2, y), label[:20], font=font, fill=color)
            y += ROW_H

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if status:
        d.text((2, 117), status[:22], font=font, fill="#FFFF00")
    else:
        d.text((2, 117), "OK:open K1:mode K3:ex", font=font, fill="#AAA")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_image_view(lcd, path, width, height, mode):
    """Display an image on the LCD."""
    try:
        img = _load_image(path, width, height, mode)
        lcd.LCD_ShowImage(img, 0, 0)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    font = scaled_font()

    cwd = START_DIR
    if not os.path.isdir(cwd):
        cwd = "/"
    entries = _list_dir(cwd)
    cursor = 0
    scroll = 0
    resize_idx = 0
    status = ""
    last_press = 0.0
    visible = 7
    viewing_image = False

    try:
        while _running:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            # Image viewing mode
            if viewing_image:
                if btn == "KEY1":
                    resize_idx = (resize_idx + 1) % len(RESIZE_MODES)
                    mode = RESIZE_MODES[resize_idx]
                    entry = entries[cursor]
                    _draw_image_view(lcd, entry["path"], WIDTH, HEIGHT, mode)
                    time.sleep(0.1)
                    continue
                elif btn == "KEY2":
                    entry = entries[cursor]
                    try:
                        ss_dir = os.path.abspath(SCREENSAVER_DIR)
                        os.makedirs(ss_dir, exist_ok=True)
                        dest = os.path.join(ss_dir, entry["name"])
                        shutil.copy2(entry["path"], dest)
                        status = "Set screensaver!"
                    except Exception as exc:
                        status = f"Err:{str(exc)[:14]}"
                    viewing_image = False
                    continue
                elif btn is not None:
                    viewing_image = False
                    continue
                time.sleep(0.08)
                continue

            # Browser mode
            if btn == "KEY3":
                break
            elif btn == "UP":
                cursor = max(0, cursor - 1)
                if cursor < scroll:
                    scroll = cursor
                status = ""
            elif btn == "DOWN":
                cursor = min(max(0, len(entries) - 1), cursor + 1)
                if cursor >= scroll + visible:
                    scroll = cursor - visible + 1
                status = ""
            elif btn == "LEFT":
                parent = os.path.dirname(cwd)
                if parent and parent != cwd:
                    cwd = parent
                    entries = _list_dir(cwd)
                    cursor = 0
                    scroll = 0
                    status = ""
            elif btn == "OK" and entries:
                entry = entries[cursor]
                if entry["is_dir"]:
                    cwd = entry["path"]
                    entries = _list_dir(cwd)
                    cursor = 0
                    scroll = 0
                    status = ""
                else:
                    mode = RESIZE_MODES[resize_idx]
                    ok = _draw_image_view(lcd, entry["path"], WIDTH, HEIGHT, mode)
                    if ok:
                        viewing_image = True
                    else:
                        status = "Load failed"
                    time.sleep(0.1)
                    continue
            elif btn == "KEY1":
                resize_idx = (resize_idx + 1) % len(RESIZE_MODES)
                status = f"Mode: {RESIZE_MODES[resize_idx]}"
            elif btn == "KEY2" and entries:
                entry = entries[cursor]
                if not entry["is_dir"]:
                    try:
                        ss_dir = os.path.abspath(SCREENSAVER_DIR)
                        os.makedirs(ss_dir, exist_ok=True)
                        dest = os.path.join(ss_dir, entry["name"])
                        shutil.copy2(entry["path"], dest)
                        status = "Set screensaver!"
                    except Exception as exc:
                        status = f"Err:{str(exc)[:14]}"

            mode = RESIZE_MODES[resize_idx]
            _draw_browser(lcd, font, cwd, entries, cursor, scroll, mode, status)
            time.sleep(0.08)

    finally:
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
