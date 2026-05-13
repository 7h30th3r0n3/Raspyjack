#!/usr/bin/env python3
"""
RaspyJack Payload -- DOOM (FreeDoom)
=====================================
Runs chocolate-doom on Xvfb, captures frames via ffmpeg x11grab,
and streams to the LCD framebuffer. Keyboard via evdev.

Controls: CardputerZero TCA8418 keyboard mapped to DOOM keys.
KEY3 = Quit
"""

import os
import sys
import time
import signal
import subprocess
import mmap
import threading

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
GPIO.setmode(GPIO.BCM)
for p in PINS.values():
    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
font = scaled_font(9)
font_sm = scaled_font(7)

FB_DEVICE = "/dev/fb1" if os.path.exists("/dev/fb1") else "/dev/fb0"
FB_SIZE = WIDTH * HEIGHT * 2
DISPLAY_NUM = ":99"

DOOM_BIN = "/usr/games/chocolate-doom"
WADS = [
    "/usr/share/games/doom/freedoom1.wad",
    "/usr/share/games/doom/freedoom2.wad",
    "/usr/share/games/doom/doom1.wad",
    "/usr/share/games/doom/doom.wad",
]

_running = True


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _find_wad():
    for w in WADS:
        if os.path.isfile(w):
            return w
    return None


def _show_msg(text, sub="", color=(0, 200, 255)):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((WIDTH // 2, HEIGHT // 2 - 10), text, font=font, fill=color, anchor="mm")
    if sub:
        d.text((WIDTH // 2, HEIGHT // 2 + 10), sub, font=font_sm, fill=(150, 150, 150), anchor="mm")
    LCD.LCD_ShowImage(img, 0, 0)


def _read_frame(proc):
    raw = b""
    while len(raw) < FB_SIZE:
        chunk = proc.stdout.read(FB_SIZE - len(raw))
        if not chunk:
            return None
        raw += chunk
    return raw


def _key_thread(doom_proc):
    """Send keypresses to Doom via xdotool on the virtual X display."""
    key_map = {
        "UP": "Up",
        "DOWN": "Down",
        "LEFT": "Left",
        "RIGHT": "Right",
        "OK": "Return",
        "KEY1": "ctrl",
        "KEY2": "space",
    }
    env = os.environ.copy()
    env["DISPLAY"] = DISPLAY_NUM
    pressed_set = set()
    last_press = {}

    while _running and doom_proc.poll() is None:
        now = time.time()
        for name, pin in PINS.items():
            is_down = GPIO.input(pin) == 0
            xkey = key_map.get(name)
            if not xkey:
                continue
            if is_down and name not in pressed_set:
                debounce = 0.4 if name == "OK" else 0.02
                if now - last_press.get(name, 0) < debounce:
                    continue
                pressed_set.add(name)
                last_press[name] = now
                subprocess.Popen(
                    ["xdotool", "keydown", xkey],
                    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif not is_down and name in pressed_set:
                pressed_set.discard(name)
                subprocess.Popen(
                    ["xdotool", "keyup", xkey],
                    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.02)


def main():
    global _running

    wad = _find_wad()
    if not wad:
        _show_msg("No WAD found", "Install: apt install freedoom", (255, 50, 50))
        time.sleep(3)
        GPIO.cleanup()
        return 1

    if not os.path.isfile(DOOM_BIN):
        _show_msg("chocolate-doom", "not installed", (255, 50, 50))
        time.sleep(3)
        GPIO.cleanup()
        return 1

    has_xdotool = os.path.isfile("/usr/bin/xdotool")
    if not has_xdotool:
        _show_msg("Installing xdotool...", "", (255, 180, 0))
        subprocess.run(["apt-get", "install", "-y", "xdotool"],
                       capture_output=True, timeout=60)

    _show_msg("DOOM", "Starting...", (255, 50, 0))

    xvfb = subprocess.Popen(
        ["Xvfb", DISPLAY_NUM, "-screen", "0", "320x200x24", "-ac", "-nocursor"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    env = os.environ.copy()
    env["DISPLAY"] = DISPLAY_NUM
    env["SDL_VIDEODRIVER"] = "x11"

    env["SDL_VIDEO_X11_WMCLASS"] = "doom"
    env["SDL_VIDEO_WINDOW_POS"] = "0,0"
    doom = subprocess.Popen(
        [DOOM_BIN, "-iwad", wad, "-nomusic", "-nomouse", "-window", "-geometry", "320x200"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)

    capture = subprocess.Popen(
        ["ffmpeg", "-hide_banner", "-loglevel", "quiet",
         "-f", "x11grab", "-framerate", "15",
         "-video_size", "320x200",
         "-i", DISPLAY_NUM,
         "-vf", f"scale={WIDTH}:{HEIGHT}:force_original_aspect_ratio=decrease,pad={WIDTH}:{HEIGHT}:(ow-iw)/2:(oh-ih)/2",
         "-pix_fmt", "rgb565le",
         "-f", "rawvideo", "pipe:1"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=FB_SIZE)

    kt = threading.Thread(target=_key_thread, args=(doom,), daemon=True)
    kt.start()

    fb_fd = os.open(FB_DEVICE, os.O_RDWR)
    fb_map = mmap.mmap(fb_fd, FB_SIZE, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)

    try:
        while _running:
            btn = None
            for name, pin in PINS.items():
                if GPIO.input(pin) == 0 and name == "KEY3":
                    btn = "KEY3"
            if btn == "KEY3":
                break

            if doom.poll() is not None:
                break

            raw = _read_frame(capture)
            if raw is None:
                break

            fb_map.seek(0)
            fb_map.write(raw)

    finally:
        _running = False
        for p in [capture, doom, xvfb]:
            try:
                p.kill()
                p.wait(timeout=2)
            except Exception:
                pass
        fb_map.close()
        os.close(fb_fd)
        subprocess.run(["pkill", "-9", "chocolate"], capture_output=True)
        subprocess.run(["pkill", "-9", "Xvfb"], capture_output=True)
        subprocess.run(["pkill", "-9", "ffmpeg"], capture_output=True)
        time.sleep(0.3)
        LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
        LCD.LCD_Clear()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
