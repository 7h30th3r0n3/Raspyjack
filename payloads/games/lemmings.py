#!/usr/bin/env python3
"""
RaspyJack Payload -- Lemmings (Pingus)
========================================
Author: 7h30th3r0n3

Pingus - Free Lemmings clone on the CardputerZero LCD.
Runs on Xvfb, captures via ffmpeg x11grab to framebuffer.

Controls:
  Arrows      Move cursor
  OK/Enter    Select/Confirm
  KEY1/Space  Action
  KEY2        Pause
  KEY3        Quit
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
GPIO.setwarnings(False)
for p in PINS.values():
    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
font = scaled_font(9)
font_sm = scaled_font(7)

FB_DEVICE = "/dev/fb1" if os.path.exists("/dev/fb1") else "/dev/fb0"
FB_SIZE = WIDTH * HEIGHT * 2
DISPLAY_NUM = ":98"
PINGUS_BIN = "/usr/games/pingus"
GAME_W, GAME_H = 800, 600

_running = True


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _show_msg(text, sub="", color=(0, 200, 255)):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    try:
        d.text((WIDTH // 2, HEIGHT // 2 - 10), text, font=font, fill=color, anchor="mm")
    except Exception:
        d.text((10, HEIGHT // 2 - 10), text, font=font, fill=color)
    if sub:
        try:
            d.text((WIDTH // 2, HEIGHT // 2 + 10), sub, font=font_sm, fill=(150, 150, 150), anchor="mm")
        except Exception:
            d.text((10, HEIGHT // 2 + 10), sub, font=font_sm, fill=(150, 150, 150))
    LCD.LCD_ShowImage(img, 0, 0)


def _read_frame(proc):
    raw = b""
    while len(raw) < FB_SIZE:
        chunk = proc.stdout.read(FB_SIZE - len(raw))
        if not chunk:
            return None
        raw += chunk
    return raw


def _ensure_deps():
    missing = []
    if not os.path.isfile(PINGUS_BIN):
        missing.append("pingus")
    if not os.path.isfile("/usr/bin/Xvfb"):
        missing.append("xvfb")
    if not os.path.isfile("/usr/bin/xdotool"):
        missing.append("xdotool")
    if not missing:
        return True
    _show_msg("Installing...", " ".join(missing), (255, 180, 0))
    r = subprocess.run(
        ["apt-get", "install", "-y"] + missing,
        capture_output=True, timeout=180)
    return os.path.isfile(PINGUS_BIN)


def _key_thread(game_proc):
    key_map = {
        "UP": "Up",
        "DOWN": "Down",
        "LEFT": "Left",
        "RIGHT": "Right",
        "KEY1": "space",
    }
    env = os.environ.copy()
    env["DISPLAY"] = DISPLAY_NUM
    pressed_set = set()
    k2_down_time = 0

    while _running and game_proc.poll() is None:
        now = time.time()

        k2_down = GPIO.input(PINS["KEY2"]) == 0
        if k2_down and "KEY2" not in pressed_set:
            pressed_set.add("KEY2")
            k2_down_time = now
        elif not k2_down and "KEY2" in pressed_set:
            pressed_set.discard("KEY2")
            held = now - k2_down_time
            key = "Escape" if held > 0.5 else "p"
            subprocess.Popen(
                ["xdotool", "key", key],
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        ok_down = GPIO.input(PINS["OK"]) == 0
        if ok_down and "OK" not in pressed_set:
            pressed_set.add("OK")
            subprocess.Popen(
                ["xdotool", "mousedown", "1"],
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif not ok_down and "OK" in pressed_set:
            pressed_set.discard("OK")
            subprocess.Popen(
                ["xdotool", "mouseup", "1"],
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        for name, pin in PINS.items():
            if name in ("KEY2", "KEY3", "OK"):
                continue
            is_down = GPIO.input(pin) == 0
            xkey = key_map.get(name)
            if not xkey:
                continue
            if is_down and name not in pressed_set:
                pressed_set.add(name)
                subprocess.Popen(
                    ["xdotool", "keydown", xkey],
                    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif not is_down and name in pressed_set:
                pressed_set.discard(name)
                subprocess.Popen(
                    ["xdotool", "keyup", xkey],
                    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Mouse control with keyboard for Pingus
        # LEFT/RIGHT also moves mouse cursor
        if "LEFT" in pressed_set or "RIGHT" in pressed_set or "UP" in pressed_set or "DOWN" in pressed_set:
            dx = (-5 if "LEFT" in pressed_set else 0) + (5 if "RIGHT" in pressed_set else 0)
            dy = (-5 if "UP" in pressed_set else 0) + (5 if "DOWN" in pressed_set else 0)
            subprocess.Popen(
                ["xdotool", "mousemove_relative", "--", str(dx), str(dy)],
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        time.sleep(0.02)


def main():
    global _running

    # Check LCD framebuffer
    if not os.path.exists("/dev/fb1"):
        try:
            with open("/proc/fb") as f:
                content = f.read()
            if "st7789v" not in content and "fbtft" not in content:
                _show_msg("CardputerZero only", "No LCD framebuffer", (255, 50, 50))
                time.sleep(3)
                GPIO.cleanup()
                return 1
        except Exception:
            pass

    if not _ensure_deps():
        _show_msg("Install failed", "Check internet", (255, 50, 50))
        time.sleep(3)
        GPIO.cleanup()
        return 1

    try:
        test_fd = os.open(FB_DEVICE, os.O_RDWR)
        os.close(test_fd)
    except Exception:
        _show_msg("No framebuffer", FB_DEVICE, (255, 50, 50))
        time.sleep(3)
        GPIO.cleanup()
        return 1

    _show_msg("LEMMINGS", "Starting...", (0, 255, 100))

    # Start Xvfb with fallback depth
    xvfb = None
    for depth in [24, 16, 8]:
        xvfb = subprocess.Popen(
            ["Xvfb", DISPLAY_NUM, "-screen", "0", f"{GAME_W}x{GAME_H}x{depth}", "-ac", "-nocursor"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        if xvfb.poll() is None:
            break
    if xvfb is None or xvfb.poll() is not None:
        _show_msg("Xvfb failed", "", (255, 50, 50))
        time.sleep(3)
        GPIO.cleanup()
        return 1

    env = os.environ.copy()
    env["DISPLAY"] = DISPLAY_NUM
    env["SDL_VIDEODRIVER"] = "x11"
    env["SDL_AUDIODRIVER"] = "dummy"

    game = subprocess.Popen(
        [PINGUS_BIN, "--window", "--quiet"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    if game.poll() is not None:
        _show_msg("Pingus crashed", "", (255, 50, 50))
        time.sleep(3)
        xvfb.kill()
        GPIO.cleanup()
        return 1

    # Center mouse
    subprocess.run(
        ["xdotool", "mousemove", "--screen", "0", str(GAME_W // 2), str(GAME_H // 2)],
        env=env, capture_output=True)

    capture = subprocess.Popen(
        ["ffmpeg", "-hide_banner", "-loglevel", "quiet",
         "-f", "x11grab", "-framerate", "15",
         "-video_size", f"{GAME_W}x{GAME_H}",
         "-i", DISPLAY_NUM,
         "-vf", f"scale={WIDTH}:{HEIGHT}",
         "-pix_fmt", "rgb565le",
         "-f", "rawvideo", "pipe:1"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=FB_SIZE)

    kt = threading.Thread(target=_key_thread, args=(game,), daemon=True)
    kt.start()

    fb_fd = os.open(FB_DEVICE, os.O_RDWR)
    fb_map = mmap.mmap(fb_fd, FB_SIZE, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)

    try:
        while _running:
            if GPIO.input(PINS["KEY3"]) == 0:
                break
            if game.poll() is not None:
                break
            raw = _read_frame(capture)
            if raw is None:
                break
            fb_map.seek(0)
            fb_map.write(raw)
    finally:
        _running = False
        for p in [capture, game, xvfb]:
            try:
                p.kill()
                p.wait(timeout=2)
            except Exception:
                pass
        try:
            fb_map.close()
            os.close(fb_fd)
        except Exception:
            pass
        subprocess.run(["pkill", "-9", "pingus"], capture_output=True)
        subprocess.run(["pkill", "-9", "Xvfb"], capture_output=True)
        subprocess.run(["pkill", "-9", "ffmpeg"], capture_output=True)
        time.sleep(0.3)
        LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
        LCD.LCD_Clear()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    import traceback
    try:
        raise SystemExit(main())
    except SystemExit:
        pass
    except Exception:
        traceback.print_exc()
