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
from payloads._audio_helper import get_audio_card, get_alsa_dev

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


def _ensure_deps():
    """Install missing dependencies. Returns True if all OK."""
    missing = []
    if not os.path.isfile(DOOM_BIN):
        missing.append("chocolate-doom")
    if not _find_wad():
        missing.append("freedoom")
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
    if not os.path.isfile(DOOM_BIN) or not _find_wad():
        _show_msg("Install failed", "Check internet", (255, 50, 50))
        time.sleep(3)
        return False
    return True


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


def _key_thread(doom_proc):
    """Send keypresses to Doom via xdotool on the virtual X display."""
    key_map = {
        "UP": "Up",
        "DOWN": "Down",
        "LEFT": "Left",
        "RIGHT": "Right",
        "OK": "Return",
        "KEY1": "ctrl",
    }
    env = os.environ.copy()
    env["DISPLAY"] = DISPLAY_NUM
    pressed_set = set()
    last_press = {}
    k2_down_time = 0

    while _running and doom_proc.poll() is None:
        now = time.time()

        # KEY2: short press = Space (use/open), long press (>0.5s) = Escape
        k2_down = GPIO.input(PINS["KEY2"]) == 0
        if k2_down and "KEY2" not in pressed_set:
            pressed_set.add("KEY2")
            k2_down_time = now
        elif not k2_down and "KEY2" in pressed_set:
            pressed_set.discard("KEY2")
            held = now - k2_down_time
            key = "Escape" if held > 0.5 else "space"
            subprocess.Popen(
                ["xdotool", "key", key],
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            last_press["KEY2"] = now

        for name, pin in PINS.items():
            if name in ("KEY2", "KEY3"):
                continue
            is_down = GPIO.input(pin) == 0
            xkey = key_map.get(name)
            if not xkey:
                continue
            if is_down and name not in pressed_set:
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

    print(f"[DOOM] FB_DEVICE={FB_DEVICE} exists={os.path.exists(FB_DEVICE)} LCD={WIDTH}x{HEIGHT}")

    if not _ensure_deps():
        print("[DOOM] FAIL: deps missing")
        GPIO.cleanup()
        return 1
    print("[DOOM] deps OK")

    wad = _find_wad()
    print(f"[DOOM] WAD={wad}")

    # Check framebuffer is usable
    try:
        test_fd = os.open(FB_DEVICE, os.O_RDWR)
        os.close(test_fd)
    except Exception as e:
        print(f"[DOOM] FAIL: framebuffer {FB_DEVICE}: {e}")
        _show_msg("No framebuffer", f"{FB_DEVICE} not available", (255, 50, 50))
        time.sleep(3)
        GPIO.cleanup()
        return 1
    print("[DOOM] framebuffer OK")

    _show_msg("DOOM", "Starting...", (255, 50, 0))
    print("[DOOM] starting...")

    # Check LCD framebuffer
    if not os.path.exists("/dev/fb1"):
        try:
            with open("/proc/fb") as f:
                if "st7789v" not in f.read() and "fbtft" not in f.read():
                    _show_msg("CardputerZero only", "No LCD framebuffer", (255, 50, 50))
                    time.sleep(3)
                    GPIO.cleanup()
                    return 1
        except Exception:
            pass

    # DOOM minimum is 320x200, LCD is 320x170
    DOOM_W, DOOM_H = 320, 200

    print("[DOOM] launching Xvfb...")
    xvfb = None
    for depth in [24, 16, 8]:
        xvfb = subprocess.Popen(
            ["Xvfb", DISPLAY_NUM, "-screen", "0", f"{DOOM_W}x{DOOM_H}x{depth}", "-ac", "-nocursor"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        if xvfb.poll() is None:
            print(f"[DOOM] Xvfb OK (depth={depth})")
            break
        print(f"[DOOM] Xvfb depth {depth} failed, trying next...")
    if xvfb is None or xvfb.poll() is not None:
        print("[DOOM] FAIL: Xvfb all depths failed")
        _show_msg("Xvfb failed", "Cannot start display", (255, 50, 50))
        time.sleep(3)
        GPIO.cleanup()
        return 1

    env = os.environ.copy()
    env["DISPLAY"] = DISPLAY_NUM
    env["SDL_VIDEODRIVER"] = "x11"
    env["SDL_VIDEO_WINDOW_POS"] = "0,0"

    subprocess.run(["amixer", "-c", get_audio_card(), "sset", "Headphone", "30"], capture_output=True)
    subprocess.run(["amixer", "-c", get_audio_card(), "sset", "DACL", "160"], capture_output=True)
    subprocess.run(["amixer", "-c", get_audio_card(), "sset", "DACR", "160"], capture_output=True)

    print("[DOOM] launching chocolate-doom...")
    doom = subprocess.Popen(
        [DOOM_BIN, "-iwad", wad, "-nomusic", "-nomouse",
         "-1", "-window", "-geometry", f"{DOOM_W}x{DOOM_H}+0+0"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(2)
    if doom.poll() is not None:
        err = doom.stderr.read(200).decode(errors="replace") if doom.stderr else ""
        print(f"[DOOM] FAIL: chocolate-doom crashed: {err}")
        _show_msg("DOOM crashed", err[:20], (255, 50, 50))
        time.sleep(3)
        xvfb.kill()
        GPIO.cleanup()
        return 1
    print("[DOOM] chocolate-doom running")

    print("[DOOM] hiding cursor...")
    subprocess.run(
        ["xdotool", "mousemove", "--screen", "0", str(DOOM_W + 10), str(DOOM_H + 10)],
        env=env, capture_output=True)
    try:
        subprocess.run(
            ["xsetroot", "-cursor_name", "none"],
            env=env, capture_output=True, timeout=2)
    except Exception:
        pass

    print("[DOOM] launching ffmpeg capture...")
    capture = subprocess.Popen(
        ["ffmpeg", "-hide_banner", "-loglevel", "quiet",
         "-f", "x11grab", "-framerate", "15",
         "-video_size", f"{DOOM_W}x{DOOM_H}",
         "-i", DISPLAY_NUM,
         "-vf", f"scale={WIDTH}:{HEIGHT}",
         "-pix_fmt", "rgb565le",
         "-f", "rawvideo", "pipe:1"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=FB_SIZE)
    print("[DOOM] ffmpeg started")

    print("[DOOM] starting key thread...")
    kt = threading.Thread(target=_key_thread, args=(doom,), daemon=True)
    kt.start()

    print(f"[DOOM] opening framebuffer {FB_DEVICE} (FB_SIZE={FB_SIZE})...")
    try:
        fb_fd = os.open(FB_DEVICE, os.O_RDWR)
        fb_map = mmap.mmap(fb_fd, FB_SIZE, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)
    except Exception as e:
        print(f"[DOOM] FAIL: mmap {FB_DEVICE}: {e}")
        for p in [capture, doom, xvfb]:
            try:
                p.kill()
            except Exception:
                pass
        GPIO.cleanup()
        return 1
    print("[DOOM] framebuffer mmap OK, entering render loop...")

    frame_count = 0
    try:
        while _running:
            btn = None
            for name, pin in PINS.items():
                if GPIO.input(pin) == 0 and name == "KEY3":
                    btn = "KEY3"
            if btn == "KEY3":
                print("[DOOM] KEY3 pressed, exiting")
                break

            if doom.poll() is not None:
                print(f"[DOOM] chocolate-doom exited with code {doom.returncode}")
                break

            raw = _read_frame(capture)
            if raw is None:
                print(f"[DOOM] ffmpeg stream ended after {frame_count} frames")
                if capture.poll() is not None:
                    print(f"[DOOM] ffmpeg exited with code {capture.returncode}")
                break

            fb_map.seek(0)
            fb_map.write(raw)
            frame_count += 1
            if frame_count == 1:
                print("[DOOM] first frame rendered!")

    except Exception as e:
        print(f"[DOOM] render loop error: {e}")
    finally:
        print(f"[DOOM] cleanup after {frame_count} frames")
        _running = False
        for p in [capture, doom, xvfb]:
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
        subprocess.run(["pkill", "-9", "chocolate"], capture_output=True)
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
        input("Press Enter to exit...")
