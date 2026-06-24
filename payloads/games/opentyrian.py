#!/usr/bin/env python3
"""
RaspyJack Payload -- OpenTyrian
=================================
Author: 7h30th3r0n3

Classic vertical shoot'em up on CardputerZero LCD.
Runs on Xvfb, captures via ffmpeg x11grab to framebuffer.

Controls:
  Arrows      Move ship
  OK/Enter    Select
  KEY1/Space  Fire
  KEY3        Quit
"""

import os, sys, time, signal, subprocess, mmap, threading
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {"UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16}
GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)
for p in PINS.values():
    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
W, H = LCD.width, LCD.height
font = scaled_font(9)
font_sm = scaled_font(7)

FB_DEVICE = "/dev/fb1" if os.path.exists("/dev/fb1") else "/dev/fb0"
FB_SIZE = W * H * 2
DISPLAY_NUM = ":97"
GAME_BIN = "/usr/games/opentyrian"
GAME_W, GAME_H = 320, 200
_running = True


def _sig(s, f):
    global _running
    _running = False

signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _show_msg(text, sub="", color=(0, 200, 255)):
    img = Image.new("RGB", (W, H), "black")
    d = ScaledDraw(img)
    try:
        d.text((W // 2, H // 2 - 10), text, font=font, fill=color, anchor="mm")
    except Exception:
        d.text((10, H // 2 - 10), text, font=font, fill=color)
    if sub:
        try:
            d.text((W // 2, H // 2 + 10), sub, font=font_sm, fill=(150, 150, 150), anchor="mm")
        except Exception:
            d.text((10, H // 2 + 10), sub, font=font_sm, fill=(150, 150, 150))
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
    if not os.path.isfile(GAME_BIN):
        missing.append("opentyrian")
    if not os.path.isfile("/usr/bin/Xvfb"):
        missing.append("xvfb")
    if not os.path.isfile("/usr/bin/xdotool"):
        missing.append("xdotool")
    if missing:
        _show_msg("Installing...", " ".join(missing), (255, 180, 0))
        subprocess.run(["apt-get", "install", "-y"] + missing, capture_output=True, timeout=180)
    if not os.path.isfile(GAME_BIN):
        return False
    data_dir = "/usr/share/games/opentyrian/data"
    if not os.path.isdir(data_dir) or not os.path.isfile(os.path.join(data_dir, "palette.dat")):
        _show_msg("Getting game data...", "Please wait", (255, 180, 0))
        subprocess.run(["apt-get", "install", "-y", "game-data-packager"],
                       capture_output=True, timeout=120)
        subprocess.run(["game-data-packager", "tyrian", "--install"],
                       capture_output=True, timeout=120)
        if not os.path.isdir(data_dir):
            tyrian_url = "https://camanis.net/tyrian/tyrian21.zip"
            dl_dir = "/tmp/tyrian_data"
            os.makedirs(dl_dir, exist_ok=True)
            subprocess.run(["wget", "-q", "-O", f"{dl_dir}/tyrian21.zip", tyrian_url],
                           capture_output=True, timeout=60)
            subprocess.run(["unzip", "-o", "-q", f"{dl_dir}/tyrian21.zip", "-d", dl_dir],
                           capture_output=True, timeout=30)
            os.makedirs(data_dir, exist_ok=True)
            subprocess.run(["cp", "-r"] + [f for f in [f"{dl_dir}/tyrian21/{f}" for f in os.listdir(f"{dl_dir}/tyrian21")] if os.path.isfile(f)] + [data_dir],
                           capture_output=True, timeout=30)
    return os.path.isfile(GAME_BIN)


def _key_thread(game_proc):
    key_map = {"UP": "Up", "DOWN": "Down", "LEFT": "Left", "RIGHT": "Right", "OK": "Return", "KEY1": "space"}
    env = os.environ.copy()
    env["DISPLAY"] = DISPLAY_NUM
    pressed = set()
    while _running and game_proc.poll() is None:
        for name, pin in PINS.items():
            if name in ("KEY2", "KEY3"):
                continue
            down = GPIO.input(pin) == 0
            xkey = key_map.get(name)
            if not xkey:
                continue
            if down and name not in pressed:
                pressed.add(name)
                subprocess.Popen(["xdotool", "keydown", xkey], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif not down and name in pressed:
                pressed.discard(name)
                subprocess.Popen(["xdotool", "keyup", xkey], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
        _show_msg("Install failed", "", (255, 50, 50)); time.sleep(3); GPIO.cleanup(); return 1
    try:
        os.open(FB_DEVICE, os.O_RDWR)
    except Exception:
        _show_msg("No framebuffer", "", (255, 50, 50)); time.sleep(3); GPIO.cleanup(); return 1

    _show_msg("OpenTyrian", "Starting...", (255, 200, 0))

    xvfb = None
    for depth in [24, 16, 8]:
        xvfb = subprocess.Popen(["Xvfb", DISPLAY_NUM, "-screen", "0", f"{GAME_W}x{GAME_H}x{depth}", "-ac", "-nocursor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        if xvfb.poll() is None:
            break
    if xvfb is None or xvfb.poll() is not None:
        _show_msg("Xvfb failed", "", (255, 50, 50)); time.sleep(3); GPIO.cleanup(); return 1

    env = os.environ.copy()
    env["DISPLAY"] = DISPLAY_NUM
    env["SDL_VIDEODRIVER"] = "x11"
    env["SDL_AUDIODRIVER"] = "dummy"

    data_dir = "/usr/share/games/opentyrian/data"
    cmd = [GAME_BIN]
    if os.path.isdir(data_dir):
        cmd += ["-t", data_dir]
    game = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    if game.poll() is not None:
        _show_msg("Game crashed", "", (255, 50, 50)); time.sleep(3); xvfb.kill(); GPIO.cleanup(); return 1

    capture = subprocess.Popen(
        ["ffmpeg", "-hide_banner", "-loglevel", "quiet", "-f", "x11grab", "-framerate", "15",
         "-video_size", f"{GAME_W}x{GAME_H}", "-i", DISPLAY_NUM,
         "-vf", f"scale={W}:{H}", "-pix_fmt", "rgb565le", "-f", "rawvideo", "pipe:1"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=FB_SIZE)

    threading.Thread(target=_key_thread, args=(game,), daemon=True).start()
    fb_fd = os.open(FB_DEVICE, os.O_RDWR)
    fb_map = mmap.mmap(fb_fd, FB_SIZE, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)

    try:
        while _running:
            if GPIO.input(PINS["KEY3"]) == 0 or game.poll() is not None:
                break
            raw = _read_frame(capture)
            if raw is None:
                break
            fb_map.seek(0)
            fb_map.write(raw)
    finally:
        _running = False
        for p in [capture, game, xvfb]:
            try: p.kill(); p.wait(timeout=2)
            except Exception: pass
        try: fb_map.close(); os.close(fb_fd)
        except Exception: pass
        subprocess.run(["pkill", "-9", "opentyrian"], capture_output=True)
        subprocess.run(["pkill", "-9", "Xvfb"], capture_output=True)
        subprocess.run(["pkill", "-9", "ffmpeg"], capture_output=True)
        time.sleep(0.3); LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT); LCD.LCD_Clear(); GPIO.cleanup()
    return 0

if __name__ == "__main__":
    import traceback
    try: raise SystemExit(main())
    except SystemExit: pass
    except Exception: traceback.print_exc()
