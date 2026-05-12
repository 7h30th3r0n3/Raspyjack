#!/usr/bin/env python3
"""
RaspyJack Payload -- Game Boy Emulator
---------------------------------------
Play Game Boy / Game Boy Color ROMs on the LCD using PyBoy.

Place .gb or .gbc ROM files in /root/Raspyjack/roms/
The emulator renders frames to the LCD at ~20 FPS on Pi Zero 2.

Controls:
  Joystick    : D-pad (Up/Down/Left/Right)
  OK          : A button
  KEY1        : B button
  KEY2        : Start
  KEY3 (hold) : Exit to RaspyJack menu
  KEY3 (tap)  : Select

Requires: pip3 install pyboy

Author: 7h30th3r0n3
"""

import os
import sys
import time
import signal

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button, flush_input

try:
    from pyboy import PyBoy
    PYBOY_OK = True
except ImportError:
    PYBOY_OK = False

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
font = scaled_font()

ROMS_DIR = "/root/Raspyjack/roms"
ROM_EXTENSIONS = (".gb", ".gbc")
KEY3_HOLD_EXIT = 1.0  # seconds to hold KEY3 for exit

# Emulator settings (persisted in roms/.pyboy_settings.json)
SETTINGS_FILE = os.path.join(ROMS_DIR, ".pyboy_settings.json")
SPEED_OPTIONS = [("1x", 1.0), ("1.5x", 1.5), ("2x", 2.0), ("3x", 3.0), ("Turbo", 0)]
_emu_settings = {"speed": 0, "render_skip": 4}  # speed index, render_skip


def _load_settings():
    global _emu_settings
    try:
        import json
        with open(SETTINGS_FILE, "r") as f:
            _emu_settings.update(json.load(f))
    except Exception:
        pass


def _save_settings():
    try:
        import json
        os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
        with open(SETTINGS_FILE, "w") as f:
            json.dump(_emu_settings, f)
    except Exception:
        pass

# Game Boy resolution
GB_W, GB_H = 160, 144

running = True


def _sig(s, f):
    global running
    running = False


signal.signal(signal.SIGTERM, _sig)
signal.signal(signal.SIGINT, _sig)


# ═══════════════════════════════════════════════════════════════
# ROM BROWSER
# ═══════════════════════════════════════════════════════════════
def _list_roms():
    """List .gb/.gbc files in ROMS_DIR."""
    os.makedirs(ROMS_DIR, exist_ok=True)
    roms = []
    for name in sorted(os.listdir(ROMS_DIR)):
        if name.lower().endswith(ROM_EXTENSIONS):
            roms.append(name)
    return roms


def _draw_browser(roms, cursor, scroll):
    """Draw ROM selection screen with Settings as first item."""
    display_list = ["⚙ Settings"] + roms
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 12), fill=(20, 40, 20))
    d.text((2, 1), "GAME BOY", font=font, fill=(0, 200, 0))
    d.text((65, 1), f"{len(roms)} ROMs", font=font, fill=(0, 120, 0))

    if not roms and cursor > 0:
        d.text((4, 30), "No ROMs found!", font=font, fill=(255, 100, 100))
        d.text((4, 45), "Place .gb/.gbc in:", font=font, fill=(150, 150, 150))
        d.text((4, 58), "/root/Raspyjack/", font=font, fill=(0, 200, 0))
        d.text((4, 70), "  roms/", font=font, fill=(0, 200, 0))
        d.text((4, 95), "KEY3 = Exit", font=font, fill=(100, 100, 100))
    else:
        visible = 7
        for i in range(min(visible, len(display_list) - scroll)):
            idx = scroll + i
            y = 16 + i * 14
            is_sel = idx == cursor

            if is_sel:
                d.rectangle((0, y - 1, 127, y + 11), fill=(0, 40, 0))
                d.rectangle((0, y - 1, 2, y + 11), fill=(0, 200, 0))

            item = display_list[idx]
            if idx == 0:
                col = (100, 180, 255) if is_sel else (60, 120, 180)
                d.text((5, y), item[:18], font=font, fill=col)
            else:
                name = item
                display = os.path.splitext(name)[0][:18]
                col = (0, 255, 0) if is_sel else (0, 120, 0)
                d.text((5, y), display, font=font, fill=col)
                if name.lower().endswith(".gbc"):
                    d.text((115, y), "C", font=font, fill=(200, 100, 255))

        if len(display_list) > visible:
            bar_h = max(5, int(100 * visible / len(display_list)))
            bar_y = 16 + int((100 - bar_h) * scroll / max(1, len(display_list) - visible))
            d.rectangle((125, bar_y, 127, bar_y + bar_h), fill=(0, 80, 0))

    # Footer
    d.rectangle((0, 117, 127, 127), fill=(10, 20, 10))
    d.text((2, 118), "OK=Play  K3=Exit", font=font, fill=(0, 80, 0))

    LCD.LCD_ShowImage(img, 0, 0)


def _settings_screen():
    """PyBoy settings menu."""
    _load_settings()
    cursor = 0
    items = [
        ("Speed", "speed", [s[0] for s in SPEED_OPTIONS]),
        ("Frame skip", "render_skip", ["2", "3", "4", "6", "8"]),
    ]
    skip_vals = [2, 3, 4, 6, 8]

    while running:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.rectangle((0, 0, 127, 12), fill=(20, 20, 40))
        d.text((2, 1), "SETTINGS", font=font, fill=(100, 180, 255))

        for i, (label, key, opts) in enumerate(items):
            y = 20 + i * 18
            is_sel = i == cursor
            if is_sel:
                d.rectangle((0, y - 1, 127, y + 13), fill=(0, 30, 60))
            col = (255, 255, 255) if is_sel else (100, 180, 255)

            if key == "speed":
                val_str = SPEED_OPTIONS[_emu_settings.get("speed", 0)][0]
            elif key == "render_skip":
                val_str = str(_emu_settings.get("render_skip", 4))
            else:
                val_str = str(_emu_settings.get(key, "?"))

            d.text((5, y), f"{label}:", font=font, fill=col)
            d.text((75, y), f"< {val_str} >", font=font, fill=(0, 255, 0) if is_sel else (0, 150, 0))

        d.rectangle((0, 117, 127, 127), fill=(10, 10, 20))
        d.text((2, 118), "L/R:Change K3:Back", font=font, fill=(60, 60, 100))
        LCD.LCD_ShowImage(img, 0, 0)

        btn = get_button(PINS, GPIO)
        if btn == "KEY3" or btn == "LEFT":
            _save_settings()
            return
        elif btn == "UP":
            cursor = max(0, cursor - 1)
            time.sleep(0.2)
        elif btn == "DOWN":
            cursor = min(len(items) - 1, cursor + 1)
            time.sleep(0.2)
        elif btn in ("RIGHT", "OK"):
            key = items[cursor][1]
            if key == "speed":
                _emu_settings["speed"] = (_emu_settings.get("speed", 0) + 1) % len(SPEED_OPTIONS)
            elif key == "render_skip":
                cur_idx = skip_vals.index(_emu_settings.get("render_skip", 4)) if _emu_settings.get("render_skip", 4) in skip_vals else 2
                _emu_settings["render_skip"] = skip_vals[(cur_idx + 1) % len(skip_vals)]
            time.sleep(0.25)
        elif btn == "KEY1":
            key = items[cursor][1]
            if key == "speed":
                _emu_settings["speed"] = (_emu_settings.get("speed", 0) - 1) % len(SPEED_OPTIONS)
            elif key == "render_skip":
                cur_idx = skip_vals.index(_emu_settings.get("render_skip", 4)) if _emu_settings.get("render_skip", 4) in skip_vals else 2
                _emu_settings["render_skip"] = skip_vals[(cur_idx - 1) % len(skip_vals)]
            time.sleep(0.25)


def _rom_browser():
    """ROM selection menu. Returns selected ROM path or None."""
    roms = _list_roms()
    cursor = 0
    scroll = 0

    # Prepend Settings entry
    display_list = ["⚙ Settings"] + roms

    while running:
        _draw_browser(roms, cursor, scroll)
        btn = get_button(PINS, GPIO)

        if btn == "KEY3":
            return None
        elif btn == "UP":
            cursor = max(0, cursor - 1)
            if cursor < scroll:
                scroll = cursor
        elif btn == "DOWN":
            cursor = min(len(roms), cursor + 1)
            if cursor >= scroll + 7:
                scroll = cursor - 6
        elif btn == "OK":
            if cursor == 0:
                _settings_screen()
            elif roms:
                return os.path.join(ROMS_DIR, roms[cursor - 1])
        elif btn == "KEY1":
            roms = _list_roms()
            display_list = ["⚙ Settings"] + roms
            cursor = min(cursor, max(0, len(display_list) - 1))

    return None


# ═══════════════════════════════════════════════════════════════
# EMULATOR
# ═══════════════════════════════════════════════════════════════
def _draw_loading(rom_name):
    """Show loading screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((64, 40), "Loading...", font=font, fill=(0, 200, 0), anchor="mm")
    name = os.path.splitext(os.path.basename(rom_name))[0][:16]
    d.text((64, 58), name, font=font, fill=(0, 255, 0), anchor="mm")
    d.text((64, 80), "Please wait", font=font, fill=(0, 100, 0), anchor="mm")
    LCD.LCD_ShowImage(img, 0, 0)


def _read_buttons_noblock():
    """Non-blocking button read. Returns dict of pressed buttons (GPIO + WebUI held)."""
    pressed = {}
    for name, pin in PINS.items():
        if GPIO.input(pin) == 0:
            pressed[name] = True
    # WebUI held buttons (continuous input)
    from payloads._input_helper import get_held_buttons
    for btn in get_held_buttons():
        pressed[btn] = True
    return pressed


def _run_emulator(rom_path):
    """Run the Game Boy emulator."""
    global running

    _draw_loading(rom_path)

    try:
        pyboy = PyBoy(
            rom_path,
            window="null",
            sound_emulated=False,
            log_level="ERROR",
        )
    except Exception as e:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((64, 40), "Load Error!", font=font, fill=(255, 0, 0), anchor="mm")
        d.text((4, 60), str(e)[:22], font=font, fill=(200, 200, 200))
        d.text((4, 75), str(e)[22:44], font=font, fill=(150, 150, 150))
        d.text((64, 100), "KEY3 = Back", font=font, fill=(100, 100, 100), anchor="mm")
        LCD.LCD_ShowImage(img, 0, 0)
        while running:
            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                return
        return

    frame_count = 0
    _load_settings()
    speed_idx = _emu_settings.get("speed", 0)
    speed_mult = SPEED_OPTIONS[min(speed_idx, len(SPEED_OPTIONS) - 1)][1]
    RENDER_EVERY = _emu_settings.get("render_skip", 4)
    GB_FPS = 59.7
    if speed_mult > 0:
        frame_target = 1.0 / (GB_FPS * speed_mult)
    else:
        frame_target = 0  # turbo - no limit

    # Pre-allocate canvas for LCD output
    _canvas = Image.new("RGB", (WIDTH, HEIGHT), (0, 0, 0))

    # Display mode depends on screen size
    _mode = "scale"
    _ratio = min(WIDTH / GB_W, HEIGHT / GB_H)
    _sw, _sh = int(GB_W * _ratio), int(GB_H * _ratio)
    _ox, _oy = (WIDTH - _sw) // 2, (HEIGHT - _sh) // 2
    # Use LANCZOS for downscale (128), NEAREST for upscale (240)
    _resample = Image.NEAREST if _ratio >= 1.0 else Image.LANCZOS

    # Button mapping: RaspyJack -> Game Boy
    # OK=A, KEY1=B, KEY2=Start, KEY3(tap)=Select, KEY3(hold)=Exit
    GB_MAP = {
        "UP": "up",
        "DOWN": "down",
        "LEFT": "left",
        "RIGHT": "right",
        "OK": "a",
        "KEY1": "b",
        "KEY2": "start",
    }

    try:
        while running:
            t0 = time.time()

            # Read physical buttons (non-blocking)
            pressed = _read_buttons_noblock()

            # KEY3 = exit, KEY2 = start + select combo
            if "KEY3" in pressed:
                break

            # Send mapped buttons to PyBoy
            for rj_btn, gb_btn in GB_MAP.items():
                if rj_btn in pressed:
                    pyboy.button_press(gb_btn)
                else:
                    pyboy.button_release(gb_btn)

            # Tick emulator (run 2 frames per loop for speed)
            render_this = (frame_count % RENDER_EVERY == 0)
            pyboy.tick(count=1, render=render_this)
            frame_count += 1

            # Only push to LCD every Nth frame
            if render_this:
                gb_img = pyboy.screen.image
                scaled = gb_img.resize((_sw, _sh), _resample)
                _canvas.paste((0, 0, 0), (0, 0, WIDTH, HEIGHT))
                _canvas.paste(scaled, (_ox, _oy))
                LCD.LCD_ShowImage(_canvas, 0, 0)

            # Frame timing
            if frame_target > 0:
                elapsed = time.time() - t0
                if elapsed < frame_target:
                    time.sleep(frame_target - elapsed)

    finally:
        try:
            pyboy.stop(save=True)
        except Exception:
            pass
        # Flush all input state to prevent KEY3 from propagating to browser
        flush_input()
        time.sleep(0.5)
        flush_input()


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════
def _auto_install():
    """Try to install PyBoy automatically."""
    import subprocess
    install_script = "/root/Raspyjack/scripts/install_pyboy.sh"

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((64, 30), "PyBoy not found", font=font, fill=(255, 200, 0), anchor="mm")
    d.text((64, 50), "Installing...", font=font, fill=(0, 200, 0), anchor="mm")
    d.text((64, 70), "Please wait", font=font, fill=(100, 100, 100), anchor="mm")
    LCD.LCD_ShowImage(img, 0, 0)

    try:
        result = subprocess.run(
            ["sudo", "bash", install_script],
            capture_output=True, text=True, timeout=120,
        )
        # Test if it worked
        subprocess.run(
            ["python3", "-c", "from pyboy import PyBoy"],
            capture_output=True, timeout=10,
        )
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((64, 50), "Installed!", font=font, fill=(0, 255, 0), anchor="mm")
        d.text((64, 70), "Restarting...", font=font, fill=(100, 100, 100), anchor="mm")
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(2)
        return True
    except Exception as e:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((64, 30), "Install failed", font=font, fill=(255, 0, 0), anchor="mm")
        d.text((4, 50), str(e)[:22], font=font, fill=(200, 200, 200))
        d.text((64, 80), "Run manually:", font=font, fill=(150, 150, 150), anchor="mm")
        d.text((64, 95), "sudo bash scripts/", font=font, fill=(0, 200, 0), anchor="mm")
        d.text((64, 107), "install_pyboy.sh", font=font, fill=(0, 200, 0), anchor="mm")
        LCD.LCD_ShowImage(img, 0, 0)
        while True:
            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                break
        return False


def main():
    global PYBOY_OK

    if not PYBOY_OK:
        if _auto_install():
            # Re-import after install
            try:
                from pyboy import PyBoy as _PB
                PYBOY_OK = True
            except ImportError:
                GPIO.cleanup()
                return 0
        else:
            GPIO.cleanup()
            return 0

    try:
        while running:
            rom = _rom_browser()
            if rom is None:
                break
            _run_emulator(rom)
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
