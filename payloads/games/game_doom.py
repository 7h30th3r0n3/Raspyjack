#!/usr/bin/env python3

import json
import os
import subprocess
import sys
import time

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6,
    "DOWN": 19,
    "LEFT": 5,
    "RIGHT": 26,
    "OK": 13,
    "KEY1": 21,
    "KEY2": 20,
    "KEY3": 16,
}

GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
FONT = scaled_font()
ROOT_DIR = os.path.abspath(os.path.join(__file__, "..", "..", ".."))
DOOM_DIR = os.path.join(ROOT_DIR, "payloads", "games", "doom")
GUI_CONF = os.path.join(ROOT_DIR, "gui_conf.json")


def draw_lines(lines):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    draw = ScaledDraw(img)
    y = 4
    for line in lines:
        draw.text((4, y), line[:22], font=FONT, fill="white")
        y += 12
    LCD.LCD_ShowImage(img, 0, 0)


def wait_for_exit(lines):
    draw_lines(lines + ["", "KEY3 = exit"])
    while True:
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            return
        time.sleep(0.05)


def get_display_type():
    try:
        with open(GUI_CONF, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return str(data.get("DISPLAY", {}).get("type") or "ST7735_128")
    except Exception:
        return "ST7735_128"


def resolve_binary():
    candidates = [
        os.path.join(DOOM_DIR, "build", "doom_raspyjack"),
        os.path.join(DOOM_DIR, "doom_raspyjack"),
    ]
    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return ""


def resolve_wad():
    env_wad = str(os.environ.get("RJ_DOOM_WAD") or "").strip()
    if env_wad and os.path.isfile(env_wad):
        return env_wad

    candidates = [
        os.path.join(DOOM_DIR, "wads", "doom1.wad"),
        os.path.join(DOOM_DIR, "wads", "doom.wad"),
        os.path.join(DOOM_DIR, "wads", "freedoom1.wad"),
        os.path.join(DOOM_DIR, "wads", "freedoom2.wad"),
        "/usr/share/games/doom/doom1.wad",
        "/usr/share/games/doom/doom.wad",
        "/usr/share/games/freedoom/freedoom1.wad",
        "/usr/share/games/freedoom/freedoom2.wad",
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return ""


def build_command(binary_path, wad_path, display_type):
    command = [binary_path, "--wad", wad_path, "--display", display_type]
    render_scale = "2" if display_type == "ST7789_240" else "1"
    command.extend(["--scale", render_scale])
    return command


def main():
    binary_path = resolve_binary()
    if not binary_path:
        wait_for_exit([
            "Doom binary missing",
            "Run build.sh in",
            "payloads/games/doom",
        ])
        return

    wad_path = resolve_wad()
    if not wad_path:
        wait_for_exit([
            "No WAD found",
            "Add doom1.wad or",
            "Freedoom to wads/",
        ])
        return

    display_type = get_display_type()
    wad_name = os.path.basename(wad_path)
    draw_lines([
        "Launching Doom",
        wad_name,
        display_type,
    ])
    time.sleep(0.5)

    env = os.environ.copy()
    env.setdefault("RJ_DOOM_ROOT", DOOM_DIR)
    env.setdefault("RJ_DOOM_WAD", wad_path)
    subprocess.run(build_command(binary_path, wad_path, display_type), cwd=DOOM_DIR, env=env, check=False)

    LCD.LCD_Clear()
    GPIO.cleanup()


if __name__ == "__main__":
    main()