#!/usr/bin/env python3
"""
RaspyJack Payload -- Simon Says memory game
---------------------------------------------
Author: 7h30th3r0n3

Controls: D-pad=input colors, OK=start, KEY1=restart, KEY3=exit
"""
import os, sys, time
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import random
import signal
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._input_helper import get_button

PINS = {"UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16}
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
_GAME_W, _GAME_H = 128, 128
font = ImageFont.load_default()

# Quadrant definitions: (name, button, normal_color, flash_color, rect)
# Layout: top=green, right=blue, bottom=yellow, left=red
# Leave 14px at top for HUD, remaining area 114px split into quadrants
QY = 14
QW, QH = 62, 55
QUADS = {
    "UP":    {"col": (0, 140, 0),   "flash": (200, 255, 200), "rect": (2, QY + 2, 63, QY + 56)},
    "RIGHT": {"col": (0, 0, 180),   "flash": (180, 180, 255), "rect": (65, QY + 2, 126, QY + 56)},
    "DOWN":  {"col": (180, 180, 0), "flash": (255, 255, 200), "rect": (65, QY + 59, 126, QY + 113)},
    "LEFT":  {"col": (180, 0, 0),   "flash": (255, 180, 180), "rect": (2, QY + 59, 63, QY + 113)},
}
QUAD_ORDER = ["UP", "RIGHT", "DOWN", "LEFT"]

COL_BG = (0, 0, 0)
COL_TEXT = (0, 255, 0)
COL_BORDER = (0, 80, 0)

running = True


def cleanup(*_):
    global running
    running = False


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)


def draw_screen(highlight=None, score=0, status="", best=0):
    """Draw the four quadrants, optionally highlighting one."""
    img = Image.new("RGB", (_GAME_W, _GAME_H), COL_BG)
    d = ImageDraw.Draw(img)

    # HUD
    d.text((2, 1), f"Score:{score} Best:{best}", font=font, fill=COL_TEXT)
    if status:
        d.text((90, 1), status, font=font, fill=COL_TEXT)

    for name, q in QUADS.items():
        col = q["flash"] if name == highlight else q["col"]
        r = q["rect"]
        d.rectangle(r, fill=col, outline=COL_BORDER, width=1)
        # Label
        labels = {"UP": "UP", "RIGHT": "RT", "DOWN": "DN", "LEFT": "LT"}
        lx = (r[0] + r[2]) // 2 - 6
        ly = (r[1] + r[3]) // 2 - 4
        d.text((lx, ly), labels[name], font=font,
               fill=(0, 0, 0) if name == highlight else (255, 255, 255))

    if _GAME_W != WIDTH or _GAME_H != HEIGHT:
        img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
    LCD.LCD_ShowImage(img, 0, 0)


def flash_quad(name, score, best, flash_ms=200, pause_ms=300):
    """Flash one quadrant bright then return to normal."""
    draw_screen(highlight=name, score=score, status="WATCH", best=best)
    time.sleep(flash_ms / 1000.0)
    draw_screen(highlight=None, score=score, status="WATCH", best=best)
    time.sleep(pause_ms / 1000.0)


def show_message(msg, score=0, best=0):
    img = Image.new("RGB", (_GAME_W, _GAME_H), COL_BG)
    d = ImageDraw.Draw(img)
    d.text((2, 1), f"Score:{score} Best:{best}", font=font, fill=COL_TEXT)
    for name, q in QUADS.items():
        d.rectangle(q["rect"], fill=q["col"], outline=COL_BORDER, width=1)
    d.rectangle([14, 50, 114, 78], fill=COL_BG, outline=COL_BORDER)
    d.text((18, 56), msg, font=font, fill=COL_TEXT)
    if _GAME_W != WIDTH or _GAME_H != HEIGHT:
        img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
    LCD.LCD_ShowImage(img, 0, 0)


def play():
    global running
    best = 0

    while running:
        sequence = []
        score = 0
        game_active = False

        show_message("OK TO START", score, best)

        # Wait for start
        while running:
            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                cleanup()
                return
            if btn == "OK":
                game_active = True
                time.sleep(0.2)
                break
            time.sleep(0.05)

        while running and game_active:
            # Add new color to sequence
            sequence = sequence + [random.choice(QUAD_ORDER)]
            score = len(sequence) - 1  # rounds completed so far

            # Speed increases every 5 rounds
            rounds = len(sequence)
            flash_ms = max(80, 200 - (rounds // 5) * 25)
            pause_ms = max(120, 300 - (rounds // 5) * 35)

            # Show sequence
            time.sleep(0.5)
            for color in sequence:
                if not running:
                    return
                flash_quad(color, score, best, flash_ms, pause_ms)

            # Player input phase
            draw_screen(score=score, status="GO!", best=best)
            player_idx = 0
            correct = True

            while running and player_idx < len(sequence):
                btn = get_button(PINS, GPIO)
                if btn == "KEY3":
                    cleanup()
                    return
                if btn == "KEY1":
                    time.sleep(0.2)
                    game_active = False
                    correct = False
                    break
                if btn in QUAD_ORDER:
                    # Flash the pressed quad
                    draw_screen(highlight=btn, score=score, status="GO!", best=best)
                    time.sleep(0.15)
                    draw_screen(score=score, status="GO!", best=best)

                    if btn != sequence[player_idx]:
                        correct = False
                        break
                    player_idx += 1
                    time.sleep(0.1)
                time.sleep(0.03)

            if not correct or not running:
                if not game_active:
                    # KEY1 restart
                    break
                # Game over
                final_score = len(sequence) - 1
                best = max(best, final_score)
                show_message(f"GAME OVER! R:{final_score}", final_score, best)

                # Flash all quadrants red briefly
                time.sleep(0.3)
                for name in QUAD_ORDER:
                    draw_screen(highlight=name, score=final_score, best=best)
                    time.sleep(0.1)
                draw_screen(score=final_score, best=best)

                show_message(f"Score:{final_score} OK/K1", final_score, best)
                while running:
                    btn = get_button(PINS, GPIO)
                    if btn == "KEY3":
                        cleanup()
                        return
                    if btn in ("OK", "KEY1"):
                        time.sleep(0.2)
                        break
                    time.sleep(0.05)
                break

            # Round completed successfully
            score = len(sequence)
            best = max(best, score)
            draw_screen(score=score, status="OK!", best=best)
            time.sleep(0.4)


if __name__ == "__main__":
    try:
        play()
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
