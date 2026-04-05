#!/usr/bin/env python3
"""
RaspyJack Payload -- Flappy Bird Clone
----------------------------------------
Author: 7h30th3r0n3

Flappy bird on the LCD. Green-on-black theme.

Controls:
  OK / KEY1  = flap (impulse upward)
  KEY3       = exit
"""

import os
import sys
import time
import random

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
_GAME_W, _GAME_H = 128, 128  # internal render resolution
font = ImageFont.load_default()

# Colors (green/black theme)
COL_BG = (0, 0, 0)
COL_BIRD = (0, 255, 0)
COL_PIPE = (0, 180, 0)
COL_PIPE_EDGE = (0, 100, 0)
COL_GROUND = (0, 60, 0)
COL_SCORE = (0, 255, 0)
COL_TEXT = (0, 255, 0)
COL_DIM = (0, 120, 0)

# Game constants
BIRD_X = 20
BIRD_SIZE = 6
GRAVITY = 0.45
FLAP_IMPULSE = -4.5
MAX_FALL = 5.0
PIPE_WIDTH = 14
PIPE_GAP = 38
PIPE_SPEED = 1.5
PIPE_SPACING = 55
GROUND_Y = 120
FPS = 30
FRAME_DELAY = 1.0 / FPS


def _create_pipe(x_pos):
    """Create a pipe dict with random gap position."""
    min_top = 20
    max_top = GROUND_Y - PIPE_GAP - 15
    gap_top = random.randint(min_top, max_top)
    return {"x": float(x_pos), "gap_top": gap_top}


def _create_initial_state():
    """Create a fresh game state."""
    return {
        "bird_y": float(_GAME_H // 2),
        "bird_vy": 0.0,
        "pipes": [
            _create_pipe(_GAME_W + 20),
            _create_pipe(_GAME_W + 20 + PIPE_SPACING),
            _create_pipe(_GAME_W + 20 + PIPE_SPACING * 2),
        ],
        "score": 0,
        "alive": True,
        "started": False,
        "scored_pipes": set(),
    }


def _check_collision(state):
    """Check if bird collides with any pipe or boundary."""
    by = state["bird_y"]

    # Ground or ceiling
    if by <= 0 or by + BIRD_SIZE >= GROUND_Y:
        return True

    # Pipe collision
    for pipe in state["pipes"]:
        px = pipe["x"]
        if BIRD_X + BIRD_SIZE > px and BIRD_X < px + PIPE_WIDTH:
            if by < pipe["gap_top"] or by + BIRD_SIZE > pipe["gap_top"] + PIPE_GAP:
                return True

    return False


def _update_state(state):
    """Update game physics for one frame. Returns new state."""
    if not state["alive"] or not state["started"]:
        return state

    new_vy = min(state["bird_vy"] + GRAVITY, MAX_FALL)
    new_by = state["bird_y"] + new_vy

    new_pipes = []
    new_score = state["score"]
    new_scored = set(state["scored_pipes"])

    for i, pipe in enumerate(state["pipes"]):
        new_x = pipe["x"] - PIPE_SPEED
        if new_x + PIPE_WIDTH < 0:
            rightmost = max(p["x"] for p in state["pipes"])
            new_pipe = _create_pipe(rightmost + PIPE_SPACING)
            new_pipes.append(new_pipe)
        else:
            new_pipes.append({"x": new_x, "gap_top": pipe["gap_top"]})
            if new_x + PIPE_WIDTH < BIRD_X and i not in new_scored:
                new_score += 1
                new_scored = new_scored | {i}

    updated = {
        "bird_y": new_by,
        "bird_vy": new_vy,
        "pipes": new_pipes,
        "score": new_score,
        "alive": True,
        "started": True,
        "scored_pipes": new_scored,
    }

    if _check_collision(updated):
        return {**updated, "alive": False}

    return updated


def _draw_game(lcd, state):
    """Render game state to LCD."""
    img = Image.new("RGB", (_GAME_W, _GAME_H), COL_BG)
    d = ImageDraw.Draw(img)

    # Ground
    d.rectangle((0, GROUND_Y, _GAME_W, _GAME_H), fill=COL_GROUND)

    # Pipes
    for pipe in state["pipes"]:
        px = int(pipe["x"])
        gap_top = pipe["gap_top"]
        gap_bottom = gap_top + PIPE_GAP

        # Top pipe
        if gap_top > 0:
            d.rectangle((px, 0, px + PIPE_WIDTH, gap_top), fill=COL_PIPE)
            d.rectangle((px, 0, px + 1, gap_top), fill=COL_PIPE_EDGE)
            d.rectangle((px + PIPE_WIDTH - 1, 0, px + PIPE_WIDTH, gap_top), fill=COL_PIPE_EDGE)
            # Lip
            d.rectangle((px - 2, gap_top - 4, px + PIPE_WIDTH + 2, gap_top), fill=COL_PIPE)

        # Bottom pipe
        if gap_bottom < GROUND_Y:
            d.rectangle((px, gap_bottom, px + PIPE_WIDTH, GROUND_Y), fill=COL_PIPE)
            d.rectangle((px, gap_bottom, px + 1, GROUND_Y), fill=COL_PIPE_EDGE)
            d.rectangle((px + PIPE_WIDTH - 1, gap_bottom, px + PIPE_WIDTH, GROUND_Y), fill=COL_PIPE_EDGE)
            # Lip
            d.rectangle((px - 2, gap_bottom, px + PIPE_WIDTH + 2, gap_bottom + 4), fill=COL_PIPE)

    # Bird
    by = int(state["bird_y"])
    d.rectangle(
        (BIRD_X, by, BIRD_X + BIRD_SIZE, by + BIRD_SIZE),
        fill=COL_BIRD,
    )
    # Eye
    d.point((BIRD_X + BIRD_SIZE - 1, by + 1), fill=COL_BG)

    # Score
    score_str = str(state["score"])
    d.text((_GAME_W // 2 - 4, 4), score_str, font=font, fill=COL_SCORE)

    # Start screen
    if not state["started"] and state["alive"]:
        d.text((25, 40), "FLAPPY BIRD", font=font, fill=COL_TEXT)
        d.text((22, 58), "OK/K1 to flap", font=font, fill=COL_DIM)
        d.text((30, 73), "K3 to exit", font=font, fill=COL_DIM)

    # Game over screen
    if not state["alive"]:
        d.rectangle((15, 35, 113, 95), fill=(0, 20, 0))
        d.rectangle((15, 35, 113, 36), fill=COL_TEXT)
        d.rectangle((15, 94, 113, 95), fill=COL_TEXT)

        d.text((32, 40), "GAME OVER", font=font, fill=COL_TEXT)
        d.text((40, 56), f"Score: {state['score']}", font=font, fill=COL_SCORE)
        d.text((25, 74), "OK=retry K3=quit", font=font, fill=COL_DIM)

    if _GAME_W != WIDTH or _GAME_H != HEIGHT:
        img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
    lcd.LCD_ShowImage(img, 0, 0)


def main():
    """Main entry point."""
    state = _create_initial_state()

    try:
        while True:
            frame_start = time.time()
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            if not state["alive"]:
                if btn == "OK" or btn == "KEY1":
                    state = _create_initial_state()
                _draw_game(LCD, state)
                elapsed = time.time() - frame_start
                if FRAME_DELAY - elapsed > 0:
                    time.sleep(FRAME_DELAY - elapsed)
                continue

            if btn == "OK" or btn == "KEY1":
                if not state["started"]:
                    state = {**state, "started": True, "bird_vy": FLAP_IMPULSE}
                else:
                    state = {**state, "bird_vy": FLAP_IMPULSE}

            state = _update_state(state)
            _draw_game(LCD, state)

            elapsed = time.time() - frame_start
            remaining = FRAME_DELAY - elapsed
            if remaining > 0:
                time.sleep(remaining)

    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
