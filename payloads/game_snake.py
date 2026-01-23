#!/usr/bin/env python3
"""
RaspyJack *payload* example – **Snake Game**
==========================================
Based on the original *Show Buttons* example, this script turns your Waveshare
1.44-inch LCD HAT into a classic *Snake* game!

Features
--------
1. **Joystick & buttons** ­– control the snake with UP / DOWN / LEFT / RIGHT;
   press **KEY3** at any time to quit and return to the RaspyJack menu.
2. **Real-time animation** on the 128 × 128 LCD at ~8 FPS.
3. **Food & scoring** – every bite grows the snake and increments your score.
4. **Game-over detection** – hit a wall or bite yourself and the game ends
   gracefully, offering you to exit (KEY3) or restart (OK).

The code is *heavily commented* so beginners can follow the logic step by step.
"""

# ---------------------------------------------------------------------------
# 0) Ensure local helper modules are importable when launched directly
# ---------------------------------------------------------------------------
import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

# ---------------------------- Standard library ----------------------------
import time
import signal
import random
from typing import List, Tuple, Optional

# ----------------------------- Third-party libs ---------------------------
import RPi.GPIO as GPIO               # Raspberry Pi GPIO access
import LCD_1in44, LCD_Config          # Waveshare driver helpers for the LCD
from PIL import Image, ImageDraw, ImageFont

# ---------------------------------------------------------------------------
# 1) GPIO pin mapping (BCM numbering) – same as in *Show Buttons*
# ---------------------------------------------------------------------------
PINS: dict[str, int] = {
    "UP"   : 6,
    "DOWN" : 19,
    "LEFT" : 5,
    "RIGHT": 26,
    "OK"   : 13,   # joystick centre push → restart after Game Over
    "KEY1" : 21,
    "KEY2" : 20,
    "KEY3" : 16,   # «Back to menu» / quit
}

# ---------------------------------------------------------------------------
# 2) LCD constants & colours
# ---------------------------------------------------------------------------
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128

CELL = 8                      # size of a grid cell in pixels → 16×16 board
GRID_W, GRID_H = WIDTH // CELL, HEIGHT // CELL

COL_BG   = (0, 0, 0)          # black
COL_SNAKE = (0, 255, 0)        # bright green
COL_FOOD  = (255, 0, 0)        # red
COL_TEXT  = (255, 255, 255)    # white

font = ImageFont.load_default()

# ---------------------------------------------------------------------------
# 3) Helper functions – drawing & text utilities
# ---------------------------------------------------------------------------

def grid_to_px(x: int, y: int) -> Tuple[int, int, int, int]:
    """Convert grid coords to an on-screen rectangle bounding box."""
    left   = x * CELL
    top    = y * CELL
    right  = left + CELL
    bottom = top + CELL
    return left, top, right, bottom


def draw_board(snake: List[Tuple[int, int]], food: Tuple[int, int], score: int,
               message: Optional[str] = None) -> None:
    """Render the whole scene and push it to the LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), COL_BG)
    d = ImageDraw.Draw(img)

    # Snake
    for seg_x, seg_y in snake:
        d.rectangle(grid_to_px(seg_x, seg_y), fill=COL_SNAKE)

    # Food
    d.rectangle(grid_to_px(*food), fill=COL_FOOD)

    # Score (top-left)
    d.text((2, 2), f"{score}", font=font, fill=COL_TEXT)

    # Optional centred message (Game Over)
    if message:
        w, h = d.textsize(message, font=font)
        d.text(((WIDTH - w) // 2, (HEIGHT - h) // 2), message,
               font=font, fill=COL_TEXT)

    LCD.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# 4) GPIO initialisation & graceful shutdown handlers
# ---------------------------------------------------------------------------
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

running = True  # global flag → exit main loop when False

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# 5) Game logic helpers
# ---------------------------------------------------------------------------

def random_empty_cell(exclude: List[Tuple[int, int]]) -> Tuple[int, int]:
    """Return random (x, y) not in *exclude*."""
    while True:
        pos = (random.randint(0, GRID_W - 1), random.randint(0, GRID_H - 1))
        if pos not in exclude:
            return pos


def opposite(dir1: Tuple[int, int], dir2: Tuple[int, int]) -> bool:
    """True if dir1 is the exact opposite of dir2."""
    return dir1[0] == -dir2[0] and dir1[1] == -dir2[1]

# ---------------------------------------------------------------------------
# 6) Main game loop – supports restart without quitting the script
# ---------------------------------------------------------------------------

def play() -> None:
    """Single round of Snake. Returns when player quits."""
    # 6.1 – initial game state
    snake: List[Tuple[int, int]] = [(GRID_W // 2, GRID_H // 2)]
    direction = (1, 0)  # moving RIGHT initially
    food = random_empty_cell(snake)
    score = 0

    # 6.2 – frame loop
    while running:
        start_time = time.time()

        # --- Read input ----------------------------------------------------
        pressed: Optional[str] = None
        for name, pin in PINS.items():
            if GPIO.input(pin) == 0:
                pressed = name
                break

        if pressed == "KEY3":            # user wants to quit game & payload
            cleanup()
            return
        elif pressed == "UP" and not opposite(direction, (0, -1)):
            direction = (0, -1)
        elif pressed == "DOWN" and not opposite(direction, (0, 1)):
            direction = (0, 1)
        elif pressed == "LEFT" and not opposite(direction, (-1, 0)):
            direction = (-1, 0)
        elif pressed == "RIGHT" and not opposite(direction, (1, 0)):
            direction = (1, 0)

        # --- Advance snake -----------------------------------------------
        head_x, head_y = snake[0]
        dx, dy = direction
        new_head = (head_x + dx, head_y + dy)

        # Check collisions: walls or self
        if (new_head[0] < 0 or new_head[0] >= GRID_W or
                new_head[1] < 0 or new_head[1] >= GRID_H or
                new_head in snake):
            break  # Game Over

        snake.insert(0, new_head)  # move head

        if new_head == food:       # ate food → grow & new food
            score += 1
            food = random_empty_cell(snake)
        else:
            snake.pop()            # remove tail

        # --- Draw everything --------------------------------------------
        draw_board(snake, food, score)

        # --- Maintain a steady frame-rate (~8 FPS) -----------------------
        elapsed = time.time() - start_time
        time.sleep(max(0, 0.125 - elapsed))

    # ---------------------------------------------------------------------
    # 7) Game Over screen --------------------------------------------------
    # ---------------------------------------------------------------------
    draw_board(snake, food, score, message="Game Over")

    # Wait for OK to restart or KEY3 to quit payload
    while running:
        if GPIO.input(PINS["KEY3"]) == 0:
            cleanup()
            return
        if GPIO.input(PINS["OK"]) == 0:
            time.sleep(0.3)  # simple debounce
            play()           # recursive restart
            return
        time.sleep(0.05)

# ---------------------------------------------------------------------------
# 8) Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        play()
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
