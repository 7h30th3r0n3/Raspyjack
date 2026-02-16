#!/usr/bin/env python3
"""
RaspyJack Payload - Conway's Game of Life
----------------------------------------
Controls:
- OK / RIGHT : Pause/Run toggle
- UP/DOWN/LEFT/RIGHT (paused): Move cursor
- KEY1       : Randomize world
- KEY2       : Toggle cell at cursor (paused) / Clear world (running)
- KEY3       : Exit
"""

import os
import sys
import time
import random

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

import RPi.GPIO as GPIO  # type: ignore
import LCD_1in44, LCD_Config  # type: ignore
from PIL import Image, ImageDraw, ImageFont  # type: ignore

from payloads._input_helper import get_button

WIDTH, HEIGHT = 128, 128
FONT = ImageFont.load_default()

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

CELL = 5
COLS = 24
ROWS = 22
GRID_X = 4
GRID_Y = 14


def lcd_init():
    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    return lcd


def make_grid(fill=0):
    return [[fill for _ in range(COLS)] for _ in range(ROWS)]


def randomize_grid(grid, density=0.26):
    for y in range(ROWS):
        for x in range(COLS):
            grid[y][x] = 1 if random.random() < density else 0


def step(grid):
    nxt = make_grid(0)
    alive = 0

    for y in range(ROWS):
        y0 = max(0, y - 1)
        y1 = min(ROWS - 1, y + 1)
        for x in range(COLS):
            x0 = max(0, x - 1)
            x1 = min(COLS - 1, x + 1)

            n = 0
            for yy in range(y0, y1 + 1):
                for xx in range(x0, x1 + 1):
                    if xx == x and yy == y:
                        continue
                    n += grid[yy][xx]

            if grid[y][x] == 1:
                nxt[y][x] = 1 if n in (2, 3) else 0
            else:
                nxt[y][x] = 1 if n == 3 else 0

            alive += nxt[y][x]

    return nxt, alive


def draw(lcd, grid, running, gen, alive, cx, cy):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)

    # Header
    d.rectangle((0, 0, 127, 12), fill="#121212")
    state = "RUN" if running else "PAUSE"
    d.text((3, 2), f"LIFE {state}", font=FONT, fill="#86efac" if running else "#facc15")
    d.text((70, 2), f"G:{gen:03d}", font=FONT, fill="#cbd5e1")

    # Grid
    for y in range(ROWS):
        py = GRID_Y + y * CELL
        for x in range(COLS):
            px = GRID_X + x * CELL
            if grid[y][x]:
                d.rectangle((px, py, px + CELL - 1, py + CELL - 1), fill="#34d399")
            else:
                d.rectangle((px, py, px + CELL - 1, py + CELL - 1), fill="#0b1220")

    # Cursor only in pause
    if not running:
        px = GRID_X + cx * CELL
        py = GRID_Y + cy * CELL
        d.rectangle((px, py, px + CELL - 1, py + CELL - 1), outline="#fbbf24", width=1)

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#101010")
    d.text((3, 118), f"A:{alive:03d}", font=FONT, fill="#93c5fd")
    d.text((48, 118), "K1 rnd", font=FONT, fill="#94a3b8")
    d.text((92, 118), "K3 x", font=FONT, fill="#94a3b8")

    lcd.LCD_ShowImage(img, 0, 0)


def debounce():
    time.sleep(0.12)


def main():
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = lcd_init()

    grid = make_grid(0)
    randomize_grid(grid)

    running = True
    generation = 0
    alive = sum(sum(row) for row in grid)
    cursor_x, cursor_y = COLS // 2, ROWS // 2

    last_tick = time.time()
    tick_delay = 0.12

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            if btn in ("OK", "RIGHT"):
                running = not running
                debounce()

            elif btn == "KEY1":
                randomize_grid(grid)
                generation = 0
                alive = sum(sum(row) for row in grid)
                debounce()

            elif btn == "KEY2":
                if running:
                    grid = make_grid(0)
                    generation = 0
                    alive = 0
                else:
                    grid[cursor_y][cursor_x] = 0 if grid[cursor_y][cursor_x] else 1
                    alive = sum(sum(row) for row in grid)
                debounce()

            elif not running and btn in ("UP", "DOWN", "LEFT", "RIGHT"):
                if btn == "UP":
                    cursor_y = (cursor_y - 1) % ROWS
                elif btn == "DOWN":
                    cursor_y = (cursor_y + 1) % ROWS
                elif btn == "LEFT":
                    cursor_x = (cursor_x - 1) % COLS
                elif btn == "RIGHT":
                    cursor_x = (cursor_x + 1) % COLS
                debounce()

            now = time.time()
            if running and (now - last_tick) >= tick_delay:
                grid, alive = step(grid)
                generation += 1
                last_tick = now

            draw(lcd, grid, running, generation, alive, cursor_x, cursor_y)
            time.sleep(0.02)

    finally:
        lcd.LCD_Clear()
        GPIO.cleanup()


if __name__ == "__main__":
    main()
