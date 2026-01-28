 #!/usr/bin/env python3
"""
RaspyJack Payload – 2048 (4x4)
------------------------------
Controls:
- UP/DOWN/LEFT/RIGHT: move
- KEY1: new game
- KEY3: exit
"""

import os
import sys
import time
import random

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

import RPi.GPIO as GPIO  # type: ignore
import LCD_1in44, LCD_Config  # type: ignore
from PIL import Image, ImageDraw, ImageFont  # type: ignore

WIDTH, HEIGHT = 128, 128
KEY_UP = 6
KEY_DOWN = 19
KEY_LEFT = 5
KEY_RIGHT = 26
KEY_PRESS = 13
KEY1 = 21
KEY3 = 16

GRID = 4


def lcd_init():
    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    return lcd


def _tile_color(val):
    palette = {
        0:  "#222222",
        2:  "#3a3a3a",
        4:  "#4a4a4a",
        8:  "#5a4a3a",
        16: "#6a4a2a",
        32: "#7a3a2a",
        64: "#8a2a2a",
        128:"#7a5a2a",
        256:"#6a6a2a",
        512:"#4a7a2a",
        1024:"#2a7a4a",
        2048:"#2a7a7a",
    }
    return palette.get(val, "#2a6a7a")


def draw_board(lcd, board, score):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    font = ImageFont.load_default()

    d.rectangle((0, 0, 127, 12), fill="#1a1a1a")
    d.text((4, 1), "2048", font=font, fill="white")
    d.text((78, 1), f"S:{score}", font=font, fill="white")

    cell = 28
    offset_x = 2
    offset_y = 14

    for r in range(GRID):
        for c in range(GRID):
            x0 = offset_x + c * cell
            y0 = offset_y + r * cell
            x1 = x0 + cell - 2
            y1 = y0 + cell - 2
            val = board[r][c]
            base_color = _tile_color(val)
            color = base_color
            text_color = "white"
            d.rectangle((x0, y0, x1, y1), fill=color, outline="#555555")
            if val:
                txt = str(val)
                if hasattr(d, "textbbox"):
                    x0b, y0b, x1b, y1b = d.textbbox((0, 0), txt, font=font)
                    w, h = x1b - x0b, y1b - y0b
                else:
                    w, h = font.getsize(txt)
                d.text((x0 + (cell - w) // 2, y0 + (cell - h) // 2), txt, font=font, fill=text_color)

    lcd.LCD_ShowImage(img, 0, 0)


def new_board():
    b = [[0] * GRID for _ in range(GRID)]
    add_random_tile(b)
    add_random_tile(b)
    return b


def add_random_tile(board):
    empties = [(r, c) for r in range(GRID) for c in range(GRID) if board[r][c] == 0]
    if not empties:
        return
    r, c = random.choice(empties)
    board[r][c] = 4 if random.random() < 0.1 else 2


def compress(line):
    new = [v for v in line if v != 0]
    new += [0] * (GRID - len(new))
    return new


def merge(line):
    score = 0
    for i in range(GRID - 1):
        if line[i] != 0 and line[i] == line[i + 1]:
            line[i] *= 2
            line[i + 1] = 0
            score += line[i]
    return line, score


def move_left(board):
    moved = False
    score = 0
    new_board = []
    for row in board:
        comp = compress(row)
        merged, sc = merge(comp)
        comp2 = compress(merged)
        if comp2 != row:
            moved = True
        new_board.append(comp2)
        score += sc
    return new_board, moved, score


def rotate(board):
    return [list(reversed(col)) for col in zip(*board)]


def move(board, direction):
    # 0:left, 1:up, 2:right, 3:down
    b = [row[:] for row in board]
    score = 0
    moved = False

    if direction == 0:
        b, moved, score = move_left(b)
    elif direction == 1:
        b = rotate(b)
        b, moved, score = move_left(b)
        b = rotate(rotate(rotate(b)))
    elif direction == 2:
        b = rotate(rotate(b))
        b, moved, score = move_left(b)
        b = rotate(rotate(b))
    elif direction == 3:
        b = rotate(rotate(rotate(b)))
        b, moved, score = move_left(b)
        b = rotate(b)

    return b, moved, score


def can_move(board):
    for r in range(GRID):
        for c in range(GRID):
            if board[r][c] == 0:
                return True
            if c + 1 < GRID and board[r][c] == board[r][c + 1]:
                return True
            if r + 1 < GRID and board[r][c] == board[r + 1][c]:
                return True
    return False


def main():
    lcd = lcd_init()
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(KEY_UP, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(KEY_DOWN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(KEY_LEFT, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(KEY_RIGHT, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(KEY_PRESS, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(KEY1, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(KEY3, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    board = new_board()
    score = 0
    draw_board(lcd, board, score)

    try:
        while True:
            if GPIO.input(KEY3) == 0:
                break
            if GPIO.input(KEY1) == 0:
                board = new_board()
                score = 0
                draw_board(lcd, board, score)
                time.sleep(0.2)
                continue

            direction = None
            # Standard controls
            # Standard mapping
            if GPIO.input(KEY_LEFT) == 0:
                direction = 0  # left
            elif GPIO.input(KEY_RIGHT) == 0:
                direction = 2  # right
            elif GPIO.input(KEY_UP) == 0:
                direction = 3  # invert up/down
            elif GPIO.input(KEY_DOWN) == 0:
                direction = 1  # invert up/down

            if direction is not None:
                newb, moved, sc = move(board, direction)
                if moved:
                    board = newb
                    score += sc
                    add_random_tile(board)
                draw_board(lcd, board, score)
                time.sleep(0.15)

            if not can_move(board):
                draw_board(lcd, board, score)
                time.sleep(0.5)
                # Show game over
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ImageDraw.Draw(img)
                font = ImageFont.load_default()
                d.text((20, 50), "GAME OVER", font=font, fill="white")
                d.text((10, 70), "KEY1=New", font=font, fill="white")
                d.text((10, 82), "KEY3=Exit", font=font, fill="white")
                lcd.LCD_ShowImage(img, 0, 0)
                while True:
                    if GPIO.input(KEY1) == 0:
                        board = new_board()
                        score = 0
                        draw_board(lcd, board, score)
                        break
                    if GPIO.input(KEY3) == 0:
                        return 0
                    time.sleep(0.1)

            time.sleep(0.05)
    finally:
        LCD_1in44.LCD().LCD_Clear()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
