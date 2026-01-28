#!/usr/bin/env python3
"""
RaspyJack Payload – Tetris
Controls:
- LEFT/RIGHT: move
- UP: rotate
- DOWN: soft drop
- KEY1: hard drop
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
KEY1 = 21
KEY3 = 16

BOARD_W = 10
BOARD_H = 20
CELL = 5
OX = 4
OY = 14

SHAPES = [
    # I
    [[1, 1, 1, 1]],
    # O
    [[1, 1],
     [1, 1]],
    # T
    [[0, 1, 0],
     [1, 1, 1]],
    # S
    [[0, 1, 1],
     [1, 1, 0]],
    # Z
    [[1, 1, 0],
     [0, 1, 1]],
    # J
    [[1, 0, 0],
     [1, 1, 1]],
    # L
    [[0, 0, 1],
     [1, 1, 1]],
]

COLORS = [
    "#00bcd4", "#ffeb3b", "#9c27b0",
    "#4caf50", "#f44336", "#3f51b5", "#ff9800"
]


def lcd_init():
    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    return lcd


def rotate(shape):
    return [list(row) for row in zip(*shape[::-1])]


def new_piece():
    idx = random.randrange(len(SHAPES))
    return SHAPES[idx], COLORS[idx]


def can_place(board, shape, x, y):
    for r, row in enumerate(shape):
        for c, v in enumerate(row):
            if v:
                nx, ny = x + c, y + r
                if nx < 0 or nx >= BOARD_W or ny >= BOARD_H:
                    return False
                if ny >= 0 and board[ny][nx] is not None:
                    return False
    return True


def merge(board, shape, x, y, color):
    for r, row in enumerate(shape):
        for c, v in enumerate(row):
            if v:
                nx, ny = x + c, y + r
                if ny >= 0:
                    board[ny][nx] = color


def clear_lines(board):
    new = [row for row in board if any(v is None for v in row)]
    cleared = BOARD_H - len(new)
    for _ in range(cleared):
        new.insert(0, [None] * BOARD_W)
    return new, cleared


def draw(lcd, board, shape, sx, sy, color, score):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    font = ImageFont.load_default()

    d.rectangle((0, 0, 127, 12), fill="#1a1a1a")
    d.text((4, 1), "TETRIS", font=font, fill="white")
    d.text((78, 1), f"S:{score}", font=font, fill="white")

    # Board
    d.rectangle((OX - 1, OY - 1, OX + BOARD_W * CELL, OY + BOARD_H * CELL), outline="#444")
    for y in range(BOARD_H):
        for x in range(BOARD_W):
            val = board[y][x]
            if val:
                x0 = OX + x * CELL
                y0 = OY + y * CELL
                d.rectangle((x0, y0, x0 + CELL - 1, y0 + CELL - 1), fill=val)

    # Current piece
    for r, row in enumerate(shape):
        for c, v in enumerate(row):
            if v:
                x0 = OX + (sx + c) * CELL
                y0 = OY + (sy + r) * CELL
                if y0 >= OY and y0 <= HEIGHT - CELL:
                    d.rectangle((x0, y0, x0 + CELL - 1, y0 + CELL - 1), fill=color)

    lcd.LCD_ShowImage(img, 0, 0)


def main():
    lcd = lcd_init()
    GPIO.setmode(GPIO.BCM)
    for pin in (KEY_UP, KEY_DOWN, KEY_LEFT, KEY_RIGHT, KEY1, KEY3):
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    board = [[None] * BOARD_W for _ in range(BOARD_H)]
    shape, color = new_piece()
    sx, sy = 3, -2
    score = 0

    drop_interval = 0.6
    last_drop = time.time()

    try:
        while True:
            if GPIO.input(KEY3) == 0:
                break

            moved = False
            if GPIO.input(KEY_LEFT) == 0 and can_place(board, shape, sx - 1, sy):
                sx -= 1
                moved = True
            elif GPIO.input(KEY_RIGHT) == 0 and can_place(board, shape, sx + 1, sy):
                sx += 1
                moved = True
            elif GPIO.input(KEY_UP) == 0:
                r = rotate(shape)
                if can_place(board, r, sx, sy):
                    shape = r
                    moved = True
            elif GPIO.input(KEY_DOWN) == 0 and can_place(board, shape, sx, sy + 1):
                sy += 1
                moved = True
            elif GPIO.input(KEY1) == 0:
                while can_place(board, shape, sx, sy + 1):
                    sy += 1
                moved = True

            if moved:
                draw(lcd, board, shape, sx, sy, color, score)
                time.sleep(0.08)

            if time.time() - last_drop > drop_interval:
                last_drop = time.time()
                if can_place(board, shape, sx, sy + 1):
                    sy += 1
                else:
                    merge(board, shape, sx, sy, color)
                    board, cleared = clear_lines(board)
                    if cleared:
                        score += cleared * 100
                    shape, color = new_piece()
                    sx, sy = 3, -2
                    if not can_place(board, shape, sx, sy):
                        # Game over
                        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                        d = ImageDraw.Draw(img)
                        font = ImageFont.load_default()
                        d.text((20, 45), "GAME OVER", font=font, fill="white")
                        d.text((12, 62), "KEY1=Restart", font=font, fill="white")
                        d.text((20, 78), "KEY3=Exit", font=font, fill="white")
                        lcd.LCD_ShowImage(img, 0, 0)
                        while True:
                            if GPIO.input(KEY1) == 0:
                                board = [[None] * BOARD_W for _ in range(BOARD_H)]
                                shape, color = new_piece()
                                sx, sy = 3, -2
                                score = 0
                                break
                            if GPIO.input(KEY3) == 0:
                                return 0
                            time.sleep(0.1)

                draw(lcd, board, shape, sx, sy, color, score)

            time.sleep(0.02)
    finally:
        LCD_1in44.LCD().LCD_Clear()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
