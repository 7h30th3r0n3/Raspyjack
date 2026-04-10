#!/usr/bin/env python3
"""
RaspyJack Payload – Tetris
Controls:
- LEFT/RIGHT: move
- UP: hard drop
- DOWN: soft drop
- KEY1: rotate
- KEY3: exit
"""

import os
import sys
import time
import random

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO  # type: ignore
import LCD_1in44, LCD_Config  # type: ignore
from PIL import Image, ImageDraw, ImageFont  # type: ignore

# Shared input helper (WebUI virtual + GPIO)
from payloads._input_helper import get_button

WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
_GAME_W, _GAME_H = 128, 128
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
    "#00e5ff",  # I - cyan
    "#ffea00",  # O - yellow
    "#aa00ff",  # T - purple
    "#00e676",  # S - green
    "#ff1744",  # Z - red
    "#2979ff",  # J - blue
    "#ff9100",  # L - orange
]

# Darker shade per piece for cell border / 3D effect
COLORS_DARK = [
    "#00838f",  # I
    "#c6a700",  # O
    "#6a1b9a",  # T
    "#1b5e20",  # S
    "#b71c1c",  # Z
    "#0d47a1",  # J
    "#e65100",  # L
]

# Side-panel metrics area
_PANEL_X = OX + BOARD_W * CELL + 4  # right of board
_PANEL_W = _GAME_W - _PANEL_X - 1


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
    return idx, SHAPES[idx], COLORS[idx]


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


def _draw_cell(d, x0, y0, color, idx):
    """Draw a single cell with a subtle border for 3D effect."""
    dark = COLORS_DARK[idx] if idx is not None else "#333"
    d.rectangle((x0, y0, x0 + CELL - 1, y0 + CELL - 1), fill=color, outline=dark)


def draw(lcd, board, shape, sx, sy, color, score, lines, level, next_idx):
    img = Image.new("RGB", (_GAME_W, _GAME_H), "#0a0a0a")
    d = ImageDraw.Draw(img)
    font = ImageFont.load_default()

    # ── Header bar ──
    d.rectangle((0, 0, 127, 12), fill="#1a1a2e")
    d.text((2, 2), "TETRIS", font=font, fill="#00e5ff")

    # ── Board outline + faint grid ──
    bx1, by1 = OX - 1, OY - 1
    bx2, by2 = OX + BOARD_W * CELL, OY + BOARD_H * CELL
    d.rectangle((bx1, by1, bx2, by2), outline="#333")
    # Vertical grid lines
    for gx in range(1, BOARD_W):
        lx = OX + gx * CELL
        d.line((lx, OY, lx, by2 - 1), fill="#1a1a1a")
    # Horizontal grid lines
    for gy in range(1, BOARD_H):
        ly = OY + gy * CELL
        d.line((OX, ly, bx2 - 1, ly), fill="#1a1a1a")

    # ── Board cells ──
    for y in range(BOARD_H):
        for x in range(BOARD_W):
            val = board[y][x]
            if val:
                cx = OX + x * CELL
                cy = OY + y * CELL
                # Find color index for dark shade
                cidx = COLORS.index(val) if val in COLORS else None
                _draw_cell(d, cx, cy, val, cidx)

    # ── Current piece ──
    pidx = COLORS.index(color) if color in COLORS else None
    for r, row in enumerate(shape):
        for c, v in enumerate(row):
            if v:
                cx = OX + (sx + c) * CELL
                cy = OY + (sy + r) * CELL
                if OY <= cy <= _GAME_H - CELL:
                    _draw_cell(d, cx, cy, color, pidx)

    # ── Side panel: stats ──
    px = _PANEL_X
    # Score
    d.text((px, OY), "SCR", font=font, fill="#888")
    d.text((px, OY + 10), str(score), font=font, fill="#ffea00")
    # Level
    d.text((px, OY + 24), "LVL", font=font, fill="#888")
    d.text((px, OY + 34), str(level), font=font, fill="#00e676")
    # Lines
    d.text((px, OY + 48), "LNS", font=font, fill="#888")
    d.text((px, OY + 58), str(lines), font=font, fill="#00e5ff")

    # ── Next piece preview ──
    d.text((px, OY + 74), "NXT", font=font, fill="#888")
    nshape = SHAPES[next_idx]
    ncolor = COLORS[next_idx]
    ndark = COLORS_DARK[next_idx]
    # Center the preview in a small 4x4 box
    preview_y = OY + 84
    preview_x = px + 2
    for r, row in enumerate(nshape):
        for c, v in enumerate(row):
            if v:
                nx0 = preview_x + c * 4
                ny0 = preview_y + r * 4
                d.rectangle((nx0, ny0, nx0 + 3, ny0 + 3), fill=ncolor, outline=ndark)

    if _GAME_W != WIDTH or _GAME_H != HEIGHT:
        img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
    lcd.LCD_ShowImage(img, 0, 0)


def main():
    lcd = lcd_init()
    GPIO.setmode(GPIO.BCM)
    for pin in (KEY_UP, KEY_DOWN, KEY_LEFT, KEY_RIGHT, KEY1, KEY3):
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    btn_map = {
        "LEFT": KEY_LEFT,
        "RIGHT": KEY_RIGHT,
        "UP": KEY_UP,
        "DOWN": KEY_DOWN,
        "KEY1": KEY1,
        "KEY3": KEY3,
    }

    board = [[None] * BOARD_W for _ in range(BOARD_H)]
    _idx, shape, color = new_piece()
    _nidx, _nshape, _ncolor = new_piece()
    sx, sy = 3, -2
    score = 0
    total_lines = 0
    level = 1

    drop_interval = 0.6
    last_drop = time.time()

    try:
        while True:
            btn = get_button(btn_map, GPIO)
            if btn == "KEY3":
                break

            moved = False
            if btn == "LEFT" and can_place(board, shape, sx - 1, sy):
                sx -= 1
                moved = True
            elif btn == "RIGHT" and can_place(board, shape, sx + 1, sy):
                sx += 1
                moved = True
            elif btn == "UP":
                # Hard drop: instantly drop piece to bottom
                while can_place(board, shape, sx, sy + 1):
                    sy += 1
                moved = True
            elif btn == "DOWN" and can_place(board, shape, sx, sy + 1):
                sy += 1
                moved = True
            elif btn == "KEY1":
                # Rotate piece
                r = rotate(shape)
                if can_place(board, r, sx, sy):
                    shape = r
                    moved = True

            if moved:
                draw(lcd, board, shape, sx, sy, color, score,
                     total_lines, level, _nidx)
                time.sleep(0.08)

            if time.time() - last_drop > drop_interval:
                last_drop = time.time()
                if can_place(board, shape, sx, sy + 1):
                    sy += 1
                else:
                    merge(board, shape, sx, sy, color)
                    board, cleared = clear_lines(board)
                    if cleared:
                        total_lines += cleared
                        level = total_lines // 10 + 1
                        # Bonus for multi-line clears
                        score += cleared * cleared * 100
                        # Speed up with level (cap at 0.15s)
                        drop_interval = max(0.15, 0.6 - (level - 1) * 0.05)
                    shape, color = _nshape, _ncolor
                    _nidx, _nshape, _ncolor = new_piece()
                    sx, sy = 3, -2
                    if not can_place(board, shape, sx, sy):
                        # Game over screen
                        img = Image.new("RGB", (_GAME_W, _GAME_H), "#0a0a0a")
                        d = ImageDraw.Draw(img)
                        font = ImageFont.load_default()
                        # Red banner
                        d.rectangle((0, 20, 127, 36), fill="#b71c1c")
                        d.text((28, 24), "GAME OVER", font=font, fill="white")
                        # Stats
                        d.text((14, 46), f"Score:  {score}", font=font, fill="#ffea00")
                        d.text((14, 58), f"Lines:  {total_lines}", font=font, fill="#00e5ff")
                        d.text((14, 70), f"Level:  {level}", font=font, fill="#00e676")
                        # Options
                        d.rectangle((10, 88, 118, 100), outline="#444")
                        d.text((14, 90), "KEY1=Retry KEY3=Exit", font=font, fill="#aaa")
                        if _GAME_W != WIDTH or _GAME_H != HEIGHT:
                            img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
                        lcd.LCD_ShowImage(img, 0, 0)
                        while True:
                            btn = get_button({"KEY1": KEY1, "KEY3": KEY3}, GPIO)
                            if btn == "KEY1":
                                board = [[None] * BOARD_W for _ in range(BOARD_H)]
                                _idx, shape, color = new_piece()
                                _nidx, _nshape, _ncolor = new_piece()
                                sx, sy = 3, -2
                                score = 0
                                total_lines = 0
                                level = 1
                                drop_interval = 0.6
                                break
                            if btn == "KEY3":
                                return 0
                            time.sleep(0.1)

                draw(lcd, board, shape, sx, sy, color, score,
                     total_lines, level, _nidx)

            time.sleep(0.02)
    finally:
        LCD_1in44.LCD().LCD_Clear()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
