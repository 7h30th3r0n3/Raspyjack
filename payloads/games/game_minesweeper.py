#!/usr/bin/env python3
"""
RaspyJack Payload -- Minesweeper
=================================
Author: 7h30th3r0n3

8x8 grid, 10 mines, 14x14px cells on a LCD.

Controls:
  UP/DOWN/LEFT/RIGHT -- Move cursor
  OK                 -- Reveal cell
  KEY1               -- Toggle flag
  KEY2               -- New game
  KEY3               -- Exit
"""

import os
import sys
import time
import random

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
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
_GAME_W, _GAME_H = 128, 128
font = ImageFont.load_default()

# ---------------------------------------------------------------------------
# Game constants
# ---------------------------------------------------------------------------
GRID_W = 8
GRID_H = 8
MINE_COUNT = 10
CELL_PX = 14
GRID_OX = (_GAME_W - GRID_W * CELL_PX) // 2
GRID_OY = 16

NUM_COLORS = {
    1: "#0000FF",
    2: "#008000",
    3: "#FF0000",
    4: "#000080",
    5: "#800000",
    6: "#008080",
    7: "#000000",
    8: "#808080",
}


# ---------------------------------------------------------------------------
# Game state (pure data, new objects on reset)
# ---------------------------------------------------------------------------

def _make_board():
    """Create a fresh game board. Returns (mines, counts, revealed, flagged)."""
    mines = [[False] * GRID_W for _ in range(GRID_H)]
    counts = [[0] * GRID_W for _ in range(GRID_H)]
    revealed = [[False] * GRID_W for _ in range(GRID_H)]
    flagged = [[False] * GRID_W for _ in range(GRID_H)]

    positions = [(r, c) for r in range(GRID_H) for c in range(GRID_W)]
    mine_positions = random.sample(positions, MINE_COUNT)
    for r, c in mine_positions:
        mines[r][c] = True

    for r in range(GRID_H):
        for c in range(GRID_W):
            if mines[r][c]:
                counts[r][c] = -1
                continue
            count = 0
            for dr in (-1, 0, 1):
                for dc in (-1, 0, 1):
                    nr, nc = r + dr, c + dc
                    if 0 <= nr < GRID_H and 0 <= nc < GRID_W and mines[nr][nc]:
                        count += 1
            counts[r][c] = count

    return mines, counts, revealed, flagged


def _flood_reveal(counts, revealed, flagged, start_r, start_c):
    """Flood-fill reveal for zero-count cells. Returns new revealed grid."""
    new_revealed = [row[:] for row in revealed]
    stack = [(start_r, start_c)]

    while stack:
        r, c = stack.pop()
        if new_revealed[r][c]:
            continue
        if flagged[r][c]:
            continue
        new_revealed[r][c] = True
        if counts[r][c] == 0:
            for dr in (-1, 0, 1):
                for dc in (-1, 0, 1):
                    nr, nc = r + dr, c + dc
                    if 0 <= nr < GRID_H and 0 <= nc < GRID_W:
                        if not new_revealed[nr][nc]:
                            stack.append((nr, nc))

    return new_revealed


def _check_win(mines, revealed):
    """True if all non-mine cells are revealed."""
    for r in range(GRID_H):
        for c in range(GRID_W):
            if not mines[r][c] and not revealed[r][c]:
                return False
    return True


def _count_flags(flagged):
    total = 0
    for row in flagged:
        for v in row:
            if v:
                total += 1
    return total


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_cell(d, r, c, mines, counts, revealed, flagged, cursor_r, cursor_c, show_all):
    """Draw a single cell."""
    x0 = GRID_OX + c * CELL_PX
    y0 = GRID_OY + r * CELL_PX
    x1 = x0 + CELL_PX - 1
    y1 = y0 + CELL_PX - 1

    is_cursor = (r == cursor_r and c == cursor_c)

    if revealed[r][c] or show_all:
        if mines[r][c]:
            d.rectangle((x0, y0, x1, y1), fill="#FF0000", outline="#880000")
            d.ellipse((x0 + 3, y0 + 3, x1 - 3, y1 - 3), fill="#000000")
        else:
            d.rectangle((x0, y0, x1, y1), fill="#CCCCCC", outline="#999999")
            num = counts[r][c]
            if num > 0:
                color = NUM_COLORS.get(num, "#000000")
                d.text((x0 + 4, y0 + 2), str(num), font=font, fill=color)
    elif flagged[r][c]:
        d.rectangle((x0, y0, x1, y1), fill="#444444", outline="#666666")
        d.polygon(
            [(x0 + 4, y0 + 3), (x0 + 4, y0 + 11), (x0 + 10, y0 + 7)],
            fill="#FFFF00",
        )
    else:
        d.rectangle((x0, y0, x1, y1), fill="#555555", outline="#777777")

    if is_cursor and not show_all:
        d.rectangle((x0, y0, x1, y1), outline="#00FF00", width=2)


def draw_board(mines, counts, revealed, flagged, cursor_r, cursor_c,
               game_over, won, show_all):
    """Render the full game board."""
    img = Image.new("RGB", (_GAME_W, _GAME_H), "black")
    d = ImageDraw.Draw(img)

    flags = _count_flags(flagged)
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "MINESWEEPER", font=font, fill="#00CCFF")
    d.text((90, 1), f"F:{flags}/{MINE_COUNT}", font=font, fill="#FFFF00")

    for r in range(GRID_H):
        for c in range(GRID_W):
            _draw_cell(d, r, c, mines, counts, revealed, flagged,
                       cursor_r, cursor_c, show_all)

    if game_over:
        d.rectangle((10, 50, 118, 75), fill="#000000", outline="#FF0000")
        d.text((20, 55), "GAME OVER!", font=font, fill="#FF0000")
        d.text((15, 65), "K2:New  K3:Exit", font=font, fill="#888")
    elif won:
        d.rectangle((10, 50, 118, 75), fill="#000000", outline="#00FF00")
        d.text((25, 55), "YOU WIN!", font=font, fill="#00FF00")
        d.text((15, 65), "K2:New  K3:Exit", font=font, fill="#888")

    if _GAME_W != WIDTH or _GAME_H != HEIGHT:
        img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    mines, counts, revealed, flagged = _make_board()
    cursor_r, cursor_c = 0, 0
    game_over = False
    won = False

    draw_board(mines, counts, revealed, flagged, cursor_r, cursor_c,
               game_over, won, False)

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            if btn == "KEY2":
                mines, counts, revealed, flagged = _make_board()
                cursor_r, cursor_c = 0, 0
                game_over = False
                won = False
                draw_board(mines, counts, revealed, flagged, cursor_r, cursor_c,
                           game_over, won, False)
                time.sleep(0.3)
                continue

            if game_over or won:
                time.sleep(0.1)
                continue

            moved = False

            if btn == "UP":
                cursor_r = max(0, cursor_r - 1)
                moved = True
            elif btn == "DOWN":
                cursor_r = min(GRID_H - 1, cursor_r + 1)
                moved = True
            elif btn == "LEFT":
                cursor_c = max(0, cursor_c - 1)
                moved = True
            elif btn == "RIGHT":
                cursor_c = min(GRID_W - 1, cursor_c + 1)
                moved = True

            elif btn == "OK":
                if not flagged[cursor_r][cursor_c] and not revealed[cursor_r][cursor_c]:
                    if mines[cursor_r][cursor_c]:
                        game_over = True
                        draw_board(mines, counts, revealed, flagged,
                                   cursor_r, cursor_c, True, False, True)
                        time.sleep(0.3)
                        continue
                    else:
                        revealed = _flood_reveal(counts, revealed, flagged,
                                                  cursor_r, cursor_c)
                        if _check_win(mines, revealed):
                            won = True
                    moved = True

            elif btn == "KEY1":
                if not revealed[cursor_r][cursor_c]:
                    new_flagged = [row[:] for row in flagged]
                    new_flagged[cursor_r][cursor_c] = not flagged[cursor_r][cursor_c]
                    flagged = new_flagged
                    moved = True

            if moved:
                draw_board(mines, counts, revealed, flagged, cursor_r, cursor_c,
                           game_over, won, False)
                time.sleep(0.12)

            time.sleep(0.04)

    finally:
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
