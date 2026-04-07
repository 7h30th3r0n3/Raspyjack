#!/usr/bin/env python3
"""
RaspyJack Payload -- Sliding Puzzle (15-puzzle)
-------------------------------------------------
Author: 7h30th3r0n3

Classic 4x4 sliding tile puzzle. Arrange tiles 1-15 in order.

Controls:
  UP/DOWN/LEFT/RIGHT = slide tile into empty space
  KEY1               = new puzzle
  KEY3               = exit
"""
import os, sys, time, signal, random
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

running = True


def cleanup(*_):
    global running
    running = False


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- Layout ---
GRID_SIZE = 4
HUD_H = 14
CELL_W = _GAME_W // GRID_SIZE          # 32
CELL_H = (_GAME_H - HUD_H) // GRID_SIZE  # 28

# --- Colors ---
COL_BG = (0, 0, 0)
COL_TEXT = (255, 255, 255)
COL_HUD = (0, 180, 255)
COL_TILE_OUTLINE = (60, 60, 60)
COL_EMPTY = (20, 20, 20)
COL_WIN = (0, 255, 0)

# Tile colors by value range for visual distinction
TILE_COLORS = [
    (0, 100, 180),   # 1-4  blue
    (0, 150, 100),   # 5-8  teal
    (150, 100, 0),   # 9-12 orange
    (140, 0, 100),   # 13-15 purple
]


def tile_color(val):
    """Return a color based on tile value."""
    if val == 0:
        return COL_EMPTY
    idx = (val - 1) // GRID_SIZE
    idx = min(idx, len(TILE_COLORS) - 1)
    return TILE_COLORS[idx]


def solved_board():
    """Return the solved board state (list of 16 ints, 0 = empty)."""
    return list(range(1, 16)) + [0]


def find_empty(board):
    """Return (row, col) of the empty tile (value 0)."""
    idx = board.index(0)
    return idx // GRID_SIZE, idx % GRID_SIZE


def board_index(row, col):
    """Convert row, col to flat index."""
    return row * GRID_SIZE + col


def is_solved(board):
    """Check if the board is in solved state."""
    return board == solved_board()


def scramble_board(num_moves=150):
    """Create a solvable scrambled board by performing random moves from solved."""
    board = solved_board()
    er, ec = find_empty(board)
    directions = [(-1, 0), (1, 0), (0, -1), (0, 1)]
    last_dir = None

    for _ in range(num_moves):
        valid = []
        for dr, dc in directions:
            nr, nc = er + dr, ec + dc
            # Avoid undoing the last move
            if last_dir and (dr, dc) == (-last_dir[0], -last_dir[1]):
                continue
            if 0 <= nr < GRID_SIZE and 0 <= nc < GRID_SIZE:
                valid.append((dr, dc))
        dr, dc = random.choice(valid)
        nr, nc = er + dr, ec + dc
        # Swap empty with neighbor
        ei = board_index(er, ec)
        ni = board_index(nr, nc)
        new_board = list(board)
        new_board[ei], new_board[ni] = new_board[ni], new_board[ei]
        board = new_board
        er, ec = nr, nc
        last_dir = (dr, dc)

    return board


def try_move(board, direction):
    """
    Attempt to slide a tile into the empty space.
    Direction is the d-pad direction pressed.
    Returns new board or None if move is invalid.
    """
    er, ec = find_empty(board)

    # The tile that slides INTO the empty space comes from the opposite direction
    move_map = {
        "UP":    (1, 0),    # tile below empty slides up
        "DOWN":  (-1, 0),   # tile above empty slides down
        "LEFT":  (0, 1),    # tile right of empty slides left
        "RIGHT": (0, -1),   # tile left of empty slides right
    }

    if direction not in move_map:
        return None

    dr, dc = move_map[direction]
    tr, tc = er + dr, ec + dc

    if not (0 <= tr < GRID_SIZE and 0 <= tc < GRID_SIZE):
        return None

    ei = board_index(er, ec)
    ti = board_index(tr, tc)
    new_board = list(board)
    new_board[ei], new_board[ti] = new_board[ti], new_board[ei]
    return new_board


def draw_board(board, moves, solved_flag, best):
    """Render the puzzle board to LCD."""
    img = Image.new("RGB", (_GAME_W, _GAME_H), COL_BG)
    d = ImageDraw.Draw(img)

    # HUD
    hud_text = f"Mv:{moves}"
    if best > 0:
        hud_text += f" Bst:{best}"
    d.text((2, 1), hud_text, font=font, fill=COL_HUD)

    if solved_flag:
        d.text((80, 1), "SOLVED!", font=font, fill=COL_WIN)

    # Draw tiles
    for row in range(GRID_SIZE):
        for col in range(GRID_SIZE):
            val = board[board_index(row, col)]
            x0 = col * CELL_W
            y0 = HUD_H + row * CELL_H
            x1 = x0 + CELL_W - 1
            y1 = y0 + CELL_H - 1

            if val == 0:
                d.rectangle([x0, y0, x1, y1], fill=COL_EMPTY)
            else:
                fill = tile_color(val)
                if solved_flag:
                    fill = (0, 120, 0)
                d.rectangle([x0, y0, x1, y1], fill=fill, outline=COL_TILE_OUTLINE)
                # Center the number text
                txt = str(val)
                tw = len(txt) * 6  # approximate char width
                tx = x0 + (CELL_W - tw) // 2
                ty = y0 + (CELL_H - 8) // 2
                d.text((tx, ty), txt, font=font, fill=COL_TEXT)

    if _GAME_W != WIDTH or _GAME_H != HEIGHT:
        img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
    LCD.LCD_ShowImage(img, 0, 0)


def play():
    """Main puzzle loop."""
    global running
    best = 0

    while running:
        board = scramble_board()
        moves = 0
        solved_flag = False

        draw_board(board, moves, False, best)

        while running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                cleanup()
                return

            if btn == "KEY1":
                # New puzzle
                time.sleep(0.2)
                break

            if solved_flag:
                # Already solved, wait for KEY1 or KEY3
                time.sleep(0.05)
                continue

            if btn in ("UP", "DOWN", "LEFT", "RIGHT"):
                new_board = try_move(board, btn)
                if new_board is not None:
                    board = new_board
                    moves += 1

                    if is_solved(board):
                        solved_flag = True
                        if best == 0 or moves < best:
                            best = moves

                    draw_board(board, moves, solved_flag, best)
                    time.sleep(0.12)

            time.sleep(0.03)


if __name__ == "__main__":
    try:
        play()
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
