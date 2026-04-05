#!/usr/bin/env python3
"""
RaspyJack payload -- Connect 4 (Puissance 4)
=============================================
Author: 7h30th3r0n3

Connect 4 vs AI with minimax alpha-beta pruning on LCD.

Controls: LEFT/RIGHT=move cursor, OK=drop disc, KEY1=toggle difficulty,
          KEY3=exit.
"""

import os, sys, time
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import signal
import random

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._input_helper import get_button

# ---------------------------------------------------------------------------
# GPIO setup
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

# ---------------------------------------------------------------------------
# LCD setup
# ---------------------------------------------------------------------------
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
_GAME_W, _GAME_H = 128, 128
font = ImageFont.load_default()

# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------
COL_BG = (0, 0, 0)
COL_BOARD = (0, 0, 140)
COL_EMPTY = (40, 40, 40)
COL_PLAYER = (0, 255, 0)
COL_AI = (255, 0, 0)
COL_CURSOR = (0, 200, 0)
COL_TEXT = (0, 255, 0)
COL_DIM = (0, 120, 0)
COL_WIN = (255, 255, 0)

# ---------------------------------------------------------------------------
# Board constants
# ---------------------------------------------------------------------------
ROWS = 6
COLS = 7
EMPTY = 0
PLAYER = 1
AI_PIECE = 2

CELL_W = 16
CELL_H = 16
BOARD_W = COLS * CELL_W    # 112
BOARD_H = ROWS * CELL_H    # 96
BOARD_OX = (_GAME_W - BOARD_W) // 2
BOARD_OY = _GAME_H - BOARD_H - 2
DISC_R = 6

DIFFICULTIES = [
    {"name": "EASY", "depth": 0},
    {"name": "MED", "depth": 3},
    {"name": "HARD", "depth": 6},
]

running = True


def cleanup_handler(*_):
    global running
    running = False


signal.signal(signal.SIGINT, cleanup_handler)
signal.signal(signal.SIGTERM, cleanup_handler)


# ---------------------------------------------------------------------------
# Board logic (immutable: tuples of tuples)
# ---------------------------------------------------------------------------
def empty_board():
    """Create an empty board as tuple of tuples (row-major)."""
    return tuple(tuple(EMPTY for _ in range(COLS)) for _ in range(ROWS))


def drop_piece(board, col, piece):
    """Drop a piece into column. Returns (new_board, row) or (None, -1)."""
    for r in range(ROWS - 1, -1, -1):
        if board[r][col] == EMPTY:
            new_board = tuple(
                tuple(piece if ri == r and ci == col else board[ri][ci]
                      for ci in range(COLS))
                for ri in range(ROWS)
            )
            return new_board, r
    return None, -1


def valid_columns(board):
    """Return list of columns that have room."""
    return [c for c in range(COLS) if board[0][c] == EMPTY]


def check_win(board, piece):
    """Return list of winning positions or empty list."""
    # Horizontal
    for r in range(ROWS):
        for c in range(COLS - 3):
            cells = [(r, c + i) for i in range(4)]
            if all(board[r][c + i] == piece for i in range(4)):
                return cells
    # Vertical
    for r in range(ROWS - 3):
        for c in range(COLS):
            cells = [(r + i, c) for i in range(4)]
            if all(board[r + i][c] == piece for i in range(4)):
                return cells
    # Diagonal down-right
    for r in range(ROWS - 3):
        for c in range(COLS - 3):
            cells = [(r + i, c + i) for i in range(4)]
            if all(board[r + i][c + i] == piece for i in range(4)):
                return cells
    # Diagonal down-left
    for r in range(ROWS - 3):
        for c in range(3, COLS):
            cells = [(r + i, c - i) for i in range(4)]
            if all(board[r + i][c - i] == piece for i in range(4)):
                return cells
    return []


def is_draw(board):
    """Board full with no winner."""
    return len(valid_columns(board)) == 0


# ---------------------------------------------------------------------------
# AI: minimax with alpha-beta pruning
# ---------------------------------------------------------------------------
def evaluate_window(window, piece):
    """Score a window of 4 cells."""
    opp = PLAYER if piece == AI_PIECE else AI_PIECE
    p_count = window.count(piece)
    o_count = window.count(opp)
    e_count = window.count(EMPTY)

    if p_count == 4:
        return 100
    if p_count == 3 and e_count == 1:
        return 5
    if p_count == 2 and e_count == 2:
        return 2
    if o_count == 3 and e_count == 1:
        return -4
    return 0


def score_position(board, piece):
    """Heuristic evaluation of the board for the given piece."""
    score = 0
    # Center column preference
    center_col = COLS // 2
    center_count = sum(1 for r in range(ROWS) if board[r][center_col] == piece)
    score += center_count * 3

    # Horizontal windows
    for r in range(ROWS):
        for c in range(COLS - 3):
            window = [board[r][c + i] for i in range(4)]
            score += evaluate_window(window, piece)

    # Vertical windows
    for r in range(ROWS - 3):
        for c in range(COLS):
            window = [board[r + i][c] for i in range(4)]
            score += evaluate_window(window, piece)

    # Diagonal down-right
    for r in range(ROWS - 3):
        for c in range(COLS - 3):
            window = [board[r + i][c + i] for i in range(4)]
            score += evaluate_window(window, piece)

    # Diagonal down-left
    for r in range(ROWS - 3):
        for c in range(3, COLS):
            window = [board[r + i][c - i] for i in range(4)]
            score += evaluate_window(window, piece)

    return score


def minimax(board, depth, alpha, beta, maximizing):
    """Minimax with alpha-beta pruning. Returns (column, score)."""
    vcols = valid_columns(board)

    if check_win(board, AI_PIECE):
        return None, 100000
    if check_win(board, PLAYER):
        return None, -100000
    if len(vcols) == 0:
        return None, 0
    if depth == 0:
        return None, score_position(board, AI_PIECE)

    if maximizing:
        best_score = -999999
        best_col = random.choice(vcols)
        for col in vcols:
            new_board, _ = drop_piece(board, col, AI_PIECE)
            if new_board is None:
                continue
            _, sc = minimax(new_board, depth - 1, alpha, beta, False)
            if sc > best_score:
                best_score = sc
                best_col = col
            alpha = max(alpha, sc)
            if alpha >= beta:
                break
        return best_col, best_score
    else:
        best_score = 999999
        best_col = random.choice(vcols)
        for col in vcols:
            new_board, _ = drop_piece(board, col, PLAYER)
            if new_board is None:
                continue
            _, sc = minimax(new_board, depth - 1, alpha, beta, True)
            if sc < best_score:
                best_score = sc
                best_col = col
            beta = min(beta, sc)
            if alpha >= beta:
                break
        return best_col, best_score


def ai_move(board, difficulty):
    """Choose a column for the AI."""
    depth = difficulty["depth"]
    if depth == 0:
        return random.choice(valid_columns(board))
    col, _ = minimax(board, depth, -999999, 999999, True)
    return col


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------
def cell_center(r, c):
    """Pixel center of a cell."""
    cx = BOARD_OX + c * CELL_W + CELL_W // 2
    cy = BOARD_OY + r * CELL_H + CELL_H // 2
    return cx, cy


def draw_board(board, cursor_col, diff_idx, p_score, a_score,
               win_cells=None, message=None):
    """Render the game state to LCD."""
    img = Image.new("RGB", (_GAME_W, _GAME_H), COL_BG)
    d = ImageDraw.Draw(img)

    # HUD
    diff_name = DIFFICULTIES[diff_idx]["name"]
    d.text((2, 2), f"P:{p_score} AI:{a_score}", font=font, fill=COL_TEXT)
    d.text((90, 2), diff_name, font=font, fill=COL_DIM)

    # Cursor arrow
    if cursor_col is not None and message is None:
        ax = BOARD_OX + cursor_col * CELL_W + CELL_W // 2
        ay = BOARD_OY - 6
        d.polygon([(ax - 3, ay - 4), (ax + 3, ay - 4), (ax, ay)],
                  fill=COL_CURSOR)

    # Board frame
    d.rectangle([BOARD_OX - 1, BOARD_OY - 1,
                 BOARD_OX + BOARD_W, BOARD_OY + BOARD_H],
                outline=COL_BOARD)

    # Cells
    win_set = set(win_cells) if win_cells else set()
    for r in range(ROWS):
        for c in range(COLS):
            cx, cy = cell_center(r, c)
            piece = board[r][c]
            if (r, c) in win_set:
                col = COL_WIN
            elif piece == PLAYER:
                col = COL_PLAYER
            elif piece == AI_PIECE:
                col = COL_AI
            else:
                col = COL_EMPTY
            d.ellipse([cx - DISC_R, cy - DISC_R, cx + DISC_R, cy + DISC_R],
                      fill=col)

    # Message overlay
    if message:
        bbox = d.textbbox((0, 0), message, font=font)
        tw = bbox[2] - bbox[0]
        th = bbox[3] - bbox[1]
        mx = (_GAME_W - tw) // 2
        my = BOARD_OY - 16
        d.rectangle([mx - 2, my - 1, mx + tw + 2, my + th + 1], fill=COL_BG)
        d.text((mx, my), message, font=font, fill=COL_TEXT)

    if _GAME_W != WIDTH or _GAME_H != HEIGHT:
        img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Win highlight animation
# ---------------------------------------------------------------------------
def flash_win(board, win_cells, diff_idx, p_score, a_score):
    """Flash winning line."""
    for i in range(6):
        cells = win_cells if i % 2 == 0 else []
        draw_board(board, None, diff_idx, p_score, a_score, win_cells=cells)
        time.sleep(0.25)


# ---------------------------------------------------------------------------
# Main game loop
# ---------------------------------------------------------------------------
def play():
    """Run Connect 4 games."""
    diff_idx = 2   # default: HARD
    p_score = 0
    a_score = 0

    while running:
        board = empty_board()
        cursor_col = COLS // 2
        game_over = False
        player_turn = True

        while running and not game_over:
            draw_board(board, cursor_col, diff_idx, p_score, a_score)

            if player_turn:
                # Player input
                btn = None
                while running and btn is None:
                    btn = get_button(PINS, GPIO)
                    if btn is None:
                        time.sleep(0.03)

                if btn == "KEY3":
                    return
                if btn == "KEY1":
                    diff_idx = (diff_idx + 1) % len(DIFFICULTIES)
                    time.sleep(0.2)
                    continue

                if btn == "LEFT":
                    cursor_col = max(0, cursor_col - 1)
                    time.sleep(0.1)
                    continue
                if btn == "RIGHT":
                    cursor_col = min(COLS - 1, cursor_col + 1)
                    time.sleep(0.1)
                    continue

                if btn == "OK":
                    new_board, row = drop_piece(board, cursor_col, PLAYER)
                    if new_board is None:
                        continue
                    board = new_board

                    win_cells = check_win(board, PLAYER)
                    if win_cells:
                        p_score += 1
                        flash_win(board, win_cells, diff_idx, p_score, a_score)
                        draw_board(board, None, diff_idx, p_score, a_score,
                                   message="YOU WIN! OK=Again")
                        game_over = True
                        continue

                    if is_draw(board):
                        draw_board(board, None, diff_idx, p_score, a_score,
                                   message="DRAW! OK=Again")
                        game_over = True
                        continue

                    player_turn = False
                    time.sleep(0.05)
                else:
                    time.sleep(0.05)

            else:
                # AI turn
                draw_board(board, None, diff_idx, p_score, a_score,
                           message="AI thinking...")

                col = ai_move(board, DIFFICULTIES[diff_idx])
                if col is None:
                    game_over = True
                    continue

                new_board, row = drop_piece(board, col, AI_PIECE)
                if new_board is None:
                    game_over = True
                    continue
                board = new_board

                win_cells = check_win(board, AI_PIECE)
                if win_cells:
                    a_score += 1
                    flash_win(board, win_cells, diff_idx, p_score, a_score)
                    draw_board(board, None, diff_idx, p_score, a_score,
                               message="AI WINS! OK=Again")
                    game_over = True
                    continue

                if is_draw(board):
                    draw_board(board, None, diff_idx, p_score, a_score,
                               message="DRAW! OK=Again")
                    game_over = True
                    continue

                player_turn = True

        # End-of-game: wait for OK=new game or KEY3=exit
        while running:
            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                return
            if btn == "OK":
                time.sleep(0.2)
                break
            time.sleep(0.05)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        play()
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
