#!/usr/bin/env python3
"""
RaspyJack Payload -- Tic-Tac-Toe vs AI (minimax with alpha-beta pruning)
--------------------------------------------------------------------------
Author: 7h30th3r0n3

Controls: D-pad=move cursor, OK=place X, KEY1=toggle difficulty, KEY3=exit
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

COL_BG = (0, 0, 0)
COL_GRID = (0, 120, 0)
COL_X = (0, 255, 0)
COL_O = (255, 0, 0)
COL_CURSOR = (0, 180, 0)
COL_TEXT = (0, 255, 0)
COL_DIM = (60, 60, 60)

CELL_SIZE = 36
GRID_OFFSET_X = (_GAME_W - CELL_SIZE * 3) // 2
GRID_OFFSET_Y = 14
EMPTY, PLAYER_X, PLAYER_O = 0, 1, 2

running = True


def cleanup(*_):
    global running
    running = False


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)


def _check_winner(board):
    """Return PLAYER_X, PLAYER_O, 'draw', or None."""
    lines = []
    for i in range(3):
        lines.append([(i, 0), (i, 1), (i, 2)])
        lines.append([(0, i), (1, i), (2, i)])
    lines.append([(0, 0), (1, 1), (2, 2)])
    lines.append([(0, 2), (1, 1), (2, 0)])
    for line in lines:
        vals = [board[r][c] for r, c in line]
        if vals[0] != EMPTY and vals[0] == vals[1] == vals[2]:
            return vals[0]
    if all(board[r][c] != EMPTY for r in range(3) for c in range(3)):
        return "draw"
    return None


def _minimax(board, depth, is_max, alpha, beta):
    """Minimax with alpha-beta pruning. AI=O(maximizer), Player=X(minimizer)."""
    result = _check_winner(board)
    if result == PLAYER_O:
        return 10 - depth
    if result == PLAYER_X:
        return depth - 10
    if result == "draw":
        return 0

    if is_max:
        best = -100
        for r in range(3):
            for c in range(3):
                if board[r][c] == EMPTY:
                    new_board = [row[:] for row in board]
                    new_board[r][c] = PLAYER_O
                    val = _minimax(new_board, depth + 1, False, alpha, beta)
                    best = max(best, val)
                    alpha = max(alpha, val)
                    if beta <= alpha:
                        return best
        return best
    else:
        best = 100
        for r in range(3):
            for c in range(3):
                if board[r][c] == EMPTY:
                    new_board = [row[:] for row in board]
                    new_board[r][c] = PLAYER_X
                    val = _minimax(new_board, depth + 1, True, alpha, beta)
                    best = min(best, val)
                    beta = min(beta, val)
                    if beta <= alpha:
                        return best
        return best


def _ai_move_hard(board):
    """Return (row, col) for best AI move using minimax."""
    best_val = -100
    best_move = None
    for r in range(3):
        for c in range(3):
            if board[r][c] == EMPTY:
                new_board = [row[:] for row in board]
                new_board[r][c] = PLAYER_O
                val = _minimax(new_board, 0, False, -100, 100)
                if val > best_val:
                    best_val = val
                    best_move = (r, c)
    return best_move


def _ai_move_easy(board):
    """Random valid move."""
    empty = [(r, c) for r in range(3) for c in range(3) if board[r][c] == EMPTY]
    return random.choice(empty) if empty else None


def _draw_x(d, cx, cy, size):
    """Draw an X shape centered at (cx, cy)."""
    half = size // 2 - 4
    d.line([(cx - half, cy - half), (cx + half, cy + half)], fill=COL_X, width=3)
    d.line([(cx - half, cy + half), (cx + half, cy - half)], fill=COL_X, width=3)


def _draw_o(d, cx, cy, size):
    """Draw an O circle centered at (cx, cy)."""
    r = size // 2 - 5
    d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=COL_O, width=3)


def draw_board(board, cur_r, cur_c, scores, hard_mode, msg=None):
    img = Image.new("RGB", (_GAME_W, _GAME_H), COL_BG)
    d = ImageDraw.Draw(img)

    # Score header
    diff_label = "HARD" if hard_mode else "EASY"
    d.text((1, 1), f"W:{scores[0]} L:{scores[1]} D:{scores[2]} [{diff_label}]",
           font=font, fill=COL_TEXT)

    ox, oy = GRID_OFFSET_X, GRID_OFFSET_Y
    # Grid lines
    for i in range(1, 3):
        x = ox + i * CELL_SIZE
        d.line([(x, oy), (x, oy + CELL_SIZE * 3)], fill=COL_GRID, width=2)
        y = oy + i * CELL_SIZE
        d.line([(ox, y), (ox + CELL_SIZE * 3, y)], fill=COL_GRID, width=2)

    # Cursor highlight
    if msg is None:
        cx0 = ox + cur_c * CELL_SIZE + 1
        cy0 = oy + cur_r * CELL_SIZE + 1
        d.rectangle([cx0, cy0, cx0 + CELL_SIZE - 2, cy0 + CELL_SIZE - 2],
                     outline=COL_CURSOR, width=2)

    # Pieces
    for r in range(3):
        for c in range(3):
            cx = ox + c * CELL_SIZE + CELL_SIZE // 2
            cy = oy + r * CELL_SIZE + CELL_SIZE // 2
            if board[r][c] == PLAYER_X:
                _draw_x(d, cx, cy, CELL_SIZE)
            elif board[r][c] == PLAYER_O:
                _draw_o(d, cx, cy, CELL_SIZE)

    if msg:
        d.rectangle([10, 54, 118, 74], fill=COL_BG, outline=COL_GRID)
        d.text((14, 58), msg, font=font, fill=COL_TEXT)

    if _GAME_W != WIDTH or _GAME_H != HEIGHT:
        img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
    LCD.LCD_ShowImage(img, 0, 0)


def play():
    global running
    scores = [0, 0, 0]  # wins, losses, draws
    hard_mode = True

    while running:
        board = [[EMPTY] * 3 for _ in range(3)]
        cur_r, cur_c = 1, 1
        player_turn = True
        game_over = False
        result_msg = None

        draw_board(board, cur_r, cur_c, scores, hard_mode)

        while running and not game_over:
            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                cleanup()
                return
            if btn == "KEY1":
                hard_mode = not hard_mode
                draw_board(board, cur_r, cur_c, scores, hard_mode)
                time.sleep(0.3)
                continue

            if player_turn:
                moved = False
                if btn == "UP" and cur_r > 0:
                    cur_r -= 1
                    moved = True
                elif btn == "DOWN" and cur_r < 2:
                    cur_r += 1
                    moved = True
                elif btn == "LEFT" and cur_c > 0:
                    cur_c -= 1
                    moved = True
                elif btn == "RIGHT" and cur_c < 2:
                    cur_c += 1
                    moved = True
                elif btn == "OK" and board[cur_r][cur_c] == EMPTY:
                    board = [row[:] for row in board]
                    board[cur_r][cur_c] = PLAYER_X
                    winner = _check_winner(board)
                    if winner is not None:
                        game_over = True
                        if winner == PLAYER_X:
                            result_msg = "YOU WIN!"
                            scores[0] += 1
                        elif winner == "draw":
                            result_msg = "DRAW!"
                            scores[2] += 1
                    else:
                        player_turn = False
                    moved = True

                if moved:
                    draw_board(board, cur_r, cur_c, scores, hard_mode,
                               result_msg if game_over else None)
                    time.sleep(0.15)
            else:
                # AI turn
                time.sleep(0.3)
                move = _ai_move_hard(board) if hard_mode else _ai_move_easy(board)
                if move:
                    board = [row[:] for row in board]
                    board[move[0]][move[1]] = PLAYER_O
                winner = _check_winner(board)
                if winner is not None:
                    game_over = True
                    if winner == PLAYER_O:
                        result_msg = "AI WINS!"
                        scores[1] += 1
                    elif winner == "draw":
                        result_msg = "DRAW!"
                        scores[2] += 1
                player_turn = True
                draw_board(board, cur_r, cur_c, scores, hard_mode,
                           result_msg if game_over else None)

            time.sleep(0.05)

        # Game over – wait for OK to replay or KEY3 to exit
        draw_board(board, cur_r, cur_c, scores, hard_mode, result_msg)
        while running:
            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                cleanup()
                return
            if btn == "OK":
                time.sleep(0.2)
                break
            time.sleep(0.05)


if __name__ == "__main__":
    try:
        play()
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
