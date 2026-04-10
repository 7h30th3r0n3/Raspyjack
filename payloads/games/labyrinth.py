#!/usr/bin/env python3
"""
RaspyJack Payload -- Random Labyrinth
=======================================
Author: 7h30th3r0n3

Generates random mazes using recursive backtracking (DFS).
Navigate from top-left to bottom-right exit.
Timer tracks completion speed. KEY2 reveals solution path.

Controls:
  UP/DOWN/LEFT/RIGHT -- Move player
  KEY1               -- New maze after completion
  KEY2               -- Show solution path briefly
  KEY3               -- Exit
"""

import os, sys, time, signal, random
from collections import deque
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._input_helper import get_button

# ---------------------------------------------------------------------------
# GPIO
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

# ---------------------------------------------------------------------------
# LCD
# ---------------------------------------------------------------------------
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
_GAME_W, _GAME_H = 128, 128

font = ImageFont.load_default()

# ---------------------------------------------------------------------------
# Maze constants
# ---------------------------------------------------------------------------
MAZE_COLS = 15
MAZE_ROWS = 15

# Each cell is CELL_SIZE pixels; walls are drawn as part of the cell
HUD_TOP = 12
AVAILABLE_H = _GAME_H - HUD_TOP
CELL_SIZE = min((_GAME_W - 2) // MAZE_COLS, AVAILABLE_H // MAZE_ROWS)
MAZE_PX_W = MAZE_COLS * CELL_SIZE
MAZE_PX_H = MAZE_ROWS * CELL_SIZE
OFFSET_X = (_GAME_W - MAZE_PX_W) // 2
OFFSET_Y = HUD_TOP + (AVAILABLE_H - MAZE_PX_H) // 2

# Directions: (dr, dc)
DIR_N = (-1, 0)
DIR_S = (1, 0)
DIR_W = (0, -1)
DIR_E = (0, 1)
DIRECTIONS = [DIR_N, DIR_S, DIR_W, DIR_E]
OPPOSITE = {DIR_N: DIR_S, DIR_S: DIR_N, DIR_W: DIR_E, DIR_E: DIR_W}

# Colours
COL_BG = (0, 0, 0)
COL_WALL = (200, 200, 220)
COL_PATH = (10, 10, 20)
COL_PLAYER = (0, 255, 80)
COL_EXIT = (255, 40, 40)
COL_SOLUTION = (80, 80, 255)
COL_VISITED = (20, 30, 20)
COL_TEXT = (0, 255, 200)
COL_TIME = (200, 200, 255)
COL_WIN = (255, 255, 0)

# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------
running = True


def cleanup(*_):
    global running
    running = False


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)


# ---------------------------------------------------------------------------
# Maze generation (recursive backtracking / DFS)
# ---------------------------------------------------------------------------
def generate_maze(rows, cols):
    """Generate maze using DFS. Returns a set of open passages.

    The maze is represented as a grid where each cell tracks which
    walls have been removed. We store passages as a set of
    ((r1,c1),(r2,c2)) tuples indicating connected cells.
    """
    visited = set()
    passages = set()
    stack = [(0, 0)]
    visited.add((0, 0))

    while stack:
        r, c = stack[-1]
        neighbors = []
        for dr, dc in DIRECTIONS:
            nr, nc = r + dr, c + dc
            if 0 <= nr < rows and 0 <= nc < cols and (nr, nc) not in visited:
                neighbors.append((nr, nc, dr, dc))

        if neighbors:
            nr, nc, dr, dc = random.choice(neighbors)
            passages.add(((r, c), (nr, nc)))
            passages.add(((nr, nc), (r, c)))
            visited.add((nr, nc))
            stack.append((nr, nc))
        else:
            stack.pop()

    return passages


def has_passage(passages, r1, c1, r2, c2):
    """Check if there is a passage between two adjacent cells."""
    return ((r1, c1), (r2, c2)) in passages


# ---------------------------------------------------------------------------
# BFS pathfinding for solution
# ---------------------------------------------------------------------------
def solve_maze(passages, start, end, rows, cols):
    """BFS to find shortest path from start to end. Returns list of cells."""
    queue = deque([(start, [start])])
    visited = {start}

    while queue:
        (r, c), path = queue.popleft()
        if (r, c) == end:
            return path
        for dr, dc in DIRECTIONS:
            nr, nc = r + dr, c + dc
            if (0 <= nr < rows and 0 <= nc < cols
                    and (nr, nc) not in visited
                    and has_passage(passages, r, c, nr, nc)):
                visited.add((nr, nc))
                queue.append(((nr, nc), path + [(nr, nc)]))
    return []


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------
def cell_rect(r, c):
    """Get pixel rectangle for a cell."""
    x1 = OFFSET_X + c * CELL_SIZE
    y1 = OFFSET_Y + r * CELL_SIZE
    return x1, y1, x1 + CELL_SIZE - 1, y1 + CELL_SIZE - 1


def draw_maze(passages, player, visited_cells, timer_sec,
              solution=None, win=False):
    """Render the maze, player, and HUD."""
    img = Image.new("RGB", (_GAME_W, _GAME_H), COL_BG)
    d = ImageDraw.Draw(img)

    exit_pos = (MAZE_ROWS - 1, MAZE_COLS - 1)

    # Draw cells
    for r in range(MAZE_ROWS):
        for c in range(MAZE_COLS):
            x1, y1, x2, y2 = cell_rect(r, c)

            # Cell background
            if (r, c) == exit_pos:
                d.rectangle([x1, y1, x2, y2], fill=COL_EXIT)
            elif (r, c) in visited_cells:
                d.rectangle([x1, y1, x2, y2], fill=COL_VISITED)
            else:
                d.rectangle([x1, y1, x2, y2], fill=COL_PATH)

            # Draw walls (only right and bottom to avoid doubling)
            # Top wall
            if r == 0 or not has_passage(passages, r, c, r - 1, c):
                d.line([(x1, y1), (x2, y1)], fill=COL_WALL)
            # Left wall
            if c == 0 or not has_passage(passages, r, c, r, c - 1):
                d.line([(x1, y1), (x1, y2)], fill=COL_WALL)
            # Bottom wall
            if r == MAZE_ROWS - 1 or not has_passage(passages, r, c, r + 1, c):
                d.line([(x1, y2), (x2, y2)], fill=COL_WALL)
            # Right wall
            if c == MAZE_COLS - 1 or not has_passage(passages, r, c, r, c + 1):
                d.line([(x2, y1), (x2, y2)], fill=COL_WALL)

    # Solution path overlay
    if solution:
        for r, c in solution:
            x1, y1, x2, y2 = cell_rect(r, c)
            cx = (x1 + x2) // 2
            cy = (y1 + y2) // 2
            s = max(1, CELL_SIZE // 4)
            d.ellipse([cx - s, cy - s, cx + s, cy + s], fill=COL_SOLUTION)

    # Player
    pr, pc = player
    px1, py1, px2, py2 = cell_rect(pr, pc)
    margin = max(1, CELL_SIZE // 4)
    d.rectangle([px1 + margin, py1 + margin, px2 - margin, py2 - margin],
                fill=COL_PLAYER)

    # HUD
    minutes = int(timer_sec) // 60
    seconds = int(timer_sec) % 60
    time_str = f"{minutes}:{seconds:02d}"
    d.text((2, 1), f"TIME {time_str}", font=font, fill=COL_TIME)

    if win:
        d.rectangle([14, 50, 114, 78], fill=(0, 0, 0), outline=COL_WIN)
        d.text((22, 53), f"COMPLETE! {time_str}", font=font, fill=COL_WIN)
        d.text((22, 65), "KEY1:New  KEY3:Exit", font=font, fill=COL_TIME)

    if _GAME_W != WIDTH or _GAME_H != HEIGHT:
        img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main game loop
# ---------------------------------------------------------------------------
def play():
    """Play the labyrinth game."""
    passages = generate_maze(MAZE_ROWS, MAZE_COLS)
    player = (0, 0)
    exit_pos = (MAZE_ROWS - 1, MAZE_COLS - 1)
    visited_cells = {player}
    start_time = time.time()
    show_solution_until = 0.0
    won = False

    while running:
        now = time.time()
        elapsed = now - start_time

        # Input
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            return

        if won:
            if btn == "KEY1":
                time.sleep(0.2)
                play()
                return
        else:
            # Movement
            dir_map = {
                "UP": DIR_N, "DOWN": DIR_S,
                "LEFT": DIR_W, "RIGHT": DIR_E,
            }
            if btn in dir_map:
                dr, dc = dir_map[btn]
                nr, nc = player[0] + dr, player[1] + dc
                if (0 <= nr < MAZE_ROWS and 0 <= nc < MAZE_COLS
                        and has_passage(passages, player[0], player[1], nr, nc)):
                    player = (nr, nc)
                    visited_cells = visited_cells | {player}

                    # Check win
                    if player == exit_pos:
                        won = True

            # Show solution briefly
            if btn == "KEY2" and not won:
                show_solution_until = now + 2.0

        # Determine if solution should be shown
        solution = None
        if 0 < show_solution_until and now < show_solution_until:
            solution = solve_maze(passages, player, exit_pos,
                                  MAZE_ROWS, MAZE_COLS)

        # Render
        draw_maze(passages, player, visited_cells,
                  elapsed, solution=solution, win=won)

        time.sleep(0.08)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        play()
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
