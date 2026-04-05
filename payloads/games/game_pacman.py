#!/usr/bin/env python3
"""
RaspyJack Payload -- Pac-Man
-----------------------------
Author: 7h30th3r0n3

Controls: D-pad=move, OK=start/pause, KEY1=restart, KEY3=exit
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

CELL = 8
COLS, ROWS = 16, 16
COL_BG = (0, 0, 0)
COL_WALL = (0, 80, 0)
COL_DOT = (0, 200, 0)
COL_PELLET = (0, 255, 0)
COL_PAC = (255, 255, 0)
COL_TEXT = (0, 255, 0)
COL_SCARED = (0, 0, 255)
GHOST_COLS = [(255, 0, 0), (255, 184, 222), (0, 255, 255), (255, 184, 82)]

# 1=wall, 0=path, 2=dot, 3=power pellet, 4=ghost pen (no dot)
_BASE = [
    "1111111111111111",
    "1222222112222221",
    "1311211112112131",
    "1212211112112121",
    "1222222222222221",
    "1211211111211211",
    "1222211111222221",
    "1111200044001111",
    "1111200044001111",
    "1222211111222221",
    "1211211111211211",
    "1222222222222221",
    "1212211112112121",
    "1311211112112131",
    "1222222112222221",
    "1111111111111111",
]

running = True


def _parse_maze():
    """Return fresh maze grid as list of lists of ints."""
    return [[int(ch) for ch in row] for row in _BASE]


def _count_dots(maze):
    total = 0
    for row in maze:
        for c in row:
            if c in (2, 3):
                total += 1
    return total


def cleanup(*_):
    global running
    running = False


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

DIR_MAP = {"UP": (0, -1), "DOWN": (0, 1), "LEFT": (-1, 0), "RIGHT": (1, 0)}
OPPOSITE = {(0, -1): (0, 1), (0, 1): (0, -1), (-1, 0): (1, 0), (1, 0): (-1, 0)}


def _can_move(maze, x, y, dx, dy):
    nx, ny = (x + dx) % COLS, (y + dy) % ROWS
    return maze[ny][nx] != 1


def _clamp(x, y):
    return x % COLS, y % ROWS


class Ghost:
    def __init__(self, idx, x, y):
        self.idx = idx
        self.x = x
        self.y = y
        self.dx, self.dy = 0, -1
        self.scared = False
        self.eaten = False
        self.pen = True
        self.release_time = time.time() + idx * 4

    def target(self, pac_x, pac_y, pac_dx, pac_dy, blinky_x, blinky_y):
        if self.scared:
            return (random.randint(0, COLS - 1), random.randint(0, ROWS - 1))
        if self.idx == 0:  # Blinky: chase directly
            return (pac_x, pac_y)
        if self.idx == 1:  # Pinky: 4 ahead
            return ((pac_x + pac_dx * 4) % COLS, (pac_y + pac_dy * 4) % ROWS)
        if self.idx == 2:  # Inky: mirror of blinky
            tx = (2 * (pac_x + pac_dx * 2) - blinky_x) % COLS
            ty = (2 * (pac_y + pac_dy * 2) - blinky_y) % ROWS
            return (tx, ty)
        # Clyde: chase when far, scatter when close
        dist = abs(self.x - pac_x) + abs(self.y - pac_y)
        if dist > 8:
            return (pac_x, pac_y)
        return (0, ROWS - 1)

    def move(self, maze, pac_x, pac_y, pac_dx, pac_dy, blinky_x, blinky_y):
        if self.pen:
            if time.time() >= self.release_time:
                self.pen = False
                self.x, self.y = 7, 6
            return
        tx, ty = self.target(pac_x, pac_y, pac_dx, pac_dy, blinky_x, blinky_y)
        best_dir = (self.dx, self.dy)
        best_dist = 9999
        opp = OPPOSITE.get((self.dx, self.dy), (0, 0))
        for ddx, ddy in [(0, -1), (0, 1), (-1, 0), (1, 0)]:
            if (ddx, ddy) == opp:
                continue
            if _can_move(maze, self.x, self.y, ddx, ddy):
                nx, ny = (self.x + ddx) % COLS, (self.y + ddy) % ROWS
                d = abs(nx - tx) + abs(ny - ty)
                if d < best_dist:
                    best_dist = d
                    best_dir = (ddx, ddy)
        self.dx, self.dy = best_dir
        if _can_move(maze, self.x, self.y, self.dx, self.dy):
            self.x, self.y = _clamp(self.x + self.dx, self.y + self.dy)


def draw_frame(maze, pac_x, pac_y, ghosts, score, lives, paused, msg=None):
    img = Image.new("RGB", (_GAME_W, _GAME_H), COL_BG)
    d = ImageDraw.Draw(img)
    for ry in range(ROWS):
        for rx in range(COLS):
            cell = maze[ry][rx]
            px, py = rx * CELL, ry * CELL
            if cell == 1:
                d.rectangle([px, py, px + CELL - 1, py + CELL - 1], fill=COL_WALL)
            elif cell == 2:
                cx, cy = px + CELL // 2, py + CELL // 2
                d.ellipse([cx - 1, cy - 1, cx + 1, cy + 1], fill=COL_DOT)
            elif cell == 3:
                cx, cy = px + CELL // 2, py + CELL // 2
                d.ellipse([cx - 3, cy - 3, cx + 3, cy + 3], fill=COL_PELLET)
    # Pac-Man
    px, py = pac_x * CELL + CELL // 2, pac_y * CELL + CELL // 2
    d.ellipse([px - 3, py - 3, px + 3, py + 3], fill=COL_PAC)
    # Ghosts
    for g in ghosts:
        if g.pen and time.time() < g.release_time:
            continue
        gx, gy = g.x * CELL, g.y * CELL
        col = COL_SCARED if g.scared else GHOST_COLS[g.idx]
        d.rectangle([gx + 1, gy + 1, gx + CELL - 2, gy + CELL - 2], fill=col)
        d.rectangle([gx + 2, gy + 2, gx + 3, gy + 3], fill=(255, 255, 255))
        d.rectangle([gx + 5, gy + 2, gx + 6, gy + 3], fill=(255, 255, 255))
    # HUD
    d.text((1, 0), f"S:{score}", font=font, fill=COL_TEXT)
    for i in range(lives):
        d.ellipse([100 + i * 10, 1, 106 + i * 10, 7], fill=COL_PAC)
    if paused:
        d.text((40, 60), "PAUSED", font=font, fill=COL_TEXT)
    if msg:
        d.text((20, 56), msg, font=font, fill=COL_TEXT)
    if _GAME_W != WIDTH or _GAME_H != HEIGHT:
        img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
    LCD.LCD_ShowImage(img, 0, 0)


def play():
    global running
    maze = _parse_maze()
    pac_x, pac_y = 1, 1
    pac_dx, pac_dy = 1, 0
    next_dx, next_dy = 1, 0
    score = 0
    lives = 3
    dots_left = _count_dots(maze)
    paused = False
    ghosts = [Ghost(i, 7 + (i % 2), 7 + (i // 2)) for i in range(4)]
    scared_timer = 0.0
    ghost_combo = 0
    move_tick = 0

    # Title screen
    draw_frame(maze, pac_x, pac_y, ghosts, score, lives, False, "OK TO START")
    while running:
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            cleanup()
            return
        if btn == "OK":
            time.sleep(0.2)
            break
        time.sleep(0.05)

    while running:
        t_start = time.time()
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            cleanup()
            return
        if btn == "KEY1":
            time.sleep(0.2)
            play()
            return
        if btn == "OK":
            paused = not paused
            time.sleep(0.2)
        if not paused and btn in DIR_MAP:
            next_dx, next_dy = DIR_MAP[btn]

        if paused:
            draw_frame(maze, pac_x, pac_y, ghosts, score, lives, True)
            time.sleep(0.05)
            continue

        # Move pac-man every other tick for slower speed
        move_tick += 1
        if move_tick % 2 == 0:
            if _can_move(maze, pac_x, pac_y, next_dx, next_dy):
                pac_dx, pac_dy = next_dx, next_dy
            if _can_move(maze, pac_x, pac_y, pac_dx, pac_dy):
                pac_x, pac_y = _clamp(pac_x + pac_dx, pac_y + pac_dy)
            cell = maze[pac_y][pac_x]
            if cell == 2:
                maze[pac_y][pac_x] = 0
                score += 10
                dots_left -= 1
            elif cell == 3:
                maze[pac_y][pac_x] = 0
                score += 50
                dots_left -= 1
                scared_timer = time.time() + 5.0
                ghost_combo = 0
                for g in ghosts:
                    if not g.pen:
                        g.scared = True

        # Move ghosts every 3rd tick
        if move_tick % 3 == 0:
            bx, by = ghosts[0].x, ghosts[0].y
            for g in ghosts:
                g.move(maze, pac_x, pac_y, pac_dx, pac_dy, bx, by)

        # Scared timer
        if scared_timer and time.time() > scared_timer:
            scared_timer = 0.0
            for g in ghosts:
                g.scared = False

        # Collision check
        for g in ghosts:
            if g.pen:
                continue
            if g.x == pac_x and g.y == pac_y:
                if g.scared:
                    ghost_combo += 1
                    score += 200 * ghost_combo
                    g.x, g.y = 7, 7
                    g.pen = True
                    g.release_time = time.time() + 3
                    g.scared = False
                else:
                    lives -= 1
                    if lives <= 0:
                        draw_frame(maze, pac_x, pac_y, ghosts, score, lives, False, "GAME OVER")
                        _wait_end()
                        return
                    pac_x, pac_y = 1, 1
                    pac_dx, pac_dy = 1, 0
                    next_dx, next_dy = 1, 0
                    for gg in ghosts:
                        gg.x, gg.y = 7 + (gg.idx % 2), 7 + (gg.idx // 2)
                        gg.pen = True
                        gg.release_time = time.time() + gg.idx * 3
                        gg.scared = False
                    scared_timer = 0.0
                    time.sleep(0.5)
                    break

        if dots_left <= 0:
            draw_frame(maze, pac_x, pac_y, ghosts, score, lives, False, "YOU WIN!")
            _wait_end()
            return

        draw_frame(maze, pac_x, pac_y, ghosts, score, lives, False)
        elapsed = time.time() - t_start
        time.sleep(max(0, 0.06 - elapsed))


def _wait_end():
    """Wait for KEY1 (restart) or KEY3 (exit)."""
    while running:
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            cleanup()
            return
        if btn in ("OK", "KEY1"):
            time.sleep(0.2)
            play()
            return
        time.sleep(0.05)


if __name__ == "__main__":
    try:
        play()
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
