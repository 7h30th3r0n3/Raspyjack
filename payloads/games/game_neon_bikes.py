#!/usr/bin/env python3
"""
RaspyJack Payload -- Neon Bikes (Tron Light Cycles)
====================================================
Author: 7h30th3r0n3

Grid-based Tron game on 128x128 canvas. Player controls a light bike
leaving a neon trail. AI opponent with chase/avoid algorithm.

Controls:
  UP/DOWN/LEFT/RIGHT -- Change direction
  KEY1               -- Restart after game over
  KEY3               -- Exit
"""

import os, sys, time, signal, random
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
# Grid & colours
# ---------------------------------------------------------------------------
CELL = 2
GRID_W, GRID_H = _GAME_W // CELL, _GAME_H // CELL  # 64x64

COL_BG = (0, 0, 20)
COL_GRID = (0, 0, 40)
COL_PLAYER = (0, 255, 100)
COL_PLAYER_HEAD = (150, 255, 200)
COL_AI = (255, 40, 40)
COL_AI_HEAD = (255, 150, 150)
COL_BORDER = (0, 80, 160)
COL_TEXT = (0, 255, 200)
COL_SCORE = (200, 200, 255)

# Directions: (dx, dy)
DIR_UP = (0, -1)
DIR_DOWN = (0, 1)
DIR_LEFT = (-1, 0)
DIR_RIGHT = (1, 0)
ALL_DIRS = [DIR_UP, DIR_DOWN, DIR_LEFT, DIR_RIGHT]

FPS = 12
FRAME_DT = 1.0 / FPS

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
# Helpers
# ---------------------------------------------------------------------------
def opposite(d1, d2):
    """True if directions are exact opposites."""
    return d1[0] == -d2[0] and d1[1] == -d2[1]


def in_bounds(x, y):
    """Check if position is inside the grid."""
    return 0 <= x < GRID_W and 0 <= y < GRID_H


def is_safe(x, y, trail_p, trail_a):
    """Check if a cell is safe to move into."""
    if not in_bounds(x, y):
        return False
    if (x, y) in trail_p or (x, y) in trail_a:
        return False
    return True


def count_reachable(sx, sy, trail_p, trail_a, limit=30):
    """BFS flood-fill to count reachable cells (capped for performance)."""
    visited = {(sx, sy)}
    queue = [(sx, sy)]
    count = 0
    while queue and count < limit:
        cx, cy = queue.pop(0)
        count += 1
        for dx, dy in ALL_DIRS:
            nx, ny = cx + dx, cy + dy
            if (nx, ny) not in visited and is_safe(nx, ny, trail_p, trail_a):
                visited.add((nx, ny))
                queue.append((nx, ny))
    return count


def ai_choose_direction(ax, ay, ai_dir, px, py, trail_p, trail_a):
    """AI picks a direction: avoid death, chase player when safe."""
    # Evaluate each valid direction
    candidates = []
    for d in ALL_DIRS:
        if opposite(d, ai_dir):
            continue
        nx, ny = ax + d[0], ay + d[1]
        if not is_safe(nx, ny, trail_p, trail_a):
            continue
        reach = count_reachable(nx, ny, trail_p, trail_a)
        # Distance to player (Manhattan) - prefer getting closer
        dist = abs(nx - px) + abs(ny - py)
        candidates.append((d, reach, dist))

    if not candidates:
        # No safe move, keep current direction (will crash)
        return ai_dir

    # Sort: prefer most reachable space, then closest to player
    candidates.sort(key=lambda c: (-c[1], c[2]))
    return candidates[0][0]


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------
def draw_frame(trail_p, trail_a, head_p, head_a, score, game_over_msg=None):
    """Render the full game frame to the LCD."""
    img = Image.new("RGB", (_GAME_W, _GAME_H), COL_BG)
    d = ImageDraw.Draw(img)

    # Draw border
    d.rectangle([0, 0, _GAME_W - 1, _GAME_H - 1], outline=COL_BORDER)

    # Draw trails
    for (tx, ty) in trail_p:
        x1, y1 = tx * CELL, ty * CELL
        d.rectangle([x1, y1, x1 + CELL - 1, y1 + CELL - 1], fill=COL_PLAYER)

    for (tx, ty) in trail_a:
        x1, y1 = tx * CELL, ty * CELL
        d.rectangle([x1, y1, x1 + CELL - 1, y1 + CELL - 1], fill=COL_AI)

    # Draw heads (brighter)
    if head_p:
        hx, hy = head_p
        x1, y1 = hx * CELL, hy * CELL
        d.rectangle([x1, y1, x1 + CELL - 1, y1 + CELL - 1], fill=COL_PLAYER_HEAD)

    if head_a:
        hx, hy = head_a
        x1, y1 = hx * CELL, hy * CELL
        d.rectangle([x1, y1, x1 + CELL - 1, y1 + CELL - 1], fill=COL_AI_HEAD)

    # Score at top
    d.text((3, 2), f"Score:{score}", font=font, fill=COL_SCORE)

    # Game over message
    if game_over_msg:
        bbox = d.textbbox((0, 0), game_over_msg, font=font)
        tw = bbox[2] - bbox[0]
        th = bbox[3] - bbox[1]
        cx = (_GAME_W - tw) // 2
        cy = (_GAME_H - th) // 2
        d.rectangle([cx - 4, cy - 4, cx + tw + 4, cy + th + 14],
                     fill=(0, 0, 0), outline=COL_BORDER)
        d.text((cx, cy), game_over_msg, font=font, fill=COL_TEXT)
        d.text((cx, cy + th + 4), "KEY1:Retry KEY3:Exit",
               font=font, fill=COL_SCORE)

    if _GAME_W != WIDTH or _GAME_H != HEIGHT:
        img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Game logic
# ---------------------------------------------------------------------------
def init_game_state():
    """Create fresh game state."""
    # Player starts left side, AI starts right side
    px, py = GRID_W // 4, GRID_H // 2
    ax, ay = 3 * GRID_W // 4, GRID_H // 2
    return {
        "px": px, "py": py,
        "p_dir": DIR_RIGHT,
        "trail_p": {(px, py)},
        "ax": ax, "ay": ay,
        "a_dir": DIR_LEFT,
        "trail_a": {(ax, ay)},
        "score": 0,
        "alive_p": True,
        "alive_a": True,
    }


def step_game(state, new_p_dir):
    """Advance one tick. Returns new state dict (immutable pattern)."""
    px, py = state["px"], state["py"]
    ax, ay = state["ax"], state["ay"]
    p_dir = state["p_dir"]
    a_dir = state["a_dir"]
    trail_p = set(state["trail_p"])
    trail_a = set(state["trail_a"])
    score = state["score"]

    # Update player direction (no reversals)
    if new_p_dir and not opposite(new_p_dir, p_dir):
        p_dir = new_p_dir

    # AI direction
    a_dir = ai_choose_direction(ax, ay, a_dir, px, py, trail_p, trail_a)

    # Move player
    npx, npy = px + p_dir[0], py + p_dir[1]
    alive_p = is_safe(npx, npy, trail_p, trail_a)

    # Move AI
    nax, nay = ax + a_dir[0], ay + a_dir[1]
    alive_a = is_safe(nax, nay, trail_p, trail_a)

    # Head-on collision
    if (npx, npy) == (nax, nay):
        alive_p = False
        alive_a = False

    if alive_p:
        trail_p.add((npx, npy))
        px, py = npx, npy
        score += 1

    if alive_a:
        trail_a.add((nax, nay))
        ax, ay = nax, nay

    return {
        "px": px, "py": py,
        "p_dir": p_dir,
        "trail_p": trail_p,
        "ax": ax, "ay": ay,
        "a_dir": a_dir,
        "trail_a": trail_a,
        "score": score,
        "alive_p": alive_p,
        "alive_a": alive_a,
    }


# ---------------------------------------------------------------------------
# Main game loop
# ---------------------------------------------------------------------------
def play():
    """Single round of Neon Bikes."""
    state = init_game_state()
    pending_dir = None

    while running:
        t0 = time.time()

        # Read input
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            return

        dir_map = {
            "UP": DIR_UP, "DOWN": DIR_DOWN,
            "LEFT": DIR_LEFT, "RIGHT": DIR_RIGHT,
        }
        if btn in dir_map:
            pending_dir = dir_map[btn]

        # Step game
        state = step_game(state, pending_dir)
        pending_dir = None

        # Check end conditions
        if not state["alive_p"]:
            msg = "YOU CRASHED!" if state["alive_a"] else "DRAW!"
            draw_frame(state["trail_p"], state["trail_a"],
                       (state["px"], state["py"]),
                       (state["ax"], state["ay"]),
                       state["score"], msg)
            # Wait for restart or exit
            while running:
                b = get_button(PINS, GPIO)
                if b == "KEY3":
                    return
                if b == "KEY1":
                    time.sleep(0.2)
                    play()
                    return
                time.sleep(0.05)
            return

        if not state["alive_a"]:
            draw_frame(state["trail_p"], state["trail_a"],
                       (state["px"], state["py"]),
                       (state["ax"], state["ay"]),
                       state["score"], "AI CRASHED!")
            while running:
                b = get_button(PINS, GPIO)
                if b == "KEY3":
                    return
                if b == "KEY1":
                    time.sleep(0.2)
                    play()
                    return
                time.sleep(0.05)
            return

        # Render
        draw_frame(state["trail_p"], state["trail_a"],
                   (state["px"], state["py"]),
                   (state["ax"], state["ay"]),
                   state["score"])

        # Frame rate cap
        elapsed = time.time() - t0
        time.sleep(max(0, FRAME_DT - elapsed))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        play()
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
