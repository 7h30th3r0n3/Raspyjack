#!/usr/bin/env python3
"""
RaspyJack payload -- Sokoban
============================
Author: 7h30th3r0n3

Classic Sokoban puzzle game on LCD. Push boxes onto targets.
10 built-in levels of increasing difficulty.

Controls: D-pad=move, OK=undo, KEY1=restart level, KEY2=skip level, KEY3=exit.
"""

import os, sys, time
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import signal
import copy

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
# Colours (green/black RaspyJack theme)
# ---------------------------------------------------------------------------
COL_BG = (0, 0, 0)
COL_WALL = (80, 80, 80)
COL_FLOOR = (20, 20, 20)
COL_PLAYER = (0, 255, 0)
COL_BOX = (180, 100, 0)
COL_BOX_ON = (255, 200, 0)
COL_TARGET = (200, 0, 0)
COL_TEXT = (0, 255, 0)
COL_DIM = (0, 120, 0)

# ---------------------------------------------------------------------------
# Levels (classic Sokoban format)
# '#'=wall ' '=floor '$'=box '.'=target '@'=player '*'=box-on-target '+'=player-on-target
# ---------------------------------------------------------------------------
RAW_LEVELS = [
    # Level 1
    [
        "  ####  ",
        "  #  #  ",
        "  #$ #  ",
        "###  ###",
        "#  . @ #",
        "#   ####",
        "#####   ",
    ],
    # Level 2
    [
        "######  ",
        "#    #  ",
        "# #$ #  ",
        "# . @#  ",
        "#  ###  ",
        "####    ",
    ],
    # Level 3
    [
        "  ####  ",
        "###  #  ",
        "# $  #  ",
        "#  .@#  ",
        "# $  #  ",
        "#  . #  ",
        "######  ",
    ],
    # Level 4
    [
        " #####  ",
        " # . #  ",
        " # $ ## ",
        "## $  # ",
        "#  .@ # ",
        "#     # ",
        "####### ",
    ],
    # Level 5
    [
        "########",
        "#      #",
        "# .$. @#",
        "# .$.  #",
        "#      #",
        "########",
    ],
    # Level 6
    [
        "  ##### ",
        "  #   # ",
        "###$# # ",
        "# $ . # ",
        "#  .#@# ",
        "# $. ## ",
        "#    #  ",
        "######  ",
    ],
    # Level 7
    [
        " ###### ",
        " #    # ",
        "##$## ##",
        "# $  . #",
        "# .  $ #",
        "## ##. #",
        " # @  # ",
        " ###### ",
    ],
    # Level 8
    [
        "  ##### ",
        "###   # ",
        "#  $  # ",
        "# #.# # ",
        "# $@$ # ",
        "# #.# # ",
        "#  .  # ",
        "###  ## ",
        "  ####  ",
    ],
    # Level 9
    [
        "########",
        "#  #   #",
        "# $$ . #",
        "#  # . #",
        "# @$$. #",
        "#  #   #",
        "########",
    ],
    # Level 10
    [
        " #######",
        " #  .  #",
        "##$### #",
        "# $ .  #",
        "#  $# ##",
        "## .@ # ",
        " #  $ # ",
        " # .# # ",
        " #    # ",
        " ###### ",
    ],
]


def parse_level(raw):
    """Parse a raw level into (walls, boxes, targets, player, rows, cols)."""
    rows = len(raw)
    cols = max(len(row) for row in raw)
    walls = set()
    boxes = set()
    targets = set()
    player = (0, 0)
    for r, line in enumerate(raw):
        for c, ch in enumerate(line):
            if ch == '#':
                walls.add((r, c))
            elif ch == '$':
                boxes.add((r, c))
            elif ch == '.':
                targets.add((r, c))
            elif ch == '@':
                player = (r, c)
            elif ch == '*':
                boxes.add((r, c))
                targets.add((r, c))
            elif ch == '+':
                player = (r, c)
                targets.add((r, c))
    return frozenset(walls), boxes, frozenset(targets), player, rows, cols


# ---------------------------------------------------------------------------
# State (immutable snapshots for undo)
# ---------------------------------------------------------------------------
def make_state(boxes, player, moves):
    """Create an immutable state snapshot."""
    return {"boxes": frozenset(boxes), "player": player, "moves": moves}


def push_history(history, state):
    """Return new history with state appended."""
    return history + [state]


def pop_history(history):
    """Return (new_history, popped_state) or (history, None)."""
    if len(history) < 2:
        return history, None
    return history[:-1], history[-1]


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------
def draw_level(walls, boxes, targets, player, rows, cols, level_num, moves):
    """Render the Sokoban grid and HUD."""
    # Calculate cell size and offset to center the grid
    cell_w = min(10, (_GAME_W - 4) // cols)
    cell_h = min(10, (_GAME_H - 16) // rows)
    cell = min(cell_w, cell_h)
    ox = (_GAME_W - cols * cell) // 2
    oy = 14 + (_GAME_H - 14 - rows * cell) // 2

    img = Image.new("RGB", (_GAME_W, _GAME_H), COL_BG)
    d = ImageDraw.Draw(img)

    # HUD
    d.text((2, 2), f"Lv:{level_num}", font=font, fill=COL_TEXT)
    d.text((60, 2), f"Mv:{moves}", font=font, fill=COL_DIM)

    # Grid
    for r in range(rows):
        for c in range(cols):
            x1 = ox + c * cell
            y1 = oy + r * cell
            x2 = x1 + cell - 1
            y2 = y1 + cell - 1
            pos = (r, c)

            if pos in walls:
                d.rectangle([x1, y1, x2, y2], fill=COL_WALL)
            else:
                # Floor background for non-wall reachable cells
                d.rectangle([x1, y1, x2, y2], fill=COL_FLOOR)

                if pos in targets and pos in boxes:
                    # Box on target
                    d.rectangle([x1 + 1, y1 + 1, x2 - 1, y2 - 1], fill=COL_BOX_ON)
                elif pos in boxes:
                    d.rectangle([x1 + 1, y1 + 1, x2 - 1, y2 - 1], fill=COL_BOX)
                elif pos in targets:
                    # Target marker (diamond)
                    mx = (x1 + x2) // 2
                    my = (y1 + y2) // 2
                    s = max(1, cell // 4)
                    d.polygon([(mx, my - s), (mx + s, my),
                               (mx, my + s), (mx - s, my)], fill=COL_TARGET)

                if pos == player:
                    d.rectangle([x1 + 1, y1 + 1, x2 - 1, y2 - 1], fill=COL_PLAYER)

    if _GAME_W != WIDTH or _GAME_H != HEIGHT:
        img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
    LCD.LCD_ShowImage(img, 0, 0)


def draw_message(line1, line2=""):
    """Show a centered message."""
    img = Image.new("RGB", (_GAME_W, _GAME_H), COL_BG)
    d = ImageDraw.Draw(img)
    bbox1 = d.textbbox((0, 0), line1, font=font)
    w1 = bbox1[2] - bbox1[0]
    d.text(((_GAME_W - w1) // 2, _GAME_H // 2 - 14), line1, font=font, fill=COL_TEXT)
    if line2:
        bbox2 = d.textbbox((0, 0), line2, font=font)
        w2 = bbox2[2] - bbox2[0]
        d.text(((_GAME_W - w2) // 2, _GAME_H // 2 + 2), line2, font=font, fill=COL_DIM)
    if _GAME_W != WIDTH or _GAME_H != HEIGHT:
        img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Win animation
# ---------------------------------------------------------------------------
def win_animation():
    """Flash a congratulations screen."""
    for i in range(6):
        col = COL_TEXT if i % 2 == 0 else COL_BG
        img = Image.new("RGB", (_GAME_W, _GAME_H), COL_BG)
        d = ImageDraw.Draw(img)
        txt = "COMPLETE!"
        bbox = d.textbbox((0, 0), txt, font=font)
        w = bbox[2] - bbox[0]
        d.text(((_GAME_W - w) // 2, _GAME_H // 2 - 6), txt, font=font, fill=col)
        if _GAME_W != WIDTH or _GAME_H != HEIGHT:
            img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(0.3)


# ---------------------------------------------------------------------------
# Movement logic
# ---------------------------------------------------------------------------
DIRECTIONS = {"UP": (-1, 0), "DOWN": (1, 0), "LEFT": (0, -1), "RIGHT": (0, 1)}


def try_move(walls, boxes, player, direction):
    """Attempt a move. Returns (new_boxes, new_player, moved)."""
    dr, dc = direction
    nr, nc = player[0] + dr, player[1] + dc
    new_pos = (nr, nc)

    # Can't walk into a wall
    if new_pos in walls:
        return boxes, player, False

    # Pushing a box
    if new_pos in boxes:
        box_dest = (nr + dr, nc + dc)
        # Can't push box into wall or another box
        if box_dest in walls or box_dest in boxes:
            return boxes, player, False
        # Move box (immutable: create new set)
        new_boxes = (boxes - {new_pos}) | {box_dest}
        return new_boxes, new_pos, True

    # Empty floor
    return boxes, new_pos, True


def is_complete(boxes, targets):
    """Check if all targets have boxes on them."""
    return targets.issubset(boxes)


# ---------------------------------------------------------------------------
# Main game loop
# ---------------------------------------------------------------------------
running = True


def cleanup_handler(*_):
    global running
    running = False


signal.signal(signal.SIGINT, cleanup_handler)
signal.signal(signal.SIGTERM, cleanup_handler)


def play():
    """Run all levels."""
    current_level = 0

    while running and current_level < len(RAW_LEVELS):
        walls, init_boxes, targets, init_player, rows, cols = parse_level(
            RAW_LEVELS[current_level]
        )
        boxes = set(init_boxes)
        player = init_player
        moves = 0
        history = [make_state(boxes, player, moves)]
        last_btn = None

        while running:
            draw_level(walls, boxes, targets, player, rows, cols,
                       current_level + 1, moves)

            # Wait for input
            btn = None
            while running and btn is None:
                btn = get_button(PINS, GPIO)
                if btn is None:
                    time.sleep(0.03)

            if btn == "KEY3":
                return

            if btn == "KEY1":
                # Restart level
                boxes = set(init_boxes)
                player = init_player
                moves = 0
                history = [make_state(boxes, player, moves)]
                continue

            if btn == "KEY2":
                # Skip level
                current_level += 1
                break

            if btn == "OK":
                # Undo
                new_hist, prev = pop_history(history)
                if prev is not None:
                    history = new_hist
                    last_state = history[-1]
                    boxes = set(last_state["boxes"])
                    player = last_state["player"]
                    moves = last_state["moves"]
                time.sleep(0.15)
                continue

            if btn in DIRECTIONS:
                new_boxes, new_player, moved = try_move(
                    walls, boxes, player, DIRECTIONS[btn]
                )
                if moved:
                    boxes = new_boxes
                    player = new_player
                    moves += 1
                    history = push_history(history, make_state(boxes, player, moves))

                # Check win
                if is_complete(frozenset(boxes), targets):
                    draw_level(walls, boxes, targets, player, rows, cols,
                               current_level + 1, moves)
                    time.sleep(0.5)
                    win_animation()
                    current_level += 1
                    break

            time.sleep(0.12)

    # All levels complete
    if running:
        draw_message("ALL LEVELS DONE!", "KEY3=Exit")
        while running:
            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                return
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
