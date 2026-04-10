#!/usr/bin/env python3
"""
RaspyJack Payload -- Frogger
-----------------------------
Author: 7h30th3r0n3

Controls: D-pad=move frog, OK=start/pause, KEY1=restart, KEY3=exit
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
COL_FROG = (0, 200, 0)
COL_FROG_DARK = (0, 120, 0)
COL_ROAD = (40, 40, 40)
COL_WATER = (0, 0, 140)
COL_LOG = (139, 90, 43)
COL_HOME = (0, 100, 0)
COL_HOME_FILLED = (0, 255, 0)
COL_SAFE = (0, 60, 0)
COL_TEXT = (0, 255, 0)
CAR_COLS = [(255, 0, 0), (255, 255, 255), (255, 255, 0), (255, 100, 0)]

# Row layout (0=top, 15=bottom):
# Row 0:  home slots
# Row 1:  safe zone
# Rows 2-5:  river (logs)
# Row 6:  safe zone (middle)
# Rows 7-11: road (cars)
# Row 12: safe zone
# Rows 13-14: grass/start area
# Row 15: HUD
ROW_HOME = 0
ROW_SAFE_TOP = 1
RIVER_ROWS = [2, 3, 4, 5]
ROW_SAFE_MID = 6
ROAD_ROWS = [7, 8, 9, 10, 11]
ROW_SAFE_BOT = 12
START_ROWS = [13, 14]
ROW_HUD = 15

HOME_SLOTS = [1, 4, 7, 10, 13]  # x positions for 5 home slots

running = True


def cleanup(*_):
    global running
    running = False


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)


class Lane:
    """A single row of moving objects (cars or logs)."""
    def __init__(self, row, speed, obj_len, gap, is_river, direction):
        self.row = row
        self.speed = speed  # pixels per frame
        self.obj_len = obj_len  # length in pixels
        self.gap = gap  # gap between objects in pixels
        self.is_river = is_river
        self.direction = direction  # 1=right, -1=left
        self.offset = 0.0
        total = self.obj_len + self.gap
        self.positions = list(range(0, _GAME_W + total, total))

    def update(self, speed_mult=1.0):
        self.offset += self.speed * self.direction * speed_mult
        if abs(self.offset) > (self.obj_len + self.gap):
            self.offset = self.offset % (self.obj_len + self.gap) if self.direction > 0 \
                else -(abs(self.offset) % (self.obj_len + self.gap))

    def get_rects(self):
        """Return list of (x_start, x_end) pixel positions for objects."""
        total = self.obj_len + self.gap
        rects = []
        start_x = -total + int(self.offset) % total - total
        while start_x < _GAME_W + total:
            rects.append((start_x, start_x + self.obj_len))
            start_x += total
        return rects

    def has_object_at(self, px):
        """Check if pixel x coordinate overlaps with any object."""
        for x0, x1 in self.get_rects():
            if x0 <= px < x1:
                return True
        return False

    def get_carry_offset(self, px):
        """For river lanes, return the speed to carry the frog."""
        if self.is_river and self.has_object_at(px):
            return self.speed * self.direction
        return 0


def _build_lanes(speed_mult):
    """Create lane definitions for roads and rivers."""
    lanes = {}
    # Road lanes (cars) - rows 7-11
    road_defs = [
        (7, 1.2, 16, 30, -1),
        (8, 0.8, 24, 28, 1),
        (9, 1.5, 12, 22, -1),
        (10, 1.0, 20, 26, 1),
        (11, 0.6, 16, 32, -1),
    ]
    for row, spd, length, gap, direction in road_defs:
        lanes[row] = Lane(row, spd, length, gap, False, direction)

    # River lanes (logs) - rows 2-5
    river_defs = [
        (2, 0.7, 32, 24, 1),
        (3, 1.0, 24, 30, -1),
        (4, 0.5, 40, 20, 1),
        (5, 0.9, 28, 26, -1),
    ]
    for row, spd, length, gap, direction in river_defs:
        lanes[row] = Lane(row, spd, length, gap, True, direction)

    return lanes


def draw_frame(frog_x, frog_y, lanes, homes_filled, score, lives, level,
               timer_left, paused, msg=None):
    img = Image.new("RGB", (_GAME_W, _GAME_H), COL_BG)
    d = ImageDraw.Draw(img)

    # Draw row backgrounds
    for row in range(ROWS):
        y0 = row * CELL
        y1 = y0 + CELL
        if row == ROW_HOME:
            d.rectangle([0, y0, _GAME_W, y1], fill=COL_WATER)
        elif row in (ROW_SAFE_TOP, ROW_SAFE_MID, ROW_SAFE_BOT):
            d.rectangle([0, y0, _GAME_W, y1], fill=COL_SAFE)
        elif row in RIVER_ROWS:
            d.rectangle([0, y0, _GAME_W, y1], fill=COL_WATER)
        elif row in ROAD_ROWS:
            d.rectangle([0, y0, _GAME_W, y1], fill=COL_ROAD)
        elif row in START_ROWS:
            d.rectangle([0, y0, _GAME_W, y1], fill=COL_SAFE)

    # Home slots
    for i, hx in enumerate(HOME_SLOTS):
        px = hx * CELL
        col = COL_HOME_FILLED if homes_filled[i] else COL_HOME
        d.rectangle([px, 0, px + CELL * 2, CELL], fill=col)

    # Draw river objects (logs)
    for row in RIVER_ROWS:
        lane = lanes[row]
        y0 = row * CELL + 1
        y1 = y0 + CELL - 2
        for x0, x1 in lane.get_rects():
            if x1 > 0 and x0 < _GAME_W:
                d.rectangle([max(0, x0), y0, min(_GAME_W, x1), y1], fill=COL_LOG)

    # Draw road objects (cars)
    car_idx = 0
    for row in ROAD_ROWS:
        lane = lanes[row]
        y0 = row * CELL + 1
        y1 = y0 + CELL - 2
        col = CAR_COLS[car_idx % len(CAR_COLS)]
        car_idx += 1
        for x0, x1 in lane.get_rects():
            if x1 > 0 and x0 < _GAME_W:
                d.rectangle([max(0, x0), y0, min(_GAME_W, x1), y1], fill=col)

    # Frog
    fx = int(frog_x * CELL)
    fy = frog_y * CELL
    d.ellipse([fx + 1, fy + 1, fx + CELL - 2, fy + CELL - 2], fill=COL_FROG)
    d.ellipse([fx + 2, fy + 1, fx + 3, fy + 3], fill=COL_FROG_DARK)
    d.ellipse([fx + 5, fy + 1, fx + 6, fy + 3], fill=COL_FROG_DARK)

    # HUD row
    d.rectangle([0, ROW_HUD * CELL, _GAME_W, _GAME_H], fill=COL_BG)
    d.text((1, ROW_HUD * CELL), f"S:{score}", font=font, fill=COL_TEXT)
    d.text((45, ROW_HUD * CELL), f"L:{level}", font=font, fill=COL_TEXT)
    t_str = f"T:{int(timer_left)}"
    d.text((75, ROW_HUD * CELL), t_str, font=font, fill=COL_TEXT)
    for i in range(lives):
        lx = 108 + i * 7
        d.ellipse([lx, ROW_HUD * CELL + 1, lx + 5, ROW_HUD * CELL + 6],
                  fill=COL_FROG)

    if paused:
        d.text((42, 60), "PAUSED", font=font, fill=COL_TEXT)
    if msg:
        d.rectangle([10, 50, 118, 70], fill=COL_BG, outline=COL_TEXT)
        d.text((14, 54), msg, font=font, fill=COL_TEXT)

    if _GAME_W != WIDTH or _GAME_H != HEIGHT:
        img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
    LCD.LCD_ShowImage(img, 0, 0)


def play():
    global running
    level = 1
    total_score = 0

    while running:
        speed_mult = 1.0 + (level - 1) * 0.25
        lanes = _build_lanes(speed_mult)
        frog_x = 7.0  # float for sub-pixel carry
        frog_y = 13
        highest_row = frog_y
        lives = 3
        homes_filled = [False] * 5
        paused = False
        attempt_start = 0.0
        timer_max = 30.0
        started = False

        draw_frame(frog_x, frog_y, lanes, homes_filled, total_score,
                   lives, level, timer_max, False, "OK TO START")

        # Wait for start
        while running:
            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                cleanup()
                return
            if btn == "OK":
                started = True
                attempt_start = time.time()
                time.sleep(0.15)
                break
            time.sleep(0.05)

        while running and started:
            t_frame = time.time()

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

            if paused:
                draw_frame(frog_x, frog_y, lanes, homes_filled,
                           total_score, lives, level, timer_max, True)
                time.sleep(0.05)
                continue

            # Movement
            new_x, new_y = frog_x, frog_y
            if btn == "UP" and frog_y > 0:
                new_y = frog_y - 1
            elif btn == "DOWN" and frog_y < 14:
                new_y = frog_y + 1
            elif btn == "LEFT" and frog_x > 0:
                new_x = frog_x - 1
            elif btn == "RIGHT" and frog_x < COLS - 1:
                new_x = frog_x + 1

            if new_y != frog_y or new_x != frog_x:
                frog_x, frog_y = new_x, new_y
                # Score for advancing
                if frog_y < highest_row:
                    total_score += 10 * (highest_row - frog_y)
                    highest_row = frog_y

            # Update lanes
            for lane in lanes.values():
                lane.update(speed_mult)

            # River carry
            if frog_y in RIVER_ROWS:
                lane = lanes[frog_y]
                carry = lane.get_carry_offset(int(frog_x * CELL + CELL // 2))
                frog_x += carry / CELL * 0.5

            # Clamp frog
            frog_x = max(0.0, min(float(COLS - 1), frog_x))

            # Timer
            timer_left = max(0.0, timer_max - (time.time() - attempt_start))

            # Collision detection
            died = False
            frog_px = int(frog_x * CELL + CELL // 2)

            if frog_y in ROAD_ROWS:
                lane = lanes[frog_y]
                if lane.has_object_at(frog_px):
                    died = True

            if frog_y in RIVER_ROWS:
                lane = lanes[frog_y]
                if not lane.has_object_at(frog_px):
                    died = True  # fell in water

            if frog_x < 0 or frog_x >= COLS:
                died = True

            if timer_left <= 0:
                died = True

            # Check home arrival
            reached_home = False
            if frog_y == ROW_HOME:
                for i, hx in enumerate(HOME_SLOTS):
                    if abs(frog_x - hx) < 1.5 and not homes_filled[i]:
                        homes_filled[i] = True
                        total_score += 50 + int(timer_left) * 2
                        reached_home = True
                        break
                if not reached_home:
                    died = True  # landed outside a home slot

            if died:
                lives -= 1
                if lives <= 0:
                    draw_frame(frog_x, frog_y, lanes, homes_filled,
                               total_score, 0, level, 0, False, "GAME OVER")
                    _wait_end_then(total_score)
                    return
                frog_x = 7.0
                frog_y = 13
                highest_row = frog_y
                attempt_start = time.time()
                time.sleep(0.3)
                continue

            if reached_home:
                if all(homes_filled):
                    total_score += 100
                    draw_frame(frog_x, frog_y, lanes, homes_filled,
                               total_score, lives, level, timer_left, False,
                               f"LEVEL {level} DONE!")
                    time.sleep(1.5)
                    level += 1
                    break  # next level
                frog_x = 7.0
                frog_y = 13
                highest_row = frog_y
                attempt_start = time.time()

            draw_frame(frog_x, frog_y, lanes, homes_filled, total_score,
                       lives, level, timer_left, False)

            elapsed = time.time() - t_frame
            time.sleep(max(0, 0.05 - elapsed))


def _wait_end_then(score):
    """Game over screen: OK/KEY1=restart, KEY3=exit."""
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
