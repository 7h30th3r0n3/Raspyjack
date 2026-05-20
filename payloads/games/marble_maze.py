#!/usr/bin/env python3
"""
RaspyJack Payload -- Marble Maze (IMU)
=======================================
Author: 7h30th3r0n3

Tilt the CardputerZero to roll a marble through a maze.
Uses the LSM6DS3TR accelerometer for tilt control.

Controls:
  Tilt       -- Move marble
  OK         -- Restart level
  KEY1       -- Skip to next level
  KEY3       -- Exit
"""

import os
import sys
import math
import time
import struct
import signal

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT

C_BG = "#0a0a12"
C_WALL = "#334155"
C_WALL_TOP = "#475569"
C_PATH = "#0f172a"
C_MARBLE = "#00E5FF"
C_MARBLE_HL = "#80F0FF"
C_GOAL = "#00E676"
C_GOAL_DIM = "#004D40"
C_START = "#7C4DFF"
C_TEXT = "#E0E0E0"
C_MUTED = "#888888"
C_HEADER = "#0d1117"
C_GOLD = "#FFD740"
C_RED = "#FF5252"

CELL = 8
GRID_W = 128 // CELL
GRID_H = (128 - 14) // CELL
MAZE_Y_OFF = 14

GRAVITY = 0.15
FRICTION = 0.85
MAX_SPEED = 2.5
MARBLE_R = 3

LEVELS = [
    {
        "name": "Easy",
        "grid": [
            "################",
            "#S.....#.......#",
            "#.####.#.#####.#",
            "#.#..#...#...#.#",
            "#.#..#####.#.#.#",
            "#....#.....#...#",
            "#.####.###.###.#",
            "#.#..#.#.#...#.#",
            "#.#..#.#.###.#.#",
            "#....#.#.....#.#",
            "#.####.#.###.#.#",
            "#......#...#.#.#",
            "#.########.#.#.#",
            "################",
        ],
    },
    {
        "name": "Medium",
        "grid": [
            "################",
            "#S...#.........#",
            "###..#.#######.#",
            "#....#.#.....#.#",
            "#.####.#.###.#.#",
            "#.#....#...#...#",
            "#.#.######.###.#",
            "#.#........#...#",
            "#.########.#.#.#",
            "#..........#.#.#",
            "#.####.#####.#.#",
            "#.#..#.......#.#",
            "#.#..#########G#",
            "################",
        ],
    },
    {
        "name": "Hard",
        "grid": [
            "################",
            "#S.#...........#",
            "#..#.#########.#",
            "#..#.#.......#.#",
            "#..#.#.#####.#.#",
            "#....#.#...#.#.#",
            "####.#.#.#.#.#.#",
            "#....#...#.#...#",
            "#.####.###.###.#",
            "#.#..#.#.....#.#",
            "#.#..#.#.###.#.#",
            "#.#....#...#...#",
            "#.######.#.###G#",
            "################",
        ],
    },
    {
        "name": "Expert",
        "grid": [
            "################",
            "#S.#.....#.....#",
            "#..#.###.#.###.#",
            "#....#.#...#.#.#",
            "####.#.#####.#.#",
            "#..#.#.........#",
            "#..#.#.#######.#",
            "#....#.#.....#.#",
            "#.####.#.###.#.#",
            "#.#....#.#.#.#.#",
            "#.#.####.#.#.#.#",
            "#.#......#...#.#",
            "#.########.###G#",
            "################",
        ],
    },
    {
        "name": "Master",
        "grid": [
            "################",
            "#S.#...#.......#",
            "#..#.#.#.#####.#",
            "#..#.#.#.....#.#",
            "#..#.#.#####.#.#",
            "#....#.......#.#",
            "####.#######.#.#",
            "#....#.....#.#.#",
            "#.####.###.#.#.#",
            "#.#..#.#.#.#...#",
            "#.#..#.#.#.#.###",
            "#.#....#.#.#...#",
            "#.######.#.###G#",
            "################",
        ],
    },
]


def _check_and_install_deps():
    try:
        import smbus2
        return True
    except ImportError:
        pass
    import subprocess
    subprocess.run(
        ["pip3", "install", "--break-system-packages", "smbus2"],
        capture_output=True, timeout=60,
    )
    try:
        import smbus2
        return True
    except ImportError:
        return False


class IMUReader:
    _CTRL1_XL = 0x10
    _CTRL2_G = 0x11
    _OUTX_L_XL = 0x28

    def __init__(self, bus_num=1, addr=0x6A):
        import smbus2
        self._bus = smbus2.SMBus(bus_num)
        self._addr = addr
        self._bus.write_byte_data(self._addr, self._CTRL1_XL, 0x40)
        self._sens = 0.000061

    def read_accel(self):
        data = []
        for reg in (self._OUTX_L_XL, self._OUTX_L_XL + 2, self._OUTX_L_XL + 4):
            low = self._bus.read_byte_data(self._addr, reg)
            high = self._bus.read_byte_data(self._addr, reg + 1)
            val = (high << 8) | low
            if val >= 0x8000:
                val -= 0x10000
            data.append(val * self._sens)
        raw_x, raw_y, raw_z = data
        return raw_y, -raw_x, raw_z

    def close(self):
        try:
            self._bus.close()
        except Exception:
            pass


class MarbleMaze:
    def __init__(self, level_idx=0):
        self.level_idx = level_idx % len(LEVELS)
        self.level = LEVELS[self.level_idx]
        self._parse_grid()
        self.mx = self.start_x
        self.my = self.start_y
        self.vx = 0.0
        self.vy = 0.0
        self.won = False
        self.win_time = 0
        self.start_time = time.monotonic()
        self.elapsed = 0.0
        self._trail = []

    def _parse_grid(self):
        self.walls = set()
        self.start_x = 1.5 * CELL
        self.start_y = 1.5 * CELL
        self.goal_x = (GRID_W - 1.5) * CELL
        self.goal_y = (len(self.level["grid"]) - 1.5) * CELL
        for row_i, row in enumerate(self.level["grid"]):
            for col_i, ch in enumerate(row):
                if ch == "#":
                    self.walls.add((col_i, row_i))
                elif ch == "S":
                    self.start_x = (col_i + 0.5) * CELL
                    self.start_y = (row_i + 0.5) * CELL
                elif ch == "G":
                    self.goal_x = (col_i + 0.5) * CELL
                    self.goal_y = (row_i + 0.5) * CELL

    def _cell_blocked(self, cx, cy):
        return (cx, cy) in self.walls

    def update(self, tilt_x, tilt_y):
        if self.won:
            return

        self.elapsed = time.monotonic() - self.start_time
        self.vx += tilt_x * GRAVITY
        self.vy += tilt_y * GRAVITY
        self.vx *= FRICTION
        self.vy *= FRICTION
        speed = math.sqrt(self.vx ** 2 + self.vy ** 2)
        if speed > MAX_SPEED:
            scale = MAX_SPEED / speed
            self.vx *= scale
            self.vy *= scale

        new_x = self.mx + self.vx
        new_y = self.my + self.vy
        r = MARBLE_R

        for corner_x, corner_y in [(new_x - r, new_y - r), (new_x + r, new_y - r),
                                    (new_x - r, new_y + r), (new_x + r, new_y + r)]:
            cell_x = int(corner_x // CELL)
            cell_y = int(corner_y // CELL)
            if self._cell_blocked(cell_x, cell_y):
                cx_center = (cell_x + 0.5) * CELL
                cy_center = (cell_y + 0.5) * CELL
                dx = new_x - cx_center
                dy = new_y - cy_center
                if abs(dx) > abs(dy):
                    if dx > 0:
                        new_x = (cell_x + 1) * CELL + r
                    else:
                        new_x = cell_x * CELL - r
                    self.vx = -self.vx * 0.3
                else:
                    if dy > 0:
                        new_y = (cell_y + 1) * CELL + r
                    else:
                        new_y = cell_y * CELL - r
                    self.vy = -self.vy * 0.3

        self.mx = max(r, min(GRID_W * CELL - r, new_x))
        self.my = max(r, min(len(self.level["grid"]) * CELL - r, new_y))

        self._trail.append((self.mx, self.my))
        if len(self._trail) > 40:
            self._trail.pop(0)

        dist = math.sqrt((self.mx - self.goal_x) ** 2 + (self.my - self.goal_y) ** 2)
        if dist < CELL * 0.6:
            self.won = True
            self.win_time = self.elapsed

    def draw(self, d, fonts):
        font_s, font_t = fonts

        d.rectangle((0, 0, 127, 13), fill=C_HEADER)
        d.text((2, 1), f"Lv{self.level_idx + 1} {self.level['name']}", font=font_t, fill=C_TEXT)
        elapsed = self.win_time if self.won else self.elapsed
        d.text((90, 1), f"{elapsed:.1f}s", font=font_t, fill=C_GOLD if self.won else C_MUTED)

        for (cx, cy) in self.walls:
            x0 = cx * CELL
            y0 = cy * CELL + MAZE_Y_OFF
            d.rectangle((x0, y0, x0 + CELL - 1, y0 + CELL - 1), fill=C_WALL)
            d.rectangle((x0, y0, x0 + CELL - 1, y0 + 1), fill=C_WALL_TOP)

        gx = int(self.goal_x)
        gy = int(self.goal_y) + MAZE_Y_OFF
        pulse = 3 + int(2 * abs(math.sin(time.monotonic() * 3)))
        d.ellipse((gx - pulse, gy - pulse, gx + pulse, gy + pulse), fill=C_GOAL_DIM)
        d.ellipse((gx - 2, gy - 2, gx + 2, gy + 2), fill=C_GOAL)

        for i, (tx, ty) in enumerate(self._trail):
            alpha = i / len(self._trail) if self._trail else 0
            tr = max(1, int(MARBLE_R * 0.4 * alpha))
            tx_i = int(tx)
            ty_i = int(ty) + MAZE_Y_OFF
            d.ellipse((tx_i - tr, ty_i - tr, tx_i + tr, ty_i + tr), fill="#0D4A5A")

        bx = int(self.mx)
        by = int(self.my) + MAZE_Y_OFF
        d.ellipse((bx - MARBLE_R, by - MARBLE_R, bx + MARBLE_R, by + MARBLE_R), fill=C_MARBLE)
        d.ellipse((bx - 1, by - 2, bx + 1, by), fill=C_MARBLE_HL)

        if self.won:
            d.rectangle((20, 45 + MAZE_Y_OFF, 108, 70 + MAZE_Y_OFF), fill="#1a1a2e")
            d.rectangle((20, 45 + MAZE_Y_OFF, 108, 70 + MAZE_Y_OFF), outline=C_GOLD)
            d.text((64, 52 + MAZE_Y_OFF), "LEVEL CLEAR!", font=font_s, fill=C_GOLD, anchor="mt")
            d.text((64, 63 + MAZE_Y_OFF), f"{self.win_time:.1f}s - KEY1 next", font=font_t, fill=C_MUTED, anchor="mt")


def main():
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    font_s = scaled_font(10)
    font_t = scaled_font(8)
    fonts = (font_s, font_t)

    if not _check_and_install_deps():
        img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
        d = ScaledDraw(img)
        d.text((64, 50), "smbus2 missing", font=font_s, fill=C_RED, anchor="mm")
        d.text((64, 66), "pip3 install smbus2", font=font_t, fill=C_MUTED, anchor="mm")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        return 0

    try:
        imu = IMUReader()
    except Exception:
        img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
        d = ScaledDraw(img)
        d.text((64, 50), "IMU not found", font=font_s, fill=C_RED, anchor="mm")
        d.text((64, 66), "LSM6DS3TR @ 0x6A", font=font_t, fill=C_MUTED, anchor="mm")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        return 0

    level_idx = 0
    game = MarbleMaze(level_idx)

    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)
    d.text((64, 40), "MARBLE MAZE", font=font_s, fill=C_MARBLE, anchor="mm")
    d.text((64, 56), "Tilt to roll!", font=font_t, fill=C_MUTED, anchor="mm")
    d.text((64, 72), f"Level 1: {LEVELS[0]['name']}", font=font_t, fill=C_GOAL, anchor="mm")
    lcd.LCD_ShowImage(img, 0, 0)
    time.sleep(2)

    target_dt = 1.0 / 30
    try:
        while True:
            t0 = time.monotonic()

            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                break
            if btn == "OK":
                game = MarbleMaze(level_idx)
            if btn == "KEY1":
                if game.won or True:
                    level_idx = (level_idx + 1) % len(LEVELS)
                    game = MarbleMaze(level_idx)

            ax, ay, az = imu.read_accel()
            tilt_x = max(-1.0, min(1.0, ax)) * 8.0
            tilt_y = max(-1.0, min(1.0, ay)) * 8.0
            game.update(tilt_x, tilt_y)

            img = Image.new("RGB", (WIDTH, HEIGHT), C_PATH)
            d = ScaledDraw(img)
            game.draw(d, fonts)
            lcd.LCD_ShowImage(img, 0, 0)

            elapsed = time.monotonic() - t0
            if elapsed < target_dt:
                time.sleep(target_dt - elapsed)

    finally:
        imu.close()
        lcd.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    sys.exit(main())
