#!/usr/bin/env python3
"""
RaspyJack Payload -- NEON BIKES (Tron Light Cycles)
====================================================
Author: 7h30th3r0n3

Intense Tron-style light cycle arena. Fast, lethal, neon.
Player 1 (green) vs AI (red). Touch anything = instant death.

Controls:
  D-pad    -- Steer (instant turn, no stopping)
  KEY2     -- Turbo (2x speed burst, limited fuel)
  OK/KEY1  -- Restart round
  KEY3     -- Exit
"""

import os, sys, time, signal, random
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}

WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT

font = scaled_font(12)
font_sm = scaled_font(9)
font_xs = scaled_font(7)

CELL = 2
GW, GH = 64, 64

UP = (0, -1)
DN = (0, 1)
LT = (-1, 0)
RT = (1, 0)
DIRS = [UP, DN, LT, RT]

SPEED = 18
TURBO_MAX = 8

_running = True


def _sig(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _opp(d1, d2):
    return d1[0] == -d2[0] and d1[1] == -d2[1]


def _safe(x, y, walls):
    return 0 <= x < GW and 0 <= y < GH and (x, y) not in walls


def _flood(sx, sy, walls, cap=50):
    vis = {(sx, sy)}
    q = [(sx, sy)]
    n = 0
    while q and n < cap:
        cx, cy = q.pop(0)
        n += 1
        for dx, dy in DIRS:
            nx, ny = cx + dx, cy + dy
            if (nx, ny) not in vis and _safe(nx, ny, walls):
                vis.add((nx, ny))
                q.append((nx, ny))
    return n


def _ai(ax, ay, ad, px, py, walls):
    best = None
    best_score = -1
    for d in DIRS:
        if _opp(d, ad):
            continue
        nx, ny = ax + d[0], ay + d[1]
        if not _safe(nx, ny, walls):
            continue
        reach = _flood(nx, ny, walls)
        dist = abs(nx - px) + abs(ny - py)
        score = reach * 100 - dist
        if score > best_score:
            best_score = score
            best = d
    return best if best else ad


class Bike:
    def __init__(self, x, y, d, color, head_color, trail_color):
        self.x = x
        self.y = y
        self.d = d
        self.color = color
        self.head_color = head_color
        self.trail_color = trail_color
        self.trail = [(x, y)]
        self.alive = True


class Game:
    def __init__(self):
        self.p = Bike(GW // 4, GH // 2, RT, "#00FF64", "#FFFFFF", "#004422")
        self.a = Bike(3 * GW // 4, GH // 2, LT, "#FF3030", "#FFAAAA", "#440011")
        self.walls = {(self.p.x, self.p.y), (self.a.x, self.a.y)}
        self.over = False
        self.msg = ""
        self.score = 0
        self.wins = 0
        self.losses = 0
        self.turbo = TURBO_MAX
        self.turbo_cd = 0
        self.tick = 0
        self.sparks = []

    def reset(self):
        self.p = Bike(GW // 4, GH // 2, RT, "#00FF64", "#FFFFFF", "#004422")
        self.a = Bike(3 * GW // 4, GH // 2, LT, "#FF3030", "#FFAAAA", "#440011")
        self.walls = {(self.p.x, self.p.y), (self.a.x, self.a.y)}
        self.over = False
        self.msg = ""
        self.score = 0
        self.turbo = TURBO_MAX
        self.turbo_cd = 0
        self.sparks = []

    def _move(self, bike):
        nx = bike.x + bike.d[0]
        ny = bike.y + bike.d[1]
        if _safe(nx, ny, self.walls):
            bike.x, bike.y = nx, ny
            bike.trail.append((nx, ny))
            self.walls.add((nx, ny))
            return True
        bike.alive = False
        self._explode(bike.x, bike.y)
        return False

    def _explode(self, x, y):
        for _ in range(12):
            self.sparks.append([
                x * CELL + random.randint(-4, 4),
                y * CELL + random.randint(-4, 4),
                random.randint(6, 14),
            ])

    def update(self, p_dir, turbo):
        if self.over:
            return
        self.tick += 1

        if p_dir and not _opp(p_dir, self.p.d):
            self.p.d = p_dir

        self.a.d = _ai(self.a.x, self.a.y, self.a.d, self.p.x, self.p.y, self.walls)

        if self.turbo_cd > 0:
            self.turbo_cd -= 1

        steps = 1
        if turbo and self.turbo > 0 and self.turbo_cd <= 0:
            steps = 2
            self.turbo -= 1
            self.turbo_cd = 2

        for _ in range(steps):
            if self.p.alive:
                self._move(self.p)
                if self.p.alive:
                    self.score += 1

        if self.a.alive:
            self._move(self.a)

        if (self.p.x, self.p.y) == (self.a.x, self.a.y):
            self.p.alive = False
            self.a.alive = False

        self.sparks = [[x, y, l - 1] for x, y, l in self.sparks if l > 0]

        if not self.p.alive and not self.a.alive:
            self.over = True
            self.msg = "DRAW"
        elif not self.p.alive:
            self.over = True
            self.msg = "DEREZZ"
            self.losses += 1
        elif not self.a.alive:
            self.over = True
            self.msg = "VICTORY"
            self.wins += 1

    def draw(self, d):
        # Grid floor — horizontal and vertical lines
        for gx in range(0, 128, 16):
            d.line((gx, 0, gx, 127), fill="#0A0A30")
        for gy in range(0, 128, 16):
            d.line((0, gy, 127, gy), fill="#0A0A30")

        # Arena border — double line glow
        d.rectangle((0, 0, 127, 127), outline="#0066CC")
        d.rectangle((1, 1, 126, 126), outline="#003366")

        # Trails
        c = CELL
        # Player trail with intensity gradient
        tl = len(self.p.trail)
        for i, (tx, ty) in enumerate(self.p.trail):
            x1, y1 = tx * c, ty * c
            if i >= tl - 6:
                col = self.p.color
            elif i >= tl - 20:
                col = "#00AA44"
            else:
                col = self.p.trail_color
            d.rectangle((x1, y1, x1 + c - 1, y1 + c - 1), fill=col)

        tl = len(self.a.trail)
        for i, (tx, ty) in enumerate(self.a.trail):
            x1, y1 = tx * c, ty * c
            if i >= tl - 6:
                col = self.a.color
            elif i >= tl - 20:
                col = "#CC2020"
            else:
                col = self.a.trail_color
            d.rectangle((x1, y1, x1 + c - 1, y1 + c - 1), fill=col)

        # Bike heads — larger bright square with direction indicator
        if self.p.alive:
            hx, hy = self.p.x * c, self.p.y * c
            d.rectangle((hx - 1, hy - 1, hx + c, hy + c), fill=self.p.head_color)
            # Direction indicator (leading pixel)
            lx = hx + self.p.d[0] * 2
            ly = hy + self.p.d[1] * 2
            d.point((lx, ly), fill=self.p.color)

        if self.a.alive:
            hx, hy = self.a.x * c, self.a.y * c
            d.rectangle((hx - 1, hy - 1, hx + c, hy + c), fill=self.a.head_color)
            lx = hx + self.a.d[0] * 2
            ly = hy + self.a.d[1] * 2
            d.point((lx, ly), fill=self.a.color)

        # Sparks
        for sx, sy, life in self.sparks:
            if 0 <= sx < 128 and 0 <= sy < 128:
                col = "#FFFFFF" if life > 8 else "#FFAA00" if life > 4 else "#FF4400"
                d.point((sx, sy), fill=col)

        # HUD — minimal, top corners
        d.text((2, 1), f"{self.score}", font=font_xs, fill="#00FF64")
        d.text((126, 1), f"W{self.wins}", font=font_xs, fill="#00AAFF", anchor="ra")

        # Turbo bar — bottom left
        for i in range(TURBO_MAX):
            col = "#FFD700" if i < self.turbo else "#1A1A2A"
            bx = 2 + i * 4
            d.rectangle((bx, 122, bx + 2, 126), fill=col)

        # Game over overlay
        if self.over:
            # Dim background
            d.rectangle((20, 40, 108, 88), fill="#000000", outline="#0066CC")
            d.rectangle((21, 41, 107, 87), outline="#003366")

            if self.msg == "VICTORY":
                col = "#00FF64"
            elif self.msg == "DEREZZ":
                col = "#FF3030"
            else:
                col = "#FFAA00"

            d.text((64, 48), self.msg, font=font, fill=col, anchor="mt")
            d.text((64, 64), f"Score: {self.score}", font=font_sm, fill="#AAAACC", anchor="mt")
            d.text((64, 78), "OK:Again K3:Exit", font=font_xs, fill="#555577", anchor="mt")


def main():
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    # Intro
    img = Image.new("RGB", (WIDTH, HEIGHT), "#000014")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 127), outline="#0066CC")
    d.text((64, 25), "NEON", font=font, fill="#00FF64", anchor="mm")
    d.text((64, 42), "BIKES", font=font, fill="#00AAFF", anchor="mm")
    d.line((20, 55, 108, 55), fill="#003366")
    d.text((64, 65), "Last trail standing", font=font_xs, fill="#555577", anchor="mm")
    d.text((64, 80), "D-pad steer", font=font_xs, fill="#444466", anchor="mm")
    d.text((64, 92), "KEY2 turbo", font=font_xs, fill="#FFD700", anchor="mm")
    d.text((64, 110), "OK to ride", font=font_xs, fill="#333355", anchor="mm")
    lcd.LCD_ShowImage(img, 0, 0)

    while _running:
        b = get_button(PINS, GPIO)
        if b == "KEY3":
            GPIO.cleanup()
            return 0
        if b in ("OK", "KEY1"):
            break
        time.sleep(0.05)

    game = Game()
    dt = 1.0 / SPEED

    try:
        while _running:
            t0 = time.monotonic()

            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                break

            if game.over:
                if btn in ("OK", "KEY1"):
                    game.reset()
                    time.sleep(0.15)
            else:
                dm = {"UP": UP, "DOWN": DN, "LEFT": LT, "RIGHT": RT}
                p_dir = dm.get(btn)
                turbo = GPIO.input(PINS["KEY2"]) == 0
                game.update(p_dir, turbo)

            img = Image.new("RGB", (WIDTH, HEIGHT), "#000014")
            d = ScaledDraw(img)
            game.draw(d)
            lcd.LCD_ShowImage(img, 0, 0)

            elapsed = time.monotonic() - t0
            if elapsed < dt:
                time.sleep(dt - elapsed)

    finally:
        lcd.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    sys.exit(main())
