#!/usr/bin/env python3
"""
RaspyJack Payload -- Glitch Runner (Cyberpunk Platformer)
==========================================================
Author: 7h30th3r0n3

Side-scrolling endless runner with cyberpunk aesthetic.
Jump over obstacles, duck under beams, avoid gaps.
Speed increases over time. Glitch effects throughout.

Controls:
  UP / OK  -- Jump
  DOWN     -- Duck / Slide
  KEY1     -- Restart after game over
  KEY3     -- Exit
"""

import os, sys, time, signal, random, math
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
_GAME_W, _GAME_H = 128, 128

font = scaled_font(10)
font_sm = scaled_font(8)
font_xs = scaled_font(7)

C_BG = "#050510"
C_GROUND = "#00B4B4"
C_GROUND2 = "#006666"
C_PLAYER = "#00FF50"
C_PLAYER_DUCK = "#00C83C"
C_PLAYER_EYE = "#FFFFFF"
C_OBS_TALL = "#FF0078"
C_OBS_LOW = "#B400FF"
C_GAP_EDGE = "#440000"
C_TEXT = "#00FFC8"
C_SCORE = "#C8C8FF"
C_HI = "#FFFF00"
C_GLITCH1 = "#FF00FF"
C_GLITCH2 = "#00FFFF"
C_PARTICLE = "#FF6600"
C_STAR = "#334455"
C_NEON = "#00FFAA"

GROUND_Y = 100
PLAYER_X = 20
PLAYER_W = 8
PLAYER_H_STAND = 16
PLAYER_H_DUCK = 8

GRAVITY = 1.2
JUMP_VEL = -10.0

OBS_MIN_GAP = 40
OBS_MAX_GAP = 60
OBS_WIDTH = 10

OBS_TALL = 0
OBS_LOW = 1
OBS_GAP = 2

INITIAL_SPEED = 2.5
SPEED_INCREMENT = 0.002
MAX_SPEED = 7.0

FPS = 25
FRAME_DT = 1.0 / FPS

_running = True


def _sig(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


class Particle:
    __slots__ = ('x', 'y', 'vx', 'vy', 'life', 'color')

    def __init__(self, x, y, color=C_PARTICLE):
        self.x = x
        self.y = y
        self.vx = random.uniform(-2, 2)
        self.vy = random.uniform(-4, -1)
        self.life = random.randint(5, 15)
        self.color = color

    def update(self):
        self.x += self.vx
        self.y += self.vy
        self.vy += 0.3
        self.life -= 1
        return self.life > 0


class Game:
    def __init__(self):
        self.py = float(GROUND_Y - PLAYER_H_STAND)
        self.vy = 0.0
        self.ducking = False
        self.on_ground = True
        self.obstacles = []
        self.score = 0
        self.high_score = 0
        self.speed = INITIAL_SPEED
        self.next_obs_x = _GAME_W + 40
        self.frame = 0
        self.game_over = False
        self.particles = []
        self.stars = [(random.randint(0, 127), random.randint(0, GROUND_Y - 5),
                       random.uniform(0.3, 1.0)) for _ in range(20)]
        self.buildings = [(random.randint(0, 127), random.randint(15, 45),
                           random.randint(8, 16)) for _ in range(8)]
        self.trail = []

    def _spawn(self):
        if self.obstacles and self.obstacles[-1]['x'] > _GAME_W - OBS_MIN_GAP:
            return
        if self.next_obs_x > _GAME_W + 10:
            return
        r = random.random()
        if self.score < 200:
            t = OBS_TALL
        elif r < 0.45:
            t = OBS_TALL
        elif r < 0.8:
            t = OBS_LOW
        else:
            t = OBS_GAP

        if t == OBS_TALL:
            h = random.randint(18, 28)
            obs = {'type': OBS_TALL, 'x': self.next_obs_x, 'w': OBS_WIDTH,
                   'h': h, 'y': GROUND_Y - h}
        elif t == OBS_LOW:
            obs = {'type': OBS_LOW, 'x': self.next_obs_x, 'w': OBS_WIDTH + 6,
                   'h': 8, 'y': GROUND_Y - 20}
        else:
            obs = {'type': OBS_GAP, 'x': self.next_obs_x, 'w': 16,
                   'h': 20, 'y': GROUND_Y}
        self.obstacles.append(obs)
        self.next_obs_x += random.randint(OBS_MIN_GAP, OBS_MAX_GAP)

    def update(self, jump, duck):
        if self.game_over:
            return

        self.frame += 1
        self.score += 1
        self.speed = min(self.speed + SPEED_INCREMENT, MAX_SPEED)

        self._spawn()

        for obs in self.obstacles:
            obs['x'] -= self.speed
        self.next_obs_x -= self.speed
        self.obstacles = [o for o in self.obstacles if o['x'] + o['w'] > -5]

        over_gap = False
        ph = PLAYER_H_DUCK if self.ducking else PLAYER_H_STAND
        for obs in self.obstacles:
            if obs['type'] == OBS_GAP:
                if PLAYER_X + PLAYER_W > obs['x'] + 2 and PLAYER_X < obs['x'] + obs['w'] - 2:
                    over_gap = True
                    break

        if jump and self.on_ground and not over_gap:
            self.vy = JUMP_VEL
            self.on_ground = False
            self.ducking = False
            for _ in range(4):
                self.particles.append(Particle(PLAYER_X + PLAYER_W // 2,
                                               self.py + ph, C_NEON))

        self.ducking = duck and self.on_ground and not over_gap

        self.vy += GRAVITY
        self.py += self.vy

        stand_h = PLAYER_H_DUCK if self.ducking else PLAYER_H_STAND
        ground = float(GROUND_Y - stand_h)

        if over_gap:
            if self.py > _GAME_H + 20:
                self._die()
                return
        else:
            if self.py >= ground:
                self.py = ground
                self.vy = 0.0
                self.on_ground = True

        if self.on_ground and self.frame % 3 == 0:
            self.trail.append((PLAYER_X, int(self.py) + stand_h - 1))
        self.trail = [(x, y) for x, y in self.trail if x > -5]
        self.trail = [(x - self.speed, y) for x, y in self.trail]

        self.particles = [p for p in self.particles if p.update()]

        if self._check_collision():
            self._die()

    def _die(self):
        self.game_over = True
        if self.score > self.high_score:
            self.high_score = self.score
        ph = PLAYER_H_DUCK if self.ducking else PLAYER_H_STAND
        for _ in range(15):
            self.particles.append(Particle(PLAYER_X + PLAYER_W // 2,
                                           self.py + ph // 2, C_GLITCH1))
            self.particles.append(Particle(PLAYER_X + PLAYER_W // 2,
                                           self.py + ph // 2, C_GLITCH2))

    def _check_collision(self):
        ph = PLAYER_H_DUCK if self.ducking else PLAYER_H_STAND
        px1, px2 = PLAYER_X, PLAYER_X + PLAYER_W
        py1, py2 = self.py, self.py + ph

        for obs in self.obstacles:
            if obs['type'] == OBS_GAP:
                if self.py > _GAME_H:
                    return True
                continue
            ox1, ox2 = obs['x'], obs['x'] + obs['w']
            oy1, oy2 = obs['y'], obs['y'] + obs['h']
            if px2 > ox1 and px1 < ox2 and py2 > oy1 and py1 < oy2:
                return True
        return False

    def draw(self, d):
        scroll = int(self.frame * self.speed * 0.3)

        for sx, sy, bright in self.stars:
            star_x = (sx - scroll * 0.1) % _GAME_W
            v = int(bright * 80)
            d.point((int(star_x), sy), fill=f"#{v:02X}{v:02X}{v+20:02X}")

        for bx, bh, bw in self.buildings:
            bx_draw = int((bx - scroll * 0.15) % (_GAME_W + 20)) - 10
            by = GROUND_Y - bh
            d.rectangle((bx_draw, by, bx_draw + bw, GROUND_Y), fill="#0A0F1A", outline="#112233")
            for wy in range(by + 3, GROUND_Y - 3, 6):
                for wx in range(bx_draw + 2, bx_draw + bw - 2, 4):
                    if random.random() < 0.4:
                        d.point((wx, wy), fill="#334400")

        d.line([(0, GROUND_Y), (127, GROUND_Y)], fill=C_GROUND, width=2)
        offset = scroll % 16
        for x in range(0, _GAME_W + 16, 16):
            sx = x - offset
            d.line([(sx, GROUND_Y + 3), (sx + 6, GROUND_Y + 3)], fill=C_GROUND2)

        for obs in self.obstacles:
            ox = int(obs['x'])
            if ox > 130 or ox + obs['w'] < -2:
                continue
            if obs['type'] == OBS_TALL:
                d.rectangle((ox, obs['y'], ox + obs['w'], obs['y'] + obs['h']),
                            fill=C_OBS_TALL, outline="#FF6496")
                for stripe_y in range(obs['y'] + 3, obs['y'] + obs['h'] - 2, 4):
                    d.line([(ox + 1, stripe_y), (ox + obs['w'] - 1, stripe_y)],
                           fill="#AA0050")
            elif obs['type'] == OBS_LOW:
                d.rectangle((ox, obs['y'], ox + obs['w'], obs['y'] + obs['h']),
                            fill=C_OBS_LOW, outline="#DC64FF")
                glow_y = obs['y'] + obs['h'] // 2
                d.line([(ox, glow_y), (ox + obs['w'], glow_y)], fill="#FF88FF")
            elif obs['type'] == OBS_GAP:
                d.rectangle((ox, GROUND_Y, ox + obs['w'], GROUND_Y + 20), fill=C_BG)
                d.line([(ox, GROUND_Y + 20), (ox + obs['w'], GROUND_Y + 20)],
                       fill=C_GAP_EDGE)
                d.line([(ox, GROUND_Y), (ox, GROUND_Y + 20)], fill=C_GAP_EDGE)
                d.line([(ox + obs['w'], GROUND_Y), (ox + obs['w'], GROUND_Y + 20)],
                       fill=C_GAP_EDGE)

        for tx, ty in self.trail:
            d.point((int(tx), ty), fill=C_GROUND2)

        if not self.game_over:
            px = PLAYER_X
            py = int(self.py)
            ph = PLAYER_H_DUCK if self.ducking else PLAYER_H_STAND
            col = C_PLAYER_DUCK if self.ducking else C_PLAYER

            d.rectangle((px, py, px + PLAYER_W, py + ph), fill=col)
            d.rectangle((px, py, px + PLAYER_W, py + 2), fill="#88FFAA")
            d.rectangle((px + 5, py + 3, px + 7, py + 5), fill=C_PLAYER_EYE)

            if not self.on_ground:
                d.line([(px + 2, py + ph), (px + 1, py + ph + 3)], fill=C_NEON)
                d.line([(px + 5, py + ph), (px + 6, py + ph + 3)], fill=C_NEON)

        for p in self.particles:
            if 0 <= int(p.x) < 128 and 0 <= int(p.y) < 128:
                d.point((int(p.x), int(p.y)), fill=p.color)

        d.text((2, 1), f"{self.score}", font=font_sm, fill=C_SCORE)
        speed_pct = int((self.speed - INITIAL_SPEED) / (MAX_SPEED - INITIAL_SPEED) * 100)
        d.text((90, 1), f"x{speed_pct}%", font=font_xs, fill=C_GROUND)

        if not self.ducking and not self.game_over and self.on_ground:
            hint_obs = None
            for obs in self.obstacles:
                if obs['x'] > PLAYER_X and obs['x'] < PLAYER_X + 50:
                    hint_obs = obs
                    break
            if hint_obs:
                if hint_obs['type'] == OBS_LOW:
                    d.text((2, 10), "DUCK!", font=font_xs, fill=C_OBS_LOW)

        if self.game_over:
            for _ in range(10):
                p = self.particles[0] if self.particles else None
            for p in self.particles:
                if p.update() and 0 <= int(p.x) < 128 and 0 <= int(p.y) < 128:
                    d.point((int(p.x), int(p.y)), fill=p.color)

            d.rectangle((14, 35, 114, 92), fill="#000000", outline=C_GLITCH1)
            d.text((64, 40), "GAME OVER", font=font, fill=C_GLITCH1, anchor="mt")
            d.text((64, 55), f"Score: {self.score}", font=font_sm, fill=C_TEXT, anchor="mt")
            d.text((64, 67), f"Best: {self.high_score}", font=font_sm, fill=C_HI, anchor="mt")
            d.text((64, 80), "OK:Retry  K3:Exit", font=font_xs, fill=C_SCORE, anchor="mt")


def main():
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    game = Game()

    try:
        while _running:
            t0 = time.monotonic()

            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                break

            if game.game_over:
                if btn in ("OK", "KEY1"):
                    hs = game.high_score
                    game = Game()
                    game.high_score = hs
            else:
                jump = btn in ("UP", "OK")
                duck = GPIO.input(PINS["DOWN"]) == 0
                game.update(jump, duck)

            img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
            d = ScaledDraw(img)
            game.draw(d)
            lcd.LCD_ShowImage(img, 0, 0)

            elapsed = time.monotonic() - t0
            if elapsed < FRAME_DT:
                time.sleep(FRAME_DT - elapsed)

    finally:
        lcd.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    sys.exit(main())
