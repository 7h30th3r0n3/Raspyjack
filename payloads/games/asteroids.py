#!/usr/bin/env python3
"""
RaspyJack payload -- Asteroids
==============================
Author: 7h30th3r0n3

Classic Asteroids on LCD. Ship rotates, thrusts, and fires bullets
at irregular polygon asteroids that break into smaller pieces.

Controls: LEFT/RIGHT=rotate, UP=thrust, OK=fire, KEY1=restart, KEY3=exit.
"""

import os, sys, time
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import math
import random
import signal

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
# Colours (green/black theme)
# ---------------------------------------------------------------------------
COL_BG = (0, 0, 0)
COL_SHIP = (0, 255, 0)
COL_ASTEROID = (0, 200, 0)
COL_BULLET = (0, 255, 0)
COL_TEXT = (0, 255, 0)
COL_DIM = (0, 120, 0)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TURN_SPEED = 0.15          # radians per frame
THRUST = 0.25
FRICTION = 0.98
MAX_SPEED = 3.0
BULLET_SPEED = 3.5
BULLET_LIFETIME = 60
MAX_BULLETS = 5
INVULN_FRAMES = 90
SHIP_SIZE = 6
FPS = 20

running = True


def cleanup(*_):
    global running
    running = False


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)


# ---------------------------------------------------------------------------
# Asteroid generation
# ---------------------------------------------------------------------------
def make_asteroid_shape(radius):
    """Return a list of (dx, dy) offsets forming an irregular polygon."""
    num_verts = random.randint(7, 11)
    verts = []
    for i in range(num_verts):
        angle = (2 * math.pi * i) / num_verts
        r = radius * random.uniform(0.7, 1.3)
        verts.append((r * math.cos(angle), r * math.sin(angle)))
    return verts


def spawn_asteroid(x, y, radius):
    """Create an asteroid dict."""
    angle = random.uniform(0, 2 * math.pi)
    speed = random.uniform(0.4, 1.2)
    return {
        "x": x, "y": y,
        "vx": math.cos(angle) * speed,
        "vy": math.sin(angle) * speed,
        "radius": radius,
        "shape": make_asteroid_shape(radius),
    }


def spawn_initial_asteroids(count):
    """Spawn asteroids away from center."""
    asteroids = []
    for _ in range(count):
        while True:
            x = random.uniform(0, _GAME_W)
            y = random.uniform(0, _GAME_H)
            dist = math.hypot(x - _GAME_W / 2, y - _GAME_H / 2)
            if dist > 40:
                break
        asteroids.append(spawn_asteroid(x, y, 12))
    return asteroids


# ---------------------------------------------------------------------------
# Geometry helpers
# ---------------------------------------------------------------------------
def wrap(x, y):
    """Wrap coordinates toroidally."""
    return x % _GAME_W, y % _GAME_H


def ship_polygon(x, y, angle):
    """Triangle vertices for the ship."""
    pts = []
    for offset_angle, dist in [(0, SHIP_SIZE), (2.4, SHIP_SIZE * 0.7), (-2.4, SHIP_SIZE * 0.7)]:
        a = angle + offset_angle
        pts.append((x + math.cos(a) * dist, y + math.sin(a) * dist))
    return pts


def asteroid_polygon(ast):
    """Absolute polygon vertices for an asteroid."""
    return [(ast["x"] + dx, ast["y"] + dy) for dx, dy in ast["shape"]]


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------
def draw_frame(ship, asteroids, bullets, score, lives, level, invuln_timer):
    """Render one frame and push to LCD."""
    img = Image.new("RGB", (_GAME_W, _GAME_H), COL_BG)
    d = ImageDraw.Draw(img)

    # Asteroids
    for ast in asteroids:
        poly = asteroid_polygon(ast)
        poly_int = [(int(px), int(py)) for px, py in poly]
        d.polygon(poly_int, outline=COL_ASTEROID)

    # Ship (flash during invulnerability)
    if ship is not None:
        show_ship = invuln_timer <= 0 or (invuln_timer // 5) % 2 == 0
        if show_ship:
            poly = ship_polygon(ship["x"], ship["y"], ship["angle"])
            poly_int = [(int(px), int(py)) for px, py in poly]
            d.polygon(poly_int, outline=COL_SHIP)

    # Bullets
    for b in bullets:
        bx, by = int(b["x"]), int(b["y"])
        d.rectangle([bx - 1, by - 1, bx + 1, by + 1], fill=COL_BULLET)

    # HUD
    d.text((2, 2), f"S:{score}", font=font, fill=COL_TEXT)
    d.text((50, 2), f"L:{level}", font=font, fill=COL_TEXT)
    # Lives as small triangles
    for i in range(lives):
        lx = _GAME_W - 12 - i * 10
        ly = 7
        tri = [(lx, ly - 4), (lx - 3, ly + 3), (lx + 3, ly + 3)]
        d.polygon(tri, outline=COL_DIM)

    if _GAME_W != WIDTH or _GAME_H != HEIGHT:
        img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
    LCD.LCD_ShowImage(img, 0, 0)


def draw_message(line1, line2=""):
    """Show a centered message screen."""
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
# Game state
# ---------------------------------------------------------------------------
def new_ship():
    """Create a fresh ship at center."""
    return {"x": _GAME_W / 2, "y": _GAME_H / 2, "vx": 0, "vy": 0, "angle": -math.pi / 2}


def score_for_radius(radius):
    """Points awarded for destroying an asteroid."""
    if radius >= 10:
        return 20
    if radius >= 6:
        return 50
    return 100


def split_asteroid(ast):
    """Split an asteroid into smaller pieces or nothing."""
    children = []
    if ast["radius"] >= 10:
        new_r = 8
    elif ast["radius"] >= 6:
        new_r = 4
    else:
        return children
    for _ in range(2):
        children.append(spawn_asteroid(ast["x"], ast["y"], new_r))
    return children


# ---------------------------------------------------------------------------
# Main game loop
# ---------------------------------------------------------------------------
def play():
    """Run the full game (supports restart)."""
    score = 0
    lives = 3
    level = 1
    ship = new_ship()
    asteroids = spawn_initial_asteroids(4)
    bullets = []
    invuln_timer = INVULN_FRAMES
    fire_cooldown = 0

    while running:
        frame_start = time.time()
        btn = get_button(PINS, GPIO)

        # --- Global keys ---------------------------------------------------
        if btn == "KEY3":
            return
        if btn == "KEY1":
            play()
            return

        # --- Ship input ----------------------------------------------------
        if ship is not None:
            if btn == "LEFT":
                ship = {**ship, "angle": ship["angle"] - TURN_SPEED}
            elif btn == "RIGHT":
                ship = {**ship, "angle": ship["angle"] + TURN_SPEED}
            if btn == "UP":
                new_vx = ship["vx"] + math.cos(ship["angle"]) * THRUST
                new_vy = ship["vy"] + math.sin(ship["angle"]) * THRUST
                speed = math.hypot(new_vx, new_vy)
                if speed > MAX_SPEED:
                    new_vx = new_vx / speed * MAX_SPEED
                    new_vy = new_vy / speed * MAX_SPEED
                ship = {**ship, "vx": new_vx, "vy": new_vy}
            if btn == "OK" and fire_cooldown <= 0 and len(bullets) < MAX_BULLETS:
                bx = ship["x"] + math.cos(ship["angle"]) * SHIP_SIZE
                by = ship["y"] + math.sin(ship["angle"]) * SHIP_SIZE
                bullets = bullets + [{
                    "x": bx, "y": by,
                    "vx": math.cos(ship["angle"]) * BULLET_SPEED,
                    "vy": math.sin(ship["angle"]) * BULLET_SPEED,
                    "life": BULLET_LIFETIME,
                }]
                fire_cooldown = 5

        fire_cooldown = max(0, fire_cooldown - 1)
        if invuln_timer > 0:
            invuln_timer -= 1

        # --- Update ship ---------------------------------------------------
        if ship is not None:
            sx, sy = wrap(ship["x"] + ship["vx"], ship["y"] + ship["vy"])
            ship = {**ship, "x": sx, "y": sy,
                    "vx": ship["vx"] * FRICTION, "vy": ship["vy"] * FRICTION}

        # --- Update bullets ------------------------------------------------
        new_bullets = []
        for b in bullets:
            nb = {**b, "x": b["x"] + b["vx"], "y": b["y"] + b["vy"],
                  "life": b["life"] - 1}
            nb["x"], nb["y"] = wrap(nb["x"], nb["y"])
            if nb["life"] > 0:
                new_bullets.append(nb)
        bullets = new_bullets

        # --- Update asteroids ----------------------------------------------
        new_asteroids = []
        for ast in asteroids:
            ax, ay = wrap(ast["x"] + ast["vx"], ast["y"] + ast["vy"])
            new_asteroids.append({**ast, "x": ax, "y": ay})
        asteroids = new_asteroids

        # --- Bullet-asteroid collisions ------------------------------------
        surviving_asteroids = []
        remaining_bullets = list(bullets)
        for ast in asteroids:
            hit = False
            for i, b in enumerate(remaining_bullets):
                dist = math.hypot(b["x"] - ast["x"], b["y"] - ast["y"])
                if dist < ast["radius"]:
                    hit = True
                    score += score_for_radius(ast["radius"])
                    remaining_bullets.pop(i)
                    surviving_asteroids.extend(split_asteroid(ast))
                    break
            if not hit:
                surviving_asteroids.append(ast)
        asteroids = surviving_asteroids
        bullets = remaining_bullets

        # --- Ship-asteroid collision ---------------------------------------
        if ship is not None and invuln_timer <= 0:
            for ast in asteroids:
                dist = math.hypot(ship["x"] - ast["x"], ship["y"] - ast["y"])
                if dist < ast["radius"] + SHIP_SIZE * 0.5:
                    lives -= 1
                    if lives <= 0:
                        ship = None
                    else:
                        ship = new_ship()
                        invuln_timer = INVULN_FRAMES
                        bullets = []
                    break

        # --- Level complete ------------------------------------------------
        if len(asteroids) == 0 and ship is not None:
            level += 1
            asteroids = spawn_initial_asteroids(3 + level)
            invuln_timer = INVULN_FRAMES

        # --- Draw ----------------------------------------------------------
        draw_frame(ship, asteroids, bullets, score, lives, level, invuln_timer)

        # --- Game over check -----------------------------------------------
        if lives <= 0 and ship is None:
            time.sleep(0.5)
            draw_message(f"GAME OVER  Score:{score}", "KEY1=Restart  KEY3=Exit")
            while running:
                b = get_button(PINS, GPIO)
                if b == "KEY3":
                    return
                if b == "KEY1":
                    play()
                    return
                time.sleep(0.05)
            return

        # --- Frame timing --------------------------------------------------
        elapsed = time.time() - frame_start
        time.sleep(max(0, (1.0 / FPS) - elapsed))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        play()
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
