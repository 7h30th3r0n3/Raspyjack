#!/usr/bin/env python3
"""
RaspyJack Payload -- 1988 Retro Arcade
----------------------------------------
Author: 7h30th3r0n3

Classic top-down arcade shooter inspired by 1980s games.
Destroy descending enemies, survive as long as you can.

Controls:
  LEFT/RIGHT = move player ship
  OK/KEY1    = fire
  KEY3       = exit
"""
import os, sys, time, signal, random
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._input_helper import get_button, get_held_buttons

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}

GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
_GAME_W, _GAME_H = 128, 128

font = ImageFont.load_default()

running = True


def cleanup(*_):
    global running
    running = False


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# --- Colors ---
COL_BG = (0, 0, 0)
COL_TEXT = (255, 255, 255)
COL_PLAYER = (0, 255, 0)
COL_PLAYER_WING = (0, 180, 0)
COL_BULLET = (255, 255, 100)
COL_HUD = (0, 200, 0)
COL_LIFE = (255, 50, 50)

# Enemy colors cycle for variety
ENEMY_COLORS = [
    (200, 0, 0),
    (200, 100, 0),
    (200, 0, 200),
    (0, 200, 200),
    (200, 200, 0),
]

# --- Game constants ---
PLAYER_W = 8
PLAYER_H = 6
PLAYER_Y = _GAME_H - 14
BULLET_SPEED = 4
PLAYER_SPEED = 3
HUD_H = 10
ENEMY_W = 8
ENEMY_H = 6
ENEMY_COLS = 8
ENEMY_ROWS = 3
ENEMY_SPACING_X = 14
ENEMY_SPACING_Y = 12
FIRE_COOLDOWN = 0.15


def make_enemies(level):
    """Create a grid of enemies. Returns list of enemy dicts."""
    enemies = []
    rows = min(ENEMY_ROWS + level // 3, 6)
    cols = min(ENEMY_COLS, 8)
    start_x = (_GAME_W - cols * ENEMY_SPACING_X) // 2
    start_y = HUD_H + 4

    for row in range(rows):
        for col in range(cols):
            ex = start_x + col * ENEMY_SPACING_X + ENEMY_SPACING_X // 2
            ey = start_y + row * ENEMY_SPACING_Y
            color_idx = (row + level) % len(ENEMY_COLORS)
            enemies.append({
                "x": ex,
                "y": ey,
                "color": ENEMY_COLORS[color_idx],
                "alive": True,
            })
    return enemies


def draw_player(draw, px):
    """Draw the player ship as a small arrow/triangle."""
    # Body
    draw.rectangle([px - 1, PLAYER_Y, px + 1, PLAYER_Y + PLAYER_H - 1],
                   fill=COL_PLAYER)
    # Wings
    draw.rectangle([px - 4, PLAYER_Y + 2, px - 2, PLAYER_Y + PLAYER_H - 1],
                   fill=COL_PLAYER_WING)
    draw.rectangle([px + 2, PLAYER_Y + 2, px + 4, PLAYER_Y + PLAYER_H - 1],
                   fill=COL_PLAYER_WING)
    # Nose
    draw.rectangle([px, PLAYER_Y - 2, px, PLAYER_Y - 1], fill=COL_PLAYER)


def draw_enemy(draw, ex, ey, color):
    """Draw a blocky enemy shape."""
    # Main body
    draw.rectangle([ex - 3, ey, ex + 3, ey + 4], fill=color)
    # Side bits
    draw.rectangle([ex - 4, ey + 1, ex - 4, ey + 3], fill=color)
    draw.rectangle([ex + 4, ey + 1, ex + 4, ey + 3], fill=color)
    # Eyes
    draw.rectangle([ex - 2, ey + 1, ex - 1, ey + 1], fill=COL_BG)
    draw.rectangle([ex + 1, ey + 1, ex + 2, ey + 1], fill=COL_BG)


def draw_frame(px, bullets, enemies, score, lives, level):
    """Render a full game frame."""
    img = Image.new("RGB", (_GAME_W, _GAME_H), COL_BG)
    d = ImageDraw.Draw(img)

    # HUD
    d.text((2, 1), f"S:{score}", font=font, fill=COL_HUD)
    d.text((50, 1), f"L:{level}", font=font, fill=COL_HUD)
    # Lives as small squares
    for i in range(lives):
        lx = _GAME_W - 8 - i * 8
        d.rectangle([lx, 2, lx + 5, 7], fill=COL_LIFE)

    # Separator line
    d.line([(0, HUD_H), (_GAME_W - 1, HUD_H)], fill=(0, 60, 0))

    # Enemies
    for e in enemies:
        if e["alive"]:
            draw_enemy(d, e["x"], e["y"], e["color"])

    # Bullets
    for bx, by in bullets:
        d.rectangle([bx, by, bx + 1, by + 3], fill=COL_BULLET)

    # Player
    draw_player(d, px)

    if _GAME_W != WIDTH or _GAME_H != HEIGHT:
        img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
    LCD.LCD_ShowImage(img, 0, 0)


def draw_message(msg, sub="", score=0):
    """Draw a centered message screen."""
    img = Image.new("RGB", (_GAME_W, _GAME_H), COL_BG)
    d = ImageDraw.Draw(img)

    d.text((2, 1), f"Score:{score}", font=font, fill=COL_HUD)

    # Title
    tw = len(msg) * 6
    d.text(((_GAME_W - tw) // 2, 50), msg, font=font, fill=COL_TEXT)

    if sub:
        sw = len(sub) * 6
        d.text(((_GAME_W - sw) // 2, 65), sub, font=font, fill=COL_HUD)

    if _GAME_W != WIDTH or _GAME_H != HEIGHT:
        img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
    LCD.LCD_ShowImage(img, 0, 0)


def check_collision(bx, by, ex, ey):
    """Check if bullet hits enemy (simple AABB)."""
    return (abs(bx - ex) <= 4 and abs(by - ey) <= 4)


def play():
    """Main arcade game loop."""
    global running
    best_score = 0

    while running:
        px = _GAME_W // 2
        bullets = []
        score = 0
        lives = 3
        level = 1
        kills = 0
        last_fire = 0.0
        enemy_dir = 1           # 1 = right, -1 = left
        enemy_drop_timer = 0.0
        base_speed = 0.6        # seconds between enemy moves
        enemies = make_enemies(level)

        draw_message("1988 ARCADE", "OK to start", best_score)

        # Wait for start
        while running:
            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                cleanup()
                return
            if btn in ("OK", "KEY1"):
                time.sleep(0.2)
                break
            time.sleep(0.05)

        if not running:
            return

        game_over = False
        last_enemy_move = time.time()

        while running and not game_over:
            frame_start = time.time()

            # --- Input ---
            btn = get_button(PINS, GPIO)
            held = get_held_buttons()

            if btn == "KEY3":
                cleanup()
                return

            # Movement (check both single press and held)
            if btn == "LEFT" or "LEFT" in held:
                px = max(5, px - PLAYER_SPEED)
            if btn == "RIGHT" or "RIGHT" in held:
                px = min(_GAME_W - 6, px + PLAYER_SPEED)

            # Fire
            now = time.time()
            if (btn in ("OK", "KEY1") or "OK" in held or "KEY1" in held):
                if now - last_fire >= FIRE_COOLDOWN:
                    bullets = bullets + [(px, PLAYER_Y - 3)]
                    last_fire = now

            # --- Update bullets ---
            new_bullets = []
            for bx, by in bullets:
                new_by = by - BULLET_SPEED
                if new_by > HUD_H:
                    new_bullets.append((bx, new_by))
            bullets = new_bullets

            # --- Bullet-enemy collision ---
            surviving_bullets = []
            for bx, by in bullets:
                hit = False
                new_enemies = []
                for e in enemies:
                    if e["alive"] and check_collision(bx, by, e["x"], e["y"]):
                        new_enemies.append(dict(e, alive=False))
                        score += 10
                        kills += 1
                        hit = True
                    else:
                        new_enemies.append(e)
                enemies = new_enemies
                if not hit:
                    surviving_bullets.append((bx, by))
            bullets = surviving_bullets

            # --- Enemy movement (timed) ---
            speed = max(0.1, base_speed - (level - 1) * 0.05)
            if now - last_enemy_move >= speed:
                last_enemy_move = now

                # Check if any alive enemy at edge
                alive_enemies = [e for e in enemies if e["alive"]]
                if alive_enemies:
                    rightmost = max(e["x"] for e in alive_enemies)
                    leftmost = min(e["x"] for e in alive_enemies)

                    if rightmost >= _GAME_W - 6 and enemy_dir == 1:
                        enemy_dir = -1
                        enemies = [
                            dict(e, y=e["y"] + 4) if e["alive"] else e
                            for e in enemies
                        ]
                    elif leftmost <= 6 and enemy_dir == -1:
                        enemy_dir = 1
                        enemies = [
                            dict(e, y=e["y"] + 4) if e["alive"] else e
                            for e in enemies
                        ]
                    else:
                        step = 2 + level // 2
                        enemies = [
                            dict(e, x=e["x"] + enemy_dir * step) if e["alive"] else e
                            for e in enemies
                        ]

            # --- Check if enemy reached bottom ---
            for e in enemies:
                if e["alive"] and e["y"] >= PLAYER_Y - 4:
                    lives -= 1
                    if lives <= 0:
                        game_over = True
                        break
                    # Reset enemies down when they reach bottom
                    enemies = make_enemies(level)
                    last_enemy_move = now
                    break

            # --- Check player collision with enemies ---
            for e in enemies:
                if e["alive"] and abs(e["x"] - px) < 6 and abs(e["y"] - PLAYER_Y) < 6:
                    lives -= 1
                    enemies = [dict(e, alive=False) if abs(e["x"] - px) < 6 and abs(e["y"] - PLAYER_Y) < 6 else e for e in enemies]
                    if lives <= 0:
                        game_over = True
                    break

            # --- Level up: all enemies destroyed ---
            alive_count = sum(1 for e in enemies if e["alive"])
            if alive_count == 0:
                level += 1
                enemies = make_enemies(level)
                enemy_dir = 1
                bullets = []
                last_enemy_move = now

                # Brief level-up message
                draw_message(f"LEVEL {level}", f"Score:{score}", score)
                time.sleep(1.0)

            if not game_over:
                draw_frame(px, bullets, enemies, score, lives, level)

            # --- Frame rate (~15 FPS) ---
            elapsed = time.time() - frame_start
            time.sleep(max(0, 0.066 - elapsed))

        # --- Game Over ---
        if not running:
            return

        best_score = max(best_score, score)
        draw_message("GAME OVER", f"Score:{score} Best:{best_score}", score)

        while running:
            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                cleanup()
                return
            if btn in ("OK", "KEY1"):
                time.sleep(0.2)
                break
            time.sleep(0.05)


if __name__ == "__main__":
    try:
        play()
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
