#!/usr/bin/env python3
"""
RaspyJack Payload -- Space Invaders
=====================================
Author: 7h30th3r0n3

Classic Space Invaders on LCD with green/black theme.
4 rows of 6 aliens, 3 destructible shields, 3 lives, score counter.

Controls:
  LEFT / RIGHT -- Move ship
  OK           -- Fire
  KEY1         -- Restart
  KEY3         -- Exit
"""

import os
import sys
import time
import random

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._input_helper import get_button

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

# ---------------------------------------------------------------------------
# Game constants
# ---------------------------------------------------------------------------
SHIP_W = 10
SHIP_H = 6
SHIP_Y = 118
ALIEN_W = 10
ALIEN_H = 8
ALIEN_COLS = 6
ALIEN_ROWS = 4
ALIEN_GAP_X = 4
ALIEN_GAP_Y = 4
ALIEN_START_Y = 18
BULLET_SPEED = 4
ALIEN_BULLET_SPEED = 2
SHIELD_W = 20
SHIELD_H = 6
SHIELD_Y = 100
MAX_LIVES = 3
ALIEN_SHOOT_CHANCE = 0.02


# ---------------------------------------------------------------------------
# Game state factory (immutable-style: new state per reset)
# ---------------------------------------------------------------------------

def _make_state():
    """Create a fresh game state dict."""
    aliens = []
    for row in range(ALIEN_ROWS):
        for col in range(ALIEN_COLS):
            x = 10 + col * (ALIEN_W + ALIEN_GAP_X)
            y = ALIEN_START_Y + row * (ALIEN_H + ALIEN_GAP_Y)
            aliens.append({"x": x, "y": y, "alive": True, "row": row})

    shields = []
    offsets = [16, 54, 92]
    for sx in offsets:
        pixels = set()
        for py in range(SHIELD_Y, SHIELD_Y + SHIELD_H):
            for px in range(sx, sx + SHIELD_W):
                pixels.add((px, py))
        shields.append(pixels)

    return {
        "ship_x": 60,
        "aliens": aliens,
        "alien_dx": 1,
        "alien_move_timer": 0,
        "alien_speed": 12,
        "player_bullets": [],
        "alien_bullets": [],
        "shields": shields,
        "lives": MAX_LIVES,
        "score": 0,
        "game_over": False,
        "victory": False,
    }


# ---------------------------------------------------------------------------
# Update logic
# ---------------------------------------------------------------------------

def _move_aliens(state):
    """Move aliens side-to-side and descend on edge hit."""
    state["alien_move_timer"] += 1
    if state["alien_move_timer"] < state["alien_speed"]:
        return

    state["alien_move_timer"] = 0
    dx = state["alien_dx"]
    hit_edge = False

    for alien in state["aliens"]:
        if alien["alive"]:
            nx = alien["x"] + dx * 2
            if nx <= 0 or nx + ALIEN_W >= _GAME_W:
                hit_edge = True
                break

    if hit_edge:
        state["alien_dx"] = -state["alien_dx"]
        for alien in state["aliens"]:
            if alien["alive"]:
                alien["y"] += 4
                if alien["y"] + ALIEN_H >= SHIP_Y:
                    state["game_over"] = True
    else:
        for alien in state["aliens"]:
            if alien["alive"]:
                alien["x"] += dx * 2


def _move_bullets(state):
    """Move all bullets and remove off-screen ones."""
    state["player_bullets"] = [
        {"x": b["x"], "y": b["y"] - BULLET_SPEED}
        for b in state["player_bullets"]
        if b["y"] - BULLET_SPEED > 10
    ]
    state["alien_bullets"] = [
        {"x": b["x"], "y": b["y"] + ALIEN_BULLET_SPEED}
        for b in state["alien_bullets"]
        if b["y"] + ALIEN_BULLET_SPEED < _GAME_H
    ]


def _check_collisions(state):
    """Check bullet-alien, bullet-ship, and bullet-shield collisions."""
    remaining_pbullets = []
    for bullet in state["player_bullets"]:
        hit = False
        bx, by = bullet["x"], bullet["y"]

        for alien in state["aliens"]:
            if not alien["alive"]:
                continue
            if (alien["x"] <= bx <= alien["x"] + ALIEN_W and
                    alien["y"] <= by <= alien["y"] + ALIEN_H):
                alien["alive"] = False
                row_score = (ALIEN_ROWS - alien["row"]) * 10
                state["score"] += row_score
                hit = True
                break

        if not hit:
            for shield in state["shields"]:
                if (bx, by) in shield:
                    shield.discard((bx, by))
                    for dx in range(-2, 3):
                        for dy in range(-2, 3):
                            shield.discard((bx + dx, by + dy))
                    hit = True
                    break

        if not hit:
            remaining_pbullets.append(bullet)

    state["player_bullets"] = remaining_pbullets

    remaining_abullets = []
    for bullet in state["alien_bullets"]:
        hit = False
        bx, by = bullet["x"], bullet["y"]

        if (state["ship_x"] <= bx <= state["ship_x"] + SHIP_W and
                SHIP_Y <= by <= SHIP_Y + SHIP_H):
            state["lives"] -= 1
            if state["lives"] <= 0:
                state["game_over"] = True
            hit = True

        if not hit:
            for shield in state["shields"]:
                if (bx, by) in shield:
                    shield.discard((bx, by))
                    for dx in range(-2, 3):
                        for dy in range(-2, 3):
                            shield.discard((bx + dx, by + dy))
                    hit = True
                    break

        if not hit:
            remaining_abullets.append(bullet)

    state["alien_bullets"] = remaining_abullets

    alive_count = sum(1 for a in state["aliens"] if a["alive"])
    if alive_count == 0:
        state["victory"] = True

    if alive_count > 0:
        speed_factor = alive_count / (ALIEN_ROWS * ALIEN_COLS)
        state["alien_speed"] = max(2, int(12 * speed_factor))


def _alien_shoot(state):
    """Random aliens fire downward."""
    alive = [a for a in state["aliens"] if a["alive"]]
    for alien in alive:
        if random.random() < ALIEN_SHOOT_CHANCE:
            state["alien_bullets"].append({
                "x": alien["x"] + ALIEN_W // 2,
                "y": alien["y"] + ALIEN_H,
            })
            break


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def draw_game(state):
    """Render the full game frame."""
    img = Image.new("RGB", (_GAME_W, _GAME_H), "black")
    d = ImageDraw.Draw(img)

    d.rectangle((0, 0, 127, 11), fill="#001100")
    d.text((2, 1), f"SCORE:{state['score']}", font=font, fill="#00FF00")
    lives_str = "L:" + "*" * state["lives"]
    d.text((85, 1), lives_str, font=font, fill="#00FF00")

    for alien in state["aliens"]:
        if not alien["alive"]:
            continue
        ax, ay = alien["x"], alien["y"]
        d.rectangle((ax, ay, ax + ALIEN_W, ay + ALIEN_H), fill="#00CC00")
        d.point((ax + 2, ay + 2), fill="#00FF00")
        d.point((ax + ALIEN_W - 2, ay + 2), fill="#00FF00")
        d.line([(ax + 1, ay + ALIEN_H - 2), (ax + ALIEN_W - 1, ay + ALIEN_H - 2)],
               fill="#004400")

    for shield in state["shields"]:
        for px, py in shield:
            d.point((px, py), fill="#006600")

    sx = state["ship_x"]
    d.rectangle((sx, SHIP_Y, sx + SHIP_W, SHIP_Y + SHIP_H), fill="#00FF00")
    d.polygon(
        [(sx + SHIP_W // 2, SHIP_Y - 3), (sx + 2, SHIP_Y), (sx + SHIP_W - 2, SHIP_Y)],
        fill="#00FF00",
    )

    for b in state["player_bullets"]:
        d.rectangle((b["x"] - 1, b["y"], b["x"] + 1, b["y"] + 3), fill="#00FF00")

    for b in state["alien_bullets"]:
        d.rectangle((b["x"] - 1, b["y"], b["x"] + 1, b["y"] + 3), fill="#FF0000")

    if state["game_over"]:
        d.rectangle((10, 45, 118, 75), fill="#000000", outline="#FF0000")
        d.text((20, 50), "GAME OVER", font=font, fill="#FF0000")
        d.text((15, 62), f"Score: {state['score']}", font=font, fill="#00FF00")
        d.text((12, 72), "K1:Restart K3:Exit", font=font, fill="#888")
    elif state["victory"]:
        d.rectangle((10, 45, 118, 75), fill="#000000", outline="#00FF00")
        d.text((22, 50), "VICTORY!", font=font, fill="#00FF00")
        d.text((15, 62), f"Score: {state['score']}", font=font, fill="#00FF00")
        d.text((12, 72), "K1:Restart K3:Exit", font=font, fill="#888")

    if _GAME_W != WIDTH or _GAME_H != HEIGHT:
        img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    state = _make_state()

    img = Image.new("RGB", (_GAME_W, _GAME_H), "black")
    d = ImageDraw.Draw(img)
    d.text((10, 25), "SPACE INVADERS", font=font, fill="#00FF00")
    d.text((10, 50), "L/R=Move  OK=Fire", font=font, fill="#006600")
    d.text((10, 62), "K1=Restart", font=font, fill="#006600")
    d.text((10, 74), "K3=Exit", font=font, fill="#006600")
    if _GAME_W != WIDTH or _GAME_H != HEIGHT:
        img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    fire_cooldown = 0

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            if btn == "KEY1":
                state = _make_state()
                fire_cooldown = 0
                time.sleep(0.3)
                continue

            if state["game_over"] or state["victory"]:
                draw_game(state)
                time.sleep(0.1)
                continue

            if btn == "LEFT":
                state["ship_x"] = max(0, state["ship_x"] - 3)
            elif btn == "RIGHT":
                state["ship_x"] = min(_GAME_W - SHIP_W, state["ship_x"] + 3)
            elif btn == "OK" and fire_cooldown <= 0:
                state["player_bullets"].append({
                    "x": state["ship_x"] + SHIP_W // 2,
                    "y": SHIP_Y - 4,
                })
                fire_cooldown = 4

            _move_aliens(state)
            _move_bullets(state)
            _check_collisions(state)
            _alien_shoot(state)

            if fire_cooldown > 0:
                fire_cooldown -= 1

            draw_game(state)
            time.sleep(0.03)

    finally:
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
