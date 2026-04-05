#!/usr/bin/env python3
"""
RaspyJack Payload -- Pong Game
-------------------------------
Author: 7h30th3r0n3

Classic Pong on the LCD. Green-on-black theme.

Controls:
  UP/DOWN  = move player paddle
  OK       = start / pause
  KEY1     = reset game
  KEY3     = exit
"""

import os
import sys
import time
import random

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
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

# Colors (green theme)
COL_BG = (0, 0, 0)
COL_PADDLE = (0, 255, 0)
COL_BALL = (0, 255, 0)
COL_NET = (0, 80, 0)
COL_SCORE = (0, 200, 0)
COL_TEXT = (0, 255, 0)

# Game constants
PADDLE_W = 3
PADDLE_H = 20
BALL_SIZE = 4
PADDLE_SPEED = 4
INITIAL_BALL_SPEED = 2.0
SPEED_INCREMENT = 0.15
MAX_BALL_SPEED = 5.0
AI_SPEED = 2.5
SCORE_Y = 2
FPS = 30
FRAME_DELAY = 1.0 / FPS


def _create_initial_state():
    """Create a fresh game state dict."""
    return {
        "player_y": _GAME_H // 2 - PADDLE_H // 2,
        "ai_y": _GAME_H // 2 - PADDLE_H // 2,
        "ball_x": float(_GAME_W // 2),
        "ball_y": float(_GAME_H // 2),
        "ball_dx": INITIAL_BALL_SPEED * random.choice([-1, 1]),
        "ball_dy": INITIAL_BALL_SPEED * random.choice([-0.7, 0.7]),
        "player_score": 0,
        "ai_score": 0,
        "speed": INITIAL_BALL_SPEED,
        "paused": True,
        "game_over": False,
    }


def _update_ball(state):
    """Update ball position and handle collisions. Returns new state."""
    if state["paused"] or state["game_over"]:
        return state

    new_bx = state["ball_x"] + state["ball_dx"]
    new_by = state["ball_y"] + state["ball_dy"]
    new_dx = state["ball_dx"]
    new_dy = state["ball_dy"]
    new_speed = state["speed"]
    p_score = state["player_score"]
    a_score = state["ai_score"]

    # Top/bottom wall bounce
    if new_by <= 12:
        new_by = 12.0
        new_dy = abs(new_dy)
    elif new_by + BALL_SIZE >= _GAME_H:
        new_by = float(_GAME_H - BALL_SIZE)
        new_dy = -abs(new_dy)

    # Player paddle collision (left side)
    p_x = 6
    if (new_bx <= p_x + PADDLE_W and
            new_bx >= p_x and
            new_by + BALL_SIZE >= state["player_y"] and
            new_by <= state["player_y"] + PADDLE_H):
        new_bx = float(p_x + PADDLE_W)
        new_speed = min(new_speed + SPEED_INCREMENT, MAX_BALL_SPEED)
        ratio = (new_by - state["player_y"]) / PADDLE_H - 0.5
        new_dx = new_speed
        new_dy = ratio * new_speed * 1.5

    # AI paddle collision (right side)
    a_x = _GAME_W - 6 - PADDLE_W
    if (new_bx + BALL_SIZE >= a_x and
            new_bx + BALL_SIZE <= a_x + PADDLE_W + 2 and
            new_by + BALL_SIZE >= state["ai_y"] and
            new_by <= state["ai_y"] + PADDLE_H):
        new_bx = float(a_x - BALL_SIZE)
        new_speed = min(new_speed + SPEED_INCREMENT, MAX_BALL_SPEED)
        ratio = (new_by - state["ai_y"]) / PADDLE_H - 0.5
        new_dx = -new_speed
        new_dy = ratio * new_speed * 1.5

    # Scoring
    game_over = False
    if new_bx < 0:
        a_score += 1
        new_bx = float(_GAME_W // 2)
        new_by = float(_GAME_H // 2)
        new_speed = INITIAL_BALL_SPEED
        new_dx = new_speed
        new_dy = INITIAL_BALL_SPEED * random.choice([-0.7, 0.7])
        if a_score >= 9:
            game_over = True
    elif new_bx > _GAME_W:
        p_score += 1
        new_bx = float(_GAME_W // 2)
        new_by = float(_GAME_H // 2)
        new_speed = INITIAL_BALL_SPEED
        new_dx = -new_speed
        new_dy = INITIAL_BALL_SPEED * random.choice([-0.7, 0.7])
        if p_score >= 9:
            game_over = True

    return {
        "player_y": state["player_y"],
        "ai_y": state["ai_y"],
        "ball_x": new_bx,
        "ball_y": new_by,
        "ball_dx": new_dx,
        "ball_dy": new_dy,
        "player_score": p_score,
        "ai_score": a_score,
        "speed": new_speed,
        "paused": state["paused"],
        "game_over": game_over,
    }


def _update_ai(state):
    """Move AI paddle toward ball. Returns new state."""
    if state["paused"] or state["game_over"]:
        return state

    ai_center = state["ai_y"] + PADDLE_H // 2
    target = state["ball_y"] + BALL_SIZE // 2
    diff = target - ai_center
    new_ai_y = state["ai_y"]

    if abs(diff) > 3:
        move = AI_SPEED if diff > 0 else -AI_SPEED
        new_ai_y = state["ai_y"] + move

    new_ai_y = max(12, min(_GAME_H - PADDLE_H, new_ai_y))

    return {
        **state,
        "ai_y": new_ai_y,
    }


def _draw_game(lcd, state):
    """Render the game state to LCD."""
    img = Image.new("RGB", (_GAME_W, _GAME_H), COL_BG)
    d = ImageDraw.Draw(img)

    # Score bar
    d.rectangle((0, 0, 127, 11), fill=(0, 20, 0))
    score_text = f"{state['player_score']}  -  {state['ai_score']}"
    d.text((40, SCORE_Y), score_text, font=font, fill=COL_SCORE)

    # Center net (dashed line)
    for yy in range(14, _GAME_H, 8):
        d.line((63, yy, 63, min(yy + 4, _GAME_H)), fill=COL_NET)

    # Player paddle (left)
    p_x = 6
    py = int(state["player_y"])
    d.rectangle((p_x, py, p_x + PADDLE_W, py + PADDLE_H), fill=COL_PADDLE)

    # AI paddle (right)
    a_x = _GAME_W - 6 - PADDLE_W
    ay = int(state["ai_y"])
    d.rectangle((a_x, ay, a_x + PADDLE_W, ay + PADDLE_H), fill=COL_PADDLE)

    # Ball
    bx, by = int(state["ball_x"]), int(state["ball_y"])
    d.rectangle((bx, by, bx + BALL_SIZE, by + BALL_SIZE), fill=COL_BALL)

    # Paused overlay
    if state["paused"] and not state["game_over"]:
        d.text((38, 55), "PAUSED", font=font, fill=COL_TEXT)
        d.text((28, 70), "OK to start", font=font, fill=(0, 150, 0))

    # Game over overlay
    if state["game_over"]:
        winner = "You WIN!" if state["player_score"] >= 9 else "AI Wins!"
        d.rectangle((20, 40, 108, 90), fill=(0, 30, 0))
        d.text((35, 45), "GAME OVER", font=font, fill=COL_TEXT)
        d.text((38, 60), winner, font=font, fill=COL_TEXT)
        d.text((28, 78), "K1=reset K3=quit", font=font, fill=(0, 150, 0))

    if _GAME_W != WIDTH or _GAME_H != HEIGHT:
        img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
    lcd.LCD_ShowImage(img, 0, 0)


def main():
    """Main entry point."""
    state = _create_initial_state()

    try:
        while True:
            frame_start = time.time()
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break
            elif btn == "KEY1":
                state = _create_initial_state()
            elif btn == "OK":
                if state["game_over"]:
                    state = _create_initial_state()
                else:
                    state = {**state, "paused": not state["paused"]}
            elif btn == "UP" and not state["paused"]:
                new_py = max(12, state["player_y"] - PADDLE_SPEED)
                state = {**state, "player_y": new_py}
            elif btn == "DOWN" and not state["paused"]:
                new_py = min(_GAME_H - PADDLE_H, state["player_y"] + PADDLE_SPEED)
                state = {**state, "player_y": new_py}

            state = _update_ball(state)
            state = _update_ai(state)

            _draw_game(LCD, state)

            elapsed = time.time() - frame_start
            remaining = FRAME_DELAY - elapsed
            if remaining > 0:
                time.sleep(remaining)

    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
