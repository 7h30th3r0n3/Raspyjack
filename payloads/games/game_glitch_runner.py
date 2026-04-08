#!/usr/bin/env python3
"""
RaspyJack Payload -- Glitch Runner (Cyberpunk Platformer)
==========================================================
Author: 7h30th3r0n3

Side-scrolling endless runner with cyberpunk aesthetic.
Jump over tall blocks, duck under low blocks.
Speed increases over time. Glitch effect on death.

Controls:
  UP    -- Jump
  DOWN  -- Duck
  KEY1  -- Restart after game over
  KEY3  -- Exit
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
# Colours
# ---------------------------------------------------------------------------
COL_BG = (5, 5, 15)
COL_GROUND = (0, 180, 180)
COL_GROUND_LINE = (0, 100, 100)
COL_PLAYER = (0, 255, 80)
COL_PLAYER_DUCK = (0, 200, 60)
COL_OBS_TALL = (255, 0, 120)
COL_OBS_LOW = (180, 0, 255)
COL_OBS_GAP = (80, 0, 0)
COL_TEXT = (0, 255, 200)
COL_SCORE = (200, 200, 255)
COL_HI = (255, 255, 0)
COL_GLITCH_1 = (255, 0, 255)
COL_GLITCH_2 = (0, 255, 255)

# ---------------------------------------------------------------------------
# Game constants
# ---------------------------------------------------------------------------
GROUND_Y = 100
PLAYER_X = 20
PLAYER_W = 8
PLAYER_H_STAND = 16
PLAYER_H_DUCK = 8

GRAVITY = 1.2
JUMP_VEL = -10.0

OBS_MIN_GAP = 35
OBS_MAX_GAP = 55
OBS_WIDTH = 10

# Obstacle types
OBS_TALL = "tall"      # must jump over
OBS_LOW = "low"        # must duck under
OBS_GAP = "gap"        # hole in ground, don't fall

INITIAL_SPEED = 3.0
SPEED_INCREMENT = 0.002
MAX_SPEED = 7.0

FPS = 20
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
# Game state
# ---------------------------------------------------------------------------
def make_obstacle(x_pos, obs_type):
    """Create an obstacle dict."""
    if obs_type == OBS_TALL:
        return {"type": OBS_TALL, "x": x_pos, "w": OBS_WIDTH, "h": 24, "y": GROUND_Y - 24}
    elif obs_type == OBS_LOW:
        return {"type": OBS_LOW, "x": x_pos, "w": OBS_WIDTH + 4, "h": 10,
                "y": GROUND_Y - 22}
    else:  # gap
        return {"type": OBS_GAP, "x": x_pos, "w": 14, "h": 20, "y": GROUND_Y}


def init_state():
    """Create fresh game state."""
    return {
        "player_y": float(GROUND_Y - PLAYER_H_STAND),
        "vel_y": 0.0,
        "ducking": False,
        "on_ground": True,
        "obstacles": [],
        "score": 0,
        "speed": INITIAL_SPEED,
        "next_obs_x": _GAME_W + 30,
        "frame_count": 0,
    }


def spawn_obstacle(state):
    """Maybe spawn a new obstacle, returns updated state."""
    obstacles = list(state["obstacles"])
    next_x = state["next_obs_x"]
    speed = state["speed"]

    if not obstacles or obstacles[-1]["x"] < _GAME_W - OBS_MIN_GAP:
        if next_x <= _GAME_W + 10:
            obs_type = random.choice([OBS_TALL, OBS_TALL, OBS_LOW, OBS_LOW, OBS_GAP])
            obstacles = obstacles + [make_obstacle(next_x, obs_type)]
            gap = random.randint(OBS_MIN_GAP, OBS_MAX_GAP)
            next_x = next_x + gap

    return {**state, "obstacles": obstacles, "next_obs_x": next_x}


def update_obstacles(state):
    """Move obstacles left and remove off-screen ones."""
    speed = state["speed"]
    moved = []
    for obs in state["obstacles"]:
        new_x = obs["x"] - speed
        if new_x + obs["w"] > 0:
            moved.append({**obs, "x": new_x})
    return {**state, "obstacles": moved, "next_obs_x": state["next_obs_x"] - speed}


def update_player(state, jump_pressed, duck_pressed):
    """Update player vertical position and ducking state."""
    py = state["player_y"]
    vy = state["vel_y"]
    ducking = state["ducking"]
    on_ground = state["on_ground"]

    # Check if over a gap
    over_gap = False
    ph = PLAYER_H_DUCK if ducking else PLAYER_H_STAND
    player_left = PLAYER_X
    player_right = PLAYER_X + PLAYER_W
    for obs in state["obstacles"]:
        if obs["type"] == OBS_GAP:
            if player_right > obs["x"] and player_left < obs["x"] + obs["w"]:
                over_gap = True
                break

    # Jump
    if jump_pressed and on_ground and not over_gap:
        vy = JUMP_VEL
        on_ground = False
        ducking = False

    # Duck
    ducking = duck_pressed and on_ground and not over_gap

    # Gravity
    vy = vy + GRAVITY
    py = py + vy

    # Ground collision
    stand_h = PLAYER_H_DUCK if ducking else PLAYER_H_STAND
    ground_level = float(GROUND_Y - stand_h)

    if over_gap:
        # Falling into gap
        if py > _GAME_H:
            return {**state, "player_y": py, "vel_y": vy,
                    "ducking": ducking, "on_ground": False}
    else:
        if py >= ground_level:
            py = ground_level
            vy = 0.0
            on_ground = True

    return {**state, "player_y": py, "vel_y": vy,
            "ducking": ducking, "on_ground": on_ground}


def check_collision(state):
    """Check if player hits any obstacle. Returns True if dead."""
    ducking = state["ducking"]
    py = state["player_y"]
    ph = PLAYER_H_DUCK if ducking else PLAYER_H_STAND
    px1 = PLAYER_X
    px2 = PLAYER_X + PLAYER_W
    py1 = py
    py2 = py + ph

    for obs in state["obstacles"]:
        if obs["type"] == OBS_GAP:
            # Fall into gap = death (handled by y > screen height)
            if py > _GAME_H:
                return True
            continue

        ox1 = obs["x"]
        ox2 = obs["x"] + obs["w"]
        oy1 = obs["y"]
        oy2 = obs["y"] + obs["h"]

        # AABB overlap
        if px2 > ox1 and px1 < ox2 and py2 > oy1 and py1 < oy2:
            return True

    return False


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------
def draw_ground(d, frame_count, speed):
    """Draw the ground line with scrolling dashes."""
    d.line([(0, GROUND_Y), (_GAME_W, GROUND_Y)], fill=COL_GROUND, width=2)
    offset = int(frame_count * speed) % 16
    for x in range(0, _GAME_W + 16, 16):
        sx = x - offset
        d.line([(sx, GROUND_Y + 4), (sx + 6, GROUND_Y + 4)],
               fill=COL_GROUND_LINE, width=1)


def draw_player(d, state):
    """Draw the player character."""
    ducking = state["ducking"]
    py = int(state["player_y"])
    ph = PLAYER_H_DUCK if ducking else PLAYER_H_STAND
    col = COL_PLAYER_DUCK if ducking else COL_PLAYER

    # Body
    d.rectangle([PLAYER_X, py, PLAYER_X + PLAYER_W, py + ph], fill=col)

    # Eye
    eye_y = py + 2
    d.rectangle([PLAYER_X + 5, eye_y, PLAYER_X + 7, eye_y + 2],
                fill=(255, 255, 255))


def draw_obstacles(d, obstacles):
    """Draw all obstacles."""
    for obs in obstacles:
        ox = int(obs["x"])
        if obs["type"] == OBS_TALL:
            d.rectangle([ox, obs["y"], ox + obs["w"], obs["y"] + obs["h"]],
                        fill=COL_OBS_TALL)
            # Neon outline
            d.rectangle([ox, obs["y"], ox + obs["w"], obs["y"] + obs["h"]],
                        outline=(255, 100, 180))
        elif obs["type"] == OBS_LOW:
            d.rectangle([ox, obs["y"], ox + obs["w"], obs["y"] + obs["h"]],
                        fill=COL_OBS_LOW)
            d.rectangle([ox, obs["y"], ox + obs["w"], obs["y"] + obs["h"]],
                        outline=(220, 100, 255))
        elif obs["type"] == OBS_GAP:
            # Draw gap as hole in ground
            d.rectangle([ox, GROUND_Y, ox + obs["w"], GROUND_Y + 20],
                        fill=COL_BG)
            d.line([(ox, GROUND_Y + 20), (ox + obs["w"], GROUND_Y + 20)],
                   fill=COL_GROUND_LINE)


def draw_glitch_effect(img):
    """Apply random pixel noise glitch effect on death."""
    pixels = img.load()
    for _ in range(600):
        gx = random.randint(0, _GAME_W - 1)
        gy = random.randint(0, _GAME_H - 1)
        col = random.choice([COL_GLITCH_1, COL_GLITCH_2, (255, 255, 255),
                             (0, 0, 0)])
        pixels[gx, gy] = col
    # Horizontal line glitches
    for _ in range(8):
        gy = random.randint(0, _GAME_H - 1)
        gx_start = random.randint(0, _GAME_W - 20)
        length = random.randint(10, 40)
        col = random.choice([COL_GLITCH_1, COL_GLITCH_2])
        for gx in range(gx_start, min(gx_start + length, _GAME_W)):
            pixels[gx, gy] = col
    return img


def draw_frame(state, game_over=False, high_score=0):
    """Render entire game frame."""
    img = Image.new("RGB", (_GAME_W, _GAME_H), COL_BG)
    d = ImageDraw.Draw(img)

    # Ground
    draw_ground(d, state["frame_count"], state["speed"])

    # Obstacles
    draw_obstacles(d, state["obstacles"])

    # Player
    draw_player(d, state)

    # Score HUD
    score_txt = f"DIST:{state['score']}"
    d.text((2, 2), score_txt, font=font, fill=COL_SCORE)

    speed_pct = int((state["speed"] - INITIAL_SPEED) /
                    (MAX_SPEED - INITIAL_SPEED) * 100)
    d.text((80, 2), f"SPD:{speed_pct}%", font=font, fill=COL_GROUND)

    if game_over:
        img = draw_glitch_effect(img)
        d = ImageDraw.Draw(img)
        # Game over box
        d.rectangle([14, 40, 114, 90], fill=(0, 0, 0), outline=COL_GLITCH_1)
        d.text((30, 44), "GAME OVER", font=font, fill=COL_GLITCH_1)
        d.text((22, 56), f"Score: {state['score']}", font=font, fill=COL_TEXT)
        d.text((22, 68), f"Best:  {high_score}", font=font, fill=COL_HI)
        d.text((16, 80), "KEY1:Retry KEY3:Exit", font=font, fill=COL_SCORE)

    if _GAME_W != WIDTH or _GAME_H != HEIGHT:
        img = img.resize((WIDTH, HEIGHT), Image.NEAREST)
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main game loop
# ---------------------------------------------------------------------------
high_score = 0


def play():
    """Single round of Glitch Runner."""
    global high_score
    state = init_state()

    while running:
        t0 = time.time()

        # Input
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            return

        jump = btn == "UP"
        duck = btn == "DOWN"

        # Update
        state = spawn_obstacle(state)
        state = update_obstacles(state)
        state = update_player(state, jump, duck)

        # Increment score and speed
        new_score = state["score"] + 1
        new_speed = min(state["speed"] + SPEED_INCREMENT, MAX_SPEED)
        state = {**state, "score": new_score, "speed": new_speed,
                 "frame_count": state["frame_count"] + 1}

        # Collision
        if check_collision(state):
            if state["score"] > high_score:
                high_score = state["score"]
            draw_frame(state, game_over=True, high_score=high_score)

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
        draw_frame(state)

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
