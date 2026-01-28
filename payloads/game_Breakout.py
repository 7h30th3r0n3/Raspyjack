#!/usr/bin/env python3
"""
RaspyJack *payload* – **Breakout**
================================
Classic arcade Break-out clone for the Waveshare 1.44-inch LCD HAT on Raspberry Pi.

Inspired by – and **building upon** – the companion example *example_show_buttons.py*.
Highlights
----------
* **Simple controls**: move the paddle with the joystick **LEFT / RIGHT** (or
  **UP / DOWN** as alternatives) and start/reset the game with **KEY1**.
  Press **KEY3** (bottom-right) or *Ctrl-C* to quit gracefully.
* **Full-screen graphics** rendered with Pillow off-screen buffers before being
  blitted to the LCD – keeps flicker low while remaining readable.
* **Tiny codebase (< 300 LOC)** yet heavily commented so Python beginners can
  follow every step.

Gameplay tweaks (feel free to experiment!)
* ``BRICK_ROWS`` and ``BRICK_COLS`` change the wall size.
* ``PADDLE_WIDTH`` or ``BALL_SPEED`` for a tougher challenge.
* ``FPS`` controls the refresh rate (30 Hz is a good compromise).

Enjoy!
"""

# ---------------------------------------------------------------------------
# 0) Make example_show_buttons.py helpers available when launched directly
# ---------------------------------------------------------------------------
import os, sys, signal, time, random
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

# ---------------------------- Standard library ----------------------------
from typing import List, Tuple

# ----------------------------- Third-party libs ---------------------------
import RPi.GPIO as GPIO               # Raspberry Pi GPIO access
import LCD_1in44, LCD_Config          # Waveshare driver helpers for the LCD
from PIL import Image, ImageDraw, ImageFont

# ---------------------------------------------------------------------------
# 1) GPIO pin mapping (BCM numbering)
# ---------------------------------------------------------------------------
PINS: dict[str, int] = {
    "UP"   : 6,
    "DOWN" : 19,
    "LEFT" : 5,
    "RIGHT": 26,
    "OK"   : 13,  # joystick centre (unused)
    "KEY1" : 21,  # START / RESET
    "KEY2" : 20,  # reserved (potential extra life?)
    "KEY3" : 16,  # EXIT back to menu
}

# ---------------------------------------------------------------------------
# 2) Gameplay constants
# ---------------------------------------------------------------------------
WIDTH, HEIGHT   = 128, 128           # LCD resolution (pixels)
MARGIN_TOP      = 10                 # leave room for score display
FPS             = 30                 # refresh rate (frames per second)
FRAME_DELAY     = 1 / FPS

# Paddle
PADDLE_WIDTH    = 26
PADDLE_HEIGHT   = 4
PADDLE_Y        = HEIGHT - 15        # vertical position of the paddle
PADDLE_SPEED    = 3                  # pixels per frame

# Ball
BALL_SIZE       = 3                  # ball is drawn as a square for speed
BALL_SPEED      = 2.2                # initial speed (pixels per frame)

# Bricks
BRICK_ROWS      = 4
BRICK_COLS      = 8
BRICK_GAP       = 2                  # gap between bricks
BRICK_HEIGHT    = 6
BRICK_COLORS    = ["#FF5555", "#FFAA00", "#55FF55", "#0099FF"]  # one per row

# ---------------------------------------------------------------------------
# 3) LCD & GPIO initialisation
# ---------------------------------------------------------------------------
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
FONT = ImageFont.load_default()

# ---------------------------------------------------------------------------
# 4) Helper classes
# ---------------------------------------------------------------------------
class Paddle:
    """Player paddle controlled by the joystick."""
    def __init__(self) -> None:
        self.x = (WIDTH - PADDLE_WIDTH) // 2  # centred

    @property
    def rect(self) -> Tuple[int, int, int, int]:
        return (self.x, PADDLE_Y, self.x + PADDLE_WIDTH, PADDLE_Y + PADDLE_HEIGHT)

    def move(self, direction: int):
        """Move paddle horizontally; *direction* = -1 (left) or +1 (right)."""
        self.x += direction * PADDLE_SPEED
        self.x = max(0, min(self.x, WIDTH - PADDLE_WIDTH))

class Ball:
    """Ball object – handles movement & collisions."""
    def __init__(self):
        self.reset()

    def reset(self):
        self.x = WIDTH  // 2
        self.y = HEIGHT // 2
        # random initial heading (avoid near-vertical angles)
        angle = random.uniform(-60, 60) if random.random() < 0.5 else random.uniform(120, 240)
        rad = angle * 3.14159 / 180
        self.vx = BALL_SPEED * math.cos(rad)
        self.vy = BALL_SPEED * math.sin(rad)

    def update(self):
        self.x += self.vx
        self.y += self.vy

    @property
    def rect(self) -> Tuple[int, int, int, int]:
        return (int(self.x), int(self.y), int(self.x + BALL_SIZE), int(self.y + BALL_SIZE))

# ---------------------------------------------------------------------------
# 5) Utility functions
# ---------------------------------------------------------------------------
import math

def create_bricks() -> List[Tuple[int, int, int, int]]:
    """Return a list of brick rectangles (x0, y0, x1, y1)."""
    brick_width = (WIDTH - BRICK_GAP * (BRICK_COLS + 1)) // BRICK_COLS
    bricks: List[Tuple[int, int, int, int]] = []
    for row in range(BRICK_ROWS):
        for col in range(BRICK_COLS):
            x0 = BRICK_GAP + col * (brick_width + BRICK_GAP)
            y0 = MARGIN_TOP + BRICK_GAP + row * (BRICK_HEIGHT + BRICK_GAP)
            bricks.append((x0, y0, x0 + brick_width, y0 + BRICK_HEIGHT))
    return bricks


def draw_screen(draw: ImageDraw.ImageDraw, paddle: Paddle, ball: Ball, bricks: List[Tuple[int,int,int,int]], score: int):
    """Draw game elements to the Pillow canvas."""
    # Bricks
    brick_width = bricks[0][2] - bricks[0][0] if bricks else 0
    for idx, brick in enumerate(bricks):
        row = (brick[1] - (MARGIN_TOP + BRICK_GAP)) // (BRICK_HEIGHT + BRICK_GAP)
        color = BRICK_COLORS[row % len(BRICK_COLORS)]
        draw.rectangle(brick, fill=color)

    # Paddle
    draw.rectangle(paddle.rect, fill="#FFFFFF")
    # Ball
    draw.rectangle(ball.rect, fill="#FFFFFF")
    # Score
    draw.text((2, 0), f"Score: {score}", font=FONT, fill="#FFFFFF")


def intersect(rect1, rect2) -> bool:
    """Axis aligned rectangle collision."""
    return not (rect1[2] <= rect2[0] or rect1[0] >= rect2[2] or rect1[3] <= rect2[1] or rect1[1] >= rect2[3])


# ---------------------------------------------------------------------------
# 6) Main gameloop
# ---------------------------------------------------------------------------

def main():
    paddle = Paddle()
    ball = Ball()
    bricks = create_bricks()
    score = 0
    running = True
    last_frame = time.perf_counter()

    def cleanup(*_):
        nonlocal running
        running = False

    # Ctrl-C or KEY3 exits
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    while running:
        frame_start = time.perf_counter()

        # -------------------------------- Input --------------------------------
        if GPIO.input(PINS["LEFT"]) == 0 or GPIO.input(PINS["UP"]) == 0:
            paddle.move(-1)
        if GPIO.input(PINS["RIGHT"]) == 0 or GPIO.input(PINS["DOWN"]) == 0:
            paddle.move(1)

        if GPIO.input(PINS["KEY3"]) == 0:  # immediate quit on KEY3
            break

        # Start/reset on KEY1 when ball is out of play
        if GPIO.input(PINS["KEY1"]) == 0 and (ball.y > HEIGHT or not bricks):
            paddle = Paddle()
            ball = Ball()
            bricks = create_bricks()
            score = 0
            time.sleep(0.3)  # basic debounce

        # ------------------------------- Physics -------------------------------
        ball.update()

        # Wall collisions
        if ball.x <= 0:
            ball.x = 0; ball.vx = abs(ball.vx)
        if ball.x + BALL_SIZE >= WIDTH:
            ball.x = WIDTH - BALL_SIZE; ball.vx = -abs(ball.vx)
        if ball.y <= MARGIN_TOP:
            ball.y = MARGIN_TOP; ball.vy = abs(ball.vy)

        # Paddle collision
        if ball.vy > 0 and intersect(ball.rect, paddle.rect):
            ball.y = PADDLE_Y - BALL_SIZE
            # Bounce depending on where the ball hits the paddle
            hit_pos = (ball.x + BALL_SIZE/2) - (paddle.x + PADDLE_WIDTH/2)
            ball.vx = hit_pos / (PADDLE_WIDTH/2) * BALL_SPEED
            ball.vy = -abs(ball.vy)

        # Brick collisions – iterate over copy to allow removal while looping
        for brick in bricks[:]:
            if intersect(ball.rect, brick):
                bricks.remove(brick)
                score += 10
                # Simple bounce: reverse vertical velocity
                ball.vy = -ball.vy
                break  # avoid double collisions in same frame

        # Ball falls below paddle → game over (wait for reset)
        if ball.y > HEIGHT:
            ball.vx = ball.vy = 0  # freeze ball

        # -------------------------------- Render -------------------------------
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ImageDraw.Draw(img)
        draw_screen(d, paddle, ball, bricks, score)
        LCD.LCD_ShowImage(img, 0, 0)

        # -------------------------------- Timing -------------------------------
        frame_time = time.perf_counter() - frame_start
        sleep_time = FRAME_DELAY - frame_time
        if sleep_time > 0:
            time.sleep(sleep_time)

    # -----------------------------------------------------------------------
    # Exit
    # -----------------------------------------------------------------------
    LCD.LCD_Clear()
    GPIO.cleanup()


if __name__ == "__main__":
    main()
