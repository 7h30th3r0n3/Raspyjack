#!/usr/bin/env python3
"""
RaspyJack *payload* example – **Show Buttons**
=============================================
This script lives in the ``payloads/`` folder of the RaspyJack project.
It demonstrates how to:

1. **Read** the on‑board joystick (UP / DOWN / LEFT / RIGHT / OK) **and** the
   three extra push‑buttons (KEY1 / KEY2 / KEY3) present on most Waveshare
   1.44‑inch LCD HATs.
2. **Display** the name of the button currently being pressed, centred on the
   LCD in bright green text.
3. **Exit cleanly** when:
   * the user presses **KEY3** (bottom‑right button) – *new feature*;
   * the user hits *Ctrl‑C* in the terminal;
   * RaspyJack UI sends a *SIGTERM* signal when the payload is stopped from the
     menu.

The code is **heavily commented** so that an absolute Python beginner can read
and understand every step.
"""

# ---------------------------------------------------------------------------
# 0) Make sure we can import local helper modules when launched directly
# ---------------------------------------------------------------------------
import os, sys
# «…/Raspyjack/» is two directories up from this script. Add it to sys.path so
# that `import LCD_1in44` works even when we run the script manually from
# inside the “payloads” folder.
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

# ---------------------------- Standard library ----------------------------
import time           # sleep() for timing / debouncing
import signal         # capture Ctrl‑C (SIGINT) & termination (SIGTERM)
import sys            # print exceptions to stderr

# ----------------------------- Third‑party libs ---------------------------
# These come pre‑installed on RaspyJack; on a vanilla Pi OS you’d need:
#   sudo apt install python3-pil python3-rpi.gpio
import RPi.GPIO as GPIO               # Raspberry Pi GPIO access
import LCD_1in44, LCD_Config          # Waveshare driver helpers for the LCD
from PIL import Image, ImageDraw, ImageFont  # Pillow – draw text on images

# ---------------------------------------------------------------------------
# 1) GPIO pin mapping (BCM numbering) – tweak here if your wiring differs
# ---------------------------------------------------------------------------
# Keys are logical names, values are BCM GPIO numbers on the Pi header.
# All buttons are **active‑LOW**: they read 0 V (logic 0) when pressed.
PINS: dict[str, int] = {
    "UP"   : 6,
    "DOWN" : 19,
    "LEFT" : 5,
    "RIGHT": 26,
    "OK"   : 13,   # joystick centre push
    "KEY1" : 21,
    "KEY2" : 20,
    "KEY3" : 16,   # ← acts as «Back to menu»
}

# ---------------------------------------------------------------------------
# 2) GPIO initialisation
# ---------------------------------------------------------------------------
GPIO.setmode(GPIO.BCM)  # use BCM numbers rather than physical pin numbers
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

# ---------------------------------------------------------------------------
# 3) LCD initialisation
# ---------------------------------------------------------------------------
LCD = LCD_1in44.LCD()                     # create driver instance
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)      # default scan direction (portrait)
WIDTH, HEIGHT = 128, 128                  # pixels
font = ImageFont.load_default()           # tiny fixed‑width font

# ---------------------------------------------------------------------------
# 4) Helper: draw centred text on the LCD
# ---------------------------------------------------------------------------

def draw(text: str) -> None:
    """Clear the screen and draw *text* centred in bright green."""
    # 4.1 – create a black canvas
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)

    # 4.2 – measure text size (Pillow ≥ 9.2 offers textbbox())
    if hasattr(d, "textbbox"):
        x0, y0, x1, y1 = d.textbbox((0, 0), text, font=font)
        w, h = x1 - x0, y1 - y0
    else:  # Pillow < 9.2 fallback
        w, h = d.textsize(text, font=font)

    # 4.3 – centre coordinates
    pos = ((WIDTH - w) // 2, (HEIGHT - h) // 2)

    # 4.4 – draw the text and push the image to the LCD
    d.text(pos, text, font=font, fill="#00FF00")
    LCD.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# 5) Graceful shutdown – SIGINT/SIGTERM & KEY3
# ---------------------------------------------------------------------------
running = True  # global flag for the main loop


def cleanup(*_):
    """Signal handler: stop the main loop so `finally` can clean up."""
    global running
    running = False

# Register handlers for Ctrl‑C and external termination
signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# 6) Main loop – poll buttons & update display
# ---------------------------------------------------------------------------
try:
    draw("Ready!")

    while running:
        pressed: str | None = None  # name of the button currently pressed

        # 6.1 – scan all buttons; break at the first active‑LOW pin
        for name, pin in PINS.items():
            if GPIO.input(pin) == 0:  # button pressed
                pressed = name
                break

        # 6.2 – act on the result
        if pressed:
            if pressed == "KEY3":  # ← user wants to go back to RaspyJack
                running = False    # leave the main loop → exit script
                break

            # display which button was pressed
            draw(f"{pressed} pressed")

            # wait until the same button is released (basic debouncing)
            while GPIO.input(PINS[pressed]) == 0 and running:
                time.sleep(0.05)
        else:
            # no button activity → small sleep to reduce CPU usage
            time.sleep(0.05)

except Exception as exc:
    # Log unexpected errors
    print(f"[ERROR] {exc}", file=sys.stderr)

finally:
    # -----------------------------------------------------------------------
    # 7) Always executed: clear the screen and release GPIO resources
    # -----------------------------------------------------------------------
    LCD.LCD_Clear()   # avoid leaving ghost images on the display
    GPIO.cleanup()    # reset all GPIO pins to a safe state

