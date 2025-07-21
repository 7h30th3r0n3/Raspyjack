#!/usr/bin/env python3
"""
RaspyJack payload – Micro Shell on 1.44‑inch LCD (v1.6)
======================================================
Hand‑held Linux terminal: interactive **/bin/bash** in a PTY, driven by a USB
keyboard, rendered on a 128 × 128 Waveshare LCD.

Requirements
------------
    sudo apt install python3-evdev

Quit : *Esc* on keyboard **or** **KEY3** on the HAT.
"""

# ---------------------------------------------------------
# 0) Imports & path tweaks
# ---------------------------------------------------------
import os, sys, time, signal, select, fcntl, pty, re
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

import LCD_1in44, LCD_Config          # Waveshare LCD driver
from PIL import Image, ImageDraw, ImageFont
from evdev import InputDevice, categorize, ecodes, list_devices
import RPi.GPIO as GPIO               # Raspberry Pi GPIO access

# ---------------------------------------------------------
# 1) LCD initialisation
# ---------------------------------------------------------
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128

# ---------------------------------------------------------
# 2) Font management (zoom)
# ---------------------------------------------------------
FONT_MIN, FONT_MAX = 6, 10
FONT_SIZE = 8  # start size – will change with KEY1/KEY2


def load_font(size: int):
    """Try DejaVu Sans Mono at *size* px; fall back to Pillow default."""
    try:
        return ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", size
        )
    except Exception:
        return ImageFont.load_default()


# Globals recalculated in set_font()
font = None  # type: ignore
CHAR_W = CHAR_H = COLS = ROWS = 0  # type: ignore

def set_font(size: int):
    """Change global font + metrics and redraw current screen."""
    global FONT_SIZE, font, CHAR_W, CHAR_H, COLS, ROWS
    FONT_SIZE = max(FONT_MIN, min(FONT_MAX, size))
    font = load_font(FONT_SIZE)
    # Measure one glyph
    _img = Image.new("RGB", (10, 10))
    _d = ImageDraw.Draw(_img)
    CHAR_W, CHAR_H = _d.textsize("M", font=font)
    COLS, ROWS = WIDTH // CHAR_W, HEIGHT // CHAR_H


set_font(FONT_SIZE)  # initialise

# ---------------------------------------------------------
# 3) GPIO pins – KEY1/KEY2 zoom, KEY3 quit
# ---------------------------------------------------------
KEY1_PIN, KEY2_PIN, KEY3_PIN = 21, 20, 16
GPIO.setmode(GPIO.BCM)
for p in (KEY1_PIN, KEY2_PIN, KEY3_PIN):
    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

_prev_state = {p: 1 for p in (KEY1_PIN, KEY2_PIN)}  # edge detection

# ---------------------------------------------------------
# 4) Locate USB keyboard
# ---------------------------------------------------------

def find_keyboard() -> InputDevice:
    for path in list_devices():
        dev = InputDevice(path)
        if ecodes.EV_KEY in dev.capabilities():
            return dev
    raise RuntimeError("No USB keyboard detected – plug one via OTG?")


# ---------------------------------------------------------
# 5) Screen drawing helpers
# ---------------------------------------------------------
scrollback: list[str] = []
current_line: str = ""


def draw_buffer(lines: list[str], partial: str = "") -> None:
    """Render last ROWS‑1 lines + *partial* line to LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    visible = lines[-(ROWS - 1):] + [partial]
    y = 0
    for line in visible:
        d.text((0, y), line.ljust(COLS)[:COLS], font=font, fill="#00FF00")
        y += CHAR_H
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------
# 6) Spawn Bash in PTY
# ---------------------------------------------------------

pid, master_fd = pty.fork()
if pid == 0:
    os.execv("/bin/bash", ["bash", "--login"])
# parent
fcntl.fcntl(master_fd, fcntl.F_SETFL, fcntl.fcntl(master_fd, fcntl.F_GETFL) | os.O_NONBLOCK)

# ---------------------------------------------------------
# 7) Keyboard device + poller
# ---------------------------------------------------------
keyboard = find_keyboard()
if hasattr(keyboard, "set_blocking"):
    keyboard.set_blocking(False)
elif hasattr(keyboard, "setblocking"):
    keyboard.setblocking(False)
else:
    fcntl.fcntl(keyboard.fd, fcntl.F_SETFL, os.O_NONBLOCK)

poller = select.poll()
poller.register(master_fd, select.POLLIN)
poller.register(keyboard.fd, select.POLLIN)

# ---------------------------------------------------------
# 8) Keycode maps
# ---------------------------------------------------------
SHIFT_KEYS = {"KEY_LEFTSHIFT", "KEY_RIGHTSHIFT"}
KEYMAP = {
    **{f"KEY_{c}": c.lower() for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
    "KEY_SPACE": " ",
    "KEY_ENTER": "\n", "KEY_KPENTER": "\n",
    "KEY_BACKSPACE": "\x7f",  # DEL char (127)
    "KEY_TAB": "\t",
    "KEY_MINUS": "-", "KEY_EQUAL": "=", "KEY_LEFTBRACE": "[",
    "KEY_RIGHTBRACE": "]", "KEY_BACKSLASH": "\\", "KEY_SEMICOLON": ";",
    "KEY_APOSTROPHE": "'", "KEY_GRAVE": "`", "KEY_COMMA": ",",
    "KEY_DOT": ".", "KEY_SLASH": "/",
    "KEY_1": "1", "KEY_2": "2", "KEY_3": "3", "KEY_4": "4",
    "KEY_5": "5", "KEY_6": "6", "KEY_7": "7", "KEY_8": "8",
    "KEY_9": "9", "KEY_0": "0",
}
SHIFT_MAP = {
    "KEY_1": "!", "KEY_2": "@", "KEY_3": "#", "KEY_4": "$", "KEY_5": "%",
    "KEY_6": "^", "KEY_7": "&", "KEY_8": "*", "KEY_9": "(", "KEY_0": ")",
    "KEY_MINUS": "_", "KEY_EQUAL": "+", "KEY_LEFTBRACE": "{", "KEY_RIGHTBRACE": "}",
    "KEY_BACKSLASH": "|", "KEY_SEMICOLON": ":", "KEY_APOSTROPHE": "\"",
    "KEY_GRAVE": "~", "KEY_COMMA": "<", "KEY_DOT": ">", "KEY_SLASH": "?",
    **{f"KEY_{c}": c for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
}
ansi_escape = re.compile(r"\x1B\[[0-9;]*[A-Za-z]")

# ---------------------------------------------------------
# 9) Helpers
# ---------------------------------------------------------

def write_byte(s: str):
    os.write(master_fd, s.encode())


def process_shell_output():
    global current_line, scrollback
    try:
        data = os.read(master_fd, 1024).decode(errors="ignore")
    except BlockingIOError:
        return
    if not data:
        return
    clean = ansi_escape.sub("", data)
    for ch in clean:
        if ch == "\n":  # Line Feed → commit line
            scrollback.append(current_line)
            current_line = ""
        elif ch == "\r":  # Carriage Return → ignore in this simple renderer
            continue
        elif ch in ("\x08", "\x7f"):  # Backspace / DEL → erase last char
            current_line = current_line[:-1]
        else:
            current_line += ch
            # wrap long lines
            while len(current_line) > COLS:
                scrollback.append(current_line[:COLS])
                current_line = current_line[COLS:]
    # cap scrollback
    if len(scrollback) > 256:
        scrollback = scrollback[-256:]
    draw_buffer(scrollback, current_line)


shift = False
running = True

def handle_key(event):
    global shift, running
    key_name = event.keycode if isinstance(event.keycode, str) else event.keycode[0]
    if key_name in SHIFT_KEYS:
        shift = event.keystate == event.key_down
        return
    if event.keystate != event.key_down:
        return
    if key_name == "KEY_ESC" or GPIO.input(KEY3_PIN) == 0:
        running = False
        return
    char = SHIFT_MAP.get(key_name) if shift else KEYMAP.get(key_name)
    if char is not None:
        write_byte(char)


# ---------------------------------------------------------
# 10) Main loop
# ---------------------------------------------------------

draw_buffer([], "Micro Shell ready – KEY1/KEY2 = zoom ±")
try:
    while running:
        # Poll PTY + keyboard
        for fd, _ in poller.poll(50):
            if fd == master_fd:
                process_shell_output()
            elif fd == keyboard.fd:
                for ev in keyboard.read():
                    if ev.type == ecodes.EV_KEY:
                        handle_key(categorize(ev))
        # Zoom buttons
        for pin, delta in ((KEY1_PIN, +1), (KEY2_PIN, -1)):
            state = GPIO.input(pin)
            if _prev_state[pin] == 1 and state == 0:  # falling edge
                set_font(FONT_SIZE + delta)
                draw_buffer(scrollback, current_line)
                time.sleep(0.15)  # simple debounce
            _prev_state[pin] = state
        # Quit via KEY3 held
        if GPIO.input(KEY3_PIN) == 0:
            running = False
except Exception as exc:
    print(f"[ERROR] {exc}", file=sys.stderr)
finally:
    LCD.LCD_Clear()
    GPIO.cleanup()
    try:
        os.close(master_fd)
    except Exception:
        pass

