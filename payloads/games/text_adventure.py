#!/usr/bin/env python3
"""
RaspyJack Payload -- LLM Text Adventure
=========================================
Author: 7h30th3r0n3

Cyberpunk text adventure powered by Anthropic Claude API.
Displays scene text with two choices. Falls back to built-in
offline adventure when no API key is available.

Controls:
  LEFT  -- Select choice A
  RIGHT -- Select choice B
  OK    -- Confirm selection
  KEY3  -- Exit

API key: env var ANTHROPIC_API_KEY or /root/Raspyjack/loot/Games/llm_config.json
"""

import os, sys, time, signal, json, textwrap
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
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

sfont = scaled_font(8)
sfont_title = scaled_font(9)

# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------
COL_BG = (5, 5, 15)
COL_TEXT = (0, 220, 180)
COL_CHOICE_A = (0, 255, 100)
COL_CHOICE_B = (255, 100, 255)
COL_SELECT = (255, 255, 0)
COL_DIM = (80, 80, 100)
COL_LOADING = (0, 180, 255)
COL_ERROR = (255, 60, 60)
COL_TITLE = (0, 255, 200)
COL_OFFLINE = (255, 200, 0)

# ---------------------------------------------------------------------------
# API configuration
# ---------------------------------------------------------------------------
API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-haiku-4-5-20251001"
CONFIG_PATH = "/root/Raspyjack/loot/Games/llm_config.json"

SYSTEM_PROMPT = (
    "You are a cyberpunk text adventure game master. "
    "Present short scenes (max 3 lines) with exactly 2 choices "
    "labeled [A] and [B]."
)

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
# API key loading
# ---------------------------------------------------------------------------
def load_api_key():
    """Load API key from environment or config file. Returns None if missing."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key:
        return key
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                conf = json.load(f)
            key = conf.get("api_key", "")
            if key:
                return key
        except (json.JSONDecodeError, OSError):
            pass
    return None


# ---------------------------------------------------------------------------
# Claude API call via urllib
# ---------------------------------------------------------------------------
def call_claude(api_key, messages):
    """Send messages to Claude API and return assistant response text.

    Returns (response_text, error_string). One will be None.
    """
    body = json.dumps({
        "model": MODEL,
        "max_tokens": 200,
        "system": SYSTEM_PROMPT,
        "messages": messages,
    }).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }

    req = Request(API_URL, data=body, headers=headers, method="POST")
    try:
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        content_blocks = data.get("content", [])
        text_parts = [b["text"] for b in content_blocks if b.get("type") == "text"]
        return "\n".join(text_parts), None
    except HTTPError as e:
        return None, f"HTTP {e.code}"
    except URLError as e:
        return None, f"Network error"
    except Exception as e:
        return None, str(e)[:30]


# ---------------------------------------------------------------------------
# Text wrapping and display helpers
# ---------------------------------------------------------------------------
def wrap_text(text, chars_per_line=20):
    """Word-wrap text to fit LCD width."""
    lines = []
    for paragraph in text.split("\n"):
        paragraph = paragraph.strip()
        if not paragraph:
            lines.append("")
            continue
        wrapped = textwrap.wrap(paragraph, width=chars_per_line)
        lines.extend(wrapped)
    return lines


def parse_choices(text):
    """Extract scene description and choices A/B from response text."""
    lines = text.strip().split("\n")
    scene_lines = []
    choice_a = ""
    choice_b = ""

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[A]"):
            choice_a = stripped[3:].strip()
        elif stripped.startswith("[B]"):
            choice_b = stripped[3:].strip()
        else:
            scene_lines.append(stripped)

    scene = "\n".join(scene_lines).strip()
    return scene, choice_a, choice_b


# ---------------------------------------------------------------------------
# Drawing functions (ScaledDraw for text-heavy UI)
# ---------------------------------------------------------------------------
def draw_screen(scene_lines, choice_a, choice_b, selected, scroll=0):
    """Render scene text and choices."""
    img = Image.new("RGB", (WIDTH, HEIGHT), COL_BG)
    d = ScaledDraw(img)

    # Title bar
    d.rectangle([0, 0, 127, 10], fill=(10, 10, 30))
    d.text((2, 1), "CYBER ADVENTURE", font=sfont, fill=COL_TITLE)

    # Scene text area (y: 13 to 85)
    y = 13
    line_h = 10
    max_lines = 7
    visible = scene_lines[scroll:scroll + max_lines]
    for line in visible:
        d.text((3, y), line, font=sfont, fill=COL_TEXT)
        y += line_h

    # Scroll indicator
    if len(scene_lines) > max_lines:
        if scroll > 0:
            d.text((120, 13), "^", font=sfont, fill=COL_DIM)
        if scroll + max_lines < len(scene_lines):
            d.text((120, 75), "v", font=sfont, fill=COL_DIM)

    # Separator
    d.line([(2, 87), (125, 87)], fill=COL_DIM)

    # Choices
    a_col = COL_SELECT if selected == "A" else COL_CHOICE_A
    b_col = COL_SELECT if selected == "B" else COL_CHOICE_B

    a_prefix = "> " if selected == "A" else "  "
    b_prefix = "> " if selected == "B" else "  "

    # Truncate choices to fit
    max_choice_len = 18
    a_display = choice_a[:max_choice_len]
    b_display = choice_b[:max_choice_len]

    d.text((2, 90), f"{a_prefix}[A] {a_display}", font=sfont, fill=a_col)
    d.text((2, 102), f"{b_prefix}[B] {b_display}", font=sfont, fill=b_col)

    # Controls hint
    d.text((2, 118), "L/R:Pick  OK:Go", font=sfont, fill=COL_DIM)

    LCD.LCD_ShowImage(img, 0, 0)


def draw_loading(message="Loading..."):
    """Show loading screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), COL_BG)
    d = ScaledDraw(img)
    d.text((2, 1), "CYBER ADVENTURE", font=sfont, fill=COL_TITLE)

    bbox = d.textbbox((0, 0), message, font=sfont)
    tw = bbox[2] - bbox[0]
    d.text(((128 - tw) // 2, 58), message, font=sfont, fill=COL_LOADING)

    # Animated dots
    dots = "." * (int(time.time() * 2) % 4)
    d.text((64, 72), dots, font=sfont, fill=COL_LOADING)

    LCD.LCD_ShowImage(img, 0, 0)


def draw_error(message):
    """Show error screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), COL_BG)
    d = ScaledDraw(img)
    d.text((2, 1), "CYBER ADVENTURE", font=sfont, fill=COL_TITLE)

    lines = wrap_text(message, 20)
    y = 40
    for line in lines[:4]:
        d.text((4, y), line, font=sfont, fill=COL_ERROR)
        y += 11

    d.text((4, 110), "OK:Retry  KEY3:Exit", font=sfont, fill=COL_DIM)
    LCD.LCD_ShowImage(img, 0, 0)


def draw_offline_banner():
    """Show offline mode notification."""
    img = Image.new("RGB", (WIDTH, HEIGHT), COL_BG)
    d = ScaledDraw(img)
    d.text((2, 1), "CYBER ADVENTURE", font=sfont, fill=COL_TITLE)
    d.text((10, 40), "No API key found", font=sfont, fill=COL_OFFLINE)
    d.text((10, 55), "OFFLINE MODE", font=sfont_title, fill=COL_OFFLINE)
    d.text((10, 75), "Built-in story", font=sfont, fill=COL_DIM)
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(2.0)


# ---------------------------------------------------------------------------
# Offline adventure (hardcoded mini-adventure)
# ---------------------------------------------------------------------------
OFFLINE_SCENES = [
    {
        "scene": "You wake in a dim alley. Neon signs flicker above. "
                 "Rain drips from rusted fire escapes. A data chip "
                 "glows in your pocket.",
        "a": "Check the data chip",
        "b": "Scout the alley exit",
        "next_a": 1,
        "next_b": 2,
    },
    {
        "scene": "The chip contains encrypted coordinates to a "
                 "corporate vault. A warning flashes: TRACE ACTIVE. "
                 "Your neural link buzzes.",
        "a": "Decrypt the coords now",
        "b": "Find a safe house first",
        "next_a": 3,
        "next_b": 4,
    },
    {
        "scene": "The alley opens to a neon-lit street. Drones patrol "
                 "overhead. A street vendor sells black-market tech. "
                 "A hooded figure watches you.",
        "a": "Approach the vendor",
        "b": "Follow the hooded figure",
        "next_a": 4,
        "next_b": 5,
    },
    {
        "scene": "You crack the encryption. The vault is three blocks "
                 "away, in MegaCorp Tower. Security is heavy but you "
                 "spot a maintenance shaft.",
        "a": "Use the maintenance shaft",
        "b": "Hack the front door lock",
        "next_a": 6,
        "next_b": 7,
    },
    {
        "scene": "The safe house is a cramped room above a ramen shop. "
                 "An old hacker named Pixel offers to help for a price. "
                 "She has a military-grade deck.",
        "a": "Accept Pixel's help",
        "b": "Go solo, keep the reward",
        "next_a": 6,
        "next_b": 7,
    },
    {
        "scene": "The hooded figure leads you to an underground club. "
                 "Music pulses. She reveals herself as a corporate "
                 "whistleblower. She needs the chip delivered.",
        "a": "Agree to deliver the chip",
        "b": "Demand payment upfront",
        "next_a": 7,
        "next_b": 6,
    },
    {
        "scene": "You infiltrate MegaCorp Tower through the shaft. "
                 "Laser grids block the path but your neural link "
                 "lets you see the pattern. You reach the vault. "
                 "MISSION COMPLETE. The data is free.",
        "a": "Play again",
        "b": "Play again",
        "next_a": 0,
        "next_b": 0,
    },
    {
        "scene": "Alarms blare as you breach the front entrance. "
                 "Corporate drones swarm. You fight through with "
                 "an EMP grenade and upload the data to the net. "
                 "MISSION COMPLETE. The truth is out.",
        "a": "Play again",
        "b": "Play again",
        "next_a": 0,
        "next_b": 0,
    },
]


# ---------------------------------------------------------------------------
# Online mode (Claude API)
# ---------------------------------------------------------------------------
def play_online(api_key):
    """Play using Claude API for dynamic story generation."""
    conversation = []
    selected = "A"
    scroll = 0

    # Initial prompt
    conversation = [{"role": "user", "content": "Start the adventure."}]
    draw_loading("Starting adventure...")

    response, error = call_claude(api_key, conversation)
    if error:
        draw_error(f"API Error: {error}")
        while running:
            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                return
            if btn == "OK":
                time.sleep(0.2)
                play_online(api_key)
                return
            time.sleep(0.05)
        return

    conversation = conversation + [{"role": "assistant", "content": response}]
    scene_text, choice_a, choice_b = parse_choices(response)

    if not choice_a:
        choice_a = "Continue"
    if not choice_b:
        choice_b = "Look around"

    scene_lines = wrap_text(scene_text, 20)

    while running:
        draw_screen(scene_lines, choice_a, choice_b, selected, scroll)

        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            return

        if btn == "LEFT":
            selected = "A"
        elif btn == "RIGHT":
            selected = "B"
        elif btn == "UP":
            scroll = max(0, scroll - 1)
        elif btn == "DOWN":
            max_scroll = max(0, len(scene_lines) - 7)
            scroll = min(scroll + 1, max_scroll)
        elif btn == "OK":
            # Send choice to Claude
            choice_text = choice_a if selected == "A" else choice_b
            user_msg = f"I choose [{selected}]: {choice_text}"
            new_conversation = conversation + [
                {"role": "user", "content": user_msg}
            ]

            # Keep conversation manageable (last 10 messages)
            if len(new_conversation) > 10:
                new_conversation = new_conversation[-10:]

            draw_loading()
            response, error = call_claude(api_key, new_conversation)

            if error:
                draw_error(f"API Error: {error}")
                while running:
                    b = get_button(PINS, GPIO)
                    if b == "KEY3":
                        return
                    if b == "OK":
                        break
                    time.sleep(0.05)
                time.sleep(0.2)
                continue

            conversation = new_conversation + [
                {"role": "assistant", "content": response}
            ]
            scene_text, choice_a, choice_b = parse_choices(response)

            if not choice_a:
                choice_a = "Continue"
            if not choice_b:
                choice_b = "Look around"

            scene_lines = wrap_text(scene_text, 20)
            selected = "A"
            scroll = 0

        time.sleep(0.08)


# ---------------------------------------------------------------------------
# Offline mode
# ---------------------------------------------------------------------------
def play_offline():
    """Play built-in hardcoded adventure."""
    draw_offline_banner()

    scene_idx = 0
    selected = "A"
    scroll = 0

    while running:
        scene_data = OFFLINE_SCENES[scene_idx]
        scene_lines = wrap_text(scene_data["scene"], 20)
        choice_a = scene_data["a"]
        choice_b = scene_data["b"]

        draw_screen(scene_lines, choice_a, choice_b, selected, scroll)

        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            return

        if btn == "LEFT":
            selected = "A"
        elif btn == "RIGHT":
            selected = "B"
        elif btn == "UP":
            scroll = max(0, scroll - 1)
        elif btn == "DOWN":
            max_scroll = max(0, len(scene_lines) - 7)
            scroll = min(scroll + 1, max_scroll)
        elif btn == "OK":
            if selected == "A":
                scene_idx = scene_data["next_a"]
            else:
                scene_idx = scene_data["next_b"]
            selected = "A"
            scroll = 0

        time.sleep(0.08)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def play():
    """Entry point: detect API key and choose mode."""
    api_key = load_api_key()
    if api_key:
        play_online(api_key)
    else:
        play_offline()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        play()
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
