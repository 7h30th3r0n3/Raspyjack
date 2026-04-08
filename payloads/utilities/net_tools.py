#!/usr/bin/env python3
"""
RaspyJack Payload -- Network Tools
===================================
Author: 7h30th3r0n3

Interactive network tools menu: ping, traceroute, mtr, nslookup, netstat,
route, arp table.

Controls:
  UP/DOWN    -- Navigate menu / scroll results / change character
  LEFT/RIGHT -- Move cursor in text input
  OK         -- Select tool / confirm input
  KEY1       -- Back to tool menu
  KEY3       -- Exit
"""

import os, sys, time, signal, subprocess, threading

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROW_H = 12
VISIBLE_ROWS = 7

# Character set for text input picker
CHAR_SET = list("abcdefghijklmnopqrstuvwxyz0123456789./-:")

# Tool definitions: (label, requires_input, default_value, command_builder)
TOOLS = [
    ("Ping",       True,  "192.168.1.1", lambda t: ["ping", "-c", "4", "-W", "2", t]),
    ("Traceroute", True,  "192.168.1.1", lambda t: ["traceroute", "-m", "15", "-w", "2", t]),
    ("MTR",        True,  "192.168.1.1", lambda t: ["mtr", "--report", "--report-cycles", "3", "-n", t]),
    ("NSLookup",   True,  "google.com",  lambda t: ["nslookup", t]),
    ("Netstat",    False, "",            lambda _: ["ss", "-tulnp"]),
    ("Route",      False, "",            lambda _: ["ip", "route", "show"]),
    ("ARP",        False, "",            lambda _: ["ip", "neigh", "show"]),
]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
running = True
lock = threading.Lock()
cmd_output_lines = []
cmd_running = False
spinner_idx = 0


def _signal_handler(_sig, _frame):
    global running
    running = False


signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# ---------------------------------------------------------------------------
# Command execution (background thread)
# ---------------------------------------------------------------------------
def _run_command(cmd_args):
    """Execute a command and store output lines thread-safely."""
    global cmd_running, cmd_output_lines
    try:
        result = subprocess.run(
            cmd_args,
            capture_output=True,
            text=True,
            timeout=60,
        )
        raw = result.stdout + result.stderr
        lines = []
        for line in raw.splitlines():
            # Wrap long lines to ~22 chars for readability on LCD
            while len(line) > 22:
                lines.append(line[:22])
                line = line[22:]
            lines.append(line)
        with lock:
            cmd_output_lines = lines if lines else ["(no output)"]
    except subprocess.TimeoutExpired:
        with lock:
            cmd_output_lines = ["Command timed out"]
    except FileNotFoundError:
        with lock:
            cmd_output_lines = [f"{cmd_args[0]}: not found"]
    except Exception as exc:
        with lock:
            cmd_output_lines = [f"Error: {str(exc)[:20]}"]
    finally:
        with lock:
            cmd_running = False


def _start_command(cmd_args):
    """Launch command in a daemon thread."""
    global cmd_running, cmd_output_lines, spinner_idx
    with lock:
        cmd_running = True
        cmd_output_lines = []
        spinner_idx = 0
    t = threading.Thread(target=_run_command, args=(cmd_args,), daemon=True)
    t.start()


# ---------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------
def _draw_header(d, font_obj, title):
    """Draw the standard header bar."""
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title[:20], font=font_obj, fill="#00CCFF")


def _draw_footer(d, font_obj, text):
    """Draw the standard footer bar."""
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font_obj, fill="#888")


# ---------------------------------------------------------------------------
# Screen: Main menu
# ---------------------------------------------------------------------------
def _draw_menu(lcd, font_obj, selected):
    """Render the tool selection menu."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, font_obj, "Network Tools")

    visible_start = 0
    if selected >= VISIBLE_ROWS:
        visible_start = selected - VISIBLE_ROWS + 1

    for i in range(min(VISIBLE_ROWS, len(TOOLS))):
        idx = visible_start + i
        if idx >= len(TOOLS):
            break
        y = 16 + i * ROW_H
        label = TOOLS[idx][0]
        is_sel = idx == selected
        marker = ">" if is_sel else " "
        color = "#FFAA00" if is_sel else "#CCCCCC"
        d.text((2, y), f"{marker} {label}", font=font_obj, fill=color)

    _draw_footer(d, font_obj, "OK:Select  KEY3:Exit")
    lcd.LCD_ShowImage(img, 0, 0)


def _handle_menu(lcd, font_obj):
    """Run the main menu loop. Returns (tool_index, True) or (None, False)."""
    selected = 0
    _draw_menu(lcd, font_obj, selected)

    while running:
        btn = get_button(PINS, GPIO)

        if btn == "KEY3":
            return None, False

        if btn == "UP":
            selected = max(0, selected - 1)
            _draw_menu(lcd, font_obj, selected)
            time.sleep(0.15)

        elif btn == "DOWN":
            selected = min(len(TOOLS) - 1, selected + 1)
            _draw_menu(lcd, font_obj, selected)
            time.sleep(0.15)

        elif btn == "OK":
            time.sleep(0.2)
            return selected, True

        time.sleep(0.05)

    return None, False


# ---------------------------------------------------------------------------
# Screen: Text input
# ---------------------------------------------------------------------------
def _draw_input(lcd, font_obj, tool_name, chars, cursor):
    """Render the text input screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, font_obj, tool_name)

    d.text((2, 18), "Target:", font=font_obj, fill="#AAAAAA")

    # Show the input string with cursor highlight
    input_str = "".join(chars)
    # Display up to 20 chars, scroll if needed
    disp_start = max(0, cursor - 18)
    disp_text = input_str[disp_start:disp_start + 20]
    cursor_in_view = cursor - disp_start

    d.text((2, 32), disp_text, font=font_obj, fill="#FFFFFF")

    # Draw cursor underline
    if 0 <= cursor_in_view < 20:
        cx = 2 + cursor_in_view * 6
        d.line((cx, 42, cx + 5, 42), fill="#FFAA00", width=1)

    # Show current character options
    if cursor < len(chars):
        cur_char = chars[cursor]
        ci = CHAR_SET.index(cur_char) if cur_char in CHAR_SET else 0
        prev_c = CHAR_SET[(ci - 1) % len(CHAR_SET)]
        next_c = CHAR_SET[(ci + 1) % len(CHAR_SET)]
        d.text((2, 52), f"UP:[{prev_c}]  DN:[{next_c}]", font=font_obj, fill="#666")

    d.text((2, 70), "UP/DN: char  L/R: move", font=font_obj, fill="#555")
    d.text((2, 82), "OK: confirm input", font=font_obj, fill="#555")

    _draw_footer(d, font_obj, "KEY1:Back  KEY3:Exit")
    lcd.LCD_ShowImage(img, 0, 0)


def _handle_input(lcd, font_obj, tool_name, default):
    """Run text input. Returns (target_string, True) or (None, False).

    KEY1 returns to menu, KEY3 exits entirely.
    """
    chars = list(default)
    if not chars:
        chars = list("a")
    cursor = len(chars) - 1

    _draw_input(lcd, font_obj, tool_name, chars, cursor)

    while running:
        btn = get_button(PINS, GPIO)

        if btn == "KEY3":
            return None, False

        if btn == "KEY1":
            time.sleep(0.2)
            return None, True  # back to menu

        if btn == "OK":
            target = "".join(chars).strip()
            if target:
                time.sleep(0.2)
                return target, True
            time.sleep(0.1)

        elif btn == "UP":
            if cursor < len(chars):
                cur = chars[cursor]
                ci = CHAR_SET.index(cur) if cur in CHAR_SET else 0
                chars[cursor] = CHAR_SET[(ci - 1) % len(CHAR_SET)]
            _draw_input(lcd, font_obj, tool_name, chars, cursor)
            time.sleep(0.15)

        elif btn == "DOWN":
            if cursor < len(chars):
                cur = chars[cursor]
                ci = CHAR_SET.index(cur) if cur in CHAR_SET else 0
                chars[cursor] = CHAR_SET[(ci + 1) % len(CHAR_SET)]
            _draw_input(lcd, font_obj, tool_name, chars, cursor)
            time.sleep(0.15)

        elif btn == "RIGHT":
            if cursor < len(chars) - 1:
                cursor += 1
            else:
                # Extend input with a new character
                chars.append(".")
                cursor = len(chars) - 1
            _draw_input(lcd, font_obj, tool_name, chars, cursor)
            time.sleep(0.15)

        elif btn == "LEFT":
            if cursor > 0:
                cursor -= 1
            _draw_input(lcd, font_obj, tool_name, chars, cursor)
            time.sleep(0.15)

        elif btn == "KEY2":
            # Delete character at cursor
            if len(chars) > 1:
                chars.pop(cursor)
                cursor = min(cursor, len(chars) - 1)
            _draw_input(lcd, font_obj, tool_name, chars, cursor)
            time.sleep(0.15)

        time.sleep(0.05)

    return None, False


# ---------------------------------------------------------------------------
# Screen: Results viewer (scrollable)
# ---------------------------------------------------------------------------
SPINNER = ["|", "/", "-", "\\"]


def _draw_results(lcd, font_obj, tool_name, lines, scroll, is_running):
    """Render scrollable command output."""
    global spinner_idx
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, font_obj, tool_name)

    if is_running:
        spinner_idx = (spinner_idx + 1) % len(SPINNER)
        d.text((2, 18), f"Running... {SPINNER[spinner_idx]}", font=font_obj, fill="#FFAA00")
        _draw_footer(d, font_obj, "KEY3:Exit")
        lcd.LCD_ShowImage(img, 0, 0)
        return

    if not lines:
        d.text((2, 30), "(no output)", font=font_obj, fill="#666")
        _draw_footer(d, font_obj, "KEY1:Back  KEY3:Exit")
        lcd.LCD_ShowImage(img, 0, 0)
        return

    # Show result rows
    rows_avail = 8  # rows between header and footer
    visible = lines[scroll:scroll + rows_avail]
    for i, line in enumerate(visible):
        y = 16 + i * ROW_H
        d.text((2, y), line[:22], font=font_obj, fill="#CCCCCC")

    # Scroll indicator
    total = len(lines)
    if total > rows_avail:
        pct = scroll / max(1, total - rows_avail)
        bar_h = max(4, int(80 * rows_avail / total))
        bar_y = int(16 + pct * (80 - bar_h))
        d.rectangle((125, bar_y, 127, bar_y + bar_h), fill="#555")

    # Line count in footer
    end_line = min(scroll + rows_avail, total)
    _draw_footer(d, font_obj, f"L{scroll + 1}-{end_line}/{total} K1:Back")
    lcd.LCD_ShowImage(img, 0, 0)


def _handle_results(lcd, font_obj, tool_name, cmd_args):
    """Run a command and display scrollable results.

    Returns True to go back to menu, False to exit entirely.
    """
    _start_command(cmd_args)
    scroll = 0

    while running:
        with lock:
            is_running = cmd_running
            lines = list(cmd_output_lines)

        _draw_results(lcd, font_obj, tool_name, lines, scroll, is_running)

        btn = get_button(PINS, GPIO)

        if btn == "KEY3":
            return False

        if btn == "KEY1" and not is_running:
            time.sleep(0.2)
            return True

        if btn == "UP" and not is_running:
            scroll = max(0, scroll - 1)
            time.sleep(0.12)

        elif btn == "DOWN" and not is_running:
            max_scroll = max(0, len(lines) - 8)
            scroll = min(scroll + 1, max_scroll)
            time.sleep(0.12)

        time.sleep(0.1 if is_running else 0.05)

    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global running

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font_obj = scaled_font()

    try:
        while running:
            # --- Main menu ---
            tool_idx, ok = _handle_menu(lcd, font_obj)
            if not ok or tool_idx is None:
                break

            tool_name, needs_input, default_val, cmd_builder = TOOLS[tool_idx]

            # --- Text input (if required) ---
            if needs_input:
                target, proceed = _handle_input(lcd, font_obj, tool_name, default_val)
                if not proceed:
                    break  # KEY3 pressed
                if target is None:
                    continue  # KEY1 pressed, back to menu
                cmd_args = cmd_builder(target)
            else:
                cmd_args = cmd_builder("")

            # --- Run command and show results ---
            go_back = _handle_results(lcd, font_obj, tool_name, cmd_args)
            if not go_back:
                break  # KEY3 pressed

    finally:
        running = False
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
