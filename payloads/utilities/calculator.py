#!/usr/bin/env python3
"""
RaspyJack Payload -- Scientific Calculator
============================================
Author: 7h30th3r0n3

Full-featured calculator with dark modern theme inspired by iOS/macOS.
Supports standard arithmetic, scientific functions, parentheses,
hex/dec/bin/oct conversion, and calculation history.

Controls
--------
  UP / DOWN / LEFT / RIGHT  -- Navigate button grid
  OK                        -- Press selected button / evaluate
  KEY1                      -- Toggle standard / scientific mode
  KEY2                      -- Toggle hex/dec/bin/oct conversion
  KEY3                      -- Exit
"""

import os
import sys
import math
import time
import signal

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
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

DEBOUNCE = 0.18

# ---------------------------------------------------------------------------
# Theme colors
# ---------------------------------------------------------------------------
CLR_BG = "#0a0a12"
CLR_HEADER = "#0d1117"
CLR_NUM = "#1e1e2e"
CLR_OP = "#7C4DFF"
CLR_FUNC = "#1a1a3a"
CLR_SEL = "#00E5FF"
CLR_RESULT = "#00E5FF"
CLR_EXPR = "#E0E0E0"
CLR_ERROR = "#FF5252"
CLR_EQ = "#00E676"
CLR_GRID_BG = "#12121e"
CLR_TEXT_DIM = "#888899"

# ---------------------------------------------------------------------------
# Safe math evaluation namespace
# ---------------------------------------------------------------------------
_SAFE_MATH = {
    "sin": math.sin,
    "cos": math.cos,
    "tan": math.tan,
    "sqrt": math.sqrt,
    "pow": math.pow,
    "log": math.log10,
    "ln": math.log,
    "pi": math.pi,
    "e": math.e,
    "abs": abs,
    "asin": math.asin,
    "acos": math.acos,
    "atan": math.atan,
}


def _safe_eval(expression):
    """Evaluate a math expression safely, returning (result_str, error)."""
    if not expression.strip():
        return ("", None)
    expr = expression.replace("×", "*").replace("÷", "/")
    try:
        result = eval(expr, {"__builtins__": {}}, _SAFE_MATH)  # noqa: S307
    except ZeroDivisionError:
        return ("", "Div by zero")
    except (SyntaxError, TypeError):
        return ("", "Syntax error")
    except (ValueError, OverflowError) as exc:
        return ("", str(exc)[:18])
    except Exception as exc:
        return ("", str(exc)[:18])
    if isinstance(result, float):
        if result == int(result) and abs(result) < 1e15:
            return (str(int(result)), None)
        return (f"{result:.10g}", None)
    return (str(result), None)


# ---------------------------------------------------------------------------
# Base conversion
# ---------------------------------------------------------------------------
_BASES = ["DEC", "HEX", "BIN", "OCT"]


def _convert_base(value_str, target_base):
    """Convert a decimal integer string to the target base representation."""
    try:
        val = int(float(value_str))
    except (ValueError, OverflowError):
        return "N/A"
    if target_base == "DEC":
        return str(val)
    if target_base == "HEX":
        return hex(val)
    if target_base == "BIN":
        return bin(val)
    if target_base == "OCT":
        return oct(val)
    return str(val)


# ---------------------------------------------------------------------------
# Button grid definitions
# ---------------------------------------------------------------------------
# Standard mode: 5 columns x 5 rows
GRID_STD = [
    ["C", "CE", "(", ")", "÷"],
    ["7", "8", "9", "×", "^"],
    ["4", "5", "6", "-", "√"],
    ["1", "2", "3", "+", "H"],
    ["0", ".", "±", "=", "←"],
]

# Scientific mode: 5 columns x 7 rows
GRID_SCI = [
    ["C", "CE", "(", ")", "÷"],
    ["sin", "cos", "tan", "×", "^"],
    ["ln", "log", "√", "-", "π"],
    ["7", "8", "9", "+", "e"],
    ["4", "5", "6", ".", "H"],
    ["1", "2", "3", "=", "←"],
    ["0", "A", "B", "D", "F"],
]

# Hex-entry row (replaces bottom row in conversion mode)
GRID_HEX_ROW = ["0", "A", "B", "D", "F"]


def _get_grid(scientific, hex_mode):
    """Return the active button grid."""
    if scientific:
        return GRID_SCI
    if hex_mode:
        grid = [row[:] for row in GRID_STD]
        grid.append(["A", "B", "C₂", "D", "F"])
        return grid
    return GRID_STD


def _btn_type(label):
    """Classify a button label for coloring."""
    if label == "=":
        return "equal"
    if label in ("+", "-", "×", "÷", "^"):
        return "operator"
    if label in ("sin", "cos", "tan", "ln", "log", "√",
                 "π", "e", "(", ")", "H", "←",
                 "C", "CE", "±", "C₂"):
        return "function"
    return "number"


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_display(d, expression, result, error, mode_label, base_label, font_sm):
    """Draw the top display area (expression + result)."""
    d.rectangle((0, 0, 127, 35), fill=CLR_HEADER)

    # Mode indicators
    d.text((2, 1), mode_label, font=font_sm, fill=CLR_TEXT_DIM)
    d.text((98, 1), base_label, font=font_sm, fill=CLR_TEXT_DIM)

    # Expression line (truncated to fit)
    expr_display = expression[-22:] if len(expression) > 22 else expression
    if not expr_display:
        expr_display = "0"
    d.text((2, 11), expr_display, font=font_sm, fill=CLR_EXPR)

    # Result line
    if error:
        d.text((2, 23), error[:22], font=font_sm, fill=CLR_ERROR)
    elif result:
        res_display = result[-22:] if len(result) > 22 else result
        d.text((2, 23), f"= {res_display}", font=font_sm, fill=CLR_RESULT)

    # Separator line
    d.line((0, 35, 127, 35), fill="#222233")


def _draw_grid(d, grid, sel_row, sel_col, font_sm):
    """Draw the calculator button grid."""
    rows = len(grid)
    cols = len(grid[0]) if grid else 0
    if rows == 0 or cols == 0:
        return

    grid_top = 38
    grid_bottom = 127
    available_h = grid_bottom - grid_top
    available_w = 126

    btn_h = available_h // rows
    btn_w = available_w // cols

    for r, row in enumerate(grid):
        for c, label in enumerate(row):
            x0 = 1 + c * btn_w
            y0 = grid_top + r * btn_h
            x1 = x0 + btn_w - 1
            y1 = y0 + btn_h - 1

            btype = _btn_type(label)
            if btype == "equal":
                bg = CLR_EQ
                fg = "#000000"
            elif btype == "operator":
                bg = CLR_OP
                fg = "#FFFFFF"
            elif btype == "function":
                bg = CLR_FUNC
                fg = "#BBBBDD"
            else:
                bg = CLR_NUM
                fg = "#E0E0E0"

            d.rectangle((x0, y0, x1, y1), fill=bg)

            if r == sel_row and c == sel_col:
                d.rectangle((x0, y0, x1, y1), outline=CLR_SEL, width=1)
                # Brighten text on selected button
                fg = "#FFFFFF"

            # Center the label text
            tw = d.textlength(label, font=font_sm)
            tx = x0 + (btn_w - 1) // 2
            ty = y0 + (btn_h - 1) // 2
            d.text((tx - tw // 2, ty - 4), label, font=font_sm, fill=fg)


def _draw_history(d, history, font_sm):
    """Draw calculation history overlay."""
    d.rectangle((0, 0, 127, 127), fill=CLR_BG)
    d.rectangle((0, 0, 127, 13), fill=CLR_HEADER)
    d.text((2, 1), "HISTORY (last 10)", font=font_sm, fill=CLR_SEL)
    d.text((108, 1), "K2", font=font_sm, fill=CLR_TEXT_DIM)

    y = 16
    if not history:
        d.text((4, y), "No calculations yet", font=font_sm, fill=CLR_TEXT_DIM)
    else:
        for entry in reversed(history[-10:]):
            if y > 118:
                break
            expr_part = entry[0][-18:]
            res_part = entry[1][-10:]
            d.text((2, y), f"{expr_part}={res_part}", font=font_sm, fill=CLR_EXPR)
            y += 11


def _draw_conversion(d, result, base_idx, font_sm):
    """Draw base conversion overlay."""
    d.rectangle((0, 0, 127, 127), fill=CLR_BG)
    d.rectangle((0, 0, 127, 13), fill=CLR_HEADER)
    d.text((2, 1), "BASE CONVERT", font=font_sm, fill=CLR_SEL)
    d.text((108, 1), "K2", font=font_sm, fill=CLR_TEXT_DIM)

    if not result:
        d.text((4, 20), "Evaluate first", font=font_sm, fill=CLR_TEXT_DIM)
        return

    y = 20
    for i, base in enumerate(_BASES):
        converted = _convert_base(result, base)
        highlight = (i == base_idx)
        fg = CLR_SEL if highlight else CLR_EXPR
        prefix = ">" if highlight else " "
        label = f"{prefix} {base}: {converted}"
        if len(label) > 24:
            label = label[:24]
        d.text((2, y), label, font=font_sm, fill=fg)
        y += 14

    d.text((2, 80), "UP/DN to select", font=font_sm, fill=CLR_TEXT_DIM)
    d.text((2, 92), "OK to copy to expr", font=font_sm, fill=CLR_TEXT_DIM)


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------

def _handle_btn_press(label, expression, result, error, history):
    """Process a calculator button press.

    Returns a new (expression, result, error, history) tuple (immutable style).
    """
    new_expr = expression
    new_result = result
    new_error = error
    new_history = list(history)

    if label == "C":
        return ("", "", None, new_history)

    if label == "CE":
        # Clear last entry (last number or operator)
        stripped = new_expr.rstrip()
        if stripped:
            # Remove last token
            i = len(stripped) - 1
            while i > 0 and stripped[i - 1] not in " +-×÷^()":
                i -= 1
            new_expr = stripped[:i]
        return (new_expr, new_result, None, new_history)

    if label == "←":  # backspace
        if new_expr:
            new_expr = new_expr[:-1]
        return (new_expr, new_result, None, new_history)

    if label == "=":
        res, err = _safe_eval(new_expr)
        if err:
            return (new_expr, "", err, new_history)
        if res:
            new_history = list(new_history)
            new_history.append((new_expr, res))
            if len(new_history) > 10:
                new_history = new_history[-10:]
        return (new_expr, res, None, new_history)

    if label == "±":  # plus/minus toggle
        if new_expr and new_expr[0] == "-":
            new_expr = new_expr[1:]
        elif new_expr:
            new_expr = "-" + new_expr
        else:
            new_expr = "-"
        return (new_expr, new_result, new_error, new_history)

    if label == "√":  # sqrt
        new_expr = new_expr + "sqrt("
        return (new_expr, new_result, None, new_history)

    if label == "^":
        new_expr = new_expr + "**"
        return (new_expr, new_result, None, new_history)

    if label == "π":  # pi
        new_expr = new_expr + "pi"
        return (new_expr, new_result, None, new_history)

    if label == "H":
        # Toggle history -- handled in main loop
        return (new_expr, new_result, new_error, new_history)

    if label in ("sin", "cos", "tan", "ln", "log"):
        new_expr = new_expr + label + "("
        return (new_expr, new_result, None, new_history)

    if label == "C₂":
        # Hex-mode C digit (to avoid conflict with Clear)
        new_expr = new_expr + "C"
        return (new_expr, new_result, None, new_history)

    # Regular character: digits, operators, parens, dot, hex letters, e
    new_expr = new_expr + label
    return (new_expr, new_result, None, new_history)


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------

_running = True


def _cleanup(*_args):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running

    font_sm = scaled_font(8)
    expression = ""
    result = ""
    error = None
    history = []
    sel_row = 0
    sel_col = 0
    scientific = False
    show_history = False
    show_conversion = False
    conv_base_idx = 0
    last_press = 0.0

    try:
        while _running:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            # ----- Exit -----
            if btn == "KEY3":
                break

            # ----- Toggle scientific mode -----
            if btn == "KEY1":
                scientific = not scientific
                sel_row = 0
                sel_col = 0
                show_history = False
                show_conversion = False
                btn = None

            # ----- Toggle conversion overlay -----
            if btn == "KEY2":
                if show_conversion:
                    show_conversion = False
                elif show_history:
                    show_history = False
                    show_conversion = True
                else:
                    show_conversion = True
                btn = None

            # ----- History overlay navigation -----
            if show_history:
                if btn in ("KEY1", "KEY2", "KEY3", "OK"):
                    show_history = False
                img = Image.new("RGB", (WIDTH, HEIGHT), CLR_BG)
                d = ScaledDraw(img)
                _draw_history(d, history, font_sm)
                LCD.LCD_ShowImage(img, 0, 0)
                time.sleep(0.08)
                continue

            # ----- Conversion overlay navigation -----
            if show_conversion:
                if btn == "UP":
                    conv_base_idx = (conv_base_idx - 1) % len(_BASES)
                elif btn == "DOWN":
                    conv_base_idx = (conv_base_idx + 1) % len(_BASES)
                elif btn == "OK":
                    if result:
                        converted = _convert_base(result, _BASES[conv_base_idx])
                        if converted != "N/A":
                            expression = converted
                            result = ""
                            error = None
                    show_conversion = False

                img = Image.new("RGB", (WIDTH, HEIGHT), CLR_BG)
                d = ScaledDraw(img)
                _draw_conversion(d, result, conv_base_idx, font_sm)
                LCD.LCD_ShowImage(img, 0, 0)
                time.sleep(0.08)
                continue

            # ----- Grid navigation -----
            grid = _get_grid(scientific, False)
            num_rows = len(grid)
            num_cols = len(grid[0]) if grid else 1

            if btn == "UP":
                sel_row = (sel_row - 1) % num_rows
            elif btn == "DOWN":
                sel_row = (sel_row + 1) % num_rows
            elif btn == "LEFT":
                sel_col = (sel_col - 1) % num_cols
            elif btn == "RIGHT":
                sel_col = (sel_col + 1) % num_cols
            elif btn == "OK":
                label = grid[sel_row][sel_col]
                if label == "H":
                    show_history = True
                else:
                    expression, result, error, history = _handle_btn_press(
                        label, expression, result, error, history,
                    )

            # Clamp selection within grid bounds
            sel_row = min(sel_row, num_rows - 1)
            sel_col = min(sel_col, num_cols - 1)

            # ----- Render -----
            mode_label = "SCI" if scientific else "STD"
            base_label = "K2:CVT"
            img = Image.new("RGB", (WIDTH, HEIGHT), CLR_BG)
            d = ScaledDraw(img)
            _draw_display(d, expression, result, error, mode_label, base_label, font_sm)
            _draw_grid(d, grid, sel_row, sel_col, font_sm)
            LCD.LCD_ShowImage(img, 0, 0)

            time.sleep(0.08)

    finally:
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
