#!/usr/bin/env python3
"""
RaspyJack Payload -- Payload Search
=====================================
Author: 7h30th3r0n3

Search installed payloads by keyword and view their docstrings.
Scans the payloads directory for .py files (excluding _ prefixed helpers).

Controls
--------
  UP / DOWN    -- Navigate character picker / results
  LEFT / RIGHT -- Move cursor in search input
  OK           -- Confirm character / select result to view docstring
  KEY1         -- Start new search
  KEY3         -- Exit (or back from docstring view)
"""

import os
import sys
import time
import signal
import ast

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
font = scaled_font()

PAYLOAD_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
DEBOUNCE = 0.18
ROW_H = 12
VISIBLE_ROWS = 7
CHARSET = list(
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789_- "
)

_running = True


def _cleanup(*_args):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# Payload scanning
# ---------------------------------------------------------------------------

def _scan_payloads():
    """Recursively find all .py payload files (excluding _ prefixed)."""
    results = []
    for root, _dirs, files in os.walk(PAYLOAD_PATH):
        for fname in sorted(files):
            if not fname.endswith(".py"):
                continue
            if fname.startswith("_"):
                continue
            rel = os.path.relpath(os.path.join(root, fname), PAYLOAD_PATH)
            results.append({"name": fname[:-3], "rel": rel,
                            "full": os.path.join(root, fname)})
    return results


def _extract_docstring(filepath):
    """Extract the module docstring from a Python file using AST."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            tree = ast.parse(fh.read(), filename=filepath)
        docstring = ast.get_docstring(tree)
        return docstring if docstring else "(no docstring)"
    except Exception:
        return "(parse error)"


def _search(payloads, keyword):
    """Filter payloads whose name or path contains the keyword."""
    kw = keyword.lower().strip()
    if not kw:
        return list(payloads)
    return [p for p in payloads if kw in p["name"].lower()
            or kw in p["rel"].lower()]


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(d, title):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title[:20], font=font, fill="#00ccff")
    d.text((108, 1), "K3", font=font, fill="#888")


def _draw_footer(d, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:26], font=font, fill="#666")


def _draw_char_picker(query, char_idx):
    """Character picker for keyword input."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "PAYLOAD SEARCH")

    d.text((2, 18), "Keyword:", font=font, fill="#aaa")
    d.text((2, 30), "".join(query)[:20] + "_", font=font, fill="#ffffff")

    current_char = CHARSET[char_idx]
    d.text((2, 50), f"Char: [ {current_char} ]", font=font, fill="#00ff00")

    # Show nearby characters
    prev_idx = (char_idx - 1) % len(CHARSET)
    next_idx = (char_idx + 1) % len(CHARSET)
    d.text((2, 62), f"  UP: {CHARSET[prev_idx]}  DN: {CHARSET[next_idx]}", font=font, fill="#555")

    d.text((2, 80), "OK: add char", font=font, fill="#666")
    d.text((2, 92), "KEY1: backspace", font=font, fill="#666")
    d.text((2, 104), "KEY2: search", font=font, fill="#666")

    _draw_footer(d, "Type keyword to search")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_results(matches, cursor, scroll):
    """Display search results list."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, f"RESULTS ({len(matches)})")

    y = 16
    end = min(len(matches), scroll + VISIBLE_ROWS)
    for i in range(scroll, end):
        is_selected = i == cursor
        bg = "#333" if is_selected else None
        fg = "#ffff00" if is_selected else "#ccc"

        if bg:
            d.rectangle((0, y, 127, y + ROW_H - 1), fill=bg)
        d.text((2, y), matches[i]["name"][:20], font=font, fill=fg)
        y += ROW_H

    if not matches:
        d.text((4, 50), "No matches", font=font, fill="#ff4444")

    _draw_footer(d, "OK:view K1:new search")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_docstring(name, docstring, scroll):
    """Display a payload's docstring."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, name[:18])

    lines = docstring.split("\n")
    y = 16
    end = min(len(lines), scroll + VISIBLE_ROWS + 1)
    for i in range(scroll, end):
        d.text((2, y), lines[i][:22], font=font, fill="#ccc")
        y += ROW_H
        if y > 112:
            break

    if len(lines) > VISIBLE_ROWS + 1:
        indicator = f"{scroll + 1}/{max(1, len(lines) - VISIBLE_ROWS)}"
        d.text((90, 105), indicator, font=font, fill="#555")

    _draw_footer(d, "UP/DN:scroll K3:back")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running

    all_payloads = _scan_payloads()
    state = "input"  # input | results | docstring
    query = []
    char_idx = 0
    matches = []
    cursor = 0
    scroll = 0
    doc_text = ""
    doc_name = ""
    doc_scroll = 0
    last_press = 0.0

    try:
        while _running:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if btn == "KEY3":
                if state == "docstring":
                    state = "results"
                    continue
                elif state == "results":
                    state = "input"
                    continue
                else:
                    break

            if state == "input":
                if btn == "UP":
                    char_idx = (char_idx - 1) % len(CHARSET)
                elif btn == "DOWN":
                    char_idx = (char_idx + 1) % len(CHARSET)
                elif btn == "OK":
                    query = query + [CHARSET[char_idx]]
                elif btn == "KEY1":
                    if query:
                        query = query[:-1]
                elif btn == "KEY2":
                    keyword = "".join(query)
                    matches = _search(all_payloads, keyword)
                    cursor = 0
                    scroll = 0
                    state = "results"
                _draw_char_picker(query, char_idx)

            elif state == "results":
                if btn == "DOWN" and matches:
                    cursor = min(cursor + 1, len(matches) - 1)
                    if cursor >= scroll + VISIBLE_ROWS:
                        scroll = cursor - VISIBLE_ROWS + 1
                elif btn == "UP":
                    cursor = max(cursor - 1, 0)
                    if cursor < scroll:
                        scroll = cursor
                elif btn == "OK" and matches:
                    entry = matches[cursor]
                    doc_text = _extract_docstring(entry["full"])
                    doc_name = entry["name"]
                    doc_scroll = 0
                    state = "docstring"
                elif btn == "KEY1":
                    query = []
                    char_idx = 0
                    state = "input"
                _draw_results(matches, cursor, scroll)

            elif state == "docstring":
                lines = doc_text.split("\n")
                max_scroll = max(0, len(lines) - VISIBLE_ROWS - 1)
                if btn == "DOWN":
                    doc_scroll = min(doc_scroll + 1, max_scroll)
                elif btn == "UP":
                    doc_scroll = max(doc_scroll - 1, 0)
                _draw_docstring(doc_name, doc_text, doc_scroll)

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
