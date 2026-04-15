"""
Shared on-screen keyboard for RaspyJack payloads.

Usage:
    from payloads._keyboard_helper import lcd_keyboard

    text = lcd_keyboard(lcd, font, pins, gpio, title="Enter IP")
    text = lcd_keyboard(lcd, font, pins, gpio, title="SSID", default="FreeWiFi")
    text = lcd_keyboard(lcd, font, pins, gpio, title="PIN", charset="digits")

    Returns the entered string, or None if cancelled (KEY3).

Controls:
    UP/DOWN/LEFT/RIGHT  Navigate keyboard grid
    OK                  Type selected character
    KEY1                Switch page (abc / ABC / 123)
    KEY2                Backspace
    KEY3                Cancel (return None)
    Long press OK on [OK] key = confirm and return text
"""

import time

try:
    from payloads._display_helper import ScaledDraw, scaled_font
    from PIL import Image
except Exception:
    ScaledDraw = None
    Image = None

from payloads import _input_helper as _input_helper

get_button = _input_helper.get_button
open_remote_text_session = getattr(_input_helper, "open_remote_text_session", lambda **_kwargs: None)
get_remote_text_event = getattr(_input_helper, "get_remote_text_event", lambda *_args, **_kwargs: None)
close_remote_text_session = getattr(_input_helper, "close_remote_text_session", lambda *_args, **_kwargs: None)

# ---------------------------------------------------------------------------
# Keyboard pages (3 pages, 10 chars per row, max 4 rows per page)
# ---------------------------------------------------------------------------

_PAGES_FULL = [
    {
        "label": "abc",
        "rows": [
            list("abcdefghij"),
            list("klmnopqrst"),
            list("uvwxyz _.-"),
        ],
    },
    {
        "label": "ABC",
        "rows": [
            list("ABCDEFGHIJ"),
            list("KLMNOPQRST"),
            list("UVWXYZ _.-"),
        ],
    },
    {
        "label": "123",
        "rows": [
            list("0123456789"),
            list("!@#$%^&*()"),
            list("-_=+/:;'  "),
        ],
    },
]

_PAGES_DIGITS = [
    {
        "label": "123",
        "rows": [
            list("1234567890"),
            list(".-:/      "),
        ],
    },
]

_PAGES_IP = [
    {
        "label": "IP",
        "rows": [
            list("1234567890"),
            list(".         "),
        ],
    },
]

_PAGES_HEX = [
    {
        "label": "hex",
        "rows": [
            list("0123456789"),
            list("ABCDEF:.  "),
        ],
    },
]

_PAGES_MAC = [
    {
        "label": "MAC",
        "rows": [
            list("0123456789"),
            list("ABCDEF:   "),
        ],
    },
]

_PAGES_URL = [
    {
        "label": "abc",
        "rows": [
            list("abcdefghij"),
            list("klmnopqrst"),
            list("uvwxyz    "),
        ],
    },
    {
        "label": "123",
        "rows": [
            list("0123456789"),
            list(":/.-_?=&@ "),
        ],
    },
]

_CHARSET_MAP = {
    "full": _PAGES_FULL,
    "alpha": _PAGES_FULL[:2],
    "digits": _PAGES_DIGITS,
    "ip": _PAGES_IP,
    "hex": _PAGES_HEX,
    "mac": _PAGES_MAC,
    "url": _PAGES_URL,
}


def lcd_keyboard(lcd, font, pins, gpio, title="Input", default="",
                 charset="full", max_len=64):
    """
    Show a paged on-screen keyboard on the LCD.

    Returns the entered string, or None if cancelled.
    """
    if Image is None or ScaledDraw is None:
        return default or ""

    pages = _CHARSET_MAP.get(charset, _PAGES_FULL)
    page_idx = 0
    cursor_r = 0
    cursor_c = 0
    text = list(default)
    WIDTH, HEIGHT = lcd.width, lcd.height

    # Use smaller font for keyboard keys
    try:
        key_font = scaled_font(8)
    except Exception:
        key_font = font

    # Layout (base 128)
    HEADER_H = 13
    INPUT_Y = HEADER_H + 1
    INPUT_H = 13
    GRID_TOP = INPUT_Y + INPUT_H + 2
    FOOTER_Y = 116
    # Available height for grid: FOOTER_Y - GRID_TOP
    GRID_H = FOOTER_Y - GRID_TOP

    remote_session_id = open_remote_text_session(
        title=title,
        default=default,
        charset=charset,
        max_len=max_len,
    )

    try:
        while True:
            page = pages[page_idx]
            grid = page["rows"]
            n_rows = len(grid)
            n_cols = max(len(r) for r in grid)

            # Compute key sizes to fill available space
            KEY_W = min(12, 124 // max(n_cols, 1))
            KEY_H = min(14, GRID_H // max(n_rows, 1))
            # Center grid horizontally
            grid_w = n_cols * KEY_W
            GRID_LEFT = max(1, (128 - grid_w) // 2)

            # Clamp cursor (n_rows = last grid row, n_rows = DONE button row)
            cursor_r = min(cursor_r, n_rows)
            if cursor_r < n_rows:
                cursor_c = min(cursor_c, len(grid[cursor_r]) - 1)

            remote_event = get_remote_text_event(remote_session_id)
            if remote_event:
                special = str(remote_event.get("special") or "")
                if special == "ESCAPE":
                    return None
                if special == "BACKSPACE":
                    if text:
                        text.pop()
                elif special == "ENTER":
                    return "".join(text)
                else:
                    key_value = str(remote_event.get("key") or "")
                    if key_value and len("".join(text)) + len(key_value) <= max_len:
                        text.extend(list(key_value))

            btn = get_button(pins, gpio)

            if btn == "KEY3":
                return None

            elif btn == "OK":
                if cursor_r >= n_rows:
                    # On the OK button row
                    return "".join(text)
                char = grid[cursor_r][cursor_c]
                if char == " ":
                    if len(text) < max_len:
                        text.append(" ")
                else:
                    if len(text) < max_len:
                        text.append(char)
                time.sleep(0.15)

            elif btn == "KEY2":
                if text:
                    text.pop()
                time.sleep(0.15)

            elif btn == "KEY1":
                if len(pages) > 1:
                    # Switch page
                    page_idx = (page_idx + 1) % len(pages)
                    cursor_r = 0
                    cursor_c = min(cursor_c, len(pages[page_idx]["rows"][0]) - 1)
                else:
                    # Only 1 page = confirm
                    return "".join(text)
                time.sleep(0.2)

            elif btn == "UP":
                # n_rows + 1 to include OK button row
                cursor_r = (cursor_r - 1) % (n_rows + 1)
                if cursor_r < n_rows:
                    cursor_c = min(cursor_c, len(grid[cursor_r]) - 1)
                time.sleep(0.1)

            elif btn == "DOWN":
                cursor_r = (cursor_r + 1) % (n_rows + 1)
                if cursor_r < n_rows:
                    cursor_c = min(cursor_c, len(grid[cursor_r]) - 1)
                time.sleep(0.1)

            elif btn == "LEFT":
                row_len = len(grid[cursor_r])
                cursor_c = (cursor_c - 1) % row_len
                time.sleep(0.1)

            elif btn == "RIGHT":
                row_len = len(grid[cursor_r])
                cursor_c = (cursor_c + 1) % row_len
                time.sleep(0.1)

            # -- Draw --
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)

            # Header
            d.rectangle((0, 0, 127, HEADER_H - 1), fill="#111")
            d.text((2, 1), title[:14], font=key_font, fill="#00CCFF")
            # Page indicator
            page_label = page["label"]
            d.text((90, 1), f"[{page_label}]", font=key_font, fill="#FFAA00")

            # Input field
            display_text = "".join(text)
            if len(display_text) > 18:
                display_text = "..." + display_text[-15:]
            d.rectangle((2, INPUT_Y, 125, INPUT_Y + INPUT_H - 1),
                         fill="#0a0a1a", outline="#333")
            d.text((4, INPUT_Y + 2), display_text + "|", font=key_font, fill="#00FF00")

            # Keyboard grid
            for r_idx, row in enumerate(grid):
                for c_idx, char in enumerate(row):
                    x = GRID_LEFT + c_idx * KEY_W
                    y = GRID_TOP + r_idx * KEY_H

                    is_sel = (r_idx == cursor_r and c_idx == cursor_c)

                    # Key background
                    if is_sel:
                        d.rectangle((x, y, x + KEY_W - 2, y + KEY_H - 2),
                                    fill="#003366", outline="#00CCFF")
                        txt_color = "#FFFFFF"
                    else:
                        d.rectangle((x, y, x + KEY_W - 2, y + KEY_H - 2),
                                    fill="#1a1a1a", outline="#222")
                        txt_color = "#AAAAAA"

                    # Character display
                    if char == " ":
                        display_char = "_"
                    else:
                        display_char = char
                    d.text((x + 1, y + 1), display_char, font=key_font, fill=txt_color)

            # OK button below keyboard
            ok_y = GRID_TOP + n_rows * KEY_H + 2
            ok_selected = (cursor_r >= n_rows)
            if ok_selected:
                d.rectangle((30, ok_y, 97, ok_y + KEY_H), fill="#005500", outline="#00FF00")
                d.text((50, ok_y + 1), "DONE", font=key_font, fill="#00FF00")
            else:
                d.rectangle((30, ok_y, 97, ok_y + KEY_H), fill="#1a1a1a", outline="#00AA00")
                d.text((50, ok_y + 1), "DONE", font=key_font, fill="#00AA00")

            # Footer
            d.rectangle((0, FOOTER_Y, 127, 127), fill="#111")
            if len(pages) > 1:
                d.text((2, FOOTER_Y + 1), "K1:Page K2:Del K3:Cancel", font=key_font, fill="#888")
            else:
                d.text((2, FOOTER_Y + 1), "K2:Del K3:Cancel", font=key_font, fill="#888")

            lcd.LCD_ShowImage(img, 0, 0)
            time.sleep(0.03)
    finally:
        close_remote_text_session(remote_session_id)
