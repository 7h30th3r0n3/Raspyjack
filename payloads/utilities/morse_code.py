#!/usr/bin/env python3
"""
RaspyJack Payload -- Morse Code Encoder / Decoder
====================================================
Author: 7h30th3r0n3

Encode text to Morse code with visual dot/dash display, or decode
Morse input tapped via buttons.  Uses the standard ITU Morse table.

Controls
--------
  KEY2         -- Toggle Encode / Decode mode

  Encode mode:
    UP / DOWN  -- Navigate character picker
    OK         -- Add character to message
    KEY1       -- Backspace / submit (long text triggers encode)

  Decode mode:
    KEY1       -- Input dot (.)
    OK         -- Input dash (-)
    DOWN       -- Letter space (decode current symbol)
    RIGHT      -- Word space
    LEFT       -- Backspace last symbol

  KEY3         -- Exit
"""

import os
import sys
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
font = scaled_font()

DEBOUNCE = 0.18
ROW_H = 12

# ---------------------------------------------------------------------------
# ITU Morse Code Table
# ---------------------------------------------------------------------------
MORSE_TABLE = {
    "A": ".-",    "B": "-...",  "C": "-.-.",  "D": "-..",
    "E": ".",     "F": "..-.",  "G": "--.",   "H": "....",
    "I": "..",    "J": ".---",  "K": "-.-",   "L": ".-..",
    "M": "--",    "N": "-.",    "O": "---",   "P": ".--.",
    "Q": "--.-",  "R": ".-.",   "S": "...",   "T": "-",
    "U": "..-",   "V": "...-",  "W": ".--",  "X": "-..-",
    "Y": "-.--",  "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--",
    "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.",
    ".": ".-.-.-", ",": "--..--", "?": "..--..", "!": "-.-.--",
    "/": "-..-.",  "(": "-.--.", ")": "-.--.-", "&": ".-...",
    ":": "---...", ";": "-.-.-.", "=": "-...-",  "+": ".-.-.",
    "-": "-....-", "_": "..--.-", '"': ".-..-.", "'": ".----.",
    "@": ".--.-.", " ": "/",
}

# Reverse lookup: morse -> character
MORSE_REVERSE = {v: k for k, v in MORSE_TABLE.items() if v != "/"}

CHARSET = list(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    " .,-?!"
)

_running = True


def _cleanup(*_args):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# Encoding / Decoding
# ---------------------------------------------------------------------------

def _encode_text(text):
    """Convert text to Morse code string."""
    result = []
    for ch in text.upper():
        code = MORSE_TABLE.get(ch, "")
        if code:
            result.append(code)
    return " ".join(result)


def _decode_symbol(symbol):
    """Decode a single Morse symbol to a character."""
    return MORSE_REVERSE.get(symbol, "?")


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


def _draw_encode_input(text_chars, char_idx):
    """Draw the encode mode character input screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "MORSE: ENCODE")

    d.text((2, 18), "Text:", font=font, fill="#aaa")
    text_str = "".join(text_chars)
    d.text((2, 30), text_str[-20:] + "_", font=font, fill="#fff")

    current = CHARSET[char_idx]
    morse = MORSE_TABLE.get(current.upper(), "")
    d.text((2, 48), f"Char: [ {current} ]", font=font, fill="#00ff00")
    d.text((2, 60), f"Morse: {morse}", font=font, fill="#ffaa00")

    d.text((2, 78), "OK:add  KEY1:del", font=font, fill="#666")
    d.text((2, 90), "KEY2:encode", font=font, fill="#666")

    _draw_footer(d, "UP/DN:char K2:encode")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_morse_output(text_str, morse_str, scroll):
    """Draw the Morse code output with visual dots and dashes."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "MORSE OUTPUT")

    # Show source text
    d.text((2, 16), f"In: {text_str[-18:]}", font=font, fill="#888")

    # Draw morse visually
    y = 30
    morse_parts = morse_str.split(" ")
    visible_start = scroll
    x = 2
    for idx in range(visible_start, len(morse_parts)):
        symbol = morse_parts[idx]
        if symbol == "/":
            x += 8
            if x > 120:
                x = 2
                y += ROW_H + 4
            continue
        for ch in symbol:
            if ch == ".":
                d.ellipse((x, y + 2, x + 4, y + 6), fill="#00ff00")
                x += 6
            elif ch == "-":
                d.rectangle((x, y + 3, x + 8, y + 5), fill="#ffaa00")
                x += 10
        x += 5
        if x > 115:
            x = 2
            y += ROW_H + 4
        if y > 105:
            break

    # Show morse text at bottom
    d.text((2, 106), morse_str[scroll:scroll + 22], font=font, fill="#555")

    _draw_footer(d, "K1:new K2:decode mode")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_decode_mode(current_symbol, decoded_text, buffer_display):
    """Draw the decode mode input screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "MORSE: DECODE")

    # Current symbol being entered
    d.text((2, 18), "Symbol:", font=font, fill="#aaa")
    display_sym = current_symbol if current_symbol else "(empty)"
    d.text((2, 30), display_sym, font=font, fill="#ffaa00")

    # Visual representation of current symbol
    x = 2
    y = 44
    for ch in current_symbol:
        if ch == ".":
            d.ellipse((x, y, x + 6, y + 6), fill="#00ff00")
            x += 9
        elif ch == "-":
            d.rectangle((x, y + 1, x + 12, y + 5), fill="#ffaa00")
            x += 15
        if x > 110:
            break

    # Decoded text so far
    d.text((2, 58), "Decoded:", font=font, fill="#aaa")
    decoded_display = decoded_text[-20:] if decoded_text else "(none)"
    d.text((2, 70), decoded_display, font=font, fill="#00ff00")

    # Buffer (recent symbols)
    d.text((2, 86), f"Buf: {buffer_display[-18:]}", font=font, fill="#555")

    d.text((2, 100), "K1:dot OK:dash", font=font, fill="#666")

    _draw_footer(d, "DN:letter RT:word L:del")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running

    mode = "encode"  # encode | encode_output | decode
    # Encode state
    enc_chars = []
    enc_char_idx = 0
    enc_morse = ""
    enc_scroll = 0
    # Decode state
    dec_symbol = ""
    dec_text = ""
    dec_buffer = ""
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
                if mode == "encode_output":
                    mode = "encode"
                    continue
                break

            # Mode toggle
            if btn == "KEY2" and mode != "encode_output":
                mode = "decode" if mode == "encode" else "encode"
                time.sleep(0.15)
                continue

            # --- Encode input mode ---
            if mode == "encode":
                if btn == "UP":
                    enc_char_idx = (enc_char_idx - 1) % len(CHARSET)
                elif btn == "DOWN":
                    enc_char_idx = (enc_char_idx + 1) % len(CHARSET)
                elif btn == "OK":
                    enc_chars = enc_chars + [CHARSET[enc_char_idx]]
                elif btn == "KEY1":
                    if enc_chars:
                        enc_chars = enc_chars[:-1]
                elif btn == "KEY2":
                    text = "".join(enc_chars)
                    enc_morse = _encode_text(text)
                    enc_scroll = 0
                    mode = "encode_output"

                _draw_encode_input(enc_chars, enc_char_idx)

            # --- Encode output mode ---
            elif mode == "encode_output":
                if btn == "LEFT":
                    enc_scroll = max(0, enc_scroll - 5)
                elif btn == "RIGHT":
                    enc_scroll = min(
                        max(0, len(enc_morse) - 20), enc_scroll + 5
                    )
                elif btn == "KEY1":
                    enc_chars = []
                    enc_morse = ""
                    mode = "encode"

                text = "".join(enc_chars)
                _draw_morse_output(text, enc_morse, enc_scroll)

            # --- Decode mode ---
            elif mode == "decode":
                if btn == "KEY1":
                    dec_symbol = dec_symbol + "."
                elif btn == "OK":
                    dec_symbol = dec_symbol + "-"
                elif btn == "DOWN":
                    # Letter space: decode current symbol
                    if dec_symbol:
                        ch = _decode_symbol(dec_symbol)
                        dec_text = dec_text + ch
                        dec_buffer = dec_buffer + dec_symbol + " "
                        dec_symbol = ""
                elif btn == "RIGHT":
                    # Word space: decode current and add space
                    if dec_symbol:
                        ch = _decode_symbol(dec_symbol)
                        dec_text = dec_text + ch
                        dec_buffer = dec_buffer + dec_symbol + " "
                        dec_symbol = ""
                    dec_text = dec_text + " "
                    dec_buffer = dec_buffer + "/ "
                elif btn == "LEFT":
                    # Backspace last symbol char
                    if dec_symbol:
                        dec_symbol = dec_symbol[:-1]
                    elif dec_text:
                        dec_text = dec_text[:-1]

                _draw_decode_mode(dec_symbol, dec_text, dec_buffer)

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
