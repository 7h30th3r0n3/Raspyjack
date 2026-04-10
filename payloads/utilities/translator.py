#!/usr/bin/env python3
"""
RaspyJack Payload -- Text Translator
======================================
Author: 7h30th3r0n3

Translate text between languages using the MyMemory API.
Character picker for text input, cycles through target languages.

API: https://api.mymemory.translated.net/get?q={text}&langpair={from}|{to}

Controls
--------
  UP / DOWN   -- Character picker / cycle target language
  LEFT        -- Backspace
  OK          -- Add character / confirm text
  RIGHT       -- Start translation
  KEY1        -- New translation (clear input)
  KEY2        -- Swap source/target language
  KEY3        -- Exit / Back
"""

import os
import sys
import time
import signal
import threading

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

try:
    from urllib.request import urlopen, Request
    from urllib.parse import quote
    import json as _json
except ImportError:
    urlopen = None

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._keyboard_helper import lcd_keyboard

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROW_H = 12
DEBOUNCE = 0.22

LANGUAGES = [
    ("EN", "English"),
    ("FR", "French"),
    ("ES", "Spanish"),
    ("DE", "German"),
    ("IT", "Italian"),
    ("PT", "Portuguese"),
    ("JA", "Japanese"),
    ("ZH", "Chinese"),
    ("RU", "Russian"),
    ("AR", "Arabic"),
]

API_URL = "https://api.mymemory.translated.net/get"

_running = True
_translate_lock = threading.Lock()
_result_text = ""
_translating = False


def _cleanup(*_args):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# Translation
# ---------------------------------------------------------------------------

def _translate(text, src_lang, tgt_lang):
    """Call MyMemory API and return translated text."""
    global _result_text, _translating

    with _translate_lock:
        _translating = True
        _result_text = "Translating..."

    try:
        encoded = quote(text)
        pair = src_lang + "|" + tgt_lang
        url = API_URL + "?q=" + encoded + "&langpair=" + pair
        req = Request(url, headers={"User-Agent": "RaspyJack/1.0"})
        resp = urlopen(req, timeout=15)
        body = resp.read().decode("utf-8")
        data = _json.loads(body)

        translated = data.get("responseData", {}).get("translatedText", "")
        status_code = data.get("responseStatus", 0)

        if status_code == 200 and translated:
            with _translate_lock:
                _result_text = translated
        else:
            err_msg = data.get("responseDetails", "Unknown error")
            with _translate_lock:
                _result_text = "Err: " + str(err_msg)[:30]
    except Exception as exc:
        with _translate_lock:
            _result_text = "Err: " + str(exc)[:30]

    with _translate_lock:
        _translating = False


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_result(lcd, fnt, source, result, src_lang, tgt_lang, translating):
    """Draw translation result screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), src_lang + " -> " + tgt_lang, font=fnt, fill="#00CCFF")

    if translating:
        d.ellipse((118, 3, 124, 9), fill="#FFAA00")

    # Source text
    y = 18
    d.text((2, y), "Source:", font=fnt, fill="#888")
    y += ROW_H
    # Wrap source text
    for i in range(0, len(source), 20):
        chunk = source[i:i + 20]
        d.text((2, y), chunk, font=fnt, fill="#AAAAAA")
        y += ROW_H
        if y > 55:
            break

    # Divider
    d.line((0, y + 2, 127, y + 2), fill="#333")
    y += 6

    # Result
    d.text((2, y), "Result:", font=fnt, fill="#888")
    y += ROW_H
    for i in range(0, len(result), 20):
        chunk = result[i:i + 20]
        color = "#00FF00" if not result.startswith("Err") else "#FF4444"
        d.text((2, y), chunk, font=fnt, fill=color)
        y += ROW_H
        if y > 112:
            break

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if translating:
        d.text((2, 117), "Translating...", font=fnt, fill="#FFAA00")
    else:
        d.text((2, 117), "K1:new K3:back", font=fnt, fill="#AAA")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_lang_picker(lcd, fnt, lang_idx, label):
    """Draw language selection screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "SELECT " + label, font=fnt, fill="#00CCFF")

    y = 18
    visible = 7
    scroll = max(0, lang_idx - 3)
    end = min(len(LANGUAGES), scroll + visible)
    for i in range(scroll, end):
        code, name = LANGUAGES[i]
        is_sel = i == lang_idx
        prefix = ">" if is_sel else " "
        color = "#00FF00" if is_sel else "#AAAAAA"
        d.text((2, y), prefix + code + " " + name, font=fnt, fill=color)
        y += ROW_H

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:select KEY3:back", font=fnt, fill="#AAA")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, _result_text

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    fnt = scaled_font()

    src_idx = 0   # EN
    tgt_idx = 1   # FR
    last_press = 0.0
    view = "input"  # input | result | pick_src | pick_tgt
    source_text = ""
    pick_cursor = 0

    try:
        while _running:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            # Language picker views
            if view in ("pick_src", "pick_tgt"):
                if btn == "KEY3":
                    view = "input"
                    time.sleep(0.1)
                    continue
                elif btn == "UP":
                    pick_cursor = max(0, pick_cursor - 1)
                elif btn == "DOWN":
                    pick_cursor = min(len(LANGUAGES) - 1, pick_cursor + 1)
                elif btn == "OK":
                    if view == "pick_src":
                        src_idx = pick_cursor
                    else:
                        tgt_idx = pick_cursor
                    view = "input"
                    time.sleep(0.1)
                    continue

                label = "SOURCE" if view == "pick_src" else "TARGET"
                _draw_lang_picker(lcd, fnt, pick_cursor, label)
                time.sleep(0.08)
                continue

            # Result view
            if view == "result":
                with _translate_lock:
                    result = _result_text
                    busy = _translating

                if btn == "KEY3" and not busy:
                    view = "input"
                    time.sleep(0.1)
                    continue
                elif btn == "KEY1" and not busy:
                    with _translate_lock:
                        _result_text = ""
                    view = "input"
                    time.sleep(0.1)
                    continue

                src_code = LANGUAGES[src_idx][0]
                tgt_code = LANGUAGES[tgt_idx][0]
                _draw_result(lcd, fnt, source_text, result, src_code, tgt_code, busy)
                time.sleep(0.12)
                continue

            # Input view -- use lcd_keyboard for text entry
            src = LANGUAGES[src_idx][0]
            tgt = LANGUAGES[tgt_idx][0]
            text = lcd_keyboard(lcd, fnt, PINS, GPIO,
                                title=src + "->" + tgt,
                                charset="full")
            if text is None:
                break
            source_text = text
            src_code = LANGUAGES[src_idx][0].lower()
            tgt_code = LANGUAGES[tgt_idx][0].lower()
            view = "result"
            threading.Thread(
                target=_translate,
                args=(text, src_code, tgt_code),
                daemon=True,
            ).start()
            time.sleep(0.1)

    finally:
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
