#!/usr/bin/env python3
"""
RaspyJack Payload -- NFC NDEF Writer
=======================================
Write NDEF records (URL, text, WiFi config) to Ultralight/NTAG tags.
Useful for demos, rickrolls, and WiFi config sharing.

Controls:
  OK         Select / Write / Edit
  UP/DOWN    Navigate / change character
  LEFT/RIGHT Move cursor
  KEY1       Switch template
  KEY2       Write to tag
  KEY3       Exit / Back
"""

import os
import sys
import time

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads.nfc_rfid._nfc_driver import auto_detect, is_ultralight

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
DEBOUNCE = 0.18
_last_btn = 0

CHARSET = " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_/:@?=&#!+%"

TEMPLATES = [
    {"name": "URL", "prefix": "https://", "text": "example.com"},
    {"name": "Text", "prefix": "", "text": "Hello World"},
    {"name": "WiFi", "prefix": "WIFI:T:WPA;S:", "text": "MySSID;P:password;;"},
    {"name": "Phone", "prefix": "tel:", "text": "+33600000000"},
    {"name": "Email", "prefix": "mailto:", "text": "user@example.com"},
    {"name": "Rickroll", "prefix": "https://", "text": "youtu.be/dQw4w9WgXcQ"},
]

URL_PREFIXES = {
    "http://www.": 0x01, "https://www.": 0x02,
    "http://": 0x03, "https://": 0x04,
    "tel:": 0x05, "mailto:": 0x06,
}


def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE:
        return None
    if b:
        _last_btn = now
    return b


def _build_ndef_url(url: str) -> bytes:
    """Build NDEF TLV for a URL record."""
    prefix_byte = 0x00
    payload_str = url
    for prefix, code in URL_PREFIXES.items():
        if url.startswith(prefix):
            prefix_byte = code
            payload_str = url[len(prefix):]
            break
    payload = bytes([prefix_byte]) + payload_str.encode("utf-8")
    # NDEF record: MB|ME|SR|TNF=0x01, type_len=1, payload_len, type="U", payload
    record = bytes([0xD1, 0x01, len(payload), 0x55]) + payload
    # TLV: type=0x03, length, data, terminator=0xFE
    tlv = bytes([0x03, len(record)]) + record + bytes([0xFE])
    return tlv


def _build_ndef_text(text: str) -> bytes:
    """Build NDEF TLV for a text record."""
    lang = b"en"
    payload = bytes([len(lang)]) + lang + text.encode("utf-8")
    record = bytes([0xD1, 0x01, len(payload), 0x54]) + payload
    tlv = bytes([0x03, len(record)]) + record + bytes([0xFE])
    return tlv


def _write_ndef_to_tag(drv, ndef_bytes: bytes, lcd, font, font_sm):
    """Write NDEF TLV to Ultralight/NTAG starting at page 4."""
    # Pad to 4-byte page boundary
    data = ndef_bytes
    while len(data) % 4:
        data += b"\x00"

    total_pages = len(data) // 4
    written = 0

    for i in range(total_pages):
        pct = (i + 1) * 100 // total_pages
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.rectangle((0, 0, 127, 14), fill="#111")
        d.text((2, 2), "WRITING", font=font_sm, fill="#FF00FF")
        d.text((80, 2), f"{pct}%", font=font_sm, fill="#FF00FF")
        d.rectangle((4, 30, 123, 38), outline="#333")
        bw = max(1, int(119 * (i + 1) / total_pages))
        d.rectangle((4, 30, 4 + bw, 38), fill="#FF00FF")
        d.text((4, 50), f"Page {4 + i}/{4 + total_pages}", font=font_sm, fill="#FFAA00")
        lcd.LCD_ShowImage(img, 0, 0)

        page_data = data[i * 4:(i + 1) * 4]
        if drv.mifare_ul_write(4 + i, page_data):
            written += 1
        else:
            return written, total_pages

    return written, total_pages


def _edit_text(lcd, font, font_sm, label, initial):
    """Simple text editor with character-by-character input."""
    text = list(initial)
    cursor = len(text) - 1
    if cursor < 0:
        cursor = 0
        text = [" "]

    while True:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.rectangle((0, 0, 127, 14), fill="#111")
        d.text((2, 2), label[:16], font=font_sm, fill="#00CCFF")
        d.text((90, 2), f"{len(text)}ch", font=font_sm, fill="#888")

        # Show text in rows
        display = "".join(text)
        row_len = 18
        y = 20
        for row_start in range(0, len(display), row_len):
            row = display[row_start:row_start + row_len]
            d.text((4, y), row, font=font_sm, fill="#ccc")
            # Cursor underline
            if row_start <= cursor < row_start + row_len:
                cx = 4 + (cursor - row_start) * 7
                d.rectangle((cx, y + 10, cx + 6, y + 11), fill="#00FF00")
            y += 14

        d.rectangle((0, 100, 127, 127), fill="#111")
        ch = text[cursor] if cursor < len(text) else " "
        d.text((4, 102), f"Char: '{ch}'", font=font_sm, fill="#888")
        d.text((4, 114), "^v:chr <>:move OK:done", font=font_sm, fill="#666")
        lcd.LCD_ShowImage(img, 0, 0)

        btn = _btn()
        if btn == "OK":
            return "".join(text).rstrip()
        elif btn == "KEY3":
            return None
        elif btn == "UP":
            ci = CHARSET.index(text[cursor]) if text[cursor] in CHARSET else 0
            text[cursor] = CHARSET[(ci + 1) % len(CHARSET)]
        elif btn == "DOWN":
            ci = CHARSET.index(text[cursor]) if text[cursor] in CHARSET else 0
            text[cursor] = CHARSET[(ci - 1) % len(CHARSET)]
        elif btn == "RIGHT":
            cursor += 1
            if cursor >= len(text):
                text.append(" ")
        elif btn == "LEFT":
            cursor = max(0, cursor - 1)
        elif btn == "KEY2":
            if len(text) > 1:
                text.pop(cursor)
                cursor = min(cursor, len(text) - 1)


def main():
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    font = scaled_font(10)
    font_sm = scaled_font(9)

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), "Detecting reader...", font=font_sm, fill="#FFAA00")
    lcd.LCD_ShowImage(img, 0, 0)

    drv, drv_desc = auto_detect()
    sel = 0
    status = drv_desc if drv else "No reader"
    current_text = TEMPLATES[0]["prefix"] + TEMPLATES[0]["text"]

    try:
        while True:
            # Draw template selection
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.rectangle((0, 0, 127, 14), fill="#111")
            d.text((2, 2), "NDEF WRITER", font=font_sm, fill="#FF00FF")

            y = 18
            d.text((2, y), status[:24], font=font_sm, fill="#FFAA00")
            y += 13

            for i, tmpl in enumerate(TEMPLATES):
                if y > 90:
                    break
                col = "#FF00FF" if i == sel else "#888"
                prefix = "> " if i == sel else "  "
                d.text((2, y), f"{prefix}{tmpl['name']}", font=font_sm, fill=col)
                if i == sel:
                    preview = (tmpl["prefix"] + tmpl["text"])[:18]
                    d.text((4, y + 12), preview, font=font_sm, fill="#555")
                    y += 12
                y += 12

            d.rectangle((0, 116, 127, 127), fill="#111")
            d.text((2, 117), "OK:Edit K2:Write K3:X", font=font_sm, fill="#666")
            lcd.LCD_ShowImage(img, 0, 0)

            btn = _btn()
            if btn == "KEY3":
                break
            elif btn == "UP":
                sel = (sel - 1) % len(TEMPLATES)
                current_text = TEMPLATES[sel]["prefix"] + TEMPLATES[sel]["text"]
            elif btn == "DOWN":
                sel = (sel + 1) % len(TEMPLATES)
                current_text = TEMPLATES[sel]["prefix"] + TEMPLATES[sel]["text"]
            elif btn == "OK":
                result = _edit_text(lcd, font, font_sm, TEMPLATES[sel]["name"], current_text)
                if result:
                    current_text = result
            elif btn == "KEY2":
                if not drv:
                    drv, drv_desc = auto_detect()
                    status = drv_desc
                    continue
                if not drv.can_write:
                    status = "Reader can't write"
                    continue

                # Build NDEF
                tmpl = TEMPLATES[sel]
                if tmpl["name"] == "Text":
                    ndef = _build_ndef_text(current_text)
                else:
                    ndef = _build_ndef_url(current_text)

                # Wait for tag
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.text((4, 40), "Place NTAG/UL tag", font=font, fill="#FFAA00")
                d.text((4, 58), "on reader...", font=font_sm, fill="#FFAA00")
                lcd.LCD_ShowImage(img, 0, 0)

                card = drv.read_passive_target(timeout=8.0)
                if not card:
                    status = "No tag detected"
                    continue
                if not is_ultralight(card):
                    status = f"Not UL/NTAG: {card.card_type}"
                    continue

                written, total = _write_ndef_to_tag(drv, ndef, lcd, font, font_sm)
                if written == total:
                    status = f"Written! {len(ndef)}B"
                else:
                    status = f"Partial: {written}/{total} pages"
                time.sleep(1)

    finally:
        if drv:
            drv.close()
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
