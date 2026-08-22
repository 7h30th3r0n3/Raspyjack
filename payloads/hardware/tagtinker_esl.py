#!/usr/bin/env python3
"""
RaspyJack Payload -- TagTinker ESL IR
======================================
Author: 7h30th3r0n3

Pricer Electronic Shelf Label control via 1.25 MHz IR.
Ported from EvilCardputer.

Controls:
  UP/DOWN     Navigate menu
  OK          Select / Confirm
  KEY3        Back / Exit
  Keyboard    Text input
"""

import os
import sys
import time
import signal
import threading

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font, SX, SY
from payloads._input_helper import get_button
from payloads._tagtinker_driver import (
    TagTinker, barcode_to_profile, barcode_to_plid, is_barcode_valid,
    nfc_to_barcode, load_targets, save_targets, add_target, delete_target,
    load_presets, save_presets, make_broadcast_page_frame,
    make_broadcast_debug_frame, make_ping_frame, BC_LEN,
    KIND_DOTMATRIX, COLOR_MONO, LOOT_DIR,
)

try:
    import evdev_keys
    EVDEV_OK = True
except ImportError:
    EVDEV_OK = False

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for p in PINS.values():
    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
W, H = LCD.width, LCD.height
IS_WIDE = W > 200

if IS_WIDE:
    from PIL import ImageFont
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 14)
        font_sm = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 11)
        font_lg = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 18)
    except Exception:
        font = scaled_font(9)
        font_sm = scaled_font(7)
        font_lg = scaled_font(14)
else:
    font = scaled_font(9)
    font_sm = scaled_font(7)
    font_lg = font

_running = True
DEBOUNCE = 0.2

C_BG = "#000000"
C_HEAD = "#1a0a00"
C_ORANGE = "#FF8C00"
C_WHITE = "#ffffff"
C_DIM = "#555555"
C_GREEN = "#00cc44"
C_RED = "#cc0000"
C_SEL = "#1a1400"

_EVDEV_CHARS = {
    2: '1', 3: '2', 4: '3', 5: '4', 6: '5', 7: '6', 8: '7', 9: '8', 10: '9', 11: '0',
    16: 'q', 17: 'w', 18: 'e', 19: 'r', 20: 't', 21: 'y', 22: 'u', 23: 'i', 24: 'o', 25: 'p',
    30: 'a', 31: 's', 32: 'd', 33: 'f', 34: 'g', 35: 'h', 36: 'j', 37: 'k', 38: 'l',
    44: 'z', 45: 'x', 46: 'c', 47: 'v', 48: 'b', 49: 'n', 50: 'm',
    57: ' ', 12: '-', 52: '.', 53: '/',
}


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _draw(img):
    if IS_WIDE:
        return ImageDraw.Draw(img)
    return ScaledDraw(img)


def _show(img):
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_header(d, title, sub=""):
    if IS_WIDE:
        d.rectangle([0, 0, W, 26], fill=C_HEAD)
        d.text((8, 4), title, font=font_lg, fill=C_ORANGE)
        if sub:
            d.text((W - 10, 8), sub, font=font_sm, fill=C_DIM, anchor="ra")
    else:
        d.rectangle([0, 0, 128, 14], fill=C_HEAD)
        d.text((4, 1), title, font=font, fill=C_ORANGE)


def _draw_footer(d, text):
    if IS_WIDE:
        d.rectangle([0, H - 18, W, H], fill="#0a0a0a")
        d.text((W // 2, H - 9), text, font=font_sm, fill=C_DIM, anchor="mm")
    else:
        d.rectangle([0, 117, 128, 128], fill="#0a0a0a")
        d.text((4, 118), text, font=font_sm, fill=C_DIM)


def _draw_msg(title, msg, color=C_ORANGE):
    img = Image.new("RGB", (W, H), C_BG)
    d = _draw(img)
    _draw_header(d, title)
    if IS_WIDE:
        d.text((W // 2, H // 2), msg, font=font, fill=color, anchor="mm")
    else:
        d.text((4, 50), msg[:20], font=font_sm, fill=color)
    _show(img)


def _get_typed_char():
    if not EVDEV_OK:
        return None
    for code, char in _EVDEV_CHARS.items():
        if evdev_keys.is_key_pressed(code):
            return char
    if evdev_keys.is_key_pressed(14):
        return '\b'
    if evdev_keys.is_key_pressed(28):
        return '\n'
    return None


def _menu(items, title):
    sel = 0
    scroll = 0
    last_btn = 0
    vis = 5 if IS_WIDE else 6

    while _running:
        img = Image.new("RGB", (W, H), C_BG)
        d = _draw(img)
        _draw_header(d, title)

        if IS_WIDE:
            y = 30
            for i in range(scroll, min(scroll + vis, len(items))):
                is_sel = i == sel
                if is_sel:
                    d.rectangle([4, y, W - 4, y + 22], fill=C_SEL)
                    d.text((12, y + 3), "> " + items[i][0], font=font, fill=C_ORANGE)
                else:
                    d.text((18, y + 3), items[i][0], font=font, fill=C_WHITE)
                y += 24
        else:
            y = 18
            for i in range(scroll, min(scroll + vis, len(items))):
                is_sel = i == sel
                prefix = ">" if is_sel else " "
                color = C_ORANGE if is_sel else C_WHITE
                d.text((4, y), prefix + items[i][0], font=font_sm, fill=color)
                y += 16

        _draw_footer(d, "OK:Select  K3:Back")
        _show(img)

        btn = get_button(PINS, GPIO)
        now = time.time()

        if btn == "KEY3":
            return -1

        if btn == "UP" and now - last_btn > DEBOUNCE:
            last_btn = now
            sel = (sel - 1) % len(items)
            if sel < scroll:
                scroll = sel
            if sel >= scroll + vis:
                scroll = sel - vis + 1

        if btn == "DOWN" and now - last_btn > DEBOUNCE:
            last_btn = now
            sel = (sel + 1) % len(items)
            if sel < scroll:
                scroll = sel
            if sel >= scroll + vis:
                scroll = sel - vis + 1

        if btn == "OK" and now - last_btn > DEBOUNCE:
            last_btn = now
            return sel

        time.sleep(0.08)
    return -1


def _get_barcode(tt):
    query = ""
    last_char = 0
    last_barcode = getattr(tt, '_last_barcode', "")

    while _running:
        img = Image.new("RGB", (W, H), C_BG)
        d = _draw(img)
        _draw_header(d, "ESL Barcode")

        if IS_WIDE:
            d.text((10, 35), "Enter 17-char barcode:", font=font_sm, fill=C_DIM)
            d.rectangle([8, 52, W - 8, 74], fill="#111")
            display_q = query + "_" * (BC_LEN - len(query))
            d.text((12, 55), display_q, font=font, fill=C_GREEN)
            d.text((10, 80), "%d / %d" % (len(query), BC_LEN), font=font_sm, fill=C_DIM)
            if last_barcode:
                d.text((10, 95), "Last: " + last_barcode, font=font_sm, fill=C_DIM)
        else:
            d.text((4, 20), query + "_" * max(0, 10 - len(query)), font=font_sm, fill=C_GREEN)
            d.text((4, 35), "%d/%d" % (len(query), BC_LEN), font=font_sm, fill=C_DIM)

        _draw_footer(d, "Type barcode K3:Cancel")
        _show(img)

        btn = get_button(PINS, GPIO)
        typed = _get_typed_char() if EVDEV_OK else None
        now = time.time()

        if btn == "KEY3":
            return ""

        if typed and now - last_char > 0.12:
            last_char = now
            if typed == '\b':
                query = query[:-1]
            elif typed == '\n':
                if len(query) == 0 and last_barcode:
                    return last_barcode
                if len(query) == BC_LEN:
                    tt._last_barcode = query
                    return query
            elif len(query) < BC_LEN:
                if len(query) < 2:
                    query += typed.upper()
                else:
                    if typed.isdigit():
                        query += typed

        time.sleep(0.05)
    return ""


def _tx_progress_screen(step, total, msg):
    img = Image.new("RGB", (W, H), C_BG)
    d = _draw(img)
    _draw_header(d, "Transmitting")

    if IS_WIDE:
        d.text((W // 2, 40), msg, font=font, fill=C_GREEN, anchor="mm")
        if total > 0:
            pct = (step + 1) * 100 // total
            d.rectangle([20, 65, W - 20, 80], fill="#111")
            bar_w = int((W - 40) * pct / 100)
            if bar_w > 0:
                d.rectangle([20, 65, 20 + bar_w, 80], fill=C_GREEN)
            d.text((W // 2, 90), "%d/%d (%d%%)" % (step + 1, total, pct),
                   font=font_sm, fill=C_WHITE, anchor="mm")
    else:
        d.text((4, 30), msg[:18], font=font_sm, fill=C_GREEN)
        if total > 0:
            d.text((4, 50), "%d/%d" % (step + 1, total), font=font_sm, fill=C_WHITE)

    _draw_footer(d, "K3:Stop")
    _show(img)


def _do_wake(tt):
    barcode = _get_barcode(tt)
    if not barcode:
        return
    _draw_msg("Wake", "Pinging tag...", C_GREEN)
    ok = tt.wake(barcode)
    _draw_msg("Result", "OK" if ok else "Failed", C_GREEN if ok else C_RED)
    time.sleep(1)


def _do_ping(tt):
    _do_wake(tt)


def _do_refresh(tt):
    barcode = _get_barcode(tt)
    if not barcode:
        return
    _draw_msg("Refresh", "Sending...", C_GREEN)
    ok = tt.refresh(barcode)
    _draw_msg("Result", "OK" if ok else "Failed", C_GREEN if ok else C_RED)
    time.sleep(1)


def _do_broadcast_page(tt):
    page = 0
    duration = 10
    repeats = 100
    items = [
        ("Page: %d" % page, None),
        ("Duration: %ds" % duration, None),
        ("Repeats: %d" % repeats, None),
        (">> TRANSMIT <<", None),
    ]

    while _running:
        items[0] = ("Page: %d" % page, None)
        items[1] = ("Duration: %ds" % duration, None)
        items[2] = ("Repeats: %d" % repeats, None)
        sel = _menu(items, "Broadcast Page")
        if sel < 0:
            return
        if sel == 0:
            page = (page + 1) % 8
        elif sel == 1:
            duration = 5 if duration >= 60 else duration + 5
        elif sel == 2:
            repeats = 50 if repeats >= 500 else repeats + 50
        elif sel == 3:
            _draw_msg("TX", "Broadcasting...", C_GREEN)
            tt.broadcast_page(page, duration, repeats=repeats)
            _draw_msg("Done", "Broadcast sent", C_GREEN)
            time.sleep(1)


def _do_broadcast_debug(tt):
    _draw_msg("Debug", "Broadcasting...", C_GREEN)
    tt.broadcast_debug()
    _draw_msg("Done", "Debug sent", C_GREEN)
    time.sleep(1)


def _do_push_text(tt):
    barcode = _get_barcode(tt)
    if not barcode:
        return
    profile = barcode_to_profile(barcode)
    if not profile or (profile["known"] and profile["width"] == 0):
        _draw_msg("Error", "Segment tag - no gfx", C_RED)
        time.sleep(2)
        return

    query = ""
    last_char = 0

    while _running:
        img = Image.new("RGB", (W, H), C_BG)
        d = _draw(img)
        _draw_header(d, "Push Text")
        if IS_WIDE:
            d.rectangle([8, 35, W - 8, 57], fill="#111")
            cur = "|" if int(time.time() * 2) % 2 else ""
            d.text((12, 38), query + cur, font=font, fill=C_WHITE)
            d.text((10, 62), "%d chars" % len(query), font=font_sm, fill=C_DIM)
        else:
            d.text((4, 20), query[-16:] + "_", font=font_sm, fill=C_WHITE)

        _draw_footer(d, "Type text ENTER:Send K3:Back")
        _show(img)

        btn = get_button(PINS, GPIO)
        typed = _get_typed_char() if EVDEV_OK else None
        now = time.time()

        if btn == "KEY3":
            return

        if typed and now - last_char > 0.12:
            last_char = now
            if typed == '\b':
                query = query[:-1]
            elif typed == '\n' and query:
                def cb(step, total, msg):
                    _tx_progress_screen(step, total, msg)
                _draw_msg("Sending", query[:20], C_GREEN)
                ok = tt.push_text(barcode, query, callback=cb)
                _draw_msg("Result", "OK" if ok else "Failed",
                          C_GREEN if ok else C_RED)
                time.sleep(1.5)
                return
            elif len(query) < 512:
                query += typed

        time.sleep(0.05)


def _do_led_test(tt):
    barcode = _get_barcode(tt)
    if not barcode:
        return
    items = [
        ("Fast blink 5s", lambda: tt.led_on(barcode, 0xC9, 5)),
        ("Slow blink 5s", lambda: tt.led_on(barcode, 0xC1, 5)),
        ("LED forever", lambda: tt.led_on(barcode, 0xC9, 0)),
        ("LED off", lambda: tt.led_on(barcode, 0x49, 1)),
    ]
    while _running:
        sel = _menu([(i[0], None) for i in items], "LED Test")
        if sel < 0:
            return
        _draw_msg("LED", "Sending...", C_GREEN)
        items[sel][1]()
        _draw_msg("Done", "LED command sent", C_GREEN)
        time.sleep(1)


def _do_tag_info(tt):
    barcode = _get_barcode(tt)
    if not barcode:
        return
    profile = barcode_to_profile(barcode)
    plid = barcode_to_plid(barcode)
    plid_str = ":".join("%02X" % b for b in plid) if plid else "?"

    info = [
        ("BC: " + barcode, None),
        ("PLID: " + plid_str, None),
    ]
    if profile:
        info.append(("Type: %d" % profile["type_code"], None))
        if profile["known"]:
            info.append(("Model: " + (profile["model_name"] or "?"), None))
            info.append(("%dx%d" % (profile["width"], profile["height"]), None))
            kind = "Dot Matrix" if profile["kind"] == KIND_DOTMATRIX else "Segment"
            info.append(("Kind: " + kind, None))
            color = {0: "Mono", 1: "Red", 2: "Yellow"}.get(profile["color"], "?")
            info.append(("Color: " + color, None))

    _menu(info, "Tag Info")


def _do_saved_targets(tt):
    while _running:
        targets = load_targets()
        items = [(t["name"] or t["barcode"], None) for t in targets]
        items.append(("+ Add New Tag", None))
        sel = _menu(items, "Saved Tags (%d)" % len(targets))
        if sel < 0:
            return
        if sel < len(targets):
            actions = [
                ("Wake/Ping", None),
                ("Push Text", None),
                ("LED Test", None),
                ("Info", None),
                ("Delete", None),
            ]
            act = _menu(actions, targets[sel]["name"] or targets[sel]["barcode"])
            if act == 0:
                tt._last_barcode = targets[sel]["barcode"]
                _do_wake(tt)
            elif act == 1:
                tt._last_barcode = targets[sel]["barcode"]
                _do_push_text(tt)
            elif act == 2:
                tt._last_barcode = targets[sel]["barcode"]
                _do_led_test(tt)
            elif act == 3:
                tt._last_barcode = targets[sel]["barcode"]
                _do_tag_info(tt)
            elif act == 4:
                delete_target(sel)
                _draw_msg("Deleted", "", C_GREEN)
                time.sleep(0.5)
        else:
            barcode = _get_barcode(tt)
            if barcode:
                profile = barcode_to_profile(barcode)
                name = profile["model_name"] if profile and profile["known"] else ""
                add_target(barcode, name or barcode)
                _draw_msg("Saved", barcode[:20], C_GREEN)
                time.sleep(0.5)


def _do_nfc_decoder(tt):
    query = ""
    last_char = 0

    while _running:
        img = Image.new("RGB", (W, H), C_BG)
        d = _draw(img)
        _draw_header(d, "NFC Decoder")
        if IS_WIDE:
            d.text((10, 35), "Enter 10-char NFC code:", font=font_sm, fill=C_DIM)
            d.rectangle([8, 52, W - 8, 74], fill="#111")
            d.text((12, 55), query + "_", font=font, fill=C_GREEN)
        else:
            d.text((4, 20), query + "_", font=font_sm, fill=C_GREEN)
        _draw_footer(d, "Type code ENTER:Decode K3:Back")
        _show(img)

        btn = get_button(PINS, GPIO)
        typed = _get_typed_char() if EVDEV_OK else None
        now = time.time()

        if btn == "KEY3":
            return
        if typed and now - last_char > 0.12:
            last_char = now
            if typed == '\b':
                query = query[:-1]
            elif typed == '\n' and query:
                code = query
                if "http" in code:
                    code = code.rsplit("/", 1)[-1]
                barcode = nfc_to_barcode(code)
                if barcode:
                    _draw_msg("Decoded", barcode, C_GREEN)
                    time.sleep(2)
                    add_target(barcode, "NFC scan")
                else:
                    _draw_msg("Error", "Invalid NFC code", C_RED)
                    time.sleep(2)
                return
            elif len(query) < 40:
                query += typed
        time.sleep(0.05)


def _do_settings(tt):
    while _running:
        items = [
            ("Protocol: %s" % ("PP16" if tt._use_pp16 else "PP4"), None),
            ("Compress: %s" % {0: "Auto", 1: "Raw", 2: "RLE"}[tt._comp_mode], None),
            ("Data repeats: %d" % tt._data_repeats, None),
            ("Wake repeats: %d" % tt._wake_repeats, None),
            ("Page: %d" % tt._page, None),
        ]
        sel = _menu(items, "Settings")
        if sel < 0:
            return
        if sel == 0:
            tt._use_pp16 = not tt._use_pp16
        elif sel == 1:
            tt._comp_mode = (tt._comp_mode + 1) % 3
        elif sel == 2:
            tt._data_repeats = 1 if tt._data_repeats >= 15 else tt._data_repeats + 1
        elif sel == 3:
            tt._wake_repeats = 10 if tt._wake_repeats >= 995 else tt._wake_repeats + 50
        elif sel == 4:
            tt._page = (tt._page + 1) % 8


def main():
    tt = TagTinker()

    _draw_msg("TagTinker ESL", "Initializing IR...", C_ORANGE)
    if not tt.open():
        _draw_msg("Error", "IR init failed", C_RED)
        _draw_msg("Error", "Check GPIO12 PWM", C_RED)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    _draw_msg("TagTinker ESL", "Ready!", C_GREEN)
    time.sleep(0.5)

    menu_items = [
        ("Saved Tags", lambda: _do_saved_targets(tt)),
        ("Tag Info", lambda: _do_tag_info(tt)),
        ("NFC Decoder", lambda: _do_nfc_decoder(tt)),
        ("Wake / Ping", lambda: _do_wake(tt)),
        ("Push Text", lambda: _do_push_text(tt)),
        ("LED Test", lambda: _do_led_test(tt)),
        ("Broadcast Page", lambda: _do_broadcast_page(tt)),
        ("Broadcast Debug", lambda: _do_broadcast_debug(tt)),
        ("Settings", lambda: _do_settings(tt)),
    ]

    try:
        while _running:
            sel = _menu([(i[0], None) for i in menu_items], "TagTinker ESL")
            if sel < 0:
                break
            menu_items[sel][1]()
    finally:
        tt.close()
        LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
        LCD.LCD_Clear()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
