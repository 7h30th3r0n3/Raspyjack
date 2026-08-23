#!/usr/bin/env python3
"""
RaspyJack Payload -- TagTinker ESL IR
======================================
Author: 7h30th3r0n3
Ported from EvilCardputer TagTinker.

Controls ESL (Electronic Shelf Label) tags via IR at 1.25 MHz.
Supports Pricer SmartTag, Continuum, DM series.

Controls:
  UP/DOWN     Navigate menus
  OK          Select / Confirm
  LEFT        Back
  KEY3        Exit payload
  Keyboard    Type barcode / text
"""

import os
import sys
import time
import signal

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font, SX, SY
from payloads._input_helper import get_button
from payloads._tagtinker_driver import (
    TagTinker, BC_LEN, COMP_AUTO, COMP_RAW, COMP_RLE,
    KIND_DOTMATRIX, KIND_SEGMENT, COLOR_MONO, COLOR_RED, COLOR_YELLOW,
    LED_TESTS, LOOT_DIR,
    is_barcode_valid, barcode_to_plid, barcode_to_type, barcode_to_profile,
    nfc_to_barcode, make_broadcast_debug_frame, make_broadcast_page_frame,
    make_ping_frame, make_refresh_frame, make_led_frame, make_addressed_frame,
    targets_load, targets_save, target_add, target_delete,
    presets_load, presets_save, preset_add, preset_delete,
    render_text, load_image_1bpp,
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
        FONT = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 14)
        FONT_SM = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 11)
        FONT_LG = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 18)
    except Exception:
        FONT = scaled_font(9)
        FONT_SM = scaled_font(7)
        FONT_LG = scaled_font(14)
else:
    FONT = scaled_font(9)
    FONT_SM = scaled_font(7)
    FONT_LG = FONT

C_BG = "#000000"
C_HEAD = "#001050"
C_ORANGE = "#FF8C00"
C_GREEN = "#00DD55"
C_RED = "#FF3333"
C_WHITE = "#FFFFFF"
C_DIM = "#555555"
C_SEL = "#002060"
C_CYAN = "#00DDDD"

DEBOUNCE = 0.2
_running = True
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


def _show(img):
    LCD.LCD_ShowImage(img, 0, 0)


def _draw(img):
    return ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)


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


def _draw_header(d, title):
    if IS_WIDE:
        d.rectangle([0, 0, W, 24], fill=C_HEAD)
        d.text((8, 3), title, font=FONT_LG, fill=C_GREEN)
    else:
        d.rectangle([0, 0, 128, 14], fill=C_HEAD)
        d.text((4, 1), title, font=FONT, fill=C_GREEN)


def _draw_footer(d, text):
    if IS_WIDE:
        d.rectangle([0, H - 18, W, H], fill="#111")
        d.text((6, H - 16), text, font=FONT_SM, fill=C_DIM)
    else:
        d.rectangle([0, 117, 128, 128], fill="#111")
        d.text((2, 118), text, font=FONT_SM, fill=C_DIM)


def _show_msg(title, msg, color=C_GREEN):
    img = Image.new("RGB", (W, H), C_BG)
    d = _draw(img)
    _draw_header(d, title)
    if IS_WIDE:
        d.text((20, 60), msg, font=FONT, fill=color)
    else:
        d.text((4, 50), msg[:18], font=FONT_SM, fill=color)
    _show(img)


def _show_msg_wait(title, msg, color=C_GREEN):
    _show_msg(title, msg, color)
    time.sleep(0.3)
    while _running:
        btn = get_button(PINS, GPIO)
        if btn in ("OK", "LEFT", "KEY3"):
            break
        time.sleep(0.05)
    time.sleep(0.15)


def _show_error(msg):
    _show_msg_wait("Error", msg, C_RED)


def _show_success(msg):
    _show_msg_wait("Success", msg, C_GREEN)


def _progress_screen(title, current, total, detail=""):
    img = Image.new("RGB", (W, H), C_BG)
    d = _draw(img)
    _draw_header(d, title)
    if IS_WIDE:
        spinner = "|/-\\"
        d.text((10, 35), "%s IR LED active" % spinner[int(time.time() * 4) % 4], font=FONT, fill=C_GREEN)
        if total > 0:
            pct = (current + 1) * 100 // total
            d.text((10, 55), "Frame %d/%d  %d%%" % (current + 1, total, pct), font=FONT, fill=C_WHITE)
            bx, bw, by = 10, W - 20, 78
            d.rectangle([bx, by, bx + bw, by + 12], outline=C_DIM)
            filled = (current + 1) * bw // total
            if filled > 0:
                d.rectangle([bx, by, bx + filled, by + 12], fill=C_GREEN)
        if detail:
            d.text((10, 100), detail, font=FONT_SM, fill=C_DIM)
    else:
        if total > 0:
            d.text((4, 30), "%d/%d" % (current + 1, total), font=FONT, fill=C_WHITE)
        if detail:
            d.text((4, 50), detail[:18], font=FONT_SM, fill=C_DIM)
    _draw_footer(d, "KEY3: Stop")
    _show(img)


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
            y = 28
            for i in range(scroll, min(len(items), scroll + vis)):
                is_sel = i == sel
                label = items[i][0] if isinstance(items[i], tuple) else items[i]
                if is_sel:
                    d.rectangle([2, y, W - 2, y + 22], fill=C_SEL)
                    d.text((10, y + 3), label, font=FONT, fill=C_ORANGE)
                else:
                    d.text((10, y + 3), label, font=FONT, fill=C_WHITE)
                y += 24
        else:
            y = 16
            for i in range(scroll, min(len(items), scroll + vis)):
                is_sel = i == sel
                label = items[i][0] if isinstance(items[i], tuple) else items[i]
                color = C_ORANGE if is_sel else C_WHITE
                d.text((4, y), label[:20], font=FONT_SM, fill=color)
                y += 16

        _draw_footer(d, "OK:Select LEFT:Back")
        _show(img)

        btn = get_button(PINS, GPIO)
        now = time.time()

        if btn == "KEY3" or btn == "LEFT":
            return -1

        if btn == "UP" and now - last_btn > 0.12:
            last_btn = now
            sel = (sel - 1) % len(items)
            if sel < scroll:
                scroll = sel
            if sel >= scroll + vis:
                scroll = sel - vis + 1

        if btn == "DOWN" and now - last_btn > 0.12:
            last_btn = now
            sel = (sel + 1) % len(items)
            if sel < scroll:
                scroll = sel
            if sel >= scroll + vis:
                scroll = sel - vis + 1

        if btn == "OK" and now - last_btn > DEBOUNCE:
            last_btn = now
            return sel

        time.sleep(0.05)
    return -1


def _get_barcode(tt):
    query = ""
    last_char = 0

    while _running:
        img = Image.new("RGB", (W, H), C_BG)
        d = _draw(img)
        _draw_header(d, "ESL Barcode Input")

        blink = int(time.time() * 2) % 2
        if IS_WIDE:
            d.text((10, 30), "Enter 17-char barcode:", font=FONT_SM, fill=C_DIM)
            display = ""
            for i in range(BC_LEN):
                if i < len(query):
                    display += query[i]
                elif i == len(query) and blink:
                    display += "_"
                else:
                    display += "_"
            d.text((10, 48), display, font=FONT, fill=C_GREEN)
            d.text((10, 70), "(%d/%d)" % (len(query), BC_LEN), font=FONT_SM, fill=C_DIM)
            if len(query) < 2:
                d.text((120, 70), "prefix (letters ok)", font=FONT_SM, fill=C_ORANGE)
            else:
                d.text((120, 70), "digits only", font=FONT_SM, fill=C_DIM)
            if tt.last_barcode and len(query) == 0:
                d.text((10, 88), "Last: %s" % tt.last_barcode, font=FONT_SM, fill=C_DIM)
                d.text((10, 104), "ENTER=reuse  S=save tag", font=FONT_SM, fill=C_CYAN)
            elif len(query) == BC_LEN:
                d.text((10, 104), "ENTER=go  S=save tag", font=FONT_SM, fill=C_CYAN)
        else:
            cur = "_" if blink else ""
            d.text((4, 20), query[:17] + cur, font=FONT_SM, fill=C_GREEN)
            d.text((4, 40), "%d/%d" % (len(query), BC_LEN), font=FONT_SM, fill=C_DIM)

        _draw_footer(d, "Type barcode KEY3:Back")
        _show(img)

        btn = get_button(PINS, GPIO)
        now = time.time()
        typed = _get_typed_char() if EVDEV_OK else None

        if btn == "KEY3":
            if query:
                query = query[:-1]
                continue
            return ""
        if btn == "LEFT":
            if query:
                query = query[:-1]
                continue
            return ""

        if typed and now - last_char > 0.12:
            last_char = now
            if typed == '\b':
                query = query[:-1]
            elif typed == '\n':
                if len(query) == 0 and tt.last_barcode:
                    return tt.last_barcode
                if len(query) == BC_LEN:
                    tt.last_barcode = query
                    return query
            elif typed in ('s', 'S') and len(query) >= 2:
                bc = query if len(query) == BC_LEN else (tt.last_barcode if tt.last_barcode else "")
                if len(bc) == BC_LEN:
                    prof = barcode_to_profile(bc)
                    def_name = prof["model_name"] if prof and prof.get("model_name") else ""
                    name = _get_text_input("Tag name")
                    if not name:
                        name = def_name if def_name else bc
                    if target_add(bc, name):
                        _show_success("Tag saved!")
                    else:
                        _show_error("Max tags reached")
                continue
            elif len(query) < BC_LEN:
                if len(query) < 2:
                    query += typed.upper()
                elif typed.isdigit():
                    query += typed

        if btn == "OK" and len(query) == BC_LEN:
            tt.last_barcode = query
            return query

        time.sleep(0.05)
    return ""


def _get_text_input(title):
    query = ""
    last_char = 0

    while _running:
        img = Image.new("RGB", (W, H), C_BG)
        d = _draw(img)
        _draw_header(d, title)
        blink = int(time.time() * 2) % 2
        cur = "_" if blink else ""
        visible = query[-20:] if len(query) > 20 else query
        if IS_WIDE:
            d.text((10, 40), visible + cur, font=FONT, fill=C_GREEN)
            d.text((10, 65), "%d chars" % len(query), font=FONT_SM, fill=C_DIM)
        else:
            d.text((4, 25), (visible + cur)[:18], font=FONT_SM, fill=C_GREEN)
        _draw_footer(d, "ENTER:OK BACK:Cancel")
        _show(img)

        typed = _get_typed_char() if EVDEV_OK else None
        now = time.time()

        if typed and now - last_char > 0.1:
            last_char = now
            if typed == '\b':
                query = query[:-1]
            elif typed == '\n':
                return query
            elif len(query) < 512:
                query += typed

        btn = get_button(PINS, GPIO)
        if btn == "KEY3" or btn == "LEFT":
            return ""
        if btn == "OK" and query:
            return query
        time.sleep(0.05)
    return ""


def _result_screen(title, stopped=False):
    img = Image.new("RGB", (W, H), C_BG)
    d = _draw(img)
    _draw_header(d, title)
    msg = "Stopped" if stopped else "Complete!"
    color = C_ORANGE if stopped else C_GREEN
    if IS_WIDE:
        d.text((30, 55), msg, font=FONT_LG, fill=color)
        d.text((10, 95), "[ENTER] Replay", font=FONT_SM, fill=C_CYAN)
        d.text((10, 110), "[BACK] Return", font=FONT_SM, fill=C_ORANGE)
    else:
        d.text((20, 50), msg, font=FONT, fill=color)
    _draw_footer(d, "OK:Replay LEFT:Back")
    _show(img)
    time.sleep(0.3)
    while _running:
        btn = get_button(PINS, GPIO)
        if btn == "OK":
            return True
        if btn == "LEFT" or btn == "KEY3":
            return False
        time.sleep(0.05)
    return False


def _do_tag_info(tt):
    bc = _get_barcode(tt)
    if not bc:
        return
    plid = barcode_to_plid(bc)
    prof = barcode_to_profile(bc)
    if not prof:
        _show_error("Invalid barcode")
        return
    valid = is_barcode_valid(bc)
    plid_str = ":".join("%02X" % b for b in plid) if plid else "?"
    items = [
        ("BC: %s" % bc,), ("PLID: %s" % plid_str,),
        ("Type: %d" % prof["type_code"],),
        ("Valid: %s" % ("Yes" if valid else "No"),),
    ]
    if prof["known"]:
        if prof["model_name"]:
            items.append(("Model: %s" % prof["model_name"],))
        items.append(("Display: %dx%d" % (prof["width"], prof["height"]),))
        items.append(("Kind: %s" % ("Dot Matrix" if prof["kind"] == KIND_DOTMATRIX else "Segment"),))
        cn = {COLOR_MONO: "Mono", COLOR_RED: "Red", COLOR_YELLOW: "Yellow"}
        items.append(("Color: %s" % cn.get(prof["color"], "?"),))
        px = prof["width"] * prof["height"]
        if px > 0:
            items.append(("Pixels: %d" % px,))
            rb = (px + 7) // 8
            fr = (rb + 19) // 20
            items.append(("Raw: %d B, %d frames" % (rb, fr),))
            items.append(("Compress: %s" % ("RLE recommended" if px > 5000 else "Raw OK"),))
        items.append((">> Save Tag <<",))
    else:
        items.append(("Unknown tag type",))

    sel = _menu(items, "Tag Info")
    if sel >= 0 and items[sel][0] == ">> Save Tag <<":
        name = _get_text_input("Tag name")
        if not name and prof.get("model_name"):
            name = prof["model_name"]
        if not name:
            name = bc
        if target_add(bc, name):
            _show_success("Tag saved!")
        else:
            _show_error("Max tags reached")


def _do_nfc_decode(tt):
    code = _get_text_input("NFC 10-char code")
    if not code:
        return
    if code.startswith("http"):
        last = code.rfind("/")
        if last >= 0:
            code = code[last + 1:]
    bc = nfc_to_barcode(code)
    if bc:
        plid = barcode_to_plid(bc)
        prof = barcode_to_profile(bc)
        items = [("NFC: %s" % code,), ("Barcode: %s" % bc,)]
        if plid:
            items.append(("PLID: %s" % ":".join("%02X" % b for b in plid),))
        if prof and prof["known"] and prof["model_name"]:
            items.append(("Model: %s" % prof["model_name"],))
        items.append((">> Save Tag <<",))
        sel = _menu(items, "NFC Decoded")
        if sel >= 0 and items[sel][0] == ">> Save Tag <<":
            target_add(bc, "NFC scan")
            _show_success("Saved!")
    else:
        _show_error("Invalid NFC code")


def _do_ping(tt):
    bc = _get_barcode(tt)
    if not bc:
        return
    while True:
        _show_msg("Ping Tag", "Sending %d reps..." % tt.wake_repeats, C_GREEN)
        tt.ping(bc)
        if not _result_screen("Ping Tag"):
            break


def _do_refresh(tt):
    bc = _get_barcode(tt)
    if not bc:
        return
    _show_msg("Refresh", "Sending...", C_GREEN)
    tt.refresh(bc)
    _show_success("Refresh sent")


def _do_led_test(tt, plid_override=None):
    if plid_override is None:
        bc = _get_barcode(tt)
        if not bc:
            return
        plid = barcode_to_plid(bc)
        if not plid:
            return
    else:
        plid = plid_override

    items = [
        ("Fast blink 5s",), ("Slow blink 5s",),
        ("Fast HIGH 5s",), ("Slow HIGH 5s",),
        ("Fast FOREVER",), ("Slow FOREVER",),
        ("LED OFF (1s)",),
    ]
    modes = [0x49, 0x41, 0xC9, 0xC1, 0xC9, 0xC1, 0x49]
    durs = [5, 5, 5, 5, 0, 0, 1]

    while True:
        sel = _menu(items, "LED Test")
        if sel < 0:
            return
        _show_msg("LED", "Waking...", C_GREEN)
        ping_frame = make_ping_frame(plid)
        tt.transmit(ping_frame, repeats=160)
        _show_msg("LED", "Sending...", C_GREEN)
        led_frame = make_led_frame(plid, modes[sel], durs[sel])
        tt.transmit(led_frame, repeats=80)
        _result_screen("LED %s" % items[sel][0])


def _do_push_text(tt):
    bc = _get_barcode(tt)
    if not bc:
        return
    prof = barcode_to_profile(bc)
    if not prof:
        return
    w = prof["width"] if prof["known"] else 296
    h = prof["height"] if prof["known"] else 128
    if w == 0 or h == 0:
        _show_error("Segment tag - no gfx")
        return

    presets = presets_load()
    if presets:
        opts = [("New text...",)] + [(p["name"],) for p in presets]
        sel = _menu(opts, "Choose Text")
        if sel < 0:
            return
        text = _get_text_input("Text for ESL") if sel == 0 else presets[sel - 1]["text"]
    else:
        text = _get_text_input("Text for ESL")

    if not text:
        return

    def _progress(cur, total, detail=""):
        _progress_screen("Push Text", cur, total, detail)

    _show_msg("Push Text", "Rendering %dx%d..." % (w, h), C_GREEN)
    plid = barcode_to_plid(bc)
    color_clear = prof["known"] and prof["color"] != COLOR_MONO
    pixels = render_text(text, w, h, tt.text_size, tt.invert)
    if not pixels:
        _show_error("Render failed")
        return
    ok = tt.send_image(bc, pixels, w, h, progress_cb=_progress, color_clear=color_clear)
    if ok:
        _result_screen("Push Text")
    else:
        _show_error("Failed")


def _do_push_image(tt):
    bc = _get_barcode(tt)
    if not bc:
        return
    prof = barcode_to_profile(bc)
    if not prof:
        return
    w = prof["width"] if prof["known"] else 296
    h = prof["height"] if prof["known"] else 128
    if w == 0 or h == 0:
        _show_error("Segment tag - no gfx")
        return

    os.makedirs(LOOT_DIR, exist_ok=True)
    files = sorted([f for f in os.listdir(LOOT_DIR)
                    if f.lower().endswith((".bmp", ".png", ".jpg"))])
    if not files:
        _show_error("No images in loot/ESL/")
        return

    items = [(f,) for f in files]
    sel = _menu(items, "Select Image")
    if sel < 0:
        return

    path = os.path.join(LOOT_DIR, files[sel])
    _show_msg("Loading", files[sel][:20], C_GREEN)
    pixels = load_image_1bpp(path, w, h)
    if not pixels:
        _show_error("Load failed")
        return

    color_clear = prof["known"] and prof["color"] != COLOR_MONO

    def _progress(cur, total, detail=""):
        _progress_screen("Push Image", cur, total, detail)

    ok = tt.send_image(bc, pixels, w, h, progress_cb=_progress, color_clear=color_clear)
    if ok:
        _result_screen("Push Image")
    else:
        _show_error("Failed")


def _do_broadcast_page(tt):
    page, duration, repeats = 1, 10, 100
    while True:
        display_items = [
            ("Page: %d" % page,), ("Duration: %ds" % duration,),
            ("Repeats: %d" % repeats,), (">> TRANSMIT <<",),
        ]
        sel = _menu(display_items, "Broadcast Page")
        if sel < 0:
            return
        if sel == 0:
            page = (page + 1) % 8
        elif sel == 1:
            duration = 5 if duration >= 60 else duration + 5
        elif sel == 2:
            repeats = 50 if repeats >= 500 else repeats + 50
        elif sel == 3:
            while True:
                _show_msg("BC Page", "Sending %d reps..." % repeats, C_GREEN)
                tt.broadcast_page(page, duration, repeats=repeats)
                if not _result_screen("BC Page Flip"):
                    break


def _do_broadcast_debug(tt):
    while True:
        _show_msg("BC Debug", "Sending 500 reps...", C_GREEN)
        tt.broadcast_debug(repeats=500)
        if not _result_screen("BC Debug"):
            break


def _do_broadcast_led(tt):
    plid = bytes(4)
    _do_led_test(tt, plid_override=plid)


def _do_text_presets(tt):
    while True:
        presets = presets_load()
        items = [(p["name"],) for p in presets] + [("+ New Preset",)]
        sel = _menu(items, "Presets (%d)" % len(presets))
        if sel < 0:
            return
        if sel < len(presets):
            sub = [("Text: %s" % presets[sel]["text"][:25],), ("Delete",)]
            s2 = _menu(sub, presets[sel]["name"])
            if s2 == 1:
                preset_delete(sel)
                _show_success("Deleted")
        else:
            name = _get_text_input("Preset name")
            if not name:
                continue
            text = _get_text_input("Preset text")
            if not text:
                continue
            if preset_add(name, text):
                _show_success("Preset saved!")
            else:
                _show_error("Max presets")


def _do_saved_targets(tt):
    while True:
        targets = targets_load()
        items = [(t["name"] if t["name"] else t["barcode"],) for t in targets]
        items.append(("+ Add New Tag",))
        sel = _menu(items, "Saved (%d)" % len(targets))
        if sel < 0:
            return
        if sel < len(targets):
            tgt = targets[sel]
            plid = barcode_to_plid(tgt["barcode"])
            acts = [
                ("Wake/Ping",), ("LED Test",), ("Push Text",),
                ("Push Image",), ("Refresh",), ("Change Page",),
                ("Info",), ("Rename",), ("Delete",),
            ]
            a = _menu(acts, tgt["name"] or tgt["barcode"])
            if a == 0:
                tt.last_barcode = tgt["barcode"]
                _do_ping(tt)
            elif a == 1 and plid:
                _do_led_test(tt, plid)
            elif a == 2:
                tt.last_barcode = tgt["barcode"]
                _do_push_text(tt)
            elif a == 3:
                tt.last_barcode = tgt["barcode"]
                _do_push_image(tt)
            elif a == 4:
                tt.last_barcode = tgt["barcode"]
                _do_refresh(tt)
            elif a == 5:
                tt.last_barcode = tgt["barcode"]
                _do_broadcast_page(tt)
            elif a == 6:
                tt.last_barcode = tgt["barcode"]
                _do_tag_info(tt)
            elif a == 7:
                name = _get_text_input("New name")
                if name:
                    targets[sel]["name"] = name
                    targets_save(targets)
            elif a == 8:
                target_delete(sel)
        else:
            bc = _get_barcode(tt)
            if bc:
                name = _get_text_input("Name (optional)")
                target_add(bc, name)


def _do_settings(tt):
    while True:
        comp_names = {COMP_AUTO: "Auto", COMP_RAW: "Raw", COMP_RLE: "RLE"}
        items = [
            ("Protocol: %s" % ("PP16 (4x fast)" if tt.use_pp16 else "PP4 (standard)"),),
            ("Compress: %s" % comp_names.get(tt.comp_mode, "?"),),
            ("Data Repeats: %d" % tt.data_repeats,),
            ("Wake Repeats: %d" % tt.wake_repeats,),
            ("Store Key: 0x%04X" % tt.store_key,),
            ("Page: %d" % tt.page,),
            ("Text Size: %d" % tt.text_size,),
            ("Invert: %s" % ("ON" if tt.invert else "OFF"),),
        ]
        sel = _menu(items, "Settings")
        if sel < 0:
            return
        if sel == 0:
            tt.use_pp16 = not tt.use_pp16
        elif sel == 1:
            tt.comp_mode = (tt.comp_mode + 1) % 3
        elif sel == 2:
            tt.data_repeats = 1 if tt.data_repeats >= 15 else tt.data_repeats + 1
        elif sel == 3:
            tt.wake_repeats = 10 if tt.wake_repeats >= 995 else tt.wake_repeats + 5
        elif sel == 4:
            tt.store_key = (tt.store_key + 0x0100) & 0xFFFF
        elif sel == 5:
            tt.page = (tt.page + 1) % 8
        elif sel == 6:
            tt.text_size = 1 if tt.text_size >= 10 else tt.text_size + 1
        elif sel == 7:
            tt.invert = not tt.invert


def main():
    tt = TagTinker()
    if not tt.open():
        _show_error("ir_carrier not found")
        GPIO.cleanup()
        return 1

    MAIN_MENU = [
        ("Saved Tags",), ("Tag Info",), ("NFC Decoder",),
        ("Push Text",), ("Push Image",), ("Text Presets",),
        ("Wake/Ping",), ("Refresh",), ("LED Test",),
        ("Broadcast Page",), ("Broadcast Debug",),
        ("Broadcast LED",), ("Settings",),
    ]

    while _running:
        sel = _menu(MAIN_MENU, "TagTinker ESL IR")
        if sel < 0:
            break
        handlers = [
            _do_saved_targets, _do_tag_info, _do_nfc_decode,
            _do_push_text, _do_push_image, _do_text_presets,
            _do_ping, _do_refresh, _do_led_test,
            _do_broadcast_page, _do_broadcast_debug,
            _do_broadcast_led, _do_settings,
        ]
        if 0 <= sel < len(handlers):
            handlers[sel](tt)

    tt.close()
    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
