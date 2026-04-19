#!/usr/bin/env python3
"""
RaspyJack Payload -- WDGoWars Upload
======================================
Upload wardriving sessions to wdgwars.pl (Watch Dogs Go Wars).
Supports CSV upload (Wigle format) and profile check.

Setup: Enter your 64-char API key from your WDGoWars profile.

Controls:
  OK         Select / Upload / Confirm
  UP/DOWN    Navigate
  KEY1       Check profile (/api/me)
  KEY2       Configure API key
  KEY3       Exit / Back
"""

import os
import sys
import time
import json
import hmac
import hashlib
import secrets
import base64
import urllib.request
import urllib.error
import ssl

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
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT

API_URL_CSV = "https://wdgwars.pl/api/upload-csv"
API_URL_JSON = "https://wdgwars.pl/api/upload"
API_URL_ME = "https://wdgwars.pl/api/me"
KEY_FILE = "/root/Raspyjack/.wdgwars_key"
SESSION_DIR = "/root/Raspyjack/loot/wardriving/sessions"
LOOT_DIR = "/root/Raspyjack/loot/wardriving"
DEBOUNCE = 0.18
_last_btn = 0


def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE:
        return None
    if b:
        _last_btn = now
    return b


def _load_key():
    try:
        with open(KEY_FILE, "r") as f:
            return f.read().strip()
    except Exception:
        return ""


def _save_key(key):
    with open(KEY_FILE, "w") as f:
        f.write(key.strip())


def _list_csv_files():
    """List all uploadable CSV files."""
    files = []
    if os.path.isdir(SESSION_DIR):
        for f in sorted(os.listdir(SESSION_DIR), reverse=True):
            if f.endswith("_wigle.csv"):
                path = os.path.join(SESSION_DIR, f)
                size = os.path.getsize(path)
                files.append((f.replace("_wigle.csv", ""), path, size))
    live = os.path.join(LOOT_DIR, "wardriving_live.csv")
    if os.path.isfile(live):
        files.insert(0, ("Live (current)", live, os.path.getsize(live)))
    return files


def _upload_csv(api_key, filepath):
    """Upload a CSV file to wdgwars.pl. Returns (success, message)."""
    boundary = f"----RaspyJack{secrets.token_hex(8)}"
    filename = os.path.basename(filepath)

    with open(filepath, "rb") as f:
        file_data = f.read()

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: text/csv\r\n\r\n"
    ).encode() + file_data + f"\r\n--{boundary}--\r\n".encode()

    req = urllib.request.Request(
        API_URL_CSV,
        data=body,
        headers={
            "X-API-Key": api_key,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "RaspyJack/2.0",
        },
        method="POST",
    )

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            if data.get("success") or data.get("ok"):
                imported = data.get("imported", data.get("new", "?"))
                captured = data.get("captured", "?")
                reinforced = data.get("reinforced", "?")
                return True, f"+{imported} new {captured} cap {reinforced} reinf"
            return False, data.get("error", "Unknown error")[:30]
    except urllib.error.HTTPError as e:
        try:
            err = json.loads(e.read().decode())
            return False, err.get("error", f"HTTP {e.code}")[:30]
        except Exception:
            return False, f"HTTP {e.code}"
    except Exception as e:
        return False, str(e)[:30]


def _get_profile(api_key):
    """Fetch profile from /api/me. Returns dict or None."""
    req = urllib.request.Request(
        API_URL_ME,
        headers={
            "X-API-Key": api_key,
            "User-Agent": "RaspyJack/2.0",
        },
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def _draw_msg(lcd, font, font_sm, title, lines, color="#00CCFF"):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "WDGWARS", font=font_sm, fill=color)
    y = 18
    d.text((4, y), title, font=font, fill=color)
    y += 14
    for txt, col in lines:
        d.text((4, y), txt[:24], font=font_sm, fill=col)
        y += 11
    lcd.LCD_ShowImage(img, 0, 0)


def _input_key(lcd, font, font_sm, current_key):
    """Hex key input using UP/DOWN to change chars, LEFT/RIGHT to move cursor."""
    HEX = "0123456789abcdef"
    key = list(current_key.ljust(64, "0")[:64])
    cursor = 0
    page = 0

    while True:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.rectangle((0, 0, 127, 12), fill="#111")
        d.text((2, 1), "API KEY", font=font_sm, fill="#FF00FF")
        d.text((80, 1), f"{cursor+1}/64", font=font_sm, fill="#888")

        # Show 16 chars per row, 4 rows visible
        chars_per_row = 16
        vis_rows = 4
        start_row = cursor // chars_per_row
        if start_row >= vis_rows:
            start_row = start_row - vis_rows + 1
        else:
            start_row = 0

        for row in range(vis_rows):
            r = start_row + row
            y = 16 + row * 22
            d.text((2, y), f"{r*chars_per_row:02d}:", font=font_sm, fill="#333")
            for col in range(chars_per_row):
                idx = r * chars_per_row + col
                if idx >= 64:
                    break
                x = 18 + col * 7
                ch = key[idx]
                if idx == cursor:
                    d.rectangle((x - 1, y - 1, x + 6, y + 9), fill="#00CCFF")
                    d.text((x, y), ch, font=font_sm, fill="#000")
                else:
                    d.text((x, y), ch, font=font_sm, fill="#aaa")

        d.rectangle((0, 105, 127, 127), fill="#111")
        d.text((2, 106), "^v:char <> :move", font=font_sm, fill="#666")
        d.text((2, 117), "OK:save KEY3:cancel", font=font_sm, fill="#666")
        lcd.LCD_ShowImage(img, 0, 0)

        btn = _btn()
        if btn == "KEY3":
            return None
        elif btn == "OK":
            return "".join(key)
        elif btn == "UP":
            ci = HEX.index(key[cursor]) if key[cursor] in HEX else 0
            key[cursor] = HEX[(ci + 1) % 16]
        elif btn == "DOWN":
            ci = HEX.index(key[cursor]) if key[cursor] in HEX else 0
            key[cursor] = HEX[(ci - 1) % 16]
        elif btn == "RIGHT":
            cursor = min(63, cursor + 1)
        elif btn == "LEFT":
            cursor = max(0, cursor - 1)


def main():
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    font = scaled_font(10)
    font_sm = scaled_font(8)
    font_xs = scaled_font(7)

    api_key = _load_key()

    try:
        while True:
            # --- Main menu ---
            files = _list_csv_files()
            has_key = len(api_key) == 64

            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.rectangle((0, 0, 127, 12), fill="#111")
            d.text((2, 1), "WDGWARS UPLOAD", font=font_sm, fill="#00CCFF")

            if has_key:
                d.text((100, 1), "KEY", font=font_sm, fill="#00FF00")
            else:
                d.text((95, 1), "NOKEY", font=font_sm, fill="#FF4444")

            d.text((4, 16), f"{len(files)} session(s) found", font=font_sm, fill="#888")

            y = 30
            menu = []
            if files:
                menu.append(("Upload latest", "latest"))
                menu.append(("Upload all", "all"))
                menu.append(("Select session", "select"))
            menu.append(("Check profile", "profile"))
            menu.append(("Set API key", "key"))

            sel = 0
            while True:
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.rectangle((0, 0, 127, 12), fill="#111")
                d.text((2, 1), "WDGWARS", font=font_sm, fill="#00CCFF")
                if has_key:
                    d.text((100, 1), "KEY", font=font_sm, fill="#00FF00")
                else:
                    d.text((95, 1), "NOKEY", font=font_sm, fill="#FF4444")

                d.text((4, 16), f"{len(files)} session(s)", font=font_sm, fill="#888")

                for i, (label, _) in enumerate(menu):
                    y = 30 + i * 14
                    col = "#00CCFF" if i == sel else "#888"
                    prefix = "> " if i == sel else "  "
                    d.text((4, y), prefix + label, font=font_sm, fill=col)

                d.rectangle((0, 116, 127, 127), fill="#111")
                d.text((2, 117), "OK:Select KEY3:Exit", font=font_xs, fill="#666")
                lcd.LCD_ShowImage(img, 0, 0)

                btn = _btn()
                if btn == "KEY3":
                    GPIO.cleanup()
                    return
                elif btn == "UP":
                    sel = (sel - 1) % len(menu)
                elif btn == "DOWN":
                    sel = (sel + 1) % len(menu)
                elif btn == "OK":
                    break

            action = menu[sel][1]

            # --- Set API key ---
            if action == "key":
                new_key = _input_key(lcd, font, font_sm, api_key)
                if new_key:
                    api_key = new_key
                    _save_key(api_key)
                    has_key = True
                    _draw_msg(lcd, font, font_sm, "Key saved!", [
                        (f"...{api_key[-8:]}", "#00FF00"),
                    ], "#00FF00")
                    time.sleep(1.5)
                continue

            # --- Check profile ---
            if action == "profile":
                if not has_key:
                    _draw_msg(lcd, font, font_sm, "No API key!", [
                        ("Set key first (menu)", "#FF4444"),
                    ], "#FF4444")
                    time.sleep(2)
                    continue

                _draw_msg(lcd, font, font_sm, "Connecting...", [
                    ("wdgwars.pl/api/me", "#888"),
                ], "#FFAA00")

                profile = _get_profile(api_key)
                if profile:
                    lines = []
                    for k in ["username", "gang", "level", "xp", "aps", "rank", "score"]:
                        v = profile.get(k)
                        if v is not None:
                            lines.append((f"{k}: {v}", "#ccc"))
                    if not lines:
                        for k, v in list(profile.items())[:6]:
                            lines.append((f"{k}: {v}"[:24], "#ccc"))
                    _draw_msg(lcd, font, font_sm, "Profile", lines, "#00FF00")
                else:
                    _draw_msg(lcd, font, font_sm, "Error", [
                        ("Could not reach API", "#FF4444"),
                        ("Check key & WiFi", "#888"),
                    ], "#FF4444")

                while _btn() != "KEY3":
                    pass
                continue

            # --- Upload ---
            if not has_key:
                _draw_msg(lcd, font, font_sm, "No API key!", [
                    ("Set key first (menu)", "#FF4444"),
                ], "#FF4444")
                time.sleep(2)
                continue

            to_upload = []

            if action == "latest" and files:
                to_upload = [files[0]]

            elif action == "all" and files:
                to_upload = files

            elif action == "select" and files:
                fsel = 0
                while True:
                    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                    d = ScaledDraw(img)
                    d.rectangle((0, 0, 127, 12), fill="#111")
                    d.text((2, 1), "SELECT SESSION", font=font_sm, fill="#00CCFF")

                    visible = 7
                    start = max(0, fsel - visible // 2)
                    for i in range(start, min(len(files), start + visible)):
                        y = 18 + (i - start) * 14
                        name = files[i][0]
                        if len(name) > 20:
                            name = name[:20] + ".."
                        size_kb = files[i][2] // 1024
                        col = "#00CCFF" if i == fsel else "#888"
                        prefix = "> " if i == fsel else "  "
                        d.text((4, y), prefix + name, font=font_sm, fill=col)
                        d.text((110, y), f"{size_kb}k", font=font_sm, fill="#555")

                    d.rectangle((0, 116, 127, 127), fill="#111")
                    d.text((2, 117), "OK:Upload KEY3:Back", font=font_xs, fill="#666")
                    lcd.LCD_ShowImage(img, 0, 0)

                    btn = _btn()
                    if btn == "KEY3":
                        break
                    elif btn == "UP":
                        fsel = (fsel - 1) % len(files)
                    elif btn == "DOWN":
                        fsel = (fsel + 1) % len(files)
                    elif btn == "OK":
                        to_upload = [files[fsel]]
                        break

            if not to_upload:
                continue

            # Upload files
            for idx, (name, path, size) in enumerate(to_upload):
                _draw_msg(lcd, font, font_sm, "Uploading...", [
                    (f"{idx+1}/{len(to_upload)}: {name[:20]}", "#FFAA00"),
                    (f"Size: {size//1024}KB", "#888"),
                    ("Please wait...", "#555"),
                ], "#FFAA00")

                ok, msg = _upload_csv(api_key, path)

                if ok:
                    _draw_msg(lcd, font, font_sm, "Success!", [
                        (name[:22], "#00FF00"),
                        (msg, "#ccc"),
                    ], "#00FF00")
                else:
                    _draw_msg(lcd, font, font_sm, "Failed!", [
                        (name[:22], "#FF4444"),
                        (msg, "#FF8800"),
                    ], "#FF4444")

                time.sleep(2)

            if len(to_upload) > 1:
                _draw_msg(lcd, font, font_sm, "Done!", [
                    (f"{len(to_upload)} files uploaded", "#00FF00"),
                ], "#00FF00")
                time.sleep(2)

    finally:
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()


if __name__ == "__main__":
    raise SystemExit(main() or 0)
