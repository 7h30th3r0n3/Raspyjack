#!/usr/bin/env python3
"""
RaspyJack Payload -- Username OSINT Checker
============================================
Author: 7h30th3r0n3

Checks username existence across ~30 popular websites via HTTP requests.
Uses a character picker to input the target username, then probes each
site in a background thread.  Results are displayed in a scrollable list
with green (found) / red (not found) indicators.

Controls:
  UP / DOWN  -- Navigate character picker / scroll results
  LEFT       -- Delete last character
  RIGHT / OK -- Add character / confirm username
  KEY1       -- (input mode) Toggle upper/lower case
  KEY2       -- Export results to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/OSINT/osint_<user>_<timestamp>.json
"""

import os
import sys
import time
import signal
import threading
import json
import re
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button, open_remote_text_session, get_remote_text_event, close_remote_text_session
from payloads._keyboard_helper import lcd_keyboard

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROW_H = 12
ROWS_VISIBLE = 6
DEBOUNCE = 0.18
LOOT_DIR = "/root/Raspyjack/loot/OSINT"

CHARSET_LOWER = list("abcdefghijklmnopqrstuvwxyz0123456789_-.")
CHARSET_UPPER = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.")

# Sites to probe: (display_name, url_template)
# {user} is replaced with the target username
SITES = [
    ("GitHub", "https://github.com/{user}"),
    ("Twitter/X", "https://x.com/{user}"),
    ("Instagram", "https://instagram.com/{user}"),
    ("Reddit", "https://reddit.com/user/{user}"),
    ("LinkedIn", "https://linkedin.com/in/{user}"),
    ("Pinterest", "https://pinterest.com/{user}"),
    ("TikTok", "https://tiktok.com/@{user}"),
    ("YouTube", "https://youtube.com/@{user}"),
    ("Twitch", "https://twitch.tv/{user}"),
    ("Medium", "https://medium.com/@{user}"),
    ("Dev.to", "https://dev.to/{user}"),
    ("GitLab", "https://gitlab.com/{user}"),
    ("Bitbucket", "https://bitbucket.org/{user}"),
    ("Keybase", "https://keybase.io/{user}"),
    ("HackerOne", "https://hackerone.com/{user}"),
    ("Bugcrowd", "https://bugcrowd.com/{user}"),
    ("SoundCloud", "https://soundcloud.com/{user}"),
    ("Flickr", "https://flickr.com/people/{user}"),
    ("Vimeo", "https://vimeo.com/{user}"),
    ("Dribbble", "https://dribbble.com/{user}"),
    ("Behance", "https://behance.net/{user}"),
    ("About.me", "https://about.me/{user}"),
    ("Gravatar", "https://en.gravatar.com/{user}"),
    ("Patreon", "https://patreon.com/{user}"),
    ("Spotify", "https://open.spotify.com/user/{user}"),
    ("Steam", "https://steamcommunity.com/id/{user}"),
    ("HackerNews", "https://news.ycombinator.com/user?id={user}"),
    ("Replit", "https://replit.com/@{user}"),
    ("Mastodon.s", "https://mastodon.social/@{user}"),
    ("NPM", "https://npmjs.com/~{user}"),
]

USER_AGENT = "Mozilla/5.0 (compatible; RaspyJack OSINT)"
REQUEST_TIMEOUT = 8

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
checking = False
progress_count = 0
progress_total = 0
status_msg = "Enter username"

# Results: list of {"site": str, "url": str, "found": bool|None}
results = []


def _cleanup(*_args):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# HTTP probe
# ---------------------------------------------------------------------------

def _check_site(site_name, url):
    """Probe a single URL and return (site_name, url, found_bool)."""
    try:
        req = Request(url, method="HEAD")
        req.add_header("User-Agent", USER_AGENT)
        resp = urlopen(req, timeout=REQUEST_TIMEOUT)
        code = resp.getcode()
        return (site_name, url, code < 400)
    except HTTPError as exc:
        if exc.code == 405:
            # HEAD not allowed, try GET
            try:
                req = Request(url, method="GET")
                req.add_header("User-Agent", USER_AGENT)
                resp = urlopen(req, timeout=REQUEST_TIMEOUT)
                return (site_name, url, resp.getcode() < 400)
            except HTTPError as exc2:
                return (site_name, url, exc2.code < 400)
            except Exception:
                return (site_name, url, False)
        return (site_name, url, exc.code < 400)
    except (URLError, OSError, Exception):
        return (site_name, url, False)


def _check_all_thread(username):
    """Check all sites for the given username in a background thread."""
    global checking, progress_count, progress_total, status_msg

    with lock:
        checking = True
        progress_count = 0
        progress_total = len(SITES)
        status_msg = f"Checking {username}..."

    for site_name, url_tpl in SITES:
        if not _running:
            break
        url = url_tpl.replace("{user}", username)
        site, full_url, found = _check_site(site_name, url)

        with lock:
            results.append({
                "site": site,
                "url": full_url,
                "found": found,
            })
            progress_count += 1
            status_msg = f"{progress_count}/{progress_total} checked"

    with lock:
        checking = False
        found_count = sum(1 for r in results if r["found"])
        status_msg = f"Done: {found_count} found"


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_results(username):
    """Export results to JSON loot file."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"osint_{username}_{ts}.json"
    filepath = os.path.join(LOOT_DIR, filename)

    with lock:
        data = {
            "timestamp": ts,
            "username": username,
            "total_sites": len(results),
            "found_count": sum(1 for r in results if r["found"]),
            "results": [dict(r) for r in results],
        }

    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)

    return filename


# ---------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------

def _draw_header(d, font_obj, title):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title[:22], font=font_obj, fill="#00CCFF")


def _draw_footer(d, font_obj, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:26], font=font_obj, fill="#888")


def _draw_input_screen(lcd, font_obj, username_chars, char_idx, uppercase):
    """Draw the character picker for username input."""
    charset = CHARSET_UPPER if uppercase else CHARSET_LOWER
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, font_obj, "OSINT USERNAME")

    # Current input
    uname = "".join(username_chars)
    d.text((2, 18), "User:", font=font_obj, fill="#888")
    d.text((32, 18), uname[-16:] if uname else "_", font=font_obj, fill="#00FF00")

    # Character selector
    current_char = charset[char_idx]
    prev_char = charset[(char_idx - 1) % len(charset)]
    next_char = charset[(char_idx + 1) % len(charset)]

    d.text((2, 38), f"  UP: {prev_char}", font=font_obj, fill="#555")
    d.text((2, 50), f"  >> {current_char} <<", font=font_obj, fill="#FFAA00")
    d.text((2, 62), f"  DN: {next_char}", font=font_obj, fill="#555")

    # Instructions
    case_label = "UPPER" if uppercase else "lower"
    d.text((2, 80), f"RIGHT:Add  LEFT:Del", font=font_obj, fill="#666")
    d.text((2, 92), f"OK:Start  K1:{case_label}", font=font_obj, fill="#666")

    _draw_footer(d, font_obj, f"Len:{len(username_chars)} K3:Exit")
    lcd.LCD_ShowImage(img, 0, 0)


def _prompt_username(lcd, font_obj, initial=""):
    username = initial
    remote_session_id = open_remote_text_session(
        title="OSINT USERNAME",
        default=initial,
        charset="full",
        max_len=64,
    )

    try:
        while _running:
            _draw_header(ScaledDraw(Image.new("RGB", (1, 1), "black")), font_obj, "")
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            _draw_header(d, font_obj, "OSINT USERNAME")
            d.text((2, 22), "Username:", font=font_obj, fill="#888")
            d.rectangle((2, 36, 125, 50), outline="#333")
            d.text((4, 38), (username[-18:] if username else "_"), font=font_obj, fill="#00FF00")
            d.text((2, 66), "Cardputer keyboard:", font=font_obj, fill="#666")
            d.text((2, 78), "type + Enter", font=font_obj, fill="#666")
            d.text((2, 94), "OK:start LEFT:del", font=font_obj, fill="#666")
            _draw_footer(d, font_obj, f"Len:{len(username)} K3:Exit")
            lcd.LCD_ShowImage(img, 0, 0)

            remote_event = get_remote_text_event(remote_session_id)
            if remote_event:
                special = str(remote_event.get("special") or "")
                if special == "ESCAPE":
                    return None
                if special == "BACKSPACE":
                    if username:
                        username = username[:-1]
                elif special == "ENTER":
                    return username.strip()
                else:
                    key_value = str(remote_event.get("key") or "")
                    if key_value:
                        username = (username + key_value)[:64]

            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                return None
            if btn == "LEFT":
                if username:
                    username = username[:-1]
                time.sleep(DEBOUNCE)
            elif btn == "OK":
                return username.strip()

            time.sleep(0.05)
    finally:
        close_remote_text_session(remote_session_id)


def _draw_results_screen(lcd, font_obj, scroll):
    """Draw the scrollable results list."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, font_obj, "OSINT RESULTS")

    with lock:
        msg = status_msg
        res = [dict(r) for r in results]
        is_checking = checking
        prog = progress_count
        total = progress_total

    # Progress bar when checking
    if is_checking and total > 0:
        bar_w = int(120 * prog / total)
        d.rectangle((2, 16, 2 + bar_w, 20), fill="#00CCFF")
        d.rectangle((2 + bar_w, 16, 122, 20), fill="#333")

    d.text((2, 22), msg[:24], font=font_obj, fill="#AAAAAA")

    # Results list
    if res:
        visible = res[scroll:scroll + ROWS_VISIBLE]
        for i, entry in enumerate(visible):
            y = 36 + i * ROW_H
            found = entry["found"]
            color = "#00FF00" if found else "#FF4444"
            marker = "+" if found else "-"
            line = f"{marker} {entry['site'][:18]}"
            d.text((2, y), line, font=font_obj, fill=color)
    else:
        if not is_checking:
            d.text((2, 50), "No results yet", font=font_obj, fill="#666")

    _draw_footer(d, font_obj, "UP/DN:Scroll K2:Save")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, results, status_msg

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font_obj = scaled_font()

    username_chars = []
    char_idx = 0
    uppercase = False
    mode = "input"  # "input" or "results"
    scroll = 0

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            if mode == "input":
                result = _prompt_username(lcd, font_obj)
                if result is None:
                    break
                uname = result.strip()
                if uname:
                    username_chars = list(uname)
                    with lock:
                        results = []
                        status_msg = "Starting..."
                    mode = "results"
                    scroll = 0
                    threading.Thread(
                        target=_check_all_thread,
                        args=(uname,),
                        daemon=True,
                    ).start()
                    time.sleep(0.3)

            elif mode == "results":
                if btn == "UP":
                    scroll = max(0, scroll - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        max_scroll = max(0, len(results) - ROWS_VISIBLE)
                    scroll = min(scroll + 1, max_scroll)
                    time.sleep(0.15)
                elif btn == "KEY2":
                    with lock:
                        has_data = len(results) > 0
                    if has_data:
                        uname = "".join(username_chars).strip()
                        fname = _export_results(uname)
                        with lock:
                            status_msg = f"Saved: {fname[:18]}"
                    time.sleep(0.3)
                elif btn == "KEY1":
                    # Return to input mode for new search
                    with lock:
                        results = []
                        status_msg = "Enter username"
                    mode = "input"
                    username_chars = []
                    char_idx = 0
                    time.sleep(0.3)

                _draw_results_screen(lcd, font_obj, scroll)

            time.sleep(0.05)

    finally:
        _running = False
        time.sleep(0.2)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
