#!/usr/bin/env python3
"""
RaspyJack Payload -- Interactive HTTP Probe (curly)
====================================================
Author: 7h30th3r0n3

Sends HTTP requests using curl and displays the response on the LCD.
Supports GET, POST, HEAD, and OPTIONS methods.  Uses a character picker
for URL input and shows status code, response time, size, and body/header
preview with scrollable output.

Controls:
  UP / DOWN  -- Select method / scroll response / navigate char picker
  LEFT       -- (input) Delete last character
  RIGHT      -- (input) Add character
  OK         -- Confirm selection / send request
  KEY1       -- New request (reset to method selection)
  KEY2       -- Toggle headers / body view
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/HTTPProbe/probe_<timestamp>.json
"""

import os
import sys
import time
import signal
import subprocess
import threading
import json
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

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
LOOT_DIR = "/root/Raspyjack/loot/HTTPProbe"
CURL_TIMEOUT = 15
CURL_OUT_FILE = "/tmp/rj_curl_out"
CURL_HDR_FILE = "/tmp/rj_curl_hdr"

METHODS = ["GET", "POST", "HEAD", "OPTIONS"]

CHARSET = list(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "/:.-_?=&@#%+~!,;"
)

DEFAULT_URL = list("http://example.com")

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
requesting = False
status_msg = "Select method"

# Response data
resp_code = 0
resp_time = ""
resp_size = ""
resp_body_lines = []
resp_header_lines = []
show_headers = False


def _cleanup(*_args):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# HTTP request via curl
# ---------------------------------------------------------------------------

def _do_request(method, url):
    """Execute curl request and parse results."""
    global requesting, resp_code, resp_time, resp_size
    global resp_body_lines, resp_header_lines, status_msg

    with lock:
        requesting = True
        status_msg = f"{method} {url[:16]}..."
        resp_code = 0
        resp_time = ""
        resp_size = ""
        resp_body_lines = []
        resp_header_lines = []

    try:
        cmd = [
            "curl", "-s",
            "-o", CURL_OUT_FILE,
            "-D", CURL_HDR_FILE,
            "-w", "%{http_code}\n%{time_total}\n%{size_download}",
            "-X", method,
            "--max-time", str(CURL_TIMEOUT),
            "-A", "RaspyJack-Probe/1.0",
            url,
        ]
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=CURL_TIMEOUT + 5,
        )

        write_data = result.stdout.strip().splitlines()
        code = 0
        total_time = "0"
        dl_size = "0"

        if len(write_data) >= 3:
            code = int(write_data[0]) if write_data[0].isdigit() else 0
            total_time = write_data[1]
            dl_size = write_data[2]
        elif len(write_data) >= 1:
            code = int(write_data[0]) if write_data[0].isdigit() else 0

        # Read response body
        body_lines = []
        try:
            with open(CURL_OUT_FILE, "r", errors="replace") as fh:
                raw = fh.read(4096)
            body_lines = raw.splitlines()
        except Exception:
            body_lines = ["(no body)"]

        # Read response headers
        header_lines = []
        try:
            with open(CURL_HDR_FILE, "r", errors="replace") as fh:
                header_lines = fh.read(2048).splitlines()
        except Exception:
            header_lines = ["(no headers)"]

        with lock:
            resp_code = code
            resp_time = f"{total_time}s"
            resp_size = f"{dl_size}B"
            resp_body_lines = body_lines[:200]
            resp_header_lines = header_lines[:50]
            if code >= 200 and code < 300:
                status_msg = f"{code} OK in {total_time}s"
            elif code >= 300 and code < 400:
                status_msg = f"{code} Redirect"
            elif code >= 400:
                status_msg = f"{code} Error"
            else:
                status_msg = f"Code: {code}"

    except subprocess.TimeoutExpired:
        with lock:
            status_msg = "Request timed out"
    except FileNotFoundError:
        with lock:
            status_msg = "curl not found"
    except Exception as exc:
        with lock:
            status_msg = f"Error: {str(exc)[:18]}"

    with lock:
        requesting = False

    # Clean up temp files
    for tmp in (CURL_OUT_FILE, CURL_HDR_FILE):
        try:
            os.remove(tmp)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_result(method, url):
    """Export probe result to JSON."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"probe_{ts}.json"
    filepath = os.path.join(LOOT_DIR, filename)

    with lock:
        data = {
            "timestamp": ts,
            "method": method,
            "url": url,
            "status_code": resp_code,
            "response_time": resp_time,
            "response_size": resp_size,
            "headers": list(resp_header_lines[:30]),
            "body_preview": list(resp_body_lines[:50]),
        }

    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)

    return filename


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(d, font_obj, title):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title[:22], font=font_obj, fill="#00CCFF")


def _draw_footer(d, font_obj, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:26], font=font_obj, fill="#888")


def _status_color(code):
    """Return a colour based on HTTP status code."""
    if 200 <= code < 300:
        return "#00FF00"
    if 300 <= code < 400:
        return "#FFAA00"
    if code >= 400:
        return "#FF4444"
    return "#CCCCCC"


def _draw_method_screen(lcd, font_obj, selected):
    """Draw method selection menu."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, font_obj, "HTTP PROBE")

    d.text((2, 18), "Select method:", font=font_obj, fill="#888")

    for i, method in enumerate(METHODS):
        y = 34 + i * ROW_H
        marker = ">" if i == selected else " "
        color = "#FFAA00" if i == selected else "#CCCCCC"
        d.text((2, y), f" {marker} {method}", font=font_obj, fill=color)

    _draw_footer(d, font_obj, "UP/DN:Select OK:Pick")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_url_input(lcd, font_obj, url_chars, char_idx):
    """Draw URL character picker screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, font_obj, "ENTER URL")

    url_str = "".join(url_chars)
    # Show last 22 chars of URL
    display_url = url_str[-22:] if len(url_str) > 22 else url_str
    d.text((2, 18), display_url if display_url else "_", font=font_obj, fill="#00FF00")

    # Character picker
    current_char = CHARSET[char_idx]
    prev_char = CHARSET[(char_idx - 1) % len(CHARSET)]
    next_char = CHARSET[(char_idx + 1) % len(CHARSET)]

    d.text((2, 38), f"  UP: {prev_char}", font=font_obj, fill="#555")
    d.text((2, 50), f"  >> {current_char} <<", font=font_obj, fill="#FFAA00")
    d.text((2, 62), f"  DN: {next_char}", font=font_obj, fill="#555")

    d.text((2, 80), "RIGHT:Add  LEFT:Del", font=font_obj, fill="#666")
    d.text((2, 92), f"Len:{len(url_chars)}", font=font_obj, fill="#666")

    _draw_footer(d, font_obj, "OK:Send K3:Exit")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_response_screen(lcd, font_obj, scroll, method, url_str):
    """Draw the response display screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, font_obj, "RESPONSE")

    with lock:
        code = resp_code
        r_time = resp_time
        r_size = resp_size
        msg = status_msg
        is_busy = requesting
        viewing_headers = show_headers
        lines = list(resp_header_lines) if viewing_headers else list(resp_body_lines)

    if is_busy:
        d.text((2, 50), "Requesting...", font=font_obj, fill="#FFAA00")
        d.ellipse((118, 3, 122, 7), fill="#00FF00")
        _draw_footer(d, font_obj, "Please wait...")
        lcd.LCD_ShowImage(img, 0, 0)
        return

    # Status line
    code_color = _status_color(code)
    d.text((2, 16), f"{method} {code}", font=font_obj, fill=code_color)
    d.text((60, 16), f"{r_time} {r_size}", font=font_obj, fill="#888")

    # View mode indicator
    view_label = "[HDR]" if viewing_headers else "[BODY]"
    d.text((100, 1), view_label, font=font_obj, fill="#FFAA00")

    # Content lines
    if lines:
        visible = lines[scroll:scroll + ROWS_VISIBLE]
        for i, line in enumerate(visible):
            y = 30 + i * ROW_H
            # Truncate long lines
            display_line = line[:24] if line else ""
            d.text((2, y), display_line, font=font_obj, fill="#CCCCCC")

        # Scroll indicator
        total = len(lines)
        if total > ROWS_VISIBLE:
            bar_h = max(4, int(ROWS_VISIBLE / total * 80))
            bar_y = 30 + int(scroll / total * 80) if total > 0 else 30
            d.rectangle((126, bar_y, 127, bar_y + bar_h), fill="#444")
    else:
        d.text((2, 50), "(empty response)", font=font_obj, fill="#666")

    _draw_footer(d, font_obj, "K1:New K2:Hdr/Body")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, show_headers, status_msg

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font_obj = scaled_font()

    method_idx = 0
    url_chars = list(DEFAULT_URL)
    char_idx = 0
    scroll = 0
    chosen_method = ""
    chosen_url = ""
    mode = "method"  # "method", "url", "response"

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            # ------ Method selection ------
            if mode == "method":
                if btn == "UP":
                    method_idx = (method_idx - 1) % len(METHODS)
                    time.sleep(DEBOUNCE)
                elif btn == "DOWN":
                    method_idx = (method_idx + 1) % len(METHODS)
                    time.sleep(DEBOUNCE)
                elif btn == "OK":
                    chosen_method = METHODS[method_idx]
                    mode = "url"
                    char_idx = 0
                    time.sleep(0.3)

                _draw_method_screen(lcd, font_obj, method_idx)

            # ------ URL input ------
            elif mode == "url":
                if btn == "UP":
                    char_idx = (char_idx - 1) % len(CHARSET)
                    time.sleep(DEBOUNCE)
                elif btn == "DOWN":
                    char_idx = (char_idx + 1) % len(CHARSET)
                    time.sleep(DEBOUNCE)
                elif btn == "RIGHT":
                    if len(url_chars) < 256:
                        url_chars = list(url_chars) + [CHARSET[char_idx]]
                    time.sleep(DEBOUNCE)
                elif btn == "LEFT":
                    if url_chars:
                        url_chars = list(url_chars[:-1])
                    time.sleep(DEBOUNCE)
                elif btn == "OK":
                    chosen_url = "".join(url_chars).strip()
                    if chosen_url:
                        mode = "response"
                        scroll = 0
                        with lock:
                            show_headers = False
                        threading.Thread(
                            target=_do_request,
                            args=(chosen_method, chosen_url),
                            daemon=True,
                        ).start()
                        time.sleep(0.3)

                _draw_url_input(lcd, font_obj, url_chars, char_idx)

            # ------ Response display ------
            elif mode == "response":
                if btn == "UP":
                    scroll = max(0, scroll - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        viewing_hdr = show_headers
                        lines = list(resp_header_lines) if viewing_hdr else list(resp_body_lines)
                    max_scroll = max(0, len(lines) - ROWS_VISIBLE)
                    scroll = min(scroll + 1, max_scroll)
                    time.sleep(0.15)
                elif btn == "KEY1":
                    # New request - go back to method select
                    mode = "method"
                    method_idx = 0
                    url_chars = list(DEFAULT_URL)
                    scroll = 0
                    with lock:
                        status_msg = "Select method"
                    time.sleep(0.3)
                elif btn == "KEY2":
                    with lock:
                        if not requesting:
                            show_headers = not show_headers
                            scroll = 0
                    time.sleep(0.3)
                elif btn == "OK":
                    # Export results
                    with lock:
                        has_data = resp_code > 0
                    if has_data:
                        fname = _export_result(chosen_method, chosen_url)
                        with lock:
                            status_msg = f"Saved: {fname[:18]}"
                    time.sleep(0.3)

                _draw_response_screen(lcd, font_obj, scroll, chosen_method, chosen_url)

            time.sleep(0.05)

    finally:
        _running = False
        time.sleep(0.2)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()
        # Clean up temp files
        for tmp in (CURL_OUT_FILE, CURL_HDR_FILE):
            try:
                os.remove(tmp)
            except OSError:
                pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
