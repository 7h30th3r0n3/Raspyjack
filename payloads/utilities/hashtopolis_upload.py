#!/usr/bin/env python3
"""
RaspyJack Payload -- Hashtopolis Uploader
==========================================
Author: 7h30th3r0n3

Upload .hc22000 / .hccapx hash files to a Hashtopolis server
via its REST API.

Controls
--------
  UP / DOWN  -- Scroll file list
  OK         -- Upload selected file
  KEY1       -- Batch upload all files
  KEY2       -- Configure server URL & API key (character picker)
  KEY3       -- Exit

Config: /root/Raspyjack/loot/Hashtopolis/config.json
Input:  /root/Raspyjack/loot/ (recursive .hc22000/.hccapx)
"""

import os
import sys
import time
import signal
import subprocess
import threading
import json
import urllib.request
import urllib.error
from datetime import datetime

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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = "/root/Raspyjack/loot"
CONFIG_DIR = os.path.join(LOOT_DIR, "Hashtopolis")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
os.makedirs(CONFIG_DIR, exist_ok=True)
HASH_EXTS = (".hc22000", ".hccapx")
ROW_H = 12
DEBOUNCE = 0.20
VISIBLE_ROWS = 7
CHAR_SET = list(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    ":/.-_@?=&"
)

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
app_running = True
hash_files = []
selected_idx = 0
scroll_pos = 0
view_mode = "list"          # list | uploading | result | config
status_msg = "Loading..."
upload_result = {}
batch_progress = 0
batch_total = 0
server_url = ""
api_key = ""

# Config editor state
config_field = 0            # 0 = server_url, 1 = api_key
config_chars = []           # list of chars being edited
config_cursor = 0


# ---------------------------------------------------------------------------
# Signal handlers
# ---------------------------------------------------------------------------
def _sig_handler(_sig, _frame):
    global app_running
    app_running = False


signal.signal(signal.SIGINT, _sig_handler)
signal.signal(signal.SIGTERM, _sig_handler)


# ---------------------------------------------------------------------------
# Config management
# ---------------------------------------------------------------------------
def _load_config():
    """Load server config from JSON file."""
    if not os.path.isfile(CONFIG_PATH):
        return "", ""
    try:
        with open(CONFIG_PATH, "r") as fh:
            data = json.load(fh)
        return (
            data.get("server_url", ""),
            data.get("api_key", ""),
        )
    except (json.JSONDecodeError, OSError):
        return "", ""


def _save_config(url, key):
    """Save server config to JSON file."""
    data = {
        "server_url": url,
        "api_key": key,
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    try:
        with open(CONFIG_PATH, "w") as fh:
            json.dump(data, fh, indent=2)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------
def _find_hash_files():
    """Recursively find hash files in loot directory."""
    found = []
    for root, _dirs, files in os.walk(LOOT_DIR):
        for fname in sorted(files):
            if fname.lower().endswith(HASH_EXTS):
                full_path = os.path.join(root, fname)
                try:
                    size = os.path.getsize(full_path)
                except OSError:
                    size = 0
                found.append({"path": full_path, "name": fname, "size": size})
    return found


def _fmt_size(size_bytes):
    """Format file size for display."""
    if size_bytes < 1024:
        return f"{size_bytes}B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes // 1024}K"
    return f"{size_bytes // (1024 * 1024)}M"


def _count_lines(filepath):
    """Count non-empty lines in a file."""
    try:
        with open(filepath, "r") as fh:
            return sum(1 for line in fh if line.strip())
    except OSError:
        return 0


# ---------------------------------------------------------------------------
# Upload via urllib
# ---------------------------------------------------------------------------
def _upload_file(filepath, url, key):
    """Upload a hash file to Hashtopolis via REST API POST."""
    try:
        with open(filepath, "rb") as fh:
            file_data = fh.read()
    except OSError as exc:
        return {"success": False, "error": str(exc)}

    basename = os.path.basename(filepath)
    hash_count = _count_lines(filepath)

    # Build multipart/form-data manually
    boundary = "----RaspyJackBoundary"
    body_parts = []

    # API key field
    body_parts.append(f"--{boundary}")
    body_parts.append('Content-Disposition: form-data; name="accessKey"')
    body_parts.append("")
    body_parts.append(key)

    # Action field
    body_parts.append(f"--{boundary}")
    body_parts.append('Content-Disposition: form-data; name="action"')
    body_parts.append("")
    body_parts.append("importFile")

    body_header = "\r\n".join(body_parts) + "\r\n"

    # File part
    file_header = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; '
        f'filename="{basename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    )
    file_footer = f"\r\n--{boundary}--\r\n"

    full_body = (
        body_header.encode("utf-8")
        + file_header.encode("utf-8")
        + file_data
        + file_footer.encode("utf-8")
    )

    content_type = f"multipart/form-data; boundary={boundary}"

    # Ensure URL ends with API path
    api_url = url.rstrip("/")
    if not api_url.endswith("/api"):
        api_url += "/api/user.php"

    req = urllib.request.Request(
        api_url,
        data=full_body,
        method="POST",
        headers={
            "Content-Type": content_type,
            "Content-Length": str(len(full_body)),
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_data = resp.read().decode("utf-8", errors="replace")
            try:
                resp_json = json.loads(resp_data)
                resp_msg = resp_json.get("response", "OK")
            except json.JSONDecodeError:
                resp_msg = resp_data[:40]

        return {
            "success": True,
            "file": basename,
            "hash_count": hash_count,
            "response": resp_msg,
        }

    except urllib.error.HTTPError as exc:
        return {
            "success": False,
            "file": basename,
            "error": f"HTTP {exc.code}",
            "hash_count": hash_count,
        }
    except urllib.error.URLError as exc:
        return {
            "success": False,
            "file": basename,
            "error": str(exc.reason)[:20],
            "hash_count": hash_count,
        }
    except Exception as exc:
        return {
            "success": False,
            "file": basename,
            "error": str(exc)[:20],
            "hash_count": hash_count,
        }


def _upload_single(file_entry):
    """Upload a single file in background."""
    global view_mode, status_msg, upload_result
    with lock:
        view_mode = "uploading"
        status_msg = f"Uploading {file_entry['name'][:14]}..."

    result = _upload_file(file_entry["path"], server_url, api_key)
    with lock:
        upload_result = result
        view_mode = "result"
        status_msg = "Uploaded" if result["success"] else "Failed"


def _upload_batch():
    """Upload all files in background."""
    global view_mode, status_msg, upload_result
    global batch_progress, batch_total

    with lock:
        files = list(hash_files)
        batch_total = len(files)
        batch_progress = 0
        view_mode = "uploading"

    succeeded = 0
    failed = 0
    total_hashes = 0

    for entry in files:
        if not app_running:
            break
        with lock:
            batch_progress += 1
            status_msg = f"{batch_progress}/{batch_total}"

        result = _upload_file(entry["path"], server_url, api_key)
        if result["success"]:
            succeeded += 1
            total_hashes += result.get("hash_count", 0)
        else:
            failed += 1

    with lock:
        upload_result = {
            "success": True,
            "batch": True,
            "succeeded": succeeded,
            "failed": failed,
            "total": batch_total,
            "hash_count": total_hashes,
        }
        view_mode = "result"
        status_msg = f"{succeeded} uploaded, {failed} fail"


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------
def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "HASHTOPOLIS", font=font, fill="#00ccff")

    with lock:
        vm = view_mode
        sel = selected_idx
        sp = scroll_pos
        msg = status_msg
        files = list(hash_files)
        res = dict(upload_result)
        bp = batch_progress
        bt = batch_total
        url = server_url
        cf = config_field
        cc = config_cursor
        chars = list(config_chars)

    if vm == "list":
        configured = bool(url)
        ind_color = "#00ff00" if configured else "#ff4444"
        d.rectangle((120, 2, 125, 11), fill=ind_color)

        y = 16
        if not files:
            d.text((2, 50), "No hash files", font=font, fill="#888888")
        else:
            end = min(len(files), sp + VISIBLE_ROWS)
            for i in range(sp, end):
                f = files[i]
                prefix = ">" if i == sel else " "
                color = "#ffff00" if i == sel else "#cccccc"
                label = f"{prefix}{f['name'][:14]} {_fmt_size(f['size'])}"
                d.text((2, y), label[:22], font=font, fill=color)
                y += ROW_H

        d.text((2, 104), msg[:22], font=font, fill="#888888")
        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "OK:up K1:all K2:cfg", font=font, fill="#666")

    elif vm == "uploading":
        d.text((2, 40), "Uploading...", font=font, fill="#ffaa00")
        d.text((2, 56), msg[:22], font=font, fill="#cccccc")
        if bt > 0:
            pct = int(bp * 100 / bt)
            d.rectangle((10, 74, 118, 86), outline="#444")
            bar_w = int(106 * pct / 100)
            if bar_w > 0:
                d.rectangle((11, 75, 11 + bar_w, 85), fill="#00ff00")

    elif vm == "result":
        y = 18
        if res.get("batch"):
            d.text((2, y), "Batch Complete", font=font, fill="#00ff00")
            y += ROW_H + 2
            d.text((2, y), f"Total: {res.get('total', 0)}",
                   font=font, fill="#cccccc")
            y += ROW_H
            d.text((2, y), f"Uploaded: {res.get('succeeded', 0)}",
                   font=font, fill="#00ff00")
            y += ROW_H
            d.text((2, y), f"Failed: {res.get('failed', 0)}",
                   font=font, fill="#ff4444")
            y += ROW_H
            d.text((2, y), f"Hashes: {res.get('hash_count', 0)}",
                   font=font, fill="#00ccff")
        else:
            ok = res.get("success", False)
            color = "#00ff00" if ok else "#ff4444"
            d.text((2, y), "UPLOADED" if ok else "FAILED",
                   font=font, fill=color)
            y += ROW_H + 2
            d.text((2, y), res.get("file", "")[:22],
                   font=font, fill="#cccccc")
            y += ROW_H
            if ok:
                d.text((2, y), f"Hashes: {res.get('hash_count', 0)}",
                       font=font, fill="#00ccff")
                y += ROW_H
                d.text((2, y), res.get("response", "")[:22],
                       font=font, fill="#888888")
            else:
                d.text((2, y), res.get("error", "")[:22],
                       font=font, fill="#ff4444")

        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "OK:back K3:exit", font=font, fill="#666")

    elif vm == "config":
        field_label = "Server URL" if cf == 0 else "API Key"
        d.text((2, 16), field_label, font=font, fill="#ffaa00")

        # Show current value
        display = "".join(chars)
        if len(display) > 20:
            start = max(0, cc - 10)
            display = display[start:start + 20]

        d.text((2, 30), display[:20], font=font, fill="#00ff00")

        # Cursor marker
        visible_cursor = min(cc, 19)
        cursor_x = 2 + visible_cursor * 6
        d.text((cursor_x, 42), "^", font=font, fill="#ff4444")

        # Current char
        if chars and cc < len(chars):
            ch = chars[cc]
            idx = CHAR_SET.index(ch) if ch in CHAR_SET else 0
            d.text((2, 56), f"Char: '{ch}' [{idx}]",
                   font=font, fill="#cccccc")

        d.text((2, 72), "UP/DN=char L/R=move", font=font, fill="#888")
        d.text((2, 84), "OK=next/save", font=font, fill="#888")

        if cf == 0:
            d.text((2, 96), "Editing URL", font=font, fill="#666")
        else:
            d.text((2, 96), "Editing API Key", font=font, fill="#666")

        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "K3:cancel", font=font, fill="#666")

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global app_running, selected_idx, scroll_pos, view_mode
    global hash_files, status_msg, server_url, api_key
    global config_field, config_chars, config_cursor

    server_url, api_key = _load_config()
    hash_files = _find_hash_files()

    if server_url:
        status_msg = f"{len(hash_files)} file(s)"
    else:
        status_msg = "K2 to configure"

    last_press = 0.0

    try:
        while app_running:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if btn == "KEY3":
                with lock:
                    if view_mode == "result":
                        view_mode = "list"
                        btn = None
                    elif view_mode == "config":
                        view_mode = "list"
                        btn = None
                    else:
                        break

            if view_mode == "config":
                if btn == "UP":
                    with lock:
                        if config_chars and config_cursor < len(config_chars):
                            ch = config_chars[config_cursor]
                            idx = CHAR_SET.index(ch) if ch in CHAR_SET else 0
                            new_idx = (idx + 1) % len(CHAR_SET)
                            new_chars = list(config_chars)
                            new_chars[config_cursor] = CHAR_SET[new_idx]
                            config_chars = new_chars

                elif btn == "DOWN":
                    with lock:
                        if config_chars and config_cursor < len(config_chars):
                            ch = config_chars[config_cursor]
                            idx = CHAR_SET.index(ch) if ch in CHAR_SET else 0
                            new_idx = (idx - 1) % len(CHAR_SET)
                            new_chars = list(config_chars)
                            new_chars[config_cursor] = CHAR_SET[new_idx]
                            config_chars = new_chars

                elif btn == "LEFT":
                    with lock:
                        if config_cursor > 0:
                            config_cursor -= 1

                elif btn == "RIGHT":
                    with lock:
                        if config_cursor < len(config_chars) - 1:
                            config_cursor += 1
                        elif len(config_chars) < 128:
                            config_chars = list(config_chars) + ["a"]
                            config_cursor += 1

                elif btn == "OK":
                    with lock:
                        value = "".join(config_chars)
                        if config_field == 0:
                            server_url = value
                            config_field = 1
                            config_chars = list(api_key) if api_key else ["a"]
                            config_cursor = 0
                        else:
                            api_key = value
                            _save_config(server_url, api_key)
                            view_mode = "list"
                            status_msg = "Config saved"
                            config_field = 0

            elif view_mode == "list":
                if btn == "UP":
                    with lock:
                        selected_idx = max(0, selected_idx - 1)
                        if selected_idx < scroll_pos:
                            scroll_pos = selected_idx

                elif btn == "DOWN":
                    with lock:
                        selected_idx = min(
                            max(0, len(hash_files) - 1), selected_idx + 1,
                        )
                        if selected_idx >= scroll_pos + VISIBLE_ROWS:
                            scroll_pos = selected_idx - VISIBLE_ROWS + 1

                elif btn == "OK":
                    if hash_files and server_url and api_key:
                        threading.Thread(
                            target=_upload_single,
                            args=(hash_files[selected_idx],),
                            daemon=True,
                        ).start()
                    elif not server_url:
                        with lock:
                            status_msg = "Configure first (K2)"

                elif btn == "KEY1":
                    if hash_files and server_url and api_key:
                        threading.Thread(
                            target=_upload_batch, daemon=True,
                        ).start()

                elif btn == "KEY2":
                    with lock:
                        view_mode = "config"
                        config_field = 0
                        config_chars = (
                            list(server_url) if server_url else ["h"]
                        )
                        config_cursor = 0

            elif view_mode == "result":
                if btn == "OK":
                    hash_files = _find_hash_files()
                    with lock:
                        view_mode = "list"
                        selected_idx = 0
                        scroll_pos = 0
                        status_msg = f"{len(hash_files)} file(s)"

            _draw_screen()
            time.sleep(0.1)

    finally:
        app_running = False
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()


if __name__ == "__main__":
    main()
