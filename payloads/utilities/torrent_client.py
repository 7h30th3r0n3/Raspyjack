#!/usr/bin/env python3
"""
RaspyJack Payload -- Torrent Client
=====================================
Author: 7h30th3r0n3

Lightweight torrent client using transmission-daemon as backend.
LCD shows torrent list with progress, speed, seeds/peers.
Full WebUI available at http://<CZ_IP>:9091

Controls:
  UP/DOWN     Navigate torrent list
  OK          Pause/Resume selected torrent
  KEY1        Add magnet link (keyboard input)
  KEY2        Delete selected torrent
  KEY3        Exit (daemon keeps running)
  LEFT/RIGHT  Switch between All/Downloading/Seeding/Paused
"""

import os
import sys
import time
import signal
import subprocess
import json
import urllib.request
import urllib.error

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._keyboard_helper import lcd_keyboard

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

FONT = scaled_font(9)
FONT_SM = scaled_font(7)
FONT_LG = scaled_font(12)

C_BG = "#000000"
C_CYAN = "#00E5FF"
C_GREEN = "#00FF00"
C_RED = "#FF4444"
C_ORANGE = "#FF8C00"
C_WHITE = "#FFFFFF"
C_DIM = "#666666"
C_DARK = "#111111"
C_SEL = "#003366"

DEBOUNCE = 0.18
_running = True

RPC_URL = "http://127.0.0.1:9091/transmission/rpc"
DOWNLOAD_DIR = "/root/Raspyjack/loot/torrents"
WATCH_DIR = "/root/Raspyjack/loot/torrents/watch"
SESSION_ID = ""

FILTERS = ["All", "DL", "Seed", "Paused"]
STATUS_MAP = {
    0: "Stopped",
    1: "Check wait",
    2: "Checking",
    3: "DL wait",
    4: "Downloading",
    5: "Seed wait",
    6: "Seeding",
}


def _sig_handler(sig, frame):
    global _running
    _running = False

signal.signal(signal.SIGINT, _sig_handler)
signal.signal(signal.SIGTERM, _sig_handler)


def _show(img):
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_msg(line1, line2="", color=C_CYAN):
    img = Image.new("RGB", (W, H), C_BG)
    d = ScaledDraw(img)
    d.text((64, 50), line1, font=FONT, fill=color, anchor="mm")
    if line2:
        d.text((64, 68), line2, font=FONT_SM, fill=C_DIM, anchor="mm")
    _show(img)


def _human_size(b):
    if b < 1024:
        return f"{b}B"
    if b < 1024 * 1024:
        return f"{b / 1024:.0f}K"
    if b < 1024 * 1024 * 1024:
        return f"{b / 1024 / 1024:.1f}M"
    return f"{b / 1024 / 1024 / 1024:.2f}G"


def _human_speed(bps):
    if bps < 1024:
        return f"{bps}B/s"
    if bps < 1024 * 1024:
        return f"{bps / 1024:.0f}K/s"
    return f"{bps / 1024 / 1024:.1f}M/s"


def _ensure_dirs():
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    os.makedirs(WATCH_DIR, exist_ok=True)


def _start_daemon():
    _draw_msg("Starting", "transmission-daemon...")
    try:
        subprocess.run(["pgrep", "-x", "transmission-da"], capture_output=True, check=True)
        return True
    except subprocess.CalledProcessError:
        pass

    _ensure_dirs()
    cmd = [
        "transmission-daemon",
        "--no-auth",
        "--download-dir", DOWNLOAD_DIR,
        "--watch-dir", WATCH_DIR,
        "--allowed", "127.0.0.1",
        "--port", "9091",
        "--no-portmap",
        "--foreground",
    ]
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        return True
    except FileNotFoundError:
        _draw_msg("Error", "transmission not installed", C_RED)
        time.sleep(2)
        return False


def _rpc(method, arguments=None):
    global SESSION_ID
    payload = {"method": method}
    if arguments:
        payload["arguments"] = arguments
    data = json.dumps(payload).encode()

    for _ in range(2):
        req = urllib.request.Request(
            RPC_URL,
            data=data,
            headers={
                "Content-Type": "application/json",
                "X-Transmission-Session-Id": SESSION_ID,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 409:
                SESSION_ID = e.headers.get("X-Transmission-Session-Id", "")
                continue
            return None
        except Exception:
            return None
    return None


def _get_torrents():
    resp = _rpc("torrent-get", {
        "fields": [
            "id", "name", "status", "percentDone",
            "rateDownload", "rateUpload",
            "peersConnected", "peersSendingToUs", "peersGettingFromUs",
            "totalSize", "downloadedEver", "uploadedEver",
            "eta",
        ]
    })
    if resp and resp.get("result") == "success":
        return resp["arguments"]["torrents"]
    return []


def _add_magnet(uri):
    return _rpc("torrent-add", {"filename": uri})


def _pause_torrent(tid):
    return _rpc("torrent-stop", {"ids": [tid]})


def _resume_torrent(tid):
    return _rpc("torrent-start", {"ids": [tid]})


def _remove_torrent(tid, delete_data=False):
    return _rpc("torrent-remove", {"ids": [tid], "delete-local-data": delete_data})


def _filter_torrents(torrents, filt):
    if filt == "All":
        return torrents
    if filt == "DL":
        return [t for t in torrents if t["status"] in (3, 4)]
    if filt == "Seed":
        return [t for t in torrents if t["status"] in (5, 6)]
    if filt == "Paused":
        return [t for t in torrents if t["status"] == 0]
    return torrents


def _draw_ui(torrents, cursor, filt_idx, total_dl, total_ul):
    img = Image.new("RGB", (W, H), C_BG)
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#0a0a1a")
    d.text((2, 1), "Torrents", font=FONT_SM, fill=C_CYAN)
    filt_label = FILTERS[filt_idx]
    d.text((80, 1), f"[{filt_label}]", font=FONT_SM, fill=C_ORANGE)

    d.rectangle((0, 13, 127, 21), fill="#050510")
    speed_str = f"D:{_human_speed(total_dl)} U:{_human_speed(total_ul)}"
    d.text((2, 13), speed_str, font=FONT_SM, fill=C_DIM)

    if not torrents:
        d.text((64, 65), "No torrents", font=FONT, fill=C_DIM, anchor="mm")
        d.text((64, 82), "K1:Add magnet", font=FONT_SM, fill=C_DIM, anchor="mm")
    else:
        y_start = 23
        row_h = 20
        vis = (116 - y_start) // row_h
        scroll = max(0, min(cursor - vis // 2, max(0, len(torrents) - vis)))

        for i in range(scroll, min(scroll + vis, len(torrents))):
            t = torrents[i]
            y = y_start + (i - scroll) * row_h
            is_sel = i == cursor

            if is_sel:
                d.rectangle((0, y, 127, y + row_h - 1), fill=C_SEL)

            name = t["name"][:18]
            pct = int(t["percentDone"] * 100)
            status = t["status"]

            if status == 0:
                st_color = C_DIM
            elif status in (3, 4):
                st_color = C_CYAN
            elif status in (5, 6):
                st_color = C_GREEN
            else:
                st_color = C_ORANGE

            d.text((2, y), name, font=FONT_SM, fill=C_WHITE if is_sel else C_DIM)

            bar_x = 2
            bar_y = y + 10
            bar_w = 90
            bar_h = 7
            d.rectangle((bar_x, bar_y, bar_x + bar_w, bar_y + bar_h), fill="#1a1a1a", outline="#333")
            fill_w = int(bar_w * pct / 100)
            if fill_w > 0:
                d.rectangle((bar_x, bar_y, bar_x + fill_w, bar_y + bar_h), fill=st_color)

            d.text((95, y), f"{pct}%", font=FONT_SM, fill=st_color)

            peers = t.get("peersConnected", 0)
            if status in (3, 4):
                spd = _human_speed(t["rateDownload"])
                d.text((95, y + 9), f"{spd}", font=FONT_SM, fill=C_DIM)
            elif status in (5, 6):
                spd = _human_speed(t["rateUpload"])
                d.text((95, y + 9), f"{spd}", font=FONT_SM, fill=C_DIM)

    d.rectangle((0, 117, 127, 127), fill="#0a0a1a")
    d.text((2, 118), "K1:Add K2:Del OK:Pause K3:Exit", font=FONT_SM, fill=C_DIM)

    _show(img)


def main():
    if not _start_daemon():
        GPIO.cleanup()
        return 1

    _draw_msg("Connected", "transmission-daemon")
    time.sleep(0.5)

    cursor = 0
    filt_idx = 0
    last_btn = 0
    last_refresh = 0
    torrents = []
    filtered = []

    while _running:
        now = time.time()

        if now - last_refresh > 2:
            last_refresh = now
            torrents = _get_torrents()
            filtered = _filter_torrents(torrents, FILTERS[filt_idx])
            if cursor >= len(filtered):
                cursor = max(0, len(filtered) - 1)

        total_dl = sum(t.get("rateDownload", 0) for t in torrents)
        total_ul = sum(t.get("rateUpload", 0) for t in torrents)
        _draw_ui(filtered, cursor, filt_idx, total_dl, total_ul)

        btn = get_button(PINS, GPIO)

        if btn == "KEY3":
            break

        if btn == "UP" and now - last_btn > DEBOUNCE:
            last_btn = now
            if filtered:
                cursor = (cursor - 1) % len(filtered)

        if btn == "DOWN" and now - last_btn > DEBOUNCE:
            last_btn = now
            if filtered:
                cursor = (cursor + 1) % len(filtered)

        if btn == "LEFT" and now - last_btn > DEBOUNCE:
            last_btn = now
            filt_idx = (filt_idx - 1) % len(FILTERS)
            last_refresh = 0

        if btn == "RIGHT" and now - last_btn > DEBOUNCE:
            last_btn = now
            filt_idx = (filt_idx + 1) % len(FILTERS)
            last_refresh = 0

        if btn == "OK" and now - last_btn > 0.3 and filtered:
            last_btn = now
            t = filtered[cursor]
            if t["status"] == 0:
                _resume_torrent(t["id"])
                _draw_msg("Resumed", t["name"][:20], C_GREEN)
            else:
                _pause_torrent(t["id"])
                _draw_msg("Paused", t["name"][:20], C_ORANGE)
            time.sleep(0.5)
            last_refresh = 0

        if btn == "KEY1" and now - last_btn > 0.3:
            last_btn = now
            magnet = lcd_keyboard(LCD, FONT_SM, PINS, GPIO, title="Magnet/URL", charset="url")
            if magnet:
                _draw_msg("Adding...", magnet[:20])
                resp = _add_magnet(magnet)
                if resp and resp.get("result") == "success":
                    _draw_msg("Added!", "", C_GREEN)
                else:
                    _draw_msg("Failed", str(resp), C_RED)
                time.sleep(1)
                last_refresh = 0

        if btn == "KEY2" and now - last_btn > 0.3 and filtered:
            last_btn = now
            t = filtered[cursor]
            _draw_msg("Delete torrent?", "OK:Yes+Data K1:Yes K3:No", C_RED)
            while _running:
                b2 = get_button(PINS, GPIO)
                if b2 == "KEY3":
                    break
                if b2 == "OK":
                    _remove_torrent(t["id"], delete_data=True)
                    _draw_msg("Deleted", "with data", C_RED)
                    time.sleep(1)
                    last_refresh = 0
                    break
                if b2 == "KEY1":
                    _remove_torrent(t["id"], delete_data=False)
                    _draw_msg("Removed", "data kept", C_ORANGE)
                    time.sleep(1)
                    last_refresh = 0
                    break
                time.sleep(0.05)

        time.sleep(0.05)

    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
