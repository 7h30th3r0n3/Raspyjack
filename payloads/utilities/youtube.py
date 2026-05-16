#!/usr/bin/env python3
"""
RaspyJack Payload -- YouTube Player
=====================================
Search and stream YouTube videos on the CardputerZero LCD.
Video + audio synchronized via ffmpeg.

Controls:
  OK          Search / Play selected video
  UP/DOWN     Navigate results
  LEFT        Back to results
  KEY1        Pause/Resume during playback
  KEY3        Exit / Stop playback

Keyboard (TCA8418): Type search query directly
"""

import os
import sys
import time
import signal
import subprocess
import mmap
import threading
import json

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

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
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 16)
        font_sm = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 12)
        font_lg = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 22)
    except Exception:
        font = scaled_font(9)
        font_sm = scaled_font(7)
        font_lg = scaled_font(14)
else:
    font = scaled_font(9)
    font_sm = scaled_font(7)
    font_lg = font

FB_DEVICE = "/dev/fb1" if os.path.exists("/dev/fb1") else "/dev/fb0"
FB_SIZE = W * H * 2
TITLE_MAX = 35 if IS_WIDE else 20
CHAN_MAX = 18 if IS_WIDE else 12

C = {
    "bg": "#0a0a0a", "head": "#1a0000", "red": "#ff0000",
    "white": "#ffffff", "dim": "#555", "card": "#1a1a1a",
    "title": "#ff4444", "sub": "#aaaaaa", "sel": "#2a0a0a",
}

HISTORY_DIR = "/root/Raspyjack/loot/YouTube"
HISTORY_FILE = os.path.join(HISTORY_DIR, "history.json")
LIKED_FILE = os.path.join(HISTORY_DIR, "liked.json")
HISTORY_MAX = 20

_running = True
_audio_offset = [0.0]
_alsa_dev = "default"

STREAM_QUALITIES = [
    ("144p", "160+139/160/worst"),
    ("240p", "133+139/133/worst"),
    ("360p", "134+139/134/worst"),
    ("480p", "135+139/135/worst"),
    ("720p", "136+139/136/worst"),
]
_stream_quality_idx = 2

def _detect_alsa_dev():
    global _alsa_dev
    try:
        r = subprocess.run(["aplay", "-l"], capture_output=True, text=True, timeout=3)
        for line in r.stdout.split('\n'):
            if 'card' in line.lower() and ':' in line:
                card_num = line.split(':')[0].replace('card', '').strip()
                if any(k in line.upper() for k in ['ES8388', 'ES8389', 'ES8390']):
                    _alsa_dev = f"plughw:{card_num},0"
                    return
                elif 'HDMI' not in line.upper():
                    _alsa_dev = f"plughw:{card_num},0"
    except Exception:
        pass

_detect_alsa_dev()
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
    """Get a draw context — raw ImageDraw on wide, ScaledDraw on small."""
    if IS_WIDE:
        from PIL import ImageDraw
        return ImageDraw.Draw(img)
    return ScaledDraw(img)


def _show_msg(text, sub="", color=C["red"]):
    img = Image.new("RGB", (W, H), C["bg"])
    d = _draw(img)
    if IS_WIDE:
        d.text((60, 55), text, font=font_lg, fill=color)
        if sub:
            d.text((60, 85), sub, font=font, fill=C["sub"])
    else:
        d.text((20, 50), text, font=font, fill=color)
        if sub:
            d.text((20, 68), sub, font=font_sm, fill=C["sub"])
    LCD.LCD_ShowImage(img, 0, 0)


def _load_history():
    try:
        with open(HISTORY_FILE) as f:
            return json.load(f)[:HISTORY_MAX]
    except Exception:
        return []


def _save_history(query):
    history = _load_history()
    history = [q for q in history if q != query]
    history.insert(0, query)
    history = history[:HISTORY_MAX]
    try:
        os.makedirs(HISTORY_DIR, exist_ok=True)
        with open(HISTORY_FILE, "w") as f:
            json.dump(history, f)
    except Exception:
        pass


def _load_liked():
    try:
        with open(LIKED_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def _save_liked(liked):
    try:
        os.makedirs(HISTORY_DIR, exist_ok=True)
        with open(LIKED_FILE, "w") as f:
            json.dump(liked, f)
    except Exception:
        pass


def _like_video(video):
    liked = _load_liked()
    if any(v["id"] == video["id"] for v in liked):
        return
    liked.insert(0, video)
    _save_liked(liked)


def _play_audio(playlist, start_idx=0):
    """Audio-only player with dashboard. L=like, LEFT/RIGHT=skip, UP/DOWN=vol."""
    idx = start_idx
    while idx < len(playlist) and _running:
        v = playlist[idx]
        url = f"https://www.youtube.com/watch?v={v['id']}"
        _show_msg("Loading...", v["title"][:25], C["red"])

        try:
            r = subprocess.run(
                ["yt-dlp", "-f", "bestaudio", "--get-url", url],
                capture_output=True, text=True, timeout=30)
            audio_url = r.stdout.strip()
        except Exception:
            audio_url = ""

        if not audio_url:
            _show_msg("Error", "No audio", (255, 50, 50))
            time.sleep(1)
            idx += 1
            continue

        proc = subprocess.Popen(
            ["ffmpeg", "-hide_banner", "-loglevel", "quiet", "-re",
             "-i", audio_url, "-ac", "2", "-ar", "44100", "-f", "alsa", _alsa_dev],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        _vol = 40
        subprocess.Popen(["amixer", "-c", "0", "sset", "Headphone", str(_vol)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        start_time = time.time()
        duration = v.get("duration", 0)
        result = "next"
        liked_this = False

        while _running:
            btn = get_button(PINS, GPIO)
            now = time.time()
            elapsed = now - start_time

            if proc.poll() is not None:
                result = "next"
                break

            if btn == "KEY3":
                result = "stop"
                break
            elif btn == "RIGHT":
                result = "next"
                break
            elif btn == "LEFT":
                result = "prev"
                break
            elif btn == "UP":
                _vol = min(63, _vol + 5)
                subprocess.Popen(["amixer", "-c", "0", "sset", "Headphone", str(_vol)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(0.1)
            elif btn == "DOWN":
                _vol = max(0, _vol - 5)
                subprocess.Popen(["amixer", "-c", "0", "sset", "Headphone", str(_vol)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(0.1)

            # Check "L" key on TCA8418 (evdev code 38)
            if EVDEV_OK and evdev_keys.is_key_pressed(38) and not liked_this:
                liked_this = True
                _like_video(v)

            # "D" key to download as MP3 directly
            if EVDEV_OK and evdev_keys.is_key_pressed(32):
                proc.send_signal(signal.SIGSTOP)
                _show_msg("Downloading MP3...", v["title"][:20], C["red"])
                _download_video(v["id"], v["title"], "mp3", "320k", "320")
                proc.send_signal(signal.SIGCONT)
                time.sleep(0.3)

            # Draw dashboard
            img = Image.new("RGB", (W, H), C["bg"])
            d = _draw(img)

            if IS_WIDE:
                # Header
                d.rectangle((0, 0, W, 28), fill=C["head"])
                mode = "MUSIC" if not liked_this else "MUSIC  L"
                d.text((8, 4), mode, font=font_lg, fill=C["red"])
                d.text((200, 8), f"{idx+1}/{len(playlist)}", font=font_sm, fill=C["dim"])

                # Title + channel
                d.text((15, 42), v["title"][:30], font=font, fill=C["white"])
                d.text((15, 62), v.get("channel", "")[:25], font=font_sm, fill=C["sub"])

                # Controls
                ctrl_y = 85
                d.text((40, ctrl_y), "<<", font=font, fill=C["dim"])
                d.text((130, ctrl_y), "||", font=font_lg, fill=C["white"])
                d.text((240, ctrl_y), ">>", font=font, fill=C["dim"])

                # Progress bar
                bar_y = 115
                d.rectangle((15, bar_y, W - 15, bar_y + 6), fill="#222")
                if duration > 0:
                    prog = min(1.0, elapsed / duration)
                    px = int(15 + (W - 30) * prog)
                    d.rectangle((15, bar_y, px, bar_y + 6), fill=C["red"])

                # Time
                d.text((15, bar_y + 10), _format_dur(int(elapsed)), font=font_sm, fill=C["white"])
                if duration > 0:
                    d.text((W - 60, bar_y + 10), _format_dur(duration), font=font_sm, fill=C["dim"])

                # Volume
                d.text((W - 50, 42), f"Vol:{_vol}", font=font_sm, fill=C["dim"])

                # Liked indicator
                if liked_this:
                    d.text((W - 30, 65), "L", font=font, fill=C["red"])

                # Footer
                d.rectangle((0, H - 18, W, H), fill=C["head"])
                d.text((6, H - 16), "<>:Skip ^v:Vol L:Like K3:Stop", font=font_sm, fill=C["dim"])
            else:
                d.rectangle((0, 0, 127, 13), fill=C["head"])
                d.text((2, 2), "MUSIC", font=font, fill=C["red"])
                d.text((80, 2), f"{idx+1}/{len(playlist)}", font=font_sm, fill=C["dim"])
                d.text((4, 20), v["title"][:18], font=font_sm, fill=C["white"])
                d.text((4, 34), v.get("channel", "")[:16], font=font_sm, fill=C["dim"])
                d.rectangle((4, 55, 123, 59), fill="#222")
                if duration > 0:
                    prog = min(1.0, elapsed / duration)
                    d.rectangle((4, 55, 4 + int(119 * prog), 59), fill=C["red"])
                d.text((4, 64), _format_dur(int(elapsed)), font=font_sm, fill=C["white"])
                if duration > 0:
                    d.text((80, 64), _format_dur(duration), font=font_sm, fill=C["dim"])
                if liked_this:
                    d.text((110, 20), "L", font=font, fill=C["red"])
                d.rectangle((0, 117, 127, 127), fill=C["head"])
                d.text((2, 118), "<>:Skip ^v:Vol K3:X", font=font_sm, fill=C["dim"])

            LCD.LCD_ShowImage(img, 0, 0)
            time.sleep(0.15)

        proc.kill()
        subprocess.run(["pkill", "-9", "ffmpeg"], capture_output=True)
        time.sleep(0.2)

        if result == "stop":
            break
        elif result == "prev":
            idx = max(0, idx - 1)
        else:
            idx += 1

    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)


def _fetch_playlist(url, max_results=20):
    """Fetch videos from a YouTube playlist URL."""
    _show_msg("Loading...", "Playlist", C["red"])
    try:
        r = subprocess.run(
            ["yt-dlp", "--flat-playlist", "--no-download",
             "-j", url],
            capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            _show_msg("Playlist error", (r.stderr or "")[:20], (255, 50, 50))
            time.sleep(2)
            return []
        results = []
        for line in r.stdout.strip().split('\n'):
            if not line:
                continue
            try:
                data = json.loads(line)
                results.append({
                    "title": data.get("title", "?")[:40],
                    "id": data.get("id", ""),
                    "duration": int(data.get("duration") or 0),
                    "channel": data.get("channel", data.get("uploader", ""))[:20],
                })
            except Exception:
                continue
            if len(results) >= max_results:
                break
        if not results:
            _show_msg("Empty playlist", "", (255, 180, 0))
            time.sleep(2)
        return results
    except subprocess.TimeoutExpired:
        _show_msg("Timeout", "Playlist too long", (255, 50, 50))
        time.sleep(2)
        return []
    except Exception as e:
        _show_msg("Error", str(e)[:20], (255, 50, 50))
        time.sleep(2)
        return []


def _get_typed_char():
    """Get a character from TCA8418 keyboard."""
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


def _search_youtube(query, max_results=10):
    """Search YouTube via yt-dlp, return list of {title, id, duration, channel}."""
    try:
        r = subprocess.run(
            ["yt-dlp", "--flat-playlist", "--no-download",
             "-j", f"ytsearch{max_results}:{query}"],
            capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            err = r.stderr[:100] if r.stderr else "Unknown error"
            _show_msg("Search error", err[:20], (255, 50, 50))
            time.sleep(2)
            return []
        results = []
        for line in r.stdout.strip().split('\n'):
            if not line:
                continue
            try:
                data = json.loads(line)
                results.append({
                    "title": data.get("title", "?")[:40],
                    "id": data.get("id", ""),
                    "duration": int(data.get("duration") or 0),
                    "channel": data.get("channel", data.get("uploader", ""))[:20],
                })
            except Exception:
                continue
        if not results:
            _show_msg("No results", f'"{query[:15]}"', (255, 180, 0))
            time.sleep(2)
        return results
    except subprocess.TimeoutExpired:
        _show_msg("Timeout", "Search took too long", (255, 50, 50))
        time.sleep(2)
        return []
    except Exception as e:
        _show_msg("Error", str(e)[:20], (255, 50, 50))
        time.sleep(2)
        return []


# On-screen keyboard for 128/240 displays (no physical keyboard)
_KB_ROWS = [
    "abcdefghij",
    "klmnopqrst",
    "uvwxyz0123",
    "456789 .<-",
]
_KB_SPECIAL = {"<-": '\b', " ": ' ', ".": '.'}


def _draw_osk(d, query, kb_row, kb_col):
    """Draw on-screen keyboard for small displays."""
    d.rectangle((0, 0, 127, 13), fill=C["head"])
    d.text((2, 2), "YouTube", font=font, fill=C["red"])

    # Query field
    d.rectangle((2, 16, 125, 26), fill=C["card"])
    cur_text = query[-16:] if len(query) > 16 else query
    d.text((4, 17), f"{cur_text}_", font=font_sm, fill=C["white"])

    # Keyboard grid
    y = 30
    cell_w = 12
    for r, row in enumerate(_KB_ROWS):
        x = 2
        for c_idx in range(0, len(row), 1):
            ch = row[c_idx]
            sel = r == kb_row and c_idx == kb_col
            if sel:
                d.rectangle((x, y, x + cell_w - 1, y + 12), fill="#440000")
            d.text((x + 2, y + 1), ch, font=font_sm,
                   fill=C["white"] if sel else C["dim"])
            x += cell_w
        y += 14

    # Special keys row
    actions = [("OK", "search"), ("DEL", "delete")]
    x = 2
    for label, _ in actions:
        sel_sp = kb_row == len(_KB_ROWS)
        d.text((x, y + 1), label, font=font_sm,
               fill=C["red"] if sel_sp else C["dim"])
        x += 30

    d.rectangle((0, 117, 127, 127), fill=C["head"])
    d.text((2, 118), "^v<>:Move OK:Select", font=font_sm, fill=C["dim"])


def _format_dur(sec):
    if sec <= 0:
        return "?"
    m, s = divmod(sec, 60)
    h, m = divmod(m, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


def _draw_search(d, query, cursor_blink):
    if IS_WIDE:
        d.rectangle((0, 0, W, 28), fill=C["head"])
        d.text((8, 4), "YouTube", font=font_lg, fill=C["red"])
        d.text((150, 8), "Search", font=font, fill=C["dim"])
        y = 38
        d.rectangle((6, y, W - 6, y + 24), fill=C["card"])
        cur = "|" if cursor_blink else ""
        d.text((10, y + 4), f"{query}{cur}", font=font, fill=C["white"])
        y += 32
        d.text((10, y), "Type to search, OK to submit", font=font_sm, fill=C["dim"])
        y += 16
        d.text((10, y), "K3:Back to menu", font=font_sm, fill=C["dim"])
        d.rectangle((0, H - 22, W, H), fill=C["head"])
        d.text((6, H - 18), "OK:Search  K3:Back", font=font_sm, fill=C["dim"])
    else:
        d.rectangle((0, 0, 127, 13), fill=C["head"])
        d.text((2, 2), "YouTube", font=font, fill=C["red"])
        d.text((60, 2), "Search", font=font_sm, fill=C["dim"])
        y = 20
        d.rectangle((2, y, 125, y + 14), fill=C["card"])
        cur = "|" if cursor_blink else ""
        d.text((4, y + 2), f"{query}{cur}", font=font_sm, fill=C["white"])
        y += 18
        d.text((4, y), "Type to search", font=font_sm, fill=C["dim"])
        d.rectangle((0, 117, 127, 127), fill=C["head"])
        d.text((2, 118), "OK:Search K3:Back", font=font_sm, fill=C["dim"])


def _draw_results(d, results, cursor, scroll, query):
    if IS_WIDE:
        ITEM_H = 28
        HDR_H = 28
        FTR_H = 22
        vis = (H - HDR_H - FTR_H) // ITEM_H
        d.rectangle((0, 0, W, HDR_H), fill=C["head"])
        d.text((8, 4), "Results", font=font_lg, fill=C["red"])
        d.text((130, 8), f"{len(results)}", font=font, fill=C["white"])
        d.text((160, 8), query[:12], font=font_sm, fill=C["dim"])
        y = HDR_H + 2
    else:
        ITEM_H = 18
        HDR_H = 16
        FTR_H = 11
        vis = (117 - 16) // ITEM_H
        d.rectangle((0, 0, 127, 13), fill=C["head"])
        d.text((2, 2), "Results", font=font, fill=C["red"])
        d.text((55, 2), f"{len(results)}", font=font_sm, fill=C["white"])
        d.text((68, 2), query[:8], font=font_sm, fill=C["dim"])
        y = HDR_H

    total_items = len(results) + 1  # +1 for "Load more"
    st = max(0, min(scroll, max(0, total_items - vis)))

    if not results:
        d.text((10, 50), "No results", font=font_sm, fill=C["dim"])
    else:
        for i in range(st, min(st + vis, total_items)):
            if i < len(results):
                r = results[i]
                sel = i == cursor
                if IS_WIDE:
                    if sel:
                        d.rectangle((0, y, W, y + ITEM_H - 2), fill=C["sel"])
                    d.text((8, y + 2), r["title"][:TITLE_MAX], font=font,
                           fill=C["white"] if sel else C["sub"])
                    dur = _format_dur(r["duration"])
                    d.text((8, y + 16), r["channel"][:CHAN_MAX], font=font_sm, fill=C["dim"])
                    d.text((220, y + 16), dur, font=font_sm, fill=C["dim"])
                else:
                    if sel:
                        d.rectangle((0, y, 127, y + ITEM_H - 2), fill=C["sel"])
                    d.text((3, y + 1), r["title"][:TITLE_MAX], font=font_sm,
                           fill=C["white"] if sel else C["sub"])
                    dur = _format_dur(r["duration"])
                    d.text((3, y + 9), r["channel"][:CHAN_MAX], font=font_sm, fill=C["dim"])
                    d.text((85, y + 9), dur, font=font_sm, fill=C["dim"])
            else:
                sel = i == cursor
                if IS_WIDE:
                    if sel:
                        d.rectangle((0, y, W, y + ITEM_H - 2), fill=C["sel"])
                    d.text((8, y + 6), "Load more...", font=font, fill=C["red"] if sel else C["dim"])
                else:
                    if sel:
                        d.rectangle((0, y, 127, y + ITEM_H - 2), fill=C["sel"])
                    d.text((3, y + 3), "Load more...", font=font_sm, fill=C["red"] if sel else C["dim"])
            y += ITEM_H

    if IS_WIDE:
        d.rectangle((0, H - FTR_H, W, H), fill=C["head"])
        d.text((6, H - 18), "OK:Play(auto-next) L:Back K3:X", font=font_sm, fill=C["dim"])
    else:
        d.rectangle((0, 117, 127, 127), fill=C["head"])
        d.text((2, 118), "OK:Play L:Back K3:X", font=font_sm, fill=C["dim"])


def _draw_playing(d, title, elapsed):
    d.rectangle((0, 0, 127, 13), fill=C["head"])
    d.text((2, 2), "Playing", font=font_sm, fill=C["red"])
    d.text((50, 2), title[:12], font=font_sm, fill=C["white"])
    d.text((2, H - 10), f"{_format_dur(int(elapsed))}", font=font_sm, fill=C["dim"])


def _read_frame(proc):
    raw = b""
    while len(raw) < FB_SIZE:
        chunk = proc.stdout.read(FB_SIZE - len(raw))
        if not chunk:
            return None
        raw += chunk
    return raw


def _apply_osd(raw, title, elapsed, duration=0):
    """Apply OSD overlay directly on RGB565 buffer. CardputerZero only."""
    if not IS_WIDE:
        return raw
    import numpy as np
    arr = np.frombuffer(raw, dtype=np.uint16).reshape(H, W).copy()
    osd_h = 16
    arr[H - osd_h:, :] = arr[H - osd_h:, :] >> 2
    # White text via pixel drawing is too slow — just darken the bar
    # The title/time info is visible enough from the darkened video
    # Progress bar
    if duration > 0:
        prog = min(1.0, elapsed / duration)
        px = int(W * prog)
        arr[H - 2:, :px] = 0x07FF  # cyan
    return arr.tobytes()


def _play_playlist(playlist, start_idx=0):
    """Play all videos in sequence. LEFT/RIGHT to skip. KEY3 to stop."""
    idx = start_idx
    offset = 0
    while idx < len(playlist) and _running:
        v = playlist[idx]
        _show_msg(f"[{idx+1}/{len(playlist)}]", v["title"][:25], C["red"])
        time.sleep(0.5)
        result = _play_video(v["id"], v["title"], playlist_mode=True, start_offset=offset)
        offset = 0
        if isinstance(result, tuple) and result[0] == "restart":
            offset = result[1]
            continue
        elif result == "next":
            idx += 1
        elif result == "prev":
            idx = max(0, idx - 1)
        elif result == "stop":
            break
        else:
            idx += 1


def _show_stream_settings():
    """Show stream quality settings menu. Press S during playback."""
    global _stream_quality_idx
    sel = _stream_quality_idx
    last_btn = 0

    while _running:
        img = Image.new("RGB", (W, H), C["bg"])
        d = _draw(img)
        if IS_WIDE:
            d.rectangle((0, 0, W, 28), fill=C["head"])
            d.text((W // 2, 14), "STREAM QUALITY", font=font_lg, fill=C["red"], anchor="mm")
            for i, (label, _) in enumerate(STREAM_QUALITIES):
                y = 38 + i * 24
                if i == sel:
                    d.rectangle([30, y, W - 30, y + 22], fill=C["sel"])
                mark = " *" if i == _stream_quality_idx else ""
                d.text((W // 2, y + 11), f"{label}{mark}", font=font,
                       fill=C["white"] if i == sel else C["dim"], anchor="mm")
            d.text((W // 2, H - 14), "UP/DN:Select OK:Apply KEY3:Back",
                   font=font_sm, fill=C["dim"], anchor="mm")
        else:
            d.rectangle((0, 0, 128, 14), fill=C["head"])
            d.text((4, 1), "QUALITY", font=font, fill=C["red"])
            for i, (label, _) in enumerate(STREAM_QUALITIES):
                y = 18 + i * 18
                if i == sel:
                    d.rectangle([2, y, 126, y + 16], fill=C["sel"])
                mark = "*" if i == _stream_quality_idx else ""
                d.text((4, y + 2), f"{label} {mark}", font=font,
                       fill=C["white"] if i == sel else C["dim"])
            d.text((4, 112), "OK:Apply K3:Back", font=font_sm, fill=C["dim"])
        LCD.LCD_ShowImage(img, 0, 0)

        btn = get_button(PINS, GPIO)
        now = time.time()
        if btn == "KEY3" and now - last_btn > 0.2:
            return
        if btn == "UP" and now - last_btn > 0.2:
            last_btn = now
            sel = (sel - 1) % len(STREAM_QUALITIES)
        if btn == "DOWN" and now - last_btn > 0.2:
            last_btn = now
            sel = (sel + 1) % len(STREAM_QUALITIES)
        if btn == "OK" and now - last_btn > 0.2:
            _stream_quality_idx = sel
            _show_msg("Quality set!", STREAM_QUALITIES[sel][0], C["white"])
            time.sleep(0.5)
            return
        time.sleep(0.08)


def _play_video(video_id, title, playlist_mode=False, start_offset=0):
    url = f"https://www.youtube.com/watch?v={video_id}"
    quality_label, quality_fmt = STREAM_QUALITIES[_stream_quality_idx]

    # Re-init LCD to ensure clean SPI state
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)

    # Show loading with hints
    img = Image.new("RGB", (W, H), C["bg"])
    d = _draw(img)
    if IS_WIDE:
        d.rectangle((0, 0, W, 28), fill=C["head"])
        d.text((W // 2, 14), "Loading...", font=font_lg, fill=C["red"], anchor="mm")
        d.text((W // 2, 50), title[:30], font=font_sm, fill=C["dim"], anchor="mm")
        d.text((W // 2, 75), f"Quality: {quality_label}", font=font_sm, fill=C["sub"], anchor="mm")
        d.text((W // 2, H - 40), "D: Download  S: Settings  L: Like", font=font_sm, fill=C["dim"], anchor="mm")
        d.text((W // 2, H - 22), "KEY1: Pause  KEY3: Stop", font=font_sm, fill=C["dim"], anchor="mm")
    else:
        d.rectangle((0, 0, 128, 14), fill=C["head"])
        d.text((4, 1), "Loading...", font=font, fill=C["red"])
        d.text((4, 20), title[:16], font=font_sm, fill=C["dim"])
        d.text((4, 38), f"Quality: {quality_label}", font=font_sm, fill=C["sub"])
        d.text((4, 60), "D:DL S:Set L:Like", font=font_sm, fill=C["dim"])
        d.text((4, 76), "K1:Pause K3:Stop", font=font_sm, fill=C["dim"])
    LCD.LCD_ShowImage(img, 0, 0)

    try:
        r = subprocess.run(
            ["yt-dlp", "-f", quality_fmt, "--get-url", url],
            capture_output=True, text=True, timeout=30)
        urls = r.stdout.strip().split('\n')
        video_url = urls[0] if urls else ""
        audio_url = urls[1] if len(urls) > 1 else ""
    except subprocess.TimeoutExpired:
        _show_msg("Timeout", "Server too slow", (255, 50, 50))
        time.sleep(2)
        return "next" if playlist_mode else None
    except Exception as e:
        _show_msg("yt-dlp error", str(e)[:20], (255, 50, 50))
        time.sleep(2)
        return "next" if playlist_mode else None

    if not video_url:
        err = r.stderr[:40] if r.stderr else "No URL returned"
        _show_msg("Stream error", err[:20], (255, 50, 50))
        time.sleep(2)
        return "next" if playlist_mode else None

    # Find the right ALSA audio device (prefer ES8388/ES8389, skip HDMI)
    has_audio = False
    alsa_dev = "default"
    try:
        r = subprocess.run(["aplay", "-l"], capture_output=True, text=True, timeout=3)
        for line in r.stdout.split('\n'):
            if 'card' in line.lower() and ':' in line:
                card_num = line.split(':')[0].replace('card', '').strip()
                if any(k in line.upper() for k in ['ES8388', 'ES8389', 'ES8390']):
                    alsa_dev = f"plughw:{card_num},0"
                    has_audio = True
                    break
                elif 'HDMI' not in line.upper() and 'hdmi' not in line:
                    alsa_dev = f"plughw:{card_num},0"
                    has_audio = True
        if not has_audio and "card" in r.stdout.lower():
            has_audio = True
    except Exception:
        pass

    target_fps = 8 if not IS_WIDE else 24
    cmd = ["ffmpeg", "-hide_banner", "-loglevel", "quiet", "-re"]
    if start_offset > 0:
        cmd += ["-ss", str(int(start_offset))]
    cmd += ["-i", video_url]
    if audio_url and has_audio:
        cmd += ["-i", audio_url]
    cmd += ["-map", "0:v:0",
            "-vf", f"scale={W}:{H}:force_original_aspect_ratio=decrease,pad={W}:{H}:(ow-iw)/2:(oh-ih)/2,fps={target_fps}",
            "-pix_fmt", "rgb565le", "-f", "rawvideo", "pipe:1"]
    if audio_url and has_audio:
        cmd += ["-map", "1:a:0", "-af", "aresample=async=1", "-ac", "2", "-ar", "44100", "-f", "alsa", alsa_dev]

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=FB_SIZE * 16)

    # Increase kernel pipe buffer to avoid stalls on slow SPI displays
    try:
        import fcntl
        F_SETPIPE_SZ = 1031
        fcntl.fcntl(proc.stdout, F_SETPIPE_SZ, FB_SIZE * 32)
    except Exception:
        pass

    # Wait a moment for ffmpeg to start
    time.sleep(0.5)
    if proc.poll() is not None:
        err = proc.stderr.read(200).decode(errors="replace") if proc.stderr else ""
        _show_msg("ffmpeg error", err[:20], (255, 50, 50))
        time.sleep(2)
        return "next" if playlist_mode else None

    use_fb = IS_WIDE
    fb_fd = None
    fb_map = None
    if use_fb:
        try:
            fb_fd = os.open(FB_DEVICE, os.O_RDWR)
            fb_map = mmap.mmap(fb_fd, FB_SIZE, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)
        except Exception:
            use_fb = False

    start_time = time.time() - start_offset
    paused = False
    pause_offset = 0
    _vol = 40
    _result = "done"

    def _set_vol(v):
        nonlocal _vol
        _vol = max(0, min(63, v))
        subprocess.Popen(["amixer", "-c", "0", "sset", "Headphone", str(_vol)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    _set_vol(_vol)

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                _result = "stop"
                break
            elif btn == "RIGHT" and playlist_mode:
                _result = "next"
                break
            elif btn == "LEFT" and playlist_mode:
                _result = "prev"
                break
            elif btn == "LEFT" and not playlist_mode:
                break
            elif btn == "UP":
                _set_vol(_vol + 5)
                time.sleep(0.1)
            elif btn == "DOWN":
                _set_vol(_vol - 5)
                time.sleep(0.1)
            elif btn == "KEY1" or btn == "OK":
                paused = not paused
                if paused:
                    pause_offset = time.time() - start_time
                    proc.send_signal(signal.SIGSTOP)
                    img = Image.new("RGB", (W, H), C["bg"])
                    d = _draw(img)
                    if IS_WIDE:
                        d.text((50, 60), "PAUSED", font=font_lg, fill=C["red"])
                        d.text((20, 85), title[:30], font=font, fill=C["dim"])
                    else:
                        d.text((30, 50), "PAUSED", font=font, fill=C["red"])
                        d.text((10, 70), title[:18], font=font_sm, fill=C["dim"])
                    LCD.LCD_ShowImage(img, 0, 0)
                else:
                    proc.send_signal(signal.SIGCONT)
                time.sleep(0.3)
                continue

            # "L" key to like during video playback
            if EVDEV_OK and evdev_keys.is_key_pressed(38):
                _like_video({"id": video_id, "title": title,
                             "channel": "", "duration": 0})
                _show_msg("Liked!", title[:20], C["red"])
                time.sleep(0.5)

            # "D" key to download during playback
            if EVDEV_OK and evdev_keys.is_key_pressed(32):
                proc.send_signal(signal.SIGSTOP)
                _show_download_menu(video_id, title)
                proc.send_signal(signal.SIGCONT)
                time.sleep(0.3)

            # "S" key to change stream quality - restart video at current position
            if EVDEV_OK and evdev_keys.is_key_pressed(31):
                proc.send_signal(signal.SIGSTOP)
                old_quality = _stream_quality_idx
                _show_stream_settings()
                if _stream_quality_idx != old_quality:
                    proc.kill()
                    proc.wait()
                    if use_fb and fb_map:
                        fb_map.close()
                        fb_map = None
                    if fb_fd is not None:
                        os.close(fb_fd)
                        fb_fd = None
                    return ("restart", 0)
                proc.send_signal(signal.SIGCONT)
                time.sleep(0.3)

            if paused:
                time.sleep(0.05)
                continue

            raw = _read_frame(proc)
            if raw is None:
                if proc.poll() is not None and proc.returncode != 0:
                    _show_msg("Stream ended", "Connection lost?", (255, 180, 0))
                else:
                    _show_msg("Video ended", title[:20], C["white"])
                time.sleep(2)
                break

            if use_fb:
                fb_map.seek(0)
                fb_map.write(raw)
            else:
                import numpy as np
                arr = np.frombuffer(raw, dtype='<u2').reshape(H, W)
                r = ((arr >> 11) & 0x1F) << 3
                g = ((arr >> 5) & 0x3F) << 2
                b = (arr & 0x1F) << 3
                rgb = np.stack([r.astype(np.uint8), g.astype(np.uint8), b.astype(np.uint8)], axis=-1)
                frame = Image.fromarray(rgb, "RGB")
                LCD.LCD_ShowImage(frame, 0, 0)

    finally:
        try:
            proc.kill()
            proc.wait(timeout=2)
        except Exception:
            pass
        try:
            if fb_map:
                fb_map.close()
        except Exception:
            pass
        try:
            if fb_fd is not None:
                os.close(fb_fd)
        except Exception:
            pass
        subprocess.run(["pkill", "-9", "ffmpeg"], capture_output=True)
        time.sleep(0.3)
        LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
        if not playlist_mode:
            _show_msg("YouTube", "Ready", C["red"])
    return _result


def _check_internet():
    """Check internet connectivity."""
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", "2", "8.8.8.8"],
                           capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def _check_deps():
    """Check and install missing dependencies. Returns True if all OK."""
    missing_apt = []
    missing_pip = []

    if not os.path.isfile("/usr/bin/ffmpeg"):
        missing_apt.append("ffmpeg")

    yt_ok = False
    try:
        r = subprocess.run(["yt-dlp", "--version"], capture_output=True, timeout=5)
        yt_ok = r.returncode == 0
    except Exception:
        pass
    if not yt_ok:
        missing_apt.append("yt-dlp")

    if missing_apt:
        _show_msg("Installing...", " ".join(missing_apt), C["red"])
        subprocess.run(["apt-get", "install", "-y"] + missing_apt,
                       capture_output=True, timeout=120)

    # Always try to upgrade yt-dlp (YouTube breaks old versions)
    if yt_ok:
        try:
            r = subprocess.run(["yt-dlp", "--version"], capture_output=True, text=True, timeout=5)
            ver = r.stdout.strip()
            # If older than 2026, upgrade
            if ver < "2026":
                _show_msg("Updating...", "yt-dlp", C["red"])
                subprocess.run(
                    ["pip3", "install", "--upgrade", "yt-dlp",
                     "--break-system-packages", "--ignore-installed", "yt-dlp"],
                    capture_output=True, timeout=120)
        except Exception:
            pass

    # Final check
    has_ffmpeg = os.path.isfile("/usr/bin/ffmpeg")
    has_ytdlp = False
    try:
        r = subprocess.run(["yt-dlp", "--version"], capture_output=True, timeout=5)
        has_ytdlp = r.returncode == 0
    except Exception:
        pass

    return has_ffmpeg and has_ytdlp


DOWNLOAD_DIR = "/root/Raspyjack/loot/YouTube/Downloads"

MP4_QUALITIES = [
    ("Best", "bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]"),
    ("720p", "bestvideo[height<=720][ext=mp4]+bestaudio[ext=m4a]/best[height<=720]"),
    ("480p", "bestvideo[height<=480][ext=mp4]+bestaudio[ext=m4a]/best[height<=480]"),
    ("360p", "bestvideo[height<=360][ext=mp4]+bestaudio[ext=m4a]/best[height<=360]"),
]

MP3_QUALITIES = [
    ("320k", "320"),
    ("192k", "192"),
    ("128k", "128"),
    ("64k", "64"),
]


def _download_video(video_id, title, fmt, quality_label, quality_val):
    """Download video/audio with progress display."""
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    safe_title = "".join(c for c in title if c.isalnum() or c in " -_")[:40].strip()
    url = f"https://www.youtube.com/watch?v={video_id}"

    if fmt == "mp4":
        ext = "mp4"
        cmd = ["yt-dlp", "-f", quality_val,
               "--merge-output-format", "mp4",
               "-o", os.path.join(DOWNLOAD_DIR, f"{safe_title}.%(ext)s"),
               "--no-playlist", url]
    else:
        ext = "mp3"
        cmd = ["yt-dlp", "-x", "--audio-format", "mp3",
               "--audio-quality", quality_val,
               "-o", os.path.join(DOWNLOAD_DIR, f"{safe_title}.%(ext)s"),
               "--no-playlist", url]

    _show_msg("Downloading...", f"{quality_label} {ext.upper()}", C["red"])

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1)

    step = 1
    last_pct = -1
    while proc.poll() is None:
        line = proc.stdout.readline()
        if not line:
            continue
        if "[download]" in line and "100%" in line:
            step += 1
        if "Merging" in line or "Post-process" in line:
            _show_msg("Merging...", safe_title[:20], C["white"])
            continue
        if "%" in line and "ETA" in line:
            try:
                pct_str = line.split("%")[0].strip().split()[-1]
                pct = float(pct_str)
                if pct == last_pct:
                    continue
                last_pct = pct
                step_label = "Video" if step == 1 and fmt == "mp4" else "Audio" if step == 2 else ""
                img = Image.new("RGB", (W, H), C["bg"])
                d = _draw(img)
                if IS_WIDE:
                    d.text((W // 2, 25), f"Downloading {ext.upper()} {quality_label}",
                           font=font_sm, fill=C["white"], anchor="mm")
                    d.text((W // 2, 45), safe_title[:30], font=font_sm,
                           fill=C["dim"], anchor="mm")
                    if step_label:
                        d.text((W // 2, 65), step_label, font=font_sm,
                               fill=C["sub"], anchor="mm")
                    bar_x, bar_w = 20, W - 40
                    bar_y = 80
                    d.rectangle([bar_x, bar_y, bar_x + bar_w, bar_y + 14], fill="#1a1a1a")
                    fill_w = int(bar_w * pct / 100)
                    if fill_w > 0:
                        d.rectangle([bar_x, bar_y, bar_x + fill_w, bar_y + 14], fill=C["red"])
                    d.text((W // 2, 115), f"{pct:.0f}%", font=font,
                           fill=C["white"], anchor="mm")
                else:
                    d.text((4, 15), f"DL {ext} {quality_label}", font=font_sm, fill=C["white"])
                    d.text((4, 30), safe_title[:16], font=font_sm, fill=C["dim"])
                    if step_label:
                        d.text((4, 45), step_label, font=font_sm, fill=C["dim"])
                    d.rectangle([10, 60, 118, 72], fill="#1a1a1a")
                    fill_w = int(108 * pct / 100)
                    if fill_w > 0:
                        d.rectangle([10, 60, 10 + fill_w, 72], fill=C["red"])
                    d.text((50, 80), f"{pct:.0f}%", font=font, fill=C["white"])
                LCD.LCD_ShowImage(img, 0, 0)
            except Exception:
                pass

    proc.wait()
    if proc.returncode == 0:
        _show_msg("Downloaded!", f"{safe_title[:20]}.{ext}", C["white"])
    else:
        _show_msg("Download failed!", "Check connection", (255, 50, 50))
    time.sleep(1.5)


def _show_download_menu(video_id, title):
    """Show format (MP3/MP4) then quality selection menu."""
    fmt_sel = 0
    formats = ["MP4 Video", "MP3 Audio"]
    last_btn = 0

    while _running:
        img = Image.new("RGB", (W, H), C["bg"])
        d = _draw(img)
        if IS_WIDE:
            d.rectangle([0, 0, W, 26], fill=C["head"])
            d.text((W // 2, 13), "DOWNLOAD", font=font_lg, fill=C["red"], anchor="mm")
            d.text((W // 2, 45), title[:30], font=font_sm, fill=C["dim"], anchor="mm")
            for i, f in enumerate(formats):
                y = 70 + i * 30
                if i == fmt_sel:
                    d.rectangle([40, y, W - 40, y + 26], fill=C["sel"])
                d.text((W // 2, y + 13), f, font=font,
                       fill=C["white"] if i == fmt_sel else C["dim"], anchor="mm")
            d.text((W // 2, H - 12), "UP/DN:Select OK:Choose KEY3:Back",
                   font=font_sm, fill=C["dim"], anchor="mm")
        else:
            d.rectangle([0, 0, 128, 16], fill=C["head"])
            d.text((4, 1), "DOWNLOAD", font=font, fill=C["red"])
            for i, f in enumerate(formats):
                y = 40 + i * 25
                if i == fmt_sel:
                    d.rectangle([4, y, 124, y + 22], fill=C["sel"])
                d.text((4, y + 4), f, font=font,
                       fill=C["white"] if i == fmt_sel else C["dim"])
            d.text((4, 110), "OK:Choose K3:Back", font=font_sm, fill=C["dim"])
        LCD.LCD_ShowImage(img, 0, 0)

        btn = get_button(PINS, GPIO)
        now = time.time()
        if btn == "KEY3" and now - last_btn > 0.2:
            return
        if btn == "UP" and now - last_btn > 0.2:
            last_btn = now
            fmt_sel = (fmt_sel - 1) % len(formats)
        if btn == "DOWN" and now - last_btn > 0.2:
            last_btn = now
            fmt_sel = (fmt_sel + 1) % len(formats)
        if btn == "OK" and now - last_btn > 0.2:
            last_btn = now
            fmt = "mp4" if fmt_sel == 0 else "mp3"
            qualities = MP4_QUALITIES if fmt == "mp4" else MP3_QUALITIES
            quality = _show_quality_menu(fmt, qualities)
            if quality:
                _download_video(video_id, title, fmt, quality[0], quality[1])
            return
        time.sleep(0.08)


def _show_quality_menu(fmt, qualities):
    """Show quality selection. Returns (label, value) or None."""
    sel = 0
    last_btn = 0

    while _running:
        img = Image.new("RGB", (W, H), C["bg"])
        d = _draw(img)
        if IS_WIDE:
            d.rectangle([0, 0, W, 26], fill=C["head"])
            d.text((W // 2, 13), f"{fmt.upper()} QUALITY", font=font_lg,
                   fill=C["red"], anchor="mm")
            for i, (label, _) in enumerate(qualities):
                y = 40 + i * 28
                if i == sel:
                    d.rectangle([40, y, W - 40, y + 24], fill=C["sel"])
                d.text((W // 2, y + 12), label, font=font,
                       fill=C["white"] if i == sel else C["dim"], anchor="mm")
            d.text((W // 2, H - 12), "UP/DN:Select OK:Download KEY3:Back",
                   font=font_sm, fill=C["dim"], anchor="mm")
        else:
            d.rectangle([0, 0, 128, 16], fill=C["head"])
            d.text((4, 1), f"{fmt.upper()} QUALITY", font=font, fill=C["red"])
            for i, (label, _) in enumerate(qualities):
                y = 24 + i * 22
                if i == sel:
                    d.rectangle([4, y, 124, y + 20], fill=C["sel"])
                d.text((4, y + 3), label, font=font,
                       fill=C["white"] if i == sel else C["dim"])
            d.text((4, 112), "OK:DL K3:Back", font=font_sm, fill=C["dim"])
        LCD.LCD_ShowImage(img, 0, 0)

        btn = get_button(PINS, GPIO)
        now = time.time()
        if btn == "KEY3" and now - last_btn > 0.2:
            return None
        if btn == "UP" and now - last_btn > 0.2:
            last_btn = now
            sel = (sel - 1) % len(qualities)
        if btn == "DOWN" and now - last_btn > 0.2:
            last_btn = now
            sel = (sel + 1) % len(qualities)
        if btn == "OK" and now - last_btn > 0.2:
            return qualities[sel]
        time.sleep(0.08)


def main():
    _show_msg("YouTube", "Checking...", C["red"])

    if not _check_internet():
        _show_msg("No Internet", "Connect WiFi/Ethernet", (255, 50, 50))
        time.sleep(3)
        GPIO.cleanup()
        return 1

    if not _check_deps():
        _show_msg("Missing deps", "ffmpeg / yt-dlp", (255, 50, 50))
        time.sleep(3)
        GPIO.cleanup()
        return 1

    _show_msg("YouTube", "Ready!", C["red"])
    time.sleep(0.5)

    query = ""
    results = []
    cursor = 0
    scroll = 0
    state = "menu"  # menu → search/history/trending → results
    last_press = 0.0
    last_char_time = 0.0
    kb_row, kb_col = 0, 0
    history = _load_history()
    menu_sel = 0
    hist_sel = 0

    DEFAULT_PRESETS = [
        "talking sasquatch",
        "sn0ren",
        "Valleytechsolutions",
        "hacking tutorial 2026",
        "cybersecurity news",
        "CTF writeup",
        "bug bounty",
        "pentest red team",
    ]
    PRESETS_FILE = os.path.join(HISTORY_DIR, "presets.json")

    def _load_presets():
        try:
            with open(PRESETS_FILE) as f:
                return json.load(f)
        except Exception:
            return list(DEFAULT_PRESETS)

    def _save_presets(presets):
        try:
            os.makedirs(HISTORY_DIR, exist_ok=True)
            with open(PRESETS_FILE, "w") as f:
                json.dump(presets, f)
        except Exception:
            pass

    presets = _load_presets()
    MENU_ITEMS = ["Search", "Quick Search", "Music", "Liked", "History"]

    def _do_search(q):
        nonlocal results, cursor, scroll, state
        _save_history(q)
        _show_msg("Searching...", q[:20], C["red"])
        results = _search_youtube(q)
        cursor = 0
        scroll = 0
        state = "results"

    try:
        while _running:
            btn = get_button(PINS, GPIO)
            now = time.time()
            typed = _get_typed_char() if EVDEV_OK else None

            if btn == "KEY3":
                if state == "menu":
                    break
                elif state == "preset_add":
                    state = "presets"
                elif state == "music_results":
                    state = "music_search"
                else:
                    state = "menu"
                continue

            if state == "menu":
                if btn and now - last_press > 0.2:
                    last_press = now
                    if btn == "UP":
                        menu_sel = (menu_sel - 1) % len(MENU_ITEMS)
                    elif btn == "DOWN":
                        menu_sel = (menu_sel + 1) % len(MENU_ITEMS)
                    elif btn == "OK":
                        if menu_sel == 0:
                            query = ""
                            state = "search"
                        elif menu_sel == 1:
                            preset_sel = 0
                            state = "presets"
                        elif menu_sel == 2:
                            query = ""
                            state = "music_search"
                        elif menu_sel == 3:
                            liked = _load_liked()
                            cursor = 0
                            scroll = 0
                            state = "liked"
                        elif menu_sel == 4:
                            history = _load_history()
                            hist_sel = 0
                            state = "history"

                img = Image.new("RGB", (W, H), C["bg"])
                d = _draw(img)
                if IS_WIDE:
                    d.rectangle((0, 0, W, 28), fill=C["head"])
                    d.text((8, 4), "YouTube", font=font_lg, fill=C["red"])
                    y = 36
                    for i, item in enumerate(MENU_ITEMS):
                        sel = i == menu_sel
                        if sel:
                            d.rectangle((6, y, W - 6, y + 19), fill=C["sel"])
                        d.text((20, y + 2), item, font=font, fill=C["white"] if sel else C["sub"])
                        y += 21
                    d.rectangle((0, H - 22, W, H), fill=C["head"])
                    d.text((6, H - 18), "OK:Select  K3:Exit", font=font_sm, fill=C["dim"])
                else:
                    d.rectangle((0, 0, 127, 13), fill=C["head"])
                    d.text((2, 2), "YouTube", font=font, fill=C["red"])
                    y = 20
                    for i, item in enumerate(MENU_ITEMS):
                        sel = i == menu_sel
                        if sel:
                            d.rectangle((2, y, 125, y + 14), fill=C["sel"])
                        d.text((6, y + 2), item, font=font_sm, fill=C["white"] if sel else C["sub"])
                        y += 16
                    d.rectangle((0, 117, 127, 127), fill=C["head"])
                    d.text((2, 118), "OK:Select K3:Exit", font=font_sm, fill=C["dim"])
                LCD.LCD_ShowImage(img, 0, 0)

            elif state == "history":
                if btn and now - last_press > 0.2:
                    last_press = now
                    if btn == "UP":
                        if history:
                            hist_sel = (hist_sel - 1) % len(history)
                    elif btn == "DOWN":
                        if history:
                            hist_sel = (hist_sel + 1) % len(history)
                    elif btn == "OK" and history and hist_sel < len(history):
                        query = history[hist_sel]
                        _do_search(query)
                    elif btn == "LEFT":
                        state = "menu"

                img = Image.new("RGB", (W, H), C["bg"])
                d = _draw(img)
                if IS_WIDE:
                    ITEM_H = 22
                    HDR_H = 28
                    FTR_H = 22
                    vis = (H - HDR_H - FTR_H) // ITEM_H
                    d.rectangle((0, 0, W, HDR_H), fill=C["head"])
                    d.text((8, 4), "History", font=font_lg, fill=C["red"])
                    d.text((130, 8), f"{len(history)}", font=font, fill=C["white"])
                    y = HDR_H + 2
                    if not history:
                        d.text((20, 70), "No history yet", font=font, fill=C["dim"])
                    else:
                        hs = max(0, min(hist_sel - vis // 2, max(0, len(history) - vis)))
                        for i in range(hs, min(hs + vis, len(history))):
                            sel = i == hist_sel
                            if sel:
                                d.rectangle((6, y, W - 6, y + ITEM_H - 2), fill=C["sel"])
                            d.text((10, y + 3), history[i][:30], font=font,
                                   fill=C["white"] if sel else C["sub"])
                            y += ITEM_H
                    d.rectangle((0, H - FTR_H, W, H), fill=C["head"])
                    d.text((6, H - 18), "OK:Search  K3:Back", font=font_sm, fill=C["dim"])
                else:
                    ITEM_H = 14
                    HDR_H = 16
                    FTR_H = 11
                    vis = (117 - HDR_H) // ITEM_H
                    d.rectangle((0, 0, 127, 13), fill=C["head"])
                    d.text((2, 2), "History", font=font, fill=C["red"])
                    y = HDR_H
                    if not history:
                        d.text((4, 50), "No history", font=font_sm, fill=C["dim"])
                    else:
                        hs = max(0, min(hist_sel - vis // 2, max(0, len(history) - vis)))
                        for i in range(hs, min(hs + vis, len(history))):
                            sel = i == hist_sel
                            if sel:
                                d.rectangle((2, y, 125, y + ITEM_H - 2), fill=C["sel"])
                            d.text((4, y + 1), history[i][:18], font=font_sm,
                                   fill=C["white"] if sel else C["dim"])
                            y += ITEM_H
                    d.rectangle((0, 117, 127, 127), fill=C["head"])
                    d.text((2, 118), "OK:Go K3:Back", font=font_sm, fill=C["dim"])
                LCD.LCD_ShowImage(img, 0, 0)

            elif state == "presets":
                if btn and now - last_press > 0.2:
                    last_press = now
                    if btn == "UP":
                        if presets:
                            preset_sel = (preset_sel - 1) % len(presets)
                    elif btn == "DOWN":
                        if presets:
                            preset_sel = (preset_sel + 1) % len(presets)
                    elif btn == "OK" and presets and preset_sel < len(presets):
                        query = presets[preset_sel]
                        _do_search(query)
                    elif btn == "KEY1" and presets and preset_sel < len(presets):
                        presets.pop(preset_sel)
                        _save_presets(presets)
                        if preset_sel >= len(presets) and presets:
                            preset_sel = len(presets) - 1
                    elif btn == "KEY2":
                        query = ""
                        state = "preset_add"

                img = Image.new("RGB", (W, H), C["bg"])
                d = _draw(img)
                if IS_WIDE:
                    ITEM_H = 22
                    HDR_H = 28
                    FTR_H = 22
                    vis = (H - HDR_H - FTR_H) // ITEM_H
                    d.rectangle((0, 0, W, HDR_H), fill=C["head"])
                    d.text((8, 4), "Quick Search", font=font_lg, fill=C["red"])
                    d.text((200, 8), f"{len(presets)}", font=font_sm, fill=C["dim"])
                    y = HDR_H + 2
                    ps = max(0, min(preset_sel - vis // 2, max(0, len(presets) - vis)))
                    for i in range(ps, min(ps + vis, len(presets))):
                        sel = i == preset_sel
                        if sel:
                            d.rectangle((6, y, W - 6, y + ITEM_H - 2), fill=C["sel"])
                        d.text((12, y + 3), presets[i][:30], font=font,
                               fill=C["white"] if sel else C["sub"])
                        y += ITEM_H
                    if not presets:
                        d.text((20, 70), "No presets", font=font, fill=C["dim"])
                    d.rectangle((0, H - FTR_H, W, H), fill=C["head"])
                    d.text((6, H - 18), "OK:Go K1:Del K2:Add K3:Back", font=font_sm, fill=C["dim"])
                else:
                    ITEM_H = 14
                    HDR_H = 16
                    FTR_H = 11
                    vis = (117 - HDR_H) // ITEM_H
                    d.rectangle((0, 0, 127, 13), fill=C["head"])
                    d.text((2, 2), "Quick Search", font=font, fill=C["red"])
                    y = HDR_H
                    ps = max(0, min(preset_sel - vis // 2, max(0, len(presets) - vis)))
                    for i in range(ps, min(ps + vis, len(presets))):
                        sel = i == preset_sel
                        if sel:
                            d.rectangle((2, y, 125, y + ITEM_H - 2), fill=C["sel"])
                        d.text((4, y + 1), presets[i][:18], font=font_sm,
                               fill=C["white"] if sel else C["dim"])
                        y += ITEM_H
                    if not presets:
                        d.text((4, 50), "No presets", font=font_sm, fill=C["dim"])
                    d.rectangle((0, 117, 127, 127), fill=C["head"])
                    d.text((2, 118), "OK K1:Del K2:Add K3:X", font=font_sm, fill=C["dim"])
                LCD.LCD_ShowImage(img, 0, 0)

            elif state == "preset_add":
                if typed and now - last_char_time > 0.15:
                    last_char_time = now
                    if typed == '\b':
                        query = query[:-1]
                    elif typed == '\n' and query.strip():
                        if query.strip() not in presets:
                            presets.append(query.strip())
                            _save_presets(presets)
                        preset_sel = len(presets) - 1
                        state = "presets"
                    elif len(query) < 40:
                        query += typed

                if IS_WIDE and btn == "OK" and query.strip() and now - last_press > 0.2:
                    last_press = now
                    presets.append(query.strip())
                    _save_presets(presets)
                    preset_sel = len(presets) - 1
                    state = "presets"

                img = Image.new("RGB", (W, H), C["bg"])
                d = _draw(img)
                if IS_WIDE:
                    d.rectangle((0, 0, W, 28), fill=C["head"])
                    d.text((8, 4), "Add Preset", font=font_lg, fill=C["red"])
                    y = 42
                    d.rectangle((6, y, W - 6, y + 24), fill=C["card"])
                    blink = int(now * 2) % 2 == 0
                    cur = "|" if blink else ""
                    d.text((10, y + 4), f"{query}{cur}", font=font, fill=C["white"])
                    d.rectangle((0, H - 22, W, H), fill=C["head"])
                    d.text((6, H - 18), "OK:Save  K3:Cancel", font=font_sm, fill=C["dim"])
                else:
                    d.rectangle((0, 0, 127, 13), fill=C["head"])
                    d.text((2, 2), "Add Preset", font=font, fill=C["red"])
                    d.rectangle((2, 20, 125, 32), fill=C["card"])
                    blink = int(now * 2) % 2 == 0
                    cur = "|" if blink else ""
                    d.text((4, 22), f"{query}{cur}", font=font_sm, fill=C["white"])
                    d.rectangle((0, 117, 127, 127), fill=C["head"])
                    d.text((2, 118), "OK:Save K3:Cancel", font=font_sm, fill=C["dim"])
                LCD.LCD_ShowImage(img, 0, 0)

            elif state == "music_search":
                if typed and now - last_char_time > 0.15:
                    last_char_time = now
                    if typed == '\b':
                        query = query[:-1]
                    elif typed == '\n' and query.strip():
                        _save_history(query)
                        _show_msg("Searching...", query[:20], C["red"])
                        results = _search_youtube(query, max_results=15)
                        cursor = 0
                        scroll = 0
                        state = "music_results"
                    elif len(query) < 40:
                        query += typed

                if IS_WIDE and btn == "OK" and query.strip() and now - last_press > 0.2:
                    last_press = now
                    _save_history(query)
                    _show_msg("Searching...", query[:20], C["red"])
                    results = _search_youtube(query, max_results=15)
                    cursor = 0
                    scroll = 0
                    state = "music_results"

                img = Image.new("RGB", (W, H), C["bg"])
                d = _draw(img)
                if IS_WIDE:
                    d.rectangle((0, 0, W, 28), fill=C["head"])
                    d.text((8, 4), "Music", font=font_lg, fill=C["red"])
                    y = 38
                    d.rectangle((6, y, W - 6, y + 24), fill=C["card"])
                    blink = int(now * 2) % 2 == 0
                    cur = "|" if blink else ""
                    d.text((10, y + 4), f"{query}{cur}", font=font, fill=C["white"])
                    y += 32
                    d.text((10, y), "Audio only - search & play", font=font_sm, fill=C["dim"])
                    d.rectangle((0, H - 22, W, H), fill=C["head"])
                    d.text((6, H - 18), "OK:Play  K3:Back", font=font_sm, fill=C["dim"])
                else:
                    d.rectangle((0, 0, 127, 13), fill=C["head"])
                    d.text((2, 2), "Music", font=font, fill=C["red"])
                    d.rectangle((2, 20, 125, 32), fill=C["card"])
                    blink = int(now * 2) % 2 == 0
                    cur = "|" if blink else ""
                    d.text((4, 22), f"{query}{cur}", font=font_sm, fill=C["white"])
                    d.text((4, 38), "Audio only", font=font_sm, fill=C["dim"])
                    d.rectangle((0, 117, 127, 127), fill=C["head"])
                    d.text((2, 118), "OK:Play K3:Back", font=font_sm, fill=C["dim"])
                LCD.LCD_ShowImage(img, 0, 0)

            elif state == "music_results":
                if btn and now - last_press > 0.2:
                    last_press = now
                    if btn == "UP" and results:
                        cursor = (cursor - 1) % len(results)
                    elif btn == "DOWN" and results:
                        cursor = (cursor + 1) % len(results)
                    elif btn == "OK" and results and cursor < len(results):
                        _play_audio(results, start_idx=cursor)

                img = Image.new("RGB", (W, H), C["bg"])
                d = _draw(img)
                if IS_WIDE:
                    ITEM_H = 22
                    HDR_H = 28
                    FTR_H = 22
                    vis = (H - HDR_H - FTR_H) // ITEM_H
                    d.rectangle((0, 0, W, HDR_H), fill=C["head"])
                    d.text((8, 4), "Music", font=font_lg, fill=C["red"])
                    d.text((100, 8), f"{len(results)}", font=font_sm, fill=C["white"])
                    d.text((130, 8), query[:12], font=font_sm, fill=C["dim"])
                    y = HDR_H + 2
                    ms = max(0, min(cursor - vis // 2, max(0, len(results) - vis)))
                    for i in range(ms, min(ms + vis, len(results))):
                        r = results[i]
                        sel = i == cursor
                        if sel:
                            d.rectangle((6, y, W - 6, y + ITEM_H - 2), fill=C["sel"])
                        dur = _format_dur(r["duration"])
                        d.text((12, y + 3), r["title"][:28], font=font,
                               fill=C["white"] if sel else C["sub"])
                        d.text((W - 55, y + 3), dur, font=font_sm, fill=C["dim"])
                        y += ITEM_H
                    d.rectangle((0, H - FTR_H, W, H), fill=C["head"])
                    d.text((6, H - 18), "OK:Play(auto-next) K3:Back", font=font_sm, fill=C["dim"])
                else:
                    ITEM_H = 14
                    HDR_H = 16
                    FTR_H = 11
                    vis = (117 - HDR_H) // ITEM_H
                    d.rectangle((0, 0, 127, 13), fill=C["head"])
                    d.text((2, 2), "Music", font=font, fill=C["red"])
                    d.text((50, 2), f"{len(results)}", font=font_sm, fill=C["white"])
                    y = HDR_H
                    ms = max(0, min(cursor - vis // 2, max(0, len(results) - vis)))
                    for i in range(ms, min(ms + vis, len(results))):
                        r = results[i]
                        sel = i == cursor
                        if sel:
                            d.rectangle((2, y, 125, y + ITEM_H - 2), fill=C["sel"])
                        d.text((4, y + 1), r["title"][:18], font=font_sm,
                               fill=C["white"] if sel else C["dim"])
                        y += ITEM_H
                    d.rectangle((0, 117, 127, 127), fill=C["head"])
                    d.text((2, 118), "OK:Play K3:Back", font=font_sm, fill=C["dim"])
                LCD.LCD_ShowImage(img, 0, 0)

            elif state == "liked":
                liked = _load_liked()
                if btn and now - last_press > 0.2:
                    last_press = now
                    if btn == "UP" and liked:
                        cursor = (cursor - 1) % len(liked)
                    elif btn == "DOWN" and liked:
                        cursor = (cursor + 1) % len(liked)
                    elif btn == "OK" and liked and cursor < len(liked):
                        _play_playlist(liked, start_idx=cursor)
                    elif btn == "KEY1" and liked and cursor < len(liked):
                        liked.pop(cursor)
                        _save_liked(liked)
                        if cursor >= len(liked) and liked:
                            cursor = len(liked) - 1

                img = Image.new("RGB", (W, H), C["bg"])
                d = _draw(img)
                if IS_WIDE:
                    ITEM_H = 22
                    HDR_H = 28
                    FTR_H = 22
                    vis = (H - HDR_H - FTR_H) // ITEM_H
                    d.rectangle((0, 0, W, HDR_H), fill=C["head"])
                    d.text((8, 4), "Liked", font=font_lg, fill=C["red"])
                    d.text((100, 8), f"{len(liked)}", font=font_sm, fill=C["white"])
                    y = HDR_H + 2
                    if not liked:
                        d.text((20, 70), "No liked videos", font=font, fill=C["dim"])
                        d.text((20, 95), "Press L during playback", font=font_sm, fill=C["dim"])
                    else:
                        ls = max(0, min(cursor - vis // 2, max(0, len(liked) - vis)))
                        for i in range(ls, min(ls + vis, len(liked))):
                            sel = i == cursor
                            if sel:
                                d.rectangle((6, y, W - 6, y + ITEM_H - 2), fill=C["sel"])
                            d.text((12, y + 3), liked[i]["title"][:30], font=font,
                                   fill=C["white"] if sel else C["sub"])
                            y += ITEM_H
                    d.rectangle((0, H - FTR_H, W, H), fill=C["head"])
                    d.text((6, H - 18), "OK:Play K1:Remove K3:Back", font=font_sm, fill=C["dim"])
                else:
                    ITEM_H = 14
                    HDR_H = 16
                    FTR_H = 11
                    vis = (117 - HDR_H) // ITEM_H
                    d.rectangle((0, 0, 127, 13), fill=C["head"])
                    d.text((2, 2), "Liked", font=font, fill=C["red"])
                    d.text((50, 2), f"{len(liked)}", font=font_sm, fill=C["white"])
                    y = HDR_H
                    if not liked:
                        d.text((4, 50), "No liked videos", font=font_sm, fill=C["dim"])
                    else:
                        ls = max(0, min(cursor - vis // 2, max(0, len(liked) - vis)))
                        for i in range(ls, min(ls + vis, len(liked))):
                            sel = i == cursor
                            if sel:
                                d.rectangle((2, y, 125, y + ITEM_H - 2), fill=C["sel"])
                            d.text((4, y + 1), liked[i]["title"][:18], font=font_sm,
                                   fill=C["white"] if sel else C["dim"])
                            y += ITEM_H
                    d.rectangle((0, 117, 127, 127), fill=C["head"])
                    d.text((2, 118), "OK K1:Del K3:Back", font=font_sm, fill=C["dim"])
                LCD.LCD_ShowImage(img, 0, 0)

            elif state == "search":
                if typed and now - last_char_time > 0.15:
                    last_char_time = now
                    if typed == '\b':
                        query = query[:-1]
                    elif typed == '\n':
                        if query.strip():
                            _do_search(query)
                    elif len(query) < 40:
                        query += typed

                if IS_WIDE:
                    if btn == "OK" and query.strip() and now - last_press > 0.2:
                        last_press = now
                        _do_search(query)
                else:
                    if btn and now - last_press > 0.18:
                        last_press = now
                        if btn == "UP":
                            kb_row = (kb_row - 1) % (len(_KB_ROWS) + 1)
                        elif btn == "DOWN":
                            kb_row = (kb_row + 1) % (len(_KB_ROWS) + 1)
                        elif btn == "LEFT":
                            if kb_row < len(_KB_ROWS):
                                kb_col = (kb_col - 1) % len(_KB_ROWS[kb_row])
                        elif btn == "RIGHT":
                            if kb_row < len(_KB_ROWS):
                                kb_col = (kb_col + 1) % len(_KB_ROWS[kb_row])
                        elif btn == "OK":
                            if kb_row < len(_KB_ROWS):
                                ch = _KB_ROWS[kb_row][kb_col]
                                if ch == '<' and kb_col + 1 < len(_KB_ROWS[kb_row]) and _KB_ROWS[kb_row][kb_col:kb_col+2] == '<-':
                                    query = query[:-1]
                                elif len(query) < 40:
                                    query += ch
                            else:
                                if query.strip():
                                    _do_search(query)
                        elif btn == "KEY2":
                            query = query[:-1]

                img = Image.new("RGB", (W, H), C["bg"])
                d = _draw(img)
                if IS_WIDE:
                    blink = int(now * 2) % 2 == 0
                    _draw_search(d, query, blink)
                else:
                    _draw_osk(d, query, kb_row, kb_col)
                LCD.LCD_ShowImage(img, 0, 0)

            elif state == "results":
                if btn and now - last_press > 0.2:
                    last_press = now
                    if btn == "UP":
                        if cursor == 0 and results:
                            cursor = len(results) - 1
                            if IS_WIDE:
                                vis = (H - 28 - 22) // 28
                            else:
                                vis = (117 - 16) // 18
                            scroll = max(0, cursor - vis + 1)
                        else:
                            cursor = max(0, cursor - 1)
                            if cursor < scroll:
                                scroll = cursor
                    elif btn == "DOWN":
                        max_idx = len(results)  # len = last real, +1 = "Load more"
                        if cursor >= max_idx:
                            cursor = 0
                            scroll = 0
                        else:
                            cursor += 1
                        if IS_WIDE:
                            vis = (H - 28 - 22) // 28
                        else:
                            vis = (117 - 16) // 18
                        if cursor >= scroll + vis:
                            scroll = cursor - vis + 1
                    elif btn == "LEFT":
                        state = "menu"
                    elif btn == "OK" and results:
                        if cursor >= len(results):
                            _show_msg("Loading more...", query[:20], C["red"])
                            more = _search_youtube(query, max_results=10)
                            existing_ids = {r["id"] for r in results}
                            for m in more:
                                if m["id"] not in existing_ids:
                                    results.append(m)
                        elif cursor < len(results):
                            _play_playlist(results, start_idx=cursor)


                img = Image.new("RGB", (W, H), C["bg"])
                d = _draw(img)
                _draw_results(d, results, cursor, scroll, query)
                LCD.LCD_ShowImage(img, 0, 0)

            time.sleep(0.08)

    finally:
        subprocess.run(["pkill", "-9", "ffmpeg"], capture_output=True)
        LCD.LCD_Clear()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
