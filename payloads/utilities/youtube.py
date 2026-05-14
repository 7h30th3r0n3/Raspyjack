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
        d.rectangle((0, H - 22, W, H), fill=C["head"])
        d.text((6, H - 18), "Type:Search  OK:Go  K3:Exit", font=font_sm, fill=C["dim"])
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
        y += 12
        d.text((4, y), "OK to submit", font=font_sm, fill=C["dim"])
        d.rectangle((0, 117, 127, 127), fill=C["head"])
        d.text((2, 118), "Type:Search OK:Go K3:X", font=font_sm, fill=C["dim"])


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

    st = max(0, min(scroll, max(0, len(results) - vis)))

    if not results:
        d.text((10, 50), "No results", font=font_sm, fill=C["dim"])
    else:
        for i in range(st, min(st + vis, len(results))):
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
            y += ITEM_H

    if IS_WIDE:
        d.rectangle((0, H - FTR_H, W, H), fill=C["head"])
        d.text((6, H - 18), "OK:Play  LEFT:Back  K3:Exit", font=font_sm, fill=C["dim"])
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


def _play_video(video_id, title):
    url = f"https://www.youtube.com/watch?v={video_id}"

    # Re-init LCD to ensure clean SPI state
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    _show_msg("Loading...", title[:20], C["red"])
    time.sleep(0.1)
    _show_msg("Fetching stream...", title[:20], C["red"])

    try:
        r = subprocess.run(
            ["yt-dlp", "-f", "160+139/160/worst", "--get-url", url],
            capture_output=True, text=True, timeout=30)
        urls = r.stdout.strip().split('\n')
        video_url = urls[0] if urls else ""
        audio_url = urls[1] if len(urls) > 1 else ""
    except subprocess.TimeoutExpired:
        _show_msg("Timeout", "Server too slow", (255, 50, 50))
        time.sleep(2)
        return
    except Exception as e:
        _show_msg("yt-dlp error", str(e)[:20], (255, 50, 50))
        time.sleep(2)
        return

    if not video_url:
        err = r.stderr[:40] if r.stderr else "No URL returned"
        _show_msg("Stream error", err[:20], (255, 50, 50))
        time.sleep(2)
        return

    _show_msg("Buffering...", title[:20], C["red"])

    # Check if ALSA audio works
    has_audio = False
    try:
        r = subprocess.run(["aplay", "-l"], capture_output=True, text=True, timeout=3)
        has_audio = "card" in r.stdout.lower()
    except Exception:
        pass

    target_fps = 8 if not IS_WIDE else 24
    cmd = ["ffmpeg", "-hide_banner", "-loglevel", "quiet", "-re"]
    cmd += ["-i", video_url]
    if audio_url and has_audio:
        cmd += ["-i", audio_url]
    cmd += ["-map", "0:v:0",
            "-vf", f"scale={W}:{H}:force_original_aspect_ratio=decrease,pad={W}:{H}:(ow-iw)/2:(oh-ih)/2,fps={target_fps}",
            "-pix_fmt", "rgb565le", "-f", "rawvideo", "pipe:1"]
    if audio_url and has_audio:
        cmd += ["-map", "1:a:0", "-ac", "2", "-ar", "44100", "-f", "alsa", "default"]

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
        return

    use_fb = IS_WIDE
    fb_fd = None
    fb_map = None
    if use_fb:
        try:
            fb_fd = os.open(FB_DEVICE, os.O_RDWR)
            fb_map = mmap.mmap(fb_fd, FB_SIZE, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)
        except Exception:
            use_fb = False

    start_time = time.time()
    paused = False
    pause_offset = 0

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break
            elif btn == "LEFT":
                break
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
        if fb_map:
            fb_map.close()
        if fb_fd is not None:
            os.close(fb_fd)
        subprocess.run(["pkill", "-9", "ffmpeg"], capture_output=True)
        time.sleep(0.3)
        LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
        _show_msg("YouTube", "Ready", C["red"])


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
    state = "search"
    last_press = 0.0
    last_char_time = 0.0
    kb_row, kb_col = 0, 0

    try:
        while _running:
            btn = get_button(PINS, GPIO)
            now = time.time()
            typed = _get_typed_char() if EVDEV_OK else None

            if btn == "KEY3":
                if state == "results":
                    state = "search"
                    continue
                break

            if state == "search":
                # Physical keyboard (CardputerZero)
                if typed and now - last_char_time > 0.15:
                    last_char_time = now
                    if typed == '\b':
                        query = query[:-1]
                    elif typed == '\n':
                        if query.strip():
                            _show_msg("Searching...", query[:20], C["red"])
                            results = _search_youtube(query)
                            cursor = 0
                            scroll = 0
                            state = "results"
                    elif len(query) < 40:
                        query += typed

                # On-screen keyboard (128/240) or OK on CardputerZero
                if IS_WIDE:
                    if btn == "OK" and query.strip():
                        _show_msg("Searching...", query[:20], C["red"])
                        results = _search_youtube(query)
                        cursor = 0
                        scroll = 0
                        state = "results"
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
                                    _show_msg("Searching...", query[:16], C["red"])
                                    results = _search_youtube(query)
                                    cursor = 0
                                    scroll = 0
                                    state = "results"
                        elif btn == "KEY1":
                            query = query[:-1]
                        elif btn == "KEY2" and query.strip():
                            _show_msg("Searching...", query[:16], C["red"])
                            results = _search_youtube(query)
                            cursor = 0
                            scroll = 0
                            state = "results"

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
                        if results and cursor >= len(results) - 1:
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
                        state = "search"
                    elif btn == "OK" and results and cursor < len(results):
                        r = results[cursor]
                        _play_video(r["id"], r["title"])

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
