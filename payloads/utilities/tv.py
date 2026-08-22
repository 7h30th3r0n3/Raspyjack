#!/usr/bin/env python3
"""
RaspyJack Payload -- TV (YouTube channels)
==========================================
A lean-back "TV" that endlessly cycles a programmed lineup of shows,
pulling episodes from YouTube.

Inspired by a classic bash "fake TV" loop: it interleaves your shows with
bumpers (commercials / trailers / music videos), picks a *random* episode
from each show without repeating the last one, and never stops.

Everything is driven by an easy-to-edit JSON config that is created on first
run:  /root/Raspyjack/loot/TV/tv_config.json

  shows   : name -> { "source": <see below>, "max": <how many to pull> }
  lineup  : ordered list of show names to rotate through, forever

A show "source" can be:
  - a YouTube channel URL   "https://www.youtube.com/@SomeChannel/videos"
  - a YouTube playlist URL  "https://www.youtube.com/playlist?list=PL..."
  - a search query          "search:retro tv commercials"  (or just plain text)

Resolved video lists are cached (default 12h) so it stays fresh without
hammering YouTube on every loop.

Controls (channel-select screen):
  UP/DOWN     Pick a channel (or "All channels")
  OK          Start watching
  KEY3        Exit

Controls (while watching):
  RIGHT       Next episode (skip)
  LEFT        Skip current
  UP/DOWN     Volume
  KEY1 / OK   Pause / Resume
  KEY2        Toggle channel banner
  KEY3        Stop / back to channel list
"""

import os
import sys
import time
import json
import random
import signal
import subprocess
import mmap

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._audio_helper import set_playback_volume

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

C = {
    "bg": "#0a0a0a", "head": "#001a1a", "accent": "#00e5ff",
    "white": "#ffffff", "dim": "#555", "card": "#101820",
    "sel": "#06303a", "sub": "#aaaaaa", "warn": "#ff5252",
}

TV_DIR = "/root/Raspyjack/loot/TV"
CONFIG_FILE = os.path.join(TV_DIR, "tv_config.json")
CACHE_FILE = os.path.join(TV_DIR, "tv_cache.json")
STATE_FILE = os.path.join(TV_DIR, "tv_state.json")

# Stream quality presets (video[+audio] format selectors for yt-dlp)
STREAM_QUALITIES = {
    "144p": "160+139/160/worst",
    "240p": "133+139/133/worst",
    "360p": "134+139/134/worst",
    "480p": "135+139/135/worst",
    "720p": "136+139/136/worst",
}

DEFAULT_CONFIG = {
    "_comment": (
        "RaspyJack TV. 'source' = channel URL, playlist URL, or 'search:<query>'. "
        "'lineup' is the rotation order (repeat names to weight them, like commercials "
        "between every show). Delete tv_cache.json to force a refresh."
    ),
    "shows": {
        "Sn0ren": {"source": "https://www.youtube.com/@sn0ren/videos", "max": 40},
        "ValleyTech": {"source": "https://www.youtube.com/@Valleytechsolutions/videos", "max": 40},
        "Sasquach": {"source": "search:talking sasquach", "max": 40},
        "Hacking": {"source": "search:cybersecurity news 2026", "max": 40},
        "Commercials": {"source": "search:retro tv commercials", "max": 40},
        "Trailers": {"source": "search:movie trailers 2026", "max": 40},
        "MusicVideos": {"source": "search:synthwave music video", "max": 40},
    },
    "lineup": [
        "Sn0ren", "Commercials", "Trailers", "MusicVideos",
        "ValleyTech", "Commercials", "Trailers", "Sasquach",
        "Commercials", "Hacking", "Trailers",
    ],
    "quality": "360p",
    "cache_hours": 12,
    "volume": 40,
    "shuffle_lineup": False,
}

_running = True
_vol = DEFAULT_CONFIG["volume"]
_alsa_dev = "default"
_alsa_card = "0"


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------
def _draw(img):
    if IS_WIDE:
        from PIL import ImageDraw
        return ImageDraw.Draw(img)
    return ScaledDraw(img)


def _show_msg(text, sub="", color=C["accent"]):
    img = Image.new("RGB", (W, H), C["bg"])
    d = _draw(img)
    if IS_WIDE:
        d.text((W // 2, 50), text, font=font_lg, fill=color, anchor="mm")
        if sub:
            d.text((W // 2, 82), sub, font=font, fill=C["sub"], anchor="mm")
    else:
        d.text((W // 2, 50), text, font=font, fill=color, anchor="mm")
        if sub:
            d.text((W // 2, 70), sub, font=font_sm, fill=C["sub"], anchor="mm")
    LCD.LCD_ShowImage(img, 0, 0)


def _format_dur(sec):
    if sec <= 0:
        return "?"
    m, s = divmod(int(sec), 60)
    h, m = divmod(m, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


# ---------------------------------------------------------------------------
# Config / cache / state
# ---------------------------------------------------------------------------
def _load_config():
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
        # Backfill any missing top-level keys from defaults
        for k, v in DEFAULT_CONFIG.items():
            cfg.setdefault(k, v)
        return cfg
    except Exception:
        os.makedirs(TV_DIR, exist_ok=True)
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(DEFAULT_CONFIG, f, indent=2)
        except Exception:
            pass
        return dict(DEFAULT_CONFIG)


def _load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def _save_json(path, data):
    try:
        os.makedirs(TV_DIR, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Audio
# ---------------------------------------------------------------------------
def _detect_alsa():
    global _alsa_dev, _alsa_card
    try:
        r = subprocess.run(["aplay", "-l"], capture_output=True, text=True, timeout=3)
        for line in r.stdout.split("\n"):
            if "card" in line.lower() and ":" in line:
                card_num = line.split(":")[0].replace("card", "").strip()
                if any(k in line.upper() for k in ["ES8388", "ES8389", "ES8390"]):
                    _alsa_dev = f"plughw:{card_num},0"
                    _alsa_card = card_num
                    return
                elif "HDMI" not in line.upper():
                    _alsa_dev = f"plughw:{card_num},0"
                    _alsa_card = card_num
    except Exception:
        pass


def _set_vol(v):
    global _vol
    _vol = max(0, min(63, v))
    set_playback_volume(_vol)


# ---------------------------------------------------------------------------
# Source resolution (channel / playlist / search -> list of videos), cached
# ---------------------------------------------------------------------------
def _resolve_source(source, max_results, cache, cache_hours):
    """Return a list of {id,title,channel,duration}. Cached by source key."""
    key = source
    entry = cache.get(key)
    now = time.time()
    if entry and (now - entry.get("ts", 0)) < cache_hours * 3600 and entry.get("items"):
        return entry["items"]

    if source.startswith("search:"):
        target = f"ytsearch{max_results}:{source[len('search:'):].strip()}"
    elif source.startswith(("http://", "https://", "www.")):
        target = source
    else:
        target = f"ytsearch{max_results}:{source.strip()}"

    try:
        r = subprocess.run(
            ["yt-dlp", "--flat-playlist", "--no-download",
             "-I", f":{max_results}", "-j", target],
            capture_output=True, text=True, timeout=90)
    except Exception:
        return entry["items"] if entry else []

    items = []
    for line in r.stdout.strip().split("\n"):
        if not line:
            continue
        try:
            data = json.loads(line)
        except Exception:
            continue
        vid = data.get("id", "")
        if not vid:
            continue
        items.append({
            "id": vid,
            "title": (data.get("title") or "?")[:60],
            "channel": (data.get("channel") or data.get("uploader") or "")[:30],
            "duration": int(data.get("duration") or 0),
        })

    if items:
        cache[key] = {"ts": now, "items": items}
        _save_json(CACHE_FILE, cache)
        return items
    return entry["items"] if entry else []


def _pick_episode(show_name, items, state):
    """Pick a random video, avoiding the immediately-previous one (like last.txt)."""
    if not items:
        return None
    last_id = state.get(show_name)
    pool = [v for v in items if v["id"] != last_id] or items
    choice = random.choice(pool)
    state[show_name] = choice["id"]
    _save_json(STATE_FILE, state)
    return choice


# ---------------------------------------------------------------------------
# Streaming engine (yt-dlp get-url -> ffmpeg -> framebuffer + ALSA)
# Ported from the youtube.py payload, trimmed for lean-back playback.
# ---------------------------------------------------------------------------
def _read_frame(proc):
    raw = b""
    while len(raw) < FB_SIZE:
        chunk = proc.stdout.read(FB_SIZE - len(raw))
        if not chunk:
            return None
        raw += chunk
    return raw


def _banner_img(show_name, channel, title, idx, total):
    """Channel-change banner ('NOW: <show>')."""
    img = Image.new("RGB", (W, H), C["bg"])
    d = _draw(img)
    if IS_WIDE:
        d.rectangle((0, 0, W, 30), fill=C["head"])
        d.text((10, 6), "RaspyJack TV", font=font_lg, fill=C["accent"])
        d.text((W - 70, 10), f"{idx}/{total}", font=font_sm, fill=C["dim"])
        d.text((10, 50), f"NOW: {show_name}", font=font_lg, fill=C["white"])
        d.text((10, 82), (title or "")[:36], font=font, fill=C["sub"])
        if channel:
            d.text((10, 104), channel[:36], font=font_sm, fill=C["dim"])
    else:
        d.rectangle((0, 0, W, 14), fill=C["head"])
        d.text((3, 2), "RaspyJack TV", font=font_sm, fill=C["accent"])
        d.text((3, 30), f"NOW:", font=font_sm, fill=C["dim"])
        d.text((3, 44), show_name[:16], font=font, fill=C["white"])
        d.text((3, 66), (title or "")[:20], font=font_sm, fill=C["sub"])
    return img


def _play_video(video_id, title, show_name, channel, idx, total, quality, show_banner):
    """Stream one video full-screen. Returns 'next' / 'skip' / 'stop'."""
    url = f"https://www.youtube.com/watch?v={video_id}"
    quality_fmt = STREAM_QUALITIES.get(quality, STREAM_QUALITIES["360p"])

    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    if show_banner:
        LCD.LCD_ShowImage(_banner_img(show_name, channel, title, idx, total), 0, 0)
        time.sleep(1.6)
    else:
        _show_msg("Tuning in...", show_name, C["accent"])

    try:
        r = subprocess.run(["yt-dlp", "-f", quality_fmt, "--get-url", url],
                           capture_output=True, text=True, timeout=40)
        urls = r.stdout.strip().split("\n")
        video_url = urls[0] if urls and urls[0] else ""
        audio_url = urls[1] if len(urls) > 1 else ""
    except Exception:
        _show_msg("Stream error", "skipping...", C["warn"])
        time.sleep(1)
        return "next"

    if not video_url:
        _show_msg("No stream", "skipping...", C["warn"])
        time.sleep(1)
        return "next"

    target_fps = 24 if IS_WIDE else 8
    cmd = ["ffmpeg", "-hide_banner", "-loglevel", "quiet", "-re", "-i", video_url]
    if audio_url:
        cmd += ["-i", audio_url]
    cmd += ["-map", "0:v:0",
            "-vf", f"scale={W}:{H}:force_original_aspect_ratio=decrease,"
                   f"pad={W}:{H}:(ow-iw)/2:(oh-ih)/2,fps={target_fps}",
            "-pix_fmt", "rgb565le", "-f", "rawvideo", "pipe:1"]
    if audio_url:
        cmd += ["-map", "1:a:0", "-af", "aresample=async=1",
                "-ac", "2", "-ar", "44100", "-f", "alsa", _alsa_dev]

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            bufsize=FB_SIZE * 16)
    try:
        import fcntl
        fcntl.fcntl(proc.stdout, 1031, FB_SIZE * 32)  # F_SETPIPE_SZ
    except Exception:
        pass

    time.sleep(0.5)
    if proc.poll() is not None:
        _show_msg("ffmpeg error", "skipping...", C["warn"])
        time.sleep(1)
        return "next"

    use_fb = IS_WIDE
    fb_fd = fb_map = None
    if use_fb:
        try:
            fb_fd = os.open(FB_DEVICE, os.O_RDWR)
            fb_map = mmap.mmap(fb_fd, FB_SIZE, mmap.MAP_SHARED,
                               mmap.PROT_WRITE | mmap.PROT_READ)
        except Exception:
            use_fb = False

    _set_vol(_vol)
    paused = False
    banner_until = time.time() + 2.5
    result = "next"

    try:
        while _running:
            btn = get_button(PINS, GPIO)
            now = time.time()

            if btn == "KEY3":
                result = "stop"
                break
            elif btn == "RIGHT":
                result = "next"
                break
            elif btn == "LEFT":
                result = "skip"
                break
            elif btn == "UP":
                _set_vol(_vol + 5)
                banner_until = now + 1.5
                time.sleep(0.1)
            elif btn == "DOWN":
                _set_vol(_vol - 5)
                banner_until = now + 1.5
                time.sleep(0.1)
            elif btn == "KEY2":
                banner_until = now + 2.5
            elif btn in ("KEY1", "OK"):
                paused = not paused
                if paused:
                    proc.send_signal(signal.SIGSTOP)
                    img = Image.new("RGB", (W, H), C["bg"])
                    d = _draw(img)
                    d.text((W // 2, H // 2), "PAUSED", font=font_lg,
                           fill=C["accent"], anchor="mm")
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
                result = "next"
                break

            if use_fb:
                fb_map.seek(0)
                fb_map.write(raw)
            else:
                import numpy as np
                arr = np.frombuffer(raw, dtype="<u2").reshape(H, W)
                rr = ((arr >> 11) & 0x1F) << 3
                gg = ((arr >> 5) & 0x3F) << 2
                bb = (arr & 0x1F) << 3
                rgb = np.stack([rr.astype(np.uint8), gg.astype(np.uint8),
                                bb.astype(np.uint8)], axis=-1)
                LCD.LCD_ShowImage(Image.fromarray(rgb, "RGB"), 0, 0)
    finally:
        try:
            proc.kill()
            proc.wait(timeout=2)
        except Exception:
            pass
        if fb_map:
            try:
                fb_map.close()
            except Exception:
                pass
        if fb_fd is not None:
            try:
                os.close(fb_fd)
            except Exception:
                pass
        subprocess.run(["pkill", "-9", "ffmpeg"], capture_output=True)
        time.sleep(0.2)
        LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)

    return result


# ---------------------------------------------------------------------------
# Dependency / connectivity checks
# ---------------------------------------------------------------------------
def _check_internet():
    try:
        return subprocess.run(["ping", "-c", "1", "-W", "2", "8.8.8.8"],
                              capture_output=True, timeout=5).returncode == 0
    except Exception:
        return False


def _check_deps():
    import shutil
    return os.path.isfile("/usr/bin/ffmpeg") and shutil.which("yt-dlp") is not None


# ---------------------------------------------------------------------------
# Channel-select screen
# ---------------------------------------------------------------------------
def _channel_menu(cfg):
    """Return 'ALL', a show name, or None (exit)."""
    shows = list(cfg.get("shows", {}).keys())
    items = ["All channels (TV)"] + shows
    sel = 0
    last = 0.0
    while _running:
        img = Image.new("RGB", (W, H), C["bg"])
        d = _draw(img)
        if IS_WIDE:
            d.rectangle((0, 0, W, 30), fill=C["head"])
            d.text((10, 6), "RaspyJack TV", font=font_lg, fill=C["accent"])
            row_h, top = 26, 38
            vis = (H - top - 20) // row_h
        else:
            d.rectangle((0, 0, W, 14), fill=C["head"])
            d.text((3, 2), "RaspyJack TV", font=font_sm, fill=C["accent"])
            row_h, top = 16, 18
            vis = (H - top - 12) // row_h
        st = max(0, min(sel - vis + 1, len(items) - vis)) if len(items) > vis else 0
        for i in range(st, min(st + vis, len(items))):
            y = top + (i - st) * row_h
            on = i == sel
            if on:
                d.rectangle((0, y, W, y + row_h - 2), fill=C["sel"])
            label = items[i]
            d.text((8, y + 3), label[:30 if IS_WIDE else 18],
                   font=font if IS_WIDE else font_sm,
                   fill=C["white"] if on else C["sub"])
        foot = "OK:Watch  K3:Exit" if IS_WIDE else "OK:Watch K3:X"
        d.text((W // 2, H - 9), foot, font=font_sm, fill=C["dim"], anchor="mm")
        LCD.LCD_ShowImage(img, 0, 0)

        btn = get_button(PINS, GPIO)
        now = time.time()
        if now - last < 0.15:
            time.sleep(0.03)
            continue
        if btn == "KEY3":
            return None
        elif btn == "UP":
            sel = (sel - 1) % len(items); last = now
        elif btn == "DOWN":
            sel = (sel + 1) % len(items); last = now
        elif btn in ("OK", "RIGHT"):
            return "ALL" if sel == 0 else items[sel]
        time.sleep(0.03)
    return None


# ---------------------------------------------------------------------------
# Main TV loop
# ---------------------------------------------------------------------------
def _watch(cfg, selection):
    quality = cfg.get("quality", "360p")
    cache_hours = float(cfg.get("cache_hours", 12))
    shows = cfg.get("shows", {})

    if selection == "ALL":
        lineup = [s for s in cfg.get("lineup", []) if s in shows]
        if not lineup:
            lineup = list(shows.keys())
        if cfg.get("shuffle_lineup"):
            random.shuffle(lineup)
    else:
        lineup = [selection]

    if not lineup:
        _show_msg("No shows", "Edit tv_config.json", C["warn"])
        time.sleep(2)
        return

    cache = _load_json(CACHE_FILE, {})
    state = _load_json(STATE_FILE, {})
    show_banner = True
    pos = 0
    total = len(lineup)

    while _running:
        show_name = lineup[pos % total]
        meta = shows.get(show_name, {})
        _show_msg("Loading", show_name, C["accent"])
        items = _resolve_source(meta.get("source", ""), int(meta.get("max", 40)),
                                cache, cache_hours)
        ep = _pick_episode(show_name, items, state)
        if ep is None:
            _show_msg(show_name, "no videos, skipping", C["warn"])
            time.sleep(1.2)
            pos += 1
            continue

        result = _play_video(ep["id"], ep["title"], show_name, ep.get("channel", ""),
                             pos % total + 1, total, quality, show_banner)
        if result == "stop":
            return
        # 'next' and 'skip' both advance the lineup; 'next' is natural end-of-video
        pos += 1


def main():
    _detect_alsa()
    cfg = _load_config()
    global _vol
    _vol = int(cfg.get("volume", 40))

    _show_msg("RaspyJack TV", "checking...", C["accent"])
    if not _check_internet():
        _show_msg("No Internet", "connect WiFi/Eth", C["warn"])
        time.sleep(3)
        GPIO.cleanup()
        return 1
    if not _check_deps():
        _show_msg("Missing deps", "ffmpeg / yt-dlp", C["warn"])
        time.sleep(3)
        GPIO.cleanup()
        return 1

    try:
        while _running:
            selection = _channel_menu(cfg)
            if selection is None:
                break
            _watch(cfg, selection)
            cfg = _load_config()  # re-read in case it was edited
    finally:
        subprocess.run(["pkill", "-9", "ffmpeg"], capture_output=True)
        LCD.LCD_Clear()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
