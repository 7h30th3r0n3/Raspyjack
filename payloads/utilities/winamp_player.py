#!/usr/bin/env python3
"""
RaspyJack Payload -- Winamp Classic Player
============================================
Author: 7h30th3r0n3

Faithful recreation of Winamp 2.x classic skin.
Real spectrum analyzer via FFT on audio PCM data.
"""

import os
import sys
import time
import signal
import subprocess
import random
import struct
import math

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
import numpy as np
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import scaled_font, S, SX, SY
from payloads._input_helper import get_button

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

AUDIO_EXT = {".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac", ".wma", ".opus"}
START_DIR = "/root/Raspyjack/loot"
DEBOUNCE = 0.18
_running = True
_volume = 40
_shuffle = False
_repeat = False
_audio_proc = None
_pcm_proc = None

# Winamp 2.x exact colors
C_BG = (35, 36, 42)
C_BG_DARK = (24, 26, 32)
C_BLACK = (0, 0, 0)
C_TITLE_BG = (0, 0, 48)
C_LED = (0, 248, 0)
C_LED_DIM = (0, 180, 0)
C_LED_OFF = (0, 100, 0)
C_TRACK_TEXT = (0, 248, 0)
C_BUTTON_HI = (148, 150, 160)
C_BUTTON_MID = (88, 90, 100)
C_BUTTON_LO = (40, 42, 50)
C_SEEK_BG = (50, 52, 60)
C_SEEK_FILL = (0, 180, 0)
C_GREY = (100, 102, 110)
C_BORDER_HI = (68, 70, 80)
C_BORDER_LO = (18, 20, 26)
# Spectrum colors (bottom to top)
C_SPEC = [(0, 200, 0), (0, 240, 0), (80, 240, 0), (180, 240, 0),
          (240, 240, 0), (240, 180, 0), (240, 120, 0), (240, 60, 0),
          (240, 0, 0), (200, 0, 0)]


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)

# Fonts
try:
    font_led = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf', S(14))
except Exception:
    font_led = scaled_font(14)
font = scaled_font(11)
font_sm = scaled_font(9)
font_xs = scaled_font(6)


def _check_btn():
    for name, pin in PINS.items():
        if GPIO.input(pin) == 0:
            return name
    return None


def _set_vol(vol):
    global _volume
    _volume = max(0, min(100, vol))
    dac_val = int(75 + (_volume * 180 / 100))
    hp_val = int(19 + (_volume * 44 / 100))
    subprocess.Popen(["amixer", "-c", "0", "sset", "Headphone", str(hp_val)],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.Popen(["amixer", "-c", "0", "sset", "DACL", str(dac_val)],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.Popen(["amixer", "-c", "0", "sset", "DACR", str(dac_val)],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _tpa_enable()


# ---------------------------------------------------------------------------
# Audio + PCM for spectrum
# ---------------------------------------------------------------------------
def _tpa_enable():
    try:
        import smbus2
        bus = smbus2.SMBus(1)
        bus.write_byte_data(0x60, 0x01, 0xC0, force=True)
        bus.close()
    except Exception:
        pass


def _start_audio(path):
    global _audio_proc, _pcm_proc
    _stop_audio()
    _audio_proc = subprocess.Popen(
        ["ffplay", "-nodisp", "-autoexit", "-loglevel", "quiet",
         "-fflags", "nobuffer", "-analyzeduration", "0", "-probesize", "32768", path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    _pcm_proc = subprocess.Popen(
        ["ffmpeg", "-hide_banner", "-loglevel", "quiet",
         "-fflags", "nobuffer", "-analyzeduration", "0", "-probesize", "32768",
         "-i", path, "-f", "s16le", "-ac", "1", "-ar", "8000", "pipe:1"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )



def _stop_audio():
    global _audio_proc, _pcm_proc
    for p in (_audio_proc, _pcm_proc):
        if p:
            try:
                p.kill()
                p.wait(timeout=1)
            except Exception:
                pass
    _audio_proc = _pcm_proc = None
    subprocess.run(["pkill", "-9", "aplay"], capture_output=True)


def _audio_playing():
    return _audio_proc and _audio_proc.poll() is None


def _get_spectrum(n_bars=19):
    if not _pcm_proc or _pcm_proc.poll() is not None:
        return [0] * n_bars
    try:
        raw = _pcm_proc.stdout.read(512)
        if not raw or len(raw) < 512:
            return [0] * n_bars
        samples = np.frombuffer(raw, dtype=np.int16).astype(np.float32) / 32768.0
        fft = np.abs(np.fft.rfft(samples * np.hanning(len(samples))))
        fft_db = 20 * np.log10(fft + 1e-10)
        bins = np.array_split(fft_db[:len(fft_db) // 2], n_bars)
        bars = [max(0, min(1.0, (np.max(b) + 50) / 50)) for b in bins]
        return bars
    except Exception:
        return [0] * n_bars


_peak_vals = [0.0] * 19
_peak_decay = 0.92


def _get_duration(path):
    try:
        r = subprocess.run(
            ["ffprobe", "-v", "quiet", "-show_entries", "format=duration",
             "-of", "default=noprint_wrappers=1:nokey=1", path],
            capture_output=True, text=True, timeout=3)
        return float(r.stdout.strip())
    except Exception:
        return 0


def _fmt_time(s):
    if not s or s < 0:
        s = 0
    return f"{int(s) // 60:02d}:{int(s) % 60:02d}"


def _human_size(sz):
    for u in ("B", "KB", "MB", "GB"):
        if sz < 1024:
            return f"{sz:.0f}{u}"
        sz /= 1024
    return f"{sz:.0f}TB"


# ---------------------------------------------------------------------------
# Winamp 2.x faithful renderer
# ---------------------------------------------------------------------------
_title_scroll_offset = 0


def _draw_winamp(draw, img, track_name, track_idx, total, duration, elapsed,
                 playing, paused, spectrum_bars):
    global _peak_vals, _title_scroll_offset

    # Scale helpers - map Winamp's 275x116 to our LCD
    def wx(v):
        return int(v * W / 275)

    def wy(v):
        return int(v * H / 116)

    # === Background ===
    draw.rectangle((0, 0, W, H), fill=C_BG)

    # === Title bar (0-14) ===
    draw.rectangle((0, 0, W, wy(14)), fill=C_TITLE_BG)
    # 3D border
    draw.line([(0, 0), (W, 0)], fill=C_BORDER_HI)
    draw.line([(0, 0), (0, wy(14))], fill=C_BORDER_HI)
    draw.line([(W - 1, 0), (W - 1, wy(14))], fill=C_BORDER_LO)
    # Title text
    draw.text((wx(10), wy(2)), "WINAMP", fill=C_LED, font=font_sm)
    # Decorative dashes
    for i in range(8):
        x = wx(55) + i * wx(5)
        draw.rectangle((x, wy(6), x + wx(3), wy(8)), fill=C_LED_DIM)
    # Minimize/Close buttons
    draw.rectangle((W - wx(28), wy(3), W - wx(19), wy(11)), fill=C_BUTTON_MID, outline=C_BUTTON_LO)
    draw.rectangle((W - wx(15), wy(3), W - wx(4), wy(11)), fill=C_BUTTON_MID, outline=C_BUTTON_LO)
    draw.text((W - wx(13), wy(2)), "X", fill=C_BG_DARK, font=font_sm)

    # === Timer display (16-42, left) ===
    timer_x, timer_y = wx(16), wy(18)
    timer_w, timer_h = wx(90), wy(22)
    draw.rectangle((timer_x, timer_y, timer_x + timer_w, timer_y + timer_h),
                   fill=C_BLACK, outline=C_BORDER_LO)
    time_str = _fmt_time(elapsed)
    draw.text((timer_x + wx(4), timer_y + wy(2)), time_str, fill=C_LED, font=font_led)

    # === Bitrate / kHz / Stereo (right of timer) ===
    info_x = timer_x + timer_w + wx(6)
    draw.text((info_x, timer_y + wy(2)), "128", fill=C_LED_DIM, font=font_sm)
    draw.text((info_x + wx(22), timer_y + wy(2)), "kbps", fill=C_LED_OFF, font=font_sm)
    draw.text((info_x, timer_y + wy(12)), "44", fill=C_LED_DIM, font=font_sm)
    draw.text((info_x + wx(16), timer_y + wy(12)), "kHz", fill=C_LED_OFF, font=font_sm)
    draw.text((info_x + wx(40), timer_y + wy(8)), "stereo", fill=C_LED_DIM, font=font_sm)

    # === Track title marquee (43-58) ===
    title_y = wy(43)
    title_h = wy(14)
    draw.rectangle((wx(10), title_y, W - wx(10), title_y + title_h),
                   fill=C_BLACK, outline=C_BORDER_LO)
    # Scrolling
    display = f"  {track_idx + 1}. {track_name}  ***  "
    if playing:
        _title_scroll_offset = (_title_scroll_offset + 1) % len(display)
    scroll_text = (display[_title_scroll_offset:] + display)[:35]
    draw.text((wx(14), title_y + wy(2)), scroll_text, fill=C_TRACK_TEXT, font=font_sm)

    # === Spectrum analyzer (24-41, below timer, left side) ===
    spec_x = wx(10)
    spec_y = wy(60)
    spec_w = W - wx(20)
    spec_h = wy(20)
    draw.rectangle((spec_x, spec_y, spec_x + spec_w, spec_y + spec_h),
                   fill=C_BLACK, outline=C_BORDER_LO)

    n_bars = len(spectrum_bars)
    bar_gap = 1
    bar_w = max(2, (spec_w - wx(4)) // n_bars - bar_gap)
    color_steps = len(C_SPEC)

    for i, val in enumerate(spectrum_bars):
        bx = spec_x + wx(2) + i * (bar_w + bar_gap)
        bar_h = int(val * (spec_h - wy(4)))

        # Peak hold with decay
        if val > _peak_vals[i]:
            _peak_vals[i] = val
        else:
            _peak_vals[i] *= _peak_decay

        # Draw bar with color gradient
        for row in range(bar_h):
            pct = row / max(1, spec_h - wy(4))
            ci = min(color_steps - 1, int(pct * color_steps))
            y = spec_y + spec_h - wy(2) - row
            draw.line([(bx, y), (bx + bar_w - 1, y)], fill=C_SPEC[ci])

        # Peak dot
        peak_h = int(_peak_vals[i] * (spec_h - wy(4)))
        if peak_h > 1:
            py = spec_y + spec_h - wy(2) - peak_h
            draw.line([(bx, py), (bx + bar_w - 1, py)], fill=C_LED)

    # === Volume slider ===
    vol_y = wy(83)
    draw.text((wx(4), vol_y), "VOL", fill=C_GREY, font=font_sm)
    vol_x = wx(28)
    vol_w = wx(80)
    draw.rectangle((vol_x, vol_y + wy(2), vol_x + vol_w, vol_y + wy(7)),
                   fill=C_BG_DARK, outline=C_BORDER_LO)
    fill_w = int(vol_w * _volume / 100)
    for px in range(fill_w):
        pct = px / max(1, vol_w)
        if pct < 0.6:
            c = C_SEEK_FILL
        elif pct < 0.8:
            c = (240, 200, 0)
        else:
            c = (240, 60, 0)
        draw.line([(vol_x + px, vol_y + wy(3)), (vol_x + px, vol_y + wy(6))], fill=c)
    # Volume knob
    kx = vol_x + fill_w
    draw.rectangle((kx - 2, vol_y, kx + 2, vol_y + wy(9)), fill=C_BUTTON_HI, outline=C_BUTTON_LO)
    # Percentage
    draw.text((vol_x + vol_w + wx(4), vol_y), f"{_volume}%", fill=C_LED_DIM, font=font_sm)

    # === Seek bar ===
    seek_y = wy(92)
    seek_x = wx(10)
    seek_w = W - wx(20)
    draw.rectangle((seek_x, seek_y, seek_x + seek_w, seek_y + wy(5)),
                   fill=C_SEEK_BG, outline=C_BORDER_LO)
    if duration > 0 and elapsed >= 0:
        prog = min(1.0, elapsed / duration)
        sw = int(seek_w * prog)
        draw.rectangle((seek_x, seek_y, seek_x + sw, seek_y + wy(5)), fill=C_SEEK_FILL)
        # Seek handle
        draw.rectangle((seek_x + sw - 2, seek_y - 1, seek_x + sw + 2, seek_y + wy(6)),
                       fill=C_BUTTON_HI, outline=C_BUTTON_LO)
    # Time remaining
    rem = max(0, duration - elapsed)
    draw.text((W - wx(50), seek_y - wy(5)), f"-{_fmt_time(rem)}", fill=C_LED_DIM, font=font_sm)

    # === Transport buttons (100-116) ===
    btn_y = wy(100)
    btn_h = wy(13)
    buttons = ["<<", ">>", "||", "[]", ">>|"]
    btn_w = (W - wx(20)) // 5
    for i, lbl in enumerate(buttons):
        bx = wx(10) + i * btn_w
        is_active = (i == 1 and playing and not paused) or (i == 2 and paused) or (i == 3 and not playing)
        bg = C_BUTTON_HI if is_active else C_BUTTON_MID
        draw.rectangle((bx, btn_y, bx + btn_w - 2, btn_y + btn_h), fill=bg, outline=C_BUTTON_LO)
        # 3D raised effect
        draw.line([(bx + 1, btn_y + 1), (bx + btn_w - 3, btn_y + 1)], fill=(180, 182, 190) if is_active else C_BORDER_HI)
        draw.line([(bx + 1, btn_y + 1), (bx + 1, btn_y + btn_h - 1)], fill=(180, 182, 190) if is_active else C_BORDER_HI)
        tw = draw.textlength(lbl, font=font_sm) if hasattr(draw, 'textlength') else len(lbl) * SX(5)
        draw.text((bx + (btn_w - int(tw)) // 2, btn_y + wy(3)), lbl, fill=C_BG_DARK, font=font_sm)

    # === Status indicators ===
    stat_y = btn_y + btn_h + wy(2)
    shf_col = C_LED if _shuffle else C_LED_OFF
    rpt_col = C_LED if _repeat else C_LED_OFF
    draw.text((wx(10), stat_y), "SHF", fill=shf_col, font=font_sm)
    draw.text((wx(35), stat_y), "RPT", fill=rpt_col, font=font_sm)
    draw.text((wx(60), stat_y), f"Track {track_idx + 1}/{total}", fill=C_GREY, font=font_sm)

    LCD.LCD_ShowImage(img, 0, 0)



# ---------------------------------------------------------------------------
# Bluetooth audio
# ---------------------------------------------------------------------------
_bt_connected = False
_bt_device = None


def _bt_scan_and_list():
    """Scan for BT devices using hcitool + bluetoothctl."""
    subprocess.run(["bluetoothctl", "power", "on"], capture_output=True, timeout=3)
    devices = []
    seen = set()
    # hcitool scan for classic BT (speakers)
    try:
        r = subprocess.run(["hcitool", "scan", "--flush"], capture_output=True, text=True, timeout=12)
        for line in r.stdout.strip().splitlines():
            line = line.strip()
            if line.startswith("Scanning"):
                continue
            parts = line.split("\t")
            if len(parts) >= 2:
                mac = parts[0].strip()
                name = parts[1].strip() if parts[1].strip() != "n/a" else mac
                if mac not in seen:
                    devices.append((mac, name))
                    seen.add(mac)
    except Exception:
        pass
    # Also try bluetoothctl for BLE devices
    try:
        scan = subprocess.Popen(["bluetoothctl", "scan", "on"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(5)
        scan.kill()
        scan.wait()
        r = subprocess.run(["bluetoothctl", "devices"], capture_output=True, text=True, timeout=3)
        for line in r.stdout.strip().splitlines():
            parts = line.split(" ", 2)
            if len(parts) >= 3:
                mac, name = parts[1], parts[2]
                if mac not in seen:
                    devices.append((mac, name))
                    seen.add(mac)
    except Exception:
        pass
    return devices


def _bt_connect(mac):
    """Pair and connect to a BT audio device."""
    global _bt_connected, _bt_device
    # Ensure bluealsa is running
    subprocess.Popen(["pkill", "bluealsa"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    subprocess.Popen(["bluealsa", "--profile=a2dp-source", "--codec=SBC"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    subprocess.run(["bluetoothctl", "pair", mac], capture_output=True, timeout=10)
    subprocess.run(["bluetoothctl", "trust", mac], capture_output=True, timeout=5)
    r = subprocess.run(["bluetoothctl", "connect", mac], capture_output=True, text=True, timeout=10)
    if "successful" in r.stdout.lower() or "connected" in r.stdout.lower():
        _bt_connected = True
        _bt_device = mac
        time.sleep(2)
        return True
    return False


def _bt_disconnect():
    """Disconnect BT audio."""
    global _bt_connected, _bt_device
    if _bt_device:
        subprocess.run(["bluetoothctl", "disconnect", _bt_device], capture_output=True, timeout=5)
    _bt_connected = False
    _bt_device = None


def _bt_menu(lcd, font, font_sm):
    """Bluetooth speaker selection screen."""
    global _bt_connected

    img = Image.new("RGB", (W, H), C_BG_DARK)
    draw = ImageDraw.Draw(img)
    draw.rectangle((0, 0, W, SY(14)), fill=C_TITLE_BG, outline=C_BORDER_HI)
    draw.text((SX(4), SY(2)), "BT SPEAKER", font=font_sm, fill=C_LED)
    draw.text((SX(60), SY(2)), "Scanning...", font=font_sm, fill=(255, 220, 0))
    lcd.LCD_ShowImage(img, 0, 0)

    devices = _bt_scan_and_list()

    cursor = 0
    scroll = 0

    while _running:
        img = Image.new("RGB", (W, H), C_BG_DARK)
        draw = ImageDraw.Draw(img)

        draw.rectangle((0, 0, W, SY(14)), fill=C_TITLE_BG, outline=C_BORDER_HI)
        draw.text((SX(4), SY(2)), "BT SPEAKER", font=font_sm, fill=C_LED)
        status = "Connected" if _bt_connected else f"{len(devices)} found"
        draw.text((SX(60), SY(2)), status, font=font_sm, fill=C_LED if _bt_connected else (255, 220, 0))

        if not devices:
            draw.text((SX(10), SY(40)), "No BT devices found", font=font_sm, fill=C_GREY)
            draw.text((SX(10), SY(55)), "Turn on your speaker", font=font_sm, fill=C_LED_DIM)
        else:
            visible = max(1, (H - SY(28)) // SY(12))
            for i in range(min(visible, len(devices) - scroll)):
                idx = scroll + i
                mac, name = devices[idx]
                y = SY(16) + i * SY(12)
                is_sel = idx == cursor
                if is_sel:
                    draw.rectangle((1, y, W - 1, y + SY(11)), fill=(60, 80, 160))
                connected = _bt_device == mac
                col = C_LED if connected else (C_LED if is_sel else C_LED_DIM)
                prefix = ">> " if connected else ""
                draw.text((SX(4), y + SY(1)), f"{prefix}{name[:20]}", font=font_sm, fill=col)

        draw.rectangle((0, H - SY(12), W, H), fill=C_TITLE_BG, outline=C_BORDER_HI)
        draw.text((SX(2), H - SY(11)), "OK:Connect K2:Rescan K3:Back", font=font_sm, fill=C_LED_OFF)
        lcd.LCD_ShowImage(img, 0, 0)

        btn = get_button(PINS, GPIO)
        if btn == "KEY3" or btn == "LEFT":
            return
        elif btn == "UP":
            cursor = max(0, cursor - 1)
            if cursor < scroll:
                scroll = cursor
            time.sleep(DEBOUNCE)
        elif btn == "DOWN":
            cursor = min(max(0, len(devices) - 1), cursor + 1)
            visible = max(1, (H - SY(28)) // SY(12))
            if cursor >= scroll + visible:
                scroll = cursor - visible + 1
            time.sleep(DEBOUNCE)
        elif btn == "OK" and devices:
            mac, name = devices[cursor]
            if _bt_device == mac:
                _bt_disconnect()
            else:
                img2 = Image.new("RGB", (W, H), C_BG_DARK)
                d2 = ImageDraw.Draw(img2)
                d2.text((W // 2, H // 2), f"Connecting to\n{name[:18]}...", font=font_sm, fill=(255, 220, 0), anchor="mm")
                lcd.LCD_ShowImage(img2, 0, 0)
                ok = _bt_connect(mac)
                if not ok:
                    img2 = Image.new("RGB", (W, H), C_BG_DARK)
                    d2 = ImageDraw.Draw(img2)
                    d2.text((W // 2, H // 2), "Connection failed", font=font_sm, fill=(255, 50, 0), anchor="mm")
                    lcd.LCD_ShowImage(img2, 0, 0)
                    time.sleep(1.5)
            time.sleep(DEBOUNCE)
        elif btn == "KEY2":
            img2 = Image.new("RGB", (W, H), C_BG_DARK)
            d2 = ImageDraw.Draw(img2)
            d2.text((W // 2, H // 2), "Scanning...", font=font_sm, fill=(255, 220, 0), anchor="mm")
            lcd.LCD_ShowImage(img2, 0, 0)
            devices = _bt_scan_and_list()
            cursor = 0
            scroll = 0
            time.sleep(DEBOUNCE)
        elif btn == "KEY1":
            if _bt_connected:
                _bt_disconnect()
            time.sleep(DEBOUNCE)


# ---------------------------------------------------------------------------
# File browser (Winamp playlist style)
# ---------------------------------------------------------------------------
def _list_audio(path):
    items = []
    try:
        entries = sorted(os.listdir(path))
    except PermissionError:
        return items
    dirs, files = [], []
    for e in entries:
        if e.startswith("."):
            continue
        full = os.path.join(path, e)
        if os.path.isdir(full):
            dirs.append({"name": e + "/", "path": full, "is_dir": True})
        elif os.path.splitext(e)[1].lower() in AUDIO_EXT:
            files.append({"name": e, "path": full, "is_dir": False, "size": os.path.getsize(full)})
    return dirs + files


def _draw_browser(items, cursor, scroll, current_dir):
    img = Image.new("RGB", (W, H), C_BG_DARK)
    draw = ImageDraw.Draw(img)

    # Winamp playlist style
    draw.rectangle((0, 0, W, SY(14)), fill=C_TITLE_BG, outline=C_BORDER_HI)
    draw.text((SX(4), SY(2)), "WINAMP PLAYLIST", fill=C_LED, font=font_sm)
    dirname = os.path.basename(current_dir) or current_dir
    draw.text((W - SX(50), SY(3)), dirname[:8], fill=C_LED_DIM, font=font_sm)

    if not items:
        draw.text((SX(10), SY(40)), "No audio files", fill=C_GREY, font=font)
        draw.text((SX(10), SY(55)), "Place MP3s in:", fill=C_LED_DIM, font=font_sm)
        draw.text((SX(10), SY(67)), START_DIR, fill=C_LED, font=font_sm)
    else:
        visible = max(1, (H - SY(28)) // SY(12))
        for i in range(min(visible, len(items) - scroll)):
            idx = scroll + i
            item = items[idx]
            y = SY(16) + i * SY(12)
            is_sel = idx == cursor

            if is_sel:
                draw.rectangle((1, y, W - 1, y + SY(11)), fill=(0, 0, 80))

            name = os.path.splitext(item["name"])[0] if not item["is_dir"] else item["name"]
            if item["is_dir"]:
                col = (255, 180, 0) if is_sel else (140, 100, 0)
            else:
                col = C_LED if is_sel else C_LED_DIM
            draw.text((SX(4), y + SY(1)), name[:24], fill=col, font=font_sm)

    draw.rectangle((0, H - SY(12), W, H), fill=C_TITLE_BG, outline=C_BORDER_HI)
    draw.text((SX(4), H - SY(11)), "OK:Play  L:Back  K3:Exit", fill=C_LED_OFF, font=font_sm)
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Player logic
# ---------------------------------------------------------------------------
def _play_mode(playlist, start_idx=0):
    global _shuffle, _repeat, _title_scroll_offset, _peak_vals

    if not playlist:
        return

    idx = start_idx
    playing = False
    paused = False
    play_start = 0
    pause_offset = 0
    duration = 0
    order = list(range(len(playlist)))
    _peak_vals = [0.0] * 19
    _title_scroll_offset = 0

    _set_vol(_volume)

    while _running:
        track = playlist[order[idx]]
        track_name = os.path.splitext(os.path.basename(track))[0]

        if not playing:
            duration = _get_duration(track)
            _start_audio(track)
            playing = True
            paused = False
            play_start = time.monotonic()
            pause_offset = 0
            _title_scroll_offset = 0

        elapsed = pause_offset if paused else pause_offset + (time.monotonic() - play_start)

        # Real spectrum from PCM
        spectrum = _get_spectrum(19) if playing and not paused else [0] * 19

        img = Image.new("RGB", (W, H), C_BG)
        draw = ImageDraw.Draw(img)
        _draw_winamp(draw, img, track_name, order[idx], len(playlist),
                     duration, elapsed, playing, paused, spectrum)

        # Auto-advance
        if playing and not paused and not _audio_playing():
            if _repeat:
                _start_audio(track)
                play_start = time.monotonic()
                pause_offset = 0
            elif idx < len(playlist) - 1:
                idx += 1
                playing = False
                continue
            else:
                playing = False
                continue

        btn = _check_btn()
        if btn == "KEY3":
            _stop_audio()
            break
        elif btn == "OK":
            if not paused:
                paused = True
                pause_offset += time.monotonic() - play_start
                if _audio_proc:
                    try:
                        _audio_proc.send_signal(signal.SIGSTOP)
                    except Exception:
                        pass
                if _pcm_proc:
                    try:
                        _pcm_proc.send_signal(signal.SIGSTOP)
                    except Exception:
                        pass
            else:
                paused = False
                play_start = time.monotonic()
                if _audio_proc:
                    try:
                        _audio_proc.send_signal(signal.SIGCONT)
                    except Exception:
                        pass
                if _pcm_proc:
                    try:
                        _pcm_proc.send_signal(signal.SIGCONT)
                    except Exception:
                        pass
            time.sleep(DEBOUNCE)
        elif btn == "RIGHT":
            _stop_audio()
            idx = (idx + 1) % len(playlist)
            playing = False
            time.sleep(DEBOUNCE)
        elif btn == "LEFT":
            _stop_audio()
            if elapsed > 3:
                playing = False
            else:
                idx = (idx - 1) % len(playlist)
                playing = False
            time.sleep(DEBOUNCE)
        elif btn == "UP":
            _set_vol(_volume + 5)
            time.sleep(0.1)
        elif btn == "DOWN":
            _set_vol(_volume - 5)
            time.sleep(0.1)
        elif btn == "KEY1":
            _shuffle = not _shuffle
            if _shuffle:
                cur = order[idx]
                random.shuffle(order)
                idx = order.index(cur)
            else:
                cur = order[idx]
                order = list(range(len(playlist)))
                idx = cur
            time.sleep(DEBOUNCE)
        elif btn == "KEY2":
            _repeat = not _repeat
            time.sleep(DEBOUNCE)

        time.sleep(0.04)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    _set_vol(_volume)
    current_dir = START_DIR
    cursor, scroll, dir_stack = 0, 0, []

    try:
        while _running:
            items = _list_audio(current_dir)
            _draw_browser(items, cursor, scroll, current_dir)
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if dir_stack:
                    current_dir, cursor, scroll = dir_stack.pop()
                else:
                    break
                time.sleep(DEBOUNCE)
            elif btn == "KEY2":
                _bt_menu(LCD, font, font_sm)
                time.sleep(DEBOUNCE)
            elif btn == "LEFT":
                if dir_stack:
                    current_dir, cursor, scroll = dir_stack.pop()
                else:
                    parent = os.path.dirname(current_dir)
                    if parent != current_dir:
                        dir_stack.append((current_dir, cursor, scroll))
                        current_dir, cursor, scroll = parent, 0, 0
                time.sleep(DEBOUNCE)
            elif btn == "UP":
                if cursor > 0:
                    cursor -= 1
                else:
                    cursor = max(0, len(items) - 1)
                if cursor < scroll:
                    scroll = cursor
                if cursor >= scroll + 7:
                    scroll = cursor - 6
                time.sleep(DEBOUNCE)
            elif btn == "DOWN":
                if cursor < len(items) - 1:
                    cursor += 1
                else:
                    cursor = 0
                    scroll = 0
                if cursor >= scroll + 7:
                    scroll = cursor - 6
                time.sleep(DEBOUNCE)
            elif btn in ("OK", "RIGHT") and items and cursor < len(items):
                item = items[cursor]
                if item["is_dir"]:
                    dir_stack.append((current_dir, cursor, scroll))
                    current_dir, cursor, scroll = item["path"], 0, 0
                else:
                    audio = [i["path"] for i in items if not i["is_dir"]]
                    ai = audio.index(item["path"])
                    _play_mode(audio, ai)
                time.sleep(DEBOUNCE)
            time.sleep(0.03)
    finally:
        _stop_audio()
        LCD.LCD_Clear()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
