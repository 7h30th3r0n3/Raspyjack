#!/usr/bin/env python3
"""
RaspyJack Payload -- Sub-GHz (Flipper Zero-style)
===================================================
Author: 7h30th3r0n3

CC1101 Cap HAT Sub-GHz interface cloned from Flipper Zero / Momentum.
Read, Read RAW, Saved, Frequency Analyzer.
Decodes 80+ protocols: Princeton, CAME, Nice FLO, KeeLoq, weather, etc.
Flipper .sub file format for save/load/replay.

Controls:
  OK          Action (start, save, send)
  UP/DOWN     Scroll / navigate
  LEFT/RIGHT  Change frequency / modulation
  KEY1        Switch mode / extra action
  KEY2        Settings / config
  KEY3        Back / Exit
"""

import os
import sys
import time
import signal
import threading

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font, SX, SY
from payloads._input_helper import get_button

try:
    from payloads._cc1101_driver import CC1101
    CC1101_OK = True
except ImportError:
    CC1101_OK = False

try:
    from payloads._cc1101_protocols import (
        ALL_PROTOCOLS, PROTOCOL_BY_NAME, DecodedSignal, save_sub_file, load_sub_file,
        decode_raw_pulses, decode_sub_file, _reverse_key,
    )
    PROTO_OK = True
except ImportError:
    PROTO_OK = False

try:
    import evdev_keys
    EVDEV_OK = True
except ImportError:
    EVDEV_OK = False

_EVDEV_HEX = {
    2: '1', 3: '2', 4: '3', 5: '4', 6: '5', 7: '6', 8: '7', 9: '8', 10: '9', 11: '0',
    30: 'a', 48: 'b', 46: 'c', 32: 'd', 18: 'e', 33: 'f',
    14: '\b', 28: '\n',
}

def _get_hex_char():
    if not EVDEV_OK:
        return None
    for code, ch in _EVDEV_HEX.items():
        if evdev_keys.is_key_pressed(code):
            return ch
    return None

try:
    import gpiod
    GPIOD_OK = True
except ImportError:
    GPIOD_OK = False

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
    try:
        FONT = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 13)
        FONT_SM = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 10)
        FONT_LG = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 16)
        FONT_XL = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 20)
    except Exception:
        FONT = scaled_font(9)
        FONT_SM = scaled_font(7)
        FONT_LG = scaled_font(12)
        FONT_XL = scaled_font(14)
else:
    FONT = scaled_font(9)
    FONT_SM = scaled_font(7)
    FONT_LG = scaled_font(12)
    FONT_XL = FONT_LG

# Flipper-style colors
C_BG = "#000000"
C_ORANGE = "#FF8C00"
C_WHITE = "#FFFFFF"
C_GREEN = "#00FF41"
C_RED = "#FF3333"
C_DIM = "#555555"
C_DARK = "#111111"
C_BLUE = "#4488FF"
C_SEL = "#1A1400"
C_HEADER = "#0D0700"

LOOT_DIR = "/root/Raspyjack/loot/CC1101"
DEBOUNCE = 0.18

FREQUENCIES = [
    300000000, 303875000, 304250000, 310000000, 315000000, 318000000,
    390000000, 418000000, 433075000, 433420000, 433920000, 434420000,
    434775000, 438900000, 868350000, 868950000, 915000000, 925000000,
]
DEFAULT_FREQ_IDX = 10  # 433.920 MHz

PRESETS = [
    {"name": "AM270", "type": "OOK", "bw": 270},
    {"name": "AM650", "type": "OOK", "bw": 650},
    {"name": "FM238", "type": "FSK", "dev": 2.38},
    {"name": "FM476", "type": "FSK", "dev": 47.6},
]
DEFAULT_PRESET_IDX = 1  # AM650

_running = True
_radio = None


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _freq_str(freq_hz):
    return f"{freq_hz / 1_000_000:.3f}"


def _show(img):
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_header(d, title, right_text=""):
    if IS_WIDE:
        d.rectangle([0, 0, W, 22], fill=C_HEADER)
        d.line([0, 22, W, 22], fill=C_ORANGE)
        d.text((6, 3), title, font=FONT_LG, fill=C_ORANGE)
        if right_text:
            d.text((W - 6, 3), right_text, font=FONT_SM, fill=C_DIM, anchor="ra")
    else:
        d.rectangle([0, 0, 128, 14], fill=C_HEADER)
        d.text((2, 1), title, font=FONT, fill=C_ORANGE)


def _draw_footer(d, text):
    if IS_WIDE:
        d.rectangle([0, H - 16, W, H], fill=C_DARK)
        d.line([0, H - 16, W, H - 16], fill=C_DIM)
        d.text((W // 2, H - 8), text, font=FONT_SM, fill=C_DIM, anchor="mm")
    else:
        d.rectangle([0, 117, 128, 128], fill=C_DARK)
        d.text((2, 118), text, font=FONT_SM, fill=C_DIM)


def _draw_msg(text, sub="", color=C_ORANGE):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
    if IS_WIDE:
        d.text((W // 2, H // 2 - 10), text, font=FONT_LG, fill=color, anchor="mm")
        if sub:
            d.text((W // 2, H // 2 + 14), sub, font=FONT_SM, fill=C_DIM, anchor="mm")
    else:
        d.text((64, 50), text, font=FONT, fill=color)
        if sub:
            d.text((64, 68), sub, font=FONT_SM, fill=C_DIM)
    _show(img)


# ── CC1101 preset configuration ──────────────────────────────────────────

# Register values from Momentum cc1101_configs.c
_PRESET_REGS = {
    "AM270": {
        0x02: 0x0D, 0x03: 0x47, 0x08: 0x32, 0x0B: 0x06,
        0x10: 0x67, 0x11: 0x32, 0x12: 0x30, 0x13: 0x00, 0x14: 0x00,
        0x18: 0x18, 0x19: 0x18,
        0x1B: 0x03, 0x1C: 0x00, 0x1D: 0x91,
        0x20: 0xFB, 0x21: 0xB6, 0x22: 0x11,
    },
    "AM650": {
        0x02: 0x0D, 0x03: 0x07, 0x08: 0x32, 0x0B: 0x06,
        0x10: 0x17, 0x11: 0x32, 0x12: 0x30, 0x13: 0x00, 0x14: 0x00,
        0x18: 0x18, 0x19: 0x18,
        0x1B: 0x07, 0x1C: 0x00, 0x1D: 0x91,
        0x20: 0xFB, 0x21: 0xB6, 0x22: 0x11,
    },
    "FM238": {
        0x02: 0x0D, 0x07: 0x04, 0x08: 0x32, 0x0B: 0x06,
        0x10: 0x67, 0x11: 0x83, 0x12: 0x04, 0x13: 0x02, 0x14: 0x00,
        0x15: 0x04,
        0x18: 0x18, 0x19: 0x16,
        0x1B: 0x07, 0x1C: 0x40, 0x1D: 0x91,
        0x20: 0xFB, 0x21: 0xB6, 0x22: 0x10,
    },
    "FM476": {
        0x02: 0x0D, 0x07: 0x04, 0x08: 0x32, 0x0B: 0x06,
        0x10: 0x67, 0x11: 0x83, 0x12: 0x04, 0x13: 0x02, 0x14: 0x00,
        0x15: 0x47,
        0x18: 0x18, 0x19: 0x16,
        0x1B: 0x07, 0x1C: 0x40, 0x1D: 0x91,
        0x20: 0xFB, 0x21: 0xB6, 0x22: 0x10,
    },
}

_PA_OOK = [0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
_PA_FSK = [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]


def _apply_preset(radio, preset_name):
    """Apply Flipper-compatible CC1101 preset (async OOK/FSK)."""
    radio.idle()
    regs = _PRESET_REGS.get(preset_name, _PRESET_REGS["AM650"])
    for reg, val in regs.items():
        radio._write_reg(reg, val)
    is_ook = preset_name.startswith("AM")
    pa = _PA_OOK if is_ook else _PA_FSK
    radio._write_burst(0x3E, pa)


# ── Raw capture via GDO0 edge timing ─────────────────────────────────────

def _capture_raw(radio, duration_s=5.0, gdo0_pin=15):
    """Capture raw OOK edges — only when RSSI above threshold (signal present)."""
    pulses = []
    if not GPIOD_OK:
        return pulses

    rssi_threshold = -50.0
    deadline = time.time() + duration_s

    # Poll RSSI until signal detected
    while time.time() < deadline and _running:
        rssi = radio.get_rssi()
        if rssi > rssi_threshold:
            break
        time.sleep(0.005)
    else:
        return pulses

    # Signal detected — capture edges
    try:
        chip = gpiod.Chip("/dev/gpiochip0")
        cfg = gpiod.LineSettings(
            direction=gpiod.line.Direction.INPUT,
            edge_detection=gpiod.line.Edge.BOTH,
        )
        req = chip.request_lines(config={gdo0_pin: cfg}, consumer="cc1101-raw")
    except Exception:
        return pulses

    last_time = time.monotonic_ns()
    last_level = False
    last_edge = time.time()

    try:
        while time.time() < deadline and _running:
            if req.wait_edge_events(timeout=0.05):
                for ev in req.read_edge_events():
                    now_ns = ev.timestamp_ns
                    dur_us = (now_ns - last_time) / 1000
                    if 50 < dur_us < 200000:
                        if last_level:
                            pulses.append(int(dur_us))
                        else:
                            pulses.append(-int(dur_us))
                        last_edge = time.time()
                    last_level = ev.event_type == gpiod.EdgeEvent.Type.RISING_EDGE
                    last_time = now_ns
            # Stop capturing after 500ms of silence
            if time.time() - last_edge > 0.5:
                break
    except Exception:
        pass
    finally:
        req.release()
    return pulses


# ── Main menu ─────────────────────────────────────────────────────────────

MENU_ITEMS = ["Read", "Read RAW", "Saved", "Decode .sub", "Freq Analyzer", "Add Manually", "Bruteforce", "Radio Settings"]


def _draw_menu(sel):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
    _draw_header(d, "Sub-GHz")

    if IS_WIDE:
        y_start = 30
        item_h = 22
        max_vis = (H - y_start - 16) // item_h
        scroll = max(0, min(sel - max_vis // 2, len(MENU_ITEMS) - max_vis))
        y = y_start
        for i in range(scroll, min(scroll + max_vis, len(MENU_ITEMS))):
            is_sel = i == sel
            if is_sel:
                d.rectangle([4, y, W - 4, y + item_h], fill=C_SEL)
                d.text((12, y + 3), f"> {MENU_ITEMS[i]}", font=FONT, fill=C_ORANGE)
            else:
                d.text((18, y + 3), MENU_ITEMS[i], font=FONT, fill=C_WHITE)
            y += item_h
        if scroll > 0:
            d.text((W - 12, y_start), "^", font=FONT_SM, fill=C_DIM)
        if scroll + max_vis < len(MENU_ITEMS):
            d.text((W - 12, y - 10), "v", font=FONT_SM, fill=C_DIM)
    else:
        y_start = 18
        item_h = 16
        max_vis = (117 - y_start) // item_h
        scroll = max(0, min(sel - max_vis // 2, len(MENU_ITEMS) - max_vis))
        y = y_start
        for i in range(scroll, min(scroll + max_vis, len(MENU_ITEMS))):
            is_sel = i == sel
            color = C_ORANGE if is_sel else C_WHITE
            prefix = ">" if is_sel else " "
            d.text((4, y), f"{prefix}{MENU_ITEMS[i]}", font=FONT_SM, fill=color)
            y += item_h

    _draw_footer(d, "OK:Select  K3:Exit")
    _show(img)


# ── Read mode ─────────────────────────────────────────────────────────────

def _mode_read(radio):
    freq_idx = DEFAULT_FREQ_IDX
    preset_idx = DEFAULT_PRESET_IDX
    signals = []
    cursor = 0
    scroll = 0
    capturing = False
    capture_thread = None
    last_btn = 0

    hopping = False
    hop_pause_until = 0

    def _capture_loop():
        nonlocal signals, freq_idx, hopping, hop_pause_until
        _apply_preset(radio, PRESETS[preset_idx]["name"])
        radio.set_frequency(FREQUENCIES[freq_idx] / 1_000_000)
        radio.set_raw_rx()
        while capturing and _running:
            if hopping and time.time() > hop_pause_until:
                freq_idx = (freq_idx + 1) % len(FREQUENCIES)
                radio.set_frequency(FREQUENCIES[freq_idx] / 1_000_000)
                radio.set_raw_rx()
            rssi_before = radio.get_rssi()
            pulses = _capture_raw(radio, duration_s=0.5 if hopping else 1.0)
            if pulses:
                decoded = decode_raw_pulses(pulses)
                for sig in decoded:
                    sig.frequency = FREQUENCIES[freq_idx]
                    sig.modulation = PRESETS[preset_idx]["name"]
                    sig.extra["_raw_pulses"] = list(pulses)
                    sig.extra["rssi"] = "%.0f" % rssi_before
                    signals.insert(0, sig)
                    if len(signals) > 50:
                        signals = signals[:50]
                if hopping and decoded:
                    hop_pause_until = time.time() + 2.0

    capturing = True
    capture_thread = threading.Thread(target=_capture_loop, daemon=True)
    capture_thread.start()

    while _running:
        btn = get_button(PINS, GPIO)
        now = time.time()

        if btn == "KEY3":
            capturing = False
            if capture_thread:
                capture_thread.join(timeout=2)
            radio.idle()
            return

        if btn == "LEFT" and now - last_btn > DEBOUNCE:
            last_btn = now
            capturing = False
            if capture_thread:
                capture_thread.join(timeout=2)
            preset_idx = (preset_idx - 1) % len(PRESETS)
            capturing = True
            capture_thread = threading.Thread(target=_capture_loop, daemon=True)
            capture_thread.start()

        if btn == "RIGHT" and now - last_btn > DEBOUNCE:
            last_btn = now
            capturing = False
            if capture_thread:
                capture_thread.join(timeout=2)
            freq_idx = (freq_idx + 1) % len(FREQUENCIES)
            capturing = True
            capture_thread = threading.Thread(target=_capture_loop, daemon=True)
            capture_thread.start()

        if btn == "KEY2" and now - last_btn > DEBOUNCE:
            last_btn = now
            hopping = not hopping

        if btn == "UP" and now - last_btn > DEBOUNCE:
            last_btn = now
            cursor = max(0, cursor - 1)

        if btn == "DOWN" and now - last_btn > DEBOUNCE:
            last_btn = now
            cursor = min(max(0, len(signals) - 1), cursor + 1)

        if btn == "KEY1" and now - last_btn > DEBOUNCE and signals and cursor < len(signals):
            last_btn = now
            sig = signals[cursor]
            while _running:
                _show_signal_detail(sig)
                b2 = get_button(PINS, GPIO)
                if b2 == "KEY3" or b2 == "KEY1":
                    break
                time.sleep(0.1)

        if btn == "OK" and now - last_btn > DEBOUNCE and signals and cursor < len(signals):
            last_btn = now
            sig = signals[cursor]
            os.makedirs(LOOT_DIR, exist_ok=True)
            ts = time.strftime("%Y%m%d_%H%M%S")
            fname = f"{sig.protocol}_{ts}.sub"
            raw = sig.extra.get("_raw_pulses", [])
            gps = _get_gps_coords()
            if gps:
                sig.extra["gps"] = gps
            save_sub_file(os.path.join(LOOT_DIR, fname), signal=sig,
                         raw_pulses=raw if raw else None,
                         frequency=sig.frequency, preset=sig.modulation)
            gps_msg = f" GPS:{gps}" if gps else ""
            _draw_msg("Saved!", fname[:25] + gps_msg, C_GREEN)
            time.sleep(1)

        # Draw
        img = Image.new("RGB", (W, H), C_BG)
        d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

        freq_s = _freq_str(FREQUENCIES[freq_idx])
        preset_s = PRESETS[preset_idx]["name"]
        hop_s = " HOP" if hopping else ""
        _draw_header(d, f"{freq_s} MHz {preset_s}{hop_s}", f"{len(signals)} signals")

        if IS_WIDE:
            if not signals:
                blink = int(time.time() * 2) % 2
                dots = "." * (blink + 1)
                d.text((W // 2, H // 2), f"Waiting for signal{dots}", font=FONT,
                       fill=C_DIM, anchor="mm")
            else:
                y = 26
                item_h = 24
                vis = (H - 26 - 16) // item_h
                scroll = max(0, min(cursor - vis // 2, max(0, len(signals) - vis)))
                for i in range(scroll, min(scroll + vis, len(signals))):
                    sig = signals[i]
                    is_sel = i == cursor
                    ry = y + (i - scroll) * item_h
                    if is_sel:
                        d.rectangle([2, ry, W - 2, ry + item_h - 1], fill=C_SEL)
                    proto_color = C_ORANGE if is_sel else C_WHITE
                    d.text((6, ry + 2), sig.protocol, font=FONT_SM, fill=proto_color)
                    d.text((120, ry + 2), sig.key_hex[:16], font=FONT_SM, fill=C_WHITE)
                    rssi_s = sig.extra.get("rssi", "")
                    info_s = f"{sig.bit_count}b"
                    if rssi_s:
                        info_s += f" {rssi_s}dB"
                    d.text((W - 60, ry + 2), info_s, font=FONT_SM, fill=C_DIM)
        else:
            if not signals:
                d.text((64, 60), "Scanning...", font=FONT_SM, fill=C_DIM)
            else:
                y = 16
                vis = 6
                for i in range(scroll, min(scroll + vis, len(signals))):
                    sig = signals[i]
                    sel = i == cursor
                    d.text((2, y), f"{sig.protocol[:8]} {sig.key_hex[:8]}",
                           font=FONT_SM, fill=C_ORANGE if sel else C_DIM)
                    y += 14

        _draw_footer(d, "<>:Freq/Mod OK:Save K1:Info K2:Hop K3:Back")
        _show(img)
        time.sleep(0.15)


# ── Read RAW mode ─────────────────────────────────────────────────────────

def _mode_read_raw(radio):
    freq_idx = DEFAULT_FREQ_IDX
    preset_idx = DEFAULT_PRESET_IDX
    recording = False
    raw_pulses = []
    waveform = []
    last_btn = 0
    rec_start = 0

    while _running:
        btn = get_button(PINS, GPIO)
        now = time.time()

        if btn == "KEY3":
            radio.idle()
            return

        if btn == "OK" and now - last_btn > 0.3:
            last_btn = now
            if not recording:
                recording = True
                raw_pulses = []
                waveform = []
                rec_start = time.time()
                _apply_preset(radio, PRESETS[preset_idx]["name"])
                radio.set_frequency(FREQUENCIES[freq_idx] / 1_000_000)
                radio.set_raw_rx(for_capture=True)
            else:
                recording = False
                radio.idle()
                if raw_pulses:
                    os.makedirs(LOOT_DIR, exist_ok=True)
                    ts = time.strftime("%Y%m%d_%H%M%S")
                    fname = f"RAW_{ts}.sub"
                    save_sub_file(os.path.join(LOOT_DIR, fname), raw_pulses=raw_pulses,
                                 frequency=FREQUENCIES[freq_idx],
                                 preset=PRESETS[preset_idx]["name"])
                    _draw_msg("Saved!", fname, C_GREEN)
                    time.sleep(1)

        if btn == "LEFT" and now - last_btn > DEBOUNCE and not recording:
            last_btn = now
            freq_idx = (freq_idx - 1) % len(FREQUENCIES)

        if btn == "RIGHT" and now - last_btn > DEBOUNCE and not recording:
            last_btn = now
            freq_idx = (freq_idx + 1) % len(FREQUENCIES)

        if recording:
            chunk = _capture_raw(radio, duration_s=0.3)
            raw_pulses.extend(chunk)
            for p in chunk[-100:]:
                waveform.append(1 if p > 0 else 0)
            if len(waveform) > 200:
                waveform = waveform[-200:]

        img = Image.new("RGB", (W, H), C_BG)
        d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

        freq_s = _freq_str(FREQUENCIES[freq_idx])
        status = "REC" if recording else "IDLE"
        _draw_header(d, f"RAW {freq_s} MHz", status)

        if IS_WIDE:
            # Waveform visualization
            wave_y = 60
            wave_h = 50
            d.rectangle([4, wave_y, W - 4, wave_y + wave_h], outline=C_DIM)
            if waveform:
                wave_w = W - 8
                step = max(1, len(waveform) * 1.0 / wave_w)
                px = 4
                for i in range(min(len(waveform), wave_w)):
                    idx = min(int(i * step), len(waveform) - 1)
                    val = waveform[idx]
                    y1 = wave_y + (5 if val else wave_h - 5)
                    d.line([(px + i, y1), (px + i, wave_y + wave_h // 2)],
                           fill=C_GREEN if val else C_RED)

            if recording:
                elapsed = time.time() - rec_start
                mins = int(elapsed) // 60
                secs = int(elapsed) % 60
                size_kb = len(raw_pulses) * 6 // 1024
                d.text((W // 2, 35), f"REC {mins:02d}:{secs:02d}  {len(raw_pulses)} pulses  ~{size_kb}KB",
                       font=FONT_SM, fill=C_RED, anchor="mm")
            else:
                d.text((W // 2, 38), "Press OK to record",
                       font=FONT_SM, fill=C_DIM, anchor="mm")

            _draw_footer(d, f"OK:{'Stop+Save' if recording else 'Record'} <>:Freq K3:Back")
        else:
            d.text((4, 20), "OK: " + ("Stop" if recording else "Rec"), font=FONT_SM, fill=C_DIM)
            d.text((4, 35), f"{len(raw_pulses)} pulses", font=FONT_SM, fill=C_GREEN)

        _show(img)
        if not recording:
            time.sleep(0.1)


# ── Saved mode ────────────────────────────────────────────────────────────

def _mode_saved(radio):
    cursor = 0
    last_btn = 0

    while _running:
        files = []
        if os.path.isdir(LOOT_DIR):
            files = sorted([f for f in os.listdir(LOOT_DIR) if f.endswith(".sub")], reverse=True)

        btn = get_button(PINS, GPIO)
        now = time.time()

        if btn == "KEY3":
            return

        if btn == "UP" and now - last_btn > DEBOUNCE:
            last_btn = now
            cursor = max(0, cursor - 1)

        if btn == "DOWN" and now - last_btn > DEBOUNCE:
            last_btn = now
            cursor = min(max(0, len(files) - 1), cursor + 1)

        if btn == "OK" and now - last_btn > 0.3 and files and cursor < len(files):
            last_btn = now
            fpath = os.path.join(LOOT_DIR, files[cursor])
            sub = load_sub_file(fpath)
            rep = _select_repeat()
            if rep is None:
                continue
            if sub.get("raw_data"):
                _draw_msg("Sending...", f"{files[cursor][:20]} x{rep}", C_RED)
                _apply_preset(radio, sub.get("preset", "AM650"))
                radio.set_frequency(sub["frequency"] / 1_000_000)
                ok = radio.send_raw_pulses(sub["raw_data"], repeat=rep)
                radio.start_rx()
                _draw_msg("Sent!" if ok else "TX Failed", "", C_GREEN if ok else C_RED)
                time.sleep(1)
            elif sub.get("protocol") and (sub.get("key") is not None or sub.get("data") is not None):
                _draw_msg("Sending...", f"{sub['protocol']} {sub['bit_count']}b x{rep}", C_RED)
                _apply_preset(radio, sub.get("preset", "AM650"))
                freq = sub.get("frequency", 433920000)
                radio.set_frequency(freq / 1_000_000)
                key_data = sub.get("key", sub.get("data", 0))
                for p in ALL_PROTOCOLS:
                    if p.name == sub["protocol"] and hasattr(p, "encode"):
                        raw = p.encode(key_data, sub.get("bit_count"))
                        if raw:
                            ok = radio.send_raw_pulses(raw, repeat=rep)
                            radio.start_rx()
                            _draw_msg("Sent!" if ok else "TX Failed", "", C_GREEN if ok else C_RED)
                            time.sleep(1)
                            break
                else:
                    _draw_msg("No encoder", sub["protocol"], C_ORANGE)
                    time.sleep(2)

        if btn == "KEY1" and now - last_btn > 0.3 and files and cursor < len(files):
            last_btn = now
            fpath = os.path.join(LOOT_DIR, files[cursor])
            try:
                os.remove(fpath)
                _draw_msg("Deleted!", files[cursor][:20], C_RED)
                cursor = max(0, cursor - 1)
            except Exception:
                pass
            time.sleep(1)

        if btn == "KEY2" and now - last_btn > 0.3 and files and cursor < len(files):
            last_btn = now
            new_name = _input_text("Rename", files[cursor].replace(".sub", ""))
            if new_name and new_name != files[cursor].replace(".sub", ""):
                old_path = os.path.join(LOOT_DIR, files[cursor])
                new_path = os.path.join(LOOT_DIR, new_name + ".sub")
                try:
                    os.rename(old_path, new_path)
                    _draw_msg("Renamed!", new_name[:20], C_GREEN)
                except Exception:
                    _draw_msg("Rename failed", "", C_RED)
                time.sleep(1)

        img = Image.new("RGB", (W, H), C_BG)
        d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
        _draw_header(d, "Saved", f"{len(files)}")

        if IS_WIDE:
            if not files:
                d.text((W // 2, H // 2), "No saved signals", font=FONT, fill=C_DIM, anchor="mm")
            else:
                y = 26
                item_h = 20
                vis = (H - 26 - 16) // item_h
                sc = max(0, min(cursor - vis // 2, max(0, len(files) - vis)))
                for i in range(sc, min(sc + vis, len(files))):
                    is_sel = i == cursor
                    ry = y + (i - sc) * item_h
                    if is_sel:
                        d.rectangle([2, ry, W - 2, ry + item_h - 1], fill=C_SEL)
                    name = files[i].replace(".sub", "")
                    d.text((6, ry + 2), name[:35], font=FONT_SM,
                           fill=C_ORANGE if is_sel else C_WHITE)
            _draw_footer(d, "OK:Send K1:Del K2:Rename K3:Back")
        else:
            if not files:
                d.text((4, 50), "No files", font=FONT_SM, fill=C_DIM)
            else:
                y = 16
                for i in range(min(6, len(files))):
                    sel = i == cursor
                    d.text((2, y), files[i][:18], font=FONT_SM,
                           fill=C_ORANGE if sel else C_DIM)
                    y += 14
            _draw_footer(d, "OK:Send K1:Del K3:Back")

        _show(img)
        time.sleep(0.1)


# ── Frequency Analyzer ───────────────────────────────────────────────────

def _mode_freq_analyzer(radio):
    scan_freqs = [
        300000000, 315000000, 390000000, 433920000,
        868350000, 868950000, 915000000,
    ]
    best_freq = 0
    best_rssi = -130
    rssi_values = [(-130, f) for f in scan_freqs]
    peak_rssi = {f: -130 for f in scan_freqs}
    peak_freq = 0
    peak_best = -130
    last_btn = 0

    _apply_preset(radio, "AM650")

    while _running:
        btn = get_button(PINS, GPIO)
        now = time.time()
        if btn == "KEY3":
            radio.idle()
            return
        if btn == "KEY1" and now - last_btn > 0.3:
            last_btn = now
            peak_rssi = {f: -130 for f in scan_freqs}
            peak_freq = 0
            peak_best = -130
        if btn == "KEY2" and now - last_btn > 0.3:
            last_btn = now
            freq = _input_frequency()
            if freq:
                scan_freqs = [int(freq * 1_000_000)]
                peak_rssi = {scan_freqs[0]: -130}

        new_best = -130
        new_best_freq = 0
        rssi_values = []
        for freq in scan_freqs:
            radio.set_frequency(freq / 1_000_000)
            radio.start_rx()
            time.sleep(0.02)
            rssi = radio.get_rssi()
            rssi_values.append((rssi, freq))
            if rssi > new_best:
                new_best = rssi
                new_best_freq = freq
            if rssi > peak_rssi.get(freq, -130):
                peak_rssi[freq] = rssi
            if rssi > peak_best:
                peak_best = rssi
                peak_freq = freq
        best_rssi = new_best
        best_freq = new_best_freq

        img = Image.new("RGB", (W, H), C_BG)
        d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
        _draw_header(d, "Freq Analyzer")

        if IS_WIDE:
            d.text((W // 2, 35), f"{_freq_str(best_freq)} MHz",
                   font=FONT_XL, fill=C_ORANGE, anchor="mm")
            d.text((W // 2, 52), f"RSSI: {best_rssi:.0f} dBm",
                   font=FONT, fill=C_WHITE, anchor="mm")
            if peak_best > -120:
                d.text((W // 2, 66), f"Peak: {_freq_str(peak_freq)} MHz {peak_best:.0f}dB",
                       font=FONT_SM, fill=C_DIM, anchor="mm")

            bar_y = 75
            bar_h = 45
            bar_w = max(4, (W - 20) // len(scan_freqs) - 2)
            for i, (rssi, freq) in enumerate(rssi_values):
                x = 10 + i * (bar_w + 2)
                norm = max(0, min(1, (rssi + 120) / 70))
                h = int(norm * bar_h)
                color = C_GREEN if freq == best_freq else C_BLUE
                if h > 2:
                    d.rectangle([x, bar_y + bar_h - h, x + bar_w, bar_y + bar_h], fill=color)
                pk = peak_rssi.get(freq, -130)
                pk_norm = max(0, min(1, (pk + 120) / 70))
                pk_y = bar_y + bar_h - int(pk_norm * bar_h)
                if pk > -120:
                    d.rectangle([x, pk_y - 1, x + bar_w, pk_y + 1], fill=C_RED)
                if h > 2:
                    d.text((x + bar_w // 2, bar_y + bar_h - h - 10),
                           f"{rssi:.0f}", font=FONT_SM, fill=C_WHITE, anchor="ma")
                d.text((x + bar_w // 2, bar_y + bar_h + 4),
                       f"{freq // 1000000}", font=FONT_SM, fill=C_DIM, anchor="ma")
        else:
            d.text((4, 20), f"{_freq_str(best_freq)} MHz", font=FONT, fill=C_ORANGE)
            d.text((4, 38), f"RSSI: {best_rssi:.0f} dBm", font=FONT_SM, fill=C_WHITE)
            if peak_best > -120:
                d.text((4, 52), f"Peak: {peak_best:.0f}dB", font=FONT_SM, fill=C_DIM)

        _draw_footer(d, "K1:Reset K2:CustomFreq K3:Back")
        _show(img)


# ── Text input helper ────────────────────────────────────────────────────

def _input_text(title, initial="", hex_only=False):
    text = initial
    last_btn = 0
    last_char = 0

    while _running:
        btn = get_button(PINS, GPIO)
        now = time.time()
        typed = _get_hex_char() if EVDEV_OK and hex_only else None

        if typed and now - last_char > 0.12:
            last_char = now
            if typed == '\b':
                text = text[:-1]
            elif typed == '\n':
                return text
            elif len(text) < 40:
                text += typed

        if btn == "KEY3":
            return None
        if btn == "OK" and now - last_btn > 0.2 and text:
            last_btn = now
            return text
        if btn == "KEY2" and now - last_btn > 0.12:
            last_btn = now
            text = text[:-1]

        img = Image.new("RGB", (W, H), C_BG)
        d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
        _draw_header(d, title)
        blink = int(now * 2) % 2
        cur = "|" if blink else ""
        if IS_WIDE:
            d.rectangle([10, 40, W - 10, 62], fill=C_DARK)
            d.text((14, 43), f"{text}{cur}", font=FONT, fill=C_WHITE)
            _draw_footer(d, "OK:Confirm K2:Del K3:Cancel")
        else:
            d.rectangle([2, 20, 126, 34], fill=C_DARK)
            d.text((4, 22), f"{text}{cur}", font=FONT_SM, fill=C_WHITE)
            _draw_footer(d, "OK K2:Del K3:Cancel")
        _show(img)
        time.sleep(0.05)
    return None


# ── Add Manually mode ────────────────────────────────────────────────────

def _mode_add_manually(radio):
    encodable = [p for p in ALL_PROTOCOLS if hasattr(p, "encode") and p.encode(0, 1) is not None]
    if not encodable:
        _draw_msg("No encoders", "available", C_RED)
        time.sleep(2)
        return

    proto_sel = 0
    last_btn = 0
    state = "proto"

    while _running:
        btn = get_button(PINS, GPIO)
        now = time.time()

        if btn == "KEY3":
            if state == "proto":
                return
            state = "proto"
            continue

        if state == "proto":
            if btn == "UP" and now - last_btn > DEBOUNCE:
                last_btn = now
                proto_sel = (proto_sel - 1) % len(encodable)
            if btn == "DOWN" and now - last_btn > DEBOUNCE:
                last_btn = now
                proto_sel = (proto_sel + 1) % len(encodable)
            if btn == "OK" and now - last_btn > 0.2:
                last_btn = now
                state = "key"
                continue

            img = Image.new("RGB", (W, H), C_BG)
            d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
            _draw_header(d, "Add Manually")
            if IS_WIDE:
                y = 28
                vis = (H - 28 - 16) // 22
                sc = max(0, min(proto_sel - vis // 2, max(0, len(encodable) - vis)))
                for i in range(sc, min(sc + vis, len(encodable))):
                    is_sel = i == proto_sel
                    ry = y + (i - sc) * 22
                    if is_sel:
                        d.rectangle([4, ry, W - 4, ry + 20], fill=C_SEL)
                    d.text((10, ry + 2), encodable[i].name, font=FONT,
                           fill=C_ORANGE if is_sel else C_WHITE)
            _draw_footer(d, "OK:Select ^v:Scroll K3:Back")
            _show(img)

        elif state == "key":
            key_hex = _input_text("Key (hex)", "", hex_only=True)
            if key_hex is None:
                state = "proto"
                continue
            try:
                key_val = int(key_hex, 16)
            except ValueError:
                _draw_msg("Invalid hex", key_hex, C_RED)
                time.sleep(1)
                state = "proto"
                continue

            bits_str = _input_text("Bit count", "12")
            if bits_str is None:
                state = "proto"
                continue
            try:
                bit_count = int(bits_str)
            except ValueError:
                bit_count = 12

            freq_idx_local = DEFAULT_FREQ_IDX
            _draw_msg("Freq", f"{_freq_str(FREQUENCIES[freq_idx_local])} MHz", C_ORANGE)
            time.sleep(0.5)

            proto = encodable[proto_sel]
            raw = proto.encode(key_val, bit_count)
            if raw:
                _draw_msg("Sending...", f"{proto.name} {bit_count}b", C_RED)
                _apply_preset(radio, "AM650")
                radio.set_frequency(FREQUENCIES[freq_idx_local] / 1_000_000)
                ok = radio.send_raw_pulses(raw, repeat=5)
                radio.start_rx()
                _draw_msg("Sent!" if ok else "TX Failed", "", C_GREEN if ok else C_RED)
            else:
                _draw_msg("Encode failed", "", C_RED)
            time.sleep(1)
            state = "proto"

        time.sleep(0.08)


# ── Bruteforce mode ──────────────────────────────────────────────────────

def _mode_bruteforce(radio):
    encodable = [p for p in ALL_PROTOCOLS if hasattr(p, "encode") and p.encode(0, 1) is not None]
    if not encodable:
        _draw_msg("No encoders", "", C_RED)
        time.sleep(2)
        return

    proto_sel = 0
    last_btn = 0
    step = "proto"
    bit_count = 12
    freq_idx_local = DEFAULT_FREQ_IDX
    delay_ms = 100

    while _running:
        btn = get_button(PINS, GPIO)
        now = time.time()

        if btn == "KEY3":
            if step == "proto":
                return
            step = "proto"
            continue

        if step == "proto":
            if btn == "UP" and now - last_btn > DEBOUNCE:
                last_btn = now
                proto_sel = (proto_sel - 1) % len(encodable)
            if btn == "DOWN" and now - last_btn > DEBOUNCE:
                last_btn = now
                proto_sel = (proto_sel + 1) % len(encodable)
            if btn == "OK" and now - last_btn > 0.2:
                last_btn = now
                step = "bits"
                continue

            img = Image.new("RGB", (W, H), C_BG)
            d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
            _draw_header(d, "Bruteforce")
            if IS_WIDE:
                y = 28
                vis = (H - 28 - 16) // 22
                sc = max(0, min(proto_sel - vis // 2, max(0, len(encodable) - vis)))
                for i in range(sc, min(sc + vis, len(encodable))):
                    is_sel = i == proto_sel
                    ry = y + (i - sc) * 22
                    if is_sel:
                        d.rectangle([4, ry, W - 4, ry + 20], fill=C_SEL)
                    d.text((10, ry + 2), encodable[i].name, font=FONT,
                           fill=C_ORANGE if is_sel else C_WHITE)
            _draw_footer(d, "OK:Select K3:Back")
            _show(img)

        elif step == "bits":
            bits_str = _input_text("Bit count", str(bit_count))
            if bits_str is None:
                step = "proto"
                continue
            try:
                bit_count = max(1, min(32, int(bits_str)))
            except ValueError:
                bit_count = 12
            step = "run"

        elif step == "run":
            proto = encodable[proto_sel]
            total = 1 << bit_count
            _apply_preset(radio, "AM650")
            radio.set_frequency(FREQUENCIES[freq_idx_local] / 1_000_000)

            for key in range(total):
                if not _running:
                    break
                b = get_button(PINS, GPIO)
                if b == "KEY3":
                    break

                raw = proto.encode(key, bit_count)
                if raw:
                    radio.send_raw_pulses(raw, repeat=3)

                if key % 5 == 0:
                    pct = key * 100 // total
                    img = Image.new("RGB", (W, H), C_BG)
                    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
                    _draw_header(d, "Bruteforce")
                    if IS_WIDE:
                        d.text((W // 2, 40), f"{proto.name} {bit_count}b",
                               font=FONT, fill=C_WHITE, anchor="mm")
                        d.text((W // 2, 60), f"Key: 0x{key:0{(bit_count+3)//4}X}",
                               font=FONT_LG, fill=C_ORANGE, anchor="mm")
                        d.text((W // 2, 80), f"{key}/{total} ({pct}%)",
                               font=FONT_SM, fill=C_DIM, anchor="mm")
                        bar_w = W - 40
                        d.rectangle([20, 100, 20 + bar_w, 112], fill=C_DARK)
                        fill_w = int(bar_w * pct / 100)
                        if fill_w > 0:
                            d.rectangle([20, 100, 20 + fill_w, 112], fill=C_ORANGE)
                    _draw_footer(d, "K3:Stop")
                    _show(img)

                time.sleep(delay_ms / 1000.0)

            radio.start_rx()
            _draw_msg("Bruteforce done", f"{proto.name} {bit_count}b", C_GREEN)
            time.sleep(2)
            step = "proto"

        time.sleep(0.08)


# ── Radio Settings mode ──────────────────────────────────────────────────

def _mode_radio_settings(radio):
    settings = [
        ("TX Power", ["Low", "Medium", "High", "Max"], 3),
        ("Default Preset", ["AM270", "AM650", "FM238", "FM476"], 1),
        ("Default Freq", [_freq_str(f) for f in FREQUENCIES], DEFAULT_FREQ_IDX),
    ]
    sel = 0
    last_btn = 0

    while _running:
        btn = get_button(PINS, GPIO)
        now = time.time()

        if btn == "KEY3":
            return

        if btn == "UP" and now - last_btn > DEBOUNCE:
            last_btn = now
            sel = (sel - 1) % len(settings)
        if btn == "DOWN" and now - last_btn > DEBOUNCE:
            last_btn = now
            sel = (sel + 1) % len(settings)
        if btn == "OK" and now - last_btn > 0.2:
            last_btn = now
            name, opts, cur = settings[sel]
            cur = (cur + 1) % len(opts)
            settings[sel] = (name, opts, cur)

        img = Image.new("RGB", (W, H), C_BG)
        d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
        _draw_header(d, "Radio Settings")

        if IS_WIDE:
            y = 30
            for i, (name, opts, cur) in enumerate(settings):
                is_sel = i == sel
                ry = y + i * 28
                if is_sel:
                    d.rectangle([4, ry, W - 4, ry + 24], fill=C_SEL)
                d.text((10, ry + 3), name, font=FONT, fill=C_ORANGE if is_sel else C_WHITE)
                d.text((W - 10, ry + 3), opts[cur], font=FONT_SM, fill=C_GREEN, anchor="ra")
        _draw_footer(d, "OK:Toggle ^v:Select K3:Back")
        _show(img)
        time.sleep(0.08)


# ── GPS helper for signal tagging ────────────────────────────────────────

def _get_gps_coords():
    try:
        from payloads._gps_helper import get_gps_data
        data = get_gps_data()
        if data and data.get("lat") and data.get("lon"):
            return "%.6f,%.6f" % (data["lat"], data["lon"])
    except Exception:
        pass
    return None


# ── Decode .sub mode ─────────────────────────────────────────────────────

def _mode_decode_sub(radio):
    cursor = 0
    last_btn = 0
    view = "browse"
    decoded_signals = []
    sub_info = None
    sig_cursor = 0

    while _running:
        files = []
        if os.path.isdir(LOOT_DIR):
            files = sorted([f for f in os.listdir(LOOT_DIR) if f.endswith(".sub")], reverse=True)

        btn = get_button(PINS, GPIO)
        now = time.time()

        if btn == "KEY3":
            if view == "browse":
                return
            elif view == "detail":
                view = "browse"
                continue
            elif view == "signal":
                view = "detail"
                continue

        if view == "browse":
            if btn == "UP" and now - last_btn > DEBOUNCE:
                last_btn = now
                cursor = max(0, cursor - 1)
            if btn == "DOWN" and now - last_btn > DEBOUNCE:
                last_btn = now
                cursor = min(max(0, len(files) - 1), cursor + 1)
            if btn == "OK" and now - last_btn > 0.3 and files and cursor < len(files):
                last_btn = now
                fpath = os.path.join(LOOT_DIR, files[cursor])
                _draw_msg("Decoding...", files[cursor][:20], C_ORANGE)
                try:
                    sub_info, decoded_signals = decode_sub_file(fpath)
                    sig_cursor = 0
                    view = "detail"
                except Exception as e:
                    _draw_msg("Error", str(e)[:25], C_RED)
                    time.sleep(2)

            img = Image.new("RGB", (W, H), C_BG)
            d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
            _draw_header(d, "Decode .sub", f"{len(files)}")
            if IS_WIDE:
                if not files:
                    d.text((W // 2, H // 2), "No .sub files", font=FONT, fill=C_DIM, anchor="mm")
                else:
                    y = 26
                    item_h = 20
                    vis = (H - 26 - 16) // item_h
                    sc = max(0, min(cursor - vis // 2, max(0, len(files) - vis)))
                    for i in range(sc, min(sc + vis, len(files))):
                        is_sel = i == cursor
                        ry = y + (i - sc) * item_h
                        if is_sel:
                            d.rectangle([2, ry, W - 2, ry + item_h - 1], fill=C_SEL)
                        name = files[i].replace(".sub", "")
                        d.text((6, ry + 2), name[:35], font=FONT_SM,
                               fill=C_ORANGE if is_sel else C_WHITE)
            else:
                y = 16
                for i in range(min(6, len(files))):
                    sel = i == cursor
                    d.text((2, y), files[i][:18], font=FONT_SM,
                           fill=C_ORANGE if sel else C_DIM)
                    y += 14
            _draw_footer(d, "OK:Decode K3:Back")
            _show(img)

        elif view == "detail":
            if btn == "UP" and now - last_btn > DEBOUNCE and decoded_signals:
                last_btn = now
                sig_cursor = max(0, sig_cursor - 1)
            if btn == "DOWN" and now - last_btn > DEBOUNCE and decoded_signals:
                last_btn = now
                sig_cursor = min(len(decoded_signals) - 1, sig_cursor + 1)
            if btn == "OK" and now - last_btn > 0.3 and decoded_signals:
                last_btn = now
                view = "signal"
            if btn == "KEY1" and now - last_btn > 0.3 and sub_info:
                last_btn = now
                if sub_info.get("raw_data"):
                    _draw_msg("Sending RAW...", "", C_RED)
                    _apply_preset(radio, sub_info.get("preset", "AM650"))
                    radio.set_frequency(sub_info["frequency"] / 1_000_000)
                    ok = radio.send_raw_pulses(sub_info["raw_data"], repeat=3)
                    radio.start_rx()
                    _draw_msg("Sent!" if ok else "TX Failed", "", C_GREEN if ok else C_RED)
                    time.sleep(1)
                elif decoded_signals:
                    sig = decoded_signals[sig_cursor]
                    _apply_preset(radio, sub_info.get("preset", "AM650"))
                    radio.set_frequency(sub_info["frequency"] / 1_000_000)
                    for p in ALL_PROTOCOLS:
                        if p.name == sig.protocol and hasattr(p, "encode"):
                            raw = p.encode(sig.data, sig.bit_count)
                            if raw:
                                _draw_msg("Sending...", sig.protocol, C_RED)
                                ok = radio.send_raw_pulses(raw, repeat=5)
                                radio.start_rx()
                                _draw_msg("Sent!" if ok else "TX Failed", "", C_GREEN if ok else C_RED)
                                time.sleep(1)
                                break
                    else:
                        _draw_msg("No encoder", sig.protocol, C_ORANGE)
                        time.sleep(1)

            img = Image.new("RGB", (W, H), C_BG)
            d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
            fname = files[cursor] if cursor < len(files) else "?"
            ftype = "RAW" if sub_info and sub_info.get("is_raw") else "KEY"
            _draw_header(d, f"Decode [{ftype}]", f"{len(decoded_signals)} found")

            if IS_WIDE:
                freq_s = _freq_str(sub_info["frequency"]) if sub_info else "?"
                d.text((6, 26), f"File: {fname[:30]}", font=FONT_SM, fill=C_DIM)
                d.text((6, 40), f"Freq: {freq_s} MHz  Preset: {sub_info.get('preset', '?')}",
                       font=FONT_SM, fill=C_DIM)

                if not decoded_signals:
                    d.text((W // 2, 80), "No protocols decoded", font=FONT, fill=C_DIM, anchor="mm")
                else:
                    y = 56
                    item_h = 22
                    vis = (H - 56 - 16) // item_h
                    sc = max(0, min(sig_cursor - vis // 2, max(0, len(decoded_signals) - vis)))
                    for i in range(sc, min(sc + vis, len(decoded_signals))):
                        sig = decoded_signals[i]
                        is_sel = i == sig_cursor
                        ry = y + (i - sc) * item_h
                        if is_sel:
                            d.rectangle([2, ry, W - 2, ry + item_h - 1], fill=C_SEL)
                        d.text((6, ry + 3), f"{sig.protocol} {sig.bit_count}b {sig.key_hex}",
                               font=FONT_SM, fill=C_ORANGE if is_sel else C_WHITE)
            _draw_footer(d, "OK:Info K1:Send K3:Back")
            _show(img)

        elif view == "signal" and decoded_signals and sig_cursor < len(decoded_signals):
            sig = decoded_signals[sig_cursor]
            _show_signal_detail(sig)

            btn2 = get_button(PINS, GPIO)
            if btn2 == "KEY3":
                view = "detail"

        time.sleep(0.1)


def _show_signal_detail(sig):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
    _draw_header(d, sig.protocol)

    if IS_WIDE:
        y = 28
        lh = 16
        n = max(1, (sig.bit_count + 7) // 8)
        yek = _reverse_key(sig.data, sig.bit_count)

        lines = [
            ("Key", sig.key_hex),
            ("Yek", f"0x{yek:0{n*2}X}"),
            ("Bit", str(sig.bit_count)),
        ]
        if sig.serial:
            lines.append(("Serial", f"0x{sig.serial:05X}"))
        if sig.btn:
            lines.append(("Button", f"0x{sig.btn:X}"))
        if sig.cnt:
            lines.append(("Counter", f"0x{sig.cnt:04X}"))
        if sig.te:
            lines.append(("TE", f"{sig.te}us"))
        lines.append(("Freq", f"{sig.frequency / 1e6:.3f} MHz"))
        lines.append(("Mod", sig.modulation))
        rssi = sig.extra.get("rssi", "")
        if rssi:
            lines.append(("RSSI", f"{rssi} dBm"))

        for label, val in lines:
            if y + lh > H - 16:
                break
            d.text((6, y), f"{label}:", font=FONT_SM, fill=C_DIM)
            d.text((80, y), val, font=FONT_SM, fill=C_WHITE)
            y += lh
    else:
        d.text((4, 18), sig.key_hex[:16], font=FONT_SM, fill=C_WHITE)
        d.text((4, 32), f"{sig.bit_count}b {sig.protocol}", font=FONT_SM, fill=C_DIM)

    _draw_footer(d, "K3:Back")
    _show(img)


# ── Custom frequency input ──────────────────────────────────────────────

def _input_frequency():
    text = "433.92"
    last_btn = 0
    last_char = 0

    while _running:
        btn = get_button(PINS, GPIO)
        now = time.time()
        typed = _get_hex_char() if EVDEV_OK else None

        if typed and now - last_char > 0.12:
            last_char = now
            if typed == '\b':
                text = text[:-1]
            elif typed == '\n' and text:
                try:
                    freq = float(text)
                    if 300 <= freq <= 928:
                        return freq
                except ValueError:
                    pass
                return None
            elif typed in '0123456789.' and len(text) < 10:
                text += typed

        if btn == "KEY3":
            return None
        if btn == "OK" and now - last_btn > 0.2 and text:
            last_btn = now
            try:
                freq = float(text)
                if 300 <= freq <= 928:
                    return freq
            except ValueError:
                pass

        img = Image.new("RGB", (W, H), C_BG)
        d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
        _draw_header(d, "Custom Freq")
        if IS_WIDE:
            d.text((W // 2, 50), "Enter frequency (MHz):", font=FONT, fill=C_DIM, anchor="mm")
            blink = int(now * 2) % 2
            cur = "|" if blink else ""
            d.rectangle([40, 70, W - 40, 94], fill=C_DARK)
            d.text((W // 2, 82), f"{text}{cur}", font=FONT_LG, fill=C_ORANGE, anchor="mm")
            d.text((W // 2, 110), "Range: 300-928 MHz", font=FONT_SM, fill=C_DIM, anchor="mm")
        else:
            d.text((4, 20), "Freq (MHz):", font=FONT_SM, fill=C_DIM)
            d.text((4, 35), text, font=FONT, fill=C_ORANGE)
        _draw_footer(d, "OK:Set K3:Cancel")
        _show(img)
        time.sleep(0.08)
    return None


# ── Repeat count selector ───────────────────────────────────────────────

def _select_repeat():
    options = [1, 3, 5, 10, 20]
    sel = 1
    last_btn = 0

    while _running:
        btn = get_button(PINS, GPIO)
        now = time.time()

        if btn == "KEY3":
            return None
        if btn == "UP" and now - last_btn > DEBOUNCE:
            last_btn = now
            sel = (sel - 1) % len(options)
        if btn == "DOWN" and now - last_btn > DEBOUNCE:
            last_btn = now
            sel = (sel + 1) % len(options)
        if btn == "OK" and now - last_btn > 0.2:
            return options[sel]

        img = Image.new("RGB", (W, H), C_BG)
        d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
        _draw_header(d, "Repeat Count")
        if IS_WIDE:
            y = 35
            for i, opt in enumerate(options):
                is_sel = i == sel
                ry = y + i * 24
                if is_sel:
                    d.rectangle([40, ry, W - 40, ry + 22], fill=C_SEL)
                d.text((W // 2, ry + 11), f"{opt}x", font=FONT,
                       fill=C_ORANGE if is_sel else C_WHITE, anchor="mm")
        else:
            y = 18
            for i, opt in enumerate(options):
                sel_c = C_ORANGE if i == sel else C_DIM
                d.text((4, y), f"{'>' if i == sel else ' '}{opt}x", font=FONT_SM, fill=sel_c)
                y += 16
        _draw_footer(d, "OK:Select K3:Cancel")
        _show(img)
        time.sleep(0.08)
    return None


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    global _radio

    if not CC1101_OK or not PROTO_OK:
        _draw_msg("Missing module", "cc1101_driver/protocols", C_RED)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    _draw_msg("Sub-GHz", "Connecting CC1101...", C_ORANGE)

    _radio = CC1101()
    if not _radio.open():
        _draw_msg("CC1101 HAT", "not found", C_RED)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    menu_sel = 0
    last_btn = 0

    try:
        while _running:
            _draw_menu(menu_sel)
            btn = get_button(PINS, GPIO)
            now = time.time()

            if btn == "KEY3":
                break

            if btn == "UP" and now - last_btn > DEBOUNCE:
                last_btn = now
                menu_sel = (menu_sel - 1) % len(MENU_ITEMS)

            if btn == "DOWN" and now - last_btn > DEBOUNCE:
                last_btn = now
                menu_sel = (menu_sel + 1) % len(MENU_ITEMS)

            if btn == "OK" and now - last_btn > DEBOUNCE:
                last_btn = now
                if menu_sel == 0:
                    _mode_read(_radio)
                elif menu_sel == 1:
                    _mode_read_raw(_radio)
                elif menu_sel == 2:
                    _mode_saved(_radio)
                elif menu_sel == 3:
                    _mode_decode_sub(_radio)
                elif menu_sel == 4:
                    _mode_freq_analyzer(_radio)
                elif menu_sel == 5:
                    _mode_add_manually(_radio)
                elif menu_sel == 6:
                    _mode_bruteforce(_radio)
                elif menu_sel == 7:
                    _mode_radio_settings(_radio)

            time.sleep(0.08)

    finally:
        if _radio:
            _radio.close()
        LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
        LCD.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
