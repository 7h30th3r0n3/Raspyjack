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
        ALL_PROTOCOLS, DecodedSignal, save_sub_file, load_sub_file, decode_raw_pulses,
    )
    PROTO_OK = True
except ImportError:
    PROTO_OK = False

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

MENU_ITEMS = ["Read", "Read RAW", "Saved", "Freq Analyzer"]


def _draw_menu(sel):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
    _draw_header(d, "Sub-GHz")

    if IS_WIDE:
        y = 30
        for i, item in enumerate(MENU_ITEMS):
            is_sel = i == sel
            if is_sel:
                d.rectangle([4, y, W - 4, y + 22], fill=C_SEL)
                d.text((12, y + 3), f"> {item}", font=FONT, fill=C_ORANGE)
            else:
                d.text((18, y + 3), item, font=FONT, fill=C_WHITE)
            y += 26
    else:
        y = 18
        for i, item in enumerate(MENU_ITEMS):
            is_sel = i == sel
            color = C_ORANGE if is_sel else C_WHITE
            prefix = ">" if is_sel else " "
            d.text((4, y), f"{prefix}{item}", font=FONT_SM, fill=color)
            y += 18

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

    def _capture_loop():
        nonlocal signals
        _apply_preset(radio, PRESETS[preset_idx]["name"])
        radio.set_frequency(FREQUENCIES[freq_idx] / 1_000_000)
        radio.set_raw_rx()
        while capturing and _running:
            pulses = _capture_raw(radio, duration_s=1.0)
            if pulses:
                decoded = decode_raw_pulses(pulses)
                for sig in decoded:
                    sig.frequency = FREQUENCIES[freq_idx]
                    sig.modulation = PRESETS[preset_idx]["name"]
                    signals.insert(0, sig)
                    if len(signals) > 50:
                        signals = signals[:50]

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

        if btn == "UP" and now - last_btn > DEBOUNCE:
            last_btn = now
            cursor = max(0, cursor - 1)

        if btn == "DOWN" and now - last_btn > DEBOUNCE:
            last_btn = now
            cursor = min(max(0, len(signals) - 1), cursor + 1)

        if btn == "OK" and now - last_btn > DEBOUNCE and signals and cursor < len(signals):
            last_btn = now
            sig = signals[cursor]
            os.makedirs(LOOT_DIR, exist_ok=True)
            ts = time.strftime("%Y%m%d_%H%M%S")
            fname = f"{sig.protocol}_{ts}.sub"
            save_sub_file(os.path.join(LOOT_DIR, fname), signal=sig,
                         frequency=sig.frequency, preset=sig.modulation)
            _draw_msg("Saved!", fname[:25], C_GREEN)
            time.sleep(1)

        # Draw
        img = Image.new("RGB", (W, H), C_BG)
        d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

        freq_s = _freq_str(FREQUENCIES[freq_idx])
        preset_s = PRESETS[preset_idx]["name"]
        _draw_header(d, f"{freq_s} MHz {preset_s}", f"{len(signals)} signals")

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
                    d.text((W - 40, ry + 2), f"{sig.bit_count}b", font=FONT_SM, fill=C_DIM)
                    if sig.extra:
                        extra = " ".join(f"{v}" for v in list(sig.extra.values())[:2])
                        d.text((6, ry + 12), extra, font=FONT_SM, fill=C_BLUE)
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

        _draw_footer(d, "<>:Freq/Mod ^v:Scroll OK:Save K3:Back")
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
                d.text((W // 2, 38), f"Recording... {len(raw_pulses)} pulses",
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
            if sub.get("raw_data"):
                _draw_msg("Sending...", files[cursor][:20], C_RED)
                _apply_preset(radio, sub.get("preset", "AM650"))
                radio.set_frequency(sub["frequency"] / 1_000_000)
                ok = radio.send_raw_pulses(sub["raw_data"], repeat=3)
                radio.start_rx()
                _draw_msg("Sent!" if ok else "TX Failed", "", C_GREEN if ok else C_RED)
                time.sleep(1)
            elif sub.get("protocol"):
                _draw_msg("Info", f"{sub['protocol']} {sub['bit_count']}b", C_ORANGE)
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
            _draw_footer(d, "OK:Send K1:Delete K3:Back")
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
    last_btn = 0

    _apply_preset(radio, "AM650")

    while _running:
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            radio.idle()
            return

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
        best_rssi = new_best
        best_freq = new_best_freq

        img = Image.new("RGB", (W, H), C_BG)
        d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
        _draw_header(d, "Freq Analyzer")

        if IS_WIDE:
            d.text((W // 2, 38), f"{_freq_str(best_freq)} MHz",
                   font=FONT_XL, fill=C_ORANGE, anchor="mm")
            d.text((W // 2, 58), f"RSSI: {best_rssi:.0f} dBm",
                   font=FONT, fill=C_WHITE, anchor="mm")

            bar_y = 75
            bar_h = 50
            bar_w = max(4, (W - 20) // len(scan_freqs) - 2)
            for i, (rssi, freq) in enumerate(rssi_values):
                x = 10 + i * (bar_w + 2)
                norm = max(0, min(1, (rssi + 120) / 70))
                h = int(norm * bar_h)
                color = C_GREEN if freq == best_freq else C_BLUE
                if h > 2:
                    d.rectangle([x, bar_y + bar_h - h, x + bar_w, bar_y + bar_h], fill=color)
                d.text((x + bar_w // 2, bar_y + bar_h + 4),
                       f"{freq // 1000000}", font=FONT_SM, fill=C_DIM, anchor="ma")
        else:
            d.text((4, 20), f"{_freq_str(best_freq)} MHz", font=FONT, fill=C_ORANGE)
            d.text((4, 38), f"RSSI: {best_rssi:.0f} dBm", font=FONT_SM, fill=C_WHITE)

        _draw_footer(d, "K3:Back")
        _show(img)


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
                    _mode_freq_analyzer(_radio)

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
