#!/usr/bin/env python3
"""
RaspyJack Payload -- CC1101 Sub-GHz (Flipper-style)
=====================================================
Author: 7h30th3r0n3

Flipper Zero-style Sub-GHz transceiver using the CC1101 Cap HAT.
Read, decode, record, save and replay sub-GHz signals.

Modes:
  Read            Auto-decode known OOK protocols (CAME, Princeton, NICE, ...)
  Read RAW        Record raw OOK timing data, visualize waveform
  Saved           Browse and replay saved .sub files
  Freq Analyzer   Real-time RSSI sweep to find active frequencies

Controls:
  OK          Select / Start-Stop
  UP/DOWN     Navigate menu / scroll
  LEFT/RIGHT  Change frequency / navigate
  KEY1        Action (save / replay)
  KEY2        Back
  KEY3        Exit

Requires: CardputerZero Cap CC1101 HAT
"""

import os
import sys
import time
import signal
import threading
import json
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font, SX, SY
from payloads._input_helper import get_button
from payloads._cc1101_driver import CC1101

try:
    from payloads._cc1101_protocols import (
        decode_timings, save_sub_file, load_sub_file, DecodedSignal,
    )
    PROTO_OK = True
except ImportError:
    PROTO_OK = False

try:
    import gpiod
    GPIOD_OK = True
except ImportError:
    gpiod = None
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
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 13)
        font_sm = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 11)
        font_lg = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 16)
        font_xs = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 9)
    except Exception:
        font = scaled_font(9)
        font_sm = scaled_font(7)
        font_lg = scaled_font(12)
        font_xs = scaled_font(6)
else:
    font = scaled_font(9)
    font_sm = scaled_font(7)
    font_lg = scaled_font(12)
    font_xs = scaled_font(6)

LOOT_DIR = "/root/Raspyjack/loot/CC1101"
DEBOUNCE = 0.18
GDO0_PIN = 15

BANDS = [
    (315.00, "315 MHz"),
    (433.92, "433.92 MHz"),
    (868.00, "868 MHz"),
    (915.00, "915 MHz"),
]

C_BG = (10, 10, 20)
C_HEAD = (20, 30, 60)
C_ORANGE = (255, 165, 0)
C_GREEN = (0, 220, 80)
C_RED = (255, 60, 60)
C_WHITE = (255, 255, 255)
C_DIM = (80, 90, 110)
C_DARK = (15, 18, 30)
C_SEL = (30, 45, 80)
C_CYAN = (0, 200, 220)

_running = True
_last_btn = 0


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    if b:
        now = time.time()
        if now - _last_btn < DEBOUNCE:
            return None
        _last_btn = now
    return b


def _draw_ctx(img):
    if IS_WIDE:
        return ImageDraw.Draw(img)
    return ScaledDraw(img)


def _show_msg(text, sub="", color=C_ORANGE):
    img = Image.new("RGB", (W, H), C_BG)
    d = _draw_ctx(img)
    if IS_WIDE:
        d.text((W // 2, H // 2 - 12), text, font=font_lg, fill=color, anchor="mm")
        if sub:
            d.text((W // 2, H // 2 + 12), sub, font=font_sm, fill=C_DIM, anchor="mm")
    else:
        d.text((64, 50), text, font=font, fill=color)
        if sub:
            d.text((64, 68), sub, font=font_sm, fill=C_DIM)
    LCD.LCD_ShowImage(img, 0, 0)


def _header(d, title, right=""):
    if IS_WIDE:
        d.rectangle([0, 0, W, 24], fill=C_HEAD)
        d.text((8, 4), title, font=font_lg, fill=C_ORANGE)
        if right:
            d.text((W - 8, 4), right, font=font_sm, fill=C_DIM, anchor="ra")
    else:
        d.rectangle([0, 0, 128, 14], fill=C_HEAD)
        d.text((2, 1), title, font=font, fill=C_ORANGE)
        if right:
            d.text((90, 2), right, font=font_xs, fill=C_DIM)


def _footer(d, text):
    if IS_WIDE:
        d.rectangle([0, H - 18, W, H], fill=C_DARK)
        d.text((6, H - 16), text, font=font_xs, fill=C_DIM)
    else:
        d.rectangle([0, 117, 128, 128], fill=C_DARK)
        d.text((2, 118), text, font=font_xs, fill=C_DIM)


# ---------------------------------------------------------------------------
# GDO0 raw timing capture via gpiod edge events
# ---------------------------------------------------------------------------
def _capture_raw_timings(radio, duration=5.0):
    """Record GDO0 edge timings. Returns list of +/- microsecond durations."""
    if not GPIOD_OK:
        return []
    radio.set_raw_rx()
    timings = []
    try:
        chip = gpiod.Chip("/dev/gpiochip0")
        config = gpiod.LineSettings(
            direction=gpiod.line.Direction.INPUT,
            edge_detection=gpiod.line.Edge.BOTH,
        )
        req = chip.request_lines(config={GDO0_PIN: config}, consumer="cc1101-raw")
        deadline = time.time() + duration
        last_ts = None
        while time.time() < deadline and _running:
            if req.wait_edge_events(timeout=datetime.timedelta(milliseconds=100)):
                for event in req.read_edge_events():
                    ts = event.timestamp_ns / 1000
                    if last_ts is not None:
                        delta = int(ts - last_ts)
                        if event.event_type == gpiod.line.Edge.RISING:
                            timings.append(-delta)
                        else:
                            timings.append(delta)
                    last_ts = ts
        req.release()
    except Exception:
        pass
    radio.set_packet_rx()
    return timings


# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------
MENU_ITEMS = ["Read", "Read RAW", "Saved", "Freq Analyzer"]


def _draw_menu(sel, radio):
    img = Image.new("RGB", (W, H), C_BG)
    d = _draw_ctx(img)
    _header(d, "Sub-GHz", f"v{radio.get_version():02X}" if radio._opened else "")
    y = 28 if IS_WIDE else 18
    row_h = 28 if IS_WIDE else 22
    for i, item in enumerate(MENU_ITEMS):
        ry = y + i * row_h
        is_sel = i == sel
        if is_sel:
            d.rectangle([4, ry, W - 4, ry + row_h - 2], fill=C_SEL)
        color = C_ORANGE if is_sel else C_WHITE
        if IS_WIDE:
            d.text((20, ry + 5), item, font=font, fill=color)
        else:
            d.text((6, ry + 3), item, font=font_sm, fill=color)
    _footer(d, "OK:Select  K3:Exit")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Read mode — auto-decode OOK protocols
# ---------------------------------------------------------------------------
def _mode_read(radio):
    band_idx = 1
    freq = BANDS[band_idx][0]
    radio.set_frequency(freq)
    radio.set_profile("ook_4k8")
    decoded_list = []
    scroll = 0
    capturing = False
    cap_thread = None
    cap_timings = []

    def _capture_loop():
        nonlocal cap_timings
        while capturing and _running:
            chunk = _capture_raw_timings(radio, duration=2.0)
            if chunk:
                cap_timings = chunk
                if PROTO_OK:
                    hits = decode_timings(chunk, frequency=freq)
                    for h in hits:
                        decoded_list.insert(0, h)
                        if len(decoded_list) > 50:
                            decoded_list.pop()

    while _running:
        img = Image.new("RGB", (W, H), C_BG)
        d = _draw_ctx(img)
        _header(d, "Read", BANDS[band_idx][1])

        if capturing:
            blink = int(time.time() * 3) % 2
            if IS_WIDE:
                if blink:
                    d.ellipse([W - 20, 6, W - 10, 16], fill=C_RED)
            else:
                if blink:
                    d.ellipse([120, 3, 126, 9], fill=C_RED)

        y = 28 if IS_WIDE else 16
        row_h = 30 if IS_WIDE else 18
        visible = max(1, (H - 46 if IS_WIDE else H - 30) // row_h)

        if not decoded_list:
            if IS_WIDE:
                d.text((W // 2, H // 2 - 5), "Waiting for signals..." if capturing else "OK to start",
                       font=font, fill=C_DIM, anchor="mm")
            else:
                msg = "Waiting..." if capturing else "OK:Start"
                d.text((64, 60), msg, font=font_sm, fill=C_DIM)
        else:
            for vi in range(visible):
                idx = scroll + vi
                if idx >= len(decoded_list):
                    break
                sig = decoded_list[idx]
                ry = y + vi * row_h
                if vi == 0 and scroll == 0:
                    d.rectangle([2, ry, W - 2, ry + row_h - 2], fill=C_SEL)
                if IS_WIDE:
                    d.text((8, ry + 1), sig.protocol, font=font_sm, fill=C_CYAN)
                    d.text((100, ry + 1), sig.code_hex(), font=font_sm, fill=C_WHITE)
                    d.text((8, ry + 14), f"Btn:{sig.button} Ser:{sig.serial}", font=font_xs, fill=C_DIM)
                    d.text((W - 8, ry + 14), f"{sig.bits}bit", font=font_xs, fill=C_DIM, anchor="ra")
                else:
                    d.text((2, ry), f"{sig.protocol} {sig.code_hex()}", font=font_xs, fill=C_WHITE)
                    d.text((2, ry + 9), f"B:{sig.button} {sig.bits}b", font=font_xs, fill=C_DIM)

        status = "OK:Stop" if capturing else "OK:Start"
        _footer(d, f"{status} LR:Band K1:Save K3:Back")
        LCD.LCD_ShowImage(img, 0, 0)

        btn = _btn()
        if btn == "KEY3":
            capturing = False
            if cap_thread:
                cap_thread.join(timeout=3)
            break
        elif btn == "OK":
            if capturing:
                capturing = False
                if cap_thread:
                    cap_thread.join(timeout=3)
            else:
                capturing = True
                cap_thread = threading.Thread(target=_capture_loop, daemon=True)
                cap_thread.start()
        elif btn == "LEFT":
            band_idx = (band_idx - 1) % len(BANDS)
            freq = BANDS[band_idx][0]
            radio.set_frequency(freq)
        elif btn == "RIGHT":
            band_idx = (band_idx + 1) % len(BANDS)
            freq = BANDS[band_idx][0]
            radio.set_frequency(freq)
        elif btn == "UP" and scroll > 0:
            scroll -= 1
        elif btn == "DOWN" and scroll < max(0, len(decoded_list) - visible):
            scroll += 1
        elif btn == "KEY1" and decoded_list:
            sig = decoded_list[scroll]
            os.makedirs(LOOT_DIR, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = os.path.join(LOOT_DIR, f"{sig.protocol}_{ts}.sub")
            if sig.raw_timings and PROTO_OK:
                save_sub_file(path, sig.raw_timings, frequency=freq)
                _show_msg("Saved!", os.path.basename(path), C_GREEN)
            else:
                info = {"protocol": sig.protocol, "code": sig.code_hex(),
                        "bits": sig.bits, "button": sig.button,
                        "serial": sig.serial, "frequency": freq}
                with open(path.replace(".sub", ".json"), "w") as f:
                    json.dump(info, f, indent=2)
                _show_msg("Saved!", os.path.basename(path), C_GREEN)
            time.sleep(1)
        elif btn == "KEY2":
            capturing = False
            if cap_thread:
                cap_thread.join(timeout=3)
            break
        time.sleep(0.05)


# ---------------------------------------------------------------------------
# Read RAW mode — record raw OOK timing + waveform display
# ---------------------------------------------------------------------------
def _mode_read_raw(radio):
    band_idx = 1
    freq = BANDS[band_idx][0]
    radio.set_frequency(freq)
    radio.set_profile("ook_4k8")
    timings = []
    recording = False

    while _running:
        img = Image.new("RGB", (W, H), C_BG)
        d = _draw_ctx(img)
        _header(d, "Read RAW", BANDS[band_idx][1])

        if recording:
            blink = int(time.time() * 3) % 2
            if IS_WIDE and blink:
                d.ellipse([W - 20, 6, W - 10, 16], fill=C_RED)
                d.text((W - 55, 5), "REC", font=font_xs, fill=C_RED)

        if timings:
            _draw_waveform(d, timings)
            if IS_WIDE:
                d.text((8, H - 36), f"{len(timings)} edges", font=font_xs, fill=C_DIM)
        elif not recording:
            if IS_WIDE:
                d.text((W // 2, H // 2), "OK to record raw signal", font=font, fill=C_DIM, anchor="mm")
            else:
                d.text((64, 60), "OK:Record", font=font_sm, fill=C_DIM)

        status = "OK:Stop" if recording else "OK:Rec"
        _footer(d, f"{status} LR:Band K1:Save K3:Back")
        LCD.LCD_ShowImage(img, 0, 0)

        btn = _btn()
        if btn == "KEY3" or btn == "KEY2":
            break
        elif btn == "OK":
            if recording:
                recording = False
            else:
                recording = True
                timings = []
                _show_msg("Recording...", "5 seconds", C_RED)
                timings = _capture_raw_timings(radio, duration=5.0)
                recording = False
                if timings and PROTO_OK:
                    hits = decode_timings(timings, frequency=freq)
                    if hits:
                        _show_msg(f"Decoded: {hits[0].protocol}", hits[0].code_hex(), C_GREEN)
                        time.sleep(1.5)
        elif btn == "LEFT":
            band_idx = (band_idx - 1) % len(BANDS)
            freq = BANDS[band_idx][0]
            radio.set_frequency(freq)
        elif btn == "RIGHT":
            band_idx = (band_idx + 1) % len(BANDS)
            freq = BANDS[band_idx][0]
            radio.set_frequency(freq)
        elif btn == "KEY1" and timings and PROTO_OK:
            os.makedirs(LOOT_DIR, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = os.path.join(LOOT_DIR, f"RAW_{int(freq)}_{ts}.sub")
            save_sub_file(path, timings, frequency=freq)
            _show_msg("Saved!", os.path.basename(path), C_GREEN)
            time.sleep(1)
        time.sleep(0.05)


def _draw_waveform(d, timings):
    """Draw a mini waveform from timing data."""
    wave_y = 60 if IS_WIDE else 30
    wave_h = 40 if IS_WIDE else 25
    wave_w = W - 16 if IS_WIDE else 120
    x_start = 8 if IS_WIDE else 4

    total_us = sum(abs(t) for t in timings[:200])
    if total_us == 0:
        return
    scale = wave_w / total_us
    x = x_start
    hi_y = wave_y
    lo_y = wave_y + wave_h
    mid_y = wave_y + wave_h // 2
    col = C_GREEN
    for t in timings[:200]:
        px = max(1, int(abs(t) * scale))
        if x + px > x_start + wave_w:
            break
        if t > 0:
            d.line([(x, hi_y), (x + px, hi_y)], fill=col, width=1)
            if x > x_start:
                d.line([(x, lo_y), (x, hi_y)], fill=col, width=1)
        else:
            d.line([(x, lo_y), (x + px, lo_y)], fill=col, width=1)
            if x > x_start:
                d.line([(x, hi_y), (x, lo_y)], fill=col, width=1)
        x += px


# ---------------------------------------------------------------------------
# Saved mode — browse and replay .sub files
# ---------------------------------------------------------------------------
def _mode_saved(radio):
    os.makedirs(LOOT_DIR, exist_ok=True)
    files = sorted([f for f in os.listdir(LOOT_DIR) if f.endswith(".sub")], reverse=True)
    sel = 0
    scroll = 0

    while _running:
        files = sorted([f for f in os.listdir(LOOT_DIR) if f.endswith(".sub")], reverse=True)
        img = Image.new("RGB", (W, H), C_BG)
        d = _draw_ctx(img)
        _header(d, "Saved", f"{len(files)}")

        y = 28 if IS_WIDE else 16
        row_h = 22 if IS_WIDE else 14
        visible = max(1, (H - 46 if IS_WIDE else H - 30) // row_h)

        if not files:
            if IS_WIDE:
                d.text((W // 2, H // 2), "No saved signals", font=font, fill=C_DIM, anchor="mm")
            else:
                d.text((64, 60), "No signals", font=font_sm, fill=C_DIM)
        else:
            for vi in range(visible):
                idx = scroll + vi
                if idx >= len(files):
                    break
                ry = y + vi * row_h
                is_sel = idx == sel
                if is_sel:
                    d.rectangle([2, ry, W - 2, ry + row_h - 2], fill=C_SEL)
                name = files[idx].replace(".sub", "")
                max_chars = 35 if IS_WIDE else 18
                color = C_ORANGE if is_sel else C_WHITE
                if IS_WIDE:
                    d.text((8, ry + 3), name[:max_chars], font=font_sm, fill=color)
                else:
                    d.text((4, ry + 1), name[:max_chars], font=font_xs, fill=color)

        _footer(d, "OK:Replay K1:Delete K3:Back")
        LCD.LCD_ShowImage(img, 0, 0)

        btn = _btn()
        if btn == "KEY3" or btn == "KEY2":
            break
        elif btn == "UP":
            sel = max(0, sel - 1)
            if sel < scroll:
                scroll = sel
        elif btn == "DOWN":
            sel = min(len(files) - 1, sel + 1) if files else 0
            if sel >= scroll + visible:
                scroll = sel - visible + 1
        elif btn == "OK" and files and PROTO_OK:
            path = os.path.join(LOOT_DIR, files[sel])
            _show_msg("Replaying...", files[sel][:20], C_ORANGE)
            timings, freq, _ = load_sub_file(path)
            if timings:
                radio.set_frequency(freq)
                radio.set_profile("ook_4k8")
                _replay_timings(radio, timings)
                _show_msg("Sent!", f"{len(timings)} edges", C_GREEN)
            else:
                _show_msg("Empty file", "", C_RED)
            time.sleep(1)
        elif btn == "KEY1" and files:
            path = os.path.join(LOOT_DIR, files[sel])
            try:
                os.remove(path)
            except Exception:
                pass
            _show_msg("Deleted", files[sel][:20], C_RED)
            time.sleep(0.5)
            files = sorted([f for f in os.listdir(LOOT_DIR) if f.endswith(".sub")], reverse=True)
            sel = min(sel, max(0, len(files) - 1))
        time.sleep(0.05)


def _replay_timings(radio, timings):
    """Replay raw OOK timings via CC1101 TX + GDO0 bit-banging.
    Simplified: use CC1101 in async serial TX mode and toggle GDO0 via SPI."""
    if not GPIOD_OK:
        return
    radio.idle()
    radio._write_reg(0x02, 0x0D)
    radio._write_reg(0x08, 0x32)
    try:
        chip = gpiod.Chip("/dev/gpiochip0")
        config = gpiod.LineSettings(
            direction=gpiod.line.Direction.OUTPUT,
            output_value=gpiod.line.Value.INACTIVE,
        )
        req = chip.request_lines(config={GDO0_PIN: config}, consumer="cc1101-tx")
        radio._strobe(0x35)
        time.sleep(0.001)
        for t in timings:
            if not _running:
                break
            if t > 0:
                req.set_value(GDO0_PIN, gpiod.line.Value.ACTIVE)
                _usleep(t)
            else:
                req.set_value(GDO0_PIN, gpiod.line.Value.INACTIVE)
                _usleep(abs(t))
        req.set_value(GDO0_PIN, gpiod.line.Value.INACTIVE)
        req.release()
    except Exception:
        pass
    radio.idle()
    radio.set_packet_rx()


def _usleep(us):
    end = time.monotonic_ns() + us * 1000
    while time.monotonic_ns() < end:
        pass


# ---------------------------------------------------------------------------
# Frequency Analyzer — RSSI sweep
# ---------------------------------------------------------------------------
def _mode_freq_analyzer(radio):
    base_freqs = [300.0, 315.0, 390.0, 418.0, 433.92, 868.0, 915.0]
    sweep_range = 2.0
    step = 0.1
    rssi_map = {}

    while _running:
        img = Image.new("RGB", (W, H), C_BG)
        d = _draw_ctx(img)
        _header(d, "Freq Analyzer")

        bar_w = max(1, (W - 20) // len(base_freqs))
        bar_max_h = H - 60 if IS_WIDE else H - 40
        x = 10

        peak_freq = 0
        peak_rssi = -200

        for bf in base_freqs:
            radio.set_frequency(bf)
            radio._strobe(0x34)
            time.sleep(0.005)
            rssi = radio.get_rssi()
            rssi_map[bf] = rssi
            if rssi > peak_rssi:
                peak_rssi = rssi
                peak_freq = bf

            norm = max(0, min(1, (rssi + 110) / 60))
            bh = int(norm * bar_max_h)
            by = (H - 30 if IS_WIDE else H - 22) - bh

            if rssi > -70:
                col = C_RED
            elif rssi > -90:
                col = C_ORANGE
            else:
                col = C_GREEN
            d.rectangle([x, by, x + bar_w - 2, H - 30 if IS_WIDE else H - 22], fill=col)

            label = f"{int(bf)}"
            if IS_WIDE:
                d.text((x + bar_w // 2, H - 26), label, font=font_xs, fill=C_DIM, anchor="mm")
            else:
                d.text((x, H - 20), label[:3], font=font_xs, fill=C_DIM)
            x += bar_w

        if peak_freq > 0:
            if IS_WIDE:
                d.text((W // 2, 28), f"Peak: {peak_freq:.2f} MHz  ({peak_rssi:.0f} dBm)",
                       font=font_sm, fill=C_WHITE, anchor="mm")
            else:
                d.text((2, 16), f"{peak_freq:.1f}MHz {peak_rssi:.0f}dB", font=font_xs, fill=C_WHITE)

        _footer(d, "Scanning...  K3:Back")
        LCD.LCD_ShowImage(img, 0, 0)

        btn = _btn()
        if btn == "KEY3" or btn == "KEY2":
            break
        time.sleep(0.02)

    radio.idle()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    radio = CC1101()

    _show_msg("Sub-GHz", "Initializing...", C_ORANGE)
    if not radio.open():
        _show_msg("CC1101 HAT not found", "Check Cap connection", C_RED)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    ver = radio.get_version()
    _show_msg("Sub-GHz", f"CC1101 v0x{ver:02X} OK", C_GREEN)
    time.sleep(0.8)

    sel = 0
    try:
        while _running:
            _draw_menu(sel, radio)
            btn = _btn()
            if btn == "KEY3":
                break
            elif btn == "UP":
                sel = (sel - 1) % len(MENU_ITEMS)
            elif btn == "DOWN":
                sel = (sel + 1) % len(MENU_ITEMS)
            elif btn == "OK":
                if sel == 0:
                    _mode_read(radio)
                elif sel == 1:
                    _mode_read_raw(radio)
                elif sel == 2:
                    _mode_saved(radio)
                elif sel == 3:
                    _mode_freq_analyzer(radio)
            time.sleep(0.05)
    finally:
        radio.close()
        LCD.LCD_Clear()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
