#!/usr/bin/env python3
"""
RaspyJack Payload -- POCSAG/FLEX Pager Decoder
================================================
Author: 7h30th3r0n3

Passive pager message decoder for POCSAG and FLEX protocols.
Receives pager transmissions on common frequencies and decodes
messages in real-time using rtl_fm + multimon-ng.

Completely legal passive radio reception.

Controls:
  OK          : Start/Stop decoding
  UP/DOWN     : Scroll messages / select message
  LEFT/RIGHT  : Change frequency
  KEY1 (SPACE): Switch view (Live / Message / Stats)
  KEY2 (BKSP) : Export log to loot
  KEY3 (ESC)  : Exit

Requires: apt install rtl-sdr multimon-ng
"""

import os
import sys
import re
import time
import signal
import subprocess
import threading
import json
from datetime import datetime
from collections import defaultdict

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font, S, SX, SY
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

font = scaled_font(9)
font_sm = scaled_font(7)
font_lg = scaled_font(12)
font_xs = scaled_font(6)

LOOT_DIR = "/root/Raspyjack/loot/SDR/pocsag"
DEBOUNCE = 0.18
MAX_MESSAGES = 500
VIEWS = ["live", "message", "stats"]

FREQUENCIES = [
    {"name": "466.075 FR", "freq": 466075000, "desc": "France POCSAG"},
    {"name": "466.025 FR", "freq": 466025000, "desc": "France"},
    {"name": "466.050 FR", "freq": 466050000, "desc": "France"},
    {"name": "466.175 FR", "freq": 466175000, "desc": "France"},
    {"name": "153.350 FX", "freq": 153350000, "desc": "FLEX"},
    {"name": "157.900 US", "freq": 157900000, "desc": "US FLEX"},
    {"name": "152.480 US", "freq": 152480000, "desc": "US FLEX"},
    {"name": "929.613 US", "freq": 929612500, "desc": "US FLEX"},
]

# Theme colors
COL_BG = (10, 10, 18)
COL_HEADER = (13, 17, 23)
COL_POCSAG = (0, 230, 118)
COL_FLEX = (0, 229, 255)
COL_NUMERIC = (255, 215, 64)
COL_TONE = (255, 138, 101)
COL_ADDRESS = (124, 77, 255)
COL_MUTED = (136, 136, 136)
COL_DIM = (85, 85, 85)
COL_ACTIVE = (0, 230, 118)
COL_ERROR = (255, 82, 82)
COL_ROW_EVEN = (12, 16, 26)
COL_ROW_ODD = (10, 10, 18)
COL_FOOTER = (13, 17, 23)

# POCSAG line pattern: POCSAG512: Address: 1234567  Function: 0  Alpha:   Hello
_RE_POCSAG = re.compile(
    r"(POCSAG\d+):\s*Address:\s*(\d+)\s+Function:\s*(\d+)\s+"
    r"(Alpha|Numeric|Tone\s*Only)\s*:\s*(.*)"
)

# FLEX line pattern: FLEX: 2024-01-15 12:34:56 1200/2/K/A 12.345 [1234567] ALN  Hello
_RE_FLEX = re.compile(
    r"(FLEX):\s*\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+"
    r"[\d/]+/[A-Z]\s+[\d.]+\s+\[(\d+)\]\s+(\w+)\s+(.*)"
)

_running = True
_decoding = False
_rtl_proc = None
_mng_proc = None
_messages = []
_msg_lock = threading.Lock()
_addr_counts = defaultdict(int)
_start_time = None
_last_btn = 0


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _btn():
    global _last_btn
    for name, pin in PINS.items():
        if GPIO.input(pin) == 0:
            now = time.time()
            if now - _last_btn < DEBOUNCE:
                return None
            _last_btn = now
            return name
    return None


def _parse_line(line):
    """Parse a single multimon-ng output line into a message dict, or return None."""
    line = line.strip()
    if not line:
        return None

    m = _RE_POCSAG.match(line)
    if m:
        protocol = m.group(1)
        address = m.group(2)
        function = int(m.group(3))
        raw_type = m.group(4).strip()
        content = m.group(5).strip()

        if "Alpha" in raw_type:
            msg_type = "Alpha"
        elif "Numeric" in raw_type:
            msg_type = "Numeric"
        else:
            msg_type = "Tone"

        return {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "protocol": protocol,
            "address": address,
            "function": function,
            "type": msg_type,
            "message": content,
        }

    m = _RE_FLEX.match(line)
    if m:
        protocol = m.group(1)
        address = m.group(2)
        type_code = m.group(3).strip()
        content = m.group(4).strip()

        if type_code == "ALN":
            msg_type = "Alpha"
        elif type_code == "NUM":
            msg_type = "Numeric"
        elif type_code == "TON":
            msg_type = "Tone"
        else:
            msg_type = "Alpha"

        return {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "protocol": protocol,
            "address": address,
            "function": 0,
            "type": msg_type,
            "message": content,
        }

    return None


def _msg_color(msg):
    """Return the display color for a message based on its type and protocol."""
    if msg["protocol"] == "FLEX":
        return COL_FLEX
    if msg["type"] == "Numeric":
        return COL_NUMERIC
    if msg["type"] == "Tone":
        return COL_TONE
    return COL_POCSAG


# ---------------------------------------------------------------------------
# Decoder thread: rtl_fm | multimon-ng
# ---------------------------------------------------------------------------
def _decode_thread(freq):
    global _rtl_proc, _mng_proc

    rtl_cmd = [
        "rtl_fm", "-f", str(freq), "-s", "22050", "-g", "49.6", "-",
    ]
    mng_cmd = [
        "multimon-ng", "-t", "raw",
        "-a", "POCSAG512", "-a", "POCSAG1200", "-a", "POCSAG2400",
        "-a", "FLEX", "-f", "alpha", "-",
    ]

    try:
        _rtl_proc = subprocess.Popen(
            rtl_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        _mng_proc = subprocess.Popen(
            mng_cmd, stdin=_rtl_proc.stdout, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1,
        )
        # Allow rtl_fm to receive SIGPIPE when multimon-ng exits
        _rtl_proc.stdout.close()

        for line in _mng_proc.stdout:
            if not _decoding:
                break
            parsed = _parse_line(line)
            if parsed is None:
                continue
            with _msg_lock:
                _messages.append(parsed)
                if len(_messages) > MAX_MESSAGES:
                    _messages.pop(0)
                _addr_counts[parsed["address"]] += 1

    except Exception:
        pass
    finally:
        _cleanup_procs()


def _cleanup_procs():
    global _rtl_proc, _mng_proc
    for proc in (_mng_proc, _rtl_proc):
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
    _rtl_proc = None
    _mng_proc = None


def _start_decode(freq):
    global _decoding, _start_time
    _stop_decode()
    _decoding = True
    _start_time = time.time()
    threading.Thread(target=_decode_thread, args=(freq,), daemon=True).start()


def _stop_decode():
    global _decoding
    _decoding = False
    _cleanup_procs()
    subprocess.run(["pkill", "-9", "rtl_fm"], capture_output=True)
    subprocess.run(["pkill", "-9", "multimon-ng"], capture_output=True)


def _export_log():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"pocsag_log_{ts}.json")
    with _msg_lock:
        data = list(_messages)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path, len(data)


def _word_wrap(text, max_chars):
    """Break text into lines of at most max_chars characters."""
    lines = []
    for paragraph in text.split("\n"):
        while len(paragraph) > max_chars:
            brk = paragraph.rfind(" ", 0, max_chars)
            if brk <= 0:
                brk = max_chars
            lines.append(paragraph[:brk])
            paragraph = paragraph[brk:].lstrip()
        lines.append(paragraph)
    return lines


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------
def _draw_live(freq_idx, scroll, selected):
    img = Image.new("RGB", (W, H), COL_BG)
    draw = ImageDraw.Draw(img)
    freq = FREQUENCIES[freq_idx]

    # Header
    draw.rectangle([(0, 0), (W, SY(14))], fill=COL_HEADER)
    draw.text((SX(2), SY(2)), "POCSAG", font=font_sm, fill=COL_POCSAG)
    draw.text((SX(38), SY(2)), freq["name"], font=font_sm, fill=COL_FLEX)
    if _decoding:
        draw.ellipse([W - SX(10), SY(4), W - SX(4), SY(10)], fill=COL_ERROR)
        draw.text((W - SX(30), SY(2)), "REC", font=font_xs, fill=COL_ERROR)

    with _msg_lock:
        messages = list(_messages)

    if not messages:
        draw.text(
            (W // 2, H // 2 - SY(5)), "No messages yet",
            font=font, fill=COL_DIM, anchor="mm",
        )
        hint = "OK to start decoding" if not _decoding else "Listening..."
        draw.text(
            (W // 2, H // 2 + SY(10)), hint,
            font=font_sm, fill=(40, 40, 60), anchor="mm",
        )
    else:
        row_h = SY(22)
        y = SY(16)
        visible = max(1, (H - SY(30)) // row_h)

        for i in range(scroll, min(len(messages), scroll + visible)):
            if y + row_h > H - SY(14):
                break
            msg = messages[-(i + 1)] if i < len(messages) else None
            if not msg:
                break

            is_selected = i == selected
            col = _msg_color(msg)

            # Row background
            bg = (20, 25, 45) if is_selected else (COL_ROW_EVEN if i % 2 == 0 else COL_ROW_ODD)
            draw.rectangle([(0, y), (W, y + row_h - 1)], fill=bg)

            # Selection indicator
            if is_selected:
                draw.rectangle([(0, y), (SX(2), y + row_h - 1)], fill=COL_ACTIVE)

            # Protocol tag
            tag = msg["protocol"][:6]
            draw.text((SX(4), SY(1) + y), tag, font=font_xs, fill=col)

            # Timestamp
            draw.text((SX(38), SY(1) + y), msg["timestamp"], font=font_xs, fill=COL_MUTED)

            # Address (RIC)
            addr_text = msg["address"][:9]
            draw.text((SX(68), SY(1) + y), addr_text, font=font_xs, fill=COL_ADDRESS)

            # Message preview (second line)
            preview = msg["message"][:42] if msg["message"] else "[no content]"
            draw.text((SX(4), SY(10) + y), preview, font=font_xs, fill=(180, 190, 200))

            y += row_h

    # Footer
    draw.rectangle([(0, H - SY(12)), (W, H)], fill=COL_FOOTER)
    if _decoding:
        footer = "OK:Stop UD:Scroll K1:View K2:Save"
    else:
        footer = "OK:Rec LR:Freq K1:View K2:Save"
    draw.text((SX(2), H - SY(11)), footer, font=font_xs, fill=COL_DIM)

    # Message count
    draw.text(
        (W - SX(30), H - SY(11)), f"{len(messages)}",
        font=font_xs, fill=COL_ACTIVE,
    )

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_message(selected):
    """Full message view with word wrap."""
    img = Image.new("RGB", (W, H), COL_BG)
    draw = ImageDraw.Draw(img)

    draw.rectangle([(0, 0), (W, SY(14))], fill=COL_HEADER)
    draw.text((SX(2), SY(2)), "MESSAGE", font=font_sm, fill=COL_FLEX)

    with _msg_lock:
        messages = list(_messages)

    if not messages:
        draw.text(
            (W // 2, H // 2), "No messages",
            font=font, fill=COL_DIM, anchor="mm",
        )
        LCD.LCD_ShowImage(img, 0, 0)
        return

    idx = min(selected, len(messages) - 1)
    msg = messages[-(idx + 1)]
    col = _msg_color(msg)

    # Index indicator
    draw.text(
        (W - SX(30), SY(2)), f"{idx + 1}/{len(messages)}",
        font=font_xs, fill=COL_MUTED,
    )

    y = SY(17)

    # Protocol + Type tag
    proto_tag = f"{msg['protocol']} {msg['type']}"
    draw.text((SX(3), y), proto_tag, font=font_sm, fill=col)
    y += SY(11)

    # Address + Function
    draw.text((SX(3), y), "RIC:", font=font_xs, fill=COL_MUTED)
    draw.text((SX(20), y), msg["address"], font=font_xs, fill=COL_ADDRESS)
    draw.text((SX(70), y), f"F:{msg['function']}", font=font_xs, fill=COL_MUTED)
    draw.text((W - SX(40), y), msg["timestamp"], font=font_xs, fill=COL_DIM)
    y += SY(11)

    # Separator
    draw.line([(SX(3), y), (W - SX(3), y)], fill=COL_DIM)
    y += SY(4)

    # Message content with word wrap
    content = msg["message"] if msg["message"] else "[no content]"
    # Estimate chars per line based on screen width and font
    chars_per_line = max(10, W // max(1, SX(3)))
    lines = _word_wrap(content, chars_per_line)

    line_h = SY(10)
    max_lines = max(1, (H - y - SY(14)) // line_h)
    for i, line_text in enumerate(lines[:max_lines]):
        draw.text((SX(3), y), line_text, font=font_xs, fill=(200, 210, 220))
        y += line_h

    if len(lines) > max_lines:
        draw.text((SX(3), y), "...", font=font_xs, fill=COL_DIM)

    # Footer
    draw.rectangle([(0, H - SY(12)), (W, H)], fill=COL_FOOTER)
    draw.text((SX(2), H - SY(11)), "UD:Prev/Next K1:View", font=font_xs, fill=COL_DIM)

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_stats(freq_idx):
    img = Image.new("RGB", (W, H), COL_BG)
    draw = ImageDraw.Draw(img)
    freq = FREQUENCIES[freq_idx]

    # Header
    draw.rectangle([(0, 0), (W, SY(14))], fill=COL_HEADER)
    draw.text((SX(2), SY(2)), "STATISTICS", font=font_sm, fill=COL_ADDRESS)

    with _msg_lock:
        total = len(_messages)
        addrs = dict(_addr_counts)
        type_counts = defaultdict(int)
        proto_counts = defaultdict(int)
        for m in _messages:
            type_counts[m["type"]] += 1
            proto_counts[m["protocol"]] += 1

    unique_addrs = len(addrs)

    # Uptime
    uptime_str = "--:--"
    mpm = 0.0
    if _start_time is not None:
        elapsed = time.time() - _start_time
        minutes = int(elapsed // 60)
        seconds = int(elapsed % 60)
        uptime_str = f"{minutes:02d}:{seconds:02d}"
        if elapsed > 0:
            mpm = total / (elapsed / 60.0)

    y = SY(18)

    # Total messages
    draw.text((SX(4), y), f"Messages: {total}", font=font, fill=COL_ACTIVE)
    y += SY(14)

    # Unique addresses
    draw.text((SX(4), y), f"Unique RICs: {unique_addrs}", font=font_sm, fill=COL_FLEX)
    y += SY(12)

    # Messages per minute
    draw.text((SX(4), y), f"Msg/min: {mpm:.1f}", font=font_sm, fill=COL_NUMERIC)
    y += SY(12)

    # Frequency
    freq_mhz = freq["freq"] / 1_000_000
    draw.text((SX(4), y), f"Freq: {freq_mhz:.3f} MHz", font=font_sm, fill=COL_MUTED)
    y += SY(12)

    # Uptime
    draw.text((SX(4), y), f"Uptime: {uptime_str}", font=font_sm, fill=COL_MUTED)
    y += SY(14)

    # Per-type breakdown
    type_colors = {
        "Alpha": COL_POCSAG,
        "Numeric": COL_NUMERIC,
        "Tone": COL_TONE,
    }
    for msg_type, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        col = type_colors.get(msg_type, COL_MUTED)
        draw.rectangle([(SX(4), y + SY(1)), (SX(12), y + SY(8))], fill=col)
        draw.text((SX(15), y), f"{msg_type}: {count}", font=font_xs, fill=col)
        y += SY(10)

    y += SY(4)

    # Top addresses bar chart
    if addrs:
        draw.text((SX(4), y), "Top RICs:", font=font_xs, fill=COL_DIM)
        y += SY(10)
        sorted_addrs = sorted(addrs.items(), key=lambda x: -x[1])[:4]
        max_count = sorted_addrs[0][1] if sorted_addrs else 1
        bar_max_w = W - SX(60)
        for addr, count in sorted_addrs:
            if y + SY(9) > H - SY(14):
                break
            draw.text((SX(4), y), addr[:8], font=font_xs, fill=COL_ADDRESS)
            bar_w = max(SX(2), int(bar_max_w * count / max_count))
            draw.rectangle(
                [(SX(48), y + SY(1)), (SX(48) + bar_w, y + SY(7))],
                fill=COL_ACTIVE,
            )
            draw.text(
                (SX(48) + bar_w + SX(3), y), str(count),
                font=font_xs, fill=COL_MUTED,
            )
            y += SY(10)

    # Footer
    draw.rectangle([(0, H - SY(12)), (W, H)], fill=COL_FOOTER)
    draw.text((SX(2), H - SY(11)), f"Freq: {freq['name']}  K1:View", font=font_xs, fill=COL_DIM)

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Dependency check screen
# ---------------------------------------------------------------------------
def _check_deps():
    """Check for rtl_fm and multimon-ng. Return True if both found."""
    missing = []
    for tool in ("rtl_fm", "multimon-ng"):
        r = subprocess.run(["which", tool], capture_output=True)
        if r.returncode != 0:
            missing.append(tool)
    if not missing:
        return True

    img = Image.new("RGB", (W, H), COL_BG)
    draw = ImageDraw.Draw(img)
    draw.rectangle([(0, 0), (W, SY(14))], fill=COL_HEADER)
    draw.text((SX(2), SY(2)), "MISSING TOOLS", font=font_sm, fill=COL_ERROR)

    y = SY(22)
    for tool in missing:
        draw.text((SX(4), y), f"  {tool} not found", font=font_sm, fill=COL_ERROR)
        y += SY(14)

    y += SY(6)
    draw.text((SX(4), y), "Install with:", font=font_sm, fill=COL_MUTED)
    y += SY(12)
    draw.text((SX(4), y), "apt install rtl-sdr", font=font_xs, fill=COL_DIM)
    y += SY(10)
    draw.text((SX(4), y), "apt install multimon-ng", font=font_xs, fill=COL_DIM)

    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(4)
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    if not _check_deps():
        GPIO.cleanup()
        return 1

    freq_idx = 0
    view_idx = 0
    scroll = 0
    selected = 0

    try:
        while _running:
            view = VIEWS[view_idx]

            if view == "live":
                _draw_live(freq_idx, scroll, selected)
            elif view == "message":
                _draw_message(selected)
            elif view == "stats":
                _draw_stats(freq_idx)

            btn = _btn()

            if btn == "KEY3":
                break

            elif btn == "KEY1":
                view_idx = (view_idx + 1) % len(VIEWS)
                scroll = 0
                time.sleep(DEBOUNCE)

            elif btn == "OK":
                if _decoding:
                    _stop_decode()
                else:
                    _start_decode(FREQUENCIES[freq_idx]["freq"])
                time.sleep(DEBOUNCE)

            elif btn == "UP":
                if view in ("live", "message"):
                    with _msg_lock:
                        max_idx = max(0, len(_messages) - 1)
                    if view == "live":
                        scroll = max(0, scroll - 1)
                    selected = max(0, selected - 1)
                time.sleep(DEBOUNCE)

            elif btn == "DOWN":
                if view in ("live", "message"):
                    with _msg_lock:
                        max_idx = max(0, len(_messages) - 1)
                    if view == "live":
                        scroll += 1
                    selected = min(max_idx, selected + 1)
                time.sleep(DEBOUNCE)

            elif btn == "RIGHT":
                freq_idx = (freq_idx + 1) % len(FREQUENCIES)
                if _decoding:
                    _start_decode(FREQUENCIES[freq_idx]["freq"])
                scroll = 0
                time.sleep(DEBOUNCE)

            elif btn == "LEFT":
                freq_idx = (freq_idx - 1) % len(FREQUENCIES)
                if _decoding:
                    _start_decode(FREQUENCIES[freq_idx]["freq"])
                scroll = 0
                time.sleep(DEBOUNCE)

            elif btn == "KEY2":
                with _msg_lock:
                    has_msgs = len(_messages) > 0
                if has_msgs:
                    path, count = _export_log()
                    img = Image.new("RGB", (W, H), COL_BG)
                    d = ScaledDraw(img)
                    d.text(
                        (64, 50), f"Exported {count} msgs",
                        font=font_sm, fill=COL_ACTIVE, anchor="mm",
                    )
                    d.text(
                        (64, 65), path[-30:],
                        font=font_xs, fill=COL_MUTED, anchor="mm",
                    )
                    LCD.LCD_ShowImage(img, 0, 0)
                    time.sleep(1.5)
                else:
                    img = Image.new("RGB", (W, H), COL_BG)
                    d = ScaledDraw(img)
                    d.text(
                        (64, 55), "No messages to export",
                        font=font_sm, fill=COL_NUMERIC, anchor="mm",
                    )
                    LCD.LCD_ShowImage(img, 0, 0)
                    time.sleep(1)
                time.sleep(DEBOUNCE)

            time.sleep(0.05)

    finally:
        _stop_decode()
        LCD.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
