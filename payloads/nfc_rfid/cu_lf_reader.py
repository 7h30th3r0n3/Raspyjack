#!/usr/bin/env python3
"""
RaspyJack Payload -- Chameleon Ultra LF Reader
=================================================
Read 125kHz badges (EM4100, HID Prox) using Chameleon Ultra.

Controls:
  OK         Single scan
  KEY1       Toggle continuous scan
  KEY2       Save log
  KEY3       Exit
"""

import os
import sys
import time
import json
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads.nfc_rfid._nfc_driver import auto_detect, ChameleonUltraDriver

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
LOOT_DIR = "/root/Raspyjack/loot/NFC/lf"
DEBOUNCE = 0.18
_last_btn = 0


def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE:
        return None
    if b:
        _last_btn = now
    return b


def _scan_lf(drv):
    """Scan for LF tags. Returns (tag_type, tag_id_hex) or (None, None)."""
    em = drv.em410x_scan()
    if em:
        return "EM4100", em.hex().upper()
    hid = drv.hid_scan()
    if hid:
        return "HID", hid.hex().upper()
    return None, None


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
    d.text((4, 50), "Detecting Chameleon...", font=font_sm, fill="#FFAA00")
    lcd.LCD_ShowImage(img, 0, 0)

    drv, desc = auto_detect()
    if not isinstance(drv, ChameleonUltraDriver):
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 35), "Chameleon Ultra", font=font, fill="#FF4444")
        d.text((4, 55), "Required", font=font, fill="#FF4444")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    continuous = False
    history = []
    scroll = 0
    status = "Ready"
    last_scan_time = 0

    try:
        while True:
            btn = _btn()
            if btn == "KEY3":
                break
            elif btn == "KEY1":
                continuous = not continuous
                status = "Scanning..." if continuous else "Paused"
            elif btn == "UP":
                scroll = max(0, scroll - 1)
            elif btn == "DOWN":
                scroll += 1

            if btn == "KEY2" and history:
                os.makedirs(LOOT_DIR, exist_ok=True)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                path = os.path.join(LOOT_DIR, f"cu_lf_{ts}.json")
                with open(path, "w") as f:
                    json.dump({"timestamp": ts, "tags": history}, f, indent=2)
                status = f"Saved {len(history)} tags"

            do_scan = btn == "OK" or (continuous and time.time() - last_scan_time > 1.0)

            if do_scan:
                last_scan_time = time.time()
                tag_type, tag_id = _scan_lf(drv)
                if tag_type:
                    existing = next((h for h in history if h["id"] == tag_id), None)
                    if existing:
                        existing["count"] += 1
                        existing["last"] = datetime.now().strftime("%H:%M:%S")
                    else:
                        history.insert(0, {
                            "type": tag_type,
                            "id": tag_id,
                            "count": 1,
                            "first": datetime.now().strftime("%H:%M:%S"),
                            "last": datetime.now().strftime("%H:%M:%S"),
                        })
                        scroll = 0
                    status = f"{tag_type}: {tag_id}"

            # Draw
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)

            # Header
            d.rectangle((0, 0, 127, 14), fill="#111")
            d.text((2, 2), "LF READER", font=font_sm, fill="#FFAA00")
            d.text((65, 2), f"{len(history)} tags", font=font_sm, fill="#888")
            scan_col = "#00FF00" if continuous else "#444"
            d.ellipse((120, 4, 125, 9), fill=scan_col)

            y = 18
            d.text((2, y), status[:24], font=font_sm, fill="#FFAA00")
            y += 13

            if not history:
                d.text((4, 55), "Press OK to scan", font=font_sm, fill="#666")
                d.text((4, 70), "K1: Continuous mode", font=font_sm, fill="#444")
            else:
                max_scroll = max(0, len(history) - 5)
                scroll = min(scroll, max_scroll)

                for i in range(scroll, min(len(history), scroll + 5)):
                    if y > 108:
                        break
                    h = history[i]
                    is_fresh = h == history[0] and time.time() - last_scan_time < 2

                    if is_fresh:
                        d.rectangle((0, y - 1, 127, y + 11), fill="#0a1a0a")

                    type_col = "#00FF88" if h["type"] == "EM4100" else "#00CCFF"
                    d.text((2, y), h["type"][:6], font=font_sm, fill=type_col)
                    d.text((40, y), h["id"][:12], font=font_sm, fill="#ccc" if is_fresh else "#888")
                    d.text((110, y), f"x{h['count']}", font=font_sm, fill="#555")
                    y += 12

            # Footer
            d.rectangle((0, 116, 127, 127), fill="#111")
            d.text((2, 117), "OK:Scan K1:Auto K2:Save", font=font_sm, fill="#666")
            lcd.LCD_ShowImage(img, 0, 0)
            time.sleep(0.03)

    finally:
        drv.close()
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
