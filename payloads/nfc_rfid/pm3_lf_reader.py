#!/usr/bin/env python3
"""
RaspyJack Payload -- PM3 LF Reader
=====================================
Read 125kHz badges (EM4100, HID, Indala, AWID) using Proxmark3.

Controls:
  OK         Read tag
  UP/DOWN    Scroll history
  KEY1       Toggle continuous scan
  KEY2       Save log
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
LOOT_DIR = "/root/Raspyjack/loot/NFC/lf"
DEBOUNCE = 0.18
_last_btn = 0

TYPE_COLORS = {
    "EM4100": "#00FF00",
    "HID": "#00CCFF",
    "Indala": "#FF00FF",
    "AWID": "#FFAA00",
    "Paradox": "#FF4444",
    "Viking": "#CCFF00",
    "FDX-B": "#FF8800",
    "IO Prox": "#00FFAA",
    "Unknown": "#888888",
}


def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE:
        return None
    if b:
        _last_btn = now
    return b


def _parse_lf(output):
    """Parse PM3 `lf search` output. Returns dict or None."""
    if not output:
        return None

    # EM4100 / EM410x
    m = re.search(r"EM\s*4(?:10)?[x0]\s*(?:ID|Tag\s*ID)\s*[:=]?\s*([0-9A-Fa-f]+)", output, re.IGNORECASE)
    if m:
        tag_id = m.group(1).upper()
        return {"type": "EM4100", "id": tag_id, "raw": tag_id}

    # HID Prox
    m = re.search(r"HID.*?(?:Facility\s*(?:Code)?)\s*[:=]?\s*(\d+).*?(?:Card\s*(?:Number)?)\s*[:=]?\s*(\d+)", output, re.IGNORECASE | re.DOTALL)
    if m:
        fc, cn = m.group(1), m.group(2)
        raw_m = re.search(r"TAG\s*ID\s*[:=]?\s*([0-9A-Fa-f]+)", output, re.IGNORECASE)
        raw = raw_m.group(1).upper() if raw_m else ""
        return {"type": "HID", "id": f"FC:{fc} CN:{cn}", "fc": fc, "cn": cn, "raw": raw}

    m = re.search(r"HID.*?TAG\s*ID\s*[:=]?\s*([0-9A-Fa-f]+)", output, re.IGNORECASE)
    if m:
        raw = m.group(1).upper()
        return {"type": "HID", "id": raw, "raw": raw}

    # Indala
    m = re.search(r"Indala.*?(?:Raw|ID)\s*[:=]?\s*([0-9A-Fa-f]+)", output, re.IGNORECASE)
    if m:
        raw = m.group(1).upper()
        return {"type": "Indala", "id": raw[:16], "raw": raw}

    # AWID
    m = re.search(r"AWID.*?(?:FC|Facility)\s*[:=]?\s*(\d+).*?(?:Card|CN)\s*[:=]?\s*(\d+)", output, re.IGNORECASE | re.DOTALL)
    if m:
        fc, cn = m.group(1), m.group(2)
        return {"type": "AWID", "id": f"FC:{fc} CN:{cn}", "fc": fc, "cn": cn, "raw": ""}

    # Paradox
    m = re.search(r"Paradox.*?(?:FC|Facility)\s*[:=]?\s*(\d+).*?(?:Card|CN)\s*[:=]?\s*(\d+)", output, re.IGNORECASE | re.DOTALL)
    if m:
        fc, cn = m.group(1), m.group(2)
        return {"type": "Paradox", "id": f"FC:{fc} CN:{cn}", "fc": fc, "cn": cn, "raw": ""}

    # Viking
    m = re.search(r"Viking.*?(?:Card|ID)\s*[:=]?\s*([0-9A-Fa-f]+)", output, re.IGNORECASE)
    if m:
        return {"type": "Viking", "id": m.group(1).upper(), "raw": m.group(1).upper()}

    # FDX-B (animal tags)
    m = re.search(r"FDX-B.*?(?:ID|Animal)\s*[:=]?\s*(\d+)", output, re.IGNORECASE)
    if m:
        return {"type": "FDX-B", "id": m.group(1), "raw": m.group(1)}

    # IO Prox
    m = re.search(r"IO\s*Prox.*?(?:FC|Facility)\s*[:=]?\s*(\d+).*?(?:Card|CN)\s*[:=]?\s*(\d+)", output, re.IGNORECASE | re.DOTALL)
    if m:
        fc, cn = m.group(1), m.group(2)
        return {"type": "IO Prox", "id": f"FC:{fc} CN:{cn}", "fc": fc, "cn": cn, "raw": ""}

    # Generic fallback — check if anything was found at all
    if "Valid" in output or "found" in output.lower():
        raw_m = re.search(r"(?:Raw|ID)\s*[:=]?\s*([0-9A-Fa-f]{6,})", output, re.IGNORECASE)
        if raw_m:
            return {"type": "Unknown", "id": raw_m.group(1).upper()[:16], "raw": raw_m.group(1).upper()}

    return None


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
        d.text((4, 60), "Connect Proxmark3", font=font_sm, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    scanning = False
    history = []
    unique_ids = set()
    scroll = 0
    status = drv_desc
    last_scan = 0

    try:
        while True:
            btn = _btn()
            if btn == "KEY3":
                break

            if btn == "OK":
                if not scanning:
                    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                    d = ScaledDraw(img)
                    d.text((4, 50), "Place badge...", font=font_sm, fill="#FFAA00")
                    lcd.LCD_ShowImage(img, 0, 0)

                    out = drv.command("lf search", timeout=8.0)
                    tag = _parse_lf(out)
                    if tag:
                        tag["ts"] = datetime.now().strftime("%H:%M:%S")
                        tag["count"] = 1
                        tag["last"] = time.time()
                        tag_key = f"{tag['type']}:{tag['id']}"
                        existing = next((h for h in history if f"{h['type']}:{h['id']}" == tag_key), None)
                        if existing:
                            existing["count"] += 1
                            existing["last"] = time.time()
                        else:
                            unique_ids.add(tag_key)
                            history.insert(0, tag)
                            scroll = 0
                        status = f"{tag['type']}: {tag['id'][:14]}"
                    else:
                        status = "No LF tag found"

            if btn == "KEY1":
                scanning = not scanning
                status = "Scanning..." if scanning else "Paused"

            if btn == "UP":
                scroll = max(0, scroll - 1)
            elif btn == "DOWN":
                scroll += 1

            if btn == "KEY2" and history:
                os.makedirs(LOOT_DIR, exist_ok=True)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                path = os.path.join(LOOT_DIR, f"lf_scan_{ts}.json")
                with open(path, "w") as f:
                    json.dump({"tags": history, "timestamp": ts}, f, indent=2)
                status = f"Saved {len(history)} tags"

            # Continuous scan
            if scanning and time.time() - last_scan > 1.0:
                last_scan = time.time()
                out = drv.command("lf search", timeout=6.0)
                tag = _parse_lf(out)
                if tag:
                    tag["ts"] = datetime.now().strftime("%H:%M:%S")
                    tag["count"] = 1
                    tag["last"] = time.time()
                    tag_key = f"{tag['type']}:{tag['id']}"
                    existing = next((h for h in history if f"{h['type']}:{h['id']}" == tag_key), None)
                    if existing:
                        existing["count"] += 1
                        existing["last"] = time.time()
                    else:
                        unique_ids.add(tag_key)
                        history.insert(0, tag)
                        scroll = 0

            # Draw
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.rectangle((0, 0, 127, 14), fill="#111")
            d.text((2, 2), "LF READER", font=font_sm, fill="#00FF00")
            total = sum(h["count"] for h in history)
            d.text((65, 2), f"{len(unique_ids)}u/{total}t", font=font_sm, fill="#888")
            scan_col = "#00FF00" if scanning else "#444"
            d.ellipse((120, 4, 125, 9), fill=scan_col)

            y = 18
            d.text((2, y), status[:24], font=font_sm, fill="#FFAA00")
            y += 13

            if not history:
                d.text((4, 50), "OK:Read  K1:Auto", font=font_sm, fill="#666")
                d.text((4, 65), "125kHz LF badges", font=font_sm, fill="#888")
            else:
                max_scroll = max(0, len(history) - 4)
                scroll = min(scroll, max_scroll)

                for i in range(scroll, min(len(history), scroll + 4)):
                    if y > 105:
                        break
                    h = history[i]
                    age = time.time() - h["last"]
                    fresh = age < 5

                    if fresh:
                        d.rectangle((0, y - 1, 127, y + 22), fill="#0a1a0a")

                    col = TYPE_COLORS.get(h["type"], "#888")
                    d.text((2, y), h["type"][:8], font=font_sm, fill=col)
                    d.text((55, y), h["id"][:14], font=font_sm, fill="#ccc" if fresh else "#666")
                    y += 12
                    d.text((4, y), f"x{h['count']}", font=font_sm, fill="#888")
                    d.text((90, y), h["ts"], font=font_sm, fill="#555")
                    y += 13

            d.rectangle((0, 116, 127, 127), fill="#111")
            d.text((2, 117), "OK:Read K1:Auto K2:Sav", font=font_sm, fill="#666")
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
