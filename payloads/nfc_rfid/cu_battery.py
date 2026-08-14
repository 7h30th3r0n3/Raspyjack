#!/usr/bin/env python3
"""
RaspyJack Payload -- Chameleon Ultra Dashboard
================================================
Device info dashboard: battery, firmware, slots overview.

Controls:
  OK         Force refresh
  KEY3       Exit
"""

import os
import sys
import time

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
    font_lg = scaled_font(12)

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
        d.text((4, 80), f"Found: {desc[:20]}", font=font_sm, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    last_refresh = 0

    try:
        while True:
            btn = _btn()
            if btn == "KEY3":
                break
            if btn == "OK":
                last_refresh = 0

            now = time.time()
            if now - last_refresh < 2.0:
                time.sleep(0.03)
                continue
            last_refresh = now

            fw = drv.get_firmware()
            git = drv.get_git_version()
            model = drv.get_device_model()
            bat = drv.get_battery()
            active = drv.get_active_slot()
            slots = drv.get_slot_info()
            enabled = drv.get_enabled_slots()

            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)

            # Header
            d.rectangle((0, 0, 127, 14), fill="#111")
            d.text((2, 2), f"CHAMELEON {model.upper()}", font=font_sm, fill="#00CCFF")

            y = 18

            # Battery bar (prominent)
            if bat:
                voltage, pct = bat
                if pct > 60:
                    bar_col = "#00FF88"
                elif pct > 30:
                    bar_col = "#FFAA00"
                else:
                    bar_col = "#FF4444"

                d.text((4, y), f"{pct}%", font=font_lg, fill=bar_col)
                d.rectangle((40, y + 2, 120, y + 12), outline="#333")
                bar_w = int(80 * pct / 100)
                if bar_w > 0:
                    d.rectangle((40, y + 2, 40 + bar_w, y + 12), fill=bar_col)
                # Battery cap
                d.rectangle((121, y + 4, 123, y + 10), fill="#333")
                d.text((40, y + 14), f"{voltage}mV", font=font_sm, fill="#555")
                y += 27
            else:
                d.text((4, y), "Battery: N/A", font=font_sm, fill="#555")
                y += 13

            # Firmware
            if fw:
                d.text((4, y), f"FW v{fw[0]}.{fw[1]}", font=font_sm, fill="#00FF00")
            else:
                d.text((4, y), "FW: --", font=font_sm, fill="#555")
            if git:
                d.text((55, y), git[:12], font=font_sm, fill="#555")
            y += 12

            # Active slot info
            slot_info = slots[active] if active < len(slots) else None
            hf_name = slot_info["hf_type"] if slot_info and slot_info["hf_type"] != "None" else "--"
            lf_name = slot_info["lf_type"] if slot_info and slot_info["lf_type"] != "None" else "--"
            d.text((4, y), f"Slot {active}", font=font_sm, fill="#00FF00")
            d.text((40, y), f"HF:{hf_name}", font=font_sm, fill="#00CCFF")
            d.text((90, y), f"LF:{lf_name}", font=font_sm, fill="#FFAA00")
            y += 14

            # Slot overview — 8 colored squares
            d.text((4, y), "Slots:", font=font_sm, fill="#888")
            sq_x = 40
            sq_size = 9
            for i in range(8):
                en = enabled[i] if i < len(enabled) else True
                si = slots[i] if i < len(slots) else None
                has_hf = si and si["hf_type"] != "None"
                has_lf = si and si["lf_type"] != "None"

                if i == active:
                    col = "#00FF88"
                elif not en:
                    col = "#FF4444"
                elif has_hf or has_lf:
                    col = "#00CCFF"
                else:
                    col = "#333"

                d.rectangle((sq_x, y, sq_x + sq_size, y + sq_size), fill=col, outline="#222")
                if i == active:
                    d.text((sq_x + 2, y), str(i), font=font_sm, fill="#000")
                sq_x += sq_size + 2

            # Footer
            d.rectangle((0, 116, 127, 127), fill="#111")
            d.text((2, 117), "OK:Refresh KEY3:Exit", font=font_sm, fill="#666")
            lcd.LCD_ShowImage(img, 0, 0)

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
