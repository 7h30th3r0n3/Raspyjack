#!/usr/bin/env python3
"""
RaspyJack Payload -- Chameleon Ultra Slot Manager
===================================================
Manage the 8 emulation slots on the Chameleon Ultra.

Controls:
  OK         Activate selected slot
  UP/DOWN    Navigate slots
  KEY1       Toggle Reader/Tag mode
  KEY2       Enable/disable selected slot
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

    cursor = 0
    status = ""

    try:
        while True:
            btn = _btn()
            if btn == "KEY3":
                break
            elif btn == "UP":
                cursor = (cursor - 1) % 8
            elif btn == "DOWN":
                cursor = (cursor + 1) % 8
            elif btn == "OK":
                drv.set_active_slot(cursor)
                status = f"Slot {cursor} activated"
            elif btn == "KEY1":
                result = drv.command(1002)
                if result and result[1]:
                    current_mode = result[1][0]
                    new_mode = 0x00 if current_mode else 0x01
                    drv.command(1001, bytes([new_mode]))
                    status = "Reader mode" if new_mode else "Tag mode"
            elif btn == "KEY2":
                enabled = drv.get_enabled_slots()
                new_state = not enabled[cursor]
                drv.set_slot_enable(cursor, new_state)
                status = f"Slot {cursor} {'enabled' if new_state else 'disabled'}"

            slots = drv.get_slot_info()
            enabled = drv.get_enabled_slots()
            active = drv.get_active_slot()
            bat = drv.get_battery()

            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)

            # Header
            d.rectangle((0, 0, 127, 14), fill="#111")
            d.text((2, 2), "SLOT MANAGER", font=font_sm, fill="#00CCFF")
            if bat:
                pct = bat[1]
                bat_col = "#00FF88" if pct > 50 else "#FFAA00" if pct > 20 else "#FF4444"
                d.text((92, 2), f"{pct}%", font=font_sm, fill=bat_col)

            y = 16

            # Status
            if status:
                d.text((2, y), status[:24], font=font_sm, fill="#FFAA00")
            y += 11

            # Slot list
            row_h = 11
            for i in range(8):
                if y + row_h > 114:
                    break

                is_active = i == active
                is_cursor = i == cursor
                is_enabled = enabled[i] if i < len(enabled) else True
                si = slots[i] if i < len(slots) else {"hf_type": "Unknown", "lf_type": "Unknown"}
                hf = si["hf_type"] if si["hf_type"] != "None" else ""
                lf = si["lf_type"] if si["lf_type"] != "None" else ""
                has_data = bool(hf or lf)

                # Row background
                if is_active and is_cursor:
                    d.rectangle((0, y, 127, y + row_h), fill="#0a2a1a")
                    d.rectangle((0, y, 2, y + row_h), fill="#00FF88")
                elif is_active:
                    d.rectangle((0, y, 127, y + row_h), fill="#081a0a")
                    d.rectangle((0, y, 2, y + row_h), fill="#00FF88")
                elif is_cursor:
                    d.rectangle((0, y, 127, y + row_h), fill="#0a1a2a")
                    d.rectangle((0, y, 2, y + row_h), fill="#00CCFF")

                # Slot number
                num_col = "#00FF88" if is_active else "#ccc" if is_enabled else "#444"
                d.text((5, y), str(i), font=font_sm, fill=num_col)

                if not is_enabled:
                    d.text((14, y), "DISABLED", font=font_sm, fill="#444")
                    d.line([(14, y + 5), (70, y + 5)], fill="#333")
                elif has_data:
                    if hf:
                        d.text((14, y), hf[:10], font=font_sm, fill="#00CCFF")
                    if lf:
                        lf_x = 80 if hf else 14
                        d.text((lf_x, y), lf[:8], font=font_sm, fill="#FFAA00")
                else:
                    d.text((14, y), "Empty", font=font_sm, fill="#333")

                # Active indicator
                if is_active:
                    d.text((118, y), "*", font=font_sm, fill="#00FF88")

                y += row_h

            # Footer
            d.rectangle((0, 116, 127, 127), fill="#111")
            d.text((2, 117), "OK:Set K1:Mode K2:En/Dis", font=font_sm, fill="#666")
            lcd.LCD_ShowImage(img, 0, 0)
            time.sleep(0.05)

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
