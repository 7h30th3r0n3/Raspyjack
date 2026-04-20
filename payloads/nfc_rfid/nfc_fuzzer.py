#!/usr/bin/env python3
"""
RaspyJack Payload -- NFC APDU Fuzzer
=======================================
Interactive APDU terminal for exploring unknown NFC cards.
Send arbitrary commands, decode responses, scan SFI/records.

Controls:
  OK         Send APDU / Select template
  UP/DOWN    Scroll history / Edit hex
  LEFT/RIGHT Move cursor
  KEY1       Switch mode (Templates / Editor / Scan)
  KEY2       Clear history
  KEY3       Exit
"""
import os, sys, time
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads.nfc_rfid._nfc_driver import auto_detect

PINS = {"UP":6,"DOWN":19,"LEFT":5,"RIGHT":26,"OK":13,"KEY1":21,"KEY2":20,"KEY3":16}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
DEBOUNCE = 0.18
_last_btn = 0

HEX_CHARS = "0123456789ABCDEF"

SW_CODES = {
    "9000": "OK", "6A82": "File not found", "6A86": "P1P2 incorrect",
    "6985": "Conditions not satisfied", "6D00": "INS not supported",
    "6E00": "CLA not supported", "6700": "Wrong length",
    "6300": "Auth failed", "6982": "Security not satisfied",
    "6A81": "Function not supported", "6A88": "Data not found",
    "6F00": "Internal error", "6283": "Selected file invalidated",
}

TEMPLATES = [
    ("SELECT PPSE", "00A404000E325041592E5359532E444446303100"),
    ("SELECT Visa", "00A4040007A000000003101000"),
    ("SELECT MC", "00A4040007A000000004101000"),
    ("SELECT CB", "00A4040007A000000042101000"),
    ("GPO", "80A8000002830000"),
    ("READ REC 1,1", "00B2010C00"),
    ("READ REC 1,2", "00B2011400"),
    ("READ REC 2,1", "00B2010C00"),
    ("GET DATA ATC", "80CA9F3600"),
    ("GET DATA PIN", "80CA9F1700"),
    ("GET CHALLENGE", "0084000008"),
]

def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE: return None
    if b: _last_btn = now
    return b

def _decode_sw(resp_hex):
    if len(resp_hex) >= 4:
        sw = resp_hex[-4:].upper()
        return SW_CODES.get(sw, f"SW:{sw}")
    return ""

def main():
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
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
    mode = 0  # 0=templates, 1=scan SFI
    sel = 0
    history = []
    scroll = 0
    card = None
    status = drv_desc if drv else "No reader"
    scan_running = False

    try:
        while True:
            btn = _btn()
            if btn == "KEY3":
                if scan_running:
                    scan_running = False
                else:
                    break
            if btn == "KEY1":
                mode = 1 - mode
                sel = 0
                scroll = 0
            if btn == "KEY2":
                history = []
                scroll = 0
                status = "History cleared"

            if mode == 0:
                # Template mode
                if btn == "UP": sel = (sel - 1) % len(TEMPLATES)
                if btn == "DOWN": sel = (sel + 1) % len(TEMPLATES)
                if btn == "OK" and drv:
                    if not card:
                        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                        d = ScaledDraw(img)
                        d.text((4, 50), "Place card...", font=font_sm, fill="#FFAA00")
                        lcd.LCD_ShowImage(img, 0, 0)
                        card = drv.read_passive_target(timeout=5.0)
                        if not card:
                            status = "No card"
                            continue
                        status = f"Card: {card.uid_hex[:8]}"
                        continue

                    name, apdu_hex = TEMPLATES[sel]
                    apdu = bytes.fromhex(apdu_hex)
                    resp = drv.data_exchange(apdu)
                    resp_hex = resp.hex().upper() if resp else "NO RESPONSE"
                    sw = _decode_sw(resp_hex) if resp else ""
                    history.insert(0, {"cmd": name, "apdu": apdu_hex[:16], "resp": resp_hex[:32], "sw": sw})
                    status = sw or "Sent"

                # Draw templates
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.rectangle((0, 0, 127, 14), fill="#111")
                d.text((2, 2), "APDU FUZZER", font=font_sm, fill="#00CCFF")
                d.text((85, 2), "TMPL", font=font_sm, fill="#888")
                y = 18
                d.text((2, y), status[:24], font=font_sm, fill="#FFAA00"); y += 12

                # Templates list
                vis = 3
                start = max(0, sel - 1)
                for i in range(start, min(len(TEMPLATES), start + vis)):
                    if y > 65: break
                    name, _ = TEMPLATES[i]
                    col = "#00CCFF" if i == sel else "#666"
                    pre = ">" if i == sel else " "
                    d.text((2, y), f"{pre}{name[:20]}", font=font_sm, fill=col)
                    y += 12

                # History
                if history:
                    d.line([(0, y), (127, y)], fill="#222"); y += 3
                    for h in history[:3]:
                        if y > 108: break
                        d.text((2, y), f"{h['cmd'][:8]}: {h['sw']}", font=font_sm, fill="#888")
                        y += 10

            elif mode == 1:
                # SFI Scan mode
                if btn == "OK" and drv and not scan_running:
                    if not card:
                        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                        d = ScaledDraw(img)
                        d.text((4, 50), "Place card...", font=font_sm, fill="#FFAA00")
                        lcd.LCD_ShowImage(img, 0, 0)
                        card = drv.read_passive_target(timeout=5.0)
                        if not card:
                            status = "No card"
                            continue
                    # Scan all SFI/records
                    scan_running = True
                    history = []
                    for sfi in range(1, 32):
                        if not scan_running: break
                        for rec in range(1, 6):
                            p2 = (sfi << 3) | 0x04
                            apdu = bytes([0x00, 0xB2, rec, p2, 0x00])
                            resp = drv.data_exchange(apdu, timeout=0.3)
                            if resp and len(resp) > 2:
                                resp_hex = resp.hex().upper()
                                sw = _decode_sw(resp_hex)
                                if "9000" in resp_hex[-4:] or len(resp) > 4:
                                    history.insert(0, {"cmd": f"SFI{sfi}R{rec}", "apdu": apdu.hex()[:16],
                                                       "resp": resp_hex[:32], "sw": sw})
                            b2 = _btn()
                            if b2 == "KEY3":
                                scan_running = False
                                break
                        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                        d = ScaledDraw(img)
                        d.rectangle((0, 0, 127, 14), fill="#111")
                        d.text((2, 2), "SFI SCAN", font=font_sm, fill="#00CCFF")
                        pct = sfi * 100 // 31
                        d.text((80, 2), f"{pct}%", font=font_sm, fill="#00CCFF")
                        d.text((4, 24), f"SFI {sfi}/31 - Found: {len(history)}", font=font_sm, fill="#FFAA00")
                        d.rectangle((4, 40, 123, 48), outline="#333")
                        bw = max(1, int(119 * sfi / 31))
                        d.rectangle((4, 40, 4 + bw, 48), fill="#00CCFF")
                        lcd.LCD_ShowImage(img, 0, 0)
                    scan_running = False
                    status = f"Found {len(history)} records"

                if btn == "UP": scroll = max(0, scroll - 1)
                if btn == "DOWN": scroll += 1

                # Draw scan results
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.rectangle((0, 0, 127, 14), fill="#111")
                d.text((2, 2), "APDU FUZZER", font=font_sm, fill="#00CCFF")
                d.text((85, 2), "SCAN", font=font_sm, fill="#888")
                y = 18
                d.text((2, y), status[:24], font=font_sm, fill="#FFAA00"); y += 12

                if history:
                    for i in range(scroll, min(len(history), scroll + 6)):
                        if y > 108: break
                        h = history[i]
                        d.text((2, y), f"{h['cmd']}: {h['resp'][:16]}", font=font_sm, fill="#ccc")
                        y += 10
                else:
                    d.text((4, 55), "OK: Scan all SFI/Rec", font=font_sm, fill="#666")

            d.rectangle((0, 116, 127, 127), fill="#111")
            d.text((2, 117), "OK:Send K1:Mode K2:Clr", font=font_sm, fill="#666")
            lcd.LCD_ShowImage(img, 0, 0)
            time.sleep(0.03)
    finally:
        if drv: drv.close()
        try: lcd.LCD_Clear()
        except: pass
        GPIO.cleanup()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
