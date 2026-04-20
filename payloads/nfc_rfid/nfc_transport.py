#!/usr/bin/env python3
"""
RaspyJack Payload -- Transport Card Reader
=============================================
Read transit cards (Calypso/Navigo, MIFARE DESFire-based transport).
Extracts: card type, environment, contracts, counters, last events.

Controls:
  OK         Read card
  UP/DOWN    Scroll data
  KEY2       Save dump
  KEY3       Exit
"""
import os, sys, time, json
from datetime import datetime
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))
import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads.nfc_rfid._nfc_driver import auto_detect

PINS = {"UP":6,"DOWN":19,"LEFT":5,"RIGHT":26,"OK":13,"KEY1":21,"KEY2":20,"KEY3":16}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
LOOT_DIR = "/root/Raspyjack/loot/NFC/transport"
DEBOUNCE = 0.18
_last_btn = 0

TRANSPORT_AIDS = [
    ("Calypso", "315449432E494341"),
    ("Navigo", "A00000000401"),
    ("Calypso2", "A000000404"),
    ("Intercode", "315449432E494341D380"),
    ("RATP", "A00000000401"),
]

CALYPSO_SFIS = {
    0x07: "Environment",
    0x08: "Events Log",
    0x09: "Contracts",
    0x0A: "Counters",
    0x19: "Special Events",
    0x1D: "Contract List",
}

NETWORKS = {
    "0001": "RATP (Paris)", "0002": "SNCF", "0003": "TCL (Lyon)",
    "0004": "TAN (Nantes)", "0005": "RTM (Marseille)",
    "0006": "TBC (Bordeaux)", "0007": "Tiseo (Toulouse)",
    "0064": "Ile-de-France Mobilites", "0100": "STIB (Brussels)",
    "0115": "De Lijn", "0116": "TEC",
}

def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE: return None
    if b: _last_btn = now
    return b

def _read_transport(drv):
    """Try to read transport card via ISO-DEP APDU."""
    result = {"type": "", "network": "", "records": [], "raw": []}

    # Try each transport AID
    for name, aid in TRANSPORT_AIDS:
        aid_bytes = bytes.fromhex(aid)
        # Calypso SELECT: CLA=94 INS=A4 P1=04 P2=00
        apdu = bytes([0x94, 0xA4, 0x04, 0x00, len(aid_bytes)]) + aid_bytes
        resp = drv.data_exchange(apdu)
        if not resp or len(resp) < 2:
            # Try standard ISO SELECT
            apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(aid_bytes)]) + aid_bytes + b"\x00"
            resp = drv.data_exchange(apdu)
        if resp and len(resp) > 4:
            result["type"] = name
            result["raw"].append({"aid": aid, "select_resp": resp.hex()})
            break

    if not result["type"]:
        return None

    # Read Calypso SFIs
    for sfi, sfi_name in CALYPSO_SFIS.items():
        for rec in range(1, 4):
            p2 = (sfi << 3) | 0x04
            # Calypso READ RECORD: CLA=94
            apdu = bytes([0x94, 0xB2, rec, p2, 0x00])
            resp = drv.data_exchange(apdu)
            if not resp or len(resp) <= 2:
                # Try standard ISO
                apdu = bytes([0x00, 0xB2, rec, p2, 0x00])
                resp = drv.data_exchange(apdu)
            if resp and len(resp) > 4:
                record = {
                    "sfi": sfi, "sfi_name": sfi_name,
                    "record": rec, "data": resp.hex(),
                }
                # Try to parse
                h = resp.hex().upper()
                if sfi == 0x07:  # Environment
                    # Network ID is often in first bytes
                    if len(h) >= 8:
                        net_id = h[0:4]
                        record["network"] = NETWORKS.get(net_id, f"Net:{net_id}")
                        result["network"] = record["network"]
                elif sfi == 0x09:  # Contracts
                    record["info"] = f"Contract {rec}"
                elif sfi == 0x08:  # Events
                    record["info"] = f"Event {rec}"
                elif sfi == 0x0A:  # Counters
                    if len(resp) >= 3:
                        counter = int.from_bytes(resp[:3], "big")
                        record["counter"] = counter
                        record["info"] = f"Counter: {counter}"

                result["records"].append(record)

    return result if result["records"] else None


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
    status = drv_desc if drv else "No reader"
    data = None
    scroll = 0

    try:
        while True:
            btn = _btn()
            if btn == "KEY3": break
            if btn == "UP": scroll = max(0, scroll - 1)
            if btn == "DOWN": scroll += 1

            if btn == "OK" and drv:
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.text((4, 50), "Place transport card", font=font_sm, fill="#FFAA00")
                lcd.LCD_ShowImage(img, 0, 0)
                card = drv.read_passive_target(timeout=5.0)
                if card:
                    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                    d = ScaledDraw(img)
                    d.text((4, 50), "Reading...", font=font_sm, fill="#FFAA00")
                    lcd.LCD_ShowImage(img, 0, 0)
                    data = _read_transport(drv)
                    scroll = 0
                    if data:
                        status = data.get("type", "Transport card")
                    else:
                        status = "Not a transport card"
                        data = None
                else:
                    status = "No card"

            if btn == "KEY2" and data:
                os.makedirs(LOOT_DIR, exist_ok=True)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                fname = f"transport_{ts}.json"
                with open(os.path.join(LOOT_DIR, fname), "w") as f:
                    json.dump({**data, "timestamp": ts}, f, indent=2)
                status = f"Saved: {fname[:16]}"

            # Draw
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.rectangle((0, 0, 127, 14), fill="#111")
            d.text((2, 2), "TRANSPORT", font=font_sm, fill="#00FF88")
            y = 20
            d.text((4, y), status[:24], font=font_sm, fill="#FFAA00"); y += 13

            if data:
                if data.get("network"):
                    d.text((4, y), data["network"][:22], font=font_sm, fill="#00FF00"); y += 13

                lines = []
                for rec in data.get("records", []):
                    name = rec.get("sfi_name", "?")
                    info = rec.get("info", "")
                    counter = rec.get("counter")
                    network = rec.get("network", "")
                    if counter is not None:
                        lines.append((f"{name}: {counter}", "#00CCFF"))
                    elif network:
                        lines.append((f"{name}: {network[:14]}", "#00FF00"))
                    elif info:
                        lines.append((f"{name}: {info[:14]}", "#ccc"))
                    else:
                        lines.append((f"{name} R{rec['record']}: data", "#888"))

                for i in range(scroll, min(len(lines), scroll + 6)):
                    if y > 108: break
                    txt, col = lines[i]
                    d.text((4, y), txt[:24], font=font_sm, fill=col)
                    y += 11
            else:
                d.text((4, 55), "Press OK to scan", font=font_sm, fill="#666")
                d.text((4, 72), "Calypso / Navigo / DL", font=font_sm, fill="#888")

            d.rectangle((0, 116, 127, 127), fill="#111")
            d.text((2, 117), "OK:Read K2:Save K3:X", font=font_sm, fill="#666")
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
