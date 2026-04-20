#!/usr/bin/env python3
"""
RaspyJack Payload -- NFC Cloner
=================================
Clone NFC cards: load a saved dump and write it to a new card.
Supports MIFARE Classic and Ultralight/NTAG.
Magic card (Gen1a/Gen2) detection for UID cloning.

Controls:
  OK         Select dump / Start clone
  UP/DOWN    Navigate dumps
  KEY1       Toggle verify mode
  KEY2       Delete dump
  KEY3       Exit / Back
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
from payloads.nfc_rfid._nfc_driver import auto_detect, is_classic, is_ultralight
from payloads.nfc_rfid._nfc_keys import KNOWN_KEYS
from payloads.nfc_rfid._nfc_cards import list_dumps, load_dump, save_dump

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


def _is_magic_card(drv, uid):
    """Detect if card is a Gen1a magic card (supports backdoor commands)."""
    try:
        # Gen1a: auth with any key on block 0 works without prior auth
        for key in [bytes.fromhex("FFFFFFFFFFFF"), bytes.fromhex("000000000000")]:
            if drv.mifare_auth(0, key, uid, 0x60):
                data = drv.mifare_read(0)
                if data:
                    return True
        return False
    except Exception:
        return False


def _clone_classic(drv, uid, dump, lcd, font, font_sm, font_xs, verify=False):
    """Write MIFARE Classic sectors from dump to target card."""
    sectors = dump.get("sectors", [])
    total = len(sectors)
    written = 0
    skipped = 0
    errors = 0
    verified = 0
    magic = _is_magic_card(drv, uid)

    for idx, sec in enumerate(sectors):
        pct = idx * 100 // max(1, total)
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.rectangle((0, 0, 127, 12), fill="#111")
        d.text((2, 1), "CLONING", font=font_sm, fill="#FF00FF")
        d.text((80, 1), f"{pct}%", font=font_sm, fill="#FF00FF")
        d.text((4, 18), f"Target: {uid.hex().upper()[:12]}", font=font_xs, fill="#ccc")
        d.text((4, 28), f"Magic: {'YES' if magic else 'NO'}", font=font_xs,
               fill="#00FF00" if magic else "#888")
        d.rectangle((4, 42, 123, 50), outline="#333")
        bw = max(1, int(119 * idx / max(1, total)))
        d.rectangle((4, 42, 4 + bw, 50), fill="#FF00FF")
        d.text((4, 54), f"Sector {idx}/{total}", font=font_sm, fill="#FFAA00")
        d.text((4, 68), f"W:{written} S:{skipped} E:{errors}", font=font_xs, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)

        blocks = sec.get("blocks", [])
        key_hex = sec.get("key", "")
        sec_num = sec.get("sector", idx)

        if not blocks or not key_hex:
            skipped += 1
            continue

        first_block = sec_num * 4
        # Auth target card
        src_key = bytes.fromhex(key_hex)
        authed = drv.mifare_auth(first_block, src_key, uid, 0x60)
        if not authed:
            # Try default keys on target
            for dk in KNOWN_KEYS[:20]:
                if drv.mifare_auth(first_block, dk, uid, 0x60):
                    authed = True
                    break
        if not authed:
            errors += 1
            continue

        for i, blk_hex in enumerate(blocks):
            block_num = first_block + i
            if not magic and block_num == 0:
                continue
            if i == 3:
                continue
            if not blk_hex or blk_hex == "?" * 32:
                continue
            try:
                data = bytes.fromhex(blk_hex)
                if drv.mifare_write(block_num, data):
                    written += 1
                    if verify:
                        readback = drv.mifare_read(block_num)
                        if readback and readback == data:
                            verified += 1
                else:
                    errors += 1
            except Exception:
                errors += 1

    return written, skipped, errors, verified, magic


def _clone_ultralight(drv, uid, dump, lcd, font, font_sm, font_xs):
    """Write Ultralight/NTAG pages from dump to target card."""
    pages = dump.get("pages", [])
    written = 0
    skipped = 0
    errors = 0

    # Skip first 4 pages (UID/lock/CC) - start from page 4
    for i in range(4, len(pages)):
        pct = i * 100 // max(1, len(pages))
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.rectangle((0, 0, 127, 12), fill="#111")
        d.text((2, 1), "CLONING UL", font=font_sm, fill="#FF00FF")
        d.text((80, 1), f"{pct}%", font=font_sm, fill="#FF00FF")
        d.rectangle((4, 30, 123, 38), outline="#333")
        bw = max(1, int(119 * i / max(1, len(pages))))
        d.rectangle((4, 30, 4 + bw, 38), fill="#FF00FF")
        d.text((4, 44), f"Page {i}/{len(pages)}", font=font_sm, fill="#FFAA00")
        d.text((4, 60), f"W:{written} S:{skipped} E:{errors}", font=font_xs, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)

        page_hex = pages[i]
        if not page_hex:
            skipped += 1
            continue
        try:
            data = bytes.fromhex(page_hex)
            if drv.mifare_ul_write(i, data):
                written += 1
            else:
                errors += 1
        except Exception:
            errors += 1

    return written, skipped, errors


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
    font_xs = scaled_font(9)

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), "Detecting reader...", font=font_sm, fill="#FFAA00")
    lcd.LCD_ShowImage(img, 0, 0)

    drv, drv_desc = auto_detect()
    verify_mode = False
    scroll = 0
    status = drv_desc if drv else "No reader"

    try:
        while True:
            dumps = list_dumps()

            if not drv:
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.text((4, 50), "No NFC reader!", font=font, fill="#FF4444")
                d.text((4, 70), "Connect PN532", font=font_sm, fill="#888")
                lcd.LCD_ShowImage(img, 0, 0)
                btn = _btn()
                if btn == "KEY3":
                    break
                if btn == "OK":
                    drv, drv_desc = auto_detect()
                    status = drv_desc
                continue

            if not drv.can_write:
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.text((4, 45), "Reader can't write!", font=font, fill="#FF4444")
                d.text((4, 65), drv_desc[:22], font=font_sm, fill="#888")
                d.text((4, 80), "Need PN532 for clone", font=font_xs, fill="#666")
                lcd.LCD_ShowImage(img, 0, 0)
                btn = _btn()
                if btn == "KEY3":
                    break
                continue

            # Draw dump list
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.rectangle((0, 0, 127, 12), fill="#111")
            d.text((2, 1), "NFC CLONE", font=font_sm, fill="#FF00FF")
            v_txt = "VER" if verify_mode else ""
            d.text((80, 1), f"{len(dumps)}cards {v_txt}", font=font_xs, fill="#888")

            y = 16
            d.text((2, y), status[:24], font=font_sm, fill="#FFAA00")
            y += 12

            if not dumps:
                d.text((4, 50), "No saved cards", font=font_sm, fill="#666")
                d.text((4, 65), "Use NFC Reader first", font=font_sm, fill="#888")
            else:
                scroll = min(scroll, max(0, len(dumps) - 1))
                for i in range(max(0, scroll - 2), min(len(dumps), scroll + 5)):
                    if y > 105:
                        break
                    dm = dumps[i]
                    col = "#FF00FF" if i == scroll else "#888"
                    prefix = "> " if i == scroll else "  "
                    d.text((2, y), f"{prefix}{dm['uid'][:10]}", font=font_sm, fill=col)
                    d.text((80, y), dm["type"][:8], font=font_xs, fill="#555")
                    y += 11

            d.rectangle((0, 116, 127, 127), fill="#111")
            d.text((2, 117), "OK:Clone K1:Vrfy K2:Del", font=font_xs, fill="#666")
            lcd.LCD_ShowImage(img, 0, 0)

            btn = _btn()
            if btn == "KEY3":
                break
            elif btn == "UP":
                scroll = max(0, scroll - 1)
            elif btn == "DOWN":
                scroll += 1
            elif btn == "KEY1":
                verify_mode = not verify_mode
                status = f"Verify: {'ON' if verify_mode else 'OFF'}"
            elif btn == "KEY2" and dumps:
                idx = min(scroll, len(dumps) - 1)
                try:
                    os.remove(dumps[idx]["path"])
                    status = f"Deleted {dumps[idx]['uid'][:8]}"
                except Exception:
                    status = "Delete failed"
            elif btn == "OK" and dumps:
                idx = min(scroll, len(dumps) - 1)
                dump = load_dump(dumps[idx]["path"])
                if not dump:
                    status = "Failed to load dump"
                    continue

                # Wait for target card
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.rectangle((0, 0, 127, 12), fill="#111")
                d.text((2, 1), "NFC CLONE", font=font_sm, fill="#FF00FF")
                d.text((4, 30), f"Source: {dump.get('uid', '?')[:12]}", font=font_sm, fill="#ccc")
                d.text((4, 50), "Place TARGET card", font=font, fill="#FFAA00")
                d.text((4, 70), "on reader now...", font=font_sm, fill="#FFAA00")
                d.text((4, 90), "KEY3 to cancel", font=font_xs, fill="#555")
                lcd.LCD_ShowImage(img, 0, 0)

                card = drv.read_passive_target(timeout=10.0)
                if not card:
                    status = "No target card"
                    continue

                # Clone based on card type
                source_type = dump.get("type", "")
                if dump.get("sectors"):
                    w, s, e, v, magic = _clone_classic(
                        drv, card.uid, dump, lcd, font, font_sm, font_xs, verify_mode)
                    if e == 0 and w > 0:
                        status = f"Cloned! {w}blk {'magic' if magic else ''}"
                        if verify_mode:
                            status += f" {v}ok"
                    else:
                        status = f"W:{w} S:{s} E:{e}"
                elif dump.get("pages"):
                    w, s, e = _clone_ultralight(drv, card.uid, dump, lcd, font, font_sm, font_xs)
                    if e == 0 and w > 0:
                        status = f"Cloned! {w} pages"
                    else:
                        status = f"W:{w} S:{s} E:{e}"
                else:
                    status = "Empty dump"

                time.sleep(1)

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
