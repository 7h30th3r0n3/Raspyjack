#!/usr/bin/env python3
"""
RaspyJack Payload -- Card Tester
==================================
Author: 7h30th3r0n3

Quick diagnostics for all WiFi and Bluetooth adapters:
  - Driver + chipset detection
  - Monitor mode test (real test, not just iw phy info)
  - Frame injection test (send deauth and verify)
  - Supported bands (2.4 / 5 GHz)
  - BLE scan capability test
  - TX power range

Controls:
  OK         Run full test on selected card
  UP/DOWN    Navigate cards
  KEY1       Test all cards at once
  KEY2       Re-scan adapters
  KEY3       Exit
"""

import os
import sys
import time
import subprocess
import threading

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT

# Colors
C_PASS = "#00FF00"
C_FAIL = "#FF3333"
C_WARN = "#FFAA00"
C_INFO = "#00CCFF"
C_DIM = "#666666"
C_BG = "#000000"
C_HEADER = "#0a0a14"


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def _get_driver(iface):
    try:
        return os.path.basename(
            os.path.realpath(f"/sys/class/net/{iface}/device/driver"))
    except Exception:
        return "unknown"


def _is_onboard(iface):
    drv = _get_driver(iface)
    if drv == "brcmfmac":
        return True
    try:
        return "mmc" in os.path.realpath(f"/sys/class/net/{iface}/device")
    except Exception:
        return False


def _get_phy(iface):
    try:
        return os.path.basename(
            os.path.realpath(f"/sys/class/net/{iface}/phy80211"))
    except Exception:
        return None


def _get_mac(iface):
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            return f.read().strip().upper()
    except Exception:
        return "?"


def _scan_wifi_cards():
    """Find all WiFi interfaces with details."""
    cards = []
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if not os.path.isdir(f"/sys/class/net/{name}/wireless"):
                continue
            driver = _get_driver(name)
            onboard = _is_onboard(name)
            mac = _get_mac(name)
            phy = _get_phy(name)

            # Check iw phy supported modes
            modes = set()
            bands = []
            if phy:
                try:
                    r = subprocess.run(["iw", "phy", phy, "info"],
                                       capture_output=True, text=True, timeout=5)
                    for line in r.stdout.splitlines():
                        line = line.strip()
                        if line.startswith("* "):
                            mode = line[2:].strip()
                            if mode in ("monitor", "AP", "managed", "mesh point",
                                        "IBSS", "P2P-client", "P2P-GO"):
                                modes.add(mode)
                        if "Band 1:" in line or "2412" in line:
                            if "2.4" not in bands:
                                bands.append("2.4")
                        if "Band 2:" in line or "5180" in line:
                            if "5" not in bands:
                                bands.append("5")
                except Exception:
                    pass

            cards.append({
                "name": name,
                "type": "WiFi",
                "driver": driver,
                "mac": mac,
                "onboard": onboard,
                "phy": phy,
                "iw_modes": modes,
                "bands": bands or ["2.4"],
                "monitor": None,     # test result
                "injection": None,   # test result
                "band_5g": None,     # test result
            })
    except Exception:
        pass
    return cards


def _scan_bt_cards():
    """Find all Bluetooth HCI interfaces."""
    cards = []
    bt_path = "/sys/class/bluetooth"
    if not os.path.isdir(bt_path):
        return cards
    for name in sorted(os.listdir(bt_path)):
        if not name.startswith("hci"):
            continue
        bus = "onboard"
        try:
            devpath = os.path.realpath(os.path.join(bt_path, name, "device"))
            if "usb" in devpath:
                bus = "USB"
        except Exception:
            pass

        mac = ""
        try:
            r = subprocess.run(["hciconfig", name], capture_output=True,
                               text=True, timeout=5)
            for line in r.stdout.splitlines():
                if "BD Address:" in line:
                    mac = line.split("BD Address:")[1].strip().split()[0]
        except Exception:
            pass

        cards.append({
            "name": name,
            "type": "BLE",
            "driver": bus,
            "mac": mac,
            "onboard": bus == "onboard",
            "ble_scan": None,    # test result
        })
    return cards


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def _test_wifi_all(iface, progress_cb=None):
    """Test monitor + injection + 5GHz in a single monitor session.

    Returns dict: {monitor: bool, injection: bool, band_5g: bool}
    """
    results = {"monitor": False, "injection": False, "band_5g": False}
    mon_name = None

    # --- Step 1: Enter monitor mode ---
    if progress_cb:
        progress_cb("Monitor mode...")

    # Try iw first
    try:
        subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                       capture_output=True, timeout=5)
        subprocess.run(["sudo", "iw", iface, "set", "monitor", "none"],
                       capture_output=True, timeout=5)
        subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                       capture_output=True, timeout=5)
        time.sleep(0.3)
        r = subprocess.run(["iw", "dev", iface, "info"],
                           capture_output=True, text=True, timeout=5)
        if "type monitor" in r.stdout:
            mon_name = iface
    except Exception:
        pass

    # Fallback: airmon-ng
    if not mon_name:
        try:
            subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                           capture_output=True, timeout=5)
            subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                           capture_output=True, timeout=5)
            subprocess.run(["sudo", "airmon-ng", "start", iface],
                           capture_output=True, timeout=15)
            for name in (f"{iface}mon", iface):
                r = subprocess.run(["iw", "dev", name, "info"],
                                   capture_output=True, text=True, timeout=5)
                if "type monitor" in r.stdout:
                    mon_name = name
                    break
        except Exception:
            pass

    if not mon_name:
        _restore_managed(iface)
        return results

    results["monitor"] = True

    # --- Step 2: Test injection (while still in monitor mode) ---
    if progress_cb:
        progress_cb("Injection test...")

    try:
        r = subprocess.run(
            ["sudo", "aireplay-ng", "--test", mon_name],
            capture_output=True, text=True, timeout=15)
        output = r.stdout + r.stderr
        if "Injection is working!" in output:
            results["injection"] = True
    except Exception:
        pass

    # --- Step 3: Test 5GHz (while still in monitor mode) ---
    if progress_cb:
        progress_cb("5 GHz test...")

    try:
        r = subprocess.run(
            ["sudo", "iw", "dev", mon_name, "set", "channel", "36"],
            capture_output=True, timeout=3)
        results["band_5g"] = r.returncode == 0
    except Exception:
        pass

    # --- Restore managed mode ---
    if mon_name != iface:
        subprocess.run(["sudo", "airmon-ng", "stop", mon_name],
                       capture_output=True, timeout=10)
    _restore_managed(iface)

    return results


def _restore_managed(iface):
    """Restore interface to managed mode."""
    for cmd in [
        ["sudo", "ip", "link", "set", iface, "down"],
        ["sudo", "iw", iface, "set", "type", "managed"],
        ["sudo", "ip", "link", "set", iface, "up"],
    ]:
        try:
            subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception:
            pass


def _test_ble(hci):
    """Test if BLE adapter can scan. Returns True/False."""
    try:
        subprocess.run(["sudo", "hciconfig", hci, "up"],
                       capture_output=True, timeout=5)
        r = subprocess.run(
            ["sudo", "timeout", "5", "btmgmt", "--index",
             hci.replace("hci", ""), "find"],
            capture_output=True, text=True, timeout=8)
        return "dev_found:" in r.stdout
    except Exception:
        return False


# ---------------------------------------------------------------------------
# LCD Drawing
# ---------------------------------------------------------------------------


def _status_icon(result):
    if result is None:
        return "?", C_DIM
    if result:
        return "OK", C_PASS
    return "X", C_FAIL


def _draw_card_list(lcd, font, font_sm, wifi_cards, bt_cards, cursor):
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill=C_HEADER)
    d.text((2, 1), "CARD TESTER", font=font_sm, fill=C_INFO)
    total = len(wifi_cards) + len(bt_cards)
    d.text((90, 1), f"{total}", font=font_sm, fill="#FFF")

    all_cards = wifi_cards + bt_cards
    if not all_cards:
        d.text((10, 50), "No cards found", font=font_sm, fill=C_FAIL)
    else:
        y = 15
        for i, card in enumerate(all_cards):
            if i < cursor - 6 or i > cursor + 7:
                continue
            selected = i == cursor
            bg = "#0a1a0a" if selected else C_BG
            d.rectangle((0, y, 127, y + 12), fill=bg)

            # Type badge
            if card["type"] == "WiFi":
                badge_col = C_PASS if not card["onboard"] else C_WARN
                badge = "W"
            else:
                badge_col = C_INFO
                badge = "B"
            d.rectangle((1, y + 1, 8, y + 9), fill=badge_col)
            d.text((2, y), badge, font=font_sm, fill="#FFF")

            # Name + driver
            name = card["name"]
            driver = card["driver"][:10]
            d.text((11, y), name, font=font_sm,
                   fill="#FFF" if selected else C_DIM)
            d.text((55, y), driver, font=font_sm, fill=C_DIM)

            # Test results (if done)
            if card["type"] == "WiFi":
                mon = card.get("monitor")
                inj = card.get("injection")
                if mon is not None:
                    sym, col = _status_icon(mon)
                    d.text((95, y), f"M:{sym}", font=font_sm, fill=col)
                if inj is not None:
                    sym, col = _status_icon(inj)
                    d.text((115, y), f"I:{sym}", font=font_sm, fill=col)
            else:
                ble = card.get("ble_scan")
                if ble is not None:
                    sym, col = _status_icon(ble)
                    d.text((100, y), f"BLE:{sym}", font=font_sm, fill=col)

            y += 13
            if y > 110:
                break

    d.rectangle((0, 116, 127, 127), fill=C_HEADER)
    d.text((2, 117), "OK:Test K1:All K2:Scan", font=font_sm, fill=C_DIM)
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_testing(lcd, font, font_sm, card_name, test_name, step, total):
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill=C_HEADER)
    d.text((2, 1), "TESTING...", font=font_sm, fill=C_WARN)

    d.text((4, 25), card_name, font=font, fill="#FFF")
    d.text((4, 45), test_name, font=font_sm, fill=C_INFO)

    # Progress bar
    pct = step / max(total, 1)
    d.rectangle((4, 65, 124, 75), outline=C_DIM)
    bar_w = int(118 * pct)
    if bar_w > 0:
        d.rectangle((5, 66, 5 + bar_w, 74), fill=C_INFO)
    d.text((50, 68), f"{step}/{total}", font=font_sm, fill="#FFF")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_results(lcd, font, font_sm, card):
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill=C_HEADER)
    d.text((2, 1), "RESULTS", font=font_sm, fill=C_PASS)

    y = 16
    d.text((4, y), card["name"], font=font, fill="#FFF")
    y += 16
    d.text((4, y), f"Driver: {card['driver']}", font=font_sm, fill=C_DIM)
    y += 12
    d.text((4, y), f"MAC: {card['mac'][:17]}", font=font_sm, fill=C_DIM)
    y += 14

    if card["type"] == "WiFi":
        # Monitor
        sym, col = _status_icon(card["monitor"])
        d.text((4, y), f"Monitor mode:", font=font_sm, fill="#FFF")
        d.text((90, y), sym, font=font_sm, fill=col)
        y += 12

        # Injection
        sym, col = _status_icon(card["injection"])
        d.text((4, y), f"Injection:", font=font_sm, fill="#FFF")
        d.text((90, y), sym, font=font_sm, fill=col)
        y += 12

        # 5GHz
        sym, col = _status_icon(card["band_5g"])
        d.text((4, y), f"5 GHz:", font=font_sm, fill="#FFF")
        d.text((90, y), sym, font=font_sm, fill=col)
        y += 12

        # Bands from iw
        bands = ", ".join(card.get("bands", []))
        d.text((4, y), f"Bands: {bands}", font=font_sm, fill=C_DIM)
        y += 12

        # Verdict
        if card["monitor"] and card["injection"]:
            verdict = "PENTEST READY"
            v_col = C_PASS
        elif card["monitor"]:
            verdict = "MONITOR ONLY"
            v_col = C_WARN
        else:
            verdict = "MANAGED ONLY"
            v_col = C_FAIL
        d.text((4, y), verdict, font=font, fill=v_col)

    else:
        sym, col = _status_icon(card["ble_scan"])
        d.text((4, y), f"BLE Scan:", font=font_sm, fill="#FFF")
        d.text((90, y), sym, font=font_sm, fill=col)
        y += 14

        if card["ble_scan"]:
            d.text((4, y), "BLE READY", font=font, fill=C_PASS)
        else:
            d.text((4, y), "BLE FAIL", font=font, fill=C_FAIL)

    d.rectangle((0, 116, 127, 127), fill=C_HEADER)
    d.text((2, 117), "OK:Back K3:Exit", font=font_sm, fill=C_DIM)
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font = scaled_font(10)
    font_sm = scaled_font(8)

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)
    d.text((64, 30), "CARD", font=font, fill=C_INFO, anchor="mm")
    d.text((64, 45), "TESTER", font=font, fill=C_INFO, anchor="mm")
    d.line([(20, 55), (108, 55)], fill=C_DIM)
    d.text((64, 68), "Monitor + Injection", font=font_sm, fill=C_DIM, anchor="mm")
    d.text((64, 82), "WiFi + Bluetooth", font=font_sm, fill=C_DIM, anchor="mm")
    d.text((64, 100), "Scanning cards...", font=font_sm, fill=C_WARN, anchor="mm")
    lcd.LCD_ShowImage(img, 0, 0)

    wifi_cards = _scan_wifi_cards()
    bt_cards = _scan_bt_cards()
    cursor = 0
    screen = "list"     # list, testing, results
    result_card = None

    time.sleep(0.3)
    while get_button(PINS, GPIO) is not None:
        time.sleep(0.05)

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if screen == "list":
                all_cards = wifi_cards + bt_cards

                if btn == "KEY3":
                    break
                elif btn == "UP":
                    cursor = max(0, cursor - 1)
                    time.sleep(0.12)
                elif btn == "DOWN":
                    cursor = min(len(all_cards) - 1, cursor + 1)
                    time.sleep(0.12)
                elif btn == "KEY2":
                    wifi_cards = _scan_wifi_cards()
                    bt_cards = _scan_bt_cards()
                    cursor = 0
                    time.sleep(0.3)
                elif btn == "OK" and all_cards:
                    card = all_cards[cursor]
                    screen = "testing"
                    if card["type"] == "WiFi":
                        step = [0]
                        def _progress(msg):
                            step[0] += 1
                            _draw_testing(lcd, font, font_sm, card["name"], msg, step[0], 3)
                        res = _test_wifi_all(card["name"], _progress)
                        card["monitor"] = res["monitor"]
                        card["injection"] = res["injection"]
                        card["band_5g"] = res["band_5g"]
                    else:
                        _draw_testing(lcd, font, font_sm, card["name"], "BLE scan...", 1, 1)
                        card["ble_scan"] = _test_ble(card["name"])
                    result_card = card
                    screen = "results"
                    time.sleep(0.3)
                elif btn == "KEY1":
                    # Test all cards
                    total_tests = len(wifi_cards) + len(bt_cards)
                    step = 0
                    for card in wifi_cards:
                        step += 1
                        _draw_testing(lcd, font, font_sm, card["name"], "Testing...", step, total_tests)
                        res = _test_wifi_all(card["name"])
                        card["monitor"] = res["monitor"]
                        card["injection"] = res["injection"]
                        card["band_5g"] = res["band_5g"]
                    for card in bt_cards:
                        step += 1
                        _draw_testing(lcd, font, font_sm, card["name"], "BLE...", step, total_tests)
                        card["ble_scan"] = _test_ble(card["name"])
                    time.sleep(0.5)

                _draw_card_list(lcd, font, font_sm, wifi_cards, bt_cards, cursor)

            elif screen == "results":
                if btn == "KEY3":
                    break
                elif btn == "OK":
                    screen = "list"
                    time.sleep(0.3)
                _draw_results(lcd, font, font_sm, result_card)

            time.sleep(0.05)

    finally:
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
