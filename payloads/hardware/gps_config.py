#!/usr/bin/env python3
"""
RaspyJack Payload -- GPS Configuration
=========================================
Author: 7h30th3r0n3

Configure u-blox GPS modules directly from the device.
Supports constellation selection, navigation mode, update rate,
SBAS configuration, and GPS reset.

Controls:
  UP/DOWN    Navigate settings
  OK         Change selected setting
  LEFT/RIGHT Adjust value
  KEY1       Apply all settings
  KEY2       Reset GPS (cold start)
  KEY3       Exit
"""

import os
import sys
import time
import subprocess

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
LCD = None

# ---------------------------------------------------------------------------
# GPS settings
# ---------------------------------------------------------------------------

NAV_MODELS = [
    (0, "Portable"),
    (2, "Stationary"),
    (3, "Pedestrian"),
    (4, "Automotive"),
    (5, "Sea"),
    (6, "Airborne 1G"),
    (7, "Airborne 2G"),
    (8, "Airborne 4G"),
]

UPDATE_RATES = [
    (1, "1 Hz"),
    (2, "2 Hz"),
    (4, "4 Hz"),
    (5, "5 Hz"),
    (10, "10 Hz"),
]

# u-blox 7: GPS et GLONASS ne peuvent PAS être simultanés
CONSTELLATIONS = [
    ("GPS", True),
    ("SBAS", True),
    ("GLONASS", False),
    ("QZSS", True),
]

# ---------------------------------------------------------------------------
# ubxtool helpers
# ---------------------------------------------------------------------------


def _run_ubx(args, timeout=5):
    """Run ubxtool command and return stdout."""
    try:
        r = subprocess.run(
            ["ubxtool"] + args,
            capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.returncode
    except Exception as e:
        return str(e), 1


def _get_current_config():
    """Read current GPS configuration."""
    config = {
        "nav_model": 0,
        "rate_hz": 1,
        "gps": True,
        "sbas": True,
        "glonass": False,
        "qzss": True,
        "fix": 0,
        "sats": 0,
    }

    # Get GNSS config
    out, _ = _run_ubx(["-p", "CFG-GNSS"], timeout=5)
    for line in out.splitlines():
        line = line.strip()
        if "GPS" in line and "enabled" in line:
            config["gps"] = True
        elif "GPS" in line and "enabled" not in line:
            config["gps"] = False
        if "SBAS" in line and "enabled" in line:
            config["sbas"] = True
        elif "SBAS" in line and "enabled" not in line:
            config["sbas"] = False
        if "GLONASS" in line and "enabled" in line:
            config["glonass"] = True
        elif "GLONASS" in line and "enabled" not in line:
            config["glonass"] = False
        if "QZSS" in line and "enabled" in line:
            config["qzss"] = True
        elif "QZSS" in line and "enabled" not in line:
            config["qzss"] = False

    # Get nav model
    out, _ = _run_ubx(["-p", "CFG-NAV5"], timeout=5)
    for line in out.splitlines():
        if "dynModel" in line:
            try:
                val = int(line.split("dynModel")[1].strip().split()[0])
                config["nav_model"] = val
            except Exception:
                pass

    # Get fix status
    out, _ = _run_ubx(["-p", "NAV-SOL"], timeout=5)
    for line in out.splitlines():
        if "gpsFix" in line:
            try:
                val = int(line.split("gpsFix")[1].strip().split()[0])
                config["fix"] = val
            except Exception:
                pass
        if "numSV" in line:
            try:
                val = int(line.split("numSV")[1].strip().split()[0])
                config["sats"] = val
            except Exception:
                pass

    return config


def _apply_constellation(name, enable):
    """Enable or disable a GNSS constellation."""
    flag = "-e" if enable else "-d"
    _run_ubx([flag, name], timeout=5)


def _apply_nav_model(model_id):
    """Set navigation model."""
    _run_ubx(["-p", f"MODEL,{model_id}"], timeout=5)


def _apply_rate(hz):
    """Set update rate in Hz."""
    period_ms = 1000 // hz
    _run_ubx(["-p", f"RATE,{period_ms}"], timeout=5)


def _cold_start():
    """Force GPS cold start (full reset)."""
    _run_ubx(["-p", "COLDBOOT"], timeout=5)


def _warm_start():
    """Force GPS warm start."""
    _run_ubx(["-p", "WARMBOOT"], timeout=5)


def _hot_start():
    """Force GPS hot start."""
    _run_ubx(["-p", "HOTBOOT"], timeout=5)


def _save_config():
    """Save current config to GPS flash/BBR."""
    _run_ubx(["-p", "SAVE"], timeout=5)


# ---------------------------------------------------------------------------
# Menu items
# ---------------------------------------------------------------------------

MENU_ITEMS = [
    {"id": "nav_model", "label": "Nav Model", "type": "cycle"},
    {"id": "rate", "label": "Update Rate", "type": "cycle"},
    {"id": "gps", "label": "GPS", "type": "toggle"},
    {"id": "sbas", "label": "SBAS/EGNOS", "type": "toggle"},
    {"id": "glonass", "label": "GLONASS", "type": "toggle"},
    {"id": "qzss", "label": "QZSS", "type": "toggle"},
    {"id": "apply", "label": "Apply & Save", "type": "action"},
    {"id": "cold", "label": "Cold Restart", "type": "action"},
    {"id": "warm", "label": "Warm Restart", "type": "action"},
    {"id": "hot", "label": "Hot Restart", "type": "action"},
]

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

nav_model_idx = 0
rate_idx = 0
gps_on = True
sbas_on = True
glonass_on = False
qzss_on = True
status_msg = ""
fix_mode = 0
sat_count = 0


# ---------------------------------------------------------------------------
# LCD Drawing
# ---------------------------------------------------------------------------


def _draw(lcd, font, font_sm, cursor):
    img = Image.new("RGB", (WIDTH, HEIGHT), "#000000")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 12), fill="#0a0a14")
    d.text((2, 1), "GPS CONFIG", font=font_sm, fill="#FFAA00")

    # Fix status
    fix_names = {0: "No fix", 1: "Dead Reck", 2: "2D", 3: "3D", 4: "GPS+DR", 5: "Time only"}
    fix_text = fix_names.get(fix_mode, f"Fix {fix_mode}")
    fix_col = "#00FF00" if fix_mode >= 2 else "#FF4444"
    d.text((75, 1), f"{fix_text} {sat_count}sv", font=font_sm, fill=fix_col)

    # Menu items
    y = 15
    for i, item in enumerate(MENU_ITEMS):
        selected = i == cursor
        bg = "#0a1a0a" if selected else "#000"
        d.rectangle((0, y, 127, y + 11), fill=bg)

        label = item["label"]
        item_id = item["id"]

        # Value display
        if item_id == "nav_model":
            val = NAV_MODELS[nav_model_idx][1]
            val_col = "#00CCFF"
        elif item_id == "rate":
            val = UPDATE_RATES[rate_idx][1]
            val_col = "#00CCFF"
        elif item_id == "gps":
            val = "ON" if gps_on else "OFF"
            val_col = "#00FF00" if gps_on else "#FF4444"
        elif item_id == "sbas":
            val = "ON" if sbas_on else "OFF"
            val_col = "#00FF00" if sbas_on else "#FF4444"
        elif item_id == "glonass":
            val = "ON" if glonass_on else "OFF"
            val_col = "#00FF00" if glonass_on else "#FF4444"
            if glonass_on and gps_on:
                val = "ON (!)"
                val_col = "#FFAA00"
        elif item_id == "qzss":
            val = "ON" if qzss_on else "OFF"
            val_col = "#00FF00" if qzss_on else "#FF4444"
        elif item_id in ("apply", "cold", "warm", "hot"):
            val = ""
            val_col = "#888"
        else:
            val = ""
            val_col = "#888"

        name_col = "#FFFFFF" if selected else "#CCCCCC"
        if item_id in ("apply",):
            name_col = "#00FF00" if selected else "#00AA00"
        elif item_id in ("cold", "warm", "hot"):
            name_col = "#FFAA00" if selected else "#886600"

        d.text((3, y), label, font=font_sm, fill=name_col)
        if val:
            d.text((80, y), val, font=font_sm, fill=val_col)

        y += 11
        if y > 112:
            break

    # Status message
    if status_msg:
        d.rectangle((0, 105, 127, 115), fill="#111")
        d.text((2, 106), status_msg[:22], font=font_sm, fill="#FFAA00")

    # Warning
    if glonass_on and gps_on:
        d.rectangle((0, 105, 127, 115), fill="#1a0a00")
        d.text((2, 106), "GPS+GLONASS: pick one!", font=font_sm, fill="#FF4444")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#0a0a14")
    d.text((2, 117), "OK:Edit K1:Apply K3:X", font=font_sm, fill="#666")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    global LCD, nav_model_idx, rate_idx, gps_on, sbas_on, glonass_on, qzss_on
    global status_msg, fix_mode, sat_count

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    font = scaled_font(10)
    font_sm = scaled_font(8)

    # Check ubxtool
    if not os.path.isfile("/usr/bin/ubxtool"):
        img = Image.new("RGB", (WIDTH, HEIGHT), "#000")
        d = ScaledDraw(img)
        d.text((4, 40), "ubxtool not found!", font=font, fill="#FF4444")
        d.text((4, 60), "apt install gpsd-clients", font=font_sm, fill="#888")
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    # Check GPS device
    gps_dev = None
    for dev in ["/dev/ttyACM0", "/dev/ttyACM1", "/dev/ttyUSB0", "/dev/ttyUSB1"]:
        if os.path.exists(dev):
            gps_dev = dev
            break

    if not gps_dev:
        img = Image.new("RGB", (WIDTH, HEIGHT), "#000")
        d = ScaledDraw(img)
        d.text((4, 40), "No GPS device!", font=font, fill="#FF4444")
        d.text((4, 60), "Check USB connection", font=font_sm, fill="#888")
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "#000")
    d = ScaledDraw(img)
    d.text((64, 30), "GPS", font=font, fill="#FFAA00", anchor="mm")
    d.text((64, 45), "CONFIG", font=font, fill="#FFAA00", anchor="mm")
    d.text((64, 65), f"Device: {gps_dev}", font=font_sm, fill="#888", anchor="mm")
    d.text((64, 80), "Reading config...", font=font_sm, fill="#666", anchor="mm")
    LCD.LCD_ShowImage(img, 0, 0)

    # Ensure gpsd is running
    subprocess.run(["pgrep", "gpsd"], capture_output=True)
    r = subprocess.run(["pgrep", "gpsd"], capture_output=True)
    if r.returncode != 0:
        subprocess.Popen(["gpsd", "-n", gps_dev],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)

    # Read current config
    cfg = _get_current_config()
    gps_on = cfg["gps"]
    sbas_on = cfg["sbas"]
    glonass_on = cfg["glonass"]
    qzss_on = cfg["qzss"]
    fix_mode = cfg["fix"]
    sat_count = cfg["sats"]

    # Match nav model to index
    for i, (mid, _) in enumerate(NAV_MODELS):
        if mid == cfg["nav_model"]:
            nav_model_idx = i
            break

    cursor = 0

    time.sleep(0.3)
    while get_button(PINS, GPIO) is not None:
        time.sleep(0.05)

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "UP":
                cursor = max(0, cursor - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                cursor = min(len(MENU_ITEMS) - 1, cursor + 1)
                time.sleep(0.15)

            elif btn in ("OK", "LEFT", "RIGHT"):
                item = MENU_ITEMS[cursor]
                item_id = item["id"]

                if item_id == "nav_model":
                    nav_model_idx = (nav_model_idx + 1) % len(NAV_MODELS)
                    time.sleep(0.2)

                elif item_id == "rate":
                    rate_idx = (rate_idx + 1) % len(UPDATE_RATES)
                    time.sleep(0.2)

                elif item_id == "gps":
                    gps_on = not gps_on
                    time.sleep(0.2)

                elif item_id == "sbas":
                    sbas_on = not sbas_on
                    time.sleep(0.2)

                elif item_id == "glonass":
                    glonass_on = not glonass_on
                    time.sleep(0.2)

                elif item_id == "qzss":
                    qzss_on = not qzss_on
                    time.sleep(0.2)

                elif item_id == "apply":
                    status_msg = "Applying..."
                    _draw(LCD, font, font_sm, cursor)

                    # u-blox 7: GPS et GLONASS mutuellement exclusifs
                    if glonass_on and gps_on:
                        status_msg = "Disable GPS or GLONASS!"
                    else:
                        _apply_constellation("GPS", gps_on)
                        _apply_constellation("SBAS", sbas_on)
                        _apply_constellation("GLONASS", glonass_on)
                        _apply_constellation("QZSS", qzss_on)
                        _apply_nav_model(NAV_MODELS[nav_model_idx][0])
                        _apply_rate(UPDATE_RATES[rate_idx][0])
                        _save_config()
                        status_msg = "Config saved!"
                    time.sleep(0.3)

                elif item_id == "cold":
                    status_msg = "Cold restart..."
                    _draw(LCD, font, font_sm, cursor)
                    _cold_start()
                    status_msg = "Cold restart done"
                    time.sleep(0.3)

                elif item_id == "warm":
                    status_msg = "Warm restart..."
                    _draw(LCD, font, font_sm, cursor)
                    _warm_start()
                    status_msg = "Warm restart done"
                    time.sleep(0.3)

                elif item_id == "hot":
                    status_msg = "Hot restart..."
                    _draw(LCD, font, font_sm, cursor)
                    _hot_start()
                    status_msg = "Hot restart done"
                    time.sleep(0.3)

            elif btn == "KEY1":
                # Quick apply
                status_msg = "Applying..."
                _draw(LCD, font, font_sm, cursor)
                if glonass_on and gps_on:
                    status_msg = "Disable GPS or GLONASS!"
                else:
                    _apply_constellation("GPS", gps_on)
                    _apply_constellation("SBAS", sbas_on)
                    _apply_constellation("GLONASS", glonass_on)
                    _apply_constellation("QZSS", qzss_on)
                    _apply_nav_model(NAV_MODELS[nav_model_idx][0])
                    _apply_rate(UPDATE_RATES[rate_idx][0])
                    _save_config()
                    status_msg = "Config saved!"
                time.sleep(0.3)

            # Refresh fix status every few frames
            if int(time.time()) % 3 == 0:
                try:
                    out, _ = _run_ubx(["-p", "NAV-SOL"], timeout=3)
                    for line in out.splitlines():
                        if "gpsFix" in line:
                            try:
                                fix_mode = int(line.split("gpsFix")[1].strip().split()[0])
                            except Exception:
                                pass
                        if "numSV" in line:
                            try:
                                sat_count = int(line.split("numSV")[1].strip().split()[0])
                            except Exception:
                                pass
                except Exception:
                    pass

            _draw(LCD, font, font_sm, cursor)
            time.sleep(0.05)

    finally:
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
