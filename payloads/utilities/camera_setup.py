#!/usr/bin/env python3
"""
RaspyJack Payload -- Camera Setup
====================================
Author: 7h30th3r0n3

Checks and configures the IMX219 camera for CardputerZero.
Fixes config.txt if needed, installs dependencies, tests camera.

Controls:
  OK          Run checks / Apply fixes
  KEY3        Exit
"""

import os
import sys
import time
import signal
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)
for p in PINS.values():
    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)
time.sleep(0.1)
_STUCK_PINS = {name for name, pin in PINS.items() if GPIO.input(pin) == 0}

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
W, H = LCD.width, LCD.height
IS_WIDE = W > 200

if IS_WIDE:
    from PIL import ImageFont
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 13)
        font_sm = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 10)
        font_lg = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 16)
    except Exception:
        font = scaled_font(9)
        font_sm = scaled_font(7)
        font_lg = scaled_font(12)
else:
    font = scaled_font(10)
    font_sm = scaled_font(8)
    font_lg = scaled_font(12)

CONFIG_PATH = "/boot/firmware/config.txt"
DEBOUNCE = 0.20
_running = True

C_BG = (5, 5, 10)
C_HEAD = (20, 20, 40)
C_GREEN = (0, 220, 80)
C_RED = (255, 50, 50)
C_YELLOW = (255, 200, 0)
C_WHITE = (255, 255, 255)
C_DIM = (80, 80, 80)
C_CYAN = (0, 200, 220)
C_DARK = (12, 12, 20)


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _get_btn():
    btn = get_button(PINS, GPIO)
    if btn and btn in _STUCK_PINS:
        return None
    return btn


def _read_config():
    try:
        with open(CONFIG_PATH, "r") as f:
            return f.read()
    except Exception:
        return ""


def _check_config():
    """Check config.txt for camera settings. Returns list of (check, status, fix_needed)."""
    config = _read_config()
    checks = []

    has_auto_detect_0 = "camera_auto_detect=0" in config
    has_auto_detect_1 = "camera_auto_detect=1" in config
    if has_auto_detect_0:
        checks.append(("camera_auto_detect=0", True, False))
    elif has_auto_detect_1:
        checks.append(("camera_auto_detect=0", False, True))
    else:
        checks.append(("camera_auto_detect=0", False, True))

    has_imx219 = "dtoverlay=imx219" in config
    checks.append(("dtoverlay=imx219", has_imx219, not has_imx219))

    has_gpio16 = "gpio=16=op,dh" in config
    checks.append(("gpio=16=op,dh (power)", has_gpio16, not has_gpio16))

    return checks


def _check_rpicam():
    """Check if rpicam tools are installed."""
    return os.path.isfile("/usr/bin/rpicam-still")


def _check_camera_detected():
    """Check if camera is detected by libcamera."""
    try:
        r = subprocess.run(
            ["rpicam-hello", "--list-cameras"],
            capture_output=True, text=True, timeout=5)
        return "imx219" in r.stdout.lower()
    except Exception:
        return False


def _check_camera_capture():
    """Try to capture a test frame."""
    try:
        r = subprocess.run(
            ["rpicam-still", "-o", "/tmp/cam_setup_test.jpg",
             "--width", "640", "--height", "480",
             "-t", "500", "--nopreview", "--rotation", "180"],
            capture_output=True, timeout=10)
        if os.path.isfile("/tmp/cam_setup_test.jpg"):
            sz = os.path.getsize("/tmp/cam_setup_test.jpg")
            os.remove("/tmp/cam_setup_test.jpg")
            return sz > 1000
    except Exception:
        pass
    return False


def _apply_fixes():
    """Fix config.txt for camera support."""
    config = _read_config()
    modified = False

    if "camera_auto_detect=1" in config:
        config = config.replace("camera_auto_detect=1", "camera_auto_detect=0")
        modified = True

    if "camera_auto_detect=0" not in config:
        config += "\ncamera_auto_detect=0\n"
        modified = True

    if "dtoverlay=imx219" not in config:
        config += "dtoverlay=imx219\n"
        modified = True

    if "gpio=16=op,dh" not in config:
        config += "gpio=16=op,dh\n"
        modified = True

    if modified:
        try:
            with open(CONFIG_PATH, "w") as f:
                f.write(config)
            return True
        except Exception:
            return False
    return True


def _install_rpicam():
    """Install rpicam tools if missing."""
    r = subprocess.run(
        ["apt-get", "install", "-y", "rpicam-apps-lite"],
        capture_output=True, timeout=120)
    return r.returncode == 0


def _draw_screen(checks, rpicam_ok, detected, capture_ok, state_msg=""):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    if IS_WIDE:
        d.rectangle([0, 0, W, 22], fill=C_HEAD)
        d.text((W // 2, 11), "CAMERA SETUP", font=font_lg, fill=C_CYAN,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 50, 2), "CAMERA SETUP", font=font_lg, fill=C_CYAN)

        y = 28
        for name, ok, _ in checks:
            icon = "" if ok else ""
            color = C_GREEN if ok else C_RED
            d.text((8, y), f"{icon} {name}", font=font_sm, fill=color)
            y += 16

        icon = "" if rpicam_ok else ""
        color = C_GREEN if rpicam_ok else C_RED
        d.text((8, y), f"{icon} rpicam-apps", font=font_sm, fill=color)
        y += 16

        icon = "" if detected else ""
        color = C_GREEN if detected else C_RED
        d.text((8, y), f"{icon} Camera detected", font=font_sm, fill=color)
        y += 16

        icon = "" if capture_ok else ""
        color = C_GREEN if capture_ok else C_RED
        d.text((8, y), f"{icon} Capture test", font=font_sm, fill=color)
        y += 20

        if state_msg:
            d.text((8, y), state_msg, font=font_sm, fill=C_YELLOW)

        needs_fix = any(fix for _, _, fix in checks) or not rpicam_ok
        needs_reboot = any(fix for _, _, fix in checks)

        d.rectangle([0, H - 16, W, H], fill=C_DARK)
        if needs_fix:
            d.text((W // 2, H - 8), "OK: Apply fixes  KEY3: Exit",
                   font=font_sm, fill=C_YELLOW,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (5, H - 13), "OK:Fix K3:Exit", font=font_sm, fill=C_YELLOW)
        elif not detected:
            d.text((W // 2, H - 8), "Config OK but camera not found - reboot needed?",
                   font=font_sm, fill=C_YELLOW,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (5, H - 13), "Reboot needed?", font=font_sm, fill=C_YELLOW)
        else:
            d.text((W // 2, H - 8), "All good! Camera ready. KEY3: Exit",
                   font=font_sm, fill=C_GREEN,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (5, H - 13), "All good! K3:Exit", font=font_sm, fill=C_GREEN)
    else:
        d.rectangle([0, 0, 128, 14], fill=C_HEAD)
        d.text((10, 1), "CAM SETUP", font=font_lg, fill=C_CYAN)
        y = 18
        for name, ok, _ in checks:
            icon = "+" if ok else "X"
            color = C_GREEN if ok else C_RED
            short = name.split("=")[0][:13]
            d.text((4, y), f"{icon} {short}", font=font_sm, fill=color)
            y += 13
        d.text((4, y), f"{'+ rpicam' if rpicam_ok else 'X rpicam'}", font=font_sm,
               fill=C_GREEN if rpicam_ok else C_RED)
        y += 13
        d.text((4, y), f"{'+ detected' if detected else 'X no cam'}", font=font_sm,
               fill=C_GREEN if detected else C_RED)
        y += 13
        d.text((4, y), f"{'+ capture' if capture_ok else 'X no cap'}", font=font_sm,
               fill=C_GREEN if capture_ok else C_RED)
        if state_msg:
            d.text((4, 100), state_msg[:17], font=font_sm, fill=C_YELLOW)
        d.text((4, 112), "OK:Fix K3:Exit", font=font_sm, fill=C_DIM)

    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global _running

    state_msg = "Checking..."
    checks = _check_config()
    rpicam_ok = _check_rpicam()
    detected = False
    capture_ok = False

    _draw_screen(checks, rpicam_ok, detected, capture_ok, state_msg)

    if rpicam_ok:
        state_msg = "Testing camera..."
        _draw_screen(checks, rpicam_ok, detected, capture_ok, state_msg)
        detected = _check_camera_detected()
        if detected:
            state_msg = "Test capture..."
            _draw_screen(checks, rpicam_ok, detected, capture_ok, state_msg)
            capture_ok = _check_camera_capture()

    needs_fix = any(fix for _, _, fix in checks) or not rpicam_ok
    if not needs_fix and detected and capture_ok:
        state_msg = "Everything OK!"
    elif not needs_fix and not detected:
        state_msg = "Config OK - reboot to apply"
    else:
        state_msg = "Fixes needed - press OK"

    _draw_screen(checks, rpicam_ok, detected, capture_ok, state_msg)
    last_btn = 0

    while _running:
        btn = _get_btn()
        now = time.time()

        if btn == "KEY3":
            break

        if btn == "OK" and now - last_btn > 0.5:
            last_btn = now
            needs_fix = any(fix for _, _, fix in checks) or not rpicam_ok

            if needs_fix:
                state_msg = "Applying config fixes..."
                _draw_screen(checks, rpicam_ok, detected, capture_ok, state_msg)
                _apply_fixes()
                checks = _check_config()

                if not rpicam_ok:
                    state_msg = "Installing rpicam-apps..."
                    _draw_screen(checks, rpicam_ok, detected, capture_ok, state_msg)
                    _install_rpicam()
                    rpicam_ok = _check_rpicam()

                state_msg = "Fixes applied! Reboot needed"
                _draw_screen(checks, rpicam_ok, detected, capture_ok, state_msg)
                time.sleep(2)

                state_msg = "Reboot now? OK:Yes KEY3:No"
                _draw_screen(checks, rpicam_ok, detected, capture_ok, state_msg)
                while _running:
                    b = _get_btn()
                    if b == "OK":
                        subprocess.run(["reboot"], capture_output=True)
                        time.sleep(5)
                        break
                    if b == "KEY3":
                        state_msg = "Reboot later to activate camera"
                        break
                    time.sleep(0.1)
            else:
                state_msg = "Re-checking..."
                _draw_screen(checks, rpicam_ok, detected, capture_ok, state_msg)
                detected = _check_camera_detected()
                if detected:
                    capture_ok = _check_camera_capture()
                if detected and capture_ok:
                    state_msg = "Camera works!"
                elif detected:
                    state_msg = "Detected but capture failed"
                else:
                    state_msg = "Not detected - check cable"

            _draw_screen(checks, rpicam_ok, detected, capture_ok, state_msg)

        time.sleep(0.1)

    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
