#!/usr/bin/env python3
"""
RaspyJack Payload -- QR Code Generator (LCD)
=====================================================
Author: 7h30th3r0n3

Generate and display QR codes on the 1.44" LCD for quick sharing
of URLs, IPs, WiFi credentials, or custom text.

Preset modes:
  - WebUI URL (https://<Pi_IP>/)
  - Pi IP address
  - WiFi Connect (WIFI:S:...;T:WPA;P:...;;)
  - Custom Text (character-by-character input)

Controls:
  LEFT / RIGHT -- Cycle mode
  OK           -- Generate / refresh QR
  UP / DOWN    -- Scroll chars in custom text mode
  KEY1         -- Toggle invert colors
  KEY3         -- Exit
"""

import os
import sys
import time
import subprocess
import threading

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

try:
    import qrcode
except ImportError:
    qrcode = None

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
font = scaled_font()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MODES = ["WebUI", "Pi IP", "WiFi", "Custom"]
QR_SIZE = WIDTH - 8
QR_OFFSET_X = 4
QR_OFFSET_Y = 2
LABEL_Y = HEIGHT - 10

# Characters for custom text input
CHARSET = list(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    " .-_/:@?&=#%+!"
)

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
mode_idx = 0
inverted = False
status_msg = ""
qr_image = None         # current PIL Image of QR code (LCD)

# Custom text state
custom_text = []         # list of characters
custom_cursor = 0
char_idx = 0             # index into CHARSET for current position

# WiFi config (editable)
wifi_ssid = "RaspyJack"
wifi_pass = "changeme"


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _get_pi_ip():
    """Get the Pi's current IP address."""
    try:
        result = subprocess.run(
            ["hostname", "-I"],
            capture_output=True, text=True, timeout=5,
        )
        ips = result.stdout.strip().split()
        return ips[0] if ips else "127.0.0.1"
    except Exception:
        return "127.0.0.1"


# ---------------------------------------------------------------------------
# QR generation
# ---------------------------------------------------------------------------

def _generate_qr(data):
    """Generate a QR code image sized for the LCD."""
    if qrcode is None:
        return _error_image("qrcode not installed")

    if not data:
        return _error_image("No data")

    try:
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=4,
            border=1,
        )
        qr.add_data(data)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_img = qr_img.resize((QR_SIZE, QR_SIZE), Image.NEAREST)
        return qr_img.convert("RGB")
    except Exception as exc:
        return _error_image(str(exc)[:20])


def _error_image(msg):
    """Create a small error placeholder image."""
    img = Image.new("RGB", (QR_SIZE, QR_SIZE), "black")
    d = ScaledDraw(img)
    d.text((4, QR_SIZE // 2 - 5), msg[:18], font=font, fill="#FF4444")
    return img


def _compose_display(qr_img, label, is_inverted):
    """Compose the final LCD display image with QR and label."""
    if is_inverted:
        from PIL import ImageOps
        qr_img = ImageOps.invert(qr_img.convert("RGB"))

    canvas = Image.new("RGB", (WIDTH, HEIGHT), "black")
    canvas.paste(qr_img, (QR_OFFSET_X, QR_OFFSET_Y))

    d = ScaledDraw(canvas)
    truncated = label[:22] if len(label) > 22 else label
    d.text((2, LABEL_Y), truncated, font=font, fill="#888888")

    return canvas


def _get_mode_data(mode):
    """Return (data_string, label) for a given mode."""
    if mode == "WebUI":
        ip = _get_pi_ip()
        url = f"https://{ip}/"
        return url, f"WebUI: {ip}"

    if mode == "Pi IP":
        ip = _get_pi_ip()
        return ip, f"IP: {ip}"

    if mode == "WiFi":
        with lock:
            ssid = wifi_ssid
            pw = wifi_pass
        data = f"WIFI:S:{ssid};T:WPA;P:{pw};;"
        return data, f"WiFi: {ssid}"

    if mode == "Custom":
        with lock:
            text = "".join(custom_text)
        if not text:
            return "", "Custom: (empty)"
        return text, f"Custom: {text[:14]}"

    return "", "Unknown mode"


def _refresh_qr():
    """Regenerate the QR code for the current mode."""
    global qr_image, status_msg

    with lock:
        mode = MODES[mode_idx]
        inv = inverted

    data, label = _get_mode_data(mode)
    qr_img = _generate_qr(data)
    display = _compose_display(qr_img, label, inv)

    with lock:
        qr_image = display
        status_msg = label


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_qr_view():
    """Show the generated QR code."""
    with lock:
        img = qr_image

    if img is not None:
        LCD.LCD_ShowImage(img, 0, 0)
    else:
        _draw_mode_select()


def _draw_mode_select():
    """Show mode selection when no QR is displayed yet."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "QR GENERATOR", font=font, fill="#00CCFF")

    with lock:
        mode = MODES[mode_idx]
        inv = inverted

    y = 20
    for i, m in enumerate(MODES):
        color = "#FFFF00" if i == mode_idx else "#888"
        marker = ">" if i == mode_idx else " "
        d.text((2, y), f"{marker} {m}", font=font, fill=color)
        y += 14

    d.text((2, 78), f"Invert: {'ON' if inv else 'OFF'}", font=font, fill="#666")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "L/R:Mode OK:Gen K3:X", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_custom_editor():
    """Show the custom text character editor."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "CUSTOM TEXT", font=font, fill="#FFAA00")

    with lock:
        text = list(custom_text)
        cur = custom_cursor
        ci = char_idx

    # Show current text
    text_str = "".join(text)
    d.text((2, 18), f"Text: {text_str[:18]}", font=font, fill="#FFFFFF")

    # Show cursor position
    if len(text_str) > 18:
        d.text((2, 30), f"      {text_str[18:36]}", font=font, fill="#FFFFFF")

    # Current character selector
    current_char = CHARSET[ci] if CHARSET else "?"
    d.text((2, 48), f"Char: [{current_char}]", font=font, fill="#00FF00")
    d.text((2, 60), f"Pos: {cur}/{len(text)}", font=font, fill="#888")

    # Instructions
    d.text((2, 78), "UP/DN: change char", font=font, fill="#666")
    d.text((2, 90), "OK: add char", font=font, fill="#666")
    d.text((2, 102), "KEY1: backspace", font=font, fill="#666")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "KEY2:Gen QR K3:Back", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global mode_idx, inverted, qr_image
    global custom_text, custom_cursor, char_idx

    if qrcode is None:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "qrcode not installed", font=font, fill="#FF4444")
        d.text((4, 65), "pip3 install qrcode", font=font, fill="#888")
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 16), "QR GENERATOR", font=font, fill="#00CCFF")
    d.text((4, 36), "Generate QR codes", font=font, fill="#888")
    d.text((4, 48), "for the LCD", font=font, fill="#888")
    d.text((4, 66), "L/R=Mode  OK=Generate", font=font, fill="#666")
    d.text((4, 78), "K1=Invert K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.5)

    in_custom_edit = False

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if in_custom_edit:
                    in_custom_edit = False
                    time.sleep(0.2)
                    continue
                break

            # --- Custom text editor ---
            if in_custom_edit:
                if btn == "UP":
                    with lock:
                        char_idx = (char_idx + 1) % len(CHARSET)
                    time.sleep(0.12)

                elif btn == "DOWN":
                    with lock:
                        char_idx = (char_idx - 1) % len(CHARSET)
                    time.sleep(0.12)

                elif btn == "OK":
                    with lock:
                        ch = CHARSET[char_idx]
                        custom_text = custom_text + [ch]
                        custom_cursor = len(custom_text)
                    time.sleep(0.15)

                elif btn == "KEY1":
                    # Backspace
                    with lock:
                        if custom_text:
                            custom_text = custom_text[:-1]
                            custom_cursor = len(custom_text)
                    time.sleep(0.15)

                elif btn == "KEY2":
                    _refresh_qr()
                    in_custom_edit = False
                    time.sleep(0.2)
                    continue

                _draw_custom_editor()
                time.sleep(0.05)
                continue

            # --- Main QR view ---
            if btn == "LEFT":
                with lock:
                    mode_idx = (mode_idx - 1) % len(MODES)
                    qr_image = None
                time.sleep(0.2)

            elif btn == "RIGHT":
                with lock:
                    mode_idx = (mode_idx + 1) % len(MODES)
                    qr_image = None
                time.sleep(0.2)

            elif btn == "OK":
                with lock:
                    mode = MODES[mode_idx]
                if mode == "Custom":
                    in_custom_edit = True
                    time.sleep(0.2)
                    continue
                _refresh_qr()
                time.sleep(0.2)

            elif btn == "KEY1":
                with lock:
                    inverted = not inverted
                # Re-render if we have a QR
                with lock:
                    has_qr = qr_image is not None
                if has_qr:
                    _refresh_qr()
                time.sleep(0.25)

            with lock:
                has_qr = qr_image is not None

            if has_qr:
                _draw_qr_view()
            else:
                _draw_mode_select()

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
