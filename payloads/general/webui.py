#!/usr/bin/env python3
"""
RaspyJack payload – WebUI Info
------------------------------
Displays the WebUI URL.
Services are managed by systemd (raspyjack-webui.service),
so this payload is just a viewer.

Controls:
  - KEY3/LEFT: back to RaspyJack
"""

import os
import sys
import time
import socket
import signal
import textwrap

# Allow imports of project drivers when run directly
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._input_helper import get_button

# --------------------------- LCD and GPIO setup ---------------------------
PINS = {
    "UP": 6,
    "DOWN": 19,
    "LEFT": 5,
    "RIGHT": 26,
    "OK": 13,
    "KEY1": 21,
    "KEY2": 20,
    "KEY3": 16,
}

GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
font = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 11)
bold = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf', 12)
small_font = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 9)

# ------------------------------- Helpers -------------------------------

def get_ip_for_url() -> str:
    """Get the IP to display for the WebUI URL.
    
    Prefer wlan0 since it is the dedicated WebUI interface and is
    never disrupted by monitor-mode payloads.
    """
    import subprocess
    # Try wlan0 first — it is the dedicated WebUI interface
    try:
        result = subprocess.run(
            ['ip', '-4', 'addr', 'show', 'wlan0'],
            capture_output=True, text=True, timeout=3)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'inet ' in line:
                    return line.split('inet ')[1].split('/')[0]
    except Exception:
        pass
    # Fallback to default-route method
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def draw_info(https_url: str, http_url: str):
    img = Image.new('RGB', (WIDTH, HEIGHT), 'black')
    d = ImageDraw.Draw(img)
    
    # Header
    d.rectangle((0, 0, 128, 20), fill='#00A321')
    d.text((4, 2), "WebUI Active", font=bold, fill='black')
    
    # Content
    y = 28
    d.text((4, y), "Use HTTPS (preferred):", font=small_font, fill='white')
    y += 13

    def _text_width(txt: str) -> int:
        """Pixel width for given text with the main font."""
        try:
            return int(d.textlength(txt, font=font))
        except Exception:
            try:
                box = d.textbbox((0, 0), txt, font=font)
                return int(box[2] - box[0])
            except Exception:
                return len(txt) * 6

    def _wrap_by_pixels(txt: str, max_px: int) -> list[str]:
        """Wrap text by pixel width (URLs have no spaces)."""
        s = str(txt or "")
        if not s:
            return []
        if max_px <= 0:
            return [s]
        out: list[str] = []
        i = 0
        while i < len(s):
            j = i + 1
            # Grow until it would overflow.
            while j <= len(s) and _text_width(s[i:j]) <= max_px:
                j += 1
            # Step back one (last fit), ensuring progress.
            j = max(i + 1, j - 1)
            out.append(s[i:j])
            i = j
        return out

    def _draw_labeled_url(y0: int, label: str, url: str) -> int:
        x0 = 4
        line_h = 14
        label_color = 'yellow'
        url_color = 'cyan'

        d.text((x0, y0), label, font=font, fill=label_color)
        label_w = _text_width(label)

        # First line: URL continues after the label.
        x_url = x0 + label_w + 2
        first_max = WIDTH - 4 - (label_w + 2)
        full_max = WIDTH - 8

        remaining = str(url or "")
        first_chunk = ""
        if remaining:
            chunks = _wrap_by_pixels(remaining, first_max)
            if chunks:
                first_chunk = chunks[0]
                d.text((x_url, y0), first_chunk, font=font, fill=url_color)
                remaining = remaining[len(first_chunk):]

        y0 += line_h
        for line in _wrap_by_pixels(remaining, full_max):
            d.text((x0, y0), line, font=font, fill=url_color)
            y0 += line_h
        return y0

    y = _draw_labeled_url(y, "Https: ", https_url)
    y = _draw_labeled_url(y, "Http: ", http_url)
        
    # Footer
    d.line([(0, 110), (128, 110)], fill='gray', width=1)
    d.text((4, 114), "< Back (KEY3)", font=small_font, fill='yellow')
    
    LCD.LCD_ShowImage(img, 0, 0)

# -------------------------------- Main --------------------------------
running = True


def _handle_exit_signal(signum, _frame):
    global running
    running = False


def main():
    global running
    try:
        signal.signal(signal.SIGINT, _handle_exit_signal)
        signal.signal(signal.SIGTERM, _handle_exit_signal)

        # 1. Get IP and URL
        ip = get_ip_for_url()
        https_url = f"https://{ip}/"
        http_url = f"http://{ip}:8080"

        print("use https")
        print(f"Https:{https_url}")
        print(f"Http:{http_url}")
        
        # 2. Draw info
        draw_info(https_url, http_url)
        
        # 3. Wait for exit button
        while running:
            btn = get_button(PINS, GPIO)
            if btn in ("KEY3", "LEFT"):
                break
            time.sleep(0.1)

    except KeyboardInterrupt:
        pass
    finally:
        # Cleanup is handled by the parent process usually, but good practice
        # to clear if we wanted, but we'll let parent restore menu
        pass

if __name__ == '__main__':
    main()
