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
import textwrap

# Allow imports of project drivers when run directly
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

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

def draw_info(url):
    img = Image.new('RGB', (WIDTH, HEIGHT), 'black')
    d = ImageDraw.Draw(img)
    
    # Header
    d.rectangle((0, 0, 128, 20), fill='#00A321')
    d.text((4, 2), "WebUI Active", font=bold, fill='black')
    
    # Content
    y = 28
    d.text((4, y), "Access at:", font=small_font, fill='white')
    y += 15
    
    # Wrap URL
    # Approx char width for small_font is 6-7px, screen is 128px ~ 18_20 chars
    # We can use textwrap for safety
    wrapper = textwrap.TextWrapper(width=18) 
    lines = wrapper.wrap(url)
    
    for line in lines:
        d.text((4, y), line, font=font, fill='cyan')
        y += 14
        
    # Footer
    d.line([(0, 110), (128, 110)], fill='gray', width=1)
    d.text((4, 114), "< Back (KEY3)", font=small_font, fill='yellow')
    
    LCD.LCD_ShowImage(img, 0, 0)

# -------------------------------- Main --------------------------------

def main():
    try:
        # 1. Get IP and URL
        ip = get_ip_for_url()
        url = f"http://{ip}:8080"
        
        # 2. Draw info
        draw_info(url)
        
        # 3. Wait for exit button
        while True:
            # Check for generic GPIO pins
            if GPIO.input(PINS['KEY3']) == 0 or GPIO.input(PINS['LEFT']) == 0:
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
