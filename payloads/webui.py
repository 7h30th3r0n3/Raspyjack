#!/usr/bin/env python3
"""
RaspyJack payload – WebUI controller
------------------------------------
Provides a tiny on-device UI to Start/Stop the RaspyJack Web UI stack:
  - device_server.py (WebSocket server broadcasting LCD frames and receiving input)
  - python -m http.server 8080 serving web/ (static frontend)

Usage inside RaspyJack:
  From the menu: WiFi Manager → WebUI

Controls:
  - UP/DOWN: navigate
  - OK: select
  - KEY3/LEFT: back to RaspyJack
"""

import os
import sys
import json
import time
import signal
import socket
import subprocess

# Allow imports of project drivers when run directly
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

# Optional virtual input bridge so the payload can be driven from the browser too
try:
    import rj_input
except Exception:
    rj_input = None


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
font = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 9)
bold = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf', 9)


# ----------------------------- Paths and state ----------------------------
ROOT_DIR = os.path.abspath(os.path.join(__file__, '..', '..'))
WEB_DIR = os.path.join(ROOT_DIR, 'web')
DEVICE_SERVER = os.path.join(ROOT_DIR, 'device_server.py')
PID_FILE = '/dev/shm/rj_webui_pids.json'


# ------------------------------- UI helpers -------------------------------
def draw_menu(items, index, subtitle=None):
    img = Image.new('RGB', (WIDTH, HEIGHT), 'black')
    d = ImageDraw.Draw(img)
    y = 2
    title = 'WebUI'
    d.text((2, y), title, font=bold, fill='yellow')
    y += 12
    if subtitle:
        d.text((2, y), subtitle[:22], font=font, fill='cyan')
        y += 10
    d.line([(0, 12), (128, 12)], fill='blue', width=1)
    # list window
    win = items
    base_y = 18
    for i, text in enumerate(win):
        sel = (i == index)
        if sel:
            d.rectangle((0, base_y - 2 + i * 12, 128, base_y + 10 + i * 12), fill='#103070')
            fill = 'white'
        else:
            fill = 'white'
        d.text((4, base_y + i * 12), text[:18], font=font, fill=fill)
    LCD.LCD_ShowImage(img, 0, 0)


def get_virtual_button_name():
    if rj_input is None:
        return None
    name = rj_input.get_virtual_button()
    # Map RaspyJack names back to local names
    mapping = {
        'KEY_UP_PIN': 'UP',
        'KEY_DOWN_PIN': 'DOWN',
        'KEY_LEFT_PIN': 'LEFT',
        'KEY_RIGHT_PIN': 'RIGHT',
        'KEY_PRESS_PIN': 'OK',
        'KEY1_PIN': 'KEY1',
        'KEY2_PIN': 'KEY2',
        'KEY3_PIN': 'KEY3',
    }
    return mapping.get(name)


def get_button():
    v = get_virtual_button_name()
    if v:
        return v
    for name, pin in PINS.items():
        if GPIO.input(pin) == 0:
            return name
    return None


def draw_message(lines, color='#00A321', wait_key=True, sleep_s=0.0):
    img = Image.new('RGB', (WIDTH, HEIGHT), 'black')
    d = ImageDraw.Draw(img)
    d.rectangle([3, 14, 124, 124], fill=color)
    y = 20
    for line in lines:
        d.text((8, y), line[:20], font=font, fill='black')
        y += 12
    LCD.LCD_ShowImage(img, 0, 0)
    if sleep_s > 0:
        time.sleep(sleep_s)
    if wait_key:
        # Wait for any button press then release
        while True:
            b = get_button()
            if b:
                while b and GPIO.input(PINS.get(b, next(iter(PINS.values())))) == 0:
                    time.sleep(0.05)
                break
            time.sleep(0.05)


# --------------------------- Process management ---------------------------
def read_pids():
    try:
        with open(PID_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {}


def write_pids(pids):
    try:
        with open(PID_FILE, 'w') as f:
            json.dump(pids, f)
    except Exception:
        pass


def clear_pids():
    try:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
    except Exception:
        pass


def is_pid_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def get_ip_for_url() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return socket.gethostname()


def start_webui() -> str:
    # If already running, keep it and just show URL
    p = read_pids()
    ws_pid = int(p.get('ws_pid', 0) or 0)
    http_pid = int(p.get('http_pid', 0) or 0)
    if (ws_pid and is_pid_running(ws_pid)) and (http_pid and is_pid_running(http_pid)):
        return f"http://{get_ip_for_url()}:8080"

    # Kill any stale instances before starting fresh
    try:
        subprocess.run(["pkill", "-f", "device_server.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-f", "http.server"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

    # Start device_server.py
    ws_env = os.environ.copy()
    ws_cmd = [sys.executable, "-u", DEVICE_SERVER]
    ws_proc = subprocess.Popen(ws_cmd, cwd=ROOT_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

    # Start static HTTP server in web/
    http_cmd = [sys.executable, "-m", "http.server", "8080"]
    http_proc = subprocess.Popen(http_cmd, cwd=WEB_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

    write_pids({"ws_pid": ws_proc.pid, "http_pid": http_proc.pid})
    # Small delay to let services bind
    time.sleep(0.5)
    return f"http://{get_ip_for_url()}:8080"


def stop_webui() -> None:
    p = read_pids()
    ws_pid = int(p.get('ws_pid', 0) or 0)
    http_pid = int(p.get('http_pid', 0) or 0)

    def _safe_kill(pid: int):
        try:
            if pid and is_pid_running(pid):
                os.kill(pid, signal.SIGTERM)
                # fallback to SIGKILL if needed
                for _ in range(10):
                    if not is_pid_running(pid):
                        break
                    time.sleep(0.1)
                if is_pid_running(pid):
                    os.kill(pid, signal.SIGKILL)
        except Exception:
            pass

    _safe_kill(ws_pid)
    _safe_kill(http_pid)

    # Extra safety: kill by pattern
    try:
        subprocess.run(["pkill", "-f", "device_server.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-f", "http.server"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

    clear_pids()


# -------------------------------- Main loop --------------------------------
MENU_ITEMS = [
    "Start WebUI",
    "Stop WebUI",
    "Back",
]


def main():
    running = True
    index = 0

    try:
        draw_menu(MENU_ITEMS, index)
        while running:
            btn = get_button()
            if not btn:
                time.sleep(0.05)
                continue

            if btn == 'UP':
                index = (index - 1) % len(MENU_ITEMS)
                draw_menu(MENU_ITEMS, index)
            elif btn == 'DOWN':
                index = (index + 1) % len(MENU_ITEMS)
                draw_menu(MENU_ITEMS, index)
            elif btn in ('LEFT', 'KEY3'):
                running = False
            elif btn == 'OK':
                choice = MENU_ITEMS[index]
                if choice.startswith('Start'):
                    url = start_webui()
                    draw_message([
                        "WebUI started!",
                        f"URL:",
                        f"  {url}",
                        "Open in browser",
                    ], wait_key=False)
                    # brief pause before returning to menu
                    time.sleep(1.2)
                    draw_menu(MENU_ITEMS, index, subtitle=url)
                elif choice.startswith('Stop'):
                    stop_webui()
                    draw_message(["WebUI stopped."], sleep_s=0.8)
                    draw_menu(MENU_ITEMS, index)
                else:  # Back
                    running = False
            # wait for button release for basic debounce
            while btn and GPIO.input(PINS.get(btn, next(iter(PINS.values())))) == 0:
                time.sleep(0.03)

    except KeyboardInterrupt:
        pass
    finally:
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()


if __name__ == '__main__':
    main()
