#!/usr/bin/env python3
"""
RaspyJack Payload -- Serial Terminal (Multi-port)
===================================================
Author: 7h30th3r0n3

Multi-port serial terminal with auto-baud detection.
Supports GPIO UART and USB serial simultaneously.
Type with TCA8418 keyboard.

Controls:
  LEFT/RIGHT  Switch between connected ports
  UP/DOWN     Scroll history (connected) / Baud rate (setup)
  OK          Connect / Send command / Disconnect (long press)
  KEY1        Auto-detect baud rate
  KEY2        Send Ctrl+C / Special chars menu
  KEY3        Exit
  Keyboard    Type and send
"""

import os
import sys
import time
import signal
import subprocess
import glob
import threading

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

try:
    import evdev
    from evdev import InputDevice, ecodes
    EVDEV_OK = True
except ImportError:
    EVDEV_OK = False

try:
    import serial
except ImportError:
    subprocess.run(["pip3", "install", "--break-system-packages", "pyserial"],
                   capture_output=True, timeout=60)
    import serial

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
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 11)
        font_sm = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 10)
        font_lg = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 14)
    except Exception:
        font = scaled_font(8)
        font_sm = scaled_font(7)
        font_lg = scaled_font(12)
else:
    font = scaled_font(8)
    font_sm = scaled_font(7)
    font_lg = font

BAUDS = [300, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600]
DEBOUNCE = 0.18
MAX_LINES = 10 if IS_WIDE else 6
MAX_COLS = 48 if IS_WIDE else 18

_running = True

C_BG = (0, 0, 0)
C_HEAD = (0, 15, 30)
C_GREEN = (0, 255, 80)
C_CYAN = (0, 200, 255)
C_WHITE = (255, 255, 255)
C_DIM = (70, 70, 70)
C_DARK = (12, 12, 18)
C_RED = (255, 50, 50)
C_YELLOW = (255, 200, 0)
C_PROMPT = (255, 160, 0)
C_TAB_ACTIVE = (0, 80, 160)
C_TAB_INACTIVE = (30, 30, 40)

_EVDEV_CHARS = {
    2: '1', 3: '2', 4: '3', 5: '4', 6: '5', 7: '6', 8: '7', 9: '8', 10: '9', 11: '0',
    16: 'q', 17: 'w', 18: 'e', 19: 'r', 20: 't', 21: 'y', 22: 'u', 23: 'i', 24: 'o', 25: 'p',
    30: 'a', 31: 's', 32: 'd', 33: 'f', 34: 'g', 35: 'h', 36: 'j', 37: 'k', 38: 'l',
    44: 'z', 45: 'x', 46: 'c', 47: 'v', 48: 'b', 49: 'n', 50: 'm',
    57: ' ', 12: '-', 13: '=', 52: '.', 53: '/', 39: ';', 40: "'",
    26: '[', 27: ']', 43: '\\', 51: ',',
}

_EVDEV_SHIFT = {
    2: '!', 3: '@', 4: '#', 5: '$', 6: '%', 7: '^', 8: '&', 9: '*', 10: '(', 11: ')',
    12: '_', 13: '+', 52: '>', 53: '?', 39: ':', 40: '"',
    26: '{', 27: '}', 43: '|', 51: '<',
}


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


class SerialPort:
    def __init__(self, path):
        self.path = path
        self.name = os.path.basename(path)
        self.baud = 115200
        self.ser = None
        self.connected = False
        self.lines = []
        self.lock = threading.Lock()
        self.thread = None

    def connect(self):
        try:
            self.ser = serial.Serial(self.path, self.baud, timeout=0.2)
            self.connected = True
            self.thread = threading.Thread(target=self._rx_loop, daemon=True)
            self.thread.start()
            return True
        except Exception:
            self.connected = False
            return False

    def disconnect(self):
        self.connected = False
        if self.ser:
            try:
                self.ser.close()
            except Exception:
                pass
        self.ser = None

    def send(self, data):
        if self.ser and self.connected:
            try:
                self.ser.write(data.encode())
            except Exception:
                pass

    def send_line(self, line):
        self.send(line + "\r\n")
        with self.lock:
            self.lines.append(f"> {line}")
            if len(self.lines) > 300:
                self.lines = self.lines[-300:]

    def clear(self):
        with self.lock:
            self.lines = []

    def _rx_loop(self):
        while self.connected and _running:
            try:
                raw = self.ser.readline()
                if raw:
                    line = raw.decode(errors="replace").rstrip("\r\n")
                    with self.lock:
                        self.lines.append(line)
                        if len(self.lines) > 300:
                            self.lines = self.lines[-300:]
            except Exception:
                time.sleep(0.05)

    def auto_baud(self):
        """Try baud rates and find the one producing readable ASCII."""
        best_baud = 115200
        best_score = 0
        was_connected = self.connected
        if was_connected:
            self.disconnect()
            time.sleep(0.2)

        for baud in [115200, 9600, 57600, 38400, 19200, 230400, 460800, 4800, 1200]:
            try:
                s = serial.Serial(self.path, baud, timeout=0.5)
                s.reset_input_buffer()
                time.sleep(0.3)
                data = s.read(256)
                s.close()
                if not data:
                    continue
                printable = sum(1 for b in data if 32 <= b <= 126 or b in (10, 13, 9))
                score = printable / len(data)
                if score > best_score:
                    best_score = score
                    best_baud = baud
                if score > 0.8:
                    break
            except Exception:
                continue

        self.baud = best_baud
        if was_connected:
            self.connect()
        return best_baud, best_score


def _scan_ports():
    ports = []
    for p in sorted(glob.glob("/dev/ttyUSB*")):
        ports.append(p)
    for p in sorted(glob.glob("/dev/ttyACM*")):
        ports.append(p)
    if os.path.exists("/dev/ttyS0"):
        ports.append("/dev/ttyS0")
    if os.path.exists("/dev/ttyAMA0") and "/dev/ttyAMA0" not in ports:
        ports.append("/dev/ttyAMA0")
    return ports


def _find_evdev_keyboard():
    if not EVDEV_OK:
        return None
    for path in evdev.list_devices():
        try:
            dev = InputDevice(path)
            if "tca8418" in dev.name.lower() or "keyboard" in dev.name.lower():
                return dev
        except Exception:
            pass
    return None


def _draw_screen(serial_ports, active_idx, tx_buf, scroll, state):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    if not serial_ports:
        if IS_WIDE:
            d.text((W // 2, H // 2), "No serial ports found", font=font, fill=C_RED,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (30, H // 2 - 6), "No serial ports found", font=font, fill=C_RED)
            d.text((W // 2, H // 2 + 20), "KEY1: Rescan  KEY3: Exit", font=font_sm, fill=C_DIM,
                   anchor="mm") if hasattr(d, 'textbbox') else d.text(
                       (30, H // 2 + 14), "KEY1:Rescan K3:Exit", font=font_sm, fill=C_DIM)
        LCD.LCD_ShowImage(img, 0, 0)
        return

    sp = serial_ports[active_idx]

    if IS_WIDE:
        tab_w = min(W // max(len(serial_ports), 1), 100)
        for i, p in enumerate(serial_ports):
            tx = i * tab_w
            color = C_TAB_ACTIVE if i == active_idx else C_TAB_INACTIVE
            d.rectangle([tx, 0, tx + tab_w - 1, 16], fill=color)
            label = p.name[:8]
            if p.connected:
                label += "*"
            tc = C_WHITE if i == active_idx else C_DIM
            d.text((tx + 3, 2), label, font=font_sm, fill=tc)

        info_y = 18
        baud_str = f"{sp.baud} baud"
        status = "CONNECTED" if sp.connected else "READY"
        sc = C_GREEN if sp.connected else C_YELLOW
        d.text((4, info_y), f"{sp.path} | {baud_str} | {status}", font=font_sm, fill=sc)

        term_y = 32
        with sp.lock:
            lines = list(sp.lines)
        visible_start = max(0, len(lines) - MAX_LINES - scroll)
        visible_end = visible_start + MAX_LINES
        visible = lines[visible_start:visible_end]

        line_h = 12
        for i, ln in enumerate(visible):
            txt = ln[:MAX_COLS]
            color = C_PROMPT if ln.startswith(">") else C_GREEN
            d.text((3, term_y + i * line_h), txt, font=font_sm, fill=color)

        prompt_y = H - 28
        d.rectangle([0, prompt_y, W, prompt_y + 13], fill=C_DARK)
        cursor = "_" if int(time.time() * 2) % 2 else " "
        d.text((3, prompt_y + 1), f"> {tx_buf}{cursor}", font=font_sm, fill=C_PROMPT)

        d.rectangle([0, H - 14, W, H], fill=C_DARK)
        if state == "connected":
            bar = "Enter:Send K1:AutoBaud K2:Ctrl+C L/R:Port K3:Exit"
        else:
            bar = "OK:Connect K1:AutoBaud UP/DN:Baud L/R:Port K3:Exit"
        d.text((W // 2, H - 7), bar, font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (2, H - 12), bar[:48], font=font_sm, fill=C_DIM)
    else:
        d.rectangle([0, 0, 128, 11], fill=C_HEAD)
        label = f"{sp.name} {sp.baud}"
        sc = C_GREEN if sp.connected else C_YELLOW
        d.text((64, 0), label, font=font_sm, fill=sc)

        with sp.lock:
            lines = list(sp.lines)
        visible_start = max(0, len(lines) - MAX_LINES - scroll)
        visible = lines[visible_start:visible_start + MAX_LINES]
        y = 13
        for i, ln in enumerate(visible):
            color = C_PROMPT if ln.startswith(">") else C_GREEN
            d.text((2, y + i * 13), ln[:MAX_COLS], font=font_sm, fill=color)

        d.text((2, H - 14), f">{tx_buf}_", font=font_sm, fill=C_PROMPT)

    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global _running

    port_paths = _scan_ports()
    serial_ports = [SerialPort(p) for p in port_paths]
    active_idx = 0
    tx_buf = ""
    scroll = 0
    last_btn = 0
    kbd = _find_evdev_keyboard()
    shift_held = False

    for sp in serial_ports:
        sp.auto_baud()
        sp.connect()

    _draw_screen(serial_ports, active_idx, tx_buf, scroll,
                 "connected" if serial_ports and serial_ports[active_idx].connected else "setup")

    while _running:
        btn = _get_btn()
        now = time.time()

        if btn == "KEY3":
            break

        if btn == "LEFT" and now - last_btn > DEBOUNCE and serial_ports:
            last_btn = now
            active_idx = (active_idx - 1) % len(serial_ports)
            scroll = 0

        if btn == "RIGHT" and now - last_btn > DEBOUNCE and serial_ports:
            last_btn = now
            active_idx = (active_idx + 1) % len(serial_ports)
            scroll = 0

        if serial_ports:
            sp = serial_ports[active_idx]

            if not sp.connected:
                if btn == "OK" and now - last_btn > DEBOUNCE:
                    last_btn = now
                    sp.connect()

                if btn == "UP" and now - last_btn > DEBOUNCE:
                    last_btn = now
                    idx = BAUDS.index(sp.baud) if sp.baud in BAUDS else 0
                    sp.baud = BAUDS[(idx + 1) % len(BAUDS)]

                if btn == "DOWN" and now - last_btn > DEBOUNCE:
                    last_btn = now
                    idx = BAUDS.index(sp.baud) if sp.baud in BAUDS else 0
                    sp.baud = BAUDS[(idx - 1) % len(BAUDS)]
            else:
                if btn == "UP" and now - last_btn > 0.08:
                    last_btn = now
                    scroll = min(scroll + 1, max(0, len(sp.lines) - MAX_LINES))

                if btn == "DOWN" and now - last_btn > 0.08:
                    last_btn = now
                    scroll = max(0, scroll - 1)

                if btn == "OK" and now - last_btn > DEBOUNCE:
                    last_btn = now
                    if tx_buf:
                        sp.send_line(tx_buf)
                        tx_buf = ""
                        scroll = 0

            if btn == "KEY1" and now - last_btn > DEBOUNCE:
                last_btn = now
                _draw_status("Auto-detecting baud...", C_YELLOW)
                baud, score = sp.auto_baud()
                _draw_status(f"Detected: {baud} ({int(score*100)}%)", C_GREEN)
                time.sleep(1)
                if not sp.connected:
                    sp.connect()

            if btn == "KEY2" and now - last_btn > DEBOUNCE and sp.connected:
                last_btn = now
                sp.send("\x03")

        if not serial_ports and btn == "KEY1" and now - last_btn > DEBOUNCE:
            last_btn = now
            port_paths = _scan_ports()
            serial_ports = [SerialPort(p) for p in port_paths]
            active_idx = 0

        if kbd and serial_ports and serial_ports[active_idx].connected:
            try:
                while True:
                    ev = kbd.read_one()
                    if ev is None:
                        break
                    if ev.type != ecodes.EV_KEY:
                        continue
                    if ev.value == 1:
                        code = ev.code
                        if code in (42, 54):
                            shift_held = True
                            continue
                        if code == 28:
                            serial_ports[active_idx].send_line(tx_buf)
                            tx_buf = ""
                            scroll = 0
                        elif code == 14:
                            tx_buf = tx_buf[:-1]
                        elif code == 1:
                            serial_ports[active_idx].send("\x03")
                        else:
                            if shift_held:
                                ch = _EVDEV_SHIFT.get(code, "")
                                if not ch:
                                    ch = _EVDEV_CHARS.get(code, "").upper()
                            else:
                                ch = _EVDEV_CHARS.get(code, "")
                            if ch:
                                tx_buf += ch
                    elif ev.value == 0:
                        if ev.code in (42, 54):
                            shift_held = False
            except Exception:
                pass

        state = "connected" if serial_ports and serial_ports[active_idx].connected else "setup"
        _draw_screen(serial_ports, active_idx, tx_buf, scroll, state)
        time.sleep(0.06)

    for sp in serial_ports:
        sp.disconnect()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


def _draw_status(msg, color):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)
    if IS_WIDE:
        d.text((W // 2, H // 2), msg, font=font, fill=color,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (10, H // 2 - 6), msg, font=font, fill=color)
    else:
        d.text((64, 60), msg[:18], font=font_sm, fill=color)
    LCD.LCD_ShowImage(img, 0, 0)


if __name__ == "__main__":
    raise SystemExit(main())
