#!/usr/bin/env python3
"""
RaspyJack Payload -- GPS Check
================================
Author: 7h30th3r0n3

Diagnostic tool for GPS modules. Scans all serial ports
(GPIO UART, USB) at multiple baud rates looking for NMEA data.
Shows raw sentences even without fix.

Controls:
  OK          Start/Stop scan on current port
  UP/DOWN     Change baud rate
  LEFT/RIGHT  Change port
  KEY1        Auto-detect (scan all ports/bauds)
  KEY2        Toggle gpsd mode vs raw serial
  KEY3        Exit
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
        font_sm = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 9)
        font_lg = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 15)
    except Exception:
        font = scaled_font(8)
        font_sm = scaled_font(6)
        font_lg = scaled_font(11)
else:
    font = scaled_font(8)
    font_sm = scaled_font(6)
    font_lg = font

BAUDS = [4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600]
DEBOUNCE = 0.18

_running = True
_scanning = False
_ser = None
_lines = []
_lines_lock = threading.Lock()
_nmea_count = 0
_fix_status = "No data"
_sats = 0
_lat = ""
_lon = ""
_alt = ""
_speed = ""
_use_gpsd = False

C_BG = (0, 5, 10)
C_HEAD = (0, 30, 30)
C_CYAN = (0, 220, 220)
C_GREEN = (0, 255, 80)
C_WHITE = (255, 255, 255)
C_DIM = (70, 70, 70)
C_DARK = (10, 15, 20)
C_RED = (255, 50, 50)
C_YELLOW = (255, 200, 0)
C_ORANGE = (255, 140, 0)


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


def _list_ports():
    ports = []
    if os.path.exists("/dev/ttyS0"):
        ports.append("/dev/ttyS0")
    if os.path.exists("/dev/ttyAMA0"):
        ports.append("/dev/ttyAMA0")
    ports.extend(sorted(glob.glob("/dev/ttyUSB*")))
    ports.extend(sorted(glob.glob("/dev/ttyACM*")))
    return ports


def _parse_nmea(sentence):
    """Parse NMEA sentence and update global state."""
    global _fix_status, _sats, _lat, _lon, _alt, _speed, _nmea_count
    _nmea_count += 1

    parts = sentence.split(",")
    msg_type = parts[0] if parts else ""

    if "GGA" in msg_type and len(parts) >= 10:
        fix_q = parts[6] if len(parts) > 6 else "0"
        _sats = int(parts[7]) if parts[7] else 0
        if fix_q == "0":
            _fix_status = "No Fix"
        elif fix_q == "1":
            _fix_status = "GPS Fix"
        elif fix_q == "2":
            _fix_status = "DGPS Fix"
        else:
            _fix_status = f"Fix({fix_q})"
        if parts[2] and parts[4]:
            _lat = f"{parts[2]} {parts[3]}"
            _lon = f"{parts[4]} {parts[5]}"
        _alt = f"{parts[9]}m" if parts[9] else ""

    elif "RMC" in msg_type and len(parts) >= 8:
        status = parts[2] if len(parts) > 2 else "V"
        if status == "A":
            _fix_status = "Active"
            if parts[3] and parts[5]:
                _lat = f"{parts[3]} {parts[4]}"
                _lon = f"{parts[5]} {parts[6]}"
        elif status == "V":
            if _fix_status == "No data":
                _fix_status = "No Fix (RMC)"
        if parts[7]:
            knots = float(parts[7])
            _speed = f"{knots * 1.852:.1f} km/h"

    elif "GSV" in msg_type and len(parts) >= 4:
        try:
            _sats = int(parts[3]) if parts[3] else _sats
        except Exception:
            pass


def _rx_thread_serial(port, baud):
    """Read raw NMEA from serial port."""
    global _scanning, _ser, _fix_status
    try:
        subprocess.run(["systemctl", "stop", "gpsd"], capture_output=True, timeout=5)
        time.sleep(0.3)
        _ser = serial.Serial(port, baud, timeout=1)
        _ser.reset_input_buffer()
        while _scanning and _running:
            try:
                raw = _ser.readline()
                if raw:
                    line = raw.decode(errors="replace").strip()
                    if line:
                        with _lines_lock:
                            _lines.append(line)
                            if len(_lines) > 100:
                                _lines[:] = _lines[-100:]
                        if line.startswith("$"):
                            _parse_nmea(line)
            except Exception:
                time.sleep(0.1)
    except Exception as e:
        _fix_status = f"Error: {str(e)[:20]}"
    finally:
        if _ser:
            _ser.close()
            _ser = None
        subprocess.run(["systemctl", "start", "gpsd"], capture_output=True, timeout=5)
        _scanning = False


def _rx_thread_gpsd():
    """Read from gpsd via gpspipe."""
    global _scanning, _fix_status
    try:
        proc = subprocess.Popen(
            ["gpspipe", "-r"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True)
        while _scanning and _running:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            if line.startswith("{"):
                with _lines_lock:
                    _lines.append(f"[JSON] {line[:60]}")
                    if len(_lines) > 100:
                        _lines[:] = _lines[-100:]
            elif line.startswith("$"):
                with _lines_lock:
                    _lines.append(line)
                    if len(_lines) > 100:
                        _lines[:] = _lines[-100:]
                _parse_nmea(line)
            elif line:
                with _lines_lock:
                    _lines.append(line)
                    if len(_lines) > 100:
                        _lines[:] = _lines[-100:]
        proc.kill()
    except Exception as e:
        _fix_status = f"gpsd error: {str(e)[:15]}"
    finally:
        _scanning = False


def _auto_detect():
    """Scan all ports at common GPS bauds, return (port, baud) or None."""
    global _fix_status
    ports = _list_ports()
    gps_bauds = [9600, 115200, 38400, 4800, 57600, 921600]

    for port in ports:
        for baud in gps_bauds:
            _fix_status = f"Trying {os.path.basename(port)}@{baud}"
            try:
                subprocess.run(["systemctl", "stop", "gpsd"],
                               capture_output=True, timeout=3)
                time.sleep(0.2)
                s = serial.Serial(port, baud, timeout=1.5)
                s.reset_input_buffer()
                time.sleep(0.5)
                data = s.read(512)
                s.close()
                subprocess.run(["systemctl", "start", "gpsd"],
                               capture_output=True, timeout=3)
                decoded = data.decode(errors="replace")
                if "$GP" in decoded or "$GN" in decoded or "$GL" in decoded:
                    return port, baud
            except Exception:
                pass
    subprocess.run(["systemctl", "start", "gpsd"],
                   capture_output=True, timeout=3)
    return None


def _draw_screen(port, baud):
    img = Image.new("RGB", (W, H), C_BG)
    d = ImageDraw.Draw(img) if IS_WIDE else ScaledDraw(img)

    if IS_WIDE:
        d.rectangle([0, 0, W, 20], fill=C_HEAD)
        title = "GPS CHECK"
        d.text((W // 2, 10), title, font=font_lg, fill=C_CYAN,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (W // 2 - 40, 1), title, font=font_lg, fill=C_CYAN)

        y = 23
        mode = "gpsd" if _use_gpsd else "serial"
        status_color = C_GREEN if _scanning else C_RED
        scan_str = "LISTENING" if _scanning else "STOPPED"
        d.text((4, y), f"{os.path.basename(port)} | {baud} | {mode} | {scan_str}",
               font=font_sm, fill=status_color)
        y += 14

        fix_color = C_GREEN if "Fix" in _fix_status and "No" not in _fix_status else C_YELLOW
        if "No data" in _fix_status or "Error" in _fix_status:
            fix_color = C_RED
        d.text((4, y), f"Status: {_fix_status}", font=font, fill=fix_color)
        y += 14
        d.text((4, y), f"Sats: {_sats}  NMEA: {_nmea_count}", font=font_sm, fill=C_WHITE)
        y += 12

        if _lat:
            d.text((4, y), f"Lat: {_lat}", font=font_sm, fill=C_WHITE)
            y += 12
            d.text((4, y), f"Lon: {_lon}", font=font_sm, fill=C_WHITE)
            y += 12
        if _alt:
            d.text((4, y), f"Alt: {_alt}", font=font_sm, fill=C_WHITE)
            y += 12
        if _speed:
            d.text((4, y), f"Speed: {_speed}", font=font_sm, fill=C_WHITE)
            y += 12

        raw_y = max(y + 4, 100)
        d.rectangle([0, raw_y - 2, W, raw_y], fill=C_DIM)
        with _lines_lock:
            visible = _lines[-4:]
        for i, ln in enumerate(visible):
            txt = ln[:48]
            color = C_GREEN if ln.startswith("$") else C_DIM
            d.text((3, raw_y + 2 + i * 12), txt, font=font_sm, fill=color)

        d.rectangle([0, H - 14, W, H], fill=C_DARK)
        bar = "OK:Start/Stop K1:AutoDetect K2:gpsd/raw UP/DN:Baud L/R:Port"
        d.text((W // 2, H - 7), bar, font=font_sm, fill=C_DIM,
               anchor="mm") if hasattr(d, 'textbbox') else d.text(
                   (2, H - 12), bar[:50], font=font_sm, fill=C_DIM)
    else:
        d.rectangle([0, 0, 128, 11], fill=C_HEAD)
        d.text((64, 0), "GPS CHECK", font=font_sm, fill=C_CYAN)
        y = 13
        fix_color = C_GREEN if "Fix" in _fix_status and "No" not in _fix_status else C_RED
        d.text((4, y), f"{_fix_status} S:{_sats}", font=font_sm, fill=fix_color)
        y += 12
        if _lat:
            d.text((4, y), _lat[:18], font=font_sm, fill=C_WHITE)
            y += 11
            d.text((4, y), _lon[:18], font=font_sm, fill=C_WHITE)
            y += 11
        with _lines_lock:
            visible = _lines[-3:]
        for ln in visible:
            d.text((2, y), ln[:18], font=font_sm, fill=C_GREEN)
            y += 11
        d.text((64, 118), f"{os.path.basename(port)} {baud}", font=font_sm, fill=C_DIM)

    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global _running, _scanning, _use_gpsd, _lines, _nmea_count
    global _fix_status, _sats, _lat, _lon, _alt, _speed

    ports = _list_ports()
    if not ports:
        ports = ["/dev/ttyS0"]
    port_idx = 0
    baud_idx = BAUDS.index(9600)
    last_btn = 0
    rx_thread = None

    _draw_screen(ports[port_idx], BAUDS[baud_idx])

    while _running:
        btn = _get_btn()
        now = time.time()

        if btn == "KEY3":
            _scanning = False
            if rx_thread:
                rx_thread.join(timeout=3)
            break

        if btn == "OK" and now - last_btn > DEBOUNCE:
            last_btn = now
            if not _scanning:
                _scanning = True
                _lines = []
                _nmea_count = 0
                _fix_status = "Listening..."
                _sats = 0
                _lat = ""
                _lon = ""
                _alt = ""
                _speed = ""
                if _use_gpsd:
                    rx_thread = threading.Thread(target=_rx_thread_gpsd, daemon=True)
                else:
                    rx_thread = threading.Thread(
                        target=_rx_thread_serial,
                        args=(ports[port_idx], BAUDS[baud_idx]),
                        daemon=True)
                rx_thread.start()
            else:
                _scanning = False
                if rx_thread:
                    rx_thread.join(timeout=3)
                    rx_thread = None

        if btn == "KEY1" and now - last_btn > DEBOUNCE:
            last_btn = now
            if _scanning:
                _scanning = False
                if rx_thread:
                    rx_thread.join(timeout=3)
            _fix_status = "Auto-detecting..."
            _draw_screen(ports[port_idx], BAUDS[baud_idx])
            result = _auto_detect()
            if result:
                port, baud = result
                if port in ports:
                    port_idx = ports.index(port)
                if baud in BAUDS:
                    baud_idx = BAUDS.index(baud)
                _fix_status = f"Found! {os.path.basename(port)}@{baud}"
            else:
                _fix_status = "No GPS found"
            _draw_screen(ports[port_idx], BAUDS[baud_idx])
            time.sleep(1)

        if btn == "KEY2" and now - last_btn > DEBOUNCE:
            last_btn = now
            if _scanning:
                _scanning = False
                if rx_thread:
                    rx_thread.join(timeout=3)
                    rx_thread = None
            _use_gpsd = not _use_gpsd

        if not _scanning:
            if btn == "UP" and now - last_btn > DEBOUNCE:
                last_btn = now
                baud_idx = (baud_idx + 1) % len(BAUDS)

            if btn == "DOWN" and now - last_btn > DEBOUNCE:
                last_btn = now
                baud_idx = (baud_idx - 1) % len(BAUDS)

            if btn == "LEFT" and now - last_btn > DEBOUNCE:
                last_btn = now
                ports = _list_ports()
                if ports:
                    port_idx = (port_idx - 1) % len(ports)

            if btn == "RIGHT" and now - last_btn > DEBOUNCE:
                last_btn = now
                ports = _list_ports()
                if ports:
                    port_idx = (port_idx + 1) % len(ports)

        _draw_screen(ports[port_idx], BAUDS[baud_idx])
        time.sleep(0.12)

    _scanning = False
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
