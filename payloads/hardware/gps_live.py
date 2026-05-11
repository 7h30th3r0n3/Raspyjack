#!/usr/bin/env python3
"""
RaspyJack Payload -- GPS Live
==============================
Real-time GPS data display: position, satellites, altitude, speed,
fix status, and raw NMEA sentences scrolling.

Controls
--------
  KEY3  -- Exit
  UP    -- Scroll NMEA up
  DOWN  -- Scroll NMEA down
"""

import os
import sys
import time
import threading
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
LCD.LCD_Clear()
WIDTH, HEIGHT = LCD.width, LCD.height

font      = scaled_font(9)
font_bold = scaled_font(10)
font_tiny = scaled_font(8)

C_BG    = "#000000"
C_TITLE = "#00ccff"
C_OK    = "#00ff44"
C_WARN  = "#ffaa00"
C_ERR   = "#ff3333"
C_INFO  = "#cccccc"
C_DIM   = "#555555"

NMEA_VISIBLE = 6

_lock = threading.Lock()
_gps  = {}
_nmea = []
_running = True


def _parse_gga(parts):
    if len(parts) < 10:
        return
    lat_raw, lat_ns = parts[2], parts[3]
    lon_raw, lon_ns = parts[4], parts[5]
    fix_q = parts[6]
    sats = parts[7]
    alt = parts[9]
    lat = lon = 0.0
    try:
        lat = float(lat_raw[:2]) + float(lat_raw[2:]) / 60.0
        if lat_ns == "S":
            lat = -lat
        lon = float(lon_raw[:3]) + float(lon_raw[3:]) / 60.0
        if lon_ns == "W":
            lon = -lon
    except (ValueError, IndexError):
        pass
    _gps["lat"] = lat
    _gps["lon"] = lon
    _gps["fix"] = int(fix_q) if fix_q.isdigit() else 0
    _gps["sats"] = sats
    _gps["alt"] = alt


def _parse_rmc(parts):
    if len(parts) < 8:
        return
    status = parts[2]
    speed_kn = parts[7]
    _gps["status"] = "FIX" if status == "A" else "NO FIX"
    try:
        _gps["speed"] = f"{float(speed_kn) * 1.852:.1f}"
    except (ValueError, IndexError):
        _gps["speed"] = "0.0"
    if len(parts) > 9 and parts[9]:
        _gps["date"] = parts[9]
    if parts[1]:
        _gps["time"] = parts[1][:2] + ":" + parts[1][2:4] + ":" + parts[1][4:6]


def _parse_gsa(parts):
    if len(parts) < 17:
        return
    _gps["pdop"] = parts[15] if parts[15] else "---"
    _gps["hdop"] = parts[16] if parts[16] else "---"


def _parse_vtg(parts):
    if len(parts) < 8:
        return
    if parts[5]:
        try:
            _gps["speed"] = f"{float(parts[7]):.1f}" if parts[7] else _gps.get("speed", "0.0")
        except (ValueError, IndexError):
            pass
    if parts[1]:
        _gps["heading"] = parts[1]


def _render():
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#081828")
    fix_status = _gps.get("status", "---")
    fix_col = C_OK if fix_status == "FIX" else C_ERR
    d.text((2, 2), "GPS LIVE", font=font_bold, fill=C_TITLE)
    d.text((68, 2), fix_status, font=font_bold, fill=fix_col)

    y = 16
    lat = _gps.get("lat", 0.0)
    lon = _gps.get("lon", 0.0)
    sats = _gps.get("sats", "0")
    alt = _gps.get("alt", "---")
    spd = _gps.get("speed", "0.0")
    fix_q = _gps.get("fix", 0)
    utc = _gps.get("time", "--:--:--")
    hdg = _gps.get("heading", "---")

    # Satellites + quality
    sats_val = int(sats) if sats and sats.isdigit() else 0
    sats_col = C_OK if sats_val >= 4 else C_WARN if sats_val > 0 else C_ERR
    d.text((2, y), f"Sat:{sats}", font=font, fill=sats_col)
    d.text((50, y), f"Q:{fix_q}", font=font, fill=C_INFO)
    d.text((80, y), utc, font=font, fill=C_DIM)
    y += 12

    # Position
    d.text((2, y), f"Lat:{lat:+.6f}", font=font, fill="#ffffff")
    y += 12
    d.text((2, y), f"Lon:{lon:+.6f}", font=font, fill="#ffffff")
    y += 12

    # Alt + Speed + Heading
    d.text((2, y), f"Alt:{alt}m", font=font, fill=C_INFO)
    d.text((68, y), f"{spd}km/h", font=font, fill=C_INFO)
    y += 13

    # Separator
    d.rectangle((2, y, 125, y), fill=C_DIM)
    y += 2

    # Raw NMEA
    with _lock:
        lines = list(_nmea[-NMEA_VISIBLE:])
    for nmea_line in lines:
        tag = nmea_line.split(",")[0] if "," in nmea_line else nmea_line
        short = nmea_line[:21]
        col = C_OK if "GGA" in tag or "RMC" in tag else C_DIM
        d.text((2, y), short, font=font_tiny, fill=col)
        y += 10
        if y > 116:
            break

    # Footer
    d.rectangle((0, 117, 127, 127), fill="#081828")
    d.text((2, 118), "K3:exit", font=font_tiny, fill=C_DIM)

    LCD.LCD_ShowImage(img, 0, 0)


def _reader():
    global _running
    try:
        import serial as _serial
    except ImportError:
        _gps["status"] = "ERR:serial"
        return

    try:
        from payloads._gps_helper import detect_gps, start_gps, _release_serial_port
    except ImportError:
        _gps["status"] = "ERR:helper"
        return

    # Stop gpsd so we can read the port directly
    subprocess.run(["systemctl", "stop", "gpsd.service", "gpsd.socket"],
                   capture_output=True, timeout=5)
    subprocess.run(["killall", "-9", "gpsd"], capture_output=True, timeout=3)
    time.sleep(0.3)

    dev, baud = detect_gps()
    if not dev:
        _gps["status"] = "NO GPS"
        return

    _release_serial_port(dev)
    time.sleep(0.3)

    _gps["device"] = os.path.basename(dev)
    _gps["baud"] = str(baud)

    try:
        ser = _serial.Serial(dev, baud, timeout=1.5)
    except Exception as e:
        _gps["status"] = f"ERR:{e}"
        return

    while _running:
        try:
            raw = ser.readline().decode("ascii", errors="ignore").strip()
        except Exception:
            break
        if not raw.startswith("$"):
            continue

        with _lock:
            _nmea.append(raw)
            if len(_nmea) > 100:
                del _nmea[:50]

        parts = raw.split(",")
        tag = parts[0]
        if "GGA" in tag:
            _parse_gga(parts)
        elif "RMC" in tag:
            _parse_rmc(parts)
        elif "GSA" in tag:
            _parse_gsa(parts)
        elif "VTG" in tag:
            _parse_vtg(parts)

        _render()

    ser.close()

    # Restart gpsd for other payloads
    try:
        start_gps()
    except Exception:
        subprocess.run(["systemctl", "start", "gpsd"], capture_output=True)


def main():
    global _running

    _gps["status"] = "Scanning..."
    _render()

    reader_thread = threading.Thread(target=_reader, daemon=True)
    reader_thread.start()

    while True:
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            break
        time.sleep(0.05)

    _running = False
    reader_thread.join(timeout=4)
    LCD.LCD_Clear()
    GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
