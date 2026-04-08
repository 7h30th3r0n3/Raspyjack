#!/usr/bin/env python3
"""
RaspyJack Payload -- GPS Tracker
==================================
Author: 7h30th3r0n3

GPS tracking and logging via serial GPS module.  Parses NMEA sentences
($GPGGA and $GPRMC) for position, speed, altitude, and satellite info.
Logs to CSV and can export GPX.

Setup / Prerequisites
---------------------
- Serial GPS module (e.g., NEO-6M) connected to /dev/ttyUSB0 or
  /dev/serial0 at 9600 baud.
- pyserial installed (pip install pyserial).

Controls
--------
  OK         -- Start / stop logging
  UP / DOWN  -- Scroll log entries
  KEY1       -- Toggle display mode (coordinates / map grid)
  KEY2       -- Export GPX file
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/GPS/
"""

import os
import sys
import time
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

try:
    import serial
    SERIAL_OK = True
except ImportError:
    serial = None
    SERIAL_OK = False

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

SERIAL_PORTS = ["/dev/ttyUSB0", "/dev/serial0", "/dev/ttyAMA0"]
BAUD_RATE = 9600
LOOT_DIR = "/root/Raspyjack/loot/GPS"
DEBOUNCE = 0.22

lock = threading.Lock()
_running = True

class GPSFix:
    """Immutable-style GPS fix snapshot."""
    __slots__ = (
        "latitude", "longitude", "altitude", "speed_knots",
        "satellites", "fix_quality", "utc_time", "valid",
    )

    def __init__(self):
        self.latitude = 0.0
        self.longitude = 0.0
        self.altitude = 0.0
        self.speed_knots = 0.0
        self.satellites = 0
        self.fix_quality = 0
        self.utc_time = ""
        self.valid = False

current_fix = GPSFix()
log_entries = []      # list of (timestamp, lat, lon, alt, speed)
logging_active = False
status_msg = "Searching..."
serial_port = None

def _nmea_checksum_ok(sentence):
    """Validate NMEA checksum."""
    if "*" not in sentence:
        return False
    body, chk = sentence.rsplit("*", 1)
    body = body.lstrip("$")
    try:
        expected = int(chk[:2], 16)
    except ValueError:
        return False
    calc = 0
    for ch in body:
        calc ^= ord(ch)
    return calc == expected

def _parse_coord(raw, direction):
    """Convert NMEA coordinate (DDMM.MMMM) to decimal degrees."""
    if not raw or not direction:
        return 0.0
    try:
        dot = raw.index(".")
        degrees = int(raw[:dot - 2])
        minutes = float(raw[dot - 2:])
        dec = degrees + minutes / 60.0
        if direction in ("S", "W"):
            dec = -dec
        return round(dec, 6)
    except (ValueError, IndexError):
        return 0.0

def _parse_gpgga(parts):
    """Parse $GPGGA sentence fields."""
    fix = GPSFix()
    try:
        fix.utc_time = parts[1][:6] if len(parts) > 1 else ""
        fix.latitude = _parse_coord(parts[2], parts[3]) if len(parts) > 3 else 0.0
        fix.longitude = _parse_coord(parts[4], parts[5]) if len(parts) > 5 else 0.0
        fix.fix_quality = int(parts[6]) if len(parts) > 6 and parts[6] else 0
        fix.satellites = int(parts[7]) if len(parts) > 7 and parts[7] else 0
        fix.altitude = float(parts[9]) if len(parts) > 9 and parts[9] else 0.0
        fix.valid = fix.fix_quality > 0
    except (ValueError, IndexError):
        pass
    return fix

def _parse_gprmc(parts, existing_fix):
    """Parse $GPRMC sentence and merge speed into existing fix."""
    try:
        speed = float(parts[7]) if len(parts) > 7 and parts[7] else 0.0
        new_fix = GPSFix()
        for attr in ("latitude", "longitude", "altitude", "satellites",
                      "fix_quality", "utc_time", "valid"):
            setattr(new_fix, attr, getattr(existing_fix, attr))
        new_fix.speed_knots = speed
        return new_fix
    except (ValueError, IndexError):
        return existing_fix

def _find_serial():
    """Find a working serial GPS port."""
    for port in SERIAL_PORTS:
        if os.path.exists(port):
            try:
                s = serial.Serial(port, BAUD_RATE, timeout=2)
                line = s.readline().decode("ascii", errors="ignore")
                if "$" in line:
                    return s
                s.close()
            except (serial.SerialException, OSError):
                continue
    return None

def _reader_thread():
    """Read NMEA sentences and update GPS fix."""
    global current_fix, status_msg, serial_port, log_entries, logging_active

    ser = _find_serial()
    if ser is None:
        with lock:
            status_msg = "No GPS found"
        return

    with lock:
        serial_port = ser
        status_msg = "Connected"

    try:
        while _running:
            try:
                raw = ser.readline().decode("ascii", errors="ignore").strip()
            except (serial.SerialException, OSError):
                with lock:
                    status_msg = "Serial error"
                break

            if not raw.startswith("$"):
                continue
            if not _nmea_checksum_ok(raw):
                continue

            parts = raw.split(",")
            sentence_type = parts[0]

            with lock:
                if sentence_type in ("$GPGGA", "$GNGGA"):
                    new_fix = _parse_gpgga(parts)
                    new_fix.speed_knots = current_fix.speed_knots
                    current_fix = new_fix
                    if new_fix.valid:
                        status_msg = f"Fix: {new_fix.satellites} sats"
                    else:
                        status_msg = f"No fix ({new_fix.satellites} sats)"

                elif sentence_type in ("$GPRMC", "$GNRMC"):
                    current_fix = _parse_gprmc(parts, current_fix)

                # Log if active and valid
                if logging_active and current_fix.valid:
                    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                    entry = (
                        ts,
                        current_fix.latitude,
                        current_fix.longitude,
                        current_fix.altitude,
                        current_fix.speed_knots,
                    )
                    log_entries = log_entries + [entry]  # immutable append

    finally:
        try:
            ser.close()
        except Exception:
            pass

def _export_csv(entries):
    """Write log entries to CSV."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"gps_log_{ts}.csv"
    fpath = os.path.join(LOOT_DIR, fname)
    try:
        with open(fpath, "w") as fh:
            fh.write("timestamp,latitude,longitude,altitude,speed_knots\n")
            for e in entries:
                fh.write(f"{e[0]},{e[1]},{e[2]},{e[3]},{e[4]}\n")
        return f"CSV: {fname[:16]}"
    except OSError as exc:
        return f"Err: {str(exc)[:16]}"

def _export_gpx(entries):
    """Write log entries as GPX file."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"gps_track_{ts}.gpx"
    fpath = os.path.join(LOOT_DIR, fname)
    try:
        lines = ['<?xml version="1.0" encoding="UTF-8"?>',
                 '<gpx version="1.1" creator="RaspyJack">',
                 '  <trk><name>RaspyJack Track</name><trkseg>']
        for e in entries:
            lines.append(f'    <trkpt lat="{e[1]}" lon="{e[2]}"><ele>{e[3]}</ele><time>{e[0]}</time></trkpt>')
        lines += ['  </trkseg></trk>', '</gpx>']
        with open(fpath, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        return f"GPX: {fname[:16]}"
    except OSError as exc:
        return f"Err: {str(exc)[:16]}"

def _speed_kmh(knots):
    return knots * 1.852

def _draw_coords(lcd, fix, logging, entries, scr, status):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#111")
    rec_color = "#ff2222" if logging else "#444"
    d.ellipse((118, 3, 122, 7), fill=rec_color)
    d.text((2, 1), "GPS TRACKER", font=font, fill="#00ccff")

    y = 16
    d.text((2, y), status[:22], font=font, fill="#ffaa00"); y += 13

    if fix.valid:
        d.text((2, y), f"Lat: {fix.latitude:11.6f}", font=font, fill="#00ff00"); y += 12
        d.text((2, y), f"Lon: {fix.longitude:11.6f}", font=font, fill="#00ff00"); y += 12
        d.text((2, y), f"Alt: {fix.altitude:.1f}m", font=font, fill="#ccc"); y += 12
        d.text((2, y), f"Spd: {_speed_kmh(fix.speed_knots):.1f}km/h", font=font, fill="#ccc"); y += 12
        d.text((2, y), f"Sat: {fix.satellites}  Q: {fix.fix_quality}", font=font, fill="#888"); y += 14
    else:
        d.text((4, 40), "Waiting for fix...", font=font, fill="#666")
        d.text((4, 55), f"Sats: {fix.satellites}", font=font, fill="#888")
        y = 75

    d.text((2, y), f"Log: {len(entries)} pts", font=font, fill="#888")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:log K1:mode K2:gpx", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)

def _draw_grid(lcd, fix, entries):
    """Simple map grid showing recent positions."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "GPS MAP GRID", font=font, fill="#00ccff")
    cx, cy, gs = 64, 68, 50
    for i in range(-gs, gs + 1, 25):
        d.line((cx + i, cy - gs, cx + i, cy + gs), fill="#222")
        d.line((cx - gs, cy + i, cx + gs, cy + i), fill="#222")
    if entries and fix.valid:
        scale = 50000
        for e in entries[-30:]:
            dx = int((e[2] - fix.longitude) * scale)
            dy = -int((e[1] - fix.latitude) * scale)
            d.point((cx + max(-gs, min(gs, dx)), cy + max(-gs, min(gs, dy))), fill="#00ff00")
        d.rectangle((cx - 2, cy - 2, cx + 2, cy + 2), fill="#ff2222")
    else:
        d.text((20, 60), "No data", font=font, fill="#666")
    d.text((2, 110), f"Pts: {len(entries)}", font=font, fill="#888")
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:log K1:mode K2:gpx", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)

def _draw_log(lcd, entries, scr):
    """Show scrollable log entries."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), f"LOG ({len(entries)} pts)", font=font, fill="#00ccff")

    y = 16
    visible = 7
    if not entries:
        d.text((4, 50), "No entries yet", font=font, fill="#666")
    else:
        end = min(len(entries), scr + visible)
        for i in range(scr, end):
            e = entries[i]
            ts = e[0][-9:-1]  # HH:MM:SS
            d.text((2, y), f"{ts} {e[1]:.4f},{e[2]:.4f}", font=font, fill="#ccc")
            y += 13

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "^v:scroll K1:mode", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)

DISPLAY_MODES = ["coords", "grid", "log"]

def main():
    global _running, logging_active, log_entries, status_msg

    if not SERIAL_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "pyserial not found!", font=font, fill="#ff0000")
        d.text((4, 65), "pip install pyserial", font=font, fill="#888")
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        LCD.LCD_Clear()
        GPIO.cleanup()
        return 1

    reader = threading.Thread(target=_reader_thread, daemon=True)
    reader.start()

    mode_idx = 0
    scroll = 0
    last_press = 0.0

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if btn == "KEY3":
                break
            elif btn == "OK":
                with lock:
                    logging_active = not logging_active
                    if logging_active:
                        status_msg = "Logging started"
                    else:
                        status_msg = "Logging stopped"
                        # Auto-save CSV
                        if log_entries:
                            result = _export_csv(log_entries)
                            status_msg = result
            elif btn == "KEY1":
                mode_idx = (mode_idx + 1) % len(DISPLAY_MODES)
                scroll = 0
            elif btn == "KEY2":
                with lock:
                    entries_snap = list(log_entries)
                if entries_snap:
                    result = _export_gpx(entries_snap)
                    with lock:
                        status_msg = result
                else:
                    with lock:
                        status_msg = "No data to export"
            elif btn == "UP":
                scroll = max(0, scroll - 1)
            elif btn == "DOWN":
                with lock:
                    max_s = max(0, len(log_entries) - 7)
                scroll = min(scroll + 1, max_s)

            with lock:
                fix_snap = current_fix
                entries_snap = list(log_entries)
                st = status_msg
                is_logging = logging_active

            mode = DISPLAY_MODES[mode_idx]
            if mode == "coords":
                _draw_coords(LCD, fix_snap, is_logging, entries_snap, scroll, st)
            elif mode == "grid":
                _draw_grid(LCD, fix_snap, entries_snap)
            elif mode == "log":
                _draw_log(LCD, entries_snap, scroll)

            time.sleep(0.08)

    finally:
        _running = False
        # Save any remaining log
        if log_entries:
            _export_csv(log_entries)
        if serial_port is not None:
            try:
                serial_port.close()
            except Exception:
                pass
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
