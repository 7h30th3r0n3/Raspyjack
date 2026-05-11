"""
GPS helper – Auto-detect and start gpsd for any GPS device.

Supports:
  - USB GPS (u-blox, SiRF, etc.) on /dev/ttyACM*, /dev/ttyUSB*
  - HAT/GPIO GPS on /dev/ttyS0, /dev/ttyAMA0 (CardputerZero, Pi HATs)
  - Auto baud rate detection (9600, 38400, 57600, 115200)

Usage:
    from payloads._gps_helper import start_gps, get_gps_data
    start_gps()  # auto-detect and start gpsd
"""

import os
import subprocess
import time
import serial


# Devices to scan, in priority order
_GPS_DEVICES = [
    # USB GPS (u-blox, Prolific, FTDI, CP210x)
    "/dev/ttyACM0", "/dev/ttyACM1", "/dev/ttyACM2",
    "/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyUSB2",
    # GPIO/UART GPS (HATs, CardputerZero LoRa+GPS HAT)
    "/dev/ttyS0", "/dev/ttyAMA0", "/dev/ttyAMA1",
]

_BAUD_RATES = [9600, 115200, 38400, 57600, 4800]

_detected_device = None
_detected_baud = None


def _is_nmea(data):
    """Check if data looks like NMEA sentences."""
    return b"$G" in data or b"$GN" in data or b"$GP" in data


def detect_gps():
    """Auto-detect GPS device and baud rate. Returns (device_path, baud) or (None, None)."""
    global _detected_device, _detected_baud

    # First check /dev/serial/by-id for known GPS devices
    try:
        by_id = "/dev/serial/by-id"
        if os.path.isdir(by_id):
            for link in os.listdir(by_id):
                if any(kw in link.lower() for kw in ("gps", "gnss", "u-blox", "sirf", "nmea")):
                    path = os.path.realpath(os.path.join(by_id, link))
                    if os.path.exists(path):
                        # USB GPS typically 9600 baud
                        _detected_device = path
                        _detected_baud = 9600
                        return path, 9600
    except Exception:
        pass

    # Scan all candidate devices
    for dev in _GPS_DEVICES:
        if not os.path.exists(dev):
            continue
        for baud in _BAUD_RATES:
            try:
                ser = serial.Serial(dev, baud, timeout=1.5)
                time.sleep(0.3)
                data = ser.read(256)
                ser.close()
                if _is_nmea(data):
                    _detected_device = dev
                    _detected_baud = baud
                    return dev, baud
            except Exception:
                continue

    return None, None


def start_gps():
    """Auto-detect GPS and start gpsd. Returns True if successful."""
    try:
        # Stop any existing gpsd
        subprocess.run(["systemctl", "stop", "gpsd.service", "gpsd.socket"],
                       capture_output=True, timeout=5)
        subprocess.run(["killall", "-9", "gpsd"], capture_output=True, timeout=3)
        time.sleep(0.5)

        dev, baud = detect_gps()
        if not dev:
            return False

        # Set baud rate for UART devices
        if "ttyS" in dev or "ttyAMA" in dev:
            try:
                subprocess.run(["stty", "-F", dev, str(baud)],
                               capture_output=True, timeout=3)
            except Exception:
                pass

        # Start gpsd with correct baud rate
        cmd = ["gpsd", "-n", "-s", str(baud), dev]
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)

        # Verify gpsd is running
        r = subprocess.run(["pgrep", "-x", "gpsd"], capture_output=True)
        return r.returncode == 0

    except Exception:
        return False


def get_detected_info():
    """Return (device, baud) of last detected GPS."""
    return _detected_device, _detected_baud
