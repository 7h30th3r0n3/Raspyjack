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
            ser = None
            try:
                ser = serial.Serial(dev, baud, timeout=1.5)
                time.sleep(0.3)
                data = ser.read(256)
                if _is_nmea(data):
                    _detected_device = dev
                    _detected_baud = baud
                    return dev, baud
            except Exception:
                continue
            finally:
                if ser is not None:
                    try:
                        ser.close()
                    except Exception:
                        pass

    return None, None


def _release_serial_port(dev):
    """Stop any serial-getty holding the UART port so gpsd can use it."""
    if "ttyS" not in dev and "ttyAMA" not in dev:
        return
    port_name = os.path.basename(dev)
    svc = f"serial-getty@{port_name}.service"
    subprocess.run(["systemctl", "stop", svc], capture_output=True, timeout=5)
    subprocess.run(["systemctl", "disable", svc], capture_output=True, timeout=5)
    subprocess.run(["systemctl", "mask", svc], capture_output=True, timeout=5)
    time.sleep(0.3)


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

        # Release serial-getty if it holds the UART port
        _release_serial_port(dev)

        # Set baud rate for UART devices
        if "ttyS" in dev or "ttyAMA" in dev:
            try:
                subprocess.run(["stty", "-F", dev, str(baud), "raw", "-echo"],
                               capture_output=True, timeout=3)
            except Exception:
                pass

        # Start gpsd (-n: don't wait for client, no -s: let gpsd probe)
        cmd = ["gpsd", "-n", dev]
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


def get_gps_data():
    """Return the current GPS fix as a dict, or None if unavailable.

    Reads from a running gpsd (start it first with ``start_gps()``) via the
    ``gpsd`` python module (``gpsd-py3``). Returns a dict with keys:
        lat, lon  -- decimal degrees (only present with a 2D/3D fix)
        alt       -- metres (3D fix only, else None)
        speed     -- metres/second
        mode      -- gpsd fix mode (0/1 = no fix, 2 = 2D, 3 = 3D)
        sats      -- satellites used in the fix
    Returns None if the gpsd module is missing, gpsd is not running, or there
    is no positional fix yet. Callers should treat a return of None, or a dict
    whose ``lat``/``lon`` are absent, as "no coordinates available".
    """
    try:
        import gpsd as _gpsd
    except Exception:
        return None
    try:
        _gpsd.connect()
        pkt = _gpsd.get_current()
    except Exception:
        return None
    try:
        mode = getattr(pkt, "mode", 0)
        data = {
            "mode": mode,
            "sats": getattr(pkt, "sats", 0),
            "speed": pkt.speed() if mode >= 2 else 0.0,
        }
        if mode >= 2:
            lat, lon = pkt.position()
            data["lat"] = lat
            data["lon"] = lon
            data["alt"] = pkt.altitude() if mode >= 3 else None
        return data
    except Exception:
        return None
