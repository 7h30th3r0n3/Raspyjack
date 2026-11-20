"""Read fixes from the Cardputer Zero cap's NMEA UART when gpsd is unavailable."""

from datetime import datetime, timezone
import math
import os
from pathlib import Path
import re
import time


UART = Path("/dev/ttyS0")
SHARED_GPS = ".shared-gpsd"
UART_LOCK = ".cap-uart.lock"


def _coordinate(value, hemisphere, degrees):
    if hemisphere not in (("N", "S") if degrees == 2 else ("E", "W")):
        raise ValueError("Invalid coordinate hemisphere")
    if not re.fullmatch(rf"[0-9]{{{degrees + 2}}}(?:\.[0-9]+)?", value):
        raise ValueError("Invalid coordinate")
    minutes = float(value[degrees:])
    coordinate = int(value[:degrees]) + minutes / 60
    if minutes >= 60 or coordinate > (90 if degrees == 2 else 180):
        raise ValueError("Coordinate outside bounds")
    return -coordinate if hemisphere in ("S", "W") else coordinate


def nmea_fix(line):
    """Return a gpsd-style TPV only for complete checksum-valid GGA/RMC sentences."""
    if len(line) > 128 or not line.startswith(b"$"):
        return None
    body, sep, expected = line[1:].rstrip(b"\r\n").partition(b"*")
    if not sep or not re.fullmatch(b"[0-9a-fA-F]{2}", expected):
        return None
    checksum = 0
    for byte in body:
        checksum ^= byte
    if checksum != int(expected, 16):
        return None
    try:
        fields = body.decode("ascii").split(",")
        if not re.fullmatch(r"G[A-Z](GGA|RMC)", fields[0]):
            return None
        result = {"class": "TPV", "mode": 1}
        if fields[0].endswith("RMC"):
            if fields[2] != "A":
                return result
            lat, ns, lon, ew = fields[3:7]
            clock = fields[1].split(".")[0]
            if re.fullmatch(r"[0-9]{6}", fields[9]) and re.fullmatch(r"[0-9]{6}", clock):
                utc = datetime.strptime(fields[9] + clock, "%d%m%y%H%M%S")
                result["time"] = utc.replace(tzinfo=timezone.utc).isoformat()
        else:
            if fields[6] not in {"1", "2", "3", "4", "5"}:
                return result
            lat, ns, lon, ew = fields[2:6]
            if fields[9] and fields[10] == "M":
                altitude = float(fields[9])
                if math.isfinite(altitude):
                    result["altMSL"] = altitude
        result.update(mode=2, lat=_coordinate(lat, ns, 2), lon=_coordinate(lon, ew, 3))
        return result
    except (ValueError, IndexError, UnicodeError):
        return None


def uart_available():
    """Kernel consoles and processes with an open UART retain ownership."""
    try:
        device = UART.stat().st_rdev
        consoles = Path("/proc/consoles").read_text().splitlines()
        if any(row.split()[0] == UART.name for row in consoles if row.strip()):
            return False
        for directory in Path("/proc").glob("[0-9]*/fd"):
            try:
                with os.scandir(directory) as descriptors:
                    for fd in descriptors:
                        try:
                            if fd.stat().st_rdev == device:
                                return False
                        except FileNotFoundError:
                            continue
            except FileNotFoundError:
                continue
        return True
    except OSError:
        return False


def share_gps(directory):
    """Yield an active direct GNSS reader before starting the native wardriver."""
    import fcntl
    directory = Path(directory)
    (directory / SHARED_GPS).touch(mode=0o600, exist_ok=True)
    deadline = time.monotonic() + 3
    with (directory / UART_LOCK).open("a") as lock:
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("Still releasing cap GPS; retry before starting Wardriving")
                time.sleep(0.05)


def read_cap_uart(stopped, update, directory):
    marker = directory / SHARED_GPS
    if stopped.is_set() or marker.exists() or not uart_available():
        return
    try:
        import fcntl
        import serial
        with (directory / UART_LOCK).open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if marker.exists() or stopped.is_set():
                return
            with serial.Serial(str(UART), 115200, timeout=0.5, exclusive=True) as port:
                while not stopped.is_set() and not marker.exists():
                    report = nmea_fix(port.read_until(b"\n", size=129))
                    if report is not None:
                        update(report)
    except (ImportError, OSError):
        # Capture continues with no fix while the GNSS or pyserial is absent.
        return
