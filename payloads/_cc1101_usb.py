"""
USB transport for the CC1101 sub-GHz radio.

Talks to the ESP32-S3 bridge firmware (EXTENSIONS/cc1101_usb/firmware) over
USB-CDC using the COBS-framed protocol in EXTENSIONS/cc1101_usb/PROTOCOL.md.

The returned object is duck-typed to stand in for a ``spidev.SpiDev`` instance
(``xfer2``/``open``/``close``/``max_speed_hz``/``mode``) so the whole register
layer of ``_cc1101_driver.CC1101`` works over USB unchanged. It additionally
exposes the timing-critical device-side ops ``tx_raw`` and ``rx_raw`` plus
``rf_switch`` / ``power`` / ``gdo_read``.

Nothing here imports at module load that is not in the stdlib except pyserial,
which is imported lazily so the HAT path keeps working on boxes without it.
"""

import os
import time
import struct
import threading

PROTO_VER = 2           # must match firmware PROTO_VER (v2: idle_us u32, TX limits)
MAGIC = b"RJC1"
MAX_BODY = 2048
# device status codes (mirror firmware enum)
ST_TXLIMIT = 0x06

# commands
CMD_PING = 0x01
CMD_INFO = 0x02
CMD_SPI_XFER = 0x10
CMD_RF_SWITCH = 0x11
CMD_POWER = 0x12
CMD_GDO_READ = 0x13
CMD_TX_RAW = 0x20
CMD_RX_RAW = 0x21

# Espressif native-USB VID; ESP32-S3 CDC enumerates here by default.
_ESP_VIDS = (0x303A,)


# ── COBS ────────────────────────────────────────────────────────────────────

def cobs_encode(data: bytes) -> bytes:
    """Canonical COBS encoder (Consistent Overhead Byte Stuffing)."""
    out = bytearray()
    code_idx = len(out)
    out.append(0)            # placeholder for the first code byte
    code = 1
    for b in data:
        if b == 0:
            out[code_idx] = code
            code_idx = len(out)
            out.append(0)
            code = 1
        else:
            out.append(b)
            code += 1
            if code == 0xFF:
                out[code_idx] = code
                code_idx = len(out)
                out.append(0)
                code = 1
    out[code_idx] = code
    return bytes(out)


def cobs_decode(data: bytes) -> bytes:
    """Canonical COBS decoder."""
    out = bytearray()
    idx = 0
    n = len(data)
    while idx < n:
        code = data[idx]
        if code == 0:
            raise ValueError("zero code byte in COBS stream")
        idx += 1
        block = data[idx:idx + code - 1]
        if len(block) != code - 1:
            raise ValueError("truncated COBS block")
        out.extend(block)
        idx += code - 1
        if code != 0xFF and idx < n:
            out.append(0)
    return bytes(out)


# ── Transport ─────────────────────────────────────────────────────────────

class CC1101UsbError(Exception):
    pass


class CC1101Usb:
    """Serial client for the ESP32-S3 CC1101 bridge; spidev-compatible."""

    def __init__(self, port, timeout=1.0):
        import serial  # lazy; raises ImportError if pyserial absent
        self._serial = serial
        self._port_name = port
        self._timeout = timeout
        self._lock = threading.RLock()
        # spidev-compatible attributes (no-ops on USB)
        self.max_speed_hz = 0
        self.mode = 0
        self.fw = (0, 0)
        self.cc_version = 0
        self._ser = None
        self._open_serial()

    def _open_serial(self):
        # dsrdtr/dtr/rts off so opening the port does NOT reset the ESP32
        # (native-USB CDC auto-reset) and does not disturb other serial gear.
        ser = self._serial.Serial(baudrate=115200, timeout=self._timeout,
                                  write_timeout=self._timeout)
        ser.port = self._port_name
        try:
            ser.dtr = False
            ser.rts = False
        except Exception:
            pass
        ser.open()
        self._ser = ser
        # let the firmware finish booting, then flush its boot log
        time.sleep(0.3)
        try:
            self._ser.reset_input_buffer()
        except Exception:
            pass

    # -- framing --

    def _txn(self, cmd, payload=b"", read_timeout=None):
        body = bytes([cmd]) + payload
        if len(body) > MAX_BODY:
            raise CC1101UsbError("request body too large")
        frame = cobs_encode(body) + b"\x00"
        rt = read_timeout if read_timeout is not None else self._timeout
        with self._lock:
            try:
                self._ser.reset_input_buffer()
                self._ser.write(frame)
                self._ser.flush()
                raw = self._read_frame(rt)
            except (self._serial.SerialException, OSError):
                # hot-unplug / renumeration: try to reopen the same port once
                self._reopen()
                self._ser.write(frame)
                self._ser.flush()
                raw = self._read_frame(rt)
        resp = cobs_decode(raw)
        if not resp:
            raise CC1101UsbError("empty response")
        status = resp[0]
        if status != 0x00:
            raise CC1101UsbError("device error 0x%02X for cmd 0x%02X" % (status, cmd))
        return resp[1:]

    def _reopen(self):
        try:
            self._ser.close()
        except Exception:
            pass
        self._open_serial()

    def _read_frame(self, timeout):
        """Read bytes until the 0x00 delimiter. Returns the pre-delimiter bytes."""
        deadline = time.time() + timeout
        buf = bytearray()
        old = self._ser.timeout
        try:
            while time.time() < deadline:
                self._ser.timeout = max(0.01, deadline - time.time())
                chunk = self._ser.read(1)
                if not chunk:
                    continue
                b = chunk[0]
                if b == 0:
                    if buf:
                        return bytes(buf)
                    # stray delimiter, keep going
                    continue
                buf.append(b)
                if len(buf) > MAX_BODY + 8:
                    raise CC1101UsbError("frame overrun")
            raise CC1101UsbError("timeout waiting for response")
        finally:
            self._ser.timeout = old

    # -- handshake --

    def ping(self):
        data = self._txn(CMD_PING)
        if len(data) < 7 or data[:4] != MAGIC:
            raise CC1101UsbError("bad PING reply")
        self.fw = (data[5], data[6])
        return data[4], self.fw  # proto, (major, minor)

    def info(self):
        data = self._txn(CMD_INFO)
        if len(data) >= 1:
            self.cc_version = data[0]
        return data

    # -- spidev-compatible API --

    def open(self, *a, **k):
        return True  # already open

    def xfer2(self, data):
        payload = bytes(bytearray(data))
        if len(payload) == 0:
            return []
        resp = self._txn(CMD_SPI_XFER, payload)
        return list(resp)

    xfer = xfer2
    xfer3 = xfer2

    def close(self):
        try:
            self._ser.close()
        except Exception:
            pass

    # -- extra device-side ops --

    def rf_switch(self, val):
        self._txn(CMD_RF_SWITCH, bytes([1 if val else 0]))

    def power(self, on):
        self._txn(CMD_POWER, bytes([1 if on else 0]))

    def gdo_read(self, which=0):
        data = self._txn(CMD_GDO_READ, bytes([which]))
        return data[0] if data else 0

    # one TX frame carries at most this many int16 pulses (fits MAX_BODY)
    MAX_TX_PULSES = 1000

    def tx_raw(self, pulses, repeat=1, flags=1):
        """Device-side OOK replay. pulses = signed int16 µs list.

        Long waveforms (> MAX_TX_PULSES) are split into several frames emitted
        back-to-back; `repeat` then loops the whole waveform host-side (a short
        re-arm gap sits between chunks, negligible for OOK replay).
        """
        repeat = max(1, min(32, int(repeat)))     # firmware caps repeat (no-jamming)
        clamped = [max(-32767, min(32767, int(p))) for p in pulses]
        n = len(clamped)
        if n == 0:
            return False
        if n <= self.MAX_TX_PULSES:
            self._tx_frame(clamped, repeat, flags)
            return True
        for _ in range(repeat):
            for i in range(0, n, self.MAX_TX_PULSES):
                self._tx_frame(clamped[i:i + self.MAX_TX_PULSES], 1, flags)
        return True

    def _tx_frame(self, clamped, repeat, flags):
        n = len(clamped)
        hdr = struct.pack("<BBH", repeat, flags & 0xFF, n)
        body = hdr + struct.pack("<%dh" % n, *clamped)
        self._txn(CMD_TX_RAW, body, read_timeout=max(5.0, repeat * 2.0))

    def rx_raw(self, duration_s=1.0, idle_us=50000, max_sym=512, flags=0):
        """Device-side edge capture. Returns signed int16 µs list."""
        dur_ms = max(1, min(60000, int(duration_s * 1000)))
        idle_us = max(0, min(0xFFFFFFFF, int(idle_us)))   # u32, no silent wrap
        max_sym = max(1, min(1000, int(max_sym)))         # firmware caps at 1000
        hdr = struct.pack("<HIHB", dur_ms, idle_us, max_sym, flags & 0xFF)
        data = self._txn(CMD_RX_RAW, hdr, read_timeout=duration_s + 3.0)
        if len(data) < 2:
            return []
        (n,) = struct.unpack("<H", data[:2])
        want = 2 + 2 * n
        if len(data) < want:
            n = (len(data) - 2) // 2
        return list(struct.unpack("<%dh" % n, data[2:2 + 2 * n]))


# ── Auto-detection ──────────────────────────────────────────────────────────

def _candidate_ports():
    """Yield serial device paths worth probing.

    When pyserial can enumerate VIDs we probe ONLY Espressif native-USB ports:
    opening+writing a PING to an unrelated device (GPS, modem, another MCU)
    could reset or disturb it. We only fall back to globbing when no VID info
    is available at all.
    """
    ordered = []
    had_vid_info = False
    try:
        from serial.tools import list_ports
        infos = list(list_ports.comports())
        esp = [p.device for p in infos if p.vid in _ESP_VIDS]
        if any(p.vid is not None for p in infos):
            had_vid_info = True
            ordered = esp            # only ESP ports when VIDs are known
        else:
            ordered = [p.device for p in infos]
    except Exception:
        pass
    # fall back to raw globbing only when we had no VID info to filter on
    if not ordered and not had_vid_info:
        import glob
        ordered = sorted(glob.glob("/dev/ttyACM*")) + sorted(glob.glob("/dev/ttyUSB*"))
    seen = set()
    for dev in ordered:
        if dev not in seen:
            seen.add(dev)
            yield dev


def detect(port=None, timeout=0.6):
    """Return an open CC1101Usb if a bridge is found, else None.

    Honours RJ_CC1101_USB=<path> to force a specific port.
    """
    forced = port or os.environ.get("RJ_CC1101_USB")
    ports = [forced] if forced else list(_candidate_ports())
    for dev in ports:
        if not dev:
            continue
        try:
            link = CC1101Usb(dev, timeout=timeout)
        except Exception:
            continue
        proto = None
        for _attempt in range(2):          # first PING can race the boot log
            try:
                proto, _fw = link.ping()
                break
            except Exception:
                time.sleep(0.15)
        try:
            if proto == PROTO_VER:
                try:
                    link.info()
                except Exception:
                    pass
                return link
            link.close()
        except Exception:
            try:
                link.close()
            except Exception:
                pass
    return None
