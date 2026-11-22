"""LoRaPipe CLI transport, pinned to the documented upstream RXLOG protocol."""

import math
import re
import time

from .profiles import validate_profile
from . import RadioError


_RX = re.compile(r"^([0-9]{1,12}),RXLOG,(-?[0-9]+(?:\.[0-9]+)?),(-?[0-9]+(?:\.[0-9]+)?),([0-9a-fA-F]{2,510})$")


def parse_rxlog(line, profile, timestamp=None):
    """Parse a complete line. MCU clock and host receipt time remain separate."""
    if isinstance(line, bytes):
        try:
            line = line.decode("ascii")
        except UnicodeDecodeError:
            return None
    if not isinstance(line, str) or len(line) > 1024:
        return None
    match = _RX.fullmatch(line.strip("\r\n"))
    if not match:
        return None
    receiver_time, rssi, snr, encoded = match.groups()
    if len(encoded) % 2:
        return None
    rssi, snr = float(rssi), float(snr)
    if not (math.isfinite(rssi) and math.isfinite(snr) and -200 <= rssi <= 20 and -40 <= snr <= 30):
        return None
    raw = bytes.fromhex(encoded)
    settings = profile.to_dict()
    # The serial CLI accepts only frequency, BW, SF, CR and sync word.
    settings["preamble_symbols"] = None
    return {"timestamp": time.time() if timestamp is None else timestamp,
            "receiver_timestamp": int(receiver_time), "profile": settings,
            "raw_hex": raw.hex(), "rssi_dbm": rssi, "snr_db": snr,
            "crc_ok": None, "crc_source": "not_reported"}


class LoRaPipeSerial:
    """115200-baud LoRaPipe CLI adapter. KISS mode is deliberately unsupported."""

    def __init__(self, profile, device, baud=115200):
        self.profile = validate_profile(profile)
        self.device, self.baud = device, baud
        self._serial = None
        self._buffer = bytearray()
        self._discard = False
        self._logging = False
        self._renew_at = 0.0
        self.diagnostics = {"received": 0, "malformed": 0, "retunes": 0,
                            "retune_dropped": 0}

    def _line(self, deadline):
        while time.monotonic() < deadline:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                line = bytes(self._buffer[:newline + 1])
                del self._buffer[:newline + 1]
                if self._discard:
                    self._discard = False
                    continue
                return line
            if len(self._buffer) > 1024:
                self._buffer.clear()
                self._discard = True
                self.diagnostics["malformed"] += 1
            chunk = self._serial.read(128)
            if chunk:
                self._buffer.extend(chunk)
        return None

    def _command(self, command, expect):
        # Commands are formed internally from validated profiles, never user text.
        self._serial.write(command.encode("ascii") + b"\r\n")
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            line = self._line(deadline)
            if line is None:
                break
            if b"RXLOG" in line:
                self.diagnostics["retune_dropped"] += 1
                continue
            # The CLI echoes each input character. Only its own response prefix
            # acknowledges a command (sometimes after the command's echoed CR).
            reply = line.rstrip(b"\r\n").rsplit(b"\r", 1)[-1].strip()
            if not reply.startswith(b"-> "):
                continue
            value = reply[3:].strip()
            if value.startswith((b"Error", b"Unknown")):
                raise RadioError("LoRaPipe rejected receive configuration")
            if value == expect or (command == "ver" and expect in value):
                return
        raise RadioError("No LoRaPipe CLI response; check firmware, baud rate and CLI mode")

    def open(self):
        try:
            import serial
        except ImportError as exc:
            raise RadioError("LoRaPipe serial capture needs pyserial") from exc
        try:
            self._serial = serial.Serial(self.device, self.baud, timeout=0.05, write_timeout=1,
                                         exclusive=True)
        except OSError as exc:
            raise RadioError("Cannot open LoRaPipe serial device; check port and ownership") from exc
        try:
            self._command("ver", expect=b"(Build:")
            self.tune(self.profile)
            return self
        except Exception:
            self.close()
            raise

    def tune(self, profile):
        profile = validate_profile(profile)
        if self._serial is None:
            raise RadioError("Serial radio is not open")
        command = "tempradio %.6f,%g,%d,%d,%02x,5" % (
            profile.frequency_hz / 1e6, profile.bandwidth_hz / 1e3,
            profile.spreading_factor, profile.coding_rate, profile.sync_word)
        # Disable log while changing channel to prevent stale FIFO bytes being
        # labeled with the new profile. The unobserved interval is counted.
        self._command("rxlog off", expect=b"rxlog off")
        self._logging = False
        self._command(command, expect=b"OK - temp params for 5 mins")
        # The upstream firmware applies temporary settings 2000 ms after the
        # response. Keep RXLOG disabled until that transition has completed.
        time.sleep(2.1)
        self._buffer.clear()
        self._serial.reset_input_buffer()
        self.profile = profile
        self._command("rxlog on", expect=b"rxlog on")
        self._logging = True
        self._renew_at = time.monotonic() + 240
        self.diagnostics["retunes"] += 1

    def receive(self, timeout=0.25):
        if self._serial is None:
            raise RadioError("Serial radio is not open")
        if time.monotonic() >= self._renew_at:
            self.tune(self.profile)
        deadline = time.monotonic() + min(max(float(timeout), 0), 2)
        while time.monotonic() < deadline:
            line = self._line(deadline)
            if line is None:
                return None
            record = parse_rxlog(line, self.profile)
            if record is not None:
                self.diagnostics["received"] += 1
                return record
            if b"RXLOG" in line:
                self.diagnostics["malformed"] += 1
        return None

    def close(self):
        if self._serial is not None:
            try:
                if self._logging:
                    self._serial.write(b"rxlog off\r\n")
            finally:
                self._logging = False
                self._serial.close()
                self._serial = None
        self._buffer.clear()

    def __enter__(self):
        return self.open()

    def __exit__(self, *_):
        self.close()
