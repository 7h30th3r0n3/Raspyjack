"""Receive-only SX1262 driver for the M5Stack CardputerZero Cap LoRa-1262.

The LoRa modem settings and packet representation derive from LORA-Pager-Pipe
(Copyright 2026 Valleytech Solutions, MIT). The cap uses SPI0 CE1 and a
PI4IOE5V6408 antenna switch, with a 3.0 V TCXO on DIO3.
"""

from contextlib import ExitStack
from pathlib import Path
import errno
import struct
import time

from . import RadioError
from .profiles import validate_profile


_RESET, _IRQ, _BUSY = 26, 23, 22
_EXT_POWER = Path("/sys/class/leds/ext_5v_out/brightness")
_EXT_MUX = Path("/sys/class/leds/ext_usb_gpio_fun/brightness")
_EXPANDER = 0x43
_IRQ_MASK = 0x0262  # RX_DONE | HEADER_ERR | CRC_ERR | TIMEOUT
_BW = {62500: 0x03, 125000: 0x04, 250000: 0x05, 500000: 0x06}
_RX_COMMANDS = frozenset({
    0x02, 0x08, 0x0D, 0x11, 0x12, 0x13, 0x14, 0x1D, 0x1E, 0x80, 0x82,
    0x86, 0x89, 0x8A, 0x8B, 0x8C, 0x8F, 0x96, 0x97, 0x98, 0x9D,
})


def _set_led(path, value, stack):
    original = path.read_text().strip()
    if original != value:
        path.write_text(value)
        stack.callback(path.write_text, original)


def _set_p0(bus, register, bit):
    previous = bus.read_byte_data(_EXPANDER, register)
    value = (previous & 0xFE) | bit
    if previous != value:
        bus.write_byte_data(_EXPANDER, register, value)
    return previous & 1


def _enable_antenna(bus, stack):
    if bus.read_byte_data(_EXPANDER, 0x01) >> 5 != 0b101:
        raise RadioError("Cap LoRa-1262 antenna switch not found on I2C1 at 0x43")
    # PI4IOE5V6408 datasheet, registers 05h, 03h, 07h: preload high,
    # select output, then release high impedance. Only P0 belongs to LoRa.
    for register, bit in ((0x05, 1), (0x03, 1), (0x07, 0)):
        original = _set_p0(bus, register, bit)
        if original != bit:
            stack.callback(_set_p0, bus, register, original)


class _GpioV1:
    """Debian Bookworm's libgpiod 1.6 binding."""

    def __init__(self, gpiod, stack):
        chip = gpiod.Chip("/dev/gpiochip0")
        stack.callback(chip.close)
        self.lines = {}
        for pin in (_BUSY, _IRQ, _RESET):
            line = chip.get_line(pin)
            line.request(consumer="raspyjack-lora", type=gpiod.LINE_REQ_DIR_IN)
            stack.callback(line.release)
            self.lines[pin] = line

    def active(self, pin):
        return bool(self.lines[pin].get_value())

    def pulse_reset(self, stack):
        reset = self.lines[_RESET]
        reset.set_direction_output(0)
        stack.callback(reset.set_direction_input)
        time.sleep(0.002)
        reset.set_value(1)


class _GpioV2:
    """Debian Trixie's libgpiod 2.x binding."""

    def __init__(self, gpiod, stack):
        self.gpiod = gpiod
        self.inputs = gpiod.LineSettings(direction=gpiod.line.Direction.INPUT)
        self.lines = gpiod.request_lines("/dev/gpiochip0", consumer="raspyjack-lora",
                                         config={(_RESET, _BUSY, _IRQ): self.inputs})
        stack.callback(self.lines.release)

    def active(self, pin):
        return self.lines.get_value(pin) == self.gpiod.line.Value.ACTIVE

    def pulse_reset(self, stack):
        gpiod = self.gpiod
        self.lines.reconfigure_lines({
            _RESET: gpiod.LineSettings(direction=gpiod.line.Direction.OUTPUT,
                                       output_value=gpiod.line.Value.INACTIVE),
            (_BUSY, _IRQ): self.inputs,
        })
        stack.callback(self.lines.reconfigure_lines, {(_RESET, _BUSY, _IRQ): self.inputs})
        time.sleep(0.002)
        self.lines.set_value(_RESET, gpiod.line.Value.ACTIVE)


class CapRadio:
    def __init__(self, profile):
        self.profile = validate_profile(profile)
        self.diagnostics = dict(received=0, timeouts=0, header_errors=0,
                                crc_errors=0, malformed=0, retunes=0)
        self._resources = None

    def open(self):
        if self._resources is not None:
            return self
        if not _EXT_POWER.is_file():
            raise RadioError("CardputerZero cap 5 V rail is unavailable on this device")
        try:
            import gpiod
            import spidev
            try:
                from smbus import SMBus
            except ImportError:
                from smbus2 import SMBus
        except ImportError as exc:
            raise RadioError("Cap needs python3-spidev, python3-smbus and python3-libgpiod") from exc

        # Reserve all GPIOs before touching power, mux or SPI.
        # In particular the optional NFC overlay can already own BCM22.
        with ExitStack() as stack:
            try:
                gpio_api = _GpioV2 if hasattr(gpiod, "request_lines") else _GpioV1
                self._gpio = gpio_api(gpiod, stack)
            except OSError as exc:
                if exc.errno == errno.EBUSY:
                    raise RadioError("Cap GPIO busy: close the other radio app or check the GPIO22 NFC overlay") from exc
                raise RadioError("Cannot claim the CardputerZero cap GPIO lines") from exc
            try:
                spi = spidev.SpiDev()
                stack.callback(spi.close)
                spi.open(0, 1)  # CE0 is the display.
                spi.mode = 0
                spi.max_speed_hz = 1_000_000
            except OSError as exc:
                raise RadioError("Cannot open the cap SPI device /dev/spidev0.1") from exc
            try:
                _set_led(_EXT_POWER, "1", stack)
                time.sleep(0.15)
            except OSError as exc:
                raise RadioError("Cannot enable the CardputerZero cap 5 V rail") from exc
            try:
                bus = SMBus(1)
                stack.callback(bus.close)
                _enable_antenna(bus, stack)
            except OSError as exc:
                raise RadioError("Cannot reach the Cap LoRa-1262 antenna switch on I2C1 at 0x43") from exc
            # The factory image exposes the mux as an LED. GPIO is the
            # board's default when a mux control is unavailable.
            if _EXT_MUX.exists():
                try:
                    _set_led(_EXT_MUX, "0", stack)
                except OSError as exc:
                    raise RadioError("Cannot select the cap GPIO pins on the HAT mux") from exc
            self._spi = spi
            self._gpio.pulse_reset(stack)
            time.sleep(0.010)
            self._command(0x80, b"\x00")  # STDBY_RC
            self._command(0x97, b"\x06\x00\x01\x40")  # DIO3 TCXO: 3.0 V, 5 ms
            self._command(0x89, b"\x7f")  # calibrate
            self._command(0x96, b"\x01")  # DC-DC regulator
            self._command(0x8A, b"\x01")  # LoRa
            if self._command(0x11, read=1) != b"\x01":
                raise RadioError("SX1262 did not confirm LoRa mode on SPI0 CE1")
            stack.callback(self._command, 0x80, b"\x00")
            self._command(0x9D, b"\x01")  # DIO2 RF switch
            self._command(0x8F, b"\x00\x00")  # FIFO base addresses
            self._tune(self.profile)
            self._resources = stack.pop_all()
        return self

    def _command(self, opcode, args=b"", read=0):
        if opcode not in _RX_COMMANDS:
            raise RadioError("Unsupported receive operation")
        deadline = time.monotonic() + 0.5
        while self._gpio.active(_BUSY):
            if time.monotonic() >= deadline:
                raise RadioError("SX1262 BUSY did not clear")
            time.sleep(0.001)
        data = bytes([opcode]) + args
        if read:
            data += bytes(1 + read)  # Skip the status byte before read data.
        result = self._spi.xfer2(list(data))
        if len(result) != len(data):
            raise RadioError("Short SX1262 SPI transfer")
        return bytes(result[-read:]) if read else b""

    def _read_register(self, address, count=1):
        return self._command(0x1D, struct.pack(">H", address), count)

    def _write_register(self, address, data):
        self._command(0x0D, struct.pack(">H", address) + data)

    def tune(self, profile):
        if self._resources is None:
            raise RadioError("Cap radio is closed")
        self._tune(validate_profile(profile))

    def _tune(self, profile):
        self._command(0x80, b"\x00")
        self._command(0x98, b"\xe1\xe9" if profile.frequency_hz >= 902000000 else b"\xd7\xdb")
        pll = (profile.frequency_hz * (1 << 25) + 16000000) // 32000000
        self._command(0x86, struct.pack(">I", pll))
        ldro = (2 ** profile.spreading_factor) / profile.bandwidth_hz > 0.016
        self._command(0x8B, bytes((profile.spreading_factor, _BW[profile.bandwidth_hz],
                                  profile.coding_rate - 4, ldro)))
        self._command(0x8C, struct.pack(">HBBBB", profile.preamble_symbols, 0, 255, 1, 0))
        sync = bytes(((profile.sync_word & 0xF0) | 4, ((profile.sync_word & 0x0F) << 4) | 4))
        self._write_register(0x0740, sync)
        if self._read_register(0x0740, 2) != sync:
            raise RadioError("SX1262 sync-word verification failed")
        self._write_register(0x08AC, b"\x96")  # boosted RX gain
        self._write_register(0x0736, bytes([self._read_register(0x0736)[0] | 0x04]))
        self._write_register(0x08D8, bytes([self._read_register(0x08D8)[0] | 0x1E]))
        self._command(0x08, struct.pack(">HHHH", _IRQ_MASK, _IRQ_MASK, 0, 0))
        self._command(0x02, b"\xff\xff")
        self._command(0x82, b"\xff\xff\xff")  # continuous RX
        self.profile = profile
        self.diagnostics["retunes"] += 1

    def receive(self, timeout=0.25):
        if self._resources is None:
            raise RadioError("Cap radio is closed")
        deadline = time.monotonic() + min(2, max(0, timeout))
        while not self._gpio.active(_IRQ):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            time.sleep(min(0.020, remaining))
        irq = int.from_bytes(self._command(0x12, read=2), "big")
        self._command(0x02, irq.to_bytes(2, "big"))
        for flag, name in ((0x0200, "timeouts"), (0x0020, "header_errors"), (0x0040, "crc_errors")):
            if irq & flag:
                self.diagnostics[name] += 1
        if not irq & 0x0002:
            return None
        length, offset = self._command(0x13, read=2)
        if not length:
            self.diagnostics["malformed"] += 1
            return None
        raw = self._command(0x1E, bytes([offset]), length)
        rssi, snr, _ = struct.unpack(">BbB", self._command(0x14, read=3))
        self.diagnostics["received"] += 1
        return {"timestamp": time.time(), "profile": self.profile.to_dict(),
                "raw_hex": raw.hex(), "rssi_dbm": -rssi / 2, "snr_db": snr / 4,
                "crc_ok": not bool(irq & 0x0060)}

    def close(self):
        resources, self._resources = self._resources, None
        if resources is not None:
            resources.close()

    def __enter__(self):
        return self.open()

    def __exit__(self, *_):
        self.close()
