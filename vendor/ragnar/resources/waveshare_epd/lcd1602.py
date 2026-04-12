# lcd1602.py
# Driver for the LCD1602 16x2 character LCD with PCF8574 I2C backpack.
#
# Exposes the same interface as other Ragnar display drivers so it integrates
# with the rest of the display system:
#   width, height, init(), Clear(), write_line(row, text), sleep()
#
# The PCF8574 I2C expander maps to LCD pins as follows:
#   Bit 7 (P7) = D7     Bit 6 (P6) = D6    Bit 5 (P5) = D5    Bit 4 (P4) = D4
#   Bit 3 (P3) = BL     Bit 2 (P2) = EN    Bit 1 (P1) = RW    Bit 0 (P0) = RS
#
# Wiring (Raspberry Pi ↔ LCD1602 I2C backpack):
#   VCC  → Pin 2  (5V)
#   GND  → Pin 6  (GND)
#   SDA  → Pin 3  (GPIO 2 / I2C SDA)
#   SCL  → Pin 5  (GPIO 3 / I2C SCL)
#
# Default I2C address is 0x27 (A0/A1/A2 all HIGH on PCF8574).
# If the display is not found at 0x27, 0x3F is tried automatically.

import logging
import time

logger = logging.getLogger(__name__)

try:
    import smbus2 as smbus2_mod
    _SMBUS2_AVAILABLE = True
except ImportError:
    smbus2_mod = None
    _SMBUS2_AVAILABLE = False
    logger.warning(
        "smbus2 not available — LCD1602 driver will not function. "
        "Install with: pip3 install smbus2"
    )

# PCF8574 pin bitmasks
_BL  = 0x08   # P3 — backlight
_EN  = 0x04   # P2 — enable (pulse to latch)
_RW  = 0x02   # P1 — read/write (always 0 = write)
_RS  = 0x01   # P0 — register select (0=cmd, 1=data)

# LCD1602 commands
_CMD_CLEARDISPLAY   = 0x01
_CMD_RETURNHOME     = 0x02
_CMD_ENTRYMODESET   = 0x04
_CMD_DISPLAYCONTROL = 0x08
_CMD_FUNCTIONSET    = 0x20

_FLAG_ENTRY_INCREMENT = 0x02
_FLAG_DISPLAY_ON      = 0x04
_FLAG_FUNCTION_4BIT   = 0x00
_FLAG_FUNCTION_2LINE  = 0x08
_FLAG_FUNCTION_5X8    = 0x00

# Row start addresses for each physical line
_ROW_OFFSETS = [0x00, 0x40]

LCD_WIDTH  = 16
LCD_HEIGHT = 2

# Candidate I2C addresses tried during auto-detection (most common first)
_CANDIDATE_ADDRESSES = [0x27, 0x3F]


class EPD:
    """LCD1602 16×2 character LCD driver (PCF8574 I2C backpack).

    Provides the same public interface as the Waveshare e-Paper drivers used
    throughout Ragnar so it integrates transparently with the display system.
    """

    def __init__(self, i2c_address=0x27, i2c_bus=1):
        self.width        = LCD_WIDTH
        self.height       = LCD_HEIGHT
        self._addr        = i2c_address
        self._bus_num     = i2c_bus
        self._bus         = None
        self._backlight   = _BL          # backlight ON by default
        self._initialized = False

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def init(self, *args):
        """Initialise the I2C bus and run the LCD1602 startup sequence.

        Idempotent: returns immediately if already initialised.
        Auto-detects I2C address if the configured one is unreachable.
        """
        if self._initialized:
            return
        self._open_bus()
        self._addr = self._detect_address()
        self._init_sequence()
        self._initialized = True
        logger.info(
            "LCD1602 initialised (%dx%d) at I2C 0x%02X bus %d",
            self.width, self.height, self._addr, self._bus_num,
        )

    def Clear(self):
        """Clear the display and return cursor to home."""
        if not self._initialized:
            self.init()
        self._send_cmd(_CMD_CLEARDISPLAY)
        time.sleep(0.002)   # clear takes up to 1.52 ms
        logger.debug("LCD1602 cleared")

    def write_line(self, row: int, text: str):
        """Write *text* to the given *row* (0 or 1), padded/truncated to 16 chars.

        Non-ASCII characters are replaced with '?' since the HD44780 ROM only
        covers ASCII + Japanese kana glyphs.  This is the primary method used
        by the display loop.
        """
        if not self._initialized:
            self.init()
        row  = max(0, min(row, LCD_HEIGHT - 1))
        text = text.encode("ascii", errors="replace").decode("ascii")
        text = text.ljust(LCD_WIDTH)[:LCD_WIDTH]
        self._set_cursor(row, 0)
        for ch in text:
            self._send_data(ord(ch))

    def backlight(self, on: bool = True):
        """Turn the backlight on or off."""
        self._backlight = _BL if on else 0x00
        # Write a dummy byte to push the backlight state to the expander
        try:
            self._write_byte(self._backlight)
        except Exception as exc:
            logger.warning("LCD1602 backlight control failed: %s", exc)

    def sleep(self):
        """Turn off the display and backlight to save power.

        Resets *_initialized* so a subsequent call to ``init()`` will re-run
        the full HD44780 startup sequence.
        """
        try:
            if self._initialized:
                self._send_cmd(_CMD_DISPLAYCONTROL)   # display OFF (all flags cleared)
            self.backlight(False)
            self._initialized = False
            logger.info("LCD1602 sleeping")
        except Exception as exc:
            logger.error("LCD1602 sleep error: %s", exc)

    # ------------------------------------------------------------------
    # Helpers — hardware / I2C
    # ------------------------------------------------------------------

    def _open_bus(self):
        """Open the I2C bus (idempotent)."""
        if self._bus is not None:
            return
        if not _SMBUS2_AVAILABLE:
            raise ImportError(
                "smbus2 is required for the LCD1602 driver. "
                "Install with: pip3 install smbus2"
            )
        try:
            self._bus = smbus2_mod.SMBus(self._bus_num)
        except Exception as exc:
            logger.error("LCD1602: cannot open I2C bus %d: %s", self._bus_num, exc)
            raise

    def _detect_address(self) -> int:
        """Return the first responsive I2C address from _CANDIDATE_ADDRESSES.

        If the configured address responds, it is used immediately.
        Otherwise the candidates are tried in order and a warning is logged.
        Falls back to the configured address if none responds.
        """
        # Try configured address first
        if self._probe(self._addr):
            return self._addr

        logger.warning(
            "LCD1602: no response at I2C 0x%02X — probing alternative addresses",
            self._addr,
        )
        for addr in _CANDIDATE_ADDRESSES:
            if addr != self._addr and self._probe(addr):
                logger.info("LCD1602: found device at 0x%02X", addr)
                return addr

        logger.warning(
            "LCD1602: no device found; falling back to 0x%02X — check wiring",
            self._addr,
        )
        return self._addr

    def _probe(self, addr: int) -> bool:
        """Return True if an I2C device responds at *addr*."""
        try:
            self._bus.read_byte(addr)
            return True
        except Exception:
            return False

    def _write_byte(self, data: int):
        """Write a single byte to the PCF8574 expander."""
        try:
            self._bus.write_byte(self._addr, data)
        except Exception as exc:
            logger.error("LCD1602: I2C write error at 0x%02X: %s", self._addr, exc)
            raise

    def _pulse_enable(self, data: int):
        """Pulse the EN pin high then low to latch a nibble."""
        self._write_byte(data | _EN)    # EN high
        time.sleep(0.0005)
        self._write_byte(data & ~_EN)   # EN low
        time.sleep(0.0001)

    def _send_nibble(self, nibble: int, mode: int):
        """Send a 4-bit nibble.  *mode* is _RS for data or 0 for command."""
        high = (nibble & 0xF0) | self._backlight | mode
        self._write_byte(high)
        self._pulse_enable(high)

    def _send_cmd(self, cmd: int):
        """Send an 8-bit command to the LCD (RS=0)."""
        self._send_nibble(cmd & 0xF0, 0)
        self._send_nibble((cmd << 4) & 0xF0, 0)

    def _send_data(self, data: int):
        """Send an 8-bit data byte to the LCD (RS=1)."""
        self._send_nibble(data & 0xF0, _RS)
        self._send_nibble((data << 4) & 0xF0, _RS)

    def _set_cursor(self, row: int, col: int):
        """Move cursor to (row, col)."""
        addr = _ROW_OFFSETS[row] + col
        self._send_cmd(0x80 | addr)

    # ------------------------------------------------------------------
    # Initialisation sequence (HD44780 4-bit mode)
    # ------------------------------------------------------------------

    def _init_sequence(self):
        """Run the HD44780 initialisation sequence for 4-bit operation."""
        time.sleep(0.05)    # wait >40 ms after VCC rises to 2.7 V

        # Three wake-up writes in 8-bit mode (before switching to 4-bit)
        for _ in range(3):
            self._send_nibble(0x30, 0)
            time.sleep(0.005)

        # Switch to 4-bit mode
        self._send_nibble(0x20, 0)
        time.sleep(0.001)

        # Function set: 4-bit, 2 lines, 5×8 font
        self._send_cmd(_CMD_FUNCTIONSET | _FLAG_FUNCTION_2LINE | _FLAG_FUNCTION_5X8)
        time.sleep(0.001)

        # Display control: display ON, cursor OFF, blink OFF
        self._send_cmd(_CMD_DISPLAYCONTROL | _FLAG_DISPLAY_ON)
        time.sleep(0.001)

        # Clear display
        self._send_cmd(_CMD_CLEARDISPLAY)
        time.sleep(0.002)

        # Entry mode: increment cursor, no display shift
        self._send_cmd(_CMD_ENTRYMODESET | _FLAG_ENTRY_INCREMENT)
        time.sleep(0.001)

        logger.debug("LCD1602 init sequence complete")
