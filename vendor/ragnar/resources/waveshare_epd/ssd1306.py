# ssd1306.py
# Driver for the 0.96" SSD1306 128x64 monochrome OLED display (I2C).
#
# Exposes the same interface as Waveshare e-Paper drivers so it integrates
# transparently with EPDHelper and the rest of Ragnar:
#   width, height, init(), Clear(), getbuffer(image), display(buf),
#   displayPartial(buf), sleep()
#
# Wiring (Raspberry Pi):
#   VCC  → 3.3V  (pin 1)
#   GND  → GND   (pin 6)
#   SCL  → GPIO3 / SCL (pin 5)
#   SDA  → GPIO2 / SDA (pin 3)

import logging
import time

logger = logging.getLogger(__name__)

try:
    import smbus2 as smbus2_mod
    _SMBUS2_AVAILABLE = True
except ImportError:
    smbus2_mod = None
    _SMBUS2_AVAILABLE = False
    logger.warning("smbus2 not available — SSD1306 driver will not function. Install with: pip3 install smbus2")

EPD_WIDTH  = 128
EPD_HEIGHT = 64

# I2C control bytes
_CTRL_CMD  = 0x00   # Co=0, D/C#=0 → command byte
_CTRL_DATA = 0x40   # Co=0, D/C#=1 → data byte

# SSD1306 initialisation command sequence
_INIT_CMDS = [
    0xAE,           # display off
    0xD5, 0x80,     # set display clock div
    0xA8, 0x3F,     # multiplex ratio 63
    0xD3, 0x00,     # display offset 0
    0x40,           # start line 0
    0x8D, 0x14,     # charge pump enable
    0x20, 0x00,     # horizontal addressing mode
    0xA1,           # segment remap (col 127 mapped to SEG0)
    0xC8,           # COM output scan direction (remapped)
    0xDA, 0x12,     # COM pins hardware config
    0x81, 0xCF,     # contrast
    0xD9, 0xF1,     # pre-charge period
    0xDB, 0x40,     # Vcomh deselect level
    0xA4,           # display follows RAM content (not all-on)
    0xA6,           # normal (non-inverted) display
    0xAF,           # display on
]


class EPD:
    """SSD1306 0.96\" 128x64 monochrome OLED driver with EPD-compatible interface."""

    def __init__(self, i2c_address=0x3C, i2c_bus=1):
        self.width        = EPD_WIDTH
        self.height       = EPD_HEIGHT
        self._addr        = i2c_address
        self._bus_num     = i2c_bus
        self._bus         = None
        self._initialized = False

    # ------------------------------------------------------------------
    # Public EPD-compatible interface
    # ------------------------------------------------------------------

    def init(self, *args):
        """Initialise I2C bus and send the SSD1306 startup sequence.

        Idempotent: if already initialised, returns immediately without
        re-sending the init sequence (same pattern as gc9a01.py).
        """
        if self._initialized:
            return
        self._setup_hardware()
        self._send_init_sequence()
        self._initialized = True
        logger.info("SSD1306 initialised (%dx%d) at I2C 0x%02X bus %d",
                    self.width, self.height, self._addr, self._bus_num)

    def Clear(self):
        """Fill the display with black (all pixels off)."""
        if not self._initialized:
            self.init()
        buf = bytes(self.width * self.height // 8)
        self.display(buf)
        logger.info("SSD1306 cleared")

    def getbuffer(self, image):
        """Convert a PIL image (mode '1', 128x64) to SSD1306 page-format bytes.

        Output: 1024 bytes — 8 pages × 128 columns.
        Each byte represents 8 vertical pixels (LSB = topmost pixel in page).
        Pixel value 255 = white/on, 0 = black/off.
        """
        from PIL import Image as PILImage

        # Ensure correct size and mode
        if image.width != self.width or image.height != self.height:
            logger.warning(
                "SSD1306 getbuffer: image size %dx%d → resizing to %dx%d",
                image.width, image.height, self.width, self.height,
            )
            image = image.resize((self.width, self.height))

        if image.mode != "1":
            image = image.convert("1")

        buf = bytearray(self.width * (self.height // 8))  # 1024 bytes
        for page in range(self.height // 8):              # pages 0..7
            for x in range(self.width):                   # columns 0..127
                byte = 0
                for bit in range(8):
                    y = page * 8 + bit
                    pixel = image.getpixel((x, y))
                    # In mode "1": non-zero = white/on
                    if pixel:
                        byte |= (1 << bit)
                buf[page * self.width + x] = byte
        return bytes(buf)

    def display(self, buf):
        """Write a full-screen framebuffer (1024 bytes) to the display."""
        if not self._initialized:
            self.init()
        self._set_addressing()
        try:
            # smbus2 write_i2c_block_data is limited to 32 bytes per call;
            # write the framebuffer in 32-byte chunks.
            data = list(buf)
            chunk_size = 32
            for i in range(0, len(data), chunk_size):
                self._bus.write_i2c_block_data(self._addr, _CTRL_DATA, data[i:i + chunk_size])
        except Exception as exc:
            logger.error("SSD1306 display write error: %s", exc)

    def displayPartial(self, buf):
        """SSD1306 supports full-frame updates; treated same as display()."""
        self.display(buf)

    def sleep(self):
        """Send display-off command (0xAE)."""
        try:
            self._write_cmd(0xAE)
            logger.info("SSD1306 sleeping")
        except Exception as exc:
            logger.error("SSD1306 sleep error: %s", exc)

    # ------------------------------------------------------------------
    # Hardware helpers
    # ------------------------------------------------------------------

    def _setup_hardware(self):
        """Open the I2C bus.  Idempotent — does nothing if already open."""
        if self._bus is not None:
            return
        if not _SMBUS2_AVAILABLE:
            raise ImportError(
                "smbus2 is required for SSD1306.  Install with: pip3 install smbus2"
            )
        try:
            self._bus = smbus2_mod.SMBus(self._bus_num)
        except Exception as exc:
            logger.error("SSD1306 I2C bus open failed (bus %d): %s", self._bus_num, exc)
            raise

    def _write_cmd(self, cmd):
        """Send a single command byte via I2C."""
        try:
            self._bus.write_byte_data(self._addr, _CTRL_CMD, cmd)
        except Exception as exc:
            logger.error("SSD1306 command 0x%02X failed: %s", cmd, exc)
            raise

    def _write_cmd_sequence(self, cmds):
        """Send a list of command bytes as a block write."""
        try:
            self._bus.write_i2c_block_data(self._addr, _CTRL_CMD, list(cmds))
        except Exception as exc:
            logger.error("SSD1306 command sequence write failed: %s", exc)
            raise

    def _set_addressing(self):
        """Set column/page addressing to cover the full 128x64 frame."""
        try:
            self._write_cmd_sequence([
                0x21, 0x00, 0x7F,   # column address: 0 → 127
                0x22, 0x00, 0x07,   # page address:   0 → 7
            ])
        except Exception as exc:
            logger.error("SSD1306 addressing setup failed: %s", exc)
            raise

    def _send_init_sequence(self):
        """Send the SSD1306 power-on initialisation sequence."""
        for cmd in _INIT_CMDS:
            self._write_cmd(cmd)
        logger.debug("SSD1306 init sequence sent (%d commands)", len(_INIT_CMDS))
