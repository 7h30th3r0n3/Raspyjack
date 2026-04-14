# gc9a01.py
# Driver for the 1.28" GC9A01 240x240 round RGB TFT LCD.
#
# Exposes the same interface as Waveshare e-Paper drivers so it integrates
# transparently with EPDHelper and the rest of Ragnar:
#   width, height, init(), Clear(), getbuffer(image), display(buf),
#   displayPartial(buf), sleep()
#
# Wiring (Raspberry Pi):
#   VCC  → 3.3V  (pin 1 or 17)
#   GND  → GND   (pin 6 or 9)
#   DIN  → GPIO10 / MOSI  (pin 19)
#   CLK  → GPIO11 / SCLK  (pin 23)
#   CS   → GPIO8  / CE0   (pin 24)
#   DC   → GPIO25         (pin 22)
#   RST  → GPIO27         (pin 13)
#   BL   → GPIO18         (pin 12)

import logging
import time
import struct

logger = logging.getLogger(__name__)

EPD_WIDTH  = 240
EPD_HEIGHT = 240

RST_PIN  = 27
DC_PIN   = 25
CS_PIN   = 8
BL_PIN   = 18
MOSI_PIN = 10
SCLK_PIN = 11

SPI_BUS    = 0
SPI_DEVICE = 0
SPI_MAX_HZ = 40_000_000


class EPD:
    """GC9A01 1.28\" 240x240 round TFT LCD driver with EPD-compatible interface."""

    def __init__(self):
        self.width  = EPD_WIDTH
        self.height = EPD_HEIGHT
        self._spi  = None
        self._gpio = {}
        self._initialized = False

    # ------------------------------------------------------------------
    # Public EPD-compatible interface
    # ------------------------------------------------------------------

    def init(self, *args):
        """Initialise SPI, GPIO and the GC9A01 controller.

        This is called every display loop iteration for e-Paper partial-update
        compatibility.  We only run the full hardware setup + reset sequence
        once to avoid the blank flash that a reset causes on every frame.
        """
        if self._initialized:
            return  # Already running — skip reset/reinit entirely
        self._setup_hardware()
        self._reset()
        self._send_init_sequence()
        self._initialized = True
        logger.info("GC9A01 initialised (%dx%d)", self.width, self.height)

    def Clear(self, color=0xFFFF):
        """Fill the entire display with a solid RGB565 colour (default white)."""
        if not self._initialized:
            self.init()
        hi = (color >> 8) & 0xFF
        lo = color & 0xFF
        buf = bytes([hi, lo]) * (self.width * self.height)
        self._set_window(0, 0, self.width - 1, self.height - 1)
        self._write_data_bulk(buf)
        logger.info("GC9A01 cleared")

    def getbuffer(self, image):
        """Convert a PIL image (any mode) to a packed RGB565 byte string.

        Ragnar renders 1-bit ('1') PIL images internally.  This converts
        any PIL mode to 16-bit RGB565 for the TFT.  The image is centre-
        cropped to a square before conversion to match the round display.
        """
        from PIL import Image as PILImage

        img = image.convert("RGB")

        # Centre-crop to square so nothing is distorted on the round panel
        w, h = img.width, img.height
        side = min(w, h)
        if w != side or h != side:
            left = (w - side) // 2
            top  = (h - side) // 2
            img  = img.crop((left, top, left + side, top + side))

        if img.width != self.width or img.height != self.height:
            logger.warning(
                "Image size %dx%d → resizing to %dx%d",
                img.width, img.height, self.width, self.height,
            )
            img = img.resize((self.width, self.height))

        pixels = img.getdata()
        buf = bytearray(self.width * self.height * 2)
        idx = 0
        for r, g, b in pixels:
            rgb565 = ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)
            buf[idx]     = (rgb565 >> 8) & 0xFF
            buf[idx + 1] = rgb565 & 0xFF
            idx += 2
        return bytes(buf)

    def display(self, buf):
        """Write a full-screen RGB565 buffer to the display."""
        if not self._initialized:
            self.init()
        self._set_window(0, 0, self.width - 1, self.height - 1)
        self._write_data_bulk(buf)

    def displayPartial(self, buf):
        """TFT supports instant full-frame updates; treated same as display()."""
        self.display(buf)

    def sleep(self):
        """Enter sleep mode and turn off backlight."""
        self._write_cmd(0x10)   # SLPIN
        time.sleep(0.005)
        if "bl" in self._gpio:
            self._gpio["bl"].off()
        logger.info("GC9A01 sleeping")

    # ------------------------------------------------------------------
    # Hardware helpers
    # ------------------------------------------------------------------

    def _setup_hardware(self):
        if self._spi is not None:
            # Already initialised — don't try to reclaim GPIO pins that are
            # still held by gpiozero from the first call.  init() is called
            # every display loop iteration (for e-Paper partial update compat)
            # so we must guard against double-setup here.
            return
        try:
            import spidev
            import gpiozero

            self._spi = spidev.SpiDev()
            self._spi.open(SPI_BUS, SPI_DEVICE)
            self._spi.max_speed_hz = SPI_MAX_HZ
            self._spi.mode = 0

            self._gpio["rst"] = gpiozero.LED(RST_PIN)
            self._gpio["dc"]  = gpiozero.LED(DC_PIN)
            self._gpio["bl"]  = gpiozero.LED(BL_PIN)

            self._gpio["bl"].on()
        except Exception as e:
            logger.error("GC9A01 hardware setup failed: %s", e)
            raise

    def _reset(self):
        self._gpio["rst"].on()
        time.sleep(0.01)
        self._gpio["rst"].off()
        time.sleep(0.01)
        self._gpio["rst"].on()
        time.sleep(0.12)

    def _write_cmd(self, cmd):
        self._gpio["dc"].off()
        self._spi.writebytes([cmd])

    def _write_data(self, data):
        self._gpio["dc"].on()
        if isinstance(data, int):
            self._spi.writebytes([data])
        else:
            self._spi.writebytes(list(data))

    def _write_data_bulk(self, data):
        """Write large payloads in chunks to avoid spidev buffer limits."""
        self._gpio["dc"].on()
        chunk = 4096
        view = memoryview(data) if not isinstance(data, memoryview) else data
        for i in range(0, len(view), chunk):
            self._spi.writebytes2(view[i : i + chunk])

    def _set_window(self, x0, y0, x1, y1):
        self._write_cmd(0x2A)   # CASET
        self._write_data(struct.pack(">HH", x0, x1))
        self._write_cmd(0x2B)   # RASET
        self._write_data(struct.pack(">HH", y0, y1))
        self._write_cmd(0x2C)   # RAMWR

    def _send_init_sequence(self):
        """GC9A01 power-on initialisation sequence."""
        self._write_cmd(0xEF)

        self._write_cmd(0xEB)
        self._write_data(0x14)

        self._write_cmd(0xFE)
        self._write_cmd(0xEF)

        self._write_cmd(0xEB)
        self._write_data(0x14)

        self._write_cmd(0x84)
        self._write_data(0x40)

        self._write_cmd(0x85)
        self._write_data(0xFF)

        self._write_cmd(0x86)
        self._write_data(0xFF)

        self._write_cmd(0x87)
        self._write_data(0xFF)

        self._write_cmd(0x88)
        self._write_data(0x0A)

        self._write_cmd(0x89)
        self._write_data(0x21)

        self._write_cmd(0x8A)
        self._write_data(0x00)

        self._write_cmd(0x8B)
        self._write_data(0x80)

        self._write_cmd(0x8C)
        self._write_data(0x01)

        self._write_cmd(0x8D)
        self._write_data(0x01)

        self._write_cmd(0x8E)
        self._write_data(0xFF)

        self._write_cmd(0x8F)
        self._write_data(0xFF)

        self._write_cmd(0xB6)
        self._write_data([0x00, 0x20])

        self._write_cmd(0x36)   # MADCTL — memory access / scan direction
        self._write_data(0x48)  # portrait, RGB order

        self._write_cmd(0x3A)   # COLMOD — pixel format
        self._write_data(0x05)  # 16-bit RGB565

        self._write_cmd(0x90)
        self._write_data([0x08, 0x08, 0x08, 0x08])

        self._write_cmd(0xBD)
        self._write_data(0x06)

        self._write_cmd(0xBC)
        self._write_data(0x00)

        self._write_cmd(0xFF)
        self._write_data([0x60, 0x01, 0x04])

        self._write_cmd(0xC3)
        self._write_data(0x13)

        self._write_cmd(0xC4)
        self._write_data(0x13)

        self._write_cmd(0xC9)
        self._write_data(0x22)

        self._write_cmd(0xBE)
        self._write_data(0x11)

        self._write_cmd(0xE1)
        self._write_data([0x10, 0x0E])

        self._write_cmd(0xDF)
        self._write_data([0x21, 0x0C, 0x02])

        self._write_cmd(0xF0)   # Positive gamma
        self._write_data([0x45, 0x09, 0x08, 0x08, 0x26, 0x2A])

        self._write_cmd(0xF1)   # Negative gamma
        self._write_data([0x43, 0x70, 0x72, 0x36, 0x37, 0x6F])

        self._write_cmd(0xF2)   # Positive gamma
        self._write_data([0x45, 0x09, 0x08, 0x08, 0x26, 0x2A])

        self._write_cmd(0xF3)   # Negative gamma
        self._write_data([0x43, 0x70, 0x72, 0x36, 0x37, 0x6F])

        self._write_cmd(0xED)
        self._write_data([0x1B, 0x0B])

        self._write_cmd(0xAE)
        self._write_data(0x77)

        self._write_cmd(0xCD)
        self._write_data(0x63)

        self._write_cmd(0x70)
        self._write_data([0x07, 0x07, 0x04, 0x0E, 0x0F, 0x09, 0x07, 0x08, 0x03])

        self._write_cmd(0xE8)
        self._write_data(0x34)

        self._write_cmd(0x62)
        self._write_data([
            0x18, 0x0D, 0x71, 0xED, 0x70, 0x70,
            0x18, 0x0F, 0x71, 0xEF, 0x70, 0x70,
        ])

        self._write_cmd(0x63)
        self._write_data([
            0x18, 0x11, 0x71, 0xF1, 0x70, 0x70,
            0x18, 0x13, 0x71, 0xF3, 0x70, 0x70,
        ])

        self._write_cmd(0x64)
        self._write_data([0x28, 0x29, 0xF1, 0x01, 0xF1, 0x00, 0x07])

        self._write_cmd(0x66)
        self._write_data([0x3C, 0x00, 0xCD, 0x67, 0x45, 0x45, 0x10, 0x00, 0x00, 0x00])

        self._write_cmd(0x67)
        self._write_data([0x00, 0x3C, 0x00, 0x00, 0x00, 0x01, 0x54, 0x10, 0x32, 0x98])

        self._write_cmd(0x74)
        self._write_data([0x10, 0x85, 0x80, 0x00, 0x00, 0x4E, 0x00])

        self._write_cmd(0x98)
        self._write_data([0x3E, 0x07])

        self._write_cmd(0x35)   # TEON
        self._write_cmd(0x21)   # INVON

        self._write_cmd(0x11)   # SLPOUT
        time.sleep(0.12)

        self._write_cmd(0x29)   # DISPON
        time.sleep(0.02)
