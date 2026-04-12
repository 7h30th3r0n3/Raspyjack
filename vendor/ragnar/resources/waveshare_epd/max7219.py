#!/usr/bin/env python3
"""
MAX7219 LED Matrix driver for Ragnar.

Supports 4-panel (32×8) and 8-panel (64×8) cascaded MAX7219 modules.

Wiring (Raspberry Pi SPI0):
  VCC → 5V      (Pin 2)
  GND → GND     (Pin 6)
  DIN → GPIO10  (Pin 19) — MOSI
  CS  → GPIO8   (Pin 24) — CE0
  CLK → GPIO11  (Pin 23) — SCLK

Dependencies:
  pip3 install luma.led_matrix luma.core
"""

import logging
import time

logger = logging.getLogger(__name__)

try:
    from luma.led_matrix.device import max7219 as _max7219_dev
    from luma.core.interface.serial import spi as _spi, noop as _noop
    from PIL import Image as _Image
    _LUMA_AVAILABLE = True
except ImportError:
    _LUMA_AVAILABLE = False
    logger.warning("luma.led_matrix not available — install with: pip3 install luma.led_matrix")


class EPD:
    """MAX7219 cascaded LED matrix — EPD-compatible interface."""

    def __init__(self, cascaded=8, spi_port=0, spi_device=0, brightness=8, block_orientation=-90):
        self.cascaded = cascaded
        self.spi_port = spi_port
        self.spi_device = spi_device
        self._brightness = max(0, min(15, brightness))
        self.block_orientation = block_orientation
        self.width  = cascaded * 8   # 32 or 64
        self.height = 8
        self._device = None

    # ------------------------------------------------------------------
    # Public interface (mirrors waveshare EPD drivers)
    # ------------------------------------------------------------------

    def init(self):
        if not _LUMA_AVAILABLE:
            raise RuntimeError("luma.led_matrix is required for MAX7219. Install: pip3 install luma.led_matrix")
        serial = _spi(port=self.spi_port, device=self.spi_device, gpio=_noop())
        self._device = _max7219_dev(
            serial,
            cascaded=self.cascaded,
            block_orientation=self.block_orientation,
            rotate=0,
            blocks_arranged_in_reverse_order=False,
        )
        # luma contrast is 0–255; map from 0–15
        self._device.contrast(self._brightness * 17)
        # Force-clear the display — MAX7219 powers on with all pixels lit
        self._device.clear()
        logger.info(f"MAX7219 initialised ({self.width}×{self.height}) cascaded={self.cascaded} brightness={self._brightness}")

    def Clear(self):
        if self._device:
            self._device.clear()

    def contrast(self, value: int):
        """Set brightness. Accepts 0–255 (will be clamped to 0–15 steps)."""
        if self._device:
            self._brightness = max(0, min(15, value // 17))
            self._device.contrast(self._brightness * 17)

    def getbuffer(self, image):
        """Convert a PIL Image (mode '1' or 'L') to a display buffer (the image itself)."""
        if image.size != (self.width, self.height):
            image = image.resize((self.width, self.height))
        return image.convert("1")

    def display(self, buf):
        """Push a PIL Image (or getbuffer result) to the MAX7219 panels."""
        if not self._device:
            return
        self._device.display(buf)

    def displayPartial(self, buf):
        self.display(buf)

    def sleep(self):
        if self._device:
            self._device.contrast(0)  # dim to zero as sleep proxy
