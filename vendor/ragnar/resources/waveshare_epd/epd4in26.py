# *****************************************************************************
# * | File        :	  epd4in26.py
# * | Author      :   Waveshare team
# * | Function    :   Electronic paper driver
# * | Info        :
# *----------------
# * | This version:   V1.0
# * | Date        :   2023-12-20
# # | Info        :   python demo
# -----------------------------------------------------------------------------
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documnetation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to  whom the Software is
# furished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS OR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

import logging
from . import epdconfig

# Display resolution
EPD_WIDTH       = 800
EPD_HEIGHT      = 480

logger = logging.getLogger(__name__)

class EPD:
    def __init__(self):
        self.is_initialized = False  # Track if the display has been initialized (Ragnar compatibility)
        self.reset_pin = epdconfig.RST_PIN
        self.dc_pin = epdconfig.DC_PIN
        self.busy_pin = epdconfig.BUSY_PIN
        self.cs_pin = epdconfig.CS_PIN
        self.width = EPD_WIDTH
        self.height = EPD_HEIGHT

    # Hardware reset
    def reset(self):
        epdconfig.digital_write(self.reset_pin, 1)
        epdconfig.delay_ms(20)
        epdconfig.digital_write(self.reset_pin, 0)
        epdconfig.delay_ms(2)
        epdconfig.digital_write(self.reset_pin, 1)
        epdconfig.delay_ms(20)

    def send_command(self, command):
        epdconfig.digital_write(self.dc_pin, 0)
        epdconfig.digital_write(self.cs_pin, 0)
        epdconfig.spi_writebyte([command])
        epdconfig.digital_write(self.cs_pin, 1)

    def send_data(self, data):
        epdconfig.digital_write(self.dc_pin, 1)
        epdconfig.digital_write(self.cs_pin, 0)
        epdconfig.spi_writebyte([data])
        epdconfig.digital_write(self.cs_pin, 1)

    def send_data2(self, data):
        epdconfig.digital_write(self.dc_pin, 1)
        epdconfig.digital_write(self.cs_pin, 0)
        epdconfig.SPI.writebytes2(data)
        epdconfig.digital_write(self.cs_pin, 1)

    def ReadBusy(self):
        logger.debug("e-Paper busy")
        busy = epdconfig.digital_read(self.busy_pin)
        while(busy == 1):
            busy = epdconfig.digital_read(self.busy_pin)
            epdconfig.delay_ms(20)
        epdconfig.delay_ms(20)
        logger.debug("e-Paper busy release")

    def TurnOnDisplay(self):
        self.send_command(0x22)  # Display Update Control
        self.send_data(0xF7)
        self.send_command(0x20)  # Activate Display Update Sequence
        self.ReadBusy()

    def TurnOnDisplay_Part(self):
        self.send_command(0x22)  # Display Update Control
        self.send_data(0xFF)
        self.send_command(0x20)  # Activate Display Update Sequence
        self.ReadBusy()

    def SetWindow(self, x_start, y_start, x_end, y_end):
        self.send_command(0x44)  # SET_RAM_X_ADDRESS_START_END_POSITION
        self.send_data(x_start & 0xFF)
        self.send_data((x_start >> 8) & 0x03)
        self.send_data(x_end & 0xFF)
        self.send_data((x_end >> 8) & 0x03)

        self.send_command(0x45)  # SET_RAM_Y_ADDRESS_START_END_POSITION
        self.send_data(y_start & 0xFF)
        self.send_data((y_start >> 8) & 0xFF)
        self.send_data(y_end & 0xFF)
        self.send_data((y_end >> 8) & 0xFF)

    def SetCursor(self, x, y):
        self.send_command(0x4E)  # SET_RAM_X_ADDRESS_COUNTER
        self.send_data(x & 0xFF)
        self.send_data((x >> 8) & 0x03)

        self.send_command(0x4F)  # SET_RAM_Y_ADDRESS_COUNTER
        self.send_data(y & 0xFF)
        self.send_data((y >> 8) & 0xFF)

    def init(self):
        if not self.is_initialized:
            if (epdconfig.module_init() != 0):
                return -1
            self.is_initialized = True

        # EPD hardware init start
        self.reset()
        self.ReadBusy()

        self.send_command(0x12)  # SWRESET
        self.ReadBusy()

        self.send_command(0x18)  # use the internal temperature sensor
        self.send_data(0x80)

        self.send_command(0x0C)  # set soft start
        self.send_data(0xAE)
        self.send_data(0xC7)
        self.send_data(0xC3)
        self.send_data(0xC0)
        self.send_data(0x80)

        self.send_command(0x01)  # drive output control
        self.send_data((self.height - 1) % 256)   # Y
        self.send_data((self.height - 1) // 256)   # Y
        self.send_data(0x02)

        self.send_command(0x3C)  # Border setting
        self.send_data(0x01)

        self.send_command(0x11)  # data entry mode
        self.send_data(0x01)    # X-mode  x+ y-

        self.SetWindow(0, self.height - 1, self.width - 1, 0)
        self.SetCursor(0, 0)
        self.ReadBusy()

        # EPD hardware init end
        return 0

    def getbuffer(self, image):
        buf = [0xFF] * (int(self.width / 8) * self.height)
        image_monocolor = image.convert('1')
        imwidth, imheight = image_monocolor.size
        pixels = image_monocolor.load()
        if imwidth == self.width and imheight == self.height:
            logger.debug("Horizontal")
            for y in range(imheight):
                for x in range(imwidth):
                    if pixels[x, y] == 0:
                        buf[int((x + y * self.width) / 8)] &= ~(0x80 >> (x % 8))
        elif imwidth == self.height and imheight == self.width:
            logger.debug("Vertical")
            for y in range(imheight):
                for x in range(imwidth):
                    newx = y
                    newy = self.height - x - 1
                    if pixels[x, y] == 0:
                        buf[int((newx + newy * self.width) / 8)] &= ~(0x80 >> (y % 8))
        return buf

    def display(self, image):
        self.send_command(0x24)
        self.send_data2(image)
        self.TurnOnDisplay()

    def display_Partial(self, Image):
        # Reset
        self.reset()

        self.send_command(0x18)  # BorderWavefrom
        self.send_data(0x80)

        self.send_command(0x3C)  # BorderWavefrom
        self.send_data(0x80)

        self.send_command(0x01)  # drive output control
        self.send_data((self.height - 1) % 256)   # Y
        self.send_data((self.height - 1) // 256)   # Y

        self.send_command(0x11)  # data entry mode
        self.send_data(0x01)    # X-mode  x+ y-

        self.SetWindow(0, self.height - 1, self.width - 1, 0)
        self.SetCursor(0, 0)

        self.send_command(0x24)  # Write Black and White image to RAM
        self.send_data2(Image)

        self.TurnOnDisplay_Part()

    def displayPartial(self, image):
        """Alias for display_Partial (Ragnar EPDHelper compatibility)."""
        self.display_Partial(image)

    def Clear(self, color=0xFF):
        self.send_command(0x24)
        self.send_data2([color] * (int(self.width / 8) * self.height))

        self.send_command(0x26)
        self.send_data2([color] * (int(self.width / 8) * self.height))

        self.TurnOnDisplay()

    def sleep(self):
        self.send_command(0x10)  # DEEP_SLEEP
        self.send_data(0x01)
        epdconfig.delay_ms(2000)
        epdconfig.module_exit()

### END OF FILE ###
