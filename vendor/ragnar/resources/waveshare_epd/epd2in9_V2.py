# *****************************************************************************
# * | File        :	  epd2in9_V2.py
# * | Author      :   Waveshare team
# * | Function    :   Electronic paper driver
# * | Info        :
# *----------------
# * | This version:   V1.1
# * | Date        :   2022-08-9
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
EPD_WIDTH       = 128
EPD_HEIGHT      = 296

logger = logging.getLogger(__name__)

WF_PARTIAL_2IN9 = [
    0x0,0x40,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x80,0x80,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x40,0x40,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x80,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x14,0x0,0x0,0x0,0x0,0x0,0x0,
    0x1,0x0,0x0,0x0,0x0,0x0,0x0,
    0x1,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x22,0x22,0x22,0x22,0x22,0x22,0x0,0x0,0x0,
    0x22,0x17,0x41,0x00,0x32,0x36,
]

WS_20_30 = [
    0x80,0x66,0x0,0x0,0x0,0x0,0x0,0x0,0x40,0x0,0x0,0x0,
    0x10,0x66,0x0,0x0,0x0,0x0,0x0,0x0,0x20,0x0,0x0,0x0,
    0x80,0x66,0x0,0x0,0x0,0x0,0x0,0x0,0x40,0x0,0x0,0x0,
    0x10,0x66,0x0,0x0,0x0,0x0,0x0,0x0,0x20,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x14,0x8,0x0,0x0,0x0,0x0,0x2,
    0xA,0xA,0x0,0xA,0xA,0x0,0x1,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x22,0x22,0x22,0x22,0x22,0x22,0x0,0x0,0x0,
    0x22,0x17,0x41,0x0,0x32,0x36,
]

WF_FULL = [
    0x90,0x66,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x60,0x66,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x90,0x66,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x60,0x66,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x16,0x8,0x0,0x0,0x0,0x0,0x2,
    0x8,0x8,0x0,0x8,0x8,0x0,0x1,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x22,0x22,0x22,0x22,0x22,0x22,0x0,0x0,0x0,
    0x22,0x17,0x41,0x0,0x32,0x36,
]

Gray4 = [
    0x00,0x60,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x20,0x60,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x28,0x60,0x14,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x60,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x18,0x04,0x04,0x08,0x04,0x04,0x02,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x22,0x22,0x22,0x22,0x22,0x22,0x00,0x00,0x00,
    0x22,0x17,0x41,0x00,0x32,0x36,
]

class EPD:
    def __init__(self):
        self.is_initialized = False  # Track if the display has been initialized #INFINITION
        self.reset_pin = epdconfig.RST_PIN
        self.dc_pin = epdconfig.DC_PIN
        self.busy_pin = epdconfig.BUSY_PIN
        self.cs_pin = epdconfig.CS_PIN
        self.width = EPD_WIDTH
        self.height = EPD_HEIGHT
        self.displayPartial = self.display_Partial  # Compatibility alias for EPDHelper

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

    # send a lot of data
    def send_data2(self, data):
        epdconfig.digital_write(self.dc_pin, 1)
        epdconfig.digital_write(self.cs_pin, 0)
        epdconfig.spi_writebyte2(data)
        epdconfig.digital_write(self.cs_pin, 1)

    def ReadBusy(self):
        logger.debug("e-Paper busy")
        while(epdconfig.digital_read(self.busy_pin) == 1):      # 0: idle, 1: busy
            epdconfig.delay_ms(10)
        logger.debug("e-Paper busy release")

    def TurnOnDisplay(self):
        self.send_command(0x22) # Display Update Control
        self.send_data(0xF7)
        self.send_command(0x20) # Activate Display Update Sequence
        self.ReadBusy()

    def TurnOnDisplay_Partial(self):
        self.send_command(0x22) # Display Update Control
        self.send_data(0xFF)
        self.send_command(0x20) # Activate Display Update Sequence
        self.ReadBusy()

    def lut(self, lut):
        self.send_command(0x32)
        for i in range(153):
            self.send_data(lut[i])
        self.ReadBusy()

    def SetLut(self, lut):
        self.lut(lut)
        self.send_command(0x3F)
        self.send_data(lut[153])
        self.send_command(0x03)     # gate voltage
        self.send_data(lut[154])
        self.send_command(0x04)     # source voltage
        self.send_data(lut[155])    # VSH
        self.send_data(lut[156])    # VSH2
        self.send_data(lut[157])    # VSL
        self.send_command(0x2C)     # VCOM
        self.send_data(lut[158])

    def SetWindow(self, x_start, y_start, x_end, y_end):
        self.send_command(0x44) # SET_RAM_X_ADDRESS_START_END_POSITION
        # x point must be the multiple of 8 or the last 3 bits will be ignored
        self.send_data((x_start >> 3) & 0xFF)
        self.send_data((x_end >> 3) & 0xFF)

        self.send_command(0x45) # SET_RAM_Y_ADDRESS_START_END_POSITION
        self.send_data(y_start & 0xFF)
        self.send_data((y_start >> 8) & 0xFF)
        self.send_data(y_end & 0xFF)
        self.send_data((y_end >> 8) & 0xFF)

    def SetCursor(self, x, y):
        self.send_command(0x4E) # SET_RAM_X_ADDRESS_COUNTER
        self.send_data(x & 0xFF)

        self.send_command(0x4F) # SET_RAM_Y_ADDRESS_COUNTER
        self.send_data(y & 0xFF)
        self.send_data((y >> 8) & 0xFF)

    def init(self):
        if not self.is_initialized:  # Avoid repeated initialization and accumulation of File descriptors #INFINITION
            if (epdconfig.module_init() != 0):
                return -1
            self.reset()
            self.is_initialized = True

        self.ReadBusy()
        self.send_command(0x12)  # SWRESET
        self.ReadBusy()

        self.send_command(0x01) # Driver output control
        self.send_data(0x27)
        self.send_data(0x01)
        self.send_data(0x00)

        self.send_command(0x11) # data entry mode
        self.send_data(0x03)

        self.SetWindow(0, 0, self.width - 1, self.height - 1)
        self.SetCursor(0, 0)

        self.send_command(0x21) # Display update control
        self.send_data(0x00)
        self.send_data(0x80)

        self.send_command(0x18)
        self.send_data(0x80)

        self.ReadBusy()

        self.SetLut(WF_FULL)
        return 0

    def init_Gray4(self):
        if (epdconfig.module_init() != 0):
            return -1
        self.reset()

        self.ReadBusy()
        self.send_command(0x12)  # SWRESET
        self.ReadBusy()

        self.send_command(0x01) # Driver output control
        self.send_data(0x27)
        self.send_data(0x01)
        self.send_data(0x00)

        self.send_command(0x11) # data entry mode
        self.send_data(0x03)

        self.SetWindow(0, 0, self.width - 1, self.height - 1)
        self.SetCursor(0, 0)

        self.send_command(0x3C) # BorderWaveform
        self.send_data(0x01)

        self.send_command(0x18)
        self.send_data(0x80)

        self.ReadBusy()

        self.SetLut(Gray4)
        return 0

    def getbuffer(self, image):
        img = image
        imwidth, imheight = img.size
        if(imwidth == self.width and imheight == self.height):
            img = img.convert('1')
        elif(imwidth == self.height and imheight == self.width):
            img = img.rotate(90, expand=True).convert('1')
        else:
            logger.warning("Wrong image dimensions: must be " + str(self.width) + "x" + str(self.height))
            return [0x00] * (int(self.width / 8) * self.height)

        buf = bytearray(img.tobytes('raw'))
        return buf

    def display(self, image):
        self.send_command(0x24)
        self.send_data2(image)
        self.TurnOnDisplay()

    def display_Base(self, image):
        self.send_command(0x24)
        self.send_data2(image)

        self.send_command(0x26)
        self.send_data2(image)
        self.TurnOnDisplay()

    def display_Base_color(self, color):
        if self.width % 8 == 0:
            linewidth = int(self.width / 8)
        else:
            linewidth = int(self.width / 8) + 1

        self.send_command(0x24)
        self.send_data2([color] * int(self.height * linewidth))

        self.send_command(0x26)
        self.send_data2([color] * int(self.height * linewidth))
        self.TurnOnDisplay()

    def display_Partial(self, image):
        epdconfig.digital_write(self.reset_pin, 0)
        epdconfig.delay_ms(1)
        epdconfig.digital_write(self.reset_pin, 1)

        self.SetLut(WF_PARTIAL_2IN9)
        self.send_command(0x37)
        self.send_data(0x00)
        self.send_data(0x00)
        self.send_data(0x00)
        self.send_data(0x00)
        self.send_data(0x00)
        self.send_data(0x40)
        self.send_data(0x00)
        self.send_data(0x00)
        self.send_data(0x00)
        self.send_data(0x00)

        self.send_command(0x3C) # BorderWaveform
        self.send_data(0x80)

        self.send_command(0x22)
        self.send_data(0xC0)
        self.send_command(0x20)
        self.ReadBusy()

        self.SetWindow(0, 0, self.width - 1, self.height - 1)
        self.SetCursor(0, 0)

        self.send_command(0x24) # WRITE_RAM
        self.send_data2(image)
        self.TurnOnDisplay_Partial()

    def display_4Gray(self, image):
        self.send_command(0x24)
        for i in range(0, 4736):
            temp3 = 0
            for j in range(0, 2):
                temp1 = image[i * 2 + j]
                for k in range(0, 2):
                    temp2 = temp1 & 0xC0
                    if(temp2 == 0xC0):
                        temp3 |= 0x01  # white
                    elif(temp2 == 0x00):
                        temp3 &= 0xFE  # black
                    elif(temp2 == 0x80):
                        temp3 &= 0xFE  # gray1
                    else:  # 0x40
                        temp3 |= 0x01  # gray2
                    temp3 <<= 1

                    temp1 <<= 2
                    temp2 = temp1 & 0xC0
                    if(temp2 == 0xC0):
                        temp3 |= 0x01  # white
                    elif(temp2 == 0x00):
                        temp3 &= 0xFE  # black
                    elif(temp2 == 0x80):
                        temp3 &= 0xFE  # gray1
                    else:  # 0x40
                        temp3 |= 0x01  # gray2
                    if(j != 1 or k != 1):
                        temp3 <<= 1
                    temp1 <<= 2
            self.send_data(temp3)

        self.send_command(0x26)
        for i in range(0, 4736):
            temp3 = 0
            for j in range(0, 2):
                temp1 = image[i * 2 + j]
                for k in range(0, 2):
                    temp2 = temp1 & 0xC0
                    if(temp2 == 0xC0):
                        temp3 |= 0x01  # white
                    elif(temp2 == 0x00):
                        temp3 &= 0xFE  # black
                    elif(temp2 == 0x80):
                        temp3 |= 0x01  # gray1
                    else:  # 0x40
                        temp3 &= 0xFE  # gray2
                    temp3 <<= 1

                    temp1 <<= 2
                    temp2 = temp1 & 0xC0
                    if(temp2 == 0xC0):
                        temp3 |= 0x01  # white
                    elif(temp2 == 0x00):
                        temp3 &= 0xFE  # black
                    elif(temp2 == 0x80):
                        temp3 |= 0x01  # gray1
                    else:  # 0x40
                        temp3 &= 0xFE  # gray2
                    if(j != 1 or k != 1):
                        temp3 <<= 1
                    temp1 <<= 2
            self.send_data(temp3)

        self.TurnOnDisplay()

    def Clear(self, color=0xFF):
        if self.width % 8 == 0:
            linewidth = int(self.width / 8)
        else:
            linewidth = int(self.width / 8) + 1

        self.send_command(0x24)
        self.send_data2([color] * int(self.height * linewidth))
        self.TurnOnDisplay()

    def sleep(self):
        self.send_command(0x10) # enter deep sleep
        self.send_data(0x01)

        epdconfig.delay_ms(2000)
        epdconfig.module_exit()

### END OF FILE ###
