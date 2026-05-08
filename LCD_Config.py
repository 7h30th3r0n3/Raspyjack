##
 #  @filename   :   DEV_Config.py
 #  @brief      :   LCD hardware interface implements (GPIO, SPI)
 #                   Supports: SPI displays (ST7735, ST7789) + CardputerZero framebuffer
 #  @author     :   Yehui from Waveshare (original), 7h30th3r0n3 (CardputerZero)
 #
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

import os
import time

# ---------------------------------------------------------------------------
# Display type detection from gui_conf.json
# ---------------------------------------------------------------------------
_DISPLAY_TYPE = "ST7735_128"
try:
    import json as _json
    for _p in [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "gui_conf.json"),
        "/root/Raspyjack/gui_conf.json",
    ]:
        if os.path.isfile(_p):
            with open(_p, "r") as _f:
                _DISPLAY_TYPE = _json.load(_f).get("DISPLAY", {}).get("type", _DISPLAY_TYPE)
            break
except Exception:
    pass

# Hardware auto-detect fallback: if gui_conf.json says ST7735 but we're on a CardputerZero
if _DISPLAY_TYPE != "CARDPUTER_320":
    try:
        with open("/sys/class/graphics/fb0/name", "r") as _fb:
            if "st7789v_m5st" in _fb.read():
                _DISPLAY_TYPE = "CARDPUTER_320"
    except Exception:
        pass


if _DISPLAY_TYPE == "CARDPUTER_320":
    # ===================================================================
    # CardputerZero: framebuffer stub (no SPI, no GPIO for display)
    # ===================================================================
    import mmap

    LCD_RST_PIN = -1
    LCD_DC_PIN = -1
    LCD_CS_PIN = -1
    LCD_BL_PIN = -1

    FB_DEVICE = os.environ.get("RJ_FB_DEVICE", "/dev/fb0")
    FB_WIDTH = 320
    FB_HEIGHT = 170
    FB_BPP = 16
    FB_SIZE = FB_WIDTH * FB_HEIGHT * (FB_BPP // 8)

    _fb_fd = None
    _fb_mmap = None

    class _SpiStub:
        max_speed_hz = 0
        mode = 0
        def writebytes(self, data):
            pass

    SPI = _SpiStub()

    def _open_fb():
        global _fb_fd, _fb_mmap
        if _fb_mmap is not None:
            return _fb_mmap
        _fb_fd = os.open(FB_DEVICE, os.O_RDWR)
        _fb_mmap = mmap.mmap(
            _fb_fd, FB_SIZE, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ
        )
        return _fb_mmap

    def fb_write(data: bytes):
        fb = _open_fb()
        fb.seek(0)
        fb.write(data)

    def epd_digital_write(pin, value):
        pass

    def Driver_Delay_ms(xms):
        pass

    def SPI_Write_Byte(data):
        pass

    def GPIO_Init():
        _open_fb()
        return 0

else:
    # ===================================================================
    # Standard Raspberry Pi: SPI + GPIO for Waveshare HAT displays
    # ===================================================================
    import spidev
    import RPi.GPIO as GPIO

    LCD_RST_PIN = 27
    LCD_DC_PIN = 25
    LCD_CS_PIN = 8
    LCD_BL_PIN = 24

    SPI = spidev.SpiDev(0, 0)

    def epd_digital_write(pin, value):
        GPIO.output(pin, value)

    def Driver_Delay_ms(xms):
        time.sleep(xms / 1000.0)

    def SPI_Write_Byte(data):
        SPI.writebytes(data)

    def GPIO_Init():
        GPIO.setmode(GPIO.BCM)
        GPIO.setwarnings(False)
        GPIO.setup(LCD_RST_PIN, GPIO.OUT)
        GPIO.setup(LCD_DC_PIN, GPIO.OUT)
        GPIO.setup(LCD_CS_PIN, GPIO.OUT)
        GPIO.setup(LCD_BL_PIN, GPIO.OUT)
        SPI.max_speed_hz = 9000000
        SPI.mode = 0b00
        return 0

### END OF FILE ###
