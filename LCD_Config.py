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

# ---------------------------------------------------------------------------
# Framebuffer display registry (panels driven via a Linux framebuffer, not SPI).
#   fb_name : substring of /sys/class/graphics/fbN/name used to locate the device
#   w/h/bpp : fallback geometry when sysfs geometry can't be read
# ---------------------------------------------------------------------------
_FB_PANELS = {
    "CARDPUTER_320":    {"fb_name": "st7789v_m5st", "w": 320, "h": 170, "bpp": 16},
    "WAVESHARE35A_480": {"fb_name": "fb_ili9486",   "w": 480, "h": 320, "bpp": 16},
}
_FRAMEBUFFER_TYPES = set(_FB_PANELS)

# Hardware auto-detect fallback: if the configured type isn't a framebuffer panel
# but a known one is physically present, switch to it (e.g. a leftover ST7735_128
# config on a board that actually has an ILI9486 / Cardputer panel wired up).
if _DISPLAY_TYPE not in _FRAMEBUFFER_TYPES:
    _found = None
    for _i in range(4):
        try:
            with open(f"/sys/class/graphics/fb{_i}/name", "r") as _fb:
                _nm = _fb.read()
        except Exception:
            continue
        for _dt, _spec in _FB_PANELS.items():
            if _spec["fb_name"] in _nm:
                _found = _dt
                break
        if _found:
            break
    if _found:
        _DISPLAY_TYPE = _found


if _DISPLAY_TYPE in _FRAMEBUFFER_TYPES:
    # ===================================================================
    # Framebuffer panels (CardputerZero, Waveshare 3.5" 35a / ILI9486):
    # render straight to a Linux framebuffer — no SPI, no display GPIO.
    # ===================================================================
    import mmap

    LCD_RST_PIN = -1
    LCD_DC_PIN = -1
    LCD_CS_PIN = -1
    LCD_BL_PIN = -1

    _panel = _FB_PANELS.get(
        _DISPLAY_TYPE, {"fb_name": "", "w": 320, "h": 170, "bpp": 16}
    )
    _panel_name = _panel["fb_name"]

    # Auto-detect framebuffer device: explicit override, else match by panel name.
    FB_DEVICE = os.environ.get("RJ_FB_DEVICE", "")
    if not FB_DEVICE:
        FB_DEVICE = "/dev/fb0"  # default fallback
        for _i in range(4):
            try:
                with open(f"/sys/class/graphics/fb{_i}/name") as _fn:
                    if _panel_name and _panel_name in _fn.read():
                        FB_DEVICE = f"/dev/fb{_i}"
                        break
            except Exception:
                pass

    def _fb_geometry(dev):
        """Read (width, height, bpp) from /sys for /dev/fbN, or None on failure."""
        base = "/sys/class/graphics/" + os.path.basename(dev)
        try:
            with open(base + "/virtual_size") as _f:
                _w, _h = (int(_x) for _x in _f.read().strip().split(","))
            with open(base + "/bits_per_pixel") as _f:
                _b = int(_f.read().strip())
            return _w, _h, _b
        except Exception:
            return None

    # Geometry priority: env override > kernel sysfs (ground truth) > registry.
    # Cardputer keeps its known-good hardcoded geometry to avoid any regression;
    # other framebuffer panels trust the kernel's reported size.
    _geo = _fb_geometry(FB_DEVICE) if _DISPLAY_TYPE != "CARDPUTER_320" else None
    FB_WIDTH  = int(os.environ.get("RJ_FB_WIDTH",  0)) or (_geo[0] if _geo else _panel["w"])
    FB_HEIGHT = int(os.environ.get("RJ_FB_HEIGHT", 0)) or (_geo[1] if _geo else _panel["h"])
    FB_BPP    = int(os.environ.get("RJ_FB_BPP",    0)) or (_geo[2] if _geo else _panel["bpp"])
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
