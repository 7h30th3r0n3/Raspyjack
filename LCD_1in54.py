# -*- coding:UTF-8 -*-
# 1.54" Spotpear ST7789 driver implementation for RaspyJack
# Assumes SPI0 (MOSI=10, MISO=9, SCLK=11, CS=8), RST=27, DC=22, BL=24

import os
import time
import numpy as np
import RPi.GPIO as GPIO
import LCD_Config

LCD_1IN54 = 1
LCD_WIDTH = 240
LCD_HEIGHT = 240
LCD_X = 0
LCD_Y = 0
LCD_X_MAXPIXEL = 240
LCD_Y_MAXPIXEL = 240

# WebUI frame mirror (same as LCD_1in44)
_FRAME_MIRROR_PATH = os.environ.get("RJ_FRAME_PATH", "/dev/shm/raspyjack_last.jpg")
_FRAME_MIRROR_ENABLED = os.environ.get("RJ_FRAME_MIRROR", "1") != "0"
try:
    _frame_fps = float(os.environ.get("RJ_FRAME_FPS", "10"))
    _FRAME_MIRROR_INTERVAL = 1.0 / max(1.0, _frame_fps)
except Exception:
    _FRAME_MIRROR_INTERVAL = 0.1
_last_frame_save = 0.0

# Scan modes (same as LCD_1in44)
L2R_U2D = 1
L2R_D2U = 2
R2L_U2D = 3
R2L_D2U = 4
U2D_L2R = 5
U2D_R2L = 6
D2U_L2R = 7
D2U_R2L = 8
SCAN_DIR_DFT = U2D_R2L


class LCD:
    def __init__(self):
        self.width = LCD_WIDTH
        self.height = LCD_HEIGHT
        self.LCD_Scan_Dir = SCAN_DIR_DFT
        self.LCD_X_Adjust = LCD_X
        self.LCD_Y_Adjust = LCD_Y

    def LCD_Reset(self):
        GPIO.output(LCD_Config.LCD_RST_PIN, GPIO.HIGH)
        LCD_Config.Driver_Delay_ms(100)
        GPIO.output(LCD_Config.LCD_RST_PIN, GPIO.LOW)
        LCD_Config.Driver_Delay_ms(100)
        GPIO.output(LCD_Config.LCD_RST_PIN, GPIO.HIGH)
        LCD_Config.Driver_Delay_ms(100)

    def LCD_WriteReg(self, Reg):
        GPIO.output(LCD_Config.LCD_DC_PIN, GPIO.LOW)
        LCD_Config.SPI_Write_Byte([Reg])

    def LCD_WriteData_8bit(self, Data):
        GPIO.output(LCD_Config.LCD_DC_PIN, GPIO.HIGH)
        LCD_Config.SPI_Write_Byte([Data])

    def LCD_WriteData_NLen16Bit(self, Data, DataLen):
        GPIO.output(LCD_Config.LCD_DC_PIN, GPIO.HIGH)
        for i in range(DataLen):
            LCD_Config.SPI_Write_Byte([Data >> 8])
            LCD_Config.SPI_Write_Byte([Data & 0xFF])

    def LCD_InitReg(self):
        self.LCD_WriteReg(0x36)
        self.LCD_WriteData_8bit(0x00)  # MX, MY, RGB

        self.LCD_WriteReg(0x3A)
        self.LCD_WriteData_8bit(0x05)  # 16-bit color

        self.LCD_WriteReg(0xB2)
        self.LCD_WriteData_8bit(0x0C)
        self.LCD_WriteData_8bit(0x0C)
        self.LCD_WriteData_8bit(0x00)
        self.LCD_WriteData_8bit(0x33)
        self.LCD_WriteData_8bit(0x33)

        self.LCD_WriteReg(0xB7)
        self.LCD_WriteData_8bit(0x35)

        self.LCD_WriteReg(0xBB)
        self.LCD_WriteData_8bit(0x19)

        self.LCD_WriteReg(0xC0)
        self.LCD_WriteData_8bit(0x2C)

        self.LCD_WriteReg(0xC2)
        self.LCD_WriteData_8bit(0x01)

        self.LCD_WriteReg(0xC3)
        self.LCD_WriteData_8bit(0x12)

        self.LCD_WriteReg(0xC4)
        self.LCD_WriteData_8bit(0x20)

        self.LCD_WriteReg(0xC6)
        self.LCD_WriteData_8bit(0x0F)

        self.LCD_WriteReg(0xD0)
        self.LCD_WriteData_8bit(0xA4)
        self.LCD_WriteData_8bit(0xA1)

        self.LCD_WriteReg(0xE0)
        self.LCD_WriteData_8bit(0xD0)
        self.LCD_WriteData_8bit(0x04)
        self.LCD_WriteData_8bit(0x0D)
        self.LCD_WriteData_8bit(0x11)
        self.LCD_WriteData_8bit(0x13)
        self.LCD_WriteData_8bit(0x2B)
        self.LCD_WriteData_8bit(0x3F)
        self.LCD_WriteData_8bit(0x54)
        self.LCD_WriteData_8bit(0x4C)
        self.LCD_WriteData_8bit(0x18)
        self.LCD_WriteData_8bit(0x0D)
        self.LCD_WriteData_8bit(0x0B)
        self.LCD_WriteData_8bit(0x1F)
        self.LCD_WriteData_8bit(0x23)

        self.LCD_WriteReg(0xE1)
        self.LCD_WriteData_8bit(0xD0)
        self.LCD_WriteData_8bit(0x04)
        self.LCD_WriteData_8bit(0x0C)
        self.LCD_WriteData_8bit(0x11)
        self.LCD_WriteData_8bit(0x13)
        self.LCD_WriteData_8bit(0x2C)
        self.LCD_WriteData_8bit(0x3F)
        self.LCD_WriteData_8bit(0x44)
        self.LCD_WriteData_8bit(0x51)
        self.LCD_WriteData_8bit(0x2F)
        self.LCD_WriteData_8bit(0x1F)
        self.LCD_WriteData_8bit(0x1F)
        self.LCD_WriteData_8bit(0x20)
        self.LCD_WriteData_8bit(0x23)

    def LCD_SetGramScanWay(self, Scan_dir):
        self.LCD_Scan_Dir = Scan_dir
        if Scan_dir in (L2R_U2D, L2R_D2U, R2L_U2D, R2L_D2U):
            self.width = LCD_HEIGHT
            self.height = LCD_WIDTH
            if Scan_dir == L2R_U2D:
                MemoryAccessReg_Data = 0x00
            elif Scan_dir == L2R_D2U:
                MemoryAccessReg_Data = 0x80
            elif Scan_dir == R2L_U2D:
                MemoryAccessReg_Data = 0x40
            else:
                MemoryAccessReg_Data = 0xC0
        else:
            self.width = LCD_WIDTH
            self.height = LCD_HEIGHT
            if Scan_dir == U2D_L2R:
                MemoryAccessReg_Data = 0x00 | 0x00 | 0x20
            elif Scan_dir == U2D_R2L:
                MemoryAccessReg_Data = 0x40 | 0x00 | 0x20
            elif Scan_dir == D2U_L2R:
                MemoryAccessReg_Data = 0x80 | 0x00 | 0x20
            else:
                MemoryAccessReg_Data = 0xC0 | 0x20

        self.LCD_X_Adjust = LCD_X
        self.LCD_Y_Adjust = LCD_Y

        self.LCD_WriteReg(0x36)
        self.LCD_WriteData_8bit(MemoryAccessReg_Data | 0x08)

    def LCD_Init(self, Lcd_ScanDir):
        if LCD_Config.GPIO_Init() != 0:
            return -1

        GPIO.output(LCD_Config.LCD_BL_PIN, GPIO.HIGH)
        self.LCD_Reset()
        self.LCD_InitReg()
        self.LCD_SetGramScanWay(Lcd_ScanDir)
        LCD_Config.Driver_Delay_ms(200)

        self.LCD_WriteReg(0x11)
        LCD_Config.Driver_Delay_ms(120)

        self.LCD_WriteReg(0x29)

    def LCD_SetWindows(self, Xstart, Ystart, Xend, Yend):
        # ST7789 uses 16-bit coordinates
        x0 = Xstart + self.LCD_X_Adjust
        y0 = Ystart + self.LCD_Y_Adjust
        x1 = Xend - 1 + self.LCD_X_Adjust
        y1 = Yend - 1 + self.LCD_Y_Adjust

        self.LCD_WriteReg(0x2A)
        self.LCD_WriteData_8bit((x0 >> 8) & 0xFF)
        self.LCD_WriteData_8bit(x0 & 0xFF)
        self.LCD_WriteData_8bit((x1 >> 8) & 0xFF)
        self.LCD_WriteData_8bit(x1 & 0xFF)

        self.LCD_WriteReg(0x2B)
        self.LCD_WriteData_8bit((y0 >> 8) & 0xFF)
        self.LCD_WriteData_8bit(y0 & 0xFF)
        self.LCD_WriteData_8bit((y1 >> 8) & 0xFF)
        self.LCD_WriteData_8bit(y1 & 0xFF)

        self.LCD_WriteReg(0x2C)

    def LCD_Clear(self):
        _buffer = [0xFF] * (self.width * self.height * 2)
        self.LCD_SetWindows(0, 0, self.width, self.height)
        GPIO.output(LCD_Config.LCD_DC_PIN, GPIO.HIGH)
        for i in range(0, len(_buffer), 4096):
            LCD_Config.SPI_Write_Byte(_buffer[i:i+4096])

    def LCD_ShowImage(self, Image, Xstart, Ystart):
        if Image is None:
            return
        imwidth, imheight = Image.size
        if imwidth != self.width or imheight != self.height:
            raise ValueError('Image must be same dimensions as display ({0}x{1}).'.format(self.width, self.height))
        img = np.asarray(Image)
        pix = np.zeros((self.width, self.height, 2), dtype=np.uint8)
        pix[..., [0]] = np.add(np.bitwise_and(img[..., [0]], 0xF8), np.right_shift(img[..., [1]], 5))
        pix[..., [1]] = np.add(np.bitwise_and(np.left_shift(img[..., [1]], 3), 0xE0), np.right_shift(img[..., [2]], 3))
        pix = pix.flatten().tolist()

        self.LCD_SetWindows(0, 0, self.width, self.height)
        GPIO.output(LCD_Config.LCD_DC_PIN, GPIO.HIGH)
        for i in range(0, len(pix), 4096):
            LCD_Config.SPI_Write_Byte(pix[i:i+4096])

        if _FRAME_MIRROR_ENABLED:
            global _last_frame_save
            try:
                now = time.monotonic()
                if (now - _last_frame_save) >= _FRAME_MIRROR_INTERVAL:
                    Image.save(_FRAME_MIRROR_PATH, "JPEG", quality=80)
                    _last_frame_save = now
            except Exception:
                pass
