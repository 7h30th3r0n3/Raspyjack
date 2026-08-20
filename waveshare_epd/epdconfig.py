##
# @filename   :   epdconfig.py
# @brief      :   Waveshare e-Paper HAT low-level SPI/GPIO interface (Raspberry Pi only)
# @author     :   Waveshare team (original), adapted for Raspyjack to use RPi.GPIO
#                  instead of gpiozero, matching LCD_Config.py's existing convention.
#
# Adapted from vendor/ragnar/resources/waveshare_epd/epdconfig.py. Only the
# RaspberryPi backend is kept; Jetson/SunriseX3 branches were dropped since
# Raspyjack only targets a Raspberry Pi.
##

import time

import spidev
import RPi.GPIO as GPIO

# Pin definition (BCM numbering)
RST_PIN = 17
DC_PIN = 25
CS_PIN = 8
BUSY_PIN = 24
PWR_PIN = 18

SPI = spidev.SpiDev()

_initialized = False


def digital_write(pin, value):
    GPIO.output(pin, value)


def digital_read(pin):
    return GPIO.input(pin)


def delay_ms(delaytime):
    time.sleep(delaytime / 1000.0)


def spi_writebyte(data):
    SPI.writebytes(data)


def spi_writebyte2(data):
    SPI.writebytes2(data)


def module_init(cleanup=False):
    global _initialized
    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)
    GPIO.setup(RST_PIN, GPIO.OUT)
    GPIO.setup(DC_PIN, GPIO.OUT)
    GPIO.setup(PWR_PIN, GPIO.OUT)
    GPIO.setup(BUSY_PIN, GPIO.IN)

    GPIO.output(PWR_PIN, 1)

    if not _initialized:
        SPI.open(0, 0)
        SPI.max_speed_hz = 4000000
        SPI.mode = 0b00
        _initialized = True
    return 0


def module_exit(cleanup=False):
    global _initialized
    SPI.close()
    _initialized = False

    GPIO.output(RST_PIN, 0)
    GPIO.output(DC_PIN, 0)
    GPIO.output(PWR_PIN, 0)

    if cleanup:
        GPIO.cleanup([RST_PIN, DC_PIN, PWR_PIN, BUSY_PIN])

### END OF FILE ###
