#!/usr/bin/env python3
"""
RaspyJack Payload -- I2C Bus Scanner
=====================================
Author: 7h30th3r0n3

Probes all 127 I2C addresses on bus 1 using smbus2.

Setup / Prerequisites:
  - Requires I2C enabled (dtparam=i2c_arm=on in config.txt).
  - Scans /dev/i2c-1.  Identifies responding
devices by matching against a built-in database of common I2C addresses
(OLED displays, sensors, EEPROMs, RTCs, etc.).

Controls:
  OK         -- Start scan
  UP / DOWN  -- Scroll device list
  KEY1       -- Read first 16 register bytes from selected device
  KEY2       -- Export results to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/I2CScan/scan_YYYYMMDD_HHMMSS.json
Requires: smbus2
"""

import os
import sys
import json
import time
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

try:
    import smbus2
    SMBUS_OK = True
except ImportError:
    SMBUS_OK = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROWS_VISIBLE = 6
ROW_H = 12

I2C_BUS = 1
LOOT_DIR = "/root/Raspyjack/loot/I2CScan"

# Built-in I2C address database (hex address -> description)
I2C_DEVICES = {
    0x0E: "MAG3110 Magnetometer",
    0x0F: "MAG3110 Magnetometer",
    0x10: "VEML7700 Light",
    0x11: "Si4713 FM TX",
    0x13: "VCNL40x0 Proximity",
    0x18: "MCP9808 Temp / LIS3DH",
    0x19: "LIS3DH Accel",
    0x1A: "AC101 Audio",
    0x1C: "MMA8452Q Accel / FXOS",
    0x1D: "ADXL345 / MMA845x",
    0x1E: "HMC5883L Compass / LSM303",
    0x20: "PCF8574 I/O Expander",
    0x21: "PCF8574 I/O Expander",
    0x22: "PCF8574 I/O Expander",
    0x23: "BH1750 Light Sensor",
    0x24: "PCF8574 I/O Expander",
    0x25: "PCF8574 I/O Expander",
    0x26: "PCF8574 I/O Expander",
    0x27: "PCF8574 LCD / I/O Exp",
    0x28: "BNO055 IMU / CAP1188",
    0x29: "VL53L0X / TSL2591 / TCS",
    0x2A: "CAP1188 Touch",
    0x38: "AHT20 Temp/Hum / FT6x06",
    0x39: "TSL2561 / APDS-9960",
    0x3C: "SSD1306 OLED 128x64",
    0x3D: "SSD1306 OLED 128x64",
    0x3E: "SSD1306 OLED (alt)",
    0x40: "INA219 / HTU21D / HDC1080",
    0x41: "INA219 Power Monitor",
    0x44: "SHT31 Temp/Hum",
    0x45: "SHT31 Temp/Hum",
    0x48: "ADS1115 ADC / TMP102",
    0x49: "ADS1115 ADC / TMP102",
    0x4A: "ADS1115 ADC / MAX44009",
    0x4B: "ADS1115 ADC",
    0x50: "AT24C32 EEPROM",
    0x51: "AT24C32 EEPROM",
    0x52: "Nunchuk / EEPROM",
    0x53: "ADXL345 Accel / EEPROM",
    0x54: "EEPROM",
    0x55: "EEPROM / MAX17048",
    0x56: "EEPROM",
    0x57: "EEPROM / MAX3010x",
    0x58: "TPA2016 Audio Amp",
    0x5A: "MLX90614 IR Temp / MPR121",
    0x5B: "MPR121 Touch / CCS811",
    0x5C: "AM2315 / BH1750 (alt)",
    0x60: "MCP4725 DAC / Si5351",
    0x61: "MCP4725 DAC / Si5351",
    0x62: "SCD40 CO2",
    0x68: "DS1307 RTC / MPU6050 IMU",
    0x69: "MPU6050 / ITG3200",
    0x6A: "LSM6DS Accel/Gyro",
    0x6B: "LSM6DS Accel/Gyro",
    0x70: "HT16K33 LED Matrix",
    0x71: "HT16K33 LED Matrix",
    0x76: "BME280 / BMP280 / MS5611",
    0x77: "BME280 / BMP180 / MS5611",
    0x78: "SSD1306 OLED (7-bit alt)",
}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
scanning = False
scroll = 0
selected = 0
status_msg = "Ready"
progress = 0.0

# Found devices: [{"addr": int, "hex": str, "desc": str}]
found_devices = []

# Register dump for selected device
reg_dump = ""

# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

def _scan_thread():
    """Scan all I2C addresses on the bus."""
    global scanning, progress, status_msg, found_devices

    results = []
    try:
        bus = smbus2.SMBus(I2C_BUS)
    except Exception as exc:
        with lock:
            status_msg = f"Bus err: {str(exc)[:16]}"
            scanning = False
        return

    for addr in range(0x03, 0x78):
        if not _running:
            break
        try:
            bus.read_byte(addr)
            desc = I2C_DEVICES.get(addr, "Unknown device")
            results.append({
                "addr": addr,
                "hex": f"0x{addr:02X}",
                "desc": desc,
            })
        except Exception:
            pass

        with lock:
            progress = (addr - 0x03) / (0x77 - 0x03)

    try:
        bus.close()
    except Exception:
        pass

    with lock:
        found_devices = results
        progress = 1.0
        scanning = False
        status_msg = f"Found {len(results)} device(s)"


def _read_registers(addr, count=16):
    """Read first N registers from a device."""
    try:
        bus = smbus2.SMBus(I2C_BUS)
        values = []
        for reg in range(count):
            try:
                val = bus.read_byte_data(addr, reg)
                values.append(f"{val:02X}")
            except Exception:
                values.append("--")
        bus.close()
        return " ".join(values)
    except Exception as exc:
        return f"Error: {str(exc)[:20]}"

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_loot():
    """Write scan results to JSON loot file."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{ts}.json"
    filepath = os.path.join(LOOT_DIR, filename)

    with lock:
        data = {
            "timestamp": ts,
            "bus": I2C_BUS,
            "devices_found": len(found_devices),
            "devices": list(found_devices),
        }

    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)

    return filename

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_frame(lcd, font_obj):
    """Render current state to the LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "I2C SCANNER", font=font_obj, fill="#00CCFF")
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if scanning else "#444")

    with lock:
        msg = status_msg
        devices = list(found_devices)
        prog = progress
        dump = reg_dump
        sel = selected

    if scanning:
        # Progress bar
        d.text((2, 16), "Scanning bus 1...", font=font_obj, fill="#FFAA00")
        bar_x, bar_y, bar_w, bar_h = 4, 30, 120, 8
        d.rectangle((bar_x, bar_y, bar_x + bar_w, bar_y + bar_h), outline="#444")
        fill_w = int(prog * (bar_w - 2))
        if fill_w > 0:
            d.rectangle(
                (bar_x + 1, bar_y + 1, bar_x + 1 + fill_w, bar_y + bar_h - 1),
                fill="#00CCFF",
            )
        pct = int(prog * 100)
        d.text((2, 42), f"{pct}%", font=font_obj, fill="#888")
    elif dump:
        # Register dump view
        d.text((2, 16), "Register dump:", font=font_obj, fill="#FFAA00")
        # Split dump into lines of ~24 chars
        for i in range(0, len(dump), 24):
            y = 28 + (i // 24) * 12
            if y > 100:
                break
            d.text((2, y), dump[i:i + 24], font=font_obj, fill="#CCCCCC")
    else:
        # Device list
        d.text((2, 16), msg[:24], font=font_obj, fill="#AAAAAA")

        visible = devices[scroll:scroll + ROWS_VISIBLE]
        for i, dev in enumerate(visible):
            y = 30 + i * ROW_H
            idx = scroll + i
            marker = ">" if idx == sel else " "
            color = "#FFAA00" if idx == sel else "#CCCCCC"
            line = f"{marker}{dev['hex']} {dev['desc'][:14]}"
            d.text((2, y), line, font=font_obj, fill=color)

        if not devices and not scanning:
            d.text((2, 50), "Press OK to scan", font=font_obj, fill="#666")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Scan K1:Reg K3:Quit", font=font_obj, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, scanning, scroll, selected, status_msg, reg_dump

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font_obj = scaled_font()

    if not SMBUS_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "smbus2 not found!", font=font_obj, fill="#FF0000")
        d.text((4, 65), "pip install smbus2", font=font_obj, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK" and not scanning:
                scanning = True
                reg_dump = ""
                with lock:
                    found_devices.clear()
                    status_msg = "Scanning..."
                threading.Thread(target=_scan_thread, daemon=True).start()
                time.sleep(0.3)

            elif btn == "KEY1":
                # Read registers from selected device
                with lock:
                    if found_devices and 0 <= selected < len(found_devices):
                        addr = found_devices[selected]["addr"]
                        reg_dump = _read_registers(addr)
                    else:
                        reg_dump = ""
                time.sleep(0.3)

            elif btn == "KEY2":
                with lock:
                    has_data = len(found_devices) > 0
                if has_data:
                    fname = _export_loot()
                    with lock:
                        status_msg = f"Exported: {fname[:16]}"
                time.sleep(0.3)

            elif btn == "UP":
                reg_dump = ""
                with lock:
                    max_sel = max(0, len(found_devices) - 1)
                selected = max(0, selected - 1)
                if selected < scroll:
                    scroll = selected
                time.sleep(0.15)

            elif btn == "DOWN":
                reg_dump = ""
                with lock:
                    max_sel = max(0, len(found_devices) - 1)
                selected = min(selected + 1, max_sel)
                if selected >= scroll + ROWS_VISIBLE:
                    scroll = selected - ROWS_VISIBLE + 1
                time.sleep(0.15)

            _draw_frame(lcd, font_obj)
            time.sleep(0.05)

    finally:
        _running = False
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
