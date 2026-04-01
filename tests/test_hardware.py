"""
Unit tests for payloads in payloads/hardware/.
"""

import importlib
import os

import pytest

PAYLOADS_DIR = os.path.join(
    os.path.dirname(__file__), os.pardir, "payloads", "hardware"
)


def _safe_import(module_name):
    try:
        return importlib.import_module(module_name)
    except (SystemExit, PermissionError, OSError) as exc:
        pytest.skip(f"Cannot import {module_name}: {exc}")
        return None


def _read_source(filename):
    path = os.path.join(PAYLOADS_DIR, filename)
    with open(path) as fh:
        return fh.read()


# =========================================================================
# i2c_scanner.py
# =========================================================================
class TestI2CScanner:
    def test_import_smoke(self):
        mod = _safe_import("payloads.hardware.i2c_scanner")
        assert mod is not None

    def test_i2c_devices_dict(self):
        mod = _safe_import("payloads.hardware.i2c_scanner")
        assert isinstance(mod.I2C_DEVICES, dict)
        assert len(mod.I2C_DEVICES) > 10

    def test_known_addresses(self):
        mod = _safe_import("payloads.hardware.i2c_scanner")
        # SSD1306 OLED at 0x3C
        assert 0x3C in mod.I2C_DEVICES
        # BME280 at 0x76
        assert 0x76 in mod.I2C_DEVICES

    def test_i2c_bus_constant(self):
        mod = _safe_import("payloads.hardware.i2c_scanner")
        assert mod.I2C_BUS == 1

    def test_loot_dir_constant(self):
        mod = _safe_import("payloads.hardware.i2c_scanner")
        assert "I2CScan" in mod.LOOT_DIR

    def test_source_has_scan_thread(self):
        src = _read_source("i2c_scanner.py")
        assert "def _scan_thread" in src

    def test_source_has_read_registers(self):
        src = _read_source("i2c_scanner.py")
        assert "def _read_registers" in src

    def test_source_has_export_loot(self):
        src = _read_source("i2c_scanner.py")
        assert "def _export_loot" in src

    def test_main_callable(self):
        mod = _safe_import("payloads.hardware.i2c_scanner")
        assert callable(mod.main)


# =========================================================================
# gpio_tripwire.py
# =========================================================================
class TestGPIOTripwire:
    def test_import_smoke(self):
        mod = _safe_import("payloads.hardware.gpio_tripwire")
        assert mod is not None

    def test_pin_presets(self):
        mod = _safe_import("payloads.hardware.gpio_tripwire")
        assert isinstance(mod.PIN_PRESETS, list)
        assert len(mod.PIN_PRESETS) >= 3
        for preset in mod.PIN_PRESETS:
            assert "name" in preset
            assert "pins" in preset
            assert "labels" in preset

    def test_buzzer_pin(self):
        mod = _safe_import("payloads.hardware.gpio_tripwire")
        assert mod.BUZZER_PIN == 18

    def test_config_path(self):
        mod = _safe_import("payloads.hardware.gpio_tripwire")
        assert "tripwire" in mod.CONFIG_PATH

    def test_source_has_monitor_thread(self):
        src = _read_source("gpio_tripwire.py")
        assert "def _monitor_thread" in src

    def test_source_has_add_event(self):
        src = _read_source("gpio_tripwire.py")
        assert "def _add_event" in src

    def test_source_has_discord_alert(self):
        src = _read_source("gpio_tripwire.py")
        assert "def _send_discord_alert" in src

    def test_main_callable(self):
        mod = _safe_import("payloads.hardware.gpio_tripwire")
        assert callable(mod.main)

    def test_initial_state(self):
        mod = _safe_import("payloads.hardware.gpio_tripwire")
        assert mod.armed is False
        assert mod.trigger_count == 0


# =========================================================================
# nfc_reader.py (GPIO at import — source-based)
# =========================================================================
class TestNFCReader:
    def test_source_has_loot_dir(self):
        src = _read_source("nfc_reader.py")
        assert "LOOT_DIR" in src
        assert "NFC" in src

    def test_source_has_pn532_class(self):
        src = _read_source("nfc_reader.py")
        assert "class PN532I2C" in src

    def test_source_has_detect_card_type(self):
        src = _read_source("nfc_reader.py")
        assert "def _detect_card_type" in src

    def test_source_has_main(self):
        src = _read_source("nfc_reader.py")
        assert "def main()" in src


# =========================================================================
# gps_tracker.py (GPIO at import — source-based)
# =========================================================================
class TestGPSTracker:
    def test_source_has_loot_dir(self):
        src = _read_source("gps_tracker.py")
        assert "LOOT_DIR" in src
        assert "GPS" in src

    def test_source_has_gpsfix_class(self):
        src = _read_source("gps_tracker.py")
        assert "class GPSFix" in src

    def test_source_has_parse_gpgga(self):
        src = _read_source("gps_tracker.py")
        assert "def _parse_gpgga" in src

    def test_source_has_nmea_checksum(self):
        src = _read_source("gps_tracker.py")
        assert "def _nmea_checksum_ok" in src


# =========================================================================
# led_control.py (GPIO at import — source-based)
# =========================================================================
class TestLEDControl:
    def test_source_has_patterns(self):
        src = _read_source("led_control.py")
        assert "PATTERNS" in src

    def test_source_has_led_set(self):
        src = _read_source("led_control.py")
        assert "def _led_set" in src

    def test_source_has_pattern_thread(self):
        src = _read_source("led_control.py")
        assert "def _pattern_thread" in src

    def test_source_has_main(self):
        src = _read_source("led_control.py")
        assert "def main()" in src


def test_lcd_1in54_env_select(monkeypatch):
    monkeypatch.setenv("RJ_LCD_MODEL", "1in54")

    import importlib
    import sys

    sys.modules.pop("LCD_1in44", None)
    sys.modules.pop("LCD_1in54", None)

    lcd_mod = importlib.import_module("LCD_1in44")
    assert lcd_mod.LCD_WIDTH == 240
    assert lcd_mod.LCD_HEIGHT == 240

    lcd = lcd_mod.LCD()
    assert lcd.width == 240
    assert lcd.height == 240

