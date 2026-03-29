"""
Unit tests for payloads in payloads/usb/.
"""

import importlib
import os
import re
import ast

import pytest

PAYLOADS_DIR = os.path.join(
    os.path.dirname(__file__), os.pardir, "payloads", "usb"
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
# hid_injector.py
# =========================================================================
class TestHIDInjector:
    """Tests for payloads.usb.hid_injector."""

    def test_import_smoke(self):
        mod = _safe_import("payloads.usb.hid_injector")
        assert mod is not None

    def test_char_to_hid_lowercase(self):
        mod = _safe_import("payloads.usb.hid_injector")
        mod_val, code = mod._char_to_hid("a")
        assert mod_val == mod.MOD_NONE
        assert code == 0x04

    def test_char_to_hid_uppercase(self):
        mod = _safe_import("payloads.usb.hid_injector")
        mod_val, code = mod._char_to_hid("A")
        assert mod_val == mod.MOD_SHIFT
        assert code == 0x04

    def test_char_to_hid_special(self):
        mod = _safe_import("payloads.usb.hid_injector")
        mod_val, code = mod._char_to_hid("!")
        assert mod_val == mod.MOD_SHIFT
        assert code == 0x1E

    def test_char_to_hid_unknown(self):
        mod = _safe_import("payloads.usb.hid_injector")
        mod_val, code = mod._char_to_hid("\x80")
        assert mod_val is None and code is None

    def test_parse_ducky_line_string(self):
        mod = _safe_import("payloads.usb.hid_injector")
        action, arg = mod._parse_ducky_line("STRING Hello World")
        assert action == "STRING"
        assert arg == "Hello World"

    def test_parse_ducky_line_delay(self):
        mod = _safe_import("payloads.usb.hid_injector")
        action, arg = mod._parse_ducky_line("DELAY 500")
        assert action == "DELAY"
        assert arg == 500

    def test_parse_ducky_line_enter(self):
        mod = _safe_import("payloads.usb.hid_injector")
        action, arg = mod._parse_ducky_line("ENTER")
        assert action == "KEY"
        assert arg == (mod.MOD_NONE, mod.KEY_ENTER)

    def test_parse_ducky_line_gui(self):
        mod = _safe_import("payloads.usb.hid_injector")
        action, arg = mod._parse_ducky_line("GUI r")
        assert action == "KEY"
        mod_val, code = arg
        assert mod_val & mod.MOD_GUI

    def test_parse_ducky_line_comment(self):
        mod = _safe_import("payloads.usb.hid_injector")
        action, _ = mod._parse_ducky_line("REM this is a comment")
        assert action == "NOP"

    def test_parse_ducky_line_empty(self):
        mod = _safe_import("payloads.usb.hid_injector")
        action, _ = mod._parse_ducky_line("")
        assert action == "NOP"

    def test_constants_exist(self):
        mod = _safe_import("payloads.usb.hid_injector")
        assert hasattr(mod, "SCRIPTS_DIR")
        assert hasattr(mod, "LOOT_DIR")
        assert hasattr(mod, "GADGET_NAME")
        assert hasattr(mod, "HID_DEV")

    def test_ducky_keys_dict(self):
        mod = _safe_import("payloads.usb.hid_injector")
        assert isinstance(mod.DUCKY_KEYS, dict)
        assert "ENTER" in mod.DUCKY_KEYS
        assert "TAB" in mod.DUCKY_KEYS
        assert "ESCAPE" in mod.DUCKY_KEYS

    def test_main_exists(self):
        mod = _safe_import("payloads.usb.hid_injector")
        assert callable(mod.main)


# =========================================================================
# usb_keylogger.py
# =========================================================================
class TestUSBKeylogger:
    """Tests for payloads.usb.usb_keylogger."""

    def test_import_smoke(self):
        mod = _safe_import("payloads.usb.usb_keylogger")
        assert mod is not None

    def test_build_hid_report_empty(self):
        mod = _safe_import("payloads.usb.usb_keylogger")
        report = mod._build_hid_report(0, [])
        assert len(report) == 8
        assert report == b"\x00" * 8

    def test_build_hid_report_with_modifier(self):
        mod = _safe_import("payloads.usb.usb_keylogger")
        report = mod._build_hid_report(0x02, [0x04])
        assert len(report) == 8
        assert report[0] == 0x02
        assert report[2] == 0x04

    def test_build_hid_report_pads_keys(self):
        mod = _safe_import("payloads.usb.usb_keylogger")
        report = mod._build_hid_report(0, [0x04, 0x05, 0x06])
        assert len(report) == 8
        assert report[2] == 0x04
        assert report[3] == 0x05
        assert report[4] == 0x06

    def test_evdev_to_hid_mapping(self):
        mod = _safe_import("payloads.usb.usb_keylogger")
        assert isinstance(mod.EVDEV_TO_HID, dict)
        # KEY_A = evdev 30
        assert 30 in mod.EVDEV_TO_HID
        hid_code, label, _ = mod.EVDEV_TO_HID[30]
        assert label == "a"

    def test_modifier_bits_mapping(self):
        mod = _safe_import("payloads.usb.usb_keylogger")
        assert 0xE0 in mod._MODIFIER_BITS  # Left Ctrl
        assert 0xE1 in mod._MODIFIER_BITS  # Left Shift

    def test_constants_exist(self):
        mod = _safe_import("payloads.usb.usb_keylogger")
        assert hasattr(mod, "LOOT_DIR")
        assert hasattr(mod, "EV_KEY")
        assert mod.EV_KEY == 0x01


# =========================================================================
# usb_ethernet_mitm.py
# =========================================================================
class TestUSBEthernetMITM:
    """Tests for payloads.usb.usb_ethernet_mitm."""

    def test_import_smoke(self):
        mod = _safe_import("payloads.usb.usb_ethernet_mitm")
        assert mod is not None

    def test_check_for_creds_username(self):
        mod = _safe_import("payloads.usb.usb_ethernet_mitm")
        # Reset state
        mod.captured_creds.clear()
        mod._check_for_creds("user=admin&pass=secret")
        assert len(mod.captured_creds) >= 1
        types = [c["type"] for c in mod.captured_creds]
        assert "username" in types or "password" in types

    def test_check_for_creds_no_match(self):
        mod = _safe_import("payloads.usb.usb_ethernet_mitm")
        mod.captured_creds.clear()
        mod._check_for_creds("normal http traffic with no credentials")
        assert len(mod.captured_creds) == 0

    def test_constants_exist(self):
        mod = _safe_import("payloads.usb.usb_ethernet_mitm")
        assert mod.GATEWAY_IP == "10.0.88.1"
        assert mod.USB_IFACE == "usb0"

    def test_main_callable(self):
        mod = _safe_import("payloads.usb.usb_ethernet_mitm")
        assert callable(mod.main)

    def test_source_has_export_data(self):
        src = _read_source("usb_ethernet_mitm.py")
        assert "def _export_data" in src


# =========================================================================
# usb_mass_storage.py
# =========================================================================
class TestUSBMassStorage:
    """Tests for payloads.usb.usb_mass_storage."""

    def test_import_smoke(self):
        mod = _safe_import("payloads.usb.usb_mass_storage")
        assert mod is not None

    def test_templates_list(self):
        mod = _safe_import("payloads.usb.usb_mass_storage")
        assert mod.TEMPLATES == ["empty", "documents", "autorun"]

    def test_constants_exist(self):
        mod = _safe_import("payloads.usb.usb_mass_storage")
        assert mod.IMAGE_SIZE_MB == 64
        assert hasattr(mod, "GADGET_NAME")
        assert mod.GADGET_NAME == "raspyjack_usb"

    def test_find_udc_callable(self):
        mod = _safe_import("payloads.usb.usb_mass_storage")
        assert callable(mod._find_udc)

    def test_main_callable(self):
        mod = _safe_import("payloads.usb.usb_mass_storage")
        assert callable(mod.main)


# =========================================================================
# ducky_library.py
# =========================================================================
class TestDuckyLibrary:
    """Tests for payloads.usb.ducky_library."""

    def test_import_smoke(self):
        mod = _safe_import("payloads.usb.ducky_library")
        assert mod is not None

    def test_bundled_scripts_dict(self):
        mod = _safe_import("payloads.usb.ducky_library")
        assert isinstance(mod.BUNDLED_SCRIPTS, dict)
        assert len(mod.BUNDLED_SCRIPTS) >= 3

    def test_ip_placeholder_constant(self):
        mod = _safe_import("payloads.usb.ducky_library")
        assert mod.IP_PLACEHOLDER == "ATTACKER_IP"

    def test_ip_chars_list(self):
        mod = _safe_import("payloads.usb.ducky_library")
        assert "." in mod.IP_CHARS
        assert "0" in mod.IP_CHARS
        assert "9" in mod.IP_CHARS

    def test_source_has_scan_scripts(self):
        src = _read_source("ducky_library.py")
        assert "def _scan_scripts" in src

    def test_main_callable(self):
        mod = _safe_import("payloads.usb.ducky_library")
        assert callable(mod.main)


# =========================================================================
# badusb_detector.py
# =========================================================================
class TestBadUSBDetector:
    """Tests for payloads.usb.badusb_detector."""

    def test_import_smoke(self):
        mod = _safe_import("payloads.usb.badusb_detector")
        assert mod is not None

    def test_alert_window_constant(self):
        mod = _safe_import("payloads.usb.badusb_detector")
        assert mod.ALERT_WINDOW_SEC == 8

    def test_trigger_alert_sets_state(self):
        mod = _safe_import("payloads.usb.badusb_detector")
        mod.alert_active = False
        mod.trigger_alert("test reason")
        assert mod.alert_active is True
        assert mod.alert_reason == "test reason"
        # Reset
        mod.alert_active = False

    def test_popup_sets_message(self):
        mod = _safe_import("payloads.usb.badusb_detector")
        mod._popup("Hello", duration=0.01)
        assert mod.status_message == "Hello"

    def test_source_has_monitor_usb(self):
        src = _read_source("badusb_detector.py")
        assert "def monitor_usb" in src

    def test_main_callable(self):
        mod = _safe_import("payloads.usb.badusb_detector")
        assert callable(mod.main)
