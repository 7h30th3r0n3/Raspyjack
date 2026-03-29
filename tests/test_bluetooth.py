"""
Unit tests for Bluetooth payloads.

Each payload is imported via importlib to gracefully handle import-time
side-effects (os.makedirs to /root, subprocess calls, etc.) that would
fail on a dev machine.
"""

import importlib
import sys

import pytest


# ---------------------------------------------------------------------------
# Safe import helper
# ---------------------------------------------------------------------------

def _safe_import(module_name):
    """Import a payload module, skipping if import-time side-effects fail."""
    try:
        return importlib.import_module(module_name)
    except (SystemExit, PermissionError, OSError) as exc:
        pytest.skip(f"Cannot import {module_name}: {exc}")
        return None


# ===================================================================
# payloads.bluetooth.ble_beacon_flood
# ===================================================================

class TestBLEBeaconFlood:
    """Tests for payloads.bluetooth.ble_beacon_flood."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.bluetooth.ble_beacon_flood")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_pins_dict(self):
        expected = {"UP", "DOWN", "LEFT", "RIGHT", "OK", "KEY1", "KEY2", "KEY3"}
        assert set(self.mod.PINS.keys()) == expected

    def test_constants(self):
        assert self.mod.HCI_DEV == "hci0"
        assert self.mod.MODES == ["iBeacon", "Eddystone", "Both"]
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/BLEBeacon"

    def test_eddystone_urls_is_list(self):
        assert isinstance(self.mod.EDDYSTONE_URLS, list)
        assert len(self.mod.EDDYSTONE_URLS) > 0

    def test_eddystone_schemes_dict(self):
        schemes = self.mod.EDDYSTONE_SCHEMES
        assert "http://" in schemes
        assert "https://" in schemes
        assert schemes["http://"] == 0x02

    def test_eddystone_suffixes_dict(self):
        suffixes = self.mod.EDDYSTONE_SUFFIXES
        assert ".com" in suffixes
        assert ".net" in suffixes

    def test_randomise_params_returns_tuple(self):
        uuid, major, minor, url = self.mod._randomise_params()
        assert isinstance(uuid, str)
        assert len(uuid) == 32  # 16 hex bytes
        assert 0 <= major <= 65535
        assert 0 <= minor <= 65535
        assert url in self.mod.EDDYSTONE_URLS

    def test_randomise_params_produces_different_values(self):
        results = set()
        for _ in range(10):
            uuid, _, _, _ = self.mod._randomise_params()
            results.add(uuid)
        # Extremely unlikely to get 10 identical UUIDs
        assert len(results) > 1

    def test_encode_eddystone_url_http(self):
        scheme, body = self.mod._encode_eddystone_url("http://evil.com")
        assert scheme == "02"  # http:// scheme
        # "evil" encoded as ASCII + ".com" suffix
        assert isinstance(body, list)
        assert len(body) > 0

    def test_encode_eddystone_url_https(self):
        scheme, body = self.mod._encode_eddystone_url("https://test.net")
        assert scheme == "03"  # https:// scheme

    def test_encode_eddystone_url_with_www(self):
        scheme, _ = self.mod._encode_eddystone_url("http://www.example.com")
        assert scheme == "00"  # http://www. scheme

    def test_build_ibeacon_cmd_structure(self):
        cmd = self.mod._build_ibeacon_cmd()
        assert isinstance(cmd, list)
        assert cmd[0] == "sudo"
        assert "hcitool" in cmd[1]
        assert "0x08" in cmd

    def test_build_eddystone_cmd_structure(self):
        cmd = self.mod._build_eddystone_cmd()
        assert isinstance(cmd, list)
        assert cmd[0] == "sudo"
        assert "hcitool" in cmd[1]


# ===================================================================
# payloads.bluetooth.ble_replay
# ===================================================================

class TestBLEReplay:
    """Tests for payloads.bluetooth.ble_replay."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.bluetooth.ble_replay")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/BLEReplay"
        assert self.mod.HCI_DEV == "hci0"
        assert self.mod.SCAN_TIMEOUT == 10
        assert self.mod.ROWS_VISIBLE == 7

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8
        assert self.mod.PINS["OK"] == 13

    def test_initial_state(self):
        assert isinstance(self.mod.devices, list)
        assert isinstance(self.mod.characteristics, list)
        assert isinstance(self.mod.recorded_sequence, list)
        assert self.mod.view_mode == "scan"
        assert self.mod.mode == "record"
        assert self.mod.recording is False
        assert self.mod.replaying is False

    def test_export_sequence_returns_none_when_empty(self):
        # With empty recorded_sequence, should return None
        original = list(self.mod.recorded_sequence)
        self.mod.recorded_sequence.clear()
        try:
            result = self.mod.export_sequence()
            assert result is None
        finally:
            self.mod.recorded_sequence.extend(original)


# ===================================================================
# payloads.bluetooth.ble_spam
# ===================================================================

class TestBLESpam:
    """Tests for payloads.bluetooth.ble_spam."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.bluetooth.ble_spam")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.HCI_DEV == "hci0"
        assert self.mod.MODES == ["FastPair", "iOS", "Windows", "ALL"]
        assert len(self.mod.SPEED_LEVELS) == 5
        assert len(self.mod.SPEED_LABELS) == 5

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8

    def test_fastpair_models_is_list_of_bytes(self):
        for model in self.mod.FASTPAIR_MODELS:
            assert isinstance(model, bytes)
            assert len(model) == 3

    def test_apple_devices_structure(self):
        for dev_bytes, name in self.mod.APPLE_DEVICES:
            assert isinstance(dev_bytes, bytes)
            assert len(dev_bytes) == 3
            assert isinstance(name, str)
            assert len(name) > 0

    def test_swift_pair_names_is_list(self):
        assert isinstance(self.mod.SWIFT_PAIR_NAMES, list)
        assert len(self.mod.SWIFT_PAIR_NAMES) > 0

    def test_build_fastpair_adv(self):
        adv_bytes, label = self.mod._build_fastpair_adv()
        assert isinstance(adv_bytes, bytes)
        assert isinstance(label, str)
        # Should start with BLE flags
        assert adv_bytes[0] == 0x02
        assert adv_bytes[1] == 0x01
        assert adv_bytes[2] == 0x06
        # Service Data type with UUID 0xFE2C
        assert 0x2C in adv_bytes
        assert 0xFE in adv_bytes

    def test_build_ios_adv(self):
        adv_bytes, label = self.mod._build_ios_adv()
        assert isinstance(adv_bytes, bytes)
        assert isinstance(label, str)
        # Should contain Apple Company ID
        assert adv_bytes[5] == 0x4C
        assert adv_bytes[6] == 0x00

    def test_build_swiftpair_adv(self):
        adv_bytes, label = self.mod._build_swiftpair_adv()
        assert isinstance(adv_bytes, bytes)
        assert label.startswith("SP:")
        # Microsoft Company ID
        assert adv_bytes[5] == 0x06
        assert adv_bytes[6] == 0x00
        # Swift Pair scenario byte
        assert adv_bytes[7] == 0x03

    def test_speed_levels_descending(self):
        # Speeds should go from slow (high ms) to fast (low ms)
        levels = self.mod.SPEED_LEVELS
        for i in range(len(levels) - 1):
            assert levels[i] >= levels[i + 1]


# ---------------------------------------------------------------------------
# Source-based helper for payloads that call GPIO at import time
# ---------------------------------------------------------------------------

import os

_BT_PAYLOADS_DIR = os.path.join(
    os.path.dirname(__file__), os.pardir, "payloads", "bluetooth"
)


def _read_source(filename):
    path = os.path.join(_BT_PAYLOADS_DIR, filename)
    with open(path) as fh:
        return fh.read()


# ===================================================================
# payloads.bluetooth.ble_scanner (GPIO at import — source-based)
# ===================================================================

class TestBLEScanner:
    """Tests for payloads.bluetooth.ble_scanner (source-based)."""

    def test_source_has_loot_dir(self):
        src = _read_source("ble_scanner.py")
        assert "LOOT_DIR" in src
        assert "BLEScan" in src

    def test_source_has_sort_modes(self):
        src = _read_source("ble_scanner.py")
        assert "SORT_MODES" in src
        assert "rssi" in src

    def test_source_has_scan_loop(self):
        src = _read_source("ble_scanner.py")
        assert "def _scan_loop" in src

    def test_source_has_main(self):
        src = _read_source("ble_scanner.py")
        assert "def main()" in src


# ===================================================================
# payloads.bluetooth.bt_audio_inject (GPIO at import — source-based)
# ===================================================================

class TestBtAudioInject:
    """Tests for payloads.bluetooth.bt_audio_inject (source-based)."""

    def test_source_has_hci_dev(self):
        src = _read_source("bt_audio_inject.py")
        assert "HCI_DEV" in src
        assert "hci0" in src

    def test_source_has_audio_file(self):
        src = _read_source("bt_audio_inject.py")
        assert "AUDIO_FILE" in src

    def test_source_has_connect_device(self):
        src = _read_source("bt_audio_inject.py")
        assert "def _connect_device" in src

    def test_source_has_play_audio(self):
        src = _read_source("bt_audio_inject.py")
        assert "def _play_audio" in src


# ===================================================================
# payloads.bluetooth.ble_mitm (GPIO at import — source-based)
# ===================================================================

class TestBLEMitm:
    """Tests for payloads.bluetooth.ble_mitm (source-based)."""

    def test_source_has_loot_dir(self):
        src = _read_source("ble_mitm.py")
        assert "LOOT_DIR" in src
        assert "BLE_MITM" in src

    def test_source_has_enumerate_gatt(self):
        src = _read_source("ble_mitm.py")
        assert "def _enumerate_gatt" in src

    def test_source_has_proxy_loop(self):
        src = _read_source("ble_mitm.py")
        assert "def _proxy_loop" in src

    def test_source_has_main(self):
        src = _read_source("ble_mitm.py")
        assert "def main()" in src


# ===================================================================
# payloads.bluetooth.bt_dos (GPIO at import — source-based)
# ===================================================================

class TestBtDos:
    """Tests for payloads.bluetooth.bt_dos (source-based)."""

    def test_source_has_hci_dev(self):
        src = _read_source("bt_dos.py")
        assert "HCI_DEV" in src

    def test_source_has_packet_sizes(self):
        src = _read_source("bt_dos.py")
        assert "PACKET_SIZES" in src

    def test_source_has_flood_loop(self):
        src = _read_source("bt_dos.py")
        assert "def _flood_loop" in src

    def test_source_has_main(self):
        src = _read_source("bt_dos.py")
        assert "def main()" in src
