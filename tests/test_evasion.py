"""
Unit tests for payloads in the evasion/ directory.

Each payload is smoke-tested for importability, key functions, pure logic,
and constants.  We never call main().
"""

import importlib
import re
import sys

import pytest


# ---------------------------------------------------------------------------
# Safe import helper
# ---------------------------------------------------------------------------

def _safe_import(module_name):
    try:
        return importlib.import_module(module_name)
    except (SystemExit, PermissionError, OSError) as exc:
        pytest.skip(f"Cannot import {module_name}: {exc}")
        return None


# ===================================================================
# mac_randomizer
# ===================================================================

class TestMACRandomizer:
    """Tests for payloads.evasion.mac_randomizer."""

    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _safe_import("payloads.evasion.mac_randomizer")

    def test_import_smoke(self):
        assert self.mod is not None

    def test_generate_random_mac_format(self):
        """Generated MAC should be a valid 6-octet colon-separated string."""
        mac = self.mod._generate_random_mac()
        assert re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac)

    def test_generate_random_mac_locally_administered(self):
        """Bit 1 of first octet must be set (locally administered)."""
        for _ in range(20):
            mac = self.mod._generate_random_mac()
            first_octet = int(mac.split(":")[0], 16)
            assert first_octet & 0x02 == 0x02, "Locally administered bit not set"

    def test_generate_random_mac_unicast(self):
        """Bit 0 of first octet must be clear (unicast)."""
        for _ in range(20):
            mac = self.mod._generate_random_mac()
            first_octet = int(mac.split(":")[0], 16)
            assert first_octet & 0x01 == 0x00, "Multicast bit should not be set"

    def test_generate_random_mac_uniqueness(self):
        """Multiple calls should produce different MACs."""
        macs = {self.mod._generate_random_mac() for _ in range(10)}
        # Very unlikely to get duplicates in 10 tries
        assert len(macs) >= 8

    def test_interfaces_list(self):
        assert hasattr(self.mod, "INTERFACES")
        assert "eth0" in self.mod.INTERFACES
        assert "wlan0" in self.mod.INTERFACES

    def test_iface_exists_on_loopback(self):
        """lo should exist on all Linux systems."""
        # _iface_exists checks /sys/class/net/<iface>
        # lo is always present
        assert self.mod._iface_exists("lo") is True

    def test_iface_exists_on_bogus(self):
        assert self.mod._iface_exists("nonexistent99") is False

    def test_key_functions_exist(self):
        assert callable(self.mod._generate_random_mac)
        assert callable(self.mod._get_mac)
        assert callable(self.mod._set_mac)
        assert callable(self.mod._scan_nearby_macs)
        assert callable(self.mod.main)

    def test_debounce_constant(self):
        assert self.mod.DEBOUNCE == 0.25


# ===================================================================
# log_cleaner
# ===================================================================

class TestLogCleaner:
    """Tests for payloads.evasion.log_cleaner."""

    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _safe_import("payloads.evasion.log_cleaner")

    def test_import_smoke(self):
        assert self.mod is not None

    def test_clean_items_list(self):
        assert hasattr(self.mod, "CLEAN_ITEMS")
        assert len(self.mod.CLEAN_ITEMS) >= 5
        names = [item["name"] for item in self.mod.CLEAN_ITEMS]
        assert "bash_history" in names
        assert "arp_cache" in names
        assert "auth_logs" in names

    def test_clean_items_have_labels(self):
        for item in self.mod.CLEAN_ITEMS:
            assert "name" in item
            assert "label" in item
            assert len(item["label"]) > 0

    def test_clean_item_unknown_returns_false(self):
        ok, msg = self.mod._clean_item("nonexistent_item")
        assert ok is False
        assert "Unknown" in msg

    def test_clean_item_dns_cache_returns_true(self):
        """dns_cache clean should return success (even if service not running)."""
        ok, _msg = self.mod._clean_item("dns_cache")
        assert ok is True

    def test_key_functions_exist(self):
        assert callable(self.mod._clean_item)
        assert callable(self.mod._draw_checklist)
        assert callable(self.mod._draw_progress)
        assert callable(self.mod._clean_selected)
        assert callable(self.mod.main)

    def test_debounce_constant(self):
        assert self.mod.DEBOUNCE == 0.25


# ===================================================================
# traffic_shaper
# ===================================================================

class TestTrafficShaper:
    """Tests for payloads.evasion.traffic_shaper."""

    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _safe_import("payloads.evasion.traffic_shaper")

    def test_import_smoke(self):
        assert self.mod is not None

    def test_bandwidth_constants(self):
        assert self.mod.MIN_BW_MBIT == 1
        assert self.mod.MAX_BW_MBIT == 100
        assert self.mod.DEFAULT_BW_MBIT == 10

    def test_default_and_fallback_ifaces(self):
        assert self.mod.DEFAULT_IFACE == "br0"
        assert "br0" in self.mod.FALLBACK_IFACES
        assert "eth0" in self.mod.FALLBACK_IFACES

    def test_get_queue_stats_returns_dict(self):
        """_get_queue_stats should return a dict with expected keys even if tc fails."""
        stats = self.mod._get_queue_stats("nonexistent99")
        assert isinstance(stats, dict)
        assert "sent" in stats
        assert "dropped" in stats
        assert "overlimits" in stats
        assert "backlog" in stats

    def test_get_proto_stats_returns_list(self):
        """_get_proto_stats should return a list on any system."""
        result = self.mod._get_proto_stats()
        assert isinstance(result, list)

    def test_detect_interface_returns_string(self):
        result = self.mod._detect_interface()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_key_functions_exist(self):
        assert callable(self.mod._detect_interface)
        assert callable(self.mod._run_tc)
        assert callable(self.mod._apply_shaping)
        assert callable(self.mod._remove_shaping)
        assert callable(self.mod._get_queue_stats)
        assert callable(self.mod._get_proto_stats)
        assert callable(self.mod._measure_latency)
        assert callable(self.mod.main)

    def test_pins_complete(self):
        expected = {"UP", "DOWN", "LEFT", "RIGHT", "OK", "KEY1", "KEY2", "KEY3"}
        assert set(self.mod.PINS.keys()) == expected


# ===================================================================
# stealth_mode
# ===================================================================

class TestStealthMode:
    """Tests for payloads.evasion.stealth_mode."""

    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _safe_import("payloads.evasion.stealth_mode")

    def test_import_smoke(self):
        assert self.mod is not None

    def test_items_list(self):
        assert hasattr(self.mod, "ITEMS")
        assert len(self.mod.ITEMS) >= 6
        ids = [item["id"] for item in self.mod.ITEMS]
        assert "act_led" in ids
        assert "mac_random" in ids
        assert "hostname" in ids
        assert "flush_logs" in ids

    def test_items_have_id_and_label(self):
        for item in self.mod.ITEMS:
            assert "id" in item
            assert "label" in item
            assert len(item["label"]) > 0

    def test_generate_random_mac_format(self):
        mac = self.mod._generate_random_mac()
        assert re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac)

    def test_generate_random_mac_uses_generic_oui(self):
        """Generated MAC should start with one of the GENERIC_OUI_PREFIXES."""
        for _ in range(10):
            mac = self.mod._generate_random_mac()
            prefix = mac[:8]
            assert prefix in self.mod.GENERIC_OUI_PREFIXES

    def test_stealth_hostname_constant(self):
        assert self.mod.STEALTH_HOSTNAME == "localhost"

    def test_led_paths_dict(self):
        assert hasattr(self.mod, "LED_PATHS")
        assert "ACT" in self.mod.LED_PATHS
        assert "PWR" in self.mod.LED_PATHS

    def test_enable_and_disable_action_tables(self):
        """Verify action dispatch tables have matching entries."""
        assert hasattr(self.mod, "_ENABLE_ACTIONS")
        assert hasattr(self.mod, "_DISABLE_ACTIONS")
        for item in self.mod.ITEMS:
            iid = item["id"]
            assert iid in self.mod._ENABLE_ACTIONS, f"Missing enable action for {iid}"

    def test_get_interfaces_returns_list(self):
        result = self.mod._get_interfaces()
        assert isinstance(result, list)
        # Should not include loopback
        assert "lo" not in result

    def test_key_functions_exist(self):
        assert callable(self.mod._generate_random_mac)
        assert callable(self.mod._get_interfaces)
        assert callable(self.mod._save_originals)
        assert callable(self.mod._activate_stealth)
        assert callable(self.mod._deactivate_stealth)
        assert callable(self.mod._toggle_item)
        assert callable(self.mod.main)

    def test_rows_visible(self):
        assert self.mod.ROWS_VISIBLE == 6


# ---------------------------------------------------------------------------
# Source-based helper for payloads that call GPIO at import time
# ---------------------------------------------------------------------------

import os

_EVASION_PAYLOADS_DIR = os.path.join(
    os.path.dirname(__file__), os.pardir, "payloads", "evasion"
)


def _read_source(filename):
    path = os.path.join(_EVASION_PAYLOADS_DIR, filename)
    with open(path) as fh:
        return fh.read()


# ===================================================================
# fingerprint_spoof (GPIO at import — source-based)
# ===================================================================

class TestFingerprintSpoof:
    """Tests for payloads.evasion.fingerprint_spoof (source-based)."""

    def test_source_has_profiles(self):
        src = _read_source("fingerprint_spoof.py")
        assert "PROFILES" in src

    def test_source_has_sysctl_read(self):
        src = _read_source("fingerprint_spoof.py")
        assert "def _sysctl_read" in src

    def test_source_has_apply_profile(self):
        src = _read_source("fingerprint_spoof.py")
        assert "def _apply_profile" in src

    def test_source_has_main(self):
        src = _read_source("fingerprint_spoof.py")
        assert "def main()" in src


# ===================================================================
# timing_evasion (GPIO at import — source-based)
# ===================================================================

class TestTimingEvasion:
    """Tests for payloads.evasion.timing_evasion (source-based)."""

    def test_source_has_presets(self):
        src = _read_source("timing_evasion.py")
        assert "PRESETS" in src

    def test_source_has_custom_delays(self):
        src = _read_source("timing_evasion.py")
        assert "CUSTOM_DELAYS" in src

    def test_source_has_tc_add_netem(self):
        src = _read_source("timing_evasion.py")
        assert "def _tc_add_netem" in src

    def test_source_has_main(self):
        src = _read_source("timing_evasion.py")
        assert "def main()" in src
