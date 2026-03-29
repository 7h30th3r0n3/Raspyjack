"""
Unit tests for WiFi payloads.

Each payload is imported via importlib to gracefully handle import-time
side-effects (os.makedirs to /root, subprocess calls, etc.) that would
fail on a dev machine.
"""

import importlib
import os
import sys

import pytest

PAYLOADS_DIR = os.path.join(
    os.path.dirname(__file__), os.pardir, "payloads", "wifi"
)


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


def _read_source(filename):
    path = os.path.join(PAYLOADS_DIR, filename)
    with open(path) as fh:
        return fh.read()


# ===================================================================
# payloads.wifi.deauth (module-level loop — source-based)
# ===================================================================

class TestDeauth:
    """Tests for payloads.wifi.deauth (source-based, has blocking import)."""

    def test_source_has_pins(self):
        src = _read_source("deauth.py")
        assert "PINS" in src

    def test_source_has_onboard_check(self):
        src = _read_source("deauth.py")
        assert "_is_onboard_wifi_iface" in src

    def test_source_has_scan(self):
        src = _read_source("deauth.py")
        assert "def scan" in src.lower() or "SCAN_TIMEOUT" in src


# ===================================================================
# payloads.wifi.evil_twin
# ===================================================================

class TestEvilTwin:
    """Tests for payloads.wifi.evil_twin."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.wifi.evil_twin")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_pins_dict(self):
        assert set(self.mod.PINS.keys()) == {
            "UP", "DOWN", "LEFT", "RIGHT", "OK", "KEY1", "KEY2", "KEY3",
        }

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/EvilTwin"
        assert self.mod.GATEWAY_IP == "10.0.66.1"
        assert self.mod.PORTAL_PORT == 80
        assert self.mod.ROWS_VISIBLE == 7

    def test_portal_html_contains_form(self):
        assert "<form" in self.mod.PORTAL_HTML
        assert "password" in self.mod.PORTAL_HTML

    def test_portal_success_contains_connected(self):
        assert "Connected" in self.mod.PORTAL_SUCCESS

    def test_is_onboard_wifi_returns_false_for_nonexistent(self):
        assert self.mod._is_onboard_wifi_iface("fake_iface") is False

    def test_portal_handler_class_exists(self):
        assert hasattr(self.mod, "PortalHandler")


# ===================================================================
# payloads.wifi.karma_ap
# ===================================================================

class TestKarmaAP:
    """Tests for payloads.wifi.karma_ap."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.wifi.karma_ap")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/KarmaAP"
        assert self.mod.GATEWAY_IP == "10.0.77.1"
        assert self.mod.PORTAL_PORT == 80

    def test_pins_dict(self):
        assert "KEY3" in self.mod.PINS
        assert self.mod.PINS["OK"] == 13

    def test_get_sorted_ssids_empty(self):
        # With empty probed_ssids, should return empty list
        original = dict(self.mod.probed_ssids)
        self.mod.probed_ssids.clear()
        try:
            result = self.mod._get_sorted_ssids()
            assert result == []
        finally:
            self.mod.probed_ssids.update(original)

    def test_get_sorted_ssids_ordering(self):
        original = dict(self.mod.probed_ssids)
        self.mod.probed_ssids.clear()
        self.mod.probed_ssids["TestNet"] = 5
        self.mod.probed_ssids["HomeWifi"] = 10
        self.mod.probed_ssids["Office"] = 1
        try:
            result = self.mod._get_sorted_ssids()
            assert result[0] == ("HomeWifi", 10)
            assert result[1] == ("TestNet", 5)
            assert result[2] == ("Office", 1)
        finally:
            self.mod.probed_ssids.clear()
            self.mod.probed_ssids.update(original)


# ===================================================================
# payloads.wifi.pmkid_grab
# ===================================================================

class TestPMKIDGrab:
    """Tests for payloads.wifi.pmkid_grab."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.wifi.pmkid_grab")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/PMKID"
        assert self.mod.CHANNELS_24 == list(range(1, 14))
        assert self.mod.ROWS_VISIBLE == 6

    def test_extract_pmkid_no_pmkid(self):
        # Random bytes should return None
        result = self.mod._extract_pmkid(b"\x00" * 64)
        assert result is None

    def test_extract_pmkid_with_kde_marker(self):
        # Build a fake payload with PMKID KDE marker
        kde_marker = b"\x00\x0f\xac\x04"
        fake_pmkid = bytes(range(16))  # 00 01 02 ... 0F
        padding = b"\x30" + b"\x00" * 10 + kde_marker + fake_pmkid
        result = self.mod._extract_pmkid(padding)
        assert result == fake_pmkid.hex()

    def test_extract_pmkid_all_zeros_ignored(self):
        # All-zero PMKID should be ignored
        kde_marker = b"\x00\x0f\xac\x04"
        zero_pmkid = b"\x00" * 16
        padding = b"\x30" + b"\x00" * 10 + kde_marker + zero_pmkid
        result = self.mod._extract_pmkid(padding)
        assert result is None

    def test_scapy_ok_flag_exists(self):
        assert hasattr(self.mod, "SCAPY_OK")
        assert isinstance(self.mod.SCAPY_OK, bool)


# ===================================================================
# payloads.wifi.handshake_hunter
# ===================================================================

class TestHandshakeHunter:
    """Tests for payloads.wifi.handshake_hunter."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.wifi.handshake_hunter")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/Handshakes"
        assert self.mod.CHANNELS_24 == list(range(1, 14))
        assert self.mod.WIDTH == 128
        assert self.mod.HEIGHT == 128

    def test_pins_dict(self):
        assert self.mod.PINS["KEY3"] == 16
        assert len(self.mod.PINS) == 8

    def test_scapy_ok_flag(self):
        assert isinstance(self.mod.SCAPY_OK, bool)

    def test_initial_phase(self):
        # Phase should be a string
        assert isinstance(self.mod.phase, str)


# ===================================================================
# payloads.wifi.wpa_enterprise_evil
# ===================================================================

class TestWPAEnterpriseEvil:
    """Tests for payloads.wifi.wpa_enterprise_evil."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.wifi.wpa_enterprise_evil")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/EnterpriseEvilTwin"
        assert self.mod.RADIUS_PORT == 1812
        assert self.mod.RADIUS_SECRET == b"testing123"
        assert self.mod.GATEWAY_IP == "10.0.88.1"

    def test_eap_type_constants(self):
        assert self.mod.EAP_IDENTITY == 1
        assert self.mod.EAP_GTC == 6
        assert self.mod.EAP_MSCHAPV2 == 26

    def test_parse_radius_attrs_empty(self):
        result = self.mod._parse_radius_attrs(b"")
        assert result == {}

    def test_parse_radius_attrs_single_attr(self):
        # Type=1 (User-Name), Length=7, Value=b"hello"
        data = bytes([1, 7]) + b"hello"
        result = self.mod._parse_radius_attrs(data)
        assert 1 in result
        assert result[1][0] == b"hello"

    def test_parse_radius_attrs_multiple(self):
        # Two attributes
        attr1 = bytes([1, 6]) + b"user"
        attr2 = bytes([79, 5]) + b"eap"
        data = attr1 + attr2
        result = self.mod._parse_radius_attrs(data)
        assert 1 in result
        assert 79 in result

    def test_build_radius_accept_length(self):
        authenticator = b"\x00" * 16
        resp = self.mod._build_radius_accept(42, authenticator)
        # Access-Accept is 20 bytes
        assert len(resp) == 20
        assert resp[0] == self.mod.RADIUS_ACCESS_ACCEPT
        assert resp[1] == 42


# ===================================================================
# payloads.wifi.wps_pixie
# ===================================================================

class TestWPSPixie:
    """Tests for payloads.wifi.wps_pixie."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.wifi.wps_pixie")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/WPS"
        assert self.mod.ROWS_VISIBLE == 6

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8
        assert self.mod.PINS["OK"] == 13

    def test_initial_attack_mode(self):
        assert self.mod.attack_mode in ("pixie", "brute")

    def test_view_modes_initial(self):
        assert self.mod.view_mode == "scan"


# ===================================================================
# payloads.wifi.captive_portal
# ===================================================================

class TestCaptivePortal:
    """Tests for payloads.wifi.captive_portal."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.wifi.captive_portal")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/CaptivePortal"
        assert self.mod.GATEWAY_IP == "10.0.99.1"
        assert self.mod.PORTAL_PORT == 80

    def test_builtin_templates_dict(self):
        assert "WiFi Login" in self.mod.BUILTIN_TEMPLATES
        assert "Hotel WiFi" in self.mod.BUILTIN_TEMPLATES
        assert len(self.mod.BUILTIN_TEMPLATES) == 2

    def test_builtin_wifi_login_html(self):
        html = self.mod.BUILTIN_WIFI_LOGIN
        assert "<form" in html
        assert "password" in html

    def test_builtin_hotel_wifi_html(self):
        html = self.mod.BUILTIN_HOTEL_WIFI
        assert "Room Number" in html or "room" in html

    def test_ssid_chars_list(self):
        chars = self.mod.SSID_CHARS
        assert "A" in chars
        assert "0" in chars
        assert " " in chars
        assert len(chars) > 50

    def test_discover_templates_returns_list(self):
        result = self.mod._discover_templates()
        assert isinstance(result, list)
        # Should find at least the 2 built-in templates
        assert len(result) >= 2
        builtin_names = {t["name"] for t in result if t["builtin"]}
        assert "WiFi Login" in builtin_names
        assert "Hotel WiFi" in builtin_names

    def test_captive_handler_class_exists(self):
        assert hasattr(self.mod, "CaptiveHandler")
        assert hasattr(self.mod.CaptiveHandler, "_guess_content_type")

    def test_guess_content_type(self):
        handler_cls = self.mod.CaptiveHandler
        # Use an unbound approach -- _guess_content_type takes self + path
        instance = object.__new__(handler_cls)
        assert instance._guess_content_type("test.html") == "text/html"
        assert instance._guess_content_type("style.css") == "text/css"
        assert instance._guess_content_type("app.js") == "application/javascript"
        assert instance._guess_content_type("image.png") == "image/png"
        assert instance._guess_content_type("unknown.xyz") == "application/octet-stream"


# ===================================================================
# payloads.wifi.wifi_probe_dump
# ===================================================================

class TestWifiProbeDump:
    """Tests for payloads.wifi.wifi_probe_dump."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.wifi.wifi_probe_dump")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/ProbesDump"
        assert self.mod.CHANNELS_24 == list(range(1, 14))
        assert self.mod.ROWS_VISIBLE == 7

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8

    def test_scapy_ok_flag(self):
        assert isinstance(self.mod.SCAPY_OK, bool)

    def test_probes_dict_is_dict(self):
        assert isinstance(self.mod.probes, dict)

    def test_signal_map_is_dict(self):
        assert isinstance(self.mod.signal_map, dict)


# ===================================================================
# payloads.wifi.wifi_alert (GPIO at import — source-based)
# ===================================================================

class TestWifiAlert:
    """Tests for payloads.wifi.wifi_alert (source-based, has blocking import)."""

    def test_source_has_scapy_ok(self):
        src = _read_source("wifi_alert.py")
        assert "SCAPY_OK" in src

    def test_source_has_loot_dir(self):
        src = _read_source("wifi_alert.py")
        assert 'LOOT_DIR' in src
        assert "WiFiAlert" in src

    def test_source_has_send_discord(self):
        src = _read_source("wifi_alert.py")
        assert "def _send_discord" in src

    def test_source_has_main(self):
        src = _read_source("wifi_alert.py")
        assert "def main()" in src


# ===================================================================
# payloads.wifi.wifi_survey (GPIO at import — source-based)
# ===================================================================

class TestWifiSurvey:
    """Tests for payloads.wifi.wifi_survey (source-based, has blocking import)."""

    def test_source_has_scapy_ok(self):
        src = _read_source("wifi_survey.py")
        assert "SCAPY_OK" in src

    def test_source_has_views(self):
        src = _read_source("wifi_survey.py")
        assert "VIEWS" in src
        assert "SORT_MODES" in src

    def test_source_has_parse_encryption(self):
        src = _read_source("wifi_survey.py")
        assert "def _parse_encryption" in src

    def test_source_has_main(self):
        src = _read_source("wifi_survey.py")
        assert "def main()" in src


# ===================================================================
# payloads.wifi.ssid_pool (GPIO at import — source-based)
# ===================================================================

class TestSSIDPool:
    """Tests for payloads.wifi.ssid_pool (source-based, has blocking import)."""

    def test_source_has_scapy_ok(self):
        src = _read_source("ssid_pool.py")
        assert "SCAPY_OK" in src

    def test_source_has_default_ssids(self):
        src = _read_source("ssid_pool.py")
        assert "DEFAULT_SSIDS" in src

    def test_source_has_build_beacon(self):
        src = _read_source("ssid_pool.py")
        assert "def _build_beacon" in src

    def test_source_has_random_bssid(self):
        src = _read_source("ssid_pool.py")
        assert "def _random_bssid" in src


# ===================================================================
# payloads.wifi.wifi_handshake_auto (GPIO at import — source-based)
# ===================================================================

class TestWifiHandshakeAuto:
    """Tests for payloads.wifi.wifi_handshake_auto (source-based, has blocking import)."""

    def test_source_has_scapy_ok(self):
        src = _read_source("wifi_handshake_auto.py")
        assert "SCAPY_OK" in src

    def test_source_has_loot_dir(self):
        src = _read_source("wifi_handshake_auto.py")
        assert "LOOT_DIR" in src
        assert "Handshakes" in src

    def test_source_has_deauth_constants(self):
        src = _read_source("wifi_handshake_auto.py")
        assert "DEAUTH_TIMEOUT" in src
        assert "HANDSHAKE_EAPOL_MIN" in src

    def test_source_has_main(self):
        src = _read_source("wifi_handshake_auto.py")
        assert "def main()" in src
