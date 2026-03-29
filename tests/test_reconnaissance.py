"""
Unit tests for payloads in payloads/reconnaissance/.
"""

import importlib
import os
import ast

import pytest

PAYLOADS_DIR = os.path.join(
    os.path.dirname(__file__), os.pardir, "payloads", "reconnaissance"
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
# auto_recon.py
# =========================================================================
class TestAutoRecon:
    def test_import_smoke(self):
        mod = _safe_import("payloads.reconnaissance.auto_recon")
        assert mod is not None

    def test_get_subnet_24(self):
        mod = _safe_import("payloads.reconnaissance.auto_recon")
        result = mod._get_subnet("192.168.1.10/24")
        assert result == "192.168.1.0/24"

    def test_get_subnet_16(self):
        mod = _safe_import("payloads.reconnaissance.auto_recon")
        result = mod._get_subnet("10.0.5.2/16")
        assert result == "10.0.0.0/16"

    def test_get_subnet_none(self):
        mod = _safe_import("payloads.reconnaissance.auto_recon")
        assert mod._get_subnet(None) is None
        assert mod._get_subnet("192.168.1.1") is None

    def test_state_management(self):
        mod = _safe_import("payloads.reconnaissance.auto_recon")
        mod._set_state(phase="testing", host_count=5)
        st = mod._get_state()
        assert st["phase"] == "testing"
        assert st["host_count"] == 5

    def test_main_callable(self):
        mod = _safe_import("payloads.reconnaissance.auto_recon")
        assert callable(mod.main)


# =========================================================================
# arp_scan_stealth.py
# =========================================================================
class TestArpScanStealth:
    def test_import_smoke(self):
        mod = _safe_import("payloads.reconnaissance.arp_scan_stealth")
        assert mod is not None

    def test_random_mac_format(self):
        mod = _safe_import("payloads.reconnaissance.arp_scan_stealth")
        mac = mod._random_mac()
        parts = mac.split(":")
        assert len(parts) == 6
        # Locally administered bit
        first_byte = int(parts[0], 16)
        assert first_byte & 0x02

    def test_random_mac_uniqueness(self):
        mod = _safe_import("payloads.reconnaissance.arp_scan_stealth")
        macs = {mod._random_mac() for _ in range(50)}
        assert len(macs) > 40  # very unlikely to get many collisions

    def test_vendor_hint_callable(self):
        mod = _safe_import("payloads.reconnaissance.arp_scan_stealth")
        assert callable(mod._vendor_hint)
        # Unknown OUI returns empty string
        result = mod._vendor_hint("AA:BB:CC:DD:EE:FF")
        assert isinstance(result, str)

    def test_source_has_scan_thread(self):
        src = _read_source("arp_scan_stealth.py")
        assert "def _scan_thread" in src


# =========================================================================
# autoNmapScan.py
# =========================================================================
class TestAutoNmapScan:
    def test_import_smoke(self):
        mod = _safe_import("payloads.reconnaissance.autoNmapScan")
        assert mod is not None

    def test_current_target_callable(self):
        mod = _safe_import("payloads.reconnaissance.autoNmapScan")
        assert callable(mod.current_target)

    def test_show_function_exists(self):
        mod = _safe_import("payloads.reconnaissance.autoNmapScan")
        assert callable(mod.show)

    def test_source_has_nmap_scan(self):
        src = _read_source("autoNmapScan.py")
        assert "def nmap_scan" in src


# =========================================================================
# analyzer.py
# =========================================================================
class TestAnalyzer:
    def test_import_smoke(self):
        mod = _safe_import("payloads.reconnaissance.analyzer")
        assert mod is not None

    def test_hci_opcode(self):
        mod = _safe_import("payloads.reconnaissance.analyzer")
        opcode = mod._hci_opcode(0x08, 0x000B)
        assert isinstance(opcode, int)

    def test_rgb_function(self):
        mod = _safe_import("payloads.reconnaissance.analyzer")
        r, g, b = mod._rgb(0.5)
        assert 0 <= r <= 255
        assert 0 <= g <= 255
        assert 0 <= b <= 255

    def test_rgb_edge_cases(self):
        mod = _safe_import("payloads.reconnaissance.analyzer")
        r0, g0, b0 = mod._rgb(0.0)
        r1, g1, b1 = mod._rgb(1.0)
        assert all(0 <= v <= 255 for v in (r0, g0, b0, r1, g1, b1))

    def test_colstr(self):
        mod = _safe_import("payloads.reconnaissance.analyzer")
        result = mod._colstr((255, 128, 0))
        assert result.startswith("#")
        assert len(result) == 7

    def test_source_has_main(self):
        src = _read_source("analyzer.py")
        assert "def main" in src


# =========================================================================
# bt_scan_classic.py
# =========================================================================
class TestBtScanClassic:
    def test_import_smoke(self):
        mod = _safe_import("payloads.reconnaissance.bt_scan_classic")
        assert mod is not None

    def test_parse_scan_output_valid(self):
        mod = _safe_import("payloads.reconnaissance.bt_scan_classic")
        output = "AA:BB:CC:DD:EE:FF  My Device\n11:22:33:44:55:66  Other"
        result = mod._parse_scan_output(output)
        assert len(result) == 2
        assert result[0][0] == "AA:BB:CC:DD:EE:FF"
        assert result[0][1] == "My Device"

    def test_parse_scan_output_empty(self):
        mod = _safe_import("payloads.reconnaissance.bt_scan_classic")
        result = mod._parse_scan_output("")
        assert result == []

    def test_parse_sdp_output_services(self):
        mod = _safe_import("payloads.reconnaissance.bt_scan_classic")
        sdp_text = (
            "Service Name: OBEX Push\n"
            "Service Description: OBEX Object Push\n"
            "Channel: 12\n"
        )
        result = mod._parse_sdp_output(sdp_text)
        assert len(result) == 1
        assert result[0]["name"] == "OBEX Push"

    def test_parse_sdp_output_empty(self):
        mod = _safe_import("payloads.reconnaissance.bt_scan_classic")
        result = mod._parse_sdp_output("")
        assert result == []


# =========================================================================
# cam_finder.py
# =========================================================================
class TestCamFinder:
    def test_import_smoke(self):
        mod = _safe_import("payloads.reconnaissance.cam_finder")
        assert mod is not None

    def test_is_camera_mac_callable(self):
        mod = _safe_import("payloads.reconnaissance.cam_finder")
        assert callable(mod._is_camera_mac)

    def test_is_camera_ssid_callable(self):
        mod = _safe_import("payloads.reconnaissance.cam_finder")
        assert callable(mod._is_camera_ssid)

    def test_source_has_class(self):
        src = _read_source("cam_finder.py")
        assert "class CamFinderScanner" in src


# =========================================================================
# cert_scanner.py
# =========================================================================
class TestCertScanner:
    def test_import_smoke(self):
        mod = _safe_import("payloads.reconnaissance.cert_scanner")
        assert mod is not None

    def test_source_has_fetch_cert(self):
        src = _read_source("cert_scanner.py")
        assert "def _fetch_cert" in src

    def test_source_has_scan_host(self):
        src = _read_source("cert_scanner.py")
        assert "def _scan_host" in src

    def test_main_callable(self):
        mod = _safe_import("payloads.reconnaissance.cert_scanner")
        assert callable(mod.main)


# =========================================================================
# device_scout.py
# =========================================================================
class TestDeviceScout:
    def test_import_smoke(self):
        mod = _safe_import("payloads.reconnaissance.device_scout")
        assert mod is not None

    def test_hci_opcode(self):
        mod = _safe_import("payloads.reconnaissance.device_scout")
        opcode = mod._hci_opcode(0x08, 0x000B)
        assert isinstance(opcode, int)

    def test_is_onboard_wifi_iface(self):
        mod = _safe_import("payloads.reconnaissance.device_scout")
        assert callable(mod._is_onboard_wifi_iface)

    def test_source_has_export(self):
        src = _read_source("device_scout.py")
        assert "def export_data" in src


# =========================================================================
# dns_leaker.py
# =========================================================================
class TestDnsLeaker:
    def test_import_smoke(self):
        mod = _safe_import("payloads.reconnaissance.dns_leaker")
        assert mod is not None

    def test_normalize_function(self):
        mod = _safe_import("payloads.reconnaissance.dns_leaker")
        result = mod.normalize("Example.COM.")
        assert result == "example.com"

    def test_source_has_log_line(self):
        src = _read_source("dns_leaker.py")
        assert "def log_line" in src


# =========================================================================
# gatt_enum.py
# =========================================================================
class TestGattEnum:
    def test_source_exists(self):
        src = _read_source("gatt_enum.py")
        assert "def main" in src or "def run" in src or len(src) > 100

    def test_import_smoke(self):
        mod = _safe_import("payloads.reconnaissance.gatt_enum")
        assert mod is not None


# =========================================================================
# honeypot.py
# =========================================================================
class TestHoneypot:
    def test_import_smoke(self):
        mod = _safe_import("payloads.reconnaissance.honeypot")
        assert mod is not None

    def test_source_has_main(self):
        src = _read_source("honeypot.py")
        assert "def main" in src

    def test_source_has_handler(self):
        src = _read_source("honeypot.py")
        assert "def " in src  # at least has functions


# =========================================================================
# mac_lookup.py
# =========================================================================
class TestMacLookup:
    def test_import_smoke(self):
        mod = _safe_import("payloads.reconnaissance.mac_lookup")
        assert mod is not None

    def test_source_has_main(self):
        src = _read_source("mac_lookup.py")
        assert "def main" in src


# =========================================================================
# navarro.py
# =========================================================================
class TestNavarro:
    def test_import_smoke(self):
        mod = _safe_import("payloads.reconnaissance.navarro")
        assert mod is not None

    def test_source_has_main(self):
        src = _read_source("navarro.py")
        assert "def main" in src


# =========================================================================
# network_mapper.py
# =========================================================================
class TestNetworkMapper:
    def test_import_smoke(self):
        mod = _safe_import("payloads.reconnaissance.network_mapper")
        assert mod is not None

    def test_source_has_main(self):
        src = _read_source("network_mapper.py")
        assert "def main" in src


# =========================================================================
# passive_os_detect.py
# =========================================================================
class TestPassiveOsDetect:
    def test_import_smoke(self):
        mod = _safe_import("payloads.reconnaissance.passive_os_detect")
        assert mod is not None

    def test_initial_ttl(self):
        mod = _safe_import("payloads.reconnaissance.passive_os_detect")
        assert mod._initial_ttl(60) == 64
        assert mod._initial_ttl(64) == 64
        assert mod._initial_ttl(120) == 128
        assert mod._initial_ttl(128) == 128
        assert mod._initial_ttl(250) == 255

    def test_classify_returns_tuple(self):
        mod = _safe_import("payloads.reconnaissance.passive_os_detect")
        os_name, confidence = mod._classify(ttl=64, win=65535, mss=1460, df_bit=True)
        assert isinstance(os_name, str)
        assert isinstance(confidence, int)
        assert 0 <= confidence <= 100

    def test_extract_mss_empty(self):
        mod = _safe_import("payloads.reconnaissance.passive_os_detect")
        assert mod._extract_mss(None) == 0
        assert mod._extract_mss([]) == 0

    def test_extract_mss_found(self):
        mod = _safe_import("payloads.reconnaissance.passive_os_detect")
        assert mod._extract_mss([("MSS", 1460)]) == 1460


# =========================================================================
# service_banner.py
# =========================================================================
class TestServiceBanner:
    def test_import_smoke(self):
        mod = _safe_import("payloads.reconnaissance.service_banner")
        assert mod is not None

    def test_identify_service(self):
        mod = _safe_import("payloads.reconnaissance.service_banner")
        result = mod._identify_service(80, "HTTP/1.1 200 OK")
        assert isinstance(result, str)

    def test_identify_service_ssh(self):
        mod = _safe_import("payloads.reconnaissance.service_banner")
        result = mod._identify_service(22, "SSH-2.0-OpenSSH_8.9")
        assert "ssh" in result.lower() or "SSH" in result

    def test_source_has_grab_banner(self):
        src = _read_source("service_banner.py")
        assert "def _grab_banner" in src


# =========================================================================
# smb_probe.py
# =========================================================================
class TestSmbProbe:
    def test_import_smoke(self):
        mod = _safe_import("payloads.reconnaissance.smb_probe")
        assert mod is not None

    def test_parse_hosts_from_nmap(self):
        mod = _safe_import("payloads.reconnaissance.smb_probe")
        assert callable(mod.parse_hosts_from_nmap)

    def test_list_interfaces_callable(self):
        mod = _safe_import("payloads.reconnaissance.smb_probe")
        assert callable(mod.list_interfaces)

    def test_source_has_main(self):
        src = _read_source("smb_probe.py")
        assert "def main" in src


# =========================================================================
# wall_of_flippers.py
# =========================================================================
class TestWallOfFlippers:
    def test_import_smoke(self):
        mod = _safe_import("payloads.reconnaissance.wall_of_flippers")
        assert mod is not None

    def test_match_packet_exact(self):
        mod = _safe_import("payloads.reconnaissance.wall_of_flippers")
        assert mod._match_packet("abcdef", "abcdef") is True

    def test_match_packet_wildcard(self):
        mod = _safe_import("payloads.reconnaissance.wall_of_flippers")
        assert mod._match_packet("abcdef", "a_c_ef") is True

    def test_match_packet_mismatch(self):
        mod = _safe_import("payloads.reconnaissance.wall_of_flippers")
        assert mod._match_packet("abcdef", "xbcdef") is False

    def test_short_truncation(self):
        mod = _safe_import("payloads.reconnaissance.wall_of_flippers")
        assert mod._short("hello world", 5) == "hell."
        assert mod._short("hi", 5) == "hi"

    def test_mac_tail(self):
        mod = _safe_import("payloads.reconnaissance.wall_of_flippers")
        result = mod._mac_tail("AA:BB:CC:DD:EE:FF")
        assert len(result) == 8

    def test_age_text(self):
        import time as _time
        mod = _safe_import("payloads.reconnaissance.wall_of_flippers")
        result = mod._age_text(int(_time.time()))
        assert "s" in result or "m" in result


# =========================================================================
# wardriving.py
# =========================================================================
class TestWardriving:
    def test_import_smoke(self):
        mod = _safe_import("payloads.reconnaissance.wardriving")
        assert mod is not None

    def test_source_has_class(self):
        src = _read_source("wardriving.py")
        assert "class WardrivingScanner" in src

    def test_source_has_main(self):
        src = _read_source("wardriving.py")
        assert "def main" in src


# =========================================================================
# whois_lookup.py
# =========================================================================
class TestWhoisLookup:
    def test_import_smoke(self):
        mod = _safe_import("payloads.reconnaissance.whois_lookup")
        assert mod is not None

    def test_is_public_ip_rfc1918(self):
        mod = _safe_import("payloads.reconnaissance.whois_lookup")
        assert mod._is_public_ip("10.0.0.1") is False
        assert mod._is_public_ip("172.16.0.1") is False
        assert mod._is_public_ip("192.168.1.1") is False

    def test_is_public_ip_loopback(self):
        mod = _safe_import("payloads.reconnaissance.whois_lookup")
        assert mod._is_public_ip("127.0.0.1") is False

    def test_is_public_ip_valid(self):
        mod = _safe_import("payloads.reconnaissance.whois_lookup")
        assert mod._is_public_ip("8.8.8.8") is True
        assert mod._is_public_ip("1.1.1.1") is True

    def test_is_public_ip_multicast(self):
        mod = _safe_import("payloads.reconnaissance.whois_lookup")
        assert mod._is_public_ip("224.0.0.1") is False

    def test_parse_whois_org(self):
        mod = _safe_import("payloads.reconnaissance.whois_lookup")
        raw = "OrgName: Google LLC\nCountry: US\n"
        result = mod._parse_whois(raw)
        assert isinstance(result, dict) or isinstance(result, tuple)

    def test_find_regional_server(self):
        mod = _safe_import("payloads.reconnaissance.whois_lookup")
        resp = "refer: whois.arin.net\n"
        result = mod._find_regional_server(resp)
        assert result == "whois.arin.net"


# =========================================================================
# wifi_client_map.py
# =========================================================================
class TestWifiClientMap:
    def test_import_smoke(self):
        mod = _safe_import("payloads.reconnaissance.wifi_client_map")
        assert mod is not None

    def test_is_onboard_wifi_iface(self):
        mod = _safe_import("payloads.reconnaissance.wifi_client_map")
        assert callable(mod._is_onboard_wifi_iface)

    def test_source_has_main(self):
        src = _read_source("wifi_client_map.py")
        assert "def main" in src

    def test_source_has_sniffer(self):
        src = _read_source("wifi_client_map.py")
        assert "def _sniffer_thread" in src


# =========================================================================
# subnet_mapper.py (GPIO at import — source-based)
# =========================================================================
class TestSubnetMapper:
    def test_source_has_loot_dir(self):
        src = _read_source("subnet_mapper.py")
        assert "LOOT_DIR" in src
        assert "SubnetMap" in src

    def test_source_has_os_from_ttl(self):
        src = _read_source("subnet_mapper.py")
        assert "def _os_from_ttl" in src

    def test_source_has_arp_scan(self):
        src = _read_source("subnet_mapper.py")
        assert "def _arp_scan" in src

    def test_source_has_main(self):
        src = _read_source("subnet_mapper.py")
        assert "def main()" in src


# =========================================================================
# ad_recon.py (GPIO at import — source-based)
# =========================================================================
class TestAdRecon:
    def test_source_has_loot_dir(self):
        src = _read_source("ad_recon.py")
        assert "LOOT_DIR" in src
        assert "ADRecon" in src

    def test_source_has_views(self):
        src = _read_source("ad_recon.py")
        assert "VIEWS" in src
        assert "domain" in src

    def test_source_has_ber_helpers(self):
        src = _read_source("ad_recon.py")
        assert "def _ber_length" in src
        assert "def _ber_seq" in src

    def test_source_has_main(self):
        src = _read_source("ad_recon.py")
        assert "def main()" in src


# =========================================================================
# sniff_creds_live.py (GPIO at import — source-based)
# =========================================================================
class TestSniffCredsLive:
    def test_source_has_loot_dir(self):
        src = _read_source("sniff_creds_live.py")
        assert "LOOT_DIR" in src
        assert "CredDashboard" in src

    def test_source_has_protocols(self):
        src = _read_source("sniff_creds_live.py")
        assert "PROTOCOLS" in src

    def test_source_has_parse_responder(self):
        src = _read_source("sniff_creds_live.py")
        assert "def _parse_responder" in src

    def test_source_has_main(self):
        src = _read_source("sniff_creds_live.py")
        assert "def main()" in src


# =========================================================================
# cctv_scanner.py (GPIO at import — source-based)
# =========================================================================
class TestCCTVScanner:
    def test_source_has_loot_dir(self):
        src = _read_source("cctv_scanner.py")
        assert "LOOT_DIR" in src
        assert "CCTV" in src

    def test_source_has_camera_ports(self):
        src = _read_source("cctv_scanner.py")
        assert "CAMERA_PORTS" in src

    def test_source_has_default_creds(self):
        src = _read_source("cctv_scanner.py")
        assert "DEFAULT_CREDS" in src

    def test_source_has_main(self):
        src = _read_source("cctv_scanner.py")
        assert "def main()" in src


# =========================================================================
# cctv_viewer.py (GPIO at import — source-based)
# =========================================================================
class TestCCTVViewer:
    def test_source_has_live_file(self):
        src = _read_source("cctv_viewer.py")
        assert "LIVE_FILE" in src

    def test_source_has_stream_mjpeg(self):
        src = _read_source("cctv_viewer.py")
        assert "def _stream_mjpeg" in src

    def test_source_has_take_screenshot(self):
        src = _read_source("cctv_viewer.py")
        assert "def _take_screenshot" in src

    def test_source_has_main(self):
        src = _read_source("cctv_viewer.py")
        assert "def main()" in src


# =========================================================================
# spycam_detector.py (GPIO at import — source-based)
# =========================================================================
class TestSpycamDetector:
    def test_source_has_loot_dir(self):
        src = _read_source("spycam_detector.py")
        assert "LOOT_DIR" in src
        assert "SpyCam" in src

    def test_source_has_ssid_patterns(self):
        src = _read_source("spycam_detector.py")
        assert "SSID_PATTERNS" in src

    def test_source_has_camera_ouis(self):
        src = _read_source("spycam_detector.py")
        assert "CAMERA_OUIS" in src

    def test_source_has_rssi_to_distance(self):
        src = _read_source("spycam_detector.py")
        assert "def _rssi_to_distance" in src
