#!/usr/bin/env python3
"""Unit tests for wardriving payload — parsers, merge, prune, GPS guard."""

import struct
import sys
import os
import time
import threading
from unittest.mock import MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(__file__, "..", "..")))

# Mock hardware modules not available outside RPi
_lcd_mock = MagicMock()
_lcd_mock.LCD_WIDTH = 128
_lcd_mock.LCD_HEIGHT = 128
_lcd_mock.SCAN_DIR_DFT = 0
for mod in ['RPi', 'RPi.GPIO', 'LCD_Config', 'spidev']:
    if mod not in sys.modules:
        sys.modules[mod] = MagicMock()
sys.modules['LCD_1in44'] = _lcd_mock

from payloads.reconnaissance.wardriving import (
    _parse_radiotap,
    _parse_80211_mgmt,
    _parse_ies,
    _merge_raw_network,
    _merge_raw_probe,
    _prune_networks,
    _ts_iso,
    _SUBTYPE_BEACON,
    _SUBTYPE_PROBE_REQ,
    _SUBTYPE_PROBE_RESP,
    networks,
    _seen_bssids,
    _insertion_order,
    _inc_sec_count,
    _inc_ch_count,
    _inc_wigle_count,
    total_beacons,
    probes,
    lock,
    MAX_NETWORKS,
)
import payloads.reconnaissance.wardriving as wd


# ---------------------------------------------------------------------------
# Helpers to build raw 802.11 frames
# ---------------------------------------------------------------------------

def _build_radiotap(signal_dbm=-50):
    """Minimal radiotap: version=0, present=flags+rate+signal (bits 1,2,5)."""
    present = (1 << 1) | (1 << 2) | (1 << 5)  # flags, rate, dBm signal
    hdr_len = 8 + 1 + 1 + 1  # 8 base + flags(1) + rate(1) + signal(1)
    hdr = struct.pack('<BBHI', 0, 0, hdr_len, present)
    hdr += struct.pack('B', 0x00)  # flags
    hdr += struct.pack('B', 0x02)  # rate
    hdr += struct.pack('b', signal_dbm)  # signal
    return hdr


def _mac_bytes(mac_str):
    return bytes.fromhex(mac_str.replace(":", ""))


def _build_mgmt_header(subtype, src_mac, bssid_mac):
    """Build 24-byte 802.11 management frame header."""
    fc = (subtype << 4) | (0 << 2)  # type=0 (mgmt), subtype
    hdr = struct.pack('<H', fc)
    hdr += b'\x00\x00'  # duration
    hdr += b'\xff\xff\xff\xff\xff\xff'  # addr1 (destination)
    hdr += _mac_bytes(src_mac)  # addr2 (source)
    hdr += _mac_bytes(bssid_mac)  # addr3 (BSSID)
    hdr += b'\x00\x00'  # seq ctrl
    return hdr


def _build_beacon_body(ssid="TestAP", channel=6):
    """Build beacon frame body: timestamp + interval + cap + IEs."""
    body = b'\x00' * 8  # timestamp
    body += struct.pack('<H', 100)  # beacon interval
    body += struct.pack('<H', 0x0431)  # capability (ESS+Privacy)
    # SSID IE
    ssid_bytes = ssid.encode('utf-8')
    body += struct.pack('BB', 0, len(ssid_bytes)) + ssid_bytes
    # DS Parameter Set IE (channel)
    body += struct.pack('BBB', 3, 1, channel)
    return body


def _build_beacon_frame(ssid="TestAP", channel=6, bssid="AA:BB:CC:DD:EE:FF", signal=-45):
    """Build a complete beacon frame with radiotap."""
    rtap = _build_radiotap(signal)
    mgmt = _build_mgmt_header(8, bssid, bssid)  # subtype 8 = beacon
    body = _build_beacon_body(ssid, channel)
    return rtap + mgmt + body


def _build_probe_req_frame(client_mac="11:22:33:44:55:66", ssid="LookingFor", signal=-60):
    """Build a probe request frame."""
    rtap = _build_radiotap(signal)
    mgmt = _build_mgmt_header(4, client_mac, "FF:FF:FF:FF:FF:FF")  # subtype 4
    body = b''
    ssid_bytes = ssid.encode('utf-8')
    body += struct.pack('BB', 0, len(ssid_bytes)) + ssid_bytes
    return rtap + mgmt + body


def _build_rsn_ie(akm_suite=b'\x00\x0f\xac\x02', cipher_suite=b'\x00\x0f\xac\x04'):
    """Build RSN IE (WPA2)."""
    ie = struct.pack('<H', 1)  # version
    ie += cipher_suite  # group cipher
    ie += struct.pack('<H', 1)  # pairwise count
    ie += cipher_suite  # pairwise cipher
    ie += struct.pack('<H', 1)  # AKM count
    ie += akm_suite  # AKM suite
    ie += struct.pack('<H', 0x000c)  # capabilities
    return struct.pack('BB', 48, len(ie)) + ie


def _build_wpa_ie():
    """Build WPA vendor IE."""
    oui = b'\x00\x50\xf2\x01'
    ie_data = oui + struct.pack('<H', 1) + b'\x00\x50\xf2\x02'
    return struct.pack('BB', 221, len(ie_data)) + ie_data


def _build_wps_ie():
    """Build WPS vendor IE."""
    oui = b'\x00\x50\xf2\x04'
    ie_data = oui + b'\x00\x00'
    return struct.pack('BB', 221, len(ie_data)) + ie_data


def _reset_globals():
    """Reset all global wardriving state for test isolation."""
    wd.networks.clear()
    wd._seen_bssids.clear()
    wd._insertion_order.clear()
    wd._inc_sec_count.clear()
    wd._inc_ch_count.clear()
    wd._inc_wigle_count = 0
    wd.total_beacons = 0
    wd.total_probes = 0
    wd.probes.clear()
    wd._dirty_bssids.clear()
    wd._recent_bssids.clear()
    wd._top_signals.clear()
    wd._gps_bssids.clear()
    wd._csv_buffer.clear()
    wd.gps_data = None


# ---------------------------------------------------------------------------
# Tests: _parse_radiotap
# ---------------------------------------------------------------------------

class TestParseRadiotap:
    def test_basic_signal(self):
        frame = _build_radiotap(signal_dbm=-42)
        hdr_len, signal = _parse_radiotap(frame)
        assert hdr_len == 11
        assert signal == -42

    def test_strong_signal(self):
        frame = _build_radiotap(signal_dbm=-20)
        _, signal = _parse_radiotap(frame)
        assert signal == -20

    def test_weak_signal(self):
        frame = _build_radiotap(signal_dbm=-90)
        _, signal = _parse_radiotap(frame)
        assert signal == -90

    def test_too_short(self):
        hdr_len, signal = _parse_radiotap(b'\x00\x00')
        assert hdr_len == 0
        assert signal == -99

    def test_empty(self):
        hdr_len, signal = _parse_radiotap(b'')
        assert hdr_len == 0
        assert signal == -99


# ---------------------------------------------------------------------------
# Tests: _parse_80211_mgmt
# ---------------------------------------------------------------------------

class TestParse80211Mgmt:
    def test_beacon(self):
        frame = _build_beacon_frame(bssid="AA:BB:CC:DD:EE:FF")
        rtap_len = struct.unpack_from('<H', frame, 2)[0]
        result = _parse_80211_mgmt(frame, rtap_len)
        assert result is not None
        assert result['subtype'] == _SUBTYPE_BEACON
        assert result['bssid'] == "AA:BB:CC:DD:EE:FF"

    def test_probe_request(self):
        frame = _build_probe_req_frame(client_mac="11:22:33:44:55:66")
        rtap_len = struct.unpack_from('<H', frame, 2)[0]
        result = _parse_80211_mgmt(frame, rtap_len)
        assert result is not None
        assert result['subtype'] == _SUBTYPE_PROBE_REQ
        assert result['sa'] == "11:22:33:44:55:66"

    def test_too_short(self):
        result = _parse_80211_mgmt(b'\x00' * 20, 10)
        assert result is None

    def test_data_frame_rejected(self):
        rtap = _build_radiotap(-50)
        fc = struct.pack('<H', (0 << 4) | (2 << 2))  # type=2 (data)
        frame = rtap + fc + b'\x00' * 22
        rtap_len = struct.unpack_from('<H', frame, 2)[0]
        result = _parse_80211_mgmt(frame, rtap_len)
        assert result is None


# ---------------------------------------------------------------------------
# Tests: _parse_ies
# ---------------------------------------------------------------------------

class TestParseIEs:
    def test_ssid_and_channel(self):
        body = b'\x00' * 12  # beacon fixed fields
        body += struct.pack('BB', 0, 6) + b'MyWiFi'  # SSID
        body += struct.pack('BBB', 3, 1, 11)  # DS channel 11
        result = _parse_ies(body, 12)
        assert result['ssid'] == 'MyWiFi'
        assert result['channel'] == 11
        assert result['security'] == 'Open'

    def test_hidden_ssid(self):
        body = b'\x00' * 12
        body += struct.pack('BB', 0, 0)  # empty SSID
        body += struct.pack('BBB', 3, 1, 6)
        result = _parse_ies(body, 12)
        assert result['ssid'] == ''
        assert result['channel'] == 6

    def test_wpa2_ccmp(self):
        body = b'\x00' * 12
        body += struct.pack('BB', 0, 4) + b'Test'
        body += _build_rsn_ie()
        result = _parse_ies(body, 12)
        assert result['security'] == 'WPA2-PSK'
        assert result['cipher'] == 'CCMP'

    def test_wpa3_sae(self):
        body = b'\x00' * 12
        body += struct.pack('BB', 0, 4) + b'Test'
        body += _build_rsn_ie(akm_suite=b'\x00\x0f\xac\x08')
        result = _parse_ies(body, 12)
        assert result['security'] == 'WPA3-SAE'

    def test_wpa_tkip(self):
        body = b'\x00' * 12
        body += struct.pack('BB', 0, 4) + b'Test'
        body += _build_wpa_ie()
        result = _parse_ies(body, 12)
        assert result['security'] == 'WPA'
        assert result['cipher'] == 'TKIP'

    def test_wps_detected(self):
        body = b'\x00' * 12
        body += struct.pack('BB', 0, 4) + b'Test'
        body += _build_wps_ie()
        result = _parse_ies(body, 12)
        assert result['wps'] is True

    def test_empty_body(self):
        result = _parse_ies(b'', 0)
        assert result['ssid'] == ''
        assert result['channel'] == 0
        assert result['security'] == 'Open'

    def test_truncated_ie(self):
        body = b'\x00' * 12
        body += struct.pack('BB', 0, 20)  # SSID length 20 but not enough data
        body += b'Short'
        result = _parse_ies(body, 12)
        assert result['ssid'] == ''  # truncated, should not crash


# ---------------------------------------------------------------------------
# Tests: _ts_iso
# ---------------------------------------------------------------------------

class TestTsIso:
    def test_float_timestamp(self):
        ts = 1700000000.0
        iso = _ts_iso(ts)
        assert '2023' in iso or '2024' in iso  # depends on TZ
        assert 'T' in iso

    def test_string_passthrough(self):
        iso = _ts_iso("2024-01-01T12:00:00")
        assert iso == "2024-01-01T12:00:00"


# ---------------------------------------------------------------------------
# Tests: _merge_raw_network
# ---------------------------------------------------------------------------

class TestMergeRawNetwork:
    def setup_method(self):
        _reset_globals()

    def test_new_network_added(self):
        _merge_raw_network("AA:BB:CC:DD:EE:01", "TestAP", 6, -45, "WPA2-PSK", "CCMP", False)
        assert "AA:BB:CC:DD:EE:01" in wd.networks
        net = wd.networks["AA:BB:CC:DD:EE:01"]
        assert net["ssid"] == "TestAP"
        assert net["channel"] == 6
        assert net["signal"] == -45
        assert net["security"] == "WPA2-PSK"
        assert net["beacon_count"] == 1

    def test_duplicate_updates(self):
        _merge_raw_network("AA:BB:CC:DD:EE:02", "AP1", 1, -50, "Open", "", False)
        _merge_raw_network("AA:BB:CC:DD:EE:02", "AP1", 1, -40, "Open", "", False)
        net = wd.networks["AA:BB:CC:DD:EE:02"]
        assert net["beacon_count"] == 2
        assert net["signal"] != -50  # signal averaged

    def test_seen_bssids_persists_after_prune(self):
        for i in range(10):
            _merge_raw_network(f"AA:BB:CC:DD:{i:02X}:00", f"AP{i}", 1, -50, "Open", "", False)
        assert len(wd._seen_bssids) == 10
        initial_seen = set(wd._seen_bssids)
        wd.MAX_NETWORKS = 5
        _prune_networks()
        assert len(wd.networks) <= 5
        assert wd._seen_bssids == initial_seen  # seen_bssids NOT pruned
        wd.MAX_NETWORKS = MAX_NETWORKS

    def test_hidden_ssid_filled(self):
        _merge_raw_network("AA:BB:CC:DD:EE:03", "", 6, -50, "Open", "", False)
        assert wd.networks["AA:BB:CC:DD:EE:03"]["ssid"] == "<hidden>"
        _merge_raw_network("AA:BB:CC:DD:EE:03", "RealName", 6, -45, "Open", "", False)
        assert wd.networks["AA:BB:CC:DD:EE:03"]["ssid"] == "RealName"

    def test_broadcast_ignored(self):
        _merge_raw_network("FF:FF:FF:FF:FF:FF", "Bad", 1, -50, "Open", "", False)
        assert "FF:FF:FF:FF:FF:FF" not in wd.networks

    def test_empty_bssid_ignored(self):
        _merge_raw_network("", "Bad", 1, -50, "Open", "", False)
        assert len(wd.networks) == 0

    def test_seen_blocks_readd(self):
        _merge_raw_network("AA:BB:CC:DD:EE:04", "AP", 1, -50, "Open", "", False)
        del wd.networks["AA:BB:CC:DD:EE:04"]  # simulate prune without clearing seen
        prev_beacons = wd.total_beacons
        _merge_raw_network("AA:BB:CC:DD:EE:04", "AP", 1, -50, "Open", "", False)
        assert "AA:BB:CC:DD:EE:04" not in wd.networks  # blocked by _seen_bssids
        assert wd.total_beacons == prev_beacons + 1  # counter still increments

    def test_counters_increment(self):
        _merge_raw_network("AA:BB:CC:DD:EE:05", "AP", 6, -50, "WPA2-PSK", "CCMP", False)
        assert wd._inc_sec_count.get("WPA2-PSK") == 1
        assert wd._inc_ch_count.get(6) == 1
        assert wd.total_beacons == 1

    def test_gps_staleness_rejected(self):
        wd.gps_data = {"lat": 48.85, "lon": 2.35, "alt": 35, "mode": 3, "ts": time.time() - 60}
        _merge_raw_network("AA:BB:CC:DD:EE:06", "AP", 1, -50, "Open", "", False)
        assert wd.networks["AA:BB:CC:DD:EE:06"]["gps"] is None  # stale GPS rejected

    def test_gps_valid_accepted(self):
        wd.gps_data = {"lat": 48.85, "lon": 2.35, "alt": 35, "mode": 3, "ts": time.time()}
        _merge_raw_network("AA:BB:CC:DD:EE:07", "AP", 1, -50, "Open", "", False)
        gps = wd.networks["AA:BB:CC:DD:EE:07"]["gps"]
        assert gps is not None
        assert gps["lat"] == 48.85

    def test_gps_no_fix_rejected(self):
        wd.gps_data = {"lat": 48.85, "lon": 2.35, "alt": 35, "mode": 1, "ts": time.time()}
        _merge_raw_network("AA:BB:CC:DD:EE:08", "AP", 1, -50, "Open", "", False)
        assert wd.networks["AA:BB:CC:DD:EE:08"]["gps"] is None

    def test_timestamps_are_floats(self):
        _merge_raw_network("AA:BB:CC:DD:EE:09", "AP", 1, -50, "Open", "", False)
        net = wd.networks["AA:BB:CC:DD:EE:09"]
        assert isinstance(net["first_seen"], float)
        assert isinstance(net["last_seen"], float)


# ---------------------------------------------------------------------------
# Tests: _merge_raw_probe
# ---------------------------------------------------------------------------

class TestMergeRawProbe:
    def setup_method(self):
        _reset_globals()

    def test_new_probe(self):
        _merge_raw_probe("11:22:33:44:55:66", "LookingFor", -60)
        assert "11:22:33:44:55:66" in wd.probes
        p = wd.probes["11:22:33:44:55:66"]
        assert "LookingFor" in p["ssids"]
        assert p["count"] == 1

    def test_probe_count_increments(self):
        _merge_raw_probe("11:22:33:44:55:77", "AP1", -60)
        _merge_raw_probe("11:22:33:44:55:77", "AP2", -55)
        p = wd.probes["11:22:33:44:55:77"]
        assert p["count"] == 2
        assert "AP1" in p["ssids"]
        assert "AP2" in p["ssids"]

    def test_broadcast_ignored(self):
        _merge_raw_probe("FF:FF:FF:FF:FF:FF", "Test", -50)
        assert "FF:FF:FF:FF:FF:FF" not in wd.probes


# ---------------------------------------------------------------------------
# Tests: _prune_networks
# ---------------------------------------------------------------------------

class TestPruneNetworks:
    def setup_method(self):
        _reset_globals()

    def test_prune_keeps_max(self):
        wd.MAX_NETWORKS = 10
        for i in range(15):
            _merge_raw_network(f"AA:BB:CC:{i:02X}:00:00", f"AP{i}", 1, -50, "Open", "", False)
        assert len(wd.networks) == 15
        _prune_networks()
        assert len(wd.networks) <= 10
        wd.MAX_NETWORKS = MAX_NETWORKS

    def test_prune_fifo_order(self):
        wd.MAX_NETWORKS = 5
        for i in range(8):
            _merge_raw_network(f"AA:BB:CC:{i:02X}:00:00", f"AP{i}", 1, -50, "Open", "", False)
        _prune_networks()
        remaining = list(wd.networks.keys())
        assert f"AA:BB:CC:00:00:00" not in remaining  # oldest evicted
        wd.MAX_NETWORKS = MAX_NETWORKS

    def test_seen_bssids_not_pruned(self):
        wd.MAX_NETWORKS = 5
        for i in range(8):
            bssid = f"AA:BB:CC:{i:02X}:00:00"
            _merge_raw_network(bssid, f"AP{i}", 1, -50, "Open", "", False)
        _prune_networks()
        assert len(wd._seen_bssids) == 8  # all 8 still in seen
        wd.MAX_NETWORKS = MAX_NETWORKS

    def test_counters_decremented(self):
        wd.MAX_NETWORKS = 3
        _merge_raw_network("AA:BB:CC:01:00:00", "AP1", 1, -50, "WPA2-PSK", "CCMP", False)
        _merge_raw_network("AA:BB:CC:02:00:00", "AP2", 6, -50, "Open", "", False)
        _merge_raw_network("AA:BB:CC:03:00:00", "AP3", 11, -50, "WPA2-PSK", "CCMP", False)
        _merge_raw_network("AA:BB:CC:04:00:00", "AP4", 1, -50, "Open", "", False)
        _prune_networks()
        total_sec = sum(wd._inc_sec_count.values())
        assert total_sec == len(wd.networks)
        wd.MAX_NETWORKS = MAX_NETWORKS

    def test_no_prune_under_limit(self):
        for i in range(5):
            _merge_raw_network(f"AA:BB:CC:{i:02X}:00:00", f"AP{i}", 1, -50, "Open", "", False)
        prev_len = len(wd.networks)
        _prune_networks()
        assert len(wd.networks) == prev_len


# ---------------------------------------------------------------------------
# Tests: Full frame parsing pipeline
# ---------------------------------------------------------------------------

class TestFullPipeline:
    def test_beacon_end_to_end(self):
        frame = _build_beacon_frame("MyNetwork", channel=11, bssid="DE:AD:BE:EF:00:01", signal=-55)
        rtap_len, signal = _parse_radiotap(frame)
        assert signal == -55
        mgmt = _parse_80211_mgmt(frame, rtap_len)
        assert mgmt['subtype'] == _SUBTYPE_BEACON
        assert mgmt['bssid'] == "DE:AD:BE:EF:00:01"
        ies = _parse_ies(frame, mgmt['body_offset'] + 12)
        assert ies['ssid'] == "MyNetwork"
        assert ies['channel'] == 11

    def test_probe_req_end_to_end(self):
        frame = _build_probe_req_frame("CA:FE:BA:BE:00:01", "SearchSSID", -70)
        rtap_len, signal = _parse_radiotap(frame)
        assert signal == -70
        mgmt = _parse_80211_mgmt(frame, rtap_len)
        assert mgmt['subtype'] == _SUBTYPE_PROBE_REQ
        assert mgmt['sa'] == "CA:FE:BA:BE:00:01"
        ies = _parse_ies(frame, mgmt['body_offset'])
        assert ies['ssid'] == "SearchSSID"


# ---------------------------------------------------------------------------
# Tests: Stress / Long-running stability
# ---------------------------------------------------------------------------

class TestStressStability:
    def setup_method(self):
        _reset_globals()

    def test_10k_unique_networks(self):
        wd.MAX_NETWORKS = 100
        for i in range(10000):
            bssid = f"{(i>>16)&0xFF:02X}:{(i>>8)&0xFF:02X}:{i&0xFF:02X}:00:00:00"
            _merge_raw_network(bssid, f"AP{i}", i % 13 + 1, -50, "Open", "", False)
            if len(wd.networks) > wd.MAX_NETWORKS:
                _prune_networks()
        assert len(wd.networks) <= wd.MAX_NETWORKS
        assert len(wd._seen_bssids) == 10000  # all kept
        wd.MAX_NETWORKS = MAX_NETWORKS

    def test_csv_buffer_bounded(self):
        wd.gps_data = {"lat": 48.85, "lon": 2.35, "alt": 35, "mode": 3, "ts": time.time()}
        for i in range(20000):
            bssid = f"{(i>>16)&0xFF:02X}:{(i>>8)&0xFF:02X}:{i&0xFF:02X}:00:00:00"
            _merge_raw_network(bssid, f"AP{i}", 1, -50, "Open", "", False)
        assert len(wd._csv_buffer) <= 10000  # bounded by maxlen
