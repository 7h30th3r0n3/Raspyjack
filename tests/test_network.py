"""
Unit tests for Network payloads.

Each payload is imported via importlib to gracefully handle import-time
side-effects (os.makedirs to /root, subprocess calls, etc.) that would
fail on a dev machine.
"""

import importlib
import struct
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
# payloads.network.dhcp_starve
# ===================================================================

class TestDHCPStarve:
    """Tests for payloads.network.dhcp_starve."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.dhcp_starve")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_pins_dict(self):
        expected = {"UP", "DOWN", "LEFT", "RIGHT", "OK", "KEY1", "KEY2", "KEY3"}
        assert set(self.mod.PINS.keys()) == expected

    def test_speed_modes(self):
        assert self.mod.SPEED_MODES == ["fast", "slow"]
        assert "fast" in self.mod.SPEED_DELAYS
        assert "slow" in self.mod.SPEED_DELAYS
        assert self.mod.SPEED_DELAYS["fast"] < self.mod.SPEED_DELAYS["slow"]

    def test_random_mac_bytes_length(self):
        mac = self.mod._random_mac_bytes()
        assert isinstance(mac, bytes)
        assert len(mac) == 6

    def test_random_mac_bytes_locally_administered(self):
        mac = self.mod._random_mac_bytes()
        # Locally administered bit set, unicast bit clear
        assert mac[0] & 0x02 == 0x02
        assert mac[0] & 0x01 == 0x00

    def test_random_mac_str_format(self):
        mac_bytes = b"\x02\xAB\xCD\xEF\x12\x34"
        result = self.mod._random_mac_str(mac_bytes)
        assert result == "02:ab:cd:ef:12:34"

    def test_random_hostname_format(self):
        hostname = self.mod._random_hostname()
        assert isinstance(hostname, str)
        assert "-" in hostname
        prefix = hostname.split("-")[0]
        assert prefix in ["PC", "LAPTOP", "DESKTOP", "PHONE", "IPAD", "WORK"]

    def test_scapy_ok_flag(self):
        assert isinstance(self.mod.SCAPY_OK, bool)


# ===================================================================
# payloads.network.mdns_poison
# ===================================================================

class TestMDNSPoison:
    """Tests for payloads.network.mdns_poison."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.mdns_poison")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.MDNS_ADDR == "224.0.0.251"
        assert self.mod.MDNS_PORT == 5353

    def test_services_list(self):
        services = self.mod.SERVICES
        assert isinstance(services, list)
        assert len(services) == 5
        for svc in services:
            assert "name" in svc
            assert "label" in svc
            assert "enabled" in svc
            assert svc["name"].endswith(".local.")

    def test_enabled_service_names_returns_set(self):
        result = self.mod._enabled_service_names()
        assert isinstance(result, set)
        # All services enabled by default
        assert len(result) == 5

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8


# ===================================================================
# payloads.network.ipv6_ra_attack
# ===================================================================

class TestIPv6RAAttack:
    """Tests for payloads.network.ipv6_ra_attack."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.ipv6_ra_attack")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.ROWS_VISIBLE == 6
        assert self.mod.WIDTH == 128

    def test_prefixes_list(self):
        prefixes = self.mod.PREFIXES
        assert isinstance(prefixes, list)
        assert len(prefixes) == 5
        for p in prefixes:
            assert "::" in p

    def test_pins_dict(self):
        assert self.mod.PINS["KEY3"] == 16

    def test_initial_state(self):
        assert isinstance(self.mod.victims, dict)
        assert self.mod.iface == "eth0"


# ===================================================================
# payloads.network.vlan_hopper
# ===================================================================

class TestVLANHopper:
    """Tests for payloads.network.vlan_hopper."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.vlan_hopper")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/VLANHop"
        assert self.mod.DTP_MULTICAST == "01:00:0c:cc:cc:cc"
        assert self.mod.DTP_SNAP_CODE == 0x2004

    def test_initial_state(self):
        assert self.mod.mode in ("double-tag", "dtp")
        assert self.mod.native_vlan == 1
        assert self.mod.target_vlan == 100
        assert self.mod.iface == "eth0"

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8


# ===================================================================
# payloads.network.stp_root_claim
# ===================================================================

class TestSTPRootClaim:
    """Tests for payloads.network.stp_root_claim."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.stp_root_claim")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.STP_MULTICAST == "01:80:c2:00:00:00"

    def test_mac_to_bytes(self):
        result = self.mod._mac_to_bytes("AA:BB:CC:DD:EE:FF")
        assert result == b"\xAA\xBB\xCC\xDD\xEE\xFF"

    def test_mac_to_bytes_lowercase(self):
        result = self.mod._mac_to_bytes("aa:bb:cc:dd:ee:ff")
        assert result == b"\xAA\xBB\xCC\xDD\xEE\xFF"

    def test_parse_bpdu_valid(self):
        # Build a minimal valid BPDU payload (35+ bytes)
        mac = b"\x11\x22\x33\x44\x55\x66"
        payload = (
            struct.pack("!H", 0x0000)  # protocol_id
            + bytes([0x00])             # version
            + bytes([0x00])             # bpdu_type
            + bytes([0x01])             # flags
            + struct.pack("!H", 32768) + mac  # root ID
            + struct.pack("!I", 100)          # root cost
            + struct.pack("!H", 32768) + mac  # bridge ID
            + struct.pack("!H", 0x8001)       # port ID
            + struct.pack("!H", 0)            # message age
            + struct.pack("!H", 20 * 256)     # max age
            + struct.pack("!H", 2 * 256)      # hello time
            + struct.pack("!H", 15 * 256)     # forward delay
        )
        result = self.mod._parse_bpdu(payload)
        assert result is not None
        assert result["root_priority"] == 32768
        assert result["root_mac"] == "11:22:33:44:55:66"
        assert result["root_cost"] == 100
        assert result["bridge_priority"] == 32768

    def test_parse_bpdu_too_short(self):
        result = self.mod._parse_bpdu(b"\x00" * 10)
        assert result is None

    def test_parse_bpdu_bad_protocol_id(self):
        payload = struct.pack("!H", 0x0001) + b"\x00" * 40
        result = self.mod._parse_bpdu(payload)
        assert result is None


# ===================================================================
# payloads.network.nac_bypass
# ===================================================================

class TestNACBypass:
    """Tests for payloads.network.nac_bypass."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.nac_bypass")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/NACBypass"
        assert self.mod.BRIDGE == "br0"
        assert self.mod.ROWS_VISIBLE == 7

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8
        assert self.mod.PINS["KEY3"] == 16

    def test_initial_state(self):
        assert self.mod.bridge_state == "down"


# ===================================================================
# payloads.network.arp_mitm
# ===================================================================

class TestArpMitm:
    """Tests for payloads.network.arp_mitm."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.arp_mitm")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/ArpMitm"
        assert self.mod.ROWS_VISIBLE == 6
        assert self.mod.ARP_INTERVAL == 2

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8

    def test_initial_state(self):
        assert isinstance(self.mod.hosts, list)
        assert self.mod.view_mode == "hosts"


# ===================================================================
# payloads.network.wpad_proxy
# ===================================================================

class TestWPADProxy:
    """Tests for payloads.network.wpad_proxy."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.wpad_proxy")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/WPAD"
        assert self.mod.PROXY_PORT == 8888
        assert self.mod.WPAD_PORT == 80
        assert self.mod.GATEWAY_IP == "10.0.77.1"

    def test_make_pac_contains_proxy(self):
        pac = self.mod._make_pac("192.168.1.100")
        assert "FindProxyForURL" in pac
        assert "192.168.1.100" in pac
        assert str(self.mod.PROXY_PORT) in pac
        assert "DIRECT" in pac

    def test_make_pac_localhost_direct(self):
        pac = self.mod._make_pac("10.0.0.1")
        assert "localhost" in pac
        assert "127.0.0.1" in pac

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8


# ===================================================================
# payloads.network.ssdp_spoof
# ===================================================================

class TestSSDPSpoof:
    """Tests for payloads.network.ssdp_spoof."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.ssdp_spoof")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.SSDP_ADDR == "239.255.255.250"
        assert self.mod.SSDP_PORT == 1900
        assert self.mod.HTTP_PORT == 8089
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/SSDP"

    def test_device_types_structure(self):
        types = self.mod.DEVICE_TYPES
        assert isinstance(types, list)
        assert len(types) == 3
        for dt in types:
            assert "name" in dt
            assert "st" in dt
            assert "friendly" in dt
            assert "manufacturer" in dt
            assert "model" in dt

    def test_build_device_xml(self):
        device = self.mod.DEVICE_TYPES[0]
        xml = self.mod._build_device_xml(device, "192.168.1.1")
        assert "<?xml" in xml
        assert device["friendly"] in xml
        assert device["manufacturer"] in xml
        assert "192.168.1.1" in xml

    def test_build_login_page(self):
        device = self.mod.DEVICE_TYPES[0]
        html = self.mod._build_login_page(device)
        assert "<form" in html
        assert "password" in html
        assert device["model"] in html

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8


# ===================================================================
# payloads.network.llmnr_query_inject
# ===================================================================

class TestLLMNRQueryInject:
    """Tests for payloads.network.llmnr_query_inject."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.llmnr_query_inject")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LLMNR_MCAST == "224.0.0.252"
        assert self.mod.LLMNR_PORT == 5355
        assert self.mod.NBTNS_BCAST == "255.255.255.255"
        assert self.mod.NBTNS_PORT == 137

    def test_hostnames_list(self):
        assert isinstance(self.mod.HOSTNAMES, list)
        assert len(self.mod.HOSTNAMES) == 20
        assert "WPAD" in self.mod.HOSTNAMES
        assert "ISATAP" in self.mod.HOSTNAMES

    def test_protocols_list(self):
        assert self.mod.PROTOCOLS == ["LLMNR", "NBT-NS", "Both"]

    def test_encode_nbtns_name_length(self):
        result = self.mod._encode_nbtns_name("WPAD")
        # 16 chars, each encoded as 2 bytes = 32 bytes
        assert len(result) == 32

    def test_encode_nbtns_name_uppercase(self):
        result1 = self.mod._encode_nbtns_name("wpad")
        result2 = self.mod._encode_nbtns_name("WPAD")
        assert result1 == result2

    def test_encode_nbtns_name_padding(self):
        # Short name should be padded to 16 chars with spaces
        result = self.mod._encode_nbtns_name("A")
        assert len(result) == 32
        # First char 'A' (0x41): encoded as 0x41 + (0x41 >> 4), 0x41 + (0x41 & 0x0F)
        # = 0x45, 0x42
        assert result[0] == 0x45
        assert result[1] == 0x42

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8


# ===================================================================
# payloads.network.silent_bridge
# ===================================================================

class TestSilentBridge:
    """Tests for payloads.network.silent_bridge."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.silent_bridge")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.BRIDGE == "br0"
        assert self.mod.WIDTH == 128
        assert self.mod.HEIGHT == 128
        assert self.mod.REFRESH_SEC == 1.0

    def test_proto_list(self):
        assert isinstance(self.mod.PROTO_LIST, list)
        assert "DNS" in self.mod.PROTO_LIST
        assert "HTTP" in self.mod.PROTO_LIST
        assert "TLS" in self.mod.PROTO_LIST
        assert len(self.mod.PROTO_LIST) == 14

    def test_map_proto_dns(self):
        assert self.mod._map_proto("DNS") == "DNS"
        assert self.mod._map_proto("  dns  ") == "DNS"

    def test_map_proto_http(self):
        assert self.mod._map_proto("HTTP") == "HTTP"

    def test_map_proto_tls(self):
        assert self.mod._map_proto("TLS") == "TLS"
        assert self.mod._map_proto("SSL") == "TLS"

    def test_map_proto_smb_variants(self):
        assert self.mod._map_proto("SMB") == "SMB"
        assert self.mod._map_proto("SMB2") == "SMB"
        assert self.mod._map_proto("NBSS") == "SMB"

    def test_map_proto_dhcp_bootp(self):
        assert self.mod._map_proto("DHCP") == "DHCP"
        assert self.mod._map_proto("BOOTP") == "DHCP"

    def test_map_proto_unknown(self):
        assert self.mod._map_proto("UNKNOWN_PROTO") is None
        assert self.mod._map_proto("") is None

    def test_map_proto_all_known(self):
        known = {
            "DNS": "DNS", "HTTP": "HTTP", "TLS": "TLS", "ICMP": "ICMP",
            "ARP": "ARP", "SMB": "SMB", "FTP": "FTP", "SSH": "SSH",
            "DHCP": "DHCP", "NTP": "NTP", "QUIC": "QUIC", "SMTP": "SMTP",
            "SNMP": "SNMP", "RDP": "RDP",
        }
        for raw_input, expected in known.items():
            assert self.mod._map_proto(raw_input) == expected

    def test_sort_ifaces(self):
        ifaces = ["usb0", "enp3s0", "eth0", "wlan0"]
        result = self.mod._sort_ifaces(ifaces)
        assert result[0] == "eth0"
        assert result[1] == "enp3s0"
        assert result[2] == "usb0"


# ===================================================================
# payloads.network.rogue_dhcp_wpad
# ===================================================================

class TestRogueDHCPWpad:
    """Tests for payloads.network.rogue_dhcp_wpad."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.rogue_dhcp_wpad")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/DHCP"
        assert self.mod.WPAD_DIR == "/tmp/raspyjack_wpad"
        assert self.mod.WIDTH == 128
        assert self.mod.HEIGHT == 128

    def test_clean_token(self):
        assert self.mod._clean_token("hello-world_1.0") == "hello-world_1.0"
        assert self.mod._clean_token("bad;chars&here") == "badcharshere"
        assert self.mod._clean_token("http://ok.com") == "http://ok.com"

    def test_sanitize_iface(self):
        assert self.mod._sanitize_iface("eth0") == "eth0"
        assert self.mod._sanitize_iface("wlan-1") == "wlan-1"
        assert self.mod._sanitize_iface("bad;iface") == "badiface"
        assert self.mod._sanitize_iface("eth_0") == "eth_0"

    def test_write_wpad_file(self, tmp_path, monkeypatch):
        # Redirect WPAD_DIR to a temp location
        wpad_dir = str(tmp_path / "wpad")
        monkeypatch.setattr(self.mod, "WPAD_DIR", wpad_dir)
        result = self.mod.write_wpad_file("10.0.0.1")
        assert result.endswith("wpad.dat")
        import os
        assert os.path.isfile(result)
        with open(result) as f:
            content = f.read()
        assert "FindProxyForURL" in content
        assert "DIRECT" in content

    def test_write_dnsmasq_conf(self, tmp_path, monkeypatch):
        result = self.mod.write_dnsmasq_conf(
            "eth0", "10.0.0.1", "10.0.0.10", "10.0.0.250",
            "http://10.0.0.1/wpad.dat", "/tmp/test.log",
        )
        assert result.endswith(".conf")
        import os
        assert os.path.isfile(result)
        with open(result) as f:
            content = f.read()
        assert "interface=eth0" in content
        assert "dhcp-option=252" in content
        assert "10.0.0.1" in content


# ===================================================================
# payloads.network.cdp_spoof
# ===================================================================

class TestCDPSpoof:
    """Tests for payloads.network.cdp_spoof."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.cdp_spoof")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/CDPSpoof"
        assert self.mod.CDP_MULTICAST == "01:00:0c:cc:cc:cc"
        assert self.mod.LLDP_MULTICAST == "01:80:c2:00:00:0e"
        assert self.mod.LLDP_ETHERTYPE == 0x88CC
        assert self.mod.CDP_INTERVAL == 30

    def test_modes_list(self):
        assert self.mod.MODES == ["Switch", "VoIP", "Custom"]

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8

    def test_build_cdp_tlv(self):
        tlv = self.mod._build_cdp_tlv(0x0001, b"hello")
        assert len(tlv) == 4 + 5
        tlv_type, tlv_len = struct.unpack("!HH", tlv[:4])
        assert tlv_type == 0x0001
        assert tlv_len == 9
        assert tlv[4:] == b"hello"

    def test_cdp_checksum(self):
        result = self.mod._cdp_checksum(b"\x00\x00")
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFF


# ===================================================================
# payloads.network.arp_dos
# ===================================================================

class TestARPDoS:
    """Tests for payloads.network.arp_dos."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.arp_dos")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.SPEED_LEVELS == [10, 50, 100, 500, 1000]
        assert self.mod.SPEED_NAMES == ["10/s", "50/s", "100/s", "500/s", "1000/s"]
        assert self.mod.IFACE_CHOICES == ["eth0", "wlan0"]
        assert self.mod.CAM_ESTIMATE == 8192

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8

    def test_get_subnet_base(self):
        assert self.mod._get_subnet_base("192.168.1.50") == "192.168.1"
        assert self.mod._get_subnet_base("10.0.0.1") == "10.0.0"

    def test_random_mac_format(self):
        mac = self.mod._random_mac()
        parts = mac.split(":")
        assert len(parts) == 6
        # Locally administered, unicast
        first_byte = int(parts[0], 16)
        assert first_byte & 0x02 == 0x02
        assert first_byte & 0x01 == 0x00


# ===================================================================
# payloads.network.lldp_recon
# ===================================================================

class TestLLDPRecon:
    """Tests for payloads.network.lldp_recon."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.lldp_recon")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/LLDPRecon"
        assert self.mod.LLDP_ETHERTYPE == 0x88CC
        assert self.mod.CDP_SNAP_CODE == 0x2000
        assert self.mod.ROWS_VISIBLE == 5

    def test_lldp_caps_dict(self):
        assert self.mod.LLDP_CAPS[0] == "Other"
        assert self.mod.LLDP_CAPS[4] == "Router"
        assert len(self.mod.LLDP_CAPS) == 8

    def test_parse_cdp_frame_short(self):
        info = self.mod._parse_cdp_frame(b"\x00\x01\x02")
        assert info["source"] == "CDP"

    def test_parse_lldp_frame_empty(self):
        # End-of-LLDPDU TLV: type=0, length=0 -> header = 0x0000
        info = self.mod._parse_lldp_frame(struct.pack("!H", 0x0000))
        assert info["source"] == "LLDP"

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8


# ===================================================================
# payloads.network.dhcpv6_rogue
# ===================================================================

class TestDHCPv6Rogue:
    """Tests for payloads.network.dhcpv6_rogue."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.dhcpv6_rogue")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/DHCPv6Rogue"
        assert self.mod.DHCPV6_SERVER_PORT == 547
        assert self.mod.DHCPV6_CLIENT_PORT == 546
        assert self.mod.IPV6_PREFIX == "fd00:dead:beef::"

    def test_build_server_duid(self):
        duid = self.mod._build_server_duid("aa:bb:cc:dd:ee:ff")
        assert isinstance(duid, bytes)
        assert len(duid) == 10  # 2 + 2 + 6

    def test_generate_ipv6(self):
        addr = self.mod._generate_ipv6(2)
        assert addr == "fd00:dead:beef::2"
        addr10 = self.mod._generate_ipv6(10)
        assert addr10 == "fd00:dead:beef::a"

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8


# ===================================================================
# payloads.network.dns_hijack
# ===================================================================

class TestDNSHijack:
    """Tests for payloads.network.dns_hijack."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.dns_hijack")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/DNSHijack"
        assert self.mod.REAL_DNS == "8.8.8.8"

    def test_default_spoof_rules(self):
        rules = self.mod.DEFAULT_SPOOF_RULES
        assert isinstance(rules, dict)
        assert "*.example.com" in rules
        assert rules["*.example.com"] == "AUTO"

    def test_matches_spoof_exact(self):
        rules = {"login.microsoft.com": "1.2.3.4"}
        assert self.mod._matches_spoof("login.microsoft.com", rules) == "1.2.3.4"
        assert self.mod._matches_spoof("login.microsoft.com.", rules) == "1.2.3.4"

    def test_matches_spoof_wildcard(self):
        rules = {"*.example.com": "AUTO"}
        assert self.mod._matches_spoof("test.example.com", rules) == "AUTO"
        assert self.mod._matches_spoof("unrelated.org", rules) is None

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8


# ===================================================================
# payloads.network.icmp_redirect
# ===================================================================

class TestICMPRedirect:
    """Tests for payloads.network.icmp_redirect."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.icmp_redirect")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/ICMPRedirect"
        assert self.mod.REDIRECT_INTERVAL == 5
        assert self.mod.ROWS_VISIBLE == 5

    def test_initial_state(self):
        assert isinstance(self.mod.hosts, list)
        assert self.mod.view_mode in ("hosts", "active")

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8


# ===================================================================
# payloads.network.rogue_gateway
# ===================================================================

class TestRogueGateway:
    """Tests for payloads.network.rogue_gateway."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.rogue_gateway")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/RogueGateway"
        assert self.mod.ARP_INTERVAL == 2
        assert self.mod.DHCP_LEASE_TIME == 300
        assert self.mod.RA_INTERVAL == 10

    def test_vector_names(self):
        assert self.mod.VECTOR_NAMES == ["ARP", "DHCP", "RA"]

    def test_vector_enabled_defaults(self):
        assert self.mod.vector_enabled["ARP"] is True
        assert self.mod.vector_enabled["DHCP"] is True
        assert self.mod.vector_enabled["RA"] is True

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8


# ===================================================================
# payloads.network.tcp_rst_inject
# ===================================================================

class TestTCPRstInject:
    """Tests for payloads.network.tcp_rst_inject."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.tcp_rst_inject")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.ROWS_VISIBLE == 6

    def test_conn_key_canonical(self):
        k1 = self.mod._conn_key("10.0.0.1", 1234, "10.0.0.2", 80)
        k2 = self.mod._conn_key("10.0.0.2", 80, "10.0.0.1", 1234)
        assert k1 == k2

    def test_conn_key_returns_tuple(self):
        key = self.mod._conn_key("1.1.1.1", 100, "2.2.2.2", 200)
        assert isinstance(key, tuple)
        assert len(key) == 4

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8


# ===================================================================
# payloads.network.port_scanner
# ===================================================================

class TestPortScanner:
    """Tests for payloads.network.port_scanner."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.port_scanner")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/PortScan"
        assert self.mod.ROWS_VISIBLE == 6

    def test_top_20_ports(self):
        assert isinstance(self.mod.TOP_20, list)
        assert len(self.mod.TOP_20) == 20
        assert 80 in self.mod.TOP_20
        assert 443 in self.mod.TOP_20
        assert 22 in self.mod.TOP_20

    def test_service_map(self):
        assert self.mod.SERVICE_MAP[80] == "HTTP"
        assert self.mod.SERVICE_MAP[443] == "HTTPS"
        assert self.mod.SERVICE_MAP[22] == "SSH"
        assert self.mod.SERVICE_MAP[3306] == "MySQL"

    def test_scan_modes(self):
        assert self.mod.SCAN_MODES == ["Top 20", "Top 100", "1-1024"]

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8


# ===================================================================
# payloads.network.network_tap
# ===================================================================

class TestNetworkTap:
    """Tests for payloads.network.network_tap."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.network_tap")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/NetworkTap"
        assert self.mod.IFACE_A == "eth0"
        assert self.mod.IFACE_B == "eth1"
        assert self.mod.BRIDGE == "br0"

    def test_display_modes(self):
        assert self.mod.DISPLAY_MODES == ["overview", "protocols", "top_talkers"]

    def test_format_bytes(self):
        assert self.mod._format_bytes(500) == "500B"
        assert self.mod._format_bytes(1500) == "1.5KB"
        assert self.mod._format_bytes(2_500_000) == "2.5MB"

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8


# ===================================================================
# payloads.network.nbns_spoof
# ===================================================================

class TestNBNSSpoof:
    """Tests for payloads.network.nbns_spoof."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.nbns_spoof")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/NBNSSpoof"
        assert self.mod.NBNS_PORT == 137
        assert self.mod.ROWS_VISIBLE == 6

    def test_decode_nbns_name_encoded(self):
        # "WPAD" in NBNS encoding: W=0x57 -> 'F','H', P=0x50 -> 'F','A', etc.
        # Each char c becomes chr((c>>4)+0x41), chr((c&0xF)+0x41)
        encoded = ""
        for ch in "WPAD":
            encoded += chr((ord(ch) >> 4) + ord("A"))
            encoded += chr((ord(ch) & 0x0F) + ord("A"))
        # Pad to 32 chars with space (0x20) encoding: 'C','A'
        while len(encoded) < 32:
            encoded += "CA"
        result = self.mod._decode_nbns_name(encoded.encode("ascii"))
        assert "WPAD" in result

    def test_decode_nbns_name_plain(self):
        result = self.mod._decode_nbns_name(b"MYHOST")
        assert result == "MYHOST"

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8


# ===================================================================
# payloads.network.igmp_snoop
# ===================================================================

class TestIGMPSnoop:
    """Tests for payloads.network.igmp_snoop."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.igmp_snoop")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/IGMPSnoop"
        assert self.mod.ROWS_VISIBLE == 6

    def test_known_groups(self):
        assert self.mod.KNOWN_GROUPS["224.0.0.251"] == "mDNS"
        assert self.mod.KNOWN_GROUPS["239.255.255.250"] == "SSDP/UPnP"
        assert self.mod.KNOWN_GROUPS["224.0.0.2"] == "All Routers"

    def test_label_group_known(self):
        assert self.mod._label_group("224.0.0.251") == "mDNS"

    def test_label_group_prefix(self):
        assert self.mod._label_group("239.255.1.1") == "Site-local"

    def test_label_group_unknown(self):
        assert self.mod._label_group("225.1.2.3") == "Unknown"

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8


# ===================================================================
# payloads.network.dhcp_snoop
# ===================================================================

class TestDHCPSnoop:
    """Tests for payloads.network.dhcp_snoop."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.dhcp_snoop")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/DHCPSnoop"
        assert self.mod.ROWS_VISIBLE == 6

    def test_dhcp_msg_types(self):
        assert self.mod.DHCP_MSG_TYPES[1] == "Discover"
        assert self.mod.DHCP_MSG_TYPES[5] == "ACK"
        assert len(self.mod.DHCP_MSG_TYPES) == 8

    def test_initial_state(self):
        assert self.mod.view_mode in ("clients", "server")
        assert isinstance(self.mod.server_info, dict)
        assert "ip" in self.mod.server_info

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8


# ===================================================================
# payloads.network.traffic_analyzer
# ===================================================================

class TestTrafficAnalyzer:
    """Tests for payloads.network.traffic_analyzer."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.traffic_analyzer")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/TrafficAnalyzer"
        assert self.mod.ROWS_VISIBLE == 6

    def test_views(self):
        assert self.mod.VIEWS == ["dashboard", "connections", "dns"]

    def test_fmt_bytes(self):
        assert self.mod._fmt_bytes(500) == "500B"
        assert self.mod._fmt_bytes(1500) == "1.5K"
        assert self.mod._fmt_bytes(2_500_000) == "2.5M"

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8


# ===================================================================
# payloads.network.hsrp_takeover
# ===================================================================

class TestHSRPTakeover:
    """Tests for payloads.network.hsrp_takeover."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.hsrp_takeover")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/HSRPTakeover"
        assert self.mod.HSRP_PORT == 1985
        assert self.mod.HSRP_MCAST == "224.0.0.2"

    def test_hsrp_states(self):
        assert self.mod.HSRP_STATES[0] == "Initial"
        assert self.mod.HSRP_STATES[16] == "Active"

    def test_parse_hsrp_valid(self):
        import socket as _socket
        # Build a 20-byte HSRP Hello payload
        payload = bytes([
            0,   # version
            0,   # opcode (hello)
            16,  # state (active)
            3,   # hellotime
            10,  # holdtime
            255, # priority
            1,   # group
            0,   # reserved
        ])
        payload += b"cisco\x00\x00\x00"          # auth (8 bytes)
        payload += _socket.inet_aton("10.0.0.1")  # VIP
        result = self.mod._parse_hsrp(payload)
        assert result is not None
        assert result["priority"] == 255
        assert result["group"] == 1
        assert result["vip"] == "10.0.0.1"
        assert result["auth"] == "cisco"

    def test_parse_hsrp_too_short(self):
        assert self.mod._parse_hsrp(b"\x00" * 10) is None

    def test_build_hsrp_hello(self):
        payload = self.mod._build_hsrp_hello(1, 255, "10.0.0.1")
        assert isinstance(payload, bytes)
        assert len(payload) == 20

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8


# ===================================================================
# payloads.network.trunk_dump
# ===================================================================

class TestTrunkDump:
    """Tests for payloads.network.trunk_dump."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.trunk_dump")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.LOOT_DIR == "/root/Raspyjack/loot/TrunkDump"
        assert self.mod.DTP_MCAST == "01:00:0c:cc:cc:cc"
        assert self.mod.ROWS_VISIBLE == 6

    def test_fmt_bytes(self):
        assert self.mod._fmt_bytes(500) == "500B"
        assert self.mod._fmt_bytes(1500) == "1.5K"
        assert self.mod._fmt_bytes(2_500_000) == "2.5M"

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8


# ===================================================================
# payloads.network.proxy_arp
# ===================================================================

class TestProxyARP:
    """Tests for payloads.network.proxy_arp."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.proxy_arp")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.ROWS_VISIBLE == 6

    def test_initial_state(self):
        assert self.mod.proxy_active is False
        assert self.mod.selective_mode is False
        assert isinstance(self.mod.selective_ips, set)

    def test_key_functions_callable(self):
        assert callable(self.mod._run_cmd)
        assert callable(self.mod._get_default_iface)
        assert callable(self.mod._get_gateway_ip)
        assert callable(self.mod._get_iface_ip)

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8


# ===================================================================
# payloads.network.syn_flood
# ===================================================================

class TestSYNFlood:
    """Tests for payloads.network.syn_flood."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.mod = _safe_import("payloads.network.syn_flood")

    def test_import_succeeds(self):
        assert self.mod is not None

    def test_constants(self):
        assert self.mod.SPEED_LEVELS == [10, 50, 100, 500, 1000, 5000]
        assert self.mod.COMMON_PORTS == [80, 443, 22, 8080, 3389, 21, 25, 53, 445, 3306]
        assert self.mod.ROWS_VISIBLE == 6

    def test_random_ip_not_private(self):
        # Run several times to verify non-reserved IPs
        for _ in range(20):
            ip = self.mod._random_ip()
            first_octet = int(ip.split(".")[0])
            assert first_octet not in (10, 127, 0, 255)

    def test_initial_state(self):
        assert self.mod.view_mode in ("hosts", "attack")
        assert self.mod.flood_active is False

    def test_pins_dict(self):
        assert len(self.mod.PINS) == 8
