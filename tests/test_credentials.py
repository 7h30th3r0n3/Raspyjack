"""
Unit tests for payloads in the credentials/ directory.

Each payload is smoke-tested for importability, key functions, pure logic,
and constants.  We never call main().
"""

import importlib
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
# ftp_bruteforce
# ===================================================================

class TestFTPBruteforce:
    """Tests for payloads.credentials.ftp_bruteforce."""

    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _safe_import("payloads.credentials.ftp_bruteforce")

    def test_import_smoke(self):
        assert self.mod is not None

    def test_wordlist_exists_and_nonempty(self):
        assert hasattr(self.mod, "WORDLIST")
        assert len(self.mod.WORDLIST) >= 40
        # Each entry should be a (user, pass) tuple
        for pair in self.mod.WORDLIST:
            assert isinstance(pair, tuple)
            assert len(pair) == 2

    def test_constants(self):
        assert self.mod.WIDTH == 128
        assert self.mod.HEIGHT == 128
        assert self.mod.ROWS_VISIBLE == 5
        assert self.mod.RATE_LIMIT == 0.5
        assert "FTP" in self.mod.LOOT_DIR

    def test_extract_ftp_from_nmap_finds_port_21(self):
        hosts = set()
        data = {"port": "21", "state": "open", "ip": "10.0.0.5"}
        self.mod._extract_ftp_from_nmap(data, hosts)
        assert "10.0.0.5" in hosts

    def test_extract_ftp_from_nmap_ignores_closed(self):
        hosts = set()
        data = {"port": "21", "state": "closed", "ip": "10.0.0.5"}
        self.mod._extract_ftp_from_nmap(data, hosts)
        assert len(hosts) == 0

    def test_extract_ftp_from_nmap_handles_nested_list(self):
        hosts = set()
        data = [{"port": 21, "state": "open", "addr": "10.0.0.6"}]
        self.mod._extract_ftp_from_nmap(data, hosts)
        assert "10.0.0.6" in hosts

    def test_key_functions_exist(self):
        assert callable(self.mod._detect_subnet)
        assert callable(self.mod._try_ftp_login)
        assert callable(self.mod._export_loot)
        assert callable(self.mod.main)

    def test_pins_has_all_buttons(self):
        expected = {"UP", "DOWN", "LEFT", "RIGHT", "OK", "KEY1", "KEY2", "KEY3"}
        assert set(self.mod.PINS.keys()) == expected


# ===================================================================
# ssh_bruteforce
# ===================================================================

class TestSSHBruteforce:
    """Tests for payloads.credentials.ssh_bruteforce."""

    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _safe_import("payloads.credentials.ssh_bruteforce")

    def test_import_smoke(self):
        assert self.mod is not None

    def test_wordlist_exists_and_nonempty(self):
        assert hasattr(self.mod, "WORDLIST")
        assert len(self.mod.WORDLIST) >= 40
        for pair in self.mod.WORDLIST:
            assert isinstance(pair, tuple) and len(pair) == 2

    def test_constants(self):
        assert self.mod.WIDTH == 128
        assert self.mod.HEIGHT == 128
        assert self.mod.RATE_LIMIT == 1.0
        assert "SSH" in self.mod.LOOT_DIR

    def test_extract_ssh_from_nmap_finds_port_22(self):
        hosts = set()
        data = {"portid": "22", "state": "open", "host": "192.168.1.10"}
        self.mod._extract_ssh_from_nmap(data, hosts)
        assert "192.168.1.10" in hosts

    def test_extract_ssh_from_nmap_skips_non_22(self):
        hosts = set()
        data = {"port": "80", "state": "open", "ip": "192.168.1.10"}
        self.mod._extract_ssh_from_nmap(data, hosts)
        assert len(hosts) == 0

    def test_key_functions_exist(self):
        assert callable(self.mod._detect_subnet)
        assert callable(self.mod._try_ssh_login)
        assert callable(self.mod._export_loot)
        assert callable(self.mod.main)


# ===================================================================
# telnet_grabber
# ===================================================================

class TestTelnetGrabber:
    """Tests for payloads.credentials.telnet_grabber."""

    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _safe_import("payloads.credentials.telnet_grabber")

    def test_import_smoke(self):
        assert self.mod is not None

    def test_cred_list_exists(self):
        assert hasattr(self.mod, "CRED_LIST")
        assert len(self.mod.CRED_LIST) >= 25
        for pair in self.mod.CRED_LIST:
            assert isinstance(pair, tuple) and len(pair) == 2

    def test_constants(self):
        assert self.mod.WIDTH == 128
        assert self.mod.HEIGHT == 128
        assert "Telnet" in self.mod.LOOT_DIR

    def test_key_functions_exist(self):
        assert callable(self.mod._detect_subnet)
        assert callable(self.mod._grab_banner)
        assert callable(self.mod._try_telnet_login)
        assert callable(self.mod._export_loot)
        assert callable(self.mod.main)

    def test_pins_complete(self):
        expected = {"UP", "DOWN", "LEFT", "RIGHT", "OK", "KEY1", "KEY2", "KEY3"}
        assert set(self.mod.PINS.keys()) == expected


# ===================================================================
# http_cred_sniffer
# ===================================================================

class TestHTTPCredSniffer:
    """Tests for payloads.credentials.http_cred_sniffer."""

    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _safe_import("payloads.credentials.http_cred_sniffer")

    def test_import_smoke(self):
        assert self.mod is not None

    def test_decode_basic_auth_valid(self):
        import base64
        encoded = base64.b64encode(b"admin:secret").decode()
        result = self.mod._decode_basic_auth(encoded)
        assert result == ("admin", "secret")

    def test_decode_basic_auth_invalid(self):
        result = self.mod._decode_basic_auth("not-valid-b64!!!")
        assert result is None

    def test_extract_form_creds_finds_fields(self):
        body = "username=alice&password=s3cret&submit=Login"
        result = self.mod._extract_form_creds(body)
        assert result is not None
        assert "username" in result or "password" in result

    def test_extract_form_creds_returns_none_on_no_match(self):
        result = self.mod._extract_form_creds("action=buy&item=42")
        assert result is None

    def test_extract_cookies(self):
        lines = [
            "HTTP/1.1 200 OK",
            "Set-Cookie: session=abc123; Path=/",
            "Content-Type: text/html",
        ]
        cookies = self.mod._extract_cookies(lines)
        assert len(cookies) == 1
        assert "session=abc123" in cookies[0]

    def test_cred_fields_regex(self):
        assert self.mod.CRED_FIELDS is not None
        assert self.mod.CRED_FIELDS.search("username=test")

    def test_constants(self):
        assert self.mod.WIDTH == 128
        assert self.mod.ROWS_VISIBLE == 6
        assert "HTTPCreds" in self.mod.LOOT_DIR


# ===================================================================
# cred_sniffer_multi
# ===================================================================

class TestCredSnifferMulti:
    """Tests for payloads.credentials.cred_sniffer_multi."""

    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _safe_import("payloads.credentials.cred_sniffer_multi")

    def test_import_smoke(self):
        assert self.mod is not None

    def test_protocols_list(self):
        assert hasattr(self.mod, "PROTOCOLS")
        assert "FTP" in self.mod.PROTOCOLS
        assert "HTTP" in self.mod.PROTOCOLS
        assert "SMB" in self.mod.PROTOCOLS
        assert len(self.mod.PROTOCOLS) >= 8

    def test_safe_b64_decode_valid(self):
        import base64
        encoded = base64.b64encode(b"hello").decode()
        result = self.mod._safe_b64_decode(encoded)
        assert result == "hello"

    def test_safe_b64_decode_invalid_returns_original(self):
        result = self.mod._safe_b64_decode("not_valid_b64!!!")
        assert result == "not_valid_b64!!!"

    def test_parse_ftp_user_pass_flow(self):
        """Simulate FTP USER then PASS sequence."""
        self.mod._ftp_sessions.clear()
        self.mod.credentials.clear()

        self.mod._parse_ftp(None, "USER admin", "1.1.1.1", "2.2.2.2")
        assert ("1.1.1.1", "2.2.2.2") in self.mod._ftp_sessions

        self.mod._parse_ftp(None, "PASS secret", "1.1.1.1", "2.2.2.2")
        assert len(self.mod.credentials) >= 1
        cred = self.mod.credentials[-1]
        assert cred["username"] == "admin"
        assert cred["password"] == "secret"

    def test_parse_imap_login(self):
        self.mod.credentials.clear()
        self.mod._parse_imap(None, 'a1 LOGIN "bob" "pass123"', "1.1.1.1", "2.2.2.2")
        assert any(c["username"] == "bob" for c in self.mod.credentials)

    def test_key_functions_exist(self):
        assert callable(self.mod._add_cred)
        assert callable(self.mod._get_active_iface)
        assert callable(self.mod._export_creds)
        assert callable(self.mod.main)

    def test_constants(self):
        assert "CredSniff" in self.mod.LOOT_DIR
        assert self.mod.ROWS_VISIBLE == 7


# ===================================================================
# ntlm_relay
# ===================================================================

class TestNTLMRelay:
    """Tests for payloads.credentials.ntlm_relay."""

    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _safe_import("payloads.credentials.ntlm_relay")

    def test_import_smoke(self):
        assert self.mod is not None

    def test_service_types(self):
        assert hasattr(self.mod, "SERVICE_TYPES")
        assert "SMB" in self.mod.SERVICE_TYPES
        assert "HTTP" in self.mod.SERVICE_TYPES

    def test_constants(self):
        assert "NTLMRelay" in self.mod.LOOT_DIR
        assert "Responder" in self.mod.RESPONDER_DIR

    def test_parse_responder_log_extracts_hash_type(self):
        """_parse_responder_log should detect NTLMv2 from filename."""
        import tempfile
        self.mod.captured_hashes.clear()

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", prefix="NTLMv2-", delete=False
        ) as f:
            f.write("admin::DOMAIN:challenge:hash:hash\n")
            fpath = f.name

        try:
            self.mod._parse_responder_log(fpath, "NTLMv2-test.txt")
            assert len(self.mod.captured_hashes) == 1
            assert self.mod.captured_hashes[0]["type"] == "NTLMv2"
            assert self.mod.captured_hashes[0]["user"] == "admin"
        finally:
            import os
            os.unlink(fpath)
            self.mod.captured_hashes.clear()

    def test_key_functions_exist(self):
        assert callable(self.mod._detect_default_iface)
        assert callable(self.mod.do_arp_scan)
        assert callable(self.mod.export_hashes)
        assert callable(self.mod.main)


# ===================================================================
# ntlm_cracker
# ===================================================================

class TestNTLMCracker:
    """Tests for payloads.credentials.ntlm_cracker."""

    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _safe_import("payloads.credentials.ntlm_cracker")

    def test_import_smoke(self):
        assert self.mod is not None

    def test_detect_john_format(self):
        assert self.mod._detect_john_format("NTLMv2-hash.txt") == "netntlmv2"
        assert self.mod._detect_john_format("NTLMv1-hash.txt") == "netntlm"
        assert self.mod._detect_john_format("NTLM-hash.txt") == "nt"
        assert self.mod._detect_john_format("random.txt") == "netntlmv2"

    def test_attack_modes(self):
        assert hasattr(self.mod, "ATTACK_MODES")
        assert len(self.mod.ATTACK_MODES) >= 3
        names = [m["name"] for m in self.mod.ATTACK_MODES]
        assert "Quick" in names
        assert "Incremental" in names

    def test_build_john_cmd_quick(self):
        cmd = self.mod._build_john_cmd("/tmp/hash.txt", "netntlmv2", "Quick")
        assert self.mod.JOHN_BIN in cmd
        assert "--format=netntlmv2" in cmd
        assert any("wordlist" in c for c in cmd)

    def test_build_john_cmd_incremental(self):
        cmd = self.mod._build_john_cmd("/tmp/hash.txt", "nt", "Incremental")
        assert "--incremental" in cmd

    def test_fmt_elapsed(self):
        assert self.mod._fmt_elapsed(0) == "00:00"
        assert self.mod._fmt_elapsed(65) == "01:05"
        assert self.mod._fmt_elapsed(3600) == "60:00"

    def test_constants(self):
        assert "CrackedNTLM" in self.mod.LOOT_DIR
        assert self.mod.ROWS_VISIBLE == 6


# ===================================================================
# wpa_cracker
# ===================================================================

class TestWPACracker:
    """Tests for payloads.credentials.wpa_cracker."""

    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _safe_import("payloads.credentials.wpa_cracker")

    def test_import_smoke(self):
        assert self.mod is not None

    def test_constants(self):
        assert "CrackedWPA" in self.mod.LOOT_DIR
        assert self.mod.ROWS_VISIBLE == 6

    def test_aircrack_key_regex(self):
        pattern = self.mod._AIRCRACK_KEY_RE
        match = pattern.search("KEY FOUND! [ mypassword123 ]")
        assert match is not None
        assert match.group(1) == "mypassword123"

    def test_aircrack_progress_regex(self):
        pattern = self.mod._AIRCRACK_PROGRESS_RE
        line = "[00:01:23] 12345/67890 keys tested (2456.78 k/s)"
        match = pattern.search(line)
        assert match is not None
        assert match.group(1) == "12345"

    def test_fmt_elapsed(self):
        assert self.mod._fmt_elapsed(0) == "00:00"
        assert self.mod._fmt_elapsed(90) == "01:30"

    def test_fmt_keys(self):
        assert self.mod._fmt_keys(500) == "500"
        assert self.mod._fmt_keys(1500) == "1.5K"
        assert self.mod._fmt_keys(2000000) == "2.0M"

    def test_file_size_kb(self):
        # Non-existent file returns 0
        assert self.mod._file_size_kb("/non/existent/file.cap") == 0

    def test_key_functions_exist(self):
        assert callable(self.mod._scan_targets)
        assert callable(self.mod._build_wordlist_options)
        assert callable(self.mod._export_result)
        assert callable(self.mod.main)


# ===================================================================
# snmp_walk
# ===================================================================

class TestSNMPWalk:
    """Tests for payloads.credentials.snmp_walk."""

    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _safe_import("payloads.credentials.snmp_walk")

    def test_import_smoke(self):
        assert self.mod is not None

    def test_community_strings_list(self):
        assert hasattr(self.mod, "COMMUNITY_STRINGS")
        assert len(self.mod.COMMUNITY_STRINGS) >= 10
        assert "public" in self.mod.COMMUNITY_STRINGS
        assert "private" in self.mod.COMMUNITY_STRINGS

    def test_walk_oids_dict(self):
        assert hasattr(self.mod, "WALK_OIDS")
        assert isinstance(self.mod.WALK_OIDS, dict)
        assert "sysDescr" in self.mod.WALK_OIDS
        assert "sysName" in self.mod.WALK_OIDS

    def test_constants(self):
        assert "SNMP" in self.mod.LOOT_DIR
        assert self.mod.WIDTH == 128
        assert self.mod.HEIGHT == 128

    def test_key_functions_exist(self):
        assert callable(self.mod._detect_subnet)
        assert callable(self.mod._export_loot)
        assert callable(self.mod.main)

    def test_pins_complete(self):
        expected = {"UP", "DOWN", "LEFT", "RIGHT", "OK", "KEY1", "KEY2", "KEY3"}
        assert set(self.mod.PINS.keys()) == expected
