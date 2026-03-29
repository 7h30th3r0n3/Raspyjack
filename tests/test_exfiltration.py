"""
Unit tests for payloads in the exfiltration/ directory.

Each payload is smoke-tested for importability, key functions, pure logic,
and constants.  We never call main().
"""

import importlib
import io
import os
import struct
import sys
import tempfile

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
# exfiltrate_discord
# ===================================================================

class TestExfiltrateDiscord:
    """Tests for payloads.exfiltration.exfiltrate_discord."""

    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _safe_import("payloads.exfiltration.exfiltrate_discord")

    def test_import_smoke(self):
        assert self.mod is not None

    def test_discord_size_limit_constant(self):
        assert self.mod.DISCORD_SIZE_LIMIT == 8 * 1024 * 1024

    def test_webhook_url_is_placeholder(self):
        # The default should still be the placeholder
        assert "xxxxxxxx" in self.mod.WEBHOOK_URL or "EDIT" in self.mod.WEBHOOK_URL

    def test_add_directory_to_zip_on_empty_dir(self):
        """add_directory_to_zip should not fail on an empty directory."""
        import zipfile
        with tempfile.TemporaryDirectory() as tmpdir:
            from pathlib import Path
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                self.mod.add_directory_to_zip(zf, Path(tmpdir))
            buf.seek(0)
            with zipfile.ZipFile(buf, "r") as zf:
                assert len(zf.namelist()) == 0

    def test_add_directory_to_zip_includes_files(self):
        """add_directory_to_zip should include files from the directory."""
        import zipfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmpdir:
            sub = os.path.join(tmpdir, "sub")
            os.makedirs(sub)
            with open(os.path.join(sub, "test.txt"), "w") as f:
                f.write("hello")
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                self.mod.add_directory_to_zip(zf, Path(sub))
            buf.seek(0)
            with zipfile.ZipFile(buf, "r") as zf:
                names = zf.namelist()
                assert len(names) >= 1

    def test_build_archive_callable(self):
        assert callable(self.mod.build_archive)

    def test_key_functions_exist(self):
        assert callable(self.mod.add_directory_to_zip)
        assert callable(self.mod.build_archive)
        assert callable(self.mod.send_to_discord)
        assert callable(self.mod.main)


# ===================================================================
# http_exfil
# ===================================================================

class TestHTTPExfil:
    """Tests for payloads.exfiltration.http_exfil."""

    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _safe_import("payloads.exfiltration.http_exfil")

    def test_import_smoke(self):
        assert self.mod is not None

    def test_default_config(self):
        assert hasattr(self.mod, "DEFAULT_CONFIG")
        cfg = self.mod.DEFAULT_CONFIG
        assert "target_url" in cfg
        assert "chunk_size" in cfg
        assert cfg["chunk_size"] == 4096

    def test_url_presets(self):
        assert hasattr(self.mod, "URL_PRESETS")
        assert len(self.mod.URL_PRESETS) >= 3

    def test_format_size(self):
        assert self.mod._format_size(500) == "500B"
        assert self.mod._format_size(2048) == "2.0K"
        assert self.mod._format_size(1048576) == "1.0M"

    def test_get_state_returns_dict(self):
        state = self.mod._get_state()
        assert isinstance(state, dict)
        assert "config" in state
        assert "files" in state
        assert "transfer_active" in state

    def test_set_state_updates_values(self):
        original = self.mod._get_state()
        self.mod._set_state(status="TestStatus")
        updated = self.mod._get_state()
        assert updated["status"] == "TestStatus"
        # Restore
        self.mod._set_state(status=original["status"])

    def test_key_functions_exist(self):
        assert callable(self.mod._format_size)
        assert callable(self.mod._get_state)
        assert callable(self.mod._set_state)
        assert callable(self.mod._cycle_url_preset)
        assert callable(self.mod.main)

    def test_constants(self):
        assert self.mod.WIDTH == 128
        assert self.mod.HEIGHT == 128
        assert self.mod.DEBOUNCE == 0.25


# ===================================================================
# ble_exfil
# ===================================================================

class TestBLEExfil:
    """Tests for payloads.exfiltration.ble_exfil."""

    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _safe_import("payloads.exfiltration.ble_exfil")

    def test_import_smoke(self):
        assert self.mod is not None

    def test_ble_constants(self):
        assert self.mod.MANUFACTURER_ID == 0xFFFF
        assert self.mod.HEADER_SIZE == 4
        assert self.mod.DATA_PER_CHUNK == 16
        assert self.mod.CHUNK_SIZE == 20

    def test_tx_intervals(self):
        assert len(self.mod.TX_INTERVALS) == len(self.mod.TX_INTERVAL_LABELS)
        assert self.mod.TX_INTERVALS[0] == 0.05
        assert self.mod.TX_INTERVALS[-1] == 0.5

    def test_format_size(self):
        assert self.mod._format_size(100) == "100B"
        assert self.mod._format_size(1024) == "1.0K"
        assert self.mod._format_size(1048576) == "1.0M"

    def test_format_eta(self):
        assert self.mod._format_eta(0) == "0s"
        assert self.mod._format_eta(30) == "30s"
        assert self.mod._format_eta(90) == "1m30s"

    def test_fragment_file(self):
        """_fragment_file should split data into 16-byte payload chunks."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"A" * 50)
            fpath = f.name
        try:
            chunks, size = self.mod._fragment_file(fpath)
            assert size == 50
            # 50 / 16 = ceil(3.125) = 4 chunks
            assert len(chunks) == 4
            # Each chunk is HEADER_SIZE + DATA_PER_CHUNK = 20 bytes
            for chunk in chunks:
                assert len(chunk) == 20
            # Verify header structure: seq (2B) + total (2B)
            seq, total = struct.unpack(">HH", chunks[0][:4])
            assert seq == 0
            assert total == 4
        finally:
            os.unlink(fpath)

    def test_get_state_and_set_state(self):
        state = self.mod._get_state()
        assert isinstance(state, dict)
        assert "status" in state

        self.mod._set_state(status="Testing")
        assert self.mod._get_state()["status"] == "Testing"
        self.mod._set_state(status="Ready")

    def test_key_functions_exist(self):
        assert callable(self.mod._fragment_file)
        assert callable(self.mod._format_eta)
        assert callable(self.mod._format_size)
        assert callable(self.mod.main)


# ===================================================================
# auto_loot_exfil
# ===================================================================

class TestAutoLootExfil:
    """Tests for payloads.exfiltration.auto_loot_exfil."""

    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _safe_import("payloads.exfiltration.auto_loot_exfil")

    def test_import_smoke(self):
        assert self.mod is not None

    def test_channels_and_labels(self):
        assert len(self.mod.CHANNELS) == len(self.mod.CHANNEL_LABELS)
        assert "discord" in self.mod.CHANNELS
        assert "http" in self.mod.CHANNELS
        assert "dns" in self.mod.CHANNELS

    def test_poll_interval(self):
        assert self.mod.POLL_INTERVAL == 10

    def test_file_hash(self):
        """_file_hash should return a sha256 hex digest."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test data for hashing")
            fpath = f.name
        try:
            h = self.mod._file_hash(fpath)
            assert h is not None
            assert len(h) == 64  # sha256 hex length
        finally:
            os.unlink(fpath)

    def test_file_hash_nonexistent(self):
        result = self.mod._file_hash("/nonexistent/file.bin")
        assert result is None

    def test_add_log(self):
        """_add_log should append a timestamped entry."""
        # Clear existing
        self.mod._set_state(log_lines=[])
        self.mod._add_log("test message")
        state = self.mod._get_state()
        assert len(state["log_lines"]) == 1
        assert "test message" in state["log_lines"][0]
        # Cleanup
        self.mod._set_state(log_lines=[])

    def test_manifest_operations(self):
        """Test manifest add/clear/get cycle."""
        self.mod._clear_manifest()
        assert len(self.mod._get_manifest()) == 0

        self.mod._add_to_manifest("abc123")
        assert "abc123" in self.mod._get_manifest()

        self.mod._clear_manifest()
        assert len(self.mod._get_manifest()) == 0

    def test_default_config(self):
        assert hasattr(self.mod, "DEFAULT_CONFIG")
        cfg = self.mod.DEFAULT_CONFIG
        assert "http_url" in cfg
        assert "dns_domain" in cfg

    def test_key_functions_exist(self):
        assert callable(self.mod._file_hash)
        assert callable(self.mod._scan_new_files)
        assert callable(self.mod._exfil_file)
        assert callable(self.mod._start_daemon)
        assert callable(self.mod._stop_daemon)
        assert callable(self.mod.main)


# ===================================================================
# dns_tunnel
# ===================================================================

class TestDNSTunnel:
    """Tests for payloads.exfiltration.dns_tunnel."""

    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _safe_import("payloads.exfiltration.dns_tunnel")

    def test_import_smoke(self):
        assert self.mod is not None

    def test_chunk_sizes(self):
        assert hasattr(self.mod, "CHUNK_SIZES")
        assert len(self.mod.CHUNK_SIZES) >= 4
        # Must all be <= MAX_LABEL_LEN
        for cs in self.mod.CHUNK_SIZES:
            assert cs <= self.mod.MAX_LABEL_LEN

    def test_preset_domains(self):
        assert hasattr(self.mod, "PRESET_DOMAINS")
        assert len(self.mod.PRESET_DOMAINS) >= 2

    def test_encode_chunk(self):
        """_encode_chunk should return a DNS-safe base32 string."""
        encoded = self.mod._encode_chunk(b"hello")
        assert encoded.islower() or encoded == ""
        # No padding characters
        assert "=" not in encoded

    def test_build_query_name_format(self):
        """Query name should be seq.hash8.data.domain."""
        qname = self.mod._build_query_name(
            seq=0, total=10, file_hash="abcdef1234567890",
            encoded_data="nbswy3dp", domain="test.example.com",
        )
        assert qname.endswith("test.example.com")
        assert "abcdef12" in qname  # first 8 chars of hash

    def test_build_query_name_max_length(self):
        """Long data should be trimmed to stay within MAX_NAME_LEN."""
        long_data = "a" * 300
        qname = self.mod._build_query_name(
            seq=0, total=1, file_hash="abcdef1234567890",
            encoded_data=long_data, domain="test.example.com",
        )
        assert len(qname) <= self.mod.MAX_NAME_LEN

    def test_constants(self):
        assert self.mod.MAX_LABEL_LEN == 63
        assert self.mod.MAX_NAME_LEN == 253

    def test_key_functions_exist(self):
        assert callable(self.mod._encode_chunk)
        assert callable(self.mod._build_query_name)
        assert callable(self.mod._send_dns_query)
        assert callable(self.mod.start_transfer)
        assert callable(self.mod.main)


# ===================================================================
# icmp_tunnel
# ===================================================================

class TestICMPTunnel:
    """Tests for payloads.exfiltration.icmp_tunnel."""

    @pytest.fixture(autouse=True)
    def _load_module(self):
        self.mod = _safe_import("payloads.exfiltration.icmp_tunnel")

    def test_import_smoke(self):
        assert self.mod is not None

    def test_xor_bytes_identity(self):
        """XOR with key then XOR again should return original."""
        data = b"Hello, World!"
        key = self.mod.XOR_KEY
        encrypted = self.mod._xor_bytes(data, key)
        decrypted = self.mod._xor_bytes(encrypted, key)
        assert decrypted == data

    def test_xor_bytes_produces_different_output(self):
        data = b"test data here"
        encrypted = self.mod._xor_bytes(data, self.mod.XOR_KEY)
        assert encrypted != data

    def test_xor_bytes_empty(self):
        result = self.mod._xor_bytes(b"", self.mod.XOR_KEY)
        assert result == b""

    def test_build_header(self):
        """Header should be 12 bytes: 2B seq + 2B total + 8B hash prefix."""
        header = self.mod._build_header(5, 100, "abcdef1234567890")
        assert len(header) == 12
        # First 2 bytes: seq=5
        seq = int.from_bytes(header[:2], "big")
        assert seq == 5
        # Next 2 bytes: total=100
        total = int.from_bytes(header[2:4], "big")
        assert total == 100
        # Last 8 bytes: hash prefix as ASCII
        assert header[4:12] == b"abcdef12"

    def test_preset_targets(self):
        assert hasattr(self.mod, "PRESET_TARGETS")
        assert len(self.mod.PRESET_TARGETS) >= 2

    def test_chunk_size(self):
        assert self.mod.CHUNK_SIZE == 48

    def test_key_functions_exist(self):
        assert callable(self.mod._xor_bytes)
        assert callable(self.mod._build_header)
        assert callable(self.mod.start_transfer)
        assert callable(self.mod.main)


# ---------------------------------------------------------------------------
# Source-based helper for payloads that call GPIO at import time
# ---------------------------------------------------------------------------

_EXFIL_PAYLOADS_DIR = os.path.join(
    os.path.dirname(__file__), os.pardir, "payloads", "exfiltration"
)


def _read_source(filename):
    path = os.path.join(_EXFIL_PAYLOADS_DIR, filename)
    with open(path) as fh:
        return fh.read()


# ===================================================================
# exfil_smb (GPIO at import — source-based)
# ===================================================================

class TestExfilSMB:
    """Tests for payloads.exfiltration.exfil_smb (source-based)."""

    def test_source_has_loot_dir(self):
        src = _read_source("exfil_smb.py")
        assert "LOOT_DIR" in src
        assert "SMBExfil" in src

    def test_source_has_modes(self):
        src = _read_source("exfil_smb.py")
        assert "MODES" in src
        assert "Serve" in src

    def test_source_has_upload_loot(self):
        src = _read_source("exfil_smb.py")
        assert "def _upload_loot" in src

    def test_source_has_main(self):
        src = _read_source("exfil_smb.py")
        assert "def main()" in src


# ===================================================================
# exfil_ftp (GPIO at import — source-based)
# ===================================================================

class TestExfilFTP:
    """Tests for payloads.exfiltration.exfil_ftp (source-based)."""

    def test_source_has_ftp_port(self):
        src = _read_source("exfil_ftp.py")
        assert "FTP_PORT" in src

    def test_source_has_default_config(self):
        src = _read_source("exfil_ftp.py")
        assert "DEFAULT_CONFIG" in src

    def test_source_has_handle_ftp_client(self):
        src = _read_source("exfil_ftp.py")
        assert "def _handle_ftp_client" in src

    def test_source_has_main(self):
        src = _read_source("exfil_ftp.py")
        assert "def main()" in src


# ===================================================================
# exfil_usb (GPIO at import — source-based)
# ===================================================================

class TestExfilUSB:
    """Tests for payloads.exfiltration.exfil_usb (source-based)."""

    def test_source_has_mount_point(self):
        src = _read_source("exfil_usb.py")
        assert "MOUNT_POINT" in src

    def test_source_has_loot_root(self):
        src = _read_source("exfil_usb.py")
        assert "LOOT_ROOT" in src

    def test_source_has_find_usb_device(self):
        src = _read_source("exfil_usb.py")
        assert "def _find_usb_device" in src

    def test_source_has_do_copy(self):
        src = _read_source("exfil_usb.py")
        assert "def _do_copy" in src
