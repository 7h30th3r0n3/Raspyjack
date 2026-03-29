"""
Unit tests for payloads in payloads/remote_access/.
"""

import importlib
import os

import pytest

PAYLOADS_DIR = os.path.join(
    os.path.dirname(__file__), os.pardir, "payloads", "remote_access"
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
# shell.py
# =========================================================================
class TestShell:
    def test_source_exists(self):
        src = _read_source("shell.py")
        assert len(src) > 100

    def test_source_has_load_font(self):
        src = _read_source("shell.py")
        assert "def load_font" in src

    def test_source_has_set_font(self):
        src = _read_source("shell.py")
        assert "def set_font" in src

    def test_source_has_draw_buffer(self):
        src = _read_source("shell.py")
        assert "def draw_buffer" in src

    def test_source_has_handle_key(self):
        src = _read_source("shell.py")
        assert "def handle_key" in src

    def test_source_font_constants(self):
        src = _read_source("shell.py")
        assert "FONT_MIN" in src
        assert "FONT_MAX" in src


# =========================================================================
# reverse_shell_gen.py
# =========================================================================
class TestReverseShellGen:
    def test_import_smoke(self):
        mod = _safe_import("payloads.remote_access.reverse_shell_gen")
        assert mod is not None

    def test_generate_shell_bash(self):
        mod = _safe_import("payloads.remote_access.reverse_shell_gen")
        cmd = mod._generate_shell("bash", "10.0.0.1", 4444)
        assert "10.0.0.1" in cmd
        assert "4444" in cmd
        assert "/dev/tcp/" in cmd

    def test_generate_shell_python(self):
        mod = _safe_import("payloads.remote_access.reverse_shell_gen")
        cmd = mod._generate_shell("python", "10.0.0.1", 4444)
        assert "socket" in cmd
        assert "10.0.0.1" in cmd

    def test_generate_shell_powershell(self):
        mod = _safe_import("payloads.remote_access.reverse_shell_gen")
        cmd = mod._generate_shell("powershell", "10.0.0.1", 4444)
        assert "TCPClient" in cmd

    def test_generate_shell_nc(self):
        mod = _safe_import("payloads.remote_access.reverse_shell_gen")
        cmd = mod._generate_shell("nc", "10.0.0.1", 4444)
        assert "nc" in cmd
        assert "mkfifo" in cmd

    def test_generate_shell_unknown(self):
        mod = _safe_import("payloads.remote_access.reverse_shell_gen")
        cmd = mod._generate_shell("nonexistent", "10.0.0.1", 4444)
        assert "Unknown" in cmd

    def test_wrap_text(self):
        mod = _safe_import("payloads.remote_access.reverse_shell_gen")
        lines = mod._wrap_text("abcdefghij", width=5)
        assert lines == ["abcde", "fghij"]

    def test_wrap_text_short(self):
        mod = _safe_import("payloads.remote_access.reverse_shell_gen")
        lines = mod._wrap_text("hi", width=10)
        assert lines == ["hi"]

    def test_shell_types_constant(self):
        mod = _safe_import("payloads.remote_access.reverse_shell_gen")
        assert "bash" in mod.SHELL_TYPES
        assert "python" in mod.SHELL_TYPES


# =========================================================================
# reverse_ssh.py
# =========================================================================
class TestReverseSSH:
    def test_import_smoke(self):
        mod = _safe_import("payloads.remote_access.reverse_ssh")
        assert mod is not None

    def test_default_config(self):
        mod = _safe_import("payloads.remote_access.reverse_ssh")
        assert isinstance(mod.DEFAULT_CONFIG, dict)
        assert "remote_host" in mod.DEFAULT_CONFIG
        assert "remote_port" in mod.DEFAULT_CONFIG

    def test_default_config_port(self):
        mod = _safe_import("payloads.remote_access.reverse_ssh")
        assert mod.DEFAULT_CONFIG["remote_port"] == 2222

    def test_format_uptime(self):
        mod = _safe_import("payloads.remote_access.reverse_ssh")
        result = mod._format_uptime(0)
        assert isinstance(result, str)

    def test_source_has_tunnel_worker(self):
        src = _read_source("reverse_ssh.py")
        assert "def _tunnel_worker" in src

    def test_main_callable(self):
        mod = _safe_import("payloads.remote_access.reverse_ssh")
        assert callable(mod.main)


# =========================================================================
# pivot_proxy.py
# =========================================================================
class TestPivotProxy:
    def test_import_smoke(self):
        mod = _safe_import("payloads.remote_access.pivot_proxy")
        assert mod is not None

    def test_socks_version_constant(self):
        mod = _safe_import("payloads.remote_access.pivot_proxy")
        assert mod.SOCKS_VERSION == 0x05

    def test_default_port(self):
        mod = _safe_import("payloads.remote_access.pivot_proxy")
        assert mod.DEFAULT_PORT == 1080

    def test_format_bytes(self):
        mod = _safe_import("payloads.remote_access.pivot_proxy")
        assert mod._format_bytes(100) == "100B"
        assert "K" in mod._format_bytes(2048)
        assert "M" in mod._format_bytes(2 * 1024 * 1024)

    def test_source_has_handle_client(self):
        src = _read_source("pivot_proxy.py")
        assert "def _handle_client" in src

    def test_main_callable(self):
        mod = _safe_import("payloads.remote_access.pivot_proxy")
        assert callable(mod.main)


# =========================================================================
# port_forwarder.py
# =========================================================================
class TestPortForwarder:
    def test_import_smoke(self):
        mod = _safe_import("payloads.remote_access.port_forwarder")
        assert mod is not None

    def test_new_rule(self):
        mod = _safe_import("payloads.remote_access.port_forwarder")
        rule = mod._new_rule()
        assert rule["local_port"] == 8080
        assert rule["remote_host"] == "192.168.1.1"
        assert rule["remote_port"] == 80
        assert rule["active"] is False

    def test_parse_octets(self):
        mod = _safe_import("payloads.remote_access.port_forwarder")
        octets = mod._parse_octets("192.168.1.100")
        assert octets == [192, 168, 1, 100]

    def test_parse_octets_invalid(self):
        mod = _safe_import("payloads.remote_access.port_forwarder")
        octets = mod._parse_octets("invalid")
        assert octets == [192, 168, 1, 1]

    def test_octets_to_str(self):
        mod = _safe_import("payloads.remote_access.port_forwarder")
        assert mod._octets_to_str([10, 0, 0, 1]) == "10.0.0.1"

    def test_format_bytes(self):
        mod = _safe_import("payloads.remote_access.port_forwarder")
        assert mod._format_bytes(512) == "512B"
        assert "K" in mod._format_bytes(4096)

    def test_main_callable(self):
        mod = _safe_import("payloads.remote_access.port_forwarder")
        assert callable(mod.main)


# =========================================================================
# tailscale_control.py
# =========================================================================
class TestTailscaleControl:
    def test_import_smoke(self):
        mod = _safe_import("payloads.remote_access.tailscale_control")
        assert mod is not None

    def test_truncate(self):
        mod = _safe_import("payloads.remote_access.tailscale_control")
        assert mod._truncate("hello world", 5) == "hell~"
        assert mod._truncate("hi", 5) == "hi"

    def test_truncate_exact(self):
        mod = _safe_import("payloads.remote_access.tailscale_control")
        assert mod._truncate("abcde", 5) == "abcde"

    def test_source_has_daemon_running(self):
        src = _read_source("tailscale_control.py")
        assert "def _daemon_running" in src

    def test_main_callable(self):
        mod = _safe_import("payloads.remote_access.tailscale_control")
        assert callable(mod.main)
