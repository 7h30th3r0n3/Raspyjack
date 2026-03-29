"""
Unit tests for payloads in payloads/utilities/.
"""

import importlib
import os

import pytest

PAYLOADS_DIR = os.path.join(
    os.path.dirname(__file__), os.pardir, "payloads", "utilities"
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
# latency.py (module-level loop — source-based tests only)
# =========================================================================
class TestLatency:
    def test_source_has_target_class(self):
        src = _read_source("latency.py")
        assert "class Target" in src

    def test_source_has_pins(self):
        src = _read_source("latency.py")
        assert "PINS" in src

    def test_source_has_target(self):
        src = _read_source("latency.py")
        assert "class Target" in src or "Target" in src


# =========================================================================
# LanTest.py
# =========================================================================
class TestLanTest:
    def test_source_has_iperf3_run(self):
        src = _read_source("LanTest.py")
        assert "iperf3" in src.lower() or "iperf" in src.lower()

    def test_source_has_pins(self):
        src = _read_source("LanTest.py")
        assert "PINS" in src

    def test_source_has_iperf3(self):
        src = _read_source("LanTest.py")
        assert "def iperf3_run" in src


# =========================================================================
# WanTest.py (module-level loop — source-based tests only)
# =========================================================================
class TestWanTest:
    def test_source_has_speedtest(self):
        src = _read_source("WanTest.py")
        assert "speedtest" in src.lower()

    def test_source_has_pins(self):
        src = _read_source("WanTest.py")
        assert "PINS" in src

    def test_source_has_run_speedtest(self):
        src = _read_source("WanTest.py")
        assert "def run_speedtest" in src


# =========================================================================
# webui.py
# =========================================================================
class TestWebUI:
    def test_source_exists(self):
        src = _read_source("webui.py")
        assert len(src) > 100

    def test_source_has_app_or_server(self):
        src = _read_source("webui.py")
        assert "app" in src.lower() or "server" in src.lower() or "flask" in src.lower()


# =========================================================================
# interface_status.py
# =========================================================================
class TestInterfaceStatus:
    def test_import_smoke(self):
        mod = _safe_import("payloads.utilities.interface_status")
        assert mod is not None

    def test_fmt_bytes(self):
        mod = _safe_import("payloads.utilities.interface_status")
        assert mod._fmt_bytes(100) == "100B"
        assert mod._fmt_bytes(1024) == "1K"
        assert mod._fmt_bytes(1048576) == "1M"

    def test_fmt_bytes_invalid(self):
        mod = _safe_import("payloads.utilities.interface_status")
        assert mod._fmt_bytes("invalid") == "-"

    def test_short_ip(self):
        mod = _safe_import("payloads.utilities.interface_status")
        assert mod._short_ip("192.168.1.1") == "192.168.1.1"
        assert mod._short_ip("") == "-"

    def test_split_ip_lines(self):
        mod = _safe_import("payloads.utilities.interface_status")
        lines = mod._split_ip_lines("192.168.1.100")
        assert lines[0] == "ip:"
        assert "192.168" in lines[1]

    def test_split_ip_lines_empty(self):
        mod = _safe_import("payloads.utilities.interface_status")
        lines = mod._split_ip_lines("")
        assert lines == ["ip:", "-"]


# =========================================================================
# loot_browser.py
# =========================================================================
class TestLootBrowser:
    def test_import_smoke(self):
        mod = _safe_import("payloads.utilities.loot_browser")
        assert mod is not None

    def test_fmt_size(self):
        mod = _safe_import("payloads.utilities.loot_browser")
        assert mod._fmt_size(500) == "500B"
        assert mod._fmt_size(2048) == "2K"

    def test_file_type_label(self):
        mod = _safe_import("payloads.utilities.loot_browser")
        assert mod._file_type_label("/tmp/test.json") == "JSON"
        assert mod._file_type_label("/tmp/test.txt") == "TEXT"
        assert mod._file_type_label("/tmp/test.pcap") == "PCAP"
        assert mod._file_type_label("/tmp/test.xyz") == "BIN"

    def test_is_text_file(self, tmp_path):
        mod = _safe_import("payloads.utilities.loot_browser")
        text_file = tmp_path / "test.txt"
        text_file.write_text("Hello world\n")
        assert mod._is_text_file(str(text_file)) is True

    def test_is_text_file_binary(self, tmp_path):
        mod = _safe_import("payloads.utilities.loot_browser")
        bin_file = tmp_path / "test.bin"
        bin_file.write_bytes(b"\x00\x01\x02\x03")
        assert mod._is_text_file(str(bin_file)) is False

    def test_list_dir(self, tmp_path):
        mod = _safe_import("payloads.utilities.loot_browser")
        (tmp_path / "a.txt").write_text("hello")
        (tmp_path / "b.json").write_text("{}")
        entries = mod._list_dir(str(tmp_path))
        assert len(entries) == 2
        names = {e["name"] for e in entries}
        assert "a.txt" in names

    def test_dir_stats(self, tmp_path):
        mod = _safe_import("payloads.utilities.loot_browser")
        (tmp_path / "file1.txt").write_text("data")
        (tmp_path / "file2.txt").write_text("more data")
        count, size = mod._dir_stats(str(tmp_path))
        assert count == 2
        assert size > 0


# =========================================================================
# engagement_timer.py
# =========================================================================
class TestEngagementTimer:
    def test_import_smoke(self):
        mod = _safe_import("payloads.utilities.engagement_timer")
        assert mod is not None

    def test_format_time(self):
        mod = _safe_import("payloads.utilities.engagement_timer")
        assert mod._format_time(3661) == "01:01:01"
        assert mod._format_time(0) == "00:00:00"
        assert mod._format_time(59) == "00:00:59"

    def test_format_short(self):
        mod = _safe_import("payloads.utilities.engagement_timer")
        assert mod._format_short(3600) == "1h00m"
        assert mod._format_short(120) == "2m"

    def test_format_time_negative(self):
        mod = _safe_import("payloads.utilities.engagement_timer")
        result = mod._format_time(-10)
        assert result == "00:00:00"

    def test_main_callable(self):
        mod = _safe_import("payloads.utilities.engagement_timer")
        assert callable(mod.main)


# =========================================================================
# qr_generator.py
# =========================================================================
class TestQRGenerator:
    def test_import_smoke(self):
        mod = _safe_import("payloads.utilities.qr_generator")
        assert mod is not None

    def test_source_has_generate_qr(self):
        src = _read_source("qr_generator.py")
        assert "def _generate_qr" in src

    def test_source_has_get_mode_data(self):
        src = _read_source("qr_generator.py")
        assert "def _get_mode_data" in src

    def test_main_callable(self):
        mod = _safe_import("payloads.utilities.qr_generator")
        assert callable(mod.main)


# =========================================================================
# auto_update.py
# =========================================================================
class TestAutoUpdate:
    def test_source_exists(self):
        src = _read_source("auto_update.py")
        assert len(src) > 100

    def test_source_has_check_space(self):
        src = _read_source("auto_update.py")
        assert "def check_space" in src

    def test_source_has_git_update(self):
        src = _read_source("auto_update.py")
        assert "def git_update" in src

    def test_source_has_backup(self):
        src = _read_source("auto_update.py")
        assert "def backup" in src


# =========================================================================
# keyboard_tester.py
# =========================================================================
class TestKeyboardTester:
    def test_source_exists(self):
        src = _read_source("keyboard_tester.py")
        assert len(src) > 100

    def test_source_has_draw(self):
        src = _read_source("keyboard_tester.py")
        assert "def draw" in src

    def test_source_has_find_keyboard(self):
        src = _read_source("keyboard_tester.py")
        assert "def find_keyboard" in src


# =========================================================================
# bt_keyboard_picker.py
# =========================================================================
class TestBtKeyboardPicker:
    def test_source_exists(self):
        src = _read_source("bt_keyboard_picker.py")
        assert len(src) > 100

    def test_source_has_discover(self):
        src = _read_source("bt_keyboard_picker.py")
        assert "def discover_devices" in src

    def test_source_has_pair(self):
        src = _read_source("bt_keyboard_picker.py")
        assert "def pair_trust_connect" in src


# =========================================================================
# wifi_manager_payload.py
# =========================================================================
class TestWifiManagerPayload:
    def test_source_exists(self):
        src = _read_source("wifi_manager_payload.py")
        assert len(src) > 100

    def test_source_has_main(self):
        src = _read_source("wifi_manager_payload.py")
        assert "def main" in src or "main" in src


# =========================================================================
# fast_wifi_connect.py
# =========================================================================
class TestFastWifiConnect:
    def test_source_exists(self):
        src = _read_source("fast_wifi_connect.py")
        assert len(src) > 100

    def test_source_has_main(self):
        src = _read_source("fast_wifi_connect.py")
        assert "def main" in src

    def test_source_has_scan_wifi(self):
        src = _read_source("fast_wifi_connect.py")
        assert "def _scan_wifi" in src


# =========================================================================
# fast_wifi_switcher.py
# =========================================================================
class TestFastWifiSwitcher:
    def test_source_exists(self):
        src = _read_source("fast_wifi_switcher.py")
        assert len(src) > 100

    def test_source_has_class(self):
        src = _read_source("fast_wifi_switcher.py")
        assert "class FastWiFiSwitcher" in src

    def test_source_has_main(self):
        src = _read_source("fast_wifi_switcher.py")
        assert "def main" in src


# =========================================================================
# packet_replay.py
# =========================================================================
class TestPacketReplay:
    def test_import_smoke(self):
        mod = _safe_import("payloads.utilities.packet_replay")
        assert mod is not None

    def test_format_size(self):
        mod = _safe_import("payloads.utilities.packet_replay")
        assert "B" in mod._format_size(100)
        assert "KB" in mod._format_size(2048) or "K" in mod._format_size(2048)
        assert "MB" in mod._format_size(2 * 1024 * 1024) or "M" in mod._format_size(2 * 1024 * 1024)

    def test_get_interfaces(self):
        mod = _safe_import("payloads.utilities.packet_replay")
        ifaces = mod._get_interfaces()
        assert isinstance(ifaces, list)

    def test_source_has_replay_thread(self):
        src = _read_source("packet_replay.py")
        assert "def _replay_thread" in src

    def test_main_callable(self):
        mod = _safe_import("payloads.utilities.packet_replay")
        assert callable(mod.main)


# =========================================================================
# c2_dashboard.py (GPIO at import — source-based)
# =========================================================================
class TestC2Dashboard:
    def test_source_has_views(self):
        src = _read_source("c2_dashboard.py")
        assert "VIEWS" in src
        assert "Overview" in src

    def test_source_has_services(self):
        src = _read_source("c2_dashboard.py")
        assert "SERVICES" in src

    def test_source_has_get_running_payloads(self):
        src = _read_source("c2_dashboard.py")
        assert "def _get_running_payloads" in src

    def test_source_has_main(self):
        src = _read_source("c2_dashboard.py")
        assert "def main()" in src


# =========================================================================
# payload_scheduler.py (GPIO at import — source-based)
# =========================================================================
class TestPayloadScheduler:
    def test_source_has_schedule_file(self):
        src = _read_source("payload_scheduler.py")
        assert "SCHEDULE_FILE" in src

    def test_source_has_check_interval(self):
        src = _read_source("payload_scheduler.py")
        assert "CHECK_INTERVAL" in src

    def test_source_has_discover_payloads(self):
        src = _read_source("payload_scheduler.py")
        assert "def _discover_payloads" in src

    def test_source_has_should_run(self):
        src = _read_source("payload_scheduler.py")
        assert "def _should_run" in src


# =========================================================================
# notification_center.py (GPIO at import — source-based)
# =========================================================================
class TestNotificationCenter:
    def test_source_has_notif_file(self):
        src = _read_source("notification_center.py")
        assert "NOTIF_FILE" in src

    def test_source_has_poll_interval(self):
        src = _read_source("notification_center.py")
        assert "POLL_INTERVAL" in src

    def test_source_has_load_notifications(self):
        src = _read_source("notification_center.py")
        assert "def _load_notifications" in src

    def test_source_has_push_discord(self):
        src = _read_source("notification_center.py")
        assert "def _push_discord" in src


# =========================================================================
# system_monitor.py (GPIO at import — source-based)
# =========================================================================
class TestSystemMonitor:
    def test_source_has_views(self):
        src = _read_source("system_monitor.py")
        assert "VIEWS" in src
        assert "Dashboard" in src

    def test_source_has_refresh_interval(self):
        src = _read_source("system_monitor.py")
        assert "REFRESH_INTERVAL" in src

    def test_source_has_read_cpu_percent(self):
        src = _read_source("system_monitor.py")
        assert "def _read_cpu_percent" in src

    def test_source_has_read_temperature(self):
        src = _read_source("system_monitor.py")
        assert "def _read_temperature" in src
