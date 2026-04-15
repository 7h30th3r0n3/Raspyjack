#!/usr/bin/env python3
import pathlib
import sys
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import EXTENSIONS._bluez as BLUEZ
from EXTENSIONS.api import REQUIRE_CAPABILITY, WAIT_FOR_NOTPRESENT, WAIT_FOR_PRESENT


class ExtensionTests(unittest.TestCase):
    def test_wait_requires_identifier(self):
        with self.assertRaises(ValueError):
            BLUEZ.wait_for_match(expect_present=True, timeout_seconds=1)

    def test_normalize_service_uuid_expands_short_form(self):
        self.assertEqual(
            BLUEZ.normalize_service_uuid("180d"),
            "0000180d-0000-1000-8000-00805f9b34fb",
        )

    def test_clean_scan_name_rejects_property_updates(self):
        self.assertEqual(BLUEZ._clean_scan_name("RSSI: 0xffffffae (-82)"), "")
        self.assertEqual(BLUEZ._clean_scan_name("ManufacturerData Key: 0x004c"), "")
        self.assertEqual(BLUEZ._clean_scan_name("QHM-S35D"), "QHM-S35D")

    def test_parse_bluetoothctl_info_extracts_name_and_uuids(self):
        sample = """
Device D6:70:43:52:A1:01
        Name: RJTRIG-A
        Alias: RJTRIG-A
        UUID: Vendor specific           (7f7b0001-2b7a-4e10-a6be-8e4f9d41c101)
        UUID: Heart Rate                (0000180d-0000-1000-8000-00805f9b34fb)
"""
        parsed = BLUEZ.parse_bluetoothctl_info(sample, mac="D6:70:43:52:A1:01")
        self.assertEqual(parsed["name"], "RJTRIG-A")
        self.assertEqual(parsed["mac"], "D6:70:43:52:A1:01")
        self.assertIn("7f7b0001-2b7a-4e10-a6be-8e4f9d41c101", parsed["service_uuids"])
        self.assertIn("0000180d-0000-1000-8000-00805f9b34fb", parsed["service_uuids"])

    def test_wait_for_present_returns_success_on_match(self):
        with mock.patch.object(BLUEZ, "ensure_bluetooth_ready", return_value={"ready": True}):
            with mock.patch.object(
                BLUEZ,
                "scan_ble",
                return_value=[{"name": "RJTRIG-A", "mac": "AA:BB:CC:DD:EE:FF", "service_uuids": []}],
            ):
                rc = BLUEZ.wait_for_match(expect_present=True, name="RJTRIG-A", timeout_seconds=1)
        self.assertEqual(rc, 0)

    def test_wait_for_not_present_returns_success_when_missing(self):
        with mock.patch.object(BLUEZ, "ensure_bluetooth_ready", return_value={"ready": True}):
            with mock.patch.object(BLUEZ, "scan_ble", return_value=[]):
                rc = BLUEZ.wait_for_match(expect_present=False, name="RJTRIG-A", timeout_seconds=1)
        self.assertEqual(rc, 0)

    def test_wait_returns_timeout(self):
        with mock.patch.object(BLUEZ, "ensure_bluetooth_ready", return_value={"ready": True}):
            with mock.patch.object(BLUEZ, "scan_ble", return_value=[]):
                with mock.patch.object(BLUEZ.time, "sleep", return_value=None):
                    rc = BLUEZ.wait_for_match(
                        expect_present=True,
                        name="RJTRIG-A",
                        timeout_seconds=1,
                        scan_window_seconds=1,
                        poll_interval_seconds=1,
                    )
        self.assertEqual(rc, 1)

    def test_api_wait_for_present_returns_true(self):
        with mock.patch.object(BLUEZ, "ensure_bluetooth_ready", return_value={"ready": True}):
            with mock.patch.object(
                BLUEZ,
                "scan_ble",
                return_value=[{"name": "RJTRIG-A", "mac": "AA:BB:CC:DD:EE:FF", "service_uuids": []}],
            ):
                self.assertTrue(WAIT_FOR_PRESENT(name="RJTRIG-A", timeout_seconds=1))

    def test_api_wait_for_present_can_warn_only(self):
        with mock.patch.object(BLUEZ, "ensure_bluetooth_ready", return_value={"ready": True}):
            with mock.patch.object(BLUEZ, "scan_ble", return_value=[]):
                with mock.patch.object(BLUEZ.time, "sleep", return_value=None):
                    self.assertFalse(
                        WAIT_FOR_PRESENT(
                            name="RJTRIG-A",
                            timeout_seconds=1,
                            scan_window_seconds=1,
                            poll_interval_seconds=1,
                            fail_closed=False,
                        )
                    )

    def test_api_wait_for_not_present_returns_true(self):
        with mock.patch.object(BLUEZ, "ensure_bluetooth_ready", return_value={"ready": True}):
            with mock.patch.object(BLUEZ, "scan_ble", return_value=[]):
                self.assertTrue(WAIT_FOR_NOTPRESENT(name="RJTRIG-A", timeout_seconds=1))

    def test_require_capability_warn_only_returns_false(self):
        self.assertFalse(
            REQUIRE_CAPABILITY("config", "definitely_missing_file.xyz", failure_policy="warn_only")
        )


if __name__ == "__main__":
    unittest.main()
