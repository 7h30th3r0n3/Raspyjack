#!/usr/bin/env python3
"""Tests for PM3Driver — mocks subprocess so no hardware needed."""

import pathlib
import subprocess
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from payloads.nfc_rfid._nfc_driver import (
    PM3Driver, CardInfo, MIFARE_AUTH_A, MIFARE_AUTH_B,
    auto_detect, identify_card, is_classic, is_ultralight, is_emv,
)


def _fake_run(stdout="", returncode=0):
    r = mock.MagicMock()
    r.stdout = stdout
    r.stderr = ""
    r.returncode = returncode
    return r


def _make_drv(send_output=""):
    """Create a PM3Driver with mocked internals (no real process)."""
    with mock.patch.object(PM3Driver, "_start"):
        drv = PM3Driver("/dev/ttyACM0")
    drv._send = mock.MagicMock(return_value=send_output)
    return drv


class TestPM3DriverReadPassive(unittest.TestCase):
    def test_parse_uid_atqa_sak(self):
        output = (
            "[usb|script] pm3 --> hf 14a reader\n"
            "[+]  UID: DE AD BE EF\n"
            "[+] ATQA: 00 04\n"
            "[+]  SAK: 08 [2]\n"
        )
        drv = _make_drv(output)
        card = drv.read_passive_target()
        self.assertIsNotNone(card)
        self.assertEqual(card.uid, bytes.fromhex("DEADBEEF"))
        self.assertEqual(card.atqa, 0x0004)
        self.assertEqual(card.sak, 0x08)
        self.assertIn("Classic", card.card_type)

    def test_no_card_returns_none(self):
        drv = _make_drv("[usb|script] pm3 --> hf 14a reader\n")
        card = drv.read_passive_target(timeout=0.3)
        self.assertIsNone(card)

    def test_7byte_uid(self):
        output = (
            "[+]  UID: 04 11 22 33 44 55 66\n"
            "[+] ATQA: 00 44\n"
            "[+]  SAK: 00\n"
        )
        drv = _make_drv(output)
        card = drv.read_passive_target()
        self.assertIsNotNone(card)
        self.assertEqual(len(card.uid), 7)
        self.assertTrue(is_ultralight(card))


class TestPM3DriverMifareAuth(unittest.TestCase):
    def test_auth_success_caches_key(self):
        output = "[=]   4 | AA BB CC DD 11 22 33 44 55 66 77 88 99 00 EE FF | ...............\n"
        drv = _make_drv(output)
        key = bytes.fromhex("A0A1A2A3A4A5")
        ok = drv.mifare_auth(4, key, b"\xDE\xAD\xBE\xEF", MIFARE_AUTH_A)
        self.assertTrue(ok)
        self.assertEqual(drv._last_auth_key, key)

    def test_auth_failure(self):
        drv = _make_drv("[!] Auth error\n")
        key = bytes.fromhex("000000000000")
        ok = drv.mifare_auth(0, key, b"\x01\x02\x03\x04", MIFARE_AUTH_A)
        self.assertFalse(ok)
        self.assertIsNone(drv._last_auth_key)

    def test_auth_key_b(self):
        drv = _make_drv("[=]   8 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................\n")
        key = bytes.fromhex("B0B1B2B3B4B5")
        ok = drv.mifare_auth(8, key, b"\x01\x02\x03\x04", MIFARE_AUTH_B)
        self.assertTrue(ok)
        cmd = drv._send.call_args[0][0]
        self.assertIn("-b", cmd)


class TestPM3DriverMifareRead(unittest.TestCase):
    def test_read_uses_cached_key(self):
        drv = _make_drv("[=]   4 | 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 | ................\n")
        drv._last_auth_key = bytes.fromhex("A0A1A2A3A4A5")
        drv._last_auth_key_type = MIFARE_AUTH_A
        data = drv.mifare_read(4)
        self.assertEqual(data, bytes.fromhex("0102030405060708090A0B0C0D0E0F10"))
        cmd = drv._send.call_args[0][0]
        self.assertIn("A0A1A2A3A4A5", cmd)

    def test_read_no_data(self):
        drv = _make_drv("[!] Failed to read block\n")
        self.assertIsNone(drv.mifare_read(4))

    def test_read_defaults_to_ff_key(self):
        drv = _make_drv("[=]   0 | AA AA BB BB CC CC DD DD EE EE 11 11 22 22 33 33 | ................\n")
        drv.mifare_read(0)
        cmd = drv._send.call_args[0][0]
        self.assertIn("FFFFFFFFFFFF", cmd)


class TestPM3DriverMifareWrite(unittest.TestCase):
    def test_write_success(self):
        drv = _make_drv("[+] Write ( ok )\n[+] isOk:01\n")
        drv._last_auth_key = bytes.fromhex("FFFFFFFFFFFF")
        self.assertTrue(drv.mifare_write(4, b"\x00" * 16))

    def test_write_failure(self):
        drv = _make_drv("[!] Write ( fail )\n")
        self.assertFalse(drv.mifare_write(4, b"\x00" * 16))


class TestPM3DriverUltralight(unittest.TestCase):
    def test_ul_read_4_pages(self):
        responses = [
            "[+] 04112233\n",
            "[+] 44556677\n",
            "[+] 8899AABB\n",
            "[+] CCDDEEFF\n",
        ]
        drv = _make_drv()
        drv._send = mock.MagicMock(side_effect=responses)
        data = drv.mifare_ul_read(0)
        self.assertEqual(data, bytes.fromhex("04112233445566778899AABBCCDDEEFF"))

    def test_ul_read_page_fail(self):
        drv = _make_drv("[!] Error\n")
        self.assertIsNone(drv.mifare_ul_read(0))

    def test_ul_write(self):
        drv = _make_drv("[+] isOk:01\n")
        self.assertTrue(drv.mifare_ul_write(4, b"\x03\x00\xFE\x00"))


class TestPM3DriverAPDU(unittest.TestCase):
    def test_data_exchange(self):
        output = "[+] response: 6F1A840E325041592E5359532E4444463031A5088801025F2D02656E9000\n"
        drv = _make_drv(output)
        resp = drv.data_exchange(bytes.fromhex("00A404000E325041592E5359532E444446303100"))
        self.assertIsNotNone(resp)
        self.assertTrue(len(resp) > 4)

    def test_data_exchange_no_response(self):
        drv = _make_drv("")
        self.assertIsNone(drv.data_exchange(b"\x00\xA4\x04\x00"))


class TestPM3DriverRaw(unittest.TestCase):
    def test_communicate_thru_delegates(self):
        drv = _make_drv("[+] response: 9000\n")
        self.assertIsNotNone(drv.communicate_thru(b"\x00\xA4\x04\x00"))

    def test_in_communicate_thru_raw(self):
        drv = _make_drv("[+] received: 0400\n")
        resp = drv.in_communicate_thru_raw(b"\x50\x00")
        self.assertEqual(resp, bytes.fromhex("0400"))


class TestPM3DriverEmulation(unittest.TestCase):
    def test_init_as_target(self):
        drv = _make_drv("[+] Simulating ISO/IEC 14443 type A tag with UID DEADBEEF\n")
        resp = drv.init_as_target(b"\xDE\xAD\xBE\xEF")
        self.assertEqual(resp, b"\xDE\xAD\xBE\xEF")

    def test_tg_stubs(self):
        drv = _make_drv()
        self.assertIsNone(drv.tg_get_data())
        self.assertFalse(drv.tg_set_data(b"\x00"))


class TestPM3DriverDetect(unittest.TestCase):
    def test_detect_rdv4(self):
        output = "[ Proxmark3 RFID instrument ]\n HW Version................. RDV4\n RRG/Iceman\n"
        with mock.patch("os.path.exists", return_value=True):
            with mock.patch("subprocess.run", return_value=_fake_run(output)):
                result = PM3Driver.detect_pm3()
        self.assertIsNotNone(result)
        self.assertEqual(result[1], "PM3 RDV4")

    def test_detect_no_device(self):
        with mock.patch("os.path.exists", return_value=False):
            self.assertIsNone(PM3Driver.detect_pm3())

    def test_detect_easy(self):
        output = "[ Proxmark3 RFID instrument ]\n HW Version: Easy\n RRG/Iceman\n"
        with mock.patch("os.path.exists", return_value=True):
            with mock.patch("subprocess.run", return_value=_fake_run(output)):
                result = PM3Driver.detect_pm3()
        self.assertEqual(result[1], "PM3 Easy")


class TestPM3DriverProperties(unittest.TestCase):
    def test_can_write_and_emulate(self):
        drv = _make_drv()
        self.assertTrue(drv.can_write)
        self.assertTrue(drv.can_emulate)

    def test_close(self):
        drv = _make_drv()
        drv._proc = mock.MagicMock()
        drv._proc.poll.return_value = None
        drv._proc.stdin = mock.MagicMock()
        drv.close()

    def test_sam_config_is_noop(self):
        drv = _make_drv()
        drv.sam_config()

    def test_get_firmware(self):
        drv = _make_drv("[ Proxmark3 RFID instrument ]\n")
        fw = drv.get_firmware()
        self.assertEqual(fw, (3, 0, 0, 0))


class TestAutoDetectPM3Priority(unittest.TestCase):
    def test_pm3_takes_priority_over_pn532(self):
        pm3_output = "[ Proxmark3 RFID instrument ]\n RRG/Iceman\n"
        with mock.patch("os.path.exists", return_value=True):
            with mock.patch("subprocess.run", return_value=_fake_run(pm3_output)):
                with mock.patch.object(PM3Driver, "_start"):
                    drv, desc = auto_detect()
        self.assertIsInstance(drv, PM3Driver)
        self.assertIn("PM3", desc)

    def test_falls_back_when_no_pm3(self):
        with mock.patch.object(PM3Driver, "detect_pm3", return_value=None):
            drv, desc = auto_detect()
        self.assertNotIsInstance(drv, PM3Driver)


class TestCardInfoPreserved(unittest.TestCase):
    def test_identify_classic_1k(self):
        self.assertEqual(identify_card(0x0004, 0x08, 4), "MIFARE Classic 1K")

    def test_identify_ultralight(self):
        self.assertEqual(identify_card(0x0044, 0x00, 7), "MIFARE Ultralight")

    def test_identify_emv(self):
        self.assertEqual(identify_card(0x0048, 0x20, 4), "ISO 14443-4 (EMV)")

    def test_cardinfo_post_init(self):
        card = CardInfo(uid=bytes.fromhex("DEADBEEF"), atqa=0x0004, sak=0x08)
        self.assertEqual(card.uid_hex, "DEADBEEF")
        self.assertEqual(card.card_type, "MIFARE Classic 1K")

    def test_is_classic(self):
        card = CardInfo(uid=b"\x01\x02\x03\x04", sak=0x08)
        self.assertTrue(is_classic(card))
        self.assertFalse(is_ultralight(card))
        self.assertFalse(is_emv(card))


class TestPM3ReadRetry(unittest.TestCase):
    def test_retries_until_card_found(self):
        no_card = "[usb|script] pm3 --> hf 14a reader\n"
        with_card = (
            "[+]  UID: AA BB CC DD\n"
            "[+] ATQA: 00 04\n"
            "[+]  SAK: 08 [2]\n"
        )
        drv = _make_drv()
        drv._send = mock.MagicMock(side_effect=[no_card, no_card, with_card])
        card = drv.read_passive_target(timeout=5.0)
        self.assertIsNotNone(card)
        self.assertEqual(card.uid_hex, "AABBCCDD")

    def test_gives_up_after_timeout(self):
        drv = _make_drv("[usb|script] pm3 --> hf 14a reader\n")
        card = drv.read_passive_target(timeout=0.3)
        self.assertIsNone(card)


if __name__ == "__main__":
    unittest.main()
