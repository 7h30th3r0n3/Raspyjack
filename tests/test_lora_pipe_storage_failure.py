# Adapted from LORA-Pager-Pipe, copyright 2026 Valleytech Solutions.
# MIT license: see evil_lora_tunnel/LICENSE.
"""Storage failures must not prevent the other capture sinks from closing."""

import sqlite3
import tempfile
import unittest
from unittest.mock import patch


from evil_lora_tunnel.profiles import select_profiles
from evil_lora_tunnel.session import Store, create_session


class FailingClose:
    def __init__(self, resource, failure):
        self.resource = resource
        self.failure = failure

    def __getattr__(self, name):
        return getattr(self.resource, name)

    def close(self):
        self.resource.close()
        raise self.failure


class StorageFailureTests(unittest.TestCase):
    def store_with_packet(self, root):
        store = Store(create_session(root))
        store.append({"timestamp": 1700000000.0, "raw_hex": "010203",
                      "profile": select_profiles("US")[0].to_dict(),
                      "rssi_dbm": -80.0, "snr_db": 2.5, "crc_ok": True,
                      "decoded": {"protocol": "unknown", "decode_status": "raw"}})
        return store

    def assert_closed(self, store):
        self.assertTrue(store.stream.closed)
        self.assertTrue(store.pcap._stream.closed)
        with self.assertRaises(sqlite3.ProgrammingError):
            store.db.execute("SELECT 1")

    def test_jsonl_close_failure_still_closes_pcap_and_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self.store_with_packet(tmp)
            failure = OSError("simulated full storage during JSONL close")
            store.stream = FailingClose(store.stream, failure)
            with self.assertRaises(OSError) as caught:
                store.close()
            self.assertIs(caught.exception, failure)
            self.assert_closed(store)
            self.assertEqual((store.directory / "lora.pcap").read_bytes()[-3:], b"\x01\x02\x03")

    def test_database_close_failure_does_not_skip_file_closes(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self.store_with_packet(tmp)
            failure = sqlite3.OperationalError("simulated database close failure")
            store.db = FailingClose(store.db, failure)
            with self.assertRaises(sqlite3.OperationalError) as caught:
                store.close()
            self.assertIs(caught.exception, failure)
            self.assert_closed(store)

    def test_flush_failure_is_preserved_when_later_close_also_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self.store_with_packet(tmp)
            first = OSError("simulated full storage during flush")
            store.stream = FailingClose(store.stream, OSError("later close failure"))
            with patch.object(store, "flush", side_effect=first):
                with self.assertRaises(OSError) as caught:
                    store.close()
            self.assertIs(caught.exception, first)
            self.assert_closed(store)
            # PCAP.close still flushes its independent buffer after the failure.
            self.assertEqual((store.directory / "lora.pcap").read_bytes()[-3:], b"\x01\x02\x03")


if __name__ == "__main__":
    unittest.main()
