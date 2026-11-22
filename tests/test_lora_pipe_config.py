# Adapted from LORA-Pager-Pipe, copyright 2026 Valleytech Solutions.
# MIT license: see evil_lora_tunnel/LICENSE.
import os
from pathlib import Path
import stat
import sqlite3
import json
import tempfile
import unittest
from contextlib import closing

from evil_lora_tunnel import config, session


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "private/config.json"

    def raw(self, text):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(text, encoding="utf-8")
        os.chmod(self.path, 0o600)

    def test_defaults_are_isolated_and_uploads_disabled(self):
        first = config.load(self.path)
        first["uploads"]["wigle"]["enabled"] = True
        second = config.load(self.path)
        self.assertEqual(second["region"], "")
        self.assertFalse(second["uploads"]["wigle"]["enabled"])
        self.assertFalse(second["uploads"]["wigle"]["auto"])

    def test_valid_updates_preserve_other_fields_and_private_permissions(self):
        config.set_value("region", "US", self.path)
        config.set_value("uploads.wardrift.api_key", "TEST_ONLY", self.path)
        self.assertEqual(config.load(self.path)["region"], "US")
        self.assertEqual(config.load(self.path)["uploads"]["wardrift"]["api_key"], "TEST_ONLY")
        self.assertEqual(list(self.path.parent.glob(".config-*")), [])
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_rejects_unknown_keys_wrong_types_and_injected_controls(self):
        for key, value in (("uploads.wardrift.endpoint", "https://example.com"),
                           ("uploads.wigle.enabled", "false"), ("mode", "invalid"),
                           ("region", "IN"), ("uploads.wigle.api_token", "secret\nvalue")):
            with self.subTest(key=key), self.assertRaises(config.ConfigError):
                config.set_value(key, value, self.path)

    def test_invalid_json_never_overwritten(self):
        self.raw('{"uploads":{"wigle":{"api_token":"TEST_SECRET"}},"unexpected":true}')
        before = self.path.read_bytes()
        with self.assertRaises(config.ConfigError):
            config.set_value("region", "US", self.path)
        self.assertEqual(self.path.read_bytes(), before)

    def test_duplicate_unknown_and_oversized_files_rejected(self):
        for text in ('{"region":"US","region":"ANZ"}', '{"uploads":{"bad":{}}}',
                     '{"mode":{}}', 'x' * (config.MAX_CONFIG_BYTES + 1)):
            self.raw(text)
            with self.assertRaises(config.ConfigError):
                config.load(self.path)

    def test_secret_get_is_blocked(self):
        config.set_value("uploads.wigle.api_token", "TEST_SECRET", self.path)
        with self.assertRaises(config.ConfigError) as caught:
            config.get_value("uploads.wigle.api_token", self.path)
        self.assertNotIn("TEST_SECRET", str(caught.exception))

    def test_symbolic_link_rejected(self):
        destination = Path(self.temporary.name) / "target.json"
        destination.write_text("{}")
        self.path.parent.mkdir()
        try:
            self.path.symlink_to(destination)
        except (OSError, NotImplementedError):
            self.skipTest("Symbolic link creation unavailable")
        with self.assertRaises(config.ConfigError):
            config.load(self.path)

    def test_credentials_are_bounded_ascii(self):
        for value in ("x" * 513, "token with spaces", "\u00e9"):
            with self.subTest(value=len(value)), self.assertRaises(config.ConfigError):
                config.set_value("uploads.wardrift.api_key", value, self.path)

    def test_recent_snapshot_is_bounded_sanitized_and_excludes_unverified_devices(self):
        directory = Path(self.temporary.name)
        path = directory / "capture.sqlite3"
        with closing(sqlite3.connect(path)) as database:
            database.executescript("""CREATE TABLE observations(id INTEGER PRIMARY KEY, received_at REAL, record_json TEXT);
                CREATE TABLE devices(last_seen REAL, latest_json TEXT); PRAGMA user_version=1;""")
            for index in range(12):
                record = {"rssi_dbm": -70, "snr_db": 4.5, "profile": {"id": "meshtastic-US-LONG_FAST"},
                    "receiver_gps": {"latitude": 12.345678},
                    "decoded": {"protocol": "meshtastic", "source_id": "!12345678", "decode_status": "decoded",
                        "name": "Field\nNode", "text": "hello\x1b[2J", "key": "DO_NOT_SHOW"}}
                database.execute("INSERT INTO observations VALUES(?,?,?)", (index, 1700000000 + index, json.dumps(record)))
            database.execute("INSERT INTO devices VALUES(?,?)", (1700000011, json.dumps(record)))
            invalid = {"decoded": {"protocol": "meshcore", "source_id": "a" * 64,
                                  "public_key": "a" * 64, "signature_valid": False, "name": "Unverified"}}
            database.execute("INSERT INTO devices VALUES(?,?)", (1700000012, json.dumps(invalid)))
            database.commit()
        before = path.read_bytes()
        observations = session.recent_records(directory)
        devices = session.recent_records(directory, devices=True)
        text = "\n".join(observations + devices)
        self.assertEqual(len(observations), 16)
        self.assertEqual(len(devices), 2)
        self.assertIn("claimed", text)
        self.assertIn("R-70", text)
        self.assertNotIn("Unverified", text)
        self.assertNotIn("DO_NOT_SHOW", text)
        self.assertNotIn("12.345678", text)
        self.assertNotIn("\x1b", text)
        self.assertEqual(path.read_bytes(), before)
