# Adapted from LORA-Pager-Pipe, copyright 2026 Valleytech Solutions.
# MIT license: see evil_lora_tunnel/LICENSE.
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest
from contextlib import closing
from unittest.mock import MagicMock, patch

from evil_lora_tunnel import RadioError, session
from evil_lora_tunnel import gnss
from evil_lora_tunnel.gnss import nmea_fix
from evil_lora_tunnel.session import GPS, Store, create_session, atomic_json, attach, finalize


class SessionTests(unittest.TestCase):
    def test_native_cap_nmea(self):
        def nmea(text):
            raw = text.encode("ascii")
            checksum = 0
            for byte in raw:
                checksum ^= byte
            return b"$" + raw + (f"*{checksum:02X}\r\n").encode("ascii")

        rmc = nmea("GNRMC,123519.00,A,4807.038,N,01131.000,E,0,0,010126,,,A")
        fix = nmea_fix(rmc)
        self.assertAlmostEqual(fix["lat"], 48.1173)
        self.assertAlmostEqual(fix["lon"], 11 + 31/60)
        self.assertEqual(fix["time"], "2026-01-01T12:35:19+00:00")
        self.assertIsNone(nmea_fix(rmc.replace(b"4807", b"4808")))
        gga = "GNGGA,123519.00,4807.038,S,01131.000,W,1,08,0.90,123.4,M,0,M,,"
        self.assertEqual(nmea_fix(nmea(gga))["altMSL"], 123.4)
        self.assertLess(nmea_fix(nmea(gga))["lat"], 0)
        self.assertEqual(nmea_fix(nmea(gga.replace(",1,08", ",0,08")))["mode"], 1)
        self.assertIsNone(nmea_fix(nmea(gga.replace("4807", "4861"))))

    def test_cap_worker_keeps_raw_and_closes_after_stop(self):
        stopped = threading.Event()
        def receive(profile):
            stopped.set()
            return {"timestamp": 1700000000, "profile": profile.to_dict(),
                    "raw_hex": "fedcba", "crc_ok": False, "rssi_dbm": -80, "snr_db": -1}
        with tempfile.TemporaryDirectory() as tmp, patch("evil_lora_tunnel.cap.CapRadio") as cap:
            radio = cap.return_value
            radio.diagnostics = {}
            radio.receive.side_effect = lambda timeout: receive(cap.call_args.args[0])
            path = create_session(tmp)
            with patch.object(GPS, "run", lambda gps, stop: stop.wait(2)):
                result = session._collect(path, {"backend": "cap", "region": "US"}, stopped, None)
            self.assertEqual(result, 0)
            radio.close.assert_called_once()
            self.assertEqual(session.status(path)["saved"], 1)
            record = json.loads((path/"observations.jsonl").read_text())
            self.assertEqual(record["raw_hex"], "fedcba")
            self.assertEqual(record["decoded"]["decode_status"], "crc_error")
            self.assertEqual(record["receiver_gps"]["status"], "no_fix")
            with closing(sqlite3.connect(path/"capture.sqlite3")) as db:
                self.assertEqual(db.execute("SELECT raw FROM observations").fetchone()[0], bytes.fromhex("fedcba"))
            self.assertTrue((path/"lora.pcap").read_bytes().endswith(bytes.fromhex("fedcba")))

    def test_radio_open_failure_preserves_actionable_status(self):
        with tempfile.TemporaryDirectory() as tmp, patch("evil_lora_tunnel.cap.CapRadio") as cap:
            radio = cap.return_value
            radio.diagnostics = {}
            radio.open.side_effect = RadioError("Cap GPIO busy")
            path = create_session(tmp)
            self.assertEqual(session._collect(path, {"backend":"cap","region":"US"}, threading.Event(), None), 1)
            self.assertEqual(session.status(path)["status"], "interrupted")
            self.assertIn("Cap GPIO busy", session.status(path)["errors"])
            radio.close.assert_called_once()

    def test_orphaned_worker_is_interrupted_after_pid_reuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = create_session(tmp)
            meta = session.status(path)
            meta.update(status="capturing", pid=123,
                        worker_identity={"pid": 123, "boot": "one", "start_tick": "10"})
            atomic_json(path / "session.json", meta)
            with patch.object(session, "process_identity", return_value=dict(meta["worker_identity"])):
                self.assertEqual(session.status(path)["status"], "capturing")
            with patch.object(session, "process_identity", return_value={"pid": 123, "boot": "two", "start_tick": "10"}):
                self.assertEqual(session.status(path)["status"], "interrupted")
            self.assertEqual(json.loads((path / "session.json").read_text())["status"], "interrupted")
            with self.assertRaises(ValueError):
                finalize(path)

    def test_gps_fallback_yields_uart_to_native_wardriving(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(gnss, "uart_available") as probe:
            path = Path(tmp)
            (path / gnss.SHARED_GPS).touch()
            gnss.read_cap_uart(threading.Event(), self.fail, path)
            probe.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "requires POSIX advisory locks")
    def test_live_uart_is_closed_before_wifi_handoff_returns(self):
        opened = threading.Event()
        closed = threading.Event()
        stopped = threading.Event()
        serial = MagicMock()
        port = serial.Serial.return_value

        def enter():
            opened.set()
            return port

        def read_until(delimiter, size):
            stopped.wait(0.01)
            return b""

        port.read_until.side_effect = read_until
        port.__enter__.side_effect = enter
        port.__exit__.side_effect = lambda *args: closed.set()
        with tempfile.TemporaryDirectory() as tmp, patch.dict(sys.modules, {"serial": serial}), \
                patch.object(gnss, "uart_available", return_value=True):
            directory = Path(tmp)
            thread = threading.Thread(target=gnss.read_cap_uart, args=(stopped, self.fail, directory))
            thread.start()
            try:
                self.assertTrue(opened.wait(2))
                gnss.share_gps(directory)
                self.assertTrue(closed.is_set())
            finally:
                stopped.set()
                thread.join(2)

    def test_gps_expiry_and_invalid_fix_never_emit_coordinates(self):
        gps = GPS()
        gps.update({'class':'TPV','mode':3,'lat':0.0,'lon':0.0}, now=10)
        self.assertTrue(gps.snapshot(now=15)['valid'])
        self.assertEqual(gps.snapshot(now=21)['status'], 'stale')
        self.assertNotIn('latitude', gps.snapshot(now=21))
        gps.update({'class':'TPV','mode':1,'lat':20,'lon':30}, now=25)
        self.assertFalse(gps.snapshot(now=26)['valid'])
        self.assertNotIn('latitude', gps.snapshot(now=26))

    def test_partial_tpv_does_not_erase_or_refresh_fix(self):
        gps = GPS()
        gps.update({'class':'TPV','mode':3,'lat':12,'lon':34}, now=10)
        gps.update({'class':'TPV','mode':3,'speed':1.2}, now=15)
        self.assertEqual(gps.snapshot(now=16)['age_seconds'], 6)
        self.assertTrue(gps.snapshot(now=16)['valid'])
        self.assertFalse(gps.snapshot(now=21)['valid'])

    def test_duplicate_packet_keeps_two_observations_one_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = create_session(tmp)
            store = Store(path)
            from evil_lora_tunnel.profiles import select_profiles
            record = {'timestamp':100.0,'raw_hex':'010203','profile':select_profiles('US')[0].to_dict(),
                      'rssi_dbm':-80.0,'snr_db':2.5,'crc_ok':True,
                      'decoded':{'protocol':'meshtastic','node_id':'1234'}}
            store.append(record)
            store.append(dict(record,timestamp=102.0,rssi_dbm=-77))
            store.close()
            with closing(sqlite3.connect(path/'capture.sqlite3')) as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM observations').fetchone()[0],2)
                self.assertEqual(db.execute('SELECT sightings FROM devices').fetchone()[0],2)
            self.assertEqual(len((path/'observations.jsonl').read_text().splitlines()),2)

    def test_finalize_requires_closed_and_preserves_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = create_session(tmp)
            csv = Path(tmp)/'native.csv'
            csv.write_text('example')
            attach(path,'wifi_csv',csv)
            with self.assertRaises(ValueError): finalize(path)
            metadata = json.loads((path/'session.json').read_text())
            metadata['status']='closed'
            atomic_json(path/'session.json',metadata)
            finalize(path)
            self.assertEqual(csv.read_bytes(),(path/'wifi.csv').read_bytes())
            csv.unlink()
            finalize(path)
            self.assertEqual((path/'wifi.csv').read_text(), 'example')

if __name__ == '__main__': unittest.main()
