"""Run the RaspyJack recorder and background worker against a Linux pseudo-terminal."""

import csv
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import sqlite3
import struct
import sys
import tempfile
import time
import unittest
from contextlib import closing
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = ROOT / "payloads" / "hardware" / "Evil-LORA-Tunnel.py"


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open")
                     and hasattr(signal, "pidfd_send_signal") and importlib.util.find_spec("serial"),
                     "requires Linux pidfds and pyserial")
class LinuxRecorderTest(unittest.TestCase):
    def test_background_resume_stop_and_export(self):
        from evil_lora_tunnel import config, session

        try:
            probe = os.pidfd_open(os.getpid())
            try:
                signal.pidfd_send_signal(probe, 0)
            finally:
                os.close(probe)
            master, slave = os.openpty()
        except OSError as exc:
            self.skipTest(f"Kernel pidfds and /dev/pts are required: {exc}")
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)

        spec = importlib.util.spec_from_file_location("raspyjack_lora_ui", PAYLOAD)
        ui = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ui)
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            loot = tmp / "loot"
            lock = tmp / "worker.lock"
            # Only replace the hardware GPS reader and shared lock in the child.
            # Keep the actual -m command line for the pidfd/boot identity check.
            (tmp / "sitecustomize.py").write_text(
                "from pathlib import Path\n"
                "from evil_lora_tunnel import session\n"
                "session.GPS.run = lambda self, stop: stop.wait()\n"
                "session.LOCK_PATH = Path(__file__).parent / 'worker.lock'\n"
            )
            env = {"EVIL_LORA_TUNNEL_CONFIG": str(tmp / "private" / "config.json"),
                   "PYTHONPATH": os.pathsep.join((str(tmp), str(ROOT), os.getenv("PYTHONPATH", "")))}
            with patch.dict(os.environ, env), patch.object(ui, "LOOT", loot), \
                    patch.object(ui, "SESSIONS", loot / "evil-lora-tunnel"), \
                    patch.object(session, "LOCK_PATH", lock):
                config.set_value("region", "US")
                config.set_value("backend", "lorapipe")
                config.set_value("serial_device", os.ttyname(slave))
                screen = Mock()
                screen.confirm.return_value = True
                screen.choose.return_value = "LoRa + native Wi-Fi"
                first = ui.Recorder(screen)
                first.start()
                proc = first.worker
                directory = first.directory
                try:
                    self.answer_command(master, b"ver", b"  -> LoRaPipe (Build: test)")
                    self.answer_command(master, b"rxlog off", b"  ->    rxlog off")
                    self.answer_command(master, b"tempradio 906.875000,250,11,5,2b,5",
                                        b"  -> OK - temp params for 5 mins")
                    self.answer_command(master, b"rxlog on", b"  ->    rxlog on")
                    self.wait_for_status(session, directory, proc, "status", "capturing")
                    self.assertTrue(lock.exists())
                    # The next UI can find this foreground collector even if
                    # the previous launcher is killed before explicit handoff.
                    recovered = ui.Recorder(screen)
                    self.assertIsInstance(recovered.worker, ui.BackgroundWorker)
                    self.assertEqual(recovered.worker.pid, proc.pid)
                    os.close(recovered.worker.fd)
                    frames = [bytes.fromhex("007fff"), bytes(range(255)), bytes.fromhex("007fff")]
                    self.send_frame(master, 1, frames[0])
                    with self.assertRaises(ui.ExitPayload):
                        first.background()
                    self.assertIsNone(first.worker)
                    self.assertEqual(json.loads((directory.parent / ".active-session.json").read_text()), directory.name)
                    self.assertTrue((directory / ".shared-gpsd").is_file())
                    self.send_frame(master, 2, frames[1])
                    reopened = ui.Recorder(screen)
                    self.assertIsInstance(reopened.worker, ui.BackgroundWorker)
                    self.assertEqual(reopened.worker.pid, proc.pid)
                    self.assertTrue(reopened.running())
                    self.send_frame(master, 3, frames[2])
                    self.wait_for_status(session, directory, proc, "saved", len(frames))
                    reopened.stop()
                    self.assertEqual(proc.wait(timeout=5), 0)
                    self.assertTrue(select.select([master], [], [], 2)[0])
                    self.assertEqual(os.read(master, 256).strip(), b"rxlog off")
                    self.assertFalse((directory.parent / ".active-session.json").exists())
                finally:
                    if proc.poll() is None:
                        ui.finish_process(proc)

                status = session.status(directory)
                self.assertEqual(status["status"], "closed")
                self.assertEqual((status["received"], status["saved"], status["queue_drops"],
                                  status["write_errors"], status["radio"]["retune_dropped"]),
                                 (len(frames), len(frames), 0, 0, 0))
                records = [json.loads(line) for line in (directory / "observations.jsonl").read_text().splitlines()]
                self.assertEqual([bytes.fromhex(row["raw_hex"]) for row in records], frames)
                self.assertEqual([row["receiver_timestamp"] for row in records], [1, 2, 3])
                with closing(sqlite3.connect(directory / "capture.sqlite3")) as db:
                    self.assertEqual([r[0] for r in db.execute("SELECT raw FROM observations ORDER BY id")], frames)
                with (directory / "lora.pcap").open("rb") as capture:
                    header = struct.unpack("<IHHIIII", capture.read(24))
                    self.assertEqual((header[0], header[-1]), (0xA1B2C3D4, 270))
                    for raw in frames:
                        _, _, incl, orig = struct.unpack("<IIII", capture.read(16))
                        self.assertEqual(incl, orig)
                        frame = capture.read(incl)
                        loratap_length = int.from_bytes(frame[2:4], "big")
                        self.assertEqual(frame[loratap_length:], raw)
                    self.assertEqual(capture.read(), b"")

                native = loot / "wardrive.csv"
                native.write_text("WigleWifi-1.4,appRelease=RaspyJack-v2\n"
                                  "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,"
                                  "CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n"
                                  "02:11:22:33:44:55,Fixture,[ESS],1700000000,1,-60,40.1,-74.1,,,WIFI\n")
                ui.session_action(directory, "wifi_csv", native)
                self.assertEqual((directory / "wifi.csv").read_bytes(), native.read_bytes())
                self.assertIn("Wi-Fi rows: 1", ui.session_action(directory, "export"))
                artifact, = (directory / ".uploads" / "exports").glob("wifi-*.csv")
                with artifact.open(newline="") as source:
                    source.readline()
                    row, = csv.DictReader(source)
                self.assertEqual((row["SSID"], row["FirstSeen"]), ("Fixture", "2023-11-14 22:13:20"))

    def answer_command(self, fd, expected, reply):
        data = b""
        deadline = time.monotonic() + 5
        while not data.endswith(b"\n"):
            timeout = deadline - time.monotonic()
            self.assertTrue(timeout > 0 and select.select([fd], [], [], timeout)[0],
                            f"timed out waiting for {expected!r}, read {data!r}")
            data += os.read(fd, 256)
        self.assertEqual(data.strip(), expected)
        os.write(fd, data + reply + b"\r\n")

    def send_frame(self, fd, index, raw):
        os.write(fd, f"{index},RXLOG,-71.5,2.0,{raw.hex()}\r\n".encode("ascii"))

    def wait_for_status(self, session, directory, proc, field, expected):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            report = session.status(directory)
            if report.get(field) == expected:
                return
            self.assertIsNone(proc.poll(), report)
            time.sleep(.03)
        self.fail(f"{field} did not reach {expected!r}: {session.status(directory)}")


if __name__ == "__main__":
    unittest.main()
