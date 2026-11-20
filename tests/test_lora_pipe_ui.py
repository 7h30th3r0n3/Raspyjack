"""Regression checks for the native recorder menu and private keyboard entry."""
import importlib.util
import os
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("recorder_ui", ROOT / "payloads/hardware/Evil-LORA-Tunnel.py")
ui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ui)


class MenuTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.screen = Mock()
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(ui, "SESSIONS", self.root / "sessions"))
        stack.enter_context(patch.dict(os.environ, {"EVIL_LORA_TUNNEL_CONFIG": str(self.root / "config.json")}))
        self.app = ui.Recorder(self.screen)

    def test_cancel_region_creates_no_files_and_spawns_no_worker(self):
        self.screen.choose.return_value = None
        with patch.object(ui.subprocess, "Popen") as worker:
            self.app.start()
        worker.assert_not_called()
        self.assertFalse(ui.SESSIONS.exists())

    def test_failed_spawn_and_immediate_stop_leave_readable_final_status(self):
        ui.config.set_value("region", "US")
        with patch.object(ui.subprocess, "Popen", side_effect=OSError("test launch error")), self.assertRaises(OSError):
            self.app.start()
        failed = ui.session.status(self.app.directory)
        self.assertEqual(failed["status"], "interrupted")
        self.assertIn("test launch error", failed["errors"][0])
        with patch.object(ui.subprocess, "Popen") as spawn:
            spawn.return_value.poll.side_effect = [None, -15]
            self.app.start()
            self.app.stop()
        early = ui.session.status(self.app.directory)
        self.assertEqual(early["status"], "interrupted")
        self.assertIn("before initialization", early["errors"][0])
        self.assertIn("ended_at", early)

    def test_reconnect_verifies_the_foreground_worker_after_pinning_pid(self):
        directory = ui.session.create_session(ui.SESSIONS)
        saved = {"pid": 2345, "start_tick": "678", "boot": "test-boot"}
        state = ui.session.status(directory)
        state.update(status="capturing", pid=saved["pid"], worker_identity=saved)
        ui.session.atomic_json(directory / "session.json", state)
        ui.session.atomic_json(ui.SESSIONS / ".active-session.json", directory.name)
        worker_argv = b"python\0-m\0evil_lora_tunnel\0" + os.fsencode(directory) + b"\0"
        with patch.object(ui.os, "pidfd_open", create=True, return_value=99), \
             patch.object(ui.os, "close") as close, \
             patch.object(Path, "read_bytes", return_value=b"python\0other.py\0") as cmdline, \
             patch.object(ui.session, "process_identity", return_value=saved) as identity:
            self.app.reconnect()  # Same PID/start tick, wrong executable arguments.
            self.assertIsNone(self.app.worker)
            close.assert_called_once_with(99)
            cmdline.return_value = worker_argv
            identity.side_effect = [saved, dict(saved, start_tick="999")]
            self.app.reconnect()  # Process changed after reading session status.
            self.assertIsNone(self.app.worker)
            self.assertEqual(close.call_count, 2)
            identity.side_effect = None
            self.app.reconnect()
            self.assertEqual(self.app.worker.pid, saved["pid"])
            self.assertEqual(self.app.directory, directory)

    def test_active_session_cannot_be_attached_to_or_switched(self):
        self.app.worker = Mock()
        self.app.worker.poll.return_value = None
        self.app.directory = self.root / "current"
        with self.assertRaises(ValueError):
            self.app.select_session()
        with self.assertRaises(ValueError):
            self.app.export()
        self.screen.choose.assert_not_called()
        self.app.worker.terminate.assert_not_called()

    def test_existing_account_credentials_are_never_prefilled(self):
        self.screen.choose.side_effect = ["WiGLE", "Credentials"]
        self.screen.text_input.side_effect = ["test-name", None]
        with patch.object(ui.config, "set_value") as save:
            self.app.accounts()
        save.assert_called_once_with("uploads.wigle.api_name", "test-name")
        for call in self.screen.text_input.call_args_list:
            self.assertEqual(call.args[1], "")
            self.assertTrue(call.kwargs["masked"])


class KeyboardTests(unittest.TestCase):
    def setUp(self):
        # Keep RaspyJack's real input socket and the Linux display out of host tests.
        with patch.dict(sys.modules, {"rj_input": None, "LCD_1in44": None}):
            from payloads import _keyboard_helper
        self.keyboard = _keyboard_helper
        self.lcd = Mock(width=128, height=128)
        self.draw = Mock()
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(self.keyboard, "Image", Mock()))
        stack.enter_context(patch.object(self.keyboard, "ScaledDraw", return_value=self.draw))
        stack.enter_context(patch.object(self.keyboard, "scaled_font", return_value=Mock(), create=True))
        stack.enter_context(patch.object(self.keyboard.time, "sleep"))

    def test_masked_physical_shift_backspace_enter_and_mirror(self):
        frames = iter([{42, 31}, {21}, {14}, {54, 17}, {28}])  # S, y, backspace, W, enter
        held = set()
        def show_frame(*args):
            held.clear()
            held.update(next(frames))
        self.lcd.LCD_ShowImage.side_effect = show_frame
        hardware = Mock(is_key_pressed=held.__contains__)
        with patch.dict(sys.modules, {"evdev_keys": hardware}), \
             patch.object(self.keyboard, "get_button", side_effect=lambda *_: "KEY2" if 14 in held else None), \
             patch.object(self.keyboard, "open_remote_text_session") as open_remote, \
             patch.object(self.keyboard, "get_remote_text_event") as read_remote:
            value = self.keyboard.lcd_keyboard(self.lcd, Mock(), {}, None, masked=True)
        self.assertEqual(value, "SW")
        fields = [call.args[1] for call in self.draw.text.call_args_list if call.args[0] == (4, 16)]
        self.assertEqual(fields, ["|", "*|", "**|", "*|", "**|"])
        open_remote.assert_not_called()
        read_remote.assert_not_called()

    def test_ordinary_keyboard_still_accepts_remote_text(self):
        events = [{"key": "sample"}, {"special": "ENTER"}]
        with patch.dict(sys.modules, {"evdev_keys": None}), \
             patch.object(self.keyboard, "get_button", return_value=None), \
             patch.object(self.keyboard, "open_remote_text_session", return_value="id"), \
             patch.object(self.keyboard, "get_remote_text_event", side_effect=events), \
             patch.object(self.keyboard, "close_remote_text_session") as close_remote:
            result = self.keyboard.lcd_keyboard(self.lcd, Mock(), {}, None)
        self.assertEqual(result, "sample")
        close_remote.assert_called_once_with("id")
