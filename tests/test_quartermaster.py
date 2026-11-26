"""Exercise the external-app handoff without booting RaspyJack's hardware UI."""

import ast
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import quartermaster_launcher as launcher


class QuartermasterTests(unittest.TestCase):
    def test_platform_launchers_keep_home_groups_and_drop_the_root_environment(self):
        user = SimpleNamespace(pw_name="builder", pw_uid=1010, pw_gid=1011, pw_dir="/home/builder",
                               pw_shell="/bin/bash")
        with (patch.dict(os.environ, {"HOME": "/root", "PYTHONPATH": "/root/Raspyjack"}, clear=True),
              patch.object(launcher.pwd, "getpwall", return_value=[user]),
              patch.object(os, "getgrouplist", return_value=[1011, 22, 44]),
              patch.object(os, "access", return_value=True), patch.object(launcher, "already_running", return_value=False)):
            for profile, want in (("ST7735_128", "st7735-128"), ("ST7789_240", "st7789-240"),
                                  ("CARDPUTER_320", None)):
                command, options = launcher.prepare(profile, "/dev/fb1")
                if want:
                    self.assertEqual(command, [launcher.DIY, "--display", want])
                else:
                    self.assertEqual(command, [launcher.CARDPUTER])
                    self.assertEqual(options["env"]["APPLAUNCH_LINUX_FBDEV_DEVICE"], "/dev/fb1")
                self.assertEqual((options["user"], options["group"], options["extra_groups"]), (1010, 1011, [1011, 22, 44]))
                self.assertEqual(options["cwd"], options["env"]["HOME"])
                self.assertEqual(options["cwd"], user.pw_dir)
                self.assertNotIn("PYTHONPATH", options["env"])

    def test_ambiguous_or_root_account_is_never_used(self):
        def user(name, uid):
            return SimpleNamespace(pw_name=name, pw_uid=uid, pw_shell="/bin/bash")
        first, second = user("pi", 1000), user("ops", 1001)
        with (patch.dict(os.environ, {}, clear=True),
              patch.object(launcher.pwd, "getpwall", return_value=[first, second, user("root", 0)])):
            with self.assertRaises(launcher.LaunchError):
                launcher.login_user()
            os.environ["RJ_QUARTERMASTER_USER"] = "ops"
            self.assertIs(launcher.login_user(), second)
            os.environ["RJ_QUARTERMASTER_USER"] = "root"
            with self.assertRaises(launcher.LaunchError):
                launcher.login_user()

    def test_active_process_and_missing_package(self):
        with tempfile.TemporaryDirectory() as folder:
            proc = Path(folder)
            task = proc / "1234" / "cmdline"
            task.parent.mkdir()
            task.write_bytes(b"/usr/bin/python3\0-m\0quartermaster\0--display\0st7789-240\0")
            self.assertTrue(launcher.already_running(proc))
            task.write_bytes(task.read_bytes() + b"--probe\0")
            self.assertFalse(launcher.already_running(proc))
        with patch.object(os, "access", return_value=False), self.assertRaisesRegex(launcher.LaunchError, "WARD"):
            launcher.prepare("CARDPUTER_320", "/dev/fb1")
        with (patch.object(os, "access", return_value=True), patch.object(launcher, "already_running", return_value=True),
              self.assertRaisesRegex(launcher.LaunchError, "already running")):
            launcher.prepare("ST7735_128", None)

    def test_pi_display_releases_and_reopens_bus_on_error(self):
        for profile in ("ST7735_128", "ST7789_240"):
            with tempfile.TemporaryDirectory() as folder:
                source = Path(folder) / "LCD_Config.py"
                shutil.copyfile(ROOT / source.name, source)
                source.with_name("gui_conf.json").write_text(json.dumps({"DISPLAY": {"type": profile}}))
                gpio, spidev = Mock(), Mock()
                with patch.dict(sys.modules, {"RPi": SimpleNamespace(GPIO=gpio), "RPi.GPIO": gpio, "spidev": spidev}):
                    spec = importlib.util.spec_from_file_location("hat_config", source)
                    config = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(config)
                    with self.assertRaises(OSError), config.quartermaster_display([6, 19, 5, 26, 13, 21, 20, 16]):
                        gpio.cleanup.assert_called_once_with((6, 19, 5, 26, 13, 21, 20, 16, 27, 25, 8, 24))
                        config.SPI.close.assert_called_once()
                        raise OSError("device disconnected")
                    config.SPI.open.assert_called_once_with(0, 0)

    @unittest.skipUnless(os.name == "posix", "needs POSIX mmap flags")
    def test_cardputer_framebuffer_is_closed_and_reopened(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "LCD_Config.py"
            shutil.copyfile(ROOT / source.name, source)
            source.with_name("gui_conf.json").write_text('{"DISPLAY": {"type": "CARDPUTER_320"}}')
            fb = Path(folder) / "fb-test"
            fb.write_bytes(bytes(320 * 170 * 2))
            with patch.dict(os.environ, {"RJ_FB_DEVICE": str(fb)}):
                spec = importlib.util.spec_from_file_location("fb_config", source)
                config = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(config)
            config.GPIO_Init()
            original = config._fb_mmap
            with config.quartermaster_display([]):
                self.assertTrue(original.closed)
                self.assertIsNone(config._fb_fd)
                with fb.open("r+b") as child_fb:
                    child_fb.write(b"QM")
            config.GPIO_Init()
            self.assertEqual(config._fb_mmap[:2], b"QM")
            with config.quartermaster_display([]):
                pass

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "needs a root Linux test process")
    def test_child_runs_nonroot_and_writes_only_in_its_home(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            path.chmod(0o711)
            home = path / "home"
            home.mkdir()
            uid = gid = 31019
            os.chown(home, uid, gid)
            script = path / "quartermaster"
            script.write_text("#!/usr/bin/python3\nimport json, os\nfrom pathlib import Path\n"
                              "Path('result').write_text(json.dumps([os.getuid(), os.getgid(), os.getgroups(), "
                              "str(Path.home()), str(Path.cwd()), os.getenv('PYTHONPATH')]))\n")
            script.chmod(0o755)
            user = SimpleNamespace(pw_name="builder", pw_uid=uid, pw_gid=gid, pw_dir=str(home), pw_shell="/bin/sh")
            with (patch.dict(os.environ, {"RJ_QUARTERMASTER_USER": "builder", "PYTHONPATH": "/root/Raspyjack"}),
                  patch.object(launcher, "CARDPUTER", str(script)), patch.object(launcher.pwd, "getpwall", return_value=[user]),
                  patch.object(os, "getgrouplist", return_value=[gid]), patch.object(launcher, "already_running", return_value=False)):
                command, options = launcher.prepare("CARDPUTER_320", "/dev/fb0")
            subprocess.run(command, **options, check=True)
            result = home / "result"
            self.assertEqual(result.stat().st_uid, uid)
            self.assertEqual(json.loads(result.read_text()), [uid, gid, [gid], str(home), str(home), None])

    def test_parent_waits_with_display_locked_then_restores_menu_on_error(self):
        # Importing raspyjack.py starts its root-only LCD UI. Exercise the actual menu callback in isolation.
        tree = ast.parse((ROOT / "raspyjack.py").read_text(encoding="utf-8"))
        callback = next(node for node in tree.body if getattr(node, "name", "") == "launch_quartermaster")
        lock, drawing = threading.Event(), threading.Lock()
        events = []

        @contextlib.contextmanager
        def handoff(pins):
            self.assertTrue(lock.is_set() and drawing.locked())
            events.append("release")
            try:
                yield
            finally:
                events.append("reclaim")

        def run(*args, **kwargs):
            self.assertTrue(lock.is_set() and drawing.locked())
            events.append("run")
            raise OSError("launch failed")

        def track(name):
            return lambda *args: events.append(name)
        namespace = dict(LCD=SimpleNamespace(display_type="CARDPUTER_320"),
                         LCD_Config=SimpleNamespace(quartermaster_display=handoff, FB_DEVICE="/dev/fb1"), PINS={},
                         subprocess=Mock(run=run, SubprocessError=RuntimeError), screen_lock=lock, draw_lock=drawing,
                         _setup_gpio=track("reinit"), rj_input=SimpleNamespace(flush=track("flush")),
                         _wait_for_button_release=track("release keys"), _mark_user_activity=track("activity"),
                         RenderCurrentMenuOnce=track("menu"), mark_display_dirty=track("refresh"), Dialog=track("dialog"))
        exec(compile(ast.Module([callback], []), "raspyjack.py", "exec"), namespace)
        with patch.object(launcher, "prepare", return_value=([launcher.CARDPUTER], {})):
            namespace["launch_quartermaster"]()
        self.assertFalse(lock.is_set() or drawing.locked())
        self.assertEqual(events, ["release keys", "release", "run", "reclaim", "reinit", "flush", "release keys",
                                  "activity", "menu", "refresh", "dialog"])


if __name__ == "__main__":
    unittest.main()
