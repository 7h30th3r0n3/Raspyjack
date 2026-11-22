#!/usr/bin/env python3
"""Tests for optional Kismet installation in install_raspyjack.sh and web_server.py."""

import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

INSTALL_SCRIPT = ROOT / "install_raspyjack.sh"

_AUTH_SECRET_TMP = tempfile.NamedTemporaryFile(prefix="rj_test_secret_", delete=False)
_AUTH_SECRET_TMP.write(b"test-secret\n")
_AUTH_SECRET_TMP.close()
os.environ.setdefault("RJ_WEB_AUTH_SECRET_FILE", _AUTH_SECRET_TMP.name)

from web_server import RaspyJackHandler  # noqa: E402


def _teardown_module():
    try:
        os.unlink(_AUTH_SECRET_TMP.name)
    except OSError:
        pass


tearDownModule = _teardown_module


def _extract_kismet_bash_snippet() -> str:
    text = INSTALL_SCRIPT.read_text(encoding="utf-8")
    header_end = text.index("# ───── mode flag")
    section_start = text.index("# ───── 2‑a1b ▸ Kismet")
    section_end = text.index("# ───── 2‑a1c ▸ Kismet config")
    return text[:header_end] + "\n" + text[section_start:section_end] + '\necho "POST_KISMET_OK"\n'


def _write_exec(path: pathlib.Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _host_tool(name):
    found = shutil.which(name)
    if found:
        return found
    for candidate in (f"/bin/{name}", f"/usr/bin/{name}"):
        if os.path.exists(candidate):
            return candidate
    return None


def _run_kismet_snippet(
    arch: str = "arm64",
    codename: str = "bookworm",
    wget_rc: int = 0,
    gpg_rc: int = 0,
    apt_update_rc: int = 0,
    apt_install_rc: int = 0,
    systemctl_rc: int = 0,
    preexisting_kismet_list: str = "",
    preexisting_keyring=None,
    fail_tmp_rm: bool = False,
    fail_list_rm: bool = False,
):
    bash_bin = shutil.which("bash")
    assert bash_bin is not None

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = pathlib.Path(tmp)
        mock_bin = tmp_path / "bin"
        fake_root = tmp_path / "root"
        call_log = tmp_path / "calls.log"
        mock_bin.mkdir()
        fake_root.mkdir()
        call_log.write_text("", encoding="utf-8")

        if preexisting_kismet_list:
            pre_list = fake_root / "etc/apt/sources.list.d/kismet.list"
            pre_list.parent.mkdir(parents=True, exist_ok=True)
            pre_list.write_text(preexisting_kismet_list, encoding="utf-8")
        if preexisting_keyring is not None:
            pre_key = fake_root / "usr/share/keyrings/kismet-archive-keyring.gpg"
            pre_key.parent.mkdir(parents=True, exist_ok=True)
            pre_key.write_bytes(preexisting_keyring)

        for tool in (
            "tee", "grep", "cut", "tr", "head", "cat", "mkdir", "dirname", "chmod",
            "mv", "cp", "mktemp", "test",
        ):
            real_tool = _host_tool(tool)
            if real_tool:
                (mock_bin / tool).symlink_to(real_tool)
        real_rm = _host_tool("rm")
        assert real_rm is not None
        if fail_tmp_rm or fail_list_rm:
            _write_exec(
                mock_bin / "rm",
                f"#!{bash_bin}\n"
                f'echo "rm $*" >> "{call_log}"\n'
                f'for arg in "$@"; do\n'
                f'  case "$arg" in\n'
                f"    /usr/share/*|/etc/*) ;;\n"
                f"    *kismet-archive-keyring.*)\n"
                f"      if [ {1 if fail_tmp_rm else 0} -eq 1 ]; then\n"
                f'        echo "rm: cannot remove $arg" >&2\n'
                f"        exit 1\n"
                f"      fi\n"
                f"      ;;\n"
                f"    */sources.list.d/kismet.list)\n"
                f"      if [ {1 if fail_list_rm else 0} -eq 1 ]; then\n"
                f'        echo "rm: cannot remove $arg" >&2\n'
                f"        exit 1\n"
                f"      fi\n"
                f"      ;;\n"
                f"  esac\n"
                f"done\n"
                f'exec "{real_rm}" "$@"\n',
            )
        else:
            (mock_bin / "rm").symlink_to(real_rm)

        _write_exec(
            mock_bin / "dpkg",
            f"#!{bash_bin}\necho {arch}\n",
        )
        _write_exec(
            mock_bin / "lsb_release",
            f"#!{bash_bin}\necho {codename}\n",
        )
        _write_exec(
            mock_bin / "wget",
            f"#!{bash_bin}\n"
            f'echo "wget $*" >> "{call_log}"\n'
            f"if [ {wget_rc} -ne 0 ]; then exit {wget_rc}; fi\n"
            f'printf "FAKEKEY"\n',
        )
        _write_exec(
            mock_bin / "gpg",
            f"#!{bash_bin}\n"
            f"cat >/dev/null\n"
            f"if [ {gpg_rc} -ne 0 ]; then exit {gpg_rc}; fi\n"
            f'printf "DEARMOREDKEY"\n',
        )
        _write_exec(
            mock_bin / "apt-get",
            f"#!{bash_bin}\n"
            f'echo "apt-get $*" >> "{call_log}"\n'
            f'for arg in "$@"; do\n'
            f'  if [ "$arg" = "update" ]; then exit {apt_update_rc}; fi\n'
            f'  if [ "$arg" = "install" ]; then\n'
            f"    if [ {apt_install_rc} -eq 0 ]; then\n"
            f'      printf "#!{bash_bin}\\nexit 0\\n" > "{mock_bin}/kismet"\n'
            f'      chmod +x "{mock_bin}/kismet"\n'
            f"    fi\n"
            f"    exit {apt_install_rc}\n"
            f"  fi\n"
            f"done\n"
            f"exit 0\n",
        )
        _write_exec(
            mock_bin / "systemctl",
            f"#!{bash_bin}\n"
            f'echo "systemctl $*" >> "{call_log}"\n'
            f"exit {systemctl_rc}\n",
        )
        _write_exec(
            mock_bin / "sudo",
            f"#!{bash_bin}\n"
            f'echo "sudo $*" >> "{call_log}"\n'
            f"mapped=()\n"
            f'for arg in "$@"; do\n'
            f'  case "$arg" in\n'
            f"    /etc/*|/usr/share/*)\n"
            f'      target="{fake_root}$arg"\n'
            f'      mkdir -p "$(dirname "$target")"\n'
            f'      mapped+=("$target")\n'
            f"      ;;\n"
            f"    *)\n"
            f'      mapped+=("$arg")\n'
            f"      ;;\n"
            f"  esac\n"
            f"done\n"
            f'exec "${{mapped[@]}}"\n',
        )

        snippet_file = tmp_path / "kismet_block.sh"
        snippet_file.write_text(_extract_kismet_bash_snippet(), encoding="utf-8")

        res = subprocess.run(
            [bash_bin, str(snippet_file)],
            capture_output=True,
            text=True,
            env={"PATH": str(mock_bin), "HOME": str(tmp_path), "TMPDIR": str(tmp_path)},
            timeout=15,
        )
        kismet_list = fake_root / "etc/apt/sources.list.d/kismet.list"
        list_content = kismet_list.read_text(encoding="utf-8") if kismet_list.exists() else None
        key_path = fake_root / "usr/share/keyrings/kismet-archive-keyring.gpg"
        key_content = key_path.read_bytes() if key_path.exists() else None
        calls = call_log.read_text(encoding="utf-8").splitlines()
        return res, list_content, calls, key_content


class InstallScriptKismetTests(unittest.TestCase):
    def test_bash_syntax_valid(self):
        res = subprocess.run(["bash", "-n", str(INSTALL_SCRIPT)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, msg=res.stderr)

    def test_apt_install_and_systemctl_failure_stays_nonfatal_under_pipefail(self):
        res, list_content, calls, key_content = _run_kismet_snippet(
            arch="arm64",
            codename="bookworm",
            apt_install_rc=100,
            systemctl_rc=1,
        )
        self.assertEqual(res.returncode, 0, msg=res.stdout + res.stderr)
        self.assertIn("Kismet install failed", res.stdout)
        self.assertIn("POST_KISMET_OK", res.stdout)
        self.assertIsNotNone(list_content)
        self.assertTrue(key_content)
        self.assertIn(b"signed-by=/usr/share/keyrings/kismet-archive-keyring.gpg", list_content.encode())
        self.assertFalse(any(c.startswith("systemctl ") for c in calls))

    def test_happy_path_arm64_bookworm_and_trixie(self):
        for codename in ("bookworm", "trixie"):
            with self.subTest(codename=codename):
                res, list_content, calls, key_content = _run_kismet_snippet(
                    arch="arm64",
                    codename=codename,
                    apt_install_rc=0,
                    systemctl_rc=0,
                )
                self.assertEqual(res.returncode, 0, msg=res.stdout + res.stderr)
                self.assertIn("POST_KISMET_OK", res.stdout)
                self.assertEqual(
                    list_content.strip(),
                    f"deb [arch=arm64 signed-by=/usr/share/keyrings/kismet-archive-keyring.gpg] "
                    f"https://www.kismetwireless.net/repos/apt/release/{codename} {codename} main",
                )
                self.assertIn("apt-get install -y --no-install-recommends kismet", calls)
                self.assertIn("systemctl disable kismet", calls)
                self.assertIn("systemctl stop kismet", calls)
                self.assertTrue(key_content)

    def test_armhf_removes_stale_repo_warns_and_skips_install(self):
        res, list_content, calls, key_content = _run_kismet_snippet(
            arch="armhf",
            codename="bookworm",
            systemctl_rc=1,
            preexisting_kismet_list="deb https://www.kismetwireless.net/repos/apt/release/bookworm bookworm main\n",
        )
        self.assertEqual(res.returncode, 0, msg=res.stdout + res.stderr)
        self.assertIsNone(list_content)
        self.assertIn("64-bit", res.stdout)
        self.assertIn("POST_KISMET_OK", res.stdout)
        self.assertFalse(any(c.startswith("apt-get ") for c in calls))
        self.assertFalse(any(c.startswith("systemctl ") for c in calls))
        self.assertIsNone(key_content)

    def test_gpg_or_apt_update_failure_warns_and_continues(self):
        for label, kwargs in (
            ("gpg_fetch_fail", {"wget_rc": 4}),
            ("apt_update_fail", {"apt_update_rc": 100}),
        ):
            with self.subTest(case=label):
                res, list_content, calls, key_content = _run_kismet_snippet(
                    arch="arm64", codename="bookworm", **kwargs,
                )
                self.assertEqual(res.returncode, 0, msg=res.stdout + res.stderr)
                self.assertIn("[WARN]", res.stdout)
                self.assertIn("POST_KISMET_OK", res.stdout)
                self.assertFalse(any(c.startswith("apt-get install") for c in calls))
                if list_content and "signed-by=/usr/share/keyrings/kismet-archive-keyring.gpg" in list_content:
                    self.assertTrue(key_content)

    def test_gpg_failure_keeps_existing_keyring_and_list(self):
        original_key = b"GOOD-KEYRING"
        original_list = (
            "deb [arch=arm64 signed-by=/usr/share/keyrings/kismet-archive-keyring.gpg] "
            "https://www.kismetwireless.net/repos/apt/release/bookworm bookworm main\n"
        )
        res, list_content, calls, key_content = _run_kismet_snippet(
            arch="arm64",
            codename="bookworm",
            wget_rc=4,
            preexisting_kismet_list=original_list,
            preexisting_keyring=original_key,
        )
        self.assertEqual(res.returncode, 0, msg=res.stdout + res.stderr)
        self.assertIn("POST_KISMET_OK", res.stdout)
        self.assertEqual(list_content, original_list)
        self.assertEqual(key_content, original_key)
        self.assertFalse(any(
            c.startswith("sudo rm") and c.rstrip().endswith("kismet-archive-keyring.gpg")
            for c in calls
        ))
        self.assertFalse(any(
            c.startswith("sudo tee /usr/share/keyrings/kismet-archive-keyring.gpg ")
            or c.startswith("sudo tee /usr/share/keyrings/kismet-archive-keyring.gpg")
            and ".tmp." not in c
            for c in calls
        ))

    def test_gpg_failure_removes_list_when_keyring_missing(self):
        res, list_content, _calls, key_content = _run_kismet_snippet(
            arch="arm64",
            codename="bookworm",
            wget_rc=4,
            preexisting_kismet_list=(
                "deb [arch=arm64 signed-by=/usr/share/keyrings/kismet-archive-keyring.gpg] "
                "https://www.kismetwireless.net/repos/apt/release/bookworm bookworm main\n"
            ),
        )
        self.assertEqual(res.returncode, 0, msg=res.stdout + res.stderr)
        self.assertIn("POST_KISMET_OK", res.stdout)
        self.assertIsNone(list_content)
        self.assertIsNone(key_content)

    def test_tmp_keyring_cleanup_failure_is_reported(self):
        res, _list, _calls, _key = _run_kismet_snippet(
            arch="arm64",
            codename="bookworm",
            wget_rc=4,
            fail_tmp_rm=True,
        )
        self.assertEqual(res.returncode, 0, msg=res.stdout + res.stderr)
        self.assertIn("POST_KISMET_OK", res.stdout)
        self.assertRegex(
            res.stdout,
            r"Could not remove temporary Kismet keyring \S*kismet-archive-keyring\.",
        )

    def test_list_cleanup_failure_is_reported_with_path(self):
        res, list_content, _calls, _key = _run_kismet_snippet(
            arch="arm64",
            codename="bookworm",
            wget_rc=4,
            preexisting_kismet_list=(
                "deb [arch=arm64 signed-by=/usr/share/keyrings/kismet-archive-keyring.gpg] "
                "https://www.kismetwireless.net/repos/apt/release/bookworm bookworm main\n"
            ),
            fail_list_rm=True,
        )
        self.assertEqual(res.returncode, 0, msg=res.stdout + res.stderr)
        self.assertIn("POST_KISMET_OK", res.stdout)
        self.assertIn(
            "Could not remove /etc/apt/sources.list.d/kismet.list "
            "(still references missing Kismet keyring /usr/share/keyrings/kismet-archive-keyring.gpg)",
            res.stdout,
        )
        self.assertIsNotNone(list_content)


class WebServerInstallKismetTests(unittest.TestCase):
    def test_happy_path_arm64_detects_codename_and_disables_service(self):
        for codename in ("bookworm", "trixie"):
            with self.subTest(codename=codename):
                os_release = f'PRETTY_NAME="Debian"\nVERSION_CODENAME={codename}\n'
                calls = []

                def fake_run(cmd, *args, **kwargs):
                    calls.append(cmd)
                    r = mock.MagicMock()
                    r.returncode = 0
                    r.stdout = "arm64\n" if cmd[0] == "dpkg" else ""
                    return r

                with mock.patch("shutil.which", side_effect=[None, "/usr/bin/kismet"]):
                    with mock.patch("builtins.open", mock.mock_open(read_data=os_release)):
                        with mock.patch("web_server.subprocess.run", side_effect=fake_run):
                            ok = RaspyJackHandler._install_kismet()

                self.assertTrue(ok)
                bash_cmds = [c[2] for c in calls if c[0] == "bash"]
                self.assertEqual(len(bash_cmds), 1)
                expected_repo = (
                    f"deb [arch=arm64 signed-by=/usr/share/keyrings/kismet-archive-keyring.gpg] "
                    f"https://www.kismetwireless.net/repos/apt/release/{codename} {codename} main"
                )
                self.assertIn(expected_repo, bash_cmds[0])
                self.assertIn("/etc/apt/sources.list.d/kismet.list", bash_cmds[0])
                self.assertIn("apt-get install -y --no-install-recommends kismet", bash_cmds[0])
                self.assertIn(["systemctl", "disable", "kismet"], calls)
                self.assertIn(["systemctl", "stop", "kismet"], calls)

    def test_armhf_returns_false_without_writing_repo(self):
        calls = []

        def fake_run(cmd, *args, **kwargs):
            calls.append(cmd)
            r = mock.MagicMock()
            r.returncode = 0
            r.stdout = "armhf\n"
            return r

        with mock.patch("shutil.which", return_value=None):
            with mock.patch("web_server.subprocess.run", side_effect=fake_run):
                ok = RaspyJackHandler._install_kismet()

        self.assertFalse(ok)
        self.assertEqual(calls, [["dpkg", "--print-architecture"]])

    def _capture_install_script(self, codename="bookworm"):
        captured = {}

        def fake_run(cmd, *args, **kwargs):
            if cmd and cmd[0] == "bash":
                captured["script"] = cmd[2]
            result = mock.MagicMock()
            result.returncode = 0
            result.stdout = "arm64\n" if cmd and cmd[0] == "dpkg" else ""
            result.stderr = ""
            return result

        os_release = f'VERSION_CODENAME={codename}\n'
        with mock.patch("shutil.which", return_value=None):
            with mock.patch("builtins.open", mock.mock_open(read_data=os_release)):
                with mock.patch("web_server.subprocess.run", side_effect=fake_run):
                    RaspyJackHandler._install_kismet()
        self.assertIn("script", captured)
        return captured["script"]

    def test_install_command_stages_keyring_and_restores_or_drops_list(self):
        script = self._capture_install_script()
        syntax = subprocess.run(["bash", "-n", "-c", script], capture_output=True, text=True)
        self.assertEqual(syntax.returncode, 0, msg=syntax.stderr)
        self.assertNotIn(
            "gpg --dearmor | tee /usr/share/keyrings/kismet-archive-keyring.gpg",
            script,
        )
        self.assertIn("Could not restore Kismet keyring", script)
        self.assertIn("Could not remove $list (signed-by $keyring missing or unreadable)", script)
        self.assertIn("Could not remove temporary Kismet keyring", script)
        self.assertIn("/etc/apt/sources.list.d/kismet.list", script)
        self.assertIn("apt-get install -y --no-install-recommends kismet", script)

    def test_failed_fetch_does_not_clobber_keyring_or_leave_unreadable_list(self):
        script = self._capture_install_script()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            key_dir = root / "keyrings"
            list_dir = root / "sources.list.d"
            key_dir.mkdir()
            list_dir.mkdir()
            key_path = key_dir / "kismet-archive-keyring.gpg"
            list_path = list_dir / "kismet.list"
            key_path.write_bytes(b"GOOD-KEYRING")
            list_path.write_text(
                "deb [arch=arm64 signed-by=/usr/share/keyrings/kismet-archive-keyring.gpg] old\n",
                encoding="utf-8",
            )
            sandboxed = script.replace("/usr/share/keyrings", str(key_dir)).replace(
                "/etc/apt/sources.list.d", str(list_dir),
            )
            bin_dir = root / "bin"
            bin_dir.mkdir()
            bash_bin = shutil.which("bash")
            self.assertIsNotNone(bash_bin)
            for tool in ("cp", "tee", "mv", "chmod", "mktemp", "rm"):
                host = _host_tool(tool)
                self.assertIsNotNone(host, msg=tool)
                (bin_dir / tool).symlink_to(host)
            _write_exec(
                bin_dir / "wget",
                f"#!{bash_bin}\nexit 4\n",
            )
            _write_exec(
                bin_dir / "gpg",
                f"#!{bash_bin}\ncat >/dev/null\nprintf 'SHOULD-NOT-LAND'\n",
            )
            _write_exec(
                bin_dir / "apt-get",
                f"#!{bash_bin}\nexit 0\n",
            )
            failed = subprocess.run(
                [bash_bin, "-c", sandboxed],
                capture_output=True, text=True,
                env={"PATH": str(bin_dir), "TMPDIR": str(root), "HOME": str(root)},
                timeout=15,
            )
            self.assertNotEqual(failed.returncode, 0, msg=failed.stderr)
            self.assertEqual(key_path.read_bytes(), b"GOOD-KEYRING")
            self.assertTrue(list_path.exists())

            key_path.unlink()
            missing_key = subprocess.run(
                [bash_bin, "-c", sandboxed],
                capture_output=True, text=True,
                env={"PATH": str(bin_dir), "TMPDIR": str(root), "HOME": str(root)},
                timeout=15,
            )
            self.assertNotEqual(missing_key.returncode, 0, msg=missing_key.stderr)
            self.assertFalse(list_path.exists())
            self.assertFalse(key_path.exists())

    def test_keyring_replace_failure_restores_previous_key(self):
        script = self._capture_install_script()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            key_dir = root / "keyrings"
            list_dir = root / "sources.list.d"
            key_dir.mkdir()
            list_dir.mkdir()
            key_path = key_dir / "kismet-archive-keyring.gpg"
            list_path = list_dir / "kismet.list"
            key_path.write_bytes(b"OLD-KEYRING")
            list_path.write_text("deb [signed-by=/usr/share/keyrings/kismet-archive-keyring.gpg] old\n", encoding="utf-8")
            sandboxed = script.replace("/usr/share/keyrings", str(key_dir)).replace(
                "/etc/apt/sources.list.d", str(list_dir),
            )
            bin_dir = root / "bin"
            bin_dir.mkdir()
            bash_bin = shutil.which("bash")
            count_file = root / "mv.count"
            for tool in ("cp", "tee", "chmod", "mktemp", "rm"):
                host = _host_tool(tool)
                self.assertIsNotNone(host, msg=tool)
                (bin_dir / tool).symlink_to(host)
            real_mv = _host_tool("mv")
            self.assertIsNotNone(real_mv)
            _write_exec(
                bin_dir / "mv",
                f"#!{bash_bin}\n"
                f'dest="${{@: -1}}"\n'
                f'if [ "$dest" = "{key_path}" ] && [ ! -f "{count_file}" ]; then\n'
                f'  echo 1 > "{count_file}"\n'
                f'  echo "mv: cannot replace $dest" >&2\n'
                f"  exit 1\n"
                f"fi\n"
                f'exec "{real_mv}" "$@"\n',
            )
            _write_exec(bin_dir / "wget", f"#!{bash_bin}\nprintf 'FAKEKEY'\n")
            _write_exec(
                bin_dir / "gpg",
                f"#!{bash_bin}\ncat >/dev/null\nprintf 'NEW-KEYRING'\n",
            )
            _write_exec(bin_dir / "apt-get", f"#!{bash_bin}\nexit 0\n")
            res = subprocess.run(
                [bash_bin, "-c", sandboxed],
                capture_output=True, text=True,
                env={"PATH": str(bin_dir), "TMPDIR": str(root), "HOME": str(root)},
                timeout=15,
            )
            self.assertNotEqual(res.returncode, 0, msg=res.stdout + res.stderr)
            self.assertEqual(key_path.read_bytes(), b"OLD-KEYRING")
            self.assertTrue(list_path.exists())
            self.assertNotIn("NEW-KEYRING", list_path.read_text(encoding="utf-8"))

    def test_backup_cleanup_failure_reports_path(self):
        script = self._capture_install_script()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            key_dir = root / "keyrings"
            list_dir = root / "sources.list.d"
            key_dir.mkdir()
            list_dir.mkdir()
            sandboxed = script.replace("/usr/share/keyrings", str(key_dir)).replace(
                "/etc/apt/sources.list.d", str(list_dir),
            )
            bin_dir = root / "bin"
            bin_dir.mkdir()
            bash_bin = shutil.which("bash")
            for tool in ("cp", "tee", "mv", "chmod", "mktemp"):
                host = _host_tool(tool)
                self.assertIsNotNone(host, msg=tool)
                (bin_dir / tool).symlink_to(host)
            real_rm = _host_tool("rm")
            self.assertIsNotNone(real_rm)
            _write_exec(
                bin_dir / "rm",
                f"#!{bash_bin}\n"
                f'for arg in "$@"; do\n'
                f'  case "$arg" in\n'
                f"    *kismet-archive-keyring.bak.*)\n"
                f'      echo "rm: cannot remove $arg" >&2\n'
                f"      exit 1\n"
                f"      ;;\n"
                f"  esac\n"
                f"done\n"
                f'exec "{real_rm}" "$@"\n',
            )
            _write_exec(bin_dir / "wget", f"#!{bash_bin}\nexit 4\n")
            _write_exec(bin_dir / "gpg", f"#!{bash_bin}\ncat >/dev/null\nexit 1\n")
            _write_exec(bin_dir / "apt-get", f"#!{bash_bin}\nexit 0\n")
            res = subprocess.run(
                [bash_bin, "-c", sandboxed],
                capture_output=True, text=True,
                env={"PATH": str(bin_dir), "TMPDIR": str(root), "HOME": str(root)},
                timeout=15,
            )
            self.assertNotEqual(res.returncode, 0, msg=res.stderr)
            self.assertRegex(
                res.stderr,
                r"Could not remove Kismet keyring backup \S*kismet-archive-keyring\.bak\.",
            )


if __name__ == "__main__":
    unittest.main()
