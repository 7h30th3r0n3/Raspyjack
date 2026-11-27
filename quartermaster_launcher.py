"""Run the installed, interactive Quartermaster app as its normal login user."""

import os
from pathlib import Path
import pwd
import subprocess


CARDPUTER = "/usr/share/APPLaunch/bin/quartermaster"
DIY = "/usr/bin/quartermaster"
HATS = {"ST7735_128": "st7735-128", "ST7789_240": "st7789-240"}


class LaunchError(Exception):
    """A short message for the on-device dialog."""


def login_user():
    name = os.environ.get("RJ_QUARTERMASTER_USER") or os.environ.get("SUDO_USER")
    users = [user for user in pwd.getpwall() if 1000 <= user.pw_uid < 60000
             and Path(user.pw_shell).name not in ("nologin", "false")]
    if name:
        users = [user for user in users if user.pw_name == name]
    if len(users) != 1:
        raise LaunchError("Set the login user\nin the service.\nSee Quartermaster docs.")
    return users[0]


def already_running(proc=Path("/proc")):
    # Both official launchers exec python3 -m quartermaster. This also catches a manual launch.
    for path in proc.glob("[0-9]*/cmdline"):
        try:
            args = path.read_bytes().split(b"\0")
        except OSError:
            continue
        if any(pair == (b"-m", b"quartermaster") for pair in zip(args, args[1:])) and b"--probe" not in args:
            return True
    return False


def prepare(display, framebuffer):
    if display == "CARDPUTER_320":
        command = [CARDPUTER]
        hint = "Install Quartermaster\nApp Store code: WARD"
    elif display in HATS:
        command = [DIY, "--display", HATS[display]]
        hint = "Install quartermaster-pi.\nSee Quartermaster docs."
    else:
        raise LaunchError("Unsupported display")
    if not os.access(command[0], os.X_OK):
        raise LaunchError(hint)
    if already_running():
        raise LaunchError("Quartermaster is\nalready running.")
    user = login_user()
    env = {"HOME": user.pw_dir, "USER": user.pw_name, "LOGNAME": user.pw_name,
           "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    if display == "CARDPUTER_320":
        env["APPLAUNCH_LINUX_FBDEV_DEVICE"] = framebuffer
    runtime = Path("/run/user") / str(user.pw_uid)
    if runtime.is_dir() and runtime.stat().st_uid == user.pw_uid:
        env["XDG_RUNTIME_DIR"] = str(runtime)
        if (runtime / "bus").is_socket():
            env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + str(runtime / "bus")
    return command, {"user": user.pw_uid, "group": user.pw_gid,
                     "extra_groups": os.getgrouplist(user.pw_name, user.pw_gid),
                     "env": env, "cwd": user.pw_dir, "stdin": subprocess.DEVNULL}
