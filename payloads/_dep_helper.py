"""
Dependency helper — auto-install missing system packages and Python modules.

Usage:
    from payloads._dep_helper import ensure_apt, ensure_pip, ensure_all

    ensure_apt("direwolf")
    ensure_pip("sgp4")
    ensure_all(apt=["direwolf", "multimon-ng"], pip=["sgp4"])
"""

import shutil
import subprocess


def _is_installed_apt(pkg):
    r = subprocess.run(
        ["dpkg", "-s", pkg], capture_output=True, timeout=5,
    )
    return r.returncode == 0


def _install_apt(pkg):
    subprocess.run(
        ["apt-get", "install", "-y", pkg],
        capture_output=True, timeout=120,
    )


def _install_pip(mod):
    subprocess.run(
        ["pip3", "install", "--break-system-packages", mod],
        capture_output=True, timeout=120,
    )


def _can_import(mod):
    try:
        __import__(mod)
        return True
    except ImportError:
        return False


def ensure_bin(name, apt_pkg=None):
    if shutil.which(name):
        return True
    pkg = apt_pkg or name
    _install_apt(pkg)
    return shutil.which(name) is not None


def ensure_apt(pkg):
    if _is_installed_apt(pkg):
        return True
    _install_apt(pkg)
    return _is_installed_apt(pkg)


def ensure_pip(mod, pip_name=None):
    if _can_import(mod):
        return True
    _install_pip(pip_name or mod)
    return _can_import(mod)


def ensure_all(apt=None, pip=None, bins=None):
    ok = True
    for pkg in (apt or []):
        if not ensure_apt(pkg):
            ok = False
    for mod in (pip or []):
        if isinstance(mod, tuple):
            if not ensure_pip(mod[0], mod[1]):
                ok = False
        elif not ensure_pip(mod):
            ok = False
    for b in (bins or []):
        if isinstance(b, tuple):
            if not ensure_bin(b[0], b[1]):
                ok = False
        elif not ensure_bin(b):
            ok = False
    return ok
