#!/usr/bin/env python3
"""Shared action helpers for RaspyJack extensions. Author: m0usem0use"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[1]
PAYLOAD_ROOT = REPO_ROOT / "payloads"


def REQUIRE_CAPABILITY(
    capability_type: str,
    value: str,
    *,
    failure_policy: str = "fail_closed",
) -> bool:
    capability_type = str(capability_type).strip().lower()
    value = str(value).strip()
    if capability_type not in {"binary", "service", "interface", "config"}:
        raise ValueError(f"unsupported capability_type: {capability_type}")
    if not value:
        raise ValueError("value is required")

    if capability_type == "binary":
        ok = shutil.which(value) is not None
    elif capability_type == "service":
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "--quiet", value],
                capture_output=True,
                timeout=5,
            )
            ok = result.returncode == 0
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            ok = False
    elif capability_type == "interface":
        try:
            result = subprocess.run(
                ["ip", "link", "show", value],
                capture_output=True,
                timeout=5,
            )
            ok = result.returncode == 0
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            ok = False
    else:
        raw = Path(value)
        target = raw if raw.is_absolute() else (REPO_ROOT / raw)
        ok = target.exists()

    if ok:
        return True
    if str(failure_policy).strip().lower() == "warn_only":
        return False
    raise RuntimeError(f"missing required capability: {capability_type}={value}")


def RUN_PAYLOAD(payload: str, *payload_args: str) -> int:
    payload_path = (PAYLOAD_ROOT / payload).resolve()
    try:
        payload_root = PAYLOAD_ROOT.resolve()
    except FileNotFoundError:
        payload_root = PAYLOAD_ROOT
    if payload_root not in payload_path.parents:
        raise ValueError("payload path escapes payload root")
    if not payload_path.is_file():
        raise FileNotFoundError(f"payload not found: {payload_path}")

    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    cmd = ["python3", str(payload_path), *payload_args]
    return subprocess.run(cmd, cwd=str(REPO_ROOT), env=env).returncode
