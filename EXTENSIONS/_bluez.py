#!/usr/bin/env python3
"""
Shared BlueZ-backed helpers for RaspyJack extensions.
Author: m0usem0use
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import time


DEVICE_RE = re.compile(r"Device ([0-9A-F:]{17})(?:\s+(.*))?$")
UUID_LINE_RE = re.compile(
    r"UUID:\s+.*?\(([0-9A-Fa-f-]{36}|[0-9A-Fa-f]{4,8})\)\s*$|UUID:\s+([0-9A-Fa-f-]{36}|[0-9A-Fa-f]{4,8})\s*$"
)
UUID_TOKEN_RE = re.compile(r"([0-9A-Fa-f-]{36}|[0-9A-Fa-f]{4,8})")
BLUETOOTH_BASE_SUFFIX = "-0000-1000-8000-00805f9b34fb"
SCAN_PROPERTY_PREFIXES = (
    "RSSI:",
    "TxPower:",
    "ManufacturerData",
    "ServiceData",
    "UUID:",
    "UUIDs:",
    "Alias:",
    "Paired:",
    "Trusted:",
    "Blocked:",
    "Connected:",
    "LegacyPairing:",
)


def normalize_service_uuid(value: str | None) -> str | None:
    if not value:
        return None
    match = UUID_TOKEN_RE.search(str(value).strip())
    if not match:
        return None
    token = match.group(1).lower()
    compact = token.replace("-", "")
    if len(compact) == 4:
        return f"0000{compact}{BLUETOOTH_BASE_SUFFIX}"
    if len(compact) == 8:
        return f"{compact}{BLUETOOTH_BASE_SUFFIX}"
    if len(compact) == 32:
        return (
            f"{compact[0:8]}-{compact[8:12]}-{compact[12:16]}-"
            f"{compact[16:20]}-{compact[20:32]}"
        )
    return None


def _clean_scan_name(value: str | None) -> str:
    name = (value or "").strip()
    if not name:
        return ""
    if any(name.startswith(prefix) for prefix in SCAN_PROPERTY_PREFIXES):
        return ""
    return name


def _run_command(cmd: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
        return None


def ensure_bluetooth_ready() -> dict[str, str | bool]:
    if shutil.which("rfkill"):
        _run_command(["rfkill", "unblock", "bluetooth"], timeout_seconds=4)
        _run_command(["rfkill", "unblock", "all"], timeout_seconds=4)
    if shutil.which("hciconfig"):
        _run_command(["hciconfig", "hci0", "up"], timeout_seconds=5)
    if shutil.which("bluetoothctl"):
        _run_command(["bluetoothctl", "power", "on"], timeout_seconds=5)

    show = _run_command(["bluetoothctl", "show"], timeout_seconds=6)
    output = (show.stdout if show else "") or ""
    powered = "unknown"
    power_state = "unknown"
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Powered:"):
            powered = stripped.split(":", 1)[1].strip().lower()
        elif stripped.startswith("PowerState:"):
            power_state = stripped.split(":", 1)[1].strip().lower()
    return {
        "ready": powered == "yes",
        "powered": powered,
        "power_state": power_state,
    }


def parse_bluetoothctl_info(text: str, mac: str, name: str = "") -> dict[str, object]:
    service_uuids: list[str] = []
    current_name = name
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("Name:"):
            current_name = line.split(":", 1)[1].strip() or current_name
            continue
        uuid_match = UUID_LINE_RE.search(line)
        if not uuid_match:
            continue
        normalized = normalize_service_uuid(uuid_match.group(1) or uuid_match.group(2))
        if normalized and normalized not in service_uuids:
            service_uuids.append(normalized)
    return {
        "mac": mac.upper(),
        "name": current_name,
        "service_uuids": service_uuids,
    }


def read_bluetoothctl_info(mac: str, timeout_seconds: int = 8) -> dict[str, object]:
    proc = _run_command(["bluetoothctl", "info", mac], timeout_seconds=timeout_seconds)
    if not proc:
        return {"mac": mac.upper(), "name": "", "service_uuids": []}
    return parse_bluetoothctl_info(proc.stdout or "", mac=mac)


def scan_ble(window_seconds: int, include_service_uuids: bool = False) -> list[dict[str, object]]:
    proc = _run_command(
        ["bluetoothctl", "--timeout", str(window_seconds), "scan", "on"],
        timeout_seconds=window_seconds + 5,
    )
    scan_text = ""
    if proc:
        scan_text = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")

    seen: dict[str, dict[str, object]] = {}
    for line in scan_text.splitlines():
        match = DEVICE_RE.search(line)
        if not match:
            continue
        mac = match.group(1).upper()
        name = _clean_scan_name(match.group(2) or "")
        if mac not in seen:
            seen[mac] = {"mac": mac, "name": name, "service_uuids": []}
        elif name and not seen[mac]["name"]:
            seen[mac]["name"] = name

    if include_service_uuids:
        info_timeout = max(4, window_seconds + 2)
        for mac, dev in seen.items():
            details = read_bluetoothctl_info(mac, timeout_seconds=info_timeout)
            if details.get("name") and not dev.get("name"):
                dev["name"] = details["name"]
            dev["service_uuids"] = list(details.get("service_uuids") or [])
    return list(seen.values())


def device_matches(
    device: dict[str, object],
    *,
    name: str = "",
    mac: str = "",
    service_uuid: str = "",
) -> bool:
    if mac and str(device.get("mac", "")).upper() != str(mac).upper():
        return False
    if name and str(device.get("name", "")) != name:
        return False
    if service_uuid:
        normalized = normalize_service_uuid(service_uuid)
        values = {normalize_service_uuid(item) for item in (device.get("service_uuids") or [])}
        if normalized not in values:
            return False
    return True


def devices_match(
    devices: list[dict[str, object]],
    *,
    name: str = "",
    mac: str = "",
    service_uuid: str = "",
) -> bool:
    return any(
        device_matches(device, name=name, mac=mac, service_uuid=service_uuid)
        for device in devices
    )


def wait_for_match(
    *,
    expect_present: bool,
    name: str = "",
    mac: str = "",
    service_uuid: str = "",
    timeout_seconds: int = 0,
    scan_window_seconds: int = 4,
    poll_interval_seconds: int = 2,
) -> int:
    normalized_name = str(name or "").strip()
    normalized_mac = str(mac or "").strip().upper()
    normalized_uuid = normalize_service_uuid(service_uuid)
    if not (normalized_name or normalized_mac or normalized_uuid):
        raise ValueError("at least one of --name, --mac, or --service-uuid is required")

    bt_state = ensure_bluetooth_ready()
    if not bt_state.get("ready"):
        print(
            f"Bluetooth unavailable: powered={bt_state.get('powered')} "
            f"power_state={bt_state.get('power_state')}",
            file=sys.stderr,
        )
        return 2

    deadline = time.monotonic() + timeout_seconds if timeout_seconds > 0 else None
    while True:
        devices = scan_ble(
            max(1, scan_window_seconds),
            include_service_uuids=bool(normalized_uuid),
        )
        matched = devices_match(
            devices,
            name=normalized_name,
            mac=normalized_mac,
            service_uuid=normalized_uuid or "",
        )
        if expect_present and matched:
            return 0
        if not expect_present and not matched:
            return 0
        if deadline is not None and time.monotonic() >= deadline:
            return 1
        time.sleep(max(1, poll_interval_seconds))


def add_common_wait_args(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("--name", default="")
    parser.add_argument("--mac", default="")
    parser.add_argument("--service-uuid", default="")
    parser.add_argument("--timeout-seconds", type=int, default=0)
    parser.add_argument("--scan-window-seconds", type=int, default=4)
    parser.add_argument("--poll-interval-seconds", type=int, default=2)
    return parser
