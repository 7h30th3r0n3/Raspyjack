#!/usr/bin/env python3
"""Shared gate helpers for RaspyJack extensions. Author: m0usem0use"""
from __future__ import annotations

try:
    from ._bluez import wait_for_match
except ImportError:
    from _bluez import wait_for_match


def _handle_wait_result(result: int, *, fail_closed: bool, condition: str) -> bool:
    if result == 0:
        return True
    if not fail_closed:
        return False
    if result == 1:
        raise TimeoutError(f"{condition} timed out")
    raise RuntimeError(f"{condition} failed because Bluetooth is unavailable")


def WAIT_FOR_PRESENT(
    *,
    name: str = "",
    mac: str = "",
    service_uuid: str = "",
    timeout_seconds: int = 0,
    scan_window_seconds: int = 4,
    poll_interval_seconds: int = 2,
    fail_closed: bool = True,
) -> bool:
    result = wait_for_match(
        expect_present=True,
        name=name,
        mac=mac,
        service_uuid=service_uuid,
        timeout_seconds=timeout_seconds,
        scan_window_seconds=scan_window_seconds,
        poll_interval_seconds=poll_interval_seconds,
    )
    return _handle_wait_result(result, fail_closed=fail_closed, condition="WAIT_FOR_PRESENT")


def WAIT_FOR_NOTPRESENT(
    *,
    name: str = "",
    mac: str = "",
    service_uuid: str = "",
    timeout_seconds: int = 0,
    scan_window_seconds: int = 4,
    poll_interval_seconds: int = 2,
    fail_closed: bool = True,
) -> bool:
    result = wait_for_match(
        expect_present=False,
        name=name,
        mac=mac,
        service_uuid=service_uuid,
        timeout_seconds=timeout_seconds,
        scan_window_seconds=scan_window_seconds,
        poll_interval_seconds=poll_interval_seconds,
    )
    return _handle_wait_result(result, fail_closed=fail_closed, condition="WAIT_FOR_NOTPRESENT")
