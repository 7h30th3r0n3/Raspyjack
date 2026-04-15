#!/usr/bin/env python3
"""
Simple BLE extension tester for RaspyJack.
Author: m0usem0use

Waits for a BLE advertiser named TestRJ, then launches the marker payload so
validation is visible in artifacts/triggers/trigger_marker.log.
"""

from __future__ import annotations

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from EXTENSIONS.api import REQUIRE_CAPABILITY, RUN_PAYLOAD, WAIT_FOR_PRESENT


DEFAULT_NAME = "TestRJ"
DEFAULT_TIMEOUT = 60
DEFAULT_LABEL = "test_ble_wait_for_present"


def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    target_name = args[0] if args else DEFAULT_NAME
    timeout_seconds = int(args[1]) if len(args) > 1 else DEFAULT_TIMEOUT
    label = args[2] if len(args) > 2 else f"{DEFAULT_LABEL}:{target_name}"

    try:
        REQUIRE_CAPABILITY("binary", "bluetoothctl")
        print(f"waiting for BLE advertiser: {target_name} (timeout={timeout_seconds}s)")
        WAIT_FOR_PRESENT(name=target_name, timeout_seconds=timeout_seconds)
        print(f"matched BLE advertiser: {target_name}")
        return RUN_PAYLOAD("utilities/trigger_marker.py", label)
    except TimeoutError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
