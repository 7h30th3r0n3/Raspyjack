#!/usr/bin/env python3
"""CLI wrapper for WAIT_FOR_NOTPRESENT. Author: m0usem0use"""
from __future__ import annotations

import argparse
import sys

from _bluez import add_common_wait_args
from api import WAIT_FOR_NOTPRESENT


def main() -> int:
    parser = argparse.ArgumentParser(description="Wait until a BLE target is no longer present.")
    add_common_wait_args(parser)
    args = parser.parse_args()
    try:
        WAIT_FOR_NOTPRESENT(
            name=args.name,
            mac=args.mac,
            service_uuid=args.service_uuid,
            timeout_seconds=args.timeout_seconds,
            scan_window_seconds=args.scan_window_seconds,
            poll_interval_seconds=args.poll_interval_seconds,
        )
        return 0
    except TimeoutError:
        return 1
    except (RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
