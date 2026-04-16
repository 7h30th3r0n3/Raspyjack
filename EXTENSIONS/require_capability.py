#!/usr/bin/env python3
"""CLI wrapper for REQUIRE_CAPABILITY. Author: m0usem0use"""
from __future__ import annotations

import argparse
import sys

from api import REQUIRE_CAPABILITY

def main() -> int:
    parser = argparse.ArgumentParser(description="Check whether a required capability is available.")
    parser.add_argument("capability_type", choices=["binary", "service", "interface", "config"])
    parser.add_argument("value")
    parser.add_argument("--failure-policy", choices=["fail_closed", "warn_only"], default="fail_closed")
    args = parser.parse_args()
    try:
        ok = REQUIRE_CAPABILITY(
            args.capability_type,
            args.value,
            failure_policy=args.failure_policy,
        )
        print(f"{args.capability_type}:{args.value}={'ok' if ok else 'missing'}")
        return 0 if ok else 1
    except (RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
