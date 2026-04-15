#!/usr/bin/env python3
"""CLI wrapper for RUN_PAYLOAD. Author: m0usem0use"""
from __future__ import annotations

import argparse
import sys

from api import RUN_PAYLOAD


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a RaspyJack payload by relative path.")
    parser.add_argument("payload")
    parser.add_argument("payload_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        return RUN_PAYLOAD(args.payload, *args.payload_args)
    except (ValueError, FileNotFoundError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
