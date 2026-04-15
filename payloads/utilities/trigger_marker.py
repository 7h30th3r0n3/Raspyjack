#!/usr/bin/env python3
"""
Simple marker payload for BLE trigger validation.
Author: m0usem0use

This payload gives a low-friction verification target during first trigger
bring-up: it appends a timestamped line to artifacts/triggers/trigger_marker.log.
"""

from __future__ import annotations

from pathlib import Path
import sys
import time


REPO_ROOT = Path(__file__).resolve().parents[2]
LOG_DIR = REPO_ROOT / "artifacts" / "triggers"
LOG_FILE = LOG_DIR / "trigger_marker.log"


def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    label = args[0] if args else "trigger_marker"
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as fh:
        fh.write(f"[{ts}] {label}\n")
    print(f"trigger marker written: {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
