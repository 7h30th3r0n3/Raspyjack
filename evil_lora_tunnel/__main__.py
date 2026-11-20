"""Foreground recorder worker for the RaspyJack hardware payload."""

import argparse
import os
from pathlib import Path
import sys
import time

from . import config, RadioError, session


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="newly created session directory")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        return session.capture(args.directory, config.load())
    except (OSError, ValueError, RadioError) as exc:
        message = str(exc) if isinstance(exc, (RadioError, config.ConfigError)) else type(exc).__name__
        print(message, file=sys.stderr)
        try:
            metadata = session.status(args.directory)
            if metadata["status"] == "created":
                metadata.update(status="interrupted", ended_at=time.time(), errors=[message])
                session.atomic_json(args.directory / "session.json", metadata)
        except (OSError, KeyError, ValueError):
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
