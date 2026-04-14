#!/usr/bin/env python3
"""Raspyjack-specific Ragnar launcher."""

import os
import signal
import sqlite3
import sys
import threading
import time


def _get_port(default: int = 8091) -> int:
    raw = os.environ.get("RAGNAR_PORT", "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        print(f"[RAGNAR] Invalid RAGNAR_PORT={raw!r}, falling back to {default}", file=sys.stderr)
        return default
    if value < 1 or value > 65535:
        print(f"[RAGNAR] Out-of-range RAGNAR_PORT={raw!r}, falling back to {default}", file=sys.stderr)
        return default
    return value


def _ensure_auth_db() -> None:
    """Precreate Ragnar auth DB schema before importing the web stack.

    Ragnar's web app instantiates AuthManager at import time. If the auth DB
    file exists but is empty or partially created, the import path can spam
    `no such table: auth`. We normalize the DB up front.

    Uses BEGIN IMMEDIATE to prevent race conditions when multiple Ragnar
    processes start simultaneously.
    """
    datadir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    os.makedirs(datadir, exist_ok=True)
    auth_db_path = os.path.join(datadir, "ragnar_auth.db")
    conn = sqlite3.connect(auth_db_path, timeout=10)
    try:
        conn.execute("BEGIN IMMEDIATE")
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS auth (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                hardware_fingerprint TEXT NOT NULL,
                encrypted_fernet_key TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS recovery_codes (
                id INTEGER PRIMARY KEY,
                code_hash TEXT NOT NULL,
                code_salt TEXT NOT NULL,
                encrypted_fernet_key TEXT NOT NULL,
                used INTEGER DEFAULT 0,
                used_at TEXT DEFAULT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS app_secrets (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def _main() -> int:
    # Prevent Ragnar from initializing the e-paper display (EPD) hardware.
    # RaspyJack uses the same SPI bus for its LCD; EPD init clobbers it and
    # causes a white screen.
    os.environ.setdefault("RAGNAR_PAGER_MODE", "1")

    from env_manager import load_env

    load_env()
    web_port = _get_port()
    _ensure_auth_db()

    try:
        from headlessRagnar import Ragnar, handle_exit
        from init_shared import shared_data
        from logger import Logger
        from webapp_modern import run_server
    except ModuleNotFoundError as exc:
        missing = getattr(exc, "name", None) or str(exc)
        print(f"[RAGNAR] Missing Python dependency: {missing}", file=sys.stderr)
        print("[RAGNAR] Run ./scripts/install_ragnar_port.sh", file=sys.stderr)
        return 3

    logger = Logger(name="raspyjack_headless.py")
    logger.info(f"Starting Ragnar via Raspyjack launcher on port {web_port}")

    try:
        shared_data.load_config()

        ragnar = Ragnar(shared_data)
        shared_data.ragnar_instance = ragnar

        ragnar_thread = threading.Thread(
            target=ragnar.run,
            name="RagnarMain",
            daemon=True,
        )
        ragnar_thread.start()

        web_thread = threading.Thread(
            target=run_server,
            kwargs={"port": web_port},
            name="RagnarWeb",
            daemon=True,
        )
        web_thread.start()

        signal.signal(
            signal.SIGINT,
            lambda sig, frame: handle_exit(sig, frame, ragnar_thread, web_thread),
        )
        signal.signal(
            signal.SIGTERM,
            lambda sig, frame: handle_exit(sig, frame, ragnar_thread, web_thread),
        )

        # Monitor thread health instead of bare sleep loop
        while True:
            if not ragnar_thread.is_alive():
                logger.error("Ragnar main thread died unexpectedly, exiting")
                break
            if not web_thread.is_alive():
                logger.error("Ragnar web thread died unexpectedly, exiting")
                break
            time.sleep(2)

    except Exception as exc:
        logger.error(f"Raspyjack Ragnar launcher failed: {exc}")
        if "ragnar" in locals():
            try:
                ragnar.stop()
            except Exception:
                pass
        return 1


if __name__ == "__main__":
    sys.exit(_main())
