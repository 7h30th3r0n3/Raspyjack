#!/usr/bin/env python3
"""
RaspyJack – WebSocket device server
-----------------------------------
Streams the latest LCD frame to web clients and receives virtual button
inputs to forward to the local input bridge.

Environment variables:
  RJ_FRAME_PATH      Path to mirrored frame (JPEG). Default: /dev/shm/raspyjack_last.jpg
  RJ_WS_HOST         Host to bind. Default: 0.0.0.0
  RJ_WS_PORT         Port to bind. Default: 8765
  RJ_FPS             Max broadcast rate (frames per second). Default: 10
  RJ_WS_TOKEN        Optional shared token; if set, clients must pass ?token=...
  RJ_INPUT_SOCK      Unix datagram socket path for input bridge. Default: /dev/shm/rj_input.sock
"""

import asyncio
import base64
import json
import logging
import os
import socket
import time
from pathlib import Path
from typing import Set
from urllib.parse import urlparse, parse_qs

import websockets
from websockets.server import WebSocketServerProtocol


# ------------------------------ Config ---------------------------------------
FRAME_PATH = Path(os.environ.get("RJ_FRAME_PATH", "/dev/shm/raspyjack_last.jpg"))
HOST = os.environ.get("RJ_WS_HOST", "0.0.0.0")
PORT = int(os.environ.get("RJ_WS_PORT", "8765"))
FPS = float(os.environ.get("RJ_FPS", "10"))
TOKEN = os.environ.get("RJ_WS_TOKEN")
INPUT_SOCK = os.environ.get("RJ_INPUT_SOCK", "/dev/shm/rj_input.sock")

SEND_TIMEOUT = 0.5  # seconds per frame send per client
PING_INTERVAL = 15   # websockets ping interval


logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
)
log = logging.getLogger("rj-ws")


# --------------------------- Client Registry ---------------------------------
clients: Set[WebSocketServerProtocol] = set()
clients_lock = asyncio.Lock()


# -------------------------- Frame Broadcasting --------------------------------
class FrameCache:
    def __init__(self, path: Path):
        self.path = path
        self._last_mtime = 0.0
        self._last_size = 0
        self._last_payload: str | None = None

    def has_changed(self) -> bool:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return False
        if st.st_mtime != self._last_mtime or st.st_size != self._last_size:
            return True
        return False

    def load_b64(self) -> str | None:
        try:
            st = self.path.stat()
            with self.path.open("rb") as f:
                raw = f.read()
            b64 = base64.b64encode(raw).decode("ascii")
            self._last_mtime = st.st_mtime
            self._last_size = st.st_size
            self._last_payload = b64
            return b64
        except FileNotFoundError:
            return None
        except Exception as exc:
            log.warning("Failed to read frame: %s", exc)
            return None

    @property
    def last_payload(self) -> str | None:
        return self._last_payload


async def broadcast_frames(cache: FrameCache) -> None:
    """Periodically broadcast new frames to all connected clients."""
    delay = max(0.001, 1.0 / max(1.0, FPS))
    log.info("Frame broadcaster started at ~%.1f FPS", 1.0 / delay)
    while True:
        try:
            payload = None
            if cache.has_changed():
                payload = cache.load_b64()
            else:
                payload = cache.last_payload

            if payload is not None:
                msg = json.dumps({"type": "frame", "data": payload})
                async with clients_lock:
                    if clients:
                        # Send concurrently with timeout per client
                        await asyncio.gather(*[
                            asyncio.wait_for(c.send(msg), timeout=SEND_TIMEOUT)
                            for c in list(clients)
                        ], return_exceptions=True)
            await asyncio.sleep(delay)
        except Exception as exc:
            log.warning("Broadcaster loop error: %s", exc)
            await asyncio.sleep(delay)


# ----------------------------- Input Bridge -----------------------------------
def send_input_event(button: str, state: str) -> None:
    """Send a JSON input event to the Unix datagram socket if present."""
    if not INPUT_SOCK:
        return
    try:
        # Best-effort send; if receiver not bound, this will raise
        data = json.dumps({"type": "input", "button": button, "state": state}).encode("utf-8")
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.settimeout(0.05)
            s.connect(INPUT_SOCK)
            s.send(data)
    except Exception:
        # Silently ignore when the bridge isn't up yet
        pass


# ----------------------------- WS Handlers ------------------------------------
def authorize(path: str) -> bool:
    if not TOKEN:
        return True
    try:
        q = parse_qs(urlparse(path).query)
        tok = q.get("token", [None])[0]
        return tok == TOKEN
    except Exception:
        return False


async def handle_client(ws: WebSocketServerProtocol, path: str) -> None:
    if not authorize(path):
        await ws.close(code=4401, reason="Unauthorized")
        return

    async with clients_lock:
        clients.add(ws)
    log.info("Client connected (%d online)", len(clients))

    try:
        async for raw in ws:
            try:
                data = json.loads(raw)
            except Exception:
                continue
            if data.get("type") == "input":
                button = str(data.get("button", ""))
                state = str(data.get("state", ""))
                if button and state in ("press", "release"):
                    send_input_event(button, state)
    except websockets.ConnectionClosed:
        pass
    finally:
        async with clients_lock:
            clients.discard(ws)
        log.info("Client disconnected (%d online)", len(clients))


async def main() -> None:
    cache = FrameCache(FRAME_PATH)
    server = await websockets.serve(
        handle_client,
        HOST,
        PORT,
        ping_interval=PING_INTERVAL,
        max_size=2 * 1024 * 1024,
    )
    log.info("WebSocket server listening on %s:%d", HOST, PORT)

    try:
        await broadcast_frames(cache)
    finally:
        server.close()
        await server.wait_closed()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
