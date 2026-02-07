#!/usr/bin/env python3
"""
RaspyJack – WebSocket device server
Compatible websockets v11+ / v12+
"""

import asyncio
import base64
import json
import logging
import os
import socket
from pathlib import Path
from typing import Set
from urllib.parse import urlparse, parse_qs

import websockets


# ------------------------------ Config ---------------------------------------
FRAME_PATH = Path(os.environ.get("RJ_FRAME_PATH", "/dev/shm/raspyjack_last.jpg"))
HOST = os.environ.get("RJ_WS_HOST", "0.0.0.0")
PORT = int(os.environ.get("RJ_WS_PORT", "8765"))
FPS = float(os.environ.get("RJ_FPS", "10"))
TOKEN = os.environ.get("RJ_WS_TOKEN")
INPUT_SOCK = os.environ.get("RJ_INPUT_SOCK", "/dev/shm/rj_input.sock")

SEND_TIMEOUT = 0.5
PING_INTERVAL = 15


logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
)
log = logging.getLogger("rj-ws")


# --------------------------- Client Registry ---------------------------------
clients: Set = set()
clients_lock = asyncio.Lock()


# -------------------------- Frame Broadcasting --------------------------------
class FrameCache:
    def __init__(self, path: Path):
        self.path = path
        self._last_mtime = 0.0
        self._last_size = 0
        self._last_payload = None

    def has_changed(self) -> bool:
        try:
            st = self.path.stat()
            return st.st_mtime != self._last_mtime or st.st_size != self._last_size
        except FileNotFoundError:
            return False

    def load_b64(self):
        try:
            st = self.path.stat()
            with self.path.open("rb") as f:
                raw = f.read()
            b64 = base64.b64encode(raw).decode()
            self._last_mtime = st.st_mtime
            self._last_size = st.st_size
            self._last_payload = b64
            return b64
        except Exception:
            return None

    @property
    def last_payload(self):
        return self._last_payload


async def broadcast_frames(cache: FrameCache):
    delay = max(0.001, 1.0 / max(1.0, FPS))
    log.info("Frame broadcaster started at ~%.1f FPS", 1.0 / delay)

    while True:
        try:
            payload = cache.load_b64() if cache.has_changed() else cache.last_payload
            if payload:
                msg = json.dumps({"type": "frame", "data": payload})
                async with clients_lock:
                    await asyncio.gather(
                        *[asyncio.wait_for(c.send(msg), SEND_TIMEOUT) for c in list(clients)],
                        return_exceptions=True,
                    )
            await asyncio.sleep(delay)
        except Exception as e:
            log.warning("Broadcaster error: %s", e)


# ----------------------------- Input Bridge -----------------------------------
def send_input_event(button, state):
    try:
        payload = json.dumps({
            "type": "input",
            "button": button,
            "state": state
        }).encode()

        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(INPUT_SOCK)
            s.send(payload)
    except Exception:
        pass


# ----------------------------- Auth -------------------------------------------
def authorize(path: str) -> bool:
    if not TOKEN:
        return True
    try:
        q = parse_qs(urlparse(path).query)
        return q.get("token", [None])[0] == TOKEN
    except Exception:
        return False


# ----------------------------- WS Handler -------------------------------------
async def handle_client(ws):
    # websockets v12+ : path is in ws.request.path
    path = getattr(getattr(ws, "request", None), "path", "/")

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
                btn = data.get("button")
                state = data.get("state")
                if btn and state in ("press", "release"):
                    send_input_event(btn, state)

    except Exception:
        pass
    finally:
        async with clients_lock:
            clients.discard(ws)
        log.info("Client disconnected (%d online)", len(clients))


# ----------------------------- Main -------------------------------------------
async def main():
    cache = FrameCache(FRAME_PATH)

    async with websockets.serve(
        handle_client,
        HOST,
        PORT,
        ping_interval=PING_INTERVAL,
        max_size=2 * 1024 * 1024,
    ):
        log.info("WebSocket server listening on %s:%d", HOST, PORT)
        await broadcast_frames(cache)


if __name__ == "__main__":
    asyncio.run(main())
