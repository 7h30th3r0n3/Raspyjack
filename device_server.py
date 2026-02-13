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
import subprocess
import termios
import fcntl
import struct
import pty
from pathlib import Path
from typing import Set
from urllib.parse import urlparse, parse_qs

import websockets


# ------------------------------ Config ---------------------------------------
FRAME_PATH = Path(os.environ.get("RJ_FRAME_PATH", "/dev/shm/raspyjack_last.jpg"))
HOST = os.environ.get("RJ_WS_HOST", "0.0.0.0")
PORT = int(os.environ.get("RJ_WS_PORT", "8765"))
FPS = float(os.environ.get("RJ_FPS", "10"))
TOKEN_FILE = Path(os.environ.get("RJ_WS_TOKEN_FILE", "/root/Raspyjack/.webui_token"))
INPUT_SOCK = os.environ.get("RJ_INPUT_SOCK", "/dev/shm/rj_input.sock")
SHELL_CMD = os.environ.get("RJ_SHELL_CMD", "/bin/bash")
SHELL_CWD = os.environ.get("RJ_SHELL_CWD", "/")

SEND_TIMEOUT = 0.5
PING_INTERVAL = 15

# WebSocket server only listens on these interfaces — wlan1+ are for attacks
WEBUI_INTERFACES = ["eth0", "wlan0", "tailscale0"]


def _load_shared_token():
    """Load auth token from env first, then token file."""
    env_token = str(os.environ.get("RJ_WS_TOKEN", "")).strip()
    if env_token:
        return env_token
    try:
        if TOKEN_FILE.exists():
            for line in TOKEN_FILE.read_text(encoding="utf-8").splitlines():
                value = line.strip()
                if value and not value.startswith("#"):
                    return value
    except Exception:
        pass
    return None


TOKEN = _load_shared_token()


def _get_interface_ip(interface: str):
    """Get the IPv4 address of a network interface."""
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", interface],
            capture_output=True, text=True, timeout=3,
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if "inet " in line:
                    return line.split("inet ")[1].split("/")[0]
    except Exception:
        pass
    return None


def _get_webui_bind_addrs():
    """Return (ip, iface_label) pairs the WS server should bind to."""
    addrs = []
    for iface in WEBUI_INTERFACES:
        ip = _get_interface_ip(iface)
        if ip:
            addrs.append((ip, iface))
    addrs.append(("127.0.0.1", "lo"))
    return addrs


logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
)
log = logging.getLogger("rj-ws")
if TOKEN:
    log.info("WebSocket token auth enabled")
else:
    log.warning("WebSocket token auth disabled (set RJ_WS_TOKEN or token file)")


# --------------------------- Client Registry ---------------------------------
clients: Set = set()
clients_lock = asyncio.Lock()


# ----------------------------- Shell Session ----------------------------------
class ShellSession:
    def __init__(self, loop: asyncio.AbstractEventLoop, ws):
        self.loop = loop
        self.ws = ws
        self.master_fd, self.slave_fd = pty.openpty()
        env = os.environ.copy()
        env.setdefault("TERM", "xterm-256color")
        self.proc = subprocess.Popen(
            [SHELL_CMD],
            stdin=self.slave_fd,
            stdout=self.slave_fd,
            stderr=self.slave_fd,
            cwd=SHELL_CWD,
            env=env,
            close_fds=True,
        )
        os.close(self.slave_fd)
        os.set_blocking(self.master_fd, False)
        self.loop.add_reader(self.master_fd, self._on_output)
        self._closed = False
        self._exit_sent = False
        self._wait_task = self.loop.create_task(self._wait_exit())

    async def _wait_exit(self):
        try:
            await asyncio.to_thread(self.proc.wait)
        except Exception:
            return
        await self._send_exit()

    def _on_output(self):
        if self._closed:
            return
        try:
            data = os.read(self.master_fd, 4096)
            if not data:
                self.loop.create_task(self._send_exit())
                return
            msg = json.dumps({"type": "shell_out", "data": data.decode("utf-8", "ignore")})
            self.loop.create_task(self._safe_send(msg))
        except Exception:
            self.loop.create_task(self._send_exit())

    async def _safe_send(self, msg: str):
        try:
            await self.ws.send(msg)
        except Exception:
            self.close()

    async def _send_exit(self):
        if self._exit_sent:
            return
        self._exit_sent = True
        code = None
        try:
            code = self.proc.poll()
        except Exception:
            pass
        try:
            await self.ws.send(json.dumps({"type": "shell_exit", "code": code}))
        except Exception:
            pass
        self.close()

    def write(self, data: str):
        if self._closed:
            return
        try:
            os.write(self.master_fd, data.encode())
        except Exception:
            self.loop.create_task(self._send_exit())

    def resize(self, cols: int, rows: int):
        if self._closed:
            return
        try:
            size = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, size)
        except Exception:
            pass

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self.loop.remove_reader(self.master_fd)
        except Exception:
            pass
        try:
            os.close(self.master_fd)
        except Exception:
            pass
        try:
            if self.proc.poll() is None:
                self.proc.terminate()
        except Exception:
            pass
        try:
            if self._wait_task:
                self._wait_task.cancel()
        except Exception:
            pass


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
    loop = asyncio.get_running_loop()
    shell = None

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
                continue

            if data.get("type") == "shell_open":
                if shell:
                    shell.close()
                shell = ShellSession(loop, ws)
                try:
                    await ws.send(json.dumps({"type": "shell_ready"}))
                except Exception:
                    shell.close()
                continue

            if data.get("type") == "shell_in":
                if shell:
                    payload = data.get("data", "")
                    if payload:
                        shell.write(payload)
                continue

            if data.get("type") == "shell_resize":
                if shell:
                    cols = int(data.get("cols") or 0)
                    rows = int(data.get("rows") or 0)
                    if cols > 0 and rows > 0:
                        shell.resize(cols, rows)
                continue

            if data.get("type") == "shell_close":
                if shell:
                    shell.close()
                    shell = None
                continue

    except Exception:
        pass
    finally:
        if shell:
            shell.close()
        async with clients_lock:
            clients.discard(ws)
        log.info("Client disconnected (%d online)", len(clients))


# ----------------------------- Main -------------------------------------------
async def main():
    cache = FrameCache(FRAME_PATH)

    # If a specific host was set via env var, honour it (single bind)
    if HOST != "0.0.0.0":
        async with websockets.serve(
            handle_client, HOST, PORT,
            ping_interval=PING_INTERVAL, max_size=2 * 1024 * 1024,
        ):
            log.info("WebSocket server listening on %s:%d", HOST, PORT)
            await broadcast_frames(cache)
        return

    # Default: bind only to eth0 + wlan0 (+ localhost).  wlan1+ stay untouched.
    bind_addrs = _get_webui_bind_addrs()
    servers = []

    for addr, iface in bind_addrs:
        try:
            srv = await websockets.serve(
                handle_client, addr, PORT,
                ping_interval=PING_INTERVAL, max_size=2 * 1024 * 1024,
            )
            servers.append(srv)
            log.info("WebSocket server listening on %s:%d (%s)", addr, PORT, iface)
        except Exception as exc:
            log.warning("Could not bind WS to %s:%d (%s): %s", addr, PORT, iface, exc)

    if not servers:
        # Last resort — fall back so the WS server is not dead
        log.warning("No WebUI interfaces available, falling back to 0.0.0.0")
        async with websockets.serve(
            handle_client, "0.0.0.0", PORT,
            ping_interval=PING_INTERVAL, max_size=2 * 1024 * 1024,
        ):
            log.info("WebSocket server listening on 0.0.0.0:%d", PORT)
            await broadcast_frames(cache)
        return

    try:
        await broadcast_frames(cache)
    finally:
        for srv in servers:
            srv.close()
            await srv.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
