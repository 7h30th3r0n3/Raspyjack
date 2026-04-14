#!/usr/bin/env python3
"""
RaspyJack – WebSocket device server
Compatible websockets v11+ / v12+ /
"""

import asyncio
import base64
import hmac
import hashlib
import json
import logging
import os
import socket
import subprocess
import time
import termios
import fcntl
import struct
import pty
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Dict, Set
from urllib.parse import urlparse, parse_qs

import websockets


# ------------------------------ Config ---------------------------------------
FRAME_PATH = Path(os.environ.get("RJ_FRAME_PATH", "/dev/shm/raspyjack_last.jpg"))
CARDPUTER_FRAME_PATH = Path(os.environ.get("RJ_CARDPUTER_FRAME_PATH", "/dev/shm/raspyjack_cardputer.jpg"))
CARDPUTER_FRAME_WIDTH = int(os.environ.get("RJ_CARDPUTER_FRAME_WIDTH", "240"))
CARDPUTER_FRAME_HEIGHT = int(os.environ.get("RJ_CARDPUTER_FRAME_HEIGHT", "135"))
HOST = os.environ.get("RJ_WS_HOST", "0.0.0.0")
PORT = int(os.environ.get("RJ_WS_PORT", "8765"))
FPS = float(os.environ.get("RJ_FPS", "10"))
CARDPUTER_FPS = float(os.environ.get("RJ_CARDPUTER_FPS", "6"))
TOKEN_FILE = Path(os.environ.get("RJ_WS_TOKEN_FILE", "/root/Raspyjack/.webui_token"))
AUTH_FILE = Path(os.environ.get("RJ_WEB_AUTH_FILE", "/root/Raspyjack/.webui_auth.json"))
AUTH_SECRET_FILE = Path(os.environ.get("RJ_WEB_AUTH_SECRET_FILE", "/root/Raspyjack/.webui_session_secret"))
SESSION_COOKIE_NAME = os.environ.get("RJ_WEB_SESSION_COOKIE", "rj_session")
INPUT_SOCK = os.environ.get("RJ_INPUT_SOCK", "/dev/shm/rj_input.sock")
TEXT_SESSION_FILE = Path(os.environ.get("RJ_TEXT_SESSION_FILE", "/dev/shm/rj_text_session.json"))
SHELL_CMD = os.environ.get("RJ_SHELL_CMD", "/bin/bash")
SHELL_CWD = os.environ.get("RJ_SHELL_CWD", "/")
STATS_LOG_INTERVAL = max(5.0, float(os.environ.get("RJ_WS_STATS_INTERVAL", "15")))

SEND_TIMEOUT = 0.5
PING_INTERVAL = 15
VERBOSE_INPUT_LOGS = os.environ.get("RJ_WS_VERBOSE_INPUT", "0") == "1"

# WebSocket server only listens on these interfaces — wlan1+ are for attacks
# Override via RJ_WEBUI_INTERFACES env var (comma-separated)
_env_ifaces = os.environ.get("RJ_WEBUI_INTERFACES", "").strip()
WEBUI_INTERFACES = [i.strip() for i in _env_ifaces.split(",") if i.strip()] if _env_ifaces else ["eth0", "eth1", "wlan0", "tailscale0"]


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


def _load_line_secret(path: Path):
    try:
        if not path.exists():
            return None
        for line in path.read_text(encoding="utf-8").splitlines():
            value = line.strip()
            if value and not value.startswith("#"):
                return value
    except Exception:
        pass
    return None


def _auth_initialized() -> bool:
    try:
        if not AUTH_FILE.exists():
            return False
        raw = AUTH_FILE.read_text(encoding="utf-8")
        data = json.loads(raw) if raw else {}
        return bool(data.get("username") and data.get("password_hash"))
    except Exception:
        return False


AUTH_SECRET = _load_line_secret(AUTH_SECRET_FILE)


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _hmac_sign(payload: str) -> str:
    if not AUTH_SECRET:
        return ""
    mac = hmac.new(AUTH_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
    return _b64url_encode(mac)


def _read_signed_token(token: str):
    if not AUTH_SECRET:
        return None
    try:
        payload, sig = token.split(".", 1)
    except ValueError:
        return None
    if not hmac.compare_digest(_hmac_sign(payload), sig):
        return None
    try:
        raw = _b64url_decode(payload)
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


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
if AUTH_SECRET:
    log.info("WebSocket session-ticket auth enabled")
else:
    log.warning("WebSocket session-ticket auth disabled (missing auth secret)")


# --------------------------- Client Registry ---------------------------------
clients: Set = set()
client_profiles: Dict = {}
client_senders: Dict = {}
client_send_locks: Dict = {}
client_frame_formats: Dict = {}
client_last_stream_state: Dict = {}
clients_lock = asyncio.Lock()

stream_stats = {
    "frames_queued": 0,
    "frames_deferred": 0,
    "frames_skipped": 0,
    "text_updates": 0,
}


def _bump_stat(key: str, amount: int = 1):
    stream_stats[key] = stream_stats.get(key, 0) + amount


async def _send_ws(ws, message, timeout: float = SEND_TIMEOUT):
    lock = client_send_locks.get(ws)
    if lock is None:
        await asyncio.wait_for(ws.send(message), timeout)
        return
    async with lock:
        await asyncio.wait_for(ws.send(message), timeout)


class ClientSender:
    def __init__(self, ws):
        self.ws = ws
        self._frame_message = None
        self._text_message = None
        self._event = asyncio.Event()
        self._closed = False
        self._task = asyncio.create_task(self._run())

    def queue_frame(self, message):
        if self._closed or not message:
            return
        self._frame_message = message
        self._event.set()

    def queue_text(self, message: str):
        if self._closed or not message:
            return
        self._text_message = message
        self._event.set()

    async def close(self):
        if self._closed:
            return
        self._closed = True
        self._event.set()
        if asyncio.current_task() is not self._task:
            await self._task

    async def _run(self):
        while True:
            await self._event.wait()
            self._event.clear()

            if self._closed:
                return

            while True:
                text_message = self._text_message
                frame_message = self._frame_message
                self._text_message = None
                self._frame_message = None

                if not text_message and not frame_message:
                    break

                try:
                    if text_message:
                        await _send_ws(self.ws, text_message)
                    if frame_message:
                        await _send_ws(self.ws, frame_message)
                except Exception:
                    return


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
            await _send_ws(self.ws, msg)
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
    def __init__(self, path: Path, profile: str = "legacy", width: int = None, height: int = None):
        self.path = path
        self.profile = profile
        self.width = width
        self.height = height
        self._last_mtime = 0.0
        self._last_size = 0
        self._last_payload = None
        self._last_binary_payload = None
        self._last_message = None
        self._revision = 0

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
            self._last_binary_payload = raw
            self._last_message = self._build_message(b64)
            self._revision += 1
            return b64
        except Exception:
            return None

    def refresh(self) -> bool:
        if self._last_message is None:
            return bool(self.load_b64())
        if not self.has_changed():
            return False
        return bool(self.load_b64())

    def _build_message(self, payload: str):
        msg = {"type": "frame", "data": payload}
        if self.profile != "legacy":
            msg["profile"] = self.profile
        if self.width:
            msg["width"] = self.width
        if self.height:
            msg["height"] = self.height
        return json.dumps(msg, separators=(",", ":"))

    @property
    def last_payload(self):
        return self._last_payload

    @property
    def last_message(self):
        return self._last_message

    @property
    def last_binary_payload(self):
        return self._last_binary_payload

    @property
    def revision(self):
        return self._revision

    def get_message(self):
        self.refresh()
        if not self.last_payload:
            return None
        return self._last_message


async def broadcast_frames(caches):
    profile_intervals = {
        "legacy": 1.0 / max(1.0, FPS),
        "cardputer": 1.0 / max(1.0, CARDPUTER_FPS),
    }
    delay = max(0.001, min(profile_intervals.values()))
    profile_next_send_at = {profile: 0.0 for profile in profile_intervals}
    last_stats_log = time.monotonic()
    log.info(
        "Frame broadcaster started legacy=%.1f FPS cardputer=%.1f FPS",
        1.0 / profile_intervals["legacy"],
        1.0 / profile_intervals["cardputer"],
    )
    last_text_message = None

    while True:
        try:
            now = time.monotonic()
            async with clients_lock:
                recipients = [
                    (
                        c,
                        client_profiles.get(c, "legacy"),
                        client_frame_formats.get(c, "json"),
                        client_senders.get(c),
                        client_last_stream_state.get(c),
                    )
                    for c in list(clients)
                ]

            messages = {}
            binary_payloads = {}
            revisions = {}
            sent_profiles = set()
            for profile, cache in caches.items():
                cache.refresh()
                messages[profile] = cache.last_message
                binary_payloads[profile] = cache.last_binary_payload
                revisions[profile] = cache.revision

            text_message = _get_text_session_message()
            if text_message != last_text_message:
                try:
                    text_state = json.loads(text_message)
                    log.info(
                        "Text session update active=%s session=%s title=%s",
                        text_state.get("active"),
                        text_state.get("session_id", ""),
                        text_state.get("title", ""),
                    )
                except Exception:
                    pass

            for client, profile, frame_format, sender, last_state in recipients:
                if not sender:
                    continue

                cache = caches.get(profile) or caches["legacy"]
                use_binary = frame_format == "binary" and profile == "cardputer"
                msg = binary_payloads.get(profile) if use_binary else messages.get(profile)
                state = (profile, frame_format, revisions.get(profile, 0))
                first_send = not last_state or last_state[0] != profile

                if msg and state != last_state:
                    if first_send or now >= profile_next_send_at.get(profile, 0.0):
                        sender.queue_frame(msg)
                        client_last_stream_state[client] = state
                        sent_profiles.add(profile)
                        _bump_stat("frames_queued")
                    else:
                        _bump_stat("frames_deferred")
                elif msg:
                    _bump_stat("frames_skipped")

                if text_message != last_text_message:
                    sender.queue_text(text_message)
                    _bump_stat("text_updates")

            for profile in sent_profiles:
                profile_next_send_at[profile] = now + profile_intervals[profile]

            last_text_message = text_message

            if (now - last_stats_log) >= STATS_LOG_INTERVAL:
                cardputer_cache = caches.get("cardputer")
                legacy_cache = caches.get("legacy")
                log.info(
                    "WS stats queued=%d deferred=%d skipped=%d text=%d legacy_bytes=%d cardputer_bytes=%d clients=%d",
                    stream_stats.get("frames_queued", 0),
                    stream_stats.get("frames_deferred", 0),
                    stream_stats.get("frames_skipped", 0),
                    stream_stats.get("text_updates", 0),
                    legacy_cache._last_size if legacy_cache else 0,
                    cardputer_cache._last_size if cardputer_cache else 0,
                    len(recipients),
                )
                for key in list(stream_stats.keys()):
                    stream_stats[key] = 0
                last_stats_log = now

            await asyncio.sleep(delay)
        except Exception as e:
            log.warning("Broadcaster error: %s", e)


async def _send_client_updates(client, frame_message=None, text_message=None):
    try:
        if frame_message:
            await _send_ws(client, frame_message)
        if text_message:
            await _send_ws(client, text_message)
    except Exception:
        pass


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


def send_text_key_event(session_id, key=None, special=None):
    if not session_id:
        return
    payload = {
        "type": "text_key",
        "session_id": session_id,
    }
    if special:
        payload["special"] = special
    elif key:
        payload["key"] = key
    else:
        return
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(INPUT_SOCK)
            s.send(json.dumps(payload).encode())
    except Exception:
        pass


def _read_text_session_state():
    try:
        if not TEXT_SESSION_FILE.exists():
            return {"type": "text_session", "active": False}
        raw = TEXT_SESSION_FILE.read_text(encoding="utf-8")
        data = json.loads(raw) if raw else {}
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}
    message = {
        "type": "text_session",
        "active": bool(data.get("active")),
    }
    if message["active"]:
        message["session_id"] = str(data.get("session_id") or "")
        message["title"] = str(data.get("title") or "Input")[:32]
        message["default"] = str(data.get("default") or "")[:128]
        message["charset"] = str(data.get("charset") or "full")
        message["max_len"] = int(data.get("max_len") or 64)
        message["timeout"] = float(data.get("timeout") or 30.0)
    return message


def _get_text_session_message():
    return json.dumps(_read_text_session_state(), separators=(",", ":"))


# ----------------------------- Auth -------------------------------------------
def authorize(path: str) -> bool:
    if not TOKEN:
        return True
    try:
        q = parse_qs(urlparse(path).query)
        return q.get("token", [None])[0] == TOKEN
    except Exception:
        return False


def _token_ok(value: str) -> bool:
    if not TOKEN:
        return True
    return str(value or "").strip() == TOKEN


def _ws_ticket_ok(value: str) -> bool:
    claims = _read_signed_token(str(value or "").strip())
    if not claims:
        return False
    if claims.get("typ") != "ws_ticket":
        return False
    try:
        return int(claims.get("exp", 0)) >= int(time.time())
    except Exception:
        return False


def _session_token_ok(token: str) -> bool:
    claims = _read_signed_token(str(token or "").strip())
    if not claims:
        return False
    if claims.get("typ") != "session":
        return False
    try:
        return int(claims.get("exp", 0)) >= int(time.time())
    except Exception:
        return False


def _cookie_session_ok(ws) -> bool:
    header_val = ""
    try:
        req_headers = getattr(ws, "request_headers", None)
        if req_headers:
            header_val = str(req_headers.get("Cookie", "") or "")
    except Exception:
        header_val = ""
    if not header_val:
        try:
            req = getattr(ws, "request", None)
            hdrs = getattr(req, "headers", None) if req else None
            if hdrs:
                header_val = str(hdrs.get("Cookie", "") or "")
        except Exception:
            header_val = ""
    if not header_val:
        return False
    c = SimpleCookie()
    try:
        c.load(header_val)
    except Exception:
        return False
    morsel = c.get(SESSION_COOKIE_NAME)
    if not morsel:
        return False
    return _session_token_ok(morsel.value)


# ----------------------------- WS Handler -------------------------------------
async def handle_client(ws):
    # websockets v12+ : path is in ws.request.path
    path = getattr(getattr(ws, "request", None), "path", "/")
    if not _auth_initialized():
        authenticated = True
    else:
        authenticated = _cookie_session_ok(ws) or (authorize(path) if TOKEN else False)
    if authenticated:
        async with clients_lock:
            clients.add(ws)
            client_profiles[ws] = "legacy"
            client_frame_formats[ws] = "json"
            client_send_locks[ws] = asyncio.Lock()
            client_senders[ws] = ClientSender(ws)
        log.info("Client connected (%d online)", len(clients))
        try:
            await _send_ws(ws, _get_text_session_message())
        except Exception:
            pass
    else:
        try:
            await ws.send(json.dumps({"type": "auth_required"}))
        except Exception:
            await ws.close(code=4401, reason="Unauthorized")
            return
    loop = asyncio.get_running_loop()
    shell = None

    try:
        async for raw in ws:
            if isinstance(raw, (bytes, bytearray)):
                continue
            try:
                data = json.loads(raw)
            except Exception:
                continue

            if not authenticated:
                msg_type = data.get("type")
                if msg_type not in ("auth", "auth_session"):
                    continue
                token_ok = msg_type == "auth" and _token_ok(data.get("token", ""))
                sess_ok = msg_type == "auth_session" and _ws_ticket_ok(data.get("ticket", ""))
                if token_ok or sess_ok:
                    authenticated = True
                    async with clients_lock:
                        clients.add(ws)
                        client_profiles[ws] = "legacy"
                        client_frame_formats[ws] = "json"
                        client_send_locks[ws] = asyncio.Lock()
                        client_senders[ws] = ClientSender(ws)
                    log.info("Client authenticated (%d online)", len(clients))
                    try:
                        await _send_ws(ws, json.dumps({"type": "auth_ok"}))
                        await _send_ws(ws, _get_text_session_message())
                    except Exception:
                        pass
                else:
                    log.warning("Client auth failed (type=%s)", msg_type)
                    try:
                        await _send_ws(ws, json.dumps({"type": "auth_error"}))
                    except Exception:
                        pass
                    await ws.close(code=4401, reason="Unauthorized")
                    break
                continue

            if data.get("type") == "input":
                btn = data.get("button")
                state = data.get("state")
                if btn and state in ("press", "release"):
                    if VERBOSE_INPUT_LOGS:
                        log.info("Cardputer input %s %s", btn, state)
                    send_input_event(btn, state)
                    try:
                        await _send_ws(ws, json.dumps({"type": "input_ack", "button": btn, "state": state, "result": "queued"}, separators=(",", ":")))
                    except Exception:
                        pass
                continue

            if data.get("type") == "text_key":
                session_id = str(data.get("session_id") or "")
                key = str(data.get("key") or "")
                special = str(data.get("special") or "")
                if session_id and (key or special):
                    if VERBOSE_INPUT_LOGS:
                        log.info("Cardputer text key session=%s key=%r special=%s", session_id, key, special)
                    send_text_key_event(session_id, key=key or None, special=special or None)
                continue

            if data.get("type") == "stream_profile":
                requested = str(data.get("profile") or "legacy").strip().lower()
                profile = "cardputer" if requested == "cardputer" else "legacy"
                requested_format = str(data.get("format") or "json").strip().lower()
                frame_format = "binary" if profile == "cardputer" and requested_format == "binary" else "json"
                async with clients_lock:
                    if ws in clients:
                        client_profiles[ws] = profile
                        client_frame_formats[ws] = frame_format
                try:
                    await _send_ws(ws, json.dumps({"type": "stream_profile", "profile": profile, "format": frame_format, "status": "ok"}, separators=(",", ":")))
                except Exception:
                    pass
                continue

            if data.get("type") == "shell_open":
                if shell:
                    shell.close()
                shell = ShellSession(loop, ws)
                try:
                    await _send_ws(ws, json.dumps({"type": "shell_ready"}))
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

    except websockets.exceptions.ConnectionClosed:
        pass
    except asyncio.TimeoutError:
        log.warning("Client timed out")
    except Exception as exc:
        log.warning("Client handler error: %s", exc)
    finally:
        if shell:
            shell.close()
        sender = None
        async with clients_lock:
            clients.discard(ws)
            client_profiles.pop(ws, None)
            client_frame_formats.pop(ws, None)
            client_last_stream_state.pop(ws, None)
            sender = client_senders.pop(ws, None)
            client_send_locks.pop(ws, None)
        if sender:
            await sender.close()
        log.info("Client disconnected (%d online)", len(clients))


# ----------------------------- Main -------------------------------------------
async def main():
    caches = {
        "legacy": FrameCache(FRAME_PATH),
        "cardputer": FrameCache(CARDPUTER_FRAME_PATH, profile="cardputer", width=CARDPUTER_FRAME_WIDTH, height=CARDPUTER_FRAME_HEIGHT),
    }

    # If a specific host was set via env var, honour it (single bind)
    if HOST != "0.0.0.0":
        async with websockets.serve(
            handle_client, HOST, PORT,
            ping_interval=PING_INTERVAL, max_size=2 * 1024 * 1024,
        ):
            log.info("WebSocket server listening on %s:%d", HOST, PORT)
            await broadcast_frames(caches)
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
            await broadcast_frames(caches)
        return

    try:
        await broadcast_frames(caches)
    finally:
        for srv in servers:
            srv.close()
            await srv.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
