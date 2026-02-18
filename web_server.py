#!/usr/bin/env python3
"""
RaspyJack WebUI HTTP server
---------------------------
Serves the static WebUI and exposes a small, read-only API to browse loot/.

Routes:
  /                  -> static WebUI (web/)
  /api/loot/list      -> JSON directory listing (read-only)
  /api/loot/download  -> file download (read-only)
  /api/loot/view      -> text preview (read-only)
  /api/system/status  -> live system monitor metrics
  /api/settings/discord_webhook -> get/save Discord webhook
  /api/auth/*         -> bootstrap/login/session endpoints

Environment:
  RJ_WEB_HOST  Host to bind (default: 0.0.0.0)
  RJ_WEB_PORT  Port to bind (default: 8080)
  RJ_WS_TOKEN  Optional shared token for API access (Bearer header)
  RJ_WS_TOKEN_FILE Optional token file (default: <repo>/.webui_token)
  RJ_WEB_AUTH_FILE Auth user storage file (default: /root/Raspyjack/.webui_auth.json)
  RJ_WEB_AUTH_SECRET_FILE Session signing secret file (default: /root/Raspyjack/.webui_session_secret)
  RJ_WEB_SESSION_TTL Session lifetime seconds (default: 28800)
  RJ_WEB_WS_TICKET_TTL WS ticket lifetime seconds (default: 120)
"""

from __future__ import annotations

import json
import base64
import hmac
import hashlib
import mimetypes
import os
import secrets
import shutil
import subprocess
import threading
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse, unquote

ROOT_DIR = Path(__file__).resolve().parent
WEB_DIR = ROOT_DIR / "web"
LOOT_DIR = ROOT_DIR / "loot"
PAYLOADS_DIR = ROOT_DIR / "payloads"
PAYLOAD_STATE_PATH = Path("/dev/shm/rj_payload_state.json")
DISCORD_WEBHOOK_PATH = ROOT_DIR / "discord_webhook.txt"
TOKEN_FILE = Path(os.environ.get("RJ_WS_TOKEN_FILE", str(ROOT_DIR / ".webui_token")))
AUTH_FILE = Path(os.environ.get("RJ_WEB_AUTH_FILE", "/root/Raspyjack/.webui_auth.json"))
AUTH_SECRET_FILE = Path(os.environ.get("RJ_WEB_AUTH_SECRET_FILE", "/root/Raspyjack/.webui_session_secret"))
SESSION_COOKIE_NAME = "rj_session"
SESSION_TTL_SECONDS = int(os.environ.get("RJ_WEB_SESSION_TTL", str(8 * 60 * 60)))
WS_TICKET_TTL_SECONDS = int(os.environ.get("RJ_WEB_WS_TICKET_TTL", "120"))
TAILSCALE_KEY_PATH = ROOT_DIR / ".tailscale_auth_key"
TAILSCALE_STATUS_PATH = Path("/dev/shm/rj_tailscale_status.json")


def _load_shared_token() -> str | None:
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


def _load_line_secret(path: Path) -> str | None:
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


def _load_or_create_auth_secret() -> str:
    existing = _load_line_secret(AUTH_SECRET_FILE)
    if existing:
        return existing
    generated = secrets.token_urlsafe(48)
    try:
        AUTH_SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
        AUTH_SECRET_FILE.write_text(generated + "\n", encoding="utf-8")
        os.chmod(AUTH_SECRET_FILE, 0o600)
    except Exception:
        # Fallback for environments where file creation is not possible.
        pass
    return generated

HOST = os.environ.get("RJ_WEB_HOST", "0.0.0.0")
PORT = int(os.environ.get("RJ_WEB_PORT", "8080"))
TOKEN = _load_shared_token()
AUTH_SECRET = _load_or_create_auth_secret()

# WebUI only listens on these interfaces — wlan1+ are for attacks/monitor mode
WEBUI_INTERFACES = ["eth0", "wlan0", "tailscale0"]


def _get_interface_ip(interface: str) -> str | None:
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


def _get_webui_bind_addrs() -> list[tuple[str, str]]:
    """Return (ip, iface_label) pairs the WebUI should bind to."""
    addrs: list[tuple[str, str]] = []
    for iface in WEBUI_INTERFACES:
        ip = _get_interface_ip(iface)
        if ip:
            addrs.append((ip, iface))
    # Always include localhost for local access
    addrs.append(("127.0.0.1", "lo"))
    return addrs
PREVIEW_MAX_BYTES = int(os.environ.get("RJ_LOOT_PREVIEW_MAX", str(200 * 1024)))
PAYLOAD_MAX_BYTES = int(os.environ.get("RJ_PAYLOAD_MAX", str(512 * 1024)))
TEXT_EXTS = {
    ".txt", ".log", ".md", ".json", ".csv", ".conf", ".ini", ".yaml", ".yml",
    ".pcapng.txt", ".xml", ".sqlite", ".db", ".out", ".py", ".sh"
}

_CPU_SNAPSHOT = None
_LOGIN_FAILS: dict[str, list[float]] = {}


def _is_valid_discord_webhook(url: str) -> bool:
    return url.startswith("https://discord.com/api/webhooks/")


def _read_discord_webhook_url() -> str:
    """Read the configured Discord webhook URL from file."""
    try:
        if not DISCORD_WEBHOOK_PATH.exists():
            return ""
        for line in DISCORD_WEBHOOK_PATH.read_text(encoding="utf-8").splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            if _is_valid_discord_webhook(value):
                return value
        return ""
    except Exception:
        return ""


def _write_discord_webhook_url(url: str) -> tuple[bool, str]:
    """Write or clear Discord webhook URL in file."""
    value = str(url or "").strip()
    try:
        if not value:
            if DISCORD_WEBHOOK_PATH.exists():
                DISCORD_WEBHOOK_PATH.unlink()
            return True, "cleared"
        if not _is_valid_discord_webhook(value):
            return False, "invalid webhook url"
        DISCORD_WEBHOOK_PATH.write_text(value + "\n", encoding="utf-8")
        return True, "saved"
    except Exception as exc:
        return False, f"write error: {exc}"


def _tailscale_write_status(payload: dict) -> None:
    """Persist last Tailscale install/bootstrap status for the WebUI."""
    try:
        TAILSCALE_STATUS_PATH.write_text(json.dumps(payload), encoding="utf-8")
    except Exception:
        pass


def _tailscale_read_status() -> dict:
    try:
        if not TAILSCALE_STATUS_PATH.exists():
            return {}
        raw = TAILSCALE_STATUS_PATH.read_text(encoding="utf-8")
        data = json.loads(raw) if raw else {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _tailscale_installed() -> bool:
    """Return True if the tailscale CLI appears to be installed."""
    try:
        return shutil.which("tailscale") is not None
    except Exception:
        return False


def _tailscale_status() -> dict:
    """
    Best-effort snapshot of the Tailscale daemon.
    Returns {"backend_state": str|None, "ip": str|None}.
    """
    summary: dict[str, str | None] = {"backend_state": None, "ip": None}
    if not _tailscale_installed():
        return summary
    try:
        res = subprocess.run(
            ["tailscale", "status", "--json"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode != 0 or not res.stdout:
            return summary
        data = json.loads(res.stdout)
        if not isinstance(data, dict):
            return summary
        summary["backend_state"] = str(data.get("BackendState") or "") or None
        self_info = data.get("Self") or {}
        if isinstance(self_info, dict):
            ips = self_info.get("TailscaleIPs") or []
            if isinstance(ips, list) and ips:
                summary["ip"] = str(ips[0])
    except Exception:
        pass
    return summary


def _tailscale_write_key(key: str) -> tuple[bool, str]:
    """Store the auth key in a root-only file so tailscale can read it."""
    value = str(key or "").strip()
    if not value:
        return False, "missing auth key"
    try:
        TAILSCALE_KEY_PATH.write_text(value + "\n", encoding="utf-8")
        try:
            os.chmod(TAILSCALE_KEY_PATH, 0o600)
        except Exception:
            # On some platforms chmod may fail; do not treat as fatal.
            pass
        return True, "ok"
    except Exception as exc:
        return False, f"write error: {exc}"


def _tailscale_run_install_and_up() -> None:
    """
    Run the official install script and bring Tailscale up using the stored auth key.
    This is executed in a background thread so HTTP handlers can return quickly.
    """
    _tailscale_write_status({"installing": True, "ok": False, "error": None})

    try:
        if not TAILSCALE_KEY_PATH.exists():
            _tailscale_write_status({
                "installing": False,
                "ok": False,
                "error": "auth key not found",
            })
            return
    except Exception:
        _tailscale_write_status({
            "installing": False,
            "ok": False,
            "error": "auth key not found",
        })
        return

    # 1) Install Tailscale using the official script.
    try:
        install_res = subprocess.run(
            ["sh", "-c", "curl -fsSL https://tailscale.com/install.sh | sh"],
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        _tailscale_write_status({
            "installing": False,
            "ok": False,
            "error": "tailscale install timeout",
        })
        return
    except Exception as exc:
        _tailscale_write_status({
            "installing": False,
            "ok": False,
            "error": str(exc),
        })
        return

    if install_res.returncode != 0:
        msg = (install_res.stderr or install_res.stdout or "").strip()
        if not msg:
            msg = f"tailscale install failed (code {install_res.returncode})"
        _tailscale_write_status({
            "installing": False,
            "ok": False,
            "error": msg[:200],
        })
        return

    # 2) Bring the daemon up using the stored auth key (non-interactive).
    try:
        auth_arg = f"--auth-key=file:{TAILSCALE_KEY_PATH}"
        up_res = subprocess.run(
            ["tailscale", "up", auth_arg, "--ssh"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        _tailscale_write_status({
            "installing": False,
            "ok": False,
            "error": "tailscale up timeout",
        })
        return
    except Exception as exc:
        _tailscale_write_status({
            "installing": False,
            "ok": False,
            "error": str(exc),
        })
        return

    if up_res.returncode != 0:
        msg = (up_res.stderr or up_res.stdout or "").strip()
        if not msg:
            msg = f"tailscale up failed (code {up_res.returncode})"
        _tailscale_write_status({
            "installing": False,
            "ok": False,
            "error": msg[:200],
        })
        return

    _tailscale_write_status({
        "installing": False,
        "ok": True,
        "error": None,
    })


def _read_cpu_percent() -> float:
    """Best-effort CPU usage based on /proc/stat delta."""
    global _CPU_SNAPSHOT
    try:
        with open("/proc/stat", "r", encoding="utf-8") as f:
            line = f.readline().strip()
        if not line.startswith("cpu "):
            return 0.0
        parts = [int(x) for x in line.split()[1:]]
        idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
        total = sum(parts)
        if _CPU_SNAPSHOT is None:
            _CPU_SNAPSHOT = (idle, total)
            return 0.0
        prev_idle, prev_total = _CPU_SNAPSHOT
        _CPU_SNAPSHOT = (idle, total)
        idle_delta = idle - prev_idle
        total_delta = total - prev_total
        if total_delta <= 0:
            return 0.0
        pct = 100.0 * (1.0 - (idle_delta / total_delta))
        return max(0.0, min(100.0, pct))
    except Exception:
        return 0.0


def _read_meminfo() -> tuple[int, int]:
    """Return used_bytes, total_bytes from /proc/meminfo."""
    try:
        vals = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                key, rest = line.split(":", 1)
                vals[key.strip()] = int(rest.strip().split()[0]) * 1024
        total = int(vals.get("MemTotal", 0))
        available = int(vals.get("MemAvailable", vals.get("MemFree", 0)))
        used = max(0, total - available)
        return used, total
    except Exception:
        return 0, 0


def _read_temp_c() -> float | None:
    try:
        raw = Path("/sys/class/thermal/thermal_zone0/temp").read_text(encoding="utf-8").strip()
        val = float(raw)
        return val / 1000.0 if val > 1000 else val
    except Exception:
        return None


def _read_uptime_seconds() -> int:
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as f:
            return int(float(f.read().split()[0]))
    except Exception:
        return 0


def _read_ipv4_interfaces() -> list[dict]:
    out = []
    try:
        res = subprocess.run(
            ["ip", "-o", "-4", "addr", "show", "up"],
            capture_output=True, text=True, timeout=3,
        )
        if res.returncode != 0:
            return out
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            iface = parts[1]
            if iface == "lo":
                continue
            try:
                inet_idx = parts.index("inet")
                addr = parts[inet_idx + 1].split("/")[0]
            except Exception:
                addr = "-"
            out.append({"name": iface, "ipv4": addr, "up": True})
    except Exception:
        pass
    return out


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _hmac_sign(payload: str) -> str:
    mac = hmac.new(AUTH_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
    return _b64url_encode(mac)


def _issue_signed_token(claims: dict) -> str:
    payload = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    sig = _hmac_sign(payload)
    return f"{payload}.{sig}"


def _read_signed_token(token: str) -> dict | None:
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


def _read_auth_config() -> dict | None:
    try:
        if not AUTH_FILE.exists():
            return None
        data = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        if not data.get("username") or not data.get("password_hash"):
            return None
        return data
    except Exception:
        return None


def _auth_initialized() -> bool:
    return _read_auth_config() is not None


def _hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    rounds = 210000
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), rounds)
    return f"pbkdf2_sha256${rounds}${salt}${_b64url_encode(dk)}"


def _verify_password(password: str, encoded: str) -> bool:
    try:
        algo, rounds, salt, digest = encoded.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), int(rounds))
        return hmac.compare_digest(_b64url_encode(dk), digest)
    except Exception:
        return False


def _write_auth_config(username: str, password: str) -> tuple[bool, str]:
    user = str(username or "").strip()
    pwd = str(password or "")
    if len(user) < 3:
        return False, "username must be at least 3 characters"
    if len(user) > 32:
        return False, "username too long"
    if len(pwd) < 8:
        return False, "password must be at least 8 characters"
    rec = {
        "username": user,
        "password_hash": _hash_password(pwd),
        "created_at": int(time.time()),
    }
    try:
        AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
        AUTH_FILE.write_text(json.dumps(rec), encoding="utf-8")
        os.chmod(AUTH_FILE, 0o600)
        return True, "ok"
    except Exception as exc:
        return False, f"write error: {exc}"


def _session_from_cookie(handler: SimpleHTTPRequestHandler) -> dict | None:
    raw = str(handler.headers.get("Cookie", "") or "")
    if not raw:
        return None
    c = SimpleCookie()
    try:
        c.load(raw)
    except Exception:
        return None
    morsel = c.get(SESSION_COOKIE_NAME)
    if not morsel:
        return None
    claims = _read_signed_token(morsel.value)
    if not claims:
        return None
    if claims.get("typ") != "session":
        return None
    if int(claims.get("exp", 0)) < int(time.time()):
        return None
    if not claims.get("usr"):
        return None
    return claims


def _bearer_token_from_request(handler: SimpleHTTPRequestHandler, query: dict) -> str:
    try:
        authz = str(handler.headers.get("Authorization", "")).strip()
        if authz.lower().startswith("bearer "):
            return authz[7:].strip()
    except Exception:
        pass
    # Legacy fallback for older links.
    return str(query.get("token", [""])[0] or "").strip()


def _auth_context(handler: SimpleHTTPRequestHandler, query: dict) -> dict | None:
    sess = _session_from_cookie(handler)
    if sess:
        return {"method": "session", "user": str(sess.get("usr")), "claims": sess}
    bearer = _bearer_token_from_request(handler, query)
    if TOKEN and bearer and hmac.compare_digest(bearer, TOKEN):
        return {"method": "token", "user": "token-admin", "claims": None}
    if not _auth_initialized():
        return {"method": "bootstrap", "user": "bootstrap", "claims": None}
    return None


def _auth_ok(handler: SimpleHTTPRequestHandler, query: dict) -> bool:
    ctx = _auth_context(handler, query)
    return ctx is not None and ctx.get("method") != "bootstrap"


def _request_is_https(handler: SimpleHTTPRequestHandler) -> bool:
    """Return True for direct TLS or trusted local reverse proxy TLS."""
    if getattr(handler, "request_version", "").startswith("HTTPS/"):
        return True
    proto = str(handler.headers.get("X-Forwarded-Proto", "") or "").strip().lower()
    if proto != "https":
        return False
    try:
        ip = str(handler.client_address[0])
    except Exception:
        ip = ""
    # Trust forwarded scheme only from local proxy hops.
    return ip in ("127.0.0.1", "::1")


def _session_cookie_header(username: str, secure: bool = False, ttl_seconds: int = SESSION_TTL_SECONDS) -> tuple[str, str]:
    now = int(time.time())
    claims = {"typ": "session", "usr": username, "iat": now, "exp": now + int(ttl_seconds)}
    token = _issue_signed_token(claims)
    secure_attr = "; Secure" if secure else ""
    cookie = f"{SESSION_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={int(ttl_seconds)}{secure_attr}"
    return ("Set-Cookie", cookie)


def _clear_session_cookie_header(secure: bool = False) -> tuple[str, str]:
    secure_attr = "; Secure" if secure else ""
    return ("Set-Cookie", f"{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure_attr}")


def _safe_loot_path(raw_path: str) -> Path | None:
    raw_path = raw_path.strip().lstrip("/")
    target = (LOOT_DIR / raw_path).resolve()
    try:
        loot_root = LOOT_DIR.resolve()
    except FileNotFoundError:
        loot_root = LOOT_DIR
    if loot_root in target.parents or target == loot_root:
        return target
    return None


def _safe_payload_path(raw_path: str) -> Path | None:
    raw_path = raw_path.strip().lstrip("/")
    target = (PAYLOADS_DIR / raw_path).resolve()
    try:
        payload_root = PAYLOADS_DIR.resolve()
    except FileNotFoundError:
        payload_root = PAYLOADS_DIR
    if payload_root in target.parents or target == payload_root:
        return target
    return None


def _json_response(
    handler: SimpleHTTPRequestHandler,
    payload: dict,
    status: int = 200,
    extra_headers: list[tuple[str, str]] | None = None,
) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    if extra_headers:
        for key, value in extra_headers:
            handler.send_header(key, value)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _read_json(handler: SimpleHTTPRequestHandler) -> dict | None:
    try:
        length = int(handler.headers.get("Content-Length", "0") or "0")
    except Exception:
        length = 0
    try:
        raw = handler.rfile.read(length) if length > 0 else b"{}"
        return json.loads(raw.decode("utf-8", "ignore")) if raw else {}
    except Exception:
        return None


def _is_text_file(path: Path) -> bool:
    ctype, _ = mimetypes.guess_type(str(path))
    if ctype and ctype.startswith("text/"):
        return True
    ext = "".join(path.suffixes).lower() or path.suffix.lower()
    if ext in TEXT_EXTS:
        return True
    return False


class RaspyJackHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/ide":
            self.path = "/ide.html" + (f"?{parsed.query}" if parsed.query else "")
            super().do_GET()
            return

        if (
            parsed.path.startswith("/api/loot/")
            or parsed.path.startswith("/api/payloads/")
            or parsed.path.startswith("/api/system/")
            or parsed.path.startswith("/api/settings/")
            or parsed.path.startswith("/api/auth/")
        ):
            query = parse_qs(parsed.query or "")
            if parsed.path == "/api/auth/bootstrap-status":
                self._handle_auth_bootstrap_status()
                return
            if parsed.path == "/api/auth/me":
                self._handle_auth_me(query)
                return

            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return

            if parsed.path == "/api/payloads/list":
                self._handle_payloads_list()
                return
            if parsed.path == "/api/payloads/status":
                self._handle_payloads_status()
                return
            if parsed.path == "/api/payloads/tree":
                self._handle_payloads_tree()
                return
            if parsed.path == "/api/payloads/file":
                self._handle_payloads_file_get(query)
                return

            if parsed.path == "/api/loot/list":
                self._handle_loot_list(query)
                return
            if parsed.path == "/api/loot/download":
                self._handle_loot_download(query)
                return
            if parsed.path == "/api/loot/view":
                self._handle_loot_view(query)
                return
            if parsed.path == "/api/system/status":
                self._handle_system_status()
                return
            if parsed.path == "/api/settings/discord_webhook":
                self._handle_settings_webhook_get()
                return
            if parsed.path == "/api/settings/tailscale":
                self._handle_settings_tailscale_get()
                return

            _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return

        super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/auth/bootstrap":
            self._handle_auth_bootstrap()
            return
        if parsed.path == "/api/auth/login":
            self._handle_auth_login()
            return
        if parsed.path == "/api/auth/logout":
            self._handle_auth_logout()
            return
        if parsed.path == "/api/auth/ws-ticket":
            query = parse_qs(parsed.query or "")
            self._handle_auth_ws_ticket(query)
            return

        if parsed.path == "/api/system/restart-ui":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_system_restart_ui()
            return

        if parsed.path in ("/api/payloads/start", "/api/payloads/run"):
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_payloads_start()
            return
        if parsed.path == "/api/payloads/entry":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_payloads_entry_create()
            return
        _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_PUT(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/payloads/file":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_payloads_file_put()
            return
        if parsed.path == "/api/settings/discord_webhook":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_settings_webhook_put()
            return
        if parsed.path == "/api/settings/tailscale":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_settings_tailscale_put()
            return
        _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_PATCH(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/payloads/entry":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_payloads_entry_rename()
            return
        _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/payloads/entry":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_payloads_entry_delete(query)
            return
        _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def _handle_loot_list(self, query: dict) -> None:
        raw = unquote(query.get("path", [""])[0])
        target = _safe_loot_path(raw)
        if target is None or not target.exists():
            _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        if not target.is_dir():
            _json_response(self, {"error": "not a directory"}, status=HTTPStatus.BAD_REQUEST)
            return

        items = []
        try:
            for entry in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
                if entry.name.startswith("."):
                    continue
                stat = entry.stat()
                items.append({
                    "name": entry.name,
                    "type": "dir" if entry.is_dir() else "file",
                    "size": stat.st_size,
                    "mtime": int(stat.st_mtime),
                })
        except Exception as exc:
            _json_response(self, {"error": f"read error: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        parent = "" if target == LOOT_DIR else str(target.relative_to(LOOT_DIR).parent)
        current = "" if target == LOOT_DIR else str(target.relative_to(LOOT_DIR))
        _json_response(self, {
            "path": current,
            "parent": "" if parent == "." else parent,
            "items": items,
        })

    def _handle_payloads_list(self) -> None:
        categories: dict[str, list[dict]] = {}
        if not PAYLOADS_DIR.exists():
            _json_response(self, {"categories": []})
            return

        for root, dirs, files in os.walk(PAYLOADS_DIR):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
            rel_dir = os.path.relpath(root, PAYLOADS_DIR)
            category = rel_dir.split(os.sep)[0] if rel_dir != "." else "general"
            for name in files:
                if not name.endswith(".py") or name.startswith("_"):
                    continue
                rel_path = os.path.join(rel_dir, name) if rel_dir != "." else name
                categories.setdefault(category, []).append({
                    "name": os.path.splitext(name)[0],
                    "path": rel_path.replace("\\", "/"),
                })

        order = [
            "reconnaissance",
            "interception",
            "evil_portal",
            "exfiltration",
            "remote_access",
            "general",
            "examples",
            "games",
            "virtual_pager",
            "incident_response",
            "known_unstable",
            "prank",
        ]

        payload_categories = []
        for cat in order:
            items = categories.get(cat, [])
            if not items:
                continue
            payload_categories.append({
                "id": cat,
                "label": cat.replace("_", " ").title(),
                "items": sorted(items, key=lambda x: x["name"].lower()),
            })

        for cat in sorted(categories.keys()):
            if cat in order:
                continue
            payload_categories.append({
                "id": cat,
                "label": cat.replace("_", " ").title(),
                "items": sorted(categories[cat], key=lambda x: x["name"].lower()),
            })

        _json_response(self, {"categories": payload_categories})

    def _handle_payloads_start(self) -> None:
        body = _read_json(self)
        if body is None:
            _json_response(self, {"error": "invalid json"}, status=HTTPStatus.BAD_REQUEST)
            return

        rel_path = str(body.get("path", "")).strip().lstrip("/").replace("\\", "/")
        if not rel_path.endswith(".py"):
            _json_response(self, {"error": "invalid payload path"}, status=HTTPStatus.BAD_REQUEST)
            return

        target = (PAYLOADS_DIR / rel_path).resolve()
        try:
            payloads_root = PAYLOADS_DIR.resolve()
        except FileNotFoundError:
            payloads_root = PAYLOADS_DIR
        if payloads_root not in target.parents or not target.exists():
            _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return

        try:
            request_path = Path("/dev/shm/rj_payload_request.json")
            request_path.write_text(json.dumps({
                "action": "start",
                "path": rel_path,
            }))
        except Exception as exc:
            _json_response(self, {"error": f"request failed: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        _json_response(self, {"ok": True})

    def _handle_payloads_status(self) -> None:
        try:
            if not PAYLOAD_STATE_PATH.exists():
                _json_response(self, {"running": False, "path": None})
                return
            raw = PAYLOAD_STATE_PATH.read_text(encoding="utf-8")
            data = json.loads(raw) if raw else {}
            _json_response(self, {
                "running": bool(data.get("running")),
                "path": data.get("path"),
                "ts": data.get("ts"),
            })
        except Exception:
            _json_response(self, {"running": False, "path": None})

    def _payload_tree_node(self, base: Path, current: Path) -> dict:
        rel = "" if current == base else str(current.relative_to(base)).replace("\\", "/")
        node = {
            "name": current.name if current != base else base.name,
            "path": rel,
            "type": "dir" if current.is_dir() else "file",
        }
        if current.is_dir():
            children = []
            try:
                entries = sorted(current.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
            except Exception:
                entries = []
            for entry in entries:
                if entry.name.startswith(".") or entry.name == "__pycache__":
                    continue
                if entry.is_file() and entry.suffix.lower() in (".pyc",):
                    continue
                children.append(self._payload_tree_node(base, entry))
            node["children"] = children
        return node

    def _handle_payloads_tree(self) -> None:
        if not PAYLOADS_DIR.exists():
            _json_response(self, {"name": "payloads", "path": "", "type": "dir", "children": []})
            return
        try:
            _json_response(self, self._payload_tree_node(PAYLOADS_DIR, PAYLOADS_DIR))
        except Exception as exc:
            _json_response(self, {"error": f"read error: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_payloads_file_get(self, query: dict) -> None:
        raw = unquote(query.get("path", [""])[0])
        target = _safe_payload_path(raw)
        if target is None or not target.exists() or not target.is_file():
            _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        if target.stat().st_size > PAYLOAD_MAX_BYTES:
            _json_response(self, {"error": "file too large"}, status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return
        if not _is_text_file(target):
            _json_response(self, {"error": "not text"}, status=HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
            return
        try:
            content = target.read_text(encoding="utf-8", errors="replace")
            rel = str(target.relative_to(PAYLOADS_DIR)).replace("\\", "/")
            st = target.stat()
            _json_response(self, {
                "path": rel,
                "content": content,
                "size": st.st_size,
                "mtime": int(st.st_mtime),
            })
        except Exception as exc:
            _json_response(self, {"error": f"read error: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_payloads_file_put(self) -> None:
        body = _read_json(self)
        if body is None:
            _json_response(self, {"error": "invalid json"}, status=HTTPStatus.BAD_REQUEST)
            return

        rel_path = str(body.get("path", "")).strip().lstrip("/").replace("\\", "/")
        content = body.get("content", "")
        if not rel_path:
            _json_response(self, {"error": "missing path"}, status=HTTPStatus.BAD_REQUEST)
            return
        if not isinstance(content, str):
            _json_response(self, {"error": "content must be string"}, status=HTTPStatus.BAD_REQUEST)
            return
        if len(content.encode("utf-8", "ignore")) > PAYLOAD_MAX_BYTES:
            _json_response(self, {"error": "content too large"}, status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return

        target = _safe_payload_path(rel_path)
        if target is None:
            _json_response(self, {"error": "invalid path"}, status=HTTPStatus.BAD_REQUEST)
            return
        if target.exists() and not target.is_file():
            _json_response(self, {"error": "not a file"}, status=HTTPStatus.BAD_REQUEST)
            return
        if not target.parent.exists():
            _json_response(self, {"error": "parent folder missing"}, status=HTTPStatus.CONFLICT)
            return
        try:
            target.write_text(content, encoding="utf-8")
            rel = str(target.relative_to(PAYLOADS_DIR)).replace("\\", "/")
            st = target.stat()
            _json_response(self, {"ok": True, "path": rel, "size": st.st_size, "mtime": int(st.st_mtime)})
        except Exception as exc:
            _json_response(self, {"error": f"write error: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_payloads_entry_create(self) -> None:
        body = _read_json(self)
        if body is None:
            _json_response(self, {"error": "invalid json"}, status=HTTPStatus.BAD_REQUEST)
            return

        rel_path = str(body.get("path", "")).strip().lstrip("/").replace("\\", "/")
        entry_type = str(body.get("type", "")).strip().lower()
        content = body.get("content", "")
        if not rel_path or entry_type not in ("file", "dir"):
            _json_response(self, {"error": "invalid request"}, status=HTTPStatus.BAD_REQUEST)
            return

        target = _safe_payload_path(rel_path)
        if target is None:
            _json_response(self, {"error": "invalid path"}, status=HTTPStatus.BAD_REQUEST)
            return
        if target.exists():
            _json_response(self, {"error": "already exists"}, status=HTTPStatus.CONFLICT)
            return

        try:
            if entry_type == "dir":
                target.mkdir(parents=True, exist_ok=False)
                rel = str(target.relative_to(PAYLOADS_DIR)).replace("\\", "/")
                _json_response(self, {"ok": True, "type": "dir", "path": rel})
                return

            if not isinstance(content, str):
                _json_response(self, {"error": "content must be string"}, status=HTTPStatus.BAD_REQUEST)
                return
            if len(content.encode("utf-8", "ignore")) > PAYLOAD_MAX_BYTES:
                _json_response(self, {"error": "content too large"}, status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                return
            if not target.parent.exists():
                _json_response(self, {"error": "parent folder missing"}, status=HTTPStatus.CONFLICT)
                return
            target.write_text(content, encoding="utf-8")
            rel = str(target.relative_to(PAYLOADS_DIR)).replace("\\", "/")
            st = target.stat()
            _json_response(self, {"ok": True, "type": "file", "path": rel, "size": st.st_size, "mtime": int(st.st_mtime)})
        except Exception as exc:
            _json_response(self, {"error": f"create error: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_payloads_entry_rename(self) -> None:
        body = _read_json(self)
        if body is None:
            _json_response(self, {"error": "invalid json"}, status=HTTPStatus.BAD_REQUEST)
            return

        old_rel = str(body.get("old_path", "")).strip().lstrip("/").replace("\\", "/")
        new_rel = str(body.get("new_path", "")).strip().lstrip("/").replace("\\", "/")
        if not old_rel or not new_rel:
            _json_response(self, {"error": "missing path"}, status=HTTPStatus.BAD_REQUEST)
            return

        old_target = _safe_payload_path(old_rel)
        new_target = _safe_payload_path(new_rel)
        if old_target is None or new_target is None:
            _json_response(self, {"error": "invalid path"}, status=HTTPStatus.BAD_REQUEST)
            return
        if not old_target.exists():
            _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        if new_target.exists():
            _json_response(self, {"error": "destination exists"}, status=HTTPStatus.CONFLICT)
            return
        if not new_target.parent.exists():
            _json_response(self, {"error": "parent folder missing"}, status=HTTPStatus.CONFLICT)
            return

        try:
            old_target.rename(new_target)
            _json_response(self, {
                "ok": True,
                "old_path": str(old_target.relative_to(PAYLOADS_DIR)).replace("\\", "/"),
                "new_path": str(new_target.relative_to(PAYLOADS_DIR)).replace("\\", "/"),
            })
        except Exception as exc:
            _json_response(self, {"error": f"rename error: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_payloads_entry_delete(self, query: dict) -> None:
        raw = unquote(query.get("path", [""])[0])
        target = _safe_payload_path(raw)
        if target is None or not target.exists():
            _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return

        try:
            if target.is_dir():
                try:
                    next(target.iterdir())
                    _json_response(self, {"error": "directory not empty"}, status=HTTPStatus.CONFLICT)
                    return
                except StopIteration:
                    pass
                target.rmdir()
                rel = "" if target == PAYLOADS_DIR else str(target.relative_to(PAYLOADS_DIR)).replace("\\", "/")
                _json_response(self, {"ok": True, "type": "dir", "path": rel})
                return

            target.unlink()
            rel = str(target.relative_to(PAYLOADS_DIR)).replace("\\", "/")
            _json_response(self, {"ok": True, "type": "file", "path": rel})
        except Exception as exc:
            _json_response(self, {"error": f"delete error: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_loot_download(self, query: dict) -> None:
        raw = unquote(query.get("path", [""])[0])
        target = _safe_loot_path(raw)
        if target is None or not target.exists() or not target.is_file():
            _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return

        ctype, _ = mimetypes.guess_type(str(target))
        ctype = ctype or "application/octet-stream"
        try:
            size = target.stat().st_size
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(size))
            self.send_header("Content-Disposition", f'attachment; filename="{target.name}"')
            self.end_headers()
            with target.open("rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except Exception:
            _json_response(self, {"error": "read error"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_loot_view(self, query: dict) -> None:
        raw = unquote(query.get("path", [""])[0])
        target = _safe_loot_path(raw)
        if target is None or not target.exists() or not target.is_file():
            _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        if not _is_text_file(target):
            _json_response(self, {"error": "not text"}, status=HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
            return

        try:
            size = target.stat().st_size
            read_size = min(size, PREVIEW_MAX_BYTES)
            with target.open("rb") as f:
                raw_data = f.read(read_size)
            text = raw_data.decode("utf-8", errors="replace")
            _json_response(self, {
                "name": target.name,
                "path": raw,
                "content": text,
                "truncated": size > PREVIEW_MAX_BYTES,
                "size": size,
                "mtime": int(target.stat().st_mtime),
            })
        except Exception:
            _json_response(self, {"error": "read error"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_system_status(self) -> None:
        try:
            cpu = _read_cpu_percent()
            mem_used, mem_total = _read_meminfo()
            du = shutil.disk_usage("/")
            temp_c = _read_temp_c()
            uptime_s = _read_uptime_seconds()
            ifaces = _read_ipv4_interfaces()
            load1, load5, load15 = os.getloadavg()
            payload_running = False
            payload_path = None
            try:
                if PAYLOAD_STATE_PATH.exists():
                    raw = PAYLOAD_STATE_PATH.read_text(encoding="utf-8")
                    pdata = json.loads(raw) if raw else {}
                    payload_running = bool(pdata.get("running"))
                    payload_path = pdata.get("path")
            except Exception:
                pass

            _json_response(self, {
                "cpu_percent": round(cpu, 1),
                "mem_used": mem_used,
                "mem_total": mem_total,
                "disk_used": int(du.used),
                "disk_total": int(du.total),
                "temp_c": (round(temp_c, 1) if temp_c is not None else None),
                "uptime_s": uptime_s,
                "load": [round(load1, 2), round(load5, 2), round(load15, 2)],
                "interfaces": ifaces,
                "payload_running": payload_running,
                "payload_path": payload_path,
            })
        except Exception as exc:
            _json_response(self, {"error": f"status error: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_system_restart_ui(self) -> None:
        try:
            subprocess.run(
                ["systemctl", "restart", "raspyjack.service"],
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
            )
            _json_response(self, {"ok": True})
        except subprocess.TimeoutExpired:
            _json_response(self, {"error": "restart timed out"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
        except subprocess.CalledProcessError as exc:
            err = (exc.stderr or exc.stdout or "").strip() or "restart failed"
            _json_response(self, {"error": err}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
        except Exception as exc:
            _json_response(self, {"error": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _client_ip(self) -> str:
        try:
            return str(self.client_address[0])
        except Exception:
            return "unknown"

    def _handle_auth_bootstrap_status(self) -> None:
        _json_response(self, {"initialized": _auth_initialized()})

    def _handle_auth_bootstrap(self) -> None:
        if _auth_initialized():
            _json_response(self, {"error": "already initialized"}, status=HTTPStatus.CONFLICT)
            return
        body = _read_json(self)
        if body is None:
            _json_response(self, {"error": "invalid json"}, status=HTTPStatus.BAD_REQUEST)
            return
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", ""))
        ok, msg = _write_auth_config(username, password)
        if not ok:
            _json_response(self, {"error": msg}, status=HTTPStatus.BAD_REQUEST)
            return
        _json_response(
            self,
            {"ok": True, "initialized": True, "user": username},
            extra_headers=[_session_cookie_header(username, secure=_request_is_https(self))],
        )

    def _handle_auth_login(self) -> None:
        body = _read_json(self)
        if body is None:
            _json_response(self, {"error": "invalid json"}, status=HTTPStatus.BAD_REQUEST)
            return
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", ""))
        now = time.time()
        ip = self._client_ip()
        failures = [ts for ts in _LOGIN_FAILS.get(ip, []) if now - ts < 600]
        _LOGIN_FAILS[ip] = failures
        if len(failures) >= 6:
            _json_response(self, {"error": "too many attempts"}, status=HTTPStatus.TOO_MANY_REQUESTS)
            return

        cfg = _read_auth_config()
        if not cfg:
            _json_response(self, {"error": "auth not initialized"}, status=HTTPStatus.PRECONDITION_FAILED)
            return
        if username != str(cfg.get("username", "")) or not _verify_password(password, str(cfg.get("password_hash", ""))):
            failures.append(now)
            _LOGIN_FAILS[ip] = failures
            _json_response(self, {"error": "invalid credentials"}, status=HTTPStatus.UNAUTHORIZED)
            return

        _LOGIN_FAILS[ip] = []
        _json_response(
            self,
            {"ok": True, "user": username},
            extra_headers=[_session_cookie_header(username, secure=_request_is_https(self))],
        )

    def _handle_auth_logout(self) -> None:
        _json_response(self, {"ok": True}, extra_headers=[_clear_session_cookie_header(secure=_request_is_https(self))])

    def _handle_auth_me(self, query: dict) -> None:
        ctx = _auth_context(self, query)
        if ctx is None or ctx.get("method") == "bootstrap":
            _json_response(self, {"authenticated": False}, status=HTTPStatus.UNAUTHORIZED)
            return
        _json_response(self, {
            "authenticated": True,
            "method": ctx.get("method"),
            "user": ctx.get("user"),
            "initialized": _auth_initialized(),
        })

    def _handle_auth_ws_ticket(self, query: dict) -> None:
        ctx = _auth_context(self, query)
        if ctx is None or ctx.get("method") == "bootstrap":
            _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
            return
        now = int(time.time())
        claims = {
            "typ": "ws_ticket",
            "usr": str(ctx.get("user", "user")),
            "iat": now,
            "exp": now + int(WS_TICKET_TTL_SECONDS),
        }
        _json_response(self, {
            "ok": True,
            "ticket": _issue_signed_token(claims),
            "expires_in": int(WS_TICKET_TTL_SECONDS),
        })

    def _handle_settings_webhook_get(self) -> None:
        webhook_url = _read_discord_webhook_url()
        _json_response(self, {
            "configured": bool(webhook_url),
            "url": webhook_url,
        })

    def _handle_settings_webhook_put(self) -> None:
        body = _read_json(self)
        if body is None:
            _json_response(self, {"error": "invalid json"}, status=HTTPStatus.BAD_REQUEST)
            return
        url = str(body.get("url", "")).strip()
        ok, status = _write_discord_webhook_url(url)
        if not ok:
            _json_response(self, {"error": status}, status=HTTPStatus.BAD_REQUEST)
            return
        _json_response(self, {
            "ok": True,
            "status": status,
            "configured": bool(url),
            "url": url if url else "",
        })

    def _handle_settings_tailscale_get(self) -> None:
        status = _tailscale_read_status()
        installed = _tailscale_installed()
        has_key = TAILSCALE_KEY_PATH.exists()
        ts = _tailscale_status() if installed else {"backend_state": None, "ip": None}
        _json_response(self, {
            "installed": installed,
            "has_key": has_key,
            "installing": bool(status.get("installing")),
            "ok": status.get("ok"),
            "error": status.get("error"),
            "backend_state": ts.get("backend_state"),
            "ip": ts.get("ip"),
        })

    def _handle_settings_tailscale_put(self) -> None:
        body = _read_json(self)
        if body is None:
            _json_response(self, {"error": "invalid json"}, status=HTTPStatus.BAD_REQUEST)
            return
        if _tailscale_installed():
            _json_response(self, {"error": "tailscale already installed"}, status=HTTPStatus.CONFLICT)
            return
        raw_key = str(body.get("auth_key", "")).strip()
        if not raw_key:
            _json_response(self, {"error": "auth key required"}, status=HTTPStatus.BAD_REQUEST)
            return
        if not raw_key.startswith("tskey-"):
            _json_response(self, {"error": "auth key must start with 'tskey-'"}, status=HTTPStatus.BAD_REQUEST)
            return
        ok, msg = _tailscale_write_key(raw_key)
        if not ok:
            _json_response(self, {"error": msg}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        threading.Thread(target=_tailscale_run_install_and_up, daemon=True).start()
        _json_response(self, {"ok": True})


def main() -> None:
    if TOKEN:
        print("[WebUI] Token auth enabled")
    else:
        print("[WebUI] WARNING: Token auth disabled (set RJ_WS_TOKEN or token file)")

    # If a specific host was set via env var, honour it as-is (single bind)
    if HOST != "0.0.0.0":
        server = ThreadingHTTPServer((HOST, PORT), RaspyJackHandler)
        print(f"[WebUI] Serving on http://{HOST}:{PORT}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return

    # Default: bind only to eth0 + wlan0 (+ localhost).  wlan1+ stay untouched.
    bind_addrs = _get_webui_bind_addrs()
    servers: list[ThreadingHTTPServer] = []

    for addr, iface in bind_addrs:
        try:
            srv = ThreadingHTTPServer((addr, PORT), RaspyJackHandler)
            servers.append(srv)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            print(f"[WebUI] Serving on http://{addr}:{PORT} ({iface})")
        except Exception as exc:
            print(f"[WebUI] Could not bind {addr}:{PORT} ({iface}): {exc}")

    if not servers:
        # Last resort — fall back to all interfaces so the WebUI is not dead
        print("[WebUI] WARNING: No WebUI interfaces available, falling back to 0.0.0.0")
        srv = ThreadingHTTPServer(("0.0.0.0", PORT), RaspyJackHandler)
        print(f"[WebUI] Serving on http://0.0.0.0:{PORT}")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            srv.server_close()
        return

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        for srv in servers:
            srv.server_close()


if __name__ == "__main__":
    main()
