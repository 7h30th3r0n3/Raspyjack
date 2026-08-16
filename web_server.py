#!/usr/bin/env python3
"""
RaspyJack WebUI HTTP server
---------------------------
Serves the static WebUI and exposes a small, read-only API to browse loot/.

Routes:
  /                  -> static WebUI (web/)
  /api/loot/list      -> JSON directory listing (read-only)
  /api/loot/download  -> file download / media stream, HTTP Range (read-only)
  /api/loot/archive   -> zip of a loot folder (read-only)
  /api/loot/view      -> text preview (read-only)
    /api/loot/nmap      -> normalized Nmap XML (read-only)
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
import socket
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse, unquote

from nmap_parser import parse_nmap_xml_file

ROOT_DIR = Path(__file__).resolve().parent
WEB_DIR = ROOT_DIR / "web"
LOOT_DIR = ROOT_DIR / "loot"
PAYLOADS_DIR = ROOT_DIR / "payloads"
PAYLOAD_STATE_PATH = Path("/dev/shm/rj_payload_state.json")
DISCORD_WEBHOOK_PATH = ROOT_DIR / "discord_webhook.txt"
WIGLE_CREDENTIALS_PATH = ROOT_DIR / ".wigle_credentials.json"
TOKEN_FILE = Path(os.environ.get("RJ_WS_TOKEN_FILE", str(ROOT_DIR / ".webui_token")))
AUTH_FILE = Path(os.environ.get("RJ_WEB_AUTH_FILE", "/root/Raspyjack/.webui_auth.json"))
AUTH_SECRET_FILE = Path(os.environ.get("RJ_WEB_AUTH_SECRET_FILE", "/root/Raspyjack/.webui_session_secret"))
SESSION_COOKIE_NAME = "rj_session"
SESSION_TTL_SECONDS = int(os.environ.get("RJ_WEB_SESSION_TTL", str(8 * 60 * 60)))
WS_TICKET_TTL_SECONDS = int(os.environ.get("RJ_WEB_WS_TICKET_TTL", "120"))
TAILSCALE_KEY_PATH = ROOT_DIR / ".tailscale_auth_key"
TAILSCALE_STATUS_PATH = Path("/dev/shm/rj_tailscale_status.json")


# ---------------------------------------------------------------------------
# ISM Manager — runs rtl_433 as a background subprocess
# ---------------------------------------------------------------------------

_ISM_BANDS = [
    {"name": "433 MHz", "freq": 433920000, "desc": "EU ISM / Remotes"},
    {"name": "315 MHz", "freq": 315000000, "desc": "US Remotes / TPMS"},
    {"name": "868 MHz", "freq": 868000000, "desc": "EU ISM / LoRa"},
    {"name": "345 MHz", "freq": 345000000, "desc": "Honeywell Security"},
    {"name": "915 MHz", "freq": 915000000, "desc": "US ISM"},
]
_ISM_LIVE = Path("/dev/shm/rj_ism_live.json")
_ISM_HISTORY_MAX = 60
_ISM_HISTORY_METRICS = (
    "temperature_C", "humidity", "pressure_kPa", "wind_avg_km_h",
    "rain_mm", "pressure_PSI", "temperature_F", "uv", "light_lux",
    "power_W", "energy_kWh", "moisture",
)

_ISM_CAT_KEYWORDS = {
    "remote": ["remote", "came", "nice", "gate", "garage", "button", "keyfob"],
    "weather": ["weather", "temp", "humid", "rain", "wind", "baro", "thermo"],
    "sensor": ["sensor", "motion", "door", "window", "alarm", "smoke", "pir"],
    "tpms": ["tpms", "tire", "pressure"],
    "car": ["car", "auto", "key", "fob", "vehicle"],
}


def _ism_empty_state():
    return {"ts": 0, "running": False, "total_signals": 0,
            "unique_devices": 0, "devices": [], "recent": [],
            "band": "", "command": "", "bands": _ISM_BANDS,
            "proto_counts": {}}


def _ism_categorize(model):
    text = model.lower()
    for cat, kws in _ISM_CAT_KEYWORDS.items():
        for kw in kws:
            if kw in text:
                return cat
    return "other"


class _ISMManager:
    def __init__(self):
        self._proc = None
        self._thread = None
        self._writer_thread = None
        self._lock = threading.Lock()
        self._signals = []
        self._devices = {}
        self._proto_counts = {}
        self._band_idx = 0
        self._start_time = 0
        self._running = False
        self._cmd = ""

    def start(self, band_idx=0):
        self.stop()
        if band_idx < 0 or band_idx >= len(_ISM_BANDS):
            band_idx = 0
        self._band_idx = band_idx
        freq = _ISM_BANDS[band_idx]["freq"]
        self._signals = []
        self._devices = {}
        self._proto_counts = {}
        self._start_time = time.time()
        self._running = True

        cmd = [
            "rtl_433", "-f", str(freq), "-g", "20",
            "-s", "1024000",
            "-F", "json",
            "-M", "time:unix", "-M", "protocol", "-M", "level",
            "-X", "n=CAME-12,m=OOK_PWM,s=320,l=640,r=15000,g=800,t=0,y=1650,bits>=12",
            "-X", "n=Princeton,m=OOK_PWM,s=320,l=640,r=15000,g=800,t=0,y=1650,bits>=24",
            "-X", "n=NiceFLO,m=OOK_PWM,s=700,l=1400,r=15000,g=1600,t=0,y=0,bits>=12",
        ]
        self._cmd = " ".join(cmd)

        try:
            subprocess.run(["pkill", "-9", "rtl_433"], capture_output=True)
            time.sleep(0.3)
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1,
            )
            self._thread = threading.Thread(target=self._reader, daemon=True)
            self._thread.start()
            self._writer_thread = threading.Thread(target=self._writer, daemon=True)
            self._writer_thread.start()
        except Exception:
            self._running = False

    def stop(self):
        self._running = False
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=3)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None
        subprocess.run(["pkill", "-9", "rtl_433"], capture_output=True)
        try:
            _ISM_LIVE.unlink(missing_ok=True)
        except Exception:
            pass

    def _reader(self):
        last_sig = {}
        try:
            for line in self._proc.stdout:
                if not self._running:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                model = data.get("model", "Unknown")
                sig_key = f"{model}_{data.get('id', '')}_{data.get('channel', '')}"
                sig_vals = {k: v for k, v in data.items()
                            if k not in ("time", "rssi", "snr", "noise", "mic")}
                sig_hash = str(sig_vals)
                now = time.time()
                if sig_key in last_sig:
                    lh, lt = last_sig[sig_key]
                    if sig_hash == lh and (now - lt) < 2.0:
                        continue
                last_sig[sig_key] = (sig_hash, now)

                from datetime import datetime as _dt
                data["_time_local"] = _dt.now().strftime("%H:%M:%S")
                cat = _ism_categorize(model)
                data["_category"] = cat

                with self._lock:
                    self._signals.append(data)
                    if len(self._signals) > 500:
                        self._signals.pop(0)
                    self._proto_counts[model] = self._proto_counts.get(model, 0) + 1
                    self._update_device(data, now)
        except Exception:
            pass

    def _update_device(self, data, now):
        model = data.get("model", "Unknown")
        dev_id = data.get("id", "")
        channel = data.get("channel", "")
        key = f"{model}_{dev_id}_{channel}"
        entry = self._devices.get(key, {"first_seen": now, "count": 0, "history": {}})
        rssi = data.get("rssi", data.get("snr", None))
        entry.update({
            "model": model, "id": dev_id, "channel": channel,
            "category": data.get("_category", "other"),
            "last_seen": now, "count": entry["count"] + 1,
            "rssi": rssi,
        })
        for k in ("temperature_C", "humidity", "battery_ok", "pressure_kPa",
                   "wind_avg_km_h", "rain_mm", "code", "button", "status",
                   "pressure_PSI", "temperature_F", "uv", "light_lux",
                   "moisture", "depth_cm", "power_W", "energy_kWh"):
            if k in data:
                entry[k] = data[k]
        hist = entry.get("history", {})
        for k in _ISM_HISTORY_METRICS:
            val = data.get(k) if k != "rssi" else rssi
            if val is not None and isinstance(val, (int, float)):
                pts = hist.get(k, [])
                pts.append([round(now, 1), round(val, 2)])
                if len(pts) > _ISM_HISTORY_MAX:
                    pts = pts[-_ISM_HISTORY_MAX:]
                hist[k] = pts
        entry["history"] = hist
        self._devices[key] = entry

    def _writer(self):
        while self._running:
            try:
                with self._lock:
                    recent = list(self._signals[-50:])
                    dev_list = sorted(self._devices.values(),
                                      key=lambda d: d.get("last_seen", 0), reverse=True)
                payload = {
                    "ts": time.time(),
                    "running": self._running,
                    "total_signals": len(self._signals),
                    "unique_devices": len(self._devices),
                    "uptime": int(time.time() - self._start_time),
                    "proto_counts": dict(self._proto_counts),
                    "devices": dev_list[:100],
                    "recent": recent,
                    "band": _ISM_BANDS[self._band_idx]["name"],
                    "freq": _ISM_BANDS[self._band_idx]["freq"],
                    "command": self._cmd,
                    "bands": _ISM_BANDS,
                }
                tmp = str(_ISM_LIVE) + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(payload, f)
                os.replace(tmp, str(_ISM_LIVE))
            except Exception:
                pass
            time.sleep(1.5)


_ism_manager = _ISMManager()


# ---------------------------------------------------------------------------
# Generic payload process manager — direct subprocess, no LCD payload dance
# ---------------------------------------------------------------------------

class _PayloadRunner:
    """Manages a payload Python script as a direct subprocess."""

    def __init__(self, name: str, script_path: str, live_path: str, kill_cmd: str | None = None):
        self._name = name
        self._script = script_path
        self._live = Path(live_path)
        self._kill_cmd = kill_cmd
        self._proc = None
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self, extra_args: list[str] | None = None):
        self.stop()
        cmd = [sys.executable, self._script, "--headless"]
        if extra_args:
            cmd.extend(extra_args)
        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception:
            self._proc = None

    def stop(self):
        with self._lock:
            if self._proc:
                try:
                    self._proc.terminate()
                    self._proc.wait(timeout=5)
                except Exception:
                    try:
                        self._proc.kill()
                    except Exception:
                        pass
                self._proc = None
            if self._kill_cmd:
                subprocess.run(["pkill", "-9", "-f", self._kill_cmd],
                               capture_output=True)
            if str(self._live):
                try:
                    self._live.unlink(missing_ok=True)
                except Exception:
                    pass


def _kill_payload(script_name: str) -> None:
    subprocess.run(["pkill", "-f", script_name], capture_output=True)
    time.sleep(0.3)
    subprocess.run(["pkill", "-9", "-f", script_name], capture_output=True)


_honeypot_runner = _PayloadRunner(
    "Honeypot", str(PAYLOADS_DIR / "reconnaissance" / "honeypot_siem.py"),
    "/dev/shm/rj_honeypot_live.json", "honeypot_siem.py",
)


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
WEBUI_INTERFACES = ["eth0", "eth1", "wlan0", "tailscale0"]


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


def _read_wigle_credentials() -> dict[str, str]:
    try:
        if not WIGLE_CREDENTIALS_PATH.exists():
            return {"api_name": "", "api_token": ""}
        raw = WIGLE_CREDENTIALS_PATH.read_text(encoding="utf-8")
        data = json.loads(raw) if raw else {}
        if not isinstance(data, dict):
            return {"api_name": "", "api_token": ""}
        return {
            "api_name": str(data.get("api_name") or "").strip(),
            "api_token": str(data.get("api_token") or "").strip(),
        }
    except Exception:
        return {"api_name": "", "api_token": ""}


def _write_wigle_credentials(api_name: str, api_token: str) -> tuple[bool, str]:
    clean_name = str(api_name or "").strip()
    clean_token = str(api_token or "").strip()
    try:
        if not clean_name and not clean_token:
            if WIGLE_CREDENTIALS_PATH.exists():
                WIGLE_CREDENTIALS_PATH.unlink()
            return True, "cleared"
        if not clean_name or not clean_token:
            return False, "api name and api token are required"
        WIGLE_CREDENTIALS_PATH.write_text(
            json.dumps({"api_name": clean_name, "api_token": clean_token}) + "\n",
            encoding="utf-8",
        )
        try:
            os.chmod(WIGLE_CREDENTIALS_PATH, 0o600)
        except Exception:
            pass
        return True, "saved"
    except Exception as exc:
        return False, f"write error: {exc}"


def _mask_secret(value: str, keep_start: int = 3, keep_end: int = 2) -> str:
    secret = str(value or "")
    if not secret:
        return ""
    if len(secret) <= (keep_start + keep_end):
        return "*" * len(secret)
    return secret[:keep_start] + ("*" * (len(secret) - keep_start - keep_end)) + secret[-keep_end:]


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


def _regenerate_caddyfile_and_reload() -> None:
    """
    Regenerate /etc/caddy/Caddyfile with current IPs (eth0, wlan0, tailscale0)
    and reload Caddy. Same logic as install_raspyjack.sh so that installing
    Tailscale from the WebUI updates HTTPS to listen on the Tailscale IP
    without re-running the install script.
    """
    hosts: list[str] = []
    for iface in ("eth0", "wlan0", "tailscale0"):
        try:
            res = subprocess.run(
                ["ip", "-4", "-o", "addr", "show", iface],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode != 0 or not res.stdout:
                continue
            # First line: "2: eth0    inet 192.168.1.100/24 ..." -> take 4th field, strip /suffix
            line = res.stdout.strip().split("\n")[0]
            parts = line.split()
            if len(parts) >= 4:
                addr = parts[3].split("/")[0].strip()
                if addr and addr not in hosts:
                    hosts.append(addr)
        except Exception:
            continue
    hosts.append("localhost")

    if not hosts:
        return

    caddy_site_addrs = ", ".join(hosts)
    caddyfile_content = f"""{{
    # RaspyJack self-signed internal CA (local trust only)
    auto_https disable_redirects
}}

{caddy_site_addrs} {{
    tls internal

    @ws path /ws*
    reverse_proxy @ws 127.0.0.1:8765 {{
        header_up X-Forwarded-Proto {{scheme}}
        header_up X-Forwarded-Host {{host}}
    }}

    reverse_proxy 127.0.0.1:8080 {{
        header_up X-Forwarded-Proto {{scheme}}
        header_up X-Forwarded-Host {{host}}
    }}
}}
"""

    tmp = Path("/dev/shm/rj_caddyfile_tmp")
    try:
        tmp.write_text(caddyfile_content, encoding="utf-8")
        subprocess.run(
            ["sudo", "cp", str(tmp), "/etc/caddy/Caddyfile"],
            check=True,
            timeout=10,
        )
        subprocess.run(
            ["sudo", "systemctl", "reload", "caddy"],
            check=True,
            timeout=15,
        )
    except Exception:
        pass
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except Exception:
            pass


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

    # Regenerate Caddyfile with tailscale0 IP and reload Caddy so HTTPS works over Tailscale.
    _regenerate_caddyfile_and_reload()

    _tailscale_write_status({
        "installing": False,
        "ok": True,
        "error": None,
    })


def _tailscale_run_reauth() -> None:
    """
    Re-authenticate an existing Tailscale install using the stored auth key.
    Does not re-run the install script, only `tailscale up --reset --auth-key=... --ssh`.
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

    try:
        auth_arg = f"--auth-key=file:{TAILSCALE_KEY_PATH}"
        up_res = subprocess.run(
            ["tailscale", "up", "--reset", auth_arg, "--ssh"],
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

    _regenerate_caddyfile_and_reload()

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

        if parsed.path.startswith("/tiles/"):
            self._handle_tile(parsed.path)
            return

        if (
            parsed.path.startswith("/api/loot/")
            or parsed.path.startswith("/api/payloads/")
            or parsed.path.startswith("/api/system/")
            or parsed.path.startswith("/api/settings/")
            or parsed.path.startswith("/api/auth/")
            or parsed.path.startswith("/api/wardriving/")
            or parsed.path.startswith("/api/adsb/")
            or parsed.path.startswith("/api/sdr/")
            or parsed.path.startswith("/api/ism/")
            or parsed.path.startswith("/api/gnss/")
            or parsed.path.startswith("/api/noaa/")
            or parsed.path.startswith("/api/aprs/")
            or parsed.path.startswith("/api/honeypot/")
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
            if parsed.path == "/api/loot/archive":
                self._handle_loot_archive(query)
                return
            if parsed.path == "/api/loot/view":
                self._handle_loot_view(query)
                return
            if parsed.path == "/api/loot/nmap":
                self._handle_loot_nmap(query)
                return
            if parsed.path == "/api/wardriving/sessions":
                self._handle_wardriving_sessions()
                return
            if parsed.path == "/api/wardriving/live":
                self._handle_wardriving_live()
                return
            if parsed.path == "/api/wardriving/session":
                self._handle_wardriving_session(query)
                return

            if parsed.path == "/api/adsb/live":
                self._handle_adsb_live()
                return
            if parsed.path == "/api/adsb/sessions":
                self._handle_adsb_sessions()
                return
            if parsed.path == "/api/adsb/session":
                self._handle_adsb_session(query)
                return

            if parsed.path == "/api/sdr/live":
                self._handle_sdr_live()
                return
            if parsed.path == "/api/sdr/recordings":
                self._handle_sdr_recordings()
                return
            if parsed.path == "/api/sdr/audio":
                self._handle_sdr_audio()
                return

            if parsed.path == "/api/ism/live":
                self._handle_ism_live()
                return

            if parsed.path == "/api/gnss/live":
                self._handle_gnss_live()
                return

            if parsed.path == "/api/aprs/live":
                self._handle_aprs_live()
                return

            if parsed.path == "/api/noaa/live":
                self._handle_noaa_live()
                return
            if parsed.path == "/api/noaa/image":
                self._handle_noaa_image(query)
                return
            if parsed.path == "/api/noaa/gallery":
                self._handle_noaa_gallery()
                return

            if parsed.path == "/api/honeypot/live":
                self._handle_honeypot_live()
                return
            if parsed.path == "/api/honeypot/sessions":
                self._handle_honeypot_sessions()
                return
            if parsed.path == "/api/honeypot/session":
                self._handle_honeypot_session(query)
                return

            if parsed.path == "/api/system/status":
                self._handle_system_status()
                return
            if parsed.path == "/api/settings/discord_webhook":
                if not _auth_ok(self, query):
                    _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                    return
                self._handle_settings_webhook_get()
                return
            if parsed.path == "/api/settings/wigle":
                if not _auth_ok(self, query):
                    _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                    return
                self._handle_settings_wigle_get()
                return
            if parsed.path == "/api/settings/tailscale":
                if not _auth_ok(self, query):
                    _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                    return
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

        if parsed.path == "/api/wardriving/start":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_wardriving_start()
            return
        if parsed.path == "/api/wardriving/stop":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_wardriving_stop()
            return
        if parsed.path == "/api/adsb/start":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_adsb_start()
            return
        if parsed.path == "/api/adsb/stop":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_adsb_stop()
            return
        if parsed.path == "/api/sdr/start":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_sdr_start()
            return
        if parsed.path == "/api/sdr/stop":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_sdr_stop()
            return
        if parsed.path == "/api/sdr/control":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_sdr_control()
            return
        if parsed.path == "/api/ism/start":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_ism_start()
            return
        if parsed.path == "/api/ism/stop":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_ism_stop()
            return
        if parsed.path == "/api/ism/control":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_ism_control()
            return
        if parsed.path == "/api/gnss/start":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            try:
                request_path = Path("/dev/shm/rj_payload_request.json")
                request_path.write_text(json.dumps({
                    "action": "start",
                    "path": "hardware/gnss_skyplot.py",
                    "args": ["--auto"],
                }))
                _json_response(self, {"ok": True, "status": "starting"})
            except Exception as exc:
                _json_response(self, {"error": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        if parsed.path == "/api/gnss/stop":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            _kill_payload("gnss_skyplot.py")
            try:
                Path("/dev/shm/rj_gnss_live.json").unlink(missing_ok=True)
            except Exception:
                pass
            _json_response(self, {"ok": True, "status": "stopped"})
            return
        if parsed.path == "/api/aprs/start":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            try:
                request_path = Path("/dev/shm/rj_payload_request.json")
                request_path.write_text(json.dumps({
                    "action": "start",
                    "path": "sdr/sdr_aprs.py",
                    "args": ["--auto"],
                }))
                _json_response(self, {"ok": True, "status": "starting"})
            except Exception as exc:
                _json_response(self, {"error": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        if parsed.path == "/api/aprs/stop":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            _kill_payload("sdr_aprs.py")
            subprocess.run(["pkill", "-9", "direwolf"], capture_output=True)
            subprocess.run(["pkill", "-9", "rtl_fm"], capture_output=True)
            try:
                Path("/dev/shm/rj_aprs_live.json").unlink(missing_ok=True)
            except Exception:
                pass
            _json_response(self, {"ok": True, "status": "stopped"})
            return
        if parsed.path == "/api/noaa/start":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            try:
                request_path = Path("/dev/shm/rj_payload_request.json")
                request_path.write_text(json.dumps({
                    "action": "start",
                    "path": "sdr/sdr_noaa.py",
                    "args": ["--auto"],
                }))
                _json_response(self, {"ok": True, "status": "starting"})
            except Exception as exc:
                _json_response(self, {"error": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        if parsed.path == "/api/noaa/stop":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            _kill_payload("sdr_noaa.py")
            subprocess.run(["pkill", "-9", "rtl_fm"], capture_output=True)
            try:
                Path("/dev/shm/rj_noaa_live.json").unlink(missing_ok=True)
            except Exception:
                pass
            _json_response(self, {"ok": True, "status": "stopped"})
            return
        if parsed.path == "/api/honeypot/start":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_honeypot_start()
            return
        if parsed.path == "/api/honeypot/stop":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_honeypot_stop()
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
        if parsed.path == "/api/settings/wigle":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(self, query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_settings_wigle_put()
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
            "ai",
            "utilities",
            "hardware",
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

    def _parse_range(self, size: int):
        """Parse a single-range 'Range: bytes=' header. Returns (start, end) or None.

        end is inclusive. Unsatisfiable ranges raise ValueError so the caller can
        emit 416. Multi-range and non-byte units are ignored (treated as full body).
        """
        header = self.headers.get("Range", "").strip()
        if not header.startswith("bytes=") or "," in header:
            return None
        spec = header[len("bytes="):].strip()
        start_s, _, end_s = spec.partition("-")
        try:
            if start_s == "":
                # suffix range: last N bytes
                n = int(end_s)
                if n <= 0:
                    raise ValueError
                start = max(0, size - n)
                end = size - 1
            else:
                start = int(start_s)
                end = int(end_s) if end_s else size - 1
        except ValueError:
            raise ValueError("invalid range")
        end = min(end, size - 1)
        if start > end or start >= size:
            raise ValueError("unsatisfiable")
        return start, end

    def _handle_loot_download(self, query: dict) -> None:
        raw = unquote(query.get("path", [""])[0])
        target = _safe_loot_path(raw)
        if target is None or not target.exists() or not target.is_file():
            _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return

        # ?inline=1 serves the file for in-browser playback/viewing instead of
        # forcing a download, so an <audio> tag or a new tab can stream it.
        inline = str(query.get("inline", [""])[0]).strip().lower() in {"1", "true", "yes", "on"}
        disposition = "inline" if inline else "attachment"

        ctype, _ = mimetypes.guess_type(str(target))
        ctype = ctype or "application/octet-stream"
        try:
            size = target.stat().st_size

            try:
                rng = self._parse_range(size)
            except ValueError:
                self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                self.send_header("Content-Range", f"bytes */{size}")
                self.end_headers()
                return

            if rng is None:
                start, end = 0, size - 1
                status = HTTPStatus.OK
            else:
                start, end = rng
                status = HTTPStatus.PARTIAL_CONTENT

            length = end - start + 1
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(length))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Disposition", f'{disposition}; filename="{target.name}"')
            if status == HTTPStatus.PARTIAL_CONTENT:
                self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            self.end_headers()

            with target.open("rb") as f:
                f.seek(start)
                remaining = length
                while remaining > 0:
                    chunk = f.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
        except (BrokenPipeError, ConnectionResetError):
            # Client seeked/closed mid-stream; normal for media playback.
            pass
        except Exception:
            _json_response(self, {"error": "read error"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_loot_archive(self, query: dict) -> None:
        """Stream a .zip of a loot folder so all files (e.g. recordings) pull at once."""
        raw = unquote(query.get("path", [""])[0])
        target = _safe_loot_path(raw)
        if target is None or not target.exists() or not target.is_dir():
            _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return

        loot_root = LOOT_DIR.resolve()
        arc_name = (target.name or "loot") + ".zip"
        tmp = None
        try:
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
            with zipfile.ZipFile(tmp, "w", zipfile.ZIP_STORED) as zf:
                for root, _dirs, files in os.walk(target):
                    root_path = Path(root)
                    # Never follow a symlink out of the loot tree.
                    if not (root_path.resolve() == loot_root or loot_root in root_path.resolve().parents):
                        continue
                    for fname in files:
                        fpath = root_path / fname
                        try:
                            if fpath.is_symlink() or not fpath.is_file():
                                continue
                            if loot_root not in fpath.resolve().parents:
                                continue
                            zf.write(fpath, fpath.relative_to(target).as_posix())
                        except (OSError, ValueError):
                            continue
            tmp.flush()
            tmp.close()
            size = os.path.getsize(tmp.name)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(size))
            self.send_header("Content-Disposition", f'attachment; filename="{arc_name}"')
            self.end_headers()
            with open(tmp.name, "rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            _json_response(self, {"error": "archive error"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
        finally:
            if tmp is not None:
                try:
                    os.unlink(tmp.name)
                except OSError:
                    pass

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

    def _handle_loot_nmap(self, query: dict) -> None:
        raw = unquote(query.get("path", [""])[0])
        target = _safe_loot_path(raw)
        if target is None or not target.exists() or not target.is_file():
            _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        if target.suffix.lower() != ".xml":
            _json_response(self, {"error": "not xml"}, status=HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
            return

        include_raw = str(query.get("include_raw", [""])[0]).strip().lower() in {"1", "true", "yes", "on"}
        try:
            payload = parse_nmap_xml_file(target, include_raw_xml=include_raw)
            payload.setdefault("file", {})["loot_path"] = raw
            _json_response(self, payload)
        except ValueError as exc:
            _json_response(self, {"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
        except Exception as exc:
            _json_response(self, {"error": f"parse error: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    # ── Wardriving API ────────────────────────────────────────────
    def _handle_wardriving_sessions(self) -> None:
        """List all wardriving session files."""
        sessions_dir = "/root/Raspyjack/loot/wardriving/sessions"
        loot_dir = "/root/Raspyjack/loot/wardriving"
        result = []
        # Session files
        if os.path.isdir(sessions_dir):
            for f in sorted(os.listdir(sessions_dir), reverse=True):
                if f.endswith("_wigle.csv"):
                    result.append({
                        "name": f.replace("_wigle.csv", ""),
                        "path": os.path.join(sessions_dir, f),
                        "size": os.path.getsize(os.path.join(sessions_dir, f)),
                    })
        # Also include legacy live file
        live = os.path.join(loot_dir, "wardriving_live.csv")
        if os.path.isfile(live):
            result.insert(0, {
                "name": "Live (current)",
                "path": live,
                "size": os.path.getsize(live),
            })
        _json_response(self, result)

    def _handle_wardriving_live(self) -> None:
        """Serve the most recent wardriving session CSV."""
        sessions_dir = "/root/Raspyjack/loot/wardriving/sessions"
        path = None
        if os.path.isdir(sessions_dir):
            csvs = sorted(
                [f for f in os.listdir(sessions_dir) if f.endswith("_wigle.csv")],
                reverse=True,
            )
            if csvs:
                path = os.path.join(sessions_dir, csvs[0])
        if not path:
            legacy = "/root/Raspyjack/loot/wardriving/wardriving_live.csv"
            if os.path.isfile(legacy):
                path = legacy
        if path and os.path.isfile(path):
            self.send_response(200)
            self.send_header("Content-Type", "text/csv")
            self.end_headers()
            with open(path, "rb") as f:
                self.wfile.write(f.read())
        else:
            self.send_response(404)
            self.end_headers()

    def _handle_wardriving_session(self, query: dict) -> None:
        """Serve a specific session CSV file, filtering bad GPS."""
        path = query.get("path", [""])[0]
        if not path or not path.startswith("/root/Raspyjack/loot/wardriving/"):
            self.send_response(403)
            self.end_headers()
            return
        if os.path.isfile(path):
            self.send_response(200)
            self.send_header("Content-Type", "text/csv")
            self.end_headers()
            with open(path, "r") as f:
                for i, line in enumerate(f):
                    if i < 2:
                        self.wfile.write(line.encode())
                        continue
                    parts = line.split(",")
                    if len(parts) >= 8:
                        try:
                            lat = float(parts[6])
                            lon = float(parts[7])
                            if abs(lat) < 1 and abs(lon) < 1:
                                continue
                        except ValueError:
                            pass
                    self.wfile.write(line.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def _handle_wardriving_start(self) -> None:
        try:
            if PAYLOAD_STATE_PATH.exists():
                raw = PAYLOAD_STATE_PATH.read_text(encoding="utf-8")
                pdata = json.loads(raw) if raw else {}
                if pdata.get("running"):
                    _json_response(self, {"ok": True, "status": "already_running", "path": pdata.get("path")})
                    return
            request_path = Path("/dev/shm/rj_payload_request.json")
            request_path.write_text(json.dumps({
                "action": "start",
                "path": "reconnaissance/wardriving.py",
                "args": ["--auto"],
            }))
            _json_response(self, {"ok": True, "status": "starting"})
        except Exception as exc:
            _json_response(self, {"error": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_wardriving_stop(self) -> None:
        _kill_payload("wardriving.py")
        _json_response(self, {"ok": True, "status": "stopped"})

    # ------------------------------------------------------------------
    # ADS-B
    # ------------------------------------------------------------------

    def _handle_adsb_live(self) -> None:
        adsb_path = Path("/dev/shm/rj_adsb_live.json")
        if adsb_path.exists():
            try:
                raw = adsb_path.read_text(encoding="utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(raw.encode())
            except Exception:
                _json_response(self, {"ts": 0, "count": 0, "total_messages": 0, "aircraft": []})
        else:
            _json_response(self, {"ts": 0, "count": 0, "total_messages": 0, "aircraft": []})

    def _handle_adsb_sessions(self) -> None:
        sessions_dir = "/root/Raspyjack/loot/SDR/adsb/sessions"
        result = []
        if os.path.isdir(sessions_dir):
            for f in sorted(os.listdir(sessions_dir), reverse=True):
                if f.endswith(".json"):
                    fp = os.path.join(sessions_dir, f)
                    try:
                        sz = os.path.getsize(fp)
                    except OSError:
                        sz = 0
                    result.append({"name": f, "path": fp, "size": sz})
        _json_response(self, result)

    def _handle_adsb_session(self, query: dict) -> None:
        path = (query.get("path") or [""])[0] if isinstance(query.get("path"), list) else str(query.get("path", ""))
        allowed_prefix = "/root/Raspyjack/loot/SDR/adsb/"
        if not path.startswith(allowed_prefix) or ".." in path:
            _json_response(self, {"error": "invalid path"}, status=HTTPStatus.BAD_REQUEST)
            return
        if os.path.isfile(path):
            try:
                raw = Path(path).read_text(encoding="utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(raw.encode())
            except Exception:
                _json_response(self, {"error": "read error"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
        else:
            self.send_response(404)
            self.end_headers()

    def _handle_adsb_start(self) -> None:
        try:
            if PAYLOAD_STATE_PATH.exists():
                raw = PAYLOAD_STATE_PATH.read_text(encoding="utf-8")
                pdata = json.loads(raw) if raw else {}
                if pdata.get("running"):
                    _json_response(self, {"ok": True, "status": "already_running", "path": pdata.get("path")})
                    return
            request_path = Path("/dev/shm/rj_payload_request.json")
            request_path.write_text(json.dumps({
                "action": "start",
                "path": "sdr/sdr_adsb.py",
                "args": ["--auto"],
            }))
            _json_response(self, {"ok": True, "status": "starting"})
        except Exception as exc:
            _json_response(self, {"error": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_adsb_stop(self) -> None:
        _kill_payload("sdr_adsb.py")
        try:
            Path("/dev/shm/rj_adsb_live.json").unlink(missing_ok=True)
        except Exception:
            pass
        _json_response(self, {"ok": True, "status": "stopped"})

    # ------------------------------------------------------------------
    # SDR
    # ------------------------------------------------------------------

    def _handle_sdr_live(self) -> None:
        sdr_path = Path("/dev/shm/rj_sdr_live.json")
        if sdr_path.exists():
            try:
                raw = sdr_path.read_text(encoding="utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(raw.encode())
            except Exception:
                _json_response(self, {"ts": 0, "streaming": False, "fft": None})
        else:
            _json_response(self, {"ts": 0, "streaming": False, "fft": None})

    def _handle_sdr_recordings(self) -> None:
        rec_dir = "/root/Raspyjack/loot/SDR/recordings"
        result = []
        if os.path.isdir(rec_dir):
            for f in sorted(os.listdir(rec_dir), reverse=True):
                if f.endswith((".raw", ".wav")):
                    fp = os.path.join(rec_dir, f)
                    try:
                        sz = os.path.getsize(fp)
                    except OSError:
                        sz = 0
                    result.append({"name": f, "path": fp, "size": sz})
        _json_response(self, result)

    def _handle_sdr_audio(self) -> None:
        """Stream demodulated audio as WAV from the PCM buffer file."""
        pcm_path = "/dev/shm/rj_sdr_audio.pcm"
        if not os.path.exists(pcm_path):
            _json_response(self, {"error": "no audio stream"}, status=HTTPStatus.NOT_FOUND)
            return
        try:
            import struct as st
            wav_header = bytearray(44)
            wav_header[0:4] = b"RIFF"
            st.pack_into("<I", wav_header, 4, 0x7FFFFFFF)
            wav_header[8:12] = b"WAVE"
            wav_header[12:16] = b"fmt "
            st.pack_into("<I", wav_header, 16, 16)
            st.pack_into("<H", wav_header, 20, 1)
            st.pack_into("<H", wav_header, 22, 1)
            st.pack_into("<I", wav_header, 24, 48000)
            st.pack_into("<I", wav_header, 28, 96000)
            st.pack_into("<H", wav_header, 32, 2)
            st.pack_into("<H", wav_header, 34, 16)
            wav_header[36:40] = b"data"
            st.pack_into("<I", wav_header, 40, 0x7FFFFFFF)
            self.send_response(200)
            self.send_header("Content-Type", "audio/wav")
            self.send_header("Cache-Control", "no-cache, no-store")
            self.end_headers()
            self.wfile.write(wav_header)
            self.wfile.flush()
            pos = 0
            try:
                fsize = os.path.getsize(pcm_path)
                pos = max(0, fsize - 48000 * 2)
            except OSError:
                pass
            while True:
                try:
                    with open(pcm_path, "rb") as f:
                        f.seek(pos)
                        chunk = f.read(16384)
                    if chunk:
                        pos += len(chunk)
                        self.wfile.write(chunk)
                        self.wfile.flush()
                    else:
                        time.sleep(0.05)
                except OSError:
                    time.sleep(0.1)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def _handle_sdr_start(self) -> None:
        try:
            if PAYLOAD_STATE_PATH.exists():
                raw = PAYLOAD_STATE_PATH.read_text(encoding="utf-8")
                pdata = json.loads(raw) if raw else {}
                if pdata.get("running"):
                    _json_response(self, {"ok": True, "status": "already_running", "path": pdata.get("path")})
                    return
            request_path = Path("/dev/shm/rj_payload_request.json")
            request_path.write_text(json.dumps({
                "action": "start",
                "path": "sdr/sdr_suite.py",
                "args": ["--auto"],
            }))
            _json_response(self, {"ok": True, "status": "starting"})
        except Exception as exc:
            _json_response(self, {"error": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_sdr_stop(self) -> None:
        _kill_payload("sdr_suite.py")
        try:
            Path("/dev/shm/rj_sdr_live.json").unlink(missing_ok=True)
        except Exception:
            pass
        _json_response(self, {"ok": True, "status": "stopped"})

    _SDR_CONTROL_PATH = "/dev/shm/rj_sdr_control.json"
    _SDR_VALID_RATES = {250000, 1024000, 2048000, 2400000, 2880000, 3200000}

    def _handle_sdr_control(self) -> None:
        body = _read_json(self)
        if body is None:
            _json_response(self, {"error": "invalid json"}, status=HTTPStatus.BAD_REQUEST)
            return
        action = str(body.get("action", "")).strip()
        value = body.get("value")
        if action == "set_freq":
            if not isinstance(value, (int, float)) or not (24_000_000 <= int(value) <= 1_766_000_000):
                _json_response(self, {"error": "freq must be 24-1766 MHz"}, status=HTTPStatus.BAD_REQUEST)
                return
            value = int(value)
        elif action == "set_gain":
            if not isinstance(value, (int, float)) or not (0 <= int(value) <= 50):
                _json_response(self, {"error": "gain must be 0-50"}, status=HTTPStatus.BAD_REQUEST)
                return
            value = int(value)
        elif action == "set_sample_rate":
            if not isinstance(value, (int, float)) or int(value) not in self._SDR_VALID_RATES:
                _json_response(self, {"error": f"sample_rate must be one of {sorted(self._SDR_VALID_RATES)}"}, status=HTTPStatus.BAD_REQUEST)
                return
            value = int(value)
        elif action in (
            "start_recording", "stop_recording",
            "start_audio", "stop_audio",
            "start_wav_recording", "stop_wav_recording",
            "start_decoder", "stop_decoder",
            "start_scan", "stop_scan",
            "add_bookmark", "delete_bookmark",
            "reset_peak_hold",
        ):
            pass
        else:
            _json_response(self, {"error": f"unknown action: {action}"}, status=HTTPStatus.BAD_REQUEST)
            return
        try:
            cmd = dict(body)
            cmd["action"] = action
            tmp = self._SDR_CONTROL_PATH + ".tmp"
            with open(tmp, "w") as f:
                json.dump(cmd, f)
            os.replace(tmp, self._SDR_CONTROL_PATH)
            _json_response(self, {"ok": True})
        except Exception as exc:
            _json_response(self, {"error": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    # ------------------------------------------------------------------
    # ISM (Sub-GHz / rtl_433) — lightweight background runner
    # ------------------------------------------------------------------

    _ISM_LIVE_PATH = Path("/dev/shm/rj_ism_live.json")

    def _handle_ism_live(self) -> None:
        if self._ISM_LIVE_PATH.exists():
            try:
                raw = self._ISM_LIVE_PATH.read_text(encoding="utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(raw.encode())
            except Exception:
                _json_response(self, _ism_empty_state())
        else:
            _json_response(self, _ism_empty_state())

    _TILES_DIR = Path("/root/Raspyjack/web/vendor/tiles")

    def _handle_tile(self, path: str) -> None:
        parts = path.strip("/").split("/")
        if len(parts) != 4 or not parts[1].isdigit():
            self.send_response(404)
            self.end_headers()
            return
        tile_path = self._TILES_DIR / parts[1] / parts[2] / parts[3]
        if tile_path.exists():
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Cache-Control", "public, max-age=604800")
            self.end_headers()
            self.wfile.write(tile_path.read_bytes())
        else:
            self.send_response(404)
            self.end_headers()

    _GNSS_LIVE_PATH = Path("/dev/shm/rj_gnss_live.json")

    def _handle_gnss_live(self) -> None:
        if self._GNSS_LIVE_PATH.exists():
            try:
                raw = self._GNSS_LIVE_PATH.read_text(encoding="utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(raw.encode())
            except Exception:
                _json_response(self, {"ts": 0, "satellites": [], "total": 0, "fix": {}})
        else:
            _json_response(self, {"ts": 0, "satellites": [], "total": 0, "fix": {}})

    # ------------------------------------------------------------------
    # NOAA Satellite Receiver
    # ------------------------------------------------------------------

    _NOAA_LIVE_PATH = Path("/dev/shm/rj_noaa_live.json")
    _NOAA_LOOT_DIR = "/root/Raspyjack/loot/SDR/noaa"

    _APRS_LIVE_PATH = Path("/dev/shm/rj_aprs_live.json")

    def _handle_aprs_live(self) -> None:
        if self._APRS_LIVE_PATH.exists():
            try:
                raw = self._APRS_LIVE_PATH.read_text(encoding="utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(raw.encode())
            except Exception:
                _json_response(self, {"ts": 0, "running": False, "total_stations": 0, "stations": [], "recent_packets": []})
        else:
            _json_response(self, {"ts": 0, "running": False, "total_stations": 0, "stations": [], "recent_packets": []})

    def _handle_noaa_live(self) -> None:
        if self._NOAA_LIVE_PATH.exists():
            try:
                raw = self._NOAA_LIVE_PATH.read_text(encoding="utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(raw.encode())
            except Exception:
                _json_response(self, {"ts": 0, "capturing": False, "passes": [], "captures": []})
        else:
            _json_response(self, {"ts": 0, "capturing": False, "passes": [], "captures": []})

    def _handle_noaa_image(self, query: dict) -> None:
        path = (query.get("path") or [""])[0] if isinstance(query.get("path"), list) else str(query.get("path", ""))
        if not path:
            path = os.path.join(self._NOAA_LOOT_DIR, "current.png")
        allowed = self._NOAA_LOOT_DIR
        if not path.startswith(allowed) or ".." in path:
            self.send_response(403)
            self.end_headers()
            return
        if os.path.isfile(path):
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            with open(path, "rb") as f:
                self.wfile.write(f.read())
        else:
            self.send_response(404)
            self.end_headers()

    def _handle_noaa_gallery(self) -> None:
        result = []
        if os.path.isdir(self._NOAA_LOOT_DIR):
            for f in sorted(os.listdir(self._NOAA_LOOT_DIR), reverse=True):
                if f.endswith(".png") and f != "current.png":
                    fp = os.path.join(self._NOAA_LOOT_DIR, f)
                    result.append({"file": f, "path": fp, "size": os.path.getsize(fp)})
        _json_response(self, result)

    def _handle_ism_start(self) -> None:
        body = _read_json(self) or {}
        band_idx = int(body.get("band", 0))
        _ism_manager.start(band_idx)
        _json_response(self, {"ok": True, "status": "running"})

    def _handle_ism_stop(self) -> None:
        _ism_manager.stop()
        _json_response(self, {"ok": True, "status": "stopped"})

    def _handle_ism_control(self) -> None:
        body = _read_json(self)
        if body is None:
            _json_response(self, {"error": "invalid json"}, status=HTTPStatus.BAD_REQUEST)
            return
        action = str(body.get("action", "")).strip()
        if action == "set_band":
            _ism_manager.stop()
            _ism_manager.start(int(body.get("value", 0)))
            _json_response(self, {"ok": True})
        elif action == "stop":
            _ism_manager.stop()
            _json_response(self, {"ok": True})
        else:
            _json_response(self, {"error": f"unknown action: {action}"}, status=HTTPStatus.BAD_REQUEST)

    # ------------------------------------------------------------------
    # Honeypot
    # ------------------------------------------------------------------

    def _handle_honeypot_live(self) -> None:
        hp_path = Path("/dev/shm/rj_honeypot_live.json")
        if hp_path.exists():
            try:
                raw = hp_path.read_text(encoding="utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(raw.encode())
            except Exception:
                _json_response(self, {"ts": 0, "running": False, "total_events": 0, "unique_ips": 0, "events_per_hour": 0, "uptime": 0, "top_ips": [], "port_stats": [], "recent_events": [], "heatmap": []})
        else:
            _json_response(self, {"ts": 0, "running": False, "total_events": 0, "unique_ips": 0, "events_per_hour": 0, "uptime": 0, "top_ips": [], "port_stats": [], "recent_events": [], "heatmap": []})

    def _handle_honeypot_sessions(self) -> None:
        sessions_dir = "/root/Raspyjack/loot/honeypot/sessions"
        result = []
        if os.path.isdir(sessions_dir):
            for f in sorted(os.listdir(sessions_dir), reverse=True):
                if f.endswith(".json"):
                    fp = os.path.join(sessions_dir, f)
                    try:
                        sz = os.path.getsize(fp)
                        with open(fp, encoding="utf-8") as fh:
                            d = json.load(fh)
                        result.append({
                            "name": f, "path": fp, "size": sz,
                            "start": d.get("session_start", ""),
                            "end": d.get("session_end", ""),
                            "events": d.get("total_events", 0),
                        })
                    except Exception:
                        result.append({"name": f, "path": fp, "size": sz})
        _json_response(self, result)

    def _handle_honeypot_session(self, query: dict) -> None:
        path = (query.get("path") or [""])[0] if isinstance(query.get("path"), list) else str(query.get("path", ""))
        allowed = "/root/Raspyjack/loot/honeypot/"
        if not path.startswith(allowed) or ".." in path:
            _json_response(self, {"error": "invalid path"}, status=HTTPStatus.BAD_REQUEST)
            return
        if os.path.isfile(path):
            try:
                raw = Path(path).read_text(encoding="utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(raw.encode())
            except Exception:
                _json_response(self, {"error": "read error"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
        else:
            self.send_response(404)
            self.end_headers()

    def _handle_honeypot_start(self) -> None:
        if _honeypot_runner.running:
            _json_response(self, {"ok": True, "status": "already_running"})
            return
        _honeypot_runner.start()
        _json_response(self, {"ok": True, "status": "starting"})

    def _handle_honeypot_stop(self) -> None:
        _honeypot_runner.stop()
        _json_response(self, {"ok": True, "status": "stopped"})

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

    def _handle_settings_wigle_get(self) -> None:
        creds = _read_wigle_credentials()
        api_name = creds.get("api_name", "")
        api_token = creds.get("api_token", "")
        _json_response(self, {
            "configured": bool(api_name and api_token),
            "api_name_masked": _mask_secret(api_name),
            "api_token_masked": _mask_secret(api_token),
        })

    def _handle_settings_wigle_put(self) -> None:
        body = _read_json(self)
        if body is None:
            _json_response(self, {"error": "invalid json"}, status=HTTPStatus.BAD_REQUEST)
            return
        clear_requested = bool(body.get("clear"))
        incoming_name = str(body.get("api_name", "")).strip()
        incoming_token = str(body.get("api_token", "")).strip()
        current = _read_wigle_credentials()
        if clear_requested:
            api_name = ""
            api_token = ""
        else:
            api_name = incoming_name or current.get("api_name", "")
            api_token = incoming_token or current.get("api_token", "")
        ok, status = _write_wigle_credentials(api_name, api_token)
        if not ok:
            _json_response(self, {"error": status}, status=HTTPStatus.BAD_REQUEST)
            return
        _json_response(self, {
            "ok": True,
            "status": status,
            "configured": bool(api_name and api_token),
            "api_name_masked": _mask_secret(api_name),
            "api_token_masked": _mask_secret(api_token),
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
        reauth = bool(body.get("reauth"))
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
        if _tailscale_installed():
            if not reauth:
                _json_response(self, {"error": "tailscale already installed"}, status=HTTPStatus.CONFLICT)
                return
            threading.Thread(target=_tailscale_run_reauth, daemon=True).start()
        else:
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

    # Bind on all interfaces — always reachable on any IP (eth, wlan, tailscale)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), RaspyJackHandler)
    print(f"[WebUI] Serving on http://0.0.0.0:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
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
