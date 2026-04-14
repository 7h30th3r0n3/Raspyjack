#!/usr/bin/env python3
"""
Launch and control the vendored Ragnar port from Raspyjack.
"""

import json
import os
import signal
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
from PIL import Image, ImageDraw

from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

ROOT = Path(__file__).resolve().parents[2]
RAGNAR_ROOT = ROOT / "vendor" / "ragnar"
RAGNAR_SHIM = RAGNAR_ROOT / "raspyjack_headless.py"
RAGNAR_LOG_DIR = ROOT / "loot" / "Ragnar"
RAGNAR_LOG_PATH = RAGNAR_LOG_DIR / "ragnar.log"
RAGNAR_UI_LOG_PATH = RAGNAR_LOG_DIR / "ragnar_ui.log"
RAGNAR_PID_PATH = Path("/dev/shm/raspyjack_ragnar.pid")
RAGNAR_PORT = int(os.environ.get("RAGNAR_PORT", "8091"))

PINS = {
    "UP": 6,
    "DOWN": 19,
    "LEFT": 5,
    "RIGHT": 26,
    "OK": 13,
    "KEY1": 21,
    "KEY2": 20,
    "KEY3": 16,
}

PAGES = (
    "overview",
    "stats",
    "targets",
    "credentials",
    "attacks",
    "wifi",
    "address",
    "controls",
    "logs",
)
CONTROL_ITEMS = (
    "start_app",
    "stop_app",
    "automation_on",
    "automation_off",
    "manual_on",
    "manual_off",
    "scan_network",
    "scan_vulns",
    "deep_scan",
    "scan_arp",
)
CONTROL_LABELS = {
    "start_app": "Start Ragnar",
    "stop_app": "Stop Ragnar",
    "automation_on": "Automation ON",
    "automation_off": "Automation OFF",
    "manual_on": "Manual ON",
    "manual_off": "Manual OFF",
    "scan_network": "Network Scan",
    "scan_vulns": "Vuln Scan",
    "deep_scan": "Deep Scan",
    "scan_arp": "ARP Sweep",
}

ATTACK_TYPES = ("ssh", "ftp", "smb", "telnet", "rdp", "sql")
ATTACK_LABELS = {
    "ssh": "SSH Brute",
    "ftp": "FTP Brute",
    "smb": "SMB Brute",
    "telnet": "Telnet Brute",
    "rdp": "RDP Brute",
    "sql": "SQL Brute",
}

LCD = None
WIDTH = 128
HEIGHT = 128
FONT = None
SMALL_FONT = None
SPINNER = ("|", "/", "-", "\\")


def _load_logo() -> Image.Image | None:
    candidates = (
        RAGNAR_ROOT / "web" / "images" / "ragnar.png",
        RAGNAR_ROOT / "web" / "images" / "icon-96x96.png",
    )
    for path in candidates:
        try:
            img = Image.open(path).convert("RGBA")
            return img.resize((28, 28))
        except Exception:
            continue
    return None


RAGNAR_LOGO = _load_logo()


def _log_ui_error(exc: Exception) -> None:
    try:
        RAGNAR_LOG_DIR.mkdir(parents=True, exist_ok=True)
        with open(RAGNAR_UI_LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] {exc.__class__.__name__}: {exc}\n")
            handle.write(traceback.format_exc())
            handle.write("\n")
    except Exception:
        pass


def _init_display() -> None:
    global LCD, WIDTH, HEIGHT, FONT, SMALL_FONT
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    LCD.LCD_Clear()
    WIDTH, HEIGHT = LCD.width, LCD.height
    FONT = scaled_font(10)
    SMALL_FONT = scaled_font(8)


def _read_pid() -> int | None:
    try:
        return int(RAGNAR_PID_PATH.read_text(encoding="utf-8").strip())
    except Exception:
        return None


def _clear_pid() -> None:
    try:
        RAGNAR_PID_PATH.unlink()
    except FileNotFoundError:
        pass


def _pid_matches_ragnar(pid: int) -> bool:
    proc_cmdline = Path(f"/proc/{pid}/cmdline")
    try:
        raw = proc_cmdline.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False
    return "raspyjack_headless.py" in raw


def _running_pid() -> int | None:
    pid = _read_pid()
    if not pid:
        return None
    try:
        os.kill(pid, 0)
    except OSError:
        _clear_pid()
        return None
    if not _pid_matches_ragnar(pid):
        _clear_pid()
        return None
    return pid


def _tail_log(lines: int = 5) -> list[str]:
    try:
        data = RAGNAR_LOG_PATH.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []
    return [line.strip()[:26] for line in data[-lines:] if line.strip()]


def _best_ip() -> str:
    try:
        proc = subprocess.run(
            ["ip", "route", "get", "1.1.1.1"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        parts = proc.stdout.split()
        if "src" in parts:
            return parts[parts.index("src") + 1]
    except Exception:
        pass
    return "device-ip"


def _base_url() -> str:
    return f"http://127.0.0.1:{RAGNAR_PORT}"


def _display_url() -> str:
    return f"http://{_best_ip()}:{RAGNAR_PORT}"


def _preflight_ragnar() -> tuple[bool, str]:
    env = os.environ.copy()
    env["RAGNAR_PAGER_MODE"] = "1"  # skip EPD init — conflicts with RaspyJack LCD SPI
    env["PYTHONPATH"] = str(RAGNAR_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    try:
        proc = subprocess.run(
            [sys.executable, "-c", "import headlessRagnar; print('OK')"],
            cwd=str(RAGNAR_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except Exception as exc:
        return False, f"Preflight failed: {exc}"

    if proc.returncode == 0:
        return True, "OK"

    blob = "\n".join(part for part in (proc.stderr, proc.stdout) if part).strip()
    if "ModuleNotFoundError" in blob and "No module named" in blob:
        marker = "No module named "
        idx = blob.rfind(marker)
        if idx >= 0:
            missing = blob[idx + len(marker):].strip().strip("'\"")
            return False, f"Missing dep: {missing}"
    if blob:
        return False, _shorten(blob.splitlines()[-1], 24)
    return False, "Import preflight failed"


def _api_json(path: str, method: str = "GET", payload: dict | None = None) -> tuple[bool, dict]:
    url = _base_url() + path
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            raw = resp.read().decode("utf-8", "ignore")
            parsed = json.loads(raw) if raw else {}
            return True, parsed
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read().decode("utf-8", "ignore")
            parsed = json.loads(raw) if raw else {}
        except Exception:
            parsed = {"error": f"http {exc.code}"}
        return False, parsed
    except Exception as exc:
        return False, {"error": str(exc)}


def _stop_ragnar() -> tuple[bool, str]:
    pid = _running_pid()
    if not pid:
        return False, "Already stopped"

    try:
        os.killpg(pid, signal.SIGTERM)
    except Exception:
        try:
            os.kill(pid, signal.SIGTERM)
        except Exception as exc:
            return False, f"Stop failed: {exc}"

    deadline = time.time() + 8
    while time.time() < deadline:
        if _running_pid() is None:
            _clear_pid()
            return True, "Ragnar stopped"
        time.sleep(0.2)

    try:
        os.killpg(pid, signal.SIGKILL)
    except Exception:
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
    _clear_pid()
    return True, "Forced stop"


def _start_ragnar() -> tuple[bool, str]:
    if not RAGNAR_SHIM.exists():
        return False, "Vendored Ragnar missing"
    if _running_pid():
        return True, "Already running"

    ready, message = _preflight_ragnar()
    if not ready:
        if message.startswith("Missing dep:"):
            return False, f"{message} install_ragnar_port"
        return False, message

    RAGNAR_LOG_DIR.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["RAGNAR_PORT"] = str(RAGNAR_PORT)
    env["RAGNAR_PAGER_MODE"] = "1"  # skip EPD init — conflicts with RaspyJack LCD SPI
    env["PYTHONPATH"] = str(RAGNAR_ROOT) + os.pathsep + env.get("PYTHONPATH", "")

    with open(RAGNAR_LOG_PATH, "ab", buffering=0) as log_handle:
        proc = subprocess.Popen(
            [sys.executable, str(RAGNAR_SHIM)],
            cwd=str(RAGNAR_ROOT),
            env=env,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    RAGNAR_PID_PATH.write_text(f"{proc.pid}\n", encoding="utf-8")

    deadline = time.time() + 8
    while time.time() < deadline:
        if _running_pid():
            ok, _status = _api_json("/api/status")
            if ok:
                return True, "Ragnar started"
        time.sleep(0.4)

    details = _tail_log(2)
    if details:
        return False, details[-1][:24]
    return False, "Start failed"


def _short_bool(value: bool) -> str:
    return "ON" if value else "OFF"


def _shorten(text: str, limit: int = 20) -> str:
    text = str(text or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "\u2026"


def _simple_wrap(text: str, width: int = 18, limit: int = 6) -> list[str]:
    words = str(text or "").split()
    if not words:
        return []
    lines: list[str] = []
    current = words[0]
    for word in words[1:]:
        candidate = f"{current} {word}"
        if len(candidate) <= width:
            current = candidate
        else:
            lines.append(current)
            current = word
            if len(lines) >= limit - 1:
                break
    if len(lines) < limit:
        lines.append(current)
    return [line[:width] for line in lines[:limit]]


def _split_url(url: str) -> list[str]:
    if "://" in url:
        scheme, rest = url.split("://", 1)
        lines = [scheme + "://"]
    else:
        rest = url
        lines = []
    while rest:
        chunk = rest[:18]
        lines.append(chunk)
        rest = rest[18:]
    return lines[:3]


# ---------------------------------------------------------------------------
# State fetching — pulls data from Ragnar API
# ---------------------------------------------------------------------------

def _fetch_state() -> dict:
    running = _running_pid() is not None
    state = {
        "running": running,
        "host_url": _display_url(),
        "api_ok": False,
        "manual_mode": False,
        "automation_enabled": False,
        "target_count": 0,
        "port_count": 0,
        "vulnerability_count": 0,
        "credential_count": 0,
        "level": 0,
        "points": 0,
        "data_stolen": 0,
        "current_ssid": "",
        "orchestrator_status": "",
        "ragnar_status": "",
        "ragnar_status2": "",
        "error": "",
        "logs": _tail_log(4),
        "targets": [],
        "credentials": {},
        "wifi_networks": [],
        "wifi_status": {},
    }
    if not running:
        return state

    ok, data = _api_json("/api/status")
    if not ok:
        state["error"] = _shorten(data.get("error", "API unavailable"), 24)
        return state

    state["api_ok"] = True
    state["manual_mode"] = bool(data.get("manual_mode"))
    state["automation_enabled"] = bool(data.get("automation_enabled"))
    state["target_count"] = int(data.get("target_count", 0) or 0)
    state["port_count"] = int(data.get("port_count", 0) or 0)
    state["vulnerability_count"] = int(data.get("vulnerability_count", 0) or 0)
    state["credential_count"] = int(data.get("credential_count", 0) or 0)
    state["current_ssid"] = str(data.get("current_ssid", "") or "")
    state["orchestrator_status"] = str(data.get("orchestrator_status", "") or "")
    state["ragnar_status"] = str(data.get("ragnar_status", "") or "")
    state["ragnar_status2"] = str(data.get("ragnar_status2", "") or "")
    return state


def _fetch_stats() -> dict:
    """Fetch extended stats from /api/stats."""
    ok, data = _api_json("/api/stats")
    if not ok:
        return {}
    return {
        "targets": int(data.get("target_count", 0) or 0),
        "inactive": int(data.get("inactive_target_count", 0) or 0),
        "total_targets": int(data.get("total_target_count", 0) or 0),
        "new_targets": int(data.get("new_target_count", 0) or 0),
        "lost_targets": int(data.get("lost_target_count", 0) or 0),
        "ports": int(data.get("port_count", 0) or 0),
        "vulns": int(data.get("vulnerability_count", 0) or 0),
        "vuln_hosts": int(data.get("vulnerable_hosts_count", 0) or 0),
        "creds": int(data.get("credential_count", 0) or 0),
        "level": int(data.get("level", 0) or 0),
        "points": int(data.get("points", 0) or 0),
        "data_stolen": int(data.get("total_data_stolen", 0) or 0),
    }


def _fetch_targets() -> list[dict]:
    """Fetch target list from /api/manual/targets."""
    ok, data = _api_json("/api/manual/targets")
    if not ok:
        return []
    raw = data.get("targets", [])
    targets = []
    for t in raw:
        targets.append({
            "ip": str(t.get("ip", "") or ""),
            "hostname": str(t.get("hostname", "") or ""),
            "ports": str(t.get("ports", "") or ""),
            "status": str(t.get("status", "") or "alive"),
            "mac": str(t.get("mac", "") or ""),
        })
    return targets


def _fetch_credentials() -> list[dict]:
    """Fetch credentials from /api/credentials, flattened."""
    ok, data = _api_json("/api/credentials")
    if not ok:
        return []
    flat = []
    if isinstance(data, dict):
        for svc, entries in data.items():
            if not isinstance(entries, list):
                continue
            for e in entries:
                flat.append({
                    "service": str(svc),
                    "ip": str(e.get("ip", "") or ""),
                    "username": str(e.get("username", "") or ""),
                    "password": str(e.get("password", "") or ""),
                })
    return flat


def _fetch_wifi_networks() -> list[dict]:
    """Fetch scanned WiFi networks."""
    ok, data = _api_json("/api/wifi/networks")
    if not ok:
        return []
    nets = data if isinstance(data, list) else data.get("networks", [])
    result = []
    for n in nets[:20]:
        result.append({
            "ssid": str(n.get("ssid", "") or ""),
            "signal": int(n.get("signal", 0) or 0),
            "security": str(n.get("security", "") or ""),
            "connected": bool(n.get("connected")),
        })
    return result


def _fetch_wifi_status() -> dict:
    """Fetch current WiFi connection status."""
    ok, data = _api_json("/api/wifi/status")
    if not ok:
        return {}
    return {
        "connected": bool(data.get("connected")),
        "ssid": str(data.get("ssid", "") or ""),
        "signal": str(data.get("signal", "") or ""),
        "ip": str(data.get("ip", "") or ""),
        "interface": str(data.get("interface", "") or ""),
    }


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

def _run_control(action: str) -> tuple[bool, str]:
    if action == "start_app":
        return _start_ragnar()
    if action == "stop_app":
        return _stop_ragnar()

    if _running_pid() is None:
        return False, "Start Ragnar first"

    mapping = {
        "automation_on": ("/api/automation/orchestrator/start", {}),
        "automation_off": ("/api/automation/orchestrator/stop", {}),
        "manual_on": ("/api/manual/orchestrator/start", {}),
        "manual_off": ("/api/manual/orchestrator/stop", {}),
        "scan_network": ("/api/manual/scan/network", {}),
        "scan_vulns": ("/api/manual/scan/vulnerability", {"ip": "all"}),
        "deep_scan": ("/api/scan/deep", {}),
        "scan_arp": ("/api/scan/arp-localnet", {}),
    }
    entry = mapping.get(action)
    if not entry:
        return False, "Unknown action"
    path, payload = entry
    method = "POST" if payload is not None else "GET"
    if action in ("scan_arp",):
        method = "GET"
    ok, data = _api_json(path, method=method, payload=payload if method == "POST" else None)
    if ok and (data.get("success") is True or data.get("ok") is True or "message" in data):
        return True, _shorten(data.get("message", CONTROL_LABELS[action]), 24)
    return False, _shorten(data.get("error", "Action failed"), 24)


def _run_attack(target_ip: str, target_port: str, attack_type: str) -> tuple[bool, str]:
    """Execute a manual attack on a specific target."""
    if _running_pid() is None:
        return False, "Start Ragnar first"
    ok, data = _api_json(
        "/api/manual/execute-attack",
        method="POST",
        payload={"ip": target_ip, "port": target_port, "action": attack_type},
    )
    if ok and data.get("success"):
        return True, _shorten(data.get("message", "Attack started"), 24)
    return False, _shorten(data.get("error", "Attack failed"), 24)


def _wifi_scan() -> tuple[bool, str]:
    ok, data = _api_json("/api/wifi/scan", method="POST")
    if ok:
        return True, "WiFi scan started"
    return False, _shorten(data.get("error", "Scan failed"), 24)


def _wifi_connect(ssid: str) -> tuple[bool, str]:
    ok, data = _api_json("/api/wifi/connect", method="POST", payload={"ssid": ssid})
    if ok and data.get("success"):
        return True, f"Connecting to {_shorten(ssid, 14)}"
    return False, _shorten(data.get("error", "Connect failed"), 24)


def _wifi_disconnect() -> tuple[bool, str]:
    ok, data = _api_json("/api/wifi/disconnect", method="POST")
    if ok:
        return True, "Disconnected"
    return False, _shorten(data.get("error", "Failed"), 24)


# ---------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------

def _draw_chrome(draw: ScaledDraw, title: str, page_idx: int) -> None:
    draw.rectangle((2, 2, 126, 126), outline="#05ff00", width=1)
    draw.text((6, 5), title, font=FONT, fill="#00ff88")
    draw.text((96, 5), f"{page_idx + 1}/{len(PAGES)}", font=SMALL_FONT, fill="#7dd3fc")
    draw.line((6, 17, 122, 17), fill="#14532d", width=1)


def _draw_logo(image: Image.Image, x: int, y: int) -> None:
    if RAGNAR_LOGO is None:
        return
    try:
        image.paste(RAGNAR_LOGO, (x, y), RAGNAR_LOGO)
    except Exception:
        pass


def _draw_signal_anim(draw: ScaledDraw, tick: int, x: int, y: int) -> None:
    heights = (4, 7, 10, 13)
    active = tick % len(heights)
    for idx, base in enumerate(heights):
        h = base if idx <= active else 3
        left = x + idx * 4
        draw.rectangle((left, y + 13 - h, left + 2, y + 13), fill="#00ff88" if idx <= active else "#14532d")


def _draw_spinner(draw: ScaledDraw, tick: int, x: int, y: int) -> None:
    draw.text((x, y), SPINNER[tick % len(SPINNER)], font=SMALL_FONT, fill="#fcd34d")


def _draw_scrollbar(draw: ScaledDraw, current: int, total: int, y_start: int = 20, y_end: int = 122) -> None:
    """Draw a thin scrollbar on the right edge."""
    if total <= 1:
        return
    bar_h = max(4, (y_end - y_start) // total)
    bar_y = y_start + int((y_end - y_start - bar_h) * current / max(1, total - 1))
    draw.rectangle((122, y_start, 124, y_end), fill="#0a2a0a")
    draw.rectangle((122, bar_y, 124, bar_y + bar_h), fill="#05ff00")


# ---------------------------------------------------------------------------
# Page: Overview
# ---------------------------------------------------------------------------

def _draw_overview(image: Image.Image, draw: ScaledDraw, state: dict, anim_tick: int) -> None:
    _draw_chrome(draw, "Ragnar", 0)
    _draw_logo(image, 92, 22)
    _draw_signal_anim(draw, anim_tick, 92, 56)
    y = 22
    lines = [
        f"State: {'RUN' if state['running'] else 'STOP'}",
        f"API: {'OK' if state['api_ok'] else '--'}",
        f"Auto: {_short_bool(state['automation_enabled'])}",
        f"Manual: {_short_bool(state['manual_mode'])}",
        f"T/P/V: {state['target_count']}/{state['port_count']}/{state['vulnerability_count']}",
        f"SSID: {_shorten(state['current_ssid'] or '-', 12)}",
        f"Orch: {_shorten(state['orchestrator_status'] or 'IDLE', 12)}",
        _shorten(state['ragnar_status2'] or state['error'] or "LT/RT pages", 18),
    ]
    for line in lines:
        draw.text((6, y), line, font=SMALL_FONT, fill="white")
        y += 11


# ---------------------------------------------------------------------------
# Page: Stats (extended metrics)
# ---------------------------------------------------------------------------

def _draw_stats(image: Image.Image, draw: ScaledDraw, stats: dict, anim_tick: int) -> None:
    _draw_chrome(draw, "Stats", 1)
    _draw_logo(image, 92, 22)
    _draw_spinner(draw, anim_tick, 113, 49)
    y = 22
    if not stats:
        draw.text((6, y), "No stats available", font=SMALL_FONT, fill="#7dd3fc")
        draw.text((6, y + 11), "Start Ragnar first", font=SMALL_FONT, fill="white")
        return
    lines = [
        f"Targets: {stats.get('targets', 0)} active",
        f"  New: {stats.get('new_targets', 0)} Lost: {stats.get('lost_targets', 0)}",
        f"Ports: {stats.get('ports', 0)} open",
        f"Vulns: {stats.get('vulns', 0)} ({stats.get('vuln_hosts', 0)} hosts)",
        f"Creds: {stats.get('creds', 0)} found",
        f"Data: {stats.get('data_stolen', 0)} files",
        f"Level: {stats.get('level', 0)}",
        f"Points: {stats.get('points', 0)}",
    ]
    for line in lines:
        draw.text((6, y), line, font=SMALL_FONT, fill="white")
        y += 11


# ---------------------------------------------------------------------------
# Page: Targets (scrollable host list)
# ---------------------------------------------------------------------------

def _draw_targets(image: Image.Image, draw: ScaledDraw, targets: list, scroll_idx: int, anim_tick: int) -> None:
    _draw_chrome(draw, "Targets", 2)
    _draw_spinner(draw, anim_tick, 113, 5)
    y = 20
    if not targets:
        draw.text((6, y), "No targets found", font=SMALL_FONT, fill="#7dd3fc")
        draw.text((6, y + 11), "Run a scan first", font=SMALL_FONT, fill="white")
        return
    visible = 8
    start = max(0, min(scroll_idx, len(targets) - visible))
    end = min(len(targets), start + visible)
    for idx in range(start, end):
        t = targets[idx]
        ip = _shorten(t["ip"], 15)
        ports = t.get("ports", "")
        port_count = len([p for p in ports.split(",") if p.strip()]) if ports else 0
        color = "#00ff88" if idx == scroll_idx else "white"
        prefix = ">" if idx == scroll_idx else " "
        label = f"{prefix}{ip}"
        if port_count:
            label += f" [{port_count}p]"
        draw.text((6, y), _shorten(label, 20), font=SMALL_FONT, fill=color)
        y += 11
    # Show selected target detail at bottom
    if 0 <= scroll_idx < len(targets):
        t = targets[scroll_idx]
        draw.line((6, 108, 120, 108), fill="#14532d", width=1)
        hostname = t.get("hostname", "")
        if hostname:
            draw.text((6, 111), _shorten(hostname, 20), font=SMALL_FONT, fill="#fcd34d")
        else:
            ports = t.get("ports", "")
            draw.text((6, 111), _shorten(f"P:{ports}" if ports else "No ports", 20), font=SMALL_FONT, fill="#fcd34d")
    _draw_scrollbar(draw, scroll_idx, len(targets))


# ---------------------------------------------------------------------------
# Page: Credentials
# ---------------------------------------------------------------------------

def _draw_credentials(image: Image.Image, draw: ScaledDraw, creds: list, scroll_idx: int, anim_tick: int) -> None:
    _draw_chrome(draw, "Creds", 3)
    _draw_spinner(draw, anim_tick, 113, 5)
    y = 20
    if not creds:
        draw.text((6, y), "No credentials yet", font=SMALL_FONT, fill="#7dd3fc")
        draw.text((6, y + 11), "Run attacks to find", font=SMALL_FONT, fill="white")
        draw.text((6, y + 22), "credentials", font=SMALL_FONT, fill="white")
        return
    visible = 7
    start = max(0, min(scroll_idx, len(creds) - visible))
    end = min(len(creds), start + visible)
    for idx in range(start, end):
        c = creds[idx]
        svc = c.get("service", "?")[:4].upper()
        ip = _shorten(c.get("ip", ""), 10)
        color = "#00ff88" if idx == scroll_idx else "white"
        prefix = ">" if idx == scroll_idx else " "
        draw.text((6, y), f"{prefix}[{svc}] {ip}", font=SMALL_FONT, fill=color)
        y += 11
    # Show selected cred detail
    if 0 <= scroll_idx < len(creds):
        c = creds[scroll_idx]
        draw.line((6, 100, 120, 100), fill="#14532d", width=1)
        draw.text((6, 103), _shorten(f"U:{c.get('username', '?')}", 20), font=SMALL_FONT, fill="#a7f3d0")
        draw.text((6, 114), _shorten(f"P:{c.get('password', '?')}", 20), font=SMALL_FONT, fill="#fcd34d")
    _draw_scrollbar(draw, scroll_idx, len(creds))


# ---------------------------------------------------------------------------
# Page: Attacks (select target + attack type, execute)
# ---------------------------------------------------------------------------

def _draw_attacks(image: Image.Image, draw: ScaledDraw, targets: list, target_idx: int,
                  attack_idx: int, notice: str | None, anim_tick: int) -> None:
    _draw_chrome(draw, "Attacks", 4)
    _draw_spinner(draw, anim_tick, 113, 5)
    y = 20
    if not targets:
        draw.text((6, y), "No targets available", font=SMALL_FONT, fill="#7dd3fc")
        draw.text((6, y + 11), "Run a scan first", font=SMALL_FONT, fill="white")
        return
    # Show selected target
    t = targets[target_idx] if 0 <= target_idx < len(targets) else {}
    ip = t.get("ip", "?")
    ports = t.get("ports", "")
    draw.text((6, y), f"Target: {_shorten(ip, 14)}", font=SMALL_FONT, fill="#a7f3d0")
    y += 11
    draw.text((6, y), f"Ports: {_shorten(ports or 'none', 14)}", font=SMALL_FONT, fill="white")
    y += 11
    atk_label = ATTACK_LABELS.get(ATTACK_TYPES[attack_idx], "?")
    draw.text((6, y), f"Attack: {atk_label}", font=SMALL_FONT, fill="#fcd34d")
    y += 11
    draw.text((6, y), "UP/DN=tgt K1=atk OK=go", font=SMALL_FONT, fill="#7dd3fc")
    y += 13
    # Show attack type list
    for idx, atype in enumerate(ATTACK_TYPES):
        color = "#00ff88" if idx == attack_idx else "white"
        prefix = ">" if idx == attack_idx else " "
        label = ATTACK_LABELS.get(atype, atype)
        draw.text((6, y), f"{prefix} {label}", font=SMALL_FONT, fill=color)
        y += 10
        if y > 106:
            break
    if notice:
        draw.line((6, 108, 120, 108), fill="#14532d", width=1)
        draw.text((6, 112), _shorten(notice, 20), font=SMALL_FONT, fill="#fcd34d")


# ---------------------------------------------------------------------------
# Page: WiFi
# ---------------------------------------------------------------------------

def _draw_wifi(image: Image.Image, draw: ScaledDraw, wifi_status: dict, wifi_nets: list,
               wifi_idx: int, notice: str | None, anim_tick: int) -> None:
    _draw_chrome(draw, "WiFi", 5)
    _draw_spinner(draw, anim_tick, 113, 5)
    y = 20
    if wifi_status.get("connected"):
        ssid = _shorten(wifi_status.get("ssid", "?"), 14)
        draw.text((6, y), f"Now: {ssid}", font=SMALL_FONT, fill="#a7f3d0")
        y += 11
        draw.text((6, y), f"IP: {_shorten(wifi_status.get('ip', '?'), 14)}", font=SMALL_FONT, fill="white")
        y += 11
    else:
        draw.text((6, y), "Not connected", font=SMALL_FONT, fill="#fcd34d")
        y += 11
    draw.text((6, y), "K1=scan OK=join K2=off", font=SMALL_FONT, fill="#7dd3fc")
    y += 12
    if not wifi_nets:
        draw.text((6, y), "No networks scanned", font=SMALL_FONT, fill="white")
    else:
        visible = 5
        start = max(0, min(wifi_idx, len(wifi_nets) - visible))
        end = min(len(wifi_nets), start + visible)
        for idx in range(start, end):
            n = wifi_nets[idx]
            ssid = _shorten(n.get("ssid", "?"), 12)
            sig = n.get("signal", 0)
            color = "#00ff88" if idx == wifi_idx else "white"
            prefix = ">" if idx == wifi_idx else " "
            conn = "*" if n.get("connected") else " "
            draw.text((6, y), f"{prefix}{conn}{ssid} {sig}dB", font=SMALL_FONT, fill=color)
            y += 10
        _draw_scrollbar(draw, wifi_idx, len(wifi_nets), y_start=55)
    if notice:
        draw.line((6, 108, 120, 108), fill="#14532d", width=1)
        draw.text((6, 112), _shorten(notice, 20), font=SMALL_FONT, fill="#a7f3d0")


# ---------------------------------------------------------------------------
# Page: Address
# ---------------------------------------------------------------------------

def _draw_address(image: Image.Image, draw: ScaledDraw, state: dict, anim_tick: int) -> None:
    _draw_chrome(draw, "Address", 6)
    _draw_logo(image, 92, 84)
    _draw_spinner(draw, anim_tick, 113, 88)
    y = 24
    for line in _split_url(state["host_url"]):
        draw.text((6, y), line, font=SMALL_FONT, fill="white")
        y += 10
    y += 4
    draw.text((6, y), "Open Ragnar WebUI", font=SMALL_FONT, fill="#a7f3d0")
    y += 11
    draw.text((6, y), "Port kept separate", font=SMALL_FONT, fill="#a7f3d0")
    y += 11
    draw.text((6, y), "from Raspyjack UI.", font=SMALL_FONT, fill="#a7f3d0")
    y += 14
    draw.text((6, y), "K2/OK refresh", font=SMALL_FONT, fill="#7dd3fc")


# ---------------------------------------------------------------------------
# Page: Controls
# ---------------------------------------------------------------------------

def _draw_controls(image: Image.Image, draw: ScaledDraw, control_idx: int, notice: str | None, anim_tick: int) -> None:
    _draw_chrome(draw, "Controls", 7)
    _draw_logo(image, 92, 22)
    _draw_spinner(draw, anim_tick, 113, 49)
    y = 22
    draw.text((6, y), CONTROL_LABELS[CONTROL_ITEMS[control_idx]], font=SMALL_FONT, fill="#fcd34d")
    y += 12
    draw.text((6, y), "UP/DN pick  OK run", font=SMALL_FONT, fill="white")
    y += 10
    draw.text((6, y), "LT/RT page  K2 refresh", font=SMALL_FONT, fill="white")
    y += 13
    window = 5
    start = max(0, min(control_idx - 1, len(CONTROL_ITEMS) - window))
    end = min(len(CONTROL_ITEMS), start + window)
    for idx in range(start, end):
        key = CONTROL_ITEMS[idx]
        color = "#00ff88" if idx == control_idx else "#7dd3fc"
        prefix = ">" if idx == control_idx else " "
        draw.text((6, y), f"{prefix} {CONTROL_LABELS[key]}"[:20], font=SMALL_FONT, fill=color)
        y += 10
    if notice:
        draw.line((6, 108, 122, 108), fill="#14532d", width=1)
        draw.text((6, 112), _shorten(notice, 18), font=SMALL_FONT, fill="#a7f3d0")


# ---------------------------------------------------------------------------
# Page: Logs
# ---------------------------------------------------------------------------

def _draw_logs(image: Image.Image, draw: ScaledDraw, state: dict, anim_tick: int) -> None:
    _draw_chrome(draw, "Logs", 8)
    _draw_logo(image, 92, 22)
    _draw_spinner(draw, anim_tick, 113, 49)
    y = 22
    logs = state.get("logs") or []
    if not logs:
        logs = [state.get("error") or "No Ragnar logs yet"]
    for line in logs[-8:]:
        draw.text((6, y), _shorten(line, 20), font=SMALL_FONT, fill="white")
        y += 11
        if y > 116:
            break


# ---------------------------------------------------------------------------
# Screen dispatch
# ---------------------------------------------------------------------------

def _draw_screen(page: str, state: dict, control_idx: int, notice: str | None = None,
                 anim_tick: int = 0, extra: dict | None = None) -> None:
    extra = extra or {}
    image = Image.new("RGB", (WIDTH, HEIGHT), "black")
    draw = ScaledDraw(image)
    if page == "overview":
        _draw_overview(image, draw, state, anim_tick)
    elif page == "stats":
        _draw_stats(image, draw, extra.get("stats", {}), anim_tick)
    elif page == "targets":
        _draw_targets(image, draw, extra.get("targets", []), extra.get("target_scroll", 0), anim_tick)
    elif page == "credentials":
        _draw_credentials(image, draw, extra.get("creds", []), extra.get("cred_scroll", 0), anim_tick)
    elif page == "attacks":
        _draw_attacks(image, draw, extra.get("targets", []), extra.get("attack_target_idx", 0),
                      extra.get("attack_type_idx", 0), notice, anim_tick)
    elif page == "wifi":
        _draw_wifi(image, draw, extra.get("wifi_status", {}), extra.get("wifi_nets", []),
                   extra.get("wifi_idx", 0), notice, anim_tick)
    elif page == "address":
        _draw_address(image, draw, state, anim_tick)
    elif page == "controls":
        _draw_controls(image, draw, control_idx, notice, anim_tick)
    else:
        _draw_logs(image, draw, state, anim_tick)
    LCD.LCD_ShowImage(image, 0, 0)


def _draw_message_screen(title: str, lines: list[str], footer: str | None = None) -> None:
    image = Image.new("RGB", (WIDTH, HEIGHT), "black")
    draw = ImageDraw.Draw(image)
    draw.rectangle((2, 2, WIDTH - 3, HEIGHT - 3), outline="#05ff00", width=1)
    try:
        draw.text((6, 5), title, font=FONT, fill="#00ff88")
    except Exception:
        draw.text((6, 5), title, fill="white")
    y = 22
    for line in lines[:8]:
        try:
            draw.text((6, y), line[:20], font=SMALL_FONT, fill="white")
        except Exception:
            draw.text((6, y), line[:20], fill="white")
        y += 11
    if footer:
        try:
            draw.text((6, HEIGHT - 14), footer[:20], font=SMALL_FONT, fill="#fcd34d")
        except Exception:
            draw.text((6, HEIGHT - 14), footer[:20], fill="white")
    LCD.LCD_ShowImage(image, 0, 0)


def _show_fatal_screen(exc: Exception) -> None:
    _log_ui_error(exc)
    # Truncate error details to avoid leaking sensitive info on-screen
    sanitized = f"{exc.__class__.__name__}: {str(exc)[:50]}"
    lines = _simple_wrap(sanitized, width=18, limit=6)
    if not lines:
        lines = ["Unknown Ragnar UI", "error"]
    _draw_message_screen("Ragnar Error", lines, "KEY3 exit")


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main() -> None:
    _init_display()
    _draw_message_screen("Ragnar", ["Loading UI...", "Please wait"], "KEY3 exit")
    page_idx = 0
    control_idx = 0
    notice = "LT/RT pages"
    notice_until = time.monotonic() + 3
    last_render_key = None
    last_refresh = 0.0
    state = _fetch_state()

    # Per-page scroll/selection indices
    target_scroll = 0
    cred_scroll = 0
    attack_target_idx = 0
    attack_type_idx = 0
    wifi_idx = 0

    # Lazily fetched data (refreshed on page enter or action)
    cached_stats: dict = {}
    cached_targets: list = []
    cached_creds: list = []
    cached_wifi_nets: list = []
    cached_wifi_status: dict = {}
    last_detail_fetch = 0.0  # tracks when detail data was last pulled

    def _refresh_detail_data():
        nonlocal cached_stats, cached_targets, cached_creds
        nonlocal cached_wifi_nets, cached_wifi_status, last_detail_fetch
        page = PAGES[page_idx]
        now = time.monotonic()
        if now - last_detail_fetch < 3.0:
            return
        last_detail_fetch = now
        if page == "stats":
            cached_stats = _fetch_stats()
        elif page in ("targets", "attacks"):
            cached_targets = _fetch_targets()
        elif page == "credentials":
            cached_creds = _fetch_credentials()
        elif page == "wifi":
            cached_wifi_nets = _fetch_wifi_networks()
            cached_wifi_status = _fetch_wifi_status()

    try:
        while True:
            now = time.monotonic()
            if now - last_refresh > 2.0:
                state = _fetch_state()
                last_refresh = now
                _refresh_detail_data()

            shown_notice = notice if now < notice_until else None
            anim_step = int(now * 4)

            extra = {
                "stats": cached_stats,
                "targets": cached_targets,
                "creds": cached_creds,
                "target_scroll": target_scroll,
                "cred_scroll": cred_scroll,
                "attack_target_idx": attack_target_idx,
                "attack_type_idx": attack_type_idx,
                "wifi_status": cached_wifi_status,
                "wifi_nets": cached_wifi_nets,
                "wifi_idx": wifi_idx,
            }

            render_key = (
                PAGES[page_idx],
                control_idx,
                shown_notice,
                anim_step,
                state["running"],
                state["api_ok"],
                state["manual_mode"],
                state["automation_enabled"],
                state["target_count"],
                state["port_count"],
                state["vulnerability_count"],
                state["current_ssid"],
                state["orchestrator_status"],
                state["ragnar_status2"],
                tuple(state.get("logs") or []),
                state["error"],
                target_scroll,
                cred_scroll,
                attack_target_idx,
                attack_type_idx,
                wifi_idx,
                len(cached_targets),
                len(cached_creds),
                len(cached_wifi_nets),
            )
            if render_key != last_render_key:
                _draw_screen(PAGES[page_idx], state, control_idx, shown_notice, anim_step, extra)
                last_render_key = render_key

            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                break

            cur_page = PAGES[page_idx]

            # ---- LEFT/RIGHT: always change page ----
            if btn == "LEFT":
                old_page = page_idx
                page_idx = (page_idx - 1) % len(PAGES)
                if page_idx != old_page:
                    last_detail_fetch = 0.0
                    _refresh_detail_data()
            elif btn == "RIGHT":
                old_page = page_idx
                page_idx = (page_idx + 1) % len(PAGES)
                if page_idx != old_page:
                    last_detail_fetch = 0.0
                    _refresh_detail_data()

            # ---- UP/DOWN: scroll / select within page ----
            elif btn == "UP":
                if cur_page == "targets":
                    target_scroll = max(0, target_scroll - 1)
                elif cur_page == "credentials":
                    cred_scroll = max(0, cred_scroll - 1)
                elif cur_page == "attacks":
                    attack_target_idx = max(0, attack_target_idx - 1)
                elif cur_page == "wifi":
                    wifi_idx = max(0, wifi_idx - 1)
                elif cur_page == "controls":
                    control_idx = (control_idx - 1) % len(CONTROL_ITEMS)
            elif btn == "DOWN":
                if cur_page == "targets":
                    target_scroll = min(max(0, len(cached_targets) - 1), target_scroll + 1)
                elif cur_page == "credentials":
                    cred_scroll = min(max(0, len(cached_creds) - 1), cred_scroll + 1)
                elif cur_page == "attacks":
                    attack_target_idx = min(max(0, len(cached_targets) - 1), attack_target_idx + 1)
                elif cur_page == "wifi":
                    wifi_idx = min(max(0, len(cached_wifi_nets) - 1), wifi_idx + 1)
                elif cur_page == "controls":
                    control_idx = (control_idx + 1) % len(CONTROL_ITEMS)

            # ---- OK: confirm / select / refresh ----
            elif btn == "OK":
                if cur_page == "controls":
                    ok, notice = _run_control(CONTROL_ITEMS[control_idx])
                    notice_until = time.monotonic() + (4 if ok else 6)
                    state = _fetch_state()
                    last_refresh = time.monotonic()
                elif cur_page == "attacks":
                    if cached_targets and 0 <= attack_target_idx < len(cached_targets):
                        t = cached_targets[attack_target_idx]
                        ports = t.get("ports", "")
                        first_port = ports.split(",")[0].strip() if ports else ""
                        ok, notice = _run_attack(
                            t["ip"], first_port, ATTACK_TYPES[attack_type_idx]
                        )
                        notice_until = time.monotonic() + (4 if ok else 6)
                    else:
                        notice = "No target selected"
                        notice_until = time.monotonic() + 3
                elif cur_page == "wifi":
                    if cached_wifi_nets and 0 <= wifi_idx < len(cached_wifi_nets):
                        ssid = cached_wifi_nets[wifi_idx].get("ssid", "")
                        if ssid:
                            ok, notice = _wifi_connect(ssid)
                            notice_until = time.monotonic() + (4 if ok else 6)
                    else:
                        notice = "No network selected"
                        notice_until = time.monotonic() + 3
                else:
                    state = _fetch_state()
                    last_detail_fetch = 0.0
                    _refresh_detail_data()
                    notice = "Refreshed"
                    notice_until = time.monotonic() + 2

            # ---- KEY1: primary action per page ----
            elif btn == "KEY1":
                if cur_page == "wifi":
                    ok, notice = _wifi_scan()
                    notice_until = time.monotonic() + 3
                    if ok:
                        time.sleep(2)
                        cached_wifi_nets = _fetch_wifi_networks()
                elif cur_page == "attacks":
                    # Cycle attack type
                    attack_type_idx = (attack_type_idx + 1) % len(ATTACK_TYPES)
                elif cur_page == "controls":
                    ok, notice = _run_control(CONTROL_ITEMS[control_idx])
                    notice_until = time.monotonic() + (4 if ok else 6)
                    state = _fetch_state()
                    last_refresh = time.monotonic()
                else:
                    state = _fetch_state()
                    last_detail_fetch = 0.0
                    _refresh_detail_data()
                    notice = "Refreshed"
                    notice_until = time.monotonic() + 2

            # ---- KEY2: secondary action / refresh ----
            elif btn == "KEY2":
                if cur_page == "wifi":
                    ok, notice = _wifi_disconnect()
                    notice_until = time.monotonic() + 3
                    cached_wifi_status = _fetch_wifi_status()
                else:
                    state = _fetch_state()
                    last_detail_fetch = 0.0
                    _refresh_detail_data()
                    notice = "Refreshed"
                    notice_until = time.monotonic() + 2

            time.sleep(0.08)
    except Exception as exc:
        _show_fatal_screen(exc)
        while True:
            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                break
            time.sleep(0.08)
    finally:
        try:
            if LCD is not None:
                LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        _log_ui_error(exc)
        try:
            if LCD is None:
                _init_display()
            _show_fatal_screen(exc)
            while True:
                btn = get_button(PINS, GPIO)
                if btn == "KEY3":
                    break
                time.sleep(0.08)
        finally:
            try:
                if LCD is not None:
                    LCD.LCD_Clear()
            except Exception:
                pass
            GPIO.cleanup()
