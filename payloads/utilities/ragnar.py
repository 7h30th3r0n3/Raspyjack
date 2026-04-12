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

PAGES = ("overview", "address", "controls", "logs")
CONTROL_ITEMS = (
    "start_app",
    "stop_app",
    "automation_on",
    "automation_off",
    "manual_on",
    "manual_off",
    "scan_network",
    "scan_vulns",
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
    return text[: limit - 1] + "…"


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
        "current_ssid": "",
        "orchestrator_status": "",
        "ragnar_status": "",
        "ragnar_status2": "",
        "error": "",
        "logs": _tail_log(4),
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
    state["current_ssid"] = str(data.get("current_ssid", "") or "")
    state["orchestrator_status"] = str(data.get("orchestrator_status", "") or "")
    state["ragnar_status"] = str(data.get("ragnar_status", "") or "")
    state["ragnar_status2"] = str(data.get("ragnar_status2", "") or "")
    return state


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
    }
    path, payload = mapping[action]
    ok, data = _api_json(path, method="POST", payload=payload)
    if ok and (data.get("success") is True or data.get("ok") is True or "message" in data):
        return True, _shorten(data.get("message", CONTROL_LABELS[action]), 24)
    return False, _shorten(data.get("error", "Action failed"), 24)


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
        _shorten(state['ragnar_status2'] or state['error'] or "UP/DN pages", 18),
    ]
    for line in lines:
        draw.text((6, y), line, font=SMALL_FONT, fill="white")
        y += 11


def _draw_address(image: Image.Image, draw: ScaledDraw, state: dict, anim_tick: int) -> None:
    _draw_chrome(draw, "Address", 1)
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


def _draw_controls(image: Image.Image, draw: ScaledDraw, control_idx: int, notice: str | None, anim_tick: int) -> None:
    _draw_chrome(draw, "Controls", 2)
    _draw_logo(image, 92, 22)
    _draw_spinner(draw, anim_tick, 113, 49)
    y = 22
    draw.text((6, y), CONTROL_LABELS[CONTROL_ITEMS[control_idx]], font=SMALL_FONT, fill="#fcd34d")
    y += 14
    draw.text((6, y), "LT/RT pick", font=SMALL_FONT, fill="white")
    y += 11
    draw.text((6, y), "K1 or OK run", font=SMALL_FONT, fill="white")
    y += 11
    draw.text((6, y), "UP/DN page", font=SMALL_FONT, fill="white")
    y += 14
    window = 4
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


def _draw_logs(image: Image.Image, draw: ScaledDraw, state: dict, anim_tick: int) -> None:
    _draw_chrome(draw, "Logs", 3)
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


def _draw_screen(page: str, state: dict, control_idx: int, notice: str | None = None, anim_tick: int = 0) -> None:
    image = Image.new("RGB", (WIDTH, HEIGHT), "black")
    draw = ScaledDraw(image)
    if page == "overview":
        _draw_overview(image, draw, state, anim_tick)
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
    lines = _simple_wrap(f"{exc.__class__.__name__}: {exc}", width=18, limit=6)
    if not lines:
        lines = ["Unknown Ragnar UI", "error"]
    _draw_message_screen("Ragnar Error", lines, "KEY3 exit")


def main() -> None:
    _init_display()
    _draw_message_screen("Ragnar", ["Loading UI...", "Please wait"], "KEY3 exit")
    page_idx = 0
    control_idx = 0
    notice = "UP/DN pages"
    notice_until = time.monotonic() + 3
    last_render_key = None
    last_refresh = 0.0
    last_anim_step = -1
    state = _fetch_state()

    try:
        while True:
            now = time.monotonic()
            if now - last_refresh > 2.0:
                state = _fetch_state()
                last_refresh = now

            shown_notice = notice if now < notice_until else None
            anim_step = int(now * 4)
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
            )
            if render_key != last_render_key:
                _draw_screen(PAGES[page_idx], state, control_idx, shown_notice, anim_step)
                last_render_key = render_key
                last_anim_step = anim_step

            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                break
            if btn == "UP":
                page_idx = (page_idx - 1) % len(PAGES)
            elif btn == "DOWN":
                page_idx = (page_idx + 1) % len(PAGES)
            elif btn == "LEFT" and PAGES[page_idx] == "controls":
                control_idx = (control_idx - 1) % len(CONTROL_ITEMS)
            elif btn == "RIGHT" and PAGES[page_idx] == "controls":
                control_idx = (control_idx + 1) % len(CONTROL_ITEMS)
            elif btn in {"KEY1", "OK"}:
                if PAGES[page_idx] == "controls":
                    ok, notice = _run_control(CONTROL_ITEMS[control_idx])
                    notice_until = time.monotonic() + (4 if ok else 6)
                    state = _fetch_state()
                    last_refresh = time.monotonic()
                else:
                    state = _fetch_state()
                    notice = "Refreshed"
                    notice_until = time.monotonic() + 2
            elif btn == "KEY2":
                state = _fetch_state()
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
