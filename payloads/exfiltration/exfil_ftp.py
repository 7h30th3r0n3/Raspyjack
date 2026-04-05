#!/usr/bin/env python3
"""
RaspyJack Payload -- Mini FTP Server for Loot Retrieval
=========================================================
Author: 7h30th3r0n3

Lightweight FTP server serving /root/Raspyjack/loot/ read-only.
Uses ``pyftpdlib`` when available; otherwise falls back to a minimal
socket-based FTP server supporting LIST, RETR, PWD, CWD, TYPE, PASV,
and QUIT.

Setup / Prerequisites
---------------------
- ``pyftpdlib`` recommended (``pip install pyftpdlib``).
- Port 21 (or configured port) must be available.

Controls
--------
  OK          -- Start / stop server
  KEY1        -- Toggle anonymous / auth mode
  UP / DOWN   -- Scroll transfer log
  KEY3        -- Exit
"""

import os
import sys
import time
import json
import socket
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
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
LOOT_ROOT = "/root/Raspyjack/loot"
CONFIG_DIR = "/root/Raspyjack/config/exfil_ftp"
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
os.makedirs(CONFIG_DIR, exist_ok=True)

FTP_PORT = 21
DEBOUNCE = 0.22
DEFAULT_CONFIG = {
    "port": FTP_PORT,
    "anonymous": True,
    "username": "raspy",
    "password": "jack",
}

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_state = {
    "config": dict(DEFAULT_CONFIG),
    "running": False,
    "stop": False,
    "status": "Idle",
    "clients": 0,
    "downloads": 0,
    "pi_ip": "",
    "log": [],
    "scroll": 0,
    "anonymous": True,
}


def _get(key):
    with _lock:
        val = _state[key]
        if isinstance(val, (list, dict)):
            return list(val) if isinstance(val, list) else dict(val)
        return val


def _set(**kw):
    with _lock:
        for k, v in kw.items():
            _state[k] = v


def _add_log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    entry = f"[{ts}] {msg}"
    with _lock:
        _state["log"] = (list(_state["log"]) + [entry])[-40:]


def _inc(key, amount=1):
    with _lock:
        _state[key] = _state[key] + amount


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
def _load_config():
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                loaded = json.load(f)
            _set(config={**DEFAULT_CONFIG, **loaded})
        except Exception:
            _set(config=dict(DEFAULT_CONFIG))
    else:
        _set(config=dict(DEFAULT_CONFIG))
        _save_config()
    _set(anonymous=_get("config").get("anonymous", True))


def _save_config():
    cfg = _get("config")
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# pyftpdlib server
# ---------------------------------------------------------------------------
def _has_pyftpdlib():
    try:
        import pyftpdlib  # noqa: F401
        return True
    except ImportError:
        return False


def _run_pyftpdlib():
    """Run FTP server using pyftpdlib."""
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.servers import FTPServer
    from pyftpdlib.authorizers import DummyAuthorizer

    cfg = _get("config")
    port = cfg.get("port", FTP_PORT)
    anon = _get("anonymous")

    authorizer = DummyAuthorizer()
    if anon:
        authorizer.add_anonymous(LOOT_ROOT, perm="elr")
    else:
        authorizer.add_user(
            cfg.get("username", "raspy"),
            cfg.get("password", "jack"),
            LOOT_ROOT, perm="elr",
        )

    handler = FTPHandler
    handler.authorizer = authorizer
    handler.banner = "RaspyJack FTP Loot Server"
    handler.passive_ports = range(60000, 60100)

    ip = _get_pi_ip()
    _set(pi_ip=ip, running=True, status=f"FTP on {ip}:{port}")
    _add_log(f"pyftpdlib on {ip}:{port}")

    server = FTPServer(("0.0.0.0", port), handler)
    server.max_cons = 10
    server.max_cons_per_ip = 3

    # Run in a way we can stop
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    while not _get("stop"):
        time.sleep(0.5)

    server.close_all()
    _set(running=False, status="FTP stopped")
    _add_log("FTP server stopped")


# ---------------------------------------------------------------------------
# Minimal socket-based FTP server (fallback)
# ---------------------------------------------------------------------------
def _run_socket_ftp():
    """Minimal FTP server using raw sockets."""
    cfg = _get("config")
    port = cfg.get("port", FTP_PORT)
    anon = _get("anonymous")
    username = cfg.get("username", "raspy")
    password = cfg.get("password", "jack")

    ip = _get_pi_ip()
    _set(pi_ip=ip, running=True, status=f"FTP on {ip}:{port}")
    _add_log(f"Socket FTP on {ip}:{port}")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.settimeout(1.0)

    try:
        srv.bind(("0.0.0.0", port))
        srv.listen(5)
    except OSError as exc:
        _set(running=False, status=f"Bind fail: {exc}")
        _add_log(f"Bind error: {exc}")
        return

    while not _get("stop"):
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        _inc("clients")
        _add_log(f"Client: {addr[0]}")
        threading.Thread(
            target=_handle_ftp_client,
            args=(conn, addr, anon, username, password),
            daemon=True,
        ).start()

    srv.close()
    _set(running=False, status="FTP stopped")
    _add_log("FTP stopped")


def _handle_ftp_client(conn, addr, anon, username, password):
    """Handle a single FTP client session."""
    cwd = LOOT_ROOT
    authenticated = anon
    data_sock = None
    pasv_sock = None

    def _send(msg):
        try:
            conn.sendall((msg + "\r\n").encode())
        except Exception:
            pass

    def _safe_path(path):
        """Resolve path safely within LOOT_ROOT."""
        if path.startswith("/"):
            resolved = os.path.normpath(os.path.join(LOOT_ROOT, path.lstrip("/")))
        else:
            resolved = os.path.normpath(os.path.join(cwd, path))
        if not resolved.startswith(LOOT_ROOT):
            return None
        return resolved

    conn.settimeout(60)
    _send("220 RaspyJack FTP Loot Server")

    try:
        while not _get("stop"):
            try:
                raw = conn.recv(1024)
            except socket.timeout:
                continue
            except Exception:
                break

            if not raw:
                break

            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue

            parts = line.split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1].strip() if len(parts) > 1 else ""

            if cmd == "USER":
                if anon or arg == username:
                    _send("331 Password required" if not anon else "230 Logged in")
                    if anon:
                        authenticated = True
                else:
                    _send("530 Invalid user")

            elif cmd == "PASS":
                if anon or arg == password:
                    authenticated = True
                    _send("230 Logged in")
                else:
                    _send("530 Login incorrect")

            elif not authenticated:
                _send("530 Please login first")

            elif cmd == "SYST":
                _send("215 UNIX Type: L8")

            elif cmd == "FEAT":
                _send("211-Features:\r\n PASV\r\n UTF8\r\n211 End")

            elif cmd == "PWD":
                rel = "/" + os.path.relpath(cwd, LOOT_ROOT)
                if rel == "/.":
                    rel = "/"
                _send(f'257 "{rel}" is current directory')

            elif cmd == "CWD":
                target = _safe_path(arg)
                if target and os.path.isdir(target):
                    cwd = target
                    _send("250 Directory changed")
                else:
                    _send("550 Failed to change directory")

            elif cmd == "CDUP":
                parent = os.path.dirname(cwd)
                if parent.startswith(LOOT_ROOT):
                    cwd = parent
                _send("250 Directory changed")

            elif cmd == "TYPE":
                _send("200 Type set")

            elif cmd == "PASV":
                if pasv_sock:
                    pasv_sock.close()
                pasv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                pasv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                pasv_sock.bind(("0.0.0.0", 0))
                pasv_sock.listen(1)
                pasv_sock.settimeout(10)
                p_ip = _get("pi_ip").replace(".", ",")
                p_port = pasv_sock.getsockname()[1]
                p1 = p_port >> 8
                p2 = p_port & 0xFF
                _send(f"227 Entering Passive Mode ({p_ip},{p1},{p2})")

            elif cmd == "LIST":
                if not pasv_sock:
                    _send("425 Use PASV first")
                    continue
                _send("150 Opening data connection")
                try:
                    data_sock, _ = pasv_sock.accept()
                    listing = ""
                    target = _safe_path(arg) if arg else cwd
                    if target and os.path.isdir(target):
                        for entry in sorted(os.listdir(target)):
                            epath = os.path.join(target, entry)
                            if os.path.isdir(epath):
                                listing += f"drwxr-xr-x 1 ftp ftp 0 Jan 01 00:00 {entry}\r\n"
                            else:
                                sz = os.path.getsize(epath)
                                listing += f"-rw-r--r-- 1 ftp ftp {sz} Jan 01 00:00 {entry}\r\n"
                    data_sock.sendall(listing.encode())
                    data_sock.close()
                    data_sock = None
                    _send("226 Transfer complete")
                except Exception:
                    _send("426 Connection closed")

            elif cmd == "RETR":
                target = _safe_path(arg)
                if not target or not os.path.isfile(target):
                    _send("550 File not found")
                    continue
                if not pasv_sock:
                    _send("425 Use PASV first")
                    continue
                _send("150 Opening data connection")
                try:
                    data_sock, _ = pasv_sock.accept()
                    with open(target, "rb") as f:
                        while True:
                            chunk = f.read(8192)
                            if not chunk:
                                break
                            data_sock.sendall(chunk)
                    data_sock.close()
                    data_sock = None
                    _send("226 Transfer complete")
                    _inc("downloads")
                    _add_log(f"DL: {os.path.basename(target)}")
                except Exception:
                    _send("426 Connection closed")

            elif cmd == "SIZE":
                target = _safe_path(arg)
                if target and os.path.isfile(target):
                    _send(f"213 {os.path.getsize(target)}")
                else:
                    _send("550 File not found")

            elif cmd == "QUIT":
                _send("221 Goodbye")
                break

            elif cmd == "NOOP":
                _send("200 OK")

            else:
                _send(f"502 Command {cmd} not implemented")

    except Exception:
        pass
    finally:
        if data_sock:
            data_sock.close()
        if pasv_sock:
            pasv_sock.close()
        conn.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _get_pi_ip():
    try:
        out = subprocess.run(
            ["hostname", "-I"], capture_output=True, text=True, timeout=5,
        )
        import subprocess  # noqa: already imported
        ips = out.stdout.strip().split()
        return ips[0] if ips else "?.?.?.?"
    except Exception:
        return "?.?.?.?"


def _start_server():
    if _get("running"):
        return
    if _has_pyftpdlib():
        threading.Thread(target=_run_pyftpdlib, daemon=True).start()
    else:
        threading.Thread(target=_run_socket_ftp, daemon=True).start()


def _stop_server():
    _set(stop=True)


# ---------------------------------------------------------------------------
# LCD drawing
# ---------------------------------------------------------------------------
def _draw_lcd():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    running = _get("running")
    status = _get("status")
    log = _get("log")
    scroll = _get("scroll")
    anon = _get("anonymous")
    pi_ip = _get("pi_ip") or "?.?.?.?"
    clients = _get("clients")
    downloads = _get("downloads")

    # Header
    d.rectangle((0, 0, 127, 12), fill="#111")
    auth_txt = "ANON" if anon else "AUTH"
    d.text((2, 1), f"FTP SERVER [{auth_txt}]", font=font, fill="#00FF88")
    d.ellipse((118, 3, 124, 9), fill="#00FF00" if running else "#666")

    y = 14
    d.text((2, y), f"IP: {pi_ip}", font=font, fill="#AAAAAA")
    y += 12
    d.text((2, y), f"Clients: {clients}  DL: {downloads}", font=font, fill="#888")
    y += 14

    # Log
    visible = 4
    start = max(0, len(log) - visible - scroll)
    end = min(start + visible, len(log))
    for i in range(start, end):
        fg = "#888"
        if "DL:" in log[i]:
            fg = "#00AAFF"
        elif "Client" in log[i]:
            fg = "#FFAA00"
        d.text((2, y), log[i][:21], font=font, fill=fg)
        y += 11

    # Status
    d.rectangle((0, 106, 127, 115), fill="#0a0a0a")
    d.text((2, 107), status[:21], font=font, fill="#FFCC00")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    action = "STOP" if running else "START"
    d.text((2, 117), f"OK:{action} K1:auth K3:x", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    _load_config()

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 16), "FTP LOOT SERVER", font=font, fill="#00FF88")
    d.text((4, 32), "Serve loot via FTP", font=font, fill="#888")
    d.text((4, 52), "OK=Start/Stop", font=font, fill="#666")
    d.text((4, 64), "K1=Toggle auth mode", font=font, fill="#666")
    d.text((4, 76), "U/D=Scroll log", font=font, fill="#666")
    d.text((4, 88), "K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    _set(pi_ip=_get_pi_ip())
    last_press = 0.0

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if btn == "KEY3":
                _stop_server()
                break

            elif btn == "OK":
                if _get("running"):
                    _stop_server()
                else:
                    _set(stop=False)
                    _start_server()

            elif btn == "KEY1":
                if not _get("running"):
                    anon = _get("anonymous")
                    _set(anonymous=not anon)
                    mode = "Anonymous" if not anon else "Auth"
                    _add_log(f"Mode: {mode}")
                    cfg = _get("config")
                    cfg["anonymous"] = not anon
                    _set(config=cfg)
                    _save_config()

            elif btn == "UP":
                s = _get("scroll")
                _set(scroll=min(max(0, len(_get("log")) - 4), s + 1))

            elif btn == "DOWN":
                s = _get("scroll")
                _set(scroll=max(0, s - 1))

            _draw_lcd()
            time.sleep(0.05)

    finally:
        _stop_server()
        time.sleep(0.3)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
