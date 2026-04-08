#!/usr/bin/env python3
"""
RaspyJack Payload -- Minimal IRC Client
=========================================
Author: 7h30th3r0n3

Connects to an IRC server and displays channel messages on the LCD.
Supports sending messages via character picker, viewing user lists,
and switching between channels.

Controls:
  UP / DOWN    -- Scroll messages
  LEFT / RIGHT -- Switch channel
  OK           -- Open character picker to type message
  KEY1         -- Send typed message
  KEY2         -- Show / hide user list
  KEY3         -- Exit

Config: /root/Raspyjack/loot/IRC/config.json
"""

import os
import sys
import json
import time
import signal
import socket
import threading
import random

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROW_H = 12
CONFIG_DIR = "/root/Raspyjack/loot/IRC"
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
MAX_MESSAGES = 100
CHARSET = list(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789 .-_/:@?!#&=+,"
)

DEFAULT_CONFIG = {
    "server": "irc.libera.chat",
    "port": 6667,
    "nick": None,  # Generated at runtime
    "channels": ["#raspyjack"],
}

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
running = True
irc_sock = None
sock_lock = threading.Lock()

server = "irc.libera.chat"
port = 6667
nick = ""
channels = ["#raspyjack"]
channel_idx = 0

# Per-channel message buffers: {channel: [{"nick": str, "text": str}]}
messages = {}
# Per-channel user lists: {channel: [str]}
users = {}

scroll_offset = 0
view_mode = "chat"  # "chat", "input", "users"
input_chars = []
input_char_idx = 0
connected = False
status_msg = "Connecting..."


def cleanup(*_args):
    global running
    running = False


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def generate_nick():
    """Generate a random nick like RaspyJack_1234."""
    digits = random.randint(1000, 9999)
    return f"RaspyJack_{digits}"


def load_config():
    global server, port, nick, channels
    try:
        with open(CONFIG_PATH, "r") as f:
            cfg = json.load(f)
        server = cfg.get("server", "irc.libera.chat")
        port = cfg.get("port", 6667)
        nick = cfg.get("nick", "") or generate_nick()
        loaded_channels = cfg.get("channels", ["#raspyjack"])
        if isinstance(loaded_channels, list) and loaded_channels:
            channels = loaded_channels
    except Exception:
        nick = generate_nick()


def save_config():
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        cfg = {
            "server": server,
            "port": port,
            "nick": nick,
            "channels": channels,
        }
        with open(CONFIG_PATH, "w") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# IRC protocol helpers
# ---------------------------------------------------------------------------


def irc_send(line):
    """Send a raw IRC line."""
    with sock_lock:
        if irc_sock is not None:
            try:
                irc_sock.sendall((line + "\r\n").encode("utf-8", errors="replace"))
            except Exception:
                pass


def add_message(channel, nick_name, text):
    """Add a message to a channel buffer."""
    if channel not in messages:
        messages[channel] = []
    messages[channel] = messages[channel] + [{"nick": nick_name, "text": text}]
    # Trim to MAX_MESSAGES
    if len(messages[channel]) > MAX_MESSAGES:
        messages[channel] = messages[channel][-MAX_MESSAGES:]


def current_channel():
    """Return the currently selected channel name."""
    if not channels:
        return "#raspyjack"
    return channels[channel_idx % len(channels)]


def current_messages():
    """Return messages for the current channel."""
    return messages.get(current_channel(), [])


def current_users():
    """Return user list for the current channel."""
    return users.get(current_channel(), [])


# ---------------------------------------------------------------------------
# IRC receive thread
# ---------------------------------------------------------------------------


def irc_receive_thread():
    """Background thread to read IRC messages."""
    global connected, status_msg, running
    buf = ""

    while running:
        with sock_lock:
            sock = irc_sock
        if sock is None:
            time.sleep(0.1)
            continue

        try:
            data = sock.recv(4096)
        except socket.timeout:
            continue
        except Exception:
            status_msg = "Disconnected"
            connected = False
            break

        if not data:
            status_msg = "Disconnected"
            connected = False
            break

        buf += data.decode("utf-8", errors="replace")
        while "\r\n" in buf:
            line, buf = buf.split("\r\n", 1)
            handle_irc_line(line)


def handle_irc_line(line):
    """Parse and handle a single IRC line."""
    global connected, status_msg

    # PING/PONG keepalive
    if line.startswith("PING"):
        payload = line[5:] if len(line) > 5 else ""
        irc_send(f"PONG {payload}")
        return

    parts = line.split(" ")
    if len(parts) < 2:
        return

    prefix = parts[0]
    command = parts[1]

    # RPL_WELCOME (001) - connected successfully
    if command == "001":
        connected = True
        status_msg = "Connected"
        for ch in channels:
            irc_send(f"JOIN {ch}")
        return

    # RPL_NAMREPLY (353) - user list
    if command == "353" and len(parts) >= 5:
        # :server 353 nick = #channel :user1 user2 ...
        chan_part = parts[4]
        user_str = line.split(":", 2)[-1] if line.count(":") >= 2 else ""
        user_list = [u.lstrip("@+%~&") for u in user_str.split() if u]
        if chan_part not in users:
            users[chan_part] = []
        users[chan_part] = users[chan_part] + user_list
        return

    # RPL_ENDOFNAMES (366) - end of user list
    if command == "366":
        return

    # PRIVMSG
    if command == "PRIVMSG" and len(parts) >= 3:
        sender = prefix.split("!")[0].lstrip(":")
        target = parts[2]
        text = line.split(":", 2)[-1] if line.count(":") >= 2 else ""
        channel_name = target if target.startswith("#") else sender
        add_message(channel_name, sender, text)
        return

    # JOIN
    if command == "JOIN":
        sender = prefix.split("!")[0].lstrip(":")
        chan = parts[2].lstrip(":") if len(parts) > 2 else ""
        if chan:
            add_message(chan, "*", f"{sender} joined")
        return

    # PART / QUIT
    if command in ("PART", "QUIT"):
        sender = prefix.split("!")[0].lstrip(":")
        chan = parts[2].lstrip(":") if len(parts) > 2 and command == "PART" else ""
        if chan:
            add_message(chan, "*", f"{sender} left")
            # Remove from user list
            if chan in users:
                users[chan] = [u for u in users[chan] if u != sender]
        return

    # Error messages
    if command in ("433", "432"):
        # Nick in use or erroneous
        status_msg = "Nick error"
        return


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------


def draw_chat(lcd, font):
    """Render the chat message view."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    chan = current_channel()[:12]
    conn_dot = "#00FF00" if connected else "#FF0000"
    d.text((2, 1), chan, font=font, fill="#00CCFF")
    d.rectangle((120, 3, 125, 8), fill=conn_dot)

    # Messages area (y 15 to 114)
    msgs = current_messages()
    max_visible = 8
    if not msgs:
        d.text((2, 40), "No messages yet", font=font, fill="#555")
    else:
        # Build display lines from messages
        display_lines = []
        for m in msgs:
            prefix = f"<{m['nick'][:6]}> " if m["nick"] != "*" else "* "
            text = prefix + m["text"]
            # Wrap long messages
            while len(text) > 21:
                display_lines.append(text[:21])
                text = " " + text[21:]
            display_lines.append(text)

        total = len(display_lines)
        # Auto-scroll to bottom unless user scrolled up
        effective_offset = scroll_offset
        if effective_offset == 0:
            effective_offset = max(0, total - max_visible)

        visible = display_lines[effective_offset:effective_offset + max_visible]
        for i, line in enumerate(visible):
            y = 15 + i * ROW_H
            color = "#CCCCCC"
            if line.startswith("* "):
                color = "#888888"
            elif line.startswith("<"):
                color = "#88CCFF"
            d.text((2, y), line[:22], font=font, fill=color)

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Msg K2:Usr K3:X", font=font, fill="#AAA")

    lcd.LCD_ShowImage(img, 0, 0)


def draw_input(lcd, font):
    """Render the message input character picker."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "TYPE MESSAGE", font=font, fill="#FFAA00")

    # Current message
    msg_str = "".join(input_chars)
    d.text((2, 18), f">{msg_str[-18:]}", font=font, fill="#FFFFFF")

    # Character selector
    current_char = CHARSET[input_char_idx]
    d.text((2, 36), f"Char: [{current_char}]", font=font, fill="#00FF00")
    d.text((2, 48), f"Len: {len(input_chars)}", font=font, fill="#888")

    # Instructions
    d.text((2, 66), "UP/DN: change char", font=font, fill="#555")
    d.text((2, 78), "OK: add char", font=font, fill="#555")
    d.text((2, 90), "LEFT: backspace", font=font, fill="#555")
    d.text((2, 102), "KEY1: send", font=font, fill="#555")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "KEY3: cancel", font=font, fill="#AAA")

    lcd.LCD_ShowImage(img, 0, 0)


def draw_users(lcd, font):
    """Render the user list view."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    chan = current_channel()[:10]
    d.text((2, 1), f"Users: {chan}", font=font, fill="#FFAA00")

    user_list = current_users()
    if not user_list:
        d.text((2, 40), "No users / loading", font=font, fill="#555")
    else:
        max_visible = 8
        visible = user_list[:max_visible]
        for i, u in enumerate(visible):
            y = 15 + i * ROW_H
            d.text((2, y), u[:20], font=font, fill="#88CCFF")
        if len(user_list) > max_visible:
            d.text((80, 1), f"+{len(user_list) - max_visible}", font=font, fill="#888")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "KEY2/KEY3: back", font=font, fill="#AAA")

    lcd.LCD_ShowImage(img, 0, 0)


def draw_connecting(lcd, font):
    """Show connecting screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "IRC CLIENT", font=font, fill="#00CCFF")
    d.text((5, 35), f"Server: {server[:16]}", font=font, fill="#CCCCCC")
    d.text((5, 47), f"Port: {port}", font=font, fill="#CCCCCC")
    d.text((5, 59), f"Nick: {nick[:14]}", font=font, fill="#CCCCCC")
    d.text((5, 75), status_msg[:20], font=font, fill="#FFFF00")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# IRC connection
# ---------------------------------------------------------------------------


def connect_irc():
    """Establish IRC connection and start receive thread."""
    global irc_sock, connected, status_msg

    status_msg = "Connecting..."
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((server, port))
        sock.settimeout(2)
    except Exception as exc:
        status_msg = f"Err: {str(exc)[:16]}"
        return False

    with sock_lock:
        irc_sock = sock

    # Send registration
    irc_send(f"NICK {nick}")
    irc_send(f"USER {nick} 0 * :RaspyJack IRC")

    # Start receive thread
    recv_thread = threading.Thread(target=irc_receive_thread, daemon=True)
    recv_thread.start()

    return True


def disconnect_irc():
    """Cleanly disconnect from IRC."""
    global irc_sock, connected
    irc_send("QUIT :RaspyJack signing off")
    time.sleep(0.3)
    with sock_lock:
        if irc_sock is not None:
            try:
                irc_sock.close()
            except Exception:
                pass
            irc_sock = None
    connected = False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    global running, channel_idx, scroll_offset, view_mode
    global input_chars, input_char_idx, status_msg

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    font = scaled_font()

    load_config()
    save_config()

    # Initialize message buffers
    for ch in channels:
        messages[ch] = []
        users[ch] = []

    # Show connecting screen and attempt connection
    draw_connecting(lcd, font)
    connect_irc()

    # Wait briefly for connection
    wait_start = time.time()
    while not connected and running and (time.time() - wait_start) < 12:
        draw_connecting(lcd, font)
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            disconnect_irc()
            try:
                lcd.LCD_Clear()
            except Exception:
                pass
            GPIO.cleanup()
            return 0
        time.sleep(0.3)

    try:
        while running:
            btn = get_button(PINS, GPIO)

            # Input mode
            if view_mode == "input":
                if btn == "UP":
                    input_char_idx = (input_char_idx + 1) % len(CHARSET)
                    time.sleep(0.1)
                elif btn == "DOWN":
                    input_char_idx = (input_char_idx - 1) % len(CHARSET)
                    time.sleep(0.1)
                elif btn == "OK":
                    input_chars = input_chars + [CHARSET[input_char_idx]]
                    time.sleep(0.12)
                elif btn == "LEFT":
                    if input_chars:
                        input_chars = input_chars[:-1]
                    time.sleep(0.12)
                elif btn == "KEY1":
                    msg_text = "".join(input_chars).strip()
                    if msg_text and connected:
                        chan = current_channel()
                        irc_send(f"PRIVMSG {chan} :{msg_text}")
                        add_message(chan, nick, msg_text)
                        input_chars = []
                    view_mode = "chat"
                    scroll_offset = 0
                    time.sleep(0.2)
                    continue
                elif btn == "KEY3":
                    input_chars = []
                    view_mode = "chat"
                    time.sleep(0.2)
                    continue

                draw_input(lcd, font)
                time.sleep(0.05)
                continue

            # User list mode
            if view_mode == "users":
                if btn in ("KEY2", "KEY3"):
                    view_mode = "chat"
                    time.sleep(0.2)
                    continue

                draw_users(lcd, font)
                time.sleep(0.1)
                continue

            # Chat mode controls
            if btn == "UP":
                msgs = current_messages()
                if scroll_offset > 0:
                    scroll_offset -= 1
                elif msgs:
                    # Enable manual scroll from auto-scroll
                    scroll_offset = max(0, len(msgs) - 8 - 1)
                time.sleep(0.15)
            elif btn == "DOWN":
                scroll_offset = 0  # Return to auto-scroll (bottom)
                time.sleep(0.15)
            elif btn == "LEFT":
                channel_idx = (channel_idx - 1) % len(channels)
                scroll_offset = 0
                # Request user list for new channel
                irc_send(f"NAMES {current_channel()}")
                time.sleep(0.25)
            elif btn == "RIGHT":
                channel_idx = (channel_idx + 1) % len(channels)
                scroll_offset = 0
                irc_send(f"NAMES {current_channel()}")
                time.sleep(0.25)
            elif btn == "OK":
                view_mode = "input"
                input_chars = []
                input_char_idx = 0
                time.sleep(0.2)
                continue
            elif btn == "KEY2":
                irc_send(f"NAMES {current_channel()}")
                view_mode = "users"
                time.sleep(0.3)
                continue
            elif btn == "KEY3":
                break

            if connected:
                draw_chat(lcd, font)
            else:
                draw_connecting(lcd, font)

            time.sleep(0.1)

    finally:
        disconnect_irc()
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
