#!/usr/bin/env python3
"""
RaspyJack Payload -- TCP Port Forwarder
========================================
Author: 7h30th3r0n3

Forward a local port to a remote host:port.  Supports multiple
simultaneous forwarding rules with bidirectional TCP relay.

Controls:
  OK         -- Start / stop forwarding for current rule
  UP / DOWN  -- Adjust selected field value
  LEFT/RIGHT -- Move between fields (local port, remote host, remote port)
  KEY1       -- Add another forward rule
  KEY2       -- Show active rules
  KEY3       -- Exit

Loot: none (service tool, no data to loot)
"""

import os
import sys
import socket
import select
import time
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
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
BUFFER_SIZE = 4096

# ---------------------------------------------------------------------------
# Forward rule data structure
# ---------------------------------------------------------------------------
# Each rule: {"local_port", "remote_host", "remote_port", "active",
#             "server_sock", "bytes_fwd", "conn_count"}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True

rules = []          # list of rule dicts
current_rule = 0    # index into rules
edit_field = 0      # 0=local_port, 1=remote_host_octet, 2=remote_port
view_mode = "config"  # "config" | "rules"

# For remote host editing, we store octets separately
# Each rule stores remote_host as "A.B.C.D"
# edit_field 1 cycles through sub-positions via LEFT/RIGHT
host_octet_idx = 0  # 0-3 for each octet of the IP

# Field indices: 0=local_port, 1=host_octet_0, 2=host_octet_1,
#                3=host_octet_2, 4=host_octet_3, 5=remote_port
FIELD_COUNT = 6

# Actual edit cursor position (0-5)
cursor_pos = 0


def _new_rule():
    """Create a new default forwarding rule."""
    return {
        "local_port": 8080,
        "remote_host": "192.168.1.1",
        "remote_port": 80,
        "active": False,
        "server_sock": None,
        "bytes_fwd": 0,
        "conn_count": 0,
    }


def _parse_octets(ip_str):
    """Parse IP string into list of 4 ints."""
    try:
        parts = ip_str.split(".")
        return [int(p) for p in parts[:4]]
    except Exception:
        return [192, 168, 1, 1]


def _octets_to_str(octets):
    """Convert 4 int octets to IP string."""
    return ".".join(str(o) for o in octets)


# ---------------------------------------------------------------------------
# TCP relay
# ---------------------------------------------------------------------------

def _relay(sock_a, sock_b, rule):
    """Bidirectional relay between two sockets."""
    sockets = [sock_a, sock_b]
    while running and rule["active"]:
        try:
            readable, _, errored = select.select(sockets, [], sockets, 1.0)
        except Exception:
            break
        if errored:
            break
        for sock in readable:
            try:
                data = sock.recv(BUFFER_SIZE)
            except Exception:
                data = b""
            if not data:
                return
            target = sock_b if sock is sock_a else sock_a
            try:
                target.sendall(data)
            except Exception:
                return
            with lock:
                rule["bytes_fwd"] = rule.get("bytes_fwd", 0) + len(data)


def _handle_connection(client_sock, rule):
    """Handle a forwarded connection."""
    remote_sock = None
    try:
        with lock:
            rule["conn_count"] = rule.get("conn_count", 0) + 1

        remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_sock.settimeout(10)
        remote_sock.connect((rule["remote_host"], rule["remote_port"]))
        remote_sock.settimeout(None)

        _relay(client_sock, remote_sock, rule)
    except Exception:
        pass
    finally:
        _safe_close(client_sock)
        _safe_close(remote_sock)


def _safe_close(sock):
    """Safely close a socket."""
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    try:
        sock.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Server thread (one per rule)
# ---------------------------------------------------------------------------

def _server_thread(rule):
    """Accept loop for a single forwarding rule."""
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(1.0)
        srv.bind(("0.0.0.0", rule["local_port"]))
        srv.listen(8)
        with lock:
            rule["server_sock"] = srv
    except OSError:
        with lock:
            rule["active"] = False
        return

    while running and rule["active"]:
        try:
            client_sock, _addr = srv.accept()
            threading.Thread(
                target=_handle_connection, args=(client_sock, rule),
                daemon=True,
            ).start()
        except socket.timeout:
            continue
        except Exception:
            break

    _safe_close(srv)
    with lock:
        rule["server_sock"] = None
        rule["active"] = False


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _format_bytes(n):
    """Format byte count for display."""
    if n < 1024:
        return f"{n}B"
    elif n < 1024 * 1024:
        return f"{n // 1024}K"
    else:
        return f"{n // (1024 * 1024)}M"


def _draw_config(lcd, font):
    """Draw the configuration screen for the current rule."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "PORT FORWARD", font=font, fill="#33CCFF")

    with lock:
        if not rules:
            rules.append(_new_rule())
        rule = dict(rules[current_rule])
        rule_count = len(rules)

    d.text((2, 16), f"Rule {current_rule + 1}/{rule_count}", font=font, fill="#AAAAAA")

    octets = _parse_octets(rule["remote_host"])

    # Field labels and values with cursor highlight
    fields = [
        ("Local Port", str(rule["local_port"])),
        ("Remote IP .0", str(octets[0])),
        ("Remote IP .1", str(octets[1])),
        ("Remote IP .2", str(octets[2])),
        ("Remote IP .3", str(octets[3])),
        ("Remote Port", str(rule["remote_port"])),
    ]

    y = 30
    for idx, (label, value) in enumerate(fields):
        is_selected = (idx == cursor_pos)
        label_color = "#FFAA00" if is_selected else "#888"
        value_color = "#FFFFFF" if is_selected else "#CCCCCC"
        marker = ">" if is_selected else " "
        d.text((2, y), f"{marker}{label}:", font=font, fill=label_color)
        d.text((90, y), value, font=font, fill=value_color)
        y += 12

    # Status
    status = "ACTIVE" if rule["active"] else "STOPPED"
    status_color = "#00FF00" if rule["active"] else "#FF0000"
    d.text((2, y + 4), f"Status: {status}", font=font, fill=status_color)

    if rule["active"]:
        d.text((2, y + 16), f"Conns:{rule['conn_count']} "
               f"Fwd:{_format_bytes(rule['bytes_fwd'])}",
               font=font, fill="#888")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Go UD:Val LR:Fld", font=font, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_rules_view(lcd, font):
    """Draw the active rules overview."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "ACTIVE RULES", font=font, fill="#33CCFF")

    with lock:
        rule_list = [dict(r) for r in rules]

    if not rule_list:
        d.text((2, 30), "No rules configured", font=font, fill="#888")
    else:
        y = 18
        for idx, rule in enumerate(rule_list):
            active = rule["active"]
            status_dot = "#00FF00" if active else "#FF0000"
            color = "#CCCCCC" if active else "#666"

            d.ellipse((2, y + 2, 6, y + 6), fill=status_dot)
            line = (
                f":{rule['local_port']} -> "
                f"{rule['remote_host']}:{rule['remote_port']}"
            )
            d.text((10, y), line[:20], font=font, fill=color)

            if active:
                detail = f"  {rule['conn_count']}c {_format_bytes(rule['bytes_fwd'])}"
                d.text((10, y + 10), detail, font=font, fill="#888")
                y += 22
            else:
                y += 12

            if y > 110:
                break

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "Press any to return", font=font, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running, current_rule, cursor_pos, view_mode

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font = scaled_font()

    # Initialize first rule
    rules.append(_new_rule())

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 16), "TCP PORT FORWARDER", font=font, fill="#33CCFF")
    d.text((4, 36), "Forward local to remote", font=font, fill="#888")
    d.text((4, 56), "OK     Start/stop", font=font, fill="#666")
    d.text((4, 68), "U/D    Adjust value", font=font, fill="#666")
    d.text((4, 80), "L/R    Switch field", font=font, fill="#666")
    d.text((4, 92), "KEY1   Add rule", font=font, fill="#666")
    d.text((4, 104), "KEY3   Exit", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)

    try:
        while running:
            btn = get_button(PINS, GPIO)

            # Rules view: any button returns to config
            if view_mode == "rules" and btn:
                view_mode = "config"
                time.sleep(0.3)
                continue

            if btn == "KEY3":
                break

            elif btn == "LEFT":
                cursor_pos = (cursor_pos - 1) % FIELD_COUNT
                time.sleep(0.15)

            elif btn == "RIGHT":
                cursor_pos = (cursor_pos + 1) % FIELD_COUNT
                time.sleep(0.15)

            elif btn == "UP":
                with lock:
                    rule = rules[current_rule]
                    if rule["active"]:
                        pass  # don't edit while active
                    else:
                        _adjust_field(rule, cursor_pos, 1)
                time.sleep(0.1)

            elif btn == "DOWN":
                with lock:
                    rule = rules[current_rule]
                    if rule["active"]:
                        pass
                    else:
                        _adjust_field(rule, cursor_pos, -1)
                time.sleep(0.1)

            elif btn == "OK":
                with lock:
                    rule = rules[current_rule]
                if rule["active"]:
                    with lock:
                        rule["active"] = False
                    srv = rule.get("server_sock")
                    _safe_close(srv)
                else:
                    with lock:
                        rule["active"] = True
                    threading.Thread(
                        target=_server_thread, args=(rule,), daemon=True,
                    ).start()
                time.sleep(0.3)

            elif btn == "KEY1":
                with lock:
                    rules.append(_new_rule())
                    current_rule = len(rules) - 1
                cursor_pos = 0
                time.sleep(0.3)

            elif btn == "KEY2":
                view_mode = "rules"
                time.sleep(0.3)

            if view_mode == "config":
                _draw_config(lcd, font)
            else:
                _draw_rules_view(lcd, font)

            time.sleep(0.05)

    finally:
        running = False
        # Stop all active rules
        with lock:
            for rule in rules:
                rule["active"] = False
                srv = rule.get("server_sock")
                if srv:
                    _safe_close(srv)
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


def _adjust_field(rule, field_idx, direction):
    """Adjust a field value by direction (+1 or -1)."""
    if field_idx == 0:
        # Local port
        new_val = rule["local_port"] + direction
        rule["local_port"] = max(1, min(65535, new_val))
    elif 1 <= field_idx <= 4:
        # Remote host octet
        octets = _parse_octets(rule["remote_host"])
        octet_idx = field_idx - 1
        octets[octet_idx] = max(0, min(255, octets[octet_idx] + direction))
        rule["remote_host"] = _octets_to_str(octets)
    elif field_idx == 5:
        # Remote port
        new_val = rule["remote_port"] + direction
        rule["remote_port"] = max(1, min(65535, new_val))


if __name__ == "__main__":
    raise SystemExit(main())
