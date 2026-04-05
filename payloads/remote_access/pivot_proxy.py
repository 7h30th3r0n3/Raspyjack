#!/usr/bin/env python3
"""
RaspyJack Payload -- SOCKS5 Pivot Proxy
========================================
Author: 7h30th3r0n3

Starts a SOCKS5 proxy server for network pivoting.  Supports the
CONNECT command (TCP tunneling) so remote tools can route through
the Pi into the internal network.

Controls:
  OK         -- Start / stop proxy
  UP / DOWN  -- Scroll active connections
  LEFT/RIGHT -- Adjust listening port
  KEY1       -- Show Pi IP addresses
  KEY3       -- Exit

Default port: 1080
"""

import os
import sys
import struct
import socket
import select
import time
import threading
import subprocess

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
ROWS_VISIBLE = 5
BUFFER_SIZE = 4096
DEFAULT_PORT = 1080

# SOCKS5 constants
SOCKS_VERSION = 0x05
CMD_CONNECT = 0x01
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True
proxy_active = False
listen_port = DEFAULT_PORT
scroll_offset = 0
show_ips = False

# Stats
total_clients = 0
bytes_transferred = 0
connections = []    # [{"src", "dst", "bytes", "active"}]

server_sock = None


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _get_ip(iface):
    """Get IPv4 address for an interface."""
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


# ---------------------------------------------------------------------------
# SOCKS5 connection handler
# ---------------------------------------------------------------------------

def _handle_client(client_sock, client_addr):
    """Handle a single SOCKS5 client connection."""
    global total_clients, bytes_transferred

    src_label = f"{client_addr[0]}:{client_addr[1]}"
    dst_label = "?"
    conn_entry = {"src": src_label, "dst": dst_label, "bytes": 0, "active": True}

    with lock:
        total_clients += 1
        connections.append(conn_entry)

    remote_sock = None
    try:
        # Greeting: client sends version + auth methods
        greeting = client_sock.recv(256)
        if len(greeting) < 2 or greeting[0] != SOCKS_VERSION:
            return

        # Reply: no auth required
        client_sock.sendall(struct.pack("BB", SOCKS_VERSION, 0x00))

        # Request: version, cmd, rsv, atyp, dst_addr, dst_port
        request = client_sock.recv(256)
        if len(request) < 4:
            return

        version, cmd, _rsv, atyp = request[0], request[1], request[2], request[3]
        if version != SOCKS_VERSION or cmd != CMD_CONNECT:
            # Command not supported
            reply = struct.pack("BBBBIH", SOCKS_VERSION, 0x07, 0, ATYP_IPV4, 0, 0)
            client_sock.sendall(reply)
            return

        # Parse destination
        if atyp == ATYP_IPV4:
            if len(request) < 10:
                return
            dst_ip = socket.inet_ntoa(request[4:8])
            dst_port = struct.unpack("!H", request[8:10])[0]
        elif atyp == ATYP_DOMAIN:
            domain_len = request[4]
            if len(request) < 5 + domain_len + 2:
                return
            domain = request[5:5 + domain_len].decode("utf-8", errors="replace")
            dst_port = struct.unpack("!H", request[5 + domain_len:7 + domain_len])[0]
            try:
                dst_ip = socket.gethostbyname(domain)
            except socket.gaierror:
                reply = struct.pack("BBBBIH", SOCKS_VERSION, 0x04, 0, ATYP_IPV4, 0, 0)
                client_sock.sendall(reply)
                return
        else:
            reply = struct.pack("BBBBIH", SOCKS_VERSION, 0x08, 0, ATYP_IPV4, 0, 0)
            client_sock.sendall(reply)
            return

        dst_label = f"{dst_ip}:{dst_port}"
        with lock:
            conn_entry["dst"] = dst_label

        # Connect to target
        remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_sock.settimeout(10)
        remote_sock.connect((dst_ip, dst_port))
        remote_sock.settimeout(None)

        # Success reply
        bind_addr = remote_sock.getsockname()
        bind_ip = socket.inet_aton(bind_addr[0])
        bind_port = struct.pack("!H", bind_addr[1])
        reply = struct.pack("BBB", SOCKS_VERSION, 0x00, 0x00)
        reply += struct.pack("B", ATYP_IPV4) + bind_ip + bind_port
        client_sock.sendall(reply)

        # Relay data bidirectionally
        _relay(client_sock, remote_sock, conn_entry)

    except Exception:
        pass
    finally:
        with lock:
            conn_entry["active"] = False
        _safe_close(client_sock)
        _safe_close(remote_sock)


def _relay(client_sock, remote_sock, conn_entry):
    """Bidirectional TCP relay between client and remote."""
    global bytes_transferred

    sockets = [client_sock, remote_sock]
    while running and proxy_active:
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

            target = remote_sock if sock is client_sock else client_sock
            try:
                target.sendall(data)
            except Exception:
                return

            n = len(data)
            with lock:
                bytes_transferred += n
                conn_entry["bytes"] = conn_entry.get("bytes", 0) + n


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
# Server thread
# ---------------------------------------------------------------------------

def _server_thread(port):
    """SOCKS5 server accept loop."""
    global proxy_active, server_sock

    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.settimeout(1.0)
        server_sock.bind(("0.0.0.0", port))
        server_sock.listen(16)
    except OSError:
        proxy_active = False
        return

    while running and proxy_active:
        try:
            client_sock, client_addr = server_sock.accept()
            threading.Thread(
                target=_handle_client, args=(client_sock, client_addr),
                daemon=True,
            ).start()
        except socket.timeout:
            continue
        except Exception:
            break

    _safe_close(server_sock)
    server_sock = None
    proxy_active = False


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _format_bytes(n):
    """Format byte count for display."""
    if n < 1024:
        return f"{n}B"
    elif n < 1024 * 1024:
        return f"{n // 1024}K"
    else:
        return f"{n // (1024 * 1024)}M"


def _draw_frame(lcd, font):
    """Render current state to the LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "SOCKS5 PROXY", font=font, fill="#9933FF")
    indicator = "#00FF00" if proxy_active else "#444"
    d.ellipse((118, 3, 122, 7), fill=indicator)

    with lock:
        port = listen_port
        clients = total_clients
        xfer = bytes_transferred
        conn_list = list(connections)
        active_count = sum(1 for c in conn_list if c["active"])

    if show_ips:
        # Show IP addresses
        ips = _get_all_ips()
        d.text((2, 16), "Pi IP Addresses:", font=font, fill="#AAAAAA")
        y = 30
        if not ips:
            d.text((2, y), "No interfaces up", font=font, fill="#FF0000")
        else:
            for iface, ip in ips.items():
                d.text((2, y), f"{iface}: {ip}", font=font, fill="#CCCCCC")
                y += 12
        d.text((2, 104), "Press any to return", font=font, fill="#888")
    else:
        # Main view
        status = "LISTENING" if proxy_active else "STOPPED"
        d.text((2, 16), f"Port: {port}  [{status}]", font=font, fill="#AAAAAA")
        d.text((2, 28), f"Clients:{clients} Active:{active_count}",
               font=font, fill="#AAAAAA")
        d.text((2, 38), f"Transferred: {_format_bytes(xfer)}", font=font, fill="#888")

        # Connection list
        active_conns = [c for c in conn_list if c["active"]]
        inactive_conns = [c for c in conn_list if not c["active"]]
        display_conns = active_conns + inactive_conns[-3:]

        visible = display_conns[scroll_offset:scroll_offset + ROWS_VISIBLE]
        for i, conn in enumerate(visible):
            y = 52 + i * 12
            dst = conn["dst"][:18]
            bcount = _format_bytes(conn["bytes"])
            color = "#00FF00" if conn["active"] else "#666"
            d.text((2, y), f"{dst} {bcount}", font=font, fill=color)

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if proxy_active:
        d.text((2, 117), "OK:Stop K1:IPs K3:Quit", font=font, fill="#888")
    else:
        d.text((2, 117), "OK:Start LR:Port K3:Q", font=font, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running, proxy_active, listen_port, scroll_offset, show_ips

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font = scaled_font()

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 16), "SOCKS5 PIVOT PROXY", font=font, fill="#9933FF")
    d.text((4, 36), "TCP tunnel through Pi", font=font, fill="#888")
    d.text((4, 56), "OK     Start/stop", font=font, fill="#666")
    d.text((4, 68), "L/R    Adjust port", font=font, fill="#666")
    d.text((4, 80), "KEY1   Show IPs", font=font, fill="#666")
    d.text((4, 92), "KEY3   Exit", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)

    try:
        while running:
            btn = get_button(PINS, GPIO)

            if show_ips and btn:
                show_ips = False
                time.sleep(0.3)
                _draw_frame(lcd, font)
                continue

            if btn == "KEY3":
                break

            elif btn == "OK":
                if proxy_active:
                    proxy_active = False
                    _safe_close(server_sock)
                else:
                    proxy_active = True
                    threading.Thread(
                        target=_server_thread, args=(listen_port,), daemon=True,
                    ).start()
                time.sleep(0.3)

            elif btn == "LEFT" and not proxy_active:
                listen_port = max(1, listen_port - 1)
                time.sleep(0.1)

            elif btn == "RIGHT" and not proxy_active:
                listen_port = min(65535, listen_port + 1)
                time.sleep(0.1)

            elif btn == "UP":
                scroll_offset = max(0, scroll_offset - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                with lock:
                    total = len(connections)
                max_scroll = max(0, total - ROWS_VISIBLE)
                scroll_offset = min(scroll_offset + 1, max_scroll)
                time.sleep(0.15)

            elif btn == "KEY1":
                show_ips = True
                time.sleep(0.3)

            _draw_frame(lcd, font)
            time.sleep(0.05)

    finally:
        running = False
        proxy_active = False
        _safe_close(server_sock)
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
