#!/usr/bin/env python3
"""
RaspyJack payload – Mini Honeypot
=================================

Lightweight, low‑interaction honeypot that listens on multiple TCP ports
and logs connection attempts. Optional Discord notifications are supported
via a webhook URL stored in `discord_webhook.txt` at the repository root.

Features:
- Multiple services: HTTP, SSH, Telnet, FTP, SMTP (generic fallback for others)
- JSONL logs under `loot/honeypot/` with timestamps and samples
- Optional Discord notifications (rate‑limited) using `discord_webhook.txt`
- LCD status screen and button controls when Waveshare 1.44" HAT is present
  - KEY1: Toggle Discord alerts
  - KEY2: Cycle display views (Stats / Recent / Config)
  - KEY3: Exit (stop honeypot)

Usage examples:
- Basic defaults (common ports, requires root for low ports):
    python3 payloads/honeypot.py --profile basic
- High ports only (no root needed):
    python3 payloads/honeypot.py --ports 8022:ssh,8080:http,2323:telnet,2121:ftp,2525:smtp
- Disable LCD UI even if present:
    python3 payloads/honeypot.py --headless

Notes:
- Binding privileged ports (<1024) typically requires root or CAP_NET_BIND_SERVICE.
- If a port fails to bind, the honeypot will skip it and continue.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as _dt
import json
import os
import signal
import socket
import sys
import time
from email.utils import formatdate
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Callable


# ---------------------------------------------------------------------------
# Paths & configuration
# ---------------------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parents[1]
LOOT_DIR = ROOT_DIR / "loot" / "honeypot"
LOOT_DIR.mkdir(parents=True, exist_ok=True)
WEBHOOK_FILE = ROOT_DIR / "discord_webhook.txt"
DEBUG_LOG = LOOT_DIR / "honeypot_debug.log"

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from payloads._input_helper import get_virtual_button

# ---------------------------------------------------------------------------
# Optional dependencies (Discord + LCD)
# ---------------------------------------------------------------------------
try:
    import requests  # type: ignore
    HAS_REQUESTS = True
except Exception:
    requests = None  # type: ignore
    HAS_REQUESTS = False

HAS_LCD = False
LCD_IMPORT_ERR: Optional[str] = None
try:
    import RPi.GPIO as GPIO
    import LCD_1in44, LCD_Config
    from PIL import Image, ImageDraw, ImageFont
    HAS_LCD = True
except Exception as _lcd_exc:
    HAS_LCD = False
    try:
        LCD_IMPORT_ERR = f"{type(_lcd_exc).__name__}: {_lcd_exc}"
    except Exception:
        LCD_IMPORT_ERR = "unknown"


# ---------------------------------------------------------------------------
# Default service profiles
# ---------------------------------------------------------------------------
DEFAULT_PROFILES: Dict[str, List[Tuple[int, str]]] = {
    # Common baseline – likely to get hits. Requires root for low ports.
    "basic": [
        (22, "ssh"),
        (23, "telnet"),
        (80, "http"),
        (8080, "http"),
    ],
    # Web‑focused
    "web": [
        (80, "http"),
        (443, "https"),
        (8080, "http"),
    ],
    # Larger mix. Many are privileged.
    "all": [
        (21, "ftp"),
        (22, "ssh"),
        (23, "telnet"),
        (25, "smtp"),
        (80, "http"),
        (110, "pop3"),
        (143, "imap"),
        (443, "https"),
        (3306, "mysql"),
        (3389, "rdp"),
        (5900, "vnc"),
        (8080, "http"),
    ],
}


# ---------------------------------------------------------------------------
# Ubuntu OS service fingerprints (banners, headers)
# ---------------------------------------------------------------------------
OS_PROFILES: Dict[str, Dict[str, str]] = {
    "ubuntu20": {
        "label": "Ubuntu 20.04 LTS",
        "ssh_banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        "http_server": "Apache/2.4.41 (Ubuntu)",
        "ftp_banner": "220 (vsFTPd 3.0.3)\r\n",
        "smtp_banner": "{hostname}",
        "telnet_preamble": "Ubuntu 20.04.6 LTS\r\n",
    },
    "ubuntu22": {
        "label": "Ubuntu 22.04 LTS",
        "ssh_banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
        "http_server": "Apache/2.4.52 (Ubuntu)",
        "ftp_banner": "220 (vsFTPd 3.0.5)\r\n",
        "smtp_banner": "{hostname}",
        "telnet_preamble": "Ubuntu 22.04.4 LTS\r\n",
    },
    "ubuntu24": {
        "label": "Ubuntu 24.04 LTS",
        "ssh_banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3",
        "http_server": "Apache/2.4.58 (Ubuntu)",
        "ftp_banner": "220 (vsFTPd 3.0.5)\r\n",
        "smtp_banner": "{hostname}",
        "telnet_preamble": "Ubuntu 24.04 LTS\r\n",
    },
}


# ---------------------------------------------------------------------------
# Debug logger
# ---------------------------------------------------------------------------
def _mk_debug_logger(enabled: bool):
    def _log(message: str) -> None:
        if not enabled:
            return
        ts = iso_now()
        line = f"[DEBUG] {ts} {message}"
        try:
            print(line)
        except Exception:
            pass
        try:
            with DEBUG_LOG.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass
    return _log


def read_webhook_url() -> Optional[str]:
    """Read the Discord webhook URL from `discord_webhook.txt` if present."""
    try:
        if WEBHOOK_FILE.exists():
            text = WEBHOOK_FILE.read_text(encoding="utf-8").strip()
            if text.lower().startswith("http"):
                return text
    except Exception:
        pass
    return None


def iso_now() -> str:
    return _dt.datetime.utcnow().replace(tzinfo=_dt.timezone.utc).isoformat()


class Honeypot:
    """Low‑interaction asyncio honeypot for a set of TCP ports."""

    def __init__(self, services: List[Tuple[int, str]], bind_host: str = "0.0.0.0", os_profile: str = "ubuntu22", hostname: Optional[str] = None, debug: bool = True):
        unique: Dict[int, str] = {}
        for port, name in services:
            if port not in unique:
                unique[port] = name.lower()

        self.bind_host: str = bind_host
        self.port_to_service: Dict[int, str] = unique
        self.servers: List[asyncio.base_events.Server] = []
        self.running: bool = False

        # Metrics & recent events
        self.total_connections: int = 0
        self.per_port_count: Dict[int, int] = {p: 0 for p in self.port_to_service}
        self.recent_events: deque[Dict] = deque(maxlen=10)

        # OS fingerprinting
        self.os_profile_key: str = os_profile if os_profile in OS_PROFILES else "ubuntu22"
        self.fingerprints: Dict[str, str] = OS_PROFILES[self.os_profile_key]
        self.hostname: str = hostname or socket.gethostname() or "ubuntu"

        # Logging
        self.session_start: str = iso_now()
        self.log_file: Path = LOOT_DIR / f"events_{_dt.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.jsonl"

        # Debug logging
        self.debug_enabled = debug
        self.debug = _mk_debug_logger(debug)
        self.debug(f"Init honeypot: host={self.bind_host} os={self.os_profile_key} hostname={self.hostname}")

        # Discord
        self.discord_url: Optional[str] = read_webhook_url()
        self.discord_enabled: bool = self.discord_url is not None
        self._last_discord_sent: float = 0.0
        self._discord_min_interval_s: float = 2.0  # rate limit

    # ---------------------------- Lifecycle --------------------------------
    async def start(self) -> None:
        """Start all configured listeners."""
        self.running = True
        print(f"[HONEYPOT] Starting on {self.bind_host} …")
        self.debug("Creating listeners …")

        for port, svc in self.port_to_service.items():
            try:
                server = await asyncio.start_server(
                    client_connected_cb=lambda r, w, p=port, s=svc: asyncio.create_task(self._handle_connection(r, w, p, s)),
                    host=self.bind_host,
                    port=port,
                )
                self.servers.append(server)
                addr_list = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
                print(f"[HONEYPOT] Listening: {svc} on {addr_list}")
                self.debug(f"Listening {svc} on {addr_list}")
            except OSError as e:
                print(f"[WARN] Failed to bind {svc} on :{port} – {e}")
                self.debug(f"Bind failed {svc}:{port} – {e}")

        if not self.servers:
            print("[ERROR] No listeners started. Exiting.")
            self.running = False

    async def stop(self) -> None:
        """Stop all listeners and close resources."""
        if not self.running:
            return
        print("[HONEYPOT] Stopping …")
        self.debug("Stopping listeners …")
        self.running = False
        for server in self.servers:
            server.close()
            try:
                await server.wait_closed()
            except Exception:
                pass
        self.servers.clear()
        print("[HONEYPOT] Stopped.")
        self.debug("Stopped")

    # ----------------------------- Handlers ---------------------------------
    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int, service: str) -> None:
        peer = writer.get_extra_info("peername")
        ip, rport = (peer[0], peer[1]) if isinstance(peer, tuple) else ("?", 0)
        ts = iso_now()
        self.debug(f"Conn open svc={service} lport={port} from={ip}:{rport}")
        event: Dict[str, object] = {
            "ts": ts,
            "ip": ip,
            "remote_port": rport,
            "local_port": port,
            "service": service,
            "sample": "",
        }

        try:
            if service == "ssh":
                ssh_banner = self.fingerprints.get("ssh_banner", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
                writer.write((ssh_banner + "\r\n").encode())
                await writer.drain()
                data = await self._read_max(reader, 1024, 3.0)
                event["sample"] = self._safe_text(data)
                self.debug(f"SSH sample: {event['sample'][:60]}")

            elif service == "telnet":
                pre = self.fingerprints.get("telnet_preamble", "")
                if pre:
                    writer.write(pre.encode())
                writer.write((f"{self.hostname} login: ").encode())
                await writer.drain()
                user = await self._read_line(reader, 4.0)
                writer.write(b"Password: ")
                await writer.drain()
                password = await self._read_line(reader, 4.0)
                user_s = self._safe_text(user).strip()
                pass_len = len(password.strip()) if isinstance(password, (bytes, bytearray)) else 0
                event["sample"] = f"USER={user_s} PASS_LEN={pass_len}"
                await asyncio.sleep(0.3)
                writer.write(b"\r\nLogin incorrect\r\n")
                await writer.drain()
                self.debug(f"TELNET user={user_s} len(pass)={pass_len}")

            elif service == "ftp":
                ftp_banner = self.fingerprints.get("ftp_banner", "220 (vsFTPd 3.0.5)\r\n")
                writer.write(ftp_banner.encode())
                await writer.drain()
                transcript = b""
                line1 = await self._read_line(reader, 4.0)
                if line1:
                    transcript += line1
                    if line1.upper().startswith(b"USER "):
                        writer.write(b"331 Please specify the password.\r\n")
                        await writer.drain()
                        line2 = await self._read_line(reader, 4.0)
                        transcript += line2 or b""
                        writer.write(b"530 Login incorrect.\r\n")
                        await writer.drain()
                    else:
                        writer.write(b"500 Unknown command.\r\n")
                        await writer.drain()
                event["sample"] = self._safe_text(transcript)
                self.debug(f"FTP transcript: {event['sample'][:60]}")

            elif service == "smtp":
                smtp_banner = f"220 {self.hostname} ESMTP Postfix (Ubuntu)\r\n"
                writer.write(smtp_banner.encode())
                await writer.drain()
                transcript = b""
                for _ in range(3):
                    line = await self._read_line(reader, 5.0)
                    if not line:
                        break
                    transcript += line
                    if line.upper().startswith((b"HELO", b"EHLO")):
                        capabilities = (
                            f"250-{self.hostname} at your service\r\n"
                            "250-PIPELINING\r\n"
                            "250-SIZE 10240000\r\n"
                            "250-ETRN\r\n"
                            "250-ENHANCEDSTATUSCODES\r\n"
                            "250-8BITMIME\r\n"
                            "250 DSN\r\n"
                        )
                        writer.write(capabilities.encode())
                        await writer.drain()
                    elif line.upper().startswith(b"QUIT"):
                        writer.write(b"221 2.0.0 Bye\r\n")
                        await writer.drain()
                        break
                    else:
                        writer.write(b"250 OK\r\n")
                        await writer.drain()
                event["sample"] = self._safe_text(transcript)
                self.debug(f"SMTP transcript: {event['sample'][:60]}")

            elif service in ("http", "https"):
                data = await self._read_max(reader, 4096, 3.0)
                method, path, headers_in = self._parse_http_request(data)
                host = headers_in.get("host", self.hostname)
                ua = headers_in.get("user-agent", "")
                event["path"] = path
                event["sample"] = f"{method} {path} UA={ua[:80]}"

                status, extra_headers, body = self._http_build_response(method, path, host)
                server_header = self.fingerprints.get("http_server", "Apache/2.4.52 (Ubuntu)")
                date_hdr = formatdate(timeval=None, localtime=False, usegmt=True)
                status_line = f"HTTP/1.1 {status} {self._http_status_text(status)}".encode()
                all_headers = [
                    status_line,
                    f"Date: {date_hdr}".encode(),
                    f"Server: {server_header}".encode(),
                ] + extra_headers + [
                    f"Content-Length: {len(body)}".encode(),
                    b"Connection: close",
                ]
                if method.upper() == "HEAD":
                    writer.write(b"\r\n".join(all_headers) + b"\r\n\r\n")
                else:
                    writer.write(b"\r\n".join(all_headers) + b"\r\n\r\n" + body)
                await writer.drain()
                self.debug(f"HTTP {status} {path} len={len(body)} Server={server_header}")

            else:
                writer.write(b"Service ready\r\n")
                await writer.drain()
                data = await self._read_max(reader, 512, 3.0)
                event["sample"] = self._safe_text(data)
                self.debug(f"RAW sample: {event['sample'][:60]}")

        except Exception as e:
            event["error"] = str(e)
            self.debug(f"Handler error: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        # Metrics & logging
        self.total_connections += 1
        self.per_port_count[port] = self.per_port_count.get(port, 0) + 1
        self.recent_events.appendleft(event)
        self._write_event(event)
        await self._maybe_notify_discord(event)

    # ----------------------------- Utilities --------------------------------
    async def _read_max(self, reader: asyncio.StreamReader, n: int, timeout: float) -> bytes:
        try:
            return await asyncio.wait_for(reader.read(n), timeout=timeout)
        except asyncio.TimeoutError:
            return b""

    async def _read_line(self, reader: asyncio.StreamReader, timeout: float) -> bytes:
        try:
            return await asyncio.wait_for(reader.readline(), timeout=timeout)
        except asyncio.TimeoutError:
            return b""

    def _safe_text(self, data: bytes) -> str:
        if not data:
            return ""
        return data[:160].decode("utf-8", errors="replace")

    # ----------------------------- HTTP helpers ------------------------------
    def _parse_http_request(self, data: bytes) -> Tuple[str, str, Dict[str, str]]:
        try:
            text = data.decode("iso-8859-1", errors="replace")
            lines = text.split("\r\n")
            request_line = lines[0] if lines else ""
            parts = request_line.split()
            method = parts[0] if len(parts) > 0 else "GET"
            path = parts[1] if len(parts) > 1 else "/"
            headers: Dict[str, str] = {}
            for line in lines[1:]:
                if not line:
                    break
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            return method, path, headers
        except Exception:
            return "GET", "/", {}

    def _http_status_text(self, code: int) -> str:
        return {
            200: "OK",
            301: "Moved Permanently",
            302: "Found",
            403: "Forbidden",
            404: "Not Found",
        }.get(code, "OK")

    def _http_build_response(self, method: str, path: str, host: str) -> Tuple[int, List[bytes], bytes]:
        # Minimal routing resembling Ubuntu Apache layout
        if path == "/" or path == "/index.html":
            body_html = (
                "<html><head><title>Apache2 Ubuntu Default Page: It works</title>"
                "<meta charset=\"UTF-8\"></head>"
                "<body><h1>Apache2 Ubuntu Default Page</h1>"
                "<p>It works!</p>"
                "<hr><address>" + self.fingerprints.get("http_server", "Apache/2.4.52 (Ubuntu)") +
                " Server at " + host + " Port 80</address></body></html>"
            )
            return 200, [b"Content-Type: text/html; charset=UTF-8"], body_html.encode("utf-8")

        if path == "/server-status":
            # Fake mod_status
            status = (
                "<html><head><title>Apache Status</title></head><body>"
                "<h1>Apache Server Status for " + host + "</h1>"
                "<p>Server Version: " + self.fingerprints.get("http_server", "Apache/2.4.52 (Ubuntu)") + "</p>"
                "<p>Server MPM: event</p><p>Server Built: unknown</p>"
                "<hr><pre>Scoreboard Key: _ Waiting . Starting S Sending R Reading K Keepalive D DNS C Closing L Logging G Graceful I Idle cleanup .</pre>"
                "</body></html>"
            )
            return 200, [b"Content-Type: text/html; charset=UTF-8"], status.encode("utf-8")

        if path.startswith("/favicon.ico"):
            return 404, [b"Content-Type: text/plain; charset=UTF-8"], b"Not Found"

        # Directory index style page
        if path.endswith("/"):
            listing = (
                "<html><head><title>Index of " + path + "</title></head><body>"
                "<h1>Index of " + path + "</h1><hr><pre>"
                "<a href=\"../\">../</a>\n"
                "</pre><hr><address>" + self.fingerprints.get("http_server", "Apache/2.4.52 (Ubuntu)") +
                " Server at " + host + " Port 80</address></body></html>"
            )
            return 200, [b"Content-Type: text/html; charset=UTF-8"], listing.encode("utf-8")

        # 404 for everything else
        notfound = (
            "<html><head><title>404 Not Found</title></head><body>"
            "<h1>Not Found</h1><p>The requested URL " + path + " was not found on this server.</p>"
            "<hr><address>" + self.fingerprints.get("http_server", "Apache/2.4.52 (Ubuntu)") +
            " Server at " + host + " Port 80</address></body></html>"
        )
        return 404, [b"Content-Type: text/html; charset=UTF-8"], notfound.encode("utf-8")

    def _write_event(self, event: Dict) -> None:
        try:
            with self.log_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"[WARN] Failed to write log: {e}")

    async def _maybe_notify_discord(self, event: Dict) -> None:
        if not self.discord_enabled or not self.discord_url or not HAS_REQUESTS:
            return
        now = asyncio.get_event_loop().time()
        if now - self._last_discord_sent < self._discord_min_interval_s:
            return
        self._last_discord_sent = now

        # Build rich embed
        ip = str(event.get("ip", "?"))
        local_port = int(event.get("local_port", 0) or 0)
        remote_port = event.get("remote_port")
        service = str(event.get("service", ""))
        sample = str(event.get("sample", ""))[:500]
        sample_block = f"```\n{sample}\n```" if sample else ""
        port_hits = int(self.per_port_count.get(local_port, 0))
        total_hits = int(self.total_connections)
        os_label = self.fingerprints.get("label", "Ubuntu")
        links = ""
        if ip and ip != "?":
            links = f"[ipinfo](https://ipinfo.io/{ip}) | [abuseipdb](https://www.abuseipdb.com/check/{ip})"

        embed: Dict[str, object] = {
            "title": f"Honeypot hit: {service}:{local_port}",
            "description": sample_block,
            "color": 0x33AAFF,
            "timestamp": str(event.get("ts", iso_now())),
            "fields": [
                {"name": "Source", "value": f"{ip}:{remote_port}", "inline": True},
                {"name": "Host", "value": self.hostname, "inline": True},
                {"name": "OS", "value": os_label, "inline": True},
                {"name": "Bind", "value": self.bind_host, "inline": True},
                {"name": "Total", "value": str(total_hits), "inline": True},
                {"name": "Port Hits", "value": str(port_hits), "inline": True},
            ],
            "footer": {"text": f"RaspyJack Honeypot • session {self.session_start}"},
        }
        if links:
            embed["fields"].append({"name": "Lookup", "value": links, "inline": False})

        payload: Dict[str, object] = {
            "username": "RaspyJack Honeypot",
            "content": "",  # keep content empty; embed carries the data
            "embeds": [embed],
            "allowed_mentions": {"parse": []},
        }

        async def _send() -> None:
            try:
                resp = await asyncio.to_thread(requests.post, self.discord_url, json=payload, timeout=10)
                if getattr(resp, "status_code", 0) not in (200, 204):
                    print(f"[WARN] Discord responded with {resp.status_code}: {getattr(resp, 'text', '')}")
            except Exception as e:
                print(f"[WARN] Discord notification failed: {e}")

        await _send()


# ---------------------------------------------------------------------------
# Optional LCD interface (runs in a background thread)
# ---------------------------------------------------------------------------
class HoneypotLCD:
    def __init__(self, hp: Honeypot):
        self.hp = hp
        self.running = False
        self.mode = 0  # 0: Stats, 1: Recent, 2: Config
        self.frame = 0  # heartbeat counter
        self._last_pressed: Dict[str, float] = {k: 0.0 for k in ["UP","DOWN","LEFT","RIGHT","OK","KEY1","KEY2","KEY3"]}
        self._debounce_s: float = 0.18

        if not HAS_LCD:
            raise RuntimeError("LCD not available")

        try:
            LCD_Config.GPIO_Init()
        except Exception:
            hp.debug("LCD_Config.GPIO_Init() not available or failed; continuing")
        GPIO.setmode(GPIO.BCM)
        self.PINS = {
            "UP": 6,
            "DOWN": 19,
            "LEFT": 5,
            "RIGHT": 26,
            "OK": 13,
            "KEY1": 21,  # Toggle Discord
            "KEY2": 20,  # Cycle view
            "KEY3": 16,  # Exit
        }
        for p in self.PINS.values():
            GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

        self.lcd = LCD_1in44.LCD()
        try:
            self.lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
            hp.debug("LCD_Init completed")
        except Exception as e:
            hp.debug(f"LCD_Init failed: {e}")
            raise
        self.W, self.H = 128, 128
        try:
            self.font_large = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
        except Exception:
            self.font_large = ImageFont.load_default()
        self.font_small = ImageFont.load_default()

        # Clear to known state once after init
        try:
            self.lcd.LCD_ShowImage(Image.new("RGB", (self.W, self.H), "black"), 0, 0)
            hp.debug("LCD first black frame drawn")
        except Exception as e:
            hp.debug(f"LCD first frame failed: {e}")

    def _text(self, draw: "ImageDraw.ImageDraw", x: int, y: int, text: str, font=None, color="white"):
        draw.text((x, y), text, font=font or self.font_small, fill=color)

    def _render_stats(self, draw: "ImageDraw.ImageDraw"):
        self._text(draw, 2, 4, "HONEYPOT", self.font_large, "#00FF00")
        self._text(draw, 2, 20, f"Ports: {len(self.hp.port_to_service)}")
        self._text(draw, 2, 32, f"Total: {self.hp.total_connections}")
        # Show top 2 ports by count
        top = sorted(self.hp.per_port_count.items(), key=lambda kv: kv[1], reverse=True)[:3]
        y = 46
        for port, cnt in top:
            self._text(draw, 2, y, f":{port} {cnt}")
            y += 12

    def _render_recent(self, draw: "ImageDraw.ImageDraw"):
        self._text(draw, 2, 4, "RECENT", self.font_large, "#00FF00")
        y = 20
        for ev in list(self.hp.recent_events)[:5]:
            ip = str(ev.get("ip"))[:15]
            svc = str(ev.get("service"))
            port = ev.get("local_port")
            self._text(draw, 2, y, f"{ip}:{port} {svc}")
            y += 12

    def _render_config(self, draw: "ImageDraw.ImageDraw"):
        self._text(draw, 2, 4, "CONFIG", self.font_large, "#00FF00")
        self._text(draw, 2, 20, f"Discord: {'ON' if self.hp.discord_enabled else 'OFF'}", color="#FFFF00")
        self._text(draw, 2, 32, f"Log: {self.hp.log_file.name[:14]}…")
        self._text(draw, 2, 44, f"Bind: {self.hp.bind_host}")
        self._text(draw, 2, 56, f"Host: {self.hp.hostname}")
        self._text(draw, 2, 68, f"OS: {self.hp.fingerprints.get('label','Ubuntu')}")

    def _draw_status_bar(self, draw: "ImageDraw.ImageDraw"):
        labels = ["Stats", "Recent", "Config"]
        label = labels[self.mode]
        w = draw.textlength(label, font=self.font_small)
        self._text(draw, (self.W - int(w) - 2), self.H - 12, label, self.font_small, "#00FF00")
        # Heartbeat counter to ensure render is progressing
        hb = f"#{self.frame}"
        self._text(draw, 2, self.H - 12, hb, self.font_small, "#8888FF")

    def _pressed(self, name: str) -> bool:
        now = time.time()
        virtual = get_virtual_button()
        if virtual == name and (now - self._last_pressed[name]) > self._debounce_s:
            self._last_pressed[name] = now
            return True
        pin = self.PINS[name]
        if GPIO.input(pin) == 0 and (now - self._last_pressed[name]) > self._debounce_s:
            self._last_pressed[name] = now
            return True
        return False

    def _poll_inputs(self):
        if self._pressed("KEY1"):
            self.hp.discord_enabled = not self.hp.discord_enabled
            return True
        if self._pressed("KEY2"):
            self.mode = (self.mode + 1) % 3
            return True
        if self._pressed("KEY3"):
            # Signal exit and request global stop
            self.running = False
            return True
        if self._pressed("UP"):
            self.mode = (self.mode - 1) % 3
            return True
        if self._pressed("DOWN"):
            self.mode = (self.mode + 1) % 3
            return True
        return False

    def run(self):
        self.running = True
        try:
            # Initial splash using the same drawing path as frames
            splash = Image.new("RGB", (self.W, self.H), "black")
            d = ImageDraw.Draw(splash)
            self._text(d, 2, 4, "HONEYPOT", self.font_large, "#00FF00")
            self._text(d, 2, 20, self.hp.fingerprints.get("label", "Ubuntu"))
            self._text(d, 2, 34, f"Host: {self.hp.hostname}")
            self._text(d, 2, 48, "KEY1: Discord ON/OFF", self.font_small, "#FFFF00")
            self._text(d, 2, 60, "KEY2: Cycle views", self.font_small, "#FFFF00")
            self._text(d, 2, 72, "KEY3: Exit", self.font_small, "#FF5555")
            self._text(d, 2, 86, "If white screen:", self.font_small, "#AAAAAA")
            self._text(d, 2, 98, "Press KEY3 (exit)", self.font_small, "#AAAAAA")
            try:
                self.lcd.LCD_ShowImage(splash, 0, 0)
                self.hp.debug("LCD splash frame drawn")
            except Exception:
                pass

            while self.running and self.hp.running:
                touched = self._poll_inputs()
                img = Image.new("RGB", (self.W, self.H), "black")
                draw = ImageDraw.Draw(img)
                try:
                    if self.mode == 0:
                        self._render_stats(draw)
                    elif self.mode == 1:
                        self._render_recent(draw)
                    else:
                        self._render_config(draw)
                    self._draw_status_bar(draw)
                except Exception:
                    pass
                try:
                    self.lcd.LCD_ShowImage(img, 0, 0)
                except Exception:
                    # If the driver throws, avoid locking the thread in a white screen
                    pass
                self.frame += 1
                # Basic debounce
                asyncio.sleep if False else None  # keep linters calm when asyncio not used here
                if touched:
                    time_sleep = 0.2
                else:
                    time_sleep = 0.5
                import time as _t
                _t.sleep(time_sleep)
        finally:
            try:
                try:
                    self.lcd.LCD_Clear()
                except Exception:
                    pass
                # Only clean up pins we used to avoid affecting the rest of the system
                try:
                    for p in self.PINS.values():
                        GPIO.setup(p, GPIO.IN)
                except Exception:
                    pass
                GPIO.cleanup()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# CLI & entrypoint
# ---------------------------------------------------------------------------
def parse_ports_arg(ports_arg: str) -> List[Tuple[int, str]]:
    """Parse "8022:ssh,8080:http" into a list of (port, service)."""
    result: List[Tuple[int, str]] = []
    if not ports_arg:
        return result
    for item in ports_arg.split(","):
        item = item.strip()
        if not item:
            continue
        if ":" in item:
            port_s, svc = item.split(":", 1)
            try:
                port = int(port_s)
            except ValueError:
                print(f"[WARN] Invalid port: {port_s}")
                continue
            result.append((port, svc.strip().lower() or "raw"))
        else:
            try:
                port = int(item)
            except ValueError:
                print(f"[WARN] Invalid port: {item}")
                continue
            # Heuristic service guess
            svc_guess = {
                21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 80: "http", 110: "pop3",
                143: "imap", 443: "https", 8080: "http",
            }.get(port, "raw")
            result.append((port, svc_guess))
    return result


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="RaspyJack mini honeypot payload")
    p.add_argument("--profile", choices=sorted(DEFAULT_PROFILES.keys()), default="basic", help="Service profile")
    p.add_argument("--ports", default="", help="Comma list of PORT[:service], overrides --profile if set")
    p.add_argument("--bind", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    p.add_argument("--os", dest="os_profile", choices=sorted(OS_PROFILES.keys()), default="ubuntu22", help="OS fingerprint to emulate")
    p.add_argument("--hostname", default=socket.gethostname() or "ubuntu", help="Hostname presented by services")
    p.add_argument("--discord", choices=["on", "off", "auto"], default="auto", help="Discord alerts: on/off/auto (auto reads discord_webhook.txt)")
    p.add_argument("--headless", action="store_true", help="Disable LCD UI even if available")
    p.add_argument("--debug", action="store_true", help="Write verbose debug info to loot/honeypot/honeypot_debug.log (default ON in menu)")
    return p


async def run_main(args: argparse.Namespace) -> None:
    services = parse_ports_arg(args.ports) if args.ports else DEFAULT_PROFILES[args.profile]
    debug_enabled = False if not any(arg.startswith("--debug") for arg in sys.argv[1:]) else args.debug
    hp = Honeypot(services=services, bind_host=args.bind, os_profile=args.os_profile, hostname=args.hostname, debug=debug_enabled)

    if args.discord == "on":
        hp.discord_enabled = True
        hp.discord_url = hp.discord_url or read_webhook_url()
    elif args.discord == "off":
        hp.discord_enabled = False

    await hp.start()
    if not hp.running:
        return

    # Optional LCD UI
    lcd_thread = None
    if HAS_LCD and not args.headless:
        import threading
        try:
            ui = HoneypotLCD(hp)
            lcd_thread = threading.Thread(target=ui.run, name="honeypot-lcd", daemon=True)
            lcd_thread.start()
            hp.debug("LCD thread started")
        except Exception as e:
            print(f"[WARN] LCD UI unavailable: {e}")
            hp.debug(f"LCD init failed: {e}")
    else:
        if args.headless:
            hp.debug("LCD disabled by --headless")
        elif not HAS_LCD:
            hp.debug(f"LCD not available (import error: {LCD_IMPORT_ERR})")

    # Graceful shutdown
    stop_event = asyncio.Event()

    def _stop(*_):
        try:
            stop_event.set()
        except Exception:
            pass

    try:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _stop)
            except NotImplementedError:
                pass
        print("[HONEYPOT] Press Ctrl‑C or KEY3 to stop …")
        hp.debug("Entering main wait loop …")
        while not stop_event.is_set():
            if get_virtual_button() == "KEY3":
                hp.debug("KEY3 (virtual) received; stopping …")
                stop_event.set()
                break
            if lcd_thread is not None and not lcd_thread.is_alive():
                hp.debug("LCD thread exited; stopping server …")
                break
            await asyncio.sleep(0.1)
    finally:
        await hp.stop()
        if lcd_thread is not None:
            try:
                lcd_thread.join(timeout=1.0)
            except Exception:
                pass
        hp.debug("Main loop exited")


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    try:
        asyncio.run(run_main(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()


