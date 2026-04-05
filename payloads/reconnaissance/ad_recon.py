#!/usr/bin/env python3
"""
RaspyJack Payload -- Active Directory Reconnaissance
======================================================
Author: 7h30th3r0n3

Active Directory reconnaissance via LDAP.  Connects to a discovered or
user-specified LDAP server on port 389/636, attempts anonymous bind
then null-session enumeration.  Extracts: domain name, naming contexts,
users (sAMAccountName), groups, computers, and OUs.

Uses subprocess ``ldapsearch`` when available; otherwise crafts
lightweight raw LDAP search requests over a plain TCP socket (no
ldap3 dependency required).

Setup / Prerequisites
---------------------
- Network access to a domain controller on port 389 or 636.
- ``ldapsearch`` recommended (from ldap-utils package).

Controls
--------
  OK          -- Start enumeration
  UP / DOWN   -- Scroll current view
  LEFT / RIGHT-- Switch view (Domain / Users / Groups / Computers)
  KEY1        -- Scan subnet for LDAP servers
  KEY2        -- Export all data as JSON
  KEY3        -- Exit
"""

import os
import sys
import time
import json
import re
import socket
import struct
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
LOOT_DIR = "/root/Raspyjack/loot/ADRecon"
CONFIG_DIR = "/root/Raspyjack/config/ad_recon"
os.makedirs(LOOT_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)

LDAP_PORT = 389
DEBOUNCE = 0.22
VIEWS = ["domain", "users", "groups", "computers"]
VIEW_LABELS = ["Domain", "Users", "Groups", "Computers"]

# ---------------------------------------------------------------------------
# Thread-safe state
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_state = {
    "ldap_servers": [],
    "selected_server": "",
    "domain": "",
    "naming_contexts": [],
    "base_dn": "",
    "users": [],
    "groups": [],
    "computers": [],
    "ous": [],
    "status": "Idle",
    "scanning": False,
    "stop": False,
    "view_idx": 0,
    "scroll": 0,
}


def _get(key):
    with _lock:
        val = _state[key]
        if isinstance(val, (list, dict)):
            return list(val) if isinstance(val, list) else dict(val)
        return val


def _set(**kw):
    with _lock:
        for k, v in kw.items():
            _state[k] = v


# ---------------------------------------------------------------------------
# LDAP server discovery
# ---------------------------------------------------------------------------
def _get_local_subnet():
    """Return local subnet in CIDR form, e.g. 192.168.1.0/24."""
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True, text=True, timeout=5,
        )
        for line in out.stdout.splitlines():
            if "127." not in line:
                m = re.search(r"inet (\d+\.\d+\.\d+)\.\d+/(\d+)", line)
                if m:
                    return f"{m.group(1)}.0/{m.group(2)}"
    except Exception:
        pass
    return "192.168.1.0/24"


def _scan_ldap_servers():
    """Scan local subnet for hosts with port 389 open."""
    _set(scanning=True, status="Scanning for LDAP...")
    subnet = _get_local_subnet()
    servers = []

    try:
        out = subprocess.run(
            ["nmap", "-p", "389", "--open", "-T4", "-oG", "-", subnet],
            capture_output=True, text=True, timeout=60,
        )
        for line in out.stdout.splitlines():
            m = re.search(r"Host:\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m and "389/open" in line:
                servers.append(m.group(1))
    except FileNotFoundError:
        # nmap not available, try ARP + connect
        servers = _fallback_ldap_scan()
    except Exception:
        pass

    _set(ldap_servers=servers, scanning=False,
         status=f"Found {len(servers)} LDAP server(s)")
    if servers and not _get("selected_server"):
        _set(selected_server=servers[0])


def _fallback_ldap_scan():
    """Simple connect scan of ARP neighbors for port 389."""
    servers = []
    try:
        out = subprocess.run(
            ["arp", "-an"], capture_output=True, text=True, timeout=5,
        )
        for line in out.stdout.splitlines():
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
            if m:
                ip = m.group(1)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.8)
                try:
                    if s.connect_ex((ip, LDAP_PORT)) == 0:
                        servers.append(ip)
                except Exception:
                    pass
                finally:
                    s.close()
    except Exception:
        pass
    return servers


# ---------------------------------------------------------------------------
# LDAP enumeration via ldapsearch subprocess
# ---------------------------------------------------------------------------
def _has_ldapsearch():
    try:
        subprocess.run(["ldapsearch", "--help"],
                       capture_output=True, timeout=3)
        return True
    except FileNotFoundError:
        return False
    except Exception:
        return True  # exists but returned error


def _ldapsearch(server, base_dn, ldap_filter, attrs, scope="sub"):
    """Run ldapsearch and return raw output text."""
    cmd = [
        "ldapsearch", "-x", "-H", f"ldap://{server}",
        "-b", base_dn, "-s", scope, ldap_filter,
    ] + attrs
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30,
        )
        return out.stdout
    except Exception as exc:
        return f"ERROR: {exc}"


def _parse_ldapsearch(text, attr_name):
    """Extract values for a given attribute from ldapsearch output."""
    results = []
    for line in text.splitlines():
        if line.startswith(f"{attr_name}:"):
            val = line.split(":", 1)[1].strip()
            if val:
                results.append(val)
    return results


# ---------------------------------------------------------------------------
# Raw LDAP (minimal ASN.1 / BER) for environments without ldapsearch
# ---------------------------------------------------------------------------
def _ber_length(length):
    """Encode a BER length field."""
    if length < 0x80:
        return bytes([length])
    if length < 0x100:
        return bytes([0x81, length])
    return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def _ber_seq(tag, data):
    """Wrap data in a BER TLV."""
    return bytes([tag]) + _ber_length(len(data)) + data


def _ber_int(val):
    """Encode integer."""
    if val < 0x80:
        return _ber_seq(0x02, bytes([val]))
    buf = val.to_bytes((val.bit_length() + 8) // 8, "big", signed=False)
    return _ber_seq(0x02, buf)


def _ber_str(val, tag=0x04):
    """Encode octet string."""
    encoded = val.encode("utf-8") if isinstance(val, str) else val
    return _ber_seq(tag, encoded)


def _ber_enum(val):
    return _ber_seq(0x0A, bytes([val]))


def _build_bind_request(msg_id):
    """Build anonymous LDAP BindRequest."""
    version = _ber_int(3)
    name = _ber_str("")
    auth = _ber_str("", tag=0x80)  # simple auth, empty password
    bind_body = version + name + auth
    bind_req = _ber_seq(0x60, bind_body)
    msg = _ber_int(msg_id) + bind_req
    return _ber_seq(0x30, msg)


def _build_search_request(msg_id, base_dn, ldap_filter, attrs):
    """Build a simple LDAP SearchRequest."""
    base = _ber_str(base_dn)
    scope = _ber_enum(2)        # subtree
    deref = _ber_enum(0)        # neverDerefAliases
    size_limit = _ber_int(100)
    time_limit = _ber_int(10)
    types_only = bytes([0x01, 0x01, 0x00])

    # Simple present filter: (objectClass=*)
    filt = _ber_str(ldap_filter, tag=0x87)

    # Attribute list
    attr_items = b"".join(_ber_str(a) for a in attrs)
    attr_seq = _ber_seq(0x30, attr_items)

    search_body = (base + scope + deref + size_limit + time_limit +
                   types_only + filt + attr_seq)
    search_req = _ber_seq(0x63, search_body)
    msg = _ber_int(msg_id) + search_req
    return _ber_seq(0x30, msg)


def _raw_ldap_query(server, base_dn, ldap_filter, attrs):
    """Send raw LDAP bind+search and return attribute values as list."""
    results = []
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(8)
    try:
        s.connect((server, LDAP_PORT))

        # Bind
        s.sendall(_build_bind_request(1))
        s.recv(4096)

        # Search
        s.sendall(_build_search_request(2, base_dn, ldap_filter, attrs))

        buf = b""
        while True:
            try:
                chunk = s.recv(8192)
                if not chunk:
                    break
                buf += chunk
            except socket.timeout:
                break

        # Crude extraction: look for printable attribute values
        text = buf.decode("utf-8", errors="replace")
        for attr in attrs:
            for m in re.finditer(re.escape(attr) + r"[\x00-\x10]*([^\x00\x01\x02\x03\x04\x30]{2,60})", text):
                val = m.group(1).strip()
                if val and len(val) > 1:
                    results.append(val)
    except Exception:
        pass
    finally:
        s.close()
    return results


# ---------------------------------------------------------------------------
# Enumeration orchestration
# ---------------------------------------------------------------------------
def _do_enumerate():
    """Full AD enumeration."""
    _set(scanning=True, stop=False, status="Connecting...")

    server = _get("selected_server")
    if not server:
        _set(scanning=False, status="No LDAP server set")
        return

    use_cli = _has_ldapsearch()

    # Step 1: get rootDSE / naming contexts
    _set(status="Reading rootDSE...")
    if use_cli:
        raw = _ldapsearch(server, "", "objectClass=*",
                          ["namingContexts", "defaultNamingContext",
                           "dnsHostName"], scope="base")
        nc_list = _parse_ldapsearch(raw, "namingContexts")
        default_nc = _parse_ldapsearch(raw, "defaultNamingContext")
        base = default_nc[0] if default_nc else (nc_list[0] if nc_list else "")
        domain_name = base.replace("DC=", "").replace(",", ".") if base else ""
    else:
        vals = _raw_ldap_query(server, "", "objectClass",
                               ["namingContexts", "defaultNamingContext"])
        nc_list = vals
        base = vals[0] if vals else ""
        domain_name = base.replace("DC=", "").replace(",", ".") if base else server

    _set(naming_contexts=nc_list, base_dn=base, domain=domain_name)

    if not base:
        _set(scanning=False, status="No base DN found")
        return

    if _get("stop"):
        _set(scanning=False)
        return

    # Step 2: Users
    _set(status="Enumerating users...")
    if use_cli:
        raw = _ldapsearch(server, base, "(&(objectClass=user)(sAMAccountName=*))",
                          ["sAMAccountName"])
        users = _parse_ldapsearch(raw, "sAMAccountName")
    else:
        users = _raw_ldap_query(server, base, "sAMAccountName",
                                ["sAMAccountName"])
    _set(users=users)

    if _get("stop"):
        _set(scanning=False)
        return

    # Step 3: Groups
    _set(status="Enumerating groups...")
    if use_cli:
        raw = _ldapsearch(server, base, "(objectClass=group)", ["cn"])
        groups = _parse_ldapsearch(raw, "cn")
    else:
        groups = _raw_ldap_query(server, base, "group", ["cn"])
    _set(groups=groups)

    if _get("stop"):
        _set(scanning=False)
        return

    # Step 4: Computers
    _set(status="Enumerating computers...")
    if use_cli:
        raw = _ldapsearch(server, base, "(objectClass=computer)",
                          ["dNSHostName", "cn"])
        computers = _parse_ldapsearch(raw, "cn")
        if not computers:
            computers = _parse_ldapsearch(raw, "dNSHostName")
    else:
        computers = _raw_ldap_query(server, base, "computer", ["cn"])
    _set(computers=computers)

    if _get("stop"):
        _set(scanning=False)
        return

    # Step 5: OUs
    _set(status="Enumerating OUs...")
    if use_cli:
        raw = _ldapsearch(server, base,
                          "(objectClass=organizationalUnit)", ["ou"])
        ous = _parse_ldapsearch(raw, "ou")
    else:
        ous = _raw_ldap_query(server, base, "organizationalUnit", ["ou"])
    _set(ous=ous)

    u = len(_get("users"))
    g = len(_get("groups"))
    c = len(_get("computers"))
    _set(scanning=False,
         status=f"U:{u} G:{g} C:{c}")


def _start_enumerate():
    if _get("scanning"):
        return
    threading.Thread(target=_do_enumerate, daemon=True).start()


def _start_ldap_scan():
    if _get("scanning"):
        return
    threading.Thread(target=_scan_ldap_servers, daemon=True).start()


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
def _export_json():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    data = {
        "scan_time": ts,
        "server": _get("selected_server"),
        "domain": _get("domain"),
        "base_dn": _get("base_dn"),
        "naming_contexts": _get("naming_contexts"),
        "users": _get("users"),
        "groups": _get("groups"),
        "computers": _get("computers"),
        "ous": _get("ous"),
    }
    path = os.path.join(LOOT_DIR, f"adrecon_{ts}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


# ---------------------------------------------------------------------------
# LCD drawing
# ---------------------------------------------------------------------------
def _draw_lcd():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    view_idx = _get("view_idx")
    scroll = _get("scroll")
    status = _get("status")
    scanning = _get("scanning")

    # Header
    d.rectangle((0, 0, 127, 12), fill="#111")
    label = VIEW_LABELS[view_idx]
    d.text((2, 1), f"AD RECON: {label}", font=font, fill="#FF8800")
    d.ellipse((118, 3, 124, 9), fill="#00FF00" if scanning else "#666")

    y = 14

    if view_idx == 0:
        # Domain info
        server = _get("selected_server")
        domain = _get("domain")
        base = _get("base_dn")
        servers = _get("ldap_servers")
        nc = _get("naming_contexts")

        d.text((2, y), f"Server: {server or '(none)'}", font=font, fill="#AAAAAA")
        y += 12
        d.text((2, y), f"Domain: {domain or '?'}", font=font, fill="#00CCFF")
        y += 12
        d.text((2, y), f"Base: {base[:18]}", font=font, fill="#888")
        y += 14

        d.text((2, y), f"LDAP servers: {len(servers)}", font=font, fill="#888")
        y += 12
        d.text((2, y), f"NCs: {len(nc)}", font=font, fill="#888")
        y += 14

        u = len(_get("users"))
        g = len(_get("groups"))
        c = len(_get("computers"))
        d.text((2, y), f"U:{u}  G:{g}  C:{c}", font=font, fill="#00FF88")

    elif view_idx == 1:
        items = _get("users")
        _draw_scroll_list(d, y, items, scroll, "Users")

    elif view_idx == 2:
        items = _get("groups")
        _draw_scroll_list(d, y, items, scroll, "Groups")

    elif view_idx == 3:
        items = _get("computers")
        _draw_scroll_list(d, y, items, scroll, "Computers")

    # Status
    d.rectangle((0, 106, 127, 115), fill="#0a0a0a")
    d.text((2, 107), status[:21], font=font, fill="#FFCC00")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK K1:scan K2:exp K3x", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_scroll_list(d, y_start, items, scroll, label):
    """Draw a scrollable text list."""
    if not items:
        d.text((4, y_start + 20), f"No {label} found", font=font, fill="#666")
        d.text((4, y_start + 34), "OK=enumerate", font=font, fill="#666")
        return

    d.text((2, y_start), f"Total: {len(items)}", font=font, fill="#888")
    y = y_start + 12
    visible = 7
    for i in range(scroll, min(scroll + visible, len(items))):
        color = "#00FF00" if i == scroll else "#AAAAAA"
        d.text((2, y), items[i][:21], font=font, fill=color)
        y += 12


def _show_msg(line1, line2=""):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), line1[:21], font=font, fill="#00FF00")
    if line2:
        d.text((4, 65), line2[:21], font=font, fill="#888")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 16), "AD RECON", font=font, fill="#FF8800")
    d.text((4, 32), "LDAP enumeration", font=font, fill="#888")
    d.text((4, 52), "OK=Enumerate", font=font, fill="#666")
    d.text((4, 64), "L/R=Views  K1=Scan", font=font, fill="#666")
    d.text((4, 76), "K2=Export  K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    last_press = 0.0

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if btn == "KEY3":
                _set(stop=True)
                break

            elif btn == "OK":
                _start_enumerate()

            elif btn == "KEY1":
                _start_ldap_scan()

            elif btn == "KEY2":
                path = _export_json()
                _show_msg("Exported!", path[-20:])

            elif btn == "LEFT":
                idx = _get("view_idx")
                _set(view_idx=(idx - 1) % len(VIEWS), scroll=0)

            elif btn == "RIGHT":
                idx = _get("view_idx")
                _set(view_idx=(idx + 1) % len(VIEWS), scroll=0)

            elif btn == "UP":
                s = _get("scroll")
                _set(scroll=max(0, s - 1))

            elif btn == "DOWN":
                s = _get("scroll")
                view_idx = _get("view_idx")
                items_map = {1: "users", 2: "groups", 3: "computers"}
                if view_idx in items_map:
                    items = _get(items_map[view_idx])
                    _set(scroll=min(max(0, len(items) - 1), s + 1))
                else:
                    _set(scroll=s + 1)

            _draw_lcd()
            time.sleep(0.05)

    finally:
        _set(stop=True)
        time.sleep(0.2)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
