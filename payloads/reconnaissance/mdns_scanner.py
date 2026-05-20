#!/usr/bin/env python3
"""
RaspyJack Payload -- mDNS / Bonjour Scanner
=============================================
Author: 7h30th3r0n3

Discovers devices on the local network via mDNS (multicast DNS).
Listens for mDNS announcements and actively queries common service
types to enumerate hostnames, IPs, MACs, and services.

Views (KEY1 to cycle):
  LIVE     Real-time discovered devices with service badges
  DETAIL   Detailed view of selected device (all services, TXT records)
  STATS    Network overview: device count by type, service distribution

Controls:
  OK         -- Start / Stop scanning
  KEY1       -- Cycle views
  UP / DOWN  -- Scroll / Select device
  KEY2       -- Export results to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/mDNS/scan_YYYYMMDD_HHMMSS.json
"""

import os
import sys
import json
import time
import socket
import struct
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._iface_helper import select_interface

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
LOOT_DIR = "/root/Raspyjack/loot/mDNS"
VIEWS = ["LIVE", "DETAIL", "STATS"]

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353

QUERY_TYPES = [
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_ssh._tcp.local.",
    "_smb._tcp.local.",
    "_printer._tcp.local.",
    "_ipp._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_googlecast._tcp.local.",
    "_spotify-connect._tcp.local.",
    "_companion-link._tcp.local.",
    "_homekit._tcp.local.",
    "_hap._tcp.local.",
    "_matter._tcp.local.",
    "_mqtt._tcp.local.",
    "_ftp._tcp.local.",
    "_workstation._tcp.local.",
    "_device-info._tcp.local.",
    "_sleep-proxy._udp.local.",
    "_services._dns-sd._udp.local.",
]

SERVICE_LABELS = {
    "_http._tcp": "HTTP",
    "_https._tcp": "HTTPS",
    "_ssh._tcp": "SSH",
    "_smb._tcp": "SMB",
    "_printer._tcp": "Print",
    "_ipp._tcp": "IPP",
    "_airplay._tcp": "AirPlay",
    "_raop._tcp": "RAOP",
    "_googlecast._tcp": "Cast",
    "_spotify-connect._tcp": "Spotify",
    "_companion-link._tcp": "Apple",
    "_homekit._tcp": "HomeKit",
    "_hap._tcp": "HAP",
    "_matter._tcp": "Matter",
    "_mqtt._tcp": "MQTT",
    "_ftp._tcp": "FTP",
    "_workstation._tcp": "WS",
    "_device-info._tcp": "Info",
    "_sleep-proxy._udp": "Sleep",
    "_services._dns-sd._udp": "DNS-SD",
}

SERVICE_COLORS = {
    "HTTP": "#4FC3F7",
    "HTTPS": "#4DB6AC",
    "SSH": "#FFB74D",
    "SMB": "#BA68C8",
    "Print": "#F06292",
    "IPP": "#F06292",
    "AirPlay": "#E0E0E0",
    "RAOP": "#E0E0E0",
    "Cast": "#66BB6A",
    "Spotify": "#1DB954",
    "Apple": "#BDBDBD",
    "HomeKit": "#FF8A65",
    "HAP": "#FF8A65",
    "Matter": "#FFF176",
    "MQTT": "#7986CB",
    "FTP": "#AED581",
    "WS": "#90A4AE",
    "Info": "#78909C",
    "Sleep": "#546E7A",
    "DNS-SD": "#607D8B",
}

# Theme
C_BG = "#0a0a12"
C_HEADER = "#0d1117"
C_ACCENT = "#00E5FF"
C_ACCENT2 = "#7C4DFF"
C_TEXT = "#E0E0E0"
C_DIM = "#555555"
C_MUTED = "#888888"
C_OK = "#00E676"
C_WARN = "#FFD740"
C_ROW_EVEN = "#0d0d1a"
C_ROW_ODD = "#12121f"
C_SELECT = "#1a1a3a"
C_BADGE_BG = "#1e1e2e"

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = False
view_idx = 0
scroll = 0
selected = 0
_frame = 0

# {mac_or_ip: {hostname, ip, mac, services: set(), txt: {}, first_seen, last_seen, source_ip}}
devices = {}
total_queries = 0
total_responses = 0

# ---------------------------------------------------------------------------
# OUI vendor lookup (common prefixes)
# ---------------------------------------------------------------------------
OUI = {
    "AC:DE:48": "Apple", "00:1C:B3": "Apple", "A4:83:E7": "Apple",
    "F0:18:98": "Apple", "34:02:86": "Apple", "00:25:00": "Apple",
    "70:56:81": "Apple", "3C:06:30": "Apple", "F4:F1:5A": "Apple",
    "FC:F1:36": "Samsung", "A0:CC:2B": "Samsung", "8C:F5:A3": "Samsung",
    "78:02:F8": "Xiaomi", "50:EC:50": "Xiaomi", "64:CE:D1": "Xiaomi",
    "B8:27:EB": "RPi", "DC:A6:32": "RPi", "E4:5F:01": "RPi",
    "D8:3A:DD": "RPi", "2C:CF:67": "RPi",
    "00:50:56": "VMware", "00:0C:29": "VMware",
    "08:00:27": "VBox",
    "3C:5A:B4": "Google", "F4:F5:D8": "Google", "54:60:09": "Google",
    "00:1A:2B": "Cisco", "00:1B:44": "Cisco",
    "44:D9:E7": "Ubiquiti", "FC:EC:DA": "Ubiquiti",
    "B0:BE:76": "TP-Link", "50:C7:BF": "TP-Link",
    "60:A4:4C": "ASUSTek", "04:D4:C4": "ASUSTek",
    "9C:B6:D0": "Rivet", "00:17:88": "Philips",
    "68:DB:F5": "Amazon", "44:65:0D": "Amazon",
    "30:FD:38": "Google",
    "E8:48:B8": "Dell", "00:14:22": "Dell",
    "98:FA:9B": "ARRIS", "00:1D:D5": "ARRIS",
    "A4:77:33": "Google",
}


def _vendor(mac):
    if not mac:
        return ""
    prefix = mac.upper()[:8]
    return OUI.get(prefix, "")


# ---------------------------------------------------------------------------
# ARP table → MAC resolution
# ---------------------------------------------------------------------------
_arp_cache = {}
_arp_ts = 0.0


def _refresh_arp():
    global _arp_ts
    now = time.time()
    if now - _arp_ts < 5:
        return
    _arp_ts = now
    try:
        r = subprocess.run(["ip", "neigh", "show"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[3] == "lladdr":
                _arp_cache[parts[0]] = parts[4].upper()
    except Exception:
        pass


def _mac_for_ip(ip):
    _refresh_arp()
    return _arp_cache.get(ip, "")


# ---------------------------------------------------------------------------
# mDNS packet building & parsing
# ---------------------------------------------------------------------------

def _build_query(name, qtype=12):
    tid = 0
    flags = 0
    questions = 1
    header = struct.pack("!HHHHHH", tid, flags, questions, 0, 0, 0)
    parts = name.rstrip(".").split(".")
    qname = b""
    for part in parts:
        encoded = part.encode("utf-8")
        qname += struct.pack("B", len(encoded)) + encoded
    qname += b"\x00"
    question = qname + struct.pack("!HH", qtype, 0x8001)
    return header + question


def _decode_name(data, offset):
    labels = []
    jumped = False
    original_offset = offset
    max_jumps = 20
    jumps = 0
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                original_offset = offset + 2
            jumped = True
            offset = pointer
            jumps += 1
            if jumps > max_jumps:
                break
            continue
        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset:offset + length].decode("utf-8", errors="replace"))
        offset += length
    name = ".".join(labels)
    return name, (original_offset if jumped else offset)


def _parse_response(data, source_ip):
    global total_responses
    if len(data) < 12:
        return

    flags = struct.unpack("!H", data[2:4])[0]
    is_response = (flags & 0x8000) != 0
    if not is_response:
        return

    total_responses += 1
    qdcount = struct.unpack("!H", data[4:6])[0]
    ancount = struct.unpack("!H", data[6:8])[0]
    nscount = struct.unpack("!H", data[8:10])[0]
    arcount = struct.unpack("!H", data[10:12])[0]

    offset = 12
    for _ in range(qdcount):
        if offset >= len(data):
            return
        _, offset = _decode_name(data, offset)
        offset += 4

    records = ancount + nscount + arcount
    for _ in range(records):
        if offset + 10 > len(data):
            return
        rname, offset = _decode_name(data, offset)
        if offset + 10 > len(data):
            return
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata_start = offset
        if offset + rdlength > len(data):
            return

        mac = _mac_for_ip(source_ip)
        hostname = ""
        ip_addr = source_ip
        service = ""
        txt_data = {}

        if rtype == 1:  # A record
            if rdlength == 4:
                ip_addr = socket.inet_ntoa(data[offset:offset + 4])
            hostname = rname.replace(".local", "").replace(".", "")

        elif rtype == 12:  # PTR
            target, _ = _decode_name(data, offset)
            for svc_key, svc_label in SERVICE_LABELS.items():
                if svc_key in rname:
                    service = svc_label
                    break
            instance_name = target.split(".")[0] if target else ""
            if instance_name:
                hostname = instance_name

        elif rtype == 33:  # SRV
            if rdlength >= 6:
                target, _ = _decode_name(data, offset + 6)
                hostname = target.replace(".local", "").replace(".", "")

        elif rtype == 16:  # TXT
            pos = offset
            end = offset + rdlength
            while pos < end:
                tlen = data[pos]
                pos += 1
                if pos + tlen > end:
                    break
                txt_str = data[pos:pos + tlen].decode("utf-8", errors="replace")
                if "=" in txt_str:
                    k, v = txt_str.split("=", 1)
                    txt_data[k] = v
                pos += tlen

        elif rtype == 28:  # AAAA
            pass

        offset = rdata_start + rdlength

        if not hostname and not service:
            continue

        _register_device(
            source_ip=source_ip,
            hostname=hostname,
            ip=ip_addr,
            mac=mac,
            service=service,
            txt=txt_data,
        )


def _register_device(source_ip, hostname, ip, mac, service, txt):
    key = ip or source_ip
    now = time.time()
    with lock:
        if key in devices:
            d = devices[key]
            if hostname and not d["hostname"]:
                d["hostname"] = hostname
            if mac and not d["mac"]:
                d["mac"] = mac
            if service:
                d["services"].add(service)
            if txt:
                d["txt"].update(txt)
            d["last_seen"] = now
        else:
            devices[key] = {
                "hostname": hostname or "",
                "ip": ip or source_ip,
                "mac": mac or "",
                "services": {service} if service else set(),
                "txt": dict(txt),
                "first_seen": now,
                "last_seen": now,
                "vendor": _vendor(mac),
            }
        if mac and not devices[key]["vendor"]:
            devices[key]["vendor"] = _vendor(mac)


# ---------------------------------------------------------------------------
# Scan threads
# ---------------------------------------------------------------------------

def _listener_thread():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        sock.bind(("", MDNS_PORT))
        mreq = struct.pack("4s4s", socket.inet_aton(MDNS_ADDR), socket.inet_aton("0.0.0.0"))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(1.0)

        while running:
            try:
                data, addr = sock.recvfrom(4096)
                _parse_response(data, addr[0])
            except socket.timeout:
                continue
            except Exception:
                continue
        sock.close()
    except Exception:
        pass


def _query_thread():
    global total_queries
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

        while running:
            for svc in QUERY_TYPES:
                if not running:
                    break
                pkt = _build_query(svc, qtype=12)
                try:
                    sock.sendto(pkt, (MDNS_ADDR, MDNS_PORT))
                    total_queries += 1
                except Exception:
                    pass
                for _ in range(10):
                    if not running:
                        break
                    time.sleep(0.1)
            for _ in range(50):
                if not running:
                    break
                time.sleep(0.1)
        sock.close()
    except Exception:
        pass


def _arp_ping_thread():
    while running:
        _refresh_arp()
        with lock:
            for key, d in devices.items():
                if not d["mac"]:
                    mac = _mac_for_ip(d["ip"])
                    if mac:
                        d["mac"] = mac
                        d["vendor"] = _vendor(mac)
        for _ in range(30):
            if not running:
                return
            time.sleep(0.1)


# ---------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------

def _sorted_devices():
    with lock:
        items = list(devices.values())
    return sorted(items, key=lambda d: (-len(d["services"]), d["hostname"].lower()))


def _draw_header(d, font_sm, title, count):
    d.rectangle((0, 0, 127, 13), fill=C_HEADER)
    d.text((3, 2), title, font=font_sm, fill=C_ACCENT)
    if running:
        dots = "." * ((_frame // 5) % 4)
        d.text((60, 2), f"SCAN{dots}", font=font_sm, fill=C_OK)
    cnt_text = str(count)
    d.text((123, 2), cnt_text, font=font_sm, fill=C_ACCENT2, anchor="ra")


def _draw_footer(d, font_sm, hint):
    d.rectangle((0, 116, 127, 127), fill=C_HEADER)
    d.text((2, 117), hint, font=font_sm, fill=C_MUTED)


def _truncate(text, font, max_w):
    if not text:
        return ""
    try:
        bbox = font.getbbox(text)
        w = bbox[2] - bbox[0]
    except Exception:
        w = len(text) * 6
    if w <= max_w:
        return text
    while len(text) > 1:
        text = text[:-1]
        try:
            bbox = font.getbbox(text + "..")
            w = bbox[2] - bbox[0]
        except Exception:
            w = (len(text) + 2) * 6
        if w <= max_w:
            return text + ".."
    return text


# ---------------------------------------------------------------------------
# LIVE view
# ---------------------------------------------------------------------------

def _draw_live(lcd, font, font_sm):
    global _frame
    _frame += 1

    devs = _sorted_devices()
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)

    _draw_header(d, font_sm, "mDNS", len(devs))

    if not devs:
        if running:
            y_center = 60
            d.text((64, y_center), "Listening...", font=font, fill=C_DIM, anchor="mm")
            anim_y = y_center + 14
            bar_w = 60
            offset = (_frame * 3) % (bar_w * 2)
            for i in range(bar_w):
                brightness = abs((i + offset) % bar_w - bar_w // 2) / (bar_w // 2)
                color_val = int(brightness * 80)
                c = f"#{color_val:02x}{color_val:02x}{int(brightness * 200):02x}"
                d.line([(34 + i, anim_y), (34 + i, anim_y + 2)], fill=c)
        else:
            d.text((64, 60), "OK = Start", font=font, fill=C_MUTED, anchor="mm")

        _draw_footer(d, font_sm, "K1:View K3:Exit")
        lcd.LCD_ShowImage(img, 0, 0)
        return

    row_h = 14
    visible = (116 - 15) // row_h
    max_scroll = max(0, len(devs) - visible)
    sc = min(scroll, max_scroll)

    for i, dev in enumerate(devs[sc:sc + visible]):
        y = 15 + i * row_h
        bg = C_ROW_ODD if (i + sc) % 2 else C_ROW_EVEN
        d.rectangle((0, y, 127, y + row_h - 1), fill=bg)

        name = dev["hostname"] or dev["ip"]
        name_trunc = _truncate(name, font_sm, 75)
        d.text((3, y + 1), name_trunc, font=font_sm, fill=C_TEXT)

        badge_x = 127
        for svc in sorted(dev["services"]):
            color = SERVICE_COLORS.get(svc, C_DIM)
            label = svc[:4]
            try:
                bbox = font_sm.getbbox(label)
                bw = bbox[2] - bbox[0] + 4
            except Exception:
                bw = len(label) * 5 + 4
            badge_x -= bw + 1
            d.rectangle((badge_x, y + 1, badge_x + bw, y + row_h - 3), fill=C_BADGE_BG)
            d.text((badge_x + 2, y + 1), label, font=font_sm, fill=color)

    if len(devs) > visible:
        bar_h = max(4, int(visible / len(devs) * 100))
        bar_y = 15 + int(sc / max(len(devs) - 1, 1) * (100 - bar_h))
        d.rectangle((126, 15, 127, 115), fill=C_BG)
        d.rectangle((126, bar_y, 127, bar_y + bar_h), fill=C_DIM)

    _draw_footer(d, font_sm, "K1:View K2:Save")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# DETAIL view
# ---------------------------------------------------------------------------

def _draw_detail(lcd, font, font_sm):
    devs = _sorted_devices()
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)

    if not devs:
        _draw_header(d, font_sm, "DETAIL", 0)
        d.text((64, 60), "No devices", font=font, fill=C_DIM, anchor="mm")
        _draw_footer(d, font_sm, "K1:View K3:Exit")
        lcd.LCD_ShowImage(img, 0, 0)
        return

    idx = min(selected, len(devs) - 1)
    dev = devs[idx]

    _draw_header(d, font_sm, f"[{idx + 1}/{len(devs)}]", len(dev["services"]))

    y = 16
    name = dev["hostname"] or "Unknown"
    d.text((3, y), _truncate(name, font, 122), font=font, fill=C_ACCENT)
    y += 13

    d.text((3, y), dev["ip"], font=font_sm, fill=C_TEXT)
    y += 10

    mac_str = dev["mac"] or "??:??:??:??:??:??"
    vendor = dev["vendor"]
    mac_display = f"{mac_str}"
    if vendor:
        mac_display += f" ({vendor})"
    d.text((3, y), _truncate(mac_display, font_sm, 122), font=font_sm, fill=C_MUTED)
    y += 11

    d.line([(3, y), (124, y)], fill=C_DIM)
    y += 3

    d.text((3, y), "Services:", font=font_sm, fill=C_ACCENT2)
    y += 10
    svcs = sorted(dev["services"])
    detail_scroll = max(0, scroll)
    visible_svcs = svcs[detail_scroll:]
    for svc in visible_svcs:
        if y > 105:
            break
        color = SERVICE_COLORS.get(svc, C_TEXT)
        d.text((8, y), svc, font=font_sm, fill=color)
        y += 9

    if not svcs:
        d.text((8, y), "(none yet)", font=font_sm, fill=C_DIM)
        y += 9

    if dev["txt"]:
        y += 2
        for k, v in list(dev["txt"].items())[:3]:
            if y > 108:
                break
            txt_line = f"{k}={v}"
            d.text((3, y), _truncate(txt_line, font_sm, 122), font=font_sm, fill=C_DIM)
            y += 9

    _draw_footer(d, font_sm, "U/D:Nav K1:View")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# STATS view
# ---------------------------------------------------------------------------

def _draw_stats(lcd, font, font_sm):
    global _frame
    _frame += 1

    devs = _sorted_devices()
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)

    _draw_header(d, font_sm, "STATS", len(devs))

    y = 17

    d.text((64, y), str(len(devs)), font=scaled_font(18), fill=C_ACCENT, anchor="mt")
    y += 22
    d.text((64, y), "Devices Found", font=font_sm, fill=C_MUTED, anchor="mt")
    y += 12

    d.line([(10, y), (117, y)], fill=C_DIM)
    y += 4

    svc_count = {}
    vendor_count = {}
    mac_count = 0
    for dev in devs:
        for svc in dev["services"]:
            svc_count[svc] = svc_count.get(svc, 0) + 1
        v = dev["vendor"]
        if v:
            vendor_count[v] = vendor_count.get(v, 0) + 1
        if dev["mac"]:
            mac_count += 1

    d.text((3, y), f"MACs resolved: {mac_count}/{len(devs)}", font=font_sm, fill=C_TEXT)
    y += 10
    d.text((3, y), f"Queries: {total_queries}  Resp: {total_responses}", font=font_sm, fill=C_DIM)
    y += 12

    top_svcs = sorted(svc_count.items(), key=lambda x: -x[1])[:4]
    if top_svcs:
        d.text((3, y), "Top services:", font=font_sm, fill=C_ACCENT2)
        y += 10
        max_count = top_svcs[0][1] if top_svcs else 1
        for svc_name, cnt in top_svcs:
            if y > 108:
                break
            color = SERVICE_COLORS.get(svc_name, C_TEXT)
            bar_w = int(cnt / max(max_count, 1) * 60)
            d.rectangle((3, y + 1, 3 + bar_w, y + 7), fill=color)
            d.text((68, y), f"{svc_name} ({cnt})", font=font_sm, fill=C_MUTED)
            y += 9

    _draw_footer(d, font_sm, "K1:View K2:Save")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    with lock:
        snapshot = {}
        for key, dev in devices.items():
            snapshot[key] = {
                "hostname": dev["hostname"],
                "ip": dev["ip"],
                "mac": dev["mac"],
                "vendor": dev["vendor"],
                "services": sorted(dev["services"]),
                "txt": dev["txt"],
                "first_seen": dev["first_seen"],
                "last_seen": dev["last_seen"],
            }

    path = os.path.join(LOOT_DIR, f"scan_{ts}.json")
    with open(path, "w") as f:
        json.dump(snapshot, f, indent=2, default=str)
    return f"scan_{ts}"


# ---------------------------------------------------------------------------
# Start / Stop
# ---------------------------------------------------------------------------
_threads = []


def _start():
    global running, total_queries, total_responses
    if running:
        return
    running = True
    total_queries = 0
    total_responses = 0

    for target in [_listener_thread, _query_thread, _arp_ping_thread]:
        t = threading.Thread(target=target, daemon=True)
        t.start()
        _threads.append(t)


def _stop():
    global running
    running = False
    for t in _threads:
        t.join(timeout=3)
    _threads.clear()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global view_idx, scroll, selected

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font = scaled_font(10)
    font_sm = scaled_font(8)

    os.makedirs(LOOT_DIR, exist_ok=True)

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 127), fill=C_BG)

    d.text((64, 20), "mDNS", font=scaled_font(16), fill=C_ACCENT, anchor="mm")
    d.text((64, 38), "Scanner", font=font, fill=C_ACCENT2, anchor="mm")

    d.line([(25, 48), (102, 48)], fill=C_DIM)

    d.text((64, 58), "Bonjour / Avahi", font=font_sm, fill=C_MUTED, anchor="mm")
    d.text((64, 70), "Service Discovery", font=font_sm, fill=C_MUTED, anchor="mm")

    d.text((64, 90), "OK = Start", font=font_sm, fill=C_OK, anchor="mm")
    d.text((64, 102), "KEY3 = Exit", font=font_sm, fill=C_MUTED, anchor="mm")

    lcd.LCD_ShowImage(img, 0, 0)

    time.sleep(0.3)
    while get_button(PINS, GPIO) is not None:
        time.sleep(0.05)

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break
            elif btn == "OK":
                if running:
                    _stop()
                else:
                    _start()
                time.sleep(0.3)
            elif btn == "KEY1":
                view_idx = (view_idx + 1) % len(VIEWS)
                scroll = 0
                time.sleep(0.2)
            elif btn == "UP":
                if VIEWS[view_idx] == "DETAIL":
                    selected = max(0, selected - 1)
                    scroll = 0
                else:
                    scroll = max(0, scroll - 1)
                time.sleep(0.12)
            elif btn == "DOWN":
                if VIEWS[view_idx] == "DETAIL":
                    with lock:
                        selected = min(selected + 1, max(0, len(devices) - 1))
                    scroll = 0
                else:
                    scroll += 1
                time.sleep(0.12)
            elif btn == "KEY2":
                name = _export()
                img2 = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
                d2 = ScaledDraw(img2)
                d2.text((64, 50), "Exported!", font=font, fill=C_OK, anchor="mm")
                d2.text((64, 68), name[:22], font=font_sm, fill=C_MUTED, anchor="mm")
                lcd.LCD_ShowImage(img2, 0, 0)
                time.sleep(1.5)

            view = VIEWS[view_idx]
            if view == "LIVE":
                _draw_live(lcd, font, font_sm)
            elif view == "DETAIL":
                _draw_detail(lcd, font, font_sm)
            elif view == "STATS":
                _draw_stats(lcd, font, font_sm)

            time.sleep(0.05)

    finally:
        _stop()
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
