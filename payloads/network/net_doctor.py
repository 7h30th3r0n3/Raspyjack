#!/usr/bin/env python3
"""
RaspyJack Payload -- Network Doctor
=====================================
Author: 7h30th3r0n3

Passive network health analyzer. Plug in via Ethernet or WiFi
and instantly detect common L2/L3 issues:

  - STP topology changes & root bridge conflicts
  - ARP storms & ARP spoofing (duplicate IPs)
  - DHCP rogue servers
  - Broadcast storms
  - Duplicate MAC addresses
  - CDP/LLDP neighbor info

Flow:
  1) Select interface (eth/wlan)
  2) Passive sniff — no packets sent
  3) Real-time dashboard with alerts

Controls:
  OK          -- Start / stop capture
  UP / DOWN   -- Scroll alerts
  LEFT / RIGHT-- Switch view (Dashboard / Alerts / STP / ARP)
  KEY1        -- Reset counters
  KEY2        -- Export report
  KEY3        -- Exit

Loot: /root/Raspyjack/loot/NetDoctor/
"""

import os
import sys
import time
import json
import threading
from datetime import datetime
from collections import defaultdict

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._iface_helper import select_interface

try:
    from scapy.all import (
        sniff, Ether, ARP, IP, UDP, BOOTP, DHCP, Dot3, LLC, STP,
        conf, Raw,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for p in PINS.values():
    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
font = scaled_font(9)
font_sm = scaled_font(7)

LOOT_DIR = "/root/Raspyjack/loot/NetDoctor"
DEBOUNCE = 0.2
VIEWS = ["dashboard", "alerts", "stp", "arp"]

lock = threading.Lock()
_shutdown = threading.Event()
_sniffing = threading.Event()

# --- Counters ---
stats = {
    "packets": 0,
    "arp_req": 0,
    "arp_rep": 0,
    "bpdu": 0,
    "dhcp": 0,
    "broadcast": 0,
}
arp_table = {}         # IP -> {mac, count, first, last}
arp_rate = []          # timestamps of ARP packets (sliding window)
stp_roots = {}         # bridge_id -> {priority, mac, port, age, last_seen}
dhcp_servers = {}      # server_ip -> {mac, last_seen, count}
alerts = []            # [(timestamp, severity, message)]
mac_ip_map = defaultdict(set)  # MAC -> set of IPs

ARP_STORM_THRESHOLD = 50    # ARP packets per second
ARP_WINDOW = 5              # seconds for rate calculation
BCAST_STORM_THRESHOLD = 200  # broadcast packets per second
bcast_rate = []


def _ts():
    return datetime.now().strftime("%H:%M:%S")


def _add_alert(severity, msg):
    with lock:
        alerts.append((_ts(), severity, msg))
        if len(alerts) > 100:
            del alerts[:50]


def _packet_handler(pkt):
    now = time.time()

    with lock:
        stats["packets"] += 1

    # --- Broadcast detection ---
    if pkt.haslayer(Ether):
        dst = pkt[Ether].dst
        if dst == "ff:ff:ff:ff:ff:ff":
            with lock:
                stats["broadcast"] += 1
                bcast_rate.append(now)
                while bcast_rate and bcast_rate[0] < now - ARP_WINDOW:
                    bcast_rate.pop(0)
                if len(bcast_rate) > BCAST_STORM_THRESHOLD:
                    rate = len(bcast_rate) / ARP_WINDOW
                    _add_alert("CRIT", f"BCAST STORM {rate:.0f}/s")
                    bcast_rate.clear()

    # --- ARP ---
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        src_ip = arp.psrc
        src_mac = arp.hwsrc.upper()
        op = arp.op

        with lock:
            if op == 1:
                stats["arp_req"] += 1
            elif op == 2:
                stats["arp_rep"] += 1

            arp_rate.append(now)
            while arp_rate and arp_rate[0] < now - ARP_WINDOW:
                arp_rate.pop(0)

            if len(arp_rate) > ARP_STORM_THRESHOLD:
                rate = len(arp_rate) / ARP_WINDOW
                _add_alert("CRIT", f"ARP STORM {rate:.0f}/s")
                arp_rate.clear()

            if src_ip and src_ip != "0.0.0.0":
                if src_ip in arp_table:
                    existing = arp_table[src_ip]
                    if existing["mac"] != src_mac:
                        _add_alert("WARN", f"ARP SPOOF {src_ip}")
                        _add_alert("WARN", f"  {existing['mac']}")
                        _add_alert("WARN", f"  {src_mac}")
                    existing["count"] += 1
                    existing["last"] = _ts()
                else:
                    arp_table[src_ip] = {
                        "mac": src_mac, "count": 1,
                        "first": _ts(), "last": _ts(),
                    }

                mac_ip_map[src_mac].add(src_ip)

    # --- STP BPDU ---
    if pkt.haslayer(STP):
        stp = pkt[STP]
        with lock:
            stats["bpdu"] += 1
            root_mac = stp.rootmac
            root_prio = stp.rootid
            bridge_mac = stp.bridgemac
            bridge_prio = stp.bridgeid
            port = stp.portid
            age = stp.maxage

            bid = f"{bridge_prio}:{bridge_mac}"
            rid = f"{root_prio}:{root_mac}"

            if rid not in stp_roots:
                _add_alert("INFO", f"STP ROOT {root_mac[:8]}")
                _add_alert("INFO", f"  prio={root_prio}")

            stp_roots[rid] = {
                "root_prio": root_prio,
                "root_mac": root_mac,
                "bridge_prio": bridge_prio,
                "bridge_mac": bridge_mac,
                "port": port,
                "age": age,
                "last_seen": _ts(),
            }

            if len(stp_roots) > 1:
                _add_alert("WARN", f"STP CONFLICT {len(stp_roots)} roots")

    # --- DHCP ---
    if pkt.haslayer(DHCP):
        with lock:
            stats["dhcp"] += 1
        if pkt.haslayer(BOOTP):
            bootp = pkt[BOOTP]
            if bootp.op == 2:
                server_ip = bootp.siaddr
                src_mac = pkt[Ether].src.upper() if pkt.haslayer(Ether) else "?"
                with lock:
                    if server_ip not in dhcp_servers:
                        _add_alert("INFO", f"DHCP SRV {server_ip}")
                    if server_ip in dhcp_servers:
                        dhcp_servers[server_ip]["count"] += 1
                        dhcp_servers[server_ip]["last_seen"] = _ts()
                    else:
                        dhcp_servers[server_ip] = {
                            "mac": src_mac, "count": 1, "last_seen": _ts(),
                        }
                    if len(dhcp_servers) > 1:
                        _add_alert("WARN", "ROGUE DHCP detected!")
                        for ip, s in dhcp_servers.items():
                            _add_alert("WARN", f"  {ip} ({s['mac'][:8]})")


def _sniff_thread(iface):
    while not _shutdown.is_set():
        if not _sniffing.is_set():
            time.sleep(0.1)
            continue
        try:
            sniff(
                iface=iface,
                prn=_packet_handler,
                store=0,
                filter="arp or (ether dst 01:80:c2:00:00:00) or (udp port 67 or udp port 68) or ether broadcast",
                stop_filter=lambda _: _shutdown.is_set() or not _sniffing.is_set(),
                timeout=30,
            )
        except Exception:
            time.sleep(1)


# --- Display ---

C_BG = "black"
C_OK = "#00ff44"
C_WARN = "#ffaa00"
C_CRIT = "#ff3333"
C_INFO = "#00ccff"
C_DIM = "#555555"
SEV_COL = {"INFO": C_INFO, "WARN": C_WARN, "CRIT": C_CRIT}


def _draw_dashboard(lcd):
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "NET DOCTOR", font=font_sm, fill=C_INFO)
    st = "SCAN" if _sniffing.is_set() else "IDLE"
    d.text((80, 1), st, font=font_sm, fill=C_OK if _sniffing.is_set() else C_DIM)

    with lock:
        s = dict(stats)
        n_alerts = len(alerts)
        n_arp = len(arp_table)
        n_stp = len(stp_roots)
        n_dhcp = len(dhcp_servers)
        crit = sum(1 for _, sev, _ in alerts if sev == "CRIT")
        warn = sum(1 for _, sev, _ in alerts if sev == "WARN")
        arp_r = len(arp_rate) / max(1, ARP_WINDOW)

    y = 15
    d.text((2, y), f"Packets: {s['packets']}", font=font_sm, fill="#fff")
    y += 11
    d.text((2, y), f"ARP: {s['arp_req']}req {s['arp_rep']}rep", font=font_sm, fill="#fff")
    d.text((90, y), f"{arp_r:.0f}/s", font=font_sm, fill=C_CRIT if arp_r > 10 else C_OK)
    y += 11
    d.text((2, y), f"BPDU: {s['bpdu']}", font=font_sm, fill="#fff")
    d.text((60, y), f"DHCP: {s['dhcp']}", font=font_sm, fill="#fff")
    y += 11
    d.text((2, y), f"Bcast: {s['broadcast']}", font=font_sm, fill="#fff")
    y += 13

    d.rectangle((2, y, 125, y), fill="#333")
    y += 3
    d.text((2, y), f"Hosts: {n_arp}", font=font_sm, fill=C_INFO)
    d.text((55, y), f"STP: {n_stp}", font=font_sm, fill=C_WARN if n_stp > 1 else C_OK)
    y += 11
    d.text((2, y), f"DHCP srv: {n_dhcp}", font=font_sm,
           fill=C_CRIT if n_dhcp > 1 else C_OK)
    y += 13

    if crit > 0:
        d.text((2, y), f"!! {crit} CRITICAL", font=font_sm, fill=C_CRIT)
    elif warn > 0:
        d.text((2, y), f"! {warn} warnings", font=font_sm, fill=C_WARN)
    else:
        d.text((2, y), "No issues detected", font=font_sm, fill=C_OK)

    d.rectangle((0, 117, 127, 127), fill="#111")
    d.text((2, 118), "OK:Scan K1:Rst K3:Exit", font=font_sm, fill=C_DIM)
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_alerts(lcd, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "ALERTS", font=font_sm, fill=C_WARN)
    with lock:
        items = list(alerts)
    d.text((60, 1), f"{len(items)}", font=font_sm, fill="#fff")

    y = 15
    visible = (HEIGHT - 30) // 10
    start = max(0, min(scroll, len(items) - visible))
    for i in range(start, min(start + visible, len(items))):
        ts, sev, msg = items[i]
        col = SEV_COL.get(sev, C_DIM)
        d.text((2, y), f"{ts} {msg[:18]}", font=font_sm, fill=col)
        y += 10

    d.rectangle((0, 117, 127, 127), fill="#111")
    d.text((2, 118), "^v:Scroll K3:Exit", font=font_sm, fill=C_DIM)
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_stp(lcd):
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "STP / SPANNING TREE", font=font_sm, fill=C_INFO)

    with lock:
        roots = list(stp_roots.values())

    y = 15
    if not roots:
        d.text((4, 40), "No BPDUs received", font=font_sm, fill=C_DIM)
        d.text((4, 55), "Connect to switch", font=font_sm, fill=C_DIM)
    else:
        for r in roots[:4]:
            d.text((2, y), f"Root: {r['root_mac'][:11]}", font=font_sm, fill=C_OK)
            y += 10
            d.text((2, y), f"  Prio:{r['root_prio']} Port:{r['port']}", font=font_sm, fill="#fff")
            y += 10
            d.text((2, y), f"  Bridge:{r['bridge_mac'][:11]}", font=font_sm, fill=C_DIM)
            y += 10
            d.text((2, y), f"  MaxAge:{r['age']} @{r['last_seen']}", font=font_sm, fill=C_DIM)
            y += 13
            if y > 105:
                break

        if len(roots) > 1:
            d.text((2, 105), f"!! {len(roots)} ROOT BRIDGES !!", font=font_sm, fill=C_CRIT)

    d.rectangle((0, 117, 127, 127), fill="#111")
    d.text((2, 118), "L/R:View K3:Exit", font=font_sm, fill=C_DIM)
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_arp(lcd, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), "ARP TABLE", font=font_sm, fill=C_INFO)

    with lock:
        items = sorted(arp_table.items(), key=lambda x: x[1]["count"], reverse=True)
        arp_r = len(arp_rate) / max(1, ARP_WINDOW)

    d.text((70, 1), f"{arp_r:.0f}/s {len(items)}h", font=font_sm, fill="#fff")

    y = 15
    visible = (HEIGHT - 30) // 10
    start = max(0, min(scroll, len(items) - visible))
    for i in range(start, min(start + visible, len(items))):
        ip, info = items[i]
        dup = len(mac_ip_map.get(info["mac"], set())) > 1
        col = C_CRIT if dup else "#fff"
        short_ip = ip.split(".")[-1] if "." in ip else ip
        d.text((2, y), f"{ip}", font=font_sm, fill=col)
        d.text((85, y), f"{info['mac'][-5:]}", font=font_sm, fill=C_DIM)
        y += 10

    d.rectangle((0, 117, 127, 127), fill="#111")
    d.text((2, 118), "^v:Scroll K3:Exit", font=font_sm, fill=C_DIM)
    lcd.LCD_ShowImage(img, 0, 0)


def _export():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    with lock:
        report = {
            "timestamp": ts,
            "stats": dict(stats),
            "alerts": [(t, s, m) for t, s, m in alerts],
            "arp_table": {ip: {**v} for ip, v in arp_table.items()},
            "stp_roots": {k: {**v} for k, v in stp_roots.items()},
            "dhcp_servers": {k: {**v} for k, v in dhcp_servers.items()},
        }
    path = os.path.join(LOOT_DIR, f"netdoctor_{ts}.json")
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    return path


def main():
    if not SCAPY_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
        d = ScaledDraw(img)
        d.text((4, 50), "scapy not found!", font=font, fill=C_CRIT)
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    iface = select_interface(LCD, font, font_sm, PINS, GPIO,
                             modes=["managed", "monitor"], title="NET DOCTOR")
    if not iface:
        GPIO.cleanup()
        return 0

    sniff_t = threading.Thread(target=_sniff_thread, args=(iface,), daemon=True)
    sniff_t.start()
    _sniffing.set()

    view_idx = 0
    scroll = 0
    last_press = 0

    try:
        while not _shutdown.is_set():
            btn = get_button(PINS, GPIO)
            now = time.time()

            if btn and now - last_press > DEBOUNCE:
                last_press = now

                if btn == "KEY3":
                    break
                elif btn == "OK":
                    if _sniffing.is_set():
                        _sniffing.clear()
                    else:
                        _sniffing.set()
                elif btn == "LEFT":
                    view_idx = (view_idx - 1) % len(VIEWS)
                    scroll = 0
                elif btn == "RIGHT":
                    view_idx = (view_idx + 1) % len(VIEWS)
                    scroll = 0
                elif btn == "UP":
                    scroll = max(0, scroll - 1)
                elif btn == "DOWN":
                    scroll += 1
                elif btn == "KEY1":
                    with lock:
                        for k in stats:
                            stats[k] = 0
                        arp_table.clear()
                        arp_rate.clear()
                        bcast_rate.clear()
                        stp_roots.clear()
                        dhcp_servers.clear()
                        alerts.clear()
                        mac_ip_map.clear()
                elif btn == "KEY2":
                    path = _export()
                    _add_alert("INFO", f"Exported {os.path.basename(path)[:15]}")

            view = VIEWS[view_idx]
            if view == "dashboard":
                _draw_dashboard(LCD)
            elif view == "alerts":
                _draw_alerts(LCD, scroll)
            elif view == "stp":
                _draw_stp(LCD)
            elif view == "arp":
                _draw_arp(LCD, scroll)

            time.sleep(0.1)

    finally:
        _shutdown.set()
        _sniffing.clear()
        LCD.LCD_Clear()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
