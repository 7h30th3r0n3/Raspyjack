#!/usr/bin/env python3
"""
RaspyJack Payload -- Network Doctor
=====================================
Author: 7h30th3r0n3

Passive network health analyzer. Detects:
  - STP root bridge conflicts
  - ARP storms & spoofing
  - Rogue DHCP servers
  - Broadcast storms
  - Host discovery

Controls:
  LEFT/RIGHT  -- Switch view (Dashboard / Alerts / STP / ARP)
  UP/DOWN     -- Scroll
  KEY1        -- Reset counters
  KEY2        -- Export JSON
  KEY3        -- Exit
"""

import os
import sys
import time
import json
import threading
import subprocess
from datetime import datetime
from collections import defaultdict, deque

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

try:
    from scapy.all import sniff, ARP, Ether, STP, BOOTP, DHCP, conf
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
W, H = LCD.width, LCD.height
font = scaled_font(9)
font_sm = scaled_font(7)

LOOT_DIR = "/root/Raspyjack/loot/NetDoctor"
VIEWS = ["dash", "alerts", "stp", "arp"]
ARP_STORM_TH = 50

# All state — no lock needed, only main thread reads, sniff thread only appends
pkt_count = [0]
arp_req = [0]
arp_rep = [0]
bpdu_count = [0]
dhcp_count = [0]
bcast_count = [0]
arp_times = deque(maxlen=200)
arp_table = {}
stp_roots = {}
dhcp_servers = {}
alerts = deque(maxlen=80)
_last_alert = ["", 0.0]
_stop = threading.Event()


def _ts():
    return time.strftime("%H:%M:%S")


def _alert(sev, msg):
    now = time.time()
    if msg == _last_alert[0] and now - _last_alert[1] < 5:
        return
    _last_alert[0] = msg
    _last_alert[1] = now
    alerts.append((_ts(), sev, msg))


def _handler(pkt):
    pkt_count[0] += 1

    if pkt.haslayer(Ether) and pkt[Ether].dst == "ff:ff:ff:ff:ff:ff":
        bcast_count[0] += 1

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        if arp.op == 1:
            arp_req[0] += 1
        else:
            arp_rep[0] += 1
        arp_times.append(time.time())
        now = time.time()
        rate = sum(1 for t in arp_times if t > now - 5) / 5.0
        if rate > ARP_STORM_TH:
            _alert("CRIT", f"ARP STORM {rate:.0f}/s")

        src_ip = arp.psrc
        src_mac = (arp.hwsrc or "").upper()
        if src_ip and src_ip != "0.0.0.0":
            if src_ip in arp_table and arp_table[src_ip]["mac"] != src_mac:
                _alert("WARN", f"SPOOF {src_ip}")
            arp_table[src_ip] = {"mac": src_mac, "count": arp_table.get(src_ip, {}).get("count", 0) + 1, "last": _ts()}

    if pkt.haslayer(STP):
        bpdu_count[0] += 1
        stp = pkt[STP]
        rid = f"{stp.rootid}:{stp.rootmac}"
        if rid not in stp_roots:
            _alert("INFO", f"STP ROOT {stp.rootmac[:11]}")
        stp_roots[rid] = {
            "root_mac": stp.rootmac, "root_prio": stp.rootid,
            "bridge_mac": stp.bridgemac, "bridge_prio": stp.bridgeid,
            "port": stp.portid, "last": _ts(),
        }
        if len(stp_roots) > 1:
            _alert("WARN", f"{len(stp_roots)} STP ROOTS!")

    if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP):
        dhcp_count[0] += 1
        if pkt[BOOTP].op == 2:
            sip = pkt[BOOTP].siaddr
            if sip and sip not in dhcp_servers:
                _alert("INFO", f"DHCP SRV {sip}")
            dhcp_servers[sip] = {"mac": pkt[Ether].src if pkt.haslayer(Ether) else "?", "last": _ts()}
            if len(dhcp_servers) > 1:
                _alert("CRIT", "ROGUE DHCP!")


def _sniff_thread(iface):
    while not _stop.is_set():
        try:
            sniff(iface=iface, prn=_handler, store=0,
                  filter="arp or stp or (udp port 67 or udp port 68)",
                  stop_filter=lambda _: _stop.is_set(), timeout=10)
        except Exception:
            time.sleep(1)


# --- Views ---

C = {
    "bg": "#080c12", "head": "#0a1520", "ok": "#00ff44",
    "warn": "#ffaa00", "crit": "#ff3333", "info": "#00ccff",
    "dim": "#444", "card": "#101820", "white": "#ddd",
}
SEV = {"INFO": C["info"], "WARN": C["warn"], "CRIT": C["crit"]}


def _bar(d, x, y, w, h, val, mx, col):
    d.rectangle((x, y, x + w, y + h), fill="#1a1a1a")
    if mx > 0 and val > 0:
        d.rectangle((x, y, x + min(w, int(w * val / mx)), y + h), fill=col)


def _draw_dash(d):
    d.rectangle((0, 0, 127, 13), fill=C["head"])
    d.text((2, 2), "NET DOCTOR", font=font, fill=C["info"])
    d.ellipse((112, 4, 118, 10), fill=C["ok"])
    d.text((96, 2), "LIVE", font=font_sm, fill=C["ok"])

    now = time.time()
    arp_r = sum(1 for t in arp_times if t > now - 5) / 5.0
    crit = sum(1 for _, s, _ in alerts if s == "CRIT")
    warn = sum(1 for _, s, _ in alerts if s == "WARN")

    y = 16
    d.rectangle((2, y, 125, y + 12), fill=C["card"])
    if crit:
        d.text((4, y + 2), f"X {crit} CRITICAL", font=font_sm, fill=C["crit"])
    elif warn:
        d.text((4, y + 2), f"! {warn} WARNING", font=font_sm, fill=C["warn"])
    else:
        d.text((4, y + 2), "HEALTHY", font=font_sm, fill=C["ok"])
    d.text((85, y + 2), f"{pkt_count[0]}p", font=font_sm, fill=C["dim"])
    y += 15

    d.rectangle((2, y, 62, y + 20), fill=C["card"])
    d.text((4, y + 2), "ARP", font=font_sm, fill=C["info"])
    ac = C["crit"] if arp_r > 10 else C["ok"]
    d.text((24, y + 2), f"{arp_r:.0f}/s", font=font_sm, fill=ac)
    _bar(d, 4, y + 13, 55, 4, arp_r, ARP_STORM_TH, ac)

    d.rectangle((65, y, 125, y + 20), fill=C["card"])
    d.text((67, y + 2), "BCAST", font=font_sm, fill=C["info"])
    d.text((95, y + 2), f"{bcast_count[0]}", font=font_sm, fill=C["white"])
    y += 23

    d.rectangle((2, y, 42, y + 18), fill=C["card"])
    d.text((4, y + 2), "STP", font=font_sm, fill=C["info"])
    sc = C["crit"] if len(stp_roots) > 1 else C["ok"] if stp_roots else C["dim"]
    d.text((4, y + 10), f"{len(stp_roots)}", font=font_sm, fill=sc)

    d.rectangle((45, y, 85, y + 18), fill=C["card"])
    d.text((47, y + 2), "DHCP", font=font_sm, fill=C["info"])
    dc = C["crit"] if len(dhcp_servers) > 1 else C["ok"] if dhcp_servers else C["dim"]
    d.text((47, y + 10), f"{len(dhcp_servers)}", font=font_sm, fill=dc)

    d.rectangle((88, y, 125, y + 18), fill=C["card"])
    d.text((90, y + 2), "HOST", font=font_sm, fill=C["info"])
    d.text((90, y + 10), f"{len(arp_table)}", font=font_sm, fill=C["white"])
    y += 21

    d.rectangle((2, y, 125, y + 10), fill=C["card"])
    d.text((4, y + 1), f"ARP {arp_req[0]}req {arp_rep[0]}rep", font=font_sm, fill=C["dim"])

    d.rectangle((0, 117, 127, 127), fill=C["head"])
    d.text((2, 118), "L/R:View K1:Rst K3:X", font=font_sm, fill=C["dim"])


def _draw_alerts(d, scroll):
    d.rectangle((0, 0, 127, 13), fill=C["head"])
    d.text((2, 2), "ALERTS", font=font, fill=C["warn"])
    items = list(alerts)
    d.text((60, 2), f"{len(items)}", font=font_sm, fill=C["white"])

    vis = (H - 32) // 11
    st = max(0, min(scroll, max(0, len(items) - vis)))
    y = 16
    if not items:
        d.text((10, 50), "No alerts", font=font_sm, fill=C["dim"])
    for i in range(st, min(st + vis, len(items))):
        ts, sev, msg = items[i]
        d.rectangle((2, y, 125, y + 9), fill=C["card"])
        d.text((4, y + 1), ts[-5:], font=font_sm, fill=C["dim"])
        d.text((35, y + 1), msg[:15], font=font_sm, fill=SEV.get(sev, C["dim"]))
        y += 11

    d.rectangle((0, 117, 127, 127), fill=C["head"])
    d.text((2, 118), "^v:Scroll K2:Export", font=font_sm, fill=C["dim"])


def _draw_stp(d):
    d.rectangle((0, 0, 127, 13), fill=C["head"])
    d.text((2, 2), "STP", font=font, fill=C["info"])
    d.text((40, 2), f"BPDU:{bpdu_count[0]}", font=font_sm, fill=C["white"])

    roots = list(stp_roots.values())
    y = 16
    if not roots:
        d.text((10, 40), "Waiting for BPDUs...", font=font_sm, fill=C["dim"])
        d.text((10, 55), "Connect to switch", font=font_sm, fill=C["dim"])
    else:
        if len(roots) > 1:
            d.rectangle((2, y, 125, y + 10), fill=C["card"])
            d.text((4, y + 1), f"!! {len(roots)} ROOT BRIDGES", font=font_sm, fill=C["crit"])
            y += 13
        for r in roots[:3]:
            d.rectangle((2, y, 125, y + 28), fill=C["card"])
            d.text((4, y + 2), "ROOT", font=font_sm, fill=C["ok"])
            d.text((30, y + 2), r["root_mac"][:11], font=font_sm, fill=C["white"])
            d.text((4, y + 11), f"Prio:{r['root_prio']}", font=font_sm, fill=C["dim"])
            d.text((55, y + 11), f"Port:{r['port']}", font=font_sm, fill=C["dim"])
            d.text((4, y + 20), f"Br:{r['bridge_mac'][:11]}", font=font_sm, fill=C["dim"])
            y += 31
            if y > 100:
                break

    d.rectangle((0, 117, 127, 127), fill=C["head"])
    d.text((2, 118), "L/R:View K3:Exit", font=font_sm, fill=C["dim"])


def _draw_arp(d, scroll):
    d.rectangle((0, 0, 127, 13), fill=C["head"])
    d.text((2, 2), "ARP TABLE", font=font, fill=C["info"])

    items = sorted(arp_table.items(), key=lambda x: x[1]["count"], reverse=True)
    now = time.time()
    rate = sum(1 for t in arp_times if t > now - 5) / 5.0
    d.text((75, 2), f"{len(items)}h {rate:.0f}/s", font=font_sm, fill=C["white"])

    vis = (H - 32) // 11
    st = max(0, min(scroll, max(0, len(items) - vis)))
    y = 16
    if not items:
        d.text((10, 50), "No ARP traffic", font=font_sm, fill=C["dim"])
    mx = items[0][1]["count"] if items else 1
    for i in range(st, min(st + vis, len(items))):
        ip, info = items[i]
        d.rectangle((2, y, 125, y + 9), fill=C["card"])
        d.text((4, y + 1), ip, font=font_sm, fill=C["white"])
        d.text((80, y + 1), info["mac"][-8:], font=font_sm, fill=C["dim"])
        bw = min(8, max(1, int(8 * info["count"] / max(1, mx))))
        d.rectangle((118, y + 2, 118 + bw, y + 7), fill=C["info"])
        y += 11

    d.rectangle((0, 117, 127, 127), fill=C["head"])
    d.text((2, 118), "^v:Scroll K2:Export", font=font_sm, fill=C["dim"])


def _export():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report = {
        "timestamp": ts,
        "packets": pkt_count[0],
        "arp_req": arp_req[0], "arp_rep": arp_rep[0],
        "bpdu": bpdu_count[0], "dhcp": dhcp_count[0],
        "alerts": list(alerts),
        "arp_table": {ip: v for ip, v in arp_table.items()},
        "stp_roots": {k: v for k, v in stp_roots.items()},
        "dhcp_servers": {k: v for k, v in dhcp_servers.items()},
    }
    path = os.path.join(LOOT_DIR, f"netdoctor_{ts}.json")
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    _alert("INFO", f"Saved {os.path.basename(path)[:15]}")


def main():
    if not SCAPY_OK:
        img = Image.new("RGB", (W, H), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "scapy not found!", font=font, fill=C["crit"])
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    # Auto-detect interface
    iface = "eth0"
    for candidate in ["eth0", "eth1", "wlan0"]:
        try:
            r = subprocess.run(["ip", "link", "show", candidate],
                               capture_output=True, timeout=3)
            if r.returncode == 0 and b"UP" in r.stdout:
                iface = candidate
                break
        except Exception:
            continue

    t = threading.Thread(target=_sniff_thread, args=(iface,), daemon=True)
    t.start()

    view_idx = 0
    scroll = 0
    last_press = 0.0

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()

            if btn and now - last_press > 0.2:
                last_press = now
                if btn == "KEY3":
                    break
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
                    pkt_count[0] = 0
                    arp_req[0] = 0
                    arp_rep[0] = 0
                    bpdu_count[0] = 0
                    dhcp_count[0] = 0
                    bcast_count[0] = 0
                    arp_times.clear()
                    arp_table.clear()
                    stp_roots.clear()
                    dhcp_servers.clear()
                    alerts.clear()
                elif btn == "KEY2":
                    _export()

            img = Image.new("RGB", (W, H), C["bg"])
            d = ScaledDraw(img)

            v = VIEWS[view_idx]
            if v == "dash":
                _draw_dash(d)
            elif v == "alerts":
                _draw_alerts(d, scroll)
            elif v == "stp":
                _draw_stp(d)
            elif v == "arp":
                _draw_arp(d, scroll)

            LCD.LCD_ShowImage(img, 0, 0)
            time.sleep(0.15)

    finally:
        _stop.set()
        LCD.LCD_Clear()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
