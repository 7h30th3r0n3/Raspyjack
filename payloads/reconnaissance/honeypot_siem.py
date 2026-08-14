#!/usr/bin/env python3
"""
RaspyJack Payload -- Honeypot SIEM
====================================
Multi-service honeypot with real-time SIEM dashboard.
Emulates 13 network services, captures credentials and payloads,
writes live stats for the WebUI dashboard.

Controls:
  OK         Start/Stop services
  UP/DOWN    Scroll events / navigate
  KEY1       Switch view (Services / Events / Stats)
  KEY2       Export log
  KEY3       Exit
"""

import json
import os
import signal
import socket
import struct
import sys
import threading
import time
from collections import Counter
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
DEBOUNCE = 0.18
_last_btn = 0

LIVE_PATH = "/dev/shm/rj_honeypot_live.json"
LOOT_DIR = "/root/Raspyjack/loot/honeypot"
EVENTS_FILE = os.path.join(LOOT_DIR, "events.jsonl")

SERVICES = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
    (80, "HTTP"), (110, "POP3"), (143, "IMAP"), (445, "SMB"),
    (3306, "MySQL"), (3389, "RDP"), (5900, "VNC"),
    (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"),
]

SERVICE_COLORS = {
    "SSH": "#FF4444", "FTP": "#FF8800", "Telnet": "#FFAA00",
    "HTTP": "#00CCFF", "HTTP-Alt": "#00CCFF", "HTTPS-Alt": "#00CCFF",
    "SMTP": "#AA88FF", "MySQL": "#00FF88", "SMB": "#CC44FF",
    "POP3": "#88AAFF", "IMAP": "#88AAFF", "RDP": "#FF6688",
    "VNC": "#44DDAA",
}

_shutdown = threading.Event()
_events = []
_events_lock = threading.Lock()
_port_counts = Counter()
_ip_counts = Counter()
_start_time = 0
_heatmap = [[0] * 24 for _ in range(7)]
_servers = []

BANNERS = {
    21: b"220 ProFTPD 1.3.7c Server (Debian)\r\n",
    22: b"SSH-2.0-OpenSSH_8.5p1 Debian-1\r\n",
    23: b"\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03Ubuntu 20.04.5 LTS\r\nlogin: ",
    25: b"220 mail.example.com ESMTP Exim 4.94.2\r\n",
    80: None,
    110: b"+OK Dovecot ready.\r\n",
    143: b"* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS] Dovecot ready.\r\n",
    445: b"\x00\x00\x00\x45\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x98\x01\x28",
    3306: None,
    3389: b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x01\x08\x00\x02\x00\x00\x00",
    5900: b"RFB 003.008\n",
    8080: None,
    8443: None,
}

HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: Apache/2.4.52 (Ubuntu)\r\n"
    b"Content-Type: text/html\r\n"
    b"Connection: close\r\n\r\n"
    b"<html><head><title>Welcome</title></head>"
    b"<body><h1>It works!</h1></body></html>\r\n"
)

MYSQL_HANDSHAKE = (
    b"\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x33\x33\x00"
    b"\x08\x00\x00\x00\x40\x41\x42\x43\x44\x45\x46\x47\x00"
    b"\xff\xf7\x21\x02\x00\xff\x81\x15\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
    b"\x50\x51\x52\x53\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61"
    b"\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00"
)


def _log_event(ip, port, service, data=""):
    ts = datetime.now().isoformat(timespec="seconds")
    event = {"ts": ts, "ip": ip, "port": port, "service": service, "data": data[:256]}
    with _events_lock:
        _events.append(event)
        _port_counts[port] += 1
        _ip_counts[ip] += 1
        now = datetime.now()
        _heatmap[now.weekday()][now.hour] += 1
    os.makedirs(LOOT_DIR, exist_ok=True)
    try:
        with open(EVENTS_FILE, "a") as f:
            f.write(json.dumps(event) + "\n")
    except Exception:
        pass


def _handle_ftp(conn, addr):
    try:
        conn.settimeout(10)
        conn.sendall(BANNERS[21])
        for _ in range(3):
            data = conn.recv(256)
            if not data:
                break
            line = data.decode("utf-8", errors="replace").strip()
            if line.upper().startswith("USER"):
                user = line[5:].strip()
                conn.sendall(b"331 Password required\r\n")
                data2 = conn.recv(256)
                pw = data2.decode("utf-8", errors="replace").strip()
                if pw.upper().startswith("PASS"):
                    pw = pw[5:].strip()
                _log_event(addr[0], 21, "FTP", f"USER={user} PASS={pw}")
                conn.sendall(b"530 Login incorrect.\r\n")
            else:
                _log_event(addr[0], 21, "FTP", line)
                conn.sendall(b"530 Please login first.\r\n")
    except Exception:
        pass
    finally:
        conn.close()


def _handle_ssh(conn, addr):
    try:
        conn.settimeout(5)
        data = conn.recv(256)
        ident = data.decode("utf-8", errors="replace").strip() if data else ""
        conn.sendall(BANNERS[22])
        _log_event(addr[0], 22, "SSH", ident)
    except Exception:
        pass
    finally:
        conn.close()


def _handle_telnet(conn, addr):
    try:
        conn.settimeout(10)
        conn.sendall(BANNERS[23])
        for _ in range(3):
            data = conn.recv(256)
            if not data:
                break
            user = data.decode("utf-8", errors="replace").strip()
            conn.sendall(b"Password: ")
            data2 = conn.recv(256)
            pw = data2.decode("utf-8", errors="replace").strip() if data2 else ""
            _log_event(addr[0], 23, "Telnet", f"{user}/{pw}")
            conn.sendall(b"\r\nLogin incorrect\r\nlogin: ")
    except Exception:
        pass
    finally:
        conn.close()


def _handle_http(conn, addr, port):
    try:
        conn.settimeout(5)
        data = conn.recv(2048)
        req = data.decode("utf-8", errors="replace") if data else ""
        first_line = req.split("\r\n")[0] if req else ""
        ua = ""
        for line in req.split("\r\n"):
            if line.lower().startswith("user-agent:"):
                ua = line[12:].strip()
                break
        summary = first_line
        if ua:
            summary += f" UA={ua[:60]}"
        svc = "HTTP" if port == 80 else ("HTTP-Alt" if port == 8080 else "HTTPS-Alt")
        _log_event(addr[0], port, svc, summary)
        conn.sendall(HTTP_RESPONSE)
    except Exception:
        pass
    finally:
        conn.close()


def _handle_smtp(conn, addr):
    try:
        conn.settimeout(10)
        conn.sendall(BANNERS[25])
        data = conn.recv(512)
        _log_event(addr[0], 25, "SMTP", data.decode("utf-8", errors="replace").strip() if data else "")
        conn.sendall(b"250 OK\r\n")
    except Exception:
        pass
    finally:
        conn.close()


def _handle_mysql(conn, addr):
    try:
        conn.settimeout(5)
        conn.sendall(MYSQL_HANDSHAKE)
        data = conn.recv(512)
        username = ""
        if data and len(data) > 36:
            try:
                username = data[36:].split(b"\x00")[0].decode("utf-8", errors="replace")
            except Exception:
                pass
        _log_event(addr[0], 3306, "MySQL", f"user={username}" if username else "connect")
        conn.sendall(b"\xff\x15\x04\x23\x32\x38\x30\x30\x30Access denied\x00")
    except Exception:
        pass
    finally:
        conn.close()


def _handle_generic(conn, addr, port, service):
    try:
        conn.settimeout(5)
        banner = BANNERS.get(port)
        if banner:
            conn.sendall(banner)
        data = conn.recv(256)
        payload = data.decode("utf-8", errors="replace").strip() if data else "connect"
        _log_event(addr[0], port, service, payload)
    except Exception:
        _log_event(addr[0], port, service, "connect")
    finally:
        conn.close()


def _connection_handler(conn, addr, port, service):
    if port == 21:
        _handle_ftp(conn, addr)
    elif port == 22:
        _handle_ssh(conn, addr)
    elif port == 23:
        _handle_telnet(conn, addr)
    elif port == 25:
        _handle_smtp(conn, addr)
    elif port in (80, 8080, 8443):
        _handle_http(conn, addr, port)
    elif port == 3306:
        _handle_mysql(conn, addr)
    else:
        _handle_generic(conn, addr, port, service)


def _service_listener(port, service):
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(1.0)
        srv.bind(("0.0.0.0", port))
        srv.listen(5)
        _servers.append(srv)
    except OSError:
        return
    while not _shutdown.is_set():
        try:
            conn, addr = srv.accept()
            threading.Thread(
                target=_connection_handler,
                args=(conn, addr, port, service),
                daemon=True,
            ).start()
        except socket.timeout:
            continue
        except OSError:
            break
    try:
        srv.close()
    except Exception:
        pass


def _write_live_stats():
    while not _shutdown.is_set():
        try:
            with _events_lock:
                total = len(_events)
                unique_ips = len(_ip_counts)
                elapsed = max(1, time.time() - _start_time)
                eph = total / (elapsed / 3600) if elapsed > 0 else 0
                top_ips = [{"ip": ip, "count": c} for ip, c in _ip_counts.most_common(20)]
                port_stats = []
                for port, svc in SERVICES:
                    cnt = _port_counts.get(port, 0)
                    if cnt > 0:
                        port_stats.append({"port": port, "service": svc, "count": cnt})
                port_stats.sort(key=lambda x: -x["count"])
                recent = list(_events[-50:])
                recent.reverse()
                hm = [row[:] for row in _heatmap]
            output = {
                "ts": time.time(),
                "running": True,
                "total_events": total,
                "unique_ips": unique_ips,
                "events_per_hour": round(eph, 1),
                "uptime": int(elapsed),
                "top_ips": top_ips,
                "port_stats": port_stats,
                "recent_events": recent,
                "heatmap": hm,
            }
            tmp = LIVE_PATH + ".tmp"
            with open(tmp, "w") as f:
                json.dump(output, f)
            os.replace(tmp, LIVE_PATH)
        except Exception:
            pass
        _shutdown.wait(2.0)


def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE:
        return None
    if b:
        _last_btn = now
    return b


def main():
    global _start_time

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    font = scaled_font(10)
    font_sm = scaled_font(9)

    auto_mode = "--auto" in sys.argv
    running = False
    scroll = 0
    view = 0
    views = ["services", "events", "stats"]
    status = "Ready"

    def start_honeypot():
        nonlocal running
        global _start_time
        _shutdown.clear()
        _start_time = time.time()
        for port, svc in SERVICES:
            t = threading.Thread(target=_service_listener, args=(port, svc), daemon=True)
            t.start()
        threading.Thread(target=_write_live_stats, daemon=True).start()
        running = True

    if auto_mode:
        start_honeypot()
        status = "Tracking..."

    try:
        while True:
            btn = _btn()
            if btn == "KEY3":
                break
            if btn == "KEY1":
                view = (view + 1) % len(views)
                scroll = 0
            if btn == "UP":
                scroll = max(0, scroll - 1)
            if btn == "DOWN":
                scroll += 1

            if btn == "OK":
                if not running:
                    start_honeypot()
                    status = "Running"
                else:
                    _shutdown.set()
                    running = False
                    status = "Stopped"

            if btn == "KEY2" and _events:
                status = f"Log: {len(_events)} events"

            with _events_lock:
                total = len(_events)
                unique = len(_ip_counts)

            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)
            d.rectangle((0, 0, 127, 14), fill="#111")
            d.text((2, 2), "HONEYPOT SIEM", font=font_sm, fill="#FF4444")
            evt_txt = f"{total}evt" if running else "OFF"
            d.text((90, 2), evt_txt, font=font_sm, fill="#00FF00" if running else "#888")
            if running:
                d.ellipse((125, 4, 127, 6), fill="#00FF00")

            y = 18
            d.text((2, y), status[:24], font=font_sm, fill="#FFAA00")
            y += 12

            if views[view] == "services":
                active_svcs = [(p, s) for p, s in SERVICES]
                for i in range(scroll, min(len(active_svcs), scroll + 6)):
                    if y > 108:
                        break
                    port, svc = active_svcs[i]
                    cnt = _port_counts.get(port, 0)
                    col = SERVICE_COLORS.get(svc, "#888")
                    d.text((2, y), f":{port}", font=font_sm, fill="#555")
                    d.text((30, y), svc[:8], font=font_sm, fill=col)
                    d.text((85, y), str(cnt), font=font_sm, fill="#ccc" if cnt else "#333")
                    y += 10

            elif views[view] == "events":
                with _events_lock:
                    recent = list(_events[-20:])
                    recent.reverse()
                for i in range(scroll, min(len(recent), scroll + 6)):
                    if y > 108:
                        break
                    ev = recent[i]
                    ts_short = ev["ts"][11:19]
                    col = SERVICE_COLORS.get(ev["service"], "#888")
                    d.text((2, y), ts_short, font=font_sm, fill="#555")
                    d.text((50, y), ev["ip"][:12], font=font_sm, fill=col)
                    d.text((2, y + 9), f"{ev['service']} {ev['data'][:18]}", font=font_sm, fill="#666")
                    y += 20

            elif views[view] == "stats":
                d.text((2, y), f"Events: {total}  IPs: {unique}", font=font_sm, fill="#ccc")
                y += 12
                elapsed = time.time() - _start_time if running else 0
                d.text((2, y), f"Uptime: {int(elapsed)}s", font=font_sm, fill="#888")
                y += 12
                with _events_lock:
                    top = _ip_counts.most_common(5)
                for ip, cnt in top:
                    if y > 108:
                        break
                    d.text((2, y), f"{ip[:15]}", font=font_sm, fill="#FF4444")
                    d.text((95, y), str(cnt), font=font_sm, fill="#ccc")
                    y += 10

            d.rectangle((0, 116, 127, 127), fill="#111")
            vname = views[view][:5].upper()
            d.text((2, 117), f"OK:{'Stop' if running else 'Start'} K1:{vname}", font=font_sm, fill="#666")
            lcd.LCD_ShowImage(img, 0, 0)
            time.sleep(0.05)

    finally:
        _shutdown.set()
        for srv in _servers:
            try:
                srv.close()
            except Exception:
                pass
        try:
            os.remove(LIVE_PATH)
        except OSError:
            pass
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
