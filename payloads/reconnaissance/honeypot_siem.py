#!/usr/bin/env python3
"""
RaspyJack Payload -- Honeypot SIEM Pro
========================================
Professional-grade multi-service honeypot with interactive shells,
threat intelligence, GeoIP enrichment, and SIEM dashboard.

18 emulated services with deep interaction (SSH/Telnet fake shells,
HTTP with login pages, FTP post-auth commands, SMTP relay capture,
Redis/Elasticsearch/Docker API emulation).

Controls:
  OK         Start/Stop services
  UP/DOWN    Scroll / navigate
  KEY1       Switch view (Dashboard / Services / Events / Stats)
  KEY2       Export log
  KEY3       Exit
"""

import json
import os
import re
import signal
import socket
import struct
import sys
import threading
import time
import urllib.request
from collections import Counter, defaultdict
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
CAPTURES_DIR = os.path.join(LOOT_DIR, "captures")
WEBHOOK_PATH = "/root/Raspyjack/discord_webhook.txt"

SERVICES = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
    (80, "HTTP"), (110, "POP3"), (143, "IMAP"), (445, "SMB"),
    (3306, "MySQL"), (3389, "RDP"), (5900, "VNC"),
    (6379, "Redis"), (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"),
    (9200, "Elastic"), (2375, "Docker"), (27017, "MongoDB"),
]

SERVICE_COLORS = {
    "SSH": "#FF4444", "FTP": "#FF8800", "Telnet": "#FFAA00",
    "HTTP": "#00CCFF", "HTTP-Alt": "#00CCFF", "HTTPS-Alt": "#00CCFF",
    "SMTP": "#AA88FF", "MySQL": "#00FF88", "SMB": "#CC44FF",
    "POP3": "#88AAFF", "IMAP": "#88AAFF", "RDP": "#FF6688",
    "VNC": "#44DDAA", "Redis": "#FF6666", "Elastic": "#FFCC00",
    "Docker": "#2496ED", "MongoDB": "#00AA44",
}

_shutdown = threading.Event()
_events = []
_events_lock = threading.Lock()
_port_counts = Counter()
_ip_counts = Counter()
_ip_last_seen = {}
_attack_types = Counter()
_exploit_attempts = []
_credentials = []
_active_sessions = 0
_session_lock = threading.Lock()
_start_time = 0
_heatmap = [[0] * 24 for _ in range(7)]
_servers = []
_alerted_ips = set()
_last_webhook = 0

# ── Exploit patterns ──────────────────────────────────────────────────
EXPLOIT_PATTERNS = [
    # RCE / Injection
    (r"\$\{jndi:", "Log4Shell", "T1190"),
    (r"\(\)\s*\{", "Shellshock", "T1190"),
    (r";\s*(ls|cat|id|wget|curl|nc|bash|sh|python|perl|rm|chmod|chown|kill|nohup|tftp|ftpget)\b", "Command Injection", "T1059"),
    (r"\|[\s+]*(ls|cat|id|bash|sh|nc|wget|curl|python|whoami|uname)", "Pipe Injection", "T1059"),
    (r"`[^`]*`", "Backtick Injection", "T1059"),
    (r"\$\([^)]+\)", "Subshell Injection", "T1059"),
    # SQLi
    (r"(union[\s+]+(all[\s+]+)?select|select[\s+]+.*from[\s+])", "SQL Injection", "T1190"),
    (r"('[\s+]*(or|and)[\s+']+|'\s*=\s*'|1[\s+]*=[\s+]*1|1'[\s+]*or)", "SQL Injection", "T1190"),
    (r"(;[\s+]*(drop|delete|insert|update|alter)[\s+])", "SQL Injection", "T1190"),
    (r"(sleep[\s+]*\([\s+]*\d|benchmark[\s+]*\(|waitfor[\s+]+delay)", "Blind SQLi", "T1190"),
    (r"(load_file|into[\s+]+outfile|into[\s+]+dumpfile)", "SQL File Access", "T1190"),
    # XSS
    (r"<script[\s>]", "XSS", "T1189"),
    (r"javascript\s*:", "XSS", "T1189"),
    (r"(onerror|onload|onmouseover|onfocus|onblur)\s*=", "XSS", "T1189"),
    (r"<img\s[^>]*src\s*=\s*['\"]?(javascript|data):", "XSS", "T1189"),
    (r"<(iframe|embed|object|svg|math|marquee)\b", "XSS", "T1189"),
    (r"(alert|confirm|prompt)\s*\(", "XSS", "T1189"),
    # LFI / RFI / Path Traversal
    (r"\.\./\.\./", "Directory Traversal", "T1083"),
    (r"(etc/passwd|etc/shadow|proc/self|proc/version|proc/cmdline)", "File Read", "T1005"),
    (r"(php://filter|php://input|expect://|data://)", "PHP Stream Wrapper", "T1190"),
    (r"(\.php\?.*=\s*https?://|\.php\?.*=\s*ftp://)", "Remote File Inclusion", "T1190"),
    # SSRF
    (r"(127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.\d+\.\d+|metadata\.google|metadata\.aws)", "SSRF", "T1190"),
    (r"(file:///|gopher://|dict://)", "SSRF Protocol", "T1190"),
    # Deserialization
    (r"(rO0AB|aced0005|O:[\d]+:\")", "Deserialization", "T1190"),
    (r"(__import__|pickle\.loads|yaml\.load)", "Python Deser", "T1190"),
    # Botnet / IoT
    (r"(busybox|/bin/busybox|mirai|mozi|gafgyt|hajime)", "IoT Botnet", "T1059"),
    (r"(/tmp/[\w.]+;|/var/tmp/[\w.]+;|/dev/null\s*2)", "Botnet Dropper", "T1059"),
    (r"(cd\s+/tmp\s*[;&]|cd\s+/var/run\s*[;&])", "Botnet Stage", "T1059"),
    # Web frameworks
    (r"(wp-login|wp-admin|xmlrpc\.php|wp-content|wp-includes)", "WordPress Probe", "T1595"),
    (r"(phpmyadmin|pma|myadmin|phpinfo)", "phpMyAdmin Probe", "T1595"),
    (r"(\.env|config\.php|config\.yml|\.git/|\.svn/|\.htaccess|\.htpasswd|web\.config)", "Config Leak", "T1552"),
    (r"(grafana|jenkins|portainer|kibana|prometheus|zabbix|nagios|cacti)", "Admin Panel Probe", "T1595"),
    (r"(actuator|debug|console|swagger|graphql|api-docs|\.well-known)", "API Discovery", "T1595"),
    # Scanner signatures
    (r"(nmap|nikto|dirbuster|gobuster|sqlmap|wpscan|nuclei|masscan|zmap)", "Scanner Detected", "T1595"),
    (r"(zgrab|censys|shodan|python-requests/|libwww-perl|Java/\d)", "Bot/Scanner UA", "T1595"),
    # Auth bypass
    (r"(admin'--|admin'\s*or|' or ''='|' or 1=1)", "Auth Bypass", "T1190"),
    # XXE
    (r"(<!ENTITY|<!DOCTYPE.*\[.*<!ENTITY)", "XXE", "T1190"),
    # SSTI
    (r"(\{\{.*\}\}|\$\{.*\}|<%.*%>|#\{.*\})", "SSTI", "T1190"),
]

# ── GeoIP (top country ranges, very approximate) ──────────────────────
_GEOIP = [
    ("1.0.0.0", "1.0.0.255", "AU"), ("1.1.1.0", "1.1.1.255", "AU"),
    ("2.16.0.0", "2.23.255.255", "EU"), ("5.0.0.0", "5.63.255.255", "RU"),
    ("14.0.0.0", "14.127.255.255", "CN"), ("23.0.0.0", "23.79.255.255", "US"),
    ("31.0.0.0", "31.47.255.255", "DE"), ("34.0.0.0", "34.127.255.255", "US"),
    ("36.0.0.0", "36.255.255.255", "CN"), ("41.0.0.0", "41.255.255.255", "ZA"),
    ("42.0.0.0", "42.127.255.255", "CN"), ("45.0.0.0", "45.127.255.255", "US"),
    ("46.0.0.0", "46.63.255.255", "RU"), ("49.0.0.0", "49.255.255.255", "KR"),
    ("51.0.0.0", "51.255.255.255", "GB"), ("52.0.0.0", "52.127.255.255", "US"),
    ("58.0.0.0", "58.255.255.255", "CN"), ("59.0.0.0", "59.255.255.255", "KR"),
    ("61.0.0.0", "61.127.255.255", "CN"), ("65.0.0.0", "65.127.255.255", "US"),
    ("77.0.0.0", "77.127.255.255", "DE"), ("78.0.0.0", "78.127.255.255", "FR"),
    ("80.0.0.0", "80.127.255.255", "GB"), ("82.0.0.0", "82.63.255.255", "NL"),
    ("85.0.0.0", "85.127.255.255", "DE"), ("87.0.0.0", "87.63.255.255", "FR"),
    ("89.0.0.0", "89.127.255.255", "RU"), ("91.0.0.0", "91.127.255.255", "UA"),
    ("92.0.0.0", "92.127.255.255", "FR"), ("93.0.0.0", "93.127.255.255", "DE"),
    ("95.0.0.0", "95.127.255.255", "RU"), ("101.0.0.0", "101.127.255.255", "CN"),
    ("103.0.0.0", "103.255.255.255", "IN"), ("104.0.0.0", "104.255.255.255", "US"),
    ("106.0.0.0", "106.127.255.255", "CN"), ("110.0.0.0", "110.255.255.255", "CN"),
    ("112.0.0.0", "112.255.255.255", "CN"), ("113.0.0.0", "113.255.255.255", "CN"),
    ("115.0.0.0", "115.255.255.255", "CN"), ("116.0.0.0", "116.255.255.255", "CN"),
    ("117.0.0.0", "117.255.255.255", "CN"), ("118.0.0.0", "118.255.255.255", "CN"),
    ("119.0.0.0", "119.255.255.255", "CN"), ("120.0.0.0", "120.255.255.255", "CN"),
    ("121.0.0.0", "121.255.255.255", "KR"), ("122.0.0.0", "122.255.255.255", "CN"),
    ("123.0.0.0", "123.255.255.255", "CN"), ("124.0.0.0", "124.255.255.255", "CN"),
    ("125.0.0.0", "125.255.255.255", "KR"), ("128.0.0.0", "128.127.255.255", "US"),
    ("141.0.0.0", "141.127.255.255", "DE"), ("142.0.0.0", "142.127.255.255", "US"),
    ("150.0.0.0", "150.127.255.255", "JP"), ("152.0.0.0", "152.127.255.255", "US"),
    ("154.0.0.0", "154.127.255.255", "ZA"), ("156.0.0.0", "156.127.255.255", "CA"),
    ("157.0.0.0", "157.127.255.255", "US"), ("159.0.0.0", "159.127.255.255", "DE"),
    ("160.0.0.0", "160.127.255.255", "DE"), ("162.0.0.0", "162.127.255.255", "US"),
    ("163.0.0.0", "163.127.255.255", "CN"), ("164.0.0.0", "164.127.255.255", "US"),
    ("166.0.0.0", "166.127.255.255", "US"), ("170.0.0.0", "170.127.255.255", "BR"),
    ("172.64.0.0", "172.71.255.255", "US"), ("175.0.0.0", "175.255.255.255", "CN"),
    ("176.0.0.0", "176.127.255.255", "RU"), ("177.0.0.0", "177.255.255.255", "BR"),
    ("178.0.0.0", "178.127.255.255", "RU"), ("180.0.0.0", "180.255.255.255", "CN"),
    ("182.0.0.0", "182.255.255.255", "CN"), ("183.0.0.0", "183.255.255.255", "CN"),
    ("185.0.0.0", "185.255.255.255", "EU"), ("186.0.0.0", "186.255.255.255", "BR"),
    ("187.0.0.0", "187.255.255.255", "BR"), ("188.0.0.0", "188.127.255.255", "RU"),
    ("190.0.0.0", "190.255.255.255", "AR"), ("191.0.0.0", "191.255.255.255", "BR"),
    ("192.0.0.0", "192.127.255.255", "US"), ("193.0.0.0", "193.127.255.255", "EU"),
    ("194.0.0.0", "194.127.255.255", "EU"), ("195.0.0.0", "195.127.255.255", "EU"),
    ("196.0.0.0", "196.255.255.255", "ZA"), ("197.0.0.0", "197.255.255.255", "NG"),
    ("198.0.0.0", "198.127.255.255", "US"), ("199.0.0.0", "199.255.255.255", "US"),
    ("200.0.0.0", "200.255.255.255", "BR"), ("201.0.0.0", "201.255.255.255", "MX"),
    ("202.0.0.0", "202.255.255.255", "JP"), ("203.0.0.0", "203.255.255.255", "AU"),
    ("204.0.0.0", "204.255.255.255", "US"), ("205.0.0.0", "205.255.255.255", "US"),
    ("206.0.0.0", "206.255.255.255", "US"), ("207.0.0.0", "207.255.255.255", "CA"),
    ("208.0.0.0", "208.255.255.255", "US"), ("209.0.0.0", "209.255.255.255", "US"),
    ("210.0.0.0", "210.255.255.255", "JP"), ("211.0.0.0", "211.255.255.255", "KR"),
    ("212.0.0.0", "212.127.255.255", "DE"), ("213.0.0.0", "213.127.255.255", "ES"),
    ("216.0.0.0", "216.255.255.255", "US"), ("218.0.0.0", "218.255.255.255", "CN"),
    ("219.0.0.0", "219.255.255.255", "KR"), ("220.0.0.0", "220.255.255.255", "CN"),
    ("221.0.0.0", "221.255.255.255", "CN"), ("222.0.0.0", "222.255.255.255", "CN"),
    ("223.0.0.0", "223.255.255.255", "CN"),
]
_geoip_cache = {}


def _ip_to_int(ip):
    try:
        parts = ip.split(".")
        return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])
    except Exception:
        return 0


def _lookup_country(ip):
    if ip in _geoip_cache:
        return _geoip_cache[ip]
    if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
        _geoip_cache[ip] = "LAN"
        return "LAN"
    ip_int = _ip_to_int(ip)
    for lo, hi, cc in _GEOIP:
        if _ip_to_int(lo) <= ip_int <= _ip_to_int(hi):
            _geoip_cache[ip] = cc
            return cc
    _geoip_cache[ip] = "??"
    return "??"


def _classify_attack(port, data):
    if not data:
        return "scan", "low"
    dl = data.lower()
    for pat, name, mitre in EXPLOIT_PATTERNS:
        if re.search(pat, data, re.IGNORECASE):
            return f"exploit:{name}", "critical"
    if any(w in dl for w in ("user", "pass", "login", "root", "admin")):
        return "brute-force", "high"
    if port in (80, 8080, 8443) and ("get" in dl or "post" in dl):
        return "recon", "medium"
    return "scan", "low"


def _send_webhook(event):
    global _last_webhook
    now = time.time()
    if now - _last_webhook < 60:
        return
    try:
        url = ""
        if os.path.isfile(WEBHOOK_PATH):
            with open(WEBHOOK_PATH) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and line.startswith("https://"):
                        url = line
                        break
        if not url:
            return
        embed = {
            "embeds": [{
                "title": f"Honeypot Alert: {event['service']}",
                "color": 0xFF4444,
                "fields": [
                    {"name": "IP", "value": f"`{event['ip']}`", "inline": True},
                    {"name": "Port", "value": str(event["port"]), "inline": True},
                    {"name": "Country", "value": event.get("country", "??"), "inline": True},
                    {"name": "Data", "value": f"```{event['data'][:200]}```"},
                ],
                "footer": {"text": f"RaspyJack Honeypot | {event['ts']}"},
            }]
        }
        req = urllib.request.Request(url, data=json.dumps(embed).encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
        _last_webhook = now
    except Exception:
        pass


def _extract_creds(service, data):
    """Extract username:password from event data based on service type."""
    if not data:
        return "", ""
    # FTP: "USER=admin PASS=password123"
    um = re.search(r'USER[=:\s]+(\S+)', data, re.IGNORECASE)
    pm = re.search(r'PASS[=:\s]+(\S+)', data, re.IGNORECASE)
    if um and pm:
        return um.group(1), pm.group(1)
    # HTTP POST: "username=admin&password=secret" or "log=admin&pwd=secret"
    for ukey in ('username', 'user', 'log', 'login', 'email', 'j_username', 'pma_username'):
        um2 = re.search(ukey + r'=([^&\s]+)', data, re.IGNORECASE)
        if um2:
            for pkey in ('password', 'pass', 'pwd', 'passwd', 'j_password', 'pma_password'):
                pm2 = re.search(pkey + r'=([^&\s]+)', data, re.IGNORECASE)
                if pm2:
                    return um2.group(1), pm2.group(1)
            return um2.group(1), ""
    # POST_CREDS: "POST_CREDS: username=x&password=y"
    if "POST_CREDS:" in data:
        body = data.split("POST_CREDS:", 1)[1].strip()
        return _extract_creds(service, body)
    # Telnet/SSH: "login: admin/password" or "admin/password"
    if "login:" in data.lower():
        after = data.split("login:", 1)[1].strip() if "login:" in data else data
        after = after.split(":", 1)[1].strip() if ":" in after and "login" in data.lower() else after
    else:
        after = data
    # "user/pass" format (Telnet)
    if "/" in after and len(after.split("/")) == 2 and len(after) < 80:
        parts = after.split("/")
        u, p = parts[0].strip(), parts[1].strip()
        if u and p and " " not in u and " " not in p:
            return u, p
    # SSH: "pass1: xxx" or "pass2: yyy (accepted)"
    pm3 = re.search(r'pass\d?:\s*(\S+)', data, re.IGNORECASE)
    if pm3:
        return "", pm3.group(1).rstrip(")")
    # MySQL: "user=root db=test"
    um4 = re.search(r'user=(\S+)', data, re.IGNORECASE)
    if um4:
        return um4.group(1), ""
    # Redis: "AUTH password123"
    am = re.search(r'AUTH\s+(\S+)', data, re.IGNORECASE)
    if am:
        return "", am.group(1)
    # CMD with credentials
    cm = re.search(r'cmd:\s*(su|sudo|login|passwd)\s+(\S+)', data, re.IGNORECASE)
    if cm:
        return cm.group(2), ""
    return "", ""


def _log_event(ip, port, service, data=""):
    ts = datetime.now().isoformat(timespec="seconds")
    country = _lookup_country(ip)
    attack_type, severity = _classify_attack(port, data)
    event = {
        "ts": ts, "ip": ip, "port": port, "service": service,
        "data": data[:512], "country": country,
        "attack_type": attack_type, "severity": severity,
    }
    is_new_ip = False
    with _events_lock:
        _events.append(event)
        if len(_events) > 5000:
            _events[:] = _events[-4000:]
        _port_counts[port] += 1
        if ip not in _ip_counts:
            is_new_ip = True
        _ip_counts[ip] += 1
        _ip_last_seen[ip] = ts
        _attack_types[attack_type] += 1
        now = datetime.now()
        _heatmap[now.weekday()][now.hour] += 1
        if "exploit:" in attack_type:
            _exploit_attempts.append(event)
            if len(_exploit_attempts) > 100:
                _exploit_attempts[:] = _exploit_attempts[-80:]
        has_creds = attack_type == "brute-force" or "CREDS=" in data or any(
            k in data.lower() for k in ("username=", "password=", "user=", "pass=", "pwd=", "log=", "j_username=", "pma_username="))
        if has_creds and data:
            username, password = _extract_creds(service, data)
            if username or password:
                cred = {"ts": ts, "ip": ip, "service": service, "port": port,
                        "country": country, "username": username, "password": password, "raw": data[:256]}
                _credentials.append(cred)
                if len(_credentials) > 200:
                    _credentials[:] = _credentials[-150:]
    os.makedirs(LOOT_DIR, exist_ok=True)
    try:
        with open(EVENTS_FILE, "a") as f:
            f.write(json.dumps(event) + "\n")
    except Exception:
        pass
    if is_new_ip and ip not in _alerted_ips:
        _alerted_ips.add(ip)
        threading.Thread(target=_send_webhook, args=(event,), daemon=True).start()


# ── Fake Shell ────────────────────────────────────────────────────────
FAKE_FS = {
    "ls": "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var\n",
    "ls -la": "total 68\ndrwxr-xr-x  18 root root 4096 Jan 15 08:30 .\ndrwxr-xr-x  18 root root 4096 Jan 15 08:30 ..\ndrwxr-xr-x   2 root root 4096 Dec 12 10:00 bin\ndrwxr-xr-x   3 root root 4096 Dec 12 10:00 boot\ndrwxr-xr-x   5 root root  360 Jan 15 08:30 dev\ndrwxr-xr-x  75 root root 4096 Jan 15 08:30 etc\ndrwxr-xr-x   3 root root 4096 Dec 12 10:00 home\n",
    "whoami": "root\n",
    "id": "uid=0(root) gid=0(root) groups=0(root)\n",
    "uname -a": "Linux server 5.10.0-20-amd64 #1 SMP Debian 5.10.158-2 x86_64 GNU/Linux\n",
    "pwd": "/root\n",
    "hostname": "server\n",
    "uptime": " 08:30:15 up 142 days, 3:22, 1 user, load average: 0.08, 0.03, 0.01\n",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\nmysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false\n",
    "cat /etc/shadow": "root:$6$rounds=656000$abc$xyz:19000:0:99999:7:::\nadmin:$6$rounds=656000$def$uvw:19000:0:99999:7:::\n",
    "ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n        ether 08:00:27:8b:c9:3f  txqueuelen 1000\n        RX bytes:1234567 TX bytes:7654321\n",
    "ip addr": "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0\n",
    "ps aux": "USER  PID  %CPU %MEM  COMMAND\nroot    1  0.0  0.1  /sbin/init\nroot   42  0.0  0.0  [kworker/0:1]\nroot  215  0.0  0.2  /usr/sbin/sshd -D\nroot  310  0.0  0.1  /usr/sbin/cron -f\nwww   420  0.2  1.5  /usr/sbin/apache2 -k start\nmysql 510  0.5  5.2  /usr/sbin/mysqld\n",
    "cat /etc/os-release": 'PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"\nNAME="Debian GNU/Linux"\nVERSION_ID="11"\nVERSION="11 (bullseye)"\nID=debian\n',
    "df -h": "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   12G   36G  25% /\ntmpfs           2.0G     0  2.0G   0% /dev/shm\n",
    "free -m": "              total  used  free  shared  buff/cache  available\nMem:           3944  1205   412     128        2326       2345\nSwap:          2048    56  1992\n",
    "w": " 08:30:15 up 142 days, 1 user, load average: 0.08, 0.03, 0.01\nUSER   TTY   FROM       LOGIN@  IDLE  WHAT\nroot   pts/0 10.0.2.2   08:29   0:00  -bash\n",
    "env": "SHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nHOME=/root\nLOGNAME=root\nLANG=en_US.UTF-8\n",
    "netstat -tlnp": "Proto Recv-Q Send-Q Local Address  Foreign Address  State   PID/Program\ntcp        0      0 0.0.0.0:22     0.0.0.0:*        LISTEN  215/sshd\ntcp        0      0 0.0.0.0:80     0.0.0.0:*        LISTEN  420/apache2\ntcp        0      0 0.0.0.0:3306   0.0.0.0:*        LISTEN  510/mysqld\n",
}


def _recv_line(conn, echo=False, timeout=120):
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            ch = conn.recv(1)
        except socket.timeout:
            continue
        if not ch:
            return None
        if ch[0] == 0xFF:
            conn.recv(2)
            continue
        if ch in (b"\r", b"\n"):
            if echo:
                conn.sendall(b"\r\n")
            return buf.decode("utf-8", errors="replace").strip()
        if ch == b"\x7f" or ch == b"\x08":
            if buf:
                buf = buf[:-1]
                if echo:
                    conn.sendall(b"\x08 \x08")
            continue
        buf += ch
        if echo:
            conn.sendall(ch)
        if len(buf) > 256:
            return buf.decode("utf-8", errors="replace").strip()
    return buf.decode("utf-8", errors="replace").strip() if buf else None


def _fake_shell(conn, addr, service, port):
    global _active_sessions
    with _session_lock:
        _active_sessions += 1
    try:
        conn.settimeout(2)
        prompt = b"root@server:~# "
        conn.sendall(prompt)
        deadline = time.time() + 120
        while time.time() < deadline and not _shutdown.is_set():
            cmd = _recv_line(conn, echo=(service == "Telnet"), timeout=min(30, deadline - time.time()))
            if cmd is None:
                break
            if not cmd:
                conn.sendall(prompt)
                continue
            _log_event(addr[0], port, service, f"cmd: {cmd}")
            if cmd in ("exit", "quit", "logout"):
                conn.sendall(b"logout\n")
                break
            if cmd.startswith("wget ") or cmd.startswith("curl "):
                url = cmd.split(None, 1)[1] if " " in cmd else ""
                _log_event(addr[0], port, service, f"download: {url}")
                os.makedirs(CAPTURES_DIR, exist_ok=True)
                try:
                    with open(os.path.join(CAPTURES_DIR, "urls.txt"), "a") as f:
                        f.write(f"{datetime.now().isoformat()} {addr[0]} {url}\n")
                except Exception:
                    pass
                conn.sendall(f"--2024-01-15 08:30:15--  {url}\nResolving... connecting... connected.\nHTTP request sent, awaiting response... 200 OK\nSaved\n".encode())
            elif cmd == "cd" or cmd.startswith("cd "):
                pass
            elif cmd in FAKE_FS:
                conn.sendall(FAKE_FS[cmd].encode())
            elif cmd.startswith("cat ") and cmd in FAKE_FS:
                conn.sendall(FAKE_FS[cmd].encode())
            elif cmd.startswith("echo "):
                conn.sendall((cmd[5:] + "\n").encode())
            else:
                for k, v in FAKE_FS.items():
                    if cmd == k:
                        conn.sendall(v.encode())
                        break
                else:
                    conn.sendall(f"bash: {cmd.split()[0]}: command not found\n".encode())
            conn.sendall(prompt)
    except Exception:
        pass
    finally:
        with _session_lock:
            _active_sessions -= 1
        conn.close()


# ── Service handlers ──────────────────────────────────────────────────

def _handle_ssh(conn, addr):
    try:
        conn.settimeout(10)
        data = conn.recv(256)
        ident = data.decode("utf-8", errors="replace").strip() if data else ""
        conn.sendall(b"SSH-2.0-OpenSSH_8.5p1 Debian-1\r\n")
        _log_event(addr[0], 22, "SSH", f"ident: {ident}")
        conn.sendall(b"\r\nPassword: ")
        pw1 = conn.recv(128)
        _log_event(addr[0], 22, "SSH", f"pass1: {pw1.decode('utf-8', errors='replace').strip()}" if pw1 else "")
        conn.sendall(b"\r\nPermission denied, please try again.\r\nPassword: ")
        pw2 = conn.recv(128)
        pw2_str = pw2.decode("utf-8", errors="replace").strip() if pw2 else ""
        _log_event(addr[0], 22, "SSH", f"pass2: {pw2_str} (accepted)")
        conn.sendall(b"\r\nWelcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.10.0-20-amd64 x86_64)\r\n\r\n")
        _fake_shell(conn, addr, "SSH", 22)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _handle_telnet(conn, addr):
    try:
        conn.settimeout(2)
        conn.sendall(b"\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03Ubuntu 20.04.5 LTS\r\nlogin: ")
        for attempt in range(3):
            user = _recv_line(conn, echo=True, timeout=15)
            if user is None:
                return
            conn.sendall(b"Password: ")
            pw = _recv_line(conn, echo=False, timeout=15) or ""
            _log_event(addr[0], 23, "Telnet", f"login: {user}/{pw}")
            if attempt >= 1:
                conn.sendall(b"\r\nLast login: Mon Jan 15 08:29:00 2024 from 10.0.2.2\r\n")
                _fake_shell(conn, addr, "Telnet", 23)
                return
            conn.sendall(b"\r\nLogin incorrect\r\nlogin: ")
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _handle_ftp(conn, addr):
    try:
        conn.settimeout(15)
        conn.sendall(b"220 ProFTPD 1.3.7c Server (Debian)\r\n")
        user = ""
        logged_in = False
        for _ in range(10):
            data = conn.recv(512)
            if not data:
                break
            line = data.decode("utf-8", errors="replace").strip()
            cmd = line.split()[0].upper() if line else ""
            if cmd == "USER":
                user = line[5:].strip()
                conn.sendall(b"331 Password required\r\n")
            elif cmd == "PASS":
                pw = line[5:].strip()
                _log_event(addr[0], 21, "FTP", f"USER={user} PASS={pw}")
                conn.sendall(b"230 Login successful.\r\n")
                logged_in = True
            elif cmd == "PWD":
                conn.sendall(b'257 "/" is the current directory\r\n')
                _log_event(addr[0], 21, "FTP", "PWD")
            elif cmd == "LIST" or cmd == "NLST":
                conn.sendall(b"150 Opening data connection\r\n")
                conn.sendall(b"226 Transfer complete\r\n")
                _log_event(addr[0], 21, "FTP", cmd)
            elif cmd == "CWD":
                conn.sendall(b"250 Directory changed\r\n")
                _log_event(addr[0], 21, "FTP", line)
            elif cmd == "RETR":
                _log_event(addr[0], 21, "FTP", f"download: {line}")
                conn.sendall(b"550 File not found\r\n")
            elif cmd == "QUIT":
                conn.sendall(b"221 Goodbye.\r\n")
                break
            else:
                _log_event(addr[0], 21, "FTP", line)
                conn.sendall(b"500 Unknown command\r\n")
    except Exception:
        pass
    finally:
        conn.close()


def _handle_smtp(conn, addr):
    try:
        conn.settimeout(15)
        conn.sendall(b"220 mail.example.com ESMTP Exim 4.94.2\r\n")
        mail_from = mail_to = body = ""
        in_data = False
        for _ in range(20):
            data = conn.recv(2048)
            if not data:
                break
            line = data.decode("utf-8", errors="replace").strip()
            if in_data:
                if line == ".":
                    in_data = False
                    _log_event(addr[0], 25, "SMTP", f"FROM={mail_from} TO={mail_to} BODY={body[:200]}")
                    conn.sendall(b"250 OK id=1234\r\n")
                else:
                    body += line + "\n"
                continue
            cmd = line.split()[0].upper() if line else ""
            if cmd in ("EHLO", "HELO"):
                conn.sendall(b"250-mail.example.com\r\n250-SIZE 10240000\r\n250-AUTH LOGIN PLAIN\r\n250 OK\r\n")
            elif line.upper().startswith("MAIL FROM"):
                mail_from = line.split(":", 1)[1].strip() if ":" in line else line
                conn.sendall(b"250 OK\r\n")
            elif line.upper().startswith("RCPT TO"):
                mail_to = line.split(":", 1)[1].strip() if ":" in line else line
                conn.sendall(b"250 OK\r\n")
            elif cmd == "DATA":
                conn.sendall(b"354 Enter message\r\n")
                in_data = True
            elif cmd == "QUIT":
                conn.sendall(b"221 Bye\r\n")
                break
            else:
                _log_event(addr[0], 25, "SMTP", line)
                conn.sendall(b"250 OK\r\n")
    except Exception:
        pass
    finally:
        conn.close()


# ── HTTP pages ────────────────────────────────────────────────────────
_HTTP_HDRS = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\nX-Powered-By: PHP/8.1.2\r\nSet-Cookie: PHPSESSID=abc123def456; path=/\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n"
_HTTP_LOGIN_FAIL = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\nX-Powered-By: PHP/8.1.2\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n"
_HTTP_PAGES = {
    "/": b"<html><head><title>Welcome</title></head><body><h1>Welcome to Ubuntu Server</h1><p>It works!</p></body></html>",
    "/admin": b'<!DOCTYPE html><html><head><title>Administration Panel</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial,sans-serif;background:#1a1a2e;display:flex;justify-content:center;align-items:center;height:100vh}.login{background:#16213e;padding:40px;border-radius:8px;box-shadow:0 8px 32px rgba(0,0,0,.5);width:360px}.login h2{color:#e94560;text-align:center;margin-bottom:24px;font-size:20px}.login input{width:100%;padding:12px;margin:8px 0;border:1px solid #0f3460;border-radius:4px;background:#1a1a2e;color:#fff;font-size:14px}.login button{width:100%;padding:12px;margin-top:16px;background:#e94560;color:#fff;border:none;border-radius:4px;font-size:16px;cursor:pointer}.login button:hover{background:#c81e45}.err{color:#e94560;text-align:center;font-size:12px;margin-top:8px}.ver{color:#555;text-align:center;font-size:10px;margin-top:16px}</style></head><body><div class="login"><h2>Admin Panel</h2><form method="POST"><input name="username" placeholder="Username" required><input name="password" type="password" placeholder="Password" required><button type="submit">Sign In</button></form><p class="ver">v3.2.1 &bull; Apache/2.4.52</p></div></body></html>',
    "/wp-admin": b'<!DOCTYPE html><html><head><title>Log In &lsaquo; WordPress</title><style>*{margin:0;padding:0;box-sizing:border-box}body{background:#f0f0f1;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;display:flex;flex-direction:column;align-items:center;padding-top:8%}#login{width:320px;background:#fff;padding:26px 24px;border:1px solid #c3c4c7;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.04)}h1{text-align:center;margin-bottom:24px}h1 a{font-size:0;display:block;width:84px;height:84px;margin:0 auto;background:url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCI+PHBhdGggZD0iTTMyIDRDMTYuNTM2IDQgNCA2LjUzNiA0IDIyYzAgMTEuOTkgNy43NDggMjIuMTQgMTguNTEgMjUuNzlMMjAgNjBoMjRsLTIuNTEtMTIuMjFDNTIuMjUyIDQ0LjE0IDYwIDMzLjk5IDYwIDIyIDYwIDYuNTM2IDQ3LjQ2NCA0IDMyIDR6IiBmaWxsPSIjMDA3MzlFIi8+PC9zdmc+) no-repeat center/contain}input{width:100%;padding:8px 10px;margin:4px 0 16px;border:1px solid #8c8f94;border-radius:4px;font-size:14px;box-shadow:inset 0 1px 2px rgba(0,0,0,.07)}label{font-size:14px;color:#1d2327;font-weight:600}.submit{margin-top:8px}input[type=submit]{background:#2271b1;color:#fff;border:none;padding:8px 16px;font-size:13px;border-radius:3px;cursor:pointer;width:auto}input[type=submit]:hover{background:#135e96}.forgetmenot{float:left;margin:8px 0}p.err{color:#d63638;padding:8px 12px;background:#fcf0f1;border-left:4px solid #d63638;margin-bottom:16px;font-size:13px}#backtoblog{text-align:center;margin-top:16px}#backtoblog a{color:#50575e;font-size:13px;text-decoration:none}</style></head><body><div id="login"><h1><a href="/">WordPress</a></h1><form method="POST" action="/wp-login.php"><label>Username or Email Address<input name="log" type="text" required></label><label>Password<input name="pwd" type="password" required></label><div class="submit"><input type="submit" value="Log In"></div></form></div><p id="backtoblog"><a href="/">&larr; Go to Site</a></p></body></html>',
    "/phpmyadmin": b'<!DOCTYPE html><html><head><title>phpMyAdmin</title><style>*{margin:0;padding:0;box-sizing:border-box}body{background:#e7e9ed;font-family:sans-serif;display:flex;justify-content:center;padding-top:5%}.container{width:520px}.header{background:#4a6fa5;color:#fff;padding:8px 16px;font-size:14px;border-radius:4px 4px 0 0;display:flex;justify-content:space-between}.header span{opacity:.7;font-size:11px}.panel{background:#fff;padding:24px;border:1px solid #ccc;border-top:none;border-radius:0 0 4px 4px}table{width:100%}td{padding:6px 4px;font-size:13px;vertical-align:middle}td:first-child{width:130px;text-align:right;color:#444;padding-right:12px}input[type=text],input[type=password],select{width:100%;padding:6px 8px;border:1px solid #aaa;border-radius:2px;font-size:13px}select{width:auto}.submit{text-align:center;padding-top:16px}input[type=submit]{background:#4a6fa5;color:#fff;border:none;padding:6px 24px;border-radius:2px;cursor:pointer;font-size:13px}input[type=submit]:hover{background:#3a5a8a}</style></head><body><div class="container"><div class="header">phpMyAdmin <span>5.2.0</span></div><div class="panel"><form method="POST"><table><tr><td>Username:</td><td><input name="pma_username" type="text" required></td></tr><tr><td>Password:</td><td><input name="pma_password" type="password"></td></tr><tr><td>Server Choice:</td><td><select><option>127.0.0.1</option></select></td></tr></table><div class="submit"><input type="submit" value="Go"></div></form></div></div></body></html>',
    "/grafana": b'<!DOCTYPE html><html><head><title>Grafana</title><style>*{margin:0;padding:0;box-sizing:border-box}body{background:#0b0c0e;font-family:Roboto,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh}.login{width:340px;text-align:center}.logo{font-size:28px;font-weight:700;color:#ff6600;margin-bottom:32px}.login input{width:100%;padding:10px 12px;margin:6px 0;background:#111217;border:1px solid #2c3235;border-radius:4px;color:#d8d9da;font-size:14px}.login button{width:100%;padding:10px;margin-top:12px;background:#3274d9;color:#fff;border:none;border-radius:4px;font-size:14px;cursor:pointer}.login button:hover{background:#245bab}.ver{color:#464c54;font-size:11px;margin-top:20px}</style></head><body><div class="login"><div class="logo">Grafana</div><form method="POST"><input name="user" placeholder="email or username" required><input name="password" type="password" placeholder="password" required><button>Log in</button></form><p class="ver">v9.3.2 (d6a92f042c)</p></div></body></html>',
    "/jenkins": b'<!DOCTYPE html><html><head><title>Jenkins [Jenkins]</title><style>*{margin:0;padding:0;box-sizing:border-box}body{background:#f0f0f0;font-family:Helvetica,Arial,sans-serif;display:flex;flex-direction:column;align-items:center;padding-top:10%}.header{background:#4b758b;width:100%;padding:8px 20px;position:fixed;top:0;color:#fff;font-weight:700;font-size:18px}.panel{background:#fff;padding:32px;border:1px solid #bbb;width:350px;margin-top:40px}h1{font-size:18px;color:#333;margin-bottom:16px}input{width:100%;padding:8px;margin:6px 0;border:1px solid #ccc;font-size:13px}button{padding:8px 24px;background:#4b758b;color:#fff;border:none;cursor:pointer;font-size:14px;margin-top:12px}button:hover{background:#3a6070}</style></head><body><div class="header">Jenkins</div><div class="panel"><h1>Sign in to Jenkins</h1><form method="POST"><input name="j_username" placeholder="User"><input name="j_password" type="password" placeholder="Password"><button>Sign in</button></form></div></body></html>',
    "/.env": b"APP_NAME=Laravel\nAPP_ENV=production\nAPP_KEY=base64:abc123\nDB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_DATABASE=app\nDB_USERNAME=admin\nDB_PASSWORD=s3cretP@ss!\nMAIL_PASSWORD=smtp_pass_123\n",
    "/robots.txt": b"User-agent: *\nDisallow: /admin\nDisallow: /wp-admin\nDisallow: /phpmyadmin\nDisallow: /api/v1/users\nDisallow: /backup\nDisallow: /.git\n",
    "/api": b'{"status":"ok","version":"2.1.0","endpoints":["/api/users","/api/config","/api/admin"]}\n',
}


def _handle_http(conn, addr, port):
    try:
        conn.settimeout(5)
        data = conn.recv(4096)
        req = data.decode("utf-8", errors="replace") if data else ""
        from urllib.parse import unquote
        req_decoded = unquote(req.replace("+", " "))
        lines = req_decoded.split("\r\n")
        first = lines[0] if lines else ""
        method = first.split()[0] if first.split() else "GET"
        path = first.split()[1] if len(first.split()) > 1 else "/"
        ua = ""
        post_body = ""
        for line in lines:
            if line.lower().startswith("user-agent:"):
                ua = line[12:].strip()
        if "\r\n\r\n" in req_decoded:
            post_body = req_decoded.split("\r\n\r\n", 1)[1]
        svc = {80: "HTTP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"}.get(port, "HTTP")
        summary = f"{method} {path}"
        if ua:
            summary += f" UA={ua[:80]}"
        if post_body:
            summary += f" BODY={post_body[:200]}"
            summary += f" CREDS={post_body[:200]}"
        _log_event(addr[0], port, svc, summary)
        if method == "POST" and post_body:
            page = _HTTP_PAGES.get(path, _HTTP_PAGES.get("/admin", b""))
            fail_msg = b'<div style="color:#d63638;background:#fcf0f1;border-left:4px solid #d63638;padding:12px;margin:12px 0;font-size:13px">Invalid username or password. Please try again.</div>'
            page = page.replace(b"</form>", fail_msg + b"</form>")
            conn.sendall(_HTTP_LOGIN_FAIL + page)
        else:
            page = _HTTP_PAGES.get(path, _HTTP_PAGES.get("/"))
            conn.sendall(_HTTP_HDRS + page)
    except Exception:
        pass
    finally:
        conn.close()


def _handle_mysql(conn, addr):
    try:
        conn.settimeout(5)
        hs = (b"\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x33\x33\x00"
              b"\x08\x00\x00\x00\x40\x41\x42\x43\x44\x45\x46\x47\x00"
              b"\xff\xf7\x21\x02\x00\xff\x81\x15\x00\x00\x00\x00\x00"
              b"\x00\x00\x00\x00\x00\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
              b"\x50\x51\x52\x53\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61"
              b"\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00")
        conn.sendall(hs)
        data = conn.recv(512)
        username = db = ""
        if data and len(data) > 36:
            try:
                rest = data[36:]
                parts = rest.split(b"\x00")
                username = parts[0].decode("utf-8", errors="replace")
                if len(parts) > 2:
                    db = parts[2].decode("utf-8", errors="replace")
            except Exception:
                pass
        _log_event(addr[0], 3306, "MySQL", f"user={username} db={db}")
        conn.sendall(b"\xff\x15\x04#28000Access denied for user\x00")
    except Exception:
        pass
    finally:
        conn.close()


def _handle_redis(conn, addr):
    try:
        conn.settimeout(15)
        for _ in range(10):
            data = conn.recv(512)
            if not data:
                break
            cmd = data.decode("utf-8", errors="replace").strip()
            _log_event(addr[0], 6379, "Redis", cmd)
            cl = cmd.upper()
            if "PING" in cl:
                conn.sendall(b"+PONG\r\n")
            elif "INFO" in cl:
                conn.sendall(b"$182\r\nredis_version:6.2.6\r\nos:Linux 5.10.0\r\nconnected_clients:3\r\nused_memory:1024000\r\ndb0:keys=42,expires=5\r\n\r\n")
            elif "CONFIG" in cl or "AUTH" in cl:
                conn.sendall(b"-ERR operation not permitted\r\n")
            elif "QUIT" in cl:
                conn.sendall(b"+OK\r\n")
                break
            else:
                conn.sendall(b"-ERR unknown command\r\n")
    except Exception:
        pass
    finally:
        conn.close()


def _handle_elastic(conn, addr):
    try:
        conn.settimeout(5)
        data = conn.recv(2048)
        req = data.decode("utf-8", errors="replace") if data else ""
        path = req.split()[1] if len(req.split()) > 1 else "/"
        _log_event(addr[0], 9200, "Elastic", req.split("\r\n")[0][:200])
        body = json.dumps({
            "name": "node-1", "cluster_name": "elasticsearch",
            "version": {"number": "7.17.0"}, "tagline": "You Know, for Search"
        }).encode()
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + body)
    except Exception:
        pass
    finally:
        conn.close()


def _handle_docker(conn, addr):
    try:
        conn.settimeout(5)
        data = conn.recv(2048)
        req = data.decode("utf-8", errors="replace") if data else ""
        _log_event(addr[0], 2375, "Docker", req.split("\r\n")[0][:200])
        body = json.dumps([
            {"Id": "abc123", "Names": ["/web"], "Image": "nginx:latest", "State": "running", "Status": "Up 5 days"},
            {"Id": "def456", "Names": ["/db"], "Image": "mysql:5.7", "State": "running", "Status": "Up 5 days"},
        ]).encode()
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nApi-Version: 1.41\r\n\r\n" + body)
    except Exception:
        pass
    finally:
        conn.close()


def _handle_generic(conn, addr, port, service):
    try:
        conn.settimeout(5)
        banner = {
            110: b"+OK Dovecot ready.\r\n",
            143: b"* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS] Dovecot ready.\r\n",
            445: b"\x00\x00\x00\x45\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x98\x01\x28",
            3389: b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x01\x08\x00\x02\x00\x00\x00",
            5900: b"RFB 003.008\n",
            27017: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00",
        }.get(port)
        if banner:
            conn.sendall(banner)
        data = conn.recv(512)
        payload = data.decode("utf-8", errors="replace").strip() if data else "connect"
        _log_event(addr[0], port, service, payload)
    except Exception:
        _log_event(addr[0], port, service, "connect")
    finally:
        conn.close()


_HANDLERS = {
    21: lambda c, a: _handle_ftp(c, a),
    22: lambda c, a: _handle_ssh(c, a),
    23: lambda c, a: _handle_telnet(c, a),
    25: lambda c, a: _handle_smtp(c, a),
    80: lambda c, a: _handle_http(c, a, 80),
    3306: lambda c, a: _handle_mysql(c, a),
    6379: lambda c, a: _handle_redis(c, a),
    8080: lambda c, a: _handle_http(c, a, 8080),
    8443: lambda c, a: _handle_http(c, a, 8443),
    9200: lambda c, a: _handle_elastic(c, a),
    2375: lambda c, a: _handle_docker(c, a),
}


def _connection_handler(conn, addr, port, service):
    handler = _HANDLERS.get(port)
    if handler:
        handler(conn, addr)
    else:
        _handle_generic(conn, addr, port, service)


def _service_listener(port, service):
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(1.0)
        srv.bind(("0.0.0.0", port))
        srv.listen(10)
        _servers.append(srv)
    except OSError:
        return
    while not _shutdown.is_set():
        try:
            conn, addr = srv.accept()
            threading.Thread(target=_connection_handler, args=(conn, addr, port, service), daemon=True).start()
        except socket.timeout:
            continue
        except OSError:
            break
    try:
        srv.close()
    except Exception:
        pass


def _threat_level():
    with _events_lock:
        total = len(_events)
        exploits = len(_exploit_attempts)
    if exploits > 5:
        return "CRITICAL"
    if total > 500:
        return "HIGH"
    if total > 100:
        return "MEDIUM"
    if total > 10:
        return "LOW"
    return "NONE"


def _write_live_stats():
    while not _shutdown.is_set():
        try:
            with _events_lock:
                total = len(_events)
                unique_ips = len(_ip_counts)
                elapsed = max(1, time.time() - _start_time)
                eph = total / (elapsed / 3600) if elapsed > 0 else 0
                top_ips = [
                    {"ip": ip, "count": c, "country": _lookup_country(ip), "last_seen": _ip_last_seen.get(ip, "")}
                    for ip, c in _ip_counts.most_common(30)
                ]
                port_stats = []
                for port, svc in SERVICES:
                    cnt = _port_counts.get(port, 0)
                    if cnt > 0:
                        port_stats.append({"port": port, "service": svc, "count": cnt})
                port_stats.sort(key=lambda x: -x["count"])
                at = [{"type": t, "count": c} for t, c in _attack_types.most_common(10)]
                recent = list(_events[-50:])
                recent.reverse()
                hm = [row[:] for row in _heatmap]
                exploits = list(_exploit_attempts[-20:])
                exploits.reverse()
                creds = list(_credentials[-50:])
                creds.reverse()
            with _session_lock:
                sessions = _active_sessions
            svcs_status = []
            for port, svc in SERVICES:
                bound = any(True for s in _servers if s.fileno() >= 0)
                svcs_status.append({"port": port, "service": svc, "active": True, "connections": _port_counts.get(port, 0)})
            output = {
                "ts": time.time(), "running": True,
                "total_events": total, "unique_ips": unique_ips,
                "events_per_hour": round(eph, 1), "uptime": int(elapsed),
                "active_sessions": sessions, "threat_level": _threat_level(),
                "top_ips": top_ips, "port_stats": port_stats,
                "attack_types": at, "recent_events": recent,
                "exploit_attempts": exploits, "credentials": creds,
                "heatmap": hm, "services_status": svcs_status,
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
    views = ["dash", "services", "events", "stats"]
    status = "Ready"

    def start_hp():
        nonlocal running
        global _start_time
        _shutdown.clear()
        _start_time = time.time()
        for port, svc in SERVICES:
            threading.Thread(target=_service_listener, args=(port, svc), daemon=True).start()
        threading.Thread(target=_write_live_stats, daemon=True).start()
        running = True

    if auto_mode:
        start_hp()
        status = "Active"

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
                    start_hp()
                    status = "Active"
                else:
                    _shutdown.set()
                    running = False
                    status = "Stopped"
            if btn == "KEY2" and _events:
                status = f"Logged {len(_events)} events"

            with _events_lock:
                total = len(_events)
                unique = len(_ip_counts)
                exploits = len(_exploit_attempts)
            with _session_lock:
                sessions = _active_sessions

            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)

            # Header
            tlvl = _threat_level()
            tc = {"CRITICAL": "#FF0000", "HIGH": "#FF4444", "MEDIUM": "#FFAA00", "LOW": "#00FF88", "NONE": "#333"}.get(tlvl, "#888")
            d.rectangle((0, 0, 127, 14), fill="#111")
            d.text((2, 2), "HONEYPOT", font=font_sm, fill="#FF4444")
            d.text((55, 2), tlvl[:4], font=font_sm, fill=tc)
            if running:
                d.ellipse((120, 4, 126, 10), fill="#00FF00")
            y = 18

            if views[view] == "dash":
                d.text((2, y), f"Events: {total}", font=font, fill="#00CCFF")
                y += 14
                d.text((2, y), f"IPs: {unique}  Sessions: {sessions}", font=font_sm, fill="#ccc")
                y += 12
                d.text((2, y), f"Exploits: {exploits}", font=font_sm, fill="#FF4444" if exploits else "#333")
                y += 12
                elapsed = time.time() - _start_time if running else 0
                h, m = int(elapsed // 3600), int((elapsed % 3600) // 60)
                d.text((2, y), f"Uptime: {h}h{m:02d}m", font=font_sm, fill="#888")
                y += 14
                with _events_lock:
                    top3 = _ip_counts.most_common(3)
                for ip, cnt in top3:
                    if y > 108:
                        break
                    cc = _lookup_country(ip)
                    d.text((2, y), f"{cc} {ip[:13]}", font=font_sm, fill="#FF8800")
                    d.text((100, y), str(cnt), font=font_sm, fill="#ccc")
                    y += 10

            elif views[view] == "services":
                d.text((2, y), status[:24], font=font_sm, fill="#FFAA00")
                y += 12
                for i in range(scroll, min(len(SERVICES), scroll + 6)):
                    if y > 108:
                        break
                    port, svc = SERVICES[i]
                    cnt = _port_counts.get(port, 0)
                    col = SERVICE_COLORS.get(svc, "#888")
                    d.text((2, y), f":{port}", font=font_sm, fill="#555")
                    d.text((30, y), svc[:8], font=font_sm, fill=col)
                    d.text((85, y), str(cnt), font=font_sm, fill="#ccc" if cnt else "#333")
                    y += 10

            elif views[view] == "events":
                with _events_lock:
                    recent = list(_events[-30:])
                    recent.reverse()
                for i in range(scroll, min(len(recent), scroll + 5)):
                    if y > 108:
                        break
                    ev = recent[i]
                    col = SERVICE_COLORS.get(ev["service"], "#888")
                    sev_col = {"critical": "#FF0000", "high": "#FF4444", "medium": "#FFAA00"}.get(ev.get("severity"), "#555")
                    d.text((2, y), ev["ts"][11:19], font=font_sm, fill="#444")
                    d.text((48, y), ev["ip"][:12], font=font_sm, fill=col)
                    d.text((2, y + 9), f"{ev['service']} {ev.get('country', '')} {ev['data'][:14]}", font=font_sm, fill="#666")
                    d.rectangle((122, y, 127, y + 8), fill=sev_col)
                    y += 20

            elif views[view] == "stats":
                d.text((2, y), f"Events: {total}  IPs: {unique}", font=font_sm, fill="#ccc")
                y += 12
                with _events_lock:
                    top_at = _attack_types.most_common(4)
                for at, cnt in top_at:
                    if y > 70:
                        break
                    d.text((2, y), f"{at[:18]}", font=font_sm, fill="#FFAA00")
                    d.text((100, y), str(cnt), font=font_sm, fill="#ccc")
                    y += 10
                y += 4
                with _events_lock:
                    top = _ip_counts.most_common(4)
                for ip, cnt in top:
                    if y > 108:
                        break
                    cc = _lookup_country(ip)
                    d.text((2, y), f"{cc} {ip[:13]}", font=font_sm, fill="#FF4444")
                    d.text((100, y), str(cnt), font=font_sm, fill="#ccc")
                    y += 10

            d.rectangle((0, 116, 127, 127), fill="#111")
            vn = views[view][:4].upper()
            d.text((2, 117), f"OK:{'Stop' if running else 'Go'} K1:{vn} K3:X", font=font_sm, fill="#666")
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
