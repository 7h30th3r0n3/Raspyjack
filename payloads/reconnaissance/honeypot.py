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

import hashlib
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
from bisect import bisect_right
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
MALWARE_DIR = os.path.join(LOOT_DIR, "malware")
WEBHOOK_PATH = "/root/Raspyjack/discord_webhook.txt"
GEOIP_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "sdr", "data", "geoip.json")

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
_malware_captures = []
_total_connections = 0
SESSION_DIR = os.path.join(LOOT_DIR, "sessions")
SESSION_FILE = os.path.join(LOOT_DIR, "session_state.json")
_current_session_path = ""


def _init_new_session():
    global _current_session_path
    os.makedirs(SESSION_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    _current_session_path = os.path.join(SESSION_DIR, f"honeypot_{ts}.json")


def _save_session():
    try:
        os.makedirs(LOOT_DIR, exist_ok=True)
        os.makedirs(SESSION_DIR, exist_ok=True)
        with _events_lock:
            state = {
                "session_start": datetime.fromtimestamp(_start_time).isoformat() if _start_time else "",
                "session_end": datetime.now().isoformat(),
                "port_counts": dict(_port_counts),
                "ip_counts": dict(_ip_counts),
                "ip_last_seen": dict(_ip_last_seen),
                "attack_types": dict(_attack_types),
                "heatmap": _heatmap,
                "credentials": _credentials[-500:],
                "exploit_attempts": _exploit_attempts[-200:],
                "malware_captures": _malware_captures[-50:],
                "total_connections": _total_connections,
                "total_events": len(_events),
                "alerted_ips": list(_alerted_ips),
                "recent_events": _events[-500:],
            }
        tmp = SESSION_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f)
        os.replace(tmp, SESSION_FILE)
        if _current_session_path:
            tmp2 = _current_session_path + ".tmp"
            with open(tmp2, "w") as f:
                json.dump(state, f, indent=2)
            os.replace(tmp2, _current_session_path)
    except Exception:
        pass


def _restore_session():
    global _total_connections
    if not os.path.isfile(SESSION_FILE):
        return False
    try:
        with open(SESSION_FILE) as f:
            state = json.load(f)
        with _events_lock:
            _port_counts.update(state.get("port_counts", {}))
            _ip_counts.update(state.get("ip_counts", {}))
            _ip_last_seen.update(state.get("ip_last_seen", {}))
            _attack_types.update(state.get("attack_types", {}))
            saved_hm = state.get("heatmap", [])
            for i in range(min(7, len(saved_hm))):
                for j in range(min(24, len(saved_hm[i]))):
                    _heatmap[i][j] = saved_hm[i][j]
            _credentials.extend(state.get("credentials", []))
            _exploit_attempts.extend(state.get("exploit_attempts", []))
            _malware_captures.extend(state.get("malware_captures", []))
            _total_connections = state.get("total_connections", 0)
            _alerted_ips.update(state.get("alerted_ips", []))
            _events.extend(state.get("recent_events", []))
        return True
    except Exception:
        return False

# ── Exploit patterns (pre-compiled for performance) ──────────────────
_EXPLOIT_PATTERNS_RAW = [
    # RCE / Injection
    (r"\$\{jndi:", "Log4Shell", "T1190"),
    (r"\(\)\s*\{", "Shellshock", "T1190"),
    (r";\s*(ls|cat|id|wget|curl|nc|bash|sh|python|perl|rm|chmod|chown|kill|nohup|tftp|ftpget)\b", "Command Injection", "T1059"),
    (r"\|[\s+]*(ls|cat|id|bash|sh|nc|wget|curl|python|whoami|uname)", "Pipe Injection", "T1059"),
    (r"`[^`]*`", "Backtick Injection", "T1059"),
    (r"\$\([^)]+\)", "Subshell Injection", "T1059"),
    # SQLi
    (r"(union[\s+]+(all[\s+]+)?select|select[\s+]+[^;]{0,200}from[\s+])", "SQL Injection", "T1190"),
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
EXPLOIT_PATTERNS = [(re.compile(p, re.IGNORECASE), n, m) for p, n, m in _EXPLOIT_PATTERNS_RAW]

# ── GeoIP ────────────────────────────────────────────────────────────
_geoip_cache = {}
_geoip_db = None
_geoip_starts = None


def _ip_to_int(ip):
    try:
        parts = ip.split(".")
        return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])
    except Exception:
        return 0


def _load_geoip_db():
    global _geoip_db, _geoip_starts
    if _geoip_db is not None:
        return
    db_path = os.path.abspath(GEOIP_DB_PATH)
    if os.path.isfile(db_path):
        try:
            with open(db_path) as f:
                _geoip_db = json.load(f)
            _geoip_starts = [r[0] for r in _geoip_db]
        except Exception:
            _geoip_db = []
            _geoip_starts = []
    else:
        _geoip_db = []
        _geoip_starts = []


def _lookup_country(ip):
    if ip in _geoip_cache:
        return _geoip_cache[ip]
    if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
        _geoip_cache[ip] = "LAN"
        return "LAN"
    _load_geoip_db()
    ip_int = _ip_to_int(ip)
    if _geoip_starts:
        idx = bisect_right(_geoip_starts, ip_int) - 1
        if 0 <= idx < len(_geoip_db):
            lo, hi, cc = _geoip_db[idx]
            if lo <= ip_int <= hi:
                _geoip_cache[ip] = cc
                return cc
    if len(_geoip_cache) > 10000:
        _geoip_cache.clear()
    _geoip_cache[ip] = "??"
    return "??"


def _classify_attack(port, data):
    if not data:
        return "scan", "low"
    dl = data.lower()
    for pat, name, mitre in EXPLOIT_PATTERNS:
        if pat.search(data):
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
        if os.path.getsize(EVENTS_FILE) > 500 * 1024 * 1024:
            rotated = EVENTS_FILE + ".1"
            try:
                os.replace(EVENTS_FILE, rotated)
            except OSError:
                pass
    except Exception:
        pass
    if is_new_ip:
        with _events_lock:
            already_alerted = ip in _alerted_ips
            _alerted_ips.add(ip)
        if not already_alerted:
            threading.Thread(target=_send_webhook, args=(event,), daemon=True).start()


# ── Fake Shell ────────────────────────────────────────────────────────
_FILES = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nsyslog:x:104:110::/home/syslog:/usr/sbin/nologin\nmysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false\nsshd:x:106:65534::/run/sshd:/usr/sbin/nologin\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\ndeploy:x:1001:1001:deploy:/home/deploy:/bin/bash\nubuntu:x:1002:1002:Ubuntu:/home/ubuntu:/bin/bash\nnginx:x:33:33:nginx:/var/www:/usr/sbin/nologin\npostgres:x:108:112:PostgreSQL:/var/lib/postgresql:/bin/bash\nredis:x:109:113:redis:/var/lib/redis:/usr/sbin/nologin\n",
    "/etc/shadow": "root:$6$rounds=656000$rN3xYq$KJ8Hf2vZ5mXwE9Lk3nQ7aRjD8bYfMcU1.T4Gk0pWzVhXsN6:19723:0:99999:7:::\ndaemon:*:19723:0:99999:7:::\nbin:*:19723:0:99999:7:::\nsys:*:19723:0:99999:7:::\nwww-data:*:19723:0:99999:7:::\nmysql:!:19723:0:99999:7:::\nadmin:$6$rounds=656000$xQ9kWm$Yp3Rj7V8eZaM5nLwF2hU4sK1dBvNqX6.T0cGf8pJrEiDm3S:19750:0:99999:7:::\ndeploy:$6$rounds=656000$mP7hNx$Zk9Lj5V3eBaC2nRwF8hU1sK4dDvMqX0.T6cGf2pJrAiYm7W:19780:0:99999:7:::\n",
    "/etc/hostname": "web-prod-01\n",
    "/etc/hosts": "127.0.0.1\tlocalhost\n127.0.1.1\tweb-prod-01\n10.0.2.20\tdb-prod-01\n10.0.2.21\tcache-prod-01\n10.0.2.22\tbackup-01\n",
    "/etc/resolv.conf": "nameserver 8.8.8.8\nnameserver 8.8.4.4\nsearch example.com\n",
    "/etc/os-release": 'PRETTY_NAME="Ubuntu 20.04.5 LTS"\nNAME="Ubuntu"\nVERSION_ID="20.04"\nVERSION="20.04.5 LTS (Focal Fossa)"\nID=ubuntu\nID_LIKE=debian\n',
    "/etc/ssh/sshd_config": "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\nMaxAuthTries 6\nPubkeyAuthentication yes\nAuthorizedKeysFile .ssh/authorized_keys\nX11Forwarding yes\nUsePAM yes\n",
    "/etc/nginx/nginx.conf": "user www-data;\nworker_processes auto;\npid /run/nginx.pid;\nevents { worker_connections 768; }\nhttp {\n  sendfile on;\n  include /etc/nginx/sites-enabled/*;\n  server {\n    listen 80;\n    server_name example.com;\n    root /var/www/html;\n    location /admin { proxy_pass http://127.0.0.1:8080; }\n  }\n}\n",
    "/etc/mysql/my.cnf": "[mysqld]\nuser = mysql\npid-file = /var/run/mysqld/mysqld.pid\nsocket = /var/run/mysqld/mysqld.sock\nport = 3306\nbasedir = /usr\ndatadir = /var/lib/mysql\nbind-address = 0.0.0.0\nmax_connections = 151\n",
    "/etc/crontab": "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n*/5 * * * * root /opt/scripts/backup.sh\n0 2 * * * root /usr/bin/certbot renew --quiet\n0 * * * * root /opt/scripts/health_check.sh\n",
    "/home/admin/.bash_history": "mysql -u root -pS3cretDB!\nscp deploy@10.0.2.20:/backups/db.sql.gz .\naws s3 cp s3://prod-backups/latest.tar.gz .\ndocker exec -it web_app bash\ncurl -H 'Authorization: Bearer eyJhbG...' https://api.internal/admin\nssh deploy@db-prod-01\ncat /var/log/auth.log | grep Failed\niptables -L\nnetstat -tlnp\n",
    "/home/deploy/.env": "APP_NAME=ProductionApp\nAPP_ENV=production\nAPP_KEY=base64:dGhpc2lzYXZlcnlsb25nc2VjcmV0a2V5Zm9ybGFyYXZlbA==\nDB_CONNECTION=mysql\nDB_HOST=10.0.2.20\nDB_PORT=3306\nDB_DATABASE=prod_app\nDB_USERNAME=app_user\nDB_PASSWORD=Pr0d_DB_P@ss!2024\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nAWS_DEFAULT_REGION=eu-west-1\nSTRIPE_SECRET=sk_live_FAKE_HONEYPOT_KEY_0x4eC39\nMAIL_PASSWORD=smtp_Pr0d_2024!\nREDIS_PASSWORD=R3d1s_S3cr3t\nJWT_SECRET=super_secret_jwt_key_never_share\n",
    "/home/deploy/.ssh/authorized_keys": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... deploy@ci-server\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... admin@workstation\n",
    "/root/.bash_history": "mysql -u root -pS3cretDB!\napt update && apt upgrade -y\ncat /etc/shadow\nuseradd -m deploy\npasswd deploy\ndocker-compose up -d\ncurl https://api.stripe.com/v1/charges -u sk_live_FAKE_HONEYPOT_KEY_0x4eC39:\naws s3 ls s3://prod-backups/\nssh-keygen -t rsa -b 4096\nhistory\n",
    "/root/.mysql_history": "SELECT * FROM users;\nSHOW DATABASES;\nSELECT user,host,authentication_string FROM mysql.user;\nGRANT ALL PRIVILEGES ON *.* TO 'backup'@'%' IDENTIFIED BY 'BackupP@ss99';\nUPDATE users SET role='admin' WHERE email='ceo@example.com';\n",
    "/proc/version": "Linux version 5.10.0-20-amd64 (debian-kernel@lists.debian.org) (gcc-10 (Debian 10.2.1-6) 10.2.1 20210110) #1 SMP Debian 5.10.158-2 (2022-12-13)\n",
    "/proc/cpuinfo": "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel name\t: Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz\nstepping\t: 1\ncpu MHz\t\t: 2300.000\ncache size\t: 46080 KB\ncpu cores\t: 4\nbogomips\t: 4600.00\n",
    "/proc/meminfo": "MemTotal:        8044956 kB\nMemFree:         1685432 kB\nMemAvailable:    4823456 kB\nBuffers:          384512 kB\nCached:          2753512 kB\nSwapTotal:       2097148 kB\nSwapFree:        2040832 kB\n",
    "/var/log/auth.log": "Jan 15 08:25:10 web-prod-01 sshd[4521]: Failed password for root from 185.220.101.42 port 43210 ssh2\nJan 15 08:25:12 web-prod-01 sshd[4521]: Failed password for root from 185.220.101.42 port 43210 ssh2\nJan 15 08:26:01 web-prod-01 sshd[4523]: Failed password for admin from 103.27.108.3 port 55123 ssh2\nJan 15 08:27:30 web-prod-01 sshd[4525]: Accepted password for admin from 10.0.2.2 port 52100 ssh2\nJan 15 08:28:15 web-prod-01 sudo:    admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash\n",
    "/var/www/html/index.html": "<html><head><title>Welcome</title></head><body><h1>Web Server</h1><p>Production server - example.com</p></body></html>\n",
    "/etc/issue": "Ubuntu 20.04.5 LTS \\n \\l\n\n",
    "/etc/motd": "Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.10.0-20-amd64 x86_64)\n\n * Documentation:  https://help.ubuntu.com\n * Management:     https://landscape.canonical.com\n * Support:        https://ubuntu.com/advantage\n\n  System information as of Mon Jan 15 08:30:15 UTC 2024\n\n  System load:  0.08\n  Usage of /:   24.0% of 50GB\n  Memory usage: 31%\n  Swap usage:   2%\n  Processes:    142\n  Users logged in: 1\n\n",
}

_DIRS = {
    "/": ["bin", "boot", "dev", "etc", "home", "lib", "media", "mnt", "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var"],
    "/etc": ["passwd", "shadow", "hostname", "hosts", "resolv.conf", "os-release", "ssh", "nginx", "mysql", "crontab", "fstab", "group"],
    "/etc/ssh": ["sshd_config", "ssh_host_rsa_key.pub"],
    "/etc/nginx": ["nginx.conf", "sites-enabled", "sites-available"],
    "/etc/mysql": ["my.cnf", "debian.cnf"],
    "/home": ["admin", "deploy", "ubuntu"],
    "/home/admin": [".bash_history", ".ssh", ".bashrc", ".profile", "backup.sh"],
    "/home/admin/.ssh": ["authorized_keys", "id_rsa", "id_rsa.pub", "known_hosts"],
    "/home/deploy": [".env", ".ssh", ".bashrc", "app", "docker-compose.yml"],
    "/home/deploy/.ssh": ["authorized_keys"],
    "/root": [".bash_history", ".mysql_history", ".ssh", ".bashrc", ".profile", "scripts"],
    "/root/.ssh": ["authorized_keys", "id_rsa", "known_hosts"],
    "/var": ["log", "www", "lib", "run", "tmp", "backups"],
    "/var/log": ["auth.log", "syslog", "nginx", "mysql", "kern.log", "dpkg.log"],
    "/var/log/nginx": ["access.log", "error.log"],
    "/var/www": ["html"],
    "/var/www/html": ["index.html", "admin", "uploads", ".htaccess"],
    "/proc": ["version", "cpuinfo", "meminfo", "self", "cmdline", "uptime"],
    "/tmp": [],
}

_BUSYBOX_FULL = (
    "BusyBox v1.30.1 (2019-06-12 17:51:55 UTC) multi-call binary.\n"
    "Usage: busybox [function [arguments]...]\n\n"
    "Currently defined functions:\n"
    "\tcat, chmod, cp, echo, grep, ifconfig, kill, ls, mkdir, mount,\n"
    "\tping, ps, pwd, rm, sh, telnet, test, tftp, wget\n"
)

_CMDS = {
    # ── Identity ──
    "whoami": "root\n",
    "id": "uid=0(root) gid=0(root) groups=0(root)\n",
    "hostname": "web-prod-01\n",
    # ── Kernel / arch (critical: bots use uname -m to choose binary) ──
    "uname": "Linux\n",
    "uname -a": "Linux web-prod-01 4.14.180 #1 SMP PREEMPT Fri Jun 5 14:30:33 UTC 2020 armv7l GNU/Linux\n",
    "uname -r": "4.14.180\n",
    "uname -m": "armv7l\n",
    "uname -n": "web-prod-01\n",
    "uname -s": "Linux\n",
    "uname -p": "armv7l\n",
    "arch": "armv7l\n",
    "getconf LONG_BIT": "32\n",
    # ── Uptime / load ──
    "uptime": " 08:30:15 up 142 days, 3:22, 1 user, load average: 0.08, 0.03, 0.01\n",
    "cat /proc/uptime": "12280935.42 48923120.68\n",
    # ── Network ──
    "ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n        ether 08:00:27:8b:c9:3f  txqueuelen 1000\n        RX bytes:42512300 TX bytes:18763200\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1  netmask 255.0.0.0\n",
    "ip addr": "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0\n       valid_lft forever preferred_lft forever\n",
    "ip route": "default via 10.0.2.1 dev eth0\n10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15\n",
    "ip link": "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000\n",
    "route": "Kernel IP routing table\nDestination     Gateway         Genmask         Flags Metric Ref    Use Iface\ndefault         10.0.2.1        0.0.0.0         UG    0      0        0 eth0\n10.0.2.0        *               255.255.255.0   U     0      0        0 eth0\n",
    "route -n": "Kernel IP routing table\nDestination     Gateway         Genmask         Flags Metric Ref    Use Iface\n0.0.0.0         10.0.2.1        0.0.0.0         UG    0      0        0 eth0\n10.0.2.0        0.0.0.0         255.255.255.0   U     0      0        0 eth0\n",
    "arp -a": "gateway (10.0.2.1) at 52:54:00:12:35:02 [ether] on eth0\n",
    "netstat -tlnp": "Proto Recv-Q Send-Q Local Address      Foreign Address    State       PID/Program\ntcp        0      0 0.0.0.0:22         0.0.0.0:*          LISTEN      215/sshd\ntcp        0      0 0.0.0.0:80         0.0.0.0:*          LISTEN      420/nginx\ntcp        0      0 0.0.0.0:443        0.0.0.0:*          LISTEN      420/nginx\ntcp        0      0 0.0.0.0:3306       0.0.0.0:*          LISTEN      510/mysqld\ntcp        0      0 127.0.0.1:6379     0.0.0.0:*          LISTEN      830/redis-server\ntcp        0      0 0.0.0.0:5432       0.0.0.0:*          LISTEN      910/postgres\n",
    "ss -tlnp": "State    Recv-Q Send-Q Local Address:Port   Peer Address:Port Process\nLISTEN   0      128    0.0.0.0:22          0.0.0.0:*       users:((\"sshd\",pid=215))\nLISTEN   0      511    0.0.0.0:80          0.0.0.0:*       users:((\"nginx\",pid=420))\nLISTEN   0      80     0.0.0.0:3306        0.0.0.0:*       users:((\"mysqld\",pid=510))\nLISTEN   0      128    127.0.0.1:6379      0.0.0.0:*       users:((\"redis\",pid=830))\n",
    "netstat -an": "Proto Recv-Q Send-Q Local Address      Foreign Address    State\ntcp        0      0 0.0.0.0:22         0.0.0.0:*          LISTEN\ntcp        0      0 0.0.0.0:80         0.0.0.0:*          LISTEN\ntcp        0      0 10.0.2.15:22       10.0.2.2:52100     ESTABLISHED\n",
    # ── Processes ──
    "ps": "  PID TTY          TIME CMD\n    1 ?        00:00:12 init\n  215 ?        00:00:00 sshd\n  420 ?        00:12:34 nginx\n  510 ?        00:45:12 mysqld\n 4521 pts/0    00:00:00 bash\n 4600 pts/0    00:00:00 ps\n",
    "ps aux": "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1 169396 11680 ?        Ss   Jan01   0:12 /sbin/init\nroot       215  0.0  0.0  72296  5500 ?        Ss   Jan01   0:00 /usr/sbin/sshd -D\nroot       310  0.0  0.0  28620  2980 ?        Ss   Jan01   0:05 /usr/sbin/cron -f\nwww-data   420  0.2  1.5 364288 62140 ?        Sl   Jan01  12:34 nginx: worker\nmysql      510  0.5  5.2 1248912 212348 ?       Ssl  Jan01  45:12 /usr/sbin/mysqld\nroot       625  0.0  0.4 712892 18456 ?        Ssl  Jan01   1:23 /usr/bin/containerd\nroot       720  0.1  0.6 1149204 25600 ?       Ssl  Jan01   5:40 /usr/bin/dockerd\nredis      830  0.1  0.3  61424  12480 ?        Ssl  Jan01   3:22 /usr/bin/redis-server\npostgres   910  0.0  1.0 215432 42000 ?        Ss   Jan01   0:45 /usr/lib/postgresql/13/bin/postgres\n",
    "ps auxf": "USER       PID %CPU %MEM COMMAND\nroot         1  0.0  0.1 /sbin/init\nroot       215  0.0  0.0  \\_ /usr/sbin/sshd -D\nroot      4521  0.0  0.0      \\_ sshd: root [priv]\nroot       310  0.0  0.0  \\_ /usr/sbin/cron -f\nwww-data   420  0.2  1.5  \\_ nginx: worker\nmysql      510  0.5  5.2  \\_ /usr/sbin/mysqld\n",
    "ps w": "  PID TTY      STAT   TIME COMMAND\n    1 ?        Ss     0:12 init\n  215 ?        Ss     0:00 /usr/sbin/sshd\n  420 ?        Sl    12:34 nginx: worker\n  510 ?        Ssl   45:12 /usr/sbin/mysqld\n",
    # ── Disk / Memory ──
    "df -h": "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   12G   36G  25% /\ntmpfs           2.0G     0  2.0G   0% /dev/shm\n/dev/sda2       200G   89G  101G  47% /var/lib/mysql\n",
    "free -m": "              total        used        free      shared  buff/cache   available\nMem:           7856        2412        1124         256        4320        4890\nSwap:          2048          56        1992\n",
    "free": "              total        used        free      shared  buff/cache   available\nMem:        8044956     2469888     1151168      262144     4423900     5010432\nSwap:       2097148       57344     2039804\n",
    "mount": "/dev/root on / type ext4 (rw,relatime)\nproc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\ntmpfs on /tmp type tmpfs (rw,nosuid,nodev)\ndevpts on /dev/pts type devpts (rw,nosuid,noexec,relatime)\n",
    # ── Users / Sessions ──
    "w": " 08:30:15 up 142 days, 3:22, 1 user, load average: 0.08, 0.03, 0.01\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nroot     pts/0    10.0.2.2         08:29    0.00s  0.03s  0.00s -bash\n",
    "who": "root     pts/0        2024-01-15 08:29 (10.0.2.2)\n",
    "last": "root     pts/0        10.0.2.2         Mon Jan 15 08:29   still logged in\nroot     pts/0        10.0.2.2         Sun Jan 14 22:10 - 23:45  (01:35)\nroot     pts/0        10.0.2.2         Sat Jan 13 09:00 - 12:30  (03:30)\nadmin    pts/1        192.168.1.100    Fri Jan 12 14:20 - 16:45  (02:25)\n\nwtmp begins Mon Dec 11 10:00:00 2023\n",
    "env": "SHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nHOME=/root\nLOGNAME=root\nUSER=root\nLANG=en_US.UTF-8\nTERM=xterm-256color\nDOCKER_HOST=unix:///var/run/docker.sock\nAWS_DEFAULT_REGION=eu-west-1\n",
    "crontab -l": "*/5 * * * * /opt/scripts/backup.sh\n0 2 * * * /usr/bin/certbot renew --quiet\n0 * * * * /opt/scripts/health_check.sh\n",
    "history": "",
    # ── Docker ──
    "docker ps": "CONTAINER ID   IMAGE          COMMAND                  STATUS          PORTS                  NAMES\na1b2c3d4e5f6   nginx:1.23     \"/docker-entrypoint.…\"   Up 45 days      0.0.0.0:80->80/tcp     web_proxy\nb2c3d4e5f6a1   myapp:latest   \"python manage.py ru…\"   Up 45 days      0.0.0.0:8080->8080     web_app\nc3d4e5f6a1b2   mysql:8.0      \"docker-entrypoint.s…\"   Up 45 days      3306/tcp               db\nd4e5f6a1b2c3   redis:7        \"docker-entrypoint.s…\"   Up 45 days      6379/tcp               cache\n",
    "docker images": "REPOSITORY   TAG       IMAGE ID       CREATED        SIZE\nnginx        1.23      3964ce7b8458   2 months ago   142MB\nmyapp        latest    a8b9c0d1e2f3   1 week ago     456MB\nmysql        8.0       5c62e459e087   3 months ago   541MB\nredis        7         7614ae9453d1   2 months ago   117MB\nalpine       3.18      05455a08881e   4 months ago   7.34MB\n",
    # ── IoT / Router probe traps (accept silently — bot thinks it worked) ──
    "enable": "\n",
    "system": "\n",
    "shell": "\n",
    "sh": "\n",
    "linuxshell": "\n",
    "cli": "\n",
    "help": "Type 'exit' to close connection.\n",
    "?": "Type 'exit' to close connection.\n",
    # ── BusyBox (critical for Mirai — makes it proceed to download) ──
    "/bin/busybox": _BUSYBOX_FULL,
    "busybox": _BUSYBOX_FULL,
    # ── /proc entries bots check ──
    "cat /proc/mounts": "rootfs / rootfs rw 0 0\n/dev/root / ext4 rw,relatime 0 0\nproc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\ntmpfs /tmp tmpfs rw,nosuid,nodev 0 0\ndevpts /dev/pts devpts rw,nosuid,noexec,relatime 0 0\n",
    "cat /proc/cpuinfo": "processor\t: 0\nmodel name\t: ARMv7 Processor rev 4 (v7l)\nBogoMIPS\t: 38.40\nFeatures\t: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae evtstrm crc32\nCPU implementer\t: 0x41\nCPU architecture: 7\nCPU variant\t: 0x0\nCPU part\t: 0xd03\nCPU revision\t: 4\nHardware\t: BCM2835\nRevision\t: a020d3\n",
    "cat /proc/net/route": "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t0102000A\t0003\t0\t0\t0\t00000000\neth0\t0002000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\n",
    "cat /proc/self/exe": "\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00(\x00\n",
    "cat /proc/self/maps": "00400000-00410000 r-xp 00000000 b3:01 1234       /bin/busybox\n00410000-00420000 rw-p 00010000 b3:01 1234       /bin/busybox\n76e00000-76f30000 r-xp 00000000 b3:01 5678       /lib/libc.so.6\n",
    "cat /bin/echo": "\x7fELF\x01\x01\x01\x00\n",
    "cat /proc/self/status": "Name:\tbash\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t4521\nPid:\t4521\nPPid:\t215\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t0\nVmPeak:\t   12480 kB\nVmSize:\t   12480 kB\n",
    # ── Cisco / router simulation ──
    "show version": "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11\nSystem image file is \"flash:c2960-lanbasek9-mz.150-2.SE11.bin\"\nSystem uptime is 142 days, 3 hours, 22 minutes\n",
    "show running-config": "Building configuration...\n\nCurrent configuration : 1024 bytes\n!\nhostname Router\n!\nenable secret 5 $1$abc$xyz\n!\ninterface FastEthernet0/0\n ip address 10.0.2.15 255.255.255.0\n no shutdown\n!\nline vty 0 4\n login local\n transport input telnet ssh\n!\nend\n",
    "configure terminal": "Enter configuration commands, one per line. End with CNTL/Z.\n",
    "terminal length 0": "\n",
    "show ip route": "Gateway of last resort is 10.0.2.1 to network 0.0.0.0\nC    10.0.2.0/24 is directly connected, FastEthernet0/0\nS*   0.0.0.0/0 [1/0] via 10.0.2.1\n",
    "show interfaces": "FastEthernet0/0 is up, line protocol is up\n  Hardware is Fast Ethernet, address is 0800.278b.c93f\n  Internet address is 10.0.2.15/24\n  MTU 1500 bytes, BW 100000 Kbit, DLY 100 usec\n",
    # ── tftp ──
    "tftp": "Usage: tftp [OPTIONS] HOST [PORT]\n\t-l FILE\tLocal FILE\n\t-r FILE\tRemote FILE\n\t-g\tGet file\n\t-p\tPut file\n",
}

def _do_ls(path, detailed=False, show_all=False):
    entries = _DIRS.get(path)
    if entries is None:
        return f"ls: cannot access '{path}': No such file or directory\n"
    if show_all:
        entries = [".", ".."] + entries
    if not detailed:
        return "  ".join(entries) + "\n" if entries else "\n"
    lines = [f"total {len(entries) * 4}"]
    for e in entries:
        if e in (".", ".."):
            lines.append(f"drwxr-xr-x 2 root root  4096 Jan 15 08:30 {e}")
            continue
        full = path.rstrip("/") + "/" + e
        if full in _FILES:
            sz = len(_FILES[full])
            lines.append(f"-rw-r--r-- 1 root root {sz:>5} Jan 15 08:30 {e}")
        elif full in _DIRS:
            lines.append(f"drwxr-xr-x 2 root root  4096 Jan 15 08:30 {e}")
        else:
            lines.append(f"-rw-r--r-- 1 root root     0 Jan 15 08:30 {e}")
    return "\n".join(lines) + "\n"


_BLOCKED_HOSTS = re.compile(
    r"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|0\.0\.0\.0|localhost|metadata|::1)"
)


def _download_malware(ip, url):
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if _BLOCKED_HOSTS.match(host):
            _log_event(ip, 0, "Malware", f"BLOCKED internal URL {url}")
            return
        os.makedirs(MALWARE_DIR, exist_ok=True)
        fname = url.split("/")[-1].split("?")[0] or "payload"
        safe_name = re.sub(r'[^\w.\-]', '_', fname)[:64]
        safe_name = safe_name.replace("..", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(MALWARE_DIR, f"{ts}_{ip}_{safe_name}")
        req = urllib.request.Request(url, headers={"User-Agent": "Wget/1.21"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read(5 * 1024 * 1024)
        with open(out_path, "wb") as f:
            f.write(data)
        sha = hashlib.sha256(data).hexdigest()
        cap = {"ts": datetime.now().isoformat(timespec="seconds"), "ip": ip, "url": url,
               "filename": safe_name, "sha256": sha, "size": len(data)}
        with _events_lock:
            _malware_captures.append(cap)
            if len(_malware_captures) > 50:
                _malware_captures[:] = _malware_captures[-40:]
        _log_event(ip, 0, "Malware", f"CAPTURED {safe_name} sha256={sha[:16]}... size={len(data)}")
    except Exception:
        _log_event(ip, 0, "Malware", f"FAILED download {url}")


FAKE_FS = _CMDS


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
        b = ch[0]
        if b == 0xFF:
            try:
                conn.recv(2)
            except Exception:
                pass
            continue
        if b == 0x00:
            continue
        if b in (0x0D, 0x0A):
            if echo:
                conn.sendall(b"\r\n")
            return buf.decode("utf-8", errors="replace").strip()
        if b in (0x7F, 0x08):
            if buf:
                buf = buf[:-1]
                if echo:
                    conn.sendall(b"\x08 \x08")
            continue
        if b < 0x20:
            continue
        buf += ch
        if echo:
            conn.sendall(ch)
        if len(buf) > 256:
            return buf.decode("utf-8", errors="replace").strip()
    return buf.decode("utf-8", errors="replace").strip() if buf else None


def _exec_one(sc, addr, port, service, cwd_box, _send):
    """Execute a single shell command. cwd_box is [cwd] for mutability."""
    sc = re.sub(r'\s*[12]?\s*>+\s*\S+', '', sc).strip()
    if '|' in sc:
        sc = sc.split('|')[0].strip()
    parts = sc.split()
    base = parts[0] if parts else ""
    if not base:
        return
    cwd = cwd_box[0]
    if base == "cd":
        target = parts[1] if len(parts) > 1 else "/root"
        if target == "..":
            cwd_box[0] = "/".join(cwd.rstrip("/").split("/")[:-1]) or "/"
        elif target == "~":
            cwd_box[0] = "/root"
        elif target.startswith("/"):
            if target.rstrip("/") in _DIRS or target.rstrip("/") == "":
                cwd_box[0] = target.rstrip("/") or "/"
        else:
            new = cwd.rstrip("/") + "/" + target.rstrip("/")
            if new in _DIRS:
                cwd_box[0] = new
    elif base == "pwd":
        _send((cwd + "\n").encode())
    elif base == "ls":
        target = cwd
        detailed = False
        show_all = False
        for p in parts[1:]:
            if p.startswith("-"):
                if "l" in p:
                    detailed = True
                if "a" in p:
                    show_all = True
            elif not p.startswith("-"):
                target = p if p.startswith("/") else cwd.rstrip("/") + "/" + p
        _send(_do_ls(target, detailed, show_all).encode())
    elif base == "cat":
        if len(parts) < 2:
            _send(b"cat: missing operand\n")
        else:
            fpath = parts[1] if parts[1].startswith("/") else cwd.rstrip("/") + "/" + parts[1]
            content = _FILES.get(fpath)
            if content:
                _send(content.encode())
            else:
                _send(f"cat: {parts[1]}: No such file or directory\n".encode())
    elif base in ("wget", "curl"):
        url = ""
        for p in parts[1:]:
            if p.startswith("http"):
                url = p
                break
        if not url and len(parts) > 1:
            url = parts[-1]
        if url and url.startswith("http"):
            _log_event(addr[0], port, service, f"malware-download: {url}")
            fname = url.split("/")[-1].split("?")[0] or "payload"
            _send(f"--{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}--  {url}\nResolving {url.split('/')[2]}... connecting...\nHTTP request sent, awaiting response... 200 OK\nLength: 14832 (14K) [application/octet-stream]\nSaving to: '{fname}'\n\n{fname}                100%[===================>]  14.48K  --.-KB/s    in 0.001s\n\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} (14.5 MB/s) - '{fname}' saved [14832/14832]\n".encode())
            threading.Thread(target=_download_malware, args=(addr[0], url), daemon=True).start()
        else:
            _send(f"{base}: missing URL\n".encode())
    elif base == "tftp":
        _log_event(addr[0], port, service, f"malware-download-tftp: {sc}")
        _send(b"Connected.\nGetting file... done.\n")
    elif base == "echo":
        rest = sc[5:] if len(sc) > 5 else ""
        _send((rest + "\n").encode())
    elif base in ("chmod", "chown", "mkdir", "touch", "cp", "mv", "rm", "killall", "kill", "pkill"):
        pass
    elif base.startswith("./") or base.startswith("/tmp/") or base.startswith("/var/tmp/"):
        _log_event(addr[0], port, service, f"malware-exec: {sc}")
    elif base == "history":
        _send(_FILES.get("/root/.bash_history", "").encode())
    elif base.startswith("/bin/busybox"):
        arg = sc.split(None, 1)[1] if " " in sc else ""
        if arg:
            _send(f"{arg}: applet not found\n".encode())
        else:
            _send(_BUSYBOX_FULL.encode())
    elif sc in _CMDS:
        _send(_CMDS[sc].encode())
    else:
        found = False
        for k, v in _CMDS.items():
            if base == k.split()[0]:
                _send(v.encode())
                found = True
                break
        if not found:
            _send(f"bash: {base}: command not found\n".encode())


def _fake_shell(conn, addr, service, port):
    global _active_sessions
    with _session_lock:
        _active_sessions += 1
    cwd_box = ["/root"]
    is_telnet = service == "Telnet"
    try:
        conn.settimeout(2)
        deadline = time.time() + 120
        def _send(text):
            if isinstance(text, str):
                text = text.encode()
            if is_telnet:
                text = text.replace(b"\n", b"\r\n")
            conn.sendall(text)
        def prompt():
            d = "~" if cwd_box[0] == "/root" else cwd_box[0]
            return f"root@web-prod-01:{d}# ".encode()
        conn.sendall(prompt())
        while time.time() < deadline and not _shutdown.is_set():
            cmd = _recv_line(conn, echo=is_telnet, timeout=min(30, deadline - time.time()))
            if cmd is None:
                break
            if not cmd:
                conn.sendall(prompt())
                continue
            _log_event(addr[0], port, service, f"cmd: {cmd}")
            subcmds = re.split(r'\s*(?:;|&&)\s*', cmd) if (';' in cmd or '&&' in cmd) else [cmd]
            should_break = False
            for sc in subcmds:
                sc = sc.strip()
                if not sc:
                    continue
                if sc.split()[0] in ("exit", "quit", "logout"):
                    _send(b"logout\n")
                    should_break = True
                    break
                _exec_one(sc, addr, port, service, cwd_box, _send)
            if should_break:
                break
            conn.sendall(prompt())
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
        conn.sendall(b"\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03")
        time.sleep(0.3)
        try:
            conn.recv(256)
        except socket.timeout:
            pass
        conn.sendall(b"Ubuntu 20.04.5 LTS\r\nlogin: ")
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
        cwd = "/"
        for _ in range(25):
            data = conn.recv(512)
            if not data:
                break
            line = data.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            parts = line.split()
            cmd = parts[0].upper()
            arg = line[len(parts[0]):].strip() if len(parts) > 1 else ""
            _log_event(addr[0], 21, "FTP", line)
            if cmd == "USER":
                user = arg
                conn.sendall(b"331 Password required for " + user.encode() + b"\r\n")
            elif cmd == "PASS":
                _log_event(addr[0], 21, "FTP", f"USER={user} PASS={arg}")
                conn.sendall(b"230 User " + user.encode() + b" logged in\r\n")
                logged_in = True
            elif cmd == "SYST":
                conn.sendall(b"215 UNIX Type: L8\r\n")
            elif cmd == "FEAT":
                conn.sendall(b"211-Features:\r\n MDTM\r\n PASV\r\n SIZE\r\n UTF8\r\n211 End\r\n")
            elif cmd == "TYPE":
                conn.sendall(b"200 Switching to Binary mode.\r\n")
            elif cmd == "PASV":
                conn.sendall(b"227 Entering Passive Mode (10,0,2,15,195,149).\r\n")
            elif cmd == "PWD" or cmd == "XPWD":
                conn.sendall(f'257 "{cwd}" is the current directory\r\n'.encode())
            elif cmd == "CWD" or cmd == "XCWD":
                target = arg if arg.startswith("/") else (cwd.rstrip("/") + "/" + arg).replace("//", "/")
                if target.rstrip("/") in _DIRS or target == "/":
                    cwd = target.rstrip("/") or "/"
                    conn.sendall(b"250 Directory successfully changed.\r\n")
                else:
                    conn.sendall(f"550 Failed to change directory: {arg}\r\n".encode())
            elif cmd == "CDUP" or cmd == "XCUP":
                cwd = "/".join(cwd.rstrip("/").split("/")[:-1]) or "/"
                conn.sendall(b"250 Directory successfully changed.\r\n")
            elif cmd in ("LIST", "NLST", "MLSD"):
                conn.sendall(b"150 Here comes the directory listing.\r\n")
                listing = _do_ls(cwd, detailed=(cmd == "LIST"))
                conn.sendall(listing.encode())
                conn.sendall(b"226 Directory send OK.\r\n")
            elif cmd == "SIZE":
                fpath = arg if arg.startswith("/") else cwd.rstrip("/") + "/" + arg
                content = _FILES.get(fpath)
                if content:
                    conn.sendall(f"213 {len(content)}\r\n".encode())
                else:
                    conn.sendall(b"550 Could not get file size.\r\n")
            elif cmd == "MDTM":
                conn.sendall(b"213 20240115083015\r\n")
            elif cmd == "RETR":
                fpath = arg if arg.startswith("/") else cwd.rstrip("/") + "/" + arg
                content = _FILES.get(fpath)
                _log_event(addr[0], 21, "FTP", f"RETR {fpath}")
                if content:
                    conn.sendall(b"150 Opening BINARY mode data connection.\r\n")
                    conn.sendall(content.encode() if isinstance(content, str) else content)
                    conn.sendall(b"226 Transfer complete.\r\n")
                else:
                    conn.sendall(b"550 File not found.\r\n")
            elif cmd == "STOR" or cmd == "APPE":
                _log_event(addr[0], 21, "FTP", f"UPLOAD {arg}")
                conn.sendall(b"150 Ok to send data.\r\n")
                try:
                    upload = conn.recv(4096)
                    _log_event(addr[0], 21, "FTP", f"upload-data: {len(upload) if upload else 0}B")
                except Exception:
                    pass
                conn.sendall(b"226 Transfer complete.\r\n")
            elif cmd == "MKD" or cmd == "XMKD":
                conn.sendall(f'257 "{arg}" created\r\n'.encode())
            elif cmd == "RMD" or cmd == "XRMD":
                conn.sendall(b"250 Remove directory operation successful.\r\n")
            elif cmd == "DELE":
                conn.sendall(b"250 Delete operation successful.\r\n")
            elif cmd == "RNFR":
                conn.sendall(b"350 Ready for RNTO.\r\n")
            elif cmd == "RNTO":
                conn.sendall(b"250 Rename successful.\r\n")
            elif cmd == "QUIT":
                conn.sendall(b"221 Goodbye.\r\n")
                break
            elif cmd == "NOOP":
                conn.sendall(b"200 NOOP ok.\r\n")
            else:
                conn.sendall(f"500 Unknown command: {cmd}\r\n".encode())
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
            elif cmd == "AUTH":
                auth_type = line.split(None, 1)[1].upper() if len(line.split()) > 1 else ""
                if "PLAIN" in auth_type:
                    cred_data = auth_type.split()[-1] if len(auth_type.split()) > 1 else ""
                    if not cred_data:
                        conn.sendall(b"334 \r\n")
                        cred_raw = conn.recv(256)
                        cred_data = cred_raw.decode("utf-8", errors="replace").strip() if cred_raw else ""
                    try:
                        import base64
                        decoded = base64.b64decode(cred_data).decode("utf-8", errors="replace")
                        parts_auth = decoded.split("\x00")
                        user_smtp = parts_auth[1] if len(parts_auth) > 1 else ""
                        pass_smtp = parts_auth[2] if len(parts_auth) > 2 else ""
                        _log_event(addr[0], 25, "SMTP", f"AUTH PLAIN USER={user_smtp} PASS={pass_smtp}")
                    except Exception:
                        _log_event(addr[0], 25, "SMTP", f"AUTH PLAIN raw={cred_data}")
                    conn.sendall(b"535 5.7.8 Authentication credentials invalid\r\n")
                elif "LOGIN" in auth_type:
                    conn.sendall(b"334 VXNlcm5hbWU6\r\n")
                    u_raw = conn.recv(256)
                    try:
                        import base64
                        user_smtp = base64.b64decode(u_raw.strip()).decode() if u_raw else ""
                    except Exception:
                        user_smtp = u_raw.decode("utf-8", errors="replace").strip() if u_raw else ""
                    conn.sendall(b"334 UGFzc3dvcmQ6\r\n")
                    p_raw = conn.recv(256)
                    try:
                        pass_smtp = base64.b64decode(p_raw.strip()).decode() if p_raw else ""
                    except Exception:
                        pass_smtp = p_raw.decode("utf-8", errors="replace").strip() if p_raw else ""
                    _log_event(addr[0], 25, "SMTP", f"AUTH LOGIN USER={user_smtp} PASS={pass_smtp}")
                    conn.sendall(b"535 5.7.8 Authentication credentials invalid\r\n")
                else:
                    _log_event(addr[0], 25, "SMTP", f"AUTH {auth_type}")
                    conn.sendall(b"504 Unrecognized authentication type\r\n")
            elif cmd == "STARTTLS":
                conn.sendall(b"220 Ready to start TLS\r\n")
                _log_event(addr[0], 25, "SMTP", "STARTTLS")
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


_MYSQL_RESULTS = {
    "show databases": "+----------+\n| Database |\n+----------+\n| prod_app |\n| mysql |\n| information_schema |\n| performance_schema |\n| test |\n+----------+\n5 rows in set (0.00 sec)\n",
    "show tables": "+-------------------+\n| Tables_in_prod_app |\n+-------------------+\n| users |\n| sessions |\n| orders |\n| products |\n| logs |\n| config |\n+-------------------+\n6 rows in set (0.00 sec)\n",
    "select * from users": "+----+---------------------+--------------------------------------------------------------+-------+---------------------+\n| id | email               | password_hash                                                | role  | created_at          |\n+----+---------------------+--------------------------------------------------------------+-------+---------------------+\n|  1 | admin@example.com   | $2b$12$LJ3m4ys12K9Xqz8ZfVhOJeKYGHzS8Wq1vN3kP5mT7uR6xA4dC9y | admin | 2023-06-15 09:30:00 |\n|  2 | john@example.com    | $2b$12$aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5aB6cD7eF8gH9 | user  | 2023-07-20 14:22:00 |\n|  3 | jane@example.com    | $2b$12$9Nk8Ml7Lj6Kh5Ig4Hf3Ge2Fd1Ec0Db9Ca8Bz7Ay6xw5Vt4Us3Rq | user  | 2023-08-01 11:00:00 |\n|  4 | deploy@internal.net | $2b$12$pQ0rS1tU2vW3xY4zA5bC6dE7fG8hI9jK0lM1nO2pQ3rS4tU5vW6x | admin | 2023-03-10 08:00:00 |\n|  5 | test@test.com       | $2b$12$tEsTpAsSwOrDhAsH000000000000000000000000000000000000000 | user  | 2024-01-10 16:45:00 |\n+----+---------------------+--------------------------------------------------------------+-------+---------------------+\n5 rows in set (0.01 sec)\n",
    "select * from config": "+----+-------------------+-------------------------------------------+\n| id | key               | value                                     |\n+----+-------------------+-------------------------------------------+\n|  1 | api_key           | sk_live_FAKE_HONEYPOT_KEY_0x4eC39            |\n|  2 | aws_secret        | wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY   |\n|  3 | jwt_secret        | super_secret_jwt_key_2024                   |\n|  4 | smtp_password     | Pr0d_M@il_2024!                             |\n|  5 | encryption_key    | aes-256-cbc-base64encoded-key-here          |\n+----+-------------------+-------------------------------------------+\n5 rows in set (0.00 sec)\n",
    "describe users": "+---------------+--------------+------+-----+---------+----------------+\n| Field         | Type         | Null | Key | Default | Extra          |\n+---------------+--------------+------+-----+---------+----------------+\n| id            | int(11)      | NO   | PRI | NULL    | auto_increment |\n| email         | varchar(255) | NO   | UNI | NULL    |                |\n| password_hash | varchar(255) | NO   |     | NULL    |                |\n| role          | varchar(20)  | YES  |     | user    |                |\n| created_at    | datetime     | YES  |     | NULL    |                |\n+---------------+--------------+------+-----+---------+----------------+\n5 rows in set (0.00 sec)\n",
    "select user()": "+----------------+\n| user()         |\n+----------------+\n| root@localhost |\n+----------------+\n1 row in set (0.00 sec)\n",
    "select version()": "+-------------------------+\n| version()               |\n+-------------------------+\n| 5.7.33-0ubuntu0.20.04.1 |\n+-------------------------+\n1 row in set (0.00 sec)\n",
    "select @@hostname": "+-------------+\n| @@hostname  |\n+-------------+\n| web-prod-01 |\n+-------------+\n1 row in set (0.00 sec)\n",
    "select database()": "+-----------+\n| database()|\n+-----------+\n| prod_app  |\n+-----------+\n1 row in set (0.00 sec)\n",
}


def _handle_mysql(conn, addr):
    try:
        conn.settimeout(10)
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
        # Send OK packet to accept auth
        conn.sendall(b"\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00")
        # Query loop
        seq = 0
        for _ in range(30):
            try:
                pkt = conn.recv(2048)
            except socket.timeout:
                continue
            if not pkt or len(pkt) < 5:
                break
            cmd_byte = pkt[4] if len(pkt) > 4 else 0
            if cmd_byte == 0x01:  # COM_QUIT
                break
            if cmd_byte != 0x03:  # not COM_QUERY
                conn.sendall(b"\x07\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00")
                continue
            query = pkt[5:].decode("utf-8", errors="replace").strip().rstrip(";")
            _log_event(addr[0], 3306, "MySQL", f"query: {query}")
            ql = query.lower().strip()
            seq += 1
            # Check for destructive queries
            if any(w in ql for w in ("insert ", "update ", "delete ", "drop ", "alter ", "truncate ", "create ")):
                _log_event(addr[0], 3306, "MySQL", f"DESTRUCTIVE: {query}")
                conn.sendall(b"\x07\x00\x00\x01\x00\x01\x00\x02\x00\x00\x00")
                continue
            # Look up result
            result = None
            for key, val in _MYSQL_RESULTS.items():
                if ql.startswith(key) or ql == key:
                    result = val
                    break
            if ql.startswith("show variables"):
                result = "+---------------+--------------------+\n| Variable_name | Value              |\n+---------------+--------------------+\n| hostname      | web-prod-01        |\n| port          | 3306               |\n| version       | 5.7.33             |\n| datadir       | /var/lib/mysql/    |\n| max_connections| 151               |\n+---------------+--------------------+\n5 rows in set (0.00 sec)\n"
            if result:
                # Send as a text result (raw bytes, not proper wire protocol)
                payload = result.encode()
                # Minimal result set: column count + rows + EOF — too complex, just send raw text
                conn.sendall(b"\x01\x00\x00\x01\x01")  # 1 column
                conn.sendall(b"\x20\x00\x00\x02\x03def\x00\x00\x00\x06result\x00\x0c\x21\x00\xff\x00\x00\x00\xfd\x01\x00\x1f\x00\x00")
                conn.sendall(b"\x05\x00\x00\x03\xfe\x00\x00\x02\x00")  # EOF
                chunk = payload[:250]
                plen = len(chunk) + 1
                conn.sendall(bytes([plen & 0xff, (plen >> 8) & 0xff, 0, 4, len(chunk)]) + chunk)
                conn.sendall(b"\x05\x00\x00\x05\xfe\x00\x00\x02\x00")  # EOF
            else:
                # Error response
                err = f"ERROR 1064 (42000): You have an error in your SQL syntax near '{query[:30]}'"
                conn.sendall(b"\x07\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00")
    except Exception:
        pass
    finally:
        conn.close()


_REDIS_KEYS = {
    "session:a1b2c3": '{"user_id":1,"email":"admin@example.com","role":"admin","token":"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ"}',
    "session:d4e5f6": '{"user_id":2,"email":"john@example.com","role":"user","token":"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiam9obiJ9"}',
    "user:1": '{"id":1,"email":"admin@example.com","name":"Admin User","role":"admin","api_key":"sk_live_FAKE_HONEYPOT_KEY_0x4eC39"}',
    "user:2": '{"id":2,"email":"john@example.com","name":"John Doe","role":"user"}',
    "config:api_key": "sk_live_FAKE_HONEYPOT_KEY_0x4eC39",
    "config:jwt_secret": "super_secret_jwt_key_2024",
    "config:db_password": "Pr0d_DB_P@ss!2024",
    "cache:homepage": "<html><body>cached homepage content</body></html>",
    "queue:emails": '["admin@example.com","john@example.com"]',
}

_REDIS_INFO = "$512\r\n# Server\r\nredis_version:6.2.6\r\nredis_mode:standalone\r\nos:Linux 5.10.0-20-amd64 x86_64\r\ntcp_port:6379\r\nuptime_in_seconds:12345678\r\nuptime_in_days:142\r\nconfig_file:/etc/redis/redis.conf\r\n\r\n# Clients\r\nconnected_clients:3\r\nblocked_clients:0\r\n\r\n# Memory\r\nused_memory:1048576\r\nused_memory_human:1.00M\r\nused_memory_peak:2097152\r\nmaxmemory:268435456\r\n\r\n# Keyspace\r\ndb0:keys=42,expires=5,avg_ttl=86400000\r\n\r\n"


def _redis_parse_cmd(data):
    """Parse RESP or plain-text Redis command. Returns list of args."""
    text = data.decode("utf-8", errors="replace").strip()
    if text.startswith("*"):
        lines = text.split("\r\n")
        args = []
        i = 1
        while i < len(lines):
            if lines[i].startswith("$"):
                if i + 1 < len(lines):
                    args.append(lines[i + 1])
                    i += 2
                else:
                    i += 1
            else:
                args.append(lines[i])
                i += 1
        return args
    return text.split()


def _handle_redis(conn, addr):
    try:
        conn.settimeout(15)
        for _ in range(30):
            data = conn.recv(1024)
            if not data:
                break
            args = _redis_parse_cmd(data)
            if not args:
                continue
            cmd = args[0].upper()
            raw = " ".join(args)
            _log_event(addr[0], 6379, "Redis", raw)
            if cmd == "PING":
                conn.sendall(b"+PONG\r\n")
            elif cmd == "AUTH":
                pw = args[1] if len(args) > 1 else ""
                _log_event(addr[0], 6379, "Redis", f"AUTH={pw}")
                conn.sendall(b"-ERR invalid password\r\n")
            elif cmd == "INFO":
                conn.sendall(_REDIS_INFO.encode())
            elif cmd == "DBSIZE":
                conn.sendall(b":42\r\n")
            elif cmd == "SELECT":
                conn.sendall(b"+OK\r\n")
            elif cmd == "KEYS":
                keys = list(_REDIS_KEYS.keys())
                resp = f"*{len(keys)}\r\n"
                for k in keys:
                    resp += f"${len(k)}\r\n{k}\r\n"
                conn.sendall(resp.encode())
            elif cmd == "GET":
                key = args[1] if len(args) > 1 else ""
                val = _REDIS_KEYS.get(key)
                if val:
                    conn.sendall(f"${len(val)}\r\n{val}\r\n".encode())
                else:
                    conn.sendall(b"$-1\r\n")
            elif cmd == "SET":
                key = args[1] if len(args) > 1 else ""
                val = args[2] if len(args) > 2 else ""
                _log_event(addr[0], 6379, "Redis", f"SET {key}={val[:100]}")
                conn.sendall(b"+OK\r\n")
            elif cmd == "DEL":
                conn.sendall(b":1\r\n")
            elif cmd == "CONFIG":
                sub = args[1].upper() if len(args) > 1 else ""
                if sub == "GET":
                    conn.sendall(b"*4\r\n$10\r\nrequirepass\r\n$0\r\n\r\n$4\r\nbind\r\n$7\r\n0.0.0.0\r\n")
                elif sub == "SET":
                    param = args[2] if len(args) > 2 else ""
                    val = args[3] if len(args) > 3 else ""
                    _log_event(addr[0], 6379, "Redis", f"CONFIG SET {param}={val} [ATTACK]")
                    conn.sendall(b"+OK\r\n")
                else:
                    conn.sendall(b"+OK\r\n")
            elif cmd in ("FLUSHALL", "FLUSHDB"):
                _log_event(addr[0], 6379, "Redis", f"{cmd} [CRITICAL]")
                conn.sendall(b"+OK\r\n")
            elif cmd in ("SAVE", "BGSAVE"):
                conn.sendall(b"+OK\r\nBackground saving started\r\n")
            elif cmd == "SLAVEOF" or cmd == "REPLICAOF":
                host = args[1] if len(args) > 1 else ""
                port = args[2] if len(args) > 2 else ""
                _log_event(addr[0], 6379, "Redis", f"SLAVEOF {host}:{port} [ATTACK-REPLICATION]")
                conn.sendall(b"+OK\r\n")
            elif cmd == "MODULE":
                _log_event(addr[0], 6379, "Redis", f"MODULE {' '.join(args[1:])} [ATTACK-RCE]")
                conn.sendall(b"-ERR module loading disabled\r\n")
            elif cmd == "EVAL":
                _log_event(addr[0], 6379, "Redis", f"EVAL {' '.join(args[1:3])} [ATTACK-LUA]")
                conn.sendall(b"-ERR scripting disabled\r\n")
            elif cmd == "QUIT":
                conn.sendall(b"+OK\r\n")
                break
            else:
                conn.sendall(f"-ERR unknown command '{cmd}'\r\n".encode())
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


def _handle_pop3(conn, addr):
    try:
        conn.settimeout(15)
        conn.sendall(b"+OK Dovecot (Ubuntu) ready.\r\n")
        user = ""
        for _ in range(10):
            data = conn.recv(256)
            if not data:
                break
            line = data.decode("utf-8", errors="replace").strip()
            cmd = line.split()[0].upper() if line else ""
            _log_event(addr[0], 110, "POP3", line)
            if cmd == "USER":
                user = line[5:].strip()
                conn.sendall(b"+OK\r\n")
            elif cmd == "PASS":
                pw = line[5:].strip()
                _log_event(addr[0], 110, "POP3", f"USER={user} PASS={pw}")
                conn.sendall(b"-ERR [AUTH] Authentication failed.\r\n")
            elif cmd == "CAPA":
                conn.sendall(b"+OK\r\nUSER\r\nTOP\r\nUIDL\r\nRESP-CODES\r\nAUTH-RESP-CODE\r\nSTLS\r\n.\r\n")
            elif cmd == "QUIT":
                conn.sendall(b"+OK Logging out.\r\n")
                break
            elif cmd == "STAT":
                conn.sendall(b"+OK 5 12480\r\n")
            elif cmd == "LIST":
                conn.sendall(b"+OK 5 messages:\r\n1 2560\r\n2 1840\r\n3 4200\r\n4 1920\r\n5 1960\r\n.\r\n")
            else:
                conn.sendall(b"-ERR Unknown command.\r\n")
    except Exception:
        pass
    finally:
        conn.close()


def _handle_imap(conn, addr):
    try:
        conn.settimeout(15)
        conn.sendall(b"* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE STARTTLS AUTH=PLAIN] Dovecot (Ubuntu) ready.\r\n")
        for _ in range(10):
            data = conn.recv(512)
            if not data:
                break
            line = data.decode("utf-8", errors="replace").strip()
            _log_event(addr[0], 143, "IMAP", line)
            parts = line.split()
            if len(parts) < 2:
                conn.sendall(b"* BAD Error in IMAP command received\r\n")
                continue
            tag = parts[0]
            cmd = parts[1].upper()
            if cmd == "LOGIN":
                user = parts[2] if len(parts) > 2 else ""
                pw = parts[3] if len(parts) > 3 else ""
                user = user.strip('"')
                pw = pw.strip('"')
                _log_event(addr[0], 143, "IMAP", f"USER={user} PASS={pw}")
                conn.sendall(f"{tag} NO [AUTHENTICATIONFAILED] Authentication failed.\r\n".encode())
            elif cmd == "CAPABILITY":
                conn.sendall(f"* CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS AUTH=PLAIN\r\n{tag} OK Capability completed.\r\n".encode())
            elif cmd == "LOGOUT":
                conn.sendall(f"* BYE Logging out\r\n{tag} OK Logout completed.\r\n".encode())
                break
            elif cmd == "NOOP":
                conn.sendall(f"{tag} OK NOOP completed.\r\n".encode())
            elif cmd == "LIST":
                conn.sendall(f'* LIST (\\HasNoChildren) "." "INBOX"\r\n* LIST (\\HasNoChildren) "." "Sent"\r\n* LIST (\\HasNoChildren) "." "Drafts"\r\n* LIST (\\HasNoChildren \\Trash) "." "Trash"\r\n{tag} OK List completed.\r\n'.encode())
            else:
                conn.sendall(f"{tag} BAD Error in IMAP command.\r\n".encode())
    except Exception:
        pass
    finally:
        conn.close()


def _handle_vnc(conn, addr):
    try:
        conn.settimeout(10)
        conn.sendall(b"RFB 003.008\n")
        data = conn.recv(12)
        ver = data.decode("utf-8", errors="replace").strip() if data else ""
        _log_event(addr[0], 5900, "VNC", f"client_version: {ver}")
        conn.sendall(b"\x01\x02")
        data2 = conn.recv(64)
        if data2:
            auth_type = data2[0] if data2 else 0
            _log_event(addr[0], 5900, "VNC", f"auth_type: {auth_type}")
            if auth_type == 2:
                import secrets as _sec
                challenge = _sec.token_bytes(16)
                conn.sendall(challenge)
                response = conn.recv(16)
                if response:
                    _log_event(addr[0], 5900, "VNC", f"auth_response: {response.hex()}")
                conn.sendall(b"\x00\x00\x00\x01")
            else:
                conn.sendall(b"\x00\x00\x00\x01")
    except Exception:
        _log_event(addr[0], 5900, "VNC", "connect")
    finally:
        conn.close()


def _handle_rdp(conn, addr):
    try:
        conn.settimeout(5)
        data = conn.recv(512)
        _log_event(addr[0], 3389, "RDP", f"connect ({len(data) if data else 0} bytes)")
        conn.sendall(b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x01\x08\x00\x02\x00\x00\x00")
        data2 = conn.recv(512)
        if data2:
            _log_event(addr[0], 3389, "RDP", f"negotiation ({len(data2)} bytes)")
    except Exception:
        _log_event(addr[0], 3389, "RDP", "connect")
    finally:
        conn.close()


def _handle_smb(conn, addr):
    try:
        conn.settimeout(5)
        data = conn.recv(512)
        _log_event(addr[0], 445, "SMB", f"negotiate ({len(data) if data else 0} bytes)")
        smb_resp = (b"\x00\x00\x00\x55"
                    b"\xff\x53\x4d\x42\x72"
                    b"\x00\x00\x00\x00\x98\x01\x28"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\xff\xfe"
                    b"\x00\x00\x00\x00\x11\x00\x00\x03"
                    b"\x10\x00\x01\x00\x04\x11\x00\x00"
                    b"\x00\x00\x01\x00\x00\x00\x00\x00"
                    b"\xfd\xe3\x00\x80"
                    b"\x4e\x54\x20\x4c\x41\x4e\x4d\x41"
                    b"\x4e\x20\x31\x2e\x30\x00")
        conn.sendall(smb_resp)
        data2 = conn.recv(512)
        if data2 and len(data2) > 60:
            try:
                user = data2[60:].split(b"\x00\x00")[0].decode("utf-16-le", errors="replace")
                if user:
                    _log_event(addr[0], 445, "SMB", f"session_setup user={user}")
            except Exception:
                _log_event(addr[0], 445, "SMB", f"session_setup ({len(data2)} bytes)")
    except Exception:
        _log_event(addr[0], 445, "SMB", "connect")
    finally:
        conn.close()


def _handle_mongodb(conn, addr):
    try:
        conn.settimeout(5)
        data = conn.recv(512)
        _log_event(addr[0], 27017, "MongoDB", f"connect ({len(data) if data else 0} bytes)")
        reply = (b"\x48\x00\x00\x00"
                 b"\x01\x00\x00\x00"
                 b"\x00\x00\x00\x00"
                 b"\x01\x00\x00\x00"
                 b"\x08\x00\x00\x00"
                 b"\x00\x00\x00\x00"
                 b"\x00\x00\x00\x00"
                 b"\x00\x00\x00\x00"
                 b"\x01\x00\x00\x00")
        ismaster = b'{"ismaster": true, "maxBsonObjectSize": 16777216, "maxMessageSizeBytes": 48000000, "maxWriteBatchSize": 100000, "localTime": "2024-01-15T08:30:00Z", "maxWireVersion": 6, "minWireVersion": 0, "ok": 1.0}'
        conn.sendall(reply + ismaster)
        data2 = conn.recv(1024)
        if data2:
            _log_event(addr[0], 27017, "MongoDB", f"query ({len(data2)} bytes)")
    except Exception:
        _log_event(addr[0], 27017, "MongoDB", "connect")
    finally:
        conn.close()


def _handle_generic(conn, addr, port, service):
    try:
        conn.settimeout(5)
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
    110: lambda c, a: _handle_pop3(c, a),
    143: lambda c, a: _handle_imap(c, a),
    445: lambda c, a: _handle_smb(c, a),
    3306: lambda c, a: _handle_mysql(c, a),
    3389: lambda c, a: _handle_rdp(c, a),
    5900: lambda c, a: _handle_vnc(c, a),
    6379: lambda c, a: _handle_redis(c, a),
    8080: lambda c, a: _handle_http(c, a, 8080),
    8443: lambda c, a: _handle_http(c, a, 8443),
    9200: lambda c, a: _handle_elastic(c, a),
    2375: lambda c, a: _handle_docker(c, a),
    27017: lambda c, a: _handle_mongodb(c, a),
}


def _connection_handler(conn, addr, port, service):
    handler = _HANDLERS.get(port)
    if handler:
        handler(conn, addr)
    else:
        _handle_generic(conn, addr, port, service)


_conn_counts = Counter()
_conn_lock = threading.Lock()
_MAX_CONNS_PER_IP = 20
_MAX_TOTAL_THREADS = 200


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
            with _conn_lock:
                global _total_connections
                if _conn_counts[addr[0]] >= _MAX_CONNS_PER_IP:
                    conn.close()
                    continue
                if sum(_conn_counts.values()) >= _MAX_TOTAL_THREADS:
                    conn.close()
                    continue
                _conn_counts[addr[0]] += 1
                _total_connections += 1

            def _wrapped_handler(c, a, p, s):
                try:
                    _connection_handler(c, a, p, s)
                finally:
                    with _conn_lock:
                        _conn_counts[a[0]] = max(0, _conn_counts[a[0]] - 1)

            threading.Thread(target=_wrapped_handler, args=(conn, addr, port, service), daemon=True).start()
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
    _save_counter = 0
    while not _shutdown.is_set():
        _save_counter += 1
        if _save_counter % 30 == 0:
            _save_session()
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
                "malware_captures": list(_malware_captures[-10:]),
                "total_connections": _total_connections,
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

    def start_hp(resume=False):
        nonlocal running
        global _start_time
        _shutdown.clear()
        _start_time = time.time()
        _init_new_session()
        if resume:
            _restore_session()
        for port, svc in SERVICES:
            threading.Thread(target=_service_listener, args=(port, svc), daemon=True).start()
        threading.Thread(target=_write_live_stats, daemon=True).start()
        running = True

    has_prev = os.path.isfile(SESSION_FILE)
    if auto_mode:
        start_hp(resume=has_prev)
        status = f"Resumed ({len(_events)} events)" if has_prev else "Active"
    elif has_prev and not auto_mode:
        # Show resume prompt on LCD
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.rectangle((0, 0, 127, 14), fill="#111")
        d.text((2, 2), "HONEYPOT SIEM", font=font_sm, fill="#FF4444")
        d.text((4, 22), "Previous session", font=font_sm, fill="#FFAA00")
        d.text((4, 34), "found. Resume?", font=font_sm, fill="#FFAA00")
        d.text((4, 55), "OK = Resume", font=font, fill="#00FF00")
        d.text((4, 72), "KEY1 = New session", font=font_sm, fill="#00CCFF")
        d.text((4, 89), "KEY3 = Exit", font=font_sm, fill="#888")
        lcd.LCD_ShowImage(img, 0, 0)
        while True:
            btn = _btn()
            if btn == "OK":
                start_hp(resume=True)
                status = f"Resumed ({len(_events)} events)"
                break
            elif btn == "KEY1":
                start_hp(resume=False)
                status = "New session"
                break
            elif btn == "KEY3":
                GPIO.cleanup()
                return 0
            time.sleep(0.03)

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
        _save_session()
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
