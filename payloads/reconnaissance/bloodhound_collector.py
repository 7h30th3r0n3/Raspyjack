#!/usr/bin/env python3
"""
RaspyJack Payload -- BloodHound Collector
Collects AD data in BloodHound-compatible JSON format.
Primary: bloodhound-python (pip).  Fallback: ldapsearch + manual JSON.
Controls: OK=start, KEY1=toggle method, KEY3=exit
"""
import os, sys, time, json, re, socket, subprocess, threading, zipfile
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

# -- Constants ---------------------------------------------------------------
LOOT_BASE = "/root/Raspyjack/loot/BloodHound"
CREDS_PATH = "/root/Raspyjack/config/bloodhound/creds.json"
CONFIG_DIR = os.path.dirname(CREDS_PATH)
LDAP_PORT = 389
DEBOUNCE = 0.22
LDAP_USER_ATTRS = ["sAMAccountName", "objectSid", "memberOf", "adminCount",
                   "userAccountControl", "servicePrincipalName",
                   "lastLogon", "pwdLastSet"]
LDAP_GROUP_ATTRS = ["cn", "objectSid", "member"]
LDAP_COMPUTER_ATTRS = ["cn", "objectSid", "operatingSystem",
                       "dNSHostName", "userAccountControl"]
LDAP_DOMAIN_ATTRS = ["objectSid", "ms-DS-MachineAccountQuota"]

# -- Thread-safe state -------------------------------------------------------
_lock = threading.Lock()
_state = {
    "method": "bloodhound-python", "dc_ip": "", "domain": "",
    "username": "", "password": "", "base_dn": "",
    "status": "Idle", "phase": "", "running": False, "stop": False,
    "stats": {"users": 0, "groups": 0, "computers": 0, "gpos": 0},
    "output_dir": "",
}

def _get(key):
    with _lock:
        val = _state[key]
        return dict(val) if isinstance(val, dict) else (
            list(val) if isinstance(val, list) else val)

def _set(**kw):
    with _lock:
        _state.update(kw)

# -- Credentials -------------------------------------------------------------
def _load_creds():
    if not os.path.isfile(CREDS_PATH):
        return False
    try:
        with open(CREDS_PATH, "r") as f:
            c = json.load(f)
        if c.get("username") and c.get("domain"):
            _set(username=c["username"], password=c.get("password", ""),
                 domain=c["domain"], dc_ip=c.get("dc_ip", ""))
            return True
    except (json.JSONDecodeError, OSError):
        pass
    return False

# -- DC auto-detection (port 389 scan) --------------------------------------
def _detect_dc():
    _set(status="Detecting DC...", phase="scan")
    try:
        out = subprocess.run(["arp", "-an"],
                             capture_output=True, text=True, timeout=5)
        for line in out.stdout.splitlines():
            if _get("stop"):
                return ""
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
            if not m:
                continue
            ip = m.group(1)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.8)
            try:
                if s.connect_ex((ip, LDAP_PORT)) == 0:
                    return ip
            except OSError:
                pass
            finally:
                s.close()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return ""

def _resolve_base_dn(domain):
    return ",".join(f"DC={p}" for p in domain.split("."))

# -- Tool detection ----------------------------------------------------------
def _has_tool(name):
    try:
        subprocess.run([name, "--help"], capture_output=True, timeout=5)
        return True
    except FileNotFoundError:
        return False
    except Exception:
        return True

# -- Primary: bloodhound-python ----------------------------------------------
def _run_bloodhound_python(out_dir):
    _set(phase="bloodhound-python", status="Running bloodhound-python...")
    cmd = ["bloodhound-python",
           "-u", _get("username"), "-p", _get("password"),
           "-d", _get("domain"), "-c", "All",
           "-ns", _get("dc_ip"), "--zip",
           "--output-prefix", "raspyjack"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=300, cwd=out_dir)
        if proc.returncode != 0:
            _set(status="bh-python error")
            return False
        # Check for zip output
        if any(f.endswith(".zip") for f in os.listdir(out_dir)):
            _set(status="Collection complete!")
            return True
        # Zip loose JSON files if present
        jfiles = [f for f in os.listdir(out_dir) if f.endswith(".json")]
        if jfiles:
            zp = os.path.join(out_dir, "bloodhound_data.zip")
            with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as zf:
                for jf in jfiles:
                    zf.write(os.path.join(out_dir, jf), jf)
            _set(status="Collection complete!")
            return True
        _set(status="No output generated")
        return False
    except subprocess.TimeoutExpired:
        _set(status="Timeout (5min)")
        return False
    except OSError as exc:
        _set(status=f"Error: {str(exc)[:16]}")
        return False

# -- Fallback: ldapsearch + BloodHound CE JSON -------------------------------
def _ldapsearch(server, base_dn, filt, attrs, scope="sub"):
    cmd = ["ldapsearch", "-x", "-H", f"ldap://{server}",
           "-b", base_dn, "-s", scope, filt] + attrs
    try:
        return subprocess.run(cmd, capture_output=True,
                              text=True, timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""

def _parse_ldap_entries(text):
    entries, cur = [], {}
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            if cur: entries.append(cur); cur = {}
            continue
        if line.startswith(" ") and cur:
            lk = list(cur.keys())[-1] if cur else None
            if lk:
                p = cur[lk]
                if isinstance(p, list): p[-1] += line.strip()
                else: cur[lk] = p + line.strip()
            continue
        if ":" not in line: continue
        key, _, val = line.partition(":")
        key, val = key.strip(), val.strip()
        if key == "dn":
            if cur: entries.append(cur)
            cur = {"dn": val}
        elif key in cur:
            ex = cur[key]
            cur[key] = (ex + [val]) if isinstance(ex, list) else [ex, val]
        else: cur[key] = val
    if cur: entries.append(cur)
    return entries

def _ensure_list(val):
    if val is None:
        return []
    return val if isinstance(val, list) else [val]

def _bh_meta(obj_type, count):
    return {"methods": 0, "type": obj_type, "version": 6, "count": count}

def _build_users_json(entries, domain):
    data = []
    dom = domain.upper()
    for e in entries:
        sam = e.get("sAMAccountName", "")
        if not sam: continue
        uac = int(e.get("userAccountControl", "512") or "512")
        data.append({"Properties": {
            "name": f"{sam}@{domain}".upper(), "domain": dom,
            "samaccountname": sam, "objectsid": e.get("objectSid", ""),
            "admincount": e.get("adminCount", "0") == "1",
            "enabled": not bool(uac & 0x2),
            "lastlogon": e.get("lastLogon", "0"),
            "pwdlastset": e.get("pwdLastSet", "0"),
            "serviceprincipalnames": _ensure_list(e.get("servicePrincipalName")),
            "hasspn": bool(e.get("servicePrincipalName"))},
            "MemberOf": _ensure_list(e.get("memberOf")),
            "ObjectIdentifier": e.get("objectSid", "")})
    return {"meta": _bh_meta("users", len(data)), "data": data}

def _build_groups_json(entries, domain):
    dom = domain.upper()
    data = [{"Properties": {"name": f"{e['cn']}@{domain}".upper(),
                            "domain": dom, "objectsid": e.get("objectSid", "")},
             "Members": [{"MemberId": m, "MemberType": "Base"}
                         for m in _ensure_list(e.get("member"))],
             "ObjectIdentifier": e.get("objectSid", "")}
            for e in entries if e.get("cn")]
    return {"meta": _bh_meta("groups", len(data)), "data": data}

def _build_computers_json(entries, domain):
    dom = domain.upper()
    data = []
    for e in entries:
        cn = e.get("cn", "")
        if not cn: continue
        uac = int(e.get("userAccountControl", "4096") or "4096")
        data.append({"Properties": {
            "name": f"{cn}.{domain}".upper(), "domain": dom,
            "objectsid": e.get("objectSid", ""),
            "operatingsystem": e.get("operatingSystem", ""),
            "enabled": not bool(uac & 0x2)},
            "ObjectIdentifier": e.get("objectSid", "")})
    return {"meta": _bh_meta("computers", len(data)), "data": data}

def _build_domains_json(entries, domain):
    dom = domain.upper()
    data = [{"Properties": {"name": dom, "domain": dom,
             "objectsid": e.get("objectSid", ""),
             "machineaccountquota": int(
                 e.get("ms-DS-MachineAccountQuota", "10") or "10")},
             "ObjectIdentifier": e.get("objectSid", "")}
            for e in entries]
    return {"meta": _bh_meta("domains", len(data)), "data": data}

def _collect_phase(label, dc, bdn, filt, attrs, builder, domain,
                   stats, stat_key, scope="sub"):
    """Run one ldapsearch phase and return built JSON (or None if stopped)."""
    _set(phase=f"{label}...", status=f"Collecting {label.lower()}...")
    raw = _ldapsearch(dc, bdn, filt, attrs, scope)
    result = builder(_parse_ldap_entries(raw), domain)
    if stat_key:
        stats[stat_key] = result["meta"]["count"]
        _set(stats=dict(stats))
    return None if _get("stop") else result

def _run_ldapsearch_fallback(out_dir):
    dc, domain = _get("dc_ip"), _get("domain")
    bdn = _resolve_base_dn(domain)
    stats = {"users": 0, "groups": 0, "computers": 0, "gpos": 0}

    users_j = _collect_phase("Users", dc, bdn,
        "(&(objectClass=user)(sAMAccountName=*))",
        LDAP_USER_ATTRS, _build_users_json, domain, stats, "users")
    if users_j is None: return False
    groups_j = _collect_phase("Groups", dc, bdn,
        "(objectClass=group)", LDAP_GROUP_ATTRS,
        _build_groups_json, domain, stats, "groups")
    if groups_j is None: return False
    comps_j = _collect_phase("Computers", dc, bdn,
        "(objectClass=computer)", LDAP_COMPUTER_ATTRS,
        _build_computers_json, domain, stats, "computers")
    if comps_j is None: return False
    doms_j = _collect_phase("Domains", dc, bdn,
        "(objectClass=domain)", LDAP_DOMAIN_ATTRS,
        _build_domains_json, domain, stats, None, scope="base")
    if doms_j is None: return False

    # GPOs
    _set(phase="GPOs...", status="Collecting GPOs...")
    raw = _ldapsearch(dc, bdn, "(objectClass=groupPolicyContainer)",
                      ["displayName", "objectSid", "gPCFileSysPath"])
    stats["gpos"] = len(_parse_ldap_entries(raw))
    _set(stats=dict(stats))
    if _get("stop"): return False

    # OUs
    _set(phase="OUs...", status="Collecting OUs...")
    _ldapsearch(dc, bdn, "(objectClass=organizationalUnit)", ["ou", "objectSid"])

    # Write JSON + zip
    _set(phase="Writing...", status="Saving JSON files...")
    fmap = {"users.json": users_j, "groups.json": groups_j,
            "computers.json": comps_j, "domains.json": doms_j}
    for fn, content in fmap.items():
        with open(os.path.join(out_dir, fn), "w") as f:
            json.dump(content, f, indent=2)
    with zipfile.ZipFile(os.path.join(out_dir, "bloodhound_data.zip"),
                         "w", zipfile.ZIP_DEFLATED) as zf:
        for fn in fmap:
            zf.write(os.path.join(out_dir, fn), fn)
    _set(status="Collection complete!")
    return True

# -- Collection orchestrator -------------------------------------------------
def _do_collect():
    _set(running=True, stop=False, status="Starting...")
    if not _get("username"): _load_creds()
    if not _get("username") or not _get("domain"):
        _set(running=False, status="No creds configured"); return
    if not _get("dc_ip"):
        dc = _detect_dc()
        if dc: _set(dc_ip=dc)
        else: _set(running=False, status="No DC found"); return
    if _get("stop"): _set(running=False); return

    out_dir = os.path.join(LOOT_BASE, datetime.now().strftime("%Y%m%d_%H%M%S"))
    os.makedirs(out_dir, exist_ok=True)
    _set(output_dir=out_dir)

    method, success = _get("method"), False
    if method == "bloodhound-python" and _has_tool("bloodhound-python"):
        success = _run_bloodhound_python(out_dir)
    elif method == "bloodhound-python" and _has_tool("ldapsearch"):
        _set(status="bh-python missing, fallback"); time.sleep(1.0)
        success = _run_ldapsearch_fallback(out_dir)
    elif _has_tool("ldapsearch"):
        success = _run_ldapsearch_fallback(out_dir)
    else:
        _set(status="No tool available!")
    if success:
        st = _get("stats")
        _set(status=f"{st['users']}u {st['groups']}g {st['computers']}c")
    _set(running=False)

def _start_collect():
    if not _get("running"):
        threading.Thread(target=_do_collect, daemon=True).start()

# -- Blood drop icon ---------------------------------------------------------
def _draw_blood_drop(d, x, y):
    d.polygon([(x+3, y), (x, y+5), (x+3, y+8), (x+6, y+5)], fill="#CC0000")
    d.ellipse((x, y+3, x+6, y+9), fill="#CC0000")
    d.ellipse((x+1, y+4, x+3, y+6), fill="#FF3333")

# -- LCD drawing -------------------------------------------------------------
def _draw_lcd():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    running, status = _get("running"), _get("status")
    method, phase = _get("method"), _get("phase")
    dc_ip, domain, stats = _get("dc_ip"), _get("domain"), _get("stats")

    # Header
    d.rectangle((0, 0, 127, 12), fill="#1a0000")
    _draw_blood_drop(d, 2, 1)
    d.text((12, 1), "BLOODHOUND", font=font, fill="#FF2222")
    d.ellipse((118, 3, 124, 9), fill="#FF0000" if running else "#444444")

    y = 15
    d.text((2, y), f"DC: {(dc_ip or '(auto)')[:18]}", font=font, fill="#AAA")
    y += 11
    d.text((2, y), f"Dom: {domain[:16]}", font=font, fill="#00CCFF")
    y += 11
    ms = "bh-py" if method == "bloodhound-python" else "ldap"
    d.text((2, y), f"Method: {ms}", font=font, fill="#888")
    y += 13
    if running and phase:
        d.text((2, y), phase[:21], font=font, fill="#FFAA00")
    y += 11

    u, g = stats.get("users", 0), stats.get("groups", 0)
    c, gp = stats.get("computers", 0), stats.get("gpos", 0)
    if u or g or c or gp:
        d.text((2, y), f"{u} users, {g} groups", font=font, fill="#00FF88")
        y += 11
        d.text((2, y), f"{c} computers, {gp} GPOs", font=font, fill="#00FF88")
        y += 11
    else:
        y += 22
    out_dir = _get("output_dir")
    if out_dir:
        d.text((2, y), out_dir[-20:], font=font, fill="#555")

    d.rectangle((0, 106, 127, 115), fill="#0a0a0a")
    d.text((2, 107), status[:21], font=font, fill="#FFCC00")
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK K1:meth K3:exit", font=font, fill="#AAA")
    LCD.LCD_ShowImage(img, 0, 0)

def _show_msg(line1, line2=""):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), line1[:21], font=font, fill="#FF2222")
    if line2:
        d.text((4, 65), line2[:21], font=font, fill="#888")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.2)

# -- Main --------------------------------------------------------------------
def main():
    os.makedirs(LOOT_BASE, exist_ok=True)
    os.makedirs(CONFIG_DIR, exist_ok=True)
    _load_creds()

    if _has_tool("bloodhound-python"):
        _set(method="bloodhound-python")
    elif _has_tool("ldapsearch"):
        _set(method="ldapsearch")

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_blood_drop(d, 56, 10)
    d.text((14, 24), "BLOODHOUND", font=font, fill="#FF2222")
    d.text((10, 38), "AD Collector", font=font, fill="#AAA")
    d.text((4, 56), "OK = Start collect", font=font, fill="#666")
    d.text((4, 68), "K1 = Toggle method", font=font, fill="#666")
    d.text((4, 80), "K3 = Exit", font=font, fill="#666")
    d.text((4, 96), f"[{_get('method')}]", font=font, fill="#00CCFF")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    last_press = 0.0
    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if btn == "KEY3":
                _set(stop=True)
                break
            elif btn == "OK":
                _start_collect()
            elif btn == "KEY1":
                cur = _get("method")
                nxt = ("ldapsearch" if cur == "bloodhound-python"
                       else "bloodhound-python")
                _set(method=nxt)
                _show_msg(f"Method: {'bh-py' if nxt == 'bloodhound-python' else 'ldap'}")

            _draw_lcd()
            time.sleep(0.05)
    finally:
        _set(stop=True)
        time.sleep(0.2)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
