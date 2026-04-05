#!/usr/bin/env python3
"""
RaspyJack Payload -- LDAP Dumper
=================================
Author: 7h30th3r0n3

Comprehensive LDAP dump of Active Directory environments.
Auto-detects domain controllers (ports 389/636), attempts anonymous
bind first, then authenticated bind using credentials from config.

Dumps: Users, Groups, Computers, OUs, GPOs, Domain Trusts,
Password Policy, and SPN targets (Kerberoasting).

Saves structured JSON to /root/Raspyjack/loot/LDAPDump/.

Controls
--------
  OK          -- Start dump
  UP / DOWN   -- Scroll results
  KEY1        -- Cycle category tab
  KEY2        -- (reserved)
  KEY3        -- Exit
"""

import os
import sys
import time
import json
import re
import socket
import subprocess
import threading
import signal
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
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = "/root/Raspyjack/loot/LDAPDump"
CONFIG_DIR = "/root/Raspyjack/config/ldap_dumper"
CREDS_FILE = os.path.join(CONFIG_DIR, "creds.json")
os.makedirs(LOOT_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)

DEBOUNCE = 0.22
CATEGORIES = ["users", "groups", "computers", "gpos", "policy"]
CAT_LABELS = ["Users", "Groups", "Computers", "GPOs", "Policy"]

# ---------------------------------------------------------------------------
# Thread-safe state
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_state = {
    "dcs": [],
    "selected_dc": "",
    "dc_idx": 0,
    "base_dn": "",
    "domain": "",
    "creds": None,
    "bind_mode": "anonymous",
    "status": "Idle",
    "scanning": False,
    "dumping": False,
    "stop": False,
    "cat_idx": 0,
    "scroll": 0,
    "phase": "dc_select",
    "users": [],
    "groups": [],
    "computers": [],
    "ous": [],
    "gpos": [],
    "trusts": [],
    "password_policy": {},
    "spns": [],
}


def _get(key):
    with _lock:
        val = _state[key]
        if isinstance(val, (list, dict)):
            return list(val) if isinstance(val, list) else dict(val)
        return val


def _set(**kw):
    with _lock:
        for k, v in kw.items():
            _state[k] = v


# ---------------------------------------------------------------------------
# Credential loading
# ---------------------------------------------------------------------------
def _load_creds():
    """Load LDAP credentials from config file if available."""
    if not os.path.isfile(CREDS_FILE):
        return None
    try:
        with open(CREDS_FILE, "r") as f:
            data = json.load(f)
        domain = data.get("domain", "")
        username = data.get("username", "")
        password = data.get("password", "")
        if username and password:
            return {"domain": domain, "username": username,
                    "password": password}
    except (json.JSONDecodeError, OSError):
        pass
    return None


# ---------------------------------------------------------------------------
# DC discovery
# ---------------------------------------------------------------------------
def _get_local_subnet():
    """Return local subnet in CIDR form."""
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True, text=True, timeout=5,
        )
        for line in out.stdout.splitlines():
            if "127." not in line:
                m = re.search(r"inet (\d+\.\d+\.\d+)\.\d+/(\d+)", line)
                if m:
                    return f"{m.group(1)}.0/{m.group(2)}"
    except Exception:
        pass
    return "192.168.1.0/24"


def _check_port(ip, port, timeout=1.0):
    """Return True if TCP port is open."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        s.close()


def _scan_for_dcs():
    """Scan local subnet for LDAP (389) and LDAPS (636) hosts."""
    _set(scanning=True, status="Scanning for DCs...")
    subnet = _get_local_subnet()
    found = []

    try:
        out = subprocess.run(
            ["nmap", "-p", "389,636", "--open", "-T4", "-oG", "-", subnet],
            capture_output=True, text=True, timeout=90,
        )
        for line in out.stdout.splitlines():
            m = re.search(r"Host:\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m and ("389/open" in line or "636/open" in line):
                ip = m.group(1)
                if ip not in found:
                    found.append(ip)
    except FileNotFoundError:
        found = _fallback_dc_scan()
    except Exception:
        found = _fallback_dc_scan()

    _set(dcs=found, scanning=False,
         status=f"Found {len(found)} DC(s)")
    if found and not _get("selected_dc"):
        _set(selected_dc=found[0], dc_idx=0)


def _fallback_dc_scan():
    """Connect-scan ARP neighbors for ports 389/636."""
    found = []
    try:
        out = subprocess.run(
            ["arp", "-an"], capture_output=True, text=True, timeout=5,
        )
        for line in out.stdout.splitlines():
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
            if m:
                ip = m.group(1)
                if _check_port(ip, 389, 0.8) or _check_port(ip, 636, 0.8):
                    found.append(ip)
    except Exception:
        pass
    return found


def _start_dc_scan():
    if _get("scanning") or _get("dumping"):
        return
    threading.Thread(target=_scan_for_dcs, daemon=True).start()


# ---------------------------------------------------------------------------
# ldapsearch wrapper
# ---------------------------------------------------------------------------
def _build_ldapsearch_cmd(server, base_dn, ldap_filter, attrs, creds=None):
    """Build ldapsearch command list."""
    use_ssl = _check_port(server, 636, 0.5)
    proto = "ldaps" if use_ssl else "ldap"
    port = 636 if use_ssl else 389

    cmd = ["ldapsearch", "-x", "-H", f"{proto}://{server}:{port}",
           "-b", base_dn, "-LLL"]

    if creds:
        bind_dn = creds["username"]
        if creds.get("domain") and "\\" not in bind_dn and "@" not in bind_dn:
            bind_dn = f"{bind_dn}@{creds['domain']}"
        cmd.extend(["-D", bind_dn, "-w", creds["password"]])

    cmd.append(ldap_filter)
    cmd.extend(attrs)
    return cmd


def _run_ldapsearch(server, base_dn, ldap_filter, attrs, creds=None):
    """Run ldapsearch and return raw stdout."""
    cmd = _build_ldapsearch_cmd(server, base_dn, ldap_filter, attrs, creds)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60,
        )
        return result.stdout
    except Exception as exc:
        return f"ERROR: {exc}"


def _parse_ldif_entries(text):
    """Parse LDIF output into a list of dicts (one per entry)."""
    entries = []
    current = {}
    for line in text.splitlines():
        if not line.strip():
            if current:
                entries.append(current)
                current = {}
            continue
        if line.startswith("#") or line.startswith("search:") or \
           line.startswith("result:"):
            continue
        if line.startswith(" "):
            # continuation line
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            val = val.strip()
            if val.startswith(":"):
                # base64 encoded
                val = val[1:].strip()
            key = key.strip()
            if key in current:
                existing = current[key]
                if isinstance(existing, list):
                    existing.append(val)
                else:
                    current[key] = [existing, val]
            else:
                current[key] = val
    if current:
        entries.append(current)
    return entries


def _extract_values(text, attr_name):
    """Extract all values for an attribute from ldapsearch output."""
    results = []
    for line in text.splitlines():
        if line.lower().startswith(f"{attr_name.lower()}:"):
            val = line.split(":", 1)[1].strip()
            if val.startswith(":"):
                val = val[1:].strip()
            if val:
                results.append(val)
    return results


# ---------------------------------------------------------------------------
# Dump logic
# ---------------------------------------------------------------------------
def _discover_base_dn(server, creds):
    """Get base DN from rootDSE."""
    raw = _run_ldapsearch(server, "", "(objectClass=*)",
                          ["defaultNamingContext", "namingContexts"],
                          creds=None)
    default = _extract_values(raw, "defaultNamingContext")
    if default:
        return default[0]
    ncs = _extract_values(raw, "namingContexts")
    for nc in ncs:
        if nc.upper().startswith("DC="):
            return nc
    return ""


def _build_domain_from_dn(base_dn):
    """Convert DC=corp,DC=local to corp.local."""
    parts = re.findall(r"DC=([^,]+)", base_dn, re.IGNORECASE)
    return ".".join(parts) if parts else ""


def _do_dump():
    """Perform full LDAP dump."""
    _set(dumping=True, stop=False, status="Starting dump...")

    server = _get("selected_dc")
    if not server:
        _set(dumping=False, status="No DC selected")
        return

    creds = _get("creds")

    # --- Discover base DN ---
    _set(status="Discovering base DN...")
    base_dn = _discover_base_dn(server, creds)
    if not base_dn:
        _set(dumping=False, status="No base DN found")
        return
    domain = _build_domain_from_dn(base_dn)
    _set(base_dn=base_dn, domain=domain)

    # Try anonymous first, then with creds
    bind_creds = None
    test_raw = _run_ldapsearch(server, base_dn,
                               "(objectClass=organizationalUnit)",
                               ["ou"], creds=None)
    anon_entries = _parse_ldif_entries(test_raw)
    if anon_entries:
        _set(bind_mode="anonymous")
    elif creds:
        bind_creds = creds
        _set(bind_mode="authenticated")
    else:
        _set(bind_mode="anonymous (limited)")

    if _get("stop"):
        _set(dumping=False)
        return

    # --- Users ---
    _set(status="Dumping users...")
    raw = _run_ldapsearch(
        server, base_dn, "(objectClass=user)",
        ["sAMAccountName", "displayName", "memberOf",
         "userAccountControl"],
        creds=bind_creds,
    )
    user_entries = _parse_ldif_entries(raw)
    user_names = _extract_values(raw, "sAMAccountName")
    _set(users=user_entries, status=f"Dumping users... ({len(user_entries)} found)")

    if _get("stop"):
        _set(dumping=False)
        return

    # --- Groups ---
    _set(status="Dumping groups...")
    raw = _run_ldapsearch(
        server, base_dn, "(objectClass=group)",
        ["cn", "member"],
        creds=bind_creds,
    )
    group_entries = _parse_ldif_entries(raw)
    _set(groups=group_entries, status=f"Dumping groups... ({len(group_entries)} found)")

    if _get("stop"):
        _set(dumping=False)
        return

    # --- Computers ---
    _set(status="Dumping computers...")
    raw = _run_ldapsearch(
        server, base_dn, "(objectClass=computer)",
        ["cn", "operatingSystem", "dNSHostName"],
        creds=bind_creds,
    )
    computer_entries = _parse_ldif_entries(raw)
    _set(computers=computer_entries,
         status=f"Dumping computers... ({len(computer_entries)} found)")

    if _get("stop"):
        _set(dumping=False)
        return

    # --- OUs ---
    _set(status="Dumping OUs...")
    raw = _run_ldapsearch(
        server, base_dn, "(objectClass=organizationalUnit)",
        ["ou"],
        creds=bind_creds,
    )
    ou_entries = _parse_ldif_entries(raw)
    _set(ous=ou_entries)

    if _get("stop"):
        _set(dumping=False)
        return

    # --- GPOs ---
    _set(status="Dumping GPOs...")
    gpo_base = f"CN=Policies,CN=System,{base_dn}"
    raw = _run_ldapsearch(
        server, gpo_base, "(objectClass=groupPolicyContainer)",
        ["displayName", "gPCFileSysPath"],
        creds=bind_creds,
    )
    gpo_entries = _parse_ldif_entries(raw)
    _set(gpos=gpo_entries, status=f"Dumping GPOs... ({len(gpo_entries)} found)")

    if _get("stop"):
        _set(dumping=False)
        return

    # --- Domain Trusts ---
    _set(status="Dumping trusts...")
    trust_base = f"CN=System,{base_dn}"
    raw = _run_ldapsearch(
        server, trust_base, "(objectClass=trustedDomain)",
        ["cn", "trustDirection", "trustType"],
        creds=bind_creds,
    )
    trust_entries = _parse_ldif_entries(raw)
    _set(trusts=trust_entries)

    if _get("stop"):
        _set(dumping=False)
        return

    # --- Password Policy ---
    _set(status="Dumping password policy...")
    raw = _run_ldapsearch(
        server, base_dn, "(objectClass=domainDNS)",
        ["minPwdLength", "maxPwdAge", "lockoutThreshold",
         "lockoutDuration", "pwdHistoryLength"],
        creds=bind_creds,
    )
    policy_entries = _parse_ldif_entries(raw)
    policy = policy_entries[0] if policy_entries else {}
    _set(password_policy=policy)

    if _get("stop"):
        _set(dumping=False)
        return

    # --- SPNs (Kerberoasting) ---
    _set(status="Dumping SPNs...")
    raw = _run_ldapsearch(
        server, base_dn,
        "(&(servicePrincipalName=*)(objectClass=user))",
        ["sAMAccountName", "servicePrincipalName"],
        creds=bind_creds,
    )
    spn_entries = _parse_ldif_entries(raw)
    _set(spns=spn_entries)

    # --- Save results ---
    _set(status="Saving dump...")
    _save_dump()

    total = (len(_get("users")) + len(_get("groups")) +
             len(_get("computers")) + len(_get("gpos")))
    _set(dumping=False,
         status=f"Done! {total} objects dumped",
         phase="results")


def _save_dump():
    """Save comprehensive dump and individual category files."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dump_dir = LOOT_DIR

    full_dump = {
        "timestamp": ts,
        "server": _get("selected_dc"),
        "domain": _get("domain"),
        "base_dn": _get("base_dn"),
        "bind_mode": _get("bind_mode"),
        "users": _get("users"),
        "groups": _get("groups"),
        "computers": _get("computers"),
        "ous": _get("ous"),
        "gpos": _get("gpos"),
        "trusts": _get("trusts"),
        "password_policy": _get("password_policy"),
        "spns": _get("spns"),
        "summary": {
            "user_count": len(_get("users")),
            "group_count": len(_get("groups")),
            "computer_count": len(_get("computers")),
            "ou_count": len(_get("ous")),
            "gpo_count": len(_get("gpos")),
            "trust_count": len(_get("trusts")),
            "spn_count": len(_get("spns")),
        },
    }

    # Full dump
    dump_path = os.path.join(dump_dir, f"dump_{ts}.json")
    with open(dump_path, "w") as f:
        json.dump(full_dump, f, indent=2)

    # Individual category files
    categories = {
        "users": _get("users"),
        "groups": _get("groups"),
        "computers": _get("computers"),
        "gpos": _get("gpos"),
    }
    for name, data in categories.items():
        cat_path = os.path.join(dump_dir, f"{name}.json")
        with open(cat_path, "w") as f:
            json.dump({"timestamp": ts, name: data}, f, indent=2)


def _start_dump():
    if _get("scanning") or _get("dumping"):
        return
    threading.Thread(target=_do_dump, daemon=True).start()


# ---------------------------------------------------------------------------
# LCD drawing helpers
# ---------------------------------------------------------------------------
def _draw_header(d, title, active=False):
    """Draw top header bar."""
    d.rectangle((0, 0, 127, 12), fill="#111")
    d.text((2, 1), title, font=font, fill="#FF8800")
    color = "#00FF00" if active else "#666"
    d.ellipse((118, 3, 124, 9), fill=color)


def _draw_footer(d, text):
    """Draw bottom footer bar."""
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:22], font=font, fill="#AAA")


def _draw_status(d, text):
    """Draw status line above footer."""
    d.rectangle((0, 106, 127, 115), fill="#0a0a0a")
    d.text((2, 107), text[:22], font=font, fill="#FFCC00")


def _draw_scroll_list(d, y_start, items, scroll, label):
    """Draw a scrollable list of entries."""
    if not items:
        d.text((4, y_start + 20), f"No {label}", font=font, fill="#666")
        return

    d.text((2, y_start), f"{label}: {len(items)}", font=font, fill="#888")
    y = y_start + 12
    visible = 7

    for i in range(scroll, min(scroll + visible, len(items))):
        entry = items[i]
        if isinstance(entry, dict):
            display = _entry_display(entry, label)
        else:
            display = str(entry)
        color = "#00FF00" if i == scroll else "#AAAAAA"
        d.text((2, y), display[:22], font=font, fill=color)
        y += 12


def _entry_display(entry, label):
    """Pick a display string from a dict entry."""
    label_lower = label.lower()
    if "users" in label_lower:
        name = entry.get("sAMAccountName", "")
        display = entry.get("displayName", "")
        return f"{name}" if name else display or "?"
    if "groups" in label_lower:
        return entry.get("cn", "?")
    if "computer" in label_lower:
        host = entry.get("dNSHostName", "")
        cn = entry.get("cn", "")
        return host or cn or "?"
    if "gpo" in label_lower:
        return entry.get("displayName", "?")
    if "policy" in label_lower:
        return str(entry)
    return str(list(entry.values())[:1])


# ---------------------------------------------------------------------------
# LCD screens
# ---------------------------------------------------------------------------
def _draw_dc_select():
    """DC selection screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    scanning = _get("scanning")
    _draw_header(d, "LDAP DUMPER", scanning)

    dcs = _get("dcs")
    dc_idx = _get("dc_idx")
    y = 14

    if not dcs:
        d.text((4, 28), "No DCs found", font=font, fill="#666")
        d.text((4, 42), "OK = scan network", font=font, fill="#888")
    else:
        d.text((2, y), f"DCs found: {len(dcs)}", font=font, fill="#888")
        y += 14
        for i, dc in enumerate(dcs):
            prefix = ">" if i == dc_idx else " "
            color = "#00FF00" if i == dc_idx else "#AAAAAA"
            ssl_ok = _check_port(dc, 636, 0.3)
            tag = " [S]" if ssl_ok else ""
            d.text((2, y), f"{prefix}{dc}{tag}", font=font, fill=color)
            y += 12
            if y > 95:
                break

    creds = _get("creds")
    cred_txt = "Creds: loaded" if creds else "Creds: none"
    d.text((2, 94), cred_txt, font=font, fill="#888")

    _draw_status(d, _get("status"))
    _draw_footer(d, "OK=dump UP/DN=sel K3=x")
    LCD.LCD_ShowImage(img, 0, 0)


def _draw_results():
    """Results browser screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    cat_idx = _get("cat_idx")
    scroll = _get("scroll")
    dumping = _get("dumping")

    cat_label = CAT_LABELS[cat_idx]
    _draw_header(d, f"LDAP: {cat_label}", dumping)

    # Tab indicators
    y_tab = 14
    for i, lab in enumerate(CAT_LABELS):
        short = lab[:3]
        color = "#FF8800" if i == cat_idx else "#555"
        x = 2 + i * 26
        d.text((x, y_tab), short, font=font, fill=color)
    d.line((0, 24, 127, 24), fill="#333")

    y = 26
    cat_key = CATEGORIES[cat_idx]

    if cat_key == "policy":
        policy = _get("password_policy")
        if policy:
            for k, v in list(policy.items())[:7]:
                short_k = k[:12]
                d.text((2, y), f"{short_k}: {v}", font=font, fill="#AAAAAA")
                y += 12
        else:
            d.text((4, y + 10), "No policy data", font=font, fill="#666")
    else:
        items = _get(cat_key)
        _draw_scroll_list(d, y, items, scroll, cat_label)

    _draw_status(d, _get("status"))
    _draw_footer(d, "K1=tab OK=dump K3=x")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
def main():
    # Load credentials
    creds = _load_creds()
    _set(creds=creds)

    # Splash screen
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 10), "LDAP DUMPER", font=font, fill="#FF8800")
    d.text((4, 26), "AD dump tool", font=font, fill="#888")
    d.text((4, 46), "Scanning for DCs...", font=font, fill="#00CCFF")
    LCD.LCD_ShowImage(img, 0, 0)

    # Auto-scan for DCs
    _start_dc_scan()
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

            phase = _get("phase")

            if btn == "KEY3":
                _set(stop=True)
                break

            if phase == "dc_select":
                _handle_dc_select(btn)
                _draw_dc_select()
            elif phase == "results":
                _handle_results(btn)
                _draw_results()

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


def _handle_dc_select(btn):
    """Handle input on DC selection screen."""
    if btn == "OK":
        dcs = _get("dcs")
        if not dcs:
            _start_dc_scan()
        else:
            dc_idx = _get("dc_idx")
            _set(selected_dc=dcs[dc_idx])
            _start_dump()

    elif btn == "UP":
        idx = _get("dc_idx")
        dcs = _get("dcs")
        if dcs:
            _set(dc_idx=max(0, idx - 1),
                 selected_dc=dcs[max(0, idx - 1)])

    elif btn == "DOWN":
        idx = _get("dc_idx")
        dcs = _get("dcs")
        if dcs:
            new_idx = min(len(dcs) - 1, idx + 1)
            _set(dc_idx=new_idx, selected_dc=dcs[new_idx])


def _handle_results(btn):
    """Handle input on results screen."""
    if btn == "KEY1":
        idx = _get("cat_idx")
        _set(cat_idx=(idx + 1) % len(CATEGORIES), scroll=0)

    elif btn == "OK":
        _start_dump()

    elif btn == "UP":
        s = _get("scroll")
        _set(scroll=max(0, s - 1))

    elif btn == "DOWN":
        s = _get("scroll")
        cat_key = CATEGORIES[_get("cat_idx")]
        if cat_key != "policy":
            items = _get(cat_key)
            _set(scroll=min(max(0, len(items) - 1), s + 1))

    elif btn == "LEFT":
        idx = _get("cat_idx")
        _set(cat_idx=(idx - 1) % len(CATEGORIES), scroll=0)

    elif btn == "RIGHT":
        idx = _get("cat_idx")
        _set(cat_idx=(idx + 1) % len(CATEGORIES), scroll=0)


if __name__ == "__main__":
    raise SystemExit(main())
