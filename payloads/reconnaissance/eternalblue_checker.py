#!/usr/bin/env python3
"""
RaspyJack Payload -- EternalBlue (MS17-010) Checker
=====================================================
DETECTION ONLY -- no exploitation code.

Scans local subnet for port 445 hosts, then sends SMB1 negotiate +
session setup + tree connect + Trans2 PeekNamedPipe to check MS17-010.
STATUS_INSUFF_SERVER_RESOURCES (0xC0000205) = VULNERABLE.

Results: /root/Raspyjack/loot/EternalBlue/scan_TIMESTAMP.json
Controls: OK=Start, UP/DOWN=Scroll, KEY3=Exit
"""

import os, sys, time, json, socket, struct, threading, subprocess, re
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

LOOT_DIR = "/root/Raspyjack/loot/EternalBlue"
os.makedirs(LOOT_DIR, exist_ok=True)

SMB_PORT = 445
CONNECT_TIMEOUT = 3
RECV_TIMEOUT = 5
DEBOUNCE = 0.22
NT_INSUFF_RESOURCES = 0xC0000205

# ---------------------------------------------------------------------------
# SMB1 packet builders (raw bytes -- detection only)
# ---------------------------------------------------------------------------

def _nb_wrap(payload):
    """Prepend NetBIOS session header to SMB payload."""
    return b"\x00" + struct.pack(">I", len(payload))[1:] + payload


def _smb_header(command, tid=0, uid=0):
    """Build a 32-byte SMB1 header."""
    hdr = b"\xff\x53\x4d\x42"          # SMB magic
    hdr += bytes([command])             # Command
    hdr += b"\x00\x00\x00\x00"         # Status
    hdr += b"\x18\x53\xc8"             # Flags + Flags2
    hdr += b"\x00" * 12                # PID high, signature, reserved
    hdr += struct.pack("<H", tid)       # TID
    hdr += b"\xff\xfe"                  # PID
    hdr += struct.pack("<H", uid)       # UID
    hdr += b"\x00\x00"                  # MID
    return hdr


def _smb1_negotiate():
    """SMB1 Negotiate with NT LM 0.12 dialect."""
    dialect = b"\x02NT LM 0.12\x00"
    payload = _smb_header(0x72)
    payload += b"\x00"                          # Word count = 0
    payload += struct.pack("<H", len(dialect))  # Byte count
    payload += dialect
    return _nb_wrap(payload)


def _smb1_session_setup():
    """SMB1 Session Setup AndX -- null/anonymous authentication."""
    words = b"\x0d"         # Word count = 13
    words += b"\xff\x00"    # AndXCommand + reserved
    words += b"\x00\x00"    # AndXOffset
    words += b"\x04\x11"    # Max buffer
    words += b"\x0a\x00"    # Max Mpx
    words += b"\x00\x00"    # VC number
    words += b"\x00" * 4    # Session key
    words += b"\x01\x00"    # ANSI pw len = 1
    words += b"\x00\x00"    # Unicode pw len = 0
    words += b"\x00" * 4    # Reserved
    words += b"\xd4\x00\x00\x00"  # Capabilities
    byte_data = b"\x00" * 4       # Null password + padding
    payload = _smb_header(0x73) + words + struct.pack("<H", len(byte_data)) + byte_data
    return _nb_wrap(payload)


def _smb1_tree_connect(ip, uid=0):
    """SMB1 Tree Connect AndX to IPC$ share."""
    words = b"\x04"         # Word count = 4
    words += b"\xff\x00"    # AndXCommand + reserved
    words += b"\x00\x00"    # AndXOffset
    words += b"\x00\x00"    # Flags
    words += b"\x01\x00"    # Password length = 1
    ipc_path = f"\\\\{ip}\\IPC$\x00".encode("ascii")
    byte_data = b"\x00" + ipc_path + b"?????\x00"
    payload = _smb_header(0x75, uid=uid) + words
    payload += struct.pack("<H", len(byte_data)) + byte_data
    return _nb_wrap(payload)


def _smb1_peeknamedpipe(tid=0, uid=0):
    """Trans request -- PeekNamedPipe FID 0 (the MS17-010 fingerprint)."""
    words = b"\x10"         # Word count = 16
    words += b"\x00\x00"    # Total param count
    words += b"\x00\x00"    # Total data count
    words += b"\xff\xff"    # Max param count
    words += b"\xff\xff"    # Max data count
    words += b"\x00\x00"    # Max setup + reserved
    words += b"\x00\x00"    # Flags
    words += b"\x00" * 4    # Timeout
    words += b"\x00\x00"    # Reserved
    words += b"\x00\x00"    # Param count
    words += b"\x4a\x00"    # Param offset
    words += b"\x00\x00"    # Data count
    words += b"\x4a\x00"    # Data offset
    words += b"\x02\x00"    # Setup count + reserved
    words += b"\x23\x00"    # PeekNamedPipe (0x0023)
    words += b"\x00\x00"    # FID = 0
    byte_data = b"\x07\x00\\PIPE\\\x00"
    payload = _smb_header(0x25, tid, uid) + words
    payload += struct.pack("<H", len(byte_data)) + byte_data
    return _nb_wrap(payload)


# ---------------------------------------------------------------------------
# Response parsers
# ---------------------------------------------------------------------------

def _parse_nt_status(resp):
    return struct.unpack("<I", resp[9:13])[0] if len(resp) >= 13 else 0

def _parse_uid(resp):
    return struct.unpack("<H", resp[36:38])[0] if len(resp) >= 38 else 0

def _parse_tid(resp):
    return struct.unpack("<H", resp[32:34])[0] if len(resp) >= 34 else 0

def _parse_os_info(resp):
    """Try to extract OS string from Session Setup response."""
    try:
        raw = resp[36:]
        if len(raw) < 3:
            return ""
        wc = raw[0]
        off = 1 + (wc * 2) + 2
        if off >= len(raw):
            return ""
        section = raw[off:]
        for encoding in ("utf-16-le", "ascii"):
            decoded = section.decode(encoding, errors="ignore")
            for part in decoded.split("\x00"):
                cleaned = part.strip()
                if len(cleaned) > 3:
                    return cleaned[:40]
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# MS17-010 check for a single host
# ---------------------------------------------------------------------------

def check_ms17_010(ip):
    """Returns dict with host, status (VULNERABLE/PATCHED/ERROR), os_info, detail."""
    result = {"host": ip, "status": "ERROR", "os_info": "", "detail": ""}
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        sock.connect((ip, SMB_PORT))
        sock.settimeout(RECV_TIMEOUT)

        # 1) Negotiate
        sock.send(_smb1_negotiate())
        resp = sock.recv(4096)
        if len(resp) < 36:
            result["detail"] = "Bad negotiate response"
            return result

        # 2) Session Setup (anonymous)
        sock.send(_smb1_session_setup())
        resp = sock.recv(4096)
        uid = _parse_uid(resp)
        result["os_info"] = _parse_os_info(resp)

        # 3) Tree Connect to IPC$
        sock.send(_smb1_tree_connect(ip, uid))
        resp = sock.recv(4096)
        tid = _parse_tid(resp)

        # 4) PeekNamedPipe -- the actual MS17-010 fingerprint
        sock.send(_smb1_peeknamedpipe(tid, uid))
        resp = sock.recv(4096)
        nt_status = _parse_nt_status(resp)

        if nt_status == NT_INSUFF_RESOURCES:
            result["status"] = "VULNERABLE"
            result["detail"] = "STATUS_INSUFF_SERVER_RESOURCES"
        else:
            result["status"] = "PATCHED"
            result["detail"] = f"NT_STATUS=0x{nt_status:08X}"

    except socket.timeout:
        result["detail"] = "Connection timeout"
    except ConnectionRefusedError:
        result["detail"] = "Port 445 refused"
    except OSError as exc:
        result["detail"] = str(exc)[:50]
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    return result


# ---------------------------------------------------------------------------
# Subnet discovery
# ---------------------------------------------------------------------------

def _get_local_cidr():
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True, text=True, timeout=5,
        )
        for line in out.stdout.splitlines():
            if "127." in line:
                continue
            m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


def _scan_port_445(cidr, on_progress, stop_fn):
    """TCP connect scan for port 445 across the subnet."""
    import ipaddress
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    hosts = []
    total = min(network.num_addresses, 256)
    checked = 0
    for addr in network.hosts():
        if stop_fn():
            break
        ip = str(addr)
        checked += 1
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((ip, SMB_PORT)) == 0:
                hosts.append(ip)
            s.close()
        except Exception:
            pass
        on_progress(checked, total, len(hosts))
    return hosts


# ---------------------------------------------------------------------------
# Thread-safe state
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_state = {
    "results": [], "status": "Idle", "scanning": False,
    "stop": False, "scroll": 0, "progress": "",
}

def _get(key):
    with _lock:
        val = _state[key]
        return list(val) if isinstance(val, list) else val

def _set(**kw):
    with _lock:
        _state.update(kw)


# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------

def _do_scan():
    _set(scanning=True, stop=False, results=[], status="Detecting subnet...")
    cidr = _get_local_cidr()
    if not cidr:
        _set(scanning=False, status="No network found")
        return

    _set(status="Scanning port 445...")

    def on_progress(checked, total, found):
        _set(progress=f"445: {checked}/{total} ({found} SMB)")

    stop_fn = lambda: _get("stop")
    smb_hosts = _scan_port_445(cidr, on_progress, stop_fn)

    if _get("stop"):
        _set(scanning=False, status="Cancelled")
        return
    if not smb_hosts:
        _set(scanning=False, status="No SMB hosts found")
        return

    _set(status=f"Checking {len(smb_hosts)} hosts...")
    results = []
    for idx, ip in enumerate(smb_hosts):
        if _get("stop"):
            break
        _set(progress=f"Check {idx + 1}/{len(smb_hosts)}: {ip}")
        results.append(check_ms17_010(ip))
        _set(results=list(results))

    vuln_count = sum(1 for r in results if r["status"] == "VULNERABLE")
    _set(results=results, scanning=False,
         status=f"Done: {vuln_count} vuln / {len(results)} hosts")
    _save_results(results)


def _save_results(results):
    if not results:
        return
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    data = {
        "scan_time": ts,
        "description": "MS17-010 EternalBlue detection scan",
        "host_count": len(results),
        "vulnerable": sum(1 for r in results if r["status"] == "VULNERABLE"),
        "patched": sum(1 for r in results if r["status"] == "PATCHED"),
        "errors": sum(1 for r in results if r["status"] == "ERROR"),
        "hosts": results,
    }
    path = os.path.join(LOOT_DIR, f"scan_{ts}.json")
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except OSError:
        pass


def _start_scan():
    if not _get("scanning"):
        threading.Thread(target=_do_scan, daemon=True).start()


# ---------------------------------------------------------------------------
# LCD drawing
# ---------------------------------------------------------------------------
CLR_VULN, CLR_PATCH, CLR_ERR = "#FF3333", "#33FF33", "#888888"
CLR_HDR_BG, CLR_HDR_FG = "#1a0000", "#FF4444"

def _status_color(status):
    if status == "VULNERABLE":
        return CLR_VULN
    return CLR_PATCH if status == "PATCHED" else CLR_ERR


def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill=CLR_HDR_BG)
    d.text((2, 1), "MS17-010 CHECK", font=font, fill=CLR_HDR_FG)
    scanning = _get("scanning")
    d.ellipse((118, 3, 124, 9), fill="#FF0000" if scanning else "#444444")

    results = _get("results")
    scroll = _get("scroll")
    status = _get("status")
    progress = _get("progress")

    if not results and not scanning:
        d.text((4, 30), status[:21], font=font, fill="#AAAAAA")
        d.text((4, 50), "OK = Start scan", font=font, fill="#666666")
        d.text((4, 62), "KEY3 = Exit", font=font, fill="#666666")
        LCD.LCD_ShowImage(img, 0, 0)
        return

    if not results:
        d.text((4, 30), status[:21], font=font, fill="#FFCC00")
        d.text((4, 46), progress[:21], font=font, fill="#AAAAAA")
        LCD.LCD_ShowImage(img, 0, 0)
        return

    # Results list (scrollable)
    visible = 7
    y = 15
    for i in range(scroll, min(scroll + visible, len(results))):
        entry = results[i]
        tag = entry["status"][:5]
        line = f"{entry['host']} {tag}"
        d.text((2, y), line[:21], font=font, fill=_status_color(entry["status"]))
        y += 13

    # Progress / status bar
    d.rectangle((0, 106, 127, 115), fill="#0a0a0a")
    d.text((2, 107), (progress if scanning else status)[:21], font=font, fill="#FFCC00")
    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111111")
    d.text((2, 117), "U/D:scroll  K3:exit", font=font, fill="#AAAAAA")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 13), fill=CLR_HDR_BG)
    d.text((2, 1), "MS17-010 CHECK", font=font, fill=CLR_HDR_FG)
    d.text((4, 24), "EternalBlue Detect", font=font, fill="#FFCC00")
    d.text((4, 40), "DETECTION ONLY", font=font, fill="#FF6666")
    d.text((4, 56), "Auto-discovers SMB", font=font, fill="#888888")
    d.text((4, 68), "hosts on local subnet", font=font, fill="#888888")
    d.text((4, 88), "OK=Start  KEY3=Exit", font=font, fill="#666666")
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
            if btn == "OK":
                _start_scan()
            if btn == "UP":
                _set(scroll=max(0, _get("scroll") - 1))
            if btn == "DOWN":
                mx = max(0, len(_get("results")) - 7)
                _set(scroll=min(mx, _get("scroll") + 1))

            _draw_screen()
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
