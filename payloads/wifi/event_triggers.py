#!/usr/bin/env python3
"""
RaspyJack Payload -- Event Triggers
=====================================
Author: 7h30th3r0n3

Configurable event monitoring system. Watches for WiFi events and triggers
alerts: deauth floods, new client connections, specific MAC detection,
and authentication captures.

Controls:
  UP/DOWN  -- Navigate triggers
  OK       -- Toggle trigger on/off
  KEY1     -- View alert log
  KEY2     -- Configure selected trigger
  KEY3     -- Exit (triggers keep running in background)
"""
import os, sys, time, signal, subprocess, threading, json, re
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

ROW_H = 12
CONFIG_DIR = "/root/Raspyjack/loot/Triggers"
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
ALERT_LOG_FILE = os.path.join(CONFIG_DIR, "alerts.log")
RESPONDER_LOG_DIR = "/root/Raspyjack/Responder/logs"
LOOT_DIR = "/root/Raspyjack/loot"
TRIGGER_NAMES = ["deauth_flood", "client_connected", "mac_trigger", "auth_capture"]
TRIGGER_LABELS = ["Deauth Flood", "Client Conn", "MAC Trigger", "Auth Capture"]

# ── OUI lookup (~50 common vendors) ─────────────────────────────────────────
OUI_BUILTIN = {
    "00:03:93": "Apple", "00:17:F2": "Apple", "00:1E:C2": "Apple",
    "00:25:00": "Apple", "3C:15:C2": "Apple", "AC:DE:48": "Apple",
    "00:15:5D": "Microsoft", "00:50:F2": "Microsoft", "28:18:78": "Microsoft",
    "00:0C:29": "VMware", "00:50:56": "VMware", "08:00:27": "Oracle/VBox",
    "00:1A:11": "Google", "3C:5A:B4": "Google", "54:60:09": "Google",
    "00:17:C4": "Broadcom", "00:10:18": "Broadcom",
    "00:1B:21": "Intel", "00:13:02": "Intel", "A4:34:D9": "Intel",
    "00:1E:64": "Intel", "B4:6B:FC": "Intel",
    "00:09:2D": "HTC", "00:23:76": "HTC",
    "00:07:AB": "Samsung", "00:16:32": "Samsung", "00:1A:8A": "Samsung",
    "00:21:19": "Samsung", "EC:1F:72": "Samsung",
    "00:04:0E": "Linksys", "00:0C:41": "Linksys",
    "00:12:17": "Cisco", "00:14:69": "Cisco", "00:1B:0D": "Cisco",
    "00:14:6C": "Netgear", "00:1B:2F": "Netgear", "00:1E:2A": "Netgear",
    "00:1C:DF": "Belkin", "00:17:3F": "Belkin",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "2C:F0:5D": "Xiaomi", "64:09:80": "Xiaomi",
    "00:1A:79": "Huawei", "00:E0:FC": "Huawei",
    "00:26:5A": "D-Link", "00:17:9A": "D-Link",
    "00:1D:0F": "TP-Link", "50:C7:BF": "TP-Link",
    "00:24:01": "Sony", "00:1E:75": "LG", "00:19:47": "Motorola",
    "94:65:2D": "OnePlus", "F8:E4:3B": "Asus", "00:24:D7": "Realtek",
}


def _oui_lookup(mac):
    """Return vendor name for a MAC address."""
    prefix = mac.upper()[:8]
    vendor = OUI_BUILTIN.get(prefix)
    if vendor:
        return vendor
    oui_path = "/usr/share/ieee-data/oui.txt"
    if os.path.isfile(oui_path):
        try:
            key = prefix.replace(":", "-")
            with open(oui_path, "r", errors="replace") as fh:
                for line in fh:
                    if key in line and "(hex)" in line:
                        parts = line.split("(hex)")
                        if len(parts) > 1:
                            return parts[1].strip()[:20]
        except Exception:
            pass
    return "Unknown"

lock = threading.Lock()
config = {
    "deauth_flood": {"enabled": False, "threshold": 20, "window": 10},
    "client_connected": {"enabled": False, "interval": 5},
    "mac_trigger": {"enabled": False, "target_mac": ""},
    "auth_capture": {"enabled": False},
}
alerts = []
cursor_pos = 0
view_mode = "main"
log_scroll = 0
known_neighbors = set()
known_loot_files = set()
known_resp_lines = 0
_running = True
_threads = {}


def _sig_handler(_s, _f):
    global _running
    _running = False

signal.signal(signal.SIGINT, _sig_handler)
signal.signal(signal.SIGTERM, _sig_handler)

def _load_config():
    global config
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if not os.path.isfile(CONFIG_FILE):
        _save_config()
        return
    try:
        with open(CONFIG_FILE, "r") as fh:
            data = json.load(fh)
        with lock:
            for key in TRIGGER_NAMES:
                if key in data:
                    config[key] = dict(data[key])
    except Exception:
        pass

def _save_config():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with lock:
        data = {k: dict(v) for k, v in config.items()}
    with open(CONFIG_FILE, "w") as fh:
        json.dump(data, fh, indent=2)

def _append_alert(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    with lock:
        alerts.append(line)
        if len(alerts) > 200:
            alerts.pop(0)
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(ALERT_LOG_FILE, "a") as fh:
            fh.write(line + "\n")
    except Exception:
        pass

def _run_cmd(args, timeout=5):
    subprocess.run(args, capture_output=True, timeout=timeout)


def _find_monitor_iface():
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if name.endswith("mon") and os.path.isdir(f"/sys/class/net/{name}/wireless"):
                return name
    except Exception:
        pass
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if not name.startswith("wlan"):
                continue
            if not os.path.isdir(f"/sys/class/net/{name}/wireless"):
                continue
            if "mmc" in os.path.realpath(f"/sys/class/net/{name}/device"):
                continue
            _run_cmd(["sudo", "ip", "link", "set", name, "down"])
            _run_cmd(["sudo", "iw", name, "set", "type", "monitor"])
            _run_cmd(["sudo", "ip", "link", "set", name, "up"])
            return name
    except Exception:
        pass
    return None

def _deauth_flood_worker():
    iface = _find_monitor_iface()
    if not iface:
        _append_alert("DEAUTH: No monitor iface found")
        return
    while _running:
        with lock:
            if not config["deauth_flood"]["enabled"]:
                break
            threshold = config["deauth_flood"].get("threshold", 20)
            window = config["deauth_flood"].get("window", 10)
        try:
            proc = subprocess.run(
                ["sudo", "tcpdump", "-i", iface, "-e", "-c", "100", "-l",
                 "type mgt subtype deauth or type mgt subtype disassoc"],
                capture_output=True, text=True, timeout=window + 5)
            output = proc.stderr + proc.stdout
        except subprocess.TimeoutExpired:
            output = ""
        except Exception:
            time.sleep(2); continue

        deauth_count = 0
        src_macs, dst_macs = set(), set()
        for line in output.splitlines():
            low = line.lower()
            if "deauth" in low or "disassoc" in low:
                deauth_count += 1
                macs = re.findall(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", low)
                if len(macs) >= 1:
                    src_macs.add(macs[0].upper())
                if len(macs) >= 2:
                    dst_macs.add(macs[1].upper())
        if deauth_count > threshold:
            _append_alert(
                f"DEAUTH FLOOD: {deauth_count} frames/{window}s "
                f"src={','.join(list(src_macs)[:3]) or '?'} "
                f"dst={','.join(list(dst_macs)[:3]) or '?'}")
        time.sleep(1)

def _client_connected_worker():
    global known_neighbors
    initial = True
    while _running:
        with lock:
            if not config["client_connected"]["enabled"]:
                break
            interval = config["client_connected"].get("interval", 5)
        try:
            result = subprocess.run(["ip", "neigh", "show"],
                                    capture_output=True, text=True, timeout=5)
        except Exception:
            time.sleep(interval); continue

        current = {}
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) < 5 or parts[-1].upper() in ("FAILED", "INCOMPLETE"):
                continue
            m = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
            if m:
                current[m.group(1).upper()] = parts[0]

        with lock:
            prev = set(known_neighbors)
        if not initial:
            for mac in set(current) - prev:
                _append_alert(f"NEW CLIENT: {mac} vendor={_oui_lookup(mac)} "
                              f"ip={current.get(mac, '?')}")
        with lock:
            known_neighbors = set(current)
        initial = False
        time.sleep(interval)

def _mac_trigger_worker():
    last_seen = False
    while _running:
        with lock:
            if not config["mac_trigger"]["enabled"]:
                break
            target = config["mac_trigger"].get("target_mac", "").upper().strip()
        if not target:
            time.sleep(5); continue
        try:
            result = subprocess.run(["ip", "neigh", "show"],
                                    capture_output=True, text=True, timeout=5)
        except Exception:
            time.sleep(10); continue

        found = target in result.stdout.upper()
        if found and not last_seen:
            ip = "?"
            for line in result.stdout.splitlines():
                if target in line.upper():
                    ip = line.split()[0] if line.split() else "?"
                    break
            _append_alert(f"MAC DETECTED: {target} ip={ip}")
        last_seen = found
        time.sleep(10)

def _count_dir_lines(dirpath):
    """Count total lines across all files in a directory."""
    total = 0
    try:
        for fn in os.listdir(dirpath):
            fp = os.path.join(dirpath, fn)
            if os.path.isfile(fp):
                with open(fp, "r", errors="replace") as fh:
                    total += len(fh.readlines())
    except Exception:
        pass
    return total

def _auth_capture_worker():
    global known_loot_files, known_resp_lines
    cap_exts = (".cap", ".pcap", ".hccapx", ".22000", ".hc22000")
    with lock:
        if os.path.isdir(LOOT_DIR):
            known_loot_files = set(os.listdir(LOOT_DIR))
        if os.path.isdir(RESPONDER_LOG_DIR):
            known_resp_lines = _count_dir_lines(RESPONDER_LOG_DIR)
    while _running:
        with lock:
            if not config["auth_capture"]["enabled"]:
                break
        if os.path.isdir(LOOT_DIR):
            cur = set(os.listdir(LOOT_DIR))
            with lock:
                new = cur - known_loot_files
            for f in new:
                if any(f.endswith(e) for e in cap_exts):
                    _append_alert(f"HANDSHAKE CAPTURED: {f}")
            with lock:
                known_loot_files = cur
        if os.path.isdir(RESPONDER_LOG_DIR):
            total = _count_dir_lines(RESPONDER_LOG_DIR)
            with lock:
                prev = known_resp_lines
            if total > prev:
                _append_alert(f"AUTH CAPTURE: {total - prev} new cred line(s)")
            with lock:
                known_resp_lines = total
        time.sleep(5)

_WORKERS = {
    "deauth_flood": _deauth_flood_worker,
    "client_connected": _client_connected_worker,
    "mac_trigger": _mac_trigger_worker,
    "auth_capture": _auth_capture_worker,
}

def _start_trigger(name):
    with lock:
        config[name]["enabled"] = True
    _save_config()
    if name in _threads and _threads[name].is_alive():
        return
    worker = _WORKERS.get(name)
    if worker:
        t = threading.Thread(target=worker, daemon=True, name=f"trig-{name}")
        t.start()
        _threads[name] = t
        _append_alert(f"TRIGGER ON: {name}")

def _stop_trigger(name):
    with lock:
        config[name]["enabled"] = False
    _save_config()
    _append_alert(f"TRIGGER OFF: {name}")

def _is_active(name):
    with lock:
        enabled = config[name]["enabled"]
    return enabled and name in _threads and _threads[name].is_alive()

def _draw_main():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "EVENT TRIGGERS", font=font, fill="#00CCFF")

    y = 16
    for i, name in enumerate(TRIGGER_NAMES):
        active = _is_active(name)
        if i == cursor_pos:
            d.rectangle((0, y, 127, y + ROW_H - 1), fill="#222")
        d.ellipse((3, y + 2, 9, y + 8),
                  fill="#00FF00" if active else "#FF0000")
        d.text((13, y), TRIGGER_LABELS[i][:16], font=font, fill="#CCCCCC")
        d.text((105, y), "ON" if active else "OFF", font=font,
               fill="#00FF00" if active else "#666")
        y += ROW_H

    with lock:
        count = len(alerts)
    d.text((2, y + 4), f"Alerts: {count}", font=font, fill="#FFAA00")
    d.text((120, 16 + cursor_pos * ROW_H), "<", font=font, fill="#FFF")
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Tog K1:Log K2:Cfg", font=font, fill="#AAA")
    LCD.LCD_ShowImage(img, 0, 0)

def _draw_log():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "ALERT LOG", font=font, fill="#FFAA00")

    with lock:
        log_copy = list(alerts)
    total = len(log_copy)

    if total == 0:
        d.text((2, 30), "No alerts yet", font=font, fill="#555")
    else:
        rev = list(reversed(log_copy))
        end = min(log_scroll + 8, total)
        y = 16
        for i in range(log_scroll, end):
            entry = rev[i]
            if entry.startswith("[") and "] " in entry:
                ts_part = entry[11:19] if len(entry) > 19 else ""
                msg_part = entry[entry.index("] ") + 2:]
                entry = f"{ts_part} {msg_part}"
            d.text((2, y), entry[:24], font=font, fill="#CCCCCC")
            y += ROW_H
        if total > 8:
            d.text((2, 116), f"{log_scroll + 1}-{end}/{total}",
                   font=font, fill="#666")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((60, 117), "K3:Back", font=font, fill="#AAA")
    LCD.LCD_ShowImage(img, 0, 0)

def _draw_config():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    name = TRIGGER_NAMES[cursor_pos]
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), f"CFG: {TRIGGER_LABELS[cursor_pos]}", font=font,
           fill="#00CCFF")

    with lock:
        cfg = dict(config[name])
    y = 20
    for key, val in cfg.items():
        if key == "enabled":
            continue
        d.text((2, y), f"{key}:", font=font, fill="#888")
        d.text((2, y + ROW_H), f"  {str(val)[:14]}", font=font, fill="#FFF")
        y += ROW_H * 2 + 2
    if not any(k != "enabled" for k in cfg):
        d.text((2, y), "No config options", font=font, fill="#555")

    d.text((2, 90), "UP/DN: adjust value", font=font, fill="#666")
    d.text((2, 102), "OK: save & back", font=font, fill="#666")
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Save  K3:Back", font=font, fill="#AAA")
    LCD.LCD_ShowImage(img, 0, 0)

def _config_adjust(direction):
    name = TRIGGER_NAMES[cursor_pos]
    with lock:
        for key, val in config[name].items():
            if key == "enabled":
                continue
            if isinstance(val, (int, float)):
                step = 5 if key == "threshold" else 1
                config[name][key] = max(1, val + step * direction)
                break
    _save_config()

def main():
    global cursor_pos, view_mode, log_scroll, _running

    _load_config()

    if os.path.isfile(ALERT_LOG_FILE):
        try:
            with open(ALERT_LOG_FILE, "r") as fh:
                with lock:
                    for line in fh.readlines()[-200:]:
                        if line.strip():
                            alerts.append(line.strip())
        except Exception:
            pass
    for name in TRIGGER_NAMES:
        with lock:
            enabled = config[name]["enabled"]
        if enabled:
            _start_trigger(name)
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 10), "EVENT TRIGGERS", font=font, fill="#00CCFF")
    d.text((4, 28), "Monitor WiFi events", font=font, fill="#888")
    d.text((4, 40), "and trigger alerts.", font=font, fill="#888")
    d.text((4, 58), "OK=Toggle  K1=Log", font=font, fill="#666")
    d.text((4, 70), "K2=Config  K3=Exit", font=font, fill="#666")
    with lock:
        active = sum(1 for n in TRIGGER_NAMES if config[n]["enabled"])
    d.text((4, 90), f"Active: {active}/{len(TRIGGER_NAMES)}", font=font,
           fill="#FFAA00")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if view_mode in ("log", "config"):
                    view_mode = "main"
                    time.sleep(0.2)
                else:
                    break
            elif view_mode == "main":
                if btn == "UP":
                    cursor_pos = max(0, cursor_pos - 1)
                    time.sleep(0.2)
                elif btn == "DOWN":
                    cursor_pos = min(len(TRIGGER_NAMES) - 1, cursor_pos + 1)
                    time.sleep(0.2)
                elif btn == "OK":
                    name = TRIGGER_NAMES[cursor_pos]
                    (_stop_trigger if _is_active(name) else _start_trigger)(name)
                    time.sleep(0.3)
                elif btn == "KEY1":
                    view_mode, log_scroll = "log", 0
                    time.sleep(0.2)
                elif btn == "KEY2":
                    view_mode = "config"
                    time.sleep(0.2)
            elif view_mode == "log":
                if btn == "UP":
                    log_scroll = max(0, log_scroll - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        mx = max(0, len(alerts) - 8)
                    log_scroll = min(log_scroll + 1, mx)
                    time.sleep(0.15)
                elif btn == "OK":
                    view_mode = "main"
                    time.sleep(0.2)
            elif view_mode == "config":
                if btn == "UP":
                    _config_adjust(1); time.sleep(0.2)
                elif btn == "DOWN":
                    _config_adjust(-1); time.sleep(0.2)
                elif btn == "OK":
                    view_mode = "main"; time.sleep(0.2)

            {"main": _draw_main, "log": _draw_log, "config": _draw_config
             }.get(view_mode, _draw_main)()
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
