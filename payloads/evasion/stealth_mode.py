#!/usr/bin/env python3
"""
RaspyJack Payload -- Stealth Mode Toggle
==========================================
Author: 7h30th3r0n3

One-click toggle to minimize the Pi's visible footprint:
  - Disable ACT/PWR LEDs
  - Reduce WiFi TX power to minimum
  - Randomize MAC addresses on all interfaces
  - Change hostname to generic name
  - Flush system logs and bash history
  - Disable syslog temporarily

All original values are saved and can be restored on deactivation.

Controls:
  OK        -- Toggle stealth on/off
  UP / DOWN -- Scroll checklist
  KEY1      -- Toggle individual items
  KEY3      -- Exit
"""

import os
import sys
import time
import random
import subprocess
import threading

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
LED_PATHS = {
    "ACT": ["/sys/class/leds/ACT/brightness", "/sys/class/leds/led0/brightness"],
    "PWR": ["/sys/class/leds/PWR/brightness", "/sys/class/leds/led1/brightness"],
}
STEALTH_HOSTNAME = "localhost"
WIFI_IFACE = "wlan0"
MIN_TX_POWER = "1"
GENERIC_OUI_PREFIXES = [
    "02:00:00", "02:42:ac", "02:50:00", "06:00:00",
]

# ---------------------------------------------------------------------------
# Stealth items
# ---------------------------------------------------------------------------
ITEMS = [
    {"id": "act_led", "label": "ACT LED off"},
    {"id": "pwr_led", "label": "PWR LED off"},
    {"id": "wifi_txpwr", "label": "WiFi TX min"},
    {"id": "mac_random", "label": "MAC randomize"},
    {"id": "hostname", "label": "Hostname generic"},
    {"id": "flush_logs", "label": "Flush logs"},
    {"id": "clear_hist", "label": "Clear history"},
    {"id": "disable_syslog", "label": "Disable syslog"},
]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
stealth_active = False
item_states = {item["id"]: False for item in ITEMS}
scroll_pos = 0
status_msg = "Ready"
ROWS_VISIBLE = 6

# Original values for restoration
_originals = {
    "act_led": "",
    "pwr_led": "",
    "wifi_txpwr": "",
    "macs": {},            # iface -> original mac
    "hostname": "",
    "syslog_was_active": False,
}


# ---------------------------------------------------------------------------
# Shell helpers
# ---------------------------------------------------------------------------

def _run(cmd, timeout=10):
    """Run a command, return (returncode, stdout)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return result.returncode, result.stdout.strip()
    except Exception as exc:
        return 1, str(exc)[:40]


def _read_file(path):
    """Read a single-line value from a sysfs file."""
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except Exception:
        return ""


def _write_file_sudo(path, value):
    """Write a value to a file using sudo tee."""
    try:
        proc = subprocess.run(
            ["sudo", "tee", path],
            input=value, capture_output=True, text=True, timeout=5,
        )
        return proc.returncode == 0
    except Exception:
        return False


def _get_mac(iface):
    """Get current MAC address."""
    path = f"/sys/class/net/{iface}/address"
    return _read_file(path)


def _generate_random_mac():
    """Generate a random locally-administered unicast MAC."""
    prefix = random.choice(GENERIC_OUI_PREFIXES)
    suffix = ":".join(f"{random.randint(0, 255):02x}" for _ in range(3))
    return f"{prefix}:{suffix}"


def _get_interfaces():
    """List network interfaces (excluding lo)."""
    try:
        entries = os.listdir("/sys/class/net")
        return [e for e in entries if e != "lo"]
    except Exception:
        return ["eth0", "wlan0"]


def _find_led_path(led_name):
    """Find the working sysfs path for an LED."""
    for path in LED_PATHS.get(led_name, []):
        if os.path.exists(path):
            return path
    return None


# ---------------------------------------------------------------------------
# Save originals
# ---------------------------------------------------------------------------

def _save_originals():
    """Capture current system state before modifications."""
    global _originals

    new_originals = dict(_originals)

    # ACT LED
    act_path = _find_led_path("ACT")
    if act_path:
        new_originals["act_led"] = _read_file(act_path)

    # PWR LED
    pwr_path = _find_led_path("PWR")
    if pwr_path:
        new_originals["pwr_led"] = _read_file(pwr_path)

    # WiFi TX power
    rc, out = _run(["iwconfig", WIFI_IFACE])
    if rc == 0:
        for line in out.splitlines():
            if "Tx-Power" in line:
                parts = line.split("Tx-Power=")
                if len(parts) > 1:
                    new_originals["wifi_txpwr"] = parts[1].split()[0]
                break

    # MAC addresses
    mac_dict = {}
    for iface in _get_interfaces():
        mac_dict[iface] = _get_mac(iface)
    new_originals["macs"] = mac_dict

    # Hostname
    rc, out = _run(["hostname"])
    if rc == 0:
        new_originals["hostname"] = out

    # Syslog status
    rc, out = _run(["systemctl", "is-active", "rsyslog"])
    new_originals["syslog_was_active"] = (out == "active")

    _originals = new_originals


# ---------------------------------------------------------------------------
# Stealth actions (enable)
# ---------------------------------------------------------------------------

def _enable_act_led():
    """Disable ACT LED."""
    path = _find_led_path("ACT")
    if path:
        _write_file_sudo(path, "0")
        # Also disable trigger
        trigger_path = path.replace("brightness", "trigger")
        if os.path.exists(trigger_path):
            _write_file_sudo(trigger_path, "none")
        return True
    return False


def _enable_pwr_led():
    """Disable PWR LED."""
    path = _find_led_path("PWR")
    if path:
        _write_file_sudo(path, "0")
        trigger_path = path.replace("brightness", "trigger")
        if os.path.exists(trigger_path):
            _write_file_sudo(trigger_path, "none")
        return True
    return False


def _enable_wifi_txpwr():
    """Reduce WiFi TX power to minimum."""
    rc, _ = _run(["sudo", "iwconfig", WIFI_IFACE, "txpower", MIN_TX_POWER])
    return rc == 0


def _enable_mac_random():
    """Randomize MAC on all interfaces."""
    success = True
    for iface in _get_interfaces():
        new_mac = _generate_random_mac()
        _run(["sudo", "ip", "link", "set", iface, "down"])
        rc, _ = _run(["sudo", "ip", "link", "set", iface, "address", new_mac])
        _run(["sudo", "ip", "link", "set", iface, "up"])
        if rc != 0:
            success = False
    return success


def _enable_hostname():
    """Change hostname to generic name."""
    rc, _ = _run(["sudo", "hostnamectl", "set-hostname", STEALTH_HOSTNAME])
    return rc == 0


def _enable_flush_logs():
    """Flush system logs."""
    _run(["sudo", "journalctl", "--vacuum-size=1M"])
    # Also clear common log files
    for logfile in ["/var/log/syslog", "/var/log/auth.log", "/var/log/messages"]:
        if os.path.exists(logfile):
            _write_file_sudo(logfile, "")
    return True


def _enable_clear_hist():
    """Clear bash history for all users."""
    for hist_path in [
        os.path.expanduser("~/.bash_history"),
        "/root/.bash_history",
        os.path.expanduser("~/.zsh_history"),
        "/root/.zsh_history",
    ]:
        if os.path.exists(hist_path):
            try:
                with open(hist_path, "w") as f:
                    f.write("")
            except PermissionError:
                _write_file_sudo(hist_path, "")
    _run(["bash", "-c", "history -c"])
    return True


def _enable_disable_syslog():
    """Disable rsyslog temporarily."""
    rc, _ = _run(["sudo", "systemctl", "stop", "rsyslog"])
    return rc == 0


# ---------------------------------------------------------------------------
# Stealth actions (disable / restore)
# ---------------------------------------------------------------------------

def _disable_act_led():
    """Restore ACT LED."""
    path = _find_led_path("ACT")
    if path:
        orig = _originals.get("act_led", "255")
        _write_file_sudo(path, orig if orig else "255")
        trigger_path = path.replace("brightness", "trigger")
        if os.path.exists(trigger_path):
            _write_file_sudo(trigger_path, "mmc0")
        return True
    return False


def _disable_pwr_led():
    """Restore PWR LED."""
    path = _find_led_path("PWR")
    if path:
        orig = _originals.get("pwr_led", "255")
        _write_file_sudo(path, orig if orig else "255")
        trigger_path = path.replace("brightness", "trigger")
        if os.path.exists(trigger_path):
            _write_file_sudo(trigger_path, "default-on")
        return True
    return False


def _disable_wifi_txpwr():
    """Restore WiFi TX power."""
    orig = _originals.get("wifi_txpwr", "20")
    if not orig:
        orig = "20"
    rc, _ = _run(["sudo", "iwconfig", WIFI_IFACE, "txpower", orig])
    return rc == 0


def _disable_mac_random():
    """Restore original MAC addresses."""
    orig_macs = _originals.get("macs", {})
    success = True
    for iface, mac in orig_macs.items():
        if not mac or mac == "N/A":
            continue
        _run(["sudo", "ip", "link", "set", iface, "down"])
        rc, _ = _run(["sudo", "ip", "link", "set", iface, "address", mac])
        _run(["sudo", "ip", "link", "set", iface, "up"])
        if rc != 0:
            success = False
    return success


def _disable_hostname():
    """Restore original hostname."""
    orig = _originals.get("hostname", "raspberrypi")
    if not orig:
        orig = "raspberrypi"
    rc, _ = _run(["sudo", "hostnamectl", "set-hostname", orig])
    return rc == 0


def _disable_disable_syslog():
    """Re-enable rsyslog."""
    if _originals.get("syslog_was_active", True):
        rc, _ = _run(["sudo", "systemctl", "start", "rsyslog"])
        return rc == 0
    return True


# Action dispatch tables
_ENABLE_ACTIONS = {
    "act_led": _enable_act_led,
    "pwr_led": _enable_pwr_led,
    "wifi_txpwr": _enable_wifi_txpwr,
    "mac_random": _enable_mac_random,
    "hostname": _enable_hostname,
    "flush_logs": _enable_flush_logs,
    "clear_hist": _enable_clear_hist,
    "disable_syslog": _enable_disable_syslog,
}

_DISABLE_ACTIONS = {
    "act_led": _disable_act_led,
    "pwr_led": _disable_pwr_led,
    "wifi_txpwr": _disable_wifi_txpwr,
    "mac_random": _disable_mac_random,
    "hostname": _disable_hostname,
    # flush_logs and clear_hist are not reversible
    "disable_syslog": _disable_disable_syslog,
}


# ---------------------------------------------------------------------------
# Toggle logic
# ---------------------------------------------------------------------------

def _activate_stealth():
    """Enable all stealth items."""
    global stealth_active, item_states, status_msg

    _save_originals()

    new_states = {}
    for item in ITEMS:
        iid = item["id"]
        action = _ENABLE_ACTIONS.get(iid)
        if action:
            ok = action()
            new_states[iid] = ok
        else:
            new_states[iid] = False

    with lock:
        item_states = new_states
        stealth_active = True
        failed = [item["label"] for item in ITEMS if not new_states[item["id"]]]
        if failed:
            status_msg = f"Partial: {len(failed)} failed"
        else:
            status_msg = "STEALTH ACTIVATED"


def _deactivate_stealth():
    """Restore all reversible stealth items."""
    global stealth_active, item_states, status_msg

    new_states = dict(item_states)
    for item in ITEMS:
        iid = item["id"]
        action = _DISABLE_ACTIONS.get(iid)
        if action and new_states.get(iid, False):
            action()
            new_states[iid] = False

    with lock:
        item_states = new_states
        stealth_active = False
        status_msg = "STEALTH DEACTIVATED"


def _toggle_item(item_id):
    """Toggle a single stealth item."""
    global item_states, status_msg

    with lock:
        currently_on = item_states.get(item_id, False)

    if currently_on:
        action = _DISABLE_ACTIONS.get(item_id)
        if action:
            ok = action()
            with lock:
                item_states = dict(item_states, **{item_id: not ok})
                status_msg = f"{'Restored' if ok else 'Fail'}: {item_id}"
        else:
            with lock:
                status_msg = f"Not reversible: {item_id}"
    else:
        if not _originals.get("hostname"):
            _save_originals()
        action = _ENABLE_ACTIONS.get(item_id)
        if action:
            ok = action()
            with lock:
                item_states = dict(item_states, **{item_id: ok})
                status_msg = f"{'Enabled' if ok else 'Fail'}: {item_id}"


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_screen():
    """Render the stealth mode interface."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        active = stealth_active
        states = dict(item_states)
        msg = status_msg
        sc = scroll_pos

    # Big status banner
    if active:
        d.rectangle((0, 0, 127, 20), fill="#003300")
        d.text((14, 4), "STEALTH ON", font=font, fill="#00FF00")
    else:
        d.rectangle((0, 0, 127, 20), fill="#330000")
        d.text((12, 4), "STEALTH OFF", font=font, fill="#FF4444")

    # Checklist
    visible_items = ITEMS[sc:sc + ROWS_VISIBLE]
    y = 24
    for i, item in enumerate(visible_items):
        global_idx = sc + i
        is_selected = (global_idx == sc)
        iid = item["id"]
        enabled = states.get(iid, False)

        check = "[X]" if enabled else "[ ]"
        color = "#00FF00" if enabled else "#FF4444"
        label_color = "#FFFFFF" if is_selected else "#CCCCCC"

        d.text((2, y), check, font=font, fill=color)
        d.text((24, y), item["label"][:16], font=font, fill=label_color)
        y += 13

    # Scroll indicators
    if sc > 0:
        d.text((118, 24), "^", font=font, fill="#666")
    if sc + ROWS_VISIBLE < len(ITEMS):
        d.text((118, 24 + (ROWS_VISIBLE - 1) * 13), "v", font=font, fill="#666")

    # Status message
    d.text((2, 104), msg[:22], font=font, fill="#FFAA00")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Toggle K1:Item K3:X", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global scroll_pos, status_msg

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 16), "STEALTH MODE", font=font, fill="#00FF00")
    d.text((4, 36), "Minimize Pi footprint", font=font, fill="#888")
    d.text((4, 48), "LEDs, WiFi, MAC, logs", font=font, fill="#888")
    d.text((4, 66), "OK=Toggle all", font=font, fill="#666")
    d.text((4, 78), "K1=Toggle item", font=font, fill="#666")
    d.text((4, 90), "UP/DN=Scroll K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.5)

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            if btn == "OK":
                with lock:
                    active = stealth_active
                if active:
                    _deactivate_stealth()
                else:
                    _activate_stealth()
                time.sleep(0.3)

            elif btn == "UP":
                with lock:
                    scroll_pos = max(0, scroll_pos - 1)
                time.sleep(0.15)

            elif btn == "DOWN":
                with lock:
                    scroll_pos = min(
                        max(0, len(ITEMS) - ROWS_VISIBLE),
                        scroll_pos + 1,
                    )
                time.sleep(0.15)

            elif btn == "KEY1":
                with lock:
                    idx = scroll_pos
                if idx < len(ITEMS):
                    _toggle_item(ITEMS[idx]["id"])
                time.sleep(0.3)

            _draw_screen()
            time.sleep(0.05)

    finally:
        # Restore everything on exit if stealth is still active
        with lock:
            active = stealth_active
        if active:
            _deactivate_stealth()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
