#!/usr/bin/env python3
"""
RaspyJack Payload -- Interface Manager
========================================
Author: 7h30th3r0n3

Centralized network interface management: rfkill, monitor mode,
up/down, IP config, driver info. One place to control all WiFi,
Ethernet, and Bluetooth interfaces.

Controls:
  UP / DOWN  -- Navigate interface list
  OK         -- Open action menu for selected interface
  KEY1       -- Refresh interface list
  KEY2       -- Quick toggle: rfkill block/unblock selected
  KEY3       -- Exit / back

Action menu (per interface):
  UP / DOWN  -- Navigate actions
  OK         -- Execute selected action
  KEY3       -- Back to interface list

Loot: /root/Raspyjack/loot/IfaceManager/
"""

import os
import sys
import time
import signal
import subprocess
import json
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROW_H = 12
LOOT_DIR = "/root/Raspyjack/loot/IfaceManager"

_running = True


def _cleanup(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)

# ---------------------------------------------------------------------------
# Interface detection
# ---------------------------------------------------------------------------

def _run(cmd, timeout=5):
    """Run a command and return stdout."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def _get_driver(iface):
    try:
        return os.path.basename(os.path.realpath(f"/sys/class/net/{iface}/device/driver"))
    except Exception:
        return ""


def _get_ip(iface):
    out = _run(["ip", "-4", "-o", "addr", "show", iface])
    for line in out.split("\n"):
        parts = line.split()
        for i, p in enumerate(parts):
            if p == "inet" and i + 1 < len(parts):
                return parts[i + 1]
    return ""


def _get_mac(iface):
    try:
        with open(f"/sys/class/net/{iface}/address", "r") as f:
            return f.read().strip().upper()
    except Exception:
        return ""


def _get_operstate(iface):
    try:
        with open(f"/sys/class/net/{iface}/operstate", "r") as f:
            return f.read().strip()
    except Exception:
        return "unknown"


def _get_mode(iface):
    """Return WiFi mode: Managed, Monitor, Master/AP, or ''."""
    out = _run(["iw", "dev", iface, "info"])
    if "type monitor" in out:
        return "Monitor"
    if "type AP" in out:
        return "Master"
    if "type managed" in out:
        return "Managed"
    # Try to extract any type
    import re
    m = re.search(r"type\s+(\S+)", out)
    if m:
        return m.group(1).capitalize()
    return ""


def _is_wifi(iface):
    return os.path.isdir(f"/sys/class/net/{iface}/wireless")


def _is_bluetooth(iface):
    return iface.startswith("hci")


def _get_rfkill_state():
    """Return dict {index: {type, soft, hard, device}}."""
    out = _run(["rfkill", "--json"])
    if not out:
        # Fallback: parse rfkill list
        out = _run(["rfkill", "list"])
        result = {}
        current = None
        for line in out.split("\n"):
            if line and line[0].isdigit() and ":" in line:
                idx = line.split(":")[0].strip()
                rest = line.split(":", 1)[1].strip()
                dev_type = "bluetooth" if "Bluetooth" in rest else "wlan" if "Wireless" in rest else rest
                current = idx
                result[idx] = {"type": dev_type, "soft": False, "hard": False, "device": rest}
            elif current and "Soft blocked" in line:
                result[current]["soft"] = "yes" in line.lower()
            elif current and "Hard blocked" in line:
                result[current]["hard"] = "yes" in line.lower()
        return result

    try:
        data = json.loads(out)
        result = {}
        for item in data.get("rfkilldevices", data.get("", [])):
            idx = str(item.get("id", ""))
            result[idx] = {
                "type": item.get("type", ""),
                "soft": item.get("soft", "") == "blocked",
                "hard": item.get("hard", "") == "blocked",
                "device": item.get("device", ""),
            }
        return result
    except Exception:
        return {}


def _supports_mode(iface, mode):
    try:
        phy_link = os.path.realpath(f"/sys/class/net/{iface}/phy80211")
        phy_name = os.path.basename(phy_link)
        out = _run(["iw", "phy", phy_name, "info"])
        return f"* {mode}" in out
    except Exception:
        return False


def _scan_interfaces():
    """Return list of all network interface info dicts."""
    ifaces = []

    # Network interfaces
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if name == "lo" or name.startswith(("veth", "br-", "docker", "virbr")):
                continue
            is_wifi = _is_wifi(name)
            info = {
                "name": name,
                "type": "wifi" if is_wifi else "eth",
                "driver": _get_driver(name),
                "mac": _get_mac(name),
                "ip": _get_ip(name),
                "state": _get_operstate(name),
                "mode": _get_mode(name) if is_wifi else "",
                "supports_mon": _supports_mode(name, "monitor") if is_wifi else False,
                "supports_ap": _supports_mode(name, "AP") if is_wifi else False,
                "rfkill_soft": False,
                "rfkill_hard": False,
            }
            ifaces.append(info)
    except Exception:
        pass

    # Bluetooth (hci)
    hci_out = _run(["hciconfig"])
    for line in hci_out.split("\n"):
        if line and not line[0].isspace() and ":" in line:
            name = line.split(":")[0].strip()
            state = "up" if "UP RUNNING" in hci_out else "down"
            mac = ""
            for l2 in hci_out.split("\n"):
                if "BD Address:" in l2:
                    parts = l2.split("BD Address:")
                    if len(parts) > 1:
                        mac = parts[1].strip().split()[0]
                    break
            ifaces.append({
                "name": name,
                "type": "bluetooth",
                "driver": "hci",
                "mac": mac,
                "ip": "",
                "state": state,
                "mode": "",
                "supports_mon": False,
                "supports_ap": False,
                "rfkill_soft": False,
                "rfkill_hard": False,
            })

    # Apply rfkill states
    rfk = _get_rfkill_state()
    for idx, rinfo in rfk.items():
        rtype = rinfo["type"].lower()
        for ifc in ifaces:
            if rtype == "bluetooth" and ifc["type"] == "bluetooth":
                ifc["rfkill_soft"] = rinfo["soft"]
                ifc["rfkill_hard"] = rinfo["hard"]
            elif rtype in ("wlan", "wireless") and ifc["type"] == "wifi":
                ifc["rfkill_soft"] = rinfo["soft"]
                ifc["rfkill_hard"] = rinfo["hard"]

    return ifaces

# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

def _set_up(iface):
    _run(["sudo", "ip", "link", "set", iface, "up"])


def _set_down(iface):
    _run(["sudo", "ip", "link", "set", iface, "down"])


def _set_monitor(iface):
    """Switch WiFi interface to monitor mode."""
    _run(["sudo", "ip", "link", "set", iface, "down"])
    # Try airmon-ng first
    out = _run(["sudo", "airmon-ng", "start", iface], timeout=15)
    if "monitor mode" in out.lower() or "enabled" in out.lower():
        return f"{iface} -> monitor (airmon)"
    # Fallback to iw
    _run(["sudo", "iw", iface, "set", "monitor", "none"])
    _run(["sudo", "ip", "link", "set", iface, "up"])
    mode = _get_mode(iface)
    if mode == "Monitor":
        return f"{iface} -> Monitor"
    # Check if mon interface was created
    mon_name = f"{iface}mon"
    if os.path.exists(f"/sys/class/net/{mon_name}"):
        return f"{mon_name} created"
    return "Monitor mode failed"


def _set_managed(iface):
    """Switch WiFi interface back to managed mode."""
    base = iface[:-3] if iface.endswith("mon") else iface
    _run(["sudo", "airmon-ng", "stop", iface], timeout=10)
    _run(["sudo", "ip", "link", "set", base, "down"])
    _run(["sudo", "iw", base, "set", "type", "managed"])
    _run(["sudo", "ip", "link", "set", base, "up"])
    _run(["sudo", "nmcli", "device", "set", base, "managed", "yes"], timeout=5)
    return f"{base} -> Managed"


def _restore_network():
    """Re-manage all WiFi interfaces + restart NetworkManager.

    Fixes broken state after payloads that kill wpa_supplicant or
    set interfaces to unmanaged.
    """
    # Re-manage all WiFi interfaces
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if os.path.isdir(f"/sys/class/net/{name}/wireless"):
                _run(["sudo", "nmcli", "device", "set", name, "managed", "yes"], timeout=5)
    except Exception:
        pass
    # Unblock rfkill
    _run(["sudo", "rfkill", "unblock", "wifi"], timeout=3)
    # Restart NetworkManager + wpa_supplicant
    _run(["sudo", "systemctl", "restart", "NetworkManager"], timeout=10)
    _run(["sudo", "systemctl", "restart", "wpa_supplicant"], timeout=10)
    return "Network restored"


def _rfkill_toggle(iface_info):
    """Toggle rfkill soft block for an interface."""
    itype = iface_info["type"]
    rf_type = "bluetooth" if itype == "bluetooth" else "wifi"
    if iface_info["rfkill_soft"]:
        _run(["sudo", "rfkill", "unblock", rf_type])
        return f"{rf_type} unblocked"
    else:
        _run(["sudo", "rfkill", "block", rf_type])
        return f"{rf_type} blocked"


def _rfkill_unblock_all():
    _run(["sudo", "rfkill", "unblock", "all"])
    return "All unblocked"


def _hci_up(iface):
    _run(["sudo", "hciconfig", iface, "up"])
    return f"{iface} up"


def _hci_down(iface):
    _run(["sudo", "hciconfig", iface, "down"])
    return f"{iface} down"


def _get_actions(iface_info):
    """Return list of available actions for an interface."""
    actions = []
    name = iface_info["name"]
    itype = iface_info["type"]
    state = iface_info["state"]

    if itype == "bluetooth":
        actions.append(("HCI Up", lambda: _hci_up(name)))
        actions.append(("HCI Down", lambda: _hci_down(name)))
        if iface_info["rfkill_soft"]:
            actions.append(("RF Unblock", lambda: _rfkill_toggle(iface_info)))
        else:
            actions.append(("RF Block", lambda: _rfkill_toggle(iface_info)))
        return actions

    # Network interfaces
    if state != "up":
        actions.append(("Bring UP", lambda: (_set_up(name), f"{name} up")[1]))
    else:
        actions.append(("Bring DOWN", lambda: (_set_down(name), f"{name} down")[1]))

    if itype == "wifi":
        mode = iface_info["mode"]
        # wlan0 onboard (brcmfmac) cannot do monitor/injection
        is_onboard = iface_info.get("driver") == "brcmfmac"
        if mode != "Monitor" and iface_info["supports_mon"] and not is_onboard:
            actions.append(("Enable Monitor", lambda: _set_monitor(name)))
        if mode == "Monitor":
            actions.append(("Disable Monitor", lambda: _set_managed(name)))
        if iface_info["supports_ap"] and mode != "Master":
            actions.append(("(AP via payload)", lambda: "Use evil_twin/captive_portal"))

        # NM re-manage
        actions.append(("NM Re-manage", lambda: (
            _run(["sudo", "nmcli", "device", "set", name, "managed", "yes"], timeout=5),
            f"{name} re-managed")[1]))

        if iface_info["rfkill_soft"]:
            actions.append(("RF Unblock", lambda: _rfkill_toggle(iface_info)))
        else:
            actions.append(("RF Block", lambda: _rfkill_toggle(iface_info)))

    actions.append(("Unblock ALL RF", lambda: _rfkill_unblock_all()))
    actions.append(("Restore Network", lambda: _restore_network()))

    return actions

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_list(lcd, font_obj, ifaces, sel, scroll):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), f"IFACE MANAGER ({len(ifaces)})", font=font_obj, fill="#58a6ff")

    visible = ifaces[scroll:scroll + 7]
    for i, ifc in enumerate(visible):
        y = 16 + i * 14
        idx = scroll + i
        prefix = ">" if idx == sel else " "

        # Color by state
        if ifc["rfkill_soft"] or ifc["rfkill_hard"]:
            color = "#FF4444" if idx != sel else "#FF6666"
            state_tag = "BLOCKED"
        elif ifc["state"] == "up":
            color = "#00FF00" if idx == sel else "#88CC88"
            state_tag = "UP"
        else:
            color = "#CCCCCC" if idx == sel else "#666666"
            state_tag = "DOWN"

        name = ifc["name"]
        mode = ifc["mode"]
        if mode:
            tag = f"{mode[:3]} {state_tag}"
        elif ifc["type"] == "bluetooth":
            tag = f"BT {state_tag}"
        else:
            tag = state_tag

        d.text((2, y), f"{prefix}{name}", font=font_obj, fill=color)
        d.text((70, y), tag[:10], font=font_obj, fill="#FFAA00" if idx == sel else "#888")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Act K1:Ref K2:RF K3:X", font=font_obj, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_detail(lcd, font_obj, ifc):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), ifc["name"], font=font_obj, fill="#58a6ff")

    y = 18
    fields = [
        ("Type", ifc["type"]),
        ("Driver", ifc["driver"] or "?"),
        ("MAC", ifc["mac"] or "?"),
        ("IP", ifc["ip"] or "none"),
        ("State", ifc["state"]),
    ]
    if ifc["type"] == "wifi":
        fields.append(("Mode", ifc["mode"] or "?"))
        fields.append(("Monitor", "Yes" if ifc["supports_mon"] else "No"))
        fields.append(("AP", "Yes" if ifc["supports_ap"] else "No"))

    rfk = ""
    if ifc["rfkill_hard"]:
        rfk = "HARD BLOCKED"
    elif ifc["rfkill_soft"]:
        rfk = "SOFT BLOCKED"
    if rfk:
        fields.append(("RFKill", rfk))

    for label, val in fields[:8]:
        d.text((2, y), f"{label}: {val[:18]}", font=font_obj, fill="#CCCCCC")
        y += 12

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "Any key: back", font=font_obj, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_actions(lcd, font_obj, ifc, actions, sel):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), f"{ifc['name']} ACTIONS", font=font_obj, fill="#FFAA00")

    for i, (label, _fn) in enumerate(actions):
        y = 18 + i * 14
        prefix = ">" if i == sel else " "
        color = "#00FF00" if i == sel else "#CCCCCC"
        d.text((2, y), f"{prefix}{label}", font=font_obj, fill=color)

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Run LEFT:Info K3:Bk", font=font_obj, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_result(lcd, font_obj, msg):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 13), fill="#002200")
    d.text((2, 1), "RESULT", font=font_obj, fill="#00FF00")
    # Word wrap
    words = msg.split()
    lines = []
    current = ""
    for w in words:
        if len(current) + len(w) + 1 > 22:
            lines.append(current)
            current = w
        else:
            current = f"{current} {w}" if current else w
    if current:
        lines.append(current)
    for i, line in enumerate(lines[:6]):
        d.text((4, 20 + i * 14), line, font=font_obj, fill="#CCCCCC")
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "Any key: back", font=font_obj, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font_obj = scaled_font()

    ifaces = _scan_interfaces()
    sel = 0
    scroll = 0
    view = "list"  # list | actions | detail | result
    action_sel = 0
    actions = []
    result_msg = ""

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if view == "list":
                if btn == "KEY3":
                    break
                elif btn == "UP":
                    sel = max(0, sel - 1)
                    if sel < scroll:
                        scroll = sel
                    time.sleep(0.15)
                elif btn == "DOWN":
                    sel = min(len(ifaces) - 1, sel + 1)
                    if sel >= scroll + 7:
                        scroll = sel - 6
                    time.sleep(0.15)
                elif btn == "OK" and ifaces:
                    actions = _get_actions(ifaces[sel])
                    action_sel = 0
                    view = "actions"
                    time.sleep(0.3)
                elif btn == "KEY1":
                    ifaces = _scan_interfaces()
                    sel = min(sel, max(0, len(ifaces) - 1))
                    time.sleep(0.3)
                elif btn == "KEY2" and ifaces:
                    result_msg = _rfkill_toggle(ifaces[sel])
                    ifaces = _scan_interfaces()
                    view = "result"
                    time.sleep(0.3)
                elif btn == "LEFT" and ifaces:
                    view = "detail"
                    time.sleep(0.3)

                _draw_list(lcd, font_obj, ifaces, sel, scroll)

            elif view == "actions":
                if btn == "KEY3":
                    view = "list"
                    time.sleep(0.3)
                elif btn == "UP":
                    action_sel = max(0, action_sel - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    action_sel = min(len(actions) - 1, action_sel + 1)
                    time.sleep(0.15)
                elif btn == "OK" and actions:
                    _label, fn = actions[action_sel]
                    result_msg = str(fn())
                    ifaces = _scan_interfaces()
                    sel = min(sel, max(0, len(ifaces) - 1))
                    view = "result"
                    time.sleep(0.3)
                elif btn == "LEFT" and ifaces:
                    view = "detail"
                    time.sleep(0.3)

                if view == "actions":
                    _draw_actions(lcd, font_obj, ifaces[sel], actions, action_sel)

            elif view == "detail":
                if btn:
                    view = "list"
                    time.sleep(0.3)
                _draw_detail(lcd, font_obj, ifaces[sel])

            elif view == "result":
                if btn:
                    view = "list"
                    time.sleep(0.3)
                _draw_result(lcd, font_obj, result_msg)

            time.sleep(0.05)

    finally:
        _running = False
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
