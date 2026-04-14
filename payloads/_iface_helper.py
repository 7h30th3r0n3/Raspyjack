"""
Shared network interface detection and LCD selection helper.

Usage in a payload:
    from payloads._iface_helper import select_interface

    # WiFi only (for deauth, evil_twin, etc.)
    iface = select_interface(lcd, font, pins, gpio, iface_type="wifi")

    # Ethernet only (for arp_mitm, vlan_hopper, etc.)
    iface = select_interface(lcd, font, pins, gpio, iface_type="eth")

    # Any network interface (for mixed payloads)
    iface = select_interface(lcd, font, pins, gpio, iface_type="any")

    # Returns iface name (str) or None if user cancelled / none found.
    # If only 1 interface matches, auto-selects it (no menu shown).
"""

import os
import subprocess
import time

from payloads._input_helper import get_button

try:
    from payloads._display_helper import ScaledDraw
    from PIL import Image
except Exception:
    ScaledDraw = None
    Image = None


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def _get_driver(iface):
    """Return kernel driver name for an interface."""
    try:
        return os.path.basename(
            os.path.realpath(f"/sys/class/net/{iface}/device/driver")
        )
    except Exception:
        return ""


def _is_onboard_wifi(iface):
    """True for the onboard RPi WiFi (SDIO / brcmfmac)."""
    try:
        devpath = os.path.realpath(f"/sys/class/net/{iface}/device")
        if "mmc" in devpath:
            return True
    except Exception:
        pass
    return _get_driver(iface) == "brcmfmac"


# Drivers known to support monitor+injection but not reporting it via nl80211
_KNOWN_MONITOR_DRIVERS = {
    "rtl88XXau", "rtl8812au", "rtl8821au", "rtl88x2bu",
    "rtl8188eus", "rtl8187", "rt2800usb", "ath9k_htc",
    "mt76x2u", "mt76x0u", "mt7921u", "rtl8814au",
    "rtl8192cu", "mt7601u",
}


def _supports_mode(iface, mode="AP"):
    """Check if a WiFi interface supports a given mode (AP, monitor, etc.).

    For monitor mode: first checks iw phy info, then falls back to
    driver name matching for known-good drivers that don't report
    capabilities correctly via nl80211 (common with out-of-tree Realtek).
    """
    try:
        phy_link = os.path.realpath(f"/sys/class/net/{iface}/phy80211")
        phy_name = os.path.basename(phy_link)
        r = subprocess.run(
            ["iw", "phy", phy_name, "info"],
            capture_output=True, text=True, timeout=5,
        )
        if f"* {mode}" in r.stdout:
            return True
    except Exception:
        pass

    # Fallback for monitor mode: check driver name against known-good list
    if mode == "monitor":
        driver = _get_driver(iface)
        if driver in _KNOWN_MONITOR_DRIVERS:
            return True

    return False


def _get_ip(iface):
    """Return first IPv4 address of an interface, or ''."""
    try:
        r = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", iface],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.strip().split("\n"):
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "inet" and i + 1 < len(parts):
                    return parts[i + 1].split("/")[0]
    except Exception:
        pass
    return ""


def _is_up(iface):
    """Return True if the interface has operstate 'up'."""
    try:
        with open(f"/sys/class/net/{iface}/operstate", "r") as f:
            return f.read().strip().lower() == "up"
    except Exception:
        return False


def list_interfaces(iface_type="any"):
    """
    Return list of interface info dicts matching the requested type.

    iface_type:
        "wifi"  -- only wlan* interfaces
        "eth"   -- only eth*, enp*, ens*, usb* (non-wireless)
        "any"   -- all non-loopback, non-virtual interfaces

    Each dict: {name, driver, is_onboard, is_wifi, is_up, ip, supports_ap, supports_monitor}
    Sorted: USB WiFi first, then onboard WiFi, then Ethernet.
    """
    result = []
    try:
        all_ifaces = sorted(os.listdir("/sys/class/net"))
    except Exception:
        return result

    for name in all_ifaces:
        if name == "lo":
            continue

        is_wifi = os.path.isdir(f"/sys/class/net/{name}/wireless")
        is_virtual = os.path.islink(f"/sys/class/net/{name}/device") is False
        # Skip docker/veth/br/tailscale for "any" mode
        if name.startswith(("veth", "br-", "docker", "virbr")):
            continue

        if iface_type == "wifi" and not is_wifi:
            continue
        if iface_type == "eth" and is_wifi:
            continue

        driver = _get_driver(name)
        onboard = _is_onboard_wifi(name) if is_wifi else False
        ip = _get_ip(name)
        up = _is_up(name)

        info = {
            "name": name,
            "driver": driver,
            "is_onboard": onboard,
            "is_wifi": is_wifi,
            "is_up": up,
            "ip": ip,
            "supports_ap": _supports_mode(name, "AP") if is_wifi else False,
            "supports_monitor": _supports_mode(name, "monitor") if is_wifi else False,
        }
        result.append(info)

    # Sort: USB WiFi first, onboard WiFi next, then eth by name
    def _sort_key(i):
        if i["is_wifi"]:
            return (0 if not i["is_onboard"] else 1, i["name"])
        return (2, i["name"])

    return sorted(result, key=_sort_key)


# ---------------------------------------------------------------------------
# LCD selector
# ---------------------------------------------------------------------------

def select_interface(lcd, font, pins, gpio, iface_type="any", title=None,
                     require_monitor=False):
    """
    Detect interfaces and let the user pick one on LCD.

    Returns the selected interface name (str) or None if cancelled/not found.
    If only one interface matches, auto-selects it without showing the menu.

    Parameters:
        lcd       -- LCD object (LCD_1in44.LCD instance)
        font      -- font from scaled_font()
        pins      -- PINS dict
        gpio      -- RPi.GPIO module
        iface_type -- "wifi", "eth", or "any"
        title     -- optional custom header text
        require_monitor -- if True, only show interfaces that support monitor mode
    """
    ifaces = list_interfaces(iface_type)

    if require_monitor:
        ifaces = [i for i in ifaces if i.get("supports_monitor")]

    if not ifaces:
        if require_monitor:
            _show_message(lcd, font, "No monitor iface!", "#FF4444")
            _show_message(lcd, font, "Need USB WiFi dongle", "#FFAA00")
        else:
            _show_message(lcd, font, "No interface found!", "#FF4444")
        return None

    # Auto-select if only one
    if len(ifaces) == 1:
        return ifaces[0]["name"]

    # Interactive selection
    if title is None:
        titles = {"wifi": "SELECT WIFI", "eth": "SELECT ETHERNET", "any": "SELECT INTERFACE"}
        title = titles.get(iface_type, "SELECT INTERFACE")

    sel = 0
    WIDTH, HEIGHT = lcd.width, lcd.height

    while True:
        btn = get_button(pins, gpio)
        if btn == "KEY3":
            return None
        elif btn == "OK":
            return ifaces[sel]["name"]
        elif btn == "UP":
            sel = max(0, sel - 1)
            time.sleep(0.15)
        elif btn == "DOWN":
            sel = min(len(ifaces) - 1, sel + 1)
            time.sleep(0.15)

        # Draw
        if Image is None or ScaledDraw is None:
            time.sleep(0.05)
            continue

        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)

        # Header
        d.rectangle((0, 0, 127, 13), fill="#111")
        d.text((2, 1), title, font=font, fill="#58a6ff")

        # Interface list
        scroll = max(0, sel - 5)
        visible = ifaces[scroll:scroll + 7]

        for i, ifc in enumerate(visible):
            y = 16 + i * 14
            idx = scroll + i
            prefix = ">" if idx == sel else " "
            name = ifc["name"]

            # Build tag: USB/onboard + AP/mon/eth
            if ifc["is_wifi"]:
                src = "USB" if not ifc["is_onboard"] else "RPi"
                caps = []
                if ifc["supports_ap"]:
                    caps.append("AP")
                if ifc["supports_monitor"]:
                    caps.append("mon")
                tag = f"{src} {'+'.join(caps)}" if caps else src
            else:
                tag = "ETH"
                if ifc["ip"]:
                    tag += f" {ifc['ip'][:12]}"

            color = "#00FF00" if idx == sel else "#CCCCCC"
            up_color = color if ifc["is_up"] else "#666666"

            d.text((2, y), f"{prefix}{name}", font=font, fill=up_color)
            d.text((62, y), tag[:12], font=font, fill="#FFAA00" if idx == sel else "#888")

        # Footer
        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "OK:Select KEY3:Cancel", font=font, fill="#888")

        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(0.05)


# ---------------------------------------------------------------------------
# Bluetooth interface detection + selection
# ---------------------------------------------------------------------------

def list_bt_interfaces():
    """Return list of Bluetooth HCI interfaces with info."""
    result = []
    bt_path = "/sys/class/bluetooth"
    if not os.path.isdir(bt_path):
        return result
    for name in sorted(os.listdir(bt_path)):
        if not name.startswith("hci"):
            continue
        info = {"name": name, "bus": "", "mac": "", "is_up": False, "bt_version": ""}
        # Bus type
        try:
            devpath = os.path.realpath(os.path.join(bt_path, name, "device"))
            if "usb" in devpath:
                info["bus"] = "USB"
            elif "uart" in devpath or "serial" in devpath:
                info["bus"] = "onboard"
            else:
                info["bus"] = "other"
        except Exception:
            pass
        # MAC + state from hciconfig
        try:
            r = subprocess.run(["hciconfig", name], capture_output=True, text=True, timeout=5)
            out = r.stdout
            if "UP RUNNING" in out:
                info["is_up"] = True
            for line in out.split("\n"):
                if "BD Address:" in line:
                    info["mac"] = line.split("BD Address:")[1].strip().split()[0]
                if "HCI Version:" in line:
                    info["bt_version"] = line.split("HCI Version:")[1].strip().split("(")[0].strip()
        except Exception:
            pass
        result.append(info)
    # Sort: USB first, then onboard
    return sorted(result, key=lambda x: (0 if x["bus"] == "USB" else 1, x["name"]))


def select_bt_interface(lcd, font, pins, gpio, title="SELECT BLUETOOTH"):
    """
    Detect BT interfaces and let the user pick one on LCD.
    Returns hci name (e.g. 'hci0') or None.
    Auto-selects if only one found.
    """
    ifaces = list_bt_interfaces()

    if not ifaces:
        _show_message(lcd, font, "No BT adapter found!", "#FF4444")
        return None

    if len(ifaces) == 1:
        # Auto-ensure it's UP
        if not ifaces[0]["is_up"]:
            subprocess.run(["sudo", "hciconfig", ifaces[0]["name"], "up"],
                           capture_output=True, timeout=5)
        return ifaces[0]["name"]

    sel = 0
    WIDTH, HEIGHT = lcd.width, lcd.height

    while True:
        btn = get_button(pins, gpio)
        if btn == "KEY3":
            return None
        elif btn == "OK":
            chosen = ifaces[sel]
            if not chosen["is_up"]:
                subprocess.run(["sudo", "hciconfig", chosen["name"], "up"],
                               capture_output=True, timeout=5)
            return chosen["name"]
        elif btn == "UP":
            sel = max(0, sel - 1)
            time.sleep(0.15)
        elif btn == "DOWN":
            sel = min(len(ifaces) - 1, sel + 1)
            time.sleep(0.15)

        if Image is None or ScaledDraw is None:
            time.sleep(0.05)
            continue

        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)

        d.rectangle((0, 0, 127, 13), fill="#111")
        d.text((2, 1), title, font=font, fill="#0088FF")

        for i, ifc in enumerate(ifaces):
            y = 18 + i * 18
            prefix = ">" if i == sel else " "
            name = ifc["name"]
            bus = ifc["bus"] or "?"
            mac_short = ifc["mac"][-8:] if ifc["mac"] else "?"
            up_str = "UP" if ifc["is_up"] else "DOWN"

            color = "#00FF00" if i == sel else "#CCCCCC"
            state_color = "#00FF00" if ifc["is_up"] else "#FF4444"

            d.text((2, y), f"{prefix}{name}", font=font, fill=color)
            d.text((50, y), bus[:6], font=font, fill="#FFAA00" if i == sel else "#888")
            d.text((2, y + 10), f"  {mac_short} {up_str}", font=font, fill=state_color)

        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "OK:Select KEY3:Cancel", font=font, fill="#888")

        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(0.05)


def _show_message(lcd, font, text, color="#FF4444"):
    """Show a brief error/info message on LCD."""
    if Image is None or ScaledDraw is None:
        return
    WIDTH, HEIGHT = lcd.width, lcd.height
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), text[:24], font=font, fill=color)
    lcd.LCD_ShowImage(img, 0, 0)
    time.sleep(2)
