#!/usr/bin/env python3
"""
RaspyJack Payload – RF Spectrum Analyzer
=========================================
Real-time spectrum analyzer with channel filters for targeted RF analysis.
Features dynamic display with auto-scaling, peak frequency detection, and
instant filter switching via LEFT/RIGHT buttons.

Bands (cycle with LEFT / RIGHT):
  2.4 GHz  – WiFi channels 1-13
  5 GHz    – WiFi channels 36-165
  ALL WiFi – both bands combined
  BLE Dev  – BLE devices by signal strength
  BT Freq  – BLE advertising channels overlaid on 2.4 GHz

Controls:
  LEFT / RIGHT – Cycle band filter
  KEY1         – Start / Stop scanning
  KEY2         – Exit
  KEY3         – Reset statistics and peak hold
  UP / DOWN    – Adjust channel dwell time (faster / slower sweep)

Author: dag nazty
"""

import os
import sys
import time
import struct
import socket
import threading
import subprocess
from collections import deque

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

import RPi.GPIO as GPIO                          # type: ignore
import LCD_1in44, LCD_Config                      # type: ignore
from PIL import Image, ImageDraw, ImageFont       # type: ignore
from payloads._input_helper import get_button

# Scapy (optional – WiFi capture won't work without it)
try:
    from scapy.all import Dot11, sniff as scapy_sniff  # type: ignore
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# BLE HCI constants (may be absent on non-Linux builds)
AF_BT    = getattr(socket, "AF_BLUETOOTH", 31)
BT_HCI   = getattr(socket, "BTPROTO_HCI", 1)
SOL_HCI  = getattr(socket, "SOL_HCI", 0)
HCI_FLT  = getattr(socket, "HCI_FILTER", 2)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
W, H = 128, 128

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}

BANDS = ["2.4 GHz", "5 GHz", "ALL WiFi", "BLE Dev", "BT Freq"]

CH24 = list(range(1, 14))
CH5  = [36, 40, 44, 48, 52, 56, 60, 64,
        100, 104, 108, 112, 116, 120, 124, 128,
        132, 136, 140, 149, 153, 157, 161, 165]
CHALL = CH24 + CH5

# BLE advertising channel → index in CH24 bar array (for BT Freq overlay)
BLE_ADV_IDX = {37: 0, 38: 5, 39: 12}

BLE_EXPIRE = 30        # seconds before a BLE device drops off
DWELL_MIN  = 0.10      # fastest channel hop  (seconds)
DWELL_MAX  = 2.00      # slowest channel hop
DWELL_STEP = 0.05

# Bar area geometry (shared by all views)
BAR_TOP = 15
BAR_BOT = 107
BAR_H   = BAR_BOT - BAR_TOP

# ---------------------------------------------------------------------------
# Mutable global state  (threads share via `lock`)
# ---------------------------------------------------------------------------
running   = False
band_idx  = 0
dwell     = 0.30       # current channel dwell time
cur_ch    = 1          # channel the adapter is currently on
mon_iface = None       # monitor-mode WiFi interface name
ble_ready = False      # True once HCI socket is open

# WiFi per-channel accumulators
chd   = {c: {"pkts": 0, "peak_rate": 0, "peak_dbm": -100,
             "sigs": deque(maxlen=64)} for c in CHALL}
rates = {c: 0 for c in CHALL}   # snapshot updated once/sec

# BLE per-device + advertising channel counters
ble_dev = {}                          # mac → {name, rssi, peak, seen}
ble_adv = {37: 0, 38: 0, 39: 0}      # packet count per adv channel

lock = threading.Lock()

# ===================================================================
# LCD helpers
# ===================================================================

def lcd_init():
    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    return lcd

# ===================================================================
# WiFi monitor-mode setup  (adapted from wardriving / cam_finder)
# ===================================================================

def find_iface():
    """Find a monitor-mode capable wireless interface."""
    ifs = []
    try:
        for n in os.listdir("/sys/class/net"):
            if n != "lo" and os.path.isdir(f"/sys/class/net/{n}/wireless"):
                ifs.append(n)
    except Exception:
        pass
    no_mon = {"brcmfmac", "b43", "wl"}
    good, fall = [], []
    for i in ifs:
        drv = ""
        try:
            drv = os.path.basename(
                os.path.realpath(f"/sys/class/net/{i}/device/driver"))
        except Exception:
            pass
        (fall if drv in no_mon else good).append(i)
    return (good or fall or [None])[0]


def monitor_up(iface):
    """Put *iface* into monitor mode. Returns interface name or None."""
    # Kill interfering services (with timeouts so nothing hangs)
    for cmd in [
        ["sudo", "systemctl", "stop", "NetworkManager"],
        ["sudo", "pkill", "-f", "wpa_supplicant"],
        ["sudo", "pkill", "-f", "dhcpcd"],
    ]:
        try:
            subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception:
            pass
    time.sleep(0.5)

    # Method 1 – airmon-ng
    try:
        subprocess.run(["sudo", "airmon-ng", "start", iface],
                       capture_output=True, timeout=30)
        for name in (f"{iface}mon", iface):
            r = subprocess.run(["iwconfig", name],
                               capture_output=True, text=True)
            if "Mode:Monitor" in r.stdout:
                return name
    except Exception:
        pass

    # Method 2 – iwconfig
    try:
        subprocess.run(["sudo", "ifconfig", iface, "down"],
                       check=True, timeout=10)
        subprocess.run(["sudo", "iwconfig", iface, "mode", "monitor"],
                       check=True, timeout=10)
        subprocess.run(["sudo", "ifconfig", iface, "up"],
                       check=True, timeout=10)
        time.sleep(1)
        r = subprocess.run(["iwconfig", iface],
                           capture_output=True, text=True, timeout=5)
        if "Mode:Monitor" in r.stdout:
            return iface
    except Exception:
        pass

    # Method 3 – iw
    try:
        subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                       check=True, timeout=10)
        subprocess.run(["sudo", "iw", iface, "set", "monitor", "none"],
                       check=True, timeout=10)
        subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                       check=True, timeout=10)
        time.sleep(1)
        r = subprocess.run(["iwconfig", iface],
                           capture_output=True, text=True, timeout=5)
        if "Mode:Monitor" in r.stdout:
            return iface
    except Exception:
        pass

    return None


def monitor_down(iface):
    """Best-effort restore to managed mode."""
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
        ["sudo", "systemctl", "start", "NetworkManager"],
    ]:
        try:
            subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception:
            pass

# ===================================================================
# WiFi threads
# ===================================================================

def _hop_thread():
    """Channel-hopper: cycles through the active band's channels."""
    global cur_ch
    idx = 0
    while running:
        band = BANDS[band_idx]
        if band in ("2.4 GHz", "BT Freq"):
            chs = CH24
        elif band == "5 GHz":
            chs = CH5
        else:                       # ALL WiFi, BLE Dev (keep WiFi alive)
            chs = CHALL
        if mon_iface:
            ch = chs[idx % len(chs)]
            try:
                subprocess.run(
                    ["sudo", "iw", "dev", mon_iface, "set", "channel", str(ch)],
                    capture_output=True, timeout=3)
                cur_ch = ch
            except Exception:
                pass
            idx += 1
        time.sleep(dwell)


def _wifi_cb(pkt):
    """Scapy per-packet callback."""
    if not pkt.haslayer(Dot11):
        return
    sig = getattr(pkt, "dBm_AntSignal", None)
    ch = cur_ch
    with lock:
        d = chd.get(ch)
        if d:
            d["pkts"] += 1
            if sig is not None:
                d["sigs"].append(sig)
                if sig > d["peak_dbm"]:
                    d["peak_dbm"] = sig


def _sniff_thread():
    """Scapy capture loop (management + data frames)."""
    if not SCAPY_OK or not mon_iface:
        return
    try:
        scapy_sniff(iface=mon_iface, prn=_wifi_cb,
                    filter="type mgt or type data",
                    stop_filter=lambda x: not running, store=0)
    except Exception:
        pass


def _rate_thread():
    """Snapshot packet counts once per second for display."""
    while running:
        with lock:
            for c in CHALL:
                rates[c] = chd[c]["pkts"]
                if chd[c]["pkts"] > chd[c]["peak_rate"]:
                    chd[c]["peak_rate"] = chd[c]["pkts"]
                chd[c]["pkts"] = 0
        time.sleep(1)

# ===================================================================
# BLE scanner  (raw HCI socket – no extra pip packages)
# ===================================================================

def _hci_opcode(ogf, ocf):
    return (ogf << 10) | ocf


def _ble_open():
    """Open HCI socket, enable LE passive scan. Returns socket or None."""
    try:
        subprocess.run(["sudo", "hciconfig", "hci0", "up"],
                       capture_output=True, timeout=5)
        time.sleep(0.3)
    except Exception:
        return None

    try:
        s = socket.socket(AF_BT, socket.SOCK_RAW, BT_HCI)
        s.bind((0,))
        s.settimeout(1.0)

        # HCI filter: receive HCI_EVENT_PKT with CMD_COMPLETE + LE_META
        #   type_mask   = 1 << 4          (HCI_EVENT_PKT = 0x04)
        #   evt_mask[0] = 1 << 14         (EVT_CMD_COMPLETE = 0x0E)
        #   evt_mask[1] = 1 << 30         (EVT_LE_META = 0x3E = bit 62-32)
        s.setsockopt(SOL_HCI, HCI_FLT,
                     struct.pack("<IIIH", 1 << 4, 1 << 14, 1 << 30, 0))

        # LE Set Scan Parameters: passive, 10 ms interval/window, public, all
        op = _hci_opcode(0x08, 0x000B)
        p = struct.pack("<BHHBB", 0x00, 0x0010, 0x0010, 0x00, 0x00)
        s.send(struct.pack("<BHB", 0x01, op, len(p)) + p)
        try:
            s.recv(256)           # eat command-complete
        except socket.timeout:
            pass

        # LE Set Scan Enable: on, no duplicate filter
        op = _hci_opcode(0x08, 0x000C)
        p = struct.pack("<BB", 0x01, 0x00)
        s.send(struct.pack("<BHB", 0x01, op, len(p)) + p)
        try:
            s.recv(256)
        except socket.timeout:
            pass

        return s
    except Exception:
        return None


def _ble_close(s):
    """Disable scan and close socket."""
    if not s:
        return
    try:
        op = _hci_opcode(0x08, 0x000C)
        p = struct.pack("<BB", 0x00, 0x00)
        s.send(struct.pack("<BHB", 0x01, op, len(p)) + p)
    except Exception:
        pass
    try:
        s.close()
    except Exception:
        pass


def _parse_adv(data):
    """Parse an LE Advertising Report event.

    Returns list of ``(mac, rssi, name)`` tuples.
    """
    out = []
    # Minimum: pkt_type(1) + evt(1) + plen(1) + sub(1) + num(1) = 5
    if len(data) < 5 or data[0] != 0x04 or data[1] != 0x3E:
        return out
    if data[3] != 0x02:       # subevent must be LE_ADV_REPORT
        return out
    try:
        num = data[4]
        off = 5
        for _ in range(num):
            if off + 9 > len(data):
                break
            addr = data[off + 2:off + 8]
            dlen = data[off + 8]
            off += 9

            mac = ":".join(f"{b:02X}" for b in reversed(addr))

            # Walk AD structures for a device name
            name = ""
            ad = data[off:off + dlen]
            j = 0
            while j < len(ad) - 1:
                al = ad[j]
                if al == 0 or j + al >= len(ad):
                    break
                if ad[j + 1] in (0x08, 0x09):  # Shortened / Complete Name
                    try:
                        name = bytes(ad[j + 2:j + 1 + al]).decode(
                            "utf-8", errors="ignore")
                    except Exception:
                        pass
                j += al + 1
            off += dlen

            rssi = (struct.unpack("b", bytes([data[off]]))[0]
                    if off < len(data) else -127)
            off += 1
            out.append((mac, rssi, name))
    except Exception:
        pass
    return out


def _ble_thread():
    """BLE scanner thread – reads advertising reports via HCI socket."""
    global ble_ready
    s = _ble_open()
    if not s:
        return
    ble_ready = True
    try:
        while running:
            try:
                data = s.recv(256)
            except socket.timeout:
                continue
            except Exception:
                continue

            now = time.time()
            for mac, rssi, name in _parse_adv(data):
                with lock:
                    if mac in ble_dev:
                        ble_dev[mac]["rssi"] = rssi
                        ble_dev[mac]["seen"] = now
                        if name:
                            ble_dev[mac]["name"] = name
                        if rssi > ble_dev[mac]["peak"]:
                            ble_dev[mac]["peak"] = rssi
                    else:
                        ble_dev[mac] = {
                            "name": name, "rssi": rssi,
                            "peak": rssi, "seen": now,
                        }
                    # Count against all 3 advertising channels
                    for ch in ble_adv:
                        ble_adv[ch] += 1
    finally:
        ble_ready = False
        _ble_close(s)

# ===================================================================
# Drawing
# ===================================================================

def _rgb(ratio):
    """Map 0.0 → green, 0.5 → yellow, 1.0 → red.  Returns (R,G,B)."""
    ratio = max(0.0, min(1.0, ratio))
    if ratio < 0.5:
        return (int(510 * ratio), 255, 0)
    return (255, int(510 * (1.0 - ratio)), 0)


def _header(d, font, band_name):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "ANALYZER", font=font, fill="#00FF00")
    if hasattr(d, "textbbox"):
        tw = d.textbbox((0, 0), band_name, font=font)[2]
    else:
        tw, _ = d.textsize(band_name, font=font)
    d.text((125 - tw, 1), band_name, font=font, fill="white")
    # Running indicator dot
    d.ellipse((121, 3, 125, 7), fill="#00FF00" if running else "#FF0000")


def _footer(d, font, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font, fill="#AAA")


def _colstr(rgb):
    return f"#{rgb[0]:02X}{rgb[1]:02X}{rgb[2]:02X}"


def _draw_wifi(d, font, channels):
    """WiFi bar graph for the given channel list. Returns footer string."""
    n = len(channels)
    gap = 1 if n <= 24 else 0
    bw = max(2, (120 - gap * (n - 1)) // n)
    total_w = bw * n + gap * (n - 1)
    x0 = (W - total_w) // 2

    with lock:
        r  = [rates.get(c, 0) for c in channels]
        pk = [chd[c]["peak_rate"] for c in channels]
        pd = [chd[c]["peak_dbm"] for c in channels]

    mx = max(max(r), 1)
    mp = max(max(pk), 1)

    for i, rate in enumerate(r):
        x = x0 + i * (bw + gap)
        if rate > 0:
            ratio = rate / mx
            h = max(1, int(ratio * BAR_H))
            d.rectangle((x, BAR_BOT - h, x + bw - 1, BAR_BOT),
                        fill=_colstr(_rgb(ratio)))
        # Peak-hold line (magenta)
        if pk[i] > 0:
            ph = max(1, int((pk[i] / mp) * BAR_H))
            d.line((x, BAR_BOT - ph, x + bw - 1, BAR_BOT - ph),
                   fill="#FF00FF")

    # Channel labels
    step = max(1, n // 7)
    for i in range(0, n, step):
        x = x0 + i * (bw + gap)
        d.text((x, 108), str(channels[i])[:3], font=font, fill="#666")

    bi = r.index(max(r))
    return f"Pk:Ch{channels[bi]} {pd[bi]}dBm {sum(r)}p/s"


def _draw_ble(d, font):
    """BLE device bar view. Returns footer string."""
    now = time.time()
    with lock:
        # Expire old entries
        for m in [m for m, v in ble_dev.items()
                  if now - v["seen"] > BLE_EXPIRE]:
            del ble_dev[m]
        devs = sorted(ble_dev.items(),
                       key=lambda kv: kv[1]["rssi"], reverse=True)[:12]

    if not devs:
        msg = "Scanning..." if ble_ready else "No BT adapter"
        d.text((25, 55), msg, font=font, fill="#666")
        return "BLE: 0 devices"

    n = len(devs)
    bw  = max(3, min(9, (118 - (n - 1)) // n))
    gap = 1
    total_w = bw * n + gap * (n - 1)
    x0 = (W - total_w) // 2
    bt, bb = BAR_TOP, 99
    bh = bb - bt

    for i, (mac, info) in enumerate(devs):
        x = x0 + i * (bw + gap)
        ratio = max(0.0, min(1.0, (info["rssi"] + 100) / 80.0))
        h = max(1, int(ratio * bh))
        d.rectangle((x, bb - h, x + bw - 1, bb), fill=_colstr(_rgb(ratio)))
        # Peak-hold line
        pr = max(0.0, min(1.0, (info["peak"] + 100) / 80.0))
        ph = max(1, int(pr * bh))
        d.line((x, bb - ph, x + bw - 1, bb - ph), fill="#FF00FF")
        # Device label
        lbl = (info["name"] or mac[-5:])[:4]
        d.text((x, 101), lbl[:3], font=font, fill="#666")

    best = devs[0][1]["rssi"]
    return f"BLE:{n} best:{best}dBm"


def _draw_btfreq(d, font):
    """2.4 GHz WiFi bars + cyan BLE advertising channel overlay."""
    n = len(CH24)
    bw, gap = 8, 1
    total_w = bw * n + gap * (n - 1)
    x0 = (W - total_w) // 2

    with lock:
        r   = [rates.get(c, 0) for c in CH24]
        adv = dict(ble_adv)

    mx = max(max(r), max(adv.values()), 1)

    # WiFi bars (green-yellow-red)
    for i, rate in enumerate(r):
        x = x0 + i * (bw + gap)
        if rate > 0:
            ratio = rate / mx
            h = max(1, int(ratio * BAR_H))
            d.rectangle((x, BAR_BOT - h, x + bw - 1, BAR_BOT),
                        fill=_colstr(_rgb(ratio)))

    # BLE overlay bars (cyan, narrower, centered on WiFi bar position)
    for ble_ch, idx in BLE_ADV_IDX.items():
        x = x0 + idx * (bw + gap) + 2
        cnt = adv.get(ble_ch, 0)
        if cnt > 0:
            ratio = cnt / mx
            h = max(1, int(ratio * BAR_H))
            d.rectangle((x, BAR_BOT - h, x + 3, BAR_BOT), fill="#00FFFF")

    # Channel labels
    for i in range(0, n, 2):
        x = x0 + i * (bw + gap)
        d.text((x, 108), str(CH24[i]), font=font, fill="#666")

    return f"WiFi:{sum(r)} BT:{sum(adv.values())}"


def draw_frame(lcd, font):
    """Render one complete frame to the LCD."""
    img = Image.new("RGB", (W, H), "black")
    d = ImageDraw.Draw(img)

    band = BANDS[band_idx]
    _header(d, font, band)

    if   band == "2.4 GHz":   ft = _draw_wifi(d, font, CH24)
    elif band == "5 GHz":     ft = _draw_wifi(d, font, CH5)
    elif band == "ALL WiFi":  ft = _draw_wifi(d, font, CHALL)
    elif band == "BLE Dev":   ft = _draw_ble(d, font)
    elif band == "BT Freq":   ft = _draw_btfreq(d, font)
    else:                     ft = ""

    _footer(d, font, ft or "")
    lcd.LCD_ShowImage(img, 0, 0)

# ===================================================================
# Start / stop / reset
# ===================================================================

def start_all():
    global running, mon_iface
    if running:
        return
    # WiFi monitor mode
    if not mon_iface:
        iface = find_iface()
        if iface:
            mon_iface = monitor_up(iface)
    running = True
    for fn in (_hop_thread, _sniff_thread, _rate_thread, _ble_thread):
        t = threading.Thread(target=fn, daemon=True)
        t.start()


def stop_all():
    global running
    running = False
    time.sleep(0.5)


def reset_stats():
    with lock:
        for c in CHALL:
            chd[c]["pkts"] = 0
            chd[c]["peak_rate"] = 0
            chd[c]["peak_dbm"] = -100
            chd[c]["sigs"].clear()
            rates[c] = 0
        ble_dev.clear()
        for ch in ble_adv:
            ble_adv[ch] = 0

# ===================================================================
# Main entry point
# ===================================================================

def main():
    global band_idx, dwell

    lcd = lcd_init()
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    font = ImageFont.load_default()

    # Splash screen
    img = Image.new("RGB", (W, H), "black")
    d = ImageDraw.Draw(img)
    d.text((16, 25), "RF ANALYZER", font=font, fill="#00FF00")
    d.text((4, 48), "KEY1  Start / Stop", font=font, fill="#888")
    d.text((4, 60), "KEY2  Exit", font=font, fill="#888")
    d.text((4, 72), "KEY3  Reset stats", font=font, fill="#888")
    d.text((4, 84), "L / R Change band", font=font, fill="#888")
    d.text((4, 96), "U / D Dwell speed", font=font, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY2":
                break
            elif btn == "KEY1":
                if running:
                    stop_all()
                else:
                    start_all()
                time.sleep(0.3)
            elif btn == "LEFT":
                band_idx = (band_idx - 1) % len(BANDS)
                time.sleep(0.2)
            elif btn == "RIGHT":
                band_idx = (band_idx + 1) % len(BANDS)
                time.sleep(0.2)
            elif btn == "KEY3":
                reset_stats()
                time.sleep(0.2)
            elif btn == "UP":
                dwell = max(DWELL_MIN, dwell - DWELL_STEP)
                time.sleep(0.15)
            elif btn == "DOWN":
                dwell = min(DWELL_MAX, dwell + DWELL_STEP)
                time.sleep(0.15)

            draw_frame(lcd, font)
            time.sleep(0.05)

    finally:
        stop_all()
        monitor_down(mon_iface)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
