#!/usr/bin/env bash
# RaspyJack installation / bootstrap script
# ------------------------------------------------------------
# * Idempotent   – safe to run multiple times
# * Bookworm‑ready – handles /boot/firmware/config.txt move
# * Enables I²C/SPI, installs all deps, sets up systemd units
# * Ends with a health‑check (SPI nodes + Python imports)
# * NEW: WiFi attack support with aircrack-ng and USB dongle tools
# ------------------------------------------------------------
set -euo pipefail

# ───── helpers ───────────────────────────────────────────────
step()  { printf "\e[1;34m[STEP]\e[0m %s\n"  "$*"; }
info()  { printf "\e[1;32m[INFO]\e[0m %s\n"  "$*"; }
warn()  { printf "\e[1;33m[WARN]\e[0m %s\n"  "$*"; }
fail()  { printf "\e[1;31m[FAIL]\e[0m %s\n"  "$*"; exit 1; }
cmd()   { command -v "$1" >/dev/null 2>&1; }

# ───── 0 ▸ convert CRLF if file came from Windows ────────────
if grep -q $'\r' "$0"; then
  step "Converting CRLF → LF in $0"
  cmd dos2unix || { sudo apt-get update -qq && sudo apt-get install -y dos2unix; }
  dos2unix "$0"
fi

# ───── 1 ▸ locate active config.txt ──────
CFG=/boot/firmware/config.txt; [[ -f $CFG ]] || CFG=/boot/config.txt
info "Using config file: $CFG"
add_dtparam() {
  local param="$1"
  if grep -qE "^#?\s*${param%=*}=on" "$CFG"; then
    sudo sed -Ei "s|^#?\s*${param%=*}=.*|${param%=*}=on|" "$CFG"
  else
    echo "$param" | sudo tee -a "$CFG" >/dev/null
  fi
}

# ───── 2 ▸ install / upgrade required APT packages ───────────
PACKAGES=(
  python3 python3-pip python3-dev python3-venv \
  python3-scapy python3-netifaces python3-pyudev python3-serial \
  python3-smbus python3-rpi.gpio python3-spidev python3-pil python3-qrcode python3-numpy \
  python3-setuptools python3-cryptography python3-requests python3-websockets \
  libglib2.0-dev python3-bluez \
  fonts-dejavu-core nmap ncat tcpdump arp-scan dsniff ettercap-text-only php procps \
  aircrack-ng wireless-tools wpasupplicant iw \
  firmware-linux-nonfree firmware-realtek firmware-atheros \
  git i2c-tools
)

step "Updating APT and installing dependencies …"
sudo apt-get update -qq
to_install=($(sudo apt-get -qq --just-print install "${PACKAGES[@]}" | awk '/^Inst/ {print $2}'))
if ((${#to_install[@]})); then
  info "Will install/upgrade: ${to_install[*]}"
  sudo apt-get install -y --no-install-recommends "${PACKAGES[@]}"
else
  info "All packages already installed & up‑to‑date."
fi

# ───── 2‑b ▸ Wall-of-Flippers deps (bluepy/bleak) via venv ───
# WoF uses bluepy.btle (BLE). Install in a venv so we never touch system Python.
RJ_VENV="/root/Raspyjack/venv"
step "Creating RaspyJack venv and installing WoF deps (bluepy, bleak) …"

if [ ! -d "$RJ_VENV" ]; then
  python3 -m venv --system-site-packages "$RJ_VENV"
  info "Created venv at $RJ_VENV (--system-site-packages so apt packages are visible)"
else
  info "Venv already exists: $RJ_VENV"
fi

"$RJ_VENV/bin/pip" install --upgrade pip -q
"$RJ_VENV/bin/pip" install bluepy bleak
info "Installed bluepy and bleak in venv (no --break-system-packages)"

# Verify WoF can import bluepy
"$RJ_VENV/bin/python" - <<'PY' || fail "bluepy import failed in venv; WoF threat detection will not be ready."
import bluepy
import bleak
print("[OK] bluepy and bleak available in venv")
PY

# ───── 2‑c ▸ Navarro (vendored in repo) ─────────────────────────
NAVARRO_PATH="/root/Raspyjack/Navarro/navarro.py"
if [ -f "$NAVARRO_PATH" ]; then
  chmod +x "$NAVARRO_PATH"
  info "Navarro found: $NAVARRO_PATH"
else
  warn "Navarro not found at $NAVARRO_PATH – add Navarro/ to your Raspyjack repo for OSINT payload"
fi

mkdir -p /usr/share/fonts/truetype/fontawesome
cd /usr/share/fonts/truetype/fontawesome
wget https://use.fontawesome.com/releases/v6.5.1/webfonts/fa-solid-900.ttf

# ───── 3 ▸ enable I²C / SPI & kernel modules ────────────────
step "Enabling I²C & SPI …"
add_dtparam dtparam=i2c_arm=on
add_dtparam dtparam=i2c1=on
add_dtparam dtparam=spi=on

MODULES=(i2c-bcm2835 i2c-dev spi_bcm2835 spidev)
for m in "${MODULES[@]}"; do
  grep -qxF "$m" /etc/modules || echo "$m" | sudo tee -a /etc/modules >/dev/null
  sudo modprobe "$m" || true
done

grep -qE '^dtoverlay=spi0-[12]cs' "$CFG" || echo 'dtoverlay=spi0-2cs' | sudo tee -a "$CFG" >/dev/null

# ───── 4 ▸ WiFi attack setup ──────────────────────────────────
step "Setting up WiFi attack environment …"

# Pin onboard WiFi to wlan0 so it never swaps with USB dongles across reboots.
# Without this, Linux can assign wlan0/wlan1 in random order on each boot,
# which breaks the WebUI (wlan0) vs monitor-mode (wlan1+) separation.
step "Pinning onboard WiFi to wlan0 (persistent naming) …"

# Detect WiFi MAC addresses by bus:
# - onboard chip: SDIO/MMC -> forced to wlan0
# - first USB dongle: USB bus -> forced to wlan1
ONBOARD_MAC=""
USB_MAC=""
for dev in /sys/class/net/wlan*; do
  [ -e "$dev" ] || continue
  DEVPATH=$(readlink -f "$dev/device" 2>/dev/null || true)
  if echo "$DEVPATH" | grep -q "mmc"; then
    ONBOARD_MAC=$(cat "$dev/address" 2>/dev/null || true)
    ONBOARD_NAME=$(basename "$dev")
    info "Found onboard WiFi: $ONBOARD_NAME ($ONBOARD_MAC) on SDIO/MMC bus"
  elif [ -z "$USB_MAC" ] && echo "$DEVPATH" | grep -q "usb"; then
    USB_MAC=$(cat "$dev/address" 2>/dev/null || true)
    USB_NAME=$(basename "$dev")
    info "Found USB WiFi dongle: $USB_NAME ($USB_MAC) on USB bus"
  fi
done

if [ -n "$ONBOARD_MAC" ]; then
  # Method 1: systemd .link file (takes priority on Bookworm / modern systemd)
  # This is the RELIABLE way — systemd overrides udev NAME= rules
  sudo tee /etc/systemd/network/10-onboard-wifi.link >/dev/null <<LINK
[Match]
MACAddress=$ONBOARD_MAC

[Link]
Name=wlan0
LINK

  if [ -n "$USB_MAC" ]; then
    sudo tee /etc/systemd/network/11-usb-wifi.link >/dev/null <<LINK
[Match]
MACAddress=$USB_MAC

[Link]
Name=wlan1
LINK
  else
    warn "No USB WiFi dongle detected during install - wlan1 pin skipped"
  fi

  # Method 2: udev rule (fallback for older systems without systemd-networkd)
  sudo tee /etc/udev/rules.d/70-raspyjack-wifi.rules >/dev/null <<UDEV
# RaspyJack: pin WiFi interfaces by MAC
# Onboard WiFi (SDIO) -> wlan0
SUBSYSTEM=="net", ACTION=="add", ATTR{address}=="$ONBOARD_MAC", NAME="wlan0"
UDEV
  if [ -n "$USB_MAC" ]; then
    echo "SUBSYSTEM==\"net\", ACTION==\"add\", ATTR{address}==\"$USB_MAC\", NAME=\"wlan1\"" | sudo tee -a /etc/udev/rules.d/70-raspyjack-wifi.rules >/dev/null
  fi

  sudo udevadm control --reload-rules
  info "Pinned onboard WiFi ($ONBOARD_MAC) to wlan0 via systemd .link + udev rule"
  if [ -n "$USB_MAC" ]; then
    info "Pinned USB WiFi dongle ($USB_MAC) to wlan1 via systemd .link + udev rule"
  fi
  info "This will take effect after reboot"
else
  warn "Could not detect onboard WiFi MAC — skipping interface pinning"
  warn "Run 'ip link' and manually create /etc/systemd/network/10-onboard-wifi.link"
fi

sudo mkdir -p /root/Raspyjack/wifi/profiles
sudo chown root:root /root/Raspyjack/wifi/profiles
sudo chmod 755 /root/Raspyjack/wifi/profiles

sudo tee /root/Raspyjack/wifi/profiles/sample.json >/dev/null <<'PROFILE'
{
  "ssid": "YourWiFiNetwork",
  "password": "your_password_here",
  "interface": "auto",
  "priority": 1,
  "auto_connect": true,
  "created": "2024-01-01T12:00:00",
  "last_used": null,
  "notes": "Sample WiFi profile - edit with your network details"
}
PROFILE

if systemctl is-active --quiet NetworkManager; then
  info "NetworkManager is active - configuring for WiFi attacks"
  sudo tee /etc/NetworkManager/conf.d/99-wifi-attacks.conf >/dev/null <<'NM_CONF'
[main]
plugins=ifupdown,keyfile

[ifupdown]
managed=true

[keyfile]
unmanaged-devices=interface-name:wlan0mon;interface-name:wlan1mon;interface-name:wlan2mon
NM_CONF
  sudo systemctl restart NetworkManager
else
  warn "NetworkManager not active - WiFi attacks may need manual setup"
fi

# Hard fallback: force WiFi naming at boot before NetworkManager
step "Installing boot-time WiFi name pinning service …"
sudo install -m 0755 /root/Raspyjack/scripts/pin_wifi_names.sh /usr/local/sbin/raspyjack-pin-wifi.sh
sudo tee /etc/systemd/system/raspyjack-pin-wifi.service >/dev/null <<'UNIT'
[Unit]
Description=RaspyJack Pin WiFi Interface Names
After=systemd-udev-settle.service local-fs.target
Wants=systemd-udev-settle.service
Before=NetworkManager.service network.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/raspyjack-pin-wifi.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable raspyjack-pin-wifi.service

# ───── 5 ▸ RaspyJack core service ────────────────────────────
SERVICE=/etc/systemd/system/raspyjack.service
step "Installing core systemd service $SERVICE …"

sudo tee "$SERVICE" >/dev/null <<'UNIT'
[Unit]
Description=RaspyJack UI Service
After=network-online.target local-fs.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/root/Raspyjack
ExecStart=/root/Raspyjack/venv/bin/python /root/Raspyjack/raspyjack.py
Restart=on-failure
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now raspyjack.service

# ───── 5‑b ▸ device server & WebUI split services ───────────
# Shared WebUI token (used by both HTTP + WS servers)
WEBUI_TOKEN_FILE=/root/Raspyjack/.webui_token
WEBUI_AUTH_SECRET_FILE=/root/Raspyjack/.webui_session_secret
step "Configuring shared WebUI token at $WEBUI_TOKEN_FILE …"
if ! sudo test -s "$WEBUI_TOKEN_FILE"; then
  sudo python3 - <<'PY'
from pathlib import Path
import secrets

path = Path("/root/Raspyjack/.webui_token")
path.write_text(secrets.token_urlsafe(32) + "\n", encoding="utf-8")
print(f"[OK] Created {path}")
PY
else
  info "Existing WebUI token file found, keeping it."
fi
sudo chown root:root "$WEBUI_TOKEN_FILE"
sudo chmod 600 "$WEBUI_TOKEN_FILE"

step "Configuring WebUI auth secret at $WEBUI_AUTH_SECRET_FILE …"
if ! sudo test -s "$WEBUI_AUTH_SECRET_FILE"; then
  sudo python3 - <<'PY'
from pathlib import Path
import secrets

path = Path("/root/Raspyjack/.webui_session_secret")
path.write_text(secrets.token_urlsafe(48) + "\n", encoding="utf-8")
print(f"[OK] Created {path}")
PY
else
  info "Existing WebUI auth secret found, keeping it."
fi
sudo chown root:root "$WEBUI_AUTH_SECRET_FILE"
sudo chmod 600 "$WEBUI_AUTH_SECRET_FILE"

# Device server
DEVICE_SERVICE=/etc/systemd/system/raspyjack-device.service
step "Installing device server systemd service $DEVICE_SERVICE …"

sudo tee "$DEVICE_SERVICE" >/dev/null <<'UNIT'
[Unit]
Description=RaspyJack Device Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/root/Raspyjack
ExecStart=/root/Raspyjack/venv/bin/python /root/Raspyjack/device_server.py
Restart=on-failure
User=root
Environment=PYTHONUNBUFFERED=1
Environment=RJ_WS_TOKEN_FILE=/root/Raspyjack/.webui_token
Environment=RJ_WEB_AUTH_SECRET_FILE=/root/Raspyjack/.webui_session_secret
Environment=RJ_WEB_AUTH_FILE=/root/Raspyjack/.webui_auth.json

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now raspyjack-device.service

# WebUI HTTP server
WEBUI_SERVICE=/etc/systemd/system/raspyjack-webui.service
step "Installing WebUI systemd service $WEBUI_SERVICE …"

sudo tee "$WEBUI_SERVICE" >/dev/null <<'UNIT'
[Unit]
Description=RaspyJack WebUI HTTP Server
After=raspyjack-device.service
Requires=raspyjack-device.service

[Service]
Type=simple
WorkingDirectory=/root/Raspyjack
ExecStart=/root/Raspyjack/venv/bin/python /root/Raspyjack/web_server.py
Restart=on-failure
User=root
Environment=PYTHONUNBUFFERED=1
Environment=RJ_WS_TOKEN_FILE=/root/Raspyjack/.webui_token
Environment=RJ_WEB_AUTH_SECRET_FILE=/root/Raspyjack/.webui_session_secret
Environment=RJ_WEB_AUTH_FILE=/root/Raspyjack/.webui_auth.json

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now raspyjack-webui.service

# ───── 5-c ▸ optional TLS reverse proxy (Caddy) ─────────────
step "Setting up optional HTTPS reverse proxy with Caddy ..."
set +e
TLS_SETUP_OK=1

# Install Caddy best-effort. If this fails, keep plain HTTP stack available.
if ! dpkg -s caddy >/dev/null 2>&1; then
  step "Installing Caddy package ..."
  if ! sudo apt-get install -y --no-install-recommends caddy; then
    warn "Caddy install failed; keeping WebUI on HTTP only."
    TLS_SETUP_OK=0
  fi
fi

if [ "$TLS_SETUP_OK" -eq 1 ]; then
  CADDY_HOSTS=()
  for IFACE in eth0 wlan0 tailscale0; do
    IFACE_IP=$(ip -4 -o addr show "$IFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)
    if [ -n "$IFACE_IP" ]; then
      CADDY_HOSTS+=("$IFACE_IP")
    fi
  done
  CADDY_HOSTS+=("localhost")

  if [ "${#CADDY_HOSTS[@]}" -eq 0 ]; then
    warn "No interface IPs detected for Caddy TLS vhosts; skipping Caddy config."
    TLS_SETUP_OK=0
  fi
fi

if [ "$TLS_SETUP_OK" -eq 1 ]; then
  CADDY_SITE_ADDRS=""
  for host in "${CADDY_HOSTS[@]}"; do
    if [ -z "$CADDY_SITE_ADDRS" ]; then
      CADDY_SITE_ADDRS="$host"
    else
      CADDY_SITE_ADDRS="${CADDY_SITE_ADDRS}, ${host}"
    fi
  done
  if ! sudo tee /etc/caddy/Caddyfile >/dev/null <<CADDYFILE
{
    # RaspyJack self-signed internal CA (local trust only)
    auto_https disable_redirects
}

${CADDY_SITE_ADDRS} {
    tls internal

    @ws path /ws*
    reverse_proxy @ws 127.0.0.1:8765 {
        header_up X-Forwarded-Proto {scheme}
        header_up X-Forwarded-Host {host}
    }

    reverse_proxy 127.0.0.1:8080 {
        header_up X-Forwarded-Proto {scheme}
        header_up X-Forwarded-Host {host}
    }
}
CADDYFILE
  then
    warn "Failed to write /etc/caddy/Caddyfile; skipping HTTPS proxy setup."
    TLS_SETUP_OK=0
  fi
fi

if [ "$TLS_SETUP_OK" -eq 1 ]; then
  if ! sudo systemctl enable --now caddy.service; then
    warn "Failed to enable/start caddy.service; keeping HTTP services active."
    TLS_SETUP_OK=0
  fi
fi

if [ "$TLS_SETUP_OK" -eq 1 ]; then
  info "HTTPS proxy is enabled. Access WebUI at: https://<device-ip>/"
  info "For first use, trust Caddy's local CA certificate on your client if prompted."
else
  warn "TLS setup incomplete. WebUI remains available on: http://<device-ip>:8080"
  warn "Manual remediation: sudo apt-get install caddy && sudo systemctl restart caddy"
fi
set -e

# ───── 6 ▸ final health‑check ────────────────────────────────
step "Running post install checks …"

# 6‑a SPI device nodes
if ls /dev/spidev* 2>/dev/null | grep -q spidev0.0; then
  info "SPI device found: $(ls /dev/spidev* | xargs)"
else
  warn "SPI device NOT found – a reboot may still be required."
fi

# 6‑b WiFi attack tools check
if cmd aireplay-ng && cmd airodump-ng && cmd airmon-ng; then
  info "WiFi attack tools found: aircrack-ng suite installed"
else
  warn "WiFi attack tools missing - check aircrack-ng installation"
fi

# 6‑c USB WiFi dongle detection
if lsusb | grep -q -i "realtek\|ralink\|atheros\|broadcom"; then
  info "USB WiFi dongles detected: $(lsusb | grep -i 'realtek\|ralink\|atheros\|broadcom' | wc -l) devices"
else
  warn "No USB WiFi dongles detected - WiFi attacks require external dongle"
fi

# 6‑d python imports (use venv – same interpreter as services and payloads)
/root/Raspyjack/venv/bin/python - <<'PY' || fail "Python dependency test failed"
import importlib, sys
for mod in ("scapy", "netifaces", "pyudev", "serial", "smbus2", "RPi.GPIO", "spidev", "PIL", "qrcode", "requests", "bluepy", "bleak"):
    try:
        importlib.import_module(mod.split('.')[0])
    except Exception as e:
        print("[FAIL]", mod, e)
        sys.exit(1)
print("[OK] All Python modules import correctly (venv)")
PY

# 6‑e WiFi integration test (venv)
/root/Raspyjack/venv/bin/python - <<'WIFI_TEST' || warn "WiFi integration test failed - check wifi/ folder"
import sys
import os
sys.path.append('/root/Raspyjack/wifi/')
try:
    from wifi.raspyjack_integration import get_available_interfaces
    interfaces = get_available_interfaces()
    print(f"[OK] WiFi integration working - found {len(interfaces)} interfaces")
except Exception as e:
    print(f"[WARN] WiFi integration test failed: {e}")
    sys.exit(1)
WIFI_TEST

# 7 ▸ set permissions for binaries
step "Setting executable permissions for binaries in bin/... "
if [ -d "/root/Raspyjack/bin" ]; then
    sudo chmod +x /root/Raspyjack/bin/*
    info "Permissions set for files in /root/Raspyjack/bin/"
fi

step "Installation finished successfully!"
info "⚠️  Reboot is recommended to ensure overlays & services start cleanly."
info "📡 For WiFi attacks: Plug in USB WiFi dongle and run payloads/interception/deauth.py"
