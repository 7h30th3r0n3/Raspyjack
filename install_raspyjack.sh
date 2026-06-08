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

# ───── mode flag ─────────────────────────────────────────────
UPDATE_MODE=0
[[ "${1:-}" == "--update" ]] && UPDATE_MODE=1

# ───── auto-detect CardputerZero hardware ────────────────────
IS_CARDPUTER=0
CFG_TMP=/boot/firmware/config.txt; [[ -f $CFG_TMP ]] || CFG_TMP=/boot/config.txt
if grep -q "cardputerzero-overlay" "$CFG_TMP" 2>/dev/null; then
  IS_CARDPUTER=1
elif cat /sys/class/graphics/fb0/name 2>/dev/null | grep -q "st7789v_m5st"; then
  IS_CARDPUTER=1
fi

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

# ───── 1‑b ▸ select display type ─────────────────────────────
if [[ $UPDATE_MODE -eq 1 ]]; then
  # Auto-detect from existing gui_conf.json
  DISPLAY_TYPE=$(python3 -c "
import json
try:
    with open('/root/Raspyjack/gui_conf.json') as f:
        print(json.load(f).get('DISPLAY',{}).get('type','ST7735_128'))
except: print('ST7735_128')
" 2>/dev/null)
  info "Update mode: detected display $DISPLAY_TYPE from gui_conf.json"
else
  step "Display configuration"
  echo ""
  echo "  Which LCD screen are you using?"
  echo ""
  echo "    1) ST7735_128    — 1.44\" 128×128  (original Waveshare HAT)"
  echo "    2) ST7789_240    — 1.3\"  240×240"
  echo "    3) CARDPUTER_320 — M5Stack CardputerZero 320×170"
  echo ""
  DEFAULT_CHOICE=1
  if [[ $IS_CARDPUTER -eq 1 ]]; then
    DEFAULT_CHOICE=3
    info "CardputerZero hardware auto-detected!"
  fi
  read -rp "  Enter choice [1/2/3] (default: $DEFAULT_CHOICE): " DISPLAY_CHOICE
  DISPLAY_CHOICE="${DISPLAY_CHOICE:-$DEFAULT_CHOICE}"
  case "$DISPLAY_CHOICE" in
    2) DISPLAY_TYPE="ST7789_240" ;;
    3) DISPLAY_TYPE="CARDPUTER_320" ;;
    *) DISPLAY_TYPE="ST7735_128" ;;
  esac
fi
info "Selected display: $DISPLAY_TYPE"

# Write DISPLAY type into gui_conf.json (preserve ALL existing settings: flip, colors, pins, etc.)
GUI_CONF="/root/Raspyjack/gui_conf.json"
if [ -f "$GUI_CONF" ]; then
  python3 - "$DISPLAY_TYPE" <<'PY'
import json, sys
dtype = sys.argv[1]
with open("/root/Raspyjack/gui_conf.json") as f:
    data = json.load(f)
# Preserve existing DISPLAY settings (flip, etc.), only update type
if "DISPLAY" not in data:
    data["DISPLAY"] = {}
data["DISPLAY"]["type"] = dtype
data["DISPLAY"]["supported_types"] = ["ST7735_128", "ST7789_240", "CARDPUTER_320"]
# Preserve flip if it exists
# (flip key is NOT overwritten, it stays as-is)
with open("/root/Raspyjack/gui_conf.json", "w") as f:
    json.dump(data, f, indent=4)
flip_status = data["DISPLAY"].get("flip", False)
print(f"[OK] gui_conf.json: type={dtype}, flip={flip_status}")
PY
else
  info "gui_conf.json not found — creating with defaults."
  python3 - "$DISPLAY_TYPE" <<'NEWCONF'
import json, sys
dtype = sys.argv[1]
data = {
    "COLORS": {
        "BACKGROUND": "#000000",
        "BORDER": "#05ff00",
        "GAMEPAD": "#141494",
        "GAMEPAD_FILL": "#eeeeee",
        "SELECTED_TEXT": "#00ff55",
        "SELECTED_TEXT_BACKGROUND": "#2d0fff",
        "TEXT": "#05ff00"
    },
    "DISPLAY": {
        "type": dtype,
        "supported_types": ["ST7735_128", "ST7789_240", "CARDPUTER_320"],
        "flip": False
    },
    "LOCK": {
        "auto_lock_seconds": 0,
        "enabled": False,
        "pin_hash": ""
    },
    "PATHS": {
        "IMAGEBROWSER_START": "/root/Raspyjack/img/",
        "SCREENSAVER_GIF": "/root/Raspyjack/img/screensaver/default.gif"
    },
    "PINS": {
        "KEY1_PIN": 21, "KEY2_PIN": 20, "KEY3_PIN": 16,
        "KEY_DOWN_PIN": 19, "KEY_LEFT_PIN": 5,
        "KEY_PRESS_PIN": 13, "KEY_RIGHT_PIN": 26, "KEY_UP_PIN": 6
    }
}
with open("/root/Raspyjack/gui_conf.json", "w") as f:
    json.dump(data, f, indent=4)
print(f"[OK] gui_conf.json created: type={dtype}")
NEWCONF
fi

# ───── 1‑c ▸ create payload config directories ───────────────
step "Creating payload config directories …"
for d in ad_recon auto_loot_exfil bt_audio cctv_scanner cctv_viewer dns_tunnel \
         exfil_ftp exfil_smb http_exfil reverse_ssh rtsp_viewer scheduler \
         ssid_pool timer tripwire usb_gadget wifi_alert; do
  mkdir -p "/root/Raspyjack/config/$d"
done
mkdir -p /root/Raspyjack/loot/wordlists

# ───── 1‑d ▸ CardputerZero: disable M5Stack APPLaunch service ─
if [[ "$DISPLAY_TYPE" == "CARDPUTER_320" ]]; then
  step "Disabling M5Stack APPLaunch service …"
  sudo systemctl stop APPLaunch.service 2>/dev/null || true
  sudo systemctl disable APPLaunch.service 2>/dev/null || true
  info "APPLaunch service disabled (replaced by RaspyJack)"

  step "Disabling desktop environment (saves RAM on CM0) …"
  sudo systemctl stop lightdm.service 2>/dev/null || true
  sudo systemctl disable lightdm.service 2>/dev/null || true
  info "LightDM disabled — HDMI available for RaspyJack mirroring"

  step "Disabling PipeWire/WirePlumber (frees audio device for direct ALSA) …"
  sudo systemctl --user --global disable pipewire.service pipewire.socket pipewire-pulse.service pipewire-pulse.socket wireplumber.service 2>/dev/null || true
  sudo pkill -9 pipewire wireplumber pipewire-pulse 2>/dev/null || true
  info "PipeWire disabled — ALSA direct access for audio"

  step "Releasing serial port for GPS HAT …"
  sudo systemctl stop serial-getty@ttyS0.service 2>/dev/null || true
  sudo systemctl disable serial-getty@ttyS0.service 2>/dev/null || true
  sudo systemctl mask serial-getty@ttyS0.service 2>/dev/null || true
  sudo systemctl stop serial-getty@ttyAMA0.service 2>/dev/null || true
  sudo systemctl disable serial-getty@ttyAMA0.service 2>/dev/null || true
  sudo systemctl mask serial-getty@ttyAMA0.service 2>/dev/null || true
  info "serial-getty disabled on ttyS0/ttyAMA0 — GPS HAT can use UART"

  step "Disabling console on LCD framebuffer …"
  sudo systemctl stop getty@tty1.service 2>/dev/null || true
  sudo systemctl disable getty@tty1.service 2>/dev/null || true
  # Remove console=tty1 from cmdline and add fbcon=map:99 to prevent fbcon on LCD
  CMDLINE="/boot/firmware/cmdline.txt"
  if [ -f "$CMDLINE" ]; then
    sudo sed -i 's/ console=tty1//g' "$CMDLINE"
    grep -q "fbcon=map:99" "$CMDLINE" || sudo sed -i 's/$/ fbcon=map:99/' "$CMDLINE"
  fi
  # Unbind fbcon from LCD immediately
  echo 0 | sudo tee /sys/class/vtconsole/vtcon1/bind 2>/dev/null || true
  info "Console/getty disabled on LCD — no more cursor bleed-through"
fi

# ───── 2 ▸ install / upgrade required APT packages ───────────
PACKAGES=(
  python3 python3-pip python3-dev \
  python3-scapy python3-netifaces python3-pyudev python3-serial \
  python3-smbus python3-rpi.gpio python3-spidev python3-pil python3-qrcode python3-numpy \
  python3-setuptools python3-cryptography python3-requests python3-websockets \
  python3-evdev \
  libglib2.0-dev python3-bluez bluez \
  fonts-dejavu-core nmap ncat tcpdump tshark arp-scan dsniff ettercap-text-only php procps \
  aircrack-ng wireless-tools wpasupplicant iw \
  hostapd dnsmasq-base sshpass bridge-utils john autossh reaver ebtables \
  firmware-linux-nonfree firmware-realtek firmware-atheros \
  git i2c-tools rtl-sdr \
  ffmpeg yt-dlp gpsd gpsd-clients
)

# CardputerZero extra packages
if [[ "$DISPLAY_TYPE" == "CARDPUTER_320" ]]; then
  PACKAGES+=( mpv rtl-433 bluez-alsa-utils chocolate-doom freedoom xvfb xdotool )
fi

# Fix missing GPG keys before apt update
step "Checking APT repository keys …"
if ! sudo apt-get update -qq 2>&1 | grep -q "^E:"; then
  info "APT repositories OK"
else
  warn "APT key issue detected, attempting fix..."
  # Fix Kali key if present (compatible Bookworm + Trixie)
  if [ -f /etc/apt/sources.list.d/kali-rolling.list ]; then
    sudo wget -q -O /usr/share/keyrings/kali-archive-keyring.gpg https://archive.kali.org/archive-key.asc 2>/dev/null \
      && info "Kali GPG key installed" \
      || warn "Could not fetch Kali GPG key"
    # Ensure signed-by is set (required for Trixie/sqv)
    if ! grep -q "signed-by" /etc/apt/sources.list.d/kali-rolling.list 2>/dev/null; then
      echo "deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" \
        | sudo tee /etc/apt/sources.list.d/kali-rolling.list >/dev/null
      info "Kali repo updated with signed-by"
    fi
  fi
  sudo apt-get update -qq || warn "APT update had errors, continuing..."
fi

step "Installing dependencies …"
to_install=($(sudo apt-get -qq --just-print install "${PACKAGES[@]}" | awk '/^Inst/ {print $2}'))
if ((${#to_install[@]})); then
  info "Will install/upgrade: ${to_install[*]}"
  sudo apt-get install -y --no-install-recommends "${PACKAGES[@]}" || warn "Some packages had errors (non-critical, continuing...)"
else
  info "All packages already installed & up‑to‑date."
fi

# ───── 2‑a2 ▸ pip packages not available via APT ─────────────────
step "Installing Python packages via pip …"
sudo pip3 install --break-system-packages smbus2 2>/dev/null \
  || sudo pip3 install smbus2 2>/dev/null \
  || warn "smbus2 pip install failed – i2c_scanner payload may not work"

# Upgrade yt-dlp to latest (apt version is often outdated, YouTube breaks compatibility)
step "Upgrading yt-dlp to latest version …"
sudo pip3 install --upgrade yt-dlp --break-system-packages --ignore-installed yt-dlp 2>/dev/null \
  || warn "yt-dlp upgrade failed – YouTube payload may not work"

# GPS python library
step "Installing gpsd-py3 …"
sudo pip3 install --break-system-packages gpsd-py3 2>/dev/null \
  || warn "gpsd-py3 install failed – wardriving GPS may not work"

# Disable hostapd/dnsmasq auto-start (only used on-demand by payloads)
sudo systemctl disable --now hostapd 2>/dev/null || true
sudo systemctl disable --now dnsmasq 2>/dev/null || true

# ───── 2‑b ▸ Wall-of-Flippers: bluepy + bleak ──────────────────
step "Checking BLE libraries (bluepy + bleak) …"

# Check if bluepy is already installed and working
BLUEPY_OK=0
python3 -c "import bluepy; print('bluepy OK')" 2>/dev/null && BLUEPY_OK=1

if [ "$BLUEPY_OK" -eq 0 ]; then
  info "bluepy not found, building from source..."
  BLUEPY_BUILD=$(mktemp -d)
  trap "rm -rf '$BLUEPY_BUILD'" EXIT
  if git clone --depth 1 https://github.com/IanHarvey/bluepy.git "$BLUEPY_BUILD" 2>/dev/null; then
    (cd "$BLUEPY_BUILD" && python3 setup.py build && sudo python3 setup.py install) 2>/dev/null \
      && info "Installed bluepy from source" \
      || warn "bluepy build failed"
  else
    warn "Could not clone bluepy repo"
  fi
else
  info "bluepy already installed, skipping build"
fi

# Set capabilities on bluepy-helper (needed for non-root BLE)
HELPER=$(find /usr -name "bluepy-helper" 2>/dev/null | head -1)
if [ -n "$HELPER" ]; then
  sudo setcap 'cap_net_raw,cap_net_admin+eip' "$HELPER" 2>/dev/null \
    && info "bluepy-helper capabilities set" \
    || warn "Could not set bluepy-helper capabilities"
fi

# Install bleak as modern fallback (preferred by wall_of_flippers)
if ! python3 -c "import bleak" 2>/dev/null; then
  sudo pip3 install --break-system-packages bleak 2>/dev/null \
    || sudo pip3 install bleak 2>/dev/null \
    || warn "bleak install failed"
  info "bleak installed"
else
  info "bleak already installed"
fi

# Verify at least one BLE library works
python3 - <<'PY' || warn "No BLE library available; WoF/BLE payloads may not work."
try:
    import bluepy
    print("[OK] bluepy available")
except ImportError:
    try:
        import bleak
        print("[OK] bleak available (bluepy missing)")
    except ImportError:
        print("[FAIL] No BLE library")
        import sys; sys.exit(1)
PY

# ───── 2‑c ▸ Navarro (vendored in repo) ─────────────────────────
NAVARRO_PATH="/root/Raspyjack/Navarro/navarro.py"
if [ -f "$NAVARRO_PATH" ]; then
  chmod +x "$NAVARRO_PATH"
  info "Navarro found: $NAVARRO_PATH"
else
  warn "Navarro not found at $NAVARRO_PATH – add Navarro/ to your Raspyjack repo for OSINT payload"
fi

# FontAwesome font (skip if already present)
if [ ! -f /usr/share/fonts/truetype/fontawesome/fa-solid-900.ttf ]; then
  mkdir -p /usr/share/fonts/truetype/fontawesome
  FA_OK=0
  for FA_URL in \
    "https://use.fontawesome.com/releases/v6.5.1/webfonts/fa-solid-900.ttf" \
    "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/webfonts/fa-solid-900.ttf" \
    "https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/webfonts/fa-solid-900.ttf"; do
    wget -q --timeout=10 -O /usr/share/fonts/truetype/fontawesome/fa-solid-900.ttf "$FA_URL" && FA_OK=1 && break
  done
  if [ "$FA_OK" = "1" ]; then
    info "FontAwesome font installed"
  else
    warn "Could not download FontAwesome font (check internet connection)"
  fi
else
  info "FontAwesome font already present"
fi

# ───── 2‑e ▸ Blacklist DVB driver for RTL-SDR direct access ──
step "Blacklisting DVB driver for RTL-SDR …"
if ! grep -q "blacklist dvb_usb_rtl28xxu" /etc/modprobe.d/rtlsdr-blacklist.conf 2>/dev/null; then
  echo "blacklist dvb_usb_rtl28xxu" | sudo tee /etc/modprobe.d/rtlsdr-blacklist.conf >/dev/null
  sudo modprobe -r dvb_usb_rtl28xxu 2>/dev/null || true
  info "dvb_usb_rtl28xxu blacklisted"
else
  info "DVB blacklist already configured"
fi

# ───── 3 ▸ enable I²C / SPI & kernel modules ────────────────
if [[ "$DISPLAY_TYPE" == "CARDPUTER_320" ]]; then
  info "CardputerZero: framebuffer display — skipping SPI/I²C HAT setup"

  # ALSA config for ES8388 codec
  step "Configuring ALSA for ES8388 audio codec …"
  ES_CARD=$(aplay -l 2>/dev/null | grep -i 'ES8388\|ES8389' | head -1 | sed 's/card //' | cut -d: -f1)
  ES_CARD=${ES_CARD:-0}
  sudo tee /etc/asound.conf >/dev/null <<ALSA
defaults.pcm.card $ES_CARD
defaults.ctl.card $ES_CARD
ALSA
  info "ALSA configured for ES8388 (card $ES_CARD)"

  # Create RPi/GPIO.py shim (shadows system RPi.GPIO with evdev-based input)
  step "Creating RPi.GPIO shim for CardputerZero keyboard …"
  mkdir -p /root/Raspyjack/RPi
  cat > /root/Raspyjack/RPi/__init__.py <<'RPYINIT'
RPYINIT
  cat > /root/Raspyjack/RPi/GPIO.py <<'RPYGPIO'
from gpio_shim import *
RPYGPIO
  info "RPi/GPIO.py shim installed (evdev-based keyboard input)"

  # Install opencv-python-headless via pip (not in apt)
  step "Installing OpenCV …"
  sudo pip3 install --break-system-packages opencv-python-headless 2>/dev/null \
    || warn "opencv install failed — video_player may not work"

else
  step "Checking I²C & SPI …"
  SPI_OK=0
  ls /dev/spidev0.0 >/dev/null 2>&1 && grep -q "i2c-dev" /etc/modules 2>/dev/null && SPI_OK=1
  if [[ $SPI_OK -eq 1 ]]; then
    info "I²C & SPI already configured"
  else
    add_dtparam dtparam=i2c_arm=on
    add_dtparam dtparam=i2c1=on
    add_dtparam dtparam=spi=on
    MODULES=(i2c-bcm2835 i2c-dev spi_bcm2835 spidev)
    for m in "${MODULES[@]}"; do
      grep -qxF "$m" /etc/modules || echo "$m" | sudo tee -a /etc/modules >/dev/null
      sudo modprobe "$m" || true
    done
    grep -qE '^dtoverlay=spi0-[12]cs' "$CFG" || echo 'dtoverlay=spi0-2cs' | sudo tee -a "$CFG" >/dev/null
    info "I²C & SPI configured"
  fi
fi

# ───── 4 ▸ WiFi attack setup ──────────────────────────────────
step "Setting up WiFi attack environment …"

# Pin onboard WiFi to wlan0 so it never swaps with USB dongles across reboots.
if [[ -f /etc/systemd/network/10-onboard-wifi.link ]]; then
  info "WiFi interface pinning already configured"
else
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
fi  # end WiFi pinning check

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
  if [[ -f /etc/NetworkManager/conf.d/99-wifi-attacks.conf ]]; then
    info "NetworkManager WiFi attack config already present"
  else
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
  fi
else
  warn "NetworkManager not active - WiFi attacks may need manual setup"
fi

# Hard fallback: force WiFi naming at boot before NetworkManager
if systemctl is-enabled raspyjack-pin-wifi.service >/dev/null 2>&1; then
  info "WiFi name pinning service already installed"
else
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
fi

# ───── 5 ▸ RaspyJack core service ────────────────────────────
SERVICE=/etc/systemd/system/raspyjack.service
step "Checking core systemd services …"

sudo tee "$SERVICE" >/dev/null <<'UNIT'
[Unit]
Description=RaspyJack UI Service
After=network-online.target local-fs.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/root/Raspyjack
ExecStart=/usr/bin/python3 /root/Raspyjack/raspyjack.py
Restart=on-failure
User=root
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=/root/Raspyjack

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
ExecStart=/usr/bin/python3 /root/Raspyjack/device_server.py
Restart=on-failure
User=root
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=/root/Raspyjack
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
ExecStart=/usr/bin/python3 /root/Raspyjack/web_server.py
Restart=on-failure
User=root
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=/root/Raspyjack
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
if dpkg -s caddy >/dev/null 2>&1; then
  info "Caddy already installed"
else
  step "Installing Caddy package ..."
  if ! sudo apt-get install -y --no-install-recommends caddy; then
    warn "Caddy install failed; keeping WebUI on HTTP only."
    TLS_SETUP_OK=0
  fi
fi

# Install Caddy auto-config service (skip if already present)
if [ "$TLS_SETUP_OK" -eq 1 ]; then
  if [[ -f /usr/local/sbin/raspyjack-caddy-autoconfig.sh ]] && systemctl is-enabled raspyjack-caddy-autoconfig.service >/dev/null 2>&1; then
    info "Caddy auto-config service already installed"
  else
    step "Installing Caddy auto-config service …"

  sudo tee /usr/local/sbin/raspyjack-caddy-autoconfig.sh >/dev/null <<'SCRIPT'
#!/usr/bin/env bash
# RaspyJack: generate Caddyfile + long-lived self-signed cert
# Binds on 0.0.0.0 — works on any network without reconfiguration
set -euo pipefail

CERT_DIR=/etc/caddy/certs
CERT=$CERT_DIR/raspyjack.crt
KEY=$CERT_DIR/raspyjack.key

# Generate 10-year self-signed cert covering all common private IPs
# Only regenerate if cert doesn't exist or is older than 1 year
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ] || \
   [ "$(find "$CERT" -mtime +365 2>/dev/null)" ]; then
  mkdir -p "$CERT_DIR"

  # Collect all current IPs for SAN
  SAN="IP:127.0.0.1,IP:0.0.0.0,DNS:raspyjack,DNS:raspyjack.local,DNS:localhost"
  for iface in $(ls /sys/class/net/); do
    case "$iface" in lo|docker*|veth*|br-*) continue ;; esac
    IP=$(ip -4 -o addr show "$iface" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)
    [ -n "$IP" ] && SAN="$SAN,IP:$IP"
  done

  openssl req -x509 -nodes -days 3650 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$KEY" -out "$CERT" \
    -subj "/CN=RaspyJack" \
    -addext "subjectAltName=$SAN" 2>/dev/null

  chown caddy:caddy "$KEY" 2>/dev/null || true
  echo "[raspyjack-caddy] Generated new TLS cert with SAN: $SAN"
fi

cat > /etc/caddy/Caddyfile <<EOF
:443 {
    tls $CERT $KEY

    @ws path /ws*
    reverse_proxy @ws 127.0.0.1:8765
    reverse_proxy 127.0.0.1:8080
}
EOF

systemctl reload caddy 2>/dev/null || systemctl restart caddy
echo "[raspyjack-caddy] Bound to 0.0.0.0 (all interfaces)"
SCRIPT
  sudo chmod +x /usr/local/sbin/raspyjack-caddy-autoconfig.sh

  sudo tee /etc/systemd/system/raspyjack-caddy-autoconfig.service >/dev/null <<'UNIT'
[Unit]
Description=RaspyJack Caddy auto-config (detect all IPs)
After=network-online.target caddy.service
Wants=network-online.target
Requires=caddy.service

[Service]
Type=oneshot
ExecStartPre=/bin/sleep 5
ExecStart=/usr/local/sbin/raspyjack-caddy-autoconfig.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT

    sudo systemctl daemon-reload
    sudo systemctl enable raspyjack-caddy-autoconfig.service
    # Run it now to generate the initial Caddyfile
    sudo /usr/local/sbin/raspyjack-caddy-autoconfig.sh
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
  info "Caddy auto-config will detect all IPs on every boot."
else
  warn "TLS setup incomplete. WebUI remains available on: http://<device-ip>:8080"
  warn "Manual remediation: sudo apt-get install caddy && sudo systemctl restart caddy"
fi
set -e

# ───── 6 ▸ final health‑check ────────────────────────────────
step "Running post install checks …"

# 6‑a SPI / framebuffer device nodes
if [[ "$DISPLAY_TYPE" == "CARDPUTER_320" ]]; then
  if [ -e /dev/fb0 ]; then
    info "Framebuffer found: /dev/fb0 (CardputerZero)"
  else
    warn "Framebuffer /dev/fb0 NOT found – display may not work"
  fi
else
  if ls /dev/spidev* 2>/dev/null | grep -q spidev0.0; then
    info "SPI device found: $(ls /dev/spidev* | xargs)"
  else
    warn "SPI device NOT found – a reboot may still be required."
  fi
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

# 6‑d python imports
RJ_DISPLAY_TYPE="$DISPLAY_TYPE" PYTHONPATH=/root/Raspyjack python3 - <<'PY' || fail "Python dependency test failed"
import importlib, sys
import os
dtype = os.environ.get("RJ_DISPLAY_TYPE", "ST7735_128")
if dtype == "CARDPUTER_320":
    required = ("scapy", "netifaces", "pyudev", "serial", "smbus2", "PIL", "qrcode", "requests", "evdev", "numpy")
else:
    required = ("scapy", "netifaces", "pyudev", "serial", "smbus2", "RPi.GPIO", "spidev", "PIL", "qrcode", "requests")
optional = ("bluepy", "bleak")
ok = True
for mod in required:
    try:
        importlib.import_module(mod.split('.')[0])
    except Exception as e:
        print("[FAIL]", mod, e)
        ok = False
for mod in optional:
    try:
        importlib.import_module(mod)
        print("[OK]", mod)
    except ImportError:
        print("[SKIP]", mod, "(optional)")
if not ok:
    sys.exit(1)
print("[OK] All required Python modules available")
PY

# 6‑e WiFi integration test
python3 - <<'WIFI_TEST' || warn "WiFi integration test failed - check wifi/ folder"
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
