#!/usr/bin/env bash
# RaspyJack installation / bootstrap #!/usr/bin/env bash
# RaspyJack installation / bootstrap script
# ------------------------------------------------------------
# * Idempotent   – safe to run multiple times
# * Bookworm‑ready – handles /boot/firmware/config.txt move
# * Enables I²C/SPI, installs all deps, sets up systemd unit
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
  # ‣ python libs
  python3-scapy python3-netifaces python3-pyudev python3-serial \
  python3-smbus python3-rpi.gpio python3-spidev python3-pil python3-numpy \
  python3-setuptools python3-cryptography python3-requests python3-evdev \
  fonts-dejavu-core \
  # ‣ network / offensive tools
  nmap ncat tcpdump arp-scan dsniff ettercap-text-only php procps tshark dnsmasq \
  # ‣ WiFi attack tools (NEW)
  aircrack-ng wireless-tools wpasupplicant iw \
  # ‣ USB WiFi dongle support
  firmware-linux-nonfree firmware-realtek firmware-atheros \
  # ‣ misc
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

# ensure overlay spi0‑2cs
grep -qE '^dtoverlay=spi0-[12]cs' "$CFG" || echo 'dtoverlay=spi0-2cs' | sudo tee -a "$CFG" >/dev/null

# ───── 4 ▸ WiFi attack setup ──────────────────────────────────
step "Setting up WiFi attack environment …"

# Create WiFi profiles directory
sudo mkdir -p /root/Raspyjack/wifi/profiles
sudo chown root:root /root/Raspyjack/wifi/profiles
sudo chmod 755 /root/Raspyjack/wifi/profiles

# Create sample WiFi profile
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

# Set up NetworkManager to allow WiFi interface management
if systemctl is-active --quiet NetworkManager; then
  info "NetworkManager is active - configuring for WiFi attacks"
  # Allow NetworkManager to manage WiFi interfaces
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

# ───── 5 ▸ systemd service ───────────────────────────────────
SERVICE=/etc/systemd/system/raspyjack.service
step "Installing systemd service $SERVICE …"

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

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now raspyjack.service

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

# 6‑d python imports
python3 - <<'PY' || fail "Python dependency test failed"
import importlib, sys
for mod in ("scapy", "netifaces", "pyudev", "serial", "smbus2", "RPi.GPIO", "spidev", "PIL", "requests", "evdev"):
    try:
        importlib.import_module(mod.split('.')[0])
    except Exception as e:
        print("[FAIL]", mod, e)
        sys.exit(1)
print("[OK] All Python modules import correctly")
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

step "Installation finished successfully!"
info "⚠️  Reboot is recommended to ensure overlays & services start cleanly."
info "📡 For WiFi attacks: Plug in USB WiFi dongle and run payloads/deauth.py"
script
# ------------------------------------------------------------
# * Idempotent   – safe to run multiple times
# * Bookworm‑ready – handles /boot/firmware/config.txt move
# * Enables I²C/SPI, installs all deps, sets up systemd unit
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
  # ‣ python libs
  python3-scapy python3-netifaces python3-pyudev python3-serial \
  python3-smbus python3-rpi.gpio python3-spidev python3-pil python3-numpy \
  python3-setuptools python3-cryptography python3-requests fonts-dejavu-core \
  # ‣ network / offensive tools
  nmap ncat tcpdump arp-scan dsniff ettercap-text-only php procps \
  # ‣ WiFi attack tools (NEW)
  aircrack-ng wireless-tools wpasupplicant iw \
  # ‣ USB WiFi dongle support
  firmware-linux-nonfree firmware-realtek firmware-atheros \
  # ‣ misc
  git i2c-tools dkms
)

step "Updating APT and installing dependencies …"
sudo apt-get update -qq

# Install packages with error handling
to_install=($(sudo apt-get -qq --just-print install "${PACKAGES[@]}" 2>/dev/null | awk '/^Inst/ {print $2}'))
if ((${#to_install[@]})); then
  info "Will install/upgrade: ${to_install[*]}"
  sudo apt-get install -y --no-install-recommends "${PACKAGES[@]}" || {
    warn "Some packages failed to install, trying individual installation..."
    for pkg in "${PACKAGES[@]}"; do
      sudo apt-get install -y --no-install-recommends "$pkg" || warn "Failed to install: $pkg"
    done
  }
else
  info "All packages already installed & up‑to‑date."
fi

# Install sqlite3 separately if needed (for Python SQLite support)
if ! python3 -c "import sqlite3" 2>/dev/null; then
  info "Installing SQLite3 support for Python..."
  sudo apt-get install -y sqlite3 libsqlite3-dev || warn "SQLite3 installation failed"
fi

# Install kernel headers for driver compilation
info "Installing kernel headers for driver compilation..."
sudo apt-get install -y raspberrypi-kernel-headers || warn "Kernel headers installation failed"

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

# ensure overlay spi0‑2cs
grep -qE '^dtoverlay=spi0-[12]cs' "$CFG" || echo 'dtoverlay=spi0-2cs' | sudo tee -a "$CFG" >/dev/null

# ───── 4 ▸ WiFi attack setup ──────────────────────────────────
step "Setting up WiFi attack environment …"

# Create WiFi profiles directory
sudo mkdir -p /root/Raspyjack/wifi/profiles
sudo chown root:root /root/Raspyjack/wifi/profiles
sudo chmod 755 /root/Raspyjack/wifi/profiles

# Create sample WiFi profile
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

# Set up NetworkManager to allow WiFi interface management
if systemctl is-active --quiet NetworkManager; then
  info "NetworkManager is active - configuring for WiFi attacks"
  # Allow NetworkManager to manage WiFi interfaces
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

# ───── 5 ▸ GPS setup ──────────────────────────────────────────
step "Setting up GPS for wardriving …"

# Install GPS dependencies
GPS_PACKAGES=(gpsd gpsd-clients)
info "Installing GPS packages: ${GPS_PACKAGES[*]}"
sudo apt-get install -y --no-install-recommends "${GPS_PACKAGES[@]}"

# Install GPS Python library via pip (with system override)
info "Installing gpsd-py3 via pip..."
sudo pip3 install --break-system-packages gpsd-py3

# Create loot directory for wardriving data
sudo mkdir -p /root/Raspyjack/loot/wardriving
sudo chown root:root /root/Raspyjack/loot/wardriving
sudo chmod 755 /root/Raspyjack/loot/wardriving

# Install raspyjack-gps.service
GPS_SERVICE=/etc/systemd/system/raspyjack-gps.service
step "Installing GPS service $GPS_SERVICE …"

sudo tee "$GPS_SERVICE" >/dev/null <<'GPS_UNIT'
[Unit]
Description=RaspyJack GPS Service
After=network.target

[Service]
Type=forking
ExecStart=/usr/sbin/gpsd -n /dev/ttyACM1
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
GPS_UNIT

# Enable and start GPS service
sudo systemctl daemon-reload
sudo systemctl enable --now raspyjack-gps.service

# Stop and mask default GPS services to prevent conflicts permanently
sudo systemctl stop gpsd
sudo systemctl stop gpsd.socket
sudo systemctl disable gpsd
sudo systemctl disable gpsd.socket
sudo systemctl mask gpsd
sudo systemctl mask gpsd.socket

# Wait for GPS service to start
sleep 3

# Check GPS service status
if systemctl is-active --quiet raspyjack-gps.service; then
  info "GPS service started successfully"
else
  warn "GPS service failed to start - check device connection"
fi

# Detect and configure GPS device
step "Detecting GPS device..."
GPS_DEVICE=""
for device in /dev/ttyACM1 /dev/ttyACM0 /dev/ttyUSB0 /dev/ttyUSB1; do
  if [ -e "$device" ]; then
    GPS_DEVICE="$device"
    info "Found GPS device: $GPS_DEVICE"
    break
  fi
done

if [ -n "$GPS_DEVICE" ]; then
  # Update service if device is different from configured
  CURRENT_DEVICE=$(grep -o '/dev/ttyACM[01]' "$GPS_SERVICE" || echo "")
  if [ "$CURRENT_DEVICE" != "$GPS_DEVICE" ]; then
    info "Updating GPS service to use $GPS_DEVICE"
    sudo sed -i "s|/dev/ttyACM[01]|$GPS_DEVICE|g" "$GPS_SERVICE"
    sudo systemctl daemon-reload
    sudo systemctl restart raspyjack-gps.service
    sleep 2
  fi
else
  warn "No GPS device found - service will use default /dev/ttyACM1"
fi

# ───── 6 ▸ systemd service ───────────────────────────────────
SERVICE=/etc/systemd/system/raspyjack.service
step "Installing systemd service $SERVICE …"

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

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now raspyjack.service

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

# 6‑c USB WiFi dongle detection and driver installation
USB_WIFI_DETECTED=false
USB_WIFI_COUNT=0

# Check for various USB WiFi dongle chipsets
USB_PATTERNS="realtek\|ralink\|atheros\|broadcom\|tp-link\|tplink\|mediatek\|qualcomm\|marvell"

if lsusb | grep -q -i "$USB_PATTERNS"; then
  USB_WIFI_COUNT=$(lsusb | grep -i "$USB_PATTERNS" | wc -l)
  info "USB WiFi dongles detected: $USB_WIFI_COUNT devices"
  lsusb | grep -i "$USB_PATTERNS" | while read line; do
    info "  - $line"
  done
  USB_WIFI_DETECTED=true
else
  warn "No USB WiFi dongles detected - WiFi attacks require external dongle"
fi

# Check specifically for TP-Link AC600 series (RTL8812AU/RTL8821AU)
if lsusb | grep -q -i "tp-link.*ac600\|tplink.*ac600\|2357:0115\|2357:012d\|2357:0120\|0bda:8812\|0bda:8811"; then
  info "TP-Link AC600 series detected - installing RTL8812AU drivers..."
  
  # Install DKMS if not already installed
  if ! dpkg -l | grep -q dkms; then
    info "Installing DKMS..."
    sudo apt-get install -y dkms
  fi
  
  # Install RTL8812AU driver (supports RTL8811AU, RTL8812AU, RTL8821AU)
  if [ ! -d "/usr/src/rtl8812au-5.6.4.2" ] && [ ! -f "/lib/modules/$(uname -r)/kernel/drivers/net/wireless/8812au.ko" ]; then
    info "Installing RTL8812AU driver for TP-Link AC600..."
    
    # Install build dependencies
    info "Installing build dependencies..."
    sudo apt-get install -y build-essential linux-headers-$(uname -r) git
    
    cd /tmp
    rm -rf rtl8812au
    if git clone https://github.com/aircrack-ng/rtl8812au.git; then
      cd rtl8812au
      info "Compiling RTL8812AU driver..."
      sudo make clean
      if sudo make -j4; then
        info "Installing RTL8812AU driver..."
        if sudo make install; then
          info "RTL8812AU driver installed successfully"
        else
          warn "RTL8812AU driver installation failed"
        fi
      else
        warn "RTL8812AU driver compilation failed"
      fi
      cd /
      rm -rf /tmp/rtl8812au
    else
      warn "Failed to download RTL8812AU driver source"
    fi
  else
    info "RTL8812AU driver already installed"
  fi
  
  # Load the driver module and check for wlan1
  info "Loading RTL8812AU driver module..."
  
  # First, try to load the module
  if sudo modprobe 8812au 2>/dev/null; then
    info "RTL8812AU module loaded successfully"
  else
    warn "Failed to load RTL8812AU module with modprobe, trying insmod..."
    # Try loading with insmod directly
    if [ -f "/lib/modules/$(uname -r)/kernel/drivers/net/wireless/88XXau.ko" ]; then
      if sudo insmod /lib/modules/$(uname -r)/kernel/drivers/net/wireless/88XXau.ko 2>/dev/null; then
        info "RTL8812AU module loaded successfully with insmod"
      else
        warn "Failed to load RTL8812AU module with insmod"
        info "Driver may need to be recompiled or device reconnected"
      fi
    else
      warn "Driver module not found in expected location"
    fi
  fi
  
  # Wait for interface to appear
  sleep 3
  
  # Check for wlan1 interface
  if ip link show wlan1 >/dev/null 2>&1; then
    info "SUCCESS: wlan1 interface detected!"
  else
    warn "wlan1 interface not found - trying alternative approaches..."
    
    # Try unloading and reloading the module
    sudo rmmod 8812au 2>/dev/null || sudo rmmod 88XXau 2>/dev/null || true
    sleep 2
    
    # Try loading again
    if sudo modprobe 8812au 2>/dev/null || sudo insmod /lib/modules/$(uname -r)/kernel/drivers/net/wireless/88XXau.ko 2>/dev/null; then
      info "RTL8812AU module reloaded"
      sleep 3
      if ip link show wlan1 >/dev/null 2>&1; then
        info "SUCCESS: wlan1 interface detected after reload!"
      else
        warn "wlan1 interface still not found after reload"
        info "Try unplugging and reconnecting the TP-Link AC600 dongle"
      fi
    else
      warn "Failed to reload RTL8812AU module"
    fi
  fi
  
  # Add module to auto-load on boot
  if ! grep -q "8812au" /etc/modules; then
    echo "8812au" | sudo tee -a /etc/modules >/dev/null
    info "Added 8812au to auto-load modules"
  fi
  
  info "TP-Link AC600 driver installation completed"
fi

# 6‑d python imports
python3 - <<'PY' || fail "Python dependency test failed"
import importlib, sys
for mod in ("scapy", "netifaces", "pyudev", "serial", "smbus2", "RPi.GPIO", "spidev", "PIL", "requests"):
    try:
        importlib.import_module(mod.split('.')[0])
    except Exception as e:
        print("[FAIL]", mod, e)
        sys.exit(1)
print("[OK] All Python modules import correctly")
PY

# 6‑e WiFi integration test
python3 - <<'WIFI_TEST' || warn "WiFi integration test failed - check wifi/ folder"
import sys
import os

# Add the wifi directory to Python path
wifi_path = '/root/Raspyjack/wifi'
if os.path.exists(wifi_path):
    sys.path.insert(0, wifi_path)
    sys.path.insert(0, '/root/Raspyjack')

try:
    # Try to import the WiFi integration module
    from wifi.raspyjack_integration import get_available_interfaces
    interfaces = get_available_interfaces()
    print(f"[OK] WiFi integration working - found {len(interfaces)} interfaces")
    
    # Check specifically for wlan1 (external dongle)
    wifi_interfaces = [iface for iface in interfaces if iface.startswith('wlan')]
    if 'wlan1' in wifi_interfaces:
        print(f"[OK] External WiFi dongle detected as wlan1")
    elif len(wifi_interfaces) > 1:
        print(f"[INFO] Multiple WiFi interfaces found: {wifi_interfaces}")
    else:
        print(f"[WARN] Only found WiFi interface: {wifi_interfaces[0] if wifi_interfaces else 'none'}")
        
except ImportError as e:
    print(f"[WARN] WiFi integration module not found: {e}")
    print("[INFO] This is normal if wifi/ folder is not present")
    # Don't exit with error for missing WiFi module
except Exception as e:
    print(f"[WARN] WiFi integration test failed: {e}")
    # Don't exit with error for WiFi integration issues
WIFI_TEST

# 6‑e.1 TP-Link AC600 specific verification
if [ "$USB_WIFI_DETECTED" = true ]; then
  step "Verifying TP-Link AC600 driver installation..."
  
  # Check if 8812au module is loaded
  if lsmod | grep -q 8812au || lsmod | grep -q 88XXau; then
    info "RTL8812AU driver module loaded successfully"
  else
    warn "RTL8812AU driver module not loaded - trying to load now..."
    # Try to load the module one more time
    if sudo modprobe 8812au 2>/dev/null || sudo insmod /lib/modules/$(uname -r)/kernel/drivers/net/wireless/88XXau.ko 2>/dev/null; then
      info "RTL8812AU driver module loaded successfully"
      sleep 2
    else
      warn "RTL8812AU driver module failed to load - may need reboot"
    fi
  fi
  
  # Check for wlan1 interface
  if ip link show wlan1 >/dev/null 2>&1; then
    info "wlan1 interface detected - TP-Link AC600 should be working"
    # Show wlan1 details
    info "wlan1 interface details:"
    ip link show wlan1 | while read line; do
      info "  $line"
    done
  else
    warn "wlan1 interface not found - checking for alternative interfaces..."
    
    # Check for any new wireless interfaces
    for iface in wlan1 wlan2 wlan3; do
      if ip link show "$iface" >/dev/null 2>&1; then
        info "Found wireless interface: $iface"
        break
      fi
    done
    
    # Check if device needs to be reconnected
    info "If wlan1 is still not found, try:"
    info "1. Unplug the TP-Link AC600 dongle"
    info "2. Wait 5 seconds"
    info "3. Plug it back in"
    info "4. Run: sudo modprobe 8812au"
  fi
  
  # Show all wireless interfaces
  info "Current wireless interfaces:"
  iwconfig 2>/dev/null | grep -E "^[a-z]" | while read line; do
    info "  - $line"
  done || warn "No wireless interfaces found via iwconfig"
  
  # Show USB device status
  info "USB WiFi device status:"
  lsusb | grep -i "tp-link\|2357" | while read line; do
    info "  - $line"
  done
fi

# 6‑f GPS service and device check
if systemctl is-active --quiet raspyjack-gps.service; then
  info "GPS service is running"
else
  warn "GPS service not running - check: sudo systemctl status raspyjack-gps.service"
fi

# Check for GPS devices
if ls /dev/ttyACM* 2>/dev/null | grep -q ttyACM; then
  info "GPS devices found: $(ls /dev/ttyACM* | xargs)"
else
  warn "No GPS devices found - check USB connection"
fi

# Test GPS data access
python3 - <<'GPS_TEST' || warn "GPS test failed - check device connection"
import gpsd
import time
try:
    gpsd.connect()
    time.sleep(2)
    packet = gpsd.get_current()
    if hasattr(packet, 'mode') and packet.mode >= 2:
        print(f"[OK] GPS working - {packet.mode}D fix at {packet.lat:.4f},{packet.lon:.4f}")
    else:
        print("[WARN] GPS connected but no fix - move to clear sky view")
        print("[INFO] GPS will work once you get a satellite fix")
except Exception as e:
    print(f"[WARN] GPS test failed: {e}")
    print("[INFO] GPS may work after reboot or when device is connected")
GPS_TEST

# Final attempt to load TP-Link driver if needed
if [ "$USB_WIFI_DETECTED" = true ] && ! ip link show wlan1 >/dev/null 2>&1; then
  step "Final attempt to activate TP-Link AC600..."
  info "Trying to load RTL8812AU driver one more time..."
  
  if sudo modprobe 8812au 2>/dev/null || sudo insmod /lib/modules/$(uname -r)/kernel/drivers/net/wireless/88XXau.ko 2>/dev/null; then
    sleep 3
    if ip link show wlan1 >/dev/null 2>&1; then
      info "SUCCESS: wlan1 interface now available!"
    else
      warn "wlan1 still not found - device may need reconnection"
    fi
  else
    warn "Final driver load attempt failed"
  fi
fi

step "Installation finished successfully!"
info "⚠️  Reboot is recommended to ensure overlays & services start cleanly."
info "📡 For WiFi attacks: Plug in USB WiFi dongle and run payloads/deauth.py"
info "🔧 TP-Link AC600: Driver installed - if wlan1 not found, unplug/reconnect dongle"
info "🗺️  For wardriving: Run payloads/wardriving.py (GPS should work automatically)"
