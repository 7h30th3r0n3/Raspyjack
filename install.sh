#!/usr/bin/env bash
set -euo pipefail

echo ">>> Updating APT and installing Python dependencies…"
sudo apt-get update -y
sudo apt-get install -y --no-install-recommends \
     python3-pil python3-pip python3-numpy python3-serial \
     python3-setuptools python3-pyudev python3-dev python3-smbus \
     python3-rpi.gpio python3-netifaces git

###############################################################################
#  I²C / SPI  — add the line only if it is not already present
###############################################################################
CFG=/boot/config.txt
add_dtparam() { grep -qxF "$1" "$CFG" || echo "$1" | sudo tee -a "$CFG" > /dev/null; }
add_module()  { grep -qxF "$1" /etc/modules || echo "$1" | sudo tee -a /etc/modules > /dev/null; }

echo ">>> Enabling I²C and SPI…"
add_dtparam "dtparam=i2c_arm=on"
add_dtparam "dtparam=i2c1=on"
add_dtparam "dtparam=spi=on"

# Recent kernels use i2c-bcm2835 instead of i2c-bcm2708
MODULE=i2c-bcm2835
lsmod | grep -q "^$MODULE" || sudo modprobe $MODULE
add_module "$MODULE"
add_module "i2c-dev"

###############################################################################
#  systemd service
###############################################################################
SERVICE=/etc/systemd/system/raspyjack.service
echo ">>> Installing systemd service…"
sudo tee "$SERVICE" > /dev/null <<'EOF'
[Unit]
Description=RaspyJack UI Service
After=network-online.target local-fs.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/root/raspyjack
ExecStart=/usr/bin/python3 /root/raspyjack/raspyjack.py
Restart=on-failure
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable raspyjack.service
sudo systemctl start  raspyjack.service

echo -e "\n✅  Done. Reboot to make sure everything comes up automatically."
