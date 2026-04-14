#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RAGNAR_DIR="$ROOT_DIR/vendor/ragnar"
SUDO="sudo"

if [[ "$(id -u)" -eq 0 ]]; then
  SUDO=""
fi

step() { printf "\e[1;34m[STEP]\e[0m %s\n" "$*"; }
info() { printf "\e[1;32m[INFO]\e[0m %s\n" "$*"; }
warn() { printf "\e[1;33m[WARN]\e[0m %s\n" "$*"; }

if [[ ! -d "$RAGNAR_DIR" ]]; then
  echo "Vendored Ragnar tree not found at $RAGNAR_DIR" >&2
  exit 1
fi

APT_PACKAGES=(
  python3-flask
  python3-netifaces
  python3-numpy
  python3-pandas
  python3-paramiko
  python3-pil
  python3-psutil
  python3-pymysql
  python3-rich
  python3-scapy
  python3-smbus
  python3-spidev
  python3-sqlalchemy
  python3-nmap
)

PIP_PACKAGES=(
  Flask-SocketIO
  Flask-Cors
  get-mac
  luma.core
  luma.led_matrix
  openai
  ping3
  pisugar
  pysmb
  python-prctl
  smbprotocol
  smbus2
)

step "Installing Ragnar port APT dependencies"
$SUDO apt-get update
$SUDO apt-get install -y "${APT_PACKAGES[@]}"

step "Installing Ragnar port pip dependencies"
for pkg in "${PIP_PACKAGES[@]}"; do
  if $SUDO pip3 install --break-system-packages "$pkg"; then
    info "Installed $pkg"
  else
    warn "Failed to install $pkg"
  fi
done

step "Running Ragnar import preflight"
if PYTHONPATH="$RAGNAR_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -c "import headlessRagnar" >/dev/null 2>&1; then
  info "Ragnar import preflight passed"
else
  warn "Ragnar import preflight failed"
  warn "Try: PYTHONPATH=$RAGNAR_DIR python3 -c 'import headlessRagnar'"
fi

step "Ragnar port dependency pass complete"
info "Launch from Raspyjack: Payload -> Utilities -> Ragnar"
info "Default Ragnar port: 8091"
