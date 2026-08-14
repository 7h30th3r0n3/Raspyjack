#!/usr/bin/env bash
set -euo pipefail

# Install Proxmark3 client (Iceman/RRG fork) for RaspyJack NFC support.
# Compiles from source — takes ~10 min on a Pi 4, ~15 min on a Pi Zero 2.

INSTALL_DIR="/opt/proxmark3"
REPO_URL="https://github.com/RfidResearchGroup/proxmark3.git"
SUDO="sudo"

if [[ "$(id -u)" -eq 0 ]]; then
  SUDO=""
fi

step() { printf "\e[1;34m[STEP]\e[0m %s\n" "$*"; }
info() { printf "\e[1;32m[INFO]\e[0m %s\n" "$*"; }
warn() { printf "\e[1;33m[WARN]\e[0m %s\n" "$*"; }
fail() { printf "\e[1;31m[FAIL]\e[0m %s\n" "$*"; exit 1; }

if which pm3 >/dev/null 2>&1; then
  info "pm3 already installed: $(which pm3)"
  pm3 --version 2>&1 | head -1 || true
  info "To reinstall, remove $INSTALL_DIR first."
  exit 0
fi

ARCH="$(uname -m)"
if [[ "$ARCH" != "aarch64" && "$ARCH" != "armv7l" ]]; then
  warn "Architecture: $ARCH — this script targets ARM (Raspberry Pi)"
fi

step "Installing build dependencies..."
$SUDO apt-get update -qq
$SUDO apt-get install -y -qq \
  git build-essential libreadline-dev gcc-arm-none-eabi \
  libnewlib-dev libusb-1.0-0-dev libbz2-dev liblz4-dev \
  pkg-config 2>/dev/null || warn "Some packages may have failed (non-critical)"

step "Cloning Proxmark3 (Iceman fork)..."
if [[ -d "$INSTALL_DIR" ]]; then
  info "Directory exists, pulling latest..."
  cd "$INSTALL_DIR"
  $SUDO git pull --ff-only || warn "Git pull failed, using existing source"
else
  $SUDO git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
  cd "$INSTALL_DIR"
fi

step "Patching Makefile for GCC 14+ compatibility..."
$SUDO sed -i 's/ -Werror//g' Makefile.defs 2>/dev/null || true

NPROC=$(nproc 2>/dev/null || echo 2)
JOBS=$((NPROC > 1 ? NPROC : 1))

step "Compiling client (${JOBS} threads)..."
$SUDO make clean >/dev/null 2>&1 || true
$SUDO make -j"$JOBS" client PLATFORM=PM3GENERIC 2>&1 | tail -5

if [[ ! -f "$INSTALL_DIR/client/proxmark3" ]]; then
  fail "Compilation failed — binary not found"
fi

step "Installing..."
$SUDO ln -sf "$INSTALL_DIR/pm3" /usr/local/bin/pm3

step "Adding udev rules for Proxmark3..."
$SUDO cp "$INSTALL_DIR/driver/77-pm3-usb-device-blacklist.rules" /etc/udev/rules.d/ 2>/dev/null || true
$SUDO udevadm control --reload-rules 2>/dev/null || true

info "Proxmark3 client installed successfully!"
info "Binary: $INSTALL_DIR/client/proxmark3"
info "Command: pm3"
echo ""
info "Plug in your Proxmark3 and run any RaspyJack NFC payload."
info "Auto-detection will find it on /dev/ttyACM0."
