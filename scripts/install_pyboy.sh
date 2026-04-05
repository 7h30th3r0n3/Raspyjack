#!/usr/bin/env bash
# Install PyBoy Game Boy emulator dependencies for RaspyJack
# Usage: sudo bash scripts/install_pyboy.sh
set -euo pipefail

info()  { printf "\e[1;32m[INFO]\e[0m %s\n"  "$*"; }
warn()  { printf "\e[1;33m[WARN]\e[0m %s\n"  "$*"; }

info "Installing PyBoy dependencies..."

# SDL2 library (required by PyBoy)
apt-get install -y --no-install-recommends libsdl2-dev 2>/dev/null \
  || warn "libsdl2-dev install failed"

# PyBoy (Game Boy emulator)
pip3 install --break-system-packages pyboy 2>/dev/null \
  || pip3 install pyboy 2>/dev/null \
  || warn "PyBoy install failed"

# Create ROMs directory
mkdir -p /root/Raspyjack/roms

# Verify
python3 -c "from pyboy import PyBoy; print('[OK] PyBoy installed')" 2>/dev/null \
  || warn "PyBoy import failed - check errors above"

info "Done! Place .gb/.gbc ROMs in /root/Raspyjack/roms/"
