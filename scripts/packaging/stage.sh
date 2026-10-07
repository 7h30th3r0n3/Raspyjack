#!/bin/bash
# Populate the staging tree with the RaspyJack runtime payload + launcher wrapper.
# Invoked by scripts/pack-deb.sh with STAGE / APP_INSTALL_DIR exported.
set -euo pipefail

APP_ROOT="$STAGE$APP_INSTALL_DIR"
mkdir -p "$APP_ROOT"

# Export the tracked tree (reproducible), falling back to a tar of the working
# tree when not in a git checkout.
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git archive --format=tar HEAD | tar -xf - -C "$APP_ROOT"
else
  tar --exclude='./.git' --exclude='./dist' --exclude='*/__pycache__' \
      --exclude='*.pyc' -cf - . | tar -xf - -C "$APP_ROOT"
fi

# Prune heavy, non-runtime artifacts to keep the .deb under the store web-portal
# ceiling (~80 MB). loot/wordlists is kept on purpose (used by cracking payloads);
# only the big DeadDrop demo blobs are dropped.
#   *.psd  ~21 MB  Photoshop sources (vendor/ragnar) — useless at runtime
# The screensaver GIF gallery and DeadDrop demo content ARE shipped (full app);
# this makes the .deb too big for the web portal, so submit via czdev.
rm -rf \
  "$APP_ROOT/.github" \
  "$APP_ROOT/github-img" \
  "$APP_ROOT/docs" \
  "$APP_ROOT/dist" \
  "$APP_ROOT/scripts/packaging/icon.png"
find "$APP_ROOT" -name '*.psd' -delete 2>/dev/null || true
find "$APP_ROOT" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true

# Keep one lightweight default screensaver so gui_conf's SCREENSAVER_GIF path
# resolves even though the full GIF gallery is excluded for size.
mkdir -p "$APP_ROOT/img/screensaver"
for g in img/screensaver/smileyglitch.gif img/screensaver/youhavebeenhacked.gif; do
  if [ -f "$g" ]; then
    cp "$g" "$APP_ROOT/img/screensaver/default.gif"
    break
  fi
done

# RPi.GPIO shim: shadow the system python3-rpi.gpio (which uses the lgpio
# backend and crashes on CardputerZero) with the evdev-based gpio_shim. Several
# modules (LCD_1in44, LCD_Config, input_events) do a top-level `import RPi.GPIO`
# that bypasses raspyjack.py's conditional, so shadowing is the reliable fix.
# PYTHONPATH=$APP_DIR (exported by the wrapper) makes this win over the system
# package. Generated only in the staged tree → never ships to a Raspberry Pi.
mkdir -p "$APP_ROOT/RPi"
: > "$APP_ROOT/RPi/__init__.py"
echo "from gpio_shim import *" > "$APP_ROOT/RPi/GPIO.py"

# APPLaunch entry point. APPLaunch execs this directly (fork+execlp, no shell),
# so all environment/privilege setup must live inside the script.
cat > "$APP_ROOT/run-raspyjack.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/usr/share/APPLaunch/apps/raspyjack"
LEGACY_DIR="/root/Raspyjack"
WORK_DIR="/tmp/raspyjack"

# Audio: RaspyJack runs privileged (sudo) for raw sockets etc., but PipeWire
# runs in the LAUNCHING user's session. Point audio at that session's
# PipeWire/Pulse so sound works from the root process (ALSA 'default',
# ffmpeg -f pulse, ffplay/SDL, paplay all follow these).
USER_XDG="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export XDG_RUNTIME_DIR="$USER_XDG"
export PULSE_SERVER="unix:${USER_XDG}/pulse/native"
export SDL_AUDIODRIVER="pulse"

# Many payloads hardcode /root/Raspyjack; expose the installed tree there.
if [ ! -e "$LEGACY_DIR" ] && [ "$(id -u)" -eq 0 ]; then
  ln -s "$APP_DIR" "$LEGACY_DIR" 2>/dev/null || true
fi

mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

export PYTHONUNBUFFERED=1
export PYTHONPATH="$APP_DIR${PYTHONPATH:+:$PYTHONPATH}"
export RJ_GPIO_BACKEND="${RJ_GPIO_BACKEND:-evdev}"

# RaspyJack needs root: raw sockets, monitor mode, iptables, nmap SYN scans,
# NFC/SPI/GPIO. The CardputerZero factory OS grants the default user passwordless
# sudo (same assumption as the cardputerzero-pwnagotchi store app); 'sudo' is a
# declared package dependency. Pass env explicitly to survive sudo env_reset,
# including the PipeWire session vars so audio reaches the user's sound server.
if [ "$(id -u)" -ne 0 ]; then
  exec sudo RJ_GPIO_BACKEND="$RJ_GPIO_BACKEND" PYTHONUNBUFFERED=1 \
       PYTHONPATH="$APP_DIR" XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
       PULSE_SERVER="$PULSE_SERVER" SDL_AUDIODRIVER="$SDL_AUDIODRIVER" \
       python3 "$APP_DIR/raspyjack.py"
fi
exec python3 "$APP_DIR/raspyjack.py"
EOF
chmod 0755 "$APP_ROOT/run-raspyjack.sh"

install -Dm0644 /dev/null "$STAGE/usr/share/doc/raspyjack/.keep"
