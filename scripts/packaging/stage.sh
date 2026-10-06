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
#   img/screensaver     ~111 MB  GIF gallery (one default re-added below)
#   *.psd                ~21 MB  Photoshop sources (vendor/ragnar)
#   loot/DeadDrop/files  ~29 MB  demo payload content
rm -rf \
  "$APP_ROOT/.github" \
  "$APP_ROOT/github-img" \
  "$APP_ROOT/docs" \
  "$APP_ROOT/dist" \
  "$APP_ROOT/img/screensaver" \
  "$APP_ROOT/loot/DeadDrop/files" \
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

# APPLaunch entry point. APPLaunch execs this directly (fork+execlp, no shell),
# so all environment/privilege setup must live inside the script.
cat > "$APP_ROOT/run-raspyjack.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/usr/share/APPLaunch/apps/raspyjack"
LEGACY_DIR="/root/Raspyjack"
RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp}/raspyjack"

# Many payloads hardcode /root/Raspyjack; expose the installed tree there.
if [ ! -e "$LEGACY_DIR" ] && [ "$(id -u)" -eq 0 ]; then
  ln -s "$APP_DIR" "$LEGACY_DIR" 2>/dev/null || true
fi

mkdir -p "$RUNTIME_DIR"
cd "$RUNTIME_DIR"

export PYTHONUNBUFFERED=1
export PYTHONPATH="$APP_DIR${PYTHONPATH:+:$PYTHONPATH}"
export RJ_GPIO_BACKEND="${RJ_GPIO_BACKEND:-evdev}"

# RaspyJack needs root: raw sockets, monitor mode, iptables, nmap SYN scans,
# NFC/SPI/GPIO. The CardputerZero factory OS grants the default user passwordless
# sudo (same assumption as the cardputerzero-pwnagotchi store app); 'sudo' is a
# declared package dependency. Pass env explicitly to survive sudo env_reset.
if [ "$(id -u)" -ne 0 ]; then
  exec sudo RJ_GPIO_BACKEND="$RJ_GPIO_BACKEND" PYTHONUNBUFFERED=1 \
       PYTHONPATH="$APP_DIR" python3 "$APP_DIR/raspyjack.py"
fi
exec python3 "$APP_DIR/raspyjack.py"
EOF
chmod 0755 "$APP_ROOT/run-raspyjack.sh"

install -Dm0644 /dev/null "$STAGE/usr/share/doc/raspyjack/.keep"
