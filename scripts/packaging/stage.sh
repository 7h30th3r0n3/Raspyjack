#!/bin/bash
set -euo pipefail

APP_ROOT="$STAGE$APP_INSTALL_DIR"
mkdir -p "$APP_ROOT"

if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git archive --format=tar HEAD | tar -xf - -C "$APP_ROOT"
fi

if command -v rsync >/dev/null 2>&1; then
  rsync -a \
    --exclude='.git' \
    --exclude='dist' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    ./ "$APP_ROOT/"
else
  tar \
    --exclude='./.git' \
    --exclude='./dist' \
    --exclude='./__pycache__' \
    --exclude='*/__pycache__' \
    --exclude='*.pyc' \
    -cf - . | tar -xf - -C "$APP_ROOT"
fi

cat > "$APP_ROOT/run-raspyjack.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/usr/share/APPLaunch/apps/raspyjack"
LEGACY_DIR="/root/Raspyjack"
RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp}/raspyjack"

if [ ! -e "$LEGACY_DIR" ] && [ "$(id -u)" -eq 0 ]; then
  ln -s "$APP_DIR" "$LEGACY_DIR"
fi

mkdir -p "$RUNTIME_DIR"
cd "$RUNTIME_DIR"
export PYTHONUNBUFFERED=1
export PYTHONPATH="$LEGACY_DIR${PYTHONPATH:+:$PYTHONPATH}"
export RJ_GPIO_BACKEND="${RJ_GPIO_BACKEND:-evdev}"
exec sudo python3 "$LEGACY_DIR/raspyjack.py"
EOF
chmod 0755 "$APP_ROOT/run-raspyjack.sh"

install -Dm0644 /dev/null "$STAGE/usr/share/doc/raspyjack/.keep"
