#!/usr/bin/env bash
# Toggle between RaspyJack and APPLaunch on CardputerZero
# Usage: sudo ./toggle_applaunch.sh [raspyjack|applaunch]
set -euo pipefail

APPLAUNCH_BIN="/usr/share/APPLaunch/bin/M5CardputerZero-APPLaunch"
OVERRIDE_DIR="/home/pi/.config/systemd/user/APPLaunch.service.d"
PI_UID=$(id -u pi 2>/dev/null || echo 1000)
RUN_USER="sudo -u pi XDG_RUNTIME_DIR=/run/user/$PI_UID"

current_mode() {
  if [ -L "$APPLAUNCH_BIN" ]; then
    echo "raspyjack"
  elif [ -f "$APPLAUNCH_BIN" ]; then
    echo "applaunch"
  else
    echo "unknown"
  fi
}

to_raspyjack() {
  echo "[*] Switching to RaspyJack mode..."
  $RUN_USER systemctl --user stop APPLaunch.service 2>/dev/null || true
  if [ -f "$APPLAUNCH_BIN" ] && [ ! -L "$APPLAUNCH_BIN" ]; then
    mv "$APPLAUNCH_BIN" "${APPLAUNCH_BIN}.real"
  fi
  ln -sf /usr/bin/sleep "$APPLAUNCH_BIN"
  mkdir -p "$OVERRIDE_DIR"
  cat > "$OVERRIDE_DIR/override.conf" <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/share/APPLaunch/bin/M5CardputerZero-APPLaunch infinity
EOF
  $RUN_USER systemctl --user daemon-reload
  $RUN_USER systemctl --user enable APPLaunch.service
  $RUN_USER systemctl --user start APPLaunch.service
  systemctl enable raspyjack.service 2>/dev/null || true
  systemctl start raspyjack.service 2>/dev/null || true
  echo "[OK] RaspyJack mode active (APPLaunch = sleep dummy for fb_load)"
}

to_applaunch() {
  echo "[*] Switching to APPLaunch mode..."
  systemctl stop raspyjack.service 2>/dev/null || true
  systemctl disable raspyjack.service 2>/dev/null || true
  $RUN_USER systemctl --user stop APPLaunch.service 2>/dev/null || true
  if [ -f "${APPLAUNCH_BIN}.real" ]; then
    rm -f "$APPLAUNCH_BIN"
    mv "${APPLAUNCH_BIN}.real" "$APPLAUNCH_BIN"
  fi
  rm -f "$OVERRIDE_DIR/override.conf"
  $RUN_USER systemctl --user daemon-reload
  $RUN_USER systemctl --user start APPLaunch.service
  echo "[OK] APPLaunch mode active (original M5Stack UI restored)"
}

MODE="${1:-}"
CURRENT=$(current_mode)

if [ -z "$MODE" ]; then
  echo "Current mode: $CURRENT"
  echo "Usage: $0 [raspyjack|applaunch]"
  exit 0
fi

case "$MODE" in
  raspyjack)
    if [ "$CURRENT" = "raspyjack" ]; then
      echo "Already in RaspyJack mode"
      exit 0
    fi
    to_raspyjack
    ;;
  applaunch)
    if [ "$CURRENT" = "applaunch" ]; then
      echo "Already in APPLaunch mode"
      exit 0
    fi
    to_applaunch
    ;;
  *)
    echo "Usage: $0 [raspyjack|applaunch]"
    exit 1
    ;;
esac
