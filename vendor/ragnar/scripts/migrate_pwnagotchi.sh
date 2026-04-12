#!/bin/bash
# Ragnar Pwnagotchi Migration Script
# Detects the old pwnagotchi fork (evilsocket/PierreGode/pwnagotchi) and
# replaces it with the correct pwnagotchiworking fork (jayofelony noai branch).
# Designed to run at boot via ragnar-pwn-migrate.service (oneshot).
set -euo pipefail

PWN_DIR="/opt/pwnagotchi"
PWN_REPO="https://github.com/PierreGode/pwnagotchiworking.git"
CONFIG_DIR="/etc/pwnagotchi"
CONFIG_FILE="$CONFIG_DIR/config.toml"
LOG_DIR="/var/log/ragnar"
LOG_FILE="$LOG_DIR/pwnagotchi_migrate_$(date +%Y%m%d_%H%M%S).log"
MARKER_FILE="/var/lib/ragnar/.pwn_migrated"

mkdir -p "$LOG_DIR" "$(dirname "$MARKER_FILE")"
touch "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

# -------------------------------------------------------------------
# SKIP CONDITIONS
# -------------------------------------------------------------------

# Already migrated — skip
if [[ -f "$MARKER_FILE" ]]; then
    echo "[MIGRATE] Migration marker found — already migrated. Skipping."
    exit 0
fi

# Pwnagotchi not installed at all — skip
if [[ ! -d "$PWN_DIR" ]]; then
    echo "[MIGRATE] No pwnagotchi installation found at ${PWN_DIR}. Skipping."
    exit 0
fi

# Already using the new version (pyproject.toml present, no setup.py) — mark and skip
if [[ -f "$PWN_DIR/pyproject.toml" ]] && [[ ! -f "$PWN_DIR/setup.py" ]]; then
    echo "[MIGRATE] Pwnagotchi is already the correct version (pwnagotchiworking). Marking as migrated."
    date -Iseconds > "$MARKER_FILE"
    exit 0
fi

# -------------------------------------------------------------------
# OLD VERSION DETECTED — MIGRATE
# -------------------------------------------------------------------
echo "[MIGRATE] ============================================="
echo "[MIGRATE] Old pwnagotchi fork detected!"
echo "[MIGRATE] Migrating to pwnagotchiworking (noai branch)"
echo "[MIGRATE] ============================================="

# Stop pwnagotchi if running
echo "[MIGRATE] Stopping pwnagotchi service..."
systemctl stop pwnagotchi >/dev/null 2>&1 || true

# Preserve user config
if [[ -f "$CONFIG_FILE" ]]; then
    cp "$CONFIG_FILE" "$CONFIG_FILE.pre_migrate"
    echo "[MIGRATE] Backed up config to ${CONFIG_FILE}.pre_migrate"
fi

# Preserve RSA keys
if [[ -f "$CONFIG_DIR/id_rsa" ]]; then
    echo "[MIGRATE] RSA keys preserved (in-place, not touched)."
fi

# Move old installation to backup (don't delete yet — rollback if clone fails)
PWN_BACKUP="${PWN_DIR}.old_backup"
echo "[MIGRATE] Moving old pwnagotchi to ${PWN_BACKUP}..."
rm -rf "$PWN_BACKUP"
mv "$PWN_DIR" "$PWN_BACKUP"

# Clone new version
echo "[MIGRATE] Cloning pwnagotchiworking..."
if ! git clone --depth 1 "$PWN_REPO" "$PWN_DIR"; then
    echo "[MIGRATE] ERROR: git clone failed (no network?). Restoring old version."
    mv "$PWN_BACKUP" "$PWN_DIR"
    exit 1
fi

# Uninstall old pip package before installing new one
echo "[MIGRATE] Uninstalling old pwnagotchi pip package..."
python3 -m pip uninstall -y pwnagotchi 2>/dev/null || true

# Install new version
echo "[MIGRATE] Installing pwnagotchiworking (editable mode via pyproject.toml)..."
cd "$PWN_DIR"
if ! python3 -m pip install --break-system-packages --use-pep517 -e . 2>&1; then
    echo "[MIGRATE] WARNING: pip install with --use-pep517 failed, retrying without..."
    if ! python3 -m pip install --break-system-packages -e . 2>&1; then
        echo "[MIGRATE] ERROR: pip install failed. Restoring old version."
        rm -rf "$PWN_DIR"
        mv "$PWN_BACKUP" "$PWN_DIR"
        # Reinstall old package so it works again
        cd "$PWN_DIR" && python3 -m pip install --break-system-packages -e . 2>/dev/null || true
        exit 1
    fi
fi

# Clone and install succeeded — remove old backup
echo "[MIGRATE] New version installed successfully. Removing old backup..."
rm -rf "$PWN_BACKUP"

# -------------------------------------------------------------------
# MIGRATE CONFIG FORMAT (flat dot-notation → TOML tables)
# -------------------------------------------------------------------
if [[ -f "$CONFIG_FILE" ]]; then
    echo "[MIGRATE] Checking config format..."

    # Detect flat dot-notation format (lines like "main.name = ...")
    if grep -qE '^main\.' "$CONFIG_FILE" 2>/dev/null; then
        echo "[MIGRATE] Old flat dot-notation config detected. Converting to TOML tables..."

        python3 -c "
import tomlkit
import sys

try:
    with open('${CONFIG_FILE}', 'r') as f:
        old_doc = tomlkit.parse(f.read())

    # tomlkit parses dotted keys correctly into nested tables,
    # but we rewrite to use explicit TOML table headers for clarity
    with open('${CONFIG_FILE}', 'w') as f:
        f.write('# Ragnar-managed Pwnagotchi user config (pwnagotchiworking / noai branch)\n')
        f.write('# Migrated from old flat dot-notation format\n\n')
        f.write(tomlkit.dumps(old_doc))
    print('[MIGRATE] Config converted successfully.')
except Exception as e:
    print(f'[MIGRATE] WARNING: Config conversion failed: {e}')
    print('[MIGRATE] Keeping original config (TOML parsers handle dotted keys).')
" 2>&1
    else
        echo "[MIGRATE] Config already in TOML table format. No conversion needed."
    fi
fi

# -------------------------------------------------------------------
# ENSURE DEFAULT CONFIG EXISTS
# -------------------------------------------------------------------
DEFAULT_TOML="$CONFIG_DIR/default.toml"
if [[ ! -f "$DEFAULT_TOML" ]]; then
    SRC_DEFAULTS="$PWN_DIR/pwnagotchi/defaults.toml"
    if [[ -f "$SRC_DEFAULTS" ]]; then
        echo "[MIGRATE] Copying defaults.toml to ${DEFAULT_TOML}..."
        cp "$SRC_DEFAULTS" "$DEFAULT_TOML"
    fi
fi

# -------------------------------------------------------------------
# UPDATE SYSTEMD SERVICE (remove --config flag if present)
# -------------------------------------------------------------------
SERVICE_FILE="/etc/systemd/system/pwnagotchi.service"
if [[ -f "$SERVICE_FILE" ]]; then
    if grep -q '\-\-config' "$SERVICE_FILE"; then
        echo "[MIGRATE] Updating systemd service (removing --config flag)..."
        sed -i 's|ExecStart=.*pwnagotchi.*|ExecStart=/usr/local/bin/pwnagotchi|' "$SERVICE_FILE"
        systemctl daemon-reload
    fi
fi

# -------------------------------------------------------------------
# FINALIZE
# -------------------------------------------------------------------
date -Iseconds > "$MARKER_FILE"
echo "[MIGRATE] ============================================="
echo "[MIGRATE] Migration complete!"
echo "[MIGRATE] Old config backup: ${CONFIG_FILE}.pre_migrate"
echo "[MIGRATE] Log: ${LOG_FILE}"
echo "[MIGRATE] ============================================="
