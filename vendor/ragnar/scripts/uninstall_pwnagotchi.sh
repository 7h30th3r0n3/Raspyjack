#!/bin/bash
# Uninstall Pwnagotchi and restore Ragnar as the only service
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo $0"
    exit 1
fi

echo "[INFO] Uninstalling Pwnagotchi..."

# Stop services
echo "[INFO] Stopping services..."
systemctl stop pwnagotchi 2>/dev/null || true
systemctl kill pwnagotchi 2>/dev/null || true
systemctl stop bettercap 2>/dev/null || true
systemctl stop ragnar-swap-button 2>/dev/null || true

# Disable services
echo "[INFO] Disabling services..."
systemctl disable pwnagotchi 2>/dev/null || true
systemctl disable ragnar-swap-button 2>/dev/null || true
systemctl disable ragnar-pwn-migrate 2>/dev/null || true

# Remove service files
echo "[INFO] Removing service files..."
rm -f /etc/systemd/system/pwnagotchi.service
rm -f /etc/systemd/system/ragnar-swap-button.service
rm -f /etc/systemd/system/ragnar-pwn-migrate.service
systemctl daemon-reload

# Remove pwnagotchi installation
echo "[INFO] Removing /opt/pwnagotchi..."
pip3 uninstall -y pwnagotchi 2>/dev/null || true
rm -rf /opt/pwnagotchi

# Remove config
echo "[INFO] Removing /etc/pwnagotchi..."
rm -rf /etc/pwnagotchi

# Remove helper scripts
echo "[INFO] Removing helper scripts..."
rm -f /usr/bin/pwnagotchi-launcher
rm -f /usr/bin/monstart
rm -f /usr/bin/monstop
rm -f /usr/local/bin/pwngrid
rm -f /usr/local/bin/ragnar-swap-button

# Remove Pillow shim
SITE=$(python3 -c "import site; print(site.getsitepackages()[0])" 2>/dev/null || echo "")
if [[ -n "$SITE" && -f "$SITE/pillow_compat.py" ]]; then
    rm -f "$SITE/pillow_compat.py"
    echo "[INFO] Removed Pillow compatibility shim"
fi

# Remove migration marker
rm -f /var/lib/ragnar/.pwn_migrated

# Reset Ragnar status file
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
STATUS_FILE="$REPO_ROOT/data/pwnagotchi_status.json"
if [[ -f "$STATUS_FILE" ]]; then
    cat > "$STATUS_FILE" << 'EOF'
{
  "state": "not_installed",
  "message": "Pwnagotchi not installed.",
  "phase": "uninstalled",
  "target_mode": "ragnar"
}
EOF
fi

# Ensure Ragnar is enabled and running
echo "[INFO] Ensuring Ragnar is running..."
systemctl enable ragnar 2>/dev/null || true
systemctl start ragnar 2>/dev/null || true

echo ""
echo "[INFO] Service status:"
echo "  ragnar:     $(systemctl is-enabled ragnar 2>/dev/null)  $(systemctl is-active ragnar 2>/dev/null)"
echo "  pwnagotchi: $(systemctl is-enabled pwnagotchi 2>/dev/null || echo 'removed')  $(systemctl is-active pwnagotchi 2>/dev/null || echo 'removed')"
echo ""
echo "[INFO] Pwnagotchi uninstalled. Ragnar is running."
