#!/bin/bash
# Ragnar service correction - ensures Ragnar always starts on boot
# Run this if pwnagotchi took over or services are misconfigured
set -euo pipefail

echo "[INFO] Fixing service configuration..."

# Stop pwnagotchi and bettercap
echo "[INFO] Stopping pwnagotchi and bettercap..."
systemctl stop pwnagotchi 2>/dev/null || true
systemctl kill pwnagotchi 2>/dev/null || true
systemctl stop bettercap 2>/dev/null || true

# Clean up leftover monitor interface
echo "[INFO] Cleaning up monitor interface..."
ip link set mon0 down 2>/dev/null || true
iw mon0 del 2>/dev/null || true

# Disable pwnagotchi - must NEVER start on boot
echo "[INFO] Disabling pwnagotchi (boot disabled)..."
systemctl disable pwnagotchi 2>/dev/null || true

# Enable ragnar - ALWAYS starts on boot
echo "[INFO] Enabling ragnar (boot enabled)..."
systemctl enable ragnar

# Reset pwnagotchi status file so dashboard shows correct state
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
STATUS_FILE="$REPO_ROOT/data/pwnagotchi_status.json"
if [[ -f "$STATUS_FILE" ]]; then
    echo "[INFO] Resetting pwnagotchi status file..."
    cat > "$STATUS_FILE" << 'STATUSEOF'
{
  "state": "installed",
  "message": "Pwnagotchi installed. Use switch button to start.",
  "phase": "complete",
  "target_mode": "ragnar"
}
STATUSEOF
fi

# Start ragnar now
echo "[INFO] Starting ragnar..."
systemctl start ragnar

# Verify
echo ""
echo "[INFO] Service status:"
echo "  ragnar:     $(systemctl is-enabled ragnar 2>/dev/null)  $(systemctl is-active ragnar 2>/dev/null)"
echo "  pwnagotchi: $(systemctl is-enabled pwnagotchi 2>/dev/null)  $(systemctl is-active pwnagotchi 2>/dev/null)"
echo ""
echo "[INFO] Done. Ragnar is master. Reboot will always start Ragnar."
