#!/bin/bash
# Fix permissions for Ragnar shell scripts

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Fixing permissions for Ragnar shell scripts..."

# Make all shell scripts executable (both root and scripts/ directory)
chmod +x "$PROJECT_ROOT"/*.sh 2>/dev/null || true
chmod +x "$SCRIPT_DIR"/*.sh

# Verify the permissions were set correctly
echo "Current permissions for shell scripts:"
ls -la "$PROJECT_ROOT"/*.sh "$SCRIPT_DIR"/*.sh

echo "All shell scripts now have execute permissions."
echo "You can now restart the Ragnar service with: sudo systemctl restart ragnar"