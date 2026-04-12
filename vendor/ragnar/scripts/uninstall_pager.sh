#!/bin/bash
#
# uninstall_pager.sh - Remove Ragnar from a WiFi Pineapple Pager
#
# Usage:
#   ./uninstall_pager.sh [pager-ip]
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
if [ -z "$1" ]; then
    read -p "Enter Pager IP address [172.16.42.1]: " _pager_ip
    PAGER_IP="${_pager_ip:-172.16.42.1}"
else
    PAGER_IP="$1"
fi
PAGER_USER="root"
PAGER_PAYLOAD_DIR="/root/payloads/user/reconnaissance/pager_ragnar"

log() {
    local level=$1; shift
    case $level in
        "INFO")    echo -e "${BLUE}[INFO]${NC} $*" ;;
        "SUCCESS") echo -e "${GREEN}[OK]${NC} $*" ;;
        "WARNING") echo -e "${YELLOW}[WARN]${NC} $*" ;;
        "ERROR")   echo -e "${RED}[ERROR]${NC} $*" ;;
        *)         echo -e "$*" ;;
    esac
}

echo -e "${CYAN}"
echo "  ╔═══════════════════════════════════════════════════════╗"
echo "  ║     Ragnar - WiFi Pineapple Pager Uninstaller        ║"
echo "  ╚═══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# SSH options
SSH_OPTS="-o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

# Find SSH key
for key in "$HOME/.ssh/id_ed25519" "$HOME/.ssh/id_rsa" "$HOME/.ssh/id_ecdsa"; do
    if [ -f "$key" ]; then
        SSH_OPTS="$SSH_OPTS -i $key"
        break
    fi
done

# Test connectivity
log "INFO" "Connecting to Pager at ${PAGER_IP}..."
if ! ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "echo ok" >/dev/null 2>&1; then
    SSH_OPTS="-o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    log "WARNING" "Key auth failed, trying password auth..."
    if ! ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "echo ok"; then
        log "ERROR" "Cannot connect to Pager at ${PAGER_IP}"
        exit 1
    fi
fi
log "SUCCESS" "Connected to Pager"

# Confirm
echo ""
echo -e "${YELLOW}This will remove Ragnar from the Pager:${NC}"
echo "  - Stop all Ragnar/Python3 processes"
echo "  - Delete ${PAGER_PAYLOAD_DIR}"
echo "  - Remove /root/Ragnar symlink"
echo "  - Remove /root/lib/libpagerctl.so"
echo "  - Optionally remove python-nmap"
echo ""
read -p "Continue? (y/n): " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# Stop processes
log "INFO" "Stopping Ragnar processes..."
ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "killall -9 python3 2>/dev/null; echo done"
log "SUCCESS" "Processes stopped"

# Remove payload directory
log "INFO" "Removing payload directory..."
ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "rm -rf ${PAGER_PAYLOAD_DIR} && echo removed"
log "SUCCESS" "Removed ${PAGER_PAYLOAD_DIR}"

# Remove symlink
log "INFO" "Removing /root/Ragnar symlink..."
ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "rm -f /root/Ragnar && echo removed"
log "SUCCESS" "Symlink removed"

# Remove system libpagerctl copy
log "INFO" "Removing /root/lib/libpagerctl.so..."
ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "rm -f /root/lib/libpagerctl.so && echo removed"
log "SUCCESS" "libpagerctl.so removed"

# Optional: remove python-nmap
echo ""
read -p "Also remove python-nmap from system? (y/n): " rm_nmap
if [[ "$rm_nmap" =~ ^[Yy]$ ]]; then
    log "INFO" "Removing python-nmap..."
    ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "rm -rf /usr/lib/python3.11/nmap && echo removed"
    log "SUCCESS" "python-nmap removed"
fi

echo ""
echo -e "${GREEN}  ╔═══════════════════════════════════════════════════════╗"
echo -e "  ║     Ragnar successfully removed from Pager!           ║"
echo -e "  ╚═══════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  To reinstall later:"
echo "    ./install_pineapple_pager.sh ${PAGER_IP}"
echo ""
