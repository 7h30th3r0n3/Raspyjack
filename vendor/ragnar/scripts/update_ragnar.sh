#!/bin/bash

# ragnar Update Script
# This script safely updates ragnar while preserving configurations and data
# Author: infinition
# Version: 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ragnar_PATH="/home/ragnar/Ragnar"

echo -e "${BLUE}ragnar Update Script${NC}"
echo -e "${YELLOW}This will update ragnar while preserving your data and configurations.${NC}"

# Check if we're in the right directory
if [ ! -d "$ragnar_PATH" ]; then
    echo -e "${RED}Error: ragnar directory not found at $ragnar_PATH${NC}"
    exit 1
fi

if [ ! -d "$ragnar_PATH/.git" ]; then
    echo -e "${RED}Error: This is not a git repository. Cannot update.${NC}"
    echo -e "${YELLOW}Please reinstall ragnar using the installation script.${NC}"
    exit 1
fi

cd "$ragnar_PATH"

# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}This script must be run as root. Please use 'sudo'.${NC}"
    exit 1
fi

echo -e "\n${BLUE}Step 1: Stopping ragnar service...${NC}"
systemctl stop ragnar.service

echo -e "${BLUE}Step 2: Backing up local changes...${NC}"
if git diff --quiet && git diff --staged --quiet; then
    echo -e "${GREEN}No local changes to backup.${NC}"
else
    echo -e "${YELLOW}Local changes detected. Creating backup...${NC}"
    git stash push -m "Auto-backup before update $(date)"
    echo -e "${GREEN}Local changes backed up.${NC}"
fi

echo -e "${BLUE}Step 2.5: Preserving local runtime data...${NC}"
BACKUP_DIR=".local_backup"
mkdir -p "$BACKUP_DIR"
PRESERVE_FILES=("data/ragnar.db" "data/livestatus.csv" "data/netkb.csv" "data/pwnagotchi_status.json")
for file in "${PRESERVE_FILES[@]}"; do
    if [ -f "$file" ]; then
        cp -p "$file" "$BACKUP_DIR/$(basename $file)"
        echo -e "  ${GREEN}✓${NC} Backed up: $file"
    fi
done

echo -e "${BLUE}Step 3: Fetching latest updates...${NC}"
git fetch origin

echo -e "${BLUE}Step 4: Updating to latest version...${NC}"
if git pull origin main; then
    echo -e "${GREEN}Update completed successfully!${NC}"
else
    echo -e "${RED}Update failed. Attempting to restore backup...${NC}"
    git stash pop
    echo -e "${YELLOW}Backup restored. Please check for conflicts manually.${NC}"
    exit 1
fi

echo -e "${BLUE}Step 5: Updating Python dependencies...${NC}"
pip3 install --break-system-packages -r requirements.txt --upgrade

echo -e "${BLUE}Step 5.5: Restoring local runtime data...${NC}"
for file in "${PRESERVE_FILES[@]}"; do
    backup_file="$BACKUP_DIR/$(basename $file)"
    if [ -f "$backup_file" ]; then
        mkdir -p "$(dirname $file)"
        cp -p "$backup_file" "$file"
        echo -e "  ${GREEN}✓${NC} Restored: $file"
    fi
done
rm -rf "$BACKUP_DIR"
echo -e "${GREEN}Local runtime data restored.${NC}"

echo -e "${BLUE}Step 5.6: Initializing data files from templates...${NC}"
bash "$ragnar_PATH/scripts/init_data_files.sh"

echo -e "${BLUE}Step 6: Setting correct permissions...${NC}"
chown -R ragnar:ragnar "$ragnar_PATH"
chmod +x "$ragnar_PATH"/*.sh 2>/dev/null || true

# Ensure specific critical scripts are executable
chmod +x "$ragnar_PATH/kill_port_8000.sh" 2>/dev/null || true
chmod +x "$ragnar_PATH/scripts/update_ragnar.sh" 2>/dev/null || true
chmod +x "$ragnar_PATH/scripts/"*.sh 2>/dev/null || true

echo -e "${BLUE}Step 6.5: Validating actions.json configuration...${NC}"
python3 << 'PYTHON_EOF'
import json
import os

actions_file = "/home/ragnar/ragnar/config/actions.json"

try:
    with open(actions_file, 'r') as f:
        actions = json.load(f)
    
    has_scanning = any(action.get('b_module') == 'scanning' for action in actions)
    
    if not has_scanning:
        print("WARNING: scanning module missing, adding it...")
        scanning_action = {
            "b_module": "scanning",
            "b_class": "NetworkScanner",
            "b_port": None,
            "b_status": "network_scanner",
            "b_parent": None
        }
        actions.insert(0, scanning_action)
        
        with open(actions_file, 'w') as f:
            json.dump(actions, f, indent=4)
        print("SUCCESS: Added scanning module to actions.json")
    else:
        print("SUCCESS: scanning module validated")
        
except Exception as e:
    print(f"ERROR validating actions.json: {e}")
PYTHON_EOF

echo -e "${BLUE}Step 6.7: Checking Pwnagotchi migration...${NC}"
MIGRATE_SCRIPT="$ragnar_PATH/scripts/migrate_pwnagotchi.sh"
if [[ -d "/opt/pwnagotchi" ]] && [[ -f "$MIGRATE_SCRIPT" ]]; then
    chmod +x "$MIGRATE_SCRIPT"
    if bash "$MIGRATE_SCRIPT"; then
        echo -e "${GREEN}Pwnagotchi migration check completed.${NC}"
    else
        echo -e "${YELLOW}Pwnagotchi migration had issues. Check /var/log/ragnar/ for details.${NC}"
    fi

    # Ensure boot-time migration service is installed
    if [[ ! -f "/etc/systemd/system/ragnar-pwn-migrate.service" ]]; then
        cat >"/etc/systemd/system/ragnar-pwn-migrate.service" <<SVCEOF
[Unit]
Description=Ragnar Pwnagotchi Migration Check
After=local-fs.target network-online.target
Before=pwnagotchi.service ragnar.service
ConditionPathExists=/opt/pwnagotchi

[Service]
Type=oneshot
ExecStart=${MIGRATE_SCRIPT}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVCEOF
        chmod 644 "/etc/systemd/system/ragnar-pwn-migrate.service"
        systemctl daemon-reload
        systemctl enable ragnar-pwn-migrate >/dev/null 2>&1 || true
        echo -e "${GREEN}Boot-time migration service installed.${NC}"
    fi
else
    echo -e "${GREEN}No Pwnagotchi installation found or migration script missing. Skipping.${NC}"
fi

echo -e "${BLUE}Step 7: Starting ragnar service...${NC}"
systemctl start ragnar.service

# Check if service started successfully
sleep 3
if systemctl is-active --quiet ragnar.service; then
    echo -e "${GREEN}ragnar service started successfully!${NC}"
else
    echo -e "${RED}Warning: ragnar service failed to start. Check logs with:${NC}"
    echo -e "${YELLOW}sudo journalctl -u ragnar.service -f${NC}"
fi

echo -e "\n${GREEN}Update completed!${NC}"
echo -e "${BLUE}To check if your local changes were backed up:${NC}"
echo -e "  git stash list"
echo -e "${BLUE}To restore your local changes if needed:${NC}"
echo -e "  git stash pop"
echo -e "${BLUE}To check service status:${NC}"
echo -e "  sudo systemctl status ragnar.service"
