#!/bin/bash
# Initialize Data Files from Templates
# This script copies .template files to their runtime versions if they don't exist
# Used during first install and updates

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DATA_DIR="$SCRIPT_DIR/data"

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Initializing Ragnar data files from templates...${NC}"

# Template files to initialize
TEMPLATES=(
    "intelligence/active_findings.json"
    "intelligence/network_profiles.json"
    "intelligence/resolved_findings.json"
    "threat_intelligence/enriched_findings.json"
    "threat_intelligence/sources_config.json"
    "threat_intelligence/threat_cache.json"
    "network_data/network_unknown_network.csv"
    "input/dictionary/users.txt"
)

INITIALIZED=0
SKIPPED=0

for template_file in "${TEMPLATES[@]}"; do
    template_path="$DATA_DIR/${template_file}.template"
    target_path="$DATA_DIR/${template_file}"
    
    if [ -f "$template_path" ]; then
        if [ ! -f "$target_path" ]; then
            # Create directory if it doesn't exist
            mkdir -p "$(dirname "$target_path")"
            
            # Copy template to target
            cp "$template_path" "$target_path"
            echo -e "  ${GREEN}✓${NC} Initialized: $template_file"
            ((INITIALIZED++))
        else
            echo -e "  ${YELLOW}⊙${NC} Exists: $template_file (skipped)"
            ((SKIPPED++))
        fi
    else
        echo -e "  ${YELLOW}⚠${NC} Template missing: ${template_file}.template"
    fi
done

echo ""
echo -e "${GREEN}Initialization complete!${NC}"
echo -e "  Created: $INITIALIZED files"
echo -e "  Skipped: $SKIPPED files (already exist)"
