#!/bin/bash
# Preserve Local Data Files Script
# This script backs up and restores local runtime data files that should never be pushed to GitHub

BACKUP_DIR=".local_backup"
DATA_DIR="data"

# Files to preserve (runtime data that should stay local)
PRESERVE_FILES=(
    "$DATA_DIR/ragnar.db"
    "$DATA_DIR/livestatus.csv"
    "$DATA_DIR/netkb.csv"
    "$DATA_DIR/pwnagotchi_status.json"
)

backup_files() {
    echo "🔒 Backing up local data files..."
    mkdir -p "$BACKUP_DIR"
    
    for file in "${PRESERVE_FILES[@]}"; do
        if [ -f "$file" ]; then
            cp -p "$file" "$BACKUP_DIR/$(basename $file)"
            echo "  ✓ Backed up: $file"
        fi
    done
    echo "✅ Backup complete"
}

restore_files() {
    echo "♻️  Restoring local data files..."
    
    for file in "${PRESERVE_FILES[@]}"; do
        backup_file="$BACKUP_DIR/$(basename $file)"
        if [ -f "$backup_file" ]; then
            mkdir -p "$(dirname $file)"
            cp -p "$backup_file" "$file"
            echo "  ✓ Restored: $file"
        fi
    done
    echo "✅ Restore complete"
}

cleanup_backup() {
    if [ -d "$BACKUP_DIR" ]; then
        rm -rf "$BACKUP_DIR"
        echo "🧹 Cleaned up backup directory"
    fi
}

case "$1" in
    backup)
        backup_files
        ;;
    restore)
        restore_files
        ;;
    cleanup)
        cleanup_backup
        ;;
    help|--help|-h)
        echo "Usage: $0 {backup|restore|cleanup}"
        echo ""
        echo "Commands:"
        echo "  backup  - Backup local data files before git pull/update"
        echo "  restore - Restore local data files after git pull/update"
        echo "  cleanup - Remove backup directory"
        echo ""
        echo "Recommended workflow:"
        echo "  ./preserve_local_data.sh backup"
        echo "  git pull"
        echo "  ./preserve_local_data.sh restore"
        echo "  ./preserve_local_data.sh cleanup"
        ;;
    *)
        echo "Error: Invalid command"
        echo "Run '$0 help' for usage information"
        exit 1
        ;;
esac
