#!/bin/sh
# Title: Ragnar
# Description: Network recon and security scanner
# Author: PierreGode / Ragnar Project
# Version: 1.2
# Category: Reconnaissance
# Library: libpagerctl.so (pagerctl)

# Payload directory (standard Pager installation path)
PAYLOAD_DIR="/root/payloads/user/reconnaissance/pager_ragnar"
DATA_DIR="$PAYLOAD_DIR/data"
LOG_FILE="$DATA_DIR/payload.log"

# Create data directory early so we can log
mkdir -p "$DATA_DIR" 2>/dev/null

# Internal logging helper - always writes to file, uses DuckyScript LOG when available
_log() {
    local color=""
    local msg="$*"
    if [ $# -ge 2 ]; then
        case "$1" in
            red|green|yellow|cyan|blue|magenta|purple)
                color="$1"
                shift
                msg="$*"
                ;;
        esac
    fi
    echo "[$(date '+%H:%M:%S')] $msg" >> "$LOG_FILE" 2>/dev/null
    if [ -n "$color" ]; then
        LOG "$color" "$msg" 2>/dev/null || true
    else
        LOG "$msg" 2>/dev/null || true
    fi
}

cd "$PAYLOAD_DIR" || {
    LOG "red" "ERROR: $PAYLOAD_DIR not found"
    exit 1
}

# Truncate log on fresh start
echo "=== Ragnar payload started $(date) ===" > "$LOG_FILE"

#
# Find and setup pagerctl dependencies (libpagerctl.so + pagerctl.py)
# Check bundled locations first, then PAGERCTL utilities dir
#
PAGERCTL_FOUND=false
for dir in "$PAYLOAD_DIR/lib" "$PAYLOAD_DIR" "/root/lib" "/mmc/root/payloads/user/utilities/PAGERCTL"; do
    if [ -f "$dir/libpagerctl.so" ]; then
        PAGERCTL_DIR="$dir"
        PAGERCTL_FOUND=true
        _log "Found libpagerctl.so in $dir"
        break
    fi
done

if [ "$PAGERCTL_FOUND" = false ]; then
    LOG ""
    LOG "red" "libpagerctl.so not found!"
    LOG ""
    LOG "Install PAGERCTL payload or copy to:"
    LOG "  $PAYLOAD_DIR/lib/"
    LOG ""
    LOG "Press any button to exit..."
    WAIT_FOR_INPUT >/dev/null 2>&1
    exit 1
fi

# If pagerctl files aren't in our lib dir, copy them there
if [ "$PAGERCTL_DIR" != "$PAYLOAD_DIR/lib" ]; then
    mkdir -p "$PAYLOAD_DIR/lib" 2>/dev/null
    cp "$PAGERCTL_DIR/libpagerctl.so" "$PAYLOAD_DIR/lib/" 2>/dev/null
    [ -f "$PAGERCTL_DIR/pagerctl.py" ] && cp "$PAGERCTL_DIR/pagerctl.py" "$PAYLOAD_DIR/lib/" 2>/dev/null
    LOG "green" "Copied pagerctl from $PAGERCTL_DIR"
fi

#
# Setup local paths for bundled binaries and libraries
# Uses libpagerctl.so for display/input handling
# MMC paths needed when python3 installed with opkg -d mmc
#
export PATH="/mmc/usr/bin:$PAYLOAD_DIR/bin:$PATH"
export PYTHONPATH="$PAYLOAD_DIR/lib:$PAYLOAD_DIR:$PYTHONPATH"
export LD_LIBRARY_PATH="/mmc/usr/lib:$PAYLOAD_DIR/lib:$PAYLOAD_DIR:$LD_LIBRARY_PATH"
export CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1
export RAGNAR_PAGER_MODE=1

#
# Check for Python3 and python3-ctypes - required system dependencies
#
NEED_PYTHON=false
NEED_CTYPES=false

if ! command -v python3 >/dev/null 2>&1; then
    NEED_PYTHON=true
    NEED_CTYPES=true
elif ! python3 -c "import ctypes" 2>/dev/null; then
    NEED_CTYPES=true
fi

if [ "$NEED_PYTHON" = true ] || [ "$NEED_CTYPES" = true ]; then
    LOG ""
    if [ "$NEED_PYTHON" = true ]; then
        LOG "red" "Python3 required to run Ragnar."
    else
        LOG "red" "Python3-ctypes required."
    fi
    LOG ""
    LOG "green" "GREEN = Install (needs internet)"
    LOG "red" "RED   = Exit"

    while true; do
        BUTTON=$(WAIT_FOR_INPUT 2>/dev/null)
        case "$BUTTON" in
            "GREEN"|"A")
                LOG ""
                LOG "Updating package lists..."
                opkg update 2>&1 | while IFS= read -r line; do LOG "  $line"; done
                LOG ""
                LOG "Installing Python3 + ctypes to MMC..."
                opkg -d mmc install python3 python3-ctypes 2>&1 | while IFS= read -r line; do LOG "  $line"; done
                LOG ""
                if command -v python3 >/dev/null 2>&1 && python3 -c "import ctypes" 2>/dev/null; then
                    LOG "green" "Python3 installed successfully!"
                    sleep 1
                else
                    LOG "red" "Failed to install Python3"
                    LOG "red" "Check internet connection and try again."
                    LOG ""
                    LOG "Press any button to exit..."
                    WAIT_FOR_INPUT >/dev/null 2>&1
                    exit 1
                fi
                break
                ;;
            "RED"|"B")
                LOG "Exiting."
                exit 0
                ;;
        esac
    done
fi

#
# Check nmap dependency
#
check_dependencies() {
    _log "Checking dependencies..."

    if ! command -v nmap >/dev/null 2>&1; then
        LOG ""
        LOG "red" "nmap not found. Installing..."
        opkg update 2>&1 | while IFS= read -r line; do LOG "  $line"; done
        opkg -d mmc install nmap 2>&1 | while IFS= read -r line; do LOG "  $line"; done

        if ! command -v nmap >/dev/null 2>&1; then
            LOG "red" "ERROR: nmap installation failed!"
            LOG "Press any button to exit..."
            WAIT_FOR_INPUT >/dev/null 2>&1
            exit 1
        fi
    fi

    # Ensure vulners.nse is in the nmap scripts directory.
    # The opkg nmap package does not include third-party NSE scripts;
    # we bundle vulners.nse in the payload and install it at runtime.
    NMAP_SCRIPTS_DIR=""
    for _d in /usr/share/nmap/scripts /usr/lib/nmap/scripts /opt/nmap/scripts; do
        if [ -d "$_d" ]; then
            NMAP_SCRIPTS_DIR="$_d"
            break
        fi
    done
    [ -z "$NMAP_SCRIPTS_DIR" ] && NMAP_SCRIPTS_DIR="/usr/share/nmap/scripts" && mkdir -p "$NMAP_SCRIPTS_DIR"

    if [ ! -f "${NMAP_SCRIPTS_DIR}/vulners.nse" ]; then
        if [ -f "${PAYLOAD_DIR}/nmap_scripts/vulners.nse" ]; then
            cp "${PAYLOAD_DIR}/nmap_scripts/vulners.nse" "${NMAP_SCRIPTS_DIR}/"
            nmap --script-updatedb >/dev/null 2>&1 || true
            _log green "Installed vulners.nse for vulnerability scanning"
        else
            _log "WARNING: vulners.nse not found - vulnerability scanning will be limited"
        fi
    fi

    _log green "All dependencies found!"
}

#
# Pre-flight: Validate Python can import critical modules BEFORE stopping pineapple
#
preflight_python() {
    _log "Running Python pre-flight checks..."

    local result
    result=$(python3 -c "
import sys, os
sys.path.insert(0, os.path.join('$PAYLOAD_DIR', 'lib'))
sys.path.insert(0, '$PAYLOAD_DIR')
errors = []
try:
    from pagerctl import Pager
except Exception as e:
    errors.append(f'pagerctl: {e}')
try:
    import json, threading, time, subprocess, signal
except Exception as e:
    errors.append(f'stdlib: {e}')
try:
    import shared
except Exception as e:
    errors.append(f'shared: {e}')
if errors:
    print('FAIL:' + '|'.join(errors))
    sys.exit(1)
else:
    print('OK')
    sys.exit(0)
" 2>&1)

    if [ $? -ne 0 ]; then
        LOG ""
        LOG "red" "=== PRE-FLIGHT FAILED ==="
        LOG "red" "Python module import errors:"
        echo "$result" | while IFS= read -r line; do
            LOG "red" "  $line"
            echo "$line" >> "$LOG_FILE"
        done
        LOG ""
        LOG "Check $LOG_FILE for details."
        LOG "Press any button to exit..."
        WAIT_FOR_INPUT >/dev/null 2>&1
        exit 1
    fi

    _log "Pre-flight OK"
}

# ============================================================
# DISPLAY TAKEOVER & CLEANUP
# ============================================================

take_over_display() {
    _log "Taking over display from pineapple service..."

    # Stop the pager service cleanly via init.d (same approach as Bjorn)
    /etc/init.d/pineapplepager stop 2>/dev/null
    sleep 0.5

    # If it's still running, force kill (fallback)
    if pgrep -x pineapple >/dev/null 2>&1; then
        _log "Service still running, force killing..."
        killall -9 pineapple 2>/dev/null
        killall -9 pineapd 2>/dev/null
        sleep 0.3
    fi

    _log green "Display takeover complete"
}

cleanup() {
    _log "Cleanup: restarting pineapplepager service..."
    # Restart pager service so the normal Pager UI comes back
    if ! pgrep -x pineapple >/dev/null 2>&1; then
        /etc/init.d/pineapplepager start 2>/dev/null
    fi
}

# Ensure pager service restarts on exit
trap cleanup EXIT

# ============================================================
# MAIN
# ============================================================

check_dependencies

# Check network connectivity (at least one interface with IP)
HAS_NETWORK=false
for IP in $(ip -4 addr 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1); do
    if [ "$IP" != "127.0.0.1" ]; then
        HAS_NETWORK=true
        break
    fi
done

if [ "$HAS_NETWORK" = false ]; then
    LOG ""
    LOG "red" "No network connected!"
    LOG ""
    LOG "Connect WiFi or Ethernet first."
    LOG ""
    LOG "Press any button to exit..."
    WAIT_FOR_INPUT >/dev/null 2>&1
    exit 1
fi

# Pre-flight Python check (while pineapple is still alive so errors show on LCD)
preflight_python

# Show splash screen
LOG ""
LOG "green" "Ragnar - Network Recon"
LOG ""
LOG "cyan" "Scan / Brute / Exfil / Vuln / Web UI"
LOG ""
LOG "green" "GREEN = Start"
LOG "red" "RED = Exit"

while true; do
    BUTTON=$(WAIT_FOR_INPUT 2>/dev/null)
    case "$BUTTON" in
        "GREEN"|"A")
            break
            ;;
        "RED"|"B")
            LOG "Exiting."
            exit 0
            ;;
    esac
done

# Take over the LCD from the pineapple service.
# Must kill pineapple (UI) + pineapd (PineAP) + deregister from procd.
LOG "Starting Ragnar..."
take_over_display
sleep 0.3

# Payload loop with handoff support
# Python writes the target launch script path to data/.next_payload
NEXT_PAYLOAD_FILE="$DATA_DIR/.next_payload"

while true; do
    cd "$PAYLOAD_DIR"
    _log "Launching pager_menu.py..."
    python3 pager_menu.py >> "$LOG_FILE" 2>&1
    EXIT_CODE=$?
    _log "pager_menu.py exited with code $EXIT_CODE"

    # Exit code 42 = hand off to another payload
    if [ "$EXIT_CODE" -eq 42 ] && [ -f "$NEXT_PAYLOAD_FILE" ]; then
        NEXT_SCRIPT=$(cat "$NEXT_PAYLOAD_FILE")
        rm -f "$NEXT_PAYLOAD_FILE"
        if [ -f "$NEXT_SCRIPT" ]; then
            _log "Handing off to $NEXT_SCRIPT"
            sh "$NEXT_SCRIPT"
            # Only loop back to Ragnar if launched app exits 42
            [ $? -eq 42 ] && continue
        fi
    fi

    # Exit code 99 = return to main menu (from pause menu)
    if [ "$EXIT_CODE" -eq 99 ]; then
        _log "Returning to menu (exit code 99)"
        continue
    fi

    # If pager_menu.py crashed, log it
    if [ "$EXIT_CODE" -ne 0 ]; then
        _log red "pager_menu.py failed (exit $EXIT_CODE)"
    fi

    break
done

exit 0
