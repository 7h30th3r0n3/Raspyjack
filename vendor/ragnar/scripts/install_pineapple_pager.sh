#!/bin/bash
#
# install_pineapple_pager.sh - Deploy Ragnar to a WiFi Pineapple Pager
#
# This script packages Ragnar as a Pager payload and copies it to the device.
# The Pager must be accessible via SSH (default: root@172.16.42.1).
#
# Usage:
#   ./install_pineapple_pager.sh [pager-ip]
#
# Requirements:
#   - WiFi Pineapple Pager connected and accessible via SSH
#   - ssh and scp commands available
#   - PAGERCTL payload installed on the Pager (provides libpagerctl.so)
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
    read -p "Enter Pager IP address [172.16.*.1]: " _pager_ip
    PAGER_IP="${_pager_ip:-172.16.42.1}"
else
    PAGER_IP="$1"
fi
PAGER_USER="root"
PAGER_PAYLOAD_DIR="/root/payloads/user/reconnaissance/pager_ragnar"
RAGNAR_DIR="$(cd "$(dirname "$0")" && pwd)"

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
echo "  ║     Ragnar - WiFi Pineapple Pager Installer          ║"
echo "  ║                                                       ║"
echo "  ║  Deploy Ragnar as a Pager payload for autonomous      ║"
echo "  ║  network reconnaissance on the go.                    ║"
echo "  ╚═══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ============================================================
# Step 1: Check connectivity to Pager
# ============================================================

log "INFO" "Checking connectivity to Pager at ${PAGER_IP}..."

# Determine the real user's home directory (for SSH keys when running with sudo)
if [ -n "$SUDO_USER" ]; then
    REAL_USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    log "INFO" "Running as sudo, using SSH keys from $REAL_USER_HOME"
else
    REAL_USER_HOME="$HOME"
fi

# Find the user's SSH identity file
SSH_IDENTITY=""
for key in "$REAL_USER_HOME/.ssh/id_ed25519" "$REAL_USER_HOME/.ssh/id_rsa" "$REAL_USER_HOME/.ssh/id_ecdsa"; do
    if [ -f "$key" ]; then
        SSH_IDENTITY="-i $key"
        log "INFO" "Using SSH key: $key"
        break
    fi
done

# SSH options for Pager connection (bypass host key issues common with Pager)
SSH_OPTS_BASE="-o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $SSH_IDENTITY"
SSH_OPTS_BATCH="${SSH_OPTS_BASE} -o BatchMode=yes"
SSH_OPTS="${SSH_OPTS_BATCH}"
USE_INTERACTIVE=false

# First try with key auth (BatchMode)
if ssh $SSH_OPTS_BATCH "${PAGER_USER}@${PAGER_IP}" "echo ok" >/dev/null 2>&1; then
    log "SUCCESS" "Connected to Pager at ${PAGER_IP} (key auth)"
else
    log "WARNING" "Key-based SSH auth failed. Trying interactive mode..."
    echo ""
    # Test if we can reach the host at all
    if ssh $SSH_OPTS_BASE -o PasswordAuthentication=yes -o NumberOfPasswordPrompts=0 "${PAGER_USER}@${PAGER_IP}" "echo ok" >/dev/null 2>&1; then
        log "SUCCESS" "Connected to Pager at ${PAGER_IP}"
    else
        echo -e "${YELLOW}SSH key auth is not working. You can continue with password auth.${NC}"
        echo -e "${YELLOW}You'll be prompted for the root password multiple times during install.${NC}"
        echo ""
        read -p "Continue with password authentication? (y/n): " use_password
        if [[ "$use_password" =~ ^[Yy]$ ]]; then
            USE_INTERACTIVE=true
            SSH_OPTS="${SSH_OPTS_BASE}"
            # Verify we can actually connect with password
            echo "Testing connection (enter root password):"
            if ! ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "echo ok"; then
                log "ERROR" "Cannot connect to Pager at ${PAGER_USER}@${PAGER_IP}"
                echo ""
                echo "  Make sure:"
                echo "    1. Pager is powered on and connected via USB"
                echo "    2. SSH is accessible at ${PAGER_IP}"
                echo "    3. You entered the correct password"
                exit 1
            fi
            log "SUCCESS" "Connected to Pager at ${PAGER_IP} (password auth)"
        else
            log "ERROR" "Cannot connect to Pager at ${PAGER_USER}@${PAGER_IP}"
            echo ""
            echo "  To set up SSH key auth:"
            echo "    ssh-copy-id ${PAGER_USER}@${PAGER_IP}"
            echo ""
            echo "  Debug: Try manually connecting:"
            echo "    ssh -v ${PAGER_USER}@${PAGER_IP}"
            exit 1
        fi
    fi
fi

# ============================================================
# Step 2: Check for libpagerctl.so availability
# ============================================================

log "INFO" "Checking for libpagerctl.so..."

# Check if we have it bundled in Ragnar itself
RAGNAR_PAGERCTL="${RAGNAR_DIR}/libpagerctl.so"
BJORN_PAGERCTL_CHECK="${RAGNAR_DIR}/../pineapple_pager_bjorn/payloads/user/reconnaissance/pager_bjorn/libpagerctl.so"

if [ -f "$RAGNAR_PAGERCTL" ]; then
    log "SUCCESS" "Found libpagerctl.so in Ragnar (will be bundled)"
    PAGERCTL_SOURCE="ragnar"
elif [ -f "$BJORN_PAGERCTL_CHECK" ]; then
    log "SUCCESS" "Found libpagerctl.so in pineapple_pager_bjorn (will be bundled)"
    PAGERCTL_SOURCE="bjorn"
else
    # Check if it exists on the Pager already
    PAGERCTL_FOUND=$(ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "
        if [ -f /root/lib/pagerctl_mock.py ]; then
            echo 'mock'
        elif [ -f /root/payloads/user/utilities/PAGERCTL/libpagerctl.so ]; then
            echo 'utilities'
        elif find /root/payloads -name 'libpagerctl.so' 2>/dev/null | head -1 | grep -q '.'; then
            echo 'found'
        else
            echo 'missing'
        fi
    ")

    if [ "$PAGERCTL_FOUND" = "mock" ]; then
        log "SUCCESS" "Mock pager detected - web display will be used"
        PAGERCTL_SOURCE="mock"
    elif [ "$PAGERCTL_FOUND" = "missing" ]; then
        log "WARNING" "libpagerctl.so not found!"
        echo ""
        echo "  The libpagerctl.so library is needed for Pager display/input."
        echo ""
        echo "  Options:"
        echo "    1. Continue without display support (headless mode, web UI only)"
        echo ""
        read -p "  Continue without display support? (y/n): " choice
        if [[ ! "$choice" =~ ^[Yy]$ ]]; then
            exit 1
        fi
        PAGERCTL_SOURCE="none"
    else
        log "SUCCESS" "Found libpagerctl.so on Pager (will copy to payload)"
        PAGERCTL_SOURCE="pager"
    fi
fi

# ============================================================
# Step 3: Create payload directory structure
# ============================================================

log "INFO" "Preparing payload package..."

STAGING_DIR=$(mktemp -d)
PAYLOAD_STAGE="${STAGING_DIR}/pager_ragnar"
mkdir -p "${PAYLOAD_STAGE}"

# Pager-specific files (live in pager/ subdirectory of the repo, deployed flat)
PAGER_FILES=(
    "PagerRagnar.py"
    "pager_display.py"
    "pager_menu.py"
    "pager_payload.sh"
    "pagerctl.py"
    "pagerctl_mock.py"
)

for f in "${PAGER_FILES[@]}"; do
    src="${RAGNAR_DIR}/pager/${f}"
    # Fallback: root of repo (in case someone hasn't reorganised yet)
    [ -f "$src" ] || src="${RAGNAR_DIR}/${f}"
    if [ -f "$src" ]; then
        cp "$src" "${PAYLOAD_STAGE}/"
    else
        log "WARNING" "Pager file not found: ${f} (skipping)"
    fi
done

# Core shared modules (live at repo root)
CORE_FILES=(
    # Shared modules
    "init_shared.py"
    "shared.py"
    "orchestrator.py"
    "comment.py"
    "logger.py"
    "__init__.py"

    # Database and storage
    "db_manager.py"
    "network_storage.py"

    # Network handling
    "multi_interface.py"
    "wifi_manager.py"
    "wifi_interfaces.py"

    # Loggers
    "nmap_logger.py"
    "attack_logger.py"

    # Intelligence and scanning
    "network_intelligence.py"
    "threat_intelligence.py"
    "traffic_analyzer.py"
    "advanced_vuln_scanner.py"
    "lynis_parser.py"

    # Utilities
    "utils.py"
    "env_manager.py"

    # AI service (optional but good to have)
    "ai_service.py"

    # Web interface
    "webapp_modern.py"
    "server_capabilities.py"

    # Resource monitor
    "resource_monitor.py"
)

for f in "${CORE_FILES[@]}"; do
    if [ -f "${RAGNAR_DIR}/${f}" ]; then
        cp "${RAGNAR_DIR}/${f}" "${PAYLOAD_STAGE}/"
    else
        log "WARNING" "File not found: ${f} (skipping)"
    fi
done

# Rename payload.sh for Pager launcher
# Hak5 firmware expects payload.sh — create both for compatibility
if [ -f "${PAYLOAD_STAGE}/pager_payload.sh" ]; then
    mv "${PAYLOAD_STAGE}/pager_payload.sh" "${PAYLOAD_STAGE}/payload.sh"
    cp "${PAYLOAD_STAGE}/payload.sh" "${PAYLOAD_STAGE}/payload"
    chmod +x "${PAYLOAD_STAGE}/payload.sh" "${PAYLOAD_STAGE}/payload"
fi

# Copy actions directory
if [ -d "${RAGNAR_DIR}/actions" ]; then
    cp -r "${RAGNAR_DIR}/actions" "${PAYLOAD_STAGE}/actions"
    log "SUCCESS" "Copied actions directory"
fi

# Copy config directory
if [ -d "${RAGNAR_DIR}/config" ]; then
    cp -r "${RAGNAR_DIR}/config" "${PAYLOAD_STAGE}/config"
    log "SUCCESS" "Copied config directory"
fi

# Copy only required resources (skip e-paper driver and large PSD source files)
mkdir -p "${PAYLOAD_STAGE}/resources"
[ -d "${RAGNAR_DIR}/resources/fonts" ]   && cp -r "${RAGNAR_DIR}/resources/fonts"   "${PAYLOAD_STAGE}/resources/"
[ -d "${RAGNAR_DIR}/resources/comments" ] && cp -r "${RAGNAR_DIR}/resources/comments" "${PAYLOAD_STAGE}/resources/"
if [ -d "${RAGNAR_DIR}/resources/images" ]; then
    mkdir -p "${PAYLOAD_STAGE}/resources/images"
    [ -d "${RAGNAR_DIR}/resources/images/static" ] && cp -r "${RAGNAR_DIR}/resources/images/static" "${PAYLOAD_STAGE}/resources/images/"
    [ -d "${RAGNAR_DIR}/resources/images/status" ] && cp -r "${RAGNAR_DIR}/resources/images/status" "${PAYLOAD_STAGE}/resources/images/"
    # Skip *.psd source files (~21MB) and waveshare_epd (e-paper driver not used on pager)
fi
log "SUCCESS" "Copied pager resources (fonts, icons, status images)"

# Copy web directory (for web UI)
if [ -d "${RAGNAR_DIR}/web" ]; then
    cp -r "${RAGNAR_DIR}/web" "${PAYLOAD_STAGE}/web"
    log "SUCCESS" "Copied web directory"
fi

# Create data directories
mkdir -p "${PAYLOAD_STAGE}/data/logs"
mkdir -p "${PAYLOAD_STAGE}/data/output/crackedpwd"
mkdir -p "${PAYLOAD_STAGE}/data/output/data_stolen"
mkdir -p "${PAYLOAD_STAGE}/data/output/vulnerabilities"
mkdir -p "${PAYLOAD_STAGE}/data/output/scan_results"
mkdir -p "${PAYLOAD_STAGE}/data/output/zombies"
mkdir -p "${PAYLOAD_STAGE}/data/input/dictionary"

# Copy dictionary files if they exist
if [ -f "${RAGNAR_DIR}/data/input/dictionary/users.txt" ]; then
    cp "${RAGNAR_DIR}/data/input/dictionary/users.txt" "${PAYLOAD_STAGE}/data/input/dictionary/"
fi
if [ -f "${RAGNAR_DIR}/data/input/dictionary/passwords.txt" ]; then
    cp "${RAGNAR_DIR}/data/input/dictionary/passwords.txt" "${PAYLOAD_STAGE}/data/input/dictionary/"
fi

# Create default dictionary files if not present
if [ ! -f "${PAYLOAD_STAGE}/data/input/dictionary/users.txt" ]; then
    cat > "${PAYLOAD_STAGE}/data/input/dictionary/users.txt" << 'DICT'
admin
root
user
administrator
test
guest
DICT
fi

if [ ! -f "${PAYLOAD_STAGE}/data/input/dictionary/passwords.txt" ]; then
    cat > "${PAYLOAD_STAGE}/data/input/dictionary/passwords.txt" << 'DICT'
password
123456
admin
root
password123
123
test
guest
DICT
fi

# ============================================================
# Step 4: Bundle Python dependencies
# ============================================================

log "INFO" "Bundling Python dependencies..."

LIB_DIR="${PAYLOAD_STAGE}/lib"
mkdir -p "${LIB_DIR}"

# Check for bundled libraries - first in Ragnar/pager_lib, then in pineapple_pager_bjorn
RAGNAR_LIB_DIR="${RAGNAR_DIR}/pager_lib"
BJORN_LIB_DIR="${RAGNAR_DIR}/../pineapple_pager_bjorn/payloads/user/reconnaissance/pager_bjorn/lib"

if [ -d "$RAGNAR_LIB_DIR" ]; then
    log "INFO" "Found bundled libraries in Ragnar/pager_lib, copying..."
    cp -r "${RAGNAR_LIB_DIR}/"* "${LIB_DIR}/" 2>/dev/null || true
    log "SUCCESS" "Copied bundled Python libraries"
elif [ -d "$BJORN_LIB_DIR" ]; then
    log "INFO" "Found bundled libraries from pineapple_pager_bjorn, copying..."
    cp -r "${BJORN_LIB_DIR}/"* "${LIB_DIR}/" 2>/dev/null || true
    log "SUCCESS" "Copied bundled Python libraries"
else
    if [ "$PAGERCTL_SOURCE" = "mock" ]; then
        log "INFO" "Mock pager - skipping MIPS libraries (Pi uses native packages)"
    else
        log "WARNING" "MIPS Python libraries not found"
        echo ""
        echo "  The Pager requires bundled Python libraries (paramiko, nmap, pymysql, etc.)"
        echo "  These should be MIPS-compiled versions."
        echo ""
        echo "  Ragnar may have limited functionality without them."
        echo ""
        read -p "  Continue without bundled libraries? (y/n): " choice
        if [[ ! "$choice" =~ ^[Yy]$ ]]; then
            rm -rf "${STAGING_DIR}"
            exit 1
        fi
    fi
fi

# ============================================================
# Step 5: Copy binary dependencies (sfreerdp, etc.)
# ============================================================

RAGNAR_BIN_DIR="${RAGNAR_DIR}/pager_bin"
BJORN_BIN_DIR="${RAGNAR_DIR}/../pineapple_pager_bjorn/payloads/user/reconnaissance/pager_bjorn/bin"

if [ -d "$RAGNAR_BIN_DIR" ]; then
    log "INFO" "Copying binary dependencies from Ragnar/pager_bin..."
    mkdir -p "${PAYLOAD_STAGE}/bin"
    cp -r "${RAGNAR_BIN_DIR}/"* "${PAYLOAD_STAGE}/bin/" 2>/dev/null || true
    log "SUCCESS" "Copied binary dependencies"
elif [ -d "$BJORN_BIN_DIR" ]; then
    log "INFO" "Copying binary dependencies from pineapple_pager_bjorn..."
    mkdir -p "${PAYLOAD_STAGE}/bin"
    cp -r "${BJORN_BIN_DIR}/"* "${PAYLOAD_STAGE}/bin/" 2>/dev/null || true
    log "SUCCESS" "Copied binary dependencies"
fi

# ============================================================
# Step 5b: Copy libpagerctl.so for Pager display support
# ============================================================

RAGNAR_PAGERCTL="${RAGNAR_DIR}/libpagerctl.so"
BJORN_PAGERCTL="${RAGNAR_DIR}/../pineapple_pager_bjorn/payloads/user/reconnaissance/pager_bjorn/libpagerctl.so"

copy_pagerctl() {
    local src="$1"
    # Copy to payload root (where pagerctl.py looks for it)
    cp "${src}" "${PAYLOAD_STAGE}/"
    # Also copy to lib/ for LD_LIBRARY_PATH fallback
    cp "${src}" "${PAYLOAD_STAGE}/lib/" 2>/dev/null || true
}

if [ -f "$RAGNAR_PAGERCTL" ]; then
    log "INFO" "Copying libpagerctl.so from Ragnar..."
    copy_pagerctl "${RAGNAR_PAGERCTL}"
    log "SUCCESS" "Copied libpagerctl.so (Pager display library)"
elif [ -f "$BJORN_PAGERCTL" ]; then
    log "INFO" "Copying libpagerctl.so from pineapple_pager_bjorn..."
    copy_pagerctl "${BJORN_PAGERCTL}"
    log "SUCCESS" "Copied libpagerctl.so (Pager display library)"
elif [ "$PAGERCTL_SOURCE" = "pager" ]; then
    # Copy from an existing payload on the Pager
    log "INFO" "Copying libpagerctl.so from existing Pager payload..."
    PAGER_LIB_PATH=$(ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "find /root/payloads -name 'libpagerctl.so' 2>/dev/null | head -1")
    if [ -n "$PAGER_LIB_PATH" ]; then
        scp $SSH_OPTS "${PAGER_USER}@${PAGER_IP}:${PAGER_LIB_PATH}" "${PAYLOAD_STAGE}/"
        cp "${PAYLOAD_STAGE}/libpagerctl.so" "${PAYLOAD_STAGE}/lib/" 2>/dev/null || true
        log "SUCCESS" "Copied libpagerctl.so from Pager"
    fi
else
    log "WARNING" "No libpagerctl.so available - Ragnar will run in headless mode"
fi

# ============================================================
# Step 5c: Bundle NSE vulnerability scripts (vulners.nse)
# ============================================================

log "INFO" "Bundling nmap NSE scripts..."

NSE_SRC_DIR="${RAGNAR_DIR}/pager_lib/nmap_scripts"
if [ -d "$NSE_SRC_DIR" ] && [ -n "$(ls -A "$NSE_SRC_DIR" 2>/dev/null)" ]; then
    mkdir -p "${PAYLOAD_STAGE}/nmap_scripts"
    cp "${NSE_SRC_DIR}/"*.nse "${PAYLOAD_STAGE}/nmap_scripts/" 2>/dev/null || true
    NSE_COUNT=$(ls -1 "${PAYLOAD_STAGE}/nmap_scripts/"*.nse 2>/dev/null | wc -l)
    log "SUCCESS" "Bundled ${NSE_COUNT} NSE script(s) (vulners.nse etc.)"
else
    log "WARNING" "No NSE scripts found in pager_lib/nmap_scripts/ - vuln scanning may not work"
fi

# ============================================================
# Step 6: Deploy to Pager
# ============================================================

log "INFO" "Deploying Ragnar payload to Pager..."

# Create payload directory on Pager
ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "mkdir -p ${PAGER_PAYLOAD_DIR}"

# Copy payload
scp $SSH_OPTS -r "${PAYLOAD_STAGE}/"* "${PAGER_USER}@${PAGER_IP}:${PAGER_PAYLOAD_DIR}/"

log "SUCCESS" "Payload deployed to ${PAGER_PAYLOAD_DIR}"

# Set permissions
ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "chmod +x ${PAGER_PAYLOAD_DIR}/payload.sh && chmod -R 755 ${PAGER_PAYLOAD_DIR}"

log "SUCCESS" "Permissions set"

# Fix libsodium symlinks (git on Windows stores symlinks as text files)
log "INFO" "Fixing libsodium symlinks..."
ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "
    cd ${PAGER_PAYLOAD_DIR}/lib
    # If libsodium.so is a text file instead of a real symlink, recreate it
    if [ -f libsodium.so.26.1.0 ]; then
        rm -f libsodium.so libsodium.so.26 2>/dev/null
        ln -sf libsodium.so.26.1.0 libsodium.so.26
        ln -sf libsodium.so.26 libsodium.so
        echo 'Recreated libsodium symlinks'
    fi
"
log "SUCCESS" "Library symlinks fixed"

# ============================================================
# Step 7: Setup system-wide libpagerctl.so
# ============================================================

log "INFO" "Setting up system-wide libpagerctl.so..."

ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "
    # Create /root/lib if it doesn't exist
    mkdir -p /root/lib
    
    # Copy libpagerctl.so to system lib dir
    if [ -f ${PAGER_PAYLOAD_DIR}/libpagerctl.so ]; then
        cp ${PAGER_PAYLOAD_DIR}/libpagerctl.so /root/lib/
        chmod 755 /root/lib/libpagerctl.so
        echo 'Copied libpagerctl.so to /root/lib/'
    fi
    
    # Ensure pagerctl.py is in payload root (already copied in Step 3)
    if [ ! -f ${PAGER_PAYLOAD_DIR}/pagerctl.py ]; then
        echo 'WARNING: pagerctl.py missing from payload root'
    fi
"

log "SUCCESS" "libpagerctl.so installed to /root/lib/"

# ============================================================
# Step 7b: Install bundled NSE scripts into nmap scripts dir
# ============================================================

log "INFO" "Installing NSE vulnerability scripts on Pager..."

ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "
    # nmap's script dir on OpenWRT (opkg install nmap puts scripts here)
    NMAP_SCRIPTS_DIR=''
    for d in /usr/share/nmap/scripts /usr/lib/nmap/scripts /opt/nmap/scripts; do
        if [ -d \"\$d\" ]; then
            NMAP_SCRIPTS_DIR=\"\$d\"
            break
        fi
    done

    if [ -z \"\$NMAP_SCRIPTS_DIR\" ]; then
        # nmap not installed yet - create the dir so scripts are ready when nmap installs
        mkdir -p /usr/share/nmap/scripts
        NMAP_SCRIPTS_DIR='/usr/share/nmap/scripts'
        echo 'Created /usr/share/nmap/scripts (nmap not yet installed)'
    fi

    if [ -d ${PAGER_PAYLOAD_DIR}/nmap_scripts ]; then
        cp ${PAGER_PAYLOAD_DIR}/nmap_scripts/*.nse \"\$NMAP_SCRIPTS_DIR/\" 2>/dev/null && \
            echo \"Installed NSE scripts to \$NMAP_SCRIPTS_DIR\" || \
            echo 'WARNING: could not copy NSE scripts'
        # Rebuild the script database if nmap is available
        if command -v nmap >/dev/null 2>&1; then
            nmap --script-updatedb 2>&1 | tail -1
        fi
    else
        echo 'No nmap_scripts directory in payload'
    fi
"

log "SUCCESS" "NSE scripts installed (vulners.nse ready for vuln scanning)"

# ============================================================
# Step 8: Install Python3 and dependencies on Pager
# ============================================================

log "INFO" "Checking Python3 on Pager..."

PYTHON3_INSTALLED=$(ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "python3 --version 2>/dev/null && echo FOUND || echo MISSING")

if echo "$PYTHON3_INSTALLED" | grep -q "MISSING"; then
    log "INFO" "Python3 not found on Pager. Installing offline packages..."

    # OpenWrt package repository for the Pager's architecture
    OPENWRT_BASE="https://downloads.openwrt.org/releases/24.10.1/packages/mipsel_24kc/packages"
    OPENWRT_VER="3.11.14-r1"
    IPK_DIR=$(mktemp -d)

    # Core Python3 packages + modules needed by Ragnar
    PYTHON3_PKGS=(
        "libpython3-3.11_${OPENWRT_VER}_mipsel_24kc.ipk"
        "python3-base_${OPENWRT_VER}_mipsel_24kc.ipk"
        "python3-light_${OPENWRT_VER}_mipsel_24kc.ipk"
        "python3-logging_${OPENWRT_VER}_mipsel_24kc.ipk"
        "python3-asyncio_${OPENWRT_VER}_mipsel_24kc.ipk"
        "python3-codecs_${OPENWRT_VER}_mipsel_24kc.ipk"
        "python3-ctypes_${OPENWRT_VER}_mipsel_24kc.ipk"
        "python3-email_${OPENWRT_VER}_mipsel_24kc.ipk"
        "python3-urllib_${OPENWRT_VER}_mipsel_24kc.ipk"
        "python3-sqlite3_${OPENWRT_VER}_mipsel_24kc.ipk"
        "python3-multiprocessing_${OPENWRT_VER}_mipsel_24kc.ipk"
        "python3-openssl_${OPENWRT_VER}_mipsel_24kc.ipk"
        "python3-uuid_${OPENWRT_VER}_mipsel_24kc.ipk"
        "python3-xml_${OPENWRT_VER}_mipsel_24kc.ipk"
        "python3-decimal_${OPENWRT_VER}_mipsel_24kc.ipk"
    )

    log "INFO" "Downloading ${#PYTHON3_PKGS[@]} Python3 .ipk packages..."
    DL_FAILED=false
    for pkg in "${PYTHON3_PKGS[@]}"; do
        if command -v wget >/dev/null 2>&1; then
            wget -q -O "${IPK_DIR}/${pkg}" "${OPENWRT_BASE}/${pkg}" 2>/dev/null || {
                log "WARNING" "Failed to download ${pkg}"
                DL_FAILED=true
            }
        elif command -v curl >/dev/null 2>&1; then
            curl -sfL -o "${IPK_DIR}/${pkg}" "${OPENWRT_BASE}/${pkg}" 2>/dev/null || {
                log "WARNING" "Failed to download ${pkg}"
                DL_FAILED=true
            }
        else
            log "ERROR" "Neither wget nor curl found. Cannot download packages."
            DL_FAILED=true
            break
        fi
    done

    if [ "$DL_FAILED" = true ]; then
        log "WARNING" "Some Python3 packages failed to download."
        log "WARNING" "Ragnar may have limited functionality if Python3 is not installed."
        echo ""
        read -p "  Continue anyway? (y/n): " choice
        if [[ ! "$choice" =~ ^[Yy]$ ]]; then
            rm -rf "${IPK_DIR}"
            rm -rf "${STAGING_DIR}"
            exit 1
        fi
    fi

    # Transfer packages to Pager
    IPK_COUNT=$(ls -1 "${IPK_DIR}"/*.ipk 2>/dev/null | wc -l)
    if [ "$IPK_COUNT" -gt 0 ]; then
        log "INFO" "Transferring ${IPK_COUNT} packages to Pager..."
        scp $SSH_OPTS "${IPK_DIR}"/*.ipk "${PAGER_USER}@${PAGER_IP}:/tmp/"

        log "INFO" "Installing Python3 packages on Pager..."
        ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "
            rm -f /var/lock/opkg.lock 2>/dev/null
            # Install core first, then modules
            opkg install /tmp/libpython3-3.11_*.ipk /tmp/python3-base_*.ipk /tmp/python3-light_*.ipk 2>&1 || true
            opkg install /tmp/python3-logging_*.ipk /tmp/python3-asyncio_*.ipk /tmp/python3-codecs_*.ipk \
                /tmp/python3-ctypes_*.ipk /tmp/python3-email_*.ipk /tmp/python3-urllib_*.ipk \
                /tmp/python3-sqlite3_*.ipk /tmp/python3-multiprocessing_*.ipk /tmp/python3-openssl_*.ipk \
                /tmp/python3-uuid_*.ipk /tmp/python3-xml_*.ipk /tmp/python3-decimal_*.ipk 2>&1 || true
            # Clean up
            rm -f /tmp/python3-*.ipk /tmp/libpython3-*.ipk 2>/dev/null
        "

        # Verify Python3
        if ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "python3 -c 'print(42)'" 2>/dev/null | grep -q "42"; then
            log "SUCCESS" "Python3 installed and working on Pager"
        else
            log "WARNING" "Python3 installation may have issues"
        fi
    fi

    rm -rf "${IPK_DIR}"
else
    log "SUCCESS" "Python3 already installed on Pager"

    # Ensure required modules are present even if Python3 was already there
    MISSING_MODS=$(ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "
        python3 -c '
import importlib, sys
needed = [\"logging\",\"asyncio\",\"ctypes\",\"sqlite3\",\"xml.etree.ElementTree\",\"email\",\"urllib\",\"multiprocessing\",\"ssl\",\"uuid\",\"decimal\",\"codecs\"]
missing = []
for m in needed:
    try:
        importlib.import_module(m)
    except ImportError:
        missing.append(m)
if missing:
    print(\" \".join(missing))
else:
    print(\"NONE\")
' 2>/dev/null || echo 'CHECK_FAILED'
    ")

    if [ "$MISSING_MODS" != "NONE" ] && [ "$MISSING_MODS" != "CHECK_FAILED" ]; then
        log "WARNING" "Missing Python3 modules: ${MISSING_MODS}"
        log "INFO" "Attempting to install missing modules..."

        OPENWRT_BASE="https://downloads.openwrt.org/releases/24.10.1/packages/mipsel_24kc/packages"
        OPENWRT_VER="3.11.14-r1"
        IPK_DIR=$(mktemp -d)

        # Map module names to package names
        for mod in $MISSING_MODS; do
            case "$mod" in
                xml.etree.ElementTree) pkg_name="python3-xml" ;;
                ssl) pkg_name="python3-openssl" ;;
                *) pkg_name="python3-${mod}" ;;
            esac
            IPK_FILE="${pkg_name}_${OPENWRT_VER}_mipsel_24kc.ipk"
            if command -v wget >/dev/null 2>&1; then
                wget -q -O "${IPK_DIR}/${IPK_FILE}" "${OPENWRT_BASE}/${IPK_FILE}" 2>/dev/null || true
            elif command -v curl >/dev/null 2>&1; then
                curl -sfL -o "${IPK_DIR}/${IPK_FILE}" "${OPENWRT_BASE}/${IPK_FILE}" 2>/dev/null || true
            fi
        done

        IPK_COUNT=$(ls -1 "${IPK_DIR}"/*.ipk 2>/dev/null | wc -l)
        if [ "$IPK_COUNT" -gt 0 ]; then
            scp $SSH_OPTS "${IPK_DIR}"/*.ipk "${PAGER_USER}@${PAGER_IP}:/tmp/"
            ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "
                rm -f /var/lock/opkg.lock 2>/dev/null
                opkg install /tmp/python3-*.ipk 2>&1 || true
                rm -f /tmp/python3-*.ipk 2>/dev/null
            "
            log "SUCCESS" "Installed additional Python3 modules"
        fi

        rm -rf "${IPK_DIR}"
    else
        log "SUCCESS" "All required Python3 modules present"
    fi
fi

# ============================================================
# Step 8b: Install python-nmap (pure Python wrapper for nmap)
# ============================================================

log "INFO" "Checking python-nmap on Pager..."

NMAP_PY_OK=$(ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "python3 -c 'import nmap; print(\"OK\")' 2>/dev/null || echo 'MISSING'")

if [ "$NMAP_PY_OK" != "OK" ]; then
    log "INFO" "Installing python-nmap module..."

    NMAP_PY_DIR=$(mktemp -d)
    NMAP_PY_URL="https://pypi.io/packages/source/p/python-nmap/python-nmap-0.7.1.tar.gz"

    DL_OK=false
    if command -v wget >/dev/null 2>&1; then
        wget -q -O "${NMAP_PY_DIR}/python-nmap.tar.gz" "$NMAP_PY_URL" 2>/dev/null && DL_OK=true
    elif command -v curl >/dev/null 2>&1; then
        curl -sfL -o "${NMAP_PY_DIR}/python-nmap.tar.gz" "$NMAP_PY_URL" 2>/dev/null && DL_OK=true
    fi

    if [ "$DL_OK" = true ]; then
        tar xzf "${NMAP_PY_DIR}/python-nmap.tar.gz" -C "${NMAP_PY_DIR}"
        NMAP_SRC=$(find "${NMAP_PY_DIR}" -maxdepth 2 -type d -name "nmap" | head -1)
        if [ -d "$NMAP_SRC" ]; then
            scp $SSH_OPTS -r "${NMAP_SRC}" "${PAGER_USER}@${PAGER_IP}:/usr/lib/python3.11/nmap"
            log "SUCCESS" "python-nmap installed on Pager"
        else
            log "WARNING" "Could not find nmap module in downloaded package"
        fi
    else
        log "WARNING" "Could not download python-nmap. Nmap scanning may not work."
    fi

    rm -rf "${NMAP_PY_DIR}"
else
    log "SUCCESS" "python-nmap already installed on Pager"
fi

log "INFO" "Verifying installation..."

VERIFY_RESULT=$(ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "
    errors=0
    
    # Check core files (libpagerctl.so not required on mock pager)
    for f in pager_menu.py pagerctl.py payload.sh; do
        if [ ! -f ${PAGER_PAYLOAD_DIR}/\$f ]; then
            echo \"MISSING: \$f\"
            errors=\$((errors + 1))
        fi
    done

    # Check display library: either libpagerctl.so (real) or pagerctl_mock.py (mock)
    if [ ! -f ${PAGER_PAYLOAD_DIR}/libpagerctl.so ] && [ ! -f ${PAGER_PAYLOAD_DIR}/pagerctl_mock.py ]; then
        echo 'MISSING: libpagerctl.so or pagerctl_mock.py'
        errors=\$((errors + 1))
    fi
    
    # Check lib directory
    if [ ! -d ${PAGER_PAYLOAD_DIR}/lib ]; then
        echo 'MISSING: lib directory'
        errors=\$((errors + 1))
    fi
    
    # Check actions directory
    if [ ! -d ${PAGER_PAYLOAD_DIR}/actions ]; then
        echo 'MISSING: actions directory'
        errors=\$((errors + 1))
    fi
    
    # Check resources/fonts
    if [ ! -d ${PAGER_PAYLOAD_DIR}/resources/fonts ]; then
        echo 'MISSING: resources/fonts directory'
        errors=\$((errors + 1))
    fi
    
    # Check system libpagerctl
    if [ ! -f /root/lib/libpagerctl.so ]; then
        echo 'MISSING: /root/lib/libpagerctl.so'
        errors=\$((errors + 1))
    fi
    
    # Test Python import
    cd ${PAGER_PAYLOAD_DIR}
    export PYTHONPATH=\"${PAGER_PAYLOAD_DIR}/lib:${PAGER_PAYLOAD_DIR}:\$PYTHONPATH\"
    export LD_LIBRARY_PATH=\"/root/lib:${PAGER_PAYLOAD_DIR}/lib:${PAGER_PAYLOAD_DIR}:\$LD_LIBRARY_PATH\"
    
    python3 -c 'from pagerctl import Pager; print(\"PAGERCTL_OK\")' 2>/dev/null || echo 'PAGERCTL_IMPORT_FAILED'
    python3 -c 'import nmap; nmap.PortScanner(); print(\"NMAP_PY_OK\")' 2>/dev/null || echo 'NMAP_PY_FAILED'
    python3 -c 'import logging, asyncio, ctypes, sqlite3, xml.etree.ElementTree; print(\"STDLIB_OK\")' 2>/dev/null || echo 'STDLIB_FAILED'

    if [ \$errors -eq 0 ]; then
        echo 'ALL_OK'
    else
        echo \"ERRORS: \$errors\"
    fi
")

if echo "$VERIFY_RESULT" | grep -q "ALL_OK"; then
    log "SUCCESS" "Installation verified successfully"
else
    log "WARNING" "Verification issues detected:"
    echo "$VERIFY_RESULT" | grep -v "ALL_OK" | while read line; do
        [ -n "$line" ] && echo "  - $line"
    done
fi

if echo "$VERIFY_RESULT" | grep -q "PAGERCTL_OK"; then
    log "SUCCESS" "pagerctl library imports correctly"
else
    log "WARNING" "pagerctl import test failed - display may not work"
fi

if echo "$VERIFY_RESULT" | grep -q "NMAP_PY_OK"; then
    log "SUCCESS" "python-nmap module works correctly"
else
    log "WARNING" "python-nmap import failed - network scanning may not work"
fi

if echo "$VERIFY_RESULT" | grep -q "STDLIB_OK"; then
    log "SUCCESS" "Python3 standard library modules OK"
else
    log "WARNING" "Some Python3 standard library modules missing"
fi

# ============================================================
# Step 9b: Generate actions.json if missing
# ============================================================

log "INFO" "Ensuring actions.json is up to date..."

ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "
    cd ${PAGER_PAYLOAD_DIR}
    export PYTHONPATH=\"${PAGER_PAYLOAD_DIR}/lib:${PAGER_PAYLOAD_DIR}:\$PYTHONPATH\"
    export LD_LIBRARY_PATH=\"/root/lib:${PAGER_PAYLOAD_DIR}/lib:${PAGER_PAYLOAD_DIR}:\$LD_LIBRARY_PATH\"

    python3 -c '
import sys, os, json, importlib
sys.path.insert(0, \".\")
actions_dir = \"actions\"
actions_config = []
for filename in os.listdir(actions_dir):
    if filename.endswith(\".py\") and filename != \"__init__.py\":
        module_name = filename[:-3]
        try:
            module = importlib.import_module(f\"actions.{module_name}\")
            if getattr(module, \"BYPASS_ACTION_MODULE\", False):
                continue
            b_class = getattr(module, \"b_class\", None)
            b_status = getattr(module, \"b_status\", None)
            if not b_class or not b_status:
                continue
            b_port = getattr(module, \"b_port\", None)
            b_parent = getattr(module, \"b_parent\", None)
            actions_config.append({\"b_module\": module_name, \"b_class\": b_class, \"b_port\": b_port, \"b_status\": b_status, \"b_parent\": b_parent})
        except Exception:
            pass
os.makedirs(\"config\", exist_ok=True)
with open(\"config/actions.json\", \"w\") as f:
    json.dump(actions_config, f, indent=4)
print(f\"Generated actions.json with {len(actions_config)} actions\")
' 2>&1 || echo 'actions.json generation failed (will be created on first run)'
"

log "SUCCESS" "actions.json configured"

# ============================================================
# Step 10: Create convenience symlink at /root/Ragnar
# ============================================================

log "INFO" "Creating /root/Ragnar symlink for compatibility..."

ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "
    # Remove old symlink if exists
    [ -L /root/Ragnar ] && rm -f /root/Ragnar
    
    # Create symlink if /root/Ragnar doesn't exist as directory
    if [ ! -d /root/Ragnar ]; then
        ln -sf ${PAGER_PAYLOAD_DIR} /root/Ragnar
        echo 'Symlink created: /root/Ragnar -> ${PAGER_PAYLOAD_DIR}'
    else
        echo '/root/Ragnar already exists as directory'
    fi
"

log "SUCCESS" "Ragnar accessible at /root/Ragnar"

# ============================================================
# Cleanup and finish
# ============================================================

rm -rf "${STAGING_DIR}"

echo ""
echo -e "${GREEN}  ╔═══════════════════════════════════════════════════════╗"
echo -e "  ║     Ragnar successfully deployed to Pineapple Pager!  ║"
echo -e "  ╚═══════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  To launch Ragnar on the Pager:"
echo "    1. Open the Pager's payload menu"
echo "    2. Navigate to: Reconnaissance > PagerRagnar"
echo "    3. Press GREEN to start"
echo ""
echo "  Web interface (when enabled): http://${PAGER_IP}:8000"
echo ""
echo "  To update later:"
echo "    ./install_pineapple_pager.sh ${PAGER_IP}"
echo ""
