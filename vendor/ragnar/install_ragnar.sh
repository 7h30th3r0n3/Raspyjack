#!/bin/bash

# ragnar Installation Script
# This script handles the complete installation of ragnar
# Author: infinition
# Version: 1.0 - 071124 - 0954

if [ -z "$BASH_VERSION" ]; then
    exec /bin/bash "$0" "$@"
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Logging configuration
LOG_DIR="/var/log/ragnar_install"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/ragnar_install_$(date +%Y%m%d_%H%M%S).log"
VERBOSE=false

# Global variables
ragnar_USER="ragnar"
ragnar_PATH="/home/${ragnar_USER}/Ragnar"
CURRENT_STEP=0
TOTAL_STEPS=11
HEADLESS_MODE=false
HEADLESS_VARIANT=""
HEADLESS_VARIANT_LABEL=""
RAGNAR_ENTRYPOINT="Ragnar.py"
SERVER_INSTALL=false
TFT_MODE=false

# Platform detection variables
OS_ID=""
OS_VERSION_ID=""
OS_PRETTY=""
PKG_MGR=""
UPDATE_CMD=""
INSTALL_CMD=""
PKG_PRESENT_CMD=""
ARCH=""
IS_ARM=false

if [[ "$1" == "--help" ]]; then
    echo "Usage: sudo ./install_ragnar.sh"
    echo "Make sure you have the necessary permissions and that all dependencies are met."
    exit 0
fi

# Function to display progress
show_progress() {
    echo -e "${BLUE}Step $CURRENT_STEP of $TOTAL_STEPS: $1${NC}"
}

# Logging function
log() {
    local level=$1
    shift
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*"
    echo -e "$message" >> "$LOG_FILE"
    if [ "$VERBOSE" = true ] || [ "$level" != "DEBUG" ]; then
        case $level in
            "ERROR") echo -e "${RED}$message${NC}" ;;
            "SUCCESS") echo -e "${GREEN}$message${NC}" ;;
            "WARNING") echo -e "${YELLOW}$message${NC}" ;;
            "INFO") echo -e "${BLUE}$message${NC}" ;;
            *) echo -e "$message" ;;
        esac
    fi
}

# Error handling function
handle_error() {
    local error_code=$?
    local error_message=$1
    log "ERROR" "An error occurred during: $error_message (Error code: $error_code)"
    log "ERROR" "Check the log file for details: $LOG_FILE"

    echo -e "\n${RED}Would you like to:"
    echo "1. Retry this step"
    echo "2. Skip this step (not recommended)"
    echo "3. Exit installation${NC}"
    read -r choice

    case $choice in
        1) return 1 ;; # Retry
        2) return 0 ;; # Skip
        3) clean_exit 1 ;; # Exit
        *) handle_error "$error_message" ;; # Invalid choice
    esac
}

# Function to check command success
check_success() {
    if [ $? -eq 0 ]; then
        log "SUCCESS" "$1"
        return 0
    else
        handle_error "$1"
        return $?
    fi
}

# Detect OS, package manager, and hardware architecture
detect_platform() {
    if [ -f "/etc/os-release" ]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        OS_ID=${ID:-unknown}
        OS_VERSION_ID=${VERSION_ID:-unknown}
        OS_PRETTY=${PRETTY_NAME:-$OS_ID}
    else
        OS_ID="unknown"
        OS_VERSION_ID="unknown"
        OS_PRETTY="unknown"
    fi

    ARCH=$(uname -m 2>/dev/null || echo "unknown")
    case "$ARCH" in
        arm*|aarch64) IS_ARM=true ;;
        *) IS_ARM=false ;;
    esac

    case "$OS_ID" in
        debian|ubuntu|raspbian)
            PKG_MGR="apt"
            UPDATE_CMD="apt-get update -y"
            INSTALL_CMD="apt-get install -y"
            PKG_PRESENT_CMD="dpkg -s"
            ;;
        fedora|rhel|centos|rocky|almalinux)
            PKG_MGR="dnf"
            UPDATE_CMD="dnf makecache -y"
            INSTALL_CMD="dnf install -y"
            PKG_PRESENT_CMD="rpm -q"
            ;;
        arch|manjaro|endeavouros)
            PKG_MGR="pacman"
            UPDATE_CMD="pacman -Sy --noconfirm"
            INSTALL_CMD="pacman -S --noconfirm"
            PKG_PRESENT_CMD="pacman -Qi"
            ;;
        opensuse*|sles)
            PKG_MGR="zypper"
            UPDATE_CMD="zypper refresh"
            INSTALL_CMD="zypper install -y"
            PKG_PRESENT_CMD="rpm -q"
            ;;
        *)
            PKG_MGR="apt"
            UPDATE_CMD="apt-get update -y"
            INSTALL_CMD="apt-get install -y"
            PKG_PRESENT_CMD="dpkg -s"
            log "WARNING" "Unknown distro; defaulting to apt commands"
            ;;
    esac

    log "INFO" "Detected platform: ${OS_PRETTY} (id=${OS_ID}, version=${OS_VERSION_ID}), arch=${ARCH}, pkg_mgr=${PKG_MGR}"
}

# Print a concise system summary for visibility
log_system_summary() {
    local cpu_model ram_mb disk_mb

    cpu_model=$(grep -m1 "model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//')
    ram_mb=$(free -m 2>/dev/null | awk '/^Mem:/{print $2}')
    disk_mb=$(df -m /home 2>/dev/null | awk 'NR==2 {print $4}')

    log "INFO" "System summary:" \
        " OS=${OS_PRETTY:-unknown}" \
        " Arch=${ARCH:-unknown}" \
        " CPU=${cpu_model:-unknown}" \
        " RAM=${ram_mb:-?}MB" \
        " FreeDisk=${disk_mb:-?}MB (/home)"
}

# Provide package-name fallbacks across distros
package_candidates() {
    local pkg=$1
    case "$pkg" in
        libopenjp2-7) echo "libopenjp2-7 openjpeg2 openjpeg" ;;
        libopenblas-dev) echo "libopenblas-dev openblas-devel openblas" ;;
        bluez-tools) echo "bluez-tools bluez-utils bluez-utils-compat" ;;
        dhcpcd5) echo "dhcpcd5 dhcpcd" ;;
        python3-pil) echo "python3-pil python3-pillow python-pillow pillow" ;;
        libjpeg-dev) echo "libjpeg-dev libjpeg-turbo-devel libjpeg-turbo" ;;
        libpng-dev) echo "libpng-dev libpng-devel" ;;
        python3-dev) echo "python3-dev python3-devel" ;;
        libffi-dev) echo "libffi-dev libffi-devel" ;;
        libssl-dev) echo "libssl-dev openssl-devel" ;;
        libgpiod-dev) echo "libgpiod-dev libgpiod-devel libgpiod" ;;
        libi2c-dev) echo "libi2c-dev i2c-tools i2c-tools-devel" ;;
        build-essential) echo "build-essential base-devel" ;;
        python3-sqlalchemy) echo "python3-sqlalchemy python-sqlalchemy sqlalchemy" ;;
        python3-pandas) echo "python3-pandas python-pandas pandas" ;;
        python3-numpy) echo "python3-numpy python-numpy numpy" ;;
        network-manager) echo "network-manager NetworkManager networkmanager" ;;
        iproute2) echo "iproute2 iproute" ;;
        iputils-ping) echo "iputils-ping iputils" ;;
        libatlas-base-dev) echo "libatlas-base-dev atlas-devel" ;;
        arp-scan) echo "arp-scan arpscan" ;;
        bluez) echo "bluez" ;;
        hostapd) echo "hostapd" ;;
        dnsmasq) echo "dnsmasq" ;;
        wireless-tools) echo "wireless-tools" ;;
        bridge-utils) echo "bridge-utils" ;;
        *) echo "$pkg" ;;
    esac
}

# Install a package using detected package manager with fallbacks
install_package() {
    local pkg=$1
    local candidates
    candidates=$(package_candidates "$pkg")

    for candidate in $candidates; do
        if [ -n "$PKG_PRESENT_CMD" ] && eval "$PKG_PRESENT_CMD $candidate" >/dev/null 2>&1; then
            log "INFO" "${candidate} already present"
            return 0
        fi
    done

    for candidate in $candidates; do
        if eval "$INSTALL_CMD $candidate" >/dev/null 2>&1; then
            log "SUCCESS" "Installed ${candidate}"
            return 0
        fi
        log "WARNING" "Failed to install ${candidate}, trying next fallback"
    done

    log "WARNING" "Could not install package ${pkg} on ${PKG_MGR}"
    return 1
}

# # Check system compatibility
# check_system_compatibility() {
#     log "INFO" "Checking system compatibility..."
    
#     # Check if running on Raspberry Pi
#     if ! grep -q "Raspberry Pi" /proc/cpuinfo; then
#         log "WARNING" "This system might not be a Raspberry Pi. Continue anyway? (y/n)"
#         read -r response
#         if [[ ! "$response" =~ ^[Yy]$ ]]; then
#             clean_exit 1
#         fi
#     fi
    
#     check_success "System compatibility check completed"
# }
# Check system compatibility
check_system_compatibility() {
    log "INFO" "Checking system compatibility..."
    local should_ask_confirmation=false
    
    # Skip hardware gating - Ragnar now supports all tested platforms

    # Check RAM (Raspberry Pi Zero has 512MB RAM)
    total_ram=$(free -m | awk '/^Mem:/{print $2}')
    if [ -n "$total_ram" ] && [ "$total_ram" -lt 410 ]; then
        log "WARNING" "Low RAM detected. Required: 512MB (410 With OS Running), Found: ${total_ram}MB"
        echo -e "${YELLOW}Your system has less RAM than recommended. This might affect performance, but you can continue.${NC}"
        should_ask_confirmation=true
    elif [ -n "$total_ram" ]; then
        log "SUCCESS" "RAM check passed: ${total_ram}MB available"
    fi

    # Check available disk space
    available_space=$(df -m /home | awk 'NR==2 {print $4}')
    if [ -n "$available_space" ] && [ "$available_space" -lt 2048 ]; then
        log "WARNING" "Low disk space. Recommended: 1GB, Found: ${available_space}MB"
        echo -e "${YELLOW}Your system has less free space than recommended. This might affect installation.${NC}"
        should_ask_confirmation=true
    else
        log "SUCCESS" "Disk space check passed: ${available_space}MB available"
    fi

    # OS/version is now accepted broadly; log for visibility only
    if [ -f "/etc/os-release" ]; then
        source /etc/os-release
        log "INFO" "OS detected: ${PRETTY_NAME} (${VERSION_ID})"
    else
        log "INFO" "OS detected: unknown (no /etc/os-release)"
    fi

    # Architecture compatibility: supported across tested platforms, log for visibility only
    if command -v dpkg >/dev/null 2>&1; then
        architecture=$(dpkg --print-architecture)
    else
        architecture=${ARCH:-$(uname -m 2>/dev/null)}
    fi
    log "INFO" "Architecture detected: ${architecture} (proceeding without compatibility warnings)"

    if [ "$should_ask_confirmation" = true ]; then
        echo -e "\n${YELLOW}Some system compatibility warnings were detected (see above).${NC}"
        echo -e "${YELLOW}The installation might not work as expected.${NC}"
        echo -e "${YELLOW}Do you want to continue anyway? (y/n)${NC}"
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            log "INFO" "Installation aborted by user after compatibility warnings"
            clean_exit 1
        fi
    else
        log "SUCCESS" "All compatibility checks passed"
    fi

    log "INFO" "System compatibility check completed"
    return 0
}

check_internet() {
    log "INFO" "Checking internet connectivity..."
    
    # Try to ping common servers
    if ping -c 2 8.8.8.8 > /dev/null 2>&1 || ping -c 2 1.1.1.1 > /dev/null 2>&1; then
        log "SUCCESS" "Internet connectivity confirmed"
        
        # Test DNS resolution
        if ping -c 1 pypi.org > /dev/null 2>&1; then
            log "SUCCESS" "DNS resolution working"
        else
            log "WARNING" "DNS resolution issues detected. Package installation may be slow."
            log "INFO" "Consider checking /etc/resolv.conf or your network settings"
        fi
        return 0
    else
        log "WARNING" "No internet connectivity detected!"
        echo -e "${YELLOW}Internet connection is required to download Python packages.${NC}"
        echo -e "${YELLOW}Please check your network connection and try again.${NC}"
        echo -e "\nDo you want to:"
        echo "1. Continue anyway (installation may fail)"
        echo "2. Exit and fix network issues first (recommended)"
        read -r choice
        case $choice in
            1) 
                log "WARNING" "Continuing without verified internet connection"
                return 0
                ;;
            *)
                log "INFO" "Installation aborted - please fix network issues first"
                clean_exit 1
                ;;
        esac
    fi
}


# Install system dependencies
install_dependencies() {
    log "INFO" "Installing system dependencies..."

    [ -z "$PKG_MGR" ] && detect_platform

    eval "$UPDATE_CMD"
    check_success "Package index updated via ${PKG_MGR}"

    packages=(
        "python3-pip"
        "wget"
        "lsof"
        "git"
        "sudo"
        "libopenjp2-7"
        "nmap"
        "libopenblas-dev"
        "bluez"
        "bluez-tools"
        "bridge-utils"
        "python3-pil"
        "libjpeg-dev"
        "zlib1g-dev"
        "libpng-dev"
        "python3-dev"
        "libffi-dev"
        "libssl-dev"
        "build-essential"
        "python3-sqlalchemy"
        "python3-pandas"
        "python3-numpy"
        "python3-flask"
        "python3-flask-socketio"
        "python3-flask-cors"
        "hostapd"
        "dnsmasq"
        "network-manager"
        "wireless-tools"
        "iproute2"
        "iputils-ping"
        "rfkill"
        "sqlite3"
        "arp-scan"
        "tcpdump"
        "nikto"
        "sqlmap"
        "whatweb"
    )

    if [ "$IS_ARM" = true ]; then
        packages+=("libgpiod-dev" "libi2c-dev" "dhcpcd5")
    fi

    optional_packages=("libatlas-base-dev")

    for package in "${packages[@]}"; do
        install_package "$package"
    done

    for package in "${optional_packages[@]}"; do
        install_package "$package" || log "WARNING" "Optional package $package unavailable on ${PKG_MGR}"
    done

    # Ensure vulners.nse script is available for vulnerability scanning
    local vulners_path="/usr/share/nmap/scripts/vulners.nse"
    if [ ! -f "$vulners_path" ]; then
        log "INFO" "Downloading vulners.nse script for nmap..."
        mkdir -p "$(dirname "$vulners_path")"
        if wget -q -O "$vulners_path" "https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse"; then
            chmod 644 "$vulners_path"
            log "SUCCESS" "Installed vulners.nse vulnerability script"
        else
            log "WARNING" "Failed to download vulners.nse script automatically. Vulnerability scans may be limited."
        fi
    else
        log "INFO" "vulners.nse script already present"
    fi

    # Update nmap scripts
    nmap --script-updatedb

    # Configure WiFi interfaces
    log "INFO" "Configuring WiFi interfaces..."

    # Ensure WiFi is not blocked by rfkill
    if command -v rfkill >/dev/null 2>&1; then
        rfkill unblock wifi
        log "SUCCESS" "WiFi unblocked via rfkill"
    else
        log "WARNING" "rfkill not available - WiFi blocking status unknown"
    fi

    # Create basic wpa_supplicant configuration if it doesn't exist
    if [ ! -f "/etc/wpa_supplicant/wpa_supplicant.conf" ]; then
        log "INFO" "Creating basic wpa_supplicant configuration..."
        mkdir -p /etc/wpa_supplicant
        cat > /etc/wpa_supplicant/wpa_supplicant.conf << EOF
country=US
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1

# This file will be managed by NetworkManager and Ragnar WiFi Manager
# Networks will be added dynamically
EOF
        chmod 600 /etc/wpa_supplicant/wpa_supplicant.conf
        log "SUCCESS" "Created basic wpa_supplicant configuration"
    fi

    check_success "Dependencies installation completed"
}

# Configure system limits
configure_system_limits() {
    log "INFO" "Configuring system limits..."

    # Configure /etc/security/limits.conf for file descriptors AND process limits
    cat >> /etc/security/limits.conf << EOF

# Ragnar system limits - File descriptors
* soft nofile 65535
* hard nofile 65535
root soft nofile 65535
root hard nofile 65535

# Ragnar system limits - Process limits (critical for threading and OpenBLAS)
* soft nproc 4096
* hard nproc 8192
root soft nproc 4096
root hard nproc 8192
$ragnar_USER soft nproc 4096
$ragnar_USER hard nproc 8192
EOF

    # Configure systemd limits
    sed -i '/^#DefaultLimitNOFILE=/d' /etc/systemd/system.conf
    echo "DefaultLimitNOFILE=65535" >> /etc/systemd/system.conf
    sed -i '/^#DefaultLimitNOFILE=/d' /etc/systemd/user.conf
    echo "DefaultLimitNOFILE=65535" >> /etc/systemd/user.conf
    
    # Add process limit to systemd
    sed -i '/^#DefaultLimitNPROC=/d' /etc/systemd/system.conf
    echo "DefaultLimitNPROC=4096" >> /etc/systemd/system.conf
    sed -i '/^#DefaultLimitNPROC=/d' /etc/systemd/user.conf
    echo "DefaultLimitNPROC=4096" >> /etc/systemd/user.conf

    # Create /etc/security/limits.d/90-ragnar-limits.conf with both file and process limits
    cat > /etc/security/limits.d/90-ragnar-limits.conf << EOF
# Ragnar System Limits Configuration
# File descriptor limits
root soft nofile 65535
root hard nofile 65535
$ragnar_USER soft nofile 65535
$ragnar_USER hard nofile 65535

# Process/thread limits (prevents OpenBLAS pthread_create errors)
root soft nproc 4096
root hard nproc 8192
$ragnar_USER soft nproc 4096
$ragnar_USER hard nproc 8192
EOF

    # Configure sysctl for file handles and process limits
    cat >> /etc/sysctl.conf << EOF

# Ragnar system tuning
fs.file-max = 2097152
kernel.pid_max = 32768
kernel.threads-max = 65536
EOF
    sysctl -p

    # Ensure PAM limits are applied
    if ! grep -q "session required pam_limits.so" /etc/pam.d/common-session; then
        echo "session required pam_limits.so" >> /etc/pam.d/common-session
    fi
    if ! grep -q "session required pam_limits.so" /etc/pam.d/common-session-noninteractive; then
        echo "session required pam_limits.so" >> /etc/pam.d/common-session-noninteractive
    fi

    log "SUCCESS" "System limits configured: nofile=65535, nproc=4096/8192"
    check_success "System limits configuration completed"
}

# Configure SPI and I2C
# Install PiSugar power manager server (required for PiSugar UPS battery/button support)
install_pisugar_server() {
    # Only relevant on ARM / Raspberry Pi hardware
    if [ "$IS_ARM" != true ]; then
        log "INFO" "Skipping PiSugar server install (not ARM hardware)"
        return 0
    fi

    # Check if pisugar-server is already installed
    if command -v pisugar-server >/dev/null 2>&1 || systemctl list-unit-files pisugar-server.service >/dev/null 2>&1; then
        log "INFO" "PiSugar server is already installed"
        echo -e "${GREEN}✓ PiSugar server already installed${NC}"
        return 0
    fi

    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  PiSugar UPS Support${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}PiSugar provides battery power, battery monitoring, and a${NC}"
    echo -e "${BLUE}hardware button for Ragnar. If you have a PiSugar UPS${NC}"
    echo -e "${BLUE}attached, the pisugar-server daemon is required.${NC}"
    echo ""
    read -p "Do you have a PiSugar UPS? Install pisugar-server? (y/n): " install_pisugar

    if [ "$install_pisugar" != "y" ] && [ "$install_pisugar" != "Y" ]; then
        log "INFO" "User opted out of PiSugar server installation"
        echo -e "${YELLOW}Skipping PiSugar server installation${NC}"
        return 0
    fi

    log "INFO" "Installing PiSugar power manager server..."
    echo -e "${BLUE}Downloading and installing PiSugar power manager...${NC}"

    if curl -sSL http://cdn.pisugar.com/release/pisugar-power-manager.sh | sudo bash; then
        log "SUCCESS" "PiSugar server installed successfully"
        echo -e "${GREEN}✓ PiSugar server installed${NC}"

        # Enable and start the service
        if systemctl enable pisugar-server 2>/dev/null; then
            log "SUCCESS" "PiSugar server service enabled"
        fi
        if systemctl start pisugar-server 2>/dev/null; then
            log "SUCCESS" "PiSugar server service started"
        fi
    else
        log "WARNING" "PiSugar server installation failed"
        echo -e "${YELLOW}⚠ PiSugar server installation failed${NC}"
        echo -e "${YELLOW}  You can install it manually later:${NC}"
        echo -e "${YELLOW}  curl http://cdn.pisugar.com/release/pisugar-power-manager.sh | sudo bash${NC}"
    fi
}

configure_interfaces() {
    log "INFO" "Configuring SPI and I2C interfaces..."

    if command -v raspi-config >/dev/null 2>&1; then
        raspi-config nonint do_spi 0
        raspi-config nonint do_i2c 0
        check_success "Interface configuration completed"
    else
        log "WARNING" "raspi-config not available; skipping SPI/I2C configuration (non-Raspberry Pi hardware)"
    fi
}

# Setup ragnar
setup_ragnar() {
    log "INFO" "Setting up ragnar..."

    # Use PiWheels for faster installs on Raspberry Pi architectures
    local machine_arch
    machine_arch=$(uname -m 2>/dev/null || echo "")
    if [[ "$machine_arch" == "armv7l" || "$machine_arch" == "armv6l" || "$machine_arch" == "aarch64" || "$machine_arch" == "arm64" ]]; then
        if [ -z "${PIP_EXTRA_INDEX_URL:-}" ]; then
            export PIP_EXTRA_INDEX_URL="https://www.piwheels.org/simple"
        else
            export PIP_EXTRA_INDEX_URL="$PIP_EXTRA_INDEX_URL https://www.piwheels.org/simple"
        fi
        log "INFO" "Using PiWheels Python package index for ${machine_arch}"
    fi

    # Create ragnar user if it doesn't exist
    if ! id -u $ragnar_USER >/dev/null 2>&1; then
        adduser --disabled-password --gecos "" $ragnar_USER
        check_success "Created ragnar user"
    fi

    # Check for existing ragnar directory with a valid git clone
    cd /home/$ragnar_USER
    if [ -d "Ragnar/.git" ]; then
        log "INFO" "Using existing ragnar directory"
        echo -e "${GREEN}Using existing ragnar directory${NC}"
    else
        # Remove empty/invalid directory if it exists
        if [ -d "Ragnar" ]; then
            log "WARNING" "Ragnar directory exists but is not a valid git clone, removing..."
            rm -rf Ragnar
        fi
        # Proceed with clone
        log "INFO" "Cloning ragnar repository"
        git clone https://github.com/PierreGode/Ragnar.git
        check_success "Cloned ragnar repository"
    fi

    cd Ragnar

    # Update the default display type in shared.py with the detected/selected version
    log "INFO" "Updating display default configuration in shared.py..."
    if [ -z "${EPD_VERSION:-}" ]; then
        if [ "$HEADLESS_MODE" = true ]; then
            log "INFO" "Headless mode selected - skipping shared.py default display configuration"
        else
            log "WARNING" "Display version not detected - skipping shared.py update"
        fi
    elif [ -f "$ragnar_PATH/shared.py" ]; then
        # Replace whatever epd_type default is currently in shared.py with the user's selection.
        # Using a wildcard pattern instead of hardcoding "epd2in13_V4" so this works correctly
        # on reinstalls where a previous run already changed the default to a different version.
        sed -i "s/\"epd_type\": \"[^\"]*\"/\"epd_type\": \"$EPD_VERSION\"/" "$ragnar_PATH/shared.py"
        check_success "Updated shared.py default EPD configuration to $EPD_VERSION"
        log "INFO" "Modified: $ragnar_PATH/shared.py"

        # Always write the selected epd_type into shared_config.json so the running service
        # uses the right driver immediately — even on a fresh install where the file doesn't
        # exist yet (previous code skipped this, leaving Ragnar to regenerate config from
        # shared.py defaults, which could be stale if sed failed for any reason).
        local config_json="$ragnar_PATH/config/shared_config.json"
        mkdir -p "$(dirname "$config_json")"
        python3 -c "
import json, os
config_path = '$config_json'
cfg = {}
if os.path.exists(config_path):
    try:
        with open(config_path, 'r') as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}
cfg['epd_type'] = '$EPD_VERSION'
with open(config_path, 'w') as f:
    json.dump(cfg, f, indent=4)
print('SUCCESS: Set shared_config.json epd_type to $EPD_VERSION')
" && log "INFO" "Config JSON epd_type set to $EPD_VERSION" \
  || log "WARNING" "Could not write shared_config.json — epd_type will be read from shared.py on first run"
    else
        log "WARNING" "shared.py not found at $ragnar_PATH/shared.py - skipping E-Paper configuration update"
    fi

    # Install requirements with --break-system-packages flag
    log "INFO" "Installing Python requirements..."
    
    # Install packages that can fail separately to handle errors
    log "INFO" "Installing core Python packages..."
    
    # Function to check if a Python package is installed
    check_python_package() {
        python3 -c "import $1" 2>/dev/null
        return $?
    }
    
    # Try to install RPi.GPIO and spidev
    if ! check_python_package "RPi.GPIO"; then
        log "INFO" "Installing RPi.GPIO and spidev..."
        pip3 install --break-system-packages RPi.GPIO==0.7.1 spidev==3.5 || {
            log "WARNING" "Failed to install RPi.GPIO or spidev, trying without version pinning..."
            pip3 install --break-system-packages RPi.GPIO spidev
        }
    else
        log "INFO" "RPi.GPIO already installed, skipping"
    fi
    
    # Install Pillow - use system package if pip fails
    if ! check_python_package "PIL"; then
        log "INFO" "Installing Pillow..."
        pip3 install --break-system-packages "Pillow>=10.0.0" || {
            log "WARNING" "Pillow pip install failed, using system package python3-pil"
            install_package "python3-pil"
        }
    else
        log "INFO" "Pillow already installed, skipping"
    fi
    
    # Install numpy and pandas - prefer system packages but fallback to pip
    log "INFO" "Checking numpy and pandas..."
    if ! check_python_package "numpy" || ! check_python_package "pandas"; then
        log "INFO" "Installing numpy and pandas (this may take a while)..."
        pip3 install --break-system-packages --retries 5 --timeout 300 "numpy>=1.24.0" "pandas>=2.0.0" || {
            log "WARNING" "Pandas/numpy pip install failed, relying on system packages"
        }
    else
        log "INFO" "numpy and pandas already installed, skipping"
    fi
    
    # Install remaining packages from requirements.txt with retry logic
    # This includes all dependencies for full Ragnar functionality:
    # - netifaces: Network interface detection for NetworkScanner
    # - smbprotocol/pysmb: SMB protocol support for StealFilesSMB and SMBBruteforce
    # - sqlalchemy: SQL database operations for StealDataSQL
    # - openai: AI-powered network analysis and vulnerability insights
    log "INFO" "Installing remaining Python packages..."
    
    # Array of packages to install with their import names
    declare -A packages=(
        ["rich>=13.0.0"]="rich"
        ["netifaces==0.11.0"]="netifaces"
        ["ping3>=4.0.0"]="ping3"
        ["get-mac>=0.9.0"]="get_mac"
        ["paramiko>=3.0.0"]="paramiko"
        ["smbprotocol>=1.10.0"]="smbprotocol"
        ["pysmb>=1.2.0"]="smb"
        ["pymysql>=1.0.0"]="pymysql"
        ["sqlalchemy>=1.4.0"]="sqlalchemy"
        ["python-nmap>=0.7.0"]="nmap"
        ["flask>=3.0.0"]="flask"
        ["flask-socketio>=5.3.0"]="flask_socketio"
        ["flask-cors>=4.0.0"]="flask_cors"
        ["psutil>=5.9.0"]="psutil"
        ["logger>=1.4"]="logger"
    )
    
    # Install each package individually with retries if not already installed
    for package in "${!packages[@]}"; do
        import_name="${packages[$package]}"
        if check_python_package "$import_name"; then
            log "INFO" "$package already installed, skipping"
        else
            log "INFO" "Installing $package..."
            pip3 install --break-system-packages --retries 3 --timeout 180 "$package" || {
                log "WARNING" "Failed to install $package after retries. Continuing..."
            }
        fi
    done
    
    # Install OpenAI package separately for root (since service runs as root)
    log "INFO" "Installing OpenAI package for root user..."
    sudo pip3 install --break-system-packages --ignore-installed "openai>=2.0.0" || {
        log "WARNING" "Failed to install openai package for root. AI features may not work."
        log "WARNING" "You can install it manually later with: sudo pip3 install --break-system-packages --ignore-installed openai>=2.0.0"
    }

    # Install cryptography package for authentication and database encryption
    log "INFO" "Installing cryptography package for authentication..."
    sudo pip3 install --break-system-packages "cryptography>=41.0.0" || {
        log "WARNING" "Failed to install cryptography package. Authentication features may not work."
        log "WARNING" "You can install it manually later with: sudo pip3 install --break-system-packages cryptography>=41.0.0"
    }

    # Verify display driver availability
    if [ "$HEADLESS_MODE" = true ] || [ -z "${EPD_VERSION:-}" ]; then
        log "INFO" "Headless mode or unknown display version detected - skipping driver verification"
    elif [ "$EPD_VERSION" = "gc9a01" ]; then
        # TFT drivers ship with Ragnar in resources/waveshare_epd/, verify the file exists
        if [ -f "$ragnar_PATH/resources/waveshare_epd/gc9a01.py" ]; then
            log "SUCCESS" "GC9A01 TFT driver verified (resources/waveshare_epd/gc9a01.py)"
        else
            log "ERROR" "GC9A01 TFT driver not found at $ragnar_PATH/resources/waveshare_epd/gc9a01.py"
        fi
        # Ensure spidev is installed for TFT SPI communication
        pip3 install spidev --break-system-packages >/dev/null 2>&1
        log "INFO" "SPI dependencies installed for TFT display"
    elif [ "$EPD_VERSION" = "ssd1306" ]; then
        if [ -f "$ragnar_PATH/resources/waveshare_epd/ssd1306.py" ]; then
            log "SUCCESS" "SSD1306 OLED driver verified (resources/waveshare_epd/ssd1306.py)"
        else
            log "ERROR" "SSD1306 OLED driver not found at $ragnar_PATH/resources/waveshare_epd/ssd1306.py"
        fi
        # Install smbus2 for I2C communication
        pip3 install smbus2 --break-system-packages >/dev/null 2>&1
        # Enable I2C interface
        raspi-config nonint do_i2c 0 2>/dev/null || true
        log "INFO" "I2C interface enabled for SSD1306"
    elif [ "$EPD_VERSION" = "lcd1602" ]; then
        if [ -f "$ragnar_PATH/resources/waveshare_epd/lcd1602.py" ]; then
            log "SUCCESS" "LCD1602 driver verified (resources/waveshare_epd/lcd1602.py)"
        else
            log "ERROR" "LCD1602 driver not found at $ragnar_PATH/resources/waveshare_epd/lcd1602.py"
        fi
        # Install smbus2 for I2C communication
        pip3 install smbus2 --break-system-packages >/dev/null 2>&1
        # Enable I2C interface
        raspi-config nonint do_i2c 0 2>/dev/null || true
        log "INFO" "I2C interface enabled for LCD1602"
    else
        log "INFO" "Verifying Waveshare e-Paper library installation for $EPD_VERSION..."
        cd /home/$ragnar_USER/e-Paper/RaspberryPi_JetsonNano/python
        pip3 install . --break-system-packages
        
        python3 -c "from waveshare_epd import ${EPD_VERSION}; print('EPD module OK')" \
            && log "SUCCESS" "$EPD_VERSION driver verified successfully" \
            || log "ERROR" "EPD driver $EPD_VERSION failed to import"
    fi

    if [[ "$EPD_VERSION" == max7219* ]]; then
        sudo pip3 install --break-system-packages luma.led_matrix luma.core 2>/dev/null || pip3 install --break-system-packages luma.led_matrix luma.core 2>/dev/null || true
    fi

    check_success "Installed Python requirements"

    # Configure Ragnar entrypoint according to the selected mode
    log "INFO" "Configuring Ragnar entrypoint ($RAGNAR_ENTRYPOINT)..."
    local entrypoint_path="$ragnar_PATH/$RAGNAR_ENTRYPOINT"

    if [ -f "$entrypoint_path" ]; then
        if [ "$RAGNAR_ENTRYPOINT" = "Ragnar.py" ]; then
            if [ -f "$ragnar_PATH/webapp_modern.py" ]; then
                # Backup original Ragnar.py if not already backed up
                if [ ! -f "${entrypoint_path}.original" ]; then
                    cp "$entrypoint_path" "${entrypoint_path}.original"
                fi

                # Update Ragnar.py to use modern webapp
                if grep -q "from webapp import web_thread" "$entrypoint_path"; then
                    sed -i 's/from webapp import web_thread/# Old webapp - replaced with modern\n# from webapp import web_thread\nfrom webapp_modern import run_server as web_thread/' "$entrypoint_path"
                    log "SUCCESS" "Configured to use modern web interface"
                else
                    log "INFO" "Modern webapp already configured or different setup detected"
                fi
            else
                log "WARNING" "Modern webapp files not found, using default configuration"
            fi
        else
            log "INFO" "Headless variant selected (${HEADLESS_VARIANT_LABEL:-headless}); skipping display configuration"
        fi
    else
        log "WARNING" "Entrypoint $entrypoint_path not found, using default configuration"
    fi

    # Set correct permissions and ownership
    chown -R $ragnar_USER:$ragnar_USER /home/$ragnar_USER/Ragnar
    chmod -R 755 /home/$ragnar_USER/Ragnar
    
    # Make utility scripts executable with proper ownership
    chmod +x $ragnar_PATH/kill_port_8000.sh 2>/dev/null || true
    chmod +x $ragnar_PATH/scripts/update_ragnar.sh 2>/dev/null || true
    chmod +x $ragnar_PATH/scripts/quick_update.sh 2>/dev/null || true
    chmod +x $ragnar_PATH/scripts/uninstall_ragnar.sh 2>/dev/null || true
    chmod +x $ragnar_PATH/scripts/wifi_fix.sh 2>/dev/null || true
    chmod +x $ragnar_PATH/scripts/init_data_files.sh 2>/dev/null || true
    chmod +x $ragnar_PATH/scripts/preserve_local_data.sh 2>/dev/null || true
    chmod +x $ragnar_PATH/wipe_epd.py 2>/dev/null || true

    # Ensure ragnar user owns all script files
    chown $ragnar_USER:$ragnar_USER $ragnar_PATH/*.sh 2>/dev/null || true
    chown $ragnar_USER:$ragnar_USER $ragnar_PATH/scripts/*.sh 2>/dev/null || true

    # Initialize data files from templates
    log "INFO" "Initializing data files from templates..."
    bash $ragnar_PATH/scripts/init_data_files.sh
    chown -R $ragnar_USER:$ragnar_USER $ragnar_PATH/data
    
    # Create missing directories and files that are needed for proper operation
    log "INFO" "Creating missing directories and files..."
    
    # Create dictionary directory and files
    mkdir -p $ragnar_PATH/data/input/dictionary
    if [ ! -f "$ragnar_PATH/data/input/dictionary/users.txt" ]; then
        cat > $ragnar_PATH/data/input/dictionary/users.txt << EOF
admin
root
user
administrator
test
guest
EOF
        log "SUCCESS" "Created users.txt dictionary file"
    fi
    
    if [ ! -f "$ragnar_PATH/data/input/dictionary/passwords.txt" ]; then
        cat > $ragnar_PATH/data/input/dictionary/passwords.txt << EOF
password
123456
admin
root
password123
123
test
guest
EOF
        log "SUCCESS" "Created passwords.txt dictionary file"
    fi
    
    # Create comments.json file if missing
    if [ ! -f "$ragnar_PATH/resources/comments/comments.json" ]; then
        mkdir -p $ragnar_PATH/resources/comments
        echo "[]" > $ragnar_PATH/resources/comments/comments.json
        log "SUCCESS" "Created comments.json file"
    fi
    
    # Create missing ragnar1.bmp placeholder if needed (optional since we handle this gracefully now)
    if [ ! -f "$ragnar_PATH/resources/images/static/ragnar1.bmp" ] && [ -f "$ragnar_PATH/resources/images/static/bjorn1.bmp" ]; then
        cp "$ragnar_PATH/resources/images/static/bjorn1.bmp" "$ragnar_PATH/resources/images/static/ragnar1.bmp"
        log "SUCCESS" "Created ragnar1.bmp from bjorn1.bmp"
    fi
    
    # Set proper ownership for all created files
    chown -R $ragnar_USER:$ragnar_USER $ragnar_PATH/data/
    chown -R $ragnar_USER:$ragnar_USER $ragnar_PATH/resources/
    
    # Validate and fix actions.json file
    log "INFO" "Validating actions.json configuration..."
    python3 << 'PYTHON_EOF'
import json
import os

actions_file = "/home/ragnar/Ragnar/config/actions.json"

# Check if scanning module exists in actions.json
try:
    with open(actions_file, 'r') as f:
        actions = json.load(f)
    
    # Check if scanning module is present
    has_scanning = any(action.get('b_module') == 'scanning' for action in actions)
    
    if not has_scanning:
        print("WARNING: scanning module missing from actions.json, adding it...")
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
        print("SUCCESS: scanning module found in actions.json")
        
except Exception as e:
    print(f"ERROR validating actions.json: {e}")
PYTHON_EOF
    
    # Add ragnar user to necessary groups (including sudo for WiFi management)
    usermod -a -G spi,gpio,i2c,sudo,netdev $ragnar_USER
    
    # Configure sudo for WiFi management commands without password
    log "INFO" "Configuring sudo permissions for WiFi management..."
    cat > /etc/sudoers.d/ragnar-wifi << EOF
# Allow ragnar user to run WiFi management commands without password
ragnar ALL=(ALL) NOPASSWD: /usr/bin/nmcli, /sbin/iwlist, /sbin/ip, /bin/systemctl start hostapd, /bin/systemctl stop hostapd, /bin/systemctl start dnsmasq, /bin/systemctl stop dnsmasq, /usr/sbin/hostapd, /usr/sbin/dnsmasq
EOF
    chmod 440 /etc/sudoers.d/ragnar-wifi
    
    # Configure sudo for nmap port scanning without password
    log "INFO" "Configuring sudo permissions for nmap..."
    cat > /etc/sudoers.d/ragnar-nmap << EOF
# Allow ragnar user to run nmap without password for port scanning
ragnar ALL=(ALL) NOPASSWD: /usr/bin/nmap
EOF
    chmod 440 /etc/sudoers.d/ragnar-nmap
    
    # Configure sudo for traffic analysis tools without password
    log "INFO" "Configuring sudo permissions for traffic analysis..."
    cat > /etc/sudoers.d/ragnar-traffic << EOF
# Allow ragnar user to run traffic analysis tools without password
ragnar ALL=(ALL) NOPASSWD: /usr/bin/tcpdump
ragnar ALL=(ALL) NOPASSWD: /usr/bin/tshark
ragnar ALL=(ALL) NOPASSWD: /usr/sbin/iftop
ragnar ALL=(ALL) NOPASSWD: /usr/sbin/nethogs
EOF
    chmod 440 /etc/sudoers.d/ragnar-traffic
    
    check_success "Added ragnar user to required groups and configured sudo permissions"
}


# Configure services
setup_services() {
    log "INFO" "Setting up system services..."

    local entrypoint_file="$RAGNAR_ENTRYPOINT"
    local wipe_exec=""
    if [ "$HEADLESS_MODE" != true ]; then
        wipe_exec="yes"
    fi
    
    # Create kill_port_8000.sh script
    cat > $ragnar_PATH/kill_port_8000.sh << 'EOF'
#!/bin/bash
PORT=8000
PIDS=$(lsof -w -t -i:$PORT 2>/dev/null)
if [ -n "$PIDS" ]; then
    echo "Killing PIDs using port $PORT: $PIDS"
    kill -9 $PIDS
fi
EOF
    chmod +x $ragnar_PATH/kill_port_8000.sh
    chown ragnar:ragnar $ragnar_PATH/kill_port_8000.sh

    # Create ragnar service
    cat > /etc/systemd/system/ragnar.service << EOF
[Unit]
Description=ragnar Service
After=network.target

[Service]
ExecStartPre=-/bin/bash -c '/home/ragnar/Ragnar/kill_port_8000.sh; ip link set mon0 down 2>/dev/null; iw mon0 del 2>/dev/null; systemctl stop pwnagotchi 2>/dev/null; systemctl stop bettercap 2>/dev/null; true'
EOF

    if [ -n "$wipe_exec" ]; then
        # Prefix with - so wipe_epd failure does not block service start
        # Must run as separate process: GPIO pins conflict if shared with Display's EPDHelper
        cat >> /etc/systemd/system/ragnar.service << EOF
ExecStartPre=-/usr/bin/python3 -OO /home/ragnar/Ragnar/wipe_epd.py
EOF
    fi

    cat >> /etc/systemd/system/ragnar.service << EOF
ExecStart=/usr/bin/python3 -OO /home/ragnar/Ragnar/${entrypoint_file}
WorkingDirectory=/home/ragnar/Ragnar
StandardOutput=inherit
StandardError=inherit
Restart=always
RestartSec=3
User=root
TimeoutStopSec=5
KillMode=mixed

# Check open files and restart if it reached the limit (ulimit -n buffer of 10000)
# ExecStartPost=/bin/bash -c 'FILE_LIMIT=\$(ulimit -n); THRESHOLD=\$(( FILE_LIMIT - 10000 )); while :; do TOTAL_OPEN_FILES=\$(lsof -w 2>/dev/null | wc -l); if [ "\$TOTAL_OPEN_FILES" -ge "\$THRESHOLD" ]; then echo "File descriptor threshold reached: \$TOTAL_OPEN_FILES (threshold: \$THRESHOLD). Restarting service."; systemctl restart ragnar.service; exit 0; fi; sleep 10; done &'

[Install]
WantedBy=multi-user.target
EOF

    # Configure NetworkManager for WiFi management
    log "INFO" "Configuring NetworkManager for WiFi management..."
    
    # Enable and start NetworkManager
    systemctl enable NetworkManager
    systemctl start NetworkManager
    
    # Configure NetworkManager for WiFi management priority
    cat > /etc/NetworkManager/conf.d/99-ragnar-wifi.conf << EOF
[main]
# Ragnar WiFi Management Configuration
dns=default

[device]
# Manage WiFi devices
wifi.scan-rand-mac-address=no

[connection]
# WiFi connection settings
wifi.cloned-mac-address=preserve
EOF

    # Ensure NetworkManager manages wlan0
    nmcli dev set wlan0 managed yes 2>/dev/null || log "WARNING" "Could not set wlan0 to managed (interface may not exist yet)"
    
    # Enable and start services
    systemctl daemon-reload
    systemctl enable ragnar.service
    if systemctl start ragnar.service; then
        log "SUCCESS" "Started ragnar.service"
    else
        log "WARNING" "Failed to start ragnar.service (it will start on next boot); check logs"
    fi

    check_success "Services setup completed"
}

# Configure ZRAM swap override to increase available swap space
configure_zram_swap() {
    log "INFO" "Configuring ZRAM swap override (ram * 2)..."

    local zram_conf_dir="/etc/systemd/zram-generator.conf.d"
    local zram_conf_file="$zram_conf_dir/override.conf"

    mkdir -p "$zram_conf_dir"
    check_success "Ensured ZRAM override directory exists"

    cat > "$zram_conf_file" << 'EOF'
[zram0]
zram-size = ram * 2
EOF
    check_success "Updated ZRAM override configuration"

    systemctl daemon-reload
    check_success "Reloaded systemd daemon for ZRAM override"

    log "SUCCESS" "ZRAM swap configured to twice the physical RAM"
}

# Configure USB Gadget
configure_usb_gadget() {
    log "INFO" "Configuring USB Gadget..."

    # Skip on systems without Pi-style boot firmware layout
    if [ ! -d "/boot/firmware" ] || [ ! -f "/boot/firmware/cmdline.txt" ]; then
        log "INFO" "USB Gadget configuration skipped: /boot/firmware not present on this platform"
        return 0
    fi

    # Modify cmdline.txt
    sed -i 's/rootwait/rootwait modules-load=dwc2,g_ether/' /boot/firmware/cmdline.txt

    # Modify config.txt
    echo "dtoverlay=dwc2" >> /boot/firmware/config.txt

    # Create USB gadget script
    cat > /usr/local/bin/usb-gadget.sh << 'EOF'
#!/bin/bash
set -e

modprobe libcomposite
cd /sys/kernel/config/usb_gadget/
mkdir -p g1
cd g1

echo 0x1d6b > idVendor
echo 0x0104 > idProduct
echo 0x0100 > bcdDevice
echo 0x0200 > bcdUSB

mkdir -p strings/0x409
echo "fedcba9876543210" > strings/0x409/serialnumber
echo "Raspberry Pi" > strings/0x409/manufacturer
echo "Pi Zero USB" > strings/0x409/product

mkdir -p configs/c.1/strings/0x409
echo "Config 1: ECM network" > configs/c.1/strings/0x409/configuration
echo 250 > configs/c.1/MaxPower

mkdir -p functions/ecm.usb0

if [ -L configs/c.1/ecm.usb0 ]; then
    rm configs/c.1/ecm.usb0
fi
ln -s functions/ecm.usb0 configs/c.1/

max_retries=10
retry_count=0

while ! ls /sys/class/udc > UDC 2>/dev/null; do
    if [ $retry_count -ge $max_retries ]; then
        echo "Error: Device or resource busy after $max_retries attempts."
        exit 1
    fi
    retry_count=$((retry_count + 1))
    sleep 1
done

if ! ip addr show usb0 | grep -q "172.20.2.1"; then
    ifconfig usb0 172.20.2.1 netmask 255.255.255.0
else
    echo "Interface usb0 already configured."
fi
EOF

    chmod +x /usr/local/bin/usb-gadget.sh

    # Create USB gadget service
    cat > /etc/systemd/system/usb-gadget.service << EOF
[Unit]
Description=USB Gadget Service
After=network.target

[Service]
ExecStartPre=/sbin/modprobe libcomposite
ExecStart=/usr/local/bin/usb-gadget.sh
Type=simple
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    # Configure network interface
    cat >> /etc/network/interfaces << EOF

allow-hotplug usb0
iface usb0 inet static
    address 172.20.2.1
    netmask 255.255.255.0
EOF

    # Enable and start services
    systemctl daemon-reload
    systemctl enable systemd-networkd
    systemctl enable usb-gadget
    systemctl start systemd-networkd
    systemctl start usb-gadget

    check_success "USB Gadget configuration completed"
}

# Prompt for which headless variant to install when no e-paper is selected
select_headless_variant() {
    echo -e "\n${BLUE}Headless Installation Options${NC}"
    echo "1. Install on Raspberry Pi (no e-paper display)"
    echo "2. Install hbp0_ragnar by DezusAZ"

    while true; do
        read -p "Choose an option (1/2): " headless_choice
        case $headless_choice in
            1)
                HEADLESS_MODE=true
                HEADLESS_VARIANT="raspberry_pi"
                HEADLESS_VARIANT_LABEL="Raspberry Pi headless"
                RAGNAR_ENTRYPOINT="headlessRagnar.py"
                log "INFO" "Selected headless installation for Raspberry Pi"
                break
                ;;
            2)
                HEADLESS_MODE=true
                HEADLESS_VARIANT="hbp0_ragnar"
                HEADLESS_VARIANT_LABEL="hbp0_ragnar by DezusAZ"
                RAGNAR_ENTRYPOINT="headlessRagnar.py"
                log "INFO" "Selected headless installation: hbp0_ragnar by DezusAZ"
                break
                ;;
            *)
                echo -e "${RED}Invalid choice. Please select 1 or 2.${NC}"
                ;;
        esac
    done
}

# Verify installation
verify_installation() {
    log "INFO" "Verifying installation..."
    
    # Check WiFi management dependencies
    log "INFO" "Verifying WiFi management dependencies..."
    
    # Check NetworkManager
    if systemctl is-active --quiet NetworkManager; then
        log "SUCCESS" "NetworkManager is running"
    else
        log "WARNING" "NetworkManager is not running - WiFi management may not work"
    fi
    
    # Check nmcli command
    if command -v nmcli >/dev/null 2>&1; then
        log "SUCCESS" "nmcli command available"
    else
        log "ERROR" "nmcli command not found - critical for WiFi management"
    fi
    
    # Check iwlist command
    if command -v iwlist >/dev/null 2>&1; then
        log "SUCCESS" "iwlist command available"
    else
        log "WARNING" "iwlist command not found - AP mode scanning may be limited"
    fi
    
    # Check hostapd and dnsmasq
    if command -v hostapd >/dev/null 2>&1 && command -v dnsmasq >/dev/null 2>&1; then
        log "SUCCESS" "hostapd and dnsmasq available"
    else
        log "ERROR" "hostapd or dnsmasq not found - AP mode will not work"
    fi
    
    # Check Python WiFi dependencies
    log "INFO" "Verifying Python dependencies..."
    python3 -c "
import sys
failed = []
required_modules = ['flask', 'flask_socketio', 'psutil', 'netifaces']
for module in required_modules:
    try:
        __import__(module)
        print(f'✓ {module}')
    except ImportError:
        failed.append(module)
        print(f'✗ {module}')

if failed:
    print(f'ERROR: Missing Python modules: {failed}')
    sys.exit(1)
else:
    print('SUCCESS: All critical Python modules available')
" && log "SUCCESS" "Python dependencies verified" || log "ERROR" "Some Python dependencies missing"
    
    # Check if services are running
    if ! systemctl is-active --quiet ragnar.service; then
        log "WARNING" "ragnar service is not running"
    else
        log "SUCCESS" "ragnar service is running"
    fi
    
    # Check web interface
    sleep 5
    if curl -s http://localhost:8000 > /dev/null; then
        log "SUCCESS" "Web interface is accessible"
    else
        log "WARNING" "Web interface is not responding"
    fi
    
    log "INFO" "WiFi timer functionality will be available when AP mode is active"
}

# Clean exit function
clean_exit() {
    local exit_code=$1
    if [ $exit_code -eq 0 ]; then
        log "SUCCESS" "ragnar installation completed successfully!"
        log "INFO" "Log file available at: $LOG_FILE"
    else
        log "ERROR" "ragnar installation failed!"
        log "ERROR" "Check the log file for details: $LOG_FILE"
    fi
    exit $exit_code
}

# Display the installation menu with banner
show_install_menu() {
    local is_pi=$1
    clear
    echo ""
    echo -e "${GREEN}"
    cat << 'BANNER'
    ____
   |  _ \ __ _  __ _ _ __   __ _ _ __
   | |_) / _` |/ _` | '_ \ / _` | '__|
   |  _ < (_| | (_| | | | | (_| | |
   |_| \_\__,_|\__, |_| |_|\__,_|_|
                |___/
BANNER
    echo -e "${NC}"
    echo -e "${CYAN}  ══════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}     Network Security & Pentesting Toolkit                ${NC}"
    echo -e "${GREEN}     Created by Pierre Gode                               ${NC}"
    echo -e "${CYAN}  ──────────────────────────────────────────────────────────${NC}"
    echo -e "${RED}     For authorized penetration testing only.              ${NC}"
    echo -e "${RED}     Unauthorized access to networks is illegal.           ${NC}"
    echo -e "${CYAN}  ══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${BLUE}   Select installation profile:${NC}"
    echo ""
    if [ "$is_pi" = true ]; then
        echo -e "   ${CYAN}*${YELLOW} 1)${CYAN} Raspberry Pi with e-Paper display              ${NC}"
        echo -e "   ${CYAN}*${YELLOW} 2)${CYAN} Raspberry Pi with TFT LCD display              ${NC}"
        echo -e "   ${CYAN}*${YELLOW} 3)${CYAN} Server install with display                    ${NC}"
        echo -e "   ${CYAN}*${YELLOW} 4)${CYAN} Server install (headless, no display)           ${NC}"
        echo -e "   ${CYAN}*${YELLOW} 5)${CYAN} WiFi Pineapple Pager ${RED}(beta)                    ${NC}"
    else
        echo -e "   ${CYAN}*${YELLOW} 1)${CYAN} Server install with display                    ${NC}"
        echo -e "   ${CYAN}*${YELLOW} 2)${CYAN} Server install (headless, no display)           ${NC}"
        echo -e "   ${CYAN}*${YELLOW} 3)${CYAN} WiFi Pineapple Pager                            ${NC}"
    fi
    echo ""
    echo -e "${CYAN}  ══════════════════════════════════════════════════════════${NC}"
    echo -e "   Enter your choice or ${RED}ctrl+c${NC} to exit."
    echo ""
    echo -ne "   ${YELLOW}> ${NC}"
}

# Main installation process
main() {
    log "INFO" "Starting ragnar installation..."

    detect_platform
    log_system_summary

    # Check if script is run as root
    if [ "$(id -u)" -ne 0 ]; then
        echo "This script must be run as root. Please use 'sudo'."
        exit 1
    fi

    local is_pi=false
    if grep -qi "Raspberry Pi" /proc/cpuinfo 2>/dev/null; then
        is_pi=true
    fi

    # Display menu and handle selection (loops on invalid input)
    local profile_choice=""
    while true; do
        show_install_menu "$is_pi"
        read -r profile_choice

        if [ "$is_pi" = true ]; then
            case $profile_choice in
                1)
                    SERVER_INSTALL=false
                    HEADLESS_MODE=false
                    TFT_MODE=false
                    HEADLESS_VARIANT=""
                    HEADLESS_VARIANT_LABEL=""
                    RAGNAR_ENTRYPOINT="Ragnar.py"
                    log "INFO" "Raspberry Pi with e-Paper installation selected"
                    break
                    ;;
                2)
                    SERVER_INSTALL=false
                    HEADLESS_MODE=false
                    TFT_MODE=true
                    HEADLESS_VARIANT=""
                    HEADLESS_VARIANT_LABEL=""
                    RAGNAR_ENTRYPOINT="Ragnar.py"
                    log "INFO" "Raspberry Pi with TFT LCD installation selected"
                    break
                    ;;
                3)
                    SERVER_INSTALL=true
                    HEADLESS_MODE=false
                    TFT_MODE=false
                    HEADLESS_VARIANT=""
                    HEADLESS_VARIANT_LABEL="Server install with display"
                    RAGNAR_ENTRYPOINT="Ragnar.py"
                    log "INFO" "Server install with display selected on Raspberry Pi hardware"
                    break
                    ;;
                4)
                    SERVER_INSTALL=true
                    HEADLESS_MODE=true
                    TFT_MODE=false
                    HEADLESS_VARIANT="server"
                    HEADLESS_VARIANT_LABEL="Server install"
                    RAGNAR_ENTRYPOINT="headlessRagnar.py"
                    log "INFO" "Server install (headless) selected on Raspberry Pi hardware"
                    break
                    ;;
                5)
                    log "INFO" "WiFi Pineapple Pager installation selected"
                    echo ""
                    echo -e "${BLUE}   This will package and deploy Ragnar to your Pineapple Pager.${NC}"
                    echo -e "${YELLOW}   Make sure your Pager is connected and accessible via SSH.${NC}"
                    echo ""
                    read -p "   Enter Pager IP address [172.16.42.1]: " pager_ip
                    pager_ip="${pager_ip:-172.16.42.1}"

                    pager_exit_code=0
                    if [ -f "$ragnar_PATH/scripts/install_pineapple_pager.sh" ]; then
                        chmod +x "$ragnar_PATH/scripts/install_pineapple_pager.sh"
                        bash "$ragnar_PATH/scripts/install_pineapple_pager.sh" "$pager_ip" || pager_exit_code=$?
                    elif [ -f "$(dirname "$0")/scripts/install_pineapple_pager.sh" ]; then
                        chmod +x "$(dirname "$0")/scripts/install_pineapple_pager.sh"
                        bash "$(dirname "$0")/scripts/install_pineapple_pager.sh" "$pager_ip" || pager_exit_code=$?
                    else
                        log "ERROR" "install_pineapple_pager.sh not found"
                        log "INFO" "Run it directly: ./scripts/install_pineapple_pager.sh $pager_ip"
                        pager_exit_code=1
                    fi
                    clean_exit $pager_exit_code
                    ;;
                *)
                    echo -e "\n   ${RED}Invalid option. Please select 1, 2, 3, 4, or 5.${NC}"
                    sleep 1
                    ;;
            esac
        else
            case $profile_choice in
                1)
                    SERVER_INSTALL=true
                    HEADLESS_MODE=false
                    HEADLESS_VARIANT=""
                    HEADLESS_VARIANT_LABEL="Server install with e-Paper"
                    RAGNAR_ENTRYPOINT="Ragnar.py"
                    log "INFO" "Server install with e-Paper selected"
                    break
                    ;;
                2)
                    SERVER_INSTALL=true
                    HEADLESS_MODE=true
                    HEADLESS_VARIANT="server"
                    HEADLESS_VARIANT_LABEL="Server install"
                    RAGNAR_ENTRYPOINT="headlessRagnar.py"
                    log "INFO" "Server install (headless) profile selected"
                    break
                    ;;
                3)
                    log "INFO" "WiFi Pineapple Pager installation selected"
                    echo ""
                    echo -e "${BLUE}   This will package and deploy Ragnar to your Pineapple Pager.${NC}"
                    echo -e "${YELLOW}   Make sure your Pager is connected and accessible via SSH.${NC}"
                    echo ""
                    read -p "   Enter Pager IP address [172.16.42.1]: " pager_ip
                    pager_ip="${pager_ip:-172.16.42.1}"

                    pager_exit_code=0
                    if [ -f "$(dirname "$0")/scripts/install_pineapple_pager.sh" ]; then
                        chmod +x "$(dirname "$0")/scripts/install_pineapple_pager.sh"
                        bash "$(dirname "$0")/scripts/install_pineapple_pager.sh" "$pager_ip" || pager_exit_code=$?
                    else
                        log "ERROR" "install_pineapple_pager.sh not found"
                        pager_exit_code=1
                    fi
                    clean_exit $pager_exit_code
                    ;;
                *)
                    echo -e "\n   ${RED}Invalid option. Please select 1, 2, or 3.${NC}"
                    sleep 1
                    ;;
            esac
        fi
    done

    # Only attempt e-paper setup when not in server/headless profile
    if [ "$HEADLESS_MODE" != true ]; then

        # ── TFT LCD display path ──────────────────────────────────────────────
        if [ "$TFT_MODE" = true ]; then
            echo -e "\n${BLUE}TFT LCD Display Setup${NC}"
            echo -e "${YELLOW}Installing SPI dependencies for TFT display...${NC}"
            pip3 install spidev --break-system-packages >/dev/null 2>&1
            log "SUCCESS" "SPI dependencies installed for TFT display"

            echo -e "\n${BLUE}Select your TFT/OLED display:${NC}"
            echo "1. GC9A01      (1.28\" Round 240x240)"
            echo "2. SSD1306     (0.96\" OLED 128x64)"
            echo "3. LCD1602     (16x2 I2C Character LCD)"
            echo "4. No display  (headless install)"

            while true; do
                read -p "Enter your choice (1-4): " tft_choice
                case $tft_choice in
                    1) EPD_VERSION="gc9a01"; break;;
                    2) EPD_VERSION="ssd1306"; break;;
                    3) EPD_VERSION="lcd1602"; break;;
                    4)
                        select_headless_variant
                        EPD_VERSION=""
                        break
                        ;;
                    *) echo -e "${RED}Invalid choice. Please select 1-4.${NC}";;
                esac
            done

            if [ -n "$EPD_VERSION" ]; then
                echo -e "${GREEN}✓ Selected display: $EPD_VERSION${NC}"
                log "INFO" "Display selected: $EPD_VERSION"
            fi

        # ── E-Paper display path ──────────────────────────────────────────────
        else
        echo -e "\n${BLUE}Installing Waveshare e-Paper library...${NC}"
        log "INFO" "Installing Waveshare e-Paper library for auto-detection"
        
        cd /home/$ragnar_USER 2>/dev/null || mkdir -p /home/$ragnar_USER
        if [ ! -d "e-Paper" ]; then
            git clone --depth=1 --filter=blob:none --sparse https://github.com/waveshareteam/e-Paper.git
            cd e-Paper
            git sparse-checkout set RaspberryPi_JetsonNano
            cd RaspberryPi_JetsonNano/python
            pip3 install . --break-system-packages >/dev/null 2>&1
            log "SUCCESS" "Installed Waveshare e-Paper library"
        else
            log "INFO" "Waveshare e-Paper repository already exists"
            cd e-Paper/RaspberryPi_JetsonNano/python
            pip3 install . --break-system-packages >/dev/null 2>&1
        fi

        echo -e "\n${BLUE}E-Paper Display Auto-Detection${NC}"
        echo -e "${YELLOW}I will now attempt to detect your e-Paper display.${NC}"
        echo -e "${YELLOW}This requires the display to be properly connected via SPI.${NC}"
        read -p "Is your e-Paper display connected? (y/n): " epd_connected
        
        if [[ "$epd_connected" =~ ^[Yy]$ ]]; then
            echo -e "\n${BLUE}Detecting E-Paper Display...${NC}"
            log "INFO" "Attempting to auto-detect E-Paper display"
            
            EPD_VERSION=""
            EPD_VERSIONS=("epd2in13_V4" "epd2in13_V3" "epd2in13_V2" "epd2in7_V2" "epd2in7" "epd2in13" "epd2in9_V2" "epd3in7" "epd4in26")
            
            for version in "${EPD_VERSIONS[@]}"; do
                echo -e "${BLUE}Testing ${version}...${NC}"
                # Create a test script that properly cleans up GPIO
                TEST_RESULT=$(python3 -c "
import sys
import time
try:
    from waveshare_epd import ${version}
    epd = ${version}.EPD()
    epd.init()
    time.sleep(0.1)
    epd.sleep()
    # Attempt to cleanup GPIO
    try:
        epd.module_exit()
    except:
        pass
    print('SUCCESS')
    sys.exit(0)
except Exception as e:
    # Attempt to cleanup GPIO even on error
    try:
        import gpiozero
        gpiozero.Device.pin_factory.reset()
    except:
        pass
    print(f'FAILED: {e}', file=sys.stderr)
    sys.exit(1)
" 2>&1)
                
                if echo "$TEST_RESULT" | grep -q "SUCCESS"; then
                    EPD_VERSION="$version"
                    echo -e "${GREEN}✓ Detected E-Paper display: $EPD_VERSION${NC}"
                    log "SUCCESS" "Auto-detected E-Paper display: $EPD_VERSION"
                    break
                else
                    # If GPIO busy, try to reset it before next attempt
                    if echo "$TEST_RESULT" | grep -qi "GPIO busy"; then
                        log "DEBUG" "GPIO busy, attempting reset before next detection attempt"
                        python3 -c "
try:
    import gpiozero
    gpiozero.Device.pin_factory.reset()
except:
    pass
" 2>/dev/null || true
                        sleep 0.5
                    fi
                fi
            done
            
            if [ -z "$EPD_VERSION" ]; then
                echo -e "${YELLOW}⚠ Could not auto-detect E-Paper display${NC}"
                echo -e "${YELLOW}This might be due to:${NC}"
                echo -e "${YELLOW}  - SPI interface not enabled${NC}"
                echo -e "${YELLOW}  - Incorrect wiring${NC}"
                echo -e "${YELLOW}  - Unsupported display model${NC}"
                echo -e "${YELLOW}  - GPIO pins in use by another process${NC}"
                log "WARNING" "E-Paper auto-detection failed despite user confirmation"
            fi
        else
            echo -e "${YELLOW}Skipping auto-detection${NC}"
            log "INFO" "User indicated e-Paper display is not connected, skipping auto-detection"
        fi
        
        if [ -z "$EPD_VERSION" ]; then
            echo -e "\n${BLUE}Please select your display:${NC}"
            echo ""
            echo -e "${CYAN}  E-Paper displays:${NC}"
            echo "1.  epd2in13     (2.13\" 122x250)"
            echo "2.  epd2in13_V2  (2.13\" V2 122x250)"
            echo "3.  epd2in13_V3  (2.13\" V3 122x250)"
            echo "4.  epd2in13_V4  (2.13\" V4 122x250)"
            echo "5.  epd2in7_V2   (2.7\"  V2 176x264)"
            echo "6.  epd2in7      (2.7\"  V1 176x264)"
            echo "7.  epd2in9_V2   (2.9\"  128x296)"
            echo "8.  epd3in7      (3.7\"  280x480)"
            echo "9.  epd4in26     (4.26\" 800x480)"
            echo ""
            echo -e "${CYAN}  TFT LCD displays:${NC}"
            echo "10. GC9A01       (1.28\" Round 240x240)"
            echo ""
            echo -e "${CYAN}  OLED displays:${NC}"
            echo "11. SSD1306      (0.96\" OLED 128x64)"
            echo ""
            echo -e "${CYAN}  Character LCD:${NC}"
            echo "12. LCD1602      (16x2 I2C Character LCD)"
            echo ""
            echo -e "${CYAN}  LED Matrix displays:${NC}"
            echo "13. MAX7219  (8 panels 64×8 LED matrix)"
            echo "14. MAX7219  (4 panels 32×8 LED matrix)"
            echo ""
            echo "15. No display (headless install)"

            while true; do
                read -p "Enter your choice (1-15): " epd_choice
                case $epd_choice in
                    1) EPD_VERSION="epd2in13"; break;;
                    2) EPD_VERSION="epd2in13_V2"; break;;
                    3) EPD_VERSION="epd2in13_V3"; break;;
                    4) EPD_VERSION="epd2in13_V4"; break;;
                    5) EPD_VERSION="epd2in7_V2"; break;;
                    6) EPD_VERSION="epd2in7"; break;;
                    7) EPD_VERSION="epd2in9_V2"; break;;
                    8) EPD_VERSION="epd3in7"; break;;
                    9) EPD_VERSION="epd4in26"; break;;
                    10) EPD_VERSION="gc9a01"; break;;
                    11) EPD_VERSION="ssd1306"; break;;
                    12) EPD_VERSION="lcd1602"; break;;
                    13) EPD_VERSION="max7219_8panel"; break;;
                    14) EPD_VERSION="max7219_4panel"; break;;
                    15)
                        select_headless_variant
                        EPD_VERSION=""
                        break
                        ;;
                    *) echo -e "${RED}Invalid choice. Please select 1-15.${NC}";;
                esac
            done

            if [ "$HEADLESS_MODE" = true ]; then
                log "INFO" "No display selected. Headless mode enabled (${HEADLESS_VARIANT_LABEL:-unspecified})."
            else
                log "INFO" "Manually selected display: $EPD_VERSION"
            fi
        fi
        fi  # end TFT_MODE else
    else
        log "INFO" "Headless/server profile selected; skipping e-Paper detection"
    fi

    CURRENT_STEP=1; show_progress "Checking system compatibility"
    check_system_compatibility
    
    CURRENT_STEP=2; show_progress "Checking internet connectivity"
    check_internet

    CURRENT_STEP=3; show_progress "Installing system dependencies"
    install_dependencies

    CURRENT_STEP=4; show_progress "Configuring system limits"
    configure_system_limits

    CURRENT_STEP=5; show_progress "Configuring interfaces"
    configure_interfaces

    CURRENT_STEP=6; show_progress "Installing PiSugar server (if applicable)"
    install_pisugar_server

    CURRENT_STEP=7; show_progress "Setting up ragnar"
    setup_ragnar

    CURRENT_STEP=8; show_progress "Configuring USB Gadget"
    configure_usb_gadget

    CURRENT_STEP=9; show_progress "Setting up services"
    setup_services

    CURRENT_STEP=9; show_progress "Verifying installation"
    verify_installation

    # Check if system qualifies for advanced tools (8GB+ RAM, not Pi Zero)
    CURRENT_STEP=10; show_progress "Checking for advanced security tools eligibility"
    
    # Detect if this is a Pi Zero (insufficient resources for advanced tools)
    IS_PI_ZERO=false
    if grep -qi "Raspberry Pi Zero" /proc/cpuinfo 2>/dev/null; then
        IS_PI_ZERO=true
        log "INFO" "Raspberry Pi Zero detected - skipping advanced tools installation"
    fi
    
    # Check available RAM (7.5GB threshold for 8GB systems with overhead)
    # Read from /proc/meminfo — always English, works under sudo, no locale issues
    TOTAL_RAM_KB=$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null)
    TOTAL_RAM_MB=$(( ${TOTAL_RAM_KB:-0} / 1024 ))
    TOTAL_RAM_GB=$(awk "BEGIN{printf \"%.2f\", ${TOTAL_RAM_MB}/1024}")
    MIN_RAM_MB=7680
    HAS_ENOUGH_RAM=0
    [ "$TOTAL_RAM_MB" -ge "$MIN_RAM_MB" ] 2>/dev/null && HAS_ENOUGH_RAM=1
    
    log "INFO" "System RAM: ${TOTAL_RAM_GB}GB / ${TOTAL_RAM_MB}MB (minimum: 7.5GB)"
    
    if [ "$IS_PI_ZERO" = false ] && [ "$HAS_ENOUGH_RAM" = "1" ]; then
        log "INFO" "System qualifies for advanced security tools (${TOTAL_RAM_GB}GB RAM, not Pi Zero)"
        echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${CYAN}  Installing Advanced Security Tools${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}Your system has sufficient resources for advanced features:${NC}"
        echo -e "  ${BLUE}•${NC} Real-time traffic analysis (tcpdump, tshark, ngrep)"
        echo -e "  ${BLUE}•${NC} Advanced vulnerability scanning (Nuclei, Nikto, SQLMap)"
        echo -e "  ${BLUE}•${NC} Web application security testing (OWASP ZAP)"
        echo -e "  ${BLUE}•${NC} Enhanced Nmap vulnerability scripts"
        echo ""
        
        log "INFO" "Automatically installing advanced security tools..."
        echo -e "${BLUE}Running advanced tools installer...${NC}"
        
        # Check if install_advanced_tools.sh exists
        if [ -f "$ragnar_PATH/scripts/install_advanced_tools.sh" ]; then
            chmod +x "$ragnar_PATH/scripts/install_advanced_tools.sh"
            cd "$ragnar_PATH"

            # Run the advanced tools installer
            if bash "$ragnar_PATH/scripts/install_advanced_tools.sh"; then
                log "SUCCESS" "Advanced security tools installed successfully"
                echo -e "${GREEN}✓ Advanced security tools installed${NC}"
            else
                log "WARNING" "Advanced tools installation encountered issues"
                echo -e "${YELLOW}⚠ Some advanced tools may not have installed correctly${NC}"
                echo -e "${YELLOW}  You can run the installer manually later:${NC}"
                echo -e "${YELLOW}  cd /home/ragnar/Ragnar && sudo ./scripts/install_advanced_tools.sh${NC}"
            fi
        else
            log "ERROR" "install_advanced_tools.sh not found at $ragnar_PATH/scripts"
            echo -e "${RED}Advanced tools installer script not found${NC}"
            echo -e "${YELLOW}You can install advanced tools manually later if needed${NC}"
        fi
    else
        if [ "$IS_PI_ZERO" = true ]; then
            log "INFO" "Raspberry Pi Zero detected - advanced tools not recommended due to limited resources"
        else
            log "INFO" "System has ${TOTAL_RAM_GB}GB RAM (minimum 7.5GB required for advanced tools)"
            echo -e "\n${YELLOW}Note: Advanced security tools require at least 8GB RAM${NC}"
            echo -e "${YELLOW}Your system: ${TOTAL_RAM_GB}GB RAM${NC}"
            echo -e "${YELLOW}Advanced tools can be manually installed later if upgraded${NC}"
        fi
    fi

    # Git repository is preserved for updates
    # Use .gitignore to protect runtime data and configurations
    log "INFO" "Git repository preserved for future updates"

            # Apply the Simple Guide: Increase ZRAM Swap instructions before reboot prompt
            configure_zram_swap

    log "SUCCESS" "ragnar installation completed!"
    log "INFO" "Please reboot your system to apply all changes."
    echo -e "\n${GREEN}Installation completed successfully!${NC}"
    echo -e "${YELLOW}Important notes:${NC}"
    echo "1. If configuring Windows PC for USB gadget connection:"
    echo "   - Set static IP: 172.20.2.2"
    echo "   - Subnet Mask: 255.255.255.0"
    echo "   - Default Gateway: 172.20.2.1"
    echo "   - DNS Servers: 8.8.8.8, 8.8.4.4"
    echo "2. Web interface will be available at: http://[device-ip]:8000"
    if [ "$SERVER_INSTALL" != true ]; then
        echo "3. Make sure your e-Paper HAT (2.13-inch) is properly connected"
    fi
    echo -e "\n${BLUE}To update ragnar in the future:${NC}"
    echo "   cd /home/ragnar/Ragnar"
    echo "   sudo git stash  # Save any local changes"
    echo "   sudo git pull   # Get latest updates"
    echo "   sudo systemctl restart ragnar"

    read -p "Would you like to reboot now? (y/n): " reboot_now
    if [ "$reboot_now" = "y" ]; then
        if reboot; then
            log "INFO" "System reboot initiated."
        else
            log "ERROR" "Failed to initiate reboot."
            exit 1
        fi
    else
        echo -e "${YELLOW}Reboot your system to apply all changes & run ragnar service.${NC}"
    fi
}

main
