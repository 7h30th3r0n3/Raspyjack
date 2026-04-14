#!/bin/bash

# Ragnar Package Installation Script
# Ensures all required system and Python packages are installed
# Author: Ragnar Team
# Version: 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    local level=$1
    shift
    local message="$*"
    case $level in
        "ERROR") echo -e "${RED}[ERROR] $message${NC}" ;;
        "SUCCESS") echo -e "${GREEN}[SUCCESS] $message${NC}" ;;
        "WARNING") echo -e "${YELLOW}[WARNING] $message${NC}" ;;
        "INFO") echo -e "${BLUE}[INFO] $message${NC}" ;;
        *) echo -e "$message" ;;
    esac
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log "ERROR" "This script must be run as root. Please use 'sudo'"
        exit 1
    fi
}

check_python_package() {
    python3 -c "import $1" 2>/dev/null
    return $?
}

install_system_packages() {
    log "INFO" "Updating package list..."
    apt-get update || {
        log "ERROR" "Failed to update package list"
        return 1
    }
    
    log "INFO" "Installing system packages..."
    
    # Core system packages
    local packages=(
        "python3-pip"
        "wget"
        "lsof"
        "git"
        "sudo"
        "libopenjp2-7"
        "nmap"
        "libopenblas-dev"
        "bluez-tools"
        "bluez"
        "dhcpcd5"
        "bridge-utils"
        "python3-pil"
        "libjpeg-dev"
        "zlib1g-dev"
        "libpng-dev"
        "python3-dev"
        "libffi-dev"
        "libssl-dev"
        "libgpiod-dev"
        "libi2c-dev"
        "build-essential"
        "python3-sqlalchemy"
        "python3-pandas"
        "python3-numpy"
        "hostapd"
        "dnsmasq"
        "network-manager"
        "wireless-tools"
        "iproute2"
        "iputils-ping"
        "rfkill"
        "sqlite3"
    )
    
    # Optional packages
    local optional_packages=(
        "libatlas-base-dev"
    )
    
    # Install required packages
    for package in "${packages[@]}"; do
        log "INFO" "Installing $package..."
        if apt-get install -y "$package"; then
            log "SUCCESS" "Installed $package"
        else
            log "ERROR" "Failed to install $package"
            return 1
        fi
    done
    
    # Install optional packages (don't fail if unavailable)
    for package in "${optional_packages[@]}"; do
        log "INFO" "Attempting to install optional package: $package..."
        if apt-get install -y "$package" 2>/dev/null; then
            log "SUCCESS" "Installed optional package: $package"
        else
            log "WARNING" "Optional package $package not available (this is OK)"
        fi
    done
    
    log "SUCCESS" "System packages installation completed"
}

install_nmap_scripts() {
    log "INFO" "Installing nmap vulnerability scripts..."
    
    local vulners_path="/usr/share/nmap/scripts/vulners.nse"
    if [ ! -f "$vulners_path" ]; then
        log "INFO" "Downloading vulners.nse script..."
        mkdir -p "$(dirname "$vulners_path")"
        if wget -q -O "$vulners_path" "https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse"; then
            chmod 644 "$vulners_path"
            log "SUCCESS" "Installed vulners.nse vulnerability script"
        else
            log "WARNING" "Failed to download vulners.nse script"
        fi
    else
        log "INFO" "vulners.nse script already present"
    fi
    
    # Update nmap script database
    log "INFO" "Updating nmap script database..."
    nmap --script-updatedb
    log "SUCCESS" "Nmap scripts updated"
}

configure_piwheels() {
    log "INFO" "Configuring PiWheels for faster Python package installation..."
    
    local machine_arch
    machine_arch=$(uname -m 2>/dev/null || echo "")
    
    if [[ "$machine_arch" == "armv7l" || "$machine_arch" == "armv6l" || "$machine_arch" == "aarch64" || "$machine_arch" == "arm64" ]]; then
        if [ -z "${PIP_EXTRA_INDEX_URL:-}" ]; then
            export PIP_EXTRA_INDEX_URL="https://www.piwheels.org/simple"
        else
            export PIP_EXTRA_INDEX_URL="$PIP_EXTRA_INDEX_URL https://www.piwheels.org/simple"
        fi
        log "SUCCESS" "Using PiWheels Python package index for ${machine_arch}"
    else
        log "INFO" "Not an ARM architecture, using standard PyPI"
    fi
}

install_python_packages() {
    log "INFO" "Installing Python packages..."
    
    configure_piwheels
    
    # Install RPi.GPIO and spidev
    if ! check_python_package "RPi.GPIO"; then
        log "INFO" "Installing RPi.GPIO and spidev..."
        if ! pip3 install --break-system-packages RPi.GPIO==0.7.1 spidev==3.5; then
            log "WARNING" "Failed to install RPi.GPIO/spidev with version pinning, trying without..."
            pip3 install --break-system-packages RPi.GPIO spidev || log "ERROR" "Failed to install RPi.GPIO/spidev"
        fi
    else
        log "SUCCESS" "RPi.GPIO already installed"
    fi
    
    # Install Pillow
    if ! check_python_package "PIL"; then
        log "INFO" "Installing Pillow..."
        if ! pip3 install --break-system-packages "Pillow>=10.0.0"; then
            log "WARNING" "Pillow pip install failed, using system package python3-pil"
            apt-get install -y python3-pil
        fi
    else
        log "SUCCESS" "Pillow already installed"
    fi
    
    # Install numpy and pandas
    if ! check_python_package "numpy" || ! check_python_package "pandas"; then
        log "INFO" "Installing numpy and pandas (this may take a while)..."
        if ! pip3 install --break-system-packages --retries 5 --timeout 300 "numpy>=1.24.0" "pandas>=2.0.0"; then
            log "WARNING" "Pandas/numpy pip install failed, relying on system packages"
        fi
    else
        log "SUCCESS" "numpy and pandas already installed"
    fi
    
    # Define all required Python packages with their import names
    declare -A packages=(
        ["rich>=13.0.0"]="rich"
        ["netifaces==0.11.0"]="netifaces"
        ["ping3>=4.0.0"]="ping3"
        ["get-mac>=0.9.0"]="getmac"
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
    )
    
    # Install each package individually with retries
    for package in "${!packages[@]}"; do
        import_name="${packages[$package]}"
        if check_python_package "$import_name"; then
            log "SUCCESS" "$package already installed"
        else
            log "INFO" "Installing $package..."
            if ! pip3 install --break-system-packages --retries 3 --timeout 180 "$package"; then
                log "ERROR" "Failed to install $package after retries"
                return 1
            fi
            log "SUCCESS" "Installed $package"
        fi
    done
    
    log "SUCCESS" "Python packages installation completed"
}

install_waveshare_epd() {
    log "INFO" "Installing Waveshare e-Paper library..."
    
    local current_dir=$(pwd)
    cd /tmp
    
    if [ -d "e-Paper" ]; then
        rm -rf e-Paper
    fi
    
    log "INFO" "Cloning Waveshare e-Paper repository..."
    if git clone --depth=1 --filter=blob:none --sparse https://github.com/waveshareteam/e-Paper.git; then
        cd e-Paper
        git sparse-checkout set RaspberryPi_JetsonNano
        cd RaspberryPi_JetsonNano/python
        
        log "INFO" "Installing e-Paper Python package..."
        if pip3 install . --break-system-packages; then
            log "SUCCESS" "Installed Waveshare e-Paper library"
        else
            log "ERROR" "Failed to install Waveshare e-Paper library"
            cd "$current_dir"
            return 1
        fi
    else
        log "ERROR" "Failed to clone Waveshare e-Paper repository"
        cd "$current_dir"
        return 1
    fi
    
    cd "$current_dir"
    log "SUCCESS" "Waveshare e-Paper library installation completed"
}

verify_installation() {
    log "INFO" "Verifying package installation..."
    
    local failed=0
    
    # Check critical Python modules
    local required_modules=("RPi.GPIO" "spidev" "PIL" "numpy" "pandas" "rich" "netifaces" "ping3" "getmac" "paramiko" "smbprotocol" "smb" "pymysql" "sqlalchemy" "nmap" "flask" "flask_socketio" "flask_cors" "psutil")
    
    for module in "${required_modules[@]}"; do
        if check_python_package "$module"; then
            log "SUCCESS" "✓ $module"
        else
            log "ERROR" "✗ $module"
            ((failed++))
        fi
    done
    
    # Check system commands
    local required_commands=("nmap" "nmcli" "hostapd" "dnsmasq" "sqlite3")
    
    for cmd in "${required_commands[@]}"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            log "SUCCESS" "✓ $cmd command available"
        else
            log "ERROR" "✗ $cmd command not found"
            ((failed++))
        fi
    done
    
    if [ $failed -eq 0 ]; then
        log "SUCCESS" "All packages verified successfully!"
        return 0
    else
        log "ERROR" "$failed packages/commands missing or failed to install"
        return 1
    fi
}

main() {
    log "INFO" "Starting Ragnar package installation..."
    
    check_root
    
    install_system_packages || {
        log "ERROR" "System packages installation failed"
        exit 1
    }
    
    install_nmap_scripts || {
        log "WARNING" "Nmap scripts installation had issues"
    }
    
    install_python_packages || {
        log "ERROR" "Python packages installation failed"
        exit 1
    }
    
    install_waveshare_epd || {
        log "WARNING" "Waveshare e-Paper library installation had issues"
    }
    
    verify_installation || {
        log "ERROR" "Package verification failed"
        exit 1
    }
    
    log "SUCCESS" "All packages installed successfully!"
    log "INFO" "You can now proceed with Ragnar installation or service restart"
}

main
