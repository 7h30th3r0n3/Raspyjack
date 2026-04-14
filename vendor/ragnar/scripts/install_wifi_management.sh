#!/bin/bash
# install_wifi_management.sh
# Quick installation script for ragnar Wi-Fi Management System
# Author: GitHub Copilot Assistant

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                    ragnar WI-FI MANAGEMENT                      ║"
    echo "║                    Installation Script                        ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_requirements() {
    print_status "Checking system requirements..."
    
    # Check if running on Raspberry Pi
    if ! grep -q "Raspberry Pi" /proc/cpuinfo 2>/dev/null; then
        print_warning "This system doesn't appear to be a Raspberry Pi"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Check for Wi-Fi interface
    if ! ip link show wlan0 &>/dev/null; then
        print_error "No wlan0 interface found. This system may not have Wi-Fi capability."
        exit 1
    fi
    
    # Check Python version
    if ! python3 --version | grep -q "Python 3\.[89]" && ! python3 --version | grep -q "Python 3\.1[0-9]"; then
        print_warning "Python 3.8+ recommended for best compatibility"
    fi
    
    print_success "System requirements check passed"
}

install_system_packages() {
    print_status "Installing system packages..."
    
    # Update package list
    apt-get update
    
    # Install required packages
    local packages=(
        "hostapd"
        "dnsmasq" 
        "network-manager"
        "wireless-tools"
        "wpasupplicant"
        "python3-pip"
        "git"
    )
    
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            print_status "Installing $package..."
            apt-get install -y "$package"
        else
            print_status "$package already installed"
        fi
    done
    
    print_success "System packages installed"
}

setup_permissions() {
    print_status "Setting up permissions..."
    
    # Make scripts executable
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    chmod +x "$SCRIPT_DIR/ragnar_wifi_setup.sh"
    chmod +x "$SCRIPT_DIR/wifi_manager_service.sh"
    
    # Create ragnar user if it doesn't exist
    if ! id "ragnar" &>/dev/null; then
        print_status "Creating ragnar user..."
        useradd -m -s /bin/bash ragnar
        usermod -a -G sudo,netdev ragnar
    else
        print_status "Adding ragnar user to required groups..."
        usermod -a -G sudo,netdev ragnar
    fi
    
    print_success "Permissions configured"
}

install_python_requirements() {
    print_status "Installing Python requirements..."
    
    # Install from requirements.txt if it exists
    if [ -f "requirements.txt" ]; then
        pip3 install -r requirements.txt
    else
        # Install minimal requirements for Wi-Fi management
        pip3 install flask flask-socketio flask-cors rich
    fi
    
    print_success "Python requirements installed"
}

create_systemd_service() {
    print_status "Creating systemd service..."
    
    # Get the current directory
    ragnar_DIR=$(pwd)
    
    # Create systemd service file
    cat > /etc/systemd/system/ragnar.service << EOF
[Unit]
Description=ragnar IoT Security Tool with Wi-Fi Management
After=network.target
Wants=network.target

[Service]
Type=simple
User=ragnar
Group=ragnar
WorkingDirectory=$ragnar_DIR
ExecStart=/usr/bin/python3 ragnar.py
Restart=always
RestartSec=10
TimeoutStopSec=10
KillMode=mixed
Environment=PYTHONPATH=$ragnar_DIR

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload
    
    print_success "Systemd service created"
}

configure_network() {
    print_status "Configuring network services..."
    
    # Stop and disable conflicting services
    systemctl stop hostapd || true
    systemctl stop dnsmasq || true
    systemctl disable hostapd || true
    systemctl disable dnsmasq || true
    
    # Enable and start NetworkManager
    systemctl enable NetworkManager
    systemctl start NetworkManager
    
    # Create configuration directory
    mkdir -p /etc/ragnar
    chown ragnar:ragnar /etc/ragnar
    
    print_success "Network services configured"
}

setup_web_interface() {
    print_status "Setting up web interface..."
    
    # Ensure web directory exists
    mkdir -p web
    
    # Create symlink for easy access to Wi-Fi config
    if [ ! -f "web/wifi.html" ] && [ -f "web/wifi_config.html" ]; then
        ln -sf wifi_config.html web/wifi.html
    fi
    
    print_success "Web interface configured"
}

final_setup() {
    print_status "Performing final setup..."
    
    # Set ownership of ragnar directory
    chown -R ragnar:ragnar .
    
    # Create log directory
    mkdir -p data/logs
    chown -R ragnar:ragnar data
    
    # Set up sudo permissions for ragnar user to manage networking
    echo "ragnar ALL=(ALL) NOPASSWD: /usr/bin/systemctl start hostapd" >> /etc/sudoers.d/ragnar-wifi
    echo "ragnar ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop hostapd" >> /etc/sudoers.d/ragnar-wifi
    echo "ragnar ALL=(ALL) NOPASSWD: /usr/bin/systemctl start dnsmasq" >> /etc/sudoers.d/ragnar-wifi
    echo "ragnar ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop dnsmasq" >> /etc/sudoers.d/ragnar-wifi
    echo "ragnar ALL=(ALL) NOPASSWD: /usr/bin/hostapd" >> /etc/sudoers.d/ragnar-wifi
    echo "ragnar ALL=(ALL) NOPASSWD: /usr/bin/dnsmasq" >> /etc/sudoers.d/ragnar-wifi
    echo "ragnar ALL=(ALL) NOPASSWD: /usr/bin/pkill hostapd" >> /etc/sudoers.d/ragnar-wifi
    echo "ragnar ALL=(ALL) NOPASSWD: /usr/bin/pkill dnsmasq" >> /etc/sudoers.d/ragnar-wifi
    echo "ragnar ALL=(ALL) NOPASSWD: /usr/bin/ip" >> /etc/sudoers.d/ragnar-wifi
    echo "ragnar ALL=(ALL) NOPASSWD: /usr/bin/iptables" >> /etc/sudoers.d/ragnar-wifi
    echo "ragnar ALL=(ALL) NOPASSWD: /usr/bin/nmcli" >> /etc/sudoers.d/ragnar-wifi
    
    chmod 0440 /etc/sudoers.d/ragnar-wifi
    
    print_success "Final setup completed"
}

show_completion_message() {
    echo
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗"
    echo -e "║                     INSTALLATION COMPLETE!                    ║"
    echo -e "╚════════════════════════════════════════════════════════════════╝${NC}"
    echo
    print_success "ragnar Wi-Fi Management System has been installed successfully!"
    echo
    echo -e "${BLUE}Next Steps:${NC}"
    echo "1. Enable and start the ragnar service:"
    echo "   sudo systemctl enable ragnar"
    echo "   sudo systemctl start ragnar"
    echo
    echo "2. Check service status:"
    echo "   sudo systemctl status ragnar"
    echo
    echo "3. Access the web interface:"
    echo "   http://localhost:5000 (if connected to Wi-Fi)"
    echo "   http://192.168.4.1:5000 (if in AP mode)"
    echo
    echo "4. Monitor logs:"
    echo "   sudo journalctl -u ragnar -f"
    echo
    echo -e "${BLUE}Wi-Fi Management Features:${NC}"
    echo "• Automatic connection to known networks"
    echo "• Fallback to AP mode if no connection"
    echo "• Web-based network configuration"
    echo "• Command-line utilities"
    echo
    echo -e "${BLUE}Utility Commands:${NC}"
    echo "• ./wifi_manager_service.sh status    - Check Wi-Fi status"
    echo "• ./wifi_manager_service.sh scan      - Scan for networks"
    echo "• ./wifi_manager_service.sh start-ap  - Start AP mode"
    echo
    echo -e "${YELLOW}⚠️  Important Notes:${NC}"
    echo "• Reboot recommended to ensure all changes take effect"
    echo "• Default AP credentials: SSID=ragnar-Setup, Password=ragnarpassword"
    echo "• Change default passwords in web interface for security"
    echo "• Review WIFI_MANAGEMENT_GUIDE.md for detailed documentation"
    echo
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root (use sudo)"
    exit 1
fi

# Main installation process
main() {
    print_header
    
    print_status "Starting ragnar Wi-Fi Management installation..."
    
    check_requirements
    install_system_packages
    setup_permissions
    install_python_requirements
    create_systemd_service
    configure_network
    setup_web_interface
    final_setup
    
    show_completion_message
}

# Run main installation
main "$@"
