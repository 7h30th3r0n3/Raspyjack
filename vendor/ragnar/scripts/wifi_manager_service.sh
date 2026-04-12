#!/bin/bash
# wifi_manager_service.sh

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
HOSTAPD_CONFIG="/tmp/ragnar/hostapd.conf"
DNSMASQ_CONFIG="/tmp/ragnar/dnsmasq.conf"
INTERFACE="wlan0"
AP_IP="192.168.4.1"

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Start Access Point mode
start_ap() {
    print_status "Starting Wi-Fi Access Point..."
    
    # Check if interface exists
    if ! ip link show "$INTERFACE" &>/dev/null; then
        print_error "Interface $INTERFACE not found"
        return 1
    fi
    
    # Stop NetworkManager management of the interface
    nmcli dev set "$INTERFACE" managed no 2>/dev/null || true
    
    # Configure interface
    print_status "Configuring interface $INTERFACE..."
    ip addr flush dev "$INTERFACE"
    ip addr add "${AP_IP}/24" dev "$INTERFACE"
    ip link set dev "$INTERFACE" up
    
    if [ $? -eq 0 ]; then
        print_success "Interface configured"
    else
        print_error "Failed to configure interface"
        return 1
    fi
    
    # Start hostapd if config exists
    if [ -f "$HOSTAPD_CONFIG" ]; then
        print_status "Starting hostapd..."
        hostapd "$HOSTAPD_CONFIG" -B
        
        if [ $? -eq 0 ]; then
            print_success "hostapd started"
        else
            print_error "Failed to start hostapd"
            cleanup_ap
            return 1
        fi
    else
        print_warning "hostapd config not found at $HOSTAPD_CONFIG"
    fi
    
    # Start dnsmasq if config exists
    if [ -f "$DNSMASQ_CONFIG" ]; then
        print_status "Starting dnsmasq..."
        dnsmasq -C "$DNSMASQ_CONFIG"
        
        if [ $? -eq 0 ]; then
            print_success "dnsmasq started"
        else
            print_error "Failed to start dnsmasq"
            cleanup_ap
            return 1
        fi
    else
        print_warning "dnsmasq config not found at $DNSMASQ_CONFIG"
    fi
    
    # Set up NAT rules
    setup_nat
    
    print_success "Wi-Fi Access Point started successfully"
    print_status "AP Details:"
    print_status "  Interface: $INTERFACE"
    print_status "  IP Address: $AP_IP"
    print_status "  DHCP Range: 192.168.4.2 - 192.168.4.20"
}

# Stop Access Point mode
stop_ap() {
    print_status "Stopping Wi-Fi Access Point..."
    
    # Stop services
    pkill hostapd 2>/dev/null || true
    pkill dnsmasq 2>/dev/null || true
    
    # Clean up interface
    cleanup_ap
    
    print_success "Wi-Fi Access Point stopped"
}

# Cleanup interface configuration
cleanup_ap() {
    print_status "Cleaning up interface configuration..."
    
    # Flush IP address
    ip addr flush dev "$INTERFACE" 2>/dev/null || true
    
    # Return interface to NetworkManager
    nmcli dev set "$INTERFACE" managed yes 2>/dev/null || true
    
    # Clear NAT rules
    cleanup_nat
    
    print_success "Interface cleanup completed"
}

# Set up NAT and forwarding rules
setup_nat() {
    print_status "Setting up NAT rules..."
    
    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # Set up iptables rules for NAT
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o wlan1 -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s 192.168.4.0/24 ! -d 192.168.4.0/24 -j MASQUERADE
    
    iptables -A FORWARD -i "$INTERFACE" -o eth0 -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "$INTERFACE" -o wlan1 -j ACCEPT 2>/dev/null || true
    
    iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    
    print_success "NAT rules configured"
}

# Clean up NAT rules
cleanup_nat() {
    print_status "Cleaning up NAT rules..."
    
    # Remove specific rules (this is a simplified cleanup)
    iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || true
    iptables -t nat -D POSTROUTING -o wlan1 -j MASQUERADE 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s 192.168.4.0/24 ! -d 192.168.4.0/24 -j MASQUERADE 2>/dev/null || true
    
    print_success "NAT rules cleaned up"
}

# Check Wi-Fi connection status
check_connection() {
    print_status "Checking Wi-Fi connection status..."
    
    # Check if connected to a network
    if nmcli -t -f ACTIVE,SSID dev wifi | grep -q '^yes:'; then
        CURRENT_SSID=$(nmcli -t -f ACTIVE,SSID dev wifi | grep '^yes:' | cut -d: -f2)
        print_success "Connected to: $CURRENT_SSID"
        
        # Test internet connectivity
        if ping -c1 8.8.8.8 &>/dev/null; then
            print_success "Internet connectivity: OK"
            return 0
        else
            print_warning "Internet connectivity: FAILED"
            return 1
        fi
    else
        print_warning "Not connected to any Wi-Fi network"
        return 1
    fi
}

# Scan for available networks
scan_networks() {
    print_status "Scanning for Wi-Fi networks..."
    
    # Trigger a fresh scan
    nmcli dev wifi rescan
    sleep 3
    
    # List available networks
    print_status "Available networks:"
    nmcli -t -f SSID,SIGNAL,SECURITY dev wifi | while IFS=: read -r ssid signal security; do
        if [ -n "$ssid" ]; then
            printf "  %-30s Signal: %3s%%  Security: %s\n" "$ssid" "$signal" "$security"
        fi
    done
}

# Connect to a network
connect_network() {
    local ssid="$1"
    local password="$2"
    
    if [ -z "$ssid" ]; then
        print_error "SSID is required"
        echo "Usage: $0 connect <SSID> [password]"
        return 1
    fi
    
    print_status "Connecting to network: $ssid"
    
    if [ -n "$password" ]; then
        nmcli dev wifi connect "$ssid" password "$password"
    else
        nmcli dev wifi connect "$ssid"
    fi
    
    if [ $? -eq 0 ]; then
        print_success "Successfully connected to $ssid"
        # Wait a moment and check connection
        sleep 3
        check_connection
    else
        print_error "Failed to connect to $ssid"
        return 1
    fi
}

# Disconnect from current network
disconnect_network() {
    print_status "Disconnecting from current network..."
    
    # Get current connection
    CONNECTION=$(nmcli -t -f NAME,TYPE con show --active | grep ':802-11-wireless' | cut -d: -f1)
    
    if [ -n "$CONNECTION" ]; then
        nmcli con down "$CONNECTION"
        print_success "Disconnected from $CONNECTION"
    else
        print_warning "No active Wi-Fi connection found"
    fi
}

# Restart networking services
restart_networking() {
    print_status "Restarting networking services..."
    
    # Stop any running AP mode
    stop_ap
    
    # Restart NetworkManager
    systemctl restart NetworkManager
    
    # Wait for service to start
    sleep 5
    
    print_success "Networking services restarted"
}

# Show service status
show_status() {
    print_status "Wi-Fi Service Status:"
    echo
    
    print_status "Interface Status:"
    ip addr show "$INTERFACE" 2>/dev/null || print_warning "Interface $INTERFACE not found"
    echo
    
    print_status "Network Connections:"
    nmcli con show --active
    echo
    
    print_status "Running Processes:"
    pgrep -l hostapd || print_status "hostapd: not running"
    pgrep -l dnsmasq || print_status "dnsmasq: not running"
    echo
    
    print_status "NetworkManager Status:"
    systemctl status NetworkManager --no-pager -l | head -10
}

# Show help
show_help() {
    echo "ragnar Wi-Fi Manager Service Script"
    echo "Usage: $0 <command> [options]"
    echo
    echo "Commands:"
    echo "  start-ap           Start Access Point mode"
    echo "  stop-ap            Stop Access Point mode"
    echo "  check              Check Wi-Fi connection status"
    echo "  scan               Scan for available networks"
    echo "  connect <SSID> [password]  Connect to a network"
    echo "  disconnect         Disconnect from current network"
    echo "  restart            Restart networking services"
    echo "  status             Show service status"
    echo "  help               Show this help message"
    echo
    echo "Examples:"
    echo "  $0 start-ap        # Start AP mode"
    echo "  $0 scan            # Scan for networks"
    echo "  $0 connect MyWiFi password123  # Connect with password"
    echo "  $0 connect OpenWiFi            # Connect to open network"
}

# Main script logic
main() {
    local command="$1"
    shift
    
    case "$command" in
        start-ap)
            check_root
            start_ap
            ;;
        stop-ap)
            check_root
            stop_ap
            ;;
        check)
            check_connection
            ;;
        scan)
            scan_networks
            ;;
        connect)
            connect_network "$1" "$2"
            ;;
        disconnect)
            disconnect_network
            ;;
        restart)
            check_root
            restart_networking
            ;;
        status)
            show_status
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
