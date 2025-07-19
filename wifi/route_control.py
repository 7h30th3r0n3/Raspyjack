#!/usr/bin/env python3
"""
RaspyJack Route Control - Command Line Interface
================================================
Command-line tool to demonstrate how interface selection
actually controls system routing.

Usage:
    python3 route_control.py status          # Show current routing
    python3 route_control.py list            # List available interfaces  
    python3 route_control.py switch <iface>  # Switch to interface
    python3 route_control.py restore         # Restore from backup
    python3 route_control.py test <iface>    # Test interface without switching
"""

import sys
import os

# Add required paths
sys.path.append('/root/Raspyjack/wifi/')

try:
    from raspyjack_integration import (
        get_available_interfaces,
        get_interface_status,
        get_current_default_route,
        show_routing_status,
        ensure_interface_default,
        backup_routing_config,
        restore_routing_from_backup,
        select_and_activate_interface
    )
    IMPORTS_OK = True
except Exception as e:
    print(f"❌ Import error: {e}")
    IMPORTS_OK = False

def show_usage():
    """Show usage information."""
    print("RaspyJack Route Control")
    print("="*30)
    print("USAGE:")
    print("  python3 route_control.py status                # Show routing status")
    print("  python3 route_control.py list                  # List interfaces")
    print("  python3 route_control.py switch <interface>    # Switch default route")
    print("  python3 route_control.py restore               # Restore from backup")
    print("  python3 route_control.py test <interface>      # Test interface status")
    print("  python3 route_control.py interactive           # Interactive mode")
    print("")
    print("EXAMPLES:")
    print("  python3 route_control.py switch wlan1          # Make wlan1 default")
    print("  python3 route_control.py switch eth0           # Switch back to ethernet")
    print("  python3 route_control.py test wlan0            # Check wlan0 status")

def cmd_status():
    """Show current routing status."""
    print("📊 Current System Routing Status")
    print("="*40)
    
    current_route = get_current_default_route()
    if current_route:
        print(f"🎯 Default Interface: {current_route.get('interface', 'unknown')}")
        print(f"🌐 Gateway: {current_route.get('gateway', 'unknown')}")
        print(f"📊 Metric: {current_route.get('metric', 'unknown')}")
    else:
        print("❌ No default route found!")
    
    print("\n" + "="*40)
    show_routing_status()

def cmd_list():
    """List available interfaces."""
    print("📡 Available Network Interfaces")
    print("="*35)
    
    interfaces = get_available_interfaces()
    current_route = get_current_default_route()
    current_iface = current_route.get('interface') if current_route else None
    
    for interface in interfaces:
        status = get_interface_status(interface)
        
        # Status symbols
        conn_symbol = "🟢" if status["connected"] else "🔴"
        default_symbol = "⭐" if interface == current_iface else "  "
        
        print(f"{default_symbol} {conn_symbol} {interface}")
        print(f"     Status: {status['status']}")
        
        if status["ip"]:
            print(f"     IP: {status['ip']}")
        else:
            print(f"     IP: Not assigned")
        
        print()

def cmd_switch(interface):
    """Switch to specified interface."""
    print(f"🔄 Switching system default route to {interface}")
    print("="*50)
    
    # Check if interface exists
    available = get_available_interfaces()
    if interface not in available:
        print(f"❌ Interface {interface} not found!")
        print(f"Available interfaces: {', '.join(available)}")
        return False
    
    # Check interface status
    status = get_interface_status(interface)
    if not status["connected"]:
        print(f"❌ Interface {interface} is not connected!")
        print("Connect to a network first, then try again.")
        return False
    
    if not status["ip"]:
        print(f"❌ Interface {interface} has no IP address!")
        return False
    
    print(f"✅ Interface {interface} is ready:")
    print(f"   IP: {status['ip']}")
    print(f"   Status: {status['status']}")
    
    # Perform the switch
    success = ensure_interface_default(interface)
    
    if success:
        print(f"\n🎉 SUCCESS! {interface} is now the system default interface")
        print("🌐 All network traffic will now use this interface")
        
        # Show verification
        print("\n📊 Verification:")
        cmd_status()
        
        return True
    else:
        print(f"\n❌ Failed to switch to {interface}")
        return False

def cmd_restore():
    """Restore routing from backup."""
    print("🔄 Restoring routing configuration from backup...")
    
    success = restore_routing_from_backup()
    
    if success:
        print("✅ Routing configuration restored!")
        print("\n📊 Current status:")
        cmd_status()
    else:
        print("❌ Failed to restore routing configuration")

def cmd_test(interface):
    """Test interface without switching."""
    print(f"🔍 Testing interface {interface}")
    print("="*30)
    
    # Check if interface exists
    available = get_available_interfaces()
    if interface not in available:
        print(f"❌ Interface {interface} not found!")
        print(f"Available interfaces: {', '.join(available)}")
        return
    
    # Get detailed status
    status = get_interface_status(interface)
    
    print(f"📡 Interface: {interface}")
    print(f"🔗 Status: {status['status']}")
    print(f"🌐 Connected: {'Yes' if status['connected'] else 'No'}")
    print(f"📍 IP Address: {status['ip'] or 'None'}")
    
    # Additional info for WiFi
    if interface.startswith('wlan'):
        try:
            from wifi_manager import wifi_manager
            wifi_status = wifi_manager.get_connection_status(interface)
            if wifi_status["ssid"]:
                print(f"📶 WiFi SSID: {wifi_status['ssid']}")
                print(f"💪 Signal: {wifi_status.get('signal', 'Unknown')}")
        except:
            pass
    
    # Test readiness for switching
    print(f"\n🎯 Ready for switching: {'Yes' if status['connected'] and status['ip'] else 'No'}")
    
    if status['connected'] and status['ip']:
        from raspyjack_integration import get_interface_gateway
        gateway = get_interface_gateway(interface)
        if gateway:
            print(f"🌐 Gateway: {gateway}")
            print("✅ This interface can be used as default route")
        else:
            print("⚠️  No gateway found - may have connectivity issues")

def cmd_interactive():
    """Interactive interface selection."""
    print("🎮 Interactive Interface Selection")
    print("="*35)
    
    success = select_and_activate_interface(interactive=True)
    
    if success:
        print("\n🎉 Interface selection completed!")
    else:
        print("\n❌ Interface selection failed or cancelled")

def main():
    """Main function."""
    if not IMPORTS_OK:
        print("❌ Required modules not available")
        print("Make sure you're running from RaspyJack directory")
        return 1
    
    if len(sys.argv) < 2:
        show_usage()
        return 1
    
    command = sys.argv[1].lower()
    
    try:
        if command == "status":
            cmd_status()
            
        elif command == "list":
            cmd_list()
            
        elif command == "switch":
            if len(sys.argv) < 3:
                print("❌ Interface name required")
                print("Usage: route_control.py switch <interface>")
                return 1
            interface = sys.argv[2]
            cmd_switch(interface)
            
        elif command == "restore":
            cmd_restore()
            
        elif command == "test":
            if len(sys.argv) < 3:
                print("❌ Interface name required")
                print("Usage: route_control.py test <interface>")
                return 1
            interface = sys.argv[2]
            cmd_test(interface)
            
        elif command == "interactive":
            cmd_interactive()
            
        else:
            print(f"❌ Unknown command: {command}")
            show_usage()
            return 1
            
    except KeyboardInterrupt:
        print("\n⏹️  Interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main()) 