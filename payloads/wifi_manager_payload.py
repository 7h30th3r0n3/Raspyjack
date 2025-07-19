#!/usr/bin/env python3
"""
RaspyJack WiFi Manager Payload
=============================
Launch the WiFi management interface in RaspyJack

BUTTON LAYOUT:
- Automatic launch of WiFi LCD interface
- Full WiFi network management
- Profile creation and connection
- Interface status and configuration

FEATURES:
- Scan and connect to WiFi networks
- Save network profiles with passwords
- Manage multiple WiFi dongles
- Interface selection for tools
- Connection status monitoring

This payload provides complete WiFi management for RaspyJack
while maintaining full ethernet compatibility.
"""

import os
import sys
import subprocess

# Add WiFi system to path
sys.path.append('/root/Raspyjack/wifi/')

def main():
    """Launch the WiFi management interface."""
    try:
        print("🌐 Launching RaspyJack WiFi Manager...")
        print("="*50)
        
        # Check if WiFi system is available
        wifi_interface_path = '/root/Raspyjack/wifi/wifi_lcd_interface.py'
        
        if not os.path.exists(wifi_interface_path):
            print("❌ WiFi management system not found!")
            print("   Please ensure WiFi system is properly installed.")
            return False
        
        print("📱 Starting WiFi LCD interface...")
        print("   Use LCD buttons to navigate:")
        print("   - UP/DOWN: Navigate menus")
        print("   - CENTER: Select/Confirm") 
        print("   - KEY1: Quick connect/disconnect")
        print("   - KEY2: Refresh/Scan")
        print("   - KEY3: Back/Exit")
        print("")
        print("📡 Features available:")
        print("   - Scan for WiFi networks")
        print("   - Save network profiles")
        print("   - Quick connect to saved networks")
        print("   - Interface configuration")
        print("   - Connection status monitoring")
        print("")
        print("🔄 WiFi + Ethernet dual support")
        print("   Both interfaces work simultaneously")
        print("")
        
        # Run the WiFi LCD interface
        result = subprocess.run([
            'python3', wifi_interface_path
        ], capture_output=False)
        
        print(f"\n📋 WiFi manager exited with code: {result.returncode}")
        return result.returncode == 0
        
    except KeyboardInterrupt:
        print("\n⏹️  WiFi manager interrupted by user")
        return True
    except Exception as e:
        print(f"❌ Error launching WiFi manager: {e}")
        return False

if __name__ == "__main__":
    main() 