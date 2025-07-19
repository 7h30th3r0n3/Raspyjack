#!/usr/bin/env python3
"""
RaspyJack WiFi Integration Functions
===================================
Integration functions to add WiFi support to RaspyJack's main system

This module provides:
- Interface selection for network tools
- Automatic interface detection
- WiFi-aware network functions
- Seamless eth0/WiFi switching

Usage in raspyjack.py:
    from wifi.raspyjack_integration import get_best_interface, get_interface_ip
    
    interface = get_best_interface()
    ip = get_interface_ip(interface)
"""

import os
import sys
import subprocess
import json
import traceback
import time
from datetime import datetime

# Add WiFi manager to path
sys.path.append('/root/Raspyjack/wifi/')

try:
    from wifi_manager import WiFiManager
    wifi_manager = WiFiManager()
except Exception as e:
    print(f"WiFi manager not available: {e}")
    wifi_manager = None

def get_available_interfaces():
    """Get list of all available network interfaces."""
    interfaces = []
    
    # Always include ethernet if available
    try:
        result = subprocess.run(['ip', 'link', 'show', 'eth0'], 
                              capture_output=True, check=False)
        if result.returncode == 0:
            interfaces.append('eth0')
    except:
        pass
    
    # Add WiFi interfaces
    if wifi_manager:
        interfaces.extend(wifi_manager.wifi_interfaces)
    
    return interfaces

def get_interface_status(interface):
    """Get status of a network interface."""
    try:
        # Check if interface exists and is up
        result = subprocess.run(['ip', 'link', 'show', interface], 
                              capture_output=True, text=True, check=False)
        
        if result.returncode != 0:
            return {"status": "not_found", "ip": None, "connected": False}
        
        is_up = "state UP" in result.stdout
        
        # Get IP address
        ip_result = subprocess.run(['ip', '-4', 'addr', 'show', interface], 
                                 capture_output=True, text=True, check=False)
        
        ip_addr = None
        for line in ip_result.stdout.split('\n'):
            if 'inet ' in line:
                ip_addr = line.split('inet ')[1].split('/')[0]
                break
        
        # For WiFi interfaces, check connection
        connected = False
        if interface.startswith('wlan') and wifi_manager:
            wifi_status = wifi_manager.get_connection_status(interface)
            connected = wifi_status["status"] == "connected"
        elif interface == "eth0" and ip_addr:
            connected = True
        
        return {
            "status": "up" if is_up else "down",
            "ip": ip_addr,
            "connected": connected,
            "interface": interface
        }
        
    except Exception as e:
        return {"status": "error", "ip": None, "connected": False, "error": str(e)}

def get_best_interface(prefer_wifi=False, bypass_checks=False):
    """Get the best available network interface for tools."""
    
    # BYPASS MODE: Skip all smart logic, just return what's actually the default route
    if bypass_checks:
        current_route = get_current_default_route()
        if current_route:
            return current_route.get('interface', 'eth0')
        return 'eth0'
    
    # Check for user-preferred interface first
    user_preference = get_interface_preference("system_preferred")
    if user_preference:
        status = get_interface_status(user_preference)
        if status["connected"] and status["ip"]:
            print(f"Using user-preferred interface: {user_preference}")
            return user_preference
        else:
            print(f"User-preferred {user_preference} not available, removing preference")
            # Clear bad preference
            try:
                import os
                pref_file = "/root/Raspyjack/wifi/interface_preferences.json"
                if os.path.exists(pref_file):
                    os.remove(pref_file)
            except:
                pass
    
    # Check current system default route
    current_route = get_current_default_route()
    if current_route:
        current_iface = current_route.get('interface')
        if current_iface:
            status = get_interface_status(current_iface)
            if status["connected"] and status["ip"]:
                print(f"Using current default route interface: {current_iface}")
                return current_iface
    
    interfaces = get_available_interfaces()
    
    if not interfaces:
        return "eth0"  # Fallback
    
    # Check status of all interfaces
    interface_status = {}
    for iface in interfaces:
        interface_status[iface] = get_interface_status(iface)
    
    # Filter to connected interfaces only
    connected_interfaces = [
        iface for iface, status in interface_status.items() 
        if status["connected"] and status["ip"]
    ]
    
    if not connected_interfaces:
        # No connected interfaces, return first available
        return interfaces[0]
    
    # Priority logic
    if prefer_wifi:
        # Prefer WiFi if requested - prioritize external dongles
        wifi_interfaces = [iface for iface in connected_interfaces if iface.startswith('wlan')]
        if wifi_interfaces:
            # Sort WiFi interfaces to prefer external dongles (wlan1, wlan2) over built-in (wlan0)
            wifi_interfaces.sort(key=lambda x: (x != 'wlan1', x != 'wlan2', x))
            return wifi_interfaces[0]
    
    # Default priority: eth0 > external WiFi dongles > built-in WiFi > others
    priority_order = ['eth0', 'wlan1', 'wlan2', 'wlan3', 'wlan0']
    
    for preferred in priority_order:
        if preferred in connected_interfaces:
            return preferred
    
    # Return first connected interface
    return connected_interfaces[0]

def get_interface_ip(interface):
    """Get IP address of an interface."""
    status = get_interface_status(interface)
    return status.get("ip")

def get_interface_network(interface):
    """Get network range for an interface (for nmap scanning)."""
    try:
        result = subprocess.run([
            'ip', '-4', 'addr', 'show', interface
        ], capture_output=True, text=True, check=False)
        
        for line in result.stdout.split('\n'):
            if 'inet ' in line:
                # Extract CIDR notation (e.g., 192.168.1.100/24)
                cidr = line.split('inet ')[1].split()[0]
                return cidr
        
        return None
    except Exception as e:
        print(f"Error getting network for {interface}: {e}")
        return None

def get_interface_gateway(interface):
    """Get gateway IP for an interface."""
    try:
        result = subprocess.run([
            'ip', 'route', 'show', 'default', 'dev', interface
        ], capture_output=True, text=True, check=False)
        
        for line in result.stdout.split('\n'):
            if 'default via' in line:
                gateway = line.split('default via ')[1].split()[0]
                return gateway
        
        return None
    except Exception as e:
        print(f"Error getting gateway for {interface}: {e}")
        return None

def create_interface_command(base_command, interface, target=None):
    """Create a command with appropriate interface parameters."""
    cmd_parts = base_command.split()
    
    if not cmd_parts:
        return base_command
    
    tool = cmd_parts[0]
    
    # Tool-specific interface handling
    if tool == "nmap":
        # Add interface specification for nmap
        interface_ip = get_interface_ip(interface)
        if interface_ip:
            cmd_parts.extend(["-S", interface_ip, "-e", interface])
        if target is None:
            target = get_interface_network(interface)
            if target:
                cmd_parts.append(target)
    
    elif tool == "arpspoof":
        # Add interface for arpspoof
        if "-i" not in cmd_parts:
            cmd_parts.extend(["-i", interface])
    
    elif tool == "tcpdump":
        # Add interface for tcpdump
        if "-i" not in cmd_parts:
            cmd_parts.extend(["-i", interface])
    
    elif tool in ["iwconfig", "iwlist"]:
        # WiFi tools - add interface if not specified
        if len(cmd_parts) == 1:
            cmd_parts.append(interface)
    
    return " ".join(cmd_parts)

def show_interface_info():
    """Show information about all available interfaces."""
    print("\n" + "="*50)
    print("RaspyJack Network Interface Status")
    print("="*50)
    
    interfaces = get_available_interfaces()
    
    if not interfaces:
        print("No network interfaces found!")
        return
    
    for interface in interfaces:
        status = get_interface_status(interface)
        
        print(f"\n📡 {interface}:")
        print(f"   Status: {status['status']}")
        print(f"   Connected: {'✅' if status['connected'] else '❌'}")
        
        if status['ip']:
            print(f"   IP Address: {status['ip']}")
            
            network = get_interface_network(interface)
            if network:
                print(f"   Network: {network}")
            
            gateway = get_interface_gateway(interface)
            if gateway:
                print(f"   Gateway: {gateway}")
        
        # WiFi-specific info
        if interface.startswith('wlan') and wifi_manager:
            wifi_status = wifi_manager.get_connection_status(interface)
            if wifi_status["ssid"]:
                print(f"   WiFi SSID: {wifi_status['ssid']}")
    
    print(f"\n🎯 Best interface: {get_best_interface()}")
    print("="*50)

def setup_tool_interface(tool_name, interface=None):
    """Setup a tool to use a specific interface."""
    if interface is None:
        interface = get_best_interface()
    
    status = get_interface_status(interface)
    if not status["connected"]:
        print(f"Warning: Interface {interface} is not connected!")
        return None
    
    return interface

# Integration functions for specific RaspyJack features
def get_nmap_target_network(interface=None):
    """Get target network for nmap scanning."""
    if interface is None:
        interface = get_best_interface()
    
    network = get_interface_network(interface)
    if network:
        return network
    
    # Fallback to old method
    try:
        result = subprocess.run([
            'ip', '-4', 'addr', 'show', interface
        ], capture_output=True, text=True, check=False)
        
        for line in result.stdout.split('\n'):
            if 'inet ' in line:
                return line.split()[1]  # Return CIDR notation
    except:
        pass
    
    return None

def get_mitm_interface():
    """Get best interface for MITM attacks."""
    # Prefer WiFi for MITM attacks if available and connected
    return get_best_interface(prefer_wifi=True)

def get_responder_interface():
    """Get interface for Responder service."""
    return get_best_interface()

def get_dns_spoof_ip(interface=None):
    """Get IP address for DNS spoofing."""
    if interface is None:
        interface = get_best_interface()
    
    return get_interface_ip(interface)

# Configuration management
def save_interface_preference(tool, interface):
    """Save interface preference for a tool."""
    config_file = "/root/Raspyjack/wifi/interface_preferences.json"
    
    try:
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = json.load(f)
        else:
            config = {}
        
        config[tool] = {
            "interface": interface,
            "timestamp": datetime.now().isoformat()
        }
        
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
            
        return True
    except Exception as e:
        print(f"Error saving interface preference: {e}")
        return False

def get_interface_preference(tool):
    """Get saved interface preference for a tool."""
    config_file = "/root/Raspyjack/wifi/interface_preferences.json"
    
    try:
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            if tool in config:
                return config[tool]["interface"]
    except Exception as e:
        print(f"Error getting interface preference: {e}")
    
    return None

# ========== SYSTEM ROUTING MANAGEMENT ==========
# These functions actually make the selected interface the default route

def get_current_default_route():
    """Get the current default route information."""
    try:
        result = subprocess.run(['ip', 'route', 'show', 'default'], 
                              capture_output=True, text=True, check=False)
        
        if result.returncode == 0 and result.stdout.strip():
            # Parse: default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.100 metric 100
            parts = result.stdout.strip().split()
            route_info = {}
            
            for i, part in enumerate(parts):
                if part == "via" and i + 1 < len(parts):
                    route_info["gateway"] = parts[i + 1]
                elif part == "dev" and i + 1 < len(parts):
                    route_info["interface"] = parts[i + 1]
                elif part == "metric" and i + 1 < len(parts):
                    route_info["metric"] = int(parts[i + 1])
                elif part == "src" and i + 1 < len(parts):
                    route_info["src"] = parts[i + 1]
            
            return route_info
        
        return None
    except Exception as e:
        print(f"Error getting current default route: {e}")
        return None

def backup_routing_config():
    """Backup current routing configuration."""
    backup_file = "/root/Raspyjack/wifi/routing_backup.json"
    
    try:
        # Get all routes
        all_routes = subprocess.run(['ip', 'route', 'show'], 
                                  capture_output=True, text=True, check=False)
        
        # Get current default route
        default_route = get_current_default_route()
        
        backup_data = {
            "timestamp": datetime.now().isoformat(),
            "default_route": default_route,
            "all_routes": all_routes.stdout if all_routes.returncode == 0 else "",
            "interfaces": {}
        }
        
        # Backup interface configurations
        for interface in ["eth0", "wlan0", "wlan1", "wlan2"]:
            try:
                iface_info = subprocess.run(['ip', 'addr', 'show', interface], 
                                          capture_output=True, text=True, check=False)
                if iface_info.returncode == 0:
                    backup_data["interfaces"][interface] = iface_info.stdout
            except:
                pass
        
        with open(backup_file, 'w') as f:
            json.dump(backup_data, f, indent=2)
        
        print(f"Routing configuration backed up to {backup_file}")
        return True
        
    except Exception as e:
        print(f"Error backing up routing config: {e}")
        return False

def set_interface_as_default(interface, force=False):
    """Set the specified interface as the system default route."""
    print(f"🔄 Setting {interface} as default route...")
    
    # Check if interface is connected
    status = get_interface_status(interface)
    if not status["connected"] or not status["ip"]:
        print(f"❌ Interface {interface} is not connected or has no IP")
        return False
    
    # Backup current routing if not forced
    if not force:
        backup_routing_config()
    
    try:
        # Get interface gateway
        gateway = get_interface_gateway(interface)
        if not gateway:
            print(f"❌ No gateway found for {interface}")
            return False
        
        # Get current default route
        current_default = get_current_default_route()
        
        # Remove existing default routes (if any)
        if current_default:
            print(f"🗑️  Removing current default route via {current_default.get('interface', 'unknown')}")
            subprocess.run(['ip', 'route', 'del', 'default'], 
                         capture_output=True, check=False)
        
        # Add new default route
        print(f"➕ Adding default route via {gateway} dev {interface}")
        result = subprocess.run(['ip', 'route', 'add', 'default', 'via', gateway, 'dev', interface], 
                              capture_output=True, text=True, check=False)
        
        if result.returncode != 0:
            print(f"❌ Failed to set default route: {result.stderr}")
            return False
        
        # Verify the change
        new_default = get_current_default_route()
        if new_default and new_default.get("interface") == interface:
            print(f"✅ Successfully set {interface} as default route")
            print(f"   Gateway: {gateway}")
            print(f"   Source IP: {status['ip']}")
            
            # Update DNS if needed
            update_dns_for_interface(interface)
            
            return True
        else:
            print(f"❌ Failed to verify default route change")
            return False
            
    except Exception as e:
        print(f"❌ Error setting default route: {e}")
        return False

def update_dns_for_interface(interface):
    """Update DNS configuration to use the interface's DNS servers."""
    try:
        print(f"🌐 Updating DNS for {interface}...")
        
        # Get DNS servers from DHCP lease or network manager
        dns_servers = []
        
        # Try to get DNS from systemd-resolved
        try:
            resolved_result = subprocess.run(['systemd-resolve', '--status', interface], 
                                           capture_output=True, text=True, check=False)
            if resolved_result.returncode == 0:
                for line in resolved_result.stdout.split('\n'):
                    if 'DNS Servers:' in line:
                        dns_servers.extend(line.split(':')[1].strip().split())
        except:
            pass
        
        # Fallback: use interface gateway as DNS
        if not dns_servers:
            gateway = get_interface_gateway(interface)
            if gateway:
                dns_servers = [gateway, "8.8.8.8", "8.8.4.4"]  # Gateway + Google DNS
        
        if dns_servers:
            # Update /etc/resolv.conf
            resolv_content = "# Generated by RaspyJack WiFi Integration\n"
            for dns in dns_servers:
                resolv_content += f"nameserver {dns}\n"
            
            with open('/etc/resolv.conf', 'w') as f:
                f.write(resolv_content)
            
            print(f"✅ DNS updated with servers: {', '.join(dns_servers)}")
            return True
        
    except Exception as e:
        print(f"❌ Error updating DNS: {e}")
    
    return False

def restore_routing_from_backup():
    """Restore routing configuration from backup."""
    backup_file = "/root/Raspyjack/wifi/routing_backup.json"
    
    if not os.path.exists(backup_file):
        print("❌ No routing backup found")
        return False
    
    try:
        with open(backup_file, 'r') as f:
            backup_data = json.load(f)
        
        default_route = backup_data.get("default_route")
        if not default_route:
            print("❌ No default route in backup")
            return False
        
        print(f"🔄 Restoring default route to {default_route.get('interface')}...")
        
        # Remove current default route
        subprocess.run(['ip', 'route', 'del', 'default'], 
                     capture_output=True, check=False)
        
        # Restore original default route
        cmd = ['ip', 'route', 'add', 'default', 'via', default_route['gateway'], 
               'dev', default_route['interface']]
        
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        
        if result.returncode == 0:
            print(f"✅ Successfully restored default route")
            return True
        else:
            print(f"❌ Failed to restore default route: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Error restoring routing: {e}")
        return False

def set_interface_priority(interface, priority=100):
    """Set routing metric/priority for an interface (lower = higher priority)."""
    try:
        # Get current route for interface
        result = subprocess.run(['ip', 'route', 'show', 'dev', interface], 
                              capture_output=True, text=True, check=False)
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'default' in line:
                    # Remove existing default route for this interface
                    subprocess.run(['ip', 'route', 'del', 'default', 'dev', interface], 
                                 capture_output=True, check=False)
                    
                    # Add with new metric
                    gateway = get_interface_gateway(interface)
                    if gateway:
                        subprocess.run(['ip', 'route', 'add', 'default', 'via', gateway, 
                                      'dev', interface, 'metric', str(priority)], 
                                     capture_output=True, check=False)
                        print(f"✅ Set {interface} priority to {priority}")
                        return True
        
    except Exception as e:
        print(f"❌ Error setting interface priority: {e}")
    
    return False

def force_interface_as_default(interface):
    """FORCE interface as default route with immediate effect - no bullshit."""
    print(f"🚀 FORCE switching to {interface}...")
    
    try:
        # STEP 1: Verify interface exists and has IP
        print(f"🔍 Step 1: Checking {interface}...")
        ip_result = subprocess.run(['ip', 'addr', 'show', interface], 
                                 capture_output=True, text=True, timeout=2)
        
        if ip_result.returncode != 0:
            print(f"❌ Interface {interface} not found")
            print(f"   Command output: {ip_result.stderr}")
            return False
        
        # Extract IP
        interface_ip = None
        for line in ip_result.stdout.split('\n'):
            if 'inet ' in line and 'scope global' in line:
                interface_ip = line.split('inet ')[1].split('/')[0]
                break
        
        if not interface_ip:
            print(f"❌ No IP on {interface}")
            print(f"   Interface output: {ip_result.stdout}")
            return False
        
        print(f"✅ Interface {interface} has IP: {interface_ip}")
        
        # STEP 2: Get or guess gateway
        print(f"🔍 Step 2: Finding gateway for {interface}...")
        route_result = subprocess.run(['ip', 'route', 'show', 'dev', interface], 
                                    capture_output=True, text=True, timeout=2)
        
        gateway = None
        if route_result.returncode == 0:
            for line in route_result.stdout.split('\n'):
                if 'via' in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == "via" and i + 1 < len(parts):
                            gateway = parts[i + 1]
                            break
                    if gateway:
                        break
        
        if not gateway:
            # Guess gateway based on IP
            ip_parts = interface_ip.split('.')
            gateway = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
            print(f"⚠️  Guessing gateway: {gateway}")
        else:
            print(f"✅ Found gateway: {gateway}")
        
        # STEP 3: Show current route before change
        print(f"🔍 Step 3: Current routing before change...")
        current_route = subprocess.run(['ip', 'route', 'show', 'default'], 
                                     capture_output=True, text=True, timeout=2)
        if current_route.returncode == 0:
            print(f"   Current default: {current_route.stdout.strip()}")
        
        # STEP 4: FORCE remove ALL default routes
        print(f"🗑️  Step 4: Removing all default routes...")
        remove_result = subprocess.run(['ip', 'route', 'del', 'default'], 
                                     capture_output=True, text=True, check=False)
        print(f"   Remove result: return_code={remove_result.returncode}")
        if remove_result.stderr:
            print(f"   Remove stderr: {remove_result.stderr}")
        
        # Verify removal
        verify_remove = subprocess.run(['ip', 'route', 'show', 'default'], 
                                     capture_output=True, text=True, timeout=2)
        if verify_remove.returncode == 0 and verify_remove.stdout.strip():
            print(f"⚠️  Still have default route after removal: {verify_remove.stdout.strip()}")
        else:
            print(f"✅ Successfully removed default routes")
        
        # STEP 5: Add new default route
        print(f"➕ Step 5: Adding new default route...")
        add_cmd = ['ip', 'route', 'add', 'default', 'via', gateway, 'dev', interface, 'metric', '100']
        print(f"   Command: {' '.join(add_cmd)}")
        
        add_result = subprocess.run(add_cmd, capture_output=True, text=True, timeout=3)
        print(f"   Add result: return_code={add_result.returncode}")
        
        if add_result.returncode != 0:
            print(f"❌ Failed to add route")
            print(f"   Add stdout: {add_result.stdout}")
            print(f"   Add stderr: {add_result.stderr}")
            return False
        
        # STEP 6: VERIFY the route was actually added
        print(f"🔍 Step 6: Verifying new route...")
        verify_result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                     capture_output=True, text=True, timeout=2)
        
        if verify_result.returncode == 0:
            new_route = verify_result.stdout.strip()
            print(f"   New default route: {new_route}")
            
            # Check if our interface is in the new route
            if interface in new_route:
                print(f"✅ VERIFIED: {interface} is now the default route!")
            else:
                print(f"❌ VERIFICATION FAILED: {interface} not in new route")
                print(f"   Expected: {interface}")
                print(f"   Actual: {new_route}")
                return False
        else:
            print(f"❌ Could not verify new route")
            return False
        
        # STEP 7: Update DNS immediately  
        print(f"🌐 Step 7: Updating DNS...")
        try:
            with open('/etc/resolv.conf', 'w') as f:
                f.write(f"# RaspyJack forced DNS for {interface} - {datetime.now()}\n")
                f.write(f"nameserver {gateway}\n")
                f.write("nameserver 8.8.8.8\n")
                f.write("nameserver 8.8.4.4\n")
            print(f"✅ DNS updated")
        except Exception as dns_error:
            print(f"⚠️  DNS update failed: {dns_error}")
        
        print(f"🎉 SUCCESS: {interface} is now the system default!")
        print(f"   Interface: {interface}")
        print(f"   IP: {interface_ip}")
        print(f"   Gateway: {gateway}")
        
        return True
            
    except Exception as e:
        print(f"❌ Force switch error: {e}")
        import traceback
        print(f"   Full traceback: {traceback.format_exc()}")
        return False

def ensure_interface_default(interface):
    """Ensure the specified interface is the active default route for all traffic."""
    print(f"\n🎯 Ensuring {interface} is the system default interface...")
    
    # Quick status check
    try:
        status_result = subprocess.run(['ip', 'addr', 'show', interface], 
                                     capture_output=True, text=True, timeout=1)
        if status_result.returncode != 0 or 'state UP' not in status_result.stdout:
            print(f"❌ Interface {interface} is not up")
            return False
    except:
        print(f"❌ Interface {interface} check failed")
        return False
    
    # Check current default route
    current_default = get_current_default_route()
    
    if current_default and current_default.get("interface") == interface:
        print(f"✅ {interface} is already the default route")
        # Still save preference
        save_interface_preference("system_preferred", interface)
        return True
    
    # FORCE set as default route
    success = force_interface_as_default(interface)
    
    if success:
        # Quick connectivity test
        print("🔍 Quick connectivity test...")
        test_result = subprocess.run(['ping', '-c', '1', '-W', '2', '8.8.8.8'], 
                                   capture_output=True, check=False)
        
        if test_result.returncode == 0:
            print(f"✅ Internet connectivity confirmed via {interface}")
        else:
            print(f"⚠️  Route set, connectivity test failed (may still work)")
        
        # Save this as the preferred interface
        save_interface_preference("system_preferred", interface)
        return True
    
    return False

def show_routing_status():
    """Show detailed routing and interface status."""
    print("\n" + "="*60)
    print("🌐 SYSTEM ROUTING STATUS")
    print("="*60)
    
    # Current default route
    default_route = get_current_default_route()
    if default_route:
        print(f"🎯 Default Route:")
        print(f"   Interface: {default_route.get('interface', 'unknown')}")
        print(f"   Gateway: {default_route.get('gateway', 'unknown')}")
        print(f"   Metric: {default_route.get('metric', 'unknown')}")
    else:
        print("❌ No default route found!")
    
    print(f"\n📡 Interface Status:")
    interfaces = get_available_interfaces()
    
    for interface in interfaces:
        status = get_interface_status(interface)
        
        symbol = "🟢" if status["connected"] else "🔴"
        print(f"   {symbol} {interface}: {status['status']}")
        
        if status["ip"]:
            print(f"      IP: {status['ip']}")
            gateway = get_interface_gateway(interface)
            if gateway:
                print(f"      Gateway: {gateway}")
    
    # DNS status
    print(f"\n🌐 DNS Configuration:")
    try:
        with open('/etc/resolv.conf', 'r') as f:
            dns_content = f.read()
            for line in dns_content.split('\n'):
                if line.startswith('nameserver'):
                    print(f"   {line}")
    except:
        print("   Unable to read DNS config")
    
    print("="*60)

# Enhanced interface selection with routing control
def select_and_activate_interface(interface=None, interactive=False):
    """Select an interface and make it the active default route."""
    if interface is None:
        if interactive:
            # Show available interfaces and let user choose
            interfaces = get_available_interfaces()
            print("\n📡 Available interfaces:")
            for i, iface in enumerate(interfaces):
                status = get_interface_status(iface)
                status_icon = "🟢" if status["connected"] else "🔴"
                print(f"   {i+1}. {status_icon} {iface} ({status['ip'] or 'No IP'})")
            
            try:
                choice = int(input("\nSelect interface (number): ")) - 1
                if 0 <= choice < len(interfaces):
                    interface = interfaces[choice]
                else:
                    print("❌ Invalid selection")
                    return False
            except:
                print("❌ Invalid input")
                return False
        else:
            interface = get_best_interface()
    
    print(f"\n🚀 Activating {interface} as primary interface...")
    
    # Ensure it becomes the default route
    success = ensure_interface_default(interface)
    
    if success:
        # Save as preferred interface for RaspyJack
        save_interface_preference("system_preferred", interface)
        print(f"\n✅ {interface} is now the primary network interface!")
        print("   All network traffic will use this interface.")
        print("   RaspyJack will remember this preference.")
        return True
    else:
        print(f"\n❌ Failed to activate {interface}")
        return False

def auto_connect_to_same_network(target_interface, source_interface="wlan0", lcd_callback=None):
    """PROFILE-BASED: Auto-connect target interface using WiFi profiles."""
    def lcd_update(msg):
        """Send short message to LCD if callback provided."""
        if lcd_callback:
            lcd_callback(msg)
    
    print(f"🔗 PROFILE-BASED AUTO-CONNECT: {target_interface} using WiFi profiles...")
    lcd_update("Loading profiles...")
    
    try:
        # STEP 1: Get source interface's current SSID
        print(f"🔍 STEP 1: Getting {source_interface} current SSID...")
        lcd_update("Getting SSID...")
        iwconfig_result = subprocess.run(['iwconfig', source_interface], 
                                       capture_output=True, text=True, timeout=5)
        
        if iwconfig_result.returncode != 0:
            print(f"❌ iwconfig failed for {source_interface}: {iwconfig_result.stderr}")
            print(f"🔄 FALLBACK: Trying to find any available WiFi profile...")
            lcd_update("Fallback mode...")
            return auto_connect_any_available_profile(target_interface, lcd_callback)
        
        current_ssid = None
        for line in iwconfig_result.stdout.split('\n'):
            if 'ESSID:' in line:
                # Extract SSID more precisely - handle quoted values properly
                essid_part = line.split('ESSID:')[1].strip()
                
                if essid_part.startswith('"'):
                    # Find the closing quote for the ESSID
                    end_quote = essid_part.find('"', 1)  # Find next quote after opening
                    if end_quote > 0:
                        current_ssid = essid_part[1:end_quote]  # Extract between quotes
                    else:
                        # Fallback: just take everything after first quote until space
                        current_ssid = essid_part[1:].split()[0].rstrip('"')
                else:
                    # No quotes, take first word
                    current_ssid = essid_part.split()[0]
                
                # Final validation
                if current_ssid and current_ssid != 'off/any' and current_ssid != '':
                    print(f"✅ Extracted SSID: '{current_ssid}' from line: '{line.strip()}'")
                    break
        
        if not current_ssid:
            print(f"❌ Could not determine {source_interface}'s SSID")
            print(f"🔄 FALLBACK: Trying to find any available WiFi profile...")
            lcd_update("No SSID found")
            return auto_connect_any_available_profile(target_interface, lcd_callback)
        
        print(f"✅ {source_interface} connected to SSID: {current_ssid}")
        lcd_update(f"Found {current_ssid[:10]}")
        
        # STEP 2: Load WiFi profiles and find matching SSID
        print(f"🗂️  STEP 2: Loading WiFi profiles for SSID: {current_ssid}")
        profiles_dir = "/root/Raspyjack/wifi/profiles"
        
        if not os.path.exists(profiles_dir):
            print(f"❌ Profiles directory not found: {profiles_dir}")
            print(f"🔄 FALLBACK: Creating example profile and trying generic connection...")
            lcd_update("No profiles dir")
            return create_and_connect_profile(target_interface, current_ssid, lcd_callback)
        
        matching_profile = None
        profile_files = [f for f in os.listdir(profiles_dir) if f.endswith('.json')]
        
        print(f"   Found {len(profile_files)} profile files")
        lcd_update(f"Checking {len(profile_files)} profiles")
        
        for profile_file in profile_files:
            try:
                profile_path = os.path.join(profiles_dir, profile_file)
                with open(profile_path, 'r') as f:
                    profile = json.load(f)
                
                if profile.get('ssid') == current_ssid:
                    matching_profile = profile
                    print(f"✅ Found matching profile: {profile_file}")
                    print(f"   SSID: {profile.get('ssid')}")
                    print(f"   Interface preference: {profile.get('interface', 'auto')}")
                    lcd_update("Profile found!")
                    break
                else:
                    print(f"   {profile_file}: SSID '{profile.get('ssid')}' != '{current_ssid}'")
                    
            except Exception as e:
                print(f"   ❌ Error reading {profile_file}: {e}")
        
        if not matching_profile:
            print(f"❌ No WiFi profile found for SSID: {current_ssid}")
            print(f"🔄 FALLBACK: Trying generic connection without password...")
            lcd_update("No profile match")
            return try_connect_without_profile(target_interface, current_ssid, lcd_callback)
        
        # STEP 3: Use WiFi manager to connect target interface
        print(f"📡 STEP 3: Connecting {target_interface} using WiFi manager...")
        lcd_update("Connecting...")
        
        # Import WiFi manager if available
        try:
            from wifi_manager import WiFiManager
            wifi_mgr = WiFiManager()
            print(f"✅ WiFi manager loaded")
        except Exception as e:
            print(f"❌ Could not load WiFi manager: {e}")
            lcd_update("WiFi mgr failed")
            return False
        
        # Clean up existing connections
        print(f"🧹 Cleaning up {target_interface}...")
        lcd_update("Cleaning up...")
        subprocess.run(['pkill', '-f', f'wpa_supplicant.*{target_interface}'], 
                      capture_output=True, check=False)
        subprocess.run(['dhclient', '-r', target_interface], 
                      capture_output=True, check=False)
        time.sleep(2)
        
        # Bring interface up
        print(f"🔌 Bringing {target_interface} up...")
        lcd_update("Bringing up...")
        up_result = subprocess.run(['ip', 'link', 'set', target_interface, 'up'], 
                                 capture_output=True, text=True, timeout=5)
        if up_result.returncode != 0:
            print(f"❌ Failed to bring {target_interface} up: {up_result.stderr}")
            lcd_update("Interface fail!")
            return False
        
        print(f"✅ {target_interface} is up")
        time.sleep(2)
        
        # Connect using WiFi manager with profile credentials
        print(f"🔐 Connecting with credentials from profile...")
        lcd_update("Using creds...")
        ssid = matching_profile['ssid']
        password = matching_profile['password']
        
        # Use WiFi manager to connect (correct parameter order: ssid, password, interface)
        connection_success = wifi_mgr.connect_to_network(ssid, password, target_interface)
        
        if connection_success:
            print(f"✅ WiFi manager connected {target_interface} to {ssid}")
            lcd_update("WiFi connected!")
            
            # Verify connection
            time.sleep(3)
            
            # Check if we got an IP
            ip_result = subprocess.run(['ip', 'addr', 'show', target_interface], 
                                     capture_output=True, text=True, timeout=5)
            
            if ip_result.returncode == 0 and 'inet ' in ip_result.stdout:
                for line in ip_result.stdout.split('\n'):
                    if 'inet ' in line and 'scope global' in line:
                        interface_ip = line.split('inet ')[1].split('/')[0]
                        print(f"🎉 SUCCESS! {target_interface} got IP: {interface_ip}")
                        lcd_update(f"Got IP: {interface_ip[:8]}")
                        return True
            
            print(f"⚠️  Connected but no IP assigned yet, trying DHCP...")
            lcd_update("Getting DHCP...")
            dhcp_result = subprocess.run(['dhclient', target_interface], 
                                       capture_output=True, text=True, timeout=10)
            time.sleep(3)
            
            # Check IP again
            ip_result = subprocess.run(['ip', 'addr', 'show', target_interface], 
                                     capture_output=True, text=True, timeout=5)
            
            if ip_result.returncode == 0 and 'inet ' in ip_result.stdout:
                for line in ip_result.stdout.split('\n'):
                    if 'inet ' in line and 'scope global' in line:
                        interface_ip = line.split('inet ')[1].split('/')[0]
                        print(f"🎉 SUCCESS! {target_interface} got IP: {interface_ip}")
                        lcd_update(f"IP: {interface_ip[:8]}")
                        return True
            
            print(f"❌ Connected but failed to get IP address")
            lcd_update("No IP received")
            return False
        else:
            print(f"❌ WiFi manager failed to connect {target_interface}")
            lcd_update("Connect failed")
            return False
        
    except Exception as e:
        print(f"❌ Profile-based auto-connect error: {e}")
        import traceback
        print(f"   Traceback: {traceback.format_exc()}")
        lcd_update("Error occurred")
        return False

def auto_connect_any_available_profile(target_interface, lcd_callback=None):
    """FALLBACK: Try to connect to any available WiFi profile."""
    def lcd_update(msg):
        if lcd_callback:
            lcd_callback(msg)
    
    print(f"🔄 FALLBACK: Auto-connecting {target_interface} to any available profile...")
    lcd_update("Trying fallback...")
    
    try:
        from wifi_manager import WiFiManager
        wifi_mgr = WiFiManager()
        
        profiles = wifi_mgr.load_profiles()
        if not profiles:
            print(f"❌ No WiFi profiles available for fallback")
            lcd_update("No profiles!")
            return False
        
        # Try highest priority profile first
        for profile in profiles:
            print(f"🔄 Trying profile: {profile.get('ssid')}")
            lcd_update(f"Try {profile.get('ssid', 'unknown')[:8]}")
            if wifi_mgr.connect_to_network(profile['ssid'], profile['password'], target_interface):
                print(f"✅ Fallback connection successful to {profile.get('ssid')}")
                lcd_update("Fallback OK!")
                return True
        
        print(f"❌ All fallback profiles failed")
        lcd_update("All failed!")
        return False
        
    except Exception as e:
        print(f"❌ Fallback auto-connect error: {e}")
        lcd_update("Fallback error")
        return False

def try_connect_without_profile(target_interface, ssid, lcd_callback=None):
    """Try to connect to an open network without a profile."""
    def lcd_update(msg):
        if lcd_callback:
            lcd_callback(msg)
    
    print(f"🔄 Trying open connection to {ssid} on {target_interface}...")
    lcd_update("Try open WiFi...")
    
    try:
        # Try connecting without password (open network)
        result = subprocess.run(['nmcli', 'device', 'wifi', 'connect', ssid, 'ifname', target_interface], 
                              capture_output=True, text=True, timeout=20)
        
        if result.returncode == 0:
            print(f"✅ Connected to open network {ssid}")
            lcd_update("Open connected!")
            time.sleep(3)
            
            # Check for IP
            ip_result = subprocess.run(['ip', 'addr', 'show', target_interface], 
                                     capture_output=True, text=True, timeout=5)
            
            if 'inet ' in ip_result.stdout:
                print(f"✅ Got IP on {target_interface}")
                lcd_update("Got IP!")
                return True
        
        print(f"❌ Failed to connect to {ssid} without password")
        lcd_update("Open failed")
        return False
        
    except Exception as e:
        print(f"❌ Open connection error: {e}")
        lcd_update("Open error")
        return False

def create_and_connect_profile(target_interface, ssid, lcd_callback=None):
    """Create a basic profile and try to connect."""
    def lcd_update(msg):
        if lcd_callback:
            lcd_callback(msg)
    
    print(f"🔄 Creating basic profile for {ssid} and connecting {target_interface}...")
    lcd_update("Creating profile...")
    
    # This would require user input for password in a real scenario
    # For now, just try as open network
    return try_connect_without_profile(target_interface, ssid, lcd_callback)

def set_raspyjack_interface(interface, lcd_callback=None):
    """Explicitly set which interface RaspyJack tools should use - IMMEDIATE."""
    def lcd_update(msg):
        """Send short message to LCD if callback provided."""
        if lcd_callback:
            lcd_callback(msg)
    
    print(f"🔄 IMMEDIATELY setting RaspyJack to use: {interface}")
    lcd_update(f"Setting {interface}...")
    
    # STEP 1: Check if interface exists
    try:
        print(f"🔍 Step 1: Checking if {interface} exists...")
        lcd_update("Checking iface...")
        check_result = subprocess.run(['ip', 'addr', 'show', interface], 
                                    capture_output=True, text=True, timeout=1)
        
        if check_result.returncode != 0:
            print(f"❌ Interface {interface} does not exist!")
            print(f"   Command output: {check_result.stderr}")
            lcd_update(f"{interface} not found!")
            return False
        
        print(f"✅ Interface {interface} exists")
        
    except Exception as e:
        print(f"❌ Failed to check {interface}: {e}")
        lcd_update("Check failed!")
        return False
    
    # STEP 2: For WiFi interfaces, check if connected and auto-connect if needed
    if interface.startswith('wlan'):
        print(f"🔍 Step 2: Checking {interface} WiFi connection...")
        lcd_update("Checking WiFi...")
        
        # Check if interface is UP and has IP
        interface_up = 'state UP' in check_result.stdout or 'LOWER_UP' in check_result.stdout
        has_ip = 'inet ' in check_result.stdout
        
        print(f"   Interface UP: {interface_up}")
        print(f"   Has IP: {has_ip}")
        
        # For WiFi interfaces, also check if actually connected to WiFi network
        wifi_connected = False
        try:
            iwconfig_result = subprocess.run(['iwconfig', interface], 
                                           capture_output=True, text=True, timeout=3)
            if iwconfig_result.returncode == 0:
                # Check for actual ESSID (not off/any)
                for line in iwconfig_result.stdout.split('\n'):
                    if 'ESSID:' in line:
                        # Extract SSID more precisely - handle quoted values properly
                        essid_part = line.split('ESSID:')[1].strip()
                        
                        current_essid = None
                        if essid_part.startswith('"'):
                            # Find the closing quote for the ESSID
                            end_quote = essid_part.find('"', 1)  # Find next quote after opening
                            if end_quote > 0:
                                current_essid = essid_part[1:end_quote]  # Extract between quotes
                            else:
                                # Fallback: just take everything after first quote until space
                                current_essid = essid_part[1:].split()[0].rstrip('"')
                        else:
                            # No quotes, take first word
                            current_essid = essid_part.split()[0]
                        
                        if current_essid and current_essid != 'off/any' and current_essid != '':
                            wifi_connected = True
                            print(f"   WiFi ESSID: {current_essid}")
                            break
                
                if not wifi_connected:
                    print(f"   WiFi status: No ESSID or off/any")
        except Exception as e:
            print(f"   WiFi check error: {e}")
        
        print(f"   WiFi connected: {wifi_connected}")
        
        # AGGRESSIVE RECONNECT: For WiFi switching, always reconnect if:
        # 1. Interface not UP, OR
        # 2. No IP, OR  
        # 3. Not connected to WiFi network
        needs_reconnect = not interface_up or not has_ip or not wifi_connected
        
        print(f"   Needs reconnect: {needs_reconnect}")
        
        if needs_reconnect:
            print(f"⚠️  {interface} needs reconnection, auto-connecting...")
            lcd_update("Reconnecting...")
            
            # Determine source interface for network info
            if interface == 'wlan0':
                # When switching TO wlan0, use wlan1 as source if available
                source_interface = 'wlan1'
                print(f"   Using {source_interface} as source for network info")
            else:
                # When switching TO wlan1, use wlan0 as source
                source_interface = 'wlan0'
                print(f"   Using {source_interface} as source for network info")
            
            if not auto_connect_to_same_network(interface, source_interface, lcd_callback):
                print(f"❌ Failed to auto-connect {interface}")
                lcd_update("Connect failed!")
                return False
            
            # Re-check after connection
            check_result = subprocess.run(['ip', 'addr', 'show', interface], 
                                        capture_output=True, text=True, timeout=1)
        else:
            print(f"✅ {interface} appears ready, skipping auto-connect")
    
    # STEP 3: Final verification
    print(f"🔍 Step 3: Final verification of {interface}...")
    lcd_update("Verifying...")
    
    if 'state UP' not in check_result.stdout and 'LOWER_UP' not in check_result.stdout:
        print(f"❌ Interface {interface} is not UP!")
        print(f"   Interface state: {check_result.stdout}")
        lcd_update("Not UP!")
        return False
    
    if 'inet ' not in check_result.stdout:
        print(f"❌ Interface {interface} has no IP address!")
        print(f"   Interface output: {check_result.stdout}")
        lcd_update("No IP!")
        return False
    
    # Extract IP for verification
    interface_ip = None
    for line in check_result.stdout.split('\n'):
        if 'inet ' in line and 'scope global' in line:
            interface_ip = line.split('inet ')[1].split('/')[0]
            break
    
    print(f"✅ {interface} ready with IP: {interface_ip}")
    lcd_update("Setting route...")
    
    time.sleep(1)  # Brief pause for stability
    
    # FORCE set system routing to use this interface
    success = force_interface_as_default(interface)
    
    if success:
        # Save as the preferred interface immediately
        save_interface_preference("system_preferred", interface)
        
        print(f"✅ RaspyJack IMMEDIATELY switched to {interface}")
        print(f"   IP: {interface_ip}")
        print(f"   🎯 All nmap scans will use {interface}")
        print(f"   🕸️  All MITM attacks will use {interface}")
        print(f"   📢 All tools will use {interface}")
        
        # Verify the switch actually worked
        verify_route = get_current_default_route()
        if verify_route and verify_route.get('interface') == interface:
            print(f"✅ VERIFIED: System default route is now {interface}")
            lcd_update(f"✅ Now {interface}")
        else:
            print(f"⚠️  Warning: Route may not have changed properly")
            lcd_update("Route warning")
        
        return True
    else:
        print(f"❌ FAILED to switch RaspyJack to {interface}")
        lcd_update("FAILED!")
        return False

def switch_wifi_interface(from_interface, to_interface):
    """Switch from one WiFi interface to another."""
    print(f"🔄 Switching from {from_interface} to {to_interface}")
    
    # Backup current routing
    backup_routing_config()
    
    # Switch to new interface
    success = set_raspyjack_interface(to_interface)
    
    if success:
        print(f"✅ Successfully switched from {from_interface} to {to_interface}")
        return True
    else:
        print(f"❌ Failed to switch from {from_interface} to {to_interface}")
        print("🔄 Attempting to restore original routing...")
        restore_routing_from_backup()
        return False

def get_current_raspyjack_interface():
    """Get the interface currently being used by RaspyJack."""
    # Check user preference first
    preferred = get_interface_preference("system_preferred")
    if preferred:
        status = get_interface_status(preferred)
        if status["connected"] and status["ip"]:
            return preferred
    
    # Fall back to system default route
    current_route = get_current_default_route()
    if current_route:
        return current_route.get('interface', 'unknown')
    
    return 'unknown'

def list_wifi_interfaces_with_status():
    """List all WiFi interfaces with detailed status."""
    interfaces = get_available_interfaces()
    wifi_interfaces = [iface for iface in interfaces if iface.startswith('wlan')]
    
    if not wifi_interfaces:
        print("❌ No WiFi interfaces found")
        return []
    
    current_iface = get_current_raspyjack_interface()
    
    print("\n📡 WiFi Interfaces Status:")
    print("="*40)
    
    interface_list = []
    for iface in wifi_interfaces:
        status = get_interface_status(iface)
        
        current_mark = "👉" if iface == current_iface else "  "
        conn_status = "🟢 UP" if status["connected"] else "🔴 DOWN"
        ip_info = status["ip"] if status["ip"] else "No IP"
        
        print(f"{current_mark} {iface}: {conn_status} - {ip_info}")
        
        interface_list.append({
            'name': iface,
            'connected': status["connected"],
            'ip': status["ip"],
            'current': iface == current_iface
        })
    
    print("="*40)
    return interface_list

# Main function for testing
def main():
    """Test the integration functions."""
    print("RaspyJack WiFi Integration Test")
    print("="*40)
    
    show_interface_info()
    
    print(f"\nTesting tool commands:")
    print(f"Best interface: {get_best_interface()}")
    print(f"Nmap target: {get_nmap_target_network()}")
    print(f"MITM interface: {get_mitm_interface()}")
    print(f"Responder interface: {get_responder_interface()}")
    
    # Show routing status
    show_routing_status()

if __name__ == "__main__":
    main() 