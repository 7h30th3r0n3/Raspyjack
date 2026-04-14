#!/usr/bin/env python3
import subprocess
import re
import sys
import json
from typing import List, Dict

def check_requirements():
    """Check if required tools are installed"""
    tools = ['nmap', 'arp-scan']
    missing = []
    
    for tool in tools:
        try:
            subprocess.run([tool, '--version'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            missing.append(tool)
    
    if missing:
        print(f"Error: Missing required tools: {', '.join(missing)}")
        print("Install with: sudo apt install nmap arp-scan")
        sys.exit(1)

def run_arp_scan(interface='eth0'):
    """Run ARP scan to discover devices on local network"""
    print(f"[*] Running ARP scan on interface {interface}...")
    
    try:
        # Run arp-scan
        result = subprocess.run(
            ['arp-scan', '--localnet', f'--interface={interface}'],
            capture_output=True,
            text=True,
            check=True
        )
        
        devices = []
        # Parse arp-scan output
        for line in result.stdout.split('\n'):
            # Match lines with IP, MAC, and vendor info
            match = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s+(.*)', line)
            if match:
                devices.append({
                    'ip': match.group(1),
                    'mac': match.group(2),
                    'vendor': match.group(3).strip()
                })
        
        print(f"[+] Found {len(devices)} devices via ARP scan")
        return devices
    
    except subprocess.CalledProcessError as e:
        print(f"Error running arp-scan: {e}")
        print("Note: arp-scan requires root privileges")
        return []
    except FileNotFoundError:
        print("Error: arp-scan not found")
        return []

def run_nmap_scan(ip_address, port_range='1-1000'):
    """Run Nmap scan on specific IP to get hostname and open ports"""
    print(f"[*] Scanning {ip_address} with Nmap...")
    
    try:
        # Run nmap with service detection
        result = subprocess.run(
            ['nmap', '-sV', '-p', port_range, '--open', ip_address],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        output = result.stdout
        
        # Extract hostname
        hostname = 'Unknown'
        hostname_match = re.search(r'Nmap scan report for (.*?) \(', output)
        if hostname_match:
            hostname = hostname_match.group(1)
        else:
            hostname_match = re.search(r'Nmap scan report for (.*)', output)
            if hostname_match:
                hostname = hostname_match.group(1)
        
        # Extract open ports
        ports = []
        port_section = False
        for line in output.split('\n'):
            if 'PORT' in line and 'STATE' in line:
                port_section = True
                continue
            if port_section and line.strip():
                match = re.match(r'(\d+)/(\w+)\s+(\w+)\s+(.*)', line)
                if match:
                    ports.append({
                        'port': match.group(1),
                        'protocol': match.group(2),
                        'state': match.group(3),
                        'service': match.group(4).strip()
                    })
        
        return {
            'hostname': hostname,
            'ports': ports
        }
    
    except subprocess.TimeoutExpired:
        print(f"[!] Nmap scan timed out for {ip_address}")
        return {'hostname': 'Timeout', 'ports': []}
    except Exception as e:
        print(f"[!] Error scanning {ip_address}: {e}")
        return {'hostname': 'Error', 'ports': []}

def scan_network(interface='eth0', port_range='1-1000', quick=False):
    """Main function to scan network"""
    
    # Check if running as root
    if subprocess.run(['id', '-u'], capture_output=True, text=True).stdout.strip() != '0':
        print("Warning: This script should be run with sudo for best results")
    
    check_requirements()
    
    # Run ARP scan
    devices = run_arp_scan(interface)
    
    if not devices:
        print("No devices found. Check your interface name.")
        print("Common interfaces: eth0, wlan0, enp0s3")
        return []
    
    # Scan each device with Nmap
    results = []
    for i, device in enumerate(devices, 1):
        print(f"\n[*] Scanning device {i}/{len(devices)}: {device['ip']}")
        
        if quick:
            # Quick scan - just get hostname
            nmap_data = run_nmap_scan(device['ip'], '80,443,22')
        else:
            # Full scan
            nmap_data = run_nmap_scan(device['ip'], port_range)
        
        results.append({
            'ip': device['ip'],
            'mac': device['mac'],
            'vendor': device['vendor'],
            'hostname': nmap_data['hostname'],
            'open_ports': nmap_data['ports']
        })
    
    return results

def print_results(results):
    """Print scan results in a formatted way"""
    print("\n" + "="*80)
    print("SCAN RESULTS")
    print("="*80)
    
    for device in results:
        print(f"\nIP Address:  {device['ip']}")
        print(f"MAC Address: {device['mac']}")
        print(f"Vendor:      {device['vendor']}")
        print(f"Hostname:    {device['hostname']}")
        
        if device['open_ports']:
            print("Open Ports:")
            for port in device['open_ports']:
                print(f"  - {port['port']}/{port['protocol']}: {port['service']}")
        else:
            print("Open Ports:  None found")
        print("-" * 80)

def save_results(results, filename='scan_results.json'):
    """Save results to JSON file"""
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Results saved to {filename}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Network Scanner using ARP and Nmap')
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface (default: eth0)')
    parser.add_argument('-p', '--ports', default='1-1000', help='Port range to scan (default: 1-1000)')
    parser.add_argument('-q', '--quick', action='store_true', help='Quick scan (only common ports)')
    parser.add_argument('-o', '--output', help='Output JSON file')
    
    args = parser.parse_args()
    
    print("="*80)
    print("NETWORK SCANNER")
    print("="*80)
    print("\nWARNING: Only scan networks you own or have permission to scan!")
    print("Unauthorized scanning may be illegal.\n")
    
    results = scan_network(args.interface, args.ports, args.quick)
    
    if results:
        print_results(results)
        
        if args.output:
            save_results(results, args.output)
    else:
        print("\n[!] No results to display")
