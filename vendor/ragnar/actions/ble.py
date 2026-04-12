#!/usr/bin/env python3
"""
Bluetooth Low Energy (BLE) and Classic Bluetooth Management Module for Ragnar
Handles all Bluetooth operations including scanning, pairing, and device management
"""

import subprocess
import re
import time
import logging
from typing import Dict, List, Optional, Tuple, Any
import json
import os
import platform
import sys

# Required attributes for Ragnar action framework
b_class = "BLE"
b_status = "bluetooth_scan"
b_port = None
b_parent = None

class BluetoothManager:
    """
    Comprehensive Bluetooth management class for Ragnar
    Supports both Classic Bluetooth and BLE operations
    Works on both Linux (bluetoothctl) and Windows (PowerShell)
    """
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.scan_active = False
        self.scan_start_time = 0.0
        self.discovered_devices = {}
        self.paired_devices = {}
        self.os_type = platform.system()  # 'Linux', 'Windows', 'Darwin'
        self.logger.info(f"BluetoothManager initialized for {self.os_type}")
        
    def _is_windows(self) -> bool:
        """Check if running on Windows"""
        return self.os_type == 'Windows'
    
    def _is_linux(self) -> bool:
        """Check if running on Linux"""
        return self.os_type == 'Linux'
        
    def check_bluetooth_availability(self) -> Tuple[bool, str]:
        """
        Check if Bluetooth is available on the system
        Returns: (available, message)
        """
        try:
            if self._is_windows():
                # Check Windows Bluetooth availability using PowerShell
                ps_script = """
                $adapters = Get-PnpDevice -Class Bluetooth -Status OK
                if ($adapters) { Write-Output "Available" } else { Write-Output "NotFound" }
                """
                result = subprocess.run(['powershell', '-Command', ps_script], 
                                      capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and 'Available' in result.stdout:
                    return True, "Bluetooth available on Windows"
                else:
                    return False, "No Bluetooth adapters found on Windows"
            else:
                # Linux/Unix method
                result = subprocess.run(['bluetoothctl', '--version'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return True, "Bluetooth available"
                else:
                    return False, "bluetoothctl not found or not working"
        except FileNotFoundError:
            if self._is_windows():
                return False, "PowerShell not found"
            else:
                return False, "bluetoothctl command not found"
        except subprocess.TimeoutExpired:
            return False, "Bluetooth check command timed out"
        except Exception as e:
            return False, f"Error checking Bluetooth: {str(e)}"
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get comprehensive Bluetooth status
        Returns detailed status information
        """
        status = {
            'enabled': False,
            'discoverable': False,
            'pairable': False,
            'scanning': self.scan_active,
            'address': None,
            'name': None,
            'class': None,
            'powered': False,
            'error': None,
            'controller_info': {},
            'os_type': self.os_type
        }
        
        try:
            if self._is_windows():
                # Windows-specific Bluetooth status check
                ps_script = """
                $adapters = Get-PnpDevice -Class Bluetooth -Status OK
                if ($adapters) {
                    $adapter = $adapters | Select-Object -First 1
                    $info = @{
                        Name = $adapter.FriendlyName
                        Status = $adapter.Status
                        InstanceId = $adapter.InstanceId
                    }
                    Write-Output ($info | ConvertTo-Json)
                }
                """
                
                result = subprocess.run(['powershell', '-NoProfile', '-Command', ps_script],
                                      capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and result.stdout.strip():
                    try:
                        adapter_info = json.loads(result.stdout.strip())
                        status['enabled'] = adapter_info.get('Status', '').upper() == 'OK'
                        status['powered'] = status['enabled']
                        status['name'] = adapter_info.get('Name', 'Windows Bluetooth Adapter')
                        status['controller_info'] = adapter_info
                        
                        self.logger.info(f"Windows Bluetooth adapter found: {status['name']}")
                    except json.JSONDecodeError:
                        status['enabled'] = True  # Assume enabled if we got output
                        status['powered'] = True
                else:
                    status['error'] = 'No Bluetooth adapter found on Windows'
                    self.logger.warning("No Bluetooth adapter available on Windows")
                
                # Windows scanning status
                status['scanning'] = self.scan_active
                
            else:
                # Linux/Unix Bluetooth status check
                # Check if Bluetooth controller exists and get detailed info
                result = subprocess.run(['bluetoothctl', 'show'], 
                                      capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    output = result.stdout
                    
                    # Parse detailed controller information
                    status['powered'] = 'Powered: yes' in output
                    status['enabled'] = status['powered']  # For backwards compatibility
                    status['discoverable'] = 'Discoverable: yes' in output
                    status['pairable'] = 'Pairable: yes' in output
                    
                    # Check actual scanning status from bluetoothctl
                    scan_status = self._check_scan_status()
                    if scan_status is not None:
                        status['scanning'] = scan_status
                        self.scan_active = scan_status  # Update internal state
                    
                    # Extract controller details
                    for line in output.split('\n'):
                        line = line.strip()
                        if line.startswith('Controller'):
                            status['address'] = line.split()[1] if len(line.split()) > 1 else None
                        elif line.startswith('Name:'):
                            status['name'] = line.replace('Name:', '').strip()
                        elif line.startswith('Class:'):
                            status['class'] = line.replace('Class:', '').strip()
                        elif line.startswith('Alias:'):
                            status['controller_info']['alias'] = line.replace('Alias:', '').strip()
                        elif line.startswith('Modalias:'):
                            status['controller_info']['modalias'] = line.replace('Modalias:', '').strip()
                            
                else:
                    status['error'] = 'No Bluetooth controller found'
                    self.logger.warning("No Bluetooth controller available")
                    
        except subprocess.TimeoutExpired:
            status['error'] = 'Bluetooth status check timed out'
            self.logger.error("Bluetooth status check timed out")
        except Exception as e:
            status['error'] = f'Error checking Bluetooth status: {str(e)}'
            self.logger.error(f"Error checking Bluetooth status: {e}")
        
        return status
    
    def _check_scan_status(self) -> Optional[bool]:
        """
        Check if scanning is actually active by checking bluetoothctl status
        Returns: True if scanning, False if not scanning, None if unable to determine
        """
        try:
            result = subprocess.run(['bluetoothctl', 'show'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                output = result.stdout.lower()
                if 'discovering: yes' in output:
                    return True
                elif 'discovering: no' in output:
                    return False
        except Exception:
            pass
        return None
    
    def power_on(self) -> Tuple[bool, str]:
        """
        Enable/Power on Bluetooth
        Returns: (success, message)
        """
        try:
            self.logger.info("Enabling Bluetooth...")
            result = subprocess.run(['bluetoothctl', 'power', 'on'], 
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                # Wait a moment for Bluetooth to stabilize
                time.sleep(2)
                
                # Verify it's actually enabled
                status = self.get_status()
                if status['enabled']:
                    self.logger.info("Bluetooth enabled successfully")
                    return True, "Bluetooth enabled successfully"
                else:
                    self.logger.warning("Bluetooth command succeeded but device not powered")
                    return False, "Bluetooth power on command succeeded but device not enabled"
            else:
                error_msg = result.stderr.strip() or 'Failed to enable Bluetooth'
                self.logger.error(f"Failed to enable Bluetooth: {error_msg}")
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            self.logger.error("Bluetooth enable command timed out")
            return False, "Enable Bluetooth command timed out"
        except Exception as e:
            self.logger.error(f"Error enabling Bluetooth: {e}")
            return False, f"Error enabling Bluetooth: {str(e)}"
    
    def power_off(self) -> Tuple[bool, str]:
        """
        Disable/Power off Bluetooth
        Returns: (success, message)
        """
        try:
            self.logger.info("Disabling Bluetooth...")
            
            # Stop scanning if active
            if self.scan_active:
                self.stop_scan()
            
            result = subprocess.run(['bluetoothctl', 'power', 'off'], 
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                self.logger.info("Bluetooth disabled successfully")
                return True, "Bluetooth disabled successfully"
            else:
                error_msg = result.stderr.strip() or 'Failed to disable Bluetooth'
                self.logger.error(f"Failed to disable Bluetooth: {error_msg}")
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            self.logger.error("Bluetooth disable command timed out")
            return False, "Disable Bluetooth command timed out"
        except Exception as e:
            self.logger.error(f"Error disabling Bluetooth: {e}")
            return False, f"Error disabling Bluetooth: {str(e)}"
    
    def set_discoverable(self, discoverable: bool) -> Tuple[bool, str]:
        """
        Set Bluetooth discoverable mode
        Args:
            discoverable: True to make discoverable, False to hide
        Returns: (success, message)
        """
        try:
            mode = 'on' if discoverable else 'off'
            action = 'discoverable' if discoverable else 'hidden'
            
            self.logger.info(f"Setting Bluetooth {action}...")
            result = subprocess.run(['bluetoothctl', 'discoverable', mode], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                message = f"Bluetooth is now {action}"
                self.logger.info(message)
                return True, message
            else:
                error_msg = result.stderr.strip() or f'Failed to make Bluetooth {action}'
                self.logger.error(f"Failed to set discoverable mode: {error_msg}")
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            return False, "Discoverable command timed out"
        except Exception as e:
            self.logger.error(f"Error setting discoverable mode: {e}")
            return False, f"Error setting discoverable mode: {str(e)}"
    
    def start_scan(self, duration: Optional[int] = None) -> Tuple[bool, str]:
        """
        Start Bluetooth device discovery scan
        Args:
            duration: Optional scan duration in seconds
        Returns: (success, message)
        """
        try:
            self.logger.info("Starting Bluetooth device scan...")
            
            if self._is_windows():
                # On Windows, scanning is done via get_discovered_devices
                # Just mark scanning as active
                self.scan_active = True
                self.scan_start_time = time.time()
                
                message = "Bluetooth device scan started (Windows mode)"
                if duration:
                    message += f" (will run for {duration} seconds)"
                message += ". Scanning for nearby Bluetooth devices..."
                
                self.logger.info("Windows Bluetooth scan initiated - devices will be discovered on demand")
                return True, message
            
            # Linux-specific scanning code
            # Ensure Bluetooth is powered on first
            status = self.get_status()
            if not status['enabled']:
                power_success, power_msg = self.power_on()
                if not power_success:
                    return False, f"Cannot start scan: {power_msg}"
            
            # Try multiple methods to start scanning
            methods_tried = []
            scan_started = False
            
            # Method 1: Standard bluetoothctl scan on
            try:
                result = subprocess.run(
                    ['bluetoothctl', 'scan', 'on'],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                methods_tried.append(f"bluetoothctl scan on: rc={result.returncode}")
                self.logger.info(
                    f"Method 1 - bluetoothctl scan on: returncode={result.returncode}, "
                    f"stdout='{result.stdout.strip()}', stderr='{result.stderr.strip()}'"
                )

                if result.returncode == 0:
                    # Treat a successful command as good enough; some stacks
                    # don't immediately report Discovering: yes via bluetoothctl show.
                    scan_started = True
                    methods_tried.append("scan command succeeded (no discovering check)")

                    # Still try to read discovering state for diagnostics only.
                    try:
                        time.sleep(2)
                        actual_scan_status = self._check_scan_status()
                        methods_tried.append(f"discovering={actual_scan_status}")
                    except Exception as e2:
                        methods_tried.append(f"discovering check failed: {e2}")
            except Exception as e:
                methods_tried.append(f"bluetoothctl scan on failed: {e}")
            
            # Method 2: If first method didn't work, try hcitool lescan (if available)
            if not scan_started:
                try:
                    result = subprocess.run(['timeout', '1', 'hcitool', 'lescan'], 
                                          capture_output=True, text=True, timeout=3)
                    methods_tried.append(f"hcitool lescan: rc={result.returncode}")
                    if result.returncode in [0, 124]:  # 124 is timeout exit code
                        scan_started = True
                        methods_tried.append("hcitool lescan working")
                except Exception as e:
                    methods_tried.append(f"hcitool lescan failed: {e}")
            
            # Method 3: Try using bluetoothctl interactively
            if not scan_started:
                try:
                    # Use echo to pipe commands to bluetoothctl
                    result = subprocess.run(['bash', '-c', 'echo "scan on" | bluetoothctl'], 
                                          capture_output=True, text=True, timeout=5)
                    methods_tried.append(f"interactive bluetoothctl: rc={result.returncode}")
                    
                    time.sleep(1)
                    actual_scan_status = self._check_scan_status()
                    if actual_scan_status is True:
                        scan_started = True
                        methods_tried.append("interactive method working")
                except Exception as e:
                    methods_tried.append(f"interactive method failed: {e}")
            
            # Update state and prepare response
            if scan_started:
                self.scan_active = True
                self.scan_start_time = time.time()
                
                message = "Bluetooth device scan started"
                if duration:
                    message += f" (will run for {duration} seconds)"
                message += ". Make sure nearby devices are in discoverable mode."
                
                self.logger.info(f"Scan started successfully. Methods tried: {', '.join(methods_tried)}")
                return True, message
            else:
                self.scan_active = False
                error_msg = f"Failed to start Bluetooth scan. Methods tried: {', '.join(methods_tried)}"
                self.logger.error(error_msg)
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            return False, "Scan start command timed out"
        except Exception as e:
            self.logger.error(f"Error starting Bluetooth scan: {e}")
            return False, f"Error starting scan: {str(e)}"
    
    def stop_scan(self) -> Tuple[bool, str]:
        """
        Stop Bluetooth device discovery scan
        Returns: (success, message)
        """
        try:
            self.logger.info("Stopping Bluetooth device scan...")
            
            if self._is_windows():
                # On Windows, just mark scanning as inactive
                self.scan_active = False
                self.logger.info("Bluetooth scan stopped (Windows mode)")
                return True, "Bluetooth scan stopped successfully"
            
            # Linux method
            result = subprocess.run(['bluetoothctl', 'scan', 'off'], 
                                  capture_output=True, text=True, timeout=10)
            
            # bluetoothctl scan off sometimes returns non-zero even when successful
            success_indicators = [
                'success', 'Discovery stopped', 'Discovering: no', 
                'discovery stopped', 'stopped discovery'
            ]
            output_text = (result.stdout + result.stderr).lower()
            
            # Check for success indicators or determine if scan actually stopped
            scan_actually_stopped = False
            if result.returncode == 0:
                scan_actually_stopped = True
            elif any(indicator.lower() in output_text for indicator in success_indicators):
                scan_actually_stopped = True
            elif 'not available' not in output_text and 'failed' not in output_text and 'error' not in output_text:
                # If no clear error indicators, assume success
                scan_actually_stopped = True
            
            if scan_actually_stopped:
                self.scan_active = False
                self.logger.info("Bluetooth scan stopped successfully")
                return True, "Bluetooth scan stopped successfully"
            else:
                # Even if command failed, mark scan as inactive for safety
                self.scan_active = False
                error_msg = result.stderr.strip() or result.stdout.strip() or 'Failed to stop Bluetooth scan'
                self.logger.warning(f"Scan stop command may have failed, but marking as stopped: {error_msg}")
                return False, f"Scan stop completed with warning: {error_msg}"
                
        except subprocess.TimeoutExpired:
            # Mark scan as inactive even on timeout
            self.scan_active = False
            return False, "Scan stop command timed out"
        except Exception as e:
            # Mark scan as inactive even on error
            self.scan_active = False
            self.logger.error(f"Error stopping Bluetooth scan: {e}")
            return False, f"Error stopping scan: {str(e)}"
    
    def get_discovered_devices(self, refresh: bool = True) -> Dict[str, Dict[str, Any]]:
        """
        Get list of discovered Bluetooth devices
        Args:
            refresh: Whether to refresh device information
        Returns: Dictionary of devices keyed by MAC address
        """
        devices = {}
        
        try:
            if self._is_windows():
                # Windows-specific device discovery using PowerShell
                devices = self._get_windows_bluetooth_devices()
                self.logger.info(f"Windows Bluetooth scan found {len(devices)} devices")
            else:
                # Linux method
                # If scanning is active, use scan results method which captures real-time discoveries
                if self.scan_active or self._check_scan_status():
                    self.logger.info("Scanning is active, getting scan results...")
                    scan_devices = self._get_scan_results()
                    if scan_devices:
                        # Enrich device names with detailed info from bluetoothctl
                        self.logger.info(f"Enriching {len(scan_devices)} discovered devices with detailed info...")
                        scan_devices = self._enrich_device_names(scan_devices)
                        devices.update(scan_devices)
                        self.logger.info(f"Found {len(scan_devices)} devices from active scan")
                
                # Also check for cached/paired devices from bluetoothctl devices
                result = subprocess.run(['bluetoothctl', 'devices'], 
                                      capture_output=True, text=True, timeout=10)
                
                self.logger.info(f"bluetoothctl devices returned: returncode={result.returncode}, stdout='{result.stdout.strip()}', stderr='{result.stderr.strip()}'")
                
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        line = line.strip()
                        self.logger.debug(f"Processing device line: '{line}'")
                        if line and line.startswith('Device '):
                            parts = line.split(None, 2)
                            if len(parts) >= 2:
                                address = parts[1]
                                name = parts[2] if len(parts) > 2 else 'Unknown Device'
                                
                                # Only add if not already in devices (scan results take priority)
                                if address not in devices:
                                    self.logger.info(f"Found cached device: {address} - {name}")
                                    
                                    device_info = {
                                        'address': address,
                                        'name': name,
                                        'rssi': None,
                                        'device_class': None,
                                        'device_type': 'Cached',
                                        'services': [],
                                        'paired': False,
                                        'connected': False,
                                        'trusted': False,
                                        'last_seen': time.time()
                                    }
                                    
                                    # Get detailed device information if requested
                                    if refresh:
                                        detailed_info = self._get_device_details(address)
                                        device_info.update(detailed_info)
                                    
                                    devices[address] = device_info
                else:
                    self.logger.warning(f"bluetoothctl devices failed with return code {result.returncode}")
                            
            self.discovered_devices = devices
            self.logger.info(f"Total devices found: {len(devices)}")
            
        except subprocess.TimeoutExpired:
            self.logger.error("Device list command timed out")
        except Exception as e:
            self.logger.error(f"Error getting device list: {e}")
        
        return devices
    
    def _get_windows_bluetooth_devices(self) -> Dict[str, Dict[str, Any]]:
        """
        Get Bluetooth devices on Windows using PowerShell
        Returns: Dictionary of devices
        """
        devices = {}
        
        try:
            # PowerShell script to discover Bluetooth devices
            ps_script = """
            Add-Type -AssemblyName System.Runtime.WindowsRuntime
            $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
            
            Function Await($WinRtTask, $ResultType) {
                $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
                $netTask = $asTask.Invoke($null, @($WinRtTask))
                $netTask.Wait(-1) | Out-Null
                $netTask.Result
            }
            
            [Windows.Devices.Enumeration.DeviceInformation,Windows.Devices.Enumeration,ContentType=WindowsRuntime] | Out-Null
            [Windows.Devices.Bluetooth.BluetoothDevice,Windows.Devices.Bluetooth,ContentType=WindowsRuntime] | Out-Null
            
            $deviceSelector = [Windows.Devices.Bluetooth.BluetoothDevice]::GetDeviceSelector()
            $deviceWatcher = [Windows.Devices.Enumeration.DeviceInformation]::FindAllAsync($deviceSelector)
            $devices = Await $deviceWatcher ([Windows.Devices.Enumeration.DeviceInformationCollection])
            
            foreach ($device in $devices) {
                $output = @{
                    Id = $device.Id
                    Name = $device.Name
                    IsPaired = $device.Pairing.IsPaired
                    IsEnabled = $device.IsEnabled
                }
                Write-Output ($output | ConvertTo-Json -Compress)
            }
            """
            
            result = subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
                                  capture_output=True, text=True, timeout=30)
            
            self.logger.info(f"Windows PowerShell BLE scan: returncode={result.returncode}")
            self.logger.debug(f"PowerShell stdout: {result.stdout}")
            self.logger.debug(f"PowerShell stderr: {result.stderr}")
            
            if result.returncode == 0 and result.stdout.strip():
                # Parse JSON output from PowerShell
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if line.startswith('{'):
                        try:
                            device_data = json.loads(line)
                            device_id = device_data.get('Id', '')
                            
                            # Extract MAC address from device ID if possible
                            # Formats: 
                            # BluetoothLE#BluetoothLE<mac>-<id>
                            # Bluetooth#Bluetooth<mac>-<id>
                            mac_match = re.search(r'Bluetooth(?:LE)?#Bluetooth(?:LE)?([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', device_id)
                            if not mac_match:
                                mac_match = re.search(r'Bluetooth(?:LE)?([0-9a-fA-F]{12})', device_id)
                            
                            if mac_match:
                                mac_raw = mac_match.group(1).replace(':', '')
                                # Format as MAC address
                                address = ':'.join([mac_raw[i:i+2] for i in range(0, 12, 2)]).upper()
                            else:
                                # Use device ID as fallback
                                address = device_id
                            
                            device_info = {
                                'address': address,
                                'name': device_data.get('Name', 'Unknown Device'),
                                'rssi': None,
                                'device_class': None,
                                'device_type': 'BLE Device',
                                'services': [],
                                'paired': device_data.get('IsPaired', False),
                                'connected': device_data.get('IsEnabled', False),
                                'trusted': False,
                                'last_seen': time.time(),
                                'windows_device_id': device_id
                            }
                            
                            devices[address] = device_info
                            self.logger.info(f"Found Windows BLE device: {device_info['name']} ({address})")
                            
                        except json.JSONDecodeError as e:
                            self.logger.warning(f"Failed to parse device JSON: {line} - {e}")
                
            else:
                self.logger.warning(f"Windows Bluetooth scan returned no devices or failed")
                if result.stderr:
                    self.logger.warning(f"PowerShell error: {result.stderr}")
                    
        except subprocess.TimeoutExpired:
            self.logger.error("Windows Bluetooth device scan timed out")
        except Exception as e:
            self.logger.error(f"Error getting Windows Bluetooth devices: {e}", exc_info=True)
        
        return devices
    
    def _get_scan_results(self) -> Dict[str, Dict[str, Any]]:
        """
        Try to get devices discovered during active scanning using multiple methods
        This is a workaround since bluetoothctl devices might not show newly discovered devices
        """
        scan_devices = {}
        
        # Method 1: Use bluetoothctl in batch mode with device listing
        try:
            # Start a fresh bluetoothctl session that scans and lists devices
            ps_script = '''
import subprocess
import time
import re

devices = {}

# Start bluetoothctl process
proc = subprocess.Popen(
    ['bluetoothctl'],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1
)

# Send scan on command
proc.stdin.write('scan on\\n')
proc.stdin.flush()

# Wait for devices to appear
time.sleep(3)

# Send devices command
proc.stdin.write('devices\\n')
proc.stdin.flush()
time.sleep(0.5)

# Send exit
proc.stdin.write('exit\\n')
proc.stdin.flush()

# Read output
try:
    output, _ = proc.communicate(timeout=2)
    
    # Parse device lines
    for line in output.split('\\n'):
        line = line.strip()
        if line.startswith('Device '):
            parts = line.split(None, 2)
            if len(parts) >= 2:
                addr = parts[1]
                name = parts[2] if len(parts) > 2 else 'Unknown Device'
                print(f"{addr}|{name}")
except:
    pass

proc.kill()
'''
            
            result = subprocess.run(
                ['python3', '-c', ps_script],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split('\n'):
                    if '|' in line:
                        parts = line.split('|', 1)
                        if len(parts) == 2:
                            address = parts[0].strip()
                            name = parts[1].strip()
                            
                            # Validate MAC address format
                            if re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', address):
                                self.logger.info(f"Found device via Python method: {address} - {name}")
                                
                                device_info = {
                                    'address': address,
                                    'name': name,
                                    'rssi': None,
                                    'device_class': None,
                                    'device_type': 'Bluetooth Device',
                                    'services': [],
                                    'paired': False,
                                    'connected': False,
                                    'trusted': False,
                                    'last_seen': time.time(),
                                    'from_scan': True,
                                    'discovery_method': 'bluetoothctl-interactive'
                                }
                                
                                scan_devices[address] = device_info
        except Exception as e:
            self.logger.debug(f"Python bluetoothctl method failed: {e}")
        
        # Method 2: Try hcitool lescan if available
        if not scan_devices:
            try:
                result = subprocess.run(['timeout', '3', 'hcitool', 'lescan'], 
                                      capture_output=True, text=True, timeout=5)
                
                if result.returncode in [0, 124]:  # 124 is timeout exit code
                    lines = result.stdout.split('\n')
                    for line in lines:
                        line = line.strip()
                        if line and ':' in line and len(line.split()) >= 2:
                            parts = line.split(None, 1)
                            if len(parts) >= 2:
                                address = parts[0]
                                name = parts[1] if len(parts) > 1 else 'Unknown Device'
                                
                                # Basic MAC address validation
                                if len(address.split(':')) == 6:
                                    self.logger.info(f"Found device via hcitool: {address} - {name}")
                                    
                                    device_info = {
                                        'address': address,
                                        'name': name,
                                        'rssi': None,
                                        'device_class': None,
                                        'device_type': 'BLE Device',
                                        'services': [],
                                        'paired': False,
                                        'connected': False,
                                        'trusted': False,
                                        'last_seen': time.time(),
                                        'from_scan': True,
                                        'discovery_method': 'hcitool'
                                    }
                                    
                                    scan_devices[address] = device_info
                                    
            except Exception as e:
                self.logger.debug(f"hcitool lescan failed: {e}")
        
        # Method 3: Try bluetoothctl in batch mode (original method)
        if not scan_devices:
            try:
                # Try running bluetoothctl in batch mode to get scan results
                result = subprocess.run(['timeout', '3', 'bluetoothctl'], 
                                      input='scan on\ndevices\nexit\n',
                                      capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0 or result.returncode == 124:  # 124 is timeout exit code
                    lines = result.stdout.split('\n')
                    for line in lines:
                        line = line.strip()
                        if line and line.startswith('Device '):
                            parts = line.split(None, 2)
                            if len(parts) >= 2:
                                address = parts[1]
                                name = parts[2] if len(parts) > 2 else 'Unknown Device'
                                
                                if address not in scan_devices:  # Don't overwrite hcitool results
                                    self.logger.info(f"Found device via bluetoothctl batch: {address} - {name}")
                                    
                                    device_info = {
                                        'address': address,
                                        'name': name,
                                        'rssi': None,
                                        'device_class': None,
                                        'device_type': 'Unknown',
                                        'services': [],
                                        'paired': False,
                                        'connected': False,
                                        'trusted': False,
                                        'last_seen': time.time(),
                                        'from_scan': True,
                                        'discovery_method': 'bluetoothctl'
                                    }
                                    
                                    scan_devices[address] = device_info
                                    
            except Exception as e:
                self.logger.debug(f"bluetoothctl batch mode failed: {e}")
        
        # Method 4: Check bluetoothctl devices (may show cached devices)
        if not scan_devices:
            try:
                result = subprocess.run(['bluetoothctl', 'devices'],
                                      capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        line = line.strip()
                        if line and line.startswith('Device '):
                            parts = line.split(None, 2)
                            if len(parts) >= 2:
                                address = parts[1]
                                name = parts[2] if len(parts) > 2 else 'Unknown Device'
                                
                                self.logger.info(f"Found device via bluetoothctl devices: {address} - {name}")
                                
                                device_info = {
                                    'address': address,
                                    'name': name,
                                    'rssi': None,
                                    'device_class': None,
                                    'device_type': 'Cached Device',
                                    'services': [],
                                    'paired': False,
                                    'connected': False,
                                    'trusted': False,
                                    'last_seen': time.time(),
                                    'from_scan': False,
                                    'discovery_method': 'bluetoothctl-cached'
                                }
                                
                                scan_devices[address] = device_info
            except Exception as e:
                self.logger.debug(f"bluetoothctl devices check failed: {e}")
            
        return scan_devices
    
    def diagnose_scanning(self) -> Dict[str, Any]:
        """
        Diagnose why Bluetooth scanning might not be finding devices
        Returns diagnostic information
        """
        diagnosis = {
            'bluetooth_available': False,
            'bluetooth_enabled': False,
            'scanning_active': False,
            'controller_info': {},
            'recommendations': [],
            'os_type': self.os_type
        }
        
        try:
            # Check basic availability
            available, msg = self.check_bluetooth_availability()
            diagnosis['bluetooth_available'] = available
            if not available:
                diagnosis['recommendations'].append(f"Bluetooth not available: {msg}")
                return diagnosis
            
            # Check status
            status = self.get_status()
            diagnosis['bluetooth_enabled'] = status.get('enabled', False)
            diagnosis['scanning_active'] = status.get('scanning', False)
            diagnosis['controller_info'] = status.get('controller_info', {})
            
            if not diagnosis['bluetooth_enabled']:
                diagnosis['recommendations'].append("Bluetooth is not enabled. Try enabling it first.")
            
            if not diagnosis['scanning_active']:
                diagnosis['recommendations'].append("Scanning is not active. Start a scan to discover devices.")
            
            # Check for paired devices as a baseline
            paired = self.get_paired_devices()
            diagnosis['paired_device_count'] = len(paired)
            
            if len(paired) == 0:
                diagnosis['recommendations'].append("No paired devices found. This might indicate Bluetooth setup issues.")
            
            # Platform-specific diagnostics
            if self._is_windows():
                diagnosis['recommendations'].append("Running on Windows - using PowerShell Bluetooth APIs")
                diagnosis['recommendations'].append("Make sure devices are in pairing/discoverable mode")
            else:
                # Test basic bluetoothctl functionality (Linux)
                try:
                    result = subprocess.run(['bluetoothctl', 'list'], 
                                          capture_output=True, text=True, timeout=5)
                    diagnosis['controllers_found'] = result.returncode == 0 and len(result.stdout.strip()) > 0
                    if not diagnosis['controllers_found']:
                        diagnosis['recommendations'].append("No Bluetooth controllers found. Check hardware.")
                except Exception:
                    diagnosis['controllers_found'] = False
                    diagnosis['recommendations'].append("Cannot communicate with bluetoothctl. Check installation.")
            
            # Add general recommendations
            if len(diagnosis['recommendations']) == 0 or (diagnosis['bluetooth_enabled'] and diagnosis['bluetooth_available']):
                diagnosis['recommendations'].extend([
                    "Bluetooth appears to be working correctly.",
                    "Make sure nearby devices are in discoverable/pairable mode.",
                    "Try putting a phone or other device in Bluetooth pairing mode.",
                    "Some devices only show up when actively scanning from them."
                ])
            
        except Exception as e:
            diagnosis['error'] = str(e)
            diagnosis['recommendations'].append(f"Error during diagnosis: {e}")
        
        return diagnosis
    
    def _get_device_details(self, address: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific Bluetooth device
        Args:
            address: MAC address of the device
        Returns: Dictionary with detailed device information
        """
        details = {}
        
        try:
            result = subprocess.run(['bluetoothctl', 'info', address], 
                                  capture_output=True, text=True, timeout=8)
            
            if result.returncode == 0:
                info_output = result.stdout
                
                # Parse device information
                for line in info_output.split('\n'):
                    line = line.strip()
                    
                    # Device name
                    if line.startswith('Name:'):
                        details['name'] = line.split(':', 1)[1].strip()
                    
                    # Device alias (friendly name, often more descriptive)
                    elif line.startswith('Alias:'):
                        alias = line.split(':', 1)[1].strip()
                        # Prefer alias over name if available
                        if alias and alias != details.get('name'):
                            details['alias'] = alias
                            # Use alias as the display name if it's more descriptive
                            if 'name' not in details or len(alias) > len(details['name']):
                                details['name'] = alias
                    
                    # RSSI (signal strength)
                    elif line.startswith('RSSI:'):
                        try:
                            details['rssi'] = int(line.split(':')[1].strip())
                        except (ValueError, IndexError):
                            pass
                    
                    # Device class
                    elif line.startswith('Class:'):
                        details['device_class'] = line.split(':', 1)[1].strip()
                    
                    # Device type/icon
                    elif line.startswith('Icon:'):
                        details['device_type'] = line.split(':', 1)[1].strip()
                    
                    # Connection status
                    elif line.startswith('Connected:'):
                        details['connected'] = 'yes' in line.lower()
                    
                    # Pairing status
                    elif line.startswith('Paired:'):
                        details['paired'] = 'yes' in line.lower()
                    
                    # Trust status
                    elif line.startswith('Trusted:'):
                        details['trusted'] = 'yes' in line.lower()
                    
                    # Services (UUIDs)
                    elif line.startswith('UUID:'):
                        if 'services' not in details:
                            details['services'] = []
                        
                        # Extract UUID and service name
                        uuid_part = line.split(':', 1)[1].strip()
                        if '(' in uuid_part and ')' in uuid_part:
                            uuid = uuid_part.split('(')[0].strip()
                            service_name = uuid_part.split('(')[1].replace(')', '').strip()
                            details['services'].append({
                                'uuid': uuid,
                                'name': service_name
                            })
                        else:
                            details['services'].append({
                                'uuid': uuid_part,
                                'name': 'Unknown Service'
                            })
                
        except Exception as e:
            self.logger.warning(f"Error getting device details for {address}: {e}")
        
        return details
    
    def _enrich_device_names(self, devices: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Enrich device information by querying bluetoothctl info for each device
        This gets better names, RSSI, and other details
        Args:
            devices: Dictionary of devices to enrich
        Returns: Enriched devices dictionary
        """
        enriched_devices = devices.copy()
        
        for address, device_info in enriched_devices.items():
            # Skip if we already have a good name (not Unknown/generic)
            current_name = device_info.get('name', '')
            if current_name and current_name not in ['Unknown Device', 'Unknown', '']:
                # Still try to get RSSI and other details if missing
                if device_info.get('rssi') is None:
                    try:
                        details = self._get_device_details(address)
                        # Only update RSSI and other metadata, keep the name if it's good
                        if 'rssi' in details:
                            device_info['rssi'] = details['rssi']
                        if 'device_class' in details and not device_info.get('device_class'):
                            device_info['device_class'] = details['device_class']
                        if 'device_type' in details and not device_info.get('device_type'):
                            device_info['device_type'] = details['device_type']
                        if 'paired' in details:
                            device_info['paired'] = details['paired']
                        if 'connected' in details:
                            device_info['connected'] = details['connected']
                        if 'trusted' in details:
                            device_info['trusted'] = details['trusted']
                        if 'services' in details and details['services']:
                            device_info['services'] = details['services']
                    except Exception as e:
                        self.logger.debug(f"Could not enrich device {address}: {e}")
                continue
            
            # Try to get full device details including proper name
            try:
                self.logger.debug(f"Enriching device info for {address}...")
                details = self._get_device_details(address)
                
                if details:
                    # Update with enriched information
                    if 'name' in details:
                        device_info['name'] = details['name']
                        self.logger.info(f"Enriched name for {address}: {details['name']}")
                    
                    # Update other fields
                    for key in ['rssi', 'device_class', 'device_type', 'paired', 'connected', 'trusted', 'services', 'alias']:
                        if key in details:
                            device_info[key] = details[key]
            except Exception as e:
                self.logger.debug(f"Could not enrich device {address}: {e}")
        
        return enriched_devices
    
    def pair_device(self, address: str) -> Tuple[bool, str]:
        """
        Pair with a Bluetooth device
        Args:
            address: MAC address of the device to pair
        Returns: (success, message)
        """
        try:
            self.logger.info(f"Attempting to pair with device {address}...")
            
            # First check if device is discoverable
            devices = self.get_discovered_devices(refresh=False)
            if address not in devices:
                return False, f"Device {address} not found. Start a scan first."
            
            result = subprocess.run(['bluetoothctl', 'pair', address], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 or 'Pairing successful' in result.stdout:
                self.logger.info(f"Successfully paired with {address}")
                return True, f"Successfully paired with {address}"
            else:
                error_msg = result.stderr.strip() or f'Failed to pair with {address}'
                if 'already paired' in error_msg.lower():
                    return True, f"Device {address} is already paired"
                
                self.logger.error(f"Failed to pair with {address}: {error_msg}")
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            return False, f"Pairing with {address} timed out"
        except Exception as e:
            self.logger.error(f"Error pairing with {address}: {e}")
            return False, f"Error pairing with {address}: {str(e)}"
    
    def unpair_device(self, address: str) -> Tuple[bool, str]:
        """
        Unpair (remove) a Bluetooth device
        Args:
            address: MAC address of the device to unpair
        Returns: (success, message)
        """
        try:
            self.logger.info(f"Removing/unpairing device {address}...")
            result = subprocess.run(['bluetoothctl', 'remove', address], 
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                self.logger.info(f"Successfully removed device {address}")
                return True, f"Successfully removed device {address}"
            else:
                error_msg = result.stderr.strip() or f'Failed to remove device {address}'
                self.logger.error(f"Failed to remove {address}: {error_msg}")
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            return False, f"Remove device {address} command timed out"
        except Exception as e:
            self.logger.error(f"Error removing device {address}: {e}")
            return False, f"Error removing device {address}: {str(e)}"
    
    def connect_device(self, address: str) -> Tuple[bool, str]:
        """
        Connect to a paired Bluetooth device
        Args:
            address: MAC address of the device to connect
        Returns: (success, message)
        """
        try:
            self.logger.info(f"Connecting to device {address}...")
            result = subprocess.run(['bluetoothctl', 'connect', address], 
                                  capture_output=True, text=True, timeout=20)
            
            if result.returncode == 0 or 'Connection successful' in result.stdout:
                self.logger.info(f"Successfully connected to {address}")
                return True, f"Successfully connected to {address}"
            else:
                error_msg = result.stderr.strip() or f'Failed to connect to {address}'
                self.logger.error(f"Failed to connect to {address}: {error_msg}")
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            return False, f"Connection to {address} timed out"
        except Exception as e:
            self.logger.error(f"Error connecting to {address}: {e}")
            return False, f"Error connecting to {address}: {str(e)}"
    
    def disconnect_device(self, address: str) -> Tuple[bool, str]:
        """
        Disconnect from a Bluetooth device
        Args:
            address: MAC address of the device to disconnect
        Returns: (success, message)
        """
        try:
            self.logger.info(f"Disconnecting from device {address}...")
            result = subprocess.run(['bluetoothctl', 'disconnect', address], 
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                self.logger.info(f"Successfully disconnected from {address}")
                return True, f"Successfully disconnected from {address}"
            else:
                error_msg = result.stderr.strip() or f'Failed to disconnect from {address}'
                self.logger.error(f"Failed to disconnect from {address}: {error_msg}")
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            return False, f"Disconnect from {address} timed out"
        except Exception as e:
            self.logger.error(f"Error disconnecting from {address}: {e}")
            return False, f"Error disconnecting from {address}: {str(e)}"
    
    def get_paired_devices(self) -> Dict[str, Dict[str, Any]]:
        """
        Get list of paired Bluetooth devices
        Returns: Dictionary of paired devices keyed by MAC address
        """
        paired_devices = {}
        
        try:
            if self._is_windows():
                # Get paired devices from Windows using the same method but filter for paired
                all_devices = self._get_windows_bluetooth_devices()
                paired_devices = {addr: dev for addr, dev in all_devices.items() if dev.get('paired', False)}
                self.logger.info(f"Found {len(paired_devices)} paired devices on Windows")
                return paired_devices
            
            # Linux method
            result = subprocess.run(['bluetoothctl', 'paired-devices'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.startswith('Device '):
                        parts = line.split(None, 2)
                        if len(parts) >= 2:
                            address = parts[1]
                            name = parts[2] if len(parts) > 2 else 'Unknown Device'
                            
                            # Get detailed info
                            device_info = self._get_device_details(address)
                            device_info.update({
                                'address': address,
                                'name': name,
                                'paired': True
                            })
                            
                            paired_devices[address] = device_info
                            
        except Exception as e:
            self.logger.error(f"Error getting paired devices: {e}")
        
        return paired_devices
    
    def scan_for_time(self, duration: int) -> Dict[str, Dict[str, Any]]:
        """
        Perform a timed Bluetooth scan
        Args:
            duration: Scan duration in seconds
        Returns: Dictionary of discovered devices
        """
        self.logger.info(f"Starting {duration}-second Bluetooth scan...")
        
        if self._is_linux():
            # On Linux/Raspberry Pi, use an interactive approach that captures real-time discoveries
            try:
                devices = self._linux_interactive_scan(duration)
                if devices:
                    self.logger.info(f"Interactive scan found {len(devices)} devices")
                    return devices
            except Exception as e:
                self.logger.warning(f"Interactive scan failed: {e}, falling back to standard method")
        
        # Fallback to standard method
        # Start scan
        success, message = self.start_scan()
        if not success:
            self.logger.error(f"Failed to start scan: {message}")
            return {}
        
        # Wait for specified duration
        time.sleep(duration)
        
        # Get discovered devices
        devices = self.get_discovered_devices()
        
        # Stop scan
        self.stop_scan()
        
        self.logger.info(f"Scan completed. Found {len(devices)} devices.")
        return devices
    
    def _linux_interactive_scan(self, duration: int) -> Dict[str, Dict[str, Any]]:
        """
        Perform an interactive Bluetooth scan on Linux that captures devices in real-time
        This is more reliable than relying on 'bluetoothctl devices' which may not update
        """
        devices = {}
        
        try:
            import threading
            import queue
            
            # Create a queue to collect output
            output_queue = queue.Queue()
            
            # Start bluetoothctl process
            proc = subprocess.Popen(
                ['bluetoothctl'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            # Thread to read output
            def read_output():
                try:
                    for line in proc.stdout:
                        output_queue.put(line)
                except:
                    pass
            
            reader_thread = threading.Thread(target=read_output, daemon=True)
            reader_thread.start()
            
            # Send commands
            self.logger.info("Sending 'power on' to bluetoothctl")
            proc.stdin.write('power on\n')
            proc.stdin.flush()
            time.sleep(1)
            
            self.logger.info("Sending 'scan on' to bluetoothctl")
            proc.stdin.write('scan on\n')
            proc.stdin.flush()
            
            # Monitor output for device discoveries
            start_time = time.time()
            self.logger.info(f"Monitoring for {duration} seconds...")
            
            while time.time() - start_time < duration:
                try:
                    line = output_queue.get(timeout=1)
                    line = line.strip()
                    
                    # Log interesting lines
                    if any(x in line for x in ['Device', 'CHG', 'NEW']):
                        self.logger.debug(f"BT Output: {line}")
                    
                    # Parse device discoveries
                    # Format: "[NEW] Device AA:BB:CC:DD:EE:FF Device Name"
                    # Format: "Device AA:BB:CC:DD:EE:FF Device Name"
                    if 'Device ' in line:
                        # Extract MAC and name
                        match = re.search(r'Device\s+([0-9A-Fa-f:]{17})(?:\s+(.+))?', line)
                        if match:
                            address = match.group(1).upper()
                            name = match.group(2).strip() if match.group(2) else 'Unknown Device'
                            
                            # Filter out empty names
                            if not name or name == 'Device':
                                name = 'Unknown Device'
                            
                            if address not in devices:
                                self.logger.info(f"Discovered: {address} - {name}")
                                
                                devices[address] = {
                                    'address': address,
                                    'name': name,
                                    'rssi': None,
                                    'device_class': None,
                                    'device_type': 'Bluetooth Device',
                                    'services': [],
                                    'paired': False,
                                    'connected': False,
                                    'trusted': False,
                                    'last_seen': time.time(),
                                    'from_scan': True,
                                    'discovery_method': 'interactive-scan'
                                }
                    
                    # Parse RSSI if available
                    # Format: "[CHG] Device AA:BB:CC:DD:EE:FF RSSI: -65"
                    if 'RSSI:' in line:
                        match = re.search(r'Device\s+([0-9A-Fa-f:]{17}).*RSSI:\s*(-?\d+)', line)
                        if match:
                            address = match.group(1).upper()
                            rssi = int(match.group(2))
                            if address in devices:
                                devices[address]['rssi'] = rssi
                                
                except queue.Empty:
                    continue
                except Exception as e:
                    self.logger.debug(f"Error parsing line: {e}")
            
            # Get final device list
            self.logger.info("Requesting final device list...")
            proc.stdin.write('devices\n')
            proc.stdin.flush()
            time.sleep(1)
            
            # Parse any remaining output
            while not output_queue.empty():
                try:
                    line = output_queue.get_nowait().strip()
                    if 'Device ' in line:
                        match = re.search(r'Device\s+([0-9A-Fa-f:]{17})(?:\s+(.+))?', line)
                        if match:
                            address = match.group(1).upper()
                            name = match.group(2).strip() if match.group(2) else 'Unknown Device'
                            
                            if address not in devices:
                                self.logger.info(f"Found in final list: {address} - {name}")
                                devices[address] = {
                                    'address': address,
                                    'name': name,
                                    'rssi': None,
                                    'device_class': None,
                                    'device_type': 'Bluetooth Device',
                                    'services': [],
                                    'paired': False,
                                    'connected': False,
                                    'trusted': False,
                                    'last_seen': time.time(),
                                    'from_scan': True,
                                    'discovery_method': 'interactive-scan'
                                }
                except:
                    break
            
            # Stop scan
            self.logger.info("Sending 'scan off' to bluetoothctl")
            proc.stdin.write('scan off\n')
            proc.stdin.flush()
            time.sleep(0.5)
            
            # Exit bluetoothctl
            proc.stdin.write('exit\n')
            proc.stdin.flush()
            
            # Wait for process to finish
            try:
                proc.wait(timeout=2)
            except:
                proc.kill()
            
            self.logger.info(f"Interactive scan complete: found {len(devices)} devices")
            return devices
            
        except Exception as e:
            self.logger.error(f"Error in interactive scan: {e}", exc_info=True)
            try:
                proc.kill()
            except:
                pass
            return {}
    
    def export_devices_to_json(self, filepath: str) -> bool:
        """
        Export discovered devices to JSON file
        Args:
            filepath: Path to save the JSON file
        Returns: Success status
        """
        try:
            devices = self.get_discovered_devices()
            
            # Convert to serializable format
            export_data = {
                'timestamp': time.time(),
                'scan_duration': time.time() - self.scan_start_time if self.scan_start_time else 0,
                'device_count': len(devices),
                'devices': devices
            }
            
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            self.logger.info(f"Exported {len(devices)} devices to {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting devices to JSON: {e}")
            return False

# Convenience functions for easy usage
def quick_scan(duration: int = 10, logger=None) -> Dict[str, Dict[str, Any]]:
    """
    Perform a quick Bluetooth scan
    Args:
        duration: Scan duration in seconds
        logger: Optional logger instance
    Returns: Dictionary of discovered devices
    """
    bt_manager = BluetoothManager(logger)
    return bt_manager.scan_for_time(duration)

def get_bluetooth_info(logger=None) -> Dict[str, Any]:
    """
    Get basic Bluetooth system information
    Args:
        logger: Optional logger instance
    Returns: Bluetooth status and device information
    """
    bt_manager = BluetoothManager(logger)
    
    available, msg = bt_manager.check_bluetooth_availability()
    if not available:
        return {'available': False, 'error': msg}
    
    status = bt_manager.get_status()
    devices = bt_manager.get_discovered_devices() if status['enabled'] else {}
    paired = bt_manager.get_paired_devices() if status['enabled'] else {}
    
    return {
        'available': True,
        'status': status,
        'discovered_devices': devices,
        'paired_devices': paired,
        'device_counts': {
            'discovered': len(devices),
            'paired': len(paired)
        }
    }


class BLE:
    """
    Ragnar action wrapper for Bluetooth scanning
    This is a standalone action (port=0) that scans for Bluetooth devices
    """
    
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.action_name = "BLE"
        self.port = 0  # Standalone action
        self.b_parent_action = None
        self.logger = logging.getLogger(__name__)
        self.bt_manager = BluetoothManager(self.logger)
    
    def execute(self):
        """
        Execute Bluetooth scan as a standalone action
        Returns 'success' or 'failed'
        """
        try:
            self.logger.info("🔵 Starting Bluetooth scan...")
            
            # Check if Bluetooth is available
            available, msg = self.bt_manager.check_bluetooth_availability()
            if not available:
                self.logger.warning(f"Bluetooth not available: {msg}")
                return 'failed'
            
            # Enable Bluetooth if needed
            status = self.bt_manager.get_status()
            if not status['enabled']:
                success, msg = self.bt_manager.power_on()
                if not success:
                    self.logger.error(f"Failed to enable Bluetooth: {msg}")
                    return 'failed'
            
            # Scan for 30 seconds
            devices = self.bt_manager.scan_for_time(30)
            
            if devices:
                self.logger.info(f"✓ Bluetooth scan found {len(devices)} devices")
                
                # Save results to file
                output_dir = os.path.join('data', 'output', 'bluetooth_devices')
                os.makedirs(output_dir, exist_ok=True)
                
                output_file = os.path.join(output_dir, f'bt_scan_{int(time.time())}.json')
                with open(output_file, 'w') as f:
                    json.dump(devices, f, indent=2)
                
                self.logger.info(f"Saved Bluetooth scan results to {output_file}")
                return 'success'
            else:
                self.logger.info("No Bluetooth devices found")
                return 'failed'
                
        except Exception as e:
            self.logger.error(f"Bluetooth scan failed: {e}")
            return 'failed'


if __name__ == "__main__":
    # Example usage and testing
    import logging
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    print("🔵 Testing Bluetooth Manager")
    print("=" * 40)
    
    # Create Bluetooth manager
    bt = BluetoothManager(logger)
    
    # Check availability
    available, msg = bt.check_bluetooth_availability()
    print(f"Bluetooth Available: {available} - {msg}")
    
    if available:
        # Get status
        status = bt.get_status()
        print(f"Bluetooth Status: {status}")
        
        # Test power on
        if not status['enabled']:
            success, msg = bt.power_on()
            print(f"Power On: {success} - {msg}")
        
        # Quick scan
        print("Starting 10-second scan...")
        devices = bt.scan_for_time(10)
        print(f"Found {len(devices)} devices:")
        
        for addr, device in devices.items():
            print(f"  • {device['name']} ({addr}) - RSSI: {device.get('rssi', 'N/A')}")