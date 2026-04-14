#!/bin/bash
# Bluetooth scan helper script for Raspberry Pi
# This script runs bluetoothctl interactively and captures device discoveries

SCAN_DURATION=${1:-10}

echo "Starting Bluetooth scan for $SCAN_DURATION seconds..."

# Start bluetoothctl and pipe commands to it
{
    echo "power on"
    sleep 1
    echo "scan on"
    sleep "$SCAN_DURATION"
    echo "devices"
    sleep 1
    echo "scan off"
    sleep 1
    echo "exit"
} | bluetoothctl 2>&1 | grep -E "Device |CHG|NEW" | tee /tmp/bluetooth_scan_output.txt

echo ""
echo "Scan complete. Results saved to /tmp/bluetooth_scan_output.txt"
