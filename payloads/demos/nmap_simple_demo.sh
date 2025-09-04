#!/bin/bash
#
# Title:         Sample Nmap Payload for Shark Jack
# Author:        Hak5
# Version:       1.2
#
# Scans target subnet with Nmap using specified options. Saves each scan result
# to loot storage folder. Includes SERIAL_WRITE commands for Shark Jack Cable.
#
# LED SETUP ... Obtaining IP address from DHCP
# LED ATTACK ... Scanning
# LED FINISH ... Scan Complete
#
# See nmap --help for options. Default "-sP" ping scans the address space for
# fast host discovery.


echo "started payload" > /tmp/payload-debug.log
NMAP_OPTIONS="-sP --host-timeout 30s --max-retries 3"
LOOT_DIR=/root/Raspyjack/loot/Nmap

# Setup loot directory, DHCP client, and determine subnet
SERIAL_WRITE [*] Setting up payload
LED SETUP
mkdir -p $LOOT_DIR
COUNT=$(($(ls -l $LOOT_DIR/*.txt | wc -l)+1))
NETMODE DHCP_CLIENT
SERIAL_WRITE [*] Waiting for IP from DHCP
while [ -z "$SUBNET" ]; do
  sleep 1
  # Try eth0 first, then wlan0
  for IFACE in eth0 wlan0; do
    CIDR=$(ip -o -4 addr show dev "$IFACE" 2>/dev/null | awk '{print $4}')
    if [ -n "$CIDR" ]; then
      SUBNET=$CIDR
      break
    fi
  done
done
echo "Recieved IP address from DHCP" >> /tmp/payload-debug.log


# Scan network
LED ATTACK
SERIAL_WRITE [*] Starting nmap scan...
nmap $NMAP_OPTIONS $SUBNET -oN $LOOT_DIR/nmap-scan_$COUNT.txt
echo "scanned network" >> /tmp/payload-debug.log
LED FINISH
SERIAL_WRITE [*] Payload complete!
sleep 2 && sync