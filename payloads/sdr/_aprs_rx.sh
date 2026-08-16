#!/bin/bash
CFG=$(mktemp)
echo "ADEVICE stdin null" > "$CFG"
echo "CHANNEL 0" >> "$CFG"
echo "MODEM 1200" >> "$CFG"
exec rtl_fm -f 144.8M -s 22050 -g 20 - 2>/dev/null | direwolf -c "$CFG" -r 22050 -t 0 -b 16 - 2>&1
