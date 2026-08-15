#!/bin/bash
# Download NOAA satellite TLE data for pass prediction
# Usage: bash scripts/update_noaa_tle.sh

TLE_DIR="/root/Raspyjack/payloads/sdr/data"
TLE_FILE="$TLE_DIR/noaa_tle.txt"

mkdir -p "$TLE_DIR"

echo "Downloading NOAA TLE data from CelesTrak..."
curl -sL "https://celestrak.org/NORAD/elements/gp.php?GROUP=noaa&FORMAT=tle" -o "$TLE_FILE.tmp"

if [ -s "$TLE_FILE.tmp" ]; then
    mv "$TLE_FILE.tmp" "$TLE_FILE"
    lines=$(wc -l < "$TLE_FILE")
    echo "TLE updated: $lines lines — $(date)"
else
    echo "Download failed, keeping previous TLE"
    rm -f "$TLE_FILE.tmp"
fi
