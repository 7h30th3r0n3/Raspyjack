#!/bin/bash
# Download NOAA APT satellite TLE data for pass prediction
# NOAA-15 (25338), NOAA-18 (28654), NOAA-19 (33591)

TLE_DIR="/root/Raspyjack/payloads/sdr/data"
TLE_FILE="$TLE_DIR/noaa_tle.txt"
BASE="https://celestrak.org/NORAD/elements/gp.php"

mkdir -p "$TLE_DIR"
> "$TLE_FILE.tmp"

echo "Downloading NOAA APT satellite TLE data..."
for ID in 25338 28654 33591; do
    curl -sL "${BASE}?CATNR=${ID}&FORMAT=tle" >> "$TLE_FILE.tmp"
done

lines=$(wc -l < "$TLE_FILE.tmp")
if [ "$lines" -ge 9 ]; then
    mv "$TLE_FILE.tmp" "$TLE_FILE"
    echo "TLE updated: $lines lines — $(date)"
else
    echo "Download failed (got $lines lines), keeping previous TLE"
    rm -f "$TLE_FILE.tmp"
fi
