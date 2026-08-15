#!/bin/bash
# Download CartoDB dark map tiles for offline use
# Zoom levels 0-7 (~170 MB)
# Usage: bash scripts/download_tiles.sh

TILE_DIR="/root/Raspyjack/web/vendor/tiles"
BASE_URL="https://basemaps.cartocdn.com/dark_all"
MAX_ZOOM=7
PARALLEL=10

mkdir -p "$TILE_DIR"

echo "Downloading CartoDB dark tiles (zoom 0-$MAX_ZOOM)..."

for z in $(seq 0 $MAX_ZOOM); do
    max=$((2**z - 1))
    total=$(( (max+1) * (max+1) ))
    echo "Zoom $z: $total tiles..."

    for x in $(seq 0 $max); do
        dir="$TILE_DIR/$z/$x"
        mkdir -p "$dir"

        for y in $(seq 0 $max); do
            file="$dir/$y.png"
            if [ ! -f "$file" ]; then
                echo "$BASE_URL/$z/$x/$y.png" "$file"
            fi
        done
    done
done | xargs -P $PARALLEL -L 2 sh -c 'curl -sL "$0" -o "$1" 2>/dev/null'

# Count results
count=$(find "$TILE_DIR" -name "*.png" | wc -l)
size=$(du -sh "$TILE_DIR" | cut -f1)
echo "Done: $count tiles, $size"
