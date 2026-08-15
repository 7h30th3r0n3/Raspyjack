#!/usr/bin/env bash
set -euo pipefail

# Build an offline GeoIP database from the ip-location-db project (public domain).
# Downloads IPv4 country ranges and converts to a compact JSON lookup file.
#
# Usage:  ./scripts/build_geoip_db.sh
# Output: payloads/sdr/data/geoip.json  (~1.5 MB)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="$ROOT_DIR/payloads/sdr/data"
OUT_PATH="$DATA_DIR/geoip.json"
CSV_URL="https://raw.githubusercontent.com/sapics/ip-location-db/master/geo-whois-asn-country/geo-whois-asn-country-ipv4.csv"
CSV_PATH="$DATA_DIR/_geoip_tmp.csv"

step() { printf "\e[1;34m[STEP]\e[0m %s\n" "$*"; }
info() { printf "\e[1;32m[INFO]\e[0m %s\n" "$*"; }
fail() { printf "\e[1;31m[FAIL]\e[0m %s\n" "$*"; exit 1; }

mkdir -p "$DATA_DIR"

step "Downloading IP-to-country CSV..."
if command -v wget >/dev/null 2>&1; then
    wget -q --show-progress -O "$CSV_PATH" "$CSV_URL" || fail "Download failed"
elif command -v curl >/dev/null 2>&1; then
    curl -# -L -o "$CSV_PATH" "$CSV_URL" || fail "Download failed"
else
    fail "Neither wget nor curl found"
fi
info "Downloaded $(wc -l < "$CSV_PATH") ranges"

step "Converting to JSON..."
export CSV_PATH OUT_PATH
python3 << 'PYEOF'
import csv, json, os, struct, socket

CSV = os.environ.get("CSV_PATH", "")
OUT = os.environ.get("OUT_PATH", "")
if not CSV or not OUT:
    # fallback
    import sys
    CSV = sys.argv[1] if len(sys.argv) > 1 else ""
    OUT = sys.argv[2] if len(sys.argv) > 2 else ""

def ip2int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]

ranges = []
with open(CSV, newline="") as f:
    for row in csv.reader(f):
        if len(row) >= 3:
            try:
                lo = ip2int(row[0].strip())
                hi = ip2int(row[1].strip())
                cc = row[2].strip().upper()
                if cc and len(cc) == 2:
                    ranges.append([lo, hi, cc])
            except Exception:
                pass

ranges.sort(key=lambda r: r[0])

with open(OUT, "w") as f:
    json.dump(ranges, f)

sz = os.path.getsize(OUT)
print(f"  Ranges: {len(ranges)}")
print(f"  File:   {sz / 1024 / 1024:.1f} MB")
PYEOF

step "Cleaning up..."
rm -f "$CSV_PATH"
info "GeoIP database ready: $OUT_PATH"
