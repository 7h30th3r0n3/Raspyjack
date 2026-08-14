#!/usr/bin/env bash
set -euo pipefail

# Build an offline aircraft database (SQLite) from the OpenSky Network
# public metadata dump.  The resulting DB maps ICAO hex codes to
# registration, aircraft type, operator and country.
#
# Usage:  ./scripts/build_aircraft_db.sh
# Output: payloads/sdr/data/aircraft.db  (~35 MB)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="$ROOT_DIR/payloads/sdr/data"
DB_PATH="$DATA_DIR/aircraft.db"
CSV_URL="https://opensky-network.org/datasets/metadata/aircraftDatabase.csv"
CSV_PATH="$DATA_DIR/_aircraftDatabase.csv"

step() { printf "\e[1;34m[STEP]\e[0m %s\n" "$*"; }
info() { printf "\e[1;32m[INFO]\e[0m %s\n" "$*"; }
warn() { printf "\e[1;33m[WARN]\e[0m %s\n" "$*"; }
fail() { printf "\e[1;31m[FAIL]\e[0m %s\n" "$*"; exit 1; }

mkdir -p "$DATA_DIR"

# ── Download ────────────────────────────────────────────────────────────
step "Downloading OpenSky aircraft database..."
if command -v wget >/dev/null 2>&1; then
    wget -q --show-progress -O "$CSV_PATH" "$CSV_URL" || fail "Download failed"
elif command -v curl >/dev/null 2>&1; then
    curl -# -L -o "$CSV_PATH" "$CSV_URL" || fail "Download failed"
else
    fail "Neither wget nor curl found"
fi
info "Downloaded $(du -h "$CSV_PATH" | cut -f1)"

# ── Build SQLite ────────────────────────────────────────────────────────
step "Building SQLite database..."
export CSV_PATH DB_PATH
python3 << 'PYEOF'
import csv, sqlite3, os, sys

CSV  = os.environ["CSV_PATH"]
DB   = os.environ["DB_PATH"]

WANT = {
    "icao24":       "icao",
    "registration":  "registration",
    "typecode":      "typecode",
    "model":         "type_desc",
    "operator":      "operator",
    "owner":         "operator",      # fallback if operator column missing
    "registered":    "country",
    "operatoricao":  None,            # ignored but used as presence check
}

conn = sqlite3.connect(DB)
conn.execute("DROP TABLE IF EXISTS aircraft")
conn.execute("""
    CREATE TABLE aircraft (
        icao         TEXT PRIMARY KEY,
        registration TEXT,
        typecode     TEXT,
        type_desc    TEXT,
        operator     TEXT,
        country      TEXT
    )
""")

inserted = 0
skipped  = 0

with open(CSV, newline="", encoding="utf-8", errors="replace") as fh:
    reader = csv.reader(fh)
    header = [h.strip().lower() for h in next(reader)]

    # Resolve column indices dynamically from header
    col = {}
    for csv_name, db_field in WANT.items():
        if csv_name in header:
            col[csv_name] = header.index(csv_name)

    icao_idx = col.get("icao24")
    if icao_idx is None:
        print("ERROR: 'icao24' column not found in CSV header", file=sys.stderr)
        print(f"  Header: {header[:10]}...", file=sys.stderr)
        sys.exit(1)

    reg_idx   = col.get("registration")
    tc_idx    = col.get("typecode")
    model_idx = col.get("model")
    op_idx    = col.get("operator", col.get("owner"))
    ctry_idx  = col.get("registered")

    batch = []
    for row in reader:
        if len(row) <= icao_idx:
            skipped += 1
            continue
        icao = row[icao_idx].strip().lower()
        if not icao or len(icao) != 6:
            skipped += 1
            continue

        def g(idx):
            return row[idx].strip() if idx is not None and idx < len(row) else ""

        batch.append((
            icao,
            g(reg_idx),
            g(tc_idx),
            g(model_idx),
            g(op_idx),
            g(ctry_idx),
        ))

        if len(batch) >= 10000:
            conn.executemany(
                "INSERT OR REPLACE INTO aircraft VALUES (?,?,?,?,?,?)", batch
            )
            batch.clear()

    if batch:
        conn.executemany(
            "INSERT OR REPLACE INTO aircraft VALUES (?,?,?,?,?,?)", batch
        )

conn.execute("CREATE INDEX IF NOT EXISTS idx_icao ON aircraft(icao)")
conn.commit()

cur = conn.execute("SELECT count(*) FROM aircraft")
total = cur.fetchone()[0]
conn.close()

db_size = os.path.getsize(DB)
print(f"  Rows inserted: {total}")
print(f"  Rows skipped:  {skipped}")
print(f"  Database size: {db_size / 1024 / 1024:.1f} MB")
PYEOF

# ── Cleanup ─────────────────────────────────────────────────────────────
step "Cleaning up downloaded CSV..."
rm -f "$CSV_PATH"

info "Aircraft database ready: $DB_PATH"
info "Run this script again at any time to update."
