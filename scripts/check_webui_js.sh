#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v node >/dev/null 2>&1; then
  echo "node is required for JS syntax checks" >&2
  exit 1
fi

FILES=(
  "$ROOT_DIR/web/shared.js"
  "$ROOT_DIR/web/app.js"
  "$ROOT_DIR/web/ide.js"
)

for file in "${FILES[@]}"; do
  if [[ ! -f "$file" ]]; then
    echo "missing file: $file" >&2
    exit 1
  fi
  node --check "$file"
  echo "ok: ${file#$ROOT_DIR/}"
done

echo "WebUI JS syntax checks passed."
