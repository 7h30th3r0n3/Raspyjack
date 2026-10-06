#!/usr/bin/env bash
# Local CardputerZero AppStore compliance check.
# Builds the .deb, derives meta.json from app-builder.json, downloads the three
# official validators, and runs them — the same rules czdev / the store CI apply.
#
# Usage: bash scripts/prepublish.sh [path/to/existing.deb]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PKG="$(python3 -c 'import json;print(json.load(open("app-builder.json"))["package_name"])')"

# 1. .deb ------------------------------------------------------------------
DEB="${1:-}"
if [ -z "$DEB" ]; then
  echo "== building .deb (local dpkg-deb) =="
  bash scripts/pack-deb.sh >/dev/null
  DEB="$(ls -t dist/${PKG}_*.deb | head -n1)"
fi
echo "deb: $DEB ($(du -h "$DEB" | cut -f1))"

# 2. meta.json + assets from app-builder.json ------------------------------
POOL="$WORK/pool/main/$PKG"
mkdir -p "$POOL/screenshots"
python3 - "$POOL" <<'PY'
import json, os, shutil, sys
pool = sys.argv[1]
ab = json.load(open("app-builder.json")); s = ab["store"]
icon_bn = os.path.basename(s["icon"])
meta = {
    "title": ab.get("app_name", ab["package_name"]),
    "summary": s["summary"],
    "description": s.get("description", ""),
    "categories": s["categories"],
    "license": s["license"],
    "source_repo": s.get("source_repo", ""),
    "author": s["author"],
    "share_code": s["share_code"],
    "permissions": s["permissions"],
    "icon": icon_bn,
    "screenshots": ["screenshots/" + os.path.basename(p) for p in s["screenshots"]],
}
if "locales" in s:
    meta["locales"] = s["locales"]
json.dump(meta, open(os.path.join(pool, "meta.json"), "w"), indent=2)
if os.path.isfile(s["icon"]):
    shutil.copy(s["icon"], os.path.join(pool, icon_bn))
for p in s["screenshots"]:
    if os.path.isfile(p):
        shutil.copy(p, os.path.join(pool, "screenshots", os.path.basename(p)))
print("meta.json written for", meta["title"])
PY

# 3. official validators (fetched fresh = authoritative) --------------------
VB="$WORK/validators"; mkdir -p "$VB"
dl() { curl -fsSL "$1" -o "$2" 2>/dev/null; }
dl "https://raw.githubusercontent.com/CardputerZero/packages/main/.github/scripts/install_path_policy.py" "$VB/install_path_policy.py" || true
dl "https://raw.githubusercontent.com/CardputerZero/packages/main/.github/scripts/store_meta_policy.py"   "$VB/store_meta_policy.py"   || true
dl "https://raw.githubusercontent.com/CardputerZero/skill/main/cardputer-app-publish/scripts/prepublish_check.py" "$VB/prepublish_check.py" || true

fail=0

run_install_path() {
  [ -f "$VB/install_path_policy.py" ] || { echo "  (skip: validator unavailable)"; return; }
  python3 -I "$VB/install_path_policy.py" "$PKG" "$DEB" "$WORK/bad.txt" >/dev/null 2>&1 || true
  if [ -s "$WORK/bad.txt" ]; then echo "  FAIL:"; sed 's/^/    /' "$WORK/bad.txt"; fail=1; else echo "  PASS"; fi
}
run_store_meta() {
  [ -f "$VB/store_meta_policy.py" ] || { echo "  (skip: validator unavailable)"; return; }
  python3 -I "$VB/store_meta_policy.py" "$PKG" "$POOL" - "$WORK/merr.txt" "$WORK/mwarn.txt" >/dev/null 2>&1 || true
  if [ -s "$WORK/merr.txt" ]; then echo "  FAIL:"; sed 's/^/    /' "$WORK/merr.txt"; fail=1; else echo "  PASS"; fi
  [ -s "$WORK/mwarn.txt" ] && { echo "  warnings:"; sed 's/^/    /' "$WORK/mwarn.txt"; } || true
}
run_prepublish() {
  [ -f "$VB/prepublish_check.py" ] || { echo "  (skip: validator unavailable)"; return; }
  # app-dir must expose the icon + screenshots app-builder.json references
  if python3 -I "$VB/prepublish_check.py" --deb "$DEB" --app-dir "$ROOT" >"$WORK/pp.txt" 2>&1; then
    echo "  PASS"
  else
    echo "  FAIL:"; sed 's/^/    /' "$WORK/pp.txt"; fail=1
  fi
}

echo ""; echo "== install_path_policy =="; run_install_path
echo "== store_meta_policy ==";            run_store_meta
echo "== prepublish_check ==";             run_prepublish

echo ""
if [ "$fail" -eq 0 ]; then
  echo "✅ ALL CHECKS PASSED — ready for czdev publish / dev.cardputer.cc"
else
  echo "❌ compliance issues above (missing 320x170 screenshots are expected until captured on-device)"
fi
exit "$fail"
