#!/bin/bash
# Run from the project root, Git Bash, or WSL.
# Requires Docker with linux/arm64 support.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Building RaspyJack .deb package..."
echo "Project root: $PROJECT_ROOT"
echo ""

if command -v docker >/dev/null 2>&1; then
    echo "Installing Docker binfmt support for arm64..."
    docker run --privileged --rm tonistiigi/binfmt --install arm64
    echo ""

    docker run --rm \
        --platform linux/arm64 \
        -v "$PROJECT_ROOT:/src" \
        -w /src \
        ghcr.io/cardputerzero/build-env:latest \
        bash scripts/pack-deb.sh
else
    echo "Docker not found; using local dpkg-deb build."
    bash "$PROJECT_ROOT/scripts/pack-deb.sh"
fi

echo ""
echo "Done. Package ready in dist/:"
ls -lh "$PROJECT_ROOT/dist/"*.deb
