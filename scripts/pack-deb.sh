#!/bin/bash
# Runs inside the Docker build environment.
# Reads scripts/packaging/meta.env, builds the .deb, and writes it to dist/.
set -euo pipefail

PACKAGING_DIR="scripts/packaging"
source "$PACKAGING_DIR/meta.env"

INSTALL_PREFIX="/usr/share/APPLaunch"
APP_INSTALL_DIR="$INSTALL_PREFIX/apps/$PKG_NAME"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

export STAGE INSTALL_PREFIX APP_INSTALL_DIR PKG_NAME PKG_VERSION PACKAGING_DIR

echo "==[ $PKG_NAME $PKG_VERSION-$PKG_REVISION (arm64) ]=="

echo "-- build.sh"
bash "$PACKAGING_DIR/build.sh"

echo "-- stage.sh"
bash "$PACKAGING_DIR/stage.sh"

mkdir -p "$STAGE/DEBIAN"
cat > "$STAGE/DEBIAN/control" <<EOF
Package: $PKG_NAME
Version: $PKG_VERSION-$PKG_REVISION
Architecture: arm64
Maintainer: CardputerZero AppStore
Depends: $PKG_DEPENDS
Description: $PKG_DESC
EOF

DESKTOP_DIR="$STAGE$INSTALL_PREFIX/applications"
mkdir -p "$DESKTOP_DIR"
cat > "$DESKTOP_DIR/$PKG_NAME.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=$APP_NAME
Exec=$APP_EXEC
Terminal=$APP_TERMINAL
Icon=$APP_ICON
EOF

if [ -f "$PACKAGING_DIR/icon.png" ]; then
    ICON_TARGET="$STAGE$INSTALL_PREFIX/$APP_ICON"
    install -Dm644 "$PACKAGING_DIR/icon.png" "$ICON_TARGET"
fi

for hook in config preinst postinst prerm; do
    if [ -f "$PACKAGING_DIR/$hook" ]; then
        cp "$PACKAGING_DIR/$hook" "$STAGE/DEBIAN/"
        chmod 755 "$STAGE/DEBIAN/$hook"
    fi
done

mkdir -p dist
DEB_FILE="dist/${PKG_NAME}_${PKG_VERSION}-${PKG_REVISION}_arm64.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$DEB_FILE"

echo "-- built: $DEB_FILE"
ls -lh "$DEB_FILE"
