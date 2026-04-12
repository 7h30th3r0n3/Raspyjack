#!/bin/bash
# Pierre Gode (Updated Installer - Fast Reinstalls, Debian 12/13 Compatible)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
STATUS_FILE="$REPO_ROOT/data/pwnagotchi_status.json"
LOG_DIR="/var/log/ragnar"
LOG_FILE="$LOG_DIR/pwnagotchi_install_$(date +%Y%m%d_%H%M%S).log"
PWN_DIR="/opt/pwnagotchi"
PWN_REPO="https://github.com/PierreGode/pwnagotchiworking.git"
SERVICE_FILE="/etc/systemd/system/pwnagotchi.service"
CONFIG_DIR="/etc/pwnagotchi"
CONFIG_FILE="$CONFIG_DIR/config.toml"
TEMP_DIR="/home/ragnar/tmp_pwnagotchi_install"
MIN_SPACE_MB=300

mkdir -p "$LOG_DIR" "$REPO_ROOT/data" "$TEMP_DIR"

export TMPDIR="$TEMP_DIR"
export TEMP="$TEMP_DIR"
export TMP="$TEMP_DIR"

touch "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

write_status() {
    local state="$1"
    local message="$2"
    local phase="$3"
    cat >"$STATUS_FILE" <<EOF
{
    "state": "${state}",
    "message": "${message}",
    "phase": "${phase}",
    "timestamp": "$(date -Iseconds)",
    "log_file": "${LOG_FILE}",
    "service_file": "${SERVICE_FILE}",
    "config_file": "${CONFIG_FILE}",
    "repo_dir": "${PWN_DIR}"
}
EOF
}

select_station_interface() {
    # Quick scan for a secondary wlan interface (not wlan0). Never blocks.
    mapfile -t wlan_ifaces < <(ls /sys/class/net 2>/dev/null | grep -E '^wlan[0-9]+' | sort || true)
    for iface in "${wlan_ifaces[@]}"; do
        if [[ "$iface" != "wlan0" ]]; then
            echo "$iface"
            return 0
        fi
    done
    # No adapter found - default to wlan1, pwnagotchi will use it when plugged in
    echo "[WARN] No secondary WiFi adapter detected. Defaulting to wlan1." >&2
    echo "wlan1"
    return 0
}

set_or_update_config_value() {
    local dotted_key="$1"
    local value="$2"
    python3 -c "
import tomlkit, sys
key_path = '${dotted_key}'.split('.')
val = '${value}'
with open('${CONFIG_FILE}', 'r') as f:
    doc = tomlkit.parse(f.read())
d = doc
for k in key_path[:-1]:
    if k not in d:
        d[k] = tomlkit.table()
    d = d[k]
# Convert types for proper TOML output
if val == 'true':
    val = True
elif val == 'false':
    val = False
elif val.isdigit():
    val = int(val)
d[key_path[-1]] = val
with open('${CONFIG_FILE}', 'w') as f:
    f.write(tomlkit.dumps(doc))
" 2>/dev/null || {
        echo "$dotted_key = \"$value\"" >> "$CONFIG_FILE"
    }
}

install_monitor_scripts() {
    local station_if="$1"
    local monitor_if="$2"

    cat > /usr/bin/monstart <<EOF
#!/bin/bash
set -euo pipefail

STA_IF="$station_if"
MON_IF="$monitor_if"

log() {
    echo "[monstart] \$*"
}

if ip link show "\$MON_IF" >/dev/null 2>&1; then
    ip link set "\$MON_IF" down >/dev/null 2>&1 || true
    iw "\$MON_IF" del >/dev/null 2>&1 || true
fi

ip link set "\$STA_IF" down >/dev/null 2>&1 || true
iw dev "\$STA_IF" set type managed >/dev/null 2>&1 || true
ip link set "\$STA_IF" up >/dev/null 2>&1 || true

if ! iw dev "\$STA_IF" interface add "\$MON_IF" type monitor >/dev/null 2>&1; then
    log "Failed to create monitor interface from \$STA_IF"
    exit 1
fi

ip link set "\$MON_IF" up >/dev/null 2>&1 || true
log "Monitor interface \$MON_IF ready (parent: \$STA_IF)"
exit 0
EOF

    cat > /usr/bin/monstop <<EOF
#!/bin/bash
set -euo pipefail

STA_IF="$station_if"
MON_IF="$monitor_if"

if ip link show "\$MON_IF" >/dev/null 2>&1; then
    ip link set "\$MON_IF" down >/dev/null 2>&1 || true
    iw "\$MON_IF" del >/dev/null 2>&1 || true
fi

ip link set "\$STA_IF" up >/dev/null 2>&1 || true
exit 0
EOF

    chmod 755 /usr/bin/monstart /usr/bin/monstop
    chown root:root /usr/bin/monstart /usr/bin/monstop
}

# Helper: check if all packages in a list are already installed
all_packages_installed() {
    for pkg in "$@"; do
        if ! dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
            return 1
        fi
    done
    return 0
}

trap 'write_status "error" "Installation failed (line ${LINENO}). Check ${LOG_FILE}." "error"' ERR

# -------------------------------------------------------------------
# PRECHECK
# -------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "This installer must be run as root."
    exit 1
fi

HEADLESS_DETECTED=false
if pgrep -f "headlessRagnar.py" >/dev/null 2>&1; then
    HEADLESS_DETECTED=true
else
    if systemctl cat ragnar.service 2>/dev/null | grep -q "headlessRagnar.py"; then
        HEADLESS_DETECTED=true
    fi
fi

if [[ "$HEADLESS_DETECTED" == true ]]; then
    BLOCK_MSG="Pwnagotchi requires an e-paper display, but Ragnar is running in Headless mode. Installation is disabled."
    echo "[ERROR] ${BLOCK_MSG}"
    write_status "error" "$BLOCK_MSG" "preflight"
    exit 1
fi

write_status "installing" "Starting Pwnagotchi installation" "preflight"
echo "[INFO] Beginning Pwnagotchi installation..."

echo "[INFO] Checking disk space in $TEMP_DIR..."
available_space=$(df -m "$TEMP_DIR" | awk 'NR==2 {print $4}')
echo "[INFO] Available disk space: ${available_space} MB"

if [[ $available_space -lt $MIN_SPACE_MB ]]; then
    echo "[ERROR] Insufficient disk space (${available_space} MB). Need at least ${MIN_SPACE_MB} MB."
    write_status "error" "Insufficient disk space. Free up space and retry." "preflight"
    exit 1
fi

# -------------------------------------------------------------------
# SYSTEM PACKAGES (skip if all already installed)
# -------------------------------------------------------------------
packages=(
    git python3 python3-pip python3-setuptools python3-dev python3-venv
    libpcap-dev libffi-dev libssl-dev libcap2-bin
    python3-smbus i2c-tools libglib2.0-dev pkg-config meson
)

optional_packages=(
    bettercap hcxdumptool hcxtools libopenblas-dev liblapack-dev
)

if all_packages_installed "${packages[@]}"; then
    echo "[INFO] All required packages already installed - skipping apt"
else
    write_status "installing" "Installing required system packages" "apt_required"
    echo "[INFO] Updating apt and installing required packages..."
    apt-get update -qq
    apt-get install -y --no-upgrade "${packages[@]}"
fi

if all_packages_installed "${optional_packages[@]}"; then
    echo "[INFO] All optional packages already installed - skipping"
else
    write_status "installing" "Installing optional wireless tools" "apt_optional"
    echo "[INFO] Installing optional wireless tools..."
    apt-get install -y --no-upgrade "${optional_packages[@]}" || \
        echo "[WARN] Some optional packages failed. Continuing."
fi

write_status "installing" "System packages ready" "dependencies"

# -------------------------------------------------------------------
# CLONE OR UPDATE REPOSITORY
# -------------------------------------------------------------------
write_status "installing" "Getting Pwnagotchi source" "clone"
if [[ -d "$PWN_DIR/.git" ]]; then
    echo "[INFO] Pwnagotchi repo exists - pulling latest changes..."
    cd "$PWN_DIR"
    git fetch --depth 1 origin
    git reset --hard origin/HEAD
    echo "[INFO] Repository updated"
else
    echo "[INFO] Cloning Pwnagotchi repository to ${PWN_DIR}..."
    rm -rf "$PWN_DIR"
    git clone --depth 1 "$PWN_REPO" "$PWN_DIR"
fi

cd "$PWN_DIR"

# -------------------------------------------------------------------
# PIP INSTALL (skip pip upgrade - system-managed)
# -------------------------------------------------------------------
write_status "installing" "Installing Pwnagotchi package and dependencies" "python_install"

# Check if pwnagotchi is already importable (fast path for reinstalls)
if python3 -c "import pwnagotchi" 2>/dev/null; then
    echo "[INFO] Pwnagotchi package already installed - reinstalling to pick up changes..."
fi

echo "[INFO] Installing Pwnagotchi package (editable mode)..."
python3 -m pip install \
    --break-system-packages \
    --use-pep517 \
    --no-deps \
    -e . 2>&1 || true

# Install dependencies separately with fallback to PyPI if piwheels fails
echo "[INFO] Installing Python dependencies..."
python3 -m pip install \
    --break-system-packages \
    --index-url https://pypi.org/simple \
    --extra-index-url https://www.piwheels.org/simple \
    PyYAML dbus-python file-read-backwards flask flask-cors flask-wtf \
    gast gpiozero inky numpy pycryptodome python-dateutil requests \
    rpi-lgpio rpi_hardware_pwm scapy setuptools shimmy smbus2 spidev \
    tomlkit toml tweepy websockets pisugar 2>&1 || true

# pydrive2 is a hard dependency (pwnagotchi crashes without it).
# Force PyPI only - piwheels drops connections on large packages like google-api-python-client.
# PIP_CONFIG_FILE=/dev/null ignores /etc/pip.conf which adds piwheels.
echo "[INFO] Installing pydrive2 from PyPI (required - may take a few minutes)..."
PIP_CONFIG_FILE=/dev/null python3 -m pip install \
    --break-system-packages \
    --index-url https://pypi.org/simple \
    --timeout 300 \
    --retries 5 \
    pydrive2 2>&1 || {
    echo "[WARN] pydrive2 first attempt failed. Retrying with no cache..."
    PIP_CONFIG_FILE=/dev/null python3 -m pip install \
        --break-system-packages \
        --index-url https://pypi.org/simple \
        --timeout 600 \
        --retries 5 \
        --no-cache-dir \
        pydrive2 2>&1 || echo "[ERROR] pydrive2 install failed. Run manually: sudo PIP_CONFIG_FILE=/dev/null pip3 install --break-system-packages --index-url https://pypi.org/simple pydrive2"
}

# -------------------------------------------------------------------
# PILLOW COMPATIBILITY SHIM (getsize() removed in Pillow 10+)
# -------------------------------------------------------------------
echo "[INFO] Installing Pillow compatibility shim..."
SITE_PACKAGES=$(python3 -c "import site; print(site.getsitepackages()[0])" 2>/dev/null || echo "/usr/local/lib/python3.13/dist-packages")
cat > "$SITE_PACKAGES/pillow_compat.py" << 'PYEOF'
"""Restore PIL.ImageFont.getsize() removed in Pillow 10+."""
from PIL import ImageFont
if not hasattr(ImageFont.FreeTypeFont, 'getsize'):
    def _getsize(self, text, *args, **kwargs):
        bbox = self.getbbox(text, *args, **kwargs)
        if bbox is None:
            return (0, 0)
        return (bbox[2] - bbox[0], bbox[3] - bbox[1])
    ImageFont.FreeTypeFont.getsize = _getsize
if not hasattr(ImageFont.FreeTypeFont, 'getmetrics'):
    def _getmetrics(self):
        bbox = self.getbbox('Ay')
        return bbox[3] if bbox else 0, 0
    ImageFont.FreeTypeFont.getmetrics = _getmetrics
PYEOF

# Inject the shim into pwnagotchi's entry point if not already present
if ! grep -q 'pillow_compat' "$PWN_DIR/pwnagotchi/cli.py" 2>/dev/null; then
    sed -i '1s|^|import pillow_compat\n|' "$PWN_DIR/pwnagotchi/cli.py"
    echo "[INFO] Pillow compatibility shim injected into pwnagotchi"
else
    echo "[INFO] Pillow shim already present - skipping"
fi

# -------------------------------------------------------------------
# VALIDATE + FIX /etc/pwnagotchi
# -------------------------------------------------------------------
write_status "installing" "Configuring Pwnagotchi" "config_dirs"
mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"
chown root:root "$CONFIG_DIR"

write_status "installing" "Detecting WiFi interfaces" "interface_detect"
STATION_IFACE="${PWN_DATA_IFACE:-$(select_station_interface)}"
MONITOR_IFACE_NAME="${PWN_MON_IFACE:-mon0}"
echo "[INFO] Using managed iface: ${STATION_IFACE} (monitor alias: ${MONITOR_IFACE_NAME})"

write_status "installing" "Installing monitor mode scripts" "monitor_scripts"
install_monitor_scripts "$STATION_IFACE" "$MONITOR_IFACE_NAME"

# -------------------------------------------------------------------
# RSA KEY
# -------------------------------------------------------------------
write_status "installing" "Setting up RSA keys" "rsa_keys"
if [[ ! -f "$CONFIG_DIR/id_rsa" ]]; then
    echo "[INFO] Generating RSA keypair..."
    ssh-keygen -t rsa -b 2048 -f "$CONFIG_DIR/id_rsa" -N ""
else
    echo "[INFO] RSA key already exists - skipping"
fi
chmod 600 "$CONFIG_DIR/id_rsa"
chmod 644 "$CONFIG_DIR/id_rsa.pub"

# -------------------------------------------------------------------
# CONFIG FILE
# -------------------------------------------------------------------
echo "[INFO] Configuring Pwnagotchi config file..."
write_status "installing" "Creating configuration files" "config_files"
if [[ ! -f "$CONFIG_FILE" ]]; then
    cat >"$CONFIG_FILE" <<EOF
# Ragnar-managed Pwnagotchi config (pwnagotchiworking)

[main]
name = "RagnarPwn"
confd = "/etc/pwnagotchi/conf.d"
custom_plugins = "/etc/pwnagotchi/custom_plugins"
iface = "${STATION_IFACE}"
mon_iface = "${MONITOR_IFACE_NAME}"
mon_start_cmd = "/usr/bin/monstart"
mon_stop_cmd = "/usr/bin/monstop"

[ui.display]
enabled = true
type = "waveshare_4"
rotation = 180
color = "black"

[ui.web]
enabled = true
address = "0.0.0.0"
username = "ragnar"
password = "ragnar"
port = 8080

[ui.font]
name = "DejaVuSansMono"

[main.plugins.grid]
enabled = false

[main.plugins.fix_services]
enabled = false

[personality]
advertise = false
EOF
    echo "[INFO] Created default config at ${CONFIG_FILE}"
else
    echo "[INFO] Config exists - updating values..."
    set_or_update_config_value "main.iface" "${STATION_IFACE}"
    set_or_update_config_value "main.mon_iface" "${MONITOR_IFACE_NAME}"
    set_or_update_config_value "main.mon_start_cmd" "/usr/bin/monstart"
    set_or_update_config_value "main.mon_stop_cmd" "/usr/bin/monstop"
    # Ensure Ragnar-managed settings are correct
    set_or_update_config_value "ui.web.enabled" "true"
    set_or_update_config_value "ui.web.address" "0.0.0.0"
    set_or_update_config_value "ui.web.username" "ragnar"
    set_or_update_config_value "ui.web.password" "ragnar"
    set_or_update_config_value "ui.web.port" "8080"
    set_or_update_config_value "ui.display.enabled" "true"
    set_or_update_config_value "ui.display.type" "waveshare_4"
    set_or_update_config_value "ui.display.rotation" "180"
    set_or_update_config_value "ui.display.color" "black"
    set_or_update_config_value "main.plugins.grid.enabled" "false"
    # Disable mesh advertising — pwngrid-peer is not used in this setup.
    # Without this, pwnagotchi crashes on start trying to reach port 8666.
    set_or_update_config_value "personality.advertise" "false"
    # Disable fix_services — it is hardcoded to wlan0mon but we use mon0/wlan1.
    # The brcmfmac recovery logic does not apply to our mt76x2u setup.
    set_or_update_config_value "main.plugins.fix_services.enabled" "false"
    echo "[INFO] Config updated"
fi

mkdir -p "$CONFIG_DIR/conf.d" "$CONFIG_DIR/custom_plugins" "$CONFIG_DIR/log"

# -------------------------------------------------------------------
# PWNGRID SHIM
# -------------------------------------------------------------------
echo "[INFO] Checking pwngrid shim..."
if [[ ! -f "/usr/local/bin/pwngrid" ]]; then
    echo "[INFO] Installing pwngrid no-op shim..."
    cat >/usr/local/bin/pwngrid <<'EOF'
#!/bin/bash
exit 0
EOF
    chmod +x /usr/local/bin/pwngrid
else
    echo "[INFO] pwngrid shim already exists - skipping"
fi

# -------------------------------------------------------------------
# LAUNCHER WRAPPER
# -------------------------------------------------------------------
echo "[INFO] Setting up pwnagotchi-launcher wrapper..."
launcher_candidates=(
    "$(command -v pwnagotchi 2>/dev/null || true)"
    "$(command -v pwnagotchi-launcher 2>/dev/null || true)"
    "/usr/local/bin/pwnagotchi"
    "/usr/local/bin/pwnagotchi-launcher"
)

launcher_target=""
for candidate in "${launcher_candidates[@]}"; do
    if [[ -n "$candidate" && -x "$candidate" && "$candidate" != "/usr/bin/pwnagotchi-launcher" ]]; then
        launcher_target="$candidate"
        break
    fi
done

if [[ -n "$launcher_target" ]]; then
    cat > /usr/bin/pwnagotchi-launcher <<EOF
#!/bin/bash
exec ${launcher_target} "\$@"
EOF
    chmod 755 /usr/bin/pwnagotchi-launcher
    chown root:root /usr/bin/pwnagotchi-launcher
    echo "[INFO] Launcher wrapper -> ${launcher_target}"
else
    echo "[WARN] Could not determine pwnagotchi binary path"
fi

# -------------------------------------------------------------------
# SYSTEMD SERVICES (all with timeouts to prevent hanging)
# -------------------------------------------------------------------
echo "[INFO] Setting up systemd services..."
write_status "installing" "Setting up systemd services" "systemd"

cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=Pwnagotchi Mode Service
After=multi-user.target network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/pwnagotchi
WorkingDirectory=${PWN_DIR}
Restart=on-failure
RestartSec=5
TimeoutStopSec=5
KillMode=mixed

[Install]
WantedBy=multi-user.target
EOF
chmod 644 "$SERVICE_FILE"

echo "[INFO] Reloading systemd daemon..."
timeout 15 systemctl daemon-reload || echo "[WARN] daemon-reload slow"

echo "[INFO] Disabling pwnagotchi service (will be started on demand)..."
timeout 10 systemctl disable pwnagotchi >/dev/null 2>&1 || true

echo "[INFO] Stopping pwnagotchi if running..."
timeout 15 systemctl stop pwnagotchi >/dev/null 2>&1 || {
    echo "[WARN] pwnagotchi stop timed out - force killing..."
    timeout 5 systemctl kill pwnagotchi >/dev/null 2>&1 || true
}

# -------------------------------------------------------------------
# PISUGAR SWAP BUTTON SERVICE
# -------------------------------------------------------------------
echo "[INFO] Setting up PiSugar swap button service..."
SWAP_BUTTON_SCRIPT="$REPO_ROOT/scripts/ragnar_swap_button.py"
SWAP_BUTTON_SERVICE="/etc/systemd/system/ragnar-swap-button.service"

if [[ -f "$SWAP_BUTTON_SCRIPT" ]]; then
    chmod 755 "$SWAP_BUTTON_SCRIPT"
    # Run directly from repo so git pull auto-updates the script
    # Also keep a symlink at the old path for backwards compatibility
    ln -sf "$SWAP_BUTTON_SCRIPT" /usr/local/bin/ragnar-swap-button

    cat >"$SWAP_BUTTON_SERVICE" <<EOF
[Unit]
Description=Swap Button Listener - GPIO KEY1 + PiSugar (Ragnar/Pwnagotchi)
After=pisugar-server.service
Wants=pisugar-server.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 $SWAP_BUTTON_SCRIPT
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "$SWAP_BUTTON_SERVICE"
    timeout 10 systemctl daemon-reload || true
    timeout 10 systemctl enable ragnar-swap-button >/dev/null 2>&1 || true
    echo "[INFO] PiSugar swap button service installed"
else
    echo "[INFO] ragnar_swap_button.py not found - skipping PiSugar button setup"
fi

# -------------------------------------------------------------------
# BOOT-TIME MIGRATION SERVICE
# -------------------------------------------------------------------
echo "[INFO] Setting up migration service..."
MIGRATE_SCRIPT="$REPO_ROOT/scripts/migrate_pwnagotchi.sh"
MIGRATE_SERVICE="/etc/systemd/system/ragnar-pwn-migrate.service"

if [[ -f "$MIGRATE_SCRIPT" ]]; then
    chmod 755 "$MIGRATE_SCRIPT"

    cat >"$MIGRATE_SERVICE" <<EOF
[Unit]
Description=Ragnar Pwnagotchi Migration Check
After=local-fs.target
Before=pwnagotchi.service
ConditionPathExists=/opt/pwnagotchi

[Service]
Type=oneshot
ExecStart=${MIGRATE_SCRIPT}
TimeoutStartSec=120
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "$MIGRATE_SERVICE"
    timeout 10 systemctl daemon-reload || true
    timeout 10 systemctl enable ragnar-pwn-migrate >/dev/null 2>&1 || true
    echo "[INFO] Migration service installed"

    mkdir -p /var/lib/ragnar
    date -Iseconds > /var/lib/ragnar/.pwn_migrated
else
    echo "[WARN] migrate_pwnagotchi.sh not found - skipping"
fi

# -------------------------------------------------------------------
# BETTERCAP SERVICE SYNC
# -------------------------------------------------------------------
echo "[INFO] Checking bettercap..."
if [[ -f "/usr/bin/bettercap-launcher" ]]; then
    chmod 755 /usr/bin/bettercap-launcher
fi
echo "[INFO] bettercap will start on swap to Pwnagotchi"

# -------------------------------------------------------------------
# CLEANUP
# -------------------------------------------------------------------
echo "[INFO] Cleaning up temp files..."
write_status "installing" "Cleaning up" "cleanup"
rm -rf "$TEMP_DIR"

# Ensure Ragnar is still the master - clean up any leftover pwnagotchi state
echo "[INFO] Ensuring Ragnar is running..."
ip link set mon0 down 2>/dev/null || true
iw mon0 del 2>/dev/null || true
timeout 10 systemctl stop pwnagotchi 2>/dev/null || true
timeout 10 systemctl stop bettercap 2>/dev/null || true
if ! systemctl is-active ragnar >/dev/null 2>&1; then
    echo "[INFO] Ragnar was stopped - restarting..."
    systemctl start ragnar
fi

write_status "installed" "Pwnagotchi installed successfully. Use Ragnar dashboard to launch." "complete"
echo "[INFO] =========================================="
echo "[INFO] Installation complete!"
echo "[INFO] Ragnar: $(systemctl is-active ragnar 2>/dev/null)"
echo "[INFO] Pwnagotchi: $(systemctl is-active pwnagotchi 2>/dev/null) (disabled)"
echo "[INFO] =========================================="
