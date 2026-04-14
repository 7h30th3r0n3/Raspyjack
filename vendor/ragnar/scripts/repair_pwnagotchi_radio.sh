#!/bin/bash
# Post-install recovery script for rebuilding the Pwnagotchi monitor interface
# Usage: sudo ./repair_pwnagotchi_radio.sh [data_iface] [monitor_iface]
# - data_iface: managed interface feeding monitor mode (defaults to first wlan!=wlan0)
# - monitor_iface: monitor alias to recreate (default mon0)

set -euo pipefail

CONFIG_FILE="/etc/pwnagotchi/config.toml"
DATA_IFACE="${1:-}"
MONITOR_IFACE="${2:-mon0}"

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (sudo)." >&2
    exit 1
fi

if [[ -z "$DATA_IFACE" ]]; then
    mapfile -t wlan_ifaces < <(ls /sys/class/net 2>/dev/null | grep -E '^wlan[0-9]+' | sort || true)
    for iface in "${wlan_ifaces[@]}"; do
        if [[ "$iface" != "wlan0" ]]; then
            DATA_IFACE="$iface"
            break
        fi
    done
fi

if [[ -z "$DATA_IFACE" ]]; then
    echo "[ERROR] Could not automatically determine a wlan interface other than wlan0." >&2
    echo "        Specify it explicitly, e.g. sudo $0 wlan1 mon0" >&2
    exit 1
fi

echo "[INFO] Using data interface: $DATA_IFACE"
echo "[INFO] Using monitor interface: $MONITOR_IFACE"

update_config_value() {
    local dotted_key="$1"
    local value="$2"
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "[WARN] $CONFIG_FILE does not exist; creating it."
        mkdir -p "$(dirname "$CONFIG_FILE")"
        cat >"$CONFIG_FILE" <<CFGEOF
[main]
name = "RagnarPwn"
CFGEOF
    fi
    # Use Python + tomlkit to safely update TOML table-style configs
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
d[key_path[-1]] = val
with open('${CONFIG_FILE}', 'w') as f:
    f.write(tomlkit.dumps(doc))
" 2>/dev/null || {
        # Fallback: append as flat dotted key if tomlkit unavailable
        echo "$dotted_key = \"$value\"" >> "$CONFIG_FILE"
    }
}

update_config_value "main.iface" "$DATA_IFACE"
update_config_value "main.mon_iface" "$MONITOR_IFACE"
update_config_value "main.mon_start_cmd" "/usr/bin/monstart"
update_config_value "main.mon_stop_cmd" "/usr/bin/monstop"

echo "[INFO] Updated $CONFIG_FILE with interface settings."

echo "[INFO] Stopping active processes that may hold the interface..."
for proc in tcpdump bettercap pwnagotchi; do
    if pkill -f "$proc" >/dev/null 2>&1; then
        echo "  - Killed $proc"
    fi
    if killall "$proc" >/dev/null 2>&1; then
        echo "  - killall $proc"
    fi
    sleep 0.5
done
systemctl stop pwnagotchi >/dev/null 2>&1 || true

if ip link show "$MONITOR_IFACE" >/dev/null 2>&1; then
    ip link set "$MONITOR_IFACE" down >/dev/null 2>&1 || true
    iw "$MONITOR_IFACE" del >/dev/null 2>&1 || true
fi

ip link set "$DATA_IFACE" down >/dev/null 2>&1 || true
iw dev "$DATA_IFACE" set type managed >/dev/null 2>&1 || true
ip link set "$DATA_IFACE" up >/dev/null 2>&1 || true

if iw dev "$DATA_IFACE" interface add "$MONITOR_IFACE" type monitor >/dev/null 2>&1; then
    ip link set "$MONITOR_IFACE" up >/dev/null 2>&1 || true
    echo "[INFO] Recreated monitor interface $MONITOR_IFACE from $DATA_IFACE."
else
    echo "[ERROR] Failed to create monitor interface $MONITOR_IFACE from $DATA_IFACE." >&2
    exit 1
fi

systemctl start pwnagotchi

echo "[SUCCESS] Monitor interface rebuilt and pwnagotchi.service restarted."
exit 0
