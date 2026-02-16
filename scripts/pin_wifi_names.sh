#!/usr/bin/env bash
set -euo pipefail

# Force stable WiFi names by hardware path:
# - onboard Pi WiFi (mmc) -> wlan0
# - first USB WiFi dongle (usb) -> wlan1

LOG_FILE="/root/Raspyjack/loot/network/wifi_pin_boot.log"
mkdir -p "$(dirname "$LOG_FILE")"

log() {
  echo "[$(date -Iseconds)] $*" >> "$LOG_FILE"
}

detect_ifaces() {
  ONBOARD_IF=""
  USB_IF=""
  for dev in /sys/class/net/wlan*; do
    [ -e "$dev" ] || continue
    iface="$(basename "$dev")"
    devpath="$(readlink -f "$dev/device" 2>/dev/null || true)"
    if echo "$devpath" | grep -q "mmc"; then
      ONBOARD_IF="$iface"
    elif [ -z "$USB_IF" ] && echo "$devpath" | grep -q "usb"; then
      USB_IF="$iface"
    fi
  done
}

log "pin service start boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)"

# Wait for wlan devices to appear (udev timing can race at boot).
for _ in $(seq 1 40); do
  detect_ifaces
  [ -n "${ONBOARD_IF:-}" ] && break
  sleep 0.5
done

detect_ifaces
log "detected onboard=${ONBOARD_IF:-none} usb=${USB_IF:-none}"

# Nothing to do if no onboard WiFi was detected.
if [ -z "${ONBOARD_IF:-}" ]; then
  log "no onboard iface detected, exit"
  exit 0
fi

# If names are already correct, quit fast.
if [ "$ONBOARD_IF" = "wlan0" ] && { [ -z "$USB_IF" ] || [ "$USB_IF" = "wlan1" ]; }; then
  log "already pinned correctly"
  exit 0
fi

log "renaming required onboard=$ONBOARD_IF usb=${USB_IF:-none}"

# Bring involved links down first.
for i in "$ONBOARD_IF" "$USB_IF" wlan0 wlan1; do
  [ -n "${i:-}" ] || continue
  ip link show "$i" >/dev/null 2>&1 || continue
  ip link set "$i" down >/dev/null 2>&1 || true
done

# Assign desired names with variable tracking so swaps cannot get stuck on tmp names.
if [ "$ONBOARD_IF" != "wlan0" ]; then
  if ip link show wlan0 >/dev/null 2>&1; then
    ip link set wlan0 name wlan_tmp0 >/dev/null 2>&1 || true
    [ "${USB_IF:-}" = "wlan0" ] && USB_IF="wlan_tmp0"
  fi
  ip link set "$ONBOARD_IF" name wlan0 >/dev/null 2>&1 || true
  ONBOARD_IF="wlan0"
fi

if [ -n "$USB_IF" ] && [ "$USB_IF" != "wlan1" ]; then
  if ip link show wlan1 >/dev/null 2>&1; then
    ip link set wlan1 name wlan_tmp1 >/dev/null 2>&1 || true
    [ "${ONBOARD_IF:-}" = "wlan1" ] && ONBOARD_IF="wlan_tmp1"
  fi
  ip link set "$USB_IF" name wlan1 >/dev/null 2>&1 || true
  USB_IF="wlan1"
fi

# If a temp name is left over and wlan1 is free, normalize it.
if ip link show wlan_tmp0 >/dev/null 2>&1 && ! ip link show wlan1 >/dev/null 2>&1; then
  ip link set wlan_tmp0 name wlan1 >/dev/null 2>&1 || true
fi

# Bring final interfaces up (best effort).
ip link show wlan0 >/dev/null 2>&1 && ip link set wlan0 up >/dev/null 2>&1 || true
ip link show wlan1 >/dev/null 2>&1 && ip link set wlan1 up >/dev/null 2>&1 || true

detect_ifaces
log "after rename onboard=${ONBOARD_IF:-none} usb=${USB_IF:-none}"
log "route=$(ip route show default 2>/dev/null | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
