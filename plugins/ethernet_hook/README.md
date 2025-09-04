# Ethernet Hook Plugin

Monitors a specified Ethernet interface and triggers payloads when the interface
obtains or loses an IPv4 address. Also optionally renders a small Ethernet icon
on the status overlay when connected.

## Features
- Detect transition: NO IP -> HAS IP ("connect")
- Detect transition: HAS IP -> NO IP ("disconnect")
- Sequential execution of configured payload lists
- Optional tiny status icon when connected
- Multi-type configuration schema (string, list, boolean)

## Configuration Schema
```jsonc
{
  "ethernet_hook": {
    "enabled": false,                   // Enable via UI after first discovery
    "priority": 160,
    "options": {
      "interface": "eth0",              // (string) Interface to monitor
      "show_status_icon": true,         // (boolean) Show icon in overlay
      "on_ethernet_connected": [],      // (list[str]) Payload names executed on connect
      "on_ethernet_disconnected": []    // (list[str]) Payload names executed on disconnect
    }
  }
}
```

NOTE: Only boolean options are toggleable in the current UI. Edit `plugins/plugins_conf.json`
manually to change `interface` or to add payload lists.

### Adding Payloads
Add payload script names (they must exist in the payloads directory) to the lists:
```json
"on_ethernet_connected": ["auto_nmap_scan.py", "silent_bridge.py"],
"on_ethernet_disconnected": ["silent_bridge.py"]
```
The plugin runs them sequentially in a background thread for each event.

## Info Panel
Selecting the plugin in the UI (Info option) will show:
- Current interface
- Current IPv4
- Connection status
- Configured payload arrays
- Whether icon is enabled

## Icon Rendering
A small jack-shaped outline + link square is drawn near the top-right when:
- `show_status_icon` is true AND
- Interface currently has an IPv4 address

## Implementation Notes
- Poll interval: 2 seconds
- Uses `ip -4 addr show <iface>` to detect IPv4
- Debounces events: only fires when state actually changes
- Skips triggering if a previous hook thread is still running

---
Log prefix: `[EthernetHook]`
