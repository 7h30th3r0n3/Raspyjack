# RaspyJack v2.0.0 — Release Notes

## Overview

Major release transforming RaspyJack from a network implant with ~25 payloads into a 
**full-spectrum red team platform with 158 payloads** across 13 categories.
---

## Highlights

- **158 payloads** (was ~25) — 6x more attack surface
- **13 categories** (was 6) — reorganized for clarity
- **136 new payloads** authored by 7h30th3r0n3
- **Dual-display support** — ST7735 128x128 + ST7789 240x240 with auto-scaling
- **581 unit tests** with full mock infrastructure
- **CCTV toolkit** ported from Evil-M5Project
- **Caddy auto-config service** — HTTPS WebUI works on any IP automatically
- **RTL8812AU driver support** for Alfa AWUS036ACH

---

## New Payload Categories

| Category | Count | New |
|----------|-------|-----|
| network | 30 | +27 |
| reconnaissance | 27 | +12 |
| utilities | 19 | +7 |
| games | 16 | +7 |
| wifi | 13 | +12 |
| exfiltration | 9 | +7 |
| credentials | 9 | +9 |
| bluetooth | 7 | +4 |
| usb | 6 | +5 |
| remote_access | 6 | +4 |
| evasion | 6 | +6 |
| hardware | 5 | +5 |

---

## New Payloads by Category

### WiFi (12 new)
- `evil_twin` — Clone AP + captive portal credential harvesting
- `karma_ap` — KARMA attack (auto-clone most-probed SSID)
- `pmkid_grab` — PMKID hash capture without client interaction
- `handshake_hunter` — WPA2 4-way handshake capture with targeted deauth
- `wpa_enterprise_evil` — WPA-Enterprise evil twin with built-in fake RADIUS
- `wps_pixie` — WPS Pixie Dust + PIN brute-force via reaver
- `captive_portal` — Template-based captive portal (reuses DNSSpoof/sites/)
- `wifi_probe_dump` — Passive probe request logger
- `ssid_pool` — Multi-SSID beacon flood (PineAP-style)
- `wifi_alert` — Airspace monitor with MAC/SSID watchlist + Discord alerts
- `wifi_survey` — Live WiFi recon dashboard (APs, clients, channels)
- `wifi_handshake_auto` — Automatic continuous handshake capture

### Network (27 new)
- `dhcp_starve`, `mdns_poison`, `ipv6_ra_attack`, `vlan_hopper`, `stp_root_claim` — Classic L2/L3 attacks
- `nac_bypass` — 802.1X/NAC bypass via transparent bridge + MAC clone
- `arp_mitm` — Dedicated ARP MITM with DNS intercept
- `wpad_proxy` — WPAD injection + transparent HTTP proxy
- `ssdp_spoof`, `llmnr_query_inject` — Service spoofing
- `cdp_spoof` — CDP/LLDP spoofing (impersonate switch/VoIP)
- `arp_dos` — CAM table overflow → hub mode
- `lldp_recon` — Passive LLDP/CDP infrastructure recon
- `dhcpv6_rogue` — Rogue DHCPv6 for IPv6 MITM
- `dns_hijack` — Active DNS hijacking with domain rules
- `icmp_redirect` — ICMP Redirect traffic rerouting
- `rogue_gateway` — Multi-vector ARP+DHCP+RA gateway takeover
- `tcp_rst_inject` — Kill specific TCP connections
- `syn_flood` — SYN flood testing
- `port_scanner` — Fast SYN scanner (scapy)
- `network_tap` — Passive bridge tap with protocol stats
- `nbns_spoof` — NetBIOS Name Service spoofing
- `igmp_snoop` — Multicast group discovery
- `dhcp_snoop` — Passive DHCP reconnaissance
- `traffic_analyzer` — Real-time traffic dashboard
- `hsrp_takeover` — HSRP/VRRP router takeover
- `trunk_dump` — DTP trunk negotiation + multi-VLAN dump
- `proxy_arp` — Subnet-wide proxy ARP

### Credentials (9 new)
- `ftp_bruteforce`, `ssh_bruteforce`, `telnet_grabber` — Brute-force with built-in wordlists
- `http_cred_sniffer` — Passive HTTP credential extraction during MITM
- `cred_sniffer_multi` — Multi-protocol sniffer (FTP, SMTP, POP3, IMAP, LDAP, Kerberos, SMB)
- `ntlm_relay` — NTLM relay via Responder
- `ntlm_cracker` — NTLM hash cracking (John the Ripper)
- `wpa_cracker` — WPA handshake + PMKID cracker (aircrack-ng + john)
- `snmp_walk` — SNMP community brute-force + MIB walk

### Bluetooth (4 new)
- `ble_spam` — iOS/Android/Windows BLE popup spam (Flipper Zero style)
- `ble_scanner` — Continuous BLE scanner dashboard
- `bt_audio_inject` — A2DP audio injection on unprotected speakers
- `ble_mitm` — BLE GATT MITM proxy
- `bt_dos` — L2CAP ping flood DoS

### USB (5 new)
- `hid_injector` — USB HID keyboard injection (BadUSB/DuckyScript)
- `usb_keylogger` — Transparent USB HID keylogger proxy (2 USB ports)
- `usb_ethernet_mitm` — USB Ethernet gadget MITM (RNDIS/ECM)
- `usb_mass_storage` — USB mass storage gadget
- `ducky_library` — DuckyScript payload browser + executor

### Exfiltration (7 new)
- `http_exfil` — HTTP/HTTPS chunked POST exfiltration
- `ble_exfil` — BLE advertisement exfiltration (no WiFi needed)
- `auto_loot_exfil` — Auto-exfil daemon (Discord/HTTP/DNS)
- `dns_tunnel` — DNS subdomain exfiltration
- `icmp_tunnel` — ICMP covert channel
- `exfil_smb` — SMB share for loot
- `exfil_ftp` — Mini FTP server
- `exfil_usb` — Auto-copy loot to USB drive

### Evasion (6 new)
- `mac_randomizer` — MAC randomize/restore/clone
- `log_cleaner` — Forensic artifact cleanup
- `traffic_shaper` — MITM latency management
- `stealth_mode` — One-click stealth toggle (LEDs, WiFi, MACs, logs)
- `fingerprint_spoof` — TCP/IP stack OS spoofing (Linux/Windows/macOS presets)
- `timing_evasion` — Network timing jitter randomizer

### Remote Access (4 new)
- `reverse_shell_gen` — Multi-platform reverse shell generator + listener
- `pivot_proxy` — SOCKS5 proxy for network pivoting
- `port_forwarder` — TCP port forwarder
- `reverse_ssh` — Persistent reverse SSH tunnel (autossh)

### Reconnaissance (12 new)
- `arp_scan_stealth` — Stealthy ARP scanner
- `mac_lookup` — MAC OUI vendor lookup
- `service_banner` — Service banner grabber
- `cert_scanner` — TLS certificate scanner
- `passive_os_detect` — p0f-style passive OS fingerprinting
- `wifi_client_map` — WiFi client-to-AP mapper
- `network_mapper` — Visual network topology on LCD
- `whois_lookup` — WHOIS + reverse DNS
- `auto_recon` — Plug-and-pwn auto recon (Shark Jack style)
- `cctv_scanner` — 8-stage CCTV camera discovery (Evil-M5Project port)
- `cctv_viewer` — Live MJPEG stream viewer on LCD 128x128
- `sniff_creds_live` — Credential aggregator dashboard
- `subnet_mapper` — Complete subnet mapping
- `ad_recon` — Active Directory LDAP enumeration
- `spycam_detector` — Hidden camera detection

### Utilities (7 new)
- `loot_browser` — Browse loot on LCD
- `engagement_timer` — Operation timer with phases
- `qr_generator` — QR code generator on LCD
- `c2_dashboard` — C2 status dashboard
- `payload_scheduler` — Cron-like payload scheduler
- `notification_center` — Notification aggregator + Discord push
- `system_monitor` — System resource monitor

### Hardware (5 new)
- `i2c_scanner` — I2C bus scanner
- `gpio_tripwire` — Physical intrusion detection
- `nfc_reader` — NFC/RFID reader (PN532)
- `gps_tracker` — GPS tracking + logging
- `led_control` — Pi LED pattern controller

### Games (7 new)
- `game_pong`, `game_flappy`, `game_minesweeper`, `game_space_invaders`
- `game_pacman` (4 ghost AIs), `game_tictactoe` (minimax), `game_simon`
- `game_frogger`, `game_asteroids`, `game_sokoban` (10 levels), `game_connect4` (minimax AI)

---

## Dual-Display Support

RaspyJack now supports two LCD screens from a single codebase:

| Display | Chip | Resolution | HAT |
|---------|------|------------|-----|
| 1.44" (original) | ST7735S | 128x128 | Waveshare 1.44" LCD HAT |
| 1.3" | ST7789 | 240x240 | Waveshare 1.3" LCD HAT |

**How it works:**
- Screen type is configured in `gui_conf.json` under `DISPLAY.type`
- The installer (`install_raspyjack.sh`) now asks which screen you have
- All coordinates are authored for 128px and auto-scaled via `S()` helper
- Payloads use `ScaledDraw` (drop-in replacement for `ImageDraw.Draw`) — all drawing coordinates scale automatically
- Fonts use `scaled_font()` instead of `ImageFont.load_default()` for readable text at any resolution
- ST7789 init includes anti-ghosting tuning (VCOM, VRH, 111Hz refresh rate)

**Key files:**
- `LCD_1in44.py` — driver with ST7735/ST7789 dual init, exports `LCD_SCALE` and `S()`
- `payloads/_display_helper.py` — `ScaledDraw` wrapper and `scaled_font()` for payloads
- `gui_conf.json` — `DISPLAY.type` selector

**Switching screens:** Change `"type"` in `gui_conf.json` and reboot. No code changes needed.

---

## Upstream Merges mostly by Hosseios and Dag
- GIF screensaver support (#32)
- Color settings save fix
- Lock function / screensaver
- Loot folder scrolling fix (#31)
- Nmap parser in loot view (#29)
- Subcategories and WiFi Manager (#25)
.
