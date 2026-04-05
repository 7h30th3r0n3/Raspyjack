<div align="center">

# 🧩 Payloads

**155 payloads across 13 categories**

</div>

---

## 💡 What Are Payloads?
Payloads are **standalone Python scripts** stored in `payloads/<category>/`. RaspyJack scans this folder at runtime and builds the **Payload** menu automatically.

**Anyone can add a payload**:
1. Create a new `.py` file in any `payloads/<category>/` subfolder.
2. Use the LCD + buttons like the examples (see `examples/example_show_buttons.py`).
3. It will appear automatically in the Payload menu.

---

## 🧪 How to Create Your Own

<ol>
  <li>Copy <code>payloads/examples/_payload_template.py</code> and rename it.</li>
  <li>Place it in the appropriate category folder (e.g. <code>payloads/wifi/</code>).</li>
  <li>Keep the <code>KEY3</code> exit behavior (clean return to RaspyJack).</li>
  <li>Draw on the LCD with <code>LCD_1in44</code> + PIL (Image/ImageDraw).</li>
  <li>Test manually: <code>python3 payloads/&lt;category&gt;/your_payload.py</code>.</li>
  <li>Restart RaspyJack to refresh the Payload menu.</li>
</ol>

---

## 🧰 Minimal Template
```python
#!/usr/bin/env python3
import os, sys, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..', '..')))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._input_helper import get_button

PINS = {"UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
        "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16}
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)

try:
    while True:
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            break
        img = Image.new("RGB", (128, 128), "black")
        d = ImageDraw.Draw(img)
        d.text((6, 6), "Hello Payload", font=ImageFont.load_default(), fill="#00FF00")
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(0.05)
finally:
    LCD.LCD_Clear()
    GPIO.cleanup()
```

---

## 📊 Category Overview

<table align="center">
  <tr><th>Category</th><th>Count</th><th>Description</th></tr>
  <tr><td>📡 WiFi</td><td>13</td><td>WiFi attacks: deauth, evil twin, WPA capture, WPS, recon</td></tr>
  <tr><td>🌐 Network</td><td>30</td><td>L2-L4 network attacks: ARP, DHCP, VLAN, STP, DNS, MITM</td></tr>
  <tr><td>🔑 Credentials</td><td>9</td><td>Credential harvesting, brute-force, cracking</td></tr>
  <tr><td>🔵 Bluetooth</td><td>7</td><td>BLE/BT scanning, spoofing, replay, spam, DoS</td></tr>
  <tr><td>🔌 USB</td><td>6</td><td>USB gadget attacks: HID injection, keylogger, MITM</td></tr>
  <tr><td>📤 Exfiltration</td><td>9</td><td>Data exfil: HTTP, DNS, BLE, Discord, SMB, FTP, USB</td></tr>
  <tr><td>🥷 Evasion</td><td>6</td><td>Stealth: MAC spoof, log cleaning, fingerprint spoof</td></tr>
  <tr><td>🔗 Remote Access</td><td>6</td><td>Reverse shells, SSH tunnels, SOCKS proxy, port forward</td></tr>
  <tr><td>🔍 Reconnaissance</td><td>27</td><td>Scanning, OSINT, passive recon, CCTV, device tracking</td></tr>
  <tr><td>🛠️ Utilities</td><td>19</td><td>System tools, WiFi management, C2 dashboard, scheduler</td></tr>
  <tr><td>🔧 Hardware</td><td>5</td><td>GPIO, I2C, NFC, GPS, LED control</td></tr>
  <tr><td>🎮 Games</td><td>16</td><td>Pac-Man, Tetris, Snake, Asteroids, Connect 4, and more</td></tr>
  <tr><td>📝 Examples</td><td>1</td><td>Payload template and button demo</td></tr>
</table>

---

## 📡 WiFi (13)

All WiFi attack payloads require a **USB WiFi dongle with monitor mode** (e.g. Alfa AWUS036ACH). The onboard wlan0 is reserved for the WebUI.

<table align="center">
  <tr><th>Payload</th><th>Description</th><th>Extra Requirements</th></tr>
  <tr><td>captive_portal</td><td>Advanced captive portal with template selection from DNSSpoof/sites/</td><td>hostapd, dnsmasq-base</td></tr>
  <tr><td>deauth</td><td>Multi-target WiFi deauthentication attack</td><td>aircrack-ng</td></tr>
  <tr><td>evil_twin</td><td>Clone a target AP and serve a credential-harvesting captive portal</td><td>hostapd, dnsmasq-base</td></tr>
  <tr><td>handshake_hunter</td><td>Capture WPA2 4-way handshakes via targeted deauth</td><td>scapy, aircrack-ng</td></tr>
  <tr><td>karma_ap</td><td>Monitor probe requests, launch rogue AP using most-probed SSID</td><td>hostapd, dnsmasq-base, tcpdump</td></tr>
  <tr><td>pmkid_grab</td><td>Capture PMKID hashes from WPA2 APs (no client needed)</td><td>scapy, aircrack-ng</td></tr>
  <tr><td>ssid_pool</td><td>Broadcast multiple fake SSIDs via beacon injection (PineAP-style)</td><td>scapy</td></tr>
  <tr><td>wifi_alert</td><td>Airspace monitor — alert when target MAC/SSID appears or disappears</td><td>scapy, requests</td></tr>
  <tr><td>wifi_handshake_auto</td><td>Automatic continuous handshake capture with optional deauth assist</td><td>scapy</td></tr>
  <tr><td>wifi_probe_dump</td><td>Passive WiFi probe request logger (device history tracking)</td><td>—</td></tr>
  <tr><td>wifi_survey</td><td>Live WiFi recon dashboard: APs, clients, channels, signal</td><td>scapy</td></tr>
  <tr><td>wpa_enterprise_evil</td><td>WPA-Enterprise evil twin with built-in fake RADIUS server</td><td>hostapd, dnsmasq-base</td></tr>
  <tr><td>wps_pixie</td><td>WPS Pixie Dust + online PIN brute-force</td><td>reaver</td></tr>
</table>

---

## 🌐 Network (30)

<table align="center">
  <tr><th>Payload</th><th>Description</th><th>Extra Requirements</th></tr>
  <tr><td>arp_dos</td><td>CAM table overflow — force switch into hub mode for passive sniffing</td><td>—</td></tr>
  <tr><td>arp_mitm</td><td>Dedicated ARP MITM with IP forwarding, DNS intercept, connection logging</td><td>—</td></tr>
  <tr><td>cdp_spoof</td><td>CDP/LLDP spoofing to impersonate a Cisco switch or VoIP phone</td><td>—</td></tr>
  <tr><td>dhcp_snoop</td><td>Passive DHCP snooping — discover clients, servers, leases</td><td>—</td></tr>
  <tr><td>dhcp_starve</td><td>DHCP starvation attack (exhaust address pool)</td><td>—</td></tr>
  <tr><td>dhcpv6_rogue</td><td>Rogue DHCPv6 server for IPv6 MITM (Windows prefers DHCPv6)</td><td>—</td></tr>
  <tr><td>dns_hijack</td><td>Active DNS hijacking with domain-to-IP spoofing rules</td><td>—</td></tr>
  <tr><td>hsrp_takeover</td><td>HSRP/VRRP active router takeover (priority 255)</td><td>—</td></tr>
  <tr><td>icmp_redirect</td><td>ICMP Redirect attack — reroute traffic without ARP spoofing</td><td>—</td></tr>
  <tr><td>igmp_snoop</td><td>IGMP snooping — discover active multicast groups (VoIP, streaming)</td><td>—</td></tr>
  <tr><td>ipv6_ra_attack</td><td>IPv6 Router Advertisement spoofing — become default IPv6 gateway</td><td>—</td></tr>
  <tr><td>lldp_recon</td><td>Passive LLDP/CDP listener — discover switches, models, firmware, VLANs</td><td>—</td></tr>
  <tr><td>llmnr_query_inject</td><td>Active LLMNR/NBT-NS query injection to trigger hash captures</td><td>—</td></tr>
  <tr><td>mdns_poison</td><td>mDNS/DNS-SD spoofing — impersonate printers, AirPlay, file shares</td><td>—</td></tr>
  <tr><td>nac_bypass</td><td>802.1X/NAC bypass via transparent bridge + MAC/IP clone</td><td>2 Ethernet interfaces, bridge-utils, ebtables</td></tr>
  <tr><td>nbns_spoof</td><td>NetBIOS Name Service spoofing (complements Responder)</td><td>—</td></tr>
  <tr><td>network_tap</td><td>Pure passive bridge tap with real-time protocol statistics</td><td>2 Ethernet interfaces, bridge-utils</td></tr>
  <tr><td>port_scanner</td><td>Fast SYN port scanner using scapy (lighter than nmap)</td><td>—</td></tr>
  <tr><td>proxy_arp</td><td>Subnet-wide proxy ARP — intercept all traffic for a subnet</td><td>—</td></tr>
  <tr><td>rogue_dhcp_wpad</td><td>Rogue DHCP server with WPAD option 252 poisoning</td><td>—</td></tr>
  <tr><td>rogue_gateway</td><td>Multi-vector gateway takeover: ARP + DHCP + IPv6 RA simultaneously</td><td>—</td></tr>
  <tr><td>silent_bridge</td><td>Stealth L2 bridge + tcpdump capture + tshark protocol counters</td><td>2 active interfaces</td></tr>
  <tr><td>ssdp_spoof</td><td>UPnP/SSDP spoofing with credential-harvesting login page</td><td>—</td></tr>
  <tr><td>stp_root_claim</td><td>STP root bridge takeover (BPDU priority 0)</td><td>—</td></tr>
  <tr><td>syn_flood</td><td>SYN flood for service resilience testing</td><td>—</td></tr>
  <tr><td>tcp_rst_inject</td><td>TCP RST injection to kill specific active connections</td><td>—</td></tr>
  <tr><td>traffic_analyzer</td><td>Real-time traffic dashboard: bandwidth, protocols, top connections, DNS</td><td>—</td></tr>
  <tr><td>trunk_dump</td><td>DTP trunk negotiation + multi-VLAN traffic dump</td><td>—</td></tr>
  <tr><td>vlan_hopper</td><td>VLAN hopping via 802.1Q double-tagging and DTP spoofing</td><td>—</td></tr>
  <tr><td>wpad_proxy</td><td>WPAD proxy injection + transparent HTTP proxy logging URLs/credentials</td><td>dnsmasq-base</td></tr>
</table>

---

## 🔑 Credentials (9)

<table align="center">
  <tr><th>Payload</th><th>Description</th><th>Extra Requirements</th></tr>
  <tr><td>cred_sniffer_multi</td><td>Passive multi-protocol credential sniffer (FTP, Telnet, SMTP, POP3, IMAP, HTTP, LDAP, Kerberos, SMB)</td><td>—</td></tr>
  <tr><td>ftp_bruteforce</td><td>FTP credential brute-force with built-in 50-pair wordlist</td><td>—</td></tr>
  <tr><td>http_cred_sniffer</td><td>Passive HTTP credential extraction (Basic Auth, POST forms, cookies) during MITM</td><td>—</td></tr>
  <tr><td>ntlm_cracker</td><td>Crack NTLM hashes from Responder logs using John the Ripper</td><td>john</td></tr>
  <tr><td>ntlm_relay</td><td>NTLM relay attack using vendored Responder</td><td>Responder</td></tr>
  <tr><td>snmp_walk</td><td>SNMP community string brute-force + MIB walk</td><td>—</td></tr>
  <tr><td>ssh_bruteforce</td><td>SSH credential spray with built-in wordlist</td><td>sshpass</td></tr>
  <tr><td>telnet_grabber</td><td>Telnet banner grab + default credential testing (IoT/routers)</td><td>—</td></tr>
  <tr><td>wpa_cracker</td><td>WPA handshake (.cap) + PMKID cracker</td><td>aircrack-ng, john</td></tr>
</table>

---

## 🔵 Bluetooth (7)

All Bluetooth payloads require a **Bluetooth adapter** (hci0, usually built-in on Raspberry Pi).

<table align="center">
  <tr><th>Payload</th><th>Description</th><th>Extra Requirements</th></tr>
  <tr><td>ble_beacon_flood</td><td>Flood fake iBeacon/Eddystone BLE advertisements</td><td>—</td></tr>
  <tr><td>ble_mitm</td><td>BLE GATT MITM proxy — intercept traffic between peripheral and app</td><td>bluez, gatttool</td></tr>
  <tr><td>ble_replay</td><td>Record and replay BLE GATT write sequences</td><td>gatttool</td></tr>
  <tr><td>ble_scanner</td><td>Continuous BLE scanner dashboard with RSSI tracking</td><td>—</td></tr>
  <tr><td>ble_spam</td><td>BLE popup spam: iOS (Proximity Pairing), Android (FastPair), Windows (Swift Pair)</td><td>—</td></tr>
  <tr><td>bt_audio_inject</td><td>Inject audio on unprotected Bluetooth A2DP speakers</td><td>pulseaudio-module-bluetooth</td></tr>
  <tr><td>bt_dos</td><td>Bluetooth L2CAP ping flood DoS</td><td>bluez (l2ping)</td></tr>
</table>

---

## 🔌 USB (6)

USB gadget payloads require a **Pi Zero USB OTG port** connected to the target.

<table align="center">
  <tr><th>Payload</th><th>Description</th><th>Extra Requirements</th></tr>
  <tr><td>badusb_detector</td><td>Detect suspicious USB HID/storage insertion events</td><td>python3-evdev, pyudev</td></tr>
  <tr><td>ducky_library</td><td>Browse and execute DuckyScript payloads from hid_scripts/</td><td>hid_injector gadget</td></tr>
  <tr><td>hid_injector</td><td>USB HID keyboard injection (BadUSB) with DuckyScript support</td><td>USB OTG, configfs</td></tr>
  <tr><td>usb_ethernet_mitm</td><td>USB Ethernet gadget MITM — target sees Pi as network adapter</td><td>USB OTG, dnsmasq</td></tr>
  <tr><td>usb_keylogger</td><td>Transparent USB HID keylogger proxy (keyboard to Pi to host)</td><td>2 USB ports, python3-evdev</td></tr>
  <tr><td>usb_mass_storage</td><td>Present Pi as USB flash drive with custom FAT32 image</td><td>USB OTG</td></tr>
</table>

---

## 📤 Exfiltration (9)

<table align="center">
  <tr><th>Payload</th><th>Description</th><th>Extra Requirements</th></tr>
  <tr><td>auto_loot_exfil</td><td>Daemon watching loot/ — auto-exfil new files via Discord/HTTP/DNS</td><td>Channel config</td></tr>
  <tr><td>ble_exfil</td><td>Ultra-stealth BLE advertisement data exfiltration (no WiFi needed)</td><td>BT adapter</td></tr>
  <tr><td>dns_tunnel</td><td>DNS exfiltration via base32 subdomain encoding</td><td>External DNS domain</td></tr>
  <tr><td>exfil_ftp</td><td>Mini FTP server serving loot/ directory</td><td>pyftpdlib (optional)</td></tr>
  <tr><td>exfil_smb</td><td>SMB share for loot, or upload to remote share</td><td>impacket-smbserver or smbclient</td></tr>
  <tr><td>exfil_usb</td><td>Auto-copy loot to USB drive on insertion</td><td>pyudev</td></tr>
  <tr><td>exfiltrate_discord</td><td>Zip loot + Responder logs and upload to Discord webhook</td><td>Discord webhook URL</td></tr>
  <tr><td>http_exfil</td><td>HTTP/HTTPS chunked POST exfiltration to configurable server</td><td>Edit config/http_exfil/config.json</td></tr>
  <tr><td>icmp_tunnel</td><td>ICMP covert channel — encode data in echo request payloads</td><td>Target IP</td></tr>
</table>

---

## 🥷 Evasion (6)

<table align="center">
  <tr><th>Payload</th><th>Description</th><th>Extra Requirements</th></tr>
  <tr><td>fingerprint_spoof</td><td>TCP/IP stack fingerprint spoofing — presets: Linux, Windows, macOS, Cisco, Printer</td><td>—</td></tr>
  <tr><td>log_cleaner</td><td>Selective forensic artifact cleanup (history, journal, ARP cache, logs)</td><td>—</td></tr>
  <tr><td>mac_randomizer</td><td>Randomize, restore, or clone MAC addresses on any interface</td><td>—</td></tr>
  <tr><td>stealth_mode</td><td>One-click stealth: disable LEDs, reduce WiFi power, randomize MACs, flush logs</td><td>—</td></tr>
  <tr><td>timing_evasion</td><td>Network timing randomizer via tc qdisc jitter (bypass timing-based IDS)</td><td>—</td></tr>
  <tr><td>traffic_shaper</td><td>Traffic shaping during MITM to keep latency below suspicious thresholds</td><td>—</td></tr>
</table>

---

## 🔗 Remote Access (6)

<table align="center">
  <tr><th>Payload</th><th>Description</th><th>Extra Requirements</th></tr>
  <tr><td>pivot_proxy</td><td>SOCKS5 proxy for network pivoting (accessible via Tailscale)</td><td>—</td></tr>
  <tr><td>port_forwarder</td><td>TCP port forwarder with multiple forwarding rules</td><td>—</td></tr>
  <tr><td>reverse_shell_gen</td><td>Generate reverse shell one-liners (bash, Python, PS, PHP, Perl, nc) + HTTP server + listener</td><td>—</td></tr>
  <tr><td>reverse_ssh</td><td>Persistent reverse SSH tunnel with auto-reconnection</td><td>autossh</td></tr>
  <tr><td>shell</td><td>Interactive bash terminal on LCD via USB keyboard</td><td>python3-evdev</td></tr>
  <tr><td>tailscale_control</td><td>Tailscale VPN control and monitoring from LCD</td><td>Tailscale installed</td></tr>
</table>

---

## 🔍 Reconnaissance (27)

<table align="center">
  <tr><th>Payload</th><th>Description</th><th>Extra Requirements</th></tr>
  <tr><td>ad_recon</td><td>Active Directory LDAP enumeration (users, groups, computers, GPOs)</td><td>Network access to DC</td></tr>
  <tr><td>analyzer</td><td>Real-time RF spectrum analyzer with channel filters</td><td>—</td></tr>
  <tr><td>arp_scan_stealth</td><td>Slow, stealthy ARP scanner with randomized timing and MAC spoofing</td><td>—</td></tr>
  <tr><td>autoNmapScan</td><td>On-demand or periodic Nmap scans with LCD display</td><td>nmap</td></tr>
  <tr><td>auto_recon</td><td>Plug-and-pwn: automatic ARP scan + nmap + Discord exfil (zero interaction)</td><td>Discord webhook (optional)</td></tr>
  <tr><td>bt_scan_classic</td><td>Bluetooth Classic device discovery + SDP service enumeration</td><td>BT adapter</td></tr>
  <tr><td>cam_finder</td><td>Security camera detection by OUI filtering during WiFi scan</td><td>—</td></tr>
  <tr><td>cctv_scanner</td><td>8-stage CCTV camera discovery: port scan, fingerprint, default creds, stream detect</td><td>requests</td></tr>
  <tr><td>cctv_viewer</td><td>Live MJPEG stream viewer on LCD 128x128 — switch between cameras</td><td>requests, cctv_live.txt</td></tr>
  <tr><td>cert_scanner</td><td>TLS certificate scanner — extract CN, SAN, issuer, detect internal hostname leaks</td><td>—</td></tr>
  <tr><td>device_scout</td><td>WiFi + BLE device scanner with anti-surveillance tracker detection</td><td>—</td></tr>
  <tr><td>dns_leaker</td><td>Passive DNS/NBNS traffic monitor for network service discovery</td><td>—</td></tr>
  <tr><td>gatt_enum</td><td>BLE GATT service and characteristic enumerator</td><td>BT adapter, gatttool</td></tr>
  <tr><td>honeypot</td><td>Low-interaction multi-port TCP honeypot with JSONL logging</td><td>—</td></tr>
  <tr><td>mac_lookup</td><td>MAC address OUI vendor lookup (auto-downloads IEEE database)</td><td>Internet (first run)</td></tr>
  <tr><td>navarro</td><td>Username OSINT checker across 25+ platforms</td><td>—</td></tr>
  <tr><td>network_mapper</td><td>Visual network topology map rendered on LCD</td><td>—</td></tr>
  <tr><td>passive_os_detect</td><td>p0f-style passive OS fingerprinting from TCP SYN characteristics</td><td>—</td></tr>
  <tr><td>service_banner</td><td>Fast service banner grabber on common ports (21, 22, 80, 443, etc.)</td><td>—</td></tr>
  <tr><td>smb_probe</td><td>Scan subnet for SMB (TCP 445) hosts</td><td>—</td></tr>
  <tr><td>sniff_creds_live</td><td>Dashboard aggregating ALL captured credentials from every payload</td><td>—</td></tr>
  <tr><td>spycam_detector</td><td>Hidden camera detection via WiFi SSID patterns and manufacturer OUIs</td><td>USB WiFi dongle</td></tr>
  <tr><td>subnet_mapper</td><td>Complete subnet mapping: ARP + ports + OS + services in one pass</td><td>nmap</td></tr>
  <tr><td>wall_of_flippers</td><td>Flipper Zero BLE threat detection and tracking</td><td>BT adapter</td></tr>
  <tr><td>wardriving</td><td>WiFi network discovery with GPS logging (JSON/CSV/KML export)</td><td>scapy, gpsd (optional)</td></tr>
  <tr><td>whois_lookup</td><td>WHOIS + reverse DNS for external IPs observed in traffic</td><td>—</td></tr>
  <tr><td>wifi_client_map</td><td>Passive WiFi client-to-AP association mapper</td><td>USB WiFi dongle</td></tr>
</table>

---

## 🛠️ Utilities (19)

<table align="center">
  <tr><th>Payload</th><th>Description</th><th>Extra Requirements</th></tr>
  <tr><td>auto_update</td><td>Backup RaspyJack, git pull updates, restart services</td><td>Internet</td></tr>
  <tr><td>bt_keyboard_picker</td><td>Scan, pair, trust and connect Bluetooth keyboards</td><td>BT adapter</td></tr>
  <tr><td>c2_dashboard</td><td>C2 dashboard: running payloads, loot stats, network status, services</td><td>—</td></tr>
  <tr><td>engagement_timer</td><td>Operation timer with phase tracking (Recon/Exploit/Persist/Exfil/Cleanup)</td><td>—</td></tr>
  <tr><td>fast_wifi_connect</td><td>Auto-connect to strongest saved WiFi network</td><td>—</td></tr>
  <tr><td>fast_wifi_switcher</td><td>Quick wlan0/wlan1 interface switching</td><td>—</td></tr>
  <tr><td>interface_status</td><td>Live eth0/eth1 link and traffic status display</td><td>—</td></tr>
  <tr><td>keyboard_tester</td><td>Display USB keyboard key presses on LCD</td><td>python3-evdev</td></tr>
  <tr><td>LanTest</td><td>LAN throughput measurement via iperf3</td><td>iperf3</td></tr>
  <tr><td>latency</td><td>TCP RTT and jitter monitor with rolling graph</td><td>—</td></tr>
  <tr><td>loot_browser</td><td>Browse loot/ directory on LCD with file preview</td><td>—</td></tr>
  <tr><td>notification_center</td><td>Notification aggregator from all payloads with Discord push</td><td>—</td></tr>
  <tr><td>packet_replay</td><td>Replay .pcap files from loot with timing control</td><td>scapy</td></tr>
  <tr><td>payload_scheduler</td><td>Cron-like payload scheduler (run at time or repeat interval)</td><td>—</td></tr>
  <tr><td>qr_generator</td><td>QR code generator on LCD (IP, WebUI URL, WiFi connect, custom text)</td><td>python3-qrcode</td></tr>
  <tr><td>system_monitor</td><td>System resource monitor: CPU, RAM, temp, disk, uptime, network</td><td>—</td></tr>
  <tr><td>WanTest</td><td>WAN speed test (download/upload via Speedtest)</td><td>speedtest-cli</td></tr>
  <tr><td>webui</td><td>Display WebUI URL on LCD</td><td>—</td></tr>
  <tr><td>wifi_manager_payload</td><td>Launch full WiFi management LCD interface</td><td>—</td></tr>
</table>

---

## 🔧 Hardware (5)

<table align="center">
  <tr><th>Payload</th><th>Description</th><th>Extra Requirements</th></tr>
  <tr><td>gpio_tripwire</td><td>Physical intrusion detection via GPIO sensor pins + Discord alerts</td><td>Sensors wired to GPIO</td></tr>
  <tr><td>gps_tracker</td><td>GPS tracking and logging via serial GPS module (NMEA parsing)</td><td>Serial GPS module (e.g. NEO-6M)</td></tr>
  <tr><td>i2c_scanner</td><td>I2C bus scanner — identify connected devices by address</td><td>I2C enabled in config.txt</td></tr>
  <tr><td>led_control</td><td>Pi LED controller with patterns: idle, scanning, attacking, alert, stealth</td><td>—</td></tr>
  <tr><td>nfc_reader</td><td>NFC/RFID reader via PN532 — read UIDs, dump MIFARE sectors</td><td>PN532 module (I2C)</td></tr>
</table>

---

## 🎮 Games (16)

All games use the D-pad for movement, OK to start/action, KEY1 to restart, KEY3 to exit.

<table align="center">
  <tr><th>Payload</th><th>Description</th></tr>
  <tr><td>game_2048</td><td>2048 puzzle game</td></tr>
  <tr><td>game_asteroids</td><td>Asteroids — rotating ship, thrust, shoot, splitting asteroids</td></tr>
  <tr><td>game_Breakout</td><td>Classic Breakout / brick breaker</td></tr>
  <tr><td>game_connect4</td><td>Connect 4 vs AI (minimax alpha-beta, 3 difficulty levels)</td></tr>
  <tr><td>game_flappy</td><td>Flappy Bird clone with pipe obstacles</td></tr>
  <tr><td>game_frogger</td><td>Frogger — cross roads and rivers, ride logs</td></tr>
  <tr><td>game_minesweeper</td><td>Minesweeper (8x8 grid, 10 mines)</td></tr>
  <tr><td>game_pacman</td><td>Pac-Man with 4 ghosts (Blinky, Pinky, Inky, Clyde AI)</td></tr>
  <tr><td>game_pong</td><td>Pong vs AI opponent</td></tr>
  <tr><td>game_simon</td><td>Simon Says — memory sequence game with 4 colors</td></tr>
  <tr><td>game_snake</td><td>Classic Snake game</td></tr>
  <tr><td>game_sokoban</td><td>Sokoban puzzle (10 levels, undo support)</td></tr>
  <tr><td>game_space_invaders</td><td>Space Invaders with shields, 4 rows of aliens</td></tr>
  <tr><td>game_tetris</td><td>Tetris with rotate, move, hard drop</td></tr>
  <tr><td>game_tictactoe</td><td>Tic-Tac-Toe vs unbeatable minimax AI</td></tr>
  <tr><td>conways_game_of_life</td><td>Conway's Game of Life cellular automaton</td></tr>
</table>

---

## 📝 Examples (1)

<table align="center">
  <tr><th>Payload</th><th>Description</th></tr>
  <tr><td>example_show_buttons</td><td>Demonstrates joystick/button input on LCD — best template for new payloads</td></tr>
</table>

---

## 📦 Dependencies

All dependencies are installed automatically by `install_raspyjack.sh`. Key packages:

<table align="center">
  <tr><th>Package</th><th>Used by</th></tr>
  <tr><td>aircrack-ng</td><td>WiFi attacks (deauth, handshake, monitor mode)</td></tr>
  <tr><td>hostapd + dnsmasq-base</td><td>Evil twin, karma AP, captive portal</td></tr>
  <tr><td>reaver</td><td>WPS Pixie Dust attacks</td></tr>
  <tr><td>john</td><td>NTLM + WPA hash cracking</td></tr>
  <tr><td>sshpass</td><td>SSH brute-force</td></tr>
  <tr><td>autossh</td><td>Persistent reverse SSH tunnel</td></tr>
  <tr><td>bridge-utils + ebtables</td><td>NAC bypass, network tap, silent bridge</td></tr>
  <tr><td>tshark</td><td>Protocol analysis, traffic stats</td></tr>
  <tr><td>bluez</td><td>All Bluetooth payloads</td></tr>
  <tr><td>python3-evdev</td><td>USB keyboard input (shell, keylogger, keyboard tester)</td></tr>
  <tr><td>python3-scapy</td><td>Packet crafting (WiFi, network attacks, sniffing)</td></tr>
  <tr><td>python3-qrcode</td><td>QR code generator</td></tr>
  <tr><td>smbus2</td><td>I2C scanner, NFC reader</td></tr>
</table>

---

## ❓ FAQ

<ul>
  <li><strong>Q: My payload doesn't appear in the menu.</strong><br/>A: It must be a <code>.py</code> file inside <code>payloads/&lt;category&gt;/</code>. Restart the UI after adding it.</li>
  <li><strong>Q: How do I exit a payload safely?</strong><br/>A: Press KEY3. All payloads handle KEY3 as the exit button.</li>
  <li><strong>Q: Where is loot saved?</strong><br/>A: All results are saved under <code>/root/Raspyjack/loot/&lt;PayloadName&gt;/</code>.</li>
  <li><strong>Q: Where are payload configs?</strong><br/>A: Configuration files are in <code>/root/Raspyjack/config/&lt;payload_name&gt;/</code>.</li>
  <li><strong>Q: Can I add non-Python payloads?</strong><br/>A: The menu executes Python scripts; use Python wrappers to launch other tools.</li>
  <li><strong>Q: "No module named LCD_1in44 / RPi.GPIO".</strong><br/>A: You are not on a Pi or the dependencies are missing. Run <code>install_raspyjack.sh</code>.</li>
  <li><strong>Q: How do I add a dependency?</strong><br/>A: Add it to the PACKAGES array in <code>install_raspyjack.sh</code> and document it in the payload docstring.</li>
</ul>

---

## 📖 Detailed Payload Reference

> Each payload card shows: what it does, why you need it, when to deploy it, and how it works under the hood.

---

### 📡 WiFi Payloads

<details align="center">
<summary><b>captive_portal</b> — Rogue AP with phishing portal</summary>

| | |
|---|---|
| **Usage** | Launch a rogue open WiFi AP serving a customizable phishing login page |
| **Why** | Harvest credentials from users who connect and "log in" to access WiFi |
| **When** | Social engineering engagements; employee security awareness testing |
| **How** | hostapd (open AP) + dnsmasq (DHCP/DNS redirect) + HTTP server serving templates from `DNSSpoof/sites/`. Credentials logged to loot |
| **Config** | `apt install hostapd dnsmasq-base` — Optional: add phishing templates to `DNSSpoof/sites/`. |
</details>

<details align="center">
<summary><b>deauth</b> — WiFi deauthentication attack</summary>

| | |
|---|---|
| **Usage** | Disconnect WiFi clients from their access point via deauth frames |
| **Why** | Force reconnection (for handshake capture), disrupt cameras, deny WiFi service |
| **When** | Pre-handshake capture, or WiFi resilience testing |
| **How** | Monitor mode on USB dongle, scapy Dot11Deauth frames targeting specific or all clients |
</details>

<details align="center">
<summary><b>evil_twin</b> — Clone AP with credential harvesting</summary>

| | |
|---|---|
| **Usage** | Clone a target AP's SSID and serve a "re-enter password" captive portal |
| **Why** | Steal WPA passwords or web credentials from users connecting to the fake AP |
| **When** | WiFi credential capture; MITM on wireless users |
| **How** | hostapd clones SSID, dnsmasq for DHCP, iptables NAT/DNS redirect, captive portal for credential harvest |
| **Config** | `apt install hostapd dnsmasq-base` — USB WiFi dongle auto-detected on wlan1+. |
</details>

<details align="center">
<summary><b>handshake_hunter</b> — WPA2 4-way handshake capture</summary>

| | |
|---|---|
| **Usage** | Capture WPA2 handshakes from target networks for offline cracking |
| **Why** | Obtain the hash needed to crack WPA2 passwords with aircrack-ng or hashcat |
| **When** | WiFi security assessments; WPA2 password strength testing |
| **How** | Scan APs, select target, discover clients, targeted deauth, capture EAPOL 4-way exchange, save .cap |
</details>

<details align="center">
<summary><b>karma_ap</b> — Auto-impersonate probed networks</summary>

| | |
|---|---|
| **Usage** | Monitor probe requests and launch AP using the most-probed SSID |
| **Why** | Devices probe for remembered networks; KARMA tricks them into connecting |
| **When** | Public spaces with many devices probing for known networks |
| **How** | tcpdump monitors probes, ranks SSIDs by frequency, hostapd clones the top SSID, captive portal captures creds |
| **Config** | `apt install hostapd dnsmasq-base tcpdump` — USB WiFi dongle auto-detected on wlan1+. |
</details>

<details align="center">
<summary><b>pmkid_grab</b> — PMKID hash capture (clientless)</summary>

| | |
|---|---|
| **Usage** | Capture PMKID hashes from WPA2 APs without needing any connected client |
| **Why** | Faster and stealthier than waiting for a client handshake |
| **When** | No clients connected to target AP; quick WPA2 hash collection |
| **How** | scapy sends association requests, extracts PMKID from EAPOL RSN PMKID-List, saves in hashcat format |
</details>

<details align="center">
<summary><b>ssid_pool</b> — Multi-SSID beacon flood</summary>

| | |
|---|---|
| **Usage** | Broadcast multiple fake SSIDs simultaneously via beacon injection |
| **Why** | Increase chances of devices auto-connecting; WiFi DoS by SSID pollution |
| **When** | Lure phase before evil_twin/karma_ap; WiFi disruption testing |
| **How** | scapy injects 802.11 Beacon frames with different SSIDs at high rate, each with a persistent random BSSID |
</details>

<details align="center">
<summary><b>wifi_alert</b> — Airspace monitoring with alerts</summary>

| | |
|---|---|
| **Usage** | Alert when a target MAC/SSID appears or disappears from the airspace |
| **Why** | Track when a target person enters/leaves an area; detect rogue APs |
| **When** | Physical surveillance; rogue AP detection during security audits |
| **How** | Monitor mode sniffs beacons + probe requests, compares against watchlist config, flashes LCD + Discord webhook on status change |
| **Config** | Edit watchlist at `/root/Raspyjack/config/wifi_alert/watchlist.json` with target MACs and SSIDs. |
</details>

<details align="center">
<summary><b>wifi_handshake_auto</b> — Automatic continuous handshake capture</summary>

| | |
|---|---|
| **Usage** | Set-and-forget: automatically captures handshakes from all nearby networks |
| **Why** | No manual target selection; passive collection over hours/days |
| **When** | Deploy implant and let it collect; long-term WiFi assessment |
| **How** | Monitors all channels, detects client associations, captures EAPOL frames, optional single deauth to trigger re-auth, auto-saves .cap files |
</details>

<details align="center">
<summary><b>wifi_probe_dump</b> — Probe request logger</summary>

| | |
|---|---|
| **Usage** | Log all WiFi probe requests to profile nearby devices and their network history |
| **Why** | Reveals which networks devices previously connected to (home, work, hotels) |
| **When** | Passive recon in public spaces; device tracking; building target profiles |
| **How** | Sniffs Dot11ProbeReq in monitor mode with channel hopping, builds {MAC: set(SSIDs)} map, exports JSON |
</details>

<details align="center">
<summary><b>wifi_survey</b> — Live WiFi recon dashboard</summary>

| | |
|---|---|
| **Usage** | Real-time dashboard of all APs, clients, channels, signal strength |
| **Why** | Complete picture of the WiFi environment before launching attacks |
| **When** | First step of any WiFi engagement; site survey |
| **How** | Channel-hopping sniffer builds live database of APs and clients with signal, encryption, client count |
</details>

<details align="center">
<summary><b>wpa_enterprise_evil</b> — WPA-Enterprise evil twin + fake RADIUS</summary>

| | |
|---|---|
| **Usage** | Evil twin targeting WPA-Enterprise to capture EAP/MSCHAPv2 credentials |
| **Why** | Capture domain credentials from enterprise WiFi users |
| **When** | Targeting corporate 802.1X networks |
| **How** | hostapd with WPA-EAP config, built-in Python RADIUS server that accepts all auth and logs credentials, returns Access-Accept |
| **Config** | `apt install hostapd dnsmasq-base` — Built-in RADIUS server, no external setup needed. |
</details>

<details align="center">
<summary><b>wps_pixie</b> — WPS Pixie Dust + PIN brute-force</summary>

| | |
|---|---|
| **Usage** | Attack WPS-enabled APs to recover WPA password via PIN cracking |
| **Why** | Many routers have WPS enabled by default; Pixie Dust cracks it in seconds |
| **When** | Target AP has WPS enabled (detected by `wash` scan) |
| **How** | `wash` scans for WPS APs, `reaver -K 1` tries Pixie Dust offline attack, falls back to online PIN brute-force |
| **Config** | `apt install reaver` (provides both `reaver` and `wash`). |
</details>

---

### 🌐 Network Payloads

<details align="center">
<summary><b>arp_dos</b> — CAM table overflow (hub mode)</summary>

| | |
|---|---|
| **Usage** | Flood switch CAM table with random MACs to force hub mode |
| **Why** | In hub mode all traffic is broadcast — enables passive sniffing without ARP poisoning |
| **When** | ARP MITM is detected/blocked; need truly passive capture |
| **How** | scapy sends massive ARP replies with randomized source MACs, overflowing the switch's MAC address table |
</details>

<details align="center">
<summary><b>arp_mitm</b> — ARP cache poisoning MITM</summary>

| | |
|---|---|
| **Usage** | Intercept traffic between a target and the gateway via ARP poisoning |
| **Why** | Classic MITM — see all traffic, inject/modify packets |
| **When** | Intercept, log, or modify a specific host's traffic |
| **How** | Poisons target + gateway ARP caches, enables IP forwarding, optional DNS intercept, logs all connections |
</details>

<details align="center">
<summary><b>cdp_spoof</b> — CDP/LLDP impersonation</summary>

| | |
|---|---|
| **Usage** | Impersonate a Cisco switch or VoIP phone via CDP/LLDP frames |
| **Why** | Access voice VLAN (less secured); learn switch model/firmware/VLAN config |
| **When** | Cisco networks; bypass VLAN segmentation; infrastructure recon |
| **How** | Sniffs existing CDP/LLDP, then injects spoofed frames advertising as switch or VoIP phone |
</details>

<details align="center">
<summary><b>dhcp_snoop</b> — Passive DHCP reconnaissance</summary>

| | |
|---|---|
| **Usage** | Monitor DHCP traffic to map clients, servers, and network config |
| **Why** | Zero-footprint recon — learn network layout without sending a packet |
| **When** | First step on a new network |
| **How** | Sniffs DHCP Discover/Offer/Request/ACK, extracts client MAC, IP, hostname, DHCP server, gateway, DNS |
</details>

<details align="center">
<summary><b>dhcp_starve</b> — DHCP pool exhaustion</summary>

| | |
|---|---|
| **Usage** | Exhaust the DHCP address pool with random MAC requests |
| **Why** | Deny IPs to new devices; force clients to accept your rogue DHCP server |
| **When** | Before rogue DHCP/WPAD attack; DoS testing |
| **How** | Sends hundreds of DHCPDISCOVER with random MACs via scapy |
</details>

<details align="center">
<summary><b>dhcpv6_rogue</b> — Rogue DHCPv6 (IPv6 MITM)</summary>

| | |
|---|---|
| **Usage** | Run a rogue DHCPv6 server to hijack IPv6 DNS |
| **Why** | Windows prefers DHCPv6 — even on IPv4-only networks, hijack DNS via IPv6 |
| **When** | Dual-stack networks with unprotected IPv6 (very common) |
| **How** | Responds to DHCPv6 Solicit with Pi as DNS server; all DNS queries now flow through Pi |
</details>

<details align="center">
<summary><b>dns_hijack</b> — Active DNS spoofing</summary>

| | |
|---|---|
| **Usage** | Intercept DNS queries and spoof responses for configured domains |
| **Why** | Redirect targets to phishing pages; block sites; intercept API calls |
| **When** | During active MITM for selective DNS manipulation |
| **How** | iptables redirects DNS to Pi, scapy spoofs responses for configured domain-to-IP rules, forwards the rest |
</details>

<details align="center">
<summary><b>hsrp_takeover</b> — Router redundancy hijack</summary>

| | |
|---|---|
| **Usage** | Claim HSRP/VRRP active router status to intercept all subnet traffic |
| **Why** | Become default gateway without ARP poisoning |
| **When** | Networks using Cisco HSRP or VRRP redundancy |
| **How** | Sniffs HSRP Hello (UDP 1985), sends Hello with priority 255 to become active router |
</details>

<details align="center">
<summary><b>icmp_redirect</b> — ICMP-based traffic rerouting</summary>

| | |
|---|---|
| **Usage** | Reroute target's traffic through Pi using ICMP Redirect messages |
| **Why** | MITM without ARP spoofing — less likely detected by ARP-monitoring IDS |
| **When** | ARP spoofing is blocked; hosts accept ICMP redirects |
| **How** | scapy sends ICMP Type 5 Redirect telling target to route through Pi |
</details>

<details align="center">
<summary><b>igmp_snoop</b> — Multicast group discovery</summary>

| | |
|---|---|
| **Usage** | Discover active multicast groups (VoIP, streaming, cameras) |
| **Why** | Identify VoIP systems, IPTV streams, camera feeds passively |
| **When** | Network recon; locating VoIP or camera infrastructure |
| **How** | Sniffs IGMP Membership Reports, matches against known multicast address database |
</details>

<details align="center">
<summary><b>ipv6_ra_attack</b> — IPv6 Router Advertisement spoofing</summary>

| | |
|---|---|
| **Usage** | Send rogue IPv6 RAs to become the default IPv6 gateway |
| **Why** | Most hosts accept RAs by default; become IPv6 gateway for MITM |
| **When** | Networks with IPv6 enabled (often by default) but unmonitored |
| **How** | scapy sends ICMPv6 Router Advertisement with Pi as source and fake prefix |
</details>

<details align="center">
<summary><b>lldp_recon</b> — Switch infrastructure reconnaissance</summary>

| | |
|---|---|
| **Usage** | Passively discover switches, models, firmware, VLANs, management IPs |
| **Why** | Map the entire switching infrastructure without any active probing |
| **When** | Infrastructure reconnaissance; switch vulnerability identification |
| **How** | Listens for LLDP (0x88cc) and CDP frames, parses TLVs for device info |
</details>

<details align="center">
<summary><b>llmnr_query_inject</b> — LLMNR/NBT-NS hash trigger</summary>

| | |
|---|---|
| **Usage** | Inject queries to force Windows hosts to reveal NTLMv2 hashes |
| **Why** | Actively trigger hash captures instead of waiting for organic traffic |
| **When** | Accelerate Responder collection on Windows networks |
| **How** | Sends LLMNR multicast queries (224.0.0.252) for WPAD, FILESRV, etc. Responder captures responding hashes |
</details>

<details align="center">
<summary><b>mdns_poison</b> — mDNS/DNS-SD service spoofing</summary>

| | |
|---|---|
| **Usage** | Impersonate printers, AirPlay, file shares via mDNS spoofing |
| **Why** | Redirect service discovery; capture credentials from clients connecting to fake services |
| **When** | Networks with macOS/Linux/iOS devices using mDNS |
| **How** | Listens on 224.0.0.251:5353, responds with spoofed answers pointing _http, _ipp, _airplay, _smb to Pi's IP |
</details>

<details align="center">
<summary><b>nac_bypass</b> — 802.1X/NAC bypass</summary>

| | |
|---|---|
| **Usage** | Bypass port-based 802.1X authentication via transparent bridge + identity clone |
| **Why** | Gain network access on 802.1X-secured ports without valid credentials |
| **When** | Target network uses port-based 802.1X/NAC |
| **How** | Sniffs authenticated device's MAC/IP, clones identity, creates transparent bridge (br0), injects traffic using cloned identity |
| **Config** | Requires 2 Ethernet interfaces (eth0 + eth1). `apt install bridge-utils ebtables`. |
</details>

<details align="center">
<summary><b>nbns_spoof</b> — NetBIOS Name Service spoofing</summary>

| | |
|---|---|
| **Usage** | Spoof NBNS responses to capture Windows NTLM hashes |
| **Why** | Complement Responder's LLMNR with dedicated NBNS poisoning |
| **When** | Windows networks; lighter alternative to full Responder |
| **How** | Listens for NBNS queries (UDP 137 broadcast), responds with Pi's IP to trigger NTLM auth |
</details>

<details align="center">
<summary><b>network_tap</b> — Invisible passive tap</summary>

| | |
|---|---|
| **Usage** | Zero-footprint network tap with real-time protocol statistics |
| **Why** | Capture all traffic with absolutely no detectable presence (no IP, no ARP) |
| **When** | Long-term covert monitoring; stealth-critical deployments |
| **How** | Transparent bridge (br0) with no IP, tcpdump captures, tshark shows protocol breakdown |
</details>

<details align="center">
<summary><b>port_scanner</b> — Fast SYN scanner</summary>

| | |
|---|---|
| **Usage** | Quick port scan using scapy — lighter than nmap |
| **Why** | Rapid port discovery with minimal footprint |
| **When** | Quick check of specific host; nmap too slow/noisy |
| **How** | scapy TCP SYN to target ports, SYN-ACK=open, RST=closed, no response=filtered |
</details>

<details align="center">
<summary><b>proxy_arp</b> — Subnet-wide ARP proxy</summary>

| | |
|---|---|
| **Usage** | Respond to all ARP requests for a subnet — intercept all local traffic |
| **Why** | Broad-spectrum MITM covering the entire subnet at once |
| **When** | Need to capture traffic from all hosts, not just one target |
| **How** | Responds to every ARP who-has with Pi's MAC, all hosts route through Pi, IP forwarding relays transparently |
</details>

<details align="center">
<summary><b>rogue_dhcp_wpad</b> — Rogue DHCP with WPAD injection</summary>

| | |
|---|---|
| **Usage** | Run rogue DHCP injecting WPAD proxy auto-configuration |
| **Why** | Force clients to use a Pi-controlled HTTP proxy |
| **When** | Networks without explicit WPAD configuration (most networks) |
| **How** | dnsmasq with DHCP Option 252 pointing to Pi's wpad.dat |
</details>

<details align="center">
<summary><b>rogue_gateway</b> — Multi-vector gateway takeover</summary>

| | |
|---|---|
| **Usage** | Become gateway using ARP + DHCP + IPv6 RA simultaneously |
| **Why** | Maximum reliability — if one vector is blocked, others still work |
| **When** | Robust persistent MITM; when individual vectors might be countered |
| **How** | Three parallel threads: ARP poisoning, rogue DHCP, IPv6 RA. Each independently redirects traffic |
</details>

<details align="center">
<summary><b>silent_bridge</b> — Stealth L2 bridge MITM</summary>

| | |
|---|---|
| **Usage** | Invisible bridge for transparent MITM with protocol logging |
| **Why** | No IP, no ARP — completely invisible on the network |
| **When** | Physical implant deployment; long-term covert monitoring |
| **How** | Bridge br0 between two interfaces, no IP assigned, tcpdump + tshark for capture and protocol stats |
</details>

<details align="center">
<summary><b>ssdp_spoof</b> — UPnP device impersonation</summary>

| | |
|---|---|
| **Usage** | Impersonate UPnP devices to lure users to a credential-harvesting page |
| **Why** | Users trust "network devices" (printers, media servers) and enter credentials |
| **When** | Social engineering on the LAN |
| **How** | Responds to SSDP M-SEARCH with fake device description, serves login page that captures credentials |
</details>

<details align="center">
<summary><b>stp_root_claim</b> — STP root bridge takeover</summary>

| | |
|---|---|
| **Usage** | Claim STP root bridge to redirect all switch traffic through Pi |
| **Why** | Root bridge sees all inter-switch traffic — total network visibility |
| **When** | Managed switch networks using STP |
| **How** | scapy sends BPDUs with priority 0, switches elect Pi as root and reroute traffic |
</details>

<details align="center">
<summary><b>syn_flood</b> — Service resilience testing</summary>

| | |
|---|---|
| **Usage** | SYN flood against a target service |
| **Why** | Test service resilience; verify IDS/firewall rules |
| **When** | Authorized resilience testing only |
| **How** | scapy sends TCP SYN with random source IPs/ports at configurable speed |
</details>

<details align="center">
<summary><b>tcp_rst_inject</b> — Connection killer</summary>

| | |
|---|---|
| **Usage** | Inject TCP RST to kill specific active connections |
| **Why** | Disrupt VPN tunnels, SSH sessions, force re-authentication |
| **When** | During MITM; selective connection disruption |
| **How** | Sniffs TCP to build connection table, injects RST with correct seq numbers in both directions |
</details>

<details align="center">
<summary><b>traffic_analyzer</b> — Real-time traffic dashboard</summary>

| | |
|---|---|
| **Usage** | Live dashboard: bandwidth, protocols, top connections, DNS queries |
| **Why** | Understand traffic patterns; identify high-value targets; spot anomalies |
| **When** | During recon or MITM |
| **How** | scapy sniffs on active interface, tracks per-protocol stats, top connections by bandwidth, recent DNS |
</details>

<details align="center">
<summary><b>trunk_dump</b> — VLAN trunk traffic dump</summary>

| | |
|---|---|
| **Usage** | Negotiate 802.1Q trunk and dump traffic from all VLANs |
| **Why** | See traffic from VLANs you shouldn't have access to |
| **When** | Cisco switches with DTP enabled (default on many ports) |
| **How** | DTP frames negotiate trunk mode, then sniffs all traffic parsing 802.1Q tags per VLAN |
</details>

<details align="center">
<summary><b>vlan_hopper</b> — VLAN escape</summary>

| | |
|---|---|
| **Usage** | Escape your VLAN via double-tagging or DTP spoofing |
| **Why** | Bypass VLAN segmentation; reach servers on other VLANs |
| **When** | Target hosts on different VLAN; weak VLAN security |
| **How** | Double-tagging (outer=native, inner=target VLAN) or DTP trunk negotiation |
</details>

<details align="center">
<summary><b>wpad_proxy</b> — WPAD + transparent proxy</summary>

| | |
|---|---|
| **Usage** | Inject WPAD + run HTTP proxy logging all URLs and credentials |
| **Why** | See every URL and extract HTTP credentials transparently |
| **When** | During MITM for full HTTP visibility |
| **How** | Rogue DHCP Option 252, PAC file, HTTP proxy on port 8888 logging URLs/credentials/cookies |
| **Config** | `apt install dnsmasq-base`. |
</details>

---

### 🔑 Credentials Payloads

<details align="center">
<summary><b>cred_sniffer_multi</b> — 9-protocol credential sniffer</summary>

| | |
|---|---|
| **Usage** | Passively capture credentials from FTP, Telnet, SMTP, POP3, IMAP, HTTP, LDAP, Kerberos, SMB |
| **Why** | One payload to catch them all — any cleartext or weak auth protocol |
| **When** | During MITM or bridge tap; long-term passive collection |
| **How** | scapy parses protocol-specific credential fields in real-time |
</details>

<details align="center">
<summary><b>ftp_bruteforce</b> — FTP credential brute-force</summary>

| | |
|---|---|
| **Usage** | Brute-force FTP logins with 50 common credential pairs |
| **Why** | FTP often uses weak/default passwords on NAS, embedded devices |
| **When** | After discovering FTP servers (port 21) |
| **How** | Auto-discovers FTP hosts from nmap loot, ftplib with 0.5s rate limiting |
</details>

<details align="center">
<summary><b>http_cred_sniffer</b> — HTTP credential extraction</summary>

| | |
|---|---|
| **Usage** | Extract Basic Auth, POST form credentials, and cookies from HTTP traffic |
| **Why** | Many internal services still use unencrypted HTTP |
| **When** | During MITM when targets use HTTP services |
| **How** | scapy on port 80, decodes Basic Auth base64, extracts POST username/password fields |
</details>

<details align="center">
<summary><b>ntlm_cracker</b> — NTLM hash cracker</summary>

| | |
|---|---|
| **Usage** | Crack NTLM hashes from Responder logs using John the Ripper |
| **Why** | Convert captured NTLMv2/v1 hashes to plaintext passwords |
| **When** | After Responder or ntlm_relay captures hashes |
| **How** | Scans Responder/logs/ for hashes, auto-detects format, runs John with wordlist/rules/incremental mode |
| **Config** | `apt install john` — Reads hashes from `Responder/logs/` and `loot/NTLMRelay/`. |
</details>

<details align="center">
<summary><b>ntlm_relay</b> — NTLM authentication relay</summary>

| | |
|---|---|
| **Usage** | Relay captured NTLM auth to a target service for instant access |
| **Why** | Access SMB/HTTP/LDAP without cracking — relay the hash in real-time |
| **When** | During MITM on Windows networks with NTLM authentication |
| **How** | Responder captures NTLM auth, relay module forwards to target service |
| **Config** | Responder must be installed at `/root/Raspyjack/Responder/`. Best after ARP MITM or silent bridge. |
</details>

<details align="center">
<summary><b>snmp_walk</b> — SNMP brute-force + enumeration</summary>

| | |
|---|---|
| **Usage** | Brute-force community strings, then enumerate device info via SNMP |
| **Why** | SNMP reveals system info, interfaces, routes, sometimes credentials |
| **When** | After discovering SNMP devices (port 161); common on network gear |
| **How** | Tries common community strings via raw SNMP packets, walks standard MIBs on success |
</details>

<details align="center">
<summary><b>ssh_bruteforce</b> — SSH credential spray</summary>

| | |
|---|---|
| **Usage** | Spray 50 common SSH credentials against discovered hosts |
| **Why** | Weak SSH passwords on IoT, dev servers, default configs |
| **When** | After discovering SSH servers (port 22) |
| **How** | sshpass for non-interactive login attempts, 1s rate limit |
| **Config** | `apt install sshpass`. |
</details>

<details align="center">
<summary><b>telnet_grabber</b> — Telnet banner + default creds</summary>

| | |
|---|---|
| **Usage** | Grab banners and test 30 IoT/router default credentials on Telnet services |
| **Why** | Telnet is unencrypted with frequent default passwords on legacy/IoT devices |
| **When** | After discovering Telnet services (port 23) |
| **How** | Socket connect, banner capture, heuristic login detection with common credential pairs |
</details>

<details align="center">
<summary><b>wpa_cracker</b> — WPA/PMKID offline cracker</summary>

| | |
|---|---|
| **Usage** | Crack WPA handshakes (.cap) and PMKID hashes offline |
| **Why** | Recover WPA passwords from captured material |
| **When** | After handshake_hunter or pmkid_grab captures |
| **How** | aircrack-ng for .cap files, John for PMKID. Supports default/rockyou/custom wordlists |
| **Config** | `apt install aircrack-ng john` — Optional: place `rockyou.txt` or `custom.txt` in `/root/Raspyjack/loot/wordlists/`. |
</details>

---

### 🔵 Bluetooth Payloads

<details align="center">
<summary><b>ble_beacon_flood</b> — Fake BLE beacon flood</summary>

| | |
|---|---|
| **Usage** | Flood area with fake iBeacon/Eddystone advertisements |
| **Why** | Overwhelm BLE scanners; disrupt positioning systems |
| **When** | BLE infrastructure disruption testing |
| **How** | hcitool broadcasts randomized iBeacon (UUID/major/minor) and Eddystone-URL advertisements |
</details>

<details align="center">
<summary><b>ble_mitm</b> — BLE GATT MITM proxy</summary>

| | |
|---|---|
| **Usage** | Intercept BLE GATT traffic between a peripheral and its controlling app |
| **Why** | Log and potentially modify all BLE communication |
| **When** | IoT security testing; BLE device reverse engineering |
| **How** | Connects to target via gatttool, enumerates GATT, advertises as peripheral, proxies all operations |
</details>

<details align="center">
<summary><b>ble_replay</b> — BLE GATT replay attack</summary>

| | |
|---|---|
| **Usage** | Record BLE GATT writes and replay them to reproduce actions |
| **Why** | Replay unlock commands, control sequences without the original controller |
| **When** | Attacking BLE smart locks, IoT devices with replay-vulnerable commands |
| **How** | Records all GATT characteristic values, replays the sequence on demand |
</details>

<details align="center">
<summary><b>ble_scanner</b> — BLE device dashboard</summary>

| | |
|---|---|
| **Usage** | Continuous BLE scanner with RSSI tracking and service enumeration |
| **Why** | Full BLE device inventory with tracking over time |
| **When** | BLE reconnaissance; identifying targets for further attacks |
| **How** | hcitool lescan with duplicate tracking, RSSI, first/last seen, GATT drill-down |
</details>

<details align="center">
<summary><b>ble_spam</b> — BLE popup spam (Flipper-style)</summary>

| | |
|---|---|
| **Usage** | Trigger popup notifications on nearby iOS, Android, and Windows devices |
| **Why** | Demonstrate BLE attack surface; create distractions during red team ops |
| **When** | Social engineering; BLE attack demonstration |
| **How** | Crafted BLE ads: Apple Proximity Pairing (iOS), Google FastPair (Android), Microsoft Swift Pair (Windows) |
</details>

<details align="center">
<summary><b>bt_audio_inject</b> — Bluetooth speaker hijack</summary>

| | |
|---|---|
| **Usage** | Connect to unprotected BT speakers and play audio remotely |
| **Why** | Demonstrate physical security risk of open Bluetooth audio devices |
| **When** | Discovering A2DP speakers/headphones in range |
| **How** | sdptool filters A2DP, bluetoothctl pairs, paplay/aplay plays audio |
| **Config** | `apt install pulseaudio-module-bluetooth` — Place audio file at `/root/Raspyjack/config/bt_audio/payload.wav`. |
</details>

<details align="center">
<summary><b>bt_dos</b> — Bluetooth L2CAP flood</summary>

| | |
|---|---|
| **Usage** | DoS a Bluetooth device with L2CAP ping flood |
| **Why** | Disrupt BT headsets, keyboards, IoT, tracking devices |
| **When** | Testing BT resilience; disrupting surveillance devices |
| **How** | `l2ping -f` with large packets to overwhelm the target's BT stack |
</details>

---

### 🔌 USB Payloads

<details align="center">
<summary><b>badusb_detector</b> — Malicious USB detection</summary>

| | |
|---|---|
| **Usage** | Alert on suspicious USB HID/storage insertion events |
| **Why** | Detect rubber duckies, BadUSB devices, unauthorized USB storage |
| **When** | Defensive; leave running as an early warning system |
| **How** | pyudev watches USB events, detects rapid HID keystroke activity post-insertion |
</details>

<details align="center">
<summary><b>ducky_library</b> — DuckyScript payload launcher</summary>

| | |
|---|---|
| **Usage** | Browse and execute pre-made DuckyScript attack payloads |
| **Why** | Quick access to common HID attacks without writing scripts |
| **When** | Pi connected to target via USB OTG |
| **How** | Browses hid_scripts/, shows preview, launches via hid_injector. Includes reverse shell, WiFi exfil, disable defender scripts |
| **Config** | Edit `ATTACKER_IP` placeholder in scripts before use. Requires `hid_injector` gadget setup. |
</details>

<details align="center">
<summary><b>hid_injector</b> — USB BadUSB keyboard injection</summary>

| | |
|---|---|
| **Usage** | Type pre-programmed keystrokes on target computer as a USB keyboard |
| **Why** | Execute commands bypassing software restrictions — the computer trusts keyboards |
| **When** | Physical access to target's USB port |
| **How** | configfs USB HID gadget, DuckyScript parser (STRING, ENTER, DELAY, GUI, etc.), writes HID keycodes to /dev/hidg0 |
| **Config** | Pi Zero USB OTG port connected to target. DuckyScript files in `payloads/hid_scripts/`. |
</details>

<details align="center">
<summary><b>usb_ethernet_mitm</b> — USB Ethernet MITM</summary>

| | |
|---|---|
| **Usage** | Present Pi as a USB Ethernet adapter for host-side MITM |
| **Why** | Target routes all traffic through Pi — undetectable from the network side |
| **When** | Physical access to target; MITM without touching the network |
| **How** | RNDIS + ECM USB gadget, dnsmasq DHCP, Pi becomes default gateway for the target host |
| **Config** | Pi Zero USB OTG port to target. `apt install dnsmasq`. |
</details>

<details align="center">
<summary><b>usb_keylogger</b> — Transparent inline keylogger</summary>

| | |
|---|---|
| **Usage** | Log all keystrokes between a USB keyboard and target computer — invisibly |
| **Why** | Capture passwords, emails, chat — completely transparent to the user |
| **When** | Physical access; Pi placed inline between keyboard and computer |
| **How** | evdev reads keyboard on USB host port, forwards HID reports to /dev/hidg0 on OTG port, logs every keystroke with timestamps |
| **Config** | 2 USB ports required: Port 1 = keyboard (host), Port 2 = USB OTG to target (gadget). `apt install python3-evdev`. |
</details>

<details align="center">
<summary><b>usb_mass_storage</b> — USB drive emulation</summary>

| | |
|---|---|
| **Usage** | Present Pi as a USB flash drive with custom payload files |
| **Why** | Drop malicious files (autorun, LNK, documents) onto target |
| **When** | Physical access; USB social engineering |
| **How** | Creates FAT32 disk image, configfs mass_storage gadget, target sees a USB drive |
</details>

---

### 📤 Exfiltration Payloads

<details align="center">
<summary><b>auto_loot_exfil</b> — Automatic loot exfiltration daemon</summary>

| | |
|---|---|
| **Usage** | Set-and-forget: automatically sends new loot files as they appear |
| **Why** | Every payload's results are exfiltrated in real-time without intervention |
| **When** | Deploy with any attack payloads; results arrive automatically |
| **How** | Polls loot/ every 10s, sends via Discord/HTTP/DNS channel, manifest prevents re-sending |
| **Config** | Set channel: Discord (webhook in `/root/Raspyjack/discord_webhook.txt`), HTTP (URL in config), or DNS (domain in config). |
</details>

<details align="center">
<summary><b>ble_exfil</b> — BLE stealth exfiltration</summary>

| | |
|---|---|
| **Usage** | Exfiltrate data over BLE advertisements — no WiFi needed |
| **Why** | Ultra-stealth; works in air-gapped or WiFi-monitored environments |
| **When** | Network exfil is too risky; BLE receiver within ~10m range |
| **How** | Files fragmented into 20-byte BLE advertisement chunks with sequence headers, receiver reassembles |
| **Config** | Receiver must scan for BLE manufacturer ID `0xFFFF` to reassemble fragments. |
</details>

<details align="center">
<summary><b>dns_tunnel</b> — DNS exfiltration</summary>

| | |
|---|---|
| **Usage** | Exfiltrate data encoded in DNS subdomain queries |
| **Why** | DNS is rarely blocked — works through most firewalls |
| **When** | HTTP/HTTPS blocked but DNS queries allowed |
| **How** | Base32-encodes data as DNS subdomain labels, sends TXT queries to your domain, DNS server captures data |
| **Config** | Edit `/root/Raspyjack/config/dns_tunnel/config.json` — set `domain` to a domain you control with an authoritative DNS server. |
</details>

<details align="center">
<summary><b>exfil_ftp</b> — FTP loot server</summary>

| | |
|---|---|
| **Usage** | Run FTP server serving the loot directory for easy download |
| **Why** | Standard protocol; any FTP client can bulk-download loot |
| **When** | Network access to Pi; bulk loot retrieval |
| **How** | pyftpdlib or socket-based FTP serving loot/ read-only |
</details>

<details align="center">
<summary><b>exfil_smb</b> — SMB loot sharing</summary>

| | |
|---|---|
| **Usage** | Serve loot via SMB or upload to remote share |
| **Why** | Windows-native; browse from file explorer |
| **When** | Windows networks; easy loot access |
| **How** | impacket-smbserver serves loot/ or smbclient uploads to remote share |
</details>

<details align="center">
<summary><b>exfil_usb</b> — USB drive auto-copy</summary>

| | |
|---|---|
| **Usage** | Auto-copy all loot to a USB drive when inserted |
| **Why** | Physical exfiltration — plug in, wait, unplug |
| **When** | Retrieving loot via physical access |
| **How** | pyudev detects USB insertion, mounts, copies loot/ to timestamped folder, unmounts |
</details>

<details align="center">
<summary><b>exfiltrate_discord</b> — Discord webhook exfil</summary>

| | |
|---|---|
| **Usage** | Zip all loot and upload to Discord webhook |
| **Why** | Quick one-shot exfiltration; easy to set up, hard to block |
| **When** | Internet access + Discord webhook configured |
| **How** | In-memory ZIP of all loot directories, uploaded as file attachment |
| **Config** | Edit Discord webhook URL in source or set in `/root/Raspyjack/discord_webhook.txt`. |
</details>

<details align="center">
<summary><b>http_exfil</b> — HTTP chunked exfiltration</summary>

| | |
|---|---|
| **Usage** | Send loot files as base64 chunks via HTTPS POST |
| **Why** | Works through proxies/firewalls; configurable and stealthy |
| **When** | Exfil server set up to receive HTTP POST |
| **How** | Base64-encodes files, sends as JSON chunks, custom headers and auth support |
| **Config** | Edit `/root/Raspyjack/config/http_exfil/config.json` — set `target_url` to your exfil server endpoint. |
</details>

<details align="center">
<summary><b>icmp_tunnel</b> — ICMP covert channel</summary>

| | |
|---|---|
| **Usage** | Hide data in ICMP echo request payloads |
| **Why** | ICMP ping rarely blocked; payloads hard to detect |
| **When** | HTTP and DNS blocked but ping allowed |
| **How** | scapy encodes file data in ICMP payload, optional XOR encryption |
| **Config** | Set target IP of the receiving machine. Optional: XOR encryption key. |
</details>

---

### 🥷 Evasion Payloads

<details align="center">
<summary><b>fingerprint_spoof</b> — OS fingerprint spoofing</summary>

| | |
|---|---|
| **Usage** | Make the Pi appear as Windows, macOS, Cisco, or a printer to OS detection tools |
| **Why** | Fool nmap/p0f; avoid Pi-specific detection rules |
| **When** | Before any active operation |
| **How** | sysctl changes TTL (64 to 128 for Windows), TCP window size, DF bit. 5 presets |
</details>

<details align="center">
<summary><b>log_cleaner</b> — Forensic artifact cleanup</summary>

| | |
|---|---|
| **Usage** | Selectively clean operational traces while keeping loot |
| **Why** | Remove evidence before implant retrieval |
| **When** | End of engagement; before physical pickup |
| **How** | Shreds bash history, vacuums journal, flushes ARP/DNS cache, cleans auth logs. Never touches loot/ |
</details>

<details align="center">
<summary><b>mac_randomizer</b> — MAC address management</summary>

| | |
|---|---|
| **Usage** | Randomize, restore, or clone MAC addresses on any interface |
| **Why** | Bypass MAC-based NAC; avoid tracking; impersonate devices |
| **When** | Before network operations to avoid identification |
| **How** | `ip link set` to change MAC; supports random, restore, and clone from ARP-discovered devices |
</details>

<details align="center">
<summary><b>stealth_mode</b> — One-click invisibility</summary>

| | |
|---|---|
| **Usage** | Toggle all stealth measures: LEDs off, low WiFi power, random MACs, flush logs |
| **Why** | Minimize physical and electronic detectability in one action |
| **When** | After physical deployment; covert operations |
| **How** | Disables LEDs, reduces WiFi TX power, randomizes MACs, changes hostname, flushes logs. Fully reversible |
</details>

<details align="center">
<summary><b>timing_evasion</b> — Network timing randomizer</summary>

| | |
|---|---|
| **Usage** | Add random jitter to outgoing packets to evade timing-based IDS |
| **Why** | Many IDS detect scans by packet timing regularity |
| **When** | Before active scans or attacks |
| **How** | tc netem qdisc adds random delay: Light (1-10ms), Medium (10-50ms), Heavy (50-200ms) |
</details>

<details align="center">
<summary><b>traffic_shaper</b> — MITM stealth traffic control</summary>

| | |
|---|---|
| **Usage** | Shape traffic during MITM to keep latency unnoticeable |
| **Why** | MITM adds latency; suspicious slowness triggers investigation |
| **When** | During long-duration MITM operations |
| **How** | tc qdisc limits/prioritizes traffic to maintain baseline latency |
</details>

---

### 🔗 Remote Access Payloads

<details align="center">
<summary><b>pivot_proxy</b> — SOCKS5 pivot proxy</summary>

| | |
|---|---|
| **Usage** | SOCKS5 proxy for routing tools through the Pi into the internal network |
| **Why** | Pivot any external tool into the target network |
| **When** | After remote access established (Tailscale/SSH) |
| **How** | SOCKS5 CONNECT proxy on configurable port |
</details>

<details align="center">
<summary><b>port_forwarder</b> — TCP port forwarder</summary>

| | |
|---|---|
| **Usage** | Forward local ports to remote hosts through the Pi |
| **Why** | Expose internal services (RDP, SSH, web apps) externally |
| **When** | Need remote access to specific internal services |
| **How** | Bi-directional TCP relay, multiple rules supported |
</details>

<details align="center">
<summary><b>reverse_shell_gen</b> — Reverse shell generator</summary>

| | |
|---|---|
| **Usage** | Generate reverse shell one-liners + HTTP server + nc listener |
| **Why** | Quick payload generation for post-exploitation |
| **When** | After compromising a host; need shell callback |
| **How** | Generates bash/Python/PS/PHP/Perl/nc one-liners, serves via HTTP, starts listener |
</details>

<details align="center">
<summary><b>reverse_ssh</b> — Persistent reverse SSH tunnel</summary>

| | |
|---|---|
| **Usage** | Maintain persistent reverse SSH to external server |
| **Why** | Remote access through NAT/firewall with auto-reconnection |
| **When** | Long-term implant deployment |
| **How** | autossh with ServerAliveInterval, forwards port back to Pi's SSH |
| **Config** | `apt install autossh` — Edit `/root/Raspyjack/config/reverse_ssh/config.json` (remote_host, remote_user, ssh_key_path). Generate keypair with KEY2, add pubkey to remote server. |
</details>

<details align="center">
<summary><b>shell</b> — LCD terminal</summary>

| | |
|---|---|
| **Usage** | Interactive bash on the 128x128 LCD via USB keyboard |
| **Why** | Full command-line without network; troubleshooting on-device |
| **When** | WiFi/WebUI unavailable; direct physical access |
| **How** | PTY-based bash, evdev keyboard input, LCD terminal rendering with zoom |
</details>

<details align="center">
<summary><b>tailscale_control</b> — Tailscale VPN manager</summary>

| | |
|---|---|
| **Usage** | Control Tailscale VPN from the LCD |
| **Why** | Manage remote access tunnel without SSH |
| **When** | Enable/disable Tailscale, check status |
| **How** | Wraps tailscale CLI with LCD UI |
</details>

---

### 🔍 Reconnaissance Payloads

<details align="center">
<summary><b>ad_recon</b> — Active Directory enumeration</summary>

| | |
|---|---|
| **Usage** | Enumerate AD users, groups, computers, GPOs via LDAP |
| **Why** | Map the AD for attack paths, admin accounts, high-value targets |
| **When** | Network access to domain controller (port 389/636) |
| **How** | ldapsearch or raw LDAP socket for anonymous/null-session enumeration |
| **Config** | Network access to a domain controller (port 389/636). Optional: `apt install ldap-utils`. |
</details>

<details align="center">
<summary><b>analyzer</b> — RF spectrum analyzer</summary>

| | |
|---|---|
| **Usage** | Real-time WiFi and BLE spectrum analysis |
| **Why** | Identify congested channels, hidden networks, BLE devices |
| **When** | Pre-engagement site survey |
| **How** | Scans 2.4/5 GHz WiFi + BLE, displays channel usage with peak detection |
</details>

<details align="center">
<summary><b>arp_scan_stealth</b> — Stealthy ARP scanner</summary>

| | |
|---|---|
| **Usage** | Slow ARP scan with randomized timing to evade IDS |
| **Why** | Fly under ARP scan detection thresholds |
| **When** | Networks with ARP scan monitoring |
| **How** | Randomized host order, 1-3s jitter, optional MAC spoofing |
</details>

<details align="center">
<summary><b>autoNmapScan</b> — Periodic Nmap scanner</summary>

| | |
|---|---|
| **Usage** | Automated Nmap scans on a schedule |
| **Why** | Recurring recon; detect new hosts over time |
| **When** | Long-term monitoring |
| **How** | Nmap at configurable intervals, saves to loot |
</details>

<details align="center">
<summary><b>auto_recon</b> — Plug-and-pwn auto recon</summary>

| | |
|---|---|
| **Usage** | Zero-interaction: ARP scan + nmap + Discord exfil automatically |
| **Why** | Drop and walk away; results arrive on Discord |
| **When** | Quick physical deployment (Shark Jack style) |
| **How** | Detects interface, ARP scans, nmap top-100, saves JSON, sends to Discord webhook |
| **Config** | Optional: set Discord webhook in `/root/Raspyjack/discord_webhook.txt` for auto-exfil. |
</details>

<details align="center">
<summary><b>bt_scan_classic</b> — Bluetooth Classic scanner</summary>

| | |
|---|---|
| **Usage** | Discover BT devices and enumerate their services (SDP) |
| **Why** | Find keyboards, mice, speakers, phones and their exposed services |
| **When** | Bluetooth recon |
| **How** | hcitool scan + sdptool browse for service enumeration |
</details>

<details align="center">
<summary><b>cam_finder</b> — Security camera detector</summary>

| | |
|---|---|
| **Usage** | Detect cameras by filtering WiFi for camera manufacturer OUIs |
| **Why** | Quickly identify surveillance cameras on network/WiFi |
| **When** | Physical security assessment |
| **How** | WiFi scan filtered for camera OUIs (Ring, Nest, Wyze, Hikvision, Dahua, etc.) |
</details>

<details align="center">
<summary><b>cctv_scanner</b> — CCTV camera discovery pipeline</summary>

| | |
|---|---|
| **Usage** | 8-stage camera discovery: scan, fingerprint, default creds, find streams |
| **Why** | Many IP cameras use default credentials — find and access them |
| **When** | Network access; camera security audit |
| **How** | Port scan (554, 8080, ONVIF), brand fingerprint (Hikvision/Dahua/Axis), test default creds, probe RTSP/MJPEG streams |
</details>

<details align="center">
<summary><b>cctv_viewer</b> — Live camera viewer on LCD</summary>

| | |
|---|---|
| **Usage** | Stream MJPEG camera feeds on the 128x128 LCD |
| **Why** | View cameras directly on device without a computer |
| **When** | After cctv_scanner discovers streams |
| **How** | HTTP streaming of multipart MJPEG, JPEG decode with PIL, 128x128 resize, LEFT/RIGHT switches cameras |
| **Config** | Populate `loot/CCTV/cctv_live.txt` from CCTV Scanner first (or add URLs manually: `Name | http://url`). |
</details>

<details align="center">
<summary><b>cert_scanner</b> — TLS certificate analyzer</summary>

| | |
|---|---|
| **Usage** | Extract hostnames, issuers, and misconfigurations from TLS certificates |
| **Why** | Internal hostnames leak in SAN fields; expired/self-signed certs reveal weak security |
| **When** | After discovering HTTPS services |
| **How** | ssl stdlib connects to TLS ports, extracts CN, SAN, issuer, validity, key size |
</details>

<details align="center">
<summary><b>device_scout</b> — WiFi + BLE device tracker</summary>

| | |
|---|---|
| **Usage** | Scan for WiFi and BLE devices with tracker detection (AirTag, Tile, etc.) |
| **Why** | Counter-surveillance; detect hidden trackers |
| **When** | Physical security sweeps |
| **How** | Simultaneous WiFi + BLE scan, identifies known tracker manufacturers, persistence scoring |
</details>

<details align="center">
<summary><b>dns_leaker</b> — Passive DNS/NBNS monitor</summary>

| | |
|---|---|
| **Usage** | Monitor DNS and NBNS queries to discover services passively |
| **Why** | Learn internal naming, find servers — all without sending a packet |
| **When** | Early recon; passive intelligence during MITM |
| **How** | Sniffs DNS (UDP 53) and NBNS (UDP 137), logs queried hostnames and clients |
</details>

<details align="center">
<summary><b>gatt_enum</b> — BLE GATT enumerator</summary>

| | |
|---|---|
| **Usage** | Map the full BLE service/characteristic API of a target device |
| **Why** | Find read/write/notify characteristics for exploitation |
| **When** | After ble_scanner identifies a target |
| **How** | gatttool connects and walks the GATT table listing services, characteristics, properties |
</details>

<details align="center">
<summary><b>honeypot</b> — Multi-port TCP honeypot</summary>

| | |
|---|---|
| **Usage** | Listen on multiple ports to detect and log unauthorized access attempts |
| **Why** | Early warning; detect attackers and malware scanning the network |
| **When** | Defensive; network monitoring |
| **How** | Listens on HTTP/SSH/Telnet/FTP/SMTP ports, JSONL logging, optional Discord alerts |
</details>

<details align="center">
<summary><b>mac_lookup</b> — MAC vendor lookup</summary>

| | |
|---|---|
| **Usage** | Identify device manufacturers from MAC addresses |
| **Why** | Reveals device types — Cisco routers, HP printers, Apple phones |
| **When** | After ARP/WiFi scans; enriching host data |
| **How** | IEEE OUI database (auto-downloaded), falls back to built-in 200 vendors |
</details>

<details align="center">
<summary><b>navarro</b> — Username OSINT</summary>

| | |
|---|---|
| **Usage** | Check if a username exists on 25+ online platforms |
| **Why** | Build target profiles from a single username |
| **When** | After obtaining a username from credential sniffing |
| **How** | Queries GitHub, Twitter, Instagram, LinkedIn, and 20+ more platforms |
</details>

<details align="center">
<summary><b>network_mapper</b> — Visual topology map</summary>

| | |
|---|---|
| **Usage** | Render network topology on the LCD screen |
| **Why** | Quick visual understanding of network layout |
| **When** | After scanning; situational awareness |
| **How** | Combines ARP + nmap data, renders nodes as colored boxes with connections |
</details>

<details align="center">
<summary><b>passive_os_detect</b> — Passive OS fingerprinting</summary>

| | |
|---|---|
| **Usage** | Identify OSes from TCP/IP fingerprints without sending probes |
| **Why** | Know Windows/Linux/macOS hosts passively |
| **When** | During MITM or passive capture |
| **How** | Analyzes TCP SYN: TTL, window size, MSS, DF bit against p0f-style signatures |
</details>

<details align="center">
<summary><b>service_banner</b> — Service version grabber</summary>

| | |
|---|---|
| **Usage** | Grab banners from open ports to identify software versions |
| **Why** | Software versions reveal specific vulnerabilities |
| **When** | After port scanning |
| **How** | Connects to common ports, sends protocol probes, captures response banners |
</details>

<details align="center">
<summary><b>smb_probe</b> — SMB host scanner</summary>

| | |
|---|---|
| **Usage** | Find hosts with SMB (port 445) open |
| **Why** | SMB hosts = file servers, DCs, print servers — high-value targets |
| **When** | Windows network recon |
| **How** | TCP 445 connect scan across local subnet |
</details>

<details align="center">
<summary><b>sniff_creds_live</b> — Credential aggregator dashboard</summary>

| | |
|---|---|
| **Usage** | Unified view of ALL credentials captured by every payload |
| **Why** | One screen to see everything — no checking each payload's loot |
| **When** | During or after engagement; unified credential overview |
| **How** | Scans 9 loot directories, parses each format, unified scrollable list with protocol filter |
</details>

<details align="center">
<summary><b>spycam_detector</b> — Hidden camera finder</summary>

| | |
|---|---|
| **Usage** | Detect hidden WiFi cameras by SSID patterns and manufacturer OUIs |
| **Why** | Find surveillance in hotel rooms, meeting rooms, Airbnbs |
| **When** | Physical security sweeps; counter-surveillance |
| **How** | Scans for IPCAM*/CAM-*/PV-* SSIDs, camera manufacturer OUIs, RSSI proximity estimation |
</details>

<details align="center">
<summary><b>subnet_mapper</b> — Full subnet mapping</summary>

| | |
|---|---|
| **Usage** | ARP scan + ports + OS detection in one pass |
| **Why** | Complete network picture with one command |
| **When** | Initial reconnaissance |
| **How** | ARP discovers hosts, SYN scans top 20 ports, OS guess from TTL |
</details>

<details align="center">
<summary><b>wall_of_flippers</b> — Flipper Zero detector</summary>

| | |
|---|---|
| **Usage** | Detect and track Flipper Zero devices via BLE |
| **Why** | Identify devices that might be attacking your network |
| **When** | Defensive; conference security |
| **How** | BLE scanner filtering for Flipper Zero characteristics |
</details>

<details align="center">
<summary><b>wardriving</b> — WiFi network mapper with GPS</summary>

| | |
|---|---|
| **Usage** | Map WiFi networks with optional GPS coordinates |
| **Why** | Geographic WiFi intelligence; find target networks |
| **When** | Pre-engagement recon; infrastructure mapping |
| **How** | Passive WiFi scan + GPS logging, exports JSON/CSV/KML |
</details>

<details align="center">
<summary><b>whois_lookup</b> — WHOIS + reverse DNS</summary>

| | |
|---|---|
| **Usage** | Look up organizations behind external IPs in captured traffic |
| **Why** | Identify communication targets and partners |
| **When** | After MITM; analyzing external communications |
| **How** | WHOIS queries + socket.getfqdn reverse DNS |
</details>

<details align="center">
<summary><b>wifi_client_map</b> — WiFi client-to-AP mapper</summary>

| | |
|---|---|
| **Usage** | Map which clients are connected to which access points |
| **Why** | Understand WiFi topology; find high-value targets |
| **When** | WiFi recon; before targeted attacks |
| **How** | Passive 802.11 FromDS/ToDS bit analysis |
</details>

---

### 🛠️ Utilities Payloads

<details align="center">
<summary><b>auto_update</b> — System updater</summary>

| | |
|---|---|
| **Usage** | Backup + git pull + restart services |
| **Why** | Keep RaspyJack up to date |
| **When** | Internet connected |
| **How** | Backs up, git pulls, restarts systemd services |
</details>

<details align="center">
<summary><b>bt_keyboard_picker</b> — BT keyboard pairing</summary>

| | |
|---|---|
| **Usage** | Scan, pair, and connect Bluetooth keyboards via LCD |
| **Why** | Set up keyboard for shell payload |
| **When** | Keyboard setup |
| **How** | bluetoothctl scan/pair/trust/connect |
</details>

<details align="center">
<summary><b>c2_dashboard</b> — C2 overview dashboard</summary>

| | |
|---|---|
| **Usage** | Running payloads, loot stats, network, services — all on one screen |
| **Why** | Single-screen operational status |
| **When** | Check implant status during engagement |
| **How** | Reads /proc, loot dirs, interface IPs, systemctl. Auto-refreshes 5s |
</details>

<details align="center">
<summary><b>engagement_timer</b> — Operation countdown</summary>

| | |
|---|---|
| **Usage** | Timer with phase tracking for timed engagements |
| **Why** | Stay on schedule; track operational phases |
| **When** | Start of any timed engagement |
| **How** | Set duration, track phases (Recon/Exploit/Persist/Exfil/Cleanup), Discord alert on expiry |
</details>

<details align="center">
<summary><b>fast_wifi_connect</b> — Quick WiFi connect</summary>

| | |
|---|---|
| **Usage** | Auto-connect to strongest saved network |
| **Why** | Instant internet without menu navigation |
| **When** | Deployment; quick setup |
| **How** | Scans, matches saved profiles, connects to strongest |
</details>

<details align="center">
<summary><b>fast_wifi_switcher</b> — Interface toggle</summary>

| | |
|---|---|
| **Usage** | Switch between wlan0 and wlan1 quickly |
| **Why** | Toggle management vs attack interface |
| **When** | Switching operational modes |
| **How** | nmcli/ip interface selection |
</details>

<details align="center">
<summary><b>interface_status</b> — Network interface monitor</summary>

| | |
|---|---|
| **Usage** | Live eth0/eth1 status and traffic stats |
| **Why** | Quick connectivity check |
| **When** | Troubleshooting |
| **How** | Reads /sys/class/net for state and RX/TX bytes |
</details>

<details align="center">
<summary><b>keyboard_tester</b> — USB keyboard test</summary>

| | |
|---|---|
| **Usage** | Display key presses on LCD |
| **Why** | Verify keyboard works before using shell |
| **When** | After keyboard connection |
| **How** | evdev key events displayed on LCD |
</details>

<details align="center">
<summary><b>LanTest</b> — LAN speed test</summary>

| | |
|---|---|
| **Usage** | Measure LAN throughput via iperf3 |
| **Why** | Network performance baseline |
| **When** | Diagnostics |
| **How** | iperf3 against target server |
</details>

<details align="center">
<summary><b>latency</b> — RTT and jitter monitor</summary>

| | |
|---|---|
| **Usage** | TCP latency monitor with rolling graph |
| **Why** | Detect issues; measure MITM overhead |
| **When** | During MITM or diagnostics |
| **How** | TCP connect RTT to targets, rolling graph display |
</details>

<details align="center">
<summary><b>loot_browser</b> — File browser for loot</summary>

| | |
|---|---|
| **Usage** | Browse loot/ on LCD with file preview |
| **Why** | Review captured data in the field |
| **When** | Quick loot review |
| **How** | File browser with navigation, text preview, size display |
</details>

<details align="center">
<summary><b>notification_center</b> — Alert aggregator</summary>

| | |
|---|---|
| **Usage** | Central notification feed from all payloads |
| **Why** | Know when any payload captures something |
| **When** | Leave running during operations |
| **How** | Watches .notifications.jsonl + new loot, color-coded severity, Discord push |
</details>

<details align="center">
<summary><b>packet_replay</b> — PCAP replayer</summary>

| | |
|---|---|
| **Usage** | Replay .pcap files from loot |
| **Why** | Reproduce network conditions; test IDS |
| **When** | Testing; analysis |
| **How** | scapy PcapReader (streaming, memory-safe), sendp replay |
</details>

<details align="center">
<summary><b>payload_scheduler</b> — Cron-like scheduler</summary>

| | |
|---|---|
| **Usage** | Schedule payloads at specific times or on repeat |
| **Why** | Automate operations — recon every 4 hours, exfil at midnight |
| **When** | Long-term deployment |
| **How** | Config in /root/Raspyjack/config/scheduler/, checks every 30s, launches subprocesses |
| **Config** | Schedules stored in `/root/Raspyjack/config/scheduler/schedule.json`. |
</details>

<details align="center">
<summary><b>qr_generator</b> — QR code display</summary>

| | |
|---|---|
| **Usage** | Generate QR on LCD: IP, WebUI URL, WiFi, custom text |
| **Why** | Share access info instantly by phone scan |
| **When** | Setup; team coordination |
| **How** | python3-qrcode, 120x120 centered on LCD |
</details>

<details align="center">
<summary><b>system_monitor</b> — Resource dashboard</summary>

| | |
|---|---|
| **Usage** | CPU, RAM, temp, disk, uptime, network — real-time |
| **Why** | Monitor Pi health; detect overheating or memory pressure |
| **When** | During intensive operations |
| **How** | Reads /proc/stat, /proc/meminfo, thermal_zone, os.statvfs, /proc/net/dev |
</details>

<details align="center">
<summary><b>WanTest</b> — Internet speed test</summary>

| | |
|---|---|
| **Usage** | Download/upload speed measurement |
| **Why** | Verify bandwidth for exfiltration |
| **When** | After internet connection |
| **How** | speedtest-cli |
</details>

<details align="center">
<summary><b>webui</b> — WebUI URL display</summary>

| | |
|---|---|
| **Usage** | Show WebUI URL on LCD |
| **Why** | Find the URL to access from browser |
| **When** | Setup |
| **How** | Detects IPs, displays https://IP/ |
</details>

<details align="center">
<summary><b>wifi_manager_payload</b> — WiFi management UI</summary>

| | |
|---|---|
| **Usage** | Full WiFi management on LCD |
| **Why** | Manage profiles, scan, connect without SSH |
| **When** | WiFi setup |
| **How** | Launches WiFi LCD management interface |
</details>

---

### 🔧 Hardware Payloads

<details align="center">
<summary><b>gpio_tripwire</b> — Physical intrusion detector</summary>

| | |
|---|---|
| **Usage** | Monitor GPIO pins for door sensors, PIR motion, etc. |
| **Why** | Alert when someone approaches the implant or enters a room |
| **When** | Physical security; implant protection |
| **How** | GPIO interrupt on state change, LCD alert + Discord webhook + optional buzzer |
| **Config** | Wire sensors to GPIO pins. Optional: Discord webhook for remote alerts. |
</details>

<details align="center">
<summary><b>gps_tracker</b> — GPS logging</summary>

| | |
|---|---|
| **Usage** | Continuous GPS tracking with NMEA parsing |
| **Why** | Geo-tag data; wardriving integration; movement tracking |
| **When** | GPS module connected (NEO-6M via serial) |
| **How** | Parses $GPGGA/$GPRMC for lat/lon/speed/altitude, CSV + GPX export |
| **Config** | Serial GPS module (e.g. NEO-6M) on `/dev/ttyUSB0` or `/dev/serial0` at 9600 baud. |
</details>

<details align="center">
<summary><b>i2c_scanner</b> — I2C bus scanner</summary>

| | |
|---|---|
| **Usage** | Discover I2C devices connected to the Pi |
| **Why** | Identify sensors, displays, modules |
| **When** | Hardware setup; device identification |
| **How** | smbus probes 127 addresses, matches against known device database |
</details>

<details align="center">
<summary><b>led_control</b> — LED status patterns</summary>

| | |
|---|---|
| **Usage** | Visual status feedback via Pi LEDs |
| **Why** | At-a-glance operational state |
| **When** | During operations; stealth (all off) |
| **How** | sysfs LED control: idle/scanning/attacking/alert/stealth patterns |
</details>

<details align="center">
<summary><b>nfc_reader</b> — NFC/RFID card reader</summary>

| | |
|---|---|
| **Usage** | Read NFC cards — UIDs, NDEF, MIFARE sector dumps |
| **Why** | Clone access cards; test NFC security |
| **When** | PN532 module connected via I2C |
| **How** | I2C communication with PN532, card polling, MIFARE Classic dumps with default keys |
| **Config** | PN532 NFC module connected via I2C (addr 0x24). `dtparam=i2c_arm=on` in config.txt. |
</details>

---

### 🎮 Games (16)

> All games: **D-pad** = move, **OK** = action, **KEY1** = restart, **KEY3** = exit

<details align="center">
<summary>View all 16 games</summary>

| Game | Description |
|------|-------------|
| **game_2048** | Sliding number puzzle — merge tiles to reach 2048 |
| **game_asteroids** | Rotating ship, thrust, shoot splitting asteroids |
| **game_Breakout** | Classic brick breaker with paddle and ball |
| **game_connect4** | Connect 4 vs minimax AI (3 difficulty levels) |
| **game_flappy** | Flappy Bird — tap to flap, dodge pipes |
| **game_frogger** | Cross roads and rivers, ride logs, fill 5 home slots |
| **game_minesweeper** | 8x8 grid, 10 mines, flag and reveal |
| **game_pacman** | Pac-Man with 4 AI ghosts (Blinky, Pinky, Inky, Clyde) |
| **game_pong** | Pong vs AI with increasing ball speed |
| **game_simon** | Simon Says memory sequence with 4 colors |
| **game_snake** | Classic Snake — eat, grow, don't crash |
| **game_sokoban** | Box-pushing puzzle, 10 levels, undo support |
| **game_space_invaders** | 4 rows of aliens, shields, 3 lives |
| **game_tetris** | Rotate, move, drop, clear lines |
| **game_tictactoe** | Tic-Tac-Toe vs unbeatable minimax AI |
| **conways_game_of_life** | Cellular automaton simulation |
</details>
