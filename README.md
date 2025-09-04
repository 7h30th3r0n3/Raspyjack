<p align="center">
  <img src="https://img.shields.io/badge/platform-Raspberry%20Pi-red?style=flat-square&logo=raspberry-pi">
  <img src="https://img.shields.io/badge/usage-educational%20only-blue?style=flat-square">
  <img src="https://img.shields.io/badge/code-python3-yellow?style=flat-square&logo=python">
</p>

<div align="center">
  <h1>RaspyJack</h1>

  <img src="github-img/logo.jpg" width="250"/>

  <p>
    Small <strong>network offensive toolkit</strong> for Raspberry&nbsp;Pi
    (+ Waveshare&nbsp;1.44″ LCD HAT).
  </p>

> ⚠️ **For educational and authorized testing purposes only, always use responsibly and legally.**  
>   
> RaspyJack is an offensive security toolkit intended for cybersecurity professionals, researchers, penetration testers, and ethical hackers.  
> Any use on networks or systems without the explicit consent of the owner is **illegal** and **strictly prohibited**.  
>   
> The author cannot be held responsible for any misuse or unlawful activity involving this project
> 
> **Full responsibility for any use of this tool rests solely with the user.**.

---

  Join the Evil-M5 discord for help and updates on RaspyJack channel😉:

  <a href="https://discord.com/invite/qbwAJch25S">
    <img src="https://cdn.prod.website-files.com/6257adef93867e50d84d30e2/66e278299a53f5bf88615e90_Symbol.svg" width="75" alt="Join Discord" />
  </a>
  
---
## ✨  Features

| Category | Built‑in actions |
|----------|-----------------|
| **Recon** | Multiple customizable Nmap scan |
| **Shells** | One‑click reverse shell with IP selection or preconfigured IP |
| **Creds capture** | Responder, ARP MITM + sniff, DNS‑spoof phishing |
| **Loot viewer** | Read Nmap scan / Responder / DNSSpoof logs on‑device |
| **File browser** | Lightweight text & image explorer |
| **System** | Theme editor, config save/restore, UI restart, shutdown |
| **Custom Script** | Custom python script can be added |
| **WiFi Attacks** | Deauth attacks, WiFi interface management, USB dongle support |
| **Boot time** | On rpi 0w2 : ~22sec  |

---

## 🛠  Hardware

| Item | Description | Buy|
|------|-------------|-------------------|
| **Waveshare 1.44″ LCD HAT** | SPI TFT + joystick + 3 buttons | [Buy 🔗](https://s.click.aliexpress.com/e/_oEmEUZW) <br>or  <br>[Buy 🔗](https://s.click.aliexpress.com/e/_EwDqSv4)|
| **Raspberry Pi Zero 2 WH** | Quad-core 1 GHz, 512 MB RAM – super compact | [Buy 🔗](https://s.click.aliexpress.com/e/_omuGisy) |
| **RPI 0w with Waveshare Ethernet/USB HUB HAT** | 3 USB + 1 Ethernet | [Buy 🔗](https://s.click.aliexpress.com/e/_oDK0eYc) |
| **Alternative : Dual Ethernet/USB HUB HAT** | 2 USB + 2 Ethernet | [Buy 🔗](https://s.click.aliexpress.com/e/_oCX3pUA) |
---

Others hardwares : 
| Item | Description | Buy|
|------|-------------|-------------------|
| **Raspberry Pi 4 Model B** (4 GB) | Quad-core 1.5 GHz, full-size HDMI, GigE LAN | [Buy 🔗](https://s.click.aliexpress.com/e/_oFOHQdm) |
| **Raspberry Pi 5** (8 GB) | Quad-core Cortex-A76 2.4 GHz, PCIe 2.0 x1 | [Buy 🔗](https://s.click.aliexpress.com/e/_oC6NEZe) |

*not tested yet on **Raspberry Pi 5** feedback are welcome in issue for tested working devices

---

## 📡 WiFi Attack Requirements

**⚠️ Important:** The onboard Raspberry Pi WiFi (Broadcom 43430) **cannot** be used for WiFi attacks due to hardware limitations.

### Required USB WiFi Dongles for WiFi Attacks:

| Dongle | Chipset | Monitor Mode | Buy |
|--------|---------|--------------|-----|
| **Alfa AWUS036ACH** | Realtek RTL8812AU | ✅ Full support |  |
| **TP-Link TL-WN722N v1** | Atheros AR9271 | ✅ Full support |  |
| **Panda PAU09** | Realtek RTL8812AU | ✅ Full support |  |

**Features:**
- **Deauth attacks** on 2.4GHz and 5GHz networks
- **Multi-target attacks** with interface switching
- **Automatic USB dongle detection** and setup
- **Research-based attack patterns** for maximum effectiveness

---

## 🚀 Installation and Setup 

### Part 1 : setup OS 
note : This installation is for a Raspberry Pi 0w2 (can probably be customized for others rpi).

<div align="center">

<img src="https://github.com/7h30th3r0n3/Raspyjack/blob/main/github-img/img-tuto/tuto1.png" width="400"/>  

Install Raspberry Pi imager

---

<img src="https://github.com/7h30th3r0n3/Raspyjack/blob/main/github-img/img-tuto/tuto2.png" width="400"/>  

Select Raspberry Pi Zero 2 W

---
<img src="https://github.com/7h30th3r0n3/Raspyjack/blob/main/github-img/img-tuto/tuto3.png" width="400"/>  

Go in Raspberry Pi OS (other)  

---
<img src="https://github.com/7h30th3r0n3/Raspyjack/blob/main/github-img/img-tuto/tuto4.png" width="400"/>  

Select Raspberry Pi OS Lite (32-bit)  

---
<img src="https://github.com/7h30th3r0n3/Raspyjack/blob/main/github-img/img-tuto/tuto5.png" width="400"/>  

Select your SD card 

---
<img src="https://github.com/7h30th3r0n3/Raspyjack/blob/main/github-img/img-tuto/tuto6.png" width="400"/>  

Change settings to configure user and enable SSH

---
<img src="https://github.com/7h30th3r0n3/Raspyjack/blob/main/github-img/img-tuto/tuto7.png" width="400"/></br>

<img src="https://github.com/7h30th3r0n3/Raspyjack/blob/main/github-img/img-tuto/tuto8.png" width="400"/>  

Set username and password and enable SSH

---
</div>
</div>

You can now connect to it on ssh using 
```bash
ssh raspyjack@<IP> 
```
</div>


### Part 2 : setup Raspyjack

```bash
sudo apt install git
sudo su
cd
git clone https://github.com/7h30th3r0n3/raspyjack.git
mv raspyjack Raspyjack
cd Raspyjack
chmod +x install_raspyjack.sh
sudo ./install_raspyjack.sh
sudo reboot
```
Note : Depending on the way you get the project Raspyjack-main can take multiple name. Just be sure that Raspyjack folder are in /root.

### Update

⚠️ Before updating backup your loot. 

```bash
sudo su
cd /root
rm -rf Raspyjack
git clone https://github.com/7h30th3r0n3/raspyjack.git
mv raspyjack Raspyjack
sudo reboot
```

---

### Part 3 : WiFi Attack Setup (Optional)

**For WiFi attacks, you need a USB WiFi dongle:**

1. **Plug in USB WiFi dongle** (see requirements above)
2. **Run WiFi Manager** from RaspyJack menu
3. **Configure WiFi profiles** for auto-connect
4. **Test interface switching** between wlan0/wlan1
5. **Run deauth attacks** on target networks

**Quick Test:**
```bash
cd /root/Raspyjack/payloads
python3 fast_wifi_switcher.py
```

---

## 🎮  Keymap

| Key | Action |
|-----|--------|
| ↑ / ↓ | navigate |
| → or OK | enter / validate |
| ← or BACK | go back |
| Q (KEY1) | toggle view mode / extra in dialogs |

---

## 🧩 Plugin System

RaspyJack features a **modular plugin system** that allows adding custom functionality without modifying the main code.

### Key Features:
- 🔧 **Event callbacks** (buttons, render, payloads, scans)
- 📦 **Executable commands** exposed globally via `bin/`
- ⚙️ **Flexible JSON configuration** per plugin
- 🎨 **Customizable HUD overlays**
- 🔄 **Configurable priorities** for execution order

### Basic structure:
```
plugins/
  my_plugin/
    __init__.py      # Entry point
    _impl.py         # Implementation
    bin/             # Exposed commands
    helpers/         # Auxiliary modules
```

### Included plugins:
- **`battery_status_plugin`** - Battery monitor in HUD
- **`temperature_plugin`** - CPU temperature monitor  
- **`discord_notifier_plugin`** - Discord notifications + exfiltration commands

📖 **Complete documentation**: [`plugins/README.md`](plugins/README.md)

---

---

## 🎨  View Modes

RaspyJack features **three different view modes** to navigate the main menu! Press **KEY1** to cycle through them:

### 📋  **List View** (Default)
- Classic vertical scrolling list
- Shows 7 items at once with smooth scrolling
- Perfect for quick navigation
- Displays icons alongside menu text

### 🔲  **Grid View** 
- Compact 2×4 grid layout showing 8 items
- Great for seeing multiple options at once
- Navigate with directional arrows
- Ideal for overview of all tools

### 🔄  **Carousel View**
- **Single-item display** with icons centered
- Shows one tool at a time with detailed focus
- **Wraparound navigation** - seamlessly cycle from last to first
- Features prominent icons and clear tool names

**How to switch:** Simply press the **KEY1** while on the main menu to cycle through: **List → Grid → Carousel → List**

Choose the one that fits your workflow best! 🚀

---

## 📡 Discord Webhook Integration

RaspyJack supports **Discord webhook integration** for Nmap scan results! Get instant notifications with full scan details and a downloadable .txt file of the Nmap results directly in your Discord server.

### 🔧 Setup Instructions

1. **Create a Discord Webhook:**
   - Go to your Discord server
   - Right-click on a channel → **Edit Channel** → **Integrations** → **Webhooks**
   - Click **"New Webhook"**
   - Copy the webhook URL

2. **Configure RaspyJack:**
   - Edit `/root/Raspyjack/discord_webhook.txt`
   - Replace the placeholder with your actual webhook URL:
   ```
   https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN
   ```

3. **Restart RaspyJack** to load the configuration

### 📊 What You'll Receive

When any Nmap scan completes, you'll get a Discord message with:
- **Scan type** and target network
- **Interface** used for scanning
- **Timestamp** of completion
- **Complete scan results as a downloadable file attachment**
- **File information** (filename, size)
- **Color-coded** embed for easy identification

### 📁 File Attachments

- Scan results are sent as `.txt` files
- Files are automatically named with scan type and timestamp
- Discord supports files up to 25MB (plenty for Nmap results)
- **No more character limits or truncated output!**

### ✅ Status Check

Check your webhook status in **Network Info**:
- **✅ Webhook configured** - Ready to send notifications
- **❌ No webhook** - Configuration needed

### 🔄 Supported Scans

Works with **all Nmap scan types**:
- Quick Scan, Full Port Scan, Service Scan
- Vulnerability Scan, OS Scan, Intensive Scan
- Stealth SYN Scan, UDP Scan, Ping Sweep
- Top100 Scan, HTTP Enumeration

**Note:** If no webhook is configured, scans will still save results locally - no functionality is lost!

---

## 📂  Layout

```
raspyjack/
├── raspyjack.py
├── install.sh
├── gui_conf.json
├── LCD_1in44.py
├── LCD_1in44.pyc
├── LCD_Config.py
├── LCD_Config.pyc
│
├── img/
│   └── logo.bmp
│
├── wifi/
│   ├── raspyjack_integration.py
│   ├── wifi_manager.py
│   ├── wifi_lcd_interface.py
│   └── profiles/
│
├── payloads/
│   ├── example_show_buttons.py
│   ├── exfiltrate_discord.py
│   ├── snake.py
│   ├── deauth.py
│   ├── fast_wifi_switcher.py
│   └── wifi_manager_payload.py
|
├── plugins/
│   ├── base.py
│   ├── battery_status_plugin/
│   │   ├── __init__.py
│   │   └── _impl.py
│   ├── temperature_plugin/
│   │   ├── __init__.py
│   │   └── _impl.py
│   ├── discord_notifier_plugin/
│   │   ├── __init__.py
│   │   ├── _impl.py
│   │   └── bin/
│   │       └── DISCORD_TEST
│
├── DNSSpoof/
│   ├── captures/
│   └── sites/
│
├── loot/
│   ├── MITM/
│   └── Nmap/
│
└── bin/
└── Responder/
```

---

## 🛡️  Disclaimer

Educational & authorised testing only – use responsibly.

---

## Acknowledgements

- [@dagnazty](https://github.com/dagnazty)
- [@Hosseios](https://github.com/Hosseios)
- [@m0usem0use](https://github.com/m0usem0use)

---

<div align="center">
⚠️ NOTE WARNING ! Coffee, coke and lemonade can cause a DoS on the equipment if spilled on it. ⚠️ <br>
Due to multiple event during the devellopement I recommand to NEVER put any brevage around the project.<br>
Considering this note we are not reliable to any mistake or miss use of this kind.
</div>

---

