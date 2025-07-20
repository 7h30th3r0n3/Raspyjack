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
| **Waveshare 1.44″ LCD HAT** | SPI TFT + joystick + 3 buttons | [Buy 🔗](https://s.click.aliexpress.com/e/_oEmEUZW) |
| **Raspberry Pi Zero 2 WH** | Quad-core 1 GHz, 512 MB RAM – super compact | [Buy 🔗](https://s.click.aliexpress.com/e/_omuGisy) |
| **RPI 0w with Waveshare Ethernet/USB HUB HAT** | 3 USB + 1 Ethernet | [Buy 🔗](https://s.click.aliexpress.com/e/_oDK0eYc) |
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
| Q (KEY1) | extra in dialogs |

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
│
├── DNSSpoof/
│   ├── captures/
│   └── sites/
│
├── loot/
│   ├── MITM/
│   └── Nmap/
│
└── Responder/
```

---

## 🛡️  Disclaimer

Educational & authorised testing only – use responsibly.

---

## 📄  License

MIT
