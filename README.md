<div align="center">

  <h1>RaspyJack</h1>

  <img src="github-img/logo.jpg" width="250"/>

  <p>
    Small <strong>network offensive toolkit</strong> for Raspberry&nbsp;Pi
    (+ Waveshare&nbsp;1.44″ LCD HAT).
  </p>

</div>

---

## ✨  Features

| Category | Built‑in actions |
|----------|-----------------|
| **Recon** | Quick / full / service / vuln / OS Nmap scans |
| **Shells** | One‑click reverse shell |
| **Cred capture** | Responder, ARP MITM + sniff, DNS‑spoof phishing |
| **Loot viewer** | Read Nmap / Responder / DNSSpoof logs on‑device |
| **File browser** | Lightweight text & image explorer |
| **System** | Theme editor, config save/restore, UI restart, shutdown |
| **Extensible** | Add a function + a menu line – done |

---

## 🛠  Hardware

| Item | Description | Buy|
|------|-------------|-------------------|
| **Waveshare 1.44″ LCD HAT** | SPI TFT + joystick + 3 buttons | [Buy 🔗](https://s.click.aliexpress.com/e/_oEmEUZW) |
| **Raspberry Pi Zero 2 WH** | Quad-core 1 GHz, 512 MB RAM – super compact | [Buy 🔗](https://s.click.aliexpress.com/e/_omuGisy) |
| **RPI 0w with Waveshare Ethernet/USB HUB HAT** | 3 USB + 1 Ethernet | [Buy 🔗](https://s.click.aliexpress.com/e/_oDK0eYc) |
| **Raspberry Pi 4 Model B** (4 GB) | Quad-core 1.5 GHz, full-size HDMI, GigE LAN | [Buy 🔗](https://s.click.aliexpress.com/e/_oFOHQdm) |
| **Raspberry Pi 5** (8 GB) | Quad-core Cortex-A76 2.4 GHz, PCIe 2.0 x1 | [Buy 🔗](https://s.click.aliexpress.com/e/_oC6NEZe) |


---

## 🚀  Quick install

```bash
git clone https://github.com/7h30th3r0n3/raspyjack.git
cd raspyjack
chmod +x install_raspyjack.sh
sudo ./install_raspyjack.sh
sudo reboot
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
