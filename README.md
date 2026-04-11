<p align="center">
  <img src="https://img.shields.io/badge/platform-Raspberry%20Pi-red?style=flat-square&logo=raspberry-pi">
  <img src="https://img.shields.io/badge/code-python3-yellow?style=flat-square&logo=python">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square">
  <img src="https://img.shields.io/badge/usage-authorized%20testing%20only-blue?style=flat-square">
</p>

<div align="center">
  <h1>RaspyJack</h1>
  <img src="github-img/logo.jpg" width="240" alt="RaspyJack logo"/>
  <p><strong>Portable Raspberry Pi offensive toolkit</strong> with LCD control, payload launcher, WebUI, and Payload IDE.</p>
</div>

---

## ⚠️ Legal / Safety

RaspyJack is for **authorized security testing, research, and education only**.

- Do **not** use it on networks/systems you do not own or have explicit permission to test.
- You are solely responsible for how you use this project.
- The authors/contributors are not responsible for misuse.

---

## ✨ What RaspyJack includes

- LCD-driven handheld-style interface (Waveshare 1.44" or 1.3" HAT)
- **Dual-display support** — 128x128 (ST7735) and 240x240 (ST7789)
- **231 payloads** across 13 categories
- Loot collection + browsing
- WebUI remote control dashboard
- Payload IDE (browser editor + run flow)
- Responder / DNS spoof / ARP MITM / handshake hunter tooling integration
- WiFi utilities + attack flows (deauth, evil twin, SSID injection, beacon flood)
- Evil portal with 84 captive portal templates + credential capture
- BLE scanner, spam, beacon flood, MITM, replay, audio inject, DoS
- Reverse shell, Discord C2, HTTPS stealth shell, DuckyScript generator
- Exfiltration via HTTP, DNS, BLE, Discord, SMB, FTP, USB, Dropbox
- Dead drop WiFi file sharing with dashboard
- 25 games including Pac-Man, Tetris, Tron, LLM adventure, labyrinth

Check the WIKI for more ! https://github.com/7h30th3r0n3/Raspyjack/wiki

---

## 🧱 Hardware

## ✅ Required Hardware
<table>
  <tr>
    <th>Item</th>
    <th>Description</th>
    <th>Buy</th>
  </tr>
  <tr>
    <td><strong>Waveshare 1.44" LCD HAT</strong> (128x128)</td>
    <td>SPI TFT ST7735 + joystick + 3 buttons</td>
    <td>
      <a href="https://s.click.aliexpress.com/e/_c3HTOQQn">Buy</a><br/>
      <a href="https://s.click.aliexpress.com/e/_EwDqSv4">Buy</a>
    </td>
  </tr>
  <tr>
    <td><strong>Waveshare 1.3" LCD HAT</strong> (240x240)</td>
    <td>SPI TFT ST7789 + joystick + 3 buttons</td>
    <td>
      <a href="https://s.click.aliexpress.com/e/_c3j1Wy4N">Buy</a>
    </td>
  </tr>
  <tr>
    <td><strong>Raspberry Pi Zero 2 WH</strong></td>
    <td>Quad-core 1 GHz, 512 MB RAM – super compact</td>
    <td><a href="https://s.click.aliexpress.com/e/_omuGisy">Buy</a></td>
  </tr>
  <tr>
    <td><strong>RPI 0W + Waveshare Ethernet/USB HUB HAT</strong></td>
    <td>3 USB + 1 Ethernet</td>
    <td><a href="https://s.click.aliexpress.com/e/_oDK0eYc">Buy</a></td>
  </tr>
  <tr>
    <td><strong>Alternative: Dual Ethernet/USB HUB HAT</strong></td>
    <td>2 USB + 2 Ethernet</td>
    <td><a href="https://s.click.aliexpress.com/e/_oCX3pUA">Buy</a></td>
  </tr>
</table>
<p><em>Note:</em> Raspyjack on RPI 0w1/2 can run headless trough WebUi, but need an ethernet module at least.</p>

---

## ➕ Other Hardware (Not Mandatory)
<table>
  <tr>
    <th>Item</th>
    <th>Description</th>
    <th>Buy</th>
  </tr>
   <tr>
    <td><strong>Raspberry Pi 3 Model B</strong> </td>
    <td>Almost same specs as RPI 0w2</td>
    <td><a href="https://s.click.aliexpress.com/e/_c4k1RESn">Buy</a></td>
  </tr>
  <tr>
    <td><strong>Raspberry Pi 4 Model B</strong> (4 GB)</td>
    <td>Quad-core 1.5 GHz, full-size HDMI, GigE LAN</td>
    <td><a href="https://s.click.aliexpress.com/e/_oFOHQdm">Buy</a></td>
  </tr>
  <tr>
    <td><strong>Raspberry Pi 5</strong> (8 GB)</td>
    <td>Quad-core Cortex-A76 2.4 GHz, PCIe 2.0 x1</td>
    <td><a href="https://s.click.aliexpress.com/e/_oC6NEZe">Buy</a></td>
  </tr>
</table>

<p><em>Note:</em> Raspberry Pi 4/5 is not fully tested yet. It should work trough Webui but screen probably need some ajustement. Feedback is welcome.</p>

---

## 📡 WiFi Attack Requirements
<strong>Important:</strong> The onboard Raspberry Pi WiFi (Broadcom 43430) cannot be used for WiFi attacks.

<table>
  <tr>
    <th>Dongle</th>
    <th>Chipset</th>
    <th>Monitor Mode</th>
  </tr>
  <tr>
    <td><strong>Alfa AWUS036ACH</strong></td>
    <td>Realtek RTL8812AU</td>
    <td>✅ Full support</td>
  </tr>
  <tr>
    <td><strong>TP-Link TL-WN722N v1</strong></td>
    <td>Atheros AR9271</td>
    <td>✅ Full support</td>
  </tr>
  <tr>
    <td><strong>Panda PAU09</strong></td>
    <td>Realtek RTL8812AU</td>
    <td>✅ Full support</td>
  </tr>
</table>

<ul>
  <li>Deauth attacks on 2.4 GHz and 5 GHz networks</li>
  <li>Multi-target attacks with interface switching</li>
  <li>Automatic USB dongle detection and setup</li>
</ul>

---

## 📡 WiFi attack requirement (important)

The onboard Pi WiFi chipset is limited for monitor/injection workflows.
For WiFi attack payloads, use a **compatible external USB WiFi adapter**.

Examples commonly used:
- Alfa AWUS036ACH (RTL8812AU)
- TP-Link TL-WN722N v1 (AR9271)
- Panda PAU09 (RTL8812AU)

---

## 🚀 Install

From a fresh Raspberry Pi OS Lite install:

```bash
sudo apt update
sudo apt install -y git
sudo -i
git clone https://github.com/7h30th3r0n3/raspyjack.git Raspyjack
cd Raspyjack
chmod +x install_raspyjack.sh
./install_raspyjack.sh
reboot
```

After reboot, RaspyJack should be available on-device.

---

## 🔄 Update

```bash
sudo -i
cd /root
rm -rf Raspyjack
git clone https://github.com/7h30th3r0n3/raspyjack.git Raspyjack
cd Raspyjack
chmod +x install_raspyjack.sh
./install_raspyjack.sh
reboot
```

Before major updates, back up loot/config you care about.

---

## 🌐 WebUI + Payload IDE

RaspyJack includes a browser UI and IDE in `web/`.

- WebUI docs: `web/README.md`
- Main WebUI: `https://<device-ip>/` (or fallback `http://<device-ip>:8080`)
- Payload IDE: `https://<device-ip>/ide` (or `http://<device-ip>:8080/ide`)

### Local JS sanity check (dev)

```bash
./scripts/check_webui_js.sh
```

This validates syntax for:
- `web/shared.js`
- `web/app.js`
- `web/ide.js`

---

## 🎮 Input mapping

| Control | Action |
|---|---|
| UP / DOWN | Navigate |
| LEFT | Back |
| RIGHT / OK | Enter / Select |
| KEY1 | Context/extra action (varies) |
| KEY2 | Secondary action (varies) |
| KEY3 | Exit / Cancel |
---

## 🖥️ Dual-Display Support

RaspyJack supports two LCD screens from the same codebase. The installer asks which screen you have.

| Display | Chip | Resolution | Config value |
|---------|------|------------|--------------|
| 1.44" (original) | ST7735S | 128x128 | `ST7735_128` |
| 1.3" | ST7789 | 240x240 | `ST7789_240` |

To switch screens, change `"type"` in `gui_conf.json` and reboot:
```json
"DISPLAY": { "type": "ST7789_240" }
```

---

## 🧩 Creating a Payload

1. Copy `payloads/examples/_payload_template.py` into the appropriate category folder
2. Use `ScaledDraw` and `scaled_font()` so it works on both screens
3. Keep `KEY3` as exit button
4. Add an icon in `menu_icons.json`

### Minimal template

```python
#!/usr/bin/env python3
import os, sys, time
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..', '..')))

import RPi.GPIO as GPIO
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {"UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
        "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16}
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
font = scaled_font()

try:
    while True:
        btn = get_button(PINS, GPIO)
        if btn == "KEY3":
            break
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((6, 6), "Hello Payload", font=font, fill="#00FF00")
        LCD.LCD_ShowImage(img, 0, 0)
        time.sleep(0.05)
finally:
    LCD.LCD_Clear()
    GPIO.cleanup()
```

---


### Adding an icon

Edit `menu_icons.json` and add your payload name in the `payloads` section:

```json
"payloads": {
    " my_payload": "\uf002",
}
```

Icons are FontAwesome 6 Solid. Browse available icons at https://fontawesome.com/v6/search?o=r&s=solid

### Display rules

- **UI/tool payloads**: Use `ScaledDraw` with 128-base coordinates (0-127). Never use `WIDTH`/`HEIGHT` in draw calls.
- **Game payloads**: Render at 128x128 with regular `ImageDraw.Draw`, then resize to `(WIDTH, HEIGHT)` before showing.

---

## 📦 Project layout

```text
Raspyjack/
├── raspyjack.py          # Main UI engine
├── gui_conf.json          # Display type, colors, pins, lock
├── menu_icons.json        # FontAwesome icons for menus
├── LCD_1in44.py           # LCD driver (ST7735 + ST7789)
├── LCD_Config.py          # SPI/GPIO config
├── web_server.py          # WebUI HTTP server
├── device_server.py       # WebSocket device server
├── rj_input.py            # Input handler
├── install_raspyjack.sh   # Installer
├── web/                   # WebUI frontend
├── payloads/
│   ├── _display_helper.py # ScaledDraw + scaled_font
│   ├── _input_helper.py   # GPIO + WebUI input
│   ├── reconnaissance/    # Nmap, Shodan, OSINT, AP/client stats, flock detection, Norse recon suite, pwnagotchi, Gobuster
│   ├── wifi/              # Deauth, evil twin, CIW Zeroclick (SSID injection), beacon flood, BLE spam, pwnagotchi
│   ├── network/           # ARP MITM, DNS spoof, handshake hunter with auto-upload, WPA cracking
│   ├── credentials/       # Responder, credential capture, hash harvesting
│   ├── bluetooth/         # Scanner, spam, beacon flood, MITM, replay, audio inject, DoS
│   ├── usb/               # DuckyScript generator, USB attacks
│   ├── exfiltration/      # HTTP, DNS, BLE, Discord, SMB, FTP, USB, Dropbox
│   ├── evasion/           # Evasion techniques
│   ├── remote_access/     # Reverse shell, Discord C2, HTTPS stealth shell
│   ├── evil_portal/       # Captive portal with 84 templates, whitelist, SSID editor, credential capture
│   ├── dead_drop/         # WiFi file sharing with dashboard
│   ├── utilities/         # Weather, IRC, morse, translator, video player, interface manager, system monitor
│   ├── hardware/          # Hardware interaction payloads
│   ├── games/             # 25 games including Pac-Man, Tetris, Tron, LLM adventure, labyrinth
│   └── examples/          # Payload templates
├── loot/                  # Captured data
├── config/                # Payload configs
├── DNSSpoof/
├── Responder/
└── wifi/                  # WiFi manager
```

---

## 🤝 Contributing

PRs are welcome.

If you submit UI changes, please include:
- short description + screenshots/gifs,
- any changed routes/workflows,
- output of `./scripts/check_webui_js.sh`.

---

## 🙏 Acknowledgements

- [@dagnazty](https://github.com/dagnazty)
- [@Hosseios](https://github.com/Hosseios)
- [@m0usem0use](https://github.com/m0usem0use)

---

<div align="center">
  Build responsibly. Test ethically. 🧌
</div>
