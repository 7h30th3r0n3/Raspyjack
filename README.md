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

- LCD-driven handheld-style interface (Waveshare 1.44" HAT)
- Payload categories (reconnaissance, interception, exfiltration, etc.)
- Loot collection + browsing
- WebUI remote control dashboard
- Payload IDE (browser editor + run flow)
- Responder / DNS spoof tooling integration
- WiFi utilities + optional attack flows (with compatible USB dongle)

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
    <td><strong>Waveshare 1.44" LCD HAT</strong></td>
    <td>SPI TFT + joystick + 3 buttons</td>
    <td>
      <a href="https://s.click.aliexpress.com/e/_c3HTOQQn">Buy</a><br/>
      <a href="https://s.click.aliexpress.com/e/_EwDqSv4">Buy</a>
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

## 🖥️ Alternate LCD: Spotpear 1.54" ST7789

To use the Spotpear 240x240 ST7789 display (pinout as in your instructions), set:

- `RJ_LCD_MODEL=1in54` (environment variable)

This triggers:

- `LCD_Config` to use `LCD_DC_PIN=22` (Spotpear wiring)
- `LCD_1in54` driver for ST7789 init sequence and 240x240 content
- `LCD_1in44` import path compatibility (existing code continues to work)

Wrap with your shell start command for RaspyJack, e.g.:

```bash
sudo RJ_LCD_MODEL=1in54 python3 raspyjack.py
```

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
cd /root
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

## 📦 Project layout (high-level)

```text
Raspyjack/
├── raspyjack.py
├── web_server.py
├── device_server.py
├── rj_input.py
├── web/
│   ├── index.html
│   ├── app.js
│   ├── ide.html
│   ├── ide.js
│   ├── shared.js
│   ├── ui.css
│   ├── device-shell.css
│   └── README.md
├── payloads/
│   ├── reconnaissance/
│   ├── interception/
│   ├── exfiltration/
│   ├── remote_access/
│   ├── general/
│   ├── games/
│   └── examples/
├── loot/
├── DNSSpoof/
├── Responder/
└── wifi/
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
