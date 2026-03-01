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

---

## 🧱 Hardware

### Common build

- Raspberry Pi Zero 2 W / WH (recommended compact build)
- Waveshare 1.44" LCD HAT
- microSD card
- Power source / battery setup

### Also used by contributors

- Raspberry Pi 4
- Raspberry Pi 5 (community testing welcome)

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
cd /root/Raspyjack
git fetch --all
git pull --rebase
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
