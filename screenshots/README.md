# Store screenshots

CardputerZero store screenshots — **PNG, exactly `320×170` px** (device screen
size), captured on a real device. 1–6 allowed. Referenced by
`app-builder.json` → `store.screenshots`.

Current set (captured from the framebuffer of a CardputerZero running RaspyJack):

- `01-menu.png`   — main menu (Scan Nmap, Responder, MITM, DNS Spoofing, WiFi…)
- `02-nfc.png`    — NFC Cap HAT (Read / Saved / Emulate / EMV)
- `03-cctv.png`   — CCTV viewer (live camera stream)
- `04-subghz.png` — Sub-GHz CC1101 spectrum + waterfall (signal peak at 433.92 MHz)

Re-capture at 320×170, then run `bash scripts/prepublish.sh` before submitting.
