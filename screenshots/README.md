# Store screenshots

The CardputerZero store validator requires **1–6 PNG screenshots, each exactly
`320×170` px** (the device screen size), with **no added chrome/borders**.

These MUST be captured on a real CardputerZero (the first store release also
requires a short demo video of the app running on-device, posted in the
submission PR). Placeholders are rejected — do not commit fake images.

Expected files (referenced by `app-builder.json` → `store.screenshots`):

- `01-menu.png`   — main menu
- `02-scan.png`   — an nmap / network scan result
- `03-wifi.png`   — Wi-Fi manager / attack screen
- `04-subghz.png` — CC1101 Sub-GHz spectrum/waterfall

Capture at 320×170, save as PNG here, then run `prepublish_check.py` before
submitting. Adjust the filename list in `app-builder.json` if you ship a
different set.
