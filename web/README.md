# RaspyJack WebUI

This WebUI provides a browser-based remote control for the RaspyJack LCD UI.
It streams LCD frames to the browser and forwards button input back to the device.

## Required folders and files on device
- `web/`
  - `web/index.html`
  - `web/app.js`
  - `web/raspyjack.png`
- `payloads/webui.py` (on-device controller that starts/stops the WebUI stack)
- `device_server.py` (WebSocket server for frames + input)
- `rj_input.py` (virtual input bridge for browser controls)
- `LCD_1in44.py` and `LCD_Config.py` (LCD driver used by `payloads/webui.py`)

## Dependencies (install script)
These are the WebUI-relevant packages in `install_raspyjack.sh`:
- `python3-websockets` (WebSocket server dependency for `device_server.py`)
- `python3-pil` (Pillow for LCD rendering in `payloads/webui.py`)
- `python3-rpi.gpio` (GPIO input in `payloads/webui.py`)
- `fonts-dejavu-core` (font files used by the on-device UI)
- `procps` (provides `pkill`, used to stop the WebUI processes)

## How it runs
`payloads/webui.py` launches:
- `device_server.py` (WebSocket server on port `8765`)
- `python -m http.server 8080` in `web/` (static frontend)

Open in a browser:
```
http://<device-ip>:8080
```

## Environment variables (optional)
`device_server.py` supports:
- `RJ_FRAME_PATH` (default `/dev/shm/raspyjack_last.jpg`)
- `RJ_WS_HOST` (default `0.0.0.0`)
- `RJ_WS_PORT` (default `8765`)
- `RJ_FPS` (default `10`)
- `RJ_WS_TOKEN` (optional shared token, passed as `?token=...`)
- `RJ_INPUT_SOCK` (default `/dev/shm/rj_input.sock`)

## Notes
- The LCD frame mirror must exist at `RJ_FRAME_PATH`.
- If you want browser input to control the UI, `rj_input.py` must be present and
  the main UI must import it so it consumes virtual button events.
