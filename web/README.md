# RaspyJack WebUI

This WebUI provides a browser-based remote control for the RaspyJack LCD UI.
It streams LCD frames to the browser and forwards button input back to the device.

## Required folders and files on device
- `web/`
  - `web/index.html`
  - `web/app.js`
  - `web/raspyjack.png`
- `payloads/general/webui.py` (on-device controller that starts/stops the WebUI stack)
- `device_server.py` (WebSocket server for frames + input)
- `web_server.py` (static WebUI + read-only loot API)
- `rj_input.py` (virtual input bridge for browser controls)
- `LCD_1in44.py` and `LCD_Config.py` (LCD driver used by `payloads/general/webui.py`)

## Dependencies (install script)
These are the WebUI-relevant packages in `install_raspyjack.sh`:
- `python3-websockets` (WebSocket server dependency for `device_server.py`)
- `python3-pil` (Pillow for LCD rendering in `payloads/general/webui.py`)
- `python3-rpi.gpio` (GPIO input in `payloads/general/webui.py`)
- `fonts-dejavu-core` (font files used by the on-device UI)
- `procps` (provides `pkill`, used to stop the WebUI processes)

## How it runs
`payloads/general/webui.py` launches:
- `device_server.py` (WebSocket server on port `8765`)
- `web_server.py` (static frontend + loot API) on port `8080`

Open in a browser:
```
http://<device-ip>:8080
```

## Authentication flow
- First run: blocking setup overlay asks for admin username/password.
- After setup: blocking login overlay appears on WebUI and IDE.
- Successful login creates an HTTP-only session cookie used for API calls.
- WebSocket access uses a short-lived WS ticket issued by `web_server.py`.
- Emergency fallback: recovery token auth is still supported.

## Environment variables (optional)
`device_server.py` supports:
- `RJ_FRAME_PATH` (default `/dev/shm/raspyjack_last.jpg`)
- `RJ_WS_HOST` (default `0.0.0.0`)
- `RJ_WS_PORT` (default `8765`)
- `RJ_FPS` (default `10`)
- `RJ_WS_TOKEN` (optional shared token)
- `RJ_WS_TOKEN_FILE` (optional token file; default `/root/Raspyjack/.webui_token`)
- `RJ_WEB_AUTH_FILE` (default `/root/Raspyjack/.webui_auth.json`)
- `RJ_WEB_AUTH_SECRET_FILE` (default `/root/Raspyjack/.webui_session_secret`)
- `RJ_WEB_SESSION_TTL` (default `28800`)
- `RJ_WEB_WS_TICKET_TTL` (default `120`)
- `RJ_INPUT_SOCK` (default `/dev/shm/rj_input.sock`)

## Notes
- The LCD frame mirror must exist at `RJ_FRAME_PATH`.
- If you want browser input to control the UI, `rj_input.py` must be present and
  the main UI must import it so it consumes virtual button events.
