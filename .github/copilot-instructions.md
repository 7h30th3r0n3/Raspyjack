# Copilot Instructions for RaspyJack

## 1) What this repository is
- Raspberry Pi offensive toolkit (LCD hardware + WebUI + payload runner).  Core app is in `raspyjack.py` (LCD/menu, payload orchestration, Responder/DNS spoof, LoOt paths).
- Web UI layer in `web_server.py` + `device_server.py` + `rj_input.py`; static frontend in `web/`.
- Payloads are stored in `payloads/` tree and expected as executable Python scripts (reconnaissance/interception/exfiltration/etc). The IDE interacts with `web_server.py` APIs under `/api/payloads/*`.

## 2) Big-picture flow
- `payloads/general/webui.py` (in `web/README.md` and main UI flow) launches `device_server.py` (WS frame+input server, port 8765) and `web_server.py` (HTTP API + file browser, port 8080).
- `raspyjack.py` manages physical hat input + LCD rendering + local payload menu. It uses `rj_input.py` to accept virtual button events from browser WS actions.
- `web_server.py` exposes read-only loot APIs (`/api/loot/*`), payload tree + editor APIs (`/api/payloads/*`), plus auth/session tickets for WebUI and CLI.
- `device_server.py` provides device shell multiplexing (via pty) plus frame transfer, protected by token/session (via `RJ_WS_TOKEN`, `RJ_WEB_*` env vars).
- Payload code is generally launched by both local UI and WebUI calls. Avoid path traversal by using `_safe_payload_path` in `web_server.py`.

## 3) Essential files to inspect for AI changes
- `raspyjack.py` (core runtime, hardware and small LCD menu stack, main UX loops)
- `web_server.py` (API routing + payload management + auth/session handling)
- `device_server.py` (WebSocket device I/O and shell session bridging)
- `rj_input.py` (virtual input queue; used by UI and payloads via WebSocket frontend)
- `web/` assets + `web/README.md` (important protocol conventions, secure path behavior, env vars).
- `scripts/check_webui_js.sh` (recommended static JS sanity check for `web/app.js`, `web/shared.js`, `web/ide.js`).

## 4) Running, test and debug commands
- Fresh install and runtime path (documented in top-level `README.md`): `./install_raspyjack.sh`; then reboot; run services through provided payloads/gateways.
- Direct launch in dev: `sudo python3 raspyjack.py`, `sudo python3 web_server.py`, `sudo python3 device_server.py` (for local debugging). Set env, e.g. `RJ_WS_TOKEN=xxx`.
- WebUI check: `./scripts/check_webui_js.sh`.
- Unit tests: `pytest -v --tb=short` (configured in `pytest.ini` targeting `tests/test_*.py`).
- Browser access endpoints: `http://<device-ip>:8080/` and `https://<device-ip>/` via Caddy proxy in deployment (`deploy/caddy/Caddyfile`).

## 5) Project-specific conventions
- Use direct file paths under `/root/Raspyjack/` in deployment. Many modules depend on this path (for payloads, loot, configs). Keep path changes minimal unless updating global constants.
- WebUI and device server include token fallback, with file-based token support: `.webui_token`, `/root/Raspyjack/.webui_auth.json`, `.webui_session_secret`.
- Input events are standardized: `button` values `UP|DOWN|LEFT|RIGHT|OK|KEY1|KEY2|KEY3`; `state` only `press` is queued by `rj_input.py`.
- Use `subprocess.run` strongly with timeout when calling external shell commands, as seen in web_server/device_server (e.g., `ip addr show`, `nmap`).

## 6) Integration and external dependencies
- Hardware: Waveshare 1.44" LCD hat, RPi GPIO via `RPi.GPIO`; Pillow for image rendering.
- Network: `scapy`, `nmap` parser (`nmap_parser.py`), Responder integration in `Responder/` and `DNSSpoof/` directories.
- Web: `python3-websockets`, simple HTTP server (`http.server`), plus frontend JS in `web/`.
- Caddy config for HTTPS/WSS is in `deploy/caddy/Caddyfile` (proxy `/` to `127.0.0.1:8080`, `/ws` to `127.0.0.1:8765`).

## 7) What Copilot should not assume
- No CI/packaging config exists in repository (`setup.py`, `pyproject.toml` absent).
- UI state is persisted to `gui_conf.json` and `loot/payload.log`; existing workflows depend on these files and may assume state format.
- `raspyjack.py` is not structured as reusable modules; prefer minimal invasive refactors rather than complete rewrite when adding a feature.

---

Please review this draft and tell me if you want sections re-ordered, if deeper WebAPI examples are needed, or if I should include an explicit “Safe editing pattern for /payloads/**” guideline next.
