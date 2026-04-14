# Ragnar System Specification

## 1. Purpose & Scope
- Capture the authoritative description of Ragnar as of December 2025.
- Align contributors on hardware expectations, software architecture, data flow, and operational behaviors.
- Cover every major subsystem including ping sweeps, orchestrator, Wi-Fi/AP control, network data separation, dashboards, vulnerabilities, installation, AI, and e-paper display.

## 2. Platform Baseline
- **Hardware target**: Raspberry Pi Zero 2 W, Pi 4, Pi 5 with Waveshare 2.13" E-Paper HAT (default `epd2in13_V4`). Pi Zero 2 W is the lowest common denominator; all timing and memory assumptions follow its limits.
- **OS**: Raspberry Pi OS (Debian Trixie, 64-bit), kernel 6.12. Earlier Debian versions must provide `systemd`, `hostapd`, `dnsmasq`, `nmap >= 7.94`.
- **Users**: System user and hostname default to `ragnar` for scripts and service files. Changing the account requires updating systemd units (`/etc/systemd/system/ragnar.service`, `ragnar_wifi.service`).
- **Resource constraints**: 512 MB RAM on Pi Zero 2 W drives conservative threading (1 orchestrator worker, 6 nmap threads), aggressive garbage collection, and incremental scanning.
- **Power**: Optimized for mobile battery packs; actual draw varies by Pi model/peripherals, so concurrency throttles and display refresh cadence are used instead of assuming fixed wattage.
- **Networking**: Single onboard WLAN interface; AP and STA modes are mutually exclusive and coordinated by Wi-Fi manager.

## 3. High-Level Architecture
- **Shared Data Core (`shared.py`)**: Initializes paths, loads configuration, handles per-network storage, bootstraps AI, intelligence engines, display helpers, and exposes convenience getters/setters to every module.
- **Database (`db_manager.py`)**: SQLite per active network; single source for hosts, ports, vulnerabilities, Wi-Fi analytics, action state, and loot inventory. All CSVs are write-through caches fed from the DB.
- **Network Scanner (`actions/scanning.py`)**: Performs ARP, ping sweep, and nmap discovery; seeds orchestrator targets and updates scan history.
- **Orchestrator (`orchestrator.py`)**: Schedules/executes action modules (scanners, attacks, data theft) with retry logic, dependency handling, and resource gating.
- **Vulnerability Scanner (`actions/nmap_vuln_scanner.py`)**: Incremental, NSE-driven scanning feeding Network Intelligence and the vulnerabilities view.
- **Wi-Fi Manager (`wifi_manager.py`)**: Maintains station mode, auto AP fallback, captive portal lifecycle, connection analytics, and endless-loop watchdog.
- **Web/API (`webapp_modern.py`, `web/`)**: Modern dashboard served on port 8000 with REST+WebSocket endpoints, config UI, AI insights, file browser, and Wi-Fi portal.
- **AI Service (`ai_service.py`)**: GPT-5 Nano integration for insights, caching, and API exposure; sanitizes outbound data.
- **Display Pipeline (`display.py`, `epd_helper.py`)**: Renders status, loot, telemetry, and gamification badges to the e-paper HAT with full/partial refresh control.
- **Logging/Monitoring**: Central `logger.py`, action-specific logs, `/var/log` fallbacks, `data/logs` for audit trails, `resource_monitor.py` for CPU/MEM tracking.

### 3.1 SharedData Boot Sequence (from `SharedData.__init__`)
- `initialize_paths()` pins every directory/file path the moment the process starts so later modules can reference `shared_data.<path attribute>` without re-walking the filesystem.
- `NetworkStorageManager` is instantiated before configs load, letting `_apply_network_context()` immediately bind per-network directories and SQLite path, even before Wi-Fi connects.
- `get_default_config()` seeds hundreds of keys; `load_config()` overlays user JSON, and `apply_display_profile()` normalizes `epd_type` width/height/orientation so downstream display math never revalidates.
- `_configure_database()` calls `get_db(...).configure_storage()` which rebinds SQLite to the currently active `data/networks/<slug>/db/<slug>.db`. This happens again on every SSID switch.
- `initialize_network_intelligence()` and `initialize_ai_service()` are deferred until after config + storage exist, ensuring both subsystems inherit the correct per-network directories and credentials.
- Background services include `_start_cleanup_task()` (periodic host pruning), `create_livestatusfile()`, live font/image loaders, and gamification loader to keep UI artifacts synced.

## 4. Data Stores & Separation
- **Per-Network Isolation (`network_storage.py`)**
  - Every SSID maps to `data/networks/<slug>/` containing `db/<slug>.db`, `intelligence/`, `threat_intelligence/`, `loot/data_stolen/`, `loot/credentials/`, and `logs/`.
  - `NetworkStorageManager` persists last SSID, migrates legacy global stores, exposes context to `SharedData.set_active_network()`, and keeps `.last_ssid` for seamless reboots.
  - Context switches flush in-memory intelligence caches before moving file pointers to avoid cross-network leakage.
- **SQLite schema (simplified)**
  | Table | Key Columns | Purpose |
  | --- | --- | --- |
  | `hosts` | mac (PK), ip, hostname, vendor, alive, open_ports, tags | Truth for discovered devices. |
  | `scan_history` | id, mac, tool, ports_found, timestamp | Audit trail of scanners per run. |
  | `vulnerabilities` | id, mac, cve, severity, source, status | Feeding Network Intelligence + UI. |
  | `wifi_networks` | ssid, bssid, signal, security | Cached AP list for portal and analytics. |
  | `wifi_connections` | id, ssid, start, end, status, failure_reason | Connection analytics/time-series. |
  | `actions_state` | mac, action_name, status, timestamp | Retry and throttling decisions. |
  | `loot_inventory` | id, mac, path, type, size | Catalog of stolen files/credentials. |
- **Legacy CSV mirrors**
  - `data/netkb.csv`: still updated for display compatibility (e-paper + scripts) but never consumed as source of truth.
  - `data/logs/*.csv`: rotating exports for offline review.
  - `data/vulnerabilities/vulnerability_summary.csv`: summary for interoperability with Bjorn tooling.

### 4.1 Database Manager API Highlights (`db_manager.DatabaseManager`)
- `upsert_host(mac, ip, hostname, ...)` is the canonical write path for scanners, orchestrator actions, and display metrics; every module calls this rather than writing SQL.
- `update_ping_status(mac, success=True/False)` increments `failed_ping_count`, updates `last_ping_success`, and flips `status` between `alive`/`degraded`.
- `add_scan_history(mac, ip, scan_type, ports_found)` appends immutable audit rows consumed by the dashboard timeline and AI context.
- `get_all_hosts()` returns SQLite rows as dictionaries; orchestrator, display, and API responses rely on this call.
- Wi-Fi analytics tables (`wifi_scan_cache`, `wifi_connection_history`, `wifi_network_analytics`) are written through helper methods in `wifi_manager.py`, letting `/api/wifi/*` endpoints query historical signal strength, durations, and failure reasons without touching raw SQL.

## 5. Network Discovery Pipeline
### 5.1 Entry Point
- `NetworkScanner.run_initial_ping_sweep()` triggered after Wi-Fi association, manual API kick, and periodically via orchestrator `scan_interval` (default 180 s).
- All results are written via `db_manager`—CSV mirrors are display-only. Each scan updates `scan_history` to preserve lineage.
- Discovery flow (simplified text diagram):
  - Wi-Fi connects → `WiFiManager` notifies SharedData → `NetworkScanner` kickoff.
  - ARP scan populates MAC/IP base.
  - Ping sweep fills gaps + high-priority hosts.
  - Nmap port scan enriches open services.
  - Orchestrator re-reads DB and schedules follow-on actions.

### 5.2 ARP Scan
- Commands: `sudo arp-scan --interface=wlan0 --localnet` plus fallback `/24` sweep for routers with custom masks. Interfaces configurable through `shared_config.arp_scan_interface`.
- Output parser extracts IP, MAC, vendor, ignoring comment lines and invalid tokens via regex and `ipaddress` validation.
- Successful entries call `db.upsert_host()` (write host metadata) and `db.update_ping_status()` (alive=1). Vendor info seeds UI badges.
- Failures (missing binary, timeout) logged with guidance to install `arp-scan` or widen sudo privileges.

### 5.3 Ping Sweep
- Targets missing from ARP results across configured CIDRs (default `192.168.1.0/24`, user-addable via config or UI).
- Priority list (default `192.168.1.192`, user-configurable) pinged with 3 attempts, 3 s timeout before general sweep (single ping, 2 s wait). Purpose: ensure crown-jewel host stays monitored even if stealthy.
- Missing MACs create temporary pseudo-MACs (`00:00:<ip octets>`) until reconciled in `update_netkb()` with real data; DB marks them `is_pseudo=1`.
- Threaded execution honors `network_max_failed_pings`, `mac_scan_blacklist`, and `ip_scan_blacklist`. Workers limited to `host_scan_workers` (default 4).
- Summary stats (hosts seen, time taken) logged for e-paper and AI ingestion.

### 5.4 Nmap Network Scan
- Runs `nmap -Pn -sS` against merged port list (top 50 + `shared_config.portlist` overrides + UI extra ports). UDP scans only appear in results when separate modules request them; the default network sweep is TCP-only.
- Adds `--open --min-rate 1000 --max-retries 1 --host-timeout 10s -v` for speed on constrained hardware; runs at full pace regardless of CPU load (no automatic `resource_monitor` backpressure inside the scanner module).
- Stores hostname, ordered ports list, service names/version strings when available; writes to SQLite and `data/logs/nmap.log` via `nmap_logger` with exact command, start/end timestamps, and outcome.
- Results feed orchestrator target selection, vulnerability scanner incremental logic, AI context, and dashboard visualizations.

### 5.5 Scanner Implementation Notes (`actions/scanning.py`)
- Thread pools for host/port scans are capped (`host_scan_workers`/`port_scan_workers` max 6) and automatically scale down on Pi Zero hardware, preventing socket exhaustion.
- `_ping_sweep_missing_hosts()` first brute-forces `priority_targets`, then iterates remaining IPs, fabricating deterministic pseudo-MACs (`00:00:c0:a8:xx:yy`) until ARP learns the real vendor. The pseudo flag is reconciled later inside `update_netkb()` so downstream modules know the host is provisional.
- `run_arp_scan()` always runs two commands (localnet + explicit `/24`), merges results, then persists to SQLite before returning. The method logs each binary invocation for offline troubleshooting.
- Every scanner write funnels through `DatabaseManager` so concurrency is controlled by SQLite’s own locking + `threading.RLock` inside the manager. CSV writing only happens in `update_netkb()` strictly for display compatibility.

## 6. Orchestrator Lifecycle
### 6.1 Initialization
- Validates config flags (`retry_success_actions`, `scan_vuln_interval`, `enable_attacks`, `scan_vuln_no_ports`) and sets semaphore to 1 for Pi Zero 2 W stability (hard limit). Pi 4/5 builds may raise via config but 1 is default safeguard.
- Loads actions from `config/actions.json` (ordered by `b_priority`). Modules with `b_port` unset become standalone actions. Each module must expose `b_class`, optional `b_parent`, `b_module` path.
- Initializes `self.network_scanner` (actions/scanning) and `self.nmap_vuln_scanner`. Missing modules fail gracefully with warning and continue boot.

### 6.2 Execution Cycle
- `process_alive_ips()` filters hosts with `Alive='1'`; pre-filters by required port before acquiring semaphore to avoid blocking queue with ineligible targets.
- Parent actions (no `b_parent_action`) execute first, followed by their children on the same host, then remaining children globally. Example chain: `FTPConnector` → `StealFilesFTP` once credentials succeed.
- Each action runs through `_execute_with_timeout()` to guard against hung operations; timeouts mapped to `action_timeout` (default 300 s). Return codes `success`, `failed`, `timeout` feed `_update_action_status()`.
- Standalone actions run once per cycle and can modify global state (e.g., `log_standalone.py` writing daily summary).
- Active action names propagate to `shared_data.ragnarorch_status` for e-paper + dashboard status card.

### 6.3 Retry Semantics
- Status strings `success_YYYYMMDD_HHMMSS` and `failed_*` stored per host/action row plus `retry_reason`. Manual DB edits should respect this format.
- `_should_retry()` enforces delays (`success_retry_delay` default 300 s, `failed_retry_delay` 180 s). Custom per-action overrides available via `config/actions.json` field `b_retry_delay`.
- Vulnerability scanners receive special-case 24 h override when remote APIs throttle or `scan_vuln_running=False`.
- Resource monitor integration (`resource_monitor.py`) blocks execution if free memory below threshold (default 30 MB) or CPU > 95% for >5 s; actions skipped with reason logged.
- Failed cycles increment `failed_scans_count`; once it flips to 1 the loop runs standalone actions, idles for a scan interval, then resets the counter—there is no configurable retry cap.

### 6.4 Standalone and Vulnerability Scans
- Standalone actions (portless) run per cycle irrespective of host ports; typical responsibilities include housekeeping (e.g., prune old loot, sync dashboards) or aggregator jobs.
- `NmapVulnScanner` triggered per `scan_vuln_interval`; records timestamps in `shared_data.last_vuln_scan_time`. Skipped when `scan_vuln_running=False` or insufficient new ports.
- Actions flagged `b_parent` require parent success before running; skip recorded as `dependency_blocked` in DB for transparency.

### 6.5 Action Metadata & Logging
- Each action module is required to set `b_class`, `b_module`, `b_port`, `b_parent`, `b_priority`. `load_action()` instantiates classes dynamically via `importlib.import_module('actions.<module>')`, so mismatched class names surface immediately in logs.
- `_execute_with_timeout()` wraps user code inside a daemon thread, captures exceptions, and returns `'failed'` if the worker dies before returning `'success'`. This guard prevents unhandled exceptions in actions from killing the orchestrator loop.
- `resource_monitor.can_start_operation(f"action_{action_key}", min_memory_mb=30)` is called **before** the semaphore is acquired, ensuring we never starve other threads due to memory pressure.
- Status strings saved back into SQLite (e.g., `ssh_connector` column) form the input for `_should_retry()`. Manual DB edits must keep `status_timestamp` format or retries will trigger every loop.

## 7. Vulnerability & Threat Intelligence
- **Incremental Port Tracking**: `scanned_ports_history.json` ensures only new or stale ports (>1 hour, configurable) are rescanned. History stored per MAC with timestamps; manual tampering resets to full scan next cycle.
- **NSE Scripts**: Uses `vulners.nse` by default plus optional NSE list defined in `shared_config.nmap_nse_scripts`. Additional script args supported via `shared_config.nmap_extra_args`.
- **Threat Sources**: `threat_intelligence.py` ingests CISA KEV, NVD CVE, AlienVault OTX, MITRE ATT&CK. Configurable in `data/threat_intelligence/sources_config.json` with API keys (if required). Data cached per network in `data/threat_intelligence/<network>/`.
- **Data Flow**: Parsed CVEs → Network Intelligence classification (`active_findings.json`, `resolved_findings.json`, `enriched_findings.json`, `threat_cache.json`). Each entry includes CVSS, exploit links, remediation text, detection timestamp, and host mapping.
- **Web Exposure**: Dashboard vulnerabilities tab queries `/api/v1/intel/vulnerabilities` (internal) pulling from Network Intelligence; updates stream through WebSocket for near-real-time cards. Dismissals mark `status=dismissed` but reappear when scanner rediscovers CVE.
- **Retention**: Findings older than `shared_config.vuln_retention_days` (default 30) auto-archive unless still active. Resolved findings kept for historical graph.
- **Logs & Auditing**: All commands stored in `data/logs/nmap.log`; vulnerability parser logs in `data/logs/vuln_scanner.log`; threat sync logs per source for debugging API failures.

### 7.1 Network Intelligence Internals (`network_intelligence.py`)
- Maintains four dicts keyed by `network_id` (`active_vulnerabilities`, `resolved_vulnerabilities`, `active_credentials`, `resolved_credentials`). Each `network_id` is a hash derived from SSID via `create_network_id()` so raw SSIDs never leave disk.
- Files persisted per network context: `network_profiles.json`, `active_findings.json`, `resolved_findings.json`. `set_storage_root()` hot-swaps directories whenever `SharedData` switches SSIDs.
- Findings lifecycle:
  1. `add_vulnerability()` / `add_credential()` generates deterministic IDs (md5 hash) and marks `status=active`.
  2. `schedule_resolution_check()` flags findings with `pending_resolution=True` when the SSID changes.
  3. `confirm_finding()` increments `confirmation_count` and clears pending flags when scanners rediscover the issue.
  4. `resolve_finding()` migrates entries into `resolved_*` dicts with reason/time stamps.
- Network profiles track `connection_count`, `active_vulnerabilities`, `active_credentials`, and are updated within `update_network_profile()` every time Wi-Fi connects or scans run.

## 8. Wi-Fi & AP Operations
### 8.1 Station Mode
- `WiFiManager.start()` runs an endless loop with a 30 s post-boot delay to let OS networking settle. If `wifi_monitor_enabled=False`, service exits after first success.
- Known networks pulled from `shared_config.json` (`wifi_known_networks`). Entries contain SSID, PSK, priority, optional static IP data. UI edits propagate to config + `wpa_supplicant.conf`.
- Connection attempts limited by `wifi_max_attempts` and `wifi_connection_timeout` (default 3 attempts, 60 s each). After each cycle results recorded in `wifi_connections` table.
- Successful connection triggers `_trigger_initial_ping_sweep()` with `wifi_ping_sweep_cooldown` (default 120 s) to refresh network map. Additional sweeps may be triggered manually or when AI requests fresh data.
- DNS + NTP sanity checks performed post-connect; repeated failures increment `wifi_validation_failures` driving endless-loop fallback.

### 8.2 Health Monitoring
- Periodic validations every `wifi_validation_interval` (180 s) with up to `wifi_validation_retries` (default 5). Each validation pings gateway, resolves DNS, optionally hits configured health URL.
- Analytics stored per cycle (RSSI, bitrate, Wi-Fi chip temperature, packet loss) for dashboard historical charts.
- Failsafe counter reboots after `failsafe_cycle_limit` cycles (default 20) with >5 minute disconnections and no AP clients; ensures unattended deployments recover automatically.
- Restart markers in `/tmp/ragnar_wifi_manager.pid` prevent multiple concurrent managers.

### 8.3 AP Mode Lifecycle
- Activates when Wi-Fi is unavailable and `wifi_auto_ap_fallback` is true or when forced via `/api/wifi/ap-mode`. Relies on `hostapd` + `dnsmasq`; `wifi_manager.py` writes fresh `/tmp/ragnar/hostapd.conf` and `/tmp/ragnar/dnsmasq.conf` files on every AP start instead of loading templates from `resources/`.
- Configurable SSID/password (`wifi_ap_ssid`, `wifi_ap_password`), default `Ragnar`/`ragnarconnect`. Channel default 6, can be changed via config.
- Serves captive portal at `http://192.168.4.1/portal` (assets under `web/`). Portal surfaces known networks, RSSI, manual SSID entry, countdown timers, and AP-client analytics.
- AP logger writes to `/var/log/ap.log` or `data/logs/ap.log` fallback; logs include AP start/stop, client associations, portal submissions, and forced exits.
- Idle timeout (`ap_mode_timeout`, default 180 s) cycles between AP and Wi-Fi reconnect attempts; user interactions extend timers and mark `ap_clients_connected=True` to prevent premature shutdown.
- Web UI can force exit AP mode via API toggles; `force_exit_ap_mode` flag triggers immediate hostapd teardown and STA retry.
- Credentials captured via portal stored encrypted (simple XOR + base64) inside SQLite until applied to wpa_supplicant.

### 8.4 Endless Loop & Analytics (from `WiFiManager`)
- `_initial_endless_loop_sequence()` enforces a 30 s post-boot delay, checks for existing connection via `/tmp/ragnar_wifi_state.json`, then either schedules AP mode or triggers `_trigger_initial_ping_sweep()` for the connected SSID.
- `_endless_loop_monitoring()` (not shown in excerpt) continually alternates between `connect_to_known_networks()` attempts, AP activation via `start_ap_mode()`, and validation cycles. Each loop records timestamps so `failsafe_cycle_limit` logic can trigger reboots if the unit stays offline >5 minutes per cycle.
- Every successful connection inserts/updates rows in `wifi_connection_history` (start/end timestamps, signal, durations) and `wifi_network_analytics` (success/failure counters). This telemetry feeds `/api/wifi/status`, `/api/wifi/networks`, and the dashboard charts without rescanning the OS every refresh.
- `setup_ap_logger()` writes AP lifecycle events to `/var/log/ap.log` when possible or `data/logs/ap.log` otherwise, making AP troubleshooting possible even during captive-portal onboarding.

## 9. Data Separation Between Networks
- `WiFiManager` calls `SharedData.set_active_network(ssid)` after association or when user selects network via dashboard.
- Context switch reconfigures SQLite path, intelligence directories, loot paths, AI caches, threat cache, and log pointers. Modules listening to `SharedData` attributes automatically start writing into the new namespace.
- `data/networks/<slug>/loot/credentials/*.csv` replaces legacy global `data/output/crackedpwd` per network. Legacy directory kept for compatibility but no longer updated once new network is active.
- `.last_ssid` ensures reboots load the last active context even before Wi-Fi connects, allowing offline review of data.
- Storage manager handles slug collisions, ASCII folding (SSID to slug), and migrations of old directories. Tools referencing direct paths should use `SharedData` helpers to stay future-proof.

### 9.1 NetworkStorageManager Helpers
- `_slugify()` strips non-ASCII, forces lowercase, and collapses non-alphanumeric characters into `_`, matching the folder naming convention enforced in code.
- `_ensure_network_dirs()` creates `db/`, `intelligence/`, `threat_intelligence/`, and `loot/*` subdirectories atomically, so modules can assume directory existence when they call `os.path.join(shared_data.datastolendir, ...)`.
- `_bootstrap_legacy_layout()` is invoked once to move pre-networks-era directories into `networks/default/`. If the directory already contains data, migration is skipped to avoid clobbering user files.

## 10. E-Paper Display Pipeline
- `SharedData` configures `EPDHelper` based on `config.epd_type`, orientation, and `screen_reversed`. Supported profiles defined in `DISPLAY_PROFILES` map width/height/flip options.
- `display.py` composes layered canvas: background template → headline metrics (targets, creds, vulns) → Wi-Fi info (SSID, IP) → rotating comments/AI quips → loot ticker. Fonts loaded from `resources/fonts` with fallback.
- Supports full refresh every configurable interval (default 2 minutes) to clear ghosting; partial updates used for incremental status changes. Full refresh triggered when `screen_reversed` changes or hardware profile swapped.
- Gamification data from `data/gamification.json` surfaces progress badges (e.g., "First Blood", "Credential Hoarder"). Each badge includes icon path under `resources/images/badges`.
- Display subsystem listens to `shared_data.ragnarorch_status`, network stats, AI summary, and Wi-Fi manager state for real-time updates.

### 10.1 Display Data Sources (`display.py`)
- `schedule_update_shared_data()` runs every 5 s, reading `livestatus.csv`, counting credentials by iterating the **network-scoped** `crackedpwddir`, and setting `shared_data.targetnbr`, `portnbr`, `vulnnbr`, `crednbr`, and `networkkbnbr`. It contains retry logic around temporary CSV locks to avoid race conditions while actions write credentials.
- `schedule_update_vuln_count()` wakes every 300 s, reads `vuln_summary_file`, and synchronizes both the display and `livestatus.csv` with the current vulnerability count derived from SQLite.
- `update_main_image()` rotates status art by calling `shared_data.update_image_randomizer()`; fonts and bitmaps come from `resources/fonts` and `resources/images`. When `shared_data.imagegen` is empty, the loop logs errors and keeps the previous image.

## 11. Web Dashboard & APIs
- **Server**: `webapp_modern.py` (Flask + Flask-SocketIO) serves REST endpoints under `/api`, WebSocket for live updates, and static files from `web/`.
- **Frontend**: `web/index_modern.html` + Tailwind CSS + vanilla Socket.IO-driven helpers in `web/scripts/ragnar_modern.js` deliver the responsive dashboard and WebSocket widgets (no AlpineJS at present).
- **Key features**:
  - Real-time host list, port map, and threat intelligence overlays with filtering, tagging, and per-host action history.
  - Config tab editing `shared_config.json` with validation + diff preview; writes via `/api/config` endpoint.
  - File browser and gallery backed by per-network loot directories; preview images, download artifacts, delete entries (updates DB + filesystem).
  - System monitor (CPU, RAM, storage, GPU temp) via `/api/system/metrics` (resource_monitor) with streaming updates.
  - Pwnagotchi bridge controls calling `scripts/install_pwnagotchi.sh` and toggling systemd units `ragnar.service`, `pwnagotchi.service`.
  - AI insights cards (network summary, vulnerabilities, weaknesses) with manual refresh + cache status.
  - Notification center showing kill switch warnings, AP status, update availability.
- **API surface (representative)**:
  - `/api/hosts`, `/api/hosts/<mac>` – host data + actions state.
  - `/api/actions/trigger` – manually kick orchestrator action.
  - `/api/files/loot` – list/download/delete loot entries.
  - `/api/system/control` – reboot/shutdown toggles.
  - `/api/wifi/*` – scan networks, connect, start/stop AP, monitor state.
  - `/api/kill` – kill switch endpoint (requires confirmation token).
- **Captive Portal**: `GET /portal` serves `web/captive_portal.html` when AP clients hit the Dashboard root. `/generate_204` responses redirect to `/portal` for Android/iOS captive detection. AP clients then call the same `/api/wifi/*` endpoints as the dashboard (there are no dedicated `/api/portal/*` routes in the current codebase).

### 11.1 REST Endpoint Inventory (from `webapp_modern.py`)
- **Wi-Fi**: `/api/wifi/interfaces`, `/status`, `/scan` (POST), `/networks`, `/connect`, `/disconnect`, `/exit-ap`, `/forget`, `/ap/enable`, `/ap/start`, `/ap/stop`, `/reconnect`, `/ap/exit`, `/force-recovery`, `/log`. All calls proxy into `WiFiManager` helpers and SQLite analytics tables.
- **System Control**: `/api/system/metrics` (resource monitor stats), `/api/system/control` (shutdown/reboot), `/api/system/update` (git pull + pip), `/api/system/logs` (tail sanitized logs).
- **Threat/Intel**: `/api/v1/intel/vulnerabilities`, `/api/v1/intel/threats`, `/api/v1/intel/summary` map directly to `shared_data.network_intelligence` and `ThreatIntelligenceFusion` caches.
- **Kill Switch**: `/api/kill` orchestrates repository wipe, `data/` purge, optional shutdown; implemented in `kill_switch()` and gated by `confirmation == "ERASE_ALL_DATA"`.
- **Pwnagotchi bridge**: `/api/pwnagotchi/install`, `/status`, `/logs`, `/swap`, `/cancel` manage service switching via `_write_pwn_status_file()` and `_schedule_pwn_mode_switch()`.
- **AI**: `/api/ai/status|insights|network-summary|vulnerabilities|weaknesses|clear-cache|token` route into `AIService` for caching + token management.

### 11.2 WebSocket Events
- Registered events include `request_status`, `request_logs`, `request_network`, `request_credentials`, `request_loot`, `start_scan`, `stop_scan`, `request_activity`. Every handler emits structured JSON snapshots so the frontend can update without polling.
- Connection metrics (`clients_connected`) increment/decrement inside the `@socketio.on('connect'/'disconnect')` handlers, enabling UI banners warning when too many viewers are online.

## 12. AI Integration
- `ai_service.py` initializes GPT-5 Nano via OpenAI SDK when `ai_enabled` and `openai_api_token` are set. Supports alternative models via `ai_model` value.
- Capabilities toggled via config: `ai_analysis_enabled`, `ai_vulnerability_summaries`, `ai_network_insights`, `ai_personality` (tone), `ai_max_tokens`, `ai_temperature`.
- Cached responses (5 min TTL) stored in memory; optional disk cache (disabled by default) toggled with `ai_cache_to_disk` for offline review.
- API surface:
  - `GET /api/ai/status` – readiness, configured model, last run.
  - `GET /api/ai/insights`, `/network-summary`, `/vulnerabilities`, `/weaknesses` – structured JSON with textual + bullet guidance.
  - `POST /api/ai/clear-cache` – flush cached responses.
  - `POST /api/ai/run` – manual prompt injection (admin only).
- Integrates with Network Intelligence to pull sanitized host/service context (no raw credentials sent); redacts IP octets when `ai_privacy_mode` enabled.
- Prompts include metadata (host counts, CVE severities, Wi-Fi health) and personalities mimic Pwnagotchi-style quips for user engagement.
- Errors (quota exceeded, timeout) bubbled to UI with actionable remediation tips.

### 12.1 AIService Internals
- `EnvManager` loads `RAGNAR_OPENAI_API_KEY` from environment or `.env` and persists tokens when `/api/ai/token` POST/DELETE endpoints run.
- `_ask()` wraps the OpenAI Responses API with a two-pass system: attempt with configured `temperature`, then automatically retry without it if the model reports an unsupported parameter.
- Responses are cached per-input via `_cache_key()` using md5 hashes of the prompt JSON; the default TTL is 3600 s (overriding legacy 300 s) to minimize token usage on Pi deployments with limited bandwidth.
- `analyze_network_summary`, `analyze_vulnerabilities`, and `identify_network_weaknesses` are the three domain-specific prompt builders. Each checks flags (`ai_network_insights`, `ai_vulnerability_summaries`) before calling `_ask()` and logs token counts for auditing.

## 13. Configuration & Settings
- Master config file: `config/shared_config.json` (auto-created from defaults in `SharedData.get_default_config()`). JSON grouped by pseudo-headings (`__title_*`).
- Categories include scan timing, logging, Wi-Fi, display, AI, attack delays, wordlists, loot filters, AP behavior, and vulnerability scanning.
- Web UI writes to config via `SharedData.save_config()`, reloading relevant services dynamically. Hot-reload events propagate via `shared_data` watchers.
- Additional per-feature configs:
  - `config/actions.json` – defines every action module, ports, parents, priority, retry overrides.
  - `data/threat_intelligence/sources_config.json` – threat feed endpoints, keys, polling intervals.
  - `data/logs/logging_config.json` (optional) – overrides logger levels/handlers.
  - `resources/comments/comments.json` – curated display comments loaded at runtime.
- Key configuration highlights:
  | Key | Default | Description |
  | --- | --- | --- |
  | `scan_interval` | 180 | Seconds between orchestrator sweeps. |
  | `scan_vuln_interval` | 300 | Seconds between vuln scans (subject to incremental logic). |
  | `enable_attacks` | False | Master switch for offensive modules. |
  | `wifi_auto_ap_fallback` | True | Whether to start AP when STA fails. |
  | `wifi_failsafe_cycle_limit` | 20 | Disconnection cycles before auto-reboot. |
  | `epd_type` | `epd2in13_V4` | Display driver selection. |
  | `ai_enabled` | False | Enables AI insights; requires token. |
  | `release_gate_enabled` | False | Lock UI/API until passphrase provided (demo mode). |
  | `steal_file_names` | [...] | Keyword list used by loot modules. |
  | `mac_scan_blacklist` | [] | MACs excluded from scanning/attacks. |
- Runtime modules reference `shared_data.config` live; writes through the Web UI call `SharedData.save_config()` which flushes JSON, updates in-memory attributes, and triggers downstream watchers (e.g., Wi-Fi manager reloading known networks, display toggling `screen_reversed`).
- Config headings (`__title_*`) are used purely for UI grouping; the parser strips these keys automatically when exporting to Python dicts.

## 14. Folder Structure Highlights
| Path | Purpose |
| --- | --- |
| `actions/` | Attack and scan modules (FTP, SMB, SQL, BLE, etc.). |
| `config/` | `actions.json`, `shared_config.json`, threat source config. |
| `data/` | Logs, intelligence, per-network stores, loot, templates. |
| `data/networks/<slug>/` | Isolated DB, intelligence, loot for each SSID. |
| `resources/` | Images, fonts, WaveShare EPD drivers, comments, AP templates. |
| `web/` | Modern dashboard HTML/CSS/JS plus captive portal assets. |
| `scripts/` | Maintenance/install scripts (`install_pwnagotchi.sh`, `fix_permissions.sh`, etc.). |
| `var/log/` | Runtime logs (AP, orchestrator) when system paths writable. |
| `var/log/ragnar/` | Optional custom log dir for packaged releases. |
| `requirements.txt` | Python dependencies for pip installation. |
| `INSTALL.md`, `KILL_SWITCH.md`, `AI_INTEGRATION.md` | Topical documentation referenced by spec. |

## 15. Installation & Upgrade Flows
- **Automated install (`install_ragnar.sh`)**
  1. Download via wget/curl, make executable, run as root.
  2. Script installs apt dependencies (nmap, arp-scan, hostapd, dnsmasq, python3-pip, libopenjp2) and pip packages from `requirements.txt`.
  3. Copies systemd units (`ragnar.service`, `ragnar_wifi.service`, `ragnar_web.service`), enables them, and seeds `/etc/sudoers.d/ragnar` entries for necessary commands.
  4. Runs `init_data_files.sh` to create data directories, templates, and default configs.
  5. Prompts for reboot after verifying EPD hardware and Wi-Fi chips.
- **Manual install**: Clone repo, run `pip install -r requirements.txt`, execute `python3 init_shared.py`, configure systemd units manually.
- **Upgrades**: `quick_update.sh` performs `git pull`, checks requirements hash, re-runs pip if needed, migrates DB schema (via `db_manager` migrations), restarts services.
- **Helper scripts**: same as before plus `install_wifi_management.sh` (sets hostapd/dnsmasq configs) and `install_pwnagotchi.sh` bridging script.
- **Kill switch**: `/api/kill` wipes DBs, logs, repository, and can optionally schedule a shutdown. Requires a POST JSON body with `{"confirmation": "ERASE_ALL_DATA", "shutdown": false}` (shutdown flag optional) and logs through the standard logger—there is no dedicated `kill.log`.

### 15.1 Kill Switch Flow (`kill_switch()`)
1. Validate `confirmation == "ERASE_ALL_DATA"` and optional `shutdown` flag.
2. Delete `data/ragnar.db` (or active network DB path), followed by `data/` tree via `shutil.rmtree`.
3. Remove the entire repository directory (`ragnar_dir`) fetched either from `$HOME/Ragnar` or the running directory.
4. Log each step with CRITICAL severity and collect per-step success flags for the API response.
5. If `shutdown_after` is true, schedule `sudo shutdown now` after returning JSON so the HTTP response flushes before power-off.

## 16. Dashboard & Web Security Considerations
- JWT-less local API expected; rely on LAN isolation. Exposing publicly requires reverse proxy authentication (NGINX + OAuth) and HTTPS termination.
- AP portal served over HTTP; credentials stored locally in SQLite and exported to `wpa_supplicant.conf`. Consider VPN tunnel if onboarding remote networks.
- Sensitive actions (kill switch, shutdown, AP enable) present explicit confirmation prompts in the UI; the kill switch in particular forces the user to type `ERASE_ALL_DATA` before the POST is issued.
- CORS is currently wide open (`flask_cors.CORS(app)` with default settings and Socket.IO `cors_allowed_origins="*"`); harden via reverse proxy or code changes if exposure beyond trusted LAN/AP is required.
- No CSRF tokens are issued today; the dashboard relies on being reachable only from the trusted LAN/AP. Harden via reverse proxy auth or custom token middleware before exposing publicly.
- File downloads sanitized via whitelist to prevent directory traversal; uploads disabled by default.

### 16.1 Resource Monitoring & Backpressure
- `resource_monitor.ResourceMonitor` runs lightweight psutil checks; `get_system_status()` powers `/api/system/metrics` and provides `memory.percent`, `cpu.percent`, process/thread counts, and a health flag.
- `ResourceMonitor.can_start_operation()` is used by orchestrator actions and scanners to ensure at least `min_memory_mb` remains free. If available RAM dips below 80 MB, it logs `CRITICAL` and instructs callers to skip work to avoid Pi Zero kernel OOM killings.
- `force_garbage_collection()` (available but rarely used) can be triggered before expensive operations to reclaim memory without rebooting.

## 17. Known Vulnerabilities & Risks
- Running offensive modules (brute force, file stealing) must be authorized; defaults have `enable_attacks=False`. Enabling them without consent can violate local laws.
- Pi Zero resource exhaustion can still occur if custom actions disregard semaphore or spawn heavy subprocesses. Always profile new modules with `shared_data` instrumentation before enabling in production.
- AP mode exposes open HTTP portal—protect physical device to prevent rogue reconfiguration. Change default AP password and disable AP auto mode if device is in hostile environment.
- AI integration sends sanitized data to OpenAI; disable in air-gapped or regulated environments or configure local proxy/LLM.
- Kill switch relies on local HTTP endpoint; if Ragnar exposed publicly without auth, attacker could wipe device. Always gate reverse proxy with auth.
- Database encryption at rest not enabled by default; use encrypted FS (LUKS) for highly sensitive deployments.

## 18. Operational Runbook (Summary)
1. Boot device; Wi-Fi manager connects or launches AP. Verify `systemctl status ragnar.service` green before proceeding.
2. Once networked, initial ping sweep populates SQLite. Confirm via `data/logs/network_scanner.log` or dashboard host count.
3. Orchestrator loops:
  - Filter alive hosts from DB.
  - Execute parent actions (e.g., credential bruteforce) respecting ports.
  - Trigger child actions after success.
  - Schedule standalone maintenance tasks.
  - Monitor `data/logs/orchestrator.log` for failures/timeouts.
4. Nmap vulnerability scanner runs per interval and updates intelligence; check `/api/v1/intel/vulnerabilities` JSON for new findings or UI Vulnerabilities tab.
5. Dashboard, AI, and e-paper display live state from shared DB/intelligence files. If UI stale, restart `ragnar_web.service` or inspect WebSocket logs.
6. Logs rotate under `data/logs`; archive regularly. Kill switch wipes artifacts when needed—document reason externally before triggering.
7. For Pwnagotchi swaps: use Config tab control, wait for service handoff, reboot, then confirm mode via dashboard badges.

## 19. Future Enhancements (Backlog Snapshot)
- Remove legacy CSV artifacts once web fully migrates to SQLite/JSON.
- Expand AI personalities and add local LLM option for offline mode.
- Increase modularity of Wi-Fi AP portal to support captive portal templates per customer.
- Add automated remediation playbooks for recurring vulnerabilities.

## 20. API Endpoint Catalog
_Ground truth: `webapp_modern.py` as of December 2025. Methods shown exactly as implemented; unless noted, responses are JSON._

### 20.1 Core UI & Captive Portal
| Path(s) | Methods | Purpose |
| --- | --- | --- |
| `/` | GET | Serve the modern dashboard or redirect AP clients into captive portal flow. |
| `/<path:filename>` | GET | Static asset handler for everything under `web/`. |
| `/portal` | GET | Explicit captive portal landing page used during AP onboarding. |
| `/wifi`, `/wifi-config`, `/setup` | GET | Legacy Wi-Fi configuration screens kept for compatibility. |
| `/connecttest.txt`, `/generate_204`, `/gen_204`, `/ncsi.txt`, `/success.txt` | GET | Captive portal probe responses that redirect mobile devices back to `/portal`. |

### 20.2 Legacy/Compatibility Data Views
| Path | Methods | Purpose |
| --- | --- | --- |
| `/download_file` | GET | Older file-download helper (still used by legacy UI widgets). |
| `/get_logs` | GET | Legacy log fetcher (plain text). |
| `/list_files` | GET | Legacy directory listing endpoint. |
| `/list_credentials` | GET | Legacy credential CSV export. |
| `/network_data` | GET | Legacy combined network JSON blob. |
| `/netkb_data_json` | GET | Legacy NetKB snapshot for scripts that predate SQLite. |

### 20.3 Dashboard Status & Telemetry APIs
| Path | Methods | Purpose |
| --- | --- | --- |
| `/api/status` | GET | High-level Ragnar health summary (hosts, Wi-Fi, orchestrator state). |
| `/api/stats` | GET | Aggregated counters for UI scorecards. |
| `/api/dashboard/quick` | GET | Lightweight stats for splash/loading cards. |
| `/api/dashboard/stats` | GET | Full dashboard metrics bundle (graphs, loot counts, etc.). |
| `/api/display` | GET | Returns e-paper friendly status payload. |
| `/api/epaper-display` | GET | Serves the last rendered e-paper image for remote preview. |
| `/api/logs` | GET | Streams orchestrator/web logs to the UI log viewer. |
| `/api/logs/activity` | GET | Activity feed summarizing recent actions. |
| `/api/network` | GET | Current network snapshot (hosts, ports, tags). |
| `/api/network/stable` | GET | Debounced network stats for widgets that poll less frequently. |

### 20.4 Configuration & Profile Management
| Path | Methods | Purpose |
| --- | --- | --- |
| `/api/config` | GET/POST | Read or persist `shared_config.json` (with server-side validation). |
| `/api/config/apply-profile` | POST | Apply predefined display/EPD hardware profile. |
| `/api/config/detect-hardware` | GET | Detect Pi model/EPD to suggest defaults. |
| `/api/config/hardware-profiles` | GET | Enumerate supported hardware profiles. |
| `/api/actions` | GET | Dump parsed `actions.json` so the UI can show orchestrator graph. |
| `/api/data/reset-threat-intel` | POST | Purge cached threat intelligence for the active network. |
| `/api/data/reset-vulnerabilities` | POST | Clear vulnerability cache to force a fresh scan. |

### 20.5 Files, Loot & Knowledge Base
| Path | Methods | Purpose |
| --- | --- | --- |
| `/api/files/list` | GET | Enumerate files under per-network loot folders. |
| `/api/files/download` | GET | Stream a selected loot artifact (binary-safe). |
| `/api/files/upload` | POST | Upload files (disabled by default, used for configs). |
| `/api/files/delete` | POST | Remove selected files and update DB inventory. |
| `/api/files/clear` | POST | Bulk-delete generated files (cleanup). |
| `/api/loot` | GET | Structured loot inventory (files + credentials) for UI cards. |
| `/api/credentials` | GET | Combined credential cache (modern + legacy view). |
| `/api/netkb/data` | GET | Live NetKB export sourced from SQLite. |
| `/api/netkb/entry/<entry_id>` | GET | Fetch an individual NetKB record for detailed inspection. |
| `/api/netkb/export` | GET | CSV/JSON export of the full NetKB. |

### 20.6 Network Discovery, Manual Control & Automation
| Path | Methods | Purpose |
| --- | --- | --- |
| `/api/attack` | GET/POST | View or trigger attack log streaming (manual kick capability). |
| `/api/manual/status` | GET | Indicates whether manual mode is active. |
| `/api/manual/targets` | GET | List of hosts eligible for manual actions. |
| `/api/manual/execute-attack` | POST | Run a single attack module manually. |
| `/api/manual/orchestrator/start`, `/api/manual/orchestrator/stop` | POST | Override orchestrator lifecycle when in manual mode. |
| `/api/manual/pentest/lynis` | POST | Fire the on-demand Lynis SSH pentest module. |
| `/api/manual/scan/network`, `/api/manual/scan/vulnerability` | POST | Force immediate network or vulnerability scans. |
| `/api/automation/orchestrator/start`, `/api/automation/orchestrator/stop` | POST | Toggle scheduled automation workflows. |
| `/api/scan/arp-localnet`, `/api/scan/combined-network`, `/api/scan/nmap-ping`, `/api/scan/status` | GET | Read-only scan telemetry (recent runs, combined results, ping view). |
| `/api/scan/start-realtime`, `/api/scan/deep`, `/api/scan/host` | POST | Kick off realtime scanning, deep single-host scans, or host-specific jobs. |

### 20.7 Threat & Vulnerability Intelligence
| Path | Methods | Purpose |
| --- | --- | --- |
| `/api/network-intelligence` | GET | Active/resolved findings for the current SSID. |
| `/api/network-intelligence/add-credential` | POST | Insert a credential finding (manual or scripted). |
| `/api/network-intelligence/add-vulnerability` | POST | Insert a vulnerability finding. |
| `/api/vulnerabilities`, `/api/vulnerabilities/grouped` | GET | Raw + grouped vulnerability lists for dashboard tabs. |
| `/api/vulnerability-intel` | GET | Summarized remediation intelligence (AI-ready payload). |
| `/api/vulnerability-report/<path:filename>` | GET | Download generated vulnerability/PDF reports. |
| `/api/vulnerability-scan/history` | GET | Retrieve historical vuln scan metadata. |
| `/api/vulnerability-scan/history/reset` | POST | Clear vuln scan history (DB + files). |
| `/api/threat-intelligence/dashboard` | GET | Aggregated threat intel KPI cards (feed health, counts). |
| `/api/threat-intelligence/enriched-findings` | GET | Per-source enriched findings (CISA/NVD/OTX). |
| `/api/threat-intelligence/status` | GET | Feed status + last refresh info. |
| `/api/threat-intelligence/trigger-vuln-scan` | POST | Force vulnerability scan when a new threat hits. |
| `/api/threat-intelligence/enrich-finding`, `/api/threat-intelligence/enrich-target` | POST | Enrich a specific CVE/host pair on demand. |
| `/api/threat-intelligence/download-report` | POST | Generate and download compiled threat reports. |

### 20.8 AI Service
| Path | Methods | Purpose |
| --- | --- | --- |
| `/api/ai/status` | GET | AI readiness + configured model summary. |
| `/api/ai/insights` | GET | Cached AI insights bundle (network summary cards). |
| `/api/ai/network-summary` | GET | Viking-style overall assessment text. |
| `/api/ai/vulnerabilities` | GET | Structured vulnerability analysis from GPT-5. |
| `/api/ai/weaknesses` | GET | Attack-path assessment generated by AI. |
| `/api/ai/clear-cache` | POST | Flush in-memory AI cache. |
| `/api/ai/token` | GET/POST/DELETE | Preview, save, or remove the OpenAI API key via `EnvManager`. |

### 20.9 Wi-Fi & AP Operations
| Path | Methods | Purpose |
| --- | --- | --- |
| `/api/wifi/interfaces` | GET | Enumerate WLAN interfaces + capabilities. |
| `/api/wifi/status` | GET | Current Wi-Fi connection state, RSSI, validation counters. |
| `/api/wifi/networks` | GET | Last scan results + analytics per SSID. |
| `/api/wifi/log` | GET | Tail AP/Wi-Fi manager logs. |
| `/api/wifi/scan` | POST | Trigger a fresh Wi-Fi scan. |
| `/api/wifi/connect` | POST | Connect to a selected SSID (applies portal credentials). |
| `/api/wifi/disconnect` | POST | Drop current Wi-Fi connection. |
| `/api/wifi/reconnect` | POST | Retry last-known SSID. |
| `/api/wifi/forget` | POST | Remove SSID from known-network list. |
| `/api/wifi/exit-ap` | POST | Leave AP mode and resume STA attempts. |
| `/api/wifi/ap/enable`, `/api/wifi/ap/start`, `/api/wifi/ap/stop`, `/api/wifi/ap/exit` | POST | Manage AP lifecycle flags and hostapd/dnsmasq processes. |
| `/api/wifi/force-recovery` | POST | Invoke Wi-Fi failsafe routines (restart services, clean state). |

### 20.10 Bluetooth Operations
| Path | Methods | Purpose |
| --- | --- | --- |
| `/api/bluetooth/devices` | GET | Enumerate seen Bluetooth devices. |
| `/api/bluetooth/status` | GET | Bluetooth adapter state, discoverability, logs. |
| `/api/bluetooth/diagnose` | GET | Run built-in diagnostics to check stack health. |
| `/api/bluetooth/enable`, `/api/bluetooth/disable` | POST | Toggle adapter power. |
| `/api/bluetooth/discoverable/on`, `/api/bluetooth/discoverable/off` | POST | Control discoverability. |
| `/api/bluetooth/scan/start`, `/api/bluetooth/scan/stop` | POST | Start/stop discovery scans. |
| `/api/bluetooth/enumerate` | POST | Enumerate profiles/services on a target device. |
| `/api/bluetooth/pair`, `/api/bluetooth/unpair` | POST | Manage device pairing. |
| `/api/bluetooth/pentest/blueborne-scan`, `/api/bluetooth/pentest/beacon-track`, `/api/bluetooth/pentest/exfiltrate`, `/api/bluetooth/pentest/track-movement` | POST | Specialized BLE pentest modules. |
| `/api/bluetooth/pentest/report` | GET | Retrieve the latest BLE pentest report. |
| `/api/bluetooth/pentest/beacon-track` etc. | POST | Additional pentest workflows (credential exfil, tracking). |

### 20.11 System Maintenance & Debug
| Path | Methods | Purpose |
| --- | --- | --- |
| `/api/system/status` | GET | CPU/RAM/disk/process overview (ResourceMonitor-backed). |
| `/api/system/network-stats` | GET | Low-level network interface stats. |
| `/api/system/processes` | GET | Running process list (filtered). |
| `/api/system/check-updates` | GET | Git + pip update availability. |
| `/api/system/update` | POST | Run `git pull` + pip sync (blocking). |
| `/api/system/stash-update` | POST | Stash dirty tree and update safely. |
| `/api/system/fix-git` | POST | Apply safe.directory fix when running off removable media. |
| `/api/system/reboot` | POST | Reboot the device. |
| `/api/system/restart-service` | POST | Restart a named systemd service. |
| `/api/debug/ai-service`, `/api/debug/orchestrator-status`, `/api/debug/connectivity-tracking`, `/api/debug/scanned-networks`, `/api/debug/test-robust-tracking`, `/api/debug/verbose-logs` | GET | Deep-dive diagnostics per subsystem. |
| `/api/debug/force-arp-scan` | POST | Immediate ARP scan for troubleshooting. |

### 20.12 Pwnagotchi Bridge
| Path | Methods | Purpose |
| --- | --- | --- |
| `/api/pwnagotchi/status` | GET | Current Pwnagotchi install/switch state. |
| `/api/pwnagotchi/install` | POST | Kick off the installer script. |
| `/api/pwnagotchi/logs` | GET | Stream installer/service logs. |
| `/api/pwnagotchi/swap` | POST | Schedule Ragnar ↔ Pwnagotchi mode swap. |

### 20.13 Kill Switch & Data Hygiene
| Path | Methods | Purpose |
| --- | --- | --- |
| `/api/kill` | POST | Authenticated educational kill switch that wipes DBs, data directory, and repo (requires `confirmation=ERASE_ALL_DATA`). |

## 21. References
- `README.md` – feature overview and quick start.
- `INSTALL.md` – detailed installation walkthrough.
- `AI_INTEGRATION.md` – instructions for GPT-5 Nano setup.
- `KILL_SWITCH.md` – secure wipe procedure.
- Source files referenced in this spec for deeper context.
