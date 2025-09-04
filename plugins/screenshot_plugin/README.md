# Screenshot Plugin

Captures the current framebuffer/LCD content to a timestamped PNG when the user performs a **LONG_PRESS** on **KEY2_PIN**. Useful for debugging UI layouts, documenting states, or attaching visual evidence to automated reports.

## Features
- One‑gesture capture (LONG_PRESS KEY2_PIN)
- Optional periodic automatic capture (configurable interval)
- Lossless PNG output (small for 128×128)
- Timestamped filenames: `shot_YYYYMMDD_HHMMSS_mmm.png`
- Automatic screenshots directory creation (`screenshots/` under install root)
- Status bar transient message on success (if not busy)
- Structured event emissions for automation / integrations

## Capture Trigger
| Action | Condition |
|--------|-----------|
| Capture | Long press (press & hold) on KEY2_PIN -> emits events & saves PNG |

## Configuration
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `periodic_enabled` | boolean | `false` | Enable periodic screenshot capture |
| `periodic_interval` | number (s) | `60` | Interval (seconds) between captures (min 5s) |

When `periodic_enabled` is true, the plugin emits screenshots roughly every `periodic_interval` seconds (first capture occurs after the first interval elapses). Manual LONG_PRESS captures still work and are marked `periodic=false`.

## Emitted Events
All events use the prefix `screenshot.` allowing wildcard subscription (`screenshot.*`).

| Event | When | Payload Fields |
|-------|------|----------------|
| `screenshot.capture.start` | Just before framebuffer snapshot | `periodic` (bool) |
| `screenshot.captured` | After successful save | `file` (absolute path), `timestamp`, `periodic` (bool) |
| `screenshot.capture.failed` | Any exception during capture | `error` (string), `periodic` (bool) |
| `screenshot.directory.ready` | Screenshots directory created/validated | `path` |
| `screenshot.directory.error` | Failed to create directory | `path`, `error` |

### Example Subscription
```python
pm = context['plugin_manager']  # if accessible
pm.subscribe_event('screenshot.*', lambda evt, data: print(evt, data))
```

## File Storage
- Directory: `<install_root>/screenshots/`
- Naming pattern: `shot_<YYYYMMDD>_<HHMMSS>_<ms>.png` (milliseconds truncated to 3 digits)
- Typical size: ~2–10 KB (depends on image complexity & palette)

You can safely copy or archive these images externally; no hidden metadata is embedded beyond PNG basics.

## Integration Ideas
| Goal | Approach |
|------|----------|
| Auto‑upload to Discord | Add an `event_hook` in the Discord Notifier referencing `screenshot.captured` and attach `{file}` |
| Batch export | Periodically zip the `screenshots/` folder via a payload script |
| Automated test evidence | Trigger a synthetic LONG_PRESS event in a test harness, then read the most recent file |

### Discord Event Hook Example
If using the Discord Notifier plugin:
```jsonc
"event_hooks": [
  {
    "id": "shot_upload",
    "event": "screenshot.captured",
    "embed": {
      "title": "Screenshot Captured",
      "description": "File: {file}\nTime: {timestamp}",
      "color": 39423
    },
    "files": ["{file}"]
  }
]
```

## Status / Info Panel
The plugin `get_info()` output includes:
- Directory path
- File count
- Last captured filename
- Aggregate size (KB)
- Trigger hint

## Failure Modes & Handling
| Scenario | Behavior | Event |
|----------|----------|-------|
| Directory cannot be created | Prints error, emits directory error | `screenshot.directory.error` |
| Exception during save | Prints error, emits failure | `screenshot.capture.failed` |
| Status bar busy | Skips transient message | *(no extra event)* |

Failures are intentionally non‑blocking—subsequent captures can still succeed.

## Performance Notes
- Capture clones the in‑memory image; negligible overhead (< a few ms) at 128×128.
- No threading: operation fast enough to run inline.
- PNG compression defaults are sufficient; no additional tuning required.

---
Log prefix: `[Screenshot]`
Events prefix: `screenshot.`
