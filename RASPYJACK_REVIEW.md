# RaspyJack Codebase Review

Bug & optimization sweep of the RaspyJack codebase (CardputerZero / Pi-Zero-class,
~352 MB usable RAM, OOMs under load). Prompted by the class of bugs found and fixed
in `payloads/utilities/ragnar.py` (PR #117): local-API field-name mismatches,
UI-loop blocking, too-short HTTP timeouts, memory heaviness, and ordinary
correctness bugs.

`payloads/utilities/ragnar.py` is **excluded** (already fixed in PR #117).

## Scope of this review

Focused (not exhaustive) review of the files most likely to carry the ragnar bug
classes, plus the shared helpers that every payload imports:

- `raspyjack.py` (main LCD app) — status/display/input loops, WiFi/battery polling
- Shared helpers: `payloads/_gps_helper.py`, `payloads/_iface_helper.py`,
  `payloads/_input_helper.py`, `payloads/_display_helper.py` (read), `_cc1101_driver.py`
- WiFi stack: `wifi/wifi_manager.py`, `wifi/raspyjack_integration.py`, `wifi/route_control.py`
- GPS payloads: `hardware/gps_live.py`, `hardware/gps_tracker.py`, `utilities/GPS_Doctor.py`
- SDR / recon samples: `sdr/sdr_adsb.py`, `sdr/cap_flipper_subghz.py`, `reconnaissance/wardriving.py`
- Full-tree greps for each bug class (local `/api/` consumers, `is True` / `== "True"`
  success checks, short HTTP timeouts, heavy `web_server`/`raspyjack` imports,
  mutable default args, serial/file-handle leaks, gpsd lifecycle).

**Vendored third-party code is out of scope**: `vendor/ragnar/*`,
`Responder/tools/MultiRelay/impacket-dev/*`.

## Headline: the ragnar bug classes did NOT replicate broadly

- **Field-name mismatch (local API):** Only `ragnar.py` consumed the device's
  `/api/wifi/status`, `/api/wifi/networks` etc. over HTTP. Every other first-party
  payload reads WiFi/interface state through the in-process helpers in
  `wifi/raspyjack_integration.py` / `wifi/wifi_manager.py`, and their producer /
  consumer key contracts match (`status` / `ip` / `connected`, and `ssid` from
  `get_connection_status`). No replicated mismatch found.
- **UI-loop blocking:** `raspyjack.py` already does the right thing — a background
  `_stats_loop` thread owns all subprocess polling (`iwgetid`, `pgrep`, temp,
  battery) and the render path is a dirty-flag `_display_loop`. `sdr_adsb.py`,
  `wardriving.py`, `sdr/cap_flipper_subghz.py` all push network/scan work onto
  background threads with shared snapshots. No synchronous network/scan calls found
  on a render/input loop.
- **Memory heaviness:** `sdr_adsb.py` bounds its route cache at 500 entries;
  `gps_live.py` trims its NMEA buffer to 100; `wardriving.py` uses O(1) incremental
  counters. No other payload re-imports the heavy `web_server` engine the way
  ragnar did.

The real findings are concentrated in the **GPS helper area**.

## Confirmed bugs (fixed in this PR)

### 1. `payloads/_gps_helper.py` — `get_gps_data()` missing (important) ✅ FIXED
`payloads/sdr/cap_flipper_subghz.py:1266` does
`from payloads._gps_helper import get_gps_data`, and the module's own docstring
(`_gps_helper.py:10`) advertises `get_gps_data`, but the function was **never
defined**. The import raised `ImportError`, swallowed by the caller's bare
`except`, so GPS signal-tagging in the Sub-GHz capture tool silently never worked.
**Fix:** implemented `get_gps_data()` reading the running gpsd via the `gpsd`
(`gpsd-py3`) module — the same module `hardware/gps_tracker.py` already uses —
returning `{lat, lon, alt, speed, mode, sats}` or `None`, matching the `lat`/`lon`
keys the caller reads.

### 2. `payloads/hardware/gps_live.py` — gpsd left stopped on failure paths (important) ✅ FIXED
`_reader()` stops/kills gpsd (lines ~201-203) so it can read the serial port
directly, then restarts it only on the **normal** loop-exit path. The early
`return`s for "no GPS detected" (`if not dev`) and "serial open failed"
(`except ... as e`) returned **after** gpsd was killed, leaving gpsd dead — which
breaks every other GPS-consuming payload (e.g. `gps_tracker.py`, `espnow_evil_master.py`,
`cap_flipper_subghz` tagging) until reboot. `ser.close()` was also skipped on those
paths. **Fix:** wrapped the body in `try/finally` so gpsd is always restarted and
the serial port is always closed, on every exit path.

### 3. `payloads/_gps_helper.py:65` — serial handle leak on read exception (minor) ✅ FIXED
In `detect_gps()`, if `serial.Serial(...)` succeeded but `ser.read()` raised, the
`except: continue` skipped `ser.close()`, leaking the port handle across the
baud-rate probe loop (5 bauds × several devices). **Fix:** moved `ser.close()` into
a `finally`.

## Report-only recommendations (not changed — lower confidence / opinionated)

### 4. `wifi/raspyjack_integration.py:154 get_interface_status` — `connected` hardcodes eth0 (minor)
`connected` is only ever `True` for `wlan*` (via wifi_manager) or the literal
`eth0` with an IP. A second wired interface (`eth1`, `enx…`, `usb0`) that has an IP
reports `connected=False`. Low impact on single-NIC CardputerZero, but worth
generalizing to "has a usable IPv4 + is up" if multi-NIC support is expected.

### 5. Short HTTP timeouts to external/local services (minor, acceptable as-is)
`sdr/sdr_adsb.py:165` (OpenSky, `timeout=3`), `utilities/torrent_client.py:174`,
`reconnaissance/cctv_scanner.py:325` (`timeout=3`). Unlike ragnar's busy local web
engine, these run on **background** threads and fail soft, so a short timeout only
delays enrichment rather than freezing the UI. Consider bumping to 5-8 s to reduce
spurious misses, but not required.

### 6. `payloads/_iface_helper.py:154` — dead code (nit)
`is_virtual = os.path.islink(...) is False` is computed but never used. Harmless;
remove for clarity.

### 7. `raspyjack.py:2227 ShowLines(arr, bold=[])` — mutable default arg (nit)
`bold` defaults to a shared mutable list but is only read (`if i in bold`), never
mutated, so it is not an active bug. Prefer `bold=None` / `bold = bold or []` as a
matter of style.

## Verification

All changed Python compiles cleanly:

```
python -m py_compile payloads/_gps_helper.py payloads/hardware/gps_live.py
```

Changes are confined to the GPS helper and the GPS-live payload — no shared
display/input/menu code touched — so blast radius is limited to GPS features.
