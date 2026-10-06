# RaspyJack — CardputerZero AppStore submission

Everything needed to publish RaspyJack to the CardputerZero AppStore, and how to
reproduce the compliance checks.

## Identity

| Field | Value |
|---|---|
| App name (store title) | `RaspyJack` |
| Package name | `raspyjack` |
| Categories | `Security`, `Radio & Comms` |
| License | `MIT` |
| Author | `7h30th3r0n3` (GitHub login) |
| Maintainer | `7h30th3r0n3 <flavienruffel@gmail.com>` |
| share_code | `RJAK` |
| Source | https://github.com/7h30th3r0n3/RaspyJack |
| Demo video | https://youtu.be/_IUcM0DcV38 |

Store metadata lives in `app-builder.json` (`store` block). `scripts/prepublish.sh`
derives the store-side `meta.json` from it at check time.

## Build

```bash
bash scripts/build-deb.sh     # arm64 via ghcr.io/cardputerzero/build-env (Docker)
# → dist/raspyjack_<version>-raspyjack1_arm64.deb  (~20 MB)
```
CI (`.github/workflows/build-cardputerzero-deb.yml`) builds the same artifact on
push / release.

## Compliance — reproduce locally

```bash
bash scripts/prepublish.sh
```
Runs the three official validators (fetched live from the CardputerZero repos):
`install_path_policy.py`, `store_meta_policy.py`, `prepublish_check.py`.

Verified status (device-independent):

- install-path policy: **pass** (everything under `usr/share/APPLaunch/**`)
- store-meta policy: **pass** (1 advisory only: optional `locales`)
- prepublish check: **pass**
- all 59 `Depends` exist in Debian Trixie stock — **no Kali repo needed**
- no setuid/setgid; real Maintainer; `RJAK` + `RaspyJack` unique store-wide

## Still required on a real device

- [ ] 4 screenshots at **exactly 320×170 px**, saved in `screenshots/` (see its README)
- [ ] Install on a **freshly flashed** CardputerZero (official Trixie arm64 image via
      M5 Imager) and confirm it appears in and launches from **APPLaunch**
- [ ] Confirm passwordless `sudo` for the UID 1000 user (the launcher wrapper relies on it)
- [ ] Demo video already recorded: https://youtu.be/_IUcM0DcV38 (ideally also show it
      launching from APPLaunch on a clean device)

## Submit (as `7h30th3r0n3`, first-come-first-served name ownership)

Two equivalent channels:

1. **CLI** — `czdev login` then `czdev publish --deb dist/raspyjack_*.deb`
   (forks `CardputerZero/packages`, uploads the .deb as a release asset, opens a PR).
2. **Web** — https://dev.cardputer.cc/#/upload (GitHub OAuth, upload the .deb).

The **first release of a new package is not auto-merged**: post the demo video in the
PR; a maintainer merges after review. Later version bumps auto-merge once validation
passes. Bump `PKG_VERSION` (or tag a release) so each submission is strictly newer.
