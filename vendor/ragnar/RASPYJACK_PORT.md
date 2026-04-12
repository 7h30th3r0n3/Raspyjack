# Ragnar In Raspyjack

This directory vendors `PierreGode/Ragnar` so Raspyjack can ship a close
1:1 copy of the upstream project.

- Upstream: `https://github.com/PierreGode/Ragnar`
- Imported as a vendored tree, excluding only the upstream `.git/` directory
- Raspyjack-specific integration lives in `raspyjack_headless.py`

The vendored Ragnar app is launched from Raspyjack through the payload
`payloads/utilities/ragnar.py`, which starts Ragnar's headless web stack on
port `8091` by default so it can coexist with Raspyjack's own WebUI.
