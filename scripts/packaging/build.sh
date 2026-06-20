#!/bin/bash
set -euo pipefail

python3 -m py_compile \
  raspyjack.py \
  device_server.py \
  web_server.py \
  input_events.py \
  rj_input.py \
  evdev_keys.py \
  gpio_config.py \
  gpio_shim.py \
  LCD_1in44.py \
  LCD_Config.py \
  nmap_parser.py

find wifi EXTENSIONS payloads -type f -name '*.py' -print0 \
  | xargs -0 -r python3 -m py_compile

echo "Syntax check passed."
