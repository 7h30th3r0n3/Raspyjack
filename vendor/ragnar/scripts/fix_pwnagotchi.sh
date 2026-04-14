#!/bin/bash
# Quick fix script for pwnagotchi issues (config, Pillow compat, log dir)
set -euo pipefail

echo "[INFO] Fixing pwnagotchi configuration and compatibility..."

# 1. Create missing directories
echo "[INFO] Creating required directories..."
mkdir -p /etc/pwnagotchi/log /etc/pwnagotchi/conf.d /etc/pwnagotchi/custom_plugins

# 2. Fix config (proper TOML booleans, correct display/web settings)
echo "[INFO] Fixing config.toml..."
python3 << 'PYEOF'
import tomlkit
with open('/etc/pwnagotchi/config.toml', 'r') as f:
    doc = tomlkit.parse(f.read())
doc['ui']['display']['enabled'] = True
doc['ui']['display']['type'] = 'waveshare_4'
doc['ui']['display']['rotation'] = 180
doc['ui']['display']['color'] = 'black'
doc['ui']['web']['enabled'] = True
doc['ui']['web']['username'] = 'ragnar'
doc['ui']['web']['password'] = 'ragnar'
doc['main']['plugins']['grid']['enabled'] = False
with open('/etc/pwnagotchi/config.toml', 'w') as f:
    f.write(tomlkit.dumps(doc))
print('[INFO] config.toml updated')
PYEOF

# 3. Install Pillow compatibility shim (getsize removed in Pillow 10+)
echo "[INFO] Installing Pillow compatibility shim..."
python3 << 'PYEOF'
import site, os
sp = site.getsitepackages()[0]
shim = os.path.join(sp, 'pillow_compat.py')
with open(shim, 'w') as f:
    f.write("""from PIL import ImageFont
if not hasattr(ImageFont.FreeTypeFont, 'getsize'):
    def _getsize(self, text, *args, **kwargs):
        bbox = self.getbbox(text, *args, **kwargs)
        return (bbox[2]-bbox[0], bbox[3]-bbox[1]) if bbox else (0, 0)
    ImageFont.FreeTypeFont.getsize = _getsize
if not hasattr(ImageFont.FreeTypeFont, 'getmetrics'):
    def _getmetrics(self):
        bbox = self.getbbox('Ay')
        return (bbox[3] if bbox else 0, 0)
    ImageFont.FreeTypeFont.getmetrics = _getmetrics
""")
print(f'[INFO] Shim written to {shim}')

cli = '/opt/pwnagotchi/pwnagotchi/cli.py'
with open(cli, 'r') as f:
    content = f.read()
if 'pillow_compat' not in content:
    with open(cli, 'w') as f:
        f.write('import pillow_compat\n' + content)
    print('[INFO] Shim injected into cli.py')
else:
    print('[INFO] Shim already injected')
PYEOF

# 4. Restart pwnagotchi
echo "[INFO] Restarting pwnagotchi..."
systemctl restart pwnagotchi

sleep 5
echo ""
echo "[INFO] Pwnagotchi status:"
systemctl is-active pwnagotchi || true
journalctl -u pwnagotchi -n 10 --no-pager
echo ""
echo "[INFO] Done. Web UI should be at http://$(hostname -I | awk '{print $1}'):8080 (ragnar/ragnar)"
