#!/usr/bin/env python3
"""
Quick WiFi Connect payload
--------------------------
Auto-connect to the strongest *saved* WiFi network currently in range.
If no saved network is found, suggest using the full WiFi Manager.
"""

import os
import sys
import subprocess
import time

# Ensure RaspyJack modules are importable when launched directly
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

LCD_OK = False
LCD = None
WIDTH, HEIGHT = 128, 128
font = None


def _init_lcd():
    global LCD_OK, LCD, font
    try:
        import LCD_1in44, LCD_Config  # type: ignore
        from PIL import ImageFont  # type: ignore

        LCD_Config.GPIO_Init()
        LCD = LCD_1in44.LCD()
        LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
        LCD.LCD_Clear()
        font = ImageFont.load_default()
        LCD_OK = True
    except Exception:
        LCD_OK = False


def _show(lines, progress=None):
    text = "\n".join(lines)
    print(text)
    if not LCD_OK:
        return
    try:
        from PIL import Image, ImageDraw  # type: ignore

        img = Image.new("RGB", (WIDTH, HEIGHT), "BLACK")
        draw = ImageDraw.Draw(img)
        y = 5
        for line in lines:
            if line:
                draw.text((5, y), line[:18], font=font, fill="WHITE")
                y += 14
        if progress is not None:
            p = max(0.0, min(1.0, progress))
            x0, y0, x1, y1 = 6, 112, 122, 120
            draw.rectangle((x0, y0, x1, y1), outline="WHITE", fill="BLACK")
            fill_w = int((x1 - x0) * p)
            if fill_w > 0:
                draw.rectangle((x0, y0, x0 + fill_w, y1), fill="WHITE")
        LCD.LCD_ShowImage(img, 0, 0)
    except Exception:
        pass


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def _get_saved_wifi():
    res = _run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"])
    if res.returncode != 0:
        return []
    saved = []
    for line in res.stdout.strip().splitlines():
        if not line:
            continue
        name, ctype = line.split(":", 1)
        if ctype in ("wifi", "802-11-wireless") and name:
            saved.append(name)
    return saved


def _scan_wifi():
    res = _run(["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "dev", "wifi", "list", "--rescan", "no"])
    if res.returncode != 0:
        res = _run(["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "dev", "wifi", "list", "--rescan", "yes"])
        if res.returncode != 0:
            return []
    networks = []
    for line in res.stdout.strip().splitlines():
        if not line:
            continue
        parts = line.split(":")
        if len(parts) < 3:
            continue
        ssid = parts[0].strip()
        if not ssid:
            continue
        try:
            signal = int(parts[1])
        except ValueError:
            signal = 0
        security = parts[2]
        networks.append({"ssid": ssid, "signal": signal, "security": security})
    return networks


def _get_wifi_device():
    res = _run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "dev"])
    if res.returncode != 0:
        return None
    for line in res.stdout.strip().splitlines():
        if not line:
            continue
        dev, dtype, state = line.split(":", 2)
        if dtype == "wifi" and state in ("connected", "connecting", "disconnected"):
            return dev
    return None


def main():
    _init_lcd()
    _show(["Quick WiFi", "Scanning...", "", "Please wait"], progress=0.10)
    saved = _get_saved_wifi()
    if not saved:
        _show(["No saved WiFi", "Use WiFi Manager", "", "Exiting"], progress=1.0)
        time.sleep(0.8)
        return 1

    nets = _scan_wifi()
    candidates = [n for n in nets if n["ssid"] in saved]
    if not candidates:
        _show(["No saved", "WiFi in range", "Use WiFi Manager", "Exiting"], progress=1.0)
        time.sleep(0.8)
        return 1

    best = sorted(candidates, key=lambda x: x["signal"], reverse=True)[0]
    _show(
        ["SSID:", best["ssid"][:16], f"Signal: {best['signal']}", "Connecting..."],
        progress=0.55,
    )

    res = _run(["nmcli", "dev", "wifi", "connect", best["ssid"]])
    if res.returncode != 0:
        _show(["Connect failed", best["ssid"][:16], "Use WiFi Manager", ""], progress=1.0)
        time.sleep(0.8)
        return 1

    dev = _get_wifi_device() or "wlan0"
    _show(
        ["Connected", best["ssid"][:16], f"Interface: {dev}", "Getting IP..."],
        progress=0.80,
    )
    ip_res = _run(["ip", "-4", "addr", "show", "dev", dev])
    ip = "unknown"
    if ip_res.returncode == 0:
        for line in ip_res.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                ip = line.split()[1].split("/")[0]
                break

    _show(["Connected", best["ssid"][:16], f"IP: {ip[:15]}", ""], progress=1.0)
    time.sleep(0.8)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
