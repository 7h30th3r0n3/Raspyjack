#!/usr/bin/env python3
"""
RaspyJack Payload -- Mobile GPS Receiver
==========================================
Author: 7h30th3r0n3

Starts an HTTP server that serves a page using the Geolocation API.
User opens the page on their smartphone, which sends GPS coordinates
back to the RPi periodically. Displays position on the LCD.

Setup / Prerequisites
---------------------
- Smartphone and RPi on the same network (or RPi AP mode).
- Modern mobile browser with Geolocation API support.

Controls
--------
  KEY1        -- Start / stop HTTP server
  KEY2        -- Export track log to CSV
  UP / DOWN   -- Scroll log entries
  KEY3        -- Exit

Loot: /root/Raspyjack/loot/GPS/
"""

import os
import sys
import time
import json
import threading
import socket
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
font = scaled_font()

LOOT_DIR = "/root/Raspyjack/loot/GPS"
HTTP_PORT = 8888
DEBOUNCE = 0.20
ROW_H = 12

lock = threading.Lock()
_app_running = True

# Shared state
_latest_pos = {
    "lat": 0.0, "lon": 0.0, "acc": 0.0,
    "alt": 0.0, "speed": 0.0, "ts": "",
}
_track_log = []  # list of dicts
_server_running = False
_httpd = None
_status_msg = "Server stopped"


HTML_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>RaspyJack GPS</title>
<style>body{font-family:sans-serif;background:#111;color:#0f0;padding:20px;text-align:center}
h2{color:#0cf}#st{color:#fa0}button{font-size:18px;padding:10px 20px;margin:10px}</style>
</head><body>
<h2>RaspyJack GPS</h2><p id="st">Waiting...</p><p id="co"></p>
<script>
var iv=null;
function send(p){
  var x=new XMLHttpRequest();
  x.open("POST","/gps",true);
  x.setRequestHeader("Content-Type","application/json");
  var d={lat:p.coords.latitude,lon:p.coords.longitude,
         acc:p.coords.accuracy||0,alt:p.coords.altitude||0,
         speed:p.coords.speed||0};
  x.send(JSON.stringify(d));
  document.getElementById("st").textContent="Sending...";
  document.getElementById("co").textContent=
    "Lat:"+d.lat.toFixed(6)+" Lon:"+d.lon.toFixed(6);
}
function err(e){document.getElementById("st").textContent="Error: "+e.message;}
if(navigator.geolocation){
  navigator.geolocation.getCurrentPosition(send,err,{enableHighAccuracy:true});
  iv=setInterval(function(){
    navigator.geolocation.getCurrentPosition(send,err,{enableHighAccuracy:true});
  },3000);
}else{document.getElementById("st").textContent="Geolocation not supported";}
</script></body></html>"""


class _GPSHandler(BaseHTTPRequestHandler):
    """Handle GET (serve page) and POST (receive GPS data)."""

    def log_message(self, format, *args):
        pass  # suppress console output

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(HTML_PAGE.encode("utf-8"))

    def do_POST(self):
        global _latest_pos, _track_log, _status_msg
        if self.path != "/gps":
            self.send_response(404)
            self.end_headers()
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            data = json.loads(body)
        except (ValueError, json.JSONDecodeError):
            self.send_response(400)
            self.end_headers()
            return

        ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        pos = {
            "lat": float(data.get("lat", 0)),
            "lon": float(data.get("lon", 0)),
            "acc": float(data.get("acc", 0)),
            "alt": float(data.get("alt", 0)),
            "speed": float(data.get("speed", 0)),
            "ts": ts,
        }

        with lock:
            _latest_pos = pos
            _track_log = _track_log + [pos]
            _status_msg = f"Fix at {ts[-9:-1]}"

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')


def _get_device_ip():
    """Get the device's local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "0.0.0.0"


def _start_server():
    """Start HTTP server in a thread."""
    global _httpd, _server_running, _status_msg
    try:
        _httpd = HTTPServer(("0.0.0.0", HTTP_PORT), _GPSHandler)
        with lock:
            _server_running = True
            _status_msg = "Server running"
        _httpd.serve_forever()
    except OSError as exc:
        with lock:
            _status_msg = f"Err: {str(exc)[:16]}"
            _server_running = False


def _stop_server():
    """Shutdown the HTTP server."""
    global _httpd, _server_running, _status_msg
    if _httpd is not None:
        _httpd.shutdown()
        _httpd = None
    with lock:
        _server_running = False
        _status_msg = "Server stopped"


def _export_track(entries):
    """Export track log to CSV."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fpath = os.path.join(LOOT_DIR, f"track_{ts}.csv")
    try:
        with open(fpath, "w") as fh:
            fh.write("timestamp,latitude,longitude,accuracy,altitude,speed\n")
            for p in entries:
                fh.write(f"{p['ts']},{p['lat']},{p['lon']},{p['acc']},{p['alt']},{p['speed']}\n")
        return f"Saved {len(entries)} pts"
    except OSError as exc:
        return f"Err: {str(exc)[:14]}"


def _draw_header(d, title):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), title[:20], font=font, fill="#00ccff")


def _draw_footer(d, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:26], font=font, fill="#666")


def _draw_screen(pos, track, scroll, running, status):
    """Draw the main GPS display."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    _draw_header(d, "MOBILE GPS")

    indicator_color = "#00ff00" if running else "#ff4444"
    d.ellipse((118, 3, 124, 9), fill=indicator_color)

    y = 16
    d.text((2, y), status[:22], font=font, fill="#ffaa00"); y += ROW_H

    if pos["ts"]:
        d.text((2, y), f"Lat: {pos['lat']:11.6f}", font=font, fill="#00ff00"); y += ROW_H
        d.text((2, y), f"Lon: {pos['lon']:11.6f}", font=font, fill="#00ff00"); y += ROW_H
        d.text((2, y), f"Acc: {pos['acc']:.1f}m", font=font, fill="#ccc"); y += ROW_H
        d.text((2, y), f"Alt: {pos['alt']:.1f}m", font=font, fill="#ccc"); y += ROW_H
        d.text((2, y), f"Spd: {pos['speed']:.1f}m/s", font=font, fill="#ccc"); y += ROW_H

        # Simple crosshair indicator
        cx, cy_c = 100, 80
        d.line((cx - 8, cy_c, cx + 8, cy_c), fill="#00ccff")
        d.line((cx, cy_c - 8, cx, cy_c + 8), fill="#00ccff")
        d.ellipse((cx - 3, cy_c - 3, cx + 3, cy_c + 3), outline="#00ff00")
    else:
        ip = _get_device_ip()
        d.text((2, y), f"Open on phone:", font=font, fill="#ccc"); y += ROW_H
        d.text((2, y), f"http://{ip}", font=font, fill="#00ff00"); y += ROW_H
        d.text((2, y), f":{HTTP_PORT}", font=font, fill="#00ff00"); y += ROW_H
        d.text((2, y), "Waiting for GPS...", font=font, fill="#666"); y += ROW_H

    d.text((2, 104), f"Track: {len(track)} pts", font=font, fill="#888")
    _draw_footer(d, "K1:srv K2:export K3:ex")
    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global _app_running, _status_msg
    scroll = 0
    last_press = 0.0
    server_thread = None

    try:
        while True:
            btn = get_button(PINS, GPIO)
            now = time.time()
            if btn and (now - last_press) < DEBOUNCE:
                btn = None
            if btn:
                last_press = now

            if btn == "KEY3":
                break
            elif btn == "KEY1":
                with lock:
                    running = _server_running
                if running:
                    threading.Thread(target=_stop_server, daemon=True).start()
                else:
                    server_thread = threading.Thread(target=_start_server, daemon=True)
                    server_thread.start()
            elif btn == "KEY2":
                with lock:
                    entries = list(_track_log)
                if entries:
                    result = _export_track(entries)
                    with lock:
                        _status_msg = result
                else:
                    with lock:
                        _status_msg = "No track data"
            elif btn == "UP":
                scroll = max(0, scroll - 1)
            elif btn == "DOWN":
                scroll += 1

            with lock:
                pos = dict(_latest_pos)
                track = list(_track_log)
                running = _server_running
                status = _status_msg

            _draw_screen(pos, track, scroll, running, status)
            time.sleep(0.15)

    finally:
        _app_running = False
        _stop_server()
        if _track_log:
            _export_track(_track_log)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
