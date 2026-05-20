#!/usr/bin/env python3
"""
RaspyJack Payload -- ADS-B Aircraft Tracker
=============================================
Track aircraft via ADS-B (1090 MHz) using RTL-SDR.
Decodes Mode-S messages: callsign, position, altitude, speed.
Displays on LCD + serves WebUI map on port 8081.

Controls:
  OK         Start/Stop tracking
  UP/DOWN    Scroll aircraft list
  KEY1       Switch view (List / Map / Stats)
  KEY2       Toggle WebUI server
  KEY3       Exit
"""

import os
import sys
import time
import math
import json
import struct
import subprocess
import threading
from datetime import datetime
import urllib.request
from io import BytesIO
from PIL import ImageEnhance
from http.server import SimpleHTTPRequestHandler, HTTPServer

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font, S
from payloads._input_helper import get_button
from payloads.sdr._sdr_core import detect_sdr

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
LOOT_DIR = "/root/Raspyjack/loot/SDR/adsb"
DEBOUNCE = 0.18
_last_btn = 0
VIEWS = ["list", "detail", "map", "stats"]
WEBUI_PORT = 8081

# ADS-B constants
ADSB_FREQ = 1090000000
ADSB_RATE = 2000000
MODES_PREAMBLE = [1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0]

# Aircraft database
aircraft = {}
lock = threading.Lock()
_shutdown = threading.Event()


def _btn():
    global _last_btn
    btn = get_button(PINS, GPIO)
    if btn:
        now = time.time()
        if now - _last_btn < DEBOUNCE:
            return None
        _last_btn = now
    return btn


# ---------------------------------------------------------------------------
# Mode-S decoder (pure Python, no pyModeS)
# ---------------------------------------------------------------------------

def _hex_to_bin(hexstr):
    return bin(int(hexstr, 16))[2:].zfill(len(hexstr) * 4)


def _crc(msg_hex):
    """CRC-24 for Mode-S messages."""
    msg_bin = _hex_to_bin(msg_hex)
    n_bits = len(msg_bin)
    gen = 0x1FFF409
    msg_int = int(msg_bin, 2)
    for i in range(n_bits - 24):
        if msg_int & (1 << (n_bits - 1 - i)):
            msg_int ^= gen << (n_bits - 25 - i)
    return msg_int & 0xFFFFFF


def _decode_callsign(msg_hex):
    """Decode aircraft callsign from TC=1-4."""
    chars = "?ABCDEFGHIJKLMNOPQRSTUVWXYZ????? 0123456789??????"
    msg_bin = _hex_to_bin(msg_hex)
    data = msg_bin[40:88]
    cs = ""
    for i in range(8):
        idx = int(data[8 + i * 6:8 + i * 6 + 6], 2)
        if idx < len(chars):
            cs += chars[idx]
    return cs.strip()


def _decode_altitude(msg_hex):
    """Decode altitude from TC=9-18 (airborne position)."""
    msg_bin = _hex_to_bin(msg_hex)
    alt_bits = msg_bin[40:52]
    q_bit = alt_bits[7]
    if q_bit == "1":
        alt_code = alt_bits[:7] + alt_bits[8:]
        alt = int(alt_code, 2) * 25 - 1000
        return alt
    return None


def _decode_cpr_position(msg_hex):
    """Extract CPR latitude/longitude from TC=9-18. Returns (lat_cpr, lon_cpr, odd_flag)."""
    msg_bin = _hex_to_bin(msg_hex)
    flag = int(msg_bin[53])
    lat_cpr = int(msg_bin[54:71], 2) / 131072.0
    lon_cpr = int(msg_bin[71:88], 2) / 131072.0
    return lat_cpr, lon_cpr, flag


def _decode_velocity(msg_hex):
    """Decode velocity from TC=19."""
    msg_bin = _hex_to_bin(msg_hex)
    sub = int(msg_bin[37:40], 2)
    if sub in (1, 2):
        ew_dir = int(msg_bin[45])
        ew_vel = int(msg_bin[46:56], 2) - 1
        ns_dir = int(msg_bin[56])
        ns_vel = int(msg_bin[57:67], 2) - 1
        if ew_dir:
            ew_vel = -ew_vel
        if ns_dir:
            ns_vel = -ns_vel
        speed = int((ew_vel ** 2 + ns_vel ** 2) ** 0.5)
        heading = int(math.degrees(math.atan2(ew_vel, ns_vel)) % 360)
        return speed, heading
    return None, None


def _cpr_global_position(lat0, lon0, lat1, lon1):
    """Decode global position from even (0) and odd (1) CPR frames."""
    dLat0 = 360.0 / 60
    dLat1 = 360.0 / 59
    j = int(math.floor(59 * lat0 - 60 * lat1 + 0.5))
    lat_even = dLat0 * (j % 60 + lat0)
    lat_odd = dLat1 * (j % 59 + lat1)
    if lat_even >= 270:
        lat_even -= 360
    if lat_odd >= 270:
        lat_odd -= 360

    # Use even frame for now
    lat = lat_even
    try:
        nl = max(1, int(math.floor(2 * math.pi / (math.acos(1 - (1 - math.cos(math.pi / 30)) / (math.cos(math.radians(lat)) ** 2))))))
    except (ValueError, ZeroDivisionError):
        nl = 1
    m = int(math.floor(lon0 * (nl - 1) - lon1 * nl + 0.5))
    lon = (360.0 / nl) * (m % nl + lon0)
    if lon > 180:
        lon -= 360
    return lat, lon


def _process_message(msg_hex):
    """Process a Mode-S message. Update aircraft dict."""
    if len(msg_hex) < 28:
        return
    df = int(msg_hex[0:2], 16) >> 3
    if df != 17:
        return
    if _crc(msg_hex) != 0:
        return

    icao = msg_hex[2:8].upper()
    tc = int(_hex_to_bin(msg_hex)[32:37], 2)

    with lock:
        if icao not in aircraft:
            aircraft[icao] = {
                "icao": icao, "callsign": "", "alt": 0, "lat": 0, "lon": 0,
                "speed": 0, "heading": 0, "seen": time.time(),
                "cpr_even": None, "cpr_odd": None, "messages": 0,
            }
        ac = aircraft[icao]
        ac["seen"] = time.time()
        ac["messages"] += 1

        if 1 <= tc <= 4:
            ac["callsign"] = _decode_callsign(msg_hex)
        elif 9 <= tc <= 18:
            alt = _decode_altitude(msg_hex)
            if alt is not None:
                ac["alt"] = alt
            lat_cpr, lon_cpr, flag = _decode_cpr_position(msg_hex)
            if flag == 0:
                ac["cpr_even"] = (lat_cpr, lon_cpr, time.time())
            else:
                ac["cpr_odd"] = (lat_cpr, lon_cpr, time.time())
            if ac["cpr_even"] and ac["cpr_odd"]:
                t0 = ac["cpr_even"][2]
                t1 = ac["cpr_odd"][2]
                if abs(t0 - t1) < 10:
                    lat, lon = _cpr_global_position(
                        ac["cpr_even"][0], ac["cpr_even"][1],
                        ac["cpr_odd"][0], ac["cpr_odd"][1],
                    )
                    if -90 <= lat <= 90 and -180 <= lon <= 180:
                        ac["lat"] = round(lat, 5)
                        ac["lon"] = round(lon, 5)
        elif tc == 19:
            speed, heading = _decode_velocity(msg_hex)
            if speed is not None:
                ac["speed"] = speed
                ac["heading"] = heading




def _draw_plane(draw, x, y, heading, size=6, color="#00FF88"):
    """Draw a small plane icon rotated to heading."""
    rad = math.radians(heading)
    sin_h = math.sin(rad)
    cos_h = math.cos(rad)
    # Nose
    nx = x + int(sin_h * size)
    ny = y - int(cos_h * size)
    # Tail
    tx = x - int(sin_h * size * 0.6)
    ty = y + int(cos_h * size * 0.6)
    # Left wing
    lx = x - int(cos_h * size * 0.7) - int(sin_h * size * 0.2)
    ly = y - int(sin_h * size * 0.7) + int(cos_h * size * 0.2)
    # Right wing
    rx = x + int(cos_h * size * 0.7) - int(sin_h * size * 0.2)
    ry = y + int(sin_h * size * 0.7) + int(cos_h * size * 0.2)
    # Body line
    draw.line([(nx, ny), (tx, ty)], fill=color, width=2)
    # Wings
    draw.line([(lx, ly), (rx, ry)], fill=color, width=2)
    # Tail wings (smaller)
    tw = size * 0.35
    tlx = tx - int(cos_h * tw)
    tly = ty - int(sin_h * tw)
    trx = tx + int(cos_h * tw)
    tr_y = ty + int(sin_h * tw)
    draw.line([(tlx, tly), (trx, tr_y)], fill=color, width=1)

# ---------------------------------------------------------------------------
# Map tile system (OSM)
# ---------------------------------------------------------------------------
_TILE_CACHE = "/root/Raspyjack/loot/SDR/adsb/.tilecache"
_TILE_URL = "https://tile.openstreetmap.org/{z}/{x}/{y}.png"
_map_bg = None
_map_bbox = None


def _lat_to_merc(lat):
    lat = max(-85.0, min(85.0, lat))
    return math.log(math.tan(math.pi / 4 + math.radians(lat) / 2))


def _fetch_tile(z, x, y):
    os.makedirs(_TILE_CACHE, exist_ok=True)
    path = os.path.join(_TILE_CACHE, f"{z}_{x}_{y}.png")
    if os.path.isfile(path):
        try:
            return Image.open(path).convert("RGB")
        except Exception:
            pass
    try:
        req = urllib.request.Request(
            _TILE_URL.format(z=z, x=x, y=y),
            headers={"User-Agent": "RaspyJack/1.0"},
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = resp.read()
        with open(path, "wb") as f:
            f.write(data)
        return Image.open(BytesIO(data)).convert("RGB")
    except Exception:
        return None


def _build_map(center_lat, center_lon, width, height, zoom=7):
    n = 2 ** zoom
    x_center = int((center_lon + 180.0) / 360.0 * n)
    lat_rad = math.radians(max(-85, min(85, center_lat)))
    y_center = int((1.0 - math.log(math.tan(lat_rad) + 1.0 / math.cos(lat_rad)) / math.pi) / 2.0 * n)

    big = Image.new("RGB", (3 * 256, 3 * 256), (10, 14, 24))
    for dx in range(-1, 2):
        for dy in range(-1, 2):
            tile = _fetch_tile(zoom, x_center + dx, y_center + dy)
            if tile:
                big.paste(tile, ((dx + 1) * 256, (dy + 1) * 256))

    nw_lon = (x_center - 1) / n * 360.0 - 180.0
    se_lon = (x_center + 2) / n * 360.0 - 180.0
    nw_lat = math.degrees(math.atan(math.sinh(math.pi * (1 - 2 * (y_center - 1) / n))))
    se_lat = math.degrees(math.atan(math.sinh(math.pi * (1 - 2 * (y_center + 2) / n))))

    darkened = ImageEnhance.Brightness(big).enhance(0.4)
    resized = darkened.resize((width, height), Image.LANCZOS)
    bbox = (_lat_to_merc(nw_lat), _lat_to_merc(se_lat), nw_lon, se_lon)
    return resized, bbox


def _map_project(lat, lon, bbox, width, height):
    nw_merc, se_merc, nw_lon, se_lon = bbox
    merc_span = nw_merc - se_merc
    lon_span = se_lon - nw_lon
    if merc_span == 0 or lon_span == 0:
        return width // 2, height // 2
    merc = _lat_to_merc(lat)
    x = int((lon - nw_lon) / lon_span * width)
    y = int((nw_merc - merc) / merc_span * height)
    return max(0, min(width - 1, x)), max(0, min(height - 1, y))

# ---------------------------------------------------------------------------
# RTL-SDR ADS-B receiver thread
# ---------------------------------------------------------------------------

def _adsb_receiver():
    """Capture 1090 MHz using rtl_adsb and decode Mode-S messages."""
    while not _shutdown.is_set():
        try:
            subprocess.run(["pkill", "-9", "rtl_adsb"], capture_output=True)
            time.sleep(0.3)
            proc = subprocess.Popen(
                ["rtl_adsb", "-g", "50"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1,
            )

            for line in proc.stdout:
                if _shutdown.is_set():
                    break
                line = line.strip()
                if not line or not line.startswith("*"):
                    continue
                msg_hex = line.strip("*;").strip()
                if len(msg_hex) >= 28:
                    _process_message(msg_hex)

            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        except Exception:
            pass
        if not _shutdown.is_set():
            time.sleep(1)


# ---------------------------------------------------------------------------
# WebUI server
# ---------------------------------------------------------------------------

_webui_running = False
_webui_server = None

WEBUI_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>RaspyJack ADS-B Radar</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="/vendor/leaflet/leaflet.css">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0e14;color:#c8d0dc;font-family:'Segoe UI',system-ui,sans-serif;overflow:hidden;height:100vh}
#map{height:100vh;width:100%;position:absolute;top:0;left:0;z-index:1}
.leaflet-container{background:#0a0e14}
#sidebar{position:absolute;top:0;right:0;width:340px;height:100vh;background:rgba(8,12,20,0.92);
  border-left:1px solid #1a2844;z-index:1000;display:flex;flex-direction:column;backdrop-filter:blur(10px)}
#header{padding:12px 16px;background:rgba(0,20,40,0.8);border-bottom:1px solid #1a2844}
#header h1{font-size:16px;color:#00ccff;font-weight:600;letter-spacing:1px}
#header .sub{font-size:11px;color:#4a6080;margin-top:2px}
#stats{display:flex;gap:8px;padding:8px 16px;border-bottom:1px solid #0d1a2e}
.stat{flex:1;text-align:center;padding:6px;background:rgba(0,40,80,0.3);border-radius:6px;border:1px solid #0d2040}
.stat .val{font-size:20px;font-weight:700;color:#00ff88}
.stat .lbl{font-size:9px;color:#4a6080;text-transform:uppercase;letter-spacing:1px}
#list{flex:1;overflow-y:auto;padding:4px 0}
#list::-webkit-scrollbar{width:4px}
#list::-webkit-scrollbar-thumb{background:#1a3050;border-radius:2px}
.ac{display:flex;align-items:center;padding:8px 16px;cursor:pointer;border-bottom:1px solid #0a1525;transition:background 0.15s}
.ac:hover{background:rgba(0,100,200,0.15)}
.ac.selected{background:rgba(0,150,255,0.2);border-left:3px solid #00ccff}
.ac-icon{font-size:20px;margin-right:10px;transform-origin:center}
.ac-info{flex:1;min-width:0}
.ac-call{font-size:13px;font-weight:600;color:#00ff88}
.ac-icao{font-size:10px;color:#3a5070;margin-left:6px}
.ac-details{font-size:11px;color:#6080a0;margin-top:2px}
.ac-alt{color:#ffaa00}
.ac-spd{color:#00bbff}
.tag-live{display:inline-block;width:6px;height:6px;background:#00ff88;border-radius:50%;margin-right:6px;
  animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}
#footer{padding:8px 16px;background:rgba(0,15,30,0.8);border-top:1px solid #1a2844;
  font-size:10px;color:#3a5070;display:flex;justify-content:space-between}
.plane-marker{color:#00ff88;font-size:22px;text-shadow:0 0 8px rgba(0,255,136,0.5);
  transition:transform 0.3s;display:flex;align-items:center;justify-content:center}
.plane-label{position:absolute;left:18px;top:-2px;font-size:10px;color:#00ccff;
  background:rgba(0,20,40,0.8);padding:1px 4px;border-radius:2px;white-space:nowrap;
  border:1px solid #0d2040;font-family:monospace}
@media(max-width:768px){
  #sidebar{width:100%;height:45vh;top:auto;bottom:0;border-left:none;border-top:1px solid #1a2844}
  #map{height:55vh}
}
</style></head><body>
<div id="map"></div>
<div id="sidebar">
  <div id="header"><h1>ADSB RADAR</h1><div class="sub">RaspyJack &bull; 1090 MHz</div></div>
  <div id="stats">
    <div class="stat"><div class="val" id="s-ac">0</div><div class="lbl">Aircraft</div></div>
    <div class="stat"><div class="val" id="s-msg">0</div><div class="lbl">Messages</div></div>
    <div class="stat"><div class="val" id="s-pos">0</div><div class="lbl">Positions</div></div>
  </div>
  <div id="list"></div>
  <div id="footer"><span>Auto-refresh 1.5s</span><span id="clock"></span></div>
</div>
<script src="/vendor/leaflet/leaflet.js"></script>
<script>
const map=L.map('map',{zoomControl:false}).setView([46.8,2.3],6);
L.control.zoom({position:'topleft'}).addTo(map);
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{
  maxZoom:18,attribution:'CartoDB'}).addTo(map);
let markers={},trails={},selected=null;
function hdgIcon(h){
  return L.divIcon({className:'',iconSize:[30,30],iconAnchor:[15,15],
    html:`<div class="plane-marker" style="transform:rotate(${h||0}deg)">&#9992;</div>`})}
function refresh(){
  fetch('/api/adsb/aircraft').then(r=>r.json()).then(data=>{
    let html='',totalMsg=0,withPos=0;
    data.forEach(ac=>{
      totalMsg+=ac.messages;
      if(ac.lat&&ac.lon)withPos++;
      const cs=ac.callsign||ac.icao;
      const sel=selected===ac.icao?'selected':'';
      html+=`<div class="ac ${sel}" onclick="selectAc('${ac.icao}',${ac.lat},${ac.lon})">
        <div class="ac-icon" style="transform:rotate(${ac.heading||0}deg)">&#9992;</div>
        <div class="ac-info">
          <div><span class="tag-live"></span><span class="ac-call">${cs}</span><span class="ac-icao">${ac.icao}</span></div>
          <div class="ac-details"><span class="ac-alt">${ac.alt.toLocaleString()}ft</span> &bull;
            <span class="ac-spd">${ac.speed}kt</span> &bull; ${ac.heading}&deg;</div>
        </div></div>`;
      if(ac.lat&&ac.lon){
        if(!markers[ac.icao]){
          markers[ac.icao]=L.marker([ac.lat,ac.lon],{icon:hdgIcon(ac.heading)}).addTo(map);
          trails[ac.icao]=L.polyline([],{color:'#00ff8840',weight:1,dashArray:'4'}).addTo(map);
        }else{
          markers[ac.icao].setLatLng([ac.lat,ac.lon]);
          markers[ac.icao].setIcon(hdgIcon(ac.heading));
          const t=trails[ac.icao].getLatLngs();
          t.push([ac.lat,ac.lon]);
          if(t.length>100)t.shift();
          trails[ac.icao].setLatLngs(t);
        }
        markers[ac.icao].bindPopup(`<div style="font-family:monospace;background:#0a0e14;color:#c8d0dc;padding:8px;border-radius:4px">
          <b style="color:#00ff88;font-size:14px">${cs}</b><br>
          <span style="color:#ffaa00">${ac.alt.toLocaleString()} ft</span><br>
          ${ac.speed} kt &bull; ${ac.heading}&deg;<br>
          <span style="color:#4a6080">${ac.lat.toFixed(4)}, ${ac.lon.toFixed(4)}</span><br>
          <span style="color:#3a5070">${ac.messages} msgs</span></div>`,{className:'dark-popup'});
      }
    });
    document.getElementById('list').innerHTML=html||'<div style="padding:40px;text-align:center;color:#3a5070">Waiting for aircraft...</div>';
    document.getElementById('s-ac').textContent=data.length;
    document.getElementById('s-msg').textContent=totalMsg>999?(totalMsg/1000).toFixed(1)+'k':totalMsg;
    document.getElementById('s-pos').textContent=withPos;
    // Remove stale markers
    const ids=new Set(data.map(a=>a.icao));
    Object.keys(markers).forEach(k=>{if(!ids.has(k)){map.removeLayer(markers[k]);map.removeLayer(trails[k]);delete markers[k];delete trails[k]}});
  }).catch(()=>{});
  document.getElementById('clock').textContent=new Date().toLocaleTimeString();
}
function selectAc(icao,lat,lon){
  selected=icao;
  if(lat&&lon)map.setView([lat,lon],10);
}
setInterval(refresh,1500);refresh();
</script></body></html>"""


class ADSBHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="/root/Raspyjack/web", **kwargs)

    def do_GET(self):
        if self.path == "/adsb" or self.path == "/adsb/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(WEBUI_HTML.encode())
        elif self.path == "/api/adsb/aircraft":
            with lock:
                now = time.time()
                active = [ac for ac in aircraft.values() if now - ac["seen"] < 60]
                active.sort(key=lambda a: -a["messages"])
            data = []
            for ac in active:
                data.append({
                    "icao": ac["icao"], "callsign": ac["callsign"],
                    "alt": ac["alt"], "lat": ac["lat"], "lon": ac["lon"],
                    "speed": ac["speed"], "heading": ac["heading"],
                    "messages": ac["messages"],
                    "squawk": ac.get("squawk", ""),
                    "rssi": ac.get("rssi", 0),
                })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
        elif self.path.startswith("/vendor/"):
            self.path = self.path
            super().do_GET()
        elif self.path == "/" or self.path == "":
            self.send_response(302)
            self.send_header("Location", "/adsb")
            self.end_headers()
        else:
            super().do_GET()

    def log_message(self, format, *args):
        pass


def _start_webui():
    global _webui_server, _webui_running
    try:
        _webui_server = HTTPServer(("0.0.0.0", WEBUI_PORT), ADSBHandler)
        # directory set in handler __init__
        _webui_running = True
        _webui_server.serve_forever()
    except Exception:
        _webui_running = False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    font = scaled_font(10)
    font_sm = scaled_font(9)
    real_w, real_h = lcd.width, lcd.height

    _map_bg = None
    _map_bbox = None

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), "Detecting SDR...", font=font_sm, fill="#FFAA00")
    lcd.LCD_ShowImage(img, 0, 0)

    found, desc, _backend = detect_sdr()
    if not found:
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.text((4, 50), "No RTL-SDR!", font=font, fill="#FF4444")
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1



    _map_bg = None
    _map_bbox = None
    _map_zoom = 7
    _map_lat = 46.8  # Default France center
    _map_lon = 2.3
    _map_manual = False  # True when user has panned/zoomed manually
    tracking = False
    receiver_thread = None
    webui_thread = None
    view_idx = 0
    scroll = 0
    status = desc[:20]

    try:
        while True:
            btn = _btn()
            if btn == "KEY3":
                break
            if btn == "KEY1":
                view_idx = (view_idx + 1) % len(VIEWS)
                scroll = 0

            view = VIEWS[view_idx]
            if view == "map":
                if btn == "UP":
                    _map_lat += 0.5 / (2 ** (_map_zoom - 5))
                    _map_manual = True
                    _map_bg = None
                elif btn == "DOWN":
                    _map_lat -= 0.5 / (2 ** (_map_zoom - 5))
                    _map_manual = True
                    _map_bg = None
                elif btn == "LEFT":
                    _map_lon -= 0.7 / (2 ** (_map_zoom - 5))
                    _map_manual = True
                    _map_bg = None
                elif btn == "RIGHT":
                    _map_lon += 0.7 / (2 ** (_map_zoom - 5))
                    _map_manual = True
                    _map_bg = None
                elif btn == "KEY2":
                    _map_zoom = min(15, _map_zoom + 1)
                    _map_bg = None
                elif btn == "OK" and not tracking:
                    pass  # handled below
                elif btn == "OK" and tracking:
                    pass  # handled below
            else:
                if btn == "UP":
                    scroll = max(0, scroll - 1)
                elif btn == "DOWN":
                    scroll += 1

            if btn == "OK":
                if view == "map" and tracking:
                    _map_zoom = max(3, _map_zoom - 1)
                    _map_bg = None
                elif not tracking:
                    tracking = True
                    _shutdown.clear()
                    receiver_thread = threading.Thread(target=_adsb_receiver, daemon=True)
                    receiver_thread.start()
                    status = "Tracking..."
                elif view != "map":
                    tracking = False
                    _shutdown.set()
                    status = "Stopped"

            if btn == "KEY2":
                if not _webui_running:
                    webui_thread = threading.Thread(target=_start_webui, daemon=True)
                    webui_thread.start()
                    time.sleep(0.5)
                    status = f"WebUI :8081"

            with lock:
                now = time.time()
                active = [ac for ac in aircraft.values() if now - ac["seen"] < 60]
                active.sort(key=lambda a: -a["messages"])
                total_msg = sum(ac["messages"] for ac in aircraft.values())
                with_pos = sum(1 for ac in active if ac["lat"] != 0)

            view = VIEWS[view_idx]

            # === LIST VIEW ===
            if view == "list":
                img = Image.new("RGB", (real_w, real_h), "black")
                draw = ImageDraw.Draw(img)
                s = max(1, S(1))

                # Header
                draw.rectangle([(0, 0), (real_w, 14*s)], fill="#111111")
                draw.text((2*s, 2*s), "ADS-B TRACKER", font=font_sm, fill="#00CCFF")
                draw.text((real_w - 80*s, 2*s), f"{len(active)}ac  {total_msg}msg", font=font_sm, fill="#888888")
                if tracking:
                    draw.ellipse([real_w - 8*s, 4*s, real_w - 2*s, 10*s], fill="#00FF00")

                # Column positions scaled to screen width
                cw = real_w
                C = [int(cw*0.01), int(cw*0.18), int(cw*0.34), int(cw*0.48), int(cw*0.60), int(cw*0.72), int(cw*0.85)]

                # Column headers
                y = 16
                draw.rectangle([(0, y), (real_w, y + 10)], fill="#0a1525")
                for label, cx in zip(["CALL","ICAO","ALT","SPD","HDG","SQK","POS"], C):
                    draw.text((cx, y + 1), label, font=font_sm, fill="#4a6080")

                y = 28
                if not active:
                    draw.text((real_w // 2, real_h // 2), "Press OK to track", font=font_sm, fill="#666666", anchor="mm")
                else:
                    row_h = 12
                    visible = max(1, (real_h - 42) // row_h)
                    for i in range(scroll, min(len(active), scroll + visible)):
                        if y + row_h > real_h - 14:
                            break
                        ac = active[i]
                        cs = ac["callsign"] or "-"
                        has_pos = ac["lat"] != 0

                        # Alternate row bg
                        if i % 2 == 0:
                            draw.rectangle([(0, y), (real_w, y + row_h)], fill="#0a0e18")

                        draw.text((C[0], y), cs[:7], font=font_sm, fill="#00FF88")
                        draw.text((C[1], y), ac["icao"][:6], font=font_sm, fill="#4488AA")
                        draw.text((C[2], y), f"{ac['alt']}", font=font_sm, fill="#FFAA00")
                        draw.text((C[3], y), f"{ac['speed']}", font=font_sm, fill="#00BBFF")
                        draw.text((C[4], y), f"{ac['heading']}°", font=font_sm, fill="#AAAAAA")
                        sq = ac.get("squawk", "")
                        sq_col = "#FF4444" if sq == "7700" else "#FFAA00" if sq in ("7600", "7500") else "#666666"
                        draw.text((C[5], y), sq if sq else "-", font=font_sm, fill=sq_col)
                        pos_icon = "●" if has_pos else "○"
                        draw.text((C[6], y), pos_icon, font=font_sm, fill="#00FF00" if has_pos else "#333333")
                        y += row_h

                # Footer
                draw.rectangle([(0, real_h - 12*s), (real_w, real_h)], fill="#111111")
                draw.text((2*s, real_h - 11*s), "OK:Track K1:View K2:Web UD:Scroll", font=font_sm, fill="#666666")
                lcd.LCD_ShowImage(img, 0, 0)

            # === DETAIL VIEW (single aircraft) ===
            elif view == "detail":
                img = Image.new("RGB", (real_w, real_h), "#0a0e18")
                draw = ImageDraw.Draw(img)
                s = max(1, S(1))

                draw.rectangle([(0, 0), (real_w, 14*s)], fill="#111111")
                draw.text((2*s, 2*s), "AIRCRAFT DETAIL", font=font_sm, fill="#00CCFF")
                draw.text((real_w - 40*s, 2*s), f"{scroll + 1}/{len(active)}", font=font_sm, fill="#888888")

                if not active:
                    draw.text((real_w // 2, real_h // 2), "No aircraft", font=font, fill="#666666", anchor="mm")
                else:
                    idx = min(scroll, len(active) - 1)
                    ac = active[idx]
                    cs = ac["callsign"] or "Unknown"
                    y = 18*s

                    # Callsign big
                    draw.text((real_w // 2, y + 2*s), cs, font=font, fill="#00FF88", anchor="mm")
                    y += 20

                    # ICAO + Squawk line
                    draw.text((4*s, y), f"ICAO: {ac['icao']}", font=font_sm, fill="#4488AA")
                    sq = ac.get("squawk", "")
                    if sq:
                        sq_col = "#FF4444" if sq == "7700" else "#FFAA00" if sq in ("7600", "7500") else "#00CCFF"
                        draw.text((real_w - 60*s, y), f"SQK: {sq}", font=font_sm, fill=sq_col)
                    y += 16

                    # Separator
                    draw.line([(4*s, y), (real_w - 4*s, y)], fill="#1a2844")
                    y += 6

                    # Data rows
                    rows = [
                        ("Altitude", f"{ac['alt']:,} ft", "#FFAA00"),
                        ("Speed", f"{ac['speed']} kt", "#00BBFF"),
                        ("Heading", f"{ac['heading']}°", "#AAAAAA"),
                        ("Position", f"{ac['lat']:.4f}, {ac['lon']:.4f}" if ac['lat'] else "No position", "#00FF88" if ac['lat'] else "#666666"),
                        ("Messages", f"{ac['messages']}", "#888888"),
                        ("RSSI", f"{ac.get('rssi', 0):.1f} dB", "#CC88FF"),
                    ]
                    for label, value, col in rows:
                        draw.text((10, y), f"{label}:", font=font_sm, fill="#4a6080")
                        draw.text((real_w // 3, y), value, font=font_sm, fill=col)
                        y += 14

                # Footer
                draw.rectangle([(0, real_h - 12*s), (real_w, real_h)], fill="#111111")
                draw.text((2*s, real_h - 11*s), "UD:Prev/Next K1:View K2:Web", font=font_sm, fill="#666666")
                lcd.LCD_ShowImage(img, 0, 0)

            # === MAP VIEW ===
            elif view == "map":
                pos_acs = [ac for ac in active if ac["lat"] != 0 and ac["lon"] != 0]
                s = max(1, S(1))

                # Auto-center on aircraft if not manually panned
                if pos_acs and not _map_manual:
                    lats = [ac["lat"] for ac in pos_acs]
                    lons = [ac["lon"] for ac in pos_acs]
                    _map_lat = sum(lats) / len(lats)
                    _map_lon = sum(lons) / len(lons)

                # Build/rebuild map tiles when needed
                if _map_bg is None or _map_bbox is None:
                    _map_bg, _map_bbox = _build_map(_map_lat, _map_lon, real_w, real_h, zoom=_map_zoom)

                img = _map_bg.copy()
                draw = ImageDraw.Draw(img)

                # Plot aircraft
                for ac in pos_acs:
                    px, py = _map_project(ac["lat"], ac["lon"], _map_bbox, real_w, real_h)
                    if 0 <= px < real_w and 0 <= py < real_h:
                        hdg = ac.get("heading", 0)
                        _draw_plane(draw, px, py, hdg, size=7, color="#00FF88")
                        cs = ac["callsign"] or ac["icao"][:4]
                        draw.text((px + 10, py - 4), cs[:6], font=font_sm, fill="#00CCFF")
                        if ac["alt"] > 0:
                            draw.text((px + 10, py + 6), f"{ac['alt']}ft", font=font_sm, fill="#888888")

                # Crosshair center
                cx, cy = real_w // 2, real_h // 2
                draw.line([(cx - 4, cy), (cx + 4, cy)], fill="#ffffff40")
                draw.line([(cx, cy - 4), (cx, cy + 4)], fill="#ffffff40")

                # Header
                draw.rectangle([(0, 0), (real_w, 14*s)], fill="#000000")
                draw.text((2*s, 2*s), f"MAP z{_map_zoom} {len(pos_acs)}/{len(active)}ac", font=font_sm, fill="#00CCFF")
                if tracking:
                    draw.ellipse([real_w - 8*s, 4*s, real_w - 2*s, 10*s], fill="#00FF00")

                # Footer controls
                draw.rectangle([(0, real_h - 12*s), (real_w, real_h)], fill="#000000")
                draw.text((2*s, real_h - 11*s), "Pad:Move K2:Zoom+ OK:Zoom-", font=font_sm, fill="#666666")

                lcd.LCD_ShowImage(img, 0, 0)

            # === STATS VIEW ===
            elif view == "stats":
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.rectangle((0, 0, 127, 14), fill="#111")
                d.text((2, 2), "ADS-B STATS", font=font_sm, fill="#00CCFF")

                y = 20
                d.text((4, y), f"Aircraft: {len(active)}", font=font, fill="#00FF00")
                y += 15
                d.text((4, y), f"With position: {with_pos}", font=font_sm, fill="#ccc")
                y += 12
                d.text((4, y), f"Messages: {total_msg}", font=font_sm, fill="#ccc")
                y += 12
                d.text((4, y), f"Total seen: {len(aircraft)}", font=font_sm, fill="#888")
                y += 15

                if _webui_running:
                    d.text((4, y), f"WebUI: port {WEBUI_PORT}", font=font_sm, fill="#00CCFF")
                    y += 12

                if active:
                    highest = max(active, key=lambda a: a["alt"])
                    fastest = max(active, key=lambda a: a["speed"])
                    d.text((4, y), f"Highest: {highest['alt']}ft", font=font_sm, fill="#FFAA00")
                    y += 11
                    d.text((4, y), f"Fastest: {fastest['speed']}kt", font=font_sm, fill="#FFAA00")

                d.rectangle((0, 116, 127, 127), fill="#111")
                d.text((2, 117), "OK:Track K1:View K2:Web", font=font_sm, fill="#666")
                lcd.LCD_ShowImage(img, 0, 0)

            time.sleep(0.05)

    finally:
        _shutdown.set()
        if _webui_server:
            _webui_server.shutdown()
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
