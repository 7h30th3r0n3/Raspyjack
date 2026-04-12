"""Lightweight device type classifier using MAC OUI vendor strings and open ports.

Zero external dependencies for base classification — pure Python dict lookups.
Designed for Pi Zero W2: classification takes <1ms per host.

Optional AI-enhanced classification via GPT-5 Nano for low-confidence devices.
"""


# ---------------------------------------------------------------------------
# Vendor keyword → device_type  (lowercase substring match against vendor)
# ---------------------------------------------------------------------------
_VENDOR_RULES = {
    # Networking equipment — routers
    "router": [
        "cisco", "ubiquiti", "unifi", "mikrotik", "netgear", "tp-link",
        "tplink", "tp link", "linksys", "d-link", "dlink",
        "zyxel", "aruba", "ruckus", "meraki", "juniper", "fortinet",
        "sonicwall", "pfsense", "opnsense", "edgerouter", "synology router",
        "huawei technolog",  # Huawei networking gear
        # ASUS router-specific product lines (bare "asus" is too broad —
        # ASUSTek Computer appears on motherboards, PCs for desktops too)
        "asus rt-", "asus gt-", "asus rog rapture", "asus zenwifi",
        "asus lyra", "asus blue cave",
        # ISP-provided routers / cable gateways
        "sagemcom", "technicolor", "arris", "calix", "actiontec",
        "hitron", "sercomm", "arcadyan", "gemtek",
        # Small-business / travel / cellular routers
        "draytek", "peplink", "pepwave", "cradlepoint", "teltonika",
        "gl.inet", "gl-inet",
    ],
    # Access points (often same vendors but specific product lines)
    "access_point": [
        "ubiquiti networks", "aruba networks", "ruckus wireless",
        "engenius", "cambium", "mist systems",
    ],
    # WiFi extenders / repeaters
    "extender": [
        "re200", "re300", "re450", "re505x", "re605x", "re650",
        "range extender", "wifi extender", "repeater",
        "tl-wa",  # TP-Link extender series
        "dap-",   # D-Link extender series
        "ex6", "ex7", "ex8",  # Netgear extenders
    ],
    # Network switches
    "switch": [
        "netgear switch", "cisco switch", "hp switch", "aruba switch",
        "unifi switch", "tl-sg", "tl-sf", "gs108", "gs305", "gs308",
        "prosafe",
    ],
    # Phones
    # NOTE: "apple" is intentionally NOT here — Apple, Inc. makes phones,
    # TVs, speakers, watches, laptops and tablets; the vendor string alone
    # cannot distinguish them.  Apple devices are classified via hostname
    # hints, port signatures, and AI fallback instead.
    "phone": [
        "samsung electro", "google pixel", "oneplus", "xiaomi commun",
        "huawei device", "oppo", "vivo", "realme", "motorola",
        "nokia", "sony mobile", "lg electronics", "honor",
        "nothing technology", "fairphone", "tecno", "infinix",
        "poco", "redmi",
    ],
    # Tablets
    "tablet": [
        "ipad", "samsung tab", "galaxy tab", "fire tablet",
        "kindle", "surface go", "surface pro",
    ],
    # Laptops (identified by specific product lines)
    "laptop": [
        "macbook", "thinkpad", "latitude", "elitebook", "probook",
        "pavilion", "inspiron", "xps", "zenbook", "vivobook",
        "ideapad", "yoga", "chromebook", "swift", "aspire",
        "surface laptop", "razer blade", "rog zephyrus", "tuf gaming",
        "predator",  # Acer gaming laptops
    ],
    # Printers
    "printer": [
        "hewlett packard", "hp inc", "canon", "brother", "epson",
        "lexmark", "xerox", "kyocera", "ricoh", "konica",
        "zebra technolog",  # Label / industrial printers
        "star micronics",   # Receipt printers
        "oki data",
    ],
    # Security cameras / IP cameras
    "camera": [
        "hikvision", "dahua", "axis communications", "reolink",
        "amcrest", "lorex", "arlo", "eufy", "wyze cam",
        "tp-link tapo", "tapo c", "unifi protect",
        "ring cam", "blink", "nest cam", "google nest cam",
        "vivotek", "hanwha", "bosch security",
        "foscam", "ezviz", "swann", "annke", "trendnet cam",
        "yi technology", "sricam",
    ],
    # Smart TVs / streaming sticks
    "smart_tv": [
        "samsung tv", "lg tv", "sony tv", "tcl", "hisense",
        "apple tv", "chromecast", "fire tv", "firestick",
        "nvidia shield", "roku", "vizio", "philips tv",
        "android tv", "webos", "tizen",
        "skyworth", "xiaomi tv", "mi tv", "lg webos",
    ],
    # Smart speakers / voice assistants
    "speaker": [
        "sonos", "amazon echo", "echo dot", "echo show",
        "google home", "google nest", "nest audio", "nest mini",
        "nest hub", "homepod", "apple homepod",
        "harman kardon", "jbl link", "bose home",
        "amazon technologies",  # Echo devices
    ],
    # Smart doorbells
    "doorbell": [
        "ring doorbell", "ring video", "nest doorbell",
        "nest hello", "eufy doorbell", "arlo doorbell",
        "remo+", "simplisafe doorbell",
    ],
    # Thermostats / climate
    "thermostat": [
        "nest thermostat", "ecobee", "honeywell home",
        "tado", "sensibo", "cielo", "mysa",
    ],
    # Smart home appliances (washers, fridges, ovens, vacuums)
    "appliance": [
        "bosch-wat", "bosch-wt", "bosch home", "samsung home",
        "lg thinq", "whirlpool", "miele", "electrolux",
        "irobot", "roomba", "roborock", "dyson", "ecovacs",
        "samsung fridge", "lg fridge",
    ],
    # Wearables / smartwatches
    "wearable": [
        "apple watch", "garmin", "fitbit", "whoop",
        "samsung galaxy watch", "oura", "amazfit",
    ],
    # IoT / embedded (generic)
    "iot": [
        "espressif", "tuya", "shelly", "sonoff", "tasmota",
        "philips lighting", "signify", "ikea of sweden",
        "ring", "wyze", "meross",
        "broadlink", "yeelight", "wemo", "smart",
        "aqara", "switchbot", "nanoleaf", "lifx", "govee",
        "tp-link kasa", "kasa", "teckin", "athom",
        "ewelink", "zemismart", "moes",
        "hubitat", "home assistant",  # Smart home hubs
    ],
    # NAS / network storage
    "nas": [
        "synology", "qnap", "asustor", "drobo", "buffalo",
        "terramaster", "wd my cloud", "western digital",
    ],
    # Servers
    "server": [
        "vmware", "supermicro", "dell emc", "hpe proliant",
        "proxmox", "truenas", "unraid", "nutanix",
    ],
    # Workstations / desktops
    "workstation": [
        "dell", "lenovo", "intel corporate", "hewlett", "acer",
        "msi", "gigabyte", "asrock", "asus",
        "microsoft", "surface",
        # Specific desktop product lines
        "optiplex", "thinkcentre", "elitedesk", "prodesk",
        "precision",  # Dell workstations
    ],
    # Raspberry Pi / SBCs
    "sbc": [
        "raspberry", "pi foundation", "orange pi", "banana pi",
        "beaglebone", "odroid", "rock pi", "libre computer",
        "pine64", "khadas", "radxa", "asus tinker",
    ],
    # Media / entertainment (audio/video equipment)
    "media": [
        "bose", "harman", "bang & olufsen",
        "denon", "marantz", "yamaha",
        "onkyo", "pioneer", "bluesound", "kef",
        "cambridge audio", "naim audio",
    ],
    # Game consoles / VR headsets
    "gaming": [
        "nintendo", "sony interactive", "playstation",
        "microsoft xbox", "valve", "steam deck",
        "meta platforms", "oculus",  # Meta Quest VR
    ],
    # Connected vehicles / EV chargers
    "vehicle": [
        "tesla", "wallbox", "chargepoint", "easee",
        "zaptec", "evbox", "juice technology",
        "bmw connected", "mercedes me",
        "myenergi", "pod point", "ohme", "andersen",
    ],
}

# Flatten: build list of (substring, device_type) sorted longest-first
# so more specific matches win (e.g. "ubiquiti networks" before "ubiquiti")
_VENDOR_LOOKUP = []
for _dtype, _keywords in _VENDOR_RULES.items():
    for _kw in _keywords:
        _VENDOR_LOOKUP.append((_kw, _dtype))
_VENDOR_LOOKUP.sort(key=lambda x: -len(x[0]))


# ---------------------------------------------------------------------------
# Port-based classification rules (applied when vendor is inconclusive)
# ---------------------------------------------------------------------------
def _classify_by_ports(ports):
    """Classify device type from a set of open port numbers."""
    if not ports:
        return None

    port_set = set()
    for p in ports:
        try:
            port_set.add(int(str(p).split("/")[0]))
        except (ValueError, IndexError):
            continue

    # Printer protocols (very specific, check first)
    if 9100 in port_set or 631 in port_set or 515 in port_set:
        return "printer"
    # RTSP → IP camera
    if 554 in port_set or 8554 in port_set:
        return "camera"
    # ONVIF → IP camera
    if 8899 in port_set or 37777 in port_set:
        return "camera"
    # Chromecast / smart TV casting
    if 8008 in port_set and 8009 in port_set:
        return "smart_tv"
    # AirPlay → Apple TV / HomePod (port 7000 = AirPlay, 3689 = DAAP)
    if 7000 in port_set and 5353 in port_set:
        return "smart_tv"
    # Apple TV often exposes AirPlay alone on port 7000
    if 7000 in port_set and 3689 in port_set:
        return "smart_tv"
    # Sonos / smart speaker (UPnP + HTTP)
    if 1400 in port_set:
        return "speaker"
    # NAS protocols (AFP + SMB or NFS)
    if 548 in port_set or (2049 in port_set and 445 in port_set):
        return "nas"
    # SMB + SSH + Synology/QNAP web port → NAS
    if 445 in port_set and 22 in port_set and 5000 in port_set:
        return "nas"
    # DHCP server → router (only if also serving DNS — real routers do both)
    if 67 in port_set and 53 in port_set:
        return "router"
    # Router: serves DNS + HTTP (typical home router)
    # BUT only if there are few ports — SBCs/servers running pi-hole also have 53+80
    if 53 in port_set and (80 in port_set or 443 in port_set) and len(port_set) <= 4:
        return "router"
    # RDP → Windows workstation
    if 3389 in port_set:
        return "workstation"
    # SMB/CIFS without SSH → workstation
    if 445 in port_set and 22 not in port_set:
        return "workstation"
    # MQTT → IoT hub
    if 1883 in port_set or 8883 in port_set:
        return "iot"
    # Media streaming ports
    if 8009 in port_set or 5353 in port_set:
        return "media"
    # SSH + HTTP but nothing else → server
    if 22 in port_set and (80 in port_set or 443 in port_set) and len(port_set) <= 4:
        return "server"
    # Many open ports → likely a server
    if len(port_set) >= 6:
        return "server"

    return None


# ---------------------------------------------------------------------------
# SVG icon paths per device type (simple, lightweight)
# ---------------------------------------------------------------------------
DEVICE_ICONS = {
    # Networking
    "router":       "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z",
    "access_point": "M12 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0-4C8.69 2 5.78 3.56 3.93 6l1.41 1.41C6.89 5.56 9.3 4.5 12 4.5s5.11 1.06 6.66 2.91L20.07 6C18.22 3.56 15.31 2 12 2zm0 4c-2.21 0-4.21.9-5.66 2.34l1.41 1.41C8.86 8.64 10.35 8 12 8s3.14.64 4.24 1.76l1.41-1.41C16.21 6.9 14.21 6 12 6zm0 10c.55 0 1 .45 1 1v3h-2v-3c0-.55.45-1 1-1z",
    "extender":     "M12 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zM2 8l1.41 1.41C5.77 7.05 8.73 6 12 6s6.23 1.05 8.59 3.41L22 8c-2.73-2.73-6.5-4.42-10-4.42S4.73 5.27 2 8zm4 4l1.41 1.41C9.14 11.68 10.5 11 12 11s2.86.68 4.59 2.41L18 12c-1.53-1.53-3.63-2.48-6-2.48S7.53 10.47 6 12zm3 3l3 3 3-3c-1.65-1.65-4.34-1.65-6 0z",
    "switch":       "M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zM7 9c.55 0 1 .45 1 1s-.45 1-1 1-1-.45-1-1 .45-1 1-1zm-3 4h2v2H4v-2zm4 2H6v-2h2v2zm2 0H8v-2h2v2zm2 0h-2v-2h2v2zm2 0h-2v-2h2v2zm2 0h-2v-2h2v2zm2 0h-2v-2h2v2zm2-6c0 .55-.45 1-1 1s-1-.45-1-1 .45-1 1-1 1 .45 1 1z",
    # Endpoints
    "phone":        "M16 1H8C6.34 1 5 2.34 5 4v16c0 1.66 1.34 3 3 3h8c1.66 0 3-1.34 3-3V4c0-1.66-1.34-3-3-3zm-2 20h-4v-1h4v1zm3.25-3H6.75V4h10.5v14z",
    "tablet":       "M18.5 0h-14C3.12 0 2 1.12 2 2.5v19C2 22.88 3.12 24 4.5 24h14c1.38 0 2.5-1.12 2.5-2.5v-19C21 1.12 19.88 0 18.5 0zm-7 23c-.83 0-1.5-.67-1.5-1.5s.67-1.5 1.5-1.5 1.5.67 1.5 1.5-.67 1.5-1.5 1.5zm8-4H4V3h15.5v16z",
    "laptop":       "M20 18c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2H4c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2H0v2h24v-2h-4zM4 6h16v10H4V6z",
    "workstation":  "M21 2H3c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h7l-2 3v1h8v-1l-2-3h7c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 12H3V4h18v10z",
    "wearable":     "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67V7z",
    # Printers / peripherals
    "printer":      "M19 8H5c-1.66 0-3 1.34-3 3v6h4v4h12v-4h4v-6c0-1.66-1.34-3-3-3zm-3 11H8v-5h8v5zm3-7c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1zm-1-9H6v4h12V3z",
    # Smart home
    "camera":       "M17 10.5V7c0-.55-.45-1-1-1H2c-.55 0-1 .45-1 1v10c0 .55.45 1 1 1h14c.55 0 1-.45 1-1v-3.5l4 4v-11l-4 4zM14 13h-3v3H9v-3H6v-2h3V8h2v3h3v2z",
    "smart_tv":     "M21 3H3c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h5v2h8v-2h5c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 14H3V5h18v14z",
    "speaker":      "M12 3c-4.97 0-9 4.03-9 9v7c0 1.1.9 2 2 2h4v-8H5v-1c0-3.87 3.13-7 7-7s7 3.13 7 7v1h-4v8h4c1.1 0 2-.9 2-2v-7c0-4.97-4.03-9-9-9z",
    "doorbell":     "M12 2C8.13 2 5 5.13 5 9c0 2.38 1.19 4.47 3 5.74V17c0 .55.45 1 1 1h6c.55 0 1-.45 1-1v-2.26c1.81-1.27 3-3.36 3-5.74 0-3.87-3.13-7-7-7zm0 2c2.76 0 5 2.24 5 5s-2.24 5-5 5-5-2.24-5-5 2.24-5 5-5zm-1.5 5a1.5 1.5 0 110-3 1.5 1.5 0 010 3zm3 0a1.5 1.5 0 110-3 1.5 1.5 0 010 3zM8 19h8v1c0 1.1-.9 2-2 2h-4c-1.1 0-2-.9-2-2v-1z",
    "thermostat":   "M15 13V5c0-1.66-1.34-3-3-3S9 3.34 9 5v8c-1.21.91-2 2.37-2 4 0 2.76 2.24 5 5 5s5-2.24 5-5c0-1.63-.79-3.09-2-4zm-4-8c0-.55.45-1 1-1s1 .45 1 1h-1v1h1v2h-1v1h1v2h-2V5z",
    "appliance":    "M18 2.01L6 2c-1.1 0-2 .89-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V4c0-1.11-.9-1.99-2-1.99zM18 20H6v-9.02h12V20zm0-11H6V4h12v5zM8 5h2v3H8z",
    # Servers / storage
    "nas":          "M2 17h20v2H2v-2zm1.15-4.05L4 11.47l.85 1.48 1.3-.75-.85-1.48H7v-1.5H5.3l.85-1.49-1.3-.75L4 8.96l-.85-1.48-1.3.75.85 1.49H1v1.5h1.7l-.85 1.48 1.3.75zM20 17h2v2h-2v-2zm-6-9.99h10V9h-10V7.01zM4 15v-0.01h16V15H4zM14 5h10v2.01H14V5zm0 4h10v2.01H14V9z",
    "server":       "M20 13H4c-.55 0-1 .45-1 1v6c0 .55.45 1 1 1h16c.55 0 1-.45 1-1v-6c0-.55-.45-1-1-1zM7 19c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zM20 3H4c-.55 0-1 .45-1 1v6c0 .55.45 1 1 1h16c.55 0 1-.45 1-1V4c0-.55-.45-1-1-1zM7 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z",
    "sbc":          "M22 9V7h-2V5c0-1.1-.9-2-2-2H4c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2v-2h2v-2h-2v-2h2v-2h-2V9h2zm-4 10H4V5h14v14zM6 13h5v4H6v-4zm6-6h4v3h-4V7zM6 7h5v5H6V7zm6 4h4v6h-4v-6z",
    # Entertainment
    "media":        "M21 3H3c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h18c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 16H3V5h18v14zM10 8v8l6-4z",
    "gaming":       "M21 6H3c-1.1 0-2 .9-2 2v8c0 1.1.9 2 2 2h18c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2zm-10 7H8v3H6v-3H3v-2h3V8h2v3h3v2zm4.5 2c-.83 0-1.5-.67-1.5-1.5s.67-1.5 1.5-1.5 1.5.67 1.5 1.5-.67 1.5-1.5 1.5zm4-3c-.83 0-1.5-.67-1.5-1.5S18.67 9 19.5 9s1.5.67 1.5 1.5-.67 1.5-1.5 1.5z",
    # IoT
    "iot":          "M7.5 5.6L10 7 8.6 4.5 10 2 7.5 3.4 5 2l1.4 2.5L5 7zm12 9.8L17 14l1.4 2.5L17 19l2.5-1.4L22 19l-1.4-2.5L22 14zM22 2l-2.5 1.4L17 2l1.4 2.5L17 7l2.5-1.4L22 7l-1.4-2.5zm-7.63 5.29a1 1 0 00-1.41 0L1.29 18.96a1 1 0 000 1.41l2.34 2.34a1 1 0 001.41 0L16.71 11.04a1 1 0 000-1.41l-2.34-2.34z",
    # Vehicle / EV
    "vehicle":      "M18.92 6.01C18.72 5.42 18.16 5 17.5 5h-11c-.66 0-1.21.42-1.42 1.01L3 12v8c0 .55.45 1 1 1h1c.55 0 1-.45 1-1v-1h12v1c0 .55.45 1 1 1h1c.55 0 1-.45 1-1v-8l-2.08-5.99zM6.5 16c-.83 0-1.5-.67-1.5-1.5S5.67 13 6.5 13s1.5.67 1.5 1.5S7.33 16 6.5 16zm11 0c-.83 0-1.5-.67-1.5-1.5s.67-1.5 1.5-1.5 1.5.67 1.5 1.5-.67 1.5-1.5 1.5zM5 11l1.5-4.5h11L19 11H5z",
    # Ragnar
    "ragnar":       "M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z",
    # Apple (generic — when specific product can't be determined)
    "apple":        "M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.81-1.31.05-2.31-1.32-3.15-2.55C4.22 16 2.97 12.11 4.71 9.5c.87-1.3 2.41-2.13 4.08-2.15 1.29-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.8-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83l.04.03zM13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z",
    # Unknown
    "unknown":      "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 17h-2v-2h2v2zm2.07-7.75l-.9.92C13.45 12.9 13 13.5 13 15h-2v-.5c0-1.1.45-2.1 1.17-2.83l1.24-1.26c.37-.36.59-.86.59-1.41 0-1.1-.9-2-2-2s-2 .9-2 2H8c0-2.21 1.79-4 4-4s4 1.79 4 4c0 .88-.36 1.68-.93 2.25z",
}

# Display labels for UI
DEVICE_TYPE_LABELS = {
    "router": "Router/Gateway",
    "access_point": "Access Point",
    "extender": "WiFi Extender",
    "switch": "Network Switch",
    "phone": "Phone",
    "tablet": "Tablet",
    "laptop": "Laptop",
    "workstation": "Desktop/Workstation",
    "wearable": "Wearable",
    "printer": "Printer",
    "camera": "IP Camera",
    "smart_tv": "Smart TV",
    "speaker": "Smart Speaker",
    "doorbell": "Smart Doorbell",
    "thermostat": "Thermostat",
    "appliance": "Smart Appliance",
    "iot": "IoT Device",
    "nas": "NAS Storage",
    "server": "Server",
    "sbc": "Single Board Computer",
    "media": "Media Device",
    "gaming": "Game Console",
    "vehicle": "Vehicle/EV Charger",
    "ragnar": "Ragnar",
    "apple": "Apple",
    "unknown": "Unknown",
}

# Colors per device type (for map legend)
DEVICE_TYPE_COLORS = {
    "router": "#f59e0b",       # amber
    "access_point": "#8b5cf6", # purple
    "extender": "#a78bfa",    # light violet
    "switch": "#7c3aed",      # deep violet
    "phone": "#3b82f6",        # blue
    "tablet": "#60a5fa",      # light blue
    "laptop": "#2563eb",      # dark blue
    "workstation": "#06b6d4",  # cyan
    "wearable": "#818cf8",    # indigo
    "printer": "#6b7280",      # gray
    "camera": "#dc2626",       # bright red
    "smart_tv": "#f97316",    # orange
    "speaker": "#14b8a6",     # teal
    "doorbell": "#eab308",    # yellow
    "thermostat": "#22d3ee",  # light cyan
    "appliance": "#84cc16",   # lime
    "iot": "#10b981",          # emerald
    "nas": "#b91c1c",          # dark red
    "server": "#ef4444",       # red
    "sbc": "#16a34a",          # green
    "media": "#ec4899",        # pink
    "gaming": "#a855f7",       # violet
    "vehicle": "#0d9488",     # dark teal
    "ragnar": "#16a34a",       # green (Ragnar brand)
    "apple": "#a3a3a3",        # silver/gray (Apple brand)
    "unknown": "#64748b",      # slate
}


def classify_device(vendor, ports, gateway_ip=None, device_ip=None):
    """Classify a network device by its MAC vendor string and open ports.

    Args:
        vendor: MAC OUI vendor string (e.g. "TP-Link Technologies")
        ports: list of port strings or ints (e.g. ["22", "80", "443"])
        gateway_ip: the network's default gateway IP (if known)
        device_ip: this device's IP address

    Returns:
        dict with keys: device_type, label, confidence (0.0-1.0)
    """
    # Gateway always wins
    if gateway_ip and device_ip and device_ip == gateway_ip:
        return {
            "device_type": "router",
            "label": DEVICE_TYPE_LABELS["router"],
            "confidence": 1.0,
        }

    device_type = None
    confidence = 0.3  # base confidence for unknown

    # Pass 1: vendor keyword match
    if vendor:
        vendor_lower = vendor.lower()
        for keyword, dtype in _VENDOR_LOOKUP:
            if keyword in vendor_lower:
                device_type = dtype
                confidence = 0.8
                break

        # Apple, Inc. makes phones, TVs, speakers, watches, laptops, tablets —
        # the vendor string alone cannot distinguish them.  Set low confidence
        # so hostname / port / AI refinement takes over.
        if vendor_lower.startswith("apple") and device_type is None:
            device_type = "apple"
            confidence = 0.4  # low enough for AI / hostname to override

    # Pass 2: port-based classification (refine or override)
    port_type = _classify_by_ports(ports)
    if port_type:
        if device_type is None:
            device_type = port_type
            confidence = 0.6
        elif device_type == "workstation" and port_type == "server":
            device_type = "server"
            confidence = 0.7
        elif device_type == "sbc" and port_type == "router":
            # SBCs running pi-hole / DNS look like routers but aren't —
            # keep the SBC classification
            pass
        elif device_type == port_type:
            confidence = 0.9  # vendor + ports agree

    if device_type is None:
        device_type = "unknown"

    return {
        "device_type": device_type,
        "label": DEVICE_TYPE_LABELS.get(device_type, "Unknown"),
        "confidence": confidence,
    }


# ---------------------------------------------------------------------------
# All valid device types (for AI classifier validation)
# ---------------------------------------------------------------------------
VALID_DEVICE_TYPES = set(DEVICE_TYPE_LABELS.keys())


# ---------------------------------------------------------------------------
# AI-enhanced classification via GPT-5 Nano (optional)
# ---------------------------------------------------------------------------
def classify_device_ai(vendor, ports, hostname, mac, ai_service=None,
                       gateway_ip=None, device_ip=None):
    """Classify a device using rule-based logic first, then GPT-5 Nano if
    confidence is below threshold.

    Args:
        vendor: MAC OUI vendor string
        ports: list of port strings or ints
        hostname: device hostname (mDNS, DHCP, NetBIOS)
        mac: full MAC address
        ai_service: an AIService instance (or None to skip AI)
        gateway_ip: default gateway IP
        device_ip: this device IP

    Returns:
        dict with keys: device_type, label, confidence, ai_enhanced (bool)
    """
    # Step 1: rule-based classification
    result = classify_device(vendor, ports, gateway_ip=gateway_ip, device_ip=device_ip)
    result["ai_enhanced"] = False

    # Step 2: hostname-based refinement
    # Strong hostname hints override even high-confidence vendor matches because
    # hostnames are user-visible names that are very specific (e.g. "RE200" is
    # always a TP-Link extender even though TP-Link vendor → router).
    if hostname:
        hostname_lower = hostname.lower()
        # Priority hostname hints — these ALWAYS override (even at confidence 0.8+)
        # because the hostname is more specific than a broad vendor match.
        _STRONG_HOSTNAME_HINTS = {
            "re200": "extender", "re300": "extender", "re450": "extender",
            "re505x": "extender", "re605x": "extender", "re650": "extender",
            "range-ext": "extender", "repeater": "extender", "ty_wr": "extender",
            "raspberry": "sbc", "raspberrypi": "sbc", "pi-hole": "sbc",
            "nest-audio": "speaker", "nest-mini": "speaker", "nest-hub": "speaker",
            "google-home": "speaker", "homepod": "speaker",
            "bosch-wat": "appliance", "bosch-wt": "appliance",
            "appletv": "smart_tv", "edvinsappletv": "smart_tv",
            "apple-tv": "smart_tv",
            "homepod": "speaker", "apple-homepod": "speaker",
            "macbook": "laptop", "imac": "workstation", "mac-mini": "workstation",
            "mac-pro": "workstation", "mac-studio": "workstation",
            "iphone": "phone", "ipad": "tablet",
            "apple-watch": "wearable", "applewatch": "wearable",
            # ASUS router hostnames (product lines that are always routers)
            "rt-ax": "router", "rt-ac": "router", "rt-n": "router",
            "gt-ax": "router", "gt-ac": "router",
            "zenwifi": "router", "asus router": "router",
            # Ragnar devices
            "ragnar": "ragnar",
        }
        for hint, dtype in _STRONG_HOSTNAME_HINTS.items():
            if hint in hostname_lower:
                result["device_type"] = dtype
                result["label"] = DEVICE_TYPE_LABELS.get(dtype, "Unknown")
                result["confidence"] = 0.85  # hostname is strong signal
                return result  # short circuit — hostname is definitive

        # Weaker hostname hints — only fire when vendor was inconclusive
        if result["confidence"] < 0.8:
            _HOSTNAME_HINTS = {
                "cam": "camera", "ipcam": "camera", "dvr": "camera", "nvr": "camera",
                "tv": "smart_tv", "firetv": "smart_tv",
                "chromecast": "smart_tv", "roku": "smart_tv",
                "echo": "speaker", "sonos": "speaker",
                "doorbell": "doorbell",
                "thermostat": "thermostat", "ecobee": "thermostat", "tado": "thermostat",
                "iphone": "phone", "android": "phone", "galaxy": "phone", "pixel": "phone",
                "ipad": "tablet", "tab": "tablet", "kindle": "tablet",
                "macbook": "laptop", "thinkpad": "laptop", "laptop": "laptop",
                "imac": "workstation", "mac-mini": "workstation",
                "xbox": "gaming", "playstation": "gaming", "ps5": "gaming",
                "nintendo": "gaming",
                "printer": "printer", "epson": "printer", "brother": "printer",
                "roomba": "appliance", "roborock": "appliance",
                "tesla": "vehicle", "wallbox": "vehicle", "chargepoint": "vehicle",
            }
            for hint, dtype in _HOSTNAME_HINTS.items():
                if hint in hostname_lower:
                    result["device_type"] = dtype
                    result["label"] = DEVICE_TYPE_LABELS.get(dtype, "Unknown")
                    result["confidence"] = 0.75
                    break

    # Step 3: AI-enhanced classification if still low confidence
    AI_CONFIDENCE_THRESHOLD = 0.65
    if ai_service and result["confidence"] < AI_CONFIDENCE_THRESHOLD:
        try:
            ai_type = _ask_ai_classify(ai_service, vendor, ports, hostname, mac)
            if ai_type and ai_type in VALID_DEVICE_TYPES:
                result["device_type"] = ai_type
                result["label"] = DEVICE_TYPE_LABELS.get(ai_type, "Unknown")
                result["confidence"] = 0.7  # AI-assigned confidence
                result["ai_enhanced"] = True
        except Exception:
            pass  # fail silently — rule-based result is still valid

    return result


def _ask_ai_classify(ai_service, vendor, ports, hostname, mac):
    """Ask GPT-5 Nano to classify a single device. Returns a device_type string or None."""
    if not ai_service or not ai_service.ensure_ready():
        return None

    valid_types = ", ".join(sorted(VALID_DEVICE_TYPES - {"ragnar", "unknown"}))

    system = (
        "You are a network device classifier. Given device metadata, reply with ONLY "
        "the device_type string — one of: " + valid_types + ". "
        "Reply with just the single word. If uncertain, reply unknown."
    )

    user = (
        f"MAC vendor: {vendor or 'unknown'}\n"
        f"Hostname: {hostname or 'unknown'}\n"
        f"MAC: {mac or 'unknown'}\n"
        f"Open ports: {', '.join(str(p) for p in (ports or [])[:20]) or 'none'}\n"
        f"Classify this device."
    )

    # Use GPT-5 Nano for fast/cheap classification
    original_model = ai_service.model
    try:
        ai_service.model = "gpt-5-nano"
        answer = ai_service._ask(system, user)
    finally:
        ai_service.model = original_model

    if not answer:
        return None

    # Sanitise — model should return just the type string
    answer = answer.strip().lower().replace(" ", "_")
    # Remove any surrounding quotes or punctuation
    answer = answer.strip('"\'.,')
    return answer if answer in VALID_DEVICE_TYPES else None
