"""
TagTinker ESL — Pricer Electronic Shelf Label IR protocol driver.
Faithful port of TagTinker from EvilCardputer by 7h30th3r0n3.

Uses 1.25 MHz IR carrier via compiled C binary (ir_carrier) on GPIO 12.
Protocol based on Pricer ESL research by furrtek (PrecIR).
"""

import os
import subprocess
import time
import struct

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROTO_DM = 0x85
PROTO_SEG = 0x84
MAX_FRAME = 96
BC_LEN = 17
DATA_BYTES_PER_FRAME = 20
DATA_BITS_PER_FRAME = DATA_BYTES_PER_FRAME * 8

COMP_AUTO = 0
COMP_RAW = 1
COMP_RLE = 2

KIND_UNKNOWN = 0
KIND_DOTMATRIX = 1
KIND_SEGMENT = 2

COLOR_MONO = 0
COLOR_RED = 1
COLOR_YELLOW = 2

# Timing: base unit from Flipper 64MHz clock, converted to microseconds
_BASE_US = 1.0 / 64.0  # 1 tick = 15.625 ns ≈ 0.015625 us

PP4_BURST_US = int(2581 * _BASE_US + 0.5)
PP16_BURST_US = int(1344 * _BASE_US + 0.5)

PP4_GAPS_US = [
    int(3871 * _BASE_US + 0.5),
    int(15483 * _BASE_US + 0.5),
    int(7741 * _BASE_US + 0.5),
    int(11612 * _BASE_US + 0.5),
]

PP16_GAPS_US = [
    int(v * _BASE_US + 0.5) for v in [
        1728, 3264, 2240, 2752, 9408, 7872, 8896, 8384,
        5312, 3776, 4800, 4288, 5824, 7360, 6336, 6848,
    ]
]

MAX_TARGETS = 50
MAX_PRESETS = 16
TARGETS_PATH = "/root/Raspyjack/loot/ESL/targets.txt"
PRESETS_PATH = "/root/Raspyjack/loot/ESL/presets.txt"
LOOT_DIR = "/root/Raspyjack/loot/ESL"
IR_CARRIER_BIN = "/usr/local/bin/ir_carrier"

# ---------------------------------------------------------------------------
# Profile table — ALL 44 known Pricer tag models
# ---------------------------------------------------------------------------

PROFILE_TABLE = [
    (1206, 0, 0, KIND_SEGMENT, COLOR_MONO, "Continuum E2 HCS", 0),
    (1207, 0, 0, KIND_SEGMENT, COLOR_MONO, "Continuum E2 HCN", 4),
    (1217, 0, 0, KIND_SEGMENT, COLOR_MONO, "Continuum E5 HCS", 2),
    (1219, 0, 0, KIND_SEGMENT, COLOR_MONO, "Continuum E5 HCN", 1),
    (1240, 0, 0, KIND_SEGMENT, COLOR_MONO, "Continuum E4 HCS", 3),
    (1241, 0, 0, KIND_SEGMENT, COLOR_MONO, "Continuum E4 HCN", 0),
    (1242, 0, 0, KIND_SEGMENT, COLOR_MONO, "Continuum E4 HCN FZ", 0),
    (1243, 0, 0, KIND_SEGMENT, COLOR_MONO, "Continuum E4 HCW", 0),
    (1265, 0, 0, KIND_SEGMENT, COLOR_MONO, "Continuum E5 HCS", 2),
    (1275, 320, 192, KIND_DOTMATRIX, COLOR_MONO, "DM110", 0),
    (1276, 320, 140, KIND_DOTMATRIX, COLOR_MONO, "DM90", 0),
    (1291, 0, 0, KIND_SEGMENT, COLOR_MONO, "FVL Promoline 3-16", 0),
    (1300, 172, 72, KIND_DOTMATRIX, COLOR_MONO, "DM3370", 0),
    (1314, 400, 300, KIND_DOTMATRIX, COLOR_MONO, "SmartTag HD110", 0),
    (1315, 296, 128, KIND_DOTMATRIX, COLOR_MONO, "SmartTag HD L", 0),
    (1317, 152, 152, KIND_DOTMATRIX, COLOR_MONO, "SmartTag HD S", 0),
    (1318, 208, 112, KIND_DOTMATRIX, COLOR_MONO, "SmartTag HD M", 0),
    (1319, 800, 480, KIND_DOTMATRIX, COLOR_MONO, "SmartTag HD200", 0),
    (1322, 152, 152, KIND_DOTMATRIX, COLOR_MONO, "SmartTag HD S", 0),
    (1324, 208, 112, KIND_DOTMATRIX, COLOR_MONO, "SmartTag HD M FZ", 0),
    (1327, 208, 112, KIND_DOTMATRIX, COLOR_RED, "SmartTag HD M Red", 0),
    (1328, 296, 128, KIND_DOTMATRIX, COLOR_RED, "SmartTag HD L Red", 0),
    (1336, 400, 300, KIND_DOTMATRIX, COLOR_RED, "SmartTag HD110 Red", 0),
    (1339, 152, 152, KIND_DOTMATRIX, COLOR_RED, "SmartTag HD S Red", 0),
    (1340, 800, 480, KIND_DOTMATRIX, COLOR_RED, "SmartTag HD200 Red", 0),
    (1344, 296, 128, KIND_DOTMATRIX, COLOR_YELLOW, "SmartTag HD L Yellow", 0),
    (1346, 800, 480, KIND_DOTMATRIX, COLOR_YELLOW, "SmartTag HD200 Yellow", 0),
    (1348, 264, 176, KIND_DOTMATRIX, COLOR_RED, "SmartTag HD T Red", 0),
    (1349, 264, 176, KIND_DOTMATRIX, COLOR_YELLOW, "SmartTag HD T Yellow", 0),
    (1351, 648, 480, KIND_DOTMATRIX, COLOR_MONO, "SmartTag HD150", 0),
    (1353, 648, 480, KIND_DOTMATRIX, COLOR_RED, "SmartTag HD150 Red", 0),
    (1354, 648, 480, KIND_DOTMATRIX, COLOR_RED, "SmartTag HD150 Red", 0),
    (1370, 296, 128, KIND_DOTMATRIX, COLOR_RED, "SmartTag HD L Red (2021)", 0),
    (1371, 648, 480, KIND_DOTMATRIX, COLOR_RED, "SmartTag HD150 Red (2021)", 0),
    (1510, 0, 0, KIND_SEGMENT, COLOR_MONO, "SmartTag E5 M", 1),
    (1627, 296, 128, KIND_DOTMATRIX, COLOR_RED, "SmartTag HD L Red", 0),
    (1628, 296, 128, KIND_DOTMATRIX, COLOR_RED, "SmartTag HD L Red", 0),
    (1639, 152, 152, KIND_DOTMATRIX, COLOR_RED, "SmartTag HD S Red", 0),
    (3145, 400, 300, KIND_DOTMATRIX, COLOR_MONO, "SmartTag HD110", 0),
    (3220, 152, 152, KIND_DOTMATRIX, COLOR_MONO, "SmartTag HD S", 0),
    (3227, 152, 152, KIND_DOTMATRIX, COLOR_MONO, "SmartTag HD S", 0),
    (3229, 152, 152, KIND_DOTMATRIX, COLOR_MONO, "SmartTag HD S", 0),
    (3547, 648, 480, KIND_DOTMATRIX, COLOR_RED, "SmartTag HD150 Red", 0),
    (6275, 296, 128, KIND_DOTMATRIX, COLOR_MONO, "SmartTag HD L", 0),
]

# ---------------------------------------------------------------------------
# NFC URL decoder LUT (from TagTinker)
# ---------------------------------------------------------------------------

_NFC_LUT = [
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,35,-1,-1,
    28,24,30,38,58, 5,23, 6, 3,40,-1,-1,-1,-1,-1,-1,
    -1,20,15,54,16,44,46,63, 4,48,34,19,37, 0,26, 1,
     8,41,31, 2,45,55,60,12,11,57,33,-1,-1,-1,-1,50,
    -1,13,39, 9,43,18,29,52,59, 7,61,62,14,25,32,56,
    42,47,53,22,36,49,10,21,17,27,51,-1,-1,-1,-1,-1,
]

# ---------------------------------------------------------------------------
# CRC16
# ---------------------------------------------------------------------------

def crc16(data):
    crc = 0x8408
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if (crc & 1) else crc >> 1
    return crc & 0xFFFF


# ---------------------------------------------------------------------------
# Barcode parsing
# ---------------------------------------------------------------------------

def is_barcode_valid(barcode):
    if not barcode or len(barcode) != BC_LEN:
        return False
    for i in range(2, 17):
        if barcode[i] < '0' or barcode[i] > '9':
            return False
    return True


def barcode_to_plid(barcode):
    if not barcode or len(barcode) != BC_LEN:
        return None
    try:
        a = int(barcode[2:7])
        b = int(barcode[7:12])
    except ValueError:
        return None
    val = (a << 16) | b
    return bytes([val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF, (val >> 24) & 0xFF])


def barcode_to_type(barcode):
    if not barcode or len(barcode) != BC_LEN:
        return None
    try:
        return int(barcode[12:16])
    except ValueError:
        return None


def barcode_to_profile(barcode):
    tc = barcode_to_type(barcode)
    if tc is None:
        return None
    for entry in PROFILE_TABLE:
        if entry[0] == tc:
            return {
                "type_code": entry[0], "width": entry[1], "height": entry[2],
                "kind": entry[3], "color": entry[4], "model_name": entry[5],
                "pl_bit_def": entry[6], "known": True,
            }
    return {"type_code": tc, "width": 0, "height": 0, "kind": KIND_UNKNOWN,
            "color": COLOR_MONO, "model_name": None, "pl_bit_def": 0, "known": False}


# ---------------------------------------------------------------------------
# NFC URL decoder
# ---------------------------------------------------------------------------

def nfc_alpha_idx(c):
    v = ord(c) if isinstance(c, str) else c
    if v >= 128:
        return -1
    return _NFC_LUT[v]


def nfc_decode_b64(s, length):
    r = 0
    for i in range(length):
        idx = nfc_alpha_idx(s[(length - 1) - i])
        if idx < 0:
            return 0
        r = r * 64 + idx
    return r


def nfc_to_barcode(nfc10):
    if len(nfc10) != 10:
        return None
    for c in nfc10:
        if nfc_alpha_idx(c) < 0:
            return None
    val1 = nfc_decode_b64(nfc10[5:], 5)
    val2 = nfc_decode_b64(nfc10[:5], 5)
    raw = "%09d%09d" % (val1, val2)
    lc = int(raw[0]) * 10 + int(raw[1])
    if lc > 25:
        return None
    out = chr(lc + 65) + raw[2:]
    if out[1] != '4':
        return None
    cs = 0
    for i in range(16):
        c = out[i]
        cs += (ord(c) - 32) if ('a' <= c <= 'z') else ord(c)
    if (cs % 10) != int(out[16]):
        return None
    return out


# ---------------------------------------------------------------------------
# Frame building
# ---------------------------------------------------------------------------

def _terminate(buf):
    c = crc16(buf)
    return buf + bytes([c & 0xFF, (c >> 8) & 0xFF])


def _raw_frame(proto, plid, cmd):
    return bytes([proto]) + plid + bytes([cmd])


def _mcu_frame(plid, cmd):
    return _raw_frame(PROTO_DM, plid, 0x34) + bytes([0x00, 0x00, 0x00, cmd])


def make_broadcast_page_frame(page, forever=False, duration=10):
    plid = bytes(4)
    buf = _raw_frame(PROTO_DM, plid, 0x06)
    buf += bytes([(((page + 1) & 7) << 3) | 0x01 | (0x80 if forever else 0x00),
                  0x00, 0x00, (duration >> 8) & 0xFF, duration & 0xFF])
    return _terminate(buf)


def make_broadcast_debug_frame():
    plid = bytes(4)
    buf = _raw_frame(PROTO_DM, plid, 0x06)
    buf += bytes([0xF1, 0x00, 0x00, 0x00, 0x0A])
    return _terminate(buf)


def make_ping_frame(plid):
    buf = _raw_frame(PROTO_DM, plid, 0x97)
    buf += bytes([0x01, 0x00, 0x00, 0x00])
    buf += bytes([0x01] * 20)
    return _terminate(buf)


def make_refresh_frame(plid):
    buf = _mcu_frame(plid, 0x01)
    buf += bytes(18)
    return _terminate(buf)


def make_addressed_frame(plid, payload):
    buf = _raw_frame(PROTO_DM, plid, payload[0])
    buf += payload[1:]
    return _terminate(buf)


def make_image_param_frame(plid, byte_count, comp_type, page, width, height, pos_x=0, pos_y=0):
    buf = _mcu_frame(plid, 0x05)
    buf += struct.pack(">H", byte_count)
    buf += bytes([0x00, comp_type, page])
    buf += struct.pack(">HHHH", width, height, pos_x, pos_y)
    buf += struct.pack(">H", 0x0000)
    buf += bytes([0x88])
    buf += struct.pack(">H", 0x0000)
    buf += bytes(4)
    return _terminate(buf)


def make_image_data_frame(plid, frame_index, data_bytes):
    buf = _mcu_frame(plid, 0x20)
    buf += struct.pack(">H", frame_index)
    chunk = bytes(data_bytes[:DATA_BYTES_PER_FRAME])
    if len(chunk) < DATA_BYTES_PER_FRAME:
        chunk += bytes(DATA_BYTES_PER_FRAME - len(chunk))
    buf += chunk
    return _terminate(buf)


def make_led_frame(plid, mode, duration):
    payload = bytes([0x06, mode, 0x00, 0x00, (duration >> 8) & 0xFF, duration & 0xFF])
    return make_addressed_frame(plid, payload)


# ---------------------------------------------------------------------------
# RLE compression (bit-level, exact port from EvilCardputer)
# ---------------------------------------------------------------------------

class _BitWriter:
    def __init__(self):
        self.data = bytearray()
        self.bit_pos = 0

    def _ensure(self, n):
        needed = (self.bit_pos + n + 7) // 8
        while len(self.data) < needed:
            self.data.append(0)

    def append(self, bit):
        self._ensure(1)
        byte_idx = self.bit_pos // 8
        bit_idx = 7 - (self.bit_pos % 8)
        if bit:
            self.data[byte_idx] |= (1 << bit_idx)
        self.bit_pos += 1

    def append_run(self, run_count):
        bits = []
        v = run_count
        while v:
            bits.append(v & 1)
            v >>= 1
        bits.reverse()
        for i in range(1, len(bits)):
            self.append(0)
        for b in bits:
            self.append(b)

    @property
    def bit_length(self):
        return self.bit_pos

    def to_bytes(self):
        return bytes(self.data)


def rle_bit_length(pixels):
    if not pixels:
        return 0
    bl = 1
    run_pixel = pixels[0]
    run_count = 1
    for i in range(1, len(pixels)):
        if pixels[i] == run_pixel:
            run_count += 1
        else:
            v = run_count
            bc = 0
            while v:
                bc += 1
                v >>= 1
            bl += bc * 2 - 1
            run_pixel = pixels[i]
            run_count = 1
    if run_count > 1:
        v = run_count
        bc = 0
        while v:
            bc += 1
            v >>= 1
        bl += bc * 2 - 1
    return bl


def encode_planes(primary, secondary=None, comp_mode=COMP_AUTO):
    total = primary if secondary is None else primary + secondary
    total_bits = len(total)
    rle_bits = rle_bit_length(total)
    use_rle = False
    if comp_mode == COMP_RLE:
        use_rle = True
    elif comp_mode == COMP_AUTO:
        use_rle = 0 < rle_bits < total_bits

    src_bits = rle_bits if use_rle else total_bits
    padding = (DATA_BITS_PER_FRAME - (src_bits % DATA_BITS_PER_FRAME)) % DATA_BITS_PER_FRAME
    padded_bits = src_bits + padding

    w = _BitWriter()
    if use_rle:
        run_pixel = total[0]
        run_count = 1
        w.append(run_pixel)
        for i in range(1, len(total)):
            if total[i] == run_pixel:
                run_count += 1
            else:
                w.append_run(run_count)
                run_pixel = total[i]
                run_count = 1
        if run_count > 1:
            w.append_run(run_count)
    else:
        for px in total:
            w.append(px)

    data = w.to_bytes()
    padded_bytes = padded_bits // 8
    if len(data) < padded_bytes:
        data += bytes(padded_bytes - len(data))
    return data[:padded_bytes], (2 if use_rle else 0)


# ---------------------------------------------------------------------------
# Text rendering via PIL
# ---------------------------------------------------------------------------

def render_text(text, width, height, text_size=2, invert=True, off_x=0, off_y=0):
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        return None
    img = Image.new("1", (width, height), 0)
    draw = ImageDraw.Draw(img)
    try:
        fsize = max(8, text_size * 8)
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", fsize)
    except Exception:
        font = ImageFont.load_default()
    draw.text((off_x + 2, off_y + 2), text, fill=1, font=font)
    pixels = []
    for y in range(height):
        for x in range(width):
            px = img.getpixel((x, y))
            if invert:
                px = 0 if px else 1
            pixels.append(1 if px else 0)
    return pixels


# ---------------------------------------------------------------------------
# Image loading (BMP/PNG)
# ---------------------------------------------------------------------------

def load_image_1bpp(path, target_w, target_h):
    try:
        from PIL import Image
    except ImportError:
        return None
    try:
        img = Image.open(path).convert("L")
    except Exception:
        return None
    img = img.resize((target_w, target_h), Image.LANCZOS)
    pixels = []
    for y in range(target_h):
        for x in range(target_w):
            pixels.append(1 if img.getpixel((x, y)) < 128 else 0)
    return pixels


# ---------------------------------------------------------------------------
# Saved targets
# ---------------------------------------------------------------------------

def targets_load():
    targets = []
    try:
        with open(TARGETS_PATH, "r") as f:
            for line in f:
                line = line.strip()
                sep = line.find("|")
                if sep < BC_LEN:
                    continue
                bc = line[:BC_LEN]
                name = line[sep + 1:].strip() if sep + 1 < len(line) else ""
                targets.append({"barcode": bc, "name": name})
                if len(targets) >= MAX_TARGETS:
                    break
    except Exception:
        pass
    return targets


def targets_save(targets):
    os.makedirs(os.path.dirname(TARGETS_PATH), exist_ok=True)
    try:
        with open(TARGETS_PATH, "w") as f:
            for t in targets:
                f.write("%s|%s\n" % (t["barcode"], t["name"]))
    except Exception:
        pass


def target_add(barcode, name=""):
    targets = targets_load()
    for t in targets:
        if t["barcode"] == barcode:
            t["name"] = name
            targets_save(targets)
            return True
    if len(targets) >= MAX_TARGETS:
        return False
    targets.append({"barcode": barcode, "name": name})
    targets_save(targets)
    return True


def target_delete(idx):
    targets = targets_load()
    if 0 <= idx < len(targets):
        targets.pop(idx)
        targets_save(targets)


# ---------------------------------------------------------------------------
# Text presets
# ---------------------------------------------------------------------------

def presets_load():
    presets = []
    try:
        with open(PRESETS_PATH, "r") as f:
            for line in f:
                line = line.strip()
                sep = line.find("|")
                if sep < 1:
                    continue
                presets.append({"name": line[:sep], "text": line[sep + 1:]})
                if len(presets) >= MAX_PRESETS:
                    break
    except Exception:
        pass
    return presets


def presets_save(presets):
    os.makedirs(os.path.dirname(PRESETS_PATH), exist_ok=True)
    try:
        with open(PRESETS_PATH, "w") as f:
            for p in presets:
                f.write("%s|%s\n" % (p["name"], p["text"]))
    except Exception:
        pass


def preset_add(name, text):
    presets = presets_load()
    if len(presets) >= MAX_PRESETS:
        return False
    presets.append({"name": name, "text": text})
    presets_save(presets)
    return True


def preset_delete(idx):
    presets = presets_load()
    if 0 <= idx < len(presets):
        presets.pop(idx)
        presets_save(presets)


# ---------------------------------------------------------------------------
# LED Explorer test table
# ---------------------------------------------------------------------------

LED_TESTS = [
    (0x49, 0x00, 0x00, 0x00, 0x05, "Fast blink 5s"),
    (0x41, 0x00, 0x00, 0x00, 0x05, "Slow blink 5s"),
    (0xC9, 0x00, 0x00, 0x00, 0x05, "Fast HIGH 5s"),
    (0xC1, 0x00, 0x00, 0x00, 0x05, "Slow HIGH 5s"),
    (0xC9, 0x00, 0x00, 0x00, 0x00, "Fast FOREVER"),
    (0xC1, 0x00, 0x00, 0x00, 0x00, "Slow FOREVER"),
    (0x49, 0x00, 0x00, 0x00, 0x01, "LED OFF (1s)"),
    (0xF1, 0x00, 0x00, 0x00, 0x0A, "Debug 0xF1"),
]


# ---------------------------------------------------------------------------
# TagTinker class — IR transmission via ir_carrier binary
# ---------------------------------------------------------------------------

class TagTinker:
    def __init__(self):
        self.use_pp16 = True
        self.data_repeats = 3
        self.wake_repeats = 250
        self.comp_mode = COMP_AUTO
        self.page = 1
        self.store_key = 0x0000
        self.text_size = 2
        self.invert = True
        self.last_barcode = ""
        self._stop_requested = False

    def open(self):
        return os.path.exists(IR_CARRIER_BIN)

    def close(self):
        pass

    def stop(self):
        self._stop_requested = True

    # -- Low-level IR --

    def _encode_frame_pp4(self, data):
        bg = []
        for byte in data:
            current = byte
            for _ in range(4):
                symbol = current & 0x03
                current >>= 2
                bg.append(PP4_BURST_US)
                bg.append(PP4_GAPS_US[symbol])
        bg.append(PP4_BURST_US)
        bg.append(1000)
        return bg

    def _encode_frame_pp16(self, data):
        bg = []
        for byte in data:
            current = byte
            for _ in range(2):
                symbol = current & 0x0F
                current >>= 4
                bg.append(PP16_BURST_US)
                bg.append(PP16_GAPS_US[symbol])
        bg.append(PP16_BURST_US)
        bg.append(1000)
        return bg

    def transmit(self, data, repeats=1, gap_delay=2, pp16=None, progress_cb=None):
        if pp16 is None:
            pp16 = self.use_pp16
        if not data:
            return False
        self._stop_requested = False

        if pp16:
            tx_data = bytes([0x00, 0x00, 0x00, 0x40]) + bytes(data)
            bg = self._encode_frame_pp16(tx_data)
        else:
            tx_data = bytes(data)
            bg = self._encode_frame_pp4(tx_data)

        gap_us = int(gap_delay * 500)
        pairs_str = " ".join(str(int(v)) for v in bg)
        proc = subprocess.run(
            [IR_CARRIER_BIN, "--stdin", str(repeats), str(gap_us)],
            input=pairs_str, capture_output=True, text=True, timeout=60,
        )
        if progress_cb:
            progress_cb(repeats, repeats)
        return proc.returncode == 0

    # -- High-level commands --

    def wake(self, barcode, repeats=None):
        plid = barcode_to_plid(barcode)
        if not plid:
            return False
        frame = make_ping_frame(plid)
        if repeats is None:
            repeats = self.wake_repeats
        return self.transmit(frame, repeats=repeats)

    def ping(self, barcode):
        plid = barcode_to_plid(barcode)
        if not plid:
            return False
        frame = make_ping_frame(plid)
        return self.transmit(frame, repeats=self.wake_repeats)

    def refresh(self, barcode):
        plid = barcode_to_plid(barcode)
        if not plid:
            return False
        self.wake(barcode, repeats=80)
        frame = make_refresh_frame(plid)
        return self.transmit(frame, repeats=20)

    def led_on(self, barcode, mode=0xC9, duration=5):
        plid = barcode_to_plid(barcode)
        if not plid:
            return False
        ping_frame = make_ping_frame(plid)
        self.transmit(ping_frame, repeats=160)
        led_frame = make_led_frame(plid, mode, duration)
        return self.transmit(led_frame, repeats=80)

    def led_off(self, barcode):
        return self.led_on(barcode, mode=0x49, duration=1)

    def broadcast_page(self, page, duration=10, forever=False, repeats=100):
        frame = make_broadcast_page_frame(page, forever, duration)
        return self.transmit(frame, repeats=repeats)

    def broadcast_debug(self, repeats=500):
        frame = make_broadcast_debug_frame()
        return self.transmit(frame, repeats=repeats)

    def send_image(self, barcode, pixels, width, height, page=None,
                   color_clear=False, progress_cb=None):
        plid = barcode_to_plid(barcode)
        if not plid:
            return False
        if page is None:
            page = self.page

        secondary = None
        if color_clear:
            secondary = [1] * len(pixels)

        data, comp_type = encode_planes(pixels, secondary, self.comp_mode)
        frame_count = len(data) // DATA_BYTES_PER_FRAME
        total = 2 + frame_count + 1

        # 1: Wake (ping)
        if progress_cb:
            progress_cb(0, total, "Waking tag...")
        ping = make_ping_frame(plid)
        self.transmit(ping, repeats=self.wake_repeats, pp16=self.use_pp16)

        # 2: Image parameters
        if progress_cb:
            progress_cb(1, total, "Image params...")
        param = make_image_param_frame(plid, len(data), comp_type, page, width, height)
        self.transmit(param, repeats=15, gap_delay=1, pp16=self.use_pp16)
        time.sleep(0.05)

        # 3: Data frames
        for fi in range(frame_count):
            if self._stop_requested:
                return False
            if progress_cb:
                progress_cb(2 + fi, total, "Frame %d/%d" % (fi + 1, frame_count))
            chunk = data[fi * DATA_BYTES_PER_FRAME:(fi + 1) * DATA_BYTES_PER_FRAME]
            df = make_image_data_frame(plid, fi, chunk)
            self.transmit(df, repeats=self.data_repeats, gap_delay=1, pp16=self.use_pp16)

        # 4: Refresh
        if progress_cb:
            progress_cb(total - 1, total, "Refreshing...")
        ref = make_refresh_frame(plid)
        self.transmit(ref, repeats=20, pp16=self.use_pp16)
        return True

    def push_text(self, barcode, text, page=None, text_size=None, invert=None):
        if page is None:
            page = self.page
        if text_size is None:
            text_size = self.text_size
        if invert is None:
            invert = self.invert

        profile = barcode_to_profile(barcode)
        if not profile:
            return False
        w = profile["width"] if profile["known"] else 296
        h = profile["height"] if profile["known"] else 128
        if w == 0 or h == 0:
            return False

        pixels = render_text(text, w, h, text_size, invert)
        if not pixels:
            return False

        color_clear = profile["known"] and profile["color"] != COLOR_MONO
        return self.send_image(barcode, pixels, w, h, page, color_clear)
