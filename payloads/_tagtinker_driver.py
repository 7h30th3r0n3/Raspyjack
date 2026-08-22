"""
TagTinker ESL (Electronic Shelf Label) IR protocol driver.

Faithfully ported from EvilCardputer (7h30th3r0n3) Arduino implementation.
Based on Pricer ESL protocol research by furrtek (PrecIR).

Uses 1.25 MHz IR carrier via hardware PWM on GPIO 12 of CardputerZero.
PP4 and PP16 pulse-position modulation for data encoding.

Usage:
    from payloads._tagtinker_driver import TagTinker, barcode_to_profile

    tt = TagTinker()
    tt.open()
    tt.wake(barcode)
    tt.push_text(barcode, "Hello")
    tt.close()
"""

import os
import time
import subprocess
import struct

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROTO_DM = 0x85
PROTO_SEG = 0x84
MAX_FRAME_SIZE = 96
BC_LEN = 17
DATA_BYTES_PER_FRAME = 20
DATA_BITS_PER_FRAME = DATA_BYTES_PER_FRAME * 8

KIND_UNKNOWN = 0
KIND_DOTMATRIX = 1
KIND_SEGMENT = 2

COLOR_MONO = 0
COLOR_RED = 1
COLOR_YELLOW = 2

COMP_AUTO = 0
COMP_RAW = 1
COMP_RLE = 2

# PP4/PP16 timing — base values from Flipper (64 MHz reference).
# On RPi we use nanoseconds directly (no CPU-cycle scaling needed).
# Base timing in CPU cycles at 64 MHz. Convert to nanoseconds: cycles / 64 * 1000
_BASE_TO_NS = 1000.0 / 64.0

PP4_BURST_NS = int(2581 * _BASE_TO_NS)
PP16_BURST_NS = int(1344 * _BASE_TO_NS)

PP4_GAPS_NS = [
    int(3871 * _BASE_TO_NS),
    int(15483 * _BASE_TO_NS),
    int(7741 * _BASE_TO_NS),
    int(11612 * _BASE_TO_NS),
]

PP16_GAPS_NS = [
    int(1728 * _BASE_TO_NS), int(3264 * _BASE_TO_NS),
    int(2240 * _BASE_TO_NS), int(2752 * _BASE_TO_NS),
    int(9408 * _BASE_TO_NS), int(7872 * _BASE_TO_NS),
    int(8896 * _BASE_TO_NS), int(8384 * _BASE_TO_NS),
    int(5312 * _BASE_TO_NS), int(3776 * _BASE_TO_NS),
    int(4800 * _BASE_TO_NS), int(4288 * _BASE_TO_NS),
    int(5824 * _BASE_TO_NS), int(7360 * _BASE_TO_NS),
    int(6336 * _BASE_TO_NS), int(6848 * _BASE_TO_NS),
]

# PWM paths
PWM_CHIP = "/sys/class/pwm/pwmchip0"
PWM_CHAN = os.path.join(PWM_CHIP, "pwm0")
PWM_PERIOD = 800       # 1.25 MHz = 800 ns period
PWM_DUTY = 400         # 50% duty cycle
IR_GPIO = 12

# Loot directory
LOOT_DIR = "/root/Raspyjack/loot/ESL"
TARGETS_FILE = os.path.join(LOOT_DIR, "targets.txt")
PRESETS_FILE = os.path.join(LOOT_DIR, "presets.txt")


# ---------------------------------------------------------------------------
# Profile table — every known Pricer ESL tag model
# (type_code, width, height, kind, color, model_name, pl_bit_def)
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
    (3547, 648, 480, KIND_DOTMATRIX, COLOR_RED, "SmartTag HD150 Red", 0),
    (6275, 296, 128, KIND_DOTMATRIX, COLOR_MONO, "SmartTag HD L", 0),
    (3220, 152, 152, KIND_DOTMATRIX, COLOR_MONO, "SmartTag HD S", 0),
    (3227, 152, 152, KIND_DOTMATRIX, COLOR_MONO, "SmartTag HD S", 0),
    (3229, 152, 152, KIND_DOTMATRIX, COLOR_MONO, "SmartTag HD S", 0),
]

# NFC URL decoder lookup table
NFC_LUT = [
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
# CRC16 — exact polynomial 0x8408 (matching EvilCardputer)
# ---------------------------------------------------------------------------

def crc16(data):
    crc = 0x8408
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if (crc & 1) else crc >> 1
    return crc & 0xFFFF


# ---------------------------------------------------------------------------
# Barcode helpers
# ---------------------------------------------------------------------------

def is_barcode_valid(barcode):
    if not barcode or len(barcode) != BC_LEN:
        return False
    return all(c.isdigit() for c in barcode[2:])


def barcode_to_plid(barcode):
    if not barcode or len(barcode) != BC_LEN:
        return None
    a = 0
    for c in barcode[2:7]:
        a = a * 10 + (ord(c) - 0x30)
    b = 0
    for c in barcode[7:12]:
        b = b * 10 + (ord(c) - 0x30)
    ident = (a << 16) | b
    return bytes([ident & 0xFF, (ident >> 8) & 0xFF,
                  (ident >> 16) & 0xFF, (ident >> 24) & 0xFF])


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
                "kind": entry[3], "color": entry[4],
                "model_name": entry[5], "pl_bit_def": entry[6], "known": True,
            }
    return {"type_code": tc, "width": 0, "height": 0, "kind": KIND_UNKNOWN,
            "color": COLOR_MONO, "model_name": None, "pl_bit_def": 0, "known": False}


def nfc_to_barcode(nfc10):
    if len(nfc10) != 10:
        return None
    for c in nfc10:
        if ord(c) >= 128 or NFC_LUT[ord(c)] < 0:
            return None

    def decode_b64(s, length):
        r = 0
        for i in range(length):
            idx = NFC_LUT[ord(s[(length - 1) - i])]
            if idx < 0:
                return 0
            r = r * 64 + idx
        return r

    val1 = decode_b64(nfc10[5:], 5)
    val2 = decode_b64(nfc10[:5], 5)
    raw = "%09d%09d" % (val1, val2)
    lc = int(raw[0:2])
    if lc > 25:
        return None
    out = chr(lc + 65) + raw[2:]
    if out[1] != '4':
        return None
    cs = sum(ord(c.upper()) if c.isalpha() else ord(c) for c in out[:16])
    if (cs % 10) != int(out[16]):
        return None
    return out


# ---------------------------------------------------------------------------
# Frame building — exact port from EvilCardputer
# ---------------------------------------------------------------------------

def _append_word(buf, value):
    buf.append((value >> 8) & 0xFF)
    buf.append(value & 0xFF)


def _terminate(buf):
    crc = crc16(buf)
    buf.append(crc & 0xFF)
    buf.append((crc >> 8) & 0xFF)
    return buf


def _raw_frame(proto, plid, cmd):
    buf = bytearray([proto]) + bytearray(plid) + bytearray([cmd])
    return buf


def _mcu_frame(plid, cmd):
    buf = _raw_frame(PROTO_DM, plid, 0x34)
    buf.extend([0x00, 0x00, 0x00, cmd])
    return buf


def make_broadcast_page_frame(page, forever=False, duration=10):
    plid = bytes(4)
    buf = _raw_frame(PROTO_DM, plid, 0x06)
    buf.append((((page + 1) & 7) << 3) | 0x01 | (0x80 if forever else 0x00))
    buf.extend([0x00, 0x00])
    buf.append((duration >> 8) & 0xFF)
    buf.append(duration & 0xFF)
    return bytes(_terminate(buf))


def make_broadcast_debug_frame():
    plid = bytes(4)
    buf = _raw_frame(PROTO_DM, plid, 0x06)
    buf.extend([0xF1, 0x00, 0x00, 0x00, 0x0A])
    return bytes(_terminate(buf))


def make_ping_frame(plid):
    buf = _raw_frame(PROTO_DM, plid, 0x97)
    buf.extend([0x01, 0x00, 0x00, 0x00])
    buf.extend([0x01] * 20)
    return bytes(_terminate(buf))


def make_refresh_frame(plid):
    buf = _mcu_frame(plid, 0x01)
    buf.extend([0x00] * 18)
    return bytes(_terminate(buf))


def make_addressed_frame(plid, payload):
    buf = _raw_frame(PROTO_DM, plid, payload[0])
    buf.extend(payload[1:])
    return bytes(_terminate(buf))


def make_image_param_frame(plid, byte_count, comp_type, page,
                           width, height, pos_x=0, pos_y=0):
    buf = _mcu_frame(plid, 0x05)
    _append_word(buf, byte_count)
    buf.append(0x00)
    buf.append(comp_type)
    buf.append(page)
    _append_word(buf, width)
    _append_word(buf, height)
    _append_word(buf, pos_x)
    _append_word(buf, pos_y)
    _append_word(buf, 0x0000)
    buf.append(0x88)
    _append_word(buf, 0x0000)
    buf.extend([0x00] * 4)
    return bytes(_terminate(buf))


def make_image_data_frame(plid, frame_index, data_bytes):
    buf = _mcu_frame(plid, 0x20)
    _append_word(buf, frame_index)
    buf.extend(data_bytes[:DATA_BYTES_PER_FRAME])
    if len(data_bytes) < DATA_BYTES_PER_FRAME:
        buf.extend([0x00] * (DATA_BYTES_PER_FRAME - len(data_bytes)))
    return bytes(_terminate(buf))


# ---------------------------------------------------------------------------
# RLE compression — exact port
# ---------------------------------------------------------------------------

def _record_run(out, run_count):
    bits = []
    v = run_count
    while v:
        bits.append(v & 1)
        v >>= 1
    bits.reverse()
    for i in range(1, len(bits)):
        out.append(0)
    out.extend(bits)


def rle_compress_bits(pixels):
    if not pixels:
        return [], 0
    out = [pixels[0]]
    run_pixel = pixels[0]
    run_count = 1
    for i in range(1, len(pixels)):
        if pixels[i] == run_pixel:
            run_count += 1
        else:
            _record_run(out, run_count)
            run_pixel = pixels[i]
            run_count = 1
    if run_count > 1:
        _record_run(out, run_count)
    if len(out) < len(pixels):
        return out, 2
    return list(pixels), 0


def _bits_to_bytes(bits):
    result = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        if b:
            result[i // 8] |= (1 << (7 - (i % 8)))
    return bytes(result)


# ---------------------------------------------------------------------------
# Image encoding
# ---------------------------------------------------------------------------

def encode_image_payload(pixels_1bpp, width, height, color_clear=False,
                         comp_mode=COMP_AUTO):
    pixel_count = width * height
    primary = list(pixels_1bpp[:pixel_count])
    if color_clear:
        secondary = [1] * pixel_count
        total_pixels = primary + secondary
    else:
        total_pixels = primary

    if comp_mode == COMP_RLE:
        encoded_bits, comp_type = rle_compress_bits(total_pixels)
    elif comp_mode == COMP_AUTO:
        encoded_bits, comp_type = rle_compress_bits(total_pixels)
        if comp_type == 0:
            encoded_bits = total_pixels
    else:
        encoded_bits = total_pixels
        comp_type = 0

    padding = (DATA_BITS_PER_FRAME - (len(encoded_bits) % DATA_BITS_PER_FRAME)) % DATA_BITS_PER_FRAME
    encoded_bits.extend([0] * padding)
    data_bytes = _bits_to_bytes(encoded_bits)
    return data_bytes, comp_type


# ---------------------------------------------------------------------------
# Saved targets
# ---------------------------------------------------------------------------

def load_targets():
    targets = []
    try:
        with open(TARGETS_FILE, "r") as f:
            for line in f:
                line = line.strip()
                sep = line.find("|")
                if sep < BC_LEN:
                    continue
                barcode = line[:BC_LEN]
                name = line[sep + 1:].strip() if sep + 1 < len(line) else ""
                targets.append({"barcode": barcode, "name": name})
                if len(targets) >= 50:
                    break
    except FileNotFoundError:
        pass
    return targets


def save_targets(targets):
    os.makedirs(LOOT_DIR, exist_ok=True)
    with open(TARGETS_FILE, "w") as f:
        for t in targets:
            f.write("%s|%s\n" % (t["barcode"], t["name"]))


def add_target(barcode, name=""):
    targets = load_targets()
    for t in targets:
        if t["barcode"] == barcode:
            t["name"] = name
            save_targets(targets)
            return True
    if len(targets) >= 50:
        return False
    targets.append({"barcode": barcode, "name": name})
    save_targets(targets)
    return True


def delete_target(idx):
    targets = load_targets()
    if 0 <= idx < len(targets):
        targets.pop(idx)
        save_targets(targets)


# ---------------------------------------------------------------------------
# Text presets
# ---------------------------------------------------------------------------

def load_presets():
    presets = []
    try:
        with open(PRESETS_FILE, "r") as f:
            for line in f:
                line = line.strip()
                sep = line.find("|")
                if sep < 1:
                    continue
                presets.append({"name": line[:sep], "text": line[sep + 1:]})
                if len(presets) >= 16:
                    break
    except FileNotFoundError:
        pass
    return presets


def save_presets(presets):
    os.makedirs(LOOT_DIR, exist_ok=True)
    with open(PRESETS_FILE, "w") as f:
        for p in presets:
            f.write("%s|%s\n" % (p["name"], p["text"]))


# ---------------------------------------------------------------------------
# IR driver — 1.25 MHz carrier via hardware PWM on GPIO 12
# ---------------------------------------------------------------------------

def _busy_wait_ns(ns):
    end = time.monotonic_ns() + ns
    while time.monotonic_ns() < end:
        pass


class TagTinker:
    def __init__(self):
        self._pwm_enabled = False
        self._enable_fh = None
        self._use_pp16 = True
        self._data_repeats = 3
        self._wake_repeats = 250
        self._comp_mode = COMP_AUTO
        self._page = 1
        self._stop_requested = False

    def open(self):
        try:
            subprocess.run(["dtoverlay", "-r", "gpio-ir-tx"],
                           capture_output=True, timeout=5)
        except Exception:
            pass
        time.sleep(0.1)

        try:
            if not os.path.exists(PWM_CHAN):
                with open(os.path.join(PWM_CHIP, "export"), "w") as f:
                    f.write("0")
                time.sleep(0.1)
            with open(os.path.join(PWM_CHAN, "period"), "w") as f:
                f.write(str(PWM_PERIOD))
            with open(os.path.join(PWM_CHAN, "duty_cycle"), "w") as f:
                f.write(str(PWM_DUTY))
            self._enable_fh = open(os.path.join(PWM_CHAN, "enable"), "w")
            self._carrier_off()
            return True
        except Exception:
            return False

    def close(self):
        self._carrier_off()
        if self._enable_fh:
            try:
                self._enable_fh.close()
            except Exception:
                pass
            self._enable_fh = None

    def _carrier_on(self):
        if self._enable_fh and not self._pwm_enabled:
            self._enable_fh.write("1")
            self._enable_fh.flush()
            self._pwm_enabled = True

    def _carrier_off(self):
        if self._enable_fh and self._pwm_enabled:
            self._enable_fh.write("0")
            self._enable_fh.flush()
            self._pwm_enabled = False

    def _burst(self, duration_ns):
        self._carrier_on()
        _busy_wait_ns(duration_ns)
        self._carrier_off()

    def _send_frame_pp4(self, data):
        for byte in data:
            current = byte
            for _ in range(4):
                symbol = current & 0x03
                current >>= 2
                self._burst(PP4_BURST_NS)
                _busy_wait_ns(PP4_GAPS_NS[symbol])
        self._burst(PP4_BURST_NS)
        self._carrier_off()

    def _send_frame_pp16(self, data):
        for byte in data:
            current = byte
            for _ in range(2):
                symbol = current & 0x0F
                current >>= 4
                self._burst(PP16_BURST_NS)
                _busy_wait_ns(PP16_GAPS_NS[symbol])
        self._burst(PP16_BURST_NS)
        self._carrier_off()

    def transmit(self, data, repeats=1, gap_delay=2, pp16=None):
        if pp16 is None:
            pp16 = self._use_pp16
        if not self._enable_fh or len(data) == 0:
            return False
        self._stop_requested = False

        if pp16:
            preamble = bytes([0x00, 0x00, 0x00, 0x40])
            tx_data = preamble + bytes(data)
        else:
            tx_data = bytes(data)

        for rep in range(repeats + 1):
            if self._stop_requested:
                self._carrier_off()
                return False
            if pp16:
                self._send_frame_pp16(tx_data)
            else:
                self._send_frame_pp4(tx_data)
            if rep < repeats:
                gap_ns = gap_delay * 500_000
                _busy_wait_ns(gap_ns)
                if rep % 5 == 4:
                    time.sleep(0.001)
        return True

    def stop(self):
        self._stop_requested = True

    # -- High-level commands --

    def wake(self, barcode, repeats=None):
        plid = barcode_to_plid(barcode)
        if not plid:
            return False
        frame = make_ping_frame(plid)
        reps = repeats if repeats is not None else self._wake_repeats
        return self.transmit(frame, reps, gap_delay=2, pp16=self._use_pp16)

    def ping(self, barcode, repeats=None):
        return self.wake(barcode, repeats or 250)

    def refresh(self, barcode):
        plid = barcode_to_plid(barcode)
        if not plid:
            return False
        frame = make_refresh_frame(plid)
        return self.transmit(frame, 20, gap_delay=2, pp16=self._use_pp16)

    def broadcast_page(self, page, duration=10, forever=False, repeats=100):
        frame = make_broadcast_page_frame(page, forever, duration)
        return self.transmit(frame, repeats, gap_delay=2, pp16=False)

    def broadcast_debug(self, repeats=200):
        frame = make_broadcast_debug_frame()
        return self.transmit(frame, repeats, gap_delay=2, pp16=False)

    def led_on(self, barcode, mode=0xC9, duration=5):
        plid = barcode_to_plid(barcode)
        if not plid:
            return False
        ping_frame = make_ping_frame(plid)
        self.transmit(ping_frame, 160, gap_delay=2, pp16=self._use_pp16)
        payload = bytes([0x06, mode, 0x00, 0x00,
                         (duration >> 8) & 0xFF, duration & 0xFF])
        led_frame = make_addressed_frame(plid, payload)
        return self.transmit(led_frame, 80, gap_delay=2, pp16=self._use_pp16)

    def send_image(self, barcode, pixels_1bpp, width, height,
                   page=None, color_clear=False, callback=None):
        plid = barcode_to_plid(barcode)
        if not plid:
            return False
        if page is None:
            page = self._page
        data_bytes, comp_type = encode_image_payload(
            pixels_1bpp, width, height, color_clear, self._comp_mode)

        frame_count = len(data_bytes) // DATA_BYTES_PER_FRAME
        total_steps = 2 + frame_count + 1

        # 1. Wake
        if callback:
            callback(0, total_steps, "Waking tag...")
        ping_frame = make_ping_frame(plid)
        self.transmit(ping_frame, self._wake_repeats, gap_delay=2)

        # 2. Image parameters
        if callback:
            callback(1, total_steps, "Sending params...")
        param_frame = make_image_param_frame(
            plid, len(data_bytes), comp_type, page, width, height)
        self.transmit(param_frame, 15, gap_delay=1)
        time.sleep(0.05)

        # 3. Data frames
        for fi in range(frame_count):
            if self._stop_requested:
                return False
            if callback:
                callback(2 + fi, total_steps,
                         "Frame %d/%d" % (fi + 1, frame_count))
            chunk = data_bytes[fi * DATA_BYTES_PER_FRAME:
                               (fi + 1) * DATA_BYTES_PER_FRAME]
            data_frame = make_image_data_frame(plid, fi, chunk)
            self.transmit(data_frame, self._data_repeats, gap_delay=1)

        # 4. Refresh
        if callback:
            callback(total_steps - 1, total_steps, "Refreshing...")
        refresh_frame = make_refresh_frame(plid)
        self.transmit(refresh_frame, 20, gap_delay=2)

        return True

    def push_text(self, barcode, text, text_size=2, invert=True,
                  page=None, callback=None):
        profile = barcode_to_profile(barcode)
        if not profile:
            return False
        w = profile["width"] if profile["known"] else 296
        h = profile["height"] if profile["known"] else 128
        if w == 0 or h == 0:
            return False

        try:
            from PIL import Image, ImageDraw, ImageFont
        except ImportError:
            return False

        img = Image.new("1", (w, h), 0)
        draw = ImageDraw.Draw(img)
        try:
            font_size = text_size * 8
            font = ImageFont.truetype(
                "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", font_size)
        except Exception:
            font = ImageFont.load_default()

        draw.text((2, 2), text, fill=1, font=font)

        pixels = []
        for y in range(h):
            for x in range(w):
                px = img.getpixel((x, y))
                if invert:
                    pixels.append(0 if px else 1)
                else:
                    pixels.append(1 if px else 0)

        color_clear = profile.get("color", COLOR_MONO) != COLOR_MONO
        return self.send_image(barcode, pixels, w, h, page,
                               color_clear, callback)
