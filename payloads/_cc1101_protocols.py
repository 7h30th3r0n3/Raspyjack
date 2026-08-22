"""
Sub-GHz protocol decoders faithfully ported from Momentum Firmware.
https://github.com/Next-Flip/Momentum-Firmware/tree/dev/lib/subghz/protocols

Each decoder's feed() state machine is a line-by-line port of the C source.
DURATION_DIFF = abs(a - b), matching the C macro exactly.

Flipper .sub file format support for save/load/replay.
"""

import os
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Helpers (from Momentum lib/subghz/blocks/math.h)
# ---------------------------------------------------------------------------

def DURATION_DIFF(a, b):
    return abs(int(a) - int(b))


def _reverse_key(data, bit_count):
    result = 0
    for i in range(bit_count):
        if data & (1 << i):
            result |= 1 << (bit_count - 1 - i)
    return result


# ---------------------------------------------------------------------------
# Base decoded signal
# ---------------------------------------------------------------------------

@dataclass
class DecodedSignal:
    protocol: str = ""
    data: int = 0
    bit_count: int = 0
    serial: int = 0
    btn: int = 0
    cnt: int = 0
    te: int = 0
    modulation: str = "AM650"
    frequency: int = 433920000
    proto_type: str = "Static"
    extra: dict = field(default_factory=dict)

    @property
    def key_hex(self):
        n = max(1, (self.bit_count + 7) // 8)
        return f"0x{self.data & ((1 << self.bit_count) - 1):0{n * 2}X}"

    def format_brief(self):
        return f"{self.protocol} {self.bit_count}b {self.key_hex}"

    def format_full(self):
        lines = [f"{self.protocol} {self.bit_count}bit"]
        lines.append(f"Key:{self.key_hex}")
        yek = _reverse_key(self.data, self.bit_count)
        n = max(1, (self.bit_count + 7) // 8)
        lines.append(f"Yek:0x{yek:0{n * 2}X}")
        if self.serial or self.btn:
            lines.append(f"Sn:0x{self.serial:05X} Btn:{self.btn:X}")
        if self.cnt:
            lines.append(f"Cnt:0x{self.cnt:04X}")
        if self.te:
            lines.append(f"Te:{self.te}us")
        for k, v in self.extra.items():
            lines.append(f"{k}: {v}")
        return "\n".join(lines)


# ===================================================================
# CAME decoder — ported from came.c
# te_short=320, te_long=640, te_delta=150, min_bits=12
# Structure: LOW+HIGH pairs. SaveDuration saves LOW, CheckDuration checks HIGH.
# Bit encoding: short_LOW + long_HIGH = 0, long_LOW + short_HIGH = 1
# ===================================================================

class CAMEDecoder:
    name = "CAME"
    _TE_SHORT = 320
    _TE_LONG = 640
    _TE_DELTA = 150
    _MIN_BITS = 12
    _VALID_BITS = (12, 18, 24, 25, 42)

    _RESET = 0
    _FOUND_START = 1
    _SAVE_DUR = 2
    _CHECK_DUR = 3

    def __init__(self):
        self.reset()

    def reset(self):
        self._step = self._RESET
        self._data = 0
        self._bits = 0
        self._te_last = 0

    def _add_bit(self, bit):
        self._data = (self._data << 1) | bit
        self._bits += 1

    def _emit(self):
        sig = DecodedSignal(protocol=self.name, data=self._data,
                            bit_count=self._bits, proto_type="Static")
        return sig

    def feed(self, level, duration):
        if self._step == self._RESET:
            if (not level) and DURATION_DIFF(duration, self._TE_SHORT * 56) < self._TE_DELTA * 63:
                self._step = self._FOUND_START
            return None

        if self._step == self._FOUND_START:
            if not level:
                return None
            if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA:
                self._step = self._SAVE_DUR
                self._data = 0
                self._bits = 0
            else:
                self._step = self._RESET
            return None

        if self._step == self._SAVE_DUR:
            if not level:
                if duration >= self._TE_SHORT * 4:
                    self._step = self._FOUND_START
                    if self._bits in self._VALID_BITS:
                        return self._emit()
                    return None
                self._te_last = duration
                self._step = self._CHECK_DUR
            else:
                self._step = self._RESET
            return None

        if self._step == self._CHECK_DUR:
            if level:
                if (DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA and
                        DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA):
                    self._add_bit(0)
                    self._step = self._SAVE_DUR
                elif (DURATION_DIFF(self._te_last, self._TE_LONG) < self._TE_DELTA and
                      DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA):
                    self._add_bit(1)
                    self._step = self._SAVE_DUR
                else:
                    self._step = self._RESET
            else:
                self._step = self._RESET
            return None
        return None


# ===================================================================
# Princeton decoder — ported from princeton.c
# te_short=390, te_long=1170, te_delta=300, min_bits=24
# Structure: HIGH+LOW pairs. SaveDuration saves HIGH, CheckDuration checks LOW.
# Bit encoding: short_HIGH + long_LOW = 0, long_HIGH + short_LOW = 1
# Requires 2 consecutive identical frames.
# ===================================================================

class PrincetonDecoder:
    name = "Princeton"
    _TE_SHORT = 390
    _TE_LONG = 1170
    _TE_DELTA = 300
    _MIN_BITS = 24

    _RESET = 0
    _SAVE_DUR = 1
    _CHECK_DUR = 2

    def __init__(self):
        self.reset()

    def reset(self):
        self._step = self._RESET
        self._data = 0
        self._bits = 0
        self._te_last = 0
        self._te_sum = 0
        self._last_data = 0

    def _add_bit(self, bit):
        self._data = (self._data << 1) | bit
        self._bits += 1

    def _emit(self):
        te = self._te_sum // (self._bits * 4 + 1) if self._bits > 0 else self._TE_SHORT
        sig = DecodedSignal(protocol=self.name, data=self._data,
                            bit_count=self._bits, te=te, proto_type="Static")
        sig.serial = int(self._data >> 4) & 0xFFFFF
        sig.btn = int(self._data & 0xF)
        return sig

    def feed(self, level, duration):
        if self._step == self._RESET:
            if (not level) and DURATION_DIFF(duration, self._TE_SHORT * 36) < self._TE_DELTA * 36:
                self._step = self._SAVE_DUR
                self._data = 0
                self._bits = 0
                self._te_sum = 0
            return None

        if self._step == self._SAVE_DUR:
            if level:
                self._te_last = duration
                self._te_sum += duration
                self._step = self._CHECK_DUR
            return None

        if self._step == self._CHECK_DUR:
            if not level:
                if duration >= self._TE_LONG * 2:
                    self._step = self._SAVE_DUR
                    result = None
                    if self._bits == self._MIN_BITS:
                        if self._last_data == self._data and self._last_data:
                            result = self._emit()
                        self._last_data = self._data
                    self._data = 0
                    self._bits = 0
                    self._te_sum = 0
                    return result

                self._te_sum += duration

                if (DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA and
                        DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA * 3):
                    self._add_bit(0)
                    self._step = self._SAVE_DUR
                elif (DURATION_DIFF(self._te_last, self._TE_LONG) < self._TE_DELTA * 3 and
                      DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA):
                    self._add_bit(1)
                    self._step = self._SAVE_DUR
                else:
                    self._step = self._RESET
            else:
                self._step = self._RESET
            return None
        return None


# ===================================================================
# Nice FLO decoder — ported from nice_flo.c
# te_short=700, te_long=1400, te_delta=250, min_bits=12
# Same structure as CAME (LOW+HIGH pairs)
# ===================================================================

class NiceFloDecoder:
    name = "Nice FLO"
    _TE_SHORT = 700
    _TE_LONG = 1400
    _TE_DELTA = 250
    _MIN_BITS = 12

    _RESET = 0
    _FOUND_START = 1
    _SAVE_DUR = 2
    _CHECK_DUR = 3

    def __init__(self):
        self.reset()

    def reset(self):
        self._step = self._RESET
        self._data = 0
        self._bits = 0
        self._te_last = 0

    def _add_bit(self, bit):
        self._data = (self._data << 1) | bit
        self._bits += 1

    def feed(self, level, duration):
        if self._step == self._RESET:
            if (not level) and DURATION_DIFF(duration, self._TE_SHORT * 36) < self._TE_DELTA * 29:
                self._step = self._FOUND_START
            return None

        if self._step == self._FOUND_START:
            if not level:
                return None
            if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA:
                self._step = self._SAVE_DUR
                self._data = 0
                self._bits = 0
            else:
                self._step = self._RESET
            return None

        if self._step == self._SAVE_DUR:
            if not level:
                if duration >= self._TE_SHORT * 4:
                    self._step = self._FOUND_START
                    if self._bits >= self._MIN_BITS:
                        return DecodedSignal(protocol=self.name, data=self._data,
                                            bit_count=self._bits, proto_type="Static")
                    return None
                self._te_last = duration
                self._step = self._CHECK_DUR
            else:
                self._step = self._RESET
            return None

        if self._step == self._CHECK_DUR:
            if level:
                if (DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA and
                        DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA):
                    self._add_bit(0)
                    self._step = self._SAVE_DUR
                elif (DURATION_DIFF(self._te_last, self._TE_LONG) < self._TE_DELTA and
                      DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA):
                    self._add_bit(1)
                    self._step = self._SAVE_DUR
                else:
                    self._step = self._RESET
            else:
                self._step = self._RESET
            return None
        return None


# ===================================================================
# Gate TX decoder — ported from gate_tx.c
# te_short=350, te_long=700, te_delta=100, min_bits=24
# Same structure as CAME but start bit is te_long HIGH, footer is te_short*10
# ===================================================================

class GateTXDecoder:
    name = "GateTX"
    _TE_SHORT = 350
    _TE_LONG = 700
    _TE_DELTA = 100
    _MIN_BITS = 24

    _RESET = 0
    _FOUND_START = 1
    _SAVE_DUR = 2
    _CHECK_DUR = 3

    def __init__(self):
        self.reset()

    def reset(self):
        self._step = self._RESET
        self._data = 0
        self._bits = 0
        self._te_last = 0

    def _add_bit(self, bit):
        self._data = (self._data << 1) | bit
        self._bits += 1

    def feed(self, level, duration):
        if self._step == self._RESET:
            if (not level) and DURATION_DIFF(duration, self._TE_SHORT * 47) < self._TE_DELTA * 47:
                self._step = self._FOUND_START
            return None

        if self._step == self._FOUND_START:
            if level and DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA * 3:
                self._step = self._SAVE_DUR
                self._data = 0
                self._bits = 0
            else:
                self._step = self._RESET
            return None

        if self._step == self._SAVE_DUR:
            if not level:
                if duration >= self._TE_SHORT * 10 + self._TE_DELTA:
                    self._step = self._FOUND_START
                    if self._bits == self._MIN_BITS:
                        sig = DecodedSignal(protocol=self.name, data=self._data,
                                            bit_count=self._bits, proto_type="Static")
                        rev = _reverse_key(self._data, self._bits)
                        sig.serial = ((rev & 0xFF) << 12 |
                                     ((rev >> 8) & 0xFF) << 4 |
                                     ((rev >> 20) & 0x0F))
                        sig.btn = (rev >> 16) & 0x0F
                        return sig
                    self._data = 0
                    self._bits = 0
                    return None
                self._te_last = duration
                self._step = self._CHECK_DUR
            return None

        if self._step == self._CHECK_DUR:
            if level:
                if (DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA and
                        DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA * 3):
                    self._add_bit(0)
                    self._step = self._SAVE_DUR
                elif (DURATION_DIFF(self._te_last, self._TE_LONG) < self._TE_DELTA * 3 and
                      DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA):
                    self._add_bit(1)
                    self._step = self._SAVE_DUR
                else:
                    self._step = self._RESET
            else:
                self._step = self._RESET
            return None
        return None


# ===================================================================
# Linear decoder — ported from linear.c
# te_short=500, te_long=1500, te_delta=350, min_bits=10
# Structure: HIGH+LOW pairs like Princeton, but the guard time also serves
# as a bit if the last HIGH before it matches te_short or te_long.
# ===================================================================

class LinearDecoder:
    name = "Linear"
    _TE_SHORT = 500
    _TE_LONG = 1500
    _TE_DELTA = 350
    _MIN_BITS = 10

    _RESET = 0
    _SAVE_DUR = 1
    _CHECK_DUR = 2

    def __init__(self):
        self.reset()

    def reset(self):
        self._step = self._RESET
        self._data = 0
        self._bits = 0
        self._te_last = 0

    def _add_bit(self, bit):
        self._data = (self._data << 1) | bit
        self._bits += 1

    def feed(self, level, duration):
        if self._step == self._RESET:
            if (not level) and DURATION_DIFF(duration, self._TE_SHORT * 42) < self._TE_DELTA * 15:
                self._data = 0
                self._bits = 0
                self._step = self._SAVE_DUR
            return None

        if self._step == self._SAVE_DUR:
            if level:
                self._te_last = duration
                self._step = self._CHECK_DUR
            else:
                self._step = self._RESET
            return None

        if self._step == self._CHECK_DUR:
            if not level:
                if duration >= self._TE_SHORT * 5:
                    self._step = self._RESET
                    if DURATION_DIFF(duration, self._TE_SHORT * 42) > self._TE_DELTA * 15:
                        return None
                    if DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA:
                        self._add_bit(0)
                    elif DURATION_DIFF(self._te_last, self._TE_LONG) < self._TE_DELTA:
                        self._add_bit(1)
                    if self._bits == self._MIN_BITS:
                        return DecodedSignal(protocol=self.name, data=self._data,
                                            bit_count=self._bits, proto_type="Static")
                    return None

                if (DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA and
                        DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA):
                    self._add_bit(0)
                    self._step = self._SAVE_DUR
                elif (DURATION_DIFF(self._te_last, self._TE_LONG) < self._TE_DELTA and
                      DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA):
                    self._add_bit(1)
                    self._step = self._SAVE_DUR
                else:
                    self._step = self._RESET
            else:
                self._step = self._RESET
            return None
        return None


# ===================================================================
# Holtek HT12X decoder — ported from holtek_ht12x.c
# te_short=320, te_long=640, te_delta=200, min_bits=12
# Structure: CAME-like (LOW+HIGH) but with start bit and 2-frame validation.
# Bit encoding is INVERTED vs CAME: long_LOW+short_HIGH=1, short_LOW+long_HIGH=0
# ===================================================================

class HoltekHT12XDecoder:
    name = "Holtek HT12x"
    _TE_SHORT = 320
    _TE_LONG = 640
    _TE_DELTA = 200
    _MIN_BITS = 12

    _RESET = 0
    _FOUND_START = 1
    _SAVE_DUR = 2
    _CHECK_DUR = 3

    def __init__(self):
        self.reset()

    def reset(self):
        self._step = self._RESET
        self._data = 0
        self._bits = 0
        self._te_last = 0
        self._te_sum = 0
        self._last_data = 0

    def _add_bit(self, bit):
        self._data = (self._data << 1) | bit
        self._bits += 1

    def feed(self, level, duration):
        if self._step == self._RESET:
            if (not level) and DURATION_DIFF(duration, self._TE_SHORT * 28) < self._TE_DELTA * 20:
                self._step = self._FOUND_START
            return None

        if self._step == self._FOUND_START:
            if level and DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA:
                self._step = self._SAVE_DUR
                self._data = 0
                self._bits = 0
                self._te_sum = duration
            else:
                self._step = self._RESET
            return None

        if self._step == self._SAVE_DUR:
            if not level:
                if duration >= self._TE_SHORT * 10 + self._TE_DELTA:
                    if self._bits == self._MIN_BITS:
                        if self._last_data == self._data and self._last_data:
                            self._te_sum //= (self._bits * 3 + 1)
                            sig = DecodedSignal(protocol=self.name, data=self._data,
                                                bit_count=self._bits, te=self._te_sum,
                                                proto_type="Static")
                            sig.btn = int(self._data & 0x0F)
                            sig.cnt = int((self._data >> 4) & 0xFF)
                            self._last_data = self._data
                            self._step = self._FOUND_START
                            self._data = 0
                            self._bits = 0
                            self._te_sum = 0
                            return sig
                        self._last_data = self._data
                    self._data = 0
                    self._bits = 0
                    self._te_sum = 0
                    self._step = self._FOUND_START
                    return None
                self._te_last = duration
                self._te_sum += duration
                self._step = self._CHECK_DUR
            else:
                self._step = self._RESET
            return None

        if self._step == self._CHECK_DUR:
            if level:
                self._te_sum += duration
                if (DURATION_DIFF(self._te_last, self._TE_LONG) < self._TE_DELTA * 2 and
                        DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA):
                    self._add_bit(1)
                    self._step = self._SAVE_DUR
                elif (DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA and
                      DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA * 2):
                    self._add_bit(0)
                    self._step = self._SAVE_DUR
                else:
                    self._step = self._RESET
            else:
                self._step = self._RESET
            return None
        return None


# ===================================================================
# Chamberlain Code decoder — ported from chamberlain_code.c
# te_short=1000, te_long=3000, te_delta=200, min_bits=10
# Tri-state encoding: each "bit" is encoded as a LOW+HIGH pair with 3 states
# ===================================================================

class ChamberlainDecoder:
    name = "Chamberlain"
    _TE_SHORT = 1000
    _TE_LONG = 3000
    _TE_DELTA = 200
    _MIN_BITS = 10

    _BIT_STOP = 0x1
    _BIT_1 = 0x3
    _BIT_0 = 0x7

    _RESET = 0
    _FOUND_START = 1
    _SAVE_DUR = 2
    _CHECK_DUR = 3

    def __init__(self):
        self.reset()

    def reset(self):
        self._step = self._RESET
        self._data = 0
        self._bits = 0
        self._te_last = 0

    def _to_binary(self, data, count):
        result = 0
        actual_bits = 0
        for i in range(count):
            nibble = (data >> ((count - 1 - i) * 4)) & 0xF
            if nibble == self._BIT_0:
                result = (result << 1) | 0
                actual_bits += 1
            elif nibble == self._BIT_1:
                result = (result << 1) | 1
                actual_bits += 1
        return result, actual_bits

    def feed(self, level, duration):
        if self._step == self._RESET:
            if (not level) and DURATION_DIFF(duration, self._TE_SHORT * 39) < self._TE_DELTA * 20:
                self._step = self._FOUND_START
            return None

        if self._step == self._FOUND_START:
            if level and DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA:
                self._data = 0
                self._bits = 0
                self._data = (self._data << 4) | self._BIT_STOP
                self._bits += 1
                self._step = self._SAVE_DUR
            else:
                self._step = self._RESET
            return None

        if self._step == self._SAVE_DUR:
            if not level:
                if duration > self._TE_SHORT * 5:
                    if self._bits >= self._MIN_BITS:
                        binary, actual = self._to_binary(self._data, self._bits)
                        if actual > 0:
                            sig = DecodedSignal(protocol=self.name, data=binary,
                                                bit_count=actual, proto_type="Static")
                            self._step = self._RESET
                            return sig
                    self._step = self._RESET
                    return None
                self._te_last = duration
                self._step = self._CHECK_DUR
            else:
                self._step = self._RESET
            return None

        if self._step == self._CHECK_DUR:
            if level:
                if (DURATION_DIFF(self._te_last, self._TE_SHORT * 3) < self._TE_DELTA and
                        DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA):
                    self._data = (self._data << 4) | self._BIT_STOP
                    self._bits += 1
                    self._step = self._SAVE_DUR
                elif (DURATION_DIFF(self._te_last, self._TE_SHORT * 2) < self._TE_DELTA and
                      DURATION_DIFF(duration, self._TE_SHORT * 2) < self._TE_DELTA):
                    self._data = (self._data << 4) | self._BIT_1
                    self._bits += 1
                    self._step = self._SAVE_DUR
                elif (DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA and
                      DURATION_DIFF(duration, self._TE_SHORT * 3) < self._TE_DELTA):
                    self._data = (self._data << 4) | self._BIT_0
                    self._bits += 1
                    self._step = self._SAVE_DUR
                else:
                    self._step = self._RESET
            else:
                self._step = self._RESET
            return None
        return None


# ===================================================================
# .sub file format
# ===================================================================

SUB_FILE_TYPE_KEY = "Flipper SubGhz Key File"
SUB_FILE_TYPE_RAW = "Flipper SubGhz RAW File"
SUB_FILE_VERSION = 1

_PRESET_MAP = {
    "AM270": "FuriHalSubGhzPresetOok270Async",
    "AM650": "FuriHalSubGhzPresetOok650Async",
    "FM238": "FuriHalSubGhzPreset2FSKDev238Async",
    "FM476": "FuriHalSubGhzPreset2FSKDev476Async",
}
_PRESET_REVERSE = {v: k for k, v in _PRESET_MAP.items()}


def save_sub_file(path, signal=None, raw_pulses=None, frequency=433920000, preset="AM650"):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    preset_full = _PRESET_MAP.get(preset, "FuriHalSubGhzPresetOok650Async")
    with open(path, "w") as f:
        if raw_pulses:
            f.write(f"Filetype: {SUB_FILE_TYPE_RAW}\n")
            f.write(f"Version: {SUB_FILE_VERSION}\n")
            f.write(f"Frequency: {frequency}\n")
            f.write(f"Preset: {preset_full}\n")
            f.write(f"Protocol: RAW\n")
            for i in range(0, len(raw_pulses), 512):
                chunk = raw_pulses[i:i + 512]
                f.write("RAW_Data: " + " ".join(str(int(p)) for p in chunk) + "\n")
        elif signal:
            f.write(f"Filetype: {SUB_FILE_TYPE_KEY}\n")
            f.write(f"Version: {SUB_FILE_VERSION}\n")
            f.write(f"Frequency: {frequency}\n")
            f.write(f"Preset: {preset_full}\n")
            f.write(f"Protocol: {signal.protocol}\n")
            n = max(1, (signal.bit_count + 7) // 8)
            key_bytes = signal.data.to_bytes(n, "big")
            f.write(f"Bit: {signal.bit_count}\n")
            f.write(f"Key: {' '.join(f'{b:02X}' for b in key_bytes)}\n")
            if signal.te:
                f.write(f"TE: {signal.te}\n")


def load_sub_file(path):
    result = {"type": None, "frequency": 0, "preset": "AM650", "protocol": "",
              "bit_count": 0, "key": 0, "te": 0, "raw_data": []}
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            key, val = line.split(":", 1)
            key = key.strip()
            val = val.strip()
            if key == "Filetype":
                result["type"] = val
            elif key == "Frequency":
                result["frequency"] = int(val)
            elif key == "Preset":
                result["preset"] = _PRESET_REVERSE.get(val, val)
            elif key == "Protocol":
                result["protocol"] = val
            elif key == "Bit":
                result["bit_count"] = int(val)
            elif key == "Key":
                result["key"] = int(val.replace(" ", ""), 16)
            elif key == "TE":
                result["te"] = int(val)
            elif key == "RAW_Data":
                result["raw_data"].extend(int(v) for v in val.split())
    return result


# ---------------------------------------------------------------------------
# Protocol registry
# ---------------------------------------------------------------------------

ALL_PROTOCOLS = [
    PrincetonDecoder(),
    CAMEDecoder(),
    NiceFloDecoder(),
    GateTXDecoder(),
    LinearDecoder(),
    HoltekHT12XDecoder(),
    ChamberlainDecoder(),
]

PROTOCOL_BY_NAME = {p.name: p for p in ALL_PROTOCOLS}


def decode_raw_pulses(pulses, protocols=None):
    if protocols is None:
        protocols = ALL_PROTOCOLS
    for p in protocols:
        p.reset()
    raw_results = []
    for pulse in pulses:
        level = pulse > 0
        duration = abs(pulse)
        for p in protocols:
            result = p.feed(level, duration)
            if result:
                raw_results.append(result)
    seen = set()
    results = []
    for r in raw_results:
        key = (r.protocol, r.key_hex)
        if key not in seen:
            seen.add(key)
            results.append(r)
    return results
