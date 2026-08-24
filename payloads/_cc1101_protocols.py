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

    def encode(self, data, bit_count=None):
        if bit_count is None:
            bit_count = 12
        te = self._TE_SHORT
        pulses = [-(te * 56), te]
        for i in range(bit_count - 1, -1, -1):
            if (data >> i) & 1:
                pulses.extend([-(te * 2), te])
            else:
                pulses.extend([-te, te * 2])
        pulses.append(-(te * 4))
        return pulses


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
            elif duration >= self._TE_LONG * 2:
                # Long LOW in SAVE_DUR = frame boundary (footer/guard)
                result = None
                if self._bits == self._MIN_BITS:
                    if self._last_data == self._data and self._last_data:
                        result = self._emit()
                    self._last_data = self._data
                self._data = 0; self._bits = 0; self._te_sum = 0
                return result
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

    def encode(self, data, bit_count=None):
        if bit_count is None:
            bit_count = 24
        te = self._TE_SHORT
        pulses = []
        for i in range(bit_count - 1, -1, -1):
            if (data >> i) & 1:
                pulses.extend([te * 3, -(te)])
            else:
                pulses.extend([te, -(te * 3)])
        pulses.extend([te, -(te * 30)])  # stop bit + guard
        return pulses


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

    def encode(self, data, bit_count=None):
        if bit_count is None:
            bit_count = self._MIN_BITS
        te = self._TE_SHORT
        pulses = [-(te * 36), te]  # header + start bit
        for i in range(bit_count - 1, -1, -1):
            if (data >> i) & 1:
                pulses.extend([-(te * 2), te])
            else:
                pulses.extend([-te, te * 2])
        pulses.append(-(te * 4))
        return pulses


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

    def encode(self, data, bit_count=None):
        if bit_count is None:
            bit_count = self._MIN_BITS
        te_s = self._TE_SHORT
        te_l = self._TE_LONG
        pulses = [-(te_s * 47), te_l]  # header + long start bit
        for i in range(bit_count - 1, -1, -1):
            if (data >> i) & 1:
                pulses.extend([-(te_l), te_s])
            else:
                pulses.extend([-(te_s), te_l])
        pulses.append(-(te_s * 10))
        return pulses


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

    def encode(self, data, bit_count=None):
        if bit_count is None:
            bit_count = self._MIN_BITS
        te_s = self._TE_SHORT
        te_l = self._TE_LONG
        pulses = []
        for i in range(bit_count - 1, 0, -1):
            if (data >> (i - 1)) & 1:
                pulses.extend([te_l, -(te_s)])
            else:
                pulses.extend([te_s, -(te_l)])
        # Last bit with guard merged
        if data & 1:
            pulses.extend([te_l, -(te_s * 42)])
        else:
            pulses.extend([te_s, -(te_s * 44)])
        return pulses


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

    def encode(self, data, bit_count=None):
        if bit_count is None:
            bit_count = self._MIN_BITS
        te = self._TE_SHORT
        pulses = [-(te * 28), te]  # header + start bit
        for i in range(bit_count - 1, -1, -1):
            if (data >> i) & 1:
                pulses.extend([-(te * 2), te])
            else:
                pulses.extend([-te, te * 2])
        pulses.append(-(te * 10))
        return pulses


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

    def encode(self, data, bit_count=None):
        if bit_count is None:
            bit_count = self._MIN_BITS
        te = self._TE_SHORT
        # Chamberlain converts each data bit to a 4-bit nibble
        # BIT_0 = 0b0111, BIT_1 = 0b0011, STOP = 0b0001
        nibbles = []
        for i in range(bit_count - 1, -1, -1):
            if (data >> i) & 1:
                nibbles.extend([0, 0, 1, 1])  # BIT_1
            else:
                nibbles.extend([0, 1, 1, 1])  # BIT_0
        # Add check nibble and guard
        if bit_count == 9:
            check_bits = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]  # MASK_CHECK for 9-bit
        else:
            check_bits = [0, 0, 0, 1]  # STOP nibble
        nibbles.extend(check_bits)
        # Prepend 36 zeros as guard
        bit_array = [0] * 36 + nibbles
        # Convert bit array to OOK pulses (left-aligned)
        pulses = []
        i = 0
        while i < len(bit_array):
            # Count consecutive same-value bits
            val = bit_array[i]
            count = 0
            while i < len(bit_array) and bit_array[i] == val:
                count += 1
                i += 1
            dur = te * count
            if val:
                pulses.append(dur)
            else:
                pulses.append(-(dur))
        return pulses


# ===================================================================
# Manchester decoder — ported from manchester_decoder.c
# ===================================================================

_MANCHESTER_TRANSITIONS = [0b00000001, 0b10010001, 0b10011011, 0b11111011]
_MANCHESTER_RESET_STATE = 1  # ManchesterStateMid1

def _manchester_advance(state, event):
    if event == 8:  # Reset
        return _MANCHESTER_RESET_STATE, None
    new_state = (_MANCHESTER_TRANSITIONS[state] >> event) & 0x3
    if new_state == state:
        return _MANCHESTER_RESET_STATE, None
    if new_state == 2:  # Mid0
        return new_state, False
    if new_state == 1:  # Mid1
        return new_state, True
    return new_state, None


# ===================================================================
# Helper: CAME-style decoder (LOW saves, HIGH checks)
# Many protocols share this exact pattern: header LOW, start bit HIGH,
# then alternating LOW(save)+HIGH(check) pairs for bits.
# bit 0 = short_LOW + long_HIGH, bit 1 = long_LOW + short_HIGH
# ===================================================================

class _CAMEStyleDecoder:
    """CAME-style: LOW+HIGH pairs. SaveDuration saves LOW, CheckDuration checks HIGH."""
    name = "Unknown"
    _TE_SHORT = 320
    _TE_LONG = 640
    _TE_DELTA = 150
    _MIN_BITS = 12
    _HEADER_LOW_MULT = 56
    _HEADER_LOW_DELTA_MULT = 63
    _HAS_START_BIT = True
    _START_DUR = None
    _START_DELTA = None
    _FOOTER_MULT = 4
    _VALID_BITS = None
    _PROTO_TYPE = "Static"

    _RESET = 0; _FOUND_START = 1; _SAVE_DUR = 2; _CHECK_DUR = 3

    def __init__(self): self.reset()
    def reset(self):
        self._step = self._RESET; self._data = 0; self._bits = 0; self._te_last = 0

    def feed(self, level, duration):
        if self._step == self._RESET:
            if (not level) and DURATION_DIFF(duration, self._TE_SHORT * self._HEADER_LOW_MULT) < self._TE_DELTA * self._HEADER_LOW_DELTA_MULT:
                self._step = self._FOUND_START if self._HAS_START_BIT else self._SAVE_DUR
                self._data = 0; self._bits = 0
            return None
        if self._step == self._FOUND_START:
            if not level: return None
            sd = self._START_DUR or self._TE_SHORT
            sdd = self._START_DELTA or self._TE_DELTA
            if DURATION_DIFF(duration, sd) < sdd:
                self._step = self._SAVE_DUR; self._data = 0; self._bits = 0
            else: self._step = self._RESET
            return None
        if self._step == self._SAVE_DUR:
            if not level:
                if duration >= self._TE_SHORT * self._FOOTER_MULT:
                    self._step = self._FOUND_START if self._HAS_START_BIT else self._RESET
                    if self._valid_count(): return self._emit()
                    return None
                self._te_last = duration; self._step = self._CHECK_DUR
            else: self._step = self._RESET
            return None
        if self._step == self._CHECK_DUR:
            if level:
                if (DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA and
                        DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA):
                    self._data = (self._data << 1) | 0; self._bits += 1; self._step = self._SAVE_DUR
                elif (DURATION_DIFF(self._te_last, self._TE_LONG) < self._TE_DELTA and
                      DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA):
                    self._data = (self._data << 1) | 1; self._bits += 1; self._step = self._SAVE_DUR
                else: self._step = self._RESET
            else: self._step = self._RESET
            return None
        return None

    def _valid_count(self):
        if self._VALID_BITS: return self._bits in self._VALID_BITS
        return self._bits >= self._MIN_BITS

    def _emit(self):
        return DecodedSignal(protocol=self.name, data=self._data, bit_count=self._bits, proto_type=self._PROTO_TYPE)

    def encode(self, data, bit_count=None):
        if self._PROTO_TYPE != "Static":
            return None
        if bit_count is None:
            bit_count = self._MIN_BITS
        te_s = self._TE_SHORT
        te_l = self._TE_LONG
        pulses = [-(te_s * self._HEADER_LOW_MULT)]
        if self._HAS_START_BIT:
            sd = self._START_DUR or te_s
            pulses.append(sd)
        for i in range(bit_count - 1, -1, -1):
            if (data >> i) & 1:
                pulses.extend([-(te_l), te_s])
            else:
                pulses.extend([-(te_s), te_l])
        pulses.append(-(te_s * self._FOOTER_MULT))
        return pulses


# ===================================================================
# Helper: Princeton-style decoder (HIGH saves, LOW checks)
# header LOW, then alternating HIGH(save)+LOW(check) pairs.
# bit 0 = short_HIGH + long_LOW, bit 1 = long_HIGH + short_LOW
# ===================================================================

class _PrincetonStyleDecoder:
    name = "Unknown"
    _TE_SHORT = 400
    _TE_LONG = 800
    _TE_DELTA = 150
    _TE_DELTA_CHECK = None  # defaults to _TE_DELTA for check
    _MIN_BITS = 12
    _HEADER_LOW_MULT = 36
    _HEADER_LOW_DELTA_MULT = 20
    _FOOTER_MULT = 4
    _HAS_START_BIT = False
    _START_LEVEL_HIGH = True
    _START_DUR = None
    _VALID_BITS = None
    _NEED_TWO_FRAMES = False
    _PROTO_TYPE = "Static"

    _RESET = 0; _FOUND_START = 1; _SAVE_DUR = 2; _CHECK_DUR = 3

    def __init__(self): self.reset()
    def reset(self):
        self._step = self._RESET; self._data = 0; self._bits = 0
        self._te_last = 0; self._last_data = 0

    def feed(self, level, duration):
        td_c = self._TE_DELTA_CHECK or self._TE_DELTA
        if self._step == self._RESET:
            if (not level) and DURATION_DIFF(duration, self._TE_SHORT * self._HEADER_LOW_MULT) < self._TE_DELTA * self._HEADER_LOW_DELTA_MULT:
                self._step = self._FOUND_START if self._HAS_START_BIT else self._SAVE_DUR
                self._data = 0; self._bits = 0
            return None
        if self._step == self._FOUND_START:
            ok = (self._START_LEVEL_HIGH and level) or (not self._START_LEVEL_HIGH and not level)
            sd = self._START_DUR or self._TE_SHORT
            if ok and DURATION_DIFF(duration, sd) < self._TE_DELTA:
                self._step = self._SAVE_DUR; self._data = 0; self._bits = 0
            else:
                self._step = self._RESET
            return None
        if self._step == self._SAVE_DUR:
            if level:
                self._te_last = duration; self._step = self._CHECK_DUR
            else:
                self._step = self._RESET
            return None
        if self._step == self._CHECK_DUR:
            if not level:
                if duration >= self._TE_LONG * self._FOOTER_MULT:
                    self._step = self._SAVE_DUR if not self._HAS_START_BIT else self._FOUND_START
                    result = None
                    if self._valid_count():
                        if self._NEED_TWO_FRAMES:
                            if self._last_data == self._data and self._last_data:
                                result = self._emit()
                            self._last_data = self._data
                        else:
                            result = self._emit()
                    self._data = 0; self._bits = 0
                    return result
                if (DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA and
                        DURATION_DIFF(duration, self._TE_LONG) < td_c * 3):
                    self._data = (self._data << 1) | 0; self._bits += 1; self._step = self._SAVE_DUR
                elif (DURATION_DIFF(self._te_last, self._TE_LONG) < td_c * 3 and
                      DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA):
                    self._data = (self._data << 1) | 1; self._bits += 1; self._step = self._SAVE_DUR
                else:
                    self._step = self._RESET
            else:
                self._step = self._RESET
            return None
        return None

    def _valid_count(self):
        if self._VALID_BITS: return self._bits in self._VALID_BITS
        return self._bits >= self._MIN_BITS

    def _emit(self):
        return DecodedSignal(protocol=self.name, data=self._data, bit_count=self._bits, proto_type=self._PROTO_TYPE)

    def encode(self, data, bit_count=None):
        if self._PROTO_TYPE != "Static":
            return None
        if bit_count is None:
            bit_count = self._MIN_BITS
        te_s = self._TE_SHORT
        te_l = self._TE_LONG
        pulses = [-(te_s * self._HEADER_LOW_MULT)]  # guard/header LOW always
        if self._HAS_START_BIT:
            sd = self._START_DUR or te_s
            if self._START_LEVEL_HIGH:
                pulses.append(sd)
            else:
                pulses.append(-sd)
        for i in range(bit_count - 1, -1, -1):
            if (data >> i) & 1:
                pulses.extend([te_l, -(te_s)])
            else:
                pulses.extend([te_s, -(te_l)])
        pulses.append(-(te_s * self._HEADER_LOW_MULT))  # guard/footer LOW
        return pulses


# ===================================================================
# Static remotes — CAME-style (LOW+HIGH pairs)
# ===================================================================

class AnsonicDecoder(_CAMEStyleDecoder):
    name = "Ansonic"; _TE_SHORT = 555; _TE_LONG = 1111; _TE_DELTA = 120; _MIN_BITS = 12
    _HEADER_LOW_MULT = 35; _HEADER_LOW_DELTA_MULT = 35

class DitecGol4Decoder(_CAMEStyleDecoder):
    name = "Ditec GOL4"; _TE_SHORT = 400; _TE_LONG = 1100; _TE_DELTA = 200; _MIN_BITS = 54
    _HEADER_LOW_MULT = 37; _HEADER_LOW_DELTA_MULT = 37
    _PROTO_TYPE = "Rolling"

class DoitrandDecoder(_CAMEStyleDecoder):
    name = "Doitrand"; _TE_SHORT = 400; _TE_LONG = 1100; _TE_DELTA = 150; _MIN_BITS = 37
    _HEADER_LOW_MULT = 14; _HEADER_LOW_DELTA_MULT = 14
    def encode(self, data, bit_count=None):
        if bit_count is None: bit_count = self._MIN_BITS
        te_s, te_l = self._TE_SHORT, self._TE_LONG
        pulses = [-(te_s * 62), te_s * 2 - 100]  # header LOW + start HIGH
        for i in range(bit_count - 1, -1, -1):
            if (data >> i) & 1:
                pulses.extend([-(te_l), te_s])
            else:
                pulses.extend([-(te_s), te_l])
        return pulses

class HoltekDecoder(_CAMEStyleDecoder):
    name = "Holtek"; _TE_SHORT = 430; _TE_LONG = 870; _TE_DELTA = 100; _MIN_BITS = 40
    _HEADER_LOW_MULT = 36; _HEADER_LOW_DELTA_MULT = 36
    _HAS_START_BIT = False
    def encode(self, data, bit_count=None):
        if bit_count is None: bit_count = self._MIN_BITS
        te_s, te_l = self._TE_SHORT, self._TE_LONG
        pulses = [-(te_s * 36), te_s]  # header LOW + start HIGH
        for i in range(bit_count - 1, -1, -1):
            if (data >> i) & 1:
                pulses.extend([-(te_l), te_s])
            else:
                pulses.extend([-(te_s), te_l])
        return pulses

class IntertechnoV3Decoder(_CAMEStyleDecoder):
    name = "Intertechno V3"; _TE_SHORT = 275; _TE_LONG = 1375; _TE_DELTA = 150; _MIN_BITS = 32
    _HEADER_LOW_MULT = 37; _HEADER_LOW_DELTA_MULT = 15
    def encode(self, data, bit_count=None):
        if bit_count is None: bit_count = self._MIN_BITS
        te_s, te_l = self._TE_SHORT, self._TE_LONG
        pulses = [te_s, -(te_s * 38)]  # header
        pulses.extend([te_s, -(te_s * 10)])  # sync
        for i in range(bit_count - 1, -1, -1):
            if (data >> i) & 1:
                pulses.extend([te_s, -(te_l), te_s, -(te_s)])
            else:
                pulses.extend([te_s, -(te_s), te_s, -(te_l)])
        return pulses

class LegrandDecoder(_CAMEStyleDecoder):
    name = "Legrand"; _TE_SHORT = 375; _TE_LONG = 1125; _TE_DELTA = 150; _MIN_BITS = 18
    _HEADER_LOW_MULT = 30; _HEADER_LOW_DELTA_MULT = 30

class MegaCodeDecoder(_CAMEStyleDecoder):
    name = "MegaCode"; _TE_SHORT = 1000; _TE_LONG = 1000; _TE_DELTA = 200; _MIN_BITS = 24
    _HEADER_LOW_MULT = 10; _HEADER_LOW_DELTA_MULT = 10
    def encode(self, data, bit_count=None):
        if bit_count is None: bit_count = self._MIN_BITS
        te = self._TE_SHORT
        # MegaCode builds upload backwards: bit 1 = gap*5, bit 0 = gap*8
        # between same-value bits gap is shorter
        pairs = []
        last_bit = (data >> 0) & 1
        for i in range(1, bit_count):
            b = (data >> i) & 1
            if b:
                gap = te * 5 if last_bit else te * 2
            else:
                gap = te * 8 if last_bit else te * 5
            pairs.append((gap, b))
            last_bit = b
        # Build pulses forward (pairs were built backwards)
        pulses = []
        for gap, _ in reversed(pairs):
            pulses.extend([te, -(gap)])
        pulses.append(te)  # final HIGH
        return pulses

class PhoenixV2Decoder(_CAMEStyleDecoder):
    name = "Phoenix V2"; _TE_SHORT = 427; _TE_LONG = 853; _TE_DELTA = 100; _MIN_BITS = 52
    _HEADER_LOW_MULT = 72; _HEADER_LOW_DELTA_MULT = 72
    _PROTO_TYPE = "Rolling"

class CameTweeDecoder(_CAMEStyleDecoder):
    name = "CAME Twee"; _TE_SHORT = 500; _TE_LONG = 1000; _TE_DELTA = 250; _MIN_BITS = 54
    _HEADER_LOW_MULT = 60; _HEADER_LOW_DELTA_MULT = 60
    _PROTO_TYPE = "Rolling"


# ===================================================================
# Static remotes — Princeton-style (HIGH+LOW pairs)
# ===================================================================

class ClemsaDecoder(_PrincetonStyleDecoder):
    name = "Clemsa"; _TE_SHORT = 385; _TE_LONG = 2695; _TE_DELTA = 150; _MIN_BITS = 18
    _HEADER_LOW_MULT = 51; _HEADER_LOW_DELTA_MULT = 25
    def encode(self, data, bit_count=None):
        if bit_count is None: bit_count = self._MIN_BITS
        te_s, te_l = self._TE_SHORT, self._TE_LONG
        pulses = []
        for i in range(bit_count - 1, 0, -1):
            if (data >> (i-1)) & 1:
                pulses.extend([te_l, -(te_s)])
            else:
                pulses.extend([te_s, -(te_l)])
        if (data >> 0) & 1:
            pulses.append(te_l)
        else:
            pulses.append(te_s)
        pulses.append(-(te_s * 51))
        return pulses

class DooyaDecoder(_PrincetonStyleDecoder):
    name = "Dooya"; _TE_SHORT = 366; _TE_LONG = 733; _TE_DELTA = 120; _MIN_BITS = 40
    _HEADER_LOW_MULT = 24; _HEADER_LOW_DELTA_MULT = 20
    _HAS_START_BIT = True; _START_LEVEL_HIGH = True
    def encode(self, data, bit_count=None):
        if bit_count is None: bit_count = self._MIN_BITS
        te_l = self._TE_LONG
        te_s = self._TE_SHORT
        # Header LOW depends on first bit of data
        if (data >> 0) & 1:
            pulses = [-(te_l * 12 + te_l)]
        else:
            pulses = [-(te_l * 12 + te_s)]
        # Start bit
        pulses.extend([te_s * 13, -(te_l * 2)])
        # Send key data
        for i in range(bit_count - 1, -1, -1):
            if (data >> i) & 1:
                pulses.extend([te_l, -(te_s)])
            else:
                pulses.extend([te_s, -(te_l)])
        return pulses

class ElplastDecoder(_PrincetonStyleDecoder):
    name = "Elplast"; _TE_SHORT = 230; _TE_LONG = 1550; _TE_DELTA = 160; _MIN_BITS = 18
    _HEADER_LOW_MULT = 72; _HEADER_LOW_DELTA_MULT = 72
    def encode(self, data, bit_count=None):
        if bit_count is None: bit_count = self._MIN_BITS
        te_s, te_l = self._TE_SHORT, self._TE_LONG
        pulses = []
        for i in range(bit_count - 1, -1, -1):
            is_last = (i == 0)
            if (data >> i) & 1:
                pulses.append(te_l)
                pulses.append(-(te_l * 8) if is_last else -(te_s))
            else:
                pulses.append(te_s)
                pulses.append(-(te_l * 8) if is_last else -(te_l))
        return pulses

class FeronDecoder(_PrincetonStyleDecoder):
    name = "Feron"; _TE_SHORT = 350; _TE_LONG = 750; _TE_DELTA = 150; _MIN_BITS = 32
    _HEADER_LOW_MULT = 36; _HEADER_LOW_DELTA_MULT = 36
    def encode(self, data, bit_count=None):
        if bit_count is None: bit_count = self._MIN_BITS
        te_s, te_l = self._TE_SHORT, self._TE_LONG
        pulses = []
        for i in range(bit_count - 1, -1, -1):
            is_last = (i == 0)
            if (data >> i) & 1:
                pulses.append(te_l)
                if is_last:
                    pulses.extend([-(te_s + 150), te_s + 150, -(te_l * 6)])
                else:
                    pulses.append(-(te_s))
            else:
                pulses.append(te_s)
                if is_last:
                    pulses.extend([-(te_s + 150), te_s + 150, -(te_l * 6)])
                else:
                    pulses.append(-(te_l))
        return pulses

class GangQiDecoder(_PrincetonStyleDecoder):
    name = "GangQi"; _TE_SHORT = 500; _TE_LONG = 1200; _TE_DELTA = 200; _MIN_BITS = 34
    _HEADER_LOW_MULT = 10; _HEADER_LOW_DELTA_MULT = 10
    _HAS_START_BIT = True
    def encode(self, data, bit_count=None):
        if bit_count is None: bit_count = self._MIN_BITS
        te_s, te_l = self._TE_SHORT, self._TE_LONG
        pulses = []
        for i in range(bit_count - 1, -1, -1):
            is_last = (i == 0)
            if (data >> i) & 1:
                pulses.append(te_l)
                pulses.append(-(te_s * 4 + self._TE_DELTA) if is_last else -(te_s))
            else:
                pulses.append(te_s)
                pulses.append(-(te_s * 4 + self._TE_DELTA) if is_last else -(te_l))
        return pulses

class Hay21Decoder(_PrincetonStyleDecoder):
    name = "Hay21"; _TE_SHORT = 300; _TE_LONG = 700; _TE_DELTA = 150; _MIN_BITS = 21
    _HEADER_LOW_MULT = 35; _HEADER_LOW_DELTA_MULT = 35
    def encode(self, data, bit_count=None):
        if bit_count is None: bit_count = self._MIN_BITS
        te_s, te_l = self._TE_SHORT, self._TE_LONG
        pulses = []
        for i in range(bit_count - 1, -1, -1):
            is_last = (i == 0)
            if (data >> i) & 1:
                pulses.append(te_l)
                pulses.append(-(te_l * 6) if is_last else -(te_s))
            else:
                pulses.append(te_s)
                pulses.append(-(te_l * 6) if is_last else -(te_l))
        return pulses

class HollarmDecoder(_PrincetonStyleDecoder):
    name = "Hollarm"; _TE_SHORT = 200; _TE_LONG = 1000; _TE_DELTA = 200; _MIN_BITS = 42
    _HEADER_LOW_MULT = 56; _HEADER_LOW_DELTA_MULT = 56
    def encode(self, data, bit_count=None):
        if bit_count is None: bit_count = self._MIN_BITS
        te_s = self._TE_SHORT
        te_l = self._TE_LONG
        shifted = data << 2  # data is shifted left by 2 bits for encoding
        pulses = []
        for i in range(bit_count - 1, -1, -1):
            is_last = (i == 0)
            if (shifted >> i) & 1:
                pulses.append(te_s)
                pulses.append(-(te_s * 12) if is_last else -(te_s * 8))
            else:
                pulses.append(te_s)
                pulses.append(-(te_s * 12) if is_last else -(te_l))
        return pulses

class IDoDecoder(_PrincetonStyleDecoder):
    name = "iDo"; _TE_SHORT = 450; _TE_LONG = 1450; _TE_DELTA = 150; _MIN_BITS = 48
    _HEADER_LOW_MULT = 10; _HEADER_LOW_DELTA_MULT = 10
    def encode(self, data, bit_count=None):
        return None  # iDo has no Send flag in Momentum

class KeyfinderDecoder(_PrincetonStyleDecoder):
    name = "Keyfinder"; _TE_SHORT = 400; _TE_LONG = 1200; _TE_DELTA = 150; _MIN_BITS = 24
    _HEADER_LOW_MULT = 50; _HEADER_LOW_DELTA_MULT = 50
    def encode(self, data, bit_count=None):
        if bit_count is None: bit_count = 24
        te_s, te_l = self._TE_SHORT, self._TE_LONG
        pulses = []
        for i in range(bit_count - 1, -1, -1):
            if (data >> i) & 1:
                pulses.extend([te_s, -(te_l)])
            else:
                pulses.extend([te_l, -(te_s)])
        for _ in range(3):
            pulses.extend([te_s, -(te_s)])
        pulses.append(te_s)
        pulses.append(-(te_s * 10))  # gap
        return pulses

class LinearDelta3Decoder(_PrincetonStyleDecoder):
    name = "Linear Delta3"; _TE_SHORT = 500; _TE_LONG = 2000; _TE_DELTA = 150; _MIN_BITS = 8
    _HEADER_LOW_MULT = 16; _HEADER_LOW_DELTA_MULT = 16
    def encode(self, data, bit_count=None):
        if bit_count is None: bit_count = self._MIN_BITS
        te_s, te_l = self._TE_SHORT, self._TE_LONG
        pulses = []
        for i in range(bit_count - 1, 0, -1):
            if (data >> (i-1)) & 1:
                pulses.extend([te_s, -(te_s * 7)])
            else:
                pulses.extend([te_l, -(te_l)])
        if data & 1:
            pulses.extend([te_s, -(te_s * 73)])
        else:
            pulses.extend([te_l, -(te_s * 70)])
        return pulses

class MagellanDecoder(_PrincetonStyleDecoder):
    name = "Magellan"; _TE_SHORT = 200; _TE_LONG = 400; _TE_DELTA = 100; _MIN_BITS = 32
    _HEADER_LOW_MULT = 150; _HEADER_LOW_DELTA_MULT = 150
    def encode(self, data, bit_count=None):
        if bit_count is None: bit_count = self._MIN_BITS
        te_s, te_l = self._TE_SHORT, self._TE_LONG
        pulses = [te_s * 4, -(te_s)]  # header HIGH + LOW
        for _ in range(12):  # 12 toggle pairs (from C source)
            pulses.extend([te_s, -(te_s)])
        pulses.extend([te_s, -(te_l)])  # last toggle + long LOW
        pulses.extend([te_l * 3, -(te_l)])  # start marker
        for i in range(bit_count - 1, -1, -1):
            if (data >> i) & 1:
                pulses.extend([te_s, -(te_l)])
            else:
                pulses.extend([te_l, -(te_s)])
        pulses.extend([te_s, -(te_l * 100)])  # stop bit + long gap
        return pulses

class Marantec24Decoder(_PrincetonStyleDecoder):
    name = "Marantec 24"; _TE_SHORT = 800; _TE_LONG = 1600; _TE_DELTA = 200; _MIN_BITS = 24
    _HEADER_LOW_MULT = 6; _HEADER_LOW_DELTA_MULT = 6
    def encode(self, data, bit_count=None):
        if bit_count is None: bit_count = self._MIN_BITS
        te_s, te_l = self._TE_SHORT, self._TE_LONG
        pulses = []
        for i in range(bit_count - 1, -1, -1):
            is_last = (i == 0)
            if (data >> i) & 1:
                pulses.append(te_s)
                pulses.append(-(te_l * 9 + te_s) if is_last else -(te_l * 2))
            else:
                pulses.append(te_l)
                pulses.append(-(te_l * 9 + te_s) if is_last else -(te_s * 3))
        return pulses

class MastercodeDecoder(_PrincetonStyleDecoder):
    name = "Mastercode"; _TE_SHORT = 1072; _TE_LONG = 2145; _TE_DELTA = 150; _MIN_BITS = 36
    _HEADER_LOW_MULT = 15; _HEADER_LOW_DELTA_MULT = 15
    def encode(self, data, bit_count=None):
        if bit_count is None: bit_count = self._MIN_BITS
        te_s, te_l = self._TE_SHORT, self._TE_LONG
        pulses = []
        for i in range(bit_count - 1, 0, -1):
            if (data >> (i-1)) & 1:
                pulses.extend([te_l, -(te_s)])
            else:
                pulses.extend([te_s, -(te_l)])
        if data & 1:
            pulses.append(te_l)
        else:
            pulses.append(te_s)
        pulses.append(-(te_s * 15))
        return pulses

class NeroRadioDecoder(_PrincetonStyleDecoder):
    name = "Nero Radio"; _TE_SHORT = 200; _TE_LONG = 400; _TE_DELTA = 80; _MIN_BITS = 56
    _HEADER_LOW_MULT = 190; _HEADER_LOW_DELTA_MULT = 190
    _HAS_START_BIT = True
    def encode(self, data, bit_count=None):
        if bit_count is None: bit_count = self._MIN_BITS
        te_s = self._TE_SHORT
        te_l = self._TE_LONG
        pulses = []
        for _ in range(49):  # 49 toggle pairs (from C source)
            pulses.extend([te_s, -(te_s)])
        pulses.extend([830, -(te_s)])  # start bit
        for i in range(bit_count - 1, 0, -1):  # all bits except last
            if (data >> i) & 1:
                pulses.extend([te_l, -(te_s)])
            else:
                pulses.extend([te_s, -(te_l)])
        # Last bit with special gap
        if (data >> 0) & 1:
            pulses.extend([te_l, -(te_s * 23)])
        else:
            pulses.extend([te_s, -(te_s * 23)])
        return pulses

class NeroSketchDecoder(_PrincetonStyleDecoder):
    name = "Nero Sketch"; _TE_SHORT = 330; _TE_LONG = 660; _TE_DELTA = 150; _MIN_BITS = 40
    _HEADER_LOW_MULT = 115; _HEADER_LOW_DELTA_MULT = 115
    _HAS_START_BIT = True
    def encode(self, data, bit_count=None):
        if bit_count is None: bit_count = self._MIN_BITS
        te_s = self._TE_SHORT
        te_l = self._TE_LONG
        pulses = []
        for _ in range(47):  # 47 toggle pairs (from C source)
            pulses.extend([te_s, -(te_s)])
        pulses.extend([te_s * 4, -(te_s)])  # start bit
        for i in range(bit_count - 1, -1, -1):
            if (data >> i) & 1:
                pulses.extend([te_l, -(te_s)])
            else:
                pulses.extend([te_s, -(te_l)])
        pulses.extend([te_s * 3, -(te_s)])  # stop bit
        return pulses

class NordIceDecoder(_PrincetonStyleDecoder):
    name = "Nord Ice"; _TE_SHORT = 300; _TE_LONG = 800; _TE_DELTA = 150; _MIN_BITS = 33
    _HEADER_LOW_MULT = 30; _HEADER_LOW_DELTA_MULT = 30
    def encode(self, data, bit_count=None):
        if bit_count is None: bit_count = self._MIN_BITS
        te_s, te_l = self._TE_SHORT, self._TE_LONG
        pulses = []
        for i in range(bit_count - 1, -1, -1):
            is_last = (i == 0)
            if (data >> i) & 1:
                pulses.append(te_l)
                pulses.append(-(te_s * 25) if is_last else -(te_s))
            else:
                pulses.append(te_s)
                pulses.append(-(te_s * 25) if is_last else -(te_l))
        return pulses

class RogerDecoder(_PrincetonStyleDecoder):
    name = "Roger"; _TE_SHORT = 500; _TE_LONG = 1000; _TE_DELTA = 270; _MIN_BITS = 28
    _HEADER_LOW_MULT = 36; _HEADER_LOW_DELTA_MULT = 36

class SMC5326Decoder(_PrincetonStyleDecoder):
    name = "SMC5326"; _TE_SHORT = 300; _TE_LONG = 900; _TE_DELTA = 200; _MIN_BITS = 25
    _HEADER_LOW_MULT = 36; _HEADER_LOW_DELTA_MULT = 36
    def encode(self, data, bit_count=None):
        if bit_count is None: bit_count = self._MIN_BITS
        te = self._TE_SHORT  # SMC5326 uses dynamic TE
        pulses = []
        for i in range(bit_count - 1, -1, -1):
            if (data >> i) & 1:
                pulses.extend([te * 3, -(te)])
            else:
                pulses.extend([te, -(te * 3)])
        pulses.extend([te, -(te * 25)])  # end + gap
        return pulses

class Treadmill37Decoder(_PrincetonStyleDecoder):
    name = "Treadmill37"; _TE_SHORT = 300; _TE_LONG = 900; _TE_DELTA = 150; _MIN_BITS = 37
    _HEADER_LOW_MULT = 29; _HEADER_LOW_DELTA_MULT = 29
    def encode(self, data, bit_count=None):
        if bit_count is None: bit_count = self._MIN_BITS
        te_s, te_l = self._TE_SHORT, self._TE_LONG
        pulses = []
        for i in range(bit_count - 1, -1, -1):
            is_last = (i == 0)
            if (data >> i) & 1:
                pulses.append(te_l)
                pulses.append(-(te_s * 20) if is_last else -(te_s))
            else:
                pulses.append(te_s)
                pulses.append(-(te_s * 20) if is_last else -(te_l))
        return pulses

class AllstarFireflyDecoder(_PrincetonStyleDecoder):
    name = "Allstar Firefly"; _TE_SHORT = 600; _TE_LONG = 4000; _TE_DELTA = 300; _MIN_BITS = 18
    _HEADER_LOW_MULT = 8; _HEADER_LOW_DELTA_MULT = 8
    def encode(self, data, bit_count=None):
        if bit_count is None: bit_count = self._MIN_BITS
        te_s, te_l = self._TE_SHORT, self._TE_LONG
        pulses = []
        for i in range(bit_count - 1, -1, -1):
            is_last = (i == 0)
            if (data >> i) & 1:
                pulses.append(te_l)
                pulses.append(-(te_s * 50 + 400) if is_last else -(te_s))
            else:
                pulses.append(te_s)
                pulses.append(-(te_s * 50 + 400) if is_last else -(te_l))
        return pulses

class DickertMAHSDecoder(_PrincetonStyleDecoder):
    name = "Dickert MAHS"; _TE_SHORT = 400; _TE_LONG = 800; _TE_DELTA = 100; _MIN_BITS = 36
    _HEADER_LOW_MULT = 50; _HEADER_LOW_DELTA_MULT = 50
    def encode(self, data, bit_count=None):
        # Dickert MAHS is CAME-style: LOW header, HIGH start, LOW+HIGH data
        if bit_count is None: bit_count = self._MIN_BITS
        te_s, te_l = self._TE_SHORT, self._TE_LONG
        pulses = [-(te_s * 112)]  # header LOW
        pulses.append(te_s)  # start bit HIGH
        for i in range(bit_count - 1, -1, -1):
            if (data >> i) & 1:
                pulses.extend([-(te_l), te_s])
            else:
                pulses.extend([-(te_s), te_l])
        return pulses

class VaunoEN8822CDecoder(_PrincetonStyleDecoder):
    name = "Vauno EN8822C"; _TE_SHORT = 500; _TE_LONG = 1000; _TE_DELTA = 200; _MIN_BITS = 32
    _HEADER_LOW_MULT = 30; _HEADER_LOW_DELTA_MULT = 30
    _PROTO_TYPE = "Weather"

class EmosE601xDecoder(_PrincetonStyleDecoder):
    name = "Emos E601x"; _TE_SHORT = 500; _TE_LONG = 2000; _TE_DELTA = 200; _MIN_BITS = 36
    _HEADER_LOW_MULT = 16; _HEADER_LOW_DELTA_MULT = 16
    _PROTO_TYPE = "Weather"

class X10Decoder(_PrincetonStyleDecoder):
    name = "X10"; _TE_SHORT = 600; _TE_LONG = 1800; _TE_DELTA = 100; _MIN_BITS = 32
    _HEADER_LOW_MULT = 16; _HEADER_LOW_DELTA_MULT = 16
    def encode(self, data, bit_count=None):
        return None  # X10 has no Send flag in Momentum


# ===================================================================
# Hörmann — Princeton-style with HIGH header instead of LOW
# te_short=500, te_long=1000, te_delta=200, min_bits=44
# ===================================================================

class HormannDecoder:
    name = "Hormann"
    _TE_SHORT = 500; _TE_LONG = 1000; _TE_DELTA = 200; _MIN_BITS = 44
    _RESET = 0; _FOUND_START = 1; _SAVE_DUR = 2; _CHECK_DUR = 3

    def __init__(self): self.reset()
    def reset(self):
        self._step = self._RESET; self._data = 0; self._bits = 0; self._te_last = 0

    def feed(self, level, duration):
        if self._step == self._RESET:
            if level and DURATION_DIFF(duration, self._TE_SHORT * 24) < self._TE_DELTA * 24:
                self._step = self._FOUND_START
            return None
        if self._step == self._FOUND_START:
            if (not level) and DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA:
                self._step = self._SAVE_DUR; self._data = 0; self._bits = 0
            else:
                self._step = self._RESET
            return None
        if self._step == self._SAVE_DUR:
            if level:
                if duration >= self._TE_SHORT * 5:
                    self._step = self._FOUND_START
                    if self._bits >= self._MIN_BITS:
                        return DecodedSignal(protocol=self.name, data=self._data, bit_count=self._bits, proto_type="Static")
                    return None
                self._te_last = duration; self._step = self._CHECK_DUR
            else:
                self._step = self._RESET
            return None
        if self._step == self._CHECK_DUR:
            if not level:
                if (DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA and
                        DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA):
                    self._data = (self._data << 1) | 0; self._bits += 1; self._step = self._SAVE_DUR
                elif (DURATION_DIFF(self._te_last, self._TE_LONG) < self._TE_DELTA and
                      DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA):
                    self._data = (self._data << 1) | 1; self._bits += 1; self._step = self._SAVE_DUR
                else:
                    self._step = self._RESET
            else:
                self._step = self._RESET
            return None
        return None

    def encode(self, data, bit_count=None):
        if bit_count is None:
            bit_count = self._MIN_BITS
        te_s = self._TE_SHORT
        te_l = self._TE_LONG
        pulses = []
        for _ in range(20):  # Hormann needs 20 internal repeats
            pulses.extend([te_s * 24, -(te_s)])  # HIGH header + LOW
            for i in range(bit_count - 1, -1, -1):
                if (data >> i) & 1:
                    pulses.extend([te_l, -(te_s)])
                else:
                    pulses.extend([te_s, -(te_l)])
        pulses.append(te_s * 24)  # final HIGH
        return pulses


# ===================================================================
# BETT — unique pattern: header LOW, then CheckDuration(HIGH) first,
# SaveDuration(LOW) second. No start bit.
# te_short=340, te_long=2000, te_delta=150, min_bits=18
# ===================================================================

class BETTDecoder:
    name = "BETT"
    _TE_SHORT = 340; _TE_LONG = 2000; _TE_DELTA = 150; _MIN_BITS = 18
    _RESET = 0; _SAVE_DUR = 1; _CHECK_DUR = 2

    def __init__(self): self.reset()
    def reset(self):
        self._step = self._RESET; self._data = 0; self._bits = 0

    def feed(self, level, duration):
        if self._step == self._RESET:
            if (not level) and DURATION_DIFF(duration, self._TE_SHORT * 44) < self._TE_DELTA * 15:
                self._data = 0; self._bits = 0; self._step = self._CHECK_DUR
            return None
        if self._step == self._SAVE_DUR:
            if not level:
                if DURATION_DIFF(duration, self._TE_SHORT * 44) < self._TE_DELTA * 15:
                    if self._bits == self._MIN_BITS:
                        sig = DecodedSignal(protocol=self.name, data=self._data, bit_count=self._bits)
                        self._data = 0; self._bits = 0
                        return sig
                    self._step = self._RESET; self._data = 0; self._bits = 0
                    return None
                if (DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA or
                        DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA * 3):
                    self._step = self._CHECK_DUR
                else:
                    self._step = self._RESET
            return None
        if self._step == self._CHECK_DUR:
            if level:
                if DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA * 3:
                    self._data = (self._data << 1) | 1; self._bits += 1; self._step = self._SAVE_DUR
                elif DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA:
                    self._data = (self._data << 1) | 0; self._bits += 1; self._step = self._SAVE_DUR
                else:
                    self._step = self._RESET
            else:
                self._step = self._RESET
            return None
        return None

    def encode(self, data, bit_count=None):
        if bit_count is None:
            bit_count = self._MIN_BITS
        te_s = self._TE_SHORT
        te_l = self._TE_LONG
        pulses = []
        for i in range(bit_count - 1, 0, -1):
            if (data >> (i - 1)) & 1:
                pulses.extend([te_l, -(te_s)])
            else:
                pulses.extend([te_s, -(te_l)])
        # Last bit with guard merged
        if data & 1:
            pulses.extend([te_l, -(te_s + te_l * 7)])
        else:
            pulses.extend([te_s, -(te_l + te_l * 7)])
        return pulses


# ===================================================================
# KeeLoq — rolling code, Princeton-style with preamble counter
# te_short=400, te_long=800, te_delta=180, min_bits=64
# ===================================================================

class KeeLoqDecoder:
    name = "KeeLoq"
    _TE_SHORT = 400; _TE_LONG = 800; _TE_DELTA = 180; _MIN_BITS = 64
    _RESET = 0; _CHECK_PREAMBLE = 1; _SAVE_DUR = 2; _CHECK_DUR = 3

    def __init__(self): self.reset()
    def reset(self):
        self._step = self._RESET; self._data = 0; self._bits = 0
        self._te_last = 0; self._header_count = 0; self._last_data = 0

    def feed(self, level, duration):
        if self._step == self._RESET:
            if level and DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA:
                self._step = self._CHECK_PREAMBLE; self._header_count += 1
            return None
        if self._step == self._CHECK_PREAMBLE:
            if (not level) and DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA:
                self._step = self._RESET; return None
            if self._header_count > 2 and DURATION_DIFF(duration, self._TE_SHORT * 10) < self._TE_DELTA * 10:
                self._step = self._SAVE_DUR; self._data = 0; self._bits = 0
            else:
                self._step = self._RESET; self._header_count = 0
            return None
        if self._step == self._SAVE_DUR:
            if level:
                self._te_last = duration; self._step = self._CHECK_DUR
            return None
        if self._step == self._CHECK_DUR:
            if not level:
                if duration >= self._TE_SHORT * 2 + self._TE_DELTA:
                    self._step = self._RESET
                    if self._MIN_BITS <= self._bits <= self._MIN_BITS + 2:
                        if self._last_data != self._data:
                            self._last_data = self._data
                            sig = DecodedSignal(protocol=self.name, data=self._data,
                                                bit_count=self._MIN_BITS, proto_type="Rolling")
                            sig.serial = int((self._data >> 0) & 0xFFFFFFFF)
                            sig.cnt = int((self._data >> 32) & 0xFFFFFFFF)
                            self._data = 0; self._bits = 0; self._header_count = 0
                            return sig
                    self._data = 0; self._bits = 0; self._header_count = 0
                    return None
                if (DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA and
                        DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA * 2):
                    self._data = (self._data << 1) | 1; self._bits += 1; self._step = self._SAVE_DUR
                elif (DURATION_DIFF(self._te_last, self._TE_LONG) < self._TE_DELTA * 2 and
                      DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA):
                    self._data = (self._data << 1) | 0; self._bits += 1; self._step = self._SAVE_DUR
                else:
                    self._step = self._RESET; self._header_count = 0
            else:
                self._step = self._RESET; self._header_count = 0
            return None
        return None


# ===================================================================
# Nice Flor-S — rolling code with 3-part header
# te_short=500, te_long=1000, te_delta=300, min_bits=52
# ===================================================================

class NiceFlorSDecoder:
    name = "Nice Flor-S"
    _TE_SHORT = 500; _TE_LONG = 1000; _TE_DELTA = 300; _MIN_BITS = 52
    _RESET = 0; _CHECK_HEADER = 1; _FOUND_HEADER = 2; _SAVE_DUR = 3; _CHECK_DUR = 4

    def __init__(self): self.reset()
    def reset(self):
        self._step = self._RESET; self._data = 0; self._bits = 0; self._te_last = 0

    def feed(self, level, duration):
        if self._step == self._RESET:
            if (not level) and DURATION_DIFF(duration, self._TE_SHORT * 38) < self._TE_DELTA * 38:
                self._step = self._CHECK_HEADER
            return None
        if self._step == self._CHECK_HEADER:
            if level and DURATION_DIFF(duration, self._TE_SHORT * 3) < self._TE_DELTA * 3:
                self._step = self._FOUND_HEADER
            else:
                self._step = self._RESET
            return None
        if self._step == self._FOUND_HEADER:
            if (not level) and DURATION_DIFF(duration, self._TE_SHORT * 3) < self._TE_DELTA * 3:
                self._step = self._SAVE_DUR; self._data = 0; self._bits = 0
            else:
                self._step = self._RESET
            return None
        if self._step == self._SAVE_DUR:
            if level:
                if DURATION_DIFF(duration, self._TE_SHORT * 3) < self._TE_DELTA:
                    self._step = self._RESET
                    if self._bits >= self._MIN_BITS:
                        return DecodedSignal(protocol=self.name, data=self._data,
                                            bit_count=self._bits, proto_type="Rolling")
                    return None
                self._te_last = duration; self._step = self._CHECK_DUR
            return None
        if self._step == self._CHECK_DUR:
            if not level:
                if (DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA and
                        DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA):
                    self._data = (self._data << 1) | 0; self._bits += 1; self._step = self._SAVE_DUR
                elif (DURATION_DIFF(self._te_last, self._TE_LONG) < self._TE_DELTA and
                      DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA):
                    self._data = (self._data << 1) | 1; self._bits += 1; self._step = self._SAVE_DUR
                else:
                    self._step = self._RESET
            else:
                self._step = self._RESET
            return None
        return None


# ===================================================================
# CAME Atomo — Manchester encoding rolling code
# te_short=600, te_long=1200, te_delta=250, min_bits=62
# ===================================================================

class CameAtomoDecoder:
    name = "CAME Atomo"
    _TE_SHORT = 600; _TE_LONG = 1200; _TE_DELTA = 250; _MIN_BITS = 62
    _RESET = 0; _DATA = 1

    def __init__(self): self.reset()
    def reset(self):
        self._step = self._RESET; self._data = 0; self._bits = 0; self._man_state = _MANCHESTER_RESET_STATE

    def feed(self, level, duration):
        if self._step == self._RESET:
            if (not level) and (
                DURATION_DIFF(duration, self._TE_LONG * 10) < self._TE_DELTA * 20 or
                DURATION_DIFF(duration, self._TE_LONG * 16) < self._TE_DELTA * 10 or
                DURATION_DIFF(duration, self._TE_LONG * 60) < self._TE_DELTA * 40):
                self._step = self._DATA; self._data = 0; self._bits = 1
                self._man_state, _ = _manchester_advance(self._man_state, 8)  # reset
                self._man_state, _ = _manchester_advance(self._man_state, 0)  # ShortLow
            return None
        if self._step == self._DATA:
            event = 8  # Reset
            if not level:
                if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA:
                    event = 0  # ShortLow
                elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA:
                    event = 4  # LongLow
                elif duration >= self._TE_LONG * 2 + self._TE_DELTA:
                    if self._bits == self._MIN_BITS:
                        sig = DecodedSignal(protocol=self.name, data=self._data,
                                            bit_count=self._bits, proto_type="Rolling")
                        self._step = self._RESET
                        return sig
                    self._data = 0; self._bits = 1
                    self._man_state, _ = _manchester_advance(self._man_state, 8)
                    self._man_state, _ = _manchester_advance(self._man_state, 0)
                    return None
                else:
                    self._step = self._RESET; return None
            else:
                if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA:
                    event = 2  # ShortHigh
                elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA:
                    event = 6  # LongHigh
                else:
                    self._step = self._RESET; return None
            if event != 8:
                self._man_state, bit_val = _manchester_advance(self._man_state, event)
                if bit_val is not None:
                    self._data = (self._data << 1) | (0 if bit_val else 1)
                    self._bits += 1
            return None
        return None


# ===================================================================
# Honeywell — Manchester encoding
# te_short=143, te_long=280, te_delta=51, min_bits=64
# ===================================================================

class HoneywellDecoder:
    name = "Honeywell"
    _TE_SHORT = 143; _TE_LONG = 280; _TE_DELTA = 51; _MIN_BITS = 62
    def __init__(self): self.reset()
    def reset(self):
        self._data = 0; self._bits = 0; self._man_state = _MANCHESTER_RESET_STATE

    def feed(self, level, duration):
        event = 8
        if not level:
            if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA:
                event = 0
            elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA * 2:
                event = 4
        else:
            if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA:
                event = 2
            elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA * 2:
                event = 6
        if event != 8:
            self._man_state, bit_val = _manchester_advance(self._man_state, event)
            if bit_val is not None:
                self._data = (self._data << 1) | (1 if bit_val else 0)
                self._bits += 1
                if self._bits >= self._MIN_BITS:
                    preamble = (self._data >> 48) & 0xFFFF
                    if preamble in (0x3FFE, 0x7FFE, 0xFFFE):
                        sig = DecodedSignal(protocol=self.name, data=self._data,
                                            bit_count=self._bits, proto_type="Static")
                        self._data = 0; self._bits = 0
                        return sig
        else:
            self._data = 0; self._bits = 0
        return None


class HoneywellWDBDecoder:
    name = "Honeywell WDB"
    _TE_SHORT = 160; _TE_LONG = 320; _TE_DELTA = 60; _MIN_BITS = 48
    def __init__(self): self.reset()
    def reset(self):
        self._data = 0; self._bits = 0; self._man_state = _MANCHESTER_RESET_STATE

    def feed(self, level, duration):
        event = 8
        if not level:
            if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA: event = 0
            elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA * 2: event = 4
        else:
            if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA: event = 2
            elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA * 2: event = 6
        if event != 8:
            self._man_state, bit_val = _manchester_advance(self._man_state, event)
            if bit_val is not None:
                self._data = (self._data << 1) | (1 if bit_val else 0)
                self._bits += 1
                if self._bits >= self._MIN_BITS:
                    sig = DecodedSignal(protocol=self.name, data=self._data, bit_count=self._bits, proto_type="Static")
                    self._data = 0; self._bits = 0
                    return sig
        else:
            self._data = 0; self._bits = 0
        return None


# ===================================================================
# FAAC SLH — rolling code, CAME-style
# te_short=255, te_long=595, te_delta=100, min_bits=64
# ===================================================================

class FaacSLHDecoder(_CAMEStyleDecoder):
    name = "Faac SLH"; _TE_SHORT = 255; _TE_LONG = 595; _TE_DELTA = 100; _MIN_BITS = 64
    _HEADER_LOW_MULT = 36; _HEADER_LOW_DELTA_MULT = 36; _PROTO_TYPE = "Rolling"

class AlutechAT4NDecoder(_PrincetonStyleDecoder):
    name = "Alutech AT-4N"; _TE_SHORT = 400; _TE_LONG = 800; _TE_DELTA = 140; _MIN_BITS = 72
    _HEADER_LOW_MULT = 70; _HEADER_LOW_DELTA_MULT = 70; _PROTO_TYPE = "Rolling"

class JaroliftDecoder(_PrincetonStyleDecoder):
    name = "Jarolift"; _TE_SHORT = 400; _TE_LONG = 800; _TE_DELTA = 167; _MIN_BITS = 72
    _HEADER_LOW_MULT = 70; _HEADER_LOW_DELTA_MULT = 70; _PROTO_TYPE = "Rolling"

class KingGatesStylo4KDecoder(_PrincetonStyleDecoder):
    name = "KingGates Stylo4K"; _TE_SHORT = 400; _TE_LONG = 1100; _TE_DELTA = 140; _MIN_BITS = 89
    _HEADER_LOW_MULT = 30; _HEADER_LOW_DELTA_MULT = 30; _PROTO_TYPE = "Rolling"

class BenincaARCDecoder(_PrincetonStyleDecoder):
    name = "Beninca ARC"; _TE_SHORT = 300; _TE_LONG = 600; _TE_DELTA = 155; _MIN_BITS = 128
    _HEADER_LOW_MULT = 40; _HEADER_LOW_DELTA_MULT = 40; _PROTO_TYPE = "Rolling"


# ===================================================================
# Somfy Telis — Manchester with preamble counter
# te_short=640, te_long=1280, te_delta=250, min_bits=56
# ===================================================================

class SomfyTelisDecoder:
    name = "Somfy Telis"
    _TE_SHORT = 640; _TE_LONG = 1280; _TE_DELTA = 250; _MIN_BITS = 56
    _RESET = 0; _PREAMBLE = 1; _CHECK_PREAMBLE = 2; _DATA = 3

    def __init__(self): self.reset()
    def reset(self):
        self._step = self._RESET; self._data = 0; self._bits = 0
        self._header_count = 0; self._man_state = _MANCHESTER_RESET_STATE

    def feed(self, level, duration):
        if self._step == self._RESET:
            if level and DURATION_DIFF(duration, self._TE_SHORT * 4) < self._TE_DELTA * 4:
                self._step = self._PREAMBLE; self._header_count += 1
            return None
        if self._step == self._PREAMBLE:
            if (not level) and DURATION_DIFF(duration, self._TE_SHORT * 4) < self._TE_DELTA * 4:
                self._step = self._CHECK_PREAMBLE
            else:
                self._header_count = 0; self._step = self._RESET
            return None
        if self._step == self._CHECK_PREAMBLE:
            if level:
                if DURATION_DIFF(duration, self._TE_SHORT * 4) < self._TE_DELTA * 4:
                    self._step = self._PREAMBLE; self._header_count += 1
                elif self._header_count > 1 and DURATION_DIFF(duration, self._TE_SHORT * 7) < self._TE_DELTA * 4:
                    self._step = self._DATA; self._data = 0; self._bits = 0; self._header_count = 0
                    self._man_state, _ = _manchester_advance(_MANCHESTER_RESET_STATE, 8)
                    self._man_state, _ = _manchester_advance(self._man_state, 6)
                else:
                    self._step = self._RESET; self._header_count = 0
            return None
        if self._step == self._DATA:
            event = 8
            if not level:
                if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA: event = 0
                elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA: event = 4
                elif duration >= self._TE_LONG * 2 + self._TE_DELTA:
                    self._step = self._RESET
                    if self._bits >= self._MIN_BITS:
                        return DecodedSignal(protocol=self.name, data=self._data,
                                            bit_count=self._bits, proto_type="Rolling")
                    return None
                else:
                    self._step = self._RESET; return None
            else:
                if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA: event = 2
                elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA: event = 6
                else:
                    self._step = self._RESET; return None
            if event != 8:
                self._man_state, bit_val = _manchester_advance(self._man_state, event)
                if bit_val is not None:
                    self._data = (self._data << 1) | (1 if bit_val else 0)
                    self._bits += 1
            return None
        return None


class SomfyKeytisDecoder(SomfyTelisDecoder):
    name = "Somfy Keytis"
    _MIN_BITS = 80


# ===================================================================
# Weather: Nexus TH — HIGH+LOW pairs, te_short=490, te_long=1980
# bit 0 = short_HIGH + 2x_short_LOW, bit 1 = short_HIGH + 4x_short_LOW
# ===================================================================

class NexusTHDecoder:
    name = "Nexus-TH"
    _TE_SHORT = 490; _TE_LONG = 1980; _TE_DELTA = 150; _MIN_BITS = 36
    _RESET = 0; _SAVE_DUR = 1; _CHECK_DUR = 2

    def __init__(self): self.reset()
    def reset(self):
        self._step = self._RESET; self._data = 0; self._bits = 0; self._te_last = 0

    def feed(self, level, duration):
        if self._step == self._RESET:
            if (not level) and DURATION_DIFF(duration, self._TE_SHORT * 8) < self._TE_DELTA * 4:
                self._step = self._SAVE_DUR; self._data = 0; self._bits = 0
            return None
        if self._step == self._SAVE_DUR:
            if level:
                self._te_last = duration; self._step = self._CHECK_DUR
            else:
                self._step = self._RESET
            return None
        if self._step == self._CHECK_DUR:
            if not level:
                if DURATION_DIFF(duration, self._TE_SHORT * 8) < self._TE_DELTA * 4:
                    self._step = self._RESET
                    if self._bits == self._MIN_BITS:
                        sig = DecodedSignal(protocol=self.name, data=self._data,
                                            bit_count=self._bits, proto_type="Weather")
                        self._parse_weather(sig)
                        return sig
                    self._data = 0; self._bits = 0
                    return None
                if (DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA and
                        DURATION_DIFF(duration, self._TE_SHORT * 2) < self._TE_DELTA * 2):
                    self._data = (self._data << 1) | 0; self._bits += 1; self._step = self._SAVE_DUR
                elif (DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA and
                      DURATION_DIFF(duration, self._TE_SHORT * 4) < self._TE_DELTA * 4):
                    self._data = (self._data << 1) | 1; self._bits += 1; self._step = self._SAVE_DUR
                else:
                    self._step = self._RESET
            else:
                self._step = self._RESET
            return None
        return None

    def _parse_weather(self, sig):
        d = sig.data
        sig.extra["id"] = (d >> 28) & 0xFF
        sig.extra["channel"] = ((d >> 24) & 0x03) + 1
        sig.extra["battery"] = "OK" if not ((d >> 27) & 1) else "Low"
        temp_raw = (d >> 12) & 0xFFF
        if temp_raw & 0x800: temp_raw -= 0x1000
        sig.extra["temp_c"] = temp_raw / 10.0
        sig.extra["humidity"] = d & 0xFF


# ===================================================================
# Weather: Acurite 606TX
# te_short=500, te_long=2000, te_delta=150, min_bits=32
# ===================================================================

class Acurite606TXDecoder(NexusTHDecoder):
    name = "Acurite 606TX"
    _TE_SHORT = 500; _TE_LONG = 2000; _TE_DELTA = 150; _MIN_BITS = 32

    def _parse_weather(self, sig):
        d = sig.data
        sig.extra["id"] = (d >> 24) & 0xFF
        sig.extra["battery"] = "OK" if not ((d >> 23) & 1) else "Low"
        temp_raw = (d >> 12) & 0x7FF
        if temp_raw & 0x400: temp_raw -= 0x800
        sig.extra["temp_c"] = temp_raw / 10.0


# ===================================================================
# Weather: ThermoPro TX4
# te_short=500, te_long=2000, te_delta=150, min_bits=37
# ===================================================================

class ThermoProTX4Decoder(NexusTHDecoder):
    name = "ThermoPro TX4"
    _TE_SHORT = 500; _TE_LONG = 2000; _TE_DELTA = 150; _MIN_BITS = 37

    def _parse_weather(self, sig):
        d = sig.data
        sig.extra["id"] = (d >> 29) & 0xFF
        sig.extra["channel"] = ((d >> 25) & 0x03) + 1
        sig.extra["battery"] = "OK" if not ((d >> 24) & 1) else "Low"
        temp_raw = (d >> 12) & 0xFFF
        if temp_raw & 0x800: temp_raw -= 0x1000
        sig.extra["temp_c"] = temp_raw / 10.0
        sig.extra["humidity"] = d & 0xFF


# ===================================================================
# Weather: LaCrosse TX141THBv2 — Manchester encoding
# te_short=208, te_long=417, te_delta=120, min_bits=40
# ===================================================================

class LaCrosseTX141Decoder:
    name = "LaCrosse TX141"
    _TE_SHORT = 208; _TE_LONG = 417; _TE_DELTA = 120; _MIN_BITS = 40
    _RESET = 0; _DATA = 1

    def __init__(self): self.reset()
    def reset(self):
        self._step = self._RESET; self._data = 0; self._bits = 0
        self._te_last = 0; self._man_state = _MANCHESTER_RESET_STATE

    def feed(self, level, duration):
        if self._step == self._RESET:
            if level and DURATION_DIFF(duration, self._TE_LONG * 4) < self._TE_DELTA * 4:
                self._step = self._DATA; self._data = 0; self._bits = 0
                self._man_state, _ = _manchester_advance(_MANCHESTER_RESET_STATE, 8)
            return None
        if self._step == self._DATA:
            event = 8
            if not level:
                if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA: event = 0
                elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA: event = 4
                elif duration >= self._TE_LONG * 3:
                    self._step = self._RESET
                    if self._bits >= self._MIN_BITS:
                        sig = DecodedSignal(protocol=self.name, data=self._data,
                                            bit_count=self._bits, proto_type="Weather")
                        return sig
                    return None
                else:
                    self._step = self._RESET; return None
            else:
                if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA: event = 2
                elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA: event = 6
                else:
                    self._step = self._RESET; return None
            if event != 8:
                self._man_state, bit_val = _manchester_advance(self._man_state, event)
                if bit_val is not None:
                    self._data = (self._data << 1) | (1 if bit_val else 0)
                    self._bits += 1
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


# ===================================================================
# Manchester helper (reusable state machine)
# Events: 0=ShortLow, 1=ShortHigh, 2=LongLow, 3=LongHigh
# Returns: (new_state, decoded_bit) or (None, None) on reset
# ===================================================================

_MANCHESTER_TABLE = [
    [(1, None), (2, None), (None, None), (None, None)],
    [(None, None), (0, 0), (None, None), (0, 1)],
    [(0, 1), (None, None), (0, 0), (None, None)],
]

def _manchester_advance(state, event):
    if state is None or state >= len(_MANCHESTER_TABLE) or event >= 4:
        return None, None
    return _MANCHESTER_TABLE[state][event]


# ===================================================================
# GT-WT-02 — te_short=500, te_long=2000, te_delta=150, min_bits=37
# ===================================================================
class GTWT02Decoder:
    name = "GT-WT-02"
    _TE_SHORT = 500; _TE_LONG = 2000; _TE_DELTA = 150; _MIN_BITS = 37
    _RESET = 0; _SAVE = 1; _CHECK = 2
    def __init__(self): self.reset()
    def reset(self): self._step = self._RESET; self._data = 0; self._bits = 0; self._te_last = 0
    def _add_bit(self, b): self._data = (self._data << 1) | b; self._bits += 1
    def feed(self, level, duration):
        if self._step == self._RESET:
            if (not level) and DURATION_DIFF(duration, self._TE_SHORT * 18) < self._TE_DELTA * 8:
                self._step = self._SAVE; self._data = 0; self._bits = 0
            return None
        if self._step == self._SAVE:
            if level: self._te_last = duration; self._step = self._CHECK
            else: self._step = self._RESET
            return None
        if self._step == self._CHECK:
            if not level:
                if DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA:
                    if DURATION_DIFF(duration, self._TE_SHORT * 18) < self._TE_DELTA * 8:
                        self._step = self._RESET
                        if self._bits == self._MIN_BITS:
                            return DecodedSignal(protocol=self.name, data=self._data, bit_count=self._bits, proto_type="Weather")
                        self._data = 0; self._bits = 0; return None
                    elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA * 2:
                        self._add_bit(0); self._step = self._SAVE
                    elif DURATION_DIFF(duration, self._TE_LONG * 2) < self._TE_DELTA * 4:
                        self._add_bit(1); self._step = self._SAVE
                    else: self._step = self._RESET
                else: self._step = self._RESET
            else: self._step = self._RESET
            return None
        return None

class GTWT03Decoder:
    name = "GT-WT-03"
    _TE_SHORT = 285; _TE_LONG = 570; _TE_DELTA = 120; _MIN_BITS = 41
    _RESET = 0; _PRE = 1; _SAVE = 2; _CHECK = 3
    def __init__(self): self.reset()
    def reset(self): self._step = self._RESET; self._data = 0; self._bits = 0; self._te_last = 0; self._hdr = 0
    def _add_bit(self, b): self._data = (self._data << 1) | b; self._bits += 1
    def feed(self, level, duration):
        if self._step == self._RESET:
            if level and DURATION_DIFF(duration, self._TE_SHORT * 3) < self._TE_DELTA * 2:
                self._step = self._PRE; self._te_last = duration; self._hdr = 0
            return None
        if self._step == self._PRE:
            if level: self._te_last = duration
            else:
                if (DURATION_DIFF(self._te_last, self._TE_SHORT * 3) < self._TE_DELTA * 2 and
                    DURATION_DIFF(duration, self._TE_SHORT * 3) < self._TE_DELTA * 2): self._hdr += 1
                elif self._hdr == 4:
                    if (DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA and
                        DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA):
                        self._data = 0; self._bits = 0; self._add_bit(0); self._step = self._SAVE
                    elif (DURATION_DIFF(self._te_last, self._TE_LONG) < self._TE_DELTA and
                          DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA):
                        self._data = 0; self._bits = 0; self._add_bit(1); self._step = self._SAVE
                    else: self._step = self._RESET
                else: self._step = self._RESET
            return None
        if self._step == self._SAVE:
            if level: self._te_last = duration; self._step = self._CHECK
            else: self._step = self._RESET
            return None
        if self._step == self._CHECK:
            if not level:
                if (DURATION_DIFF(self._te_last, self._TE_SHORT * 3) < self._TE_DELTA * 2 and
                    DURATION_DIFF(duration, self._TE_SHORT * 3) < self._TE_DELTA * 2):
                    if self._bits == self._MIN_BITS:
                        sig = DecodedSignal(protocol=self.name, data=self._data, bit_count=self._bits, proto_type="Weather")
                        self._data = 0; self._bits = 0; self._hdr = 1; self._step = self._PRE; return sig
                    self._data = 0; self._bits = 0; self._hdr = 1; self._step = self._PRE
                elif (DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA and
                      DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA): self._add_bit(0); self._step = self._SAVE
                elif (DURATION_DIFF(self._te_last, self._TE_LONG) < self._TE_DELTA and
                      DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA): self._add_bit(1); self._step = self._SAVE
                else: self._step = self._RESET
            else: self._step = self._RESET
            return None
        return None

class Acurite609TXCDecoder(GTWT02Decoder):
    name = "Acurite 609TXC"
    _TE_SHORT = 500; _TE_LONG = 1000; _TE_DELTA = 150; _MIN_BITS = 40

class AuriolAHFLDecoder(GTWT02Decoder):
    name = "Auriol AHFL"
    _TE_SHORT = 500; _TE_LONG = 2000; _TE_DELTA = 150; _MIN_BITS = 42

class AuriolHG0601ADecoder(GTWT02Decoder):
    name = "Auriol HG0601A"
    _TE_SHORT = 500; _TE_LONG = 2000; _TE_DELTA = 150; _MIN_BITS = 37

class Acurite986Decoder:
    name = "Acurite 986"
    _TE_LONG = 1750; _TE_SHORT = 800; _TE_DELTA = 50; _MIN_BITS = 40
    _RESET = 0; _S1 = 1; _S2 = 2; _S3 = 3; _SAVE = 4; _CHECK = 5
    def __init__(self): self.reset()
    def reset(self): self._step = self._RESET; self._data = 0; self._bits = 0; self._te_last = 0
    def feed(self, level, duration):
        if self._step == self._RESET:
            if (not level) and DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA * 15:
                self._step = self._S1; self._data = 0; self._bits = 0
            return None
        if self._step in (self._S1, self._S2, self._S3):
            if DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA * 15:
                if not level: self._step += 1
            else: self._step = self._RESET
            return None
        if self._step == self._SAVE:
            if level: self._te_last = duration; self._step = self._CHECK
            else: self._step = self._RESET
            return None
        if self._step == self._CHECK:
            if not level:
                if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA * 10:
                    self._data = (self._data << 1) | (0 if duration < self._TE_SHORT else 1); self._bits += 1
                    self._step = self._SAVE
                else:
                    self._step = self._RESET
                    if self._bits == self._MIN_BITS:
                        return DecodedSignal(protocol=self.name, data=self._data, bit_count=self._bits, proto_type="Weather")
            else: self._step = self._RESET
            return None
        return None

class Acurite592TXRDecoder(GTWT03Decoder):
    name = "Acurite 592TXR"
    _TE_SHORT = 200; _TE_LONG = 400; _TE_DELTA = 90; _MIN_BITS = 56

class Acurite5n1Decoder(GTWT03Decoder):
    name = "Acurite 5n1"
    _TE_SHORT = 200; _TE_LONG = 400; _TE_DELTA = 90; _MIN_BITS = 64

class SolightTE44Decoder:
    name = "Solight TE44"
    _TE_SHORT = 490; _TE_DELTA = 150; _MIN_BITS = 36
    _RESET = 0; _SAVE = 1; _CHECK = 2
    def __init__(self): self.reset()
    def reset(self): self._step = self._RESET; self._data = 0; self._bits = 0; self._te_last = 0
    def feed(self, level, duration):
        if self._step == self._RESET:
            if (not level) and duration >= 3000: self._step = self._SAVE; self._data = 0; self._bits = 0
            return None
        if self._step == self._SAVE:
            if level: self._te_last = duration; self._step = self._CHECK
            else: self._step = self._RESET
            return None
        if self._step == self._CHECK:
            if not level:
                if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA:
                    self._step = self._RESET
                    if self._bits == self._MIN_BITS:
                        return DecodedSignal(protocol=self.name, data=self._data, bit_count=self._bits, proto_type="Weather")
                elif (DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA and
                      DURATION_DIFF(duration, self._TE_SHORT * 2) < self._TE_DELTA):
                    self._data = (self._data << 1); self._bits += 1; self._step = self._SAVE
                elif (DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA and
                      DURATION_DIFF(duration, self._TE_SHORT * 4) < self._TE_DELTA):
                    self._data = (self._data << 1) | 1; self._bits += 1; self._step = self._SAVE
                else: self._step = self._RESET
            else: self._step = self._RESET
            return None
        return None

class InfactoryDecoder(GTWT03Decoder):
    name = "Infactory"
    _TE_SHORT = 500; _TE_LONG = 2000; _TE_DELTA = 150; _MIN_BITS = 40

class KedsumTHDecoder(GTWT03Decoder):
    name = "Kedsum TH"
    _TE_SHORT = 500; _TE_LONG = 2000; _TE_DELTA = 150; _MIN_BITS = 42

class Bresser3chDecoder(SolightTE44Decoder):
    name = "Bresser 3ch"
    _TE_SHORT = 250; _TE_DELTA = 150; _MIN_BITS = 36

class TX8300Decoder(GTWT02Decoder):
    name = "TX 8300"
    _TE_SHORT = 1940; _TE_LONG = 3880; _TE_DELTA = 250; _MIN_BITS = 72

class WendoxW6726Decoder(GTWT03Decoder):
    name = "Wendox W6726"
    _TE_SHORT = 1955; _TE_LONG = 5865; _TE_DELTA = 300; _MIN_BITS = 29

class PowerSmartDecoder:
    name = "Power Smart"
    _TE_SHORT = 225; _TE_LONG = 450; _TE_DELTA = 100; _MIN_BITS = 64
    _HEADER = 0xFD000000C0000000; _HEADER_MASK = 0xFF000000FF000000
    def __init__(self): self.reset()
    def reset(self): self._data = 0; self._m_state = 0
    def feed(self, level, duration):
        event = -1
        if not level:
            if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA: event = 0
            elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA * 2: event = 2
        else:
            if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA: event = 1
            elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA * 2: event = 3
        if event >= 0:
            ns, bit = _manchester_advance(self._m_state, event)
            if ns is not None:
                self._m_state = ns
                if bit is not None:
                    self._data = ((self._data << 1) | (1 - bit)) & ((1 << 64) - 1)
                    if (self._data & self._HEADER_MASK) == self._HEADER:
                        sig = DecodedSignal(protocol=self.name, data=self._data, bit_count=self._MIN_BITS, proto_type="Static")
                        self._data = 0; return sig
        else: self._data = 0; self._m_state = 0
        return None

class ReversRB2Decoder:
    name = "Revers RB2"
    _TE_SHORT = 250; _TE_LONG = 500; _TE_DELTA = 160; _MIN_BITS = 64
    _RESET = 0; _HDR = 1; _DATA = 2
    def __init__(self): self.reset()
    def reset(self): self._step = self._RESET; self._data = 0; self._bits = 0; self._m_state = 0; self._hdr = 0; self._last = 0
    def feed(self, level, duration):
        if self._step == self._RESET:
            if (not level) and DURATION_DIFF(duration, 600) < self._TE_DELTA:
                self._step = self._HDR; self._hdr = 0; self._m_state = 0
            return None
        if self._step == self._HDR:
            ok = DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA
            if ok:
                if (not level and self._last == 1) or (level and self._last == 0): self._hdr += 1
                self._last = 1 if level else 0
            else: self._step = self._RESET
            if self._hdr == 4:
                self._data = 0xF; self._bits = 4; self._step = self._DATA
            return None
        if self._step == self._DATA:
            event = -1
            if not level:
                if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA: event = 0
                elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA * 2: event = 2
            else:
                if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA: event = 1
                elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA * 2: event = 3
            if event >= 0:
                ns, bit = _manchester_advance(self._m_state, event)
                if ns is not None:
                    self._m_state = ns
                    if bit is not None:
                        self._data = ((self._data << 1) | bit) & ((1 << 64) - 1); self._bits += 1
                        if self._bits == self._MIN_BITS:
                            sig = DecodedSignal(protocol=self.name, data=self._data, bit_count=self._bits, proto_type="Static")
                            self._step = self._RESET; return sig
            else: self._step = self._RESET
            return None
        return None

class MarantecDecoder:
    name = "Marantec"
    _TE_SHORT = 1000; _TE_LONG = 2000; _TE_DELTA = 200; _MIN_BITS = 49
    _RESET = 0; _DATA = 1
    def __init__(self): self.reset()
    def reset(self): self._step = self._RESET; self._data = 0; self._bits = 0; self._m_state = 0
    def feed(self, level, duration):
        if self._step == self._RESET:
            if (not level) and DURATION_DIFF(duration, self._TE_LONG * 5) < self._TE_DELTA * 8:
                self._step = self._DATA; self._data = 1; self._bits = 1; self._m_state = 0
            return None
        event = -1
        if not level:
            if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA: event = 0
            elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA: event = 2
            elif duration >= self._TE_LONG * 2 + self._TE_DELTA:
                if self._bits == self._MIN_BITS:
                    sig = DecodedSignal(protocol=self.name, data=self._data, bit_count=self._bits, proto_type="Rolling")
                    self._data = 1; self._bits = 1; self._m_state = 0; return sig
                self._data = 1; self._bits = 1; self._m_state = 0; return None
            else: self._step = self._RESET; return None
        else:
            if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA: event = 1
            elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA: event = 3
            else: self._step = self._RESET; return None
        if event >= 0:
            ns, bit = _manchester_advance(self._m_state, event)
            if ns is not None:
                self._m_state = ns
                if bit is not None: self._data = (self._data << 1) | bit; self._bits += 1
        return None

class AmbientWeatherDecoder(PowerSmartDecoder):
    name = "Ambient Weather"
    _TE_SHORT = 500; _TE_LONG = 1000; _TE_DELTA = 120; _MIN_BITS = 48
    _HEADER = 0x33; _HEADER_MASK = 0xFF

class SchraderGG4Decoder:
    name = "Schrader GG4"
    _TE_SHORT = 120; _TE_LONG = 240; _TE_DELTA = 55; _MIN_BITS = 64; _PRE_BITS = 8
    _RESET = 0; _PRE = 1; _DATA = 2
    def __init__(self): self.reset()
    def reset(self): self._step = self._RESET; self._data = 0; self._bits = 0; self._m_state = 3; self._hdr = 0
    def feed(self, level, duration):
        if self._step != self._RESET:
            event = -1
            if not level:
                if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA: event = 0
                elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA: event = 2
            else:
                if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA: event = 1
                elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA: event = 3
            if event < 0: self._step = self._RESET; return None
            ns, bit = _manchester_advance(self._m_state, event)
            if ns is None: self._step = self._RESET; return None
            self._m_state = ns
            if bit is None: return None
            bit = 1 - bit
        if self._step == self._RESET:
            if level and DURATION_DIFF(duration, self._TE_LONG * 2) < self._TE_DELTA:
                self._step = self._PRE; self._hdr = 0; self._data = 0; self._bits = 0; self._m_state = 3
            return None
        if self._step == self._PRE:
            if bit != 0: self._step = self._RESET; return None
            self._hdr += 1
            if self._hdr == self._PRE_BITS: self._step = self._DATA
            return None
        if self._step == self._DATA:
            self._data = (self._data << 1) | bit; self._bits += 1
            if self._bits == self._MIN_BITS:
                sig = DecodedSignal(protocol=self.name, data=self._data, bit_count=self._bits, proto_type="TPMS")
                self._step = self._RESET; return sig
        return None

class SecPlusV2Decoder:
    name = "Security+ V2"
    _TE_SHORT = 250; _TE_LONG = 500; _TE_DELTA = 110; _MIN_BITS = 62
    _RESET = 0; _DATA = 1
    def __init__(self): self.reset()
    def reset(self): self._step = self._RESET; self._data = 0; self._bits = 0; self._m_state = 0
    def feed(self, level, duration):
        if self._step == self._RESET:
            if (not level) and DURATION_DIFF(duration, self._TE_LONG * 130) < self._TE_DELTA * 100:
                self._step = self._DATA; self._data = 0; self._bits = 0; self._m_state = 0
            return None
        event = -1
        if not level:
            if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA: event = 0
            elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA: event = 2
            elif duration >= self._TE_LONG * 2 + self._TE_DELTA:
                if self._bits == self._MIN_BITS:
                    sig = DecodedSignal(protocol=self.name, data=self._data, bit_count=self._bits, proto_type="Rolling")
                    self._data = 0; self._bits = 0; self._m_state = 0; return sig
                self._data = 0; self._bits = 0; self._m_state = 0; return None
            else: self._step = self._RESET; return None
        else:
            if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA: event = 1
            elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA: event = 3
            else: self._step = self._RESET; return None
        if event >= 0:
            ns, bit = _manchester_advance(self._m_state, event)
            if ns is not None:
                self._m_state = ns
                if bit is not None: self._data = (self._data << 1) | bit; self._bits += 1
        return None

class HormannBiSecurDecoder:
    name = "Hormann BiSecur"
    _TE_SHORT = 208; _TE_LONG = 416; _TE_DELTA = 104; _MIN_BITS = 176
    _RESET = 0; _ALT_S = 1; _HI_VL = 2; _ALT_L = 3; _DATA = 4
    def __init__(self): self.reset()
    def reset(self): self._step = self._RESET; self._data = 0; self._bits = 0; self._m_state = 0; self._sync = 0
    def feed(self, level, duration):
        if self._step == self._RESET:
            if not level and DURATION_DIFF(duration, self._TE_SHORT + self._TE_SHORT // 2) < self._TE_DELTA:
                self._step = self._ALT_S
            return None
        if self._step == self._ALT_S:
            if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA: return None
            if level and DURATION_DIFF(duration, self._TE_LONG * 4) < self._TE_DELTA:
                self._step = self._HI_VL; return None
            self._step = self._RESET; return None
        if self._step == self._HI_VL:
            if not level and DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA:
                self._sync = 3; self._step = self._ALT_L; return None
            self._step = self._RESET; return None
        if self._step == self._ALT_L:
            if level == bool(self._sync & 1) and DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA:
                self._sync -= 1
                if self._sync == 0: self._step = self._DATA; self._data = 0; self._bits = 0; self._m_state = 0
                return None
            self._step = self._RESET; return None
        if self._step == self._DATA:
            event = -1
            if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA:
                event = 1 if not level else 0
            elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA:
                event = 3 if not level else 2
            if event < 0: self._step = self._RESET; return None
            ns, bit = _manchester_advance(self._m_state, event)
            if ns is None: self._step = self._RESET; return None
            self._m_state = ns
            if bit is not None:
                self._data = (self._data << 1) | bit; self._bits += 1
                if self._bits == self._MIN_BITS:
                    sig = DecodedSignal(protocol=self.name, data=self._data, bit_count=self._bits, proto_type="Rolling")
                    self._step = self._RESET; return sig
            return None
        return None

class SecPlusV1Decoder:
    name = "Security+ V1"
    _TE_SHORT = 500; _TE_LONG = 1500; _TE_DELTA = 100; _MIN_BITS = 21
    _RESET = 0; _START = 1; _SAVE = 2; _CHECK = 3
    def __init__(self): self.reset()
    def reset(self): self._step = self._RESET; self._data = 0; self._bits = 0; self._te_last = 0
    def feed(self, level, duration):
        if self._step == self._RESET:
            if (not level) and DURATION_DIFF(duration, self._TE_SHORT * 120) < self._TE_DELTA * 120:
                self._step = self._START; self._data = 0; self._bits = 0
            return None
        if self._step == self._START:
            if level:
                if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA: self._bits += 1; self._step = self._SAVE
                elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA: self._bits += 1; self._step = self._SAVE
                else: self._step = self._RESET
            else: self._step = self._RESET
            return None
        if self._step == self._SAVE:
            if not level:
                if DURATION_DIFF(duration, self._TE_SHORT * 120) < self._TE_DELTA * 120:
                    if self._bits == self._MIN_BITS:
                        sig = DecodedSignal(protocol=self.name, data=self._data, bit_count=self._bits, proto_type="Rolling")
                        self._step = self._RESET; return sig
                    self._bits = 0; self._step = self._START
                else: self._te_last = duration; self._step = self._CHECK
            else: self._step = self._RESET
            return None
        if self._step == self._CHECK:
            if level:
                self._data = (self._data << 1); self._bits += 1; self._step = self._SAVE
            else: self._step = self._RESET
            return None
        return None


# ---------------------------------------------------------------------------
# Protocol registry
# ---------------------------------------------------------------------------

ALL_PROTOCOLS = [
    # Original 7 (tested & working)
    PrincetonDecoder(),
    CAMEDecoder(),
    NiceFloDecoder(),
    GateTXDecoder(),
    LinearDecoder(),
    HoltekHT12XDecoder(),
    ChamberlainDecoder(),
    # Static remotes — CAME-style
    AnsonicDecoder(),
    DitecGol4Decoder(),
    DoitrandDecoder(),
    HoltekDecoder(),
    IntertechnoV3Decoder(),
    LegrandDecoder(),
    MegaCodeDecoder(),
    PhoenixV2Decoder(),
    CameTweeDecoder(),
    # Static remotes — Princeton-style
    ClemsaDecoder(),
    DooyaDecoder(),
    ElplastDecoder(),
    FeronDecoder(),
    GangQiDecoder(),
    Hay21Decoder(),
    HollarmDecoder(),
    IDoDecoder(),
    KeyfinderDecoder(),
    LinearDelta3Decoder(),
    MagellanDecoder(),
    Marantec24Decoder(),
    MastercodeDecoder(),
    NeroRadioDecoder(),
    NeroSketchDecoder(),
    NordIceDecoder(),
    RogerDecoder(),
    SMC5326Decoder(),
    Treadmill37Decoder(),
    AllstarFireflyDecoder(),
    DickertMAHSDecoder(),
    X10Decoder(),
    # Static — unique patterns
    HormannDecoder(),
    BETTDecoder(),
    # Rolling code
    KeeLoqDecoder(),
    NiceFlorSDecoder(),
    CameAtomoDecoder(),
    FaacSLHDecoder(),
    AlutechAT4NDecoder(),
    JaroliftDecoder(),
    KingGatesStylo4KDecoder(),
    BenincaARCDecoder(),
    SomfyTelisDecoder(),
    SomfyKeytisDecoder(),
    # Manchester-based
    HoneywellDecoder(),
    HoneywellWDBDecoder(),
    # Weather/sensors
    NexusTHDecoder(),
    Acurite606TXDecoder(),
    ThermoProTX4Decoder(),
    LaCrosseTX141Decoder(),
    VaunoEN8822CDecoder(),
    EmosE601xDecoder(),
    GTWT02Decoder(),
    GTWT03Decoder(),
    Acurite609TXCDecoder(),
    Acurite986Decoder(),
    Acurite592TXRDecoder(),
    Acurite5n1Decoder(),
    AuriolAHFLDecoder(),
    AuriolHG0601ADecoder(),
    SolightTE44Decoder(),
    InfactoryDecoder(),
    KedsumTHDecoder(),
    Bresser3chDecoder(),
    TX8300Decoder(),
    WendoxW6726Decoder(),
    AmbientWeatherDecoder(),
    # Manchester-based (static/rolling)
    PowerSmartDecoder(),
    ReversRB2Decoder(),
    MarantecDecoder(),
    # TPMS
    SchraderGG4Decoder(),
    # Rolling code (Manchester)
    SecPlusV2Decoder(),
    HormannBiSecurDecoder(),
    SecPlusV1Decoder(),
]

# ===================================================================
# Oregon V1 decoder — ported from oregon_v1.c (Manchester, weather)
# te_short=1465, te_long=2930, te_delta=350, min_bits=32
# ===================================================================

class OregonV1Decoder:
    name = "Oregon V1"
    _TE_SHORT = 1465
    _TE_LONG = 2930
    _TE_DELTA = 350
    _MIN_BITS = 32

    _RESET = 0
    _PREAMBLE = 1
    _PARSE = 2

    def __init__(self):
        self.reset()

    def reset(self):
        self._step = self._RESET
        self._data = 0
        self._bits = 0
        self._te_last = 0
        self._header_count = 0
        self._first_bit = 0
        self._manchester_state = 0

    def feed(self, level, duration):
        if self._step == self._RESET:
            if level and DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA:
                self._step = self._PREAMBLE
                self._te_last = duration
                self._header_count = 0
            return None

        if self._step == self._PREAMBLE:
            if level:
                if (DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA or
                    DURATION_DIFF(duration, self._TE_SHORT * 4) < self._TE_DELTA):
                    self._te_last = duration
                else:
                    self._step = self._RESET
            else:
                if (DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA and
                    DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA):
                    self._header_count += 1
                elif (DURATION_DIFF(duration, self._TE_SHORT * 3) < self._TE_DELTA and
                      DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA):
                    if self._header_count > 7:
                        self._header_count = 0xFF
                elif (self._header_count == 0xFF and
                      DURATION_DIFF(self._te_last, self._TE_SHORT * 4) < self._TE_DELTA):
                    self._data = 0
                    self._bits = 1
                    self._manchester_state = 0
                    self._step = self._PARSE
                    self._first_bit = 1 if duration < self._TE_SHORT * 4 else 0
                else:
                    self._step = self._RESET
            return None

        if self._step == self._PARSE:
            event = -1
            if level:
                if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA:
                    event = 1
                elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA:
                    event = 3
                else:
                    self._step = self._RESET
                    return None
            else:
                if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA:
                    event = 0
                elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA:
                    event = 2
                elif duration >= self._TE_LONG * 2:
                    if self._bits == self._MIN_BITS:
                        if self._first_bit:
                            self._data = ~self._data | (1 << 31)
                        data_rev = _reverse_key(self._data & 0xFFFFFFFF, 32)
                        crc = ((data_rev & 0xFF) + ((data_rev >> 8) & 0xFF) +
                               ((data_rev >> 16) & 0xFF))
                        crc = (crc & 0xFF) + ((crc >> 8) & 0xFF)
                        if crc == ((data_rev >> 24) & 0xFF):
                            sig = DecodedSignal(
                                protocol=self.name, data=self._data & 0xFFFFFFFF,
                                bit_count=self._bits, proto_type="Weather")
                            sig.extra["temp"] = "%.1f" % self._decode_temp(data_rev)
                            sig.extra["ch"] = ((data_rev >> 6) & 0x03) + 1
                            self._step = self._RESET
                            return sig
                    self._data = 0
                    self._bits = 0
                    self._manchester_state = 0
                    self._step = self._RESET
                    return None
                else:
                    self._step = self._RESET
                    return None

            if event >= 0:
                ns, bit = _manchester_advance(self._manchester_state, event)
                if ns is None:
                    self._step = self._RESET
                    return None
                self._manchester_state = ns
                if bit is not None:
                    self._data = (self._data << 1) | (0 if bit else 1)
                    self._bits += 1
        return None

    def _decode_temp(self, data_rev):
        raw = ((data_rev >> 8) & 0xF) * 0.1 + ((data_rev >> 12) & 0xF) + ((data_rev >> 16) & 0xF) * 10.0
        if not ((data_rev >> 21) & 1):
            return raw
        return -raw


# ===================================================================
# Oregon V2 decoder — simplified (Manchester, weather, preamble-based)
# te_short=500, te_long=1000, te_delta=200, min_bits=32
# ===================================================================

class OregonV2Decoder:
    name = "Oregon V2"
    _TE_SHORT = 500
    _TE_LONG = 1000
    _TE_DELTA = 200
    _MIN_BITS = 32
    _PREAMBLE_BITS = 16
    _PREAMBLE = 0xFFFF

    _RESET = 0
    _FOUND_PREAMBLE = 1

    def __init__(self):
        self.reset()

    def reset(self):
        self._step = self._RESET
        self._data = 0
        self._bits = 0
        self._manchester_state = 0
        self._have_bit = False
        self._prev_bit = False

    def feed(self, level, duration):
        inv_level = not level
        if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA:
            event = 1 if inv_level else 0
        elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA:
            event = 3 if inv_level else 2
        else:
            self._step = self._RESET
            self._have_bit = False
            self._data = 0
            self._bits = 0
            return None

        ns, bit = _manchester_advance(self._manchester_state, event)
        if ns is None:
            self._step = self._RESET
            self._manchester_state = 0
            self._have_bit = False
            self._data = 0
            self._bits = 0
            return None
        self._manchester_state = ns

        if bit is not None:
            if self._have_bit:
                if not self._prev_bit and bit:
                    self._data = (self._data << 1) | 1
                    self._bits += 1
                elif self._prev_bit and not bit:
                    self._data = (self._data << 1) | 0
                    self._bits += 1
                else:
                    self.reset()
                    return None
                self._have_bit = False
            else:
                self._prev_bit = bit
                self._have_bit = True

        if self._step == self._RESET:
            if (self._bits >= self._PREAMBLE_BITS and
                (self._data & ((1 << self._PREAMBLE_BITS) - 1)) == self._PREAMBLE):
                self._step = self._FOUND_PREAMBLE
                self._data = 0
                self._bits = 0
        elif self._step == self._FOUND_PREAMBLE:
            if self._bits == self._MIN_BITS:
                sig = DecodedSignal(
                    protocol=self.name, data=self._data & 0xFFFFFFFF,
                    bit_count=self._bits, proto_type="Weather")
                sensor_id = (self._data >> 16) & 0xFFFF
                sig.extra["sensor_id"] = "0x%04X" % sensor_id
                self.reset()
                return sig
        return None


# ===================================================================
# Oregon V3 decoder — simplified (Manchester, weather, preamble-based)
# te_short=500, te_long=1100, te_delta=300, min_bits=32
# ===================================================================

class OregonV3Decoder:
    name = "Oregon V3"
    _TE_SHORT = 500
    _TE_LONG = 1100
    _TE_DELTA = 300
    _MIN_BITS = 32
    _PREAMBLE_BITS = 28
    _PREAMBLE = 0xFFFFFFF5

    _RESET = 0
    _FOUND_PREAMBLE = 1

    def __init__(self):
        self.reset()

    def reset(self):
        self._step = self._RESET
        self._data = 0
        self._bits = 0
        self._manchester_state = 0
        self._prev_bit = False

    def feed(self, level, duration):
        inv_level = not level
        if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA:
            event = 1 if inv_level else 0
        elif DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA:
            event = 3 if inv_level else 2
        else:
            self.reset()
            return None

        ns, bit = _manchester_advance(self._manchester_state, event)
        if ns is None:
            self.reset()
            return None
        self._manchester_state = ns
        if bit is not None:
            self._data = (self._data << 1) | (1 if bit else 0)
            self._bits += 1

        if self._step == self._RESET:
            if (self._bits >= self._PREAMBLE_BITS and
                (self._data & ((1 << self._PREAMBLE_BITS) - 1)) == (self._PREAMBLE & ((1 << self._PREAMBLE_BITS) - 1))):
                self._step = self._FOUND_PREAMBLE
                self._data = 0
                self._bits = 0
        elif self._step == self._FOUND_PREAMBLE:
            if self._bits == self._MIN_BITS:
                sig = DecodedSignal(
                    protocol=self.name, data=self._data & 0xFFFFFFFF,
                    bit_count=self._bits, proto_type="Weather")
                sensor_id = (self._data >> 16) & 0xFFFF
                sig.extra["sensor_id"] = "0x%04X" % sensor_id
                self.reset()
                return sig
        return None


# ===================================================================
# LaCrosse TX decoder — ported from lacrosse_tx.c
# te_short=550, te_long=1300, te_delta=120, min_bits=44
# ===================================================================

class LaCrosseTXDecoder:
    name = "LaCrosse TX"
    _TE_SHORT = 550
    _TE_LONG = 1300
    _TE_DELTA = 120
    _GAP = 1000
    _MIN_BITS = 44
    _SYNC_MASK = 0x0F000000000
    _SYNC_PAT = 0x0A000000000

    _RESET = 0
    _PREAMBLE = 1
    _SAVE_DUR = 2
    _CHECK_DUR = 3

    def __init__(self):
        self.reset()

    def reset(self):
        self._step = self._RESET
        self._data = 0
        self._bits = 0
        self._te_last = 0
        self._header_count = 0

    def _add_bit(self, bit):
        self._data = (self._data << 1) | bit
        self._bits += 1

    def feed(self, level, duration):
        if self._step == self._RESET:
            if not level and DURATION_DIFF(duration, self._GAP) < self._TE_DELTA * 2:
                self._step = self._PREAMBLE
                self._header_count = 0
            return None

        if self._step == self._PREAMBLE:
            if level:
                if (DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA and
                        self._header_count > 1):
                    self._step = self._CHECK_DUR
                    self._data = 0
                    self._bits = 0
                    self._te_last = duration
                elif duration > self._TE_LONG * 2:
                    self._step = self._RESET
            else:
                if DURATION_DIFF(duration, self._GAP) < self._TE_DELTA * 2:
                    self._te_last = duration
                    self._header_count += 1
                else:
                    self._step = self._RESET
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
                if duration > self._GAP * 3:
                    if DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA:
                        self._add_bit(1)
                    elif DURATION_DIFF(self._te_last, self._TE_LONG) < self._TE_DELTA:
                        self._add_bit(0)
                    if (self._data & self._SYNC_MASK) == self._SYNC_PAT and self._bits >= self._MIN_BITS:
                        sig = DecodedSignal(
                            protocol=self.name, data=self._data,
                            bit_count=self._bits, proto_type="Weather")
                        self.reset()
                        return sig
                    self._data = 0
                    self._bits = 0
                    self._header_count = 0
                    self._step = self._RESET
                elif (DURATION_DIFF(self._te_last, self._TE_SHORT) < self._TE_DELTA and
                      DURATION_DIFF(duration, self._TE_LONG) < self._TE_DELTA):
                    self._add_bit(1)
                    self._step = self._SAVE_DUR
                elif (DURATION_DIFF(self._te_last, self._TE_LONG) < self._TE_DELTA and
                      DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA):
                    self._add_bit(0)
                    self._step = self._SAVE_DUR
                else:
                    self._step = self._RESET
            else:
                self._step = self._RESET
            return None
        return None


# ===================================================================
# POCSAG decoder — simplified (pager protocol, FSK, 512/1200/2400 bps)
# te_short=833 (1200bps), te_delta=100
# ===================================================================

class POCSAGDecoder:
    name = "POCSAG"
    _TE_SHORT = 833
    _TE_DELTA = 100
    _MIN_BITS = 32
    _SYNC_WORD = 0x7CD215D8

    _RESET = 0
    _PREAMBLE = 1
    _DATA = 2

    def __init__(self):
        self.reset()

    def reset(self):
        self._step = self._RESET
        self._data = 0
        self._bits = 0
        self._te_last = 0
        self._preamble_count = 0

    def _add_bit(self, bit):
        self._data = (self._data << 1) | bit
        self._bits += 1

    def feed(self, level, duration):
        if self._step == self._RESET:
            if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA:
                self._step = self._PREAMBLE
                self._preamble_count = 1
                self._te_last = duration
            return None

        if self._step == self._PREAMBLE:
            if DURATION_DIFF(duration, self._TE_SHORT) < self._TE_DELTA:
                self._preamble_count += 1
                if self._preamble_count >= 18:
                    self._step = self._DATA
                    self._data = 0
                    self._bits = 0
            else:
                self._step = self._RESET
            return None

        if self._step == self._DATA:
            n_bits = max(1, round(duration / self._TE_SHORT))
            bit_val = 1 if level else 0
            for _ in range(min(n_bits, 4)):
                self._add_bit(bit_val)

            if self._bits >= self._MIN_BITS:
                if (self._data & 0xFFFFFFFF) == self._SYNC_WORD:
                    self._data = 0
                    self._bits = 0
                elif self._bits >= 64:
                    sig = DecodedSignal(
                        protocol=self.name, data=self._data & 0xFFFFFFFF,
                        bit_count=min(self._bits, 32), proto_type="Other")
                    self.reset()
                    return sig
            if self._bits > 128:
                self._step = self._RESET
        return None


ALL_PROTOCOLS.extend([
    OregonV1Decoder(),
    OregonV2Decoder(),
    OregonV3Decoder(),
    LaCrosseTXDecoder(),
    POCSAGDecoder(),
])

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
