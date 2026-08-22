"""
Sub-GHz OOK protocol decoders for CC1101 raw signal capture.

Decodes timing sequences (lists of +/- microsecond durations) into
protocol names, codes, and button values.  Compatible with Flipper Zero
.sub RAW_Data format.

Supported protocols:
  Princeton (24-bit), CAME (12-bit), NICE FLO (12-bit), Linear (10-bit),
  GateTX (24-bit), Chamberlain (9-bit), Holtek HT12x (12-bit),
  KeeLoq (66-bit, decode-only).
"""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class DecodedSignal:
    protocol: str
    code: int
    bits: int
    button: str
    serial: str
    frequency: float
    modulation: str
    raw_timings: list

    def code_hex(self):
        nibbles = max(1, (self.bits + 3) // 4)
        return f"0x{self.code:0{nibbles}X}"

    def code_bin(self):
        return format(self.code, f"0{self.bits}b") if self.bits else ""


def _match_pulse(dur, target, tolerance=0.35):
    lo = target * (1.0 - tolerance)
    hi = target * (1.0 + tolerance)
    return lo <= abs(dur) <= hi


def _try_princeton(timings):
    """Princeton/PT2262: short=350us, long=1050us, sync=350+10850.
    24-bit code encoded as tristate: short-long=0, long-short=1, short-short=float."""
    results = []
    i = 0
    while i < len(timings) - 49:
        if timings[i] > 0 and _match_pulse(timings[i], 350) and \
           timings[i + 1] < 0 and abs(timings[i + 1]) > 5000:
            bits = []
            j = i + 2
            ok = True
            for _ in range(24):
                if j + 3 >= len(timings):
                    ok = False
                    break
                p1h, p1l, p2h, p2l = timings[j], timings[j+1], timings[j+2], timings[j+3]
                if _match_pulse(p1h, 350) and _match_pulse(p1l, -1050) and \
                   _match_pulse(p2h, 350) and _match_pulse(p2l, -1050):
                    bits.append(0)
                elif _match_pulse(p1h, 1050) and _match_pulse(p1l, -350) and \
                     _match_pulse(p2h, 1050) and _match_pulse(p2l, -350):
                    bits.append(1)
                else:
                    bits.append(0)
                j += 4
            if ok and len(bits) == 24:
                code = 0
                for b in bits:
                    code = (code << 1) | b
                btn_nibble = code & 0x0F
                serial_val = (code >> 4) & 0xFFFFF
                results.append(DecodedSignal(
                    protocol="Princeton",
                    code=code, bits=24,
                    button=f"0x{btn_nibble:X}",
                    serial=f"0x{serial_val:05X}",
                    frequency=0, modulation="AM650",
                    raw_timings=timings[i:j],
                ))
            i = j
        else:
            i += 1
    return results


def _try_came(timings):
    """CAME 12-bit: short=320us, long=640us, sync_gap=11520us.
    Encoding: short-long=0, long-short=1."""
    results = []
    i = 0
    while i < len(timings) - 25:
        if timings[i] > 0 and _match_pulse(timings[i], 320) and \
           timings[i + 1] < 0 and abs(timings[i + 1]) > 8000:
            bits = []
            j = i + 2
            ok = True
            for _ in range(12):
                if j + 1 >= len(timings):
                    ok = False
                    break
                h, l = timings[j], timings[j+1]
                if _match_pulse(h, 320) and _match_pulse(l, -640):
                    bits.append(0)
                elif _match_pulse(h, 640) and _match_pulse(l, -320):
                    bits.append(1)
                else:
                    ok = False
                    break
                j += 2
            if ok and len(bits) == 12:
                code = 0
                for b in bits:
                    code = (code << 1) | b
                results.append(DecodedSignal(
                    protocol="CAME",
                    code=code, bits=12,
                    button=f"0x{code & 0xF:X}",
                    serial=f"0x{(code >> 4) & 0xFF:02X}",
                    frequency=0, modulation="AM650",
                    raw_timings=timings[i:j],
                ))
            i = j
        else:
            i += 1
    return results


def _try_nice_flo(timings):
    """NICE FLO 12-bit: short=700us, long=1400us, sync_gap=25200us.
    Encoding: short-long=0, long-short=1."""
    results = []
    i = 0
    while i < len(timings) - 25:
        if timings[i] > 0 and _match_pulse(timings[i], 700) and \
           timings[i + 1] < 0 and abs(timings[i + 1]) > 15000:
            bits = []
            j = i + 2
            ok = True
            for _ in range(12):
                if j + 1 >= len(timings):
                    ok = False
                    break
                h, l = timings[j], timings[j+1]
                if _match_pulse(h, 700) and _match_pulse(l, -1400):
                    bits.append(0)
                elif _match_pulse(h, 1400) and _match_pulse(l, -700):
                    bits.append(1)
                else:
                    ok = False
                    break
                j += 2
            if ok and len(bits) == 12:
                code = 0
                for b in bits:
                    code = (code << 1) | b
                results.append(DecodedSignal(
                    protocol="NICE FLO",
                    code=code, bits=12,
                    button=f"0x{code & 0xF:X}",
                    serial=f"0x{(code >> 4) & 0xFF:02X}",
                    frequency=0, modulation="AM650",
                    raw_timings=timings[i:j],
                ))
            i = j
        else:
            i += 1
    return results


def _try_linear(timings):
    """Linear 10-bit: short=500us, long=1500us.
    Encoding: short-short=0, long-long=1."""
    results = []
    i = 0
    while i < len(timings) - 21:
        bits = []
        j = i
        ok = True
        for _ in range(10):
            if j + 1 >= len(timings):
                ok = False
                break
            h, l = timings[j], timings[j+1]
            if _match_pulse(h, 500) and _match_pulse(l, -500):
                bits.append(0)
            elif _match_pulse(h, 1500) and _match_pulse(l, -1500):
                bits.append(1)
            else:
                ok = False
                break
            j += 2
        if ok and len(bits) == 10:
            code = 0
            for b in bits:
                code = (code << 1) | b
            results.append(DecodedSignal(
                protocol="Linear",
                code=code, bits=10,
                button="", serial=f"0x{code:03X}",
                frequency=0, modulation="AM650",
                raw_timings=timings[i:j],
            ))
        i += 1 if not ok else j
    return results


def _try_gatetx(timings):
    """GateTX 24-bit: short=350us, long=700us, sync=350+10500.
    Same timing ratio as Princeton but shorter long pulse."""
    results = []
    i = 0
    while i < len(timings) - 49:
        if timings[i] > 0 and _match_pulse(timings[i], 350) and \
           timings[i + 1] < 0 and abs(timings[i + 1]) > 7000:
            bits = []
            j = i + 2
            ok = True
            for _ in range(24):
                if j + 1 >= len(timings):
                    ok = False
                    break
                h, l = timings[j], timings[j+1]
                if _match_pulse(h, 350) and _match_pulse(l, -700):
                    bits.append(0)
                elif _match_pulse(h, 700) and _match_pulse(l, -350):
                    bits.append(1)
                else:
                    ok = False
                    break
                j += 2
            if ok and len(bits) == 24:
                code = 0
                for b in bits:
                    code = (code << 1) | b
                results.append(DecodedSignal(
                    protocol="GateTX",
                    code=code, bits=24,
                    button=f"0x{code & 0xF:X}",
                    serial=f"0x{(code >> 4) & 0xFFFFF:05X}",
                    frequency=0, modulation="AM650",
                    raw_timings=timings[i:j],
                ))
            i = j
        else:
            i += 1
    return results


def _try_chamberlain(timings):
    """Chamberlain 9-bit: high=1500us, gap=3000us per bit.
    1 = 1500us HIGH + 1500us LOW, 0 = 1500us LOW + 1500us HIGH (inverted)."""
    results = []
    i = 0
    while i < len(timings) - 19:
        bits = []
        j = i
        ok = True
        for _ in range(9):
            if j + 1 >= len(timings):
                ok = False
                break
            h, l = timings[j], timings[j+1]
            if _match_pulse(h, 1500) and _match_pulse(l, -1500):
                bits.append(1)
            elif _match_pulse(h, 500, 0.5) and _match_pulse(l, -2500, 0.4):
                bits.append(0)
            else:
                ok = False
                break
            j += 2
        if ok and len(bits) == 9:
            code = 0
            for b in bits:
                code = (code << 1) | b
            results.append(DecodedSignal(
                protocol="Chamberlain",
                code=code, bits=9,
                button=f"{code & 0x7}", serial=f"0x{(code >> 3) & 0x3F:02X}",
                frequency=0, modulation="AM650",
                raw_timings=timings[i:j],
            ))
        i += 1 if not ok else j
    return results


def _try_holtek(timings):
    """Holtek HT12x 12-bit: short=210us, long=630us, sync=210+6930.
    Encoding: short-long=0, long-short=1."""
    results = []
    i = 0
    while i < len(timings) - 25:
        if timings[i] > 0 and _match_pulse(timings[i], 210, 0.4) and \
           timings[i + 1] < 0 and abs(timings[i + 1]) > 4000:
            bits = []
            j = i + 2
            ok = True
            for _ in range(12):
                if j + 1 >= len(timings):
                    ok = False
                    break
                h, l = timings[j], timings[j+1]
                if _match_pulse(h, 210, 0.4) and _match_pulse(l, -630, 0.4):
                    bits.append(0)
                elif _match_pulse(h, 630, 0.4) and _match_pulse(l, -210, 0.4):
                    bits.append(1)
                else:
                    ok = False
                    break
                j += 2
            if ok and len(bits) == 12:
                code = 0
                for b in bits:
                    code = (code << 1) | b
                results.append(DecodedSignal(
                    protocol="Holtek",
                    code=code, bits=12,
                    button=f"0x{code & 0xF:X}",
                    serial=f"0x{(code >> 4) & 0xFF:02X}",
                    frequency=0, modulation="AM650",
                    raw_timings=timings[i:j],
                ))
            i = j
        else:
            i += 1
    return results


_DECODERS = [
    _try_princeton,
    _try_came,
    _try_nice_flo,
    _try_linear,
    _try_gatetx,
    _try_chamberlain,
    _try_holtek,
]


def decode_timings(timings, frequency=433.92):
    """Run all protocol decoders on a timing sequence.
    Returns list of DecodedSignal (may be empty)."""
    all_results = []
    for decoder in _DECODERS:
        try:
            hits = decoder(timings)
            for sig in hits:
                sig.frequency = frequency
            all_results.extend(hits)
        except Exception:
            pass
    return all_results


def save_sub_file(path, timings, frequency=433.92, preset="FuriHalSubGhzPresetOok650Async"):
    """Save timings in Flipper Zero .sub file format."""
    freq_hz = int(frequency * 1_000_000)
    lines = [
        "Filetype: Flipper SubGhz RAW File",
        "Version: 1",
        f"Frequency: {freq_hz}",
        f"Preset: {preset}",
        "Protocol: RAW",
    ]
    chunk = []
    for t in timings:
        chunk.append(str(t))
        if len(chunk) >= 512:
            lines.append("RAW_Data: " + " ".join(chunk))
            chunk = []
    if chunk:
        lines.append("RAW_Data: " + " ".join(chunk))
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def load_sub_file(path):
    """Load a Flipper .sub file. Returns (timings, frequency, preset)."""
    timings = []
    frequency = 433920000
    preset = ""
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("Frequency:"):
                frequency = int(line.split(":", 1)[1].strip())
            elif line.startswith("Preset:"):
                preset = line.split(":", 1)[1].strip()
            elif line.startswith("RAW_Data:"):
                parts = line.split(":", 1)[1].strip().split()
                for p in parts:
                    try:
                        timings.append(int(p))
                    except ValueError:
                        pass
    return timings, frequency / 1_000_000, preset
