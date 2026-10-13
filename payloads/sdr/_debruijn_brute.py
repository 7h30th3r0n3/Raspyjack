"""
De Bruijn / OpenSesame fixed-code garage brute-force — pulse builder.

Ported from Evil-Cardputer `src/garage_brute.h`, itself a port of Samy Kamkar's
OpenSesame (samyk/opensesame: garages.h + rf.c) with timings confirmed against
EvilCrowRF `.sub` captures.

FIXED-CODE ONLY (Linear/Stanley Multicode, Chamberlain, Linear MooreMatic).
This is NOT jamming and NOT rolling-code: it emits every possible N-bit *fixed*
code on YOUR OWN garage. No rolling-code counter, no RF jamming — those remain
permanently out of scope and this module does not touch them.

Idea: a De Bruijn sequence B(2,n) has length 2^n and, emitted continuously with
no inter-symbol gap, every sliding window of n bits is a distinct code — so all
2^n codes play in ~2^n symbols instead of 2^n separate frames.
  10b ~= 2.07 s, 9b ~= 1.04 s, 8b ~= 0.53 s per pass (Te = 500 us).

Encoding (verbatim OpenSesame: baud=2000 -> Te=500us, MSB-first), OOK PWM, each
protocol bit = one 2000 us word:
  bit 0 = "1000" = 500 us HIGH + 1500 us LOW  -> pulses [ +500, -1500]
  bit 1 = "1110" = 1500 us HIGH + 500 us LOW  -> pulses [+1500,  -500]

This module is PURE Python and never touches the radio. It returns signed-int
pulse buffers (µs; HIGH > 0, LOW < 0) in the exact format
`CC1101USB.tx_raw(pulses)` expects. The payload is responsible for setting the
frequency/modulation (OOK) and calling tx_raw() on each returned buffer.

tx_raw() caps one USB frame at ~1021 pulses (MAX_BODY=2048 -> 4 + 2*n + 1 bytes),
so the 9-bit and 10-bit De Bruijn streams (1042 / 2066 pulses) do not fit one
frame. `chunk_debruijn_pulses()` splits the stream into frames that each fit,
OVERLAPPING consecutive chunks by (n-1) bits so no n-bit code window is ever
split across a frame boundary (completeness is preserved; the only cost is
re-sending n-1 overlap symbols per chunk).
"""

# ── Garage protocol presets (aligned on Evil GARAGE_PROTOS / OpenSesame) ──────
# key -> (display name, bit length, default frequency Hz)
PRESETS = {
    "multicode10":   ("Linear Multicode 10b",  10, 310_000_000),
    "stanley10":     ("Stanley Multicode 10b", 10, 310_000_000),
    "chamberlain9us":("Chamberlain 9b (US)",    9, 390_000_000),
    "chamberlain9ca":("Chamberlain 9b (CA)",    9, 315_000_000),
    "chamberlain8":  ("Chamberlain 8b",         8, 390_000_000),
    "chamberlain7":  ("Chamberlain 7b",         7, 390_000_000),
    "moorematic8":   ("Linear MooreMatic 8b",   8, 310_000_000),
}

# Ordered list for menu display: (key, name, bits, def_hz)
PRESET_LIST = [
    (k, PRESETS[k][0], PRESETS[k][1], PRESETS[k][2])
    for k in ("multicode10", "stanley10", "chamberlain9us", "chamberlain9ca",
              "chamberlain8", "chamberlain7", "moorematic8")
]

# Selectable frequencies (Hz) — union of the Willy / EvilCrowRF sets.
GARAGE_FREQS = [300_000_000, 310_000_000, 315_000_000,
                390_000_000, 433_920_000, 868_350_000]

TE_US = 500               # base symbol time
_MAX_TX_PULSES = 1020     # tx_raw cap (even): 4 + 2*1020 + 1 = 2045 <= 2048


# ── De Bruijn B(2,n) generator (FKM "prefer-smallest", rf.c db()) ─────────────
def debruijn_sequence(n):
    """Return the linear De Bruijn sequence B(2,n) as a list of 0/1 ints.

    Length = 2^n + (n-1): the cyclic FKM sequence of length 2^n (which begins
    with n zeros) followed by (n-1) zeros so that, read linearly, every n-bit
    string appears exactly once as a sliding window (the trailing zeros == the
    wrapped-around prefix, since the smallest De Bruijn sequence starts 0^n).
    """
    if n < 1 or n > 16:
        raise ValueError("n must be 1..16")
    a = [0] * (n + 1)          # 1-indexed necklace register a[1..n]
    seq = []

    def db(t, p):
        if t > n:
            if n % p == 0:
                seq.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, 2):   # binary: a[t-p]+1 .. 1
                a[t] = j
                db(t + 1, t)

    db(1, 1)                   # yields 2^n symbols
    seq.extend([0] * (n - 1))  # wrap padding
    return seq


# ── bits -> OOK pulses (signed µs: HIGH > 0, LOW < 0) ─────────────────────────
def bits_to_ook_pulses(bits, te_us=TE_US):
    """Flatten a 0/1 bit list into a signed-µs pulse buffer for tx_raw().

    bit 1 -> [+3*te, -te]   (1110)
    bit 0 -> [+te,  -3*te]  (1000)
    """
    hi, lo = 3 * te_us, te_us
    pulses = []
    for b in bits:
        if b:
            pulses.append(hi); pulses.append(-lo)
        else:
            pulses.append(lo); pulses.append(-hi)
    return pulses


def code_to_pulses(code, n, te_us=TE_US):
    """One n-bit fixed code (MSB-first) -> pulse buffer (frame-by-frame / DIP)."""
    bits = [(code >> b) & 1 for b in range(n - 1, -1, -1)]
    return bits_to_ook_pulses(bits, te_us)


# ── High-level builders ───────────────────────────────────────────────────────
def build_garage_brute(preset, te_us=TE_US):
    """Build the full continuous De Bruijn pulse buffer for a preset.

    `preset` is a PRESETS key or an int bit-length. Returns a single flat signed
    pulse list (may exceed one tx_raw frame — use chunk_debruijn_pulses() to
    emit it, or send directly if it fits).
    """
    n = preset if isinstance(preset, int) else PRESETS[preset][1]
    return bits_to_ook_pulses(debruijn_sequence(n), te_us)


def chunk_debruijn_pulses(preset, te_us=TE_US, max_pulses=_MAX_TX_PULSES):
    """Split a preset's De Bruijn stream into tx_raw-sized frames.

    Consecutive frames overlap by (n-1) protocol bits so that every n-bit code
    window stays contiguous within at least one frame (no code is lost at a
    boundary). Returns a list of pulse buffers; send each via tx_raw() in order.
    """
    n = preset if isinstance(preset, int) else PRESETS[preset][1]
    seq = debruijn_sequence(n)
    bits_per_frame = max_pulses // 2          # 2 pulses per protocol bit
    if bits_per_frame < n:
        raise ValueError("max_pulses too small for one n-bit window")
    total = len(seq)
    if total <= bits_per_frame:
        return [bits_to_ook_pulses(seq, te_us)]

    step = bits_per_frame - (n - 1)           # overlap (n-1) bits
    chunks = []
    start = 0
    while True:
        window = seq[start:start + bits_per_frame]
        chunks.append(bits_to_ook_pulses(window, te_us))
        if start + bits_per_frame >= total:
            break
        start += step
    return chunks


def dip_frames(n, te_us=TE_US):
    """Frame-by-frame (DIP) mode: yield (code, pulses) for every n-bit code.

    Each frame is a single fixed code sent on its own (with the normal
    inter-frame gap the payload inserts between tx_raw calls). Slower than the
    De Bruijn stream but one code per press/frame, matching a DIP-switch remote.
    """
    for code in range(1 << n):
        yield code, code_to_pulses(code, n, te_us)


def preset_duration_s(preset, te_us=TE_US):
    """Approx on-air duration of one continuous De Bruijn pass, in seconds."""
    n = preset if isinstance(preset, int) else PRESETS[preset][1]
    return (len(debruijn_sequence(n)) * 4 * te_us) / 1_000_000.0
