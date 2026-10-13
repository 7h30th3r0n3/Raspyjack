"""
mfkey32 — reader-nonce capture helpers + offline key recovery for MIFARE Classic.

RaspyJack side of the Evil-Cardputer "Emul capture / mfkey" feature
(src/nfc_mfemul.h). The capture itself lives in
``payloads/_nfc_emulator.py:NFCEmulator.capture_mfkey32`` (emulate a card, answer
AUTH with a fixed tag nonce, record the reader's encrypted {nr, ar}).

Like Evil, the primary deliverable is the CAPTURE + saving the nonce tuples for
offline recovery: two authentications against the same sector key (same block +
keytype) with the static nonce are exactly what mfkey32 needs. ``save_nonces``
writes a tuple file consumable by standard offline tools (Proxmark3 ``mfkey32v2``,
Flipper ``mfkey``, etc.).

``recover_key`` additionally attempts the recovery on-device (crapto1
lfsr_recovery32). It ALWAYS validates a candidate against the second nonce before
returning, so it never returns a wrong key — it returns None when it cannot
recover (then use the saved tuple file with an offline tool).

NOTE (status): the odd/even half-state recovery, the rollback and the validation
are verified correct; the bucketed odd/even JOIN (crapto1 recover/
bucket_sort_intersect / update_contribution) does not yet pair the true state, so
recover_key currently returns None on real inputs. The capture + save path is the
working, Evil-aligned feature; finishing the join is a follow-up.
"""

import os
import sys

# The fixed tag nonce presented on every AUTH (identical to Evil's MFE_STATIC_NT).
MFE_STATIC_NT = 0x01200145

# Reuse the crypto primitives already shipped with RaspyJack.
_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)
try:
    from payloads._crypto1 import (
        Crypto1, prng_successor, _filter as _filt, even_parity32 as _evenp,
        _bebit, _LF_POLY_ODD as _LF_ODD, _LF_POLY_EVEN as _LF_EVEN,
    )
except Exception:  # pragma: no cover - fallback when imported as top-level pkg
    from _crypto1 import (  # type: ignore
        Crypto1, prng_successor, _filter as _filt, even_parity32 as _evenp,
        _bebit, _LF_POLY_ODD as _LF_ODD, _LF_POLY_EVEN as _LF_EVEN,
    )


# ── Nonce tuple persistence (Evil-parity deliverable) ────────────────────────

def _keytype_str(keytype):
    return "A" if keytype == 0x60 else "B"


def pair_for_recovery(caps):
    """Group captured nonces by (keytype, block) and return the first group that
    has two DISTINCT {nr,ar} pairs — the input mfkey32 needs. Returns a dict or
    None."""
    groups = {}
    for c in caps:
        groups.setdefault((c['keytype'], c['block']), []).append(c)
    for (keytype, block), lst in groups.items():
        seen = []
        for c in lst:
            if (c['nr'], c['ar']) not in [(s['nr'], s['ar']) for s in seen]:
                seen.append(c)
            if len(seen) >= 2:
                return {
                    'uid': seen[0]['uid'], 'keytype': keytype, 'block': block,
                    'nt0': seen[0]['nt'], 'nr0': seen[0]['nr'], 'ar0': seen[0]['ar'],
                    'nt1': seen[1]['nt'], 'nr1': seen[1]['nr'], 'ar1': seen[1]['ar'],
                }
    return None


def save_nonces(path, caps):
    """Append captured nonce tuples to ``path`` in an offline-recovery format.

    One line per capture:
      <uid8> <keytype> <block> <nt8> <nr8> <ar8>
    plus, when a sector has two distinct pairs, a ready-to-run line:
      # mfkey32v2 <uid> <nt0> <nr0> <ar0> <nt1> <nr1> <ar1>
    Hex, space-separated — parseable by Proxmark3 / Flipper mfkey tools.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lines = []
    for c in caps:
        lines.append("%08X %s %d %08X %08X %08X" % (
            c['uid'], _keytype_str(c['keytype']), c['block'],
            c['nt'], c['nr'], c['ar']))
    pr = pair_for_recovery(caps)
    if pr:
        lines.append("# mfkey32v2 %08X %08X %08X %08X %08X %08X %08X" % (
            pr['uid'], pr['nt0'], pr['nr0'], pr['ar0'],
            pr['nt1'], pr['nr1'], pr['ar1']))
    with open(path, "a") as f:
        f.write("\n".join(lines) + "\n")
    return len(lines)


# ── crapto1 lfsr_recovery32 (on-device best-effort solver) ───────────────────

def _update_contrib(item, m1, m2):
    p = item >> 25
    p = (p << 1) | _evenp(item & m1)
    p = (p << 1) | _evenp(item & m2)
    return (p << 24) | (item & 0xFFFFFF)


def _ext_simple(tbl, bit):
    out = []
    for s in tbl:
        s <<= 1
        f0 = _filt(s)
        f1 = _filt(s | 1)
        if f0 ^ f1:
            out.append(s | (f0 ^ bit))
        elif f0 == bit:
            out.append(s)
            out.append(s | 1)
    return out


def _ext_table(tbl, bit, m1, m2, inb):
    inb <<= 24
    out = []
    for s in tbl:
        s <<= 1
        f0 = _filt(s)
        f1 = _filt(s | 1)
        if f0 ^ f1:
            s |= (f0 ^ bit)
            out.append(_update_contrib(s, m1, m2) ^ inb)
        elif f0 == bit:
            out.append(_update_contrib(s, m1, m2) ^ inb)
            out.append(_update_contrib(s | 1, m1, m2) ^ inb)
    return out


def _recover(o_tbl, oks, e_tbl, eks, rem, inb, res):
    if rem == -1:
        for e in e_tbl:
            e2 = (e << 1) ^ _evenp(e & _LF_EVEN) ^ (1 if (inb & 4) else 0)
            for o in o_tbl:
                res.append((e2 ^ _evenp(o & _LF_ODD), o))  # (odd, even)
        return
    o = o_tbl
    e = e_tbl
    i = 0
    while i < 4:
        cur = rem
        rem = rem - 1
        if cur == 0:  # mimic C `rem--` short-circuit
            break
        oks >>= 1
        eks >>= 1
        o = _ext_table(o, oks & 1, _LF_EVEN << 1, _LF_ODD, 0)
        if not o:
            return
        e = _ext_table(e, eks & 1, _LF_ODD, (_LF_EVEN << 1) | 1, inb & 3)
        if not e:
            return
        inb >>= 2
        i += 1
    from collections import defaultdict
    eb = defaultdict(list)
    ob = defaultdict(list)
    for s in e:
        eb[(s >> 24) & 0xFF].append(s)
    for s in o:
        ob[(s >> 24) & 0xFF].append(s)
    for k in ob:
        if k in eb:
            _recover(ob[k], oks, eb[k], eks, rem, inb, res)


def _lfsr_recovery32(ks2, inb=0):
    oks = 0
    eks = 0
    for i in range(31, -1, -2):
        oks = (oks << 1) | _bebit(ks2, i)
    for i in range(30, -1, -2):
        eks = (eks << 1) | _bebit(ks2, i)
    o = []
    e = []
    for i in range(0, (1 << 20) + 1):
        if _filt(i) == (oks & 1):
            o.append(i)
        if _filt(i) == (eks & 1):
            e.append(i)
    for _ in range(4):
        oks >>= 1
        eks >>= 1
        o = _ext_simple(o, oks & 1)
        e = _ext_simple(e, eks & 1)
    res = []
    _recover(o, oks, e, eks, 11, inb << 1, res)
    return res


def _state_to_key(odd, even):
    """Invert Crypto1.init: rebuild the 48-bit key from the odd/even subregs."""
    key = 0
    for k in range(24):
        key |= ((odd >> (23 - k)) & 1) << ((46 - 2 * k) ^ 7)
        key |= ((even >> (23 - k)) & 1) << ((47 - 2 * k) ^ 7)
    return key


def _validate(key, uid, nt, nr_enc, ar_enc):
    v = Crypto1()
    v.init(key)
    v.word(uid ^ nt, 0)
    v.word(nr_enc, 1)
    return ar_enc == (prng_successor(nt, 64) ^ v.word(0, 0))


def recover_key(uid, nt0, nr0, ar0, nt1, nr1, ar1):
    """Recover the 48-bit sector key from two reader-nonce captures (mfkey32).

    All inputs are ints; nr*/ar* are the ENCRYPTED values as captured over the
    air. Returns the key (int) or None. Always validated against the second
    nonce, so it never returns a wrong key. See the module NOTE on solver status.
    """
    p64 = prng_successor(nt0, 64)
    for odd, even in _lfsr_recovery32(ar0 ^ p64, 0):
        cr = Crypto1()
        cr.odd = odd & 0xFFFFFF
        cr.even = even & 0xFFFFFF
        cr.lfsr_rollback_word(0, 0)
        cr.lfsr_rollback_word(nr0, 1)
        cr.lfsr_rollback_word(uid ^ nt0, 0)
        key = _state_to_key(cr.odd, cr.even)
        if _validate(key, uid, nt1, nr1, ar1):
            return key
    return None


def solve_captures(caps):
    """Best-effort: recover keys for every sector that has two distinct pairs.
    Returns {(keytype, block): key}. Keys that cannot be recovered are omitted."""
    out = {}
    groups = {}
    for c in caps:
        groups.setdefault((c['keytype'], c['block']), []).append(c)
    for (keytype, block), lst in groups.items():
        pairs = []
        for c in lst:
            if (c['nr'], c['ar']) not in [(p[1], p[2]) for p in pairs]:
                pairs.append((c['nt'], c['nr'], c['ar']))
            if len(pairs) >= 2:
                break
        if len(pairs) < 2:
            continue
        key = recover_key(lst[0]['uid'], pairs[0][0], pairs[0][1], pairs[0][2],
                          pairs[1][0], pairs[1][1], pairs[1][2])
        if key is not None:
            out[(keytype, block)] = key
    return out
