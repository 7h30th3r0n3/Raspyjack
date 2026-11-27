"""
NFC-F (FeliCa) and NFC-B (ISO14443-B) pollers for the RaspyJack Cap-NFC HAT
(ST25R3916).

Ported from Evil-Cardputer src/nfc_iso15693_felica.h (nfcv_felica_poll,
nfcv_isob_poll). ISO15693 / NFC-V is deferred to a later pass — it needs
subcarrier-stream mode, not a plain mode switch.

SAFETY CONTRACT (no regression): each poller switches the ST25R3916 into
NFC-F or NFC-B, polls, then ALWAYS restores NFC-A via a try/finally so the
existing Read / Emulate / EMV / Relay flows stay healthy.

VALIDATION (2026-10-27, via PM3 `hf felica litesim`): FeliCa poll returns ZERO
bytes across all attempts on the Cap-NFC C0 (HITS=0/18) — the TX/RX path is dead,
not just a parse/CRC issue.

ROOT CAUSE (not yet fixed — a real RF bring-up task): `_st25r_driver._enter_mode`
only writes MODE_DEF + BIT_RATE for NFC-F/NFC-B, whereas `_configure_nfc_a` also
programs the full analog receiver front-end (RX_CONF1-4 reg 0x24-0x27, the
over/under-shoot and correlator B-registers, AUX correlator) tuned for NFC-A
106 kbps. Those receiver settings are WRONG for the 212 kbps FeliCa subcarrier
(and for ISO-B), so the demodulator never recovers a response. Fixing it needs
the ST25R3916 technology-specific analog-config register tables (cf. ST RFAL
rfalSetAnalogConfig for POLL_NFCF_212 / POLL_NFCB) added to `_enter_mode`, plus
on-device iteration. Until then felica_poll/isob_poll will not detect tags.
"""


def felica_poll(drv):
    """Poll for a FeliCa (NFC-F) card.

    Sends the Polling command (system code FFFF, request code 01) and parses
    the response. Returns {"idm": bytes[8], "pmm": bytes[8], "sys": bytes|None}
    or None if no card. Always restores NFC-A before returning.
    """
    # Polling: [LEN=06][cmd=00][syscode FFFF][reqcode 01][timeslot 00]
    cmd = [0x06, 0x00, 0xFF, 0xFF, 0x01, 0x00]
    try:
        drv.set_mode_nfc_f()
        rx = drv.transceive_raw(cmd, timeout_ms=60, min_rx=18)
    finally:
        drv.set_mode_nfc_a()

    # Response FIFO: [LEN][0x01][IDm 8][PMm 8][opt request data 2]
    if not rx or len(rx) < 18 or rx[1] != 0x01:
        return None
    idm = bytes(rx[2:10])
    pmm = bytes(rx[10:18])
    sys = bytes(rx[18:20]) if len(rx) >= 20 else None
    return {"idm": idm, "pmm": pmm, "sys": sys}


def isob_poll(drv):
    """Poll for an ISO14443-B card.

    Sends REQB (APf=05, AFI=00, PARAM=00) and parses the ATQB. Returns
    {"pupi": bytes[4], "atqb": bytes} or None if no card. Always restores
    NFC-A before returning.
    """
    # REQB: [APf 0x05][AFI 0x00][PARAM 0x00]  (PARAM.b3=0 -> REQB, N=1 slot)
    reqb = [0x05, 0x00, 0x00]
    try:
        drv.set_mode_nfc_b()
        rx = drv.transceive_raw(reqb, timeout_ms=60, min_rx=12)
    finally:
        drv.set_mode_nfc_a()

    # ATQB: [0x50][PUPI 4][AppData 4][ProtInfo 3]  (12 bytes before CRC)
    if not rx or len(rx) < 12 or rx[0] != 0x50:
        return None
    pupi = bytes(rx[1:5])
    atqb = bytes(rx[0:12])
    return {"pupi": pupi, "atqb": atqb}
