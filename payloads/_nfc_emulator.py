"""
NFC card emulator for CardputerZero Cap HAT (ST25R3916).

Ported from the Flipper Zero Momentum firmware's listener implementation.
Supports MIFARE Classic 1K/4K emulation with Crypto1, MIFARE Ultralight/
NTAG emulation, and UID-only emulation for access control systems.

Requires: _st25r_driver.py (ST25R3916 hardware driver)
          _crypto1.py     (MIFARE Crypto1 cipher)
"""

import os
import struct
import time
from typing import Optional, List, Callable

try:
    from payloads._crypto1 import Crypto1
except ImportError:
    Crypto1 = None

# ── ST25R3916 register/command constants (mirror _st25r_driver.py) ────

_OP_CTRL     = 0x02
_MODE_DEF    = 0x03
_ISO14443A   = 0x05
_AUX_DEF     = 0x0A
_NRT1        = 0x10
_TIMER_EMV   = 0x12
_MASK_IRQ    = 0x16
_IRQ_MAIN    = 0x1A
_IRQ_ERR     = 0x1C
_IRQ_TGT     = 0x1D
_FIFO_STA1   = 0x1E
_TX_BYTES1   = 0x22
_AUX_DISP    = 0x31
_PASS_TGT    = 0x08  # Passive Target register
_MASK_RX_TMR = 0x13

_CMD_STOP_ALL    = 0xC2
_CMD_TX_CRC      = 0xC4
_CMD_TX_NO_CRC   = 0xC5
_CMD_CLEAR_FIFO  = 0xDB
_CMD_GOTO_SENSE  = 0xCD
_CMD_GOTO_SLEEP  = 0xCE
_CMD_UNMASK_RX   = 0xD1
_CMD_TRANSPARENT = 0xDC

_OP_READ     = 0x40
_OP_FIFO_W   = 0x80
_OP_FIFO_R   = 0x9F
_PT_A_LOAD   = 0xA0

# OP_CTRL bits
_OP_EN   = 0x80
_OP_RX   = 0x40
_OP_TX   = 0x08
_OP_FD   = 0x03

# Interrupt bits
_I_TXE      = 0x08000000
_I_RXS      = 0x20000000
_I_RXE      = 0x10000000
_I_COL      = 0x04000000
_I_NRE      = 0x00400000
_I_CRC_ERR  = 0x00008000
_I_PAR_ERR  = 0x00004000
_I_ERR1     = 0x00002000
_I_ERR2     = 0x00001000
_I_EON      = 0x00000200
_I_EOF      = 0x00000100
_I_WU_A     = 0x00000008
_I_WU_A_X   = 0x00000004

_LISTEN_IRQS = (_I_TXE | _I_RXS | _I_RXE | _I_COL | _I_PAR_ERR | _I_CRC_ERR |
                _I_ERR1 | _I_ERR2 | _I_NRE | _I_EON | _I_EOF | _I_WU_A_X | _I_WU_A)

# AUX register bits for UID length
_AUX_NFC_ID_MASK  = 0x30
_AUX_NFC_ID_4B    = 0x00
_AUX_NFC_ID_7B    = 0x10

# MIFARE Classic commands
_MF_AUTH_A    = 0x60
_MF_AUTH_B    = 0x61
_MF_READ      = 0x30
_MF_WRITE     = 0xA0
_MF_DEC       = 0xC0
_MF_INC       = 0xC1
_MF_RESTORE   = 0xC2
_MF_TRANSFER  = 0xB0
_MF_HALT_MSB  = 0x50
_MF_ACK       = 0x0A
_MF_NACK      = 0x00

_MF_BLOCK_SIZE   = 16
_MF_1K_BLOCKS    = 64
_MF_4K_BLOCKS    = 256
_MF_KEY_SIZE     = 6

# ISO14443-A CRC
def _crc_a(data):
    crc = 0x6363
    for b in data:
        b ^= crc & 0xFF
        b ^= (b << 4) & 0xFF
        crc = (crc >> 8) ^ (b << 8) ^ (b << 3) ^ (b >> 4)
        crc &= 0xFFFF
    return crc


def _sector_of_block(block):
    if block < 128:
        return block // 4
    return 32 + (block - 128) // 16


def _is_sector_trailer(block):
    if block < 128:
        return (block % 4) == 3
    return (block % 16) == 15


class NFCEmulator:
    """NFC card emulator using ST25R3916 passive target mode."""

    def __init__(self, driver):
        """Initialize with an opened ST25R3916Driver instance."""
        self._drv = driver
        self._running = False
        self._crypto = Crypto1() if Crypto1 else None
        self._comm_encrypted = False
        self._auth_complete = False
        self._auth_key_type = 0
        self._auth_block = 0
        self._nt = 0
        self._write_block = 0
        self._cmd_in_progress = False

    # ── Hardware target mode setup ────────────────────────────────────

    def _write_pt_mem(self, data):
        """Write Passive Target A-config memory (UID/ATQA/SAK)."""
        self._drv._xfer([_PT_A_LOAD] + list(data))

    def _setup_target_mode(self, uid, atqa, sak):
        """Configure ST25R3916 as ISO14443-A passive target."""
        d = self._drv

        d._wr(_OP_CTRL, _OP_EN | _OP_RX | _OP_FD)
        d._wr(_MODE_DEF, 0x88)  # targ_targ(0x80) | om0(0x08)
        d._wr(_PASS_TGT, 0x5C)  # fdel_2|fdel_0|d_ac_ap2p|d_212_424_1r
        d._wr(_MASK_RX_TMR, 0x02)

        # Set UID length in AUX register
        if len(uid) <= 4:
            d._mod(_AUX_DEF, _AUX_NFC_ID_4B, _AUX_NFC_ID_MASK)
        else:
            d._mod(_AUX_DEF, _AUX_NFC_ID_7B, _AUX_NFC_ID_MASK)

        # Build PT memory: UID(0-9) + ATQA(10-11) + SAK1(12) + SAK2(13) + SAK3(14)
        pt = bytearray(15)
        pt[:len(uid)] = uid[:min(len(uid), 10)]
        pt[10] = atqa & 0xFF
        pt[11] = (atqa >> 8) & 0xFF
        if len(uid) <= 4:
            pt[12] = sak & ~0x04
        else:
            pt[12] = 0x04  # cascade
        pt[13] = sak & ~0x04
        pt[14] = sak & ~0x04
        self._write_pt_mem(pt)

        d._cmd(_CMD_STOP_ALL)
        d._read_irqs()
        d._wr32(_MASK_IRQ, ~_LISTEN_IRQS & 0xFFFFFFFF)
        d._clear_irqs()

        # Enable auto-collision resolution for 106kbps NFC-A
        d._mod(_PASS_TGT, 0, 0x01)  # clear d_106_ac_a
        d._cmd(_CMD_GOTO_SENSE)

    def _listener_tx(self, data, with_crc=True):
        """Transmit data as target (response to reader)."""
        d = self._drv
        d._cmd(_CMD_CLEAR_FIFO)
        d._fifo_w(data)
        d._set_tx_len(len(data))
        if with_crc:
            d._cmd(_CMD_TX_CRC)
        else:
            d._cmd(_CMD_TX_NO_CRC)
        d._wait_irq(_I_TXE, 10)

    def _listener_tx_short(self, nibble):
        """Transmit 4-bit short frame (ACK/NACK)."""
        d = self._drv
        d._cmd(_CMD_CLEAR_FIFO)
        d._fifo_w([nibble])
        # TX length = 0 bytes, 4 bits
        d._wr(_TX_BYTES1, 0x00)
        d._wr(_TX_BYTES1 + 1, 0x04)
        d._cmd(_CMD_TX_NO_CRC)
        d._wait_irq(_I_TXE, 10)

    def _listener_tx_encrypted(self, plaintext, with_crc=True):
        """Encrypt and transmit data (after MIFARE auth)."""
        if not self._crypto:
            return
        if with_crc:
            crc = _crc_a(plaintext)
            plaintext = bytes(plaintext) + bytes([crc & 0xFF, (crc >> 8) & 0xFF])
        encrypted = self._crypto.encrypt_bytes(plaintext)
        d = self._drv
        d._cmd(_CMD_CLEAR_FIFO)
        # Set no_tx_par + no_rx_par for custom parity (encrypted stream)
        d._wr(_ISO14443A, d._rr(_ISO14443A) | 0xC0)
        d._fifo_w(encrypted)
        d._set_tx_len(len(encrypted))
        d._cmd(_CMD_TX_NO_CRC)
        d._wait_irq(_I_TXE, 10)
        # Restore parity
        d._wr(_ISO14443A, d._rr(_ISO14443A) & ~0xC0)

    def _listener_rx(self, timeout_ms=50):
        """Wait for and receive data from reader."""
        d = self._drv
        flags = d._wait_irq(_I_RXE | _I_NRE | _I_EOF | _I_CRC_ERR | _I_PAR_ERR, timeout_ms)
        if flags & _I_EOF:
            return None  # field off
        if not (flags & _I_RXE):
            return None
        n = d._fifo_len()
        if n == 0:
            return None
        return d._fifo_r(n)

    def _decrypt_rx(self, data):
        """Decrypt received data if in encrypted mode."""
        if not self._comm_encrypted or not self._crypto:
            return data
        return self._crypto.decrypt_bytes(data)

    # ── MIFARE Classic emulation handlers ─────────────────────────────

    def _reset_auth(self):
        self._auth_complete = False
        self._comm_encrypted = False
        self._cmd_in_progress = False
        if self._crypto:
            self._crypto.reset()

    def _handle_auth(self, cmd, block_num, data_blocks, uid, keys_a, keys_b):
        """Handle MIFARE AUTH command (first part: send NT)."""
        if not self._crypto:
            return False
        key_type = 0 if cmd == _MF_AUTH_A else 1
        sector = _sector_of_block(block_num)
        key = keys_a.get(sector, b'\xFF' * 6) if key_type == 0 else keys_b.get(sector, b'\xFF' * 6)
        key_num = int.from_bytes(key[:6], 'big')
        cuid = int.from_bytes(uid[:4], 'big')

        self._auth_key_type = key_type
        self._auth_block = block_num

        # Generate random NT
        self._nt = int.from_bytes(os.urandom(4), 'big')
        nt_bytes = self._nt.to_bytes(4, 'big')

        self._crypto.init(key_num)
        if not self._comm_encrypted:
            self._crypto.word(self._nt ^ cuid, False)
            self._listener_tx(nt_bytes, with_crc=False)
        else:
            ks = (self._nt ^ cuid).to_bytes(4, 'big')
            encrypted_nt = self._crypto.encrypt_with_keystream(nt_bytes, ks)
            self._listener_tx_encrypted(encrypted_nt, with_crc=False)

        self._cmd_in_progress = True
        return True

    def _handle_auth_part2(self, data):
        """Handle MIFARE AUTH second part: verify NR+AR, send AT."""
        if not self._crypto or len(data) < 8:
            self._reset_auth()
            return False

        nr = int.from_bytes(data[:4], 'big')
        ar = int.from_bytes(data[4:8], 'big')

        self._crypto.word(nr, True)
        expected = self._crypto.prng_successor(self._nt, 64)
        actual = ar ^ self._crypto.word(0, False)

        if actual != expected:
            self._reset_auth()
            return False

        at = self._crypto.prng_successor(self._nt, 96)
        at_bytes = at.to_bytes(4, 'big')
        self._listener_tx_encrypted(at_bytes, with_crc=False)

        self._auth_complete = True
        self._comm_encrypted = True
        self._cmd_in_progress = False
        return True

    def _handle_read(self, block_num, data_blocks):
        """Handle MIFARE READ command."""
        if not self._auth_complete:
            return False
        if block_num >= len(data_blocks):
            return False
        auth_sector = _sector_of_block(self._auth_block)
        if _sector_of_block(block_num) != auth_sector:
            return False

        block_data = data_blocks[block_num]
        if _is_sector_trailer(block_num):
            block_data = bytearray(block_data)
            block_data[:6] = b'\x00' * 6   # mask key A
            block_data[10:16] = b'\x00' * 6  # mask key B

        self._listener_tx_encrypted(bytes(block_data))
        return True

    def _handle_write_part1(self, block_num, data_blocks):
        """Handle MIFARE WRITE first part: ACK."""
        if not self._auth_complete:
            return False
        if block_num >= len(data_blocks) or block_num == 0:
            return False
        auth_sector = _sector_of_block(self._auth_block)
        if _sector_of_block(block_num) != auth_sector:
            return False
        self._write_block = block_num
        self._cmd_in_progress = True
        return True

    def _handle_write_part2(self, data, data_blocks):
        """Handle MIFARE WRITE second part: receive data."""
        self._cmd_in_progress = False
        if len(data) < _MF_BLOCK_SIZE:
            return False
        block_num = self._write_block
        if block_num < len(data_blocks):
            data_blocks[block_num] = bytes(data[:_MF_BLOCK_SIZE])
        return True

    # ── Main emulation loop ───────────────────────────────────────────

    def emulate_mifare_classic(self, uid, atqa, sak, data_blocks,
                               keys_a=None, keys_b=None, timeout=60.0,
                               on_auth=None):
        """Emulate a MIFARE Classic card.

        Args:
            uid: Card UID (4 or 7 bytes)
            atqa: ATQA value (2 bytes as int)
            sak: SAK byte
            data_blocks: list of 16-byte blocks (64 for 1K, 256 for 4K)
            keys_a: dict {sector: 6-byte key} for key A (default all FF)
            keys_b: dict {sector: 6-byte key} for key B (default all FF)
            timeout: max emulation time in seconds
            on_auth: callback(key_type, block, nr, ar) called on each auth
        """
        if keys_a is None:
            keys_a = {}
        if keys_b is None:
            keys_b = {}
        data_blocks = [bytearray(b) for b in data_blocks]

        self._setup_target_mode(uid, atqa, sak)
        self._reset_auth()
        self._running = True

        deadline = time.time() + timeout
        while self._running and time.time() < deadline:
            rx = self._listener_rx(timeout_ms=200)
            if rx is None:
                # Check for field-off / WU_A
                if self._drv._stored_irqs & (_I_EOF | _I_WU_A | _I_WU_A_X):
                    self._reset_auth()
                    # Re-enable auto-anticollision
                    self._drv._mod(_PASS_TGT, 0, 0x01)
                    self._drv._cmd(_CMD_GOTO_SENSE)
                continue

            if self._comm_encrypted and self._crypto:
                rx = self._crypto.decrypt_bytes(rx)

            # Strip CRC if present
            if len(rx) >= 3:
                crc = _crc_a(rx[:-2])
                if (rx[-2] == (crc & 0xFF)) and (rx[-1] == ((crc >> 8) & 0xFF)):
                    rx = rx[:-2]

            cmd = rx[0] if rx else 0

            if self._cmd_in_progress:
                if self._auth_complete and not self._write_block:
                    # Auth part 2
                    if not self._handle_auth_part2(rx):
                        self._listener_tx_short(_MF_NACK)
                        self._reset_auth()
                        self._drv._cmd(_CMD_GOTO_SENSE)
                else:
                    # Write part 2
                    if self._handle_write_part2(rx, data_blocks):
                        self._listener_tx_short(_MF_ACK)
                    else:
                        self._listener_tx_short(_MF_NACK)
                    self._cmd_in_progress = False
                continue

            if cmd == _MF_HALT_MSB and len(rx) >= 2 and rx[1] == 0x00:
                self._reset_auth()
                self._drv._mod(_PASS_TGT, 0, 0x01)
                self._drv._cmd(_CMD_GOTO_SLEEP)

            elif cmd in (_MF_AUTH_A, _MF_AUTH_B) and len(rx) >= 2:
                block_num = rx[1]
                if self._handle_auth(cmd, block_num, data_blocks, uid, keys_a, keys_b):
                    if on_auth:
                        on_auth(0 if cmd == _MF_AUTH_A else 1, block_num)
                else:
                    self._listener_tx_short(_MF_NACK)
                    self._reset_auth()

            elif cmd == _MF_READ and len(rx) >= 2:
                if not self._handle_read(rx[1], data_blocks):
                    self._listener_tx_short(_MF_NACK)
                    self._reset_auth()

            elif cmd == _MF_WRITE and len(rx) >= 2:
                if self._handle_write_part1(rx[1], data_blocks):
                    self._listener_tx_short(_MF_ACK)
                else:
                    self._listener_tx_short(_MF_NACK)
                    self._reset_auth()

            else:
                self._listener_tx_short(_MF_NACK)
                self._reset_auth()
                self._drv._cmd(_CMD_GOTO_SENSE)

        self._running = False
        self._drv._cmd(_CMD_STOP_ALL)
        return data_blocks

    def emulate_mifare_ultralight(self, uid, pages, timeout=60.0):
        """Emulate a MIFARE Ultralight / NTAG card.

        Args:
            uid: 7-byte UID
            pages: list of 4-byte pages
            timeout: max emulation time
        """
        atqa = 0x0044  # MIFARE Ultralight ATQA
        sak = 0x00     # SAK for Ultralight
        self._setup_target_mode(uid, atqa, sak)
        self._running = True

        deadline = time.time() + timeout
        while self._running and time.time() < deadline:
            rx = self._listener_rx(timeout_ms=200)
            if rx is None:
                if self._drv._stored_irqs & (_I_EOF | _I_WU_A | _I_WU_A_X):
                    self._drv._mod(_PASS_TGT, 0, 0x01)
                    self._drv._cmd(_CMD_GOTO_SENSE)
                continue

            if len(rx) >= 3:
                crc = _crc_a(rx[:-2])
                if (rx[-2] == (crc & 0xFF)) and (rx[-1] == ((crc >> 8) & 0xFF)):
                    rx = rx[:-2]

            cmd = rx[0] if rx else 0

            if cmd == _MF_READ and len(rx) >= 2:
                page = rx[1]
                # Ultralight READ returns 4 consecutive pages (16 bytes)
                resp = bytearray()
                for i in range(4):
                    p = (page + i) % len(pages)
                    resp.extend(pages[p][:4] if p < len(pages) else b'\x00' * 4)
                self._listener_tx(resp)

            elif cmd == 0xA2 and len(rx) >= 6:
                # WRITE (1 page = 4 bytes)
                page = rx[1]
                if 2 <= page < len(pages):
                    pages[page] = bytes(rx[2:6])
                    self._listener_tx_short(_MF_ACK)
                else:
                    self._listener_tx_short(_MF_NACK)

            elif cmd == 0x60 and len(rx) >= 2:
                # GET_VERSION (NTAG)
                self._listener_tx(b'\x00\x04\x04\x02\x01\x00\x11\x03')

            elif cmd == _MF_HALT_MSB:
                self._drv._mod(_PASS_TGT, 0, 0x01)
                self._drv._cmd(_CMD_GOTO_SLEEP)

            else:
                self._listener_tx_short(_MF_NACK)

        self._running = False
        self._drv._cmd(_CMD_STOP_ALL)
        return pages

    def emulate_uid_only(self, uid, atqa, sak, timeout=60.0):
        """Emulate a card that only responds with UID (for UID-only access systems).

        The ST25R3916 handles anticollision automatically in target mode.
        This function just keeps the emulation alive.
        """
        self._setup_target_mode(uid, atqa, sak)
        self._running = True

        deadline = time.time() + timeout
        while self._running and time.time() < deadline:
            rx = self._listener_rx(timeout_ms=500)
            if rx is None:
                if self._drv._stored_irqs & (_I_EOF | _I_WU_A | _I_WU_A_X):
                    self._drv._mod(_PASS_TGT, 0, 0x01)
                    self._drv._cmd(_CMD_GOTO_SENSE)
                continue
            # Respond NACK to anything after SELECT (UID-only)
            self._listener_tx_short(_MF_NACK)
            self._drv._mod(_PASS_TGT, 0, 0x01)
            self._drv._cmd(_CMD_GOTO_SENSE)

        self._running = False
        self._drv._cmd(_CMD_STOP_ALL)

    # ── ISO-DEP (ISO14443-4) relay target ────────────────────────────

    def relay_iso_dep(self, uid, atqa, sak, ats, apdu_cb,
                      on_event=None, should_stop=None, idle_timeout=180.0):
        """Present as an ISO-DEP card to a terminal and relay each application
        APDU to a remote reader through ``apdu_cb`` (the EvilRelay emulator role).

        The ST25R3916 auto-resolves ISO14443-A anticollision in target mode; this
        loop answers RATS/PPS itself (ATS forged from the reader's IDENT) and
        relays assembled I-block APDUs, handling I/R/S-block chaining both ways.

        Args:
            uid, atqa, sak: card identity captured by the remote reader (IDENT).
            ats: full ATS bytes (TL-first) to answer RATS; a sane default is used
                 when empty.
            apdu_cb(apdu: bytes) -> bytes | None: forward one terminal APDU to the
                 remote card; return its response, or None on link loss.
            on_event(dict): optional UI hook (keys: state, apdu, resp, count, fsd).
            should_stop() -> bool: optional cooperative stop check (polled between
                 RF frames, ~5x/s), used to exit on a key press.
            idle_timeout: seconds with no RF field before giving up.

        Returns the number of relayed APDUs.
        """
        def emit(**kw):
            if on_event:
                try:
                    on_event(kw)
                except Exception:
                    pass

        # Force the ISO14443-4 bit so the terminal issues RATS, and provide a
        # default ATS (FSCI=8 -> 256-byte frames, FWI=14 -> ~4.9 s FWT) when the
        # reader could not expose the real one.
        sak4 = (sak | 0x20) & 0xFF
        ats = bytes(ats) if ats else bytes([0x05, 0x78, 0x80, 0xE0, 0x00])

        # FSD (max frame the terminal accepts) decoded from the RATS FSDI nibble.
        _FSD = {0: 16, 1: 24, 2: 32, 3: 40, 4: 48, 5: 64, 6: 96, 7: 128, 8: 256}

        self._setup_target_mode(uid, atqa, sak4)
        self._running = True
        count = 0
        fsd = 256
        last_field = time.time()
        rx_chain = bytearray()  # reader -> card I-block chaining assembly

        while self._running and (should_stop is None or not should_stop()):
            rx = self._listener_rx(timeout_ms=200)
            if rx is None:
                if time.time() - last_field > idle_timeout:
                    break
                if self._drv._stored_irqs & (_I_EOF | _I_WU_A | _I_WU_A_X):
                    self._drv._mod(_PASS_TGT, 0, 0x01)
                    self._drv._cmd(_CMD_GOTO_SENSE)
                    rx_chain = bytearray()
                continue
            last_field = time.time()

            # Strip + verify the CRC_A the hardware appended.
            if len(rx) >= 3:
                crc = _crc_a(rx[:-2])
                if rx[-2] == (crc & 0xFF) and rx[-1] == ((crc >> 8) & 0xFF):
                    rx = rx[:-2]
                else:
                    continue  # bad CRC -> let the terminal retransmit
            if not rx:
                continue
            pcb = rx[0]

            # ---- RATS (answer with the forged ATS) ----
            if pcb == 0xE0 and len(rx) >= 2:
                fsd = _FSD.get((rx[1] >> 4) & 0x0F, 256)
                self._listener_tx(ats, with_crc=True)
                emit(state="rats", fsd=fsd)
                continue

            # ---- PPS (echo the PPSS, accept the proposed rates) ----
            if (pcb & 0xF0) == 0xD0:
                self._listener_tx(bytes([pcb]), with_crc=True)
                emit(state="pps")
                continue

            # ---- S-block (DESELECT / WTX) ----
            if (pcb & 0xC0) == 0xC0:
                self._listener_tx(bytes([pcb]), with_crc=True)
                if (pcb & 0x30) == 0x00:  # DESELECT -> drop back to anticollision
                    self._drv._mod(_PASS_TGT, 0, 0x01)
                    self._drv._cmd(_CMD_GOTO_SENSE)
                    rx_chain = bytearray()
                    emit(state="deselect")
                continue

            # ---- R-block (stray ACK/NAK outside chaining) ----
            if (pcb & 0xE6) == 0xA2:
                self._listener_tx(bytes([0xA2 | (pcb & 0x01)]), with_crc=True)
                continue

            # ---- I-block (carries the application APDU) ----
            if (pcb & 0xE2) == 0x02:
                blk = pcb & 0x01
                idx = 1
                if pcb & 0x08:  # CID present
                    idx += 1
                if pcb & 0x04:  # NAD present
                    idx += 1
                rx_chain += bytes(rx[idx:])
                if pcb & 0x10:  # reader is chaining -> ACK and keep assembling
                    self._listener_tx(bytes([0xA2 | blk]), with_crc=True)
                    continue
                apdu = bytes(rx_chain)
                rx_chain = bytearray()
                emit(state="apdu", apdu=apdu)
                resp = apdu_cb(apdu)
                if resp is None:
                    emit(state="linklost")
                    break
                count += 1
                emit(state="relayed", count=count, apdu=apdu, resp=resp)
                self._iso_dep_send_response(resp, blk, fsd)
                continue

            # Unknown frame -> ignore and wait for the next.

        self._running = False
        try:
            self._drv._cmd(_CMD_STOP_ALL)
        except Exception:
            pass
        return count

    def _iso_dep_send_response(self, resp, blk, fsd):
        """Send an application response as one or more I-blocks, chaining out when
        it exceeds the terminal's frame size (FSD)."""
        max_inf = max(1, min(fsd, 256) - 3)  # minus PCB(1) + CRC(2)
        resp = bytes(resp)
        n = len(resp)
        if n == 0:
            self._listener_tx(bytes([0x02 | blk]), with_crc=True)
            return
        off = 0
        while off < n:
            chunk = resp[off:off + max_inf]
            off += len(chunk)
            more = off < n
            pcb = 0x02 | blk | (0x10 if more else 0x00)
            self._listener_tx(bytes([pcb]) + chunk, with_crc=True)
            if not more:
                break
            # Chaining out: wait for the terminal's R(ACK) before the next chunk.
            r = self._listener_rx(timeout_ms=300)
            if r is None:
                return
            if len(r) >= 3:
                rc = _crc_a(r[:-2])
                if r[-2] == (rc & 0xFF) and r[-1] == ((rc >> 8) & 0xFF):
                    r = r[:-2]
            if not r or (r[0] & 0xE6) != 0xA2:
                return  # not an R-block -> abort this response

    # ── mfkey32 reader-nonce capture ──────────────────────────────────

    def _listener_rx_raw(self, nbytes, timeout_ms=40):
        """Receive one frame with parity disabled and unpack the 9-bit groups.

        With no_rx_par set the FIFO holds raw bits D7..D0 P D7..D0 P ...; this
        strips every 9th (parity) bit and returns ``nbytes`` data bytes (mirrors
        Evil's mfe_rx_raw / the MIFARE read unpack). Returns None on timeout.
        """
        d = self._drv
        d._wr(_ISO14443A, d._rr(_ISO14443A) | 0xC0)  # no_tx_par + no_rx_par
        flags = d._wait_irq(_I_RXE | _I_NRE | _I_EOF | _I_CRC_ERR | _I_PAR_ERR, timeout_ms)
        if not (flags & _I_RXE):
            return None
        n = d._fifo_len()
        if n <= 0:
            return None
        raw = d._fifo_r(n)
        out = bytearray()
        bit = 0
        total = len(raw) * 8
        while bit + 8 <= total and len(out) < nbytes:
            v = 0
            for b in range(8):
                by = (bit + b) // 8
                bi = (bit + b) % 8
                if raw[by] & (1 << bi):
                    v |= (1 << b)
            out.append(v)
            bit += 9  # skip the parity bit
        return bytes(out)

    def capture_mfkey32(self, uid, atqa, sak, on_event=None, should_stop=None,
                        max_captures=24, idle_timeout=180.0):
        """Emulate a MIFARE Classic card and capture reader-nonce tuples for mfkey32.

        Presents the given identity, answers every reader AUTH (0x60/0x61) with a
        FIXED tag nonce (MFE_STATIC_NT), and records the reader's encrypted
        {nr, ar}. No sector key is needed; the returned tuples feed an offline
        mfkey32 solver (see nfc_rfid/_mfkey32.py). Faithful to Evil's
        nfc_mfemul.h capture path (mode 1). Reuses the existing target-mode
        primitives; it does NOT run Crypto1 and never touches the emulate_* /
        relay_iso_dep paths.

        Returns a list of dicts: {uid, block, keytype, nt, nr, ar} (ints).
        """
        d = self._drv
        self._setup_target_mode(uid, atqa, sak)
        self._running = True
        caps = []
        cuid = int.from_bytes(bytes(uid[:4]), 'big')
        nt = 0x01200145  # mirrors nfc_rfid/_mfkey32.MFE_STATIC_NT (Evil MFE_STATIC_NT)
        ntb = nt.to_bytes(4, 'big')
        last_field = time.time()

        while self._running and (should_stop is None or not should_stop()):
            rx = self._listener_rx(timeout_ms=200)
            if rx is None:
                if time.time() - last_field > idle_timeout:
                    break
                if d._stored_irqs & (_I_EOF | _I_WU_A | _I_WU_A_X):
                    d._mod(_PASS_TGT, 0, 0x01)
                    d._cmd(_CMD_GOTO_SENSE)
                continue
            last_field = time.time()

            if len(rx) >= 3:
                crc = _crc_a(rx[:-2])
                if rx[-2] == (crc & 0xFF) and rx[-1] == ((crc >> 8) & 0xFF):
                    rx = rx[:-2]

            if len(rx) >= 2 and rx[0] in (_MF_AUTH_A, _MF_AUTH_B):
                keytype = rx[0]
                block = rx[1]
                # Answer with the static nt ASAP (plaintext, std parity, no CRC).
                self._listener_tx(ntb, with_crc=False)
                # Reader replies {nr,ar} encrypted -> capture raw (no parity).
                na = self._listener_rx_raw(8, timeout_ms=40)
                d._wr(_ISO14443A, d._rr(_ISO14443A) & ~0xC0)  # restore std parity
                if na and len(na) >= 8:
                    nr = int.from_bytes(na[:4], 'big')
                    ar = int.from_bytes(na[4:8], 'big')
                    dup = any(c['nr'] == nr and c['ar'] == ar and
                              c['block'] == block and c['keytype'] == keytype
                              for c in caps)
                    if not dup and len(caps) < max_captures:
                        rec = {'uid': cuid, 'block': block, 'keytype': keytype,
                               'nt': nt, 'nr': nr, 'ar': ar}
                        caps.append(rec)
                        if on_event:
                            try:
                                on_event({'state': 'nonce', 'count': len(caps), 'rec': rec})
                            except Exception:
                                pass
                d._mod(_PASS_TGT, 0, 0x01)
                d._cmd(_CMD_GOTO_SENSE)
            elif rx and rx[0] == _MF_HALT_MSB:
                d._mod(_PASS_TGT, 0, 0x01)
                d._cmd(_CMD_GOTO_SENSE)

        self._running = False
        try:
            d._cmd(_CMD_STOP_ALL)
        except Exception:
            pass
        return caps

    def stop(self):
        """Stop emulation."""
        self._running = False
