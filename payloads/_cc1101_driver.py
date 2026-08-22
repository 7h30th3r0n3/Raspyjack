"""
CC1101 Sub-GHz transceiver driver for CardputerZero Cap HAT.

Hardware: TI CC1101 on SPI0.1, ST25R3916 NFC on SPI0.2 (separate driver).
Power:    ext_5v_out LED class + GPIO26 output HIGH.
Pins:     GDO0=GPIO15 (packet ready), RF_SW0=GPIO14 (antenna band select).

Usage:
    from payloads._cc1101_driver import CC1101

    radio = CC1101()
    if not radio.open():
        print("CC1101 not found")
    radio.set_frequency(433.92)
    radio.start_rx()
    pkt = radio.read_packet(timeout=2.0)
    radio.close()
"""

import os
import time
import struct
import threading

try:
    import spidev
    SPIDEV_OK = True
except ImportError:
    spidev = None
    SPIDEV_OK = False

try:
    import gpiod
    GPIOD_OK = True
except ImportError:
    gpiod = None
    GPIOD_OK = False

# CC1101 SPI command strobes
SRES = 0x30
SRX = 0x34
STX = 0x35
SIDLE = 0x36
SFRX = 0x3A
SFTX = 0x3B
SNOP = 0x3D

# CC1101 status registers (read with burst bit 0xC0)
REG_PARTNUM = 0x30
REG_VERSION = 0x31
REG_FREQEST = 0x32
REG_RSSI = 0x34
REG_MARCSTATE = 0x35
REG_PKTSTATUS = 0x38
REG_RXBYTES = 0x3B
REG_TXBYTES = 0x3A

# CC1101 config registers
REG_IOCFG2 = 0x00
REG_IOCFG1 = 0x01
REG_IOCFG0 = 0x02
REG_FIFOTHR = 0x03
REG_SYNC1 = 0x04
REG_SYNC0 = 0x05
REG_PKTLEN = 0x06
REG_PKTCTRL1 = 0x07
REG_PKTCTRL0 = 0x08
REG_ADDR = 0x09
REG_CHANNR = 0x0A
REG_FSCTRL1 = 0x0B
REG_FSCTRL0 = 0x0C
REG_FREQ2 = 0x0D
REG_FREQ1 = 0x0E
REG_FREQ0 = 0x0F
REG_MDMCFG4 = 0x10
REG_MDMCFG3 = 0x11
REG_MDMCFG2 = 0x12
REG_MDMCFG1 = 0x13
REG_MDMCFG0 = 0x14
REG_DEVIATN = 0x15
REG_MCSM2 = 0x16
REG_MCSM1 = 0x17
REG_MCSM0 = 0x18
REG_FOCCFG = 0x19
REG_BSCFG = 0x1A
REG_AGCCTRL2 = 0x1B
REG_AGCCTRL1 = 0x1C
REG_AGCCTRL0 = 0x1D
REG_FREND1 = 0x21
REG_FREND0 = 0x22
REG_FSCAL3 = 0x23
REG_FSCAL2 = 0x24
REG_FSCAL1 = 0x25
REG_FSCAL0 = 0x26
REG_TEST2 = 0x2C
REG_TEST1 = 0x2D
REG_TEST0 = 0x2E

FIFO_ADDR = 0x3F
PA_TABLE = 0x3E

MARCSTATE_IDLE = 0x01
MARCSTATE_RX = 0x0D
MARCSTATE_TX = 0x13
MARCSTATE_RXFIFO_OVERFLOW = 0x11
MARCSTATE_TXFIFO_UNDERFLOW = 0x16

FOSC = 26_000_000

# Pre-computed radio profiles: (name, register_patch_dict)
# Each profile sets modulation, data rate, bandwidth, deviation.
PROFILES = {
    "2fsk_low": {
        "name": "2-FSK 1.2kbps",
        REG_MDMCFG4: 0xF5, REG_MDMCFG3: 0x83, REG_MDMCFG2: 0x00,
        REG_DEVIATN: 0x15,
        REG_AGCCTRL2: 0x03, REG_AGCCTRL1: 0x40, REG_AGCCTRL0: 0x91,
        REG_FOCCFG: 0x16, REG_BSCFG: 0x6C,
    },
    "2fsk_mid": {
        "name": "2-FSK 38.4kbps",
        REG_MDMCFG4: 0xCA, REG_MDMCFG3: 0x83, REG_MDMCFG2: 0x00,
        REG_DEVIATN: 0x34,
        REG_AGCCTRL2: 0x43, REG_AGCCTRL1: 0x40, REG_AGCCTRL0: 0x91,
        REG_FOCCFG: 0x16, REG_BSCFG: 0x6C,
    },
    "ook_4k8": {
        "name": "OOK/ASK 4.8kbps",
        REG_MDMCFG4: 0x87, REG_MDMCFG3: 0x32, REG_MDMCFG2: 0x30,
        REG_DEVIATN: 0x00,
        REG_AGCCTRL2: 0x04, REG_AGCCTRL1: 0x00, REG_AGCCTRL0: 0x92,
        REG_FOCCFG: 0x16, REG_BSCFG: 0x6C,
        REG_FREND0: 0x11,
    },
    "gfsk_100k": {
        "name": "GFSK 100kbps",
        REG_MDMCFG4: 0x5B, REG_MDMCFG3: 0xF8, REG_MDMCFG2: 0x10,
        REG_DEVIATN: 0x47,
        REG_AGCCTRL2: 0xC7, REG_AGCCTRL1: 0x00, REG_AGCCTRL0: 0xB0,
        REG_FOCCFG: 0x1D, REG_BSCFG: 0x1C,
    },
}

# Default register config (after reset, then patched for packet mode)
_DEFAULT_CONFIG = {
    REG_IOCFG2: 0x29,
    REG_IOCFG0: 0x06,   # GDO0 = asserts on sync word, deasserts end of packet
    REG_FIFOTHR: 0x47,
    REG_SYNC1: 0xD3, REG_SYNC0: 0x91,
    REG_PKTLEN: 0x3D,   # max 61 bytes
    REG_PKTCTRL1: 0x04, # append status (RSSI+LQI+CRC_OK)
    REG_PKTCTRL0: 0x05, # variable length, CRC enabled, whitening
    REG_ADDR: 0x00,
    REG_CHANNR: 0x00,
    REG_FSCTRL1: 0x06,
    REG_FSCTRL0: 0x00,
    REG_MDMCFG1: 0x22,
    REG_MDMCFG0: 0xF8,
    REG_MCSM2: 0x07,
    REG_MCSM1: 0x30,   # CCA mode, stay in RX after packet, go to IDLE after TX
    REG_MCSM0: 0x18,
    REG_FREND1: 0x56,
    REG_FREND0: 0x10,
    REG_FSCAL3: 0xE9,
    REG_FSCAL2: 0x2A,
    REG_FSCAL1: 0x00,
    REG_FSCAL0: 0x1F,
    REG_TEST2: 0x81,
    REG_TEST1: 0x35,
    REG_TEST0: 0x09,
}

# PA table for ~+10 dBm at each band
_PA_TABLE_BY_BAND = {
    315: [0xC0],
    433: [0xC0],
    868: [0xC2],
    915: [0xC0],
}

# RF switch GPIO14 values per band (from M5Stack binary)
# GPIO14 = RF_SW0 controls antenna path
_RF_SW_BY_BAND = {
    315: 0,
    433: 0,
    868: 1,
    915: 1,
}


class CC1101:
    """CC1101 transceiver driver for CardputerZero Cap HAT."""

    def __init__(self, spi_bus=0, spi_cs=1, speed_hz=500000,
                 gpio_chip="/dev/gpiochip0", gdo0_line=15,
                 rf_sw0_line=14, power_line=26):
        self._spi_bus = spi_bus
        self._spi_cs = spi_cs
        self._speed = speed_hz
        self._gpio_chip_path = gpio_chip
        self._gdo0_line = gdo0_line
        self._rf_sw0_line = rf_sw0_line
        self._power_line = power_line

        self._spi = None
        self._gpio_req = None
        self._freq_mhz = 433.92
        self._profile = "2fsk_mid"
        self._opened = False
        self._lock = threading.Lock()

    def open(self):
        if self._opened:
            return True
        if not SPIDEV_OK or not GPIOD_OK:
            return False
        try:
            self._power_on()
            time.sleep(0.3)
            self._spi = spidev.SpiDev()
            self._spi.open(self._spi_bus, self._spi_cs)
            self._spi.max_speed_hz = self._speed
            self._spi.mode = 0
            self._reset()
            time.sleep(0.05)
            ver = self._read_status(REG_VERSION)
            if ver == 0x00 or ver == 0xFF:
                self.close()
                return False
            self._apply_config()
            self.set_frequency(self._freq_mhz)
            self._opened = True
            return True
        except Exception:
            self.close()
            return False

    def close(self):
        self._opened = False
        if self._spi:
            try:
                self._strobe(SIDLE)
            except Exception:
                pass
            try:
                self._spi.close()
            except Exception:
                pass
            self._spi = None
        self._power_off()

    def _power_on(self):
        try:
            with open("/sys/class/leds/ext_5v_out/brightness", "w") as f:
                f.write("1")
        except Exception:
            pass
        try:
            chip = gpiod.Chip(self._gpio_chip_path)
            config = gpiod.LineSettings(
                direction=gpiod.line.Direction.OUTPUT,
                output_value=gpiod.line.Value.ACTIVE,
            )
            self._gpio_req = chip.request_lines(
                config={self._power_line: config, self._rf_sw0_line: config},
                consumer="raspyjack-cc1101",
            )
        except Exception:
            pass

    def _power_off(self):
        if self._gpio_req:
            try:
                self._gpio_req.release()
            except Exception:
                pass
            self._gpio_req = None

    def _set_rf_switch(self, band_mhz):
        band = int(band_mhz)
        for b in (315, 433, 868, 915):
            if abs(band - b) < 50:
                val = _RF_SW_BY_BAND[b]
                break
        else:
            val = 0
        if self._gpio_req:
            try:
                lv = gpiod.line.Value.ACTIVE if val else gpiod.line.Value.INACTIVE
                self._gpio_req.set_value(self._rf_sw0_line, lv)
            except Exception:
                pass

    def _strobe(self, cmd):
        with self._lock:
            r = self._spi.xfer2([cmd])
            return r[0] if r else 0

    def _write_reg(self, addr, value):
        with self._lock:
            self._spi.xfer2([addr, value])

    def _read_reg(self, addr):
        with self._lock:
            r = self._spi.xfer2([addr | 0x80, 0x00])
            return r[1]

    def _read_status(self, addr):
        with self._lock:
            r = self._spi.xfer2([addr | 0xC0, 0x00])
            return r[1]

    def _write_burst(self, addr, data):
        with self._lock:
            self._spi.xfer2([addr | 0x40] + list(data))

    def _read_burst(self, addr, length):
        with self._lock:
            r = self._spi.xfer2([addr | 0xC0] + [0x00] * length)
            return r[1:]

    def _reset(self):
        self._strobe(SRES)
        time.sleep(0.01)

    def _apply_config(self):
        for reg, val in _DEFAULT_CONFIG.items():
            self._write_reg(reg, val)
        profile = PROFILES.get(self._profile, PROFILES["2fsk_mid"])
        for reg, val in profile.items():
            if isinstance(reg, int):
                self._write_reg(reg, val)

    def _set_pa_table(self, band_mhz):
        band = int(band_mhz)
        for b in (315, 433, 868, 915):
            if abs(band - b) < 50:
                pa = _PA_TABLE_BY_BAND[b]
                break
        else:
            pa = [0xC0]
        self._write_burst(PA_TABLE, pa)

    # -- Public API --

    def set_profile(self, name):
        if name not in PROFILES:
            return False
        self._profile = name
        if self._opened:
            self._strobe(SIDLE)
            profile = PROFILES[name]
            for reg, val in profile.items():
                if isinstance(reg, int):
                    self._write_reg(reg, val)
        return True

    def set_frequency(self, freq_mhz):
        self._freq_mhz = freq_mhz
        freq_hz = int(freq_mhz * 1_000_000)
        freq_word = int(freq_hz * (2**16) / FOSC)
        self._write_reg(REG_FREQ2, (freq_word >> 16) & 0xFF)
        self._write_reg(REG_FREQ1, (freq_word >> 8) & 0xFF)
        self._write_reg(REG_FREQ0, freq_word & 0xFF)
        self._set_rf_switch(freq_mhz)
        self._set_pa_table(freq_mhz)

    def get_frequency(self):
        return self._freq_mhz

    def idle(self):
        self._strobe(SIDLE)

    def start_rx(self):
        self._strobe(SIDLE)
        self._strobe(SFRX)
        self._strobe(SRX)

    def start_tx(self):
        self._strobe(STX)

    def get_rssi(self):
        raw = self._read_status(REG_RSSI)
        if raw >= 128:
            rssi = (raw - 256) / 2.0 - 74
        else:
            rssi = raw / 2.0 - 74
        return rssi

    def get_marcstate(self):
        return self._read_status(REG_MARCSTATE) & 0x1F

    def get_version(self):
        return self._read_status(REG_VERSION)

    def read_packet(self, timeout=2.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            state = self.get_marcstate()
            if state == MARCSTATE_RXFIFO_OVERFLOW:
                self._strobe(SFRX)
                self._strobe(SRX)
                continue
            rxbytes = self._read_status(REG_RXBYTES)
            if rxbytes & 0x7F:
                pkt_len = self._read_reg(FIFO_ADDR)
                if pkt_len == 0 or pkt_len > 61:
                    self._strobe(SFRX)
                    self._strobe(SRX)
                    continue
                data = self._read_burst(FIFO_ADDR, pkt_len + 2)
                payload = bytes(data[:pkt_len])
                rssi_raw = data[pkt_len]
                lqi_crc = data[pkt_len + 1]
                crc_ok = bool(lqi_crc & 0x80)
                lqi = lqi_crc & 0x7F
                if rssi_raw >= 128:
                    rssi = (rssi_raw - 256) / 2.0 - 74
                else:
                    rssi = rssi_raw / 2.0 - 74
                if state != MARCSTATE_RX:
                    self._strobe(SRX)
                return {
                    "data": payload,
                    "rssi": rssi,
                    "lqi": lqi,
                    "crc_ok": crc_ok,
                    "length": pkt_len,
                }
            time.sleep(0.01)
        return None

    def send_packet(self, data):
        if len(data) > 61:
            data = data[:61]
        self._strobe(SIDLE)
        self._strobe(SFTX)
        self._write_burst(FIFO_ADDR, [len(data)] + list(data))
        self._strobe(STX)
        deadline = time.time() + 2.0
        while time.time() < deadline:
            state = self.get_marcstate()
            if state == MARCSTATE_IDLE or state == MARCSTATE_RX:
                return True
            if state == MARCSTATE_TXFIFO_UNDERFLOW:
                self._strobe(SFTX)
                return False
            time.sleep(0.005)
        return False

    def set_raw_rx(self):
        self._strobe(SIDLE)
        self._write_reg(REG_IOCFG0, 0x0D)
        self._write_reg(REG_PKTCTRL0, 0x32)
        self._strobe(SFRX)
        self._strobe(SRX)

    def set_packet_rx(self):
        self._strobe(SIDLE)
        self._write_reg(REG_IOCFG0, 0x06)
        self._write_reg(REG_PKTCTRL0, 0x05)
        self._strobe(SFRX)
        self._strobe(SRX)

    def detect_hat():
        if not SPIDEV_OK:
            return False
        if not os.path.exists("/dev/spidev0.1"):
            return False
        try:
            with open("/sys/class/leds/ext_5v_out/brightness", "w") as f:
                f.write("1")
            time.sleep(0.1)
            if GPIOD_OK:
                chip = gpiod.Chip("/dev/gpiochip0")
                config = gpiod.LineSettings(
                    direction=gpiod.line.Direction.OUTPUT,
                    output_value=gpiod.line.Value.ACTIVE,
                )
                req = chip.request_lines(config={26: config}, consumer="cc1101-detect")
                time.sleep(0.15)
            spi = spidev.SpiDev()
            spi.open(0, 1)
            spi.max_speed_hz = 500000
            spi.mode = 0
            spi.xfer2([SRES])
            time.sleep(0.01)
            r = spi.xfer2([REG_VERSION | 0xC0, 0x00])
            spi.close()
            if GPIOD_OK:
                req.release()
            return r[1] not in (0x00, 0xFF)
        except Exception:
            return False
    detect_hat = staticmethod(detect_hat)
