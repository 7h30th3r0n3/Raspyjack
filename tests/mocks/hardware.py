"""
Hardware mock classes for RaspyJack test suite.

These mocks replace RPi.GPIO, LCD_1in44, LCD_Config, spidev, smbus/smbus2,
pyudev, serial, and rj_input so that payload tests can run on any machine
without Raspberry Pi hardware.
"""

import types
from unittest.mock import MagicMock


# ---------------------------------------------------------------------------
# RPi.GPIO mock
# ---------------------------------------------------------------------------

class MockGPIO:
    """Drop-in replacement for the RPi.GPIO module."""

    BCM = 11
    BOARD = 10
    IN = 0
    OUT = 1
    HIGH = 1
    LOW = 0
    PUD_UP = 22
    PUD_DOWN = 21
    PUD_OFF = 20
    RISING = 31
    FALLING = 32
    BOTH = 33

    _mode = None
    _pin_states: dict = {}

    @classmethod
    def setmode(cls, mode):
        cls._mode = mode

    @classmethod
    def getmode(cls):
        return cls._mode

    @classmethod
    def setwarnings(cls, flag):
        pass

    @classmethod
    def setup(cls, channel, direction, pull_up_down=None, initial=None):
        # For input pins, default to 1 (not pressed -- GPIO buttons are
        # active-low).  For output pins, default to 0.
        if initial is not None:
            default = initial
        elif direction == cls.IN:
            default = 1
        else:
            default = 0

        if isinstance(channel, (list, tuple)):
            for ch in channel:
                cls._pin_states[ch] = default
        else:
            cls._pin_states[channel] = default

    @classmethod
    def input(cls, channel):
        """Return 1 (not pressed) by default -- GPIO buttons are active-low."""
        return cls._pin_states.get(channel, 1)

    @classmethod
    def output(cls, channel, value):
        if isinstance(channel, (list, tuple)):
            for ch in channel:
                cls._pin_states[ch] = value
        else:
            cls._pin_states[channel] = value

    @classmethod
    def cleanup(cls, channel=None):
        if channel is None:
            cls._pin_states.clear()
            cls._mode = None
        elif isinstance(channel, (list, tuple)):
            for ch in channel:
                cls._pin_states.pop(ch, None)
        else:
            cls._pin_states.pop(channel, None)

    @classmethod
    def add_event_detect(cls, channel, edge, callback=None, bouncetime=None):
        pass

    @classmethod
    def remove_event_detect(cls, channel):
        pass

    @classmethod
    def event_detected(cls, channel):
        return False

    @classmethod
    def wait_for_edge(cls, channel, edge, bouncetime=None, timeout=None):
        return channel

    @classmethod
    def gpio_function(cls, channel):
        return cls.IN

    @classmethod
    def reset(cls):
        """Reset all internal state -- call between tests."""
        cls._mode = None
        cls._pin_states = {}


def _build_gpio_module():
    """Build a module-like object that behaves like ``import RPi.GPIO``."""
    mod = types.ModuleType("RPi.GPIO")
    for attr in dir(MockGPIO):
        if not attr.startswith("_"):
            setattr(mod, attr, getattr(MockGPIO, attr))
    return mod


def _build_rpi_package():
    """Build a fake ``RPi`` package containing a ``GPIO`` sub-module."""
    rpi = types.ModuleType("RPi")
    rpi.__path__ = []
    rpi.GPIO = _build_gpio_module()
    return rpi


# ---------------------------------------------------------------------------
# LCD_1in44 mock
# ---------------------------------------------------------------------------

class MockLCD:
    """Mock for the LCD_1in44.LCD class."""

    SCAN_DIR_DFT = 6  # U2D_R2L from the real module
    width = 128
    height = 128

    def __init__(self):
        self.width = 128
        self.height = 128
        self.LCD_Scan_Dir = self.SCAN_DIR_DFT
        self.LCD_X_Adjust = 2
        self.LCD_Y_Adjust = 1
        self._initialized = False
        self._last_image = None

    def LCD_Init(self, scan_dir=None):
        self._initialized = True
        return 0

    def LCD_ShowImage(self, image, x_start=0, y_start=0):
        self._last_image = image

    def LCD_Clear(self):
        self._last_image = None

    def LCD_SetWindows(self, x_start, y_start, x_end, y_end):
        pass

    def LCD_WriteReg(self, reg):
        pass

    def LCD_WriteData_8bit(self, data):
        pass


def _build_lcd_1in44_module():
    """Build a fake ``LCD_1in44`` module."""
    mod = types.ModuleType("LCD_1in44")
    mod.LCD = MockLCD
    mod.SCAN_DIR_DFT = MockLCD.SCAN_DIR_DFT
    mod.LCD_WIDTH = 128
    mod.LCD_HEIGHT = 128
    mod.LCD_1IN44 = 1
    mod.LCD_1IN8 = 0
    # Scanning direction constants from the real module
    mod.L2R_U2D = 1
    mod.L2R_D2U = 2
    mod.R2L_U2D = 3
    mod.R2L_D2U = 4
    mod.U2D_L2R = 5
    mod.U2D_R2L = 6
    mod.D2U_L2R = 7
    mod.D2U_R2L = 8
    return mod


# ---------------------------------------------------------------------------
# LCD_Config mock
# ---------------------------------------------------------------------------

class MockLCDConfig:
    """Namespace holding the constants and helpers from LCD_Config."""

    LCD_RST_PIN = 27
    LCD_DC_PIN = 25
    LCD_CS_PIN = 8
    LCD_BL_PIN = 24

    @staticmethod
    def GPIO_Init():
        return 0

    @staticmethod
    def Driver_Delay_ms(xms):
        pass

    @staticmethod
    def SPI_Write_Byte(data):
        pass


def _build_lcd_config_module():
    """Build a fake ``LCD_Config`` module."""
    mod = types.ModuleType("LCD_Config")
    for attr in ("LCD_RST_PIN", "LCD_DC_PIN", "LCD_CS_PIN", "LCD_BL_PIN",
                 "GPIO_Init", "Driver_Delay_ms", "SPI_Write_Byte"):
        setattr(mod, attr, getattr(MockLCDConfig, attr))
    # Provide a mock SPI attribute (some code references LCD_Config.SPI)
    mod.SPI = MagicMock()
    return mod


# ---------------------------------------------------------------------------
# spidev mock
# ---------------------------------------------------------------------------

class MockSpiDev:
    """Mock for spidev.SpiDev."""

    def __init__(self, bus=0, device=0):
        self.max_speed_hz = 0
        self.mode = 0
        self._bus = bus
        self._device = device

    def open(self, bus, device):
        self._bus = bus
        self._device = device

    def close(self):
        pass

    def writebytes(self, data):
        pass

    def writebytes2(self, data):
        pass

    def readbytes(self, length):
        return [0] * length

    def xfer(self, data):
        return [0] * len(data)

    def xfer2(self, data):
        return [0] * len(data)


def _build_spidev_module():
    """Build a fake ``spidev`` module."""
    mod = types.ModuleType("spidev")
    mod.SpiDev = MockSpiDev
    return mod


# ---------------------------------------------------------------------------
# smbus / smbus2 mock
# ---------------------------------------------------------------------------

class MockSMBus:
    """Mock for smbus.SMBus / smbus2.SMBus."""

    def __init__(self, bus=1):
        self._bus = bus

    def open(self, bus):
        self._bus = bus

    def close(self):
        pass

    def read_byte(self, addr):
        return 0

    def write_byte(self, addr, value):
        pass

    def read_byte_data(self, addr, register):
        return 0

    def write_byte_data(self, addr, register, value):
        pass

    def read_word_data(self, addr, register):
        return 0

    def write_word_data(self, addr, register, value):
        pass

    def read_i2c_block_data(self, addr, register, length):
        return [0] * length

    def write_i2c_block_data(self, addr, register, data):
        pass

    def read_block_data(self, addr, register):
        return [0] * 32

    def write_block_data(self, addr, register, data):
        pass

    def write_quick(self, addr):
        pass

    def process_call(self, addr, register, value):
        return 0


def _build_smbus_module(name="smbus"):
    """Build a fake ``smbus`` or ``smbus2`` module."""
    mod = types.ModuleType(name)
    mod.SMBus = MockSMBus
    return mod


# ---------------------------------------------------------------------------
# pyudev mock
# ---------------------------------------------------------------------------

def _build_pyudev_module():
    """Build a fake ``pyudev`` module with Context and Monitor stubs."""
    mod = types.ModuleType("pyudev")

    class FakeContext:
        def list_devices(self, **kwargs):
            return []

    class FakeMonitor:
        def __init__(self, *args, **kwargs):
            pass

        @classmethod
        def from_netlink(cls, context, source="udev"):
            return cls()

        def filter_by(self, subsystem=None, device_type=None):
            pass

        def poll(self, timeout=None):
            return None

        def start(self):
            pass

    class FakeMonitorObserver:
        def __init__(self, monitor, callback=None, *args, **kwargs):
            pass

        def start(self):
            pass

        def stop(self):
            pass

    mod.Context = FakeContext
    mod.Monitor = FakeMonitor
    mod.MonitorObserver = FakeMonitorObserver
    return mod


# ---------------------------------------------------------------------------
# serial (pyserial) mock
# ---------------------------------------------------------------------------

class MockSerial:
    """Mock for serial.Serial."""

    def __init__(self, port=None, baudrate=9600, timeout=None, **kwargs):
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.is_open = True
        self._read_buffer = b""

    def open(self):
        self.is_open = True

    def close(self):
        self.is_open = False

    def read(self, size=1):
        data = self._read_buffer[:size]
        self._read_buffer = self._read_buffer[size:]
        return data

    def readline(self):
        idx = self._read_buffer.find(b"\n")
        if idx == -1:
            data = self._read_buffer
            self._read_buffer = b""
            return data
        data = self._read_buffer[: idx + 1]
        self._read_buffer = self._read_buffer[idx + 1 :]
        return data

    def write(self, data):
        return len(data)

    def flush(self):
        pass

    def reset_input_buffer(self):
        self._read_buffer = b""

    def reset_output_buffer(self):
        pass

    @property
    def in_waiting(self):
        return len(self._read_buffer)


def _build_serial_module():
    """Build a fake ``serial`` module."""
    mod = types.ModuleType("serial")
    mod.Serial = MockSerial
    mod.EIGHTBITS = 8
    mod.PARITY_NONE = "N"
    mod.STOPBITS_ONE = 1
    mod.SerialException = type("SerialException", (IOError,), {})
    return mod


# ---------------------------------------------------------------------------
# rj_input mock
# ---------------------------------------------------------------------------

class MockRjInput:
    """Mock for the rj_input virtual-input module."""

    def __init__(self):
        self._next_button = None

    @staticmethod
    def get_virtual_button():
        """Always returns None (no virtual button pressed)."""
        return None

    @staticmethod
    def restart_listener():
        pass


def _build_rj_input_module():
    """Build a fake ``rj_input`` module."""
    mod = types.ModuleType("rj_input")
    mock = MockRjInput()
    mod.get_virtual_button = mock.get_virtual_button
    mod.restart_listener = mock.restart_listener
    mod._BTN_MAP = {}
    return mod


# ---------------------------------------------------------------------------
# scapy mock (minimal -- just enough so imports don't fail)
# ---------------------------------------------------------------------------

def _build_scapy_modules():
    """Return a dict of scapy sub-module stubs to inject into sys.modules."""
    scapy_root = types.ModuleType("scapy")
    scapy_root.__path__ = []

    scapy_all = types.ModuleType("scapy.all")
    # Provide commonly used scapy names as MagicMocks
    for name in ("ARP", "Ether", "IP", "TCP", "UDP", "ICMP", "DNS", "DNSQR",
                 "DNSRR", "Raw", "srp", "sr1", "send", "sendp", "sniff",
                 "conf", "get_if_list", "get_if_addr", "wrpcap", "rdpcap",
                 "Dot11", "Dot11Beacon", "Dot11Deauth", "Dot11Auth",
                 "Dot11ProbeReq", "Dot11ProbeResp",
                 "RadioTap", "Dot11Elt", "hexdump",
                 "NBNSQueryRequest"):
        setattr(scapy_all, name, MagicMock())

    scapy_layers = types.ModuleType("scapy.layers")
    scapy_layers.__path__ = []

    modules = {
        "scapy": scapy_root,
        "scapy.all": scapy_all,
        "scapy.layers": scapy_layers,
        "scapy.layers.l2": MagicMock(),
        "scapy.layers.inet": MagicMock(),
        "scapy.layers.inet6": MagicMock(),
        "scapy.layers.dns": MagicMock(),
        "scapy.layers.dot11": MagicMock(),
        "scapy.layers.dhcp": MagicMock(),
        "scapy.layers.netbios": MagicMock(),
        "scapy.config": MagicMock(),
        "scapy.sendrecv": MagicMock(),
        "scapy.utils": MagicMock(),
        "scapy.volatile": MagicMock(),
        "scapy.arch": MagicMock(),
    }
    return modules


# ---------------------------------------------------------------------------
# netifaces mock
# ---------------------------------------------------------------------------

def _build_netifaces_module():
    """Build a fake ``netifaces`` module."""
    mod = types.ModuleType("netifaces")
    mod.AF_INET = 2
    mod.AF_INET6 = 10
    mod.AF_LINK = 17

    def interfaces():
        return ["lo", "eth0"]

    def ifaddresses(iface):
        return {
            mod.AF_INET: [{"addr": "192.168.1.100", "netmask": "255.255.255.0"}],
            mod.AF_LINK: [{"addr": "00:11:22:33:44:55"}],
        }

    def gateways():
        return {"default": {mod.AF_INET: ("192.168.1.1", "eth0")}}

    mod.interfaces = interfaces
    mod.ifaddresses = ifaddresses
    mod.gateways = gateways
    return mod


# ---------------------------------------------------------------------------
# Public API: install everything into sys.modules
# ---------------------------------------------------------------------------

def install_all_mocks():
    """
    Patch ``sys.modules`` with mocks for every hardware-dependent module.

    This MUST be called before importing any RaspyJack payload or core module
    that touches hardware at import time (e.g. ``LCD_Config``, ``LCD_1in44``,
    ``raspyjack``).

    Returns a dict of all injected module objects keyed by module name so
    callers can inspect or further customise them.
    """
    import sys

    rpi_pkg = _build_rpi_package()
    gpio_mod = rpi_pkg.GPIO

    lcd_config_mod = _build_lcd_config_module()
    lcd_1in44_mod = _build_lcd_1in44_module()
    spidev_mod = _build_spidev_module()
    smbus_mod = _build_smbus_module("smbus")
    smbus2_mod = _build_smbus_module("smbus2")
    pyudev_mod = _build_pyudev_module()
    serial_mod = _build_serial_module()
    rj_input_mod = _build_rj_input_module()
    netifaces_mod = _build_netifaces_module()

    scapy_mods = _build_scapy_modules()

    injected = {
        "RPi": rpi_pkg,
        "RPi.GPIO": gpio_mod,
        "LCD_Config": lcd_config_mod,
        "LCD_1in44": lcd_1in44_mod,
        "spidev": spidev_mod,
        "smbus": smbus_mod,
        "smbus2": smbus2_mod,
        "pyudev": pyudev_mod,
        "serial": serial_mod,
        "rj_input": rj_input_mod,
        "netifaces": netifaces_mod,
    }
    injected.update(scapy_mods)

    for name, mod in injected.items():
        sys.modules[name] = mod

    return injected
