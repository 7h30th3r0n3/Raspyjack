"""
Sanity tests that verify the hardware mock infrastructure itself.

These tests ensure that every mock module is importable and behaves as
expected before any payload-level tests are written.
"""


def test_gpio_is_mocked(mock_gpio):
    """GPIO mock is installed and returns expected defaults."""
    assert mock_gpio.BCM == 11
    mock_gpio.setmode(mock_gpio.BCM)
    assert mock_gpio.getmode() == mock_gpio.BCM
    mock_gpio.setup(5, mock_gpio.IN, pull_up_down=mock_gpio.PUD_UP)
    # Default: not pressed (active-low buttons return 1)
    assert mock_gpio.input(5) == 1


def test_gpio_cleanup_resets_state(mock_gpio):
    """GPIO.cleanup() clears pin states."""
    mock_gpio.setmode(mock_gpio.BCM)
    mock_gpio.setup(17, mock_gpio.OUT)
    mock_gpio.output(17, mock_gpio.HIGH)
    mock_gpio.cleanup()
    assert mock_gpio.getmode() is None
    assert mock_gpio._pin_states == {}


def test_lcd_init_and_show(mock_lcd):
    """MockLCD can be initialised and accepts images."""
    assert mock_lcd.LCD_Init() == 0
    assert mock_lcd._initialized is True
    mock_lcd.LCD_ShowImage("fake_image", 0, 0)
    assert mock_lcd._last_image == "fake_image"
    mock_lcd.LCD_Clear()
    assert mock_lcd._last_image is None


def test_lcd_config_gpio_init(mock_lcd_config):
    """LCD_Config.GPIO_Init() returns 0 (success)."""
    assert mock_lcd_config.GPIO_Init() == 0
    assert mock_lcd_config.LCD_RST_PIN == 27


def test_spi_readwrite(mock_spi):
    """MockSpiDev supports basic read/write."""
    mock_spi.writebytes([0x01, 0x02])
    result = mock_spi.readbytes(4)
    assert len(result) == 4
    assert all(b == 0 for b in result)


def test_smbus_readwrite(mock_smbus):
    """MockSMBus responds to read/write calls."""
    mock_smbus.write_byte(0x48, 0xFF)
    assert mock_smbus.read_byte(0x48) == 0
    block = mock_smbus.read_i2c_block_data(0x48, 0x00, 8)
    assert len(block) == 8


def test_serial_readwrite(mock_serial):
    """MockSerial handles basic I/O."""
    assert mock_serial.is_open is True
    written = mock_serial.write(b"hello")
    assert written == 5
    mock_serial._read_buffer = b"world\n"
    line = mock_serial.readline()
    assert line == b"world\n"


def test_rj_input_returns_none(mock_rj_input):
    """rj_input.get_virtual_button() returns None by default."""
    assert mock_rj_input.get_virtual_button() is None


def test_button_sequencer(mock_get_button):
    """ButtonSequencer yields values in order, then None."""
    seq = mock_get_button(["UP", "DOWN", "KEY3"])
    assert seq() == "UP"
    assert seq() == "DOWN"
    assert seq() == "KEY3"
    assert seq() is None
    assert seq.remaining == 0


def test_button_sequencer_with_nones(mock_get_button):
    """ButtonSequencer handles None entries (no press)."""
    seq = mock_get_button([None, None, "KEY3"])
    assert seq() is None
    assert seq() is None
    assert seq() == "KEY3"
    assert seq() is None


def test_button_sequencer_reset(mock_get_button):
    """ButtonSequencer.reset() replays the sequence."""
    seq = mock_get_button(["KEY1", "KEY2"])
    assert seq() == "KEY1"
    assert seq() == "KEY2"
    seq.reset()
    assert seq() == "KEY1"
    assert seq.remaining == 1


def test_scapy_import_does_not_fail():
    """Scapy mock allows import without hardware."""
    from scapy.all import ARP, Ether, srp  # noqa: F401

    assert ARP is not None


def test_netifaces_import():
    """Netifaces mock provides expected interface data."""
    import netifaces

    ifaces = netifaces.interfaces()
    assert "eth0" in ifaces
    addrs = netifaces.ifaddresses("eth0")
    assert netifaces.AF_INET in addrs


def test_gpio_isolated_between_tests(mock_gpio):
    """Verify autouse _reset_gpio fixture clears state between tests."""
    # After reset, mode should be None and pin_states empty
    assert mock_gpio.getmode() is None
    assert mock_gpio._pin_states == {}
