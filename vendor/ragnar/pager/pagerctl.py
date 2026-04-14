"""
pagerctl.py - Python ctypes wrapper for libpagerctl.so

WiFi Pineapple Pager hardware control library.
Use this for smooth, responsive applications on the Pager.

Example:
    from pagerctl import Pager

    pager = Pager()
    pager.init()
    pager.set_rotation(270)
    pager.clear(pager.rgb(0, 0, 32))
    pager.draw_text(10, 10, "Hello!", pager.WHITE, 2)
    pager.flip()
    pager.cleanup()
"""

import os
from ctypes import CDLL, Structure, c_int, c_uint8, c_uint16, c_uint32, c_float, c_char, c_char_p, c_void_p, POINTER, byref


class PagerInput(Structure):
    """Input state structure matching pager_input_t in C."""
    _fields_ = [
        ("current", c_uint8),   # Currently held buttons (bitmask)
        ("pressed", c_uint8),   # Just pressed this frame (bitmask)
        ("released", c_uint8),  # Just released this frame (bitmask)
    ]


class PagerInputEvent(Structure):
    """Input event structure for thread-safe event queue."""
    _fields_ = [
        ("button", c_uint8),     # Which button (single bit from PBTN_* bitmask)
        ("type", c_int),         # Event type (PAGER_EVENT_*)
        ("timestamp", c_uint32), # When event occurred (ms since init)
    ]


# Event types for PagerInputEvent
PAGER_EVENT_NONE = 0
PAGER_EVENT_PRESS = 1
PAGER_EVENT_RELEASE = 2

# Find the shared library (portable - looks relative to this file first, then system paths)
_lib_paths = [
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "libpagerctl.so"),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib", "libpagerctl.so"),
    "./libpagerctl.so",
    "/root/lib/libpagerctl.so",
    "/root/payloads/user/reconnaissance/pager_ragnar/libpagerctl.so",
    "/root/payloads/user/utilities/PAGERCTL/libpagerctl.so",
]

_lib = None
for path in _lib_paths:
    if os.path.exists(path):
        try:
            _lib = CDLL(path)
            break
        except OSError:
            # File exists but wrong architecture (e.g. MIPS .so on Windows)
            continue

if _lib is None:
    # No hardware library found - try pygame mock for desktop testing
    _using_mock = True
    try:
        from pagerctl_mock import Pager as _MockPager
        print("[pagerctl] libpagerctl.so not found - using pygame mock emulator")
    except ImportError:
        raise OSError(
            "Could not find libpagerctl.so and pagerctl_mock.py is not available.\n"
            "On Pager hardware: ensure libpagerctl.so is in the payload directory.\n"
            "On desktop: install pygame (pip install pygame) and copy pagerctl_mock.py here."
        )
else:
    _using_mock = False


class Pager:
    """High-level wrapper for pager hardware control."""

    # Predefined colors (RGB565)
    BLACK = 0x0000
    WHITE = 0xFFFF
    RED = 0xF800
    GREEN = 0x07E0
    BLUE = 0x001F
    YELLOW = 0xFFE0
    CYAN = 0x07FF
    MAGENTA = 0xF81F
    ORANGE = 0xFD20
    PURPLE = 0x8010
    GRAY = 0x8410

    # Rotation modes
    ROTATION_0 = 0      # Portrait 222x480
    ROTATION_90 = 90    # Landscape 480x222
    ROTATION_180 = 180  # Portrait inverted
    ROTATION_270 = 270  # Landscape inverted (default)

    # Font sizes (for built-in bitmap font)
    FONT_SMALL = 1   # 5x7
    FONT_MEDIUM = 2  # 10x14
    FONT_LARGE = 3   # 15x21

    # Button masks
    BTN_UP = 0x01
    BTN_DOWN = 0x02
    BTN_LEFT = 0x04
    BTN_RIGHT = 0x08
    BTN_A = 0x10     # Green
    BTN_B = 0x20     # Red
    BTN_POWER = 0x40 # Power button

    # Input event types (for get_input_event)
    EVENT_NONE = 0
    EVENT_PRESS = 1
    EVENT_RELEASE = 2

    # RTTTL playback modes
    RTTTL_SOUND_ONLY = 0     # Sound only (default)
    RTTTL_SOUND_VIBRATE = 1  # Sound + vibration
    RTTTL_VIBRATE_ONLY = 2   # Silent vibration pattern

    # RTTTL melodies
    RTTTL_TETRIS = (
        "tetris:d=4,o=5,b=160:"
        "e6,8b,8c6,8d6,16e6,16d6,8c6,8b,a,8a,8c6,e6,8d6,8c6,"
        "b,8b,8c6,d6,e6,c6,a,2a,8p,"
        "d6,8f6,a6,8g6,8f6,e6,8e6,8c6,e6,8d6,8c6,"
        "b,8b,8c6,d6,e6,c6,a,a"
    )
    RTTTL_GAME_OVER = "smbdeath:d=4,o=5,b=90:8p,16b,16f6,16p,16f6,16f.6,16e.6,16d6,16c6,16p,16e,16p,16c,4p"
    RTTTL_LEVEL_UP = "levelup:d=16,o=5,b=200:c,e,g,c6,8p,g,c6,e6,8g6"

    def __init__(self):
        self._setup_functions()
        self._initialized = False

    def _setup_functions(self):
        """Set up ctypes function signatures."""
        # Init/cleanup
        _lib.pager_init.argtypes = []
        _lib.pager_init.restype = c_int
        _lib.pager_cleanup.argtypes = []
        _lib.pager_cleanup.restype = None

        # Rotation
        _lib.pager_set_rotation.argtypes = [c_int]
        _lib.pager_set_rotation.restype = None
        _lib.pager_get_width.argtypes = []
        _lib.pager_get_width.restype = c_int
        _lib.pager_get_height.argtypes = []
        _lib.pager_get_height.restype = c_int

        # Frame management
        _lib.pager_flip.argtypes = []
        _lib.pager_flip.restype = None
        _lib.pager_clear.argtypes = [c_uint16]
        _lib.pager_clear.restype = None
        _lib.pager_get_ticks.argtypes = []
        _lib.pager_get_ticks.restype = c_uint32
        _lib.pager_delay.argtypes = [c_uint32]
        _lib.pager_delay.restype = None
        _lib.pager_frame_sync.argtypes = []
        _lib.pager_frame_sync.restype = c_uint32

        # Drawing
        _lib.pager_set_pixel.argtypes = [c_int, c_int, c_uint16]
        _lib.pager_set_pixel.restype = None
        _lib.pager_fill_rect.argtypes = [c_int, c_int, c_int, c_int, c_uint16]
        _lib.pager_fill_rect.restype = None
        _lib.pager_draw_rect.argtypes = [c_int, c_int, c_int, c_int, c_uint16]
        _lib.pager_draw_rect.restype = None
        _lib.pager_hline.argtypes = [c_int, c_int, c_int, c_uint16]
        _lib.pager_hline.restype = None
        _lib.pager_vline.argtypes = [c_int, c_int, c_int, c_uint16]
        _lib.pager_vline.restype = None
        _lib.pager_draw_line.argtypes = [c_int, c_int, c_int, c_int, c_uint16]
        _lib.pager_draw_line.restype = None
        _lib.pager_fill_circle.argtypes = [c_int, c_int, c_int, c_uint16]
        _lib.pager_fill_circle.restype = None
        _lib.pager_draw_circle.argtypes = [c_int, c_int, c_int, c_uint16]
        _lib.pager_draw_circle.restype = None

        # Text (built-in font)
        _lib.pager_draw_char.argtypes = [c_int, c_int, c_char, c_uint16, c_int]
        _lib.pager_draw_char.restype = c_int
        _lib.pager_draw_text.argtypes = [c_int, c_int, c_char_p, c_uint16, c_int]
        _lib.pager_draw_text.restype = c_int
        _lib.pager_draw_text_centered.argtypes = [c_int, c_char_p, c_uint16, c_int]
        _lib.pager_draw_text_centered.restype = None
        _lib.pager_text_width.argtypes = [c_char_p, c_int]
        _lib.pager_text_width.restype = c_int
        _lib.pager_draw_number.argtypes = [c_int, c_int, c_int, c_uint16, c_int]
        _lib.pager_draw_number.restype = c_int

        # TTF text
        _lib.pager_draw_ttf.argtypes = [c_int, c_int, c_char_p, c_uint16, c_char_p, c_float]
        _lib.pager_draw_ttf.restype = c_int
        _lib.pager_ttf_width.argtypes = [c_char_p, c_char_p, c_float]
        _lib.pager_ttf_width.restype = c_int
        _lib.pager_ttf_height.argtypes = [c_char_p, c_float]
        _lib.pager_ttf_height.restype = c_int
        _lib.pager_draw_ttf_centered.argtypes = [c_int, c_char_p, c_uint16, c_char_p, c_float]
        _lib.pager_draw_ttf_centered.restype = None
        _lib.pager_draw_ttf_right.argtypes = [c_int, c_char_p, c_uint16, c_char_p, c_float, c_int]
        _lib.pager_draw_ttf_right.restype = None
        _lib.pager_ttf_cleanup.argtypes = []
        _lib.pager_ttf_cleanup.restype = None

        # Audio
        _lib.pager_play_rtttl.argtypes = [c_char_p]
        _lib.pager_play_rtttl.restype = None
        _lib.pager_play_rtttl_ex.argtypes = [c_char_p, c_int]
        _lib.pager_play_rtttl_ex.restype = None
        _lib.pager_stop_audio.argtypes = []
        _lib.pager_stop_audio.restype = None
        _lib.pager_audio_playing.argtypes = []
        _lib.pager_audio_playing.restype = c_int
        _lib.pager_beep.argtypes = [c_int, c_int]
        _lib.pager_beep.restype = None
        _lib.pager_play_rtttl_sync.argtypes = [c_char_p, c_int]
        _lib.pager_play_rtttl_sync.restype = None

        # Vibration
        _lib.pager_vibrate.argtypes = [c_int]
        _lib.pager_vibrate.restype = None
        _lib.pager_vibrate_pattern.argtypes = [c_char_p]
        _lib.pager_vibrate_pattern.restype = None

        # LEDs
        _lib.pager_led_set.argtypes = [c_char_p, c_int]
        _lib.pager_led_set.restype = None
        _lib.pager_led_rgb.argtypes = [c_char_p, c_uint8, c_uint8, c_uint8]
        _lib.pager_led_rgb.restype = None
        _lib.pager_led_dpad.argtypes = [c_char_p, c_uint32]
        _lib.pager_led_dpad.restype = None
        _lib.pager_led_all_off.argtypes = []
        _lib.pager_led_all_off.restype = None

        # Random
        _lib.pager_random.argtypes = [c_int]
        _lib.pager_random.restype = c_int
        _lib.pager_seed_random.argtypes = [c_uint32]
        _lib.pager_seed_random.restype = None

        # Input
        _lib.pager_wait_button.argtypes = []
        _lib.pager_wait_button.restype = c_int
        _lib.pager_poll_input.argtypes = [POINTER(PagerInput)]
        _lib.pager_poll_input.restype = None

        # Thread-safe input event queue
        _lib.pager_get_input_event.argtypes = [POINTER(PagerInputEvent)]
        _lib.pager_get_input_event.restype = c_int
        _lib.pager_has_input_events.argtypes = []
        _lib.pager_has_input_events.restype = c_int
        _lib.pager_peek_buttons.argtypes = []
        _lib.pager_peek_buttons.restype = c_uint8
        _lib.pager_clear_input_events.argtypes = []
        _lib.pager_clear_input_events.restype = None

        # Backlight / Brightness
        _lib.pager_set_brightness.argtypes = [c_int]
        _lib.pager_set_brightness.restype = c_int
        _lib.pager_get_brightness.argtypes = []
        _lib.pager_get_brightness.restype = c_int
        _lib.pager_get_max_brightness.argtypes = []
        _lib.pager_get_max_brightness.restype = c_int
        _lib.pager_screen_off.argtypes = []
        _lib.pager_screen_off.restype = c_int
        _lib.pager_screen_on.argtypes = []
        _lib.pager_screen_on.restype = c_int

        # Image support
        _lib.pager_load_image.argtypes = [c_char_p]
        _lib.pager_load_image.restype = c_void_p
        _lib.pager_free_image.argtypes = [c_void_p]
        _lib.pager_free_image.restype = None
        _lib.pager_draw_image.argtypes = [c_int, c_int, c_void_p]
        _lib.pager_draw_image.restype = None
        _lib.pager_draw_image_scaled.argtypes = [c_int, c_int, c_int, c_int, c_void_p]
        _lib.pager_draw_image_scaled.restype = None
        _lib.pager_draw_image_file.argtypes = [c_int, c_int, c_char_p]
        _lib.pager_draw_image_file.restype = c_int
        _lib.pager_draw_image_file_scaled.argtypes = [c_int, c_int, c_int, c_int, c_char_p]
        _lib.pager_draw_image_file_scaled.restype = c_int
        _lib.pager_get_image_info.argtypes = [c_char_p, POINTER(c_int), POINTER(c_int)]
        _lib.pager_get_image_info.restype = c_int

    # Initialization
    def init(self):
        """Initialize pager hardware. Call before any other functions."""
        result = _lib.pager_init()
        if result == 0:
            self._initialized = True
        return result

    def cleanup(self):
        """Clean up and release hardware. Always call on exit."""
        if self._initialized:
            _lib.pager_cleanup()
            self._initialized = False

    # Rotation
    def set_rotation(self, rotation):
        """Set display rotation: 0, 90, 180, or 270."""
        _lib.pager_set_rotation(rotation)

    @property
    def width(self):
        """Get current logical screen width."""
        return _lib.pager_get_width()

    @property
    def height(self):
        """Get current logical screen height."""
        return _lib.pager_get_height()

    # Frame management
    def flip(self):
        """Display the current frame. Call once per frame."""
        _lib.pager_flip()

    def clear(self, color=0):
        """Clear screen to color (default black)."""
        _lib.pager_clear(color)

    def get_ticks(self):
        """Get milliseconds since init."""
        return _lib.pager_get_ticks()

    def delay(self, ms):
        """Sleep for milliseconds."""
        _lib.pager_delay(ms)

    def frame_sync(self):
        """Frame rate limiter. Call at end of game loop."""
        return _lib.pager_frame_sync()

    # Color helpers
    @staticmethod
    def rgb(r, g, b):
        """Convert RGB (0-255) to RGB565."""
        return ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)

    @staticmethod
    def hex_color(rgb_hex):
        """Convert 0xRRGGBB to RGB565."""
        r = (rgb_hex >> 16) & 0xFF
        g = (rgb_hex >> 8) & 0xFF
        b = rgb_hex & 0xFF
        return Pager.rgb(r, g, b)

    # Drawing primitives
    def pixel(self, x, y, color):
        """Set a single pixel."""
        _lib.pager_set_pixel(x, y, color)

    def fill_rect(self, x, y, w, h, color):
        """Draw a filled rectangle."""
        _lib.pager_fill_rect(x, y, w, h, color)

    def rect(self, x, y, w, h, color):
        """Draw a rectangle outline."""
        _lib.pager_draw_rect(x, y, w, h, color)

    def hline(self, x, y, w, color):
        """Draw horizontal line."""
        _lib.pager_hline(x, y, w, color)

    def vline(self, x, y, h, color):
        """Draw vertical line."""
        _lib.pager_vline(x, y, h, color)

    def line(self, x0, y0, x1, y1, color):
        """Draw a line between two points."""
        _lib.pager_draw_line(x0, y0, x1, y1, color)

    def fill_circle(self, cx, cy, r, color):
        """Draw a filled circle."""
        _lib.pager_fill_circle(cx, cy, r, color)

    def circle(self, cx, cy, r, color):
        """Draw a circle outline."""
        _lib.pager_draw_circle(cx, cy, r, color)

    # Text (built-in bitmap font)
    def draw_char(self, x, y, char, color, size=1):
        """Draw a single character. Returns width."""
        return _lib.pager_draw_char(x, y, char.encode(), color, size)

    def draw_text(self, x, y, text, color, size=1):
        """Draw text at position. Returns width."""
        return _lib.pager_draw_text(x, y, text.encode(), color, size)

    def draw_text_centered(self, y, text, color, size=1):
        """Draw horizontally centered text."""
        _lib.pager_draw_text_centered(y, text.encode(), color, size)

    def text_width(self, text, size=1):
        """Get width of text in pixels."""
        return _lib.pager_text_width(text.encode(), size)

    def draw_number(self, x, y, num, color, size=1):
        """Draw a number. Returns width."""
        return _lib.pager_draw_number(x, y, num, color, size)

    # TTF text
    def draw_ttf(self, x, y, text, color, font_path, font_size):
        """Draw text using TTF font. Returns width or -1 on error."""
        return _lib.pager_draw_ttf(x, y, text.encode(), color, font_path.encode(), font_size)

    def ttf_width(self, text, font_path, font_size):
        """Get width of TTF text in pixels."""
        return _lib.pager_ttf_width(text.encode(), font_path.encode(), font_size)

    def ttf_height(self, font_path, font_size):
        """Get height of TTF font in pixels."""
        return _lib.pager_ttf_height(font_path.encode(), font_size)

    def draw_ttf_centered(self, y, text, color, font_path, font_size):
        """Draw horizontally centered TTF text."""
        _lib.pager_draw_ttf_centered(y, text.encode(), color, font_path.encode(), font_size)

    def draw_ttf_right(self, y, text, color, font_path, font_size, padding=0):
        """Draw right-aligned TTF text."""
        _lib.pager_draw_ttf_right(y, text.encode(), color, font_path.encode(), font_size, padding)

    # Audio
    def play_rtttl(self, melody, mode=None):
        """Play RTTTL melody in background.

        Args:
            melody: RTTTL melody string
            mode: Optional playback mode:
                  RTTTL_SOUND_ONLY (0) - Sound only (default)
                  RTTTL_SOUND_VIBRATE (1) - Sound + vibration
                  RTTTL_VIBRATE_ONLY (2) - Silent vibration pattern
        """
        if mode is None:
            _lib.pager_play_rtttl(melody.encode())
        else:
            _lib.pager_play_rtttl_ex(melody.encode(), mode)

    def stop_audio(self):
        """Stop any playing audio."""
        _lib.pager_stop_audio()

    def audio_playing(self):
        """Check if audio is playing."""
        return bool(_lib.pager_audio_playing())

    def beep(self, freq, duration_ms):
        """Play a simple beep (blocking)."""
        _lib.pager_beep(freq, duration_ms)

    def play_rtttl_sync(self, melody, with_vibration=False):
        """Play RTTTL synchronously (blocking)."""
        _lib.pager_play_rtttl_sync(melody.encode(), 1 if with_vibration else 0)

    # Vibration
    def vibrate(self, duration_ms=200):
        """Vibrate for duration in milliseconds."""
        _lib.pager_vibrate(duration_ms)

    def vibrate_pattern(self, pattern):
        """Play vibration pattern: 'on,off,on,off,...'"""
        _lib.pager_vibrate_pattern(pattern.encode())

    # LEDs
    def led_set(self, name, brightness):
        """Set LED brightness (0-255). Names: 'a-button-led', 'b-button-led'"""
        _lib.pager_led_set(name.encode(), brightness)

    def led_rgb(self, button, r, g, b):
        """Set D-pad LED color. Buttons: 'up', 'down', 'left', 'right'"""
        _lib.pager_led_rgb(button.encode(), r, g, b)

    def led_dpad(self, direction, color):
        """Set D-pad LED from 0xRRGGBB color."""
        _lib.pager_led_dpad(direction.encode(), color)

    def led_all_off(self):
        """Turn off all LEDs."""
        _lib.pager_led_all_off()

    # Random
    def random(self, max_val):
        """Get random number from 0 to max-1."""
        return _lib.pager_random(max_val)

    def seed_random(self, seed):
        """Seed the random number generator."""
        _lib.pager_seed_random(seed)

    # Input
    def wait_button(self):
        """Wait for any button press (blocking)."""
        return _lib.pager_wait_button()

    def poll_input(self):
        """Poll input state (non-blocking).

        Returns:
            tuple: (current, pressed, released) where each is a button bitmask.
                - current: buttons currently held down
                - pressed: buttons just pressed this frame
                - released: buttons just released this frame

        Example:
            current, pressed, released = p.poll_input()
            if pressed & Pager.BTN_A:
                print("A button just pressed!")
            if current & Pager.BTN_UP:
                print("UP is being held")
        """
        state = PagerInput()
        _lib.pager_poll_input(byref(state))
        return state.current, state.pressed, state.released

    # Thread-safe input event queue methods
    def get_input_event(self):
        """Get next input event from thread-safe queue.

        This is the preferred method for multi-threaded applications.
        Each event is only returned once, regardless of which thread reads it.

        Returns:
            tuple: (button, event_type, timestamp) or None if queue is empty.
                - button: which button (single bit from BTN_* constants)
                - event_type: PAGER_EVENT_PRESS (1) or PAGER_EVENT_RELEASE (2)
                - timestamp: when event occurred (ms since init)

        Example:
            event = pager.get_input_event()
            if event:
                button, event_type, timestamp = event
                if button == Pager.BTN_B and event_type == PAGER_EVENT_PRESS:
                    show_pause_menu()
        """
        event = PagerInputEvent()
        if _lib.pager_get_input_event(byref(event)):
            return (event.button, event.type, event.timestamp)
        return None

    def has_input_events(self):
        """Check if there are pending input events in the queue.

        Returns:
            bool: True if events are waiting, False otherwise.
        """
        return bool(_lib.pager_has_input_events())

    def peek_buttons(self):
        """Get current button state without consuming events.

        Thread-safe way to check which buttons are currently held.
        Does not affect the event queue.

        Returns:
            int: Bitmask of currently held buttons.

        Example:
            if pager.peek_buttons() & Pager.BTN_UP:
                print("UP is being held")
        """
        return _lib.pager_peek_buttons()

    def clear_input_events(self):
        """Clear all pending input events from the queue.

        Use this when transitioning between screens or game states
        to prevent stale events from triggering actions.
        """
        _lib.pager_clear_input_events()

    # Backlight / Brightness
    def set_brightness(self, percent):
        """Set screen brightness as percentage (0-100).
        Returns 0 on success, -1 if backlight control not available.
        """
        return _lib.pager_set_brightness(percent)

    def get_brightness(self):
        """Get current screen brightness as percentage (0-100).
        Returns -1 if backlight control not available.
        """
        return _lib.pager_get_brightness()

    def get_max_brightness(self):
        """Get maximum brightness value from hardware.
        Returns -1 if backlight control not available.
        """
        return _lib.pager_get_max_brightness()

    def screen_off(self):
        """Turn screen off (sets brightness to 0%).
        Returns 0 on success, -1 if backlight control not available.
        """
        return _lib.pager_screen_off()

    def screen_on(self):
        """Turn screen on (sets brightness to 80%).
        Returns 0 on success, -1 if backlight control not available.
        """
        return _lib.pager_screen_on()

    # Image support (JPG, PNG, BMP, GIF)
    def load_image(self, filepath):
        """Load image from file. Returns opaque handle for draw_image().
        Call free_image() when done. Returns None on error."""
        handle = _lib.pager_load_image(filepath.encode())
        return handle if handle else None

    def free_image(self, handle):
        """Free a loaded image."""
        if handle:
            _lib.pager_free_image(handle)

    def draw_image(self, x, y, handle):
        """Draw a loaded image at position."""
        if handle:
            _lib.pager_draw_image(x, y, handle)

    def draw_image_scaled(self, x, y, w, h, handle):
        """Draw a loaded image scaled to fit w x h."""
        if handle:
            _lib.pager_draw_image_scaled(x, y, w, h, handle)

    def draw_image_file(self, x, y, filepath):
        """Load and draw image from file in one call. Returns 0 on success."""
        return _lib.pager_draw_image_file(x, y, filepath.encode())

    def draw_image_file_scaled(self, x, y, w, h, filepath):
        """Load and draw image from file, scaled. Returns 0 on success."""
        return _lib.pager_draw_image_file_scaled(x, y, w, h, filepath.encode())

    def get_image_info(self, filepath):
        """Get image dimensions without loading. Returns (width, height) or None."""
        w = c_int()
        h = c_int()
        if _lib.pager_get_image_info(filepath.encode(), byref(w), byref(h)) == 0:
            return (w.value, h.value)
        return None

    # Context manager support
    def __enter__(self):
        self.init()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False


# If running on desktop without libpagerctl.so, replace the real Pager with the mock
if _using_mock:
    Pager = _MockPager


# Quick demo if run directly
if __name__ == "__main__":
    with Pager() as p:
        p.set_rotation(270)
        p.clear(p.rgb(0, 0, 32))
        p.draw_text_centered(100, "libpagerctl.so", p.WHITE, 2)
        p.draw_text_centered(130, "Python Demo", p.CYAN, 1)
        p.flip()
        p.beep(800, 100)
        p.vibrate(100)
        p.delay(3000)
