"""
pagerctl_mock.py - Pygame-based mock of the WiFi Pineapple Pager display.

Drop-in replacement for pagerctl.py when libpagerctl.so is not available.
Emulates the Pager LCD (222x480 portrait / 480x222 landscape) in a desktop window.

Keyboard mapping:
    Arrow keys  -> D-pad (UP/DOWN/LEFT/RIGHT)
    Enter/Space -> A button (GREEN)
    Escape/Backspace -> B button (RED)

Usage:
    from pagerctl_mock import Pager   # same API as real pagerctl
"""

import os
import sys
import time
import threading
import collections

try:
    import pygame
except ImportError:
    print("ERROR: pygame is required for the pager mock emulator.")
    print("Install it with:  pip install pygame")
    sys.exit(1)


# Event types (match real pagerctl)
PAGER_EVENT_NONE = 0
PAGER_EVENT_PRESS = 1
PAGER_EVENT_RELEASE = 2

# Display scale factor for desktop visibility
_SCALE = 2


def _rgb565_to_rgb888(color):
    """Convert RGB565 (16-bit) to standard (R, G, B) tuple."""
    r = ((color >> 11) & 0x1F) * 255 // 31
    g = ((color >> 5) & 0x3F) * 255 // 63
    b = (color & 0x1F) * 255 // 31
    return (r, g, b)


class Pager:
    """Pygame-based mock of the WiFi Pineapple Pager hardware."""

    # Predefined colors (RGB565) - identical to real pagerctl
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
    ROTATION_0 = 0
    ROTATION_90 = 90
    ROTATION_180 = 180
    ROTATION_270 = 270

    # Font sizes (built-in bitmap font)
    FONT_SMALL = 1
    FONT_MEDIUM = 2
    FONT_LARGE = 3

    # Button masks
    BTN_UP = 0x01
    BTN_DOWN = 0x02
    BTN_LEFT = 0x04
    BTN_RIGHT = 0x08
    BTN_A = 0x10      # Green
    BTN_B = 0x20      # Red
    BTN_POWER = 0x40

    # Input event types
    EVENT_NONE = 0
    EVENT_PRESS = 1
    EVENT_RELEASE = 2

    # RTTTL (no-op on mock)
    RTTTL_SOUND_ONLY = 0
    RTTTL_SOUND_VIBRATE = 1
    RTTTL_VIBRATE_ONLY = 2
    RTTTL_TETRIS = ""
    RTTTL_GAME_OVER = ""
    RTTTL_LEVEL_UP = ""

    # Keyboard -> pager button mapping
    _KEY_MAP = {
        pygame.K_UP: 0x01,
        pygame.K_DOWN: 0x02,
        pygame.K_LEFT: 0x04,
        pygame.K_RIGHT: 0x08,
        pygame.K_RETURN: 0x10,
        pygame.K_SPACE: 0x10,
        pygame.K_z: 0x10,
        pygame.K_ESCAPE: 0x20,
        pygame.K_BACKSPACE: 0x20,
        pygame.K_x: 0x20,
    }

    def __init__(self):
        self._initialized = False
        self._rotation = 0
        self._w = 222
        self._h = 480
        self._brightness = 80
        self._start_ticks = 0

        # Back buffer (drawn to, then flipped)
        self._surface = None
        self._screen = None

        # Thread-safe input event queue
        self._event_queue = collections.deque(maxlen=64)
        self._event_lock = threading.Lock()
        self._held_buttons = 0

        # Font cache
        self._font_cache = {}

        # Image cache
        self._image_cache = {}

    def _setup_functions(self):
        """Compatibility stub - real pagerctl sets up ctypes here."""
        pass

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def init(self):
        """Initialize the mock pager display."""
        if self._initialized:
            return 0
        pygame.init()
        pygame.display.set_caption("Pager Mock - Ragnar")
        self._start_ticks = pygame.time.get_ticks()
        self._create_window()
        self._initialized = True
        return 0

    def _create_window(self):
        """Create/resize the pygame window for current rotation."""
        sw = self._w * _SCALE
        sh = self._h * _SCALE
        self._screen = pygame.display.set_mode((sw, sh))
        self._surface = pygame.Surface((self._w, self._h))
        self._surface.fill((0, 0, 0))

        # Draw initial frame
        scaled = pygame.transform.scale(self._surface, (sw, sh))
        self._screen.blit(scaled, (0, 0))
        pygame.display.flip()

    def cleanup(self):
        """Clean up the mock display."""
        if self._initialized:
            self._initialized = False
            try:
                pygame.quit()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Rotation and dimensions
    # ------------------------------------------------------------------

    def set_rotation(self, rotation):
        """Set display rotation: 0, 90, 180, or 270."""
        self._rotation = rotation
        if rotation in (0, 180):
            self._w = 222
            self._h = 480
        else:
            self._w = 480
            self._h = 222
        if self._initialized:
            self._create_window()

    @property
    def width(self):
        return self._w

    @property
    def height(self):
        return self._h

    # ------------------------------------------------------------------
    # Frame management
    # ------------------------------------------------------------------

    def flip(self):
        """Display the current back buffer."""
        if not self._initialized:
            return
        self._pump_events()
        sw = self._w * _SCALE
        sh = self._h * _SCALE
        scaled = pygame.transform.scale(self._surface, (sw, sh))
        self._screen.blit(scaled, (0, 0))
        pygame.display.flip()

    def clear(self, color=0):
        """Clear the back buffer."""
        if not self._initialized:
            return
        self._pump_events()
        self._surface.fill(_rgb565_to_rgb888(color))

    def get_ticks(self):
        """Get milliseconds since init."""
        if self._initialized:
            return pygame.time.get_ticks() - self._start_ticks
        return 0

    def delay(self, ms):
        """Sleep for milliseconds."""
        pygame.time.delay(ms)

    def frame_sync(self):
        """Frame rate limiter (target ~30fps)."""
        pygame.time.delay(33)
        return self.get_ticks()

    # ------------------------------------------------------------------
    # Color helpers
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Drawing primitives
    # ------------------------------------------------------------------

    def pixel(self, x, y, color):
        self._surface.set_at((x, y), _rgb565_to_rgb888(color))

    def fill_rect(self, x, y, w, h, color):
        pygame.draw.rect(self._surface, _rgb565_to_rgb888(color), (x, y, w, h))

    def rect(self, x, y, w, h, color):
        pygame.draw.rect(self._surface, _rgb565_to_rgb888(color), (x, y, w, h), 1)

    def hline(self, x, y, w, color):
        pygame.draw.line(self._surface, _rgb565_to_rgb888(color), (x, y), (x + w - 1, y))

    def vline(self, x, y, h, color):
        pygame.draw.line(self._surface, _rgb565_to_rgb888(color), (x, y), (x, y + h - 1))

    def line(self, x0, y0, x1, y1, color):
        pygame.draw.line(self._surface, _rgb565_to_rgb888(color), (x0, y0), (x1, y1))

    def fill_circle(self, cx, cy, r, color):
        pygame.draw.circle(self._surface, _rgb565_to_rgb888(color), (cx, cy), r)

    def circle(self, cx, cy, r, color):
        pygame.draw.circle(self._surface, _rgb565_to_rgb888(color), (cx, cy), r, 1)

    # ------------------------------------------------------------------
    # Text - built-in bitmap font (simple fallback)
    # ------------------------------------------------------------------

    def _get_builtin_font(self, size):
        """Get a pygame font for the built-in bitmap font sizes."""
        px = {1: 10, 2: 16, 3: 22}.get(size, 12)
        key = ("builtin", px)
        if key not in self._font_cache:
            self._font_cache[key] = pygame.font.SysFont("monospace", px)
        return self._font_cache[key]

    def draw_char(self, x, y, char, color, size=1):
        font = self._get_builtin_font(size)
        surf = font.render(char, True, _rgb565_to_rgb888(color))
        self._surface.blit(surf, (x, y))
        return surf.get_width()

    def draw_text(self, x, y, text, color, size=1):
        font = self._get_builtin_font(size)
        surf = font.render(text, True, _rgb565_to_rgb888(color))
        self._surface.blit(surf, (x, y))
        return surf.get_width()

    def draw_text_centered(self, y, text, color, size=1):
        font = self._get_builtin_font(size)
        surf = font.render(text, True, _rgb565_to_rgb888(color))
        x = (self._w - surf.get_width()) // 2
        self._surface.blit(surf, (x, y))

    def text_width(self, text, size=1):
        font = self._get_builtin_font(size)
        return font.size(text)[0]

    def draw_number(self, x, y, num, color, size=1):
        return self.draw_text(x, y, str(num), color, size)

    # ------------------------------------------------------------------
    # TTF text
    # ------------------------------------------------------------------

    def _get_ttf_font(self, font_path, font_size):
        """Load and cache a TTF font."""
        # Round font_size for cache key
        fs = int(font_size + 0.5)
        key = (font_path, fs)
        if key not in self._font_cache:
            try:
                self._font_cache[key] = pygame.font.Font(font_path, fs)
            except (FileNotFoundError, OSError):
                # Fallback to system font
                self._font_cache[key] = pygame.font.SysFont("arial", fs)
        return self._font_cache[key]

    def draw_ttf(self, x, y, text, color, font_path, font_size):
        """Draw TTF text. Returns width."""
        font = self._get_ttf_font(font_path, font_size)
        surf = font.render(text, True, _rgb565_to_rgb888(color))
        self._surface.blit(surf, (x, y))
        return surf.get_width()

    def ttf_width(self, text, font_path, font_size):
        """Get width of TTF text in pixels."""
        font = self._get_ttf_font(font_path, font_size)
        return font.size(text)[0]

    def ttf_height(self, font_path, font_size):
        """Get height of TTF font in pixels."""
        font = self._get_ttf_font(font_path, font_size)
        return font.get_height()

    def draw_ttf_centered(self, y, text, color, font_path, font_size):
        """Draw horizontally centered TTF text."""
        font = self._get_ttf_font(font_path, font_size)
        surf = font.render(text, True, _rgb565_to_rgb888(color))
        x = (self._w - surf.get_width()) // 2
        self._surface.blit(surf, (x, y))

    def draw_ttf_right(self, y, text, color, font_path, font_size, padding=0):
        """Draw right-aligned TTF text."""
        font = self._get_ttf_font(font_path, font_size)
        surf = font.render(text, True, _rgb565_to_rgb888(color))
        x = self._w - surf.get_width() - padding
        self._surface.blit(surf, (x, y))

    # ------------------------------------------------------------------
    # Input handling
    # ------------------------------------------------------------------

    def _pump_events(self):
        """Process pygame events and feed the input queue."""
        if not self._initialized:
            return
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                self.cleanup()
                sys.exit(0)
            elif event.type == pygame.KEYDOWN:
                btn = self._KEY_MAP.get(event.key, 0)
                if btn:
                    self._held_buttons |= btn
                    ts = self.get_ticks()
                    with self._event_lock:
                        self._event_queue.append((btn, PAGER_EVENT_PRESS, ts))
            elif event.type == pygame.KEYUP:
                btn = self._KEY_MAP.get(event.key, 0)
                if btn:
                    self._held_buttons &= ~btn
                    ts = self.get_ticks()
                    with self._event_lock:
                        self._event_queue.append((btn, PAGER_EVENT_RELEASE, ts))

    def wait_button(self):
        """Wait for any button press (blocking). Returns button bitmask."""
        while self._initialized:
            self._pump_events()
            with self._event_lock:
                for i, (btn, etype, ts) in enumerate(self._event_queue):
                    if etype == PAGER_EVENT_PRESS:
                        # Remove this and all earlier events
                        for _ in range(i + 1):
                            self._event_queue.popleft()
                        return btn
            time.sleep(0.016)
        return 0

    def poll_input(self):
        """Poll input state (non-blocking). Returns (current, pressed, released)."""
        self._pump_events()
        pressed = 0
        released = 0
        with self._event_lock:
            while self._event_queue:
                btn, etype, ts = self._event_queue.popleft()
                if etype == PAGER_EVENT_PRESS:
                    pressed |= btn
                elif etype == PAGER_EVENT_RELEASE:
                    released |= btn
        return self._held_buttons, pressed, released

    def get_input_event(self):
        """Get next input event from queue. Returns (button, type, timestamp) or None."""
        self._pump_events()
        with self._event_lock:
            if self._event_queue:
                return self._event_queue.popleft()
        return None

    def has_input_events(self):
        """Check if there are pending events."""
        self._pump_events()
        with self._event_lock:
            return len(self._event_queue) > 0

    def peek_buttons(self):
        """Get currently held buttons without consuming events."""
        self._pump_events()
        return self._held_buttons

    def clear_input_events(self):
        """Clear all pending input events."""
        self._pump_events()
        with self._event_lock:
            self._event_queue.clear()

    # ------------------------------------------------------------------
    # Brightness (stored but visual is no-op)
    # ------------------------------------------------------------------

    def set_brightness(self, percent):
        self._brightness = max(0, min(100, percent))
        return 0

    def get_brightness(self):
        return self._brightness

    def get_max_brightness(self):
        return 100

    def screen_off(self):
        self._brightness = 0
        return 0

    def screen_on(self):
        self._brightness = 80
        return 0

    # ------------------------------------------------------------------
    # LEDs (no-op on mock)
    # ------------------------------------------------------------------

    def led_set(self, name, brightness):
        pass

    def led_rgb(self, button, r, g, b):
        pass

    def led_dpad(self, direction, color):
        pass

    def led_all_off(self):
        pass

    # ------------------------------------------------------------------
    # Audio / Vibration (no-op on mock)
    # ------------------------------------------------------------------

    def play_rtttl(self, melody, mode=None):
        pass

    def stop_audio(self):
        pass

    def audio_playing(self):
        return False

    def beep(self, freq, duration_ms):
        pass

    def play_rtttl_sync(self, melody, with_vibration=False):
        pass

    def vibrate(self, duration_ms=200):
        pass

    def vibrate_pattern(self, pattern):
        pass

    # ------------------------------------------------------------------
    # Random
    # ------------------------------------------------------------------

    def random(self, max_val):
        import random as _rand
        return _rand.randint(0, max_val - 1)

    def seed_random(self, seed):
        import random as _rand
        _rand.seed(seed)

    # ------------------------------------------------------------------
    # Image support
    # ------------------------------------------------------------------

    def _load_pygame_image(self, filepath):
        """Load an image file, with caching."""
        if filepath in self._image_cache:
            return self._image_cache[filepath]
        try:
            img = pygame.image.load(filepath).convert_alpha()
            self._image_cache[filepath] = img
            return img
        except (pygame.error, FileNotFoundError, OSError):
            return None

    def load_image(self, filepath):
        """Load image from file. Returns handle (pygame Surface) or None."""
        return self._load_pygame_image(filepath)

    def free_image(self, handle):
        pass

    def draw_image(self, x, y, handle):
        if handle:
            self._surface.blit(handle, (x, y))

    def draw_image_scaled(self, x, y, w, h, handle):
        if handle and w > 0 and h > 0:
            scaled = pygame.transform.scale(handle, (w, h))
            self._surface.blit(scaled, (x, y))

    def draw_image_file(self, x, y, filepath):
        """Load and draw image from file. Returns 0 on success."""
        img = self._load_pygame_image(filepath)
        if img:
            self._surface.blit(img, (x, y))
            return 0
        return -1

    def draw_image_file_scaled(self, x, y, w, h, filepath):
        """Load and draw image scaled. Returns 0 on success."""
        img = self._load_pygame_image(filepath)
        if img and w > 0 and h > 0:
            scaled = pygame.transform.scale(img, (w, h))
            self._surface.blit(scaled, (x, y))
            return 0
        return -1

    def get_image_info(self, filepath):
        """Get image dimensions. Returns (width, height) or None."""
        img = self._load_pygame_image(filepath)
        if img:
            return (img.get_width(), img.get_height())
        return None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self):
        self.init()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False


# Quick demo if run directly
if __name__ == "__main__":
    print("Pager Mock Emulator")
    print("Keys: Arrow keys = D-pad, Enter/Space = A (green), Escape = B (red)")
    print()

    with Pager() as p:
        p.set_rotation(270)  # Landscape like pager_menu.py

        # Draw a simple test screen
        p.clear(Pager.BLACK)

        # Title
        font = None
        ragnar_dir = os.path.join(os.path.dirname(__file__), "..", "OneDrive", "dokument", "GitHub", "Ragnar")
        viking_font = os.path.join(ragnar_dir, "resources", "fonts", "Viking.TTF")
        if not os.path.exists(viking_font):
            # Try relative to script
            viking_font = os.path.join(os.path.dirname(__file__), "resources", "fonts", "Viking.TTF")

        title_color = Pager.rgb(100, 200, 255)
        if os.path.exists(viking_font):
            p.draw_ttf_centered(20, "Ragnar", title_color, viking_font, 48.0)
        else:
            p.draw_text_centered(20, "Ragnar", title_color, 3)

        # Instructions
        p.draw_text_centered(90, "Pager Mock Emulator", Pager.WHITE, 2)
        p.draw_text_centered(120, "Arrow keys = D-pad", Pager.GRAY, 1)
        p.draw_text_centered(135, "Enter/Space = GREEN (A)", Pager.GREEN, 1)
        p.draw_text_centered(150, "Escape = RED (B)", Pager.RED, 1)
        p.draw_text_centered(175, "Press any button...", Pager.YELLOW, 1)
        p.flip()

        # Wait for button
        btn = p.wait_button()
        btn_names = {0x01: "UP", 0x02: "DOWN", 0x04: "LEFT", 0x08: "RIGHT",
                     0x10: "A/GREEN", 0x20: "B/RED"}
        name = btn_names.get(btn, f"0x{btn:02x}")

        p.clear(Pager.BLACK)
        p.draw_text_centered(100, f"You pressed: {name}", Pager.GREEN, 2)
        p.flip()
        time.sleep(1.5)

    print("Mock emulator exited cleanly.")
