#!/usr/bin/env python3
"""
Flexible Menu System for Raspyjack UI
=====================================
This module provides a reusable menu system with pluggable renderers
and configurable navigation behavior.
"""

from typing import List, Dict, Any, Optional, Callable, Union, Tuple
import time
import threading
from abc import ABC, abstractmethod
from .widgets import WidgetContext
from ui.framebuffer import fb


class MenuItem:
    """Represents a single menu item with label, action, and metadata."""
    
    def __init__(self, 
                 label: str, 
                 action: Optional[Union[Callable, str]] = None,
                 icon: str = "",
                 description: str = "",
                 metadata: Optional[Dict[str, Any]] = None):
        """
        Initialize a menu item.
        
        Args:
            label: Display text for the item
            action: Function to call or submenu key when selected
            icon: Icon character/code for display
            description: Tooltip/help text
            metadata: Additional data for custom use
        """
        self.label = label
        self.action = action
        self.icon = icon
        self.description = description
        self.metadata = metadata or {}
    
    def get_display_icon(self) -> str:
        """Get the icon to display for this item."""
        return self.icon
    
    def handle_selection(self) -> Optional[Any]:
        """Handle selection of this item. Override in subclasses."""
        return self.action
    
    def __str__(self) -> str:
        return self.label


class CheckboxMenuItem(MenuItem):
    """Specialized MenuItem that acts as a checkbox/toggle."""
    
    def __init__(self, 
                 label: str,
                 checked: bool = False,
                 icon: str = "",
                 description: str = "",
                 metadata: Optional[Dict[str, Any]] = None,
                 on_toggle: Optional[Callable[[bool], None]] = None):
        """
        Initialize a checkbox menu item.
        
        Args:
            label: Display text for the item
            checked: Initial checkbox state
            icon: Icon character/code for display (fallback if no checkbox icons)
            description: Tooltip/help text
            metadata: Additional data for custom use
            on_toggle: Optional callback function called when toggled with new state
        """
        # Don't pass action to parent - checkboxes handle their own selection
        super().__init__(label, action=None, icon=icon, description=description, metadata=metadata)
        self.checked = checked
        self.on_toggle = on_toggle
    
    def get_display_icon(self) -> str:
        """Get the appropriate checkbox icon."""
        return "☑" if self.checked else "☐"
    
    def toggle(self) -> bool:
        """Toggle checkbox state and return new state."""
        self.checked = not self.checked
        if self.on_toggle:
            try:
                self.on_toggle(self.checked)
            except Exception:
                pass  # Don't let callback errors break the toggle
        return self.checked
    
    def handle_selection(self) -> bool:
        """Handle selection by toggling the checkbox."""
        return self.toggle()
    
    def set_checked(self, checked: bool) -> None:
        """Set checkbox state without triggering callback."""
        self.checked = checked


class MenuRenderer(ABC):
    """Abstract base class for menu renderers."""
    
    def __init__(self, context: WidgetContext):
        self.ctx = context
    
    @abstractmethod
    def render(self, items: List[MenuItem], selected_index: int, **kwargs) -> None:
        """
        Render the menu items with the given selection.
        
        Args:
            items: List of menu items to display
            selected_index: Currently selected item index
            **kwargs: Additional rendering options
        """
        pass
    
    @abstractmethod
    def get_visible_range(self, total_items: int, selected_index: int) -> Tuple[int, int]:
        """
        Get the range of items that should be visible.
        
        Args:
            total_items: Total number of items
            selected_index: Currently selected item
            
        Returns:
            Tuple of (start_index, end_index) for visible items
        """
        pass
    
    def navigate_up(self, current_index: int, items: List[MenuItem], wrap_navigation: bool) -> int:
        """
        Handle up navigation for this renderer type.
        
        Args:
            current_index: Current selected index
            items: List of menu items
            wrap_navigation: Whether to wrap around at edges
            
        Returns:
            New selected index
        """
        # Default linear navigation (used by List and Carousel)
        if wrap_navigation:
            return (current_index - 1) % len(items)
        else:
            return max(0, current_index - 1)
    
    def navigate_down(self, current_index: int, items: List[MenuItem], wrap_navigation: bool) -> int:
        """
        Handle down navigation for this renderer type.
        
        Args:
            current_index: Current selected index
            items: List of menu items
            wrap_navigation: Whether to wrap around at edges
            
        Returns:
            New selected index
        """
        # Default linear navigation (used by List and Carousel)
        if wrap_navigation:
            return (current_index + 1) % len(items)
        else:
            return min(len(items) - 1, current_index + 1)
    
    def navigate_left(self, current_index: int, items: List[MenuItem], wrap_navigation: bool) -> int:
        """
        Handle left navigation for this renderer type.
        
        Args:
            current_index: Current selected index
            items: List of menu items
            wrap_navigation: Whether to wrap around at edges
            
        Returns:
            New selected index (default: no movement for linear renderers)
        """
        # Default: no horizontal navigation for linear renderers
        return current_index
    
    def navigate_right(self, current_index: int, items: List[MenuItem], wrap_navigation: bool) -> int:
        """
        Handle right navigation for this renderer type.
        
        Args:
            current_index: Current selected index
            items: List of menu items
            wrap_navigation: Whether to wrap around at edges
            
        Returns:
            New selected index (default: no movement for linear renderers)
        """
        # Default: no horizontal navigation for linear renderers
        return current_index

    # --- Common frame finalization (commit + optional overlay) ---------------
    def commit_base_frame(self, render_image, render_draw) -> None:
        """Persist the newly rendered menu frame and optionally layer overlay.

        Always commits as persistent because menu frames define the UI's base
        state reused by the background render loop. If the plugin manager has
        not yet produced an overlay snapshot, we invoke its overlay render as
        a fallback so the user still sees plugin info immediately.
        """
        try:
            fb.commit(render_image, persist=True)
        except Exception:
            try:
                self.ctx.image.paste(render_image)
            except Exception:
                pass

        pm = getattr(self.ctx, 'plugin_manager', None)
        if not pm:
            return
        try:
            if pm.get_overlay() is None:
                pm.dispatch_render_overlay(render_image, render_draw)
        except Exception:
            pass


class ListRenderer(MenuRenderer):
    """Classic vertical list renderer."""
    
    def __init__(self, context: WidgetContext, window_size: int = 7):
        super().__init__(context)
        self.window_size = window_size
        # Marquee state
        self._marquee_index: Optional[int] = None
        self._marquee_offset: int = 0
        self._marquee_last_update: float = 0.0
        self._marquee_interval: float = 0.4  # seconds between shifts
        self._marquee_padding = 4  # spaces at end before loop (still used for smooth pause)
    
    def get_visible_range(self, total_items: int, selected_index: int) -> Tuple[int, int]:
        """Calculate visible window for scrolling list."""
        if total_items <= self.window_size:
            return 0, total_items
        
        # Calculate offset to keep selected item visible
        offset = max(0, min(selected_index - self.window_size // 2, 
                           total_items - self.window_size))
        return offset, offset + self.window_size
    
    def render(self, items: List[MenuItem], selected_index: int, **kwargs) -> None:
        """Render items as vertical scrolling list."""
        if not items:
            return

        render_image, render_draw = fb.begin(clone=True)

        self.ctx.color.draw_menu_background(draw_override=render_draw)
        # Ensure outer border is always redrawn (may have been overwritten by fullscreen widgets)
        self.ctx.color.draw_border(draw_override=render_draw)
        
        # Draw title if provided
        title = kwargs.get('title')
        if title:
            render_draw.text((5, 15), title, fill=self.ctx.color.selected_text,
                              font=self.ctx.fonts.get('default'))
            base_y = 30
        else:
            base_y = self.ctx.default.start_text[1]

        start_idx, end_idx = self.get_visible_range(len(items), selected_index)
        visible_items = items[start_idx:end_idx]
        
        for i, item in enumerate(visible_items):
            actual_idx = start_idx + i
            is_selected = (actual_idx == selected_index)
            
            y_pos = base_y + self.ctx.default.text_gap * i
            
            # Draw selection highlight
            if is_selected:
                render_draw.rectangle(
                    (self.ctx.default.start_text[0] - 5, y_pos,
                     120, y_pos + 10),
                    fill=self.ctx.color.select
                )
            
            # Choose colors
            text_color = (self.ctx.color.selected_text if is_selected 
                         else self.ctx.color.text)
            
            # Draw icon if available
            x_offset = 0
            display_icon = item.get_display_icon()
            if display_icon:
                icon_font = self.ctx.fonts.get('icon')
                render_draw.text(
                    (self.ctx.default.start_text[0] - 2, y_pos),
                    display_icon,
                    font=icon_font,
                    fill=text_color
                )
                x_offset = 12
            
            # Draw label (with marquee for selected overlength item)
            max_len = kwargs.get('max_label_length', 20)
            if is_selected and len(item.label) > max_len:
                # If selection changed, reset marquee state
                if self._marquee_index != actual_idx:
                    self._marquee_index = actual_idx
                    self._marquee_offset = 0
                    self._marquee_last_update = time.time()
                padded = item.label + (' ' * self._marquee_padding)
                last_start = len(item.label) - max_len
                if last_start < 0:
                    last_start = 0
                # Clamp offset to last_start; once reached, hold one cycle then reset
                if self._marquee_offset > last_start:
                    self._marquee_offset = 0
                display_text = padded[self._marquee_offset:self._marquee_offset + max_len]
            else:
                display_text = item.label[:max_len]
            render_draw.text(
                (self.ctx.default.start_text[0] + x_offset, y_pos),
                display_text,
                font=self.ctx.fonts.get('default'),
                fill=text_color
            )
        
        # Draw status bar
        if self.ctx.status_bar:
            self.ctx.status_bar.render(render_draw, self.ctx.fonts.get('default'))

        # Finalize frame
        self.commit_base_frame(render_image, render_draw)
    # Background render loop will push frame


class GridRenderer(MenuRenderer):
    """Grid layout renderer (2x4 by default)."""
    
    def __init__(self, context: WidgetContext, cols: int = 2, rows: int = 4):
        super().__init__(context)
        self.cols = cols
        self.rows = rows
        self.items_per_page = cols * rows
    
    def get_visible_range(self, total_items: int, selected_index: int) -> Tuple[int, int]:
        """Calculate visible page for grid layout."""
        page_start = (selected_index // self.items_per_page) * self.items_per_page
        page_end = min(page_start + self.items_per_page, total_items)
        return page_start, page_end
    
    def navigate_up(self, current_index: int, items: List[MenuItem], wrap_navigation: bool) -> int:
        """Navigate up one row in grid."""
        current_row = current_index // self.cols
        current_col = current_index % self.cols
        
        if current_row > 0:
            # Move up one row in same column
            new_idx = (current_row - 1) * self.cols + current_col
            if new_idx < len(items):
                return new_idx
        elif wrap_navigation:
            # Wrap to bottom row, same column
            total_rows = (len(items) - 1) // self.cols
            new_idx = min(total_rows * self.cols + current_col, len(items) - 1)
            return new_idx
        
        return current_index
    
    def navigate_down(self, current_index: int, items: List[MenuItem], wrap_navigation: bool) -> int:
        """Navigate down one row in grid."""
        current_row = current_index // self.cols
        current_col = current_index % self.cols
        
        next_row = current_row + 1
        new_idx = next_row * self.cols + current_col
        
        if new_idx < len(items):
            # Move down one row in same column
            return new_idx
        elif wrap_navigation:
            # Wrap to top row, same column
            new_idx = current_col
            if new_idx < len(items):
                return new_idx
        
        return current_index
    
    def navigate_left(self, current_index: int, items: List[MenuItem], wrap_navigation: bool) -> int:
        """Navigate left in current row."""
        current_col = current_index % self.cols
        if current_col > 0:
            new_idx = current_index - 1
            if new_idx >= 0:
                return new_idx
        elif wrap_navigation:
            # Wrap to end of current row
            current_row = current_index // self.cols
            row_end = min((current_row + 1) * self.cols - 1, len(items) - 1)
            return row_end
        
        return current_index
    
    def navigate_right(self, current_index: int, items: List[MenuItem], wrap_navigation: bool) -> int:
        """Navigate right in current row."""
        current_row = current_index // self.cols
        current_col = current_index % self.cols
        
        if current_col < self.cols - 1 and current_index < len(items) - 1:
            new_idx = current_index + 1
            # Make sure we don't go beyond the current row or total items
            row_end = (current_row + 1) * self.cols
            if new_idx < min(row_end, len(items)):
                return new_idx
        elif wrap_navigation:
            # Wrap to beginning of current row
            row_start = current_row * self.cols
            if row_start < len(items):
                return row_start
        
        return current_index
    
    def render(self, items: List[MenuItem], selected_index: int, **kwargs) -> None:
        """Render items in grid layout."""
        if not items:
            return
        
        render_image, render_draw = fb.begin(clone=True)
        self.ctx.color.draw_menu_background(draw_override=render_draw)
        self.ctx.color.draw_border(draw_override=render_draw)
        
        start_idx, end_idx = self.get_visible_range(len(items), selected_index)
        visible_items = items[start_idx:end_idx]
        
        cell_width = 128 // self.cols
        cell_height = 25
        
        for i, item in enumerate(visible_items):
            actual_idx = start_idx + i
            is_selected = (actual_idx == selected_index)
            
            # Calculate grid position
            row = i // self.cols
            col = i % self.cols
            
            x = self.ctx.default.start_text[0] + (col * cell_width)
            y = self.ctx.default.start_text[1] + (row * cell_height)
            
            # Draw selection highlight
            if is_selected:
                render_draw.rectangle(
                    (x - 2, y - 2, x + cell_width - 3, y + cell_height - 3),
                    fill=self.ctx.color.select
                )
            
            # Choose colors
            text_color = (self.ctx.color.selected_text if is_selected 
                         else self.ctx.color.text)
            
            # Draw icon
            display_icon = item.get_display_icon()
            if display_icon:
                icon_font = self.ctx.fonts.get('icon')
                render_draw.text((x + 2, y), display_icon, font=icon_font, fill=text_color)
                # Draw short label below icon
                short_text = item.label[:8]
                render_draw.text((x, y + 13), short_text, 
                                  font=self.ctx.fonts.get('default'), fill=text_color)
            else:
                # Text only
                short_text = item.label[:10]
                render_draw.text((x, y + 8), short_text, 
                                  font=self.ctx.fonts.get('default'), fill=text_color)

        if self.ctx.status_bar:
            self.ctx.status_bar.render(render_draw, self.ctx.fonts.get('default'))

        # Finalize frame
        self.commit_base_frame(render_image, render_draw)
    # Background render loop flushes


class CarouselRenderer(MenuRenderer):
    """Single-item carousel renderer with large icons."""
    
    def get_visible_range(self, total_items: int, selected_index: int) -> Tuple[int, int]:
        """Carousel shows only current item."""
        return selected_index, selected_index + 1
    
    def navigate_up(self, current_index: int, items: List[MenuItem], wrap_navigation: bool) -> int:
        """Navigate left (up in carousel context)."""
        return self.navigate_left(current_index, items, wrap_navigation)
    
    def navigate_down(self, current_index: int, items: List[MenuItem], wrap_navigation: bool) -> int:
        """Navigate right (down in carousel context)."""
        return self.navigate_right(current_index, items, wrap_navigation)
    
    def navigate_left(self, current_index: int, items: List[MenuItem], wrap_navigation: bool) -> int:
        """Navigate to previous item in carousel."""
        if current_index > 0:
            return current_index - 1
        elif wrap_navigation:
            return len(items) - 1
        return current_index
    
    def navigate_right(self, current_index: int, items: List[MenuItem], wrap_navigation: bool) -> int:
        """Navigate to next item in carousel."""
        if current_index < len(items) - 1:
            return current_index + 1
        elif wrap_navigation:
            return 0
        return current_index
    
    def render(self, items: List[MenuItem], selected_index: int, **kwargs) -> None:
        """Render single item with large icon in center."""
        if not items or selected_index >= len(items):
            return
        
        render_image, render_draw = fb.begin(clone=True)
        self.ctx.color.draw_menu_background(draw_override=render_draw)
        self.ctx.color.draw_border(draw_override=render_draw)
        
        item = items[selected_index]
        total_items = len(items)
        
        center_x, center_y = 64, 64  # Screen center
        
        # Draw large icon
        display_icon = item.get_display_icon()
        if display_icon:
            try:
                from PIL import ImageFont
                large_font = ImageFont.truetype(
                    '/usr/share/fonts/truetype/fontawesome/fa-solid-900.ttf', 48)
                render_draw.text((center_x, center_y - 12), display_icon, 
                                  font=large_font, fill=self.ctx.color.selected_text, 
                                  anchor="mm")
            except:
                # Fallback to regular font
                render_draw.text((center_x - 10, center_y - 12), display_icon,
                                  font=self.ctx.fonts.get('icon'),
                                  fill=self.ctx.color.selected_text)
        
        # Draw title below icon
        try:
            from PIL import ImageFont
            title_font = ImageFont.truetype(
                '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf', 12)
            render_draw.text((center_x, center_y + 28), item.label.strip(),
                              font=title_font, fill=self.ctx.color.selected_text,
                              anchor="mm")
        except:
            # Fallback
            render_draw.text((center_x - len(item.label) * 3, center_y + 28),
                              item.label.strip(), font=self.ctx.fonts.get('default'),
                              fill=self.ctx.color.selected_text)
        
        # Draw navigation arrows if multiple items
        if total_items > 1:
            try:
                from PIL import ImageFont
                arrow_font = ImageFont.truetype(
                    '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 18)
                render_draw.text((20, center_y), "◀", font=arrow_font, 
                                  fill=self.ctx.color.text, anchor="mm")
                render_draw.text((108, center_y), "▶", font=arrow_font, 
                                  fill=self.ctx.color.text, anchor="mm")
            except:
                render_draw.text((15, center_y), "<", 
                                  font=self.ctx.fonts.get('default'),
                                  fill=self.ctx.color.text)
                render_draw.text((110, center_y), ">", 
                                  font=self.ctx.fonts.get('default'),
                                  fill=self.ctx.color.text)

        if self.ctx.status_bar:
            self.ctx.status_bar.render(render_draw, self.ctx.fonts.get('default'))

        # Finalize frame
        self.commit_base_frame(render_image, render_draw)
    # Flush handled by background loop


class Menu:
    """Main menu controller with pluggable renderers."""
    
    def __init__(self, 
                 context: WidgetContext,
                 renderer: MenuRenderer,
                 wrap_navigation: bool = True):
        """
        Initialize menu system.
        
        Args:
            context: Widget context for drawing
            renderer: Menu renderer implementation
            wrap_navigation: Whether to wrap around at list ends
        """
        self.ctx = context
        self.renderer = renderer
        self.wrap_navigation = wrap_navigation
        
        self.items: List[MenuItem] = []
        self.selected_index = 0
        self.running = False
        self.title = ""
    
    def set_items(self, items: List[MenuItem]) -> None:
        """Set menu items and reset selection."""
        self.items = items
        self.selected_index = 0
        self._ensure_valid_selection()
    
    def set_title(self, title: str) -> None:
        """Set the menu's title."""
        self.title = title

    def add_item(self, item: MenuItem) -> None:
        """Add single item to menu."""
        self.items.append(item)
    
    def clear_items(self) -> None:
        """Clear all menu items."""
        self.items.clear()
        self.selected_index = 0
    
    def _ensure_valid_selection(self) -> None:
        """Ensure selected index is valid."""
        if not self.items:
            self.selected_index = 0
        else:
            self.selected_index = max(0, min(self.selected_index, len(self.items) - 1))
    
    def navigate_up(self) -> None:
        """Move selection up/previous."""
        if not self.items:
            return
        
        self.selected_index = self.renderer.navigate_up(
            self.selected_index, self.items, self.wrap_navigation
        )
    
    def navigate_down(self) -> None:
        """Move selection down/next."""
        if not self.items:
            return
        
        self.selected_index = self.renderer.navigate_down(
            self.selected_index, self.items, self.wrap_navigation
        )
    
    def navigate_left(self) -> None:
        """Handle left navigation (renderer-specific)."""
        if not self.items:
            return
        
        self.selected_index = self.renderer.navigate_left(
            self.selected_index, self.items, self.wrap_navigation
        )
    
    def navigate_right(self) -> None:
        """Handle right navigation (renderer-specific)."""
        if not self.items:
            return
        
        self.selected_index = self.renderer.navigate_right(
            self.selected_index, self.items, self.wrap_navigation
        )
    
    def get_selected_item(self) -> Optional[MenuItem]:
        """Get currently selected menu item."""
        if self.items and 0 <= self.selected_index < len(self.items):
            return self.items[self.selected_index]
        return None
    
    def select_current(self) -> Optional[Any]:
        """Execute action of currently selected item or handle specialized behavior."""
        item = self.get_selected_item()
        if item:
            return item.handle_selection()
        return None
    
    def render(self, **kwargs) -> None:
        """Render the menu using current renderer."""
        # Add title to the kwargs passed to the renderer
        render_kwargs = kwargs.copy()
        if self.title:
            render_kwargs['title'] = self.title

        if not self.items:
            # Show empty state
            render_image, render_draw = fb.begin(clone=True)
            self.ctx.color.draw_menu_background(draw_override=render_draw)
            self.ctx.color.draw_border(draw_override=render_draw)
            render_draw.text((10, 50), "No items available", 
                              font=self.ctx.fonts.get('default'),
                              fill=self.ctx.color.text)
            if self.ctx.status_bar:
                self.ctx.status_bar.render(render_draw, self.ctx.fonts.get('default'))

            # Finalize empty state frame
            self.renderer.commit_base_frame(render_image, render_draw)
            # Background loop will handle LCD flush
        else:
            self.renderer.render(self.items, self.selected_index, **render_kwargs)
    
    def run_interactive(self, 
                       exit_keys: List[str] = None,
                       custom_handlers: Dict[str, Callable] = None) -> Optional[Any]:
        """
        Run interactive menu loop.
        
        Args:
            exit_keys: Button names that exit the menu
            custom_handlers: Custom button handlers
            
        Returns:
            Selected action or None if cancelled
        """
        if exit_keys is None:
            exit_keys = ["KEY_LEFT_PIN"]
        
        if custom_handlers is None:
            custom_handlers = {}
        
        self.running = True
        
        marquee_stop = threading.Event()

        def _marquee_thread():
            # Only applies to ListRenderer
            if not isinstance(self.renderer, ListRenderer):
                return
            while not marquee_stop.is_set() and self.running:
                # Advance marquee state if needed
                updated = False
                try:
                    # Determine selected item & if needs scrolling
                    if self.items:
                        sel_idx = self.selected_index
                        if 0 <= sel_idx < len(self.items):
                            item = self.items[sel_idx]
                            max_len = 17  # default; could be extended to dynamic
                            if len(item.label) > max_len:
                                now = time.time()
                                # Initialize if selection changed
                                if self.renderer._marquee_index != sel_idx:
                                    self.renderer._marquee_index = sel_idx
                                    self.renderer._marquee_offset = 0
                                    self.renderer._marquee_last_update = now
                                if now - self.renderer._marquee_last_update >= self.renderer._marquee_interval:
                                    self.renderer._marquee_last_update = now
                                    last_start = len(item.label) - max_len
                                    if last_start < 0:
                                        last_start = 0
                                    if self.renderer._marquee_offset >= last_start:
                                        # Reset after allowing the last frame to be visible once
                                        self.renderer._marquee_offset = 0
                                    else:
                                        self.renderer._marquee_offset += 1
                                    updated = True
                    if updated:
                        # Re-render to show next marquee frame
                        self.render()
                except Exception:
                    pass
                # Sleep small interval to keep CPU low
                time.sleep(0.05)

        # Start marquee animation thread if relevant
        marquee_thread = None
        if isinstance(self.renderer, ListRenderer):
            marquee_thread = threading.Thread(target=_marquee_thread, daemon=True)
            marquee_thread.start()

        last_nav_time = 0.0
        accelerating = False

        from input_events import clear_button_events as _clear_events
        pending_left_right_press = None  # track initial press for left/right
        while self.running:
            self.render()
            evt = self.ctx.get_button_event(timeout=0.25)
            if not evt:
                continue
            etype = evt.get('type')
            button = evt.get('button')

            # Acceleration only for vertical navigation
            if etype == "LONG_PRESS" and button in ("KEY_UP_PIN", "KEY_DOWN_PIN"):
                accelerating = True
                last_nav_time = time.time()
                if button == "KEY_UP_PIN":
                    self.navigate_up()
                elif button == "KEY_DOWN_PIN":
                    self.navigate_down()
                continue
            if accelerating and etype == "REPEAT" and button in ("KEY_UP_PIN", "KEY_DOWN_PIN"):
                now = time.time()
                if now - last_nav_time >= 0.05:
                    last_nav_time = now
                    if button == "KEY_UP_PIN":
                        self.navigate_up()
                    else:
                        self.navigate_down()
                continue

            # LEFT/RIGHT should act only on release (debounce repeats)
            if button in ("KEY_LEFT_PIN", "KEY_RIGHT_PIN"):
                if etype == "PRESS":
                    pending_left_right_press = button
                    continue
                if etype == "RELEASE" and pending_left_right_press == button:
                    # treat release as action
                    if button == "KEY_LEFT_PIN":
                        # Exit only for list renderer; otherwise navigate
                        if isinstance(self.renderer, ListRenderer) and "KEY_LEFT_PIN" in exit_keys:
                            self.running = False
                            return None
                        else:
                            self.navigate_left()
                    else:  # RIGHT
                        if isinstance(self.renderer, ListRenderer):
                            action = self.select_current()
                            if action is not None:
                                # Flush any queued events before returning
                                _clear_events()
                                self.running = False
                                return action
                        else:
                            self.navigate_right()
                    pending_left_right_press = None
                # ignore REPEAT / LONG_PRESS for left/right
                continue

            # Handle vertical navigation on PRESS/REPEAT only
            if button in ("KEY_UP_PIN", "KEY_DOWN_PIN"):
                if etype in ("PRESS",):
                    if button == "KEY_UP_PIN":
                        self.navigate_up()
                    else:
                        self.navigate_down()
                # REPEAT handled in acceleration block
                continue

            # Selection / exit actions on RELEASE to avoid repeats during holds
            if button == "KEY_PRESS_PIN":
                if etype == "RELEASE":
                    action = self.select_current()
                    if action is not None:
                        _clear_events()
                        self.running = False
                        return action
                continue

            if button in exit_keys and etype == "RELEASE":
                self.running = False
                return None

            # Custom handlers trigger on RELEASE
            if button in custom_handlers and etype == "RELEASE":
                result = custom_handlers[button]()
                if result is not None:
                    _clear_events()
                    self.running = False
                    return result
                continue
        
        # Stop marquee thread
        marquee_stop.set()
        if marquee_thread:
            try:
                marquee_thread.join(timeout=0.2)
            except Exception:
                pass

        return None
    
    def stop(self) -> None:
        """Stop the interactive menu loop."""
        self.running = False


# Convenience functions for creating common menu types
def create_list_menu(context: WidgetContext, **kwargs) -> Menu:
    """Create a menu with list renderer."""
    renderer = ListRenderer(context, **kwargs)
    return Menu(context, renderer)


def create_grid_menu(context: WidgetContext, **kwargs) -> Menu:
    """Create a menu with grid renderer."""
    renderer = GridRenderer(context, **kwargs)
    return Menu(context, renderer)


def create_carousel_menu(context: WidgetContext, **kwargs) -> Menu:
    """Create a menu with carousel renderer."""
    renderer = CarouselRenderer(context, **kwargs)
    return Menu(context, renderer)