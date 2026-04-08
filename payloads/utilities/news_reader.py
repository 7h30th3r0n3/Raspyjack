#!/usr/bin/env python3
"""
RaspyJack Payload -- RSS News Reader
======================================
Author: 7h30th3r0n3

Fetches and displays RSS feed articles from configurable sources.
Parses RSS XML with xml.etree.ElementTree. Shows scrollable article
titles with summaries on selection.

Controls:
  UP / DOWN    -- Scroll article list
  OK           -- Open article summary
  KEY1         -- Switch feed
  KEY2         -- Refresh current feed
  KEY3         -- Exit (or back from summary)

Config: /root/Raspyjack/loot/News/feeds.json
"""

import os
import sys
import json
import time
import signal
import xml.etree.ElementTree as ET
from urllib.request import urlopen, Request
from urllib.error import URLError
from html import unescape
import re

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROW_H = 12
CONFIG_DIR = "/root/Raspyjack/loot/News"
CONFIG_PATH = os.path.join(CONFIG_DIR, "feeds.json")

DEFAULT_FEEDS = [
    {"name": "HackerNews", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "BleepComp", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "Krebs", "url": "https://krebsonsecurity.com/feed/"},
]

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
running = True
feeds = list(DEFAULT_FEEDS)
feed_idx = 0
articles = []
article_idx = 0
scroll_offset = 0
view_mode = "list"  # "list" or "detail"
detail_scroll = 0


def cleanup(*_args):
    global running
    running = False


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def load_feeds():
    global feeds
    try:
        with open(CONFIG_PATH, "r") as f:
            loaded = json.load(f)
        if isinstance(loaded, list) and loaded:
            feeds = loaded
    except Exception:
        feeds = list(DEFAULT_FEEDS)


def save_feeds():
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump(feeds, f, indent=2)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# RSS parsing
# ---------------------------------------------------------------------------


def strip_html(text):
    """Remove HTML tags from text."""
    cleaned = re.sub(r"<[^>]+>", "", text)
    return unescape(cleaned).strip()


def fetch_feed(url):
    """Fetch and parse RSS feed. Returns list of dicts with title/summary."""
    try:
        req = Request(url, headers={"User-Agent": "RaspyJack/1.0"})
        with urlopen(req, timeout=15) as resp:
            data = resp.read()
    except (URLError, OSError) as exc:
        return [{"title": f"Error: {str(exc)[:30]}", "summary": ""}]

    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return [{"title": "XML parse error", "summary": ""}]

    items = []
    # Standard RSS 2.0: channel/item
    for item in root.iter("item"):
        title_el = item.find("title")
        desc_el = item.find("description")
        title = strip_html(title_el.text or "") if title_el is not None else "No title"
        summary = strip_html(desc_el.text or "") if desc_el is not None else ""
        items.append({"title": title, "summary": summary[:500]})

    # Atom fallback: feed/entry
    if not items:
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        for entry in root.iter("{http://www.w3.org/2005/Atom}entry"):
            title_el = entry.find("atom:title", ns) or entry.find(
                "{http://www.w3.org/2005/Atom}title"
            )
            sum_el = entry.find("atom:summary", ns) or entry.find(
                "{http://www.w3.org/2005/Atom}summary"
            )
            title = strip_html(title_el.text or "") if title_el is not None else "No title"
            summary = strip_html(sum_el.text or "") if sum_el is not None else ""
            items.append({"title": title, "summary": summary[:500]})

    return items if items else [{"title": "No articles found", "summary": ""}]


# ---------------------------------------------------------------------------
# Text wrapping
# ---------------------------------------------------------------------------


def wrap_text(text, max_chars=20):
    """Wrap text into lines of max_chars width."""
    words = text.split()
    lines = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 <= max_chars:
            current = (current + " " + word).strip()
        else:
            if current:
                lines.append(current)
            # Handle words longer than max_chars
            while len(word) > max_chars:
                lines.append(word[:max_chars])
                word = word[max_chars:]
            current = word
    if current:
        lines.append(current)
    return lines if lines else [""]


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------


def draw_list(lcd, font):
    """Render the article list view."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    feed_name = feeds[feed_idx].get("name", "Feed")[:10]
    d.text((2, 1), f"News: {feed_name}", font=font, fill="#00CCFF")

    if not articles:
        d.text((2, 40), "No articles", font=font, fill="#888")
    else:
        # Show articles in scrollable list
        max_visible = 8
        visible = articles[scroll_offset:scroll_offset + max_visible]
        for i, art in enumerate(visible):
            y = 15 + i * ROW_H
            idx = scroll_offset + i
            color = "#FFFF00" if idx == article_idx else "#CCCCCC"
            marker = ">" if idx == article_idx else " "
            title = art["title"][:19]
            d.text((2, y), f"{marker}{title}", font=font, fill=color)

        # Count indicator
        total = len(articles)
        d.text((80, 1), f"{article_idx + 1}/{total}", font=font, fill="#888")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Read K1:Feed K3:X", font=font, fill="#AAA")

    lcd.LCD_ShowImage(img, 0, 0)


def draw_detail(lcd, font):
    """Render the article detail/summary view."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "Article", font=font, fill="#FFAA00")

    if not articles or article_idx >= len(articles):
        d.text((2, 30), "No article", font=font, fill="#888")
    else:
        art = articles[article_idx]
        # Title lines
        title_lines = wrap_text(art["title"], 20)
        # Summary lines
        summary = art.get("summary", "")
        summary_lines = wrap_text(summary, 20) if summary else ["No summary"]
        all_lines = title_lines + ["---"] + summary_lines

        max_visible = 8
        visible = all_lines[detail_scroll:detail_scroll + max_visible]
        for i, line in enumerate(visible):
            y = 15 + i * ROW_H
            color = "#00FF88" if i < len(title_lines) - detail_scroll and detail_scroll == 0 else "#CCCCCC"
            if line == "---":
                color = "#555"
            d.text((2, y), line[:22], font=font, fill=color)

        if len(all_lines) > max_visible:
            pos = f"{detail_scroll + 1}/{max(1, len(all_lines) - max_visible + 1)}"
            d.text((90, 1), pos, font=font, fill="#888")

    # Footer
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "UP/DN:Scrl KEY3:Back", font=font, fill="#AAA")

    lcd.LCD_ShowImage(img, 0, 0)


def draw_loading(lcd, font, msg="Loading..."):
    """Show a loading screen."""
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "NEWS READER", font=font, fill="#00CCFF")
    d.text((10, 55), msg, font=font, fill="#FFFF00")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    global running, feed_idx, articles, article_idx
    global scroll_offset, view_mode, detail_scroll

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    font = scaled_font()

    load_feeds()
    save_feeds()  # Ensure config file exists with defaults

    # Initial fetch
    draw_loading(lcd, font, "Fetching feed...")
    articles = fetch_feed(feeds[feed_idx]["url"])
    article_idx = 0
    scroll_offset = 0

    try:
        while running:
            btn = get_button(PINS, GPIO)

            # Detail view
            if view_mode == "detail":
                if btn == "UP":
                    if detail_scroll > 0:
                        detail_scroll -= 1
                    time.sleep(0.15)
                elif btn == "DOWN":
                    detail_scroll += 1
                    time.sleep(0.15)
                elif btn == "KEY3":
                    view_mode = "list"
                    detail_scroll = 0
                    time.sleep(0.2)
                    continue

                draw_detail(lcd, font)
                time.sleep(0.05)
                continue

            # List view controls
            if btn == "UP":
                if article_idx > 0:
                    article_idx -= 1
                    if article_idx < scroll_offset:
                        scroll_offset = article_idx
                time.sleep(0.15)
            elif btn == "DOWN":
                if article_idx < len(articles) - 1:
                    article_idx += 1
                    if article_idx >= scroll_offset + 8:
                        scroll_offset = article_idx - 7
                time.sleep(0.15)
            elif btn == "OK":
                if articles:
                    view_mode = "detail"
                    detail_scroll = 0
                time.sleep(0.2)
                continue
            elif btn == "KEY1":
                feed_idx = (feed_idx + 1) % len(feeds)
                draw_loading(lcd, font, "Switching feed...")
                articles = fetch_feed(feeds[feed_idx]["url"])
                article_idx = 0
                scroll_offset = 0
                time.sleep(0.3)
            elif btn == "KEY2":
                draw_loading(lcd, font, "Refreshing...")
                articles = fetch_feed(feeds[feed_idx]["url"])
                article_idx = 0
                scroll_offset = 0
                time.sleep(0.3)
            elif btn == "KEY3":
                break

            draw_list(lcd, font)
            time.sleep(0.05)

    finally:
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
