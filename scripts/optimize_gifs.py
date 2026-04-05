#!/usr/bin/env python3
"""
Optimize screensaver GIFs for the current LCD resolution.

- Backs up originals to img/screensaver/originals/
- Converts GIFs to the LCD resolution (128x128 or 240x240)
- Preserves frame timing and animation quality (LANCZOS resize)
- Skips GIFs already at the correct size
- Safe to run multiple times

Usage:
    python3 scripts/optimize_gifs.py
    python3 scripts/optimize_gifs.py --restore   # restore originals
"""

import os
import sys
import shutil
import json

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

from PIL import Image, ImageSequence

# Detect target resolution from gui_conf.json
INSTALL_DIR = os.path.abspath(os.path.join(__file__, "..", ".."))
CONF_PATH = os.path.join(INSTALL_DIR, "gui_conf.json")
SCREENSAVER_DIR = os.path.join(INSTALL_DIR, "img", "screensaver")
ORIGINALS_DIR = os.path.join(SCREENSAVER_DIR, "originals")

def _get_target_size():
    try:
        with open(CONF_PATH) as f:
            conf = json.load(f)
        dtype = conf.get("DISPLAY", {}).get("type", "ST7735_128")
    except Exception:
        dtype = "ST7735_128"
    if dtype == "ST7789_240":
        return 240, 240
    return 128, 128


def optimize():
    target_w, target_h = _get_target_size()
    print(f"Target resolution: {target_w}x{target_h}")

    os.makedirs(ORIGINALS_DIR, exist_ok=True)

    gif_files = sorted(
        f for f in os.listdir(SCREENSAVER_DIR)
        if f.lower().endswith(".gif") and os.path.isfile(os.path.join(SCREENSAVER_DIR, f))
    )

    if not gif_files:
        print("No GIF files found.")
        return

    optimized = 0
    skipped = 0

    for name in gif_files:
        src = os.path.join(SCREENSAVER_DIR, name)

        # Check if already at target size
        try:
            with Image.open(src) as img:
                if img.size == (target_w, target_h):
                    skipped += 1
                    print(f"  SKIP {name} (already {target_w}x{target_h})")
                    continue
                orig_size = img.size
        except Exception as e:
            print(f"  ERROR {name}: {e}")
            continue

        # Backup original (only if not already backed up)
        backup = os.path.join(ORIGINALS_DIR, name)
        if not os.path.exists(backup):
            shutil.copy2(src, backup)

        # Convert
        try:
            frames = []
            durations = []
            with Image.open(src) as gif:
                for frame in ImageSequence.Iterator(gif):
                    resized = frame.convert("RGBA").resize(
                        (target_w, target_h), Image.LANCZOS
                    )
                    frames.append(resized)
                    dur = frame.info.get("duration") or gif.info.get("duration") or 100
                    durations.append(dur)

            if not frames:
                print(f"  ERROR {name}: no frames")
                continue

            # Save optimized GIF
            frames[0].save(
                src,
                save_all=True,
                append_images=frames[1:],
                duration=durations,
                loop=0,
                optimize=False,
            )
            optimized += 1
            print(f"  OK {name}: {orig_size[0]}x{orig_size[1]} -> {target_w}x{target_h} ({len(frames)} frames)")

        except Exception as e:
            print(f"  ERROR {name}: {e}")
            # Restore from backup on error
            if os.path.exists(backup):
                shutil.copy2(backup, src)

    print(f"\nDone: {optimized} optimized, {skipped} skipped")
    print(f"Originals backed up in: {ORIGINALS_DIR}/")


def restore():
    """Restore original GIFs from backup."""
    if not os.path.isdir(ORIGINALS_DIR):
        print("No originals directory found.")
        return

    restored = 0
    for name in os.listdir(ORIGINALS_DIR):
        if not name.lower().endswith(".gif"):
            continue
        src = os.path.join(ORIGINALS_DIR, name)
        dst = os.path.join(SCREENSAVER_DIR, name)
        shutil.copy2(src, dst)
        restored += 1
        print(f"  Restored: {name}")

    print(f"\nRestored {restored} GIFs from originals/")


if __name__ == "__main__":
    if "--restore" in sys.argv:
        restore()
    else:
        optimize()
