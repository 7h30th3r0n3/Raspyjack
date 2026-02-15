#!/usr/bin/env python3
"""
RaspyJack payload – Navarro username checker
=============================================================================
This payload prompts for a username, runs Navarro, saves JSON results under
loot/OSINT/, and shows found profile URLs on the 128×128 LCD.
-Credits: https://github.com/noobosaurus-r3x/Navarro
-Device Port Author: @hosseios https://github.com/Hosseios

requirements
-----------
  • python3
  • Navarro present at /home/raspyjack/Navarro/navarro.py
  • qrcode sudo apt install -y python3-qrcode python3-pil

Controls
--------
  • UP/DOWN: navigate fields/lists
  • LEFT/RIGHT: page results
  • OK: edit username (on-screen keyboard)
  • KEY1: Start/Rescan
  • KEY3: Back/Exit
"""

import os, sys, time, signal, subprocess, json, fcntl, re
from urllib.parse import urlparse
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

import RPi.GPIO as GPIO
import LCD_1in44
from PIL import Image, ImageDraw, ImageFont
from payloads._input_helper import get_button
try:
    import qrcode 
except Exception:
    qrcode = None


# ----------------------------- Config -----------------------------
PINS = {
    "UP": 6,
    "DOWN": 19,
    "LEFT": 5,
    "RIGHT": 26,
    "OK": 13,
    "KEY1": 21,
    "KEY2": 20,
    "KEY3": 16,
}

WIDTH, HEIGHT = 128, 128
FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_SMALL_SIZE = 9
FONT_BIG_SIZE = 11

NAVARRO_PATHS = [
    "/root/Raspyjack/Navarro/navarro.py",
    "/home/raspyjack/Navarro/navarro.py",
]
NAVARRO_PATH = next((p for p in NAVARRO_PATHS if os.path.exists(p)), NAVARRO_PATHS[0])
LOOT_BASE = "/root/Raspyjack/loot/OSINT"
os.makedirs(LOOT_BASE, exist_ok=True)
APP_RUNNING = True


# --------------------------- LCD / Fonts ---------------------------
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)

def load_font(size: int):
    try:
        return ImageFont.truetype(FONT_PATH, size)
    except Exception:
        return ImageFont.load_default()

font_small = load_font(FONT_SMALL_SIZE)
font_big = load_font(FONT_BIG_SIZE)


# ----------------------------- GPIO -------------------------------
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)


# ------------------------- Drawing helpers ------------------------
def new_canvas():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    return img, ImageDraw.Draw(img)


def draw_center(lines, *, small: bool = False, footer: str | None = None):
    img, d = new_canvas()
    f = font_small if small else font_big
    if isinstance(lines, str):
        lines = [lines]
    heights = [d.textbbox((0, 0), s, font=f)[3] for s in lines]
    total_h = sum(heights) + max(0, len(lines) - 1) * 2
    y = (HEIGHT - total_h) // 2
    for s, h in zip(lines, heights):
        w = d.textbbox((0, 0), s, font=f)[2]
        d.text(((WIDTH - w) // 2, y), s, font=f, fill="#00FF00")
        y += h + 2
    if footer:
        d.text((2, HEIGHT - 10), footer[:20], font=font_small, fill="#999999")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_home(username: str, cursor: int):
    img, d = new_canvas()
    d.text((2, 2), "Navarro", font=font_big, fill="#00FF00")
    d.line([(0, 14), (WIDTH, 14)], fill="#202020")
    rows = [
        ("Username", username or "<enter>"),
        ("Start", "Run ▶" if username else "Disabled"),
    ]
    y = 24
    for i, (k, v) in enumerate(rows):
        prefix = ">" if i == cursor else " "
        d.text((4, y), f"{prefix} {k}: ", font=font_small, fill="#FFFFFF")
        d.text((70, y), v[:14], font=font_small, fill=("#00FF00" if i == cursor else "#CCCCCC"))
        y += 16
    d.line([(0, HEIGHT - 12), (WIDTH, HEIGHT - 12)], fill="#202020")
    d.text((2, HEIGHT - 10), "OK=Edit  K1 Start  K3 Back", font=font_small, fill="#999999")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_keyboard(buffer: str, grid: list[list[str]], gx: int, gy: int, page_name: str):
    img, d = new_canvas()
    d.text((2, 2), f"Type ({page_name})", font=font_small, fill="#00FF00")
    d.line([(0, 14), (WIDTH, 14)], fill="#202020")
    d.text((2, 18), buffer[-18:], font=font_big, fill="#FFFFFF")
    top = 36
    padding = 4
    max_cols = max(len(row) for row in grid) if grid else 1
    cell_w = max(12, min(16, (WIDTH - 2 * padding) // max_cols))
    cell_h = 16
    left = padding
    for y, row in enumerate(grid):
        for x, key in enumerate(row):
            rx = left + x * cell_w
            ry = top + y * cell_h
            sel = (x == gx and y == gy)
            d.rectangle((rx, ry, rx + cell_w - 2, ry + cell_h - 2), outline=("#00FF00" if sel else "#404040"))
            label = key if key != " " else "␣"
            tw = d.textbbox((0, 0), label[:2], font=font_small)[2]
            d.text((rx + max(1, (cell_w - tw) // 2), ry + 2), label[:2], font=font_small, fill=("#00FF00" if sel else "#CCCCCC"))
    d.line([(0, HEIGHT - 12), (WIDTH, HEIGHT - 12)], fill="#202020")
    d.text((2, HEIGHT - 10), "OK=Add  K1=Backsp  K2=Page  Enter  K3=Cancel", font=font_small, fill="#999999")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_running(user: str, bounce_pos: int):
    img, d = new_canvas()
    d.text((2, 2), f"{user}", font=font_small, fill="#00FF00")
    d.line([(0, 14), (WIDTH, 14)], fill="#202020")

    # Status line (single): "Checking <user>…"
    d.text((2, 18), f"Checking {user}…", font=font_small, fill="#FFFFFF")

    # Bouncing bar
    bar_y1, bar_y2 = 36, 42
    d.rectangle((2, bar_y1, WIDTH - 2, bar_y2), outline="#404040")
    seg_w = 24
    pos = max(2, min(WIDTH - 2 - seg_w, 2 + bounce_pos))
    d.rectangle((pos, bar_y1 + 1, pos + seg_w, bar_y2 - 1), fill="#00AA00")

    # No duplicate bottom status line

    d.text((2, HEIGHT - 10), "K3 Stop", font=font_small, fill="#999999")
    LCD.LCD_ShowImage(img, 0, 0)


def _shorten_middle(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    if max_chars <= 3:
        return text[:max_chars]
    keep = max_chars - 3
    left = keep // 2
    right = keep - left
    return text[:left] + "…" + text[-right:]


def draw_results(user: str, items: list[tuple[str, str]], page: int, selected_idx: int, per_page: int = 6):
    img, d = new_canvas()
    d.text((2, 2), f"Results: {user}", font=font_small, fill="#00FF00")
    d.line([(0, 14), (WIDTH, 14)], fill="#202020")
    total_pages = max(1, (len(items) + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    for i, (platform, url) in enumerate(items[start:start + per_page]):
        y = 18 + i * 16
        gi = start + i
        render = platform[:20]
        fill = "#00FF00" if gi == selected_idx else "#FFFFFF"
        d.text((2, y), f"• {render}", font=font_small, fill=fill)
    d.text((WIDTH - 34, HEIGHT - 10), f"{page}/{total_pages}", font=font_small, fill="#999999")
    d.line([(0, HEIGHT - 12), (WIDTH, HEIGHT - 12)], fill="#202020")
    d.text((2, HEIGHT - 10), "OK=Detail  LR=Pages  K3 Back", font=font_small, fill="#999999")
    LCD.LCD_ShowImage(img, 0, 0)


def draw_result_detail(user: str, platform: str, url: str, idx: int, total: int):
    img, d = new_canvas()
    d.text((2, 2), f"{platform}  {idx+1}/{total}", font=font_small, fill="#00FF00")
    d.line([(0, 14), (WIDTH, 14)], fill="#202020")

    # Try to render a QR code on the right (64x64). If unavailable, use full width for text
    text_right = WIDTH - 4
    if qrcode is not None:
        try:
            qr = qrcode.QRCode(version=None, box_size=2, border=1)
            qr.add_data(url)
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
            qr_img = qr_img.resize((64, 64))
            img.paste(qr_img, (WIDTH - 64 - 2, 20))
            text_right = WIDTH - 64 - 6  # leave gap before QR
        except Exception:
            text_right = WIDTH - 4

    # wrap url text within the available area
    max_w = max(20, text_right - 2)
    words = [url]
    lines: list[str] = []
    while words:
        w = words.pop(0)
        acc = ""
        for ch in w:
            test = acc + ch
            tw = d.textbbox((0, 0), test, font=font_small)[2]
            if tw <= max_w:
                acc = test
            else:
                lines.append(acc)
                acc = ch
        if acc:
            lines.append(acc)
        if len(lines) > 8:
            lines = lines[:8]
            break
    y = 20
    for line in lines:
        d.text((2, y), line, font=font_small, fill="#FFFFFF")
        y += 12
    d.line([(0, HEIGHT - 12), (WIDTH, HEIGHT - 12)], fill="#202020")
    d.text((2, HEIGHT - 10), "LR=Prev/Next  K3 Back", font=font_small, fill="#999999")
    LCD.LCD_ShowImage(img, 0, 0)


# ------------------------- Buttons/helpers ------------------------
def first_pressed() -> str | None:
    return get_button(PINS, GPIO)


def wait_release(name: str):
    while APP_RUNNING and GPIO.input(PINS[name]) == 0:
        time.sleep(0.03)


# ------------------------------ Runner ----------------------------
_URL_RE = re.compile(r"https?://[^\s]+", re.IGNORECASE)
_HOST_RE = re.compile(r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:/|\b)")
_CHECK_RE = re.compile(r"^\s*[^A-Za-z0-9]*\s*Checking\s+\S+\.\.\.\s+([^\s]+)", re.IGNORECASE)
_SUMMARY_RE = re.compile(r"Username:\s*\S+\s*\|\s*Found:\s*(\d+)/(\d+)", re.IGNORECASE)
_PCT_RE = re.compile(r"(\d{1,3})%")


def _extract_platform_from_line(line: str) -> str | None:
    line = line.strip()
    if not line:
        return None
    # If a URL is present, extract hostname
    for token in _URL_RE.findall(line):
        try:
            host = urlparse(token).netloc or token.split("//", 1)[1].split("/", 1)[0]
            return host
        except Exception:
            continue
    # Otherwise, try explicit activity keywords (word-bound)
    for key in ("Checking", "Site", "Testing", "Scanning"):
        if re.search(rf"\b{key}\b", line, re.IGNORECASE):
            m = _HOST_RE.search(line)
            if m:
                return m.group(1)
            return None
    # As a last resort, any hostname-looking token
    m = _HOST_RE.search(line)
    if m:
        return m.group(1)
    return None


def run_navarro(username: str) -> tuple[list[str], str]:
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_dir = os.path.join(LOOT_BASE, f"navarro_{username}_{ts}")
    os.makedirs(run_dir, exist_ok=True)
    json_path = os.path.join(run_dir, "results.json")
    log_path = os.path.join(run_dir, "log.txt")
    cmd = ["python3", "-u", NAVARRO_PATH, username, "--export", json_path]

    start_t = time.time()
    # Simplified UI: no platform/percent parsing
    bounce_pos = 2
    bounce_dir = 4
    last_platform: str | None = None
    with open(log_path, "w", encoding="utf-8") as logf:
        try:
            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=env)
        except Exception as exc:
            logf.write(f"Failed to spawn navarro: {exc}\n")
            return [], run_dir
        try:
            # make stdout non-blocking
            if proc.stdout is not None:
                fd = proc.stdout.fileno()
                fl = fcntl.fcntl(fd, fcntl.F_GETFL)
                fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
            buf = ""
            while True:
                if not APP_RUNNING:
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                    break
                if proc.poll() is not None:
                    break
                # drain any available output (non-blocking)
                chunk = ""
                try:
                    if proc.stdout is not None:
                        chunk = proc.stdout.read() or ""
                except Exception:
                    chunk = ""
                if chunk:
                    buf += chunk
                    while True:
                        nl = buf.find('\n')
                        if nl == -1:
                            break
                        line = buf[:nl + 1]
                        buf = buf[nl + 1:]
                        logf.write(line)
                        last_line = line.strip()
                        # Ignore platform/percent; keep logging only
                # update bouncing bar position
                bounce_pos += bounce_dir
                if bounce_pos >= (WIDTH - 2 - 24) or bounce_pos <= 2:
                    bounce_dir *= -1
                draw_running(username, bounce_pos)
                # Allow stop
                if get_button(PINS, GPIO) == "KEY3":
                    try:
                        proc.terminate()
                        time.sleep(0.3)
                        proc.kill()
                    except Exception:
                        pass
                    break
                time.sleep(0.05)
        finally:
            try:
                proc.wait(timeout=2)
            except Exception:
                pass

    # Parse JSON for found_profiles
    items: list[tuple[str, str]] = []  # (platform, url)
    try:
        with open(json_path, "r", encoding="utf-8") as jf:
            data = json.load(jf)
        # Data structure: { "username": { "found_profiles": {Site: URL, ...}, ... } }
        # Pull the first (only) root key
        if isinstance(data, dict) and data:
            root = next(iter(data.values()))
            found = root.get("found_profiles") or {}
            for platform, url in found.items():
                items.append((platform, url))
    except Exception:
        pass

    return items, run_dir


# ------------------------------ Main UI ---------------------------
def _handle_exit_signal(_signum, _frame):
    global APP_RUNNING
    APP_RUNNING = False


def _safe_shutdown():
    try:
        LCD.LCD_Clear()
    except Exception:
        pass
    try:
        GPIO.cleanup()
    except Exception:
        pass


def main():
    username = ""
    cursor = 0  # 0 Username, 1 Start
    page = 1
    results: list[tuple[str, str]] = []
    selected_idx = 0
    in_detail = False

    signal.signal(signal.SIGINT, _handle_exit_signal)
    signal.signal(signal.SIGTERM, _handle_exit_signal)

    draw_home(username, cursor)

    while APP_RUNNING:
        btn = first_pressed()
        if not btn:
            time.sleep(0.05)
            continue
        if btn == "KEY3":
            if in_detail:
                in_detail = False
            elif results and cursor == 1:
                # Back to search (home screen) without exiting payload
                results = []
                page = 1
                selected_idx = 0
                cursor = 0
            else:
                break
        # In detail view, ignore UP/DOWN entirely
        if btn == "UP":
            if results and cursor == 1 and not in_detail:
                page_start = (page - 1) * 6
                selected_idx = max(page_start, selected_idx - 1)
            elif not in_detail:
                cursor = (cursor - 1) % 2
        elif btn == "DOWN":
            if results and cursor == 1 and not in_detail:
                page_start = (page - 1) * 6
                page_end = min(len(results), page_start + 6)
                selected_idx = min(page_end - 1, selected_idx + 1)
            elif not in_detail:
                cursor = (cursor + 1) % 2
        elif btn == "LEFT" and results and cursor == 1:
            if in_detail:
                selected_idx = max(0, selected_idx - 1)
            else:
                if page > 1:
                    page -= 1
                    page_start = (page - 1) * 6
                    page_end = min(len(results), page_start + 6)
                    selected_idx = page_end - 1  # wrap to last item of previous page
        elif btn == "RIGHT" and results and cursor == 1:
            if in_detail:
                selected_idx = min(len(results) - 1, selected_idx + 1)
            else:
                total_pages = max(1, (len(results) + 5) // 6)
                if page < total_pages:
                    page += 1
                    selected_idx = (page - 1) * 6  # wrap to first item of next page
        elif btn == "OK" and cursor == 0:
            username = keyboard_input(username)
        elif btn == "KEY1" and username and not in_detail and not results:
            draw_center(["Starting…"], small=True)
            results, run_dir = run_navarro(username.strip())
            page = 1
            if not results:
                draw_center(["No results", "(saved log)", "K3 Back"], small=True)
                wait_release(btn)
            else:
                cursor = 1
                selected_idx = 0
                in_detail = False
        elif btn == "OK" and results and cursor == 1:
            # open detail view for current selected item in current page
            start = (page - 1) * 6
            end = min(len(results), start + 6)
            # ensure selected_idx is within current page bounds
            if selected_idx < start or selected_idx >= end:
                selected_idx = start
            in_detail = True

        wait_release(btn)

        if cursor == 1 and results:
            if in_detail:
                platform, url = results[selected_idx]
                draw_result_detail(username, platform, url, selected_idx, len(results))
            else:
                draw_results(username, results, page, selected_idx)
        else:
            draw_home(username, cursor)

    _safe_shutdown()


# ------------------------- On‑screen keyboard ---------------------
KB_PAGES = [
    ("abc", [
        list("abcdefghi"),
        list("jklmnopqr"),
        list("stuvwxyz_"),
        [" ", "-", ".", "@", "←", "Enter"],
    ]),
    ("ABC", [
        list("ABCDEFGHI"),
        list("JKLMNOPQR"),
        list("STUVWXYZ_"),
        [" ", "-", ".", "@", "←", "Enter"],
    ]),
    ("123", [
        list("123456789"),
        list("0+/#$%&*"),
        ["(", ")", "[", "]", "_", "-", ".", "@", ":"],
        [" ", ",", ";", "'", "\"", "←", "Enter"],
    ]),
]


def keyboard_input(initial: str) -> str:
    buf = initial
    page_idx = 0
    gx = gy = 0
    repeat_btn: str | None = None
    first_press_t = 0.0
    last_rep_t = 0.0
    REPEAT_DELAY = 0.30
    REPEAT_RATE = 0.07
    while APP_RUNNING:
        page_name, grid = KB_PAGES[page_idx]
        draw_keyboard(buf, grid, gx, gy, page_name)
        btn = first_pressed()
        now = time.time()
        if repeat_btn in ("UP", "DOWN", "LEFT", "RIGHT") and GPIO.input(PINS[repeat_btn]) == 0:
            if now - first_press_t >= REPEAT_DELAY and now - last_rep_t >= REPEAT_RATE:
                if repeat_btn == "UP":
                    gy = max(0, gy - 1)
                elif repeat_btn == "DOWN":
                    gy = min(len(grid) - 1, gy + 1)
                elif repeat_btn == "LEFT":
                    gx = max(0, gx - 1)
                elif repeat_btn == "RIGHT":
                    gx = min(len(grid[gy]) - 1, gx + 1)
                last_rep_t = now
                continue
        else:
            repeat_btn = None
        if not btn:
            time.sleep(0.02)
            continue
        if btn == "KEY3":
            wait_release(btn)
            return initial
        if btn == "KEY2":
            page_idx = (page_idx + 1) % len(KB_PAGES)
            wait_release(btn)
            continue
        if btn in ("UP", "DOWN", "LEFT", "RIGHT"):
            if btn == "UP":
                gy = max(0, gy - 1)
            elif btn == "DOWN":
                gy = min(len(grid) - 1, gy + 1)
            elif btn == "LEFT":
                gx = max(0, gx - 1)
            elif btn == "RIGHT":
                gx = min(len(grid[gy]) - 1, gx + 1)
            repeat_btn = btn
            first_press_t = now
            last_rep_t = now
            continue
        elif btn == "KEY1":
            if buf:
                buf = buf[:-1]
            wait_release(btn)
            continue
        elif btn == "OK":
            key = grid[gy][gx]
            if key == "←":
                if buf:
                    buf = buf[:-1]
            elif key == "Enter":
                wait_release(btn)
                return buf
            else:
                buf += key
            wait_release(btn)
            continue
        wait_release(btn)
    return buf


if __name__ == "__main__":
    try:
        main()
    except Exception:
        _safe_shutdown()
        raise
