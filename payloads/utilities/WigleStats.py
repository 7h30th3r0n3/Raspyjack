#!/usr/bin/env python3
"""
RaspyJack Payload -- WiGLE Stats 
================================
Author: h0ss310s

Three-page WiGLE stats payload showing user, group, and upload info.

Controls:
  LEFT/RIGHT  - Switch pages
    UP/DOWN     - Scroll uploads page / detail view
    OK          - Open selected upload details
  KEY1        - Refresh from WiGLE
  KEY3        - Exit
"""

import json
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

ROOT_DIR = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT_DIR))

import requests
import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont

from payloads._input_helper import get_button
from payloads._display_helper import ScaledDraw, scaled_font

API_BASE = "https://api.wigle.net/api/v2"
CREDENTIALS_PATH = ROOT_DIR / ".wigle_credentials.json"
CACHE_PATH = Path("/dev/shm/wigle_stats_cache.json")
REQUEST_TIMEOUT = 12
MAX_UPLOAD_ROWS = 3
DETAIL_VISIBLE_LINES = 7

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

GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height


def _load_font(candidates: List[Tuple[str, int]], fallback: Optional[ImageFont.ImageFont] = None):
    for path, size in candidates:
        try:
            return ImageFont.truetype(path, size)
        except Exception:
            continue
    return fallback or scaled_font()


FONT = scaled_font()
FONT_BIG = _load_font(
    [
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 9),
        ("/usr/share/fonts/truetype/freefont/FreeSansBold.ttf", 9),
    ],
    fallback=FONT,
)
FONT_SMALL = _load_font(
    [
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 7),
        ("/usr/share/fonts/truetype/freefont/FreeSans.ttf", 7),
    ],
    fallback=FONT,
)
FONT_DETAIL = _load_font(
    [
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 8),
        ("/usr/share/fonts/truetype/freefont/FreeSans.ttf", 8),
    ],
    fallback=FONT,
)
FONT_DETAIL_BOLD = _load_font(
    [
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 8),
        ("/usr/share/fonts/truetype/freefont/FreeSansBold.ttf", 8),
    ],
    fallback=FONT_BIG,
)

PAGES = ["Overview", "Group", "Uploads"]

running = True
state_lock = threading.Lock()
state: Dict[str, Any] = {
    "snapshot": None,
    "source": "none",
    "status": "Loading...",
    "error": "",
    "loading": False,
    "last_attempt": 0,
}


class WigleError(Exception):
    def __init__(self, message: str, code: Optional[int] = None, retry_after: Optional[str] = None):
        super().__init__(message)
        self.code = code
        self.retry_after = retry_after


def _text_width(font: ImageFont.ImageFont, text: str) -> int:
    try:
        box = font.getbbox(text)
        return int(box[2] - box[0])
    except Exception:
        try:
            return int(font.getsize(text)[0])
        except Exception:
            return len(text) * 6


def _fit_text(text: Any, max_width: int, font: ImageFont.ImageFont = FONT) -> str:
    text = str(text or "")
    if _text_width(font, text) <= max_width:
        return text
    trimmed = text
    while len(trimmed) > 1 and _text_width(font, trimmed + "...") > max_width:
        trimmed = trimmed[:-1]
    return trimmed + "..."


def _fmt_num(value: Any) -> str:
    try:
        number = int(value or 0)
    except Exception:
        return "--"
    if number >= 1000000:
        return f"{number / 1000000:.1f}M"
    if number >= 1000:
        return f"{number / 1000:.1f}K"
    return str(number)


def _fmt_size(value: Any) -> str:
    try:
        size = float(value or 0)
    except Exception:
        return "--"
    units = ["B", "KB", "MB", "GB"]
    unit_index = 0
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024.0
        unit_index += 1
    if unit_index == 0:
        return f"{int(size)}{units[unit_index]}"
    return f"{size:.1f}{units[unit_index]}"


def _fmt_rank(value: Any) -> str:
    try:
        rank = int(value or 0)
    except Exception:
        return "--"
    return f"#{rank}" if rank > 0 else "--"


def _fmt_group_rank(value: Any) -> str:
    try:
        rank = int(value)
    except Exception:
        return "--"
    return f"#{rank}" if rank >= 0 else "--"


def _fmt_percent(value: Any) -> str:
    try:
        return f"{float(value):.0f}%"
    except Exception:
        return "--"


def _fmt_age(ts: Any) -> str:
    try:
        age = max(0, int(time.time() - float(ts)))
    except Exception:
        return "--"
    if age < 60:
        return f"{age}s"
    if age < 3600:
        return f"{age // 60}m"
    if age < 86400:
        return f"{age // 3600}h"
    return f"{age // 86400}d"


def _fmt_status(value: Any) -> str:
    raw = str(value or "unknown").strip()
    if not raw:
        return "Unknown"
    normalized = raw.lower()
    mapping = {
        "d": "Done",
        "done": "Done",
        "complete": "Done",
        "completed": "Done",
        "q": "Queued",
        "queued": "Queued",
        "p": "Processing",
        "proc": "Processing",
        "processing": "Processing",
        "r": "Running",
        "running": "Running",
        "u": "Uploaded",
        "uploaded": "Uploaded",
        "f": "Failed",
        "fail": "Failed",
        "failed": "Failed",
        "e": "Error",
        "error": "Error",
    }
    return mapping.get(normalized, raw[:1].upper() + raw[1:])


def _fmt_last_update(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "upd --"

    parsed: Optional[datetime] = None
    try:
        parsed = datetime.fromtimestamp(float(raw), tz=timezone.utc)
    except Exception:
        parsed = None

    if parsed is None:
        for candidate in (raw.replace("Z", "+00:00"), raw.split(".")[0], raw):
            try:
                parsed = datetime.fromisoformat(candidate)
                break
            except Exception:
                continue

    if parsed is not None:
        try:
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            delta = max(0, int((datetime.now(timezone.utc) - parsed).total_seconds()))
            return f"upd {_fmt_age(time.time() - delta)}"
        except Exception:
            pass

    compact = raw.replace("T", " ").replace("Z", "")
    return _fit_text(f"upd {compact}", 56, FONT_SMALL)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _split_lines(text: Any, width: int, limit: int) -> List[str]:
    source = str(text or "").strip()
    if not source:
        return [""]

    words = source.split()
    if not words:
        return [_fit_text(source, width)]

    lines: List[str] = []
    current = words[0]
    for word in words[1:]:
        trial = f"{current} {word}"
        if _text_width(FONT, trial) <= width:
            current = trial
            continue
        lines.append(_fit_text(current, width))
        current = word
        if len(lines) == limit - 1:
            break

    if len(lines) < limit:
        lines.append(_fit_text(current if len(lines) < limit - 1 else " ".join([current] + words[len(lines) + 1:]), width))

    return lines[:limit]


def _split_value_for_label(label: str, value: Any, width: int, limit: int = 2) -> List[str]:
    source = str(value or "--").strip() or "--"
    lines: List[str] = []
    current = source
    first_width = max(8, width - _text_width(FONT_DETAIL_BOLD, f"{label} "))

    while current and len(lines) < limit:
        allowed = first_width if not lines else width
        if _text_width(FONT_DETAIL, current) <= allowed:
            lines.append(current)
            current = ""
            break

        cut = len(current)
        while cut > 1 and _text_width(FONT_DETAIL, current[:cut]) > allowed:
            cut -= 1

        split_at = current.rfind(" ", 0, cut)
        if split_at <= 0:
            split_at = cut
        lines.append(current[:split_at].strip())
        current = current[split_at:].strip()

    if current and len(lines) == limit:
        lines[-1] = _fit_text(lines[-1] + " " + current, width, FONT_DETAIL)

    return lines or ["--"]


def _scroll_text(text: Any, max_width: int, slot: int, font: ImageFont.ImageFont = FONT) -> str:
    source = str(text or "")
    if _text_width(font, source) <= max_width:
        return source

    loop = source + "   "
    doubled = loop + loop
    step = int(time.time() * 3 + slot * 7)
    start = step % len(loop)
    window = doubled[start:start + len(loop)]

    visible = ""
    for char in window:
        trial = visible + char
        if _text_width(font, trial) > max_width:
            break
        visible = trial

    return visible.rstrip() or _fit_text(source, max_width, font)


def _sync_upload_window(selected_index: int, upload_offset: int, total_uploads: int) -> Tuple[int, int]:
    if total_uploads <= 0:
        return 0, 0

    selected_index = max(0, min(total_uploads - 1, selected_index))
    max_offset = max(0, total_uploads - MAX_UPLOAD_ROWS)
    upload_offset = max(0, min(upload_offset, max_offset))

    if selected_index < upload_offset:
        upload_offset = selected_index
    elif selected_index >= upload_offset + MAX_UPLOAD_ROWS:
        upload_offset = selected_index - MAX_UPLOAD_ROWS + 1

    upload_offset = min(upload_offset, max_offset)
    return selected_index, upload_offset


def _read_credentials() -> Tuple[str, str]:
    try:
        if not CREDENTIALS_PATH.exists():
            return "", ""
        raw = CREDENTIALS_PATH.read_text(encoding="utf-8")
        data = json.loads(raw) if raw else {}
        if not isinstance(data, dict):
            return "", ""
        return str(data.get("api_name") or "").strip(), str(data.get("api_token") or "").strip()
    except Exception:
        return "", ""


def _load_cache() -> Optional[Dict[str, Any]]:
    try:
        if not CACHE_PATH.exists():
            return None
        raw = CACHE_PATH.read_text(encoding="utf-8")
        data = json.loads(raw) if raw else None
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _save_cache(snapshot: Dict[str, Any]) -> None:
    try:
        CACHE_PATH.write_text(json.dumps(snapshot) + "\n", encoding="utf-8")
    except Exception:
        pass


def _pick_user_name(profile: Dict[str, Any], stats: Dict[str, Any]) -> str:
    candidates = [
        stats.get("user"),
        profile.get("userid"),
        profile.get("userName"),
        profile.get("username"),
    ]
    for candidate in candidates:
        value = str(candidate or "").strip()
        if value:
            return value
    return ""


def _wigle_get(path: str, auth: Tuple[str, str], params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    try:
        response = requests.get(
            f"{API_BASE}{path}",
            params=params,
            auth=auth,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.Timeout as exc:
        raise WigleError("WiGLE timeout") from exc
    except requests.RequestException as exc:
        raise WigleError(f"WiGLE request failed: {exc}") from exc

    if response.status_code == 401:
        raise WigleError("WiGLE auth failed", code=401)
    if response.status_code == 404:
        raise WigleError("WiGLE resource not found", code=404)
    if response.status_code == 429:
        raise WigleError(
            "WiGLE rate limit",
            code=429,
            retry_after=response.headers.get("Retry-After"),
        )
    if response.status_code >= 400:
        raise WigleError(f"WiGLE HTTP {response.status_code}", code=response.status_code)

    try:
        data = response.json()
    except Exception as exc:
        raise WigleError("Bad WiGLE response") from exc
    return data if isinstance(data, dict) else {}


def _derive_group_rank(groups: List[Dict[str, Any]], group_id: str, group_name: str) -> int:
    for index, group in enumerate(groups):
        gid = str(group.get("groupId") or group.get("groupid") or "")
        gname = str(group.get("groupName") or "")
        if (group_id and gid == group_id) or (group_name and gname == group_name):
            return index
    ranked = sorted(groups, key=lambda item: _safe_int(item.get("discovered")), reverse=True)
    for index, group in enumerate(ranked):
        gid = str(group.get("groupId") or group.get("groupid") or "")
        gname = str(group.get("groupName") or "")
        if (group_id and gid == group_id) or (group_name and gname == group_name):
            return index
    return -1


def _derive_user_rank(users: List[Dict[str, Any]], user_name: str) -> int:
    if not users or not user_name:
        return 0
    target = user_name.lower()
    for index, user in enumerate(users, start=1):
        name = str(user.get("username") or user.get("userName") or "").lower()
        if name == target:
            return index
    ranked = sorted(
        users,
        key=lambda item: (_safe_int(item.get("discovered")), _safe_int(item.get("total"))),
        reverse=True,
    )
    for index, user in enumerate(ranked, start=1):
        name = str(user.get("username") or user.get("userName") or "").lower()
        if name == target:
            return index
    return 0


def _normalize_uploads(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    uploads = []
    for item in data.get("results") or []:
        if not isinstance(item, dict):
            continue
        uploads.append(
            {
                "transid": str(item.get("transid") or ""),
                "username": str(item.get("username") or ""),
                "first_time": str(item.get("firstTime") or ""),
                "file_name": str(item.get("fileName") or ""),
                "file_size": _safe_int(item.get("fileSize")),
                "file_lines": _safe_int(item.get("fileLines")),
                "status": str(item.get("status") or item.get("wwwdStatus") or "unknown"),
                "discovered_gps": _safe_int(item.get("discoveredGps")),
                "discovered": _safe_int(item.get("discovered")),
                "total": _safe_int(item.get("total")),
                "total_gps": _safe_int(item.get("totalGps")),
                "total_locations": _safe_int(item.get("totalLocations")),
                "percent_done": float(item.get("percentDone") or 0),
                "time_parsing": _safe_int(item.get("timeParsing")),
                "gen_discovered": _safe_int(item.get("genDiscovered")),
                "gen_discovered_gps": _safe_int(item.get("genDiscoveredGps")),
                "gen_total": _safe_int(item.get("genTotal")),
                "gen_total_gps": _safe_int(item.get("genTotalGps")),
                "gen_total_locations": _safe_int(item.get("genTotalLocations")),
                "bt_discovered": _safe_int(item.get("btDiscovered")),
                "bt_discovered_gps": _safe_int(item.get("btDiscoveredGps")),
                "bt_total": _safe_int(item.get("btTotal")),
                "bt_total_gps": _safe_int(item.get("btTotalGps")),
                "bt_total_locations": _safe_int(item.get("btTotalLocations")),
                "wwwd_status": str(item.get("wwwdStatus") or ""),
                "wait": _safe_int(item.get("wait")),
                "brand": str(item.get("brand") or ""),
                "model": str(item.get("model") or ""),
                "os_release": str(item.get("osRelease") or ""),
                "last_update": str(item.get("lastupdt") or item.get("firstTime") or ""),
            }
        )
    return uploads


def _build_snapshot(auth: Tuple[str, str]) -> Dict[str, Any]:
    errors: List[str] = []

    profile = _wigle_get("/profile/user", auth)
    stats = _wigle_get("/stats/user", auth)
    user_name = _pick_user_name(profile, stats)
    if not user_name:
        raise WigleError("WiGLE user name missing")

    stats_blob = stats.get("statistics") or {}
    if not isinstance(stats_blob, dict):
        stats_blob = {}

    group_info: Dict[str, Any] = {}
    try:
        group_info = _wigle_get(f"/group/groupForUser/{quote(user_name, safe='')}", auth)
    except WigleError as exc:
        if exc.code != 404:
            errors.append(str(exc))

    group_id = str(group_info.get("groupId") or group_info.get("groupid") or "")
    group_name = str(group_info.get("groupName") or "")

    groups_response = {}
    try:
        groups_response = _wigle_get("/stats/group", auth)
    except WigleError as exc:
        errors.append(str(exc))

    groups = groups_response.get("groups") or []
    if not isinstance(groups, list):
        groups = []
    group_rank = _derive_group_rank(groups, group_id, group_name)

    members = []
    user_rank_in_group = 0
    if group_id:
        try:
            members_response = _wigle_get("/group/groupMembers", auth, params={"groupid": group_id})
            members = members_response.get("users") or []
            if not isinstance(members, list):
                members = []
            user_rank_in_group = _derive_user_rank(members, user_name)
        except WigleError as exc:
            errors.append(str(exc))

    uploads = []
    try:
        uploads_response = _wigle_get("/file/transactions", auth, params={"pagestart": 0, "pageend": 15})
        uploads = _normalize_uploads(uploads_response)
    except WigleError as exc:
        errors.append(str(exc))

    return {
        "user": {
            "name": user_name,
            "userid": str(profile.get("userid") or user_name),
            "join_date": str(profile.get("joindate") or ""),
            "last_login": str(profile.get("lastlogin") or ""),
        },
        "user_stats": {
            "global_rank": _safe_int(stats.get("rank") or stats_blob.get("rank")),
            "month_rank": _safe_int(stats.get("monthRank") or stats_blob.get("monthRank")),
            "wifi_discovered": _safe_int(stats_blob.get("discoveredWiFi")),
            "wifi_gps": _safe_int(stats_blob.get("discoveredWiFiGPS")),
            "wifi_gps_percent": float(stats_blob.get("discoveredWiFiGPSPercent") or 0),
            "cell_discovered": _safe_int(stats_blob.get("discoveredCell")),
            "bt_discovered": _safe_int(stats_blob.get("discoveredBt")),
            "total_wifi_locations": _safe_int(stats_blob.get("totalWiFiLocations")),
            "month_count": _safe_int(stats_blob.get("eventMonthCount")),
            "prev_month_count": _safe_int(stats_blob.get("eventPrevMonthCount")),
            "first_seen": str(stats_blob.get("first") or ""),
            "last_seen": str(stats_blob.get("last") or ""),
        },
        "group": {
            "id": group_id,
            "name": group_name,
            "owner": str(group_info.get("owner") or ""),
            "group_rank": group_rank,
            "user_rank_in_group": user_rank_in_group,
            "members_count": len(members),
            "discovered": _safe_int(group_info.get("discovered")),
            "total": _safe_int(group_info.get("total")),
        },
        "uploads": uploads,
        "errors": errors,
        "fetched_at": time.time(),
    }


def _load_initial_state() -> None:
    cached = _load_cache()
    with state_lock:
        if cached:
            state["snapshot"] = cached
            state["source"] = "cache"
            state["status"] = f"Cached {_fmt_age(cached.get('fetched_at'))}"
        else:
            state["status"] = "Press KEY1 refresh"


def _refresh_snapshot() -> None:
    with state_lock:
        if state["loading"]:
            return
        state["loading"] = True
        state["error"] = ""
        state["status"] = "Refreshing..."
        state["last_attempt"] = time.time()

    api_name, api_token = _read_credentials()
    if not api_name or not api_token:
        with state_lock:
            state["loading"] = False
            state["error"] = "missing_credentials"
            state["status"] = "Add WiGLE creds"
        return

    try:
        snapshot = _build_snapshot((api_name, api_token))
        _save_cache(snapshot)
        with state_lock:
            state["snapshot"] = snapshot
            state["source"] = "live"
            state["loading"] = False
            state["status"] = f"Live {_fmt_age(snapshot.get('fetched_at'))}"
            state["error"] = ""
    except WigleError as exc:
        cached = _load_cache()
        with state_lock:
            state["loading"] = False
            state["error"] = str(exc)
            if cached:
                state["snapshot"] = cached
                state["source"] = "cache"
                state["status"] = f"Cached {_fmt_age(cached.get('fetched_at'))}"
            else:
                state["source"] = "none"
                state["status"] = str(exc)


def _start_refresh() -> None:
    thread = threading.Thread(target=_refresh_snapshot, daemon=True)
    thread.start()


def _signal_stop(_signum, _frame):
    global running
    running = False


signal.signal(signal.SIGINT, _signal_stop)
signal.signal(signal.SIGTERM, _signal_stop)


def _draw_header(draw: ImageDraw.ImageDraw, page_index: int) -> None:
    draw.rectangle((0, 0, 127, 11), fill="white")
    draw.text((3, 2), f"WiGLE {PAGES[page_index]}", font=FONT, fill="black")
    draw.text((103, 2), f"{page_index + 1}/3", font=FONT, fill="black")


def _draw_footer(draw: ImageDraw.ImageDraw, status: str, source: str) -> None:
    draw.line((0, 113, 127, 113), fill="white")
    draw.text((2, 116), _fit_text(status, 80), font=FONT, fill="white")
    draw.text((68, 116), "K1=Refresh", font=FONT, fill="white")


def _draw_centered(draw: ImageDraw.ImageDraw, y: int, text: str) -> None:
    width = _text_width(FONT, text)
    draw.text((max(0, (WIDTH - width) // 2), y), text, font=FONT, fill="white")


def _draw_error_state(draw: ImageDraw.ImageDraw, error_code: str) -> None:
    lines = ["WiGLE offline"]
    if error_code == "missing_credentials":
        lines += ["Save creds in", "WebUI Settings", "KEY1 refresh"]
    else:
        lines += [_fit_text(error_code, 118), "KEY1 retry", "KEY3 exit"]
    y = 28
    for line in lines:
        _draw_centered(draw, y, line)
        y += 12


def _draw_overview(draw: ImageDraw.ImageDraw, snapshot: Dict[str, Any]) -> None:
    user = snapshot.get("user") or {}
    stats_blob = snapshot.get("user_stats") or {}
    group = snapshot.get("group") or {}

    lines = [
        _fit_text(user.get("name") or "Unknown", 118),
        f"Month { _fmt_rank(stats_blob.get('month_rank')) }".replace("  ", " "),
        f"Global { _fmt_rank(stats_blob.get('global_rank')) }".replace("  ", " "),
        f"Group  { _fmt_group_rank(group.get('group_rank')) }".replace("  ", " "),
        f"In grp { _fmt_rank(group.get('user_rank_in_group')) }",
        f"WiFi  {_fmt_num(stats_blob.get('wifi_discovered'))}",
        f"Cell  {_fmt_num(stats_blob.get('cell_discovered'))}  BT {_fmt_num(stats_blob.get('bt_discovered'))}",
        f"GPS {_fmt_percent(stats_blob.get('wifi_gps_percent'))}  Loc {_fmt_num(stats_blob.get('total_wifi_locations'))}",
    ]
    y = 16
    for line in lines:
        draw.text((4, y), _fit_text(line, 120), font=FONT, fill="white")
        y += 12


def _draw_group_page(draw: ImageDraw.ImageDraw, snapshot: Dict[str, Any]) -> None:
    group = snapshot.get("group") or {}

    name_lines = _split_lines(group.get("name") or "No group linked", 120, 2)
    owner_lines = _split_lines(f"Owner {group.get('owner') or 'Unknown'}", 120, 2)
    lines = name_lines + [
        f"Members {_fmt_num(group.get('members_count'))}",
        f"Group   {_fmt_group_rank(group.get('group_rank'))}",
    ] + owner_lines + [
        f"Disc {_fmt_num(group.get('discovered'))}",
        f"Total {_fmt_num(group.get('total'))}",
    ]

    y = 16
    for line in lines[:8]:
        draw.text((4, y), _fit_text(line, 120), font=FONT, fill="white")
        y += 12


def _draw_uploads_page(
    draw: ImageDraw.ImageDraw,
    snapshot: Dict[str, Any],
    upload_offset: int,
    selected_upload_index: int,
) -> None:
    uploads = snapshot.get("uploads") or []
    total_uploads = len(uploads)
    if not uploads:
        lines = ["No upload logs", "", "Refresh after", "WiGLE upload"]
        y = 28
        for line in lines:
            _draw_centered(draw, y, line)
            y += 12
        return

    selected_upload_index, upload_offset = _sync_upload_window(selected_upload_index, upload_offset, len(uploads))
    visible = uploads[upload_offset:upload_offset + MAX_UPLOAD_ROWS]
    selected_visible_index = selected_upload_index - upload_offset
    selected_item = visible[selected_visible_index]
    latest_label = selected_item.get("file_name") or selected_item.get("transid") or "upload"
    latest_status = _fmt_status(selected_item.get("status"))
    latest_percent = _fmt_percent(selected_item.get("percent_done"))
    latest_update = _fmt_last_update(selected_item.get("last_update"))
    selected_marker = f"{selected_upload_index + 1}/{total_uploads}"
    marker_x = 121 - _text_width(FONT_SMALL, selected_marker)
    label_width = max(56, marker_x - 10)

    draw.rectangle((3, 15, 124, 49), outline="white")
    draw.text((6, 18), _scroll_text(latest_label, label_width, selected_upload_index, FONT_BIG), font=FONT_BIG, fill="white")
    draw.text((marker_x, 20), selected_marker, font=FONT_SMALL, fill="white")
    draw.text((6, 31), _fit_text(f"{latest_status} {latest_percent}", 114, FONT), font=FONT, fill="white")
    draw.text((6, 41), _fit_text(latest_update, 114, FONT_SMALL), font=FONT_SMALL, fill="white")

    y = 54
    for index, item in enumerate(visible):
        if index == selected_visible_index:
            continue
        row_number = upload_offset + index + 1
        label = item.get("file_name") or item.get("transid") or "upload"
        status_text = _fmt_status(item.get("status"))
        percent_text = _fmt_percent(item.get("percent_done"))
        update_text = _fmt_last_update(item.get("last_update"))

        draw.text((4, y), _fit_text(f"{row_number:02d} {label}", 120, FONT_SMALL), font=FONT_SMALL, fill="white")
        y += 9
        meta = f"{status_text} {percent_text}  {update_text}"
        draw.text((4, y), _fit_text(meta, 120, FONT_SMALL), font=FONT_SMALL, fill="white")
        y += 13

    if len(uploads) > MAX_UPLOAD_ROWS:
        draw.text((4, 102), f"Rows {upload_offset + 1}-{len(uploads)}", font=FONT, fill="white")


def _get_selected_upload(snapshot: Dict[str, Any], selected_upload_index: int) -> Optional[Dict[str, Any]]:
    uploads = snapshot.get("uploads") or []
    if not uploads:
        return None
    selected_upload_index = max(0, min(len(uploads) - 1, selected_upload_index))
    return uploads[selected_upload_index]


def _build_upload_detail_lines(upload: Dict[str, Any]) -> List[Tuple[str, str]]:
    lines: List[Tuple[str, str]] = []

    def add(label: str, value: Any, max_lines: int = 1) -> None:
        value_lines = _split_value_for_label(label, value, 116, max_lines)
        for index, item in enumerate(value_lines):
            lines.append((label if index == 0 else "", item))

    add("File", upload.get("file_name") or "upload", 2)
    add("Txn", upload.get("transid") or "--", 2)
    add("User", upload.get("username") or "--")
    add("Status", f"{_fmt_status(upload.get('status'))} {_fmt_percent(upload.get('percent_done'))}")
    add("Upd", _fmt_last_update(upload.get("last_update")))
    add("First", upload.get("first_time") or "--", 2)
    add("Size", f"{_fmt_size(upload.get('file_size'))}  Lines {_fmt_num(upload.get('file_lines'))}")
    add("Disc", f"{_fmt_num(upload.get('discovered'))}  GPS {_fmt_num(upload.get('discovered_gps'))}")
    add("Total", f"{_fmt_num(upload.get('total'))}  GPS {_fmt_num(upload.get('total_gps'))}")
    add("Loc", f"{_fmt_num(upload.get('total_locations'))}  Parse {_fmt_num(upload.get('time_parsing'))}")
    add("GenD", f"{_fmt_num(upload.get('gen_discovered'))}  GenT {_fmt_num(upload.get('gen_total'))}")
    add("GenG", f"{_fmt_num(upload.get('gen_discovered_gps'))}/{_fmt_num(upload.get('gen_total_gps'))}")
    add("GenL", f"{_fmt_num(upload.get('gen_total_locations'))}  Wait {_fmt_num(upload.get('wait'))}")
    add("BtD", f"{_fmt_num(upload.get('bt_discovered'))}  BtT {_fmt_num(upload.get('bt_total'))}")
    add("BtG", f"{_fmt_num(upload.get('bt_discovered_gps'))}/{_fmt_num(upload.get('bt_total_gps'))}")
    add("BtL", _fmt_num(upload.get("bt_total_locations")))
    if upload.get("wwwd_status"):
        add("WWWD", upload.get("wwwd_status"), 2)
    if upload.get("brand"):
        add("Brand", upload.get("brand"), 2)
    if upload.get("model"):
        add("Model", upload.get("model"), 2)
    if upload.get("os_release"):
        add("OS", upload.get("os_release"), 2)
    return lines


def _draw_upload_detail_page(
    draw: ImageDraw.ImageDraw,
    snapshot: Dict[str, Any],
    selected_upload_index: int,
    detail_scroll: int,
) -> None:
    upload = _get_selected_upload(snapshot, selected_upload_index)
    if not upload:
        _draw_centered(draw, 40, "No upload selected")
        _draw_centered(draw, 52, "LEFT back")
        return

    lines = _build_upload_detail_lines(upload)
    visible_lines = DETAIL_VISIBLE_LINES
    max_scroll = max(0, len(lines) - visible_lines)
    detail_scroll = max(0, min(detail_scroll, max_scroll))

    draw.rectangle((3, 15, 124, 105), outline="white")
    y = 18
    for label, value in lines[detail_scroll:detail_scroll + visible_lines]:
        if label:
            label_text = f"{label}:"
            draw.text((6, y), label_text, font=FONT_DETAIL_BOLD, fill="white")
            value_x = 10 + _text_width(FONT_DETAIL_BOLD, label_text)
        else:
            value_x = 12
        draw.text((value_x, y), _fit_text(value, 122 - value_x, FONT_DETAIL), font=FONT_DETAIL, fill="white")
        y += 11

    draw.line((5, 92, 122, 92), fill="white")
    marker = f"{selected_upload_index + 1}/{len(snapshot.get('uploads') or [])}"
    draw.text((6, 95), _fit_text(marker, 26, FONT_SMALL), font=FONT_SMALL, fill="white")
    draw.text((34, 95), _fit_text(f"Lines {detail_scroll + 1}-{min(len(lines), detail_scroll + visible_lines)}", 86, FONT_SMALL), font=FONT_SMALL, fill="white")


def _render(
    page_index: int,
    upload_offset: int,
    selected_upload_index: int,
    upload_detail_open: bool,
    detail_scroll: int,
) -> None:
    with state_lock:
        snapshot = state.get("snapshot")
        status = str(state.get("status") or "")
        error = str(state.get("error") or "")
        source = str(state.get("source") or "none")
        loading = bool(state.get("loading"))

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    draw = ScaledDraw(img)

    draw.rectangle((0, 0, WIDTH - 1, HEIGHT - 1), outline="white")
    _draw_header(draw, page_index)

    if loading and not snapshot:
        _draw_centered(draw, 40, "Fetching WiGLE")
        _draw_centered(draw, 52, "Please wait")
    elif not snapshot:
        _draw_error_state(draw, error or "No cached data")
    else:
        if page_index == 0:
            _draw_overview(draw, snapshot)
        elif page_index == 1:
            _draw_group_page(draw, snapshot)
        else:
            if upload_detail_open:
                _draw_upload_detail_page(draw, snapshot, selected_upload_index, detail_scroll)
            else:
                _draw_uploads_page(draw, snapshot, upload_offset, selected_upload_index)
        errors = snapshot.get("errors") or []
        if errors:
            draw.text((4, 103), _fit_text(errors[0], 120), font=FONT, fill="white")

    footer_status = status if not loading else "Refreshing..."
    _draw_footer(draw, footer_status, source)
    LCD.LCD_ShowImage(img, 0, 0)


def main() -> None:
    page_index = 0
    upload_offset = 0
    selected_upload_index = 0
    upload_detail_open = False
    detail_scroll = 0
    _load_initial_state()
    if state.get("snapshot") is None:
        _start_refresh()

    try:
        while running:
            with state_lock:
                uploads = (state.get("snapshot") or {}).get("uploads") or []
            selected_upload_index, upload_offset = _sync_upload_window(
                selected_upload_index,
                upload_offset,
                len(uploads),
            )

            selected_upload = uploads[selected_upload_index] if uploads and selected_upload_index < len(uploads) else None
            detail_lines = _build_upload_detail_lines(selected_upload) if selected_upload else []
            max_detail_scroll = max(0, len(detail_lines) - DETAIL_VISIBLE_LINES)
            detail_scroll = max(0, min(detail_scroll, max_detail_scroll))

            _render(page_index, upload_offset, selected_upload_index, upload_detail_open, detail_scroll)
            btn = get_button(PINS, GPIO)
            if btn == "KEY3":
                break
            if page_index == 2 and upload_detail_open and btn == "LEFT":
                upload_detail_open = False
                detail_scroll = 0
            elif btn == "LEFT":
                page_index = (page_index - 1) % len(PAGES)
                upload_offset = 0
                selected_upload_index = 0
                upload_detail_open = False
                detail_scroll = 0
            elif btn == "RIGHT":
                if not (page_index == 2 and upload_detail_open):
                    page_index = (page_index + 1) % len(PAGES)
                    upload_offset = 0
                    selected_upload_index = 0
                    upload_detail_open = False
                    detail_scroll = 0
            elif btn == "KEY1":
                _start_refresh()
            elif page_index == 2 and not upload_detail_open and btn == "OK":
                if uploads:
                    upload_detail_open = True
                    detail_scroll = 0
            elif page_index == 2 and upload_detail_open and btn == "DOWN":
                detail_scroll = min(max_detail_scroll, detail_scroll + 1)
            elif page_index == 2 and upload_detail_open and btn == "UP":
                detail_scroll = max(0, detail_scroll - 1)
            elif page_index == 2 and btn == "DOWN":
                selected_upload_index += 1
                selected_upload_index, upload_offset = _sync_upload_window(
                    selected_upload_index,
                    upload_offset,
                    len(uploads),
                )
            elif page_index == 2 and btn == "UP":
                selected_upload_index -= 1
                selected_upload_index, upload_offset = _sync_upload_window(
                    selected_upload_index,
                    upload_offset,
                    len(uploads),
                )
            time.sleep(0.05)
    finally:
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()


if __name__ == "__main__":
    main()
