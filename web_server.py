#!/usr/bin/env python3
"""
RaspyJack WebUI HTTP server
---------------------------
Serves the static WebUI and exposes a small, read-only API to browse loot/.

Routes:
  /                  -> static WebUI (web/)
  /api/loot/list      -> JSON directory listing (read-only)
  /api/loot/download  -> file download (read-only)
  /api/loot/view      -> text preview (read-only)

Environment:
  RJ_WEB_HOST  Host to bind (default: 0.0.0.0)
  RJ_WEB_PORT  Port to bind (default: 8080)
  RJ_WS_TOKEN  Optional shared token for API access (?token=...)
"""

from __future__ import annotations

import json
import mimetypes
import os
import subprocess
import threading
import time
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse, unquote

ROOT_DIR = Path(__file__).resolve().parent
WEB_DIR = ROOT_DIR / "web"
LOOT_DIR = ROOT_DIR / "loot"
PAYLOADS_DIR = ROOT_DIR / "payloads"
PAYLOAD_STATE_PATH = Path("/dev/shm/rj_payload_state.json")

HOST = os.environ.get("RJ_WEB_HOST", "0.0.0.0")
PORT = int(os.environ.get("RJ_WEB_PORT", "8080"))
TOKEN = os.environ.get("RJ_WS_TOKEN")

# WebUI only listens on these interfaces — wlan1+ are for attacks/monitor mode
WEBUI_INTERFACES = ["eth0", "wlan0"]


def _get_interface_ip(interface: str) -> str | None:
    """Get the IPv4 address of a network interface."""
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", interface],
            capture_output=True, text=True, timeout=3,
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if "inet " in line:
                    return line.split("inet ")[1].split("/")[0]
    except Exception:
        pass
    return None


def _get_webui_bind_addrs() -> list[tuple[str, str]]:
    """Return (ip, iface_label) pairs the WebUI should bind to."""
    addrs: list[tuple[str, str]] = []
    for iface in WEBUI_INTERFACES:
        ip = _get_interface_ip(iface)
        if ip:
            addrs.append((ip, iface))
    # Always include localhost for local access
    addrs.append(("127.0.0.1", "lo"))
    return addrs
PREVIEW_MAX_BYTES = int(os.environ.get("RJ_LOOT_PREVIEW_MAX", str(200 * 1024)))
PAYLOAD_MAX_BYTES = int(os.environ.get("RJ_PAYLOAD_MAX", str(512 * 1024)))
TEXT_EXTS = {
    ".txt", ".log", ".md", ".json", ".csv", ".conf", ".ini", ".yaml", ".yml",
    ".pcapng.txt", ".xml", ".sqlite", ".db", ".out", ".py", ".sh"
}


def _auth_ok(query: dict) -> bool:
    if not TOKEN:
        return True
    return query.get("token", [None])[0] == TOKEN


def _safe_loot_path(raw_path: str) -> Path | None:
    raw_path = raw_path.strip().lstrip("/")
    target = (LOOT_DIR / raw_path).resolve()
    try:
        loot_root = LOOT_DIR.resolve()
    except FileNotFoundError:
        loot_root = LOOT_DIR
    if loot_root in target.parents or target == loot_root:
        return target
    return None


def _safe_payload_path(raw_path: str) -> Path | None:
    raw_path = raw_path.strip().lstrip("/")
    target = (PAYLOADS_DIR / raw_path).resolve()
    try:
        payload_root = PAYLOADS_DIR.resolve()
    except FileNotFoundError:
        payload_root = PAYLOADS_DIR
    if payload_root in target.parents or target == payload_root:
        return target
    return None


def _json_response(handler: SimpleHTTPRequestHandler, payload: dict, status: int = 200) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _read_json(handler: SimpleHTTPRequestHandler) -> dict | None:
    try:
        length = int(handler.headers.get("Content-Length", "0") or "0")
    except Exception:
        length = 0
    try:
        raw = handler.rfile.read(length) if length > 0 else b"{}"
        return json.loads(raw.decode("utf-8", "ignore")) if raw else {}
    except Exception:
        return None


def _is_text_file(path: Path) -> bool:
    ctype, _ = mimetypes.guess_type(str(path))
    if ctype and ctype.startswith("text/"):
        return True
    ext = "".join(path.suffixes).lower() or path.suffix.lower()
    if ext in TEXT_EXTS:
        return True
    return False


class RaspyJackHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/ide":
            self.path = "/ide.html" + (f"?{parsed.query}" if parsed.query else "")
            super().do_GET()
            return

        if parsed.path.startswith("/api/loot/") or parsed.path.startswith("/api/payloads/"):
            query = parse_qs(parsed.query or "")
            if not _auth_ok(query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return

            if parsed.path == "/api/payloads/list":
                self._handle_payloads_list()
                return
            if parsed.path == "/api/payloads/status":
                self._handle_payloads_status()
                return
            if parsed.path == "/api/payloads/tree":
                self._handle_payloads_tree()
                return
            if parsed.path == "/api/payloads/file":
                self._handle_payloads_file_get(query)
                return

            if parsed.path == "/api/loot/list":
                self._handle_loot_list(query)
                return
            if parsed.path == "/api/loot/download":
                self._handle_loot_download(query)
                return
            if parsed.path == "/api/loot/view":
                self._handle_loot_view(query)
                return

            _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return

        super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/api/payloads/start", "/api/payloads/run"):
            query = parse_qs(parsed.query or "")
            if not _auth_ok(query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_payloads_start()
            return
        if parsed.path == "/api/payloads/entry":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_payloads_entry_create()
            return
        _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_PUT(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/payloads/file":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_payloads_file_put()
            return
        _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_PATCH(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/payloads/entry":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_payloads_entry_rename()
            return
        _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/payloads/entry":
            query = parse_qs(parsed.query or "")
            if not _auth_ok(query):
                _json_response(self, {"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._handle_payloads_entry_delete(query)
            return
        _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def _handle_loot_list(self, query: dict) -> None:
        raw = unquote(query.get("path", [""])[0])
        target = _safe_loot_path(raw)
        if target is None or not target.exists():
            _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        if not target.is_dir():
            _json_response(self, {"error": "not a directory"}, status=HTTPStatus.BAD_REQUEST)
            return

        items = []
        try:
            for entry in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
                if entry.name.startswith("."):
                    continue
                stat = entry.stat()
                items.append({
                    "name": entry.name,
                    "type": "dir" if entry.is_dir() else "file",
                    "size": stat.st_size,
                    "mtime": int(stat.st_mtime),
                })
        except Exception as exc:
            _json_response(self, {"error": f"read error: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        parent = "" if target == LOOT_DIR else str(target.relative_to(LOOT_DIR).parent)
        current = "" if target == LOOT_DIR else str(target.relative_to(LOOT_DIR))
        _json_response(self, {
            "path": current,
            "parent": "" if parent == "." else parent,
            "items": items,
        })

    def _handle_payloads_list(self) -> None:
        categories: dict[str, list[dict]] = {}
        if not PAYLOADS_DIR.exists():
            _json_response(self, {"categories": []})
            return

        for root, dirs, files in os.walk(PAYLOADS_DIR):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
            rel_dir = os.path.relpath(root, PAYLOADS_DIR)
            category = rel_dir.split(os.sep)[0] if rel_dir != "." else "general"
            for name in files:
                if not name.endswith(".py") or name.startswith("_"):
                    continue
                rel_path = os.path.join(rel_dir, name) if rel_dir != "." else name
                categories.setdefault(category, []).append({
                    "name": os.path.splitext(name)[0],
                    "path": rel_path.replace("\\", "/"),
                })

        order = [
            "reconnaissance",
            "interception",
            "evil_portal",
            "exfiltration",
            "remote_access",
            "general",
            "examples",
            "games",
            "virtual_pager",
            "incident_response",
            "known_unstable",
            "prank",
        ]

        payload_categories = []
        for cat in order:
            items = categories.get(cat, [])
            if not items:
                continue
            payload_categories.append({
                "id": cat,
                "label": cat.replace("_", " ").title(),
                "items": sorted(items, key=lambda x: x["name"].lower()),
            })

        for cat in sorted(categories.keys()):
            if cat in order:
                continue
            payload_categories.append({
                "id": cat,
                "label": cat.replace("_", " ").title(),
                "items": sorted(categories[cat], key=lambda x: x["name"].lower()),
            })

        _json_response(self, {"categories": payload_categories})

    def _handle_payloads_start(self) -> None:
        body = _read_json(self)
        if body is None:
            _json_response(self, {"error": "invalid json"}, status=HTTPStatus.BAD_REQUEST)
            return

        rel_path = str(body.get("path", "")).strip().lstrip("/").replace("\\", "/")
        if not rel_path.endswith(".py"):
            _json_response(self, {"error": "invalid payload path"}, status=HTTPStatus.BAD_REQUEST)
            return

        target = (PAYLOADS_DIR / rel_path).resolve()
        try:
            payloads_root = PAYLOADS_DIR.resolve()
        except FileNotFoundError:
            payloads_root = PAYLOADS_DIR
        if payloads_root not in target.parents or not target.exists():
            _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return

        try:
            request_path = Path("/dev/shm/rj_payload_request.json")
            request_path.write_text(json.dumps({
                "action": "start",
                "path": rel_path,
            }))
        except Exception as exc:
            _json_response(self, {"error": f"request failed: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        _json_response(self, {"ok": True})

    def _handle_payloads_status(self) -> None:
        try:
            if not PAYLOAD_STATE_PATH.exists():
                _json_response(self, {"running": False, "path": None})
                return
            raw = PAYLOAD_STATE_PATH.read_text(encoding="utf-8")
            data = json.loads(raw) if raw else {}
            _json_response(self, {
                "running": bool(data.get("running")),
                "path": data.get("path"),
                "ts": data.get("ts"),
            })
        except Exception:
            _json_response(self, {"running": False, "path": None})

    def _payload_tree_node(self, base: Path, current: Path) -> dict:
        rel = "" if current == base else str(current.relative_to(base)).replace("\\", "/")
        node = {
            "name": current.name if current != base else base.name,
            "path": rel,
            "type": "dir" if current.is_dir() else "file",
        }
        if current.is_dir():
            children = []
            try:
                entries = sorted(current.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
            except Exception:
                entries = []
            for entry in entries:
                if entry.name.startswith(".") or entry.name == "__pycache__":
                    continue
                if entry.is_file() and entry.suffix.lower() in (".pyc",):
                    continue
                children.append(self._payload_tree_node(base, entry))
            node["children"] = children
        return node

    def _handle_payloads_tree(self) -> None:
        if not PAYLOADS_DIR.exists():
            _json_response(self, {"name": "payloads", "path": "", "type": "dir", "children": []})
            return
        try:
            _json_response(self, self._payload_tree_node(PAYLOADS_DIR, PAYLOADS_DIR))
        except Exception as exc:
            _json_response(self, {"error": f"read error: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_payloads_file_get(self, query: dict) -> None:
        raw = unquote(query.get("path", [""])[0])
        target = _safe_payload_path(raw)
        if target is None or not target.exists() or not target.is_file():
            _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        if target.stat().st_size > PAYLOAD_MAX_BYTES:
            _json_response(self, {"error": "file too large"}, status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return
        if not _is_text_file(target):
            _json_response(self, {"error": "not text"}, status=HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
            return
        try:
            content = target.read_text(encoding="utf-8", errors="replace")
            rel = str(target.relative_to(PAYLOADS_DIR)).replace("\\", "/")
            st = target.stat()
            _json_response(self, {
                "path": rel,
                "content": content,
                "size": st.st_size,
                "mtime": int(st.st_mtime),
            })
        except Exception as exc:
            _json_response(self, {"error": f"read error: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_payloads_file_put(self) -> None:
        body = _read_json(self)
        if body is None:
            _json_response(self, {"error": "invalid json"}, status=HTTPStatus.BAD_REQUEST)
            return

        rel_path = str(body.get("path", "")).strip().lstrip("/").replace("\\", "/")
        content = body.get("content", "")
        if not rel_path:
            _json_response(self, {"error": "missing path"}, status=HTTPStatus.BAD_REQUEST)
            return
        if not isinstance(content, str):
            _json_response(self, {"error": "content must be string"}, status=HTTPStatus.BAD_REQUEST)
            return
        if len(content.encode("utf-8", "ignore")) > PAYLOAD_MAX_BYTES:
            _json_response(self, {"error": "content too large"}, status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return

        target = _safe_payload_path(rel_path)
        if target is None:
            _json_response(self, {"error": "invalid path"}, status=HTTPStatus.BAD_REQUEST)
            return
        if target.exists() and not target.is_file():
            _json_response(self, {"error": "not a file"}, status=HTTPStatus.BAD_REQUEST)
            return
        if not target.parent.exists():
            _json_response(self, {"error": "parent folder missing"}, status=HTTPStatus.CONFLICT)
            return
        try:
            target.write_text(content, encoding="utf-8")
            rel = str(target.relative_to(PAYLOADS_DIR)).replace("\\", "/")
            st = target.stat()
            _json_response(self, {"ok": True, "path": rel, "size": st.st_size, "mtime": int(st.st_mtime)})
        except Exception as exc:
            _json_response(self, {"error": f"write error: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_payloads_entry_create(self) -> None:
        body = _read_json(self)
        if body is None:
            _json_response(self, {"error": "invalid json"}, status=HTTPStatus.BAD_REQUEST)
            return

        rel_path = str(body.get("path", "")).strip().lstrip("/").replace("\\", "/")
        entry_type = str(body.get("type", "")).strip().lower()
        content = body.get("content", "")
        if not rel_path or entry_type not in ("file", "dir"):
            _json_response(self, {"error": "invalid request"}, status=HTTPStatus.BAD_REQUEST)
            return

        target = _safe_payload_path(rel_path)
        if target is None:
            _json_response(self, {"error": "invalid path"}, status=HTTPStatus.BAD_REQUEST)
            return
        if target.exists():
            _json_response(self, {"error": "already exists"}, status=HTTPStatus.CONFLICT)
            return

        try:
            if entry_type == "dir":
                target.mkdir(parents=True, exist_ok=False)
                rel = str(target.relative_to(PAYLOADS_DIR)).replace("\\", "/")
                _json_response(self, {"ok": True, "type": "dir", "path": rel})
                return

            if not isinstance(content, str):
                _json_response(self, {"error": "content must be string"}, status=HTTPStatus.BAD_REQUEST)
                return
            if len(content.encode("utf-8", "ignore")) > PAYLOAD_MAX_BYTES:
                _json_response(self, {"error": "content too large"}, status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                return
            if not target.parent.exists():
                _json_response(self, {"error": "parent folder missing"}, status=HTTPStatus.CONFLICT)
                return
            target.write_text(content, encoding="utf-8")
            rel = str(target.relative_to(PAYLOADS_DIR)).replace("\\", "/")
            st = target.stat()
            _json_response(self, {"ok": True, "type": "file", "path": rel, "size": st.st_size, "mtime": int(st.st_mtime)})
        except Exception as exc:
            _json_response(self, {"error": f"create error: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_payloads_entry_rename(self) -> None:
        body = _read_json(self)
        if body is None:
            _json_response(self, {"error": "invalid json"}, status=HTTPStatus.BAD_REQUEST)
            return

        old_rel = str(body.get("old_path", "")).strip().lstrip("/").replace("\\", "/")
        new_rel = str(body.get("new_path", "")).strip().lstrip("/").replace("\\", "/")
        if not old_rel or not new_rel:
            _json_response(self, {"error": "missing path"}, status=HTTPStatus.BAD_REQUEST)
            return

        old_target = _safe_payload_path(old_rel)
        new_target = _safe_payload_path(new_rel)
        if old_target is None or new_target is None:
            _json_response(self, {"error": "invalid path"}, status=HTTPStatus.BAD_REQUEST)
            return
        if not old_target.exists():
            _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        if new_target.exists():
            _json_response(self, {"error": "destination exists"}, status=HTTPStatus.CONFLICT)
            return
        if not new_target.parent.exists():
            _json_response(self, {"error": "parent folder missing"}, status=HTTPStatus.CONFLICT)
            return

        try:
            old_target.rename(new_target)
            _json_response(self, {
                "ok": True,
                "old_path": str(old_target.relative_to(PAYLOADS_DIR)).replace("\\", "/"),
                "new_path": str(new_target.relative_to(PAYLOADS_DIR)).replace("\\", "/"),
            })
        except Exception as exc:
            _json_response(self, {"error": f"rename error: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_payloads_entry_delete(self, query: dict) -> None:
        raw = unquote(query.get("path", [""])[0])
        target = _safe_payload_path(raw)
        if target is None or not target.exists():
            _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return

        try:
            if target.is_dir():
                try:
                    next(target.iterdir())
                    _json_response(self, {"error": "directory not empty"}, status=HTTPStatus.CONFLICT)
                    return
                except StopIteration:
                    pass
                target.rmdir()
                rel = "" if target == PAYLOADS_DIR else str(target.relative_to(PAYLOADS_DIR)).replace("\\", "/")
                _json_response(self, {"ok": True, "type": "dir", "path": rel})
                return

            target.unlink()
            rel = str(target.relative_to(PAYLOADS_DIR)).replace("\\", "/")
            _json_response(self, {"ok": True, "type": "file", "path": rel})
        except Exception as exc:
            _json_response(self, {"error": f"delete error: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_loot_download(self, query: dict) -> None:
        raw = unquote(query.get("path", [""])[0])
        target = _safe_loot_path(raw)
        if target is None or not target.exists() or not target.is_file():
            _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return

        ctype, _ = mimetypes.guess_type(str(target))
        ctype = ctype or "application/octet-stream"
        try:
            size = target.stat().st_size
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(size))
            self.send_header("Content-Disposition", f'attachment; filename="{target.name}"')
            self.end_headers()
            with target.open("rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except Exception:
            _json_response(self, {"error": "read error"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _handle_loot_view(self, query: dict) -> None:
        raw = unquote(query.get("path", [""])[0])
        target = _safe_loot_path(raw)
        if target is None or not target.exists() or not target.is_file():
            _json_response(self, {"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        if not _is_text_file(target):
            _json_response(self, {"error": "not text"}, status=HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
            return

        try:
            size = target.stat().st_size
            read_size = min(size, PREVIEW_MAX_BYTES)
            with target.open("rb") as f:
                raw_data = f.read(read_size)
            text = raw_data.decode("utf-8", errors="replace")
            _json_response(self, {
                "name": target.name,
                "path": raw,
                "content": text,
                "truncated": size > PREVIEW_MAX_BYTES,
                "size": size,
                "mtime": int(target.stat().st_mtime),
            })
        except Exception:
            _json_response(self, {"error": "read error"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)


def main() -> None:
    # If a specific host was set via env var, honour it as-is (single bind)
    if HOST != "0.0.0.0":
        server = ThreadingHTTPServer((HOST, PORT), RaspyJackHandler)
        print(f"[WebUI] Serving on http://{HOST}:{PORT}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return

    # Default: bind only to eth0 + wlan0 (+ localhost).  wlan1+ stay untouched.
    bind_addrs = _get_webui_bind_addrs()
    servers: list[ThreadingHTTPServer] = []

    for addr, iface in bind_addrs:
        try:
            srv = ThreadingHTTPServer((addr, PORT), RaspyJackHandler)
            servers.append(srv)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            print(f"[WebUI] Serving on http://{addr}:{PORT} ({iface})")
        except Exception as exc:
            print(f"[WebUI] Could not bind {addr}:{PORT} ({iface}): {exc}")

    if not servers:
        # Last resort — fall back to all interfaces so the WebUI is not dead
        print("[WebUI] WARNING: No WebUI interfaces available, falling back to 0.0.0.0")
        srv = ThreadingHTTPServer(("0.0.0.0", PORT), RaspyJackHandler)
        print(f"[WebUI] Serving on http://0.0.0.0:{PORT}")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            srv.server_close()
        return

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        for srv in servers:
            srv.server_close()


if __name__ == "__main__":
    main()
