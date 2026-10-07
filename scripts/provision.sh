#!/usr/bin/env bash
#
# RaspyJack first-boot provisioning for the CardputerZero store package.
#
# Installs the "heavy" payload tools that can't be plain apt Depends (own repos
# or source builds): kismet, dump1090, PyBoy, Ragnar, Proxmark3. Runs as a
# systemd oneshot created/enabled by the package postinst, AFTER the network is
# up. Idempotent: each tool is skipped once present, failures are retried on the
# next boot, and the service self-disables only when everything is done.
#
# Progress is written to a JSON status file + a log so RaspyJack (and the user)
# can see advancement.
set -u

APP_DIR="/usr/share/APPLaunch/apps/raspyjack"
LEGACY_DIR="/root/Raspyjack"
STATUS_DIR="$LEGACY_DIR/loot/provision"
STATUS="$STATUS_DIR/status.json"
LOG="$STATUS_DIR/provision.log"
DONE_MARKER="/var/lib/raspyjack/provision.done"

mkdir -p "$STATUS_DIR" /var/lib/raspyjack 2>/dev/null || true
exec >>"$LOG" 2>&1
echo "==== provision run $(date -Is) ===="

# Ordered list: name|label (fast tools first, proxmark3 last ~15 min)
# proxmark3 is NOT auto-provisioned: its ~30-60 min single-thread source build
# saturates this small device. Install it on demand instead with
# scripts/install_proxmark3.sh (the pm3_* payloads use /opt/proxmark3).
TOOLS=(
  "kismet|Kismet (WiFi)"
  "pyboy|PyBoy (Game Boy)"
  "ragnar|Ragnar"
  "dump1090|dump1090 (ADS-B)"
)

# Keep the device usable during source builds: low CPU/IO priority and pin to
# 2 cores (taskset also caps nproc, so `make -j$(nproc)` builds stay at 2 jobs).
LOWPRIO=""
command -v nice    >/dev/null 2>&1 && LOWPRIO="nice -n 19"
command -v ionice  >/dev/null 2>&1 && LOWPRIO="$LOWPRIO ionice -c3"
command -v taskset >/dev/null 2>&1 && [ "$(nproc 2>/dev/null || echo 1)" -gt 2 ] && LOWPRIO="$LOWPRIO taskset -c 0,1"

py() { python3 - "$@"; }

status_init() {
  py "$STATUS" "${TOOLS[@]}" <<'PY'
import json,sys,time
path=sys.argv[1]; tools=sys.argv[2:]
try: d=json.load(open(path))
except Exception: d={}
steps={s["name"]:s for s in d.get("steps",[])}
out=[]
for t in tools:
    name,label=t.split("|",1)
    prev=steps.get(name,{})
    out.append({"name":name,"label":label,
                "state":prev.get("state","pending"),
                "detail":prev.get("detail","")})
d={"overall":"running","started":d.get("started") or time.strftime("%Y-%m-%dT%H:%M:%S"),
   "updated":time.strftime("%Y-%m-%dT%H:%M:%S"),"steps":out}
json.dump(d,open(path,"w"),indent=2)
PY
}

set_step() { # name state detail
  py "$STATUS" "$1" "$2" "${3:-}" <<'PY'
import json,sys,time
path,name,state=sys.argv[1:4]
detail=sys.argv[4] if len(sys.argv)>4 else ""
try: d=json.load(open(path))
except Exception: d={"steps":[]}
for s in d.setdefault("steps",[]):
    if s["name"]==name: s["state"]=state; s["detail"]=detail; break
else:
    d["steps"].append({"name":name,"label":name,"state":state,"detail":detail})
d["updated"]=time.strftime("%Y-%m-%dT%H:%M:%S")
json.dump(d,open(path,"w"),indent=2)
PY
  echo "[$(date +%H:%M:%S)] $1 -> $2 ${3:-}"
}

finalize() { # done | partial
  py "$STATUS" "$1" <<'PY'
import json,sys,time
path,overall=sys.argv[1:3]
try: d=json.load(open(path))
except Exception: d={}
d["overall"]=overall; d["updated"]=time.strftime("%Y-%m-%dT%H:%M:%S")
json.dump(d,open(path,"w"),indent=2)
PY
}

# ---------------------------------------------------------------- tools

do_kismet() {
  command -v kismet >/dev/null 2>&1 && { set_step kismet done "already installed"; return 0; }
  set_step kismet installing "adding repo"
  local cn
  cn=$(. /etc/os-release 2>/dev/null; echo "${VERSION_CODENAME:-trixie}")
  case "$cn" in bookworm|trixie) ;; *) cn=trixie ;; esac
  wget -qO - https://www.kismetwireless.net/repos/kismet-release.gpg.key 2>/dev/null \
    | gpg --dearmor > /usr/share/keyrings/kismet-archive-keyring.gpg 2>/dev/null
  echo "deb [signed-by=/usr/share/keyrings/kismet-archive-keyring.gpg] https://www.kismetwireless.net/repos/apt/release/$cn $cn main" \
    > /etc/apt/sources.list.d/kismet.list
  apt-get update -qq 2>/dev/null
  set_step kismet installing "apt install"
  if apt-get install -y --no-install-recommends kismet 2>/dev/null; then
    systemctl disable kismet 2>/dev/null; systemctl stop kismet 2>/dev/null
    if [ ! -f /etc/kismet/kismet_raspyjack.conf ]; then
      mkdir -p /etc/kismet
      printf 'httpd_bind_address=127.0.0.1\nhttpd_port=2501\nlog_prefix=%s/loot/kismet/logs\n' "$LEGACY_DIR" \
        > /etc/kismet/kismet_raspyjack.conf
    fi
    command -v kismet >/dev/null 2>&1 && { set_step kismet done ""; return 0; }
  fi
  set_step kismet failed "apt install failed (will retry)"; return 1
}

do_dump1090() {
  command -v dump1090 >/dev/null 2>&1 && { set_step dump1090 done "already installed"; return 0; }
  set_step dump1090 installing "build deps"
  apt-get install -y --no-install-recommends librtlsdr-dev libncurses-dev pkg-config build-essential 2>/dev/null
  set_step dump1090 installing "compiling"
  local b=/tmp/dump1090-build
  rm -rf "$b"; git clone --depth 1 https://github.com/flightaware/dump1090 "$b" 2>/dev/null
  if ( cd "$b" && $LOWPRIO make BLADERF=no HACKRF=no LIMESDR=no -j"$(nproc)" 2>/dev/null && cp dump1090 /usr/local/bin/ ); then
    rm -rf "$b"; set_step dump1090 done ""; return 0
  fi
  rm -rf "$b"; set_step dump1090 failed "build failed (will retry)"; return 1
}

do_pyboy() {
  python3 -c 'import pyboy' >/dev/null 2>&1 && { set_step pyboy done "already installed"; return 0; }
  set_step pyboy installing "sdl2 + pip"
  if $LOWPRIO bash "$APP_DIR/scripts/install_pyboy.sh" 2>/dev/null && python3 -c 'import pyboy' >/dev/null 2>&1; then
    set_step pyboy done ""; return 0
  fi
  set_step pyboy failed "install failed (will retry)"; return 1
}

do_ragnar() {
  if PYTHONPATH="$APP_DIR/vendor/ragnar" python3 -c 'import headlessRagnar' >/dev/null 2>&1; then
    set_step ragnar done "already installed"; return 0
  fi
  set_step ragnar installing "apt + pip deps"
  if $LOWPRIO bash "$APP_DIR/scripts/install_ragnar_port.sh" 2>/dev/null \
     && PYTHONPATH="$APP_DIR/vendor/ragnar" python3 -c 'import headlessRagnar' >/dev/null 2>&1; then
    set_step ragnar done ""; return 0
  fi
  set_step ragnar failed "deps failed (will retry)"; return 1
}

do_proxmark3() {
  command -v pm3 >/dev/null 2>&1 && { set_step proxmark3 done "already installed"; return 0; }
  # This device has very little RAM (~352 MB); a parallel proxmark3 build OOMs
  # and crashes it. Build SINGLE-THREADED (taskset -c 0 => nproc=1 => make -j1)
  # with a temporary 2 GB swapfile, low priority. Slow but does not crash.
  set_step proxmark3 installing "compiling single-thread (long, ~30-60 min)"
  local SW=/var/swap.rjprov rc=1
  if [ ! -f "$SW" ]; then
    ( fallocate -l 2G "$SW" 2>/dev/null || dd if=/dev/zero of="$SW" bs=1M count=2048 2>/dev/null ) \
      && chmod 600 "$SW" && mkswap "$SW" >/dev/null 2>&1 && swapon "$SW" 2>/dev/null
  fi
  nice -n 19 ionice -c3 taskset -c 0 bash "$APP_DIR/scripts/install_proxmark3.sh" 2>/dev/null
  command -v pm3 >/dev/null 2>&1 && rc=0
  swapoff "$SW" 2>/dev/null || true; rm -f "$SW" 2>/dev/null || true
  if [ "$rc" -eq 0 ]; then set_step proxmark3 done ""; return 0; fi
  set_step proxmark3 failed "build failed (will retry)"; return 1
}

# ---------------------------------------------------------------- run

status_init
apt-get update -qq 2>/dev/null || true

all_ok=1
for entry in "${TOOLS[@]}"; do
  name="${entry%%|*}"
  "do_${name}" || all_ok=0
done

if [ "$all_ok" -eq 1 ]; then
  finalize done
  touch "$DONE_MARKER"
  systemctl disable raspyjack-provision.service 2>/dev/null || true
  echo "==== provisioning complete ===="
else
  finalize partial
  echo "==== provisioning partial — will retry on next boot ===="
fi
exit 0
