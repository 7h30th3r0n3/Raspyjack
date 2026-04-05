#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd -- "$SCRIPT_DIR/../../.." && pwd)
VENDOR_DIR="$SCRIPT_DIR/vendor/doomgeneric"
BUILD_DIR="$SCRIPT_DIR/build"
SRC_DIR="$SCRIPT_DIR/src"
OUTPUT="$BUILD_DIR/doom_raspyjack"
DG_DIR="$VENDOR_DIR/doomgeneric"
DG_HEADER="$DG_DIR/doomgeneric.h"
DG_SOURCE="$DG_DIR/doomgeneric.c"

CFLAGS=(
  -std=c11
  -O2
  -Wall
  -Wextra
  -pedantic
  -DNORMALUNIX
  -DLINUX
  -DSNDSERV
  -D_DEFAULT_SOURCE
  -DDOOMGENERIC_RESX=320
  -DDOOMGENERIC_RESY=200
)

LDFLAGS=(
  -lm
  -lc
)

DOOM_SOURCES=(
  dummy.c am_map.c doomdef.c doomstat.c dstrings.c d_event.c d_items.c d_iwad.c d_loop.c
  d_main.c d_mode.c d_net.c f_finale.c f_wipe.c g_game.c hu_lib.c hu_stuff.c info.c
  i_cdmus.c i_endoom.c i_joystick.c i_scale.c i_sound.c i_system.c i_timer.c memio.c
  m_argv.c m_bbox.c m_cheat.c m_config.c m_controls.c m_fixed.c m_menu.c m_misc.c
  m_random.c p_ceilng.c p_doors.c p_enemy.c p_floor.c p_inter.c p_lights.c p_map.c
  p_maputl.c p_mobj.c p_plats.c p_pspr.c p_saveg.c p_setup.c p_sight.c p_spec.c
  p_switch.c p_telept.c p_tick.c p_user.c r_bsp.c r_data.c r_draw.c r_main.c r_plane.c
  r_segs.c r_sky.c r_things.c sha1.c sounds.c statdump.c st_lib.c st_stuff.c s_sound.c
  tables.c v_video.c wi_stuff.c w_checksum.c w_file.c w_main.c w_wad.c z_zone.c
  w_file_stdc.c i_input.c i_video.c doomgeneric.c mus2mid.c
)

if [[ ! -d "$VENDOR_DIR" ]]; then
  echo "Missing upstream source: $VENDOR_DIR"
  echo "Vendor the selected Doom engine before building."
  exit 1
fi

if [[ ! -f "$DG_HEADER" || ! -f "$DG_SOURCE" ]]; then
  echo "Missing DoomGeneric sources under: $DG_DIR"
  echo "Expected files: doomgeneric.h and doomgeneric.c"
  exit 1
fi

mkdir -p "$BUILD_DIR"

echo "Doom source detected at: $VENDOR_DIR"
echo "RaspyJack root: $ROOT_DIR"
echo "Build output: $OUTPUT"

pushd "$DG_DIR" >/dev/null

cc "${CFLAGS[@]}" \
  -I"$SRC_DIR" \
  -I"$DG_DIR" \
  "$SRC_DIR/doomgeneric_raspyjack.c" \
  "$SRC_DIR/rj_platform.c" \
  "${DOOM_SOURCES[@]}" \
  -o "$OUTPUT" \
  "${LDFLAGS[@]}"

popd >/dev/null

chmod +x "$OUTPUT"
echo "Built: $OUTPUT"
echo "Note: this first build uses a fixed DoomGeneric render size of 320x200"