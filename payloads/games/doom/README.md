# Doom Integration Scaffold

This directory contains the RaspyJack-specific integration scaffold for running real Doom as a native payload.

## Layout

- `build.sh` builds the native Doom binary when DoomGeneric is present.
- `src/` contains the RaspyJack-specific native backend scaffold.
- `vendor/doomgeneric/` is the expected location for the upstream engine source.
- `wads/` is the default search location for `doom1.wad` or Freedoom assets.

## Current Status

The Python launcher is wired into RaspyJack and will appear under Games as `game_doom`.
The native build now expects a vendored DoomGeneric tree and will output `build/doom_raspyjack`.
The platform layer is only partially implemented at this stage:

- argument parsing and DoomGeneric hook wiring are present
- display detection from `gui_conf.json` is present
- SPI device setup is present
- LCD init and RGB565 frame upload are present
- GPIO button polling is present
- aspect-fit scaling from DoomGeneric's frame buffer to the LCD is present
- the build now targets the real DoomGeneric source tree
- input mapping and performance tuning still need refinement

## WAD Search Order

1. `RJ_DOOM_WAD` environment variable
2. `payloads/games/doom/wads/doom1.wad`
3. `payloads/games/doom/wads/doom.wad`
4. `payloads/games/doom/wads/freedoom1.wad`
5. `payloads/games/doom/wads/freedoom2.wad`
6. System Doom/Freedoom install paths under `/usr/share/games/`

## Expected Binary

The launcher looks for one of these files:

- `payloads/games/doom/build/doom_raspyjack`
- `payloads/games/doom/doom_raspyjack`

## Build Notes

- `build.sh` now compiles the vendored DoomGeneric source tree plus the RaspyJack backend.
- The current build pins DoomGeneric to `320x200` using compiler defines.
- The next likely work after first hardware test is tuning input behavior and render resolution.

## Next Implementation Work

1. Vendor the chosen upstream Doom engine into `vendor/doomgeneric/doomgeneric/`.
2. Test the native backend against a real vendored DoomGeneric tree.
3. Tune Doom key mapping and button press/release behavior.
4. Verify ST7735 and ST7789 initialization on hardware and adjust timings if needed.
5. Improve rendering quality or performance if the Pi Zero 2 W needs a lower internal render target.