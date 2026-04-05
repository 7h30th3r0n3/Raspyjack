# Native Backend

This folder contains the RaspyJack-specific native Doom backend scaffold.

The backend will be responsible for:

- detecting `ST7735_128` vs `ST7789_240` from `gui_conf.json`
- pushing RGB565 frames to the SPI LCD
- polling RaspyJack GPIO buttons
- mapping buttons to Doom controls
- exposing the timing and exit hooks expected by the selected Doom engine

Current files:

- `doomgeneric_raspyjack.c` wires DoomGeneric to the RaspyJack platform layer.
- `rj_platform.h` defines the platform contract and runtime structures.
- `rj_platform.c` currently handles argument/runtime state, display detection, SPI setup, LCD initialization, RGB565 frame upload, and GPIO button polling.

The backend should compile into `payloads/games/doom/build/doom_raspyjack`.