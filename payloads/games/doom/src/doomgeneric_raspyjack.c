#include "rj_platform.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "doomgeneric.h"

static rj_platform_t g_platform;
static rj_options_t g_options;

static int parse_args(int argc, char **argv, rj_options_t *options) {
    int i;

    memset(options, 0, sizeof(*options));
    options->scale = 1;

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--wad") == 0 && i + 1 < argc) {
            options->wad_path = argv[++i];
        } else if (strcmp(argv[i], "--display") == 0 && i + 1 < argc) {
            options->display_name = argv[++i];
        } else if (strcmp(argv[i], "--scale") == 0 && i + 1 < argc) {
            options->scale = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--root") == 0 && i + 1 < argc) {
            options->root_dir = argv[++i];
        } else {
            fprintf(stderr, "[doom] ignoring unknown arg: %s\n", argv[i]);
        }
    }

    if (!options->root_dir || !options->root_dir[0]) {
        options->root_dir = getenv("RJ_DOOM_ROOT");
    }
    if ((!options->wad_path || !options->wad_path[0]) && getenv("RJ_DOOM_WAD")) {
        options->wad_path = getenv("RJ_DOOM_WAD");
    }

    return 0;
}

static int map_button_to_doom_key(int button) {
    switch (button) {
        case RJ_BTN_UP:
            return KEY_UPARROW;
        case RJ_BTN_DOWN:
            return KEY_DOWNARROW;
        case RJ_BTN_LEFT:
            return KEY_LEFTARROW;
        case RJ_BTN_RIGHT:
            return KEY_RIGHTARROW;
        case RJ_BTN_OK:
            return KEY_FIRE;
        case RJ_BTN_KEY1:
            return KEY_USE;
        case RJ_BTN_KEY2:
            return ' ';
        case RJ_BTN_KEY3:
            g_platform.exit_requested = 1;
            return KEY_ESCAPE;
        default:
            return 0;
    }
}

void DG_Init(void) {
    if (rj_platform_init(&g_platform, &g_options) != 0) {
        fprintf(stderr, "[doom] failed to initialize RaspyJack platform\n");
    }
    fprintf(stderr, "[doom] platform initialized for %s, internal %dx%d, scale %d\n",
            rj_platform_display_name(&g_platform),
            g_platform.internal_width,
            g_platform.internal_height,
            g_platform.scale);
}

void DG_DrawFrame(void) {
    rj_platform_present(&g_platform, DG_ScreenBuffer);
}

void DG_SleepMs(uint32_t ms) {
    rj_platform_sleep_ms(ms);
}

uint32_t DG_GetTicksMs(void) {
    return rj_platform_ticks_ms();
}

int DG_GetKey(int *pressed, unsigned char *doom_key) {
    int button = rj_platform_poll_button(&g_platform);
    int mapped = map_button_to_doom_key(button);

    if (mapped == 0) {
        return 0;
    }

    *pressed = 1;
    *doom_key = (unsigned char)mapped;
    return 1;
}

void DG_SetWindowTitle(const char *title) {
    fprintf(stderr, "[doom] title: %s\n", title ? title : "Doom");
}

int main(int argc, char **argv) {
    char *doom_argv[8];
    int doom_argc = 0;

    parse_args(argc, argv, &g_options);

    doom_argv[doom_argc++] = argv[0];
    if (g_options.wad_path && g_options.wad_path[0]) {
        doom_argv[doom_argc++] = (char *)"-iwad";
        doom_argv[doom_argc++] = (char *)g_options.wad_path;
    }
    doom_argv[doom_argc++] = (char *)"-nosound";
    doom_argv[doom_argc] = NULL;

    doomgeneric_Create(doom_argc, doom_argv);
    while (!g_platform.exit_requested) {
        doomgeneric_Tick();
    }

    rj_platform_shutdown(&g_platform);
    return 0;
}