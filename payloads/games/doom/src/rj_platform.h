#ifndef RJ_PLATFORM_H
#define RJ_PLATFORM_H

#include <stdint.h>

typedef struct rj_options {
    const char *wad_path;
    const char *display_name;
    const char *root_dir;
    int scale;
} rj_options_t;

typedef enum rj_display_type {
    RJ_DISPLAY_ST7735_128 = 0,
    RJ_DISPLAY_ST7789_240 = 1,
} rj_display_type_t;

typedef struct rj_platform {
    rj_display_type_t display_type;
    int display_width;
    int display_height;
    int internal_width;
    int internal_height;
    int viewport_x;
    int viewport_y;
    int viewport_width;
    int viewport_height;
    int scale;
    int spi_fd;
    int gpio_ready;
    int exit_requested;
    int tx_buffer_size;
    unsigned int last_event_ms;
    char root_dir[512];
    char wad_path[512];
    char display_name[32];
    int output_pins[4];
    int output_fds[4];
    int button_pins[8];
    int button_fds[8];
    int button_levels[8];
    int button_count;
    unsigned char *tx_buffer;
} rj_platform_t;

enum {
    RJ_BTN_NONE = 0,
    RJ_BTN_UP,
    RJ_BTN_DOWN,
    RJ_BTN_LEFT,
    RJ_BTN_RIGHT,
    RJ_BTN_OK,
    RJ_BTN_KEY1,
    RJ_BTN_KEY2,
    RJ_BTN_KEY3,
};

int rj_platform_init(rj_platform_t *platform, const rj_options_t *options);
void rj_platform_shutdown(rj_platform_t *platform);
int rj_platform_present(rj_platform_t *platform, const uint32_t *argb_frame);
int rj_platform_poll_button(rj_platform_t *platform);
uint32_t rj_platform_ticks_ms(void);
void rj_platform_sleep_ms(uint32_t ms);
const char *rj_platform_display_name(const rj_platform_t *platform);

#endif