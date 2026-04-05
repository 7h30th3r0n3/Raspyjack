#include "rj_platform.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/spi/spidev.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define RJ_SPI_DEVICE "/dev/spidev0.0"
#define RJ_GUI_CONF_RELATIVE "gui_conf.json"
#define RJ_GPIO_ROOT "/sys/class/gpio"
#define RJ_LCD_RST_PIN 27
#define RJ_LCD_DC_PIN 25
#define RJ_LCD_CS_PIN 8
#define RJ_LCD_BL_PIN 24
#define RJ_BUTTON_COUNT 8
#define RJ_OUTPUT_COUNT 4
#define RJ_DEBOUNCE_MS 40u

enum {
    RJ_OUT_RST = 0,
    RJ_OUT_DC,
    RJ_OUT_CS,
    RJ_OUT_BL,
};

static const int RJ_DEFAULT_BUTTON_PINS[RJ_BUTTON_COUNT] = {6, 19, 5, 26, 13, 21, 20, 16};
static const int RJ_DEFAULT_OUTPUT_PINS[RJ_OUTPUT_COUNT] = {RJ_LCD_RST_PIN, RJ_LCD_DC_PIN, RJ_LCD_CS_PIN, RJ_LCD_BL_PIN};

static uint32_t monotonic_ms(void) {
    struct timespec spec;
    if (clock_gettime(CLOCK_MONOTONIC, &spec) != 0) {
        return 0;
    }
    return (uint32_t)((spec.tv_sec * 1000u) + (spec.tv_nsec / 1000000u));
}

static int sleep_ms(unsigned int ms) {
    struct timespec req;
    req.tv_sec = (time_t)(ms / 1000u);
    req.tv_nsec = (long)((ms % 1000u) * 1000000u);
    return nanosleep(&req, NULL);
}

static void copy_string(char *dst, size_t dst_size, const char *src, const char *fallback) {
    const char *value = src && src[0] ? src : fallback;
    if (!value) {
        value = "";
    }
    snprintf(dst, dst_size, "%s", value);
}

static int read_text_file(const char *path, char *buffer, size_t buffer_size) {
    FILE *handle = fopen(path, "rb");
    size_t bytes_read;

    if (!handle) {
        return -1;
    }

    bytes_read = fread(buffer, 1, buffer_size - 1, handle);
    fclose(handle);
    buffer[bytes_read] = '\0';
    return 0;
}

static int write_text_file(const char *path, const char *value) {
    int fd = open(path, O_WRONLY);
    ssize_t written;
    if (fd < 0) {
        return -1;
    }
    written = write(fd, value, strlen(value));
    close(fd);
    return (written >= 0) ? 0 : -1;
}

static int gpio_path(char *buffer, size_t size, int pin, const char *suffix) {
    return snprintf(buffer, size, "%s/gpio%d/%s", RJ_GPIO_ROOT, pin, suffix);
}

static int gpio_export(int pin) {
    char path[PATH_MAX];
    struct stat st;
    snprintf(path, sizeof(path), "%s/gpio%d", RJ_GPIO_ROOT, pin);
    if (stat(path, &st) == 0) {
        return 0;
    }
    snprintf(path, sizeof(path), "%s/export", RJ_GPIO_ROOT);
    {
        int fd = open(path, O_WRONLY);
        char value[16];
        ssize_t written;
        if (fd < 0) {
            return -1;
        }
        snprintf(value, sizeof(value), "%d", pin);
        written = write(fd, value, strlen(value));
        close(fd);
        if (written < 0 && errno != EBUSY) {
            return -1;
        }
    }
    return 0;
}

static int gpio_unexport(int pin) {
    char path[PATH_MAX];
    int fd;
    char value[16];
    ssize_t written;

    snprintf(path, sizeof(path), "%s/unexport", RJ_GPIO_ROOT);
    fd = open(path, O_WRONLY);
    if (fd < 0) {
        return -1;
    }
    snprintf(value, sizeof(value), "%d", pin);
    written = write(fd, value, strlen(value));
    close(fd);
    return (written >= 0) ? 0 : -1;
}

static int gpio_set_direction(int pin, const char *direction) {
    char path[PATH_MAX];
    gpio_path(path, sizeof(path), pin, "direction");
    return write_text_file(path, direction);
}

static int gpio_open_value_fd(int pin, int flags) {
    char path[PATH_MAX];
    gpio_path(path, sizeof(path), pin, "value");
    return open(path, flags);
}

static int gpio_write_fd(int fd, int value) {
    const char out = value ? '1' : '0';
    if (fd < 0) {
        return -1;
    }
    if (lseek(fd, 0, SEEK_SET) < 0) {
        return -1;
    }
    return (write(fd, &out, 1) == 1) ? 0 : -1;
}

static int gpio_read_fd(int fd) {
    char in = '1';
    if (fd < 0) {
        return 1;
    }
    if (lseek(fd, 0, SEEK_SET) < 0) {
        return 1;
    }
    if (read(fd, &in, 1) != 1) {
        return 1;
    }
    return (in == '0') ? 0 : 1;
}

static void spi_write_bytes(rj_platform_t *platform, const unsigned char *data, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = size - offset;
        if (chunk > 4096u) {
            chunk = 4096u;
        }
        if (write(platform->spi_fd, data + offset, chunk) < 0) {
            return;
        }
        offset += chunk;
    }
}

static void lcd_write_command(rj_platform_t *platform, uint8_t value) {
    gpio_write_fd(platform->output_fds[RJ_OUT_DC], 0);
    spi_write_bytes(platform, &value, 1u);
}

static void lcd_write_data8(rj_platform_t *platform, uint8_t value) {
    gpio_write_fd(platform->output_fds[RJ_OUT_DC], 1);
    spi_write_bytes(platform, &value, 1u);
}

static void lcd_write_data16(rj_platform_t *platform, uint16_t value) {
    uint8_t bytes[2];
    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)(value & 0xffu);
    gpio_write_fd(platform->output_fds[RJ_OUT_DC], 1);
    spi_write_bytes(platform, bytes, 2u);
}

static void lcd_reset(rj_platform_t *platform) {
    gpio_write_fd(platform->output_fds[RJ_OUT_RST], 1);
    sleep_ms(100u);
    gpio_write_fd(platform->output_fds[RJ_OUT_RST], 0);
    sleep_ms(100u);
    gpio_write_fd(platform->output_fds[RJ_OUT_RST], 1);
    sleep_ms(100u);
}

static void lcd_init_regs_st7735(rj_platform_t *platform) {
    static const uint8_t gamma_pos[] = {0x0f,0x1a,0x0f,0x18,0x2f,0x28,0x20,0x22,0x1f,0x1b,0x23,0x37,0x00,0x07,0x02,0x10};
    static const uint8_t gamma_neg[] = {0x0f,0x1b,0x0f,0x17,0x33,0x2c,0x29,0x2e,0x30,0x30,0x39,0x3f,0x00,0x07,0x03,0x10};
    int i;

    lcd_write_command(platform, 0xB1); lcd_write_data8(platform, 0x01); lcd_write_data8(platform, 0x2C); lcd_write_data8(platform, 0x2D);
    lcd_write_command(platform, 0xB2); lcd_write_data8(platform, 0x01); lcd_write_data8(platform, 0x2C); lcd_write_data8(platform, 0x2D);
    lcd_write_command(platform, 0xB3); lcd_write_data8(platform, 0x01); lcd_write_data8(platform, 0x2C); lcd_write_data8(platform, 0x2D); lcd_write_data8(platform, 0x01); lcd_write_data8(platform, 0x2C); lcd_write_data8(platform, 0x2D);
    lcd_write_command(platform, 0xB4); lcd_write_data8(platform, 0x07);
    lcd_write_command(platform, 0xC0); lcd_write_data8(platform, 0xA2); lcd_write_data8(platform, 0x02); lcd_write_data8(platform, 0x84);
    lcd_write_command(platform, 0xC1); lcd_write_data8(platform, 0xC5);
    lcd_write_command(platform, 0xC2); lcd_write_data8(platform, 0x0A); lcd_write_data8(platform, 0x00);
    lcd_write_command(platform, 0xC3); lcd_write_data8(platform, 0x8A); lcd_write_data8(platform, 0x2A);
    lcd_write_command(platform, 0xC4); lcd_write_data8(platform, 0x8A); lcd_write_data8(platform, 0xEE);
    lcd_write_command(platform, 0xC5); lcd_write_data8(platform, 0x0E);
    lcd_write_command(platform, 0xE0);
    for (i = 0; i < (int)(sizeof(gamma_pos) / sizeof(gamma_pos[0])); ++i) {
        lcd_write_data8(platform, gamma_pos[i]);
    }
    lcd_write_command(platform, 0xE1);
    for (i = 0; i < (int)(sizeof(gamma_neg) / sizeof(gamma_neg[0])); ++i) {
        lcd_write_data8(platform, gamma_neg[i]);
    }
    lcd_write_command(platform, 0xF0); lcd_write_data8(platform, 0x01);
    lcd_write_command(platform, 0xF6); lcd_write_data8(platform, 0x00);
    lcd_write_command(platform, 0x3A); lcd_write_data8(platform, 0x05);
}

static void lcd_init_regs_st7789(rj_platform_t *platform) {
    static const uint8_t gamma_pos[] = {0xD0,0x04,0x0D,0x11,0x13,0x2B,0x3F,0x54,0x4C,0x18,0x0D,0x0B,0x1F,0x23};
    static const uint8_t gamma_neg[] = {0xD0,0x04,0x0C,0x11,0x13,0x2C,0x3F,0x44,0x51,0x2F,0x1F,0x1F,0x20,0x23};
    int i;

    lcd_write_command(platform, 0x36); lcd_write_data8(platform, 0x00);
    lcd_write_command(platform, 0x3A); lcd_write_data8(platform, 0x05);
    lcd_write_command(platform, 0xB2); lcd_write_data8(platform, 0x0C); lcd_write_data8(platform, 0x0C); lcd_write_data8(platform, 0x00); lcd_write_data8(platform, 0x33); lcd_write_data8(platform, 0x33);
    lcd_write_command(platform, 0xB7); lcd_write_data8(platform, 0x35);
    lcd_write_command(platform, 0xBB); lcd_write_data8(platform, 0x2B);
    lcd_write_command(platform, 0xC0); lcd_write_data8(platform, 0x2C);
    lcd_write_command(platform, 0xC2); lcd_write_data8(platform, 0x01);
    lcd_write_command(platform, 0xC3); lcd_write_data8(platform, 0x15);
    lcd_write_command(platform, 0xC4); lcd_write_data8(platform, 0x20);
    lcd_write_command(platform, 0xC6); lcd_write_data8(platform, 0x01);
    lcd_write_command(platform, 0xD0); lcd_write_data8(platform, 0xA4); lcd_write_data8(platform, 0xA1);
    lcd_write_command(platform, 0xE0);
    for (i = 0; i < (int)(sizeof(gamma_pos) / sizeof(gamma_pos[0])); ++i) {
        lcd_write_data8(platform, gamma_pos[i]);
    }
    lcd_write_command(platform, 0xE1);
    for (i = 0; i < (int)(sizeof(gamma_neg) / sizeof(gamma_neg[0])); ++i) {
        lcd_write_data8(platform, gamma_neg[i]);
    }
    lcd_write_command(platform, 0x21);
}

static void lcd_set_scan_default(rj_platform_t *platform) {
    lcd_write_command(platform, 0x36);
    if (platform->display_type == RJ_DISPLAY_ST7789_240) {
        lcd_write_data8(platform, 0x60);
    } else {
        lcd_write_data8(platform, 0x68);
    }
}

static void lcd_init_display(rj_platform_t *platform) {
    gpio_write_fd(platform->output_fds[RJ_OUT_BL], 1);
    gpio_write_fd(platform->output_fds[RJ_OUT_CS], 1);
    lcd_reset(platform);
    if (platform->display_type == RJ_DISPLAY_ST7789_240) {
        lcd_init_regs_st7789(platform);
    } else {
        lcd_init_regs_st7735(platform);
    }
    lcd_set_scan_default(platform);
    sleep_ms(200u);
    lcd_write_command(platform, 0x11);
    sleep_ms(120u);
    lcd_write_command(platform, 0x29);
}

static void lcd_set_window(rj_platform_t *platform, int x0, int y0, int x1, int y1) {
    int x_adjust = 0;
    int y_adjust = 0;

    if (platform->display_type == RJ_DISPLAY_ST7735_128) {
        x_adjust = 1;
        y_adjust = 2;
    }

    lcd_write_command(platform, 0x2A);
    lcd_write_data16(platform, (uint16_t)(x0 + x_adjust));
    lcd_write_data16(platform, (uint16_t)(x1 - 1 + x_adjust));
    lcd_write_command(platform, 0x2B);
    lcd_write_data16(platform, (uint16_t)(y0 + y_adjust));
    lcd_write_data16(platform, (uint16_t)(y1 - 1 + y_adjust));
    lcd_write_command(platform, 0x2C);
}

static uint16_t rgb888_to_rgb565(uint32_t argb) {
    uint8_t r = (uint8_t)((argb >> 16) & 0xffu);
    uint8_t g = (uint8_t)((argb >> 8) & 0xffu);
    uint8_t b = (uint8_t)(argb & 0xffu);
    return (uint16_t)(((r & 0xF8u) << 8) | ((g & 0xFCu) << 3) | (b >> 3));
}

static void compute_viewport(rj_platform_t *platform) {
    int view_w = platform->display_width;
    int view_h = (platform->display_width * platform->internal_height) / platform->internal_width;

    if (view_h > platform->display_height) {
        view_h = platform->display_height;
        view_w = (platform->display_height * platform->internal_width) / platform->internal_height;
    }
    if (view_w <= 0) {
        view_w = platform->display_width;
    }
    if (view_h <= 0) {
        view_h = platform->display_height;
    }

    platform->viewport_width = view_w;
    platform->viewport_height = view_h;
    platform->viewport_x = (platform->display_width - view_w) / 2;
    platform->viewport_y = (platform->display_height - view_h) / 2;
}

static rj_display_type_t detect_display_type(const char *root_dir, const char *requested_name) {
    char gui_conf_path[640];
    char buffer[4096];

    if (requested_name && strcmp(requested_name, "ST7789_240") == 0) {
        return RJ_DISPLAY_ST7789_240;
    }
    if (requested_name && strcmp(requested_name, "ST7735_128") == 0) {
        return RJ_DISPLAY_ST7735_128;
    }

    if (!root_dir || !root_dir[0]) {
        return RJ_DISPLAY_ST7735_128;
    }

    snprintf(gui_conf_path, sizeof(gui_conf_path), "%s/%s", root_dir, RJ_GUI_CONF_RELATIVE);
    if (read_text_file(gui_conf_path, buffer, sizeof(buffer)) != 0) {
        return RJ_DISPLAY_ST7735_128;
    }
    if (strstr(buffer, "ST7789_240") != NULL) {
        return RJ_DISPLAY_ST7789_240;
    }
    return RJ_DISPLAY_ST7735_128;
}

static void set_display_dimensions(rj_platform_t *platform) {
    if (platform->display_type == RJ_DISPLAY_ST7789_240) {
        platform->display_width = 240;
        platform->display_height = 240;
        copy_string(platform->display_name, sizeof(platform->display_name), "ST7789_240", NULL);
    } else {
        platform->display_width = 128;
        platform->display_height = 128;
        copy_string(platform->display_name, sizeof(platform->display_name), "ST7735_128", NULL);
    }

    platform->internal_width = 320;
    platform->internal_height = 200;
    if (platform->scale <= 0) {
        platform->scale = 1;
    }
    compute_viewport(platform);
}

static int configure_spi(rj_platform_t *platform) {
    uint8_t mode = SPI_MODE_0;
    uint8_t bits_per_word = 8;
    uint32_t speed_hz = (platform->display_type == RJ_DISPLAY_ST7789_240) ? 40000000u : 9000000u;

    platform->spi_fd = open(RJ_SPI_DEVICE, O_RDWR);
    if (platform->spi_fd < 0) {
        return -1;
    }

    if (ioctl(platform->spi_fd, SPI_IOC_WR_MODE, &mode) < 0) {
        return -1;
    }
    if (ioctl(platform->spi_fd, SPI_IOC_WR_BITS_PER_WORD, &bits_per_word) < 0) {
        return -1;
    }
    if (ioctl(platform->spi_fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed_hz) < 0) {
        return -1;
    }
    return 0;
}

static int setup_output_gpio(rj_platform_t *platform) {
    int i;
    for (i = 0; i < RJ_OUTPUT_COUNT; ++i) {
        platform->output_pins[i] = RJ_DEFAULT_OUTPUT_PINS[i];
        platform->output_fds[i] = -1;
        if (gpio_export(platform->output_pins[i]) != 0) {
            return -1;
        }
        sleep_ms(5u);
        if (gpio_set_direction(platform->output_pins[i], "out") != 0) {
            return -1;
        }
        platform->output_fds[i] = gpio_open_value_fd(platform->output_pins[i], O_WRONLY);
        if (platform->output_fds[i] < 0) {
            return -1;
        }
    }
    return 0;
}

static int setup_button_gpio(rj_platform_t *platform) {
    int i;
    platform->button_count = RJ_BUTTON_COUNT;
    for (i = 0; i < platform->button_count; ++i) {
        platform->button_pins[i] = RJ_DEFAULT_BUTTON_PINS[i];
        platform->button_fds[i] = -1;
        if (gpio_export(platform->button_pins[i]) != 0) {
            return -1;
        }
        sleep_ms(5u);
        if (gpio_set_direction(platform->button_pins[i], "in") != 0) {
            return -1;
        }
        platform->button_fds[i] = gpio_open_value_fd(platform->button_pins[i], O_RDONLY);
        if (platform->button_fds[i] < 0) {
            return -1;
        }
        platform->button_levels[i] = gpio_read_fd(platform->button_fds[i]);
    }
    platform->gpio_ready = 1;
    return 0;
}

int rj_platform_init(rj_platform_t *platform, const rj_options_t *options) {
    memset(platform, 0, sizeof(*platform));
    platform->spi_fd = -1;
    platform->last_event_ms = 0;

    if (options != NULL) {
        copy_string(platform->root_dir, sizeof(platform->root_dir), options->root_dir, "");
        copy_string(platform->wad_path, sizeof(platform->wad_path), options->wad_path, "");
        platform->scale = options->scale;
        platform->display_type = detect_display_type(platform->root_dir, options->display_name);
    } else {
        platform->display_type = RJ_DISPLAY_ST7735_128;
        platform->scale = 1;
    }

    set_display_dimensions(platform);
    if (configure_spi(platform) != 0) {
        fprintf(stderr, "[doom] warning: failed to open/configure %s: %s\n", RJ_SPI_DEVICE, strerror(errno));
        if (platform->spi_fd >= 0) {
            close(platform->spi_fd);
            platform->spi_fd = -1;
        }
    }

    if (setup_output_gpio(platform) != 0 || setup_button_gpio(platform) != 0) {
        fprintf(stderr, "[doom] warning: GPIO setup incomplete; input/output may not work\n");
    } else if (platform->spi_fd >= 0) {
        lcd_init_display(platform);
    }

    platform->tx_buffer_size = platform->display_width * platform->display_height * 2;
    platform->tx_buffer = (unsigned char *)malloc((size_t)platform->tx_buffer_size);
    if (!platform->tx_buffer) {
        fprintf(stderr, "[doom] warning: failed to allocate frame buffer\n");
    }

    return 0;
}

void rj_platform_shutdown(rj_platform_t *platform) {
    int i;
    if (!platform) {
        return;
    }
    if (platform->spi_fd >= 0) {
        close(platform->spi_fd);
        platform->spi_fd = -1;
    }
    for (i = 0; i < RJ_OUTPUT_COUNT; ++i) {
        if (platform->output_fds[i] >= 0) {
            close(platform->output_fds[i]);
            platform->output_fds[i] = -1;
        }
        if (platform->output_pins[i] > 0) {
            gpio_unexport(platform->output_pins[i]);
        }
    }
    for (i = 0; i < platform->button_count; ++i) {
        if (platform->button_fds[i] >= 0) {
            close(platform->button_fds[i]);
            platform->button_fds[i] = -1;
        }
        if (platform->button_pins[i] > 0) {
            gpio_unexport(platform->button_pins[i]);
        }
    }
    free(platform->tx_buffer);
    platform->tx_buffer = NULL;
}

int rj_platform_present(rj_platform_t *platform, const uint32_t *argb_frame) {
    int x;
    int y;
    if (!platform || platform->spi_fd < 0 || !platform->tx_buffer || !argb_frame) {
        return -1;
    }

    memset(platform->tx_buffer, 0, (size_t)platform->tx_buffer_size);
    for (y = 0; y < platform->viewport_height; ++y) {
        int src_y = (y * platform->internal_height) / platform->viewport_height;
        int dst_y = y + platform->viewport_y;
        for (x = 0; x < platform->viewport_width; ++x) {
            int src_x = (x * platform->internal_width) / platform->viewport_width;
            int dst_x = x + platform->viewport_x;
            int dst_index = (dst_y * platform->display_width + dst_x) * 2;
            uint16_t pixel = rgb888_to_rgb565(argb_frame[src_y * platform->internal_width + src_x]);
            platform->tx_buffer[dst_index] = (unsigned char)(pixel >> 8);
            platform->tx_buffer[dst_index + 1] = (unsigned char)(pixel & 0xffu);
        }
    }

    lcd_set_window(platform, 0, 0, platform->display_width, platform->display_height);
    gpio_write_fd(platform->output_fds[RJ_OUT_DC], 1);
    spi_write_bytes(platform, platform->tx_buffer, (size_t)platform->tx_buffer_size);
    return 0;
}

int rj_platform_poll_button(rj_platform_t *platform) {
    static const int button_codes[RJ_BUTTON_COUNT] = {
        RJ_BTN_UP,
        RJ_BTN_DOWN,
        RJ_BTN_LEFT,
        RJ_BTN_RIGHT,
        RJ_BTN_OK,
        RJ_BTN_KEY1,
        RJ_BTN_KEY2,
        RJ_BTN_KEY3,
    };
    int i;
    uint32_t now = monotonic_ms();

    if (!platform || !platform->gpio_ready) {
        return RJ_BTN_NONE;
    }

    for (i = 0; i < platform->button_count; ++i) {
        int level = gpio_read_fd(platform->button_fds[i]);
        if (level != platform->button_levels[i]) {
            platform->button_levels[i] = level;
            if ((now - platform->last_event_ms) < RJ_DEBOUNCE_MS) {
                return RJ_BTN_NONE;
            }
            platform->last_event_ms = now;
            if (level == 0) {
                return button_codes[i];
            }
            return RJ_BTN_NONE;
        }
    }

    return RJ_BTN_NONE;
}

uint32_t rj_platform_ticks_ms(void) {
    return monotonic_ms();
}

void rj_platform_sleep_ms(uint32_t ms) {
    sleep_ms(ms);
}

const char *rj_platform_display_name(const rj_platform_t *platform) {
    if (!platform) {
        return "unknown";
    }
    return platform->display_name;
}