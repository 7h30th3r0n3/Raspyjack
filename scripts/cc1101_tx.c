/*
 * cc1101_tx — precise GPIO bitbang OOK TX for CC1101 via GDO0
 * Uses libgpiod v2 for kernel-level GPIO control + busy-wait for µs precision.
 *
 * Usage: echo "pulses..." | sudo cc1101_tx [repeat_count]
 *   Input: one pulse per line (positive=HIGH, negative=LOW), "---" = stop
 *
 * Compile: gcc -O2 -o cc1101_tx cc1101_tx.c $(pkg-config --cflags --libs libgpiod) -lrt
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sched.h>
#include <sys/mman.h>
#include <gpiod.h>

#define GDO0_PIN       15
#define GPIO_CHIP      "/dev/gpiochip0"
#define MAX_PULSES     65536

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static inline void busy_wait_ns(uint64_t target_ns) {
    while (now_ns() < target_ns) ;
}

int main(int argc, char *argv[]) {
    int repeat = 1;
    if (argc > 1) repeat = atoi(argv[1]);
    if (repeat < 1) repeat = 1;
    if (repeat > 100) repeat = 100;

    int32_t pulses[MAX_PULSES];
    int count = 0;
    char line[64];
    while (fgets(line, sizeof(line), stdin) && count < MAX_PULSES) {
        if (line[0] == '-' && line[1] == '-') break;
        int32_t val = atoi(line);
        if (val != 0) pulses[count++] = val;
    }
    if (count == 0) { fprintf(stderr, "No pulses\n"); return 1; }

    struct gpiod_chip *chip = gpiod_chip_open(GPIO_CHIP);
    if (!chip) { perror("gpiod_chip_open"); return 1; }

    struct gpiod_line_settings *settings = gpiod_line_settings_new();
    gpiod_line_settings_set_direction(settings, GPIOD_LINE_DIRECTION_OUTPUT);
    gpiod_line_settings_set_output_value(settings, GPIOD_LINE_VALUE_INACTIVE);

    struct gpiod_line_config *line_cfg = gpiod_line_config_new();
    unsigned int offset = GDO0_PIN;
    gpiod_line_config_add_line_settings(line_cfg, &offset, 1, settings);

    struct gpiod_request_config *req_cfg = gpiod_request_config_new();
    gpiod_request_config_set_consumer(req_cfg, "cc1101-tx");

    struct gpiod_line_request *request = gpiod_chip_request_lines(chip, req_cfg, line_cfg);
    gpiod_request_config_free(req_cfg);
    gpiod_line_config_free(line_cfg);
    gpiod_line_settings_free(settings);

    if (!request) { perror("request_lines"); gpiod_chip_close(chip); return 1; }

    struct sched_param sp = { .sched_priority = 50 };
    sched_setscheduler(0, SCHED_FIFO, &sp);
    mlockall(MCL_CURRENT | MCL_FUTURE);

    /* Detect if inter-frame gap needed: if last pulse and first pulse
     * are same polarity, insert a brief opposite pulse to separate frames */
    int needs_sep = (count >= 2) && ((pulses[count-1] < 0) == (pulses[0] < 0));

    for (int r = 0; r < repeat; r++) {
        uint64_t t = now_ns();
        for (int i = 0; i < count; i++) {
            int32_t p = pulses[i];
            enum gpiod_line_value val = (p > 0) ? GPIOD_LINE_VALUE_ACTIVE : GPIOD_LINE_VALUE_INACTIVE;
            gpiod_line_request_set_value(request, GDO0_PIN, val);
            t += (uint64_t)(abs(p)) * 1000ULL;
            busy_wait_ns(t);
        }
        gpiod_line_request_set_value(request, GDO0_PIN, GPIOD_LINE_VALUE_INACTIVE);
        if (r < repeat - 1 && needs_sep) {
            /* Brief HIGH separator then back to LOW */
            gpiod_line_request_set_value(request, GDO0_PIN, GPIOD_LINE_VALUE_ACTIVE);
            t += 100000ULL; /* 100us HIGH */
            busy_wait_ns(t);
            gpiod_line_request_set_value(request, GDO0_PIN, GPIOD_LINE_VALUE_INACTIVE);
            t += 100000ULL; /* 100us LOW */
            busy_wait_ns(t);
        }
    }

    gpiod_line_request_set_value(request, GDO0_PIN, GPIOD_LINE_VALUE_INACTIVE);
    gpiod_line_request_release(request);
    gpiod_chip_close(chip);
    fprintf(stderr, "TX %d pulses x%d\n", count, repeat);
    return 0;
}
