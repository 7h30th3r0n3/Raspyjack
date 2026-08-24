/*
 * cc1101_tx — precise GPIO bitbang OOK TX for CC1101 via GDO0
 *
 * Uses /sys/class/gpio for maximum compatibility (no libgpiod needed).
 * Reads pulse durations from stdin, toggles GDO0 with µs precision.
 *
 * Usage: echo "pulses..." | sudo cc1101_tx [repeat_count]
 *   Input: one pulse per line (positive=HIGH, negative=LOW), "---" = stop
 *
 * Compile: gcc -O2 -o cc1101_tx cc1101_tx.c -lrt
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sched.h>
#include <sys/mman.h>

#define GDO0_PIN       15
#define MAX_PULSES     65536

static int gpio_fd = -1;

static int gpio_export(int pin) {
    char buf[64];
    int fd = open("/sys/class/gpio/export", O_WRONLY);
    if (fd < 0) return -1;
    int n = snprintf(buf, sizeof(buf), "%d", pin);
    write(fd, buf, n);
    close(fd);
    usleep(100000); /* wait for sysfs to create files */
    return 0;
}

static int gpio_set_direction(int pin, const char *dir) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/gpio/gpio%d/direction", pin);
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    write(fd, dir, strlen(dir));
    close(fd);
    return 0;
}

static int gpio_open_value(int pin) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/gpio/gpio%d/value", pin);
    return open(path, O_WRONLY);
}

static void gpio_unexport(int pin) {
    char buf[64];
    int fd = open("/sys/class/gpio/unexport", O_WRONLY);
    if (fd < 0) return;
    int n = snprintf(buf, sizeof(buf), "%d", pin);
    write(fd, buf, n);
    close(fd);
}

static inline void gpio_set(int val) {
    if (val)
        write(gpio_fd, "1", 1);
    else
        write(gpio_fd, "0", 1);
    lseek(gpio_fd, 0, SEEK_SET);
}

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static inline void busy_wait_ns(uint64_t target_ns) {
    while (now_ns() < target_ns)
        ;
}

int main(int argc, char *argv[]) {
    int repeat = 1;
    if (argc > 1)
        repeat = atoi(argv[1]);
    if (repeat < 1) repeat = 1;
    if (repeat > 100) repeat = 100;

    /* Read pulses from stdin */
    int32_t pulses[MAX_PULSES];
    int count = 0;
    char line[64];
    while (fgets(line, sizeof(line), stdin) && count < MAX_PULSES) {
        if (line[0] == '-' && line[1] == '-') break;
        int32_t val = atoi(line);
        if (val != 0)
            pulses[count++] = val;
    }

    if (count == 0) {
        fprintf(stderr, "No pulses\n");
        return 1;
    }

    /* Setup GPIO */
    gpio_export(GDO0_PIN);
    if (gpio_set_direction(GDO0_PIN, "out") < 0) {
        fprintf(stderr, "Cannot set GPIO %d as output\n", GDO0_PIN);
        return 1;
    }
    gpio_fd = gpio_open_value(GDO0_PIN);
    if (gpio_fd < 0) {
        fprintf(stderr, "Cannot open GPIO %d value\n", GDO0_PIN);
        return 1;
    }
    gpio_set(0);

    /* Real-time priority + lock memory */
    struct sched_param sp;
    sp.sched_priority = 50;
    sched_setscheduler(0, SCHED_FIFO, &sp);
    mlockall(MCL_CURRENT | MCL_FUTURE);

    /* Send pulses */
    for (int r = 0; r < repeat; r++) {
        uint64_t t = now_ns();
        for (int i = 0; i < count; i++) {
            int32_t p = pulses[i];
            uint64_t dur_ns = (uint64_t)(abs(p)) * 1000ULL;
            gpio_set(p > 0 ? 1 : 0);
            t += dur_ns;
            busy_wait_ns(t);
        }
        gpio_set(0);
        t += 1000000ULL;
        busy_wait_ns(t);
    }

    gpio_set(0);
    close(gpio_fd);
    gpio_set_direction(GDO0_PIN, "in");
    gpio_unexport(GDO0_PIN);

    fprintf(stderr, "TX %d pulses x%d\n", count, repeat);
    return 0;
}
