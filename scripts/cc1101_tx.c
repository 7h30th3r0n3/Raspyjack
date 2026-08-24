/*
 * cc1101_tx — precise GPIO bitbang OOK TX for CC1101 via GDO0
 *
 * Reads pulse durations from stdin (one per line, positive=HIGH, negative=LOW)
 * and toggles GDO0 (GPIO 15) with microsecond precision using mmap + busy-wait.
 *
 * The CC1101 must be pre-configured in async serial TX mode by the Python caller:
 *   IOCFG0=0x2E, MDMCFG2=0x30, PKTCTRL0=0x32, FREND0=0x11, STX strobe sent
 *
 * Usage: echo "pulses..." | sudo cc1101_tx [repeat_count]
 *   Input: one pulse per line, integer microseconds (positive=HIGH, negative=LOW)
 *          Empty line or "---" = end of frame (separator for repeats)
 *   repeat_count: how many times to send (default 1)
 *
 * Compile: gcc -O2 -o cc1101_tx cc1101_tx.c -lrt
 * Install: sudo cp cc1101_tx /usr/local/bin/
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <time.h>
#include <sched.h>

#define BLOCK_SIZE         4096

static off_t detect_gpio_base(void) {
    /* Parse /proc/iomem for actual GPIO base address.
     * Works on BCM2835 (0x20200000), BCM2836/7 (0x3F200000),
     * and BCM2711 (0xFE200000). */
    FILE *f = fopen("/proc/iomem", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "gpio")) {
                unsigned long base = strtoul(line, NULL, 16);
                fclose(f);
                if (base) return (off_t)base;
            }
        }
        fclose(f);
    }
    return 0x20200000; /* BCM2835 fallback */
}

#define GDO0_PIN           15

#define GPFSEL1            1
#define GPSET0             7
#define GPCLR0             10

#define MAX_PULSES         65536

static volatile uint32_t *gpio_map;

static void gpio_init(void) {
    off_t base = detect_gpio_base();
    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) {
        fd = open("/dev/gpiomem", O_RDWR | O_SYNC);
        if (fd < 0) { perror("open /dev/mem and /dev/gpiomem"); exit(1); }
        gpio_map = (volatile uint32_t *)mmap(NULL, BLOCK_SIZE,
            PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        close(fd);
    } else {
        gpio_map = (volatile uint32_t *)mmap(NULL, BLOCK_SIZE,
            PROT_READ | PROT_WRITE, MAP_SHARED, fd, base);
        close(fd);
    }
    if (gpio_map == MAP_FAILED) { perror("mmap"); exit(1); }
    fprintf(stderr, "GPIO base: 0x%lx\n", (unsigned long)base);

    /* Set GDO0_PIN as output */
    int reg = GDO0_PIN / 10;
    int shift = (GDO0_PIN % 10) * 3;
    uint32_t fsel = gpio_map[reg];
    fsel &= ~(7 << shift);
    fsel |=  (1 << shift);
    gpio_map[reg] = fsel;
}

static inline void gpio_high(void) {
    gpio_map[GPSET0] = (1 << GDO0_PIN);
}

static inline void gpio_low(void) {
    gpio_map[GPCLR0] = (1 << GDO0_PIN);
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

    /* Read all pulses from stdin */
    int32_t pulses[MAX_PULSES];
    int count = 0;
    char line[64];
    while (fgets(line, sizeof(line), stdin) && count < MAX_PULSES) {
        if (line[0] == '-' && line[1] == '-') break;  /* --- = stop */
        int32_t val = atoi(line);
        if (val != 0)
            pulses[count++] = val;
    }

    if (count == 0) {
        fprintf(stderr, "No pulses\n");
        return 1;
    }

    gpio_init();
    gpio_low();

    /* Set real-time priority for minimal jitter */
    struct sched_param sp;
    sp.sched_priority = 50;
    sched_setscheduler(0, SCHED_FIFO, &sp);

    /* Send pulses */
    for (int r = 0; r < repeat; r++) {
        uint64_t t = now_ns();
        for (int i = 0; i < count; i++) {
            int32_t p = pulses[i];
            uint64_t dur_ns = (uint64_t)(abs(p)) * 1000ULL;
            if (p > 0)
                gpio_high();
            else
                gpio_low();
            t += dur_ns;
            busy_wait_ns(t);
        }
        gpio_low();
        /* Small gap between repeats */
        t += 1000000ULL;  /* 1ms */
        busy_wait_ns(t);
    }

    gpio_low();

    /* Restore GPIO to input */
    int reg = GDO0_PIN / 10;
    int shift = (GDO0_PIN % 10) * 3;
    uint32_t fsel = gpio_map[reg];
    fsel &= ~(7 << shift);
    gpio_map[reg] = fsel;

    fprintf(stderr, "TX %d pulses x%d\n", count, repeat);
    return 0;
}
