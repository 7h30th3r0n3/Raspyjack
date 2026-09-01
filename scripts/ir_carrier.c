/*
 * ir_carrier — fast GPIO bitbang for ~1.4 MHz IR carrier on GPIO 12
 *
 * Mode 1: ir_carrier <duration_us>
 *   Simple carrier for N microseconds.
 *
 * Mode 2: ir_carrier <burst_us> <gap_us> [burst gap ...]
 *   Single frame from argv.
 *
 * Mode 3: echo "burst gap burst gap ... | burst gap ... | ..." | ir_carrier --stdin <repeats> <gap_us>
 *   Read burst/gap pairs from stdin (pipe-separated frames), repeat N times
 *   with gap_us between repeats. All repeats in-process, no fork overhead.
 *
 * Compile: gcc -O2 -o ir_carrier ir_carrier.c -lrt
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <sched.h>

#define BCM2835_PERI_BASE  0x20000000
#define GPIO_BASE          (BCM2835_PERI_BASE + 0x200000)
#define BLOCK_SIZE         4096
#define GPIO_PIN           12
#define GPFSEL1            1
#define GPSET0             7
#define GPCLR0             10

#define MAX_PAIRS          4096

static volatile uint32_t *gpio_map;
static int nop_count = 30;

static void gpio_init(void) {
    int fd = open("/dev/gpiomem", O_RDWR | O_SYNC);
    if (fd < 0) {
        fd = open("/dev/mem", O_RDWR | O_SYNC);
        if (fd < 0) { perror("open"); exit(1); }
        gpio_map = (volatile uint32_t *)mmap(NULL, BLOCK_SIZE,
            PROT_READ | PROT_WRITE, MAP_SHARED, fd, GPIO_BASE);
    } else {
        gpio_map = (volatile uint32_t *)mmap(NULL, BLOCK_SIZE,
            PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    }
    close(fd);
    if (gpio_map == MAP_FAILED) { perror("mmap"); exit(1); }
    uint32_t fsel = gpio_map[GPFSEL1];
    fsel &= ~(7 << 6);
    fsel |=  (1 << 6);
    gpio_map[GPFSEL1] = fsel;
}

static inline void gpio_set(void) { gpio_map[GPSET0] = (1 << GPIO_PIN); }
static inline void gpio_clr(void) { gpio_map[GPCLR0] = (1 << GPIO_PIN); }

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void calibrate_nops(void) {
    uint64_t start = now_ns();
    int cycles = 10000;
    for (int c = 0; c < cycles; c++) {
        gpio_set();
        for (volatile int i = 0; i < nop_count; i++) __asm__("nop");
        gpio_clr();
        for (volatile int i = 0; i < nop_count; i++) __asm__("nop");
    }
    uint64_t elapsed = now_ns() - start;
    /* Target ~1.4 MHz to match ESP32-S3 Evil-Cardputer */
    double actual_freq = (double)cycles * 1000000000.0 / elapsed;
    double ratio = actual_freq / 1400000.0;
    nop_count = (int)(nop_count * ratio);
    if (nop_count < 1) nop_count = 1;
    if (nop_count > 200) nop_count = 200;
}

static void carrier_on(uint64_t duration_ns) {
    uint64_t end = now_ns() + duration_ns;
    while (now_ns() < end) {
        gpio_set();
        for (volatile int i = 0; i < nop_count; i++) __asm__("nop");
        gpio_clr();
        for (volatile int i = 0; i < nop_count; i++) __asm__("nop");
    }
}

static inline void busy_wait_ns(uint64_t target) {
    while (now_ns() < target);
}

static void set_realtime(void) {
    struct sched_param sp = { .sched_priority = 50 };
    sched_setscheduler(0, SCHED_FIFO, &sp);
    mlockall(MCL_CURRENT | MCL_FUTURE);
}

static void send_pairs(uint32_t *burst_ns, uint32_t *gap_ns, int count) {
    for (int i = 0; i < count; i++) {
        carrier_on(burst_ns[i]);
        if (gap_ns[i] > 0) {
            gpio_clr();
            uint64_t end = now_ns() + gap_ns[i];
            busy_wait_ns(end);
        }
    }
    gpio_clr();
}

int main(int argc, char *argv[]) {
    gpio_init();
    calibrate_nops();
    set_realtime();

    if (argc >= 2 && strcmp(argv[1], "--stdin") == 0) {
        /* Mode 3: stdin with repeats */
        int repeats = argc >= 3 ? atoi(argv[2]) : 1;
        int gap_us  = argc >= 4 ? atoi(argv[3]) : 500;

        char line[65536];
        if (!fgets(line, sizeof(line), stdin)) {
            fprintf(stderr, "No input\n");
            return 1;
        }

        /* Parse burst/gap pairs separated by spaces, frames by | */
        uint32_t burst_ns[MAX_PAIRS], gap_ns_arr[MAX_PAIRS];
        int pair_count = 0;

        char *frame_str = strtok(line, "\n");
        if (!frame_str) return 1;

        /* Single frame: parse all numbers as burst gap burst gap ... */
        char *tok = strtok(frame_str, " \t");
        int val_idx = 0;
        uint32_t vals[MAX_PAIRS * 2];
        int nvals = 0;
        while (tok && nvals < MAX_PAIRS * 2) {
            vals[nvals++] = (uint32_t)atol(tok);
            tok = strtok(NULL, " \t");
        }

        for (int i = 0; i < nvals - 1; i += 2) {
            burst_ns[pair_count] = (uint64_t)vals[i] * 1000;
            gap_ns_arr[pair_count] = (uint64_t)vals[i + 1] * 1000;
            pair_count++;
        }
        if (nvals % 2 == 1) {
            burst_ns[pair_count] = (uint64_t)vals[nvals - 1] * 1000;
            gap_ns_arr[pair_count] = 0;
            pair_count++;
        }

        if (pair_count == 0) {
            fprintf(stderr, "No pairs parsed\n");
            return 1;
        }

        uint64_t gap_ns = (uint64_t)gap_us * 1000;

        for (int r = 0; r <= repeats; r++) {
            send_pairs(burst_ns, gap_ns_arr, pair_count);
            if (r < repeats && gap_ns > 0) {
                uint64_t end = now_ns() + gap_ns;
                busy_wait_ns(end);
            }
        }
        gpio_clr();
        fprintf(stderr, "TX %d pairs x%d\n", pair_count, repeats + 1);

    } else if (argc == 2) {
        /* Mode 1: simple carrier */
        uint64_t dur = (uint64_t)atol(argv[1]) * 1000;
        carrier_on(dur);
        gpio_clr();

    } else if (argc > 2) {
        /* Mode 2: burst/gap from argv (legacy) */
        for (int i = 1; i < argc - 1; i += 2) {
            uint64_t burst = (uint64_t)atol(argv[i]) * 1000;
            uint64_t gap   = (uint64_t)atol(argv[i+1]) * 1000;
            carrier_on(burst);
            gpio_clr();
            uint64_t end = now_ns() + gap;
            busy_wait_ns(end);
        }
        if ((argc - 1) % 2 == 1) {
            uint64_t burst = (uint64_t)atol(argv[argc-1]) * 1000;
            carrier_on(burst);
        }
        gpio_clr();
    }

    return 0;
}
