/*
 * ir_carrier — fast GPIO bitbang for 1.25 MHz IR carrier on GPIO 12
 * Usage: ir_carrier <duration_us> [burst_us gap_us burst_us gap_us ...]
 *   No args: carrier ON for duration_us then OFF
 *   With burst/gap pairs: modulated output (TagTinker ESL)
 *
 * Compile: gcc -O2 -o ir_carrier ir_carrier.c
 * Run:     sudo ./ir_carrier 1000000   (1 second carrier)
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

/* BCM2835 GPIO registers */
#define BCM2835_PERI_BASE  0x20000000  /* RPi Zero / CM0 */
#define GPIO_BASE          (BCM2835_PERI_BASE + 0x200000)
#define BLOCK_SIZE         4096

#define GPIO_PIN           12

/* Register offsets (in 32-bit words) */
#define GPFSEL1            1    /* GPIO 10-19 function select */
#define GPSET0             7    /* GPIO 0-31 set */
#define GPCLR0             10   /* GPIO 0-31 clear */

static volatile uint32_t *gpio_map;

static void gpio_init(void) {
    int fd = open("/dev/gpiomem", O_RDWR | O_SYNC);
    if (fd < 0) {
        fd = open("/dev/mem", O_RDWR | O_SYNC);
        if (fd < 0) { perror("open /dev/mem"); exit(1); }
        gpio_map = (volatile uint32_t *)mmap(NULL, BLOCK_SIZE,
            PROT_READ | PROT_WRITE, MAP_SHARED, fd, GPIO_BASE);
    } else {
        gpio_map = (volatile uint32_t *)mmap(NULL, BLOCK_SIZE,
            PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    }
    close(fd);
    if (gpio_map == MAP_FAILED) { perror("mmap"); exit(1); }

    /* Set GPIO 12 as output (FSEL1 bits 8:6 = 001) */
    uint32_t fsel = gpio_map[GPFSEL1];
    fsel &= ~(7 << 6);   /* clear bits 8:6 */
    fsel |=  (1 << 6);   /* set output */
    gpio_map[GPFSEL1] = fsel;
}

static inline void gpio_set(void) {
    gpio_map[GPSET0] = (1 << GPIO_PIN);
}

static inline void gpio_clr(void) {
    gpio_map[GPCLR0] = (1 << GPIO_PIN);
}

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* Generate 1.25 MHz carrier for duration_ns nanoseconds */
/* Calibration: nop count auto-tuned at startup */
static int nop_count = 30;

static void calibrate_nops(void) {
    /* Measure toggle speed with current nop_count, adjust to hit 1250 kHz */
    uint64_t start = now_ns();
    int cycles = 10000;
    for (int c = 0; c < cycles; c++) {
        gpio_set();
        for (volatile int i = 0; i < nop_count; i++) __asm__("nop");
        gpio_clr();
        for (volatile int i = 0; i < nop_count; i++) __asm__("nop");
    }
    uint64_t elapsed = now_ns() - start;
    double actual_freq = (double)cycles * 1000000000.0 / elapsed;
    double ratio = actual_freq / 1250000.0;
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

static void carrier_off_wait(uint64_t duration_ns) {
    gpio_clr();
    uint64_t end = now_ns() + duration_ns;
    while (now_ns() < end);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <duration_us> [burst_us gap_us ...]\n", argv[0]);
        return 1;
    }

    gpio_init();
    calibrate_nops();

    if (argc == 2) {
        /* Simple carrier for N microseconds */
        uint64_t dur = (uint64_t)atol(argv[1]) * 1000;
        carrier_on(dur);
        gpio_clr();
    } else {
        /* Burst/gap pairs from argv */
        for (int i = 1; i < argc - 1; i += 2) {
            uint64_t burst = (uint64_t)atol(argv[i]) * 1000;
            uint64_t gap   = (uint64_t)atol(argv[i+1]) * 1000;
            carrier_on(burst);
            carrier_off_wait(gap);
        }
        /* Last arg if odd = final burst */
        if ((argc - 1) % 2 == 1) {
            uint64_t burst = (uint64_t)atol(argv[argc-1]) * 1000;
            carrier_on(burst);
        }
        gpio_clr();
    }

    return 0;
}
