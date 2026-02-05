#include <time.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static inline double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

int main(int argc, char *argv[]) {
    printf("Busy wait started\n");
    fflush(stdout);
    sleep(1);
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <seconds> <pages>\n", argv[0]);
        fprintf(stderr, "  seconds : busy wait time (e.g. 3.5)\n");
        fprintf(stderr, "  pages   : number of 4KB pages to allocate\n");
        return 1;
    }

    double seconds = atof(argv[1]);
    if (seconds < 0) {
        fprintf(stderr, "Invalid time: %f\n", seconds);
        return 1;
    }

    char *endptr = NULL;
    long pages_long = strtol(argv[2], &endptr, 10);
    if (*argv[2] == '\0' || *endptr != '\0') {
        fprintf(stderr, "Invalid pages: %s\n", argv[2]);
        return 1;
    }
    if (pages_long < 0) {
        fprintf(stderr, "Pages must be non-negative.\n");
        return 1;
    }

    size_t page_num = (size_t)pages_long;
    const size_t page_size = 4096;  
    size_t total_size = page_num * page_size;

    volatile char *buf = NULL;

    if (page_num > 0) {
        void *addr = mmap(NULL, total_size,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS,
                          -1, 0);
        if (addr == MAP_FAILED) {
            fprintf(stderr, "mmap failed: %s\n", strerror(errno));
            return 1;
        }

        buf = (volatile char *)addr;
    }

    double start = now_sec();
    size_t i = 0;

    while (now_sec() - start < seconds) {
        if (page_num > 0) {
            size_t page_index = i % page_num;
            size_t offset = page_index * page_size;
            buf[offset]++;  
            ++i;
        }
    }

    if (page_num > 0) {
        if (munmap((void *)buf, total_size) != 0) {
            fprintf(stderr, "munmap failed: %s\n", strerror(errno));
            return 1;
        }
    }

    printf("Busy wait finished\n");
    fflush(stdout);

    return 0;
}
