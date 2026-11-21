#define _POSIX_C_SOURCE 200809L
#include "zerokull.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    bool watch = (argc > 1 && strcmp(*(argv + 1), "-w") == 0);
    int fd = shm_open(ZK_SHM_NAME, O_RDONLY, 0);
    if (fd < 0) {
        fprintf(stderr, "zerokull-stat: /dev/shm%s not found (is zerokull-daemon running?)\n", ZK_SHM_NAME);
        return 1;
    }

    const struct zk_shm_telemetry *shm = mmap(NULL, sizeof(*shm), PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (shm == MAP_FAILED || shm->magic != ZK_SHM_MAGIC) {
        fprintf(stderr, "zerokull-stat: invalid telemetry header\n");
        return 1;
    }

    do {
        uint64_t now = (uint64_t)time(NULL);
        uint64_t up = (shm->start_ts > 0 && now >= shm->start_ts) ? (now - shm->start_ts) : 0;
        printf("ZEROKULL TELEMETRY | status=%s pid=%u uptime=%llus | inspected=%llu drops=%llu bans=%llu\n",
               shm->pid ? "ACTIVE" : "STOPPED",
               shm->pid,
               (unsigned long long)up,
               (unsigned long long)shm->inspected,
               (unsigned long long)shm->drops,
               (unsigned long long)shm->bans);
        fflush(stdout);
        if (watch) sleep(1);
    } while (watch);

    munmap((void *)shm, sizeof(*shm));
    return 0;
}
