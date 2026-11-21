// ZEROKULL (zerokull1) | Author Signature: 0x5A45524F4B554C4CULL
// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0.

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
    if (fd < 0) { fprintf(stderr, "zerokull-stat: /dev/shm%s not found\n", ZK_SHM_NAME); return 1; }

    const volatile struct zk_shm_telemetry *shm = mmap(NULL, sizeof(*shm), PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (shm == MAP_FAILED || shm->magic != ZK_SHM_MAGIC) {
        fprintf(stderr, "zerokull-stat: invalid telemetry header\n");
        if (shm != MAP_FAILED) munmap((void *)shm, sizeof(*shm));
        return 1;
    }

    do {
        uint64_t now = (uint64_t)time(NULL), start_ts = shm->start_ts;
        uint32_t pid = shm->pid;
        uint64_t inspected = shm->inspected, drops = shm->drops, bans = shm->bans;
        uint64_t up = (start_ts > 0 && now >= start_ts) ? (now - start_ts) : 0;
        printf("ZEROKULL TELEMETRY | status=%s pid=%u uptime=%llus | inspected=%llu drops=%llu bans=%llu\n",
               pid ? "ACTIVE" : "STOPPED", pid, (unsigned long long)up,
               (unsigned long long)inspected, (unsigned long long)drops, (unsigned long long)bans);
        fflush(stdout);
        if (watch) sleep(1);
    } while (watch);

    munmap((void *)shm, sizeof(*shm));
    return 0;
}
