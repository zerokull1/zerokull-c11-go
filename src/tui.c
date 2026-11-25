// ZEROKULL (zerokull1) | Author Signature: 0x5A45524F4B554C4CULL
// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0.

#define _POSIX_C_SOURCE 200809L
#include "zerokull.h"
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static struct termios g_orig_termios;
static bool g_tty_raw = false;

static void restore_tty(void) {
    if (g_tty_raw) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_orig_termios);
        g_tty_raw = false;
    }
    printf("\033[?25h\033[0m\n");
    fflush(stdout);
}

static void enable_raw_tty(void) {
    if (!isatty(STDIN_FILENO)) return;
    if (tcgetattr(STDIN_FILENO, &g_orig_termios) == 0) {
        struct termios raw = g_orig_termios;
        raw.c_lflag &= (tcflag_t)~(ECHO | ICANON);
        raw.c_cc[VMIN] = 0;
        raw.c_cc[VTIME] = 0;
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == 0) {
            g_tty_raw = true;
            atexit(restore_tty);
        }
    }
}

static bool pid_alive(uint32_t pid) {
    if (pid == 0) return false;
    return kill((pid_t)pid, 0) == 0;
}

int main(int argc, char **argv) {
    const char *shm_name = (argc > 1) ? argv[1] : ZK_SHM_NAME;
    bool once = (argc > 2 && strcmp(argv[2], "--once") == 0);

    enable_raw_tty();
    printf("\033[?25l");

    uint64_t prev_insp = 0, prev_drop = 0;
    bool have_prev = false;
    char status_msg[96] = "READY (keys: [R] reload policy SIGHUP | [Q] quit)";

    for (;;) {
        struct zk_shm_telemetry snap;
        memset(&snap, 0, sizeof(snap));
        bool valid = false;

        int fd = shm_open(shm_name, O_RDONLY, 0);
        if (fd >= 0) {
            void *p = mmap(NULL, sizeof(snap), PROT_READ, MAP_SHARED, fd, 0);
            if (p != MAP_FAILED) {
                memcpy(&snap, p, sizeof(snap));
                munmap(p, sizeof(snap));
                if (snap.magic == ZK_SHM_MAGIC) valid = true;
            }
            close(fd);
        }

        bool active = valid && pid_alive(snap.pid);
        uint64_t pps = (valid && have_prev && snap.inspected >= prev_insp) ? (snap.inspected - prev_insp) * 5ULL : 0ULL;
        uint64_t dps = (valid && have_prev && snap.drops >= prev_drop) ? (snap.drops - prev_drop) * 5ULL : 0ULL;
        if (valid) {
            prev_insp = snap.inspected;
            prev_drop = snap.drops;
            have_prev = true;
        }

        uint64_t up = (active && (uint64_t)time(NULL) >= snap.start_ts) ? ((uint64_t)time(NULL) - snap.start_ts) : 0ULL;
        uint64_t drop_pct = (valid && snap.inspected > 0) ? ((snap.drops * 100ULL) / snap.inspected) : 0ULL;
        if (drop_pct > 100ULL) drop_pct = 100ULL;

        char bar[32];
        size_t filled = (size_t)((drop_pct * 30ULL) / 100ULL);
        for (size_t i = 0; i < 30; i++) bar[i] = (i < filled) ? '#' : '.';
        bar[30] = '\0';

        printf("\033[H\033[2J");
        printf("\033[1;36m+----------------------------------------------------------------------+\033[0m\n");
        printf("\033[1;36m| ZEROKULL SSH OPERATOR RADAR (zero-tui | Headless XDP/C11 Console)    |\033[0m\n");
        printf("\033[1;36m+----------------------------------------------------------------------+\033[0m\n");
        printf("| State : %s%-12s\033[0m | PID: %-8u | Uptime: %-10llus |\n",
               active ? "\033[1;32m" : "\033[1;31m",
               active ? "ACTIVE" : "OFFLINE",
               snap.pid, (unsigned long long)up);
        printf("| Mode  : %-12s | SHM: %-36s |\n",
               (valid && snap.shadow_mode) ? "SHADOW_AUDIT" : "XDP_ENFORCE", shm_name);
        printf("+----------------------------------------------------------------------+\n");
        printf("| Inspected Total : %-18llu | Rate : %-12llu pps |\n",
               (unsigned long long)snap.inspected, (unsigned long long)pps);
        printf("| Dropped Total   : %-18llu | Rate : %-12llu pps |\n",
               (unsigned long long)snap.drops, (unsigned long long)dps);
        printf("| Auto-Banned IPs : %-18llu | Drop Ratio : %3llu%%          |\n",
               (unsigned long long)snap.bans, (unsigned long long)drop_pct);
        printf("| Mitigation Load : [\033[1;33m%s\033[0m]                  |\n", bar);
        printf("+----------------------------------------------------------------------+\n");
        printf("| %s%-68s\033[0m |\n", "\033[0;37m", status_msg);
        printf("+----------------------------------------------------------------------+\n");
        fflush(stdout);

        if (once) break;

        char ch = 0;
        if (read(STDIN_FILENO, &ch, 1) == 1) {
            if (ch == 'q' || ch == 'Q') break;
            if (ch == 'r' || ch == 'R') {
                if (active && kill((pid_t)snap.pid, SIGHUP) == 0) {
                    snprintf(status_msg, sizeof(status_msg), "SIGHUP SENT -> PID %u reloaded /etc/zeromani/policy.conf", snap.pid);
                } else {
                    snprintf(status_msg, sizeof(status_msg), "WARN: daemon offline or EPERM sending SIGHUP");
                }
            }
        }

        struct timespec ts = { .tv_sec = 0, .tv_nsec = 200000000L };
        nanosleep(&ts, NULL);
    }
    return 0;
}
