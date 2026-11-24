// ZEROKULL (zerokull1) | Author Signature: 0x5A45524F4B554C4CULL
// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0.

#define _POSIX_C_SOURCE 200809L
#include "zerokull.h"
#include "xdp_guard.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define ZK_MAX_PORTS 1024

static volatile sig_atomic_t g_stop = 0;

struct app_ctx {
    struct zk_engine_ctx engine;
    volatile struct zk_shm_telemetry *shm;
    int blacklist_fd;
    int whitelist_fd;
    int stats_fd;
    unsigned int ncpus;
    struct zk_xdp_stats *cpu_stats;
    bool shadow_mode;
};

static void on_signal(int sig) { (void)sig; g_stop = 1; }

static bool is_physical_iface(const char *name) {
    if (!name || !name[0]) return false;
    if (strcmp(name, "lo") == 0) return false;
    if (strncmp(name, "veth", 4) == 0) return false;
    if (strncmp(name, "docker", 6) == 0) return false;
    if (strncmp(name, "virbr", 5) == 0) return false;
    if (strncmp(name, "br-", 3) == 0) return false;
    if (strncmp(name, "tun", 3) == 0 || strncmp(name, "tap", 3) == 0) return false;
    return true;
}

static unsigned int sync_all_ports_xdp(struct bpf_program *prog, struct bpf_link **links, bool all_ports, unsigned int single_idx) {
    unsigned int active = 0;
    char ifname[IF_NAMESIZE];
    for (unsigned int idx = 2; idx < ZK_MAX_PORTS; idx++) {
        if (!all_ports && idx != single_idx) continue;
        if (if_indextoname(idx, ifname) != NULL && (!all_ports || is_physical_iface(ifname))) {
            if (!links[idx]) {
                links[idx] = bpf_program__attach_xdp(prog, (int)idx);
            }
            if (links[idx]) active++;
        } else if (links[idx]) {
            bpf_link__destroy(links[idx]);
            links[idx] = NULL;
        }
    }
    return active;
}

static void sync_telemetry(struct app_ctx *app) {
    if (!app->shm) return;
    uint64_t kern_drops = 0, kern_rx = 0;
    uint32_t zero = 0;
    if (app->cpu_stats && bpf_map_lookup_elem(app->stats_fd, &zero, app->cpu_stats) == 0) {
        for (unsigned int i = 0; i < app->ncpus; i++) {
            kern_rx    += app->cpu_stats[i].rx_packets;
            kern_drops += app->cpu_stats[i].xdp_drops;
        }
    }
    uint64_t total_rx = app->engine.total_inspected + kern_drops;
    if (kern_rx > total_rx) total_rx = kern_rx;
    app->shm->inspected = total_rx;
    app->shm->drops     = app->engine.total_drops + kern_drops;
    app->shm->bans      = app->engine.total_bans;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct app_ctx *app = (struct app_ctx *)ctx;
    const struct zk_pkt_event *ev = (const struct zk_pkt_event *)data;
    if (data_sz < offsetof(struct zk_pkt_event, data) || ev->cap_len > ZK_MAX_PKT_LEN) return 0;
    if (data_sz < offsetof(struct zk_pkt_event, data) + (size_t)ev->cap_len) return 0;

    uint32_t src_ip = 0;
    enum zk_verdict raw_v = zk_inspect_packet(&app->engine, ev->data, ev->cap_len, &src_ip);
    if (raw_v == ZK_VERDICT_BAN && src_ip != 0 && !app->shadow_mode) {
        uint8_t one = 1;
        bpf_map_update_elem(app->blacklist_fd, &src_ip, &one, BPF_ANY);
        bpf_map_delete_elem(app->whitelist_fd, &src_ip);
    }
    return 0;
}

int main(int argc, char **argv) {
    bool all_ports = true;
    bool shadow_mode = false;
    unsigned int single_idx = 0;
    const char *mode_label = "ALL-PORTS-MESH (1..1024 NICs)";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--shadow") == 0 || strcmp(argv[i], "-s") == 0) {
            shadow_mode = true;
        } else if (strcmp(argv[i], "all") == 0 || strcmp(argv[i], "--all") == 0) {
            all_ports = true;
        } else {
            all_ports = false;
            mode_label = argv[i];
            single_idx = if_nametoindex(mode_label);
            if (single_idx == 0 || single_idx >= ZK_MAX_PORTS) { perror("if_nametoindex"); return 1; }
        }
    }

    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    struct xdp_guard_bpf *skel = xdp_guard_bpf__open();
    if (!skel) { fprintf(stderr, "xdp_guard_bpf__open failed\n"); return 1; }
    skel->rodata->shadow_mode = shadow_mode ? 1 : 0;
    if (xdp_guard_bpf__load(skel) != 0) {
        fprintf(stderr, "xdp_guard_bpf__load failed\n");
        xdp_guard_bpf__destroy(skel);
        return 1;
    }

    struct bpf_link **links = calloc(ZK_MAX_PORTS, sizeof(struct bpf_link *));
    if (!links) { xdp_guard_bpf__destroy(skel); return 1; }

    unsigned int attached = sync_all_ports_xdp(skel->progs.zerokull_xdp_guard, links, all_ports, single_idx);
    if (attached == 0) {
        fprintf(stderr, "no active physical interfaces attached\n");
        free(links);
        xdp_guard_bpf__destroy(skel);
        return 1;
    }

    int shm_fd = shm_open(ZK_SHM_NAME, O_CREAT | O_RDWR, 0644);
    volatile struct zk_shm_telemetry *shm = NULL;
    if (shm_fd >= 0) {
        if (flock(shm_fd, LOCK_EX | LOCK_NB) < 0) {
            fprintf(stderr, "zerokull-daemon already running (shm locked)\n");
            close(shm_fd);
            for (unsigned int i = 0; i < ZK_MAX_PORTS; i++) if (links[i]) bpf_link__destroy(links[i]);
            free(links);
            xdp_guard_bpf__destroy(skel);
            return 1;
        }
        if (ftruncate(shm_fd, sizeof(*shm)) == 0) {
            void *p = mmap(NULL, sizeof(*shm), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
            if (p != MAP_FAILED) {
                shm = (volatile struct zk_shm_telemetry *)p;
                shm->version = 1;
                shm->pid = (uint32_t)getpid();
                shm->start_ts = (uint64_t)time(NULL);
                shm->inspected = 0; shm->drops = 0; shm->bans = 0;
                shm->shadow_mode = shadow_mode ? 1U : 0U; shm->_reserved = 0U;
                __sync_synchronize();
                shm->magic = ZK_SHM_MAGIC;
            }
        }
        if (!shm) { close(shm_fd); shm_fd = -1; shm_unlink(ZK_SHM_NAME); }
    }

    int ncpus_raw = libbpf_num_possible_cpus();
    unsigned int ncpus = (ncpus_raw > 0) ? (unsigned int)ncpus_raw : 1U;

    struct app_ctx app;
    zk_engine_init(&app.engine);
    app.shm = shm;
    app.blacklist_fd = bpf_map__fd(skel->maps.blacklist_map);
    app.whitelist_fd = bpf_map__fd(skel->maps.whitelist_map);
    app.stats_fd     = bpf_map__fd(skel->maps.stats_map);
    app.ncpus        = ncpus;
    app.cpu_stats    = calloc(ncpus, sizeof(struct zk_xdp_stats));
    app.shadow_mode  = shadow_mode;

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf_map), handle_event, &app, NULL);
    if (!rb) {
        free(app.cpu_stats);
        if (shm) { shm->pid = 0; munmap((void *)shm, sizeof(*shm)); shm_unlink(ZK_SHM_NAME); }
        if (shm_fd >= 0) close(shm_fd);
        for (unsigned int i = 0; i < ZK_MAX_PORTS; i++) if (links[i]) bpf_link__destroy(links[i]);
        free(links);
        xdp_guard_bpf__destroy(skel);
        return 1;
    }

    printf("[zerokull] active on %s (attached_nics=%u, mode=%s, shm=/dev/shm%s)\n",
           mode_label, attached, shadow_mode ? "SHADOW_DROP(DRY-RUN)" : "BPF_LINK_XDP_ENFORCE", ZK_SHM_NAME);
    fflush(stdout);
    while (!g_stop) {
        if (ring_buffer__poll(rb, 100) < 0 && errno != EINTR) break;
        if (all_ports) (void)sync_all_ports_xdp(skel->progs.zerokull_xdp_guard, links, true, 0);
        sync_telemetry(&app);
    }

    sync_telemetry(&app);
    printf("\n[zerokull] stopped | inspected=%llu drops=%llu bans=%llu\n",
           (unsigned long long)app.engine.total_inspected,
           (unsigned long long)app.engine.total_drops,
           (unsigned long long)app.engine.total_bans);

    ring_buffer__free(rb);
    free(app.cpu_stats);
    if (shm) { shm->pid = 0; munmap((void *)shm, sizeof(*shm)); shm_unlink(ZK_SHM_NAME); }
    if (shm_fd >= 0) close(shm_fd);
    for (unsigned int i = 0; i < ZK_MAX_PORTS; i++) if (links[i]) bpf_link__destroy(links[i]);
    free(links);
    xdp_guard_bpf__destroy(skel);
    return 0;
}
