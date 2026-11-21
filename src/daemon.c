#include "zerokull.h"
#include "xdp_guard.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;

struct app_ctx {
    struct zk_engine_ctx engine;
    int blacklist_fd;
};

static void on_signal(int sig) { (void)sig; g_stop = 1; }

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct app_ctx *app = (struct app_ctx *)ctx;
    const struct zk_pkt_event *ev = (const struct zk_pkt_event *)data;
    if (data_sz < offsetof(struct zk_pkt_event, data) || ev->cap_len > ZK_MAX_PKT_LEN) return 0;

    uint32_t src_ip = 0;
    if (zk_inspect_packet(&app->engine, ev->data, ev->cap_len, &src_ip) == ZK_VERDICT_BAN && src_ip != 0) {
        uint8_t one = 1;
        bpf_map_update_elem(app->blacklist_fd, &src_ip, &one, BPF_ANY);
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *ifname = (argc > 1) ? *(argv + 1) : "enp0s20u11";
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) { perror("if_nametoindex"); return 1; }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    struct xdp_guard_bpf *skel = xdp_guard_bpf__open_and_load();
    if (!skel) { fprintf(stderr, "open_and_load failed\n"); return 1; }

    __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
    if (bpf_xdp_attach((int)ifindex, bpf_program__fd(skel->progs.zerokull_xdp_guard), xdp_flags, NULL) < 0) {
        perror("bpf_xdp_attach");
        xdp_guard_bpf__destroy(skel);
        return 1;
    }

    struct app_ctx app;
    zk_engine_init(&app.engine);
    app.blacklist_fd = bpf_map__fd(skel->maps.blacklist_map);

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf_map), handle_event, &app, NULL);
    if (!rb) {
        bpf_xdp_detach((int)ifindex, xdp_flags, NULL);
        xdp_guard_bpf__destroy(skel);
        return 1;
    }

    printf("[zerokull] active on %s (ifindex=%u)\n", ifname, ifindex);
    fflush(stdout);
    while (!g_stop) {
        if (ring_buffer__poll(rb, 100) < 0 && errno != EINTR) break;
    }

    printf("[zerokull] stopped: inspected=%llu drops=%llu bans=%llu\n",
           (unsigned long long)app.engine.total_inspected,
           (unsigned long long)app.engine.total_drops,
           (unsigned long long)app.engine.total_bans);
    ring_buffer__free(rb);
    bpf_xdp_detach((int)ifindex, xdp_flags, NULL);
    xdp_guard_bpf__destroy(skel);
    return 0;
}
