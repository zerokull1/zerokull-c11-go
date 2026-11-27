// ZEROKULL (zerokull1) | Author Signature: 0x5A45524F4B554C4CULL
// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0.

#ifndef ZK_POLICY_H
#define ZK_POLICY_H

#include <stdbool.h>
#include <stdint.h>

#define ZK_DEFAULT_POLICY_PATH "/etc/zeromani/policy.conf"
#define ZK_POLICY_MAX_IPS      256

struct zk_policy_cfg {
    bool     loaded;
    bool     has_mode;
    bool     shadow_mode;
    int      cpu_affinity;
    uint32_t allow_ips[ZK_POLICY_MAX_IPS];
    uint32_t allow_cnt;
    uint32_t deny_ips[ZK_POLICY_MAX_IPS];
    uint32_t deny_cnt;
};

#ifdef ZK_NO_RUST_POLICY
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
static inline int zk_policy_load(const char *path, struct zk_policy_cfg *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    out->cpu_affinity = -1;
    FILE *f = fopen(path ? path : ZK_DEFAULT_POLICY_PATH, "r");
    if (!f) return -1;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\r' || *p == '\0') continue;
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *val = eq + 1;
        size_t vl = strlen(val);
        while (vl > 0 && (val[vl - 1] == '\n' || val[vl - 1] == '\r' || val[vl - 1] == ' ' || val[vl - 1] == '\t')) val[--vl] = '\0';
        if (strcmp(p, "mode") == 0) {
            out->has_mode = true;
            out->shadow_mode = (strcmp(val, "shadow") == 0);
        } else if (strcmp(p, "cpu_affinity") == 0) {
            out->cpu_affinity = atoi(val);
        } else if (strcmp(p, "allow_ip") == 0 && out->allow_cnt < ZK_POLICY_MAX_IPS) {
            struct in_addr a;
            if (inet_pton(AF_INET, val, &a) == 1) out->allow_ips[out->allow_cnt++] = a.s_addr;
        } else if (strcmp(p, "deny_ip") == 0 && out->deny_cnt < ZK_POLICY_MAX_IPS) {
            struct in_addr a;
            if (inet_pton(AF_INET, val, &a) == 1) out->deny_ips[out->deny_cnt++] = a.s_addr;
        }
    }
    fclose(f);
    out->loaded = true;
    return 0;
}
#include <unistd.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>
static inline void zk_policy_apply_bpf(const struct zk_policy_cfg *prev, const struct zk_policy_cfg *cur,
                                       int whitelist_fd, int blacklist_fd) {
    uint64_t val = 1;
    if (prev) {
        for (uint32_t i = 0; i < prev->allow_cnt; i++) bpf_map_delete_elem(whitelist_fd, &prev->allow_ips[i]);
        for (uint32_t i = 0; i < prev->deny_cnt; i++) bpf_map_delete_elem(blacklist_fd, &prev->deny_ips[i]);
    }
    if (cur) {
        for (uint32_t i = 0; i < cur->allow_cnt; i++) bpf_map_update_elem(whitelist_fd, &cur->allow_ips[i], &val, BPF_ANY);
        for (uint32_t i = 0; i < cur->deny_cnt; i++) bpf_map_update_elem(blacklist_fd, &cur->deny_ips[i], &val, BPF_ANY);
    }
}
extern long syscall(long number, ...);
static inline void zk_policy_apply_affinity(int cpu_id) {
    if (cpu_id < 0 || cpu_id >= 1024) return;
    uint64_t mask[16] = {0};
    mask[(unsigned)cpu_id >> 6] = 1ULL << ((unsigned)cpu_id & 63U);
    (void)syscall(SYS_sched_setaffinity, 0L, (long)sizeof(mask), mask);
}
#else
int  zk_policy_load(const char *path, struct zk_policy_cfg *out);
#endif
void zk_policy_apply_bpf(const struct zk_policy_cfg *prev, const struct zk_policy_cfg *cur,
                         int whitelist_fd, int blacklist_fd);
void zk_policy_apply_affinity(int cpu_id);

#endif
