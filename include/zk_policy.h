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

int  zk_policy_load(const char *path, struct zk_policy_cfg *out);
void zk_policy_apply_bpf(const struct zk_policy_cfg *prev, const struct zk_policy_cfg *cur,
                         int whitelist_fd, int blacklist_fd);
void zk_policy_apply_affinity(int cpu_id);

#endif
