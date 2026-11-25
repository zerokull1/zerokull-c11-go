// ZEROKULL (zerokull1) | Author Signature: 0x5A45524F4B554C4CULL
// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0.

#define _GNU_SOURCE
#include "zk_policy.h"
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <ctype.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *trim_ws(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)*(s + n - 1))) {
        *(s + n - 1) = '\0';
        n--;
    }
    return s;
}

static bool ip_in_list(uint32_t ip, const uint32_t *arr, uint32_t cnt) {
    for (uint32_t i = 0; i < cnt; i++) {
        if (*(arr + i) == ip) return true;
    }
    return false;
}

int zk_policy_load(const char *path, struct zk_policy_cfg *out) {
    memset(out, 0, sizeof(*out));
    out->cpu_affinity = -1;
    if (!path || !path[0]) return -1;

    FILE *f = fopen(path, "r");
    if (!f) return (errno == ENOENT) ? 0 : -1;

    char line[512];
    while (fgets(line, sizeof(line), f) != NULL) {
        char *p = trim_ws(line);
        if (*p == '\0' || *p == '#' || *p == ';') continue;
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = trim_ws(p);
        char *val = trim_ws(eq + 1);

        if (strcmp(key, "mode") == 0) {
            out->has_mode = true;
            out->shadow_mode = (strcmp(val, "shadow") == 0 || strcmp(val, "dry-run") == 0);
        } else if (strcmp(key, "cpu_affinity") == 0) {
            char *endp = NULL;
            long cpu = strtol(val, &endp, 10);
            if (endp != val && cpu >= 0 && cpu < 1024) out->cpu_affinity = (int)cpu;
        } else if (strcmp(key, "allow_ip") == 0 && out->allow_cnt < ZK_POLICY_MAX_IPS) {
            struct in_addr addr;
            if (inet_pton(AF_INET, val, &addr) == 1 && !ip_in_list(addr.s_addr, out->allow_ips, out->allow_cnt)) {
                *(out->allow_ips + out->allow_cnt) = addr.s_addr;
                out->allow_cnt++;
            }
        } else if (strcmp(key, "deny_ip") == 0 && out->deny_cnt < ZK_POLICY_MAX_IPS) {
            struct in_addr addr;
            if (inet_pton(AF_INET, val, &addr) == 1 && !ip_in_list(addr.s_addr, out->deny_ips, out->deny_cnt)) {
                *(out->deny_ips + out->deny_cnt) = addr.s_addr;
                out->deny_cnt++;
            }
        }
    }
    fclose(f);
    out->loaded = true;
    return 0;
}

void zk_policy_apply_bpf(const struct zk_policy_cfg *prev, const struct zk_policy_cfg *cur,
                         int whitelist_fd, int blacklist_fd) {
    uint8_t one = 1;
    if (prev && prev->loaded) {
        for (uint32_t i = 0; i < prev->allow_cnt; i++) {
            uint32_t ip = *(prev->allow_ips + i);
            if (!ip_in_list(ip, cur->allow_ips, cur->allow_cnt)) bpf_map_delete_elem(whitelist_fd, &ip);
        }
        for (uint32_t i = 0; i < prev->deny_cnt; i++) {
            uint32_t ip = *(prev->deny_ips + i);
            if (!ip_in_list(ip, cur->deny_ips, cur->deny_cnt)) bpf_map_delete_elem(blacklist_fd, &ip);
        }
    }
    for (uint32_t i = 0; i < cur->allow_cnt; i++) {
        uint32_t ip = *(cur->allow_ips + i);
        bpf_map_update_elem(whitelist_fd, &ip, &one, BPF_ANY);
        bpf_map_delete_elem(blacklist_fd, &ip);
    }
    for (uint32_t i = 0; i < cur->deny_cnt; i++) {
        uint32_t ip = *(cur->deny_ips + i);
        bpf_map_update_elem(blacklist_fd, &ip, &one, BPF_ANY);
        bpf_map_delete_elem(whitelist_fd, &ip);
    }
}

void zk_policy_apply_affinity(int cpu_id) {
    if (cpu_id < 0 || cpu_id >= CPU_SETSIZE) return;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu_id, &set);
    (void)sched_setaffinity(0, sizeof(set), &set);
}
