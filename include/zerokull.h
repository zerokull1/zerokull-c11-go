// ZEROKULL (zerokull1) | Author Signature: 0x5A45524F4B554C4CULL
// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0.

#ifndef ZEROKULL_H
#define ZEROKULL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdalign.h>
#include <stdatomic.h>

#define ZK_MAX_PKT_LEN 1536
#define ZK_FLOW_SLOTS  256
#define ZK_FLOW_MASK   (ZK_FLOW_SLOTS - 1)

enum zk_verdict { ZK_VERDICT_PASS = 0, ZK_VERDICT_DROP = 1, ZK_VERDICT_BAN = 2 };

static inline enum zk_verdict zk_effective_verdict(enum zk_verdict v, bool shadow_mode) {
    return shadow_mode ? ZK_VERDICT_PASS : v;
}

struct zk_pkt_event {
    uint32_t wire_len;
    uint32_t cap_len;
    uint32_t ingress_ifindex;
    uint32_t _pad;
    uint8_t  data[ZK_MAX_PKT_LEN];
};

struct zk_xdp_stats {
    uint64_t rx_packets;
    uint64_t xdp_drops;
    uint64_t ringbuf_sent;
    uint64_t ringbuf_drops;
};

struct zk_flow_slot {
    _Atomic uint32_t lock_state;
    uint32_t flow_hash;
    uint16_t pkt_count;
    uint16_t fsm_flags;
    uint16_t last_l7_len;
    uint16_t same_len_streak;
    uint32_t ema_popcnt;
};

struct zk_engine_ctx {
    alignas(64) struct zk_flow_slot flows[ZK_FLOW_SLOTS];
    alignas(64) _Atomic uint64_t total_inspected;
    _Atomic uint64_t total_drops;
    _Atomic uint64_t total_bans;
};

void zk_engine_init(struct zk_engine_ctx *ctx);
enum zk_verdict zk_inspect_packet(struct zk_engine_ctx *ctx, const uint8_t *pkt, size_t len, uint32_t *out_src_ip_be);

enum zk_verdict zk_exec_millicode(const uint16_t *code, size_t n_insns, const uint8_t *pkt, size_t len, enum zk_verdict base_v);

size_t zk_emit_epoch_jit_x86(uint8_t *dst, size_t cap, uint32_t epoch_id, uint32_t *out_crc);

#define ZK_SHM_NAME "/zerokull_stats"
#define ZK_SHM_MAGIC 0x5A45524F4B554C4CULL

struct zk_shm_telemetry {
    alignas(64) uint64_t magic;
    uint32_t version;
    uint32_t pid;
    uint64_t start_ts;
    uint64_t inspected;
    uint64_t drops;
    uint64_t bans;
    uint32_t shadow_mode;
    uint32_t _reserved;
};


struct __attribute__((aligned(64))) zk_hardware_pulse_anchor {
    uint32_t cpu_sig;
    uint32_t target_batch;
    uint64_t base_pulse_tsc;
    uint64_t current_period_tsc;
    uint64_t last_pulse_tsc;
    uint64_t realign_epochs;
    uint64_t _pad[3];
};

void zk_pulse_calibrate_boot(struct zk_hardware_pulse_anchor *a, uint32_t target_batch);
int  zk_pulse_periodic_realign(struct zk_hardware_pulse_anchor *a, uint32_t arrived_pkts);


struct __attribute__((aligned(64))) zk_meta_norm_slot {
    uint64_t flow_hash;
    uint64_t meta_anchor;
    uint64_t seq_or_ctr;
    uint8_t  state;
    uint8_t  _pad;
};

uint8_t zk_normalize_64b_gate(
    struct zk_meta_norm_slot *slot,
    uint64_t hash,
    uint8_t is_udp,
    uint8_t tcp_flags,
    const uint8_t *l7,
    size_t l7_len
);

#endif

