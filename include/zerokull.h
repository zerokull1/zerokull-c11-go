#ifndef ZEROKULL_H
#define ZEROKULL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define ZK_MAX_PKT_LEN 1536
#define ZK_FLOW_SLOTS  256
#define ZK_FLOW_MASK   (ZK_FLOW_SLOTS - 1)

enum zk_verdict { ZK_VERDICT_PASS = 0, ZK_VERDICT_DROP = 1, ZK_VERDICT_BAN = 2 };

struct zk_pkt_event {
    uint32_t wire_len;
    uint32_t cap_len;
    uint8_t  data[ZK_MAX_PKT_LEN];
};

struct zk_flow_slot {
    uint32_t flow_hash;
    uint16_t pkt_count;
    uint16_t fsm_flags;
    uint16_t last_l7_len;
    uint16_t same_len_streak;
    uint32_t ema_popcnt;
};

struct zk_engine_ctx {
    struct zk_flow_slot flows[ZK_FLOW_SLOTS];
    uint64_t total_inspected;
    uint64_t total_drops;
    uint64_t total_bans;
};

void zk_engine_init(struct zk_engine_ctx *ctx);
enum zk_verdict zk_inspect_packet(struct zk_engine_ctx *ctx, const uint8_t *pkt, size_t len, uint32_t *out_src_ip_be);

#endif

/* Снапшот телеметрии реального времени в /dev/shm/zerokull_stats */
#define ZK_SHM_NAME "/zerokull_stats"
#define ZK_SHM_MAGIC 0x5A45524F4B554C4CULL

struct zk_shm_telemetry {
    uint64_t magic;
    uint32_t version;
    uint32_t pid;
    uint64_t start_ts;
    uint64_t inspected;
    uint64_t drops;
    uint64_t bans;
};
