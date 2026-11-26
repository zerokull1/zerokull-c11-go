// ZEROKULL (zerokull1) | Author Signature: 0x5A45524F4B554C4CULL
#ifndef ZK_GPU_RING_H
#define ZK_GPU_RING_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__x86_64__)
#define ZK_SFENCE() __asm__ __volatile__("sfence" ::: "memory")
#define ZK_PAUSE()  __builtin_ia32_pause()
#elif defined(__aarch64__)
#define ZK_SFENCE() __asm__ __volatile__("dmb ishst" ::: "memory")
#define ZK_PAUSE()  __asm__ __volatile__("yield" ::: "memory")
#else
#define ZK_SFENCE() __sync_synchronize()
#define ZK_PAUSE()  do {} while (0)
#endif

typedef enum {
    ZK_ACCEL_CPU_SWAR     = 0,
    ZK_ACCEL_GENERIC_GPU  = 1,
    ZK_ACCEL_DIRECT_RING  = 2
} ZkAccelMode;

typedef struct {
    ZkAccelMode mode;
    uint32_t vendor_id;
    uint32_t ndesc;
    uint32_t cur_put;
    uint32_t ring_mask;
    uint64_t *ring_ptr;
    const volatile uint32_t *get_ptr;
    volatile uint32_t *put_ptr;
    uint64_t desc[64];
    char device_name[128];
} ZkGpuRingCtx;

static inline uint32_t zk_swar_batch_entropy_score(const uint8_t *buf, size_t len) {
    if (!buf || len == 0) return 0;
    uint64_t acc = 0x9E3779B97F4A7C15ULL;
    size_t i = 0;
    for (; i + 8 <= len; i += 8) {
        uint64_t w = 0;
        memcpy(&w, buf + i, 8);
        acc ^= w;
        acc *= 0xBF58476D1CE4E5B9ULL;
        acc ^= acc >> 31;
    }
    for (; i < len; i++) {
        acc ^= (uint64_t)buf[i] << ((i & 7u) * 8u);
        acc *= 0x94D049BB133111EBULL;
    }
    return (uint32_t)(acc ^ (acc >> 32));
}

static inline void zk_gpu_ring_init(ZkGpuRingCtx *ctx) {
    if (!ctx) return;
    memset(ctx, 0, sizeof(*ctx));
    ctx->mode = ZK_ACCEL_CPU_SWAR;
    memcpy(ctx->device_name, "Universal-SWAR-CPU", 19);
}

static inline int zk_gpu_ring_submit_pipelined(ZkGpuRingCtx *ctx, uint32_t win_slots) {
    if (!ctx) return -1;
    if (ctx->mode == ZK_ACCEL_DIRECT_RING && ctx->ring_ptr && ctx->put_ptr && ctx->get_ptr && ctx->ndesc > 0) {
        uint32_t put = ctx->cur_put;
        uint32_t mask = ctx->ring_mask;
        uint32_t limit = (win_slots > 0 ? win_slots : 4u) * ctx->ndesc;
        uint64_t spin = 0;
        while (((put - *ctx->get_ptr) & mask) >= limit && spin++ < 50000000ULL) {
            ZK_PAUSE();
        }
        for (uint32_t d = 0; d < ctx->ndesc; d++) {
            ctx->ring_ptr[(put + d) & mask] = ctx->desc[d];
        }
        put = (put + ctx->ndesc) & mask;
        ctx->cur_put = put;
        ZK_SFENCE();
        *ctx->put_ptr = put;
        return 0;
    }
    return 0;
}

static inline int zk_gpu_ring_sync_drain(ZkGpuRingCtx *ctx) {
    if (!ctx) return -1;
    if (ctx->mode == ZK_ACCEL_DIRECT_RING && ctx->get_ptr) {
        ZK_SFENCE();
        uint64_t spin = 0;
        while (*ctx->get_ptr != ctx->cur_put && spin++ < 50000000ULL) {
            ZK_PAUSE();
        }
        return (*ctx->get_ptr == ctx->cur_put) ? 0 : -2;
    }
    return 0;
}

static inline int zk_gpu_ring_submit_batch(ZkGpuRingCtx *ctx) {
    int rc = zk_gpu_ring_submit_pipelined(ctx, 1u);
    return (rc == 0) ? zk_gpu_ring_sync_drain(ctx) : rc;
}

#endif
