// ZEROMANI (zerokull1) | Author Signature: 0x5A45524F4D414E49ULL
#ifndef ZK_L1_MASTER_ORCHESTRATOR_H
#define ZK_L1_MASTER_ORCHESTRATOR_H

#include <stdint.h>
#include <stddef.h>

enum {
    ZK_CTRL_L7_QUARANTINE    = (1ULL << 0),
    ZK_CTRL_XDP_DROP         = (1ULL << 1),
    ZK_CTRL_GPU_OFFLOAD      = (1ULL << 2),
    ZK_CTRL_WX_TRAP_ARMED    = (1ULL << 3),
    ZK_CTRL_MUTAGEN_VAPORIZE = (1ULL << 4),
    ZK_CTRL_WAN_BATON_ALT    = (1ULL << 5),
    ZK_CTRL_STAGE0_SHED      = (1ULL << 6)
};

typedef struct __attribute__((aligned(64))) {
    int8_t   weights[32];
    int32_t  threshold;
    int32_t  baseline_ema;
    uint32_t jitter_ema;
    uint64_t last_tsc;
    uint32_t discovered_modules;
    uint64_t control_bus;
    uint64_t generation;
    uint64_t learned_attacks;
    uint64_t learned_clean;
    uint64_t baton_switches;
    uint64_t _pad[20];
} zk_l1_agent_t;

static inline uint64_t zk_l1_read_cycles(void) {
#if defined(__x86_64__)
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__)
    uint64_t cnt;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(cnt));
    return cnt;
#else
    return 0;
#endif
}

static inline void zk_l1_init(zk_l1_agent_t *mem, uint32_t hw_mmio_mask) {
    if (!mem) return;
    for (size_t i = 0; i < 32; i++) mem->weights[i] = 4;
    mem->threshold = 2400;
    mem->baseline_ema = 800;
    mem->jitter_ema = 64;
    mem->last_tsc = 0;
    uint32_t caps = 0x2u | 0x8u;
#if defined(__AVX2__) || defined(__ARM_NEON)
    caps |= 0x1u;
#endif
    if (hw_mmio_mask != 0) caps |= 0x4u;
    mem->discovered_modules = caps;
    mem->control_bus = ZK_CTRL_STAGE0_SHED | ZK_CTRL_WX_TRAP_ARMED;
    mem->generation = 0;
    mem->learned_attacks = 0;
    mem->learned_clean = 0;
    mem->baton_switches = 0;
    for (size_t i = 0; i < 20; i++) mem->_pad[i] = 0;
}

static inline uint64_t zk_l1_orchestrate(
    zk_l1_agent_t *mem,
    const uint8_t *features32,
    uint32_t l7_threat_mask,
    uint32_t xdp_verdict,
    size_t batch_bytes
) {
    if (!mem || !features32) return 0;
    if ((mem->control_bus & ZK_CTRL_STAGE0_SHED) == 0) {
        zk_l1_init(mem, 0x1u);
    }

    uint64_t now = zk_l1_read_cycles();
    uint32_t delta = (mem->last_tsc != 0) ? (uint32_t)(now - mem->last_tsc) : mem->jitter_ema;
    mem->last_tsc = now;
    int timing_spike = (delta > (mem->jitter_ema * 8u + 2048u));
    uint32_t clamped = (delta > 65535u) ? 65535u : delta;
    mem->jitter_ema = ((mem->jitter_ema * 7u) + clamped) >> 3;

    int32_t teacher = ((l7_threat_mask | xdp_verdict) != 0) ? 1 : 0;
    int32_t score = 0;
    for (size_t i = 0; i < 32; i++) {
        uint8_t xi = features32[i];
        int8_t wi = mem->weights[i];
        score += (int32_t)xi * (int32_t)wi;
        if (teacher > 0 && xi > 16 && wi < 6) {
            mem->weights[i] = (int8_t)(wi + 1);
        }
    }

    uint32_t fired = (score >= mem->threshold) ? 1u : 0u;
    if (fired == 0 && teacher == 0) {
        mem->baseline_ema = ((mem->baseline_ema * 15) + score) >> 4;
        int32_t adap = mem->baseline_ema * 2;
        if (adap < 1600) adap = 1600;
        if (adap > 6000) adap = 6000;
        mem->threshold = ((mem->threshold * 7) + adap) >> 3;
    }

    uint64_t bus = ZK_CTRL_STAGE0_SHED | ZK_CTRL_WX_TRAP_ARMED | (mem->control_bus & ZK_CTRL_WAN_BATON_ALT);
    if (timing_spike) {
        bus ^= ZK_CTRL_WAN_BATON_ALT;
        mem->baton_switches++;
    }
    if (fired != 0 || teacher > 0) {
        bus |= ZK_CTRL_L7_QUARANTINE | ZK_CTRL_XDP_DROP | ZK_CTRL_MUTAGEN_VAPORIZE;
        mem->learned_attacks++;
    } else {
        if (batch_bytes >= 4096 && (mem->discovered_modules & 0x4u) != 0) {
            bus |= ZK_CTRL_GPU_OFFLOAD;
        }
        mem->learned_clean++;
    }

    mem->generation++;
    mem->control_bus = bus;
    return bus;
}

#endif
