// ZEROKULL (zerokull1) | Author Signature: 0x5A45524F4B554C4CULL
// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0.

#include "zerokull.h"
#include <string.h>

static inline uint16_t rd_be16(const uint8_t *p) { return (uint16_t)(((uint16_t)(*(p + 0)) << 8) | *(p + 1)); }
static inline uint32_t rd_be32(const uint8_t *p) {
    return ((uint32_t)(*(p + 0)) << 24) | ((uint32_t)(*(p + 1)) << 16) | ((uint32_t)(*(p + 2)) << 8) | (uint32_t)(*(p + 3));
}
static inline uint64_t rd_le64(const uint8_t *p) { uint64_t v = 0; memcpy(&v, p, sizeof(v)); return v; }

static inline uint32_t zk_crc32c_u32(uint32_t crc, uint32_t v) {
#if defined(__x86_64__) && defined(__SSE4_2__)
    return __builtin_ia32_crc32si(crc, v);
#else
    crc ^= v;
    for (int i = 0; i < 32; i++) crc = (crc >> 1) ^ (0x82F63B78U & (uint32_t)(-(int32_t)(crc & 1U)));
    return crc;
#endif
}

void zk_engine_init(struct zk_engine_ctx *ctx) {
    if (!ctx) return;
    memset(ctx, 0, sizeof(*ctx));
    for (size_t i = 0; i < ZK_FLOW_SLOTS; i++) ctx->flows[i].ema_popcnt = 64;
}

static inline enum zk_verdict inspect_l3_guard(const uint8_t *ip, size_t ip_avail) {
    if (ip_avail < 20 || (*(ip + 0)) != 0x45U) return ZK_VERDICT_DROP;
    if ((rd_be16(ip + 6) & 0x3FFFU) != 0) return ZK_VERDICT_DROP;
    uint8_t ttl = *(ip + 8);
    if (ttl == 0 || ttl == 65 || ttl == 129) return ZK_VERDICT_DROP;
    return ZK_VERDICT_PASS;
}

static inline enum zk_verdict inspect_l7_payload(uint8_t proto, uint16_t dport, const uint8_t *l7, size_t l7_len) {
    if (!l7 || l7_len == 0) return ZK_VERDICT_PASS;
    if (dport == 445 && l7_len >= 4) {
        if (*(l7 + 0) == 0xFF && *(l7 + 1) == 'S' && *(l7 + 2) == 'M' && *(l7 + 3) == 'B') return ZK_VERDICT_BAN;
        if (!(*(l7 + 0) == 0xFE && *(l7 + 1) == 'S' && *(l7 + 2) == 'M' && *(l7 + 3) == 'B') && *(l7 + 0) != 0x00) return ZK_VERDICT_DROP;
    }
    if (proto == 6 && (dport == 102 || dport == 502 || dport == 2404) && l7_len < 6) return ZK_VERDICT_DROP;
    if (proto == 6 && l7_len >= 5 && *(l7 + 0) == 0x16) {
        uint16_t ver = rd_be16(l7 + 1);
        uint16_t rec_len = rd_be16(l7 + 3);
        if (ver >= 0x0300 && ver <= 0x0304) {
            if (ver < 0x0301 || rec_len < 40U) return ZK_VERDICT_DROP;
        } else if (dport == 443 || dport == 8443 || dport == 853 || dport == 465 || dport == 993) {
            return ZK_VERDICT_DROP;
        }
    }
    if (proto == 6 && (dport == 80 || dport == 8080) && l7_len >= 13 && *(l7 + 3) == 0x08) {
        uint32_t f_len = (rd_be32(l7) >> 8) & 0x00FFFFFFU;
        uint32_t win_inc = rd_be32(l7 + 9) & 0x7FFFFFFFU;
        if (f_len == 4U && (win_inc == 0U || win_inc >= 0x40000000U)) return ZK_VERDICT_BAN;
    }
    if (proto == 6 && l7_len >= 12) {
        uint32_t m0 = 0;
        memcpy(&m0, l7, sizeof(m0));
        uint32_t is_http = (uint32_t)(m0 == 0x20544547U) | (uint32_t)(m0 == 0x54534F50U) |
                           (uint32_t)(m0 == 0x44414548U) | (uint32_t)(m0 == 0x20545550U);
        if (is_http != 0U) {
            size_t end = (l7_len - 4U < 96U) ? (l7_len - 4U) : 96U;
            uint32_t bad = 0U;
            for (size_t off = 4U; off <= end; off++) {
                uint32_t w = 0;
                memcpy(&w, l7 + off, sizeof(w));
                uint8_t b0 = (uint8_t)(w & 0xFFU);
                if (b0 == 0x0DU || b0 == 0x0AU) break;
                uint32_t hit_semi = (uint32_t)(w == 0x2F3B2E2EU);
                uint32_t hit_slash = (uint32_t)((w & 0x00FFFFFFU) == 0x002F2E2EU);
                uint32_t hit_nul = (uint32_t)(((w - 0x01010101U) & ~w & 0x80808080U) != 0U);
                bad |= hit_semi | hit_slash | hit_nul;
            }
            if (bad != 0U) return ZK_VERDICT_BAN;
        }
    }
    return ZK_VERDICT_PASS;
}

static inline enum zk_verdict inspect_stateful_drift(struct zk_engine_ctx *ctx, uint32_t src_ip, uint32_t dst_ip,
                                                   uint32_t ports_word, uint8_t tcp_flags, const uint8_t *l7, size_t l7_len) {
    uint32_t ip_lo = (src_ip < dst_ip) ? src_ip : dst_ip;
    uint32_t ip_hi = (src_ip < dst_ip) ? dst_ip : src_ip;
    uint32_t p_swapped = (ports_word >> 16) | (ports_word << 16);
    uint32_t p_canon = (ports_word < p_swapped) ? ports_word : p_swapped;
    uint32_t h1 = zk_crc32c_u32(0x5A45524FU, ip_lo);
    uint32_t h2 = zk_crc32c_u32(h1, ip_hi);
    uint32_t fid = zk_crc32c_u32(h2, p_canon);
    if (fid == 0) fid = 1U;
    struct zk_flow_slot *slot = &ctx->flows[fid & ZK_FLOW_MASK];

    if ((tcp_flags & 0x05U) != 0) {
        if (slot->flow_hash == fid) {
            memset(slot, 0, sizeof(*slot));
            slot->ema_popcnt = 64;
        }
        return ZK_VERDICT_PASS;
    }

    bool is_syn = (tcp_flags & 0x02U) != 0;
    bool is_ack = (tcp_flags & 0x10U) != 0;
    bool is_tls = (l7 && l7_len >= 5 && *(l7 + 0) == 0x16);
    uint16_t step_flags = (is_syn ? 1U : 0U) | (is_tls ? 2U : 0U) | ((l7_len >= 16) ? 4U : 0U) | ((!is_syn && is_ack && l7_len == 0) ? 8U : 0U);

    if (slot->flow_hash != fid && slot->flow_hash != 0 && slot->pkt_count >= 8U) return ZK_VERDICT_PASS;
    if (slot->flow_hash != fid || (is_syn && !is_ack)) {
        slot->flow_hash = fid;
        slot->pkt_count = 1;
        slot->fsm_flags = step_flags;
        slot->last_l7_len = (uint16_t)(l7_len > 0xFFFF ? 0xFFFF : l7_len);
        slot->same_len_streak = 0;
        if (l7 && l7_len >= 16) {
            slot->ema_popcnt = (uint32_t)(__builtin_popcountll(rd_le64(l7)) + __builtin_popcountll(rd_le64(l7 + 8)));
        } else {
            slot->ema_popcnt = 64;
        }
        return ZK_VERDICT_PASS;
    }

    if (slot->pkt_count < 0xFFFFU) slot->pkt_count++;
    slot->fsm_flags |= step_flags;

    if ((slot->fsm_flags & 4U) != 0 && (slot->fsm_flags & 11U) == 0 && slot->pkt_count >= 4) return ZK_VERDICT_DROP;

    if (l7 && l7_len >= 16) {
        uint16_t cur_len = (uint16_t)(l7_len > 0xFFFF ? 0xFFFF : l7_len);
        if (slot->last_l7_len == cur_len) {
            if (slot->same_len_streak < 0xFFFFU) slot->same_len_streak++;
        } else {
            slot->last_l7_len = cur_len;
            slot->same_len_streak = 0;
        }
        uint32_t bits = (uint32_t)(__builtin_popcountll(rd_le64(l7)) + __builtin_popcountll(rd_le64(l7 + 8)));
        slot->ema_popcnt = (slot->ema_popcnt * 3U + bits) >> 2;
        if ((slot->fsm_flags & 2U) == 0 && slot->pkt_count >= 12 && slot->same_len_streak >= 16 && slot->ema_popcnt >= 56 && slot->ema_popcnt <= 72) {
            memset(slot, 0, sizeof(*slot));
            slot->ema_popcnt = 64;
            return ZK_VERDICT_BAN;
        }
    }
    return ZK_VERDICT_PASS;
}

enum zk_verdict zk_inspect_packet(struct zk_engine_ctx *ctx, const uint8_t *pkt, size_t len, uint32_t *out_src_ip_be) {
    if (!ctx || !pkt || len < 34) return ZK_VERDICT_PASS;
    size_t l3_off = 14;
    uint16_t eth_proto = rd_be16(pkt + 12);
    for (int i = 0; i < 2 && (eth_proto == 0x8100 || eth_proto == 0x88A8); i++) {
        if (len < l3_off + 24) return ZK_VERDICT_PASS;
        eth_proto = rd_be16(pkt + l3_off + 2);
        l3_off += 4;
    }
    if (eth_proto != 0x0800) return ZK_VERDICT_PASS;

    const uint8_t *ip = pkt + l3_off;
    size_t ip_avail = len - l3_off;
    if (ip_avail < 20) { ctx->total_inspected++; ctx->total_drops++; return ZK_VERDICT_DROP; }
    uint16_t ip_tot = rd_be16(ip + 2);
    if (ip_tot < 20 || (size_t)ip_tot > ip_avail) { ctx->total_inspected++; ctx->total_drops++; return ZK_VERDICT_DROP; }
    ip_avail = (size_t)ip_tot;
    uint32_t src_ip = 0, dst_ip = 0;
    memcpy(&src_ip, ip + 12, sizeof(src_ip));
    memcpy(&dst_ip, ip + 16, sizeof(dst_ip));
    if (out_src_ip_be) *out_src_ip_be = src_ip;

    enum zk_verdict v = inspect_l3_guard(ip, ip_avail);
    if (v != ZK_VERDICT_PASS) { ctx->total_inspected++; ctx->total_drops++; return v; }

    uint8_t proto = *(ip + 9);
    const uint8_t *l4 = ip + 20;
    size_t l4_avail = ip_avail - 20;
    uint16_t dport = 0; uint8_t tcp_flags = 0; const uint8_t *l7 = NULL; size_t l7_len = 0; uint32_t ports_word = 0;

    if (proto == 6) {
        if (l4_avail < 20) { ctx->total_inspected++; ctx->total_drops++; return ZK_VERDICT_DROP; }
        uint8_t doff = (uint8_t)(((*(l4 + 12)) >> 4) * 4U);
        if (doff < 20 || l4_avail < doff) { ctx->total_inspected++; ctx->total_drops++; return ZK_VERDICT_DROP; }
        memcpy(&ports_word, l4, sizeof(ports_word));
        dport = rd_be16(l4 + 2); tcp_flags = *(l4 + 13); l7 = l4 + doff; l7_len = l4_avail - doff;
        if (tcp_flags == 0x00U || tcp_flags == 0x01U || (tcp_flags & 0x03U) == 0x03U || (tcp_flags & 0x29U) == 0x29U) { ctx->total_inspected++; ctx->total_drops++; return ZK_VERDICT_DROP; }
    } else if (proto == 17) {
        if (l4_avail < 8) { ctx->total_inspected++; ctx->total_drops++; return ZK_VERDICT_DROP; }
        memcpy(&ports_word, l4, sizeof(ports_word));
        dport = rd_be16(l4 + 2); l7 = l4 + 8; l7_len = l4_avail - 8;
    }
    ctx->total_inspected++;
    v = inspect_l7_payload(proto, dport, l7, l7_len);
    if (v == ZK_VERDICT_PASS && proto == 6) v = inspect_stateful_drift(ctx, src_ip, dst_ip, ports_word, tcp_flags, l7, l7_len);
    if (v == ZK_VERDICT_DROP) ctx->total_drops++;
    else if (v == ZK_VERDICT_BAN) { ctx->total_drops++; ctx->total_bans++; }
    return v;
}

enum zk_verdict zk_exec_millicode(const uint16_t *code, size_t n_insns, const uint8_t *pkt, size_t len, enum zk_verdict base_v) {
    if (!code || n_insns == 0) return base_v;
    uint32_t r[8] = {0};
    r[0] = (uint32_t)base_v;
    r[1] = (uint32_t)(len > 0xFFFFU ? 0xFFFFU : len);
    size_t steps = n_insns > 32U ? 32U : n_insns;
    for (size_t pc = 0; pc < steps; pc++) {
        uint16_t ins = code[pc];
        uint8_t op  = (uint8_t)(ins >> 12);
        uint8_t dst = (uint8_t)((ins >> 9) & 0x07U);
        uint8_t src = (uint8_t)((ins >> 6) & 0x07U);
        uint8_t imm = (uint8_t)(ins & 0xFFU);
        switch (op) {
            case 0x1: r[dst] = imm; break;
            case 0x2: r[dst] ^= r[src]; break;
            case 0x3: r[dst] = (pkt && (size_t)imm < len) ? (uint32_t)pkt[imm] : 0U; break;
            case 0x4: r[0] = (r[dst] == r[src]) ? (uint32_t)ZK_VERDICT_BAN : r[0]; break;
            case 0x5: r[0] = (r[dst] < (uint32_t)imm) ? (uint32_t)ZK_VERDICT_DROP : r[0]; break;
            case 0xF: pc = steps; break;
            default: break;
        }
    }
    return (r[0] <= (uint32_t)ZK_VERDICT_BAN) ? (enum zk_verdict)r[0] : ZK_VERDICT_DROP;
}
