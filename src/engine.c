// ZEROKULL (zerokull1) | Author Signature: 0x5A45524F4B554C4CULL
// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0.

#include "zerokull.h"
#include <string.h>

static inline uint16_t rd_be16(const uint8_t *p) { return (uint16_t)(((uint16_t)(*(p + 0)) << 8) | *(p + 1)); }
static inline uint32_t rd_be32(const uint8_t *p) {
    return ((uint32_t)(*(p + 0)) << 24) | ((uint32_t)(*(p + 1)) << 16) | ((uint32_t)(*(p + 2)) << 8) | (uint32_t)(*(p + 3));
}
static inline uint32_t rd_le32(const uint8_t *p) {
    uint32_t v = 0; memcpy(&v, p, sizeof(v));
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    v = __builtin_bswap32(v);
#endif
    return v;
}
static inline uint64_t rd_le64(const uint8_t *p) {
    uint64_t v = 0; memcpy(&v, p, sizeof(v));
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    v = __builtin_bswap64(v);
#endif
    return v;
}

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


static inline uint32_t zk_inspect_php_proto_vector_swar(const uint8_t *buf, size_t len) {
    if (len < 6U) return 0U;
    size_t scan_lim = (len > 1024U) ? 1024U : len;
    uint32_t hit = 0U;
    for (size_t i = 0U; i + 4U <= scan_lim; i++) {
        uint32_t w = rd_le32(buf + i);
        uint8_t b0 = (uint8_t)(w & 0xFFU) & 0xDFU;
        uint8_t b1 = (uint8_t)((w >> 8) & 0xFFU);
        uint8_t b2 = (uint8_t)((w >> 16) & 0xFFU);
        hit |= (uint32_t)(((b0 == 'O') | (b0 == 'C')) & (b1 == ':') & ((uint8_t)(b2 - '0') <= 9U));
        uint32_t wu = w & 0xDFDFDFFFU;
        hit |= (uint32_t)((wu == 0x4133254FU) | (wu == 0x41332543U));
        uint32_t wl = w | 0x20202020U;
        if (__builtin_expect(wl == 0x736E692FU && i + 12U <= scan_lim, 0)) {
            hit |= (uint32_t)((rd_le64(buf + i + 4U) | 0x2020200020202020ULL) == 0x7068702E6C6C6174ULL);
        }
        if (__builtin_expect(wl == 0x6470752FU && i + 11U <= scan_lim, 0)) {
            uint64_t tail = 0ULL;
            memcpy(&tail, buf + i + 4U, 7U);
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
            tail = __builtin_bswap64(tail);
#endif
            hit |= (uint32_t)((tail | 0x0020202000202020ULL) == 0x007068702E657461ULL);
        }
        if (__builtin_expect(wl == 0x72616870U && i + 7U <= scan_lim, 0)) {
            hit |= (uint32_t)((*(buf + i + 4U) == ':') & (*(buf + i + 5U) == '/') & (*(buf + i + 6U) == '/'));
        }
    }
    return hit;
}

static inline enum zk_verdict inspect_l7_payload(uint8_t proto, uint16_t dport, const uint8_t *l7, size_t l7_len) {
    if (!l7 || l7_len == 0) return ZK_VERDICT_PASS;
    if (dport == 135U || (dport >= 137U && dport <= 139U) || dport == 445U || dport == 3389U || dport == 5355U || dport == 5985U || dport == 5986U) {
        return ZK_VERDICT_BAN;
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
    if (proto == 6 && l7_len >= 5 && *(l7 + 0) == 0x17) {
        uint16_t ver = rd_be16(l7 + 1);
        uint16_t rec_len = rd_be16(l7 + 3);
        if (ver == 0x0303 && rec_len < 16U) return ZK_VERDICT_DROP;
    }
    if (proto == 6 && (dport == 80 || dport == 8080) && l7_len >= 13) {
        uint32_t f_len = (rd_be32(l7) >> 8) & 0x00FFFFFFU;
        uint8_t f_type = *(l7 + 3);
        if (f_type == 0x08U) {
            uint32_t win_inc = rd_be32(l7 + 9) & 0x7FFFFFFFU;
            if (f_len == 4U && (win_inc == 0U || win_inc >= 0x40000000U)) return ZK_VERDICT_BAN;
        } else if (f_type == 0x01U && (size_t)f_len + 18U <= l7_len) {
            const uint8_t *f2 = l7 + 9U + (size_t)f_len;
            uint32_t f2_len = (rd_be32(f2) >> 8) & 0x00FFFFFFU;
            if (*(f2 + 3) == 0x03U && f2_len == 4U) return ZK_VERDICT_BAN;
            if ((*(l7 + 4) & 0x04U) == 0U && *(f2 + 3) == 0x09U && (*(f2 + 4) & 0x04U) == 0U) return ZK_VERDICT_BAN;
        }
    }
    if (proto == 17 && dport == 53 && l7_len >= 14U) {
        uint8_t q_lbl = *(l7 + 12);
        if (q_lbl >= 48U && q_lbl <= 63U) return ZK_VERDICT_BAN;
    }
    if (proto == 17 && (dport == 443 || dport == 8443)) return ZK_VERDICT_DROP;
    if (proto == 6 && zk_inspect_php_proto_vector_swar(l7, l7_len)) return ZK_VERDICT_BAN;
    if (proto == 6 && l7_len >= 12) {
        size_t uri_start = 0U;
        for (size_t m = 0U; m < 10U && m + 1U < l7_len; m++) {
            uint8_t c = *(l7 + m);
            if (c == 0x20U && m >= 3U) { uri_start = m + 1U; break; }
            uint8_t cu = c & 0xDFU;
            if (cu < 'A' || cu > 'Z') break;
        }
        if (uri_start != 0U) {
            if (uri_start == 8U && (rd_le64(l7) & 0x00DFDFDFDFDFDFDFULL) == 0x005443454E4E4F43ULL) return ZK_VERDICT_BAN;
            size_t end = (l7_len - 4U < 512U) ? (l7_len - 4U) : 512U;
            uint32_t bad = 0U;
            for (size_t off = uri_start; off <= end; off++) {
                uint32_t w = rd_le32(l7 + off);
                uint8_t b0 = (uint8_t)(w & 0xFFU);
                if (b0 == 0x0DU || b0 == 0x0AU) break;
                uint32_t hit_semi = (uint32_t)(w == 0x2F3B2E2EU);
                uint32_t hit_slash = (uint32_t)((w & 0x00FFFFFFU) == 0x002F2E2EU);
                uint32_t hit_dbl_slash = (uint32_t)((w & 0xFFFFU) == 0x2F2FU || (w & 0xFFU) == 0x5CU);
                uint32_t w_lo = w | 0x00202000U;
                uint32_t hit_pct = (uint32_t)((w_lo & 0x00FFFFFFU) == 0x00653225U || (w_lo & 0x00FFFFFFU) == 0x00663225U ||
                                              (w_lo & 0x00FFFFFFU) == 0x00633525U || (w_lo & 0x00FFFFFFU) == 0x00303025U);
                uint32_t hit_nul = (uint32_t)(((w - 0x01010101U) & ~w & 0x80808080U) != 0U);
                bad |= hit_semi | hit_slash | hit_dbl_slash | hit_pct | hit_nul;
            }
            if (bad != 0U) return ZK_VERDICT_BAN;
            if (l7_len > 20U) {
                size_t scan_lim = (l7_len - 18U < 1024U) ? (l7_len - 18U) : 1024U;
                uint32_t has_cl = 0U, has_te = 0U, has_upg = 0U;
                for (size_t h = uri_start; h <= scan_lim; h++) {
                    if (*(l7 + h - 1U) != 0x0AU) continue;
                    if (*(l7 + h) == 0x0DU || *(l7 + h) == 0x0AU) break;
                    uint64_t hw = rd_le64(l7 + h), hw2 = rd_le64(l7 + h + 8U);
                    uint64_t hw_up = hw & 0xDFDFDFDFDFDFDFDFULL;
                    if (hw_up == 0x0D544E45544E4F43ULL && (hw2 & 0x0000DFDFDFDFDFDFULL) == 0x00004854474E454CULL && *(l7 + h + 14U) == ':') has_cl++;
                    if (hw_up == 0x524546534E415254ULL && (hw2 & 0xDFDFDFDFDFDFDFDFULL) == 0x4E49444F434E450DULL && (*(l7 + h + 16U) & 0xDFU) == 'G' && *(l7 + h + 17U) == ':') has_te++;
                    if ((hw_up & 0x00FFFFFFFFFFFFFFULL) == 0x0045444152475055ULL && *(l7 + h + 7U) == ':') has_upg++;
                    if ((hw_up & 0x00000000FFFFFFFFULL) == 0x0000000054534F48ULL && *(l7 + h + 4U) == ':') {
                        size_t v = h + 5U;
                        while (v < scan_lim && (*(l7 + v) == ' ' || *(l7 + v) == '	')) v++;
                        uint64_t hv = rd_le64(l7 + v);
                        if ((hv & 0xFFFFFFFFULL) == 0x2E373231U || (hv & 0xFFFFFFFFFFFFFFFFULL) == 0x2E3435322E393631ULL || ((hv & 0xDFDFDFDFDFDFDFDFULL) == 0x534F484C41434F4CULL && (*(l7 + v + 8U) & 0xDFU) == 'T')) return ZK_VERDICT_BAN;
                    }
                }
                if ((has_cl != 0U && has_te != 0U) || has_cl > 1U || has_te > 1U || (has_upg != 0U && (has_te != 0U || has_cl != 0U))) return ZK_VERDICT_BAN;
                size_t body_lim = (l7_len - 8U < 1024U) ? (l7_len - 8U) : 1024U;
                for (size_t b = uri_start; b <= body_lim; b++) {
                    if (rd_le32(l7 + b) == 0x0A0D0A0DU && b + 8U <= l7_len) {
                        uint32_t sig = rd_le32(l7 + b + 4U);
                        if (sig == 0x6D783F3CU || sig == 0x4F44213CU || sig == 0x41304F72U || sig == 0x0500EDACU) return ZK_VERDICT_BAN;
                        break;
                    }
                }
            }
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
        if (slot->flow_hash == fid && (slot->fsm_flags & 1U) != 0) {
            memset(slot, 0, sizeof(*slot));
            slot->ema_popcnt = 64;
            return ZK_VERDICT_PASS;
        }
        return ((tcp_flags & 0x04U) != 0) ? ZK_VERDICT_PASS : ZK_VERDICT_DROP;
    }

    bool is_syn = (tcp_flags & 0x02U) != 0;
    bool is_ack = (tcp_flags & 0x10U) != 0;
    bool is_tls = (l7 && l7_len >= 5 && *(l7 + 0) == 0x16);
    uint16_t step_flags = (is_syn ? 1U : 0U) | (is_tls ? 2U : 0U) | ((l7_len >= 16) ? 4U : 0U) | ((!is_syn && is_ack && l7_len == 0) ? 8U : 0U);

    if (slot->flow_hash != fid && slot->flow_hash != 0 && slot->pkt_count >= 8U) return ZK_VERDICT_PASS;
    if (slot->flow_hash != fid && !is_syn && is_ack && l7_len == 0U) return ZK_VERDICT_DROP;
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
        uint16_t diff = (slot->last_l7_len > cur_len) ? (slot->last_l7_len - cur_len) : (cur_len - slot->last_l7_len);
        if (diff <= 16U) {
            if (slot->same_len_streak < 0xFFFFU) slot->same_len_streak++;
            slot->last_l7_len = cur_len;
        } else {
            slot->last_l7_len = cur_len;
            slot->same_len_streak = 0;
        }
        uint32_t bits = (uint32_t)(__builtin_popcountll(rd_le64(l7)) + __builtin_popcountll(rd_le64(l7 + 8)));
        slot->ema_popcnt = (slot->pkt_count <= 2U) ? bits : ((slot->ema_popcnt * 3U + bits) >> 2);
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
        if (len < l3_off + 24) { ctx->total_inspected++; ctx->total_drops++; return ZK_VERDICT_DROP; }
        eth_proto = rd_be16(pkt + l3_off + 2);
        l3_off += 4;
    }
    if (eth_proto == 0x8100 || eth_proto == 0x88A8) { ctx->total_inspected++; ctx->total_drops++; return ZK_VERDICT_DROP; }
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
    if (proto == 132U || proto == 33U || proto == 47U || proto == 21U) {
        ctx->total_inspected++; ctx->total_drops++; return ZK_VERDICT_DROP;
    }
    const uint8_t *l4 = ip + 20;
    size_t l4_avail = ip_avail - 20;
    uint16_t dport = 0; uint8_t tcp_flags = 0; const uint8_t *l7 = NULL; size_t l7_len = 0; uint32_t ports_word = 0;

    if (proto == 6) {
        if (l4_avail < 20) { ctx->total_inspected++; ctx->total_drops++; return ZK_VERDICT_DROP; }
        uint8_t doff = (uint8_t)(((*(l4 + 12)) >> 4) * 4U);
        if (doff < 20 || l4_avail < doff) { ctx->total_inspected++; ctx->total_drops++; return ZK_VERDICT_DROP; }
        memcpy(&ports_word, l4, sizeof(ports_word));
        dport = rd_be16(l4 + 2); tcp_flags = *(l4 + 13); l7 = l4 + doff; l7_len = l4_avail - doff;
        uint16_t urg_ptr = rd_be16(l4 + 18);
        if (tcp_flags == 0x00U || (tcp_flags & 0x03U) == 0x03U || (tcp_flags & 0x06U) == 0x06U || (tcp_flags & 0x05U) == 0x05U ||
            ((tcp_flags & 0x29U) != 0U && (tcp_flags & 0x10U) == 0U) ||
            ((tcp_flags & 0x12U) == 0x02U && l7_len > 0U) ||
            (urg_ptr != 0U && (tcp_flags & 0x20U) == 0U) ||
            ((tcp_flags & 0x20U) != 0U && (urg_ptr == 0U || (size_t)urg_ptr > l7_len))) { ctx->total_inspected++; ctx->total_drops++; return ZK_VERDICT_DROP; }
    } else if (proto == 17) {
        if (l4_avail < 8) { ctx->total_inspected++; ctx->total_drops++; return ZK_VERDICT_DROP; }
        memcpy(&ports_word, l4, sizeof(ports_word));
        dport = rd_be16(l4 + 2); l7 = l4 + 8; l7_len = l4_avail - 8;
    }
    ctx->total_inspected++;
    v = inspect_l7_payload(proto, dport, l7, l7_len);
    if (v == ZK_VERDICT_PASS && proto == 6) {
        v = inspect_stateful_drift(ctx, src_ip, dst_ip, ports_word, tcp_flags, l7, l7_len);
        if (v == ZK_VERDICT_PASS && dport != 22U && l7_len >= 1U && l7_len < 12U && (tcp_flags & 0x01U) == 0U) {
            uint32_t ip_lo = (src_ip < dst_ip) ? src_ip : dst_ip, ip_hi = (src_ip < dst_ip) ? dst_ip : src_ip;
            uint32_t p_sw = (ports_word >> 16) | (ports_word << 16);
            uint32_t fid = zk_crc32c_u32(zk_crc32c_u32(zk_crc32c_u32(0x5A45524FU, ip_lo), ip_hi), (ports_word < p_sw) ? ports_word : p_sw);
            struct zk_flow_slot *sl = &ctx->flows[(fid ? fid : 1U) & ZK_FLOW_MASK];
            if ((sl->fsm_flags & 16U) != 0U) { memset(sl, 0, sizeof(*sl)); sl->ema_popcnt = 64; v = ZK_VERDICT_BAN; }
            else { sl->fsm_flags |= 16U; }
        }
    }
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


static uint32_t zk_crc32c_sw(const uint8_t *buf, size_t len) {
    uint32_t crc = 0x5A45524FU;
    for (size_t i = 0; i < len; i++) {
        crc ^= buf[i];
        for (int k = 0; k < 8; k++) crc = (crc >> 1) ^ (0x82F63B78U & (0U - (crc & 1U)));
    }
    return crc;
}

size_t zk_emit_epoch_jit_x86(uint8_t *dst, size_t cap, uint32_t epoch_id, uint32_t *out_crc) {
#if !defined(__x86_64__) && !defined(_M_X64)
    (void)dst; (void)cap; (void)epoch_id; (void)out_crc;
    return 0;
#else
    if (!dst || cap < 43U) return 0;
    size_t p = 0;
    uint32_t variant = epoch_id & 3U;
    if ((variant & 1U) == 0U) { *(dst + p++) = 0x4DU; *(dst + p++) = 0x31U; *(dst + p++) = 0xC0U; }
    else                       { *(dst + p++) = 0x4DU; *(dst + p++) = 0x29U; *(dst + p++) = 0xC0U; }
    const char *head   = "\x66\x48\x0F\x6E\xC7\x66\x0F\x6F\x0A";
    const char *body_a = "\xF2\x4C\x0F\x38\xF1\xC7\x66\x0F\x38\xDC\xC1\xF2\x4C\x0F\x38\xF1\xC6\x66\x0F\x38\xDC\xC1";
    const char *body_b = "\x66\x0F\x38\xDC\xC1\xF2\x4C\x0F\x38\xF1\xC7\x66\x0F\x38\xDC\xC1\xF2\x4C\x0F\x38\xF1\xC6";
    const char *tail   = "\x66\x48\x0F\x7E\xC0\x4C\x31\xC0\xC3";
    memcpy(dst + p, head, 9U); p += 9U;
    memcpy(dst + p, (variant < 2U) ? body_a : body_b, 22U); p += 22U;
    memcpy(dst + p, tail, 9U); p += 9U;
    if (out_crc) *out_crc = zk_crc32c_sw(dst, p);
    return p;
}

#endif

static inline uint64_t zk_rdtscp_now(void) {
#if defined(__x86_64__)
    uint32_t lo, hi;
    __asm__ __volatile__("rdtscp\n\tlfence" : "=a"(lo), "=d"(hi) :: "rcx");
    return ((uint64_t)hi << 32) | lo;
#else
    return 0ULL;
#endif
}

static inline uint32_t zk_cpuid_sig(void) {
#if defined(__x86_64__)
    uint32_t eax, ebx, ecx, edx;
    __asm__ __volatile__("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1), "c"(0));
    return eax;
#else
    return 0U;
#endif
}

void zk_pulse_calibrate_boot(struct zk_hardware_pulse_anchor *a, uint32_t target_batch) {
    if (!a) return;
    memset(a, 0, sizeof(*a));
    a->cpu_sig = zk_cpuid_sig();
    a->target_batch = target_batch ? target_batch : 32U;
    uint64_t t0 = zk_rdtscp_now();
    for (volatile uint32_t i = 0; i < 256U; i++) {}
    uint64_t t1 = zk_rdtscp_now();
    uint64_t probe = t1 - t0;
    uint64_t base = (probe > 0ULL && probe < 200000ULL) ? (probe << 5) : 32000ULL;
    a->base_pulse_tsc = base;
    a->current_period_tsc = base;
    a->last_pulse_tsc = t1;
    a->realign_epochs = 1ULL;
}

int zk_pulse_periodic_realign(struct zk_hardware_pulse_anchor *a, uint32_t arrived_pkts) {
    if (!a) return 0;
    uint64_t now = zk_rdtscp_now();
    uint32_t sig = zk_cpuid_sig();
    if (sig != a->cpu_sig) {
        a->cpu_sig = sig;
        a->current_period_tsc = a->base_pulse_tsc;
        a->last_pulse_tsc = now;
        a->realign_epochs++;
        return 1;
    }
    if ((now - a->last_pulse_tsc) < a->current_period_tsc && arrived_pkts < a->target_batch) return 0;
    a->last_pulse_tsc = now;
    a->realign_epochs++;
    if (arrived_pkts > a->target_batch) {
        uint64_t next = a->current_period_tsc - (a->current_period_tsc >> 3);
        a->current_period_tsc = (next < 2000ULL) ? 2000ULL : next;
    } else if (arrived_pkts < (a->target_batch >> 1)) {
        uint64_t next = a->current_period_tsc + (a->current_period_tsc >> 3);
        a->current_period_tsc = (next > 3300000ULL) ? 3300000ULL : next;
    }
    return 1;
}

// ZEROKULL Slab-Isolated Quarantine & Mirror Labyrinth (4 banks x 16 cells, 0 malloc)
typedef struct {
    uint64_t tag64;
    uint32_t cls;
    uint32_t locked;
    uint8_t  mirage_ttl;
    uint8_t  tcp_win;
    uint8_t  state;
} zk_slab_cell_t;

static zk_slab_cell_t zk_labyrinth_arena[64];

uint32_t zk_labyrinth_admit(uint64_t fid, uint32_t threat_cls, uint64_t tsc_lo, uint8_t *out_ttl, uint8_t *out_win) {
    uint32_t cls = threat_cls & 3U;
    uint64_t tag = (fid * 0x9E3779B97F4A7C15ULL) ^ ((uint64_t)cls << 48) ^ 0x5A45524F4B554C4CULL;
    uint32_t base = cls * 16U + (uint32_t)((tag & 7ULL) * 2ULL);
    zk_slab_cell_t *c0 = &zk_labyrinth_arena[base];
    zk_slab_cell_t *c1 = &zk_labyrinth_arena[base + 1U];
    zk_slab_cell_t *t = NULL;
    if (c0->state && c0->tag64 == tag) t = c0;
    else if (c1->state && c1->tag64 == tag) t = c1;
    else if (!c0->state) t = c0;
    else if (!c1->state) t = c1;
    else if (cls == 0U) { memset(c0, 0, sizeof(*c0)); t = c0; }
    else return 0U;
    t->tag64 = tag; t->cls = cls; t->locked = (cls == 1U || cls == 3U) ? 1U : 0U;
    t->mirage_ttl = (cls == 0U || cls == 2U) ? (uint8_t)(65U + (uint8_t)(tsc_lo & 0x35U)) : 0U;
    t->tcp_win = (cls == 0U || cls == 2U) ? 1U : 0U;
    t->state = (cls == 3U) ? 3U : ((cls == 0U || cls == 2U) ? 1U : 2U);
    if (out_ttl) *out_ttl = t->mirage_ttl;
    if (out_win) *out_win = t->tcp_win;
    return t->state;
}
