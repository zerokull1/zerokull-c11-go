#include "zk_gpu_ring.h"
// ZEROKULL (zerokull1) | Author Signature: 0x5A45524F4B554C4CULL
// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0.

#include "zerokull.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static size_t build_tcp(uint8_t *buf, uint32_t src_ip, uint16_t sport, uint16_t dport,
                        uint8_t ttl, uint8_t flags, const uint8_t *payload, size_t plen) {
    memset(buf, 0, 54 + plen);
    buf[12] = 0x08; buf[13] = 0x00;
    uint8_t *ip = buf + 14;
    ip[0] = 0x45;
    uint16_t ip_len = (uint16_t)(40 + plen);
    ip[2] = (uint8_t)(ip_len >> 8); ip[3] = (uint8_t)(ip_len & 0xFF);
    ip[8] = ttl; ip[9] = 6;
    memcpy(ip + 12, &src_ip, 4);
    uint32_t dst_ip = 0x0201010A;
    memcpy(ip + 16, &dst_ip, 4);
    uint8_t *tcp = ip + 20;
    tcp[0] = (uint8_t)(sport >> 8); tcp[1] = (uint8_t)(sport & 0xFF);
    tcp[2] = (uint8_t)(dport >> 8); tcp[3] = (uint8_t)(dport & 0xFF);
    tcp[12] = 0x50; tcp[13] = flags; tcp[14] = 0xFA; tcp[15] = 0xF0;
    if (payload && plen > 0) memcpy(buf + 54, payload, plen);
    return 54 + plen;
}

int main(void) {
    struct zk_engine_ctx ctx;
    zk_engine_init(&ctx);
    uint32_t sip = 0;
    uint8_t pkt[512] = {0};

    assert(zk_inspect_packet(&ctx, pkt, build_tcp(pkt, 0x0101010A, 41000, 443, 64, 0x02, NULL, 0), &sip) == ZK_VERDICT_PASS);
    uint8_t tls_buf[64] = {0x16, 0x03, 0x03, 0x00, 0x3B, 0x01};
    uint8_t tls_split[6] = {0x16, 0x03, 0x03, 0x00, 0x01, 0x01};
    assert(zk_inspect_packet(&ctx, pkt, build_tcp(pkt, 0x0101010A, 41000, 443, 64, 0x18, tls_buf, 64), &sip) == ZK_VERDICT_PASS);
    assert(zk_inspect_packet(&ctx, pkt, build_tcp(pkt, 0x0101010A, 41001, 443, 64, 0x18, tls_split, 6), &sip) == ZK_VERDICT_DROP);

    uint8_t web_buf[160];
    memset(web_buf, 0x41, sizeof(web_buf));
    for (int i = 0; i < 20; i++) {
        assert(zk_inspect_packet(&ctx, pkt, build_tcp(pkt, 0x0101010A, 41000, 443, 64, 0x18, web_buf, 160), &sip) == ZK_VERDICT_PASS);
    }

    assert(zk_inspect_packet(&ctx, pkt, build_tcp(pkt, 0x0301010A, 42000, 443, 65, 0x02, NULL, 0), &sip) == ZK_VERDICT_DROP);

    uint8_t smb1[8] = {0xFF, 'S', 'M', 'B', 0x72, 0x00, 0x00, 0x00};
    assert(zk_inspect_packet(&ctx, pkt, build_tcp(pkt, 0x0401010A, 43000, 445, 64, 0x18, smb1, 8), &sip) == ZK_VERDICT_BAN);

    for (int i = 0; i < 4; i++) {
        enum zk_verdict v = zk_inspect_packet(&ctx, pkt, build_tcp(pkt, 0x0501010A, 44000, 9000, 64, 0x18, web_buf, 64), &sip);
        assert(v == (i < 3 ? ZK_VERDICT_PASS : ZK_VERDICT_DROP));
    }

    uint8_t rnd_buf[128];
    for (size_t i = 0; i < sizeof(rnd_buf); i++) rnd_buf[i] = (uint8_t)((i * 73U + 19U) ^ (i >> 1));
    enum zk_verdict last = ZK_VERDICT_PASS;
    for (int i = 0; i < 20 && last == ZK_VERDICT_PASS; i++) {
        last = zk_inspect_packet(&ctx, pkt, build_tcp(pkt, 0x0601010A, 45000, 9001, 64, i == 0 ? 0x02 : 0x18, i == 0 ? NULL : rnd_buf, i == 0 ? 0 : 128), &sip);
    }
    assert(last == ZK_VERDICT_BAN);

    uint8_t h2_flood[13] = {0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
    assert(zk_inspect_packet(&ctx, pkt, build_tcp(pkt, 0x0701010A, 46000, 80, 64, 0x18, h2_flood, 13), &sip) == ZK_VERDICT_BAN);

    uint16_t mcode[] = {
        (0x1U << 12) | (2U << 9) | 0x45U,
        (0x3U << 12) | (3U << 9) | 14U,
        (0x4U << 12) | (2U << 9) | (3U << 6),
        (0xFU << 12)
    };
    assert(zk_exec_millicode(mcode, 4, pkt, 60, ZK_VERDICT_PASS) == ZK_VERDICT_BAN);
        {
        uint8_t pkt_trav[74] = {
            0,0,0,0,0,1, 0,0,0,0,0,2, 0x08,0x00,
            0x45,0x00, 0x00,0x3c, 0x00,0x01, 0x40,0x00, 0x40,0x06, 0x00,0x00,
            10,0,0,99, 10,0,0,1,
            0x1f,0x90, 0x00,0x50, 0,0,0,1, 0,0,0,1, 0x50,0x18, 0x20,0x00, 0,0, 0,0,
            'G','E','T',' ','/','.','.',';','/','e','t','c','/','p','a','s','s','w','d',' '
        };
        uint32_t bip = 0;
        if (zk_inspect_packet(&ctx, pkt_trav, sizeof(pkt_trav), &bip) != ZK_VERDICT_BAN) return 91;
    }
    uint8_t sctp_pkt[64] = {0}; sctp_pkt[12]=0x08; sctp_pkt[14]=0x45; sctp_pkt[17]=40; sctp_pkt[22]=64; sctp_pkt[23]=132; sctp_pkt[26]=10; sctp_pkt[30]=10;
    enum zk_verdict sctp_v = zk_inspect_packet(&ctx, sctp_pkt, sizeof(sctp_pkt), &sip);
    assert(sctp_v == ZK_VERDICT_DROP);
    assert(zk_effective_verdict(sctp_v, true) == ZK_VERDICT_PASS);
    assert(zk_effective_verdict(ZK_VERDICT_BAN, true) == ZK_VERDICT_PASS);
    assert(zk_effective_verdict(sctp_v, false) == ZK_VERDICT_DROP);
    uint32_t c0 = 0, c1 = 0;
    uint8_t jit0[64] = {0}, jit1[64] = {0};
    assert(zk_emit_epoch_jit_x86(jit0, 42U, 0, &c0) == 0U);
    assert(zk_emit_epoch_jit_x86(jit0, sizeof(jit0), 0, &c0) == 43U);
    assert(zk_emit_epoch_jit_x86(jit1, sizeof(jit1), 1, &c1) == 43U);
    assert(c0 != c1 && jit0[1] == 0x31U && jit1[1] == 0x29U);
    {
        uint8_t tls17_micro[60] = {
            0,0,0,0,0,1, 0,0,0,0,0,2, 0x08,0x00,
            0x45,0x00, 0x00,0x2e, 0,1, 0,0, 64, 6, 0,0,
            10,0,0,77, 10,0,0,1,
            0x1f,0x90, 0x01,0xbb, 0,0,0,1, 0,0,0,1, 0x50,0x18, 0x20,0x00, 0,0, 0,0,
            0x17, 0x03, 0x03, 0x00, 0x04, 0xaa
        };
        uint32_t tip = 0;
        assert(zk_inspect_packet(&ctx, tls17_micro, sizeof(tls17_micro), &tip) == ZK_VERDICT_DROP);
    }

    /* Regression: Cacti 4HTTP2SHELL 0-day (28.11.2026) */
    {
        const char *cacti_atk = "GET /cacti/auth_profile.php?action=update_data&preview_graphs_per_page=1'+OR+1=1-- HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n";
        const char *cacti_ok  = "GET /cacti/auth_profile.php?action=update_data&preview_graphs_per_page=30 HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n";
        const char *base_hdr =
            "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02\x08\x00"
            "\x45\x00\x00\x00\x00\x02\x00\x00\x40\x06\x00\x00"
            "\x0a\x00\x00\x58\x0a\x00\x00\x01"
            "\xd4\x31\x00\x50\x00\x00\x00\x01\x00\x00\x00\x01\x50\x18\x20\x00\x00\x00\x00\x00";
        uint8_t *p1 = (uint8_t *)__builtin_alloca(256U);
        uint8_t *p2 = (uint8_t *)__builtin_alloca(256U);
        size_t l1 = 54U + strlen(cacti_atk), l2 = 54U + strlen(cacti_ok);
        memcpy(p1, base_hdr, 54U);
        *(p1 + 16) = (uint8_t)((l1 - 14U) >> 8);
        *(p1 + 17) = (uint8_t)((l1 - 14U) & 0xFFU);
        memcpy(p1 + 54U, cacti_atk, strlen(cacti_atk));

        memcpy(p2, base_hdr, 54U);
        *(p2 + 29) = 89U;
        *(p2 + 16) = (uint8_t)((l2 - 14U) >> 8);
        *(p2 + 17) = (uint8_t)((l2 - 14U) & 0xFFU);
        memcpy(p2 + 54U, cacti_ok, strlen(cacti_ok));

        uint32_t tip = 0;
        assert(zk_inspect_packet(&ctx, p1, l1, &tip) == ZK_VERDICT_BAN);
        assert(zk_inspect_packet(&ctx, p2, l2, &tip) == ZK_VERDICT_PASS);
    }

        /* Regression: CDN/Cloudflare TCP Window Scaling (sport=443, raw win=32 -> PASS, FP=0) */
    {
        uint32_t sip_cf = 0;
        uint8_t cf_pkt[256] = {0};
        uint8_t cf_tls[64] = {0x16, 0x03, 0x03, 0x00, 0x3B, 0x02};
        assert(zk_inspect_packet(&ctx, cf_pkt, build_tcp(cf_pkt, 0x1A171468U, 443, 49153, 64, 0x12, NULL, 0), &sip_cf) == ZK_VERDICT_PASS);
        size_t cf_len = build_tcp(cf_pkt, 0x1A171468U, 443, 49153, 64, 0x18, cf_tls, 64);
        cf_pkt[48] = 0x00; cf_pkt[49] = 0x20; /* raw tcp_win = 32 (scaled window) */
        assert(zk_inspect_packet(&ctx, cf_pkt, cf_len, &sip_cf) == ZK_VERDICT_PASS);
    }
        /* Regression: Transit CISA KEV (Double-encoded %252e traversal, X-Rewrite-URL, padded XXE -> BAN, FP=0) */
    {
        uint32_t sip_tr = 0;
        uint8_t tr_pkt[512] = {0};
        const char *m_dbl = "GET /npm-pwg/%252e%252e/etc/passwd HTTP/1.1\r\nHost: mitel.local\r\n\r\n";
        const char *m_xrw = "GET /api/v1/status HTTP/1.1\r\nHost: juniper.local\r\nX-Rewrite-URL: /admin\r\n\r\n";
        const char *m_xxe = "POST /xmlrpc HTTP/1.1\r\nHost: danfoss.local\r\nContent-Length: 32\r\n\r\n  \n<!DOCTYPE foo SYSTEM \"x\">";
        const char *m_ok  = "POST /api/v1/telemetry HTTP/1.1\r\nHost: edge.local\r\nContent-Length: 18\r\n\r\n{\"status\":\"ready\"}";
        assert(zk_inspect_packet(&ctx, tr_pkt, build_tcp(tr_pkt, 0x0B01010AU, 51001, 80, 64, 0x18, (const uint8_t *)m_dbl, strlen(m_dbl)), &sip_tr) == ZK_VERDICT_BAN);
        assert(zk_inspect_packet(&ctx, tr_pkt, build_tcp(tr_pkt, 0x0C01010AU, 51002, 80, 64, 0x18, (const uint8_t *)m_xrw, strlen(m_xrw)), &sip_tr) == ZK_VERDICT_BAN);
        assert(zk_inspect_packet(&ctx, tr_pkt, build_tcp(tr_pkt, 0x0D01010AU, 51003, 80, 64, 0x18, (const uint8_t *)m_xxe, strlen(m_xxe)), &sip_tr) == ZK_VERDICT_BAN);
        assert(zk_inspect_packet(&ctx, tr_pkt, build_tcp(tr_pkt, 0x0E01010AU, 51004, 80, 64, 0x18, (const uint8_t *)m_ok, strlen(m_ok)), &sip_tr) == ZK_VERDICT_PASS);
    }
    printf("[TEST PASS] inspected=%llu drops=%llu bans=%llu\n",
           (unsigned long long)ctx.total_inspected,
           (unsigned long long)ctx.total_drops,
           (unsigned long long)ctx.total_bans);
    {
        uint8_t del_pkt[] = {
            0,0,0,0,0,1, 0,0,0,0,0,2, 0x08,0x00,
            0x45,0x00, 0x00,0x56, 0,1, 0,0, 64, 6, 0,0, 10,0,0,88, 10,0,0,1,
            0x1f,0x90, 0x00,0x50, 0,0,0,1, 0,0,0,1, 0x50,0x18, 0x20,0x00, 0,0, 0,0,
            'D','E','L','E','T','E',' ','/','.','.','/','.','.','/','e','t','c','/','p','a','s','s','w','d',' ',
            'H','T','T','P','/','1','.','1','\r','\n','H','o','s','t',':',' ','x','\r','\n','\r','\n'
        };
        assert(zk_inspect_packet(&ctx, del_pkt, sizeof(del_pkt), &sip) == ZK_VERDICT_BAN);
        uint8_t leg_post[] = {
            0,0,0,0,0,1, 0,0,0,0,0,2, 0x08,0x00,
            0x45,0x00, 0x00,0x72, 0,1, 0,0, 64, 6, 0,0, 10,0,0,89, 10,0,0,1,
            0x1f,0x90, 0x00,0x50, 0,0,0,1, 0,0,0,1, 0x50,0x18, 0x20,0x00, 0,0, 0,0,
            'P','O','S','T',' ','/','a','p','i',' ','H','T','T','P','/','1','.','1','\r','\n',
            'C','o','n','t','e','n','t','-','T','y','p','e',':',' ','a','p','p','l','i','c','a','t','i','o','n','/','j','s','o','n','\r','\n',
            'C','o','n','t','e','n','t','-','L','e','n','g','t','h',':',' ','2','\r','\n','\r','\n','{','}'
        };
        assert(zk_inspect_packet(&ctx, leg_post, sizeof(leg_post), &sip) == ZK_VERDICT_PASS);
        uint8_t syn_p[54] = {0,0,0,0,0,1,0,0,0,0,0,2,0x08,0x00,0x45,0,0,40,0,1,0,0,64,6,0,0,10,0,0,90,10,0,0,1,0x9c,0x40,0x01,0xbb,0,0,0,1,0,0,0,0,0x50,0x02,0x20,0,0,0,0,0};
        assert(zk_inspect_packet(&ctx, syn_p, 54, &sip) == ZK_VERDICT_PASS);
        uint8_t jit_p[200] = {0,0,0,0,0,1,0,0,0,0,0,2,0x08,0x00,0x45,0,0,170,0,1,0,0,64,6,0,0,10,0,0,90,10,0,0,1,0x9c,0x40,0x01,0xbb,0,0,0,2,0,0,0,1,0x50,0x18,0x20,0,0,0,0,0};
        uint32_t st = 0xDEADBEEFU; int banned = 0;
        for (int k = 0; k < 18; k++) {
            size_t pl = 128U + (size_t)(k & 1);
            uint16_t tot = (uint16_t)(40U + pl);
            *(jit_p + 16) = (uint8_t)(tot >> 8); *(jit_p + 17) = (uint8_t)tot;
            for (size_t b = 0; b < pl; b++) { st ^= st << 13; st ^= st >> 17; st ^= st << 5; *(jit_p + 54 + b) = (uint8_t)st; }
            if (zk_inspect_packet(&ctx, jit_p, 54U + pl, &sip) == ZK_VERDICT_BAN) { banned = 1; break; }
        }
        assert(banned == 1);
    }
        
    {
        const char *vecs[4] = {
            "GET /core/install.php?profile=standard HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: example.com\r\nX-Original-URL: /update.php\r\n\r\n",
            "POST /api/v1/user HTTP/1.1\r\nHost: example.com\r\nCookie: s=O:8:\"stdClass\":0:{}\r\n\r\n",
            "GET /avatar?src=phar://uploads/evil.jpg HTTP/1.1\r\nHost: example.com\r\n\r\n"
        };
        for (size_t k = 0; k < 4; k++) {
            uint8_t p[256] = {0};
            p[1] = 1; p[7] = 2; p[12] = 0x08; p[13] = 0x00;
            p[14] = 0x45; p[19] = 1; p[22] = 64; p[23] = 6;
            p[26] = 10; p[29] = (uint8_t)(80 + k);
            p[30] = 10; p[33] = 1;
            p[34] = 0x1f; p[35] = 0x90; p[36] = 0x00; p[37] = 0x50;
            p[41] = 1; p[45] = 1; p[46] = 0x50; p[47] = 0x18; p[48] = 0x20;
            size_t pl = strlen(vecs[k]);
            uint16_t tot = (uint16_t)(40U + pl);
            p[16] = (uint8_t)(tot >> 8); p[17] = (uint8_t)tot;
            memcpy(p + 54, vecs[k], pl);
            assert(zk_inspect_packet(&ctx, p, 54U + pl, &sip) == ZK_VERDICT_BAN);
        }
    }

    /* Regression tests: CVE-2026-133469 (Bugs #76, #77, #78: header-only, %7b%7d, { } whitespace, JSON body NO-FP) */
    {
        const char *cases[4] = {
            "GET /api/session HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {}\r\n\r\n",
            "GET /api/session HTTP/1.1\r\nHost: x\r\nCookie: tok=%7b%7d\r\n\r\n",
            "GET /api/session HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer { }\r\n\r\n",
            "POST /api/query HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer eyJhbGci.valid.sig\r\nContent-Length: 13\r\n\r\n{\"filter\":{}}"
        };
        const enum zk_verdict exp[4] = { ZK_VERDICT_BAN, ZK_VERDICT_BAN, ZK_VERDICT_BAN, ZK_VERDICT_PASS };
        for (size_t k = 0; k < 4; k++) {
            uint8_t p[256] = {0};
            uint32_t sip = 0U;
            p[1] = 1; p[7] = 2; p[12] = 0x08; p[13] = 0x00;
            p[14] = 0x45; p[19] = 1; p[22] = 64; p[23] = 6;
            p[26] = 10; p[29] = (uint8_t)(90U + k); p[30] = 10; p[33] = 1;
            p[34] = 0x1f; p[35] = 0x90; p[36] = 0x00; p[37] = 0x50;
            p[41] = 1; p[45] = 1; p[46] = 0x50; p[47] = 0x18; p[48] = 0x20;
            size_t pl = strlen(cases[k]);
            uint16_t tot = (uint16_t)(40U + pl);
            p[16] = (uint8_t)(tot >> 8); p[17] = (uint8_t)tot;
            memcpy(p + 54, cases[k], pl);
            assert(zk_inspect_packet(&ctx, p, 54U + pl, &sip) == exp[k]);
        }
    }

    ZkGpuRingCtx gctx;
    zk_gpu_ring_init(&gctx);
    uint64_t mock_ring[16] = {0};
    volatile uint32_t mock_get = 0, mock_put = 0;
    gctx.mode = ZK_ACCEL_DIRECT_RING;
    gctx.ring_ptr = mock_ring; gctx.ring_mask = 15;
    gctx.get_ptr = &mock_get; gctx.put_ptr = &mock_put;
    gctx.ndesc = 4; gctx.desc[0] = 0x04000000ULL;
    mock_get = 4;
    if (zk_gpu_ring_submit_batch(&gctx) != 0 || mock_put != 4) return 91;
    if (zk_swar_batch_entropy_score((const uint8_t *)"ZEROKULL", 8) == 0) return 92;
    gctx.ndesc = 999999U;
    if (zk_gpu_ring_submit_batch(&gctx) != -2) return 93;
    gctx.ndesc = 4;
    const uint8_t *vlan0_pkt = (const uint8_t[]){0x00,0x11,0x22,0x33,0x44,0x55,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x81,0x00,0x00,0x00,0x08,0x00,0x45,0x00,0x00,0x28,0,1,0,0,64,6,0,0,10,0,0,2,10,0,0,1,0x30,0x39,0x00,0x50,0,0,0,1,0,0,0,0,0x50,0x02,0x20,0x00,0,0,0,0};
    if (zk_inspect_packet(&ctx, vlan0_pkt, 58, NULL) != ZK_VERDICT_DROP) return 94;
    const uint8_t *nfs_pkt = (const uint8_t[]){0x00,0x11,0x22,0x33,0x44,0x55,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x08,0x00,0x45,0x00,0x00,0x2c,0,2,0,0,64,6,0,0,10,0,0,2,10,0,0,1,0x30,0x39,0x08,0x01,0,0,0,1,0,0,0,1,0x50,0x18,0x20,0x00,0,0,0,0,'N','F','S','4'};
    if (zk_inspect_packet(&ctx, nfs_pkt, 58, NULL) != ZK_VERDICT_BAN) return 95;
    struct zk_meta_norm_slot mslot;
    memset(&mslot, 0, sizeof(mslot));
    uint8_t mpkt[148];
    memset(mpkt, 0, sizeof(mpkt));
    if (zk_normalize_64b_gate(&mslot, 0x1111ULL, 0, 1, 0x02, mpkt, 0) != 0) return 96;
    if (zk_normalize_64b_gate(&mslot, 0x1111ULL, 0, 1, 0x18, mpkt, 32) != 1) return 97;
    if (zk_normalize_64b_gate(&mslot, 0x1111ULL, 0, 1, 0x18, mpkt, 64) != 0) return 98;
    *(mpkt + 0) = 1; *(mpkt + 4) = 0xAA;
    if (zk_normalize_64b_gate(&mslot, 0x2222ULL, 1, 0, 0, mpkt, 148) != 0) return 99;
    *(mpkt + 0) = 2; *(mpkt + 4) = 0x55; *(mpkt + 8) = 0xBB;
    if (zk_normalize_64b_gate(&mslot, 0x2222ULL, 1, 0, 0, mpkt, 92) != 1) return 100;
    *(mpkt + 8) = 0xAA;
    if (zk_normalize_64b_gate(&mslot, 0x2222ULL, 1, 0, 0, mpkt, 92) != 0) return 101;
    *(mpkt + 0) = 4; *(mpkt + 4) = 0x55; *(mpkt + 8) = 1;
    if (zk_normalize_64b_gate(&mslot, 0x2222ULL, 1, 0, 0, mpkt, 32) != 1) return 102;
    if (zk_normalize_64b_gate(&mslot, 0x2222ULL, 1, 0, 0, mpkt, 64) != 0) return 103;
    printf("[PASS] Universal GPFIFO+GPPut Ring & SWAR Fallback Self-Test OK\n");
    return 0;
}