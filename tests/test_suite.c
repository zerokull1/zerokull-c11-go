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
    tcp[12] = 0x50; tcp[13] = flags;
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
    return 0;
}
