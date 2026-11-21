#include "zerokull.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t build_tcp(uint8_t *buf, uint32_t src_ip, uint16_t sport, uint16_t dport,
                        uint8_t ttl, uint8_t flags, const uint8_t *payload, size_t plen) {
    memset(buf, 0, 54 + plen);
    *(buf + 12) = 0x08; *(buf + 13) = 0x00; *(buf + 14) = 0x45;
    *(buf + 22) = ttl;  *(buf + 23) = 6;
    memcpy(buf + 26, &src_ip, 4);
    uint32_t dst = 0x0100000A;
    memcpy(buf + 30, &dst, 4);
    *(buf + 34) = (uint8_t)(sport >> 8); *(buf + 35) = (uint8_t)(sport & 0xFF);
    *(buf + 36) = (uint8_t)(dport >> 8); *(buf + 37) = (uint8_t)(dport & 0xFF);
    *(buf + 46) = 0x50; *(buf + 47) = flags;
    if (payload && plen > 0) memcpy(buf + 54, payload, plen);
    return 54 + plen;
}

int main(void) {
    struct zk_engine_ctx ctx;
    zk_engine_init(&ctx);
    uint8_t *pkt = calloc(1, 512);
    uint32_t sip = 0;

    assert(zk_inspect_packet(&ctx, pkt, build_tcp(pkt, 0x0101010A, 41000, 443, 64, 0x02, NULL, 0), &sip) == ZK_VERDICT_PASS);
    const uint8_t *tls_buf = (const uint8_t *)"\x16\x03\x03\x00\x1B\x01";
    assert(zk_inspect_packet(&ctx, pkt, build_tcp(pkt, 0x0101010A, 41000, 443, 64, 0x18, tls_buf, 6), &sip) == ZK_VERDICT_PASS);
    uint8_t *web_buf = calloc(1, 160);
    memset(web_buf, 0x41, 160);
    for (size_t i = 0; i < 20; i++)
        assert(zk_inspect_packet(&ctx, pkt, build_tcp(pkt, 0x0101010A, 41000, 443, 64, 0x18, web_buf, 32 + (i * 5) % 80), &sip) == ZK_VERDICT_PASS);

    assert(zk_inspect_packet(&ctx, pkt, build_tcp(pkt, 0x0202020A, 42000, 443, 65, 0x02, NULL, 0), &sip) == ZK_VERDICT_DROP);

    const uint8_t *smb_buf = (const uint8_t *)"\xFFSMB\x72\x00\x00\x00";
    assert(zk_inspect_packet(&ctx, pkt, build_tcp(pkt, 0x0303030A, 43000, 445, 64, 0x18, smb_buf, 8), &sip) == ZK_VERDICT_BAN);

    const uint8_t *req = (const uint8_t *)"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    for (int i = 0; i < 3; i++)
        assert(zk_inspect_packet(&ctx, pkt, build_tcp(pkt, 0x0404040A, 44000, 80, 64, 0x18, req, 27), &sip) == ZK_VERDICT_PASS);
    assert(zk_inspect_packet(&ctx, pkt, build_tcp(pkt, 0x0404040A, 44000, 80, 64, 0x18, req, 27), &sip) == ZK_VERDICT_DROP);

    assert(zk_inspect_packet(&ctx, pkt, build_tcp(pkt, 0x0505050A, 45000, 443, 64, 0x02, NULL, 0), &sip) == ZK_VERDICT_PASS);
    uint8_t *tun_buf = calloc(1, 96);
    for (size_t i = 0; i < 96; i += 4) {
        *(tun_buf + i + 0) = 0x55; *(tun_buf + i + 1) = 0xAA;
        *(tun_buf + i + 2) = 0x33; *(tun_buf + i + 3) = 0xCC;
    }
    bool banned = false;
    for (int i = 0; i < 25; i++) {
        if (zk_inspect_packet(&ctx, pkt, build_tcp(pkt, 0x0505050A, 45000, 443, 64, 0x18, tun_buf, 96), &sip) == ZK_VERDICT_BAN) {
            banned = true; break;
        }
    }
    assert(banned);

    printf("[TEST PASS] inspected=%llu drops=%llu bans=%llu\n",
           (unsigned long long)ctx.total_inspected, (unsigned long long)ctx.total_drops, (unsigned long long)ctx.total_bans);
    free(pkt); free(web_buf); free(tun_buf);
    return 0;
}
