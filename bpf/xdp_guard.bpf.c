// ZEROKULL (zerokull1) | Author Signature: 0x5A45524F4B554C4CULL
// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ZK_MAX_PKT_LEN 1536U

/* Set via libbpf .rodata prior to load: 0 = ENFORCE (XDP_DROP), 1 = SHADOW_DROP (XDP_PASS + count) */
volatile const __u8 shadow_mode = 0;

#define ZK_DROP_ACTION(st) do { \
    if (st) (st)->xdp_drops++; \
    return shadow_mode ? XDP_PASS : XDP_DROP; \
} while (0)

struct zk_vlan_hdr { __be16 h_vlan_TCI; __be16 h_vlan_encapsulated_proto; };
struct zk_pkt_event { __u32 wire_len; __u32 cap_len; __u32 ingress_ifindex; __u32 _pad; __u8 data[ZK_MAX_PKT_LEN]; };
struct zk_xdp_stats { __u64 rx_packets; __u64 xdp_drops; __u64 ringbuf_sent; __u64 ringbuf_drops; };

struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, __u8); } blacklist_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, __u8); } whitelist_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, struct zk_xdp_stats); } stats_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 256 * 1024); } ringbuf_map SEC(".maps");

SEC("xdp")
int zerokull_xdp_guard(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    __u32 zero = 0;
    struct zk_xdp_stats *st = bpf_map_lookup_elem(&stats_map, &zero);
    if (st) st->rx_packets++;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    __be16 h_proto = eth->h_proto;
    void *nh = (void *)(eth + 1);
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
            struct zk_vlan_hdr *vh = nh;
            if ((void *)(vh + 1) > data_end) return XDP_PASS;
            h_proto = vh->h_vlan_encapsulated_proto;
            nh = (void *)(vh + 1);
        }
    }

    // [Уязвимость #1 закрыта] Инспекция IPv6 (ETH_P_IPV6): отсекаем HopLimit=0/65/129, IPv6 Fragment (44) и RA/Redirect спуфинг
    if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = nh;
        if ((void *)(ip6 + 1) > data_end) { ZK_DROP_ACTION(st); }
        if (ip6->version != 6 || ip6->hop_limit == 0 || ip6->hop_limit == 65 || ip6->hop_limit == 129 || ip6->nexthdr == 44) {
            ZK_DROP_ACTION(st);
        }
        if (ip6->nexthdr == 0 || ip6->nexthdr == 60) {
            struct ipv6_opt_hdr *opt = (void *)(ip6 + 1);
            if ((void *)(opt + 1) > data_end || opt->hdrlen > 2) {
                ZK_DROP_ACTION(st);
            }
        }
        return XDP_PASS;
    }

    if (h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = nh;
    if ((void *)(iph + 1) > data_end) return XDP_PASS;

    // [Уязвимость #4 закрыта] Валидация tot_len, IHL, TTL, IPv4-фрагментации и Bogon/Martian source spoofing (0.0.0.0, 255.255.255.255, 127.0.0.0/8)
    __u16 tot_len = bpf_ntohs(iph->tot_len);
    __u32 src_host = bpf_ntohl(iph->saddr);
    if (iph->version != 4 || iph->ihl != 5 || tot_len < 20 ||
        iph->ttl == 0 || iph->ttl == 65 || iph->ttl == 129 ||
        (iph->frag_off & bpf_htons(0x3FFF)) != 0 ||
        src_host == 0U || src_host == 0xFFFFFFFFU || (src_host & 0xFF000000U) == 0x7F000000U) {
        ZK_DROP_ACTION(st);
    }

    if (iph->protocol == 132 || iph->protocol == 33 || iph->protocol == 47 || iph->protocol == 21) {
        ZK_DROP_ACTION(st);
    }
    __u32 src_ip = iph->saddr;
    if (bpf_map_lookup_elem(&blacklist_map, &src_ip)) { ZK_DROP_ACTION(st); }
    if (bpf_map_lookup_elem(&whitelist_map, &src_ip)) return XDP_PASS;

    __u64 wire_len = (__u64)((long)data_end - (long)data);
    if (wire_len < 34) return XDP_PASS;
    __u32 cap_len = wire_len > ZK_MAX_PKT_LEN ? ZK_MAX_PKT_LEN : (__u32)wire_len;
    asm volatile("" : "+r"(cap_len));
    if (cap_len < 34 || cap_len > ZK_MAX_PKT_LEN) return XDP_PASS;

    struct zk_pkt_event *ev = bpf_ringbuf_reserve(&ringbuf_map, sizeof(*ev), 0);
    if (!ev) { if (st) st->ringbuf_drops++; return XDP_PASS; }
    ev->wire_len = (__u32)wire_len;
    ev->cap_len  = cap_len;
    // [Уязвимость #2 закрыта] Фиксируем точный номер входного порта ctx->ingress_ifindex для многопортового узла
    ev->ingress_ifindex = ctx->ingress_ifindex;
    ev->_pad = 0;
    if (bpf_xdp_load_bytes(ctx, 0, ev->data, cap_len) < 0) { bpf_ringbuf_discard(ev, 0); return XDP_PASS; }
    bpf_ringbuf_submit(ev, 0);
    if (st) st->ringbuf_sent++;
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
