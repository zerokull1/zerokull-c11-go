// ZEROKULL (zerokull1) | Author Signature: 0x5A45524F4B554C4CULL
// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ZK_MAX_PKT_LEN 1536

struct zk_pkt_event { __u32 wire_len; __u32 cap_len; __u8 data[ZK_MAX_PKT_LEN]; };
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
    if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;

    __u32 src_ip = iph->saddr;
    if (bpf_map_lookup_elem(&blacklist_map, &src_ip)) { if (st) st->xdp_drops++; return XDP_DROP; }
    if (bpf_map_lookup_elem(&whitelist_map, &src_ip)) return XDP_PASS;

    if (iph->ihl != 5 || iph->ttl == 0 || iph->ttl == 65 || iph->ttl == 129 || (iph->frag_off & bpf_htons(0x3FFF)) != 0) {
        if (st) st->xdp_drops++;
        return XDP_DROP;
    }

    __u64 wire_len = (__u64)((long)data_end - (long)data);
    if (wire_len == 0) return XDP_PASS;
    __u32 cap_len = wire_len > ZK_MAX_PKT_LEN ? ZK_MAX_PKT_LEN : (__u32)wire_len;

    struct zk_pkt_event *ev = bpf_ringbuf_reserve(&ringbuf_map, sizeof(*ev), 0);
    if (!ev) { if (st) st->ringbuf_drops++; return XDP_PASS; }
    ev->wire_len = (__u32)wire_len;
    ev->cap_len  = cap_len;
    if (bpf_xdp_load_bytes(ctx, 0, ev->data, cap_len) < 0) { bpf_ringbuf_discard(ev, 0); return XDP_PASS; }
    bpf_ringbuf_submit(ev, 0);
    if (st) st->ringbuf_sent++;
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
