# ZEROKULL — Deterministic XDP + Ringbuf & Stateful L3–L7 DPI Engine (C11)

Standard C11 + `libbpf` CO-RE port of the ZEROMANI packet inspection engine.

## Architecture
- `bpf/xdp_guard.bpf.c`: Kernel XDP hook with L1 `XDP_DROP` IPv4 blacklist map, whitelist map, per-CPU counters, and zero-copy `BPF_MAP_TYPE_RINGBUF`.
- `src/engine.c`: Portable C11 deterministic L3/L4/L7 packet inspectors + stateful flow tracker (TCP/TLS FSM anomaly detection & `POPCNT` EMA covert-tunnel entropy drift).
- `src/daemon.c`: `libbpf` skeleton loader and `ring_buffer__poll` event loop (`~30 KB` binary).
- `tests/test_suite.c`: Automated unit and behavioral verification suite.

## Build & Test
```bash
make && make test
sudo ./build/zerokull-daemon enp0s20u11
```
