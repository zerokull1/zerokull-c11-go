# ZEROKULL-C11-GO

**ZEROKULL-C11-GO** — сверхкомпактный детерминированный движок периметровой защиты и инспекции трафика (L3–L7) для Linux на базе eBPF/XDP, ISO C11 и Go.

## Архитектура и характеристики

* **1. Kernel Space (eBPF XDP):** Блокировки по черному списку (LRU Hash), белый список и Zero-Copy Ringbuf (256 KB).
* **2. Data-Plane (ISO C11 + 16-bit Millicode VM):** Программируемые 16-битные микропрограммы политики (`zk_exec_millicode`), Инспекция L2–L7 (TLS, HTTP/2, SMB1), stateful-таблица потоков и производительность **84.82 Mpps**.
* **3. Control-Plane (Go 1.22+):** Статическая CLI-утилита `zerokull-ctl` с поддержкой Prometheus `/metrics` и JSON API.

## Быстрый старт

### Зависимости (Ubuntu / Debian / Arch)

* **Arch:** `sudo pacman -S gcc clang llvm libbpf bpftool go`
* **Ubuntu/Debian:** `sudo apt install gcc clang llvm libbpf-dev libelf-dev zlib1g-dev bpftool golang-go`

### Сборка и запуск

```bash
git clone https://github.com && cd zerokull-c11-go
make && make test && go test -v ./...
sudo make install && sudo zerokull-daemon eth0
zerokull-ctl status
zerokull-ctl serve 127.0.0.1:9109
```

## Лицензия

Этот проект распространяется под лицензией **GNU Affero General Public License v3.0 (AGPL-3.0)** — см. файл [`LICENSE`](LICENSE). Любое использование модифицированных версий в сетевых и облачных сервисах требует раскрытия исходного кода.


## Multi-Port XDP Mesh (1..1024 Interfaces)
- By default (`./build/zerokull-daemon` or `all`), the daemon attaches the eBPF/XDP guard across **all active physical interfaces simultaneously** (up to 1024 ports) and automatically binds newly hot-plugged NICs every 100ms while sharing a unified LRU blacklist.

## Hardening & Anti-Eviction Guarantees
- **Flow-Slot Anti-Eviction Lock:** Warmed flow state slots (`pkt_count >= 8`) are protected against single-packet hash-collision slot eviction (`src/engine.c`).
- **L3/L4 Anomaly & Scan Filtering:** Immediate deterministic drop of IPv4 fragments (`MF` / `offset > 0`), non-standard `IHL != 5`, `TTL 0/65/129`, and anomalous TCP flag combinations (`Null`, `FIN-only`, `SYN+FIN`, `XMAS`).
- **IPv6 & Bogon/Martian XDP Filtering:** Early driver-level inspection of IPv6 headers (`HopLimit` anomalies & Fragment Extension Header `44`), IPv4 `tot_len` validation, Bogon/Martian source drop (`0.0.0.0`, `255.255.255.255`, `127.0.0.0/8`), and per-event `ingress_ifindex` tagging in `BPF_MAP_TYPE_RINGBUF`.

## Adaptive Multi-WAN ECMP & Early-Boot Perimeter Lock

- **Adaptive Multi-WAN (`deploy/zeromani-multiwan.sh` + `deploy/zeromani-multiwan-watchdog.py`):** Automatically aggregates all active uplinks (USB tethering, Wi-Fi, Ethernet) via L4 ECMP (`fib_multipath_hash_policy=1`), binds active flows with `nftables` Sticky Connmark (`ct mark`) and Per-NIC SNAT (`snat ip to`), enforces outbound `TTL=65` + `MTU 1380` + `FQ`, and dynamically recalculates `nexthop` weights every 3 seconds based on live RTT and packet loss.
- **Early-Boot `network-pre.target` Lock (`deploy/install-early-boot.sh`):** Binds `nftables.service`, `zeromani-18caps.service` (All-Ports XDP Mesh), and `zeromani-core3-guard.service` strictly `Before=network-pre.target NetworkManager.service`, eliminating the warm/cold reboot race window before NICs and DHCP come online.
- **Mobile Gateway XDP Compatibility:** Permits inbound `TTL=65` / `HopLimit=65` frames at the XDP ingress layer for seamless operation behind mobile tethering gateways.

## 30-Second Reproducible Audit Stand

Run a full end-to-end verification (build, unit tests, isolated `netns` `BPF_LINK_XDP` attachment, mixed exploit injection, zero-syscall `/dev/shm` telemetry, and Go JSON/Prometheus API) in a single command:

```bash
sudo ./tools/demo_audit_30s.sh
```
