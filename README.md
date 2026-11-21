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
