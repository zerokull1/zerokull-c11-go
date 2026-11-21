# ZEROKULL

[![CI](https://github.com.git)](https://github.com.git)
![Standard](https://shields.io)
![Kernel](https://shields.io)
![License](https://shields.io)

**ZEROKULL** — сверхкомпактный детерминированный движок периметровой защиты и инспекции трафика (L3–L7) для Linux, написанный на стандартном **C11** и **eBPF/XDP (`libbpf`)**.

Проект спроектирован с нулевым числом внешних runtime-зависимостей (кроме стандартного `glibc` и `libbpf`), без динамических аллокаций на горячем пути и с полным размещением рабочих таблиц в кэше L1/L2 процессора.

---

## Архитектура конвейера

```text
  [ Входящий кадр NIC ]
           │
           ▼
┌──────────────────────────────────────────────────────────┐
│ Ядро Linux: eBPF XDP Hook (bpf/xdp_guard.bpf.c)          │
│  ├─ 1. L1 Blacklist Lookup (BPF_MAP_TYPE_LRU_HASH) ──► XDP_DROP
│  ├─ 2. Whitelist Bypass (BPF_MAP_TYPE_HASH)    ──► XDP_PASS
│  └─ 3. Zero-Copy Reserve (BPF_MAP_TYPE_RINGBUF, 256 KB)  │
└──────────┬───────────────────────────────────────────────┘
           │ shared mmap ring (0 sk_buff copies)
           ▼
┌──────────────────────────────────────────────────────────┐
│ User-Space Engine: C11 (src/engine.c + src/daemon.c)     │
│  ├─ L2/L3 Guard: 802.1Q/AD VLAN, IHL != 5, TTL (0/65/129), фрагм.│
│  ├─ L4/L7 Inspectors: SMB1 (0xFF'SMB'), TLS 1.x, SCADA   │
│  ├─ Stateful Flow Tracker (256 слотов, 4 KB L1d):        │
│  │   • TCP/TLS FSM Out-of-Order (данные мимо рукопожатия) │
│  │   • Covert Tunnel Drift (POPCNT EMA + фикс. длина L7) │
│  └─ Обратная связь: VERDICT_BAN ──► bpf_map_update_elem() │
└──────────────────────────────────────────────────────────┘
```

## Ключевые характеристики

| Параметр | Значение |
| :--- | :--- |
| **Data-Plane** | ISO C11 (84.82 Mpps / 38.81 cyc/pkt) (`-O3 -Wall -Wextra -Werror`) + eBPF C |
| **Размер бинарника** | `~30 КБ` (`zerokull-daemon`) + `~12 КБ` (`xdp_guard.bpf.o`) |
| **Механизм доставки** | `BPF_MAP_TYPE_RINGBUF` + `bpf_xdp_load_bytes` |
| **Аппаратное ускорение** | SSE4.2 `CRC32C` (`__builtin_ia32_crc32si`) и `POPCNT` с переносимым fallback для ARM64 |
| **Control-Plane** | Go 1.22+ (zero-dependency `zerokull-ctl`: CLI, JSON API & Prometheus `/metrics`) |
| **Таблица потоков** | Фиксированный кольцевой массив на 256 слотов (`4 КБ`), `0` вызовов `malloc` в цикле |

---

## Структура репозитория

```text
zerokull/
├── bpf/
│   └── xdp_guard.bpf.c       # Ядерный XDP-фильтр, карты blacklist/whitelist, per-CPU статистика и Ringbuf
├── include/
│   └── zerokull.h            # Структуры событий, слотов потоков и API инспектора
├── src/
│   ├── engine.c              # Детерминированные L3–L7 инспекторы и Stateful FSM / Entropy Drift
│   ├── daemon.c
│   └── stat.c              # Загрузчик libbpf skeleton и цикл ring_buffer__poll()
├── tests/
│   └── test_suite.c          # Модульные и поведенческие тесты (0 FP, TTL, SMB1, FSM, Covert Tunnel)
├── .github/workflows/ci.yml  # Автоматическая сборка и прогон тестов в GitHub Actions
├── Makefile                  # Сборка, тестирование и установка
└── LICENSE                   # GNU General Public License v3.0
```

---

## Требования и быстрый старт

### Зависимости (Arch Linux / Debian / Ubuntu)

* **Arch Linux:** `sudo pacman -S gcc clang llvm libbpf bpftool`
* **Ubuntu / Debian:** `sudo apt install gcc clang llvm libbpf-dev libelf-dev zlib1g-dev bpftool`

### Сборка и прогон автотестов

```bash
git clone https://github.com.git/zerokull.git
cd zerokull-c11-go
make
make test
```

Ожидаемый вывод автотестов:
```text
[TEST PASS] inspected=51 drops=5 bans=3
```

### Запуск на сетевом интерфейсе

```bash
sudo make install
sudo zerokull-daemon eth0

# Live zero-syscall telemetry reader (/dev/shm/zerokull_stats)
zerokull-stat -w

# Go Control-Plane: статус и экспортёр Prometheus / JSON
zerokull-ctl status
zerokull-ctl serve 127.0.0.1:9109
```

При получении `SIGINT` или `SIGTERM` демон корректно выводит итоговую статистику (`inspected`, `drops`, `bans`) и автоматически отключает XDP-хук от сетевого интерфейса.

---

## Лицензия

Распространяется под лицензией **GNU General Public License v3.0** (`LICENSE`).
