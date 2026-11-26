# ZEROKULL (zerokull1) | Author Signature: 0x5A45524F4B554C4CULL
# Copyright (c) 2026 zerokull1 (https://github.com)

CC      ?= gcc
CLANG   ?= clang
BPFTOOL ?= bpftool
ARCH    := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

OPT_FLAGS := -O3 -flto=auto -fno-plt -fno-semantic-interposition \
             -fno-asynchronous-unwind-tables -fomit-frame-pointer \
             -ffunction-sections -fdata-sections
ifeq ($(NATIVE),1)
OPT_FLAGS += -march=native -mtune=native
endif

CFLAGS   := $(OPT_FLAGS) -std=c11 -Wall -Wextra -Werror -Iinclude -Ibuild
BIN_LD   := -Wl,--gc-sections -s
LDFLAGS  := $(BIN_LD) $(shell pkg-config --libs libbpf) -lelf -lz -ldl

.PHONY: all clean test sha256 verify-sha256 install uninstall

all: build/zerokull-daemon build/zerokull-stat build/zero-tui build/zerokull-ctl build/test_suite

build:
	mkdir -p build

MULTIARCH := $(shell $(CC) -print-multiarch 2>/dev/null)
BPF_INC   := $(if $(MULTIARCH),-I/usr/include/$(MULTIARCH),)

build/xdp_guard.bpf.o: bpf/xdp_guard.bpf.c | build
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -Iinclude $(BPF_INC) -c $< -o $@

build/xdp_guard.skel.h: build/xdp_guard.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

build/libzk_policy_rs.a: rust_ctrl/Cargo.toml rust_ctrl/src/lib.rs | build
	cargo build --release --manifest-path rust_ctrl/Cargo.toml
	cp rust_ctrl/target/release/libzk_policy_rs.a $@

build/zerokull-daemon: src/daemon.c src/engine.c src/zk_gpu_ring.c build/libzk_policy_rs.a include/zerokull.h include/zk_policy.h build/xdp_guard.skel.h
	$(CC) $(CFLAGS) src/daemon.c src/engine.c src/zk_gpu_ring.c build/libzk_policy_rs.a -o $@ $(LDFLAGS)

build/zerokull-stat: src/stat.c include/zerokull.h | build
	$(CC) $(CFLAGS) src/stat.c -o $@ $(BIN_LD)

build/zero-tui: rust_ctrl/Cargo.toml rust_ctrl/src/bin/zero-tui.rs | build
	cargo build --release --bin zero-tui --manifest-path rust_ctrl/Cargo.toml
	cp rust_ctrl/target/release/zero-tui $@

build/zerokull-ctl: cmd/zerokull-ctl/main.go go.mod | build
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $@ ./cmd/zerokull-ctl

build/test_suite: tests/test_suite.c src/engine.c src/zk_gpu_ring.c include/zerokull.h | build
	$(CC) $(CFLAGS) tests/test_suite.c src/engine.c src/zk_gpu_ring.c -o $@ $(BIN_LD) -ldl

test: build/test_suite
	./build/test_suite

sha256: all
	sha256sum build/zerokull-daemon build/zerokull-stat build/zero-tui build/zerokull-ctl > build/SHA256SUMS.txt

verify-sha256: sha256 test
	sha256sum -c build/SHA256SUMS.txt

install: verify-sha256
	install -Dm755 build/zerokull-daemon /usr/local/bin/zerokull-daemon
	install -Dm755 build/zerokull-stat /usr/local/bin/zerokull-stat
	install -Dm755 build/zero-tui /usr/local/bin/zero-tui
	install -Dm755 build/zerokull-ctl /usr/local/bin/zerokull-ctl
	install -d -m 0755 /etc/zeromani
	test -f /etc/zeromani/policy.conf || install -m 0644 deploy/policy.conf /etc/zeromani/policy.conf

uninstall:
	rm -f /usr/local/bin/zerokull-daemon /usr/local/bin/zerokull-stat /usr/local/bin/zero-tui /usr/local/bin/zerokull-ctl

clean:
	rm -rf build
