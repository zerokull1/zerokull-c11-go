CC      ?= gcc
CLANG   ?= clang
BPFTOOL ?= bpftool
ARCH    := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CFLAGS  := -O3 -std=c11 -Wall -Wextra -Werror -Iinclude -Ibuild
LDFLAGS := $(shell pkg-config --libs libbpf) -lelf -lz

.PHONY: all clean test install uninstall

all: build/zerokull-daemon build/zerokull-stat build/zerokull-ctl build/test_suite

build:
	mkdir -p build

MULTIARCH := $(shell $(CC) -print-multiarch 2>/dev/null)
BPF_INC   := $(if $(MULTIARCH),-I/usr/include/$(MULTIARCH),)

build/xdp_guard.bpf.o: bpf/xdp_guard.bpf.c | build
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -Iinclude $(BPF_INC) -c $< -o $@

build/xdp_guard.skel.h: build/xdp_guard.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

build/zerokull-daemon: src/daemon.c src/engine.c include/zerokull.h build/xdp_guard.skel.h
	$(CC) $(CFLAGS) src/daemon.c src/engine.c -o $@ $(LDFLAGS)

build/zerokull-stat: src/stat.c include/zerokull.h | build
	$(CC) $(CFLAGS) src/stat.c -o $@

build/zerokull-ctl: cmd/zerokull-ctl/main.go go.mod | build
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $@ ./cmd/zerokull-ctl

build/test_suite: tests/test_suite.c src/engine.c include/zerokull.h | build
	$(CC) $(CFLAGS) tests/test_suite.c src/engine.c -o $@

test: build/test_suite
	./build/test_suite

install: build/zerokull-daemon build/zerokull-stat
	install -Dm755 build/zerokull-daemon /usr/local/bin/zerokull-daemon
	install -Dm755 build/zerokull-stat /usr/local/bin/zerokull-stat
	install -Dm755 build/zerokull-ctl /usr/local/bin/zerokull-ctl

uninstall:
	rm -f /usr/local/bin/zerokull-daemon /usr/local/bin/zerokull-stat /usr/local/bin/zerokull-ctl

clean:
	rm -rf build
