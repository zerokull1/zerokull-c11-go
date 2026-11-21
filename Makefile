CC      ?= gcc
CLANG   ?= clang
BPFTOOL ?= bpftool
ARCH    := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CFLAGS  := -O3 -std=c11 -Wall -Wextra -Werror -Iinclude -Ibuild
LDFLAGS := $(shell pkg-config --libs libbpf) -lelf -lz

.PHONY: all clean test

all: build/zerokull-daemon build/test_suite

build:
	mkdir -p build

build/xdp_guard.bpf.o: bpf/xdp_guard.bpf.c | build
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -Iinclude -c $< -o $@

build/xdp_guard.skel.h: build/xdp_guard.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

build/zerokull-daemon: src/daemon.c src/engine.c include/zerokull.h build/xdp_guard.skel.h
	$(CC) $(CFLAGS) src/daemon.c src/engine.c -o $@ $(LDFLAGS)

build/test_suite: tests/test_suite.c src/engine.c include/zerokull.h | build
	$(CC) $(CFLAGS) tests/test_suite.c src/engine.c -o $@

test: build/test_suite
	./build/test_suite

clean:
	rm -rf build
