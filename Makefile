CC ?= gcc
CLANG ?= clang
BPFTOOL ?= bpftool

CFLAGS ?= -O2 -g -Wall -I./bpf
LDFLAGS ?= -lbpf -lelf -lz

BPF_OBJ = bpf/skb_lifespan.bpf.o
SKEL_H = bpf/skb_lifespan.skel.h
C_BIN = bin/skb_lifespan_c
RUST_BIN = bin/skb_lifespan_rust

all: $(C_BIN) $(RUST_BIN)

bpf/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): bpf/skb_lifespan.bpf.c bpf/skb_lifespan.h bpf/vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 -I./bpf -I/usr/include -c $< -o $@

$(SKEL_H): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(C_BIN): c_src/skb_lifespan.c $(SKEL_H)
	mkdir -p bin
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

$(RUST_BIN): $(BPF_OBJ) src/*.rs Cargo.toml build.rs
	cargo build --release
	mkdir -p bin
	cp target/release/skb_lifespan $(RUST_BIN)

clean:
	rm -rf bpf/*.o bpf/*.skel.h bin/* target/

.PHONY: all clean
