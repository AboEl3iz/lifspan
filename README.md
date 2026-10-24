# `skb-lifespan` - Linux Kernel `sk_buff` Lifespan & IRQ/Sched Visualizer

`skb-lifespan` is a kernel observability tool built using **eBPF CO-RE (BTF `fentry`/`fexit`, `tp_btf/sched_switch`, `tp_btf/irq_handler_entry`/`exit`)**, **C**, and **Rust**. It provides **3-Way Root Cause Disambiguation** for NIC receive buffer refill delays by correlating memory refills with **Hard IRQ Handlers** and **Scheduler Context Switches**.

---

## ⚡ 3-Way Diagnostic Root Cause Disambiguation

When an inter-cycle memory refill delay occurs (> 100 µs), the tool disambiguates between three distinct failure modes:

1. **Hard IRQ Stall (`OP_HARD_IRQ_DELAY`)**:
   - Traced via `tp_btf/irq_handler_entry` & `irq_handler_exit`.
   - **Root Cause**: A device driver's Hard IRQ handler (e.g., NVMe/disk interrupt handler) ran on the CPU during the refill delay, stalling NIC buffer refills without triggering a scheduler context switch.
   - **Attribution**: Identifies the exact IRQ number and handler name (`irq_name`, e.g., `"nvme0q2"`).

2. **Scheduler Preemption & SoftIRQ Starvation (`OP_CPU_PREEMPTED`)**:
   - Traced via `tp_btf/sched_switch`.
   - **Root Cause**: A higher-priority user/kernel task preempted the CPU core, preventing NAPI / `ksoftirqd` from refilling the RX ring.
   - **Attribution**: Identifies the exact competing task (`preempt_comm`, `preempt_pid`, `preempt_prio`).

3. **Slab / Page Allocator Memory Contention (`OP_NIC_WAIT`)**:
   - **Root Cause**: Neither Hard IRQ handlers nor context switches occurred during the delay. The stall is caused by Linux kernel memory subsystem / slab allocator contention.

### SoftIRQ Execution Mode Awareness
- Tracks whether SoftIRQ execution occurred via **Threaded NAPI (`ksoftirqd/X`)** or direct interrupt tail (`OP_THREADED_NAPI`).

---

## 🎛 Driver Hardware Queue Descriptors & Tail Pointer Monitoring

The tool monitors driver-level hardware ring buffer descriptors and driver **Tail Pointer** updates:

1. **Free Descriptors Count & Zero-Descriptor Alarm (`OP_NIC_DESCRIPTOR_EXHAUSTION`)**:
   - Monitors available free RX descriptors in host memory rings.
   - **Zero-Descriptor Alert**: When free descriptors hit **0**, the NIC's internal hardware FIFO runs out of DMA target buffers, causing immediate hardware packet drops at the MAC/PHY layer before the Linux kernel is aware of the packets.

2. **Tail Pointer Refill Starvation (`OP_TAIL_POINTER_STALL`)**:
   - Monitors the driver's Tail Pointer register updates (doorbell writes telling NIC how many buffers are prepared).
   - **Tail Pointer Stall**: If the Tail Pointer remains unchanged for > 100 µs while active traffic arrives, the tool flags driver refill starvation.

---

## 🔄 Kernel SKB Transformation Event Probes

The engine attaches explicit BTF probes to trace all kernel functions that modify `sk_buff` structure:

1. **Coalescing (`tcp_try_coalesce` & `skb_try_coalesce`)**:
   - Explicit probe on `tcp_try_coalesce()` / `skb_try_coalesce()`.
   - **Diagnostic**: When an SKB dies while its data buffer survives, the tool explicitly attributes: *"This SKB header died because it was coalesced into target SKB 0x..."*.

2. **Splitting & Appending (`skb_split` & `skb_append`)**:
   - Explicit probes on `skb_split()` (splits `skb_shared_info` data boundary into two SKBs) and `skb_append()` (surgical data append).
   - **Graph Representation**: Renders directed graph edges showing packet split boundaries and surgical appends.

3. **GSO Outbound Egress Path (`skb_segment`)**:
   - Explicit probe on `skb_segment()` during TCP/UDP Segmentation Offload on egress.
   - **Outbound Tracing**: Traces outbound traffic (e.g., `iperf3`, `curl`, `FTP`) where large super-SKBs (64KB) are split into smaller MTU-sized packets before being handed to the driver `dev_queue_xmit()`.

---

## 🔑 Solving the Cloning Challenge (`skb_clone`)

When the Linux kernel calls `skb_clone(skb, gfp_mask)`:
1. A **new header pointer** (`skb_child`) is allocated.
2. Both `skb_parent` and `skb_child` point to the **same underlying data buffer** (`skb->head`).
3. `skb->cloned` flag is set to `1`.
4. `skb_shared_info(skb)->dataref` counter is incremented.

### Header vs Data Buffer Disambiguation
- **Header Free (`consume_skb`)**: When `skb->users` drops to 0, the `struct sk_buff` memory header is freed. If `dataref > 1`, the physical data buffer **survives** because sibling cloned SKBs still reference it!
- **Data Buffer Free (`skb_release_data`)**: Occurs ONLY when `dataref` reaches 0.

---

## 🛠 Project Architecture

```
/media/karim/New Volume16/devops/tools/lifspan/
├── Makefile                # Top-level build orchestrator (C & Rust)
├── bpf/
│   ├── skb_lifespan.h      # Shared C/Rust event structure & enum types
│   ├── skb_lifespan.bpf.c  # eBPF program with IRQ & sched_switch correlation
│   ├── vmlinux.h           # Kernel BTF definitions
│   └── skb_lifespan.skel.h # Generated skeleton header
├── c_src/
│   └── skb_lifespan.c      # C ringbuffer consumer & logger
├── Cargo.toml              # Rust crate dependencies
├── build.rs                # Rust build script linking libbpf, libelf, zlib
└── src/
    ├── main.rs             # Rust CLI entry point & orchestrator
    ├── bpf.rs              # FFI bindings for libbpf C library
    ├── tracker.rs          # State engine for headers, buffers, and latency
    ├── events.rs           # Processed event types and 5-tuple parsing
    ├── cli.rs              # Terminal ASCII tree graph renderer
    ├── web.rs              # HTTP server hosting visual dashboard
    └── index.html          # Embedded HTML5 + Vis.js graph UI
```

---

## 🚀 Building & Running

```bash
make
```

Binaries:
- `bin/skb_lifespan_c` - Standalone C tracer.
- `bin/skb_lifespan_rust` - Rust graph engine with built-in Interactive Web Dashboard.

### Usage
```bash
# Launch Rust engine with Interactive Web UI on http://localhost:8080
sudo ./bin/skb_lifespan_rust --port 8080

# Launch terminal CLI mode
sudo ./bin/skb_lifespan_rust --no-web
```
