#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../bpf/skb_lifespan.h"
#include "../bpf/skb_lifespan.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static const char *event_type_str(enum skb_event_type type)
{
    switch (type) {
    case EVENT_STRUCT_CHANGE:   return "STRUCT_CHANGE";
    case EVENT_LIFESPAN_SUMMARY:return "LIFESPAN_SUMMARY";
    case EVENT_FREE_DATA:       return "FREE_DATA";
    default:                    return "UNKNOWN";
    }
}

static void ip_to_str(unsigned int ip, char *buf, size_t size)
{
    struct in_addr addr;
    addr.s_addr = ip;
    inet_ntop(AF_INET, &addr, buf, size);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct skb_event *e = data;
    char saddr_str[32] = "-", daddr_str[32] = "-";

    if (e->saddr) ip_to_str(e->saddr, saddr_str, sizeof(saddr_str));
    if (e->daddr) ip_to_str(e->daddr, daddr_str, sizeof(daddr_str));

    printf("[%llu ns] %-16s | SKB: 0x%llx | Head: 0x%llx | PID: %d (%s) | Fn: %-18s\n",
           e->timestamp_ns,
           event_type_str(e->event_type),
           e->skb_addr,
           e->head_addr,
           e->pid,
           e->comm,
           e->func_name);

    if (e->event_type == EVENT_LIFESPAN_SUMMARY) {
        double intra_us = (double)e->lifespan_ns / 1000.0;
        double inter_us = (double)e->inter_cycle_ns / 1000.0;

        printf("  |- [INTRA-CYCLE LIFESPAN] Processing: %.2f us (%llu ns)\n", intra_us, e->lifespan_ns);

        if (e->inter_cycle_ns > 0) {
            if (e->irq_preempted || (e->op_flags & OP_HARD_IRQ_DELAY)) {
                printf("  |- [INTER-CYCLE LATENCY] Memory Refill: %.2f us -> [HARD IRQ STALL (Handler \"%s\", IRQ %d)]\n",
                       inter_us, e->irq_name, e->irq_number);
            } else if (e->cpu_preempted || (e->op_flags & OP_CPU_PREEMPTED)) {
                printf("  |- [INTER-CYCLE LATENCY] Memory Refill: %.2f us -> [CPU PREEMPTED by \"%s\" (PID %u, Prio %u)]\n",
                       inter_us, e->preempt_comm, e->preempt_pid, e->preempt_prio);
            } else if (e->op_flags & OP_NIC_WAIT) {
                printf("  |- [INTER-CYCLE LATENCY] Memory Refill: %.2f us -> [SLAB / MEMORY ALLOCATOR STALL]\n", inter_us);
            } else {
                printf("  |- [INTER-CYCLE LATENCY] Memory Refill: %.2f us\n", inter_us);
            }
        }

        const char *softirq_mode = (e->op_flags & OP_THREADED_NAPI) ? " [THREADED NAPI]" : "";
        printf("  |- Users: %u | Dataref: %u | Cloned: %u%s\n", e->users, e->dataref, e->cloned, softirq_mode);
        printf("  |- HW Queue: Free Descriptors: %u | Tail Pointer: %llu\n", e->free_descriptors, e->tail_ptr);

        if (e->op_flags & OP_NIC_DESCRIPTOR_EXHAUSTION) {
            printf("  ! [NIC HARDWARE FIFO RISK] 0 Free RX Descriptors remaining! High risk of hardware MAC drops!\n");
        }
        if (e->op_flags & OP_TAIL_POINTER_STALL) {
            double stall_us = (double)e->tail_stall_ns / 1000.0;
            printf("  ! [TAIL POINTER STALL] Driver tail pointer unchanged for %.2f us (Tail Ptr: %llu). System experiencing RX starvation!\n",
                   stall_us, e->tail_ptr);
        }

        if (e->dataref > 1) {
            printf("  [HEADER FREED ONLY] SKB Header 0x%llx freed, but Data Buffer 0x%llx SURVIVES (dataref=%u)\n",
                   e->skb_addr, e->head_addr, e->dataref - 1);
        } else {
            printf("  [SKB & DATA FREED] SKB Header 0x%llx freed, dataref reached 0.\n", e->skb_addr);
        }
    } else if (e->event_type == EVENT_STRUCT_CHANGE) {
        printf("  |- Operation: %s | Target SKB: 0x%llx\n", e->func_name, e->target_skb);
    } else if (e->event_type == EVENT_FREE_DATA) {
        printf("  [DATA BUFFER DESTROYED] Memory for Data Buffer 0x%llx released.\n", e->head_addr);
    }

    if (e->saddr && e->daddr) {
        printf("  |- Flow: %s:%u -> %s:%u (Proto: %u)\n",
               saddr_str, e->sport, daddr_str, e->dport, e->protocol);
    }

    printf("\n");
    return 0;
}

int main(int argc, char **argv)
{
    struct skb_lifespan_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("=== skb-lifespan (C 3-Way Disambiguation Engine) ===\n");
    printf("Loading eBPF programs and attaching BTF probes...\n");

    skel = skb_lifespan_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = skb_lifespan_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = skb_lifespan_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Successfully attached! Tracing lifespans with Hard IRQ & sched_switch correlation...\n");
    printf("Press Ctrl+C to exit.\n\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    skb_lifespan_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
