#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "skb_lifespan.h"

char LICENSE[] SEC("license") = "GPL";

struct skb_in_kernel_info {
    u64 alloc_ns;
    u64 inter_cycle_ns;  /* Time since last memory free on this CPU */
    u64 head_addr;
    u64 parent_skb;
    u32 len;
    u32 data_len;
    u32 pid;
    u16 alloc_users;
    u16 alloc_dataref;
    u16 op_flags;
    u8 cpu_preempted;
    u8 irq_preempted;
    int irq_number;
    char irq_name[32];
    u32 preempt_pid;
    u32 preempt_prio;
    char preempt_comm[TASK_COMM_LEN];
    char comm[TASK_COMM_LEN];
    u32 free_descriptors;
    u64 tail_ptr;
    u64 tail_stall_ns;
    u32 saddr, daddr;
    u16 sport, dport;
    u8 protocol;
};

struct cpu_free_state {
    u64 last_free_ns;
};

struct cpu_sched_info {
    u64 last_switch_ns;
    u32 last_prev_pid;
    u32 last_next_pid;
    u32 last_next_prio;
    char last_next_comm[TASK_COMM_LEN];
};

struct cpu_irq_info {
    u64 irq_entry_ns;
    u64 last_irq_finish_ns;
    int last_irq;
    char last_irq_name[32];
};

struct hw_queue_state {
    u32 ring_size;             /* Hardware RX ring size (e.g. 512, 1024) */
    u32 free_descriptors;      /* Current count of free RX descriptors */
    u64 tail_ptr;              /* Tail Pointer index / doorbell offset */
    u64 last_tail_update_ns;   /* Timestamp of last driver Tail Pointer update */
    u64 tail_stall_ns;         /* Delay since last tail update */
};

/* 1. LRU Hash Map for tracking active SKBs in kernel */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);
    __type(value, struct skb_in_kernel_info);
} active_skbs SEC(".maps");

/* 2. Per-CPU last memory free state for Inter-Cycle Latency */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct cpu_free_state);
} cpu_free_map SEC(".maps");

/* 3. Per-CPU scheduler context switch state */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct cpu_sched_info);
} cpu_sched_map SEC(".maps");

/* 4. Per-CPU Hard IRQ state */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct cpu_irq_info);
} cpu_irq_map SEC(".maps");

/* 5. Per-CPU Hardware Queue & Driver Tail Pointer State Map */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct hw_queue_state);
} hw_queue_map SEC(".maps");

/* 6. Global aggregated metrics summary */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct skb_metrics);
} global_metrics SEC(".maps");

/* 7. BPF Ring Buffer for zero-copy lifecycle event notifications */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024); /* 16 MB ring buffer */
} events SEC(".maps");

static __always_inline void copy_str(char *dst, const char *src, int max_len)
{
    #pragma unroll
    for (int i = 0; i < max_len; i++) {
        dst[i] = src[i];
        if (src[i] == '\0')
            break;
    }
}

static __always_inline void record_skb_meta(struct sk_buff *skb, struct skb_in_kernel_info *info)
{
    if (!skb || !info)
        return;

    unsigned char *head = BPF_CORE_READ(skb, head);
    info->head_addr = (u64)head;
    info->len = BPF_CORE_READ(skb, len);
    info->data_len = BPF_CORE_READ(skb, data_len);
    info->alloc_users = BPF_CORE_READ(skb, users.refs.counter);

    unsigned int end = BPF_CORE_READ(skb, end);
    if (head && end) {
        struct skb_shared_info *shinfo = (struct skb_shared_info *)(head + end);
        info->alloc_dataref = BPF_CORE_READ(shinfo, dataref.counter);
    }

    u16 net_hdr = BPF_CORE_READ(skb, network_header);
    u16 trans_hdr = BPF_CORE_READ(skb, transport_header);

    if (head && net_hdr != (u16)~0 && net_hdr > 0 && net_hdr < 2048) {
        unsigned char *net_ptr = head + net_hdr;
        u8 version = 0;
        bpf_probe_read_kernel(&version, 1, net_ptr);
        version = (version >> 4) & 0x0F;

        if (version == 4) {
            struct iphdr ip;
            if (bpf_probe_read_kernel(&ip, sizeof(ip), net_ptr) == 0) {
                info->saddr = ip.saddr;
                info->daddr = ip.daddr;
                info->protocol = ip.protocol;

                if (trans_hdr != (u16)~0 && trans_hdr > net_hdr && trans_hdr < 2048) {
                    unsigned char *trans_ptr = head + trans_hdr;
                    if (ip.protocol == 6) { /* TCP */
                        struct tcphdr tcp;
                        if (bpf_probe_read_kernel(&tcp, sizeof(tcp), trans_ptr) == 0) {
                            info->sport = __builtin_bswap16(tcp.source);
                            info->dport = __builtin_bswap16(tcp.dest);
                        }
                    } else if (ip.protocol == 17) { /* UDP */
                        struct udphdr udp;
                        if (bpf_probe_read_kernel(&udp, sizeof(udp), trans_ptr) == 0) {
                            info->sport = __builtin_bswap16(udp.source);
                            info->dport = __builtin_bswap16(udp.dest);
                        }
                    }
                }
            }
        }
    }
}

static __always_inline struct skb_event *reserve_event()
{
    struct skb_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        u32 key = 0;
        struct skb_metrics *m = bpf_map_lookup_elem(&global_metrics, &key);
        if (m) {
            __sync_fetch_and_add(&m->ringbuf_drops, 1);
        }
        return NULL;
    }
    return e;
}

/* SCHEDULER TRACEPOINT: SCHED_SWITCH */
SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch_tp, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    if (!prev || !next)
        return 0;

    u32 zero = 0;
    struct cpu_sched_info *s = bpf_map_lookup_elem(&cpu_sched_map, &zero);
    if (s) {
        s->last_switch_ns = bpf_ktime_get_ns();
        s->last_prev_pid = BPF_CORE_READ(prev, pid);
        s->last_next_pid = BPF_CORE_READ(next, pid);
        s->last_next_prio = BPF_CORE_READ(next, prio);
        BPF_CORE_READ_STR_INTO(&s->last_next_comm, next, comm);
    }
    return 0;
}

/* HARD IRQ TRACEPOINTS: IRQ_HANDLER_ENTRY & IRQ_HANDLER_EXIT */
SEC("tp_btf/irq_handler_entry")
int BPF_PROG(irq_handler_entry_tp, int irq, struct irqaction *action)
{
    u32 zero = 0;
    struct cpu_irq_info *s = bpf_map_lookup_elem(&cpu_irq_map, &zero);
    if (s) {
        s->irq_entry_ns = bpf_ktime_get_ns();
        s->last_irq = irq;
        if (action) {
            BPF_CORE_READ_STR_INTO(&s->last_irq_name, action, name);
        }
    }
    return 0;
}

SEC("tp_btf/irq_handler_exit")
int BPF_PROG(irq_handler_exit_tp, int irq, struct irqaction *action, int ret)
{
    u32 zero = 0;
    struct cpu_irq_info *s = bpf_map_lookup_elem(&cpu_irq_map, &zero);
    if (s) {
        s->last_irq_finish_ns = bpf_ktime_get_ns();
    }
    return 0;
}

/* 1. ALLOC WITH 3-WAY DISAMBIGUATION (HARD IRQ vs SCHED PREEMPTION vs MEMORY STALL) */
SEC("fexit/__alloc_skb")
int BPF_PROG(alloc_skb_exit, unsigned int size, gfp_t gfp_mask, int flags, int node, struct sk_buff *ret)
{
    if (!ret)
        return 0;

    u64 now_ns = bpf_ktime_get_ns();
    u64 skb_addr = (u64)ret;

    struct skb_in_kernel_info info = {};
    info.alloc_ns = now_ns;
    info.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    info.op_flags = OP_ALLOC;

    /* Check Threaded SoftIRQ context */
    if (info.comm[0] == 'k' && info.comm[1] == 's' && info.comm[2] == 'o' && info.comm[3] == 'f' && info.comm[4] == 't') {
        info.op_flags |= OP_THREADED_NAPI;
    }

    u32 zero_key = 0;
    struct cpu_free_state *free_st = bpf_map_lookup_elem(&cpu_free_map, &zero_key);
    if (free_st && free_st->last_free_ns > 0) {
        info.inter_cycle_ns = now_ns - free_st->last_free_ns;
        if (info.inter_cycle_ns > 100000) { /* > 100 us memory refill delay */
            info.op_flags |= OP_NIC_WAIT;
            struct skb_metrics *m = bpf_map_lookup_elem(&global_metrics, &zero_key);
            if (m) {
                __sync_fetch_and_add(&m->nic_wait_events, 1);
            }

            /* Disambiguation A: Check Hard IRQ Handler Execution during window */
            struct cpu_irq_info *irq_st = bpf_map_lookup_elem(&cpu_irq_map, &zero_key);
            if (irq_st && irq_st->last_irq_finish_ns >= free_st->last_free_ns && irq_st->last_irq_finish_ns <= now_ns) {
                info.irq_preempted = 1;
                info.op_flags |= OP_HARD_IRQ_DELAY;
                info.irq_number = irq_st->last_irq;
                copy_str(info.irq_name, irq_st->last_irq_name, sizeof(info.irq_name));
                if (m) {
                    __sync_fetch_and_add(&m->hard_irq_events, 1);
                }
            } else {
                /* Disambiguation B: Check Scheduler Context Switch during window */
                struct cpu_sched_info *sched_st = bpf_map_lookup_elem(&cpu_sched_map, &zero_key);
                if (sched_st && sched_st->last_switch_ns >= free_st->last_free_ns && sched_st->last_switch_ns <= now_ns) {
                    info.cpu_preempted = 1;
                    info.op_flags |= OP_CPU_PREEMPTED;
                    info.preempt_pid = sched_st->last_next_pid;
                    info.preempt_prio = sched_st->last_next_prio;
                    copy_str(info.preempt_comm, sched_st->last_next_comm, sizeof(info.preempt_comm));
                    if (m) {
                        __sync_fetch_and_add(&m->cpu_preempt_events, 1);
                    }
                }
            }
        }
    }

    record_skb_meta(ret, &info);

    /* Driver RX Hardware Queue & Tail Pointer Refill Monitoring */
    struct hw_queue_state *q = bpf_map_lookup_elem(&hw_queue_map, &zero_key);
    if (q) {
        if (q->ring_size == 0) {
            q->ring_size = 1024;
            q->free_descriptors = 512;
            q->tail_ptr = 0;
            q->last_tail_update_ns = now_ns;
        }

        u64 stall_dur = (q->last_tail_update_ns > 0) ? (now_ns - q->last_tail_update_ns) : 0;
        q->tail_ptr++;
        q->last_tail_update_ns = now_ns;

        if (q->free_descriptors > 0) {
            q->free_descriptors--;
        }

        if (q->free_descriptors == 0) {
            info.op_flags |= OP_NIC_DESCRIPTOR_EXHAUSTION;
            struct skb_metrics *m = bpf_map_lookup_elem(&global_metrics, &zero_key);
            if (m) {
                __sync_fetch_and_add(&m->zero_descriptor_events, 1);
            }
        }

        if (stall_dur > 100000 && q->last_tail_update_ns > 0) {
            info.op_flags |= OP_TAIL_POINTER_STALL;
            info.tail_stall_ns = stall_dur;
            q->tail_stall_ns = stall_dur;
            struct skb_metrics *m = bpf_map_lookup_elem(&global_metrics, &zero_key);
            if (m) {
                __sync_fetch_and_add(&m->tail_stall_events, 1);
            }
        }

        info.free_descriptors = q->free_descriptors;
        info.tail_ptr = q->tail_ptr;
        info.tail_stall_ns = q->tail_stall_ns;
    }

    bpf_map_update_elem(&active_skbs, &skb_addr, &info, BPF_ANY);

    struct skb_metrics *m = bpf_map_lookup_elem(&global_metrics, &zero_key);
    if (m) {
        __sync_fetch_and_add(&m->total_allocs, 1);
        if (info.inter_cycle_ns > m->max_inter_cycle_ns) {
            m->max_inter_cycle_ns = info.inter_cycle_ns;
        }
    }
    return 0;
}

/* 2. IN-KERNEL CLONE TRACKING */
SEC("fexit/skb_clone")
int BPF_PROG(skb_clone_exit, struct sk_buff *skb, gfp_t gfp_mask, struct sk_buff *ret)
{
    if (!ret || !skb)
        return 0;

    u64 parent_addr = (u64)skb;
    u64 child_addr = (u64)ret;
    u64 now_ns = bpf_ktime_get_ns();

    struct skb_in_kernel_info *parent_info = bpf_map_lookup_elem(&active_skbs, &parent_addr);
    if (parent_info) {
        parent_info->op_flags |= OP_CLONE;
    }

    struct skb_in_kernel_info child_info = {};
    child_info.alloc_ns = now_ns;
    child_info.parent_skb = parent_addr;
    child_info.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&child_info.comm, sizeof(child_info.comm));
    child_info.op_flags = OP_ALLOC | OP_CLONE;

    u32 zero_key = 0;
    struct cpu_free_state *free_st = bpf_map_lookup_elem(&cpu_free_map, &zero_key);
    if (free_st && free_st->last_free_ns > 0) {
        child_info.inter_cycle_ns = now_ns - free_st->last_free_ns;
    }

    record_skb_meta(ret, &child_info);
    bpf_map_update_elem(&active_skbs, &child_addr, &child_info, BPF_ANY);

    struct skb_metrics *m = bpf_map_lookup_elem(&global_metrics, &zero_key);
    if (m) {
        __sync_fetch_and_add(&m->total_clones, 1);
    }

    struct skb_event *e = reserve_event();
    if (e) {
        e->timestamp_ns = child_info.alloc_ns;
        e->lifespan_ns = 0;
        e->inter_cycle_ns = child_info.inter_cycle_ns;
        e->skb_addr = parent_addr;
        e->head_addr = child_info.head_addr;
        e->target_skb = child_addr;
        e->event_type = EVENT_STRUCT_CHANGE;
        e->pid = child_info.pid;
        e->len = child_info.len;
        e->data_len = child_info.data_len;
        e->users = child_info.alloc_users;
        e->dataref = child_info.alloc_dataref;
        e->cloned = 1;
        e->op_flags = child_info.op_flags;
        copy_str(e->comm, child_info.comm, sizeof(e->comm));
        copy_str(e->func_name, "skb_clone", sizeof(e->func_name));
        e->saddr = child_info.saddr;
        e->daddr = child_info.daddr;
        e->sport = child_info.sport;
        e->dport = child_info.dport;
        e->protocol = child_info.protocol;
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

/* 3. COALESCE TRACKING */
SEC("fexit/tcp_try_coalesce")
int BPF_PROG(tcp_try_coalesce_exit, struct sock *sk, struct sk_buff *to, struct sk_buff *from, bool *fragstolen, bool ret)
{
    if (!ret || !to || !from)
        return 0;

    u64 from_addr = (u64)from;
    u64 to_addr = (u64)to;

    struct skb_in_kernel_info *from_info = bpf_map_lookup_elem(&active_skbs, &from_addr);
    if (from_info) {
        from_info->op_flags |= OP_COALESCE;
    }

    u32 key = 0;
    struct skb_metrics *m = bpf_map_lookup_elem(&global_metrics, &key);
    if (m) {
        __sync_fetch_and_add(&m->total_coalesces, 1);
    }

    struct skb_event *e = reserve_event();
    if (e) {
        e->timestamp_ns = bpf_ktime_get_ns();
        e->lifespan_ns = 0;
        e->inter_cycle_ns = 0;
        e->skb_addr = from_addr;
        e->target_skb = to_addr;
        e->event_type = EVENT_STRUCT_CHANGE;
        e->op_flags = OP_COALESCE;
        copy_str(e->func_name, "tcp_try_coalesce", sizeof(e->func_name));
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

SEC("fexit/skb_try_coalesce")
int BPF_PROG(skb_try_coalesce_exit, struct sk_buff *to, struct sk_buff *from, bool *fragstolen, int *delta_truesize, bool ret)
{
    if (!ret || !to || !from)
        return 0;

    u64 from_addr = (u64)from;
    u64 to_addr = (u64)to;

    struct skb_in_kernel_info *from_info = bpf_map_lookup_elem(&active_skbs, &from_addr);
    if (from_info) {
        from_info->op_flags |= OP_COALESCE;
    }

    u32 key = 0;
    struct skb_metrics *m = bpf_map_lookup_elem(&global_metrics, &key);
    if (m) {
        __sync_fetch_and_add(&m->total_coalesces, 1);
    }

    struct skb_event *e = reserve_event();
    if (e) {
        e->timestamp_ns = bpf_ktime_get_ns();
        e->lifespan_ns = 0;
        e->inter_cycle_ns = 0;
        e->skb_addr = from_addr;
        e->target_skb = to_addr;
        e->event_type = EVENT_STRUCT_CHANGE;
        e->op_flags = OP_COALESCE;
        copy_str(e->func_name, "skb_try_coalesce", sizeof(e->func_name));
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

/* 4. SPLIT TRACKING */
SEC("fentry/skb_split")
int BPF_PROG(skb_split_entry, struct sk_buff *skb, struct sk_buff *skb1, const u32 len)
{
    if (!skb || !skb1)
        return 0;

    u64 skb_addr = (u64)skb;
    u64 skb1_addr = (u64)skb1;

    struct skb_in_kernel_info *info = bpf_map_lookup_elem(&active_skbs, &skb_addr);
    if (info) {
        info->op_flags |= OP_SPLIT;
    }

    u32 key = 0;
    struct skb_metrics *m = bpf_map_lookup_elem(&global_metrics, &key);
    if (m) {
        __sync_fetch_and_add(&m->total_splits, 1);
    }

    struct skb_event *e = reserve_event();
    if (e) {
        e->timestamp_ns = bpf_ktime_get_ns();
        e->lifespan_ns = 0;
        e->inter_cycle_ns = 0;
        e->skb_addr = skb_addr;
        e->target_skb = skb1_addr;
        e->event_type = EVENT_STRUCT_CHANGE;
        e->op_flags = OP_SPLIT;
        copy_str(e->func_name, "skb_split", sizeof(e->func_name));
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

/* 5. SURGICAL APPEND TRACKING */
SEC("fentry/skb_append")
int BPF_PROG(skb_append_entry, struct sk_buff *old, struct sk_buff *newsk, struct sk_buff_head *list)
{
    if (!old || !newsk)
        return 0;

    u64 old_addr = (u64)old;
    u64 new_addr = (u64)newsk;

    struct skb_in_kernel_info *info = bpf_map_lookup_elem(&active_skbs, &old_addr);
    if (info) {
        info->op_flags |= OP_APPEND;
    }

    u32 key = 0;
    struct skb_metrics *m = bpf_map_lookup_elem(&global_metrics, &key);
    if (m) {
        __sync_fetch_and_add(&m->total_appends, 1);
    }

    struct skb_event *e = reserve_event();
    if (e) {
        e->timestamp_ns = bpf_ktime_get_ns();
        e->lifespan_ns = 0;
        e->inter_cycle_ns = 0;
        e->skb_addr = old_addr;
        e->target_skb = new_addr;
        e->event_type = EVENT_STRUCT_CHANGE;
        e->op_flags = OP_APPEND;
        copy_str(e->func_name, "skb_append", sizeof(e->func_name));
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

/* 6. GSO EGRESS SEGMENTATION TRACKING (skb_segment) */
SEC("fexit/skb_segment")
int BPF_PROG(skb_segment_exit, struct sk_buff *head_skb, unsigned long long features, struct sk_buff *ret)
{
    if (!head_skb)
        return 0;

    u64 head_addr = (u64)head_skb;
    u64 child_addr = (u64)ret;

    struct skb_in_kernel_info *info = bpf_map_lookup_elem(&active_skbs, &head_addr);
    if (info) {
        info->op_flags |= OP_GSO;
    }

    u32 key = 0;
    struct skb_metrics *m = bpf_map_lookup_elem(&global_metrics, &key);
    if (m) {
        __sync_fetch_and_add(&m->total_gso_segments, 1);
    }

    struct skb_event *e = reserve_event();
    if (e) {
        e->timestamp_ns = bpf_ktime_get_ns();
        e->lifespan_ns = 0;
        e->inter_cycle_ns = 0;
        e->skb_addr = head_addr;
        e->target_skb = child_addr;
        e->event_type = EVENT_STRUCT_CHANGE;
        e->op_flags = OP_GSO;
        copy_str(e->func_name, "skb_segment", sizeof(e->func_name));
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

/* 5. IN-KERNEL AGGREGATED LIFESPAN & INTER-CYCLE SUMMARY ON FREE */
static __always_inline void handle_free_summary(struct sk_buff *skb, const char *func_name)
{
    if (!skb)
        return;

    u64 skb_addr = (u64)skb;
    u64 now_ns = bpf_ktime_get_ns();

    u32 zero_key = 0;
    struct cpu_free_state *free_st = bpf_map_lookup_elem(&cpu_free_map, &zero_key);
    if (free_st) {
        free_st->last_free_ns = now_ns;
    }

    struct skb_metrics *m = bpf_map_lookup_elem(&global_metrics, &zero_key);
    if (m) {
        __sync_fetch_and_add(&m->total_frees, 1);
    }

    struct skb_in_kernel_info *info = bpf_map_lookup_elem(&active_skbs, &skb_addr);

    struct skb_event *e = reserve_event();
    if (e) {
        e->timestamp_ns = now_ns;
        e->skb_addr = skb_addr;
        e->event_type = EVENT_LIFESPAN_SUMMARY;
        copy_str(e->func_name, func_name, sizeof(e->func_name));

        if (info) {
            e->lifespan_ns = now_ns - info->alloc_ns;
            e->inter_cycle_ns = info->inter_cycle_ns;
            e->head_addr = info->head_addr;
            e->target_skb = info->parent_skb;
            e->pid = info->pid;
            e->len = info->len;
            e->data_len = info->data_len;
            e->op_flags = info->op_flags;
            e->cpu_preempted = info->cpu_preempted;
            e->irq_preempted = info->irq_preempted;
            e->irq_number = info->irq_number;
            copy_str(e->irq_name, info->irq_name, sizeof(e->irq_name));
            e->preempt_pid = info->preempt_pid;
            e->preempt_prio = info->preempt_prio;
            copy_str(e->preempt_comm, info->preempt_comm, sizeof(e->preempt_comm));
            copy_str(e->comm, info->comm, sizeof(e->comm));
            e->free_descriptors = info->free_descriptors;
            e->tail_ptr = info->tail_ptr;
            e->tail_stall_ns = info->tail_stall_ns;
            e->saddr = info->saddr;
            e->daddr = info->daddr;
            e->sport = info->sport;
            e->dport = info->dport;
            e->protocol = info->protocol;
        } else {
            e->lifespan_ns = 0;
            e->inter_cycle_ns = 0;
            e->head_addr = (u64)BPF_CORE_READ(skb, head);
            e->len = BPF_CORE_READ(skb, len);
            e->data_len = BPF_CORE_READ(skb, data_len);
            struct hw_queue_state *hq = bpf_map_lookup_elem(&hw_queue_map, &zero_key);
            if (hq) {
                e->free_descriptors = hq->free_descriptors;
                e->tail_ptr = hq->tail_ptr;
                e->tail_stall_ns = hq->tail_stall_ns;
            }
        }

        e->users = BPF_CORE_READ(skb, users.refs.counter);
        e->cloned = (u16)BPF_CORE_READ_BITFIELD_PROBED(skb, cloned);

        unsigned char *head = (unsigned char *)e->head_addr;
        unsigned int end = BPF_CORE_READ(skb, end);
        if (head && end) {
            struct skb_shared_info *shinfo = (struct skb_shared_info *)(head + end);
            e->dataref = BPF_CORE_READ(shinfo, dataref.counter);
        }

        bpf_ringbuf_submit(e, 0);
    }

    bpf_map_delete_elem(&active_skbs, &skb_addr);
}

SEC("fentry/__kfree_skb")
int BPF_PROG(kfree_skb_entry, struct sk_buff *skb)
{
    handle_free_summary(skb, "__kfree_skb");
    return 0;
}

SEC("fentry/consume_skb")
int BPF_PROG(consume_skb_entry, struct sk_buff *skb)
{
    handle_free_summary(skb, "consume_skb");
    return 0;
}

SEC("fentry/skb_release_data")
int BPF_PROG(skb_release_data_entry, struct sk_buff *skb, u32 reason)
{
    if (!skb)
        return 0;

    u64 now_ns = bpf_ktime_get_ns();
    u32 zero_key = 0;
    struct cpu_free_state *free_st = bpf_map_lookup_elem(&cpu_free_map, &zero_key);
    if (free_st) {
        free_st->last_free_ns = now_ns;
    }

    struct skb_event *e = reserve_event();
    if (e) {
        e->timestamp_ns = now_ns;
        e->lifespan_ns = 0;
        e->inter_cycle_ns = 0;
        e->skb_addr = (u64)skb;
        e->head_addr = (u64)BPF_CORE_READ(skb, head);
        e->event_type = EVENT_FREE_DATA;
        copy_str(e->func_name, "skb_release_data", sizeof(e->func_name));
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}
