#ifndef __SKB_LIFESPAN_H
#define __SKB_LIFESPAN_H

#define TASK_COMM_LEN 16
#define IFNAMSIZ 16
#define MAX_FUNC_LEN 32

/* Bitmask for in-kernel tracked operations & diagnostics */
#define OP_ALLOC          (1 << 0)
#define OP_CLONE          (1 << 1)
#define OP_COPY           (1 << 2)
#define OP_COALESCE       (1 << 3)
#define OP_SPLIT          (1 << 4)
#define OP_QUEUE          (1 << 5)
#define OP_GRO            (1 << 6)
#define OP_GSO            (1 << 7)
#define OP_NIC_WAIT       (1 << 8)  /* Inter-cycle delay > 100us */
#define OP_CPU_PREEMPTED  (1 << 9)  /* Context switch occurred during refill delay */
#define OP_HARD_IRQ_DELAY (1 << 10) /* Hard IRQ executed during refill delay */
#define OP_THREADED_NAPI             (1 << 11) /* Executed inside ksoftirqd thread */
#define OP_NIC_DESCRIPTOR_EXHAUSTION (1 << 12) /* Free hardware RX descriptors == 0 */
#define OP_TAIL_POINTER_STALL        (1 << 13) /* Driver Tail Pointer refill stalled */
#define OP_APPEND                    (1 << 14) /* Surgical data append operation */

enum skb_event_type {
    EVENT_STRUCT_CHANGE = 1,  /* CLONE, COALESCE, SPLIT */
    EVENT_LIFESPAN_SUMMARY,   /* Aggregated summary on SKB completion */
    EVENT_FREE_DATA,          /* Data buffer destruction */
};

struct skb_event {
    unsigned long long timestamp_ns;
    unsigned long long lifespan_ns;     /* Intra-cycle latency (Packet processing duration) */
    unsigned long long inter_cycle_ns;  /* Inter-cycle latency (Time since last free to alloc) */
    unsigned long long skb_addr;        /* Pointer to struct sk_buff */
    unsigned long long head_addr;       /* Pointer to skb->head */
    unsigned long long target_skb;      /* Cloned or coalesced SKB target */
    unsigned int event_type;            /* enum skb_event_type */
    unsigned int pid;
    unsigned int len;
    unsigned int data_len;
    unsigned short users;               /* skb->users refcount */
    unsigned short dataref;             /* skb_shared_info(skb)->dataref */
    unsigned short cloned;              /* skb->cloned flag */
    unsigned short op_flags;            /* Bitmask of all operations encountered */
    
    /* Scheduler Preemption Correlation */
    unsigned char cpu_preempted;        /* 1 if context switch occurred during inter-cycle delay */
    unsigned int preempt_pid;           /* PID of preempting task */
    unsigned int preempt_prio;          /* Priority of preempting task */
    char preempt_comm[TASK_COMM_LEN];   /* Comm name of preempting task */

    /* Hard IRQ Latency Correlation */
    unsigned char irq_preempted;        /* 1 if Hard IRQ handler executed during delay */
    int irq_number;                     /* IRQ number */
    char irq_name[32];                  /* Hard IRQ handler name */

    /* NIC Hardware Queue & Driver Tail Pointer Diagnostics */
    unsigned int free_descriptors;      /* Available RX descriptors in hardware queue */
    unsigned long long tail_ptr;        /* Driver Tail Pointer index / doorbell offset */
    unsigned long long tail_stall_ns;   /* Duration since last driver Tail Pointer update */

    char comm[TASK_COMM_LEN];
    char func_name[MAX_FUNC_LEN];
    char ifname[IFNAMSIZ];
    unsigned int saddr;                 /* IPv4 src addr */
    unsigned int daddr;                 /* IPv4 dst addr */
    unsigned short sport;               /* Src port */
    unsigned short dport;               /* Dst port */
    unsigned char protocol;             /* IP protocol */
    unsigned char drop_reason;
};

/* In-kernel aggregated metrics summary */
struct skb_metrics {
    unsigned long long total_allocs;
    unsigned long long total_clones;
    unsigned long long total_coalesces;
    unsigned long long total_splits;
    unsigned long long total_frees;
    unsigned long long ringbuf_drops;
    unsigned long long nic_wait_events;        /* Count of inter-cycle latency > 100us */
    unsigned long long cpu_preempt_events;     /* Count of NIC delays caused by CPU preemption */
    unsigned long long hard_irq_events;        /* Count of NIC delays caused by Hard IRQs */
    unsigned long long zero_descriptor_events; /* Count of 0 free hardware descriptor occurrences */
    unsigned long long tail_stall_events;      /* Count of driver tail pointer refill stalls */
    unsigned long long total_appends;          /* Count of skb_append operations */
    unsigned long long total_gso_segments;     /* Count of GSO egress skb_segment operations */
    unsigned long long max_inter_cycle_ns;
};

#endif /* __SKB_LIFESPAN_H */
