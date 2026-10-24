use crate::events::{ProcessedEvent, SkbEventType};
use crate::tracker::SkbTracker;

pub fn print_cli_event(e: &ProcessedEvent) {
    let type_badge = match e.event_type {
        SkbEventType::StructChange => "\x1b[33m[STRUCT_CHANGE]\x1b[0m",
        SkbEventType::LifespanSummary => "\x1b[32m[LIFESPAN_SUMMARY]\x1b[0m",
        SkbEventType::FreeData => "\x1b[41;37m[FREE_DATA]\x1b[0m",
    };

    println!(
        "[{:>12} ns] {:<18} | SKB: {} | Head: {} | PID: {} ({}) | Fn: {}",
        e.timestamp_ns, type_badge, e.skb_addr, e.head_addr, e.pid, e.comm, e.func_name
    );

    if e.event_type == SkbEventType::LifespanSummary {
        let intra_latency_us = (e.lifespan_ns as f64) / 1000.0;
        let inter_latency_us = (e.inter_cycle_ns as f64) / 1000.0;

        println!(
            "  └─ \x1b[1;36m[INTRA-CYCLE LIFESPAN]\x1b[0m Packet Processing: {:.2} us ({} ns)",
            intra_latency_us, e.lifespan_ns
        );

        if e.inter_cycle_ns > 0 {
            if e.irq_preempted {
                println!(
                    "  └─ \x1b[1;31m[INTER-CYCLE LATENCY]\x1b[0m Refill Delay: {:.2} us -> \x1b[41;37m[HARD IRQ STALL (Handler: \"{}\", IRQ {})]\x1b[0m",
                    inter_latency_us, e.irq_name, e.irq_number
                );
            } else if e.cpu_preempted {
                println!(
                    "  └─ \x1b[1;31m[INTER-CYCLE LATENCY]\x1b[0m Refill Delay: {:.2} us -> \x1b[41;37m[CPU PREEMPTED by \"{}\" (PID {}, Prio {})]\x1b[0m",
                    inter_latency_us, e.preempt_comm, e.preempt_pid, e.preempt_prio
                );
            } else if e.nic_wait {
                println!(
                    "  └─ \x1b[1;31m[INTER-CYCLE LATENCY]\x1b[0m Refill Delay: {:.2} us -> \x1b[41;37m[SLAB / MEMORY ALLOCATOR STALL]\x1b[0m",
                    inter_latency_us
                );
            } else {
                println!(
                    "  └─ \x1b[1;32m[INTER-CYCLE LATENCY]\x1b[0m Memory Refill: {:.2} us ({} ns)",
                    inter_latency_us, e.inter_cycle_ns
                );
            }
        }

        let softirq_mode = if e.threaded_napi { " [THREADED NAPI]" } else { "" };
        println!(
            "  └─ RefCounts: [users: {}, dataref: {}, cloned: {}]{}",
            e.users, e.dataref, e.cloned, softirq_mode
        );
        println!(
            "  └─ HW Queue: Free Descriptors: {} | Tail Pointer: {}",
            e.free_descriptors, e.tail_ptr
        );

        if e.zero_descriptors {
            println!(
                "  ! \x1b[41;37m[NIC HARDWARE FIFO RISK]\x1b[0m 0 Free RX Descriptors remaining! High risk of hardware MAC drops!\x1b[0m"
            );
        }
        if e.tail_pointer_stalled {
            let stall_us = (e.tail_stall_ns as f64) / 1000.0;
            println!(
                "  ! \x1b[41;37m[TAIL POINTER STALL]\x1b[0m Driver tail pointer unchanged for {:.2} us (Tail Ptr: {}). System experiencing RX starvation!\x1b[0m",
                stall_us, e.tail_ptr
            );
        }

        if e.dataref > 1 {
            println!(
                "  ! \x1b[33m[HEADER FREED ONLY]\x1b[0m SKB Header {} destroyed, but Data Buffer {} \x1b[32mSURVIVES\x1b[0m (dataref={} remaining!)\x1b[0m",
                e.skb_addr, e.head_addr, e.dataref - 1
            );
        } else {
            println!(
                "  + \x1b[32m[SKB & DATA FREED]\x1b[0m Header {} and Data Buffer {} freed.\x1b[0m",
                e.skb_addr, e.head_addr
            );
        }
    } else if e.event_type == SkbEventType::StructChange {
        if !e.target_skb.is_empty() {
            println!("  └─ Operation: {} | Target SKB: {}", e.func_name, e.target_skb);
        }
    }

    if e.saddr != "-" {
        println!("  └─ Flow: {}:{} -> {}:{} (Proto: {})", e.saddr, e.sport, e.daddr, e.dport, e.protocol);
    }
    println!();
}

pub fn print_ascii_graph_tree(tracker: &SkbTracker) {
    let snapshot = tracker.get_snapshot();
    println!("\n=======================================================");
    println!("             sk_buff LIFESPAN GRAPH TREE               ");
    println!("=======================================================");

    for skb in &snapshot.skbs {
        let status_color = if skb.status == "ALIVE" { "\x1b[32mALIVE\x1b[0m" } else { "\x1b[31mDESTROYED\x1b[0m" };
        let intra_us = (skb.lifespan_ns as f64) / 1000.0;
        let inter_us = (skb.inter_cycle_ns as f64) / 1000.0;

        let mem_status = if skb.irq_preempted {
            format!("\x1b[31m[HARD IRQ STALL (Handler \"{}\", IRQ {})]\x1b[0m", skb.irq_name, skb.irq_number)
        } else if skb.cpu_preempted {
            format!("\x1b[31m[CPU PREEMPTED by \"{}\" (PID {})]\x1b[0m", skb.preempt_comm, skb.preempt_pid)
        } else if skb.nic_wait {
            "\x1b[31m[SLAB / MEMORY ALLOCATOR STALL]\x1b[0m".to_string()
        } else {
            "\x1b[32m[NORMAL]\x1b[0m".to_string()
        };

        println!(
            "|- SKB Header [{}] status: {} | Processing: {:.2} us | Refill: {:.2} us {}",
            skb.addr, status_color, intra_us, inter_us, mem_status
        );
        println!("|  |- Data Buffer: {}", skb.head_addr);
        println!("|  |- RefCounts: users={} | len={}", skb.users, skb.len);
        if let Some(parent) = &skb.parent_skb {
            println!("|  |- Cloned From Parent SKB: {}", parent);
        }
        if skb.flow != "-" {
            println!("|  |- Flow: {}", skb.flow);
        }
        println!("|  |- Events Recorded: {}", skb.events.len());
        for ev in &skb.events {
            println!("|     |- [{}] {} @ {} ns", ev.event_type.as_str(), ev.func_name, ev.timestamp_ns);
        }
        println!("|");
    }

    println!("-------------------------------------------------------");
    println!("Shared Data Buffers State:");
    for buf in &snapshot.buffers {
        let status_color = match buf.status.as_str() {
            "ALIVE" => "\x1b[32mALIVE\x1b[0m",
            "CLONED_SURVIVING" => "\x1b[33mCLONED_SURVIVING (Header freed, Data alive!)\x1b[0m",
            _ => "\x1b[31mDESTROYED\x1b[0m",
        };
        println!("|- Buffer [{}] status: {} | dataref={}", buf.head_addr, status_color, buf.dataref);
        println!("|  |- Referencing SKBs: {:?}", buf.associated_skbs);
    }
    println!("=======================================================\n");
}
