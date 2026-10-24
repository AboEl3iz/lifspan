use std::collections::{HashMap, VecDeque};
use serde::{Deserialize, Serialize};
use crate::events::{ProcessedEvent, SkbEventType};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkbNode {
    pub addr: String,
    pub head_addr: String,
    pub created_at: u64,
    pub destroyed_at: Option<u64>,
    pub lifespan_ns: u64,
    pub inter_cycle_ns: u64,
    pub nic_wait: bool,
    pub cpu_preempted: bool,
    pub preempt_pid: u32,
    pub preempt_prio: u32,
    pub preempt_comm: String,
    pub irq_preempted: bool,
    pub irq_number: i32,
    pub irq_name: String,
    pub threaded_napi: bool,
    pub free_descriptors: u32,
    pub tail_ptr: u64,
    pub tail_stall_ns: u64,
    pub zero_descriptors: bool,
    pub tail_pointer_stalled: bool,
    pub status: String, // "ALIVE" or "DESTROYED"
    pub users: u16,
    pub len: u32,
    pub data_len: u32,
    pub cloned: bool,
    pub parent_skb: Option<String>,
    pub flow: String,
    pub events: Vec<ProcessedEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferNode {
    pub head_addr: String,
    pub created_at: u64,
    pub destroyed_at: Option<u64>,
    pub status: String, // "ALIVE", "CLONED_SURVIVING", "DESTROYED"
    pub dataref: u16,
    pub associated_skbs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub label: String,
    pub edge_type: String, // "CLONE", "COALESCE", "SPLIT", "HEAD_PTR"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSnapshot {
    pub skbs: Vec<SkbNode>,
    pub buffers: Vec<BufferNode>,
    pub edges: Vec<GraphEdge>,
    pub stats: TrackerStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackerStats {
    pub total_allocations: u64,
    pub total_clones: u64,
    pub total_coalesces: u64,
    pub total_splits: u64,
    pub active_skb_headers: usize,
    pub active_data_buffers: usize,
    pub surviving_cloned_buffers: usize,
    pub nic_wait_events: u64,
    pub cpu_preempt_events: u64,
    pub hard_irq_events: u64,
    pub zero_descriptor_events: u64,
    pub tail_stall_events: u64,
    pub total_appends: u64,
    pub total_gso_segments: u64,
}

pub struct SkbTracker {
    skbs: HashMap<String, SkbNode>,
    buffers: HashMap<String, BufferNode>,
    edges: Vec<GraphEdge>,
    recent_events: VecDeque<ProcessedEvent>,
    stats: TrackerStats,
    max_events: usize,
}

impl SkbTracker {
    pub fn new(max_events: usize) -> Self {
        SkbTracker {
            skbs: HashMap::new(),
            buffers: HashMap::new(),
            edges: Vec::new(),
            recent_events: VecDeque::new(),
            stats: TrackerStats {
                total_allocations: 0,
                total_clones: 0,
                total_coalesces: 0,
                total_splits: 0,
                active_skb_headers: 0,
                active_data_buffers: 0,
                surviving_cloned_buffers: 0,
                nic_wait_events: 0,
                cpu_preempt_events: 0,
                hard_irq_events: 0,
                zero_descriptor_events: 0,
                tail_stall_events: 0,
                total_appends: 0,
                total_gso_segments: 0,
            },
            max_events,
        }
    }

    pub fn process_event(&mut self, event: ProcessedEvent) {
        if self.recent_events.len() >= self.max_events {
            self.recent_events.pop_front();
        }
        self.recent_events.push_back(event.clone());

        let skb_addr = event.skb_addr.clone();
        let head_addr = event.head_addr.clone();
        let target_skb = event.target_skb.clone();
        let ts = event.timestamp_ns;

        if event.nic_wait {
            self.stats.nic_wait_events += 1;
        }
        if event.cpu_preempted {
            self.stats.cpu_preempt_events += 1;
        }
        if event.irq_preempted {
            self.stats.hard_irq_events += 1;
        }
        if event.zero_descriptors {
            self.stats.zero_descriptor_events += 1;
        }
        if event.tail_pointer_stalled {
            self.stats.tail_stall_events += 1;
        }

        let flow_str = if event.saddr != "-" && event.daddr != "-" {
            format!("{}:{} -> {}:{}", event.saddr, event.sport, event.daddr, event.dport)
        } else {
            "-".to_string()
        };

        // 1. Update BufferNode
        if !head_addr.is_empty() && head_addr != "0x0" {
            let buf = self.buffers.entry(head_addr.clone()).or_insert_with(|| BufferNode {
                head_addr: head_addr.clone(),
                created_at: ts,
                destroyed_at: None,
                status: "ALIVE".to_string(),
                dataref: event.dataref,
                associated_skbs: Vec::new(),
            });
            buf.dataref = event.dataref;
            if !buf.associated_skbs.contains(&skb_addr) {
                buf.associated_skbs.push(skb_addr.clone());
            }
        }

        // 2. Update SkbNode
        {
            let skb_node = self.skbs.entry(skb_addr.clone()).or_insert_with(|| SkbNode {
                addr: skb_addr.clone(),
                head_addr: head_addr.clone(),
                created_at: ts,
                destroyed_at: None,
                lifespan_ns: event.lifespan_ns,
                inter_cycle_ns: event.inter_cycle_ns,
                nic_wait: event.nic_wait,
                cpu_preempted: event.cpu_preempted,
                preempt_pid: event.preempt_pid,
                preempt_prio: event.preempt_prio,
                preempt_comm: event.preempt_comm.clone(),
                irq_preempted: event.irq_preempted,
                irq_number: event.irq_number,
                irq_name: event.irq_name.clone(),
                threaded_napi: event.threaded_napi,
                free_descriptors: event.free_descriptors,
                tail_ptr: event.tail_ptr,
                tail_stall_ns: event.tail_stall_ns,
                zero_descriptors: event.zero_descriptors,
                tail_pointer_stalled: event.tail_pointer_stalled,
                status: "ALIVE".to_string(),
                users: event.users,
                len: event.len,
                data_len: event.data_len,
                cloned: event.cloned,
                parent_skb: None,
                flow: flow_str.clone(),
                events: Vec::new(),
            });

            skb_node.users = event.users;
            skb_node.len = event.len;
            skb_node.data_len = event.data_len;
            skb_node.cloned = event.cloned;
            skb_node.free_descriptors = event.free_descriptors;
            skb_node.tail_ptr = event.tail_ptr;
            if event.tail_stall_ns > 0 {
                skb_node.tail_stall_ns = event.tail_stall_ns;
            }
            if event.zero_descriptors {
                skb_node.zero_descriptors = true;
            }
            if event.tail_pointer_stalled {
                skb_node.tail_pointer_stalled = true;
            }
            if event.lifespan_ns > 0 {
                skb_node.lifespan_ns = event.lifespan_ns;
            }
            if event.inter_cycle_ns > 0 {
                skb_node.inter_cycle_ns = event.inter_cycle_ns;
            }
            if event.nic_wait {
                skb_node.nic_wait = true;
            }
            if event.cpu_preempted {
                skb_node.cpu_preempted = true;
                skb_node.preempt_pid = event.preempt_pid;
                skb_node.preempt_prio = event.preempt_prio;
                skb_node.preempt_comm = event.preempt_comm.clone();
            }
            if event.irq_preempted {
                skb_node.irq_preempted = true;
                skb_node.irq_number = event.irq_number;
                skb_node.irq_name = event.irq_name.clone();
            }
            if event.threaded_napi {
                skb_node.threaded_napi = true;
            }
            if skb_node.flow == "-" && flow_str != "-" {
                skb_node.flow = flow_str.clone();
            }
            skb_node.events.push(event.clone());
        }

        // 3. Connect SKB -> Data Buffer Edge
        if !head_addr.is_empty() && head_addr != "0x0" {
            self.add_edge(skb_addr.clone(), head_addr.clone(), "HEAD_PTR", "data_ref");
        }

        // 4. Handle Event Specific Logic
        match event.event_type {
            SkbEventType::StructChange => {
                if event.func_name == "skb_clone" && !target_skb.is_empty() {
                    self.stats.total_clones += 1;
                    let parent_flow = self.skbs.get(&skb_addr).map(|s| s.flow.clone()).unwrap_or_else(|| "-".to_string());

                    let child_node = self.skbs.entry(target_skb.clone()).or_insert_with(|| SkbNode {
                        addr: target_skb.clone(),
                        head_addr: head_addr.clone(),
                        created_at: ts,
                        destroyed_at: None,
                        lifespan_ns: 0,
                        inter_cycle_ns: event.inter_cycle_ns,
                        nic_wait: event.nic_wait,
                        cpu_preempted: event.cpu_preempted,
                        preempt_pid: event.preempt_pid,
                        preempt_prio: event.preempt_prio,
                        preempt_comm: event.preempt_comm.clone(),
                        irq_preempted: event.irq_preempted,
                        irq_number: event.irq_number,
                        irq_name: event.irq_name.clone(),
                        threaded_napi: event.threaded_napi,
                        free_descriptors: event.free_descriptors,
                        tail_ptr: event.tail_ptr,
                        tail_stall_ns: event.tail_stall_ns,
                        zero_descriptors: event.zero_descriptors,
                        tail_pointer_stalled: event.tail_pointer_stalled,
                        status: "ALIVE".to_string(),
                        users: 1,
                        len: event.len,
                        data_len: event.data_len,
                        cloned: true,
                        parent_skb: Some(skb_addr.clone()),
                        flow: parent_flow,
                        events: Vec::new(),
                    });
                    child_node.parent_skb = Some(skb_addr.clone());

                    self.add_edge(skb_addr.clone(), target_skb.clone(), "CLONE", "cloned_from");
                } else if (event.func_name == "tcp_try_coalesce" || event.func_name == "skb_try_coalesce") && !target_skb.is_empty() {
                    self.stats.total_coalesces += 1;
                    self.add_edge(skb_addr.clone(), target_skb.clone(), "COALESCE", "coalesced_into");
                } else if event.func_name == "skb_split" && !target_skb.is_empty() {
                    self.stats.total_splits += 1;
                    self.add_edge(skb_addr.clone(), target_skb.clone(), "SPLIT", "split_to");
                } else if event.func_name == "skb_append" && !target_skb.is_empty() {
                    self.stats.total_appends += 1;
                    self.add_edge(skb_addr.clone(), target_skb.clone(), "APPEND", "appended_to");
                } else if event.func_name == "skb_segment" && !target_skb.is_empty() {
                    self.stats.total_gso_segments += 1;
                    self.add_edge(skb_addr.clone(), target_skb.clone(), "GSO", "egress_gso_segment");
                }
            }
            SkbEventType::LifespanSummary => {
                self.stats.total_allocations += 1;
                if let Some(s) = self.skbs.get_mut(&skb_addr) {
                    s.status = "DESTROYED".to_string();
                    s.destroyed_at = Some(ts);
                    if event.lifespan_ns > 0 {
                        s.lifespan_ns = event.lifespan_ns;
                    }
                }

                if let Some(buf) = self.buffers.get_mut(&head_addr) {
                    if event.dataref > 1 {
                        buf.status = "CLONED_SURVIVING".to_string();
                    }
                }
            }
            SkbEventType::FreeData => {
                if let Some(buf) = self.buffers.get_mut(&head_addr) {
                    buf.status = "DESTROYED".to_string();
                    buf.destroyed_at = Some(ts);
                    buf.dataref = 0;
                }
            }
        }

        self.recalculate_stats();
    }

    fn add_edge(&mut self, from: String, to: String, edge_type: &str, label: &str) {
        let edge = GraphEdge {
            from,
            to,
            label: label.to_string(),
            edge_type: edge_type.to_string(),
        };
        if !self.edges.contains(&edge) {
            self.edges.push(edge);
        }
    }

    fn recalculate_stats(&mut self) {
        self.stats.active_skb_headers = self.skbs.values().filter(|s| s.status == "ALIVE").count();
        self.stats.active_data_buffers = self.buffers.values().filter(|b| b.status != "DESTROYED").count();
        self.stats.surviving_cloned_buffers = self.buffers.values().filter(|b| b.status == "CLONED_SURVIVING").count();
    }

    pub fn get_snapshot(&self) -> GraphSnapshot {
        GraphSnapshot {
            skbs: self.skbs.values().cloned().collect(),
            buffers: self.buffers.values().cloned().collect(),
            edges: self.edges.clone(),
            stats: self.stats.clone(),
        }
    }

    pub fn get_recent_events(&self) -> Vec<ProcessedEvent> {
        self.recent_events.iter().cloned().collect()
    }
}
