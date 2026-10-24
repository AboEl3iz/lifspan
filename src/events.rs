use serde::{Deserialize, Serialize};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SkbEventType {
    StructChange = 1,
    LifespanSummary = 2,
    FreeData = 3,
}

impl SkbEventType {
    pub fn from_u32(val: u32) -> Self {
        match val {
            1 => SkbEventType::StructChange,
            2 => SkbEventType::LifespanSummary,
            3 => SkbEventType::FreeData,
            _ => SkbEventType::LifespanSummary,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SkbEventType::StructChange => "STRUCT_CHANGE",
            SkbEventType::LifespanSummary => "LIFESPAN_SUMMARY",
            SkbEventType::FreeData => "FREE_DATA",
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct RawSkbEvent {
    pub timestamp_ns: u64,
    pub lifespan_ns: u64,
    pub inter_cycle_ns: u64,
    pub skb_addr: u64,
    pub head_addr: u64,
    pub target_skb: u64,
    pub event_type: u32,
    pub pid: u32,
    pub len: u32,
    pub data_len: u32,
    pub users: u16,
    pub dataref: u16,
    pub cloned: u16,
    pub op_flags: u16,
    pub cpu_preempted: u8,
    pub preempt_pid: u32,
    pub preempt_prio: u32,
    pub preempt_comm: [u8; 16],
    pub irq_preempted: u8,
    pub irq_number: i32,
    pub irq_name: [u8; 32],
    pub free_descriptors: u32,
    pub tail_ptr: u64,
    pub tail_stall_ns: u64,
    pub comm: [u8; 16],
    pub func_name: [u8; 32],
    pub ifname: [u8; 16],
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub protocol: u8,
    pub drop_reason: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessedEvent {
    pub timestamp_ns: u64,
    pub lifespan_ns: u64,
    pub inter_cycle_ns: u64,
    pub event_type: SkbEventType,
    pub skb_addr: String,
    pub head_addr: String,
    pub target_skb: String,
    pub pid: u32,
    pub comm: String,
    pub func_name: String,
    pub ifname: String,
    pub len: u32,
    pub data_len: u32,
    pub users: u16,
    pub dataref: u16,
    pub cloned: bool,
    pub op_flags: u16,
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
    pub saddr: String,
    pub daddr: String,
    pub sport: u16,
    pub dport: u16,
    pub protocol: u8,
}

fn c_str_to_string(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).trim().to_string()
}

fn u32_to_ip(ip: u32) -> String {
    if ip == 0 {
        return "-".to_string();
    }
    let bytes = ip.to_ne_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

impl ProcessedEvent {
    pub fn from_raw(raw: &RawSkbEvent) -> Self {
        let nic_wait = (raw.op_flags & (1 << 8)) != 0;
        let cpu_preempted = raw.cpu_preempted != 0 || (raw.op_flags & (1 << 9)) != 0;
        let irq_preempted = raw.irq_preempted != 0 || (raw.op_flags & (1 << 10)) != 0;
        let threaded_napi = (raw.op_flags & (1 << 11)) != 0;
        let zero_descriptors = (raw.op_flags & (1 << 12)) != 0 || raw.free_descriptors == 0;
        let tail_pointer_stalled = (raw.op_flags & (1 << 13)) != 0 || raw.tail_stall_ns > 100_000;

        ProcessedEvent {
            timestamp_ns: raw.timestamp_ns,
            lifespan_ns: raw.lifespan_ns,
            inter_cycle_ns: raw.inter_cycle_ns,
            event_type: SkbEventType::from_u32(raw.event_type),
            skb_addr: format!("0x{:x}", raw.skb_addr),
            head_addr: format!("0x{:x}", raw.head_addr),
            target_skb: if raw.target_skb != 0 {
                format!("0x{:x}", raw.target_skb)
            } else {
                "".to_string()
            },
            pid: raw.pid,
            comm: c_str_to_string(&raw.comm),
            func_name: c_str_to_string(&raw.func_name),
            ifname: c_str_to_string(&raw.ifname),
            len: raw.len,
            data_len: raw.data_len,
            users: raw.users,
            dataref: raw.dataref,
            cloned: raw.cloned != 0,
            op_flags: raw.op_flags,
            nic_wait,
            cpu_preempted,
            preempt_pid: raw.preempt_pid,
            preempt_prio: raw.preempt_prio,
            preempt_comm: c_str_to_string(&raw.preempt_comm),
            irq_preempted,
            irq_number: raw.irq_number,
            irq_name: c_str_to_string(&raw.irq_name),
            threaded_napi,
            free_descriptors: raw.free_descriptors,
            tail_ptr: raw.tail_ptr,
            tail_stall_ns: raw.tail_stall_ns,
            zero_descriptors,
            tail_pointer_stalled,
            saddr: u32_to_ip(raw.saddr),
            daddr: u32_to_ip(raw.daddr),
            sport: raw.sport,
            dport: raw.dport,
            protocol: raw.protocol,
        }
    }
}
