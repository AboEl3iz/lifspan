mod events;
mod tracker;
mod bpf;
mod cli;
mod web;

use std::env;
use std::os::raw::{c_int, c_void};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use events::{ProcessedEvent, RawSkbEvent};
use tracker::SkbTracker;
use bpf::BpfRunner;

static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn handle_event_cb(ctx: *mut c_void, data: *mut c_void, _size: usize) -> c_int {
    if data.is_null() || ctx.is_null() {
        return 0;
    }

    let tracker_ptr = ctx as *mut Mutex<SkbTracker>;
    let raw = unsafe { &*(data as *const RawSkbEvent) };
    let processed = ProcessedEvent::from_raw(raw);

    cli::print_cli_event(&processed);

    unsafe {
        if let Ok(mut tracker) = (*tracker_ptr).lock() {
            tracker.process_event(processed);
        }
    }

    0
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut port: u16 = 8080;
    let mut bpf_path = "bpf/skb_lifespan.bpf.o".to_string();
    let mut enable_web = true;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                if i + 1 < args.len() {
                    port = args[i + 1].parse().unwrap_or(8080);
                    i += 1;
                }
            }
            "--bpf" => {
                if i + 1 < args.len() {
                    bpf_path = args[i + 1].clone();
                    i += 1;
                }
            }
            "--no-web" => {
                enable_web = false;
            }
            "--help" | "-h" => {
                println!("sk_buff Lifespan & Cloning Visualizer Engine (Rust + C eBPF)");
                println!("Usage: skb_lifespan [OPTIONS]");
                println!();
                println!("Options:");
                println!("  --port <PORT>    Web UI server port (default: 8080)");
                println!("  --bpf <PATH>     Path to compiled bpf object (default: bpf/skb_lifespan.bpf.o)");
                println!("  --no-web         Disable embedded Web UI server");
                println!("  --help           Show this help message");
                return;
            }
            _ => {}
        }
        i += 1;
    }

    println!("===========================================================");
    println!("     sk_buff LIFESPAN & CLONING TRACING ENGINE (RUST)      ");
    println!("===========================================================");

    let tracker = Arc::new(Mutex::new(SkbTracker::new(5000)));

    if enable_web {
        let tracker_web = Arc::clone(&tracker);
        thread::spawn(move || {
            web::start_web_server(tracker_web, port);
        });
    }

    let raw_ctx = Arc::into_raw(Arc::clone(&tracker)) as *mut c_void;

    println!("Loading eBPF object: {}...", bpf_path);
    let runner = match BpfRunner::load_and_attach(&bpf_path, handle_event_cb, raw_ctx) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[ERROR] Failed to initialize BPF tracer: {}", e);
            eprintln!("Ensure root permissions (sudo) and BTF support (/sys/kernel/btf/vmlinux).");
            return;
        }
    };

    println!("[OK] BPF BTF fentry/fexit probes attached successfully!");
    if enable_web {
        println!("[INFO] Open your browser at: http://localhost:{}", port);
    }
    println!("Tracing active network traffic... Press Ctrl+C to stop.\n");

    ctrlc_handler();

    while RUNNING.load(Ordering::Relaxed) {
        let ret = runner.poll(100);
        if ret < 0 && ret != -libc::EINTR {
            eprintln!("Ringbuffer poll error: {}", ret);
            break;
        }
    }

    println!("\nShutting down BPF tracer...");
    let tracker_guard = tracker.lock().unwrap();
    cli::print_ascii_graph_tree(&tracker_guard);
}

fn ctrlc_handler() {
    let _ = ctrlc::set_handler(move || {
        RUNNING.store(false, Ordering::Relaxed);
    });
}
