use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

pub type RingBufferSampleFn = extern "C" fn(ctx: *mut c_void, data: *mut c_void, size: usize) -> c_int;

extern "C" {
    fn bpf_object__open_file(path: *const c_char, opts: *const c_void) -> *mut c_void;
    fn bpf_object__load(obj: *mut c_void) -> c_int;
    fn bpf_object__next_program(obj: *mut c_void, prev: *mut c_void) -> *mut c_void;
    fn bpf_program__attach(prog: *const c_void) -> *mut c_void;
    fn bpf_object__find_map_by_name(obj: *const c_void, name: *const c_char) -> *mut c_void;
    fn bpf_map__fd(map: *const c_void) -> c_int;
    fn ring_buffer__new(
        fd: c_int,
        sample_cb: RingBufferSampleFn,
        ctx: *mut c_void,
        opts: *const c_void,
    ) -> *mut c_void;
    fn ring_buffer__poll(rb: *mut c_void, timeout_ms: c_int) -> c_int;
    fn ring_buffer__free(rb: *mut c_void);
    fn bpf_object__close(obj: *mut c_void);
}

pub struct BpfRunner {
    bpf_obj: *mut c_void,
    _links: Vec<*mut c_void>,
    ringbuf: *mut c_void,
}

impl BpfRunner {
    pub fn load_and_attach(
        bpf_path: &str,
        sample_cb: RingBufferSampleFn,
        ctx: *mut c_void,
    ) -> Result<Self, String> {
        let path_c = CString::new(bpf_path).map_err(|e| e.to_string())?;

        unsafe {
            let obj = bpf_object__open_file(path_c.as_ptr(), ptr::null());
            if obj.is_null() {
                return Err(format!("Failed to open BPF object file: {}", bpf_path));
            }

            let err = bpf_object__load(obj);
            if err != 0 {
                bpf_object__close(obj);
                return Err(format!("Failed to load BPF object: error code {}", err));
            }

            let mut links = Vec::new();
            let mut prog = bpf_object__next_program(obj, ptr::null_mut());

            while !prog.is_null() {
                let link = bpf_program__attach(prog);
                if !link.is_null() {
                    links.push(link);
                }
                prog = bpf_object__next_program(obj, prog);
            }

            let map_name = CString::new("events").unwrap();
            let map = bpf_object__find_map_by_name(obj, map_name.as_ptr());
            if map.is_null() {
                bpf_object__close(obj);
                return Err("Failed to find 'events' BPF ringbuffer map".to_string());
            }

            let fd = bpf_map__fd(map);
            if fd < 0 {
                bpf_object__close(obj);
                return Err(format!("Invalid map fd: {}", fd));
            }

            let rb = ring_buffer__new(fd, sample_cb, ctx, ptr::null());
            if rb.is_null() {
                bpf_object__close(obj);
                return Err("Failed to create ringbuffer consumer".to_string());
            }

            Ok(BpfRunner {
                bpf_obj: obj,
                _links: links,
                ringbuf: rb,
            })
        }
    }

    pub fn poll(&self, timeout_ms: i32) -> i32 {
        unsafe { ring_buffer__poll(self.ringbuf, timeout_ms) }
    }
}

impl Drop for BpfRunner {
    fn drop(&mut self) {
        unsafe {
            if !self.ringbuf.is_null() {
                ring_buffer__free(self.ringbuf);
            }
            if !self.bpf_obj.is_null() {
                bpf_object__close(self.bpf_obj);
            }
        }
    }
}
