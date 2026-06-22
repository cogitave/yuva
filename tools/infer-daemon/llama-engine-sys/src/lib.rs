//! llama-engine-sys — the narrow `extern "C"` bindings to the flat `engine_shim`
//! ABI over vendored llama.cpp. This is the ONLY `unsafe` in the M32 daemon
//! workspace's Rust (`memsafety=UNSAFE-C-PROCESS-CONFINED`): every call crosses
//! into vendored C. The bindings are deliberately tiny (4 functions) so the
//! attack/audit surface is the shim contract, never a struct layout.
//!
//! The safe wrappers live here; the engine worker (a SEPARATE process spawned
//! by the daemon, env-cleared + seccomp/Landlock-sandboxed BEFORE it parses the
//! GGUF) is the only thing that calls them.

use std::ffi::c_char;
use std::ffi::CString;

#[allow(non_camel_case_types)]
type c_int = i32;

extern "C" {
    fn engine_backend_init();
    fn engine_backend_free();
    fn engine_sysinfo(buf: *mut c_char, cap: c_int) -> c_int;
    fn engine_generate(
        model_path: *const c_char,
        prompt: *const c_char,
        prompt_len: c_int,
        n_predict: c_int,
        n_threads: c_int,
        out: *mut c_char,
        out_cap: c_int,
    ) -> c_int;
}

/// Initialize the llama.cpp backend (call once per process).
pub fn backend_init() {
    // SAFETY: the shim's `llama_backend_init()` is a no-arg one-time init.
    unsafe { engine_backend_init() }
}

/// Tear the backend down (call once at process end).
pub fn backend_free() {
    // SAFETY: matches a prior `backend_init`.
    unsafe { engine_backend_free() }
}

/// The pinned llama.cpp `llama_print_system_info()` feature string — the §4
/// `sysinfo-pinned` tripwire input.
pub fn sysinfo() -> String {
    let mut buf = vec![0u8; 4096];
    // SAFETY: `buf` is a writable `cap`-byte region; the shim writes <= cap-1
    // bytes + a NUL and returns the length.
    let n = unsafe { engine_sysinfo(buf.as_mut_ptr() as *mut c_char, buf.len() as c_int) };
    if n < 0 {
        return String::new();
    }
    buf.truncate(n as usize);
    String::from_utf8_lossy(&buf).into_owned()
}

/// Errors from a generate call (the shim's negative return codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineError {
    ModelLoad,
    Tokenize,
    ContextInit,
    Decode,
    SamplerInit,
    Unknown(i32),
}

impl EngineError {
    fn from_rc(rc: i32) -> Self {
        match rc {
            -1 => EngineError::ModelLoad,
            -2 => EngineError::Tokenize,
            -3 => EngineError::ContextInit,
            -4 => EngineError::Decode,
            -5 => EngineError::SamplerInit,
            other => EngineError::Unknown(other),
        }
    }
}

/// Run ONE greedy raw-completion over the pinned envelope. `model_path` MUST be
/// an already-SHA256-verified GGUF (the daemon verifies before the worker fd
/// handoff — the C parser never touches an unverified byte). Returns the
/// generated continuation bytes (response only, never the echoed prompt).
///
/// `prompt` is raw bytes (no chat template — §5.4). `n_threads` is pinned to 1
/// by the worker (§4). `out_cap` bounds the response.
pub fn generate(
    model_path: &str,
    prompt: &[u8],
    n_predict: i32,
    n_threads: i32,
    out_cap: usize,
) -> Result<Vec<u8>, EngineError> {
    let model_c = CString::new(model_path).map_err(|_| EngineError::ModelLoad)?;
    // The prompt may contain interior NULs only if a caller passed raw bytes;
    // the shim takes an explicit length, so a NUL-bearing prompt is fine — we
    // pass the pointer + length, NOT a CString of the prompt.
    let mut out = vec![0u8; out_cap];
    // SAFETY: model_c is a valid NUL-terminated C string; prompt ptr+len is a
    // readable region; out ptr+cap is a writable region. The shim returns the
    // byte count written (>= 0) or a negative error code; on success n <= cap.
    let n = unsafe {
        engine_generate(
            model_c.as_ptr(),
            prompt.as_ptr() as *const c_char,
            prompt.len() as c_int,
            n_predict,
            n_threads,
            out.as_mut_ptr() as *mut c_char,
            out_cap as c_int,
        )
    };
    if n < 0 {
        return Err(EngineError::from_rc(n));
    }
    out.truncate(n as usize);
    Ok(out)
}
