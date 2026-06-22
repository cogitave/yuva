//! infer-daemon — the M32 stage-A host-adjudicated local-inference daemon.
//!
//! TWO ROLES, one binary:
//!
//!  * THE DAEMON (default): the key-holding, witness-emitting peer. It IS the
//!    QEMU chardev peer on its legacy legs (`peer_id=0x02`, M30 echo + M31 mock,
//!    byte-identical to xport-harness so the required chain stays green), and it
//!    ADDS the LOCAL-ENGINE backend: double-gated by `--local-llama` +
//!    `XPORT_LOCAL_LLAMA=1`, it spawns the keyless sandboxed worker, runs the §4
//!    determinism legs, and emits the §8 witness line(s) on host stdout. NO
//!    local-engine byte reaches the guest at stage A
//!    (`guestpath=MOCK-PINNED-HOST-ADJUDICATED`).
//!
//!  * THE WORKER (`--worker`): the ONLY process containing C. Spawned by the
//!    daemon with `env_clear()`; installs seccomp+Landlock BEFORE parsing the
//!    GGUF; runs ONE greedy completion; answers over the pipe seam. See
//!    `worker.rs`.
//!
//! The M32 marker (`M32: local-infer OK backend=LOCAL-ENGINE`) is NEVER printed
//! here — it is workflow-adjudicated from the witness (the real-infer.yml
//! summary-only precedent), so it can never enter the cumulative chain.

// witness is ALWAYS compiled so its unit tests run WITHOUT the C toolchain (the
// brief's "unit-test the Rust paths, no llama.cpp" rule); its render is only
// CALLED by the engine path, so allow dead_code when the feature is off.
#[cfg_attr(not(feature = "engine"), allow(dead_code))]
mod witness;

// pins/engine/worker are the engine-feature paths.
#[cfg(feature = "engine")]
mod engine;
#[cfg(feature = "engine")]
mod pins;
#[cfg(feature = "engine")]
mod worker;

use std::process::exit;
use std::time::{Duration, Instant};

use xport_core::{hex, ChardevPeer};

/// The exit-3 LOUD refusal (the M31 NO_KEY_REFUSAL precedent): opted into the
/// local engine but the artifacts/sandbox/determinism legs did not hold. NEVER
/// a mock fallback wearing the local token.
#[cfg(feature = "engine")]
const LOCAL_REFUSAL_EXIT: i32 = 3;

fn main() {
    let argv: Vec<String> = std::env::args().collect();

    // --- the golden-measurement helper (landing + re-pin only) -------------
    // `--digest-of-hex <lowercase-hex>` prints the body_digest (the §4 golden)
    // of the given response bytes. Used ONCE at landing to seed the repo-pinned
    // goldens, and at every reviewed re-pin; NEVER on the green lane path.
    if let Some(h) = arg_value_always(&argv, "--digest-of-hex") {
        let bytes = decode_hex(&h);
        let d = tb_encode::inferwire::body_digest(&bytes);
        println!("{}", hex(&d));
        exit(0);
    }

    // --- the WORKER re-exec branch (engine feature only) -------------------
    #[cfg(feature = "engine")]
    if argv.iter().any(|a| a == "--worker") {
        let model = arg_value(&argv, "--model").unwrap_or_else(|| {
            eprintln!("infer-daemon --worker: --model required");
            exit(2);
        });
        let n_predict = arg_value(&argv, "--n-predict")
            .and_then(|v| v.parse().ok())
            .unwrap_or(pins::N_PREDICT);
        worker::run_worker(&model, n_predict);
    }

    // --- the standalone LOCAL-MEASURE branch (M32 stage-A host-adjudicated) -
    // Stage A is host-adjudicated and NO local-engine byte reaches the guest
    // (guestpath=MOCK-PINNED-HOST-ADJUDICATED), so the §4 measurement is run as
    // its OWN step by the local-infer.yml lane — decoupled from the kernel boot
    // (the heavy 6-spawn legs must never sit inside the QEMU wall-clock). The
    // double gate still applies.
    #[cfg(feature = "engine")]
    if argv.iter().any(|a| a == "--local-measure") {
        let local_mode = std::env::var("XPORT_LOCAL_LLAMA")
            .map(|v| v == "1")
            .unwrap_or(false);
        if !local_mode {
            eprintln!("infer-daemon --local-measure: refusing without XPORT_LOCAL_LLAMA=1 (the double gate)");
            exit(LOCAL_REFUSAL_EXIT);
        }
        run_local_once();
        exit(0);
    }

    // --- the DAEMON branch -------------------------------------------------
    let mut socket_path: Option<String> = None;
    let mut key_out: Option<String> = None;
    let mut timeout_secs: u64 = 300;
    let mut local_flag = false;
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--socket" => {
                i += 1;
                socket_path = argv.get(i).cloned();
            }
            "--key-out" => {
                i += 1;
                key_out = argv.get(i).cloned();
            }
            "--timeout-secs" => {
                i += 1;
                timeout_secs = argv.get(i).and_then(|v| v.parse().ok()).unwrap_or(timeout_secs);
            }
            "--local-llama" => local_flag = true,
            "--worker" => { /* handled above when engine is on; ignore otherwise */ }
            "--model" | "--n-predict" => {
                i += 1; /* worker args, skip the value */
            }
            other => {
                eprintln!("infer-daemon: unknown arg '{other}'");
                exit(2);
            }
        }
        i += 1;
    }

    // The double gate (the M31 --anthropic / XPORT_ANTHROPIC precedent): the
    // LOCAL-ENGINE leg activates ONLY with the flag AND the env var.
    let local_mode = local_flag
        && std::env::var("XPORT_LOCAL_LLAMA")
            .map(|v| v == "1")
            .unwrap_or(false);

    let socket_path = match socket_path {
        Some(p) => p,
        None => {
            eprintln!("usage: infer-daemon --socket <unix-socket> [--key-out <file>] [--timeout-secs <n>] [--local-llama]");
            exit(2);
        }
    };

    // The chardev peer is born with the per-run host-custodied key + nonce.
    let mut peer = ChardevPeer::new();
    if let Some(kp) = &key_out {
        std::fs::write(kp, hex(peer.key())).expect("infer-daemon: cannot write --key-out");
    }

    // Connect (retry: QEMU creates the listener at startup).
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut stream = loop {
        match std::os::unix::net::UnixStream::connect(&socket_path) {
            Ok(s) => break s,
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("infer-daemon: cannot connect to {socket_path}: {e}");
                exit(1);
            }
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("infer-daemon: set_read_timeout");

    // Serve the legacy M30/M31 legs byte-identically (peer_id=0x02). The serve
    // role stays MOCK-ONLY — the LOCAL-ENGINE §4 measurement is the separate
    // `--local-measure` step (stage A is host-adjudicated; the heavy multi-spawn
    // legs must never sit inside the QEMU boot wall-clock). `--local-llama` on
    // the serve role is accepted (the double gate) but the measurement is NOT
    // run here; it documents intent and keeps the activation surface uniform.
    let _ = local_mode;
    let echoes = peer.serve(&mut stream, deadline, |_body, _challenge, _req_id| {});

    exit(if echoes >= 1 { 0 } else { 1 });
}

#[cfg(feature = "engine")]
fn arg_value(argv: &[String], key: &str) -> Option<String> {
    argv.iter().position(|a| a == key).and_then(|i| argv.get(i + 1).cloned())
}

/// arg_value available regardless of the engine feature (for `--digest-of-hex`).
fn arg_value_always(argv: &[String], key: &str) -> Option<String> {
    argv.iter().position(|a| a == key).and_then(|i| argv.get(i + 1).cloned())
}

/// Decode a lowercase-hex string to bytes (for `--digest-of-hex`).
fn decode_hex(s: &str) -> Vec<u8> {
    let b = s.trim().as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i + 1 < b.len() + 1 && i + 1 < b.len() {
        let hi = (b[i] as char).to_digit(16);
        let lo = (b[i + 1] as char).to_digit(16);
        if let (Some(h), Some(l)) = (hi, lo) {
            out.push(((h << 4) | l) as u8);
        }
        i += 2;
    }
    out
}

/// Run the M32 LOCAL-ENGINE measurement + witness emission AT MOST ONCE per
/// process (the latch). On any failure it prints the loud refusal and exits 3 —
/// never a silent green, never a mock fallback wearing the local token.
#[cfg(feature = "engine")]
fn run_local_once() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static DONE: AtomicBool = AtomicBool::new(false);
    if DONE.swap(true, Ordering::SeqCst) {
        return;
    }

    let self_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "infer-daemon".into());

    // The per-run nonce: the workflow samples it and passes it via env (so it
    // is an INDEPENDENT stream from the daemon — the §4 leg-4 canned-table
    // killer). Absent => the daemon samples its own (still fresh per run).
    let nonce16 = nonce_from_env_or_random();

    // The measured substrate fields (§4): from env (the workflow measures and
    // passes them) or "UNKNOWN".
    let runner_image = std::env::var("M32_RUNNER_IMAGE").unwrap_or_else(|_| "UNKNOWN".into());
    let glibc = std::env::var("M32_GLIBC").unwrap_or_else(|_| "UNKNOWN".into());

    // Models: the in-repo 260K (always) + the Q8_0 (only if its path resolves
    // and verifies — the cache lane provides it; absent on a bare smoke run).
    let model_q8_path = std::env::var("M32_Q8_PATH").ok();

    let mut any_emitted = false;

    for (pin, path_override) in [
        (&pins::STORIES260K, std::env::var("M32_260K_PATH").ok()),
        (&pins::STORIES15M_Q8, model_q8_path),
    ] {
        // The Q8 model is optional: if its artifact is missing AND no override
        // was given, skip it (the 260K is the required smoke). The 260K missing
        // is a hard refusal.
        let is_required = pin.name == pins::STORIES260K.name;
        let resolved = path_override.as_deref();
        match engine::measure_model(
            &self_exe,
            pin,
            resolved,
            &nonce16,
            &runner_image,
            &glibc,
        ) {
            Ok(w) => {
                println!("{}", w.render());
                std::io::Write::flush(&mut std::io::stdout()).ok();
                any_emitted = true;
            }
            Err(engine::EngineLaneError::ArtifactMissing(m)) if !is_required => {
                eprintln!("infer-daemon: optional model {} absent ({m}) — skipping (260K is the required smoke)", pin.name);
            }
            Err(e) => {
                eprintln!("infer-daemon: LOCAL-ENGINE refusal for {}: {e:?}", pin.name);
                exit(LOCAL_REFUSAL_EXIT);
            }
        }
    }

    if !any_emitted {
        eprintln!("infer-daemon: LOCAL-ENGINE produced no witness (no model verified) — loud refusal");
        exit(LOCAL_REFUSAL_EXIT);
    }
}

#[cfg(feature = "engine")]
fn nonce_from_env_or_random() -> [u8; 16] {
    if let Ok(h) = std::env::var("M32_NONCE_HEX") {
        let h = h.trim();
        if h.len() == 32 {
            let mut out = [0u8; 16];
            let mut ok = true;
            for (i, byte) in out.iter_mut().enumerate() {
                match u8::from_str_radix(&h[i * 2..i * 2 + 2], 16) {
                    Ok(b) => *byte = b,
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                return out;
            }
        }
    }
    let r = xport_core::os_random(16);
    let mut out = [0u8; 16];
    out.copy_from_slice(&r);
    out
}
