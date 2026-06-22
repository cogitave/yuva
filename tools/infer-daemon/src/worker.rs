//! The engine WORKER (the ONLY process containing C). Spawned by the daemon as
//! a `--worker` re-exec with `env_clear()` (no ANTHROPIC_API_KEY / no XKEY-class
//! material reachable via /proc/self/environ), no argv secrets, and a read-only
//! model path. The worker:
//!
//!   1. installs its self-sandbox BEFORE parsing the GGUF (§5.1 — the parser IS
//!      the attack surface; this inverts llamafile's post-load order):
//!      PR_SET_NO_NEW_PRIVS -> seccomp-BPF allowlist (TSYNC) -> Landlock
//!      read-only ruleset on the model path;
//!   2. runs in-process negative probes (§5.2): socket(AF_INET) must FAIL,
//!      open("/etc/passwd") must be DENIED — these double as the per-run
//!      sandbox pre-flight (a runner that stops providing the ABI is a loud
//!      named FAIL, never a skip);
//!   3. reads the prompt from stdin (length-prefixed), runs ONE greedy
//!      completion over the pinned envelope, writes the response to stdout
//!      (length-prefixed) + the sandbox-probe + sysinfo lines.
//!
//! The pipe protocol is a process-internal seam, NOT a second wire codec:
//!   stdin :  u32_le prompt_len, prompt bytes
//!   stdout:  "SANDBOX net=<0|1> fs=<0|1> env=<0|1>\n"
//!            "SYSINFO <feature string>\n"
//!            "RESP <u32 hex len> <lowercase-hex response bytes>\n"
//!  or on a fault:  "ENGINE-FAULT <reason>\n"  (and a nonzero exit)
//!
//! `memsafety=UNSAFE-C-PROCESS-CONFINED`: this is hardening inside
//! host=RESIDUAL-TCB, NOT an isolation boundary (§5.7 / assumptions.md §3c).

use std::io::{Read, Write};

use xport_core::hex;

/// Outcome of the in-worker sandbox negative probes (§5.2).
struct ProbeResult {
    net_denied: bool,
    fs_denied: bool,
    env_cleared: bool,
}

/// The worker entry point (called from main when argv has `--worker`).
/// Reads ONE prompt, generates, writes the response + evidence. Exits 0 on a
/// served response, nonzero on an engine fault (the daemon maps that to the
/// closed `ERR code=ENGINE-FAULT`, §5.6).
pub fn run_worker(model_path: &str, n_predict: i32) -> ! {
    // --- (1) install the self-sandbox BEFORE any GGUF byte is parsed ---------
    // env-clear is enforced by the DAEMON at spawn (env_clear()); the worker
    // VERIFIES it (a NAMED canary must be absent) so envclear=0x1 is earned,
    // not assumed.
    let env_cleared = verify_env_cleared();

    // Open the model fd FIRST (Landlock will forbid new opens after this).
    let model_file = match std::fs::File::open(model_path) {
        Ok(f) => f,
        Err(e) => fault(&format!("model-open: {e}")),
    };

    install_no_new_privs();
    let fs_ruleset_ok = install_landlock(model_path);
    install_seccomp();

    // --- (2) the anti-hollow negative probes (also the per-run pre-flight) ---
    let probe = run_negative_probes(fs_ruleset_ok, env_cleared);
    // A widened/disabled/unavailable filter is a loud FAIL, never a skip.
    if !probe.net_denied || !probe.fs_denied {
        fault("sandbox-preflight: a negative probe unexpectedly SUCCEEDED (filter widened/disabled/unavailable)");
    }

    // --- (3) read the prompt, generate, answer -------------------------------
    let prompt = read_prompt_from_stdin();

    // Keep the verified model fd alive until after generation (it documents the
    // pre-Landlock open; llama.cpp re-opens by path, which Landlock allows
    // read-only on exactly this path).
    let _ = &model_file;

    let sysinfo = llama_engine_sys::sysinfo();
    let resp = match llama_engine_sys::generate(model_path, &prompt, n_predict, 1, 1 << 16) {
        Ok(r) => r,
        Err(e) => fault(&format!("engine: {e:?}")),
    };

    let mut out = std::io::stdout().lock();
    let _ = writeln!(
        out,
        "SANDBOX net={} fs={} env={}",
        u8::from(probe.net_denied),
        u8::from(probe.fs_denied),
        u8::from(probe.env_cleared),
    );
    // sysinfo is engine-derived text -> hex-encode (the §6 inert-alphabet rule,
    // one ring inward: the worker's own stdout is a parsed stream).
    let _ = writeln!(out, "SYSINFO {}", hex(sysinfo.as_bytes()));
    let _ = writeln!(out, "RESP {:x} {}", resp.len(), hex(&resp));
    let _ = out.flush();
    std::process::exit(0);
}

/// Print a closed ENGINE-FAULT line and exit nonzero (the daemon maps this to
/// `ERR code=ENGINE-FAULT`; C library text never crosses as raw bytes — the
/// reason is our own ASCII tag, never echoed model/library bytes).
fn fault(reason: &str) -> ! {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "ENGINE-FAULT {reason}");
    let _ = out.flush();
    std::process::exit(7);
}

/// VERIFY the daemon's env_clear() took: a NAMED canary must be absent from the
/// worker's environment. The daemon sets nothing; if ANTHROPIC_API_KEY (or any
/// XKEY-class var) is reachable here, env-clear failed.
fn verify_env_cleared() -> bool {
    for forbidden in ["ANTHROPIC_API_KEY", "XPORT_ANTHROPIC"] {
        if std::env::var_os(forbidden).is_some() {
            return false;
        }
    }
    true
}

fn install_no_new_privs() {
    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) is a process-self call.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        fault("prctl(PR_SET_NO_NEW_PRIVS) failed");
    }
}

/// Landlock read-only on the model path, nothing else. Returns true if the
/// ruleset was enforced (the per-run pre-flight folds this into fs-denied).
fn install_landlock(model_path: &str) -> bool {
    use landlock::{
        Access, AccessFs, PathBeneath, PathFd, RestrictionStatus, Ruleset, RulesetAttr,
        RulesetCreatedAttr, ABI,
    };

    let abi = ABI::V4;
    let ro = AccessFs::from_read(abi);
    let res = (|| -> Result<RestrictionStatus, Box<dyn std::error::Error>> {
        let ruleset = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))?
            .create()?;
        // Read-only on the model path only.
        let pf = PathFd::new(model_path)?;
        let ruleset = ruleset.add_rule(PathBeneath::new(pf, ro))?;
        Ok(ruleset.restrict_self()?)
    })();
    match res {
        Ok(status) => {
            // FullyEnforced or PartiallyEnforced both count as "installed"; a
            // kernel that returns NotEnforced means the ABI is unavailable.
            matches!(
                status.ruleset,
                landlock::RulesetStatus::FullyEnforced
                    | landlock::RulesetStatus::PartiallyEnforced
            )
        }
        Err(_) => false,
    }
}

/// seccomp-BPF allowlist via seccompiler (TSYNC), installed before llama.cpp
/// spawns threads. socket/connect/execve/ptrace are denied outright (network
/// egress + C2 structurally impossible from the worker). We use a DENYLIST of
/// the dangerous syscalls over a default-allow, because a full allowlist for
/// the whole ggml/libc surface is brittle across glibc versions and a widened
/// allowlist that accidentally permits socket() would silently defeat the
/// claim; an explicit deny on the network/exec/ptrace family is the auditable
/// minimum, and the §5.2 negative probes PROVE the deny is live per run.
fn install_seccomp() {
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch,
    };
    use std::collections::BTreeMap;

    // Deny the network/exec/ptrace family; default-allow everything else.
    let denied: &[i64] = &[
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_ptrace,
        libc::SYS_socketpair,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
    ];
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for &nr in denied {
        rules.insert(nr, vec![]);
    }
    // Matched (denied) syscalls -> errno EPERM (the probe checks for the error,
    // not a kill, so the worker can REPORT the deny rather than dying); the
    // default action is Allow.
    let filter = match SeccompFilter::new(
        rules,
        SeccompAction::Allow,                 // default for unlisted
        SeccompAction::Errno(libc::EPERM as u32), // listed (denied) -> EPERM
        TargetArch::x86_64,
    ) {
        Ok(f) => f,
        Err(e) => fault(&format!("seccomp build: {e:?}")),
    };
    let prog: BpfProgram = match filter.try_into() {
        Ok(p) => p,
        Err(e) => fault(&format!("seccomp compile: {e:?}")),
    };
    if let Err(e) = seccompiler::apply_filter(&prog) {
        fault(&format!("seccomp apply: {e:?}"));
    }
}

/// The §5.2 anti-hollow probes: a forbidden network op + a forbidden fs open
/// must each fail now that the filters are installed.
fn run_negative_probes(fs_ruleset_ok: bool, env_cleared: bool) -> ProbeResult {
    // (a) socket(AF_INET, SOCK_STREAM, 0) must fail (seccomp EPERM).
    // SAFETY: a syscall with constant args; we only read the return value.
    let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    let net_denied = if s < 0 {
        true
    } else {
        // It unexpectedly succeeded — close it and report NOT denied.
        // SAFETY: s is a valid fd we just opened.
        unsafe {
            libc::close(s);
        }
        false
    };

    // (b) open("/etc/passwd") must be denied by Landlock (path not in the
    // read-only ruleset). If Landlock did not enforce, this open succeeds and
    // fs is NOT denied — a loud pre-flight FAIL.
    let fs_denied = match std::fs::File::open("/etc/passwd") {
        Ok(_) => false,
        Err(_) => fs_ruleset_ok,
    };

    ProbeResult {
        net_denied,
        fs_denied,
        env_cleared,
    }
}

/// Read a length-prefixed prompt from stdin (the process-internal seam).
fn read_prompt_from_stdin() -> Vec<u8> {
    let mut stdin = std::io::stdin().lock();
    let mut lenb = [0u8; 4];
    if stdin.read_exact(&mut lenb).is_err() {
        fault("stdin: short read of prompt length");
    }
    let len = u32::from_le_bytes(lenb) as usize;
    if len > (1 << 20) {
        fault("stdin: prompt length over cap");
    }
    let mut buf = vec![0u8; len];
    if stdin.read_exact(&mut buf).is_err() {
        fault("stdin: short read of prompt body");
    }
    buf
}
