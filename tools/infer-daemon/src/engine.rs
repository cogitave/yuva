//! The daemon-side LOCAL-ENGINE driver (the key-holding, witness-emitting half).
//! It NEVER links llama.cpp; it spawns the `--worker` re-exec with `env_clear()`
//! and a verified-by-hash model path, feeds the prompt over the pipe seam,
//! parses the worker's evidence, runs the §4 four-leg determinism compare, and
//! builds the §8 witness line. The C is one process away, holding no key, no
//! env, no network.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

use tb_encode::inferwire::body_digest;
use xport_core::hex;

use crate::pins::{ModelPin, N_PREDICT, NEG_PROMPT, NONCE_PROMPT_PREFIX, PRIMARY_PROMPT};
use crate::witness::{ModelWitness, SandboxProbe};

/// One worker run's parsed evidence.
pub struct WorkerRun {
    pub resp: Vec<u8>,
    pub sandbox: SandboxProbe,
    pub sysinfo: String,
}

/// A typed failure for the local-engine lane (the daemon's exit-3 refusal / the
/// closed ENGINE-FAULT mapping).
#[derive(Debug)]
pub enum EngineLaneError {
    ArtifactMissing(String),
    HashMismatch { path: String, want: String, got: String },
    WorkerSpawn(String),
    WorkerFault(String),
    NonDeterministic(String),
    GoldenMismatch { which: String, want: String, got: String },
    NegCollision,
    SysinfoDrift(String),
    SandboxPreflight(String),
}

/// Resolve a model's on-disk path (env override for the cache lane), verify it
/// exists and its SHA256 matches the pin (the C parser never touches an
/// unverified byte — the daemon re-verifies BEFORE every worker handoff).
pub fn verify_artifact(pin: &ModelPin, path_override: Option<&str>) -> Result<String, EngineLaneError> {
    let path = path_override.map(|s| s.to_string()).unwrap_or_else(|| pin.default_path.to_string());
    let bytes = std::fs::read(&path)
        .map_err(|e| EngineLaneError::ArtifactMissing(format!("{path}: {e}")))?;
    let got = sha256_hex(&bytes);
    if got != pin.sha256 {
        return Err(EngineLaneError::HashMismatch {
            path,
            want: pin.sha256.to_string(),
            got,
        });
    }
    Ok(path)
}

/// SHA256 over the artifact (the daemon's own verification; uses the system
/// sha256sum via a tiny pure-Rust impl would add a dep — instead we shell to
/// sha256sum, present on every Linux runner and in WSL, no crypto crate).
fn sha256_hex(bytes: &[u8]) -> String {
    use std::io::Write as _;
    let mut child = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("infer-daemon: sha256sum unavailable");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(bytes)
        .expect("write to sha256sum");
    let out = child.wait_with_output().expect("sha256sum output");
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string()
}

/// Spawn ONE fresh worker process (env_clear'd) and run ONE completion.
pub fn run_worker_once(
    self_exe: &str,
    model_path: &str,
    prompt: &[u8],
) -> Result<WorkerRun, EngineLaneError> {
    let mut child = Command::new(self_exe)
        .arg("--worker")
        .arg("--model")
        .arg(model_path)
        .arg("--n-predict")
        .arg(N_PREDICT.to_string())
        // THE KEYLESS, ENV-CLEARED SPAWN (§2): no ANTHROPIC_API_KEY, no
        // XKEY-class material reachable via /proc/self/environ. We pass ONLY
        // PATH (so the dynamic loader / sha256sum resolve) — nothing secret.
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| EngineLaneError::WorkerSpawn(format!("{e}")))?;

    // Feed the length-prefixed prompt.
    {
        let mut sin = child.stdin.take().expect("worker stdin");
        let len = prompt.len() as u32;
        sin.write_all(&len.to_le_bytes())
            .and_then(|()| sin.write_all(prompt))
            .map_err(|e| EngineLaneError::WorkerSpawn(format!("feed prompt: {e}")))?;
        // drop closes stdin
    }

    let out = child
        .wait_with_output()
        .map_err(|e| EngineLaneError::WorkerSpawn(format!("wait: {e}")))?;
    let text = String::from_utf8_lossy(&out.stdout);

    if let Some(line) = text.lines().find(|l| l.starts_with("ENGINE-FAULT")) {
        return Err(EngineLaneError::WorkerFault(line.to_string()));
    }
    if !out.status.success() {
        return Err(EngineLaneError::WorkerFault(format!(
            "worker exited {:?}",
            out.status.code()
        )));
    }
    parse_worker_output(&text)
}

fn parse_worker_output(text: &str) -> Result<WorkerRun, EngineLaneError> {
    let mut sandbox: Option<SandboxProbe> = None;
    let mut sysinfo = String::new();
    let mut resp: Option<Vec<u8>> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("SANDBOX ") {
            sandbox = parse_sandbox(rest);
        } else if let Some(rest) = line.strip_prefix("SYSINFO ") {
            sysinfo = String::from_utf8_lossy(&unhex(rest.trim())).into_owned();
        } else if let Some(rest) = line.strip_prefix("RESP ") {
            let mut it = rest.split_whitespace();
            let _hexlen = it.next();
            let h = it.next().unwrap_or("");
            resp = Some(unhex(h));
        }
    }
    let sandbox = sandbox
        .ok_or_else(|| EngineLaneError::WorkerFault("worker output missing SANDBOX line".into()))?;
    let resp =
        resp.ok_or_else(|| EngineLaneError::WorkerFault("worker output missing RESP line".into()))?;
    Ok(WorkerRun {
        resp,
        sandbox,
        sysinfo,
    })
}

fn parse_sandbox(rest: &str) -> Option<SandboxProbe> {
    let mut net = None;
    let mut fs = None;
    let mut env = None;
    for kv in rest.split_whitespace() {
        let (k, v) = kv.split_once('=')?;
        let b = v == "1";
        match k {
            "net" => net = Some(b),
            "fs" => fs = Some(b),
            "env" => env = Some(b),
            _ => {}
        }
    }
    Some(SandboxProbe {
        net_denied: net?,
        fs_denied: fs?,
        env_cleared: env?,
    })
}

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() + 1 && i + 1 < bytes.len() {
        let hi = hex_val(bytes[i]);
        let lo = hex_val(bytes[i + 1]);
        if let (Some(h), Some(l)) = (hi, lo) {
            out.push((h << 4) | l);
        }
        i += 2;
    }
    out
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Run the full §4 four-leg evidence for ONE model and build the witness.
/// `nonce16` is the workflow-sampled per-run 16-byte nonce (§4 leg 4).
/// `runner_image`/`glibc` are the measured substrate fields (§4).
#[allow(clippy::too_many_arguments)]
pub fn measure_model(
    self_exe: &str,
    pin: &ModelPin,
    path_override: Option<&str>,
    nonce16: &[u8; 16],
    runner_image: &str,
    glibc: &str,
) -> Result<ModelWitness, EngineLaneError> {
    let path = verify_artifact(pin, path_override)?;

    // --- leg 2: fresh-process 2-run compare on the PRIMARY prompt ---
    let run1 = run_worker_once(self_exe, &path, PRIMARY_PROMPT)?;
    let run2 = run_worker_once(self_exe, &path, PRIMARY_PROMPT)?;
    let resp_digest = body_digest(&run1.resp);
    let resp_digest_run2 = body_digest(&run2.resp);
    if resp_digest != resp_digest_run2 {
        return Err(EngineLaneError::NonDeterministic(format!(
            "{}: primary resp-digest != run2 ({} vs {})",
            pin.name,
            hex(&resp_digest),
            hex(&resp_digest_run2)
        )));
    }

    // --- sysinfo tripwire (§4): two-sided baseline-ISA check ---
    for needle in crate::pins::SYSINFO_REQUIRE {
        if !run1.sysinfo.contains(needle) {
            return Err(EngineLaneError::SysinfoDrift(format!(
                "{}: sysinfo missing required '{needle}' — got: {}",
                pin.name, run1.sysinfo
            )));
        }
    }
    for forbidden in crate::pins::SYSINFO_FORBID {
        if run1.sysinfo.contains(forbidden) {
            return Err(EngineLaneError::SysinfoDrift(format!(
                "{}: sysinfo carries FORBIDDEN '{forbidden}' (SIMD dispatch re-enabled — cross-runner divergence risk) — got: {}",
                pin.name, run1.sysinfo
            )));
        }
    }
    let sysinfo_pinned = true;

    // --- sandbox pre-flight (§5.2): both probes must have denied ---
    if !run1.sandbox.net_denied || !run1.sandbox.fs_denied {
        return Err(EngineLaneError::SandboxPreflight(format!(
            "{}: net-denied={} fs-denied={}",
            pin.name, run1.sandbox.net_denied, run1.sandbox.fs_denied
        )));
    }

    // --- leg 3: the frozen NEG-PROMPT, its own golden, measured-distinct ---
    let neg = run_worker_once(self_exe, &path, NEG_PROMPT)?;
    let neg_digest = body_digest(&neg.resp);
    if neg_digest == resp_digest {
        // distinctness is asserted-at-pin; a collision means a pin drifted (a
        // loud finding, never a designed-in false red).
        return Err(EngineLaneError::NegCollision);
    }

    // --- leg 4: per-run nonce-freshness, its OWN fresh-process 2-run ---
    let mut nonce_prompt = NONCE_PROMPT_PREFIX.to_vec();
    nonce_prompt.extend_from_slice(&hex(nonce16).into_bytes());
    let n1 = run_worker_once(self_exe, &path, &nonce_prompt)?;
    let n2 = run_worker_once(self_exe, &path, &nonce_prompt)?;
    let nonce_digest = body_digest(&n1.resp);
    let nonce_digest_run2 = body_digest(&n2.resp);
    if nonce_digest != nonce_digest_run2 {
        return Err(EngineLaneError::NonDeterministic(format!(
            "{}: nonce resp-digest != run2",
            pin.name
        )));
    }

    // --- leg 1: repo-pinned golden adjudication (skipped in measure-mode) ---
    // The daemon prints the measured digests; the WORKFLOW string-compares the
    // primary/neg digests against the repo constants (the independent stream).
    // When the pin carries a real golden (not the @@..@@ placeholder), the
    // daemon ALSO self-checks here as a belt-and-braces (the workflow is the
    // load-bearing leg).
    if !pin.golden_primary.starts_with("@@") {
        let got = hex(&resp_digest);
        if got != pin.golden_primary {
            return Err(EngineLaneError::GoldenMismatch {
                which: format!("{}-primary", pin.name),
                want: pin.golden_primary.to_string(),
                got,
            });
        }
        let gotn = hex(&neg_digest);
        if gotn != pin.golden_neg {
            return Err(EngineLaneError::GoldenMismatch {
                which: format!("{}-neg", pin.name),
                want: pin.golden_neg.to_string(),
                got: gotn,
            });
        }
    }

    let prompt_digest = body_digest(PRIMARY_PROMPT);

    Ok(ModelWitness {
        model: pin.name.to_string(),
        gguf_sha256: pin.sha256.to_string(),
        enginepin: crate::pins::ENGINE_PIN.to_string(),
        runner_image: runner_image.to_string(),
        glibc: glibc.to_string(),
        sysinfo_pinned,
        prompt_digest,
        resp_digest,
        resp_digest_run2,
        neg_digest,
        nonce: *nonce16,
        nonce_digest,
        nonce_digest_run2,
        sandbox: run1.sandbox,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unhex_roundtrips() {
        assert_eq!(unhex("00ff10ab"), vec![0x00, 0xff, 0x10, 0xab]);
        assert_eq!(unhex(""), Vec::<u8>::new());
    }

    #[test]
    fn parse_worker_output_happy() {
        let text = "SANDBOX net=1 fs=1 env=1\nSYSINFO 4350\nRESP 5 68656c6c6f\n";
        let r = parse_worker_output(text).expect("parse");
        assert_eq!(r.resp, b"hello");
        assert!(r.sandbox.net_denied && r.sandbox.fs_denied && r.sandbox.env_cleared);
        assert_eq!(r.sysinfo, "CP");
    }

    #[test]
    fn parse_worker_output_missing_resp_is_fault() {
        let text = "SANDBOX net=1 fs=1 env=1\n";
        assert!(matches!(
            parse_worker_output(text),
            Err(EngineLaneError::WorkerFault(_))
        ));
    }

    #[test]
    fn parse_worker_output_missing_sandbox_is_fault() {
        let text = "RESP 1 61\n";
        assert!(matches!(
            parse_worker_output(text),
            Err(EngineLaneError::WorkerFault(_))
        ));
    }

    #[test]
    fn parse_sandbox_partial_is_none() {
        // A forged worker that drops the env field cannot be parsed as a probe.
        assert!(parse_sandbox("net=1 fs=1").is_none());
    }

    #[test]
    fn sandbox_not_denied_is_loud() {
        // A worker reporting net=0 (socket succeeded) must parse but the caller
        // (measure_model) rejects it; here we assert the parse preserves the 0.
        let p = parse_sandbox("net=0 fs=1 env=1").expect("parse");
        assert!(!p.net_denied);
    }
}
