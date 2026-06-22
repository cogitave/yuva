//! The M32 daemon witness vocabulary — the closed token grammar (proposal §7,
//! §8). Every spelling here is BINDING (from the plan, verbatim); the run-script
//! / workflow guards strip-then-reject against exactly these literals.

use xport_core::hex;

// --- the closed debt token grammar (§7) -------------------------------------
pub const BACKEND: &str = "LOCAL-ENGINE";
pub const ENGINE: &str = "VENDORED-C-LLAMACPP";
pub const DEBT: &str = "SOVEREIGNTY-OPEN-B3";
pub const MEMSAFETY: &str = "UNSAFE-C-PROCESS-CONFINED";
pub const WEIGHTS: &str = "UNTRUSTED-INPUT-NAMED";

// --- the determinism envelope tokens (§4) -----------------------------------
pub const SAMPLER: &str = "GREEDY-TOPK1";
pub const REPRO: &str = "BIT-IDENTICAL-2RUN";
pub const DETERMINISM: &str = "BUILD-PINNED-SINGLE-THREAD-GREEDY";
pub const DIGEST_KIND: &str = "TUPLE-CONDITIONAL";
pub const GOLDEN: &str = "REPO-PINNED-MATCHED";
pub const NEG_PROMPT_TOK: &str = "FROZEN-PINNED";
pub const SEED: &str = "MOOT-GREEDY";
pub const DISPATCH: &str = "STATIC";

// ISA — the named honesty fallback (§4 / the brief's cross-runner risk). The
// proposal pins X86-64-V3-PINNED; this stage-A landing builds the BASELINE ISA
// (no AVX dispatch at all) for cross-runner bit-exactness, and says so in the
// token. A reviewed bump to x86-64-v3 (faster, narrower fleet) re-measures the
// goldens.
pub const ISA: &str = "X86-64-BASELINE-PINNED";

// --- the sandbox + custody tokens (§5) --------------------------------------
pub const SANDBOX: &str = "SECCOMP-LANDLOCK-PRE-PARSE";
pub const GUESTPATH: &str = "MOCK-PINNED-HOST-ADJUDICATED";
pub const XMACHINE: &str = "NOT-CLAIMED";
pub const XARCH: &str = "NOT-CLAIMED";

// --- inherited (§7) ---------------------------------------------------------
pub const KEY: &str = "CAPREF-HOST-CUSTODIED";
pub const HOST: &str = "RESIDUAL-TCB";
pub const AMBIENT: &str = "ZERO-IN-GUEST";
pub const SEC: &str = "ASSUMED-FROM-LITERATURE";

/// The sandbox probe results the worker reports back to the daemon.
#[derive(Debug, Clone, Copy)]
pub struct SandboxProbe {
    pub net_denied: bool,
    pub fs_denied: bool,
    pub env_cleared: bool,
}

/// Everything the daemon measured for ONE model, rendered into the single
/// witness line (§8 — all corroboration on the SAME line; the digest binds the
/// whole tuple).
pub struct ModelWitness {
    pub model: String,
    pub gguf_sha256: String,
    pub enginepin: String,
    pub runner_image: String,
    pub glibc: String,
    pub sysinfo_pinned: bool,
    pub prompt_digest: [u8; 16],
    pub resp_digest: [u8; 16],
    pub resp_digest_run2: [u8; 16],
    pub neg_digest: [u8; 16],
    pub nonce: [u8; 16],
    pub nonce_digest: [u8; 16],
    pub nonce_digest_run2: [u8; 16],
    pub sandbox: SandboxProbe,
}

impl ModelWitness {
    /// Render the §8 stage-A daemon witness line VERBATIM (one line, every
    /// corroboration field present). The flags use the `0x1` spelling the
    /// guards require (`=0x0*1`).
    pub fn render(&self) -> String {
        format!(
            "infer-daemon: backend={BACKEND} engine={ENGINE} debt={DEBT} \
memsafety={MEMSAFETY} weights={WEIGHTS} gguf=SHA256:{gguf} model={model} \
enginepin={enginepin} threads=1 parallel=1 blas=OFF openmp=OFF isa={ISA} \
dispatch={DISPATCH} sysinfo-pinned=0x{sysinfo} sampler={SAMPLER} \
cache-prompt=OFF batch=PINNED seed={SEED} runner-image={runner} glibc={glibc} \
prompt-digest=0x{pdig} resp-digest=0x{rdig} resp-digest-run2=0x{rdig2} \
golden={GOLDEN} neg-prompt={NEG_PROMPT_TOK} neg-digest=0x{ndig} \
neg-golden={GOLDEN} nonce=0x{nonce} nonce-digest=0x{nndig} \
nonce-digest-run2=0x{nndig2} repro={REPRO} determinism={DETERMINISM} \
digest={DIGEST_KIND} xmachine={XMACHINE} xarch={XARCH} sandbox={SANDBOX} \
net-denied=0x{net} fs-denied=0x{fs} envclear=0x{env} guestpath={GUESTPATH} \
key={KEY} host={HOST} ambient={AMBIENT} sec={SEC}",
            gguf = self.gguf_sha256,
            model = self.model,
            enginepin = self.enginepin,
            sysinfo = if self.sysinfo_pinned { 1 } else { 0 },
            runner = self.runner_image,
            glibc = self.glibc,
            pdig = hex(&self.prompt_digest),
            rdig = hex(&self.resp_digest),
            rdig2 = hex(&self.resp_digest_run2),
            ndig = hex(&self.neg_digest),
            nonce = hex(&self.nonce),
            nndig = hex(&self.nonce_digest),
            nndig2 = hex(&self.nonce_digest_run2),
            net = if self.sandbox.net_denied { 1 } else { 0 },
            fs = if self.sandbox.fs_denied { 1 } else { 0 },
            env = if self.sandbox.env_cleared { 1 } else { 0 },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ModelWitness {
        ModelWitness {
            model: "STORIES260K".into(),
            gguf_sha256: "00".repeat(32),
            enginepin: "b9756-gd0f9d2e5ac5d".into(),
            runner_image: "ubuntu24.04".into(),
            glibc: "2.39".into(),
            sysinfo_pinned: true,
            prompt_digest: [1u8; 16],
            resp_digest: [2u8; 16],
            resp_digest_run2: [2u8; 16],
            neg_digest: [3u8; 16],
            nonce: [4u8; 16],
            nonce_digest: [5u8; 16],
            nonce_digest_run2: [5u8; 16],
            sandbox: SandboxProbe {
                net_denied: true,
                fs_denied: true,
                env_cleared: true,
            },
        }
    }

    #[test]
    fn render_carries_every_debt_token() {
        let line = sample().render();
        for tok in [
            "backend=LOCAL-ENGINE",
            "engine=VENDORED-C-LLAMACPP",
            "debt=SOVEREIGNTY-OPEN-B3",
            "memsafety=UNSAFE-C-PROCESS-CONFINED",
            "weights=UNTRUSTED-INPUT-NAMED",
        ] {
            assert!(line.contains(tok), "missing {tok} in: {line}");
        }
    }

    #[test]
    fn render_flags_use_0x1_spelling() {
        let line = sample().render();
        assert!(line.contains("sysinfo-pinned=0x1"));
        assert!(line.contains("net-denied=0x1"));
        assert!(line.contains("fs-denied=0x1"));
        assert!(line.contains("envclear=0x1"));
    }

    #[test]
    fn render_is_single_line() {
        assert_eq!(sample().render().lines().count(), 1);
    }

    #[test]
    fn render_carries_envelope_and_custody() {
        let line = sample().render();
        for tok in [
            "repro=BIT-IDENTICAL-2RUN",
            "determinism=BUILD-PINNED-SINGLE-THREAD-GREEDY",
            "digest=TUPLE-CONDITIONAL",
            "golden=REPO-PINNED-MATCHED",
            "neg-prompt=FROZEN-PINNED",
            "sandbox=SECCOMP-LANDLOCK-PRE-PARSE",
            "guestpath=MOCK-PINNED-HOST-ADJUDICATED",
            "key=CAPREF-HOST-CUSTODIED",
            "host=RESIDUAL-TCB",
            "ambient=ZERO-IN-GUEST",
            "sec=ASSUMED-FROM-LITERATURE",
        ] {
            assert!(line.contains(tok), "missing {tok}");
        }
    }
}
