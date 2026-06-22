//! The M32 lane PINS — the artifact SHA256s, the engine pin, the frozen prompts,
//! and the repo-pinned golden digests (§4 leg 1 / §5.5 / §12). Every value here
//! is a reviewed constant; a bump re-measures the goldens (the §4 leg-1
//! independent stream is exactly this repo constant vs the daemon's stdout).

/// One CI model: its name token, the path env var, and its SHA256 pin.
pub struct ModelPin {
    pub name: &'static str,
    /// Default in-repo / cache path (overridable by env for the cache lane).
    pub default_path: &'static str,
    pub sha256: &'static str,
    /// The §4 leg-1 goldens (16-byte body_digest of the response, lowercase hex
    /// 32 chars). MEASURED AT LANDING; re-pinned only by a reviewed commit.
    /// Empty string = "measure mode" (the daemon prints the measured digest and
    /// the workflow does NOT yet string-compare — used once at landing to seed
    /// the constant, never green on a required lane while empty).
    pub golden_primary: &'static str,
    pub golden_neg: &'static str,
}

// stories260K — committed IN-REPO (the network-independent smoke; §17.17).
pub const STORIES260K: ModelPin = ModelPin {
    name: "STORIES260K",
    default_path: "tools/infer-daemon/models/stories260K.gguf",
    sha256: "270cba1bd5109f42d03350f60406024560464db173c0e387d91f0426d3bd256d",
    // MEASURED at landing on the baseline-ISA build (see build.rs flags),
    // prompt "Once upon a time" / NEG-PROMPT, n_predict 64.
    golden_primary: "8602c11292c2fdd0ab4af10c4d462874",
    golden_neg: "2c091277ca095b7b9e74fc84a51d6dd8",
};

// stories15M-q8_0 — the quantized-kernel path; rides the hash-keyed cache with
// the §5.5 setup-step pinned re-fetch on miss (NOT committed in-repo).
pub const STORIES15M_Q8: ModelPin = ModelPin {
    name: "STORIES15M-Q8_0",
    default_path: "tools/infer-daemon/models/stories15M-q8_0.gguf",
    sha256: "2eda49203f2f044f3dddf29a7dd7cc861ef5a0340f518a19613d73ba6d9c06b6",
    golden_primary: "40ef3f2f6bada73c8f56923791a02e1c",
    golden_neg: "fa53224c767e2182e1e855ba90c43ea5",
};

/// The engine pin string for the witness (`enginepin=<btag>-g<12hex>`).
pub const ENGINE_PIN: &str = "b9756-gd0f9d2e5ac5d";

/// The §4 `sysinfo-pinned` tripwire. The baseline-ISA build's
/// `llama_print_system_info()` reports ONLY the universal x86-64 baseline
/// features (SSE3/SSSE3/BMI2 — present on every x86-64 CPU) and OMITS every
/// SIMD-dispatch feature. The tripwire is therefore TWO-SIDED:
///   * [`SYSINFO_REQUIRE`] substrings MUST be present (the build really linked
///     the CPU backend), and
///   * [`SYSINFO_FORBID`] tokens MUST be ABSENT — any AVX/AVX2/AVX512/FMA token
///     means an upstream bump silently re-enabled SIMD dispatch (the
///     cross-runner-divergence tripwire).
pub const SYSINFO_REQUIRE: &[&str] = &["CPU :", "SSE3 = 1"];
pub const SYSINFO_FORBID: &[&str] = &["AVX", "FMA"];

// --- the frozen prompts (§4) -------------------------------------------------

/// The PRIMARY pinned prompt (raw bytes, no chat template). Fixed forever for
/// the golden; a change re-measures the golden (a reviewed act).
pub const PRIMARY_PROMPT: &[u8] = b"Once upon a time";

/// The FROZEN second prompt — the §4 leg-3 negative control. Its golden is
/// distinct from the primary's BY MEASUREMENT (asserted at landing); a stub or
/// cache returning the same bytes for both fails one golden.
pub const NEG_PROMPT: &[u8] = b"The little robot looked at the stars and";

/// The pinned prefix the per-run workflow nonce is appended to (§4 leg 4). No
/// golden can exist for the nonce prompt by construction (the nonce is fresh
/// per run); its claim is freshness + envelope-determinism.
pub const NONCE_PROMPT_PREFIX: &[u8] = b"A story about ";

/// `n_predict` for the pinned prompts (§4: fixed, <= 64).
pub const N_PREDICT: i32 = 64;
